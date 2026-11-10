"""
vpn_location_detect - VPN location spoofing detection as a Cortex XSIAM agent script.

Port of vpn-location-detection-full.ps1 to the Python 3.7 runtime built into the
Cortex XDR agent, so the detection can be run across a fleet from Action Center or
the run_script API instead of one box at a time.

RUNTIME CONSTRAINTS THIS FILE IS WRITTEN AGAINST
  * Python 3.7. No walrus, no f-string "=", no dict union.
  * Only modules on the tenant's Upload Script allowlist may be imported. `typing`,
    `math`, `urllib` and `ipaddress` are NOT on it, which is why none appear here and
    why the original wifi-geolocation.py cannot be uploaded unchanged.
  * The agent runs scripts as SYSTEM on Windows. HKEY_CURRENT_USER reaches SYSTEM's
    own hive, not the logged-on user's, so no per-user registry check is attempted.
  * Everything optional is imported inside a try, so one missing module degrades a
    single indicator instead of failing the run.

WHAT RUNS WHERE
  The endpoint collects only what an endpoint can see: the WiFi BSSIDs around it, its
  own timezone, its adapters, processes, installed software, DNS, routes, and the first
  public hop on its path out. Resolving those into a location and an ASN is enrichment,
  and enrichment belongs server-side:

    enrich=false  (default, fleet runs)  raw observables + local-only score.
                  No API key on the endpoint, no third-party calls from the endpoint,
                  and BSSID sets dedupe across endpoints before anyone pays Google.
    enrich=true   (PoC, single endpoint) the script resolves location and geo itself
                  and returns the full score, matching the PowerShell version.

ENTRY POINT
  run_detection(google_api_key, enrich, scan_wifi) -> dict
"""

import base64
import datetime
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import traceback

import ctypes

# ctypes.wintypes is Windows-only and raises on some non-Windows builds, which
# would make the whole module unimportable on a Mac rather than degrading one
# indicator. The shim exists only so the WLAN structures below can be DEFINED on
# any platform; off Windows they are never instantiated.
try:
    from ctypes import wintypes
    HAVE_WINTYPES = True
except (ImportError, ValueError):
    HAVE_WINTYPES = False

    class _WinTypesShim(object):
        DWORD = ctypes.c_uint32
        WORD = ctypes.c_uint16
        BOOL = ctypes.c_int32
        HANDLE = ctypes.c_void_p

    wintypes = _WinTypesShim()

IS_WINDOWS = platform.system() == "Windows"
IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

SCRIPT_VERSION = "2.1.0"

# ---------------------------------------------------------------------------
# Configuration - kept identical to vpn-location-detection-full.ps1 so results
# from the two implementations stay comparable.
# ---------------------------------------------------------------------------

CA_BOUNDS = {"lat_min": 32.53, "lat_max": 42.01, "lng_min": -124.48, "lng_max": -114.13}

# Windows TimeZoneKeyName -> plausible longitude band for the IP location.
TIMEZONE_LONGITUDE = {
    "Pacific Standard Time": (-125.0, -114.0),
    "Mountain Standard Time": (-114.0, -102.0),
    "US Mountain Standard Time": (-114.0, -102.0),
    "Central Standard Time": (-102.0, -87.0),
    "Eastern Standard Time": (-87.0, -67.0),
    # macOS reports IANA names, not Windows ones. Without these the timezone
    # mismatch indicator silently never fires on a Mac.
    "America/Los_Angeles": (-125.0, -114.0),
    "America/Phoenix": (-114.0, -102.0),
    "America/Denver": (-114.0, -102.0),
    "America/Chicago": (-102.0, -87.0),
    "America/New_York": (-87.0, -67.0),
}

VPN_DNS_SERVERS = {
    "103.86.96.100", "103.86.99.100",     # NordVPN
    "10.255.255.1",                        # NordVPN internal
    "100.64.0.7",                          # ExpressVPN
    "162.252.172.57", "149.154.159.92",   # Surfshark
    "10.2.0.1",                            # CyberGhost
    "10.0.0.243",                          # ProtonVPN
    "10.8.0.1",                            # common OpenVPN
    "209.222.18.222", "209.222.18.218",   # Private Internet Access
    "193.138.218.74",                      # Mullvad
    "76.76.19.19", "76.223.122.150",      # Cloudflare WARP
}

VPN_ADAPTER_PATTERNS = [
    "tap-windows", "tap-win32", "wintun", "wireguard", "nordlynx",
    "windscribe", "surfshark", "expressvpn", "cyberghost", "protonvpn",
    "openvpn", "hotspot shield", "private internet", "tunnelbear",
    "mullvad", "ipvanish", "hidemyass", "vyprvpn", "zenmate",
    "kaspersky vpn", "avast secureline", "norton vpn",
]

VPN_PROCESS_NAMES = [
    "nordvpn", "nordlynx", "expressvpn", "expressvpnd", "openvpn",
    "openvpn-gui", "openvpnserv", "wireguard", "surfshark",
    "surfsharkservice", "cyberghost", "cyberghostvpn", "protonvpn",
    "protonvpnservice", "pia-service", "pia-client", "pia-wireguard",
    "privateinternetaccess", "mullvad-vpn", "mullvad-daemon", "windscribe",
    "windscribeservice", "tunnelbear", "ipvanish", "ipvanishvpn",
    "hidemyass", "hma", "vyprvpn", "zenmate", "avast-secureline",
    "avastseculine", "norton-vpn", "nortonvpn",
]

VPN_SOFTWARE_PATTERNS = [
    "nordvpn", "expressvpn", "surfshark", "cyberghost", "protonvpn",
    "private internet access", "mullvad", "windscribe", "tunnelbear",
    "ipvanish", "hidemyass", "vyprvpn", "hotspot shield", "openvpn",
    "wireguard", "zenmate", "zenmate vpn", "tailscale",
]

# Tailscale rides wintun, so it already matches VPN_ADAPTER_PATTERNS and would be
# scored as an unsanctioned consumer VPN. It is named explicitly here so it is
# identifiable rather than a generic "wintun" hit.
VPN_PROCESS_NAMES += ["tailscale", "tailscaled", "tailscale-ipn"]
VPN_ADAPTER_PATTERNS += ["tailscale"]

# Matches here are reported but do NOT score. The corporate mesh VPN is not the
# thing being looked for, and without this every machine carrying it is a
# permanent HIGH. Override per tenant with the sanctioned_patterns parameter.
DEFAULT_SANCTIONED_PATTERNS = ["tailscale", "globalprotect", "prisma access"]

# Scoring. Bands match the PowerShell version: 100+ CRITICAL, 70-99 HIGH,
# 40-69 MEDIUM, below 40 LOW, out of a nominal 300.
SCORE_LOCATION_OUTSIDE_CA = 50
SCORE_TIMEZONE_MISMATCH = 25
SCORE_IP_VPN_ASN = 25
SCORE_HOP_VPN_ASN = 25
SCORE_VPN_ADAPTER = 30
SCORE_VPN_PROCESS = 30
SCORE_VPN_SOFTWARE = 15
SCORE_VPN_DNS = 20
SCORE_SPLIT_DEFAULT_ROUTE = 20
MAX_SCORE = 300

GOOGLE_GEOLOCATE_URL = "https://www.googleapis.com/geolocation/v1/geolocate"
IPAPI_URL = ("http://ip-api.com/json/?fields=status,message,country,regionName,"
             "city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query")
NOMINATIM_URL = "https://nominatim.openstreetmap.org/reverse"

# ANYCAST. Reachability only. 8.8.8.8, 1.1.1.1 and 9.9.9.9 are answered by the
# nearest edge PoP wherever the device is, so a laptop in Austin measures the same
# ~10ms a laptop in Sacramento does. RTT to these says nothing about where the
# device is, and treating it as a distance signal is the easiest way to build a
# location check that cannot detect location.
ANYCAST_ANCHORS = [("8.8.8.8", 53), ("1.1.1.1", 53), ("9.9.9.9", 53)]

# A usable distance signal needs a UNICAST host at a known fixed location, which
# in practice means one you own. Pass it in with the latency_anchors parameter as
# "host:port,host:port". Only anchors supplied that way are treated as positional.
#
# THE ANCHOR IS OPTIONAL BY DESIGN, AND IT NEVER SCORES. Leave latency_anchors
# blank and the detection runs unchanged: anchor_type reports "none" and the
# confidence score is identical. Many environments have nowhere suitable to point
# it, so a deployment must not depend on one. When it IS configured the values are
# reported for an XQL baseline to compare against that device's own history,
# which is where a latency judgement belongs. Do not add a scoring rule here: a
# fixed threshold cannot tell hotel wifi in Sacramento from fibre in Austin.
#
# Pick a port the far end is likely to allow. Measured 2026-11-06: a laptop on a
# conference network reached 443 and ICMP and nothing else, so anchors on 8096
# and 8450 both read as unreachable while the device was demonstrably routable.
DEFAULT_LATENCY_PORT = 443

PRIVATE_V4_PREFIXES = ("10.", "192.168.", "127.", "169.254.", "0.")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _run(cmd, timeout=30):
    """Run a command and return stdout, or '' on any failure."""
    try:
        completed = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            shell=False,
        )
        return completed.stdout.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _is_private_v4(addr):
    if not addr:
        return True
    if addr.startswith(PRIVATE_V4_PREFIXES):
        return True
    parts = addr.split(".")
    if len(parts) != 4:
        return True
    try:
        first, second = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 100 and 64 <= second <= 127:   # CGNAT, common on carrier and VPN paths
        return True
    return False


def _in_california(lat, lng):
    if lat is None or lng is None:
        return None
    return (CA_BOUNDS["lat_min"] <= lat <= CA_BOUNDS["lat_max"]
            and CA_BOUNDS["lng_min"] <= lng <= CA_BOUNDS["lng_max"])


def _join(values, limit=20):
    """Collapse a list to a pipe-delimited string for the results table."""
    uniq = []
    for value in values:
        if value and value not in uniq:
            uniq.append(value)
    return "|".join(uniq[:limit])


# ---------------------------------------------------------------------------
# 1. WiFi BSSID collection
#
# Two methods, tried in order. The native WLAN API is primary because it is
# locale independent and returns RSSI in dBm directly; `netsh wlan show networks`
# prints localized labels, so a regex over its output breaks on a non-English
# Windows install. The netsh fallback therefore matches bare MAC addresses rather
# than labelled fields, which keeps it locale independent too, at the cost of
# signal strength.
#
# Whether either works under SYSTEM with no interactive session is the first
# thing to measure on a real endpoint, which is why the method used is reported.
# ---------------------------------------------------------------------------

DOT11_SSID_MAX_LENGTH = 32
DOT11_BSS_TYPE_ANY = 3
WLAN_SCAN_SETTLE_SECONDS = 4


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceGuid", _GUID),
                ("strInterfaceDescription", ctypes.c_wchar * 256),
                ("isState", wintypes.DWORD)]


class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", _WLAN_INTERFACE_INFO * 1)]


class _DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_ulong),
                ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH)]


class _WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", ctypes.c_ulong),
                ("usRateSet", ctypes.c_ushort * 126)]


class _WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", _DOT11_SSID),
                ("uPhyId", ctypes.c_ulong),
                ("dot11Bssid", ctypes.c_ubyte * 6),
                ("dot11BssType", ctypes.c_uint),
                ("dot11BssPhyType", ctypes.c_uint),
                ("lRssi", ctypes.c_long),
                ("uLinkQuality", ctypes.c_ulong),
                ("bInRegDomain", wintypes.BOOL),
                ("usBeaconPeriod", ctypes.c_ushort),
                ("ullTimestamp", ctypes.c_ulonglong),
                ("ullHostTimestamp", ctypes.c_ulonglong),
                ("usCapabilityInformation", ctypes.c_ushort),
                ("ulChCenterFrequency", ctypes.c_ulong),
                ("wlanRateSet", _WLAN_RATE_SET),
                ("ulIeOffset", ctypes.c_ulong),
                ("ulIeSize", ctypes.c_ulong)]


class _WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD),
                ("dwNumberOfItems", wintypes.DWORD),
                ("wlanBssEntries", _WLAN_BSS_ENTRY * 1)]


def _wlan_scan_native(errors):
    """Collect BSSIDs through wlanapi.dll. Returns a list of access point dicts."""
    if not IS_WINDOWS:
        return []

    try:
        wlanapi = ctypes.windll.wlanapi
    except Exception as exc:
        errors.append("wlanapi load: %s" % exc)
        return []

    handle = wintypes.HANDLE()
    negotiated = wintypes.DWORD()
    access_points = []

    try:
        if wlanapi.WlanOpenHandle(2, None, ctypes.byref(negotiated),
                                  ctypes.byref(handle)) != 0:
            errors.append("WlanOpenHandle failed")
            return []
    except Exception as exc:
        errors.append("WlanOpenHandle: %s" % exc)
        return []

    iface_list_ptr = ctypes.POINTER(_WLAN_INTERFACE_INFO_LIST)()
    try:
        if wlanapi.WlanEnumInterfaces(handle, None,
                                      ctypes.byref(iface_list_ptr)) != 0:
            errors.append("WlanEnumInterfaces failed")
            return []

        iface_list = iface_list_ptr.contents
        count = iface_list.dwNumberOfItems
        if count == 0:
            errors.append("no wireless interfaces present")
            return []

        interfaces = ctypes.cast(
            ctypes.byref(iface_list.InterfaceInfo),
            ctypes.POINTER(_WLAN_INTERFACE_INFO * count),
        ).contents

        for iface in interfaces:
            guid = ctypes.byref(iface.InterfaceGuid)

            # WlanGetNetworkBssList returns the cached list, so ask for a fresh
            # scan first and let it settle. A failure here is not fatal; the
            # cached list is still better than nothing.
            try:
                if wlanapi.WlanScan(handle, guid, None, None, None) == 0:
                    time.sleep(WLAN_SCAN_SETTLE_SECONDS)
            except Exception as exc:
                errors.append("WlanScan: %s" % exc)

            bss_list_ptr = ctypes.POINTER(_WLAN_BSS_LIST)()
            result = wlanapi.WlanGetNetworkBssList(
                handle, guid, None, DOT11_BSS_TYPE_ANY, False, None,
                ctypes.byref(bss_list_ptr),
            )
            if result != 0:
                errors.append("WlanGetNetworkBssList failed (%s)" % result)
                continue

            try:
                bss_list = bss_list_ptr.contents
                entry_count = bss_list.dwNumberOfItems
                if entry_count == 0:
                    continue
                entries = ctypes.cast(
                    ctypes.byref(bss_list.wlanBssEntries),
                    ctypes.POINTER(_WLAN_BSS_ENTRY * entry_count),
                ).contents
                for entry in entries:
                    mac = ":".join("%02x" % b for b in entry.dot11Bssid)
                    ssid = bytes(
                        entry.dot11Ssid.ucSSID[:entry.dot11Ssid.uSSIDLength]
                    ).decode("utf-8", errors="replace")
                    access_points.append({
                        "macAddress": mac,
                        "signalStrength": int(entry.lRssi),
                        "ssid": ssid,
                    })
            finally:
                wlanapi.WlanFreeMemory(bss_list_ptr)
    except Exception as exc:
        errors.append("wlan native: %s" % exc)
    finally:
        try:
            if iface_list_ptr:
                wlanapi.WlanFreeMemory(iface_list_ptr)
        except Exception:
            pass
        try:
            wlanapi.WlanCloseHandle(handle, None)
        except Exception:
            pass

    return access_points


MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")


def _wlan_scan_netsh(errors):
    """Fallback BSSID collection. Matches bare MACs so it survives localization."""
    if not IS_WINDOWS:
        return []
    output = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=45)
    if not output:
        errors.append("netsh returned no output")
        return []
    macs = []
    for mac in MAC_RE.findall(output):
        mac = mac.lower()
        if mac not in macs:
            macs.append(mac)
    return [{"macAddress": mac} for mac in macs]


# macOS BSSID collection.
#
# Read this before trusting a macOS result. Apple gates BSSID behind Location
# Services authorization for the calling application, and the agent runs as root,
# which does NOT bypass that gate. The legacy `airport -s` scanner that used to
# return a full list was removed in macOS 14.4. So on a Mac this returns at most
# the BSSID of the CURRENTLY ASSOCIATED access point, and usually not a scan list.
#
# One BSSID is below what Google's Geolocation API wants for a WiFi fix, so the
# value here is not a coordinate. It is a FINGERPRINT: a stable identifier for
# where the laptop is sitting. Comparing today's BSSID against the ones that
# device has reported before answers "has it moved" without any API call, and
# that is the macOS signal worth building on.

def _macs_from_labelled_lines(output, label="BSSID"):
    """Only take MACs off a line that names the field.

    MEASURED 2026-11-06, and this is why the function exists. An earlier version
    regexed every MAC-shaped string in the whole blob. On macOS that returns the
    en1 interface's own MAC and awdl0's, because `system_profiler SPAirPortDataType`
    carries "MAC Address:" lines and NO BSSID field at all. Those interface MACs
    are locally administered, look exactly like a BSSID, and are useless to Google.

    The result was a Mac reporting bssid_count: 2 with two confident, wrong values.
    A layer that silently returns plausible garbage is worse than one that returns
    nothing, so this will only accept a MAC the output itself labels.
    """
    macs = []
    for line in output.splitlines():
        if label not in line.upper():
            continue
        for mac in MAC_RE.findall(line):
            if mac.lower() not in macs:
                macs.append(mac.lower())
    return macs


def _wlan_scan_macos(errors):
    """macOS BSSID collection, which on a current OS returns nothing.

    MEASURED 2026-11-06 through the agent on a Mac Studio, running as root
    (euid 0): `wdutil info` prints `BSSID : <redacted>`. Apple gates BSSID on
    Location Services authorization for the CALLING PROCESS, and root does not
    satisfy it. `system_profiler SPAirPortDataType` has no BSSID field in any
    form, JSON or text. `airport -s` was removed in macOS 14.4.

    So the CRITICAL-confidence layer is unavailable on macOS from an agent
    script, and no amount of privilege changes that. The remaining nine layers
    work, and in testing they separated an away laptop from two at-home machines
    on their own. Treat macOS as a nine-layer detection and say so.
    """
    # Kept in order anyway: an older fleet member or a future authorisation
    # path may answer, and wifi_method reports which one did.
    output = _run(["/usr/bin/wdutil", "info"], timeout=20)
    macs = _macs_from_labelled_lines(output)
    if macs:
        return [{"macAddress": m} for m in macs], "wdutil"
    if "REDACTED" in output.upper():
        errors.append("macos: wdutil returned BSSID <redacted>; Location Services "
                      "gates it per-process and root does not bypass it")

    output = _run(["/usr/sbin/system_profiler", "SPAirPortDataType"], timeout=45)
    macs = _macs_from_labelled_lines(output)
    if macs:
        return [{"macAddress": m} for m in macs], "system_profiler"

    airport = ("/System/Library/PrivateFrameworks/Apple80211.framework"
               "/Versions/Current/Resources/airport")
    if os.path.exists(airport):
        output = _run([airport, "-s"], timeout=45)
        macs = _macs_from_labelled_lines(output)
        if not macs:
            # The -s table has a BSSID column rather than a label per line.
            for line in output.splitlines()[1:]:
                found = MAC_RE.findall(line)
                if found and found[0].lower() not in macs:
                    macs.append(found[0].lower())
        if macs:
            return [{"macAddress": m} for m in macs], "airport"

    if not errors or "redacted" not in errors[-1]:
        errors.append("macos: no BSSID source returned a labelled value")
    return [], "none"


def collect_wifi(errors):
    """Return (access_points, method_used). method_used names the surface that
    answered, so a zero result can be told apart from an unavailable one."""
    if IS_MACOS:
        return _wlan_scan_macos(errors)
    access_points = _wlan_scan_native(errors)
    if access_points:
        return access_points, "wlanapi"
    access_points = _wlan_scan_netsh(errors)
    if access_points:
        return access_points, "netsh"
    return [], "none"


# ---------------------------------------------------------------------------
# 2. Timezone
# ---------------------------------------------------------------------------

def collect_timezone(errors):
    info = {"timezone_key": None, "utc_offset_hours": None}
    try:
        offset = -(time.altzone if time.daylight and time.localtime().tm_isdst
                   else time.timezone)
        info["utc_offset_hours"] = round(offset / 3600.0, 2)
    except Exception as exc:
        errors.append("utc offset: %s" % exc)

    if IS_MACOS:
        # /etc/localtime symlinks into the zoneinfo tree, e.g.
        # /var/db/timezone/zoneinfo/America/Los_Angeles -> "America/Los_Angeles"
        try:
            target = os.path.realpath("/etc/localtime")
            marker = "zoneinfo/"
            if marker in target:
                info["timezone_key"] = target.split(marker, 1)[1]
        except Exception as exc:
            errors.append("macos timezone: %s" % exc)
        return info

    if not IS_WINDOWS:
        return info
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
        )
        try:
            info["timezone_key"] = winreg.QueryValueEx(key, "TimeZoneKeyName")[0]
        finally:
            winreg.CloseKey(key)
    except Exception as exc:
        errors.append("timezone key: %s" % exc)
    return info


# ---------------------------------------------------------------------------
# 3. Network adapters, processes, installed software, DNS, routes
# ---------------------------------------------------------------------------

def _wmi_connection(errors):
    try:
        import pythoncom
        pythoncom.CoInitialize()
    except Exception:
        pass
    try:
        import wmi
        return wmi.WMI()
    except Exception as exc:
        errors.append("wmi: %s" % exc)
        return None


def collect_adapters(conn, errors):
    """VPN-shaped network adapters, by name or driver service name."""
    names = []
    if conn is not None:
        try:
            for adapter in conn.Win32_NetworkAdapter():
                for field in (adapter.Name, adapter.Description, adapter.ServiceName):
                    if field:
                        names.append(field)
        except Exception as exc:
            errors.append("Win32_NetworkAdapter: %s" % exc)

    if not names:
        try:
            import psutil
            names = list(psutil.net_if_stats().keys())
        except Exception as exc:
            errors.append("psutil adapters: %s" % exc)

    matches = []
    for name in names:
        lowered = name.lower()
        for pattern in VPN_ADAPTER_PATTERNS:
            if pattern in lowered:
                matches.append(name)
                break
    return matches


def collect_processes(errors):
    matches = []
    try:
        import psutil
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            if not name:
                continue
            stem = name[:-4] if name.endswith(".exe") else name
            if stem in VPN_PROCESS_NAMES:
                matches.append(name)
    except Exception as exc:
        errors.append("psutil processes: %s" % exc)
    return matches


UNINSTALL_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]


def collect_software(errors):
    """Installed VPN software from the machine uninstall keys.

    HKEY_CURRENT_USER is deliberately not read: the agent runs as SYSTEM, so that
    hive is SYSTEM's, not the signed-in user's.
    """
    if IS_MACOS:
        # Bundle names under /Applications. Far faster than system_profiler
        # SPApplicationsDataType, which can take 30s on a populated machine.
        matches = []
        for directory in ("/Applications", "/Applications/Utilities"):
            try:
                for entry in os.listdir(directory):
                    lowered = entry.lower()
                    for pattern in VPN_SOFTWARE_PATTERNS:
                        if pattern in lowered:
                            matches.append(entry)
                            break
            except Exception:
                continue
        return matches

    if not IS_WINDOWS:
        return []
    matches = []
    try:
        import winreg
    except Exception as exc:
        errors.append("winreg: %s" % exc)
        return matches

    for path in UNINSTALL_PATHS:
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except Exception:
            continue
        try:
            index = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                try:
                    subkey = winreg.OpenKey(root, subkey_name)
                    try:
                        display = winreg.QueryValueEx(subkey, "DisplayName")[0]
                    finally:
                        winreg.CloseKey(subkey)
                except Exception:
                    continue
                lowered = display.lower()
                for pattern in VPN_SOFTWARE_PATTERNS:
                    if pattern in lowered:
                        matches.append(display)
                        break
        finally:
            winreg.CloseKey(root)
    return matches


def collect_dns(conn, errors):
    """Configured DNS servers, and any that belong to a known VPN provider."""
    servers = []
    if conn is not None:
        try:
            for cfg in conn.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                for server in (cfg.DNSServerSearchOrder or []):
                    if server not in servers:
                        servers.append(server)
        except Exception as exc:
            errors.append("Win32_NetworkAdapterConfiguration: %s" % exc)

    if not servers and IS_MACOS:
        output = _run(["/usr/sbin/scutil", "--dns"], timeout=20)
        for match in re.findall(r"nameserver\[\d+\]\s*:\s*([0-9a-fA-F:.]+)", output):
            if match not in servers:
                servers.append(match)

    if not servers and IS_WINDOWS:
        output = _run(["ipconfig", "/all"], timeout=30)
        for match in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", output):
            if match not in servers:
                servers.append(match)

    vpn_servers = [s for s in servers if s in VPN_DNS_SERVERS]
    return servers, vpn_servers


def collect_routes(conn, errors):
    """Detect the full-tunnel routing signature.

    A full-tunnel client usually installs 0.0.0.0/128.0.0.0 and 128.0.0.0/128.0.0.0,
    a pair that covers the whole address space at a longer prefix than the real
    default route, so it wins without deleting it. Two or more default routes is a
    weaker second signal.
    """
    routes = []
    if conn is not None:
        try:
            for route in conn.Win32_IP4RouteTable():
                routes.append((route.Destination, route.Mask))
        except Exception as exc:
            errors.append("Win32_IP4RouteTable: %s" % exc)

    if IS_MACOS:
        # BSD netstat prints CIDR shorthand, so the same full-tunnel signature
        # reads as "0/1" and "128.0/1" rather than the Windows mask form.
        output = _run(["/usr/sbin/netstat", "-rn", "-f", "inet"], timeout=30)
        destinations = []
        for line in output.splitlines():
            fields = line.split()
            if fields:
                destinations.append(fields[0])
        half_a = "0/1" in destinations
        half_b = "128.0/1" in destinations
        return {
            "split_default_pair": bool(half_a and half_b),
            "default_route_count": destinations.count("default"),
            "route_count": len(destinations),
        }

    if not routes and IS_WINDOWS:
        output = _run(["route", "print", "-4"], timeout=30)
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 2 and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", fields[0]):
                routes.append((fields[0], fields[1]))

    half_a = ("0.0.0.0", "128.0.0.0") in routes
    half_b = ("128.0.0.0", "128.0.0.0") in routes
    default_count = sum(1 for dest, mask in routes
                        if dest == "0.0.0.0" and mask == "0.0.0.0")
    return {
        "split_default_pair": bool(half_a and half_b),
        "default_route_count": default_count,
        "route_count": len(routes),
    }


def collect_gateway_fingerprint(errors):
    """The default gateway's MAC address: a network fingerprint with no gate on it.

    WHY THIS EXISTS. The BSSID layer is the strongest location signal in this
    detection and it is unavailable on macOS: Apple gates BSSID behind Location
    Services authorization for the calling process and root does not satisfy it
    (measured 2026-11-06 through the agent, every macOS row since reports
    wifi_method `none`). That left macOS a three-axis detection.

    The gateway MAC recovers most of what was lost, and is arguably the better
    signal of the two:

      * It is layer 2, BELOW any tunnel, so a VPN cannot change it. That is the
        same property that makes a BSSID worth collecting.
      * Nothing gates ARP. No entitlement, no Location Services, no MDM profile.
      * It works on a WIRED connection, where there is no BSSID to read at all,
        which covers the Mac Studio, the Mac mini and every server.
      * It is stable per network and distinct between networks: a home router,
        an office switch and a hotel gateway are three different MACs.

    What it is not: a coordinate. Like a BSSID it answers "is this the same
    network as last time", which is exactly what the baseline comparison asks.

    THE TRAP THIS AVOIDS. A full-tunnel VPN installs its own default route, so
    naively reading "the default gateway" returns the tunnel's and the signal
    goes constant. Every default route is collected here, the link-local and
    tunnel pseudo-gateways are dropped, and what remains is resolved through
    the ARP cache, which only ever holds real L2 neighbours.
    """
    gateways, macs, method = [], [], "none"

    if IS_MACOS or IS_LINUX:
        if IS_MACOS:
            output = _run(["/usr/sbin/netstat", "-rn", "-f", "inet"], timeout=30)
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 2 and fields[0] == "default":
                    gateways.append(fields[1])
            method = "netstat"
        else:
            output = _run(["/sbin/ip", "-4", "route", "show", "default"], timeout=30)
            for line in output.splitlines():
                fields = line.split()
                if "via" in fields:
                    gateways.append(fields[fields.index("via") + 1])
            method = "iproute"
    elif IS_WINDOWS:
        output = _run(["route", "print", "-4"], timeout=30)
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[0] == "0.0.0.0" and fields[1] == "0.0.0.0":
                gateways.append(fields[2])
        method = "route"

    # A tunnel's "gateway" is a link#N or an interface name, never an address.
    gateways = [g for g in gateways
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", g or "")
                and not g.startswith("169.254.")]
    gateways = sorted(set(gateways))

    for gateway in gateways:
        arp = _run(["arp", "-n", gateway], timeout=15)
        found = MAC_RE.findall(arp)
        for mac in found:
            mac = mac.lower()
            # macOS prints a short form (c8:29:c8:fb:82:16 is already padded,
            # but 0:1e:... appears for octets under 0x10). Normalise so today's
            # value compares equal to the one in the baseline.
            mac = ":".join(p.zfill(2) for p in mac.split(":"))
            if mac not in macs and not mac.startswith("00:00:00:00:00"):
                macs.append(mac)

    if gateways and not macs:
        errors.append("gateway %s did not resolve to a MAC in the ARP cache"
                      % ",".join(gateways))
    if not gateways:
        method = "none"
        errors.append("no IPv4 default gateway found")

    return {"gateway_ips": gateways, "gateway_macs": macs, "gateway_method": method}


# ---------------------------------------------------------------------------
# 4. Path and latency
# ---------------------------------------------------------------------------

def collect_first_public_hop(errors):
    """First non-private hop on the way out. Router-level VPN shows up here."""
    try:
        from icmplib import traceroute
        hops = traceroute("8.8.8.8", count=1, max_hops=8, timeout=1)
        for hop in hops:
            if not _is_private_v4(hop.address):
                return {"address": hop.address,
                        "distance": hop.distance,
                        "rtt_ms": round(hop.avg_rtt, 2)}
        return {"address": None, "distance": None, "rtt_ms": None}
    except Exception as exc:
        errors.append("icmplib traceroute: %s" % exc)

    if IS_MACOS:
        output = _run(["/usr/sbin/traceroute", "-n", "-m", "8", "-w", "1",
                       "-q", "1", "8.8.8.8"], timeout=60)
    elif IS_WINDOWS:
        output = _run(["tracert", "-d", "-h", "8", "-w", "1000", "8.8.8.8"],
                      timeout=60)
    else:
        return {"address": None, "distance": None, "rtt_ms": None}
    for line in output.splitlines():
        for addr in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line):
            if not _is_private_v4(addr):
                return {"address": addr, "distance": None, "rtt_ms": None}
    return {"address": None, "distance": None, "rtt_ms": None}


def _parse_anchors(spec):
    """Turn "host:port,host" into [(host, port)]. Bare host gets the default port."""
    anchors = []
    for item in (spec or "").split(","):
        item = item.strip()
        if not item:
            continue
        if ":" in item:
            host, _, port = item.rpartition(":")
            try:
                anchors.append((host, int(port)))
                continue
            except ValueError:
                pass
        anchors.append((item, DEFAULT_LATENCY_PORT))
    return anchors


def _tcp_rtt_ms(host, port, attempts=3):
    """Best of N TCP connect times. Best, not mean, because a single scheduler
    stall or retransmit inflates a mean far more than it inflates a minimum."""
    best = None
    for _ in range(attempts):
        started = time.time()
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=2)
            elapsed = (time.time() - started) * 1000.0
            if best is None or elapsed < best:
                best = elapsed
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
    return round(best, 1) if best is not None else None


TAILSCALE_BINARIES = [
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    "/usr/local/bin/tailscale",
    "/usr/bin/tailscale",
    r"C:\Program Files\Tailscale\tailscale.exe",
]


def collect_tailscale(errors):
    """Home DERP region and direct-versus-relay counts.

    Why this is needed before an anchor RTT means anything: Tailscale carries a
    peer either direct (UDP hole-punched) or through a DERP relay. A flip from
    direct to relay inflates RTT and is caused by NAT conditions, not geography,
    so it looks exactly like travel. Capture the path and the baseline can
    compare direct-to-direct and relay-to-relay instead of chasing it.

    The home DERP region is a free coarse geolocation, because Tailscale homes to
    the nearest one. It is NOT trustworthy against the threat being detected: a
    full-tunnel consumer VPN carries the Tailscale underlay too, so DERP is
    chosen near the VPN exit. It catches travel, not spoofing.
    """
    info = {"derp": None, "direct_peers": 0, "relay_peers": 0}
    for binary in TAILSCALE_BINARIES:
        if not os.path.exists(binary):
            continue
        output = _run([binary, "status", "--json"], timeout=20)
        if not output:
            continue
        try:
            status = json.loads(output)
        except ValueError:
            continue
        info["derp"] = (status.get("Self") or {}).get("Relay") or None
        for peer in (status.get("Peer") or {}).values():
            if peer.get("Relay"):
                info["relay_peers"] += 1
            elif peer.get("CurAddr"):
                info["direct_peers"] += 1
        return info
    return info


def collect_latency(anchor_spec, errors):
    """Measure RTT to positional anchors, and separately to the anycast set.

    Returns both, labelled, and never mixes them. `anchor_rtts` is the only field
    a distance comparison may use; `anycast_rtt_ms` is a liveness check.

    The values are returned per anchor rather than averaged so the comparison can
    be made against each device's own history. A global threshold does not work
    here: hotel wifi in Sacramento is slower than fibre in Austin, so a fixed
    cutoff flags the wrong people in both directions. The question worth asking is
    whether THIS device is far off ITS OWN baseline, which is an XQL job over the
    collected rows, not something the endpoint can answer in one run.
    """
    positional = _parse_anchors(anchor_spec)
    anchor_rtts = {}
    for host, port in positional:
        anchor_rtts["%s:%d" % (host, port)] = _tcp_rtt_ms(host, port)
    if positional and all(v is None for v in anchor_rtts.values()):
        errors.append("no positional anchor reachable")

    anycast = [_tcp_rtt_ms(h, p, attempts=1) for h, p in ANYCAST_ANCHORS]
    measured = [v for v in anycast if v is not None]

    # Reported as a count, not inferred from a null. All three failing means
    # outbound 53 is blocked, which guest and hotel networks routinely do to
    # force their own resolver. That is a "not your own network" signal in its
    # own right and it was being thrown away as a missing value.
    return {
        "anchor_rtts": anchor_rtts,
        "anchor_type": "unicast" if positional else "none",
        "anycast_reachable": len(measured),
        "anycast_rtt_ms": round(sum(measured) / len(measured), 1) if measured else None,
    }


# ---------------------------------------------------------------------------
# 5. Enrichment. Only runs when enrich=true. See the module docstring for why
#    the default is to do this server-side instead.
# ---------------------------------------------------------------------------

def _requests():
    import requests
    return requests


def geolocate_wifi(access_points, api_key, errors):
    if len(access_points) < 2:
        errors.append("geolocate skipped: need 2+ access points, have %d"
                      % len(access_points))
        return None
    payload = {"considerIp": False, "wifiAccessPoints": []}
    for access_point in access_points[:30]:
        entry = {"macAddress": access_point["macAddress"]}
        if "signalStrength" in access_point:
            entry["signalStrength"] = access_point["signalStrength"]
        payload["wifiAccessPoints"].append(entry)
    try:
        response = _requests().post(
            GOOGLE_GEOLOCATE_URL, params={"key": api_key}, json=payload, timeout=30
        )
        if response.status_code != 200:
            errors.append("google geolocate HTTP %d" % response.status_code)
            return None
        body = response.json()
        return {"lat": body["location"]["lat"],
                "lng": body["location"]["lng"],
                "accuracy_m": body.get("accuracy")}
    except Exception as exc:
        errors.append("google geolocate: %s" % exc)
        return None


def lookup_ip_info(errors):
    try:
        response = _requests().get(IPAPI_URL, timeout=15)
        body = response.json()
        if body.get("status") != "success":
            errors.append("ip-api: %s" % body.get("message"))
            return None
        return body
    except Exception as exc:
        errors.append("ip-api: %s" % exc)
        return None


def reverse_geocode(lat, lng, errors):
    try:
        response = _requests().get(
            NOMINATIM_URL,
            params={"lat": lat, "lon": lng, "format": "json", "zoom": 10},
            headers={"User-Agent": "cortex-vpn-location-detect/%s" % SCRIPT_VERSION},
            timeout=15,
        )
        address = response.json().get("address", {})
        city = (address.get("city") or address.get("town")
                or address.get("village") or address.get("county"))
        return ", ".join([p for p in (city, address.get("state"),
                                      address.get("country")) if p])
    except Exception as exc:
        errors.append("reverse geocode: %s" % exc)
        return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _split_sanctioned(values, sanctioned_patterns):
    """Partition matches into (unsanctioned, sanctioned)."""
    unsanctioned, sanctioned = [], []
    for value in values:
        lowered = value.lower()
        if any(pattern in lowered for pattern in sanctioned_patterns):
            sanctioned.append(value)
        else:
            unsanctioned.append(value)
    return unsanctioned, sanctioned


def run_detection(google_api_key="", enrich=False, scan_wifi=True,
                  latency_anchors="", sanctioned_patterns=""):
    started = time.time()
    errors = []
    indicators = []
    score = 0

    def add(name, points, confidence):
        indicators.append("%s(%s,+%d)" % (name, confidence, points))
        return points

    allowed = [p.strip().lower() for p in (sanctioned_patterns or "").split(",")
               if p.strip()] or DEFAULT_SANCTIONED_PATTERNS

    access_points = []
    wifi_method = "skipped"
    if scan_wifi:
        access_points, wifi_method = collect_wifi(errors)

    timezone_info = collect_timezone(errors)
    conn = _wmi_connection(errors) if IS_WINDOWS else None

    adapters, ok_adapters = _split_sanctioned(collect_adapters(conn, errors), allowed)
    processes, ok_processes = _split_sanctioned(collect_processes(errors), allowed)
    software, ok_software = _split_sanctioned(collect_software(errors), allowed)
    dns_servers, vpn_dns = collect_dns(conn, errors)
    routing = collect_routes(conn, errors)
    gateway = collect_gateway_fingerprint(errors)
    first_hop = collect_first_public_hop(errors)
    latency = collect_latency(latency_anchors, errors)
    tailscale = collect_tailscale(errors)

    if adapters:
        score += add("vpn_adapter", SCORE_VPN_ADAPTER, "HIGH")
    if processes:
        score += add("vpn_process", SCORE_VPN_PROCESS, "HIGH")
    if software:
        score += add("vpn_software", SCORE_VPN_SOFTWARE, "HIGH")
    if vpn_dns:
        score += add("vpn_dns", SCORE_VPN_DNS, "MEDIUM")
    if routing["split_default_pair"]:
        score += add("full_tunnel_routing", SCORE_SPLIT_DEFAULT_ROUTE, "MEDIUM")

    physical_location = None
    ip_location = None
    ip_info = None
    fix = None
    in_california = None

    if enrich:
        if google_api_key and access_points:
            fix = geolocate_wifi(access_points, google_api_key, errors)
        ip_info = lookup_ip_info(errors)

        if fix:
            in_california = _in_california(fix["lat"], fix["lng"])
            physical_location = reverse_geocode(fix["lat"], fix["lng"], errors)
            if in_california is False:
                score += add("physical_location_outside_ca",
                             SCORE_LOCATION_OUTSIDE_CA, "CRITICAL")

        if ip_info:
            ip_location = ", ".join(
                [p for p in (ip_info.get("city"), ip_info.get("regionName"),
                             ip_info.get("country")) if p]
            )
            if ip_info.get("hosting") or ip_info.get("proxy"):
                score += add("ip_datacenter_or_proxy", SCORE_IP_VPN_ASN, "HIGH")

            band = TIMEZONE_LONGITUDE.get(timezone_info.get("timezone_key"))
            longitude = ip_info.get("lon")
            if band and longitude is not None:
                if not (band[0] <= longitude <= band[1]):
                    score += add("timezone_ip_mismatch",
                                 SCORE_TIMEZONE_MISMATCH, "HIGH")

    if score >= 100:
        confidence = "CRITICAL"
    elif score >= 70:
        confidence = "HIGH"
    elif score >= 40:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    bssids = [ap["macAddress"] for ap in access_points]

    # No nulls in the returned dict. A None in a typed output column is the
    # other half of the 500 described in build_manifest.py, and it is untested
    # even for `string`. Empty strings are skipped by the dataset push, so this
    # changes nothing downstream.
    def _s(value):
        return "" if value is None else value

    result = {
        "schema_version": SCRIPT_VERSION,
        "scanned_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": socket.gethostname(),
        "enriched": bool(enrich),

        "confidence": confidence,
        "score": score,
        "max_score": MAX_SCORE,
        "indicators": _join(indicators),

        "wifi_method": wifi_method,
        "bssid_count": len(bssids),
        # Carried back so a playbook can resolve the fix server-side, deduped
        # across endpoints, with the API key held in the credential store.
        "bssids": _join(bssids, limit=30),
        "bssid_payload_b64": base64.b64encode(
            json.dumps(access_points).encode("utf-8")
        ).decode("ascii") if access_points else "",

        "timezone_key": timezone_info.get("timezone_key"),
        "utc_offset_hours": timezone_info.get("utc_offset_hours"),

        "vpn_adapters": _join(adapters),
        "vpn_processes": _join(processes),
        "vpn_software": _join(software),
        "sanctioned_vpn": _join(ok_adapters + ok_processes + ok_software),
        "dns_servers": _join(dns_servers),
        "vpn_dns_servers": _join(vpn_dns),
        "split_default_pair": routing["split_default_pair"],
        "default_route_count": routing["default_route_count"],

        # L2 network identity. Survives a VPN and needs no entitlement,
        # which is what makes it the macOS replacement for the BSSID set.
        "gateway_ips": _join(gateway["gateway_ips"]),
        "gateway_macs": _join(gateway["gateway_macs"]),
        "gateway_method": gateway["gateway_method"],

        "first_public_hop": first_hop.get("address"),
        "first_public_hop_distance": first_hop.get("distance"),
        # Per anchor, deliberately not averaged, and never mixed with anycast.
        # The baseline comparison is an XQL job over these rows, not a threshold.
        "anchor_rtts": json.dumps(latency.get("anchor_rtts") or {}),
        "anchor_type": latency.get("anchor_type"),
        "anycast_reachable": latency.get("anycast_reachable"),
        "anycast_rtt_ms": latency.get("anycast_rtt_ms"),
        "tailscale_derp": tailscale.get("derp"),
        "tailscale_direct_peers": tailscale.get("direct_peers"),
        "tailscale_relay_peers": tailscale.get("relay_peers"),

        "physical_location": physical_location,
        "physical_lat": fix["lat"] if fix else None,
        "physical_lng": fix["lng"] if fix else None,
        "in_california": in_california,
        "ip_address": ip_info.get("query") if ip_info else None,
        "ip_location": ip_location,
        "ip_asn": ip_info.get("as") if ip_info else None,
        "ip_isp": ip_info.get("isp") if ip_info else None,

        "duration_s": round(time.time() - started, 1),
        "errors": _join(errors, limit=12),
    }
    return {key: _s(value) for key, value in result.items()}


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "y")


if __name__ == "__main__":
    # Local testing outside the agent:
    #   python vpn_location_detect.py [api_key] [enrich] [scan_wifi] [anchors] [sanctioned]
    key = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "GOOGLE_GEOLOCATION_API_KEY", "")
    do_enrich = _parse_bool(sys.argv[2]) if len(sys.argv) > 2 else False
    do_wifi = _parse_bool(sys.argv[3]) if len(sys.argv) > 3 else True
    anchors = sys.argv[4] if len(sys.argv) > 4 else ""
    sanctioned = sys.argv[5] if len(sys.argv) > 5 else ""
    try:
        print(json.dumps(
            run_detection(key, do_enrich, do_wifi, anchors, sanctioned), indent=2))
    except Exception:
        traceback.print_exc()
        sys.exit(1)
