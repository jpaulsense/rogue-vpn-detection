#!/usr/bin/env python3
"""
WiFi BSSID Geolocation Script

Uses nearby WiFi access points to determine physical location via Google Geolocation API.
This is the highest-confidence detection method for VPN location spoofing.

Requirements:
- Python 3.6+
- requests library (pip install requests)
- macOS: Uses system_profiler or CoreWLAN
- Windows: Uses netsh wlan
- Linux: Uses nmcli or iwlist

Usage:
    python3 wifi-geolocation.py [--api-key YOUR_KEY]
    python3 wifi-geolocation.py --test  # Test with sample data

Or set GOOGLE_GEOLOCATION_API_KEY environment variable.

IMPORTANT: On modern macOS (12+), BSSID access is restricted for privacy.
The script will work best on Windows endpoints. For macOS testing,
use the --test flag with sample BSSIDs.
"""

import subprocess
import json
import re
import sys
import os
import argparse
import urllib.request
import urllib.error
from typing import List, Dict, Optional, Tuple

# California bounding box
CA_BOUNDS = {
    'lat_min': 32.53,
    'lat_max': 42.01,
    'lng_min': -124.48,
    'lng_max': -114.13
}

# ANSI color codes
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def get_api_key() -> str:
    """Get API key from environment or .env file."""
    # Check environment variable first
    api_key = os.environ.get('GOOGLE_GEOLOCATION_API_KEY')
    if api_key:
        return api_key

    # Check .claude/.env file
    env_paths = [
        os.path.join(os.path.dirname(__file__), '.claude', '.env'),
        os.path.expanduser('~/.claude/.env'),
    ]

    for env_path in env_paths:
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('GOOGLE_GEOLOCATION_API_KEY='):
                        return line.split('=', 1)[1].strip()

    return None


def scan_wifi_macos() -> List[Dict]:
    """Scan WiFi networks on macOS using system_profiler."""
    print(f"{Colors.YELLOW}Scanning WiFi networks (macOS)...{Colors.NC}")

    try:
        # Use system_profiler to get WiFi data
        result = subprocess.run(
            ['system_profiler', 'SPAirPortDataType', '-json'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            print(f"{Colors.RED}Error running system_profiler{Colors.NC}")
            return []

        data = json.loads(result.stdout)
        access_points = []

        # Navigate the JSON structure
        airport_data = data.get('SPAirPortDataType', [])
        for item in airport_data:
            interfaces = item.get('spairport_airport_interfaces', [])
            for interface in interfaces:
                # Get current network
                current = interface.get('spairport_current_network_information', {})
                for ssid, info in current.items():
                    if 'spairport_network_bssid' in info:
                        bssid = info.get('spairport_network_bssid', '')
                        signal = info.get('spairport_signal_noise', '')
                        # Parse signal like "-65 dBm / -95 dBm"
                        rssi = -70  # default
                        if signal:
                            match = re.search(r'-(\d+)\s*dBm', signal)
                            if match:
                                rssi = -int(match.group(1))

                        if bssid:
                            access_points.append({
                                'macAddress': bssid,
                                'signalStrength': rssi
                            })

                # Get other networks
                others = interface.get('spairport_airport_other_local_wireless_networks', [])
                for network in others:
                    for ssid, info in network.items():
                        bssid = info.get('spairport_network_bssid', '')
                        if bssid:
                            access_points.append({
                                'macAddress': bssid,
                                'signalStrength': -80  # default for others
                            })

        return access_points

    except subprocess.TimeoutExpired:
        print(f"{Colors.RED}Timeout scanning WiFi{Colors.NC}")
        return []
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}Error parsing WiFi data: {e}{Colors.NC}")
        return []
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.NC}")
        return []


def scan_wifi_macos_wdutil() -> List[Dict]:
    """Alternative: Use wdutil for WiFi scanning (requires sudo)."""
    print(f"{Colors.YELLOW}Attempting WiFi scan with wdutil...{Colors.NC}")

    try:
        # wdutil requires sudo
        result = subprocess.run(
            ['sudo', 'wdutil', 'info'],
            capture_output=True,
            text=True,
            timeout=30
        )

        access_points = []
        current_bssid = None

        for line in result.stdout.split('\n'):
            # Look for BSSID patterns
            bssid_match = re.search(r'BSSID\s*:\s*([0-9a-fA-F:]{17})', line)
            if bssid_match:
                current_bssid = bssid_match.group(1)

            rssi_match = re.search(r'RSSI\s*:\s*(-?\d+)', line)
            if rssi_match and current_bssid:
                access_points.append({
                    'macAddress': current_bssid,
                    'signalStrength': int(rssi_match.group(1))
                })
                current_bssid = None

        return access_points

    except Exception as e:
        print(f"{Colors.YELLOW}wdutil not available or requires sudo: {e}{Colors.NC}")
        return []


def scan_wifi_linux() -> List[Dict]:
    """Scan WiFi networks on Linux using nmcli or iwlist."""
    print(f"{Colors.YELLOW}Scanning WiFi networks (Linux)...{Colors.NC}")

    access_points = []

    # Try nmcli first
    try:
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'BSSID,SIGNAL', 'dev', 'wifi', 'list'],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if ':' in line:
                    parts = line.rsplit(':', 1)
                    if len(parts) == 2:
                        bssid = parts[0].replace('\\:', ':')
                        try:
                            signal_pct = int(parts[1])
                            rssi = signal_pct // 2 - 100
                            access_points.append({
                                'macAddress': bssid,
                                'signalStrength': rssi
                            })
                        except ValueError:
                            continue
            return access_points
    except FileNotFoundError:
        pass

    # Fallback to iwlist
    try:
        result = subprocess.run(
            ['sudo', 'iwlist', 'scan'],
            capture_output=True,
            text=True,
            timeout=30
        )

        current_bssid = None
        for line in result.stdout.split('\n'):
            addr_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
            if addr_match:
                current_bssid = addr_match.group(1)

            signal_match = re.search(r'Signal level[=:]?\s*(-?\d+)', line)
            if signal_match and current_bssid:
                access_points.append({
                    'macAddress': current_bssid,
                    'signalStrength': int(signal_match.group(1))
                })
                current_bssid = None

        return access_points

    except Exception as e:
        print(f"{Colors.RED}Error scanning WiFi: {e}{Colors.NC}")
        return []


def scan_wifi_windows() -> List[Dict]:
    """Scan WiFi networks on Windows using netsh."""
    print(f"{Colors.YELLOW}Scanning WiFi networks (Windows)...{Colors.NC}")

    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True,
            text=True,
            timeout=30
        )

        access_points = []
        current_bssid = None

        for line in result.stdout.split('\n'):
            bssid_match = re.search(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})', line)
            if bssid_match:
                current_bssid = bssid_match.group(1)

            signal_match = re.search(r'Signal\s*:\s*(\d+)%', line)
            if signal_match and current_bssid:
                signal_pct = int(signal_match.group(1))
                rssi = signal_pct // 2 - 100
                access_points.append({
                    'macAddress': current_bssid,
                    'signalStrength': rssi
                })
                current_bssid = None

        return access_points

    except Exception as e:
        print(f"{Colors.RED}Error scanning WiFi: {e}{Colors.NC}")
        return []


def get_test_access_points() -> List[Dict]:
    """Return sample access points for testing the API."""
    # These are fictional BSSIDs - the API will return an approximate location
    # based on its database. For testing, we use common patterns.
    print(f"{Colors.YELLOW}Using test/sample access points...{Colors.NC}")
    return [
        {"macAddress": "00:11:22:33:44:55", "signalStrength": -65},
        {"macAddress": "00:11:22:33:44:56", "signalStrength": -70},
        {"macAddress": "00:11:22:33:44:57", "signalStrength": -75},
    ]


def scan_wifi(use_test_data: bool = False) -> List[Dict]:
    """Scan WiFi networks based on OS."""
    if use_test_data:
        return get_test_access_points()

    if sys.platform == 'darwin':
        aps = scan_wifi_macos()
        if not aps:
            # Try wdutil as fallback
            aps = scan_wifi_macos_wdutil()

        if not aps:
            print(f"{Colors.YELLOW}Note: On modern macOS, BSSID access is restricted.{Colors.NC}")
            print(f"{Colors.YELLOW}Use --test flag to test with sample data, or run on Windows.{Colors.NC}")

        return aps
    elif sys.platform == 'linux':
        return scan_wifi_linux()
    elif sys.platform == 'win32':
        return scan_wifi_windows()
    else:
        print(f"{Colors.RED}Unsupported platform: {sys.platform}{Colors.NC}")
        return []


def geolocate(access_points: List[Dict], api_key: str) -> Optional[Dict]:
    """Query Google Geolocation API with WiFi access points."""
    if not access_points:
        print(f"{Colors.RED}No access points to query{Colors.NC}")
        return None

    # Take top 10 by signal strength
    sorted_aps = sorted(access_points, key=lambda x: x.get('signalStrength', -100), reverse=True)[:10]

    print(f"{Colors.YELLOW}Querying Google Geolocation API with {len(sorted_aps)} access points...{Colors.NC}")

    payload = {
        'wifiAccessPoints': sorted_aps
    }

    print(f"{Colors.BLUE}Request payload:{Colors.NC}")
    print(json.dumps(payload, indent=2))
    print()

    try:
        url = f'https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}'
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))

        if 'error' in result:
            error = result['error']
            print(f"{Colors.RED}API Error:{Colors.NC}")
            print(f"  Code: {error.get('code')}")
            print(f"  Message: {error.get('message')}")
            return None

        return result

    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        try:
            error_json = json.loads(error_body)
            error = error_json.get('error', {})
            print(f"{Colors.RED}API Error:{Colors.NC}")
            print(f"  Code: {error.get('code')}")
            print(f"  Message: {error.get('message')}")
        except:
            print(f"{Colors.RED}HTTP Error {e.code}: {error_body}{Colors.NC}")
        return None
    except urllib.error.URLError as e:
        print(f"{Colors.RED}Request error: {e}{Colors.NC}")
        return None


def reverse_geocode(lat: float, lng: float) -> Optional[Dict]:
    """Get location name from coordinates using Nominatim."""
    try:
        url = f'https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lng}&format=json'
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'VPN-Detection-Script/1.0'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception:
        return None


def is_in_california(lat: float, lng: float) -> bool:
    """Check if coordinates are within California bounds."""
    return (CA_BOUNDS['lat_min'] <= lat <= CA_BOUNDS['lat_max'] and
            CA_BOUNDS['lng_min'] <= lng <= CA_BOUNDS['lng_max'])


def main():
    parser = argparse.ArgumentParser(description='WiFi-based geolocation detection')
    parser.add_argument('--api-key', help='Google Geolocation API key')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--test', action='store_true', help='Use sample BSSIDs to test API connectivity')
    parser.add_argument('--bssid', action='append', help='Manually specify BSSID (can be used multiple times)')
    args = parser.parse_args()

    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print(f"{Colors.BLUE}WiFi BSSID Geolocation Detection{Colors.NC}")
    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print()

    # Get API key
    api_key = args.api_key or get_api_key()
    if not api_key:
        print(f"{Colors.RED}Error: No API key provided{Colors.NC}")
        print("Set GOOGLE_GEOLOCATION_API_KEY environment variable or use --api-key")
        sys.exit(1)

    print(f"{Colors.YELLOW}Platform: {sys.platform}{Colors.NC}")
    print()

    # Handle manual BSSID input
    if args.bssid:
        access_points = []
        for i, bssid in enumerate(args.bssid):
            access_points.append({
                'macAddress': bssid,
                'signalStrength': -60 - (i * 5)
            })
        print(f"{Colors.YELLOW}Using manually specified BSSIDs{Colors.NC}")
    else:
        # Scan WiFi
        access_points = scan_wifi(use_test_data=args.test)

    if not access_points:
        print(f"{Colors.RED}No WiFi access points found!{Colors.NC}")
        print()
        print("Possible reasons:")
        print("  - WiFi is disabled")
        print("  - No WiFi adapter present")
        print("  - Connected via Ethernet only")
        print("  - Insufficient permissions")
        print()
        print("On macOS, try connecting to a WiFi network first.")
        sys.exit(1)

    print(f"{Colors.GREEN}Found {len(access_points)} nearby WiFi access points{Colors.NC}")
    print()

    # Query geolocation API
    result = geolocate(access_points, api_key)

    if not result:
        print(f"{Colors.RED}Failed to get geolocation{Colors.NC}")
        sys.exit(1)

    print(f"{Colors.BLUE}API Response:{Colors.NC}")
    print(json.dumps(result, indent=2))
    print()

    # Extract coordinates
    location = result.get('location', {})
    lat = location.get('lat')
    lng = location.get('lng')
    accuracy = result.get('accuracy', 0)

    if lat is None or lng is None:
        print(f"{Colors.RED}No coordinates in response{Colors.NC}")
        sys.exit(1)

    print(f"{Colors.GREEN}========================================{Colors.NC}")
    print(f"{Colors.GREEN}LOCATION RESULTS{Colors.NC}")
    print(f"{Colors.GREEN}========================================{Colors.NC}")
    print(f"Latitude:  {Colors.BLUE}{lat}{Colors.NC}")
    print(f"Longitude: {Colors.BLUE}{lng}{Colors.NC}")
    print(f"Accuracy:  {Colors.BLUE}{accuracy}m{Colors.NC}")
    print()

    # Google Maps link
    maps_url = f"https://www.google.com/maps?q={lat},{lng}"
    print(f"{Colors.YELLOW}Google Maps:{Colors.NC} {maps_url}")
    print()

    # Check California bounds
    print(f"{Colors.YELLOW}Checking California bounds...{Colors.NC}")

    in_california = is_in_california(lat, lng)

    if in_california:
        print(f"{Colors.GREEN}[PASS] Device is physically located within California{Colors.NC}")
        print()
        print(f"{Colors.GREEN}No VPN location spoofing detected based on WiFi geolocation.{Colors.NC}")
    else:
        print(f"{Colors.RED}[ALERT] Device is physically located OUTSIDE California!{Colors.NC}")
        print()
        print(f"{Colors.RED}========================================{Colors.NC}")
        print(f"{Colors.RED}POTENTIAL VPN LOCATION SPOOFING DETECTED{Colors.NC}")
        print(f"{Colors.RED}========================================{Colors.NC}")
        print()
        print("The device's WiFi environment indicates it is NOT in California.")
        print("If this device claims a California IP address, the user may be")
        print("using a VPN to mask their true physical location.")
        print()

        # Get location name
        print(f"{Colors.YELLOW}Attempting to identify location...{Colors.NC}")
        location_info = reverse_geocode(lat, lng)

        if location_info and 'address' in location_info:
            addr = location_info['address']
            city = addr.get('city') or addr.get('town') or addr.get('village', 'Unknown')
            state = addr.get('state', 'Unknown')
            country = addr.get('country', 'Unknown')
            print(f"Detected Location: {Colors.RED}{city}, {state}, {country}{Colors.NC}")

    print()
    print(f"{Colors.BLUE}========================================{Colors.NC}")
    print(f"{Colors.BLUE}Script completed{Colors.NC}")
    print(f"{Colors.BLUE}========================================{Colors.NC}")

    # Output JSON if requested
    if args.json:
        output = {
            'latitude': lat,
            'longitude': lng,
            'accuracy_meters': accuracy,
            'in_california': in_california,
            'access_points_found': len(access_points),
            'maps_url': maps_url
        }
        print()
        print("JSON Output:")
        print(json.dumps(output, indent=2))

    sys.exit(0 if in_california else 1)


if __name__ == '__main__':
    main()
