# Rogue VPN Detection

Comprehensive multi-layered detection system for identifying users circumventing geographic work requirements using consumer VPNs, including router-level VPN detection.

## Overview

This tool detects VPN location spoofing by analyzing multiple indicators:

| Method | Confidence | Description |
|--------|------------|-------------|
| WiFi BSSID Geolocation | CRITICAL | Physical location via nearby WiFi access points (Google API) |
| Timezone vs IP Mismatch | HIGH | System timezone doesn't match IP geolocation |
| Source IP ASN Classification | HIGH | IP belongs to known VPN/datacenter provider |
| Network Hop Analysis | HIGH | Router-level VPN - first hop to VPN ASN |
| Virtual Network Adapters | HIGH | TAP, Wintun, WireGuard, NordLynx adapters |
| VPN Client Processes | HIGH | nordvpn.exe, expressvpn.exe, etc. |
| VPN Registry/Software Scan | HIGH | Installed VPN software in registry |
| DNS Configuration | MEDIUM | VPN DNS servers configured |
| Routing Table Anomalies | MEDIUM | Full-tunnel VPN routing pattern |
| Windows Location Services | MEDIUM | Built-in Windows GPS/WiFi location |
| Latency Analysis | LOW-MED | Network timing anomalies |

## Key Feature: Router-Level VPN Detection

Traditional VPN detection looks for VPN software on the endpoint. This tool also detects VPNs running on the user's router by:

- Analyzing the network path (traceroute) to identify the first public hop
- Checking if traffic exits through known VPN/datacenter ASNs
- Comparing physical location (WiFi BSSID) against IP geolocation

## Scoring System

| Score | Confidence | Meaning |
|-------|------------|---------|
| 100+ | CRITICAL | VPN spoofing almost certain |
| 70-99 | HIGH | Strong evidence of VPN spoofing |
| 40-69 | MEDIUM | Suspicious activity, requires review |
| 0-39 | LOW | No clear indication of spoofing |

## Files

### Windows (Primary)
- `vpn-location-detection-full.ps1` - Full detection script with all 11 methods
- `wifi-geolocation-windows.ps1` - WiFi BSSID geolocation only (simpler)

### macOS/Linux (Limited)
- `wifi-geolocation.py` - Cross-platform Python script
- `wifi-scanner.swift` - macOS WiFi scanner (requires Location Services)

**Note:** macOS restricts BSSID access for privacy. The macOS tools require Location Services permission and may not work in all scenarios.

## Usage

### Windows (Recommended)

```powershell
# Set API key
$env:GOOGLE_GEOLOCATION_API_KEY = "your-api-key"

# Run full detection
.\vpn-location-detection-full.ps1

# JSON output for automation
.\vpn-location-detection-full.ps1 -OutputJson

# Skip WiFi check (no WiFi adapter)
.\vpn-location-detection-full.ps1 -SkipWifi
```

### Python (Cross-platform)

```bash
export GOOGLE_GEOLOCATION_API_KEY="your-api-key"
python3 wifi-geolocation.py
```

## Requirements

- Windows 10/11 with PowerShell 5.1+
- Google Geolocation API key
- WiFi adapter (for BSSID geolocation)
- Administrator rights recommended

## API Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Enable the Geolocation API
3. Create an API key and restrict it to Geolocation API
4. Cost: ~$5 per 1,000 requests

## Known VPN Providers Detected

NordVPN, ExpressVPN, Surfshark, CyberGhost, ProtonVPN, Private Internet Access, Mullvad, Windscribe, TunnelBear, IPVanish, HideMyAss, VyprVPN, Hotspot Shield, OpenVPN, WireGuard, and major cloud/datacenter providers (AWS, Azure, DigitalOcean, etc.)

## Exit Codes

- `0` - LOW confidence (likely clean)
- `1` - MEDIUM confidence (needs review)
- `2` - HIGH confidence (likely spoofing)
- `3` - CRITICAL confidence (spoofing detected)

## License

Internal use only.
