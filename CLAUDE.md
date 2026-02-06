# Device Location Checking - VPN Spoofing Detection

## Project Overview

This project implements WiFi BSSID-based geolocation detection to identify VPN location spoofing. It's based on the "Consumer VPN Location Spoofing Detection Strategy" document for detecting State of California employees who circumvent geographic work requirements.

## Key Concept

Users may use consumer VPNs (NordVPN, ExpressVPN, etc.) to route their traffic through California-based exit nodes while physically located outside California. The WiFi BSSID geolocation method is the **highest-confidence detection vector** because:

1. Every WiFi-enabled device can see nearby access point BSSIDs (MAC addresses)
2. These BSSIDs are cataloged in databases (Google, Apple, Wigle.net)
3. The physical WiFi environment **cannot be spoofed** by a VPN
4. Returns actual physical location regardless of IP-based masking

## Files

- `wifi-geolocation.py` - Cross-platform Python script (macOS/Linux/Windows)
- `wifi-geolocation-windows.ps1` - Windows PowerShell script with additional VPN detection
- `wifi-geolocation.sh` - Original bash script (deprecated, use Python version)

## API Configuration

The Google Geolocation API key is stored in `.claude/.env`:
```
GOOGLE_GEOLOCATION_API_KEY=<key>
```

Cost: ~$5 per 1,000 API requests

## Usage

### Python (Cross-platform)
```bash
# With environment variable
export GOOGLE_GEOLOCATION_API_KEY="your-key"
python3 wifi-geolocation.py

# With API key parameter
python3 wifi-geolocation.py --api-key YOUR_KEY

# Test mode (uses sample BSSIDs)
python3 wifi-geolocation.py --test

# Manually specify BSSIDs
python3 wifi-geolocation.py --bssid "00:11:22:33:44:55" --bssid "AA:BB:CC:DD:EE:FF"

# JSON output
python3 wifi-geolocation.py --json
```

### Windows PowerShell
```powershell
# With environment variable
$env:GOOGLE_GEOLOCATION_API_KEY = "your-key"
.\wifi-geolocation-windows.ps1

# With parameter
.\wifi-geolocation-windows.ps1 -ApiKey "YOUR_KEY"

# JSON output
.\wifi-geolocation-windows.ps1 -OutputJson
```

## Platform Notes

### Windows (Primary Target)
- Uses `netsh wlan show networks mode=bssid`
- Full BSSID access available
- PowerShell script includes additional VPN indicators

### macOS (Limited)
- Modern macOS (12+) restricts BSSID access for privacy
- Use `--test` flag to verify API connectivity
- For real testing, deploy to Windows endpoints

### Linux
- Uses `nmcli` or `iwlist` (may require sudo)
- Full BSSID access typically available

## California Bounding Box

```
Latitude:  32.53 to 42.01
Longitude: -124.48 to -114.13
```

## Detection Scoring (PowerShell Script)

The Windows script calculates a detection score based on multiple indicators:

| Indicator | Points | Confidence |
|-----------|--------|------------|
| Location outside California | 50 | CRITICAL |
| VPN network adapters | 30 | HIGH |
| VPN processes running | 30 | HIGH |
| VPN DNS servers | 20 | MEDIUM |
| VPN routing patterns | 20 | MEDIUM |

**Score Interpretation:**
- 80+: HIGH confidence VPN spoofing
- 50-79: MEDIUM confidence suspicious activity
- <50: LOW confidence, likely legitimate

## GCP Project

- Project ID: `prod-kzmo157frhxj`
- API enabled: `geolocation.googleapis.com`
- Service account: `jared-cicd@prod-kzmo157frhxj.iam.gserviceaccount.com`
