#!/bin/bash
#
# WiFi BSSID Geolocation Script
# Uses nearby WiFi access points to determine physical location via Google Geolocation API
#
# This script:
# 1. Scans for nearby WiFi networks (BSSIDs)
# 2. Sends BSSIDs to Google Geolocation API
# 3. Returns lat/lng coordinates of actual physical location
#
# Usage: ./wifi-geolocation.sh [API_KEY]
# Or set GOOGLE_GEOLOCATION_API_KEY environment variable
#

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# California bounding box (for validation)
CA_LAT_MIN=32.53
CA_LAT_MAX=42.01
CA_LNG_MIN=-124.48
CA_LNG_MAX=-114.13

# API Key handling
API_KEY="${1:-$GOOGLE_GEOLOCATION_API_KEY}"

if [ -z "$API_KEY" ]; then
    echo -e "${RED}Error: No API key provided${NC}"
    echo "Usage: $0 <API_KEY>"
    echo "Or set GOOGLE_GEOLOCATION_API_KEY environment variable"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}WiFi BSSID Geolocation Detection${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
    OS="windows"
else
    echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo -e "${YELLOW}Detected OS: $OS${NC}"
echo ""

# Function to scan WiFi networks on macOS
scan_wifi_macos() {
    echo -e "${YELLOW}Scanning nearby WiFi networks...${NC}"

    if [ ! -f "$AIRPORT" ]; then
        echo -e "${RED}Error: airport utility not found at $AIRPORT${NC}"
        exit 1
    fi

    # Run airport scan (requires WiFi to be enabled)
    SCAN_OUTPUT=$("$AIRPORT" -s 2>/dev/null)

    if [ -z "$SCAN_OUTPUT" ]; then
        echo -e "${RED}Error: No WiFi networks found. Is WiFi enabled?${NC}"
        exit 1
    fi

    # Parse the output - skip header line
    # Format: SSID BSSID RSSI CHANNEL HT CC SECURITY
    echo "$SCAN_OUTPUT" | tail -n +2 | while IFS= read -r line; do
        # Extract BSSID (MAC address format: xx:xx:xx:xx:xx:xx)
        BSSID=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
        # Extract RSSI (negative number)
        RSSI=$(echo "$line" | grep -oE '\s-[0-9]+\s' | tr -d ' ')

        if [ -n "$BSSID" ] && [ -n "$RSSI" ]; then
            echo "${BSSID}|${RSSI}"
        fi
    done
}

# Function to scan WiFi networks on Linux
scan_wifi_linux() {
    echo -e "${YELLOW}Scanning nearby WiFi networks...${NC}"

    # Try nmcli first
    if command -v nmcli &> /dev/null; then
        nmcli -t -f BSSID,SIGNAL dev wifi list 2>/dev/null | while IFS=':' read -r bssid signal; do
            # Convert signal percentage to dBm (approximate)
            RSSI=$(( signal / 2 - 100 ))
            echo "${bssid}|${RSSI}"
        done
    elif command -v iwlist &> /dev/null; then
        # Fallback to iwlist
        sudo iwlist scan 2>/dev/null | grep -E 'Address|Signal' | paste - - | while read -r line; do
            BSSID=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}')
            RSSI=$(echo "$line" | grep -oE '\-[0-9]+' | head -1)
            if [ -n "$BSSID" ] && [ -n "$RSSI" ]; then
                echo "${BSSID}|${RSSI}"
            fi
        done
    else
        echo -e "${RED}Error: Neither nmcli nor iwlist found${NC}"
        exit 1
    fi
}

# Function to scan WiFi networks on Windows (via PowerShell)
scan_wifi_windows() {
    echo -e "${YELLOW}Scanning nearby WiFi networks...${NC}"

    powershell.exe -Command '
        $networks = netsh wlan show networks mode=bssid
        $bssid = ""
        $signal = ""
        $networks | ForEach-Object {
            if ($_ -match "BSSID\s+\d+\s+:\s+(.+)") {
                $bssid = $matches[1].Trim()
            }
            if ($_ -match "Signal\s+:\s+(\d+)%") {
                $signal = [int]$matches[1]
                $rssi = [int]($signal / 2 - 100)
                Write-Output "$bssid|$rssi"
            }
        }
    '
}

# Collect WiFi data based on OS
case $OS in
    macos)
        WIFI_DATA=$(scan_wifi_macos)
        ;;
    linux)
        WIFI_DATA=$(scan_wifi_linux)
        ;;
    windows)
        WIFI_DATA=$(scan_wifi_windows)
        ;;
esac

# Check if we got any data
if [ -z "$WIFI_DATA" ]; then
    echo -e "${RED}Error: No WiFi networks detected${NC}"
    exit 1
fi

# Count networks found
NETWORK_COUNT=$(echo "$WIFI_DATA" | wc -l | tr -d ' ')
echo -e "${GREEN}Found $NETWORK_COUNT nearby WiFi networks${NC}"
echo ""

# Build JSON payload for Google Geolocation API
echo -e "${YELLOW}Building API request...${NC}"

# Start JSON array
JSON_ARRAY="["
FIRST=true

# Take top 10 strongest signals
echo "$WIFI_DATA" | sort -t'|' -k2 -nr | head -10 | while IFS='|' read -r bssid rssi; do
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo ","
    fi
    # Convert BSSID format (remove colons for some APIs, keep for Google)
    echo "{\"macAddress\":\"$bssid\",\"signalStrength\":$rssi}"
done > /tmp/wifi_aps.json

# Construct full JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
  "wifiAccessPoints": [
$(cat /tmp/wifi_aps.json | tr '\n' ',' | sed 's/,$//')
  ]
}
EOF
)

echo -e "${BLUE}Request payload:${NC}"
echo "$JSON_PAYLOAD" | head -20
echo ""

# Call Google Geolocation API
echo -e "${YELLOW}Querying Google Geolocation API...${NC}"

RESPONSE=$(curl -s -X POST \
    "https://www.googleapis.com/geolocation/v1/geolocate?key=${API_KEY}" \
    -H "Content-Type: application/json" \
    -d "$JSON_PAYLOAD")

echo -e "${BLUE}API Response:${NC}"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
echo ""

# Parse response
if echo "$RESPONSE" | grep -q "error"; then
    echo -e "${RED}Error from API:${NC}"
    echo "$RESPONSE" | python3 -c "import sys,json; err=json.load(sys.stdin).get('error',{}); print(f\"Code: {err.get('code')}\nMessage: {err.get('message')}\")" 2>/dev/null
    exit 1
fi

# Extract coordinates
LAT=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['location']['lat'])" 2>/dev/null)
LNG=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['location']['lng'])" 2>/dev/null)
ACCURACY=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['accuracy'])" 2>/dev/null)

if [ -z "$LAT" ] || [ -z "$LNG" ]; then
    echo -e "${RED}Error: Could not parse coordinates from response${NC}"
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}LOCATION RESULTS${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Latitude:  ${BLUE}$LAT${NC}"
echo -e "Longitude: ${BLUE}$LNG${NC}"
echo -e "Accuracy:  ${BLUE}${ACCURACY}m${NC}"
echo ""

# Google Maps link
MAPS_URL="https://www.google.com/maps?q=${LAT},${LNG}"
echo -e "${YELLOW}Google Maps:${NC} $MAPS_URL"
echo ""

# Check if location is within California
echo -e "${YELLOW}Checking California bounds...${NC}"

IN_CALIFORNIA=$(python3 -c "
lat = $LAT
lng = $LNG
lat_min, lat_max = $CA_LAT_MIN, $CA_LAT_MAX
lng_min, lng_max = $CA_LNG_MIN, $CA_LNG_MAX

if lat_min <= lat <= lat_max and lng_min <= lng <= lng_max:
    print('YES')
else:
    print('NO')
")

if [ "$IN_CALIFORNIA" = "YES" ]; then
    echo -e "${GREEN}[PASS] Device is physically located within California${NC}"
    echo ""
    echo -e "${GREEN}No VPN location spoofing detected based on WiFi geolocation.${NC}"
else
    echo -e "${RED}[ALERT] Device is physically located OUTSIDE California!${NC}"
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}POTENTIAL VPN LOCATION SPOOFING DETECTED${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "The device's WiFi environment indicates it is NOT in California."
    echo "If this device claims a California IP address, the user may be"
    echo "using a VPN to mask their true physical location."
    echo ""

    # Get approximate location name using reverse geocoding
    echo -e "${YELLOW}Attempting to identify location...${NC}"
    LOCATION_INFO=$(curl -s "https://nominatim.openstreetmap.org/reverse?lat=${LAT}&lon=${LNG}&format=json" \
        -H "User-Agent: VPN-Detection-Script/1.0")

    if [ -n "$LOCATION_INFO" ]; then
        CITY=$(echo "$LOCATION_INFO" | python3 -c "import sys,json; d=json.load(sys.stdin).get('address',{}); print(d.get('city') or d.get('town') or d.get('village','Unknown'))" 2>/dev/null)
        STATE=$(echo "$LOCATION_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('address',{}).get('state','Unknown'))" 2>/dev/null)
        COUNTRY=$(echo "$LOCATION_INFO" | python3 -c "import sys,json; print(json.load(sys.stdin).get('address',{}).get('country','Unknown'))" 2>/dev/null)

        echo -e "Detected Location: ${RED}${CITY}, ${STATE}, ${COUNTRY}${NC}"
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Script completed at $(date)${NC}"
echo -e "${BLUE}========================================${NC}"

# Cleanup
rm -f /tmp/wifi_aps.json
