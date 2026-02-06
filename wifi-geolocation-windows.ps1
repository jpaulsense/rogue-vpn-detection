<#
.SYNOPSIS
    WiFi BSSID Geolocation Detection Script for Windows

.DESCRIPTION
    Uses nearby WiFi access points to determine physical location via Google Geolocation API.
    This is the highest-confidence detection method for VPN location spoofing.

    The script:
    1. Scans for nearby WiFi networks (BSSIDs) using netsh wlan
    2. Sends BSSIDs to Google Geolocation API
    3. Returns lat/lng coordinates of actual physical location
    4. Compares against California boundaries

.PARAMETER ApiKey
    Google Geolocation API key. Can also be set via GOOGLE_GEOLOCATION_API_KEY environment variable.

.PARAMETER OutputJson
    Output results as JSON for machine parsing.

.EXAMPLE
    .\wifi-geolocation-windows.ps1 -ApiKey "YOUR_API_KEY"

.EXAMPLE
    $env:GOOGLE_GEOLOCATION_API_KEY = "YOUR_API_KEY"
    .\wifi-geolocation-windows.ps1

.NOTES
    Author: VPN Location Detection System
    Date: February 2026
    Requires: Windows 10/11 with WiFi adapter
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [switch]$OutputJson
)

# California bounding box
$CaBounds = @{
    LatMin = 32.53
    LatMax = 42.01
    LngMin = -124.48
    LngMax = -114.13
}

# Known VPN provider DNS servers (for additional detection)
$VpnDnsServers = @(
    '103.86.96.100', '103.86.99.100',  # NordVPN
    '10.255.255.1',                      # NordVPN internal
    '100.64.0.7',                        # ExpressVPN
    '162.252.172.57', '149.154.159.92',  # Surfshark
    '10.2.0.1',                          # CyberGhost
    '10.0.0.243',                        # ProtonVPN
    '10.8.0.1'                           # Common OpenVPN
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Get-ApiKey {
    # Check parameter first
    if ($ApiKey) { return $ApiKey }

    # Check environment variable
    if ($env:GOOGLE_GEOLOCATION_API_KEY) { return $env:GOOGLE_GEOLOCATION_API_KEY }

    # Check .env file in script directory
    $envPath = Join-Path $PSScriptRoot ".env"
    if (Test-Path $envPath) {
        $content = Get-Content $envPath -Raw
        if ($content -match 'GOOGLE_GEOLOCATION_API_KEY=(.+)') {
            return $matches[1].Trim()
        }
    }

    return $null
}

function Get-WifiNetworks {
    <#
    .SYNOPSIS
        Scans for nearby WiFi networks and returns BSSID/signal strength pairs.
    #>

    Write-ColorOutput "Scanning nearby WiFi networks..." -Color Yellow

    try {
        $wifiOutput = netsh wlan show networks mode=bssid

        if (-not $wifiOutput) {
            throw "No WiFi output received"
        }

        $accessPoints = @()
        $currentBssid = $null

        foreach ($line in $wifiOutput) {
            # Match BSSID line: "    BSSID 1                 : aa:bb:cc:dd:ee:ff"
            if ($line -match 'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})') {
                $currentBssid = $matches[1].Trim()
            }

            # Match Signal line: "    Signal             : 85%"
            if ($line -match 'Signal\s*:\s*(\d+)%' -and $currentBssid) {
                $signalPct = [int]$matches[1]
                # Convert percentage to dBm (approximate)
                $rssi = [int]($signalPct / 2) - 100

                $accessPoints += @{
                    macAddress = $currentBssid
                    signalStrength = $rssi
                }

                $currentBssid = $null
            }
        }

        return $accessPoints
    }
    catch {
        Write-ColorOutput "Error scanning WiFi: $_" -Color Red
        return @()
    }
}

function Invoke-GeolocationApi {
    param(
        [array]$AccessPoints,
        [string]$Key
    )

    if ($AccessPoints.Count -eq 0) {
        Write-ColorOutput "No access points to query" -Color Red
        return $null
    }

    # Take top 10 by signal strength
    $topAps = $AccessPoints | Sort-Object { $_.signalStrength } -Descending | Select-Object -First 10

    Write-ColorOutput "Querying Google Geolocation API with $($topAps.Count) access points..." -Color Yellow

    $payload = @{
        wifiAccessPoints = $topAps
    } | ConvertTo-Json -Depth 3

    Write-ColorOutput "Request payload:" -Color Blue
    Write-Host $payload
    Write-Host ""

    try {
        $uri = "https://www.googleapis.com/geolocation/v1/geolocate?key=$Key"

        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop

        return $response
    }
    catch {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errorDetails.error) {
            Write-ColorOutput "API Error:" -Color Red
            Write-ColorOutput "  Code: $($errorDetails.error.code)" -Color Red
            Write-ColorOutput "  Message: $($errorDetails.error.message)" -Color Red
        }
        else {
            Write-ColorOutput "Request error: $_" -Color Red
        }
        return $null
    }
}

function Get-ReverseGeocode {
    param(
        [double]$Lat,
        [double]$Lng
    )

    try {
        $uri = "https://nominatim.openstreetmap.org/reverse?lat=$Lat&lon=$Lng&format=json"
        $response = Invoke-RestMethod -Uri $uri -Headers @{"User-Agent" = "VPN-Detection-Script/1.0"} -ErrorAction Stop
        return $response
    }
    catch {
        return $null
    }
}

function Test-InCalifornia {
    param(
        [double]$Lat,
        [double]$Lng
    )

    return ($Lat -ge $CaBounds.LatMin -and $Lat -le $CaBounds.LatMax -and
            $Lng -ge $CaBounds.LngMin -and $Lng -le $CaBounds.LngMax)
}

function Get-VpnIndicators {
    <#
    .SYNOPSIS
        Checks for additional VPN indicators on the system.
    #>

    $indicators = @{
        VpnAdapters = @()
        VpnProcesses = @()
        VpnDns = @()
        VpnRoutes = $false
    }

    # Check for VPN network adapters
    $vpnAdapterPatterns = @(
        'TAP-Windows', 'Wintun', 'WireGuard', 'NordLynx',
        'Windscribe', 'Surfshark', 'ExpressVPN', 'CyberGhost',
        'ProtonVPN', 'OpenVPN', 'Hotspot Shield', 'Private Internet', 'TunnelBear'
    )

    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $desc = $_.InterfaceDescription
        $vpnAdapterPatterns | Where-Object { $desc -match $_ }
    }

    if ($adapters) {
        $indicators.VpnAdapters = @($adapters | Select-Object -ExpandProperty InterfaceDescription)
    }

    # Check for VPN processes
    $vpnProcessNames = @(
        'nordvpn', 'NordVPN', 'nordvpn-service',
        'expressvpn', 'ExpressVPN', 'expressvpn-service',
        'openvpn', 'openvpn-gui',
        'wireguard', 'wg',
        'surfshark', 'Surfshark', 'SurfsharkService',
        'cyberghost', 'CyberGhost',
        'protonvpn', 'ProtonVPN', 'ProtonVPNService',
        'pia-service', 'pia-client', 'privateinternetaccess',
        'mullvad-vpn', 'mullvad-daemon',
        'windscribe', 'WindscribeService'
    )

    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
        $vpnProcessNames -contains $_.Name
    }

    if ($processes) {
        $indicators.VpnProcesses = @($processes | Select-Object -ExpandProperty Name -Unique)
    }

    # Check DNS servers
    $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses

    $vpnDns = $dnsServers | Where-Object { $VpnDnsServers -contains $_ }
    if ($vpnDns) {
        $indicators.VpnDns = @($vpnDns)
    }

    # Check for VPN routing patterns (0.0.0.0/1 and 128.0.0.0/1)
    $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $vpnRoutes = $routes | Where-Object {
        $_.DestinationPrefix -eq '0.0.0.0/1' -or $_.DestinationPrefix -eq '128.0.0.0/1'
    }

    if ($vpnRoutes) {
        $indicators.VpnRoutes = $true
    }

    return $indicators
}

# ============================================================================
# Main Script
# ============================================================================

Write-ColorOutput "========================================" -Color Blue
Write-ColorOutput "WiFi BSSID Geolocation Detection" -Color Blue
Write-ColorOutput "========================================" -Color Blue
Write-Host ""

# Get API key
$apiKey = Get-ApiKey
if (-not $apiKey) {
    Write-ColorOutput "Error: No API key provided" -Color Red
    Write-Host "Set GOOGLE_GEOLOCATION_API_KEY environment variable or use -ApiKey parameter"
    exit 1
}

Write-ColorOutput "Platform: Windows" -Color Yellow
Write-Host ""

# Scan WiFi networks
$accessPoints = Get-WifiNetworks

if ($accessPoints.Count -eq 0) {
    Write-ColorOutput "No WiFi access points found!" -Color Red
    Write-Host ""
    Write-Host "Possible reasons:"
    Write-Host "  - WiFi is disabled"
    Write-Host "  - No WiFi adapter present"
    Write-Host "  - Connected via Ethernet only"
    Write-Host "  - WLAN AutoConfig service not running"
    exit 1
}

Write-ColorOutput "Found $($accessPoints.Count) nearby WiFi access points" -Color Green
Write-Host ""

# Query geolocation API
$result = Invoke-GeolocationApi -AccessPoints $accessPoints -Key $apiKey

if (-not $result) {
    Write-ColorOutput "Failed to get geolocation" -Color Red
    exit 1
}

Write-ColorOutput "API Response:" -Color Blue
$result | ConvertTo-Json -Depth 3 | Write-Host
Write-Host ""

# Extract coordinates
$lat = $result.location.lat
$lng = $result.location.lng
$accuracy = $result.accuracy

if (-not $lat -or -not $lng) {
    Write-ColorOutput "No coordinates in response" -Color Red
    exit 1
}

Write-ColorOutput "========================================" -Color Green
Write-ColorOutput "LOCATION RESULTS" -Color Green
Write-ColorOutput "========================================" -Color Green
Write-Host "Latitude:  $lat"
Write-Host "Longitude: $lng"
Write-Host "Accuracy:  ${accuracy}m"
Write-Host ""

# Google Maps link
$mapsUrl = "https://www.google.com/maps?q=$lat,$lng"
Write-ColorOutput "Google Maps: $mapsUrl" -Color Yellow
Write-Host ""

# Check California bounds
Write-ColorOutput "Checking California bounds..." -Color Yellow

$inCalifornia = Test-InCalifornia -Lat $lat -Lng $lng

if ($inCalifornia) {
    Write-ColorOutput "[PASS] Device is physically located within California" -Color Green
    Write-Host ""
    Write-ColorOutput "No VPN location spoofing detected based on WiFi geolocation." -Color Green
}
else {
    Write-ColorOutput "[ALERT] Device is physically located OUTSIDE California!" -Color Red
    Write-Host ""
    Write-ColorOutput "========================================" -Color Red
    Write-ColorOutput "POTENTIAL VPN LOCATION SPOOFING DETECTED" -Color Red
    Write-ColorOutput "========================================" -Color Red
    Write-Host ""
    Write-Host "The device's WiFi environment indicates it is NOT in California."
    Write-Host "If this device claims a California IP address, the user may be"
    Write-Host "using a VPN to mask their true physical location."
    Write-Host ""

    # Get location name
    Write-ColorOutput "Attempting to identify location..." -Color Yellow
    $locationInfo = Get-ReverseGeocode -Lat $lat -Lng $lng

    if ($locationInfo -and $locationInfo.address) {
        $city = if ($locationInfo.address.city) { $locationInfo.address.city }
                elseif ($locationInfo.address.town) { $locationInfo.address.town }
                else { $locationInfo.address.village }
        $state = $locationInfo.address.state
        $country = $locationInfo.address.country

        Write-ColorOutput "Detected Location: $city, $state, $country" -Color Red
    }
}

Write-Host ""

# Check for additional VPN indicators
Write-ColorOutput "Checking for VPN indicators..." -Color Yellow
$vpnIndicators = Get-VpnIndicators

$vpnScore = 0

if ($vpnIndicators.VpnAdapters.Count -gt 0) {
    Write-ColorOutput "[HIGH] VPN network adapters detected:" -Color Red
    $vpnIndicators.VpnAdapters | ForEach-Object { Write-Host "  - $_" }
    $vpnScore += 30
}

if ($vpnIndicators.VpnProcesses.Count -gt 0) {
    Write-ColorOutput "[HIGH] VPN processes running:" -Color Red
    $vpnIndicators.VpnProcesses | ForEach-Object { Write-Host "  - $_" }
    $vpnScore += 30
}

if ($vpnIndicators.VpnDns.Count -gt 0) {
    Write-ColorOutput "[MEDIUM] VPN DNS servers configured:" -Color Yellow
    $vpnIndicators.VpnDns | ForEach-Object { Write-Host "  - $_" }
    $vpnScore += 20
}

if ($vpnIndicators.VpnRoutes) {
    Write-ColorOutput "[MEDIUM] VPN routing pattern detected (0.0.0.0/1 + 128.0.0.0/1)" -Color Yellow
    $vpnScore += 20
}

if (-not $inCalifornia) {
    $vpnScore += 50
}

Write-Host ""
Write-ColorOutput "========================================" -Color Blue
Write-ColorOutput "DETECTION SCORE: $vpnScore / 150" -Color Blue
Write-ColorOutput "========================================" -Color Blue

if ($vpnScore -ge 80) {
    Write-ColorOutput "HIGH CONFIDENCE: VPN location spoofing detected" -Color Red
}
elseif ($vpnScore -ge 50) {
    Write-ColorOutput "MEDIUM CONFIDENCE: Suspicious activity detected" -Color Yellow
}
else {
    Write-ColorOutput "LOW CONFIDENCE: No clear indication of VPN spoofing" -Color Green
}

Write-Host ""
Write-ColorOutput "Script completed at $(Get-Date)" -Color Blue
Write-ColorOutput "========================================" -Color Blue

# JSON output if requested
if ($OutputJson) {
    $output = @{
        latitude = $lat
        longitude = $lng
        accuracy_meters = $accuracy
        in_california = $inCalifornia
        access_points_found = $accessPoints.Count
        maps_url = $mapsUrl
        vpn_score = $vpnScore
        vpn_indicators = $vpnIndicators
        timestamp = (Get-Date -Format "o")
    }

    Write-Host ""
    Write-Host "JSON Output:"
    $output | ConvertTo-Json -Depth 3
}

# Exit with appropriate code
if ($inCalifornia -and $vpnScore -lt 50) {
    exit 0
}
else {
    exit 1
}
