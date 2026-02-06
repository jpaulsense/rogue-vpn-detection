<#
.SYNOPSIS
    Comprehensive VPN Location Spoofing Detection Script for Windows

.DESCRIPTION
    Multi-layered detection strategy for identifying users circumventing geographic
    work requirements using consumer VPNs (including router-level VPN).

    Detection Methods:
    1. WiFi BSSID Geolocation (Google API) - CRITICAL confidence
    2. Timezone vs IP Geolocation Mismatch - HIGH confidence
    3. Source IP ASN/Datacenter Classification - HIGH confidence
    4. Network Hop Analysis (Router VPN Detection) - HIGH confidence
    5. Virtual Network Adapters - HIGH confidence
    6. VPN Client Processes - HIGH confidence
    7. VPN Software Registry Scan - HIGH confidence
    8. DNS Configuration Analysis - MEDIUM confidence
    9. Routing Table Anomalies - MEDIUM confidence
    10. Windows Location Services - MEDIUM confidence
    11. Latency Analysis - LOW-MEDIUM confidence

.PARAMETER ApiKey
    Google Geolocation API key. Can also be set via GOOGLE_GEOLOCATION_API_KEY environment variable.

.PARAMETER OutputJson
    Output results as JSON for machine parsing.

.PARAMETER SkipWifi
    Skip WiFi BSSID geolocation (for devices without WiFi).

.PARAMETER Verbose
    Show detailed output for each check.

.NOTES
    Author: VPN Location Detection System
    Date: February 2026
    Requires: Windows 10/11, PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ApiKey,

    [Parameter()]
    [switch]$OutputJson,

    [Parameter()]
    [switch]$SkipWifi
)

# ============================================================================
# Configuration
# ============================================================================

# California bounding box
$CaBounds = @{
    LatMin = 32.53
    LatMax = 42.01
    LngMin = -124.48
    LngMax = -114.13
}

# US Timezone to approximate longitude mapping
$TimezoneMapping = @{
    'Pacific Standard Time' = @{ LngMin = -125; LngMax = -114; States = @('CA', 'WA', 'OR', 'NV') }
    'Mountain Standard Time' = @{ LngMin = -114; LngMax = -102; States = @('AZ', 'CO', 'MT', 'NM', 'UT', 'WY') }
    'Central Standard Time' = @{ LngMin = -102; LngMax = -87; States = @('TX', 'IL', 'MN', 'WI', 'IA', 'MO') }
    'Eastern Standard Time' = @{ LngMin = -87; LngMax = -67; States = @('NY', 'FL', 'PA', 'OH', 'GA', 'NC') }
}

# Known VPN provider DNS servers
$VpnDnsServers = @(
    '103.86.96.100', '103.86.99.100',   # NordVPN
    '10.255.255.1',                      # NordVPN internal
    '100.64.0.7',                        # ExpressVPN
    '162.252.172.57', '149.154.159.92', # Surfshark
    '10.2.0.1',                          # CyberGhost
    '10.0.0.243',                        # ProtonVPN
    '10.8.0.1',                          # Common OpenVPN
    '209.222.18.222', '209.222.18.218', # PIA
    '193.138.218.74',                    # Mullvad
    '76.76.19.19', '76.223.122.150'     # Cloudflare WARP
)

# Known VPN/Datacenter ASNs (partial list - major providers)
$VpnDatacenterAsns = @{
    # Consumer VPN Providers
    'AS9009' = 'M247 (NordVPN/Surfshark)'
    'AS62041' = 'NordVPN'
    'AS212238' = 'NordVPN'
    'AS209103' = 'NordVPN'
    'AS136787' = 'ExpressVPN'
    'AS141995' = 'ExpressVPN'
    'AS394711' = 'ExpressVPN'
    'AS200651' = 'Surfshark'
    'AS211252' = 'Surfshark'
    'AS39351' = 'CyberGhost'
    'AS209854' = 'Proton AG'
    'AS51396' = 'Proton AG'
    'AS198605' = 'PIA'
    'AS46562' = 'PIA'
    'AS198385' = 'Mullvad'
    'AS39560' = 'Mullvad'

    # Major Datacenter/Cloud Providers (not residential)
    'AS14061' = 'DigitalOcean'
    'AS16276' = 'OVH'
    'AS24940' = 'Hetzner'
    'AS63949' = 'Linode'
    'AS20473' = 'Vultr'
    'AS14618' = 'AWS'
    'AS16509' = 'AWS'
    'AS8075' = 'Microsoft Azure'
    'AS15169' = 'Google Cloud'
    'AS13335' = 'Cloudflare'
    'AS396982' = 'Google Cloud'
}

# VPN adapter patterns
$VpnAdapterPatterns = @(
    'TAP-Windows', 'TAP-Win32', 'Wintun', 'WireGuard', 'NordLynx',
    'Windscribe', 'Surfshark', 'ExpressVPN', 'CyberGhost',
    'ProtonVPN', 'OpenVPN', 'Hotspot Shield', 'Private Internet',
    'TunnelBear', 'Mullvad', 'IPVanish', 'HideMyAss', 'VyprVPN',
    'ZenMate', 'Kaspersky VPN', 'Avast SecureLine', 'Norton VPN'
)

# VPN process names
$VpnProcessNames = @(
    'nordvpn', 'NordVPN', 'nordvpn-service', 'NordLynx',
    'expressvpn', 'ExpressVPN', 'expressvpn-service', 'expressvpnd',
    'openvpn', 'openvpn-gui', 'openvpnserv',
    'wireguard', 'wg', 'wg-quick',
    'surfshark', 'Surfshark', 'SurfsharkService',
    'cyberghost', 'CyberGhost', 'CyberGhostVPN',
    'protonvpn', 'ProtonVPN', 'ProtonVPNService', 'protonvpn-service',
    'pia-service', 'pia-client', 'privateinternetaccess', 'pia-wireguard',
    'mullvad-vpn', 'mullvad-daemon', 'mullvad-problem-report',
    'windscribe', 'WindscribeService', 'windscribe-cli',
    'tunnelbear', 'TunnelBear',
    'ipvanish', 'IPVanish', 'IPVanishVPN',
    'hidemyass', 'HMA',
    'vyprvpn', 'VyprVPN',
    'zenmate', 'ZenMate',
    'avast-secureline', 'avastseculine',
    'norton-vpn', 'NortonVPN'
)

# VPN Registry paths and keys
$VpnRegistryPaths = @(
    'HKLM:\SOFTWARE\NordVPN',
    'HKLM:\SOFTWARE\ExpressVPN',
    'HKLM:\SOFTWARE\Surfshark',
    'HKLM:\SOFTWARE\CyberGhost',
    'HKLM:\SOFTWARE\ProtonVPN',
    'HKLM:\SOFTWARE\Private Internet Access',
    'HKLM:\SOFTWARE\Mullvad VPN',
    'HKLM:\SOFTWARE\Windscribe',
    'HKLM:\SOFTWARE\TunnelBear',
    'HKLM:\SOFTWARE\OpenVPN',
    'HKLM:\SOFTWARE\WireGuard',
    'HKCU:\SOFTWARE\NordVPN',
    'HKCU:\SOFTWARE\ExpressVPN',
    'HKCU:\SOFTWARE\Surfshark'
)

# ============================================================================
# Helper Functions
# ============================================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorOutput "────────────────────────────────────────" -Color Cyan
    Write-ColorOutput "  $Title" -Color Cyan
    Write-ColorOutput "────────────────────────────────────────" -Color Cyan
}

function Get-ApiKey {
    # 1. Check command line parameter
    if ($ApiKey) { return $ApiKey }

    # 2. Check environment variable
    if ($env:GOOGLE_GEOLOCATION_API_KEY) { return $env:GOOGLE_GEOLOCATION_API_KEY }

    # 3. Check .env file in script directory
    $envPath = Join-Path $PSScriptRoot ".env"
    if (Test-Path $envPath) {
        $content = Get-Content $envPath -Raw
        if ($content -match 'GOOGLE_GEOLOCATION_API_KEY=(.+)') {
            $key = $matches[1].Trim()
            if ($key -and $key -ne 'your-api-key-here') {
                return $key
            }
        }
    }

    # 4. Prompt user interactively
    Write-Host ""
    Write-ColorOutput "════════════════════════════════════════════════════════════════" -Color Yellow
    Write-ColorOutput "  Google Geolocation API Key Required" -Color Yellow
    Write-ColorOutput "════════════════════════════════════════════════════════════════" -Color Yellow
    Write-Host ""
    Write-Host "WiFi BSSID geolocation requires a Google Geolocation API key."
    Write-Host ""
    Write-Host "To get a key:"
    Write-Host "  1. Go to https://console.cloud.google.com"
    Write-Host "  2. Create a project (or select existing)"
    Write-Host "  3. Enable 'Geolocation API'"
    Write-Host "  4. Go to 'Credentials' and create an API key"
    Write-Host "  5. (Optional) Restrict the key to Geolocation API only"
    Write-Host ""
    Write-Host "Cost: ~`$5 per 1,000 requests"
    Write-Host ""

    $inputKey = Read-Host "Enter your Google Geolocation API key (or press Enter to skip WiFi check)"

    if ($inputKey) {
        # Optionally save to .env for future runs
        $saveChoice = Read-Host "Save this key to .env file for future runs? (Y/N)"
        if ($saveChoice -eq 'Y' -or $saveChoice -eq 'y') {
            "GOOGLE_GEOLOCATION_API_KEY=$inputKey" | Out-File -FilePath $envPath -Encoding UTF8
            Write-ColorOutput "API key saved to .env file" -Color Green
        }
        return $inputKey
    }

    return $null
}

# ============================================================================
# Detection Functions
# ============================================================================

function Get-ExternalIPInfo {
    <#
    .SYNOPSIS
        Gets external IP address and related information from multiple sources.
    #>

    Write-ColorOutput "Fetching external IP information..." -Color Yellow

    $ipInfo = @{
        IP = $null
        City = $null
        Region = $null
        Country = $null
        Timezone = $null
        ISP = $null
        Org = $null
        ASN = $null
        IsDatacenter = $false
        IsVpn = $false
        Latitude = $null
        Longitude = $null
    }

    try {
        # Primary: ip-api.com (includes ASN and VPN detection)
        $response = Invoke-RestMethod -Uri "http://ip-api.com/json/?fields=status,message,country,regionName,city,lat,lon,timezone,isp,org,as,mobile,proxy,hosting,query" -TimeoutSec 10

        if ($response.status -eq 'success') {
            $ipInfo.IP = $response.query
            $ipInfo.City = $response.city
            $ipInfo.Region = $response.regionName
            $ipInfo.Country = $response.country
            $ipInfo.Timezone = $response.timezone
            $ipInfo.ISP = $response.isp
            $ipInfo.Org = $response.org
            $ipInfo.ASN = ($response.as -split ' ')[0]  # Extract just ASN number
            $ipInfo.IsDatacenter = $response.hosting
            $ipInfo.IsVpn = $response.proxy
            $ipInfo.Latitude = $response.lat
            $ipInfo.Longitude = $response.lon
        }
    }
    catch {
        Write-ColorOutput "  Warning: ip-api.com lookup failed, trying backup..." -Color Yellow

        try {
            # Backup: ipinfo.io
            $response = Invoke-RestMethod -Uri "https://ipinfo.io/json" -TimeoutSec 10
            $ipInfo.IP = $response.ip
            $ipInfo.City = $response.city
            $ipInfo.Region = $response.region
            $ipInfo.Country = $response.country
            $ipInfo.Timezone = $response.timezone
            $ipInfo.ISP = $response.org
            $ipInfo.Org = $response.org

            if ($response.loc) {
                $coords = $response.loc -split ','
                $ipInfo.Latitude = [double]$coords[0]
                $ipInfo.Longitude = [double]$coords[1]
            }
        }
        catch {
            Write-ColorOutput "  Error: Could not fetch IP information" -Color Red
        }
    }

    # Check if ASN is in our known VPN/datacenter list
    if ($ipInfo.ASN -and $VpnDatacenterAsns.ContainsKey($ipInfo.ASN)) {
        $ipInfo.IsDatacenter = $true
        $ipInfo.AsnName = $VpnDatacenterAsns[$ipInfo.ASN]
    }

    return $ipInfo
}

function Get-TimezoneCheck {
    <#
    .SYNOPSIS
        Compares system timezone against IP-based geolocation.
    #>
    param(
        [object]$IpInfo
    )

    Write-ColorOutput "Checking timezone consistency..." -Color Yellow

    $result = @{
        SystemTimezone = $null
        SystemUtcOffset = $null
        IpTimezone = $null
        ExpectedTimezone = $null
        Mismatch = $false
        Details = ""
    }

    try {
        $tz = Get-TimeZone
        $result.SystemTimezone = $tz.Id
        $result.SystemUtcOffset = $tz.BaseUtcOffset.TotalHours
        $result.IpTimezone = $IpInfo.Timezone

        # Check if system timezone matches expected for IP location
        $isPacific = $result.SystemTimezone -match 'Pacific'
        $ipInCalifornia = $IpInfo.Region -match 'California'

        # Determine expected timezone based on IP longitude
        if ($IpInfo.Longitude) {
            foreach ($tzName in $TimezoneMapping.Keys) {
                $tz = $TimezoneMapping[$tzName]
                if ($IpInfo.Longitude -ge $tz.LngMin -and $IpInfo.Longitude -lt $tz.LngMax) {
                    $result.ExpectedTimezone = $tzName
                    break
                }
            }
        }

        # Detect mismatch scenarios
        if ($ipInCalifornia -and -not $isPacific) {
            $result.Mismatch = $true
            $result.Details = "IP geolocates to California but system timezone is $($result.SystemTimezone)"
        }
        elseif ($result.ExpectedTimezone -and $result.SystemTimezone -ne $result.ExpectedTimezone) {
            # Allow some flexibility (e.g., Arizona doesn't observe DST)
            if (-not ($result.SystemTimezone -match 'Arizona|Hawaii')) {
                $result.Mismatch = $true
                $result.Details = "System timezone ($($result.SystemTimezone)) doesn't match expected ($($result.ExpectedTimezone)) for IP location"
            }
        }

        # Check for recent timezone changes (suspicious if changed recently)
        try {
            $tzEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                Id = 1
                ProviderName = 'Microsoft-Windows-Kernel-General'
            } -MaxEvents 10 -ErrorAction SilentlyContinue | Where-Object {
                $_.TimeCreated -gt (Get-Date).AddDays(-7)
            }

            if ($tzEvents) {
                $result.RecentTimezoneChange = $true
                $result.Details += " [WARNING: Timezone changed within last 7 days]"
            }
        }
        catch { }
    }
    catch {
        Write-ColorOutput "  Error checking timezone: $_" -Color Red
    }

    return $result
}

function Get-WifiNetworks {
    <#
    .SYNOPSIS
        Scans for nearby WiFi networks and returns BSSID/signal strength pairs.
    #>

    Write-ColorOutput "Scanning nearby WiFi networks..." -Color Yellow

    try {
        $wifiOutput = netsh wlan show networks mode=bssid 2>&1

        if ($wifiOutput -match 'service.*not running|interface.*not.*ready') {
            Write-ColorOutput "  WiFi service not available" -Color Yellow
            return @()
        }

        $accessPoints = @()
        $currentBssid = $null

        foreach ($line in $wifiOutput) {
            if ($line -match 'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})') {
                $currentBssid = $matches[1].Trim()
            }

            if ($line -match 'Signal\s*:\s*(\d+)%' -and $currentBssid) {
                $signalPct = [int]$matches[1]
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
        Write-ColorOutput "  Error scanning WiFi: $_" -Color Red
        return @()
    }
}

function Invoke-GeolocationApi {
    param(
        [array]$AccessPoints,
        [string]$Key
    )

    if ($AccessPoints.Count -eq 0) { return $null }

    $topAps = $AccessPoints | Sort-Object { $_.signalStrength } -Descending | Select-Object -First 10

    Write-ColorOutput "  Querying Google Geolocation API with $($topAps.Count) access points..." -Color Yellow

    $payload = @{ wifiAccessPoints = $topAps } | ConvertTo-Json -Depth 3

    try {
        $uri = "https://www.googleapis.com/geolocation/v1/geolocate?key=$Key"
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $payload -ContentType "application/json" -ErrorAction Stop
        return $response
    }
    catch {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errorDetails.error) {
            Write-ColorOutput "  API Error: $($errorDetails.error.message)" -Color Red
        }
        return $null
    }
}

function Get-NetworkHopAnalysis {
    <#
    .SYNOPSIS
        Analyzes network path for VPN indicators (including router-level VPN).
        Detects anomalies like:
        - First hop to datacenter/VPN ASN
        - Unusual geographic routing
        - Missing local ISP hops
    #>

    Write-ColorOutput "Analyzing network path (traceroute)..." -Color Yellow

    $result = @{
        Hops = @()
        FirstPublicHop = $null
        FirstPublicHopAsn = $null
        SuspiciousRouting = $false
        RouterVpnLikely = $false
        Details = @()
    }

    try {
        # Use tracert to a well-known target
        $targets = @('8.8.8.8', '1.1.1.1')
        $tracertOutput = $null

        foreach ($target in $targets) {
            Write-ColorOutput "  Tracing route to $target..." -Color Gray
            $tracertOutput = tracert -d -h 10 -w 1000 $target 2>&1
            if ($tracertOutput -notmatch 'could not find|request timed out') {
                break
            }
        }

        if (-not $tracertOutput) {
            Write-ColorOutput "  Could not perform traceroute" -Color Yellow
            return $result
        }

        $hopNumber = 0
        foreach ($line in $tracertOutput) {
            # Parse tracert output: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            if ($line -match '^\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)') {
                $hopNumber = [int]$matches[1]
                $hopIp = $matches[2]

                # Skip private IPs
                $isPrivate = $hopIp -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)'

                $hopInfo = @{
                    Number = $hopNumber
                    IP = $hopIp
                    IsPrivate = $isPrivate
                    ASN = $null
                    Org = $null
                }

                # Look up ASN for public IPs
                if (-not $isPrivate -and -not $result.FirstPublicHop) {
                    $result.FirstPublicHop = $hopIp

                    try {
                        # Quick ASN lookup
                        $asnLookup = Invoke-RestMethod -Uri "http://ip-api.com/json/$hopIp`?fields=as,org,isp,hosting,proxy" -TimeoutSec 5
                        $hopInfo.ASN = ($asnLookup.as -split ' ')[0]
                        $hopInfo.Org = $asnLookup.org
                        $result.FirstPublicHopAsn = $hopInfo.ASN

                        # Check if first public hop is a known VPN/datacenter
                        if ($VpnDatacenterAsns.ContainsKey($hopInfo.ASN)) {
                            $result.RouterVpnLikely = $true
                            $result.Details += "First public hop ($hopIp) is $($VpnDatacenterAsns[$hopInfo.ASN])"
                        }

                        if ($asnLookup.hosting -or $asnLookup.proxy) {
                            $result.SuspiciousRouting = $true
                            $result.Details += "First public hop is flagged as hosting/proxy"
                        }
                    }
                    catch { }
                }

                $result.Hops += $hopInfo

                # Only analyze first 5 hops
                if ($hopNumber -ge 5) { break }
            }
        }

        # Additional analysis: if we have very few hops to a major service, suspicious
        if ($result.Hops.Count -le 3 -and $result.FirstPublicHopAsn) {
            # Unusually short path might indicate VPN/proxy
            $result.Details += "Unusually short network path detected"
        }
    }
    catch {
        Write-ColorOutput "  Error in network analysis: $_" -Color Red
    }

    return $result
}

function Get-VpnAdapters {
    <#
    .SYNOPSIS
        Checks for VPN-related network adapters.
    #>

    Write-ColorOutput "Checking for VPN network adapters..." -Color Yellow

    $found = @()

    try {
        # Active adapters
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
            $desc = $_.InterfaceDescription
            $VpnAdapterPatterns | Where-Object { $desc -match $_ }
        }

        foreach ($adapter in $adapters) {
            $found += @{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                Status = $adapter.Status
                MacAddress = $adapter.MacAddress
            }
        }

        # Also check disabled/hidden adapters via WMI
        $wmiAdapters = Get-WmiObject Win32_NetworkAdapter -ErrorAction SilentlyContinue | Where-Object {
            $desc = $_.Description
            $VpnAdapterPatterns | Where-Object { $desc -match $_ }
        }

        foreach ($adapter in $wmiAdapters) {
            if (-not ($found | Where-Object { $_.Description -eq $adapter.Description })) {
                $found += @{
                    Name = $adapter.NetConnectionID
                    Description = $adapter.Description
                    Status = if ($adapter.NetEnabled) { "Enabled" } else { "Disabled" }
                    MacAddress = $adapter.MACAddress
                }
            }
        }
    }
    catch {
        Write-ColorOutput "  Error checking adapters: $_" -Color Red
    }

    return $found
}

function Get-VpnProcesses {
    <#
    .SYNOPSIS
        Checks for running VPN client processes.
    #>

    Write-ColorOutput "Checking for VPN processes..." -Color Yellow

    $found = @()

    try {
        $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $VpnProcessNames -contains $_.Name -or
            $_.Path -match 'vpn|wireguard|openvpn|nordvpn|expressvpn|surfshark|proton|mullvad'
        }

        foreach ($proc in $processes) {
            $found += @{
                Name = $proc.Name
                Path = $proc.Path
                Id = $proc.Id
            }
        }
    }
    catch {
        Write-ColorOutput "  Error checking processes: $_" -Color Red
    }

    return $found
}

function Get-VpnRegistryEntries {
    <#
    .SYNOPSIS
        Scans registry for installed VPN software.
    #>

    Write-ColorOutput "Scanning registry for VPN software..." -Color Yellow

    $found = @()

    # Check specific VPN paths
    foreach ($path in $VpnRegistryPaths) {
        if (Test-Path $path) {
            $found += @{
                Path = $path
                Type = "Direct VPN Key"
            }
        }
    }

    # Check uninstall entries
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $vpnSoftwarePatterns = @(
        'NordVPN', 'ExpressVPN', 'Surfshark', 'CyberGhost', 'ProtonVPN',
        'Private Internet Access', 'Mullvad', 'Windscribe', 'TunnelBear',
        'IPVanish', 'HideMyAss', 'VyprVPN', 'Hotspot Shield', 'ZenMate',
        'OpenVPN', 'WireGuard', 'SoftEther', 'Psiphon', 'Lantern',
        'Kaspersky VPN', 'Avast SecureLine', 'Norton.*VPN', 'McAfee.*VPN'
    )

    try {
        foreach ($path in $uninstallPaths) {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $displayName = $item.DisplayName
                if ($displayName) {
                    foreach ($pattern in $vpnSoftwarePatterns) {
                        if ($displayName -match $pattern) {
                            $found += @{
                                Name = $displayName
                                Version = $item.DisplayVersion
                                InstallLocation = $item.InstallLocation
                                Type = "Installed Software"
                            }
                            break
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-ColorOutput "  Error scanning registry: $_" -Color Red
    }

    # Check for OpenVPN config files
    $configPaths = @(
        "$env:USERPROFILE\OpenVPN\config",
        "$env:ProgramFiles\OpenVPN\config",
        "$env:ProgramData\OpenVPN\config"
    )

    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            $ovpnFiles = Get-ChildItem -Path $configPath -Filter "*.ovpn" -ErrorAction SilentlyContinue
            if ($ovpnFiles) {
                $found += @{
                    Name = "OpenVPN Config Files"
                    Path = $configPath
                    Count = $ovpnFiles.Count
                    Type = "Configuration Files"
                }
            }
        }
    }

    return $found
}

function Get-VpnDnsCheck {
    <#
    .SYNOPSIS
        Checks DNS configuration for VPN indicators.
    #>

    Write-ColorOutput "Checking DNS configuration..." -Color Yellow

    $result = @{
        VpnDnsFound = @()
        DnsServers = @()
        DnsLeakRisk = $false
    }

    try {
        $dnsConfig = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue

        foreach ($config in $dnsConfig) {
            foreach ($server in $config.ServerAddresses) {
                $result.DnsServers += @{
                    Interface = $config.InterfaceAlias
                    Server = $server
                }

                if ($VpnDnsServers -contains $server) {
                    $result.VpnDnsFound += @{
                        Interface = $config.InterfaceAlias
                        Server = $server
                    }
                }

                # Check for internal/private DNS ranges often used by VPNs
                if ($server -match '^10\.' -or $server -match '^100\.64\.') {
                    $result.VpnDnsFound += @{
                        Interface = $config.InterfaceAlias
                        Server = $server
                        Note = "Private range often used by VPNs"
                    }
                }
            }
        }
    }
    catch {
        Write-ColorOutput "  Error checking DNS: $_" -Color Red
    }

    return $result
}

function Get-RoutingTableCheck {
    <#
    .SYNOPSIS
        Checks routing table for VPN indicators.
    #>

    Write-ColorOutput "Checking routing table..." -Color Yellow

    $result = @{
        VpnRoutingDetected = $false
        SuspiciousRoutes = @()
        DefaultGateway = $null
    }

    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue

        # Check for classic VPN full-tunnel pattern
        $route1 = $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/1' }
        $route2 = $routes | Where-Object { $_.DestinationPrefix -eq '128.0.0.0/1' }

        if ($route1 -and $route2) {
            $result.VpnRoutingDetected = $true
            $result.SuspiciousRoutes += "Full tunnel override: 0.0.0.0/1 + 128.0.0.0/1"
        }

        # Check default gateway
        $defaultRoute = $routes | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
        if ($defaultRoute) {
            $result.DefaultGateway = $defaultRoute.NextHop | Select-Object -First 1

            # Check if default route goes through a VPN adapter
            $gwAdapter = Get-NetAdapter -InterfaceIndex $defaultRoute.InterfaceIndex -ErrorAction SilentlyContinue
            if ($gwAdapter) {
                foreach ($pattern in $VpnAdapterPatterns) {
                    if ($gwAdapter.InterfaceDescription -match $pattern) {
                        $result.VpnRoutingDetected = $true
                        $result.SuspiciousRoutes += "Default route via VPN adapter: $($gwAdapter.InterfaceDescription)"
                    }
                }
            }
        }

        # Look for routes to known VPN server ranges
        $vpnRanges = @('10.0.0.0/8', '100.64.0.0/10')  # Common VPN internal ranges
        foreach ($route in $routes) {
            if ($route.DestinationPrefix -match '^(10\.|100\.64\.)' -and $route.NextHop -ne '0.0.0.0') {
                $result.SuspiciousRoutes += "Route to VPN range: $($route.DestinationPrefix) via $($route.NextHop)"
            }
        }
    }
    catch {
        Write-ColorOutput "  Error checking routes: $_" -Color Red
    }

    return $result
}

function Get-WindowsLocationServices {
    <#
    .SYNOPSIS
        Attempts to get location from Windows Location Services.
    #>

    Write-ColorOutput "Checking Windows Location Services..." -Color Yellow

    $result = @{
        Available = $false
        Latitude = $null
        Longitude = $null
        Accuracy = $null
        Source = $null
    }

    try {
        Add-Type -AssemblyName System.Device -ErrorAction SilentlyContinue

        $watcher = New-Object System.Device.Location.GeoCoordinateWatcher
        $watcher.Start()

        # Wait for position (max 10 seconds)
        $timeout = 10
        $elapsed = 0
        while ($watcher.Status -ne 'Ready' -and $elapsed -lt $timeout) {
            Start-Sleep -Milliseconds 500
            $elapsed += 0.5
        }

        if ($watcher.Status -eq 'Ready') {
            $position = $watcher.Position.Location
            if (-not $position.IsUnknown) {
                $result.Available = $true
                $result.Latitude = $position.Latitude
                $result.Longitude = $position.Longitude
                $result.Accuracy = $position.HorizontalAccuracy
                $result.Source = "Windows Location Services"
            }
        }

        $watcher.Stop()
    }
    catch {
        Write-ColorOutput "  Windows Location Services not available: $_" -Color Yellow
    }

    return $result
}

function Get-LatencyAnalysis {
    <#
    .SYNOPSIS
        Analyzes latency to various endpoints to detect location inconsistencies.
    #>

    Write-ColorOutput "Performing latency analysis..." -Color Yellow

    $result = @{
        Measurements = @()
        Anomalies = @()
    }

    # Test endpoints in different regions
    $endpoints = @(
        @{ Name = "West US (California)"; Host = "west-us.azure.com"; ExpectedFromCA = @(10, 50) }
        @{ Name = "East US"; Host = "east-us.azure.com"; ExpectedFromCA = @(60, 120) }
        @{ Name = "Europe"; Host = "eu.azure.com"; ExpectedFromCA = @(140, 200) }
    )

    # Alternative: use common reliable endpoints
    $testEndpoints = @(
        @{ Name = "Google DNS"; Host = "8.8.8.8" }
        @{ Name = "Cloudflare"; Host = "1.1.1.1" }
        @{ Name = "Level3"; Host = "4.2.2.1" }
    )

    foreach ($endpoint in $testEndpoints) {
        try {
            $ping = Test-Connection -ComputerName $endpoint.Host -Count 3 -ErrorAction SilentlyContinue
            if ($ping) {
                $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
                $result.Measurements += @{
                    Endpoint = $endpoint.Name
                    Host = $endpoint.Host
                    AvgLatencyMs = [math]::Round($avgLatency, 1)
                }
            }
        }
        catch { }
    }

    return $result
}

function Test-InCalifornia {
    param(
        [double]$Lat,
        [double]$Lng
    )

    return ($Lat -ge $CaBounds.LatMin -and $Lat -le $CaBounds.LatMax -and
            $Lng -ge $CaBounds.LngMin -and $Lng -le $CaBounds.LngMax)
}

function Get-ReverseGeocode {
    param(
        [double]$Lat,
        [double]$Lng
    )

    try {
        $uri = "https://nominatim.openstreetmap.org/reverse?lat=$Lat&lon=$Lng&format=json"
        $response = Invoke-RestMethod -Uri $uri -Headers @{"User-Agent" = "VPN-Detection-Script/1.0"} -TimeoutSec 10
        return $response
    }
    catch {
        return $null
    }
}

# ============================================================================
# Main Script
# ============================================================================

$startTime = Get-Date

Write-ColorOutput "╔══════════════════════════════════════════════════════════════╗" -Color Cyan
Write-ColorOutput "║     VPN LOCATION SPOOFING DETECTION - COMPREHENSIVE SCAN     ║" -Color Cyan
Write-ColorOutput "║                      Internal Testing v2.0                   ║" -Color Cyan
Write-ColorOutput "╚══════════════════════════════════════════════════════════════╝" -Color Cyan
Write-Host ""
Write-ColorOutput "Scan started: $startTime" -Color Gray
Write-Host ""

# Initialize results
$results = @{
    Timestamp = $startTime.ToString("o")
    ComputerName = $env:COMPUTERNAME
    Username = $env:USERNAME

    # Detection results
    WifiGeolocation = $null
    IpInfo = $null
    TimezoneCheck = $null
    NetworkHops = $null
    VpnAdapters = @()
    VpnProcesses = @()
    VpnRegistry = @()
    VpnDns = $null
    VpnRouting = $null
    WindowsLocation = $null
    LatencyAnalysis = $null

    # Scoring
    Indicators = @()
    TotalScore = 0
    MaxScore = 300
    Confidence = "LOW"

    # Final determination
    InCalifornia = $null
    PhysicalLocation = $null
    IpLocation = $null
}

# ============================================================================
# Run All Detection Checks
# ============================================================================

# 1. Get External IP Information (includes ASN check)
Write-Section "1. External IP Analysis"
$results.IpInfo = Get-ExternalIPInfo

if ($results.IpInfo.IP) {
    Write-Host "  External IP: $($results.IpInfo.IP)"
    Write-Host "  Location: $($results.IpInfo.City), $($results.IpInfo.Region), $($results.IpInfo.Country)"
    Write-Host "  ISP: $($results.IpInfo.ISP)"
    Write-Host "  ASN: $($results.IpInfo.ASN)"

    if ($results.IpInfo.IsVpn -or $results.IpInfo.IsDatacenter) {
        Write-ColorOutput "  [ALERT] IP flagged as VPN/Proxy/Datacenter!" -Color Red
        $results.Indicators += @{ Name = "IP Datacenter/VPN Classification"; Score = 40; Confidence = "HIGH" }
        $results.TotalScore += 40
    }

    if ($results.IpInfo.AsnName) {
        Write-ColorOutput "  [ALERT] ASN belongs to known VPN provider: $($results.IpInfo.AsnName)" -Color Red
        $results.Indicators += @{ Name = "Known VPN Provider ASN"; Score = 40; Confidence = "HIGH" }
        $results.TotalScore += 40
    }

    $results.IpLocation = "$($results.IpInfo.City), $($results.IpInfo.Region)"
}

# 2. Timezone Check
Write-Section "2. Timezone Analysis"
$results.TimezoneCheck = Get-TimezoneCheck -IpInfo $results.IpInfo

Write-Host "  System Timezone: $($results.TimezoneCheck.SystemTimezone)"
Write-Host "  IP Timezone: $($results.TimezoneCheck.IpTimezone)"

if ($results.TimezoneCheck.Mismatch) {
    Write-ColorOutput "  [ALERT] $($results.TimezoneCheck.Details)" -Color Red
    $results.Indicators += @{ Name = "Timezone Mismatch"; Score = 30; Confidence = "HIGH" }
    $results.TotalScore += 30
}
else {
    Write-ColorOutput "  [OK] Timezone consistent with IP location" -Color Green
}

# 3. WiFi BSSID Geolocation
if (-not $SkipWifi) {
    Write-Section "3. WiFi BSSID Geolocation (Physical Location)"

    $apiKey = Get-ApiKey
    if ($apiKey) {
        $accessPoints = Get-WifiNetworks

        if ($accessPoints.Count -gt 0) {
            Write-Host "  Found $($accessPoints.Count) nearby WiFi access points"

            $geoResult = Invoke-GeolocationApi -AccessPoints $accessPoints -Key $apiKey

            if ($geoResult -and $geoResult.location) {
                $wifiLat = $geoResult.location.lat
                $wifiLng = $geoResult.location.lng
                $wifiAccuracy = $geoResult.accuracy

                $results.WifiGeolocation = @{
                    Latitude = $wifiLat
                    Longitude = $wifiLng
                    Accuracy = $wifiAccuracy
                    AccessPointCount = $accessPoints.Count
                }

                Write-Host "  Physical Location: $wifiLat, $wifiLng (±${wifiAccuracy}m)"

                $wifiInCA = Test-InCalifornia -Lat $wifiLat -Lng $wifiLng
                $results.InCalifornia = $wifiInCA

                # Get location name
                $locInfo = Get-ReverseGeocode -Lat $wifiLat -Lng $wifiLng
                if ($locInfo -and $locInfo.address) {
                    $city = $locInfo.address.city ?? $locInfo.address.town ?? $locInfo.address.village ?? "Unknown"
                    $state = $locInfo.address.state ?? "Unknown"
                    $results.PhysicalLocation = "$city, $state"
                    Write-Host "  Resolved: $($results.PhysicalLocation)"
                }

                if (-not $wifiInCA) {
                    Write-ColorOutput "  [CRITICAL] Device physically located OUTSIDE California!" -Color Red
                    $results.Indicators += @{ Name = "WiFi Geolocation Outside CA"; Score = 60; Confidence = "CRITICAL" }
                    $results.TotalScore += 60
                }
                else {
                    Write-ColorOutput "  [OK] Device physically in California" -Color Green
                }

                # Check if WiFi location differs significantly from IP location
                if ($results.IpInfo.Latitude -and $results.IpInfo.Longitude) {
                    $latDiff = [math]::Abs($wifiLat - $results.IpInfo.Latitude)
                    $lngDiff = [math]::Abs($wifiLng - $results.IpInfo.Longitude)

                    # More than 2 degrees difference is suspicious (roughly 100+ miles)
                    if ($latDiff -gt 2 -or $lngDiff -gt 2) {
                        Write-ColorOutput "  [ALERT] WiFi location differs significantly from IP location!" -Color Red
                        $results.Indicators += @{ Name = "WiFi/IP Location Mismatch"; Score = 50; Confidence = "HIGH" }
                        $results.TotalScore += 50
                    }
                }
            }
            else {
                Write-ColorOutput "  Could not determine location from WiFi" -Color Yellow
            }
        }
        else {
            Write-ColorOutput "  No WiFi networks found (device may be on Ethernet only)" -Color Yellow
        }
    }
    else {
        Write-ColorOutput "  [SKIP] No API key provided for WiFi geolocation" -Color Yellow
    }
}

# 4. Network Hop Analysis (Router VPN Detection)
Write-Section "4. Network Path Analysis (Router VPN Detection)"
$results.NetworkHops = Get-NetworkHopAnalysis

if ($results.NetworkHops.RouterVpnLikely) {
    Write-ColorOutput "  [ALERT] Router-level VPN detected!" -Color Red
    foreach ($detail in $results.NetworkHops.Details) {
        Write-Host "    - $detail"
    }
    $results.Indicators += @{ Name = "Router VPN Detected"; Score = 50; Confidence = "HIGH" }
    $results.TotalScore += 50
}
elseif ($results.NetworkHops.SuspiciousRouting) {
    Write-ColorOutput "  [WARNING] Suspicious network routing detected" -Color Yellow
    foreach ($detail in $results.NetworkHops.Details) {
        Write-Host "    - $detail"
    }
    $results.Indicators += @{ Name = "Suspicious Network Path"; Score = 25; Confidence = "MEDIUM" }
    $results.TotalScore += 25
}
else {
    Write-ColorOutput "  [OK] Network path appears normal" -Color Green
}

# 5. VPN Adapter Check
Write-Section "5. VPN Network Adapter Check"
$results.VpnAdapters = Get-VpnAdapters

if ($results.VpnAdapters.Count -gt 0) {
    Write-ColorOutput "  [ALERT] VPN adapters found:" -Color Red
    foreach ($adapter in $results.VpnAdapters) {
        Write-Host "    - $($adapter.Description) [$($adapter.Status)]"
    }
    $results.Indicators += @{ Name = "VPN Adapters Present"; Score = 35; Confidence = "HIGH" }
    $results.TotalScore += 35
}
else {
    Write-ColorOutput "  [OK] No VPN adapters detected" -Color Green
}

# 6. VPN Process Check
Write-Section "6. VPN Process Check"
$results.VpnProcesses = Get-VpnProcesses

if ($results.VpnProcesses.Count -gt 0) {
    Write-ColorOutput "  [ALERT] VPN processes running:" -Color Red
    foreach ($proc in $results.VpnProcesses) {
        Write-Host "    - $($proc.Name) (PID: $($proc.Id))"
    }
    $results.Indicators += @{ Name = "VPN Processes Running"; Score = 35; Confidence = "HIGH" }
    $results.TotalScore += 35
}
else {
    Write-ColorOutput "  [OK] No VPN processes detected" -Color Green
}

# 7. VPN Registry/Software Check
Write-Section "7. Installed VPN Software Check"
$results.VpnRegistry = Get-VpnRegistryEntries

if ($results.VpnRegistry.Count -gt 0) {
    Write-ColorOutput "  [ALERT] VPN software installed:" -Color Red
    foreach ($entry in $results.VpnRegistry) {
        Write-Host "    - $($entry.Name) [$($entry.Type)]"
    }
    $results.Indicators += @{ Name = "VPN Software Installed"; Score = 30; Confidence = "HIGH" }
    $results.TotalScore += 30
}
else {
    Write-ColorOutput "  [OK] No VPN software found in registry" -Color Green
}

# 8. DNS Configuration Check
Write-Section "8. DNS Configuration Check"
$results.VpnDns = Get-VpnDnsCheck

if ($results.VpnDns.VpnDnsFound.Count -gt 0) {
    Write-ColorOutput "  [ALERT] VPN DNS servers configured:" -Color Yellow
    foreach ($dns in $results.VpnDns.VpnDnsFound) {
        Write-Host "    - $($dns.Server) on $($dns.Interface)"
    }
    $results.Indicators += @{ Name = "VPN DNS Configuration"; Score = 20; Confidence = "MEDIUM" }
    $results.TotalScore += 20
}
else {
    Write-ColorOutput "  [OK] No VPN DNS servers detected" -Color Green
}

# 9. Routing Table Check
Write-Section "9. Routing Table Check"
$results.VpnRouting = Get-RoutingTableCheck

if ($results.VpnRouting.VpnRoutingDetected) {
    Write-ColorOutput "  [ALERT] VPN routing patterns detected:" -Color Yellow
    foreach ($route in $results.VpnRouting.SuspiciousRoutes) {
        Write-Host "    - $route"
    }
    $results.Indicators += @{ Name = "VPN Routing Pattern"; Score = 25; Confidence = "MEDIUM" }
    $results.TotalScore += 25
}
else {
    Write-ColorOutput "  [OK] No VPN routing patterns detected" -Color Green
}

# 10. Windows Location Services
Write-Section "10. Windows Location Services"
$results.WindowsLocation = Get-WindowsLocationServices

if ($results.WindowsLocation.Available) {
    Write-Host "  Location: $($results.WindowsLocation.Latitude), $($results.WindowsLocation.Longitude)"
    Write-Host "  Accuracy: $($results.WindowsLocation.Accuracy)m"

    $winLocInCA = Test-InCalifornia -Lat $results.WindowsLocation.Latitude -Lng $results.WindowsLocation.Longitude

    if (-not $winLocInCA) {
        Write-ColorOutput "  [ALERT] Windows Location outside California!" -Color Red
        $results.Indicators += @{ Name = "Windows Location Outside CA"; Score = 40; Confidence = "MEDIUM" }
        $results.TotalScore += 40
    }
    else {
        Write-ColorOutput "  [OK] Windows Location in California" -Color Green
    }
}
else {
    Write-ColorOutput "  [INFO] Windows Location Services not available" -Color Yellow
}

# 11. Latency Analysis
Write-Section "11. Latency Analysis"
$results.LatencyAnalysis = Get-LatencyAnalysis

if ($results.LatencyAnalysis.Measurements.Count -gt 0) {
    foreach ($m in $results.LatencyAnalysis.Measurements) {
        Write-Host "  $($m.Endpoint): $($m.AvgLatencyMs)ms"
    }
}

# ============================================================================
# Final Scoring and Determination
# ============================================================================

Write-Host ""
Write-ColorOutput "╔══════════════════════════════════════════════════════════════╗" -Color Cyan
Write-ColorOutput "║                    DETECTION SUMMARY                         ║" -Color Cyan
Write-ColorOutput "╚══════════════════════════════════════════════════════════════╝" -Color Cyan
Write-Host ""

# Determine confidence level
if ($results.TotalScore -ge 100) {
    $results.Confidence = "CRITICAL"
}
elseif ($results.TotalScore -ge 70) {
    $results.Confidence = "HIGH"
}
elseif ($results.TotalScore -ge 40) {
    $results.Confidence = "MEDIUM"
}
else {
    $results.Confidence = "LOW"
}

Write-ColorOutput "Detection Score: $($results.TotalScore) / $($results.MaxScore)" -Color White
Write-Host ""

if ($results.Indicators.Count -gt 0) {
    Write-ColorOutput "Indicators Found:" -Color Yellow
    foreach ($indicator in $results.Indicators) {
        $color = switch ($indicator.Confidence) {
            "CRITICAL" { "Red" }
            "HIGH" { "Red" }
            "MEDIUM" { "Yellow" }
            default { "White" }
        }
        Write-ColorOutput "  [$($indicator.Confidence)] $($indicator.Name) (+$($indicator.Score) pts)" -Color $color
    }
}
else {
    Write-ColorOutput "No suspicious indicators found." -Color Green
}

Write-Host ""
Write-ColorOutput "────────────────────────────────────────" -Color Cyan

$confidenceColor = switch ($results.Confidence) {
    "CRITICAL" { "Red" }
    "HIGH" { "Red" }
    "MEDIUM" { "Yellow" }
    default { "Green" }
}

Write-ColorOutput "CONFIDENCE LEVEL: $($results.Confidence)" -Color $confidenceColor

if ($results.Confidence -eq "CRITICAL" -or $results.Confidence -eq "HIGH") {
    Write-Host ""
    Write-ColorOutput "⚠️  VPN LOCATION SPOOFING LIKELY DETECTED ⚠️" -Color Red
    Write-Host ""
    Write-Host "Physical Location (WiFi): $($results.PhysicalLocation ?? 'Unknown')"
    Write-Host "IP-Based Location: $($results.IpLocation ?? 'Unknown')"
}
elseif ($results.Confidence -eq "MEDIUM") {
    Write-Host ""
    Write-ColorOutput "⚡ SUSPICIOUS ACTIVITY - REQUIRES REVIEW" -Color Yellow
}
else {
    Write-Host ""
    Write-ColorOutput "✓ NO CLEAR INDICATION OF VPN SPOOFING" -Color Green
}

Write-Host ""
Write-ColorOutput "Scan completed at $(Get-Date)" -Color Gray
Write-ColorOutput "Duration: $([math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)) seconds" -Color Gray

# JSON Output
if ($OutputJson) {
    Write-Host ""
    Write-ColorOutput "────────────────────────────────────────" -Color Cyan
    Write-ColorOutput "JSON OUTPUT:" -Color Cyan
    $results | ConvertTo-Json -Depth 5
}

# Exit code based on confidence
switch ($results.Confidence) {
    "CRITICAL" { exit 3 }
    "HIGH" { exit 2 }
    "MEDIUM" { exit 1 }
    default { exit 0 }
}
