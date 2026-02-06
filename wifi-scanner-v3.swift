#!/usr/bin/env swift
/*
 WiFi Scanner v3 - Direct scan without authorization check
*/

import Foundation
import CoreWLAN

let args = CommandLine.arguments
let outputJson = args.contains("--json")

let wifiClient = CWWiFiClient.shared()
guard let interface = wifiClient.interface() else {
    fputs("ERROR: No WiFi interface found\n", stderr)
    exit(1)
}

fputs("WiFi Interface: \(interface.interfaceName ?? "unknown")\n", stderr)
fputs("Power: \(interface.powerOn() ? "On" : "Off")\n", stderr)

if let ssid = interface.ssid() {
    fputs("Connected SSID: \(ssid)\n", stderr)
} else {
    fputs("Connected SSID: <not available>\n", stderr)
}

if let bssid = interface.bssid() {
    fputs("Connected BSSID: \(bssid) ✓\n", stderr)
} else {
    fputs("Connected BSSID: <restricted>\n", stderr)
}

fputs("\nScanning for networks...\n", stderr)

do {
    let networks = try interface.scanForNetworks(withSSID: nil)
    fputs("Found \(networks.count) networks\n\n", stderr)

    var results: [[String: Any]] = []
    var hasAnyBssid = false

    for network in networks {
        let ssid = network.ssid ?? "<hidden>"
        let rssi = network.rssiValue

        if let bssid = network.bssid, !bssid.isEmpty {
            hasAnyBssid = true
            results.append([
                "macAddress": bssid,
                "signalStrength": rssi
            ])
            if !outputJson {
                print("✓ BSSID: \(bssid), RSSI: \(rssi) dBm, SSID: \(ssid)")
            }
        } else {
            if !outputJson {
                print("✗ BSSID: <restricted>, RSSI: \(rssi) dBm, SSID: \(ssid)")
            }
        }
    }

    if outputJson {
        if let jsonData = try? JSONSerialization.data(withJSONObject: results, options: .prettyPrinted),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            print(jsonString)
        }
    }

    if !hasAnyBssid {
        fputs("\n⚠️  No BSSIDs available - Location Services not working for this app\n", stderr)
    }

} catch {
    fputs("Scan error: \(error.localizedDescription)\n", stderr)
    exit(1)
}
