#!/usr/bin/env swift
/*
 WiFi Scanner v2 - macOS BSSID Scanner with Location Services
 Properly requests location authorization
*/

import Foundation
import CoreWLAN
import CoreLocation

class WifiScanner: NSObject, CLLocationManagerDelegate {
    let locationManager = CLLocationManager()
    var outputJson = false
    let semaphore = DispatchSemaphore(value: 0)

    override init() {
        super.init()
        locationManager.delegate = self
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        let status = manager.authorizationStatus
        fputs("Authorization status changed to: \(statusName(status))\n", stderr)

        if status == .authorizedAlways || status == .authorized {
            // We have permission, proceed with scan
            semaphore.signal()
        } else if status == .denied || status == .restricted {
            fputs("Location access denied. Please enable in System Settings.\n", stderr)
            semaphore.signal()
        }
        // If notDetermined, wait for user response
    }

    func statusName(_ status: CLAuthorizationStatus) -> String {
        switch status {
        case .notDetermined: return "notDetermined"
        case .restricted: return "restricted"
        case .denied: return "denied"
        case .authorizedAlways: return "authorizedAlways"
        case .authorized: return "authorized"
        @unknown default: return "unknown"
        }
    }

    func run(json: Bool) {
        self.outputJson = json

        let status = locationManager.authorizationStatus
        fputs("Current authorization: \(statusName(status))\n", stderr)

        if status == .notDetermined {
            fputs("Requesting location authorization...\n", stderr)
            // This triggers the system prompt for apps with proper Info.plist
            locationManager.requestWhenInUseAuthorization()

            // Wait for authorization response (timeout after 30 seconds)
            let result = semaphore.wait(timeout: .now() + 30)
            if result == .timedOut {
                fputs("Authorization request timed out.\n", stderr)
                fputs("Please manually enable location in System Settings > Privacy & Security > Location Services\n", stderr)
            }
        }

        // Now scan
        scanNetworks()
    }

    func scanNetworks() {
        let wifiClient = CWWiFiClient.shared()
        guard let interface = wifiClient.interface() else {
            fputs("ERROR: No WiFi interface found\n", stderr)
            exit(1)
        }

        fputs("WiFi Interface: \(interface.interfaceName ?? "unknown")\n", stderr)

        if let bssid = interface.bssid() {
            fputs("Connected BSSID: \(bssid)\n", stderr)
        } else {
            fputs("Connected BSSID: <restricted>\n", stderr)
        }

        fputs("Scanning...\n", stderr)

        do {
            let networks = try interface.scanForNetworks(withSSID: nil)
            fputs("Found \(networks.count) networks\n", stderr)

            var results: [[String: Any]] = []

            for network in networks {
                if let bssid = network.bssid, !bssid.isEmpty {
                    results.append([
                        "macAddress": bssid,
                        "signalStrength": network.rssiValue
                    ])
                    if !outputJson {
                        print("BSSID: \(bssid), RSSI: \(network.rssiValue), SSID: \(network.ssid ?? "<hidden>")")
                    }
                }
            }

            if outputJson {
                if let jsonData = try? JSONSerialization.data(withJSONObject: results, options: .prettyPrinted),
                   let jsonString = String(data: jsonData, encoding: .utf8) {
                    print(jsonString)
                }
            }

            if results.isEmpty {
                fputs("\n*** No BSSIDs retrieved ***\n", stderr)
                fputs("Location Services must be enabled for this app.\n", stderr)
                fputs("Check: System Settings > Privacy & Security > Location Services > WiFi Scanner\n", stderr)
            }

        } catch {
            fputs("Scan error: \(error)\n", stderr)
        }
    }
}

// Main
let args = CommandLine.arguments
let json = args.contains("--json")

// Need to run on main thread for location services
let scanner = WifiScanner()

// Use RunLoop to allow delegate callbacks
DispatchQueue.main.async {
    scanner.run(json: json)
    exit(0)
}

RunLoop.main.run()
