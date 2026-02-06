#!/usr/bin/env swift
/*
 WiFi Scanner - macOS BSSID Scanner with Location Services

 This tool scans for nearby WiFi networks and outputs their BSSIDs.
 It requires Location Services permission to access BSSID data.

 SETUP:
 1. Compile: swiftc -o wifi-scanner wifi-scanner.swift -framework CoreWLAN -framework CoreLocation -framework Foundation
 2. Run once: ./wifi-scanner
 3. Go to System Settings > Privacy & Security > Location Services
 4. Enable location for "wifi-scanner" (or Terminal if running from there)
 5. Run again to get BSSID data

 Usage:
   ./wifi-scanner          # Output human-readable
   ./wifi-scanner --json   # Output JSON for API submission
*/

import Foundation
import CoreWLAN
import CoreLocation

// MARK: - Location Manager Delegate

class LocationDelegate: NSObject, CLLocationManagerDelegate {
    var authorizationStatus: CLAuthorizationStatus = .notDetermined
    let semaphore = DispatchSemaphore(value: 0)

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        authorizationStatus = manager.authorizationStatus
        semaphore.signal()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        fputs("Location error: \(error.localizedDescription)\n", stderr)
    }
}

// MARK: - WiFi Scanner

struct WiFiNetwork: Codable {
    let macAddress: String
    let signalStrength: Int
    let ssid: String?
    let channel: Int?
}

func scanWiFiNetworks(outputJson: Bool) {
    // Initialize location manager to trigger permission request
    let locationManager = CLLocationManager()
    let locationDelegate = LocationDelegate()
    locationManager.delegate = locationDelegate

    // Check current authorization
    let currentAuth = locationManager.authorizationStatus

    if currentAuth == .notDetermined {
        fputs("Location permission not determined. Requesting...\n", stderr)
        fputs("Please grant location access in System Settings > Privacy & Security > Location Services\n", stderr)

        // Note: requestWhenInUseAuthorization() only works for apps with proper Info.plist
        // For CLI tools, user must manually enable in System Settings
    }

    if currentAuth == .denied || currentAuth == .restricted {
        fputs("ERROR: Location access denied.\n", stderr)
        fputs("Please enable location access:\n", stderr)
        fputs("  1. Open System Settings\n", stderr)
        fputs("  2. Go to Privacy & Security > Location Services\n", stderr)
        fputs("  3. Enable location for Terminal or this application\n", stderr)
        exit(1)
    }

    // Get WiFi interface
    let wifiClient = CWWiFiClient.shared()
    guard let interface = wifiClient.interface() else {
        fputs("ERROR: No WiFi interface found\n", stderr)
        exit(1)
    }

    fputs("WiFi Interface: \(interface.interfaceName ?? "unknown")\n", stderr)
    fputs("Power: \(interface.powerOn() ? "On" : "Off")\n", stderr)

    // Check current connection
    if let ssid = interface.ssid() {
        fputs("Connected to: \(ssid)\n", stderr)
    }

    if let bssid = interface.bssid() {
        fputs("Connected BSSID: \(bssid)\n", stderr)
    } else {
        fputs("Connected BSSID: <restricted - enable Location Services>\n", stderr)
    }

    fputs("\nScanning for networks...\n", stderr)

    // Scan for networks
    var networks: [WiFiNetwork] = []

    do {
        let scanResults = try interface.scanForNetworks(withSSID: nil)

        fputs("Found \(scanResults.count) networks\n\n", stderr)

        for network in scanResults {
            let bssid = network.bssid
            let ssid = network.ssid
            let rssi = network.rssiValue
            let channel = network.wlanChannel?.channelNumber ?? 0

            // Only include if we got a valid BSSID
            if let bssid = bssid, !bssid.isEmpty {
                networks.append(WiFiNetwork(
                    macAddress: bssid,
                    signalStrength: rssi,
                    ssid: ssid,
                    channel: channel
                ))
            } else if !outputJson {
                // Print even without BSSID in human-readable mode
                print("  SSID: \(ssid ?? "<hidden>"), BSSID: <restricted>, RSSI: \(rssi) dBm")
            }
        }

    } catch {
        fputs("Scan error: \(error.localizedDescription)\n", stderr)
        exit(1)
    }

    // Output results
    if outputJson {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]

        if let jsonData = try? encoder.encode(networks),
           let jsonString = String(data: jsonData, encoding: .utf8) {
            print(jsonString)
        }
    } else {
        if networks.isEmpty {
            print("\nNo BSSIDs retrieved - Location Services may not be enabled.")
            print("\nTo enable:")
            print("  1. System Settings > Privacy & Security > Location Services")
            print("  2. Enable location for Terminal (or this application)")
            print("  3. Run this tool again")
        } else {
            print("\nNetworks with BSSID access:")
            for network in networks {
                print("  BSSID: \(network.macAddress), RSSI: \(network.signalStrength) dBm, SSID: \(network.ssid ?? "<hidden>")")
            }

            print("\n\nJSON for Google Geolocation API:")
            let payload: [String: Any] = [
                "wifiAccessPoints": networks.map { [
                    "macAddress": $0.macAddress,
                    "signalStrength": $0.signalStrength
                ]}
            ]
            if let jsonData = try? JSONSerialization.data(withJSONObject: payload, options: .prettyPrinted),
               let jsonString = String(data: jsonData, encoding: .utf8) {
                print(jsonString)
            }
        }
    }
}

// MARK: - Main

let arguments = CommandLine.arguments
let outputJson = arguments.contains("--json")

if arguments.contains("--help") || arguments.contains("-h") {
    print("""
    WiFi Scanner - Scan nearby WiFi networks for BSSIDs

    Usage: wifi-scanner [options]

    Options:
      --json    Output JSON suitable for Google Geolocation API
      --help    Show this help message

    Note: Requires Location Services permission on macOS.
          Enable in System Settings > Privacy & Security > Location Services
    """)
    exit(0)
}

scanWiFiNetworks(outputJson: outputJson)
