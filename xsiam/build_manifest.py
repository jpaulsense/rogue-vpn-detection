#!/usr/bin/env python3
"""Generate the agent script manifest FROM the script's actual return value.

WHY THIS EXISTS, measured 2026-11-07
    The manifest was hand-maintained and drifted. `run_detection` returned 41
    keys while the manifest declared 40: `max_score` was returned and never
    declared. The script uploaded fine, ran fine, and reported
    COMPLETED_SUCCESSFULLY on a single endpoint, and then
    `scripts/get_script_execution_results` answered a bare **HTTP 500** with no
    detail, on both v1 and v2, while the same route returned 200 for a snippet
    action at the same moment.

    So an undeclared key in a dictionary output does not fail at upload, does
    not fail at run time, and does not produce a readable error. It fails when
    something tries to read the results back. That is unrecoverable by
    inspection, which is why the manifest is now derived rather than written.

    Run --check in any pre-flight. It exits 1 the moment the script returns a
    key the manifest does not declare.

Usage:
    ./build_manifest.py            regenerate both manifests
    ./build_manifest.py --check    exit 1 on drift, change nothing
"""
import json
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "vpn_location_detect.py"
MANIFEST = HERE / "vpn_location_detect.manifest.json"
MANIFEST_ALT = HERE / "vpn_location_detect.manifest.stringflags.json"

NAME = "vpn_location_detect"
# 200 characters is the console's cap and it is not documented. 453 was rejected.
DESCRIPTION = ("Detects consumer VPN location spoofing from the endpoint: WiFi BSSIDs, "
               "timezone, VPN adapters, processes, software, DNS, routing, first public "
               "hop and per-anchor latency.")

INPUTS = [
    ("google_api_key", "string"),
    ("enrich", "boolean"),
    ("scan_wifi", "boolean"),
    ("latency_anchors", "string"),
    ("sanctioned_patterns", "string"),
]

# Only fields needing a non-obvious type or label. Everything else is inferred
# from the value the script actually returns.
OVERRIDES = {
    "ip_address": ("Source IP", "ip"),
    "first_public_hop": ("First Public Hop", "ip"),
    "ip_asn": ("Source ASN", "string"),
    "ip_isp": ("Source ISP", "string"),
    "bssid_payload_b64": ("BSSID Payload", "string"),
    "anchor_rtts": ("Anchor RTTs", "string"),
    "utc_offset_hours": ("UTC Offset", "number"),
    "anycast_rtt_ms": ("Anycast RTT ms", "number"),
    "duration_s": ("Duration s", "number"),
    "tailscale_derp": ("Tailscale DERP", "string"),
    "tailscale_direct_peers": ("TS Direct Peers", "number"),
    "tailscale_relay_peers": ("TS Relay Peers", "number"),
    "split_default_pair": ("Full Tunnel Routing", "boolean"),
}
# Fields whose runtime value is None on a clean run, so the type cannot be
# inferred and must be stated.
NULLABLE_TYPES = {
    "physical_location": "string", "physical_lat": "number",
    "physical_lng": "number", "in_california": "boolean",
    "ip_location": "string", "timezone_key": "string",
    "first_public_hop_distance": "number", "anchor_type": "string",
}


def returned_keys():
    """Run the script and take the keys it ACTUALLY returns.

    Flags are false so the run is fast and makes no outbound calls; the key set
    does not depend on them, because run_detection builds one dict literal.
    """
    out = subprocess.run([sys.executable, str(SCRIPT), "", "false", "false"],
                         stdout=subprocess.PIPE, check=True).stdout.decode()
    return json.loads(out)


def infer(name, value):
    if name in OVERRIDES:
        return OVERRIDES[name]
    friendly = name.replace("_", " ").title()
    if name in NULLABLE_TYPES:
        return friendly, NULLABLE_TYPES[name]
    if isinstance(value, bool):
        return friendly, "boolean"
    if isinstance(value, (int, float)):
        return friendly, "number"
    return friendly, "string"


# PROVEN TYPES, measured 2026-11-07 by elimination on jpse-ca-gov.
#   file_exists  output boolean           -> results fetch 200
#   test_acs     dictionary, string+bool  -> results fetch 200
#   registry_get dictionary, string       -> ships with the product
#   vpn_location_detect, the ONLY script on the tenant declaring `ip` or
#   `number` inside a dictionary          -> results fetch a bare HTTP 500
#
# The action completes successfully either way; only reading the results back
# fails, with no detail on v1 or v2. So the exotic types are confined to the
# display layer and are not worth a broken read path. Everything is declared
# `string` here. The dataset's own schema does the real typing, in
# build_dashboard.SCHEMA for the lookup and in the collector for the raw
# dataset, so nothing downstream loses a number.
# Everything is `string`, not just the exotic types. A field declared boolean
# whose value is "" (unknown, because enrichment did not run) is the same class
# of mismatch as `ip` holding a null, and "" is semantically right: in_california
# is genuinely UNKNOWN on a non-enriched run, which False would misreport.
SAFE_TYPES = {"string"}


def build(result, boolean_flags=True):
    outputs = []
    for name, value in result.items():
        friendly, typ = infer(name, value)
        if typ not in SAFE_TYPES:
            typ = "string"
        outputs.append({"name": name, "friendly_name": friendly, "type": typ})
    assert len(DESCRIPTION) <= 200, "description over the 200-char cap"
    return {
        "name": NAME,
        "description": DESCRIPTION,
        "outcome": "Standard",
        "platform": "Windows,macOS",
        "timeout": 600,
        "entry_point": "run_detection",
        "entry_point_definition": {
            "input_params": [
                {"name": n, "type": t if (boolean_flags or t != "boolean") else "string"}
                for n, t in INPUTS],
            "output_params": {"type": "JSON", "value": outputs},
        },
    }


def serialise(manifest):
    line = json.dumps(manifest, separators=(",", ":"))
    assert "\n" not in line and "\t" not in line, "manifest must be a single line"
    return line


def main():
    check = "--check" in sys.argv
    result = returned_keys()
    primary = serialise(build(result, boolean_flags=True))
    fallback = serialise(build(result, boolean_flags=False))

    if check:
        drift = False
        for path, want in ((MANIFEST, primary), (MANIFEST_ALT, fallback)):
            have = path.read_text().strip() if path.exists() else ""
            if have != want:
                print("DRIFT: %s does not match the script's return" % path.name)
                if path.exists():
                    declared = {f["name"] for f in json.loads(have)
                                ["entry_point_definition"]["output_params"]["value"]}
                    missing = sorted(set(result) - declared)
                    extra = sorted(declared - set(result))
                    if missing:
                        print("  returned but NOT declared (this is the 500):", missing)
                    if extra:
                        print("  declared but not returned:", extra)
                drift = True
        if drift:
            return 1
        print("OK: both manifests match the %d keys run_detection returns."
              % len(result))
        return 0

    MANIFEST.write_text(primary)
    MANIFEST_ALT.write_text(fallback)
    print("wrote %s (%d bytes) and %s (%d bytes); %d output fields"
          % (MANIFEST.name, len(primary), MANIFEST_ALT.name, len(fallback), len(result)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
