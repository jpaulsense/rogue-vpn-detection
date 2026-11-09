#!/usr/bin/env python3
"""Create the device-location datasets, widgets and dashboard on the tenant.

ONE WRITER. Per the measured lesson in the xsiam-xql-correlation skill, a
deployed object with two authors drifts silently: the tenant copy gets fixed by
hand, the script overwrites it with the old wiring, and nothing warns. This file
is the only thing that should write these objects. Edit here, re-run, never
hand-edit in the console.

Usage:
    ./build_dashboard.py --datasets     create the two lookup datasets
    ./build_dashboard.py --widgets      create or replace the widgets
    ./build_dashboard.py --dashboard    create the dashboard
    ./build_dashboard.py --all
"""
import argparse
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402

# History lives in a RAW dataset, not a lookup. A lookup has no _time and
# ignores the query timeframe, so the dashboard time picker does nothing on it.
# Measured 2026-11-06. Created by ingestion from the HTTP collector configured
# with Vendor 'agentscript' and Product 'devicelocation'; it cannot be created
# by API, because xql/add_dataset answers "Dataset type: raw is not supported".
HISTORY = "agentscript_devicelocation_raw"
LEGACY_HISTORY_LOOKUP = "vpn_location_history"
CURRENT = "vpn_location_current"

# The automation writes a __BEACON__ row at each stage of a sweep so a failing
# run says where it stopped. Those rows are in the same dataset as the scans
# and carry a host_name, so `filter host_name != null` does NOT exclude them:
# every by-device widget listed __BEACON__ as an eleventh device all weekend.
BEACON = "__BEACON__"

# datetime so XQL gets a real time axis; everything else text or number.
SCHEMA = {
    "scanned_at": "datetime", "host_name": "text", "agent_id": "text",
    "confidence": "text", "score": "number", "indicators": "text",
    "wifi_method": "text", "bssid_count": "number", "bssids": "text",
    "timezone_key": "text", "utc_offset_hours": "number",
    "first_public_hop": "text", "anchor_type": "text", "anchor_rtts": "text",
    "anycast_reachable": "number", "anycast_rtt_ms": "number",
    "tailscale_derp": "text", "tailscale_relay_peers": "number",
    "dns_servers": "text", "vpn_adapters": "text", "vpn_processes": "text",
    "vpn_software": "text", "sanctioned_vpn": "text",
    "split_default_pair": "bool", "in_california": "bool",
    "physical_location": "text", "ip_address": "text", "ip_location": "text",
    "ip_asn": "text", "errors": "text",
}

# widget_key MUST start with "xql_" or insert returns
# 200 with errors[].error "widget_key must start with xql_".
# EVERY WIDGET READS THE RAW DATASET. Two of them read the CURRENT lookup
# until 2026-11-09 and showed Saturday's data all weekend, because the lookup
# is written by run_detection.py --push from this laptop and the nightly job
# does not write it at all. Nothing announced that: the widgets rendered,
# with real rows, 38 hours old. One dataset with one writer cannot go stale
# that way, and `dedup host_name by desc _time` gives the same latest-per-
# device result the lookup existed to serve.
#
# The lookup is NOT retired -- it is still the right shape for joining device
# state onto another query. It is just not a dashboard source.
REAL_ROWS = ("| filter host_name != null and host_name != \"" + BEACON + "\"\n")

# `scans` counts DISTINCT scanned_at, not rows. On 2026-11-08 one run wrote 41
# identical rows per host (see README, results fan-out), and count() reported
# 46 scans for a device that had been scanned six times. Those rows are still
# in the dataset and a raw dataset has no selective delete, so the query has
# to be the thing that is robust to them.
WIDGETS = [
    {
        "key": "xql_vpnloc_current_state",
        "title": "Device location · current state",
        "description": "Latest scan per device. Egress point, reachability and sanctioned VPN.",
        "query": (
            "dataset = " + HISTORY + "\n"
            + REAL_ROWS +
            "| dedup host_name by desc _time\n"
            "| fields host_name, scanned_at, first_public_hop, anycast_reachable,\n"
            "         tailscale_derp, wifi_method, timezone_key, sanctioned_vpn, confidence\n"
            "| sort asc host_name"
        ),
        "view": None,
    },
    {
        "key": "xql_vpnloc_movement",
        "title": "Device movement · distinct egress points",
        "description": "A device seen behind more than one egress point has moved networks.",
        "query": (
            "dataset = " + HISTORY + "\n"
            + REAL_ROWS +
            "| comp count_distinct(scanned_at) as scans,\n"
            "       count_distinct(first_public_hop) as networks,\n"
            "       values(first_public_hop) as egress_points,\n"
            "       min(scanned_at) as first_seen, max(scanned_at) as last_seen by host_name\n"
            "| alter moved = if(networks > 1, \"MOVED\", \"stationary\")\n"
            "| sort desc networks"
        ),
        "view": None,
    },
    {
        "key": "xql_vpnloc_egress_spread",
        "title": "Egress points by device count",
        "description": "Where the fleet leaves the internet from. One tall bar is the office.",
        "query": (
            "dataset = " + HISTORY + "\n"
            + REAL_ROWS +
            "| filter first_public_hop != null\n"
            "| comp count_distinct(host_name) as devices by first_public_hop\n"
            "| sort desc devices\n"
            "| limit 15\n"
            "| view graph type = column xaxis = first_public_hop yaxis = devices layout = horizontal"
        ),
        "view": [("xaxis", "first_public_hop"), ("yaxis", "devices"),
                 ("layout", "horizontal")],
        "graph": "column",
    },
    {
        "key": "xql_vpnloc_restricted_net",
        "title": "Devices on a restricted network",
        "description": (
            "Zero of three public resolvers reachable. Guest and hotel networks block "
            "outbound 53 to force their own resolver, so this is a not-your-network tell."
        ),
        "query": (
            "dataset = " + HISTORY + "\n"
            + REAL_ROWS +
            "| dedup host_name by desc _time\n"
            "| filter anycast_reachable = 0\n"
            "| fields host_name, scanned_at, first_public_hop, dns_servers, anchor_rtts\n"
            "| sort asc host_name"
        ),
        "view": None,
    },
    {
        "key": "xql_vpnloc_scan_coverage",
        "title": "Scan coverage · last seen per device",
        "description": "A device that stopped reporting is not the same as a device that is clean.",
        "query": (
            "dataset = " + HISTORY + "\n"
            + REAL_ROWS +
            "| comp count_distinct(scanned_at) as scans,\n"
            "       max(scanned_at) as last_scan by host_name\n"
            "| sort asc last_scan"
        ),
        "view": None,
    },
]

TIME_FRAME = {"relativeTime": 604800000}   # 7 days
DASHBOARD_NAME = "Device Location \u00b7 VPN spoofing"


def make_datasets():
    for name in (HISTORY, CURRENT):
        status, body = api.call("xql/add_dataset", {"request_data": {
            "dataset_name": name, "dataset_type": "lookup",
            "dataset_schema": SCHEMA}})
        print("  %-26s %s %s" % (name, status, json.dumps(body)[:120]))


def widget_payload(spec):
    """Build one widget.

    EVERY WIDGET NEEDS viewOptions, INCLUDING A PLAIN TABLE. Omit it and
    `widgets/insert` returns 200, `widgets/get` reads the widget back intact,
    every query runs clean over the API — and the panel renders
    "Error initializing xql widget" in the console, with nothing anywhere
    naming the field that is missing. Measured 2026-11-09: our four table
    widgets were the only 4 of the tenant's 69 with no viewOptions, and the
    only 4 that failed. A working table on this tenant carries exactly
    {"type": "table", "commands": []}.
    """
    data = {"phrase": spec["query"], "time_frame": TIME_FRAME}
    if spec.get("view"):
        data["viewOptions"] = {
            "type": spec.get("graph", "column"),
            "commands": [{"command": {"op": "=", "name": n, "value": v}}
                         for n, v in spec["view"]],
        }
    else:
        data["viewOptions"] = {"type": "table", "commands": []}
    tables = [t for t in (HISTORY, CURRENT) if t in spec["query"]]
    # support_time_range must be FALSE for a widget over a LOOKUP dataset.
    # A lookup has no _time, so the dashboard's time picker has nothing to
    # filter on and the widget misbehaves in the UI while the same query runs
    # clean over the API. Only the raw dataset carries a real time axis.
    time_ranged = HISTORY in spec["query"]
    return {
        "widget_key": spec["key"],
        "title": spec["title"],
        "description": spec["description"],
        "data": data,
        "support_time_range": time_ranged,
        "additional_info": {"query_tables": tables, "query_uses_library": False},
    }


def make_widgets():
    created = []
    for spec in WIDGETS:
        payload = widget_payload(spec)
        # request_data IS the list. Wrapping it in an object returns
        # 400 "The request should contain only a list of JSONs", the same trap
        # the xsiam-xql-correlation skill records for correlations/insert.
        status, body = api.call("widgets/insert",
                                {"request_data": [{"widgets_data": [payload]}]})
        print("  %-26s %s %s" % (spec["key"], status, json.dumps(body)[:160]))
        if status == 200:
            created.append(spec["key"])
    return created


def make_dashboard(widget_keys):
    """Dashboard shape, copied from a live object rather than invented.

    Required fields the API does not document and will reject you for:
      global_id            a 32-char hex id. Absent -> 200 with
                           errors[].error "No global id present in one of the
                           imported dashboards". Derived from the name here so
                           re-running updates the same dashboard.
      layout               a list of ROWS, each {"id", "data": [cells]}. A flat
                           list of widgets is not accepted.
      cell.data.type       "Custom XQL" for an XQL widget.
    """
    import hashlib
    rows = []
    for index, key in enumerate(widget_keys):
        rows.append({
            "id": "row-%d" % index,
            "data": [{"key": key,
                      "data": {"type": "Custom XQL", "width": 100, "height": 350}}],
        })
    payload = {
        "name": DASHBOARD_NAME,
        "description": ("Where the fleet is, and which devices have moved "
                        "networks. Built by build_dashboard.py; do not edit here."),
        "status": "ENABLED",
        "layout": rows,
        "default_dashboard_id": 0,
        "global_id": hashlib.md5(DASHBOARD_NAME.encode("utf-8")).hexdigest(),
        "metadata": {},
        "dynamic_layout": None,
    }
    status, body = api.call("dashboards/insert",
                            {"request_data": [{"dashboards_data": [payload]}]})
    print("  dashboard %s %s" % (status, json.dumps(body)[:400]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets", action="store_true")
    parser.add_argument("--widgets", action="store_true")
    parser.add_argument("--dashboard", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    if not any(vars(args).values()):
        parser.print_help()
        return

    keys = [w["key"] for w in WIDGETS]
    if args.datasets or args.all:
        print("datasets:")
        make_datasets()
    if args.widgets or args.all:
        print("widgets:")
        keys = make_widgets() or keys
    if args.dashboard or args.all:
        print("dashboard:")
        make_dashboard(keys)


if __name__ == "__main__":
    main()
