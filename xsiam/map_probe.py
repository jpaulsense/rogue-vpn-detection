#!/usr/bin/env python3
"""TEMPORARY. Find out what the Map graph type binds to, by building one of each.

The documentation names Map as a graph type and never says what it plots. It is
not in use anywhere on this tenant, so there is no working example to copy, and
the GitBook corpus answers "We couldn't answer this question". The only
remaining test is to render one and look at it, which is the same conclusion
WIDGETS.md reaches about every widget.

So: four widgets, identical except for the place string, each over the real
fleet so the count is real. Whichever ones draw a shape tell us the binding.

    ./map_probe.py --build     create the four widgets and the probe dashboard
    ./map_probe.py --verdict   record what rendered, then delete this file

DO NOT reuse these widget keys for anything real. A deleted widget_key is burned
on this tenant: the insert returns 200, reports the key in added_objects, and
stores nothing (WIDGETS.md, verified 2026-11-04).
"""
import argparse
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402

DATASET = "agentscript_devicelocation_raw"
DASHBOARD = "Map probe · delete me"

# Candidates, widest to narrowest. If only the first two draw, the binding is
# country level and an IP-to-country lookup is enough. If `California` draws,
# the map can answer the question the customer actually asked without any
# coordinate at all.
CANDIDATES = [
    ("country_name", "United States"),
    ("country_iso", "US"),
    ("state_name", "California"),
    ("city_name", "Sacramento"),
]


def query(place):
    return (
        "dataset = " + DATASET + "\n"
        "| filter host_name != null and host_name != \"__BEACON__\"\n"
        "| dedup host_name by desc _time\n"
        "| alter place = \"" + place + "\"\n"
        "| comp count_distinct(host_name) as devices by place\n"
        "| view graph type = map xaxis = place yaxis = devices"
    )


def build():
    keys = []
    for suffix, place in CANDIDATES:
        key = "xql_mapprobe_" + suffix
        payload = {
            "widget_key": key,
            "title": "Map probe: %s" % place,
            "description": "Temporary. Does the Map type plot the string %r?" % place,
            "data": {
                "phrase": query(place),
                "time_frame": {"relativeTime": 604800000},
                "viewOptions": {
                    "type": "map",
                    "commands": [
                        {"command": {"op": "=", "name": "xaxis", "value": "place"}},
                        {"command": {"op": "=", "name": "yaxis", "value": "devices"}},
                    ],
                },
            },
            "support_time_range": True,
            "additional_info": {"query_tables": [DATASET], "query_uses_library": False},
        }
        status, body = api.call("widgets/insert",
                                {"request_data": [{"widgets_data": [payload]}]})
        print("  %-28s %s %s" % (key, status, json.dumps(body)[:140]))
        keys.append(key)

    rows = [{"id": "row-%d" % i,
             "data": [{"key": k, "data": {"type": "Custom XQL",
                                          "width": 50, "height": 320}}]}
            for i, k in enumerate(keys)]
    payload = {
        "name": DASHBOARD,
        "description": "Temporary probe for the Map graph type. Safe to delete.",
        "status": "ENABLED",
        "layout": rows,
        "default_dashboard_id": 0,
        "global_id": hashlib.md5(DASHBOARD.encode("utf-8")).hexdigest(),
        "metadata": {},
        "dynamic_layout": None,
    }
    status, body = api.call("dashboards/insert",
                            {"request_data": [{"dashboards_data": [payload]}]})
    print("  dashboard %s %s" % (status, json.dumps(body)[:200]))

    # Read back. An insert that reports success and stores nothing is the
    # documented failure mode for this route, so never trust the reply alone.
    status, body = api.call("widgets/get", {"request_data": {}})
    live = {w["widget_key"] for o in body.get("objects", [])
            for w in o.get("widgets_data", [])}
    missing = [k for k in keys if k not in live]
    print("\n  stored: %d of %d%s" % (len(keys) - len(missing), len(keys),
                                      ("  MISSING: %s" % missing) if missing else ""))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--build", action="store_true")
    a = p.parse_args()
    if not a.build:
        raise SystemExit(__doc__)
    build()
