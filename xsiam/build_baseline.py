#!/usr/bin/env python3
"""Compute what normal looks like for each device, and store it.

THE WHOLE IDEA. Every observable this detection collects is meaningless on its
own. `first_public_hop = 192.77.111.1` is not suspicious; it is suspicious on a
device that has reported a different address on all 47 of its previous scans.
So the baseline is the thing that makes the rest legible, and it is per device
and never fleet-wide: a regional office is not an anomaly, and no global list
of acceptable addresses can survive an estate with many egress points.

FOUR AXES, RANKED BY HOW HARD THEY ARE TO SPOOF

  gateway_macs    L2 neighbour. Below any tunnel, needs no entitlement, works
                  wired. Added 2026-11-10 because the BSSID axis is gated off
                  on macOS.
  bssids          RF environment. Strongest where available, Windows only in
                  practice.
  timezone_key    OS clock. Changes when travelling unless set deliberately.
  first_public_hop / ip_asn
                  Egress. The weakest and the easiest to read, which is why
                  everyone stops here. A VPN changes it by design.

WHY A LOOKUP, HAVING ARGUED AGAINST ONE FOR HISTORY

A lookup has no `_time` and ignores the query timeframe, which is exactly what
made it the wrong home for scan history and produced a dashboard frozen on a
Saturday. The baseline is the opposite shape: one small mutable row per device,
read by joining, never plotted over time. That is a reference table.

AGGREGATION HAPPENS HERE, NOT IN XQL. Ten devices and a few hundred rows fit in
memory, and a nested comp with values() over pipe-joined sets is far harder to
get right than the equivalent twenty lines of Python. Revisit at fleet scale.

    ./build_baseline.py --dataset     create the lookup dataset
    ./build_baseline.py --compute     compute and upsert, print what changed
    ./build_baseline.py --show        print the stored baseline
"""
import argparse
import collections
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402
import xql  # noqa: E402

HISTORY = "agentscript_devicelocation_raw"
BASELINE = "vpn_location_baseline"
BEACON = "__BEACON__"
WINDOW = "30d"

# Maturity. A device below BOTH of these produces no finding at any confidence,
# which is what stops a newly enrolled laptop alerting on its first trip. These
# are a starting position, not a measured one: revisit once the fleet has a
# month of daily scans behind it.
MATURE_DAYS = 14
MATURE_SCANS = 10

# Set-valued axes, held as pipe-joined strings on the scan row.
SET_AXES = ["gateway_macs", "bssids", "first_public_hop", "ip_asn", "timezone_key"]

SCHEMA = {
    "host_name": "text",
    "gateway_macs": "text", "bssids": "text", "first_public_hop": "text",
    "ip_asn": "text", "timezone_key": "text",
    "anycast_typical": "number",
    "scan_count": "number", "scan_days": "number",
    "axes_available": "number", "mature": "bool",
    "first_seen": "text", "last_seen": "text", "baseline_updated": "text",
}


def _values(raw):
    """Split a pipe-joined cell into its members. Empty stays empty."""
    if raw is None or raw == "":
        return []
    return [v.strip() for v in str(raw).split("|") if v.strip()]


def fetch():
    """No `| fields` list, deliberately.

    A raw dataset only carries a column once a value for it has arrived. Naming
    an axis that has never been populated fails the whole query at validation:
    `unknown field ip_asn`, because enrichment is off so nothing has ever
    written one. The same would happen for `gateway_macs` until the new agent
    script is uploaded.

    Selecting everything and reading the axes defensively means a new axis
    starts contributing to the baseline the day its first value lands, with no
    change here.
    """
    rows, _ = xql.run(
        "dataset = " + HISTORY + "\n"
        "| filter host_name != null and host_name != \"" + BEACON + "\"",
        WINDOW, limit=5000)
    return rows


def compute(rows):
    """One baseline per device. Counts are per distinct scan, never per row.

    The per-scan rule matters: on 2026-11-08 a fan-out bug wrote 41 identical
    rows per host for one sweep, and those rows are permanent because a raw
    dataset has no selective delete. Counting rows would report that device as
    having six times the history it has, and a maturity gate reading that count
    would let an immature device through.
    """
    by_host = collections.defaultdict(lambda: {
        "axes": collections.defaultdict(collections.Counter),
        "scans": set(), "anycast": collections.Counter(),
        "first": None, "last": None,
    })

    for row in rows:
        host = row.get("host_name")
        if not host:
            continue
        agg = by_host[host]
        scan = row.get("scanned_at")
        if scan in agg["scans"]:
            continue                       # a duplicate of a scan already counted
        agg["scans"].add(scan)
        for axis in SET_AXES:
            for value in _values(row.get(axis)):
                agg["axes"][axis][value] += 1
        reach = row.get("anycast_reachable")
        if reach is not None:
            agg["anycast"][int(reach)] += 1
        # SPAN IS MEASURED ON scanned_at, NOT _time, and the difference is not
        # cosmetic. `_time` is when the row was ingested; `scanned_at` is when
        # the endpoint actually ran. Rows backfilled from an earlier action
        # carry a scanned_at days before their _time, and the collector here
        # was only created on 2026-11-07, so `_time` reports 2.6 days of
        # history for a device observed since 2026-11-05. Maturity is a claim
        # about how long the device has been watched, so it has to read the
        # observation time or it under-counts every backfill and holds a device
        # immature for longer than it should be.
        stamp = scan if isinstance(scan, (int, float)) else row.get("_time")
        if stamp is not None:
            agg["first"] = stamp if agg["first"] is None else min(agg["first"], stamp)
            agg["last"] = stamp if agg["last"] is None else max(agg["last"], stamp)

    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    out = []
    for host, agg in sorted(by_host.items()):
        scan_count = len(agg["scans"])
        span_ms = (agg["last"] - agg["first"]) if agg["first"] and agg["last"] else 0
        scan_days = round(span_ms / 86400000.0, 1)
        row = {
            "host_name": host,
            "scan_count": scan_count,
            "scan_days": scan_days,
            # An axis counts as available only if this device has ever produced
            # a value for it. A Mac with no BSSID is a three-axis device, and
            # saying so on the baseline is what stops a later reader treating
            # its silence as agreement.
            "axes_available": sum(1 for a in ("gateway_macs", "bssids",
                                              "timezone_key", "first_public_hop")
                                  if agg["axes"][a]),
            "mature": scan_days >= MATURE_DAYS and scan_count >= MATURE_SCANS,
            "anycast_typical": (agg["anycast"].most_common(1)[0][0]
                                if agg["anycast"] else 0),
            "first_seen": _iso(agg["first"]),
            "last_seen": _iso(agg["last"]),
            "baseline_updated": now,
        }
        for axis in SET_AXES:
            # value=count, most common first, so a reader can see which value is
            # the device's home and which was a one-off.
            #
            # `=` and not `:`. A MAC address is colon-separated, so `value:count`
            # renders c2:ba:81:2a:4e:d3 with two scans as
            # "c2:ba:81:2a:4e:d3:2", which no reader and no parser can split
            # back. Every axis value here is a MAC, an IP, an ASN or a timezone
            # key, and none of them contains an equals sign.
            row[axis] = "|".join("%s=%d" % (v, n)
                                 for v, n in agg["axes"][axis].most_common(12))
        out.append(row)
    return out


def _iso(ms):
    if not ms:
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ms / 1000.0))


def make_dataset():
    status, body = api.call("xql/add_dataset", {"request_data": {
        "dataset_name": BASELINE, "dataset_type": "lookup",
        "dataset_schema": SCHEMA}})
    print("  %-26s %s %s" % (BASELINE, status, json.dumps(body)[:160]))


def upsert(rows):
    # `data` must be a LIST of row objects. The published schema says an object
    # of key-value pairs; pass that and the API reads each PAIR as a row and
    # answers 200 with "rows skipped: <your field count>".
    status, body = api.call("xql/lookups/add_data", {"request_data": {
        "dataset_name": BASELINE, "key_fields": ["host_name"], "data": rows}})
    print("  upsert %s %s" % (status, json.dumps(body)[:200]))
    return status == 200


def show():
    rows, _ = xql.run("dataset = " + BASELINE + " | sort asc host_name", "7d")
    for r in rows:
        print("%-46s scans=%-3s days=%-5s axes=%s mature=%-5s" % (
            r.get("host_name"), r.get("scan_count"), r.get("scan_days"),
            r.get("axes_available"), r.get("mature")))
        for axis in SET_AXES:
            if r.get(axis):
                print("    %-18s %s" % (axis, r[axis]))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", action="store_true")
    p.add_argument("--compute", action="store_true")
    p.add_argument("--show", action="store_true")
    a = p.parse_args()
    if not any(vars(a).values()):
        raise SystemExit(__doc__)
    if a.dataset:
        make_dataset()
    if a.compute:
        rows = compute(fetch())
        print("  %d devices" % len(rows))
        for r in rows:
            print("    %-46s scans=%-3d days=%-5s axes=%d mature=%s"
                  % (r["host_name"], r["scan_count"], r["scan_days"],
                     r["axes_available"], r["mature"]))
        upsert(rows)
    if a.show:
        show()
