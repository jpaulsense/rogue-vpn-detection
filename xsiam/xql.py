#!/usr/bin/env python3
"""Run one XQL query against the tenant and print the rows.

Two calls, always: start_xql_query returns an execution id, get_query_results
polls it. A PENDING reply is normal and is not an error.

    ./xql.py 'dataset = agentscript_devicelocation_raw | fields host_name' 24h
    ./xql.py --raw 'dataset = playbook_tasks' 7d
"""
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402

UNITS = {"m": 60, "h": 3600, "d": 86400}


def seconds(window):
    return int(window[:-1]) * UNITS[window[-1]]


def run(query, window="24h", limit=100, timeout=120):
    now = int(time.time() * 1000)
    status, body = api.call("xql/start_xql_query", {"request_data": {
        "query": query,
        "tenants": [],
        "timeframe": {"from": now - seconds(window) * 1000, "to": now},
    }})
    if status != 200:
        raise SystemExit("start_xql_query %s: %s" % (status, body))
    exec_id = body["reply"]

    deadline = time.time() + timeout
    while time.time() < deadline:
        status, body = api.call("xql/get_query_results", {"request_data": {
            "query_id": exec_id, "pending_flag": False, "limit": limit,
            "format": "json"}})
        if status != 200:
            raise SystemExit("get_query_results %s: %s" % (status, body))
        reply = body["reply"]
        if reply.get("status") == "SUCCESS":
            results = reply.get("results", {})
            return results.get("data", []), reply
        if reply.get("status") in ("FAIL", "CANCELLED"):
            raise SystemExit("query %s: %s" % (reply.get("status"), reply))
        time.sleep(3)
    raise SystemExit("timed out after %ss" % timeout)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--raw"]
    raw = "--raw" in sys.argv
    if not args:
        raise SystemExit(__doc__)
    query = args[0]
    window = args[1] if len(args) > 1 else "24h"
    rows, reply = run(query, window)
    if raw:
        print(json.dumps(rows, indent=2, default=str))
    else:
        print("%d rows  (window %s)" % (len(rows), window))
        for row in rows:
            print(json.dumps({k: v for k, v in row.items() if v not in (None, "")},
                             default=str)[:1200])
