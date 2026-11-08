#!/usr/bin/env python3
"""Run vpn_location_detect on tenant endpoints and print the results.

WHY A SNIPPET AND NOT THE SCRIPTS LIBRARY
  There is no API to upload an agent script. The documented script-execution
  routes are get_scripts, get_script_metadata, get_script_code, run_script and
  run_snippet_code_script: all read or execute, none write. `scripts/insert`
  exists but returns YAML in a zip, so it manages XSOAR automations, not agent
  scripts. Putting vpn_location_detect in the Scripts Library is a console job.

  `run_snippet_code_script` needs no upload, which makes it the right tool for
  iterating. The tradeoffs versus a library script:
    - No manifest, so no named output fields and no filterable results table.
      Everything arrives as stdout, which this tool parses as JSON.
    - No entry point, so the snippet must call itself. Appended below.
    - Needs both "Run High-risk scripts" and "Script configuration" permissions.

Usage:
    ./run_detection.py --list
    ./run_detection.py --host "Jared's MacBook Air"
    ./run_detection.py --host windows-test --anchors "198.51.100.10:443"
    ./run_detection.py --all-workstations
    ./run_detection.py --results 97
"""
import argparse
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / "vpn_location_detect.py"

# Appended to the module source. The snippet runner executes top to bottom with
# no entry point, and __name__ is not reliably "__main__", so the call is
# explicit. Markers bracket the JSON so stdout stays parseable even if the agent
# or the script itself writes anything else.
INVOKE = '''
import json as _json
try:
    _r = run_detection(%(key)r, %(enrich)r, %(wifi)r, %(anchors)r, %(sanctioned)r)
    print("__VPNDETECT_BEGIN__")
    print(_json.dumps(_r))
    print("__VPNDETECT_END__")
except Exception:
    import traceback as _tb
    print("__VPNDETECT_ERROR__")
    _tb.print_exc()
'''


def endpoints():
    status, body = api.call("endpoints/get_endpoints",
                            {"request_data": {"search_from": 0, "search_to": 200}})
    if status != 200:
        raise SystemExit("get_endpoints returned %s" % status)
    return body["reply"]


def build_snippet(args):
    source = SCRIPT.read_text(encoding="utf-8")
    return source + INVOKE % {
        "key": args.api_key, "enrich": bool(args.enrich),
        "wifi": not args.no_wifi, "anchors": args.anchors,
        "sanctioned": args.sanctioned,
    }


def submit(snippet, agent_ids, timeout):
    status, body = api.call("scripts/run_snippet_code_script", {"request_data": {
        "filters": [{"field": "endpoint_id_list", "operator": "in", "value": agent_ids}],
        "snippet_code": snippet,
        "timeout": timeout,
    }})
    if status != 200:
        raise SystemExit("run_snippet_code_script returned %s: %s" % (status, body))
    return body["reply"]["action_id"]


def wait(action_id, poll=10, limit=24):
    """Wait for the action, but do not wait on PENDING.

    PENDING means the agent has not pulled the request yet, and a closed laptop
    stays that way for up to the four days before the action expires. Blocking on
    it wastes the whole poll budget and reports TIMED_OUT_WAITING for a run that
    is working exactly as designed. So this returns as soon as nothing is moving:
    everything has reached a terminal state, or the only thing left is PENDING.
    Re-read later with --results <action_id>.
    """
    terminal = {"COMPLETED_SUCCESSFULLY", "FAILED", "EXPIRED", "CANCELED", "TIMEOUT"}
    for _ in range(limit):
        _, body = api.call("scripts/get_script_execution_status",
                           {"request_data": {"action_id": str(action_id)}})
        reply = body.get("reply") or {}
        general = reply.get("general_status")
        if general in terminal:
            return general
        pending = reply.get("endpoints_pending") or 0
        in_progress = reply.get("endpoints_in_progress") or 0
        if in_progress == 0 and pending:
            return "%s (%d endpoint(s) still PENDING, agent has not polled; " \
                   "re-read with --results %s)" % (general, pending, action_id)
        time.sleep(poll)
    return "TIMED_OUT_WAITING"


def parse_stdout(text):
    if not text:
        return None
    if "__VPNDETECT_BEGIN__" not in text:
        return None
    chunk = text.split("__VPNDETECT_BEGIN__", 1)[1].split("__VPNDETECT_END__", 1)[0]
    try:
        return json.loads(chunk.strip())
    except ValueError:
        return None


FIELDS = ["confidence", "score", "indicators", "wifi_method", "bssid_count",
          "bssids", "timezone_key", "vpn_adapters", "vpn_processes",
          "vpn_software", "sanctioned_vpn", "split_default_pair",
          "first_public_hop", "anchor_rtts", "anchor_type", "anycast_rtt_ms",
          "duration_s", "errors"]


PUSH_FIELDS = [
    "scanned_at", "host_name", "agent_id", "confidence", "score", "indicators",
    "wifi_method", "bssid_count", "bssids", "timezone_key", "utc_offset_hours",
    "first_public_hop", "anchor_type", "anchor_rtts", "anycast_reachable",
    "anycast_rtt_ms", "tailscale_derp", "tailscale_relay_peers", "dns_servers",
    "vpn_adapters", "vpn_processes", "vpn_software", "sanctioned_vpn",
    "split_default_pair", "in_california", "physical_location", "ip_address",
    "ip_location", "ip_asn", "errors",
]


def push_collector(rows):
    """Append scan rows to a RAW dataset through the HTTP Log Collector.

    This is the correct home for history. Measured 2026-11-06: a lookup dataset
    has NO `_time` column, only `_insert_time` and `_update_time`, and it ignores
    the query timeframe completely. The same query over `vpn_location_history`
    returned 13 rows at a 3-day window and 13 at a 60-second window, while
    `xdr_data` over 60 seconds correctly returned 1. So on a lookup the dashboard
    time picker does nothing, "movement over the last 7 days" is not expressible,
    and a correlation rule's search window is meaningless. A lookup is a mutable
    reference table, and location history is an append-only time series.

    The collector wants gzip: a plain JSON body returns
    400 `gzip compression error (invalid header)`.

    The dataset name is NOT chosen by the caller. XSIAM derives it from the
    Vendor and Product set when the collector is created, as `<vendor>_<product>_raw`,
    so pointing this somewhere new is a console step.
    """
    import gzip as _gzip
    creds = api.load_creds()
    # DEVLOC collector: Vendor 'agentscript', Product 'devicelocation', so
    # ingestion creates agentscript_devicelocation_raw. Falls back to the
    # tenant's general collector only if the dedicated one is absent.
    url = (creds.get("%s_DEVLOC_COLLECTOR_URL" % api.PREFIX)
           or creds.get("%s_HTTP_COLLECTOR_URL" % api.PREFIX))
    token = (creds.get("%s_DEVLOC_COLLECTOR_TOKEN" % api.PREFIX)
             or creds.get("%s_HTTP_COLLECTOR_TOKEN" % api.PREFIX))
    if not (url and token):
        print("push: no HTTP collector configured, skipping raw history")
        return
    body = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    proc = subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "60",
         "-X", "POST", url,
         "-H", "Authorization: %s" % token,
         "-H", "Content-Type: application/json",
         "-H", "Content-Encoding: gzip",
         "--data-binary", "@-"],
        input=_gzip.compress(body), stdout=subprocess.PIPE)
    print("push collector: HTTP %s (%d rows)"
          % (proc.stdout.decode().strip(), len(rows)))


def push(action_id, agent_ids=None, history="collector"):
    """Write an action's results to the current-state lookup and to history.

    vpn_location_current  lookup, upsert on host_name. Latest state per device.
                          This is what a lookup is FOR: small, typed, mutable,
                          joinable as enrichment. It stays whatever else changes.

    history="collector"   DEFAULT. agentscript_devicelocation_raw, through the
                          HTTP collector. _time native, timeframe works,
                          retention applies. Verified 2026-11-07: 24h window
                          returns 10 rows, 60s window returns 0.
    history="lookup"      the retired vpn_location_history stopgap. Kept only so
                          an old run can be replayed; it has no _time.

    TWO SHAPE TRAPS on the lookup API, both of which return HTTP 200 and do
    nothing useful: `data` must be a LIST of row objects. The published schema
    says it is an object of key-value pairs; pass that and the API reads each
    PAIR as a row and answers {"rows added": 0, "rows skipped": 24}. Nothing
    errors. `filters` on remove_data is a list too, for the same reason.
    """
    _, body = api.call("scripts/get_script_execution_results",
                       {"request_data": {"action_id": str(action_id)}})
    ids = agent_ids or {e["host_name"]: e["agent_id"] for e in endpoints()}

    rows, latest = [], {}
    for result in (body.get("reply") or {}).get("results", []):
        parsed = parse_stdout(result.get("standard_output"))
        if not parsed:
            continue
        host = result.get("endpoint_name")
        row = {}
        for field in PUSH_FIELDS:
            value = parsed.get(field)
            if field == "host_name":
                value = host
            elif field == "agent_id":
                value = ids.get(host, "")
            if value is None or value == "":
                continue
            row[field] = (value if isinstance(value, (str, int, float, bool))
                          else json.dumps(value))
        rows.append(row)
        if row.get("scanned_at", "") >= latest.get(host, {}).get("scanned_at", ""):
            latest[host] = row

    if not rows:
        print("push: nothing to write (no parseable results yet)")
        return

    if history == "collector":
        push_collector(rows)
    else:
        status, reply = api.call("xql/lookups/add_data", {"request_data": {
            "dataset_name": "vpn_location_history", "data": rows}})
        print("push history (lookup, temporary): %s %s"
              % (status, json.dumps(reply)[:120]))
    status, reply = api.call("xql/lookups/add_data", {"request_data": {
        "dataset_name": "vpn_location_current",
        "key_fields": ["host_name"], "data": list(latest.values())}})
    print("push current: %s %s" % (status, json.dumps(reply)[:120]))


def show(action_id):
    _, body = api.call("scripts/get_script_execution_results",
                       {"request_data": {"action_id": str(action_id)}})
    for row in (body.get("reply") or {}).get("results", []):
        print("=" * 72)
        print("%s   [%s]" % (row.get("endpoint_name"), row.get("execution_status")))
        parsed = parse_stdout(row.get("standard_output"))
        if parsed is None:
            print("  no parseable result. raw stdout:")
            print("  " + str(row.get("standard_output"))[:2000].replace("\n", "\n  "))
            continue
        for field in FIELDS:
            value = parsed.get(field)
            if value not in (None, "", {}, []):
                print("  %-22s %s" % (field, value))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", action="store_true", help="list endpoints and exit")
    parser.add_argument("--host", action="append", default=[],
                        help="host name, repeatable; substring match")
    parser.add_argument("--all-workstations", action="store_true")
    parser.add_argument("--results", help="just fetch results for an action id")
    parser.add_argument("--push", metavar="ACTION_ID",
                        help="write an action's results to the lookup datasets")
    parser.add_argument("--no-push", action="store_true",
                        help="skip the automatic dataset write after a run")
    parser.add_argument("--history", choices=("lookup", "collector"),
                        default="collector",
                        help="where scan history goes. 'collector' is the raw "
                             "dataset and the default; 'lookup' is the retired "
                             "stopgap and has no _time")
    parser.add_argument("--anchors", default="", help="unicast anchors, host:port,...")
    parser.add_argument("--sanctioned", default="", help="sanctioned VPN patterns")
    parser.add_argument("--api-key", default="", help="Google key; PoC only")
    parser.add_argument("--enrich", action="store_true", help="resolve on endpoint")
    parser.add_argument("--no-wifi", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    if args.push:
        return push(args.push, history=args.history)
    if args.results:
        return show(args.results)

    eps = endpoints()
    if args.list:
        for e in sorted(eps, key=lambda e: e["host_name"]):
            print("%-52s %-12s %-10s %s" % (
                e["host_name"], e.get("agent_type"), e.get("agent_status"),
                e["agent_id"]))
        return

    if args.all_workstations:
        chosen = [e for e in eps if e.get("agent_type") == "Workstation"
                  and e.get("agent_status") == "CONNECTED"]
    else:
        chosen = [e for e in eps
                  if any(h.lower() in e["host_name"].lower() for h in args.host)]
    if not chosen:
        raise SystemExit("no endpoints matched. try --list")

    snippet = build_snippet(args)
    print("snippet: %d bytes -> %s" % (
        len(snippet), ", ".join(e["host_name"] for e in chosen)))

    action_id = submit(snippet, [e["agent_id"] for e in chosen], args.timeout)
    print("action_id: %s" % action_id)
    print("status: %s" % wait(action_id))
    show(action_id)
    if not args.no_push:
        push(action_id, history=args.history)


if __name__ == "__main__":
    main()
