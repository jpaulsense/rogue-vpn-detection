#!/usr/bin/env python3
"""Deploy the native scheduled sweep: XSOAR list, automation, playbook.

WHAT RUNS WHERE, AND WHY IT IS SHAPED THIS WAY

  Job (console-created, time-triggered)
    -> Playbook "Device Location Sweep"
         task 1  DeviceLocationSweep   the whole sweep, and closes the container

  The automation does everything rather than the playbook orchestrating four
  tasks. That is deliberate. Every context path between playbook tasks is a
  silent-failure risk on this platform: a wrong path substitutes EMPTY, the task
  reports Completed, and the run looks green with no data in it. One task with
  one scalar output has almost no surface for that. Decompose later if the
  canvas visibility is worth the risk.

  The close is inside the automation for a different reason: a playbook task
  carrying the builtin fails on this tenant whatever shape it is given. The
  job itself has to be created in the console; --job here produces one that
  cannot run. Both are measured, and both are in xsiam/README.md.

CREDENTIALS
  The collector token lives in an XSOAR list, not in the playbook or the
  automation body, so neither carries a secret and both can be exported.

Usage:
    ./deploy_playbook.py --list        store collector creds in an XSOAR list
    ./deploy_playbook.py --automation  create/update the automation
    ./deploy_playbook.py --playbook    create/update the playbook
    ./deploy_playbook.py --all         all three of the above; NOT the job
"""
import argparse
import io
import json
import pathlib
import subprocess
import sys
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xsiam_api as api  # noqa: E402

LIST_NAME = "DeviceLocationCollector"
AUTOMATION = "DeviceLocationSweep"
PLAYBOOK = "Device Location Sweep"
JOB = "Device Location Sweep"
JOB_CRON = "0 1 * * *"
JOB_TZ = "America/Los_Angeles"
AGENT_SCRIPT_NAME = "vpn_location_detect"

# The automation body. Runs inside the XSOAR Docker image, where `requests` and
# the demisto SDK are available. It is NOT the agent script and is not bound by
# the agent module allowlist.
AUTOMATION_CODE = r'''
import json, gzip, time, traceback

LIST_NAME = "DeviceLocationCollector"
CODE_VERSION = "v8-apiprobe"
FIELDS = ["scanned_at","host_name","agent_id","confidence","score","indicators",
          "wifi_method","bssid_count","bssids","timezone_key","utc_offset_hours",
          "first_public_hop","anchor_type","anchor_rtts","anycast_reachable",
          "anycast_rtt_ms","tailscale_derp","tailscale_relay_peers","dns_servers",
          "vpn_adapters","vpn_processes","vpn_software","sanctioned_vpn",
          "split_default_pair","in_california","physical_location","ip_address",
          "ip_location","ip_asn","errors",
          # L2 network identity, added 2026-11-10. This is the axis that gives
          # macOS and every wired machine a physical-network signal, the BSSID
          # set being unavailable there. See collect_gateway_fingerprint.
          "gateway_ips","gateway_macs","gateway_method"]


def _cmd(name, args, context_path=None):
    """executeCommand, returning EntryContext[context_path] or Contents.

    MEASURED 2026-11-08: reading `Contents` alone is wrong for the core-*
    commands. core-get-endpoints puts its list at EntryContext
    "Core.Endpoint(...)" while Contents carries something else, so
    endpoint_ids came out empty, the sweep took its "nothing to do" exit, and
    the job reported COMPLETED in 20 seconds having run nothing. A silent
    success is the worst possible shape for that, which is why the caller now
    raises instead.
    """
    res = demisto.executeCommand(name, args)
    if not res:
        raise RuntimeError("no response from %s" % name)
    for entry in res:
        if isinstance(entry, dict) and entry.get("Type") == 4:
            raise RuntimeError("%s errored: %s" % (name, entry.get("Contents")))
    if context_path:
        for entry in res:
            ctx = (entry or {}).get("EntryContext") or {}
            for key, value in ctx.items():
                # keys carry a dedup suffix, e.g. "Core.Endpoint(val.x == obj.x)"
                if key.split("(")[0] == context_path:
                    return value
    return res[0].get("Contents")


def _collector():
    raw = _cmd("getList", {"listName": LIST_NAME})
    cfg = json.loads(raw) if isinstance(raw, str) else raw
    if not cfg.get("url") or not cfg.get("token"):
        raise RuntimeError("list %s is missing url or token" % LIST_NAME)
    return cfg


def _parse_stdout(text):
    """The agent script brackets its JSON so stdout stays parseable."""
    if not text or "__VPNDETECT_BEGIN__" not in text:
        return None
    chunk = text.split("__VPNDETECT_BEGIN__", 1)[1].split("__VPNDETECT_END__", 1)[0]
    try:
        return json.loads(chunk.strip())
    except Exception:
        return None


NUMERIC = {"score", "max_score", "bssid_count", "utc_offset_hours",
           "default_route_count", "first_public_hop_distance", "anycast_reachable",
           "anycast_rtt_ms", "tailscale_direct_peers", "tailscale_relay_peers",
           "duration_s", "physical_lat", "physical_lng"}
BOOLEAN = {"enriched", "split_default_pair", "in_california"}


def _coerce(name, value):
    """Entry-point results arrive as STRINGS regardless of declared type.

    Measured 2026-11-08: `_score` is '0', `_split_default_pair` is 'False',
    `_anycast_reachable` is '3'. Pushing those straight on would type the raw
    dataset's columns as text and break every numeric comparison in XQL, so
    they are coerced back here.
    """
    if value in ("", None):
        return None
    if name in NUMERIC:
        try:
            number = float(value)
            return int(number) if number.is_integer() else number
        except (TypeError, ValueError):
            return None
    if name in BOOLEAN:
        return str(value).strip().lower() == "true"
    return value


def _extract(row):
    """Get one scan result out of a per-endpoint result row.

    TWO SHAPES, because the Scripts Library offers two Input modes:

      Run by entry point  run_detection() RETURNS a dict and XSIAM promotes each
                          key onto the result row. TWO undocumented quirks:
                          every key is PREFIXED WITH AN UNDERSCORE (`_confidence`,
                          not `confidence`), and every value is a STRING whatever
                          the manifest declared. Both are handled here.
      Just run            no entry point, nothing returned, stdout only. That is
                          also what the snippet path produces, hence the markers.

    Entry-point fields are tried first, then the stdout markers, so this works
    whichever way the script was uploaded.
    """
    direct = {}
    for key, value in row.items():
        if not key.startswith("_"):
            continue
        name = key[1:]
        if name not in FIELDS and name not in ("max_score", "schema_version",
                                               "hostname", "enriched",
                                               "default_route_count",
                                               "first_public_hop_distance",
                                               "bssid_payload_b64", "duration_s",
                                               "physical_lat", "physical_lng",
                                               "vpn_dns_servers", "ip_isp"):
            continue
        coerced = _coerce(name, value)
        if coerced is not None:
            direct[name] = coerced
    # confidence is always set by the script, so its presence proves the entry
    # point ran and returned a dict rather than merely printing.
    if "confidence" in direct:
        return direct
    return _parse_stdout(row.get("standard_output"))


def _beacon(stage, detail=""):
    """Write a marker straight to the collector, before anything can fail.

    Instrumentation, not logging. Job runs on this tenant report `completed`
    whether or not the playbook attached, produce no searchable container, and
    expose no task errors through any API route tried. A row in the dataset is
    the only signal that reaches outside the container, so the automation
    announces itself at each stage. If no beacon appears, the automation never
    ran and the fault is upstream in the job or playbook.
    """
    try:
        cfg = _collector()
        body = json.dumps({"host_name": "__BEACON__", "wifi_method": stage,
                           "errors": str(detail)[:400],
                           "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                       time.gmtime())}).encode("utf-8")
        requests.post(cfg["url"],
                      headers={"Authorization": cfg["token"],
                               "Content-Type": "application/json",
                               "Content-Encoding": "gzip"},
                      data=gzip.compress(body), timeout=30)
    except Exception:
        pass


def main():
    _beacon("start", CODE_VERSION)
    args = demisto.args()
    script_name = args.get("script_name") or "vpn_location_detect"
    wait_seconds = int(args.get("wait_seconds") or 120)
    poll_every = 15

    # 1. the script uid, by name, so no uid is hardcoded anywhere
    scripts = _cmd("core-get-scripts", {}, "Core.Scripts")
    uid = None
    for s in (scripts if isinstance(scripts, list) else [scripts]):
        if isinstance(s, dict) and s.get("name") == script_name:
            uid = s.get("script_uid")
            break
    if not uid:
        raise RuntimeError("agent script %r is not in the Scripts Library. "
                           "Upload it in the console first." % script_name)

    # 2. connected endpoints
    eps = _cmd("core-get-endpoints", {"status": "connected"}, "Core.Endpoint")
    eps = eps if isinstance(eps, list) else [eps]
    endpoint_ids = [e.get("endpoint_id") for e in eps if e.get("endpoint_id")]
    if not endpoint_ids:
        # Never return cleanly here. A fleet with zero connected endpoints is
        # not a normal outcome, and reporting success for it hid a real bug.
        raise RuntimeError("core-get-endpoints returned no endpoint_id values "
                           "(got %r)" % (eps if not isinstance(eps, list) else eps[:2]))

    # 3. run it
    # `parameters` must be a JSON STRING; the integration json.loads it and
    # sends it as parameters_values. Omitting it sends {}, which the API
    # rejects for a script that declares inputs, with the misleading
    # "parameters_values must be of type: dict". This shape is the one proven
    # working on action 109 via the raw API.
    params = json.dumps({
        "google_api_key": args.get("google_api_key", ""),
        "enrich": False,
        "scan_wifi": True,
        "latency_anchors": args.get("latency_anchors", ""),
        "sanctioned_patterns": args.get("sanctioned_patterns", ""),
    })
    _beacon("run_script", "endpoints=%d uid=%s" % (len(endpoint_ids), uid))
    run = _cmd("core-run-script", {"script_uid": uid,
                                   "endpoint_ids": ",".join(endpoint_ids),
                                   "parameters": params,
                                   "timeout": 600}, "Core.ScriptRun")
    run = run[0] if isinstance(run, list) and run else run
    action_id = str(run.get("action_id"))

    # 4. wait. core-run-script is async and returns only an action id; a task
    #    that branches on the result without waiting gets the id instead.
    #    PENDING is not waited out: a closed laptop stays PENDING for days.
    waited = 0
    while waited < wait_seconds:
        time.sleep(poll_every); waited += poll_every
        st = _cmd("core-get-script-execution-status", {"action_id": action_id},
                  "Core.ScriptStatus")
        st = st[0] if isinstance(st, list) and st else st
        general = (st or {}).get("general_status")
        if general in ("COMPLETED_SUCCESSFULLY", "FAILED", "EXPIRED", "CANCELED", "TIMEOUT"):
            break
        if not (st or {}).get("endpoints_in_progress") and (st or {}).get("endpoints_pending"):
            break

    # 5. results -> rows, ONE PER ENDPOINT
    #
    # MEASURED 2026-11-08: the raw API returns exactly one entry per endpoint
    # for a given action -- action 110, nine endpoints, nine entries, read
    # straight from scripts/get_script_execution_results. The first run through
    # this path still wrote 41 identical rows per endpoint, 41 being the field
    # count, so something between the integration command and this list
    # multiplies entries. Keying on endpoint_id makes the shape irrelevant, and
    # the beacon below reports what was actually received rather than leaving
    # it to be inferred from the row count afterwards.
    res = _cmd("core-get-script-execution-results", {"action_id": action_id},
               "Core.ScriptResult")
    res = res[0] if isinstance(res, list) and res else res
    results = (res or {}).get("results") or []
    by_endpoint = {}
    for r in results:
        parsed = _extract(r)
        if not parsed:
            continue
        row = {}
        for f in FIELDS:
            v = parsed.get(f)
            if f == "host_name":
                v = r.get("endpoint_name")
            elif f == "agent_id":
                v = r.get("endpoint_id")
            if v is None or v == "":
                continue
            row[f] = v if isinstance(v, (str, int, float, bool)) else json.dumps(v)
        key = r.get("endpoint_id") or r.get("endpoint_name") or len(by_endpoint)
        by_endpoint.setdefault(key, row)
    rows = list(by_endpoint.values())
    _beacon("collect", "results=%d rows=%d restype=%s"
            % (len(results), len(rows), type(res).__name__))

    if not rows:
        return CommandResults(
            readable_output="Action %s produced no parseable results yet. "
                            "Endpoints may still be PENDING." % action_id,
            outputs_prefix="DeviceLocation.Sweep",
            outputs={"action_id": action_id, "rows": 0})

    # 6. push to the raw dataset. The collector requires gzip; a plain body
    #    returns 400 "gzip compression error (invalid header)".
    cfg = _collector()
    body = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    resp = requests.post(cfg["url"],
                         headers={"Authorization": cfg["token"],
                                  "Content-Type": "application/json",
                                  "Content-Encoding": "gzip"},
                         data=gzip.compress(body), timeout=60)
    if resp.status_code != 200:
        raise RuntimeError("collector returned %s: %s"
                           % (resp.status_code, resp.text[:300]))

    # 6b. PROBE, remove once answered. Can this container reach the XDR public
    #     API without carrying a key? The baseline recompute has to write a
    #     lookup, `xql/lookups/add_data` lives on /public_api/v1, and the Core
    #     integration's own errors quote paths under /api/webapp/public_api/v1,
    #     so the surface should hang off core-api-post. If it does, the whole
    #     baseline job moves onto the tenant and stops depending on a script
    #     being run from a laptop. An empty request_data is deliberate: a 400
    #     naming a missing parameter proves the route is reachable, which is
    #     the only thing being asked here.
    try:
        probe = demisto.executeCommand("core-api-post", {
            "uri": "/public_api/v1/xql/lookups/add_data",
            "body": json.dumps({"request_data": {}})})
        _beacon("apiprobe", json.dumps(probe)[:350])
    except Exception as exc:               # noqa: BLE001 - probe must not fail the run
        _beacon("apiprobe", "raised: %s" % str(exc)[:300])

    # 7. close the job's container from HERE, not from a playbook task.
    #
    # MEASURED 2026-11-08 over three runs: a task carrying
    # scriptId "Builtin|||closeInvestigation" fails in 200-300ms with an EMPTY
    # errors array, copied field-for-field from the shipping Phishing - Core
    # task, with and without `iscommand`. Neither spelling of that flag even
    # survives playbook/save -- it reads back None -- so the task form is not
    # reachable from the API on this tenant. The same builtin called from
    # inside the automation works. It matters because a job container that
    # never closes leaves one open investigation per run, and on a job with
    # shouldTriggerNew=False it stops the schedule dead after the first run.
    try:
        demisto.executeCommand("closeInvestigation", {
            "closeReason": "Resolved",
            "closeNotes": "Device location sweep completed."})
        _beacon("closed", "rows=%d" % len(rows))
    except Exception as exc:               # noqa: BLE001 - never fail the sweep
        _beacon("close_failed", str(exc)[:200])

    moved = [r["host_name"] for r in rows if r.get("anycast_reachable") == 0]
    return CommandResults(
        readable_output=("Device location sweep: %d endpoints scanned, %d rows "
                         "written to agentscript_devicelocation_raw (action %s).%s"
                         % (len(results), len(rows), action_id,
                            ("\\nOn a restricted network: " + ", ".join(moved)) if moved else "")),
        outputs_prefix="DeviceLocation.Sweep",
        outputs={"action_id": action_id, "endpoints": len(results),
                 "rows": len(rows), "restricted": moved})


try:
    return_results(main())
except Exception as exc:
    demisto.error(traceback.format_exc())
    _beacon("FAILED", "%s | %s" % (exc, traceback.format_exc()[-300:]))
    return_error("DeviceLocationSweep failed: %s" % exc)
'''

AUTOMATION_YML = """args:
- description: Name of the agent script in the Scripts Library.
  name: script_name
  required: false
  defaultValue: {script_name}
- description: Seconds to wait for endpoints to report before collecting results.
  name: wait_seconds
  required: false
  defaultValue: "120"
- description: Google Geolocation API key. Leave empty; enrichment is server-side.
  name: google_api_key
  required: false
- description: Unicast latency anchors as host:port,host:port. Optional, never scores.
  name: latency_anchors
  required: false
- description: Comma-separated sanctioned VPN name patterns.
  name: sanctioned_patterns
  required: false
comment: |
  Runs the device-location agent script across all connected endpoints, collects
  the results, and writes them to the agentscript_devicelocation_raw dataset
  through the HTTP collector. Collector credentials come from the XSOAR list
  {list_name}, so this script carries no secret.
commonfields:
  id: {name}
  version: -1
dockerimage: demisto/python3:3.12.13.10116658
enabled: true
engineinfo: {{}}
name: {name}
outputs:
- contextPath: DeviceLocation.Sweep.action_id
  description: Script execution action ID.
  type: String
- contextPath: DeviceLocation.Sweep.endpoints
  description: Endpoints the action reported on.
  type: Number
- contextPath: DeviceLocation.Sweep.rows
  description: Rows written to the dataset.
  type: Number
- contextPath: DeviceLocation.Sweep.restricted
  description: Hosts that could not reach any public resolver.
  type: Unknown
runas: DBotWeakRole
runonce: false
script: |-
{indented_code}
scripttarget: 0
subtype: python3
system: false
tags:
- device-location
timeout: 0s
type: python
"""


def make_list():
    creds = api.load_creds()
    url = creds.get("%s_DEVLOC_COLLECTOR_URL" % api.PREFIX)
    token = creds.get("%s_DEVLOC_COLLECTOR_TOKEN" % api.PREFIX)
    if not (url and token):
        raise SystemExit("DEVLOC collector credentials not in .credentials.env")
    status, body = api.call("lists/save", {
        "name": LIST_NAME,
        "data": json.dumps({"url": url, "token": token}),
        "type": "json",
    }, surface="xsoar/public/v1")
    print("  list %s -> %s" % (LIST_NAME, status))


def make_automation():
    indented = "\n".join("  " + line for line in AUTOMATION_CODE.strip("\n").splitlines())
    yml = AUTOMATION_YML.format(name=AUTOMATION, list_name=LIST_NAME,
                                script_name=AGENT_SCRIPT_NAME,
                                indented_code=indented)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("metadata.json", json.dumps({
            "id": "", "version": 0, "packID": "", "packName": "",
            "itemVersion": "", "fromServerVersion": "", "toServerVersion": "",
        }))
        z.writestr("automation/automation-%s.yml" % AUTOMATION, yml)
    path = pathlib.Path("/tmp/%s.zip" % AUTOMATION)
    path.write_bytes(buf.getvalue())

    creds = api.load_creds()
    fqdn, hdrs = api.headers(creds, advanced=True)
    hdrs.pop("Content-Type", None)      # curl sets the multipart boundary
    cmd = ["curl", "-s", "-w", "\n__STATUS__%{http_code}", "--max-time", "90",
           "-X", "POST", "https://%s/public_api/v1/scripts/insert" % fqdn,
           "-F", "file=@%s" % path]
    for k, v in hdrs.items():
        cmd += ["-H", "%s: %s" % (k, v)]
    out = subprocess.run(cmd, stdout=subprocess.PIPE).stdout.decode()
    payload, _, status = out.rpartition("__STATUS__")
    print("  automation %s -> %s %s" % (AUTOMATION, status.strip(), payload.strip()[:300]))


def make_playbook():
    """Playbook JSON on the XSOAR surface.

    Traps, all measured and all of which return success:
      * the body is a LIST of playbooks
      * a task's `view` must be a JSON STRING on write, though search returns it
        deserialized
      * tasks reference their script by `scriptId`, not `script`. A `script` key
        saves 200, renders correctly, and every task does nothing.
      * closeInvestigation is a BUILTIN, not an automation. It is absent from
        all 537 automations on this tenant and present in shipping playbooks as
        scriptId "Builtin|||closeInvestigation" with brand "Builtin" -- and
        MEASURED 2026-11-08, reproducing that exact shape from the API still
        errors every run. The automation closes the container instead.
    """
    import uuid

    def view(x, y):
        return json.dumps({"position": {"x": x, "y": y}})

    # taskId must be a UUID. The working playbook on this tenant uses GUIDs;
    # the first version here used "task-0"/"task-1" and the job errored before
    # ever creating an investigation. Derived from the playbook name so a
    # re-run produces the same ids rather than orphaning the old tasks.
    def tid(n):
        return str(uuid.uuid5(uuid.NAMESPACE_URL, "%s/task/%d" % (PLAYBOOK, n)))

    t0, t1 = tid(0), tid(1)

    # ONE REAL TASK. Closing the container is done by the automation itself,
    # not by a second task -- see the long note at step 7 of AUTOMATION_CODE.
    # A task carrying scriptId "Builtin|||closeInvestigation" errors in under a
    # third of a second with an empty errors array on this tenant, three runs
    # in a row, copied field-for-field from a shipping playbook.
    tasks = {
        "0": {"id": "0", "taskid": t0, "type": "start",
              "task": {"id": t0, "version": -1, "type": "start"},
              "nexttasks": {"#none#": ["1"]},
              "separatecontext": False, "view": view(450, 50),
              "scriptarguments": {}, "reputationcalc": 0},
        "1": {"id": "1", "taskid": t1, "type": "regular",
              "task": {"id": t1, "version": -1,
                       "name": "Sweep device locations",
                       "description": ("Run the agent script fleet-wide, collect "
                                       "results, write them to the dataset, then "
                                       "close the job container."),
                       "scriptId": AUTOMATION, "type": "regular"},
              "scriptarguments": {
                  "script_name": {"simple": AGENT_SCRIPT_NAME},
                  "wait_seconds": {"simple": "120"}},
              "separatecontext": False, "view": view(450, 200),
              "reputationcalc": 0},
    }
    payload = {
        "id": PLAYBOOK, "name": PLAYBOOK, "version": -1,
        "description": ("Scheduled device-location sweep. Built by "
                        "deploy_playbook.py; do not edit in the console."),
        "starttaskid": "0",
        "tasks": tasks,
        "view": json.dumps({"linkLabelsPosition": {}, "paper": {"dimensions": {
            "height": 500, "width": 380, "x": 450, "y": 50}}}),
        "inputs": [], "outputs": [],
        "fromversion": "8.0.0",
        "fromServerVersion": "8.0.0",
    }
    status, body = api.call("playbook/save", [payload], surface="xsoar")
    print("  playbook %s -> %s %s" % (PLAYBOOK, status, str(body)[:300]))


def make_job():
    """Create the time-triggered job. DOES NOT PRODUCE A WORKING JOB — see below.

    MEASURED 2026-11-08, and the reason --all no longer calls this. A job
    created through this route is inert: `jobs/run` answers 200, droppedCount
    goes up, no container is created, the playbook never attaches, and
    runStatus lands on `error` with nothing anywhere saying why. The
    console-created job `Device location Sweep 2`, pointed at the same
    playbook, runs correctly. Aligning every non-derived field that differed
    between the two — `type`, `rawType`, `category`, `rawCategory` — changed
    nothing, so the category note that used to be here is withdrawn and so is
    its replacement.

    Create the job in the console. Kept here because the schedule fields below
    were expensive to work out and are right.

    THREE THINGS THE CONSOLE FORM AND THE DOCS DO NOT TELL YOU, all measured
    2026-11-08 after the console rejected a plain cron with
    "Invalid schedule configuration":

    1. `startDate` is REQUIRED. The cron alone is not a valid schedule. A
       working job on this tenant carries one, which is where the shape here
       came from.
    2. `startDate` is a WALL-CLOCK time in the job's own timezone, written with
       a Z suffix. Supplying a real offset like 2026-11-09T01:00:00-08:00 gets
       converted to 09:00Z and then has the Pacific offset applied AGAIN,
       landing the job at 09:00 local instead of 01:00. Its clock reading must
       match the cron's hour.
    3. `nextRunTime` is computed at CREATE and never recalculated on update.
       POSTing a corrected cron returns 200, stores the new cron, and leaves the
       job firing on the old schedule. The only reliable fix is delete and
       recreate, which is why this does that.
    """
    status, body = api.call("jobs/search", {"page": 0, "size": 50},
                            surface="xsoar/public/v1")
    for existing in (body or {}).get("data") or []:
        if existing.get("name") == JOB:
            api.call("jobs/%s" % existing["id"], None,
                     surface="xsoar/public/v1", method="DELETE")
            print("  removed existing job %s" % existing["id"])

    # A dedicated incident type. The job that works on this tenant carries a
    # real type; `Unclassified` does not survive a run. Creating one is a
    # single call and removes the variable.
    api.call("incidenttype", {"name": JOB, "id": JOB}, surface="xsoar/public/v1")

    hour = JOB_CRON.split()[1]
    status, body = api.call("jobs", {
        "name": JOB, "playbookId": PLAYBOOK, "type": "Unclassified",
        "cron": JOB_CRON,
        "startDate": "2026-11-09T%02d:00:00Z" % int(hour),
        "cronView": True, "scheduled": True, "recurrent": True,
        "endingType": "never", "endingDate": "0001-01-01T00:00:00Z", "times": 0,
        "timezone": JOB_TZ, "timezoneOffset": 480,
        # true, not false, while this is being proven: if closeInvestigation
        # ever fails the container lingers, and "don't trigger a new run" would
        # mean the sweep silently stops after one night.
        "shouldTriggerNew": True,
        "isFeed": False, "disabled": False,
        # [] not None. The working job carries empty lists here and the first
        # attempt, which left them null, errored with no investigation created.
        "selectedFeeds": [], "tags": [],
        "closePrevRun": True,
        "details": "Nightly device-location sweep.",
        "humanCron": {"timePeriodType": "days", "timePeriod": 1},
    }, surface="xsoar/public/v1")
    print("  job %s -> %s %s" % (JOB, status, (body or {}).get("id")))

    # A FAILED RUN LEAVES ITS CONTAINER OPEN, and the next run is then dropped
    # with 400 "already running (10100)" rather than queued. On a job carrying
    # shouldTriggerNew=false that means one bad night ends the schedule for
    # good, silently. Measured 2026-11-08; it is set true above for that
    # reason and should stay true even once the sweep is trusted.
    status, body = api.call("jobs/search", {"page": 0, "size": 50},
                            surface="xsoar/public/v1")
    for j in (body or {}).get("data") or []:
        if j.get("name") == JOB:
            print("  cron=%s tz=%s nextRunTime=%s"
                  % (j.get("cron"), j.get("timezone"), j.get("nextRunTime")))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--list", action="store_true")
    p.add_argument("--automation", action="store_true")
    p.add_argument("--playbook", action="store_true")
    p.add_argument("--job", action="store_true",
                   help="create the job. INERT on this tenant; see make_job.")
    p.add_argument("--all", action="store_true",
                   help="list, automation and playbook. Not the job.")
    a = p.parse_args()
    if not any(vars(a).values()):
        p.print_help(); return
    if a.list or a.all:
        print("list:"); make_list()
    if a.automation or a.all:
        print("automation:"); make_automation()
    if a.playbook or a.all:
        print("playbook:"); make_playbook()
    # --all deliberately excludes the job: it creates one that cannot run.
    if a.job:
        print("job:"); make_job()


if __name__ == "__main__":
    main()
