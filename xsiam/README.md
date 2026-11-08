# Running this detection from Cortex XSIAM

Lab / PoC on the **jpse-ca-gov** tenant. Takes the detection in
`../vpn-location-detection-full.ps1` and runs it across endpoints carrying the Cortex XDR agent,
instead of one box at a time.

Everything in the "Measured" sections below was executed against that tenant and the response
recorded. Everything else is documentation, with its page named.

## Files

| File | What it is |
|---|---|
| `vpn_location_detect.py` | The detection. Entry point `run_detection`. Windows and macOS. |
| `vpn_location_detect.manifest.json` | Script manifest. Single line, as the upload parser requires. |
| `check_allowlist.py` | Checks imports against the tenant module allowlist. Run before any upload. |
| `xsiam_api.py` | Tenant client. Handles both auth schemes, curl transport. |
| `run_detection.py` | Runs the detection on endpoints as a snippet and prints parsed results. |

## Why this is a port and not a wrapper

Agent scripts are **Python**, executed by a runtime built into the agent, not PowerShell. From
[Run agent scripts on an endpoint](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/detect-investigate-and-respond-to-threats/investigation-and-response/response-actions/run-agent-scripts-on-an-endpoint.md):

> For enhanced endpoint remediation and endpoint management, you can run Python 3.7 scripts on
> your endpoints directly from Cortex XSIAM.

> During upload, Cortex XSIAM parses the script to ensure you are using only supported Python
> modules.

Agent v7.1 or later. Scripts run as **SYSTEM** on Windows and **root** on macOS and Linux.

**Measured 2026-11-05: the macOS agent runtime is Python 3.9.5, not 3.7.** A snippet printing
`platform.system()` and `sys.version` on Jared's Mac Studio returned `Darwin 25.6.0 3.9.5`. Treat
3.7 as the floor the allowlist is validated against, not the interpreter you get. This code stays
3.7-compatible because Windows agents have not been checked.

### The PowerShell route exists and is deliberately not used

Palo Alto's own Cortex Core integration ships `core-run-script-execute-commands`, which calls
`run_script` against a hardcoded script UID and wraps each command as `powershell -Command "..."`
(`work/cortex-expert/build/content/Packs/ApiModules/Scripts/CoreIRApiModule/CoreIRApiModule.py:2707`).

**Measured 2026-11-05: that script is real and present on the tenant.** `scripts/get_scripts`
returns `execute_commands`, uid `a6f7683c8e217d85bd3c398f0d3fb6bf`, high-risk, supported on
Windows, macOS and Linux. The uid matches the one hardcoded in the integration source exactly.

It is **not in the documented out-of-the-box script list** and returns zero hits across the whole
Cortex documentation portal. It works, and for a script this size it means shipping a base64
`-EncodedCommand` blob of unmeasured maximum length through an undocumented parameter. The Python
port is inspectable and cross-platform, so that is the lane taken here.

## The module allowlist is tenant state, not documentation

Visible only at **Action Center → Agent Script Library → New Script → supported modules**. No
Cortex doc page publishes it. Transcribed into `check_allowlist.py` as read on 2026-11-05; re-read
it after a content update.

It allows `subprocess`, `requests`, `wmi`, `winreg`, `psutil`, `netifaces`, `icmplib`, `ctypes`,
`winapps` and the whole `win32*` family. What it does **not** include is the trap: `typing`,
`math`, `urllib`, `ipaddress`, `itertools`, `string`, `copy`, `tempfile`.

The repository's own `../wifi-geolocation.py` imports `typing` and `urllib`, so it fails upload:

```
$ ./check_allowlist.py ../wifi-geolocation.py
wifi-geolocation.py: 8 imports, 2 outside the allowlist
  NO  typing           line 34
  NO  urllib           line 32
FAIL: at least one import is outside the allowlist.
```

## `scripts/insert` is real, and it is the WRONG scripts

This one is worth reading carefully, because the route exists, it works, and it uploads the other
kind of script. Cortex has two things called a script and one API name between them:

| | Agent script | Automation |
|---|---|---|
| Lives in | Action Center → Agent Script Library | Automation → Scripts |
| Runs on | the endpoint, via the XDR agent | the server, in a Docker container |
| Language | Python, allowlisted modules | Python or PowerShell, any module in the image |
| Write API | **none** | `POST /public_api/v1/scripts/insert`, multipart zip |

**Measured 2026-11-05, and this is the proof.** `POST /public_api/v1/scripts/get` with a singular
`filter`:

```
execute_commands   400  {"error":"Error on automation script find", "id":"execute_commands"}
file_exists        400  {"error":"Error on automation script find", "id":"file_exists"}
PrintToIncident    200  application/zip  ['metadata.json', 'automation/automation-PrintToIncident.yml']
Sleep              200  application/zip  ['metadata.json', 'automation/automation-Sleep.yml']
```

The two agent scripts are refused by name and the two automations come back as zipped YAML under
an `automation/` path. Palo Alto's own client agrees: the function behind that route in
`Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.py:768` is named
`create_automation_script`.

`scripts/insert` answers **415 Unsupported Media Type** to a JSON body rather than the 500 that a
nonexistent route returns, which is how you can tell it is there at all. Fifteen other guessed
names (`scripts/upload`, `scripts/create`, `scripts/save`, `agent_scripts/insert`, …) all returned
the 500 control.

**So putting `vpn_location_detect.py` in the Agent Script Library is a console job.** Drag the
file in, then upload `vpn_location_detect.manifest.json` as the definitions file. Automations,
including anything the playbook needs, *can* be deployed from code.

### Manifest limits the documentation does not mention

| Limit | Detail |
|---|---|
| `description` | **200 characters.** The first version was 453 and was rejected. Nothing else in the manifest is near a cap; the only other string over 60 chars was that one. |
| Single line | No `\n`, no `\t`, anywhere in the file. Generate it, do not hand-type it. |
| `enrich`, `scan_wifi` | Declared `boolean`. If the console rejects boolean input params, use `vpn_location_detect.manifest.stringflags.json`, which is identical with those two as `string`. `_parse_bool` already accepts `"true"`/`"false"`, so no code changes. |

**Set Input to "Run by entry point", not "Just run".** They return results in completely different
places: an entry point RETURNS a dict and XSIAM promotes each key to a named, filterable field per
`output_params`, while Just run returns nothing and leaves only stdout. Just run also cannot accept
parameters, and the console greys the Output section out entirely. If the upload wizard shows Just
run selected and Linux checked, the manifest did not apply: click **reset** next to "To change the
current definitions by uploading a new manifest, you must first reset definitions to default",
then upload it again.

`DeviceLocationSweep` reads the named fields first and falls back to the stdout markers, so it
works either way, but entry point is the configuration to aim for.

### Dictionary output: three undocumented behaviours, one of them fatal

**1. `ip` and `number` types break reading the results back.** Measured 2026-11-07 by elimination:

| Script | Output | `get_script_execution_results` |
|---|---|---|
| `file_exists` | `boolean` | 200 |
| `test_acs` | `dictionary`, string + boolean | 200 |
| snippet action | stdout only | 200 |
| `vpn_location_detect` | `dictionary` with `ip` + `number` | **bare HTTP 500** |

The action reports `COMPLETED_SUCCESSFULLY` either way; only the read fails, with no detail on v1
or v2, and `get_script_execution_results_files` answers a clean 404 for the same action proving
the IDs are fine. Declaring every field `string` fixed it. The display types are cosmetic anyway,
because the dataset schema does the real typing. `build_manifest.py` now forces this.

A null in a typed column was the other half of the same hypothesis and was fixed at the same time;
`run_detection` returns `""` rather than `None`. That is also more honest, since `in_california` is
genuinely *unknown* on a non-enriched run and `False` would misreport it.

**2. Result keys come back prefixed with an underscore.** `confidence` is returned by the script
and arrives as `_confidence` on the result row. All 41, every time.

**3. Every value arrives as a string**, whatever the manifest declared. `_score` is `'0'`,
`_split_default_pair` is `'False'`, `_anycast_reachable` is `'3'`. Pushing those on untouched would
type the raw dataset's columns as text and break every numeric comparison in XQL, so
`DeviceLocationSweep._coerce` converts them back using explicit numeric and boolean field sets.

Verified against a real row from action 109: 25 non-empty fields extracted with `score` as `int`,
`anycast_rtt_ms` as `float`, `split_default_pair` as `bool`.

**Guard:** `./build_manifest.py --check` regenerates the manifest from the script's actual return
and exits 1 on drift. Run it before any upload. It exists because a hand-maintained manifest
declared 40 fields while the script returned 41, and the only symptom was an unexplained 500.

`run_snippet_code_script` needs no upload, which makes it the right tool for iterating, and it is
what `run_detection.py` uses. Tradeoffs: no manifest, so no named output fields and no filterable
results table; no entry point, so the snippet calls itself; and it needs both **Run High-risk
scripts** and **Script configuration** permissions.

```bash
./run_detection.py --list
./run_detection.py --host "MacBook Air"
./run_detection.py --host windows-test --anchors "198.51.100.10:443"
./run_detection.py --all-workstations
./run_detection.py --results 98
```

### Measured: the snippet path works end to end

A 41,292-byte snippet carrying the whole module plus an invocation ran on the Mac Studio as root,
action 98, `COMPLETED_SUCCESSFULLY`, 9.3s, and returned results byte-identical to running the same
file locally. No size limit was hit at that length.

## Auth: two schemes, and the wrong one 401s on every route

| Key | Header |
|---|---|
| Standard | `Authorization: <api_key>` |
| Advanced | `Authorization: sha256(api_key + nonce + timestamp)`, plus `x-xdr-nonce` and `x-xdr-timestamp` |

An Advanced key sent the Standard way answers **401 on every route including a nonsense control**,
which reads as a revoked key rather than a wrong signature. `xsiam_api.py probe` sends the control
deliberately. On this tenant a nonsense route returns **500**, so 500 means "no such route" and
401 means "your credential is wrong".

## What runs on the endpoint, and what does not

| `enrich` | Behaviour | Use for |
|---|---|---|
| `false` (default) | Raw observables and the local-only score. No key leaves the console, no third-party calls from endpoints, and BSSID sets dedupe across endpoints before anyone pays Google. | Fleet runs |
| `true` | The script resolves the WiFi fix and IP geo itself. | Single-endpoint testing |

A script in the Scripts Library can be **downloaded** by anyone holding the Scripts permission, so
an embedded Google key is a published key. Passing it as a run parameter is better but still lands
in the Action Center run record. The integration-held key is the only version that does neither.

## Latency anchors: anycast is not a location signal

`8.8.8.8`, `1.1.1.1` and `9.9.9.9` are anycast. They answer from the nearest edge PoP wherever the
device is, so a laptop in Austin reads the same RTT as one in Sacramento. The script measures them
as a liveness check and reports them separately as `anycast_rtt_ms`, never as position.

A distance signal needs a **unicast host at a known fixed location**, which means one you own. Pass
it with `latency_anchors` as `host:port,host:port`. Results come back per anchor in `anchor_rtts`
and are deliberately not averaged.

**The threshold is the harder half.** A global cutoff flags the wrong people in both directions,
because hotel wifi in Sacramento is slower than fibre in Austin. The question that works is whether
*this device* is off *its own* baseline, which is an XQL job over accumulated rows. Collect for a
week before trusting any gate.

## Sanctioned VPNs

Tailscale rides wintun, so it matched the generic adapter pattern and would have scored every
machine carrying it as a permanent HIGH. `sanctioned_patterns` defaults to
`tailscale, globalprotect, prisma access`; matches are reported in `sanctioned_vpn` and do not
score. Verified on the Mac Studio: `sanctioned_vpn: tailscale|Tailscale.app`, score 0.

## macOS: the BSSID is a fingerprint, not a fix

Apple gates BSSID behind Location Services authorization for the calling application, and running
as root does not bypass it. The legacy `airport -s` scanner was removed in macOS 14.4. The script
tries `wdutil info`, then `system_profiler SPAirPortDataType`, then `airport`, and reports which
one answered in `wifi_method`.

**Measured on the Mac Studio: `system_profiler` returned 2 BSSIDs**, which is better than expected
and is the minimum Google wants for a WiFi fix. Do not assume that holds on a laptop associated to
a single AP.

Where only the associated BSSID comes back, the value is not a coordinate, it is a stable
identifier for where the machine is sitting. Comparing today's BSSID against the ones a device has
reported before answers "has it moved" with no API call at all.

## Measured: Host Inventory does not help on this tenant

`host_inventory` **is** a queryable XQL dataset here, carrying `applications`, `drivers`,
`services`, `auto_runs`, `daemons` and `extensions` per endpoint, with `applications` as a list of
JSON strings keyed on `application_name`. That answers the open question about XQL reachability:
yes.

But only **four hosts report into it**: `windows-test`, `windows-prod`, `windows-client` and
`windows-dirty`, all GCP lab VMs. None of the Macs, and not Stormbreaker. So the "four of eleven
layers are already collected, drop them from the script" shortcut does **not** apply on this
tenant, and the script is doing real work rather than duplicating telemetry.

Tenant licence shows `host_insights_expiration: 0`. The dataset answers anyway.

## Scope limits to design around

- `run_script` accepts one filter field, `endpoint_id_list` with operator `in`. No "all endpoints"
  filter on the API, so page `endpoints/get_endpoints` first.
- Maximum **1000 endpoints** per action.
- Script execution actions **expire after four days**. Laptops that stay off never run.
- Default timeout 600s. This script completes in about 10s.

## The native scheduled sweep

```
Job (time-triggered, console)
  -> Playbook "Device Location Sweep"
       task 1  DeviceLocationSweep    automation, does the whole sweep
       task 2  closeInvestigation     builtin
```

Deployed by `deploy_playbook.py --all`. Three objects, all API-created:

| Object | What it is |
|---|---|
| `DeviceLocationCollector` | XSOAR list holding the collector url and token, so neither the playbook nor the automation carries a secret |
| `DeviceLocationSweep` | automation: finds the agent script by name, runs it on every connected endpoint, waits, collects results, gzip-POSTs them to the raw dataset |
| `Device Location Sweep` | playbook: the automation, then `closeInvestigation` |

**The automation does the whole sweep rather than the playbook orchestrating four
tasks, deliberately.** Every context path between playbook tasks is a silent-failure surface
here: a wrong path substitutes empty, the task reports Completed, and the run is green with no
data in it. One task with one scalar output has almost none of that.

### `closeInvestigation` resolved

It is a **builtin, not an automation**, which is why an earlier probe read it as absent. Measured:
it does not appear in any of the 537 automations on this tenant, and it is present in three
shipping playbooks as:

```json
{"scriptId": "Builtin|||closeInvestigation", "brand": "Builtin", "type": "regular"}
```

That shape was copied from `Phishing - Core` rather than invented. It matters because a scheduled
job opens an investigation container, and without this task the job stays **Running** forever.
With the default queue handling that means the sweep runs **once** and then silently never again.

### STATUS 2026-11-08: the job chain is NOT working. Read this first.

Everything up to and including the dataset and dashboard works. The job → playbook → automation
chain does not. Current fault: **the `DeviceLocationSweep` task does not execute at all** (no
beacons). It did execute earlier in the day; deleting and recreating the automation via
`scripts/insert` broke the playbook's binding to it, and re-saving the playbook twice and saving
the automation in the console did not restore it.

To restore: in the console, open the playbook, delete the `Sweep device locations` task, re-add it
pointing at `DeviceLocationSweep`, save. Or delete the automation in the console and redeploy.

**The last real error, which is already fixed in code but has never run:**

```
core-run-script errored: ... {"err_extra": "parameters_values must be of type: dict"}
```

`core-run-script` requires `parameters` as a **JSON string**. Omit it and the integration sends
`parameters_values: {}`, which the API rejects for a script that declares inputs. The error names
the wrong thing: the problem is an absent argument, not a wrong type.

### Run a job from code

**`POST /xsoar/public/v1/jobs/{operation}/{job_id}`**, e.g. `jobs/run/<id>`. Documented on
`xsoar-8-api/cortex-xsoar-8.x-apis/jobs.md`. Note the order: operation then id. `jobs/{id}/run`
returns 405 because it matches the `jobs/{id}` pattern, which reads as "no such route".

### `scripts/insert` updates storage, not execution

Measured 2026-11-08: after inserting new automation code, `scripts/get` returns the new text while
the engine keeps running the old. Proved by version-stamping a beacon; the stamp never appeared.
Deleting and recreating breaks the playbook binding instead. **Assume an automation update needs a
console save to take effect**, and verify with a version marker rather than by reading the code
back.

### `category` is NOT the difference between console and API jobs

An earlier note here claimed it was. **Withdrawn.** A console-created job on this tenant also
carries `category='job'`. The real difference between the API-created job that never attached its
playbook and the console-created one that does is still unidentified.

### Reading a job run

There is no good path. `runStatus` reports `completed` even when the playbook never attached.
`investigationId` is empty on working and broken jobs alike. No case or issue is created that
`incidents/search` can find, for any job including the working one. `playbook_runs` and
`playbook_tasks` are empty. **`GET investigation/{id}/workplan` CREATES an empty investigation if
one does not exist**, so querying it manufactures the evidence you then read — two rounds were lost
to that.

What does work is instrumenting the automation to write a beacon row to the dataset at each stage.
That is the only signal that escapes the container. `_beacon()` in the automation does this.

### Playbook write traps

- the body is a **list** of playbooks
- tasks reference their script by `scriptId`, not `script`. A `script` key saves 200, renders
  correctly in the canvas, and every task does nothing
- a task's `view` must be a JSON **string** on write, though search returns it deserialised
- **reads come back camelCase** (`startTaskId`, `nextTasks`, `taskId`) while writes take
  lowercase. Verifying with the lowercase names makes a correctly-wired playbook look orphaned

Always read back and check `startTaskId` and `nextTasks` are populated, using the camelCase names.

## Scheduling, and the trap in it

No scheduler in Action Center. Use **Automations → Jobs → time-triggered job** running a playbook.

**The job documentation requires the playbook to end with `closeInvestigation`**, or the container
stays open and the job sticks in Running. But a measured note from this tenant on 2026-09-25 says a
task calling `|||closeInvestigation` errors and stops the parent playbook. It is a builtin in
`CommonServer.js`, not a standalone automation, so that probe may have been in the wrong namespace.

Test it before trusting a schedule. With queue handling set to "Don't trigger a new job run", a
stuck container means the sweep runs **once** and then silently never again.

## Getting results into XQL: five write paths, and the one that wins

The Action Center is for an operator, not a correlation source. A correlation rule may source
`xdr_data`, `correlations_auditing` and any custom dataset, but **not** `issues` or `alerts`.

| Path | Creates | Semantics | Correlation source | API-creatable |
|---|---|---|---|---|
| **`xql/add_dataset` + `xql/lookups/add_data`** | lookup dataset, typed schema | append, or upsert on `key_fields` | yes | **yes, end to end** |
| HTTP Log Collector | raw dataset | append | yes | no, console configures the target |
| Generic Webhook integration | incident **and** `generic_webhook_generic_alert_raw` | append | yes | integration instance only |
| `setIncident` custom fields | nothing new | per issue | **no**, `issues` is barred | yes |
| `dataset/define_dataset` | BigQuery-backed user dataset | Notebook only | n/a | not applicable here |

### A lookup dataset is the wrong home for history. Measured.

The first build put scan history in a lookup, because it was the only path creatable end to end
from the API. That was wrong, and the test that settles it:

```
dataset = vpn_location_history   timeframe 3 days      -> 13 rows
dataset = vpn_location_history   timeframe 60 seconds  -> 13 rows
dataset = xdr_data               timeframe 60 seconds  ->  1 row
```

**A lookup dataset has no `_time` column**, only `_insert_time` and `_update_time`, and it
**ignores the query timeframe completely**. Consequences, none of which announce themselves:

- the dashboard time-range picker does nothing on a lookup-backed widget
- "movement over the last 7 days" cannot be expressed
- a correlation rule's search window over it is meaningless, so every row re-evaluates forever
- it is mutable, which is the wrong storage class for a record of where an employee was
- it has no retention policy, so it only grows

A lookup is a **reference table**: small, typed, mutable, joinable. Location history is an
**append-only time series**. Use each for what it is.

| Dataset | Type | Written with | Holds |
|---|---|---|---|
| `agentscript_devicelocation_raw` | **raw**, via HTTP collector | gzip POST, append | one row per device per scan. `_time` native, retention applies, scales. **The history.** |
| `vpn_location_current` | lookup | `key_fields: ["host_name"]`, upserts | latest state per device. Small, joinable as enrichment. **Correct use of a lookup.** |

`vpn_location_history`, the lookup stopgap, was deleted on 2026-11-07 once the raw dataset was
live. `run_detection.py --history lookup` still exists for replaying an old run and should not be
used for anything else.

### The collector is the only console step, because the API refuses

```
xql/add_dataset dataset_type=raw   ->  500 "Dataset type: raw is not supported"
```

`lookup` is the only type that route accepts, and there is no collector or parsing-rule API
either: `collectors/*`, `custom_collectors/*`, `http_collector/create`, `data_sources/get` and
`parsing_rules/*` all return the generic 500 that means no such route, against a control that
returns the same. Parsing rules map an already-arrived log into XDM; they do not create the
dataset. **Ingestion creates the dataset**, and ingestion needs a collector whose Vendor and
Product cannot be set from the API or overridden per request.

Collector settings that produced this dataset, created 2026-11-07:

| Field | Value |
|---|---|
| Vendor | `agentscript` |
| Product | `devicelocation` |
| Log Format | JSON |
| Compression | gzip |

Vendor names the **mechanism that produced the data**, not a company. A dataset called
`panw_device_location_raw` would sort beside `panw_ngfw_traffic_raw` and read as shipped content.
`agentscript` also scales: the next agent script becomes `agentscript_<thing>_raw`.

Credentials are `XSIAM_CAGOV_DEVLOC_COLLECTOR_URL` and `..._TOKEN` in `work/.credentials.env`,
separate from `XSIAM_CAGOV_HTTP_COLLECTOR_*`, which targets a different vendor and product.

### Verified on the raw dataset, 2026-11-07

```
dataset = agentscript_devicelocation_raw   timeframe 24 hours    -> 10 rows
dataset = agentscript_devicelocation_raw   timeframe 60 seconds  ->  0 rows
```

The timeframe is honoured, which is the whole reason for the move. **Top-level scalars promote to
native columns with no parsing rule**: `host_name`, `first_public_hop`, `anycast_reachable`,
`confidence`, `scanned_at`, `score` and the rest all arrive as real fields alongside `_time`.

One nuance: `_time` is **ingest** time and `scanned_at` is when the endpoint actually ran. On live
runs they match within seconds; on a backfill they diverge by however old the run was. Filter the
window on `_time` and plot the timeline on `scanned_at`.

Add `| filter host_name != null` to any query over this dataset. A raw dataset also carries
collector-level rows that have no scan fields.

### `delete_dataset` is on v2

`POST /public_api/v1/xql/delete_dataset` answers `Missing required param: dataset_name` however
you shape the body. The working route is **`/public_api/v2/xql/delete_dataset`** with
`{"request_data": {"dataset_name": "..."}}`.

### Three shape traps, all of which return HTTP 200

1. **`lookups/add_data` `data` must be a LIST of row objects.** The published schema says it is an
   object of key-value pairs. Pass that and the API reads each **pair** as a row:
   `{"rows added": 0, "rows updated": 0, "rows skipped": 24}` where 24 is your field count.
   Nothing errors.
2. **`lookups/remove_data` `filters` is a list too.** An object returns a 500 whose `err_extra`
   begins `'str' object has ...`.
3. **`widgets/insert` and `dashboards/insert` take `request_data` AS the list**, and each element
   wraps its payload: `{"request_data": [{"widgets_data": [widget]}]}`. A bare object returns
   400 `The request should contain only a list of JSONs`, the same trap the
   `xsiam-xql-correlation` skill records for `correlations/insert`.

Plus two undocumented requirements that each cost a round trip: **a widget key must start with
`xql_`**, and **a dashboard must carry a 32-char hex `global_id`** or insert answers 200 with
`No global id present in one of the imported dashboards`.

The HTTP collector also works and is the right tool at fleet scale, where a raw dataset is cheaper
than a lookup. It wants **gzip**: a plain JSON body returns
`400 gzip compression error (invalid header)`, and the same body gzipped with
`Content-Encoding: gzip` returns 200. Its target dataset is set in the console, not by the caller.

## The dashboard

`build_dashboard.py` is the **only** thing that should write these objects. Edit it and re-run;
never hand-edit in the console. Two authors on one deployed object drift silently, which is the
measured lesson behind the same rule in the playbook notes.

```bash
./build_dashboard.py --datasets     # the two lookup datasets
./build_dashboard.py --widgets      # five widgets
./build_dashboard.py --dashboard    # "Device Location · VPN spoofing"
```

Live on the tenant as of 2026-11-06: five widgets, one dashboard, both datasets. The movement
widget identified the MacBook Air as `MOVED` across two egress points from real scan history while
the three stationary machines stayed at one.

```bash
./run_detection.py --all-workstations      # runs, then writes both datasets
./run_detection.py --push 102              # backfill one action
./run_detection.py --all-workstations --no-push
```

## Measured: what each platform actually returned

Action 98 and 99, 2026-11-05, run as snippets.

| Endpoint | Platform | `wifi_method` | BSSIDs | Notes |
|---|---|---|---|---|
| Jared's Mac Studio | macOS | `system_profiler` | 2 | 9.3s. Tailscale found and classed sanctioned. |
| Stormbreaker | Windows workstation | **`wlanapi`** | 2 | 5.4s. Timezone `Pacific Standard Time`. |
| windows-test | Windows Server, GCP | `none` | 0 | 17.9s. `wlanapi load: wlanapi`, degraded cleanly. |
| Jared's MacBook Air | macOS | pending | | Agent had not polled; action waits up to four days. |

**The native WLAN API works under SYSTEM with no interactive session.** That was the largest
unknown in the design and Stormbreaker settles it: `wlanapi` answered and returned BSSIDs with
nobody logged in to the console.

A Windows Server with no wireless hardware fails to load `wlanapi.dll` and reports
`wifi_method: none` with the reason in `errors`, which is the intended behaviour rather than a
fault. Cloud VMs will always look like this; do not read it as a detection failure.

## Open items

1. Is `boolean` accepted for a manifest input parameter, or must the flags be strings?
   `_parse_bool` already handles `"true"`/`"false"`, so only the manifest would change.
2. Does `closeInvestigation` work here, as a builtin rather than an automation?
3. Maximum payload length through `commands_list`, if the PowerShell route is ever needed.
4. Whether `system_profiler` still returns a BSSID on a laptop associated to a single AP, as
   opposed to the Studio's two.
