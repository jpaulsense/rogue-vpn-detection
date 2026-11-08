#!/usr/bin/env python3
"""Minimal Cortex XSIAM API client for deploying and driving this detection.

TWO AUTH SCHEMES, AND THE WRONG ONE RETURNS 401 ON EVERY ROUTE INCLUDING NONSENSE
  Standard key:  Authorization: <api_key>
  Advanced key:  Authorization: sha256(api_key + nonce + timestamp)
                 plus x-xdr-nonce and x-xdr-timestamp

  An Advanced key sent the Standard way answers 401 everywhere, which reads as a
  revoked key or a wrong tenant rather than a wrong signature. Run `probe` first:
  it sends a deliberately nonsense route as a control, so a 401 on the control
  tells you the credential is wrong and a 401 on only some routes does not.

NETWORK
  Every call is curl, never Python's ssl stack, because the PA-440 decrypts
  outbound HTTPS from the Mac Studio and curl trusts the keychain while Python
  does not. Same reason bin/cortex-docs does it.

CREDENTIALS
  Read from work/.credentials.env. Never printed, never written to a file.

Usage:
    ./xsiam_api.py probe
    ./xsiam_api.py call scripts/get_scripts '{"request_data":{}}'
"""
import hashlib
import json
import os
import pathlib
import secrets
import string
import subprocess
import sys
import time

TREE = pathlib.Path(__file__).resolve()
while TREE.name != "work" and TREE.parent != TREE:
    TREE = TREE.parent
CREDS = TREE / ".credentials.env"

PREFIX = os.environ.get("XSIAM_TENANT_PREFIX", "XSIAM_CAGOV")


def load_creds():
    """Parse the env file without sourcing it. Values stay in memory."""
    if not CREDS.exists():
        raise SystemExit("credentials not found at %s" % CREDS)
    values = {}
    for line in CREDS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def headers(creds, advanced=True):
    fqdn = creds["%s_FQDN" % PREFIX]
    if advanced:
        key = creds["%s_ADVANCED_API_KEY" % PREFIX]
        key_id = creds["%s_ADVANCED_API_KEY_ID" % PREFIX]
        alphabet = string.ascii_letters + string.digits
        nonce = "".join(secrets.choice(alphabet) for _ in range(64))
        timestamp = str(int(time.time()) * 1000)
        digest = hashlib.sha256(
            (key + nonce + timestamp).encode("utf-8")).hexdigest()
        return fqdn, {
            "x-xdr-timestamp": timestamp,
            "x-xdr-nonce": nonce,
            "x-xdr-auth-id": str(key_id),
            "Authorization": digest,
            "Content-Type": "application/json",
        }
    return fqdn, {
        "x-xdr-auth-id": str(creds["%s_API_KEY_ID" % PREFIX]),
        "Authorization": creds["%s_API_KEY" % PREFIX],
        "Content-Type": "application/json",
    }


def call(route, body=None, advanced=True, surface="public_api/v1", method="POST"):
    """Returns (status_code, parsed_body_or_text)."""
    creds = load_creds()
    fqdn, hdrs = headers(creds, advanced)
    url = "https://%s/%s/%s" % (fqdn, surface, route.lstrip("/"))

    cmd = ["curl", "-s", "-S", "--max-time", "60",
           "-o", "/dev/stdout", "-w", "\n__STATUS__%{http_code}",
           "-X", method, url]
    for name, value in hdrs.items():
        cmd += ["-H", "%s: %s" % (name, value)]
    if body is not None:
        cmd += ["--data-binary", json.dumps(body) if not isinstance(body, str) else body]

    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    raw = result.stdout.decode("utf-8", errors="replace")
    payload, _, status = raw.rpartition("__STATUS__")
    payload = payload.rstrip("\n")
    try:
        return int(status or 0), json.loads(payload) if payload else None
    except ValueError:
        return int(status or 0), payload


def probe():
    """Prove the credential works before concluding anything about a route."""
    checks = [
        ("zzz_not_a_real_route", "CONTROL, expect a non-401"),
        ("system/get_tenant_info", "licence and expiry"),
        ("scripts/get_scripts", "agent script library"),
        ("endpoints/get_endpoint_count", "endpoint inventory"),
    ]
    for advanced in (True, False):
        label = "ADVANCED" if advanced else "STANDARD"
        print("=== %s key ===" % label)
        for route, note in checks:
            try:
                status, body = call(route, {"request_data": {}}, advanced=advanced)
            except Exception as exc:
                print("  %-34s ERROR %s" % (route, exc))
                continue
            extra = ""
            if status == 200 and isinstance(body, dict):
                reply = body.get("reply")
                if isinstance(reply, dict):
                    extra = "  keys=%s" % list(reply.keys())[:6]
                elif isinstance(reply, list):
                    extra = "  items=%d" % len(reply)
            print("  %-34s %s  %s%s" % (route, status, note, extra))
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] == "probe":
        probe()
    elif sys.argv[1] == "call":
        route = sys.argv[2]
        body = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {"request_data": {}}
        surface = sys.argv[4] if len(sys.argv) > 4 else "public_api/v1"
        status, payload = call(route, body, surface=surface)
        print("HTTP %s" % status)
        print(json.dumps(payload, indent=2)[:8000] if payload is not None else "")
    else:
        raise SystemExit(__doc__)
