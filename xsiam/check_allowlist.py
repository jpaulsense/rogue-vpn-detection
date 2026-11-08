#!/usr/bin/env python3
"""Check an agent script against the Cortex XSIAM Upload Script module allowlist.

XSIAM parses a script at upload time and rejects it if it imports anything outside
the allowlist. The rejection happens in the browser, after the file is dragged in,
and it names one module at a time. This runs the same check locally.

The allowlist below was read from Action Center -> Agent Script Library -> New Script
-> supported modules on 2026-11-05. It is tenant state, not documentation: no Cortex
doc page publishes it. Re-read it from the console before trusting this file after a
content update.

Note what is NOT on it and would otherwise be reached for without thinking:
`typing`, `math`, `urllib`, `ipaddress`, `itertools`, `string`, `copy`, `tempfile`.
The repository's own wifi-geolocation.py imports both `typing` and `urllib`, which is
why it cannot be uploaded unchanged.

Usage:
    ./check_allowlist.py vpn_location_detect.py
    ./check_allowlist.py          # defaults to every .py beside this file
"""
import ast
import pathlib
import sys

ALLOWED = {
    "argparse", "asyncio", "base64", "browserhistory", "certifi", "collections",
    "contextlib", "csv", "ctypes", "datetime", "enum", "fnmatch", "functools",
    "glob", "globmatch", "gzip", "hashlib", "icmplib", "importlib", "io", "json",
    "LnkParse3", "locale", "logging", "multiprocessing", "netifaces", "os",
    "pathlib", "pefile", "platform", "pprint", "protobuf", "psutil", "pysftp",
    "python_hosts", "pythoncom", "pytsk3", "pywintypes", "queue", "random", "re",
    "Registry", "requests", "runpy", "setuptools", "shlex", "shutil", "signal",
    "socket", "sqlite_utils", "sqlite3", "ssl", "stat", "struct", "subprocess",
    "sys", "threading", "time", "traceback", "types", "unicodecsv", "uuid",
    "websocket", "win32api", "win32com", "win32con", "win32evtlog",
    "win32evtlogutil", "win32file", "win32net", "win32netcon", "win32process",
    "win32security", "win32service", "win32serviceutil", "win32timezone",
    "winapps", "winerror", "winpty", "winreg", "wmi", "xml", "xmljson", "yara",
    "zipfile", "zlib",
}


def imported_modules(path):
    """Every top-level module name the file imports, at any nesting depth."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.setdefault(alias.name.split(".")[0], node.lineno)
        elif isinstance(node, ast.ImportFrom):
            if node.level:            # relative import, no top-level module
                continue
            if node.module:
                found.setdefault(node.module.split(".")[0], node.lineno)
    return found


def check(path):
    modules = imported_modules(path)
    bad = {name: line for name, line in modules.items() if name not in ALLOWED}
    print("%s: %d imports, %d outside the allowlist"
          % (path.name, len(modules), len(bad)))
    for name in sorted(modules):
        mark = "ok " if name in ALLOWED else "NO "
        print("  %s %-16s line %d" % (mark, name, modules[name]))
    return not bad


def main():
    here = pathlib.Path(__file__).resolve().parent
    if len(sys.argv) > 1:
        targets = [pathlib.Path(a) for a in sys.argv[1:]]
    else:
        targets = sorted(p for p in here.glob("*.py") if p.name != "check_allowlist.py")

    ok = True
    for target in targets:
        if not check(target):
            ok = False
        print()
    if not ok:
        print("FAIL: at least one import is outside the allowlist.")
        return 1
    print("PASS: every import is on the allowlist.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
