#!/usr/bin/env python3
"""`synology-dsm-scanner` — detection-only triage for Synology DSM SA-26:19.

Grades a Synology DiskStation Manager (DSM) build against the fixed
releases in Synology-SA-26:19 (2026-11-10):

* `CVE-2026-76954` — CVSS 3.1 9.8, CWE-89, SQL injection in the DSM Auth API.
  Pre-auth, no user interaction, no workaround. Fixed builds per branch:
  7.4.1-90080-1, 7.3.2-86009-5, 7.2.2-72806-10, 7.2.1-69057-13.
* `CVE-2026-85101` — CVSS 3.1 8.6, CWE-288, authentication bypass via an
  alternate path in rsync. Same fixed builds.

Detection-only: this tool reads a version string or the NAS's own
`/etc/VERSION` file and compares it against the vendor's fixed-build
table. It sends no network traffic, no payloads, and no exploit traffic.
There is no remote probe: DSM does not expose a trustworthy version
string to unauthenticated clients, so anything that claims to grade a
NAS from the network alone is guessing. Run it on the NAS (SSH) or feed
it a version string from your inventory.

DSM version anatomy — `7.2.2-72806 Update 10`:
* `productversion` 7.2.2 — the DSM train (`major.minor.patch`).
* `buildnumber` 72806 — the build inside the train.
* `smallfixnumber` 10 — the Update number. This is the part people
  miss: `7.2.2-72806` with no Update is still vulnerable; the fix is
  Update 10, not build 72806.

Grading rules:
* A build is PATCHED only when `(productversion, buildnumber,
  smallfixnumber)` is at or above the fixed build for its own train.
  Build numbers do not compare across trains — `7.2.1-69057-13` is
  fixed while `7.2.2-72806-9` is still vulnerable.
* Anything below 7.2.1 grades UNKNOWN. Synology's advisory lists no
  row for older trains and the CVE records mark everything below 7.2.1
  as unknown. UNKNOWN is not clean — treat the box as potentially
  affected.
* A bare `7.2.2` with no build number grades UNKNOWN. No build, no
  verdict.
* Trains newer than 7.4 (e.g. a future 7.5) grade PATCHED: they ship
  after the fix. The note says so, so a later advisory can correct it.
* `--no-rsync` grades `CVE-2026-85101` NOT-EXPOSED (rsync disabled in
  File Services) while `CVE-2026-76954` is still graded on version.

Exit codes: 0 PATCHED / NOT-EXPOSED, 1 VULNERABLE, 2 UNKNOWN, 3 error.
"""

import argparse
import json
import os
import re
import sys

VERSION = "1.0.0"

# (major, minor) train -> (fixed productversion tuple, fixed build, fixed smallfix)
FIXED = {
    (7, 4): ((7, 4, 1), 90080, 1),
    (7, 3): ((7, 3, 2), 86009, 5),
    (7, 2): None,  # split train, handled below
}
# 7.2 is two trains: 7.2.1 and 7.2.2, each with its own fixed build.
FIXED_72 = {
    (7, 2, 1): (69057, 13),
    (7, 2, 2): (72806, 10),
}

CVES = (
    {
        "id": "CVE-2026-76954",
        "score": "9.8",
        "severity": "Critical",
        "cwe": "CWE-89",
        "title": "SQL injection in the DSM Auth API",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    {
        "id": "CVE-2026-85101",
        "score": "8.6",
        "severity": "Important",
        "cwe": "CWE-288",
        "title": "Authentication bypass in rsync (alternate path)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
    },
)

# `7.2.2-72806-10`, `7.2.2-72806 Update 10`, `DSM 7.4.1-90080-1`, `7.2.2`
VERSION_RE = re.compile(
    r"(?i)(?:dsm\s+)?"
    r"(\d+)\.(\d+)(?:\.(\d+))?"
    r"(?:-(\d+)(?:-(\d+))?)?"
    r"(?:\s+update\s+(\d+))?"
)

KV_RE = re.compile(r'^\s*([A-Za-z_]+)\s*=\s*"?([^"\n]*)"?\s*$')


def parse_version(raw):
    """Parse a DSM version string.

    Returns a dict with `product` (tuple), `build` (int or None),
    `smallfix` (int, 0 when absent) and `display`, or None when the
    string holds no recognisable version at all.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    m = VERSION_RE.search(text)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else 0
    build = int(m.group(4)) if m.group(4) is not None else None
    smallfix = int(m.group(5)) if m.group(5) is not None else None
    if smallfix is None and m.group(6) is not None:
        smallfix = int(m.group(6))
    if smallfix is None:
        smallfix = 0
    product = (major, minor, patch)
    display = "%d.%d.%d" % product
    if build is not None:
        display += "-%d" % build
        if smallfix:
            display += "-%d" % smallfix
    return {
        "product": product,
        "build": build,
        "smallfix": smallfix,
        "display": display,
        "raw": text,
    }


def parse_version_file_text(text):
    """Parse a file that may be `/etc/VERSION` or a bare version string.

    `/etc/VERSION` is `key="value"` lines: `productversion`,
    `buildnumber`, `smallfixnumber`. Anything else falls back to the
    first version-looking token in the text.
    """
    kv = {}
    for line in text.splitlines():
        m = KV_RE.match(line)
        if m:
            kv[m.group(1).strip().lower()] = m.group(2).strip()
    if "productversion" in kv:
        product = kv["productversion"].strip()
        build = kv.get("buildnumber", "").strip()
        smallfix = kv.get("smallfixnumber", "").strip()
        raw = product
        if build:
            raw += "-" + build
            if smallfix:
                raw += "-" + smallfix
        parsed = parse_version(raw)
        if parsed is not None:
            parsed["source"] = "etc-VERSION"
            return parsed
    # Fall back: first version-looking token anywhere in the text.
    parsed = parse_version(text)
    if parsed is not None:
        parsed["source"] = "version-string"
    return parsed


def fixed_for(product):
    """Fixed build for a productversion tuple, or None if unknown.

    Returns (fixed product tuple, fixed build, fixed smallfix).
    """
    major, minor, patch = product
    if (major, minor) in ((7, 4), (7, 3)):
        return FIXED[(major, minor)]
    if (major, minor) == (7, 2):
        if product >= (7, 2, 2):
            build, smallfix = FIXED_72[(7, 2, 2)]
            return ((7, 2, 2), build, smallfix)
        if product == (7, 2, 1):
            build, smallfix = FIXED_72[(7, 2, 1)]
            return ((7, 2, 1), build, smallfix)
        return None  # 7.2.0 and below: below the lowest fixed train
    return None


def grade(version):
    """Grade a parsed version. Returns (verdict, detail)."""
    if version is None:
        return ("UNKNOWN", "no recognisable DSM version")
    product = version["product"]
    build = version["build"]
    smallfix = version["smallfix"]
    display = version["display"]

    # Below 7.2.1 the CVE records say unknown and the advisory has no row.
    if product < (7, 2, 1):
        return (
            "UNKNOWN",
            "%s is below 7.2.1: Synology marks pre-7.2.1 unknown, "
            "treat as potentially affected" % display,
        )
    # Trains newer than any listed fixed build ship after the fix.
    if (product[0], product[1]) > (7, 4):
        return (
            "PATCHED",
            "%s is a later train than 7.4 and ships after the "
            "SA-26:19 fixes" % display,
        )
    if build is None:
        return (
            "UNKNOWN",
            "%s carries no build number, so it cannot be graded "
            "against a fixed build" % display,
        )
    fixed = fixed_for(product)
    if fixed is None:
        return (
            "UNKNOWN",
            "%s has no fixed build listed in SA-26:19" % display,
        )
    fixed_product, fixed_build, fixed_smallfix = fixed
    fixed_display = "%d.%d.%d-%d-%d" % (
        fixed_product + (fixed_build, fixed_smallfix)
    )
    have = (product, build, smallfix)
    want = (fixed_product, fixed_build, fixed_smallfix)
    if have >= want:
        return (
            "PATCHED",
            "%s is at or above the fixed build %s" % (display, fixed_display),
        )
    return (
        "VULNERABLE",
        "%s is below the fixed build %s for its train" % (display, fixed_display),
    )


def grade_cve(version, cve, no_rsync=False):
    """Grade one CVE. Returns a result dict."""
    verdict, detail = grade(version)
    if cve["id"] == "CVE-2026-85101" and no_rsync and verdict == "VULNERABLE":
        verdict = "NOT-EXPOSED"
        detail += "; rsync disabled, so the rsync bypass has no service to reach"
    return {
        "cve": cve["id"],
        "score": cve["score"],
        "severity": cve["severity"],
        "cwe": cwe(cve),
        "title": cve["title"],
        "verdict": verdict,
        "detail": detail,
    }


def cwe(cve):
    return cve["cwe"]


def overall(results):
    """Worst verdict across per-CVE results."""
    verdicts = [r["verdict"] for r in results]
    if "VULNERABLE" in verdicts:
        return "VULNERABLE"
    if "UNKNOWN" in verdicts:
        return "UNKNOWN"
    if all(v == "NOT-EXPOSED" for v in verdicts):
        return "NOT-EXPOSED"
    return "PATCHED"


def scan_version(raw, label, no_rsync=False):
    """Grade one version string. Returns a result dict."""
    version = parse_version(raw)
    results = [grade_cve(version, cve, no_rsync=no_rsync) for cve in CVES]
    return {
        "label": label,
        "version": version["display"] if version else None,
        "raw": raw,
        "results": results,
        "verdict": overall(results),
    }


def detect_local(dsm_root):
    """Read the version off a NAS. `dsm_root` is `/` on the NAS itself,
    or a directory holding an offline copy of `etc/VERSION`."""
    path = os.path.join(dsm_root, "etc", "VERSION")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return None, "cannot read %s: %s" % (path, exc)
    version = parse_version_file_text(text)
    if version is None:
        return None, "%s holds no recognisable DSM version" % path
    return version, None


def scan_local(dsm_root, no_rsync=False):
    version, error = detect_local(dsm_root)
    if version is None:
        return {"label": dsm_root, "version": None, "raw": None,
                "results": [], "verdict": "UNKNOWN", "error": error}
    results = [grade_cve(version, cve, no_rsync=no_rsync) for cve in CVES]
    return {
        "label": dsm_root,
        "version": version["display"],
        "raw": version["raw"],
        "results": results,
        "verdict": overall(results),
    }


def scan_version_file(path, label, no_rsync=False):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        return {"label": label, "version": None, "raw": None,
                "results": [], "verdict": "UNKNOWN",
                "error": "cannot read %s: %s" % (path, exc)}
    version = parse_version_file_text(text)
    if version is None:
        return {"label": label, "version": None, "raw": None,
                "results": [], "verdict": "UNKNOWN",
                "error": "%s holds no recognisable DSM version" % path}
    results = [grade_cve(version, cve, no_rsync=no_rsync) for cve in CVES]
    return {
        "label": label,
        "version": version["display"],
        "raw": version["raw"],
        "results": results,
        "verdict": overall(results),
    }


def print_result(result, as_json=False):
    if as_json:
        print(json.dumps(result, indent=2))
        return
    label = result.get("label") or "?"
    version = result.get("version") or result.get("raw") or "?"
    print("[%s] %s (%s)" % (result["verdict"], label, version))
    if result.get("error"):
        print("  ! %s" % result["error"])
        return
    for r in result["results"]:
        print("  %s [%s %s] %s" % (r["verdict"], r["cve"], r["score"], r["title"]))
        print("    %s" % r["detail"])


def print_fix_table():
    print("Synology-SA-26:19 fixed builds (upgrade to the build for your train, or above):")
    print("  DSM 7.4   -> 7.4.1-90080-1")
    print("  DSM 7.3   -> 7.3.2-86009-5")
    print("  DSM 7.2.2 -> 7.2.2-72806-10")
    print("  DSM 7.2.1 -> 7.2.1-69057-13")
    print("  Below 7.2.1: no fixed build listed, graded UNKNOWN.")
    print("  CVE-2026-76954 (9.8, Auth API SQLi) and CVE-2026-85101 (8.6, rsync")
    print("  auth bypass) share these fixed builds.")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for Synology DSM SA-26:19 "
                    "(CVE-2026-76954 / CVE-2026-85101)."
    )
    parser.add_argument("--version", help="DSM version string, e.g. 7.2.2-72806-10")
    parser.add_argument("--version-file", help="file holding a DSM version or /etc/VERSION")
    parser.add_argument("--local", action="store_true",
                        help="read /etc/VERSION on this NAS")
    parser.add_argument("--dsm-root", default="/",
                        help="root holding etc/VERSION (default: /, use with --local)")
    parser.add_argument("--inventory-json",
                        help="JSON list of {host, version} (or {host, version_file})")
    parser.add_argument("--no-rsync", action="store_true",
                        help="rsync service is disabled (CVE-2026-85101 NOT-EXPOSED)")
    parser.add_argument("--list", action="store_true", help="print the fixed-build table")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.list:
        print_fix_table()
        return 0

    modes = sum(bool(x) for x in (args.version, args.version_file, args.local,
                                  args.inventory_json))
    if modes != 1:
        parser.error("give exactly one of --version, --version-file, --local, "
                     "--inventory-json (or --list)")

    results = []
    if args.version:
        results.append(scan_version(args.version, args.version, args.no_rsync))
    elif args.version_file:
        results.append(scan_version_file(args.version_file, args.version_file,
                                         args.no_rsync))
    elif args.local:
        results.append(scan_local(args.dsm_root, args.no_rsync))
    elif args.inventory_json:
        try:
            with open(args.inventory_json, "r", encoding="utf-8") as fh:
                entries = json.load(fh)
        except (OSError, ValueError) as exc:
            print("cannot read inventory %s: %s" % (args.inventory_json, exc),
                  file=sys.stderr)
            return 3
        if not isinstance(entries, list):
            print("inventory must be a JSON list of {host, version} objects",
                  file=sys.stderr)
            return 3
        for entry in entries:
            host = entry.get("host") or entry.get("name") or "?"
            if entry.get("version_file"):
                results.append(scan_version_file(entry["version_file"], host,
                                                 args.no_rsync))
            else:
                results.append(scan_version(entry.get("version"), host,
                                            args.no_rsync))

    for result in results:
        print_result(result, as_json=args.json)

    verdicts = [r["verdict"] for r in results]
    if "VULNERABLE" in verdicts:
        return 1
    if "UNKNOWN" in verdicts:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
