# `synology-dsm-scanner`

Detection-only triage for Synology DSM `SA-26:19`: `CVE-2026-76954` (9.8, pre-auth SQLi in the Auth API) and `CVE-2026-85101` (8.6, rsync auth bypass). Grades your DSM build against Synology's fixed releases. No payloads, no exploit traffic, no network probes.

## `What it checks`

* `CVE-2026-76954` — SQL injection in the DSM Auth API. `CVSS 9.8`, `CWE-89`. Remote, no login, no user interaction. Synology lists no workaround: patching is the only fix.
* `CVE-2026-85101` — authentication bypass in rsync, alternate path. `CVSS 8.6`, `CWE-288`. Same fixed builds.

Fixed builds, per `Synology-SA-26:19` (2026-11-10):

| `DSM train` | `Upgrade to` |
| --- | --- |
| `7.4` | `7.4.1-90080-1` |
| `7.3` | `7.3.2-86009-5` |
| `7.2.2` | `7.2.2-72806-10` |
| `7.2.1` | `7.2.1-69057-13` |

## `Usage`

```bash
# on the NAS itself (SSH), reads /etc/VERSION
python3 synology_dsm_scanner.py --local

# a version string from your inventory
python3 synology_dsm_scanner.py --version 7.2.2-72806-9
python3 synology_dsm_scanner.py --version "7.2.2-72806 Update 10"

# a saved /etc/VERSION, or any file holding a version string
python3 synology_dsm_scanner.py --version-file /path/to/VERSION

# a whole fleet at once
python3 synology_dsm_scanner.py --inventory-json fleet.json

# rsync is disabled on this box, so CVE-2026-85101 has nothing to reach
python3 synology_dsm_scanner.py --local --no-rsync

# machine output / the fixed-build table
python3 synology_dsm_scanner.py --version 7.2.2-72806-10 --json
python3 synology_dsm_scanner.py --list
```

`fleet.json` is a list of `{"host": "nas-a", "version": "7.2.2-72806-10"}` objects. Entries can use `"version_file"` instead of `"version"` to point at a saved `/etc/VERSION`.

Exit codes: `0` patched or not exposed, `1` vulnerable, `2` unknown, `3` usage error.

## `The traps`

* `The bare build trap` — `7.2.2-72806` with no Update number looks patched. It is not. The fix is Update 10, and a bare build grades `VULNERABLE`.
* `The cross-train trap` — build numbers do not compare across trains. `7.2.1-69057-13` is fixed while `7.2.2-72806-9` is still vulnerable, even though `72806` is the bigger number.
* `The below 7.2.1 trap` — Synology lists no row for older trains and the CVE records mark everything below `7.2.1` as unknown. This tool grades those `UNKNOWN`, never clean. Treat the box as potentially affected.
* `The no-build trap` — a bare `7.2.2` with no build number grades `UNKNOWN`. No build, no verdict.
* `The rsync trap` — `CVE-2026-85101` only matters if rsync is on. `--no-rsync` grades it `NOT-EXPOSED` while the Auth API flaw is still graded on version.

## `Why local only`

DSM does not hand a trustworthy version string to unauthenticated clients, so a remote probe would be guessing. This tool grades the version the NAS reports about itself: `/etc/VERSION` on the box, or a version string from inventory. That is the same call the Fortinet, SAP and Faspex scanners in this series make, and it is the honest one here.

## `Sources and disagreements`

* `Synology-SA-26:19` (2026-11-10, Rev 1): advisory, fixed builds, `CVSS 9.8` / `8.6`, mitigation `None`. Primary source for everything graded here.
* CVE records published 2026-11-12 (`CVE-2026-76954` 03:41 UTC, `CVE-2026-85101` 03:40 UTC). NVD still lists both as `Received` with no NVD-generated score, so Synology's scores are followed.
* Neither CVE was in CISA KEV as of the 2026-11-10 catalog. Synology reports no exploitation. A public containerized PoC exists; this tool does not use it and sends no exploit traffic.
* `SA-26:18`, published the same day, fixes 25 more DSM flaws on the 7.3 and 7.4 trains with the same fixed builds. This scanner grades only the two `SA-26:19` CVEs.
* DSM `6.x` is end of support since October 2024 and has no fixed build listed. Graded `UNKNOWN`.

## `Thanks to`

* `Nguyễn Bá Nam Dũng` and `Hà Thế Long` of Viettel Cyber Security Research Lab — found `CVE-2026-76954`.
* `Warisse Valentin` (Aytio) — found `CVE-2026-85101`.
* Synology, for publishing a clean fixed-build table instead of a single version number.

## `Disclaimer`

Detection only, for defenders checking their own boxes. Educational use. If you are not supposed to be on the NAS, do not run this there.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
