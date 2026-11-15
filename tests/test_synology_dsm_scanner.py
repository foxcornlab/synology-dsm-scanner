#!/usr/bin/env python3
"""Tests for `synology_dsm_scanner` — run with `python3 -m unittest discover -s tests -v`."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import synology_dsm_scanner as s


def etc_version(product, build, smallfix):
    """A realistic /etc/VERSION file for a DSM build."""
    return (
        'majorversion="%d"\n'
        'minorversion="%d"\n'
        'productversion="%s"\n'
        'buildphase="GM"\n'
        'buildnumber="%d"\n'
        'smallfixnumber="%d"\n'
        'builddate="2025/07/24"\n'
        'buildtime="02:21:17"\n'
    ) % (product[0], product[1], ".".join(str(x) for x in product),
         build, smallfix)


class TestParseVersion(unittest.TestCase):
    def test_dash_form(self):
        v = s.parse_version("7.2.2-72806-10")
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 2, 2), 72806, 10))

    def test_update_form(self):
        v = s.parse_version("7.2.2-72806 Update 10")
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 2, 2), 72806, 10))

    def test_dsm_prefix(self):
        v = s.parse_version("DSM 7.4.1-90080-1")
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 4, 1), 90080, 1))

    def test_bare_build_no_update(self):
        # `7.2.2-72806` with no Update suffix: smallfix defaults to 0.
        v = s.parse_version("7.2.2-72806")
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 2, 2), 72806, 0))

    def test_bare_version_no_build(self):
        v = s.parse_version("7.2.2")
        self.assertEqual(v["product"], (7, 2, 2))
        self.assertIsNone(v["build"])

    def test_two_part_version(self):
        v = s.parse_version("7.4")
        self.assertEqual(v["product"], (7, 4, 0))

    def test_garbage(self):
        self.assertIsNone(s.parse_version("not a version"))
        self.assertIsNone(s.parse_version(""))
        self.assertIsNone(s.parse_version(None))


class TestParseVersionFile(unittest.TestCase):
    def test_etc_version(self):
        v = s.parse_version_file_text(etc_version((7, 2, 2), 72806, 10))
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 2, 2), 72806, 10))

    def test_etc_version_missing_smallfix(self):
        text = etc_version((7, 2, 1), 69057, 13).replace(
            'smallfixnumber="13"\n', "")
        v = s.parse_version_file_text(text)
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 2, 1), 69057, 0))

    def test_bare_string_fallback(self):
        v = s.parse_version_file_text("DSM version 7.3.2-86009-5\n")
        self.assertEqual((v["product"], v["build"], v["smallfix"]),
                         ((7, 3, 2), 86009, 5))

    def test_no_version(self):
        self.assertIsNone(s.parse_version_file_text("nothing here\n"))


class TestGrade(unittest.TestCase):
    def grade(self, raw):
        return s.grade(s.parse_version(raw))[0]

    def test_exact_fixed_builds_patched(self):
        for raw in ("7.4.1-90080-1", "7.3.2-86009-5",
                    "7.2.2-72806-10", "7.2.1-69057-13"):
            self.assertEqual(self.grade(raw), "PATCHED", raw)

    def test_one_update_above_fixed_patched(self):
        for raw in ("7.4.1-90080-2", "7.3.2-86009-6",
                    "7.2.2-72806-11", "7.2.1-69057-14"):
            self.assertEqual(self.grade(raw), "PATCHED", raw)

    def test_one_update_below_fixed_vulnerable(self):
        for raw in ("7.4.1-90080-0", "7.3.2-86009-4",
                    "7.2.2-72806-9", "7.2.1-69057-12"):
            self.assertEqual(self.grade(raw), "VULNERABLE", raw)

    def test_bare_build_trap(self):
        # Build number alone is not the fix: no Update suffix means
        # smallfix 0, below every fixed build.
        for raw in ("7.4.1-90080", "7.3.2-86009",
                    "7.2.2-72806", "7.2.1-69057"):
            self.assertEqual(self.grade(raw), "VULNERABLE", raw)

    def test_older_patch_release_vulnerable(self):
        self.assertEqual(self.grade("7.4.0-64570"), "VULNERABLE")
        self.assertEqual(self.grade("7.3.1-12345"), "VULNERABLE")
        self.assertEqual(self.grade("7.3.2-86009-4"), "VULNERABLE")

    def test_cross_train_trap(self):
        # 7.2.1-69057-13 is fixed, but the 7.2.2 train needs its own
        # build: a 7.2.2 box one Update behind is still vulnerable.
        self.assertEqual(self.grade("7.2.1-69057-13"), "PATCHED")
        self.assertEqual(self.grade("7.2.2-72806-9"), "VULNERABLE")
        # And a 7.2.2 build number is higher than 7.2.1's — that proves
        # nothing across trains.
        self.assertEqual(self.grade("7.2.2-72806-10"), "PATCHED")

    def test_below_721_unknown(self):
        for raw in ("7.2.0-12345", "7.1.1-42962-6", "7.0.1-42218-3"):
            verdict, detail = s.grade(s.parse_version(raw))
            self.assertEqual(verdict, "UNKNOWN", raw)
            self.assertIn("unknown", detail.lower())

    def test_dsm6_unknown(self):
        verdict, detail = s.grade(s.parse_version("6.2.4-25556-7"))
        self.assertEqual(verdict, "UNKNOWN")
        self.assertIn("potentially affected", detail)

    def test_bare_version_unknown(self):
        for raw in ("7.2.2", "7.4.1", "7.3.2"):
            verdict, detail = s.grade(s.parse_version(raw))
            self.assertEqual(verdict, "UNKNOWN", raw)
            self.assertIn("no build number", detail)

    def test_later_train_patched(self):
        self.assertEqual(self.grade("7.5.0-10000-1"), "PATCHED")
        self.assertEqual(self.grade("8.0.0-10000"), "PATCHED")

    def test_no_version_unknown(self):
        self.assertEqual(s.grade(None)[0], "UNKNOWN")


class TestPerCve(unittest.TestCase):
    def test_both_vulnerable(self):
        r = s.scan_version("7.2.2-72806-9", "nas1")
        self.assertEqual(r["verdict"], "VULNERABLE")
        self.assertEqual([x["verdict"] for x in r["results"]],
                         ["VULNERABLE", "VULNERABLE"])

    def test_both_patched(self):
        r = s.scan_version("7.2.2-72806-10", "nas1")
        self.assertEqual(r["verdict"], "PATCHED")
        self.assertEqual([x["cve"] for x in r["results"]],
                         ["CVE-2026-76954", "CVE-2026-85101"])

    def test_no_rsync_exposes_only_auth_api(self):
        r = s.scan_version("7.2.2-72806-9", "nas1", no_rsync=True)
        self.assertEqual(r["verdict"], "VULNERABLE")  # Auth API still open
        self.assertEqual([x["verdict"] for x in r["results"]],
                         ["VULNERABLE", "NOT-EXPOSED"])

    def test_no_rsync_when_patched_stays_patched(self):
        r = s.scan_version("7.4.1-90080-1", "nas1", no_rsync=True)
        self.assertEqual(r["verdict"], "PATCHED")

    def test_unknown_overall(self):
        r = s.scan_version("6.2.4-25556-7", "old-nas")
        self.assertEqual(r["verdict"], "UNKNOWN")


class TestLocalAndFiles(unittest.TestCase):
    def test_scan_local_fixture(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "etc"))
            with open(os.path.join(root, "etc", "VERSION"), "w") as fh:
                fh.write(etc_version((7, 3, 2), 86009, 5))
            r = s.scan_local(root)
            self.assertEqual(r["verdict"], "PATCHED")
            self.assertEqual(r["version"], "7.3.2-86009-5")

    def test_scan_local_vulnerable_fixture(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "etc"))
            with open(os.path.join(root, "etc", "VERSION"), "w") as fh:
                fh.write(etc_version((7, 2, 2), 72806, 9))
            r = s.scan_local(root)
            self.assertEqual(r["verdict"], "VULNERABLE")

    def test_scan_local_missing_file(self):
        with tempfile.TemporaryDirectory() as root:
            r = s.scan_local(root)
            self.assertEqual(r["verdict"], "UNKNOWN")
            self.assertIn("cannot read", r["error"])

    def test_scan_version_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt",
                                         delete=False) as fh:
            fh.write(etc_version((7, 4, 1), 90080, 1))
            path = fh.name
        try:
            r = s.scan_version_file(path, "nas2")
            self.assertEqual(r["verdict"], "PATCHED")
        finally:
            os.unlink(path)

    def test_inventory_json(self):
        entries = [
            {"host": "nas-a", "version": "7.2.2-72806-10"},
            {"host": "nas-b", "version": "7.2.1-69057-12"},
            {"host": "nas-c", "version": "6.2.4-25556-7"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(entries, fh)
            path = fh.name
        try:
            code = s.main(["--inventory-json", path, "--json"])
            self.assertEqual(code, 1)  # one vulnerable box
        finally:
            os.unlink(path)


class TestCli(unittest.TestCase):
    def test_list(self):
        self.assertEqual(s.main(["--list"]), 0)

    def test_exit_codes(self):
        self.assertEqual(s.main(["--version", "7.2.2-72806-10"]), 0)
        self.assertEqual(s.main(["--version", "7.2.2-72806-9"]), 1)
        self.assertEqual(s.main(["--version", "6.2.4-25556-7"]), 2)
        self.assertEqual(s.main(["--version", "garbage"]), 2)

    def test_json_output(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = s.main(["--version", "7.2.2-72806-10", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["verdict"], "PATCHED")


if __name__ == "__main__":
    unittest.main()
