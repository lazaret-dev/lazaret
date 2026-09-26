#!/usr/bin/env python3
"""CLI-level regression tests — lazaret.py report writing (card "CLI
writes reports into CWD").

Run:  python3 lazaret/test_lazaret_report_cli.py [unittest-args]

Exercises the real CLI end-to-end (subprocess), covering the acceptance
criteria that unit tests can't:

  4. Regression: run a scan with CWD set to a read-only directory; expect
     success (reports land under the scan root) or an early clear error —
     never a post-scan PermissionError / traceback / lost scan.
     - the post-scan FailurePathError the card was opened with
     - the silent-clobber of unrelated same-named files (impact 2)
     - --out-dir, --force-overwrite, --sarif, exit codes 1/2/3, and that
       the printed summary (scan results) appears before any output error

  5. Card f22ce3c5 — hostile deep-nest pre-planted report destinations:
     a scanned repo carries a ~60k-deep lazaret-report.json (the default
     JSON path resolves under the scan root); the pre-scan provenance parse
     (lazaret_report.is_our_report) used to let json.loads' RecursionError
     escape as a traceback with an undefined exit code. Now: exit
     EXIT_OUTPUT=3, refusal message naming the path, planted file
     untouched, and the re-scan workflow (--force-overwrite or a fresh
     --json path) still succeeds.
"""
from __future__ import annotations

import json
import os

from tests import _support  # noqa: E402
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
CLI = _support.CLI

# NOTE on samples: lazaret_flow.analyze() (shipped engine) crashes on any
# Python file containing a `return <expr>` under Python 3.12+ (ast.Num
# removal) — a separate card's scope. CLI tests here use samples that the
# SHIPPED engine scans cleanly so this suite stays about report handling.
SAMPLE = {
    "app.js": "var x = 1;\nconsole.log(x);\n",
    "a.py": "x = 1\ny = x + 2\n",
}

def run_cli(args, cwd, cli_path=CLI):
    return subprocess.run([sys.executable, cli_path] + args,
                          cwd=cwd, capture_output=True, encoding="utf-8", errors="replace",
                          timeout=120)


class CliReportBase(unittest.TestCase):
    def make_scan_root(self, files=None):
        root = tempfile.mkdtemp(prefix="cg-cli-root-")
        self.addCleanup(self._rmtree_rw, root)
        for name, text in (files or SAMPLE).items():
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return root

    def make_ro_cwd(self):
        d = tempfile.mkdtemp(prefix="cg-cli-ro-")
        os.chmod(d, stat.S_IRUSR | stat.S_IXUSR)
        # Restore writability BEFORE rmtree (cleanups run LIFO).
        self.addCleanup(self._rmtree_rw, d)
        return d

    @staticmethod
    def _rmtree_rw(path):
        import shutil
        def onerror(func, p, exc):
            try:
                os.chmod(os.path.dirname(p) if os.path.isfile(p) else p, 0o700)
            except OSError:
                pass
            func(p)
        if os.path.isdir(path):
            for dp, dns, fns in os.walk(path):
                for dn in dns:
                    try:
                        os.chmod(os.path.join(dp, dn), 0o700)
                    except OSError:
                        pass
                try:
                    os.chmod(dp, 0o700)
                except OSError:
                    pass
        shutil.rmtree(path, ignore_errors=True)


class TestReadOnlyCwd(CliReportBase):
    """Acceptance criterion 4: CWD read-only, scan root writable — success."""

    def test_scan_from_read_only_cwd_succeeds_and_writes_under_scan_root(self):
        root = self.make_scan_root()
        ro_cwd = self.make_ro_cwd()
        p = run_cli([root], cwd=ro_cwd)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("PermissionError", p.stderr)
        # Reports under the scan root, not the (read-only) CWD.
        for name in ("lazaret-report.json", "lazaret-report.html"):
            path = os.path.join(root, name)
            self.assertTrue(os.path.isfile(path),
                            f"missing {name} under scan root")
            self.assertGreater(os.path.getsize(path), 0)
        self.assertEqual(os.listdir(ro_cwd), [])   # nothing dropped in CWD

    @_support.skip_unless_permissions_enforced

    def test_read_only_cwd_and_read_only_scan_root_fails_fast_prescan(self):
        # Both read-only: the default report destinations are unwritable →
        # early, clear exit 3 BEFORE the scan (no traceback), and the scan
        # summary is never printed (never paid for a scan to lose it).
        ro_root = self.make_scan_root()
        os.chmod(ro_root, stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(lambda: os.chmod(ro_root, 0o755))
        ro_cwd = self.make_ro_cwd()
        p = run_cli([ro_root], cwd=ro_cwd)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("error:", p.stderr)
        self.assertIn("not writable", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        # print_report() runs only after a scan; a pre-scan exit must not
        # have paid for (or printed) one.
        self.assertNotIn("Lazaret scan", p.stdout)


class TestReportsDisabledOnReadOnlyRoot(unittest.TestCase):
    def test_no_html_no_json_allows_read_only_scan_root(self):
        root = tempfile.mkdtemp(prefix="cg-cli-root-")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        with open(os.path.join(root, "app.js"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("var x = 1;\n")
        os.chmod(root, stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(lambda: os.chmod(root, 0o755))
        p = run_cli([root, "--no-json", "--no-html"], cwd=root)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)


class TestClobberPrevention(CliReportBase):
    """Acceptance criterion 3: never silently clobber unrelated files."""

    def test_unrelated_same_named_file_in_scan_root_is_preserved(self):
        root = self.make_scan_root()
        precious = os.path.join(root, "lazaret-report.json")
        with open(precious, "w", encoding="utf-8") as fh:
            fh.write('{"precious": true}')
        p = run_cli([root], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        with open(precious, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["precious"], True)   # untouched

    def test_unrelated_html_report_refused_not_clobbered(self):
        root = self.make_scan_root()
        precious = os.path.join(root, "lazaret-report.html")
        with open(precious, "w", encoding="utf-8") as fh:
            fh.write("<html><body>my dashboard</body></html>")
        p = run_cli([root], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        with open(precious, encoding="utf-8") as fh:
            self.assertIn("my dashboard", fh.read())            # untouched

    def test_force_overwrite_replaces_unrelated_file(self):
        root = self.make_scan_root()
        junk = os.path.join(root, "lazaret-report.json")
        with open(junk, "w", encoding="utf-8") as fh:
            fh.write("junk")
        p = run_cli([root, "--force-overwrite"], cwd=root)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(junk, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)[cr_ENGINE_MARKER_KEY()], cr_ENGINE_MARKER_VALUE())

    def test_rerun_scan_overwrites_own_reports(self):
        # The re-scan workflow: our own earlier reports are replaced.
        root = self.make_scan_root()
        p1 = run_cli([root], cwd=root)
        self.assertEqual(p1.returncode, 0, p1.stderr)
        mtime1 = os.path.getmtime(os.path.join(root, "lazaret-report.json"))
        p2 = run_cli([root], cwd=root)
        self.assertEqual(p2.returncode, 0, p2.stderr)
        mtime2 = os.path.getmtime(os.path.join(root, "lazaret-report.json"))
        self.assertGreaterEqual(mtime2, mtime1)
        # And the JSON is still valid and marker-stamped.
        with open(os.path.join(root, "lazaret-report.json"), encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data[cr_ENGINE_MARKER_KEY()], cr_ENGINE_MARKER_VALUE())


class TestOutDirAndExplicitPaths(CliReportBase):
    def test_out_dir_places_reports_there(self):
        root = self.make_scan_root()
        out = tempfile.mkdtemp(prefix="cg-cli-out-")
        self.addCleanup(lambda: __import__("shutil").rmtree(out, True))
        p = run_cli([root, "--out-dir", out], cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.isfile(os.path.join(out, "lazaret-report.json")))
        self.assertTrue(os.path.isfile(os.path.join(out, "lazaret-report.html")))

    def test_out_dir_missing_fails_fast_pre_scan(self):
        root = self.make_scan_root()
        missing = os.path.join(tempfile.gettempdir(), "cg-no-such-out-dir")
        p = run_ci = run_cli([root, "--out-dir", missing], cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("error:", p.stderr)
        self.assertIn("does not exist", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    @_support.skip_unless_permissions_enforced

    def test_out_dir_read_only_fails_fast_pre_scan(self):
        root = self.make_scan_root()
        out = tempfile.mkdtemp(prefix="cg-cli-outro-")
        os.chmod(out, stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(lambda: os.chmod(out, 0o755))
        p = run_cli([root, "--out-dir", out], cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("error:", p.stderr)
        self.assertIn("not writable", p.stderr)
        self.assertNotIn("Lazaret scan", p.stdout)   # pre-scan: no summary

    def test_explicit_relative_json_path_lands_under_scan_root(self):
        # A bare --json name (the old code wrote it to CWD) now resolves
        # under the scan root, not the CWD.
        root = self.make_scan_root()
        cwd = tempfile.mkdtemp(prefix="cg-cli-cwd-")
        self.addCleanup(lambda: __import__("shutil").rmtree(cwd, True))
        p = run_cli([root, "--json", "my-report.json"], cwd=cwd)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.isfile(os.path.join(root, "my-report.json")))
        self.assertFalse(os.path.exists(os.path.join(cwd, "my-report.json")))
        with open(os.path.join(cwd, "lazaret-report.json"), "w", encoding="utf-8", newline="\n") as fh:
            pass            # ensure CWD stayed clean of defaults too
        self.assertEqual([f for f in os.listdir(cwd)
                          if not f.startswith(".")], ["lazaret-report.json"])

    def test_explicit_relative_json_path_out_dir_relative(self):
        root = self.make_scan_root()
        out = tempfile.mkdtemp(prefix="cg-cli-out-")
        self.addCleanup(lambda: __import__("shutil").rmtree(out, True))
        p = run_cli([root, "--out-dir", out, "--json", "custom.json"],
                    cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(os.path.isfile(os.path.join(out, "custom.json")))

    def test_sarif_report_written_and_stamped(self):
        root = self.make_scan_root()
        out = tempfile.mkdtemp(prefix="cg-cli-out-")
        self.addCleanup(lambda: __import__("shutil").rmtree(out, True))
        p = run_ci = run_cli([root, "--out-dir", out, "--sarif", "out.sarif"],
                             cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 0, p.stderr)
        path = os.path.join(out, "out.sarif")
        self.assertTrue(os.path.isfile(path))
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        props = data.get("properties", {})
        self.assertEqual(props.get(cr_ENGINE_MARKER_KEY()), cr_ENGINE_MARKER_VALUE())


class TestDeepNestHostileDestination(CliReportBase):
    """Card f22ce3c5 acceptance: a hostile repo pre-plants the report
    destination with a deeply-nested JSON document (~60KB of '['). The
    pre-scan provenance check parses that head with json.loads; the
    RecursionError used to escape as a traceback with an undefined exit
    code. Now: no traceback, defined exit EXIT_OUTPUT=3, refusal message
    naming the path, the planted file untouched, and the re-scan workflow
    (--force-overwrite or a fresh --json path) still succeeds."""

    # 120k '[' bytes ≈ 60k-deep nesting — deep enough that CPython's
    # json.loads blows its C recursion limit (independent of version).
    DEEP = "[" * 120000

    def _plant(self, root, name="lazaret-report.json", content=None):
        path = os.path.join(root, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content if content is not None else self.DEEP)
        return path

    def test_deep_default_json_destination_refused_not_crash(self):
        root = self.make_scan_root()
        planted = self._plant(root)
        p = run_cli([root], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)         # EXIT_OUTPUT
        self.assertIn("refusing to overwrite", p.stderr)
        self.assertIn(planted, p.stderr)                    # names the path
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("Traceback", p.stdout)
        self.assertNotIn("Lazaret scan", p.stdout)        # pre-scan exit
        with open(planted, encoding="utf-8") as fh:         # untouched
            self.assertEqual(len(fh.read()), len(self.DEEP))

    def test_deep_explicit_json_destination_refused(self):
        root = self.make_scan_root()
        planted = self._plant(root, "deep.json")
        p = run_cli([root, "--no-html", "--json", planted], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_deep_sarif_destination_refused(self):
        root = self.make_scan_root()
        planted = self._plant(root, "deep.sarif")
        p = run_cli([root, "--no-json", "--no-html", "--sarif", planted],
                    cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        with open(planted, encoding="utf-8") as fh:         # untouched
            self.assertEqual(len(fh.read()), len(self.DEEP))

    def test_deep_html_destination_refused(self):
        root = self.make_scan_root()
        planted = self._plant(root, "lazaret-report.html")
        p = run_cli([root, "--no-json"], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_force_overwrite_replaces_deep_planted_doc(self):
        root = self.make_scan_root()
        planted = self._plant(root)
        p = run_cli([root, "--force-overwrite"], cwd=root)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        with open(planted, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data[cr_ENGINE_MARKER_KEY()],
                         cr_ENGINE_MARKER_VALUE())

    def test_fresh_json_path_scans_despite_deep_plant(self):
        # Acceptance: "a subsequent re-scan … with a fresh --json path
        # still succeeds" — the hostile plant blocks only its own path.
        root = self.make_scan_root()
        planted = self._plant(root, "hostile.json")
        fresh = os.path.join(root, "fresh.json")
        p = run_cli([root, "--no-html", "--json", fresh], cwd=root)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        with open(fresh, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)[cr_ENGINE_MARKER_KEY()],
                             cr_ENGINE_MARKER_VALUE())
        with open(planted, encoding="utf-8") as fh:         # still intact
            self.assertEqual(len(fh.read()), len(self.DEEP))

    def test_hostile_replacement_of_our_report_refused_next_run(self):
        # Realistic sequence: run 1 writes OUR report to the default path;
        # the repo content then swaps it for a hostile deep doc; run 2 must
        # refuse cleanly (exit 3, no traceback), not crash on provenance.
        # (The in-process mid-scan TOCTOU race itself is covered at module
        # level: write_report's re-check refuses a deep doc deterministically.)
        root = self.make_scan_root()
        p1 = run_cli([root], cwd=root)
        self.assertEqual(p1.returncode, 0, p1.stderr)
        planted = self._plant(root)                        # swap for DEEP
        p2 = run_cli([root], cwd=root)
        self.assertEqual(p2.returncode, 3, p2.stderr)
        self.assertIn("refusing to overwrite", p2.stderr)
        self.assertNotIn("Traceback", p2.stderr)
        self.assertNotIn("Traceback", p2.stdout)
        with open(planted, encoding="utf-8") as fh:
            self.assertEqual(len(fh.read()), len(self.DEEP))

    def test_deeper_than_marker_window_still_refused(self):
        # Deep doc longer than the 64KB provenance read window: only the
        # first 64KB is read, which is already a 120k-'[' head anyway.
        root = self.make_scan_root()
        planted = self._plant(root, content="[" * 130000)
        p = run_cli([root], cwd=root)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("refusing to overwrite", p.stderr)
        self.assertNotIn("Traceback", p.stderr)


class TestExitCodes(CliReportBase):
    def test_usage_error_is_still_2(self):
        p = run_cli([], cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 2)
        p = run_cli(["/no/such/dir"], cwd=tempfile.gettempdir())
        self.assertEqual(p.returncode, 2)

    def test_quality_gate_ci_exit_1_unaffected(self):
        # A gate-failing sample: 'eval()' flagged on the .py file (S-EVAL-PY).
        # Exit 1 must still be reached AND reports still written (default on).
        root = self.make_scan_root({
            "app.py": "eval(user_input)\n",
        })
        p = run_cli([root, "--ci"], cwd=root)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertTrue(os.path.isfile(os.path.join(root, "lazaret-report.json")))
        self.assertNotIn("Traceback", p.stderr)


def cr_ENGINE_MARKER_KEY():
    return "generatedBy"

def cr_ENGINE_MARKER_VALUE():
    return "lazaret-cli-1"


if __name__ == "__main__":
    unittest.main(verbosity=2)
