"""Review findings 1, 2 and 4 — report provenance, baseline trust, report
permissions.

1. is_our_report parsed only the first 64 KiB of a report, so any real
   report over ~100 findings was "not ours": a plain re-scan exited 3 and
   every genuine --baseline was untrusted. Provenance is now a bounded prefix
   match on the marker.
2. The engine marker is a public constant: a hand-written 5-line baseline
   carrying it zeroed "New issues vs baseline". Now: with
   LAZARET_BASELINE_KEY set, reports are HMAC-signed and a baseline must
   verify; without a key, a baseline inside the scanned tree is untrusted.
4. A re-scan reset a 0600 report to 0644; the existing mode is now kept.

All fixtures are inert (no code is executed; the "project" is text).
"""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from tests import _support
from lazaret.scanner import core as lazaret
from lazaret.scanner import reports

PY = sys.executable or "python3"
CLI = _support.CLI

EVIL_PY = 'import os\ndef f(x):\n    os.system("ls " + x)\n    eval(x)\n'


def _issue(n, path="pkg/mod.py"):
    return {"rule": "S-EVAL-PY", "name": "n", "type": "VULN", "sev": "CRITICAL",
            "msg": "m" * 200, "why": "w" * 200, "fix": "f", "ref": "r",
            "file": path, "line": n + 1, "snipStart": n,
            "snippet": [f"x{n} = 1", f"eval(data_{n})", "pass"]}


def _big_result(count=400):
    return {"project": "/p", "pass": False, "conditions": [], "metrics": {},
            "counts": {}, "ratings": {}, "issues": [_issue(i) for i in range(count)]}


def _env(key=None):
    env = dict(os.environ)
    env.pop(reports.BASELINE_KEY_ENV, None)
    if key is not None:
        env[reports.BASELINE_KEY_ENV] = key
    return env


def load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run_cli(args, key=None):
    return subprocess.run([PY, CLI, *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=40, env=_env(key))


class TempDirs(unittest.TestCase):
    def mkdtemp(self):
        d = tempfile.mkdtemp(prefix="lz-review-rep-")
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


# ---------------------------------------------------------------------------
# 1. provenance of large reports
# ---------------------------------------------------------------------------
class LargeReportProvenance(TempDirs):
    def test_large_json_report_is_ours(self):
        d = self.mkdtemp()
        path = self.write(os.path.join(d, "r.json"), reports.json_renderer(_big_result()))
        self.assertGreater(os.path.getsize(path), 2 * reports.MARKER_READ_BYTES)
        self.assertTrue(reports.is_our_report(path, "json"))

    def test_large_sarif_is_ours(self):
        d = self.mkdtemp()
        sarif = {"version": "2.1.0", "runs": [{"results": ["x" * 1000] * 200}]}
        path = self.write(os.path.join(d, "r.sarif"), reports.sarif_renderer(sarif))
        self.assertGreater(os.path.getsize(path), reports.MARKER_READ_BYTES)
        self.assertTrue(reports.is_our_report(path, "sarif"))

    def test_html_marker_in_head(self):
        d = self.mkdtemp()
        good = self.write(os.path.join(d, "a.html"),
                          "<!doctype html><html><head>" + reports.HTML_ENGINE_MARKER
                          + "</head><body>" + "x" * 200000 + "</body></html>")
        body_only = self.write(os.path.join(d, "b.html"),
                               "<html><head></head><body>" + reports.HTML_ENGINE_MARKER
                               + "</body></html>")
        self.assertTrue(reports.is_our_report(good, "html"))
        self.assertFalse(reports.is_our_report(body_only, "html"))

    def test_marker_not_first_key_is_not_ours(self):
        d = self.mkdtemp()
        cases = ['{"issues": [], "generatedBy": "lazaret-cli-1"}',
                 '{"x": "{\\"generatedBy\\": \\"lazaret-cli-1\\""}',
                 '["generatedBy", "lazaret-cli-1"]',
                 '{"generatedBy": "lazaret-cli-2"}',
                 "[" * 120000]
        for i, text in enumerate(cases):
            with self.subTest(text=text[:40]):
                path = self.write(os.path.join(d, f"c{i}.json"), text)
                self.assertFalse(reports.is_our_report(path, "json"))

    def test_marker_prefix_tolerates_whitespace_and_bom(self):
        d = self.mkdtemp()
        path = self.write(os.path.join(d, "w.json"),
                          '﻿ \n{ \n\t"generatedBy" :\n "lazaret-cli-1" , "issues": []}')
        self.assertTrue(reports.is_our_report(path, "json"))

    def test_rescan_over_large_report_succeeds(self):
        """The reviewer's repro: a plain re-scan over a big existing report
        exited 3 ("refusing to overwrite")."""
        root = self.mkdtemp()
        self.write(os.path.join(root, "a.py"), EVIL_PY)
        self.write(os.path.join(root, reports.JSON_REPORT_NAME),
                   reports.json_renderer(_big_result()))
        p = run_cli([root, "--no-html", "-q"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("refusing to overwrite", p.stderr)

    def test_large_genuine_baseline_outside_root_is_trusted(self):
        root, out = self.mkdtemp(), self.mkdtemp()
        self.write(os.path.join(root, "a.py"), EVIL_PY)
        base = os.path.join(out, "base.json")
        p1 = run_cli([root, "--no-html", "--json", base, "-q"])
        self.assertEqual(p1.returncode, 0, p1.stderr)
        # pad the genuine report past the old 64 KiB parse window
        doc = load_json(base)
        doc["padding"] = "x" * (3 * reports.MARKER_READ_BYTES)
        with open(base, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc, indent=2))
        p2 = run_cli([root, "--no-html", "--no-json", "--baseline", base])
        self.assertIn("New issues vs baseline: 0", p2.stdout)
        self.assertNotIn("untrusted", p2.stderr)


# ---------------------------------------------------------------------------
# 2. baseline trust
# ---------------------------------------------------------------------------
FORGED = ('{"generatedBy": "lazaret-cli-1", "issues": ['
          '{"rule": "S-OSCMD-PY", "file": "evil.py", "line": 3, "snipStart": 3,'
          ' "snippet": ["    os.system(\\"ls \\" + x)"]},'
          '{"rule": "S-EVAL-PY", "file": "evil.py", "line": 4, "snipStart": 4,'
          ' "snippet": ["    eval(x)"]}]}')


class BaselineTrustCLI(TempDirs):
    def setUp(self):
        self.root = self.mkdtemp()
        self.write(os.path.join(self.root, "evil.py"), EVIL_PY)

    def test_forged_in_tree_baseline_is_untrusted(self):
        """Reviewer repro: a hand-written baseline with the public marker
        printed "New issues vs baseline: 0"."""
        base = self.write(os.path.join(self.root, "prev-report.json"), FORGED)
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base])
        self.assertNotIn("New issues vs baseline: 0", p.stdout)
        self.assertIn("inside the scanned tree", p.stderr)
        self.assertIn("RUNNER_TEMP", p.stderr)
        self.assertIn(reports.BASELINE_KEY_ENV, p.stderr)

    def test_genuine_in_tree_baseline_without_key_is_untrusted(self):
        base = os.path.join(self.root, "base.json")
        run_cli([self.root, "--no-html", "--json", base, "-q"])
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base])
        self.assertIn("inside the scanned tree", p.stderr)
        self.assertNotIn("New issues vs baseline: 0", p.stdout)

    def test_outside_tree_baseline_without_key_is_trusted(self):
        base = os.path.join(self.mkdtemp(), "base.json")
        run_cli([self.root, "--no-html", "--json", base, "-q"])
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base])
        self.assertIn("New issues vs baseline: 0", p.stdout)
        self.assertEqual(p.stderr, "")

    def test_signed_in_tree_baseline_is_trusted(self):
        base = os.path.join(self.root, "base.json")
        run_cli([self.root, "--no-html", "--json", base, "-q"], key="k1")
        doc = load_json(base)
        self.assertEqual(list(doc)[:2], [reports.ENGINE_MARKER, reports.SIGNATURE_FIELD])
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base], key="k1")
        self.assertIn("New issues vs baseline: 0", p.stdout)
        self.assertEqual(p.stderr, "")

    def test_forged_baseline_with_key_is_untrusted(self):
        base = self.write(os.path.join(self.mkdtemp(), "forged.json"), FORGED)
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base], key="k1")
        self.assertIn("no baseline signature", p.stderr)
        self.assertNotIn("New issues vs baseline: 0", p.stdout)

    def test_wrong_key_or_tampering_is_untrusted(self):
        base = os.path.join(self.root, "base.json")
        run_cli([self.root, "--no-html", "--json", base, "-q"], key="k1")
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base], key="k2")
        self.assertIn("does not verify", p.stderr)
        # tamper: same key, but an extra (attacker-added) fingerprint
        doc = load_json(base)
        doc["issues"].append(dict(doc["issues"][0], rule="S-FAKE"))
        with open(base, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        p = run_cli([self.root, "--no-html", "--no-json", "--baseline", base], key="k1")
        self.assertIn("does not verify", p.stderr)
        self.assertNotIn("New issues vs baseline: 0", p.stdout)


class BaselineTrustUnit(TempDirs):
    def res(self):
        return {"issues": [dict(_issue(1)), dict(_issue(2))]}

    def test_scan_root_argument_marks_in_tree_untrusted(self):
        root = self.mkdtemp()
        base = self.write(os.path.join(root, "sub", "b.json"),
                          reports.json_renderer(self.res()))
        old = os.environ.pop(reports.BASELINE_KEY_ENV, None)
        try:
            res = self.res()
            with contextlib.redirect_stderr(io.StringIO()) as err:
                lazaret.apply_baseline(res, base, scan_root=root)
            self.assertIn("inside the scanned tree", err.getvalue())
            self.assertTrue(res["baselineUntrusted"])
            res = self.res()
            lazaret.apply_baseline(res, base)          # no root: marker check
            self.assertEqual(res["newIssues"], 0)
        finally:
            if old is not None:
                os.environ[reports.BASELINE_KEY_ENV] = old

    def test_signature_is_order_and_separator_independent(self):
        a = [_issue(1, "app/views/x.py"), _issue(2, "app/b.py")]
        b = [_issue(2, "app\\b.py"), _issue(1, "app\\views\\x.py"), _issue(1, "app/views/x.py")]
        fa = [reports.fingerprint(i) for i in a]
        fb = [reports.fingerprint(i) for i in b]
        self.assertEqual(reports.sign_fingerprints(fa, b"k"), reports.sign_fingerprints(fb, b"k"))
        self.assertNotEqual(reports.sign_fingerprints(fa, b"k"), reports.sign_fingerprints(fa, b"k2"))

    def test_core_fingerprint_is_the_shared_one(self):
        self.assertEqual(lazaret.fingerprint(_issue(3)), reports.fingerprint(_issue(3)))

    def test_verify_signature_rejects_bad_shapes(self):
        for doc in ([], {"issues": []}, {reports.SIGNATURE_FIELD: "x"},
                    {reports.SIGNATURE_FIELD: {"alg": "MD5", "value": "00"}}):
            ok, why = reports.verify_signature(doc, b"k")
            self.assertFalse(ok)
            self.assertTrue(why)


# ---------------------------------------------------------------------------
# 4. report permissions survive a re-scan
# ---------------------------------------------------------------------------
@_support.skip_on_windows("POSIX permission bits")
class ReportMode(TempDirs):
    def test_existing_mode_is_preserved(self):
        d = self.mkdtemp()
        path = os.path.join(d, "r.json")
        reports.write_report(path, lambda: reports.json_renderer(_big_result(2)), "json")
        os.chmod(path, 0o600)
        reports.write_report(path, lambda: reports.json_renderer(_big_result(3)), "json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        os.chmod(path, 0o640)
        reports.write_report(path, lambda: reports.json_renderer(_big_result(3)), "json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o640)

    def test_new_file_gets_default_mode(self):
        d = self.mkdtemp()
        path = os.path.join(d, "n.json")
        reports.write_report(path, lambda: reports.json_renderer(_big_result(1)), "json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o666 & ~reports._umask())

    def test_cli_rescan_keeps_0600(self):
        """Reviewer repro (perm/): 0600 report came back 0644 after a re-scan."""
        root = self.mkdtemp()
        self.write(os.path.join(root, "a.py"), "x = 1\n")
        p = run_cli([root, "--no-html", "-q"])
        self.assertEqual(p.returncode, 0, p.stderr)
        rep = os.path.join(root, reports.JSON_REPORT_NAME)
        os.chmod(rep, 0o600)
        p = run_cli([root, "--no-html", "-q"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(rep).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
