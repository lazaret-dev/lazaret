#!/usr/bin/env python3
"""Unit tests — artifact hygiene (card 12c56422; audit L1, G17, G20, G21, L5).

L1  Secrets redacted in EVERY sink (JSON/HTML/SARIF/DB), default-on,
    --no-redact-secrets opt-out; context lines of any rule's snippet swept.
G17 Baselines are untrusted unless they carry this engine's provenance
    marker; /dev/* report paths refused; special files refused before open
    (no FIFO hang).
G20 SQLite Store: WAL + busy_timeout, race-free add_package, atomic
    single-statement save_scan upsert.
G21 The shipped bundle contains no prior-run state/pycache/AppleDouble/DB.
L5  mcp-config.json points LAZARET_DB at an absolute path.
"""
from __future__ import annotations

import json
import os

from tests import _support  # noqa: E402
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

CLI = _support.CLI
PY = sys.executable or "python3"

from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.scanner import reports as lazaret_report  # noqa: E402
from lazaret.registry import repo as lazaret_repo  # noqa: E402

SECRET_SRC = ("import os\n"
              "os.system(cmd)\n"
              "password = \"hunter2secr3t\"\n"
              "aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n")


def write_project(tmp, name="proj"):
    root = os.path.join(tmp, name)
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, "secrets.py"), "w") as fh:
        fh.write(SECRET_SRC)
    return root


def run_cli(args, timeout=120, env=None):
    return subprocess.run([PY, CLI, *args], capture_output=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=env)


# ---------------------------------------------------------------------------
# L1 — redaction at every sink
# ---------------------------------------------------------------------------
class TestSecretRedaction(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-hyg-")
        self.root = write_project(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mk_issue_redacts_flagged_line(self):
        rule = {"id": "S-SECRET", "name": "n", "type": "VULN", "sev": "BLOCKER",
                "msg": "m", "why": "w", "fix": "f", "ref": "r"}
        lines = SECRET_SRC.splitlines()
        issue = lazaret.mk_issue(rule, "secrets.py", 3, lines)
        flagged = issue["snippet"][issue["line"] - issue["snipStart"]]
        self.assertIn("[redacted: secret rule S-SECRET]", flagged)
        self.assertNotIn("hunter2secr3t", flagged)

    def test_mk_issue_opt_out(self):
        old = lazaret.REDACT_SECRETS
        lazaret.REDACT_SECRETS = False
        try:
            rule = {"id": "S-SECRET", "name": "n", "type": "VULN",
                    "sev": "BLOCKER", "msg": "m", "why": "w", "fix": "f",
                    "ref": "r"}
            issue = lazaret.mk_issue(rule, "secrets.py", 3,
                                       SECRET_SRC.splitlines())
            self.assertIn("hunter2secr3t",
                          issue["snippet"][issue["line"] - issue["snipStart"]])
        finally:
            lazaret.REDACT_SECRETS = old

    def test_scan_file_context_lines_scrubbed(self):
        issues = lazaret.scan_file("secrets.py", SECRET_SRC, "py")
        for i in issues:
            for line in i["snippet"]:
                self.assertNotIn("hunter2secr3t", line, i["rule"])
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", line, i["rule"])
        self.assertTrue(any(i["rule"] == "S-SECRET" for i in issues))
        self.assertTrue(any(i["rule"] == "S-TOKEN" for i in issues))

    def test_redact_result_sweeps_foreign_snippets(self):
        # an issue that BYPASSED mk_issue (e.g. hand-built) still gets swept
        res = {"issues": [{"rule": "S-OSCMD-PY", "line": 3, "snipStart": 1,
                           "snippet": ["x = 1", "password = \"hunter2secr3t\"",
                                       "aws_key = \"AKIAIOSFODNN7EXAMPLE\""]}]}
        lazaret.redact_result(res)
        joined = "\n".join(res["issues"][0]["snippet"])
        self.assertNotIn("hunter2secr3t", joined)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", joined)

    def test_cli_json_html_sarif_clean_by_default(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        # --ci: the documented exit contract — exit 1 ONLY with --ci when the
        # quality gate fails (README: "0 scan ok (gate passed, or no --ci)");
        # without it a failed gate still exits 0 after writing reports.
        p = run_cli([self.root, "--no-html", "--ci", "--json",
                     os.path.join(out, "r.json"), "--sarif",
                     os.path.join(out, "r.sarif")])
        self.assertEqual(p.returncode, 1, p.stderr[:400])  # gate fails: secrets
        jtxt = open(os.path.join(out, "r.json")).read()
        self.assertNotIn("hunter2secr3t", jtxt)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", jtxt)
        self.assertIn("[redacted: secret rule", jtxt)
        p2 = run_cli([self.root, "--no-json", "--html",
                      os.path.join(out, "r.html")])
        html = open(os.path.join(out, "r.html")).read()
        self.assertNotIn("hunter2secr3t", html)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", html)

    def test_cli_opt_out_flag(self):
        out = os.path.join(self.tmp, "out2")
        os.makedirs(out)
        p = run_cli([self.root, "--no-redact-secrets", "--no-html", "--json",
                     os.path.join(out, "r.json")])
        jtxt = open(os.path.join(out, "r.json")).read()
        self.assertIn("hunter2secr3t", jtxt)

    def test_baseline_fingerprint_stable_across_scans(self):
        # same line scanned twice redacts to the same placeholder → a
        # same-engine baseline still matches (newIssues == 0)
        # The baseline lives INSIDE the scanned tree (self.tmp/out3), which is
        # only trusted when reports are signed: run both scans with a
        # LAZARET_BASELINE_KEY (review finding 2 — unsigned in-tree baselines
        # are now untrusted; test updated accordingly).
        out = os.path.join(self.tmp, "out3")
        os.makedirs(out)
        env = dict(os.environ, LAZARET_BASELINE_KEY="test-key-not-secret")
        r1 = run_cli([self.tmp, "--no-html", "--json",
                      os.path.join(out, "base.json"), "-q"], env=env)
        r2 = run_cli([self.tmp, "--no-html", "--no-json", "--baseline",
                      os.path.join(out, "base.json")], env=env)
        self.assertIn("New issues vs baseline: 0", r2.stdout)


# ---------------------------------------------------------------------------
# G17 — baseline trust, special-file report paths
# ---------------------------------------------------------------------------
class TestBaselineTrust(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-hyg-base-")
        self.root = write_project(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan_json(self, name):
        out = os.path.join(self.tmp, name)
        run_cli([self.root, "--no-html", "--json", out, "-q"])
        return out

    def test_forged_baseline_is_untrusted(self):
        base = self.scan_json("engine.json")
        data = json.load(open(base))
        # attacker forges the same shape WITHOUT the engine marker
        forged = os.path.join(self.tmp, "forged.json")
        with open(forged, "w") as fh:
            json.dump({"issues": data["issues"]}, fh)
        os.utime(forged, (1, 1))
        res = {"issues": [dict(data["issues"][0])]}
        lazaret.apply_baseline(res, forged)
        self.assertTrue(res["baselineUntrusted"])
        self.assertEqual(res["newIssues"], len(res["issues"]))
        self.assertTrue(all(i["new"] for i in res["issues"]))

    def test_engine_baseline_is_trusted(self):
        base = self.scan_json("engine.json")
        res = {"issues": [dict(i) for i in json.load(open(base))["issues"]]}
        lazaret.apply_baseline(res, base)
        self.assertNotIn("baselineUntrusted", res)
        self.assertEqual(res["newIssues"], 0)

    def test_dev_paths_refused(self):
        for dev in ("/dev/null", "/dev/stdout"):
            with self.assertRaises(lazaret_report.ReportPathError) as cm:
                lazaret_report._validate_path(dev, "json", strict=True)
            self.assertIn("device", str(cm.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFOs on this platform")
    def test_fifo_report_path_refused_without_open(self):
        fifo = os.path.join(self.tmp, "lazaret-report.json")
        os.mkfifo(fifo)
        # is_our_report must answer False via lstat — never open() the FIFO
        self.assertFalse(lazaret_report.is_our_report(fifo, "json"))
        with self.assertRaises(lazaret_report.ReportPathError):
            lazaret_report._validate_path(fifo, "json", strict=True)
        # the CLI fails fast instead of hanging on the planted FIFO
        p = run_cli([self.root, "--no-html", "--json", fifo, "-q"], timeout=30)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 3)


# ---------------------------------------------------------------------------
# G20 — SQLite store: WAL, races, atomic upsert
# ---------------------------------------------------------------------------
class TestStoreHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-hyg-db-")
        self.db = os.path.join(self.tmp, "reg.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def RESULT(self):
        return {"version": "1.0.0", "profile": "supply-chain",
                "scannedAt": "2026-01-01T00:00:00", "filesScanned": 1,
                "archiveBytes": 10,
                "sevCounts": {"BLOCKER": 1, "CRITICAL": 0, "MAJOR": 0},
                "supplyChain": 1, "issues": [], "verdict": "SUSPICIOUS"}

    def test_wal_and_busy_timeout(self):
        s = lazaret_repo.Store(self.db)
        self.assertEqual(
            s.conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        self.assertEqual(
            s.conn.execute("PRAGMA busy_timeout").fetchone()[0], 30000)

    def test_concurrent_add_package_no_unique_error(self):
        lazaret_repo.Store(self.db).add_package("npm", "warm")  # schema init
        results, errors = [], []

        def worker():
            try:
                st = lazaret_repo.Store(self.db)
                results.append(st.add_package("npm", "same-pkg"))
            except Exception as exc:              # pragma: no cover
                errors.append(f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(len({r[0] for r in results}), 1)  # one id, not six

    def test_save_scan_is_atomic_upsert(self):
        s = lazaret_repo.Store(self.db)
        pid, _ = s.add_package("npm", "pkg")
        s.save_scan(pid, self.RESULT())
        s.save_scan(pid, self.RESULT())          # crash-window regression:
        n = s.conn.execute(                      # no DELETE+INSERT gap
            "SELECT COUNT(*) FROM scans WHERE package_id=?", (pid,)).fetchone()[0]
        self.assertEqual(n, 1)
        res2 = self.RESULT()
        res2["verdict"] = "OK"
        s.save_scan(pid, res2)
        row = s.conn.execute(
            "SELECT verdict FROM scans WHERE package_id=?", (pid,)).fetchone()
        self.assertEqual(row[0], "OK")
        self.assertTrue(s.has_scan(pid, "1.0.0", "supply-chain"))


# ---------------------------------------------------------------------------
# G21 + L5 — clean bundle, absolute DB path in the MCP template
# ---------------------------------------------------------------------------
class TestBundleHygiene(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-hyg-bundle-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self, *extra):
        out = os.path.join(self.tmp, "b.tgz")
        p = subprocess.run([PY, _support.MAKE_BUNDLE, out,
                            *extra], capture_output=True, encoding="utf-8", errors="replace",
                           timeout=120, cwd=HERE)
        return out, p

    def test_is_junk_filters(self):
        make_bundle = _support.load_script(_support.MAKE_BUNDLE, "make_bundle")
        for rel in ("x/__pycache__/lazaret.cpython-310.pyc", "a.pyc",
                    "._lazaret.py", ".DS_Store", "lazaret-registry.db",
                    "reg.db-wal", "lazaret-report.json", "r-report.html",
                    "out.sarif", "p/node_modules/evil/index.js", "base.json"):
            self.assertTrue(make_bundle.is_junk(rel), rel)
        for rel in ("lazaret.py", "README.md", "test_sca.py",
                    "testproj/app.py", "schema.sql", "test.js",
                    "examples/.env.example"):
            self.assertFalse(make_bundle.is_junk(rel), rel)
        # secrets files and build outputs never ship
        self.assertFalse(make_bundle.is_junk("python/tests/fixtures/detection_gaps/dist/bundle.py"))
        self.assertTrue(make_bundle.is_junk("build/typosquats/lazarat/js/index.js"))
        for rel in (".env", "python/.env.local", "python/dist/lazaret-0.0.1.tar.gz",
                    "python/src/lazaret.egg-info/PKG-INFO", "python/.venv/bin/python"):
            self.assertTrue(make_bundle.is_junk(rel), rel)

    def test_bundle_has_no_junk_and_carries_engine(self):
        out, p = self.build()
        self.assertEqual(p.returncode, 0, p.stderr[:400])
        with tarfile.open(out) as tf:
            names = tf.getnames()
        junk = [n for n in names if "__pycache__" in n or n.endswith(
            (".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".sarif",
             "-report.json", "-report.html")) or "/._" in n
            or "/node_modules/" in n or n.endswith("/base.json")]
        self.assertEqual(junk, [])
        for must in ("lazaret/python/src/lazaret/scanner/core.py", "lazaret/README.md",
                     "lazaret/scripts/make_bundle.py", "lazaret/python/pyproject.toml",
                     "lazaret/python/tests/scanner/test_sca.py"):
            self.assertIn(must, names)
        # every fixture survives, including ones in directories named like
        # build output (detection_gaps/dist/ tests the scanner's dist-skipping)
        fixtures = []
        for root, dirs, files in os.walk(_support.FIXTURES):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            fixtures += [os.path.relpath(os.path.join(root, f), _support.REPO_ROOT).replace(os.sep, "/")
                         for f in files]
        self.assertIn("python/tests/fixtures/detection_gaps/dist/bundle.py", fixtures)
        self.assertEqual([f for f in fixtures if f"lazaret/{f}" not in names], [])
        secrets = [n for n in names if os.path.basename(n) == ".env"
                   or (os.path.basename(n).startswith(".env.") and not n.endswith(".example"))]
        self.assertEqual(secrets, [])

    def test_bundle_members_have_sanitized_metadata(self):
        out, _ = self.build()
        with tarfile.open(out) as tf:
            for m in tf.getmembers():
                self.assertEqual((m.uid, m.gid, m.uname, m.gname), (0, 0, "", ""))

    def test_dogfood_scanning_the_bundle_itself(self):
        # scan-the-archive-with-itself: unpack and scan the product sources
        out, p = self.build()
        self.assertEqual(p.returncode, 0, p.stderr[:400])
        root = os.path.join(self.tmp, "unpack")
        with tarfile.open(out) as tf:
            tf.extractall(root)
        scan = subprocess.run(
            [PY, CLI, os.path.join(root, "lazaret", "python", "src"),
             "--no-html", "--no-json", "-q"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=300)
        self.assertNotIn("Traceback", scan.stderr)
        # product sources must carry no hardcoded-secret findings of their own
        self.assertNotIn("S-SECRET", scan.stdout)
        self.assertNotIn("S-TOKEN", scan.stdout)

    def test_mcp_config_uses_absolute_db_path(self):
        cfg = json.load(open(os.path.join(_support.EXAMPLES, "mcp-config.json")))
        env = cfg["mcpServers"]["lazaret"]["env"]
        self.assertEqual(env["LAZARET_DB"],
                         "/ABSOLUTE/PATH/TO/lazaret-registry.db")


if __name__ == "__main__":
    unittest.main()
