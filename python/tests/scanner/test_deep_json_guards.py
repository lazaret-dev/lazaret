#!/usr/bin/env python3
"""Unit tests — hostile-repo JSON hardening beyond scan_manifest
(card 1149e3e5; scope split from 48033f94 "hostile repo crashes the audit").

48033f94 guarded the json.loads-RecursionError primitive in
lazaret.scan_manifest (CLI-side, package.json-shaped). This card audits
EVERY OTHER json.loads/json.load consumer fed from scanned-repo content.
Each test drives one call site with the same ~60k-deep JSON document
(~60KB of '['), asserting: no crash, a warning or structured error, and
remaining work still reported.

Call sites covered (production sites audited; already-guarded ones are
regression-tested so they cannot silently regress):
  1. lazaret_mcp.py main() JSON-RPC frame parsing — hostile frame now
     yields a -32700 parse-error reply and the server KEEPS SERVING later
     frames (was: uncaught RecursionError → process death). Non-object
     frames ([1,2]) no longer AttributeError-kill the loop either.
  2. lazaret.py main() taint-config json.load — auto-loaded
     .lazaret-taint.json (scanned-repo content!) and --taint-config:
     RecursionError is not a JSONDecodeError, so it escaped the except and
     crashed the CLI mid-scan (verified pre-fix: rc=1 + Traceback). Now:
     warn-and-scan.
  3. lazaret_flow.load_config_quietly — same RecursionError escape in the
     flow engine's own loader; now warn-and-skip via warnings_out.
  4. lazaret.py apply_baseline json.load — deep baseline (48033f94 added
     RecursionError to the tuple; regression-tested here).
  5. lazaret_repo.py Store.report — stored scan issues blob
     (user-supplied content at write time) round-trips through json.loads:
     deep blob now degrades to a CRITICAL SC-STORED-DEPTH issue with
     verdict/metrics intact instead of a traceback.
  6. lazaret_repo.py http_json — registry metadata/feed JSON: deep-nest
     now raises FetchError ("too deeply nested") like any fetch failure,
     so scan-all sweeps and discovery warn-and-skip instead of dying.
  7. Registry scan-all sweep with a hostile package among clean ones: the
     sweep completes, every package gets a verdict, findings from the
     clean sibling are still reported (remaining-work acceptance).

Run:  python3 lazaret/test_deep_json_guards.py [unittest-args]
"""
from __future__ import annotations

import io
import json
import os

from tests import _support  # noqa: E402
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
CLI = _support.CLI
MCP = _support.MCP
PY = sys.executable or "python3"

sys.path.insert(0, HERE)  # the lazaret/ dir itself

from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.registry import repo as lazaret_repo  # noqa: E402

#: The hostile document: 120k '[' bytes → 60k-nesting parse, ~60KB on disk.
DEEP = "[" * 120000

APPEAL_PY = "import os\nq = request.args['q']\nos.system(q)\n"
REAL_FINDING_JS = "eval('hostile input')\n"


def build_tgz(members):
    """members: list of (relpath, bytes) → tgz bytes (deterministic)."""
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, data in members:
            if isinstance(data, str):
                data = data.encode("utf-8")
            ti = tarfile.TarInfo(rel)
            ti.size = len(data)
            ti.mtime = 1577836800
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = ""
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def run_registry_cli(args, db, tarballs, timeout=300):
    """Run lazaret_repo.py main() end-to-end in a child process whose
    network seam serves `tarballs` {(name, version): tgz_bytes} — the
    _registry_bootstrap.py harness from test_crash_guards_registry.py."""
    reg = _support.BOOTSTRAP
    env = dict(os.environ)
    env["CG_FAKE_REGISTRY"] = json.dumps({
        "tarballs": {f"{n}@{v}": tgz.hex() for (n, v), tgz in tarballs.items()},
    })
    env["LAZARET_DB"] = db
    return subprocess.run([PY, reg, "lazaret_repo.py"] + args,
                          capture_output=True, encoding="utf-8", errors="replace", cwd=HERE, env=env,
                          timeout=timeout)


# ---------------------------------------------------------------------------
# 1. MCP server — JSON-RPC frame parsing (lazaret_mcp.py:main)
# ---------------------------------------------------------------------------
class McpDeepFrameTests(unittest.TestCase):
    """A deep-nested frame must produce a -32700 error reply AND the server
    must keep serving every subsequent frame (was: process death)."""

    def _serve(self, lines, tmp):
        env = dict(os.environ)
        env["LAZARET_DB"] = os.path.join(tmp, "reg.db")
        p = subprocess.run([PY, MCP], input="\n".join(lines) + "\n",
                           capture_output=True, encoding="utf-8", errors="replace", timeout=120, env=env)
        return p

    def test_deep_frame_error_reply_and_server_survives(self):
        with tempfile.TemporaryDirectory(prefix="cg-mcp-") as tmp:
            p = self._serve([DEEP,
                             '{"jsonrpc":"2.0","id":1,"method":"ping"}',
                             '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'],
                            tmp)
            self.assertNotIn("Traceback", p.stderr)
            self.assertEqual(p.returncode, 0, p.stderr[-500:])
            frames = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
            # frame 1: structured parse error for the hostile frame
            self.assertEqual(frames[0]["id"], None)
            self.assertEqual(frames[0]["error"]["code"], -32700)
            self.assertIn("depth", frames[0]["error"]["message"])
            # server stayed ALIVE: the later frames got real replies
            self.assertEqual(frames[1]["id"], 1)
            self.assertIn("result", frames[1])
            self.assertEqual(frames[2]["id"], 2)
            names = [t["name"] for t in frames[2]["result"]["tools"]]
            self.assertIn("scan_directory", names)

    def test_malformed_frame_answered_and_server_survives(self):
        # a frame that is not JSON now gets -32700 with id null (JSON-RPC 2.0;
        # review finding 18c: the old silent drop left clients waiting)
        with tempfile.TemporaryDirectory(prefix="cg-mcp-") as tmp:
            p = self._serve(["{not json at all",
                             '{"jsonrpc":"2.0","id":9,"method":"ping"}'], tmp)
            self.assertNotIn("Traceback", p.stderr)
            frames = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
            self.assertEqual([f.get("id") for f in frames], [None, 9])
            self.assertEqual(frames[0]["error"]["code"], -32700)
            self.assertIn("result", frames[1])

    def test_non_object_frame_does_not_kill_loop(self):
        # parses fine, but is not a dict: req.get() used to AttributeError.
        # Card 1149e3e5's interim guard dropped it silently; card 418d4c93
        # upgraded that to the JSON-RPC-mandated -32600 Invalid Request reply
        # (id null — the id is unreadable in a non-object frame).
        with tempfile.TemporaryDirectory(prefix="cg-mcp-") as tmp:
            p = self._serve(["[1,2]",
                             '{"jsonrpc":"2.0","id":5,"method":"ping"}'], tmp)
            self.assertNotIn("Traceback", p.stderr)
            frames = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
            self.assertEqual([f.get("id") for f in frames], [None, 5])
            self.assertEqual(frames[0]["error"]["code"], -32600)
            self.assertIn("result", frames[1])

    def test_normal_frames_unaffected(self):
        # vacuity guard: identical traffic without the hostile frame behaves
        # exactly as before (one reply per request, no error frames)
        with tempfile.TemporaryDirectory(prefix="cg-mcp-") as tmp:
            p = self._serve(['{"jsonrpc":"2.0","id":1,"method":"ping"}',
                             '{"jsonrpc":"2.0","id":2,"method":"ping"}'], tmp)
            frames = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
            self.assertEqual([f.get("id") for f in frames], [1, 2])
            self.assertTrue(all("result" in f for f in frames))


# ---------------------------------------------------------------------------
# 2+4. CLI consumers — taint-config load + baseline load
# ---------------------------------------------------------------------------
class CliConfigBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-cli-")
        with open(os.path.join(self.tmp, "a.py"), "w") as fh:
            fh.write("x = 1\n")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *extra):
        return subprocess.run(
            [PY, CLI, self.tmp, "--no-html", "--no-json", *extra],
            capture_output=True, encoding="utf-8", errors="replace", timeout=120)

    def test_autoloaded_deep_taint_config_warns_and_scans(self):
        # scanned-repo content: hostile repo plants .lazaret-taint.json
        with open(os.path.join(self.tmp, ".lazaret-taint.json"), "w") as fh:
            fh.write(DEEP)
        p = self._cli("--trust-repo-config")  # repo config is opt-in (review finding 5)
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("Traceback", p.stdout)
        self.assertEqual(p.returncode, 0, (p.returncode, p.stderr[-500:]))
        self.assertIn("warning: could not load taint config", p.stderr)
        self.assertIn("Quality gate", p.stdout)  # report still produced

    def test_explicit_deep_taint_config_exits_4(self):
        # An explicit --taint-config is what CI asked for: failing to load it
        # must not quietly scan without its rules (final review item 2; this
        # test used to expect warn-and-scan, exit 0). Still no traceback.
        cfg = os.path.join(self.tmp, "deep.json")
        with open(cfg, "w") as fh:
            fh.write(DEEP)
        p = self._cli("--taint-config", cfg)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 4, p.stderr[-500:])
        self.assertIn("error: could not load taint config", p.stderr)
        self.assertNotIn("Quality gate", p.stdout)

    def test_deep_taint_config_does_not_hide_sibling_findings(self):
        with open(os.path.join(self.tmp, ".lazaret-taint.json"), "w") as fh:
            fh.write(DEEP)
        with open(os.path.join(self.tmp, "a.py"), "w") as fh:
            fh.write(APPEAL_PY)
        p = self._cli("--trust-repo-config")  # repo config is opt-in (review finding 5)
        self.assertEqual(p.returncode, 0)
        # remaining work still reported: sibling findings survive
        self.assertIn("S-OSCMD-PY", p.stdout)

    def test_deep_baseline_warns_and_ignored(self):
        base = os.path.join(self.tmp, "base.json")
        with open(base, "w") as fh:
            fh.write(DEEP)
        p = self._cli("--baseline", base)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0)
        # warn-and-ignore, whichever guard fires first: a deep-nest baseline
        # is now caught EARLIER by is_our_report (card f22ce3c5: wrong shape /
        # no engine marker → "not a report produced by this engine") before
        # the reader's own RecursionError path ("could not read baseline").
        # Either way the baseline is ignored and the scan completes.
        self.assertTrue(
            "warning: baseline" in p.stderr
            and ("could not read baseline" in p.stderr
                 or "is not a report produced" in p.stderr),
            p.stderr[-400:])

    def test_valid_taint_config_still_loads(self):
        # vacuity guard: a sane config still applies (no over-blocking)
        with open(os.path.join(self.tmp, ".lazaret-taint.json"), "w") as fh:
            fh.write('{"python":{"sources":["\\\\brequest\\\\.args\\\\b"]}}')
        with open(os.path.join(self.tmp, "a.py"), "w") as fh:
            fh.write(APPEAL_PY)
        p = self._cli("--trust-repo-config")  # repo config is opt-in (review finding 5)
        self.assertEqual(p.returncode, 0)
        self.assertIn("Loaded taint config", p.stdout)
        self.assertIn("T-CMD", p.stdout)  # custom source fired


# ---------------------------------------------------------------------------
# 3. Flow engine's own config loader
# ---------------------------------------------------------------------------
class FlowLoadConfigTests(unittest.TestCase):
    def test_deep_config_warns_and_returns_false(self):
        from lazaret.scanner import flow as lazaret_flow
        path = os.path.join(tempfile.mkdtemp(prefix="cg-flow-"), "cfg.json")
        with open(path, "w") as fh:
            fh.write(DEEP)
        warns = []
        ok = lazaret_flow.load_config_quietly(path, warns)
        self.assertFalse(ok)
        self.assertEqual(len(warns), 1)
        self.assertIn("could not load taint config", warns[0])
        # str() of the RecursionError: 3.14 names the failure mode
        # ("Stack overflow"); older versions say "maximum recursion depth".
        self.assertRegex(warns[0], r"Stack overflow|maximum recursion depth")

    def test_valid_config_still_applies(self):
        from lazaret.scanner import flow as lazaret_flow
        state = _FlowState()
        self.addCleanup(state.restore)
        path = os.path.join(tempfile.mkdtemp(prefix="cg-flow-"), "cfg.json")
        with open(path, "w") as fh:
            fh.write('{"python":{"sources":["\\\\brequest\\\\.args\\\\b"]}}')
        warns = []
        ok = lazaret_flow.load_config_quietly(path, warns)
        self.assertTrue(ok)
        self.assertEqual(warns, [])


class _FlowState:
    """Snapshot/restore flow engine taint tables (as in other suites)."""

    def __init__(self):
        from lazaret.scanner import flow as f
        self.f = f
        self.saved = (list(f._PY_SOURCE_EXTRA), list(f._EXTRA_PY_SINKS),
                      set(f.FULL_SANITIZERS_PY), dict(f._EXTRA_PARTIAL_PY),
                      list(f._JS_SINKS), dict(f._JS_PARTIAL_SAN))

    def restore(self):
        f = self.f
        (pse, eps, fsp, epp, jsinks, jpart) = self.saved
        f._PY_SOURCE_EXTRA[:] = pse
        f._EXTRA_PY_SINKS[:] = eps
        f.FULL_SANITIZERS_PY.clear()
        f.FULL_SANITIZERS_PY.update(fsp)
        f._EXTRA_PARTIAL_PY.clear()
        f._EXTRA_PARTIAL_PY.update(epp)
        f._JS_SINKS[:] = jsinks
        f._JS_PARTIAL_SAN.clear()
        f._JS_PARTIAL_SAN.update(jpart)


# ---------------------------------------------------------------------------
# 5. Store.report — stored scan issues blob round-trip
# ---------------------------------------------------------------------------
class StoreReportDeepBlobTests(unittest.TestCase):
    def _store_with_blob(self, blob):
        db = os.path.join(tempfile.mkdtemp(prefix="cg-store-"), "r.db")
        st = lazaret_repo.Store(db)
        pid, _ = st.add_package("npm", "hostile")
        cur = st.conn.cursor()
        cur.execute(
            "INSERT INTO scans (package_id,version,profile,scanned_at,"
            "engine_version,files_scanned,archive_bytes,blockers,criticals,"
            "majors,supply_chain,issue_count,verdict,issues) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, "1.0.0", "supply-chain", "2026-09-25T00:00:00+00:00", "test",
             3, 100, 0, 1, 0, 1, 1, "SUSPICIOUS", blob))
        st.conn.commit()
        return st

    def test_deep_stored_blob_yields_named_issue_not_crash(self):
        st = self._store_with_blob(DEEP)
        res = st.report("npm", "hostile")   # was: RecursionError traceback
        self.assertIsNotNone(res)
        self.assertEqual(res["verdict"], "SUSPICIOUS")  # intact
        self.assertEqual(len(res["issues"]), 1)
        issue = res["issues"][0]
        self.assertEqual(issue["rule"], "SC-STORED-DEPTH")
        self.assertEqual(issue["sev"], "CRITICAL")
        self.assertIn("RecursionError", issue["msg"])

    def test_valid_stored_blob_still_parses(self):
        good = json.dumps([{"rule": "X", "file": "a.js", "line": 1,
                            "sev": "CRITICAL", "msg": "m"}])
        st = self._store_with_blob(good)
        res = st.report("npm", "hostile")
        self.assertEqual(res["issues"][0]["rule"], "X")

    def test_garbage_stored_blob_also_degrades(self):
        st = self._store_with_blob("}{ not json")
        res = st.report("npm", "hostile")   # JSONDecodeError, also guarded
        self.assertEqual(res["issues"][0]["rule"], "SC-STORED-DEPTH")


# ---------------------------------------------------------------------------
# 6. http_json — registry metadata / discovery feeds
# ---------------------------------------------------------------------------
class HttpJsonDeepTests(unittest.TestCase):
    def setUp(self):
        self._real_fetch = lazaret_repo._fetch
        lazaret_repo._OPENER = _FakeOpener()

    def tearDown(self):
        lazaret_repo._fetch = self._real_fetch

    def _patch_fetch(self, data):
        lazaret_repo._fetch = (
            lambda url, max_bytes=None, timeout=None: data)

    def test_deep_registry_json_is_fetcherror_not_recursionerror(self):
        self._patch_fetch(DEEP.encode("ascii"))
        with self.assertRaises(lazaret_repo.FetchError) as cm:
            lazaret_repo.http_json("https://registry.npmjs.org/x")
        self.assertIn("too deeply nested", str(cm.exception))
        self.assertNotIsInstance(cm.exception, RecursionError)

    def test_invalid_registry_json_still_fetcherror(self):
        self._patch_fetch(b"not json")
        with self.assertRaises(lazaret_repo.FetchError) as cm:
            lazaret_repo.http_json("https://registry.npmjs.org/y")
        self.assertIn("invalid JSON", str(cm.exception))

    def test_valid_registry_json_still_parses(self):
        self._patch_fetch(b'{"dist-tags": {"latest": "1.2.3"}}')
        self.assertEqual(lazaret_repo.http_json("https://registry.npmjs.org/z")
                         ["dist-tags"]["latest"], "1.2.3")


class _FakeOpener:
    """Placeholder opener (network never touched: _fetch is patched)."""

    class _Resp:
        def __init__(self, data):
            self._d = data

        def read(self, n=-1):
            return self._d[:n] if n and n > 0 else self._d

        def close(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def open(self, req, timeout=None):
        return self._Resp(b"{}")


# ---------------------------------------------------------------------------
# 7. Registry scan-all sweep — hostile package among clean ones
# ---------------------------------------------------------------------------
class ScanAllSweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-sweep-")
        self.db = os.path.join(self.tmp, "registry.db")
        self.tarballs = {
            ("hostile", "1.0.0"): build_tgz([
                ("hostile/package.json", DEEP),
                ("hostile/payload.js", REAL_FINDING_JS)]),
            ("clean-pkg", "1.0.0"): build_tgz([
                ("clean-pkg/package.json",
                 '{"name": "clean-pkg", "version": "1.0.0", '
                 '"scripts": {"test": "node test.js"}}'),
                ("clean-pkg/index.js", "var x = 1;\n")]),
        }

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_scan_all_completes_with_hostile_package(self):
        p1 = run_registry_cli(["add", "npm:hostile", "npm:clean-pkg"],
                              self.db, self.tarballs)
        self.assertEqual(p1.returncode, 0, p1.stderr[-500:])
        p2 = run_registry_cli(["scan-all"], self.db, self.tarballs)
        self.assertNotIn("Traceback", p2.stderr)
        self.assertEqual(p2.returncode, 0, p2.stderr[-800:])
        # hostile package: the 48033f94 finding surfaces (SC-MANIFEST-DEPTH),
        # NOT an 'error scanning' suppression line
        self.assertIn("SC-MANIFEST-DEPTH", p2.stdout)
        self.assertNotIn("error scanning npm:hostile", p2.stdout)
        # remaining work still reported: the clean sibling got a verdict
        self.assertIn("npm:clean-pkg", p2.stdout)
        verdicts = self._verdicts()
        self.assertEqual(verdicts.get("hostile"), "SUSPICIOUS")
        self.assertIn(verdicts.get("clean-pkg"), ("OK", "WARN"))

    def _verdicts(self):
        con = sqlite3.connect(self.db)
        try:
            rows = con.execute(
                "SELECT p.name, s.verdict FROM scans s JOIN packages p "
                "ON s.package_id = p.id").fetchall()
            return dict(rows)
        finally:
            con.close()

    def test_report_command_survives_hostile_stored_blob(self):
        # end-to-end for call site 5: scan hostile, then 'report' it —
        # the issues blob round-trips through Store.report
        p1 = run_registry_cli(["add", "npm:hostile"], self.db, self.tarballs)
        p2 = run_registry_cli(["scan", "npm:hostile"], self.db, self.tarballs)
        self.assertEqual(p2.returncode, 0, p2.stderr[-500:])
        p3 = run_registry_cli(["report", "npm:hostile"], self.db, self.tarballs)
        self.assertNotIn("Traceback", p3.stderr)
        self.assertEqual(p3.returncode, 0, p3.stderr[-500:])


if __name__ == "__main__":
    unittest.main(verbosity=2)
