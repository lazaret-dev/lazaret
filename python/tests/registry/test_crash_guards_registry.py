#!/usr/bin/env python3
"""INTEGRATION harness — hostile-repo crash guards in REGISTRY MODE
(card 48033f94, PoC 2 nested package.json → RecursionError).

The CLI-level PoCs (lazaret.py directory scan) are covered by
test_crash_guards.py (11 subprocess runs). This suite covers the registry
scanner (lazaret_repo.py), where the original bug was that a hostile
nested package.json turned the scan into an "error scanning <spec>: <exc>"
outcome: finding suppression — no SUSPICIOUS verdict persisted, findings
lost. The fix routes RecursionError into the SC-MANIFEST-DEPTH finding.

A hostile package.json cannot be published to the real npm/PyPI registry,
so the network seam (resolve_npm/resolve_pypi, http_bytes, verify_digest)
is monkeypatched in a child process via PYTHONSTARTUP-style bootstrap
(_registry_bootstrap.py). The child then runs the real lazaret_repo.py
main() — same argparse, same Store, same DB, same print_scan — with only
the network replaced by a fake registry serving local tarballs. No source
changes are made to lazaret_repo.py.

Run:  cd lazaret && python3 -m unittest test_crash_guards_registry -v
"""
import json
import os

from tests import _support  # noqa: E402
import subprocess
import sys
import sqlite3
import tarfile
import tempfile
import unittest
import io

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

# ---------------------------------------------------------------- fixtures

HOSTILE_NEST = "[" * 120000           # PoC 2: 60KB+ of brackets, 60k+ depth
SCALAR_SCRIPTS = '{"name": "w", "version": "1.0.0", "scripts": 5}'
CLEAN_MANIFEST = ('{"name": "clean-pkg", "version": "1.0.0", '
                  '"scripts": {"test": "node test.js"}}')
BAD_TAINT = '{"python": {"sources": ["("]}}'
REAL_FINDING_JS = "eval('hostile input')\n"


def build_tgz(members):
    """members: list of (relpath, bytes) → tgz bytes (deterministic)."""
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


def sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def run_cli(args, db, tarballs, timeout=300):
    """Run lazaret_repo.py main() end-to-end in a child process whose
    network seam serves `tarballs` {(name, version): tgz_bytes}."""
    reg = _support.BOOTSTRAP
    env = dict(os.environ)
    env["CG_FAKE_REGISTRY"] = json.dumps({
        "tarballs": {f"{n}@{v}": tgz.hex() for (n, v), tgz in tarballs.items()},
    })
    env["LAZARET_DB"] = db
    return subprocess.run(
        [sys.executable, reg, "lazaret_repo.py"] + args,
        capture_output=True, text=True, cwd=HERE, env=env, timeout=timeout)


class RegistryGuardTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cgit-reg-")
        self.db = os.path.join(self.tmp, "registry.db")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------------

    def assertNoTraceback(self, proc, label):
        tb = "Traceback (most recent call last)" in proc.stderr
        self.assertFalse(tb, f"{label}: uncaught traceback in CLI:\n{proc.stderr[-2000:]}")

    def db_verdict(self, eco, name):
        con = sqlite3.connect(self.db)
        try:
            rows = con.execute(
                "SELECT verdict FROM scans s JOIN packages p "
                "ON s.package_id = p.id WHERE p.name = ? ORDER BY s.scanned_at DESC",
                (name,)).fetchall()
            return [r[0] for r in rows]
        finally:
            con.close()

    # -- stages -----------------------------------------------------------

    def test_r1_nested_manifest_suspicious(self):
        """R1: nested package.json → scan completes, SC-MANIFEST-DEPTH
        finding, verdict SUSPICIOUS persisted (was: 'error' + suppression)."""
        tgz = build_tgz([
            ("package/package.json", HOSTILE_NEST),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R1")
        self.assertIn("SUSPICIOUS", proc.stdout, proc.stderr[-500:])
        self.assertIn("SC-MANIFEST-DEPTH", proc.stdout, proc.stdout[-2000:])
        self.assertEqual(self.db_verdict("npm", "hostile-pkg"), ["SUSPICIOUS"])

    def test_r2_hostile_manifest_does_not_suppress_other_findings(self):
        """R2: nested manifest + a real JS finding in the same archive —
        both findings must be reported (no suppression). Uses --full: the
        default supply-chain profile applies SC- rules only by design, so
        non-SC finding survival is asserted in full profile."""
        tgz = build_tgz([
            ("package/package.json", HOSTILE_NEST),
            ("package/evil.js", REAL_FINDING_JS),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg", "--full"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R2")
        self.assertIn("SC-MANIFEST-DEPTH", proc.stdout, proc.stdout[-3000:])
        self.assertIn("S-EVAL-JS", proc.stdout, proc.stdout[-3000:])
        self.assertIn("eval", proc.stdout.lower(), proc.stdout[-2000:])

    def test_r3_scalar_scripts_completes(self):
        """R3: scalar scripts → scan completes, no crash, no depth finding."""
        tgz = build_tgz([
            ("package/package.json", SCALAR_SCRIPTS),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R3")
        self.assertNotIn("SC-MANIFEST-DEPTH", proc.stdout)
        verdicts = self.db_verdict("npm", "hostile-pkg")
        self.assertEqual(len(verdicts), 1, "scan must be persisted")
        self.assertIn(verdicts[0], ("OK", "WARN"))

    def test_r4_clean_package_ok(self):
        """R4: clean manifest + clean file → verdict OK, sanity baseline."""
        tgz = build_tgz([
            ("package/package.json", CLEAN_MANIFEST),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R4")
        self.assertEqual(self.db_verdict("npm", "hostile-pkg"), ["OK"])

    def test_r5_cli_ci_exit_codes(self):
        """R5: `scan --ci` on hostile manifest exits 1 (bad) with the
        SUSPICIOUS verdict — not a crash exit, not silent success."""
        tgz = build_tgz([
            ("package/package.json", HOSTILE_NEST),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg", "--ci"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R5")
        self.assertEqual(proc.returncode, 1, f"stdout tail: {proc.stdout[-500:]}")
        self.assertIn("SC-MANIFEST-DEPTH", proc.stdout)

    def test_r6_bad_taint_member_no_crash(self):
        """R6: hostile .lazaret-taint.json member with bad regex — the
        scan must complete (the CLI-level PoC 1 equivalent in registry
        mode). Note: registry scan_package may not auto-load taint configs
        from the archive; if it does not, the contract is simply no-crash.
        """
        tgz = build_tgz([
            ("package/package.json", CLEAN_MANIFEST),
            ("package/.lazaret-taint.json", BAD_TAINT),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-pkg"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R6")
        verdicts = self.db_verdict("npm", "hostile-pkg")
        self.assertEqual(len(verdicts), 1)

    def test_r7_compound_hostility(self):
        """R7: nested manifest + scalar scripts in different members +
        bad taint member — all tolerated, verdict persisted."""
        tgz = build_tgz([
            ("package/package.json", HOSTILE_NEST),
            ("package/other/package.json", SCALAR_SCRIPTS),
            ("package/.lazaret-taint.json", BAD_TAINT),
            ("package/a.py", b"x=1\n"),
        ])
        proc = run_cli(["scan", "npm:hostile-p3", "npm:hostile-pkg"], self.db,
                       {("hostile-pkg", "1.0.0"): tgz})
        self.assertNoTraceback(proc, "R7")
        self.assertIn("SC-MANIFEST-DEPTH", proc.stdout)
        verdicts = self.db_verdict("npm", "hostile-pkg")
        self.assertEqual(verdicts, ["SUSPICIOUS"])

    def test_r8_list_and_report_after_hostile_scan(self):
        """R8: list/report read back the hostile scan — DB rows well-formed,
        verdict readable by the downstream report command."""
        tgz = build_tgz([
            ("package/package.json", HOSTILE_NEST),
            ("package/a.py", b"x=1\n"),
        ])
        tb = {("hostile-pkg", "1.0.0"): tgz}
        p1 = run_cli(["scan", "npm:hostile-pkg"], self.db, tb)
        self.assertNoTraceback(p1, "R8 scan")
        p2 = run_cli(["list"], self.db, tb)
        self.assertNoTraceback(p2, "R8 list")
        self.assertIn("hostile-pkg", p2.stdout)
        self.assertIn("SUSPICIOUS", p2.stdout)
        p3 = run_cli(["report", "npm:hostile-pkg"], self.db, tb)
        self.assertNoTraceback(p3, "R8 report")
        self.assertIn("SC-MANIFEST-DEPTH", p3.stdout)
        self.assertIn("package.json:1", p3.stdout)


if __name__ == "__main__":
    unittest.main()
