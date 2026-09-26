"""Final-review items 3 and 7: registry sweep exit codes.

3. `lazaret-registry scan-all` (and `scan`, `discover --scan`) kept going
   when a package failed to scan — a download error, a digest mismatch —
   but then exited 0: only store failures or --ci gave 1, so a sweep in
   which nothing could be checked looked clean. Every package is still
   attempted; any per-package error (scan or store) now makes the run exit
   1 at the END of the sweep, after a one-line summary of the failed
   packages on stderr.
7. A version skipped as "already scanned" (no --rescan) did not count
   toward --ci, so a nightly `scan-all --ci` failed once on a SUSPICIOUS
   package and passed every night after, without anything changing. The
   stored verdict of a skipped version now counts.

Fixtures are inert archives built in memory; the network seam is patched.
"""

import base64
import contextlib
import hashlib
import io
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import DECODE_EXEC_JS, tarball

GOOD = tarball({"index.js": "module.exports = 1;\n"})
EVIL = tarball({"index.js": DECODE_EXEC_JS})
ARTIFACTS = {"a-good": GOOD, "c-digest": GOOD, "d-good": GOOD, "e-evil": EVIL}


def integrity(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def resolve_npm(name, version):
    url = f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz"
    data = ARTIFACTS.get(name, b"")
    # c-digest: the registry publishes a digest the served bytes don't match
    published = integrity(b"something else" if name == "c-digest" else data)
    return "1.0.0", url, "tgz", "npm", {"dist": {"integrity": published}}


def http_bytes(url):
    name = url.split("/")[3]
    if name == "b-fetch":
        raise repo.FetchError(f"HTTP 503 fetching {url}")
    return ARTIFACTS[name]


class Sweep:
    """Run repo.main() in-process against a temporary SQLite DB."""

    def __init__(self, test):
        # main() leaves its Store open; on Windows the DB file stays locked
        # until the connection is collected
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        test.addCleanup(tmp.cleanup)
        self.db = os.path.join(tmp.name, "r.db")

    def run(self, *argv, feed=()):
        with mock.patch.object(repo, "resolve_npm", side_effect=resolve_npm), \
                mock.patch.object(repo, "http_bytes", side_effect=http_bytes), \
                mock.patch.object(repo, "discover_npm", return_value=list(feed)), \
                mock.patch.object(repo, "discover_pypi", return_value=[]), \
                mock.patch("sys.argv", ["lazaret-registry", *argv, "--db", self.db]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
                exc.__traceback__ = None          # release main()'s Store
        return code, out.getvalue(), err.getvalue()

    def verdicts(self):
        con = sqlite3.connect(self.db)
        try:
            return dict(con.execute("SELECT p.name, s.verdict FROM scans s "
                                    "JOIN packages p ON p.id = s.package_id").fetchall())
        finally:
            con.close()


class ScanErrorExitTests(unittest.TestCase):
    SPECS = ["npm:a-good", "npm:b-fetch", "npm:c-digest", "npm:d-good"]

    def check_failed_sweep(self, sweep, code, out, err):
        self.assertEqual(code, 1, err)
        self.assertIn("error scanning npm:b-fetch", err)
        self.assertIn("error scanning npm:c-digest", err)
        self.assertIn("SC-DIGEST-MISMATCH", err)
        summary = [l for l in err.splitlines() if l.startswith("error: ")]
        self.assertEqual(summary, ["error: 2 package(s) failed to scan or store: "
                                   "npm:b-fetch, npm:c-digest"])
        # everything else was still scanned and stored
        self.assertIn("npm:a-good@1.0.0", out)
        self.assertIn("npm:d-good@1.0.0", out)
        self.assertEqual(sweep.verdicts(), {"a-good": "OK", "d-good": "OK"})

    def test_scan_all_exits_1_after_scanning_everything_else(self):
        sweep = Sweep(self)
        self.assertEqual(sweep.run("add", *self.SPECS)[0], 0)
        self.check_failed_sweep(sweep, *sweep.run("scan-all"))

    def test_scan_exits_1(self):
        sweep = Sweep(self)
        self.check_failed_sweep(sweep, *sweep.run("scan", *self.SPECS))

    def test_discover_scan_exits_1(self):
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        feed = [("npm", s.split(":", 1)[1], "1.0.0", now) for s in self.SPECS]
        sweep = Sweep(self)
        code, out, err = sweep.run("discover", "--scan", feed=feed)
        self.assertEqual(code, 1, err)
        self.assertIn("error: 2 package(s) failed to scan or store", err)
        self.assertEqual(sweep.verdicts(), {"a-good": "OK", "d-good": "OK"})

    def test_clean_sweep_still_exits_0(self):
        sweep = Sweep(self)
        code, out, err = sweep.run("scan", "npm:a-good", "npm:d-good")
        self.assertEqual(code, 0, err)
        self.assertNotIn("error", err)

    def test_store_failure_is_in_the_summary(self):
        sweep = Sweep(self)
        real = repo.Store.save_scan

        def flaky(store, pid, res):
            if res["name"] == "a-good":
                raise sqlite3.OperationalError("disk I/O error")
            return real(store, pid, res)
        with mock.patch.object(repo.Store, "save_scan", flaky):
            code, out, err = sweep.run("scan", "npm:a-good", "npm:d-good")
        self.assertEqual(code, 1)
        self.assertIn("error: 1 package(s) failed to scan or store: npm:a-good", err)
        self.assertEqual(sweep.verdicts(), {"d-good": "OK"})

    def test_summary_is_one_bounded_line(self):
        errors = [f"npm:p{i}" for i in range(25)]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            repo._finish_sweep(errors, False, False)
        self.assertEqual(cm.exception.code, 1)
        self.assertEqual(len(err.getvalue().splitlines()), 1)
        self.assertIn("npm:p19, … (+5 more)", err.getvalue())

    def test_cmd_scan_collects_scan_failures(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            store = repo.Store(os.path.join(d, "r.db"))
            try:
                errors = []
                with mock.patch.object(repo, "resolve_npm", side_effect=resolve_npm), \
                        mock.patch.object(repo, "http_bytes", side_effect=http_bytes), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    bad = repo.cmd_scan(store, self.SPECS, False, False, errors=errors)
            finally:
                store.conn.close()
        self.assertTrue(bad)
        self.assertEqual(errors, ["npm:b-fetch", "npm:c-digest"])


class CachedVerdictTests(unittest.TestCase):
    def test_skipped_suspicious_version_still_fails_ci(self):
        sweep = Sweep(self)
        code, _, _ = sweep.run("scan", "npm:e-evil", "npm:a-good", "--ci")
        self.assertEqual(code, 1)
        self.assertEqual(sweep.verdicts(), {"e-evil": "SUSPICIOUS", "a-good": "OK"})
        # next sweep without --rescan: nothing is downloaded again, but the
        # stored SUSPICIOUS verdict still fails --ci
        code, out, err = sweep.run("scan-all", "--ci")
        self.assertEqual(code, 1, out + err)
        self.assertIn("npm:e-evil@1.0.0 already scanned (supply-chain, SUSPICIOUS)", out)
        self.assertIn("npm:a-good@1.0.0 already scanned (supply-chain, OK)", out)
        # without --ci a known verdict is information, not an error
        code, out, err = sweep.run("scan-all")
        self.assertEqual(code, 0, err)

    def test_skipped_clean_versions_pass_ci(self):
        sweep = Sweep(self)
        self.assertEqual(sweep.run("scan", "npm:a-good", "--ci")[0], 0)
        code, out, err = sweep.run("scan-all", "--ci")
        self.assertEqual(code, 0, err)
        self.assertIn("already scanned (supply-chain, OK)", out)

    def test_stored_verdict(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            store = repo.Store(os.path.join(d, "r.db"))
            try:
                pid, _ = store.add_package("npm", "x")
                self.assertIsNone(store.stored_verdict(pid, "1.0.0", "supply-chain"))
                with mock.patch.object(repo, "resolve_npm", side_effect=resolve_npm), \
                        mock.patch.object(repo, "http_bytes", return_value=EVIL), \
                        mock.patch.object(repo, "verify_digest", return_value=None):
                    res = repo.scan_package("npm", "x")
                store.save_scan(pid, res)
                self.assertEqual(store.stored_verdict(pid, "1.0.0", "supply-chain"), "SUSPICIOUS")
                self.assertIsNone(store.stored_verdict(pid, "1.0.0", "full"))
                self.assertIsNone(store.stored_verdict(pid, "1.0.0", "supply-chain",
                                                       engine_version="0.0.1"))
            finally:
                store.conn.close()


if __name__ == "__main__":
    unittest.main()
