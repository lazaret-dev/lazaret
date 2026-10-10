"""Review P2: what the registry stores is always redacted.

LAZARET_NO_REDACT=1 (the MCP server) and --no-redact-secrets (the registry
CLI) flipped the one process-wide redaction switch, and registry scans are
stored in the state DB: a package's credential line reached the scans.issues
blob raw, where the MCP tools and a shared Postgres read it back.
repo.scan_package now always redacts, whatever the switch says; the switch
keeps working for project scans (the user's own code).

The "credential" is AWS's documented example key pair: inert. The network is
faked (repo's resolve/download seam), nothing is fetched or executed.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import _support
from lazaret.mcp import server
from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry._review_support import manifest, scan_npm, tarball

KEY = "AKI\x41IOSFODNN7EXAMPLE"
SECRET_JS = ('const creds = {accessKeyId: "%s", '
             'secretAccessKey: "wJalrXUtnFEMI/K7MDEN\x47/bPxRfiCYEXAMPLEKEY"};\n' % KEY)
PKG = {"package.json": manifest(main="index.js"), "index.js": SECRET_JS}


def stored_issues(db):
    con = sqlite3.connect(db)
    try:
        return [row[0] for row in con.execute("SELECT issues FROM scans")]
    finally:
        con.close()


class ScanPackageTests(unittest.TestCase):
    def test_redacted_whatever_the_switch_says(self):
        with mock.patch.object(core, "REDACT_SECRETS", False):
            res = scan_npm(PKG)
            self.assertFalse(core.REDACT_SECRETS)           # the switch is restored afterwards
        self.assertTrue([i for i in res["issues"] if i["rule"] in core.SECRET_RULES],
                        "the fixture must produce a secret finding")
        self.assertNotIn(KEY, json.dumps(res))
        self.assertIn(core.REDACT_FINGERPRINT, json.dumps(res["issues"]))

    def test_the_switch_still_works_for_project_scans(self):
        with mock.patch.object(core, "REDACT_SECRETS", False):
            self.assertIn(KEY, json.dumps(core.scan_file("index.js", SECRET_JS, "js")))
        self.assertNotIn(KEY, json.dumps(core.scan_file("index.js", SECRET_JS, "js")))

    def test_forced_redaction_restores_on_error(self):
        with mock.patch.object(core, "REDACT_SECRETS", False):
            with self.assertRaises(RuntimeError):
                with core.forced_redaction():
                    self.assertTrue(core.REDACT_SECRETS)
                    raise RuntimeError("boom")
            self.assertFalse(core.REDACT_SECRETS)


class McpTests(unittest.TestCase):
    def test_scan_package_with_LAZARET_NO_REDACT(self):
        """The reviewer's reproduction: the switch as LAZARET_NO_REDACT=1 sets
        it, then the scan_package tool; the DB blob held the raw key."""
        d = tempfile.mkdtemp(prefix="lz-p2-")
        self.addCleanup(shutil.rmtree, d, True)
        db = os.path.join(d, "r.db")
        rv = ("1.0.0", "https://registry.npmjs.org/x/-/x-1.0.0.tgz", "tgz", "npm", {})
        with mock.patch.object(core, "REDACT_SECRETS", False), \
                mock.patch.object(server, "REGISTRY_DB", db), \
                mock.patch.object(repo, "resolve_npm", return_value=rv), \
                mock.patch.object(repo, "http_bytes", return_value=tarball(PKG)), \
                mock.patch.object(repo, "verify_digest", return_value=None):
            out = server.tool_scan_package({"spec": "npm:x"})
        self.assertNotIn("storeError", out)
        self.assertNotIn(KEY, json.dumps(out))
        (blob,) = stored_issues(db)
        self.assertNotIn(KEY, blob)
        self.assertIn(core.REDACT_FINGERPRINT, blob)


class RegistryCliTests(unittest.TestCase):
    def test_no_redact_secrets_is_a_no_op_with_a_note(self):
        d = tempfile.mkdtemp(prefix="lz-p2-cli-")
        self.addCleanup(shutil.rmtree, d, True)
        db = os.path.join(d, "r.db")
        env = dict(os.environ, LAZARET_DB=db, CG_FAKE_REGISTRY=json.dumps(
            {"tarballs": {"x@1.0.0": tarball(PKG).hex()}}))
        p = subprocess.run([sys.executable, _support.BOOTSTRAP, "lazaret_repo.py",
                            "scan", "npm:x", "--no-redact-secrets"],
                           capture_output=True, encoding="utf-8", errors="replace",
                           cwd=d, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.assertIn("--no-redact-secrets has no effect", p.stderr)
        self.assertNotIn(KEY, p.stdout + p.stderr)
        (blob,) = stored_issues(db)
        self.assertNotIn(KEY, blob)
        self.assertIn(core.REDACT_FINGERPRINT, blob)


if __name__ == "__main__":
    unittest.main()
