"""Final-review item 4: every capped, cut-short or budget-limited MCP tool
call must carry an SC-TRUNCATED finding (or, for per-package results, an
INCOMPLETE entry), so it can never look clean.

scan_files with a hit cap (LAZARET_MCP_MAX_FILES=2 and 3 paths) returned
`incomplete: true` but no SC-TRUNCATED finding: worstSeverity was whatever
the scanned files had. Each file the cap leaves out now carries an
SC-TRUNCATED finding, counted in totalIssues and worstSeverity. Also
checked here: scan_directory / quality_gate on every cap, scan_package past
its deadline, and discover_packages(scan=true), whose packages beyond the
per-call scan limit used to be dropped without a word.

Fixtures are inert text; the network seam is patched.
"""

import atexit
import datetime
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.registry import repo
from tests.registry._review_support import tarball


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-mcp-caps-")
    atexit.register(shutil.rmtree, root, True)
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    return root


STRONG = ("BLOCKER", "CRITICAL")


class ScanFilesCapTests(unittest.TestCase):
    def setUp(self):
        self.root = tree({f"m{i}.py": "x = 1\n" for i in range(3)})
        self.paths = [os.path.join(self.root, f"m{i}.py") for i in range(3)]

    def check_capped(self, out, unscanned):
        self.assertTrue(out["incomplete"])
        self.assertIn(out["worstSeverity"], STRONG)
        for p in unscanned:
            entry = out["files"][p]
            self.assertEqual((entry["rule"], entry["sev"]), ("SC-TRUNCATED", "CRITICAL"))
            self.assertIn("not scanned", entry["error"])
        return out

    def test_file_cap(self):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_FILES": "2"}):
            out = server.tool_scan_files({"paths": self.paths})
        self.check_capped(out, self.paths[2:])
        self.assertIn("issueCount", out["files"][self.paths[1]])
        self.assertEqual(out["totalIssues"],
                         sum(e.get("issueCount", 0) for e in out["files"].values()) + 1)

    def test_byte_cap(self):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_BYTES": "3"}):
            out = server.tool_scan_files({"paths": self.paths})
        self.check_capped(out, self.paths[1:])

    def test_time_cap(self):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_SECONDS": "0.000001"}):
            out = server.tool_scan_files({"paths": self.paths})
        self.check_capped(out, self.paths)
        self.assertEqual(out["totalIssues"], 3)

    def test_uncapped_call_has_no_truncation(self):
        out = server.tool_scan_files({"paths": self.paths})
        self.assertNotIn("incomplete", out)
        self.assertFalse(any(e.get("rule") == "SC-TRUNCATED" for e in out["files"].values()))


class ProjectToolCapTests(unittest.TestCase):
    CAPS = {"files": {"LAZARET_MCP_MAX_FILES": "2"},
            "bytes": {"LAZARET_MCP_MAX_BYTES": "3"},
            "time": {"LAZARET_MCP_MAX_SECONDS": "0.000001"}}

    def test_scan_directory_and_quality_gate(self):
        root = tree({f"m{i}.py": "x = 1\n" for i in range(4)})
        for cap, env in self.CAPS.items():
            with self.subTest(cap=cap), mock.patch.dict(os.environ, env):
                out = server.tool_scan_directory({"path": root})
                self.assertTrue(out["incomplete"])
                self.assertEqual(out["qualityGate"], "FAILED")
                self.assertIn("SC-TRUNCATED", {i["rule"] for i in out["issues"]})
                gate = server.tool_quality_gate({"path": root})
                self.assertTrue(gate["incomplete"])
                self.assertEqual(gate["qualityGate"], "FAILED")


NOW = datetime.datetime.now(datetime.timezone.utc)
GOOD_TGZ = tarball({"package.json": json.dumps({"name": "g"}), "index.js": "module.exports = 1;\n"})


def registry_patches(db, found=()):
    def resolve(name, version):
        return ("1.0.0", f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz", "tgz", "npm", {})
    return [mock.patch.object(server, "REGISTRY_DB", db),
            mock.patch.object(repo, "discover_pypi", return_value=[]),
            mock.patch.object(repo, "discover_npm", return_value=list(found)),
            mock.patch.object(repo, "resolve_npm", side_effect=resolve),
            mock.patch.object(repo, "http_bytes", return_value=GOOD_TGZ),
            mock.patch.object(repo, "verify_digest", return_value=None)]


class RegistryToolCapTests(unittest.TestCase):
    def run_patched(self, fn, found=(), env=None):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            patches = registry_patches(os.path.join(d, "r.db"), found)
            for p in patches:
                p.start()
            try:
                with mock.patch.dict(os.environ, env or {}):
                    return fn()
            finally:
                for p in reversed(patches):
                    p.stop()

    def test_scan_package_past_its_deadline(self):
        out = self.run_patched(lambda: server.tool_scan_package({"spec": "npm:g"}),
                               env={"LAZARET_MCP_MAX_SECONDS": "0.000001"})
        self.assertEqual(out["verdict"], "INCOMPLETE")
        self.assertIn("SC-TRUNCATED", {i["rule"] for i in out["issues"]})

    def test_discover_scan_limit_lists_the_rest_as_incomplete(self):
        found = [("npm", f"p{i:02d}", "1.0.0", NOW) for i in range(server.MAX_DISCOVER_SCANS + 4)]
        out = self.run_patched(lambda: server.tool_discover_packages({"since": "1d", "scan": True}),
                               found=found)
        self.assertEqual(len(out["scanned"]), len(found))
        verdicts = [r["verdict"] for r in out["scanned"]]
        self.assertEqual(verdicts[:server.MAX_DISCOVER_SCANS], ["OK"] * server.MAX_DISCOVER_SCANS)
        self.assertEqual(verdicts[server.MAX_DISCOVER_SCANS:], ["INCOMPLETE"] * 4)
        self.assertEqual(len(out["flagged"]), 4)
        self.assertTrue(all("not scanned" in f["error"] for f in out["flagged"]))
        self.assertTrue(out["incomplete"])
        self.assertIn("at most", out["incompleteReason"])

    def test_discover_past_the_deadline(self):
        found = [("npm", "a", "1.0.0", NOW), ("npm", "b", None, NOW)]
        out = self.run_patched(lambda: server.tool_discover_packages({"since": "1d", "scan": True}),
                               found=found, env={"LAZARET_MCP_MAX_SECONDS": "0.000001"})
        self.assertEqual({r["package"]: r["verdict"] for r in out["scanned"]},
                         {"npm:a@1.0.0": "INCOMPLETE", "npm:b": "INCOMPLETE"})
        self.assertTrue(out["incomplete"])
        self.assertIn("time budget", out["incompleteReason"])

    def test_small_discover_scan_is_complete(self):
        found = [("npm", "a", "1.0.0", NOW)]
        out = self.run_patched(lambda: server.tool_discover_packages({"since": "1d", "scan": True}),
                               found=found)
        self.assertNotIn("incomplete", out)
        self.assertEqual(out["flagged"], [])


if __name__ == "__main__":
    unittest.main()
