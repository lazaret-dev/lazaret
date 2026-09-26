"""Audit findings — MCP server.

2  Every ScanTargetError became an empty clean result: a root that can't be
   listed (chmod 000) or a directory with nothing Lazaret scans gave
   qualityGate PASSED with no incomplete flag (the CLI exits 2 there), and
   scan_files on an unreadable file returned totalIssues 0, not incomplete.
3  The byte/file budget preflight skipped every directory named vendor, venv
   or .venv and never counted .pth files, while collect reads such a
   directory when it has no marker file and reads .pth files whole: 40 x
   50 KB of .js under vendor/ passed a 100 KB budget and were all read.

Fixtures are inert text files.
"""
import atexit
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.scanner import core as lazaret
from tests import _support


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-mcp-audit-")
    atexit.register(shutil.rmtree, root, True)
    for rel, body in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    return root


def refuse_scandir(target):
    """os.scandir that fails with EACCES for `target` only."""
    real = os.scandir

    def scandir(path="."):
        if os.fspath(path) == target:
            raise PermissionError(errno.EACCES, "Permission denied", target)
        return real(path)
    return mock.patch("os.scandir", side_effect=scandir)


def run_unprivileged(test, code, *args):
    """Run `code` in a Python the permission bits apply to: this user when it
    is not root; as root, uid/gid 65534 through util-linux setpriv, with a
    world-readable copy of the package. Skips where neither is possible."""
    if not hasattr(os, "geteuid"):
        test.skipTest("POSIX permissions only")
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    argv = [sys.executable, "-c", code, *args]
    src = _support.SRC
    if os.geteuid() == 0:
        setpriv = shutil.which("setpriv")
        if setpriv is None:
            test.skipTest("root ignores permission bits and setpriv is not available")
        work = tempfile.mkdtemp(prefix="lz-mcp-src-")
        test.addCleanup(shutil.rmtree, work, True)
        src = os.path.join(work, "src")
        shutil.copytree(os.path.join(_support.SRC, "lazaret"), os.path.join(src, "lazaret"),
                        ignore=shutil.ignore_patterns("__pycache__"))
        for dirpath, dirnames, filenames in os.walk(work):
            os.chmod(dirpath, 0o755)
            for name in filenames:
                os.chmod(os.path.join(dirpath, name), 0o644)
        argv = [setpriv, "--reuid=65534", "--regid=65534", "--clear-groups", *argv]
    env["PYTHONPATH"] = src
    probe = subprocess.run(argv[:-len(args) - 2] + ["-c", "import lazaret.mcp.server"],
                           capture_output=True, env=env, encoding="utf-8", errors="replace",
                           timeout=30)
    if probe.returncode != 0:
        test.skipTest(f"the unprivileged interpreter can't import lazaret: {probe.stderr[-300:]}")
    p = subprocess.run(argv, capture_output=True, env=env, encoding="utf-8", errors="replace",
                       timeout=40)
    test.assertEqual(p.returncode, 0, p.stderr[-2000:])
    return json.loads(p.stdout)


# ---------------------------------------------------------------------------
# 2. a target that can't be scanned is never a clean pass
# ---------------------------------------------------------------------------
class ScanTargetTests(unittest.TestCase):
    def test_unlistable_root_is_a_tool_error(self):
        root = tree({"app.py": "x = 1\n"})
        for tool in (server.tool_scan_directory, server.tool_quality_gate):
            with self.subTest(tool=tool.__name__), refuse_scandir(root):
                with self.assertRaisesRegex(ValueError, "Cannot read directory .*Permission denied"):
                    tool({"path": root})

    def test_missing_root_is_a_tool_error(self):
        root = os.path.join(tree({}), "gone")
        with self.assertRaisesRegex(ValueError, "Not a directory"):
            server.run_project_scan(root)

    def test_nothing_to_scan_is_incomplete(self):
        for label, files in (("empty", {}),
                             ("only Go and Markdown", {"main.go": "package main\n",
                                                       "README.md": "# demo\n"})):
            root = tree(files)
            with self.subTest(label):
                out = server.tool_scan_directory({"path": root})
                self.assertEqual(out["qualityGate"], "FAILED")
                self.assertTrue(out["incomplete"])
                self.assertIn("nothing to scan", out["incompleteReason"])
                self.assertEqual([(i["rule"], i["sev"]) for i in out["issues"]],
                                 [("SC-TRUNCATED", "CRITICAL")])
                gate = server.tool_quality_gate({"path": root})
                self.assertEqual(gate["qualityGate"], "FAILED")
                self.assertTrue(gate["incomplete"])

    def test_a_scannable_tree_is_unchanged(self):
        out = server.tool_scan_directory({"path": tree({"app.py": "x = 1\n"})})
        self.assertEqual(out["qualityGate"], "PASSED")
        self.assertNotIn("incomplete", out)


class ScanFilesUnreadableTests(unittest.TestCase):
    def check_not_read(self, out, path, text):
        entry = out["files"][path]
        self.assertEqual((entry["rule"], entry["sev"]), ("SC-TRUNCATED", "CRITICAL"))
        self.assertIn(text, entry["error"])
        self.assertTrue(out["incomplete"])
        self.assertIn("could not be read", out["incompleteReason"])
        self.assertEqual(out["worstSeverity"], "CRITICAL")

    def test_read_error(self):
        root = tree({"a.py": "x = 1\n"})
        path = os.path.join(root, "a.py")
        err = PermissionError(errno.EACCES, "Permission denied")
        with mock.patch.object(lazaret, "_read_prefix", side_effect=err):
            out = server.tool_scan_files({"paths": [path]})
        self.check_not_read(out, path, "cannot read the file (Permission denied)")
        self.assertEqual(out["totalIssues"], 1)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs named pipes")
    def test_fifo_and_directory(self):
        root = tree({"ok.py": "x = 1\n"})
        fifo, folder = os.path.join(root, "pipe.py"), os.path.join(root, "pkg.py")
        os.mkfifo(fifo)
        os.mkdir(folder)
        ok = os.path.join(root, "ok.py")
        out = server.tool_scan_files({"paths": [ok, fifo, folder]})
        self.check_not_read(out, fifo, "named pipe")
        self.check_not_read(out, folder, "directory")
        self.assertIn("issueCount", out["files"][ok])
        self.assertIn("2 of 3 file(s) could not be read", out["incompleteReason"])

    def test_missing_file_is_still_just_not_found(self):
        path = os.path.join(tree({}), "gone.py")
        out = server.tool_scan_files({"paths": [path]})
        self.assertEqual(out["files"][path], {"error": "File not found"})
        self.assertEqual(out["totalIssues"], 0)
        self.assertNotIn("incomplete", out)


# ---------------------------------------------------------------------------
# 3. the budget preflight counts the tree collect reads
# ---------------------------------------------------------------------------
def byte_tree(files):
    root = tempfile.mkdtemp(prefix="lz-mcp-budget-")
    atexit.register(shutil.rmtree, root, True)
    for rel, size in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"var x = 1;\n" * (size // 11) + b"/" * (size % 11))
    return root


class PreflightBudgetTests(unittest.TestCase):
    # whole-file reads: lib/a.js, vendor/b.js (no marker: first-party), x.pth,
    # package.json = 380 bytes. Pruned unless include_deps: node_modules/ and
    # env/ (it has a pyvenv.cfg): 700 more. Never counted: README.md (header
    # sample only), .git/.
    MIXED = {"lib/a.js": 100, "vendor/b.js": 200, "x.pth": 50, "package.json": 30,
             "node_modules/dep/c.js": 400, "env/pyvenv.cfg": 20, "env/d.py": 300,
             "README.md": 5000, ".git/e.js": 5000}

    def scan(self, root, max_bytes, include_deps=False):
        with mock.patch.dict(os.environ, {"LAZARET_MCP_MAX_BYTES": str(max_bytes)}):
            return server.tool_scan_directory({"path": root, "include_deps": include_deps})

    def refused(self, out):
        return bool(out.get("incomplete")) and "LAZARET_MCP_MAX_BYTES" in out["incompleteReason"]

    def test_budget_counts_exactly_the_bytes_collect_reads(self):
        root = byte_tree(self.MIXED)
        for include_deps, total in ((False, 380), (True, 1080)):
            with self.subTest(include_deps=include_deps):
                self.assertFalse(self.refused(self.scan(root, total, include_deps)))
                self.assertTrue(self.refused(self.scan(root, total - 1, include_deps)))

    def test_vendor_without_marker_and_pth_files_are_refused_unread(self):
        read = []
        real = lazaret._read_prefix

        def counting(path, limit):
            data = real(path, limit)
            read.append(len(data))
            return data
        for sub, ext in (("vendor", ".js"), ("lib", ".pth")):
            root = byte_tree({f"{sub}/f{i}{ext}": 50_000 for i in range(3)})
            with self.subTest(sub=sub, ext=ext), mock.patch.object(lazaret, "_read_prefix", counting):
                read.clear()
                out = self.scan(root, 100_000)
                self.assertTrue(self.refused(out), out.get("incompleteReason"))
                self.assertEqual(out["qualityGate"], "FAILED")
                self.assertEqual(sum(read), 0)

    def test_marked_dependency_trees_are_not_counted(self):
        root = byte_tree({"app.js": 100, "vendor/modules.txt": 10, "vendor/big.js": 150_000,
                          ".venv/pyvenv.cfg": 10, ".venv/lib/x.py": 150_000})
        self.assertFalse(self.refused(self.scan(root, 100_000)))
        self.assertTrue(self.refused(self.scan(root, 100_000, include_deps=True)))


class RealPermissionTests(unittest.TestCase):
    """The same through the real permission bits (chmod 000)."""

    CODE = textwrap.dedent("""
        import json, sys
        from lazaret.mcp import server
        out = {}
        for tool in ("scan_directory", "quality_gate"):
            try:
                res = server.HANDLERS[tool]({"path": sys.argv[1]})
                out[tool] = "returned " + res["qualityGate"]
            except ValueError as exc:
                out[tool] = "error: " + str(exc)
        out["scan_files"] = server.tool_scan_files({"paths": [sys.argv[2]]})
        print(json.dumps(out))
    """)

    def test_chmod_000(self):
        work = tempfile.mkdtemp(prefix="lz-mcp-perm-")
        locked, secret = os.path.join(work, "locked"), os.path.join(work, "noread.py")
        os.mkdir(locked)
        for path in (os.path.join(locked, "app.py"), secret):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
        os.chmod(locked, 0)
        os.chmod(secret, 0)
        os.chmod(work, 0o755)
        self.addCleanup(shutil.rmtree, work, True)
        self.addCleanup(os.chmod, locked, 0o755)
        out = run_unprivileged(self, self.CODE, locked, secret)
        for tool in ("scan_directory", "quality_gate"):
            self.assertRegex(out[tool], "^error: Cannot read directory .*Permission denied")
        files = out["scan_files"]
        self.assertTrue(files["incomplete"])
        self.assertEqual(files["files"][secret]["rule"], "SC-TRUNCATED")
        self.assertIn("Permission denied", files["files"][secret]["error"])


if __name__ == "__main__":
    unittest.main()
