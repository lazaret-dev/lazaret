"""Audit findings — MCP server.

2  Every ScanTargetError became an empty clean result: a root that can't be
   listed (chmod 000) or a directory with nothing Lazaret scans gave
   qualityGate PASSED with no incomplete flag (the CLI exits 2 there), and
   scan_files on an unreadable file returned totalIssues 0, not incomplete.
3  The byte/file budget preflight skipped every directory named vendor, venv
   or .venv and never counted .pth files, while collect reads such a
   directory when it has no marker file and reads .pth files whole: 40 x
   50 KB of .js under vendor/ passed a 100 KB budget and were all read.
7  discover_packages did not validate `ecosystem` or `limit`: ["PyPI"] or
   ["NPM"] queried nothing and answered count 0, complete; a plain "npm" was
   iterated character by character; a negative limit was accepted. Its
   deadline and cancel flag were not checked before the registry walks.
9  LAZARET_MCP_ROOTS set but empty ("", ":", " ") meant no path restriction
   at all; it now refuses every tool call as a configuration error.

Fixtures are inert text files.
"""
import atexit
import datetime
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.registry import repo
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
                             ("only Java and Markdown", {"Main.java": "class Main {}\n",
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


# ---------------------------------------------------------------------------
# 7. discover_packages validates its arguments and honours the call context
# ---------------------------------------------------------------------------
NOW = datetime.datetime.now(datetime.timezone.utc)


class DiscoverArgumentTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake(eco):
            def discover(cutoff, limit, notes=None):
                self.calls.append((eco, limit))
                return [(eco, f"{eco}-pkg", "1.0.0", NOW)]
            return discover
        for eco in ("pypi", "npm"):
            patcher = mock.patch.object(repo, f"discover_{eco}", side_effect=fake(eco))
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, **args):
        return server.tool_discover_packages(dict({"since": "1d"}, **args))

    def test_bad_ecosystems_are_tool_errors(self):
        for bad in (["PyPI"], ["NPM"], "npm", "npm,pypi", ["npm", 5], ["go"], {"npm": True}):
            with self.subTest(ecosystem=bad):
                with self.assertRaisesRegex(ValueError, "ecosystem must be an array"):
                    self.call(ecosystem=bad)
        self.assertEqual(self.calls, [])

    def test_good_ecosystems(self):
        for eco, want in ((["npm"], ["npm"]), (["npm", "pypi"], ["pypi", "npm"]), ([], ["pypi", "npm"]),
                          (None, ["pypi", "npm"]), (["pypi", "pypi"], ["pypi"])):
            with self.subTest(ecosystem=eco):
                self.calls.clear()
                out = self.call(**({} if eco is None else {"ecosystem": eco}))
                self.assertEqual([e for e, _ in self.calls], want)
                self.assertEqual(out["count"], len(want))
                self.assertNotIn("incomplete", out)

    def test_limit(self):
        for bad in (-1, 0, True, "x", 2.5, [3]):
            with self.subTest(limit=bad):
                with self.assertRaisesRegex(ValueError, "limit must be"):
                    self.call(limit=bad)
        self.assertEqual(self.calls, [])
        for value, want in ((None, 25), (10, 10), ("10", 10), (7.0, 7), (500, 50)):
            with self.subTest(limit=value):
                self.calls.clear()
                self.call(**({} if value is None else {"limit": value}), ecosystem=["npm"])
                self.assertEqual(self.calls, [("npm", want)])

    def run_in(self, ctx, **args):
        server._LOCAL.ctx = ctx
        try:
            return self.call(**args)
        finally:
            server._LOCAL.ctx = None

    def test_deadline_is_checked_before_each_registry(self):
        ctx = server.ToolContext()
        ctx.deadline = time.monotonic() - 1
        out = self.run_in(ctx)
        self.assertEqual(self.calls, [])
        self.assertEqual(out["count"], 0)
        self.assertTrue(out["incomplete"])
        self.assertEqual(out["incompleteReason"].count("not checked: time budget"), 2)

        ctx = server.ToolContext()

        def slow_pypi(cutoff, limit, notes=None):      # the budget runs out during PyPI
            self.calls.append(("pypi", limit))
            ctx.deadline = time.monotonic() - 1
            return []
        repo.discover_pypi.side_effect = slow_pypi
        self.calls.clear()
        out = self.run_in(ctx)
        self.assertEqual(self.calls, [("pypi", 25)])
        self.assertTrue(out["incomplete"])
        self.assertTrue(out["incompleteReason"].startswith("npm not checked: time budget"))

    def test_cancel_stops_before_any_registry(self):
        event = threading.Event()
        event.set()
        with self.assertRaises(server.ToolCancelled):
            self.run_in(server.ToolContext(event))
        self.assertEqual(self.calls, [])


# ---------------------------------------------------------------------------
# 9. LAZARET_MCP_ROOTS set but empty refuses tools instead of allowing all
# ---------------------------------------------------------------------------
EMPTY_ROOTS = ("", os.pathsep, " ", f" {os.pathsep} ")


class RootsConfigTests(unittest.TestCase):
    def test_set_but_empty_refuses_every_tool(self):
        root = tree({"app.py": "x = 1\n"})
        calls = [server.allowed_roots, server.ToolContext,
                 lambda: server.tool_scan_directory({"path": root}),
                 lambda: server.tool_quality_gate({"path": root}),
                 lambda: server.tool_scan_files({"paths": [os.path.join(root, "app.py")]})]
        for raw in EMPTY_ROOTS:
            for call in calls:
                with self.subTest(roots=raw), mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": raw}):
                    with self.assertRaisesRegex(ValueError, "LAZARET_MCP_ROOTS is set but names no"):
                        call()

    def test_the_server_answers_a_tool_error_and_keeps_serving(self):
        frames = []
        out = mock.Mock()
        out.write.side_effect = lambda s: frames.extend(json.loads(l) for l in s.splitlines() if l)
        srv = server.Server()
        self.addCleanup(srv.close, 10)
        with mock.patch.object(server, "_OUT", out), \
                mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": os.pathsep}):
            srv.handle_line(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "scan_snippet", "arguments": {"code": "x = 1\n", "language": "py"}}}))
            srv.handle_line(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}))
            deadline = time.monotonic() + 10
            while len(frames) < 2 and time.monotonic() < deadline:
                time.sleep(0.01)
        by_id = {f["id"]: f for f in frames}
        self.assertEqual(by_id[2]["result"], {})
        self.assertTrue(by_id[1]["result"]["isError"])
        self.assertIn("LAZARET_MCP_ROOTS is set but names no directory",
                      by_id[1]["result"]["content"][0]["text"])

    def test_blank_entries_next_to_real_ones_are_ignored(self):
        inside, outside = tree({"a.py": "x = 1\n"}), tree({"b.py": "y = 2\n"})
        raw = f" {os.pathsep}{inside}{os.pathsep}{os.pathsep}"
        with mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": raw}):
            self.assertEqual(server.allowed_roots(), [os.path.normcase(os.path.realpath(inside))])
            self.assertIn("qualityGate", server.tool_scan_directory({"path": inside}))
            with self.assertRaisesRegex(ValueError, "outside the allowed roots"):
                server.tool_scan_directory({"path": outside})

    def test_unset_is_unrestricted(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("LAZARET_MCP_ROOTS", None)
            self.assertEqual(server.ToolContext().roots, [])
            self.assertIn("qualityGate", server.tool_scan_directory({"path": tree({"a.py": "x = 1\n"})}))


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
