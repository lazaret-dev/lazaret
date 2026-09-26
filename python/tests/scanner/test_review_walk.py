"""Review items 2, 3 and 4 (FIX-SPEC 11): the project walk.

2. Every open() followed symlinks and accepted special files, with unbounded
   reads: a FIFO named b.py (or package.json, or x.so) hung the scan forever;
   b.py -> /dev/urandom raised MemoryError; settings.py -> /outside/creds.txt
   pulled a host file into the report. Now only regular files are opened
   (lstat + S_ISREG, O_NOFOLLOW|O_NONBLOCK + fstat), symlinks are never
   followed (INFO Q-SYMLINK), special/unreadable entries are INFO
   Q-UNREADABLE, and reads are bounded.
3. os.walk recursed on 3.10/3.11: a tree 1,100 directories deep raised
   RecursionError. The walk is iterative now.
4. A non-UTF-8 file name (b'bad\\xff.py') crashed the HTML writer after the
   scan (UnicodeEncodeError, traceback, exit 1) and put a lone surrogate in
   the SARIF URI. Paths are valid UTF-8 at collection time now.

Fixtures are inert; the "outside" credential is a dummy string.
"""
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import _support
from lazaret.scanner import core

PY = sys.executable
POSIX = os.name == "posix"


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-walk-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def run_cli(root, *extra, html=False):
    out = tempfile.mkdtemp(prefix="lz-review-out-")
    try:
        args = [PY, _support.CLI, root, "--out-dir", out, *extra]
        if not html:
            args.append("--no-html")
        p = subprocess.run(args, capture_output=True, encoding="utf-8", errors="replace",
                           timeout=40)
        report = None
        path = os.path.join(out, "lazaret-report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
        blobs = {}
        for name in os.listdir(out):
            with open(os.path.join(out, name), "rb") as fh:
                blobs[name] = fh.read()
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return p, report, blobs


def by_file(report):
    out = {}
    for i in report["issues"]:
        out.setdefault(i["file"].replace(os.sep, "/"), set()).add(i["rule"])
    return out


@unittest.skipUnless(POSIX and hasattr(os, "mkfifo"), "needs POSIX FIFOs")
class SpecialFiles(unittest.TestCase):
    def test_fifo_never_blocks_the_scan(self):
        for name in ("b.py", "package.json", "x.so", "binding.gyp", "notes.txt"):
            with self.subTest(fifo=name):
                root = make_tree({"a.py": "eval(x)\n"})
                self.addCleanup(shutil.rmtree, root, True)
                os.mkfifo(os.path.join(root, name))
                p, report, _ = run_cli(root)       # would hang forever before
                self.assertNotIn("Traceback", p.stderr)
                self.assertEqual(p.returncode, 0, p.stderr)
                files = by_file(report)
                self.assertEqual(files[name], {"Q-UNREADABLE"})
                self.assertIn("S-EVAL-PY", files["a.py"])
                msg = [i["msg"] for i in report["issues"] if i["rule"] == "Q-UNREADABLE"][0]
                self.assertIn("named pipe", msg)

    def test_read_prefix_refuses_a_fifo_swapped_in_after_lstat(self):
        root = make_tree({})
        self.addCleanup(shutil.rmtree, root, True)
        path = os.path.join(root, "late.py")
        os.mkfifo(path)
        with self.assertRaises(OSError):
            core._read_prefix(path, 10)          # O_NONBLOCK + fstat: no hang

    @unittest.skipUnless(os.path.exists("/dev/urandom"), "no /dev/urandom")
    def test_symlink_to_a_device_is_not_read(self):
        root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        os.symlink("/dev/urandom", os.path.join(root, "b.py"))
        p, report, _ = run_cli(root)             # MemoryError before
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(by_file(report)["b.py"], {"Q-SYMLINK"})


@unittest.skipUnless(hasattr(os, "symlink") and POSIX, "needs symlinks")
class Symlinks(unittest.TestCase):
    SECRET = "dummy-credential-value-7Q2Z"

    def setUp(self):
        self.outside = make_tree({
            "creds.txt": f'password = "{self.SECRET}"\n',
            "pkg/evil.py": "eval(x)\n"})
        self.addCleanup(shutil.rmtree, self.outside, True)
        self.root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, self.root, True)
        os.symlink(os.path.join(self.outside, "creds.txt"), os.path.join(self.root, "settings.py"))
        os.symlink(os.path.join(self.outside, "pkg"), os.path.join(self.root, "linked"))
        os.symlink(self.root, os.path.join(self.root, "loop"))

    def test_links_are_reported_not_followed(self):
        p, report, blobs = run_cli(self.root, "--sarif", "r.sarif", html=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        files = by_file(report)
        for name in ("settings.py", "linked", "loop"):
            self.assertEqual(files[name], {"Q-SYMLINK"}, name)
        self.assertNotIn("linked/evil.py", files)
        for name, blob in blobs.items():
            self.assertNotIn(self.SECRET.encode(), blob, name)   # host file not pulled in
        link = [i for i in report["issues"] if i["file"] == "settings.py"][0]
        self.assertEqual((link["sev"], link["type"]), ("INFO", "SMELL"))
        self.assertIn("-> ", link["msg"])
        self.assertTrue(report["pass"], "coverage notes must not fail the gate")


class WindowsLinkTargets(unittest.TestCase):
    """os.readlink on Windows returns an absolute target in its \\\\?\\ form;
    Q-SYMLINK shows it the way the npm engine (libuv) does. Runs on every OS:
    the conversion is plain text."""

    def test_the_nt_prefix_is_undone_as_libuv_does(self):
        cases = {
            r"\\?\C:\Users\RUNNER~1\Temp\mod.py": r"C:\Users\RUNNER~1\Temp\mod.py",
            r"\\?\c:": "c:",
            r"\\?\UNC\server\share\x": r"\\server\share\x",
            r"\\?\unc\server\share": r"\\server\share",
            r"\\?\Volume{0000}\x": r"\\?\Volume{0000}\x",     # not a drive or a share: as is
            r"\\?\C:x": r"\\?\C:x",
            r"..\sibling\mod.py": r"..\sibling\mod.py",       # relative: as written
            "/etc/passwd": "/etc/passwd",
        }
        for raw, shown in cases.items():
            with self.subTest(target=raw):
                self.assertEqual(core.link_target_text(raw), shown)

    def test_the_walker_uses_it_on_windows_only(self):
        with mock.patch.object(core.os, "readlink", return_value=r"\\?\C:\x"):
            with mock.patch.object(core.os, "name", "nt"):
                self.assertEqual(core._readlink("link"), r"C:\x")
            with mock.patch.object(core.os, "name", "posix"):
                self.assertEqual(core._readlink("link"), r"\\?\C:\x")   # a legal POSIX name


class DeepTree(unittest.TestCase):
    DEPTH = 1100

    def test_deep_tree_is_walked_iteratively(self):
        root = tempfile.mkdtemp(prefix="lz-review-deep-")
        self.addCleanup(self._remove_deep, root)
        path = root
        for _ in range(self.DEPTH):         # os.makedirs recurses too
            path = os.path.join(path, "d")
            try:
                os.mkdir(path)
            except OSError as exc:
                # macOS caps a path at 1024 bytes (PATH_MAX); Linux allows 4096
                # and the Windows runners have long paths enabled
                if exc.errno != errno.ENAMETOOLONG:
                    raise
                self.skipTest(f"this OS limits paths to fewer bytes than a "
                              f"{self.DEPTH}-level tree needs (macOS: 1024)")
        with open(os.path.join(path, "leaf.py"), "w", encoding="utf-8") as fh:
            fh.write("eval(x)\n")
        with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        p, report, _ = run_cli(root)
        self.assertNotIn("RecursionError", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        leaf = "/".join(["d"] * self.DEPTH + ["leaf.py"])
        self.assertIn("S-EVAL-PY", by_file(report).get(leaf, set()))

    @staticmethod
    def _remove_deep(root):
        # shutil.rmtree recurses on older Pythons; delete bottom-up by hand
        stack, dirs = [root], []
        while stack:
            cur = stack.pop()
            dirs.append(cur)
            try:
                entries = list(os.scandir(cur))
            except OSError:
                continue
            for e in entries:
                if e.is_dir(follow_symlinks=False):
                    stack.append(e.path)
                else:
                    try:
                        os.unlink(e.path)
                    except OSError:
                        pass
        for d in reversed(dirs):
            try:
                os.rmdir(d)
            except OSError:
                pass


class Unreadable(unittest.TestCase):
    """Permission errors become Q-UNREADABLE (simulated: tests run as root)."""

    def test_unreadable_file(self):
        root = make_tree({"a.py": "eval(x)\n", "b.py": "x = 1\n", "c.so": b"\x00" * 10})
        self.addCleanup(shutil.rmtree, root, True)
        real = core._read_prefix

        def deny(path, limit):
            if os.path.basename(path) in ("b.py", "c.so"):
                raise PermissionError(13, "Permission denied")
            return real(path, limit)
        with mock.patch.object(core, "_read_prefix", deny):
            res = core.scan_project(root)
        files = {}
        for i in res["issues"]:
            files.setdefault(i["file"], set()).add(i["rule"])
        self.assertEqual(files["b.py"], {"Q-UNREADABLE"})
        self.assertEqual(files["c.so"], {"Q-UNREADABLE"})
        self.assertIn("S-EVAL-PY", files["a.py"])
        msg = [i["msg"] for i in res["issues"] if i["file"] == "b.py"][0]
        self.assertIn("Permission denied", msg)

    def test_unreadable_subdirectory(self):
        root = make_tree({"a.py": "x = 1\n", "sub/b.py": "eval(x)\n"})
        self.addCleanup(shutil.rmtree, root, True)
        real = os.scandir

        def scandir(path="."):
            if os.path.basename(os.fspath(path)) == "sub":
                raise PermissionError(13, "Permission denied")
            return real(path)
        with mock.patch.object(core.os, "scandir", scandir):
            res = core.scan_project(root)
        subs = [i for i in res["issues"] if i["file"] == "sub"]
        self.assertEqual([i["rule"] for i in subs], ["Q-UNREADABLE"])

    @_support.skip_unless_permissions_enforced
    def test_real_permission_denied(self):
        root = make_tree({"a.py": "x = 1\n", "locked/b.py": "eval(x)\n", "c.py": "eval(y)\n"})
        self.addCleanup(shutil.rmtree, root, True)
        os.chmod(os.path.join(root, "locked"), 0)
        os.chmod(os.path.join(root, "c.py"), 0)
        self.addCleanup(os.chmod, os.path.join(root, "locked"), 0o700)
        p, report, _ = run_cli(root)
        self.assertEqual(p.returncode, 0, p.stderr)
        files = by_file(report)
        self.assertEqual(files["locked"], {"Q-UNREADABLE"})
        self.assertEqual(files["c.py"], {"Q-UNREADABLE"})


@unittest.skipUnless(sys.platform.startswith("linux"), "needs a filesystem that accepts non-UTF-8 names")
class NonUtf8Names(unittest.TestCase):
    def test_reports_are_valid_utf8(self):
        root = make_tree({"ok.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        bad = os.path.join(os.fsencode(root), b"bad\xff.py")
        with open(bad, "wb") as fh:
            fh.write(b"eval(input())\n")
        os.makedirs(os.path.join(os.fsencode(root), b"d\xfe"))
        with open(os.path.join(os.fsencode(root), b"d\xfe", b"x.js"), "wb") as fh:
            fh.write(b"eval(location.hash)\n")
        p, report, blobs = run_cli(root, "--sarif", "r.sarif", html=True)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(set(blobs), {"lazaret-report.json", "lazaret-report.html", "r.sarif"})
        for name, blob in blobs.items():
            blob.decode("utf-8")                       # strict: no surrogates, valid UTF-8
            self.assertNotIn(b"\\udc", blob, name)     # no escaped lone surrogates either
        files = by_file(report)
        self.assertIn("S-EVAL-PY", files["bad\\xff.py"])
        self.assertIn("S-EVAL-JS", files["d\\xfe/x.js"])
        sarif = json.loads(blobs["r.sarif"])
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in sarif["runs"][0]["results"]}
        self.assertIn("bad%5Cxff.py", uris)


class RepeatedCalls(unittest.TestCase):
    """collect_files()/skipped_tree_issues() reset per call (MCP reuse)."""

    def test_skipped_trees_do_not_leak(self):
        a = make_tree({"a.py": "x = 1\n", "node_modules/p/i.js": "x\n"})
        b = make_tree({"b.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, a, True)
        self.addCleanup(shutil.rmtree, b, True)
        core.collect_files(a, [])
        self.assertEqual(len(core.skipped_tree_issues()), 1)
        core.collect_files(b, [])
        self.assertEqual(core.skipped_tree_issues(), [])
        for _ in range(2):
            self.assertEqual(
                [i["file"] for i in core.scan_project(a)["issues"] if i["rule"] == "Q-SKIPPED-TREE"],
                ["node_modules"])
        self.assertFalse([i for i in core.scan_project(b)["issues"] if i["rule"] == "Q-SKIPPED-TREE"])


if __name__ == "__main__":
    unittest.main()
