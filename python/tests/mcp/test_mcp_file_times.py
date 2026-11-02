"""LZ-03 on Windows, the review of its round 3 (HIGH): an edited file read as another file on the real disk.

The walk lstat's each entry Windows' listing gives no file ID (core._Root.listdir), and held the file to that lstat's
st_ctime_ns, the read's fstat to the same. On Windows with Python 3.12 and later the two calls fill st_ctime from
different times: os.lstat and os.stat the creation time (posixmodule.c's win32_xstat copies st_birthtime into it), and
os.fstat the change time (fileutils.c's _Py_fstat_noraise: FILE_BASIC_INFO.ChangeTime). So a file written or given its
times after it was made (an edited file, a checked-out one, a package extracted with its times), unchanged during the
call, was another file at its read: SC-TRUNCATED, the call incomplete and the gate FAILED. The walk now holds a file to
its creation time there (core._held_time: st_birthtime_ns from 3.12; st_ctime_ns on 3.10 and 3.11, the creation time in
every call), and to its change time on POSIX as before.

Nothing is stood in for here: the files are written on this system's disk, then, well past one tick of its clock,
written again or given other times, so that a file's change time is not its creation time. On Windows with Python 3.12
or later these tests fail without the fix (test_mcp_path_race.WithoutFileIdsTests stands in for those calls on any
system); elsewhere they hold as before. Fixtures are inert text files in a temporary directory; no link is made."""

import contextlib
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.scanner import core

TOOLS = (("scan_directory", server.tool_scan_directory), ("quality_gate", server.tool_quality_gate))
FILES = {"package.json": '{"name": "x", "version": "1.0.0"}\n', "a.py": "x = 1\n", "lib/b.js": "module.exports = 1;\n",
         "lib/c.py": "y = 2\n"}
#: Well past one tick of the system's clock (NTFS stamps a file's times from it, some 15.6 ms a tick; FAT's two
#: seconds are not met here: the tests' folder is the system's temporary one).
TICKS = 0.25
#: 2020-09-13, a time set back
SET_BACK_NS = 1_600_000_000_000_000_000
CHANGED = "changed while the tree was read"


class EditedFileTests(unittest.TestCase):
    """A tree whose files were written after they were made: a.py written again, lib/b.js's times set back,
    package.json's set to now, lib/c.py as it was written."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="lz-mcp-times-")
        self.addCleanup(shutil.rmtree, self.base, True)
        patch = mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": self.base})
        patch.start()
        self.addCleanup(patch.stop)
        for rel, text in FILES.items():
            os.makedirs(os.path.dirname(self.at(rel)), exist_ok=True)
            self.write(rel, text)
        time.sleep(TICKS)
        self.write("a.py", "x = 2\n")
        os.utime(self.at("lib/b.js"), ns=(SET_BACK_NS, SET_BACK_NS))
        os.utime(self.at("package.json"))

    def at(self, rel):
        return os.path.join(self.base, *rel.split("/"))

    def write(self, rel, text):
        with open(self.at(rel), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)

    def stats(self, rel):
        """(lstat, stat, fstat) of `rel`."""
        fd = os.open(self.at(rel), os.O_RDONLY | getattr(os, "O_BINARY", 0))
        try:
            fst = os.fstat(fd)
        finally:
            os.close(fd)
        return os.lstat(self.at(rel)), os.stat(self.at(rel)), fst

    def test_a_files_fstat_is_the_file_its_lstat_recorded(self):
        # (the walk's record of a file, from its lstat, and a read's fstat of it, unchanged between them)
        for rel in FILES:
            with self.subTest(file=rel):
                lst, _st, fst = self.stats(rel)
                self.assertEqual((fst.st_dev, fst.st_ino), (lst.st_dev, lst.st_ino))
                self.assertTrue(core._same_file(fst, core._file_record(lst)))
                self.assertTrue(core._same_entry(lst, (lst.st_dev, lst.st_ino, lst.st_mode & 0o170000)
                                                 + core._file_record(lst)[2:]))

    def test_each_call_gives_a_file_the_same_held_time(self):
        for rel in FILES:
            with self.subTest(file=rel):
                lst, st, fst = self.stats(rel)
                self.assertEqual({core._held_time(s) for s in (lst, st, fst)}, {core._held_time(lst)})
                if os.name != "nt":                         # (POSIX: its change time, which only the system sets)
                    self.assertEqual(core._held_time(lst), lst.st_ctime_ns)

    @unittest.skipUnless(os.name == "nt", "Windows' stat calls")
    def test_windows_fills_the_times_as_cpythons_sources_say(self):
        # (what the fix stands on, and what made the HIGH: read in CPython 3.10.11 to 3.14.0's posixmodule.c and
        # fileutils.c; a.py was written again, lib/b.js and package.json given times, all well after they were made)
        for rel in ("a.py", "lib/b.js", "package.json"):
            with self.subTest(file=rel):
                lst, st, fst = self.stats(rel)
                if sys.version_info >= (3, 12):
                    self.assertEqual({lst.st_birthtime_ns, st.st_birthtime_ns}, {fst.st_birthtime_ns})
                    self.assertEqual(lst.st_ctime_ns, lst.st_birthtime_ns)          # (win32_xstat's copy)
                    if sys.version_info < (3, 15):          # (the HIGH's cause: the change time, the versions read)
                        self.assertNotEqual(fst.st_ctime_ns, lst.st_ctime_ns)
                else:
                    self.assertFalse(hasattr(lst, "st_birthtime_ns"))
                    self.assertEqual({lst.st_ctime_ns, st.st_ctime_ns}, {fst.st_ctime_ns})

    def test_an_edited_tree_is_complete_and_passes(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                out = tool({"path": self.base})
                self.assertFalse(out.get("incomplete"), out)
                self.assertEqual(out["qualityGate"], "PASSED", out)
                if name == "scan_directory":
                    self.assertFalse([i for i in out["issues"] if i["rule"] in ("SC-TRUNCATED", "Q-UNREADABLE")],
                                     out["issues"])
        res = core.scan_project(self.base)                  # (the command line's pipeline)
        self.assertFalse(res.get("incomplete"), res.get("incompleteReason"))
        self.assertFalse([i for i in res["issues"] if i["rule"] in ("SC-TRUNCATED", "Q-UNREADABLE")], res["issues"])

    @contextlib.contextmanager
    def replaced_once_listed(self, rel):
        """`rel` replaced by a copy of it with its times (another file: another inode or file ID, the same text, size
        and times) once the walk has listed the root, before it reads anything."""
        real_listdir, real_walk = core._Root.listdir, core._walk
        state = {"walking": False, "swapped": False}

        def walk(tree, *args, **kwargs):
            state["walking"] = True
            try:
                return real_walk(tree, *args, **kwargs)
            finally:
                state["walking"] = False

        def listdir(tree, parts=(), **kwargs):
            got = real_listdir(tree, parts, **kwargs)
            if state["walking"] and not state["swapped"] and tuple(parts) == () and kwargs.get("identify", True):
                state["swapped"] = True
                at = self.at(rel)
                st = os.stat(at)
                shutil.copyfile(at, at + ".new")
                os.utime(at + ".new", ns=(st.st_atime_ns, st.st_mtime_ns))
                os.replace(at + ".new", at)
            return got
        with mock.patch.object(core._Root, "listdir", listdir), mock.patch.object(core, "_walk", walk):
            yield
        self.assertTrue(state["swapped"], "the file was replaced")

    def test_a_file_replaced_by_a_copy_is_still_a_change(self):
        for name, tool in TOOLS + (("scan_project", None),):
            with self.subTest(tool=name):
                with self.replaced_once_listed("a.py"):
                    out = tool({"path": self.base}) if tool else core.scan_project(self.base)
                self.assertTrue(out.get("incomplete"), out)
                if tool:
                    self.assertEqual(out["qualityGate"], "FAILED", out)
                if name != "quality_gate":
                    found = [i for i in out["issues"] if i["rule"] == "SC-TRUNCATED"]
                    self.assertEqual([(i["file"], i["sev"]) for i in found], [("a.py", "CRITICAL")], out["issues"])
                    self.assertIn(CHANGED, found[0]["msg"])


if __name__ == "__main__":
    unittest.main()
