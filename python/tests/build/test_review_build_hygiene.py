"""Review fixes for the build backend: what may ship, and byte-identical
artifacts on every OS.

- The backend used to pack every file under src/lazaret except bytecode, so a
  .env, a macOS ._* twin, .DS_Store, an editor swap file or a .orig backup in
  the source tree went to PyPI (a wheel built from an uploaded tree carried 28
  AppleDouble members; `pip install --target` installed lazaret/registry/.env).
  Now only allowlisted files ship and anything else fails the build.
- zipfile marks members as made by MS-DOS on Windows (create_system 0 vs 3
  elsewhere), and a CRLF checkout changed every member: rebuilding a tag was
  only byte-identical on POSIX with LF files.
- Metadata-Version 2.4 (PEP 639): License-Expression + License-File, and no
  "License ::" classifier (PyPI rejects the combination).
"""

import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest import mock

from tests import _support

PY_ROOT = pathlib.Path(_support.PY_ROOT)
TEXT_SUFFIXES = (".py", ".sql", ".html", ".md", ".toml")


def copy_python_tree(dest):
    """The files the backend reads, copied to dest (no caches)."""
    dest = pathlib.Path(dest)
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(PY_ROOT / name, dest / name)
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(PY_ROOT / "_build", dest / "_build", ignore=ignore)
    shutil.copytree(PY_ROOT / "src", dest / "src", ignore=ignore)
    return dest


_loaded = 0


def load_backend(root):
    global _loaded
    _loaded += 1
    return _support.load_script(str(pathlib.Path(root) / "_build" / "lazaret_build.py"),
                                f"lazaret_build_review_{_loaded}")


def old_package_listing(pkg):
    """What the pre-fix backend packed: every file except bytecode."""
    out = []
    for path in sorted(pathlib.Path(pkg).rglob("*")):
        rel = path.relative_to(pkg)
        if path.is_file() and "__pycache__" not in rel.parts and path.suffix not in (".pyc", ".pyo"):
            out.append("lazaret/" + rel.as_posix())
    return out


class Tree:
    """A fresh copy of python/ in a temp dir, with its own backend module."""

    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = copy_python_tree(pathlib.Path(self._tmp.name))
        self.pkg = self.root / "src" / "lazaret"
        self.out = self.root / "out"
        self.out.mkdir()
        self.b = load_backend(self.root)

    def wheel(self):
        return self.out / self.b.build_wheel(str(self.out))

    def sdist(self):
        return self.out / self.b.build_sdist(str(self.out))

    def close(self):
        self._tmp.cleanup()


class AllowlistTests(unittest.TestCase):
    JUNK = [".env", "registry/.env", "scanner/._core.py", ".DS_Store", "web/.DS_Store",
            "x.orig", "scanner/.core.py.swp", "core.py~", "stray.pyc", ".hidden/x.py",
            "notes.txt"]

    def setUp(self):
        self.tree = Tree()
        self.addCleanup(self.tree.close)

    def test_clean_tree_ships_what_it_shipped_before(self):
        expected = old_package_listing(self.tree.pkg)
        self.assertIn("lazaret/registry/schema.sql", expected)
        self.assertIn("lazaret/web/lazaret.html", expected)
        with zipfile.ZipFile(self.tree.wheel()) as z:
            shipped = sorted(n for n in z.namelist() if ".dist-info/" not in n)
        self.assertEqual(shipped, expected)
        with tarfile.open(self.tree.sdist()) as tf:
            base = f"lazaret-{self.tree.b.version()}/"
            names = sorted(n[len(base):] for n in tf.getnames())
        self.assertEqual(names, sorted(["LICENSE", "PKG-INFO", "README.md", "pyproject.toml",
                                        "_build/lazaret_build.py"]
                                       + ["src/" + n for n in expected]))

    def test_bytecode_caches_are_skipped_not_errors(self):
        cache = self.tree.pkg / "scanner" / "__pycache__"
        cache.mkdir(exist_ok=True)
        (cache / "core.cpython-312.pyc").write_bytes(b"\x00" * 16)
        (cache / ".DS_Store").write_bytes(b"x")          # never shipped, so not an error
        (self.tree.root / "_build" / "__pycache__").mkdir(exist_ok=True)
        (self.tree.root / "_build" / "__pycache__" / "lazaret_build.cpython-312.pyc").write_bytes(b"x")
        with zipfile.ZipFile(self.tree.wheel()) as z:
            self.assertFalse([n for n in z.namelist() if "__pycache__" in n or n.endswith(".pyc")])
        with tarfile.open(self.tree.sdist()) as tf:
            self.assertFalse([n for n in tf.getnames() if "__pycache__" in n])

    def test_each_kind_of_junk_fails_both_builds(self):
        for rel in self.JUNK:
            with self.subTest(planted=rel):
                path = self.tree.pkg / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("AWS_SECRET_ACCESS_KEY=dummy-not-a-secret\n")
                try:
                    for build in (self.tree.b.build_wheel, self.tree.b.build_sdist):
                        with self.assertRaises(self.tree.b.UnexpectedFilesError) as cm:
                            build(str(self.tree.out))
                        self.assertIn("src/lazaret/" + rel, str(cm.exception))
                    self.assertEqual(os.listdir(self.tree.out), [])   # nothing half-written
                finally:
                    path.unlink()
                    if rel.startswith(".hidden/"):
                        path.parent.rmdir()

    def test_error_lists_every_offender(self):
        for rel in (".env", "scanner/._core.py", "x.orig"):
            (self.tree.pkg / rel).write_text("x\n")
        with self.assertRaises(self.tree.b.UnexpectedFilesError) as cm:
            self.tree.b.build_wheel(str(self.tree.out))
        msg = str(cm.exception)
        for rel in (".env", "scanner/._core.py", "x.orig"):
            self.assertIn("src/lazaret/" + rel, msg)
        self.assertIn("3 file(s)", msg)

    def test_symlinks_fail_the_build(self):
        target = self.tree.root / "outside.txt"
        target.write_text("not part of the package\n")
        link = self.tree.pkg / "linked.py"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here: {exc}")
        with self.assertRaises(self.tree.b.UnexpectedFilesError) as cm:
            self.tree.b.build_wheel(str(self.tree.out))
        self.assertIn("linked.py", str(cm.exception))

    def test_junk_in_build_dir_fails_the_sdist(self):
        (self.tree.root / "_build" / ".env").write_text("TOKEN=dummy\n")
        with self.assertRaises(self.tree.b.UnexpectedFilesError) as cm:
            self.tree.b.build_sdist(str(self.tree.out))
        self.assertIn("_build/.env", str(cm.exception))

    def test_command_line_reports_the_error_without_a_traceback(self):
        (self.tree.pkg / "registry" / ".env").write_text("DB_PASSWORD=dummy\n")
        p = subprocess.run([sys.executable, str(self.tree.root / "_build" / "lazaret_build.py"),
                            str(self.tree.out)], capture_output=True, encoding="utf-8",
                           errors="replace", timeout=40)
        self.assertEqual(p.returncode, 1)
        self.assertIn("src/lazaret/registry/.env", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual([n for n in os.listdir(self.tree.out) if n.endswith(".whl")], [])


class CrossPlatformBytesTests(unittest.TestCase):
    def setUp(self):
        self.lf = Tree()
        self.addCleanup(self.lf.close)

    def test_every_member_is_unix_made_with_fixed_modes(self):
        with zipfile.ZipFile(self.lf.wheel()) as z:
            for info in z.infolist():
                self.assertEqual(info.create_system, 3, info.filename)
                self.assertEqual(info.external_attr >> 16, stat.S_IFREG | 0o644, info.filename)
        with tarfile.open(self.lf.sdist()) as tf:
            for m in tf.getmembers():
                self.assertTrue(m.isreg(), m.name)
                self.assertEqual((m.mode, m.uid, m.gid, m.uname, m.gname), (0o644, 0, 0, "", ""), m.name)

    def test_wheel_bytes_do_not_depend_on_the_platform(self):
        # zipfile.ZipInfo picks create_system from sys.platform when it is built
        native = self.lf.wheel().read_bytes()
        with tempfile.TemporaryDirectory() as d, mock.patch.object(sys, "platform", "win32"):
            windows = (pathlib.Path(d) / self.lf.b.build_wheel(d)).read_bytes()
        self.assertEqual(native, windows)

    def test_crlf_checkout_builds_the_same_bytes(self):
        crlf = Tree()
        self.addCleanup(crlf.close)
        converted = 0
        for path in crlf.root.rglob("*"):
            if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name == "LICENSE"):
                data = path.read_bytes()
                path.write_bytes(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
                converted += 1
        self.assertGreater(converted, 20)
        crlf.b = load_backend(crlf.root)     # reload the (now CRLF) backend source
        self.assertEqual(self.lf.wheel().read_bytes(), crlf.wheel().read_bytes())
        self.assertEqual(self.lf.sdist().read_bytes(), crlf.sdist().read_bytes())
        with zipfile.ZipFile(crlf.wheel()) as z:
            self.assertNotIn(b"\r\n", z.read("lazaret/web/lazaret.html"))


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = Tree()
        wheel = cls.tree.wheel()
        cls.version = cls.tree.b.version()
        dist_info = f"lazaret-{cls.version}.dist-info"
        with zipfile.ZipFile(wheel) as z:
            cls.meta = z.read(f"{dist_info}/METADATA").decode("utf-8")
            cls.names = z.namelist()
            cls.license = z.read(f"{dist_info}/licenses/LICENSE")
        with tarfile.open(cls.tree.sdist()) as tf:
            base = f"lazaret-{cls.version}/"
            cls.pkg_info = tf.extractfile(base + "PKG-INFO").read().decode("utf-8")
            cls.sdist_license = tf.extractfile(base + "LICENSE").read()
        cls.headers = cls.meta.split("\n\n", 1)[0].splitlines()

    @classmethod
    def tearDownClass(cls):
        cls.tree.close()

    def field(self, name):
        return [h.split(": ", 1)[1] for h in self.headers if h.startswith(name + ": ")]

    def test_pep_639_license_fields(self):
        self.assertEqual(self.headers[0], "Metadata-Version: 2.4")
        self.assertEqual(self.field("License-Expression"), ["Apache-2.0"])
        self.assertEqual(self.field("License-File"), ["LICENSE"])
        self.assertEqual(self.field("License"), [])      # superseded by License-Expression
        self.assertEqual([c for c in self.field("Classifier") if c.startswith("License ::")], [])
        # License-File paths resolve in both artifacts
        self.assertIn(f"lazaret-{self.version}.dist-info/licenses/LICENSE", self.names)
        self.assertEqual(self.license, self.sdist_license)
        self.assertIn(b"Apache License", self.license)

    def test_python_versions_and_urls(self):
        classifiers = self.field("Classifier")
        for minor in range(10, 15):
            self.assertIn(f"Programming Language :: Python :: 3.{minor}", classifiers)
        self.assertEqual(self.field("Requires-Python"), [">=3.10"])
        self.assertEqual(self.field("Project-URL"), [
            "Homepage, https://lazaret.dev",
            "Source, https://github.com/lazaret-dev/lazaret",
            "Issues, https://github.com/lazaret-dev/lazaret/issues",
        ])

    def test_headers_are_well_formed(self):
        for h in self.headers:
            self.assertRegex(h, r"^[A-Z][A-Za-z-]*: \S")
        for single in ("Metadata-Version", "Name", "Version", "Summary", "Requires-Python",
                       "License-Expression", "Description-Content-Type"):
            self.assertEqual(len(self.field(single)), 1, single)

    def test_sdist_pkg_info_matches_the_wheel(self):
        self.assertEqual(self.pkg_info, self.meta)


if __name__ == "__main__":
    unittest.main()
