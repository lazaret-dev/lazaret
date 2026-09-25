"""Review fix for the build backend's metadata: Metadata-Version 2.4
(PEP 639) with License-Expression + License-File, no "License ::" classifier
(PyPI rejects the combination), Python 3.10-3.14 classifiers and the project
URLs, identical in the wheel's METADATA and the sdist's PKG-INFO.
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
