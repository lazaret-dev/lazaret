"""The stdlib build backend: what the wheel and sdist contain, that they're
reproducible, and that an installed wheel actually works."""

import base64
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from tests import _support

BACKEND = os.path.join(_support.PY_ROOT, "_build", "lazaret_build.py")


def read_member(wheel, name):
    with zipfile.ZipFile(wheel) as z:
        return z.read(name)


def backend(path=BACKEND):
    return _support.load_script(path, f"lazaret_build_{abs(hash(path))}")


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.b = backend()
        cls.wheel = os.path.join(cls.tmp, cls.b.build_wheel(cls.tmp))
        cls.sdist = os.path.join(cls.tmp, cls.b.build_sdist(cls.tmp))
        cls.version = cls.b.version()

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp)

    def names(self):
        with zipfile.ZipFile(self.wheel) as z:
            return z.namelist()

    def test_pyproject_declares_no_requirements(self):
        text = pathlib.Path(_support.PY_ROOT, "pyproject.toml").read_text()
        self.assertRegex(text, r"(?m)^requires = \[\]$")
        self.assertNotIn("[project]", text)  # metadata lives in the backend (see its docstring)
        self.assertEqual(self.b.REQUIRES_DIST, [])
        self.assertEqual(self.b.get_requires_for_build_wheel(), [])

    def test_version_comes_from_the_package(self):
        import lazaret
        self.assertEqual(self.version, lazaret.__version__)
        self.assertTrue(self.wheel.endswith(f"lazaret-{self.version}-py3-none-any.whl"))

    def test_wheel_contents(self):
        names = self.names()
        for must in ("lazaret/__init__.py", "lazaret/scanner/core.py", "lazaret/registry/schema.sql",
                     "lazaret/web/lazaret.html", "lazaret/pg/connection.py", "lazaret/safexml/ElementTree.py",
                     f"lazaret-{self.version}.dist-info/METADATA", f"lazaret-{self.version}.dist-info/RECORD"):
            self.assertIn(must, names)
        for name in names:
            self.assertFalse(name.startswith(("tests/", "_build/")) or "__pycache__" in name
                             or name.endswith((".pyc", ".pyo")), name)

    def test_metadata(self):
        meta = read_member(self.wheel, f"lazaret-{self.version}.dist-info/METADATA").decode()
        self.assertIn(f"Version: {self.version}\n", meta)
        self.assertIn("Requires-Python: >=3.10\n", meta)
        self.assertIn("License-Expression: Apache-2.0\n", meta)   # PEP 639; was "License:"
        self.assertNotIn("Requires-Dist", meta)

    def test_record_hashes_match(self):
        with zipfile.ZipFile(self.wheel) as z:
            record = z.read(f"lazaret-{self.version}.dist-info/RECORD").decode().splitlines()
            self.assertEqual(len(record), len(z.namelist()))
            for line in record:
                name, digest, size = line.rsplit(",", 2)
                if not digest:
                    continue  # RECORD itself
                data = z.read(name)
                expected = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                self.assertEqual((digest, int(size)), (expected, len(data)), name)

    def test_console_scripts_resolve(self):
        ep = read_member(self.wheel, f"lazaret-{self.version}.dist-info/entry_points.txt").decode()
        import importlib
        for name, module, func in re.findall(r"^(\S+) = ([\w.]+):(\w+)$", ep, re.M):
            with self.subTest(script=name):
                self.assertTrue(callable(getattr(importlib.import_module(module), func)))
        self.assertEqual(len(re.findall(r" = ", ep)), 4)

    def test_builds_are_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            again_wheel = os.path.join(d, self.b.build_wheel(d))
            again_sdist = os.path.join(d, self.b.build_sdist(d))
            for first, second in ((self.wheel, again_wheel), (self.sdist, again_sdist)):
                with self.subTest(artifact=os.path.basename(first)):
                    self.assertEqual(pathlib.Path(first).read_bytes(), pathlib.Path(second).read_bytes())

    def test_sdist_contents_and_rebuild(self):
        base = f"lazaret-{self.version}/"
        with tarfile.open(self.sdist) as tf:
            names = tf.getnames()
            for must in ("PKG-INFO", "pyproject.toml", "_build/lazaret_build.py", "LICENSE",
                         "src/lazaret/scanner/core.py", "src/lazaret/registry/schema.sql"):
                self.assertIn(base + must, names)
            self.assertFalse([n for n in names if "/tests/" in n or "__pycache__" in n])
            with tempfile.TemporaryDirectory() as d:
                tf.extractall(d, filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(d)
                # a wheel built from the sdist has the same files as one built from the repo
                inner = backend(os.path.join(d, base, "_build", "lazaret_build.py"))
                rebuilt = os.path.join(d, inner.build_wheel(d))
                with zipfile.ZipFile(rebuilt) as z:
                    self.assertEqual(sorted(z.namelist()), sorted(self.names()))

    def test_installed_wheel_runs_without_the_source_tree(self):
        with tempfile.TemporaryDirectory() as target:
            with zipfile.ZipFile(self.wheel) as z:
                z.extractall(target)
            env = dict(os.environ, PYTHONPATH=target)   # only the installed copy
            check = subprocess.run(
                [sys.executable, "-c", "import lazaret, lazaret.registry.repo, lazaret.mcp.server; print(lazaret.__file__)"],
                capture_output=True, encoding="utf-8", errors="replace", env=env, cwd=target, timeout=60)
            self.assertEqual(check.returncode, 0, check.stderr)
            # compare resolved paths: on macOS the temp dir is a symlink (/var -> /private/var)
            installed = os.path.realpath(check.stdout.strip())
            self.assertTrue(installed.startswith(os.path.realpath(target) + os.sep), check.stdout)
            scan = subprocess.run(
                [sys.executable, "-m", "lazaret", os.path.join(_support.FIXTURES, "testproj"),
                 "--no-html", "--no-json", "-q"],
                capture_output=True, encoding="utf-8", errors="replace", env=env, cwd=target, timeout=120)
            self.assertNotIn("Traceback", scan.stderr)
            self.assertIn("Supply-chain", scan.stdout)

    def test_editable_wheel_points_at_src(self):
        with tempfile.TemporaryDirectory() as d:
            wheel = os.path.join(d, self.b.build_editable(d))
            with zipfile.ZipFile(wheel) as z:
                pth = [n for n in z.namelist() if n.endswith(".pth")]
                self.assertEqual(len(pth), 1)
                self.assertEqual(z.read(pth[0]).decode().strip(), _support.SRC)

    def test_command_line_build(self):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, BACKEND, d], capture_output=True, encoding="utf-8", errors="replace", timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(sorted(os.listdir(d)),
                             sorted([f"lazaret-{self.version}.tar.gz", f"lazaret-{self.version}-py3-none-any.whl"]))


if __name__ == "__main__":
    unittest.main()
