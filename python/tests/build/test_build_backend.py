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
import unittest.mock
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
        text = pathlib.Path(_support.PY_ROOT, "pyproject.toml").read_text(encoding="utf-8")
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
        self.assertEqual(len(re.findall(r" = ", ep)), 5)

    def test_every_command_prints_its_version(self):
        """`--version` on each console script of the installed wheel (the
        Python commands had none: which lazaret was on the PATH could only be
        told by importing the package)."""
        ep = read_member(self.wheel, f"lazaret-{self.version}.dist-info/entry_points.txt").decode()
        shown = {"lazaret-guard": "lazaret guard"}
        with tempfile.TemporaryDirectory() as target:
            with zipfile.ZipFile(self.wheel) as z:
                z.extractall(target)
            env = dict(os.environ, PYTHONPATH=target)
            for name, module, func in re.findall(r"^(\S+) = ([\w.]+):(\w+)$", ep, re.M):
                with self.subTest(script=name):
                    code = (f"import sys; from {module} import {func}; sys.argv = [{name!r}, '--version']; "
                            f"sys.exit({func}())")
                    p = subprocess.run([sys.executable, "-c", code], capture_output=True, encoding="utf-8",
                                       errors="replace", env=env, cwd=target, timeout=60)
                    # the scanning commands name the engine they run (engine.py): the
                    # native one where it is installed, else python
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertRegex(p.stdout, "^" + re.escape(f"{shown.get(name, name)} {self.version}")
                                     + (r" \(engine: (?:rust \S+|python)\)" if name in ("lazaret", "lazaret-registry")
                                        else "") + "\n\\Z")

    def test_a_platform_wheel_carries_the_native_engine(self):
        """LAZARET_NATIVE_LIBRARY and LAZARET_WHEEL_PLATFORM make a platform
        wheel with the library where _native.py looks for it; one without
        the other, or a bad tag, stops the build."""
        with tempfile.TemporaryDirectory() as d:
            lib = pathlib.Path(d, "built.so")
            lib.write_bytes(b"\x7fELF-native-engine")
            env = {"LAZARET_NATIVE_LIBRARY": str(lib), "LAZARET_WHEEL_PLATFORM": "manylinux_2_28_x86_64"}
            with unittest.mock.patch.dict(os.environ, env):
                name = self.b.build_wheel(d)
            self.assertEqual(name, f"lazaret-{self.version}-py3-none-manylinux_2_28_x86_64.whl")
            wheel = os.path.join(d, name)
            self.assertEqual(read_member(wheel, "lazaret/_native/liblazaret_native.so"), b"\x7fELF-native-engine")
            info = read_member(wheel, f"lazaret-{self.version}.dist-info/WHEEL").decode()
            self.assertIn("Root-Is-Purelib: false\n", info)
            self.assertIn("Tag: py3-none-manylinux_2_28_x86_64\n", info)
            record = read_member(wheel, f"lazaret-{self.version}.dist-info/RECORD").decode()
            self.assertIn("lazaret/_native/liblazaret_native.so,sha256=", record)
            self.assertEqual(self.b.native_library_name("win_amd64"), "lazaret_native.dll")
            self.assertEqual(self.b.native_library_name("macosx_11_0_arm64"), "liblazaret_native.dylib")
            for bad in ({"LAZARET_NATIVE_LIBRARY": str(lib)}, {"LAZARET_WHEEL_PLATFORM": "win_amd64"},
                        dict(env, LAZARET_WHEEL_PLATFORM="Linux x86"), dict(env, LAZARET_WHEEL_PLATFORM="any"),
                        dict(env, LAZARET_NATIVE_LIBRARY=os.path.join(d, "missing.so"))):
                with self.subTest(env=bad), unittest.mock.patch.dict(os.environ, bad):
                    with self.assertRaises(RuntimeError):
                        self.b.build_wheel(d)
        self.assertNotIn("lazaret/_native/liblazaret_native.so", self.names())      # the pure wheel has none
        with tarfile.open(self.sdist) as t:
            self.assertFalse([n for n in t.getnames() if "/_native/" in n])

    def test_a_platform_wheel_carries_cpythons_license_and_the_notice(self):
        """Part of the native engine is a Rust translation of CPython code
        (rust/NOTICE): a platform wheel carries CPython's LICENSE and that
        notice as license files and declares both licenses. The pure wheel
        and the sdist hold none of that code, and say Apache-2.0 alone."""
        dist_info = f"lazaret-{self.version}.dist-info"
        with tempfile.TemporaryDirectory() as d:
            lib = pathlib.Path(d, "built.so")
            lib.write_bytes(b"\x7fELF-native-engine")
            wheel = os.path.join(d, self.b.build_platform_wheel(d, "manylinux_2_28_x86_64", str(lib)))
            meta = read_member(wheel, f"{dist_info}/METADATA").decode()
            self.assertIn("License-Expression: Apache-2.0 AND Python-2.0.1\n", meta)
            self.assertEqual(re.findall(r"^License-File: (.+)$", meta, re.M), ["LICENSE", "LICENSE-PYTHON", "NOTICE"])
            for name in ("LICENSE-PYTHON", "NOTICE"):
                with self.subTest(name=name):
                    self.assertEqual(read_member(wheel, f"{dist_info}/licenses/{name}"),
                                     pathlib.Path(_support.REPO_ROOT, "rust", name).read_bytes())
            self.assertIn(b"Copyright (c) 2001 Python Software Foundation; All Rights Reserved",
                          read_member(wheel, f"{dist_info}/licenses/LICENSE-PYTHON"))
            with unittest.mock.patch.dict(self.b.NATIVE_LICENSE_FILES, {"NOTICE": pathlib.Path(d, "missing")}):
                with self.assertRaises(RuntimeError) as cm:                 # no notices, no platform wheel
                    self.b.build_platform_wheel(d, "win_amd64", str(lib))
                self.assertIn("missing", str(cm.exception))
        pure = read_member(self.wheel, f"{dist_info}/METADATA").decode()
        self.assertIn("License-Expression: Apache-2.0\n", pure)
        self.assertEqual(re.findall(r"^License-File: (.+)$", pure, re.M), ["LICENSE"])
        self.assertFalse([n for n in self.names() if n.endswith(("/LICENSE-PYTHON", "/NOTICE"))])
        with tarfile.open(self.sdist) as t:
            self.assertFalse([n for n in t.getnames() if n.endswith(("/LICENSE-PYTHON", "/NOTICE"))])
            pkg_info = t.extractfile(f"lazaret-{self.version}/PKG-INFO").read().decode()
        self.assertIn("License-Expression: Apache-2.0\n", pkg_info)

    def test_the_command_line_builds_a_platform_wheel_per_platform(self):
        """Release CI: `lazaret_build.py dist --platform TAG=LIBRARY …` writes the
        sdist, the pure wheel, and one platform wheel per --platform, each the
        pure wheel's files plus its library. A bad --platform stops the build
        before anything is written."""
        env = {k: v for k, v in os.environ.items() if k not in ("LAZARET_NATIVE_LIBRARY", "LAZARET_WHEEL_PLATFORM")}

        def build(out, *args):
            return subprocess.run([sys.executable, BACKEND, out, *args], capture_output=True, encoding="utf-8",
                                  errors="replace", env=env, timeout=40)

        with tempfile.TemporaryDirectory() as d:
            so, dll = pathlib.Path(d, "built.so"), pathlib.Path(d, "built.dll")
            so.write_bytes(b"\x7fELF-linux")
            dll.write_bytes(b"MZ-windows")
            out = os.path.join(d, "dist")
            p = build(out, "--platform", f"manylinux_2_28_x86_64={so}", "--platform", f"win_amd64={dll}")
            self.assertEqual(p.returncode, 0, p.stderr)
            v = self.version
            self.assertEqual(sorted(os.listdir(out)), sorted([
                f"lazaret-{v}.tar.gz", f"lazaret-{v}-py3-none-any.whl",
                f"lazaret-{v}-py3-none-manylinux_2_28_x86_64.whl", f"lazaret-{v}-py3-none-win_amd64.whl"]))

            def members(name):
                with zipfile.ZipFile(os.path.join(out, name)) as z:
                    return {n: z.read(n) for n in z.namelist()}

            pure = members(f"lazaret-{v}-py3-none-any.whl")
            dist_info = f"lazaret-{v}.dist-info/"
            for tag, library, data in (("manylinux_2_28_x86_64", "liblazaret_native.so", b"\x7fELF-linux"),
                                       ("win_amd64", "lazaret_native.dll", b"MZ-windows")):
                with self.subTest(tag=tag):
                    wheel = members(f"lazaret-{v}-py3-none-{tag}.whl")
                    notices = {dist_info + "licenses/LICENSE-PYTHON", dist_info + "licenses/NOTICE"}
                    self.assertEqual(set(wheel) - set(pure), {f"lazaret/_native/{library}"} | notices)
                    self.assertEqual(set(pure) - set(wheel), set())
                    self.assertEqual(wheel[f"lazaret/_native/{library}"], data)
                    for name in pure:
                        if name not in (dist_info + "WHEEL", dist_info + "RECORD", dist_info + "METADATA"):
                            self.assertEqual(wheel[name], pure[name], name)
                    self.assertIn(f"Tag: py3-none-{tag}\n", wheel[dist_info + "WHEEL"].decode())

            for args in (["--platform", "manylinux_2_28_x86_64"], ["--platform", f"any={so}"],
                         ["--platform", f"Linux x86={so}"], ["--platform", f"win_amd64={d}/missing.dll"],
                         ["--platform", f"win_amd64={dll}", "--platform", f"win_amd64={so}"]):
                with self.subTest(args=args):
                    empty = os.path.join(d, "none")
                    p = build(empty, *args)
                    self.assertNotEqual(p.returncode, 0)
                    self.assertIn("--platform", p.stderr)
                    self.assertNotIn("Traceback", p.stderr)
                    self.assertFalse(os.path.exists(empty) and os.listdir(empty))

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
