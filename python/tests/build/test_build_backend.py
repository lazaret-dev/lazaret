"""The stdlib build backend: what the wheel and sdist contain, that they're
reproducible, and that an installed wheel actually works.

Every wheel carries the native engine (there is no pure wheel since the
Rust-first refactor). The wheels here are built from the library the suite
runs on (LAZARET_NATIVE_LIBRARY, tagged for this machine), so nothing is
compiled; how the backend compiles one with cargo where no library is named
is checked with cargo mocked.
"""

import base64
import contextlib
import hashlib
import io
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


def the_library():
    """The native library the suite runs on (lazaret.scanner._native's)."""
    from lazaret.scanner import _native
    return _native.library_path()


def library_env(b):
    """The environment a wheel of the_library(), for this machine, is built in."""
    return {"LAZARET_NATIVE_LIBRARY": the_library(), "LAZARET_WHEEL_PLATFORM": b.local_platform()}


@unittest.skipUnless(the_library(), "the native library is not built here")
class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.b = backend()
        cls.env = library_env(cls.b)
        with unittest.mock.patch.dict(os.environ, cls.env):
            cls.wheel = os.path.join(cls.tmp, cls.b.build_wheel(cls.tmp))
        cls.sdist = os.path.join(cls.tmp, cls.b.build_sdist(cls.tmp))
        cls.version = cls.b.version()
        cls.platform = cls.b.local_platform()

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
        self.assertTrue(self.wheel.endswith(f"lazaret-{self.version}-py3-none-{self.platform}.whl"))

    def test_the_wheel_carries_the_library(self):
        name = self.b.native_library_name(self.platform)
        self.assertEqual(read_member(self.wheel, f"lazaret/_native/{name}"),
                         pathlib.Path(the_library()).read_bytes())
        info = read_member(self.wheel, f"lazaret-{self.version}.dist-info/WHEEL").decode()
        self.assertEqual(info, "Wheel-Version: 1.0\nGenerator: lazaret_build\nRoot-Is-Purelib: false\n"
                               f"Tag: py3-none-{self.platform}\n")

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
        self.assertIn("License-Expression: Apache-2.0 AND Unicode-3.0\n", meta)   # PEP 639
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
            env = {k: v for k, v in os.environ.items() if k != "LAZARET_NATIVE_LIB"}    # the wheel's own library
            env["PYTHONPATH"] = target
            for name, module, func in re.findall(r"^(\S+) = ([\w.]+):(\w+)$", ep, re.M):
                with self.subTest(script=name):
                    code = (f"import sys; from {module} import {func}; sys.argv = [{name!r}, '--version']; "
                            f"sys.exit({func}())")
                    p = subprocess.run([sys.executable, "-c", code], capture_output=True, encoding="utf-8",
                                       errors="replace", env=env, cwd=target, timeout=60)
                    # the scanning commands name the engine (engine.py): the wheel's library
                    self.assertEqual(p.returncode, 0, p.stderr)
                    self.assertRegex(p.stdout, "^" + re.escape(f"{shown.get(name, name)} {self.version}")
                                     + (re.escape(f" (engine: rust {self.version})")
                                        if name in ("lazaret", "lazaret-registry") else "") + "\n\\Z")

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
        with tarfile.open(self.sdist) as t:
            self.assertFalse([n for n in t.getnames() if "/_native/" in n])

    def test_every_artifact_carries_the_engines_notice(self):
        """Every wheel carries the engine's notice (rust/NOTICE) as a license
        file beside LICENSE and LICENSE-UNICODE and declares Apache-2.0 AND
        Unicode-3.0, and so does the sdist, which carries the engine's source
        (the files at its root, where PKG-INFO's License-File finds them). The
        engine is Lazaret's own since P-16, and no artifact carries CPython's
        license (the codec names the dashboard lists are facts about Python)."""
        dist_info = f"lazaret-{self.version}.dist-info"
        with tempfile.TemporaryDirectory() as d:
            lib = pathlib.Path(d, "built.so")
            lib.write_bytes(b"\x7fELF-native-engine")
            platform_wheel = os.path.join(d, self.b.build_platform_wheel(d, "manylinux_2_28_x86_64", str(lib)))
            for wheel in (self.wheel, platform_wheel):
                with self.subTest(wheel=os.path.basename(wheel)):
                    meta = read_member(wheel, f"{dist_info}/METADATA").decode()
                    self.assertIn("License-Expression: Apache-2.0 AND Unicode-3.0\n", meta)
                    self.assertEqual(re.findall(r"^License-File: (.+)$", meta, re.M),
                                     ["LICENSE", "LICENSE-UNICODE", "NOTICE"])
                    self.assertEqual(read_member(wheel, f"{dist_info}/licenses/NOTICE"),
                                     pathlib.Path(_support.REPO_ROOT, "rust", "NOTICE").read_bytes())
                    with zipfile.ZipFile(wheel) as z:
                        self.assertFalse([n for n in z.namelist() if n.endswith("LICENSE-PYTHON")])
            with unittest.mock.patch.dict(self.b.NATIVE_LICENSE_FILES, {"NOTICE": pathlib.Path(d, "missing")}):
                with self.assertRaises(RuntimeError) as cm:                 # no notices, no platform wheel
                    self.b.build_platform_wheel(d, "win_amd64", str(lib))
                self.assertIn("missing", str(cm.exception))
        base = f"lazaret-{self.version}/"
        with tarfile.open(self.sdist) as t:
            self.assertEqual(t.extractfile(base + "NOTICE").read(),
                             pathlib.Path(_support.REPO_ROOT, "rust", "NOTICE").read_bytes())
            self.assertFalse([n for n in t.getnames() if n.endswith("LICENSE-PYTHON")])
            pkg_info = t.extractfile(base + "PKG-INFO").read().decode()
        self.assertEqual(pkg_info, read_member(self.wheel, f"{dist_info}/METADATA").decode())

    def test_the_command_line_builds_a_platform_wheel_per_platform(self):
        """Release CI: `lazaret_build.py dist --platform TAG=LIBRARY …` writes the
        sdist and one platform wheel per --platform (and no wheel for this
        machine), each the same files plus its library. A bad --platform
        stops the build before anything is written."""
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
                f"lazaret-{v}.tar.gz",
                f"lazaret-{v}-py3-none-manylinux_2_28_x86_64.whl", f"lazaret-{v}-py3-none-win_amd64.whl"]))

            def members(name):
                with zipfile.ZipFile(os.path.join(out, name)) as z:
                    return {n: z.read(n) for n in z.namelist()}

            linux, windows = (members(f"lazaret-{v}-py3-none-{tag}.whl") for tag in ("manylinux_2_28_x86_64",
                                                                                     "win_amd64"))
            dist_info = f"lazaret-{v}.dist-info/"
            self.assertEqual(linux["lazaret/_native/liblazaret_native.so"], b"\x7fELF-linux")
            self.assertEqual(windows["lazaret/_native/lazaret_native.dll"], b"MZ-windows")
            self.assertEqual(set(linux) - {"lazaret/_native/liblazaret_native.so"},
                             set(windows) - {"lazaret/_native/lazaret_native.dll"})
            for name in linux:
                if not name.startswith("lazaret/_native/") and name not in (dist_info + "WHEEL", dist_info + "RECORD"):
                    self.assertEqual(linux[name], windows[name], name)
            self.assertEqual(self.names_of(linux), self.names_of(self.member_map(self.wheel)))

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

    @staticmethod
    def member_map(wheel):
        with zipfile.ZipFile(wheel) as z:
            return {n: z.read(n) for n in z.namelist()}

    @staticmethod
    def names_of(members):
        """A wheel's member names, its library's as lazaret/_native/*."""
        return sorted("lazaret/_native/*" if n.startswith("lazaret/_native/") else n for n in members)

    def test_builds_are_reproducible(self):
        with tempfile.TemporaryDirectory() as d:
            with unittest.mock.patch.dict(os.environ, self.env):
                again_wheel = os.path.join(d, self.b.build_wheel(d))
            again_sdist = os.path.join(d, self.b.build_sdist(d))
            for first, second in ((self.wheel, again_wheel), (self.sdist, again_sdist)):
                with self.subTest(artifact=os.path.basename(first)):
                    self.assertEqual(pathlib.Path(first).read_bytes(), pathlib.Path(second).read_bytes())

    def test_sdist_contents_and_rebuild(self):
        base = f"lazaret-{self.version}/"
        with tarfile.open(self.sdist) as tf:
            names = tf.getnames()
            for must in ("PKG-INFO", "pyproject.toml", "_build/lazaret_build.py", "LICENSE", "LICENSE-UNICODE",
                         "NOTICE", "src/lazaret/scanner/core.py", "src/lazaret/registry/schema.sql",
                         # the engine's sources, which pip compiles where no platform wheel fits
                         "rust/Cargo.toml", "rust/Cargo.lock", "rust/NOTICE", "rust/LICENSE-UNICODE",
                         "rust/crates/lazaret-engine/Cargo.toml", "rust/crates/lazaret-engine/src/lib.rs",
                         "rust/crates/lazaret-engine/rules/lazaret-rules.json",
                         "rust/crates/lazaret-ffi/Cargo.toml", "rust/crates/lazaret-ffi/src/lib.rs",
                         # the network layer (NET-1), and the library it is built on, which ships with its licence
                         "rust/crates/lazaret-net/Cargo.toml", "rust/crates/lazaret-net/src/lib.rs",
                         "rust/crates/lazaret-verify/Cargo.toml", "rust/crates/lazaret-verify/src/lib.rs",
                         "rust/crates/tiny_https/Cargo.toml", "rust/crates/tiny_https/LICENSE",
                         "rust/crates/tiny_https/src/lib.rs", "rust/crates/tiny_https/src/http/hostrules.rs",
                         # the Sigstore TUF root tiny_https builds in (src/tuf.rs)
                         "rust/crates/tiny_https/roots/sigstore_tuf_root.json"):
                self.assertIn(base + must, names)
            # tiny_https's test and example sources ship (cargo reads every target its manifest declares before it
            # builds any), and nothing else of its tests: no data, no vectors, no documents
            vendored = base + "rust/crates/tiny_https/"
            self.assertFalse([n for n in names if ("/tests/" in n or "/examples/" in n)
                              and not (n.startswith(vendored) and n.endswith(".rs") and "/tests/data/" not in n)])
            self.assertFalse([n for n in names if n.startswith(vendored) and n.endswith((".md", ".txt", ".json", ".der",
                                                                                          ".pem", ".sha256"))
                              and n != vendored + "roots/sigstore_tuf_root.json"])
            self.assertFalse([n for n in names if "__pycache__" in n or "/target/" in n
                              or "/." in n or n.endswith((".so", ".dll", ".dylib"))])
            with tempfile.TemporaryDirectory() as d:
                tf.extractall(d, filter="data") if hasattr(tarfile, "data_filter") else tf.extractall(d)
                # a wheel built from the sdist (with the same library) is the one built from the repo
                inner = backend(os.path.join(d, base, "_build", "lazaret_build.py"))
                self.assertEqual(inner.RUST, pathlib.Path(d, base, "rust").resolve())
                with unittest.mock.patch.dict(os.environ, self.env):
                    rebuilt = os.path.join(d, inner.build_wheel(d))
                self.assertEqual(pathlib.Path(rebuilt).read_bytes(), pathlib.Path(self.wheel).read_bytes())
                # and so is an sdist built from it
                again = os.path.join(d, "again")
                os.mkdir(again)
                self.assertEqual(pathlib.Path(again, inner.build_sdist(again)).read_bytes(),
                                 pathlib.Path(self.sdist).read_bytes())

    def test_a_stray_file_among_the_engines_sources_stops_the_sdist(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d, "rust")
            for rel, path in self.b._rust_files():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_bytes(path.read_bytes())
            (root / "crates" / "lazaret-engine" / "src" / "lib.rs.orig").write_text("// old\n", encoding="utf-8")
            (root / "crates" / "lazaret-engine" / "examples").mkdir()
            (root / "crates" / "lazaret-engine" / "examples" / "x.rs").write_text("fn main() {}\n", encoding="utf-8")
            with unittest.mock.patch.object(self.b, "RUST", root):
                with self.assertRaises(self.b.UnexpectedFilesError) as cm:
                    self.b._rust_files()
                self.assertIn("lib.rs.orig", str(cm.exception))
                (root / "crates" / "lazaret-engine" / "src" / "lib.rs.orig").unlink()
                shipped = [rel for rel, _path in self.b._rust_files()]
                self.assertNotIn("crates/lazaret-engine/examples/x.rs", shipped)     # examples never ship
                (root / "Cargo.lock").unlink()
                with self.assertRaises(RuntimeError) as cm:
                    self.b._rust_files()
                self.assertIn("Cargo.lock", str(cm.exception))

    def test_installed_wheel_runs_without_the_source_tree(self):
        with tempfile.TemporaryDirectory() as target:
            with zipfile.ZipFile(self.wheel) as z:
                z.extractall(target)
            env = {k: v for k, v in os.environ.items() if k != "LAZARET_NATIVE_LIB"}
            env["PYTHONPATH"] = target                  # only the installed copy, and its library
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

    def test_editable_wheel_points_at_src_and_places_the_library(self):
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d, "src")
            (src / "lazaret").mkdir(parents=True)
            with unittest.mock.patch.object(self.b, "SRC", src), unittest.mock.patch.dict(os.environ, self.env):
                wheel = os.path.join(d, self.b.build_editable(d))
            with zipfile.ZipFile(wheel) as z:
                pth = [n for n in z.namelist() if n.endswith(".pth")]
                self.assertEqual(len(pth), 1)
                self.assertEqual(z.read(pth[0]).decode().strip(), str(src))
                self.assertFalse([n for n in z.namelist() if "/_native/" in n])
            placed = src / "lazaret" / "_native" / self.b.native_library_name(self.platform)
            self.assertEqual(placed.read_bytes(), pathlib.Path(the_library()).read_bytes())

    def test_an_editable_installs_library_never_ships(self):
        """src/lazaret/_native/ (where build_editable puts the library) is not
        packed from the tree: the wheel's library is the one it is built with."""
        with tempfile.TemporaryDirectory() as d:
            pkg = pathlib.Path(d, "lazaret")
            (pkg / "_native").mkdir(parents=True)
            (pkg / "__init__.py").write_text("__version__ = '0'\n", encoding="utf-8")
            (pkg / "_native" / "liblazaret_native.so").write_bytes(b"\x7fELF-stale")
            with unittest.mock.patch.object(self.b, "PKG", pkg):
                self.assertEqual([p.name for p in self.b._package_files()], ["__init__.py"])

    def test_command_line_build(self):
        env = dict(os.environ, **self.env)
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, BACKEND, d], capture_output=True, encoding="utf-8", errors="replace",
                               env=env, timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(sorted(os.listdir(d)), sorted([f"lazaret-{self.version}.tar.gz",
                                                            f"lazaret-{self.version}-py3-none-{self.platform}.whl"]))


class CargoTests(unittest.TestCase):
    """Where no library is named, the backend compiles one with cargo (cargo
    itself mocked here: what it runs, and the errors it gives)."""

    def setUp(self):
        self.b = backend()
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("LAZARET_NATIVE_LIBRARY", "LAZARET_WHEEL_PLATFORM", "CARGO", "CARGO_TARGET_DIR")}
        quiet = contextlib.redirect_stderr(io.StringIO())       # (the backend says what it runs)
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def test_without_cargo_the_build_says_what_to_do(self):
        with unittest.mock.patch.dict(os.environ, self.env, clear=True), \
                unittest.mock.patch("shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as cm:
                self.b.build_wheel(tempfile.gettempdir())
        self.assertIn("cargo was not found", str(cm.exception))
        self.assertIn("https://rustup.rs", str(cm.exception))
        self.assertIn("--only-binary", str(cm.exception))

    def test_what_cargo_is_asked_and_what_it_builds(self):
        # (build_native loads the library it built, in this process: Windows
        # can't delete a loaded DLL, so the directory may outlive the test there)
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            target = pathlib.Path(d, "target")
            name = self.b.native_library_name(self.b.local_platform())
            ran = []

            def cargo(cmd, cwd=None, env=None, stdout=None):
                ran.append((cmd, cwd, env))
                (target / "release").mkdir(parents=True, exist_ok=True)
                (target / "release" / name).write_bytes(pathlib.Path(the_library()).read_bytes())
                return subprocess.CompletedProcess(cmd, 0)

            env = dict(self.env, CARGO="/opt/cargo/bin/cargo", CARGO_TARGET_DIR=str(target))
            with unittest.mock.patch.dict(os.environ, env, clear=True), \
                    unittest.mock.patch("subprocess.run", side_effect=cargo):
                library = self.b.build_native()
            self.assertEqual(library, target / "release" / name)
            (cmd, cwd, used), = ran
            self.assertEqual(cmd, ["/opt/cargo/bin/cargo", "build", "--release", "--offline", "--locked",
                                   "-p", "lazaret-ffi"])
            self.assertEqual(cwd, self.b.RUST)
            if sys.platform == "darwin":
                self.assertIn(used["MACOSX_DEPLOYMENT_TARGET"], ("11.0", "10.12"))
            if sys.platform == "win32":
                self.assertIn("+crt-static", used["RUSTFLAGS"])

    def test_a_failed_or_foreign_build_stops(self):
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d, "target")
            env = dict(self.env, CARGO="cargo", CARGO_TARGET_DIR=str(target))
            with unittest.mock.patch.dict(os.environ, env, clear=True):
                with unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 101)):
                    with self.assertRaises(RuntimeError) as cm:
                        self.b.build_native()
                    self.assertIn("cargo exited with 101", str(cm.exception))
                with unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
                    with self.assertRaises(RuntimeError) as cm:             # nothing built
                        self.b.build_native()
                    self.assertIn("built no", str(cm.exception))
                (target / "release").mkdir(parents=True)
                (target / "release" / self.b.native_library_name(self.b.local_platform())).write_bytes(b"not a library")
                with unittest.mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0)):
                    with self.assertRaises(RuntimeError) as cm:             # it does not load here
                        self.b.build_native()
                    self.assertIn("does not load", str(cm.exception))

    def test_the_local_platform_tag(self):
        tag = self.b.local_platform()
        self.assertRegex(tag, r"\A[a-z0-9_]+\Z")
        self.assertNotEqual(tag, "any")
        with unittest.mock.patch("sysconfig.get_platform", return_value="linux-x86_64"):
            self.assertEqual(self.b.local_platform(), "linux_x86_64")
        with unittest.mock.patch("sysconfig.get_platform", return_value="win-amd64"):
            self.assertEqual(self.b.local_platform(), "win_amd64")
        for machine, want in (("arm64", "macosx_11_0_arm64"), ("x86_64", "macosx_10_12_x86_64")):
            with unittest.mock.patch("sysconfig.get_platform", return_value="macosx-10.9-universal2"), \
                    unittest.mock.patch("platform.machine", return_value=machine):
                self.assertEqual(self.b.local_platform(), want)


if __name__ == "__main__":
    unittest.main()
