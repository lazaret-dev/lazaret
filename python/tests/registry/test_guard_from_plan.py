"""lazaret guard --from-plan (0.1.9, P-3): pip installs the files the guard
scanned, from a folder, instead of resolving and downloading everything again.

With the real pip and a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py):
the install is the same as without the flag (every file under --target, the
dist-info markers included, with extras, a constraints file and a requirements
file), it asks the index for less, a blocked dependency still blocks, and a file
that is no longer the one that was scanned is blocked, whatever --trust says.
The folder itself (`guard._plan_folder`) is tested on its own below it: a
source distribution, a file too large to scan, a file that changed.

Skipped where there is no venv with pip."""

import contextlib
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.registry import guard, pmsettings
from tests.registry import _guard_support as gs


def pypi_files():
    """The fake index's files, and a package with an extra."""
    files = gs.default_pypi_files()
    name, data = gs.wheel("extra-py", "1.0", {"extra_py/__init__.py": ""},
                          requires=["good-py; extra == 'more'\nProvides-Extra: more"])
    files["extra-py"] = [(name, data, gs.OLD)]
    return files


def tree(target):
    """{relative path: bytes} of what an install put under --target (no bytecode)."""
    out = {}
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for f in files:
            path = os.path.join(root, f)
            with open(path, "rb") as fh:
                out[os.path.relpath(path, target)] = fh.read()
    return out


class FromPlanInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = gs.PypiIndex(pypi_files())
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-from-plan-")
        cls.env = gs.base_env(cls.tmp)
        venv = os.path.join(cls.tmp, "venv")
        proc = subprocess.run([sys.executable, "-m", "venv", venv], capture_output=True)
        bindir = os.path.join(venv, "Scripts" if os.name == "nt" else "bin")
        if proc.returncode != 0 or not os.path.exists(os.path.join(bindir, "pip.exe" if os.name == "nt" else "pip")):
            cls.tearDownClass()
            raise unittest.SkipTest("no venv with pip here (ensurepip missing)")
        cls.pip_env = dict(cls.env, PATH=bindir + os.pathsep + cls.env.get("PATH", ""), VIRTUAL_ENV=venv,
                           LAZARET_GUARD_PYPI_URL=cls.index.url)

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def install(self, name, from_plan, *pip_args):
        """(exit code, output, requests the index got, files under --target)."""
        target = os.path.join(self.tmp, name)
        before = len(self.index.requests)
        code, out = gs.run_guard(["--jobs", "1"] + (["--from-plan"] if from_plan else [])
                                 + ["pip", "install", "--target", target, *pip_args], self.tmp, self.pip_env)
        return code, out, len(self.index.requests) - before, tree(target)

    def test_the_same_install_from_the_folder_asks_the_index_for_less(self):
        code, out, asked, usual = self.install("usual-tool", False, "good-tool")
        self.assertEqual(code, 0, out)
        code, out, asked_folder, folder = self.install("folder-tool", True, "good-tool")
        self.assertEqual(code, 0, out)
        self.assertIn("installing the 2 files it checked, from a folder (--from-plan)", out)
        self.assertIn("good_tool/__init__.py", folder)
        self.assertIn("good_py/__init__.py", folder)
        self.assertEqual(folder, usual)         # the dist-info markers too: REQUESTED, INSTALLER, no direct_url.json
        self.assertFalse([p for p in folder if p.endswith("direct_url.json")])
        self.assertLess(asked_folder, asked)

    def test_extras_a_constraints_file_and_a_requirements_file(self):
        reqs = os.path.join(self.tmp, "requirements.txt")
        cons = os.path.join(self.tmp, "constraints.txt")
        with open(reqs, "w", encoding="utf-8") as f:
            f.write("extra-py[more]\n")
        with open(cons, "w", encoding="utf-8") as f:
            f.write("good-py==1.0\n")
        code, out, _, usual = self.install("usual-reqs", False, "-r", reqs, "-c", cons)
        self.assertEqual(code, 0, out)
        code, out, _, folder = self.install("folder-reqs", True, "-r", reqs, "-c", cons)
        self.assertEqual(code, 0, out)
        self.assertIn("installing the 2 files it checked", out)
        self.assertIn("good_py/__init__.py", folder)    # the extra's dependency
        self.assertEqual(folder, usual)

    def test_a_blocked_dependency_blocks_as_before(self):
        code, out, _, files = self.install("blocked", True, "py-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0 (evil_py-1.0-py3-none-any.whl): SUSPICIOUS", out)
        self.assertNotIn("from a folder", out)
        self.assertEqual(files, {})

    def test_a_plan_with_nothing_to_install_is_left_to_pip(self):
        code, out = gs.run_guard(["--jobs", "1", "pip", "install", "good-py"], self.tmp, self.pip_env)
        self.assertEqual(code, 0, out)
        code, out = gs.run_guard(["--jobs", "1", "--from-plan", "pip", "install", "good-py"], self.tmp, self.pip_env)
        self.assertEqual(code, 0, out)
        self.assertIn("0 packages to check (pip's plan)", out)
        self.assertNotIn("from a folder", out)

    def test_a_file_that_changed_after_the_scan_is_blocked_and_nothing_is_installed(self):
        real = guard._plan_folder

        def tamper(ctx, index):
            for n in index.planned:
                _check, spooled = index.results[n]
                with open(spooled, "ab") as f:
                    f.write(b"\0")
            return real(ctx, index)

        target = os.path.join(self.tmp, "tampered")
        out = io.StringIO()
        # --trust good-py: a reviewed finding is one thing, a file that is not the scanned one is another
        with mock.patch.dict(os.environ, self.pip_env, clear=True), \
                mock.patch.object(guard, "_plan_folder", tamper), contextlib.redirect_stderr(out):
            code = guard.main(["--jobs", "1", "--from-plan", "--trust", "good-py", "pip", "install",
                               "--target", target, "good-py"])
        text = out.getvalue()
        self.assertEqual(code, 1, text)
        self.assertIn("the file changed between the plan and the install", text)
        self.assertIn("nothing was installed", text)
        self.assertFalse(os.path.exists(target))


class PlanFolderTests(unittest.TestCase):
    """guard._plan_folder, with an index whose files are written by hand."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-plan-folder-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.out = io.StringIO()
        self.ctx = self.make_context([])

    def make_context(self, extra):
        opts = guard.build_parser().parse_args(["--min-age", "0", "--no-cache", "--jobs", "1", *extra,
                                                "pip", "install", "x"])
        opts.min_age = guard.parse_duration(opts.min_age)
        ctx = guard.Context(opts, out=self.out)
        self.addCleanup(ctx.close)
        self.index = guard.PypiIndex(ctx, None, self.tmp, indexes=[pmsettings.Index("http://127.0.0.1:9/simple/")])
        return ctx

    def add(self, number, filename, data=b"PK wheel", scanned=True, digest=None):
        """A file the index served and scanned: its spooled bytes and its Check."""
        spooled = os.path.join(self.tmp, f"spool-{number}")
        with open(spooled, "wb") as f:
            f.write(data)
        check = self.ctx.add(guard.Check("pypi", "x", "1.0", filename))
        check.digest = digest or "sha256:" + hashlib.sha256(data).hexdigest()
        self.index.files[number] = {"url": "http://127.0.0.1:9/f", "project": "x", "filename": filename,
                                    "version": "1.0", "sha256": "", "published": None, "size": len(data)}
        self.index.results[number] = (check, spooled if scanned else None)
        self.index.planned = (self.index.planned or []) + [number]
        return check, spooled

    def test_the_files_of_the_plan_are_put_in_a_folder(self):
        self.add("1", "x-1.0-py3-none-any.whl", b"one")
        self.add("2", "y-2.0-py3-none-any.whl", b"two")
        folder = guard._plan_folder(self.ctx, self.index)
        self.assertEqual(sorted(os.listdir(folder)), ["x-1.0-py3-none-any.whl", "y-2.0-py3-none-any.whl"])
        with open(os.path.join(folder, "y-2.0-py3-none-any.whl"), "rb") as f:
            self.assertEqual(f.read(), b"two")
        self.assertEqual(self.ctx.blocked(), [])
        self.assertIn("installing the 2 files it checked", self.out.getvalue())

    def test_no_plan_means_pip_goes_to_the_index(self):
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertEqual(self.out.getvalue(), "")

    def test_a_source_distribution_in_the_plan_means_the_index(self):
        self.add("1", "x-1.0-py3-none-any.whl")
        self.add("2", "y-2.0.tar.gz")
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertIn("y-2.0.tar.gz is a source distribution", self.out.getvalue())
        self.assertEqual(self.ctx.blocked(), [])
        self.assertFalse(os.path.exists(os.path.join(self.index.spool, "plan")))

    def test_a_file_too_large_to_scan_means_the_index(self):
        self.add("1", "x-1.0-py3-none-any.whl", scanned=False)
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertIn("was not scanned in full", self.out.getvalue())
        self.assertEqual(self.ctx.blocked(), [])

    def test_a_folder_that_cannot_be_made_means_the_index(self):
        self.add("1", "x-" + "a" * 300 + "-1.0-py3-none-any.whl")        # a name the file system refuses
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertIn("could not set the folder up", self.out.getvalue())
        self.assertEqual(self.ctx.blocked(), [])

    def test_a_file_that_is_not_the_scanned_one_is_blocked(self):
        check, _ = self.add("1", "x-1.0-py3-none-any.whl", b"scanned", digest="sha256:" + "0" * 64)
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertEqual(len(self.ctx.blocked()), 1)
        self.assertIn("changed between the plan and the install", check.blocked[0])

    def test_trust_does_not_let_a_changed_file_through(self):
        self.ctx = self.make_context(["--trust", "x"])
        check, _ = self.add("1", "x-1.0-py3-none-any.whl", b"scanned", digest="sha256:" + "0" * 64)
        self.assertIsNone(guard._plan_folder(self.ctx, self.index))
        self.assertEqual(len(self.ctx.blocked()), 1)


if __name__ == "__main__":
    unittest.main()
