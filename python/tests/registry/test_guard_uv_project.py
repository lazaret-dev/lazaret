"""lazaret guard with the real uv, against a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py): uv's project
commands, the new uv.lock checked before anything is installed. Skipped where uv is not installed. (Split from
test_guard_python.py; MAC-TESTS.)

A blocked package is never handed to the tool, so its code never runs."""

import os
import shutil
import sys
import tempfile
import unittest

from tests.registry import _guard_support as gs
from tests.registry._guard_support import venv_has


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvProjectGuardTests(gs.IndexCase):
    PYPROJECT = ('[project]\nname = "guardtest"\nversion = "0.1.0"\nrequires-python = ">=3.8"\n'
                 'dependencies = []\n')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.uv_env = dict(cls.env, UV_DEFAULT_INDEX=cls.index.url.rstrip("/"), UV_PYTHON=sys.executable)

    def project(self):
        d = tempfile.mkdtemp(prefix="uvproj-", dir=self.tmp)
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(self.PYPROJECT)
        return d

    def test_add_a_clean_package(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (uv.lock)", out)
        self.assertTrue(venv_has(os.path.join(d, ".venv"), "good_py"))
        code, out = self.guard(d, self.uv_env, "uv", "sync")                      # nothing new
        self.assertEqual(code, 0, out)
        self.assertIn("0 packages to check (uv.lock)", out)

    def test_a_suspicious_dependency_blocks_and_puts_the_files_back(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "py-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0 (evil_py-1.0-py3-none-any.whl): SUSPICIOUS", out)
        self.assertIn("pyproject.toml and uv.lock put back", out)
        self.assertEqual(gs.read(os.path.join(d, "pyproject.toml")), self.PYPROJECT)
        self.assertFalse(os.path.exists(os.path.join(d, "uv.lock")))

    def test_a_new_release_is_blocked_unless_allowed(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "fresh-py")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    fresh-py@1.1 (fresh_py-1.1-py3-none-any.whl): published 1 hour ago", out)
        code, out = self.guard(d, self.uv_env, "--allow-new", "fresh-py", "uv", "add", "fresh-py")
        self.assertEqual(code, 0, out)
        self.assertIn("let through by --allow-new", out)

    def test_lock_checks_and_installs_nothing(self):
        d = self.project()
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(self.PYPROJECT.replace("dependencies = []", 'dependencies = ["py-parent"]'))
        code, out = self.guard(d, self.uv_env, "uv", "lock")
        self.assertEqual(code, 1, out)
        self.assertFalse(os.path.exists(os.path.join(d, "uv.lock")))
        self.assertFalse(os.path.exists(os.path.join(d, ".venv")))


if __name__ == "__main__":
    unittest.main()
