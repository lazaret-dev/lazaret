"""lazaret guard with the real pip, against a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py), through the
guard's local index (every file scanned before pip gets it; files younger than --min-age left out of it): what is
installed and blocked, a local archive refused, an sdist scanned before pip can build it. Skipped where a tool is
missing. (The indexes pip is given: test_guard_pip_indexes.py; uv: test_guard_uv.py, test_guard_uv_tool.py,
test_guard_uv_project.py.)

(MAC-TESTS: the guard's tests of the real tools are split into modules of a few tests each, so each module
runs well inside the 45 s a module gets alone, on a Mac too, where starting the tools and the guard's
workers takes longer: test_guard_npm, _npm_lockfile, _npm_resolve, _pnpm, _yarn, _bun, _private_registry,
_python, _pip_indexes, _uv, _uv_tool, _uv_project.)

A blocked package is never handed to the tool, so its code never runs."""

import unittest

from tests.registry import _guard_support as gs
from tests.registry._guard_support import venv_has


class PipGuardTests(gs.PipCase):
    def test_a_clean_package_is_installed(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (pip's plan)", out)
        self.assertTrue(venv_has(self.venv, "good_py"))

    def test_a_suspicious_dependency_blocks_the_install(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "py-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0 (evil_py-1.0-py3-none-any.whl): SUSPICIOUS", out)
        self.assertIn("SC-SITECUSTOMIZE (CRITICAL)", out)
        self.assertFalse(venv_has(self.venv, "py_parent") or venv_has(self.venv, "evil_py"))

    def test_local_archives_are_refused(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "--find-links", "./wheels", "good-py")
        self.assertEqual(code, 2, out)
        self.assertIn("install without local archives", out)

    def test_new_releases_are_left_out_of_the_index(self):
        code, out = self.guard(self.tmp, self.pip_env, "--plan", "pip", "install", "fresh-py")
        self.assertEqual(code, 0, out)
        self.assertIn("held back  fresh-py: 1 release younger than 2 days", out)
        self.assertIn("nothing blocked (--plan: nothing was installed)", out)
        self.assertFalse(venv_has(self.venv, "fresh_py"))

    def test_an_sdist_is_scanned_before_pip_can_build_it(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "evil-sdist")
        self.assertEqual(code, 1, out)
        self.assertIn("opens a reverse shell", out)


if __name__ == "__main__":
    unittest.main()
