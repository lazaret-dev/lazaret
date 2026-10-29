"""lazaret guard with the real pnpm, against a fake registry on 127.0.0.1 (tests/registry/_guard_support.py): what is
installed, what is blocked and put back, and --plan. Skipped where pnpm is not installed. (Split from
test_guard_npm.py; MAC-TESTS.)

The tools run with scripts off (npm_config_ignore_scripts), so no package code runs, blocked or not."""

import os
import shutil
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("pnpm"), "pnpm is not installed")
class PnpmGuardTests(gs.RegistryCase):
    def test_a_clean_package_is_installed(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "pnpm", "add", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")

    def test_a_suspicious_dependency_blocks_the_install_and_puts_the_files_back(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "pnpm", "add", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("package.json and pnpm-lock.yaml put back", out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])

    def test_plan_installs_nothing(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--plan", "pnpm", "add", "fresh-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])


if __name__ == "__main__":
    unittest.main()
