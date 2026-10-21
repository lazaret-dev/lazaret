"""lazaret guard with the real npm against a fake registry on 127.0.0.1 (tests/registry/_guard_support.py): what
npm resolves under the guard: releases younger than --min-age held back (npm --before), packages for other platforms
left out, and the guard's worker processes scanning. Skipped where npm is not installed. (Split from
test_guard_npm.py; MAC-TESTS.)

The tools run with scripts off (npm_config_ignore_scripts), so no package code runs, blocked or not."""

import shutil
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("npm"), "npm is not installed")
class NpmResolveGuardTests(gs.RegistryCase):
    def test_new_releases_are_held_back(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "fresh-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("releases younger than 2 days are held back (npm --before", out)
        self.assertEqual(self.installed(d, "fresh-pkg"), "1.0.0")        # 1.1.0 is an hour old
        code, out = self.guard(d, "npm", "install", "only-new")         # nothing old enough
        self.assertEqual(code, 3, out)
        self.assertIn("resolving (npm install) failed", out)

    def test_packages_for_other_platforms_are_left_out(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "plat-parent")      # its optional dependency is for AIX
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (package-lock.json; 1 package for other platforms left out)", out)
        self.assertIsNone(self.installed(d, "plat-other"))

    def test_worker_processes_scan_too(self):
        d = gs.project(self.tmp)
        code, out = gs.run_guard(["--jobs", "2", "--no-cache", "npm", "install", "dep-parent"], d, self.env)
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)


if __name__ == "__main__":
    unittest.main()
