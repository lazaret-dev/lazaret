"""lazaret guard with the real npm against a fake registry on 127.0.0.1 (tests/registry/_guard_support.py): what a
lockfile holds is checked as it is (npm ci): a locked release younger than --min-age, a tarball that is not the
lockfile's, and a verdict reused without a download. Skipped where npm is not installed. (Split from
test_guard_npm.py; MAC-TESTS.)

The tools run with scripts off (npm_config_ignore_scripts), so no package code runs, blocked or not."""

import json
import os
import shutil
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("npm"), "npm is not installed")
class NpmLockfileGuardTests(gs.RegistryCase):
    def test_a_locked_new_release_is_blocked(self):
        """npm ci installs what the lockfile says, whatever `before` is: the
        guard checks the age itself (the tarball's Last-Modified, confirmed by
        the registry's `time`)."""
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--min-age", "0", "npm", "install", "fresh-pkg@1.1.0")
        self.assertEqual(code, 0, out)
        shutil.rmtree(os.path.join(d, "node_modules"))
        code, out = self.guard(d, "npm", "ci")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    fresh-pkg@1.1.0: published 1 hour ago, under --min-age 2 days "
                      "(--allow-new fresh-pkg lets it through)", out)
        self.assertFalse(os.path.exists(os.path.join(d, "node_modules")))
        code, out = self.guard(d, "--allow-new", "fresh-pkg", "npm", "ci")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "fresh-pkg"), "1.1.0")
        self.assertIn("let through by --allow-new", out)

    def test_a_verdict_is_reused_without_a_download(self):
        a = gs.project(self.tmp)
        code, out = self.guard(a, "npm", "install", "@scope/good")
        self.assertEqual(code, 0, out)
        b = gs.project(self.tmp)
        for name in ("package.json", "package-lock.json"):
            shutil.copy(os.path.join(a, name), os.path.join(b, name))
        seen = len(self.registry.requests)
        code, out = self.guard(b, "npm", "ci")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(b, "@scope/good"), "2.0.0")
        self.assertEqual([p for ua, p in self.registry.requests[seen:] if ua.startswith("lazaret-guard")], [])

    def test_a_tarball_that_is_not_the_lockfiles_is_blocked(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--plan", "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        code, out = self.guard(d, "npm", "install", "good-pkg", "--package-lock-only")
        lock_path = os.path.join(d, "package-lock.json")
        lock = json.loads(gs.read(lock_path))
        lock["packages"]["node_modules/good-pkg"]["integrity"] = self.registry.integrity("evil-pkg", "1.0.0")
        with open(lock_path, "w", encoding="utf-8") as f:
            json.dump(lock, f)
        code, out = self.guard(d, "--no-cache", "npm", "ci")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    good-pkg@1.0.0: its sha512 digest is not the lockfile's", out)


if __name__ == "__main__":
    unittest.main()
