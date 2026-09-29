"""lazaret guard with the real npm and pnpm, against a fake registry on
127.0.0.1 (tests/registry/_guard_support.py): what is installed, what is
blocked and put back, what is held back as too new, and what is left out as
built for another platform. Skipped where npm or pnpm is not installed.

The tools run with scripts off (npm_config_ignore_scripts), so no package
code runs, blocked or not."""

import json
import os
import shutil
import tempfile
import unittest

from tests.registry import _guard_support as gs


class _RegistryCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = gs.NpmRegistry()
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-guard-npm-")
        cls.env = gs.base_env(cls.tmp)
        cls.env["npm_config_registry"] = cls.registry.url

    @classmethod
    def tearDownClass(cls):
        cls.registry.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def guard(self, cwd, *args):
        return gs.run_guard(["--jobs", "1", *args], cwd, self.env)

    def installed(self, d, name):
        text = gs.read(os.path.join(d, "node_modules", name, "package.json"))
        return json.loads(text)["version"] if text else None


@unittest.skipUnless(shutil.which("npm"), "npm is not installed")
class NpmGuardTests(_RegistryCase):
    def test_a_clean_package_is_installed(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")
        self.assertIn("lazaret guard: checked 1 OK", out)

    def test_a_suspicious_dependency_blocks_the_install_and_puts_the_files_back(self):
        d = gs.project(self.tmp)
        before = gs.read(os.path.join(d, "package.json"))
        code, out = self.guard(d, "npm", "install", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("SC-INSTALL-HOOK (CRITICAL)", out)
        self.assertIn("1 blocked — nothing was installed; package.json and package-lock.json put back", out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])
        self.assertEqual(gs.read(os.path.join(d, "package.json")), before)

    def test_plan_installs_nothing(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--plan", "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("nothing blocked (--plan: nothing was installed", out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])

    def test_new_releases_are_held_back(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "fresh-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("releases younger than 2 days are held back (npm --before", out)
        self.assertEqual(self.installed(d, "fresh-pkg"), "1.0.0")        # 1.1.0 is an hour old
        code, out = self.guard(d, "npm", "install", "only-new")         # nothing old enough
        self.assertEqual(code, 3, out)
        self.assertIn("resolving (npm install) failed", out)

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

    def test_trust_installs_a_blocked_package_and_says_so(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--trust", "evil-*", "npm", "install", "dep-parent")
        self.assertEqual(code, 0, out)
        self.assertIn("TRUSTED    evil-pkg@1.0.0: installed anyway (--trust): SUSPICIOUS", out)
        self.assertEqual(self.installed(d, "evil-pkg"), "1.0.0")

    def test_packages_for_other_platforms_are_left_out(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "plat-parent")      # its optional dependency is for AIX
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (package-lock.json; 1 package for other platforms left out)", out)
        self.assertIsNone(self.installed(d, "plat-other"))

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

    def test_worker_processes_scan_too(self):
        d = gs.project(self.tmp)
        code, out = gs.run_guard(["--jobs", "2", "--no-cache", "npm", "install", "dep-parent"], d, self.env)
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)


@unittest.skipUnless(shutil.which("pnpm"), "pnpm is not installed")
class PnpmGuardTests(_RegistryCase):
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
