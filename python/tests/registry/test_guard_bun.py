"""lazaret guard with the real Bun, against a fake registry on 127.0.0.1 (tests/registry/_guard_support.py), and
what keeps one run's tools from answering for another's. Skipped where Bun is not installed. (Split from
test_guard_yarn_bun.py; MAC-TESTS.)

Bun resolves with --lockfile-only, and a blocked package is never installed, so no package code runs."""

import os
import shutil
import tempfile
import time
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("bun"), "bun is not installed")
class BunGuardTests(gs.RegistryCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["BUN_INSTALL_CACHE_DIR"] = os.path.join(cls.tmp, "bun-cache")

    def bun_project(self, install=None):
        d = gs.project(self.tmp)
        with open(os.path.join(d, "bunfig.toml"), "w", encoding="utf-8") as f:
            f.write(install or f'[install]\nregistry = "{self.registry.url}"\n')
        return d

    def test_a_clean_package_is_installed_and_other_platforms_left_out(self):
        d = self.bun_project()
        code, out = self.guard(d, "bun", "add", "good-pkg", "plat-parent")
        self.assertEqual(code, 0, out)
        self.assertIn("2 packages to check (bun.lock; 1 package for other platforms left out)", out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")

    def test_a_suspicious_dependency_blocks_the_install_and_puts_the_files_back(self):
        d = self.bun_project()
        before = gs.read(os.path.join(d, "package.json"))
        code, out = self.guard(d, "bun", "add", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("package.json and bun.lock put back", out)
        self.assertEqual(gs.read(os.path.join(d, "package.json")), before)
        self.assertEqual(sorted(os.listdir(d)), ["bunfig.toml", "package.json"])

    def test_new_releases_are_held_back(self):
        d = self.bun_project()
        code, out = self.guard(d, "bun", "add", "fresh-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("held back (bun --minimum-release-age)", out)
        self.assertEqual(self.installed(d, "fresh-pkg"), "1.0.0")


class IsolationTests(unittest.TestCase):
    """What keeps one run's tools from answering for another's (N-22: pnpm's packuments, kept in ~/.cache by the
    registry's host and port, answered for a test registry that got a port an earlier run's had, with that run's
    tarball digest, and the guard blocked the package as it should)."""

    def test_the_tools_caches_are_the_runs_own(self):
        tmp = tempfile.mkdtemp(prefix="lazaret-guard-isolation-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        env = gs.base_env(tmp)
        for key in ("npm_config_cache", "npm_config_store_dir", "npm_config_cache_dir", "UV_CACHE_DIR",
                    "LAZARET_GUARD_CACHE", "XDG_CONFIG_HOME"):
            with self.subTest(key):
                self.assertTrue(env[key].startswith(tmp), env[key])

    def test_a_package_is_the_same_bytes_whenever_it_is_made(self):
        first = gs.npm_package("good-pkg", "1.0.0", files=gs.GOOD_JS)[0]
        time.sleep(1.1)                                        # (gzip's header held the second it was made)
        self.assertEqual(gs.npm_package("good-pkg", "1.0.0", files=gs.GOOD_JS)[0], first)


if __name__ == "__main__":
    unittest.main()
