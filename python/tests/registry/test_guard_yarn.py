"""lazaret guard with the real yarn (1 and 2+), against a fake registry on 127.0.0.1
(tests/registry/_guard_support.py). Skipped where a tool is not installed; yarn 2+ where LAZARET_TEST_YARN_BERRY does
not name its standalone yarn.js (the release's @yarnpkg/cli-dist bin/yarn.js). (Split from test_guard_yarn_bun.py;
MAC-TESTS.)

The tools resolve with scripts off (yarn 1 with --ignore-scripts in a copy of the project, yarn 2+ with
--mode=update-lockfile), and a blocked package is never installed, so no package code runs."""

import os
import shutil
import unittest

from tests.registry import _guard_support as gs
from tests.registry._guard_support import BERRY, berry_env, yarn_classic_project, yarn_major


@unittest.skipUnless(yarn_major() == 1, "yarn 1 is not installed")
class YarnClassicGuardTests(gs.RegistryCase):
    """yarn 1 resolves in a temporary copy of the project with scripts off:
    the project itself is not touched until the checked install runs."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env["YARN_CACHE_FOLDER"] = os.path.join(cls.tmp, "yarn-cache")

    def test_a_clean_package_is_installed(self):
        d = yarn_classic_project(self.tmp, self.registry)
        code, out = self.guard(d, "yarn", "add", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")
        self.assertIn("lazaret guard: checked 1 OK", out)

    def test_a_suspicious_dependency_blocks_the_install(self):
        d = yarn_classic_project(self.tmp, self.registry)
        before = gs.read(os.path.join(d, "package.json"))
        code, out = self.guard(d, "yarn", "add", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("1 blocked — nothing was installed", out)
        self.assertEqual(sorted(os.listdir(d)), [".npmrc", "package.json"])      # the copy resolved, not this
        self.assertEqual(gs.read(os.path.join(d, "package.json")), before)

    def test_plan_and_a_locked_new_release(self):
        d = yarn_classic_project(self.tmp, self.registry)
        code, out = self.guard(d, "--plan", "yarn", "add", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(os.listdir(d)), [".npmrc", "package.json"])
        code, out = self.guard(d, "yarn", "add", "fresh-pkg@1.1.0")           # yarn 1 can't hold it back
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    fresh-pkg@1.1.0: published 1 hour ago", out)


class _Berry(gs.RegistryCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.env = berry_env(cls.tmp, cls.env)

    def berry_project(self, extra=""):
        d = gs.project(self.tmp)
        with open(os.path.join(d, ".yarnrc.yml"), "w", encoding="utf-8") as f:
            f.write(f'npmRegistryServer: "{self.registry.url}"\nunsafeHttpWhitelist:\n  - "127.0.0.1"\n' + extra)
        return d


@unittest.skipUnless(BERRY, "LAZARET_TEST_YARN_BERRY does not name yarn 2+'s yarn.js")
class YarnBerryGuardTests(_Berry):
    def test_a_clean_package_is_installed(self):
        d = self.berry_project()
        code, out = self.guard(d, "yarn", "add", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")
        self.assertIn("lazaret guard: checked 1 OK", out)

    def test_a_suspicious_dependency_blocks_the_install_and_puts_the_files_back(self):
        d = self.berry_project()
        before = gs.read(os.path.join(d, "package.json"))
        code, out = self.guard(d, "yarn", "add", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("put back", out)
        self.assertEqual(gs.read(os.path.join(d, "package.json")), before)
        self.assertFalse(os.path.exists(os.path.join(d, "yarn.lock")))
        self.assertFalse(os.path.exists(os.path.join(d, ".yarn")))               # what it fetched is gone
        self.assertFalse(os.path.exists(os.path.join(d, "node_modules")))

    def test_new_releases_are_held_back_and_a_verdict_is_known_again(self):
        d = self.berry_project()
        code, out = self.guard(d, "yarn", "add", "fresh-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("held back (yarn npmMinimalAgeGate)", out)
        self.assertEqual(self.installed(d, "fresh-pkg"), "1.0.0")
        shutil.rmtree(os.path.join(d, "node_modules"))
        seen = len(self.registry.requests)
        code, out = self.guard(d, "yarn", "install")
        self.assertEqual(code, 0, out)
        self.assertEqual([p for ua, p in self.registry.requests[seen:] if ua.startswith("lazaret-guard")], [])


if __name__ == "__main__":
    unittest.main()
