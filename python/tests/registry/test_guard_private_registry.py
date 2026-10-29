"""lazaret guard and a private registry (0.1.8): a registry on 127.0.0.1 (tests/registry/_guard_support.py) that
answers only with a token, reached by npm, pnpm, yarn 1, yarn 2+ and Bun with the credentials of each tool's own
settings. Skipped where a tool is not installed; yarn 2+ where LAZARET_TEST_YARN_BERRY does not name its standalone
yarn.js. (Split from test_guard_yarn_bun.py; MAC-TESTS.)

A blocked package is never installed, so no package code runs."""

import json
import os
import shutil
import tempfile
import unittest

from tests.registry import _guard_support as gs
from tests.registry._guard_support import BERRY, berry_env, yarn_major

TOKEN = "lz-" + "t0ken" + "-" + "9f8e7d"          # (built in pieces: a whole one would trip secret scanners)


class PrivateRegistryTests(unittest.TestCase):
    """A registry that answers only with a token: the guard fetches with the
    credentials each tool's own settings give (npm's and pnpm's .npmrc with
    ${VAR}, yarn 1's .npmrc, yarn 2+'s .yarnrc.yml, bunfig.toml), sends them
    to that registry, and never prints them."""

    @classmethod
    def setUpClass(cls):
        cls.registry = gs.NpmRegistry(auth="Bearer " + TOKEN)
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-guard-private-")
        cls.env = gs.base_env(cls.tmp)
        cls.env["LZ_TEST_TOKEN"] = TOKEN
        cls.host = cls.registry.url[len("http://"):]

    @classmethod
    def tearDownClass(cls):
        cls.registry.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, d, env, *command):
        seen = len(self.registry.authorizations)
        code, out = gs.run_guard(["--jobs", "1", "--no-cache", *command], d, env)
        self.assertEqual(code, 0, out)
        self.assertNotIn(TOKEN, out)
        text = gs.read(os.path.join(d, "node_modules", "good-pkg", "package.json"))
        self.assertEqual(json.loads(text)["version"] if text else None, "1.0.0", out)
        guard_auth = {a for ua, _p, a in self.registry.authorizations[seen:] if ua.startswith("lazaret-guard")}
        self.assertEqual(guard_auth, {"Bearer " + TOKEN}, out)

    def npmrc_project(self, extra=""):
        d = gs.project(self.tmp)
        with open(os.path.join(d, ".npmrc"), "w", encoding="utf-8") as f:
            f.write(f"registry={self.registry.url}\n//{self.host}:_authToken=${{LZ_TEST_TOKEN}}\n" + extra)
        return d

    @unittest.skipUnless(shutil.which("npm"), "npm is not installed")
    def test_npm(self):
        self.check(self.npmrc_project(), self.env, "npm", "install", "good-pkg")

    @unittest.skipUnless(shutil.which("pnpm"), "pnpm is not installed")
    def test_pnpm(self):
        self.check(self.npmrc_project(), self.env, "pnpm", "add", "good-pkg")

    @unittest.skipUnless(yarn_major() == 1, "yarn 1 is not installed")
    def test_yarn_classic(self):
        env = dict(self.env, YARN_CACHE_FOLDER=os.path.join(self.tmp, "yarn-cache"))
        self.check(self.npmrc_project("always-auth=true\n"), env, "yarn", "add", "good-pkg")

    @unittest.skipUnless(BERRY, "LAZARET_TEST_YARN_BERRY does not name yarn 2+'s yarn.js")
    def test_yarn_berry(self):
        env = berry_env(self.tmp, self.env)
        d = gs.project(self.tmp)
        with open(os.path.join(d, ".yarnrc.yml"), "w", encoding="utf-8") as f:
            f.write(f'npmRegistryServer: "{self.registry.url}"\nunsafeHttpWhitelist:\n  - "127.0.0.1"\n'
                    'npmAlwaysAuth: true\nnpmAuthToken: "${LZ_TEST_TOKEN}"\n')
        self.check(d, env, "yarn", "add", "good-pkg")

    @unittest.skipUnless(shutil.which("bun"), "bun is not installed")
    def test_bun(self):
        d = gs.project(self.tmp)
        with open(os.path.join(d, "bunfig.toml"), "w", encoding="utf-8") as f:
            f.write(f'[install]\nregistry = {{ url = "{self.registry.url}", token = "$LZ_TEST_TOKEN" }}\n')
        self.check(d, dict(self.env, BUN_INSTALL_CACHE_DIR=os.path.join(self.tmp, "bun-cache")),
                   "bun", "add", "good-pkg")


if __name__ == "__main__":
    unittest.main()
