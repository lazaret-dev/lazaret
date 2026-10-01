"""lazaret guard with the real yarn (1 and 2+) and Bun, against a fake
registry on 127.0.0.1 (tests/registry/_guard_support.py), and (0.1.8) a
private registry reached with the credentials of each tool's own settings
(npm and pnpm too). Skipped where a tool is not installed; yarn 2+ where
LAZARET_TEST_YARN_BERRY does not name its standalone yarn.js (the release's
@yarnpkg/cli-dist bin/yarn.js).

The tools resolve with scripts off (yarn 1 with --ignore-scripts in a copy of
the project, yarn 2+ with --mode=update-lockfile, bun with --lockfile-only),
and a blocked package is never installed, so no package code runs."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from tests.registry import _guard_support as gs
from tests.registry.test_guard_npm import _RegistryCase

TOKEN = "lz-" + "t0ken" + "-" + "9f8e7d"          # (built in pieces: a whole one would trip secret scanners)


def yarn_major():
    exe = shutil.which("yarn")
    if exe is None:
        return None
    try:
        with tempfile.TemporaryDirectory() as d:
            out = subprocess.run([exe, "--version"], cwd=d, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=60).stdout
        return int(out.strip().split(".")[0])
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


BERRY = os.environ.get("LAZARET_TEST_YARN_BERRY")
BERRY = BERRY if BERRY and os.path.isfile(BERRY) and os.name != "nt" and shutil.which("node") else None


def yarn_classic_project(tmp, registry, npmrc=""):
    d = gs.project(tmp)
    with open(os.path.join(d, ".npmrc"), "w", encoding="utf-8") as f:
        f.write(f"registry={registry.url}\n" + npmrc)
    return d


@unittest.skipUnless(yarn_major() == 1, "yarn 1 is not installed")
class YarnClassicGuardTests(_RegistryCase):
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


def berry_env(tmp, env):
    """env with yarn 2+ (LAZARET_TEST_YARN_BERRY, its standalone yarn.js)
    first on PATH as `yarn`: its cache in the project, node_modules, no
    telemetry, and not CI's immutable or hardened mode."""
    bindir = tempfile.mkdtemp(prefix="berry-bin-", dir=tmp)
    with open(os.path.join(bindir, "yarn"), "w", encoding="utf-8") as f:
        f.write(f'#!/bin/sh\nexec "{shutil.which("node")}" "{BERRY}" "$@"\n')
    os.chmod(os.path.join(bindir, "yarn"), 0o755)
    return dict(env, PATH=bindir + os.pathsep + env.get("PATH", ""), YARN_ENABLE_TELEMETRY="0",
                YARN_ENABLE_GLOBAL_CACHE="false", YARN_NODE_LINKER="node-modules",
                YARN_ENABLE_IMMUTABLE_INSTALLS="false", YARN_ENABLE_HARDENED_MODE="0",
                YARN_GLOBAL_FOLDER=os.path.join(tmp, "berry-global"))


class _Berry(_RegistryCase):
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


@unittest.skipUnless(shutil.which("bun"), "bun is not installed")
class BunGuardTests(_RegistryCase):
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
