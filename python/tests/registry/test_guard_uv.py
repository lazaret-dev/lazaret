"""lazaret guard with the real uv, against a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py): uv pip through
the guard's local index, and (0.1.8) the indexes of uv's settings relayed, not bypassed. Skipped where uv is not
installed. (Split from test_guard_python.py; MAC-TESTS.)

A blocked package is never handed to the tool, so its code never runs."""

import base64
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.registry import _guard_support as gs
from tests.registry._guard_support import venv_has


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvPipGuardTests(gs.IndexCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.venv = os.path.join(cls.tmp, "uv-venv")
        subprocess.run(["uv", "venv", "-q", "--python", sys.executable, cls.venv], env=cls.env, check=True)
        cls.uv_env = dict(cls.env, VIRTUAL_ENV=cls.venv, LAZARET_GUARD_PYPI_URL=cls.index.url)

    def test_a_clean_package_is_installed(self):
        code, out = self.guard(self.tmp, self.uv_env, "uv", "pip", "install", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (uv's plan)", out)
        self.assertTrue(venv_has(self.venv, "good_py"))

    def test_suspicious_packages_block_the_install(self):
        for spec, finding in (("py-parent", "SC-SITECUSTOMIZE (CRITICAL)"), ("evil-sdist", "opens a reverse shell")):
            with self.subTest(spec):
                code, out = self.guard(self.tmp, self.uv_env, "uv", "pip", "install", spec)
                self.assertEqual(code, 1, out)
                self.assertIn(finding, out)
        self.assertFalse(venv_has(self.venv, "py_parent") or venv_has(self.venv, "evil_py"))


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvSettingsTests(gs.IndexCase):
    """uv's own indexes: one in a settings file used to come before the
    guard's (UV_DEFAULT_INDEX is uv's last), so uv fetched from it itself,
    unscanned; the guard now relays it, and uv asks the guard first and
    only (UV_INDEX, and an empty page for a project no index has)."""

    def test_an_index_in_uv_toml_is_relayed_not_bypassed(self):
        side = gs.PypiIndex({"sneaky-py": gs.default_pypi_files()["evil-py"]})
        self.addCleanup(side.close)
        d = tempfile.mkdtemp(prefix="uvcfg-", dir=self.tmp)
        with open(os.path.join(d, "uv.toml"), "w", encoding="utf-8") as f:
            f.write(f'[[index]]\nname = "side"\nurl = "{side.url}"\n')
        venv = os.path.join(d, "venv")
        subprocess.run(["uv", "venv", "-q", "--python", sys.executable, venv], env=self.env, check=True)
        env = {k: v for k, v in self.env.items() if k != "UV_NO_CONFIG"}
        env.update(VIRTUAL_ENV=venv, UV_DEFAULT_INDEX=self.index.url)
        code, out = self.guard(d, env, "uv", "pip", "install", "evil-py")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0", out)
        self.assertEqual({ua.split("/")[0] for ua, _p, _a in side.requests}, {"lazaret-guard"})
        self.assertFalse(venv_has(venv, "evil_py"))

    def test_a_named_index_with_credentials_in_the_environment(self):
        auth = "Basic " + base64.b64encode(b"u:" + b"pa" + b"ss").decode()
        private = gs.PypiIndex(auth=auth)
        self.addCleanup(private.close)
        venv = os.path.join(self.tmp, "uv-private")
        subprocess.run(["uv", "venv", "-q", "--python", sys.executable, venv], env=self.env, check=True)
        env = dict(self.env, VIRTUAL_ENV=venv, UV_INDEX=f"corp={private.url}", UV_INDEX_CORP_USERNAME="u",
                   UV_INDEX_CORP_PASSWORD="pa" + "ss")
        code, out = self.guard(self.tmp, env, "uv", "pip", "install", "good-py")
        self.assertEqual(code, 0, out)
        self.assertTrue(venv_has(venv, "good_py"))
        self.assertEqual({a for _ua, _p, a in private.requests}, {auth})


if __name__ == "__main__":
    unittest.main()
