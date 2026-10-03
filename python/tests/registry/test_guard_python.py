"""lazaret guard with the real pip and uv, against a fake PyPI on 127.0.0.1
(tests/registry/_guard_support.py): pip and uv pip through the guard's local
index (every file scanned before the tool gets it; files younger than
--min-age left out of it), and uv's project commands (the new uv.lock checked
before anything is installed); (0.1.8) the indexes of the command line and
of the tools' settings relayed with their credentials, a PEP 503 (HTML)
index, uvx / uv tool and uv run. Skipped where a tool is missing.

A blocked package is never handed to the tool, so its code never runs."""

import base64

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.registry import _guard_support as gs


def venv_has(venv, module):
    for root, dirs, _files in os.walk(venv):
        if os.path.basename(root) == "site-packages":
            return module in dirs
    return False


class _IndexCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = gs.PypiIndex()
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-guard-py-")
        cls.env = gs.base_env(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        cls.index.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def guard(self, cwd, env, *args):
        return gs.run_guard(["--jobs", "1", *args], cwd, env)


class PipGuardTests(_IndexCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.venv = os.path.join(cls.tmp, "venv")
        proc = subprocess.run([sys.executable, "-m", "venv", cls.venv], capture_output=True)
        bindir = os.path.join(cls.venv, "Scripts" if os.name == "nt" else "bin")
        pip = os.path.join(bindir, "pip.exe" if os.name == "nt" else "pip")
        if proc.returncode != 0 or not os.path.exists(pip):
            super().tearDownClass()
            raise unittest.SkipTest("no venv with pip here (ensurepip missing)")
        cls.pip_env = dict(cls.env, PATH=bindir + os.pathsep + cls.env.get("PATH", ""), VIRTUAL_ENV=cls.venv,
                           LAZARET_GUARD_PYPI_URL=cls.index.url)

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

    def test_an_sdist_is_scanned_before_pip_can_build_it(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "evil-sdist")
        self.assertEqual(code, 1, out)
        self.assertIn("opens a reverse shell", out)

    def test_new_releases_are_left_out_of_the_index(self):
        code, out = self.guard(self.tmp, self.pip_env, "--plan", "pip", "install", "fresh-py")
        self.assertEqual(code, 0, out)
        self.assertIn("held back  fresh-py: 1 release younger than 2 days", out)
        self.assertIn("nothing blocked (--plan: nothing was installed)", out)
        self.assertFalse(venv_has(self.venv, "fresh_py"))

    def test_local_archives_are_refused(self):
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "--find-links", "./wheels", "good-py")
        self.assertEqual(code, 2, out)
        self.assertIn("install without local archives", out)

    def test_an_index_of_the_command_line_is_relayed(self):
        """(0.1.7 refused it.) pip is still pointed at the guard alone; the
        guard fetches from the index named, and scans what it serves."""
        side = gs.PypiIndex({"side-only": gs.default_pypi_files()["good-py"],
                             "evil-py": gs.default_pypi_files()["evil-py"]})
        self.addCleanup(side.close)
        code, out = self.guard(self.tmp, self.pip_env, "pip", "install", "--extra-index-url", side.url, "evil-py")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0", out)
        self.assertIn(f"relaying {self.index.url}, {side.url}", out)
        self.assertTrue(side.requests)
        self.assertEqual({ua.split("/")[0] for ua, _p, _a in side.requests}, {"lazaret-guard"})

    def test_a_private_index_with_credentials_in_pips_settings(self):
        auth = "Basic " + base64.b64encode(b"reader:" + b"s3cr" + b"et-pw").decode()
        private = gs.PypiIndex(auth=auth)
        self.addCleanup(private.close)
        env = dict(self.pip_env)
        del env["LAZARET_GUARD_PYPI_URL"]
        env["PIP_INDEX_URL"] = private.url.replace("http://", "http://reader:" + "s3cr" + "et-pw@")
        code, out = self.guard(self.tmp, env, "pip", "install", "--force-reinstall", "good-py")
        self.assertEqual(code, 0, out)
        self.assertNotIn("et-pw", out)
        self.assertIn(f"relaying {private.url}", out)
        self.assertEqual({(ua.split("/")[0], a) for ua, _p, a in private.requests}, {("lazaret-guard", auth)})

    def test_a_pep_503_index(self):
        """An index that serves HTML pages (no upload times: --min-age can't
        hold its new releases back, and the report says so)."""
        html_index = gs.PypiIndex(html=True)
        self.addCleanup(html_index.close)
        env = dict(self.pip_env, LAZARET_GUARD_PYPI_URL=html_index.url)
        code, out = self.guard(self.tmp, env, "pip", "install", "--force-reinstall", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("good-py: the index gives no upload times", out)


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvPipGuardTests(_IndexCase):
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
class UvSettingsTests(_IndexCase):
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


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvToolAndRunTests(_IndexCase):
    """uvx / uv tool install through the local index (a plan first), and
    uv run: the project synced as uv sync is checked, then the command."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.uv_env = dict(cls.env, LAZARET_GUARD_PYPI_URL=cls.index.url, UV_PYTHON=sys.executable,
                          UV_TOOL_DIR=os.path.join(cls.tmp, "uv-tools"),
                          UV_TOOL_BIN_DIR=os.path.join(cls.tmp, "uv-tools", "bin"))

    def test_uvx_runs_a_clean_tool(self):
        code, out = self.guard(self.tmp, self.uv_env, "uvx", "good-tool")
        self.assertEqual(code, 0, out)
        self.assertIn("2 packages to check (uv's plan)", out)
        self.assertIn("good-tool ran", out)

    def test_uvx_blocks_a_tool_whose_dependency_is_suspicious(self):
        code, out = self.guard(self.tmp, self.uv_env, "uvx", "evil-tool")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0", out)
        self.assertNotIn("evil-tool ran", out)

    def test_uv_tool_install(self):
        code, out = self.guard(self.tmp, self.uv_env, "--plan", "uv", "tool", "install", "good-tool")
        self.assertEqual(code, 0, out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "uv-tools", "good-tool")))
        code, out = self.guard(self.tmp, self.uv_env, "uv", "tool", "install", "good-tool")
        self.assertEqual(code, 0, out)
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "uv-tools", "good-tool")))

    def test_uv_run_in_a_project(self):
        d = tempfile.mkdtemp(prefix="uvrun-", dir=self.tmp)
        pyproject = ('[project]\nname = "runner"\nversion = "0.1.0"\nrequires-python = ">=3.8"\n'
                     'dependencies = ["good-py"]\n')
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(pyproject)
        env = dict(self.uv_env, UV_DEFAULT_INDEX=self.index.url.rstrip("/"))
        code, out = self.guard(d, env, "uv", "run", "python", "-c", "import good_py; print('ran', good_py.VALUE)")
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (uv.lock)", out)
        self.assertIn("ran 1", out)
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(pyproject.replace('["good-py"]', '["good-py", "py-parent"]'))
        code, out = self.guard(d, env, "uv", "run", "python", "-c", "print('RUN' + 'NING')")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0", out)
        self.assertNotIn("RUNNING", out)                                  # (the command line shows 'RUN' + 'NING')


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvProjectGuardTests(_IndexCase):
    PYPROJECT = ('[project]\nname = "guardtest"\nversion = "0.1.0"\nrequires-python = ">=3.8"\n'
                 'dependencies = []\n')

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.uv_env = dict(cls.env, UV_DEFAULT_INDEX=cls.index.url.rstrip("/"), UV_PYTHON=sys.executable)

    def project(self):
        d = tempfile.mkdtemp(prefix="uvproj-", dir=self.tmp)
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(self.PYPROJECT)
        return d

    def test_add_a_clean_package(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "good-py")
        self.assertEqual(code, 0, out)
        self.assertIn("1 package to check (uv.lock)", out)
        self.assertTrue(venv_has(os.path.join(d, ".venv"), "good_py"))
        code, out = self.guard(d, self.uv_env, "uv", "sync")                      # nothing new
        self.assertEqual(code, 0, out)
        self.assertIn("0 packages to check (uv.lock)", out)

    def test_a_suspicious_dependency_blocks_and_puts_the_files_back(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "py-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-py@1.0 (evil_py-1.0-py3-none-any.whl): SUSPICIOUS", out)
        self.assertIn("pyproject.toml and uv.lock put back", out)
        self.assertEqual(gs.read(os.path.join(d, "pyproject.toml")), self.PYPROJECT)
        self.assertFalse(os.path.exists(os.path.join(d, "uv.lock")))

    def test_a_new_release_is_blocked_unless_allowed(self):
        d = self.project()
        code, out = self.guard(d, self.uv_env, "uv", "add", "fresh-py")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    fresh-py@1.1 (fresh_py-1.1-py3-none-any.whl): published 1 hour ago", out)
        code, out = self.guard(d, self.uv_env, "--allow-new", "fresh-py", "uv", "add", "fresh-py")
        self.assertEqual(code, 0, out)
        self.assertIn("let through by --allow-new", out)

    def test_lock_checks_and_installs_nothing(self):
        d = self.project()
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as f:
            f.write(self.PYPROJECT.replace("dependencies = []", 'dependencies = ["py-parent"]'))
        code, out = self.guard(d, self.uv_env, "uv", "lock")
        self.assertEqual(code, 1, out)
        self.assertFalse(os.path.exists(os.path.join(d, "uv.lock")))
        self.assertFalse(os.path.exists(os.path.join(d, ".venv")))


if __name__ == "__main__":
    unittest.main()
