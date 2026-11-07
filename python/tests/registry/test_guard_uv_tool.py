"""lazaret guard with the real uv, against a fake PyPI on 127.0.0.1 (tests/registry/_guard_support.py) (0.1.8): uvx,
uv tool install and uv run. Skipped where uv is not installed. (Split from test_guard_python.py; MAC-TESTS.)

A blocked package is never handed to the tool, so its code never runs."""

import os
import shutil
import sys
import tempfile
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("uv"), "uv is not installed")
class UvToolAndRunTests(gs.IndexCase):
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


if __name__ == "__main__":
    unittest.main()
