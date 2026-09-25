"""The defensive stub packages fail loudly and depend on nothing."""

import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_typosquat_stubs.py")


class StubTests(unittest.TestCase):
    def test_python_stub_raises_and_has_no_dependencies(self):
        stubs = _support.load_script(SCRIPT, "make_typosquat_stubs")
        with tempfile.TemporaryDirectory() as d:
            wheel = stubs.build_python_stub("lazarat", os.path.join(d, "dist"))
            target = os.path.join(d, "site")
            with zipfile.ZipFile(wheel) as z:   # closed before the temp dir is removed (Windows)
                meta = z.read("lazarat-0.0.1.dist-info/METADATA").decode()
                z.extractall(target)
            self.assertNotIn("Requires-Dist", meta)
            p = subprocess.run([sys.executable, "-c", "import lazarat"], capture_output=True, encoding="utf-8", errors="replace",
                               env=dict(os.environ, PYTHONPATH=target), timeout=60)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("You probably want 'lazaret'", p.stderr)

    def test_js_stub_throws(self):
        stubs = _support.load_script(SCRIPT, "make_typosquat_stubs")
        with tempfile.TemporaryDirectory() as d:
            out = stubs.build_js_stub("lazarat", d)
            with open(os.path.join(out, "index.js")) as f:
                self.assertIn("throw new Error", f.read())

    def test_rejects_odd_names(self):
        stubs = _support.load_script(SCRIPT, "make_typosquat_stubs")
        with self.assertRaises(ValueError):
            stubs.build_python_stub("../evil", tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main()
