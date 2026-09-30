"""0.1.8: programs set to start at login or boot (tests/scanner/
test_persistence_services.py) in registry scans: an npm release whose
postinstall writes and enables a systemd user unit (the CanisterWorm shape)
and an sdist whose setup.py adds a Windows Run key are SUSPICIOUS; a wheel
that ships an auto-launch helper, run only when its app asks, stays OK.
Inert text: nothing runs.
"""
import json
import unittest

from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel
from tests.scanner.test_persistence_services import UNIT_WRITER


class ServicesRegistryTests(unittest.TestCase):
    def test_an_npm_postinstall_that_enables_a_systemd_unit(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.19.1", "main": "index.js",
                                                    "scripts": {"postinstall": "node index.js"}}),
                        "index.js": UNIT_WRITER})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn(("CRITICAL", "Install hook runs index.js, which installs a systemd service."),
                      [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"])

    def test_an_sdist_whose_setup_py_adds_a_run_key(self):
        setup = ("import sys, winreg\nfrom setuptools import setup\n"
                 "if sys.platform == 'win32':\n"
                 "    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
                 " 0, winreg.KEY_SET_VALUE)\n"
                 "    winreg.SetValueEx(k, 'svc', 0, winreg.REG_SZ, sys.executable + ' -m x.agent')\n"
                 "setup(name='x', version='1.0')\n")
        res = scan_sdist({"setup.py": setup, "x/__init__.py": ""})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(any("adds a program to a Windows Run key" in i["msg"] for i in res["issues"]), res["issues"])

    def test_an_auto_launch_helper_run_when_asked_stays_ok(self):
        helper = ("import os, winreg\nRUN = r'Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n"
                  "def enable(name, command):\n"
                  "    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN, 0, winreg.KEY_SET_VALUE) as k:\n"
                  "        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, command)\n")
        res = scan_wheel({"lit/__init__.py": "", "lit/autostart.py": helper,
                          "lit-1.0.dist-info/METADATA": "Name: lit\nVersion: 1.0\n"})
        self.assertEqual(res["verdict"], "OK", res["issues"])


if __name__ == "__main__":
    unittest.main()
