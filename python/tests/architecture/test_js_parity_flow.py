"""Engine parity for the cross-file flow engine's JavaScript half: the npm
engine's js/src/scanner/flow.js against lazaret.scanner.flow (_js_mask,
_js_functions, _analyze_js, analyze).

1. Both CLIs on a tree with JavaScript flows (a command and an SQL sink
   reached from a route in another file, a sanitized and a placeholder call,
   a U+2028 that moves the line, a credential literal in a snippet, a
   dependency that is not analyzed): the same findings, every field of the
   X-* findings including the redacted snippets, the same gate and exit code.
2. The Python half has no port: its X-* flow on a Python file stays
   Python-only, and the npm engine's gate label says the project's Python
   files were not analyzed; with no Python files the labels are identical.
3. flow.analyze and analyzeFlows compared directly, in one node process, on
   the review's JavaScript cases, the size cap (code points, not UTF-16
   units), the sink-argument window around astral characters, and a seeded
   random corpus of JavaScript-ish text: every field of every finding, the
   masked text and the function table.

All content is inert: nothing is executed, credentials are dummies.
Skipped where node is missing.
"""
import json
import os
import random
import subprocess
import tempfile
import unittest

from lazaret.scanner import flow
from tests import _support
from tests.architecture import test_js_parity as parity

FLOW_JS = os.path.join(_support.REPO_ROOT, "js", "src", "scanner", "flow.js")
SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9"
LS = chr(0x2028)
ASTRAL = chr(0x1F600)

TREE = {
    "lib/run.js": ("const { exec } = require('child_process');\n"
                   "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\n"
                   "function find(id) {\n  return db.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n"
                   "function safeFind(id) {\n  return db.query('SELECT * FROM t WHERE id = ?', [id]);\n}\n"
                   "module.exports = { runIt, find, safeFind };\n"),
    "routes/app.js": ("const { runIt, find, safeFind } = require('../lib/run');\n"
                      "app.get('/x', (req, res) => {\n"
                      '  const seed = "' + SEED + '";\n'
                      "  const q = req.query.q;\n"
                      "  runIt(q);\n"
                      "  find(q);\n"
                      "  safeFind(q);\n"
                      "  runIt(parseInt(q));\n"
                      "});\n"),
    "routes/sep.js": "// header" + LS + "const a = 1;\napp.get('/y', (req, res) => { runIt(req.body.cmd); });\n",
    "node_modules/dep/index.js": "function runDep(c) {\n  exec(c);\n}\nrunDep(req.query.x);\n",
    "node_modules/dep/package.json": '{"name": "dep", "version": "1.0.0"}\n',
}
PY_FLOW = {"tool/app.py": ("import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
                           "def view():\n    run(request.args.get('c'))\n")}

NPM_FLOW = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const f = await import(pathToFileURL(process.argv[1]).href);
const { srcs, sets } = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify({
  masks: srcs.map((s) => f.jsMask(s)),
  funcs: srcs.map((s) => { const c = f.jsMask(s); return f.jsFunctions(s, c).map(([n, p, [a, b], l]) => [n, p, c.slice(a, b), l]); }),
  flows: sets.map((files) => f.analyzeFlows(files)),
}));
"""


def write_tree(root, tree):
    for rel, text in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)


def flows(report):
    return sorted((i["rule"], i["file"].replace("\\", "/"), i["line"], i["sev"], i["msg"], i["name"], i["why"],
                   i["fix"], i["ref"], i["type"], json.dumps(i["snippet"]), i["snipStart"])
                  for i in report["issues"] if i["rule"].startswith(parity.FLOW_PREFIXES)
                  and not parity._python_only(i, project=report["project"]))


def js_files(*pairs):
    return [{"path": p, "content": c, "lang": "js"} for p, c in pairs]


APP = "app.get('/x', (req, res) => { const q = req.query.q; CALL; });\n"


def review_cases():
    """The review's JavaScript flow cases (tests/scanner/test_review_flow_js*.py,
    test_review_flow_sink_line.py), as file sets."""
    helpers = [
        ("function runIt(cmd) {\n  exec(cmd);\n}\n", "runIt(q)"),
        ('function runIt(cmd) {\n  const banner = "}";\n  exec(cmd);\n}\n', "runIt(q)"),
        ('function logIt(cmd) {\n  console.log("{" + cmd);\n}\nfunction other(cmd) {\n  exec(cmd);\n}\n', "logIt(q); other(q)"),
        ('function logIt(cmd) {\n  // exec(cmd) would be bad\n  console.log("exec(" + cmd + ")");\n}\n', "logIt(q)"),
        ('function audit(msg) {\n  exec("uptime");\n  console.log(msg);\n}\n', "audit(q)"),
        ('function audit(msg) {\n  exec("echo " + wrap(msg, ")"));\n}\n', "audit(q)"),
        ("function show(html) {\n  el.innerHTML = '<b>' + html + '</b>';\n  log(html);\n}\n"
         "function safe(t) {\n  el.innerHTML = 'x';\n  log(t);\n}\n", "show(q); safe(q)"),
        ("function find(id) {\n  return db.query(`SELECT * FROM t WHERE id = ${id}`);\n}\n", "find(q)"),
        ("function find(id) {\n  return db.query('SELECT * FROM t WHERE id = ?', [id]);\n}\n", "find(q)"),
        ("function runIt(\n  cmd,\n  opts\n) {\n  return exec(\n    cmd);\n}\n", "runIt(q)"),
        ("function runIt(cmd) {" + LS + "  const a = 1;" + chr(0x2029) + "  exec(cmd);\n}\n", "runIt(q)"),
        ("function runIt(cmd) {\n  log(cmd);\n  exec(cmd);\n  execSync(cmd);\n}\n", "runIt(q)"),
        ("const go = (u) => { res.redirect(u); };\nconst ev = async function (s) { eval(s); };\n"
         "function net(u) { fetch(u); axios.get(u); }\n", "go(q); ev(q); net(q)"),
        ("function runIt(cmd) {\n  exec(shellQuote(cmd));\n  exec(cmd);\n}\n", "runIt(escapeHtml(q)); runIt(Number(q))"),
        ("function runIt(cmd) {\n  exec(" + ASTRAL * 3998 + "cmd);\n}\n", "runIt(q)"),
        ("function runIt(cmd) {\n  exec(" + ASTRAL * 3997 + "cmd);\n}\n", "runIt(q)"),
        ("function show(h) {\n  el.innerHTML = " + ASTRAL * 3000 + " + h;\n}\n", "show(q)"),
    ]
    sets = [js_files(("h.js", h), ("app.js", APP.replace("CALL", call))) for h, call in helpers]
    sets.append(js_files(("h.js", "function runIt(cmd) {\n\n  exec(cmd);\n}\n"),
                         ("z.js", "function runIt(cmd) {\n  return cmd;\n}\n"),
                         ("app.js", APP.replace("CALL", "runIt(q)"))))
    sets.append(js_files(("h.js", "/* helper */" + LS + "function runIt(cmd) {\n  exec(cmd);\n}\n"),
                         ("app.js", "// header" + LS + "const x = 1;" + chr(0x2029) + "const y = 2;\n"
                          + APP.replace("CALL", "runIt(q); eval(q)"))))
    # the size cap counts code points: 2,000,000 are analyzed, one more is not;
    # 1,000,001 astral characters (2,000,002 UTF-16 units) are analyzed
    sets.append(js_files(("big.js", "function runIt(c) { exec(c); }\n//" + "a" * (2_000_000 - 33)),
                         ("app.js", APP.replace("CALL", "runIt(q)"))))
    sets.append(js_files(("big.js", "function runIt(c) { exec(c); }\n//" + "a" * (2_000_000 - 32)),
                         ("app.js", APP.replace("CALL", "runIt(q)"))))
    sets.append(js_files(("astral.js", "function runIt(c) { exec(c); }\n//" + ASTRAL * 1_000_001),
                         ("app.js", APP.replace("CALL", "runIt(q)"))))
    return sets


TOKENS = ["'", '"', "`", "${", "}", "{", "(", ")", "[", "]", "/", "*", "\\", "\n", LS, chr(0x2029), " ", "\t",
          "return", "typeof", "x", "a1", "_$", "9", "3.5e1", "=", "+", "-", ";", ",", ":", "?", "!", "&", "|",
          "<", ">", "~", "^", "%", ".", ASTRAL, "\u00e9", "\u00a0", "\ufeff", "\x85", "//", "/*", "*/", "\r",
          "function f(a, b) {", "const g = (c) => {", "let h = async function (d) {", "exec(", "eval(",
          "req.query.q", "db.query(`", "el.innerHTML = ", "fetch(", "res.redirect(", "f(req.query.x)",
          "g(t)", "const t = req.body.z;", "h(t, 1)", "new Function(", chr(0x10400), "parseInt(", "quote("]


def soup(rnd):
    return "".join(rnd.choice(TOKENS) for _ in range(rnd.randint(0, 70)))


@unittest.skipUnless(parity.NODE, "node is not installed")
class FlowParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    def test_cli_trees_agree(self):
        for label, tree, deps in (("js", TREE, False), ("js --deps", TREE, True),
                                  ("js+py", {**TREE, **PY_FLOW}, False)):
            with self.subTest(tree=label), tempfile.TemporaryDirectory() as root:
                write_tree(root, tree)
                js, py = parity.both(root, deps=deps, extra=("--ci",))
                self.assert_same(js, py, label=label)
                self.assertEqual(flows(js[1]), flows(py[1]))            # every field, redacted snippets included
                found = {(i["rule"], i["file"].replace("\\", "/"), i["line"]) for i in js[1]["issues"]
                         if i["rule"].startswith("X-")}
                self.assertEqual(found, {("X-CMD", "routes/app.js", 5), ("X-SQL", "routes/app.js", 6),
                                         ("X-CMD", "routes/sep.js", 3)})
                for _, report, _ in (js, py):
                    self.assertNotIn(SEED, json.dumps(report))
                    self.assertFalse([i for i in report["issues"] if i["rule"].startswith("X-")
                                      and "node_modules" in i["file"]])
                self.assertEqual((js[0], py[0]), (1, 1))
                js_gate, py_gate = js[1]["conditions"][-1], py[1]["conditions"][-1]
                self.assertEqual(py_gate, {"label": "No cross-file taint flows", "ok": False})
                if "py" in label:
                    self.assertEqual(js_gate, {"label": "No cross-file taint flows (JavaScript only: "
                                                        "1 Python file not analyzed)", "ok": False})
                    self.assertIn(("X-CMD", "tool/app.py"), {(i["rule"], i["file"].replace("\\", "/"))
                                                             for i in py[1]["issues"]})
                else:
                    self.assertEqual(js_gate, py_gate)

    def test_label_counts_python_files_not_dependencies(self):
        tree = {"a.py": "x = 1\n", "b/c.py": "y = 2\n", "node_modules/d/e.py": "z = 3\n",
                "node_modules/d/package.json": '{"name": "d", "version": "1.0.0"}\n', "app.js": "const a = 1;\n"}
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            js, py = parity.both(root, deps=True)
            self.assert_same(js, py, label="label")
            self.assertEqual(js[1]["conditions"][-1],
                             {"label": "No cross-file taint flows (JavaScript only: 2 Python files not analyzed)",
                              "ok": True})
            self.assertEqual(py[1]["conditions"][-1], {"label": "No cross-file taint flows", "ok": True})

    def test_engines_agree_function_by_function(self):
        rnd = random.Random(20260927)
        srcs = [soup(rnd) for _ in range(3000)]
        srcs += ["const b = \"}\"; exec(cmd);", "x = /}[/]\\//g.test(s);", "y = `t ${ {a:1}.a + `in ${z}` } }` + q;",
                 "`" + "${" * 2000 + "x", "'" * 3000, "/" * 3000, "/*" + "x" * 3000, "`" * 3001]
        sets = review_cases()
        for _ in range(800):
            sets.append([{"path": f"p{k}.js", "content": soup(rnd) + "\n" + soup(rnd), "lang": "js"}
                         for k in range(rnd.randint(1, 4))])
        p = subprocess.run([parity.NODE, "--input-type=module", "-e", NPM_FLOW, FLOW_JS],
                           input=json.dumps({"srcs": srcs, "sets": sets}), capture_output=True,
                           encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        js = json.loads(p.stdout)
        for src, got in zip(srcs, js["masks"]):
            self.assertEqual(got, flow._js_mask(src), repr(src)[:200])
        for src, got in zip(srcs, js["funcs"]):
            code = flow._js_mask(src)
            want = [[n, params, code[a:b], line] for n, params, (a, b), line in flow._js_functions(src, code)]
            self.assertEqual(got, want, repr(src)[:200])
        total = 0
        for files, got in zip(sets, js["flows"]):
            want = flow.analyze(files)
            total += len(want)
            self.assertEqual(got, want, json.dumps(files)[:300])
        # not vacuous: the review cases and the corpus produce flows and the skip note
        rules = {i["rule"] for found in js["flows"] for i in found}
        self.assertTrue({"X-CMD", "X-SQL", "X-XSS", "X-CODE", "X-SSRF", "X-REDIR", "X-FLOW-SKIPPED"} <= rules, rules)
        self.assertGreater(total, 100)


if __name__ == "__main__":
    unittest.main()
