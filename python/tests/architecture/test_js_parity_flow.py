"""Engine parity for the cross-file flow engine's JavaScript half: the npm
package's js/src/scanner/flow.js against lazaret.scanner.flow (_analyze_js,
analyze). Since the Rust-first refactor both run the engine's pass (the
`js_flow` call: natively in the Python package, as WebAssembly in the npm
package; before it, jsflow.py and its npm twin) and build their findings
from its outputs, so this holds the two hosts' findings — and the two
builds of the pass — to each other.

1. Both CLIs on a tree with JavaScript flows (a command and an SQL sink
   reached from a route in another file, a sanitized and a placeholder call,
   a U+2028 that moves the line, a credential literal in a snippet, a
   dependency that is not analyzed): the same findings, every field of the
   X-* findings including the redacted snippets, the same gate and exit code.
2. The Python half has no port: its X-* flow on a Python file stays
   Python-only, and the npm engine's gate label says the project's Python
   files were not analyzed; with no Python files the labels are identical.
3. flow.analyze and analyzeFlows compared directly, in one node process, on
   the review's JavaScript cases (brace counting, sink lines, modules and
   returned values, calls that can't be resolved and the evidence that binds
   nothing, helpers' values, shadowed sanitizers, values through locals,
   destructuring, push and loops, RegExp receivers of exec():
   tests/scanner/test_review_flow_js*.py), the engine's own cases
   (tests/scanner/test_jsflow.py: routes, fixed hosts, classes, exported
   variables, TypeScript, JSX), the size caps (code points, not UTF-16
   units), the fixpoint's cap and the work budget, files the reader rejects,
   seeded generated projects (tests/architecture/jsgen.py) and seeded token
   soups: every field of every finding, in order.

All content is inert: nothing is executed, credentials are dummies.
Skipped where node or the npm package's WebAssembly build is missing (npm
run build in js/).
"""
import json
import os
import random
import subprocess
import tempfile
import unittest

from lazaret.scanner import flow
from tests import _support
from tests.architecture import jsgen
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
const { sets } = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(sets.map((files) => f.analyzeFlows(files))));
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
    # modules and returned values (tests/scanner/test_review_flow_js_modules.py)
    sets.append(js_files(("lib/input.js", "function getCmd(req) {\n  return req.query.cmd;\n}\n"
                                          "const getName = (req) => req.body.name;\n"
                                          "function getSafe(req) { return escapeHtml(req.query.n); }\n"
                                          "module.exports = { getCmd, getName, getSafe };\n"),
                         ("app.js", "const { getCmd, getName, getSafe } = require('./lib/input');\n"
                                    "app.get('/x', (req, res) => {\n  exec(getCmd(req));\n  const c = getCmd(req);\n"
                                    "  execSync(c);\n  el.innerHTML = getName(req);\n  el.innerHTML = getSafe(req);\n"
                                    "  exec(getSafe(req));\n  db.query('SELECT ?', [getName(req)]);\n"
                                    "  db.query('SELECT ' + getName(req));\n  exec(Number(getCmd(req)));\n"
                                    "  exec(shellQuote(getCmd(req)));\n});\n")))
    sets.append(js_files(("h.js", "function runIt(cmd) { exec(cmd); }\nfunction wrap(x) { return 'ls ' + x; }\n"
                                  "function yes(x) { log(x); return true; }\nfunction escape(x) { return escapeHtml(x); }\n"
                                  "function show(h) { el.innerHTML = h; }\n"
                                  "module.exports = { runIt, wrap, yes, escape, show };\n"),
                         ("app.js", "const { runIt, wrap, yes, escape, show } = require('./h');\n"
                                    "app.get('/x', (req, res) => {\n  const q = req.query.q;\n  runIt(wrap(q));\n"
                                    "  runIt(yes(q));\n  const w = wrap(q); runIt(w);\n  show(escape(q));\n"
                                    "  runIt(escape(q));\n});\n")))
    sets.append(js_files(("safe.js", "function runIt(cmd) { log(cmd); }\nmodule.exports = { runIt };\n"),
                         ("danger.js", "function runIt(cmd) { exec(cmd); }\nmodule.exports = { runIt };\n"),
                         ("a.js", "const { runIt } = require('./safe');\napp.get('/', (req) => { runIt(req.query.q); });\n"),
                         ("b.js", "app.get('/', (req) => { runIt(req.query.q); });\n"),
                         ("c.js", "const { runIt } = require('some-pkg');\napp.get('/', (req) => { runIt(req.query.q); });\n"),
                         ("d.js", "const d = require('./danger');\napp.get('/', (req) => { d.runIt(req.query.q); "
                                  "obj.runIt(req.query.q); this.runIt(req.query.q); });\n")))
    sets.append(js_files(("src/input.ts", "export function getCmd(req: any): string {\n  return req.query.cmd;\n}\n"
                                          "export default function getDef(req) { return req.body.x; }\n"),
                         ("src/index.ts", "export * from './input.js';\nexport { getDef as other } from './input.js';\n"),
                         ("src/app.ts", "import { getCmd } from './input.js';\nimport * as inp from './input';\n"
                                        "import g from './input';\nimport { getCmd as gc2, other } from './index';\n"
                                        "exec(getCmd(req));\nexec(inp.getCmd(req));\nexec(g(req));\nexec(gc2(req));\n"
                                        "exec(other(req));\n")))
    sets.append(js_files(("a.js", "module.exports = function getCmd(req) { return req.query.c; };\n"),
                         ("b.js", "function helper(req) { return req.query.c; }\nmodule.exports = helper;\n"),
                         ("c.js", "exports.getIt = function getIt(req) { return req.query.c; };\n"),
                         ("d.js", "module.exports = require('./b');\n"),
                         ("app.js", "const x = require('./a');\nconst y = require('./b');\nconst { getIt } = require('./c');\n"
                                    "const z = require('./d');\nexec(x(req));\nexec(y(req));\nexec(getIt(req));\nexec(z(req));\n")))
    sets.append(js_files(("a.js", "function probe() { var result = typeof win.location.href; return 1; }\n"
                                  "function make() { var result = compute(); return result; }\n"
                                  "function use() { el.innerHTML = make(); }\nfunction getQ() { return req.query.q; }\n"
                                  "app.get('/', function (req, res) {\n  const c = getQ();\n"
                                  "  db.run(sql, function (err) { exec(c); });\n});\n"
                                  "const cmd = req.query.c;\nfunction runIt(cmd) { exec(cmd); }\n"
                                  "const id = (cmd) => cmd;\nid(cmd);\n")))
    chain = "".join(f"function c{i}(a) {{ return c{i + 1}(a); }}\n" for i in range(40))
    sets.append(js_files(("chain.js", chain + "function c40(a) { return req.query.q; }\nexec(c0(1));\n")))
    chain = "".join(f"function c{i}() {{ return v{i + 1}; }}\nvar v{i + 1} = c{i + 1}();\n" for i in range(40))
    sets.append(js_files(("vchain.js", chain + "function c40() { return req.query.q; }\nexec(c0());\n")))
    lib = "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\nmodule.exports = { runIt };\n"
    route = "app.get('/x', (req, res) => {\n  CALL;\n});\n"
    sets.append(js_files(
        ("lib/run.js", lib), ("b1.js", "export * from './lib/run';\n"),
        *[(f"b{i}.js", f"export * from './b{i - 1}';\n") for i in range(2, 6)],
        ("a1.js", route.replace("CALL", "require('./lib/run').runIt(req.query.q)")),
        ("a2.js", "const lib = require('./lib/run');\nconst o = lib;\n" + route.replace("CALL", "o.runIt(req.query.q)")),
        ("a3.js", "import { runIt } from '@/lib/run';\n" + route.replace("CALL", "runIt(req.query.q)")),
        ("a4.js", "import { runIt } from './b5';\n" + route.replace("CALL", "runIt(req.query.q)")),
        ("a5.js", "const { runIt } = require('./lib/run');\n" + route.replace("CALL", "const go = runIt; go(req.query.q)")),
        ("a6.js", "const { runIt: go } = require('./lib/run');\nfunction unrelated() {\n  function go(x) { log(x); }\n}\n"
                  + route.replace("CALL", "go(req.query.q)")),
        ("a7.js", "function apply(runIt, q) {\n  runIt(q);\n}\n" + route.replace("CALL", "apply(log, req.query.q)")),
        ("a8.js", route.replace("CALL", "JSON.parse(req.query.q); const s = req.query.q; s.replace(/a/g, 'b')")),
        ("a9.js", "const { readFile } = require('node:fs');\n" + route.replace("CALL", "readFile(req.query.q)")),
        ("h.js", "module.exports = {\n  runIt(cmd) { exec(cmd); },\n  handle(req) { this.runIt(req.query.q); },\n};\n"),
        ("run.js", "module.exports = function runIt(cmd) { exec(cmd); };\n"),
        ("a10.js", route.replace("CALL", "require('./run')(req.query.q)")),
        ("a11.js", "let m = require('./b1');\nm = require('./lib/run');\n" + route.replace("CALL", "m.runIt(req.query.q)")),
        ("a12.js", "const { runIt } = require('./lib/run');\nfunction tidy(x) { return 'x'; }\ntidy = runIt;\n"
                   + route.replace("CALL", "tidy(req.query.q)"))))
    helpers = ("function runIt(cmd) {\n  exec('ls ' + cmd);\n}\n"
               "function t1(x) {\n  const y = x.trim();\n  return y;\n}\n"
               "function t2(x) {\n  let s = 'ls ';\n  s += x;\n  return s;\n}\n"
               "function t3(x) {\n  const a = [];\n  a.push(x);\n  return a.join(' ');\n}\n"
               "function T4(x) {\n  this.v = x;\n}\nfunction ok(s) {\n  if (s.length > 3) return true;\n  return false;\n}\n"
               "function escapeHtml(s) { return s; }\nfunction show(h) { el.innerHTML = h; }\n"
               "function getName(req) { return escapeHtml(req.query.n); }\n"
               "function viaClosure(req) {\n  let c;\n  [1].forEach(i => { c = req.query.cmd; });\n  return c;\n}\n"
               "function viaCb(cmd) {\n  exec(cmd());\n}\n"
               "module.exports = { runIt, t1, t2, t3, T4, ok, escapeHtml, show, getName, viaClosure, viaCb };\n")
    sets.append(js_files(("h.js", helpers), ("app.js", (
        "const { runIt, t1, t2, t3, T4, ok, escapeHtml, show, getName, viaClosure, viaCb } = require('./h')\n"
        "app.get('/x', (req, res) => {\n  const a = t1(req.query.q); runIt(a)\n  const b = t2(req.query.q); runIt(b)\n"
        "  const c = t3(req.query.q); runIt(c)\n  const d = new T4(req.query.q); runIt(d)\n"
        "  const e = ok(req.query.q); runIt(e)\n  show(escapeHtml(req.query.q))\n  el.innerHTML = getName(req)\n"
        "  exec(viaClosure(req))\n  viaCb(x => req.query.q)\n  let f\n  f = req.query.q\n  runIt(f)\n})\n"))))
    # values through locals (tests/scanner/test_review_flow_js_locals.py)
    bodies = [
        "const q = 'SELECT * FROM t WHERE a = ' + p;\n  return db.query(q);",
        "const q =\n    `SELECT * FROM t WHERE a = '${p}'`;\n  return db.query(q)",
        "let q = 'SELECT 1';\n  if (!p) q = 'SELECT 2';\n  else q += ' WHERE a = ' + p;\n  return db.query(q);",
        "let q = 'SELECT * FROM t WHERE 1=1';\n  if (p) q += \" AND a = '\" + p + \"'\";\n  return db.query(q);",
        "const a = p.trim();\n  const q = 'SELECT ' + a;\n  ids.forEach((i) => { db.query(q); });",
        "let q;\n  [1].forEach(() => { q = 'SELECT ' + p; });\n  return db.query(q);",
        "const w = [];\n  if (p.name) w.push(\"name = '\" + p.name + \"'\");\n  return db.query('SELECT * WHERE ' + w.join(' AND '));",
        "const parts = ['SELECT ('];\n  parts.push(p);\n  const q = parts.join('');\n  return db.query(q);",
        "const { id } = p;\n  const [x] = id;\n  return db.query('SELECT * FROM t WHERE id = ' + x);",
        "let s = '';\n  for (const [k, v] of Object.entries(p)) {\n    s += k + ' = ' + v;\n  }\n  return db.query('UPDATE ' + s);",
        "for (const k in p) {\n    exec('echo ' + k);\n  }",
        "const c = format(p);\n  exec(c);\n  const h = '<b>' + p;\n  el.innerHTML = h;\n  const u = API + p;\n  fetch(u);",
        "const t = p || '/';\n  res.redirect(t);\n  const s = 'return ' + p;\n  eval(s);",
        "const params = [p];\n  db.query('SELECT $1', params);\n  const like = '%' + p + '%';\n  db.query('SELECT $1', [like]);",
        "const q = p;\n  db.query(q);\n  const r = sql`SELECT ${p}`;\n  db.query(r);\n  const n = parseInt(p, 10);\n  exec('kill ' + n);",
        "const s = escapeHtml(p);\n  el.innerHTML = s;\n  const e = pool.escape(p);\n  pool.query('SELECT ' + e);",
        "const q = 'SELECT ' + p;\n  items.map(function (q) {\n    return db.query(q + ' LIMIT 1');\n  });",
    ]
    locals_lib = "".join(f"function l{k}(p) {{\n  {b}\n}}\n" for k, b in enumerate(bodies))
    locals_lib += ("function pat({ id, name }, opts = pick(a, b), p) {\n  const q = 'SELECT ' + id;\n  db.query(q);\n"
                   "  const c = p;\n  exec(c);\n}\nconst arrow = (p) => {\n  const q = 'SELECT ' + p;\n  return db.query(q);\n};\n"
                   "function isValid(s) {\n  if (s.length > 3) return true;\n  return false;\n}\n"
                   "function checked(p) {\n  const ok = isValid(p);\n  exec('check ' + ok);\n}\n"
                   "function wide(" + ", ".join(f"p{i}" for i in range(70)) + ") {\n  const c = "
                   + " + ".join(f"p{i}" for i in range(70)) + ";\n  exec(c);\n}\n")
    calls = "".join(f"  l{k}(req.query.q);\n" for k in range(len(bodies)))
    calls += ("  pat(req.body, 1, req.query.q);\n  arrow(req.query.q);\n  checked(req.query.q);\n"
              "  wide(" + ", ".join("1" for _ in range(63)) + ", req.query.q);\n"
              "  wide(" + ", ".join("1" for _ in range(64)) + ", req.query.q);\n"
              "  const { user, pass: pw } = req.body;\n  l0(user);\n  l3(pw);\n  const [first] = req.body.list;\n"
              "  l4(first);\n  for (const u of req.body.users) l5(u)\n  let v = 'x';\n  if (req.body.v) v = req.body.v;\n"
              "  l6(v);\n")
    sets.append(js_files(("locals.js", locals_lib + "module.exports = { "
                          + ", ".join([f"l{k}" for k in range(len(bodies))] + ["pat", "arrow", "checked", "wide"]) + " };\n"),
                         ("app.js", "const L = require('./locals');\nconst { " + ", ".join(
                             [f"l{k}" for k in range(len(bodies))] + ["pat", "arrow", "checked", "wide"])
                          + " } = L;\napp.post('/x', (req, res) => {\n" + calls + "});\n")))
    # RegExp receivers (tests/scanner/test_review_flow_js_regexp.py)
    from tests.scanner import test_review_flow_js_regexp as rx
    rx_app = rx.APP
    for src in [rx.lib("  return /^(\\w+)=(.*)$/.exec(p);"), rx.lib("  return /x/gi\n    .exec(p);"),
                rx.lib("  return RE.exec(p) && RE.test(p);", "const RE = /x/g;\nRE.lastIndex = 0;\n"),
                rx.lib("  var m = CRED.exec(p)\n  return m", "var CRED = /^ *(?:[Bb]asic) +(\\S+) *$/\n"),
                rx.lib("  return new RegExp('^a').exec(p) || RegExp('b').exec(p);"),
                rx.lib("  return re.exec(p);", "const re: RegExp = new RegExp('^' + prefix, 'i');\n"),
                rx.lib("  if (p) {\n    let re = /x/\n    return re.exec(p)\n  }"),
                rx.lib("  const m = /^(\\w+)$/.exec(p);\n  cp.exec('ls ' + p);", "const cp = require('child_process');\n"),
                rx.lib("  o.re.exec(p);\n  re?.exec(p);", "const o = { re: /x/ };\nconst re = /y/;\n"),
                rx.lib("  const re = require('child_process');\n  re.exec(p);", "const re = /x/;\n"),
                rx.lib("  [cp].forEach(re => re.exec(p));\n  try { throw cp; } catch (x) { x.exec(p); }",
                       "const re = /x/;\nconst x = /y/;\nconst cp = require('child_process');\n"),
                rx.lib("  re.exec(p);", "const re = /x/;\nre.exec = require('child_process').exec;\n"),
                rx.lib("  return /x/.exec(p);", "RegExp.prototype.exec = function (c) { return run(c); };\n"),
                rx.lib("  with (env) { re.exec(p); }\n  return /y/.exec(p);", "const re = /x/;\n"),
                rx.lib("  eval(code);\n  re.exec(p);", "const re = /x/;\n"),
                rx.lib("  new RegExp('x').exec(p);", "globalThis.RegExp = function () { return require('child_process'); };\n"),
                rx.lib("  re.exec(p);", "const re = /x/ && require('child_process');\n"),
                "function g() {\n  const re = /x/;\n}\n" + rx.lib("  re.exec(p);\n  " + ASTRAL + "/z/.exec(p);")]:
        sets.append(js_files(("lib.js", src), ("app.js", rx_app)))
    nest = "function pad(a){return g(function(){" * 2500 + "}})" * 2500 + "\n"
    sets.append(js_files(("lib.js", lib), ("app.js", nest + "const { runIt } = require('./lib');\n"
                                                        + route.replace("CALL", "runIt(req.query.q)"))))
    scopes = "function f0(e0) {" + "".join(f"function f{i}(e{i}) {{ var t{i} = e{i} + t{i - 1};" for i in range(1, 400))
    sets.append(js_files(("deep.js", scopes + "exec(t399);" + "}" * 400 + "\nf0(req.query.q);\n")))
    sets.append(js_files(("nest.js", "function g(req){return req.query.q}\n" + "exec(" * 20000 + "g(req)" + ")" * 20000 + "\n")))
    sets.append(js_files(("nest.js", "function f(a){return g(function(){" * 5000 + "\U0001F600" * 3000)))
    # the fixpoint's cap and the work budget (tests/scanner/test_review_flow_js_modules.py)
    chain = "".join(f"function c{i}() {{ return v{i + 1}; }}\nvar v{i + 1} = c{i + 1}();\n" for i in range(60))
    sets.append(js_files(("vchain60.js", chain + "function c60() { return req.query.q; }\nexec(c0());\n")))
    sets.append(js_files(("budget.js", chain + "function c60() { return req.query.q; }\n" + "x = y + z;\n" * 6000
                          + "exec(c0());\n")))
    # the engine's own cases (tests/scanner/test_jsflow.py) and files the reader rejects or skips
    from tests.scanner import test_jsflow as jf
    lib, use = jf.LIB, jf.USE
    for app in ("app.get('/x', (rq, rs) => {\n  runIt(rq.query.a);\n});\n",
                "router.route('/x').get(ok).post((q, s) => {\n  runIt(q.body.a);\n});\n",
                "app.use((err, q, s, next) => {\n  runIt(q.query.a);\n  runIt(err.message);\n});\n",
                "app.post('/x', asyncHandler(async (q, s) => {\n  runIt(q.params.id);\n}));\n",
                "router.get('/x', async (ctx) => {\n  runIt(ctx.request.body.a);\n});\n",
                "cache.get('key', (q, s) => {\n  runIt(q.query.a);\n});\n"):
        sets.append(js_files(("lib.js", lib), ("app.js", use + app)))
    sets.append(js_files(("lib.js", jf.Urls.LIB), ("app.js", (
        "const L = require('./lib');\napp.get('/x', (req, res) => {\n  L.get(req.query.a);\n  L.get2(req.query.a);\n"
        "  L.get3(req.query.b, 1);\n  L.go(res, req.query.a);\n  L.go2(res, req.query.a);\n  L.go3(res, req.query.a);\n"
        "});\n"))))
    sets.append(js_files(("cfg.js", "export const target = process.argv[2];\nexport let other = 'x';\n"),
                         ("run.js", "import { target, other } from './cfg.js';\nexec('ping ' + target);\nexec('ping ' + other);\n")))
    sets.append(js_files(("repo.js", "class Repo {\n  find(id) {\n    return this.db.query('SELECT * FROM t WHERE id = ' + id);\n"
                                     "  }\n  static run(c) {\n    exec(c);\n  }\n}\nclass Sub extends Repo {\n  look(id) {\n"
                                     "    return super.find(id);\n  }\n}\nmodule.exports = { Repo, Sub };\n"),
                         ("app.js", "const { Repo, Sub } = require('./repo');\napp.get('/x', (req, res) => {\n"
                                    "  new Repo().find(req.query.id);\n  Repo.run(req.query.c);\n  new Sub().look(req.query.id);\n});\n")))
    sets.append(js_files(("lib.ts", "namespace N { export function f(x: string) { return x; } }\nenum E { A = 1 }\n"
                                    "function run(c: string): void { exec(c); }\nexport = run;\n"),
                         ("app.ts", "import run = require('./lib');\napp.get('/x', (req: any, res: any) => {\n"
                                    "  run(req.query.c as string);\n});\n"),
                         ("Html.jsx", "export function Html({ html }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n"),
                         ("page.jsx", "import { Html } from './Html';\nexport const Page = () => Html({ html: location.hash });\n"),
                         ("types.d.ts", "export declare function f(): void;\n"), ("broken.js", "function (\n"),
                         ("a.cts", "export = function f(): void;\n")))
    return sets


TOKENS = ["'", '"', "`", "${", "}", "{", "(", ")", "[", "]", "/", "*", "\\", "\n", LS, chr(0x2029), " ", "\t",
          "return", "typeof", "x", "a1", "_$", "9", "3.5e1", "=", "+", "-", ";", ",", ":", "?", "!", "&", "|",
          "<", ">", "~", "^", "%", ".", ASTRAL, "\u00e9", "\u00a0", "\ufeff", "\x85", "//", "/*", "*/", "\r",
          "function f(a, b) {", "const g = (c) => {", "let h = async function (d) {", "exec(", "eval(",
          "req.query.q", "db.query(`", "el.innerHTML = ", "fetch(", "res.redirect(", "f(req.query.x)",
          "g(t)", "const t = req.body.z;", "h(t, 1)", "new Function(", chr(0x10400), "parseInt(", "quote(",
          "return ", "return req.query.r;", "require('./p1')", "import { f, g as h } from './p0';",
          "export function f(x) {", "module.exports = { f, g };", "exports.h = f;", "export * from './p2';",
          "export default g;", "const { f, g: k } = require('./p1');", "import * as ns from './p1';", "ns.f(",
          "obj.g(", "this.h(", "=>", "function* ", "escapeHtml(", "shellQuote(", "Number(", "?.", "getQ(req)",
          "const getQ = (r) => r.query.x;", "function getQ(r) { return r.body.y; }", "k(", "m.f(",
          "const m = require('./p3');", "import d from './p2';", "d(", "export { f as g };", "module.exports = f;",
          "if (", "catch (", ") {", "exec(f(req.query.q));", "el.innerHTML = g(t);",
          "const { a: b, c } = ", "let [p, , ...q] = ", "for (const {print:c, node:p} of D) {",
          "var e, t = 1, n = f(1, 2), r;", "let r=(i,s={})=>{", "x += ", "s += req.query.q;", "new Box(",
          "super.f(", "JSON.parse(", "require('./p1').f(", "require('./p2')(", "const o = m;", "const go = f;",
          "go(", "o.f(", "x.replace(", "x => req.query.q", "(a, b) => a", "function () { return req.body.w; }",
          "import { readFile } from 'fs';", "readFile(", "import { g } from '@/lib/g';", "f = g;",
          "function isOk(s) { return true; }", "isOk(", "function escapeHtml(s) { return s; }",
          "(x: string, y?: T) => {", "e.r(", "t(", "a?.b?.(", "let data\n", "data = req.query.d\n",
          "if (x) q += ", "else q = ", "=> q = ", ") q = ", "for (const [k, v] of ", "for (let k in ", "for (var x of ",
          "w.push(", "w.unshift(", ".join(", ".concat(", "const { u } = req.body;", "const [a1, b1] = ", "sql`",
          "function f({ a, b }, c = g(1, 2)) {", "const q = 'SELECT ' + a;", "db.query(q);", "db.query(q, [a]);",
          "q = q + ", "x++ + ", "+x", "`${a}`", "tag`${q}`",
          "/x/g.exec(", "/a b/.exec(", ".exec(", "new RegExp(", "RegExp(", "const re = /x/;", "re.exec(",
          "let re = new RegExp(q)\n", "re.lastIndex = 0;", "RegExp.prototype", "with (", "catch (re) {", "re?.exec(",
          "var CRED = /x/i\n", "CRED.exec(", "cp.exec(", "instanceof RegExp", "re = cp;"]


def soup(rnd):
    return "".join(rnd.choice(TOKENS) for _ in range(rnd.randint(0, 70)))


@unittest.skipUnless(parity.NODE, "node is not installed")
class FlowParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    @unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
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

    @unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
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

    @unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
    def test_coverage_notes_do_not_rate_the_code(self):
        """A file the JavaScript reader rejects is a Q-FLOW-SKIPPED note: it
        says what was not analyzed, not how the code is written, so neither
        engine counts it as a smell (the npm engine did: its random-junk
        eval corpus rated E where Python rated A)."""
        tree = {f"bad{k}.js": "function (\n" for k in range(3)}
        tree["ok.js"] = "const a = 1;\n"
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            js, py = parity.both(root)
            self.assert_same(js, py, label="coverage notes")
            for _, report, _ in (js, py):
                self.assertEqual([i["rule"] for i in report["issues"]], ["Q-FLOW-SKIPPED"] * 3)
                self.assertEqual(report["ratings"]["maintainability"], "A")

    @unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
    def test_engines_agree_on_every_finding(self):
        rnd = random.Random(20260927)
        sets = review_cases()
        sets.extend(jsgen.projects(20260928, 150))
        for _ in range(200):
            sets.append([{"path": f"p{k}.js", "content": soup(rnd) + "\n" + soup(rnd) + "\n" + soup(rnd), "lang": "js"}
                         for k in range(rnd.randint(1, 4))])
        p = subprocess.run([parity.NODE, "--input-type=module", "-e", NPM_FLOW, FLOW_JS],
                           input=json.dumps({"sets": sets}), capture_output=True,
                           encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        got = json.loads(p.stdout)
        total = 0
        for files, js in zip(sets, got):
            want = flow.analyze(files)
            total += len(want)
            self.assertEqual(js, want, json.dumps(files)[:300])
        # not vacuous: every sink category, both kinds of flow, each note
        found = [i for f in got for i in f]
        rules = {i["rule"] for i in found}
        self.assertTrue({"X-CMD", "X-SQL", "X-XSS", "X-CODE", "X-SSRF", "X-REDIR", "X-PATH", "X-SSTI", "X-FLOW-SKIPPED",
                         "Q-FLOW-SKIPPED", "Q-FLOW-INCOMPLETE"} <= rules, rules)
        self.assertEqual({i["name"] for i in found if i["rule"] == "Q-FLOW-INCOMPLETE"},
                         {"Flow analysis incomplete (iteration cap)", "Flow analysis incomplete (size budget)"})
        self.assertGreater(sum("the value returned by" in i["why"] for i in found), 50)
        self.assertGreater(sum("imported from" in i["why"] for i in found), 0)
        self.assertGreater(total, 1000)


if __name__ == "__main__":
    unittest.main()
