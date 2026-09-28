// Audit P0: taint through f-strings and template literals, statements over
// several lines, augmented assignments, the Flask / Django sinks and the
// precision around them (twin of python/tests/scanner/test_taint_fstrings.py;
// the engines are held to each other on every case of that module by
// tests/architecture/test_js_parity_taint.py). Nothing here runs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";
import {
  taintCode, firstArg, positionalArgs, extent, offsiteArgs, viewBody, scopeOpener, guardedNames, neutralize,
} from "../src/scanner/taint.js";

const FLASK = "from flask import Flask, request, redirect, url_for, make_response, jsonify, render_template, abort\n";
const found = (lang, content) => new Set(scanFile({ path: `x.${lang}`, content, lang })
  .filter((i) => i.rule.startsWith("T-")).map((i) => `${i.rule}:${i.line}`));

test("f-strings, template literals, joined statements, augmented assignments", () => {
  const cases = [
    ["py", "import codecs\nname = input()\nf = codecs.open(f'/srv/files/{name}', 'r', 'utf-8')\n", ["T-PATH:3"]],
    ["py", "import os\nf = input()\nname = 'x'\nos.system(f\"ls {name}\")\nos.system(f'ls {f}')\n", ["T-CMD:5"]],
    ["js", "const { exec } = require('child_process');\nconst name = process.argv[2];\nexec(`ls ${name}`);\n", ["T-CMD:3"]],
    ["py", "import subprocess\nq = input()\nsubprocess.run(\n    f\"echo {q}\",\n    shell=True,\n)\n", ["T-CMD:3"]],
    ["js", "const cp = require('child_process');\nlet cmd = 'ls ';\ncmd += process.argv[2];\ncp.exec(cmd);\n", ["T-CMD:4"]],
    ["py", "import os\nq = input()\ncmd = 'ls '\ncmd += q\ncmd += ' -l'\nos.system(cmd)\n", ["T-CMD:6"]],
  ];
  for (const [lang, src, want] of cases) assert.deepEqual(found(lang, src), new Set(want), src);
});

test("Flask views, responses, Django", () => {
  assert.deepEqual(found("py", FLASK + "app = Flask(__name__)\n@app.route('/a')\ndef a():\n"
    + "    q = request.args.get('q', '')\n    return f'<p>{q}</p>'\n"), new Set(["T-XSS:6"]));
  assert.deepEqual(found("py", FLASK + "def a():\n    q = request.args['q']\n    resp = make_response(\n"
    + "        '<b>' + q + '</b>'\n    )\n    return resp\n"), new Set(["T-XSS:4"]));
  assert.deepEqual(found("py", "from django.http import HttpResponse\ndef v(request):\n"
    + "    q = request.GET.get('q', '')\n    return HttpResponse(f'<p>{q}</p>')\n"), new Set(["T-XSS:4"]));
  for (const quiet of [
    FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n    return {'q': q}\n",
    FLASK + "@app.route('/a')\ndef a():\n    return request.get_json()\n",
    FLASK + "@app.route('/a')\ndef a():\n    return render_template(\n        'a.html',\n        q=request.args['q'],\n    )\n",
    FLASK + "def a():\n    return redirect(url_for('auth.login', next=request.full_path))\n",
    FLASK + "def a():\n    bar = request.args['b']\n    return make_response(('text', {'X-B': bar}))\n",
  ]) assert.deepEqual(found("py", quiet), new Set(), quiet);
});

test("only the injectable arguments are read", () => {
  assert.deepEqual(found("py", "q = input()\ncur.execute('SELECT * FROM t WHERE a = ?', (q,))\n"), new Set());
  assert.deepEqual(found("js", "const q = process.argv[2];\ndb.query('SELECT * FROM t WHERE a = ?', [q]);\n"), new Set());
  assert.deepEqual(found("js", "const q = process.argv[2];\ndb.query(`SELECT * FROM t WHERE a = '${q}'`);\n"), new Set(["T-SQL:2"]));
  assert.deepEqual(found("js", "const n = process.argv[2];\ndb.query(sql`SELECT * FROM t WHERE n = ${n}`);\n"), new Set());
  assert.deepEqual(found("js", "const cp = require('child_process');\ncp.exec('ls'); console.log(location.search);\n"), new Set());
  assert.deepEqual(found("js", "app.get('/u', (req, res) => {\n  res.redirect('/user/' + req.params.id);\n});\n"), new Set());
  assert.deepEqual(found("js", "app.get('/r', (req, res) => {\n  res.redirect(301, req.query.next);\n});\n"), new Set(["T-REDIR:2"]));
});

test("guards and where a taint lives", () => {
  assert.deepEqual(found("js", "const fs = require('fs');\napp.get('/f', (req, res) => {\n  const name = req.query.name;\n"
    + "  if (name.includes('..')) return res.sendStatus(400);\n  res.send(fs.readFileSync(name));\n});\n"), new Set());
  assert.deepEqual(found("js", "const fs = require('fs');\napp.get('/a', (req, res) => {\n  const f = req.query.f;\n  res.send(f);\n});\n"
    + "app.get('/b', (req, res) => {\n  const f = '/srv/index.html';\n  res.sendFile(f);\n});\n"), new Set());
  assert.deepEqual(found("js", "const cp = require('child_process');\nfunction outer(req) {\n  const c = req.query.c;\n"
    + "  return function inner() {\n    cp.exec(c);\n  };\n}\n"), new Set(["T-CMD:5"]));
  assert.deepEqual(found("py", "import os\ndef a():\n    name = input()\n    return name\ndef b():\n    name = 'ls'\n    os.system(name)\n"), new Set());
  assert.deepEqual(found("py", "import os\nname = input()\nif name == 'x':\n    name = 'fixed'\nos.system(name)\n"), new Set(["T-CMD:5"]));
  assert.deepEqual(found("py", "import os\nq = input()\nsql = \"\"\"\nSELECT (\n\"\"\"\nq = 'x'\nos.system(q)\n"), new Set());
});

test("helpers", () => {
  assert.deepEqual(taintCode('os.system(f"ls {d!r} {{x}}" + rb"q")', "py").split(/\s+/).filter(Boolean), ["os.system(", "d!r", "+", ")"]);
  assert.deepEqual(taintCode("exec(`ls ${a}`); q = sql`x ${b}`; return `${c}`", "js").split(/\s+/).filter(Boolean),
    ["exec(", "a", ");", "q", "=", "sql;", "return", "c"]);
  assert.equal(firstArg(" (body, {'h': bar}))"), "body");
  assert.equal(positionalArgs(" url, data=d, headers=h)"), " url");
  assert.equal(extent("cmd); log(location.href)"), "cmd");
  assert.equal(offsiteArgs(" 301, '/x' + y"), " 301");
  assert.equal(viewBody(" User.to_dict(q, page=1)"), false);
  assert.equal(viewBody(" str(q)"), true);
  assert.equal(scopeOpener("app.get('/a', (req, res) => {", "js"), true);
  assert.equal(scopeOpener("if (x) {", "js"), false);
  assert.deepEqual(guardedNames("if '..' in name or not p.startswith(BASE):", "py"), ["name", "p"]);
  assert.equal(neutralize("n = request.args.get('n', 1, type=int)", "py"), "n =  ");
});

test("linear time on hostile lines", () => {
  for (const text of ["(".repeat(200_000), "'".repeat(200_000), "a,".repeat(200_000), "f'{".repeat(100_000),
    "=>".repeat(200_000) + " {", "a.".repeat(200_000) + "get(type=int)", " ".repeat(100_000) + "if '..' in x:"]) {
    const t0 = Date.now();
    firstArg(text); positionalArgs(text); extent(text); offsiteArgs(text);
    taintCode(text, "py"); taintCode(text, "js"); scopeOpener(text, "js");
    neutralize(text, "py", "XSS"); guardedNames(text, "py");
    assert.ok(Date.now() - t0 < 10_000, text.slice(0, 12));
  }
});
