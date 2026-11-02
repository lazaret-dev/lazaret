// Q-4 (0.1.9): the intra-file taint pass follows a call into the helper it
// names — a function or a method of a class defined in the file, or in another
// file of the project — that returns untrusted data of its own (it reads the
// request): the call carries that data too. Following only adds (reworked after
// two independent reviews): the call's text is read as before and never loses
// what it carries, so a helper returning a constant clears nothing. Twin of
// python/tests/scanner/test_taint_helpers.py: the pass is the native engine's in
// both packages (its helpers are held by
// rust/crates/lazaret-engine/src/taint_tests.rs). Nothing here runs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { taintScan } from "../src/scanner/scan.js";
import { collectionIssues, projectHelpers } from "../src/scancollection.js";

const FLASK = "from flask import Flask, request\nimport os, html\napp = Flask(__name__)\n";
const WRAPPER = "class Wrapper:\n    def __init__(self, request):\n        self.request = request\n"
  + "    def get_param(self, name):\n        return self.request.args.get(name)\n"
  + "    def get_value(self, name):\n        return 'bar'\n";
const HELPERS = "def passthru(x):\n    return x.strip()\ndef constant(x):\n    return 'safe'\n"
  + "def escaped(x):\n    return html.escape(x)\ndef read_param():\n    return request.args.get('p')\n";
const view = (body) => FLASK + WRAPPER + HELPERS + "@app.route('/a')\ndef a():\n" + body.map((l) => `    ${l}\n`).join("");
const marked = (src) => src.split("\n").flatMap((l, k) => (l.trimEnd().endsWith("# !") ? [k + 1] : []));
const found = (src) => new Set(taintScan("x.py", src.split("\n"), "py")
  .filter((i) => i.rule.startsWith("T-")).map((i) => `${i.rule}:${i.line}`));

test("a helper that returns the request's data, or what it was given, is followed", () => {
  const reported = [
    ["w = Wrapper(request)", "param = w.get_param('id')", "os.system('ls ' + param)  # !"],
    ["param = Wrapper(request).get_param('id')", "os.system(param)  # !"],
    ["v = read_param()", "os.system(v)  # !"],
    ["v = passthru(request.args['q'])", "os.system(v)  # !"],
    ["v = escaped(request.args['q'])", "os.system(v)  # !"],
  ];
  for (const body of reported) {
    const src = view(body);
    assert.deepEqual(found(src), new Set(marked(src).map((n) => `T-CMD:${n}`)), body.join(" / "));
  }
});

test("a helper adds nothing where it returns no untrusted data of its own, and takes nothing away", () => {
  const quiet = [
    ["w = Wrapper(request)", "param = w.get_value('id')", "os.system('ls ' + param)"],
    ["v = escaped(request.args['q'])", "return '<p>' + v"],
    ["v = passthru('x')", "os.system(v)"],
  ];
  for (const body of quiet) assert.deepEqual(found(view(body)), new Set(), body.join(" / "));
  const kept = [
    ["w = Wrapper(request.args)", "param = w.get_value('id')", "os.system(param)  # !"],
    ["v = constant(request.args['q'])", "os.system(v)  # !"],
  ];
  for (const body of kept) {
    const src = view(body);
    assert.deepEqual(found(src), new Set(marked(src).map((n) => `T-CMD:${n}`)), body.join(" / "));
  }
});

test("the helper in another file of the project", () => {
  const helper = "from flask import request\nfrom html import escape\n" + WRAPPER + HELPERS.replace("html.escape", "escape");
  const project = (imports, body) => ({
    files: [
      { path: "helpers/__init__.py", content: "", lang: "py", dep: false },
      { path: "helpers/wrap.py", content: helper, lang: "py", dep: false },
      { path: "app/view.py", lang: "py", dep: false,
        content: imports + "\nfrom flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n"
          + body.map((l) => `    ${l}\n`).join("") },
    ],
    manifests: [], configs: [], binaryIssues: [], skippedIssues: [],
  });
  const viewFindings = (col) => new Set(collectionIssues(col)
    .filter((i) => i.file === "app/view.py" && i.rule.startsWith("T-")).map((i) => `${i.rule}:${i.line}`));
  const reported = [
    ["import helpers.wrap", ["x = helpers.wrap.Wrapper(request)", "param = x.get_param('id')", "os.system(param)  # !"]],
    ["from helpers.wrap import Wrapper", ["x = Wrapper(request)", "os.system(x.get_param('h'))  # !"]],
    ["from helpers import wrap", ["v = wrap.read_param()", "os.system(v)  # !"]],
    ["import helpers.wrap as hw", ["v = hw.passthru(request.args['q'])", "os.system(v)  # !"]],
  ];
  for (const [imports, body] of reported) {
    const col = project(imports, body);
    const want = new Set(marked(col.files[2].content).map((n) => `T-CMD:${n}`));
    assert.ok(want.size > 0);
    assert.deepEqual(viewFindings(col), want, imports);
  }
  const quiet = [
    ["import helpers.wrap", ["x = helpers.wrap.Wrapper(request)", "param = x.get_value('id')", "os.system(param)"]],
  ];
  for (const [imports, body] of quiet) assert.deepEqual(viewFindings(project(imports, body)), new Set(), imports);
  const col = project("from helpers.wrap import constant", ["v = constant(request.args['q'])", "os.system(v)  # !"]);
  assert.deepEqual(viewFindings(col), new Set(marked(col.files[2].content).map((n) => `T-CMD:${n}`)));
});

// (following only adds) each reported before Q-4, the call read as text; lost by one of Q-4's earlier versions
const Q = "request.args['q']";
const app = (helpers, body) => FLASK + helpers + "@app.route('/a')\ndef a():\n" + body.map((l) => `    ${l}\n`).join("");
const BASE_SUB = "class Base:\n    def __init__(self, p):\n        self.p = p\n    def get(self):\n        return self.p\n"
  + "class Sub(Base):\n    def get(self):\n        return 'const'\n";
const PICK = "def pick(p):\n    return 'x'\n";

test("a helper, however it is written, keeps what its call's text carries", () => {
  const cases = [
    ["def gen(p):\n    for x in p:\n        yield x\n", [`os.system(''.join(gen(${Q})))  # !`]],
    ["def pick(p):\n    if p: return p\n    return 'g'\n", [`os.system(pick(${Q}))  # !`]],
    ["def pick(p):\n    k, v = p.split('=', 1)\n    return v\n", [`os.system(pick(${Q}))  # !`]],
    ["def pick(p):\n    if (v := p.strip()):\n        return v\n    return ''\n", [`os.system(pick(${Q}))  # !`]],
    ["def pick(p):\n    with ctx(p) as v:\n        return v\n", [`os.system(pick(${Q}))  # !`]],
    ["def pick(p):\n    def inner():\n        return p\n    return inner()\n", [`os.system(pick(${Q}))  # !`]],
    ["class W:\n    def set(self, p):\n        self.v = p\n        return self.v\n", [`os.system(W().set(${Q}))  # !`]],
    ["class B:\n    def get(self, p):\n        return p\nclass S(B):\n    def get(self, p):\n        return super().get(p)\n",
      [`os.system(S().get(${Q}))  # !`]],
  ];
  for (const [helpers, body] of cases) {
    const src = app(helpers, body);
    assert.deepEqual(found(src), new Set(marked(src).map((n) => `T-CMD:${n}`)), helpers);
  }
});

test("a call that may reach another definition, or state the helper reads, keeps what its text carries", () => {
  const cases = [
    [BASE_SUB, ["if request.args.get('m'):", `    x = Base(${Q})`, "else:", `    x = Sub(${Q})`, "os.system(x.get())  # !"]],
    [BASE_SUB, [`x = Sub(${Q})`, "x.get = lambda: x.p", "os.system(x.get())  # !"]],
    ["class T:\n    def run(self, p):\n        return 'x'\n    def go(self, p):\n        return self.run(p)\n"
      + "class U(T):\n    def run(self, p):\n        return p\n", [`os.system(U().go(${Q}))  # !`]],
    [PICK + "def ident(p):\n    return p\npick = ident\n", [`os.system(pick(${Q}))  # !`]],
    [PICK + "from helpers import *\n", [`os.system(pick(${Q}))  # !`]],
    [PICK, ["from shlex import quote as pick", `os.system(pick(${Q}))  # !`]],
    ["import functools\n@functools.singledispatch\n" + PICK, [`os.system(pick(${Q}))  # !`]],
    [PICK, [`os.system(pick(${Q}))  # !`]],
    ["CONFIG = {'cmd': 'ls'}\ndef current(p):\n    return CONFIG['cmd']\n", [`CONFIG['cmd'] = ${Q}`, `os.system(current(${Q}))  # !`]],
    ["class C:\n    def __init__(self, f):\n        self.get = f\n    def get(self, p):\n        return 'safe'\n",
      ["x = C(str.strip)", `os.system(x.get(${Q}))  # !`]],
    [PICK, [`os.system(pick(v := ${Q}) + v)  # !`]],
  ];
  for (const [helpers, body] of cases) {
    const src = app(helpers, body);
    assert.deepEqual(found(src), new Set(marked(src).map((n) => `T-CMD:${n}`)), body.join(" / "));
  }
});

test("the cross-file versions keep what the call's text carries", () => {
  const VIEW = "from flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n";
  const project = (files, imports, body) => ({
    files: [...Object.entries(files).map(([path, content]) => ({ path, content, lang: "py", dep: false })),
      { path: "app/__init__.py", content: "", lang: "py", dep: false },
      { path: "app/view.py", lang: "py", dep: false, content: imports + "\n" + VIEW + body.map((l) => `    ${l}\n`).join("") }],
    manifests: [], configs: [], binaryIssues: [], skippedIssues: [],
  });
  const cases = [
    [{ "helpers.py": "def gen(p):\n    yield p\n" }, "from helpers import gen", [`for v in gen(${Q}):`, "    os.system(v)  # !"]],
    [{ "helpers.py": "def ident(p):\n    return p\ndef pick(p):\n    return 'x'\npick = ident\n" }, "from helpers import pick",
      [`os.system(pick(${Q}))  # !`]],
    [{ "pkg/__init__.py": "def pick(p):\n    return ''\nfrom .impl import pick\n", "pkg/impl.py": "def pick(p):\n    return p\n" },
      "from pkg import pick", [`os.system(pick(${Q}))  # !`]],
    [{ "models.py": BASE_SUB }, "from models import Base, Sub",
      ["if request.args.get('m'):", `    x = Base(${Q})`, "else:", `    x = Sub(${Q})`, "os.system(x.get())  # !"]],
    [{ "utils.py": "def pick(p):\n    return p\n", "app/utils.py": "def pick(p):\n    return 'x'\n" }, "import utils",
      [`os.system(utils.pick(${Q}))  # !`]],
    [{ "helpers.py": "class C:\n    def get(self, p):\n        return 'safe'\n", "patch.py": "import helpers\nhelpers.C.get = lambda self, p: p\n" },
      "import patch\nfrom helpers import C", ["x = C()", `os.system(x.get(${Q}))  # !`]],
  ];
  for (const [files, imports, body] of cases) {
    const col = project(files, imports, body);
    const view = col.files.find((f) => f.path === "app/view.py");
    const want = new Set(marked(view.content).map((n) => `T-CMD:${n}`));
    const got = new Set(collectionIssues(col).filter((i) => i.file === "app/view.py" && i.rule.startsWith("T-"))
      .map((i) => `${i.rule}:${i.line}`));
    assert.ok(want.size > 0);
    assert.deepEqual(got, want, imports);
  }
});

test("many definitions of one name take linear time", () => {
  // 8x the definitions: about 8x the time (Q-4's first version linked each call of the name to each of them)
  const classes = (n) => FLASK + Array.from({ length: n }, (_, k) => `class C${k}:\n    def get(self):\n`
    + "        return request.args.get('q')\n    def run(self):\n        os.system(self.get())\n").join("");
  const functions = (n) => FLASK + Array.from({ length: n }, (_, k) => `def get():\n    return request.args.get('q${k}')\n`
    + `def run${k}():\n    os.system(get())\n`).join("");
  const best = (src) => {
    const lines = src.split("\n");
    let t = Infinity;
    for (let k = 0; k < 3; k++) {
      const t0 = performance.now();
      taintScan("x.py", lines, "py");
      t = Math.min(t, performance.now() - t0);
    }
    return t;
  };
  for (const make of [classes, functions]) {
    const small = best(make(500));
    const big = best(make(4000));
    assert.ok(big < 24 * Math.max(small, 2), `${small.toFixed(1)}ms -> ${big.toFixed(1)}ms`);
  }
});

test("a failure of the helpers' reading warns, and each file is read with its own", async () => {
  const warned = [];
  const listen = (w) => { if (w.code === "LAZARET_TAINT_HELPERS") warned.push(w.message); };
  process.on("warning", listen);
  const got = projectHelpers([{ path: 5, content: "import a\n", lang: "py" }, { path: 6, content: "import b\n", lang: "py" }]);
  await new Promise((resolve) => setImmediate(resolve));
  process.removeListener("warning", listen);
  assert.equal(got.size, 0);
  assert.equal(warned.length, 1, "one warning");
  assert.match(warned[0], /taint pass: the helpers other files define were not read/);
});
