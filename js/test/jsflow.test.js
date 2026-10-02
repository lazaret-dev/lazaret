// The cross-file JavaScript pass on parsed trees (0.1.7; the engine's since
// the Rust-first refactor: rust/crates/lazaret-engine/src/jsflow/, through
// src/scanner/flow.js): twin of tests/scanner/test_jsflow.py. Express-style routes (a
// handler's request and response whatever their names), a request's and a
// response's methods binding to no project function, a fixed host or a path
// on this site clearing SSRF and open redirect, Server-Sent Events frames,
// library namespaces, classes, a module's exported variable, a project
// function named like a sink, tagged templates, TypeScript's forms and
// dangerouslySetInnerHTML. tests/architecture/test_js_parity_flow.py compares
// the engines. Inert text only: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFlows } from "../src/scanner/flow.js";

const LIB = "function runIt(c) {\n  exec('ls ' + c);\n}\nmodule.exports = { runIt };\n";
const USE = "const { runIt } = require('./lib');\n";
const analyze = (files) => analyzeFlows(Object.entries(files).map(([path, content]) => ({ path, content, lang: "js" })));
const flows = (files) => analyze(files).filter((i) => i.rule.startsWith("X-")).map((i) => [i.rule, i.file, i.line]);

test("a route handler's parameters, whatever their names", () => {
  const cases = {
    "app.get": "app.get('/x', (rq, rs) => {\n  runIt(rq.query.a);\n});\n",
    "a route's methods": "router.route('/x').get(ok).post((q, s) => {\n  runIt(q.body.a);\n});\n",
    use: "app.use(function (q, s, next) {\n  runIt(q.headers.a);\n});\n",
    "an error handler": "app.use((err, q, s, next) => {\n  runIt(q.query.a);\n  runIt(err.message);\n});\n",
    "a wrapped handler": "app.post('/x', asyncHandler(async (q, s) => {\n  runIt(q.params.id);\n}));\n",
    paths: "app.put(['/a', /^\\/b/], function h(q) {\n  runIt(q.cookies.a);\n});\n",
    koa: "router.get('/x', async (ctx) => {\n  runIt(ctx.request.body.a);\n});\n",
  };
  for (const [label, app] of Object.entries(cases)) {
    assert.deepEqual(flows({ "lib.js": LIB, "app.js": USE + app }), [["X-CMD", "app.js", 3]], label);
  }
  for (const app of ["cache.get('key', (q, s) => {\n  runIt(q.query.a);\n});\n",
    "app.get('title', (q) => {\n  runIt(q.query.a);\n});\n", "emitter.on('/x', (q) => {\n  runIt(q.query.a);\n});\n"]) {
    assert.deepEqual(flows({ "lib.js": LIB, "app.js": USE + app }), [], app);
  }
});

test("a response whatever its name; a request's and a response's methods are the framework's", () => {
  const lib = "function getName(req) {\n  return req.query.n;\n}\nmodule.exports = { getName };\n";
  const app = "const { getName } = require('./lib');\napp.get('/x', (rq, rs) => {\n  rs.send(getName(rq));\n" +
    "  rs.type('text/plain').send(getName(rq));\n  rs.json(getName(rq));\n  rs.send({ n: getName(rq) });\n" +
    "  rs.location(getName(rq));\n  rs.sendFile(getName(rq));\n  rs.sendFile(getName(rq), { root: DIR });\n});\n";
  const got = analyze({ "lib.js": lib, "app.js": app });
  assert.deepEqual(got.map((i) => [i.rule, i.line]), [["X-XSS", 3], ["X-REDIR", 7], ["X-PATH", 8]]);
  assert.equal(got[0].msg, "Possible cross-site scripting: untrusted data from lib.js:2 (in getName()) " +
    "reaches a sink at app.js:3 (cross-file).");
  assert.deepEqual(flows({ "lib.js": "function download(p) {\n  return readFileSync(p);\n}\nmodule.exports = { download };\n",
    "app.js": "app.get('/x', (req, res) => {\n  res.download(req.params.f, { root: DIR });\n  helper.download(req.params.f);\n});\n" }),
  [["X-PATH", "app.js", 3]]);
});

test("a fixed host or a path on this site; Server-Sent Events are no HTML", () => {
  const lib = "function get(u) {\n  return fetch('https://api.example.com/users/' + u);\n}\n" +
    "function get2(u) {\n  return fetch(`https://api.example.com/${u}`);\n}\n" +
    "function get3(base, u) {\n  return fetch(base + '/users/' + u);\n}\n" +
    "function go(res, u) {\n  res.redirect('/profile/' + u);\n}\n" +
    "function go2(res, u) {\n  res.redirect('//' + u);\n}\n" +
    "function go3(res, u) {\n  res.redirect(`https://${u}/x`);\n}\n" +
    "module.exports = { get, get2, get3, go, go2, go3 };\n";
  assert.deepEqual(flows({ "lib.js": lib, "app.js": "const L = require('./lib');\napp.get('/x', (req, res) => {\n" +
    "  L.get(req.query.a);\n  L.get2(req.query.a);\n  L.get3(req.query.b, 1);\n  L.go(res, req.query.a);\n" +
    "  L.go2(res, req.query.a);\n  L.go3(res, req.query.a);\n});\n" }),
  [["X-SSRF", "app.js", 5], ["X-REDIR", "app.js", 7], ["X-REDIR", "app.js", 8]]);
  assert.deepEqual(flows({ "lib.js": "function send(res, d) {\n  res.write(`data: ${JSON.stringify(d)}\\n\\n`);\n" +
    "  res.write('event: x\\ndata: ' + d);\n}\nfunction html(res, d) {\n  res.write('<p>' + d);\n}\n" +
    "module.exports = { send, html };\n",
  "app.js": "const { send, html } = require('./lib');\napp.get('/x', (req, res) => {\n  send(res, req.query.a);\n" +
    "  html(res, req.query.a);\n});\n" }), [["X-XSS", "app.js", 4]]);
});

test("library namespaces, classes, a module's exported variable", () => {
  assert.deepEqual(flows({ "vendor.js": "function ajax(o) {\n  document.write(o.url);\n}\n",
    "app.js": "$.ajax({ url: location.href });\njQuery.ajax({ url: location.hash });\n_.ajax({ url: location.hash });\n" +
      "x.ajax({ url: location.hash });\n" }), [["X-XSS", "app.js", 4]]);
  assert.deepEqual(flows({ "repo.js": "class Repo {\n  find(id) {\n    return this.db.query('SELECT * FROM t WHERE id = ' + id);\n" +
      "  }\n  static run(c) {\n    exec(c);\n  }\n  byName(n) {\n    return this.find(n);\n  }\n}\n" +
      "class Sub extends Repo {\n  look(id) {\n    return super.find(id);\n  }\n}\nmodule.exports = { Repo, Sub };\n",
  "app.js": "const { Repo, Sub } = require('./repo');\napp.get('/x', (req, res) => {\n  new Repo().find(req.query.id);\n" +
      "  Repo.run(req.query.c);\n  const s = new Sub();\n  s.look(req.query.id);\n  s.byName(req.query.n);\n});\n" }),
  [["X-SQL", "app.js", 3], ["X-CMD", "app.js", 4], ["X-SQL", "app.js", 6], ["X-SQL", "app.js", 7]]);
  const got = analyze({ "cfg.js": "export const target = process.argv[2];\nexport let other = 'x';\n",
    "run.js": "import { target, other } from './cfg.js';\nexec('ping ' + target);\nexec('ping ' + other);\n" });
  assert.deepEqual(got.map((i) => [i.rule, i.file, i.line]), [["X-CMD", "run.js", 2]]);
  assert.match(got[0].why, /the value target imported from cfg\.js/);
});

test("a project function named like a sink; tagged templates; TypeScript; JSX", () => {
  assert.deepEqual(flows({ "db.js": "export function exec(sql) {\n  return pool.query(sql);\n}\n",
    "app.js": "import { exec } from './db';\napp.get('/x', (req, res) => {\n  exec('SELECT ' + req.query.q);\n});\n" }),
  [["X-SQL", "app.js", 3]]);
  assert.deepEqual(flows({ "db.js": "export function sql(strings, ...vals) {\n  return pool.query(strings.join('?') + vals.join(','));\n}\n",
    "app.js": "import { sql } from './db';\napp.get('/x', (req, res) => {\n  sql`SELECT ${req.query.q}`;\n" +
      "  sqlTag`SELECT ${req.query.q}`;\n});\n" }), [["X-SQL", "app.js", 3]]);
  assert.deepEqual(flows({ "lib.ts": "namespace N { export function f(x: string) { return x; } }\nenum E { A = 1 }\n" +
      "@sealed\nclass K {}\nfunction run(c: string): void { exec(c); }\nexport = run;\n",
  "app.ts": "import run = require('./lib');\napp.get('/x', (req: any, res: any) => {\n  run(req.query.c as string);\n});\n" }),
  [["X-CMD", "app.ts", 3]]);
  assert.deepEqual(flows({ "Html.jsx": "export function Html({ html }) {\n  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n",
    "page.jsx": "import { Html } from './Html';\nexport const Page = () => Html({ html: location.hash });\n" }),
  [["X-XSS", "page.jsx", 2]]);
});

test("declaration files are no code; a file the reader rejects is noted", () => {
  const got = analyze({ "types.d.ts": "export declare function f(x: string): void;\n", "broken.js": "function (\n",
    "a.cts": "export = function f(): void;\n" });
  assert.deepEqual(got.map((i) => [i.rule, i.file]), [["Q-FLOW-SKIPPED", "a.cts"], ["Q-FLOW-SKIPPED", "broken.js"]]);
  assert.match(got[0].msg, /could not be read as TypeScript \(line 1: /);
});
