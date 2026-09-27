// The JavaScript cross-file heuristic follows values through local variables
// (twin of tests/scanner/test_review_flow_js_locals.py; the two engines are
// compared by tests/architecture/test_js_parity_flow.py). A parameter reaches
// a sink through the locals of its function that hold it — assigned from it,
// joined with it, `+=`, destructured from it, pushed into an array with it, a
// for … of / in over it — read the way request data is (sanitizers and what
// project functions return count, a scope's own declarations hide its
// enclosing scopes' names). For SQL it must be joined into the query text on
// the way or in the sink's first argument: bound values, a whole query passed
// through and a tagged template are not findings. Pattern parameters bind
// their names; request data destructured, looped over or assigned in a body
// without braces reaches the call site. Inert text only: nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeFlows } from "../src/scanner/flow.js";

const dedent = (s) => {
  const lines = s.replace(/^\n/, "").split("\n");
  const pad = Math.min(...lines.filter((l) => l.trim()).map((l) => l.match(/^ */)[0].length));
  return lines.map((l) => l.slice(pad)).join("\n");
};
const analyze = (files) => analyzeFlows(Object.entries(files).map(([path, c]) => ({ path, content: dedent(c), lang: "js" })));
const flows = (files) => analyze(files).filter((i) => i.rule.startsWith("X-")).map((i) => [i.rule, i.file, i.line]);
const lib = (body, params = "p") => `function f(${params}) {\n${body}\n}\nmodule.exports = { f };\n`;
const route = (call) => "const { f } = require('./lib');\napp.post('/x', (req, res) => {\n  " + call + ";\n});\n";
const one = (body, call = "f(req.query.q)", params = "p") => flows({ "lib.js": lib(body, params), "app.js": route(call) });

test("vulnerable-node's login: a parameter joined into a local, the local queried", () => {
  const got = analyze({
    "model/db.js": `
      const pool = new Pool();
      function login(username, password) {
        const q = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        return pool.query(q);
      }
      module.exports = { pool, login };
      `,
    "routes/auth.js": `
      const db = require('../model/db');
      router.post('/login/auth', async (req, res) => {
        const user = req.body.username;
        const password = req.body.password;
        const { rows } = await db.login(user, password);
      });
      ` });
  assert.deepEqual(got.map((i) => [i.rule, i.file, i.line]), [["X-SQL", "routes/auth.js", 5]]);
  assert.equal(got[0].msg, "Possible SQL injection: untrusted data from routes/auth.js:5 reaches a sink at model/db.js:4 (in login()) (cross-file).");
});

test("every sink kind through a local", () => {
  const cases = {
    "X-SQL": "  const q = 'SELECT * FROM t WHERE a = ' + p;\n  return db.query(q);",
    "X-CMD": "  const c = 'ls ' + p;\n  exec(c);",
    "X-XSS": "  const h = '<b>' + p + '</b>';\n  el.innerHTML = h;",
    "X-SSRF": "  const u = API + '/users/' + p;\n  return fetch(u);",
    "X-REDIR": "  const t = p || '/';\n  res.redirect(t);",
    "X-CODE": "  const s = 'return ' + p;\n  return eval(s);",
  };
  for (const [rule, body] of Object.entries(cases)) assert.deepEqual(one(body), [[rule, "app.js", 3]], rule);
});

test("how a local comes to hold a parameter", () => {
  const cases = {
    "on the next line": "  const q =\n    'SELECT * FROM t WHERE a = ' + p;\n  return db.query(q);",
    "a template": "  const q = `SELECT * FROM t WHERE a = '${p}'`;\n  return db.query(q);",
    "+= in an if without braces": "  let q = 'SELECT * FROM t WHERE 1=1';\n  if (p) q += \" AND a = '\" + p + \"'\";\n  return db.query(q);",
    "+= after else": "  let q = 'SELECT 1';\n  if (!p) q = 'SELECT 2';\n  else q += ' WHERE a = ' + p;\n  return db.query(q);",
    "q = q + p in a block": "  let q = 'SELECT * FROM t';\n  if (p) {\n    q = q + ' WHERE a = ' + p;\n  }\n  return db.query(q);",
    "two hops": "  const a = p.trim();\n  const q = 'SELECT * FROM t WHERE a = ' + a;\n  return db.query(q);",
    "no semicolons": "  const q = 'SELECT * FROM t WHERE a = ' + p\n  return db.query(q)",
    "read in a closure": "  const q = 'DELETE FROM t WHERE id = ' + p;\n  ids.forEach((i) => { db.query(q); });",
    "assigned in a closure": "  let q;\n  [1].forEach(() => { q = 'SELECT ' + p; });\n  return db.query(q);",
    "through an unknown helper": "  const c = format(p);\n  return db.query('SELECT ' + c);",
    "pushed, then joined": "  const w = [];\n  if (p.name) w.push(\"name = '\" + p.name + \"'\");\n" +
      "  const q = 'SELECT * FROM t WHERE ' + w.join(' AND ');\n  return db.query(q);",
    "raw values pushed, then joined": "  const parts = ['SELECT * FROM t WHERE id IN ('];\n  parts.push(p);\n" +
      "  parts.push(')');\n  const q = parts.join('');\n  return db.query(q);",
    "destructured in the body": "  const { id } = p;\n  return db.query('SELECT * FROM t WHERE id = ' + id);",
    "array destructured": "  const [id] = p;\n  const q = 'SELECT ' + id;\n  return db.query(q);",
    "for .. of Object.entries": "  let s = '';\n  for (const [k, v] of Object.entries(p)) {\n    s += k + ' = ' + v + ', ';\n  }\n" +
      "  return db.query('UPDATE t SET ' + s);",
    "for .. in keys": "  for (const k in p) {\n    db.query('SELECT ' + k);\n  }",
  };
  for (const [label, body] of Object.entries(cases)) assert.deepEqual(one(body), [["X-SQL", "app.js", 3]], label);
});

test("arrow functions and pattern parameters; parameters from the whole list", () => {
  assert.deepEqual(flows({ "lib.js": "const f = (p) => {\n  const q = 'SELECT ' + p;\n  return db.query(q);\n};\nmodule.exports = { f };\n",
    "app.js": route("f(req.query.q)") }), [["X-SQL", "app.js", 3]]);
  assert.deepEqual(one("  const q = 'SELECT * FROM t WHERE id = ' + id;\n  return db.query(q);", "f(req.body)", "{ id, name }"),
    [["X-SQL", "app.js", 3]]);
  assert.deepEqual(one("  return db.query('SELECT * FROM t WHERE id = ' + id);", "f(req.body)", "{ id } = {}"), [["X-SQL", "app.js", 3]]);
  assert.deepEqual(one("  const c = p;\n  exec(c);", "f({}, req.query.q)", "opts = pick(a, b), p"), [["X-CMD", "app.js", 3]]);
  assert.deepEqual(one("  exec(p);", "f(req.query.q, 1)", "opts = pick(a, b), p"), []);
});

test("vulnerable-node's updateProfile: column names from the request body", () => {
  assert.deepEqual(flows({
    "db.js": "function updateProfile(userId, fields) {\n  const sets = [];\n  const values = [userId];\n" +
      "  for (const [k, v] of Object.entries(fields)) {\n    values.push(v);\n    sets.push(`${k} = $${values.length}`);\n  }\n" +
      "  return pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1`, values);\n}\nmodule.exports = { updateProfile };\n",
    "app.js": "const db = require('./db');\nrouter.post('/account', async (req, res) => {\n  await db.updateProfile(req.session.userId, req.body);\n});\n",
  }), [["X-SQL", "app.js", 3]]);
});

test("what stays quiet", () => {
  const cases = {
    "bound as parameters": "  const params = [p];\n  return db.query('SELECT * FROM t WHERE a = $1', params);",
    "a LIKE pattern built, but bound": "  const like = '%' + p + '%';\n  return db.query('SELECT * FROM t WHERE a LIKE $1', [like]);",
    "the whole query passed through": "  const q = p;\n  return db.query(q);",
    "a tagged template": "  const q = sql`SELECT * FROM t WHERE a = ${p}`;\n  return db.query(q);",
    "a constant query": "  const q = 'SELECT * FROM t WHERE a = ?';\n  return db.query(q, [p]);",
    parseInt: "  const n = parseInt(p, 10);\n  exec('kill ' + n);",
    Number: "  const n = Number(p);\n  return db.query('SELECT * FROM t WHERE id = ' + n);",
    "escaped for the sink": "  const s = escapeHtml(p);\n  el.innerHTML = '<b>' + s + '</b>';",
    "SQL-escaped": "  const s = pool.escape(p);\n  return pool.query('SELECT * FROM t WHERE a = ' + s);",
    "an inner function's own parameter": "  const q = 'SELECT ' + p;\n  items.map(function (q) {\n    return db.query(q + ' LIMIT 1');\n  });",
    "a local of another function": "  const q = 'SELECT ' + p;\n  return q;\n}\nfunction g() {\n  const q = 'SELECT 1';\n  return db.query(q + ' LIMIT 1');",
  };
  for (const [label, body] of Object.entries(cases)) assert.deepEqual(one(body), [], label);
  assert.deepEqual(flows({ "lib.js": "function isValid(s) {\n  if (s.length > 3) return true;\n  return false;\n}\n" +
    lib("  const ok = isValid(p);\n  exec('check ' + ok);"), "app.js": route("f(req.query.q)") }), []);
  assert.deepEqual(one("  const q = 'SELECT ' + p;\n  return db.query(q);", "f('id')"), []);
});

test("request data destructured, looped over or assigned without braces reaches the call", () => {
  const sink = "  return db.query(\"SELECT * FROM t WHERE u = '\" + p + \"'\");";
  const cases = {
    destructured: "const { user } = req.body;\n  f(user)",
    renamed: "const { username: u } = req.body;\n  f(u)",
    nested: "const { a: { b } } = req.body;\n  f(b)",
    "from an array": "const [first] = req.body.list;\n  f(first)",
    "a loop": "for (const u of req.body.users) f(u)",
    "an if without braces": "let u = 'x';\n  if (req.body.u) u = req.body.u;\n  f(u)",
  };
  for (const [label, call] of Object.entries(cases)) {
    assert.deepEqual(one(sink, call), [["X-SQL", "app.js", 3 + call.split("\n").length - 1]], label);
  }
  assert.deepEqual(one(sink, "const { pid } = req.body;\n  f(parseInt(pid, 10))"), []);
});

test("destructured names are no aliases", () => {
  assert.deepEqual(flows({ "lib.js": "function runIt(c) {\n  exec(c);\n}\nmodule.exports = { runIt };\n",
    "app.js": "const { runIt } = require('./lib');\nconst { other } = runIt;\napp.get('/', (req) => {\n  runIt(req.query.q);\n});\n" }),
  [["X-CMD", "app.js", 4]]);
});

test("nested bindings and deep scopes stay linear", () => {
  let scopes = "function f0(e0) {";
  for (let i = 1; i < 3000; i++) scopes += `function f${i}(e${i}) { var t${i} = e${i} + t${i - 1};`;
  scopes += "exec(t2999);" + "}".repeat(3000) + "\n";
  const cases = {
    patterns: "function f(p) {" + "const {a} = g(function(){".repeat(30000) + "}".repeat(30000) + "}\n",
    loops: "function f(p) {" + "for (const x of g(function(){".repeat(30000) + "})){}".repeat(30000) + "}\n",
    pushes: "function f(p) {\n" + "a.push(".repeat(200000) + "p" + ")".repeat(200000) + ";\n exec(a);\n}\n",
    scopes,
    sinks: "function f(p) {\n const q = p;\n" + "exec(".repeat(20000) + "q" + ")".repeat(20000) + "\n}\n",
  };
  for (const [label, src] of Object.entries(cases)) {
    const t = Date.now();
    analyzeFlows([{ path: "a.js", content: src, lang: "js" }]);
    assert.ok(Date.now() - t < 20000, label);
  }
});

test("a value holds at most so many parameters", () => {
  const params = Array.from({ length: 100 }, (_, i) => `p${i}`);
  const src = `function f(${params.join(", ")}) {\n  const c = ${params.join(" + ")};\n  exec(c);\n}\n`;
  assert.deepEqual(flows({ "a.js": src + `f(${Array(63).fill("1").join(", ")}, req.query.q);\n` }), [["X-CMD", "a.js", 5]]);
  assert.deepEqual(flows({ "a.js": src + `f(${Array(64).fill("1").join(", ")}, req.query.q);\n` }), []);
});
