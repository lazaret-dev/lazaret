"""The JavaScript cross-file heuristic follows values through local variables.

A parameter used to reach a sink only where its own name was written in the
sink's arguments: vulnerable-node's

    function login(username, password) {
      const q = "SELECT … '" + username + "' …";
      return pool.query(q);
    }

was not a flow, and neither was request data destructured at the call site
(`const { user } = req.body; db.login(user, p)`). Now:

* a parameter reaches a sink through the locals of its function (and of the
  functions inside it) that hold it — assigned from it, joined with it, `+=`,
  destructured from it, pushed into an array with it, a for … of / in over
  it — read the way request data is: sanitizers and what project functions
  return count, a scope's own declarations hide its enclosing scopes' names;
* for SQL the parameter must be joined into the query text (`+`, a `${…}` in
  an untagged template, `.join()`, `.concat()`, `+=`) on the way or in the
  sink's first argument: values bound as parameters, a whole query passed
  through, and a tagged template (sql`…${x}`) are not findings;
* a pattern parameter (`function f({ id })`) binds its names to its
  argument, and parameters are read from the whole list (`(a = f(1, 2), b)`
  is two);
* `const { a } = req.body`, `for (const x of req.body.list)` and an
  assignment in a body without braces (`if (c) q += …`) carry request data
  to the call site.

The npm engine's twin (js/src/scanner/flow.js) must agree:
tests/architecture/test_js_parity_flow.py. Inert text only.
"""
import textwrap
import time
import unittest

from lazaret.scanner import flow


def analyze(files):
    recs = [{"path": p, "content": textwrap.dedent(c).lstrip("\n"), "lang": "js"} for p, c in files.items()]
    return flow.analyze(recs)


def flows(files):
    return [(i["rule"], i["file"], i["line"]) for i in analyze(files) if i["rule"].startswith("X-")]


def lib(body, params="p"):
    return f"function f({params}) {{\n{body}\n}}\nmodule.exports = {{ f }};\n"


def route(call):
    return "const { f } = require('./lib');\napp.post('/x', (req, res) => {\n  " + call + ";\n});\n"


def one(body, call="f(req.query.q)", params="p"):
    """The findings of a route calling lib.js's f with request data."""
    return flows({"lib.js": lib(body, params), "app.js": route(call)})


class ParametersThroughLocals(unittest.TestCase):
    def test_vulnerable_node_login(self):
        found = analyze({
            "model/db.js": """
                const pool = new Pool();
                function login(username, password) {
                  const q = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
                  return pool.query(q);
                }
                module.exports = { pool, login };
                """,
            "routes/auth.js": """
                const db = require('../model/db');
                router.post('/login/auth', async (req, res) => {
                  const user = req.body.username;
                  const password = req.body.password;
                  const { rows } = await db.login(user, password);
                });
                """})
        self.assertEqual([(i["rule"], i["file"], i["line"]) for i in found], [("X-SQL", "routes/auth.js", 5)])
        self.assertEqual(found[0]["msg"], "Possible SQL injection: untrusted data from routes/auth.js:5 reaches "
                                          "a sink at model/db.js:4 (in login()) (cross-file).")

    def test_every_sink_kind(self):
        cases = {
            "X-SQL": "  const q = 'SELECT * FROM t WHERE a = ' + p;\n  return db.query(q);",
            "X-CMD": "  const c = 'ls ' + p;\n  exec(c);",
            "X-XSS": "  const h = '<b>' + p + '</b>';\n  el.innerHTML = h;",
            "X-SSRF": "  const u = API + '/users/' + p;\n  return fetch(u);",
            "X-REDIR": "  const t = p || '/';\n  res.redirect(t);",
            "X-CODE": "  const s = 'return ' + p;\n  return eval(s);",
        }
        for rule, body in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(one(body), [(rule, "app.js", 3)])

    def test_how_a_local_comes_to_hold_a_parameter(self):
        cases = {
            "on the next line": "  const q =\n    'SELECT * FROM t WHERE a = ' + p;\n  return db.query(q);",
            "a template": "  const q = `SELECT * FROM t WHERE a = '${p}'`;\n  return db.query(q);",
            "+= in an if without braces": "  let q = 'SELECT * FROM t WHERE 1=1';\n"
                                          "  if (p) q += \" AND a = '\" + p + \"'\";\n  return db.query(q);",
            "+= after else": "  let q = 'SELECT 1';\n  if (!p) q = 'SELECT 2';\n  else q += ' WHERE a = ' + p;\n"
                             "  return db.query(q);",
            "q = q + p in a block": "  let q = 'SELECT * FROM t';\n  if (p) {\n    q = q + ' WHERE a = ' + p;\n  }\n"
                                    "  return db.query(q);",
            "two hops": "  const a = p.trim();\n  const q = 'SELECT * FROM t WHERE a = ' + a;\n  return db.query(q);",
            "no semicolons": "  const q = 'SELECT * FROM t WHERE a = ' + p\n  return db.query(q)",
            "read in a closure": "  const q = 'DELETE FROM t WHERE id = ' + p;\n  ids.forEach((i) => { db.query(q); });",
            "assigned in a closure": "  let q;\n  [1].forEach(() => { q = 'SELECT ' + p; });\n  return db.query(q);",
            "through an unknown helper": "  const c = format(p);\n  return db.query('SELECT ' + c);",
            "pushed, then joined": "  const w = [];\n  if (p.name) w.push(\"name = '\" + p.name + \"'\");\n"
                                   "  const q = 'SELECT * FROM t WHERE ' + w.join(' AND ');\n  return db.query(q);",
            "raw values pushed, then joined": "  const parts = ['SELECT * FROM t WHERE id IN ('];\n  parts.push(p);\n"
                                              "  parts.push(')');\n  const q = parts.join('');\n  return db.query(q);",
            "destructured in the body": "  const { id } = p;\n  return db.query('SELECT * FROM t WHERE id = ' + id);",
            "array destructured": "  const [id] = p;\n  const q = 'SELECT ' + id;\n  return db.query(q);",
            "for .. of Object.entries": "  let s = '';\n  for (const [k, v] of Object.entries(p)) {\n"
                                        "    s += k + ' = ' + v + ', ';\n  }\n  return db.query('UPDATE t SET ' + s);",
            "for .. in keys": "  for (const k in p) {\n    db.query('SELECT ' + k);\n  }",
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self.assertEqual(one(body), [("X-SQL", "app.js", 3)])

    def test_arrow_functions_and_pattern_parameters(self):
        self.assertEqual(flows({"lib.js": "const f = (p) => {\n  const q = 'SELECT ' + p;\n  return db.query(q);\n};\n"
                                          "module.exports = { f };\n", "app.js": route("f(req.query.q)")}),
                         [("X-SQL", "app.js", 3)])
        self.assertEqual(one("  const q = 'SELECT * FROM t WHERE id = ' + id;\n  return db.query(q);",
                             "f(req.body)", "{ id, name }"), [("X-SQL", "app.js", 3)])
        self.assertEqual(one("  return db.query('SELECT * FROM t WHERE id = ' + id);", "f(req.body)", "{ id } = {}"),
                         [("X-SQL", "app.js", 3)])
        # the whole list: the default's comma doesn't make p the third parameter
        self.assertEqual(one("  const c = p;\n  exec(c);", "f({}, req.query.q)", "opts = pick(a, b), p"),
                         [("X-CMD", "app.js", 3)])
        self.assertEqual(one("  exec(p);", "f(req.query.q, 1)", "opts = pick(a, b), p"), [])

    def test_the_updateprofile_shape(self):
        # vulnerable-node: column names from the request body
        self.assertEqual(flows({
            "db.js": ("function updateProfile(userId, fields) {\n  const sets = [];\n  const values = [userId];\n"
                      "  for (const [k, v] of Object.entries(fields)) {\n    values.push(v);\n"
                      "    sets.push(`${k} = $${values.length}`);\n  }\n"
                      "  return pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1`, values);\n}\n"
                      "module.exports = { updateProfile };\n"),
            "app.js": ("const db = require('./db');\nrouter.post('/account', async (req, res) => {\n"
                       "  await db.updateProfile(req.session.userId, req.body);\n});\n")}),
            [("X-SQL", "app.js", 3)])

    def test_what_stays_quiet(self):
        cases = {
            "bound as parameters": "  const params = [p];\n  return db.query('SELECT * FROM t WHERE a = $1', params);",
            "a LIKE pattern built, but bound": "  const like = '%' + p + '%';\n"
                                               "  return db.query('SELECT * FROM t WHERE a LIKE $1', [like]);",
            "the whole query passed through": "  const q = p;\n  return db.query(q);",
            "a tagged template": "  const q = sql`SELECT * FROM t WHERE a = ${p}`;\n  return db.query(q);",
            "a constant query": "  const q = 'SELECT * FROM t WHERE a = ?';\n  return db.query(q, [p]);",
            "parseInt": "  const n = parseInt(p, 10);\n  exec('kill ' + n);",
            "Number": "  const n = Number(p);\n  return db.query('SELECT * FROM t WHERE id = ' + n);",
            "escaped for the sink": "  const s = escapeHtml(p);\n  el.innerHTML = '<b>' + s + '</b>';",
            "SQL-escaped": "  const s = pool.escape(p);\n  return pool.query('SELECT * FROM t WHERE a = ' + s);",
            "an inner function's own parameter": "  const q = 'SELECT ' + p;\n"
                                                 "  items.map(function (q) {\n    return db.query(q + ' LIMIT 1');\n  });",
            "a local of another function": "  const q = 'SELECT ' + p;\n  return q;\n}\nfunction g() {\n"
                                           "  const q = 'SELECT 1';\n  return db.query(q + ' LIMIT 1');",
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                self.assertEqual(one(body), [])
        self.assertEqual(flows({"lib.js": "function isValid(s) {\n  if (s.length > 3) return true;\n  return false;\n}\n"
                                          + lib("  const ok = isValid(p);\n  exec('check ' + ok);"),
                                "app.js": route("f(req.query.q)")}), [])
        self.assertEqual(one("  const q = 'SELECT ' + p;\n  return db.query(q);", "f('id')"), [])


class RequestDataThroughLocals(unittest.TestCase):
    SINK = "  return db.query(\"SELECT * FROM t WHERE u = '\" + p + \"'\");"

    def test_destructuring_loops_and_braceless_bodies_at_the_call_site(self):
        cases = {
            "destructured": "const { user } = req.body;\n  f(user)",
            "renamed": "const { username: u } = req.body;\n  f(u)",
            "nested": "const { a: { b } } = req.body;\n  f(b)",
            "from an array": "const [first] = req.body.list;\n  f(first)",
            "a loop": "for (const u of req.body.users) f(u)",
            "an if without braces": "let u = 'x';\n  if (req.body.u) u = req.body.u;\n  f(u)",
        }
        for label, call in cases.items():
            with self.subTest(case=label):
                self.assertEqual(one(self.SINK, call), [("X-SQL", "app.js", 3 + call.count("\n"))])
        self.assertEqual(one(self.SINK, "const { pid } = req.body;\n  f(parseInt(pid, 10))"), [])

    def test_destructured_names_are_no_aliases(self):
        # `const { runIt } = require('./lib')` still binds the function, and
        # destructuring a value binds no call to it
        found = flows({"lib.js": "function runIt(c) {\n  exec(c);\n}\nmodule.exports = { runIt };\n",
                       "app.js": "const { runIt } = require('./lib');\nconst { other } = runIt;\n"
                                 "app.get('/', (req) => {\n  runIt(req.query.q);\n});\n"})
        self.assertEqual(found, [("X-CMD", "app.js", 4)])


class Bounds(unittest.TestCase):
    def test_nested_bindings_and_deep_scopes_stay_linear(self):
        cases = {
            "patterns": "function f(p) {" + "const {a} = g(function(){" * 30000 + "}" * 30000 + "}\n",
            "loops": "function f(p) {" + "for (const x of g(function(){" * 30000 + "})){}" * 30000 + "}\n",
            "pushes": "function f(p) {\n" + "a.push(" * 200000 + "p" + ")" * 200000 + ";\n exec(a);\n}\n",
            "scopes": "function f0(e0) {" + "".join(f"function f{i}(e{i}) {{ var t{i} = e{i} + t{i - 1};"
                                                   for i in range(1, 3000)) + "exec(t2999);" + "}" * 3000 + "\n",
            "sinks": "function f(p) {\n const q = p;\n" + "exec(" * 20000 + "q" + ")" * 20000 + "\n}\n",
        }
        for label, src in cases.items():
            with self.subTest(case=label):
                t = time.perf_counter()
                analyze({"a.js": src})
                self.assertLess(time.perf_counter() - t, 20)

    def test_a_value_holds_at_most_so_many_parameters(self):
        params = ", ".join(f"p{i}" for i in range(100))
        joined = " + ".join(f"p{i}" for i in range(100))
        src = f"function f({params}) {{\n  const c = {joined};\n  exec(c);\n}}\n"
        first = ", ".join("1" for _ in range(63))
        self.assertEqual(flows({"a.js": src + f"f({first}, req.query.q);\n"}), [("X-CMD", "a.js", 5)])
        later = ", ".join("1" for _ in range(64))
        self.assertEqual(flows({"a.js": src + f"f({later}, req.query.q);\n"}), [])


if __name__ == "__main__":
    unittest.main()
