"""The cross-file JavaScript pass on parsed trees (0.1.7): what reading the
tree adds to the behavior the review suites pin (test_review_flow_js*.py,
test_review_flow_sink_line.py).

* Express-style routes: a function registered with `app.get('/p', fn)`,
  `router.route('/p').post(fn)`, `app.use(fn)` or wrapped
  (`asyncHandler(async (q, s) => …)`) gets the request as its first
  parameter and the response as its second (after the error of a
  four-parameter handler), whatever their names; a response's send / write
  / end is an XSS sink unless it sends JSON or a non-HTML type;
* a request's or a response's methods are the framework's: they bind to no
  project function of that name;
* a URL whose text starts with a fixed host or a path on this site
  (`'https://api.example.com/' + id`, `` `/profile/${u}` ``) is no SSRF
  or open redirect; a Server-Sent Events frame (`data: …`) is no HTML;
* jQuery's and lodash's namespaces (`$`, `jQuery`, `_`) are libraries: their
  members bind to no project function;
* classes: methods through `new C()`, `this`, `super` and static members;
  a variable another module exports carries its value to the importer; a
  tagged template calls its tag; a call that binds to a project function
  is that function, even named like a sink (`exec`);
* TypeScript's `import x = require()`, `export =`, namespaces and enums;
  declaration files (.d.ts, .d.mts, .d.cts) hold no code and are not read;
* a taint config's JavaScript sources, sinks and sanitizers apply
  (flow.configure).

The npm engine's twin (js/src/scanner/jsflow.js) must agree:
tests/architecture/test_js_parity_flow.py. Inert text only.
"""
import textwrap
import unittest

from lazaret.scanner import flow

LIB = "function runIt(c) {\n  exec('ls ' + c);\n}\nmodule.exports = { runIt };\n"
USE = "const { runIt } = require('./lib');\n"


def analyze(files):
    recs = [{"path": p, "content": textwrap.dedent(c).lstrip("\n"), "lang": "js"} for p, c in files.items()]
    return flow.analyze(recs)


def flows(files):
    return [(i["rule"], i["file"], i["line"]) for i in analyze(files) if i["rule"].startswith("X-")]


class Routes(unittest.TestCase):
    def test_a_handlers_parameters_whatever_their_names(self):
        cases = {
            "app.get": "app.get('/x', (rq, rs) => {\n  runIt(rq.query.a);\n});\n",
            "a route's methods": "router.route('/x').get(ok).post((q, s) => {\n  runIt(q.body.a);\n});\n",
            "use": "app.use(function (q, s, next) {\n  runIt(q.headers.a);\n});\n",
            "an error handler": "app.use((err, q, s, next) => {\n  runIt(q.query.a);\n  runIt(err.message);\n});\n",
            "a wrapped handler": "app.post('/x', asyncHandler(async (q, s) => {\n  runIt(q.params.id);\n}));\n",
            "paths": "app.put(['/a', /^\\/b/], function h(q) {\n  runIt(q.cookies.a);\n});\n",
            "koa": "router.get('/x', async (ctx) => {\n  runIt(ctx.request.body.a);\n});\n",
        }
        for label, app in cases.items():
            with self.subTest(case=label):
                self.assertEqual(flows({"lib.js": LIB, "app.js": USE + app}), [("X-CMD", "app.js", 3)])

    def test_what_is_no_route(self):
        for app in ("cache.get('key', (q, s) => {\n  runIt(q.query.a);\n});\n",
                    "app.get('title', (q) => {\n  runIt(q.query.a);\n});\n",
                    "emitter.on('/x', (q) => {\n  runIt(q.query.a);\n});\n"):
            with self.subTest(app=app):
                self.assertEqual(flows({"lib.js": LIB, "app.js": USE + app}), [])

    def test_a_response_whatever_its_name(self):
        lib = "function getName(req) {\n  return req.query.n;\n}\nmodule.exports = { getName };\n"
        app = ("const { getName } = require('./lib');\napp.get('/x', (rq, rs) => {\n  rs.send(getName(rq));\n"
               "  rs.type('text/plain').send(getName(rq));\n  rs.json(getName(rq));\n  rs.send({ n: getName(rq) });\n"
               "  rs.location(getName(rq));\n  rs.sendFile(getName(rq));\n  rs.sendFile(getName(rq), { root: DIR });\n"
               "});\n")
        found = analyze({"lib.js": lib, "app.js": app})
        self.assertEqual([(i["rule"], i["line"]) for i in found], [("X-XSS", 3), ("X-REDIR", 7), ("X-PATH", 8)])
        self.assertEqual(found[0]["msg"], "Possible cross-site scripting: untrusted data from lib.js:2 (in getName()) "
                                          "reaches a sink at app.js:3 (cross-file).")
        self.assertIn("the value returned by getName()", found[0]["why"])

    def test_a_requests_and_a_responses_methods_are_the_frameworks(self):
        found = flows({"lib.js": "function download(p) {\n  return readFileSync(p);\n}\nmodule.exports = { download };\n",
                       "app.js": "app.get('/x', (req, res) => {\n  res.download(req.params.f, { root: DIR });\n"
                                 "  helper.download(req.params.f);\n});\n"})
        self.assertEqual(found, [("X-PATH", "app.js", 3)])


class Urls(unittest.TestCase):
    LIB = ("function get(u) {\n  return fetch('https://api.example.com/users/' + u);\n}\n"
           "function get2(u) {\n  return fetch(`https://api.example.com/${u}`);\n}\n"
           "function get3(base, u) {\n  return fetch(base + '/users/' + u);\n}\n"
           "function go(res, u) {\n  res.redirect('/profile/' + u);\n}\n"
           "function go2(res, u) {\n  res.redirect('//' + u);\n}\n"
           "function go3(res, u) {\n  res.redirect(`https://${u}/x`);\n}\n"
           "module.exports = { get, get2, get3, go, go2, go3 };\n")

    def test_a_fixed_host_or_a_path_on_this_site(self):
        found = flows({"lib.js": self.LIB, "app.js": (
            "const L = require('./lib');\napp.get('/x', (req, res) => {\n  L.get(req.query.a);\n  L.get2(req.query.a);\n"
            "  L.get3(req.query.b, 1);\n  L.go(res, req.query.a);\n  L.go2(res, req.query.a);\n  L.go3(res, req.query.a);\n"
            "});\n")})
        self.assertEqual(found, [("X-SSRF", "app.js", 5), ("X-REDIR", "app.js", 7), ("X-REDIR", "app.js", 8)])

    def test_server_sent_events_are_no_html(self):
        found = flows({"lib.js": ("function send(res, d) {\n  res.write(`data: ${JSON.stringify(d)}\\n\\n`);\n"
                                  "  res.write('event: x\\ndata: ' + d);\n}\nfunction html(res, d) {\n"
                                  "  res.write('<p>' + d);\n}\nmodule.exports = { send, html };\n"),
                       "app.js": ("const { send, html } = require('./lib');\napp.get('/x', (req, res) => {\n"
                                  "  send(res, req.query.a);\n  html(res, req.query.a);\n});\n")})
        self.assertEqual(found, [("X-XSS", "app.js", 4)])


class Binding(unittest.TestCase):
    def test_library_namespaces(self):
        found = flows({"vendor.js": "function ajax(o) {\n  document.write(o.url);\n}\n",
                       "app.js": "$.ajax({ url: location.href });\njQuery.ajax({ url: location.hash });\n"
                                 "_.ajax({ url: location.hash });\nx.ajax({ url: location.hash });\n"})
        self.assertEqual(found, [("X-XSS", "app.js", 4)])

    def test_classes(self):
        found = flows({"repo.js": ("class Repo {\n  find(id) {\n    return this.db.query('SELECT * FROM t WHERE id = ' + id);\n"
                                   "  }\n  static run(c) {\n    exec(c);\n  }\n  byName(n) {\n    return this.find(n);\n  }\n}\n"
                                   "class Sub extends Repo {\n  look(id) {\n    return super.find(id);\n  }\n}\n"
                                   "module.exports = { Repo, Sub };\n"),
                       "app.js": ("const { Repo, Sub } = require('./repo');\napp.get('/x', (req, res) => {\n"
                                  "  new Repo().find(req.query.id);\n  Repo.run(req.query.c);\n  const s = new Sub();\n"
                                  "  s.look(req.query.id);\n  s.byName(req.query.n);\n});\n")})
        self.assertEqual(found, [("X-SQL", "app.js", 3), ("X-CMD", "app.js", 4), ("X-SQL", "app.js", 6),
                                 ("X-SQL", "app.js", 7)])

    def test_a_modules_exported_variable(self):
        found = analyze({"cfg.js": "export const target = process.argv[2];\nexport let other = 'x';\n",
                         "run.js": "import { target, other } from './cfg.js';\nexec('ping ' + target);\nexec('ping ' + other);\n"})
        self.assertEqual([(i["rule"], i["file"], i["line"]) for i in found], [("X-CMD", "run.js", 2)])
        self.assertEqual(found[0]["msg"], "Possible command injection: untrusted data from cfg.js:1 reaches a sink at "
                                          "run.js:2 (cross-file).")
        self.assertIn("the value target imported from cfg.js", found[0]["why"])

    def test_a_project_function_named_like_a_sink_is_that_function(self):
        found = flows({"db.js": "export function exec(sql) {\n  return pool.query(sql);\n}\n",
                       "app.js": "import { exec } from './db';\napp.get('/x', (req, res) => {\n"
                                 "  exec('SELECT ' + req.query.q);\n});\n"})
        self.assertEqual(found, [("X-SQL", "app.js", 3)])

    def test_a_tagged_template_calls_its_tag(self):
        found = flows({"db.js": "export function sql(strings, ...vals) {\n  return pool.query(strings.join('?') + vals.join(','));\n}\n",
                       "app.js": "import { sql } from './db';\napp.get('/x', (req, res) => {\n  sql`SELECT ${req.query.q}`;\n"
                                 "  sqlTag`SELECT ${req.query.q}`;\n});\n"})
        self.assertEqual(found, [("X-SQL", "app.js", 3)])

    def test_typescript_forms(self):
        found = flows({"lib.ts": ("namespace N { export function f(x: string) { return x; } }\nenum E { A = 1 }\n"
                                  "@sealed\nclass K {}\nfunction run(c: string): void { exec(c); }\nexport = run;\n"),
                       "app.ts": ("import run = require('./lib');\napp.get('/x', (req: any, res: any) => {\n"
                                  "  run(req.query.c as string);\n});\n")})
        self.assertEqual(found, [("X-CMD", "app.ts", 3)])

    def test_react_dangerously_set_inner_html(self):
        found = flows({"Html.jsx": ("export function Html({ html }) {\n"
                                    "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n}\n"),
                       "page.jsx": "import { Html } from './Html';\nexport const Page = () => Html({ html: location.hash });\n"})
        self.assertEqual(found, [("X-XSS", "page.jsx", 2)])


class Files(unittest.TestCase):
    def test_declaration_files_are_no_code_and_a_rejected_file_is_noted(self):
        found = analyze({"types.d.ts": "export declare function f(x: string): void;\n", "broken.js": "function (\n",
                         "a.cts": "export = function f(): void;\n"})
        self.assertEqual([(i["rule"], i["file"]) for i in found], [("Q-FLOW-SKIPPED", "a.cts"),
                                                                    ("Q-FLOW-SKIPPED", "broken.js")])
        self.assertIn("could not be read as TypeScript (line 1: ", found[0]["msg"])


class Config(unittest.TestCase):
    def setUp(self):
        self.saved = (flow._JS_SOURCE_RE, list(flow._JS_SINKS), set(flow._JS_FULL_SAN), dict(flow._JS_PARTIAL_SAN))

    def tearDown(self):
        src, sinks, full, partial = self.saved
        flow._JS_SOURCE_RE = src
        flow._JS_SINKS[:] = sinks
        flow._JS_FULL_SAN.clear()
        flow._JS_FULL_SAN.update(full)
        flow._JS_PARTIAL_SAN.clear()
        flow._JS_PARTIAL_SAN.update(partial)

    def test_configured_sources_sinks_and_sanitizers(self):
        files = {"lib.js": ("function store(v) {\n  dangerous_sink(v);\n}\nfunction put(o, v) {\n  o.rawHtml = v;\n}\n"
                            "module.exports = { store, put };\n"),
                 "app.js": ("const { store, put } = require('./lib');\nconst data = getUserInput();\nstore(data);\n"
                            "store(toSafeInt(data));\nput(el, myEscape(data));\nput(el, data);\n")}
        self.assertEqual(flows(files), [])
        warnings = []
        flow.configure({"javascript": {"sources": ["getUserInput"],
                                       "sinks": [{"pattern": "dangerous_sink", "category": "command injection"},
                                                 {"pattern": r"\.rawHtml =$", "category": "cross-site scripting"}],
                                       "sanitizers": {"full": ["toSafeInt"],
                                                      "partial": {"myEscape": ["cross-site scripting"]}}}},
                       on_warn=warnings.append)
        self.assertEqual(warnings, [])
        self.assertEqual(flows(files), [("X-CMD", "app.js", 3), ("X-XSS", "app.js", 6)])


if __name__ == "__main__":
    unittest.main()
