"""The JavaScript cross-file heuristic follows modules and returned values.

It used to bind a call to the last function of that name anywhere in the
project (so commander's `parse()` reached a sink in the `ms` package), read
a function's own header as a call, saw only calls whose arguments held no
parentheses, and ignored what functions return. Now:

* a call binds to what its file names: a definition visible from the call,
  else what a relative require() / import brings in (named, default and
  namespace imports, `require('./x').f()`, a module copied to a const;
  module.exports, exports.x and ESM exports; `export … from` and `export *`
  re-exports; `./x.js` naming `x.ts`) — a definite binding;
* where it cannot tell (a package, a path alias, a workspace package,
  `this.f()`, `obj.f()`, an unknown or reassigned name) the call may reach
  any project function of that name: the name-based pass's coverage is
  never lost to an unresolved import. Only positive evidence binds nothing:
  a Node built-in module, a JavaScript global object's member, a built-in
  method name on an unknown receiver, a parameter or variable a scope around
  the call declares;
* a definite call reads as what its function returns: the request data it
  returns, and its arguments unless no return of it can hold them (or all
  are sanitized for a category); a constructor keeps its arguments; an open
  call keeps its arguments and adds what its functions may return. A
  project function shadows a sanitizer of the same name;
* a sink holding request data another function returned is a finding at the
  sink; returned values and sinks read their own scope chain, a bare
  assignment belonging to the scope that declares its name;
* the fixpoint and what each file reads are bounded; past the budget, calls
  whose arguments hold no nested call are still checked, with a note.

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


INPUT = """
    function getCmd(req) {
      return req.query.cmd;
    }
    const getName = (req) => req.body.name;
    function getSafe(req) { return escapeHtml(req.query.n); }
    module.exports = { getCmd, getName, getSafe };
    """


class ReturnedValues(unittest.TestCase):
    def test_a_source_returned_by_a_helper_reaches_a_sink(self):
        found = analyze({"lib/input.js": INPUT, "app.js": """
            const { getCmd, getName, getSafe } = require('./lib/input');
            app.get('/x', (req, res) => {
              exec(getCmd(req));
              const c = getCmd(req);
              execSync(c);
              el.innerHTML = getName(req);
              el.innerHTML = getSafe(req);
              exec(getSafe(req));
              db.query('SELECT * FROM t WHERE id = ?', [getName(req)]);
              db.query('SELECT * FROM t WHERE id = ' + getName(req));
              exec(Number(getCmd(req)));
              exec(shellQuote(getCmd(req)));
            });
            """})
        self.assertEqual([(i["rule"], i["line"]) for i in found],
                         [("X-CMD", 3), ("X-CMD", 5), ("X-XSS", 6), ("X-CMD", 8), ("X-SQL", 10)])
        first = found[0]
        self.assertEqual(first["msg"], "Possible command injection: untrusted data from lib/input.js:2 "
                                       "(in getCmd()) reaches a sink at app.js:3 (cross-file).")
        self.assertIn("the value returned by getCmd()", first["why"])
        self.assertEqual((first["file"], first["snippet"][first["line"] - first["snipStart"]]),
                         ("app.js", "  exec(getCmd(req));"))

    def test_parameters_returned_carry_taint_and_a_clean_return_clears_it(self):
        helpers = """
            function runIt(cmd) { exec(cmd); }
            function wrap(x) { return "ls " + x; }
            function yes(x) { log(x); return true; }
            function clean(x) { return Number(x); }
            function escape(x) { return escapeHtml(x); }
            function show(h) { el.innerHTML = h; }
            module.exports = { runIt, wrap, yes, clean, escape, show };
            """
        found = flows({"h.js": helpers, "app.js": """
            const { runIt, wrap, yes, clean, escape, show } = require('./h');
            app.get('/x', (req, res) => {
              const q = req.query.q;
              runIt(wrap(q));
              runIt(yes(q));
              runIt(clean(q));
              const w = wrap(q); runIt(w);
              const v = yes(q); runIt(v);
              show(escape(q));
              runIt(escape(q));
            });
            """})
        self.assertEqual(found, [("X-CMD", "app.js", 4), ("X-CMD", "app.js", 7), ("X-CMD", "app.js", 10)])

    def test_a_chain_of_returns_and_nested_functions(self):
        found = analyze({
            "a.js": ("function inner(req) { return req.query.c; }\n"
                     "function outer(req) { const v = inner(req); return v.trim(); }\n"
                     "function cb(cmd) {\n  run(function () { return cmd; });\n  return 'ok';\n}\n"
                     "module.exports = { outer, cb };\n"),
            "app.js": "const { outer, cb } = require('./a');\nexec(outer(req));\nexec(cb(req.query.q));\n"})
        self.assertEqual([(i["rule"], i["line"]) for i in found], [("X-CMD", 2)])
        self.assertIn("from a.js:1 (in inner())", found[0]["msg"])
        self.assertIn("the value returned by outer()", found[0]["why"])

    def test_request_data_read_in_the_sinks_own_function_is_left_to_the_intra_file_engine(self):
        self.assertEqual(flows({"a.js": "function wrap(x) { return x; }\n"
                                        "app.get('/', (req) => { exec(wrap(req.query.q)); });\n"}), [])


class Binding(unittest.TestCase):
    def test_import_resolution(self):
        found = flows({
            "safe.js": "function runIt(cmd) { log(cmd); }\nmodule.exports = { runIt };\n",
            "danger.js": "function runIt(cmd) { exec(cmd); }\nmodule.exports = { runIt };\n",
            "a.js": "const { runIt } = require('./safe');\napp.get('/', (req) => { runIt(req.query.q); });\n",
            "b.js": "app.get('/', (req) => { runIt(req.query.q); });\n",
            "c.js": "const { runIt } = require('some-pkg');\napp.get('/', (req) => { runIt(req.query.q); });\n",
            "d.js": ("const d = require('./danger');\n"
                     "app.get('/', (req) => { d.runIt(req.query.q); });\n"
                     "app.get('/', (req) => { obj.runIt(req.query.q); this.runIt(req.query.q); });\n"),
            "e.js": "const { runIt } = require('fs');\napp.get('/', (req) => { runIt(req.query.q); });\n",
        })
        # a.js names safe.js's runIt; a package (c.js), an unknown receiver
        # and `this` may be project code: every runIt; a Node built-in (e.js) is not
        self.assertEqual(found, [("X-CMD", "b.js", 1), ("X-CMD", "c.js", 2), ("X-CMD", "d.js", 2),
                                 ("X-CMD", "d.js", 3)])

    def test_esm_default_namespace_barrels_and_typescript_sources(self):
        found = analyze({
            "src/input.ts": ("export function getCmd(req: any): string {\n  return req.query.cmd;\n}\n"
                             "export default function getDef(req) { return req.body.x; }\n"),
            "src/index.ts": "export * from './input.js';\nexport { getDef as other } from './input.js';\n",
            "src/app.ts": ("import { getCmd } from './input.js';\nimport * as inp from './input';\n"
                           "import g from './input';\nimport { getCmd as gc2, other } from './index';\n"
                           "import type { Nothing } from './input';\n"
                           "exec(getCmd(req));\nexec(inp.getCmd(req));\nexec(g(req));\nexec(gc2(req));\n"
                           "exec(other(req));\n"),
        })
        self.assertEqual([(i["line"], i["msg"].split("from ")[1].split(" reaches")[0]) for i in found],
                         [(6, "src/input.ts:2 (in getCmd())"), (7, "src/input.ts:2 (in getCmd())"),
                          (8, "src/input.ts:4 (in getDef())"), (9, "src/input.ts:2 (in getCmd())"),
                          (10, "src/input.ts:4 (in getDef())")])

    def test_commonjs_default_exports(self):
        found = flows({
            "a.js": "module.exports = function getCmd(req) { return req.query.c; };\n",
            "b.js": "function helper(req) { return req.query.c; }\nmodule.exports = helper;\n",
            "c.js": "exports.getIt = function getIt(req) { return req.query.c; };\n",
            "d.js": "module.exports = require('./b');\n",
            "app.js": ("const x = require('./a');\nconst y = require('./b');\nconst { getIt } = require('./c');\n"
                       "const z = require('./d');\nexec(x(req));\nexec(y(req));\nexec(getIt(req));\nexec(z(req));\n"),
        })
        self.assertEqual(found, [("X-CMD", "app.js", 5), ("X-CMD", "app.js", 6), ("X-CMD", "app.js", 7),
                                 ("X-CMD", "app.js", 8)])

    def test_a_function_header_is_not_a_call(self):
        self.assertEqual(flows({"h.js": "const cmd = req.query.c;\nfunction runIt(cmd) { exec(cmd); }\n"}), [])

    def test_an_arrow_function_spans_its_expression(self):
        # `id` used to span runIt's body (the next '{'): id(q) was a command injection
        self.assertEqual(flows({"h.js": "const id = (cmd) => cmd;\nfunction runIt(cmd) { exec(cmd); }\n",
                                "app.js": "app.get('/', (req) => { id(req.query.q); runIt(req.query.q); });\n"}),
                         [("X-CMD", "app.js", 1)])
        self.assertEqual(flows({"h.js": "const run = (c) => exec(c);\n",
                                "app.js": "app.get('/', (req) => { run(req.query.q); });\n"}),
                         [("X-CMD", "app.js", 1)])

    def test_typescript_and_rest_parameters(self):
        found = flows({"h.ts": ("function runIt(cmd: string, opts?: object) { exec(cmd); }\n"
                                "function all(...parts) { exec(parts.join(' ')); }\n"),
                       "app.ts": "app.get('/', (req) => {\n  runIt(req.query.q);\n  all(req.query.q);\n});\n"})
        self.assertEqual(found, [("X-CMD", "app.ts", 2), ("X-CMD", "app.ts", 3)])

    def test_nested_call_arguments_are_read(self):
        found = flows({"h.js": "function runIt(cmd) {\n  exec(cmd);\n}\n",
                       "app.js": ("app.get('/', (req) => {\n  runIt(format(req.query.q));\n"
                                  "  runIt(Number(req.query.q));\n  runIt(function () { log(req.query.q); });\n"
                                  "  runIt([req.query.a, 1].join(','));\n});\n")})
        self.assertEqual(found, [("X-CMD", "app.js", 2), ("X-CMD", "app.js", 5)])


class RecallFirst(unittest.TestCase):
    """Where the binding can't be resolved, the call still reaches every
    project function of that name (what the name-based pass always did)."""
    LIB = "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\nmodule.exports = { runIt };\n"

    def route(self, call, head=""):
        return head + "app.get('/x', (req, res) => {\n  " + call + ";\n});\n"

    def test_unresolved_imports_and_receivers(self):
        cases = {
            "inline require": {"lib/run.js": self.LIB, "app.js": self.route("require('./lib/run').runIt(req.query.q)")},
            "module copied": {"lib/run.js": self.LIB, "app.js": self.route(
                "o.runIt(req.query.q)", "const lib = require('./lib/run');\nconst o = lib;\n")},
            "path alias": {"src/lib/run.js": self.LIB, "src/app.js": self.route(
                "runIt(req.query.q)", "import { runIt } from '@/lib/run';\n")},
            "workspace package": {"packages/util/index.js": self.LIB, "packages/web/app.js": self.route(
                "runIt(req.query.q)", "const { runIt } = require('@acme/util');\n")},
            "five re-export hops": dict({"lib/run.js": self.LIB, "b1.js": "export * from './lib/run';\n",
                                         "app.js": self.route("runIt(req.query.q)", "import { runIt } from './b5';\n")},
                                        **{f"b{i}.js": f"export * from './b{i - 1}';\n" for i in range(2, 6)}),
            "default export called inline": {"run.js": "module.exports = function runIt(cmd) { exec(cmd); };\n",
                                             "app.js": self.route("require('./run')(req.query.q)")},
            "const copy of an import": {"lib.js": self.LIB, "app.js": self.route(
                "const go = runIt; go(req.query.q)", "const { runIt } = require('./lib');\n")},
            "this.method": {"h.js": ("module.exports = {\n  runIt(cmd) { exec(cmd); },\n"
                                     "  handle(req) { this.runIt(req.query.q); },\n};\n"
                                     "function runIt(cmd) { exec(cmd); }\n")},
            "a namesake in another scope": {"h.js": self.LIB, "app.js": (
                "const { runIt: go } = require('./h');\nfunction unrelated() {\n  function go(x) { log(x); }\n}\n"
                + self.route("go(req.query.q)"))},
            "module rebound": {"a.js": "function runIt(cmd) { return 'ok'; }\nmodule.exports = { runIt };\n",
                               "b.js": self.LIB, "app.js": self.route(
                                   "m.runIt(req.query.q)", "let m = require('./a');\nm = require('./b');\n")},
            "function rebound": {"lib.js": self.LIB, "app.js": self.route(
                "tidy(req.query.q)", "const { runIt } = require('./lib');\nfunction tidy(x) { return 'x'; }\ntidy = runIt;\n")},
            "function values": {"lib.js": "function runIt(cmd) {\n  exec(cmd());\n}\nmodule.exports = { runIt };\n",
                                "app.js": self.route("runIt(x => req.query.q)", "const { runIt } = require('./lib');\n")},
        }
        for label, files in cases.items():
            with self.subTest(case=label):
                self.assertEqual({r for r, _, _ in flows(files)}, {"X-CMD"})

    def test_positive_evidence_binds_nothing(self):
        cases = {
            "JSON.parse": {"lib.js": "function parse(cmd) { exec(cmd); }\nmodule.exports = { parse };\n",
                           "app.js": self.route("JSON.parse(req.query.q)")},
            "a Node built-in": {"lib.js": "function readFile(p) { exec('cat ' + p); }\nmodule.exports = { readFile };\n",
                                "app.js": self.route("readFile(req.query.q)", "const { readFile } = require('node:fs');\n")},
            "a visible local function": {"lib.js": self.LIB, "app.js": self.route(
                "function runIt(x) { log(x); }\n  runIt(req.query.q)")},
            "a parameter": {"lib.js": self.LIB, "app.js": (
                "function apply(runIt, q) {\n  runIt(q);\n}\n" + self.route("apply(log, req.query.q)"))},
            "a built-in method": {"lib.js": "function replace(s) { exec(s); }\nmodule.exports = { replace };\n",
                                  "app.js": self.route("const s = req.query.q; s.replace(/a/g, 'b')")},
        }
        for label, files in cases.items():
            with self.subTest(case=label):
                self.assertEqual(flows(files), [])


class Evaluation(unittest.TestCase):
    """A helper's value keeps its arguments unless no return of it can hold them."""
    H = "function runIt(cmd) {\n  exec('ls ' + cmd);\n}\n"

    def route(self, call, head):
        return head + "app.get('/x', (req, res) => {\n  " + call + ";\n});\n"

    def test_arguments_flow_through_locals(self):
        cases = {
            "copied to a local": "function tidy(x) {\n  const y = x.trim();\n  return y;\n}\n",
            "built with +=": "function tidy(x) {\n  let s = 'ls ';\n  s += x;\n  return s;\n}\n",
            "pushed into an array": "function tidy(x) {\n  const a = [];\n  a.push(x);\n  return a.join(' ');\n}\n",
            "a constructor": "function tidy(x) {\n  this.v = x;\n}\n",
        }
        for label, helper in cases.items():
            call = "const v = new tidy(req.query.q); runIt(v)" if label == "a constructor" else \
                "const v = tidy(req.query.q); runIt(v)"
            with self.subTest(case=label):
                self.assertEqual(flows({"h.js": self.H + helper + "module.exports = { runIt, tidy };\n",
                                        "app.js": self.route(call, "const { runIt, tidy } = require('./h');\n")}),
                                 [("X-CMD", "app.js", 3)])

    def test_returns_that_hold_no_argument(self):
        self.assertEqual(flows({"h.js": self.H + "function ok(s) {\n  if (s.length > 3) return true;\n  return false;\n}\n"
                                                 "module.exports = { runIt, ok };\n",
                                "app.js": self.route("const v = ok(req.query.q); runIt(v)",
                                                     "const { runIt, ok } = require('./h');\n")}), [])

    def test_returned_values_through_closures_compound_assignments_and_asi(self):
        found = analyze({
            "get.js": ("function viaClosure(req) {\n  let c;\n  [1].forEach(i => { c = req.query.cmd; });\n  return c;\n}\n"
                       "function viaPlus(req) {\n  let s = 'ls ';\n  s += req.query.cmd;\n  return s;\n}\n"
                       "module.exports = { viaClosure, viaPlus };\n"),
            "app.js": "const { viaClosure, viaPlus } = require('./get')\nexec(viaClosure(req))\nexec(viaPlus(req))\n",
        })
        self.assertEqual([(i["rule"], i["line"]) for i in found], [("X-CMD", 2), ("X-CMD", 3)])
        self.assertEqual(flows({"lib.js": self.H + "module.exports = { runIt };\n",
                                "app.js": ("const { runIt } = require('./lib')\napp.get('/x', (req, res) => {\n"
                                           "  let c\n  c = req.query.q\n  runIt(c)\n})\n")}),
                         [("X-CMD", "app.js", 5)])

    def test_a_project_function_shadows_a_sanitizer_name(self):
        found = flows({
            "lib.js": ("function escapeHtml(s) { return s; }\nfunction show(h) { el.innerHTML = h; }\n"
                       "function getName(req) { return escapeHtml(req.query.n); }\n"
                       "module.exports = { escapeHtml, show, getName };\n"),
            "app.js": ("const { escapeHtml, show, getName } = require('./lib');\n"
                       "app.get('/', (req) => {\n  show(escapeHtml(req.query.q));\n});\n"
                       "app.get('/', (req) => {\n  el.innerHTML = getName(req);\n});\n"),
        })
        self.assertEqual(found, [("X-XSS", "app.js", 3), ("X-XSS", "app.js", 6)])


class Scoping(unittest.TestCase):
    def test_a_name_tainted_in_one_function_does_not_taint_its_namesake(self):
        # react-dom's `JSCompiler_inline_result = "string" === typeof x.location.href`
        # tainted every variable of that name in the 13,000-line file
        src = ("function probe() { var result = typeof win.location.href; return 1; }\n"
               "function make() { var result = compute(); return result; }\n"
               "function use() { el.innerHTML = make(); }\n")
        self.assertEqual(flows({"a.js": src}), [])
        # ... while a function's variables stay visible in the functions inside it
        src = ("function getQ() { return req.query.q; }\n"
               "app.get('/', function (req, res) {\n  const c = getQ();\n"
               "  db.run(sql, function (err) { exec(c); });\n});\n")
        self.assertEqual(flows({"a.js": src}), [("X-CMD", "a.js", 4)])


class BracketTable(unittest.TestCase):
    def test_the_table_reads_the_same_spans_as_the_character_scan(self):
        """_js_arg_end_at / _js_sink_span / _js_split_at jump over bracket
        groups with the file's bracket table; they must return exactly what
        the character-by-character _js_arg_end / _js_sink_args /
        _js_split_args return (window included)."""
        import random
        rnd = random.Random(20260927)
        tokens = ["(", ")", "[", "]", "{", "}", ",", ";", "\n", " ", "a", "exec(", "x.innerHTML = ",
                  "\U0001F600", "\u00e9", "fetch (", "  "]
        for _ in range(1500):
            code = "".join(rnd.choice(tokens) for _ in range(rnd.randint(0, 120)))
            if rnd.random() < 0.05:
                code *= 60                               # past the 4,000-character window
            pairs = flow._js_bracket_pairs(code)
            for sink_re, _ in flow._JS_SINKS:
                for m in list(sink_re.finditer(code))[:5]:
                    a, b = flow._js_sink_span(code, m.start(), m.end(), pairs)
                    self.assertEqual(code[a:b], flow._js_sink_args(code, m.start(), m.end()), repr(code))
                    self.assertEqual(flow._js_split_at(code, a, b, pairs), flow._js_split_args(code[a:b]))
            for _ in range(4):
                k = rnd.randint(0, len(code))
                for statement in (True, False):
                    self.assertEqual(flow._js_arg_end_at(code, k, statement, pairs),
                                     flow._js_arg_end(code, k, statement), repr(code[k:k + 60]))


class Bounds(unittest.TestCase):
    def test_long_chains_of_returns(self):
        # functions are read callees first: a long chain settles in a round
        src = "".join(f"function c{i}(a) {{ return c{i + 1}(a); }}\n" for i in range(40))
        src += "function c40(a) { return req.query.q; }\nexec(c0(1));\n"
        self.assertEqual(flows({"a.js": src}), [("X-CMD", "a.js", 42)])
        # a chain through module variables takes a round a link: the cap notes itself
        src = "".join(f"function c{i}() {{ return v{i + 1}; }}\nvar v{i + 1} = c{i + 1}();\n" for i in range(40))
        src += "function c40() { return req.query.q; }\nexec(c0());\n"
        (note,) = analyze({"a.js": src})
        self.assertEqual((note["rule"], note["name"]), ("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (iteration cap)"))
        self.assertEqual(note["sev"], "INFO")

    def test_past_the_budget_every_plain_call_is_still_checked(self):
        nest = "function pad(a){return g(function(){" * 2500 + "}})" * 2500 + "\n"
        found = analyze({"lib.js": "function runIt(cmd) {\n  exec(cmd);\n}\nmodule.exports = { runIt };\n",
                         "app.js": nest + "const { runIt } = require('./lib');\n"
                                          "app.get('/', (req) => {\n  runIt(req.query.q);\n});\n"})
        self.assertEqual([(i["rule"], i["line"]) for i in found],
                         [("Q-FLOW-INCOMPLETE", 1), ("X-CMD", 4)])
        self.assertIn("calls whose arguments hold no nested call were still checked", found[0]["msg"])

    def test_nested_code_is_linear_and_bounded(self):
        cases = {
            "returns": "function f(a){return g(function(){" * 30000,
            "sinks": "function g(req){return req.query.q}\n" + "exec(" * 200000 + "g(req)" + ")" * 200000 + "\n",
            "html": "function g(req){return req.query.q}\n" + "el.innerHTML = (" * 100000 + "g(req)" + ")" * 100000 + ";\n",
            "calls": "function runIt(c){exec(c)}\n" + "runIt(" * 200000 + "req.query.q" + ")" * 200000 + "\n",
        }
        for label, src in cases.items():
            with self.subTest(case=label):
                t = time.perf_counter()
                found = analyze({"a.js": src})
                self.assertLess(time.perf_counter() - t, 20)
                if label != "calls":
                    notes = [i for i in found if i["rule"] == "Q-FLOW-INCOMPLETE"]
                    self.assertEqual([i["name"] for i in notes], ["Flow analysis incomplete (size budget)"])


if __name__ == "__main__":
    unittest.main()
