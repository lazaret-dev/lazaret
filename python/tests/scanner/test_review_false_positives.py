"""False positives found by `lazaret-registry discover --scan` on real npm and
PyPI releases, and the detections that must survive the fixes.

1. The dependency-mode decode flow took any `.exec(` / `.eval(` for a sink.
   Every bundler's regex loop, `for (re.lastIndex = 0; (m = re.exec(t));)`,
   became "decoded payload reaches a code-execution sink" when a variable of
   the same name had been decoded anywhere in the file (npm:research-agent-ui,
   extract-youtube, react-reason-editor: SUSPICIOUS).
2. SC-MARSHAL flagged `exec(compile(src, path, "exec"))`, the standard way to
   run a .py file (pypi:sandweave: SUSPICIOUS from five of them), and was the
   only rule that caught `exec(compile(b64decode(…)))`.
3. SC-CHARCODE counted numbers anywhere on the line, so every fromCharCode on
   a long minified line fired: binary parsers, UTF-16 surrogate encoders; and
   any array of printable codes on the line counted for every call on it
   (extract-youtube's 98 KB line).
4. The decode flow tracks names without scopes: npm:pullfrog's 7.8 MB bundle
   decodes a WebAssembly module (`mod = …compile(Buffer.from(…, "base64"))`)
   at line 7310, esbuild's `__importStar(mod)` helper carried the mark to
   6,216 names, and every spawn in the file became a BLOCKER, along with a
   `function exec(…) {` definition. A decode now taints names for
   DEP_FLOW_WINDOW characters, and definitions are not calls.

The npm engine and the dashboard run the same inputs through
tests/architecture/test_js_parity.py and test_review_dashboard_parity.py.
Fixtures are inert strings; nothing is executed.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

B64 = '"Y29uc29sZS5sb2coMSk="'


def rules_by_line(src, lang, dep=True, rule=None):
    return sorted((i["line"], i["rule"]) for i in core.scan_file("x." + lang, src, lang, dep=dep)
                  if rule is None or i["rule"] == rule)


def flow_lines(src, lang="js"):
    return [ln for ln, _ in rules_by_line(src, lang, True, "SC-EVAL-DECODE")]


class MethodCallSinkTests(unittest.TestCase):
    PREFIX = "var t = atob(%s);\n" % B64            # line 1: a decoded name `t`

    def test_regexp_and_other_methods_are_not_code_execution(self):
        for line in ("for (ya.lastIndex = 0; (r = ya.exec(t)) !== null;) { g(r) }",
                     "for (; null !== (e = Be.exec(t));) {}",
                     "let q = /[^=]*/.exec(t)[0];",
                     "var D = E.exec(t);",
                     "db.exec(t);",
                     "model.eval(t);",
                     "foo().exec(t);"):
            with self.subTest(line=line):
                self.assertEqual(flow_lines(self.PREFIX + line + "\n"), [])

    def test_real_sinks_still_count(self):
        for line in ("eval(t);", "window.eval(t);", "globalThis.eval(t);", "new Function(t);",
                     'require("child_process").exec(t);', "child_process.exec(t);",
                     "exec(t);",                              # destructured from child_process
                     "anything.execSync(t);", "worker.spawn(t);", "vm.runInThisContext(t);"):
            with self.subTest(line=line):
                self.assertEqual(flow_lines(self.PREFIX + line + "\n"), [2])

    def test_names_bound_to_child_process(self):
        for bind in ('const cp = require("child_process");', "var cp=require('node:child_process');",
                     'import cp from "child_process";', 'import * as cp from "node:child_process";',
                     'const cp = await import("child_process");'):
            with self.subTest(bind=bind):
                self.assertEqual(flow_lines(self.PREFIX + bind + "\ncp.exec(t);\n"), [3])

    def test_a_decode_written_in_the_sink_call(self):
        src = 'const cp = require("child_process");\ncp.exec(wrap(atob(%s)));\n' % B64
        found = [i for i in core.scan_file("x.js", src, "js", dep=True) if i["rule"] == "SC-EVAL-DECODE"]
        self.assertEqual([i["line"] for i in found], [2])
        self.assertEqual(found[0]["msg"], "Decoded payload reaches a code-execution sink in the same call.")
        # an unrelated method call with a decode in it is not a sink
        self.assertEqual(flow_lines("x = re.exec(wrap(atob(%s)));\n" % B64), [])

    def test_python_methods_named_exec(self):
        prefix = "d = base64.b64decode(p)\n"
        self.assertEqual(flow_lines(prefix + "session.exec(d)\n", "py"), [])
        self.assertEqual(flow_lines(prefix + "cursor.exec(d)\n", "py"), [])
        self.assertEqual(flow_lines(prefix + "exec(d)\n", "py"), [2])
        self.assertEqual(flow_lines(prefix + "builtins.exec(d)\n", "py"), [2])
        self.assertEqual(flow_lines(prefix + "exec(compile(d, 'x', 'exec'))\n", "py"), [2])

    def test_minified_one_line_bundle(self):
        # the shape of react-reason-editor's dist/*.js: one line, regex loops
        line = ('var n=atob(%s);function Be(e,t){return function(n){let r,s=0,i="";'
                'for(;r=e.exec(n);)s!==r.index&&(i+=n.substring(s,r.index));return i}}'
                'let t=/[^=]*/.exec(n)[0];\n') % B64
        self.assertEqual(flow_lines(line), [])


class FlowReachTests(unittest.TestCase):
    """A decode reaches sinks within DEP_FLOW_WINDOW characters; definitions
    named exec are not calls."""
    DECODE = "var t = atob(%s);\n" % B64

    @staticmethod
    def pad(n):
        return "var pad = [%s];\n" % ("0," * (n // 2))

    def test_a_sink_far_from_the_decode_is_not_reached(self):
        far = core.DEP_FLOW_WINDOW + 500
        self.assertEqual(flow_lines(self.DECODE + self.pad(far) + "eval(t);\n"), [])
        self.assertEqual(flow_lines(self.DECODE + self.pad(2_000) + "eval(t);\n"), [3])

    def test_propagation_keeps_the_distance_from_the_decode(self):
        half = core.DEP_FLOW_WINDOW * 2 // 3
        src = self.DECODE + self.pad(half) + "var u = t;\n" + self.pad(half) + "eval(u);\n"
        self.assertEqual(flow_lines(src), [])
        self.assertEqual(flow_lines(self.DECODE + "var u = t;\n" + self.pad(half) + "eval(u);\n"), [4])

    def test_bundle_helpers_far_from_a_wasm_decode(self):
        # the shape of npm:pullfrog's dist/index.js
        src = ('var mod = await WebAssembly.compile(Buffer.from("AGFzbQEAAAA=", "base64"));\n'
               + self.pad(core.DEP_FLOW_WINDOW + 500)
               + "function __importStar(mod) { var result = {}; result.default = mod; return result; }\n"
               + 'var cp = __importStar(require("child_process"));\n'
               + "var r = __importStar(mod); spawn(r.default); cp.spawn(r);\n")
        self.assertEqual(flow_lines(src), [])

    def test_definitions_named_exec_are_not_calls(self):
        for line in ("function exec(t, e) { return run(t, e); }", "function* exec(t) { yield t; }",
                     "var o = { exec(t) { return t; } };", "class A { exec(t, e) { return 1; } }",
                     "class B { async eval(t) {} }"):
            with self.subTest(line=line):
                self.assertEqual(flow_lines(self.DECODE + line + "\n"), [])
        self.assertEqual(flow_lines("d = base64.b64decode(p)\ndef exec(d):\n    return d\n", "py"), [])
        # a call is still a call, also next to a definition
        self.assertEqual(flow_lines(self.DECODE + "function run(x) { return x; } exec(t);\n"), [2])
        self.assertEqual(flow_lines(self.DECODE + "if (ok) exec(t); { g(); }\n"), [2])


class CompileAndMarshalTests(unittest.TestCase):
    def rules(self, src, dep=True):
        return {r for _, r in rules_by_line(src + "\n", "py", dep)}

    def test_running_a_source_file_is_not_bytecode(self):
        src = 'exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)'
        self.assertEqual(self.rules(src), set())                   # supply-chain profile
        self.assertEqual(self.rules(src, dep=False), {"S-EVAL-PY"})  # --full still says exec

    def test_decode_then_compile_is_decode_then_execute(self):
        for src in ('exec(compile(base64.b64decode(x), "<s>", "exec"))',
                    'exec(compile(zlib.decompress(b), "f", "exec"))',
                    'exec(compile(__import__("base64").b64decode(x), "s", "exec"))'):
            with self.subTest(src=src):
                self.assertIn("SC-EVAL-DECODE", self.rules(src))

    def test_bytecode_is_still_sc_marshal(self):
        for src in ("exec(marshal.loads(blob))", "code = marshal.loads(blob)",
                    "code = marshal.load(fh)", 'exec(__import__("marshal").loads(b))',
                    "f = types.FunctionType(marshal.loads(b), globals())",
                    'c = types.CodeType(0, 0, 0, 0, 0, 0, b"", (), (), (), "", "", 0, b"")',
                    'm = imp.load_compiled("x", "x.pyc")',
                    'loader = SourcelessFileLoader("x", "x.pyc")'):
            with self.subTest(src=src):
                self.assertIn("SC-MARSHAL", self.rules(src))


class CharCodeTests(unittest.TestCase):
    def col(self, line):
        """The finding's excerpt of the line, or None when not flagged."""
        found = [i for i in core.scan_file("x.js", line + "\n", "js", dep=True) if i["rule"] == "SC-CHARCODE"]
        return found[0]["snippet"][0] if found else None

    NUMBERS = "x=12,y=34,z=56,w=78,v=90,u=11,q=22,r=33,s=44,t=55,o=66;"

    def test_parsers_and_encoders_on_long_lines_are_not_obfuscation(self):
        for line in ("for(let a=0;a<i.length;a++)s+=String.fromCharCode(i[a]);",
                     "n+=String.fromCharCode(255&e),e>>>=8;",
                     "t+=String.fromCharCode(e>>>10&1023|55296),e=56320|1023&e;",
                     "a.languageCode=String.fromCharCode(96+(c&31));",
                     "return String.fromCharCode(...n.subarray(0,r));",
                     "catch(r){r=String.fromCharCode.apply(null,n)}",
                     "z=String.fromCharCode(a,b);t=[300,400,500,600,700,800,900,100,200,250,260];"):
            with self.subTest(line=line):
                self.assertIsNone(self.col(line + self.NUMBERS))

    def test_codes_written_in_the_code_are_still_flagged(self):
        codes = "104,116,116,112,115,58,47,47,101,120,97"
        for line in (f"var s=String.fromCharCode({codes});",
                     f"x=String.fromCharCode.apply(null,[{codes}]);",
                     f"y=String.fromCharCode(...[{codes}]);",
                     f"var k=[{codes}];eval(String.fromCharCode(...k));",
                     f"var k=[{codes}];x=String.fromCharCode.apply(null,k);"):
            with self.subTest(line=line):
                self.assertIsNotNone(self.col(line))

    def test_a_code_table_counts_only_for_calls_that_use_it(self):
        codes = "104,116,116,112,115,58,47,47,101,120,97"
        # extract-youtube: a table of printable codes elsewhere on a long line
        for line in (f"var T=[{codes}];s+=String.fromCharCode(e>>>10&1023|55296);",
                     f"var k=[{codes}];x=String.fromCharCode(o.k);",
                     f"o.k=[{codes}];x=String.fromCharCode(...k);",
                     f"var k=[{codes}];x=String.fromCharCode(kk);"):
            with self.subTest(line=line):
                self.assertIsNone(self.col(line + self.NUMBERS))
        for line in (f"var k=[{codes}];y=1;x=String.fromCharCode(...k.map(c=>c^1));",
                     f"const k = [ {codes} ], s = String.fromCharCode.call(null, ...k);",
                     f"s=String.fromCharCode.apply(null,k);var k=[{codes}];"):
            with self.subTest(line=line):
                self.assertIn("fromCharCode", self.col(line) or "")

    def test_the_excerpt_shows_the_offending_call(self):
        # a long minified line: the excerpt is centred on the call that counts
        line = ("a=String.fromCharCode(e);" + "f(x);" * 600
                + "b=String.fromCharCode(104,116,116,112,115,58,47,47,101,120,97);")
        excerpt = self.col(line)
        self.assertIn("fromCharCode(104", excerpt)
        self.assertNotIn("fromCharCode(e)", excerpt)

    def test_linear_on_many_calls(self):
        import time
        line = "String.fromCharCode(" * 50_000 + "1" * 10 + ",12" * 20_000
        t = time.monotonic()
        core.scan_file("x.js", line + "\n", "js", dep=True)
        self.assertLess(time.monotonic() - t, 8.0)


if __name__ == "__main__":
    unittest.main()
