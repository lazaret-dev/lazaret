"""The engine's JavaScript parser (the `js_parse` and `js_parse_file`
calls: rust/crates/lazaret-engine/src/jsparse/): its options and its
bounds. test_snapshot_js_parse.py holds its trees to the recorded ones and
tests/scanner/test_jsparse.py pins node shapes; here:

* `js_parse_file` picks the dialect from the path (jsparse_cases.dialect:
  .ts, .mts and .cts are TypeScript, .tsx TypeScript with JSX, anything
  else JavaScript with JSX) and answers what `js_parse` does in it;
* with `"spans": true` each node's `start` and `end` (code points) follow
  its `line` and nothing else changes, and `line` is the line of `start`;
* every construct that nests is read 84 deep and is an error 257 deep (the
  depth limit, MAX_DEPTH 256, counts nested statements, expressions and
  types, some constructs two or three levels a step);
* the answers kept from jsparse.py, which the parser was ported from: a
  parenthesized list that starts with a rest element (jsparse.py's
  KeyError: line 0), a chain of Flow's `?T` past Python's recursion limit
  ("nesting too deep", line 1), a generic arrow function's read ahead at
  the edge of its budget (4096 tokens);
* linear time on the inputs that were not: a minified single line,
  TypeScript's `f<f<f<…`.

Inert text only. Skipped where the native library is not built.
"""
import bisect
import time
import unittest

from lazaret.scanner import _native
from tests.architecture import jsparse_cases as cases


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeParseTests(unittest.TestCase):
    maxDiff = None

    def test_the_file_name_picks_the_dialect(self):
        src = "let x: T = <T>y; <a b={c} />; enum E { A }"
        for path in ("a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.mts", "a.cts", "a.tsx", "A.TS", "b.Tsx", "c.d.ts",
                     "d.ts.js", "dir.ts/e", "noext"):
            with self.subTest(path=path):
                status, got = cases.native_raw("js_parse_file", {"path": path}, src)
                self.assertEqual(status, 0)
                self.assertEqual(got, cases.native_json(src, *cases.dialect(path)))

        def reads(path, text):
            return cases.native_raw("js_parse_file", {"path": path}, text)[1].startswith('{"type":"Program"')
        # JSX, and TypeScript's enums: JavaScript has the one, TypeScript the other, a .tsx file both
        self.assertEqual([(reads(p, "<a></a>;"), reads(p, "enum E { A }")) for p in ("a.js", "a.ts", "a.tsx")],
                         [(True, False), (False, True), (True, True)])

    def test_spans(self):
        items = cases.items_of(cases.READER_SNIPPETS) + cases.own_sources()
        checked = 0
        for path, src in items:
            ts, jsx = cases.dialect(path)
            plain = cases.native_json(src, ts, jsx)
            with_spans = cases.native_json(src, ts, jsx, spans=True)
            self.assertEqual(cases.SPAN_RE.sub("", with_spans), plain, path)
            ends = [m.start() for m in cases.LINE_END_RE.finditer(src)]
            for m in cases.LINE_SPAN_RE.finditer(with_spans):
                line, start, end = (int(g) for g in m.groups())
                self.assertTrue(0 <= start <= end <= len(src), (path, m.group()))
                self.assertEqual(line, bisect.bisect_left(ends, start) + 1, (path, m.group()))
                checked += 1
        self.assertGreater(checked, 50_000)

    def test_every_nesting_at_the_depth_limit(self):
        for name, path, make in cases.NESTINGS:
            with self.subTest(construct=name):
                ts, jsx = cases.dialect(path)
                self.assertTrue(cases.native_json(make(84), ts, jsx).startswith('{"type":"Program"'))
                self.assertTrue(cases.native_json(make(257), ts, jsx).startswith('{"error":{"line":1,'))

    def test_the_answers_kept_from_jsparse_py(self):
        answers = {src: cases.native_json(src, *cases.dialect(path)) for path, src in cases.SNIPPETS}
        self.assertEqual(answers["x = (...a, b);"], '{"error":{"line":0,"reason":"KeyError: \'line\'"}}')
        self.assertEqual(answers["let x: " + "? " * 30000 + "T;"], '{"error":{"line":1,"reason":"nesting too deep"}}')
        self.assertIn('"ArrowFunctionExpression"', answers["x = <T,>(" + "a," * 2044 + ") => 0;"])
        self.assertNotIn('"ArrowFunctionExpression"', answers["x = <T,>(" + "a," * 2050 + ") => 0;"])

    def test_linear_on_what_was_not(self):
        line = ("s.js", "var a=function(b,c){return b+c},d=[1,2,3].map(function(e){return e*2});" * 15000)
        gen = ("s.ts", "f<" * 40000)
        for path, src in (line, gen):
            ts, jsx = cases.dialect(path)
            t = time.perf_counter()
            got = cases.native_json(src, ts, jsx)
            self.assertLess(time.perf_counter() - t, 2.0)
            self.assertTrue(got.startswith(('{"type":"Program"', '{"error":')), got[:80])


if __name__ == "__main__":
    unittest.main()
