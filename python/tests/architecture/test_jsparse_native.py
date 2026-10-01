"""Parity for the native engine's JavaScript parser (the `js_parse` call:
rust/crates/lazaret-engine/src/jsparse/) against lazaret.scanner.jsparse,
node for node: the same tree — every node, field, value and line, key for
key in jsparse.py's order — or the same JsSyntaxError (line and reason), on
the inputs test_js_parity_parse.py holds the retired JavaScript twin to:

* its curated snippets, the repository's own JavaScript and seeded
  generated projects (jsgen.py), seeded token soups and mutations of real
  files;
* its linearity cases (a minified single line, TypeScript's `f<f<f<…`),
  which the engine reads in well under a second.

And the call's options: `js_parse_file` picks jsparse.dialect's dialect
from the path; with `"spans": true` each node's `start` and `end` (code
points) follow its `line` and nothing else changes, and `line` is the line
of `start`.

jsparse_cases.py's own inputs (the speculation budgets at their edges,
jsparse.py's bugs, every construct that nests at the depth limit …) are in
test_jsparse_native_b.py. The whole of the 20 npm packages installed on the
development machine (24,428 files) was compared the same way: see
docs/RUST_ENGINE.md. Inert text only. Skipped where the native library is
not built.
"""
import bisect
import time
import unittest

from lazaret.scanner import _native, jsparse
from tests.architecture import jsgen
from tests.architecture import jsparse_cases as cases
from tests.architecture import test_js_parity_parse as twin


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeParseTests(unittest.TestCase):
    maxDiff = None

    def same(self, items):
        self.assertEqual(cases.differences(items), [])

    def test_snippets(self):
        items = twin.items_of(twin.SNIPPETS)
        self.same(items)
        answers = [cases.native_json(src, *jsparse.dialect(path)) for path, src in items]
        self.assertGreater(sum(a.startswith('{"error"') for a in answers), 10)    # the error cases are errors
        self.assertGreater(sum(a.startswith('{"type":"Program"') for a in answers), 35)

    def test_own_sources_and_generated_projects(self):
        self.same(twin.own_sources() + [(f["path"], f["content"]) for files in jsgen.projects(20260928, 60)
                                        for f in files])

    def test_soups_and_mutations(self):
        self.same(twin.soups(20260928, 1500) + twin.mutations(twin.own_sources(), 20260928, 300))

    def test_linear_on_what_was_not(self):
        line = ("s.js", "var a=function(b,c){return b+c},d=[1,2,3].map(function(e){return e*2});" * 15000)
        gen = ("s.ts", "f<" * 40000)
        for path, src in (line, gen):
            ts, jsx = jsparse.dialect(path)
            t = time.perf_counter()
            got = cases.native_json(src, ts, jsx)
            self.assertLess(time.perf_counter() - t, 2.0)
            self.assertEqual(got, cases.oracle_json(src, ts, jsx))

    def test_the_file_name_picks_the_dialect(self):
        src = "let x: T = <T>y; <a b={c} />; enum E { A }"
        for path in ("a.js", "a.mjs", "a.cjs", "a.jsx", "a.ts", "a.mts", "a.cts", "a.tsx", "A.TS", "b.Tsx", "c.d.ts",
                     "d.ts.js", "dir.ts/e", "noext"):
            with self.subTest(path=path):
                status, got = cases.native_raw("js_parse_file", {"path": path}, src)
                self.assertEqual(status, 0)
                self.assertEqual(got, cases.oracle_json(src, *jsparse.dialect(path)))

    def test_spans(self):
        items = twin.items_of(twin.SNIPPETS) + twin.own_sources()
        checked = 0
        for path, src in items:
            ts, jsx = jsparse.dialect(path)
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


if __name__ == "__main__":
    unittest.main()
