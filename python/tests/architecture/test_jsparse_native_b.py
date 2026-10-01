"""Parity for the native engine's JavaScript parser against
lazaret.scanner.jsparse (see test_jsparse_native.py), on jsparse_cases.py's
inputs:

* snippets for what test_js_parity_parse.py's do not reach: the speculation
  budgets at their edges (a generic arrow function's read ahead of 4096
  tokens, function_type_ahead's 256, the file's allowance spent), the
  places jsparse.py fails outside its JsSyntaxError (a parenthesized list
  that starts with a rest element: KeyError, which the engine answers with
  line 0; a long chain of Flow's `?T`, a long JSX member name: Python's
  recursion limit, "nesting too deep" at line 1), surrogates lone and
  paired, numbers, strings' escapes, regular expressions, templates, ASI,
  comments, JSX, TypeScript and Flow;
* every construct that nests, at depths around the limit (MAX_DEPTH: the
  deepest each reads, and one deeper);
* seeded soups of TypeScript, JSX and Flow pieces, and seeded mutations of
  the repository's own JavaScript.

Inert text only. Skipped where the native library is not built.
"""
import unittest

from lazaret.scanner import _native, jsparse
from tests.architecture import jsparse_cases as cases
from tests.architecture import test_js_parity_parse as twin

DEPTHS = [1, 2, 83, 84, 85, 124, 125, 126, 127, 128, 129, 250, 251, 252, 253, 254, 255, 256, 257]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeParseCasesTests(unittest.TestCase):
    maxDiff = None

    def test_snippets(self):
        self.assertEqual(cases.differences(cases.SNIPPETS), [])
        # (they reach what they are there for)
        answers = {src: cases.native_json(src, *jsparse.dialect(path)) for path, src in cases.SNIPPETS}
        self.assertEqual(answers["x = (...a, b);"], '{"error":{"line":0,"reason":"KeyError: \'line\'"}}')
        self.assertEqual(answers["let x: " + "? " * 30000 + "T;"], '{"error":{"line":1,"reason":"nesting too deep"}}')
        self.assertIn('"ArrowFunctionExpression"', answers["x = <T,>(" + "a," * 2044 + ") => 0;"])
        self.assertNotIn('"ArrowFunctionExpression"', answers["x = <T,>(" + "a," * 2050 + ") => 0;"])

    def test_every_nesting_at_the_depth_limit(self):
        items = [(path, src) for _, path, src in cases.nesting_cases(DEPTHS)]
        self.assertEqual(cases.differences(items), [])
        for name, path, make in cases.NESTINGS:
            with self.subTest(construct=name):
                ts, jsx = jsparse.dialect(path)
                self.assertTrue(cases.native_json(make(84), ts, jsx).startswith('{"type":"Program"'))
                self.assertTrue(cases.native_json(make(257), ts, jsx).startswith('{"error"'))

    def test_soups(self):
        self.assertEqual(cases.differences(cases.soup(20261001, 6000)), [])

    def test_mutations(self):
        self.assertEqual(cases.differences(cases.mutate(twin.own_sources(), 20261001, 800)), [])


if __name__ == "__main__":
    unittest.main()
