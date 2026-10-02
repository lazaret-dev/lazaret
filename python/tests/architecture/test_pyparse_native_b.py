"""The native engine's Python parser against Python 3.13's `ast.parse` (see
test_pyparse_native.py), on:

* seeded token soups (with a stray NUL, lone surrogate, form feed …) and
  seeded mutations of the repository's own Python (characters deleted,
  doubled, swapped, inserted): the same answers, and for errors the same
  line, but for a few soups (where Python's error pass settles for the
  longest part of an expression that reads: at most 1 in 200);
* every construct that nests, at the deepest Python reads and one deeper:
  the engine reads exactly as deep (pyparse_cases.NESTINGS), or for a few
  combinations, less deep than Python (STRICTER: its estimate of Python's
  parser stack errs on the strict side, never the lenient), and in each of
  many contexts no longer a chain of `not`s than Python (INNERMOST);
* long inputs, which it reads in linear time.

Inert text only: nothing is executed. Skipped where Python 3.13 or the
native library is missing.
"""
import json
import time
import unittest

from lazaret.scanner import _native
from tests.architecture import pyparse_cases as cases
from tests.architecture import pyparse_oracle as oracle


@unittest.skipUnless(oracle.PYTHON313, oracle.SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativePythonParseCasesTests(unittest.TestCase):
    maxDiff = None

    def compare(self, sources, other_lines=0.0):
        want = oracle.oracle(sources)
        self.assertEqual(oracle.differences(sources, answers=want), [])
        errors = [(s, w) for s, w in zip(sources, want) if oracle.is_error(w)]
        other = [(json.dumps(s)[:120], w[:160], g[:160]) for s, w, g in
                 ((s, w, oracle.native(s)) for s, w in errors) if oracle.error_line(w) != oracle.error_line(g)]
        self.assertLessEqual(len(other), len(errors) * other_lines, other[:5])
        return want

    def test_soups(self):
        want = self.compare(cases.soups(20261001, 12000), other_lines=0.005)
        self.assertGreater(sum(oracle.is_error(w) for w in want), 8000)

    def test_mutations(self):
        want = self.compare(cases.mutations(cases.own_sources(), 20261001, 3000))
        self.assertGreater(sum(oracle.is_error(w) for w in want), 1500)

    def test_every_nesting_at_its_deepest(self):
        sources = []
        for name, make, deepest in cases.NESTINGS:
            sources += [make(deepest), make(deepest + 1)]
        want = oracle.oracle(sources)
        for i, (name, make, deepest) in enumerate(cases.NESTINGS):
            with self.subTest(construct=name):
                at, past = want[2 * i], want[2 * i + 1]
                self.assertFalse(oracle.is_error(at), at[:200])
                self.assertTrue(oracle.is_error(past), past[:200])
                self.assertEqual(oracle.native(make(deepest)), at)
                self.assertTrue(oracle.is_error(oracle.native(make(deepest + 1))))

    def test_where_the_engine_is_stricter(self):
        sources = []
        for name, make, engine, python in cases.STRICTER:
            sources += [make(engine), make(python), make(python + 1)]
        want = oracle.oracle(sources)
        for i, (name, make, engine, python) in enumerate(cases.STRICTER):
            with self.subTest(construct=name):
                at, deepest, past = want[3 * i:3 * i + 3]
                self.assertEqual(oracle.native(make(engine)), at)
                self.assertTrue(oracle.is_error(oracle.native(make(engine + 1))))
                self.assertFalse(oracle.is_error(deepest))
                self.assertTrue(oracle.is_error(past))

    def test_never_deeper_than_python_in_any_context(self):
        # as many `not`s as Python reads in each context: the engine reads no
        # more (its estimate of Python's parser stack errs on the strict
        # side, never the lenient), and not many fewer
        deepest = oracle.deepest(cases.INNERMOST)
        for (before, after), k in zip(cases.INNERMOST, deepest):
            with self.subTest(context=before + "…" + after):
                self.assertGreater(k, 5000)
                self.assertTrue(oracle.is_error(oracle.native(before + "not " * (k + 1) + "x" + after)))
                self.assertFalse(oracle.is_error(oracle.native(before + "not " * (k - 20) + "x" + after)))

    def test_deep_trees_are_refused_as_python_refuses_them(self):
        # ast converts a tree 9,997 nodes deep at most (a RecursionError), its
        # parser keeps 6000 rule calls (a MemoryError), no line for either; its
        # tokenizer 200 brackets (a SyntaxError on the line)
        for src in ("a" + " + a" * 20000, "a" + ".b" * 50000, "-" * 7000 + "x", "x = " + "[" * 300 + "]" * 300):
            with self.subTest(src=src[:20]):
                want = oracle.oracle([src])[0]
                self.assertTrue(oracle.is_error(want))
                got = oracle.native(src)
                self.assertTrue(oracle.is_error(got))
                self.assertEqual(oracle.error_line(got), oracle.error_line(want))

    def test_long_inputs_in_linear_time(self):
        for src in ("x = 1\n" * 100_000, "x = [" + "1, " * 200_000 + "]\n", "f(" + "a, " * 200_000 + ")\n",
                    "'a' " * 100_000 + "\n", "f'" + "{a}b" * 50_000 + "'\n",
                    "if x:\n" + "    y = 1\n" * 100_000, "a = " + " + ".join(["b"] * 9000) + "\n",
                    "x = (" + "lambda: " * 2000 + "1)\n"):
            with self.subTest(src=src[:20]):
                t = time.perf_counter()
                got = oracle.native(src)
                self.assertLess(time.perf_counter() - t, 2.0)
                self.assertTrue(got.startswith('{"_type":"Module"'), got[:200])


if __name__ == "__main__":
    unittest.main()
