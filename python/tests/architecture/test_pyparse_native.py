"""The native engine's Python parser (the `py_parse` call:
rust/crates/lazaret-engine/src/pyparse/) against Python 3.13's `ast.parse`,
node for node: the same tree — every node, field and value, `lineno`,
`col_offset`, `end_lineno`, `end_col_offset` — written as JSON text the same
way and compared as text, or an error where Python raises one (SyntaxError,
IndentationError, TabError, the ValueError of a NUL, MemoryError and
RecursionError for nesting), on the line Python reports:

* curated snippets of every construct (pyparse_cases.py), of the errors, and
  of the errors whose line is the point (which one Python reports, and
  where);
* seeded programs generated from the grammar;
* the repository's own Python;
* with `"spans": true`, each node's code-point `start` and `end` after its
  positions and nothing else changed, and `lineno` the line of `start`.

The oracle is a python3.13 subprocess (pyparse_oracle.py); the parity on
token soups, mutations of real files and every construct that nests is in
test_pyparse_native_b.py, the whole of the Python installed on the
development machine in docs/RUST_ENGINE.md. Inert text only: nothing is
executed. Skipped where Python 3.13 or the native library is missing.
"""
import bisect
import json
import re
import unittest

from lazaret.scanner import _native
from tests.architecture import pyparse_cases as cases
from tests.architecture import pyparse_oracle as oracle

SPAN_RE = re.compile(r',"start":\d+,"end":\d+')
POS_RE = re.compile(r'"lineno":(\d+),"col_offset":\d+,"end_lineno":\d+,"end_col_offset":\d+,"start":(\d+),"end":(\d+)')
LINE_END_RE = re.compile(r"\r\n|\r|\n")


@unittest.skipUnless(oracle.PYTHON313, oracle.SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativePythonParseTests(unittest.TestCase):
    maxDiff = None

    def compare(self, sources, lines=True):
        """The same answers, and for errors the same line."""
        want = oracle.oracle(sources)
        self.assertEqual(oracle.differences(sources, answers=want), [])
        if lines:
            other = [(json.dumps(s)[:120], w, g) for s, w, g in
                     ((s, w, oracle.native(s)) for s, w in zip(sources, want) if oracle.is_error(w))
                     if oracle.error_line(w) != oracle.error_line(g)]
            self.assertEqual(other[:5], [])
        return want

    def test_statements_and_expressions(self):
        sources = cases.STATEMENTS + cases.EXPRESSIONS + cases.MATCH
        want = self.compare(sources)
        # (a few are errors on purpose: `match x`, a walrus alone …)
        self.assertGreater(sum(not oracle.is_error(w) for w in want), len(sources) * 0.95)

    def test_errors(self):
        want = self.compare(cases.ERRORS + cases.ERROR_LINES)
        # (they are errors, Python's and the engine's)
        self.assertEqual([s for s, w in zip(cases.ERRORS, want) if not oracle.is_error(w)], [])

    def test_generated_programs(self):
        programs = cases.programs(20261001, 400)
        want = self.compare(programs)
        self.assertGreater(sum(not oracle.is_error(w) for w in want), 350)

    def test_own_sources(self):
        sources = cases.own_sources()
        self.assertGreater(len(sources), 300)
        want = self.compare(sources)
        self.assertEqual([s[:80] for s, w in zip(sources, want) if oracle.is_error(w)], [])

    def test_spans(self):
        sources = cases.STATEMENTS + cases.EXPRESSIONS + cases.MATCH + cases.own_sources()[:120]
        checked = 0
        for src in sources:
            plain = oracle.native(src)
            with_spans = oracle.native(src, spans=True)
            self.assertEqual(SPAN_RE.sub("", with_spans), plain, src[:80])
            ends = [m.end() for m in LINE_END_RE.finditer(src)]
            for m in POS_RE.finditer(with_spans):
                line, start, end = (int(g) for g in m.groups())
                self.assertTrue(0 <= start <= end <= len(src), (src[:80], m.group()))
                self.assertEqual(line, bisect.bisect_right(ends, start) + 1, (src[:80], m.group()))
                checked += 1
        self.assertGreater(checked, 50_000)

    def test_the_answer_for_a_small_module(self):
        self.assertEqual(oracle.native("x = 1\n"), oracle.oracle(["x = 1\n"])[0])
        self.assertEqual(oracle.native("x = (\n"),
                         '{"error":{"line":1,"reason":"\'(\' was never closed"}}')
        # a NUL: Python's ValueError-like error has no line
        self.assertEqual(oracle.error_line(oracle.native("x = 1\0")), 0)


if __name__ == "__main__":
    unittest.main()
