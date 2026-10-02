"""linre's time grows linearly with the text; pyre's — the native engine's
re, which backtracks as sre does — does not, on texts that make it backtrack.

Patterns of the rule pack, each on a text of one piece repeated:
- `_SVC_LAUNCHCTL_RE` on "launchctl" and " --a" k times, then " x": in
  `(?:[ \\t]+-{1,2}[\\w-]+)*[ \\t]+(?:load|…)`, "--a" splits two ways
  (`-{1,2}` takes one dash or two, `[\\w-]+` the rest), and the near miss
  at the end makes a backtracking matcher try every split: 2^k paths;
- `_DD_PARAM_RE` on spaces: `\\s*(?:async\\s+)?(?:function…)?\\(?\\s*(…)`
  has two `\\s*` in a row, tried from every start: the cube of the length;
- `_JSON_COLON_RE`, `_LD_CALLED_RE`, `_DL_JOIN_CHAIN_RE` on spaces: a
  leading `\\s*` (or `[ \\t]*`) runs to the end from every start: the square.

Each is timed through the same call (pyre.probe and linre.probe: search,
match, fullmatch, finditer, sub and split), the best of a few runs. pyre's
time grows fourfold or more when the text doubles (exponential: when two
pieces are added); linre's about twofold, its time on a text four times
longer at most eight times its time, and on a million characters well
under a second. Skipped where the native library is not built.
"""
import time
import unittest

from lazaret.scanner import _native
from tests.architecture.test_rust_parity_regex import pack_patterns

LAUNCHCTL = ("_SVC_LAUNCHCTL_RE", lambda k: "launchctl" + " --a" * k + " x")
SPACES = [(name, lambda n: " " * n) for name in ("_DD_PARAM_RE", "_JSON_COLON_RE", "_LD_CALLED_RE", "_DL_JOIN_CHAIN_RE")]


def seconds(engine, src, flags, text, runs=3):
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        got = _native.call(engine + ".probe", {"pattern": src, "flags": flags, "texts": [text]})
        best = min(best, time.perf_counter() - start)
    assert "error" not in got, got
    return best


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LinreLinearTimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pack = {name: (src, flags) for name, src, flags in pack_patterns()}

    def grows(self, engine, name, make, sizes):
        src, flags = self.pack[name]
        return [seconds(engine, src, flags, make(n)) for n in sizes]

    def test_pyre_backtracks_exponentially_linre_does_not(self):
        name, make = LAUNCHCTL
        p = self.grows("pyre", name, make, [10, 12, 14])
        self.assertGreater(p[2] / p[0], 8, f"pyre {p}")             # 2^k: fourfold for each two pieces
        lin = self.grows("linre", name, make, [10_000, 40_000])
        self.assertLess(lin[1] / lin[0], 8, f"linre {lin}")        # 4x the text: about 4x the time
        self.assertLess(self.grows("linre", name, make, [14])[0], p[2])

    def test_pyre_backtracks_polynomially_linre_does_not(self):
        for name, make in SPACES:
            with self.subTest(pattern=name):
                small = 100 if name == "_DD_PARAM_RE" else 1000    # (the cube: pyre takes 0.2 s on 400)
                p = self.grows("pyre", name, make, [small, 4 * small])
                self.assertGreater(p[1] / p[0], 10, f"pyre {p}")    # the square: 16x, the cube: 64x
                lin = self.grows("linre", name, make, [50_000, 200_000])
                self.assertLess(lin[1] / lin[0], 8, f"linre {lin}")
                self.assertLess(self.grows("linre", name, make, [4 * small])[0] * 5, p[1])

    def test_a_million_characters(self):
        # what pyre would take hours on (by the growth above), linre reads at once
        for name, make in [(LAUNCHCTL[0], lambda n: LAUNCHCTL[1](n // 4))] + SPACES:
            with self.subTest(pattern=name):
                src, flags = self.pack[name]
                self.assertLess(seconds("linre", src, flags, make(1_000_000), runs=1), 2.0)


if __name__ == "__main__":
    unittest.main()
