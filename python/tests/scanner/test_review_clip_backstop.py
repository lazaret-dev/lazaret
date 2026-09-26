"""Final review: snippet clipping in O(window) and a time backstop that holds
inside one rule's per-match loop — Python engine and dashboard.

* The npm engine and the dashboard clipped each snippet line with
  Array.from(<whole line>) once per finding: 2.5k / 5k / 10k / 20k repeats of
  `try{}catch(e){}` on ONE line took 1.1 / 3.5 / 12.6 / > 44 s (the page:
  10k in 10.2 s). Clipping is O(window) now, with output identical to
  core.clip_snippet_line (code points, surrogate pairs never split) — checked
  here against the page on astral characters and lone surrogates.
* The 30 s per-file backstop was checked between rules only, so a text rule
  with thousands of matches ran to the end (a 2 s budget: 13.5 s and all 10k
  findings). The deadline is checked inside per-match loops in every engine;
  the backstop tests use a fake clock (every clock read is 1 ms later), so
  they do not depend on the machine's speed.

Timing bounds are loose (slow CI runners): far above today's cost, far below
the old one. All content is inert.
"""
import itertools
import json
import time
import unittest
from unittest import mock

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

REPEATS = (2_500, 5_000, 10_000, 20_000)
LIMIT_S = 4.0
E = "…"


class ticking_clock:
    """Patch core's monotonic clock: each read is 1 ms after the previous one;
    the per-file budget is `ticks` reads."""

    def __init__(self, ticks):
        self.ticks = ticks

    def __enter__(self):
        counter = itertools.count()
        self.patches = [mock.patch.object(core.time, "monotonic", lambda: next(counter) / 1000),
                        mock.patch.object(core, "SCAN_TIME_BUDGET", self.ticks / 1000)]
        for p in self.patches:
            p.start()

    def __exit__(self, *exc):
        for p in reversed(self.patches):
            p.stop()


def reported(issues, rule):
    """Findings of `rule`, counting the ones Q-CAPPED says were omitted."""
    n = sum(i["rule"] == rule for i in issues)
    for i in issues:
        if i["rule"] == "Q-CAPPED" and i["msg"].endswith(f" more {rule} findings omitted"):
            n += int(i["msg"].split()[0])
    return n


class PythonEngineTests(unittest.TestCase):
    def test_one_line_repeats_scan_in_linear_time(self):
        for n in REPEATS:
            with self.subTest(repeats=n):
                started = time.monotonic()
                issues = core.scan_file("t.js", "try{}catch(e){}" * n, "js")
                self.assertLess(time.monotonic() - started, LIMIT_S)
                self.assertEqual(sum(i["rule"] == "B-EMPTY-CATCH" for i in issues), 1)
                self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})

    def test_clip_is_windowed(self):
        line = "try{}catch(e){}" * 20_000
        started = time.monotonic()
        for k in range(20_000):
            out = core.clip_snippet_line(line, k * 15 + 5)
        self.assertLess(time.monotonic() - started, LIMIT_S)
        self.assertEqual(len(out), 240)
        self.assertTrue(out.startswith(E) and out.endswith("catch(e){}"))

    def test_backstop_stops_a_text_rules_match_loop(self):
        n = 20_000
        # one clock read per line, then one per 256 matches of B-EMPTY-CATCH:
        # the budget runs out ~40 reads into the text rule
        with ticking_clock(n + 40):
            issues = core.scan_file("t.js", "try{}catch(e){}\n" * n, "js")
        self.assertEqual(sum(i["rule"] == "SC-TRUNCATED" for i in issues), 1)
        self.assertTrue(0 < reported(issues, "B-EMPTY-CATCH") < n)

    def test_backstop_stops_the_dependency_decode_flow_on_one_line(self):
        with ticking_clock(5):
            issues = core.scan_file("dep.js", "var d = atob(p); " * 5000 + "\n", "js", dep=True)
        self.assertEqual(sum(i["rule"] == "SC-TRUNCATED" for i in issues), 1)


def page_timed(n):
    return (f"(() => {{ const content = 'try{{}}catch(e){{}}'.repeat({n}); const t0 = Date.now();"
            f" const issues = scanFile({{name: 't.js', lang: 'js', content}});"
            f" return {{ms: Date.now() - t0, catches: issues.filter((i) => i.rule === 'B-EMPTY-CATCH').length,"
            f" truncated: issues.some((i) => i.rule === 'SC-TRUNCATED')}}; }})()")


PAGE_MKISSUE = """(() => {
  const line = "try{}catch(e){}".repeat(20000), lines = ["// a", line, "// b"];
  registerScanContext(lines, SECRET_SKIP_RE);
  const t0 = Date.now();
  let last = null;
  for (let k = 0; k < 20000; k++)
    last = mkIssue({id: "B-EMPTY-CATCH", name: "n", type: "BUG", sev: "MAJOR", msg: "m", why: "w", fix: "f", ref: "r"},
                   "t.js", 2, lines, k * 15 + 5);
  return {ms: Date.now() - t0, snippet: last.snippet[1]};
})()"""


def page_ticking(ticks, n):
    return (f"(() => {{ const realNow = Date.now; let t = 0; Date.now = () => t++; setScanTimeBudget({ticks});"
            f" try {{ return scanFile({{name: 't.js', lang: 'js', content: 'try{{}}catch(e){{}}\\n'.repeat({n})}}); }}"
            f" finally {{ Date.now = realNow; setScanTimeBudget(); }} }})()")


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_one_line_repeats_scan_in_linear_time(self):
        results = dash.run([{"op": "eval", "expr": page_timed(n)} for n in REPEATS])
        for n, r in zip(REPEATS, results):
            with self.subTest(repeats=n):
                self.assertLess(r["ms"], LIMIT_S * 1000, f"{n} repeats: {r['ms']} ms (10k was 10.2 s)")
                self.assertEqual(r["catches"], 1)
                self.assertFalse(r["truncated"])

    def test_mkissue_is_windowed(self):
        (r,) = dash.run([{"op": "eval", "expr": PAGE_MKISSUE}])
        self.assertLess(r["ms"], LIMIT_S * 1000)
        self.assertEqual(r["snippet"], core.clip_snippet_line("try{}catch(e){}" * 20_000, 19_999 * 15 + 5))

    def test_clip_matches_core_on_astral_and_lone_surrogates(self):
        # a lone LOW surrogate is what a surrogate-escaped byte leaves in a Python str; a
        # high + low pair of separate code points cannot come from decoded source text
        pieces = ["a", "é", "\U0001F600", "\udc80", "\U0010FFFF", " "]
        cases, state = [], 11
        for t in range(300):
            state = (state * 1103515245 + 12345) & 0x7FFFFFFF
            length, kinds = 180 + state % 500, 1 + (state >> 8) % len(pieces)
            s = "".join(pieces[(state >> (k % 20)) % kinds] for k in range(length))
            for col in (None, 0, state % (len(s) + 1), len(s), len(s) + 3):
                cases.append((s, col))
        (page,) = dash.run([{"op": "eval", "expr": f"{json.dumps(cases)}.map(([s, c]) => clipLine(s, c))"}])
        self.assertEqual(page, [core.clip_snippet_line(s, col) for s, col in cases])

    def test_backstop_stops_a_text_rules_match_loop(self):
        n = 20_000
        (issues,) = dash.run([{"op": "eval", "expr": page_ticking(n + 40, n)}])
        self.assertEqual(sum(i["rule"] == "SC-TRUNCATED" for i in issues), 1)
        self.assertTrue(0 < reported(issues, "B-EMPTY-CATCH") < n)


if __name__ == "__main__":
    unittest.main()
