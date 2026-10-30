"""Final review: snippet clipping in O(window) and a time backstop that holds
inside one rule's per-match loop.

* The npm engine and the dashboard clipped each snippet line with
  Array.from(<whole line>) once per finding: 2.5k / 5k / 10k / 20k repeats of
  `try{}catch(e){}` on ONE line took 1.1 / 3.5 / 12.6 / > 44 s (the page:
  10k in 10.2 s). Clipping is O(window) now, with output identical to
  core.clip_snippet_line (code points, surrogate pairs never split). Since
  BR-7's step 3 c (0.1.9) the engine clips for both packages, all of a file's
  findings in one call.
* The 30 s per-file backstop was checked between rules only, so a text rule
  with thousands of matches ran to the end (a 2 s budget: 13.5 s and all 10k
  findings). The deadline is checked inside per-match loops; the backstop
  tests use a fake clock (every clock read is 1 ms later), so they do not
  depend on the machine's speed. Since the Rust-first refactor the native
  engine reads the rules under its work budget (steps of its regex matcher,
  engine.WORK_BUDGET), not a clock: a file that spends it is SC-TRUNCATED.
  Since Q-1 (0.1.9) the passes after the rules in project mode (taint, SQL,
  function metrics) are the engine's too, and since BR-7's step 3 a config
  file's scan, so the packages read no clock while scanning a file, and
  since step 5 the dashboard runs the engine too.

Timing bounds are loose (slow CI runners): far above today's cost, far below
the old one. All content is inert.
"""
import sysconfig
import time
import unittest
from unittest import mock

from lazaret.scanner import core, engine

REPEATS = (2_500, 5_000, 10_000, 20_000)
# (a Python built on musl is slower at this: test_clip_is_windowed took 12.7 s on the Wheels' musllinux x86_64 job
# and 7.9 s on aarch64, Oct 29; the whole-line clip took over 44 s on glibc)
LIMIT_S = 30.0 if "musl" in (sysconfig.get_config_var("HOST_GNU_TYPE") or "") else 4.0
E = "…"


def reported(issues, rule):
    """Findings of `rule`, counting the ones Q-CAPPED says were omitted."""
    n = sum(i["rule"] == rule for i in issues)
    for i in issues:
        if i["rule"] == "Q-CAPPED" and i["msg"].endswith(f" more {rule} findings omitted"):
            n += int(i["msg"].split()[0])
    return n


class PythonPackageTests(unittest.TestCase):
    def test_one_line_repeats_scan_in_linear_time(self):
        for n in REPEATS:
            with self.subTest(repeats=n):
                started = time.monotonic()
                issues = core.scan_file("t.js", "try{}catch(e){}" * n, "js")
                self.assertLess(time.monotonic() - started, LIMIT_S)
                self.assertEqual(sum(i["rule"] == "B-EMPTY-CATCH" for i in issues), 1)
                self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})

    def test_clip_is_windowed(self):
        # (since BR-7's step 3 c the engine makes the snippets of the findings the packages build: a file's in one
        # call, mk_issues)
        line = "try{}catch(e){}" * 20_000
        rule = {"id": "B-EMPTY-CATCH", "name": "n", "type": "BUG", "sev": "MAJOR", "msg": "m", "why": "w", "fix": "f",
                "ref": "r"}
        started = time.monotonic()
        issues = core.mk_issues("t.js", ["// header", line, "// footer"], [(rule, 2, k * 15 + 5) for k in range(20_000)])
        self.assertLess(time.monotonic() - started, LIMIT_S)
        out = issues[-1]["snippet"][1]
        self.assertEqual(len(out), 240)
        self.assertTrue(out.startswith(E) and out.endswith("catch(e){}"))
        self.assertEqual(issues[0]["snippet"], ["// header", line[:239] + E, "// footer"])

    def test_a_project_scan_is_bounded_by_the_work_budget(self):
        # (Q-1: the same file gets the same findings on every machine, however slow it is)
        n = 20_000
        issues = core.scan_file("t.js", "try{}catch(e){}\n" * n, "js")
        self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})
        self.assertEqual(reported(issues, "B-EMPTY-CATCH"), n)
        with mock.patch.object(engine, "WORK_BUDGET", 10_000):
            (t,) = core.scan_file("t.js", "try{}catch(e){}\n" * n, "js")
        self.assertEqual((t["rule"], t["sev"]), ("SC-TRUNCATED", "CRITICAL"))
        self.assertIn(engine.EXHAUSTED, t["msg"])

    def test_the_work_budget_stops_the_dependency_decode_flow_on_one_line(self):
        text = "var d = atob(p); " * 5000 + "\n"
        self.assertEqual(core.scan_file("dep.js", text, "js", dep=True), [])
        with mock.patch.object(engine, "WORK_BUDGET", 10_000):
            issues = core.scan_file("dep.js", text, "js", dep=True)
            self.assertEqual(core.scan_file("dep.js", "var d = 1;\n", "js", dep=True), [])
        (t,) = issues
        self.assertEqual((t["rule"], t["sev"]), ("SC-TRUNCATED", "CRITICAL"))
        self.assertIn(engine.EXHAUSTED, t["msg"])


if __name__ == "__main__":
    unittest.main()
