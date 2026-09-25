#!/usr/bin/env python3
"""Unit tests — silent taint-config rule rejection (card "taint config
silently discards invalid rules", audit id NEW-4 / 55c8e10b).

Run:  python3 lazaret/test_taint_config_validation.py [unittest-args]

Acceptance criteria covered:
  1. Every skipped/invalid rule produces a warning naming the file, the rule
     and the reason (unknown category vs empty pattern), listing the valid
     categories.
  2. Unknown categories are reported, not silently ignored.
  3. An explicitly-passed --taint-config containing rejected rules exits
     non-zero (4) so CI cannot silently lose coverage; --strict-taint-config
     extends this to the auto-loaded config; without strictness the scan
     still completes (exit 0) with the warning on stderr.
  4. Regression: a warning is emitted for an unknown-category sink, and the
     equivalent VALID category still fires (control against vacuous passes).

Both engines are covered: lazaret.apply_taint_config (intra-file, T-*)
and lazaret_flow.configure (interprocedural, X-*).
"""
from __future__ import annotations

import json
import os

from tests import _support  # noqa: E402
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # the lazaret/ dir itself

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
CLI = _support.CLI
PY = sys.executable or "python3"

from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.scanner import flow as lazaret_flow  # noqa: E402

APPEAL_JS = "var data = getUserInput();\ndangerous_sink(data);\n"

VALID_CATS = sorted(lazaret._CAT_META)
VALID_CATS_TXT = ", ".join(VALID_CATS)


class _EngineState:
    """Snapshot/restore the global taint tables that apply_taint_config /
    configure mutate, so tests cannot poison each other."""

    def __init__(self):
        import copy
        self.saved = (
            dict(lazaret.TAINT_SOURCES),
            [list(s) for s in lazaret.TAINT_SINKS.values()],
            dict(lazaret._FULL_SAN),
            copy.deepcopy(lazaret._PARTIAL_SAN),
            list(lazaret_flow._PY_SOURCE_EXTRA),
            list(lazaret_flow._EXTRA_PY_SINKS),
            set(lazaret_flow.FULL_SANITIZERS_PY),
            dict(lazaret_flow._EXTRA_PARTIAL_PY),
            lazaret_flow._JS_SOURCE_RE,
            list(lazaret_flow._JS_SINKS),
            lazaret_flow._JS_FULL_SAN_RE,
            dict(lazaret_flow._JS_PARTIAL_SAN),
        )

    def restore(self):
        import copy
        (srcs, sinks, full, part, pse, eps, fsp, epp, jsrc, jsinks,
         jfull, jpart) = self.saved
        lazaret.TAINT_SOURCES.clear()
        lazaret.TAINT_SOURCES.update(srcs)
        for lang, rows in zip(("py", "js"), sinks):
            lazaret.TAINT_SINKS[lang][:] = rows
        lazaret._FULL_SAN.clear()
        lazaret._FULL_SAN.update(full)
        lazaret._PARTIAL_SAN.clear()
        lazaret._PARTIAL_SAN.update(part)
        lazaret_flow._PY_SOURCE_EXTRA[:] = pse
        lazaret_flow._EXTRA_PY_SINKS[:] = eps
        lazaret_flow.FULL_SANITIZERS_PY.clear()
        lazaret_flow.FULL_SANITIZERS_PY.update(fsp)
        lazaret_flow._EXTRA_PARTIAL_PY.clear()
        lazaret_flow._EXTRA_PARTIAL_PY.update(epp)
        lazaret_flow._JS_SOURCE_RE = jsrc
        lazaret_flow._JS_SINKS[:] = jsinks
        lazaret_flow._JS_FULL_SAN_RE = jfull
        lazaret_flow._JS_PARTIAL_SAN.clear()
        lazaret_flow._JS_PARTIAL_SAN.update(jpart)


# ---------------------------------------------------------------------------
# 1+2+4. Module level — apply_taint_config warns for every rejected rule
# ---------------------------------------------------------------------------
class TestIntraFileWarnings(unittest.TestCase):
    def setUp(self):
        self.state = _EngineState()
        self.state.restore()          # start from a clean baseline snapshot
        self._snap = _EngineState()

    def tearDown(self):
        self._snap.restore()

    def apply(self, cfg):
        lazaret.apply_taint_config(cfg)
        return lazaret.get_taint_config_warnings()

    def test_unknown_category_sink_warns_regression(self):
        """THE regression: category 'sql' must not be silently dropped."""
        warns = self.apply({"python": {"sinks": [
            {"pattern": "(", "category": "sql"}]}})
        self.assertEqual(len(warns), 1, f"expected exactly 1 warning, got {warns}")
        w = warns[0]
        self.assertIn("unknown category 'sql'", w)
        self.assertIn("python sink #1", w)                 # names the rule
        self.assertIn("pattern '('", w)                    # names the pattern
        for cat in VALID_CATS:                             # lists all valid cats
            self.assertIn(cat, w)

    def test_every_valid_category_is_accepted_silently(self):
        warns = self.apply({lang: {"sinks": [
            {"pattern": r"a\.sink", "category": cat}]}
            for lang in ("python", "javascript")
            for cat in VALID_CATS})
        self.assertEqual(warns, [])

    def test_empty_pattern_warns(self):
        warns = self.apply({"python": {"sinks": [
            {"pattern": "", "category": "SQL injection"}]}})
        self.assertEqual(len(warns), 1)
        self.assertIn("empty 'pattern'", warns[0])
        self.assertIn("SQL injection", warns[0])

    def test_missing_category_warns_and_lists_categories(self):
        warns = self.apply({"python": {"sinks": [{"pattern": "x"}]}})
        self.assertEqual(len(warns), 1)
        self.assertIn("has no 'category'", warns[0])
        self.assertIn(VALID_CATS_TXT, warns[0])

    def test_sink_not_an_object_warns(self):
        warns = self.apply({"python": {"sinks": ["nope"]}})
        self.assertEqual(len(warns), 1)
        self.assertIn("sink #1 is not an object", warns[0])

    def test_sinks_not_a_list_warns(self):
        warns = self.apply({"python": {"sinks": "nope"}})
        self.assertEqual(len(warns), 1)
        self.assertIn("python.sinks is str, not a list", warns[0])

    def test_partial_sanitizer_unknown_category_warns(self):
        warns = self.apply({"python": {"sanitizers": {
            "partial": {"clean": ["sql"]}}}})
        self.assertEqual(len(warns), 1)
        self.assertIn("sanitizer 'clean' lists unknown category 'sql'", warns[0])
        self.assertIn(VALID_CATS_TXT, warns[0])

    def test_non_dict_top_level_and_section_warn(self):
        self.assertEqual(len(self.apply(["x"])), 1)
        self.assertIn("top level is list", self.apply(["x"])[0])
        warns = self.apply({"python": 5})
        self.assertEqual(len(warns), 1)
        self.assertIn("section 'python' is int", warns[0])

    def test_unknown_top_level_section_warns_comment_tolerated(self):
        warns = self.apply({"sanitizers": 9})
        self.assertEqual(len(warns), 1)
        self.assertIn("unknown top-level section 'sanitizers'", warns[0])
        # _-prefixed keys are metadata (the shipped example uses _comment)
        self.assertEqual(self.apply({"_comment": "hi"}), [])

    def test_warning_texts_match_flow_engine_for_cli_dedupe(self):
        """The CLI dedupes the two engines' rejections; their texts match."""
        cfg = {"javascript": {"sinks": [{"pattern": "p", "category": "sql"}]}}
        intra = self.apply(cfg)
        flow = []
        lazaret_flow.configure(cfg, on_warn=flow.append)
        self.assertEqual(intra, flow)

    def test_rejected_rule_not_added_to_sink_table(self):
        before = len(lazaret.TAINT_SINKS["js"])
        self.apply({"javascript": {"sinks": [{"pattern": "p", "category": "sql"}]}})
        self.assertEqual(len(lazaret.TAINT_SINKS["js"]), before)

    def test_warnings_reset_between_calls(self):
        self.apply({"python": {"sinks": [{"pattern": "(", "category": "sql"}]}})
        self.assertTrue(lazaret.get_taint_config_warnings())
        self.apply({})
        self.assertEqual(lazaret.get_taint_config_warnings(), [])


# ---------------------------------------------------------------------------
# 2. Interprocedural engine — configure(on_warn=...) reports rejections
# ---------------------------------------------------------------------------
class TestFlowWarnings(unittest.TestCase):
    def setUp(self):
        self.state = _EngineState()
        self.state.restore()
        self._snap = _EngineState()
        self.warns = []

    def tearDown(self):
        self._snap.restore()

    def configure(self, cfg):
        lazaret_flow.configure(cfg, on_warn=self.warns.append)

    def test_unknown_category_sink_warns(self):
        self.configure({"python": {"sinks": [{"pattern": "(", "category": "sql"}]}})
        self.assertEqual(len(self.warns), 1)
        self.assertIn("unknown category 'sql'", self.warns[0])
        self.assertIn(VALID_CATS_TXT, self.warns[0])

    def test_empty_pattern_and_missing_category_warn(self):
        self.configure({"javascript": {"sinks": [
            {"pattern": "", "category": "SQL injection"},
            {"pattern": "x"},
            {"pattern": "y", "category": "sql"}]}})
        self.assertEqual(len(self.warns), 3)
        self.assertIn("empty 'pattern'", self.warns[0])
        self.assertIn("has no 'category'", self.warns[1])
        self.assertIn("unknown category 'sql'", self.warns[2])

    def test_partial_sanitizer_unknown_category_warns(self):
        self.configure({"javascript": {"sanitizers": {
            "partial": {"esc": ["sql"]}}}})
        self.assertEqual(len(self.warns), 1)
        self.assertIn("sanitizer 'esc' lists unknown category 'sql'", self.warns[0])

    def test_no_callback_is_backward_compatible(self):
        """configure(cfg) with no on_warn must not raise (old call sites)."""
        lazaret_flow.configure({"python": {"sinks": [
            {"pattern": "x", "category": "sql"}]}})
        self.assertEqual(len(lazaret_flow._EXTRA_PY_SINKS), 0)

    def test_malformed_shapes_do_not_crash(self):
        for cfg in ("str", ["list"], {"python": 5}, {"javascript": {"sinks": "x"}},
                    {"python": {"sanitizers": {"partial": 3}}}):
            self.configure(cfg)      # must not raise

    def test_valid_rule_still_added(self):
        self.configure({"python": {"sinks": [
            {"pattern": r"my\.sink", "category": "SQL injection"}]}})
        self.assertEqual(self.warns, [])
        self.assertEqual(lazaret_flow._EXTRA_PY_SINKS[-1][1], "SQL injection")


# ---------------------------------------------------------------------------
# 3+4. CLI end-to-end — warnings on stderr, exit 4 in strict mode, control
# ---------------------------------------------------------------------------
class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-taint-")
        self.js = os.path.join(self.tmp, "app.js")
        with open(self.js, "w") as fh:
            fh.write(APPEAL_JS)
        self.bad = {"javascript": {"sources": ["getUserInput"],
                                    "sinks": [{"pattern": "dangerous_sink",
                                               "category": "sql"}]}}
        self.good = {"javascript": {"sources": ["getUserInput"],
                                     "sinks": [{"pattern": "dangerous_sink",
                                                "category": "SQL injection"}]}}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_cfg(self, cfg, name=".lazaret-taint.json"):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as fh:
            json.dump(cfg, fh)
        return path

    def run_cli(self, *extra):
        # NOT -q: the control test needs per-issue lines (e.g. "T-SQL").
        p = subprocess.run([PY, CLI, self.tmp, "--no-html", "--no-json",
                            *extra], capture_output=True, text=True, timeout=120)
        return p.returncode, p.stdout, p.stderr

    def assert_unknown_category_warning(self, rc, out, err, cfg_name):
        """The warning names the file, the rule, the reason, and the cats."""
        self.assertIn(f"warning: {cfg_name}: javascript sink #1 "
                      f"(pattern 'dangerous_sink') has unknown category 'sql'",
                      err)
        for cat in VALID_CATS:
            self.assertIn(cat, err)

    def test_autoloaded_bad_config_warns_and_scan_completes(self):
        cfg = self.write_cfg(self.bad)
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 0)
        self.assert_unknown_category_warning(rc, out, err, cfg)
        self.assertIn(f"Loaded taint config: {cfg}", out)
        self.assertNotIn("T-SQL", out)          # rule really is inert...

    def test_explicit_taint_config_with_rejected_rule_exits_4(self):
        cfg = self.write_cfg(self.bad, "bad.json")
        rc, out, err = self.run_cli("--taint-config", cfg)
        self.assertEqual(rc, lazaret.EXIT_TAINT_CONFIG)
        self.assertEqual(rc, 4)
        self.assert_unknown_category_warning(rc, out, err, cfg)
        self.assertIn("error: 1 taint-config rule(s) rejected in", err)

    def test_strict_flag_on_autoloaded_config_exits_4(self):
        cfg = self.write_cfg(self.bad)
        rc, out, err = self.run_cli("--strict-taint-config")
        self.assertEqual(rc, 4)
        self.assert_unknown_category_warning(rc, out, err, cfg)

    def test_valid_config_fires_t_sql_control(self):
        """Guards against vacuous passes: a VALID category must still work."""
        self.write_cfg(self.good)
        rc, out, err = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")               # no false warnings
        self.assertIn("T-SQL", out)

    def test_valid_explicit_config_exit_0(self):
        cfg = self.write_cfg(self.good, "good.json")
        rc, out, err = self.run_cli("--taint-config", cfg)
        self.assertEqual(rc, 0)
        self.assertEqual(err, "")

    def test_dedupe_no_double_warning_from_two_engines(self):
        cfg = self.write_cfg(self.bad)
        rc, out, err = self.run_cli()
        n = err.count("has unknown category 'sql'")
        self.assertEqual(n, 1, f"warning printed {n} times:\n{err}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
