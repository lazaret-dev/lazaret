"""Review finding 5 — taint-config trust and robustness.

.lazaret-taint.json was auto-loaded from the scanned repository and fully
trusted: a repo could declare `str` a full sanitizer and silence a real
cross-file X-CMD; `(a|a)+b` as a source regex hung the scan; wrong JSON
types crashed both engines; `sources: "request"` was iterated per character.

Now: the repo's config is loaded only with --trust-repo-config and then may
add sources and sinks but never sanitizers; --taint-config is trusted fully;
every field is type-checked (warning, exit 4 when strict — never a
traceback); user regexes are length-capped, statically checked for
catastrophic backtracking, and matched against at most 2,000 characters of
each candidate. A used repo config shows up in the report (Q-TAINT-CONFIG).

Fixtures are inert text; nothing is executed.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

from tests import _support
from lazaret.scanner import core as lazaret
from lazaret.scanner import flow as lazaret_flow
from lazaret.scanner import taintspec

PY = sys.executable or "python3"
CLI = _support.CLI

VIEW_PY = ("from flask import request\n"
           "from runner import run_cmd\n"
           "def view():\n"
           "    run_cmd(str(request.args['q']))\n")
RUNNER_PY = "import os\ndef run_cmd(c):\n    os.system(c)\n"
STR_IS_SAFE = {"python": {"sanitizers": {"full": ["str"]}}}


class _EngineState:
    """Snapshot/restore every global table both engines' config loaders
    mutate, so these tests cannot leak rules into other tests."""

    def __init__(self):
        self.saved = (dict(lazaret.TAINT_SOURCES),
                      {k: list(v) for k, v in lazaret.TAINT_SINKS.items()},
                      dict(lazaret._FULL_SAN), copy.deepcopy(lazaret._PARTIAL_SAN),
                      list(lazaret_flow._PY_SOURCE_EXTRA), list(lazaret_flow._EXTRA_PY_SINKS),
                      set(lazaret_flow.FULL_SANITIZERS_PY), dict(lazaret_flow._EXTRA_PARTIAL_PY),
                      lazaret_flow._JS_SOURCE_RE, list(lazaret_flow._JS_SINKS),
                      lazaret_flow._JS_FULL_SAN_RE, dict(lazaret_flow._JS_PARTIAL_SAN))

    def restore(self):
        (srcs, sinks, full, part, pse, eps, fsp, epp, jsrc, jsinks, jfull, jpart) = self.saved
        lazaret.TAINT_SOURCES.clear()
        lazaret.TAINT_SOURCES.update(srcs)
        for k, v in sinks.items():
            lazaret.TAINT_SINKS[k][:] = v
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


class Project(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="lz-review-cfg-")
        self.out = tempfile.mkdtemp(prefix="lz-review-cfg-out-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(shutil.rmtree, self.out, True)
        self.write("view.py", VIEW_PY)
        self.write("runner.py", RUNNER_PY)

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return path

    def scan(self, *extra):
        rep = os.path.join(self.out, "r.json")
        if os.path.exists(rep):
            os.unlink(rep)
        p = subprocess.run([PY, CLI, self.root, "--no-html", "--json", rep, "-q", *extra],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertNotIn("Traceback", p.stderr)
        report = {"issues": []}
        if os.path.exists(rep):
            with open(rep, encoding="utf-8") as fh:
                report = json.load(fh)
        return p, {i["rule"] for i in report["issues"]}, report


class RepoConfigTrust(Project):
    def test_repo_config_not_loaded_without_flag(self):
        self.write(".lazaret-taint.json", json.dumps(STR_IS_SAFE))
        p, rules, _ = self.scan()
        self.assertIn("found but not loaded", p.stdout)
        self.assertIn("--trust-repo-config", p.stdout)
        self.assertNotIn("Loaded taint config", p.stdout)
        self.assertIn("X-CMD", rules)          # the repo could not silence it

    def test_repo_config_sanitizers_ignored_even_when_trusted(self):
        """Reviewer repro: `str` declared a full sanitizer silenced a real
        cross-file X-CMD."""
        self.write(".lazaret-taint.json", json.dumps(STR_IS_SAFE))
        p, rules, report = self.scan("--trust-repo-config")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("sanitizers ignored", p.stderr)
        self.assertIn("X-CMD", rules)
        notes = [i for i in report["issues"] if i["rule"] == "Q-TAINT-CONFIG"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["file"], ".lazaret-taint.json")
        self.assertEqual(notes[0]["sev"], "INFO")
        self.assertIn("1 sanitizer rule(s) ignored", notes[0]["msg"])

    def test_repo_config_sources_and_sinks_apply(self):
        self.write("custom.py", "import mylib\ndata = mylib.read_untrusted()\nmylib.run_shell(data)\n")
        self.write(".lazaret-taint.json", json.dumps({"python": {
            "sources": [r"mylib\.read_untrusted"],
            "sinks": [{"pattern": r"mylib\.run_shell", "category": "command injection"}]}}))
        _, rules, _ = self.scan()
        self.assertNotIn("T-CMD", rules)
        _, rules, _ = self.scan("--trust-repo-config")
        self.assertIn("T-CMD", rules)
        self.assertIn("Q-TAINT-CONFIG", rules)

    def test_explicit_config_is_trusted_fully(self):
        cfg = os.path.join(self.out, "cfg.json")
        with open(cfg, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(STR_IS_SAFE, fh)
        p, rules, _ = self.scan("--taint-config", cfg)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn("X-CMD", rules)       # operator's own choice
        self.assertNotIn("Q-TAINT-CONFIG", rules)

    @unittest.skipUnless(hasattr(os, "symlink"), "no symlinks")
    def test_symlinked_repo_config_refused(self):
        target = os.path.join(self.out, "real.json")
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"python": {"sources": ["x"]}}, fh)
        try:
            os.symlink(target, os.path.join(self.root, ".lazaret-taint.json"))
        except OSError:
            self.skipTest("cannot create symlinks here")
        p, _, _ = self.scan("--trust-repo-config")
        self.assertIn("not a regular file", p.stderr)


class ConfigTypeValidationCLI(Project):
    """Every reviewer shape: no traceback; explicit config → exit 4."""
    CASES = {
        "sources_int": '{"python": {"sources": [1]}}',
        "sources_null": '{"python": {"sources": null}}',
        "sources_string": '{"python": {"sources": "request"}}',
        "full_nested": '{"python": {"sanitizers": {"full": [["x"]]}}}',
        "partial_nested": '{"python": {"sanitizers": {"partial": {"a": [["x"]]}}}}',
        "js_sources_int": '{"javascript": {"sources": 5}}',
        "full_int": '{"python": {"sanitizers": {"full": 5}}}',
        "js_full_int": '{"javascript": {"sanitizers": {"full": 5}}}',
        "sink_pattern_int": '{"python": {"sinks": [{"pattern": 5, "category": "code injection"}]}}',
        "sink_category_list": '{"python": {"sinks": [{"pattern": "x", "category": ["x"]}]}}',
        "redos_source": '{"python": {"sources": ["(a|a)+b"]}}',
        "redos_sink": '{"python": {"sinks": [{"pattern": "^(a|aa)+$", "category": "command injection"}]}}',
        "long_pattern": json.dumps({"python": {"sources": ["a" * 600]}}),
    }

    def test_explicit_bad_shapes_exit_4_without_traceback(self):
        for name, text in self.CASES.items():
            with self.subTest(case=name):
                cfg = os.path.join(self.out, name + ".json")
                with open(cfg, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                t = time.time()
                p, _, _ = self.scan("--taint-config", cfg)
                self.assertLess(time.time() - t, 30)
                self.assertEqual(p.returncode, 4, p.stderr)
                self.assertIn("rejected", p.stderr)

    def test_undecodable_and_huge_int_configs_warn(self):
        for name, data in (("xff", b'{"python": {"sources": ["\xff"]}}'),
                           ("bigint", b'{"python": {"sources": [' + b"9" * 5000 + b"]}}")):
            with self.subTest(case=name):
                cfg = os.path.join(self.out, name + ".json")
                with open(cfg, "wb") as fh:
                    fh.write(data)
                p, _, _ = self.scan("--taint-config", cfg)
                self.assertIn("could not load taint config", p.stderr + p.stdout)

    def test_repo_bad_shape_warns_but_scans(self):
        self.write(".lazaret-taint.json", '{"python": {"sources": "request"}}')
        p, rules, _ = self.scan("--trust-repo-config")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("python.sources is str, not a list", p.stderr)
        p, _, _ = self.scan("--trust-repo-config", "--strict-taint-config")
        self.assertEqual(p.returncode, 4)


class ValidatorUnit(unittest.TestCase):
    def setUp(self):
        self.state = _EngineState()
        self.addCleanup(self.state.restore)

    def test_string_sources_not_iterated(self):
        spec = taintspec.validate({"python": {"sources": "request"}})
        self.assertEqual(spec.python.sources, [])
        self.assertEqual(len(spec.warnings), 1)

    def test_both_engines_share_texts(self):
        cfg = {"python": {"sources": [1, "(a+)+"], "sinks": [{"pattern": 5, "category": "code injection"}],
                          "sanitizers": {"full": [["x"]], "partial": {"a": [["x"]]}}},
               "javascript": {"sources": 5}}
        lazaret.apply_taint_config(cfg)
        intra = lazaret.get_taint_config_warnings()
        flow = []
        lazaret_flow.configure(cfg, on_warn=flow.append)
        self.assertEqual(intra, flow)
        self.assertEqual(len(intra), 6, intra)

    def test_repo_mode_ignores_sanitizers_with_note(self):
        spec = taintspec.validate(STR_IS_SAFE, allow_sanitizers=False)
        self.assertEqual(spec.warnings, [])
        self.assertEqual(len(spec.notes), 1)
        self.assertEqual(spec.python.full, [])
        before = set(lazaret_flow.FULL_SANITIZERS_PY)
        lazaret_flow.configure(STR_IS_SAFE, allow_sanitizers=False)
        self.assertEqual(lazaret_flow.FULL_SANITIZERS_PY, before)

    def test_redos_patterns_rejected(self):
        for pat in ("(a|a)+b", "(a+)+", "(.*)*", "^(a|aa)+$", "(a)\\1", ".*.*x",
                    "\\w+\\w+x", "a*a*a*b"):
            with self.subTest(pat=pat):
                gp, why = taintspec.check_pattern(pat)
                self.assertIsNone(gp)
                self.assertTrue(why)
        for pat in (r"mylib\.read_untrusted", r"request\.(args|form)", r"\bexec_\w+\s*\(", "(a|b)+"):
            with self.subTest(pat=pat):
                self.assertIsNotNone(taintspec.check_pattern(pat)[0])

    def test_match_text_is_capped(self):
        gp, _ = taintspec.check_pattern("needle")
        cap = taintspec.MAX_MATCH_TEXT
        self.assertIsNotNone(gp.search("x" * (cap - 10) + "needle"))
        self.assertIsNone(gp.search("x" * cap + "needle"))
        hits = [m.start() for m in gp.finditer("needle\n" + "x" * 50 + "needle")]
        self.assertEqual(hits, [0, 57])

    def test_polynomial_pattern_on_huge_line_is_bounded(self):
        """An accepted pattern with one unbounded repeat is O(n^2) per
        candidate; the 2,000-char cap keeps a 200 kB line fast in the
        intra-file engine (it used to see the whole line)."""
        lazaret.apply_taint_config({"python": {
            "sources": [r"\w*y"],
            "sinks": [{"pattern": r"sink_\w*\(", "category": "code injection"}]}})
        self.assertEqual(lazaret.get_taint_config_warnings(), [])
        line = "a = " + "b" * 200_000
        t = time.time()
        lazaret.taint_scan("x.py", [line, "sink_(" + "c" * 200_000], "py")
        self.assertLess(time.time() - t, 5)

    def test_intra_file_source_union_still_matches_builtin(self):
        lazaret.apply_taint_config({"python": {"sources": [r"my\.source\b"]}})
        src = lazaret.TAINT_SOURCES["py"]
        self.assertIsNotNone(src.search("x = request.args['q']"))
        self.assertIsNotNone(src.search("x = my.source()"))
        self.assertIsNone(src.search("x = 1"))


if __name__ == "__main__":
    unittest.main()
