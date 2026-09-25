#!/usr/bin/env python3
"""Unit tests — Lazaret flow-engine Python 3.12+ compat (card "replace
removed ast.Num/ast.Str in lazaret_flow.py:228 — every real Python scan
crashes on Python 3.12+", audit id C1/F1, plus the M16/F12 recursion guard).

Run:  python3 lazaret/test_flow_py312_compat.py [unittest-args]

Acceptance criteria covered:
  C1 (F1): lazaret_flow._py_expr_taint referenced ast.Num/ast.Str, which
      were REMOVED in Python 3.12 — the attribute access raised AttributeError
      on the first non-ast.Name expression in any function body, so every
      real Python scan crashed (module-level analyze(), MCP
      scan_directory/scan_files/quality_gate, registry --full). The CLI
      swallowed it into a stderr warning and silently lost all
      interprocedural findings. Fixed: the isinstance check now uses
      ast.Constant only (all literals are Constant since 3.8; the deprecated
      aliases were equivalent, so nothing is lost). This is the only
      occurrence — a full ast.X inventory was re-checked.
  M16/F12: _py_analyze_fn/_visit are mutually recursive with no bound, and
      _py_expr_taint recurses on operand trees. CPython rejects >100 nested
      parens (SyntaxError), but an operator chain ("1+1+…" / "- - -1")
      parses fine and builds a left-deep AST, so hostile/generated code can
      still overflow the ~1000-frame limit. A per-function RecursionError
      guard keeps the rest of the scan (Q-FLOW-RECURSION INFO note, like
      Q-SKIPPED-TREE).
"""
from __future__ import annotations

import ast
import json
import os

from tests import _support  # noqa: E402
import subprocess
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
CLI = _support.CLI


from lazaret.scanner import flow as lazaret_flow  # noqa: E402

assert os.path.abspath(lazaret_flow.__file__) == _support.FLOW_SRC, (
    f"test imported a shadowed module: {lazaret_flow.__file__}")

# Two-file interprocedural sample: default source (request.args) flows into
# a default sink (execute) via a cross-function call — found ONLY by the
# flow engine (never by the intra-file taint_scan), so it proves the engine
# is actually running, not merely not crashing.
API_PY = (
    'def handler():\n'
    '    q = request.args.get("q")\n'
    '    return db_run(q)\n'
)
STORE_PY = (
    'def db_run(x):\n'
    '    return cur.execute("SELECT * FROM t WHERE a = " + x)\n'
)


def _deep_src(terms=4000):
    """Valid Python that parses fine but builds a left-deep AST of ~4k nodes
    (CPython's >100 nested-parens SyntaxError does not stop operator
    chains)."""
    return "def deep(x):\n    y = " + "1+" * terms + "1\n    return y\n"


class C1AstNumCompat(unittest.TestCase):
    """ast.Num/ast.Str removed in 3.12 — engine must not touch them."""

    def test_analyze_numeric_expression_in_function_body(self):
        """The card's minimal repro: a def whose body contains a numeric
        expression. Pre-fix this raised AttributeError (ast.Num) on
        Python 3.12+; it must return findings (possibly none) instead."""
        files = [{"path": "repro.py", "lang": "py",
                  "content": "def f(x):\n    return 42\n"}]
        out = lazaret_flow.analyze(files)  # must not raise
        self.assertIsInstance(out, list)

    def test_analyze_string_and_binop_constants(self):
        """String constants and binops hit the same removed-alias branch."""
        files = [{"path": "repro2.py", "lang": "py",
                  "content": ('def g(x):\n'
                              '    s = "prefix" + "suffix"\n'
                              '    y = 1 + 2\n'
                              '    return s if y else ""\n')}]
        out = lazaret_flow.analyze(files)  # must not raise
        self.assertIsInstance(out, list)

    def test_interprocedural_taint_still_found(self):
        """Golden path: the two-file request.args -> db_run -> execute chain
        must yield the cross-file X-SQL finding (engine live, not dead)."""
        files = [{"path": "api.py", "lang": "py", "content": API_PY},
                 {"path": "store.py", "lang": "py", "content": STORE_PY}]
        out = lazaret_flow.analyze(files)
        rules = [(i["rule"], i["file"], i["sev"]) for i in out]
        self.assertIn(("X-SQL", "api.py", "BLOCKER"), rules,
                      f"flow engine lost its interprocedural finding: {rules}")

    def test_no_removed_ast_aliases_left(self):
        """Guard the whole source tree against the removed aliases coming
        back (the card's inventory claim, kept enforceable)."""
        for fname in ("lazaret_flow.py", "lazaret.py",
                      "lazaret_repo.py", "lazaret_mcp.py",
                      "lazaret_report.py", "lazaret_pg.py"):
            path = os.path.join(HERE, fname)
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    # strip comments — explanatory notes may mention the
                    # removed aliases; only code references are regressions
                    code = line.split("#", 1)[0]
                    self.assertNotRegex(
                        code, r"ast\.(Num|Str|Bytes|NameConstant|Ellipsis)\b",
                        f"{fname}:{lineno} still references a removed "
                        f"ast alias: {line.strip()}")


class C1DriverInheritance(unittest.TestCase):
    """The MCP driver calls analyze() unguarded — with the engine fixed it
    must find the cross-file finding instead of crashing."""

    def test_mcp_run_project_scan(self):
        from lazaret.mcp import server as lazaret_mcp
        root = tempfile.mkdtemp(prefix="cg-c1-mcp-")
        self.addCleanup(lambda: _rmtree(root))
        for name, text in (("api.py", API_PY), ("store.py", STORE_PY)):
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        res = lazaret_mcp.run_project_scan(root)  # must not raise
        rules = [i.get("rule") for i in res["issues"]]
        self.assertIn("X-SQL", rules,
                      f"MCP scan lost the interprocedural finding: {rules}")

    def test_cli_flow_engine_not_skipped(self):
        """CLI end-to-end: pre-fix it printed 'interprocedural taint analysis
        skipped' (engine dead, findings silently lost). Now the warning must
        be gone AND the flow finding must appear in the JSON report."""
        root = tempfile.mkdtemp(prefix="cg-c1-cli-")
        self.addCleanup(lambda: _rmtree(root))
        for name, text in (("api.py", API_PY), ("store.py", STORE_PY)):
            with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        out_json = os.path.join(root, "report.json")
        proc = subprocess.run(
            [sys.executable, CLI, "--json", out_json, "--no-html", root],
            cwd=root, capture_output=True, text=True, timeout=180)
        self.assertNotIn("interprocedural taint analysis skipped",
                         proc.stderr,
                         "flow engine still degrading on this Python: "
                         f"{proc.stderr[-400:]}")
        self.assertNotIn("Traceback", proc.stderr)
        with open(out_json, encoding="utf-8") as fh:
            data = json.load(fh)
        rules = [i.get("rule") for i in data.get("issues", [])]
        self.assertIn("X-SQL", rules,
                      f"CLI report lost the flow finding: {rules}")


class M16RecursionGuard(unittest.TestCase):
    """Deep-but-valid ASTs must not kill the whole scan."""

    def test_deep_chain_no_crash_and_info_note(self):
        files = [{"path": "deep.py", "lang": "py", "content": _deep_src()}]
        out = lazaret_flow.analyze(files)  # must not raise
        notes = [i for i in out if i["rule"] == "Q-FLOW-RECURSION"]
        self.assertEqual(len(notes), 1, f"expected one INFO note: {out}")
        note = notes[0]
        self.assertEqual(note["sev"], "INFO")
        self.assertEqual(note["file"], "deep.py")
        self.assertEqual(note["line"], 1)

    def test_deep_chain_preserves_other_files_findings(self):
        """One hostile/generated file must not cost the scan its real
        findings in other files (per-function guard, not a global catch)."""
        files = [
            {"path": "deep.py", "lang": "py", "content": _deep_src()},
            {"path": "api.py", "lang": "py", "content": API_PY},
            {"path": "store.py", "lang": "py", "content": STORE_PY},
        ]
        out = lazaret_flow.analyze(files)
        rules = sorted(i["rule"] for i in out)
        self.assertIn("X-SQL", rules, f"deep file cost us real findings: {rules}")
        self.assertIn("Q-FLOW-RECURSION", rules)
        self.assertEqual(rules.count("X-SQL"), 1)

    def test_shallow_code_gets_no_recursion_note(self):
        files = [{"path": "api.py", "lang": "py", "content": API_PY},
                 {"path": "store.py", "lang": "py", "content": STORE_PY}]
        out = lazaret_flow.analyze(files)
        self.assertEqual([i["rule"] for i in out], ["X-SQL"])


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
