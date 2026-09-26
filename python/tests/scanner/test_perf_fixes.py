#!/usr/bin/env python3
"""Unit tests — Lazaret performance on adversarial/large input (card
6d3d24c9: audit findings F11, G3, G4 — quadratic SQL text rules, quadratic +
memory-explosive JS function extraction in CLI and dashboard).

Run:  python3 lazaret/test_perf_fixes.py [unittest-args]

Acceptance criteria covered:
  1. F11 — SQL-DELETE-NOWHERE / SQL-UPDATE-NOWHERE are no longer
     tempered-dot whole-file patterns: adversarial SQL (20k unterminated
     DELETE statements in ~490 KB) scans in linear time, and detection
     parity holds (terminated offender fires; WHERE'd statement does not;
     unterminated statements never fired the old pattern either).
  2. G4 — extract_functions' JS branch is a single linear brace pass:
     adversarial minified shapes (1500 unclosed headers / one 1.5 MB line)
     complete quickly, and outputs match the old window-scan implementation
     on both curated fixtures and randomized inputs (differential).
  3. G3 — lazaret_flow._js_functions returns spans (no body copies) that
     slice to the exact old body strings; _analyze_js matches the old
     implementation on randomized taint fixtures (differential) and
     completes on adversarial input; files above _JS_MAX_FILE are skipped
     with a visible INFO finding (X-FLOW-SKIPPED), never silently.
  4. CLI end-to-end: a project containing the adversarial SQL file scans
     to completion with exit 0 in bounded time and still reports the
     genuine offender.

Timing budgets are generous (10–30 s) so CI variance cannot flake; the
before-fix numbers were 735 s (F11), 20 s (G4), 27 s + 66 s (G3).
"""
from __future__ import annotations

import os

from tests import _support  # noqa: E402
import re
import subprocess
import sys
import time
import unittest


HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
CLI = _support.CLI
PY = sys.executable or "python3"

from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.scanner import flow as lazaret_flow  # noqa: E402


# ---------------------------------------------------------------- helpers
def make_sql(n_stmts=20_000, size_target=280_000):
    """Audit F11 shape: n_stmts UNTERMINATED DELETE statements (no ';')."""
    parts = []
    pad = max(1, (size_target // n_stmts) - 24)
    for i in range(n_stmts):
        parts.append(f"DELETE FROM t{i} /*{'x' * pad}*/")
    return "\n".join(parts)


def make_js_multiline(n_lines=1500, size_target=1_500_000):
    """Audit G4 shape: one fn header per line, braces never closed."""
    per = max(80, size_target // n_lines)
    lines = []
    for i in range(n_lines):
        lines.append(f"function f{i}(p){{var v{i}='{'x' * (per - 40)}';")
    return "\n".join(lines).split("\n")


def make_js_single(n_fns=1500, size_target=1_500_000):
    """Audit G3 shape: minified single line, functions never closed."""
    per = max(60, size_target // n_fns)
    return "".join(
        f"function f{i}(p){{var v{i}='{'x' * (per - 45)}';return v{i}+p;"
        for i in range(n_fns))


# ------------------------------------------------- old implementations
# Verbatim pre-fix behavior, used as the differential oracle.
_OLD_CX_RE = re.compile(r"\b(if|for|while|case|catch)\b|&&|\|\||\?[^.:]")
_OLD_FN_RE = re.compile(
    r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?"
    r"(?:function|\([^)]*\)\s*=>|\w+\s*=>)|(\w+)\s*\([^)]*\)\s*\{)")


def old_extract_functions_js(lines):
    fns = []
    for i, line in enumerate(lines):
        m = _OLD_FN_RE.search(line)
        if not m:
            continue
        name = m.group(1) or m.group(2) or m.group(3) or "(anonymous)"
        depth, started, end = 0, False, i
        for j in range(i, min(len(lines), i + 800)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        end = j
                        break
            else:
                end = j
                continue
            break
        if not started:
            continue
        body = "\n".join(lines[i:end + 1])
        fns.append({"name": name, "line": i + 1, "len": end - i + 1,
                    "cx": 1 + len(_OLD_CX_RE.findall(body))})
    return fns


def old_js_functions(content):
    out = []
    for m in lazaret_flow._JS_FUNC_RE.finditer(content):
        name = m.group("n1") or m.group("n2") or m.group("n3")
        ps = m.group("p1") or m.group("p2") or m.group("p3") or ""
        params = [p.strip().split("=")[0].strip() for p in ps.split(",") if p.strip()]
        brace = content.find("{", m.end() - 1)
        if brace == -1:
            continue
        depth, i = 0, brace
        while i < len(content):
            if content[i] == "{":
                depth += 1
            elif content[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = content[brace:i + 1]
        start_line = content[:m.start()].count("\n") + 1
        out.append((name, params, body, start_line))
    return out


def old_analyze_js(files, findings):
    """Pre-fix _analyze_js (oracle)."""
    summaries = {}
    fn_defs = {}
    js_files = [f for f in files if f["lang"] == "js"]
    for f in js_files:
        for name, params, body, start in old_js_functions(f["content"]):
            fn_defs[name] = (f["path"], start)
            reach = {}
            for sink_re, cat in lazaret_flow._JS_SINKS:
                for sm in sink_re.finditer(body):
                    seg = body[sm.start():sm.start() + 200]
                    for p in params:
                        if p and lazaret_flow._js_param_dangerous(seg, p, cat):
                            reach[p] = cat
            if reach:
                summaries[name] = (params, reach)
    if not summaries:
        return
    call_re = re.compile(r"\b(\w+)\s*\(([^;()]*)\)")
    for f in js_files:
        lines = f["content"].split("\n")
        tainted = set()
        assign_re = re.compile(
            r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
            r"|(?:^|[;{]\s*)([A-Za-z_$][\w$]*)\s*=(?![=>])\s*([^;\n]+)")
        for am in assign_re.finditer(f["content"]):
            name = am.group(1) or am.group(3)
            rhs = am.group(2) or am.group(4) or ""
            rhs = lazaret_flow._js_neutralize(rhs, ())
            if lazaret_flow._JS_SOURCE_RE.search(rhs) or any(
                    re.search(r"\b%s\b" % re.escape(v), rhs) for v in tainted):
                tainted.add(name)
        for i, ln in enumerate(lines):
            for cm in call_re.finditer(ln):
                fname, argstr = cm.group(1), cm.group(2)
                if fname not in summaries:
                    continue
                params, reach = summaries[fname]
                call_args = [a.strip() for a in argstr.split(",")]
                for idx, pname in enumerate(params):
                    if pname not in reach or idx >= len(call_args):
                        continue
                    a = lazaret_flow._js_neutralize(call_args[idx], {reach[pname]})
                    if lazaret_flow._JS_SOURCE_RE.search(a) or any(
                            re.search(r"\b%s\b" % re.escape(v), a) for v in tainted):
                        dfile, dline = fn_defs.get(fname, (f["path"], 1))
                        findings.append(lazaret_flow._issue(
                            reach[pname], f["path"], i + 1, lines,
                            source_loc=f"{f['path']}:{i + 1}",
                            sink_loc=f"{dfile}:{dline} (in {fname}())",
                            chain=f"the call to {fname}()"))
                        break


# ---------------------------------------------------------------- tests
class F11SqlRules(unittest.TestCase):
    """Tempered-dot SQL *-NOWHERE rules replaced by a linear statement scan."""

    def test_rules_are_linear_patterns(self):
        for rid in ("SQL-DELETE-NOWHERE", "SQL-UPDATE-NOWHERE"):
            r = next(r for r in lazaret.TEXT_RULES if r["id"] == rid)
            self.assertNotIn("(?!", r["re"].pattern, f"{rid} still tempered")
            self.assertFalse(r["re"].flags & re.S, f"{rid} still uses re.S")

    def test_adversarial_sql_is_linear(self):
        sql = make_sql()
        t0 = time.perf_counter()
        issues = lazaret.scan_file("adv.sql", sql, "sql")
        dt = time.perf_counter() - t0
        self.assertLess(dt, 10.0, f"F11: adversarial SQL took {dt:.1f}s")
        # unterminated statements must NOT fire (old pattern required ';')
        self.assertFalse([i for i in issues if i["rule"].endswith("NOWHERE")])

    def test_detection_parity(self):
        content = ("DELETE FROM sessions;\n"
                   "DELETE FROM sessions WHERE id=1;\n"
                   "UPDATE t SET a=1;\n"
                   "UPDATE t SET a=1 WHERE id=1;\n")
        got = [(i["rule"], i["line"]) for i in lazaret.scan_file("p.sql", content, "sql")
               if i["rule"].endswith("NOWHERE")]
        self.assertEqual(got, [("SQL-DELETE-NOWHERE", 1), ("SQL-UPDATE-NOWHERE", 3)])

    def test_multi_statement_line(self):
        # statements on one line: an offender after a WHERE'd statement still
        # fires, the WHERE'd one alone doesn't; two offenders on one line are
        # ONE finding (same rule, line and message: identical in every report)
        def got(content):
            return [i["line"] for i in lazaret.scan_file("p.sql", content, "sql")
                    if i["rule"] == "SQL-DELETE-NOWHERE"]
        self.assertEqual(got("DELETE FROM a; DELETE FROM b WHERE x=1; DELETE FROM c;\n"), [1])
        self.assertEqual(got("DELETE FROM b WHERE x=1; DELETE FROM c;\n"), [1])
        self.assertEqual(got("DELETE FROM b WHERE x=1;\n"), [])

    def test_sqlproj_corpus_unchanged(self):
        """The sample SQL corpus reports exactly the pre-fix 12 issues."""
        per_rule = {}
        for fn in os.listdir(os.path.join(HERE, "sqlproj")):
            if not fn.endswith(".sql"):
                continue
            p = os.path.join(HERE, "sqlproj", fn)
            content = open(p, encoding="utf-8", errors="replace").read()
            for i in lazaret.scan_file(p, content, "sql"):
                per_rule[i["rule"]] = per_rule.get(i["rule"], 0) + 1
        self.assertEqual(sum(per_rule.values()), 12)
        self.assertEqual(per_rule.get("SQL-DELETE-NOWHERE"), 1)
        self.assertEqual(per_rule.get("SQL-UPDATE-NOWHERE"), 1)


class G4ExtractFunctions(unittest.TestCase):
    """Single linear brace pass replaces the 800-line window restarts."""

    def test_adversarial_multiline_fast(self):
        lines = make_js_multiline()
        t0 = time.perf_counter()
        fns = lazaret.extract_functions(lines, "js")
        dt = time.perf_counter() - t0
        self.assertEqual(len(fns), 1500)
        self.assertLess(dt, 10.0, f"G4: multiline scan took {dt:.1f}s")

    def test_adversarial_single_line_fast(self):
        js = make_js_single()
        t0 = time.perf_counter()
        fns = lazaret.extract_functions(js.split("\n"), "js")
        dt = time.perf_counter() - t0
        self.assertEqual(len(fns), 1)
        self.assertLess(dt, 10.0, f"G4: single-line scan took {dt:.1f}s")

    def test_curated_fixtures_match_old(self):
        fixtures = [
            ["function a(x){ if(x){ return 1; } return 0; }"],
            ["function a(){", "  if(1){}", "}", "function b(){", "}"],
            ["const f = (x) => {", "  for(;;){}", "};"],
            ["foo(){", "  while(1){}", "}"],
            ["var g = function(){", "  x && y;", "};"],
            ["class K {", "  m(){", "  }", "}"],
            ["function noBrace(x)"],
            ["function un(x){ var s = 'no close';", "more"],
            ["function cap(x){", "}"],
            ["", "function o(){ // comment", "}"],
            ["x = {a:1};", "function later(){}"],
            ["function far(){"] + ["x;"] * 898 + ["}"],
        ]
        for lines in fixtures:
            with self.subTest(head=lines[0][:30]):
                old = [(f["name"], f["line"], f["len"], f["cx"])
                       for f in old_extract_functions_js(lines)]
                new = [(f["name"], f["line"], f["len"], f["cx"])
                       for f in lazaret.extract_functions(lines, "js")]
                self.assertEqual(old, new)

    def test_randomized_differential(self):
        import random
        rng = random.Random(1234)
        vocab = ["function f{n}(){{", "}}", "if(1){{}}", "const c{n} = (x) => {{",
                 "x && y;", "for(;;){{}}", "while(x){{", "var v{n} = function(){{",
                 "plain; text", "", "obj = {{a:1}};", "switch(x){{case 1:",
                 "try{{}}catch(e){{}}"]
        for _ in range(300):
            n = rng.randint(1, 40)
            lines = [rng.choice(vocab).replace("{n}", str(rng.randint(0, 9)))
                     for _ in range(n)]
            old = [(f["name"], f["line"], f["len"], f["cx"])
                   for f in old_extract_functions_js(lines)]
            new = [(f["name"], f["line"], f["len"], f["cx"])
                   for f in lazaret.extract_functions(lines, "js")]
            if old != new:
                self.fail(f"differential mismatch on {lines!r}\nold={old}\nnew={new}")


class G3FlowEngine(unittest.TestCase):
    """_js_functions spans + linear _analyze_js replace per-match EOF scans."""

    def test_js_functions_spans_slice_to_old_bodies(self):
        import random
        rng = random.Random(99)
        vocab = ["function a(x){", "function b(){return 1;}", "const c=(y)=>{",
                 "x();", "}", "var d=function(z){", "if(1){}", "obj={a:1};",
                 "e()=>{", "plain; text", "function un(u){", "db.query(",
                 "}", "x = eval(", "p = req.query.p;"]
        for _ in range(300):
            n = rng.randint(1, 30)
            content = "".join(rng.choice(vocab) for _ in range(n))
            old = old_js_functions(content)
            new = lazaret_flow._js_functions(content)
            self.assertEqual(len(old), len(new), content)
            for (n1, p1, body, s1), (n2, p2, span, s2) in zip(old, new):
                self.assertEqual((n1, p1, s1), (n2, p2, s2), content)
                self.assertEqual(body, content[span[0]:span[1]], content)

    def test_adversarial_js_functions_fast(self):
        js = make_js_single()
        t0 = time.perf_counter()
        fns = lazaret_flow._js_functions(js)
        dt = time.perf_counter() - t0
        self.assertEqual(len(fns), 1500)
        self.assertLess(dt, 10.0, f"G3: _js_functions took {dt:.1f}s")

    def test_adversarial_analyze_js_fast(self):
        js = make_js_single()
        files = [{"path": "poc.js", "content": js, "lang": "js"}]
        findings = []
        t0 = time.perf_counter()
        lazaret_flow._analyze_js(files, findings)
        dt = time.perf_counter() - t0
        self.assertLess(dt, 10.0, f"G3: _analyze_js took {dt:.1f}s")

    def test_analyze_js_differential(self):
        import random
        rng = random.Random(4242)
        frag = [
            "function sinky(p){ return db.query('SELECT ' + p); }",
            "function ev(q){ return eval(q); }",
            "function inner(p){ return setTimeout(function(){ eval(p); }, 1); }",
            "function clean(p){ return parseInt(p); }",
            "var t = req.query.t;",
            "var t2 = t + 'x';",
            "sink(t);",
            "sinky(t);",
            "ev(t2);",
            "inner(t);",
            "sink(parseInt(t));",
            "sink('literal');",
            "other(x);",
            "x = 1;",
            "const y = t2;",
            "sink(y);",
            "var noTaint = 'plain';",
            "sink(noTaint);",
            "fetch(t);",
            "exec(t);",
        ]
        for trial in range(400):
            n = rng.randint(1, 16)
            content = "\n".join(rng.choice(frag) for _ in range(n))
            files = [{"path": "t.js", "content": content, "lang": "js"}]
            o, w = [], []
            old_analyze_js(files, o)
            lazaret_flow._analyze_js(files, w)
            ko = sorted((x["rule"], x["line"]) for x in o)
            kw = sorted((x["rule"], x["line"]) for x in w)
            if ko != kw:
                self.fail(f"trial {trial} mismatch\ncontent={content!r}\n"
                          f"old={ko}\nnew={kw}")

    def test_oversized_file_skip_is_visible(self):
        big = "var x = 1;\n" + "x;\n" * (lazaret_flow._JS_MAX_FILE // 2)
        files = [{"path": "big.js", "content": big, "lang": "js"}]
        findings = []
        lazaret_flow._analyze_js(files, findings)
        skipped = [i for i in findings if i["rule"] == "X-FLOW-SKIPPED"]
        self.assertEqual(len(skipped), 1)
        self.assertEqual(skipped[0]["sev"], "INFO")
        self.assertIn("big.js", skipped[0]["msg"])


class CliEndToEnd(unittest.TestCase):
    """The CLI completes on a project containing the adversarial SQL file."""

    def test_scan_project_with_adversarial_sql(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "adv.sql"), "w", encoding="utf-8", newline="\n") as f:
                f.write(make_sql(n_stmts=4000, size_target=60_000))
                f.write("\nDELETE FROM sessions;\n")
            t0 = time.perf_counter()
            r = subprocess.run([PY, CLI, d, "--no-html", "--quiet"],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=120)
            dt = time.perf_counter() - t0
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(d, "lazaret-report.json"), encoding="utf-8") as f:
                rep = json.load(f)
            rules = [i["rule"] for i in rep.get("issues", [])]
            self.assertIn("SQL-DELETE-NOWHERE", rules, json.dumps(rules))
            # old semantics: 20k unterminated heads + 1 real statement = 1 issue
            self.assertEqual(rules.count("SQL-DELETE-NOWHERE"), 1, rules)
            self.assertLess(dt, 60.0, f"CLI scan took {dt:.1f}s")


if __name__ == "__main__":
    unittest.main(verbosity=2)
