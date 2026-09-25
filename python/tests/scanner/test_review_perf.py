"""Review fix: quadratic hot spots in scan_file, and the per-file time backstop.

Each case from the review is its repro scaled up ~10x (S-ENTROPY: 1.5x, as
10x would exceed the 2 MB source-file cap and the test's time budget); the
other patterns fixed alongside are tested at a size where their old
quadratic cost was already several seconds. Before the fix these took from 1.4 s
to 20+ s at the ORIGINAL size and grow quadratically, so at these sizes they
would run for minutes; now each finishes in well under a second on a quiet
machine. The bound per case is deliberately loose (CI machines are slow and
shared); the whole file stays under ~10 s.
"""
import random
import string
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

PER_CASE_LIMIT = 4.0


def _entropy_lines(n):
    rnd = random.Random(1)
    alphabet = string.ascii_letters + string.digits
    return "\n".join('k%d = "%s"' % (i, "".join(rnd.choice(alphabet) for _ in range(24)))
                     for i in range(n))


CASES = {
    # review repro -> 10x
    "js fn_re on a 320 KB hex literal (32 KB: 12.7 s)":
        ('const wasm = "' + "0123456789abcdef" * 20000 + '";', "js"),
    "js fn_re on 'a' * 400k (40 KB: 21.9 s)": ("a" * 400000, "js"),
    "js fn_re on 'a(' * 100k": ("a(" * 100000, "js"),
    "py taint chain a0..a10000 (a1000: 20 s)":
        ("from flask import request\na0 = request.args['x']\n"
         + "".join("a%d = a%d\n" % (i + 1, i) for i in range(10000)), "py"),
    "js 'try{}catch(e){}' * 30000 on one line (x3000: 20 s)":
        ("try{}catch(e){}" * 30000, "js"),
    "py '.execute(' * 40000 (x4000: 3.3 s)": (".execute(" * 40000, "py"),
    "py 'x = 1' + 400k spaces + '#' (40k: 4.6 s)": ("x = 1" + " " * 400000 + "#", "py"),
    "sql 'SET @a = ' + 500k quotes (50k: 7.6 s)": ("SET @a = " + "'" * 500000, "sql"),
    "sql 'GRANT ' * 80000 (x8000: 1.4 s)": ("GRANT " * 80000, "sql"),
    "sql 'EXECUTE IMMEDIATE ' * 30000": ("EXECUTE IMMEDIATE " * 30000, "sql"),
    "py S-ENTROPY dedupe on 30k secret lines (20k: 15.7 s)": (_entropy_lines(30000), "py"),
    "py 'except:' + 500k newlines (B-EXCEPT-PASS)": ("except:" + "\n" * 500000 + "x", "py"),
    "py 'except ' * 35000 on one line": ("except " * 35000, "py"),
    "py 1000 nested defs + 100k blank lines": (
        "".join(" " * k + "def f%d():\n" % k for k in range(1000)) + "\n" * 100000, "py"),
    "py 'yaml.load(' * 50000 + 'SafeLoader'": ("yaml.load(" * 50000 + "SafeLoader", "py"),
    "py 'chmod(' * 40000": ("chmod(" * 40000, "py"),
    "js 'catch(' * 40000": ("catch(" * 40000, "js"),
    "js lexer: '=/[' * 100000": ("=/[" * 100000, "js"),
}


class QuadraticHotSpotTests(unittest.TestCase):
    def test_each_case_is_fast(self):
        for label, (content, lang) in CASES.items():
            with self.subTest(case=label):
                t = time.monotonic()
                issues = core.scan_file("x." + lang, content, lang)
                elapsed = time.monotonic() - t
                self.assertLess(elapsed, PER_CASE_LIMIT, f"{label}: {elapsed:.1f}s")
                self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})


class DependencyModeFlowPerfTests(unittest.TestCase):
    """The dep-mode decode->sink flow added with this fix stays linear."""

    def test_long_lines_of_sinks(self):
        for content in ("const d = atob(x);\n" + "eval(e" * 50000,
                        "const d = atob(x);\n" + "eval(" * 30000 + "d" + ")" * 30000,
                        "a=atob(x);" * 40000):
            t = time.monotonic()
            core.scan_file("dep.js", content, "js", dep=True)
            self.assertLess(time.monotonic() - t, PER_CASE_LIMIT)


class BackstopTests(unittest.TestCase):
    def setUp(self):
        self._budget = core.SCAN_TIME_BUDGET
        self.addCleanup(setattr, core, "SCAN_TIME_BUDGET", self._budget)

    def test_budget_exceeded_emits_sc_truncated(self):
        core.SCAN_TIME_BUDGET = -1.0
        issues = core.scan_file("slow.py", "import os\nos.system(input())  # nosec\n", "py")
        trunc = [i for i in issues if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(len(trunc), 1)
        self.assertIn("scan time budget exceeded", trunc[0]["msg"])
        self.assertEqual(trunc[0]["sev"], "CRITICAL")

    def test_default_budget_is_30_seconds(self):
        self.assertEqual(self._budget, 30.0)
        self.assertNotIn("SC-TRUNCATED",
                         {i["rule"] for i in core.scan_file("a.py", "x = 1\n", "py")})


class RewrittenPatternSemanticsTests(unittest.TestCase):
    """The linear rewrites still match what the old patterns matched."""

    def rules(self, src, lang):
        return {i["rule"] for i in core.scan_file("x." + lang, src, lang)}

    def test_sql_dynamic(self):
        for src in ("EXEC(@sql + @x);", "EXECUTE IMMEDIATE 'SELECT ' || v;",
                    "EXEC sp_executesql N'SELECT ' + @x;", "EXEC('SELECT ' + @x);",
                    "SET @q = 'SELECT * FROM t WHERE a=' + @a;",
                    "SET @q = 'x' || v;", "EXECUTE IMMEDIATE x EXECUTE IMMEDIATE 'a' || b;"):
            with self.subTest(src=src):
                self.assertIn("SQL-DYNAMIC", self.rules(src + "\n", "sql"))
        for src in ("SET @q = 'x';", "SET @n = 1 + 2;", "EXECUTE IMMEDIATE 'x'; y || z;"):
            with self.subTest(src=src):
                self.assertNotIn("SQL-DYNAMIC", self.rules(src + "\n", "sql"))

    def test_sql_grant_public(self):
        self.assertIn("SQL-GRANT-PUBLIC", self.rules("GRANT SELECT ON t TO PUBLIC;\n", "sql"))
        self.assertIn("SQL-GRANT-PUBLIC",
                      self.rules("GRANT GRANT SELECT ON t TO PUBLIC;\n", "sql"))
        self.assertNotIn("SQL-GRANT-PUBLIC",
                         self.rules("GRANT SELECT ON t TO bob; SELECT 1 TO PUBLIC\n", "sql"))

    def test_except_pass_and_empty_catch(self):
        self.assertIn("B-EXCEPT-PASS", self.rules("try:\n    f()\nexcept ValueError:\n\n    pass\n", "py"))
        self.assertIn("B-EXCEPT-PASS", self.rules("try:\n    f()\nexcept:  \n    pass\n", "py"))
        self.assertNotIn("B-EXCEPT-PASS", self.rules("try:\n    f()\nexcept E:\n    log()\n", "py"))
        self.assertIn("B-EMPTY-CATCH", self.rules("try { f() } catch (e) { }\n", "js"))
        self.assertIn("B-EMPTY-CATCH", self.rules("try { f() } catch { }\n", "js"))

    def test_chmod_and_yaml(self):
        self.assertIn("S-CHMOD", self.rules("import os\nos.chmod(p, 0o777)\n", "py"))
        self.assertIn("S-YAML", self.rules("yaml.load(data)\n", "py"))
        self.assertNotIn("S-YAML", self.rules("yaml.load(data, Loader=yaml.SafeLoader)\n", "py"))

    def test_sql_assign_template_still_tracked(self):
        src = 'q = "SELECT * FROM t WHERE id = %s"   \ncur.execute(q % uid)\n'
        self.assertIn("S-SQL-PY", self.rules(src, "py"))

    def test_sql_analyzer_paren_pairing(self):
        src = 'cur.execute("SELECT %s" % f(x), )\ncur.execute(q, (a, b))\n'
        issues = core.scan_file("x.py", src, "py")
        self.assertEqual([i["line"] for i in issues if i["rule"] == "S-SQL-PY"], [1])


def _old_py_functions(lines):
    """The pre-fix O(defs x lines) Python branch of extract_functions."""
    import re
    fns = []
    cx_re = re.compile(r"\b(if|elif|for|while|and|or|except|case)\b")
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)(?:async\s+)?def\s+(\w+)", line)
        if not m:
            continue
        indent = len(m.group(1))
        end = i + 1
        while end < len(lines):
            l = lines[end]
            if l.strip() and not l.strip().startswith("#") and (len(l) - len(l.lstrip())) <= indent:
                break
            end += 1
        body = "\n".join(lines[i:end])
        fns.append({"name": m.group(2), "line": i + 1, "len": end - i,
                    "cx": 1 + len(cx_re.findall(body))})
    return fns


class PythonFunctionSpanEquivalenceTests(unittest.TestCase):
    def test_same_spans_as_the_old_scan(self):
        import os
        samples = [os.path.join(_support.PKG, "scanner", n) for n in ("core.py", "flow.py", "sca.py")]
        texts = []
        for p in samples:
            with open(p, encoding="utf-8") as fh:
                texts.append(fh.read())
        texts.append("def a():\n    def b():\n        pass\n    # c\n  # d\nx = 1\n"
                     "async def c():\n\n    if x and y:\n        pass\ndef e(): pass\n")
        for text in texts:
            lines = text.split("\n")
            self.assertEqual(core.extract_functions(lines, "py"), _old_py_functions(lines))


if __name__ == "__main__":
    unittest.main()
