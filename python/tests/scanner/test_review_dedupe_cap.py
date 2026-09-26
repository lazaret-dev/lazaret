"""Final review: report blowup from non-capped, repeated findings.

The per-(file, rule) cap covered only rules whose severity was INFO/MINOR or
whose type was SMELL, so a MAJOR bug rule still exploded: a 1.95 MB one-line
file of `try{}catch(e){}` x 130,000 gave 130,001 B-EMPTY-CATCH findings and
an 87.7 MB JSON report (a 120,000-line variant 66.7 MB). Shared semantics
now (core.cap_issues, the npm engine's capIssues, the dashboard's capIssues):

* findings identical on (rule, file, line, msg) are reported ONCE — they are
  indistinguishable in every report (same line, same snippet text); this
  applies to every rule, security rules included, and runs before the cap;
  findings of one rule on one line with DIFFERENT messages are kept;
* every rule that is not a security rule (S-, T-, SC-, X-, SQL-) is capped at
  200 findings per file, whatever its severity or type, with one Q-CAPPED.

The dashboard (node:vm, skipped without node) is checked on the same inputs.
All content is inert.
"""
import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

ONE_LINE = "try{}catch(e){}" * 130_000            # the review's 1.95 MB repro
MANY_LINES = "try{}catch(e){}\n" * 1000


def count(issues, rule):
    return sum(i["rule"] == rule for i in issues)


def capped_msgs(issues):
    return sorted(i["msg"] for i in issues if i["rule"] == "Q-CAPPED")


class DedupeTests(unittest.TestCase):
    def test_one_line_file_is_one_finding_per_rule(self):
        self.assertEqual(len(ONE_LINE), 1_950_000)
        issues = core.scan_file("one.js", ONE_LINE, "js")
        self.assertEqual(count(issues, "B-EMPTY-CATCH"), 1)
        (issue,) = [i for i in issues if i["rule"] == "B-EMPTY-CATCH"]
        self.assertEqual(issue["snippet"][0], ONE_LINE[:239] + "…")   # the leftmost match is kept
        self.assertLess(len(json.dumps(issues)), 20_000)                    # was ~88 MB as a report

    def test_security_rules_are_deduplicated_too(self):
        src = "DELETE FROM a; DELETE FROM b; DELETE FROM c;\n" * 3
        issues = core.scan_file("d.sql", src, "sql")
        self.assertEqual([i["line"] for i in issues if i["rule"] == "SQL-DELETE-NOWHERE"], [1, 2, 3])

    def test_different_messages_on_one_line_are_kept(self):
        src = "cur.execute(sql % x); cur.execute(tpl.format(y))\ncur.execute(a % x); cur.execute(b % y)\n"
        got = sorted((i["line"], i["msg"]) for i in core.scan_file("s.py", src, "py") if i["rule"] == "S-SQL-PY")
        self.assertEqual(got, [(1, "SQL query built with %-interpolation into execute()."),
                               (1, "SQL query built with .format()/f-string into execute()."),
                               (2, "SQL query built with %-interpolation into execute().")])

    def test_dedupe_key_is_rule_file_line_msg(self):
        def issue(rule="T-CMD", file="a.py", line=3, msg="m1", snippet=("x",)):
            return {"rule": rule, "file": file, "line": line, "msg": msg, "snippet": list(snippet)}
        first = issue(snippet=("first",))
        kept = core.dedupe_issues([first, issue(snippet=("second",)), issue(msg="m2"), issue(line=4),
                                   issue(file="b.py"), issue(rule="T-CODE"), issue(msg="m2")])
        self.assertIs(kept[0], first)
        self.assertEqual([(i["rule"], i["file"], i["line"], i["msg"]) for i in kept],
                         [("T-CMD", "a.py", 3, "m1"), ("T-CMD", "a.py", 3, "m2"), ("T-CMD", "a.py", 4, "m1"),
                          ("T-CMD", "b.py", 3, "m1"), ("T-CODE", "a.py", 3, "m1")])


class CapTests(unittest.TestCase):
    def test_major_bug_rule_is_capped(self):
        issues = core.scan_file("many.js", MANY_LINES, "js")
        self.assertEqual(count(issues, "B-EMPTY-CATCH"), 200)
        self.assertEqual(capped_msgs(issues), ["800 more B-EMPTY-CATCH findings omitted"])
        (cap,) = [i for i in issues if i["rule"] == "Q-CAPPED"]
        self.assertEqual((cap["line"], cap["sev"], cap["type"]), (201, "INFO", "SMELL"))
        self.assertEqual(cap["why"], "Findings of one rule that repeat hundreds of times in one file are "
                                     "capped so reports stay readable; security findings are never capped.")

    def test_major_python_bug_rule_is_capped(self):
        issues = core.scan_file("e.py", "try:\n    f()\nexcept:\n    pass\n" * 250, "py")
        self.assertEqual(count(issues, "B-EXCEPT-PASS"), 200)
        self.assertEqual(capped_msgs(issues), ["50 more B-BARE-EXCEPT findings omitted",
                                               "50 more B-EXCEPT-PASS findings omitted"])

    def test_security_rules_are_never_capped(self):
        issues = core.scan_file("s.js", "eval(a); eval(b)\n" * 300, "js")
        self.assertEqual(count(issues, "S-EVAL-JS"), 300)
        issues = core.scan_file("d.sql", "DELETE FROM t;\n" * 250, "sql")
        self.assertEqual(count(issues, "SQL-DELETE-NOWHERE"), 250)
        self.assertEqual(capped_msgs(issues), [])

    def test_the_120k_line_variant_stays_small(self):
        issues = core.scan_file("lines.js", "try{}catch(e){}\n" * 120_000, "js")
        self.assertEqual(count(issues, "B-EMPTY-CATCH"), 200)
        self.assertEqual(capped_msgs(issues), ["119800 more B-EMPTY-CATCH findings omitted"])
        self.assertLess(len(json.dumps(issues)), 200_000)                 # was ~67 MB as a report


@dash.requires_node
class DashboardTests(unittest.TestCase):
    """The page's engine applies the same dedupe and cap (field-by-field equal)."""

    def test_same_findings_as_the_cli(self):
        cases = [("one.js", "js", "try{}catch(e){}" * 20_000),
                 ("many.js", "js", MANY_LINES),
                 ("e.py", "py", "try:\n    f()\nexcept:\n    pass\n" * 250),
                 ("d.sql", "sql", "DELETE FROM a; DELETE FROM b; DELETE FROM c;\n" * 3 + "DELETE FROM t;\n" * 250),
                 ("s.py", "py", "cur.execute(sql % x); cur.execute(tpl.format(y))\ncur.execute(a % x); "
                                "cur.execute(b % y)\n")]
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": lang, "content": c}} for n, lang, c in cases])
        for (name, lang, content), got in zip(cases, page):
            with self.subTest(file=name):
                key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
                self.assertEqual(sorted(map(key, got)), sorted(map(key, core.scan_file(name, content, lang))))
        self.assertEqual(count(page[0], "B-EMPTY-CATCH"), 1)
        self.assertEqual(capped_msgs(page[1]), ["800 more B-EMPTY-CATCH findings omitted"])


if __name__ == "__main__":
    unittest.main()
