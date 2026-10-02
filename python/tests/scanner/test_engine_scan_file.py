"""engine.scan_files and engine.scan_file: the native engine scans the files
in dependency mode (Python, JavaScript, SQL), and the first part of the
others (project mode: its scan_rules), after which core runs the passes that
follow, the markers and the cap (core.scan_file_after_rules). A file the
engine cannot answer is SC-TRUNCATED, which fails the gate: EXHAUSTED when
it spent its work budget, "its scan failed" on an internal error. The
answers come back in the order asked, and redaction follows
core.REDACT_SECRETS.

What is sent, and what an unanswered file becomes, are checked with the
library mocked; the findings, with the library (skipped where it is not
built).
"""
import unittest
from unittest import mock

from lazaret.scanner import _native, core, engine

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"               # a fake key, built so no scanner takes it for a real one
FILES = [
    ("pkg/decode.js", "const p = Buffer.from(x, 'base64').toString();\neval(p);\n", "js", True),
    ("pkg/key.py", f"KEY = '{AWS}'\nprint(KEY)\n", "py", True),
    ("app/own.py", f"KEY = '{AWS}'\nimport os\nos.system(input())\n", "py", False),     # project mode
    ("pkg/q.sql", f"SELECT 1; -- {AWS}\n", "sql", True),
    ("pkg/empty.js", "", "js", True),
]


def one_by_one(items):
    return [engine.scan_file(path, text, lang, dep=dep) for path, text, lang, dep in items]


def rules(answers):
    return [sorted(i["rule"] for i in found) for found in answers]


REAL_CALL = _native.call


def answering(item):
    """A mocked _native.call whose batches answer each call with `item` (the
    calls sent are kept in .sent); any other call goes to the library."""
    def call(name, args, text=None):
        if name != "batch":
            return REAL_CALL(name, args, text)
        call.sent.extend(args["calls"])
        return [dict(item) for _ in args["calls"]]
    call.sent = []
    return call


class CallTests(unittest.TestCase):
    """The native library mocked."""

    def test_nothing_to_scan(self):
        with mock.patch.object(_native, "call") as call:
            self.assertEqual(engine.scan_files([]), [])
        call.assert_not_called()

    def test_what_each_file_is_sent_as(self):
        call = answering({"ok": []})
        with mock.patch.object(_native, "call", side_effect=call), \
                mock.patch.object(core, "scan_file_after_rules", lambda path, content, lang, found: found):
            engine.scan_files(FILES)
        self.assertEqual([text for _call, _args, text in call.sent], [f[1] for f in FILES])
        for (name, args, _text), (_path, _t, lang, dep) in zip(call.sent, FILES):
            self.assertEqual(name, "scan_file" if dep else "scan_rules")
            self.assertEqual(args["dep"], dep)
            self.assertEqual(args["lang"], lang)
            self.assertEqual(args["redact"], bool(core.REDACT_SECRETS))
            self.assertIs(args["neumaier"], False)

    def test_a_file_that_spends_the_work_budget_is_truncated(self):
        deps = [f for f in FILES if f[3]]
        with mock.patch.object(_native, "call", side_effect=answering({"error": "exhausted", "exhausted": True})):
            got = engine.scan_files(deps)
        self.assertEqual(rules(got), [["SC-TRUNCATED"]] * len(deps))
        for found in got:
            self.assertIn(engine.EXHAUSTED, found[0]["msg"])
            self.assertEqual(found[0]["sev"], "CRITICAL")

    def test_a_file_the_engine_fails_on_is_truncated(self):
        with mock.patch.object(_native, "call", side_effect=answering({"error": "panic", "panic": True})):
            got = engine.scan_files(FILES[:1])
        self.assertEqual(rules(got), [["SC-TRUNCATED"]])
        self.assertIn("its scan failed (NativeError)", got[0][0]["msg"])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeEngineTests(unittest.TestCase):
    def test_the_answers_in_order(self):
        got = engine.scan_files(FILES)
        self.assertEqual(got, one_by_one(FILES))
        self.assertIn("SC-EVAL-DECODE", rules(got)[0])
        self.assertIn("S-TOKEN", rules(got)[1])
        self.assertEqual(rules(got)[2], ["S-OSCMD-PY", "S-TOKEN", "T-CMD"])   # (project mode: the engine's rules, core's taint)
        self.assertEqual(got[4], [])

    def test_more_files_than_a_batch(self):
        items = [(f"pkg/{k}.py", f"K{k} = '{AWS}'\n", "py", True) for k in range(engine.BATCH + 3)]
        got = engine.scan_files(items)
        self.assertEqual(got, one_by_one(items))
        self.assertEqual([path for found in got for path in {i["file"] for i in found}], [p for p, *_ in items])

    def test_redaction_follows_core(self):
        for redact in (True, False):
            with self.subTest(redact=redact), mock.patch.object(core, "REDACT_SECRETS", redact):
                got = engine.scan_files(FILES[1:2])
                shown = "\n".join(line for i in got[0] for line in i["snippet"])
                self.assertEqual(AWS in shown, not redact)

    def test_in_project_mode_the_passes_that_follow_still_run(self):
        with mock.patch.object(_native, "call", side_effect=answering({"error": "exhausted", "exhausted": True})):
            got = engine.scan_files(FILES[2:3])
        self.assertEqual(rules(got), [["SC-TRUNCATED", "T-CMD"]])

    def test_core_scan_file_is_the_engines(self):
        path, text, lang, dep = FILES[0]
        self.assertEqual(core.scan_file(path, text, lang, dep=dep), engine.scan_files([FILES[0]])[0])


if __name__ == "__main__":
    unittest.main()
