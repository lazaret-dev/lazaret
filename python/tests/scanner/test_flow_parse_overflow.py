"""The flow engine survives a file that overflows the parser.

A deep enough operator chain overflows Python's parser (its stack: "too
complex to parse"); the engine's parser refuses the same, the same way on
every platform. That must cost only that file, with an INFO note, never the
whole flow pass."""

import unittest

from lazaret.scanner import flow as lazaret_flow

HOSTILE = "x = " + "-" * 6000 + "1\n"
VICTIM = (
    "from flask import request\n"
    "import os\n"
    "def run(c):\n"
    "    os.system(c)\n"
    "def view():\n"
    "    run(request.args['cmd'])\n"
)


class ParserOverflowTests(unittest.TestCase):
    def test_parser_overflow_costs_one_file_with_a_note(self):
        files = [{"path": "gen/hostile.py", "content": HOSTILE, "lang": "py"},
                 {"path": "app/victim.py", "content": VICTIM, "lang": "py"}]
        findings = lazaret_flow.analyze(files)   # must not raise
        notes = [f for f in findings if f["rule"] == "Q-FLOW-RECURSION"]
        self.assertEqual([(n["file"], n["line"]) for n in notes], [("gen/hostile.py", 1)])
        self.assertEqual([(f["rule"], f["file"], f["line"]) for f in findings if f["rule"].startswith("X-")],
                         [("X-CMD", "app/victim.py", 6)])

    def test_only_overflowing_files_still_get_a_note(self):
        files = [{"path": "gen/hostile.py", "content": HOSTILE, "lang": "py"}]
        findings = lazaret_flow.analyze(files)
        self.assertEqual([f["rule"] for f in findings], ["Q-FLOW-RECURSION"])


if __name__ == "__main__":
    unittest.main()
