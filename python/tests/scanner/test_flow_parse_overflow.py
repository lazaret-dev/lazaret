"""The flow engine survives a file that overflows Python's parser.

On Python 3.11, and on Windows (smaller C stack) even on later versions,
ast.parse itself can raise RecursionError on a deep operator chain. That must
cost only that file, with an INFO note, never the whole flow pass. The parser
overflow is simulated so this runs identically on every platform."""

import ast
import unittest
from unittest import mock

from lazaret.scanner import flow as lazaret_flow

HOSTILE = "x = 1" + " + 1" * 50 + "\n"
VICTIM = (
    "from flask import request\n"
    "import os\n"
    "def run():\n"
    "    os.system(request.args['cmd'])\n"
)


class ParserOverflowTests(unittest.TestCase):
    def test_parser_overflow_costs_one_file_with_a_note(self):
        real_parse = ast.parse

        def parse(source, *args, **kwargs):
            if source == HOSTILE:
                raise RecursionError("maximum recursion depth exceeded during ast construction")
            return real_parse(source, *args, **kwargs)

        files = [{"path": "gen/hostile.py", "content": HOSTILE, "lang": "py"},
                 {"path": "app/victim.py", "content": VICTIM, "lang": "py"}]
        with mock.patch.object(lazaret_flow.ast, "parse", side_effect=parse):
            findings = lazaret_flow.analyze(files)   # must not raise
        notes = [f for f in findings if f["rule"] == "Q-FLOW-RECURSION"]
        self.assertEqual([(n["file"], n["line"]) for n in notes], [("gen/hostile.py", 1)])

    def test_only_overflowing_files_still_get_a_note(self):
        files = [{"path": "gen/hostile.py", "content": HOSTILE, "lang": "py"}]
        with mock.patch.object(lazaret_flow.ast, "parse", side_effect=RecursionError):
            findings = lazaret_flow.analyze(files)
        self.assertEqual([f["rule"] for f in findings], ["Q-FLOW-RECURSION"])


if __name__ == "__main__":
    unittest.main()
