"""Review fix: where a manifest's JSON syntax error is, the same on every Python.

A root package.json with a trailing comma,

    {
      "name": "app",
      "version": "1.0.0",
    }

was SC-MANIFEST-UNPARSEABLE "(JSONDecodeError: line 3 column 21)" on Python
3.13/3.14, which report the comma, and "(... line 4 column 1)" on 3.10-3.12
and in the npm engine, which report the bracket after it. The comma it is
now on every Python (core.json_error_where) and in npm (pyjson.js); both
CLIs are compared in tests/architecture/test_js_parity_lexing.py.
"""
import json
import unittest

from tests import _support  # noqa: F401  (puts src/ on sys.path)
from lazaret.scanner import core

AUDIT = '{\n  "name": "app",\n  "version": "1.0.0",\n}\n'
# (text, where Python 3.13+ reports the error)
CASES = [
    ('{"a": 1,}', "line 1 column 8"),
    ('{"a": 1,\n}', "line 1 column 8"),
    ("[1, ]", "line 1 column 3"),
    ("[1,\n\t\r ]", "line 1 column 3"),
    ('{"a": [[],]}', "line 1 column 10"),
    # not a trailing comma: where every Python reports it
    ('{"a": 1,]', "line 1 column 9"),
    ("[1,}", "line 1 column 4"),
    ("[1,,]", "line 1 column 4"),
    ("{,}", "line 1 column 2"),
    ("[1,\f]", "line 1 column 4"),
    ('{"a": 1,', "line 1 column 9"),
]


class JsonErrorPositionTests(unittest.TestCase):
    def test_trailing_comma_in_a_root_manifest(self):
        data, issues = core.load_manifest("package.json", AUDIT)
        self.assertIsNone(data)
        self.assertEqual([(i["rule"], i["msg"]) for i in issues], [(
            "SC-MANIFEST-UNPARSEABLE", "package.json could not be parsed (JSONDecodeError: line 3 column 21); "
                                       "its install hooks could not be checked.")])

    def test_a_trailing_comma_is_at_the_comma(self):
        for text, where in CASES:
            with self.subTest(text=text):
                with self.assertRaises(json.JSONDecodeError) as cm:
                    json.loads(text)
                self.assertEqual(core.json_error_where(cm.exception), where)


if __name__ == "__main__":
    unittest.main()
