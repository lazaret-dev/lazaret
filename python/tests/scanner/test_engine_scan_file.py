"""engine.scan_files and engine.scan_file: which engine scans a file, and
that the answer is core.scan_file's whichever engine gives it.

- With the Python engine, core scans every file.
- With the native engine, it scans the files in dependency mode (Python,
  JavaScript, SQL); core scans the others (project mode) and every file the
  native engine does not answer: an error for that file, or a batch it
  refuses (its work budget spent). The answers come back in the order
  asked.
- Redaction follows core.REDACT_SECRETS, as core's own scan does.

The cases that run the native library skip where it is not built; the
fallbacks are checked with the library mocked, everywhere.
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


def core_answers(items):
    return [core.scan_file(path, text, lang, dep=dep) for path, text, lang, dep in items]


def rules(answers):
    return [sorted(i["rule"] for i in found) for found in answers]


class PythonEngineTests(unittest.TestCase):
    def test_core_scans_every_file(self):
        with mock.patch.object(engine, "_choice", "python"), \
                mock.patch.object(_native, "call", side_effect=AssertionError("the native engine was called")):
            self.assertEqual(engine.scan_files(FILES), core_answers(FILES))

    def test_nothing_to_scan(self):
        self.assertEqual(engine.scan_files([]), [])


class FallbackTests(unittest.TestCase):
    """The native engine mocked: what core answers when it does not."""

    def test_a_file_the_native_engine_answers_with_an_error_is_scanned_by_core(self):
        def answer(call, args):
            return [{"error": "internal"} for _ in args["calls"]]
        with mock.patch.object(engine, "name", lambda: "rust"), mock.patch.object(_native, "call", side_effect=answer):
            self.assertEqual(engine.scan_files(FILES), core_answers(FILES))

    def test_a_batch_the_native_engine_refuses_is_scanned_by_core(self):
        with mock.patch.object(engine, "name", lambda: "rust"), \
                mock.patch.object(_native, "call", side_effect=_native.NativeExhausted("work budget spent")):
            self.assertEqual(engine.scan_files(FILES), core_answers(FILES))

    def test_only_dependency_files_are_sent(self):
        sent = []

        def answer(call, args):
            sent.extend(args["calls"])
            return [{"error": "internal"} for _ in args["calls"]]
        with mock.patch.object(engine, "name", lambda: "rust"), mock.patch.object(_native, "call", side_effect=answer):
            engine.scan_files(FILES)
        self.assertEqual([text for _call, _args, text in sent], [f[1] for f in FILES if f[3]])
        for name, args, _text in sent:
            self.assertEqual(name, "scan_file")
            self.assertTrue(args["dep"])
            self.assertEqual(args["redact"], bool(core.REDACT_SECRETS))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeEngineTests(unittest.TestCase):
    def native(self, items):
        with mock.patch.object(engine, "_choice", "rust"):
            return engine.scan_files(items)

    def test_the_answers_are_cores_in_order(self):
        got = self.native(FILES)
        self.assertEqual(got, core_answers(FILES))
        self.assertIn("SC-EVAL-DECODE", rules(got)[0])
        self.assertIn("S-TOKEN", rules(got)[1])

    def test_more_files_than_a_batch(self):
        items = [(f"pkg/{k}.py", f"K{k} = '{AWS}'\n", "py", True) for k in range(engine.BATCH + 3)]
        self.assertEqual(self.native(items), core_answers(items))

    def test_redaction_follows_core(self):
        for redact in (True, False):
            with self.subTest(redact=redact), mock.patch.object(core, "REDACT_SECRETS", redact):
                got = self.native(FILES[1:2])
                self.assertEqual(got, core_answers(FILES[1:2]))
                shown = "\n".join(line for i in got[0] for line in i["snippet"])
                self.assertEqual(AWS in shown, not redact)

    def test_scan_file_is_a_batch_of_one(self):
        path, text, lang, dep = FILES[0]
        with mock.patch.object(engine, "_choice", "rust"):
            self.assertEqual(engine.scan_file(path, text, lang, dep=dep), core.scan_file(path, text, lang, dep=dep))


if __name__ == "__main__":
    unittest.main()
