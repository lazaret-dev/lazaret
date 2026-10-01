"""scan_file in project mode as the Python package runs it with the native
engine (engine.scan_files: the native engine's scan_rules, then core's
passes — the SQL statements without WHERE, taint, the SQL-sink pass, the
function metrics — its suppression markers and its cap, through
core.scan_file_after_rules) against core.scan_file alone, file for file and
finding for finding. The files are the scan_file corpus and a share of the
dependency-mode test's real files (test_rust_parity_scanfile), read as your
own. Skipped where the native library is not built.
"""
import unittest
from unittest import mock

from lazaret.scanner import _native, core, engine
from tests.architecture.scanfile_corpus import corpus
from tests.architecture.test_rust_parity_scanfile import jsonable, lang_of, real_files


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ProjectScanThroughTheEngineTests(unittest.TestCase):
    maxDiff = None

    def test_each_file_scans_as_core_scans_it(self):
        cases = [(path, text) for path, text in corpus() + real_files()[::3] if lang_of(path) in ("py", "js", "sql")]
        self.assertGreater(len(cases), 200)
        engine.choose("rust")
        try:
            got = engine.scan_files([(path, text, lang_of(path), False) for path, text in cases])
        finally:
            engine.choose(None)
        differ = []
        for (path, text), issues in zip(cases, got):
            want = jsonable(core.scan_file(path, text, lang_of(path)))
            if jsonable(issues) != want:
                differ.append(path)
        self.assertEqual(differ[:5], [])

    def test_a_file_the_engine_cannot_answer_is_scanned_by_core(self):
        path, text = "app.py", "import os\nos.system(input())  # TODO: check\n" + "x = 1\n" * 50
        engine.choose("rust")
        try:
            with mock.patch.object(engine, "_batch_calls", return_value=[None]) as asked:
                got = engine.scan_files([(path, text, "py", False)])[0]
        finally:
            engine.choose(None)
        self.assertEqual(asked.call_args[0][0][0][0], "scan_rules")
        self.assertEqual(jsonable(got), jsonable(core.scan_file(path, text, "py")))
        self.assertIn("Q-TODO", {i["rule"] for i in got})


if __name__ == "__main__":
    unittest.main()
