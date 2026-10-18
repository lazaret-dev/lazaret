"""RA-6: inert source strings only; no fragment is run or compiled."""
import json
from pathlib import Path
import unittest
from lazaret.scanner import _native

REASON = "deletes the user's files"
CASES = json.loads((Path(__file__).resolve().parents[3] / "tests/fixtures/ra6-deletion.json").read_text())

class DeletionTests(unittest.TestCase):
    def test_shared_paths_and_cleanup(self):
        for case in CASES:
            with self.subTest(case=case):
                args = {"lang": case["lang"], "command": case["command"]}
                reasons = _native.call("install_script_risk", args, case["text"])
                self.assertEqual(REASON in reasons, case["found"], reasons)
                if case["lang"] != "sh":
                    reasons, line = _native.call("import_time_risk", args, case["text"])
                    self.assertEqual(REASON in reasons, case["found"], (reasons,line))

    def test_alias_expansion_is_bounded(self):
        # A tiny alias DAG must not expand exponentially. No source is executed.
        py = 'import shutil, os\np0 = os.getenv("HOME")\n'
        js = 'const fs=require("fs"); const p0=process.env.HOME;\n'
        for i in range(1, 10):
            expr = '+'.join([f'p{i-1}']*32)
            py += f'p{i}={expr}\n'
            js += f'const p{i}={expr};\n'
        for lang, text in [('py',py+'shutil.rmtree(p9)'),('js',js+'fs.rmSync(p9,{recursive:true});')]:
            _native.call("install_script_risk", {"lang":lang}, text)

if __name__ == "__main__":
    unittest.main()
