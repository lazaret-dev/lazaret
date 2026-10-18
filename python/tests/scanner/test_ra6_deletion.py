"""RA-6: inert source strings only; no fragment is run or compiled."""
import json
from pathlib import Path
import unittest
from lazaret.scanner import _native

REASON = "deletes the user's files"
CASES = json.loads((Path(__file__).resolve().parents[3] / "tests/fixtures/ra6-deletion.json").read_text(encoding="utf-8"))

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

    def test_own_folder_paths_and_source_shapes(self):
        fixture = json.loads((Path(__file__).resolve().parents[3] / "tests/fixtures/ra6-own-folders.json").read_text(encoding="utf-8"))
        for case in fixture["paths"]:
            path = case["path"]
            # Source strings only. Home is resolved by the model, not this machine.
            if path.startswith("~"):
                js_path = "require('os').homedir()+" + json.dumps(path[1:])
                py_path = "os.path.expanduser('~')+" + json.dumps(path[1:])
            else:
                js_path = py_path = json.dumps(path)
            texts = [("js", "require('fs').rmSync(" + js_path + ",{recursive:true});"),
                     ("py", "import os,shutil\nshutil.rmtree(" + py_path + ")")]
            for lang, text in texts:
                with self.subTest(path=path, lang=lang):
                    reasons = _native.call("install_script_risk", {"lang":lang}, text)
                    self.assertEqual(REASON in reasons, case["found"], reasons)
                    if case["found"]:
                        from lazaret.scanner import core
                        self.assertEqual(core.install_script_severity(reasons), "CRITICAL")
        for case in fixture["sources"]:
            with self.subTest(source=case["name"]):
                args = {"lang":case["lang"]}
                reasons = _native.call("install_script_risk", args, case["text"])
                self.assertEqual(REASON in reasons, case["found"], reasons)
                if case["found"]:
                    self.assertEqual(_native.call("install_script_severity", {"reasons":reasons}), "CRITICAL")
                reasons, line = _native.call("import_time_risk", args, case["text"])
                self.assertEqual(REASON in reasons, case["found"], (reasons,line))
                if "line" in case:
                    self.assertEqual(line, case["line"], (reasons,line))

    def test_listing_work_is_bounded(self):
        text="const fs=require('fs'),path=require('path');const D=require('os').homedir()+'/.tool/state';\n"
        text+="fs.readdirSync(D).map(n=>fs.rmSync(path.join(D,n),{recursive:true}));\n"*1600
        text+="fs.rmSync(require('os').homedir()+'/Documents',{recursive:true});"
        self.assertIn(REASON,_native.call("install_script_risk",{"lang":"js"},text))
        cyclic="const fs=require('fs'),path=require('path');const D=path.join(require('os').homedir(),'.tool',name);const names=fs.readdirSync(D);const name=names[i];fs.rmSync(D,{recursive:true});"
        self.assertIn(REASON,_native.call("install_script_risk",{"lang":"js"},cyclic))

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
