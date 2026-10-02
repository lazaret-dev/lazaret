"""The analyst's smaller gaps, closed in both engines (and the dashboard).

* `.mts` / `.cts` TypeScript sources were not read (Node 23 runs them;
  ts-node, tsx, bun and deno always did); they are JavaScript-family sources
  now, read without JSX like `.ts`. A camera's `.mts` video (an MPEG
  transport stream, as a `.ts` can be) is media, not source.
* `.jsc` (V8 bytecode, bytenode) was nothing; it is a compiled artifact
  (SC-BINARY) like `.pyc` or `.node`.
* `__import__("os").system(…)` was not S-OSCMD-PY.
* A dangerous name hidden with fewer than eight escapes was not SC-HEXSTR:
  global["\\x72\\x65\\x71\\x75\\x69\\x72\\x65"]("child_process") spells require in 7.

The npm engine: js/test/review-small-gaps.test.js;
tests/architecture/test_js_parity.py (the adversarial tree) compares the
packages, and test_snapshot_small.py holds the engine's hidden names to its
recorded outputs. Fixtures are inert text.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry._review_support import issues, scan_npm

#: an MPEG transport stream: a sync byte (0x47) every 188 bytes
VIDEO = b"".join(b"\x47" + bytes((k * 7 + n) % 256 for n in range(187)) for k in range(40))


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-gaps-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


class ProjectTests(unittest.TestCase):
    FILES = {
        "src/a.mts": "const el = <HTMLInputElement>document.body;\n// eval(z)\neval(atob(p));\n",
        "src/b.cts": "const cp = require('child_process');\ncp.exec(process.argv[2]);\n",
        "media/clip.mts": VIDEO,
        "media/clip.ts": VIDEO,
        "dist/app.jsc": b"\x00\x01bytenode\x02" * 10,
        "tool.py": "__import__('os').system(input())\nimportlib.import_module('os').popen(cmd)\n",
        "hide.js": 'var m = global["\\x72\\x65\\x71\\x75\\x69\\x72\\x65"]("child_process");\n'
                   'var u = "https:\\u002F\\u002Fexample.invalid";\n'
                   'var b = "\\x00\\x01\\x65val";\n',
    }

    @classmethod
    def setUpClass(cls):
        cls.root = make_tree(cls.FILES)
        cls.res = core.scan_project(cls.root)
        cls.found = {(i["rule"], i["file"].replace(os.sep, "/"), i["line"]) for i in cls.res["issues"]}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_mts_and_cts_are_typescript(self):
        self.assertIn(("S-EVAL-JS", "src/a.mts", 3), self.found)
        self.assertIn(("SC-EVAL-DECODE", "src/a.mts", 3), self.found)
        self.assertNotIn(("S-EVAL-JS", "src/a.mts", 2), self.found)       # a comment, read without JSX
        self.assertIn(("T-CMD", "src/b.cts", 2), self.found)
        self.assertEqual(core.EXTS[".mts"], core.EXTS[".cts"], "js")
        self.assertFalse(core.jsx_reading("x.MTS") or core.jsx_reading("x.cts"))

    def test_a_video_is_not_source(self):
        self.assertFalse({f for _, f, _ in self.found} & {"media/clip.mts", "media/clip.ts"}, self.found)
        self.assertEqual(self.res["metrics"]["files"], 4)                  # a.mts, b.cts, tool.py, hide.js
        saved = core.SOURCE_SIZE_CAP
        core.SOURCE_SIZE_CAP = 1000                                         # a big video is not SC-TRUNCATED
        try:
            res = core.scan_project(self.root)
        finally:
            core.SOURCE_SIZE_CAP = saved
        self.assertNotIn("media/clip.mts", {i["file"].replace(os.sep, "/") for i in res["issues"]})

    def test_jsc_is_a_compiled_artifact(self):
        (jsc,) = [i for i in self.res["issues"] if i["file"].replace(os.sep, "/") == "dist/app.jsc"]
        self.assertEqual((jsc["rule"], jsc["sev"], jsc["msg"]),
                         ("SC-BINARY", "MAJOR", "Executable/compiled binary in the source tree: compiled artifact (.jsc)."))

    def test_an_inline_os_import(self):
        self.assertIn(("S-OSCMD-PY", "tool.py", 1), self.found)
        self.assertIn(("S-OSCMD-PY", "tool.py", 2), self.found)

    def test_a_name_hidden_in_a_few_escapes(self):
        (hex_,) = [i for i in self.res["issues"] if i["rule"] == "SC-HEXSTR"]
        self.assertEqual((hex_["file"], hex_["line"], hex_["sev"], hex_["msg"]),
                         ("hide.js", 1, "CRITICAL", "Escape sequences hide a name: 'require'."))


class HiddenNameTests(unittest.TestCase):
    def test_names(self):
        cases = {
            'x = "\\x65val"': ("eval", 5), 'x = "sy\\x73tem"': ("system", 7), "s = '\\145val'": ("eval", 5),
            'w["\\u{65}v\\u0061l"](x)': ("eval", 3), 'p = "\\U00000065xec"': ("exec", 5),
            'u = "\\u0068ttps://example.invalid"': ("https://", 5), 'k = "\\x5f_import__"': ("__import__", 5),
            'x = "\\\\\\x65val"': ("eval", 7), "a = '\\x00\\x00\\x00'; b = '\\x65val'": ("eval", 25),
            'x = "\\x65val" # \\x41': ("eval", 5), 'x = `\\x63url -s x`': ("curl", 5),
        }
        for line, want in cases.items():
            with self.subTest(line=line):
                self.assertEqual(core.hex_hidden_name(line), want)

    def test_not_names(self):
        for line in ('x = "\\\\x65val"', 'u = "https:\\u002F\\u002Fexample.invalid"', 'b = b"\\x00\\x01\\x65val"',
                     'x = "\\x41PI system"', 'x = "e\\x76al_thing"', 'x = "\\x65"; y = "val"', 'x = "\\u00e9val"',
                     'x = "\\U0001F600\\x65val"', "x = eval", 'x = "a\\x2fb"', "\\x65val"):
            with self.subTest(line=line):
                self.assertIsNone(core.hex_hidden_name(line))

    def test_eight_escapes_keep_their_finding(self):
        line = 'x = "\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f"'
        (hex_,) = [i for i in core.scan_file("x.js", line + "\n", "js") if i["rule"] == "SC-HEXSTR"]
        self.assertEqual(hex_["msg"], "Hex escapes hide readable text: 'eval(ato'.")


class RegistryTests(unittest.TestCase):
    def test_an_mts_member_is_source_and_a_video_member_is_not(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "index.mts"}),
                        "index.mts": "eval(atob('Y29uc29sZS5sb2coMSk='));\n"})
        self.assertIn("index.mts", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        with mock.patch.object(repo, "MAX_MEMBER", 4096):                  # a video over the limit
            res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0"}),
                            "media/clip.mts": VIDEO * 3, "media/clip.ts": VIDEO * 3})
        self.assertEqual(issues(res, "SC-TRUNCATED"), [])
        self.assertNotEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        _text, extra = core.decode_member("clip.mts", VIDEO)
        self.assertEqual(extra, [])

    def test_a_jsc_member_is_a_binary(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0"}),
                        "lib/app.jsc": b"\xc0\xde\x0b\x0f" + bytes(range(256)) * 4})     # V8 code cache: binary
        self.assertEqual([i["file"] for i in issues(res, "SC-BINARY")], ["lib/app.jsc"])


if __name__ == "__main__":
    unittest.main()
