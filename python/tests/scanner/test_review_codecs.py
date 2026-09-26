"""Review fix: a coding cookie decodes to the same text in both engines.

The npm engine and the dashboard decoded a cookie's codec with the runtime's
TextDecoder, which has no label for 63 of the codecs Python decodes (cp037,
cp500, cp437, cp850, the mac_* family, utf-32, unicode-escape, …): they
reported "detected cp037" and then read the file as UTF-8, so
`# coding: cp037` + `x = eval(input())` gave S-EVAL-PY / T-CODE in npm only.
(unicode-escape and raw-unicode-escape now decode in both engines too: see
test_review_escape_codecs.py.)
Where a label existed, its table was not always Python's (cp1252's undefined
bytes, cp866, tis-620; no ISO-8859-16 at all). Now:

* single-byte codecs decode with Python's own tables, generated into
  js/src/lib/codecs.js by scripts/make_codec_tables.py (checked current here);
* a codec the npm engine cannot decode exactly as Python does is read as
  UTF-8 by both engines, with Q-ENCODING and SC-TRUNCATED (not fully
  scanned) — no silent fallback;
* cookie names only newer Pythons know (windows-874, windows-31j, …) and
  palmos (its 0x9B changed in 3.13) resolve the same on every Python.

The multi-byte codecs with a TextDecoder label (Shift_JIS, EUC-*, GBK, Big5,
…) still decode with it: their text can differ from Python's for bytes
outside the codec's own repertoire. All input is inert.
"""
import base64
import json
import os
import shutil
import subprocess
import unittest

from tests import _support
from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

NODE = shutil.which("node")
SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_codec_tables.py")
ENCODING_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "encoding.js")
# every byte once, after the cookie line (NUL-free up front: no UTF-16 sniff)
BODY = bytes(b for b in range(256) if b not in (0x0a, 0x0d)) + b"\n"
NPM_DECODE = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { decodeSource } = await import(pathToFileURL(process.argv[1]).href);
const out = JSON.parse(readFileSync(0, "utf8")).map((b64) => decodeSource(Buffer.from(b64, "base64"), { py: true }));
process.stdout.write(JSON.stringify(out));
"""


def cookie_file(name):
    return f"# coding: {name}\n".encode("ascii") + BODY


def core_view(data):
    text, info = core.decode_source(data, "py")
    return {"text": text, "encoding": info["encoding"], "reported": info["reported"],
            "utf7": info["utf7"], "cookieLine": info["cookieLine"], "undecoded": bool(info.get("undecoded")),
            "escapes": bool(info.get("escapes"))}


def js_view(r):
    return {"text": core.normalize_newlines(r["text"]), "encoding": r["encoding"], "reported": r["reported"],
            "utf7": r["utf7"], "cookieLine": r["cookieLine"], "undecoded": bool(r.get("undecoded")),
            "escapes": bool(r.get("escapes"))}


def aliases():
    """{codec: [names]} as the generator writes it."""
    return _support.load_script(SCRIPT, "make_codec_tables").codec_aliases(core)


class GeneratedTablesTests(unittest.TestCase):
    def test_generated_codec_module_is_current(self):
        gen = _support.load_script(SCRIPT, "make_codec_tables")
        self.assertEqual(gen.main(["--check"]), 0, "run python3 scripts/make_codec_tables.py")

    def test_resolution_is_the_same_on_every_python(self):
        for name, codec in (("windows-874", "cp874"), ("MS874", "cp874"), ("windows_31j", "cp932"),
                            ("csEUCKR", "euc_kr"), ("ISO-8859-8-I", "iso8859-8"), ("mbcs", None),
                            ("dbcs", None), ("oem", None)):
            with self.subTest(name=name):
                self.assertEqual(core._normal_codec(name), codec)
        text, _ = core.decode_source(b"# coding: palmos\ns = '\x9b'\n", "py")
        self.assertIn("›", text)          # 3.13+'s mapping, on every version


class EngineCodecParityTests(unittest.TestCase):
    """Every codec a cookie can name (and each of its spellings), through
    core.decode_source, the npm engine's decodeSource and the dashboard's."""

    @classmethod
    def setUpClass(cls):
        cls.cases = []                         # (codec, spelling)
        for codec, names in aliases().items():
            for name in dict.fromkeys([codec] + names[:3]):
                cls.cases.append((codec, name))
        cls.data = [cookie_file(name) for _, name in cls.cases]

    def check(self, got):
        self.assertEqual(len(got), len(self.cases))
        textdecoder = 0
        for (codec, name), data, page in zip(self.cases, self.data, got):
            with self.subTest(codec=codec, name=name):
                want = core_view(data)
                have = js_view(page)
                if codec in core._TEXTDECODER_CODECS:       # the known residual (see the docstring)
                    textdecoder += 1
                    want.pop("text")
                    have.pop("text")
                self.assertEqual(have, want)
        self.assertLess(textdecoder, len(self.cases) // 3)

    @unittest.skipUnless(NODE, "node is not installed")
    def test_npm_engine(self):
        p = subprocess.run([NODE, "--input-type=module", "-e", NPM_DECODE, ENCODING_JS],
                           input=json.dumps([base64.b64encode(d).decode("ascii") for d in self.data]),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        self.check(json.loads(p.stdout))

    @dash.requires_node
    def test_dashboard(self):
        exprs = [{"op": "eval", "expr": f"decodeSource(new Uint8Array({list(d)}), {{py: true}})"} for d in self.data]
        self.check(dash.run(exprs))

    def test_findings(self):
        """The review's case, and a codec neither engine decodes."""
        text, info = core.decode_source(b"# coding: cp037\nprint(1)\nx = eval(input())\n", "py")
        issues = core.encoding_issues("e.py", text, info) + core.scan_file("e.py", text, "py")
        self.assertEqual([i["rule"] for i in issues], ["Q-ENCODING"])      # EBCDIC-decoded: no eval
        text, info = core.decode_source(b"# coding: utf-32\nx = eval(y)\n", "py")
        issues = core.encoding_issues("u.py", text, info) + core.scan_file("u.py", text, "py")
        self.assertEqual(sorted(i["rule"] for i in issues), ["Q-ENCODING", "S-EVAL-PY", "SC-TRUNCATED"])
        (trunc,) = [i for i in issues if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(trunc["msg"], "File not fully scanned: its source encoding (utf-32) is not decoded "
                                       "by Lazaret; the file was read as UTF-8.")


if __name__ == "__main__":
    unittest.main()
