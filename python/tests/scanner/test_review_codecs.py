"""Review fix: a coding cookie decodes to the same text in both packages.

The npm engine and the dashboard decoded a cookie's codec with the runtime's
TextDecoder, which has no label for 63 of the codecs Python decodes (cp037,
cp500, cp437, cp850, the mac_* family, utf-32, unicode-escape, …): they
reported "detected cp037" and then read the file as UTF-8, so
`# coding: cp037` + `x = eval(input())` gave S-EVAL-PY / T-CODE in npm only.
Where a label existed, its table was not always Python's (cp1252's undefined
bytes, cp866, tis-620; no ISO-8859-16 at all). The fix gave npm Python's
single-byte tables and read any codec it could not decode exactly as UTF-8
in both packages, with SC-TRUNCATED.

Since BR-7 step 4 (b) the engine decodes for both packages, every text codec
Python has, as Python decodes it (tests/architecture/test_decode_engine.py
holds it to Python's codecs); its tables are written by
scripts/make_codec_tables.py (checked current here). Since BR-7 step 5 the
dashboard runs the engine too. All input is inert.
"""
import os
import unittest

from tests import _support
from lazaret.scanner import core

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_codec_tables.py")
class GeneratedTablesTests(unittest.TestCase):
    def test_generated_codec_module_is_current(self):
        gen = _support.load_script(SCRIPT, "make_codec_tables")
        self.assertEqual(gen.main(["--check"]), 0, "run python3 scripts/make_codec_tables.py")


class FindingsTests(unittest.TestCase):
    def test_findings(self):
        """The review's case, a codec read as UTF-8 before BR-7 step 4 (b), and one that still is."""
        text, info = core.decode_source(b"# coding: cp037\nprint(1)\nx = eval(input())\n", "py")
        issues = core.encoding_issues("e.py", text, info) + core.scan_file("e.py", text, "py")
        self.assertEqual([i["rule"] for i in issues], ["Q-ENCODING"])      # EBCDIC-decoded: no eval
        data = "# coding: euc_jis_2004\n# 漢字\nx = eval(y)\n".encode("euc_jis_2004")
        text, info = core.decode_source(data, "py")
        self.assertEqual(text, data.decode("euc_jis_2004"))
        issues = core.encoding_issues("j.py", text, info) + core.scan_file("j.py", text, "py")
        self.assertEqual(sorted(i["rule"] for i in issues), ["Q-ENCODING", "S-EVAL-PY"])
        text, info = core.decode_source(b"# coding: idna\nx = eval(y)\n", "py")
        issues = core.encoding_issues("i.py", text, info) + core.scan_file("i.py", text, "py")
        self.assertEqual(sorted(i["rule"] for i in issues), ["Q-ENCODING", "S-EVAL-PY", "SC-TRUNCATED"])
        (trunc,) = [i for i in issues if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(trunc["msg"], "File not fully scanned: its source encoding (idna) is not decoded "
                                       "by Lazaret; the file was read as UTF-8.")


if __name__ == "__main__":
    unittest.main()
