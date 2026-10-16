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
scripts/make_codec_tables.py (checked current here), which also writes the
dashboard's copy of the single-byte ones. The dashboard decodes as npm did
until it runs the engine (BR-7 step 5): it is checked here on the codecs it
decodes. All input is inert.
"""
import os
import unittest

from tests import _support
from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_codec_tables.py")
# every byte once, after the cookie line (NUL-free up front: no UTF-16 sniff)
BODY = bytes(b for b in range(256) if b not in (0x0a, 0x0d)) + b"\n"
#: the multi-byte codecs the dashboard decodes with the runtime's TextDecoder: its text can differ from Python's for
#: bytes outside the codec's repertoire (the residual it had, as npm had, until it runs the engine)
TEXTDECODER_CODECS = frozenset((
    "utf-16", "utf-16-le", "utf-16-be", "shift_jis", "cp932", "euc_jp", "iso2022_jp",
    "gbk", "gb2312", "cp936", "gb18030", "big5", "cp950", "euc_kr", "cp949"))


def cookie_file(name):
    return f"# coding: {name}\n".encode("ascii") + BODY


def core_view(data):
    text, info = core.decode_source(data, "py")
    return {"text": text, "encoding": info["encoding"], "reported": info["reported"],
            "utf7": info["utf7"], "cookieLine": info["cookieLine"], "undecoded": bool(info.get("undecoded")),
            "escapes": bool(info.get("escapes"))}


def page_view(r):
    return {"text": core.normalize_newlines(r["text"]), "encoding": r["encoding"], "reported": r["reported"],
            "utf7": r["utf7"], "cookieLine": r["cookieLine"], "undecoded": bool(r.get("undecoded")),
            "escapes": bool(r.get("escapes"))}


def aliases():
    """{codec: [names]} as the generator writes it."""
    return _support.load_script(SCRIPT, "make_codec_tables").codec_aliases()


class GeneratedTablesTests(unittest.TestCase):
    def test_generated_codec_module_is_current(self):
        gen = _support.load_script(SCRIPT, "make_codec_tables")
        self.assertEqual(gen.main(["--check"]), 0, "run python3 scripts/make_codec_tables.py")


class DashboardCodecTests(unittest.TestCase):
    """Every codec a cookie can name (and each of its spellings) that the dashboard decodes, through
    core.decode_source and the dashboard's decodeSource (until the dashboard runs the engine: BR-7 step 5)."""

    @classmethod
    def setUpClass(cls):
        gen = _support.load_script(SCRIPT, "make_codec_tables")
        single = gen.single_byte_tables(aliases())
        decoded = set(single) | TEXTDECODER_CODECS | {"utf-7", "ascii", "iso8859-1", "unicode-escape",
                                                      "raw-unicode-escape"}
        cls.cases = []                         # (codec, spelling)
        for codec, names in aliases().items():
            if codec in decoded:
                for name in dict.fromkeys([codec] + names[:3]):
                    cls.cases.append((codec, name))
        cls.data = [cookie_file(name) for _, name in cls.cases]

    @dash.requires_node
    def test_dashboard(self):
        exprs = [{"op": "eval", "expr": f"decodeSource(new Uint8Array({list(d)}), {{py: true}})"} for d in self.data]
        got = dash.run(exprs)
        self.assertEqual(len(got), len(self.cases))
        for (codec, name), data, page in zip(self.cases, self.data, got):
            with self.subTest(codec=codec, name=name):
                want = core_view(data)
                have = page_view(page)
                if codec in TEXTDECODER_CODECS:       # the known residual (see TEXTDECODER_CODECS)
                    want.pop("text")
                    have.pop("text")
                self.assertEqual(have, want)


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
