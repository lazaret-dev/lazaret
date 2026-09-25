"""Review items 1 and 10 (FIX-SPEC 4 and 15, collection side): source
encodings in the project walk.

1. A NUL in the first 4 bytes without a BOM made detect_encoding() return the
   generic "utf-16" codec, whose decoder raises UnicodeError ("UTF-16 stream
   does not start with BOM") — uncaught, so the whole scan died with a
   traceback (exit 1). BOM-less UTF-16LE is exactly what M17 targeted, and
   macOS AppleDouble "._*.py" files (NUL at offset 0) triggered it.
10. A PEP 263 cookie naming UTF-7 hides code in a comment: '+AAo-' decodes to
   a newline, so '#+AAo-exec(...)' is a comment to every reviewer and an
   exec() call to Python. Now: SC-UTF7 (CRITICAL) and the decoded text is
   scanned.

All fixtures are inert text; nothing is executed.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support
from lazaret.scanner import core

PY = sys.executable
APPLEDOUBLE = (b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        \x00\x02"
               + b"\x00" * 20 + b"com.apple.quarantine" + b"\x00" * 3000)


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-enc-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def run_cli(root, *extra):
    out = tempfile.mkdtemp(prefix="lz-review-out-")
    try:
        p = subprocess.run([PY, _support.CLI, root, "--out-dir", out, "--no-html", *extra],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=45)
        path = os.path.join(out, "lazaret-report.json")
        report = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return p, report


def rules_for(report, name):
    return {i["rule"] for i in report["issues"] if i["file"].replace(os.sep, "/") == name}


class DetectEncoding(unittest.TestCase):
    def test_spec_table(self):
        de = core.detect_encoding
        cases = [
            (b"\xff\xfeA\x00", "utf-16-le", True),
            (b"\xfe\xff\x00A", "utf-16-be", True),
            (b"\xef\xbb\xbfx", "utf-8-sig", True),
            (b"i\x00m\x00", "utf-16-le", True),     # NUL at index 1
            (b"im\x00\x00", "utf-16-le", True),     # NUL at index 3 (and 2)
            (b"\x00i\x00m", "utf-16-be", True),     # NUL at index 0 / 2
            (b"\x00\x05\x16\x07", "utf-16-be", True),   # AppleDouble magic
            (b"imp\x00", "utf-16-le", True),
            (b"import os", "utf-8", False),
            (b"ab", "utf-8", False),
            (b"", "utf-8", False),
        ]
        for head, enc, reported in cases:
            with self.subTest(head=head):
                got = de(head)
                self.assertEqual((got["encoding"], got["reported"]), (enc, reported))

    def test_nul_after_byte_4_is_not_sniffed(self):
        self.assertEqual(core.detect_encoding(b"abcd\x00")["encoding"], "utf-8")

    def test_decode_never_raises(self):
        samples = [b"i\x00", b"i\x00m", b"\xff\xfe\x00", b"\x00", b"\x00\xd8\x00",
                   b"\xfe\xff\xd8\x00", b"\xff" * 7, APPLEDOUBLE]
        for data in samples:
            for lang in ("py", "js", "sql", None):
                with self.subTest(data=data[:8], lang=lang):
                    text, info = core.decode_source(data, lang)
                    self.assertIsInstance(text, str)

    def test_bom_is_stripped(self):
        text, info = core.decode_source("﻿eval(x)\n".encode("utf-16-le"), "py")
        self.assertEqual(text, "eval(x)\n")
        text, _ = core.decode_source("﻿eval(x)\n".encode("utf-16-be"), "py")
        self.assertEqual(text, "eval(x)\n")


class BomlessUtf16(unittest.TestCase):
    def setUp(self):
        self.root = make_tree({
            "evil.py": "import os\nos.system(input())\n".encode("utf-16-le"),
            "evil_be.js": "eval(location.hash)\n".encode("utf-16-be"),
            "odd.py": "eval(x)\n".encode("utf-16-le") + b"\x00",   # odd byte count
            "ok.py": "x=1\n",
        })
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_scan_completes_and_sees_the_code(self):
        p, report = run_cli(self.root)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue({"S-OSCMD-PY", "Q-ENCODING"} <= rules_for(report, "evil.py"))
        self.assertTrue({"S-EVAL-JS", "Q-ENCODING"} <= rules_for(report, "evil_be.js"))
        self.assertIn("S-EVAL-PY", rules_for(report, "odd.py"))
        msgs = [i["msg"] for i in report["issues"] if i["rule"] == "Q-ENCODING"
                and i["file"] == "evil.py"]
        self.assertEqual(msgs, ["Source file is not UTF-8 (detected utf-16-le); decoded explicitly."])


class AppleDouble(unittest.TestCase):
    """macOS '._name' metadata files next to real sources."""

    def test_appledouble_never_crashes_and_adds_nothing(self):
        root = make_tree({"a.py": "x = 1\n", "._a.py": APPLEDOUBLE,
                          "._app.js": APPLEDOUBLE, "._q.sql": APPLEDOUBLE[:40]})
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_cli(root)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr)
        for name in ("._a.py", "._app.js", "._q.sql"):
            self.assertLessEqual(rules_for(report, name), {"Q-ENCODING"}, name)
        self.assertEqual(report["metrics"]["files"], 1)   # metadata is not source
        self.assertTrue(report["pass"])


def cookie(name, body):
    return f"# -*- coding: {name} -*-\n{body}".encode("ascii")


class EncodingCookies(unittest.TestCase):
    HIDDEN = "#+AAo-exec(input())\n"      # '+AAo-' is a newline in UTF-7

    def scan(self, files):
        root = make_tree(files)
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_cli(root)
        self.assertNotIn("Traceback", p.stderr)
        return p, report

    def test_utf7_cookie_flags_and_scans_decoded_text(self):
        p, report = self.scan({"hide.py": cookie("utf-7", self.HIDDEN)})
        self.assertEqual(p.returncode, 0, p.stderr)
        got = rules_for(report, "hide.py")
        self.assertTrue({"SC-UTF7", "Q-ENCODING", "S-EVAL-PY"} <= got, got)
        utf7 = [i for i in report["issues"] if i["rule"] == "SC-UTF7"][0]
        self.assertEqual((utf7["sev"], utf7["line"]), ("CRITICAL", 1))
        self.assertEqual(utf7["msg"], "Python source declares UTF-7; code can hide in comments.")
        self.assertFalse(report["pass"])

    def test_utf7_spellings(self):
        for name in ("utf-7", "UTF7", "u7", "unicode-1-1-utf-7", "UTF_7", "unicode_1_1_utf_7"):
            with self.subTest(name=name):
                text, info = core.decode_source(cookie(name, self.HIDDEN), "py")
                self.assertTrue(info["utf7"])
                self.assertIn("\nexec(", text)

    def test_ci_fails_on_utf7(self):
        root = make_tree({"hide.py": cookie("utf-7", "x = 1\n")})
        self.addCleanup(shutil.rmtree, root, True)
        p, _ = run_cli(root, "--ci")
        self.assertEqual(p.returncode, 1, p.stderr)

    def test_cookie_on_line_two_after_blank_or_comment(self):
        data = b"#!/usr/bin/env python\n# coding: utf-7\n" + self.HIDDEN.encode()
        text, info = core.decode_source(data, "py")
        self.assertTrue(info["utf7"])
        self.assertEqual(info["cookieLine"], 2)

    def test_cookie_on_line_two_after_code_is_ignored(self):
        # the interpreter only reads line 2 when line 1 is blank or a comment
        data = b"x = 1\n# coding: utf-7\n" + self.HIDDEN.encode()
        text, info = core.decode_source(data, "py")
        self.assertFalse(info["reported"])
        self.assertFalse(info["utf7"])

    def test_latin1_cookie_decodes_with_the_codec(self):
        p, report = self.scan({"l1.py": b"# -*- coding: latin-1 -*-\ns = 'caf\xe9'\neval(x)\n"})
        got = rules_for(report, "l1.py")
        self.assertTrue({"Q-ENCODING", "S-EVAL-PY"} <= got, got)
        self.assertNotIn("SC-UTF7", got)
        text, info = core.decode_source(b"# coding: latin-1\ns = '\xe9'\n", "py")
        self.assertIn("\xe9", text)

    def test_utf8_cookie_is_plain(self):
        for name in ("utf-8", "utf8", "UTF-8", "utf_8", "utf-8-sig"):
            with self.subTest(name=name):
                text, info = core.decode_source(cookie(name, "x = 1\n"), "py")
                self.assertFalse(info["reported"])

    def test_unknown_or_non_text_codec_falls_back_to_utf8(self):
        for name in ("x-no-such-codec", "rot13", "hex"):
            with self.subTest(name=name):
                text, info = core.decode_source(cookie(name, "eval(x)\n"), "py")
                self.assertTrue(info["reported"])
                self.assertFalse(info["utf7"])
                self.assertIn("eval(x)", text)

    def test_cookie_only_applies_to_python(self):
        text, info = core.decode_source(cookie("utf-7", self.HIDDEN), "js")
        self.assertFalse(info["reported"])
        self.assertNotIn("\nexec(", text)

    def test_long_comment_line_does_not_hide_the_cookie(self):
        data = b"#" + b"a" * 8000 + b"\n# coding: utf-7\n" + self.HIDDEN.encode()
        self.assertTrue(core.decode_source(data, "py")[1]["utf7"])


if __name__ == "__main__":
    unittest.main()
