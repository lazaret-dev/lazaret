"""Escape codecs: a `# coding: unicode_escape` (or raw_unicode_escape) cookie.

Python decodes such a file's escape sequences before it reads the code, so
`# \\x0aeval(z)` is a comment followed by `eval(z)` and `\\x6fs.system(...)`
is `os.system(...)`: the interpreter runs code that no editor, diff or
reviewer shows. 0.1.2's Python engine decoded these codecs and the npm
engine read the file as UTF-8, silently; integrating the codec-parity fix
made both read it as UTF-8 with SC-TRUNCATED, so the hidden code went
unscanned and a registry scan said INCOMPLETE instead of SUSPICIOUS. Now:

* they are decoded exactly as Python does: by the engine, for both packages
  since BR-7 step 4 (b) (decode/escape.rs; core._decode_escapes and
  encoding.js decodeEscapes before; checked against Python's codecs below);
* a \\N{name} escape (the engine has no Unicode name table) or an escape
  Python rejects (it would not run the file) is read as UTF-8, with
  SC-TRUNCATED, as for any codec the engine does not decode;
* the cookie itself is SC-ESCAPE-CODEC (CRITICAL), as UTF-7 is SC-UTF7: no
  legitimate project needs this source encoding.

All fixtures are inert text.
"""
import random
import re
import unittest
import warnings

from lazaret.scanner import _native, core
from tests.scanner import _dashboard_vm as dash

ESCAPE_CODECS = ("unicode-escape", "raw-unicode-escape")
#: a \N escape: an N after an odd run of backslashes
NAMED_ESCAPE_RE = re.compile(rb"(?:^|[^\\])(?:\\\\)*\\N")
SURROGATE_RE = re.compile("[\ud800-\udfff]")


def python_view(data, carried=False):
    """What each codec gives, as decode_source keeps it (None: not decoded): Python's codecs, but for \\N{name}
    (`carried`: as the engine's `decode` answer carries it, as_carried)."""
    out = []
    for codec in ESCAPE_CODECS:
        if codec == "unicode-escape" and NAMED_ESCAPE_RE.search(data):
            out.append(None)
            continue
        with warnings.catch_warnings():     # "invalid escape sequence" (kept as written)
            warnings.simplefilter("ignore")
            try:
                text = data.decode(codec)
                out.append(SURROGATE_RE.sub("\ufffd", as_carried(text) if carried else text))
            except UnicodeDecodeError:
                out.append(None)
    return out


def as_carried(text):
    """`text` as a JSON answer carries it: a high surrogate and a low one after it read back as one character (the
    engine's `decode` answer; decode_source's text holds no surrogate)."""
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def engine_view(data):
    """The engine's decoding of `data` in each codec (its `decode` call), as decode_source keeps it."""
    out = []
    for codec in ESCAPE_CODECS:
        text = _native.call("decode", {"codec": codec}, data.decode("latin-1"))["text"]
        out.append(None if text is None else SURROGATE_RE.sub("\ufffd", text))
    return out


def corpus():
    rng = random.Random(20260926)
    alphabet = [b"\\"] * 6 + [bytes([c]) for c in b"xuUN{}0137849afFgD\n\r'\"btnvq "] + [b"\xe9", b"\xff", b"\x00"]
    cases = [b"".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14))) for _ in range(4000)]
    return cases + [b"\\U0010ffff", b"\\U00110000", b"\\UFFFFFFFF", b"\\ud83d\\ude00", b"\\udc80", b"\\777",
                    b"\\400", b"\\8", b"abc\\", b"\\\\N{X}", b"\\N{LATIN SMALL LETTER A}", b"\\x4",
                    b"\\x41\\x4g", b"a\\\nb", b"a\\\r\nb", b"\\u00e9\xe9"]


class DecodeTests(unittest.TestCase):
    def test_python_semantics(self):
        text, info = core.decode_source(b"# coding: unicode_escape\n# \\x0aeval(z)\n\\x6fs.system(1)\n", "py")
        self.assertEqual(text, "# coding: unicode_escape\n# \neval(z)\nos.system(1)\n")
        self.assertEqual((info["encoding"], info["escapes"], info.get("undecoded")), ("unicode-escape", True, None))
        text, info = core.decode_source(b"# coding: raw_unicode_escape\n# \\x0a \\u000aeval(z)\n", "py")
        self.assertEqual(text, "# coding: raw_unicode_escape\n# \\x0a \neval(z)\n")
        self.assertEqual((info["encoding"], info["escapes"]), ("raw-unicode-escape", True))

    def test_what_is_read_as_utf8(self):
        for body, codec in ((b"# \\N{LATIN SMALL LETTER E}val(z)\n", "unicode_escape"),
                            (b"x = '\\x4'\n", "unicode_escape"), (b"x = '\\u12'\n", "raw_unicode_escape"),
                            (b"x = 1 \\", "unicode_escape"), (b"x = '\\U00110000'\n", "raw_unicode_escape")):
            with self.subTest(body=body, codec=codec):
                data = f"# coding: {codec}\n".encode() + body
                text, info = core.decode_source(data, "py")
                self.assertEqual(text, data.decode("utf-8"))
                self.assertTrue(info["escapes"] and info["undecoded"])
        # an escaped backslash before N is no \\N escape
        self.assertEqual(engine_view(b"\\\\N{X}")[0], "\\N{X}")

    def test_findings(self):
        text, info = core.decode_source(b"# coding: unicode_escape\n# \\x0aeval(z)\n", "py")
        issues = core.encoding_issues("u.py", text, info) + core.scan_file("u.py", text, "py")
        self.assertEqual(sorted((i["rule"], i["line"], i["sev"]) for i in issues),
                         [("Q-ENCODING", 1, "INFO"), ("S-EVAL-PY", 3, "CRITICAL"), ("SC-ESCAPE-CODEC", 1, "CRITICAL")])
        (esc,) = [i for i in issues if i["rule"] == "SC-ESCAPE-CODEC"]
        self.assertEqual(esc["msg"], "Python source declares unicode-escape; code can hide in escape sequences.")
        text, info = core.decode_source(b"#!/usr/bin/env python\n# coding: unicode_escape\n# \\N{X}\n", "py")
        rules = sorted((i["rule"], i["line"]) for i in core.encoding_issues("n.py", text, info))
        self.assertEqual(rules, [("Q-ENCODING", 1), ("SC-ESCAPE-CODEC", 2), ("SC-TRUNCATED", 1)])

    def test_cpython_agrees_with_the_documented_cases(self):
        self.assertEqual(python_view(b"a\\x41\\u00e9\\U0001F600\\101\\7777\\q\\\\\\'\\\"\\a\\b\\f\\n\\r\\t\\v\\\nz\xe9")[0],
                         "aA\xe9\U0001f600A\u01ff7\\q\\'\"\x07\x08\x0c\n\r\t\x0bz\xe9")
        self.assertEqual(python_view(b"\\ud83d\\ude00 \\udc80")[0], "\ufffd\ufffd \ufffd")
        self.assertEqual(python_view(b"\\\\u0041 \\u0041 \\x41 \\N{X} \\")[1], "\\\\u0041 A \\x41 \\N{X} \\")


class EngineParityTests(unittest.TestCase):
    """The engine's decoder against this Python's codecs, case by case (CI runs it on every supported Python)."""

    def test_the_engine(self):
        for case in corpus():
            self.assertEqual(engine_view(case), python_view(case, carried=True), case)

    @dash.requires_node
    def test_dashboard_decoder(self):
        cases = corpus()[-16:] + corpus()[:200]
        got = dash.run([{"op": "eval", "expr": f"[decodeEscapes(new Uint8Array({list(c)}), false), "
                                               f"decodeEscapes(new Uint8Array({list(c)}), true)]"} for c in cases])
        self.assertEqual(len(got), len(cases))
        for case, have in zip(cases, got):
            self.assertEqual(have, python_view(case), case)


class RegistryVerdictTests(unittest.TestCase):
    def test_a_wheel_module_with_an_escape_cookie_is_suspicious(self):
        from tests.registry._review_support import issues, scan_wheel
        res = scan_wheel({"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n",
                          "x/__init__.py": b"# coding: unicode_escape\n# \\x0aprint(1)\n"})
        self.assertEqual([(i["file"], i["sev"]) for i in issues(res, "SC-ESCAPE-CODEC")],
                         [("x/__init__.py", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
