"""Decoding is the engine's (BR-7 step 4 (b), 0.1.9).

core.decode_source, encoding_issues and decode_member and the npm package's decodeSource, encodingIssues and
decodeMember (lib/encoding.js, lib/codecs.js and lib/fs.js) each decoded a source file, held equal by the parity
tests: Python with its own codecs, npm with generated single-byte tables and the runtime's TextDecoder, and both read
a codec npm could not decode exactly (most CJK codecs, the ISO-2022 family, HZ, UTF-32) as UTF-8, SC-TRUNCATED. The
engine decodes for both (rust/crates/lazaret-engine/src/decode/: the `decode_source`, `encoding_issues` and
`decode` calls), every text codec Python has, as Python decodes it, from tables scripts/make_codec_tables.py reads
from Python's own decoders.

Held here to core's code as it was (below: what this replaced, word for word but its docstrings), decoding every
codec with Python's codecs, as core did for those both packages read: every codec under its spellings; generated
files (byte order marks, NULs near the top, cookies on line 1 or 2 or too late, each line ending, the escape codecs
with \\N); each codec's bytes (every byte, every two bytes of the multibyte and stateful codecs, gb18030's four-byte
and EUC-KR's eight-byte forms, the ISO-2022 escapes with each byte after them, random bytes); decode_member's
findings, redacted and not; and the WebAssembly build to the native library on the same calls. Before the commit,
the same over more (every three bytes after a held two, 300,000 random strings for each stateful codec): no
difference.
"""
import codecs
import json
import os
import random
import re
import subprocess
import unittest
import warnings

from lazaret.scanner import _native, core
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

if not _native.available():
    raise unittest.SkipTest(f"decoding is the native engine's ({_native.load_error()})")

GEN = _support.load_script(_support.REPO_ROOT + "/scripts/make_codec_tables.py", "make_codec_tables_for_decode")

# ---------------------------------------------------------------- core's code as it was (774bf22)

_codecs = codecs
_PY_COOKIE_RE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_PY_BLANK_RE = re.compile(rb"^[ \t\f]*(?:#.*)?$")
_UTF7_NAMES = frozenset({"utf-7", "utf7", "u7", "unicode-1-1-utf-7"})
CODEC_ALIAS_EXTRAS, HOST_CODECS, CHARMAP_FIXES = GEN.CODEC_ALIAS_EXTRAS, GEN.HOST_CODECS, GEN.CHARMAP_FIXES
_NON_TEXT_CHARS_RE = re.compile("[\udc80-\udcff\x00-\x08\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a"
                                "\x1c-\x1f\x7f]")
_NON_TEXT_SHARE = 0.30
mk_issue, _Redactor, truncated_issue = core.mk_issue, core._Redactor, core.truncated_issue
normalize_newlines, EXTS, MPEG_TS_EXTS, _mpeg_ts = core.normalize_newlines, core.EXTS, core.MPEG_TS_EXTS, core._mpeg_ts
#: the codecs core decoded with Python's codecs: those npm decoded too. Python decodes every codec but these three,
#: and the engine now does as Python does.
NOT_DECODED = ("idna", "punycode", "undefined")


def _decoded_by_both_engines(codec):
    return codec not in NOT_DECODED


def detect_encoding(head):
    if head.startswith(b"\xff\xfe"):
        return {"encoding": "utf-16-le", "reported": True, "bom": 2}
    if head.startswith(b"\xfe\xff"):
        return {"encoding": "utf-16-be", "reported": True, "bom": 2}
    if head.startswith(b"\xef\xbb\xbf"):
        return {"encoding": "utf-8-sig", "reported": True, "bom": 0}
    first = head[:4]
    if b"\x00" in first:
        le = first[1:2] == b"\x00" or first[3:4] == b"\x00"
        return {"encoding": "utf-16-le" if le else "utf-16-be", "reported": True, "bom": 0}
    return {"encoding": "utf-8", "reported": False, "bom": 0}


def _python_cookie(data):
    lines = re.split(rb"\r\n|\r|\n", data, maxsplit=2)[:2]
    for idx, line in enumerate(lines):
        m = _PY_COOKIE_RE.match(line)
        if m:
            return m.group(1).decode("ascii"), idx + 1
        if not _PY_BLANK_RE.match(line):
            break
    return None, None



def _codec_key(name):
    return re.sub(r"[^a-z0-9.]+", "_", name.lower()).strip("_")


def _normal_codec(name):
    short = name[:12].lower().replace("_", "-")
    if short == "utf-8" or short.startswith("utf-8-"):
        return "utf-8"
    if short in ("latin-1", "iso-8859-1", "iso-latin-1") or short.startswith(
            ("latin-1-", "iso-8859-1-", "iso-latin-1-")):
        return "iso8859-1"
    key = _codec_key(name)
    extra = CODEC_ALIAS_EXTRAS.get(key) or CODEC_ALIAS_EXTRAS.get(key.replace(".", "_"))
    if extra:
        return extra
    try:
        info = _codecs.lookup(name)
    except LookupError:
        return None
    if not getattr(info, "_is_text_encoding", True):
        return None                     # rot13, hex, zlib… are not text encodings
    return None if info.name in HOST_CODECS else info.name



#: Codecs that decode escape sequences before Python reads the code: in a file
#: that declares one, '\u000a' in a comment is a newline and '\u0065' is 'e'
#: (SC-ESCAPE-CODEC). Both engines decode them (_decode_escapes).
ESCAPE_CODECS = ("unicode-escape", "raw-unicode-escape")
#: A \N escape: an N after an odd run of backslashes (linear: a run is
#: tried only from the character before it).
_NAMED_ESCAPE_RE = re.compile(rb"(?:^|[^\\])(?:\\\\)*\\N")


def _decode_escapes(body, codec):
    if codec == "unicode-escape" and _NAMED_ESCAPE_RE.search(body):
        return None
    with warnings.catch_warnings():     # "invalid escape sequence" (kept as written)
        warnings.simplefilter("ignore")
        try:
            return body.decode(codec)
        except UnicodeDecodeError:
            return None


#: A surrogate code point: never text on its own (see decode_source).
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def REFERENCE_decode_source(data, lang=None):
    enc = detect_encoding(data[:4])
    if (enc["reported"] and not enc["bom"] and enc["encoding"].startswith("utf-16")
            and not _text_is_plausible(data[:4096].decode(enc["encoding"], "replace"))):
        # A NUL near the top of a UTF-8 file (`/*\0*/eval(…)`) is not UTF-16:
        # decoded that way the payload turns into CJK-looking garbage that no
        # rule reads. Accept the BOM-less UTF-16 guess only when it reads as
        # text (real UTF-16 source is mostly ASCII).
        enc = {"encoding": "utf-8", "reported": False, "bom": 0}
    codec, body = enc["encoding"], data[enc["bom"]:]
    info = {"encoding": codec, "reported": enc["reported"], "utf7": False, "cookieLine": None}
    if lang == "py" and not enc["reported"]:
        name, line_no = _python_cookie(data)
        if name is not None:
            real = _normal_codec(name)
            if real is None:
                info.update(encoding=name, reported=True, cookieLine=line_no)
            elif real != "utf-8":
                info.update(encoding=real, reported=True, cookieLine=line_no,
                            utf7=(real == "utf-7"
                                  or name.lower().replace("_", "-") in _UTF7_NAMES))
                if real in ESCAPE_CODECS:
                    info["escapes"] = True
                if _decoded_by_both_engines(real):
                    codec = real
                else:           # read as UTF-8, as the npm engine can only read it
                    info["undecoded"] = True
    text = _decode_escapes(body, codec) if codec in ESCAPE_CODECS else None
    if codec in ESCAPE_CODECS and text is None:
        info["undecoded"] = True        # read as UTF-8, as the npm engine can only read it
        codec = "utf-8"
    if text is None:
        try:
            text = body.decode(codec)
        except Exception:               # malformed input or a misbehaving codec:
            try:                        # never abort the scan over content
                text = body.decode(codec, "replace")
            except Exception:
                text = body.decode("utf-8", "replace")
    fix = CHARMAP_FIXES.get(codec)
    if fix:
        text = text.translate(fix)
    if not text.isascii():
        text = _SURROGATE_RE.sub("\ufffd", text)
    return normalize_newlines(text), info


def REFERENCE_encoding_issues(path, text, info):
    if not info["reported"]:
        return []
    lines = text.split("\n")
    red = _Redactor(lines)
    out = [mk_issue(
        {"id": "Q-ENCODING", "name": "Non-UTF-8 source encoding", "type": "SMELL",
         "sev": "INFO",
         "msg": f"Source file is not UTF-8 (detected {info['encoding']}); decoded explicitly.",
         "why": "A non-UTF-8 source read as UTF-8 decodes to mojibake, hiding every "
                "pattern-based finding — a UTF-16 eval() scans clean.",
         "fix": "Re-save the file as UTF-8 so tooling reads it as written.",
         "ref": "Maintainability"}, path, 1, lines, redactor=red)]
    if info["utf7"]:
        out.append(mk_issue(
            {"id": "SC-UTF7", "name": "UTF-7 source encoding", "type": "HOTSPOT",
             "sev": "CRITICAL",
             "msg": "Python source declares UTF-7; code can hide in comments.",
             "why": "In UTF-7, '+AAo-' decodes to a newline: text that every editor, diff "
                    "and reviewer shows as a comment becomes executable code when Python "
                    "reads the file. No legitimate project needs a UTF-7 source file.",
             "fix": "Re-save the file as UTF-8 and review the decoded text (the findings "
                    "for this file are reported against it).",
             "ref": "CWE-506 · Supply chain"}, path, info["cookieLine"] or 1, lines,
            redactor=red))
    if info.get("escapes"):
        out.append(mk_issue(
            {"id": "SC-ESCAPE-CODEC", "name": "Escape-sequence source encoding", "type": "HOTSPOT",
             "sev": "CRITICAL",
             "msg": f"Python source declares {info['encoding']}; code can hide in escape sequences.",
             "why": "Python decodes this file's escape sequences before it reads the code: "
                    "'\\u000a' is a newline and '\\u0065' is 'e', so text that every editor, "
                    "diff and reviewer shows as a comment or a string escape becomes executable "
                    "code. No legitimate project needs this source encoding.",
             "fix": "Re-save the file as UTF-8 and review the decoded text (the findings "
                    "for this file are reported against it).",
             "ref": "CWE-506 · Supply chain"}, path, info["cookieLine"] or 1, lines,
            redactor=red))
    if info.get("undecoded"):
        out.append(truncated_issue(
            path, f"its source encoding ({info['encoding']}) is not decoded by Lazaret; "
                  f"the file was read as UTF-8"))
    return out


def _text_is_plausible(text):
    if not text:
        return False
    sample = text[:2048]
    plain = sum(1 for ch in sample if " " <= ch <= "~" or ch in "\t\r\n")
    return plain / len(sample) >= 0.70


def _undecodable_share(text):
    if not text:
        return 0.0
    sample = text[:65536]
    bad = sample.count("\ufffd") + len(_NON_TEXT_CHARS_RE.findall(sample))
    return bad / len(sample)


def REFERENCE_decode_member(path, data, lang=None):
    data = bytes(data or b"")
    ext = os.path.splitext(path)[1].lower()
    if lang is None:
        lang = "py" if ext in (".py", ".pyw") else EXTS.get(ext)
    text, info = REFERENCE_decode_source(data, lang)
    extra = REFERENCE_encoding_issues(path, text, info)
    share = _undecodable_share(text)
    if share > _NON_TEXT_SHARE and not (ext in MPEG_TS_EXTS and _mpeg_ts(data[:512])):
        extra.append(truncated_issue(
            path, f"content is not decodable as text ({share:.0%} invalid bytes or "
                  f"control characters), so no rule could read it"))
    return text, extra


# ---------------------------------------------------------------- the tests

STATELESS = GEN.STATELESS
STATEFUL = GEN.ISO2022 + ["hz"]
UNICODE = ["utf-7", "utf-16", "utf-16-be", "utf-16-le", "utf-32", "utf-32-be", "utf-32-le", "utf-8", "utf-8-sig"]
SAMPLE = "Lazaret: x = 1\r\n" + "".join(map(chr, range(0x20, 0x2000, 7))) + "漢字かなカナ한국어中文\n"


def python_decode(codec, data):
    """What core.decode_source reads `data` as in `codec` (before the cookie's checks): None where it read UTF-8."""
    if codec in ESCAPE_CODECS:
        return as_carried(_decode_escapes(data, codec))
    if codec in NOT_DECODED:
        return None
    try:
        text = data.decode(codec, "replace")
    except RuntimeError:            # iso2022_jp_2: single shift 2 with JIS X 0201 Roman in G2
        return None
    fix = CHARMAP_FIXES.get(codec)
    return text.translate(fix) if fix else text


def as_carried(text):
    """`text` as the `decode` call's JSON answer carries it: a high surrogate and a low one after it (which the
    escape codecs leave apart) read back as one character."""
    return None if text is None else text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def engine_decode(codec, inputs):
    out = []
    for k in range(0, len(inputs), 2048):
        calls = [["decode", {"codec": codec}, b.decode("latin-1")] for b in inputs[k:k + 2048]]
        for a in _native.call("batch", {"calls": calls, "threads": 4}):
            out.append(a["ok"]["text"] if "ok" in a else a)
    return out


class CodecTests(unittest.TestCase):
    """The engine's `decode` call: bytes in a codec, as Python decodes them (and every two bytes, the long forms and
    the escape sequences: test_decode_engine_codecs.py)."""

    def check(self, codec, inputs):
        got = engine_decode(codec, inputs)
        bad = [(b, python_decode(codec, b), g) for b, g in zip(inputs, got) if python_decode(codec, b) != g]
        self.assertEqual(bad[:3], [], f"{codec}: {len(bad)} of {len(inputs)} differ")

    def test_every_codec_byte_by_byte_and_on_text(self):
        rnd = random.Random(4)
        for codec in GEN.codec_aliases():
            with self.subTest(codec=codec):
                inputs = [bytes([b]) for b in range(256)]
                inputs += [bytes(rnd.randrange(256) for _ in range(rnd.randint(2, 30))) for _ in range(300)]
                try:
                    inputs.append(SAMPLE.encode(codec, "ignore"))
                except (UnicodeError, TypeError, LookupError):
                    pass
                self.check(codec, inputs)

    def test_random_bytes_for_the_stateful_codecs(self):
        alphabet = list(range(256)) + list(b"\x1b\x1b\x1b$$$(((()))BBJJIDA@CNO.\x0e\x0f\n~~{}!!##0123&&@@") * 6
        utf7 = list(range(256)) + list(b"++++----ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/2D") * 4
        escapes = list(range(256)) + list(b"\\\\\\\\uUxXN{}0123456789abcdefABCDEF") * 6
        for codec in STATEFUL + ["utf-7", "unicode-escape", "raw-unicode-escape"]:
            rnd = random.Random(codec)
            letters = utf7 if codec == "utf-7" else escapes if "escape" in codec else alphabet
            with self.subTest(codec=codec):
                self.check(codec, [bytes(rnd.choice(letters) for _ in range(rnd.randint(1, 40))) for _ in range(4000)])

    def test_where_python_raises_the_file_is_read_as_utf8(self):
        data = b"# coding: iso2022_jp_2\n\x1b.J\x1bNa = 1\n"
        with self.assertRaises(RuntimeError):
            data.decode("iso2022_jp_2", "replace")
        self.assertEqual(engine_decode("iso2022_jp_2", [data]), [None])
        self.assertEqual(core.decode_source(data, "py"), REFERENCE_decode_source(data, "py"))

    def test_a_codec_python_lacks_and_one_that_is_not_text(self):
        self.assertEqual(_native.call("decode", {"codec": "no-such-codec"}, "x"), {"codec": None, "text": None})
        self.assertEqual(_native.call("decode", {"codec": "rot13"}, "x"), {"codec": None, "text": None})
        self.assertEqual(_native.call("decode", {"codec": "IDNA"}, "x"), {"codec": "idna", "text": None})
        with self.assertRaises(_native.NativeError):
            _native.call("decode", {"codec": "utf-8"}, "Ā")


def cookie_file(name, body=bytes(b for b in range(256) if b not in (0x0a, 0x0d)) + b"\n"):
    return f"# coding: {name}\n".encode("ascii") + body


def generated_files(seed, n):
    rnd = random.Random(seed)
    names = sorted({name for codec, spellings in GEN.codec_aliases().items() for name in [codec] + spellings[:2]})
    heads = [b"", b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf", b"a\x00", b"\x00a", b"/*\x00*/", b"#!/usr/bin/env python\n",
             b"\n", b"# a comment\r\n", b"x = 1\n\n"]
    out = []
    for _ in range(n):
        eol = rnd.choice([b"\n", b"\r\n", b"\r"])
        lines = [b"# -*- coding: " + rnd.choice(names).encode() + b" -*-"] if rnd.random() < 0.8 else []
        body = rnd.choice([bytes(rnd.randrange(256) for _ in range(rnd.randint(0, 60))),
                           "eval(x) # é 漢字 \\x0a \\u000a +AAo- \\N{X}".encode(rnd.choice(["utf-8", "latin-1", "utf-16-le"]),
                                                                                         "replace")])
        data = rnd.choice(heads) + eol.join(lines + [body, b"y = 2", b""])
        out.append(data)
    return out


class DecodeSourceTests(unittest.TestCase):
    def test_every_codec_under_its_spellings(self):
        for codec, names in GEN.codec_aliases().items():
            for name in dict.fromkeys([codec] + names[:3]):
                data = cookie_file(name)
                with self.subTest(codec=codec, name=name):
                    self.assertEqual(core.decode_source(data, "py"), REFERENCE_decode_source(data, "py"))

    def test_generated_files(self):
        for k, data in enumerate(generated_files(6, 1500)):
            for lang in ("py", "js", None):
                with self.subTest(file=k, lang=lang):
                    self.assertEqual(core.decode_source(data, lang), REFERENCE_decode_source(data, lang))

    def test_cookies_and_spellings_resolve_on_every_python(self):
        for name, codec in (("windows-874", "cp874"), ("MS874", "cp874"), ("windows_31j", "cp932"),
                            ("csEUCKR", "euc_kr"), ("ISO-8859-8-I", "iso8859-8"), ("cp01140", "cp1140"),
                            ("IBM00858", "cp858"), ("latin-1-unix", "iso8859-1"), ("UTF-8-mac", None),
                            ("mbcs", "mbcs"), ("dbcs", "dbcs"), ("oem", "oem"), ("rot13", "rot13")):
            with self.subTest(name=name):
                info = core.decode_source(cookie_file(name, b"x = 1\n"), "py")[1]
                self.assertEqual(info["encoding"], codec or "utf-8")
        text, _ = core.decode_source(b"# coding: palmos\ns = '\x9b'\n", "py")
        self.assertIn("›", text)          # 3.13+'s mapping, on every version

    def test_the_encoding_findings(self):
        for k, data in enumerate(generated_files(7, 400)):
            text, info = core.decode_source(data, "py")
            for redact in (True, False):
                with self.subTest(file=k, redact=redact), _redacting(redact):
                    self.assertEqual(core.encoding_issues("f.py", text, info),
                                     REFERENCE_encoding_issues("f.py", text, info))


class _redacting:
    def __init__(self, on):
        self.on = on

    def __enter__(self):
        self.was, core.REDACT_SECRETS = core.REDACT_SECRETS, self.on

    def __exit__(self, *exc):
        core.REDACT_SECRETS = self.was


class DecodeMemberTests(unittest.TestCase):
    def test_members(self):
        rnd = random.Random(8)
        ts = bytes(([0x47] + [rnd.randrange(256) for _ in range(187)]) * 4)
        files = generated_files(9, 600) + [ts, b"\x00" * 100, bytes(range(256)) * 4, "x = 1\n".encode("utf-16"),
                                           b"\x7fELF" + bytes(300), b"# coding: utf-7\n+AAo-eval(x)\n"]
        names = ["a.py", "b.js", "c.ts", "d.mts", "e.m2ts", "setup.py", "f.sql", "g.txt", "dir/h.PY", "i.TS"]
        for k, data in enumerate(files):
            for name in rnd.sample(names, 3):
                for lang in (None, "py", "js"):
                    for redact in (True, False):
                        with self.subTest(file=k, name=name, lang=lang, redact=redact), _redacting(redact):
                            self.assertEqual(core.decode_member(name, data, lang),
                                             REFERENCE_decode_member(name, data, lang))


def engine_calls():
    calls = []
    for k, data in enumerate(generated_files(10, 300)):
        text = data.decode("latin-1")
        calls.append(("decode_source", {"lang": "py"}, text))
        calls.append(("decode_source", {"lang": "py", "issues": True, "name": f"m{k}.ts", "redact": k % 2 == 0}, text))
        info = _native.call("decode_source", {"lang": "py"}, text)
        calls.append(("encoding_issues", {"info": info["info"], "redact": True}, info["text"]))
    rnd = random.Random(11)
    for codec in STATELESS + STATEFUL + UNICODE + ["cp037", "unicode-escape", "raw-unicode-escape", "mac_roman"]:
        for _ in range(20):
            calls.append(("decode", {"codec": codec}, bytes(rnd.randrange(256) for _ in range(30)).decode("latin-1")))
    return calls


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class WasmParityTests(unittest.TestCase):
    def test_the_calls(self):
        from tests.architecture.test_result_engine import NODE_ANSWERS
        from tests.architecture.test_wasm_parity import NATIVE_JS
        calls = engine_calls()
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", NODE_ANSWERS, NATIVE_JS], input=json.dumps(calls),
                           capture_output=True, encoding="utf-8", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        wasm = json.loads(p.stdout)
        self.assertEqual(len(wasm), len(calls))
        for k, (call, got) in enumerate(zip(calls, wasm)):
            with self.subTest(call=k, name=call[0]):
                self.assertEqual(got, {"ok": _native.call(*call)})


if __name__ == "__main__":
    unittest.main()
