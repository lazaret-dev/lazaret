"""S-TOKEN-PEM: a private-key header counts only with its key right after it.

The token rule's PEM alternative is the header alone, so a header is a key only with key material after it. That
material had to be on the header's line or the next two, anywhere there: on a minified line, which runs on for
megabytes, any long run of base64's characters made a library's header a key, and jose's importPKCS8
(`pkcs8.indexOf('-----BEGIN PRIVATE KEY-----') !== 0`) made two BLOCKERs in the bundles of redhat.vscode-yaml 1.25.0
(the live checks, Oct 9). Now the material must begin right after the header, past what a string or a
concatenation puts there (blanks, the escapes \\n \\r \\t, a backslash that ends the line, quotes and a string's
prefix, `#`, `+`, `,` and `.`), or at the start of the next line
that holds anything (a comment's marks aside), and an encrypted key's `Proc-Type:` counts as its key; and past a
header without its key, the line's other tokens are still read.

Code files: the engine (scanfile.rs's pem_has_material and token_col), with the native library. Config files:
configsecrets.key_follows. The npm package and the dashboard have twins (js/test/scanner/scan.test.js,
js/test/config-secrets.test.js, test_review_dashboard_parity's cases). Every key here is made up, and written in
pieces (tests/fixtures/README.md)."""

import time
import unittest

from lazaret.scanner import _native, configsecrets, core, engine

HEADER = "-----BEGIN " + "PRIVATE KEY-----"
RSA_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----"
FOOTER = "-----END " + "PRIVATE KEY-----"
RSA_FOOTER = "-----END RSA " + "PRIVATE KEY-----"
BODY = "MIIEvQIB" + "ADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Zq8vN3pL0wX7rT2mK9sB"     # 64 of base64's, mixed
AWS = "AKI" + "A" + "QWERTYUIOPASDFGH"
# 60,000 headers without their keys on one line, then an AWS key: the line is read in one walk, each header's key
# looked for in place (searching the line again from each header, or copying its rest, took over 45 seconds)
MANY = ('x="' + HEADER + '")x(') * 60_000 + f'"{AWS}"'
# jose's check as a bundle has it (dist/extension.js of redhat.vscode-yaml 1.25.0), with long runs of base64's
# characters later on the same line, as a minified file has them
JOSE = ('async function E(e,t,n){if("string"!=typeof e||0!==e.indexOf("' + HEADER + '"))throw new TypeError('
        '\'"pkcs8" must be PKCS#8 formatted string\');return x(e)}var t="' + BODY + '",u="data:font/woff2;base64,'
        + BODY * 3 + '";')


def tokens(path, text, lang, dep=True):
    """The lines S-TOKEN is reported on, by the native engine."""
    return [i["line"] for i in engine.scan_file(path, text, lang, dep=dep) if i["rule"] == "S-TOKEN"]


@unittest.skipUnless(_native.available(), "the native library is not built here")
class CodeFileTests(unittest.TestCase):
    def test_a_library_that_checks_a_keys_header_holds_no_key(self):
        for dep in (True, False):
            with self.subTest(dep=dep):
                self.assertEqual(tokens("dist/extension.js", JOSE + "\n", "js", dep), [])
        # the header as a constant, and a path of 40 or more of base64's characters on the next line
        text = f'const HEADER = "{HEADER}"\nconst docs = "src/runtime/node/key/import/pkcs8/whatever/aaaaaaaa"\n'
        self.assertEqual(tokens("lib/pem.js", text, "js"), [])
        self.assertEqual(tokens("lib/ssh.py", f'_PEM_BEGIN = b"{RSA_HEADER}"\n', "py"), [])

    def test_a_key_right_after_its_header_is_a_key(self):
        cases = {
            "escapes in a string": (f'KEY = "{HEADER}\\n{BODY}\\n{FOOTER}"\n', 1),
            "on the header's line": (f'k = "{HEADER}{BODY}{FOOTER}"\n', 1),
            "on the next line": (f'KEY = """{RSA_HEADER}\n{BODY}\n{RSA_FOOTER}"""\n', 1),
            "strings put together": (f'KEY = ("{HEADER}\\n"\n       "{BODY}\\n"\n       "{FOOTER}")\n', 1),
            "a line continued": (f'KEY = "{HEADER}\\n" \\\n      "{BODY}\\n" \\\n      "{FOOTER}"\n', 1),
            "PHP's concatenation": (f'$k = "{HEADER}\\n" .\n      "{BODY}\\n" .\n      "{FOOTER}";\n', 1),
            # (ecdsa 0.19.2's test keys: the first build read the `b` of `b"` as the key's start, and missed three)
            "bytes put together": (f'KEY = (\n    b"{HEADER}\\n"\n    b"{BODY}\\n"\n    b"{FOOTER}\\n"\n)\n', 2),
            "a list of lines": (f'KEY = [\n    "{RSA_HEADER}",\n    "{BODY}",\n    "{RSA_FOOTER}",\n]\n', 2),
            "commented out": (f"# {HEADER}\n# {BODY}\n# {FOOTER}\n", 1),
            "encrypted": (f'KEY = """{RSA_HEADER}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n'
                          f'{BODY}\n{RSA_FOOTER}"""\n', 1),
            "encrypted, on one line": (f'KEY = "{RSA_HEADER}\\nProc-Type: 4,ENCRYPTED\\n'
                                       f'DEK-Info: AES-128-CBC,0123\\n"\n', 1),
        }
        for what, (text, line) in cases.items():
            with self.subTest(what):
                self.assertEqual(tokens("lib/key.py", text, "py"), [line], text)
        # the next two lines are read, and no further
        self.assertEqual(tokens("lib/key.py", f'KEY = """{RSA_HEADER}\n\n\n{BODY}\n{RSA_FOOTER}"""\n', "py"), [])
        js = f"const k = `{RSA_HEADER}\n{BODY}\n{RSA_FOOTER}`;\nconst j = '{HEADER}\\n' +\n  '{BODY}';\n"
        self.assertEqual(tokens("lib/key.js", js, "js"), [1, 4])
        rs = f'const K: &str = concat!(\n    r#"{HEADER}"#,\n    r#"{BODY}"#,\n);\n'
        self.assertEqual(tokens("src/key.rs", rs, "rs"), [2])

    def test_a_header_without_its_key_leaves_the_lines_other_tokens_to_be_read(self):
        # before, the line's first token was the only one tried: a key's header without its key hid the AWS key
        self.assertEqual(tokens("lib/x.py", f'x = "{HEADER}"; y = "{AWS}"\n', "py"), [1])
        self.assertEqual(tokens("dist/x.js", JOSE + f'var k="{AWS}";\n', "js"), [1])

    def test_a_line_of_many_headers_is_read_in_one_walk(self):
        t0 = time.perf_counter()
        self.assertEqual(tokens("dist/x.js", f"a = 1;\n{MANY}\n", "js"), [2])
        self.assertLess(time.perf_counter() - t0, 10.0)


class ConfigFileTests(unittest.TestCase):
    def found(self, name, text):
        return sorted((i["rule"], i["line"]) for i in core.scan_config_file(name, text) if i["rule"] == "S-TOKEN")

    def test_a_service_accounts_key_on_one_line(self):
        text = ('{\n  "type": "service_account",\n  "private_key": "' + HEADER + "\\n" + BODY + "\\n" + FOOTER
                + '\\n",\n  "client_email": "svc@example.invalid"\n}\n')
        self.assertEqual(self.found("sa.json", text), [("S-TOKEN", 3)])

    def test_a_placeholder_or_a_note_is_not_the_headers_key(self):
        self.assertEqual(self.found(".env", f'PRIVATE_KEY="{HEADER}\\n...\\n{FOOTER}"\n'), [])
        self.assertEqual(self.found("c.yaml", f'header: "{HEADER}"  # see {BODY}\n'), [])

    def test_a_key_on_the_next_line_and_an_encrypted_one(self):
        self.assertEqual(self.found("k.pem", f"{RSA_HEADER}\n{BODY}\n{RSA_FOOTER}\n"), [("S-TOKEN", 1)])
        enc = f"{RSA_HEADER}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{BODY}\n{RSA_FOOTER}\n"
        self.assertEqual(self.found("e.pem", enc), [("S-TOKEN", 1)])
        # the next two lines are read, and no further
        self.assertEqual(self.found("f.pem", f"{RSA_HEADER}\n\n\n{BODY}\n{RSA_FOOTER}\n"), [])

    def test_a_line_of_many_headers_is_read_in_one_walk(self):
        t0 = time.perf_counter()
        self.assertEqual(self.found("x.env", f"a = 1\n{MANY}\n"), [("S-TOKEN", 2)])
        self.assertLess(time.perf_counter() - t0, 10.0)

    def test_key_follows(self):
        def follows(after, following):
            return configsecrets.key_follows(HEADER + after, len(HEADER), following)
        self.assertTrue(follows("\\n" + BODY, []))
        self.assertTrue(follows('\\\\n" + "' + BODY, []))              # a string inside a string, then joined
        self.assertTrue(follows('",', ['    "' + BODY + '",']))
        self.assertTrue(follows("", ["", "  # " + BODY]))               # a blank line, then a comment's mark
        self.assertTrue(follows("", ["Proc-Type: 4,ENCRYPTED"]))
        self.assertTrue(follows("\\nProc-Type: 4,ENCRYPTED\\n", []))
        self.assertTrue(follows('\\n" \\', ['      "' + BODY + '\\n"']))   # a line continued
        self.assertTrue(follows('\\n" .', ['      "' + BODY + '";']))        # PHP's and Perl's concatenation
        self.assertFalse(follows("\\ x", [BODY]))                          # a backslash, and then not an escape
        self.assertTrue(follows('\\n"', ['    b"' + BODY + '\\n"']))         # a string's prefix
        self.assertTrue(follows('"#,', ['    r#"' + BODY + '"#,']))          # Rust's raw strings
        self.assertFalse(follows('"', ['    bytes("' + BODY + '")']))        # not a prefix: a call
        self.assertFalse(follows('"))throw new TypeError("x");var t="' + BODY + '"', []))
        self.assertFalse(follows('"', ["const x = 1; // " + BODY]))
        self.assertFalse(follows("\\n" + "privatekey" * 6, []))          # not mixed: a template's text
        self.assertFalse(follows("", ["", "  ", "x"]))                   # the first line that holds anything decides
        self.assertFalse(follows("", []))


if __name__ == "__main__":
    unittest.main()
