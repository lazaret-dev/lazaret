"""Engine parity for SC-HEXSTR's hidden names and text: the native engine's
hex_hidden_name and hex_hidden_text (crates/lazaret-engine: scanfile.rs;
the npm package runs it as WebAssembly) against core.hex_hidden_name and
core.hex_hidden_text, case by case on curated lines and a seeded random
corpus of string literals built from escapes (\\xNN, \\uNNNN, \\u{N…},
\\UNNNNNNNN, octal), backslash runs, quotes, letters of dangerous names,
punctuation and non-ASCII text. The expectations are in
tests/scanner/test_review_hex_names.py. Columns are code points in both.
(Until 0.1.9 this held the npm engine's JavaScript twin to core.) Skipped
where the native library is not built.
"""
import json
import random
import unittest

from lazaret.scanner import _native, core

CURATED = [
    'var m = global["\\x72\\x65\\x71\\x75\\x69\\x72\\x65"]("child_process");', 'x = "\\x65val"', 'x = "\\\\x65val"',
    'x = "\\\\\\x65val"', 'u = "https:\\u002F\\u002Fexample.invalid"', 'u = "\\u0068ttps://example.invalid"',
    'w["\\u{65}v\\u0061l"](x)', 's = "\\145val"', 'b = b"\\x00\\x01\\x65val"', 'b = b"\\x00\\x65\\x76\\x61\\x6c"',
    'x = "\\x41PI system"', 'x = "sy\\x73tem"', 'x = "e\\x76al_thing"', 'k = "\\x5f_import__"', 'p = "\\U00000065xec"',
    'x = "\\x65"; y = "val"', "a = '\\x00\\x00\\x00'; b = '\\x65val'", 'x = "\\u00e9val"', 'x = "\\U0001F600\\x65val"',
    'x = "\\UFFFFFFFF\\x65val"', 'x = "\\u{110000}\\x65val"', 'x = `\\x63url -s x`', 'x = "\\x2Fbin\\x2Fsh"',
    'x = "/b\\x69n/sh"', 'x = "\\x70ickle.loads"', 'x = "\U0001F600" + "\\x65val"', 'x = "é\\x65val"',
    'x = "\\x65val" + "\\x65xec"', "\\x65val", '"\\x65val', 'x = ""', 'x = "\\"\\x65val"',
]
PIECES = ["\\x65", "\\x76", "\\x61", "\\x6c", "\\x45", "\\x72", "\\x71", "\\x69", "\\x00", "\\x7f", "\\x20", "\\x2f", "\\x5f",
          "\\u0065", "\\u0076", "\\u00e9", "\\u002F", "\\ud83d", "\\u{65}", "\\u{1F600}", "\\u{110000}", "\\U00000065",
          "\\U0001F600", "\\145", "\\166", "\\777", "\\", "\\\\", "\\\\\\", "x", "e", "v", "a", "l", "val", "eval", "exec",
          "require", "system", "curl", "https://", "/bin/sh", "import", "_", "0", "9", " ", "é", "\U0001F600", "ſ",
          "\u212a", "İ", "\x1c", '"', '"', "'", "`", "+", ";", "(", ")", "[", "]", "/"]


WORDS = ["eval", "exec", "execSync", "require", "system", "popen", "spawn", "curl", "wget", "https://",
         "http://", "/bin/sh", "/bin/bash", "__import__", "import", "base64", "atob", "Function", "fromCharCode",
         "marshal", "pickle", "child_process", "subprocess", "powershell", "cmd.exe", "compile", "b64decode", "EVAL"]


def escape(ch, rnd):
    """ch written as one of the escape forms (octal only below 0o1000)."""
    c = ord(ch)
    return rnd.choice([f"\\x{c:02x}", f"\\x{c:02X}", f"\\u{c:04x}", f"\\u{{{c:x}}}", f"\\U{c:08x}", f"\\{c:03o}"])


def corpus(seed=20260927, count=3000):
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(count):
        q = rnd.choice(['"', "'", "`"])
        if rnd.random() < 0.6:                      # a dangerous word, some of it escaped
            word = "".join(escape(ch, rnd) if rnd.random() < 0.4 else ch for ch in rnd.choice(WORDS))
            body = ("".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 4))) + word
                    + "".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 4))))
        else:
            body = "".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 12)))
        cases.append(rnd.choice(["x = ", "w[", "", "f("]) + q + body + q + rnd.choice(["", ";", ")", "](x)"]))
    return [json.loads(json.dumps(c)) for c in cases]


def core_view(text):
    name = core.hex_hidden_name(text)
    return [list(name) if name else None, core.hex_hidden_text(text)]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HexNameParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_case_agrees(self):
        cases = corpus()
        native = [r.get("ok", r) for r in _native.call("batch", {"calls": [["hex_view", {}, c] for c in cases]})]
        diffs = [(c, core_view(c), r) for c, r in zip(cases, native) if core_view(c) != r]
        self.assertEqual(diffs[:10], [])
        found = sum(1 for c in cases if core.hex_hidden_name(c))
        self.assertGreater(found, 300)                  # the corpus reaches the finding
        self.assertGreater(len(cases) - found, 300)     # and its absence


if __name__ == "__main__":
    unittest.main()
