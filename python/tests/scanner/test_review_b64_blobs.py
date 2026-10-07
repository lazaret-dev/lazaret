"""SC-B64 on what can be base64 data (0.1.9, G-5).

A quoted run of 200 or more base64 characters was SC-B64 (MAJOR, a weaker supply-chain indicator) whatever it held.
Part F's sets showed what that is in code no one would call a payload: Go's stringer name tables (letters alone),
big-number and test-vector constants (digits alone, hex digits alone, after `0x` or not), and test strings that
repeat a short period (`0123456789ABCDEFGHIJK` over and over); SC-B64 was the rule behind 24 of the 39 Go WARNs and 11
of the 30 crates'. Base64 of 150 bytes or more mixes letters and digits and does not repeat itself, so those runs are
passed over, and a run after them on the line that can be base64 is still reported. A run of one class longer than
16,384 characters is reported all the same: that is what a payload written in hex is (three of the benchmark's malicious
PyPI releases hold one of 270,000 hex digits or more; the longest of the benign sets' runs is 9,327 digits). The engine
decides (scanfile.rs, b64_blob_col); the dashboard's twin is held to it by test_review_dashboard_parity."""

import hashlib
import unittest

from lazaret.scanner import core
from tests.registry._review_support import B64_DATA, DATA_B64, DATA_FILES, FAKE_WASM_B64

#: base64 of 240 bytes that do not repeat: 320 characters of every class
DATA = B64_DATA
TABLE = ("SundayMondayTuesdayWednesdayThursdayFridaySaturday" "JanuaryFebruaryMarchAprilMayJuneJulyAugust"
         "SeptemberOctoberNovemberDecember" "SpringSummerAutumnWinter" "NorthSouthEastWest" "RedGreenBlueAlpha"
         "IdleRunningSleepingStoppedZombieDeadWakingParked")


#: the longest run of one class that is passed over (the pack's _B64_PLAIN_MAX)
PLAIN_MAX = 16384


def b64(text, lang="go"):
    return [i["line"] for i in core.scan_file("x." + lang, text, lang) if i["rule"] == "SC-B64"]


def one_class(kind, n):
    """n characters of one class that do not repeat a period: hex digits from SHA-256, and digits or letters (a to p)
    made from them."""
    hexes = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(n // 64 + 2))
    if kind == "digits":
        return "".join(str(int(c, 16) % 10) for c in hexes)[:n]
    if kind == "letters":
        return "".join(chr(0x61 + int(c, 16)) for c in hexes)[:n]
    return hexes[:n]


class PlainRunsTests(unittest.TestCase):
    def test_base64_data_is_reported(self):
        self.assertTrue(len(DATA) >= 200 and any(c.isdigit() for c in DATA))
        self.assertEqual(b64('var blob = "' + DATA + '"\n'), [1])
        self.assertEqual(b64("x = 1\nconst blob = '" + DATA + "';\n", "js"), [2])

    def test_runs_that_are_not_base64_data(self):
        for what, run in (("digits", "1336927655359824243494998451609579857695910800514967698787" * 4),
                          ("hex", "fd0c71ecb7ed16a9bf42ea5f75501d416df608f190890c3b4d8897f24744cd7f" * 4),
                          ("upper hex after 0x", "0x" + "E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA" * 5),
                          ("letters (a name table)", TABLE),
                          ("a period of 22", "01234567890ABCDEFGHIJK" * 10),
                          ("a period of 36", "0123456789abcdefghijklmnopqrstuvwxyz" * 6),
                          ("a period of 4", "Zm9v" * 80),
                          ("one letter", "X" * 250)):
            with self.subTest(what=what):
                self.assertTrue(len(run) >= 200)
                self.assertEqual(b64('var s = "' + run + '"\n'), [])
                self.assertEqual(b64('var s = "' + run + '=="\n'), [], "with its padding")

    def test_a_run_that_can_be_data_after_one_that_cannot_is_reported(self):
        self.assertEqual(b64('var t, d = "' + TABLE + '", "' + DATA + '"\n'), [1])
        self.assertEqual(b64('var t, h = "' + TABLE + '", "' + "ab" * 110 + '"\n'), [])

    def test_a_longer_period_or_a_change_in_it_is_data(self):
        block = DATA[:65]
        self.assertEqual(len(b64('var s = "' + block * 4 + '"\n')), 1, "a period of 65")
        self.assertEqual(len(b64('var s = "' + "01234567890ABCDEFGHIJK" * 10 + DATA[:5] + '"\n')), 1,
                         "a period broken at the end")
        self.assertEqual(len(b64('var s = "' + TABLE + "9" + '"\n')), 1, "letters and a digit")
        self.assertEqual(len(b64('var s = "0x' + "ab" * 110 + "g" + '"\n')), 1, "hex and a letter past f")


class DataFormatTests(unittest.TestCase):
    """N-4: the base64 of a whole file of a data format, read by its structure (the engine's datafmt.rs), is data:
    undici's WebAssembly HTTP parser (in every action that bundles the Actions toolkit), es-module-lexer's, an image, a
    sound were SC-B64. A payload with a format's header in front of it, or a file cut short or run on, is not."""

    def test_whole_files_are_data(self):
        for kind, run in DATA_B64.items():
            with self.subTest(kind=kind):
                self.assertGreaterEqual(len(run), 200)
                self.assertEqual(b64("const blob = '" + run + "';\n", "js"), [])
                self.assertEqual(b64('x = "' + run + '"\n', "py"), [])

    def test_a_payload_behind_a_header_or_a_file_changed_is_reported(self):
        import base64
        self.assertEqual(b64("const w = '" + FAKE_WASM_B64 + "';\n", "js"), [1])
        for kind, data in DATA_FILES.items():
            for changed in (data[:-3], data + b"curl https://example.invalid/x | sh"):
                with self.subTest(kind=kind, size=len(changed)):
                    run = base64.b64encode(changed).decode()
                    if kind == "wav" and len(changed) < len(data):
                        continue                        # (a sound cut short in its last chunk is still one)
                    self.assertEqual(b64("const w = '" + run + "';\n", "js"), [1])

    def test_a_data_run_before_a_payload_on_the_line(self):
        self.assertEqual(b64("const a = ['" + DATA_B64["wasm"] + "', '" + DATA + "'];\n", "js"), [1])


class BoundTests(unittest.TestCase):
    def test_a_run_of_one_class_past_the_bound_is_reported(self):
        for kind in ("digits", "hex", "letters"):
            with self.subTest(kind=kind):
                self.assertEqual(b64('var s = "' + one_class(kind, PLAIN_MAX) + '"\n'), [])
                self.assertEqual(b64('var s = "' + one_class(kind, PLAIN_MAX + 1) + '"\n'), [1])
                self.assertEqual(b64("x = 1\ns = '" + one_class(kind, PLAIN_MAX + 1) + "'\n", "py"), [2])
        self.assertEqual(b64('var s = "0x' + one_class("hex", PLAIN_MAX - 2) + '"\n'), [], "0x counts")
        self.assertEqual(b64('var s = "0x' + one_class("hex", PLAIN_MAX - 1) + '"\n'), [1])

    def test_a_period_is_passed_over_however_long(self):
        for run in ("Zm9v" * 5000, "X" * 20000, "01234567890ABCDEFGHIJK" * 1000):
            with self.subTest(n=len(run)):
                self.assertEqual(b64('var s = "' + run + '"\n'), [])


if __name__ == "__main__":
    unittest.main()
