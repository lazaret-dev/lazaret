"""Decoding is the engine's (BR-7 step 4 (b), 0.1.9): the bytes of the multibyte and stateful codecs.

test_decode_engine.py's codec tests, at length: every two bytes of each stateless multibyte codec, HZ and
UTF-7, gb18030's four-byte and EUC-KR's eight-byte forms, and the ISO-2022 escape sequences with each byte
after them, through the engine's `decode` call, held to Python's codecs.
"""
import random
import unittest

from tests.architecture import test_decode_engine as base


class LongCodecTests(unittest.TestCase):
    check = base.CodecTests.check

    def test_the_multibyte_codecs_two_bytes_at_a_time(self):
        pairs = [bytes([a, b]) for a in range(256) for b in range(256)]
        for codec in base.STATELESS + ["hz", "utf-7"]:     # (the ISO-2022 codecs' escapes: test_the_long_forms)
            with self.subTest(codec=codec):
                self.check(codec, pairs)

    def test_the_long_forms(self):
        rnd = random.Random(5)
        with self.subTest("gb18030's four bytes"):
            self.check("gb18030", [bytes([b1, b2, b3, b4]) for b1 in range(0x81, 0xFF) for b2 in range(0x30, 0x3A)
                                   for b3 in (0x81, 0x82, 0x99, 0xD2, 0xFE, rnd.randrange(0x81, 0xFF), 0x80, 0x30)
                                   for b4 in (0x30, 0x35, 0x39, 0x2F, 0x81)])
        with self.subTest("EUC-KR's make-up sequences"):
            jamo = list(range(0xA1, 0xD5)) + [0xA0, 0xD5, 0x41]
            self.check("euc_kr", [bytes([0xA4, 0xD4, 0xA4, x, 0xA4, y, 0xA4, z])
                                  for x in jamo for y in jamo for z in rnd.sample(jamo, 6)]
                       + [bytes([0xA4, 0xD4, 0xA4, 0xA1, 0xA4, 0xBF, 0xA4][:n]) for n in range(1, 8)])
        finals = list(b"@ABCDFIJOPQ") + rnd.sample(range(0x40, 0x5B), 2)
        escapes = [b"\x1b" + i + bytes([f]) for i in (b"$", b"$(", b"$)", b"(", b")", b".", b"&") for f in finals]
        for codec in base.GEN.ISO2022:
            with self.subTest(f"{codec}'s escape sequences"):
                self.check(codec, [e + p + bytes([c]) + b"!" for e in escapes
                                   for p in (b"", b"\x0e", b"\x1bN", b"\x1bx") for c in range(256)])
        with self.subTest("six bytes that end in ESC $ B"):
            for codec in base.GEN.ISO2022:
                self.check(codec, [b"\x1b" + bytes([a, b]) + b"\x1b$B!!" for a in b"$&()." for b in range(256)])
        with self.subTest("ISO-2022 escape sequences of every length"):
            for codec in ("iso2022_jp", "iso2022_kr"):
                self.check(codec, [b"\x1b" + i * n + b"Bx" + t for i in (b"$", b"(", b"0", b"\n") for n in range(18)
                                   for t in (b"", b"\x80")])


if __name__ == "__main__":
    unittest.main()
