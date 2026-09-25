import io
import unittest

import lazaret.safexml as sx
from lazaret.safexml import ElementTree as ET

from ._harness import APIS


def nested(depth):
    return b"<a>" * depth + b"x" + b"</a>" * depth


class LimitTests(unittest.TestCase):
    def test_default_depth_limit(self):
        for name, api in APIS.items():
            with self.subTest(api=name):
                api(nested(sx.DEFAULT_MAX_DEPTH))
                with self.assertRaisesRegex(sx.LimitExceeded, "max_depth=500"):
                    api(nested(sx.DEFAULT_MAX_DEPTH + 1))

    def test_custom_and_disabled_depth_limit(self):
        for name, api in APIS.items():
            with self.subTest(api=name):
                with self.assertRaises(sx.LimitExceeded):
                    api(nested(11), max_depth=10)
                api(nested(3000), max_depth=None)

    def test_depth_counts_nesting_not_elements(self):
        wide = b"<r>" + b"<a><b/></a>" * 5000 + b"</r>"
        for name, api in APIS.items():
            with self.subTest(api=name):
                api(wide, max_depth=3)

    def test_size_limit(self):
        doc = b"<r>" + b"<a>payload</a>" * 100 + b"</r>"
        for name, api in APIS.items():
            with self.subTest(api=name):
                api(doc, max_bytes=len(doc))
                with self.assertRaisesRegex(sx.LimitExceeded, "max_bytes"):
                    api(doc, max_bytes=len(doc) - 1)

    def test_size_limit_streams_without_reading_everything(self):
        class Endless(io.RawIOBase):
            reads = 0

            def readable(self):
                return True

            def readinto(self, buffer):
                Endless.reads += 1
                chunk = b"<r>" if Endless.reads == 1 else b"<a/>" * (len(buffer) // 4)
                buffer[:len(chunk)] = chunk
                return len(chunk)

        with self.assertRaises(sx.LimitExceeded):
            for _ in ET.iterparse(io.BufferedReader(Endless()), max_bytes=1_000_000):
                pass
        self.assertLess(Endless.reads, 200)  # stopped soon after the limit, not at end of stream

    def test_option_validation(self):
        for bad in (0, -1, 1.5, "10"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    sx.Options(max_depth=bad)
                with self.assertRaises(ValueError):
                    ET.fromstring(b"<a/>", max_bytes=bad)


if __name__ == "__main__":
    unittest.main()
