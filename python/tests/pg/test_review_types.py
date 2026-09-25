"""Review fixes in value encoding and decoding (lazaret.pg._types)."""

import unittest
from datetime import timedelta

from lazaret.pg import _types as t


class IntervalEncodingTests(unittest.TestCase):
    def test_every_field_carries_its_own_sign(self):
        # Under IntervalStyle=sql_standard a leading "-" applies to all
        # following unsigned fields: "-1 days 5 seconds" meant -86405 s.
        cases = [
            (timedelta(days=-1, seconds=5), b"-1 days +5.000000 seconds"),
            (timedelta(days=3, hours=4, microseconds=5), b"+3 days +14400.000005 seconds"),
            (timedelta(0), b"+0 days +0.000000 seconds"),
            (timedelta(microseconds=-1), b"-1 days +86399.999999 seconds"),
        ]
        for value, payload in cases:
            with self.subTest(value=value):
                self.assertEqual(t.encode_param(value), (t.INTERVAL, 0, payload))


if __name__ == "__main__":
    unittest.main()
