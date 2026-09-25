"""Review fixes in value encoding and decoding (lazaret.pg._types)."""

import enum
import unittest
from datetime import timedelta
from decimal import Decimal

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


class DecoderFallbackTests(unittest.TestCase):
    """Any decoder failure returns the text value instead of raising, because
    an exception while reading a DataRow aborts the connection."""

    def test_json_deeper_than_the_recursion_limit(self):
        deep = b"[" * 100_000 + b"]" * 100_000
        for oid in (t.JSON, t.JSONB):
            with self.subTest(oid=oid):
                self.assertEqual(t.decoder_for(oid, t.DECODERS)(deep), deep.decode())

    def test_registered_decoder_that_raises_anything(self):
        for exc in (KeyError("zzz"), TypeError("x"), RuntimeError("y"), AttributeError("z")):
            def broken(text, exc=exc):
                raise exc
            with self.subTest(exc=type(exc).__name__):
                self.assertEqual(t.decoder_for(25, {25: broken})(b"zzz"), "zzz")

    def test_non_utf8_bytes(self):
        self.assertEqual(t.decoder_for(t.INT4, t.DECODERS)(b"4\xff2"), "4\ufffd2")
        self.assertEqual(t.decoder_for(t.TEXT, t.DECODERS)(b"caf\xe9"), "caf\ufffd")
        self.assertEqual(t.decoder_for(1009, t.DECODERS)(b"{a,\xe9}"), "{a,\ufffd}")

    def test_keyboard_interrupt_is_not_swallowed(self):
        def interrupted(text):
            raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            t.decoder_for(25, {25: interrupted})(b"x")


class ParameterTypeTests(unittest.TestCase):
    """Integers get the smallest of int4/int8/numeric that holds them (the
    server casts integer types up, never down); str lists are untyped."""

    def test_integer_sizes(self):
        cases = [(0, t.INT4), (2**31 - 1, t.INT4), (-(2**31), t.INT4), (2**31, t.INT8),
                 (-(2**31) - 1, t.INT8), (2**63 - 1, t.INT8), (2**63, t.NUMERIC), (-(2**63) - 1, t.NUMERIC)]
        for value, oid in cases:
            with self.subTest(value=value):
                self.assertEqual(t.encode_param(value), (oid, 0, str(value).encode()))

    def test_int_enum_is_sent_as_its_value(self):
        class Level(enum.IntEnum):
            HIGH = 3
        self.assertEqual(t.encode_param(Level.HIGH), (t.INT4, 0, b"3"))

    def test_integer_arrays_widen_to_fit_every_element(self):
        cases = [([1, 2], 1007), ([1, 2**40], 1016), ([[1], [2**40]], 1016), ([1, 2**70], 1231),
                 ([1, Decimal("1.5")], 1231), ([1, 2.5], 1022), ([2**40, 2.5], 1022)]
        for value, oid in cases:
            with self.subTest(value=value):
                self.assertEqual(t.encode_param(value)[0], oid)
        for bad in ([2**70, 2.5], [Decimal(1), 2.5], [1, "a"]):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                t.encode_param(bad)

    def test_string_arrays_are_untyped(self):
        self.assertEqual(t.encode_param(["a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"]),
                         (0, 0, b'{"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"}'))
        self.assertEqual(t.encode_param([["a"], [None]])[0], 0)


if __name__ == "__main__":
    unittest.main()
