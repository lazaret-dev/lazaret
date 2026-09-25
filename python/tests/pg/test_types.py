import ipaddress
import unittest
import uuid
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

from lazaret.pg import _types as t


class DecodeTests(unittest.TestCase):
    def test_decode_timestamp(self):
        cases = [
            ("2026-09-24 13:30:00", datetime(2026, 9, 24, 13, 30)),
            ("2026-09-24 13:30:00.5", datetime(2026, 9, 24, 13, 30, 0, 500000)),
            ("2026-09-24 13:30:00.123456+00", datetime(2026, 9, 24, 13, 30, 0, 123456, timezone.utc)),
            ("2026-09-24 13:30:00+05:30", datetime(2026, 9, 24, 13, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))),
            ("1850-01-01 00:00:00-05:50:36", datetime(1850, 1, 1, tzinfo=timezone(-timedelta(hours=5, minutes=50, seconds=36)))),
            ("infinity", "infinity"),
            ("-infinity", "-infinity"),
            ("0044-03-15 12:00:00 BC", "0044-03-15 12:00:00 BC"),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(t.decode_timestamp(text), expected)

    def test_decode_date_time(self):
        self.assertEqual(t.decode_date("2026-09-24"), date(2026, 9, 24))
        self.assertEqual(t.decode_date("infinity"), "infinity")
        self.assertEqual(t.decode_time("13:30:05.25"), time(13, 30, 5, 250000))
        self.assertEqual(t.decode_time("13:30:05-07"), time(13, 30, 5, tzinfo=timezone(-timedelta(hours=7))))
        self.assertEqual(t.decode_time("24:00:00"), "24:00:00")

    def test_decode_interval(self):
        cases = [
            ("PT0S", timedelta(0)),
            ("P1DT2H3M4.5S", timedelta(days=1, hours=2, minutes=3, seconds=4.5)),
            ("P-1DT-1H", timedelta(days=-1, hours=-1)),
            ("PT-0.000001S", timedelta(microseconds=-1)),
            ("P2W", timedelta(weeks=2)),
            ("P1M", "P1M"),          # months have no fixed length
            ("P1Y2M3D", "P1Y2M3D"),
            ("1 day", "1 day"),      # non-ISO style falls back to text
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(t.decode_interval(text), expected)

    def test_decode_bytea(self):
        self.assertEqual(t.decode_bytea("\\x00ff10"), b"\x00\xff\x10")
        self.assertEqual(t.decode_bytea("a\\000b\\\\c\\377"), b"a\x00b\\c\xff")

    def test_parse_array(self):
        cases = [
            ("{}", []),
            ("{1,2,3}", ["1", "2", "3"]),
            ("{1,NULL,3}", ["1", None, "3"]),
            ('{"NULL",NULL}', ["NULL", None]),
            ('{"a,b","c\\"d","e\\\\f","{x}"," "}', ["a,b", 'c"d', "e\\f", "{x}", " "]),
            ("{{1,2},{3,4}}", [["1", "2"], ["3", "4"]]),
            ("[0:1]={7,8}", ["7", "8"]),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(t.parse_array(text, str), expected)

    def test_parse_array_rejects_malformed(self):
        for bad in ("{1,2", "{1,2}}", "{", "1,2}"):
            with self.subTest(bad=bad), self.assertRaises((ValueError, IndexError)):
                t.parse_array(bad, str)

    def test_decoder_falls_back_to_text_on_bad_values(self):
        dec = t.decoder_for(t.INT4, t.DECODERS)
        self.assertEqual(dec(b"42"), 42)
        self.assertEqual(dec(b"not a number"), "not a number")
        self.assertEqual(t.decoder_for(1007, t.DECODERS)(b"{1,NULL,3}"), [1, None, 3])
        self.assertEqual(t.decoder_for(999999, t.DECODERS)(b"custom"), "custom")


class EncodeTests(unittest.TestCase):
    def test_encode_scalars(self):
        cases = [
            (None, 0, None),
            (True, t.BOOL, b"t"),
            (False, t.BOOL, b"f"),
            (42, t.INT8, b"42"),
            (-(2**63), t.INT8, str(-(2**63)).encode()),
            (2**63, t.NUMERIC, str(2**63).encode()),
            (1.5, t.FLOAT8, b"1.5"),
            (float("nan"), t.FLOAT8, b"NaN"),
            (float("-inf"), t.FLOAT8, b"-Infinity"),
            (Decimal("1.10"), t.NUMERIC, b"1.10"),
            ("héllo", 0, "héllo".encode()),
            (date(2026, 9, 24), t.DATE, b"2026-09-24"),
            (datetime(2026, 9, 24, 1, 2, 3), t.TIMESTAMP, b"2026-09-24 01:02:03"),
            (datetime(2026, 9, 24, 1, 2, 3, tzinfo=timezone.utc), t.TIMESTAMPTZ, b"2026-09-24 01:02:03+00:00"),
            (time(1, 2, 3), t.TIME, b"01:02:03"),
            (timedelta(days=-1, seconds=5), t.INTERVAL, b"-1 days +5.000000 seconds"),
            (uuid.UUID(int=1), t.UUID, b"00000000-0000-0000-0000-000000000001"),
            ({"a": [1, 2]}, t.JSONB, b'{"a": [1, 2]}'),
            (t.Json([1, "x"]), t.JSONB, b'[1, "x"]'),
            (ipaddress.ip_address("10.0.0.1"), t.INET, b"10.0.0.1"),
            (ipaddress.ip_network("10.0.0.0/8"), t.CIDR, b"10.0.0.0/8"),
        ]
        for value, oid, payload in cases:
            with self.subTest(value=value):
                self.assertEqual(t.encode_param(value), (oid, 0, payload))

    def test_encode_bytes_uses_binary_format(self):
        self.assertEqual(t.encode_param(b"\x00\x01"), (t.BYTEA, 1, b"\x00\x01"))
        self.assertEqual(t.encode_param(bytearray(b"ab")), (t.BYTEA, 1, b"ab"))

    def test_encode_arrays(self):
        cases = [
            ([1, 2, None], 1016, '{"1","2",NULL}'),
            (["a,b", 'q"', "back\\slash"], 1009, '{"a,b","q\\"","back\\\\slash"}'),
            ([[1, 2], [3, 4]], 1016, '{{"1","2"},{"3","4"}}'),
            ([1, 2.5], 1022, '{"1","2.5"}'),
            ([], 0, "{}"),
            ([None], 0, "{NULL}"),
            ([b"\x01"], 1001, '{"\\\\x01"}'),
        ]
        for value, oid, literal in cases:
            with self.subTest(value=value):
                self.assertEqual(t.encode_param(value), (oid, 0, literal.encode()))

    def test_encode_rejects_mixed_arrays_and_unknown_types(self):
        with self.assertRaises(TypeError):
            t.encode_param([1, "a"])
        with self.assertRaises(TypeError):
            t.encode_param(object())


class RowTests(unittest.TestCase):
    def test_row_access(self):
        Row = t.row_class(("id", "name", "count"))
        r = Row((1, "x", 5))
        self.assertEqual((r[0], r["name"], r.id), (1, "x", 1))
        self.assertEqual(r["count"], 5)  # attribute access would hit tuple.count
        self.assertEqual(r.as_dict(), {"id": 1, "name": "x", "count": 5})
        self.assertEqual(r.get("missing", "d"), "d")
        self.assertEqual(r, (1, "x", 5))
        self.assertEqual(repr(r), "Row(id=1, name='x', count=5)")
        with self.assertRaises(KeyError):
            r["missing"]
        with self.assertRaises(AttributeError):
            r.missing


if __name__ == "__main__":
    unittest.main()
