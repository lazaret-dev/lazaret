"""Conversion between Python values and PostgreSQL's text wire format.

Results are always requested in text format and decoded by type OID. Values
that cannot be represented in Python (infinity timestamps, BC dates, intervals
with months) are returned as the server's text rather than raising.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import re
import uuid
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable

# --- type OIDs ----------------------------------------------------------------
BOOL, BYTEA, CHAR, NAME, INT8, INT2, INT4, TEXT, OID = 16, 17, 18, 19, 20, 21, 23, 25, 26
JSON, CIDR, FLOAT4, FLOAT8, UNKNOWN, INET = 114, 650, 700, 701, 705, 869
BPCHAR, VARCHAR, DATE, TIME, TIMESTAMP, TIMESTAMPTZ, INTERVAL = 1042, 1043, 1082, 1083, 1114, 1184, 1186
TIMETZ, NUMERIC, UUID, JSONB = 1266, 1700, 2950, 3802

ARRAY_ELEMENT = {
    1000: BOOL, 1001: BYTEA, 1002: CHAR, 1003: NAME, 1005: INT2, 1007: INT4, 1009: TEXT,
    1014: BPCHAR, 1015: VARCHAR, 1016: INT8, 1021: FLOAT4, 1022: FLOAT8, 1028: OID,
    1041: INET, 651: CIDR, 1115: TIMESTAMP, 1182: DATE, 1183: TIME, 1185: TIMESTAMPTZ,
    1187: INTERVAL, 1231: NUMERIC, 1270: TIMETZ, 2951: UUID, 199: JSON, 3807: JSONB,
}
ARRAY_OF = {elem: arr for arr, elem in ARRAY_ELEMENT.items()}


class Json:
    """Wrap a value to send it as jsonb (needed for lists and strings, which
    would otherwise be sent as arrays and text). Dicts are sent as jsonb
    automatically."""

    __slots__ = ("obj",)

    def __init__(self, obj: Any):
        self.obj = obj

    def __repr__(self) -> str:
        return f"Json({self.obj!r})"


# --- decoding (server text -> Python) -------------------------------------------

_TS_RE = re.compile(
    r"(\d{4})-(\d\d)-(\d\d)[ T](\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?"
    r"(?:([+-])(\d\d)(?::?(\d\d))?(?::?(\d\d))?)?"
)
_DATE_RE = re.compile(r"(\d{4})-(\d\d)-(\d\d)")
_TIME_RE = re.compile(r"(\d\d):(\d\d):(\d\d)(?:\.(\d{1,6}))?(?:([+-])(\d\d)(?::?(\d\d))?(?::?(\d\d))?)?")
_INTERVAL_RE = re.compile(
    r"P(?:(-?\d+)Y)?(?:(-?\d+)M)?(?:(-?\d+)W)?(?:(-?\d+)D)?"
    r"(?:T(?:(-?\d+)H)?(?:(-?\d+)M)?(?:(-?\d+(?:\.\d+)?)S)?)?"
)


def _tz(sign: str | None, hh: str | None, mm: str | None, ss: str | None) -> timezone | None:
    if not sign:
        return None
    offset = timedelta(hours=int(hh), minutes=int(mm or 0), seconds=int(ss or 0))
    return timezone(-offset if sign == "-" else offset)


def _micro(frac: str | None) -> int:
    return int(frac.ljust(6, "0")) if frac else 0


def decode_timestamp(s: str) -> datetime | str:
    m = _TS_RE.fullmatch(s)
    if not m:
        return s  # infinity, -infinity, BC, or year > 9999
    y, mo, d, h, mi, sec, frac, sign, th, tm, ts = m.groups()
    return datetime(int(y), int(mo), int(d), int(h), int(mi), int(sec), _micro(frac), _tz(sign, th, tm, ts))


def decode_date(s: str) -> date | str:
    m = _DATE_RE.fullmatch(s)
    return date(*map(int, m.groups())) if m else s


def decode_time(s: str) -> time | str:
    m = _TIME_RE.fullmatch(s)
    if not m:
        return s
    h, mi, sec, frac, sign, th, tm, ts = m.groups()
    if int(h) == 24:  # PostgreSQL allows 24:00:00; Python does not
        return s
    return time(int(h), int(mi), int(sec), _micro(frac), _tz(sign, th, tm, ts))


def decode_interval(s: str) -> timedelta | str:
    """Decodes IntervalStyle=iso_8601 output. Intervals with years or months
    have no fixed length, so they are returned as text."""
    m = _INTERVAL_RE.fullmatch(s)
    if not m or s == "P":
        return s
    years, months, weeks, days, hours, minutes, seconds = m.groups()
    if (years and int(years)) or (months and int(months)):
        return s
    micros = int(Decimal(seconds) * 1_000_000) if seconds else 0
    return timedelta(
        weeks=int(weeks or 0), days=int(days or 0), hours=int(hours or 0),
        minutes=int(minutes or 0), microseconds=micros,
    )


def decode_bytea(s: str) -> bytes:
    if s.startswith("\\x"):
        return bytes.fromhex(s[2:])
    # bytea_output = 'escape'
    out, i, raw = bytearray(), 0, s.encode("latin-1")
    while i < len(raw):
        if raw[i] == 0x5C:  # backslash
            if raw[i + 1] == 0x5C:
                out.append(0x5C)
                i += 2
            else:
                out.append(int(raw[i + 1:i + 4], 8))
                i += 4
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


def decode_inet(s: str) -> Any:
    return ipaddress.ip_interface(s) if "/" in s else ipaddress.ip_address(s)


def parse_array(s: str, element: Callable[[str], Any]) -> list:
    """Parse PostgreSQL's array text format, e.g. {1,NULL,"a,b"} or {{1,2},{3,4}}."""
    if s.startswith("["):  # explicit bounds such as [0:2]={...}
        s = s[s.index("=") + 1:]
    value, pos = _parse_array_level(s, 0, element)
    if pos != len(s):
        raise ValueError("trailing data after array")
    return value


def _parse_array_level(s: str, pos: int, element: Callable[[str], Any]) -> tuple[list, int]:
    if s[pos] != "{":
        raise ValueError("expected '{'")
    pos += 1
    out: list = []
    if s[pos] == "}":
        return out, pos + 1
    while True:
        c = s[pos]
        if c == "{":
            sub, pos = _parse_array_level(s, pos, element)
            out.append(sub)
        elif c == '"':
            pos += 1
            buf = []
            while s[pos] != '"':
                if s[pos] == "\\":
                    pos += 1
                buf.append(s[pos])
                pos += 1
            pos += 1
            out.append(element("".join(buf)))
        else:
            start = pos
            while s[pos] not in ",}":
                pos += 1
            token = s[start:pos]
            out.append(None if token == "NULL" else element(token))
        if s[pos] == ",":
            pos += 1
        elif s[pos] == "}":
            return out, pos + 1
        else:
            raise ValueError("malformed array")


def _decimal(s: str) -> Decimal:
    return Decimal(s)


DECODERS: dict[int, Callable[[str], Any]] = {
    BOOL: lambda s: s == "t",
    BYTEA: decode_bytea,
    INT2: int, INT4: int, INT8: int, OID: int,
    FLOAT4: float, FLOAT8: float,
    NUMERIC: _decimal,
    JSON: json.loads, JSONB: json.loads,
    UUID: uuid.UUID,
    DATE: decode_date,
    TIME: decode_time, TIMETZ: decode_time,
    TIMESTAMP: decode_timestamp, TIMESTAMPTZ: decode_timestamp,
    INTERVAL: decode_interval,
    INET: decode_inet, CIDR: ipaddress.ip_network,
}


def decoder_for(oid: int, decoders: dict[int, Callable[[str], Any]]) -> Callable[[bytes], Any]:
    """Return a function bytes -> value. Anything that fails to convert comes
    back as the server's text, so an odd server setting never crashes a query."""
    fn = decoders.get(oid)
    if fn is None and oid in ARRAY_ELEMENT:
        elem = decoders.get(ARRAY_ELEMENT[oid], str)
        fn = functools.partial(parse_array, element=elem)
    if fn is None:
        return _decode_text

    def decode(raw: bytes, fn=fn) -> Any:
        text = raw.decode("utf-8")
        try:
            return fn(text)
        except (ValueError, IndexError, ArithmeticError):
            return text

    return decode


def _decode_text(raw: bytes) -> str:
    return raw.decode("utf-8")


# --- encoding (Python -> server) -------------------------------------------------

_INT8_MIN, _INT8_MAX = -(2**63), 2**63 - 1


def _float_text(v: float) -> str:
    if v != v:
        return "NaN"
    if v in (float("inf"), float("-inf")):
        return "Infinity" if v > 0 else "-Infinity"
    return repr(v)


def _scalar(v: Any) -> tuple[int, str]:
    """(type OID, text) for a non-None scalar. OID 0 lets the server infer the type."""
    if isinstance(v, bool):
        return BOOL, "t" if v else "f"
    if isinstance(v, int):
        return (INT8 if _INT8_MIN <= v <= _INT8_MAX else NUMERIC), str(v)
    if isinstance(v, float):
        return FLOAT8, _float_text(v)
    if isinstance(v, Decimal):
        return NUMERIC, str(v)
    if isinstance(v, str):
        return 0, v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return BYTEA, "\\x" + bytes(v).hex()
    if isinstance(v, datetime):
        aware = v.tzinfo is not None and v.utcoffset() is not None
        return (TIMESTAMPTZ if aware else TIMESTAMP), v.isoformat(sep=" ")
    if isinstance(v, date):
        return DATE, v.isoformat()
    if isinstance(v, time):
        aware = v.tzinfo is not None and v.utcoffset() is not None
        return (TIMETZ if aware else TIME), v.isoformat()
    if isinstance(v, timedelta):
        return INTERVAL, f"{v.days} days {v.seconds}.{v.microseconds:06d} seconds"
    if isinstance(v, uuid.UUID):
        return UUID, str(v)
    if isinstance(v, Json):
        return JSONB, json.dumps(v.obj, ensure_ascii=False)
    if isinstance(v, dict):
        return JSONB, json.dumps(v, ensure_ascii=False)
    if isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address,
                      ipaddress.IPv4Interface, ipaddress.IPv6Interface)):
        return INET, str(v)
    if isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return CIDR, str(v)
    raise TypeError(f"cannot send a value of type {type(v).__name__} as a query parameter")


def _quote_element(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _encode_array(v: list | tuple) -> tuple[int, str]:
    oids: set[int] = set()

    def walk(items: list | tuple) -> str:
        parts = []
        for item in items:
            if item is None:
                parts.append("NULL")
            elif isinstance(item, (list, tuple)):
                parts.append(walk(item))
            else:
                oid, text = _scalar(item)
                oids.add(oid)
                parts.append(_quote_element(text))
        return "{" + ",".join(parts) + "}"

    literal = walk(v)
    if not oids:
        return 0, literal  # empty or all NULL: let the server infer
    if oids == {INT8, FLOAT8}:
        oids = {FLOAT8}
    elif oids == {INT8, NUMERIC}:
        oids = {NUMERIC}
    if len(oids) > 1:
        raise TypeError("array parameters must contain values of a single type")
    elem = oids.pop()
    if elem == 0:
        return ARRAY_OF[TEXT], literal
    if elem not in ARRAY_OF:
        raise TypeError("unsupported array element type")
    return ARRAY_OF[elem], literal


def encode_param(v: Any) -> tuple[int, int, bytes | None]:
    """Return (type OID, format code, payload). Format 1 (binary) is used only
    for bytes, which avoids hex-encoding large blobs."""
    if v is None:
        return 0, 0, None
    if isinstance(v, (bytes, bytearray, memoryview)):
        return BYTEA, 1, bytes(v)
    if isinstance(v, (list, tuple)):
        oid, text = _encode_array(v)
    else:
        oid, text = _scalar(v)
    return oid, 0, text.encode("utf-8")


# --- rows ------------------------------------------------------------------------

@functools.lru_cache(maxsize=256)
def row_class(names: tuple[str, ...]) -> type:
    """A tuple subclass with access by index, by column name (row["id"]), and
    by attribute (row.id) when the name doesn't clash with a tuple method."""
    index: dict[str, int] = {}
    for i, name in enumerate(names):
        index.setdefault(name, i)

    class Row(tuple):
        __slots__ = ()
        _fields = names

        def __getitem__(self, key):
            if isinstance(key, str):
                try:
                    return tuple.__getitem__(self, index[key])
                except KeyError:
                    raise KeyError(key) from None
            return tuple.__getitem__(self, key)

        def __getattr__(self, name: str):
            try:
                return tuple.__getitem__(self, index[name])
            except KeyError:
                raise AttributeError(name) from None

        def get(self, key: str, default: Any = None) -> Any:
            return tuple.__getitem__(self, index[key]) if key in index else default

        def keys(self) -> tuple[str, ...]:
            return names

        def as_dict(self) -> dict[str, Any]:
            return dict(zip(names, self))

        def __repr__(self) -> str:
            return "Row(" + ", ".join(f"{n}={v!r}" for n, v in zip(names, self)) + ")"

    return Row


class Rows(list):
    """A list of Row objects that also carries the column names, which are
    available even when no rows matched."""

    columns: tuple[str, ...] = ()
