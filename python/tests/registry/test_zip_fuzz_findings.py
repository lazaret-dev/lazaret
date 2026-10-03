"""The zip reader on what the 0.1.9 lane's fuzzers found (Oct 3, 2026;
audits/lazaret-fuzz-findings-2026-10-03.md):

F-2  entries that overlap (the shape of a zip bomb) were a warning on
     Python 3.12.3+, an exception out of the reader under -W error, and no
     anomaly on any version: now SC-ARCHIVE-OVERLAP, the same on every one;
F-6  an entry with no name raised IndexError out of the reader on Python
     3.10 (ZipInfo.is_dir) and was dropped without a word on 3.11+: now an
     anomaly (SC-ARCHIVE-PATH), and the entry is not read;
F-7  an LZMA entry declaring a 4 GiB dictionary raised MemoryError out of the
     reader where memory is capped: a dictionary over MAX_LZMA_DICT is
     refused before zipfile allocates it, and MemoryError reading an entry
     makes it corrupt.

The archives are built by hand; nothing in them runs.
"""
import io
import struct
import unittest
import warnings
import zipfile
import zlib
from unittest import mock

from lazaret.registry import repo


def build(entries):
    """Zip bytes from (name, data, method, stored bytes or None) entries."""
    out, central = b"", b""
    for name, data, method, comp in entries:
        nb, comp = name.encode(), data if comp is None else comp
        crc, off, ver = zlib.crc32(data) & 0xffffffff, len(out), 63 if method == zipfile.ZIP_LZMA else 20
        out += struct.pack("<IHHHHHIIIHH", 0x04034b50, ver, 0, method, 0, 0x21, crc, len(comp), len(data),
                           len(nb), 0) + nb + comp
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014b50, ver, ver, 0, method, 0, 0x21, crc, len(comp),
                               len(data), len(nb), 0, 0, 0, 0, 0o644 << 16, off) + nb
    return out + central + struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, len(entries), len(entries), len(central),
                                       len(out), 0)


def overlapping():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.py", b"x = 1\n")
        zf.writestr("b.py", b"y = 2\n")
    data = bytearray(buf.getvalue())
    first = data.find(b"PK\x01\x02")
    second = data.find(b"PK\x01\x02", first + 4)
    data[second + 42:second + 46] = data[first + 42:first + 46]       # b.py starts where a.py does
    return bytes(data)


def read(data, artifact="wheel"):
    anomalies = []
    with warnings.catch_warnings():
        warnings.simplefilter("error")                 # a warning out of the reader fails the test
        members = [(m[0], m[3], getattr(m, "detail", "")) for m in
                   repo.iter_archive(data, "zip", artifact, anomalies=anomalies)]
    return members, anomalies


class OverlapTests(unittest.TestCase):
    def test_entries_that_overlap(self):
        members, anomalies = read(overlapping())
        self.assertEqual([(n, r) for n, r, _d in members], [("a.py", None), ("b.py", "corrupt")])
        self.assertEqual(anomalies, [("overlap", "b.py", "its bytes overlap another entry's")])

    def test_the_finding(self):
        rules = {(i["rule"], i["sev"]) for i in repo._scan_artifact(overlapping(), "zip", "wheel", False,
                                                                   None)["issues"]}
        self.assertIn(("SC-ARCHIVE-OVERLAP", "MAJOR"), rules)

    def test_a_plain_archive_does_not_overlap(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(6):
                zf.writestr(f"pkg/m{i}.py", "x = 1\n" * (i * 40 + 1))
        members, anomalies = read(buf.getvalue())
        self.assertEqual((len(members), anomalies), (6, []))


class NamelessTests(unittest.TestCase):
    def test_an_entry_with_no_name(self):
        members, anomalies = read(build([("a.py", b"x = 1\n", 0, None), ("", b"y = 2\n", 0, None)]))
        self.assertEqual([(n, r) for n, r, _d in members], [("a.py", None)])
        self.assertEqual(anomalies, [("noname", "(archive)", "an entry with no name, which was not read")])


class LzmaTests(unittest.TestCase):
    def test_a_huge_dictionary_is_refused_before_it_is_allocated(self):
        props = bytes([0x5d]) + (0xfbff8300).to_bytes(4, "little")
        stored = b"\x09\x14" + (5).to_bytes(2, "little") + props + b"\x00" * 32
        data = build([("a.py", b"x = 1\n", 0, None), ("b.py", b"y = 2\n", zipfile.ZIP_LZMA, stored)])
        with mock.patch("lzma.LZMADecompressor", side_effect=AssertionError("a decompressor was made")):
            members, _anomalies = read(data, "sdist")
        self.assertEqual(members[1][:2], ("b.py", "corrupt"))
        self.assertIn("an LZMA dictionary of 4,227,826,432 bytes, over the 67,108,864-byte limit", members[1][2])

    def test_a_dictionary_in_bounds_is_read(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_LZMA) as zf:
            zf.writestr("a.py", "x = 1\n" * 100)
        members, _anomalies = read(buf.getvalue(), "sdist")
        self.assertEqual([(n, r) for n, r, _d in members], [("a.py", None)])

    def test_memory_error_reading_an_entry(self):
        real_open = zipfile.ZipFile.open

        def open_(zf, name, *a, **kw):
            if getattr(name, "filename", name) == "b.py":
                raise MemoryError
            return real_open(zf, name, *a, **kw)
        data = build([("a.py", b"x = 1\n", 0, None), ("b.py", b"y = 2\n", 0, None)])
        with mock.patch.object(zipfile.ZipFile, "open", open_):
            members, _anomalies = read(data)
        self.assertEqual([(n, r) for n, r, _d in members], [("a.py", None), ("b.py", "corrupt")])


if __name__ == "__main__":
    unittest.main()
