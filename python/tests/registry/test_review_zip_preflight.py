"""Final-review item 6: a zip with ~1M central-directory records cost
~340 MB and 4 s inside zipfile.ZipFile() — which parses the whole central
directory and builds a ZipInfo per record — before the MAX_FILES cap could
apply. The verdict (INCOMPLETE) was right; the memory was not. The End Of
Central Directory record (and the ZIP64 one) is now read first, and the
archive is refused — INCOMPLETE, with a reason naming the limit — when the
declared entry count exceeds MAX_FILES, the declared directory size is
implausible, or the directory holds more record signatures than MAX_FILES
(a count field can lie), all BEFORE zipfile.ZipFile is constructed.

Archives are hand-built, stored (no compression), with empty members.
"""

import io
import struct
import time
import unittest
import zipfile
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import scan_bytes, zipball


def stored_zip(names, declare=None, zip64=False, cd_size=None, comment=b""):
    """Empty stored members named `names` (bytes); the end records may
    declare another entry count / directory size than the real ones."""
    body, cdir, off = [], [], 0
    for nm in names:
        lh = struct.pack("<4s5H3L2H", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, len(nm), 0) + nm
        cd = struct.pack("<4s6H3L5H2L", b"PK\x01\x02", 20, 20, 0, 0, 0, 0x21, 0, 0, 0,
                         len(nm), 0, 0, 0, 0, 0, off) + nm
        body.append(lh)
        cdir.append(cd)
        off += len(lh)
    body, cdir = b"".join(body), b"".join(cdir)
    n = len(names) if declare is None else declare
    size = len(cdir) if cd_size is None else cd_size
    if zip64:
        eocd64 = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, n, n, size, len(body))
        loc64 = struct.pack("<4sLQL", b"PK\x06\x07", 0, len(body) + len(cdir), 1)
        eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, len(comment)) + comment
        return body + cdir + eocd64 + loc64 + eocd
    eocd = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, min(n, 0xFFFF), min(n, 0xFFFF),
                       min(size, 0xFFFFFFFF), len(body), len(comment)) + comment
    return body + cdir + eocd


def names(count, prefix=b"x/m"):
    return [prefix + str(i).encode() + b".py" for i in range(count)]


class PreflightTests(unittest.TestCase):
    def scan_refused(self, data):
        """Scan a wheel with zipfile.ZipFile made unusable: the preflight
        must decide before it is constructed."""
        with mock.patch.object(repo.zipfile, "ZipFile",
                               side_effect=AssertionError("ZipFile constructed")):
            res = scan_bytes(data, container="zip", artifact="wheel", eco="pypi")
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        trunc = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(len(trunc), 1, res["issues"])
        return trunc[0]["msg"]

    def test_hundred_thousand_records_refused_before_zipfile(self):
        data = stored_zip([b"a"] * 100_000, zip64=True)
        t = time.monotonic()
        msg = self.scan_refused(data)
        self.assertLess(time.monotonic() - t, 10)
        self.assertIn("declares 100,000 entries", msg)
        self.assertIn(f"{repo.MAX_FILES:,}-file limit", msg)

    def test_classic_end_record_count(self):
        msg = self.scan_refused(stored_zip(names(repo.MAX_FILES + 1)))
        self.assertIn(f"declares {repo.MAX_FILES + 1:,} entries", msg)

    def test_lying_count_is_caught_by_the_record_count(self):
        for zip64 in (False, True):
            with self.subTest(zip64=zip64):
                msg = self.scan_refused(stored_zip(names(repo.MAX_FILES + 50), declare=1,
                                                   zip64=zip64))
                self.assertIn(f"more than {repo.MAX_FILES:,} entries", msg)
                self.assertIn("1 declared", msg)

    def test_implausible_directory_size(self):
        msg = self.scan_refused(stored_zip(names(3), cd_size=repo.MAX_ZIP_CENTRAL_DIR + 1,
                                           zip64=True))
        self.assertIn("central directory declares", msg)
        self.assertIn("bytes", msg)

    def test_end_record_behind_an_archive_comment(self):
        with mock.patch.object(repo, "MAX_FILES", 5):
            msg = self.scan_refused(stored_zip(names(8), comment=b"c" * 300))
        self.assertIn("declares 8 entries", msg)

    def test_small_archives_still_scan(self):
        # vacuity guards: a normal wheel, a ZIP64-format one, one with a
        # comment, and exactly MAX_FILES entries (with the cap lowered)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.comment = b"built by a tool that leaves a comment"
            zf.writestr("x/__init__.py", "V = 1\n")
        cases = {"wheel": zipball({"x/__init__.py": "V = 1\n"}),
                 "zip64": stored_zip(names(3), zip64=True),
                 "comment": buf.getvalue(),
                 "at_cap": stored_zip(names(5))}
        with mock.patch.object(repo, "MAX_FILES", 5):
            for label, data in cases.items():
                with self.subTest(case=label):
                    self.assertIsNone(repo._zip_preflight(data))
                    res = scan_bytes(data, container="zip", artifact="wheel", eco="pypi")
                    self.assertEqual(res["verdict"], "OK", res["issues"])
                    self.assertGreaterEqual(res["filesScanned"], 1)

    def test_not_a_zip_is_left_to_zipfile(self):
        self.assertIsNone(repo._zip_preflight(b"not a zip at all"))
        res = scan_bytes(b"not a zip at all", container="zip", artifact="wheel", eco="pypi")
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertTrue(any("not a readable zip archive" in i["msg"] for i in res["issues"]))


def zip_with_bad_crc(files, symlinks, bad):
    """Stored zip; the central-directory CRC of member `bad` is wrong, so
    reading it raises BadZipFile (what a corrupted download looks like)."""
    import stat
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
        for path, target in symlinks.items():
            info = zipfile.ZipInfo(path)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    data = bytearray(buf.getvalue())
    pos = 0
    while True:
        pos = data.index(b"PK\x01\x02", pos)
        name_len = struct.unpack_from("<H", data, pos + 28)[0]
        if bytes(data[pos + 46:pos + 46 + name_len]) == bad.encode():
            struct.pack_into("<L", data, pos + 16, 0xDEADBEEF)
            return bytes(data)
        pos += 4


class ZipLinkReadTests(unittest.TestCase):
    """Final-review item 7 (repo.py audit): a zip symlink whose own entry
    could not be read was reported as "link to '' points outside the
    archive" — SC-ARCHIVE-LINK, a WARN — although what it installs was never
    scanned; and a link whose TARGET could not be read raised out of the
    archive reader, failing the whole package instead of marking it."""

    def test_unreadable_link_is_incomplete_not_warn(self):
        data = zip_with_bad_crc({"x-1.0/x/__init__.py": "V = 1\n"},
                                {"x-1.0/x/run.py": "__init__.py"}, bad="x-1.0/x/run.py")
        res = scan_bytes(data, container="zip", artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "INCOMPLETE", res["issues"])
        self.assertFalse(any(i["rule"] == "SC-ARCHIVE-LINK" for i in res["issues"]))
        self.assertTrue(any("link x/run.py could not be read" in i["msg"]
                            for i in res["issues"] if i["rule"] == "SC-TRUNCATED"))

    def test_unreadable_link_target_is_incomplete_not_an_error(self):
        data = zip_with_bad_crc({"x-1.0/x/__init__.py": "V = 1\n"},
                                {"x-1.0/x/run.py": "__init__.py"}, bad="x-1.0/x/__init__.py")
        res = scan_bytes(data, container="zip", artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "INCOMPLETE")
        msgs = [i["msg"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertTrue(any("link target x/__init__.py of x/run.py" in m for m in msgs), msgs)


if __name__ == "__main__":
    unittest.main()
