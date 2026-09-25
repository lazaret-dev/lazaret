"""Review items 6 and 7 (FIX-SPEC 9): size cap and magic bytes.

6. Any file over 2 MB — a 2.5 MB hero.jpg, a 2.1 MB package-lock.json — was a
   CRITICAL SC-TRUNCATED that failed the gate. The cap now applies only to
   files that would be read whole (sources, package.json, binding.gyp).
7. Repo-mode binary detection went by extension only: an ELF copied to
   `helper`, `logo.png` or `data.bin` was not flagged, and nested archives /
   opaque blobs were never checked. Every non-source regular file is now
   classified from a header sample by magic bytes (classify_binary).

Binary fixtures are synthetic headers (an ELF magic followed by zeros, a zip
local-file header ...); nothing is executable.
"""
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support
from lazaret.scanner import core

PY = sys.executable
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 1017
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 100
ZIP = b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 200
TAR = b"notes.txt".ljust(257, b"\x00") + b"ustar\x0000" + b"\x00" * 250
BLOB = random.Random(1234).getrandbits(8 * 4096).to_bytes(4096, "little")


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-bin-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def run_cli(root, *extra):
    out = tempfile.mkdtemp(prefix="lz-review-out-")
    try:
        p = subprocess.run([PY, _support.CLI, root, "--out-dir", out, "--no-html", *extra],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        report = None
        path = os.path.join(out, "lazaret-report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return p, report


def by_file(res):
    out = {}
    for i in res["issues"]:
        out.setdefault(i["file"].replace(os.sep, "/"), set()).add(i["rule"])
    return out


class MagicBytes(unittest.TestCase):
    def test_disguised_binaries_are_flagged(self):
        root = make_tree({"a.py": "x = 1\n", "helper": ELF, "logo.png": ELF, "data.bin": ELF,
                          "lib.so": ELF, "notes.txt": ZIP, "bundle.dat": TAR, "blob.dat": BLOB,
                          "real.png": PNG, "photo.jpg": JPEG, "README.md": "# hi\n",
                          "doc.docx": ZIP})
        self.addCleanup(shutil.rmtree, root, True)
        files = by_file(core.scan_project(root))
        for name in ("helper", "logo.png", "data.bin", "lib.so"):
            self.assertEqual(files.get(name), {"SC-BINARY"}, name)
        self.assertEqual(files.get("notes.txt"), {"SC-NESTED-ARCHIVE"})
        self.assertEqual(files.get("bundle.dat"), {"SC-NESTED-ARCHIVE"})
        self.assertEqual(files.get("blob.dat"), {"SC-OPAQUE-BLOB"})
        for name in ("real.png", "photo.jpg", "README.md", "doc.docx", "a.py"):
            self.assertNotIn(name, files, name)

    def test_only_a_header_sample_is_read(self):
        root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, "disk.img"), "wb") as fh:
            fh.write(ELF)
            fh.truncate(3 * 1024 ** 3)          # sparse 3 GB: never read whole
        reads = []
        real = core._read_prefix

        def spy(path, limit):
            reads.append((os.path.basename(path), limit))
            return real(path, limit)
        from unittest import mock
        with mock.patch.object(core, "_read_prefix", spy):
            files = by_file(core.scan_project(root))
        self.assertEqual(files.get("disk.img"), {"SC-BINARY"})
        self.assertIn(("disk.img", core.HEADER_SAMPLE_BYTES), reads)
        self.assertEqual(core.HEADER_SAMPLE_BYTES, 512)


class SizeCap(unittest.TestCase):
    def test_cap_only_for_files_read_whole(self):
        big = 2_100_000
        root = make_tree({
            "a.py": "x = 1\n",
            "hero.jpg": JPEG + b"\x00" * 2_500_000,
            "package-lock.json": '{"lockfileVersion": 3, "pad": "' + "a" * big + '"}',
            "data.csv": "a,b\n" * 600_000,
        })
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_cli(root, "--ci")
        self.assertEqual(p.returncode, 0, p.stdout[-600:])    # used to fail the gate
        self.assertTrue(report["pass"])
        self.assertFalse([i for i in report["issues"] if i["rule"] == "SC-TRUNCATED"])

    def test_oversize_source_and_manifest_are_truncated(self):
        root = make_tree({
            "a.py": "x = 1\n",
            "big.py": "x = 1\n" * 400_000,
            "sub/package.json": '{"pad": "' + "a" * 2_100_000 + '"}',
        })
        self.addCleanup(shutil.rmtree, root, True)
        with open(os.path.join(root, "huge.js"), "wb") as fh:
            fh.truncate(5 * 1024 ** 3)          # sparse: rejected by size, never read
        files = by_file(core.scan_project(root))
        for name in ("big.py", "sub/package.json", "huge.js"):
            self.assertEqual(files.get(name), {"SC-TRUNCATED"}, name)
        msg = [i["msg"] for i in core.scan_project(root)["issues"] if i["file"] == "big.py"][0]
        self.assertEqual(msg, "File not fully scanned: 2,400,000 bytes exceeds the "
                              "2,000,000-byte file limit.")


if __name__ == "__main__":
    unittest.main()
