"""Review findings 2, 5, 9 and the path half of 13: reading archives the way
installers do.

2. tarfile stopped at one zero block or a bad-checksum header while npm's
   node-tar reads on (README + zero block + hooked package.json + payload
   => OK). Now: ignore_zeros, and a bad header, entries after an
   end-of-archive block or trailing data make the scan INCOMPLETE.
5. Hard/symbolic links were skipped although pip extracts them (an sdist whose
   setup.py is a link to docs/notes.txt => OK while pip ran the payload).
   Links are resolved and the target scanned under the link's name; a link
   out of the archive is SC-ARCHIVE-LINK. npm (pacote) drops links.
9. Oversize members were decompressed to be skipped without being charged,
   and "r:*" accepted bz2/xz inside a .tgz (277 bytes -> 256 MiB). Every
   decompressed byte now counts, the container's real codec is required,
   and a per-archive deadline makes the scan INCOMPLETE.
13. strip_root's lstrip("./") mapped ./decoy/setup.js onto setup.js: paths
   are now canonicalized exactly like node-tar strip:1, and two entries with
   the same path are SC-ARCHIVE-DUP.
"""

import bz2
import gzip
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
import zlib
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import (
    DECODE_EXEC_JS, DECODE_EXEC_PY, EXFIL_JS, hooks, issues, manifest, rules, scan_bytes,
    scan_wheel, tar_member)

HOOKED = hooks(postinstall="node index.js").encode()
PAYLOAD = DECODE_EXEC_JS.encode()


def zero_block_tgz():
    return gzip.compress(tar_member("package/README.md", b"hi\n") + b"\0" * 512
                         + tar_member("package/package.json", HOOKED)
                         + tar_member("package/index.js", PAYLOAD) + b"\0" * 1024)


def bad_checksum_tgz():
    junk = tar_member("package/junk")
    junk = junk[:148] + b"0000000\0" + junk[156:]
    return gzip.compress(tar_member("package/README.md", b"hi\n") + junk
                         + tar_member("package/package.json", HOOKED)
                         + tar_member("package/index.js", PAYLOAD) + b"\0" * 1024)


def _node_tar():
    node = shutil.which("node")
    if not node:
        return None, None
    out = subprocess.run([node, "-e", "console.log(require.resolve('npm/package.json'))"],
                         capture_output=True, text=True, env=dict(os.environ, NODE_PATH=os.path.join(
                             os.path.dirname(os.path.dirname(os.path.realpath(node))), "lib", "node_modules")), encoding="utf-8", errors="replace")
    if out.returncode != 0:
        return node, None
    tar = os.path.join(os.path.dirname(out.stdout.strip()), "node_modules", "tar")
    return node, tar if os.path.isdir(tar) else None


class TarStructureTests(unittest.TestCase):
    def test_zero_block_does_not_end_the_scan(self):
        res = scan_bytes(zero_block_tgz())
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("SC-EVAL-DECODE", rules(res))
        self.assertIn("SC-INSTALL-HOOK", rules(res))
        self.assertIn("SC-TRUNCATED", rules(res))           # the ambiguity itself is reported

    def test_bad_checksum_header_is_skipped_like_node_tar(self):
        res = scan_bytes(bad_checksum_tgz())
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(any("invalid tar header" in i["msg"] for i in issues(res, "SC-TRUNCATED")))

    def test_bad_header_alone_makes_it_incomplete(self):
        junk = tar_member("package/junk")
        junk = junk[:148] + b"0000000\0" + junk[156:]
        data = gzip.compress(tar_member("package/index.js", b"module.exports = 1;\n") + junk
                             + tar_member("package/b.js", b"1;\n") + b"\0" * 1024)
        self.assertEqual(scan_bytes(data)["verdict"], "INCOMPLETE")

    def test_trailing_data_is_incomplete(self):
        for tail in (b"GARBAGE" * 100, b"GARBAGE"):
            with self.subTest(tail=len(tail)):
                data = gzip.compress(tar_member("package/index.js", b"module.exports = 1;\n")
                                     + b"\0" * 1024 + tail)
                self.assertEqual(scan_bytes(data)["verdict"], "INCOMPLETE")

    def test_clean_tarball_with_padding_is_ok(self):
        data = gzip.compress(tar_member("package/index.js", b"module.exports = 1;\n") + b"\0" * 10240)
        res = scan_bytes(data)
        self.assertEqual(res["verdict"], "OK", res["issues"])

    def test_concatenated_gzip_members_are_read(self):
        data = (gzip.compress(tar_member("package/a.js", b"1;\n"))
                + gzip.compress(tar_member("package/index.js", PAYLOAD) + b"\0" * 1024))
        self.assertEqual(scan_bytes(data)["verdict"], "SUSPICIOUS")

    def test_garbage_after_the_gzip_stream_is_incomplete(self):
        data = gzip.compress(tar_member("package/a.js", b"1;\n") + b"\0" * 1024) + b"NOT GZIP"
        self.assertEqual(scan_bytes(data)["verdict"], "INCOMPLETE")

    def test_truncated_gzip_is_incomplete_not_an_error(self):
        full = gzip.compress(tar_member("package/a.js", b"1;\n" * 5000) + b"\0" * 1024)
        res = scan_bytes(full[:len(full) // 2])
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_matches_node_tar(self):
        node, tar = _node_tar()
        if not tar:
            self.skipTest("node / npm's bundled node-tar not available")
        script = ("const tar=require(process.argv[1]);const fs=require('fs');"
                  "tar.x({file:process.argv[2],cwd:process.argv[3],strip:1,sync:true,"
                  "filter:(p,e)=>!/Link$/.test(e.type),onwarn:()=>{}});"
                  "console.log(fs.readdirSync(process.argv[3]).sort().join(','))")
        for name, data in (("zero-block", zero_block_tgz()), ("bad-cksum", bad_checksum_tgz())):
            with self.subTest(archive=name), tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "a.tgz")
                with open(path, "wb") as fh:
                    fh.write(data)
                out = os.path.join(d, "out")
                os.mkdir(out)
                got = subprocess.run([node, "-e", script, tar, path, out], capture_output=True,
                                     text=True, timeout=30, encoding="utf-8", errors="replace")
                extracted = set(got.stdout.strip().split(","))
                seen = {m[0] for m in repo.iter_archive(data, "tgz", "npm") if m[3] is None}
                self.assertTrue(extracted <= seen, (extracted, seen))


class PathTests(unittest.TestCase):
    def test_node_tar_strip_1(self):
        cases = {"package/setup.js": "setup.js", "./decoy/setup.js": "decoy/setup.js",
                 "package/./a.js": "a.js", "package//b.js": "b.js", "/package/c.js": "package/c.js",
                 "setup.js": None, "package\\lib\\x.js": "lib/x.js"}
        for name, want in cases.items():
            with self.subTest(name=name):
                self.assertEqual(repo.canonical_member_path(name, "npm")[0], want)
        self.assertEqual(repo.canonical_member_path("package/../d.js", "npm"), (None, "path contains '..'"))

    def test_wheel_and_sdist_paths(self):
        self.assertEqual(repo.canonical_member_path("pkg/__init__.py", "wheel")[0], "pkg/__init__.py")
        self.assertEqual(repo.canonical_member_path("evil.pth", "wheel")[0], "evil.pth")
        self.assertEqual(repo.canonical_member_path("x-1.0/setup.py", "sdist")[0], "setup.py")
        self.assertEqual(repo.canonical_member_path("./x-1.0/setup.py", "sdist")[0], "setup.py")

    def test_decoy_does_not_shadow_the_hook_target(self):
        raw = (tar_member("package/package.json", hooks(postinstall="node setup.js"))
               + tar_member("package/setup.js", EXFIL_JS)
               + tar_member("./decoy/setup.js", "console.log('building');\n") + b"\0" * 1024)
        res = scan_bytes(gzip.compress(raw))
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        hook = issues(res, "SC-INSTALL-HOOK")[0]
        self.assertEqual(hook["sev"], "CRITICAL")

    def test_duplicate_paths_are_flagged(self):
        raw = (tar_member("package/index.js", "module.exports = 1;\n")
               + tar_member("pkg2/index.js", "module.exports = 2;\n") + b"\0" * 1024)
        res = scan_bytes(gzip.compress(raw))
        self.assertEqual([(i["file"], i["sev"]) for i in issues(res, "SC-ARCHIVE-DUP")],
                         [("index.js", "MAJOR")])
        self.assertEqual(res["verdict"], "WARN")

    def test_traversal_entry_is_flagged_not_scanned(self):
        raw = (tar_member("package/index.js", "1;\n") + tar_member("package/../evil.js", PAYLOAD)
               + b"\0" * 1024)
        res = scan_bytes(gzip.compress(raw))
        self.assertIn("SC-ARCHIVE-PATH", rules(res))
        self.assertNotIn("SC-EVAL-DECODE", rules(res))


class LinkTests(unittest.TestCase):
    NOTES = ("open('/tmp/claude-inert-marker', 'w')\n" + DECODE_EXEC_PY).encode()

    def sdist(self, kind, linkname):
        raw = (tar_member("x-1.0/PKG-INFO", b"Metadata-Version: 2.1\nName: x\nVersion: 1.0\n")
               + tar_member("x-1.0/docs/notes.txt", self.NOTES)
               + tar_member("x-1.0/setup.py", b"", kind, linkname) + b"\0" * 1024)
        return gzip.compress(raw)

    def test_hardlinked_setup_py_is_scanned(self):
        res = scan_bytes(self.sdist(tarfile.LNKTYPE, "x-1.0/docs/notes.txt"), artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("setup.py", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})

    def test_symlinked_setup_py_is_scanned(self):
        res = scan_bytes(self.sdist(tarfile.SYMTYPE, "docs/notes.txt"), artifact="sdist", eco="pypi")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("setup.py", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})

    def test_links_out_of_the_archive_are_flagged(self):
        for kind, target in ((tarfile.SYMTYPE, "../../../etc/passwd"), (tarfile.SYMTYPE, "/etc/passwd"),
                             (tarfile.LNKTYPE, "/etc/passwd")):
            with self.subTest(target=target):
                res = scan_bytes(self.sdist(kind, target), artifact="sdist", eco="pypi")
                link = issues(res, "SC-ARCHIVE-LINK")
                self.assertEqual([(i["file"], i["sev"]) for i in link], [("setup.py", "MAJOR")])

    def test_npm_links_are_ignored_like_pacote(self):
        raw = (tar_member("package/package.json", manifest())
               + tar_member("package/index.js", b"", tarfile.SYMTYPE, "/etc/passwd") + b"\0" * 1024)
        res = scan_bytes(gzip.compress(raw))
        self.assertEqual(res["verdict"], "OK", res["issues"])

    def test_zip_symlinks(self):
        res = scan_wheel({"x/__init__.py": "", "x/notes.txt": DECODE_EXEC_PY},
                         symlinks={"x/helper.py": "notes.txt"})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("x/helper.py", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})
        res = scan_wheel({"x/__init__.py": ""}, symlinks={"x/helper.py": "../../../etc/passwd"})
        self.assertIn("SC-ARCHIVE-LINK", rules(res))


class BudgetTests(unittest.TestCase):
    def test_bz2_or_xz_served_as_npm_tgz_is_rejected(self):
        raw = tar_member("package/a.bin", b"\0" * 4096) + b"\0" * 1024
        for data in (bz2.compress(raw), lzma.compress(raw)):
            res = scan_bytes(data)
            self.assertEqual(res["verdict"], "INCOMPLETE")
            self.assertTrue(any("compressed" in i["msg"] for i in issues(res, "SC-TRUNCATED")))

    def test_sdist_codecs_follow_the_file_name(self):
        raw = tar_member("x-1.0/setup.py", DECODE_EXEC_PY) + b"\0" * 1024
        self.assertEqual(scan_bytes(bz2.compress(raw), container="tbz2", artifact="sdist",
                                    eco="pypi")["verdict"], "SUSPICIOUS")
        self.assertEqual(scan_bytes(lzma.compress(raw), container="txz", artifact="sdist",
                                    eco="pypi")["verdict"], "SUSPICIOUS")
        self.assertEqual(scan_bytes(bz2.compress(raw), container="tgz", artifact="sdist",
                                    eco="pypi")["verdict"], "INCOMPLETE")
        self.assertEqual(scan_bytes(raw, container="tgz", artifact="sdist",
                                    eco="pypi")["verdict"], "INCOMPLETE")
        self.assertEqual(repo.pypi_container("x-1.0.tar.bz2"), "tbz2")
        self.assertEqual(repo.pypi_container("x-1.0-py3-none-any.whl"), "zip")
        self.assertIsNone(repo.pypi_container("x-1.0.egg"))

    def test_skipped_member_bytes_are_charged(self):
        # a member far over MAX_MEMBER: its data is skipped, not read, but
        # every decompressed byte still counts against the budget
        co = zlib.compressobj(9, zlib.DEFLATED, 31)
        ti = tarfile.TarInfo("package/data.js")
        ti.size = 64 << 20
        data = co.compress(ti.tobuf(tarfile.GNU_FORMAT))
        chunk = b"\0" * (1 << 20)
        for _ in range(64):
            data += co.compress(chunk)
        data += co.compress(b"\0" * 1024) + co.flush()
        with mock.patch.object(repo, "MAX_ARCHIVE_TOTAL", 8 << 20):
            t = time.monotonic()
            res = scan_bytes(data)
        self.assertLess(time.monotonic() - t, 10)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertTrue(any("cumulative decompressed" in i["msg"] for i in issues(res, "SC-TRUNCATED")))

    def test_budget_counts_all_decompressed_bytes(self):
        members = list(repo.iter_archive(zero_block_tgz(), "tgz", "npm", budget=repo.Budget(total=1024)))
        self.assertEqual(members[-1][3], "total")

    def test_deadline_makes_it_incomplete(self):
        data = gzip.compress(b"".join(tar_member(f"package/f{i}.js", "1;\n") for i in range(50))
                             + b"\0" * 1024)
        with mock.patch.object(repo, "SCAN_TIMEOUT", -1):
            res = scan_bytes(data)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertTrue(any("time budget" in i["msg"] for i in issues(res, "SC-TRUNCATED")))

    def test_cancel_raises(self):
        data = gzip.compress(tar_member("package/a.js", "1;\n") + b"\0" * 1024)
        with self.assertRaises(repo.ScanCancelled):
            scan_bytes(data, cancel=lambda: True)

    def test_legacy_iter_archive_call_still_works(self):
        raw = tar_member("pkg/a.py", b"x = 1\n") + b"\0" * 1024
        members = list(repo.iter_archive(raw, "tgz"))
        self.assertEqual([(m[0], m[1], m[3]) for m in members], [("a.py", 6, None)])
        self.assertEqual(repo.strip_root("./pkg/a.py"), "a.py")


if __name__ == "__main__":
    unittest.main()
