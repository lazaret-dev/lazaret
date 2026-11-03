"""FP-OPAQUE-MEDIA in the registry scan: a release's sound, video, image and font files are walked by their structure
to their end, and its keystores are credential files, in an sdist, a wheel and an npm tarball, as a project scan reads
them (tests/scanner/test_review_opaque_media.py); and a GitHub scan's verdict (ghdiscover.result over the project
scan of a checkout), where John's tally found the three files.

A member is read whole up to the member limit; one larger is walked as the archive's stream passes. A file that is
not its format to its end stays SC-OPAQUE-BLOB (WARN); a keystore is S-SECRET, which never sets a verdict. Files from
tests/_media_files.py, inert.
"""
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

from tests import _media_files as mf
from tests._support import native_rel
from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel

SETUP = "from setuptools import setup\nsetup(name='x')\n"
WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
NPM = '{"name": "x", "version": "1.0.0", "main": "index.js"}'


def kinds():
    """(scan, its base files) for an sdist, a wheel and an npm tarball."""
    return ((scan_sdist, {"setup.py": SETUP, "x/__init__.py": ""}),
            (scan_wheel, {"x/__init__.py": "", **WHEEL_META}),
            (scan_npm, {"package.json": NPM, "index.js": "1;\n"}))


def found(res):
    """The supply-chain and keystore findings (but SC-UNPARSED-CODE: an MPEG transport stream named .ts is TypeScript
    to the registry, as before, which its parser cannot read: INFO)."""
    return sorted((i["file"], i["rule"], i["sev"]) for i in res["issues"]
                  if (i["rule"].startswith("SC-") and i["rule"] != "SC-UNPARSED-CODE") or i["rule"] == "S-SECRET")


class Releases(unittest.TestCase):
    def test_the_encoders_files_are_quiet(self):
        media = {f"x/assets/{n}": d for n, d in mf.fixtures().items()}
        for scan_, base in kinds():
            res = scan_({**base, **media})
            self.assertEqual(found(res), [], res["issues"])
            self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_the_tallys_shapes(self):
        files = {"x/music/music1.mp3": mf.raw_mp3(60), "x/Tests/images/bw_gradient.imt": mf.imt_gradient(),
                 "x/signing/tiles-foss-debug.pkcs12": mf.pkcs12()}
        for scan_, base in kinds():
            res = scan_({**base, **files})
            self.assertEqual(found(res), [("x/signing/tiles-foss-debug.pkcs12", "S-SECRET", "BLOCKER")])
            self.assertEqual(res["verdict"], "OK", res["verdictReason"])
            self.assertEqual(res["binaryArtifacts"], 0)

    def test_what_stays_opaque_sets_its_verdict(self):
        for scan_, base in kinds():
            for bad in (mf.appended(mf.fixture("noise.png")), mf.glued(mf.raw_mp3(20)), mf.appended(mf.pkcs12())):
                res = scan_({**base, "x/data.bin": bad})
                self.assertEqual(found(res), [("x/data.bin", "SC-OPAQUE-BLOB", "MAJOR")])
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_past_the_member_limit(self):
        from lazaret.registry import repo
        big, m4a = mf.raw_mp3(60), mf.fixture("noise.m4a")
        with mock.patch.object(repo, "MAX_MEMBER", 8192):
            for scan_, base in kinds():
                res = scan_({**base, "x/long.mp3": big, "x/long.m4a": m4a})
                self.assertEqual(found(res), [], res["issues"])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])
                res = scan_({**base, "x/long.mp3": mf.appended(big), "x/glued.m4a": mf.glued(m4a, 20000)})
                self.assertEqual(found(res), [("x/glued.m4a", "SC-OPAQUE-BLOB", "MAJOR"),
                                              ("x/long.mp3", "SC-OPAQUE-BLOB", "MAJOR")])


class TheReviewsBounds(unittest.TestCase):
    """The review of Oct 27, in a release: a member cut short as the archive's stream passes, keystore shells and a
    keystore holding more than a keystore does, a payload in a part that walks: WARN, as before the walk."""

    def test_a_member_that_claims_past_its_end(self):
        from lazaret.registry import repo
        from tests.scanner.test_review_opaque_media import claims_past_its_end
        with mock.patch.object(repo, "MAX_MEMBER", 4096):
            for scan_, base in kinds():
                res = scan_({**base, "x/claims.mp4": claims_past_its_end("mp4"), "x/claims.wav": claims_past_its_end("wav")})
                self.assertEqual(found(res), [("x/claims.mp4", "SC-OPAQUE-BLOB", "MAJOR"),
                                              ("x/claims.wav", "SC-OPAQUE-BLOB", "MAJOR")])
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_keystores(self):
        big = mf.jks([(1, mf.jks_key_entry(n=20000))])
        shell = mf.jks([(2, (5).to_bytes(2, "big") + b"X.509" + (16000).to_bytes(4, "big") + mf.noise(36, 16000))])
        for scan_, base in kinds():
            res = scan_({**base, "x/big.jks": big, "x/shell.jks": shell})
            self.assertEqual(found(res), [("x/big.jks", "S-SECRET", "BLOCKER"), ("x/big.jks", "SC-OPAQUE-BLOB", "MAJOR"),
                                          ("x/shell.jks", "SC-OPAQUE-BLOB", "MAJOR")])
            self.assertEqual(res["verdict"], "WARN", res["verdictReason"])


class GitHubScans(unittest.TestCase):
    """The scan-all route of the tally: a repository's checkout scanned as a project, its verdict decided as a
    registry's (ghdiscover.result). Its findings are at the checkout's files' paths, as a project scan reports them
    (os.sep-separated: `native_rel`), not at an archive member's."""

    def verdict(self, files):
        from lazaret.registry import ghdiscover
        root = tempfile.mkdtemp(prefix="lz-gh-media-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data.encode() if isinstance(data, str) else data)
        ck = types.SimpleNamespace(root=root, commit="0" * 40, bytes=0, files=len(files), incomplete=[], calls=[],
                                   skipped=[], twins=[], overlaid={})
        res = ghdiscover.result("owner/repo", ck)
        return res["verdict"], found(res)

    def test_each_file_alone_is_ok(self):
        for path, data, want in (("music/music1.mp3", mf.raw_mp3(60), []),
                                 ("Tests/images/bw_gradient.imt", mf.imt_gradient(), []),
                                 ("signing/tiles-foss-debug.pkcs12", mf.pkcs12(),
                                  [(native_rel("signing/tiles-foss-debug.pkcs12"), "S-SECRET", "BLOCKER")])):
            with self.subTest(path=path):
                self.assertEqual(self.verdict({path: data, "README.md": "# x\n"}), ("OK", want))

    def test_a_payload_is_still_warn(self):
        self.assertEqual(self.verdict({"music/music1.mp3": mf.appended(mf.raw_mp3(60))}),
                         ("WARN", [(native_rel("music/music1.mp3"), "SC-OPAQUE-BLOB", "MAJOR")]))

    def test_the_reviews_shells_are_warn(self):
        # a Netpbm header on random bytes; free space then media data to the end, no movie; a big keystore
        for path, data in (("img/a.bin", b"P5\n100 100\n255\n" + mf.noise(40, 10000)),
                           ("v/a.bin", (8).to_bytes(4, "big") + b"free\x00\x00\x00\x00mdat" + mf.noise(41, 16000)),
                           ("k/big.jks", mf.jks([(1, mf.jks_key_entry(n=20000))]))):
            with self.subTest(path=path):
                verdict, got = self.verdict({path: data, "README.md": "# x\n"})
                self.assertEqual(verdict, "WARN")
                self.assertIn((native_rel(path), "SC-OPAQUE-BLOB", "MAJOR"), got)


if __name__ == "__main__":
    unittest.main()
