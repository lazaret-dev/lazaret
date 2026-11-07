"""Engine parity for media files and keystores (FP-OPAQUE-MEDIA): the Python CLI and the npm CLI report the same
findings (rule, file, line, severity, message), metrics, gate and exit code on a tree of the files the real encoders
wrote (tests/fixtures/media), the shapes of John's tally (an MP3 that starts at its first frame, Pillow's IM Tools
image, a debug keystore), each kind of keystore, files changed to stay opaque (a payload appended, a format's first
bytes glued onto random bytes), files over the size limit walked as their stream passes (a 300 MB MP4, sparse, its
mdat passed over), and a dependency's under --deps. The expectations are in
tests/scanner/test_review_opaque_media.py; this holds the packages to each other. Inert. Skipped where the npm engine
is not built (node, and npm run build in js/).
"""
import collections
import os
import tempfile
import unittest

from tests import _media_files as mf
from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key


def media_tree():
    files = {f"assets/{n}": d for n, d in mf.fixtures().items()}
    for n in ("noise.png", "noise-raw.mp3", "noise.m4a", "noise.webm", "noise-nopad.flac", "noise.woff2"):
        files[f"bad/a-{n}"] = mf.appended(mf.fixture(n))
        files[f"bad/g-{n}"] = mf.glued(mf.fixture(n))
    files.update({
        "app.js": "require('pkg')\n", "package.json": '{"dependencies": {"pkg": "1.0.0"}}',
        "music/music1.mp3": mf.raw_mp3(60), "Tests/images/bw_gradient.imt": mf.imt_gradient(),
        "signing/tiles-foss-debug.pkcs12": mf.pkcs12(),
        "k/truststore.p12": mf.pkcs12(key=False), "k/certs.p12": mf.pkcs12(key=False, encrypted_certs=False,
                                                                           clear_certs=True),
        "k/release.jks": mf.jks([(1, mf.jks_key_entry()), (2, mf.jks_cert_entry())]),
        "k/secret.jceks": mf.jks([(3, mf.sealed_object())], magic=b"\xce\xce\xce\xce"),
        "k/android.bks": mf.bks([(2, mf.bks_key()), (1, mf.bks_cert())]),
        "k/bad.p12": mf.appended(mf.pkcs12()),
        "random.bin": mf.noise(9, 5000),
        "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}',
        "node_modules/pkg/index.js": "module.exports = 1\n",
        "node_modules/pkg/beep.mp3": mf.raw_mp3(20), "node_modules/pkg/debug.keystore": mf.jks([(1, mf.jks_key_entry())]),
        "node_modules/pkg/payload.png": mf.glued(mf.fixture("noise.png")),
    })
    return files


def write(root, files):
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    # a 300 MB MP4, sparse: walked as its stream passes, its mdat passed over; and one with a payload after its mdat
    ftyp = (24).to_bytes(4, "big") + b"ftypisom\x00\x00\x02\x00isomiso2"
    size = 300 * 1024 * 1024
    os.makedirs(os.path.join(root, "big"), exist_ok=True)
    for name, tail in (("video.mp4", b""), ("bad.mp4", mf.noise(8, 100))):
        with open(os.path.join(root, "big", name), "wb") as fh:
            fh.write(ftyp + (size - 24).to_bytes(4, "big") + b"mdat" + mf.noise(5, 9000))
            fh.truncate(size)
            fh.seek(size)
            fh.write(tail)


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class MediaParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, deps):
        with tempfile.TemporaryDirectory() as root:
            write(root, media_tree())
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root, deps=deps)
        self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []})
        self.assertEqual(js["metrics"], py["metrics"])
        for field in DERIVED:
            self.assertEqual(derived(js, field), derived(py, field), field)
        self.assertEqual(js_exit, py_exit)
        return py

    def found(self, report):
        return {(i["file"].replace("\\", "/"), i["rule"], i["sev"]) for i in report["issues"]
                if i["rule"].startswith("SC-") or i["rule"] == "S-SECRET"}

    def test_media_and_keystores(self):
        got = self.found(self.assert_same(deps=False))
        opaque = {f for f, r, _ in got if r == "SC-OPAQUE-BLOB"}
        # (a WebM's first 512 bytes, the project scan's sample, are its header and track entries, not near-random:
        # with a payload appended it is not looked at, before as now; glued onto random bytes it is)
        bad = {f for f in media_tree() if f.startswith("bad/")} - {"bad/a-noise.webm"}
        self.assertEqual(opaque, bad | {"k/bad.p12", "random.bin", "big/bad.mp4"})
        self.assertEqual({(f, s) for f, r, s in got if r == "S-SECRET"},
                         {("signing/tiles-foss-debug.pkcs12", "BLOCKER"), ("k/truststore.p12", "MAJOR"),
                          ("k/certs.p12", "INFO"), ("k/release.jks", "BLOCKER"), ("k/secret.jceks", "BLOCKER"),
                          ("k/android.bks", "BLOCKER")})

    def test_media_and_keystores_with_deps(self):
        got = self.found(self.assert_same(deps=True))
        self.assertIn(("node_modules/pkg/debug.keystore", "S-SECRET", "BLOCKER"), got)
        self.assertIn(("node_modules/pkg/payload.png", "SC-OPAQUE-BLOB", "MAJOR"), got)
        self.assertFalse(any(f == "node_modules/pkg/beep.mp3" for f, _, _ in got))


if __name__ == "__main__":
    unittest.main()
