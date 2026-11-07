"""FP-OPAQUE-MEDIA (John chose to build it, Oct 21): a near-random file is a sound, video, image or font when its bytes
are that format from start to end, and a keystore is a credential file, in a project scan and with --deps.

John's fp-tally over 261 GitHub scans: SC-OPAQUE-BLOB (MAJOR) set 3 WARN verdicts, 2 of them alone, on
music/music1.mp3 (an MP3 with no ID3v2 tag: its first frame first, which no first-bytes signature named), Pillow's
Tests/images/bw_gradient.imt (an IM Tools image: a text header, then 2,560 bytes of a grey gradient, every level ten
times, 7.9 bits a byte and nothing hidden) and signing/tiles-foss-debug.pkcs12 (a debug signing keystore). Each
format's structure is walked to the file's end (the engine's media/: frame, page, box, chunk and element chains, the
directories of fonts, bitmaps, icons and TIFF), never its name; bytes the structure does not hold keep
SC-OPAQUE-BLOB, as does a file no walker reads, and the formats once taken by their first bytes alone (a PNG's, a
font's by its extension) are walked too: a PNG signature glued onto random bytes is opaque now. A keystore read to its
end (PKCS#12, JKS, JCEKS, BKS) is S-SECRET: BLOCKER when it holds a private or secret key in the clear part of its
structure, MAJOR when its entries are encrypted whole, INFO for certificates alone.

The files: tests/_media_files.py (the encoders' files, the tally's shapes, keystores laid out as keytool, OpenSSL
and Bouncy Castle write them with random bytes for their keys). All content is inert.
"""
import os
import shutil
import tempfile
import unittest
from unittest import mock

from tests import _media_files as mf
from lazaret.scanner import core


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-media-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def scan(files, **kw):
    root = tree({"app.py": "x = 1\n", **files})       # (a tree of media alone is nothing to scan)
    try:
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res, rules=("SC-", "S-SECRET")):
    """{file: {(rule, sev)}} of the supply-chain and keystore findings."""
    out = {}
    for i in res["issues"]:
        if i["rule"].startswith(rules):
            out.setdefault(i["file"].replace(os.sep, "/"), set()).add((i["rule"], i["sev"]))
    return out


def msg(res, path, rule):
    return next(i["msg"] for i in res["issues"] if i["file"].replace(os.sep, "/") == path and i["rule"] == rule)


OPAQUE = ("SC-OPAQUE-BLOB", "MAJOR")
KEY = ("S-SECRET", "BLOCKER")


class TheTallysFiles(unittest.TestCase):
    def test_an_mp3_that_starts_at_its_first_frame_is_audio(self):
        res = scan({"music/music1.mp3": mf.raw_mp3(60), "app.py": "print(1)\n"})
        self.assertEqual(found(res), {}, res["issues"])
        self.assertEqual(res["supplyChain"], 0)

    def test_pillows_im_tools_image_is_an_image(self):
        res = scan({"Tests/images/bw_gradient.imt": mf.imt_gradient()})
        self.assertEqual(found(res), {}, res["issues"])

    def test_a_debug_signing_keystore_is_a_credential_file(self):
        res = scan({"signing/tiles-foss-debug.pkcs12": mf.pkcs12()})
        self.assertEqual(found(res), {"signing/tiles-foss-debug.pkcs12": {KEY}})
        self.assertEqual(res["supplyChain"], 0)
        self.assertIn("a PKCS#12 keystore that holds a private or secret key (1 private key and 1 encrypted part)",
                      msg(res, "signing/tiles-foss-debug.pkcs12", "S-SECRET"))


class TheEncodersFiles(unittest.TestCase):
    def test_are_quiet_whatever_their_names(self):
        files = mf.fixtures()
        named = {f"assets/{n}": d for n, d in files.items()}
        named.update({f"blobs/b{k}.bin": d for k, d in enumerate(files.values())})
        res = scan(named)
        self.assertEqual(found(res), {}, [i for i in res["issues"] if i["rule"].startswith("SC-")][:5])

    def test_what_writers_do_that_the_format_allows(self):
        # shapes real files have (Pillow's and scipy's test files, a camera's): a multi-picture JPEG padded between
        # its images (an MPO), a WAV whose RIFF size is smaller than its chunks, which run to the file's end
        jpg, wav = mf.fixture("noise.jpg"), bytearray(mf.fixture("signal.wav"))
        wav[4:8] = (int.from_bytes(wav[4:8], "little") - 12).to_bytes(4, "little")
        # (classify_binary's sample, 8 KB, as the registry reads one: a JPEG's first 512 bytes are its tables)
        for path, data in (("a/photo.mpo", jpg + b"\x00" + jpg), ("a/sound.wav", bytes(wav))):
            self.assertIsNone(core.classify_binary(path, data, len(data), "repo"), path)
            self.assertEqual(core.classify_binary(path, data + b"\x01", len(data) + 1, "repo")["rule"],
                             "SC-OPAQUE-BLOB", path)


class WhatStaysOpaque(unittest.TestCase):
    def test_bytes_the_structure_does_not_hold(self):
        files = {}
        for name in ("noise.png", "noise.jpg", "noise-raw.mp3", "noise.m4a", "signal.wav", "noise.woff2",
                     "noise.gif", "noise-nopad.flac", "noise.aac", "noise-lzw.tif"):
            data = mf.fixture(name)
            files[f"g/{name}"] = mf.glued(data)
            # (a JPEG's first 512 bytes, its tables, are not near-random: a project scan's sample, before as now,
            # so a payload after one is not looked at; the registry's sample is 8 KB)
            if name != "noise.jpg":
                files[f"a/{name}"] = mf.appended(data)
        files["a/music1.mp3"] = mf.appended(mf.raw_mp3(30))
        files["a/gradient.imt"] = mf.imt_gradient() + b"\x01"
        res = scan(files)
        got = found(res)
        for path in files:
            self.assertEqual(got.get(path), {OPAQUE}, path)
        self.assertIn("read as PNG image, it is not one to its end: bytes follow the image's end (IEND) at byte 7028",
                      msg(res, "a/noise.png", "SC-OPAQUE-BLOB"))
        self.assertIn("read as MP3 audio, it is not one to its end", msg(res, "g/noise-raw.mp3", "SC-OPAQUE-BLOB"))

    def test_random_bytes_and_a_first_bytes_signature_alone(self):
        res = scan({"blob.dat": mf.noise(1, 5000), "fake.png": b"\x89PNG\r\n\x1a\n" + mf.noise(2, 5000),
                    "fake.ttf": b"\x00\x01\x00\x00" + mf.noise(3, 5000)})
        self.assertEqual(found(res), {"blob.dat": {OPAQUE}, "fake.png": {OPAQUE}, "fake.ttf": {OPAQUE}})
        self.assertRegex(msg(res, "blob.dat", "SC-OPAQUE-BLOB"), r"^Opaque high-entropy file \(5000 bytes, entropy 7\.6/8\)\.$")


class Keystores(unittest.TestCase):
    def test_each_kind_by_what_it_holds(self):
        files = {
            "k/debug.p12": mf.pkcs12(),
            "k/secret.p12": mf.pkcs12(key=False, secret=True),
            "k/truststore.p12": mf.pkcs12(key=False),
            "k/certs.p12": mf.pkcs12(key=False, encrypted_certs=False, clear_certs=True),
            "k/release.jks": mf.jks([(1, mf.jks_key_entry()), (2, mf.jks_cert_entry())]),
            "k/cacerts": mf.jks([(2, mf.jks_cert_entry(k)) for k in range(3)]),
            "k/secret.jceks": mf.jks([(3, mf.sealed_object())], magic=b"\xce\xce\xce\xce"),
            "k/android.bks": mf.bks([(2, mf.bks_key()), (1, mf.bks_cert())]),
            "k/trust.bks": mf.bks([(1, mf.bks_cert())]),
        }
        res = scan(files)
        self.assertEqual(found(res), {
            "k/debug.p12": {KEY}, "k/secret.p12": {KEY}, "k/truststore.p12": {("S-SECRET", "MAJOR")},
            "k/certs.p12": {("S-SECRET", "INFO")}, "k/release.jks": {KEY}, "k/cacerts": {("S-SECRET", "INFO")},
            "k/secret.jceks": {KEY}, "k/android.bks": {KEY}, "k/trust.bks": {("S-SECRET", "INFO")}})
        self.assertIn("a JCEKS keystore that holds a private or secret key (1 secret key)",
                      msg(res, "k/secret.jceks", "S-SECRET"))
        self.assertIn("a JKS keystore that holds no private or secret key (3 certificates)",
                      msg(res, "k/cacerts", "S-SECRET"))
        self.assertTrue(all(i["line"] == 1 and not i.get("snippet") for i in res["issues"] if i["rule"] == "S-SECRET"))

    def test_a_keystore_with_bytes_after_it_is_not_one(self):
        res = scan({"k/debug.p12": mf.appended(mf.pkcs12()), "k/x.jks": mf.glued(mf.jks([(1, mf.jks_key_entry())]))})
        self.assertEqual(found(res), {"k/debug.p12": {OPAQUE}, "k/x.jks": {OPAQUE}})


class OverTheSizeLimit(unittest.TestCase):
    """A file too large to read whole is walked as its stream passes (read by chunks, passing over what the walk
    skips): a long MP3 or video is audio or video, as one of a few KB is."""

    def test_walked_as_it_is_read(self):
        big = mf.raw_mp3(60)                      # 25 KB, over a 4 KB limit
        mp4 = mf.fixture("noise.m4a")
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 4096):
            res = scan({"m/long.mp3": big, "m/long.m4a": mp4, "m/bad.mp3": mf.appended(big),
                        "m/glued.mp3": mf.glued(big, 20000), "m/keystore.p12": mf.pkcs12()})
        got = found(res)
        self.assertEqual(got.get("m/bad.mp3"), {OPAQUE})
        self.assertEqual(got.get("m/glued.mp3"), {OPAQUE})
        self.assertNotIn("m/long.mp3", got)
        self.assertNotIn("m/long.m4a", got)
        # a keystore is read whole up to the limit (2,310 bytes: under it); past it, judged by its first bytes
        self.assertEqual(got.get("m/keystore.p12"), {KEY})
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 2048):
            self.assertEqual(found(scan({"m/keystore.p12": mf.pkcs12()})), {"m/keystore.p12": {OPAQUE}})

    def test_only_the_bytes_the_walk_reads(self):
        # a 300 MB MP4 of a few boxes, sparse: its walk passes over its mdat box, never reading it
        root = tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        ftyp = (24).to_bytes(4, "big") + b"ftypisom\x00\x00\x02\x00isomiso2"
        size = 300 * 1024 * 1024
        with open(os.path.join(root, "video.mp4"), "wb") as fh:
            fh.write(ftyp + (size - 24).to_bytes(4, "big") + b"mdat" + mf.noise(5, 9000))
            fh.truncate(size)
        reads = []
        real = os.read

        def spy(fd, n):
            data = real(fd, n)
            reads.append(len(data))
            return data
        with mock.patch.object(core.os, "read", spy):
            res = core.scan_project(root)
        self.assertEqual(found(res), {}, res["issues"])
        self.assertLess(sum(reads), 4 * 1024 * 1024)


def claims_past_its_end(kind):
    """A file whose part claims a gigabyte with 20 KB of random bytes there (the review's probes, Oct 27): an MP4's
    media data box, a WAV's data chunk."""
    if kind == "mp4":
        return (24).to_bytes(4, "big") + b"ftypisom\x00\x00\x02\x00isomiso2" + (1 << 30).to_bytes(4, "big") + b"mdat" \
            + mf.noise(30, 20000)
    fmt = b"fmt " + (16).to_bytes(4, "little") + bytes.fromhex("01000100225600004" "4ac000002001000")
    return b"RIFF" + (1 << 30).to_bytes(4, "little") + b"WAVE" + fmt + b"data" + (1 << 30).to_bytes(4, "little") \
        + mf.noise(31, 20000)


class TheReviewsBounds(unittest.TestCase):
    """The review of Oct 27: a file cut short as its stream passes, the shapes no real file has, the free-form parts'
    bounds, raw samples that are random, keystores' parts by their shapes and sizes."""

    def test_a_part_that_runs_past_the_end_streamed(self):
        files = {"v/claims.mp4": claims_past_its_end("mp4"), "v/claims.wav": claims_past_its_end("wav")}
        for cap in (4096, core.SOURCE_SIZE_CAP):
            with mock.patch.object(core, "SOURCE_SIZE_CAP", cap):
                res = scan(files)
            self.assertEqual(found(res), {"v/claims.mp4": {OPAQUE}, "v/claims.wav": {OPAQUE}}, cap)
            self.assertIn("cut short", msg(res, "v/claims.mp4", "SC-OPAQUE-BLOB"))

    def test_payloads_in_parts_that_walk(self):
        png = mf.fixture("noise.png")
        z = b"zTXt" + mf.noise(32, 20000)
        import zlib
        chunk = (20000).to_bytes(4, "big") + z + zlib.crc32(z).to_bytes(4, "big")
        files = {"p/ztxt.png": png[:33] + chunk + png[33:],
                 "p/pnm.bin": b"P5\n100 100\n255\n" + mf.noise(33, 10000),
                 "p/free.mp4": (8).to_bytes(4, "big") + b"free" + b"\x00\x00\x00\x00mdat" + mf.noise(34, 16000),
                 "p/no-idat.png": png[:33] + png[-12:] + mf.noise(35, 4000)}
        res = scan(files)
        self.assertEqual(found(res), {k: {OPAQUE} for k in files})
        self.assertIn("PNG text, private and unregistered chunks hold 20000 bytes", msg(res, "p/ztxt.png", "SC-OPAQUE-BLOB"))
        self.assertIn("samples from byte 15 are near-random", msg(res, "p/pnm.bin", "SC-OPAQUE-BLOB"))

    def test_a_keystore_that_holds_more_than_a_keystore_is_an_opaque_blob_too(self):
        res = scan({"k/big.jks": mf.jks([(1, mf.jks_key_entry(n=20000))]),
                    "k/random-cert.jks": mf.jks([(2, (5).to_bytes(2, "big") + b"X.509" + (16000).to_bytes(4, "big")
                                                  + mf.noise(36, 16000))])})
        self.assertEqual(found(res), {"k/big.jks": {KEY, OPAQUE}, "k/random-cert.jks": {OPAQUE}})
        self.assertIn("its largest such part holds 20000 bytes", msg(res, "k/big.jks", "SC-OPAQUE-BLOB"))


def collection(fonts, tables=4096, distinct=False, seed=37):
    """A font collection of `fonts` fonts, each a directory of `tables` 1-byte tables with a zero byte after each
    (the re-review's walk-cost file, N1): random bytes as its first table, so that its first bytes are near-random,
    then the tables every font has and tags of its own, distinct or one over and over."""
    required = [b"head", b"cmap", b"hhea", b"hmtx", b"maxp", b"name"]
    rnd = mf.noise(seed, 8000)
    head = 12 + 4 * fonts
    dirs = head + len(rnd)
    size = 12 + 16 * tables
    at = dirs + fonts * size
    out = bytearray(b"ttcf" + (0x10000).to_bytes(4, "big") + fonts.to_bytes(4, "big"))
    out += b"".join((dirs + k * size).to_bytes(4, "big") for k in range(fonts)) + rnd
    for k in range(fonts):
        out += (0x10000).to_bytes(4, "big") + tables.to_bytes(2, "big") + bytes(6)
        for t in range(tables):
            n = k * tables + t
            tag = required[t] if t < len(required) else b"Z" + bytes(97 + n // 26 ** i % 26 for i in (2, 1, 0)) \
                if distinct else b"glyf"
            off, length = (head, len(rnd)) if (k, t) == (0, 0) else (at, 1)
            if (k, t) != (0, 0):
                at += 2
            out += tag + bytes(4) + off.to_bytes(4, "big") + length.to_bytes(4, "big")
    return bytes(out + b"\x41\x00" * ((at - dirs - fonts * size) // 2))


class TheReReviewsBounds(unittest.TestCase):
    """The re-review of Oct 27: a font collection's walk in linear time, its tables named once and its parts bounded
    (N1); a keystore's certificates and aliases counted (N2)."""

    def test_a_font_collections_walk_is_bounded(self):
        import time
        # (32 fonts: its first 512 bytes, the project scan's sample, are near-random, so it is walked; 64 fonts' are not)
        files = {"f/same-tag.ttc": collection(32), "f/many-parts.ttc": collection(17, distinct=True)}
        t = time.monotonic()
        res = scan(files)
        self.assertLess(time.monotonic() - t, 20)
        self.assertEqual(found(res), {k: {OPAQUE} for k in files})
        self.assertIn("names table 'glyf' twice", msg(res, "f/same-tag.ttc", "SC-OPAQUE-BLOB"))
        self.assertIn("more than a real file's (at most 65536)", msg(res, "f/many-parts.ttc", "SC-OPAQUE-BLOB"))

    def test_a_keystores_certificates_and_aliases_count(self):
        def cert(body):
            c = mf.certificate(41)
            # (an extension holding `body` bytes, inside the tbs: its fields are not read)
            tbs_len = int.from_bytes(c[6:8], "big")
            tbs = c[4:8 + tbs_len]
            ext = mf.der(0xA3, mf.der(0x30, mf.der(0x30, mf.der(0x06, b"\x55\x1d\x0e") + mf.der(0x04, mf.noise(42, body)))))
            tbs = mf.der(0x30, tbs[4:] + ext)
            c = mf.der(0x30, tbs + c[8 + tbs_len:])
            return (5).to_bytes(2, "big") + b"X.509" + len(c).to_bytes(4, "big") + c
        res = scan({"k/real.jks": mf.jks([(2, cert(300))]), "k/big-cert.jks": mf.jks([(2, cert(40000))])})
        self.assertEqual(found(res), {"k/real.jks": {("S-SECRET", "INFO")},
                                      "k/big-cert.jks": {("S-SECRET", "INFO"), OPAQUE}})
        self.assertIn("certificates, names past a real one's size", msg(res, "k/big-cert.jks", "SC-OPAQUE-BLOB"))


class Dependencies(unittest.TestCase):
    def test_with_deps(self):
        files = {"app.js": "require('pkg')\n", "package.json": '{"dependencies": {"pkg": "1.0.0"}}',
                 "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}',
                 "node_modules/pkg/index.js": "module.exports = 1\n",
                 "node_modules/pkg/sounds/beep.mp3": mf.raw_mp3(20),
                 "node_modules/pkg/fonts/icons.woff2": mf.fixture("noise.woff2"),
                 "node_modules/pkg/android/debug.keystore": mf.jks([(1, mf.jks_key_entry())]),
                 "node_modules/pkg/data/payload.png": mf.glued(mf.fixture("noise.png"))}
        res = scan(files, include_deps=True)
        self.assertEqual(found(res), {"node_modules/pkg/android/debug.keystore": {KEY},
                                      "node_modules/pkg/data/payload.png": {OPAQUE}})


if __name__ == "__main__":
    unittest.main()
