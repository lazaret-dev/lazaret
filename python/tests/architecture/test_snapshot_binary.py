"""Binaries, bytecode and .pth files, held to their recorded outputs (_snapshots.py): the engine's reading of a
file's bytes (rust/crates/lazaret-engine/src/binary.rs: the `binary_check`, `binary_classify`, `binary_disguised`,
`pyc_issues` and `pth_issues` calls) on seeded corpora.

Until BR-7's step 3 d (0.1.9) both packages did it themselves (core.looks_binary, classify_binary, disguised_binary,
pyc_issues and pth_issues; js/src/lib/binary.js and pth.js). The engine took them over; these sets were built for the
move, and their hashes were recorded from the Python the engine replaced, which answered every case alike.

The corpora: byte samples put together from the signatures the classifier knows (programs, archives, images, fonts,
media, documents, a tar header at its offset, a transport stream's sync bytes), valid and invalid UTF-8, controls
and random bytes, at every size around the limits, under paths of every extension (upper case, leading dots, a
Windows separator) in each context; bytecode headers checked and unchecked, with a source and without; and .pth
files of import lines, paths, comments and the line breaks str.splitlines() adds, some running or decoding a payload
(inert: the payloads print a word), with CRLF and a byte-order mark, redacted and not.

All content is inert data: no sample is a program, and nothing is executed.
"""
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

SIGS = [b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\x00asm", b"dex\n", b"MZ", b"MZ\x90\x00", b"PK\x03\x04", b"\x1f\x8b", b"BZh",
        b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"OggS", b"BM",
        b"\x00\x00\x01\x00", b"wOFF", b"wOF2", b"ID3", b"%PDF", b"II*\x00", b"MM\x00*", b"\x1a\x45\xdf\xa3",
        b"\x00\x00\x00\x18ftypmp42", b"\xff\x4f\xff\x51", b"8BPS", b"icns", b"OTTO", b"ttcf", b"%!PS", b"gimp xcf",
        b"qoif", b"#?RADIANCE", b"fLaC", b"\x00\x01\x00\x00", b"true", b"typ1", b"", b"#!/bin/sh\n", b"\xef\xbb\xbf"]
EXTS = ["", ".bin", ".so", ".SO", ".pyd", ".dll", ".node", ".exe", ".pyc", ".jsc", ".wasm", ".jar", ".png", ".ttf",
        ".woff2", ".ts", ".mts", ".m2ts", ".docx", ".epub", ".zip", ".gz", ".tar", ".dat", ".py", ".js", ".PY", ".txt"]
DIRS = ["", "a/", "a/b/", "..", "a\\b\\", "x.y/", "./"]
NAMES = ["f", ".hidden", "..f", "...", "f.tar", "F\u00e9", "\U0001F600"]
CONTEXTS = ["repo", "npm", "sdist", "wheel", "other"]


def chunk(rnd):
    r = rnd.random()
    if r < 0.25:
        return bytes(rnd.randrange(256) for _ in range(rnd.randint(1, 600)))
    if r < 0.45:
        return ("caf\u00e9 \u4e2d\u6587 text \U0001F600\n" * rnd.randint(1, 40)).encode("utf-8")
    if r < 0.6:
        return bytes(rnd.choice([0, 1, 7, 9, 10, 13, 27, 31, 127, 0x41]) for _ in range(rnd.randint(1, 300)))
    if r < 0.75:
        return bytes(rnd.choice(b"\x80\xbf\xc0\xc1\xc2\xe0\xe2\xed\xa0\xf0\xf4\xf5\xff\x41\x82\xac")
                     for _ in range(rnd.randint(1, 300)))
    if r < 0.85:
        return b"G" + bytes(rnd.randrange(256) for _ in range(187))
    return b"x = 1\n" * rnd.randint(1, 200)


def sample(rnd):
    data = rnd.choice(SIGS) + b"".join(chunk(rnd) for _ in range(rnd.randint(0, 6)))
    if rnd.random() < 0.15:                     # packed or encrypted data: random bytes past the entropy's floor
        data = rnd.choice([b"", b"\x01", b"MZ", b"PK\x03\x04"]) + bytes(rnd.randrange(256)
                                                                     for _ in range(rnd.randint(700, 9000)))
    if rnd.random() < 0.08 and len(data) > 262:
        data = data[:257] + b"ustar" + data[262:]
    if rnd.random() < 0.05 and len(data) > 40:
        data = data[:36] + b"acsp" + data[40:]
    if rnd.random() < 0.08:
        unit = b"G" + bytes(rnd.randrange(256) for _ in range(187))
        data = unit * rnd.randint(1, 4)
    cut = rnd.choice([None, 0, 1, 377, 512, 2048, 8192, rnd.randrange(len(data) + 1)])
    return data if cut is None else data[:cut]


def text(data):
    return data.decode("latin-1")


def path(rnd):
    return rnd.choice(DIRS) + rnd.choice(NAMES) + rnd.choice(EXTS)


def byte_calls(seed=20261020, count=6000):
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        data = sample(rnd)
        size = rnd.choice([len(data), len(data), 1023, 1024, 4096, 10 ** 7, 0])
        windows = rnd.random() < 0.2
        out += [("binary_check", {"check": "looks"}, text(data[:rnd.choice([2048, 512, 64])])),
                ("binary_check", {"check": "mpeg_ts"}, text(data[:377])),
                ("binary_check", {"check": "program"}, text(data[:2048])),
                ("binary_classify", {"path": path(rnd), "size": size, "context": rnd.choice(CONTEXTS),
                                     "windows": windows, "neumaier": False}, text(data[:8192])),
                ("binary_disguised", {"path": path(rnd), "windows": windows}, text(data[:2048]))]
    for _ in range(800):
        magic = rnd.choice([b"\xa7\r\r\n", b"\xa7\r\r\x0a", b"\x55\x0d\x0d\x0a", b"xx\r\n", b"\xa7\r\n\r"])
        flags = rnd.choice([b"\x01\x00\x00\x00", b"\x03\x00\x00\x00", b"\x00\x00\x00\x00", b"\x01\x00\x00\x01"])
        header = (magic + flags + bytes(rnd.randrange(256) for _ in range(8)))[:rnd.choice([16, 8, 7, 4, 0])]
        out.append(("pyc_issues", {"path": "pkg/__pycache__/" + rnd.choice(NAMES) + ".cpython-311.pyc",
                                   "has_source": rnd.random() < 0.5}, text(header)))
    return out


PTH_LINES = [
    "import os", "import\tsite", "  import os", "importlib", "./src", "../lib", "# a comment", "",
    "import _distutils_hack; _distutils_hack.do()", "import sys; exec('print(1)')",
    'import os, base64; exec(base64.b64decode("cHJpbnQoMSk="))', "import x; y = 'x'.decode('rot13')",
    "import os; os.system('\\x69d')", "import zlib, marshal; marshal.loads(z)",
    "import urllib.request; urllib.request.urlopen('http://192.0.2.1/x')",
    "import subprocess; subprocess.Popen(['echo', 'hi'])", "import site; site.addsitedir('x')",
    "# notes\x0cimport sys; print('x')", "x\x0bimport os", "a\x1cimport os", "b\x85import os", "c\u2028import os",
    "d\u2029import\tos", "import os # password = 'hunter22'", "import codecs; codecs.decode('k', 'rot13')",
    "import os; exec(compile('print(2)', 'x', 'exec'))", "import\u00a0os", "IMPORT os", "import os\x00",
]


def pth_calls(seed=20261021, count=2500):
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        lines = [rnd.choice(PTH_LINES) for _ in range(rnd.randint(0, 12))]
        body = rnd.choice(["\n", "\r\n", "\r", "\n"]).join(lines) + rnd.choice(["", "\n", "\r\n"])
        if rnd.random() < 0.05:
            body = "\ufeff" + body
        out.append(("pth_issues", {"redact": rnd.random() < 0.8, "neumaier": False}, body))
    return out


def snapshot_sets():
    return {"binary_bytes": byte_calls, "binary_pth": pth_calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class BinarySnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_bytes(self):
        calls = byte_calls()
        got = self.answers("binary_bytes")
        by = {}
        for (c, args, _t), a in zip(calls, got):
            by.setdefault((c, args.get("check")), []).append(a)
        self.assertGreater(sum(by[("binary_check", "looks")]), 1500)
        self.assertGreater(sum(by[("binary_check", "mpeg_ts")]), 140)
        self.assertGreater(sum(by[("binary_check", "program")]), 400)
        rules = [a[0] for a in by[("binary_classify", None)] if a is not None]
        for rule in ("SC-BINARY", "SC-NESTED-ARCHIVE", "SC-OPAQUE-BLOB"):
            self.assertGreater(rules.count(rule), 90, rule)
        self.assertGreater(sum(1 for a in by[("binary_disguised", None)] if a is not None), 300)
        self.assertGreater(sum(len(a) for a in by[("pyc_issues", None)]), 350)

    def test_pth_files(self):
        got = self.answers("binary_pth")
        sevs = [i[3] for a in got for i in a]
        self.assertGreater(sevs.count("CRITICAL"), 3000)
        self.assertGreater(sevs.count("MAJOR"), 2000)


if __name__ == "__main__":
    unittest.main()
