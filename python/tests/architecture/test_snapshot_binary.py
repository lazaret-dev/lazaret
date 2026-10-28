"""Binaries, bytecode, .pth files and model files, held to their recorded outputs (_snapshots.py): the engine's
reading of a file's bytes (rust/crates/lazaret-engine/src/binary.rs: the `binary_check`, `binary_classify`,
`binary_disguised`, `pyc_issues` and `pth_issues` calls; src/pickle/: `model_sniff` and `model_file`, FP-MODEL-FILES)
on seeded corpora.

Until BR-7's step 3 d (0.1.9) both packages did it themselves (core.looks_binary, classify_binary, disguised_binary,
pyc_issues and pth_issues; js/src/lib/binary.js and pth.js). The engine took them over; these sets were built for the
move, and their hashes were recorded from the Python the engine replaced, which answered every case alike.

The corpora: byte samples put together from the signatures the classifier knows (programs, archives, images, fonts,
media, documents, a tar header at its offset, a transport stream's sync bytes), valid and invalid UTF-8, controls
and random bytes, at every size around the limits, under paths of every extension (upper case, leading dots, a
Windows separator) in each context; bytecode headers checked and unchecked, with a source and without; and .pth
files of import lines, paths, comments and the line breaks str.splitlines() adds, some running or decoding a payload
(inert: the payloads print a word), with CRLF and a byte-order mark, redacted and not; model files written opcode by
opcode in the containers the libraries write (a checkpoint's zip, an .npy and an .npz, joblib's arrays, zlib and gzip
of stored blocks, PyTorch's legacy stream, a compression the reader cannot undo), cut, a byte changed or an opcode put
in (inert: os.system and the like named, never called).

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


# ---- model files (FP-MODEL-FILES): pickles written opcode by opcode, in the containers the libraries write, and
# mutated (cut, a byte changed, an opcode put in), so that the reader's answers on what it cannot finish are held too

def _su(t):
    t = t.encode()
    return b"\x8c" + bytes([len(t)]) + t


def _g(m, n):
    return b"c" + m.encode() + b"\n" + n.encode() + b"\n"


_STATE = (b"\x80\x02" + _g("collections", "OrderedDict") + b")Rq\x00" + _su("w") + _g("torch._utils", "_rebuild_tensor_v2")
          + b"((" + _su("storage") + _g("torch", "FloatStorage") + _su("0") + _su("cpu") + b"K\x04tQK\x00K\x02K\x02\x86"
          + b"K\x02K\x01\x86\x89" + _g("collections", "OrderedDict") + b")RtRs.")
_PICKLES = [
    _STATE,
    b"\x80\x02" + _g("os", "system") + _su("id") + b"\x85R.",
    b"\x80\x04" + _su("os") + b"\x94" + _su("system") + b"\x94h\x00h\x01\x93" + _su("id") + b"\x85R.",
    b"(S'id'\nios\nsystem\n.",
    b"\x80\x02(" + _g("subprocess", "Popen") + _su("sh") + b"o.",
    b"\x80\x02" + _g("argparse", "Namespace") + b")\x81}" + _su("__setstate__") + _g("os", "system") + b"sb" + _su("id") + b"b.",
    b"\x80\x02" + _g("numpy.core", "_ufunc_reconstruct") + _su("os") + _su("system") + b"\x86R" + _su("id") + b"\x85R.",
    b"\x80\x02" + _g("somepkg", "factory") + b")RK\x01\x85R.",
    b"\x80\x02" + _g("builtins", "type") + _su("X") + b")}\x87R.",
    b"\x80\x02" + _g("somelib.util", "run") + _su("rm -rf /tmp/x") + b"\x85R.",
    b"\x80\x02" + _g("sklearn.tree._tree", "Tree") + b"K\x04" + _g("numpy", "ndarray") + b"K\x01\x87R.",
    b"\x80\x02" + _g("pandas.core.indexes.base", "_new_Index") + _g("pandas", "Index") + b"}" + _su("name")
    + _su("my col") + b"s\x86R.",
    b"\x80\x02" + _g("sklearn.linear_model._logistic", "LogisticRegression") + b")\x81}" + _su("C") + b"K\x01sb.",
    b"(dp0\nS'lr'\np1\nF0.1\ns.",
    b"ccopy_reg\n_reconstructor\np0\n(cargparse\nNamespace\np1\nc__builtin__\nobject\np2\nNtp3\nRp4\n(dp5\nsb.",
    b"\x80\x02" + _g("torch.storage", "_load_from_bytes") + b"B\x10\x00\x00\x00\x80\x02" + _g("os", "system")[:12] + b".\x85R.",
]


def _wrapper(n, aligned, descr="f8", flags=0):
    w = (_g("joblib.numpy_pickle", "NumpyArrayWrapper") + b")\x81}(" + _su("shape") + b"K" + bytes([n]) + b"\x85"
         + _su("dtype") + _g("numpy", "dtype") + _su(descr) + b"\x89\x88\x87R(K\x03" + _su("<")
         + b"NNNJ\xff\xff\xff\xffJ\xff\xff\xff\xffK" + bytes([flags]) + b"tb")
    if aligned:
        w += _su("numpy_array_alignment_bytes") + b"K\x10"
    return w + b"ub"


def _joblib(rnd):
    n = rnd.randint(0, 6)
    head = b"\x80\x04}" + _su("a") + _wrapper(n, rnd.random() < 0.7)
    pad = rnd.randint(1, 16)
    body = bytes([pad]) + b"\xff" * pad if b"alignment" in head else b""
    body += bytes(rnd.randrange(256) for _ in range(8 * n)) if rnd.random() < 0.5 else bytes(8 * n)
    return head + body + b"s."


def _zip(entries):
    import struct
    import zlib
    out, cd = b"", b""
    for name, body in entries:
        n = name.encode()
        crc = zlib.crc32(body) & 0xFFFFFFFF
        cd += (b"PK\x01\x02\x14\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00" + struct.pack("<III", crc, len(body), len(body))
               + struct.pack("<H", len(n)) + bytes(12) + struct.pack("<I", len(out)) + n)
        out += (b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00" + struct.pack("<III", crc, len(body), len(body))
                + struct.pack("<HH", len(n), 0) + n + body)
    return out + cd + b"PK\x05\x06" + bytes(4) + struct.pack("<HHII", len(entries), len(entries), len(cd), len(out)) + bytes(2)


def _stored(data, gz):
    import struct
    import zlib
    blocks = b"".join(bytes([1 if k + 65535 >= len(data) else 0]) + struct.pack("<HH", len(c), len(c) ^ 0xFFFF) + c
                      for k in range(0, max(len(data), 1), 65535) for c in [data[k:k + 65535]])
    if gz:
        return (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + blocks
                + struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data)))
    return b"\x78\x01" + blocks + struct.pack(">I", zlib.adler32(data) & 0xFFFFFFFF)


def _npy(descr, after):
    import struct
    h = "{'descr': %s, 'fortran_order': False, 'shape': (3,), }" % descr
    h += " " * (63 - (10 + len(h)) % 64) + "\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(h)) + h.encode() + after


_MAGIC = b"\x80\x02\x8a\x0a\x6c\xfc\x9c\x46\xf9\x20\x6a\xa8\x50\x19\x2e"


def _model(rnd):
    """A model file: a pickle in one of its containers, and a name."""
    pkl = rnd.choice(_PICKLES) if rnd.random() < 0.8 else _joblib(rnd)
    kind = rnd.randrange(8)
    if kind == 0:
        return pkl, rnd.choice(["m.pkl", "m.joblib", "m.bin", "m", "data.txt", "m.pt"])
    if kind == 1:
        return _zip([("archive/data.pkl", pkl), ("archive/version", b"3\n"), ("archive/data/0", bytes(16))]
                    + ([("x/data.pkl", rnd.choice(_PICKLES))] if rnd.random() < 0.2 else [])
                    + ([("archive/extra.exe", b"MZ")] if rnd.random() < 0.2 else [])), rnd.choice(["w.pt", "w.bin", "w"])
    if kind == 2:
        return _npy(rnd.choice(["'|O'", "'<f8'", "[('a', '<i4'), ('b', '|O')]", "'<U3'"]), pkl), "a.npy"
    if kind == 3:
        return _zip([("w.npy", _npy("'<f8'", bytes(24))), ("o.npy", _npy("'|O'", pkl))]), "x.npz"
    if kind == 4:
        return _stored(pkl, rnd.random() < 0.5), rnd.choice(["m.joblib", "m.pkl.gz", "m.gz", "m"])
    if kind == 5:
        return _MAGIC + b"\x80\x02M\xe9\x03." + b"\x80\x02}." + pkl + b"\x80\x02]." + bytes(8), "old.pth"
    if kind == 6:
        return rnd.choice([b"BZh91AY&SY", b"\xfd7zXZ\x00", b"\x5d\x00\x00\x80", b"\x04\x22\x4d\x18"]) + bytes(20), "m.pkl.xz"
    ops = b"(.012FIJKLMNPQRSTUVXabcd}eghijl]oopqrst)uGBC" + bytes(range(0x80, 0x99))
    return b"\x80\x04" + bytes(rnd.choice(ops) for _ in range(rnd.randint(1, 60))) + b".", "soup.pkl"


def _mutate(rnd, data):
    r = rnd.random()
    if r < 0.6 or not data:
        return data
    if r < 0.75:
        return data[:rnd.randrange(len(data))]
    if r < 0.9:
        k = rnd.randrange(len(data))
        return data[:k] + bytes([rnd.randrange(256)]) + data[k + 1:]
    k = rnd.randrange(len(data))
    return data[:k] + bytes([rnd.choice(b"(.0RbcQ\x81\x93\x94h")]) + data[k:]


def model_calls(seed=20261020, count=1500):
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        data, name = _model(rnd)
        data = _mutate(rnd, data)
        out.append(("model_sniff", {"path": name, "windows": False}, text(data[:512])))
        if rnd.random() < 0.1:
            out.append(("model_file", {"path": name, "size": 50_000_000, "limit": 16_000_000, "windows": False},
                        text(data[:8192])))
        else:
            out.append(("model_file", {"path": name, "size": len(data), "windows": False}, text(data)))
    return out


def snapshot_sets():
    return {"binary_bytes": byte_calls, "binary_pth": pth_calls, "binary_models": model_calls}


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

    def test_model_files(self):
        got = self.answers("binary_models")
        files = [a for a in got[1::2] if a is not None]
        # (with the calls with text a file holds for model_own: SC-PICKLE-GLOBAL, MAJOR)
        rules = [i[0] for a in files for i in a["issues"] + [c[2] for c in a.get("calls", [])]]
        self.assertGreater(len(files), 1000)
        for rule in ("SC-PICKLE-CODE", "SC-PICKLE-GLOBAL", "SC-TRUNCATED"):
            self.assertGreater(rules.count(rule), 50, rule)
        self.assertGreater(sum(1 for a in files if not a["issues"]), 200)

    def test_pth_files(self):
        got = self.answers("binary_pth")
        sevs = [i[3] for a in got for i in a]
        self.assertGreater(sevs.count("CRITICAL"), 3000)
        self.assertGreater(sevs.count("MAJOR"), 2000)


if __name__ == "__main__":
    unittest.main()
