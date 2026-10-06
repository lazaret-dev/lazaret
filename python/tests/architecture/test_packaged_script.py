"""scripts/popular/packaged.py (0.1.9, N-2): the release gate's Go and Rust benign sets, from Ubuntu's golang-*-dev
and librust-*-dev packages and from Go's own tree, each module or crate packed as its registry serves it.

The .debs, their index and the Go tree are built here from small inert files; nothing goes on the network (a
stand-in answers for archive.ubuntu.com)."""

import contextlib
import gzip
import hashlib
import io
import json
import lzma
import os
import shutil
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile

from tests import _support

pk = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "popular", "packaged.py"), "packaged_set")

DEP5 = "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\n"
EXPAT = DEP5 + "Files: *\nCopyright: 2024 A\nLicense: Expat\n\nFiles: debian/*\nCopyright: 2024 B\nLicense: GPL-2+\n"
GPL = DEP5 + "Files: *\nCopyright: 2024 A\nLicense: GPL-3+\n"
GO = "package {0}\n\nfunc F() int {{ return 1 }}\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tar_of(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path, data in sorted(files.items()):
            info = tarfile.TarInfo("./" + path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def ar_of(members):
    out = [b"!<arch>\n"]
    for name, data in members:
        out.append(f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}".encode() + b"`\n")
        out.append(data + (b"\n" if len(data) % 2 else b""))
    return b"".join(out)


def deb_of(files):
    """A .deb (ar; control.tar.xz and data.tar.xz) holding `files` ({path: text})."""
    data = {p: t.encode() for p, t in files.items()}
    return ar_of([("debian-binary", b"2.0\n"), ("control.tar.xz", lzma.compress(tar_of({"control": b"Package: x\n"}))),
                  ("data.tar.xz", lzma.compress(tar_of(data)))])


def index_of(debs):
    """A Packages.xz for {package: (filename, bytes)}, with a package this set does not take."""
    stanzas = [f"Package: {pkg}\nVersion: 1.0-1\nArchitecture: all\nFilename: pool/universe/x/{pkg}/{name}\n"
               f"Size: {len(data)}\nSHA256: {sha(data)}\n" for pkg, (name, data) in sorted(debs.items())]
    stanzas.append(f"Package: libfoo1\nVersion: 1\nFilename: pool/main/f/foo/libfoo1_1_amd64.deb\nSHA256: {'0' * 64}\n")
    return lzma.compress("\n".join(stanzas).encode())


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def zip_names(path):
    with zipfile.ZipFile(path) as zf:
        return sorted(zf.namelist())


def tgz_names(path):
    with tarfile.open(path, "r:gz") as tf:
        return sorted(tf.getnames())


class Archive:
    """A stand-in for urllib's urlopen: {url: bytes}."""

    def __init__(self, pages):
        self.pages, self.asked = dict(pages), []

    def __call__(self, req, timeout=None):
        self.asked.append(req.full_url)
        if req.full_url not in self.pages:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
        return contextlib.closing(io.BytesIO(self.pages[req.full_url]))


class LicenceTests(unittest.TestCase):
    def test_a_packages_licences(self):
        self.assertEqual(pk.dep5_licences(EXPAT), (True, ["expat"]))                 # debian/* aside
        for text, ok in ((DEP5 + "Files: *\nLicense: Apache-2.0 or GPL-2+\n", True),
                         (DEP5 + "Files: *\nLicense: MIT and Unicode-3.0\n", True),
                         (DEP5 + "Files: *\nLicense: BSD-3-clause\n\nFiles: x/*\nLicense: ISC\n", True),
                         (DEP5 + "Files: *\nLicense: MIT and GPL-2\n", False),
                         (DEP5 + "Files: *\nLicense: BSD-4-clause\n", False),
                         (DEP5 + "Files: *\nLicense: MPL-2.0\n", False),
                         (DEP5 + "Files: *\nLicense: Expat\n\nFiles: vendor/*\nLicense: LGPL-3\n", False),
                         (DEP5 + "Files: debian/*\nLicense: GPL-2+\n", False),              # nothing upstream named
                         ("This package was debianized by A.\nLicense: MIT\n", False)):     # not DEP-5
            self.assertEqual(pk.dep5_licences(text)[0], ok, text)


class UnitTests(unittest.TestCase):
    def test_go_modules_are_go_mod_roots_less_the_nested_ones(self):
        files = {"example.invalid/a/go.mod": b"module example.invalid/a\n", "example.invalid/a/a.go": b"package a\n",
                 "example.invalid/a/sub/go.mod": b"module example.invalid/a/sub\n",
                 "example.invalid/a/sub/s.go": b"package sub\n", "example.invalid/b/b.go": b"package b\n"}
        units = dict(pk.go_units(files))
        self.assertEqual(sorted(units), ["example.invalid/a", "example.invalid/a/sub"])
        self.assertEqual(sorted(units["example.invalid/a"]), ["a.go", "go.mod"])
        self.assertEqual(sorted(units["example.invalid/a/sub"]), ["go.mod", "s.go"])

    def test_without_a_go_mod_the_import_paths_roots(self):
        files = {"github.com/o/r/x.go": b"package r\n", "github.com/o/r/sub/y.go": b"package sub\n",
                 "example.invalid/p/q/z.go": b"package q\n", "example.invalid/p/q/deeper/w.go": b"package deeper\n"}
        units = dict(pk.go_units(files))
        self.assertEqual(sorted(units), ["example.invalid/p/q", "github.com/o/r"])
        self.assertEqual(sorted(units["github.com/o/r"]), ["sub/y.go", "x.go"])
        self.assertEqual(sorted(units["example.invalid/p/q"]), ["deeper/w.go", "z.go"])

    def test_crates_are_the_registry_directories(self):
        files = {"foo-1.0.0/Cargo.toml": b"[package]\n", "foo-1.0.0/src/lib.rs": b"", "bar-0.1.0/src/lib.rs": b"",
                 "stray": b""}
        self.assertEqual([(n, sorted(u)) for n, u in pk.crate_units(files)],
                         [("bar-0.1.0", ["src/lib.rs"]), ("foo-1.0.0", ["Cargo.toml", "src/lib.rs"])])

    def test_packed_as_the_registries_serve_them_the_same_bytes_each_time(self):
        unit = {"go.mod": b"module example.invalid/m\n", "m.go": b"package m\n", "z/doc.txt": b"text\n"}
        one, two = pk.pack_zip("example.invalid/m@v0.0.0/", unit), pk.pack_zip("example.invalid/m@v0.0.0/", dict(unit))
        self.assertEqual(one, two)
        with zipfile.ZipFile(io.BytesIO(one)) as zf:
            self.assertEqual(zf.namelist(), ["example.invalid/m@v0.0.0/go.mod", "example.invalid/m@v0.0.0/m.go",
                                             "example.invalid/m@v0.0.0/z/doc.txt"])
            self.assertEqual({i.date_time for i in zf.infolist()}, {(1980, 1, 1, 0, 0, 0)})
        crate = {"Cargo.toml": b"[package]\nname = \"foo\"\n", "src/lib.rs": b"pub fn f() {}\n"}
        one, two = pk.pack_crate("foo-1.0.0/", crate), pk.pack_crate("foo-1.0.0/", dict(crate))
        self.assertEqual(one, two)
        self.assertEqual(gzip.decompress(one)[:9], b"foo-1.0.0")
        with tarfile.open(fileobj=io.BytesIO(one), mode="r:gz") as tf:
            self.assertEqual(tf.getnames(), ["foo-1.0.0/Cargo.toml", "foo-1.0.0/src/lib.rs"])
            self.assertEqual({m.mtime for m in tf.getmembers()}, {0})

    def test_a_unit_without_code_is_left_out(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(pk.pack_units("go", [("example.invalid/docs", {"README": b"x"})], lambda n: "v0.0.0", d),
                             [])
            self.assertEqual(os.listdir(d), [])


class UbuntuTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.debs_dir = os.path.join(self.dir, "debs")
        os.makedirs(self.debs_dir)
        self.debs = {
            "golang-example-a-dev": ("golang-example-a-dev_1.0-1_all.deb", deb_of({
                "usr/share/doc/golang-example-a-dev/copyright": EXPAT,
                "usr/share/gocode/src/example.invalid/a/go.mod": "module example.invalid/a\n",
                "usr/share/gocode/src/example.invalid/a/a.go": GO.format("a"),
                "usr/share/gocode/src/example.invalid/a/v2/go.mod": "module example.invalid/a/v2\n",
                "usr/share/gocode/src/example.invalid/a/v2/a.go": GO.format("a")})),
            "golang-example-gpl-dev": ("golang-example-gpl-dev_1.0-1_all.deb", deb_of({
                "usr/share/doc/golang-example-gpl-dev/copyright": GPL,
                "usr/share/gocode/src/example.invalid/gpl/g.go": GO.format("gpl")})),
            "librust-foo-dev": ("librust-foo-dev_1.0.0-1_amd64.deb", deb_of({
                "usr/share/doc/librust-foo-dev/copyright": EXPAT,
                "usr/share/cargo/registry/foo-1.0.0/Cargo.toml": "[package]\nname = \"foo\"\nversion = \"1.0.0\"\n",
                "usr/share/cargo/registry/foo-1.0.0/src/lib.rs": "pub fn f() -> u32 { 1 }\n"})),
        }
        self.index = os.path.join(self.dir, "Packages.xz")
        with open(self.index, "wb") as fh:
            fh.write(index_of(self.debs))
        with open(self.index, "rb") as fh:
            self.index_sha = sha(fh.read())

    def place(self, *packages):
        for pkg in packages:
            name, data = self.debs[pkg]
            with open(os.path.join(self.debs_dir, name), "wb") as fh:
                fh.write(data)

    def run_ubuntu(self, *extra, opener=None, tag="1"):
        cache, manifest = os.path.join(self.dir, "cache"), os.path.join(self.dir, f"m{tag}.jsonl")
        left = os.path.join(self.dir, f"left{tag}.jsonl")
        args = pk.build_parser().parse_args(["ubuntu", "--debs", self.debs_dir, "--cache", cache,
                                             "--manifest", manifest, "--left-out", left, "--index", self.index,
                                             "--index-sha256", self.index_sha, *extra])
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pk.cmd_ubuntu(args, opener or Archive({}))
        return code, read_jsonl(manifest), read_jsonl(left), out.getvalue() + err.getvalue()

    def test_the_index_is_pinned_and_holds_the_go_and_rust_dev_packages(self):
        with open(self.index, "rb") as fh:
            data = fh.read()
        rows = pk.read_index(data, self.index_sha)
        self.assertEqual([(r["package"], r["eco"]) for r in rows],
                         [("golang-example-a-dev", "go"), ("golang-example-gpl-dev", "go"),
                          ("librust-foo-dev", "crates")])
        with self.assertRaisesRegex(pk.SetError, "not the pinned"):
            pk.read_index(data)                                                  # noble's own sha256

    def test_each_module_and_crate_packed_and_listed_the_others_left_out(self):
        self.place(*self.debs)
        code, lines, left, said = self.run_ubuntu("--no-dpkg")
        self.assertEqual(code, pk.EXIT_OK, said)
        self.assertEqual([(x["id"], x["eco"], x["container"], x["kind"], x["cat"]) for x in lines], [
            ("ubuntu:golang-example-a-dev:example.invalid/a", "go", "zip", "gomod", "benign"),
            ("ubuntu:golang-example-a-dev:example.invalid/a/v2", "go", "zip", "gomod", "benign"),
            ("ubuntu:librust-foo-dev:foo-1.0.0", "crates", "tgz", "crate", "benign")])
        self.assertEqual(left, [{"package": "golang-example-gpl-dev", "eco": "go", "why": "licence: gpl-3+"}])
        self.assertEqual(zip_names(lines[0]["artifact_path"]),
                         ["example.invalid/a@v0.0.0/a.go", "example.invalid/a@v0.0.0/go.mod"])   # v2 is its own
        self.assertEqual(tgz_names(lines[2]["artifact_path"]), ["foo-1.0.0/Cargo.toml", "foo-1.0.0/src/lib.rs"])
        for x in lines:
            with open(x["artifact_path"], "rb") as fh:
                self.assertEqual(sha(fh.read()), x["sha256"])
        self.assertIn("3 packages, 2 kept (1 left out, 0 failed); Go modules 2, crates 1", said)
        again = self.run_ubuntu("--no-dpkg", tag="2")[1]
        self.assertEqual([x["sha256"] for x in again], [x["sha256"] for x in lines])
        if shutil.which("dpkg-deb"):                                             # dpkg-deb reads them the same
            self.assertEqual([x["sha256"] for x in self.run_ubuntu(tag="3")[1]], [x["sha256"] for x in lines])

    def test_a_missing_deb_is_fetched_and_other_bytes_are_refused(self):
        self.place("golang-example-a-dev", "golang-example-gpl-dev")
        name, data = self.debs["librust-foo-dev"]
        url = pk.UBUNTU + f"pool/universe/x/librust-foo-dev/{name}"
        code, lines, left, said = self.run_ubuntu("--no-dpkg", opener=Archive({url: data}))
        self.assertEqual((code, [x["name"] for x in lines if x["eco"] == "crates"]), (pk.EXIT_OK, ["foo-1.0.0"]))
        os.remove(os.path.join(self.debs_dir, name))
        code, lines, left, said = self.run_ubuntu("--no-dpkg", opener=Archive({url: data + b"x"}), tag="2")
        self.assertEqual(code, pk.EXIT_FAIL)
        self.assertEqual([x["eco"] for x in lines], ["go", "go"])
        self.assertIn("the index says", left[-1]["why"])
        self.assertFalse(os.path.exists(os.path.join(self.debs_dir, name)))

    def test_only_https_from_the_archive_is_fetched(self):
        with self.assertRaisesRegex(pk.SetError, "only"):
            pk.download("http://archive.ubuntu.com/ubuntu/x.deb", os.path.join(self.dir, "x"), "0" * 64, 10,
                        Archive({}))


class GoStdTests(unittest.TestCase):
    def test_std_cmd_and_each_vendored_module(self):
        with tempfile.TemporaryDirectory() as d:
            files = {"VERSION": "go1.99.0\ntime 2026-01-01T00:00:00Z\n",
                     "src/go.mod": "module std\n", "src/fmt/print.go": GO.format("fmt"),
                     "src/cmd/go.mod": "module cmd\n", "src/cmd/go/main.go": GO.format("main"),
                     "src/vendor/modules.txt":
                         "# golang.org/x/net v0.1.0\n## explicit; go 1.22\ngolang.org/x/net/http2\n",
                     "src/vendor/golang.org/x/net/http2/h2.go": GO.format("http2"),
                     "src/cmd/vendor/modules.txt": "# golang.org/x/net v0.1.0\n## explicit\ngolang.org/x/net/html\n",
                     "src/cmd/vendor/golang.org/x/net/html/h.go": GO.format("html")}
            for path, text in files.items():
                os.makedirs(os.path.dirname(os.path.join(d, "go", path)), exist_ok=True)
                with open(os.path.join(d, "go", path), "w", encoding="utf-8") as fh:
                    fh.write(text)
            manifest = os.path.join(d, "gostd.jsonl")
            with contextlib.redirect_stdout(io.StringIO()):
                code = pk.main(["gostd", "--goroot", os.path.join(d, "go"), "--cache", os.path.join(d, "c"),
                                "--manifest", manifest])
            self.assertEqual(code, pk.EXIT_OK)
            lines = read_jsonl(manifest)
            self.assertEqual([x["id"] for x in lines], [
                "gostd:go1.99.0:std@v0.0.0", "gostd:go1.99.0:cmd@v0.0.0",
                "gostd:go1.99.0:vendor/golang.org/x/net@v0.1.0", "gostd:go1.99.0:cmd/vendor/golang.org/x/net@v0.1.0"])
            names = [zip_names(x["artifact_path"]) for x in lines]
            self.assertEqual(names[0], ["std@v0.0.0/fmt/print.go", "std@v0.0.0/go.mod"])
            self.assertEqual(names[1], ["cmd@v0.0.0/go.mod", "cmd@v0.0.0/go/main.go"])
            self.assertEqual(names[2], ["golang.org/x/net@v0.1.0/http2/h2.go"])
            self.assertEqual(names[3], ["golang.org/x/net@v0.1.0/html/h.go"])


if __name__ == "__main__":
    unittest.main()
