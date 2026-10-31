"""FP-BINARY-BY-NAME: a file is a compiled binary by its bytes, not its name, in a project scan, with --deps, in the
registry and as the GitHub scan route reads a checkout.

John's corrected fp-tally: `toanle88/Agentic`'s `examples/sandbox/Dockerfile.node` was SC-BINARY ("Executable/compiled
binary in the source tree: compiled artifact (.node)"): a text Dockerfile, called a Node addon by its extension
(COMPILED_EXTS). Now a name in COMPILED_EXTS makes a file a compiled artifact only when its bytes are binary
(looks_binary, or an ar archive's text header: a static library); text is read as what it is (a Dockerfile as
config). A program's own bytes (EXEC_MAGIC: ELF, Mach-O, PE, WebAssembly, DEX, 0xCAFEBABE) are one whatever its name,
as before; a DEX's whole magic is needed now (`dex\\n` begins text too), and 0xCAFEBABE is told apart by the field
after it (a universal Mach-O's architecture count, a Java class's version). Binary bytes under such a name keep
SC-BINARY, as before. `binbandit/native`'s `….pcm` stays "Mach-O 64-bit binary": a clang precompiled module built
with module debugging (`-gmodules`) is a Mach-O object file. Files from tests/_binary_names.py, inert.
"""
import os
import shutil
import tempfile
import types
import unittest

from tests import _binary_names as bn
from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel
from lazaret.scanner import core


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-binname-")
    for rel, data in {"app.py": "x = 1\n", **files}.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode() if isinstance(data, str) else data)
    return root


def scan(files, **kw):
    root = tree(files)
    try:
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res, prefix=""):
    return {(i["file"].replace(os.sep, "/")[len(prefix):], i["rule"], i["sev"], i["msg"]) for i in res["issues"]
            if i["rule"].startswith("SC-") and i["file"].replace(os.sep, "/").startswith(prefix)}


def rules(res, prefix=""):
    return {(f, r, s) for f, r, s, _ in found(res, prefix)}


TEXT = {"examples/sandbox/Dockerfile.node": bn.DOCKERFILE, "lib/libc.so": bn.LINKER_SCRIPT,
        "notes/setup.exe": "Run setup from the release page.\n", "src/Main.class": "class Main {}\n",
        "bin/tool.dll": "placeholder\n", "x/mod.dex": "dex\nnot a dex file\n"}
BINARY = {"build/addon.node": bn.elf(), "lib/libz.a": bn.ar_archive(), "lib/libtext.a": bn.ar_text_first(),
          "out/CFNetwork-2ABC.pcm": bn.macho_object(), "bin/tool": bn.macho_fat(), "classes/Main.class": bn.java_class(),
          "classes.dex": bn.dex(), "data/blob.node": bn.filler(3000, 3)}
WANT = {("build/addon.node", "SC-BINARY", "MAJOR", "ELF binary (Linux/Unix executable or shared object)"),
        ("lib/libz.a", "SC-BINARY", "MAJOR", "compiled artifact (.a)"),
        ("lib/libtext.a", "SC-BINARY", "MAJOR", "compiled artifact (.a)"),
        ("out/CFNetwork-2ABC.pcm", "SC-BINARY", "MAJOR", "Mach-O 64-bit binary (macOS)"),
        ("bin/tool", "SC-BINARY", "MAJOR", "Mach-O universal binary (macOS)"),
        ("classes/Main.class", "SC-BINARY", "MAJOR", "Java .class bytecode"),
        ("classes.dex", "SC-BINARY", "MAJOR", "Android DEX bytecode"),
        ("data/blob.node", "SC-BINARY", "MAJOR", "compiled artifact (.node)")}


def described(res, prefix=""):
    return {(f, r, s, m.split(": ", 1)[1].rstrip(".")) for f, r, s, m in found(res, prefix) if r == "SC-BINARY"}


class TheFalsePositive(unittest.TestCase):
    def test_a_dockerfile_named_node_is_a_dockerfile(self):
        res = scan({"examples/sandbox/Dockerfile.node": bn.DOCKERFILE})
        self.assertEqual(rules(res), set(), res["issues"])
        self.assertEqual(res["supplyChain"], 0)
        self.assertEqual(res["metrics"]["configFiles"], 1)        # (read as config, as any Dockerfile is)

    def test_text_under_a_compiled_name_is_text(self):
        self.assertEqual(rules(scan(TEXT)), set())


class CompiledCode(unittest.TestCase):
    def test_by_its_bytes_whatever_its_name(self):
        self.assertEqual(described(scan(BINARY)), WANT)

    def test_with_deps(self):
        base = {"package.json": '{"dependencies": {"pkg": "1.0.0"}}', "app.js": "require('pkg')\n",
                "node_modules/pkg/package.json": '{"name": "pkg", "version": "1.0.0"}',
                "node_modules/pkg/index.js": "module.exports = 1\n"}
        files = {**base, **{f"node_modules/pkg/{k}": v for k, v in {**TEXT, **BINARY}.items()}}
        res = scan(files, include_deps=True)
        self.assertEqual(described(res, "node_modules/pkg/"), WANT)


class TheWholeFile(unittest.TestCase):
    """The review of Oct 27: a compiled name loses SC-BINARY only when the whole file is text, read to the size
    limit; a jar after a launch script, compiled code after text, a file too large to read whole keep it."""

    def test_text_first_then_compiled_code(self):
        res = scan({"app/app.jar": bn.launcher_jar(), "lib/mod.node": bn.text_then_elf(),
                    "notes/setup.exe": "Run setup from the release page.\n"})
        self.assertEqual(rules(res), {("app/app.jar", "SC-BINARY", "MAJOR"), ("lib/mod.node", "SC-BINARY", "MAJOR")})

    def test_too_large_to_read_whole(self):
        from unittest import mock
        text = bn.LINKER_SCRIPT * 200                     # (14 KB of text)
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 4096):
            self.assertEqual(rules(scan({"lib/libc.so": text})), {("lib/libc.so", "SC-BINARY", "MAJOR")})
        self.assertEqual(rules(scan({"lib/libc.so": text})), set())


class ContainerDocuments(unittest.TestCase):
    """The review of Oct 27: a document named as a container (.docx, .xlsx, .svgz, …) is quiet when its bytes are
    that container's, and otherwise judged as any file."""

    def test_by_their_bytes(self):
        res = scan({"doc/real.docx": bn.zip_of(b"word/document.xml", b"<w:document/>" * 50),
                    "doc/random.docx": bn.filler(8000, 21), "doc/archive.xlsx": b"7z\xbc\xaf\x27\x1c" + bn.filler(4000, 22),
                    "doc/prefixed.docx": b"text first\n" * 3 + bn.zip_of(b"x", bn.filler(8000, 23))})
        # (judged as any file: an archive in a project is MINOR; a project scan's sample is a file's first 512 bytes,
        # so a longer text before the zip leaves it quiet there, as any file's)
        self.assertEqual(rules(res), {("doc/random.docx", "SC-OPAQUE-BLOB", "MAJOR"),
                                      ("doc/archive.xlsx", "SC-NESTED-ARCHIVE", "MINOR"),
                                      ("doc/prefixed.docx", "SC-OPAQUE-BLOB", "MAJOR")})


class Registry(unittest.TestCase):
    def test_releases(self):
        npm = {"package.json": '{"name": "x", "version": "1.0.0", "main": "index.js"}', "index.js": "1;\n"}
        sdist = {"setup.py": "from setuptools import setup\nsetup(name='x')\n", "x/__init__.py": ""}
        files = {f"x/{k}": v for k, v in {**TEXT, **BINARY}.items()}
        # (the registry classifies a member whose first 2 KB look binary, as before: a static library whose first
        # bytes read as text, its long-names table, is not looked at there, before as now)
        want = {w for w in WANT if w[0] != "lib/libtext.a"}
        for scan_, base in ((scan_npm, npm), (scan_sdist, sdist)):
            res = scan_({**base, **files})
            self.assertEqual(described(res, "x/"), want, scan_.__name__)
        res = scan_wheel({"x/__init__.py": "", "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n", **files})
        self.assertEqual({(f, s) for f, _, s, _ in described(res, "x/")}, {(f, "INFO") for f, _, _, _ in want})


class GitHubScans(unittest.TestCase):
    def test_the_tallys_repository_shape(self):
        from lazaret.registry import ghdiscover
        root = tree({"examples/sandbox/Dockerfile.node": bn.DOCKERFILE, "README.md": "# Agentic\n"})
        self.addCleanup(shutil.rmtree, root, True)
        ck = types.SimpleNamespace(root=root, commit="0" * 40, bytes=0, files=2, incomplete=[], calls=[],
                                   skipped=[], twins=[], overlaid={})
        res = ghdiscover.result("toanle88/Agentic", ck)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
