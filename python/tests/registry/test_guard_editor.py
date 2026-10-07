"""lazaret guard code --install-extension … (0.1.9, E-1's fifth part): the version the editor would install, and every
extension it brings, fetched, checked and scanned; then the editor installs those files and nothing else.

Three kinds of test. The rules the editor chooses a version by (editorcompat), case by case, as VS Code applies them.
The registry modules' lists of what an editor chooses among (Open VSX's query API, the Marketplace's gallery query),
built in the shape each registry serves (the sandbox reaches neither; John checks them live). And the command, in this
process, against those registries and a fake editor: a Python program in PATH that answers `--version` and
`--list-extensions --show-versions` from a state file and "installs" a .vsix by recording its package.json's id and
version and the file's SHA-256, so what the editor was given, and in what order, is known. The scanner is a stand-in
(a file whose code holds SUSPICIOUS-MARK is SUSPICIOUS), except in the tests of the real scan, which use test_vsix's
inert fragments (an environment sent to a documentation address)."""

import datetime
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import editorcompat as C
from lazaret.registry import editorguard as E
from lazaret.registry import guard as G
from lazaret.registry import repo
from lazaret.registry.ecosystems import base, openvsx, vsmarketplace as vsm
from lazaret.scanner import _native
from tests.registry import test_vsmarketplace as tvm
from tests.registry._review_support import EXFIL_JS
from tests.registry.test_guard import options
from tests.registry.test_vsix import ext_manifest, vsix

API = "https://open-vsx.org/api/"
UTC = datetime.timezone.utc
NOW = datetime.datetime.now(UTC)
OLD = (NOW - datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
FRESH = (NOW - datetime.timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
MARK = "/* SUSPICIOUS-MARK */"
CONTROL = "https://lists.example.org/extensions/control.json"


def ext_file(ext_id, version, deps=(), pack=(), engine="^1.90.0", code="exports.activate = () => 1;\n"):
    """An extension's .vsix: its package.json (main, onStartupFinished, the engine, what it brings) and its code."""
    pub, name = ext_id.split(".")
    return vsix({"package.json": ext_manifest(name=name, publisher=pub, version=version, main="./extension.js",
                                              activationEvents=["onStartupFinished"], engines={"vscode": engine},
                                              extensionDependencies=list(deps), extensionPack=list(pack)),
                 "extension.js": code})


def manifest_bytes(data):
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return z.read("extension/package.json")


# ---------------------------------------------------------------- the editor's rules
class EngineTests(unittest.TestCase):
    """engines.vscode as VS Code reads it (extensionValidator's isEngineValid)."""

    def test_ranges(self):
        cases = [
            ("*", "1.105.1", True), ("^1.80.0", "1.105.1", True), ("^1.105.0", "1.105.1", True),
            ("^1.105.2", "1.105.1", False), ("^1.106.0", "1.105.1", False), ("1.105.x", "1.105.1", True),
            ("1.104.x", "1.105.1", False), (">=1.80.0", "1.105.1", True), (">=1.106.0", "1.105.1", False),
            (">=1.105.1", "1.105.1", True), ("1.105.1", "1.105.1", True), ("1.105.0", "1.105.1", False),
            ("^2.0.0", "1.105.1", False), ("1.x.x", "1.105.1", True), ("^1.105.0-insider", "1.105.1", True),
            # an editor 1.x takes a 0.x range unless it is an exact version
            ("^0.10.0", "1.105.1", True), ("0.10.x", "1.105.1", True), ("0.10.0", "1.105.1", False),
            # not specific enough, or not a range at all
            ("x.1.0", "1.105.1", False), ("0.x.0", "1.105.1", False), ("^1.80", "1.105.1", False),
            ("latest", "1.105.1", False), ("", "1.105.1", False), ("~1.80.0", "1.105.1", False),
            (" ^1.80.0 ", "1.105.1", True), (" * ", "1.105.1", False),
        ]
        for engine, product, want in cases:
            with self.subTest(engine=engine, product=product):
                self.assertIs(C.engine_ok(engine, product), want)

    def test_a_date_part_holds_back_an_older_build_of_the_same_version(self):
        built = "2025-10-08T09:59:12.906Z"
        self.assertFalse(C.engine_ok("^1.105.1-20251201", "1.105.1", built))
        self.assertTrue(C.engine_ok("^1.105.1-20251001", "1.105.1", built))
        self.assertTrue(C.engine_ok("^1.105.1-20251201", "1.105.1", None))             # (a build date not known)
        self.assertTrue(C.engine_ok("^1.105.0-20251201", "1.105.1", built))            # (a later patch: the date is not read)
        self.assertFalse(C.engine_ok(">=1.105.1-202512011200", "1.105.1", built))


class PlatformTests(unittest.TestCase):
    def test_the_target_platform(self):
        cases = [("linux", "x64", None, "linux-x64"), ("linux", "x86_64", None, "linux-x64"),
                 ("linux", "arm64", None, "linux-arm64"), ("linux", "arm", None, "linux-armhf"),
                 ("linux", "x64", 'NAME="Alpine Linux"\nID=alpine\n', "alpine-x64"),
                 ("linux", "arm64", "ID=alpine\n", "alpine-arm64"), ("linux", "x64", "ID=debian\n", "linux-x64"),
                 ("linux", "ia32", None, "unknown"), ("darwin", "arm64", None, "darwin-arm64"),
                 ("darwin", "x64", None, "darwin-x64"), ("win32", "x64", None, "win32-x64"),
                 ("win32", "AMD64", None, "win32-x64"), ("win32", "arm64", None, "win32-arm64"),
                 ("win32", "ia32", None, "unknown"), ("freebsd14", "x64", None, "unknown")]
        for system, arch, release, want in cases:
            with self.subTest(system=system, arch=arch):
                self.assertEqual(C.target_platform(system, arch, release), want)

    def test_what_fits(self):
        self.assertTrue(C.platform_fits("universal", "linux-x64"))
        self.assertTrue(C.platform_fits("undefined", "unknown"))
        self.assertTrue(C.platform_fits("linux-x64", "linux-x64"))
        self.assertFalse(C.platform_fits("linux-arm64", "linux-x64"))
        self.assertFalse(C.platform_fits("web", "linux-x64"))
        self.assertFalse(C.platform_fits("unknown", "unknown"))


class ChooseTests(unittest.TestCase):
    CANDS = [C.Candidate("1.3.0-beta.1", "universal", "^1.80.0", pre=True),
             C.Candidate("1.2.1", "linux-x64", "^1.110.0"), C.Candidate("1.2.1", "universal", "^1.80.0"),
             C.Candidate("1.2.0", "universal", "^1.80.0"), C.Candidate("1.1.0", "darwin-arm64", "^1.80.0"),
             C.Candidate("1.10.0-rc.1", "universal", "^1.80.0", pre=True)]

    def pick(self, target="linux-x64", product="1.105.1", **kw):
        c = C.choose(self.CANDS, target, product, **kw)
        return None if c is None else (c.version, c.platform)

    def test_the_newest_release_that_fits(self):
        self.assertEqual(self.pick(), ("1.2.1", "universal"))
        self.assertEqual(self.pick(product="1.111.0"), ("1.2.1", "linux-x64"))     # (the platform's own file first)
        self.assertEqual(self.pick(product=None), ("1.2.1", "linux-x64"))          # (engines not known: not checked)
        self.assertEqual(self.pick(product="1.70.0"), None)

    def test_pre_releases_only_when_asked_and_by_version_not_by_order(self):
        self.assertEqual(self.pick(pre_release=True), ("1.10.0-rc.1", "universal"))

    def test_an_exact_version_is_that_one_or_nothing(self):
        self.assertEqual(self.pick(version="1.2.0"), ("1.2.0", "universal"))
        self.assertEqual(self.pick(version="1.1.0"), None)                            # (darwin's only)
        self.assertEqual(self.pick(target="darwin-arm64", version="1.1.0"), ("1.1.0", "darwin-arm64"))
        # VS Code's walk: the platform's own file first, and the first file of the version that does not fit ends it
        self.assertEqual(self.pick(version="1.2.1"), None)
        self.assertEqual(self.pick(version="9.9.9"), None)

    def test_an_engine_the_registry_does_not_give_is_left_to_the_file(self):
        cands = [C.Candidate("2.0.0", "universal", None), C.Candidate("1.0.0", "universal", "^1.80.0")]
        self.assertEqual(C.choose(cands, "linux-x64", "1.105.1").version, "2.0.0")

    def test_version_order(self):
        versions = ["1.2.0", "1.10.0", "1.2.0-beta.2", "1.2.0-beta.10", "1.2.0-alpha", "junk", "2026.4.0", "0.4.3075"]
        self.assertEqual(sorted(versions, key=C.version_key),
                         ["junk", "0.4.3075", "1.2.0-alpha", "1.2.0-beta.2", "1.2.0-beta.10", "1.2.0", "1.10.0", "2026.4.0"])


# ---------------------------------------------------------------- the registries
def ovsx_entry(ext_id, version, data, platform="universal", pre=False, when=OLD, engine="^1.90.0", deps=(), pack=()):
    """One entry of Open VSX's query API (the shape it served on Oct 6, 2026), and the URLs it names."""
    ns, name = ext_id.split(".")
    base_name = f"{ns}.{name}-{version}" + ("" if platform == "universal" else f"@{platform}")
    root = f"{API}{ns}/{name}/" + ("" if platform == "universal" else f"{platform}/") + f"{version}/file/"
    return {"namespace": ns, "name": name, "version": version, "targetPlatform": platform, "preRelease": pre,
            "timestamp": when, "engines": {"vscode": engine}, "downloadable": True, "verified": True,
            "files": {"download": root + base_name + ".vsix", "sha256": root + base_name + ".sha256",
                      "manifest": root + "package.json", "signature": root + base_name + ".sigzip"},
            "dependencies": [{"namespace": d.split(".")[0], "extension": d.split(".")[1]} for d in deps],
            "bundledExtensions": [{"namespace": p.split(".")[0], "extension": p.split(".")[1]} for p in pack]}


class OpenVSXGallery:
    """`repo.module_transport` for Open VSX: the query API (every version, or one, newest first), each file, its
    `.sha256`, its package.json; and a list of malicious extensions at CONTROL."""

    def __init__(self):
        self.entries, self.files, self.calls = [], {}, []
        self.control = None

    def add(self, ext_id, version, platforms=("universal",), pre=False, when=OLD, engine="^1.90.0", deps=(), pack=(),
            code="exports.activate = () => 1;\n", digest=None):
        data = None
        for platform in platforms:
            data = ext_file(ext_id, version, deps, pack, engine, code + f"// {platform}\n")
            e = ovsx_entry(ext_id, version, data, platform, pre, when, engine, deps, pack)
            self.entries.append(e)
            self.files[e["files"]["download"]] = data
            self.files[e["files"]["sha256"]] = (digest or hashlib.sha256(data).hexdigest()).encode()
            self.files[e["files"]["manifest"]] = manifest_bytes(data)
        return data

    def __call__(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None, data=None,
                 content_type=None):
        check_redirect(url)
        self.calls.append(url)
        parts = urllib.parse.urlsplit(url)
        if parts.path == "/api/-/query":
            q = urllib.parse.parse_qs(parts.query)
            ext_id, version = q["extensionId"][0].lower(), q.get("extensionVersion", [None])[0]
            size, offset = int(q["size"][0]), int(q["offset"][0])
            mine = [e for e in self.entries if f"{e['namespace']}.{e['name']}".lower() == ext_id
                    and (version is None or e["version"] == version)]
            mine.sort(key=lambda e: C.version_key(e["version"]), reverse=True)
            return json.dumps({"offset": offset, "totalSize": len(mine), "extensions": mine[offset:offset + size]}).encode()
        if url == CONTROL and self.control is not None:
            return json.dumps({"malicious": self.control, "learnMoreLinks": {}}).encode()
        body = self.files.get(url)
        if body is None:
            err = base.FetchError("not found")
            err.status = 404
            raise err
        return body

    def asked(self, fragment):
        return [u for u in self.calls if fragment in u]


class OpenVSXCandidatesTests(unittest.TestCase):
    def fetch(self, gallery):
        return base.Fetch(openvsx.ECOSYSTEM, gallery, clock=lambda: 0.0, sleep=lambda s: None)

    def test_rounds_page_by_page_and_one_version(self):
        g = OpenVSXGallery()
        g.add("rust-lang.rust-analyzer", "0.3.2600", platforms=("linux-x64", "darwin-arm64"))
        g.add("rust-lang.rust-analyzer", "0.4.3075", platforms=("linux-x64",), pre=True)
        rounds = list(openvsx.ECOSYSTEM.candidates("rust-lang.rust-analyzer", self.fetch(g)))
        self.assertEqual(len(rounds), 1)
        self.assertEqual([(c.version, c.platform, c.pre) for c in rounds[0]],
                         [("0.4.3075", "linux-x64", True), ("0.3.2600", "linux-x64", False),
                          ("0.3.2600", "darwin-arm64", False)])
        c = rounds[0][1]
        self.assertEqual(c.engine, "^1.90.0")
        self.assertEqual(c.when.year, NOW.year if NOW.month > 2 else c.when.year)
        one = list(openvsx.ECOSYSTEM.candidates("rust-lang.rust-analyzer", self.fetch(g), "0.3.2600"))
        self.assertEqual([[(c.version, c.platform) for c in r] for r in one],
                         [[("0.3.2600", "linux-x64"), ("0.3.2600", "darwin-arm64")]])
        self.assertIn("extensionVersion=0.3.2600", g.calls[-1])
        with self.assertRaises(base.NotFound):
            list(openvsx.ECOSYSTEM.candidates("rust-lang.nothing", self.fetch(g)))
        with self.assertRaises(base.NotFound):
            list(openvsx.ECOSYSTEM.candidates("rust-lang.rust-analyzer", self.fetch(g), "9.9.9"))

    def test_more_pages_only_when_asked_for(self):
        g = OpenVSXGallery()
        for k in range(3):
            g.add("a.b", f"1.0.{k}")
        with mock.patch.object(openvsx, "HISTORY_PAGE", 2):
            it = openvsx.ECOSYSTEM.candidates("a.b", self.fetch(g))
            first = next(it)
            self.assertEqual([c.version for c in first], ["1.0.2", "1.0.1"])
            self.assertEqual(len(g.asked("/-/query")), 1)
            second = next(it)
            self.assertEqual([c.version for c in second], ["1.0.2", "1.0.1", "1.0.0"])
            self.assertEqual(list(it), [])

    def test_an_entry_without_its_files_or_not_served_is_not_a_candidate(self):
        g = OpenVSXGallery()
        g.add("a.b", "1.0.0")
        g.add("a.b", "1.0.1")
        g.entries[0]["downloadable"] = False
        del g.entries[1]["files"]["sha256"]
        self.assertEqual(list(openvsx.ECOSYSTEM.candidates("a.b", self.fetch(g))), [[]])

    def test_the_file_its_digest_and_its_manifest(self):
        g = OpenVSXGallery()
        data = g.add("redhat.java", "1.40.0", platforms=("linux-x64",))
        fetch = self.fetch(g)
        cand = next(openvsx.ECOSYSTEM.candidates("redhat.java", fetch))[0]
        art = openvsx.ECOSYSTEM.artifact("redhat.java", cand, fetch)
        self.assertEqual(art["filename"], "redhat.java-1.40.0@linux-x64.vsix")
        self.assertEqual(art["entry"], {"sha256": hashlib.sha256(data).hexdigest(), "platform": "linux-x64"})
        self.assertEqual(openvsx.ECOSYSTEM.verify(data, art["entry"], "redhat.java", "1.40.0")[0], "sha256")
        self.assertEqual(openvsx.ECOSYSTEM.manifest("redhat.java", cand, fetch)["version"], "1.40.0")
        cand.entry["download"] = "https://x.invalid/a.vsix"
        with self.assertRaises(base.FetchError):
            openvsx.ECOSYSTEM.artifact("redhat.java", cand, fetch)


class MarketplaceCandidatesTests(unittest.TestCase):
    def fetch(self, gallery):
        return base.Fetch(vsm.ECOSYSTEM, gallery, clock=lambda: 0.0, sleep=lambda s: None)

    def test_the_latest_first_then_every_version(self):
        entries = [tvm.version_entry("ms-python", "python", "2026.2.0", pre=True),
                   tvm.version_entry("ms-python", "python", "2026.1.0", platform="linux-x64"),
                   tvm.version_entry("ms-python", "python", "2026.1.0", platform="darwin-arm64"),
                   tvm.version_entry("ms-python", "python", "2025.9.0")]
        g = tvm.Gallery(tvm.extension("ms-python", "python", entries))
        rounds = list(vsm.ECOSYSTEM.candidates("ms-python.python", self.fetch(g)))
        self.assertEqual([[(c.version, c.platform, c.pre) for c in r] for r in rounds],
                         [[("2026.2.0", "undefined", True), ("2026.1.0", "linux-x64", False),
                           ("2026.1.0", "darwin-arm64", False)],
                          [("2026.2.0", "undefined", True), ("2026.1.0", "linux-x64", False),
                           ("2026.1.0", "darwin-arm64", False), ("2025.9.0", "undefined", False)]])
        self.assertEqual(rounds[0][0].engine, "^1.90.0")
        self.assertEqual([b["flags"] & vsm.LATEST_ONLY_FLAG for b in g.bodies], [vsm.LATEST_ONLY_FLAG, 0])
        # with a version, every version at once
        g2 = tvm.Gallery(tvm.extension("ms-python", "python", entries))
        self.assertEqual(len(list(vsm.ECOSYSTEM.candidates("ms-python.python", self.fetch(g2), "2025.9.0"))), 1)
        with self.assertRaises(base.NotFound):
            list(vsm.ECOSYSTEM.candidates("ms-python.nothing", self.fetch(tvm.Gallery(None))))

    def test_the_file_and_the_manifest_of_a_candidate(self):
        e = tvm.version_entry("ms-python", "python", "2026.1.0", platform="linux-x64", files=False)
        u = tvm.version_entry("ms-python", "python", "2026.1.0")
        g = tvm.Gallery(tvm.extension("ms-python", "python", [e, u]))
        fetch = self.fetch(g)
        cands = next(vsm.ECOSYSTEM.candidates("ms-python.python", fetch))
        art = vsm.ECOSYSTEM.artifact("ms-python.python", cands[0], fetch)
        self.assertEqual(art["url"], e["fallbackAssetUri"] + "/" + vsm.VSIX_ASSET + "?targetPlatform=linux-x64")
        self.assertEqual(art["filename"], "ms-python.python-2026.1.0@linux-x64.vsix")
        art = vsm.ECOSYSTEM.artifact("ms-python.python", cands[1], fetch)
        self.assertEqual((art["url"], art["filename"], art["entry"]),
                         (tvm.vsix_url(u), "ms-python.python-2026.1.0.vsix", {"platform": "universal"}))
        g.files[u["files"][0]["source"]] = b'{"name": "python", "publisher": "ms-python", "version": "2026.1.0"}'
        self.assertEqual(vsm.ECOSYSTEM.manifest("ms-python.python", cands[1], fetch)["publisher"], "ms-python")
        g.files[e["fallbackAssetUri"] + "/" + vsm.MANIFEST_ASSET] = b'{"name": "python"}'
        self.assertEqual(vsm.ECOSYSTEM.manifest("ms-python.python", cands[0], fetch), {"name": "python"})


# ---------------------------------------------------------------- what the guard reads of an extension
class ManifestTests(unittest.TestCase):
    def test_what_is_read(self):
        m = E.vsix_manifest(ext_file("Example.Thing", "1.2.3", deps=["Example.Base", "bad name", 5],
                                     pack=["example.other", "Example.Other"], engine="^1.90.0"))
        self.assertEqual((m.id, m.version, m.engine, m.deps, m.pack),
                         ("example.thing", "1.2.3", "^1.90.0", ("example.base",), ("example.other",)))

    def test_what_is_refused(self):
        good = ext_file("a.b", "1.0.0")
        two = vsix({"package.json": ext_manifest(name="b", publisher="a", version="1.0.0")},
                   extra={"extension/package.json": "{}"})
        cases = {"no package.json": vsix({"x.js": "1"}), "two of them": two, "not a zip": b"PK\x03\x04 nonsense",
                 "not an object": vsix({"package.json": "[1, 2]"}),
                 "no publisher": vsix({"package.json": json.dumps({"name": "b", "version": "1.0.0"})}),
                 "a bad version": vsix({"package.json": json.dumps({"name": "b", "publisher": "a", "version": "1 0"})})}
        self.assertEqual(E.vsix_manifest(good).id, "a.b")
        for what, data in cases.items():
            with self.subTest(what=what), self.assertRaises(ValueError):
                E.vsix_manifest(data)


class ArgsTests(unittest.TestCase):
    def test_the_command_line(self):
        reqs, flags, values = E.parse_args("code", ["--install-extension", "MS-Python.Python@2026.1.0",
                                                    "--install-extension=a.b@prerelease", "--force", "--profile",
                                                    "Work", "--install-extension", "sub/x.VSIX", "--pre-release",
                                                    "--user-data-dir=/u"], cwd="/w")
        self.assertEqual([(r.id, r.version, r.pre, r.path) for r in reqs],
                         [("ms-python.python", "2026.1.0", False, None), ("a.b", None, True, None),
                          (None, None, False, os.path.join("/w", "sub/x.VSIX"))])
        self.assertEqual(flags, {"--force", "--pre-release"})
        self.assertEqual(values, {"--profile": "Work", "--user-data-dir": "/u"})

    def test_what_is_refused(self):
        for args in ([], ["--list-extensions"], ["--update-extensions"], ["--uninstall-extension", "a.b"],
                     ["--install-extension"], ["--install-extension", "nope"], ["--install-extension", "a.b", "."],
                     ["--install-extension", "a.b@1.0"], ["--install-extension", "a.b", "--install-extension", "A.B"],
                     ["--install-extension", "a.b", "--force=yes"], ["--install-extension", "a.b", "--verbose"]):
            with self.subTest(args=args), self.assertRaises(G.GuardError):
                E.parse_args("code", args, cwd="/w")


# ---------------------------------------------------------------- the command, against a fake editor
FAKE_EDITOR = r'''#!{python}
import hashlib, json, os, sys, zipfile
state_path = os.environ["FAKE_EDITOR_STATE"]
with open(state_path, encoding="utf-8") as f:
    state = json.load(f)
args = sys.argv[1:]
state.setdefault("calls", []).append(args)
def save():
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f)
if args == ["--version"]:
    print(state["version"]); print("0123456789abcdef0123456789abcdef01234567"); print(state.get("arch", "x64"))
    save(); sys.exit(0)
if args[:2] == ["--list-extensions", "--show-versions"]:
    print("Extensions installed on Example:") if state.get("header") else None
    for k, v in sorted(state["installed"].items()):
        print(k + "@" + v)
    save(); sys.exit(state.get("list_exit", 0))
if "--install-extension" in args:
    k = 0
    while k < len(args):
        if args[k] == "--install-extension":
            path = args[k + 1]
            with zipfile.ZipFile(path) as z:
                m = json.loads(z.read("extension/package.json"))
            ext = (m["publisher"] + "." + m["name"]).lower()
            state["installed"][ext] = m["version"]
            with open(path, "rb") as f:
                state.setdefault("files", {})[ext] = hashlib.sha256(f.read()).hexdigest()
            state.setdefault("order", []).append(ext)
            k += 2
        else:
            k += 1
    for extra, version in state.pop("also", {}).items():
        state["installed"][extra] = version
    save(); sys.exit(state.get("install_exit", 0))
save(); sys.exit(9)
'''


class FakeScanner:
    """Stands in for guard.Scanner: a file whose code holds MARK is SUSPICIOUS, any other OK."""

    def __init__(self):
        self.calls = []

    def cached(self, key):
        return None

    def remember(self, key, hit, published):
        pass

    def holding(self, nbytes):
        return G.ByteGate(1 << 40).hold(nbytes)

    def scan(self, data, container, kind):
        import zipfile
        self.calls.append((container, kind, hashlib.sha256(data).hexdigest()))
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            text = b"".join(z.read(n) for n in z.namelist())
        if MARK.encode() in text:
            return {"verdict": "SUSPICIOUS", "reason": "1 strong supply-chain indicator",
                    "indicators": ["SC-IMPORT-RISK (CRITICAL) extension.js: sends the environment"]}
        return {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": []}

    def close(self):
        pass


class EditorCase(unittest.TestCase):
    TOOL = "codium"
    VERSION = "1.105.1"
    PRODUCT = {"nameShort": "VSCodium", "dataFolderName": ".vscode-oss", "date": "2025-10-08T09:59:12.906Z",
               "extensionsGallery": {"serviceUrl": "https://open-vsx.org/vscode/gallery", "controlUrl": CONTROL}}
    BUILTINS = {"vscode.git": "1.0.0"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-guard-ext-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.app = os.path.join(self.tmp, "app")
        os.makedirs(os.path.join(self.app, "bin"))
        self.exe = os.path.join(self.app, "bin", self.TOOL)
        if os.name == "nt":                     # (a .cmd that runs the program: Windows runs no #! line)
            script = os.path.join(self.app, "bin", "fake_editor.py")
            with open(script, "w", encoding="utf-8") as f:
                f.write(FAKE_EDITOR.split("\n", 1)[1])
            self.exe += ".cmd"
            with open(self.exe, "w", encoding="utf-8", newline="") as f:
                f.write(f'@echo off\r\n"{sys.executable}" "{script}" %*\r\n')
        else:
            with open(self.exe, "w", encoding="utf-8", newline="\n") as f:
                f.write(FAKE_EDITOR.replace("{python}", sys.executable))
            os.chmod(self.exe, 0o755)
        if self.PRODUCT is not None:
            with open(os.path.join(self.app, "product.json"), "w", encoding="utf-8") as f:
                json.dump(self.PRODUCT, f)
        for ext_id, version in self.BUILTINS.items():
            pub, name = ext_id.split(".")
            folder = os.path.join(self.app, "extensions", name)
            os.makedirs(folder)
            with open(os.path.join(folder, "package.json"), "w", encoding="utf-8") as f:
                f.write(ext_manifest(name=name, publisher=pub, version=version))
        self.state_path = os.path.join(self.tmp, "state.json")
        self.set_state(version=self.VERSION, installed={})
        self.extdir = os.path.join(self.tmp, "extensions")
        os.makedirs(self.extdir)
        scratch = os.path.join(self.tmp, "scratch")
        os.makedirs(scratch, mode=0o700)
        env = {"PATH": os.path.join(self.app, "bin") + os.pathsep + os.environ.get("PATH", ""),
               "FAKE_EDITOR_STATE": self.state_path, "VSCODE_EXTENSIONS": self.extdir,
               "LAZARET_GUARD_SCRATCH": scratch}
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        os.environ.pop("VSCODE_PORTABLE", None)
        self.gallery = self.make_gallery()
        for p in (mock.patch.object(repo, "module_transport", self.gallery),
                  mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None)):
            p.start()
            self.addCleanup(p.stop)

    def make_gallery(self):
        return OpenVSXGallery()

    def set_state(self, **kw):
        state = self.state() if os.path.exists(self.state_path) else {}
        state.update(kw)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(state, f)

    def state(self):
        with open(self.state_path, encoding="utf-8") as f:
            return json.load(f)

    def installs(self):
        """The editor's --install-extension commands: [[the ids of its files, in order], the other words]."""
        out = []
        for call in self.state().get("calls", []):
            if "--install-extension" in call:
                files = [os.path.basename(call[k + 1]) for k, a in enumerate(call) if a == "--install-extension"]
                rest = [a for k, a in enumerate(call) if a != "--install-extension"
                        and (k == 0 or call[k - 1] != "--install-extension")]
                out.append((files, rest))
        return out

    def run_guard(self, *args, real_scanner=False, **opts):
        gallery = opts.pop("gallery", None)
        ctx = G.Context(options(tool=self.TOOL, args=list(args), gallery=gallery, **opts), out=io.StringIO())
        if not real_scanner:
            ctx.scanner.close()
            ctx.scanner = FakeScanner()
        self.ctx = ctx
        try:
            code = E.guard_editor(ctx, self.TOOL, list(args), gallery)
        except G.GuardError as exc:
            ctx.say(f"GuardError: {exc}")
            code = G.EXIT_USAGE
        finally:
            ctx.close()
        self.out = ctx.out.getvalue()
        return code


class InstallTests(EditorCase):
    def test_one_extension_checked_then_installed_from_the_checked_file(self):
        data = self.gallery.add("redhat.vscode-yaml", "1.25.0", platforms=("universal",))
        self.gallery.add("redhat.vscode-yaml", "1.26.0-next.1", pre=True)
        code = self.run_guard("--install-extension", "redhat.vscode-yaml")
        self.assertEqual(code, 0, self.out)
        st = self.state()
        self.assertEqual(st["installed"], {"redhat.vscode-yaml": "1.25.0"})
        self.assertEqual(st["files"]["redhat.vscode-yaml"], hashlib.sha256(data).hexdigest())
        [(files, rest)] = self.installs()
        self.assertEqual(files, ["1-redhat.vscode-yaml-1.25.0.vsix"])
        self.assertEqual(rest, ["--do-not-include-pack-dependencies"])
        self.assertIn("lazaret guard: VSCodium 1.105.1 for ", self.out)
        self.assertIn("checked 1 OK", self.out)
        # the digest was read, the file fetched, the control list read; and nothing is left in the scratch folder
        self.assertEqual(len(self.gallery.asked(".sha256")), 1)
        self.assertEqual(os.listdir(os.environ["LAZARET_GUARD_SCRATCH"]), [])

    def test_installed_already_is_left_alone_as_the_editor_leaves_it(self):
        self.gallery.add("redhat.vscode-yaml", "1.25.0")
        self.set_state(installed={"redhat.vscode-yaml": "1.24.0"})
        self.assertEqual(self.run_guard("--install-extension", "redhat.vscode-yaml"), 0)
        self.assertIn("is installed already, and the editor leaves it", self.out)
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.gallery.calls, [])
        self.assertEqual(self.run_guard("--install-extension", "redhat.vscode-yaml@prerelease"), 0)
        self.assertEqual(self.installs(), [])
        # --force updates it; the version given is installed
        self.assertEqual(self.run_guard("--install-extension", "redhat.vscode-yaml", "--force"), 0, self.out)
        self.assertEqual(self.state()["installed"], {"redhat.vscode-yaml": "1.25.0"})
        self.assertEqual(self.run_guard("--install-extension", "redhat.vscode-yaml@1.25.0"), 0)
        self.assertIn("redhat.vscode-yaml@1.25.0 is installed already", self.out)

    def test_a_built_in_extension_is_installed_already(self):
        self.gallery.add("vscode.git", "2.0.0")
        self.assertEqual(self.run_guard("--install-extension", "vscode.git"), 0)
        self.assertIn("vscode.git 1.0.0 is installed already, and the editor leaves it", self.out)
        self.assertEqual(self.installs(), [])

    def test_an_older_version_given_is_installed_over_a_newer_one(self):
        self.gallery.add("redhat.vscode-yaml", "1.20.0")
        self.gallery.add("redhat.vscode-yaml", "1.25.0")
        self.set_state(installed={"redhat.vscode-yaml": "1.25.0"})
        self.assertEqual(self.run_guard("--install-extension", "redhat.vscode-yaml@1.20.0"), 0, self.out)
        self.assertEqual(self.state()["installed"], {"redhat.vscode-yaml": "1.20.0"})
        [(_files, rest)] = self.installs()
        self.assertIn("--force", rest)                      # (the editor installs an older file only with --force)

    def test_pre_releases(self):
        self.gallery.add("a.b", "1.0.0")
        self.gallery.add("a.b", "1.1.0-beta.1", pre=True)
        self.assertEqual(self.run_guard("--install-extension", "a.b", "--pre-release", plan=True), 0)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.1.0-beta.1"])
        self.assertEqual(self.run_guard("--install-extension", "a.b@prerelease", plan=True), 0)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.1.0-beta.1"])
        self.assertEqual(self.run_guard("--install-extension", "a.b", plan=True), 0)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.0.0"])
        self.assertIn("nothing was installed", self.out)
        self.assertEqual(self.installs(), [])

    def test_the_newest_version_for_this_editor_and_this_platform(self):
        target = C.target_platform(sys.platform, "x64")
        other = "darwin-arm64" if target != "darwin-arm64" else "linux-x64"
        self.gallery.add("a.b", "1.0.0")
        self.gallery.add("a.b", "1.1.0", platforms=(other,))
        self.gallery.add("a.b", "1.2.0", engine="^1.110.0")
        self.assertEqual(self.run_guard("--install-extension", "a.b", plan=True), 0, self.out)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.0.0"])
        self.assertEqual(self.run_guard("--install-extension", "a.b@1.2.0"), G.EXIT_RESOLVE)
        self.assertIn("a.b@1.2.0 cannot be installed: none of its versions is for VSCodium 1.105.1", self.out)
        self.assertEqual(self.run_guard("--install-extension", "a.b@1.1.0"), G.EXIT_RESOLVE)
        self.assertIn(f"it has no file for {target}", self.out)
        self.assertEqual(self.installs(), [])

    def test_what_cannot_be_installed_stops_the_run_before_anything_is(self):
        self.gallery.add("a.b", "1.0.0")
        self.gallery.add("c.d", "1.0.0")
        self.gallery.add("only.pre", "1.0.0-rc.1", pre=True)
        for spec, says in (("no.such", "not found in Open VSX"), ("c.d@9.9.9", "not found in Open VSX (no version 9.9.9)"),
                           ("only.pre", "it has no release, only pre-releases (--pre-release installs one)")):
            with self.subTest(spec=spec):
                self.assertEqual(self.run_guard("--install-extension", "a.b", "--install-extension", spec),
                                 G.EXIT_RESOLVE)
                self.assertIn(says, self.out)
                self.assertEqual(self.installs(), [])

    def test_a_suspicious_extension_blocks_the_whole_install(self):
        self.gallery.add("a.b", "1.0.0")
        self.gallery.add("evil.ext", "1.0.0", code=MARK + EXFIL_JS)
        code = self.run_guard("--install-extension", "a.b", "--install-extension", "evil.ext")
        self.assertEqual(code, G.EXIT_BLOCKED)
        self.assertIn("BLOCKED    evil.ext@1.0.0: SUSPICIOUS", self.out)
        self.assertIn("1 blocked — nothing was installed", self.out)
        self.assertEqual(self.installs(), [])
        # --trust lets it through, and says so
        self.assertEqual(self.run_guard("--install-extension", "a.b", "--install-extension", "evil.ext",
                                        trust=["evil.*"]), 0, self.out)
        self.assertIn("TRUSTED", self.out)

    def test_a_file_that_is_not_the_one_the_registry_published_is_blocked(self):
        self.gallery.add("a.b", "1.0.0", digest="00" * 32)
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("not the file Open VSX published", self.out)
        self.assertEqual(self.installs(), [])

    def test_a_file_of_another_extension_or_version_is_blocked(self):
        self.gallery.add("a.b", "1.0.0")
        e = self.gallery.entries[0]
        self.gallery.files[e["files"]["download"]] = ext_file("a.b", "0.9.0")
        self.gallery.files[e["files"]["sha256"]] = hashlib.sha256(ext_file("a.b", "0.9.0")).hexdigest().encode()
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("the file is a.b@0.9.0, not the version the registry named", self.out)

    def test_a_registry_that_cannot_be_reached_blocks(self):
        self.gallery.add("a.b", "1.0.0")
        del self.gallery.files[self.gallery.entries[0]["files"]["download"]]
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("could not be checked", self.out)
        self.assertEqual(self.installs(), [])

    def test_too_new_is_held_unless_allowed(self):
        self.gallery.add("a.b", "1.0.0", when=FRESH)
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("published 3 hours ago, under --min-age 2 days (--allow-new a.b lets it through)", self.out)
        self.assertEqual(self.run_guard("--install-extension", "a.b", allow_new=["a.b"]), 0, self.out)
        self.assertEqual(self.state()["installed"], {"a.b": "1.0.0"})

    def test_the_galleries_list_of_malicious_extensions(self):
        self.gallery.add("bad.one", "1.0.0")
        self.gallery.add("badpub.thing", "1.0.0")
        self.gallery.add("a.b", "1.0.0")
        self.gallery.control = ["Bad.One", "BadPub", "not.listed"]
        self.assertEqual(self.run_guard("--install-extension", "bad.one", "--install-extension", "badpub.thing",
                                        "--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("bad.one@1.0.0: the extension is on the list of malicious extensions VSCodium's gallery keeps "
                      "(lists.example.org)", self.out)
        self.assertIn("badpub.thing@1.0.0: its publisher badpub is on the list", self.out)
        self.assertEqual(self.installs(), [])
        # a list that cannot be read is said, and the run goes on
        self.gallery.control = None
        self.assertEqual(self.run_guard("--install-extension", "a.b"), 0)
        self.assertIn("the list of malicious extensions at lists.example.org could not be read", self.out)

    def test_what_the_editor_installs_beyond_what_was_checked_fails_the_run(self):
        self.gallery.add("a.b", "1.0.0")
        self.set_state(also={"sneaky.ext": "6.6.6"})
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_BLOCKED)
        self.assertIn("installed but not checked: sneaky.ext@6.6.6", self.out)
        self.assertIn("the editor installed or updated them itself", self.out)

    def test_the_editors_own_failure_is_its_exit_code(self):
        self.gallery.add("a.b", "1.0.0")
        self.set_state(install_exit=1, also={})
        self.assertEqual(self.run_guard("--install-extension", "a.b"), 1)

    def test_the_profile_and_folders_are_passed_on(self):
        self.gallery.add("a.b", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", "a.b", "--profile", "Work", "--do-not-sync"), 0)
        lists = [c for c in self.state()["calls"] if c[:1] == ["--list-extensions"]]
        self.assertEqual(lists, [["--list-extensions", "--show-versions", "--profile", "Work"]] * 2)
        [(_files, rest)] = self.installs()
        self.assertEqual(rest, ["--profile", "Work", "--do-not-sync", "--do-not-include-pack-dependencies"])

    def test_an_editor_that_cannot_list_its_extensions_stops_the_run(self):
        self.gallery.add("a.b", "1.0.0")
        self.set_state(list_exit=1)
        self.assertEqual(self.run_guard("--install-extension", "a.b"), G.EXIT_USAGE)
        self.assertIn("--list-extensions failed (exit 1)", self.out)


class BringsTests(EditorCase):
    def test_dependencies_and_pack_members_as_the_editor_walks_them(self):
        g = self.gallery
        g.add("ex.app", "1.0.0", deps=["ex.base", "vscode.git"], pack=["ex.member", "ex.installed"])
        g.add("ex.base", "2.0.0", deps=["ex.deep"])
        g.add("ex.deep", "3.0.0")
        g.add("ex.member", "1.0.0")
        g.add("ex.installed", "5.0.0", deps=["ex.fromnewer"])     # (installed at 4.0.0: its newest version is read)
        g.add("ex.fromnewer", "1.0.0")
        self.set_state(installed={"ex.installed": "4.0.0"})
        self.assertEqual(self.run_guard("--install-extension", "ex.app"), 0, self.out)
        self.assertEqual(self.state()["installed"], {"ex.app": "1.0.0", "ex.base": "2.0.0", "ex.deep": "3.0.0",
                                                     "ex.member": "1.0.0", "ex.installed": "4.0.0",
                                                     "ex.fromnewer": "1.0.0"})
        self.assertEqual(sorted(c.name for c in self.ctx.checks),
                         ["ex.app", "ex.base", "ex.deep", "ex.fromnewer", "ex.member"])
        # the built-in vscode.git is installed as far as the editor is concerned: never asked for
        self.assertEqual(g.asked("vscode.git"), [])
        # the installed member's newest version: its manifest read, not its file
        self.assertEqual(g.asked("ex.installed-5.0.0.vsix"), [])
        self.assertEqual(len(g.asked("installed/5.0.0/file/package.json")), 1)
        [(files, rest)] = self.installs()
        self.assertEqual(len(files), 5)
        self.assertIn("--do-not-include-pack-dependencies", rest)

    def test_a_dependency_that_cannot_be_installed_fails_and_a_pack_member_is_left_out(self):
        g = self.gallery
        g.add("ex.app", "1.0.0", deps=["ex.missing"])
        g.add("ex.pack", "1.0.0", pack=["ex.gone", "ex.member"])
        g.add("ex.member", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", "ex.app"), G.EXIT_RESOLVE)
        self.assertIn("ex.app cannot be installed: it needs ex.missing, which the editor cannot install: not found",
                      self.out)
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.run_guard("--install-extension", "ex.pack"), 0, self.out)
        self.assertIn("ex.gone, in the pack of ex.pack, is left out, as the editor leaves it: not found", self.out)
        self.assertEqual(sorted(self.state()["installed"]), ["ex.member", "ex.pack"])

    def test_a_suspicious_member_blocks_the_pack(self):
        g = self.gallery
        g.add("ex.pack", "1.0.0", pack=["ex.member", "ex.evil"])
        g.add("ex.member", "1.0.0")
        g.add("ex.evil", "1.0.0", code=MARK + EXFIL_JS)
        self.assertEqual(self.run_guard("--install-extension", "ex.pack"), G.EXIT_BLOCKED)
        self.assertIn("BLOCKED    ex.evil@1.0.0", self.out)
        self.assertEqual(self.installs(), [])

    def test_pre_releases_for_what_a_pre_release_brings(self):
        g = self.gallery
        g.add("ex.app", "2.0.0-rc.1", pre=True, deps=["ex.base"])
        g.add("ex.base", "1.0.0")
        g.add("ex.base", "1.1.0-rc.1", pre=True)
        self.assertEqual(self.run_guard("--install-extension", "ex.app@prerelease", plan=True), 0, self.out)
        self.assertEqual(sorted((c.name, c.version) for c in self.ctx.checks),
                         [("ex.app", "2.0.0-rc.1"), ("ex.base", "1.1.0-rc.1")])

    def test_updating_a_pack_brings_only_its_new_members(self):
        g = self.gallery
        g.add("ex.pack", "2.0.0", pack=["ex.old", "ex.new"])
        g.add("ex.old", "1.0.0")
        g.add("ex.new", "1.0.0")
        self.set_state(installed={"ex.pack": "1.0.0"})
        folder = os.path.join(self.extdir, "ex.pack-1.0.0")
        os.makedirs(folder)
        with open(os.path.join(folder, "package.json"), "w", encoding="utf-8") as f:
            f.write(ext_manifest(name="pack", publisher="ex", version="1.0.0", extensionPack=["ex.old"]))
        self.assertEqual(self.run_guard("--install-extension", "ex.pack", "--force"), 0, self.out)
        self.assertEqual(sorted(self.state()["installed"]), ["ex.new", "ex.pack"])     # (ex.old was uninstalled: left so)

    def test_do_not_include_pack_dependencies(self):
        self.gallery.add("ex.app", "1.0.0", deps=["ex.base"])
        self.assertEqual(self.run_guard("--install-extension", "ex.app", "--do-not-include-pack-dependencies"), 0)
        self.assertEqual(self.state()["installed"], {"ex.app": "1.0.0"})
        self.assertEqual(self.gallery.asked("ex.base"), [])


class OlderEditorTests(EditorCase):
    VERSION = "1.90.2"

    def test_what_an_extension_brings_is_installed_before_it(self):
        g = self.gallery
        g.add("ex.app", "1.0.0", deps=["ex.base"], pack=["ex.member"])
        g.add("ex.base", "1.0.0", deps=["ex.deep"])
        g.add("ex.deep", "1.0.0")
        g.add("ex.member", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", "ex.app"), 0, self.out)
        waves = [sorted(f.split("-", 1)[1].rsplit("-", 1)[0] for f in files) for files, _rest in self.installs()]
        self.assertEqual(waves, [["ex.deep", "ex.member"], ["ex.base"], ["ex.app"]])
        self.assertTrue(all("--do-not-include-pack-dependencies" not in rest for _f, rest in self.installs()))

    def test_extensions_that_bring_one_another_are_not_installed(self):
        g = self.gallery
        g.add("ex.a", "1.0.0", deps=["ex.b"])
        g.add("ex.b", "1.0.0", deps=["ex.a"])
        self.assertEqual(self.run_guard("--install-extension", "ex.a"), G.EXIT_RESOLVE)
        self.assertIn("ex.a, ex.b bring one another, and VSCodium 1.90.2 installs what an extension brings itself", self.out)
        self.assertEqual(self.installs(), [])

    def test_the_flag_it_does_not_know_is_refused(self):
        self.gallery.add("ex.app", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", "ex.app", "--do-not-include-pack-dependencies"),
                         G.EXIT_USAGE)
        self.assertIn("does not know --do-not-include-pack-dependencies", self.out)


class ForkVersionTests(EditorCase):
    """A fork that reports its own version: its product.json's vscodeVersion when it has one; else engines are not
    checked (the editor checks the file it installs)."""
    TOOL = "cursor"
    VERSION = "1.7.38"
    PRODUCT = {"nameShort": "Cursor", "dataFolderName": ".cursor", "vscodeVersion": "1.99.3",
               "extensionsGallery": {"serviceUrl": "https://marketplace.example.com/_apis/public/gallery"}}

    def test_vscode_version_from_product_json(self):
        self.gallery.add("a.b", "1.0.0", engine="^1.99.0")
        self.gallery.add("a.b", "1.1.0", engine="^1.100.0")
        self.assertEqual(self.run_guard("--install-extension", "a.b", plan=True), 0, self.out)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.0.0"])
        self.assertIn("Cursor 1.7.38 (VS Code 1.99.3)", self.out)
        self.assertIn("names a gallery the guard does not read ('marketplace.example.com'): it reads Open VSX", self.out)

    def test_no_vscode_version_known(self):
        with open(os.path.join(self.app, "product.json"), "w", encoding="utf-8") as f:
            json.dump({"nameShort": "Cursor"}, f)
        self.gallery.add("a.b", "1.0.0", engine="^1.99.0")
        self.gallery.add("a.b", "1.1.0", engine="^1.200.0")
        self.assertEqual(self.run_guard("--install-extension", "a.b", plan=True), 0, self.out)
        self.assertEqual([c.version for c in self.ctx.checks], ["1.1.0"])
        self.assertIn("Cursor reports version 1.7.38, not a VS Code version", self.out)


class FileTests(EditorCase):
    def write(self, name, data):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_a_vsix_file_is_scanned_and_installed_from_the_guards_copy(self):
        data = ext_file("my.ext", "0.1.0", deps=["ex.base"])
        path = self.write("my.vsix", data)
        self.gallery.add("ex.base", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", path), 0, self.out)
        st = self.state()
        self.assertEqual(st["installed"], {"my.ext": "0.1.0", "ex.base": "1.0.0"})
        self.assertEqual(st["files"]["my.ext"], hashlib.sha256(data).hexdigest())
        files = [f for fs, _r in self.installs() for f in fs]
        self.assertNotIn("my.vsix", files)                          # (the guard's copy, not the user's file)
        self.assertEqual([c.eco for c in self.ctx.checks if c.name == "my.ext"], ["vsix"])

    def test_a_suspicious_file_is_not_installed(self):
        path = self.write("evil.vsix", ext_file("my.ext", "0.1.0", code=MARK + EXFIL_JS))
        self.assertEqual(self.run_guard("--install-extension", path), G.EXIT_BLOCKED)
        self.assertEqual(self.installs(), [])

    def test_a_newer_one_installed_is_left_alone_without_force(self):
        path = self.write("old.vsix", ext_file("my.ext", "0.1.0"))
        self.set_state(installed={"my.ext": "0.2.0"})
        self.assertEqual(self.run_guard("--install-extension", path), 0)
        self.assertIn("a newer my.ext (0.2.0) is installed; the editor leaves it", self.out)
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.run_guard("--install-extension", path, "--force"), 0)
        self.assertEqual(self.state()["installed"], {"my.ext": "0.1.0"})

    def test_what_a_file_brings_that_cannot_be_installed_is_left_out(self):
        path = self.write("my.vsix", ext_file("my.ext", "0.1.0", deps=["ex.missing"]))
        self.assertEqual(self.run_guard("--install-extension", path), 0, self.out)
        self.assertIn("is left out, as the editor leaves it when one of them cannot be installed", self.out)
        self.assertEqual(self.state()["installed"], {"my.ext": "0.1.0"})

    def test_files_that_are_not_extensions_or_not_for_this_editor(self):
        for name, data, says in (("x.vsix", b"not a zip", "is not an extension the editor installs"),
                                 ("new.vsix", ext_file("my.ext", "0.1.0", engine="^1.200.0"),
                                  "is not for VSCodium 1.105.1")):
            with self.subTest(name=name):
                self.assertEqual(self.run_guard("--install-extension", self.write(name, data)), G.EXIT_USAGE)
                self.assertIn(says, self.out)
        self.assertEqual(self.run_guard("--install-extension", os.path.join(self.tmp, "none.vsix")), G.EXIT_USAGE)


class MarketplaceTests(EditorCase):
    """VS Code: the Marketplace's gallery query, files without a digest, Microsoft's list of malicious extensions."""
    TOOL = "code"
    PRODUCT = None

    def make_gallery(self):
        self.entries = []
        g = tvm.Gallery(None)
        g.files[E.MARKETPLACE_CONTROL] = json.dumps({"malicious": ["evilpub"]}).encode()
        return g

    def publish(self, pub, name, version, deps="", pack="", pre=False, code="exports.activate = () => 1;\n"):
        data = ext_file(f"{pub}.{name}", version, [d for d in deps.split(",") if d], [p for p in pack.split(",") if p],
                        code=code)
        entry = tvm.version_entry(pub, name, version, pre=pre, deps=deps, pack=pack)
        entry["lastUpdated"] = OLD
        self.gallery.files[tvm.vsix_url(entry)] = data
        self.entries.append(((pub, name), entry))
        return data

    def serve(self):
        """The gallery answers for each extension asked for (test_vsmarketplace's Gallery answers for one; here each
        query is answered by one of its own, for the extension asked for)."""
        entries = self.entries

        def query(body):
            asked = next(c["value"] for c in body["filters"][0]["criteria"] if c["filterType"] == 7).lower()
            versions = [e for (pub, name), e in entries if f"{pub}.{name}" == asked]
            if not versions:
                return None
            pub, name = asked.split(".")
            ext = tvm.extension(pub, name, sorted(versions, key=lambda e: C.version_key(e["version"]), reverse=True))
            return tvm.Gallery(ext).query(body)
        self.gallery.query = query

    def test_from_the_marketplace(self):
        data = self.publish("ms-python", "python", "2026.1.0", deps="ms-python.debugpy")
        self.publish("ms-python", "python", "2026.2.0", pre=True)
        self.publish("ms-python", "debugpy", "2026.0.0")
        self.serve()
        self.assertEqual(self.run_guard("--install-extension", "ms-python.python"), 0, self.out)
        st = self.state()
        self.assertEqual(st["installed"], {"ms-python.python": "2026.1.0", "ms-python.debugpy": "2026.0.0"})
        self.assertEqual(st["files"]["ms-python.python"], hashlib.sha256(data).hexdigest())
        self.assertIn("extensions from the Visual Studio Marketplace", self.out)
        self.assertEqual([u for u, _a, _t in self.gallery.calls if u == E.MARKETPLACE_CONTROL], [E.MARKETPLACE_CONTROL])

    def test_microsofts_list_blocks(self):
        self.publish("evilpub", "thing", "1.0.0")
        self.serve()
        self.assertEqual(self.run_guard("--install-extension", "evilpub.thing"), G.EXIT_BLOCKED)
        self.assertIn("its publisher evilpub is on the list of malicious extensions VS Code's gallery keeps "
                      "(main.vscode-cdn.net)", self.out)

    def test_the_gallery_option(self):
        ovsx = OpenVSXGallery()
        ovsx.add("a.b", "1.0.0")
        with mock.patch.object(repo, "module_transport", ovsx):
            self.assertEqual(self.run_guard("--install-extension", "a.b", gallery="openvsx"), 0, self.out)
        self.assertIn("extensions from Open VSX", self.out)
        self.assertEqual(self.state()["installed"], {"a.b": "1.0.0"})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RealScanTests(EditorCase):
    def test_an_extension_that_sends_the_environment_when_the_editor_starts_is_blocked(self):
        self.gallery.add("ex.evil", "1.0.0", code="exports.activate = () => {\n" + EXFIL_JS + "};\n")
        self.gallery.add("ex.fine", "1.0.0")
        self.assertEqual(self.run_guard("--install-extension", "ex.evil", "--install-extension", "ex.fine",
                                        real_scanner=True), G.EXIT_BLOCKED, self.out)
        self.assertIn("BLOCKED    ex.evil@1.0.0: SUSPICIOUS", self.out)
        self.assertEqual(self.installs(), [])
        self.assertEqual(self.run_guard("--install-extension", "ex.fine", real_scanner=True), 0, self.out)


class WavesTests(unittest.TestCase):
    def test_order(self):
        def item(i):
            it = E.Item(i, "x")
            return it
        items = [item(i) for i in ("a", "b", "c", "d")]
        brings = {"a": ["b", "c"], "b": ["c", "zz"], "c": [], "d": ["d"]}
        waves, cycle = E.order_waves(items, lambda i: brings[i.id])
        self.assertEqual([[i.id for i in w] for w in waves], [["c", "d"], ["b"], ["a"]])
        self.assertEqual(cycle, [])
        brings = {"a": ["b"], "b": ["a"], "c": [], "d": ["c"]}
        waves, cycle = E.order_waves(items, lambda i: brings[i.id])
        self.assertEqual([[i.id for i in w] for w in waves], [["c"], ["d"]])
        self.assertEqual(sorted(i.id for i in cycle), ["a", "b"])


class CommandLineTests(unittest.TestCase):
    def test_the_editors_are_tools_of_the_guard(self):
        ap = G.build_parser()
        for tool in E.EDITORS:
            self.assertIn(tool, G.TOOLS)
            opts = ap.parse_args(["--gallery", "openvsx", tool, "--install-extension", "a.b"])
            self.assertEqual((opts.tool, opts.gallery, opts.args), (tool, "openvsx", ["--install-extension", "a.b"]))
        self.assertEqual(set(G.EDITOR_TOOLS), set(E.EDITORS))

    def test_lazaret_guard_takes_them(self):
        from lazaret import _cli
        self.assertEqual(set(_cli.GUARD_TOOLS), set(G.TOOLS))
        self.assertTrue(_cli.is_guard(["guard", "code", "--install-extension", "ms-python.python"]))
        self.assertTrue(_cli.is_guard(["guard", "--plan", "cursor", "--install-extension", "a.b"]))

    def test_the_npm_packages_pointer_knows_them_too(self):
        import re
        cli_js = os.path.join(os.path.dirname(__file__), "..", "..", "..", "js", "src", "cli.js")
        if not os.path.isfile(cli_js):
            self.skipTest("the npm package's sources are not here")
        with open(cli_js, encoding="utf-8") as f:
            listed = re.search(r"const GUARD_TOOLS = \[([^\]]*)\]", f.read()).group(1)
        self.assertEqual(set(re.findall(r'"([^"]+)"', listed)), set(G.TOOLS))


if __name__ == "__main__":
    unittest.main()
