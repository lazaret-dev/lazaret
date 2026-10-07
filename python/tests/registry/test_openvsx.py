"""Open VSX (0.1.9, E-1's second part): `lazaret-registry openvsx:namespace.name[@version]` resolves an extension to
its `.vsix` files, one per target platform it is published for, checks each against the SHA-256 Open VSX publishes
beside it, and scans them as `lazaret FILE.vsix` does (repo.py's `vsix` kind).

The registry's answers are built here, in the shape open-vsx.org served on Oct 6, 2026 (its keys, its `downloads`
map, its file URLs and their `.sha256` neighbours, `verified`, `publishedBy`, `dependencies` and
`bundledExtensions` as objects): the sandbox cannot reach the registry, so nothing could be recorded, and John checks
the module against the live registry. The extensions are built here too, inert (test_vsix's fragments: an
environment sent to a documentation address). Nothing opens a socket."""

import hashlib
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io
from unittest import mock

from lazaret.registry import repo
from lazaret.registry.ecosystems import base, openvsx
from lazaret.scanner import _native
from tests.registry._review_support import EXFIL_JS
from tests.registry.ecosystem_contract import EcosystemContract
from tests.registry.test_registry_go_crates import Served
from tests.registry.test_vsix import ext_manifest, vsix

API = "https://open-vsx.org/api/"
PLAIN = vsix({"package.json": ext_manifest(name="vscode-yaml", publisher="redhat", version="1.25.0",
                                           main="./dist/extension.js", activationEvents=["onLanguage:yaml"]),
              "dist/extension.js": "exports.activate = () => 1;\n"})


def file_url(ns, name, version, filename, platform=None):
    return f"{API}{ns}/{name}/" + (f"{platform}/" if platform else "") + f"{version}/file/{filename}"


def document(ns, name, version, platform="universal", platforms=("universal",), **extra):
    """One version's answer from /api/<ns>/<name>[/<platform>]/<version>, in the shape Open VSX serves."""
    def files(p):
        base_name = f"{ns}.{name}-{version}" + ("" if p == "universal" else f"@{p}")
        where = None if p == "universal" else p
        return {"download": file_url(ns, name, version, base_name + ".vsix", where),
                "signature": file_url(ns, name, version, base_name + ".sigzip", where),
                "manifest": file_url(ns, name, version, "package.json", where),
                "sha256": file_url(ns, name, version, base_name + ".sha256", where),
                "publicKey": "https://open-vsx.org/api/-/public-key/00000000-0000-0000-0000-000000000000"}
    doc = {"namespace": ns, "name": name, "version": version, "targetPlatform": platform, "files": files(platform),
           "downloads": {p: files(p)["download"] for p in platforms}, "downloadable": True, "verified": True,
           "publishedBy": {"loginName": "example-ci", "provider": "github", "fullName": "Example CI"},
           "preRelease": False, "deprecated": False, "timestamp": "2026-10-06T08:18:12.286437Z",
           "dependencies": [], "bundledExtensions": [], "versionAlias": ["latest"],
           "allVersions": {"latest": f"{API}{ns}/{name}/latest", version: f"{API}{ns}/{name}/{version}"},
           "engines": {"vscode": "^1.90.0"}}
    doc.update(extra)
    return doc


def responses(ns, name, version, data_by_platform, latest=True, **extra):
    """Every URL a resolve and a scan of `ns.name@version` asks for: the documents, each file's digest, each file."""
    platforms = tuple(sorted(data_by_platform))
    main = "universal" if "universal" in platforms else platforms[0]
    out = {}
    top = json.dumps(document(ns, name, version, main, platforms, **extra)).encode()
    out[f"{API}{ns}/{name}/{version}"] = top
    if latest:
        out[f"{API}{ns}/{name}"] = top
    for p, data in data_by_platform.items():
        doc = document(ns, name, version, p, (p,), **extra)
        if p != main:
            out[f"{API}{ns}/{name}/{p}/{version}"] = json.dumps(doc).encode()
        out[doc["files"]["sha256"]] = hashlib.sha256(data).hexdigest().encode()
        out[doc["files"]["download"]] = data
    return out


class OpenVSXContract(EcosystemContract, unittest.TestCase):
    GOOD_NAMES = ("redhat.vscode-yaml", "ms-python.python", "Example.My-Ext", "a.b", "a1.b2")
    GOOD_VERSIONS = ("1.25.0", "0.4.3074", "2026.4.0", "1.0.0-beta.1")
    GOOD_SPEC = ("redhat.vscode-yaml", "1.25.0")
    SAME_IDENTITY = (("redhat.vscode-yaml", "RedHat.VSCode-YAML"),)
    DIFFERENT_IDENTITY = (("redhat.vscode-yaml", "redhat.vscode-yml"), ("a.bc", "ab.c"))
    EXTRA_BAD_NAMES = ("redhat", "redhat.", ".vscode-yaml", "a.b.c", "-a.b", "a.-b", "a_b.c", "a.b_c", "a..b",
                       "a." + "b" * 129, "a/b.c", "redhat.vscode yaml")
    MEMBER_PATHS = (("vsix", "extension/package.json", None, ("package.json", None)),
                    ("vsix", "extension/./dist//a.js", None, ("dist/a.js", None)),
                    ("vsix", "extension.vsixmanifest", None, (None, None)),
                    ("vsix", "[Content_Types].xml", None, (None, None)),
                    ("vsix", "Extension/a.js", None, (None, None)),
                    ("vsix", "extension/../a.js", None, (None, "path contains '..'")))

    def make(self):
        return openvsx.OpenVSX()

    def responses(self):
        return responses("redhat", "vscode-yaml", "1.25.0", {"universal": PLAIN})

    def verify_case(self):
        return PLAIN, {"sha256": hashlib.sha256(PLAIN).hexdigest(), "platform": "universal"}, *self.GOOD_SPEC

    def malformed_digests(self):
        return ({"sha256": "x" * 64}, {"sha256": hashlib.sha256(PLAIN).hexdigest()[:63]}, {"sha256": 5}, {"sha": "x"})

    def hostile_responses(self, url):
        good = self.responses()
        doc = json.loads(good[f"{API}redhat/vscode-yaml/1.25.0"])
        doc["files"]["download"] = url
        doc["downloads"] = {"universal": url}
        good[f"{API}redhat/vscode-yaml/1.25.0"] = json.dumps(doc).encode()
        good[f"{API}redhat/vscode-yaml"] = json.dumps(doc).encode()
        return good


class ResolveTests(unittest.TestCase):
    def fetch(self, served):
        return base.Fetch(openvsx.ECOSYSTEM, served, clock=lambda: 0.0, sleep=lambda s: None)

    def test_every_platforms_file_with_its_own_digest(self):
        data = {p: vsix({"package.json": ext_manifest(name="rust-analyzer", publisher="rust-lang"),
                         "server/" + p: "x" * (i + 1)}) for i, p in enumerate(("universal", "linux-x64", "darwin-arm64"))}
        served = Served(responses("rust-lang", "rust-analyzer", "0.4.3074", data))
        res = openvsx.ECOSYSTEM.resolve("rust-lang.rust-analyzer", None, self.fetch(served))
        self.assertEqual(res[0], "0.4.3074")
        self.assertEqual([a["filename"] for a in res.artifacts], [
            "rust-lang.rust-analyzer-0.4.3074@darwin-arm64.vsix", "rust-lang.rust-analyzer-0.4.3074@linux-x64.vsix",
            "rust-lang.rust-analyzer-0.4.3074.vsix"])
        for art in res.artifacts:
            platform = art["entry"]["platform"]
            self.assertEqual(art["entry"]["sha256"], hashlib.sha256(data[platform]).hexdigest())
            self.assertEqual(openvsx.ECOSYSTEM.verify(data[platform], art["entry"], "x", "y")[0], "sha256")
        # (the universal document is the top one; each other platform's document, and each digest, is asked for once)
        asked = [u for u, _m, _t in served.calls]
        self.assertEqual(asked.count(API + "rust-lang/rust-analyzer/linux-x64/0.4.3074"), 1)
        self.assertEqual(sum(1 for u in asked if u.endswith(".sha256")), 3)
        self.assertEqual(len(asked), 6)

    def test_a_platform_the_editor_does_not_install_is_listed(self):
        data = {"universal": PLAIN, "sunos-sparc": PLAIN + b"\0"}
        served = Served(responses("redhat", "vscode-yaml", "1.25.0", data))
        res = openvsx.ECOSYSTEM.resolve("redhat.vscode-yaml", "1.25.0", self.fetch(served))
        self.assertEqual([a["entry"]["platform"] for a in res.artifacts], ["universal"])
        self.assertEqual([(s["filename"], s["installable"]) for s in res.skipped],
                         [("redhat.vscode-yaml-1.25.0@sunos-sparc.vsix", False)])

    def test_what_the_registry_says_of_the_publisher_and_what_the_extension_brings(self):
        extra = {"verified": False, "unrelatedPublisher": True, "preRelease": True,
                 "dependencies": [{"namespace": "Example", "extension": "Base", "url": API + "Example/Base"}],
                 "bundledExtensions": [{"namespace": "example", "extension": "other"}, {"namespace": "bad name"}, 5]}
        served = Served(responses("example", "pack", "2.0.0", {"universal": PLAIN}, **extra))
        res = openvsx.ECOSYSTEM.resolve("example.pack", "2.0.0", self.fetch(served))
        self.assertEqual({k: res.info[k] for k in ("verified", "unrelatedPublisher", "preRelease", "publishedBy",
                                                   "dependencies", "bundledExtensions")},
                         {"verified": False, "unrelatedPublisher": True, "preRelease": True,
                          "publishedBy": "example-ci", "dependencies": ["example.base"],
                          "bundledExtensions": ["example.other"]})
        self.assertEqual(openvsx.ECOSYSTEM.dependencies(res, None), ("example.base", "example.other"))

    def test_answers_that_are_refused(self):
        good = responses("redhat", "vscode-yaml", "1.25.0", {"universal": PLAIN})
        top = API + "redhat/vscode-yaml/1.25.0"
        doc = json.loads(good[top])
        digest_url = doc["files"]["sha256"]
        cases = {
            "another extension": {top: json.dumps({**doc, "name": "vscode-yml"}).encode()},
            "another version": {top: json.dumps({**doc, "version": "1.24.0"}).encode()},
            "not downloadable": {top: json.dumps({**doc, "downloadable": False}).encode()},
            "an error": {top: json.dumps({"error": "Extension not found: redhat.vscode-yaml"}).encode()},
            "no digest": {top: json.dumps({**doc, "files": {"download": doc["files"]["download"]}}).encode()},
            "a digest that is not one": {digest_url: b"not a digest"},
            "a platform that is not one": {top: json.dumps({**doc, "downloads": {
                "universal": doc["files"]["download"], "\u001b[31mx": "https://open-vsx.org/x"}}).encode()},
            "a file on another host": {top: json.dumps({**doc, "files": {**doc["files"], "download": "https://x.invalid/a.vsix"},
                                                        "downloads": {"universal": "https://x.invalid/a.vsix"}}).encode()},
        }
        for what, change in cases.items():
            with self.subTest(what=what), self.assertRaises(base.FetchError):
                openvsx.ECOSYSTEM.resolve("redhat.vscode-yaml", "1.25.0", self.fetch(Served({**good, **change})))

    def test_a_platforms_document_must_be_that_platforms(self):
        data = {"universal": PLAIN, "linux-x64": PLAIN + b"\0"}
        good = responses("redhat", "vscode-yaml", "1.25.0", data)
        url = API + "redhat/vscode-yaml/linux-x64/1.25.0"
        wrong = json.loads(good[url])
        for change in ({"targetPlatform": "darwin-arm64"}, {"targetPlatform": "linux x64"}, {"version": "1.24.0"}):
            with self.subTest(change=change), self.assertRaises(base.FetchError):
                served = Served({**good, url: json.dumps({**wrong, **change}).encode()})
                openvsx.ECOSYSTEM.resolve("redhat.vscode-yaml", "1.25.0", self.fetch(served))

    def test_the_content_host_serves_the_files(self):
        fetch = self.fetch(Served({}))
        fetch.check_url("https://openvsx.eclipsecontent.org/redhat/vscode-yaml/1.25.0/redhat.vscode-yaml-1.25.0.vsix")
        with self.assertRaises(base.FetchError):
            fetch.check_url("https://open-vsx.org.x.invalid/a.vsix")
        self.assertEqual(openvsx.ECOSYSTEM.rate, {"open-vsx.org": 0.5})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanTests(unittest.TestCase):
    def scan(self, served, spec="openvsx:redhat.vscode-yaml@1.25.0"):
        eco, name, version = repo.parse_spec(spec)
        with mock.patch.object(repo, "module_transport", served), mock.patch.object(repo._base.Fetch, "_wait_turn",
                                                                                   lambda self, url: None):
            return repo.scan_package(eco, name, version)

    def test_a_scan_reads_the_extension_as_the_editor_runs_it(self):
        bad = vsix({"package.json": ext_manifest(name="vscode-yaml", publisher="redhat", main="e.js",
                                                 activationEvents=["*"], extensionPack=["Example.Other"]),
                    "e.js": EXFIL_JS})
        res = self.scan(Served(responses("redhat", "vscode-yaml", "1.25.0", {"universal": bad})))
        self.assertEqual((res["ecosystem"], res["name"], res["version"], res["artifact"]),
                         ("openvsx", "redhat.vscode-yaml", "1.25.0", "vsix"))
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual([i["rule"] for i in res["issues"] if i["sev"] == "CRITICAL"], ["SC-IMPORT-RISK"])
        self.assertEqual((res["extensionDependencies"], res["startupEvent"]), (["example.other"], "*"))
        self.assertEqual(res["registryInfo"]["verified"], True)
        self.assertEqual(res["digest"], ("sha256", hashlib.sha256(bad).hexdigest()))
        out = io.StringIO()
        with redirect_stdout(out):
            repo.print_scan(res)
        self.assertIn("openvsx:redhat.vscode-yaml@1.25.0", out.getvalue())
        self.assertIn("Open VSX: the namespace is verified, published by example-ci (github)", out.getvalue())
        self.assertIn("starts with the editor (activation event '*')", out.getvalue())

    def test_every_platform_is_scanned_and_the_worst_decides(self):
        good = vsix({"package.json": ext_manifest(name="x", publisher="p", main="e.js"), "e.js": "exports.activate = () => 1;\n"})
        bad = vsix({"package.json": ext_manifest(name="x", publisher="p", main="e.js"), "e.js": EXFIL_JS})
        res = self.scan(Served(responses("p", "x", "1.0.0", {"universal": good, "linux-x64": bad})), "openvsx:p.x@1.0.0")
        self.assertEqual((res["verdict"], res["artifact"]), ("SUSPICIOUS", "2 vsix files"))
        self.assertEqual({a["filename"]: a["verdict"] for a in res["artifacts"]},
                         {"p.x-1.0.0.vsix": "OK", "p.x-1.0.0@linux-x64.vsix": "SUSPICIOUS"})
        self.assertIn("worst: p.x-1.0.0@linux-x64.vsix", res["verdictReason"])

    def test_a_file_that_does_not_match_its_digest_is_never_scanned(self):
        served = Served(responses("redhat", "vscode-yaml", "1.25.0", {"universal": PLAIN}))
        doc = document("redhat", "vscode-yaml", "1.25.0")
        served.responses[doc["files"]["download"]] = PLAIN + b"\0"
        with self.assertRaises(repo.DigestError) as caught:
            self.scan(served)
        self.assertIn("SC-DIGEST-MISMATCH", str(caught.exception))

    def test_an_unverified_namespace_is_said(self):
        res = self.scan(Served(responses("redhat", "vscode-yaml", "1.25.0", {"universal": PLAIN}, verified=False,
                                         publishedBy={"loginName": "someone"})))
        self.assertEqual(res["verdict"], "OK")
        self.assertEqual(repo.registry_lines(res),
                         ["Open VSX: the namespace is not verified (Open VSX has not confirmed who owns it), "
                          "published by someone"])



def query_url(ident, size, offset=0):
    return f"{API}-/query?extensionId={ident}&includeAllVersions=true&size={size}&offset={offset}"


def query_entry(ident, version, timestamp, brings=(), pre=False, by="example-ci", platform="universal"):
    ns, name = ident.split(".")
    return {"namespace": ns, "name": name, "version": version, "timestamp": timestamp, "preRelease": pre,
            "targetPlatform": platform, "publishedBy": {"loginName": by, "provider": "github"},
            "dependencies": [], "bundledExtensions": [{"namespace": b.split(".")[0], "extension": b.split(".")[1]}
                                                      for b in brings]}


def history(ident, entries):
    """The query API's answers for every version of `ident` (`entries`, newest first): the history's page and the
    first-publication lookup's two."""
    page = json.dumps({"offset": 0, "totalSize": len(entries), "extensions": entries}).encode()
    first = json.dumps({"offset": 0, "totalSize": len(entries), "extensions": entries[:1]}).encode()
    return {query_url(ident, 1000): page, query_url(ident, 1): first}


class NewDependencyTests(unittest.TestCase):
    """SC-NEW-DEPENDENCY for an Open VSX release (E-1's third part): an extension it brings that the version
    published before it did not, first published days before it, by another publisher (GlassWorm's extensionPack)."""

    RELEASE = "2026-10-06T08:18:12.286437Z"           # (test_openvsx.document's timestamp)

    def served(self, brings, extra=None):
        bad = vsix({"package.json": ext_manifest(name="tool", publisher="acme", version="1.1.0", extensionPack=brings)})
        out = responses("acme", "tool", "1.1.0", {"universal": bad})
        out.update(history("acme.tool", [
            query_entry("acme.tool", "1.1.0", self.RELEASE, brings),
            query_entry("acme.tool", "1.0.5", "2026-10-01T00:00:00Z", ["evil.helper"], pre=True),
            query_entry("acme.tool", "1.0.0", "2026-09-01T00:00:00.5Z", [])]))
        out.update(history("evil.helper", [query_entry("evil.helper", "0.0.1", "2026-10-04T00:00:00Z", by="mallory")]))
        out.update(history("old.thing", [query_entry("old.thing", "3.0.0", "2026-10-05T00:00:00Z"),
                                         query_entry("old.thing", "1.0.0", "2025-01-01T00:00:00.123456789Z")]))
        out.update(history("same.account", [query_entry("same.account", "0.1.0", "2026-10-05T00:00:00Z")]))
        out.update(extra or {})
        return Served(out)

    def scan(self, served):
        with mock.patch.object(repo, "module_transport", served), \
                mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None):
            return repo.scan_package("openvsx", "acme.tool", "1.1.0")

    def news(self, res):
        return [(i["sev"], i["file"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-NEW-DEPENDENCY"]

    def test_an_extension_published_days_before_the_release(self):
        served = self.served(["evil.helper", "acme.sibling", "old.thing", "same.account", "missing.ext"])
        res = self.scan(served)
        self.assertEqual(self.news(res), [(
            "CRITICAL", "(release)",
            'Brings "evil.helper" (its extensionDependencies or extensionPack), which 1.0.0 did not: an extension first '
            'published 2 days before this release, by another publisher ("evil").')])
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        asked = served.urls()
        self.assertNotIn(query_url("acme.sibling", 1), asked, "the release's own publisher's is not looked up")
        self.assertIn(query_url("missing.ext", 1), asked)

    def test_weeks_old_is_major(self):
        served = self.served(["evil.helper"], history("evil.helper", [
            query_entry("evil.helper", "0.0.1", "2026-09-20T00:00:00Z", by="mallory")]))
        self.assertEqual([sev for sev, _f, _m in self.news(self.scan(served))], ["MAJOR"])

    def test_what_the_previous_version_brought_is_not_new(self):
        served = self.served(["evil.helper"])
        served.responses.update(history("acme.tool", [
            query_entry("acme.tool", "1.1.0", self.RELEASE, ["evil.helper"]),
            query_entry("acme.tool", "1.0.0", "2026-09-01T00:00:00Z", ["evil.helper"])]))
        self.assertEqual(self.news(self.scan(served)), [])

    def test_a_pre_release_is_compared_with_any_version(self):
        served = self.served(["evil.helper"])
        served.responses.update(history("acme.tool", [
            query_entry("acme.tool", "1.1.0", self.RELEASE, ["evil.helper"], pre=True),
            query_entry("acme.tool", "1.0.5", "2026-10-01T00:00:00Z", ["evil.helper"], pre=True),
            query_entry("acme.tool", "1.0.0", "2026-09-01T00:00:00Z", [])]))
        self.assertEqual(self.news(self.scan(served)), [])

    def test_the_first_publication_is_read_from_every_page_when_the_last_is_recent(self):
        ext = openvsx.OpenVSX()
        entries = [query_entry("big.ext", f"1.0.{i}", f"2026-10-0{1 + i % 5}T00:00:00Z") for i in range(3)]
        older = query_entry("big.ext", "0.9.0", "2024-01-01T00:00:00Z")
        pages = {query_url("big.ext", 1): json.dumps({"offset": 0, "totalSize": 1001, "extensions": entries[:1]}).encode(),
                 query_url("big.ext", 1000, 1): json.dumps({"offset": 1, "totalSize": 1001, "extensions": entries}).encode(),
                 query_url("big.ext", 1000, 0): json.dumps({"offset": 0, "totalSize": 1001,
                                                            "extensions": [older] + entries}).encode(),
                 query_url("big.ext", 1000, 1000): json.dumps({"offset": 1000, "totalSize": 1001,
                                                               "extensions": entries[-1:]}).encode()}
        served = Served(pages)
        fetch = base.Fetch(ext, served)
        recent = lambda t: False                                              # noqa: E731
        when, _by = ext.first_published("big.ext", fetch, old_enough=recent)
        self.assertEqual(when.year, 2024, "the older version on another page")
        served.calls.clear()
        when, _by = ext.first_published("big.ext", fetch, old_enough=lambda t: True)
        self.assertEqual(when.isoformat(), "2026-10-01T00:00:00+00:00")
        self.assertNotIn(query_url("big.ext", 1000, 0), served.urls(), "old enough: the last page is the answer")

    def test_the_check_can_be_turned_off_and_a_silent_registry_is_no_finding(self):
        served = self.served(["evil.helper"])
        with mock.patch.dict(os.environ, {"LAZARET_NO_DEPENDENCY_HISTORY": "1"}):
            self.assertEqual(self.news(self.scan(served)), [])
        served = self.served(["evil.helper"])
        del served.responses[query_url("acme.tool", 1000)]
        self.assertEqual(self.news(self.scan(served)), [])


if __name__ == "__main__":
    unittest.main()
