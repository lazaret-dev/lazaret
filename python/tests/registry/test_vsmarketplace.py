"""The Visual Studio Marketplace (0.1.9, E-1's second part, decision 11): `lazaret-registry vscode:publisher.name[@version]`
resolves an extension through the gallery API VS Code queries (`extensionquery`), downloads the `.vsix` of every
platform its version is published for, and scans them as `lazaret FILE.vsix` does. The Marketplace publishes no digest,
so the files are scanned unverified, and the result says so.

The gallery's answers are built here, in the shape VS Code's gallery service reads (its raw extension and version
types: `publisher`, `extensionName`, `versions` with `version`, `targetPlatform`, `files` of `assetType` and `source`,
`properties` of `key` and `value`, `assetUri`, `fallbackAssetUri`, and `statistics`): the sandbox cannot reach the
Marketplace, so nothing could be recorded, and John checks the module against the live gallery. The extensions are
built here too, inert (test_vsix's fragments). Nothing opens a socket."""

import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

from lazaret.registry import repo
from lazaret.registry.ecosystems import base, vsmarketplace as vsm
from lazaret.scanner import _native
from tests.registry._review_support import EXFIL_JS
from tests.registry.ecosystem_contract import EcosystemContract
from tests.registry.test_vsix import ext_manifest, vsix

PLAIN = vsix({"package.json": ext_manifest(name="vscode-yaml", publisher="redhat", version="1.25.0",
                                           main="./dist/extension.js", activationEvents=["onLanguage:yaml"]),
              "dist/extension.js": "exports.activate = () => 1;\n"})


def version_entry(pub, name, version, platform=None, pre=False, deps="", pack="", stamp=1759737600000, files=True):
    """One version entry of a gallery answer, as VS Code's gallery service reads it."""
    asset = f"https://{pub}.gallerycdn.vsassets.io/extensions/{pub}/{name}/{version}/{stamp}"
    fallback = f"https://{pub}.gallery.vsassets.io/_apis/public/gallery/publisher/{pub}/extension/{name}/{version}/assetbyname"
    entry = {"version": version, "flags": "validated", "lastUpdated": "2026-10-06T08:00:00.000Z",
             "files": [{"assetType": "Microsoft.VisualStudio.Code.Manifest", "source": f"{asset}/Microsoft.VisualStudio.Code.Manifest"},
                       {"assetType": "Microsoft.VisualStudio.Services.VsixSignature",
                        "source": f"{asset}/Microsoft.VisualStudio.Services.VsixSignature"},
                       {"assetType": vsm.VSIX_ASSET, "source": f"{asset}/{vsm.VSIX_ASSET}"}] if files else [],
             "properties": [{"key": "Microsoft.VisualStudio.Code.Engine", "value": "^1.90.0"},
                            {"key": vsm.DEPENDENCIES, "value": deps}, {"key": vsm.EXTENSION_PACK, "value": pack},
                            *([{"key": vsm.PRE_RELEASE, "value": "true"}] if pre else [])],
             "assetUri": asset, "fallbackAssetUri": fallback}
    if platform:
        entry["targetPlatform"] = platform
    return entry


def extension(pub, name, versions, verified=True, installs=1234567):
    return {"publisher": {"publisherId": "00000000-0000-0000-0000-000000000001", "publisherName": pub,
                          "displayName": pub.title(), "flags": "verified" if verified else "none",
                          "domain": f"https://{pub}.example" if verified else None, "isDomainVerified": verified},
            "extensionId": "00000000-0000-0000-0000-000000000002", "extensionName": name, "displayName": name,
            "flags": "validated, public", "versions": versions,
            "statistics": [{"statisticName": "install", "value": installs}, {"statisticName": "averagerating", "value": 4.5}],
            "deploymentType": 0}


def answer(ext):
    return {"results": [{"extensions": [ext] if ext else [], "pagingToken": None,
                         "resultMetadata": [{"metadataType": "ResultCount",
                                             "metadataItems": [{"name": "TotalCount", "count": 1 if ext else 0}]}]}]}


def vsix_url(entry):
    return next(f["source"] for f in entry["files"] if f["assetType"] == vsm.VSIX_ASSET)


class Gallery:
    """`repo.module_transport` for the Marketplace: the query answered from `ext` (with the latest-only flag, the
    newest release and the newest pre-release only, each on every platform), the files from `files`."""

    def __init__(self, ext, files=None):
        self.ext, self.files = ext, dict(files or {})
        self.calls, self.bodies = [], []
        self._lock = threading.Lock()

    def __call__(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None, data=None, content_type=None):
        check_redirect(url)
        with self._lock:
            self.calls.append((url, accept, content_type))
            if data is not None:
                self.bodies.append(json.loads(data))
        if url == vsm.QUERY_URL:
            return json.dumps(answer(self.query(json.loads(data)))).encode()
        body = self.files.get(url)
        if body is None:
            err = base.FetchError("not found")
            err.status = 404
            raise err
        return body

    def query(self, body):
        ext = self.ext
        if not ext:
            return None
        if body["flags"] & vsm.LATEST_ONLY_FLAG:
            keep, seen = [], set()
            for v in ext["versions"]:
                pre = any(p["key"] == vsm.PRE_RELEASE for p in v["properties"])
                first = next(w["version"] for w in ext["versions"]
                             if any(p["key"] == vsm.PRE_RELEASE for p in w["properties"]) == pre)
                if v["version"] == first and (pre, v.get("targetPlatform")) not in seen:
                    seen.add((pre, v.get("targetPlatform")))
                    keep.append(v)
            ext = {**ext, "versions": keep}
        return ext


def served(ext, data_by_entry=()):
    """A Gallery for `ext` serving each (entry, data) pair's file."""
    return Gallery(ext, {vsix_url(e): d for e, d in data_by_entry})


class MarketplaceContract(EcosystemContract, unittest.TestCase):
    GOOD_NAMES = ("redhat.vscode-yaml", "ms-python.python", "Example.My-Ext", "a.b", "a1.b2")
    GOOD_VERSIONS = ("1.25.0", "0.4.3074", "2026.4.0", "1.0.0-beta.1")
    GOOD_SPEC = ("redhat.vscode-yaml", "1.25.0")
    SAME_IDENTITY = (("redhat.vscode-yaml", "RedHat.VSCode-YAML"),)
    DIFFERENT_IDENTITY = (("redhat.vscode-yaml", "redhat.vscode-yml"), ("a.bc", "ab.c"))
    EXTRA_BAD_NAMES = ("redhat", "redhat.", ".vscode-yaml", "a.b.c", "-a.b", "a.-b", "a_b.c", "a.b_c", "a..b",
                       "a." + "b" * 129, "a/b.c", "redhat.vscode yaml")
    MEMBER_PATHS = (("vsix", "extension/package.json", None, ("package.json", None)),
                    ("vsix", "extension/./dist//a.js", None, ("dist/a.js", None)),
                    ("vsix", "extension.vsixmanifest", None, (".vsixmanifest", None)),
                    ("vsix", "extensionout/a.js", None, ("out/a.js", None)),
                    ("vsix", "extension", None, (None, None)),
                    ("vsix", "Extension/a.js", None, (None, None)),
                    ("vsix", "extension/../a.js", None, (None, "path contains '..'")))
    ENTRY = version_entry("redhat", "vscode-yaml", "1.25.0")

    def make(self):
        return vsm.Marketplace()

    def responses(self):
        ext = extension("redhat", "vscode-yaml", [self.ENTRY])
        return {vsm.QUERY_URL: json.dumps(answer(ext)).encode(), vsix_url(self.ENTRY): PLAIN}

    def verify_case(self):
        return None                                 # (the Marketplace publishes no digest)

    def hostile_responses(self, url):
        entry = json.loads(json.dumps(self.ENTRY))
        entry["files"] = [{"assetType": vsm.VSIX_ASSET, "source": url}]
        entry["fallbackAssetUri"] = url
        return {vsm.QUERY_URL: json.dumps(answer(extension("redhat", "vscode-yaml", [entry]))).encode()}


class ResolveTests(unittest.TestCase):
    def fetch(self, transport):
        return base.Fetch(vsm.ECOSYSTEM, transport, clock=lambda: 0.0, sleep=lambda s: None)

    def test_the_query_is_the_one_vs_code_sends(self):
        gallery = served(extension("redhat", "vscode-yaml", [version_entry("redhat", "vscode-yaml", "1.25.0")]))
        vsm.ECOSYSTEM.resolve("RedHat.vscode-yaml", None, self.fetch(gallery))
        vsm.ECOSYSTEM.resolve("redhat.vscode-yaml", "1.25.0", self.fetch(gallery))
        latest, pinned = gallery.bodies
        self.assertEqual(latest["filters"][0]["criteria"], [{"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                                                            {"filterType": 7, "value": "RedHat.vscode-yaml"},
                                                            {"filterType": 12, "value": "4096"}])
        self.assertEqual((latest["flags"], pinned["flags"]), (vsm.QUERY_FLAGS | 65536, vsm.QUERY_FLAGS))
        self.assertEqual(vsm.QUERY_FLAGS, 435)
        self.assertEqual({(u, a, c) for u, a, c in gallery.calls},
                         {(vsm.QUERY_URL, "application/json;api-version=3.0-preview.1", "application/json")})

    def test_every_platforms_file(self):
        entries = [version_entry("rust-lang", "rust-analyzer", "0.4.3074", p, stamp=1759737600000 + i)
                   for i, p in enumerate(("linux-x64", "darwin-arm64", "win32-x64", "sunos-sparc"))]
        res = vsm.ECOSYSTEM.resolve("rust-lang.rust-analyzer", None, self.fetch(served(extension("rust-lang", "rust-analyzer", entries))))
        self.assertEqual(res[0], "0.4.3074")
        self.assertEqual([(a["filename"], a["url"]) for a in res.artifacts],
                         [("rust-lang.rust-analyzer-0.4.3074@darwin-arm64.vsix", vsix_url(entries[1])),
                          ("rust-lang.rust-analyzer-0.4.3074@linux-x64.vsix", vsix_url(entries[0])),
                          ("rust-lang.rust-analyzer-0.4.3074@win32-x64.vsix", vsix_url(entries[2]))])
        self.assertEqual([(s["filename"], s["installable"]) for s in res.skipped],
                         [("rust-lang.rust-analyzer-0.4.3074@sunos-sparc.vsix", False)])
        self.assertIsNone(res.info["digest"])

    def test_the_release_vs_code_installs_or_a_pinned_version(self):
        entries = [version_entry("p", "x", "2.1.0", pre=True), version_entry("p", "x", "2.0.0"), version_entry("p", "x", "1.0.0")]
        ext = extension("p", "x", entries)
        self.assertEqual(vsm.ECOSYSTEM.resolve("p.x", None, self.fetch(served(ext)))[0], "2.0.0")
        res = vsm.ECOSYSTEM.resolve("p.x", "2.1.0", self.fetch(served(ext)))
        self.assertEqual((res[0], res.info["preRelease"]), ("2.1.0", True))
        self.assertEqual(vsm.ECOSYSTEM.resolve("p.x", "1.0.0", self.fetch(served(ext)))[0], "1.0.0")
        only_pre = extension("p", "x", [version_entry("p", "x", "0.1.0", pre=True)])
        res = vsm.ECOSYSTEM.resolve("p.x", None, self.fetch(served(only_pre)))
        self.assertEqual((res[0], res.info["preReleaseReason"]), ("0.1.0", "the extension has no release"))
        self.assertEqual(repo.registry_lines({"ecosystem": "vscode", "registryInfo": {"preRelease": True, **{
            k: res.info[k] for k in ("verified", "installs", "preReleaseReason")}}})[1],
            "Visual Studio Marketplace: a pre-release version, taken with no version asked for: the extension has no "
            "release")
        # (a release, or a version asked for, has no reason)
        self.assertNotIn("preReleaseReason", vsm.ECOSYSTEM.resolve("p.x", "2.1.0", self.fetch(served(ext))).info)

    def test_what_the_marketplace_says_of_the_publisher_and_what_the_extension_brings(self):
        entries = [version_entry("example", "pack", "2.0.0", deps="Example.Base, bad name,a.b.c", pack="example.other")]
        res = vsm.ECOSYSTEM.resolve("example.pack", "2.0.0", self.fetch(served(extension("example", "pack", entries, verified=False,
                                                                                            installs=42))))
        self.assertEqual({k: res.info[k] for k in ("publisher", "verified", "domain", "installs", "preRelease",
                                                   "dependencies", "bundledExtensions", "digest")},
                         {"publisher": "example", "verified": False, "domain": None, "installs": 42, "preRelease": False,
                          "dependencies": ["example.base"], "bundledExtensions": ["example.other"], "digest": None})
        self.assertEqual(vsm.ECOSYSTEM.dependencies(res, None), ("example.base", "example.other"))

    def test_a_version_without_a_vsix_file_falls_back_as_vs_code_does(self):
        entry = version_entry("p", "x", "1.0.0", "linux-x64", files=False)
        res = vsm.ECOSYSTEM.resolve("p.x", "1.0.0", self.fetch(served(extension("p", "x", [entry]))))
        self.assertEqual(res.artifacts[0]["url"],
                         entry["fallbackAssetUri"] + "/Microsoft.VisualStudio.Services.VSIXPackage?targetPlatform=linux-x64")

    def test_answers_that_are_refused(self):
        good = version_entry("redhat", "vscode-yaml", "1.25.0")
        cases = {
            "no such extension": None,
            "another extension": extension("redhat", "vscode-yml", [good]),
            "another publisher": extension("redhat2", "vscode-yaml", [good]),
            "no versions": extension("redhat", "vscode-yaml", []),
            "a platform that is not one": extension("redhat", "vscode-yaml", [{**good, "targetPlatform": "\u001b[31mx"}]),
            "a file on another host": extension("redhat", "vscode-yaml", [{**good, "files": [
                {"assetType": vsm.VSIX_ASSET, "source": "https://x.invalid/a.vsix"}]}]),
            "a file two labels below the CDN": extension("redhat", "vscode-yaml", [{**good, "files": [
                {"assetType": vsm.VSIX_ASSET, "source": "https://a.b.gallerycdn.vsassets.io/a.vsix"}]}]),
            "no file and no fallback": extension("redhat", "vscode-yaml", [{**good, "files": [], "fallbackAssetUri": None}]),
        }
        for what, ext in cases.items():
            with self.subTest(what=what), self.assertRaises(base.FetchError):
                vsm.ECOSYSTEM.resolve("redhat.vscode-yaml", "1.25.0", self.fetch(served(ext)))
        with self.assertRaises(base.FetchError):
            vsm.ECOSYSTEM.resolve("redhat.vscode-yaml", "9.9.9", self.fetch(served(extension("redhat", "vscode-yaml", [good]))))

    def test_the_hosts_a_file_may_come_from(self):
        fetch = self.fetch(Gallery(None))
        for url in ("https://redhat.gallerycdn.vsassets.io/extensions/redhat/vscode-yaml/1.25.0/1/x",
                    "https://redhat.gallery.vsassets.io/_apis/public/gallery/publisher/redhat/extension/x",
                    "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"):
            with self.subTest(url=url):
                self.assertEqual(fetch.check_url(url), url)
        for url in ("https://gallerycdn.vsassets.io/x", "https://a.b.gallerycdn.vsassets.io/x",
                    "https://x.gallerycdn.vsassets.io:8443/x", "https://x.gallerycdn.vsassets.io.evil.example/x",
                    "http://x.gallerycdn.vsassets.io/x", "https://-x.gallerycdn.vsassets.io/x",
                    "https://x.vsassets.io/x", "https://evilgallerycdn.vsassets.io/x"):
            with self.subTest(url=url), self.assertRaises(base.FetchError):
                fetch.check_url(url)
        self.assertEqual(vsm.ECOSYSTEM.rate, {"marketplace.visualstudio.com": 0.5})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanTests(unittest.TestCase):
    def scan(self, transport, spec="vscode:redhat.vscode-yaml@1.25.0"):
        eco, name, version = repo.parse_spec(spec)
        with mock.patch.object(repo, "module_transport", transport), mock.patch.object(repo._base.Fetch, "_wait_turn",
                                                                                       lambda self, url: None):
            return repo.scan_package(eco, name, version)

    def test_a_scan_reads_the_extension_as_the_editor_runs_it_and_says_it_is_unverified(self):
        bad = vsix({"package.json": ext_manifest(name="vscode-yaml", publisher="redhat", main="e.js",
                                                 activationEvents=["*"], extensionPack=["Example.Other"]),
                    "e.js": EXFIL_JS})
        entry = version_entry("redhat", "vscode-yaml", "1.25.0")
        res = self.scan(served(extension("redhat", "vscode-yaml", [entry]), [(entry, bad)]))
        self.assertEqual((res["ecosystem"], res["name"], res["version"], res["artifact"]),
                         ("vscode", "redhat.vscode-yaml", "1.25.0", "vsix"))
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual([i["rule"] for i in res["issues"] if i["sev"] == "CRITICAL"], ["SC-IMPORT-RISK"])
        self.assertEqual((res["extensionDependencies"], res["startupEvent"]), (["example.other"], "*"))
        self.assertIsNone(res["digest"])
        self.assertEqual((res["registryInfo"]["verified"], res["registryInfo"]["installs"]), (True, 1234567))
        out = io.StringIO()
        with redirect_stdout(out):
            repo.print_scan(res)
        text = out.getvalue()
        self.assertIn("vscode:redhat.vscode-yaml@1.25.0", text)
        self.assertIn("Visual Studio Marketplace: the publisher's domain is verified (https://redhat.example)", text)
        self.assertIn("Visual Studio Marketplace: no digest is published, so the files were scanned unverified", text)
        self.assertIn("starts with the editor (activation event '*')", text)

    def test_every_platform_is_scanned_and_the_worst_decides(self):
        good = vsix({"package.json": ext_manifest(name="x", publisher="p", main="e.js"), "e.js": "exports.activate = () => 1;\n"})
        bad = vsix({"package.json": ext_manifest(name="x", publisher="p", main="e.js"), "e.js": EXFIL_JS})
        a, b = version_entry("p", "x", "1.0.0", "linux-x64", stamp=1), version_entry("p", "x", "1.0.0", "win32-x64", stamp=2)
        res = self.scan(served(extension("p", "x", [a, b]), [(a, good), (b, bad)]), "vscode:p.x@1.0.0")
        self.assertEqual((res["verdict"], res["artifact"]), ("SUSPICIOUS", "2 vsix files"))
        self.assertEqual({x["filename"]: x["verdict"] for x in res["artifacts"]},
                         {"p.x-1.0.0@linux-x64.vsix": "OK", "p.x-1.0.0@win32-x64.vsix": "SUSPICIOUS"})
        self.assertIn("worst: p.x-1.0.0@win32-x64.vsix", res["verdictReason"])

    def test_an_unverified_publisher_is_said(self):
        entry = version_entry("redhat", "vscode-yaml", "1.25.0")
        res = self.scan(served(extension("redhat", "vscode-yaml", [entry], verified=False, installs=3), [(entry, PLAIN)]))
        self.assertEqual(res["verdict"], "OK")
        self.assertEqual(repo.registry_lines(res),
                         ["Visual Studio Marketplace: the publisher's domain is not verified; 3 installs",
                          "Visual Studio Marketplace: no digest is published, so the files were scanned unverified"])

    def test_the_spec_and_its_errors(self):
        self.assertEqual(repo.parse_spec("vscode:RedHat.vscode-yaml@1.25.0"), ("vscode", "RedHat.vscode-yaml", "1.25.0"))
        with self.assertRaises(repo.SpecError) as caught:
            repo.parse_spec("vsce:redhat.vscode-yaml")
        self.assertIn("vscode", str(caught.exception))



class Galleries(Gallery):
    """A Gallery that answers for several extensions (`exts`: {identifier, lowercase: extension}) by the name the query
    asks for."""

    def __init__(self, exts, files=None):
        super().__init__(None, files)
        self.exts = exts

    def query(self, body):
        name = next(c["value"] for c in body["filters"][0]["criteria"] if c["filterType"] == vsm.FILTER_NAME)
        self.ext = self.exts.get(name.lower())
        return super().query(body)


class NewDependencyTests(unittest.TestCase):
    """SC-NEW-DEPENDENCY for a Marketplace release (E-1's third part): an extension it brings that the version
    published before it did not, first published days before it (the gallery's publishedDate), of another publisher."""

    def entry(self, version, when, pack="", pre=False):
        e = version_entry("acme", "tool", version, pack=pack, pre=pre)
        e["lastUpdated"] = when
        return e

    def dep(self, ident, published):
        pub, name = ident.split(".")
        ext = extension(pub, name, [version_entry(pub, name, "0.0.1")])
        ext["publishedDate"], ext["releaseDate"] = published, published
        return ext

    def scan(self, versions, deps, brings):
        bad = vsix({"package.json": ext_manifest(name="tool", publisher="acme", version="1.1.0", extensionPack=brings)})
        exts = {"acme.tool": extension("acme", "tool", versions), **{k.lower(): v for k, v in deps.items()}}
        gallery = Galleries(exts, {vsix_url(versions[0]): bad})
        with mock.patch.object(repo, "module_transport", gallery), \
                mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None):
            res = repo.scan_package("vscode", "acme.tool", "1.1.0")
        return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-NEW-DEPENDENCY"], gallery

    def test_an_extension_published_days_before_the_release(self):
        versions = [self.entry("1.1.0", "2026-10-06T08:00:00Z", "evil.helper,acme.sibling,old.thing"),
                    self.entry("1.0.0", "2026-09-01T00:00:00Z")]
        found, gallery = self.scan(versions, {"evil.helper": self.dep("evil.helper", "2026-10-05T20:00:00Z"),
                                              "old.thing": self.dep("old.thing", "2024-02-02T00:00:00Z")},
                                   ["evil.helper", "acme.sibling", "old.thing"])
        self.assertEqual(found, [("CRITICAL", 'Brings "evil.helper" (its extensionDependencies or extensionPack), '
                                              "which 1.0.0 did not: an extension first published 12 hours before this "
                                              'release, by another publisher ("evil").')])
        names = [next(c["value"] for c in b["filters"][0]["criteria"] if c["filterType"] == vsm.FILTER_NAME)
                 for b in gallery.bodies]
        self.assertNotIn("acme.sibling", names, "the release's own publisher's is not looked up")
        self.assertIn({"filterType": vsm.FILTER_NAME, "value": "evil.helper"},
                      next(b for b in gallery.bodies if b["flags"] == 0)["filters"][0]["criteria"])

    def test_brought_before_or_weeks_old(self):
        versions = [self.entry("1.1.0", "2026-10-06T08:00:00Z", "evil.helper,new.one"),
                    self.entry("1.0.0", "2026-09-01T00:00:00Z", "evil.helper")]
        found, _g = self.scan(versions, {"evil.helper": self.dep("evil.helper", "2026-10-05T20:00:00Z"),
                                         "new.one": self.dep("new.one", "2026-09-20T00:00:00Z")},
                              ["evil.helper", "new.one"])
        self.assertEqual([sev for sev, _m in found], ["MAJOR"])
        self.assertIn('"new.one"', found[0][1])

    def test_a_release_is_compared_with_releases_only(self):
        versions = [self.entry("1.1.0", "2026-10-06T08:00:00Z", "evil.helper"),
                    self.entry("1.0.5", "2026-10-01T00:00:00Z", "evil.helper", pre=True),
                    self.entry("1.0.0", "2026-09-01T00:00:00Z")]
        found, _g = self.scan(versions, {"evil.helper": self.dep("evil.helper", "2026-10-05T20:00:00Z")},
                              ["evil.helper"])
        self.assertEqual(len(found), 1)
        self.assertIn("which 1.0.0 did not", found[0][1])


if __name__ == "__main__":
    unittest.main()
