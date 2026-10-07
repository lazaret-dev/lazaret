"""scripts/popular (B-2): the release gate's second benign set, the popular releases pinned by version and sha256.

The pinned file is checked as it is in the tree (valid, and holding the nine popular releases 0.1.8 made
SUSPICIOUS, at the versions the sweep found them). Resolving, pinning and fetching run against a stand-in for
the registries: nothing here goes on the network."""

import argparse
import contextlib
import hashlib
import io
import json
import os
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from tests import _support

POPULAR = os.path.join(_support.REPO_ROOT, "scripts", "popular")
pop = _support.load_script(os.path.join(POPULAR, "popular.py"), "popular_set")

NPM_FILES = "https://registry.npmjs.org/"
PY_FILES = "https://files.pythonhosted.org/packages/ab/cd/"
CRATE_FILES = "https://static.crates.io/crates/"
API = "https://crates.io/api/v1/crates/"
OVSX = "https://open-vsx.org/api/"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Registry:
    """A stand-in for urllib's urlopen: {url: bytes}, and the URLs asked for in order."""

    def __init__(self, pages):
        self.pages, self.asked = dict(pages), []

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.asked.append(url)
        if url not in self.pages:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return contextlib.closing(io.BytesIO(self.pages[url]))


def row(eco="npm", name="left-pad", version="1.3.0", data=b"tarball", **over):
    if eco == "npm":
        filename = f"{name.rsplit('/', 1)[-1]}-{version}.tgz"
        url, ck = f"{NPM_FILES}{name}/-/{filename}", ("tgz", "npm")
    elif eco == "crates":
        filename = f"{name}-{version}.crate"
        url, ck = f"{CRATE_FILES}{name}/{filename}", ("tgz", "crate")
    elif eco == "openvsx":
        filename = f"{name}-{version}.vsix"
        url, ck = f"{OVSX}{name.replace('.', '/')}/{version}/file/{filename}", ("zip", "vsix")
    else:
        filename = f"{name}-{version}-py3-none-any.whl"
        url, ck = PY_FILES + filename, ("zip", "wheel")
    r = {"id": f"{eco}:{name}@{version}", "ecosystem": eco, "name": name, "version": version, "filename": filename,
         "url": url, "container": ck[0], "kind": ck[1], "sha256": sha(data), "bytes": len(data)}
    r.update(over)
    return r


class PinnedFileTests(unittest.TestCase):
    def test_the_pinned_file_is_valid(self):
        rows = pop.read_releases()
        self.assertEqual(pop.validate(rows), [])
        ecos = [r["ecosystem"] for r in rows]
        self.assertGreater(ecos.count("npm"), 700)
        self.assertGreater(ecos.count("pypi"), 350)
        self.assertGreater(ecos.count("crates"), 450)

    def test_it_holds_the_releases_0_1_8_made_suspicious(self):
        ids = {r["id"] for r in pop.read_releases()}
        for rid in ("npm:vite@8.3.2", "npm:vitest@5.0.3", "npm:monaco-editor@0.57.0", "pypi:coverage@7.16.2",
                    "pypi:numba@0.68.0", "pypi:future@1.0.0", "pypi:sympy@1.14.0", "pypi:ipython@9.17.1",
                    "pypi:kubernetes@36.0.3"):
            self.assertIn(rid, ids)

    def test_check_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            pop.write_releases([row(), row("pypi", "six", "1.17.0")], path)
            self.assertEqual(pop.main(["--releases", path, "check"]), pop.EXIT_OK)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row(sha256="0" * 63)) + "\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pop.main(["--releases", path, "check"]), pop.EXIT_INVALID)

    def test_written_sorted_with_its_fields_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            pop.write_releases([row(name="zz"), dict(row(name="aa"), extra=1)], path)
            rows = pop.read_releases(path)
        self.assertEqual([r["name"] for r in rows], ["aa", "zz"])
        self.assertEqual(list(rows[0]), list(pop.FIELDS))


class ValidateTests(unittest.TestCase):
    def problems(self, *rows):
        return pop.validate(list(rows))

    def test_each_kind_of_problem(self):
        cases = {
            "pinned twice": [row(), row()],
            "the id is not": [row(id="npm:left-pad@9")],
            "sha256 is not": [row(sha256="ABC")],
            "bytes must be": [row(bytes=0)],
            "the url is not https": [row(url="http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")],
            "does not end in the filename": [row(url=NPM_FILES + "left-pad/-/other-1.3.0.tgz")],
            "container and kind": [row(kind="sdist")],
            "unknown ecosystem": [row(ecosystem="gem")],
            "missing": [{k: v for k, v in row().items() if k != "url"}],
            "not an object": [["npm:x@1"]],
        }
        for text, rows in cases.items():
            with self.subTest(text=text):
                problems = pop.validate(rows)
                self.assertTrue(problems and all(text in p for p in problems[-1:]), problems)

    def test_a_file_from_another_host_is_refused(self):
        other = row(url="https://evil.invalid/left-pad-1.3.0.tgz")
        self.assertIn("is not https on registry.npmjs.org", self.problems(other)[0])
        pypi_on_npm = row("pypi", "six", "1.17.0", url=NPM_FILES + "six-1.17.0-py3-none-any.whl")
        self.assertTrue(self.problems(pypi_on_npm))

    def test_container_kind(self):
        self.assertEqual(pop.container_kind("npm", "a-1.tgz"), ("tgz", "npm"))
        self.assertEqual(pop.container_kind("pypi", "a-1-py3-none-any.whl"), ("zip", "wheel"))
        self.assertEqual(pop.container_kind("pypi", "a-1.tar.gz"), ("tgz", "sdist"))
        self.assertEqual(pop.container_kind("pypi", "a-1.zip"), ("zip", "sdist"))
        self.assertIsNone(pop.container_kind("pypi", "a-1.egg"))
        self.assertIsNone(pop.container_kind("npm", "a-1.zip"))
        self.assertEqual(pop.container_kind("crates", "serde-1.0.228.crate"), ("tgz", "crate"))
        self.assertIsNone(pop.container_kind("crates", "serde-1.0.228.tgz"))
        self.assertEqual(pop.container_kind("openvsx", "redhat.java-1.40.0@linux-x64.vsix"), ("zip", "vsix"))
        self.assertIsNone(pop.container_kind("openvsx", "redhat.java-1.40.0.zip"))
        self.assertIsNone(pop.container_kind("npm", "redhat.java-1.40.0.vsix"))

    def test_an_extension_only_from_open_vsx_and_its_content_host(self):
        self.assertEqual(self.problems(row("openvsx", "redhat.java", "1.40.0")), [])
        content = row("openvsx", "redhat.java", "1.40.0",
                      url="https://openvsx.eclipsecontent.org/redhat/java/1.40.0/file/redhat.java-1.40.0.vsix")
        self.assertEqual(self.problems(content), [])
        self.assertIn("is not https on open-vsx.org or openvsx.eclipsecontent.org",
                      self.problems(row("openvsx", "redhat.java", "1.40.0",
                                        url="https://marketplace.invalid/redhat.java-1.40.0.vsix"))[0])

    def test_a_crate_only_from_static_crates_io(self):
        good = row("crates", "serde", "1.0.228")
        self.assertEqual(self.problems(good), [])
        self.assertIn("is not https on static.crates.io",
                      self.problems(row("crates", "serde", "1.0.228",
                                        url="https://crates.io/api/v1/crates/serde/1.0.228/download"))[0])


class PickTests(unittest.TestCase):
    def files(self, *names):
        return [{"filename": n, "packagetype": "sdist" if n.endswith((".tar.gz", ".zip")) else "bdist_wheel"}
                for n in names]

    def pick(self, *names):
        got = pop.pypi_pick(self.files(*names))
        return got and got["filename"]

    def test_the_file_pip_installs_on_linux_x86_64(self):
        sdist, pure = "x-1.tar.gz", "x-1-py3-none-any.whl"
        cp311 = "x-1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
        abi3 = "x-1-cp39-abi3-manylinux_2_28_x86_64.whl"
        cp313 = "x-1-cp313-cp313-manylinux_2_17_x86_64.whl"
        mac = "x-1-cp311-cp311-macosx_11_0_arm64.whl"
        arm = "x-1-cp311-cp311-manylinux_2_17_aarch64.whl"
        self.assertEqual(self.pick(sdist, cp311, pure), pure)
        self.assertEqual(self.pick(sdist, cp313, cp311), cp311)
        self.assertEqual(self.pick(sdist, cp313, abi3), abi3)
        self.assertEqual(self.pick(sdist, mac, cp313), cp313)
        self.assertEqual(self.pick(mac, arm, sdist), sdist)
        self.assertIsNone(self.pick(mac, arm))


class ResolveAndPinTests(unittest.TestCase):
    def npm_meta(self, name, version, tarball):
        return json.dumps({"name": name, "version": version, "dist": {"tarball": tarball}}).encode()

    def test_npm_latest_and_a_scoped_name(self):
        data = b"\x1f\x8b scoped tarball"
        tarball = NPM_FILES + "@scope/pkg/-/pkg-2.0.0.tgz"
        reg = Registry({"https://registry.npmjs.org/@scope%2Fpkg/latest": self.npm_meta("@scope/pkg", "2.0.0", tarball),
                        tarball: data})
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("npm", "@scope/pkg", None, cache, reg)
            self.assertTrue(os.path.isfile(os.path.join(cache, sha(data))))
        self.assertEqual(got, {"id": "npm:@scope/pkg@2.0.0", "ecosystem": "npm", "name": "@scope/pkg",
                               "version": "2.0.0", "filename": "pkg-2.0.0.tgz", "url": tarball, "container": "tgz",
                               "kind": "npm", "sha256": sha(data), "bytes": len(data)})
        self.assertEqual(pop.validate([got]), [])

    def pypi_registry(self, data, digest=None, size=None, files=None):
        whl = PY_FILES + "six-1.17.0-py3-none-any.whl"
        urls = files or [{"filename": "six-1.17.0.tar.gz", "packagetype": "sdist", "url": PY_FILES + "six-1.17.0.tar.gz",
                          "digests": {"sha256": "1" * 64}},
                         {"filename": "six-1.17.0-py3-none-any.whl", "packagetype": "bdist_wheel", "url": whl,
                          "digests": {"sha256": digest or sha(data)}, "size": size or len(data)}]
        meta = {"info": {"version": "1.17.0"}, "urls": urls}
        return Registry({"https://pypi.org/pypi/six/json": json.dumps(meta).encode(),
                         "https://pypi.org/pypi/six/1.17.0/json": json.dumps(meta).encode(), whl: data})

    def test_pypi_the_picked_file_checked_against_the_registrys_digest(self):
        data = b"PK wheel bytes"
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("pypi", "six", None, cache, self.pypi_registry(data))
            self.assertEqual((got["filename"], got["kind"], got["sha256"]), ("six-1.17.0-py3-none-any.whl", "wheel", sha(data)))
            with self.assertRaisesRegex(pop.PinError, "not the file the registry lists"):
                pop.pin_one("pypi", "six", "1.17.0", cache, self.pypi_registry(data, digest="2" * 64))
            self.assertEqual(os.listdir(cache), [sha(data)])                # the bytes that failed are gone

    def test_what_is_not_pinned(self):
        with tempfile.TemporaryDirectory() as cache:
            with self.assertRaisesRegex(pop.PinError, "over"):
                pop.pin_one("pypi", "six", None, cache, self.pypi_registry(b"x", size=pop.MAX_FILE_BYTES + 1))
            mac = [{"filename": "six-1.17.0-cp311-cp311-macosx_11_0_arm64.whl", "packagetype": "bdist_wheel",
                    "url": PY_FILES + "six-1.17.0-cp311-cp311-macosx_11_0_arm64.whl"}]
            with self.assertRaisesRegex(pop.PinError, "no file to install"):
                pop.pin_one("pypi", "six", None, cache, self.pypi_registry(b"x", files=mac))
            reg = Registry({"https://registry.npmjs.org/gone/latest": json.dumps({"version": "1.0.0"}).encode()})
            with self.assertRaisesRegex(pop.PinError, "no tarball"):
                pop.pin_one("npm", "gone", None, cache, reg)
            with self.assertRaisesRegex(pop.PinError, "404"):
                pop.pin_one("npm", "missing", None, cache, Registry({}))
            elsewhere = Registry({"https://registry.npmjs.org/moved/latest":
                                  self.npm_meta("moved", "1.0.0", "https://cdn.invalid/moved-1.0.0.tgz")})
            with self.assertRaisesRegex(pop.PinError, "only https from registry.npmjs.org"):
                pop.pin_one("npm", "moved", None, cache, elsewhere)
            self.assertEqual(os.listdir(cache), [])


class CratesTests(unittest.TestCase):
    """A crate's release: crates.io's default version by the name crates.io spells, its licence, its checksum."""

    def setUp(self):
        old = pop.API_INTERVAL
        pop.API_INTERVAL = 0
        self.addCleanup(setattr, pop, "API_INTERVAL", old)

    def registry(self, data, licence="MIT OR Apache-2.0", checksum=None, yanked=False, extra=None):
        version = {"num": "0.6.4", "checksum": checksum or sha(data), "license": licence, "yanked": yanked,
                   "crate_size": len(data), "crate": "rand_core"}
        meta = {"crate": {"name": "rand_core", "default_version": "0.6.4", "max_version": "0.7.0-pre"},
                "versions": [version, dict(version, num="0.5.1")]}
        pages = {API + "rand-core": json.dumps(meta).encode(), API + "rand_core": json.dumps(meta).encode(),
                 CRATE_FILES + "rand_core/rand_core-0.6.4.crate": data}
        pages.update(extra or {})
        return Registry(pages)

    def test_the_default_version_under_the_name_crates_io_spells(self):
        data = b"\x1f\x8b crate bytes"
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("crates", "rand-core", None, cache, self.registry(data))
        self.assertEqual(got, {"id": "crates:rand_core@0.6.4", "ecosystem": "crates", "name": "rand_core",
                               "version": "0.6.4", "filename": "rand_core-0.6.4.crate",
                               "url": CRATE_FILES + "rand_core/rand_core-0.6.4.crate", "container": "tgz",
                               "kind": "crate", "sha256": sha(data), "bytes": len(data)})
        self.assertEqual(pop.validate([got]), [])

    def test_a_version_the_crates_answer_leaves_out_and_build_metadata(self):
        data = b"wasi crate"
        version = {"num": "0.1.0+wasi-snapshot", "checksum": sha(data), "license": "Apache-2.0 WITH LLVM-exception",
                   "yanked": False, "crate_size": len(data)}
        reg = Registry({API + "wasi": json.dumps({"crate": {"name": "wasi", "default_version": "0.2.0"},
                                                  "versions": []}).encode(),
                        API + "wasi/0.1.0%2Bwasi-snapshot": json.dumps({"version": version}).encode(),
                        CRATE_FILES + "wasi/wasi-0.1.0+wasi-snapshot.crate": data})
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("crates", "wasi", "0.1.0+wasi-snapshot", cache, reg)
        self.assertEqual((got["id"], got["filename"]), ("crates:wasi@0.1.0+wasi-snapshot",
                                                         "wasi-0.1.0+wasi-snapshot.crate"))
        self.assertEqual(pop.validate([got]), [])

    def test_what_is_not_pinned(self):
        data = b"crate"
        with tempfile.TemporaryDirectory() as cache:
            for reg, version, text in (
                    (self.registry(data, licence="GPL-3.0-only"), None, "licence 'GPL-3.0-only' is not one"),
                    (self.registry(data, licence=None), None, "licence None"),
                    (self.registry(data, yanked=True), "0.5.1", "yanked"),
                    (self.registry(data), "9.9.9", "404"),
                    (self.registry(data, checksum="3" * 64), None, "not the file the registry lists")):
                with self.subTest(text=text), self.assertRaisesRegex(pop.PinError, text):
                    pop.pin_one("crates", "rand_core", version, cache, reg)
            self.assertEqual(os.listdir(cache), [])

    def test_crates_io_is_asked_once_a_second(self):
        pop.API_INTERVAL = 0.2
        reg = self.registry(b"x")
        with tempfile.TemporaryDirectory() as cache:
            started = time.monotonic()
            for _ in range(3):
                pop.pin_one("crates", "rand-core", None, cache, reg)
        self.assertGreaterEqual(time.monotonic() - started, 0.4)

    def test_the_licences_a_crate_may_be_under(self):
        for expr, ok in (("MIT OR Apache-2.0", True), ("MIT/Apache-2.0", True), ("Unlicense/MIT", True),
                         ("(MIT OR Apache-2.0) AND Unicode-3.0", True), ("Apache-2.0 WITH LLVM-exception", True),
                         ("MIT OR GPL-3.0", True), ("Apache-2.0+", True), ("Zlib OR Apache-2.0 OR MIT", True),
                         ("GPL-3.0", False), ("MIT AND GPL-2.0", False), ("MPL-2.0", False), ("GPL-2.0+", False),
                         ("Apache-2.0 WITH Classpath-exception-2.0", False), ("CDLA-Permissive-2.0", False),
                         ("", False), (None, False), ("MIT OR", False), ("(MIT", False), ("MIT)", False),
                         ("(" * 5000 + "MIT" + ")" * 5000, False), (" OR ".join(["MIT"] * 40), False)):
            with self.subTest(expr=expr):
                self.assertEqual(pop.licence_ok(expr), ok)


def extension(version, platform="universal", pre=False, licence="MIT", ns="redhat", name="java", **over):
    """An entry of Open VSX's query answer: one version's file for one platform."""
    at = "" if platform == "universal" else f"@{platform}"
    where = f"{OVSX}{ns}/{name}/" + ("" if platform == "universal" else f"{platform}/") + f"{version}/file/"
    file = f"{where}{ns}.{name}-{version}{at}"
    e = {"namespace": ns, "name": name, "version": version, "targetPlatform": platform, "preRelease": pre,
         "files": {"download": file + ".vsix", "sha256": file + ".sha256"}}
    if licence is not None:
        e["license"] = licence
    e.update(over)
    return e


def query(name="redhat.java", version=None, offset=0, size=1000):
    which = f"&extensionVersion={version}" if version else "&includeAllVersions=true"
    return f"{OVSX}-/query?extensionId={name}{which}&size={size}&offset={offset}"


class OpenVSXTests(unittest.TestCase):
    """An extension's release: Open VSX's newest release with a file for Linux x86-64, its licence, its sha256."""

    def setUp(self):
        old = pop.OPENVSX_INTERVAL
        pop.OPENVSX_INTERVAL = 0
        self.addCleanup(setattr, pop, "OPENVSX_INTERVAL", old)

    def registry(self, entries, data=b"PK vsix bytes", digest=None, total=None, extra=None, name="redhat.java",
                 version=None):
        pages = {query(name, version): json.dumps({"extensions": entries, "totalSize": len(entries) if total is None
                                                   else total}).encode()}
        for e in entries:
            pages[e["files"]["download"]] = data
            pages[e["files"]["sha256"]] = (digest or sha(data)).encode() + b"\n"
        pages.update(extra or {})
        return Registry(pages)

    def test_the_newest_release_with_a_file_for_linux_x86_64(self):
        data = b"PK linux-x64 vsix"
        entries = [extension("1.42.0", pre=True), extension("1.41.0", "darwin-arm64"),
                   extension("1.40.0", "darwin-arm64"), extension("1.40.0", "linux-x64"), extension("1.39.0"),
                   extension("1.43.0", downloadable=False)]
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("openvsx", "redhat.java", None, cache, self.registry(entries, data))
            self.assertEqual(os.listdir(cache), [sha(data)])
        url = OVSX + "redhat/java/linux-x64/1.40.0/file/redhat.java-1.40.0@linux-x64.vsix"
        self.assertEqual(got, {"id": "openvsx:redhat.java@1.40.0", "ecosystem": "openvsx", "name": "redhat.java",
                               "version": "1.40.0", "filename": "redhat.java-1.40.0@linux-x64.vsix", "url": url,
                               "container": "zip", "kind": "vsix", "sha256": sha(data), "bytes": len(data)})
        self.assertEqual(pop.validate([got]), [])

    def test_a_named_version_a_universal_file_and_the_registrys_spelling(self):
        entries = [extension("0.47.1", ns="golang", name="Go"),
                   extension("0.47.1", "darwin-x64", ns="golang", name="Go")]
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("openvsx", "golang.go", "0.47.1", cache,
                              self.registry(entries, name="golang.go", version="0.47.1"))
        self.assertEqual((got["id"], got["filename"]), ("openvsx:golang.Go@0.47.1", "golang.Go-0.47.1.vsix"))
        pre = [extension("2.0.0", pre=True)]
        with tempfile.TemporaryDirectory() as cache:                       # a pre-release, when it is named
            got = pop.pin_one("openvsx", "redhat.java", "2.0.0", cache, self.registry(pre, version="2.0.0"))
        self.assertEqual(got["version"], "2.0.0")

    def test_the_pages_are_read_until_one_holds_a_release(self):
        old = pop.OPENVSX_PAGE
        pop.OPENVSX_PAGE = 2
        self.addCleanup(setattr, pop, "OPENVSX_PAGE", old)
        first, second = [extension("1.2.0", pre=True), extension("1.1.0", pre=True)], [extension("1.0.0")]
        reg = self.registry(first + second, extra={
            query(size=2): json.dumps({"extensions": first, "totalSize": 3}).encode(),
            query(offset=2, size=2): json.dumps({"extensions": second, "totalSize": 3}).encode()})
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("openvsx", "redhat.java", None, cache, reg)
        self.assertEqual(got["version"], "1.0.0")
        self.assertIn(query(offset=2, size=2), reg.asked)

    def test_a_licence_only_the_versions_document_names(self):
        entries = [extension("1.40.0", "linux-x64", licence=None)]
        doc = {OVSX + "redhat/java/linux-x64/1.40.0": json.dumps({"license": "Apache-2.0"}).encode()}
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("openvsx", "redhat.java", None, cache, self.registry(entries, extra=doc))
        self.assertEqual(got["version"], "1.40.0")

    def test_what_is_not_pinned(self):
        release = [extension("1.40.0")]
        no_licence = {OVSX + "redhat/java/1.40.0": json.dumps({"license": "EPL-2.0"}).encode()}
        with tempfile.TemporaryDirectory() as cache:
            for reg, name, text in (
                    (self.registry([], total=0), "redhat.java", "not in Open VSX"),
                    (self.registry([extension("1.0.0", pre=True), extension("0.9.0", "win32-x64"),
                                    extension("0.8.0", downloadable=False)]), "redhat.java",
                     "no release with a file for Linux x86-64"),
                    (self.registry([extension("1.40.0", licence="GPL-3.0-only")]), "redhat.java",
                     "licence 'GPL-3.0-only' is not one"),
                    (self.registry([extension("1.40.0", licence=None)], extra=no_licence), "redhat.java",
                     "licence 'EPL-2.0' is not one"),
                    (self.registry(release, digest="4" * 64), "redhat.java", "not the file the registry lists"),
                    (self.registry(release, digest="not a digest"), "redhat.java", "is not a sha256"),
                    (Registry({query(): b"<html>"}), "redhat.java", "not JSON"),
                    (Registry({query(): b'{"extensions": {}}'}), "redhat.java", "not a list of versions"),
                    (self.registry(release), "java", "not namespace.name")):
                with self.subTest(text=text), self.assertRaisesRegex(pop.PinError, text):
                    pop.pin_one("openvsx", name, None, cache, reg)
            moved = extension("1.40.0")
            moved["files"]["download"] = "https://cdn.invalid/redhat.java-1.40.0.vsix"
            with self.assertRaisesRegex(pop.PinError, "only https from open-vsx.org or openvsx.eclipsecontent.org"):
                pop.pin_one("openvsx", "redhat.java", None, cache, self.registry([moved]))
            elsewhere = extension("1.40.0")
            elsewhere["files"]["sha256"] = "https://cdn.invalid/redhat.java-1.40.0.sha256"
            with self.assertRaisesRegex(pop.PinError, "its digest is not on open-vsx.org"):
                pop.pin_one("openvsx", "redhat.java", None, cache, self.registry([elsewhere]))
            self.assertEqual(os.listdir(cache), [])

    def test_open_vsx_is_asked_twice_a_second(self):
        pop.OPENVSX_INTERVAL = 0.05
        reg = self.registry([extension("1.40.0")])
        with tempfile.TemporaryDirectory() as cache:
            started = time.monotonic()
            for _ in range(2):                         # the query, the digest and the file, twice
                pop.pin_one("openvsx", "redhat.java", None, cache, reg)
        self.assertGreaterEqual(time.monotonic() - started, 0.25)

    def test_the_version_order(self):
        order = ["1.0", "0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11",
                 "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0+build"]
        self.assertEqual(sorted(reversed(order), key=pop.version_key), order)


class RedirectTests(unittest.TestCase):
    def test_a_redirect_only_to_https_on_a_registrys_host(self):
        handler = pop._Redirects()
        req = urllib.request.Request(OVSX + "redhat/java/1.40.0/file/redhat.java-1.40.0.vsix")
        to = "https://openvsx.eclipsecontent.org/redhat/java/1.40.0/file/redhat.java-1.40.0.vsix"
        self.assertEqual(handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, to).full_url, to)
        for bad in ("http://openvsx.eclipsecontent.org/x.vsix", "https://cdn.invalid/x.vsix", "file:///etc/passwd"):
            with self.subTest(to=bad), self.assertRaisesRegex(urllib.error.HTTPError, "not https on a registry's host"):
                handler.redirect_request(req, io.BytesIO(), 302, "Found", {}, bad)

    def test_the_default_opener_checks_them(self):
        self.assertTrue(any(isinstance(h, pop._Redirects) for h in pop.urlopen.__self__.handlers))
        self.assertIs(pop.get.__defaults__[-1], pop.urlopen)


class FetchTests(unittest.TestCase):
    def test_fetched_once_named_by_sha256_and_hashed_again(self):
        data = b"the pinned bytes"
        r = row(data=data)
        reg = Registry({r["url"]: data})
        with tempfile.TemporaryDirectory() as cache:
            path = pop.fetch_file(r, cache, reg)
            self.assertEqual(os.path.basename(path), sha(data))
            pop.fetch_file(r, cache, reg)
            self.assertEqual(len(reg.asked), 1)                               # the cached file is used
            with open(path, "wb") as fh:
                fh.write(b"swapped")
            pop.fetch_file(r, cache, reg)                                      # and hashed again first
            self.assertEqual(len(reg.asked), 2)
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), data)

    def test_other_bytes_are_refused_and_not_kept(self):
        r = row(data=b"pinned")
        with tempfile.TemporaryDirectory() as cache:
            with self.assertRaisesRegex(pop.PinError, "not the pinned ones"):
                pop.fetch_file(r, cache, Registry({r["url"]: b"substituted"}))
            self.assertEqual(os.listdir(cache), [])

    def test_the_size_limit(self):
        r = row(data=b"x")
        big = b"x" * (2 << 20)
        with tempfile.TemporaryDirectory() as cache:
            old = pop.MAX_FILE_BYTES
            pop.MAX_FILE_BYTES = 1 << 20
            try:
                with self.assertRaisesRegex(pop.PinError, "more than 1 MiB"):
                    pop.fetch_file(r, cache, Registry({r["url"]: big}))
            finally:
                pop.MAX_FILE_BYTES = old
            self.assertEqual(os.listdir(cache), [])

    def test_fetch_command_writes_the_benchmark_manifest(self):
        good, bad = row(data=b"good"), row(name="other", data=b"pinned")
        reg = Registry({good["url"]: b"good", bad["url"]: b"changed"})
        with tempfile.TemporaryDirectory() as d:
            releases, cache, manifest = (os.path.join(d, n) for n in ("r.jsonl", "cache", "m.jsonl"))
            pop.write_releases([good, bad], releases)
            args = pop.build_parser().parse_args(["--releases", releases, "fetch", "--cache", cache,
                                                  "--manifest", manifest])
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(pop.cmd_fetch(args, reg), pop.EXIT_FETCH)
            self.assertIn("not the pinned ones", err.getvalue())
            with open(manifest, encoding="utf-8") as fh:
                lines = [json.loads(line) for line in fh]
        self.assertEqual(len(lines), 1)
        self.assertEqual({k: lines[0][k] for k in ("id", "cat", "container", "kind")},
                         {"id": "popular:npm:left-pad@1.3.0", "cat": "benign", "container": "tgz", "kind": "npm"})
        self.assertEqual(os.path.basename(lines[0]["artifact_path"]), sha(b"good"))


class NamesAndSpecsTests(unittest.TestCase):
    def test_top_names_less_the_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            names = os.path.join(d, "names.json")
            with open(names, "w", encoding="utf-8") as fh:
                json.dump({"npm": {"targets": ["semver", "debug", "chalk", "lodash"]},
                           "pypi": {"targets": ["boto3", "typing-extensions", "six"]}}, fh)
            exclude = os.path.join(d, "exclude.txt")
            with open(exclude, "w", encoding="utf-8") as fh:
                fh.write("npm:debug\n# the benchmark's\nTyping_Extensions\n")
            got = pop.top_names({"npm": 2, "pypi": 2}, pop.read_exclude(exclude), names)
            self.assertEqual(got, [("npm", "semver"), ("npm", "chalk"), ("pypi", "boto3"), ("pypi", "six")])
            with open(names, "w", encoding="utf-8") as fh:
                json.dump({"npm": {"targets": ["semver"]}, "pypi": {"targets": ["six"]},
                           "crates": {"targets": ["syn", "rand-core", "serde"]}}, fh)
            with open(exclude, "w", encoding="utf-8") as fh:
                fh.write("crates:rand_core\n")
            got = pop.top_names(pop.parse_top("1,0,2"), pop.read_exclude(exclude), names)
        self.assertEqual(got, [("npm", "semver"), ("crates", "syn"), ("crates", "serde")])

    def test_extensions_from_the_vscode_section(self):
        with tempfile.TemporaryDirectory() as d:
            names = os.path.join(d, "names.json")
            with open(names, "w", encoding="utf-8") as fh:
                json.dump({"npm": {"targets": ["semver"]}, "pypi": {"targets": []}, "crates": {"targets": []},
                           "vscode": {"targets": ["ms-python.python", "redhat.java", "golang.go"]}}, fh)
            exclude = os.path.join(d, "exclude.txt")
            with open(exclude, "w", encoding="utf-8") as fh:
                fh.write("openvsx:RedHat.Java\n")
            got = pop.top_names(pop.parse_top("0,0,0,2"), pop.read_exclude(exclude), names)
        self.assertEqual(got, [("openvsx", "ms-python.python"), ("openvsx", "golang.go")])

    def test_top_counts(self):
        self.assertEqual(pop.parse_top("800,400"), {"npm": 800, "pypi": 400})
        self.assertEqual(pop.parse_top("800,400,500"), {"npm": 800, "pypi": 400, "crates": 500})
        self.assertEqual(pop.parse_top("0,0,0,300"), {"npm": 0, "pypi": 0, "crates": 0, "openvsx": 300})
        for bad in ("800", "1,2,3,4,5", "a,b", "1,-1"):
            with self.subTest(top=bad), self.assertRaises(argparse.ArgumentTypeError):
                pop.parse_top(bad)

    def test_specs(self):
        self.assertEqual(pop.parse_spec("npm:@babel/parser@7.29.9"), ("npm", "@babel/parser", "7.29.9"))
        self.assertEqual(pop.parse_spec("pypi:sympy"), ("pypi", "sympy", None))
        self.assertEqual(pop.parse_spec("crates:rand_core@0.6.4"), ("crates", "rand_core", "0.6.4"))
        self.assertEqual(pop.parse_spec("openvsx:redhat.java@1.40.0"), ("openvsx", "redhat.java", "1.40.0"))
        for bad in ("gem:rails@7", "npm:", "lodash@4"):
            with self.subTest(spec=bad), self.assertRaises(ValueError):
                pop.parse_spec(bad)

    def test_pin_with_specs_keeps_the_others_and_moves_a_name(self):
        data = b"new tarball"
        url = NPM_FILES + "left-pad/-/left-pad-1.4.0.tgz"
        reg = Registry({"https://registry.npmjs.org/left-pad/1.4.0":
                        json.dumps({"version": "1.4.0", "dist": {"tarball": url}}).encode(), url: data})
        with tempfile.TemporaryDirectory() as d:
            releases = os.path.join(d, "r.jsonl")
            pop.write_releases([row(), row("pypi", "six", "1.17.0")], releases)
            args = pop.build_parser().parse_args(["--releases", releases, "pin", "npm:left-pad@1.4.0",
                                                  "--cache", os.path.join(d, "cache")])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pop.cmd_pin(args, reg), pop.EXIT_OK)
            ids = [r["id"] for r in pop.read_releases(releases)]
        self.assertEqual(ids, ["npm:left-pad@1.4.0", "pypi:six@1.17.0"])

    def test_pin_top_keeps_the_ecosystems_it_is_given_no_count_for(self):
        with open(pop.NAMES, encoding="utf-8") as fh:
            first = json.load(fh)["vscode"]["targets"][0]
        ns, name = first.split(".")
        entry = extension("3.0.0", ns=ns, name=name)
        data = b"PK newer vsix"
        reg = Registry({query(first): json.dumps({"extensions": [entry], "totalSize": 1}).encode(),
                        entry["files"]["download"]: data, entry["files"]["sha256"]: sha(data).encode()})
        old = pop.OPENVSX_INTERVAL
        pop.OPENVSX_INTERVAL = 0
        self.addCleanup(setattr, pop, "OPENVSX_INTERVAL", old)
        with tempfile.TemporaryDirectory() as d:
            releases = os.path.join(d, "r.jsonl")
            pop.write_releases([row(), row("crates", "serde", "1.0.228"), row("openvsx", first, "2.0.0")], releases)
            args = pop.build_parser().parse_args(["--releases", releases, "pin", "--top", "0,0,0,1",
                                                  "--cache", os.path.join(d, "cache")])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pop.cmd_pin(args, reg), pop.EXIT_OK)
            ids = [r["id"] for r in pop.read_releases(releases)]
        self.assertEqual(ids, ["crates:serde@1.0.228", "npm:left-pad@1.3.0", f"openvsx:{first}@3.0.0"])

    def test_pin_takes_specs_or_top(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pop.main(["pin", "--cache", "x"]), pop.EXIT_USAGE)
            self.assertEqual(pop.main(["pin", "npm:a@1", "--top", "1,1", "--cache", "x"]), pop.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
