"""lazaret guard's comparison of a WARN release with its established predecessor (SC-NEW-INDICATOR, registry/prior.py),
as `lazaret-registry` compares it: for a release from npm's or PyPI's public registry published less than
guard.PROVENANCE_DAYS ago, over the guard's fetcher and scanner, the predecessor's verdict cached as any other's.

The scans are real (in this process); the registries are recorded answers built here, and nothing opens a socket.
Names are made up and the payloads inert: an install hook that runs a file that prints, a base64 string of the bytes
0 to 255."""

import base64
import datetime
import email.utils
import hashlib
import io
import json
import os
import unittest
import urllib.parse
import zipfile
from unittest import mock

from lazaret.registry import guard, prior, repo
from lazaret.registry.ecosystems import base
from lazaret.scanner import _native
from tests.registry._review_support import manifest, tarball
from tests.registry.test_guard import context

NPM = guard.NPM_REGISTRY
ON = {prior.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": ""}
BLOB = base64.b64encode(bytes(range(256)) * 2).decode()


def days_ago(days):
    return guard.now() - datetime.timedelta(days=days)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def npm_package(hook):
    files = {"package.json": manifest(main="index.js", **({"scripts": {"postinstall": "node install.js"}} if hook
                                                          else {})),
             "index.js": "module.exports = 1;\n", "install.js": "console.log('ready');\n"}
    return tarball(files)


class Fetcher:
    """The guard's Fetcher over recorded answers: a file's response carries the time it was published."""

    def __init__(self, answers, published):
        self.answers, self.published, self.asked = dict(answers), published, []

    def get(self, url, max_bytes=None, accept=None, timeout=None):
        self.asked.append(url)
        body = self.answers.get(url)
        if isinstance(body, Exception):
            raise body
        if body is None:
            raise base.FetchError(f"HTTP 404 fetching {url}")
        return body

    def fetch(self, url, max_bytes=None, accept=None, timeout=None):
        return self.get(url), {"Last-Modified": email.utils.format_datetime(self.published, usegmt=True)}

    def json(self, url, accept=None):
        raise base.FetchError("not asked here")


class CountingScanner(guard.Scanner):
    """guard.Scanner in this process, counting its scans."""

    def __init__(self, cache):
        super().__init__(cache, jobs=1, isolate=False)
        self.scans = 0

    def scan(self, data, container, kind):
        self.scans += 1
        return super().scan(data, container, kind)


def npm_answers(name, versions):
    """{version: (published, tarball)} -> the registry's answers: the packument, each tarball."""
    answers, times, docs = {}, {"created": iso(min(t for t, _d in versions.values()))}, {}
    for v, (when, data) in versions.items():
        url = f"{NPM}{name}/-/{name}-{v}.tgz"
        answers[url], times[v] = data, iso(when)
        docs[v] = {"name": name, "version": v, "dist": {"tarball": url, "integrity": sri(data)}}
    answers[NPM + urllib.parse.quote(name, safe="@")] = json.dumps({"name": name, "time": times,
                                                                    "versions": docs}).encode()
    return answers


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
class NpmTests(unittest.TestCase):
    def setUp(self):
        self.cache = guard.VerdictCache(None)

    def check(self, versions, version, registry=NPM, answers=None):
        answers = answers or npm_answers("files-kit", versions)
        when, data = versions[version]
        fetcher = Fetcher(answers, when)
        ctx = context(tool="npm")
        ctx.scanner.close()
        ctx.scanner = CountingScanner(self.cache)
        tarball_url = f"{registry}files-kit/-/files-kit-{version}.tgz"
        fetcher.answers[tarball_url] = data
        pkg = {"name": "files-kit", "version": version, "tarball": tarball_url, "integrity": sri(data),
               "registry": registry, "lock_digest": None}
        return guard.check_npm_package(ctx, fetcher, pkg), fetcher, ctx.scanner

    def test_a_hook_its_predecessor_did_not_have_is_blocked(self):
        versions = {"1.0.0": (days_ago(30), npm_package(False)), "1.0.1": (days_ago(3), npm_package(True)),
                    "1.0.2": (days_ago(2), npm_package(True))}
        check, fetcher, scanner = self.check(versions, "1.0.2")
        self.assertEqual(check.verdict, "SUSPICIOUS")
        self.assertTrue(check.blocked[0].startswith("SUSPICIOUS: Install hook (SC-INSTALL-HOOK) is new in this "
                                                    "release: 1.0.0, published 28 days before it"), check.blocked)
        self.assertTrue(check.indicators[0].startswith("SC-NEW-INDICATOR (CRITICAL) package.json: "), check.indicators)
        self.assertEqual(check.to_json()["priorRelease"], {"version": "1.0.0", "publishedBefore": "28 days",
                                                           "files": ["files-kit-1.0.0.tgz"],
                                                           "newRules": ["SC-INSTALL-HOOK"]})
        self.assertEqual(scanner.scans, 2)                                  # the release and its predecessor
        # the verdict cached with the comparison, the predecessor's with its rules: nothing fetched or scanned again
        check, fetcher, scanner = self.check(versions, "1.0.2")
        self.assertEqual((check.verdict, scanner.scans), ("SUSPICIOUS", 0))
        self.assertEqual(fetcher.asked, [])                                 # (known by the lockfile's digest)
        older = self.cache.get(guard.VerdictCache.key("npm", "files-kit", "1.0.0", sri(versions["1.0.0"][1])))
        self.assertEqual((older["verdict"], "rules" in older), ("OK", False))    # (an OK verdict has none)

    def test_a_hook_its_predecessor_had(self):
        versions = {"1.0.0": (days_ago(30), npm_package(True)), "1.0.2": (days_ago(2), npm_package(True))}
        check, _, _ = self.check(versions, "1.0.2")
        self.assertEqual((check.verdict, check.blocked, check.prior["newRules"]), ("WARN", [], []))

    def test_not_compared(self):
        versions = {"1.0.0": (days_ago(70), npm_package(False)), "1.0.2": (days_ago(40), npm_package(True))}
        check, fetcher, _ = self.check(versions, "1.0.2")                  # out of the window
        self.assertEqual((check.verdict, check.prior, len(fetcher.asked)), ("WARN", None, 1))
        self.cache = guard.VerdictCache(None)
        versions = {"1.0.0": (days_ago(30), npm_package(False)), "1.0.2": (days_ago(2), npm_package(True))}
        check, fetcher, _ = self.check(versions, "1.0.2", registry="https://npm.example.invalid/")
        self.assertEqual((check.verdict, check.prior), ("WARN", None))   # a private registry's: not named to npm's
        self.assertFalse(any(u.startswith(NPM) for u in fetcher.asked), fetcher.asked)
        self.cache = guard.VerdictCache(None)
        with mock.patch.dict(os.environ, {prior.OFF_ENV: "1"}):
            check, _, _ = self.check(versions, "1.0.2")
        self.assertEqual((check.verdict, check.prior), ("WARN", None))

    def test_a_registry_that_did_not_answer_is_asked_again(self):
        versions = {"1.0.0": (days_ago(30), npm_package(False)), "1.0.2": (days_ago(2), npm_package(True))}
        answers = npm_answers("files-kit", versions)
        answers[NPM + "files-kit"] = base.FetchError("HTTP 503 fetching the packument")
        check, _, scanner = self.check(versions, "1.0.2", answers=answers)
        self.assertEqual((check.verdict, scanner.scans), ("WARN", 1))
        self.assertIn("HTTP 503", check.prior["notCompared"])
        check, _, scanner = self.check(versions, "1.0.2")                 # (the release's rules from the cache)
        self.assertEqual((check.verdict, scanner.scans), ("SUSPICIOUS", 1))


def wheel(version, blob):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pkg/__init__.py", f"DATA = '{BLOB}'\n" if blob else "DATA = 1\n")
        z.writestr(f"pkg-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: pkg\nVersion: {version}\n")
        z.writestr(f"pkg-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        z.writestr(f"pkg-{version}.dist-info/RECORD", "")
    return buf.getvalue()


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
class PypiTests(unittest.TestCase):
    def check(self, old_blob):
        answers, files = {}, []
        for version, when, blob in (("1.0", days_ago(30), old_blob), ("1.1", days_ago(2), True)):
            name = f"pkg-{version}-py3-none-any.whl"
            url = f"https://files.pythonhosted.org/packages/xx/{name}"
            answers[url] = wheel(version, blob)
            files.append({"filename": name, "url": url, "hashes": {"sha256": hashlib.sha256(answers[url]).hexdigest()},
                          "upload-time": iso(when)})
        answers["https://pypi.org/simple/pkg/"] = json.dumps({"name": "pkg", "versions": ["1.0", "1.1"],
                                                              "files": files}).encode()
        ctx = context(tool="pip")
        ctx.scanner.close()
        ctx.scanner = CountingScanner(guard.VerdictCache(None))
        f = {"url": files[1]["url"], "hash": "sha256:" + files[1]["hashes"]["sha256"], "upload-time": files[1]["upload-time"],
             "filename": files[1]["filename"]}
        return guard.check_file(ctx, Fetcher(answers, days_ago(2)), "pkg", "1.1", f)

    def test_a_blob_its_predecessor_did_not_have_is_blocked(self):
        check = self.check(old_blob=False)
        self.assertEqual((check.verdict, check.prior["files"]), ("SUSPICIOUS", ["pkg-1.0-py3-none-any.whl"]))
        self.assertTrue(check.blocked)

    def test_one_it_had(self):
        check = self.check(old_blob=True)
        self.assertEqual((check.verdict, check.blocked, check.prior["newRules"]), ("WARN", [], []))


if __name__ == "__main__":
    unittest.main()
