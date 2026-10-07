"""lazaret guard's provenance check (0.1.9, NET-1): npm's and PyPI's, for a release published less than
guard.PROVENANCE_DAYS ago, as `lazaret-registry` checks it (registry/provenance.py), merged into the scan's verdict.

On the real attestations test_provenance reads (tiny_https's capture of the registries: the npm package sigstore 2.2.0
and 4.0.0, the wheel pypi-attestations 0.0.30), with the registries' other documents built in their shapes. The scan
is a stand-in (every archive OK), so what moves a verdict here is the provenance alone. Nothing here opens a socket."""

import base64
import datetime
import email.utils
import hashlib
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.registry import guard, provenance, repo
from lazaret.registry.ecosystems import base
from tests.registry import test_provenance as TP
from tests.registry.test_guard import _FakeFetcher, context

NPM = guard.NPM_REGISTRY
TARBALL = NPM + "sigstore/-/sigstore-{v}.tgz"


class OkScanner:
    """Stands in for guard.Scanner: every archive OK; a verdict cache in memory."""

    def __init__(self, cache=None):
        self.cache, self.scans = dict(cache or {}), 0

    def cached(self, key):
        return self.cache.get(key) if key else None

    def remember(self, key, hit, published):
        if key:
            self.cache[key] = hit

    def holding(self, nbytes):
        return guard.ByteGate(1 << 40).hold(nbytes)

    def scan(self, data, container, kind):
        self.scans += 1
        return {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": []}

    def close(self):
        pass


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def days_ago(days):
    return guard.now() - datetime.timedelta(days=days)


class NpmFetcher:
    """The guard's Fetcher over recorded answers: a tarball's response carries its Last-Modified."""

    def __init__(self, answers, published):
        self.answers, self.published, self.asked = dict(answers), published, []

    def get(self, url, max_bytes=None, accept=None, timeout=None):
        self.asked.append(url)
        body = self.answers.get(url)
        if body is None:
            err = base.FetchError(f"HTTP 404 fetching {url}")
            err.status = 404
            raise err
        return body

    def fetch(self, url, max_bytes=None, accept=None, timeout=None):
        return self.get(url), {"Last-Modified": email.utils.format_datetime(self.published, usegmt=True)}

    def json(self, url, accept=None):
        raise base.FetchError("not asked here")


@unittest.skipUnless(TP.checks(), "no native library with the provenance check")
@mock.patch.dict(os.environ, TP.ON)
class NpmTests(unittest.TestCase):
    def check(self, version, data, manifests, published=None, registry=NPM, cache=None, **opts):
        answers = TP.npm_answers(*manifests)
        answers[TARBALL.format(v=version)] = data
        fetcher = NpmFetcher(answers, published or days_ago(5))
        ctx = context(tool="npm", **opts)
        ctx.scanner.close()
        ctx.scanner = OkScanner(cache)
        pkg = {"name": "sigstore", "version": version, "tarball": TARBALL.format(v=version).replace(NPM, registry),
               "integrity": sri(data), "registry": registry, "lock_digest": None}
        if registry != NPM:
            fetcher.answers[pkg["tarball"]] = data
        check = guard.check_npm_package(ctx, fetcher, pkg)
        return check, fetcher, ctx

    def test_a_release_its_ci_built_like_the_one_before(self):
        check, fetcher, _ = self.check("4.0.0", TP.TARBALLS["4.0.0"], [TP.npm_manifest(v) for v in TP.TARBALLS])
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertEqual(check.provenance["repository"], TP.SIGSTORE_JS)
        self.assertEqual(check.provenance["previous"]["version"], "2.2.0")
        self.assertEqual(check.to_json()["provenance"]["files"], [{"filename": None, "status": "verified"}])
        # (the package's document read once, the two releases' attestations)
        self.assertEqual(sorted(u for u in fetcher.asked if u != TARBALL.format(v="4.0.0")),
                         [NPM + "-/npm/v1/attestations/sigstore@2.2.0", NPM + "-/npm/v1/attestations/sigstore@4.0.0",
                          NPM + "sigstore"])

    def test_a_release_without_the_provenance_the_one_before_had_is_a_warning(self):
        data = b"another tarball"
        later = TP.npm_manifest("4.0.1", attested=False, data=data)
        manifests = [TP.npm_manifest(v) for v in TP.TARBALLS] + [later]
        check, _, ctx = self.check("4.0.1", data, manifests)
        self.assertEqual((check.verdict, check.blocked), ("WARN", []))
        self.assertIn("4.0.1 has no provenance, though 4.0.0, the release before it, has", check.reason)
        self.assertTrue(check.indicators[0].startswith("SC-PROVENANCE-DROPPED (MAJOR)"), check.indicators)
        self.assertEqual(ctx.scanner.cache[guard.VerdictCache.key("npm", "sigstore", "4.0.1", f"sha512-{sri(data)[7:]}")]
                         ["verdict"], "WARN")                                          # (kept with the verdict)
        check, _, _ = self.check("4.0.1", data, manifests, block_warn=True)
        self.assertEqual(check.blocked, [f"WARN (--block-warn): {check.reason}"])

    def test_attestations_that_do_not_hold_for_the_tarball_block_it(self):
        data = b"another tarball"
        manifests = [TP.npm_manifest(v) for v in ("2.2.0",)] + [TP.npm_manifest("4.0.0", data=data)]
        check, _, _ = self.check("4.0.0", data, manifests)
        self.assertEqual(check.verdict, "SUSPICIOUS")
        self.assertTrue(check.blocked and check.blocked[0].startswith("SUSPICIOUS: An attestation of"), check.blocked)
        self.assertTrue(check.indicators[0].startswith("SC-PROVENANCE-INVALID (CRITICAL)"), check.indicators)

    def test_what_is_not_checked(self):
        data = b"another tarball"
        later = TP.npm_manifest("4.0.1", attested=False, data=data)
        manifests = [TP.npm_manifest(v) for v in TP.TARBALLS] + [later]
        cases = {"published more than PROVENANCE_DAYS ago": dict(published=days_ago(guard.PROVENANCE_DAYS + 1)),
                 "from another registry (its packages are not named to npm's)": dict(registry="https://npm.example/"),
                 "a verdict from the cache": dict(cache={guard.VerdictCache.key("npm", "sigstore", "4.0.1",
                                                                                f"sha512-{sri(data)[7:]}"):
                                                         {"verdict": "OK", "reason": "", "indicators": []}})}
        for why, kw in cases.items():
            with self.subTest(why):
                check, fetcher, _ = self.check("4.0.1", data, manifests, **kw)
                self.assertEqual(check.verdict, "OK")
                self.assertIsNone(check.provenance)
                self.assertFalse([u for u in fetcher.asked if "/-/npm/v1/" in u or u == NPM + "sigstore"], fetcher.asked)
        with mock.patch.dict(os.environ, {provenance.OFF_ENV: "1"}):
            check, fetcher, _ = self.check("4.0.1", data, manifests)
        self.assertEqual((check.verdict, check.provenance), ("OK", None))
        # (a publish time not known is checked: the release may be new)
        self.assertTrue(guard.provenance_due(None))

    def test_a_document_that_cannot_be_read_flags_nothing(self):
        data = b"another tarball"
        check, fetcher, _ = self.check("4.0.1", data, [])                 # (the document lists no 4.0.1)
        self.assertEqual(check.verdict, "OK")
        self.assertEqual(check.provenance["files"], [{"filename": None, "status": "unchecked"}])
        report = provenance.guard_npm("sigstore", "4.0.1", "00" * 64, TP.Served({}))
        self.assertIn("could not be read", report["files"][0]["unchecked"])


def pypi_answers(*entries):
    out = {TP.SIMPLE: TP.simple(*entries),
           f"https://pypi.org/integrity/pypi-attestations/0.0.30/{TP.WHEEL_NAME}/provenance": TP.PEP740}
    return out


@unittest.skipUnless(TP.checks(), "no native library with the provenance check")
@mock.patch.dict(os.environ, TP.ON)
class PyPITests(unittest.TestCase):
    LATER = "pypi_attestations-0.0.31-py3-none-any.whl"

    def entries(self, published):
        def when(t):
            return t.strftime("%Y-%m-%dT%H:%M:%SZ")
        return [TP.simple_file("0.0.30", TP.WHEEL_NAME, TP.WHEEL, when(published - datetime.timedelta(days=5))),
                TP.simple_file("0.0.31", self.LATER, b"x", when(published), provenance_url=False)]

    def lockfile_check(self, version, filename, data, published):
        entries = self.entries(published)
        fetcher = _FakeFetcher({}, {**pypi_answers(*entries), f"https://files.pythonhosted.org/packages/{filename}": data})
        ctx = context(tool="uv")
        ctx.scanner.close()
        ctx.scanner = OkScanner()
        f = {"url": f"https://files.pythonhosted.org/packages/{filename}",
             "hash": "sha256:" + hashlib.sha256(data).hexdigest(), "filename": filename,
             "upload-time": published.isoformat()}
        return guard.check_file(ctx, fetcher, "pypi-attestations", version, f)

    def test_a_wheel_from_a_lockfile(self):
        check = self.lockfile_check("0.0.30", TP.WHEEL_NAME, TP.WHEEL, days_ago(5))
        self.assertEqual(check.verdict, "OK")
        self.assertEqual(check.provenance["repository"], "https://github.com/pypi/pypi-attestations")
        check = self.lockfile_check("0.0.31", self.LATER, b"x", days_ago(5))
        self.assertEqual(check.verdict, "WARN")
        self.assertIn("0.0.31 has no provenance, though 0.0.30, the release before it, has", check.reason)
        check = self.lockfile_check("0.0.31", self.LATER, b"x", days_ago(guard.PROVENANCE_DAYS + 1))
        self.assertEqual((check.verdict, check.provenance), ("OK", None))

    def test_a_file_the_local_index_serves(self):
        published = days_ago(5)
        upstream = "https://pypi.org/simple/"
        entries = self.entries(published)
        fetcher = _FakeFetcher({upstream + "pypi-attestations/": json.loads(TP.simple(*entries))},
                               {**pypi_answers(*entries), entries[1]["url"]: b"x", entries[0]["url"]: TP.WHEEL})
        spool = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, spool)
        ctx = context(tool="pip", min_age=0)
        ctx.scanner.close()
        ctx.scanner = OkScanner()
        index = guard.PypiIndex(ctx, fetcher, spool, upstream)
        index.page("pypi-attestations")
        numbers = {i["filename"]: n for n, i in index.files.items()}
        check, spooled = index.scan(numbers[self.LATER])
        self.assertEqual((check.verdict, check.blocked), ("WARN", []))
        self.assertIsNotNone(spooled)
        check, _ = index.scan(numbers[TP.WHEEL_NAME])
        self.assertEqual(check.verdict, "OK")
        self.assertEqual(check.provenance["files"], [{"filename": TP.WHEEL_NAME, "status": "verified"}])


class MergeTests(unittest.TestCase):
    """with_provenance on reports made here (no native library needed)."""

    def report(self, outcome=None, previous=True):
        files = [{"filename": None, "attestations": None if outcome is None else [
            {"predicateType": "https://slsa.dev/provenance/v1", "outcome": outcome, "reason": "no subject", "signer": None,
             "time": 1}]}]
        return {"files": files, "previous": {"version": "1.0.0", "provenance": previous}}

    def test_the_verdict_moves_up_only(self):
        ok = {"verdict": "OK", "reason": "fine", "indicators": []}
        bad = {"verdict": "SUSPICIOUS", "reason": "1 strong supply-chain indicator", "indicators": ["SC-X (CRITICAL) a.js: x"]}
        for hit, report, want in ((ok, self.report(), "WARN"), (ok, self.report("invalid"), "SUSPICIOUS"),
                                  (bad, self.report(), "SUSPICIOUS"), (ok, self.report(previous=False), "OK"),
                                  ({**ok, "verdict": "INCOMPLETE"}, self.report(), "INCOMPLETE")):
            with self.subTest(hit=hit["verdict"], report=report):
                check = guard.Check("npm", "x", "1.1.0")
                got = guard.with_provenance(check, hit, "npm", report)
                self.assertEqual(got["verdict"], want)
                self.assertIsNotNone(check.provenance)
        got = guard.with_provenance(guard.Check("npm", "x", "1.1.0"), bad, "npm", self.report())
        self.assertEqual(got["reason"], bad["reason"])
        self.assertEqual(got["indicators"][1:], bad["indicators"])
        self.assertTrue(got["indicators"][0].startswith("SC-PROVENANCE-DROPPED (MAJOR)"))


if __name__ == "__main__":
    unittest.main()
