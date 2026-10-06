"""`registry/provenance.py` (0.1.9, NET-1's fifth item): npm's and PyPI's provenance as findings, on real attestations.

The data is tiny_https's capture of the real registries (rust/crates/tiny_https/tests/data/sigstore/README.txt, fetched
Oct 5, 2026; the artifacts are Apache-2.0): the npm package sigstore 0.2.0, 2.2.0 and 4.0.0 with their attestations
(npm's publish attestation and SLSA provenance from sigstore/sigstore-js's workflow), and PyPI's PEP 740 provenance of
the wheel pypi-attestations 0.0.30 with the wheel. The registries' other documents (npm's abbreviated packument, PyPI's
Simple API JSON) are built here in their shapes, with the real digests. The check is the native library's
(`verify.sigstore`); without it these tests skip. Nothing here opens a socket."""

import base64
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from lazaret.registry import provenance, repo
from lazaret.registry.ecosystems import base
from lazaret.scanner import _native
from tests import _support
from tests.registry._review_support import tarball

DATA = os.path.join(_support.REPO_ROOT, "rust", "crates", "tiny_https", "tests", "data", "sigstore")
NPM = "https://registry.npmjs.org/"
ATTESTATIONS = NPM + "-/npm/v1/attestations/"
SIGSTORE_JS = "https://github.com/sigstore/sigstore-js"
WHEEL_NAME = "pypi_attestations-0.0.30-py3-none-any.whl"
SIMPLE = "https://pypi.org/simple/pypi-attestations/"
ON = {provenance.OFF_ENV: ""}                      # (tests/__init__.py turns the check off for every other test)


def captured(name, text=False):
    with open(os.path.join(DATA, name), "rb") as fh:
        data = fh.read()
    return data.decode("utf-8") if text else data


TARBALLS = {v: captured(f"sigstore-{v}.tgz") for v in ("0.2.0", "2.2.0", "4.0.0")}
NPM_DOCS = {v: captured(f"sigstore-{v}.attestations.json") for v in TARBALLS}
WHEEL = captured(WHEEL_NAME)
PEP740 = captured(WHEEL_NAME + ".provenance.json")


def sha512_hex(data):
    return hashlib.sha512(data).hexdigest()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def npm_manifest(version, attested=True, data=None):
    data = TARBALLS.get(version, b"") if data is None else data
    dist = {"tarball": f"{NPM}sigstore/-/sigstore-{version}.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}
    if attested:
        dist["attestations"] = {"url": f"{ATTESTATIONS}sigstore@{version}",
                                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}
    return {"name": "sigstore", "version": version, "dist": dist}


def packument(*manifests):
    return json.dumps({"name": "sigstore", "versions": {m["version"]: m for m in manifests}}).encode()


class Served:
    """The fetch the check is given, over these answers (a missing URL is a 404), remembering what it was asked."""

    def __init__(self, answers):
        self.answers, self.asked = answers, []

    def __call__(self, url, max_bytes, accept):
        self.asked.append((url, accept))
        body = self.answers.get(url)
        if body is None:
            err = base.FetchError(f"HTTP 404 for {url}")
            err.status = 404
            raise err
        if len(body) > max_bytes:
            raise base.FetchError("over the budget")
        return body


def npm_answers(*manifests):
    out = {NPM + "sigstore": packument(*manifests)}
    out.update({f"{ATTESTATIONS}sigstore@{v}": doc for v, doc in NPM_DOCS.items()})
    return out


def checks():
    if not _native.available():
        return False
    try:
        _native.call("verify.sigstore", {})
    except _native.NativeError as exc:
        return "unknown call" not in str(exc)
    return True


def rules(issues):
    return [(i["rule"], i["sev"]) for i in issues]


@unittest.skipUnless(checks(), f"no native library with the provenance check ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
class NpmTests(unittest.TestCase):
    def check(self, version, data, answers, manifest=None):
        manifest = manifest or npm_manifest(version)
        resolved = (version, manifest["dist"]["tarball"], "tgz", "npm", manifest)
        served = Served(answers)
        issues, summary = provenance.check_release("npm", "sigstore", version, resolved, [(None, sha512_hex(data))], served)
        return issues, summary, served

    def test_a_release_built_by_its_ci_like_the_one_before(self):
        issues, summary, served = self.check("4.0.0", TARBALLS["4.0.0"], npm_answers(*(npm_manifest(v) for v in TARBALLS)))
        self.assertEqual(issues, [])
        self.assertEqual(summary["repository"], SIGSTORE_JS)
        self.assertEqual(summary["files"], [{"filename": None, "status": "verified"}])
        self.assertEqual(summary["previous"]["version"], "2.2.0")
        self.assertEqual(summary["previous"]["repository"]["uri"], SIGSTORE_JS)
        self.assertEqual(summary["previous"]["repository"]["id"], "495574555")
        kinds = sorted(v["signer"]["kind"] for v in summary["verified"])
        self.assertEqual(kinds, ["certificate", "key"])                           # (npm's own attestation, and SLSA's)
        self.assertEqual(provenance.line(summary), f"Provenance: built from {SIGSTORE_JS} "
                         f"({SIGSTORE_JS}/.github/workflows/release.yml@refs/heads/main), verified")
        self.assertIn((NPM + "sigstore", provenance.NPM_ABBREVIATED), served.asked)

    def test_a_release_without_the_provenance_the_one_before_had(self):
        later = npm_manifest("4.0.1", attested=False, data=b"another tarball")
        issues, summary, served = self.check("4.0.1", b"another tarball",
                                             npm_answers(*(npm_manifest(v) for v in TARBALLS), later), manifest=later)
        self.assertEqual(rules(issues), [("SC-PROVENANCE-DROPPED", "MAJOR")])
        self.assertIn("though 4.0.0, the release before it, has", issues[0]["msg"])
        self.assertEqual(summary["files"], [{"filename": None, "status": "none"}])
        self.assertEqual(provenance.line(summary), "Provenance: none, though 4.0.0 (the release before) has it")
        self.assertNotIn(f"{ATTESTATIONS}sigstore@4.0.1", [u for u, _ in served.asked])

    def test_a_first_release_with_none_and_one_after_a_release_with_none_are_not_findings(self):
        for before in ([], [npm_manifest("4.0.0", attested=False)]):
            with self.subTest(before=len(before)):
                later = npm_manifest("4.0.1", attested=False, data=b"x")
                issues, summary, _ = self.check("4.0.1", b"x", npm_answers(*before, later), manifest=later)
                self.assertEqual(issues, [])

    def test_a_tarball_the_attestations_are_not_about(self):
        issues, summary, _ = self.check("4.0.0", b"another tarball", npm_answers(*(npm_manifest(v) for v in TARBALLS)))
        self.assertEqual(rules(issues), [("SC-PROVENANCE-INVALID", "CRITICAL")] * 2)
        self.assertIn("no subject", issues[0]["msg"])
        self.assertEqual(summary["files"], [{"filename": None, "status": "invalid"}])
        self.assertNotIn("repository", summary)

    def test_what_could_not_be_checked_is_said_and_flags_nothing(self):
        answers = npm_answers(*(npm_manifest(v) for v in TARBALLS))
        del answers[f"{ATTESTATIONS}sigstore@4.0.0"]                             # (the registry did not answer)
        issues, summary, _ = self.check("4.0.0", TARBALLS["4.0.0"], answers)
        self.assertEqual(rules(issues), [("SC-PROVENANCE-UNCHECKED", "INFO")])
        self.assertEqual(summary["files"][0]["status"], "unchecked")
        # the packument unreachable: the release before is not known, and nothing is flagged
        later = npm_manifest("4.0.1", attested=False, data=b"x")
        issues, summary, _ = self.check("4.0.1", b"x", {}, manifest=later)
        self.assertEqual(issues, [])
        self.assertIn("404", summary["previousUnchecked"])

    def test_npm_keys_that_do_not_know_the_registrys_key(self):
        with tempfile.TemporaryDirectory() as folder:
            keys = os.path.join(folder, "keys.json")
            with open(keys, "w", encoding="utf-8") as fh:
                fh.write('{"keys": []}')
            with mock.patch.dict(os.environ, {provenance.NPM_KEYS_ENV: keys}):
                issues, summary, _ = self.check("4.0.0", TARBALLS["4.0.0"], npm_answers(*(npm_manifest(v) for v in TARBALLS)))
        self.assertEqual(rules(issues), [("SC-PROVENANCE-UNCHECKED", "INFO")])
        self.assertIn("no trusted key", issues[0]["msg"])
        self.assertEqual(summary["repository"], SIGSTORE_JS)                    # (the SLSA provenance still verified)

    def test_the_release_before_is_the_highest_lower_version(self):
        versions = {v: {} for v in ("1.0.0", "1.2.0", "2.0.0-rc.1", "2.0.0", "1.10.0", "not-semver", "3.0.0-beta.1")}
        self.assertEqual(provenance.npm_previous(versions, "2.0.0"), "1.10.0")
        self.assertEqual(provenance.npm_previous(versions, "2.0.1"), "2.0.0")
        self.assertEqual(provenance.npm_previous(versions, "3.0.0-beta.2"), "3.0.0-beta.1")
        self.assertEqual(provenance.npm_previous(versions, "1.0.0"), None)
        self.assertEqual(provenance.npm_previous(versions, "garbage"), None)

    def test_the_scan_says_it(self):
        manifest = npm_manifest("4.0.0")
        resolved = ("4.0.0", manifest["dist"]["tarball"], "tgz", "npm", manifest)
        served = Served(npm_answers(*(npm_manifest(v) for v in TARBALLS)))
        with mock.patch.object(repo, "http_bytes", return_value=TARBALLS["4.0.0"]), \
                mock.patch.object(repo, "_provenance_fetch", served):
            res = repo.scan_package("npm", "sigstore", "4.0.0", resolved=resolved)
        self.assertEqual(res["provenance"]["repository"], SIGSTORE_JS)
        self.assertFalse([i for i in res["issues"] if i["rule"].startswith("SC-PROVENANCE")])
        # a tarball the registry's document vouches for and the attestations do not
        other = tarball({"package.json": json.dumps({"name": "sigstore", "version": "4.0.0"}), "index.js": "module.exports = 1;\n"})
        manifest = npm_manifest("4.0.0", data=other)
        resolved = ("4.0.0", manifest["dist"]["tarball"], "tgz", "npm", manifest)
        with mock.patch.object(repo, "http_bytes", return_value=other), mock.patch.object(repo, "_provenance_fetch", served):
            res = repo.scan_package("npm", "sigstore", "4.0.0", resolved=resolved)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual([i["rule"] for i in res["issues"] if i["rule"].startswith("SC-PROVENANCE")], ["SC-PROVENANCE-INVALID"] * 2)
        # and off
        with mock.patch.dict(os.environ, {provenance.OFF_ENV: "1"}), mock.patch.object(repo, "http_bytes", return_value=other), \
                mock.patch.object(repo, "_provenance_fetch", side_effect=AssertionError("no request")):
            res = repo.scan_package("npm", "sigstore", "4.0.0", resolved=resolved)
        self.assertNotIn("provenance", res)


def simple(*files, versions=None):
    listed = versions or sorted({f["v"] for f in files})
    return json.dumps({"meta": {"api-version": "1.4"}, "name": "pypi-attestations", "versions": listed,
                       "files": [{k: v for k, v in f.items() if k != "v"} for f in files]}).encode()


def simple_file(version, filename, data, when, provenance_url=True, yanked=False):
    out = {"v": version, "filename": filename, "url": f"https://files.pythonhosted.org/packages/{filename}",
           "hashes": {"sha256": sha256_hex(data)}, "upload-time": when, "yanked": yanked}
    if provenance_url:
        out["provenance"] = f"https://pypi.org/integrity/pypi-attestations/{version}/{filename}/provenance"
    return out


@unittest.skipUnless(checks(), f"no native library with the provenance check ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
class PyPITests(unittest.TestCase):
    def check(self, version, files, answers):
        served = Served(answers)
        issues, summary = provenance.check_release("pypi", "pypi-attestations", version, None,
                                                   [(name, sha256_hex(data)) for name, data in files], served)
        return issues, summary, served

    def answers(self, *entries):
        out = {SIMPLE: simple(*entries)}
        out[f"https://pypi.org/integrity/pypi-attestations/0.0.30/{WHEEL_NAME}/provenance"] = PEP740
        return out

    def test_a_wheel_built_by_its_ci_like_the_one_before(self):
        # (the release before is listed with the same wheel's digest and provenance: its check is a real one)
        before = simple_file("0.0.29", "pypi_attestations-0.0.29-py3-none-any.whl", WHEEL, "2025-12-11T13:24:20Z")
        answers = self.answers(before, simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z"))
        answers[before["provenance"]] = PEP740
        issues, summary, served = self.check("0.0.30", [(WHEEL_NAME, WHEEL)], answers)
        self.assertEqual(issues, [])
        self.assertEqual(summary["repository"], "https://github.com/pypi/pypi-attestations")
        self.assertEqual(summary["files"], [{"filename": WHEEL_NAME, "status": "verified"}])
        self.assertEqual(summary["previous"]["version"], "0.0.29")
        self.assertEqual(summary["previous"]["repository"], {"uri": "https://github.com/pypi/pypi-attestations", "id": "772247423",
                                                             "owner": "https://github.com/pypi", "ownerId": "2964877"})
        self.assertIn((SIMPLE, provenance.PYPI_SIMPLE_JSON), served.asked)

    def test_a_release_without_the_provenance_the_one_before_had(self):
        later = "pypi_attestations-0.0.31-py3-none-any.whl"
        answers = self.answers(simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z"),
                               simple_file("0.0.31", later, b"x", "2026-08-01T00:00:00Z", provenance_url=False))
        issues, summary, _ = self.check("0.0.31", [(later, b"x")], answers)
        self.assertEqual(rules(issues), [("SC-PROVENANCE-DROPPED", "MAJOR")])
        self.assertIn("though 0.0.30, the release before it, has", issues[0]["msg"])

    def test_a_yanked_release_before_and_a_prerelease_do_not_count(self):
        later = "pypi_attestations-0.0.31-py3-none-any.whl"
        answers = self.answers(simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z", yanked=True),
                               simple_file("0.0.31rc1", "pypi_attestations-0.0.31rc1-py3-none-any.whl", WHEEL,
                                           "2026-07-30T00:00:00Z"),
                               simple_file("0.0.31", later, b"x", "2026-08-01T00:00:00Z", provenance_url=False),
                               simple_file("0.0.29", "pypi_attestations-0.0.29.tar.gz", b"y", "2025-12-11T13:24:21Z",
                                           provenance_url=False))
        issues, summary, _ = self.check("0.0.31", [(later, b"x")], answers)
        self.assertEqual(issues, [])
        self.assertEqual(summary["previous"], {"version": "0.0.29", "provenance": False})

    def test_a_wheel_the_attestation_is_not_about(self):
        answers = self.answers(simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z"))
        issues, summary, _ = self.check("0.0.30", [(WHEEL_NAME, b"another wheel")], answers)
        self.assertEqual(rules(issues), [("SC-PROVENANCE-INVALID", "CRITICAL")])
        self.assertEqual(issues[0]["file"], WHEEL_NAME)

    def test_a_trust_that_does_not_know_the_log(self):
        root = json.loads(captured("trusted_root.json", text=True))
        root["tlogs"] = [t for t in root.get("tlogs", ()) if "rekor.sigstore.dev" not in json.dumps(t)]
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "root.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(root, fh)
            with mock.patch.dict(os.environ, {provenance.ROOT_ENV: path}):
                answers = self.answers(simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z"))
                issues, summary, _ = self.check("0.0.30", [(WHEEL_NAME, WHEEL)], answers)
        self.assertEqual([r for r, _ in rules(issues)], ["SC-PROVENANCE-UNCHECKED"])     # (not INVALID: the trust is older)

    def test_the_simple_api_unreachable(self):
        issues, summary, _ = self.check("0.0.30", [(WHEEL_NAME, WHEEL)], {})
        self.assertEqual(issues, [])
        self.assertIn("404", summary["unchecked"])

    def test_files_the_simple_api_does_not_list_say_nothing_of_a_drop(self):
        later = "pypi_attestations-0.0.31-py3-none-any.whl"
        answers = self.answers(simple_file("0.0.30", WHEEL_NAME, WHEEL, "2026-07-28T14:08:30Z"),
                               simple_file("0.0.31", later, b"x", "2026-08-01T00:00:00Z", provenance_url=False))
        issues, summary, _ = self.check("0.0.31", [("pypi_attestations-0.0.31.tar.gz", b"x")], answers)
        self.assertEqual(issues, [])
        self.assertEqual(summary["unchecked"], "the release's files are not in the Simple API's answer")


def repo_of(uri, rid=None, owner_id=None):
    return {"uri": uri, "id": rid, "owner": uri.rsplit("/", 1)[0], "ownerId": owner_id}


class FindingTests(unittest.TestCase):
    """`release_issues`, `same_repository` and `same_owner` on reports made here (no native library needed)."""

    @staticmethod
    def verified(uri, rid, owner_id):
        return {"predicateType": "https://slsa.dev/provenance/v1", "outcome": "verified", "time": 1,
                "signer": {"kind": "certificate", "repository": uri, "repositoryId": rid, "owner": uri.rsplit("/", 1)[0],
                           "ownerId": owner_id, "workflow": None}}

    def report(self, here, there):
        return {"files": [{"filename": None, "attestations": [self.verified(*here)]}],
                "previous": {"version": "1.0.0", "provenance": True, "repository": repo_of(*there)}}

    def test_another_owners_repository(self):
        issues, summary = provenance.release_issues("npm", "x", "1.1.0", self.report(("https://github.com/evil/x", "2", "20"),
                                                                                     ("https://github.com/acme/x", "1", "10")))
        self.assertEqual(rules(issues), [("SC-PROVENANCE-REPO-CHANGED", "MAJOR")])
        self.assertIn("https://github.com/evil/x", issues[0]["msg"])
        self.assertIn("https://github.com/acme/x", issues[0]["msg"])
        self.assertIn("another owner's", issues[0]["msg"])

    def test_another_repository_of_the_same_owner_is_said_and_does_not_count(self):
        # (seen on the popular set: scikit-learn 1.9.1 from scikit-learn/scikit-learn-release, @rolldown/pluginutils 1.0.1
        # from rolldown/plugins after rolldown/rolldown)
        issues, _ = provenance.release_issues("pypi", "x", "1.1.0", self.report(("https://github.com/acme/x-release", "2", "10"),
                                                                                ("https://github.com/acme/x", "1", "10")))
        self.assertEqual(rules(issues), [("SC-PROVENANCE-REPO-CHANGED", "INFO")])
        self.assertIn("a repository of the same owner", issues[0]["msg"])

    def test_a_renamed_repository_keeps_its_id(self):
        issues, _ = provenance.release_issues("npm", "x", "1.1.0", self.report(("https://github.com/acme-org/x", "1", "11"),
                                                                               ("https://github.com/acme/x", "1", "10")))
        self.assertEqual(issues, [])

    def test_without_ids_the_uri(self):
        same, owner = provenance.same_repository, provenance.same_owner
        self.assertTrue(same(repo_of("https://github.com/Acme/X.git"), repo_of("https://github.com/acme/x/", "7")))
        self.assertFalse(same(repo_of("https://github.com/acme/y"), repo_of("https://github.com/acme/x")))
        self.assertFalse(same(repo_of("https://github.com/acme/x", "1"), repo_of("https://github.com/acme/x", "2")))
        self.assertTrue(owner(repo_of("https://github.com/acme/y"), repo_of("https://github.com/Acme/x")))
        self.assertFalse(owner(repo_of("https://github.com/evil/x"), repo_of("https://github.com/acme/x")))
        self.assertFalse(owner(repo_of("https://github.com/acme/x", None, "1"), repo_of("https://github.com/acme/y", None, "2")))

    def test_messages_are_short_and_printable(self):
        hostile = {"files": [{"filename": "\x1b[31mevil", "attestations": [
            {"predicateType": "\x1b[0m" * 300, "outcome": "invalid", "reason": "‮" * 500}]}], "previous": None}
        issues, _ = provenance.release_issues("pypi", "x", "1.0", hostile)
        for i in issues:
            self.assertTrue(i["msg"].isprintable() and len(i["msg"]) < 600, i["msg"])


class TrustTests(unittest.TestCase):
    def test_the_shipped_trust_is_the_recorded_copy(self):
        self.assertEqual(provenance.shipped_files_intact(), [])
        for ours, theirs in (("trusted_root.json", "trusted_root.json"), ("npm_keys.json", "npm-registry-keys.json")):
            with open(os.path.join(provenance.HERE, ours), "rb") as a, open(os.path.join(DATA, theirs), "rb") as b:
                self.assertEqual(a.read(), b.read(), ours)

    def test_off_by_default_in_the_tests_and_on_otherwise(self):
        self.assertFalse(provenance.enabled())                    # (tests/__init__.py)
        with mock.patch.dict(os.environ, ON):
            self.assertTrue(provenance.enabled())

    def test_other_registries_and_nothing_scanned(self):
        with mock.patch.dict(os.environ, ON):
            for eco in ("go", "crates", "openvsx", "vscode"):
                self.assertEqual(provenance.check_release(eco, "x", "1.0.0", None, [("x", "00")], None), ([], None))
            self.assertEqual(provenance.check_release("npm", "x", "1.0.0", None, [], None), ([], None))


if __name__ == "__main__":
    unittest.main()
