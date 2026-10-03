"""SC-NEW-DEPENDENCY (0.1.8): a release that adds a dependency first published
days before it, by someone who does not maintain the package — the @mastra
compromise, where each hijacked release gained easy-day-js 19 hours after it
was created and changed no code.

The registry's documents are fakes served by URL; nothing reaches the
network. Package names are made up.
"""
import datetime
import json
import os
import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import tarball

UTC = datetime.timezone.utc
RELEASE = datetime.datetime(2026, 6, 17, 2, 6, 22, tzinfo=UTC)


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def packument(name, versions, maintainers=("owner",), created=None):
    """{version: (published, dependencies)} -> a full npm registry document."""
    times = {v: iso(t) for v, (t, _deps) in versions.items()}
    times["created"] = iso(created or min(t for t, _deps in versions.values()))
    return {"name": name, "time": times, "maintainers": [{"name": m} for m in maintainers],
            "versions": {v: {"name": name, "version": v, "dependencies": deps} for v, (_t, deps) in versions.items()}}


class Registry:
    """http_json serving documents by URL; a URL it doesn't know is a 404."""

    def __init__(self, docs):
        self.docs, self.fetched = docs, []

    def __call__(self, url, accept=None):
        self.fetched.append(url)
        if url not in self.docs:
            err = repo.FetchError(f"HTTP 404 fetching {url}")
            err.status = 404
            raise err
        doc = self.docs[url]
        if isinstance(doc, Exception):
            raise doc
        return doc


NPM = "https://registry.npmjs.org/"


def npm(name):
    """The URL of a package's registry document (a scoped name keeps its @ and encodes the /)."""
    return NPM + urllib.parse.quote(name, safe="@")
OLD = RELEASE - datetime.timedelta(days=22)


def parent(extra_versions=None):
    versions = {"0.2.0": (OLD, {"files-kit": "^1.5.0"}),
                "0.0.0-snapshot-20260616": (RELEASE - datetime.timedelta(hours=2), {"files-kit": "^1.5.0",
                                                                                     "fresh-lib": "^1"}),
                "0.2.1": (RELEASE, {"files-kit": "^1.5.0", "easy-day-kit": "^1.11.21"})}
    versions.update(extra_versions or {})
    return packument("@acme/files", versions, maintainers=("alice", "bob"))


def dep(name, age, maintainers=("mallory",)):
    created = RELEASE - age
    return packument(name, {"1.0.0": (created, {})}, maintainers=maintainers, created=created)


class NpmTests(unittest.TestCase):
    def check(self, docs, manifest=None, name="@acme/files", version="0.2.1"):
        reg = Registry(docs)
        manifest = manifest or parent()["versions"][version]
        prev, found = repo.npm_new_dependencies(name, version, manifest, fetch=reg)
        return prev, [(d, a, o) for d, a, o in found], reg

    def test_a_dependency_published_hours_before_the_release(self):
        prev, found, _ = self.check({npm("@acme/files"): parent(),
                                     NPM + "easy-day-kit": dep("easy-day-kit", datetime.timedelta(hours=19))})
        self.assertEqual(prev, "0.2.0")                        # not the snapshot published in between
        self.assertEqual([(d, a, o) for d, a, o in found], [("easy-day-kit", datetime.timedelta(hours=19), ["mallory"])])
        issue = repo._new_dependency_issue("npm", *found[0][:2], prev, found[0][2])
        self.assertEqual((issue["rule"], issue["sev"], issue["file"]), ("SC-NEW-DEPENDENCY", "CRITICAL", "package.json"))
        self.assertEqual(issue["msg"], 'Adds a dependency on "easy-day-kit", which 0.2.0 did not have: a package first '
                                       "published 19 hours before this release by mallory, who does not maintain this one.")

    def test_weeks_old_is_major_and_months_old_is_nothing(self):
        for age, sev in ((datetime.timedelta(days=10), "MAJOR"), (datetime.timedelta(days=45), None)):
            with self.subTest(age=age):
                prev, found, _ = self.check({npm("@acme/files"): parent(), NPM + "easy-day-kit": dep("easy-day-kit", age)})
                issues = [repo._new_dependency_issue("npm", d, a, prev, o) for d, a, o in found]
                self.assertEqual([i["sev"] for i in issues], [sev] if sev else [])

    def test_what_does_not_count(self):
        young = datetime.timedelta(hours=5)
        cases = {
            "the package's own scope": ({"files-kit": "^1.5.0", "@acme/helpers": "^1"}, npm("@acme/helpers"),
                                        dep("@acme/helpers", young)),
            "a maintainer of both": ({"files-kit": "^1.5.0", "side-kit": "^1"}, NPM + "side-kit",
                                     dep("side-kit", young, maintainers=("bob",))),
            "a git dependency": ({"files-kit": "^1.5.0", "g": "github:someone/g"}, NPM + "g", dep("g", young)),
            "a file dependency": ({"files-kit": "^1.5.0", "f": "file:../f"}, NPM + "f", dep("f", young)),
            "already a dependency": ({"files-kit": "^2.0.0"}, NPM + "files-kit", dep("files-kit", young)),
        }
        for label, (deps, url, doc) in cases.items():
            with self.subTest(label):
                _prev, found, reg = self.check({npm("@acme/files"): parent(), url: doc}, manifest={"dependencies": deps})
                self.assertEqual(found, [])

    def test_an_alias_names_the_package_it_installs(self):
        manifest = {"dependencies": {"files-kit": "^1.5.0", "dayjs": "npm:easy-day-kit@^1.11.21"}}
        _prev, found, _ = self.check({npm("@acme/files"): parent(),
                                      NPM + "easy-day-kit": dep("easy-day-kit", datetime.timedelta(hours=3))},
                                     manifest=manifest)
        self.assertEqual([d for d, _a, _o in found], ["easy-day-kit"])

    def test_a_release_with_no_dependencies_asks_nothing(self):
        prev, found, reg = self.check({}, manifest={"dependencies": {}})
        self.assertEqual((prev, found, reg.fetched), (None, [], []))

    def test_no_previous_release_and_unknown_time(self):
        first = packument("@acme/files", {"0.1.0": (RELEASE, {"x": "^1"})})
        self.assertEqual(self.check({npm("@acme/files"): first}, manifest={"dependencies": {"x": "^1"}},
                                    version="0.1.0")[:2], (None, []))
        doc = parent()
        del doc["time"]["0.2.1"]
        self.assertEqual(self.check({npm("@acme/files"): doc})[:2], (None, []))

    def test_a_dependency_that_cannot_be_looked_up_is_skipped(self):
        big = repo.FetchError("response exceeds 5MB budget")
        _prev, found, _ = self.check({npm("@acme/files"): parent(), NPM + "easy-day-kit": big})
        self.assertEqual(found, [])

    def test_at_most_five_lookups_that_count(self):
        deps = {"files-kit": "^1.5.0", **{f"n{k}": "^1" for k in range(8)}}
        docs = {npm("@acme/files"): parent(), **{NPM + f"n{k}": dep(f"n{k}", datetime.timedelta(hours=1))
                                                  for k in range(8)}}
        _prev, found, _ = self.check(docs, manifest={"dependencies": deps})
        self.assertEqual(len(found), repo.NEW_DEP_LOOKUPS)


PYPI = "https://pypi.org/pypi/"


def pypi_project(releases, roles=None, organization=None):
    """{version: first upload} -> the project's JSON document (release files
    only), with its "ownership" when `roles` ({user: role}) or an
    organization is given."""
    doc = {"info": {}, "releases": {v: [{"upload_time_iso_8601": iso(t)}] for v, t in releases.items()}}
    if roles is not None or organization is not None:
        doc["ownership"] = {"roles": [{"role": r, "user": u} for u, r in (roles or {}).items()],
                            "organization": organization}
    return doc


class PypiTests(unittest.TestCase):
    def test_a_requirement_published_a_day_before(self):
        docs = {PYPI + "acme/json": pypi_project({"1.0": OLD, "1.1rc1": RELEASE - datetime.timedelta(hours=3),
                                                  "1.1": RELEASE}),
                PYPI + "acme/1.0/json": {"info": {"requires_dist": ["requests>=2"]}},
                PYPI + "requesst/json": pypi_project({"0.1": RELEASE - datetime.timedelta(days=1)}),
                PYPI + "pytest-mock/json": pypi_project({"0.1": RELEASE - datetime.timedelta(days=1)})}
        info = {"requires_dist": ["requests>=2", "Requesst (>=0.1)", "pytest-mock; extra == 'test'"]}
        prev, found = repo.pypi_new_dependencies("acme", "1.1", info, fetch=Registry(docs))
        self.assertEqual(prev, "1.0")                          # not the release candidate
        self.assertEqual(found, [("requesst", datetime.timedelta(days=1), [])])
        issue = repo._new_dependency_issue("pypi", *found[0][:2], prev, [])
        self.assertEqual((issue["sev"], issue["file"]), ("CRITICAL", "(release)"))
        self.assertTrue(issue["msg"].endswith("a package first published 24 hours before this release."), issue["msg"])

    def test_the_projects_own_owners_and_organization(self):
        """(the detection round) the JSON API's "ownership": a requirement an
        owner or maintainer of the project also owns or maintains, or its
        organization owns, does not count; another account's does, named."""
        day = datetime.timedelta(days=1)
        project = pypi_project({"1.0": OLD, "1.1": RELEASE}, roles={"alice": "Owner", "ci-bot": "Maintainer"},
                               organization="acme-org")
        docs = {PYPI + "acme/json": project, PYPI + "acme/1.0/json": {"info": {"requires_dist": []}},
                PYPI + "acme-core/json": pypi_project({"0.1": RELEASE - day}, roles={"alice": "Owner"}),
                PYPI + "acme-bot/json": pypi_project({"0.1": RELEASE - day}, roles={"ci-bot": "Maintainer"}),
                PYPI + "acme-org-lib/json": pypi_project({"0.1": RELEASE - day}, roles={"carol": "Owner"},
                                                         organization="acme-org"),
                PYPI + "easy-day/json": pypi_project({"0.1": RELEASE - day}, roles={"mallory": "Owner", "eve": "Maintainer"},
                                                     organization="other-org"),
                PYPI + "no-ownership/json": pypi_project({"0.1": RELEASE - day})}
        info = {"requires_dist": ["acme-core", "acme-bot", "acme-org-lib", "easy-day", "no-ownership"]}
        prev, found = repo.pypi_new_dependencies("acme", "1.1", info, fetch=Registry(docs))
        self.assertEqual(found, [("easy-day", day, ["eve", "mallory"]), ("no-ownership", day, [])])
        msgs = [repo._new_dependency_issue("pypi", d, a, prev, o)["msg"] for d, a, o in found]
        self.assertTrue(msgs[0].endswith("24 hours before this release by eve, mallory, who does not maintain this one."),
                        msgs[0])
        self.assertTrue(msgs[1].endswith("24 hours before this release."), msgs[1])
        # a project document without "ownership" (a mirror): every account counts, as before
        docs[PYPI + "acme/json"] = pypi_project({"1.0": OLD, "1.1": RELEASE})
        prev, found = repo.pypi_new_dependencies("acme", "1.1", info, fetch=Registry(docs))
        self.assertEqual([d for d, _a, _o in found], ["acme-bot", "acme-core", "acme-org-lib", "easy-day", "no-ownership"])

    def test_no_requirements_asks_nothing(self):
        reg = Registry({})
        self.assertEqual(repo.pypi_new_dependencies("acme", "1.1", {"requires_dist": None}, fetch=reg), (None, []))
        self.assertEqual(reg.fetched, [])


class ScanPackageTests(unittest.TestCase):
    def test_the_release_is_suspicious_and_the_check_can_be_turned_off(self):
        manifest = parent()["versions"]["0.2.1"]
        data = tarball({"package.json": '{"name": "@acme/files", "version": "0.2.1"}', "index.js": "module.exports = 1;\n"})
        rv = ("0.2.1", "https://registry.npmjs.org/@acme/files/-/files-0.2.1.tgz", "tgz", "npm", manifest)
        reg = Registry({npm("@acme/files"): parent(),
                        NPM + "easy-day-kit": dep("easy-day-kit", datetime.timedelta(hours=19))})
        for off in (False, True):
            env = {"LAZARET_NO_DEPENDENCY_HISTORY": "1"} if off else {}
            with self.subTest(off=off), mock.patch.dict(os.environ, env), \
                    mock.patch.object(repo, "http_json", side_effect=reg), \
                    mock.patch.object(repo, "http_bytes", return_value=data), \
                    mock.patch.object(repo, "verify_digest", return_value=None):
                res = repo.scan_package("npm", "@acme/files", "0.2.1", resolved=rv)
            rules = [i["rule"] for i in res["issues"]]
            self.assertEqual((res["verdict"], "SC-NEW-DEPENDENCY" in rules), ("OK", False) if off else ("SUSPICIOUS", True))

    def test_one_no_file_names_is_critical(self):
        """A dependency 7 to 30 days old is MAJOR, and CRITICAL when no file
        of the release names it (SC-UNUSED-DEPENDENCY)."""
        manifest = parent()["versions"]["0.2.1"]
        rv = ("0.2.1", "https://registry.npmjs.org/@acme/files/-/files-0.2.1.tgz", "tgz", "npm", manifest)
        pj = json.dumps({"name": "@acme/files", "version": "0.2.1", "dependencies": manifest["dependencies"]})
        reg = Registry({npm("@acme/files"): parent(),
                        NPM + "easy-day-kit": dep("easy-day-kit", datetime.timedelta(days=10))})
        for code, want in (("module.exports = require('files-kit');\n", (
                "CRITICAL", 'Adds a dependency on "easy-day-kit", which 0.2.0 did not have and no file of this release '
                            "names: a package first published 10 days before this release by mallory, who does not "
                            "maintain this one.")),
                           ("require('files-kit');\nrequire('easy-day-kit');\n", (
                "MAJOR", 'Adds a dependency on "easy-day-kit", which 0.2.0 did not have: a package first published '
                         "10 days before this release by mallory, who does not maintain this one."))):
            data = tarball({"package.json": pj, "index.js": code})
            with self.subTest(code=code), mock.patch.object(repo, "http_json", side_effect=reg), \
                    mock.patch.object(repo, "http_bytes", return_value=data), \
                    mock.patch.object(repo, "verify_digest", return_value=None):
                res = repo.scan_package("npm", "@acme/files", "0.2.1", resolved=rv)
                self.assertEqual([(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-NEW-DEPENDENCY"],
                                 [want])

    def test_an_unreachable_registry_is_not_a_finding(self):
        manifest = parent()["versions"]["0.2.1"]
        data = tarball({"package.json": '{"name": "@acme/files", "version": "0.2.1"}'})
        rv = ("0.2.1", "https://registry.npmjs.org/@acme/files/-/files-0.2.1.tgz", "tgz", "npm", manifest)
        with mock.patch.object(repo, "http_json", side_effect=Registry({})), \
                mock.patch.object(repo, "http_bytes", return_value=data), \
                mock.patch.object(repo, "verify_digest", return_value=None):
            res = repo.scan_package("npm", "@acme/files", "0.2.1", resolved=rv)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
