"""0.1.9 (RA-9): a look-alike package from a look-alike account is SC-PUBLISHER-LOOKALIKE, CRITICAL.

The arrayref shape: proc-macro1, one change from proc-macro2, published to crates.io by dtolney, one change from
dtolnay, proc-macro2's maintainer. When a release's own name is one change from a popular package's (SC-TYPOSQUAT),
its owners — crates.io's owners API (the answer SC-NEW-DEPENDENCY reads, asked once), npm's maintainers and the
version's `_npmUser`, PyPI's JSON `ownership` — are compared with the popular package's (popular_names.json's
"owners"). An owner one change from one of theirs is the finding; an identical owner is not (the maintainer's own
sibling package), nor an owner of any popular package, nor a short name; and a registry that names no owners says
nothing. The guard has the owners where it reads npm's packument or PyPI's JSON document anyway.

The popular packages' owners are made up here (lookalike._OWNERS patched), the names the real targets; registries and
crates are fakes served by URL, inert (nothing is built or run). Nothing opens a socket."""

import datetime
import email.utils
import hashlib
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from lazaret.registry import guard, lookalike, repo
from lazaret.registry.ecosystems import crates
from lazaret.scanner import _native
from tests import _support
from tests.registry import _cargo_support
from tests.registry._review_support import tarball, zipball
from tests.registry.test_guard import context
from tests.registry.test_guard_provenance import OkScanner, sri
from tests.registry.test_registry_go_crates import INDEX, STATIC, served

API = "https://crates.io/api/v1/crates/"
NPM = "https://registry.npmjs.org/"
#: the popular packages' owners, made up: two packages of dtolnay's, one of dtolnaj's (a real maintainer one change
#: from dtolnay: never a look-alike), lodash's and requests'
OWNERS = lookalike.owner_tables({
    "crates": {"proc-macro2": ["dtolnay"], "quote": ["dtolnay", "github:dtolnay:publish"], "anyhow": ["dtolnaj"]},
    "npm": {"lodash": ["jdalton", "mathias"], "@babel/core": ["nicolo-ribaudo"]},
    "pypi": {"requests": ["lukasa", "nateprewitt", "psf"]}})


def made_up_owners():
    return mock.patch.dict(lookalike._OWNERS, OWNERS, clear=True)


def publisher(res):
    return [(i["rule"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-PUBLISHER-LOOKALIKE"]


def rules(res):
    return sorted({(i["rule"], i["sev"]) for i in res["issues"] if i["rule"].startswith("SC-") and i["sev"] != "INFO"})


class OwnerChangeTests(unittest.TestCase):
    def test_one_change(self):
        for mine, theirs, want in (("dtolney", "dtolnay", "a character changed"),
                                   ("dtolnayy", "dtolnay", "a character added"),
                                   ("dtolny", "dtolnay", "a character dropped"),
                                   ("dtonlay", "dtolnay", "two characters swapped"),
                                   ("nicolo_ribaudo", "nicolo-ribaudo", "its separators changed"),
                                   ("nicoloribaudo", "nicolo-ribaudo", "its separators changed"),
                                   ("nicolo-ribaud0", "nicolo-ribaudo", "a character changed"),
                                   ("nicolor-ibaudoo", "nicolo-ribaudo", "a character added, its separators aside")):
            with self.subTest(mine):
                self.assertEqual(lookalike.owner_change(mine, theirs), want)

    def test_not_a_change(self):
        for mine, theirs in (("dtolnay", "dtolnay"),                                    # the same account
                             ("alice", "bob"), ("dtolnay", "dtolnayxx"),                 # two changes
                             ("tjx", "tj"), ("ljhb", "ljha"), ("l-j-h-b", "ljha")):      # under MIN_OWNER letters
            with self.subTest(mine):
                self.assertIsNone(lookalike.owner_change(mine, theirs))

    def test_the_lookalike(self):
        data = OWNERS["crates"]
        self.assertEqual(lookalike.owner_lookalike("crates", "proc-macro1", ["dtolney"], owner_data=data),
                         ("proc-macro2", "a character changed", "dtolney", "dtolnay", "a character changed"))
        self.assertEqual(lookalike.owner_lookalike("crates", "Proc_Macro1", ["DTolney"], owner_data=data)[2], "dtolney")
        for name, owners in (("proc-macro1", ["alice"]),                    # an owner unlike theirs
                             ("proc-macro1", ["dtolnay"]),                  # theirs: the maintainer's sibling package
                             ("proc-macro1", ["dtolnay", "dtolney"]),       # theirs among them: no finding at all
                             ("proc-macro1", ["dtolnaj"]),                  # an owner of another popular crate
                             ("proc-macro1", []), ("proc-macro1", None),    # no owners named
                             ("proc-macro2", ["dtolney"]),                  # the popular crate itself
                             ("fresh-thing", ["dtolney"]),                  # a name like no popular one's
                             ("serde-json1", ["dtolney"])):                 # a popular one's with no owners known
            with self.subTest(name=name, owners=owners):
                self.assertIsNone(lookalike.owner_lookalike("crates", name, owners, owner_data=data))
        self.assertIsNone(lookalike.owner_lookalike("go", "github.com/shopsprint/decimal", ["x"]))
        self.assertIsNone(lookalike.owner_target("vscode", "juanbIanco.solidity"))

    def test_the_finding(self):
        with made_up_owners():
            found = lookalike.owner_issues("crates", "proc-macro1", {"dtolney"})
            self.assertEqual(lookalike.owner_issues("crates", "proc-macro1", None), [])
            self.assertEqual(lookalike.owner_issues("crates", "proc-macro1", set()), [])
        self.assertEqual([(i["rule"], i["sev"], i["file"], i["line"]) for i in found],
                         [("SC-PUBLISHER-LOOKALIKE", "CRITICAL", "(release)", 1)])
        self.assertEqual(found[0]["msg"], 'Published by "dtolney", whose name imitates "dtolnay" (a character changed), '
                                          'a maintainer of "proc-macro2", one of the 5,000 most-downloaded crates; and '
                                          'the package\'s own name, "proc-macro1", is one change from "proc-macro2" (a '
                                          'character changed). Two look-alikes together are impersonation, not chance.')

    def test_the_owners_tables(self):
        by_name, everyone = lookalike.owner_tables({"pypi": {
            "Python_Dateutil": ["DateUtil", " ", 5, "PGanssle"], "nobody": [], "x": 5,
            "requests": "Lukasa  nateprewitt"}})["pypi"]
        self.assertEqual(by_name, {"python-dateutil": frozenset({"dateutil", "pganssle"}),
                                   "requests": frozenset({"lukasa", "nateprewitt"})})
        self.assertEqual(everyone, frozenset({"dateutil", "pganssle", "lukasa", "nateprewitt"}))
        self.assertEqual(lookalike.owner_tables({})["npm"], ({}, frozenset()))


class ShippedOwnersTests(unittest.TestCase):
    """popular_names.json's "owners": the targets' accounts, lower-cased, sorted, space-separated, nothing else."""

    def test_the_section(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            raw = json.load(f)
        sec = raw["owners"]
        self.assertTrue(sec["source"] and sec["license"] and sec["changes"])
        for eco in lookalike.OWNER_ECOSYSTEMS:
            with self.subTest(eco):
                targets = set(raw[eco]["targets"])
                self.assertGreater(len(sec[eco]), 500)
                self.assertEqual(list(sec[eco]), sorted(sec[eco]))
                for name, text in sec[eco].items():
                    owners = text.split(" ")
                    self.assertIn(name, targets)
                    self.assertTrue(owners and owners == sorted(set(owners)) and len(owners) <= 64, name)
                    self.assertTrue(all(o and o == o.lower() and "@" not in o for o in owners), name)

    def test_no_popular_package_flags_against_another(self):
        """A popular package is never a look-alike, and its owners, with any other popular package's owners, are
        never look-alikes of each other (those of an organization are the same accounts)."""
        for eco in lookalike.OWNER_ECOSYSTEMS:
            by_name, _everyone = lookalike._owner_data(eco)
            with self.subTest(eco):
                self.assertEqual([n for n, o in by_name.items() if lookalike.owner_lookalike(eco, n, o)], [])
        self.assertEqual(lookalike._owner_data("crates")[0].get("proc-macro2"), frozenset({"dtolnay"}))


# ---------------------------------------------------------------- the registry scan: crates
def crate_index(name, versions, data):
    """The sparse index's file of a crate: {version: (pubtime, [(dependency, kind)])}; the last version's checksum is
    `data`'s (the .crate served), the others' made up (never downloaded)."""
    out = b""
    last = list(versions)[-1]
    for v, (pubtime, deps) in versions.items():
        out += json.dumps({"name": name, "vers": v, "features": {}, "yanked": False, "pubtime": pubtime,
                           "cksum": hashlib.sha256(data).hexdigest() if v == last else "0" * 64,
                           "deps": [{"name": d, "req": "^1", "features": [], "optional": False, "default_features": True,
                                     "target": None, "kind": k} for d, k in deps]}).encode() + b"\n"
    return out


def owners_answer(*logins):
    return json.dumps({"users": [{"id": k, "login": login, "kind": "user"} for k, login in enumerate(logins)]}).encode()


def crate_responses(owners=("dtolney",), name="proc-macro1", fresh_dependency=False):
    """proc-macro1 1.0.1 (inert: a library with no build script), its index file, and its owners when given."""
    data = _cargo_support.crate_tgz(name, "1.0.1", {})
    versions = {"1.0.0": ("2026-10-01T10:00:00Z", []),
                "1.0.1": ("2026-10-02T10:00:00Z", [("freshdep", "normal")] if fresh_dependency else [])}
    out = {INDEX + crates.index_path(name): crate_index(name, versions, data),
           STATIC + f"{name}/{name}-1.0.1.crate": data}
    if fresh_dependency:
        out[INDEX + crates.index_path("freshdep")] = crate_index("freshdep", {"0.1.0": ("2026-10-01T12:00:00Z", [])}, b"")
        out[API + "freshdep/owners"] = owners_answer("mallory")
    if owners is not None:
        out[API + f"{name}/owners"] = owners_answer(*owners)
    return out


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class CratesScanTests(unittest.TestCase):
    def scan(self, responses, name="proc-macro1"):
        transport, patch = served(responses)
        with patch, made_up_owners():
            return repo.scan_package("crates", name, "1.0.1"), transport

    def test_the_arrayref_shape_is_critical(self):
        res, transport = self.scan(crate_responses(("dtolney",)))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(rules(res), [("SC-PUBLISHER-LOOKALIKE", "CRITICAL"), ("SC-TYPOSQUAT", "MAJOR")])
        self.assertIn('Published by "dtolney", whose name imitates "dtolnay"', publisher(res)[0][2])
        self.assertEqual(transport.urls().count(API + "proc-macro1/owners"), 1)

    def test_an_unrelated_owner_is_the_typosquat_alone(self):
        res, _ = self.scan(crate_responses(("alice",)))
        self.assertEqual((res["verdict"], rules(res)), ("WARN", [("SC-TYPOSQUAT", "MAJOR")]))

    def test_the_maintainer_himself_is_no_finding(self):
        for owners in (("dtolnay",), ("dtolnay", "dtolney"), ("dtolnaj",)):
            with self.subTest(owners=owners):
                res, _ = self.scan(crate_responses(owners))
                self.assertEqual(publisher(res), [])
                self.assertEqual(res["verdict"], "WARN")

    def test_no_owners_answer_or_offline_is_no_finding(self):
        res, transport = self.scan(crate_responses(owners=None))                # (the API answers 404)
        self.assertEqual((res["verdict"], publisher(res)), ("WARN", []))
        with mock.patch.dict(os.environ, {"LAZARET_NO_DEPENDENCY_HISTORY": "1"}):
            res, transport = self.scan(crate_responses(("dtolney",)))
        self.assertEqual((res["verdict"], publisher(res)), ("WARN", []))
        self.assertNotIn(API + "proc-macro1/owners", transport.urls())

    def test_a_name_like_no_popular_ones_asks_for_no_owners(self):
        res, transport = self.scan(crate_responses(("dtolney",), name="fresh-thing"), name="fresh-thing")
        self.assertEqual((res["verdict"], publisher(res)), ("OK", []))
        self.assertFalse([u for u in transport.urls() if u.startswith(API)])

    def test_the_owners_are_asked_once_with_sc_new_dependency(self):
        res, transport = self.scan(crate_responses(("dtolney",), fresh_dependency=True))
        self.assertEqual([r for r, _s in rules(res)], ["SC-NEW-DEPENDENCY", "SC-PUBLISHER-LOOKALIKE", "SC-TYPOSQUAT"])
        self.assertEqual(transport.urls().count(API + "proc-macro1/owners"), 1)

    def test_crate_owners_are_kept_on_the_resolution(self):
        transport, patch = served(crate_responses(("dtolney",)))
        with patch:
            resolved = repo.resolve("crates", "proc-macro1", "1.0.1")
            self.assertEqual(repo.crate_owners("proc-macro1", resolved), {"dtolney"})
            self.assertEqual(repo.crate_owners("proc-macro1", resolved), {"dtolney"})
            self.assertEqual(repo.crate_owners("proc-macro1", ("1.0.1",)), {"dtolney"})        # (a tuple: asked again)
        self.assertEqual(transport.urls().count(API + "proc-macro1/owners"), 2)


# ---------------------------------------------------------------- the registry scan: npm and PyPI
def npm_manifest(name, maintainers, npm_user=None):
    out = {"name": name, "version": "1.0.0", "maintainers": [{"name": m, "email": f"{m}@example.invalid"}
                                                            for m in maintainers],
           "dist": {"tarball": f"{NPM}{name}/-/{name}-1.0.0.tgz"}}
    if npm_user:
        out["_npmUser"] = {"name": npm_user, "email": "npm-oidc-no-reply@github.com"}
    return out


class NpmPypiScanTests(unittest.TestCase):
    def scan_npm(self, name, maintainers, npm_user=None):
        manifest = npm_manifest(name, maintainers, npm_user)
        data = tarball({"package.json": json.dumps({"name": name, "version": "1.0.0"}),
                        "index.js": "module.exports = 1;\n"})
        rv = ("1.0.0", manifest["dist"]["tarball"], "tgz", "npm", manifest)
        with made_up_owners(), mock.patch.object(repo, "http_bytes", return_value=data), \
                mock.patch.object(repo, "verify_digest", return_value=None), \
                mock.patch.object(repo, "http_json", side_effect=AssertionError("no document is fetched")):
            return repo.scan_package("npm", name, "1.0.0", resolved=rv)

    def test_an_npm_maintainer_like_lodashs(self):
        res = self.scan_npm("lodahs", ["jdaltom"])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(rules(res), [("SC-PUBLISHER-LOOKALIKE", "CRITICAL"), ("SC-TYPOSQUAT", "MAJOR")])
        self.assertIn('Published by "jdaltom", whose name imitates "jdalton" (a character changed), a maintainer of '
                      '"lodash", one of the 5,000 most-downloaded npm packages', publisher(res)[0][2])
        self.assertNotIn("example.invalid", publisher(res)[0][2])

    def test_npms_publishing_account_and_what_is_not_one(self):
        self.assertEqual(rules(self.scan_npm("lodahs", ["someone"], npm_user="mathiass"))[0],
                         ("SC-PUBLISHER-LOOKALIKE", "CRITICAL"))
        for maintainers, npm_user in ((["someone"], None), (["someone"], "GitHub Actions"), (["jdalton"], None),
                                      (["jdalton", "jdaltom"], "jdaltom"), ([], None)):
            with self.subTest(maintainers=maintainers, npm_user=npm_user):
                res = self.scan_npm("lodahs", maintainers, npm_user)
                self.assertEqual((res["verdict"], rules(res)), ("WARN", [("SC-TYPOSQUAT", "MAJOR")]))
        manifest = {"maintainers": [{"name": "a"}, "b", {"x": 1}], "_npmUser": {"name": "GitHub Actions"}}
        self.assertEqual(repo.npm_owners(manifest, {"maintainers": [{"name": "c"}]}), {"a", "c"})

    def test_a_pypi_owner_like_requests(self):
        meta = "Metadata-Version: 2.1\nName: requesxs\nVersion: 1.0\n\nA description.\n"
        data = zipball({"requesxs/__init__.py": "", "requesxs-1.0.dist-info/METADATA": meta})
        doc = {"info": {"name": "requesxs", "version": "1.0"},
               "urls": [{"filename": "requesxs-1.0-py3-none-any.whl", "packagetype": "bdist_wheel",
                         "url": "https://files.pythonhosted.org/requesxs-1.0-py3-none-any.whl",
                         "digests": {"sha256": hashlib.sha256(data).hexdigest()}}],
               "ownership": {"organization": None, "roles": [{"role": "Owner", "user": "NatePrewit"}]}}
        for ownership, want in ((doc["ownership"], "SUSPICIOUS"),
                                ({"organization": "psf", "roles": [{"role": "Owner", "user": "NatePrewit"}]}, "WARN"),
                                ({"organization": "lukasaa", "roles": []}, "SUSPICIOUS"),
                                ({"organization": None, "roles": [{"role": "Owner", "user": "carol"}]}, "WARN"),
                                (None, "WARN")):
            with self.subTest(ownership=ownership), made_up_owners(), \
                    mock.patch.object(repo, "http_json", return_value={**doc, "ownership": ownership}), \
                    mock.patch.object(repo, "http_bytes", return_value=data):
                resolved = repo.resolve("pypi", "requesxs", "1.0")
                self.assertEqual(resolved.ownership, ownership)
                res = repo.scan_package("pypi", "requesxs", "1.0", resolved=resolved)
                self.assertEqual(res["verdict"], want, res["issues"])
                self.assertEqual(bool(publisher(res)), want == "SUSPICIOUS")

    def test_no_documents_is_no_finding(self):
        with made_up_owners():
            self.assertEqual(repo.publisher_lookalike_issues("pypi", "requesxs", repo.Resolution(
                "1.0", [{"url": "u", "container": "zip", "artifact": "wheel", "entry": {}, "filename": "f"}])), [])
            self.assertEqual(repo.publisher_lookalike_issues("npm", "lodahs", None), [])
            self.assertEqual(repo.publisher_lookalike_issues("npm", "lodahs", ("1.0.0", "u", "tgz", "npm", None)), [])
            self.assertEqual(repo.publisher_lookalike_issues("go", "github.com/shopsprint/decimal", None), [])
            self.assertEqual(repo.pypi_owners({"roles": [{"user": "a"}, {"role": "Owner"}], "organization": "org"}),
                             {"a", "org"})


# ---------------------------------------------------------------- the guard
class GuardFetcher:
    """The guard's Fetcher over made-up answers: documents by URL (json), files by URL (get, fetch)."""

    def __init__(self, documents, files, published):
        self.documents, self.files, self.published, self.asked = documents, files, published, []

    def json(self, url, accept="application/json"):
        self.asked.append(url)
        if url not in self.documents:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.documents[url]

    def get(self, url, *args, **kw):
        self.asked.append(url)
        if url not in self.files:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.files[url]

    def fetch(self, url, *args, **kw):
        return self.get(url), {"Last-Modified": email.utils.format_datetime(self.published, usegmt=True)}


def ago(**kw):
    return guard.now() - datetime.timedelta(**kw)


class GuardTests(unittest.TestCase):
    def npm_check(self, maintainers, published, **opts):
        data = tarball({"package.json": '{"name": "lodahs", "version": "1.0.0"}'})
        tar = NPM + "lodahs/-/lodahs-1.0.0.tgz"
        packument = {"name": "lodahs", "maintainers": [{"name": m} for m in maintainers],
                     "time": {"1.0.0": published.isoformat()},
                     "versions": {"1.0.0": {"name": "lodahs", "version": "1.0.0", "_npmUser": {"name": maintainers[0]}}}}
        fetcher = GuardFetcher({NPM + "lodahs": packument}, {tar: data}, published)
        ctx = context(tool="npm", **opts)
        ctx.scanner.close()
        ctx.scanner = OkScanner()
        pkg = {"name": "lodahs", "version": "1.0.0", "tarball": tar, "integrity": sri(data), "registry": NPM,
               "lock_digest": None}
        with made_up_owners():
            return guard.check_npm_package(ctx, fetcher, pkg), fetcher, ctx

    def test_npm_with_the_packument_read_for_the_publish_time(self):
        check, fetcher, ctx = self.npm_check(["jdaltom"], ago(hours=3), allow_new=["lodahs"])
        self.assertEqual(check.verdict, "SUSPICIOUS")
        self.assertTrue(check.reason.startswith('Published by "jdaltom", whose name imitates "jdalton"'), check.reason)
        self.assertTrue(check.indicators[0].startswith("SC-PUBLISHER-LOOKALIKE (CRITICAL)"), check.indicators)
        self.assertEqual(len(check.blocked), 1)
        self.assertEqual(fetcher.asked.count(NPM + "lodahs"), 1)              # (the one the publish time asked for)
        # the verdict cache keeps it; the same check from the cache says it once
        key = next(iter(ctx.scanner.cache))
        self.assertEqual(ctx.scanner.cache[key]["verdict"], "SUSPICIOUS")
        with made_up_owners():
            again = guard.with_publisher(check, ctx.scanner.cache[key], {"jdaltom"})
        self.assertEqual(again["indicators"], ctx.scanner.cache[key]["indicators"])

    def test_npm_what_says_nothing(self):
        check, _f, _c = self.npm_check(["someone"], ago(hours=3), allow_new=["lodahs"])
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        # an older release: the guard reads no packument for it, so it has no owners to compare (no request added)
        check, fetcher, _c = self.npm_check(["jdaltom"], ago(days=5))
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertNotIn(NPM + "lodahs", fetcher.asked)

    def test_pypi_with_the_document_read_for_the_upload_time(self):
        data = zipball({"requesxs/__init__.py": ""})
        url = "https://files.pythonhosted.org/packages/requesxs-1.0-py3-none-any.whl"
        f = {"url": url, "hash": "sha256:" + hashlib.sha256(data).hexdigest(),
             "filename": "requesxs-1.0-py3-none-any.whl", "upload-time": None}
        for owner, want in (("nateprewit", "SUSPICIOUS"), ("carol", "OK")):
            doc = {"urls": [{"filename": f["filename"], "upload_time_iso_8601": ago(days=5).isoformat()}],
                   "ownership": {"organization": None, "roles": [{"role": "Owner", "user": owner}]}}
            fetcher = GuardFetcher({guard.PYPI_JSON + "requesxs/1.0/json": doc}, {url: data}, ago(days=5))
            ctx = context(tool="uv")
            ctx.scanner.close()
            ctx.scanner = OkScanner()
            with self.subTest(owner=owner), made_up_owners():
                check = guard.check_file(ctx, fetcher, "requesxs", "1.0", f)
                self.assertEqual(check.verdict, want, check.reason)
                self.assertEqual(bool(check.blocked), want == "SUSPICIOUS")


# ---------------------------------------------------------------- the data scripts
class OwnersScriptTests(unittest.TestCase):
    """scripts/fetch-target-owners.py over a fake registry, and update-popular-names.py --owners on small files."""

    def setUp(self):
        self.fetch = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "fetch-target-owners.py"),
                                          "fetch_target_owners_for_tests")
        self.update = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "update-popular-names.py"),
                                           "update_popular_names_for_owner_tests")

    def test_what_is_kept_of_each_answer(self):
        self.assertEqual(self.fetch.npm_owners({"maintainers": [{"name": "Jdalton", "email": "j@example.invalid"},
                                                                 {"email": "x@example.invalid"}],
                                                 "_npmUser": {"name": "GitHub Actions"}}), ["jdalton"])
        self.assertEqual(self.fetch.pypi_owners({"ownership": {"organization": "PSF", "roles": [
            {"role": "Owner", "user": "Lukasa"}, {"role": "Maintainer", "user": "nateprewitt"}]}}),
            ["lukasa", "nateprewitt", "psf"])
        self.assertEqual(self.fetch.pypi_owners({"info": {}}), [])
        self.assertEqual(self.fetch.crates_owners({"users": [{"login": "dtolnay", "name": "David", "avatar": "u"},
                                                             {"login": "github:serde-rs:publish", "kind": "team"}]}),
                         ["dtolnay", "github:serde-rs:publish"])
        with self.assertRaises(ValueError):
            self.fetch.crates_owners({"errors": [{"detail": "Not Found"}]})

    def test_a_run_goes_on_where_it_stopped(self):
        answers = {"https://crates.io/api/v1/crates/syn/owners": {"users": [{"login": "dtolnay"}]},
                   "https://crates.io/api/v1/crates/rand/owners": {"users": [{"login": "dhardy"}]}}
        asked = []

        def fake(url, gzipped=False):
            asked.append(url)
            if url not in answers:
                raise OSError("HTTP 404")
            return answers[url]
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "crates.jsonl")
            with mock.patch.object(self.fetch, "CRATES_INTERVAL", 0.0):
                self.assertEqual(self.fetch.fetch_list("crates", ["syn", "gone"], pathlib.Path(path), fetch=fake,
                                                       progress=None), (2, 1, 1))
                with open(path, "a", encoding="utf-8") as f:
                    f.write('{"name": "half')                                  # (a line cut short when it stopped)
                answers["https://crates.io/api/v1/crates/gone/owners"] = {"users": [{"login": "back"}]}
                self.assertEqual(self.fetch.fetch_list("crates", ["syn", "gone", "rand"], pathlib.Path(path), fetch=fake,
                                                       progress=None), (2, 2, 0))
            with open(path, encoding="utf-8") as f:
                rows = [json.loads(line) for line in f]
        self.assertEqual(asked.count("https://crates.io/api/v1/crates/syn/owners"), 1)
        self.assertEqual(sorted((r["name"], r["owners"]) for r in rows),
                         [("gone", ["back"]), ("rand", ["dhardy"]), ("syn", ["dtolnay"])])

    def test_crates_io_is_asked_once_a_second(self):
        now, slept = [100.0], []
        def sleep(s):
            slept.append(s)
            now[0] += s
        pace = self.fetch.Pace(1.0, clock=lambda: now[0], sleep=sleep)
        paced = pace(lambda url, **kw: url)
        for url in ("a", "b", "c"):
            paced(url)
            now[0] += 0.25
        self.assertEqual(slept, [0.75, 0.75])

    def test_the_owners_section(self):
        current = {eco: {"targets": targets} for eco, targets in (("npm", ["lodash", "@babel/core", "chalk"]),
                                                                   ("pypi", ["requests", "python-dateutil"]),
                                                                   ("crates", ["proc-macro2", "rust-decimal"]))}
        with tempfile.TemporaryDirectory() as d:
            rows = {"npm.jsonl": [{"rank": 0, "name": "lodash", "owners": ["mathias", "JDalton", "jdalton"]},
                                  {"rank": 1, "name": "@babel/core", "error": "HTTPError: 404"},
                                  {"rank": 2, "name": "chalk", "owners": ["x@example.invalid", "sindresorhus", "a b"]},
                                  {"rank": 9, "name": "not-a-target", "owners": ["someone"]}],
                    "pypi.jsonl": [{"rank": 1, "name": "Python_Dateutil", "owners": ["pganssle"]},
                                   {"rank": 0, "name": "requests", "owners": []}]}
            for name, items in rows.items():
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in items))
            sec = self.update.owners_section(d, {}, current)["owners"]
            with mock.patch.object(self.update, "MAX_OWNERS", 1):
                capped = self.update.owners_section(d, {}, current)["owners"]
            with self.assertRaises(SystemExit):
                self.update.owners_section(os.path.join(d, "none"), {}, current)
        self.assertEqual({k: sec[k] for k in ("npm", "pypi", "crates")},
                         {"npm": {"chalk": "sindresorhus", "lodash": "jdalton mathias"},
                          "pypi": {"python-dateutil": "pganssle"}, "crates": {}})
        self.assertEqual(capped["npm"]["lodash"], "jdalton")
        self.assertIn("npm.jsonl", sec["source"])
        self.assertNotIn("crates.jsonl", sec["source"])
        self.assertIn("npm 2 of its 3, PyPI 1 of its 2, crates 0 of its 2", sec["changes"])
        # without --owners the section is kept, to the targets the file has
        current["npm"]["targets"].remove("chalk")
        kept = self.update.owners_section(None, sec, current)["owners"]
        self.assertEqual(kept["npm"], {"lodash": "jdalton mathias"})
        self.assertEqual((kept["source"], kept["pypi"]), (sec["source"], sec["pypi"]))

    def test_the_command_line(self):
        self.assertIsNone(self.fetch.options([]))
        self.assertIsNone(self.fetch.options(["out", "--only", "go"]))
        self.assertIsNone(self.fetch.options(["out", "--top", "0"]))
        opts = self.fetch.options(["out", "--only", "crates", "--top", "1000"])
        self.assertEqual((str(opts[0]), opts[1], opts[2]), ("out", ["crates"], 1000))
        err = io.StringIO()
        with mock.patch.object(self.update, "configure_stdio"), mock.patch("sys.stderr", err):
            self.assertEqual(self.update.main(["--owners"]), 2)
        self.assertIn("--owners FILES_DIR", err.getvalue())


if __name__ == "__main__":
    unittest.main()
