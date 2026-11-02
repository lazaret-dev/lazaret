"""`registry/ecosystems/base.py`: the shared errors, `Resolution`, the checked fetch seam and the `Ecosystem` defaults,
and the conformance mixin itself (`ecosystem_contract.py`), which a toy module must pass and a set of deliberately
broken toy modules must each fail on the check that exists to catch that fault. Nothing here opens a socket."""

import hashlib
import http.client
import inspect
import json
import re
import threading
import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import ecosystems, repo
from lazaret.registry.ecosystems import base
from tests.registry import ecosystem_contract as contract
from tests.registry.ecosystem_contract import EcosystemContract

NAME_CHARS = re.compile(r"[A-Za-z0-9_-]")


# ---------------------------------------------------------------------------
# A small registry that follows every rule, and the pieces the broken ones replace
# ---------------------------------------------------------------------------

class Toy(base.Ecosystem):
    id = "toy"
    title = "Toy registry"
    hosts = frozenset({"reg.example", "dl.example"})
    rate = {"reg.example": 0.5}
    artifact_kinds = ("toy",)
    manifest_names = frozenset({"toy.json"})

    def check_name(self, name):
        return base.ascii_name(name, "package name", NAME_CHARS, 40, "toy")

    def identity(self, name):
        return self.check_name(name).lower().replace("_", "-")

    # ---- resolve, in small steps so that a broken toy can replace one
    def _dig(self, doc, name, version):
        if not isinstance(doc, dict) or not isinstance(doc.get("versions"), dict) or not doc["versions"]:
            raise base.FetchError("toy: the registry document has no versions")
        if version is None:
            version = doc.get("latest")
            if not isinstance(version, str) or version not in doc["versions"]:
                raise base.FetchError("toy: the registry document names no latest version")
        entry = doc["versions"].get(version)
        if not isinstance(entry, dict):
            raise base.SpecError(f"toy: no version {base.show(version)} of {base.show(name)}")
        return version, entry

    def _artifact_url(self, fetch, url):
        return fetch.check_url(url)

    def _fallback(self, doc, version):
        return None

    def resolve(self, name, version, fetch):
        name = self.check_name(name)
        want = self.check_version(version)
        doc = fetch.json(f"https://reg.example/toy/{self.segment(name)}")
        got, entry = self._dig(doc, name, want)
        got = self.check_version(got)
        url = entry.get("url")
        if not isinstance(url, str):
            raise base.FetchError("toy: the registry document names no download")
        url = self._artifact_url(fetch, url)
        filename = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
        if not filename.endswith(".tgz"):
            raise base.FetchError("toy: the download is not a .tgz")
        size = entry.get("size", 0)
        if type(size) is not int or size < 0 or size > base.MAX_ARTIFACT_BYTES:
            raise base.FetchError("toy: the download is over the size limit")
        art = {"url": url, "container": "tgz", "artifact": "toy", "entry": entry, "filename": filename}
        return base.Resolution(got, [art], [], {"name": name})

    def archive_root(self, resolved, artifact):
        try:
            return f"{resolved.info['name']}-{resolved[0]}/"
        except (AttributeError, KeyError, TypeError):
            return None

    def verify(self, data, entry, name, version):
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
            return None
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest.lower():
            raise base.DigestError(f"toy: SHA-256 of the download does not match what the registry published "
                                   f"for {base.show(name)} {base.show(version)}")
        return "sha256", actual

    def container(self, filename):
        return "tgz" if isinstance(filename, str) and filename.endswith((".tgz", ".tar.gz")) else None

    def member_path(self, kind, name, root=None):
        return base.root_stripped(name, root) if root else base.top_directory_stripped(name)

    def declared(self, kind, manifests, members):
        text = manifests.get("toy.json")
        try:
            doc = json.loads(text) if text else None
        except (ValueError, RecursionError):                 # (a deeply nested document is a RecursionError before Python 3.12)
            doc = None
        if not isinstance(doc, dict):
            return base.Declared()
        deps = doc.get("dependencies")
        return base.Declared(doc["name"] if isinstance(doc.get("name"), str) else None,
                             [d for d in deps if isinstance(d, str)] if isinstance(deps, list) else ())


def toy_responses():
    def entry(version, data):
        return {"url": f"https://dl.example/toy/x-{version}.tgz", "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}
    doc = {"name": "x", "latest": "1.2.0",
           "versions": {"1.0.0": entry("1.0.0", b"one"), "1.2.0": entry("1.2.0", b"twelve")}}
    return {"https://reg.example/toy/x": json.dumps(doc).encode()}


class ToyData(EcosystemContract):
    """What the toy's contract test supplies; the probes below run the same data against broken toys."""
    GOOD_NAMES = ("x", "left-pad", "Foo_Bar", "a" * 40)
    GOOD_VERSIONS = ("1.0.0", "0.0.1-alpha.1", "2024.10.3", "v1")
    GOOD_SPEC = ("x", "1.0.0")
    SAME_IDENTITY = (("Foo_Bar", "foo-bar"), ("X", "x"))
    DIFFERENT_IDENTITY = (("foo", "foo2"), ("a-b", "ab"))
    GOOD_ARCHIVE_MEMBERS = ("x-1.0.0/", "x-1.0.0/a.py", "x-1.0.0/a/b.py", "x-1.0.0/PKG-INFO")
    MEMBER_PATHS = (
        ("toy", "x-1.0.0/a/b.py", "x-1.0.0/", ("a/b.py", None)),
        ("toy", "x-1.0.0\\a\\b.py", "x-1.0.0/", ("a/b.py", None)),
        ("toy", "x-1.0.0//etc/passwd", "x-1.0.0/", ("etc/passwd", None)),
        ("toy", "x-1.0.0/../etc", "x-1.0.0/", (None, "path contains '..'")),
        ("toy", "x-1.0.0/", "x-1.0.0/", (None, None)),
        ("toy", "y-1.0.0/a.py", "x-1.0.0/", (None, "member outside the archive's root directory")),
        ("toy", "x-1.0.0x/a.py", "x-1.0.0/", (None, "member outside the archive's root directory")),
        ("toy", "top/a/b.py", None, ("a/b.py", None)),
        ("toy", "a.py", None, ("a.py", None)),
        ("toy", "./top/./a.py", None, ("a.py", None)),
    )
    toy_class = Toy

    def make(self):
        return self.toy_class()

    def responses(self):
        return toy_responses()

    def verify_case(self):
        data = b"toy archive bytes"
        return data, {"sha256": hashlib.sha256(data).hexdigest()}, "x", "1.0.0"

    def malformed_digests(self):
        return [{"sha256": "zz"}, {"sha256": 5}, {"sha256": ""}, {}, {"sha256": "A" * 63 + "g"}, {"sha256": "a" * 65}]

    def roots(self):
        return {"toy": "x-1.0.0/"}

    def hostile_responses(self, url):
        doc = json.loads(toy_responses()["https://reg.example/toy/x"])
        doc["versions"]["1.0.0"]["url"] = url
        return {"https://reg.example/toy/x": json.dumps(doc).encode()}


class ToyContract(ToyData, unittest.TestCase):
    """The toy is a module like any other: it gets the whole contract."""


def failing(toy_class):
    """The names of the contract tests that fail for `toy_class` (a broken module)."""
    probe = type("Probe", (ToyData, unittest.TestCase), {"toy_class": toy_class})
    result = unittest.TestResult()
    unittest.defaultTestLoader.loadTestsFromTestCase(probe).run(result)
    names = set()
    for case, _text in result.failures + result.errors:
        names.add(getattr(case, "test_case", case)._testMethodName)
    return names


# ---------------------------------------------------------------------------
# Broken modules: each one fails the check that exists for its fault
# ---------------------------------------------------------------------------

class LaxNames(Toy):
    def check_name(self, name):
        if not isinstance(name, str):
            raise base.SpecError("toy: a name is text")
        return name


class EchoesNames(Toy):
    def check_name(self, name):
        if not isinstance(name, str) or not NAME_CHARS.fullmatch(name[:1] or "!"):
            raise base.SpecError("toy: bad name " + str(name))
        return super().check_name(name)


class LaxVersions(Toy):
    def check_version(self, version):
        return None if version is None else str(version).strip()


class EchoesVersions(Toy):
    def check_version(self, version):
        try:
            return super().check_version(version)
        except base.SpecError:
            raise base.SpecError("toy: bad version " + str(version)) from None


class NotIdempotent(Toy):
    def identity(self, name):
        return super().identity(name) + "!"


class MergesNames(Toy):
    def identity(self, name):
        return super().identity(name).replace("-", "")


class SplitsSameName(Toy):
    def identity(self, name):
        return self.check_name(name)


class QuerySegment(Toy):
    def segment(self, value):
        return str(value) + "?x=1"


class TrustsTheDocument(Toy):
    def _artifact_url(self, fetch, url):
        return url


class CrashesOnOddDocuments(Toy):
    def _dig(self, doc, name, version):
        entry = doc["versions"][version or doc["latest"]]
        return version or doc["latest"], entry


class AnyVersionWillDo(Toy):
    def _dig(self, doc, name, version):
        try:
            return super()._dig(doc, name, version)
        except base.SpecError:
            return super()._dig(doc, name, None)


class NeverFailsClosed(Toy):
    def verify(self, data, entry, name, version):
        return "sha256", hashlib.sha256(data).hexdigest()


class TrustsAnyDigest(Toy):
    def verify(self, data, entry, name, version):
        got = super().verify(data, entry, name, version)
        return got if got is not None else ("sha256", hashlib.sha256(data).hexdigest())


class RawMemberPaths(Toy):
    def member_path(self, kind, name, root=None):
        return str(name), None


class KeepsDotDot(Toy):
    def member_path(self, kind, name, root=None):
        rel, problem = super().member_path(kind, name, root)
        if problem:
            return str(name).replace("\\", "/"), None
        return rel, problem


class NoId(Toy):
    id = ""


class SchemeInHosts(Toy):
    hosts = frozenset({"https://reg.example", "dl.example"})


class RateForAStranger(Toy):
    rate = {"elsewhere.example": 1.0}


class UndeclaredDownloadHost(Toy):
    hosts = frozenset({"reg.example"})


class RunTargetsCrash(Toy):
    def run_targets(self, kind, manifests, members):
        return base.RunTargets(entries=[manifests["toy.json"]["main"]])


class DeclaredCrash(Toy):
    def declared(self, kind, manifests, members):
        return base.Declared(name=json.loads(manifests["toy.json"])["name"])


class ContainerCrash(Toy):
    def container(self, filename):
        return filename.rsplit(".", 1)[1]


class NotAResolution(Toy):
    def resolve(self, name, version, fetch):
        res = super().resolve(name, version, fetch)
        return (res[0], res.artifacts[0]["url"])


class ArtifactsOutsideKinds(Toy):
    artifact_kinds = ("other",)


class RootWithoutSlash(Toy):
    def archive_root(self, resolved, artifact):
        return super().archive_root(resolved, artifact).rstrip("/")


class RootNobodyAgreesWith(Toy):
    def archive_root(self, resolved, artifact):
        return "other-" + super().archive_root(resolved, artifact)


class RootEscapes(Toy):
    def archive_root(self, resolved, artifact):
        return "../" + super().archive_root(resolved, artifact)


class RootCrashesOnOddInput(Toy):
    def archive_root(self, resolved, artifact):
        return f"{resolved.info['name']}-{resolved[0]}/"


class TheseBrokenModulesAreCaught(unittest.TestCase):
    """The contract has teeth: each fault is found by the test written for it, and the toy it was copied from passes."""

    CASES = (
        (LaxNames, {"test_hostile_names_are_refused_without_echoing_them"}),
        (EchoesNames, {"test_a_refusal_never_contains_what_made_it_hostile",
                       "test_hostile_names_are_refused_without_echoing_them"}),
        (LaxVersions, {"test_hostile_versions_are_refused_without_echoing_them",
                       "test_versions_that_are_not_text_are_refused"}),
        (EchoesVersions, {"test_hostile_versions_are_refused_without_echoing_them"}),
        (NotIdempotent, {"test_good_names_are_accepted_and_checking_one_twice_changes_nothing"}),
        (MergesNames, {"test_identity_groups_names_as_the_module_says"}),
        (SplitsSameName, {"test_identity_groups_names_as_the_module_says"}),
        (QuerySegment, {"test_a_checked_name_and_version_cannot_change_where_a_url_goes"}),
        (TrustsTheDocument, {"test_a_document_that_names_an_artifact_on_another_host_is_refused"}),
        (CrashesOnOddDocuments, {"test_resolve_survives_documents_that_no_registry_sends",
                                 "test_resolve_of_a_version_the_registry_does_not_have_is_an_error"}),
        (AnyVersionWillDo, {"test_resolve_of_a_version_the_registry_does_not_have_is_an_error"}),
        (NeverFailsClosed, {"test_verify_matches_a_published_digest_and_fails_closed_on_any_change"}),
        (TrustsAnyDigest, {"test_a_digest_that_is_garbled_is_never_a_match"}),
        (RawMemberPaths, {"test_member_paths_are_always_safe_to_join_to_a_directory",
                          "test_member_paths_are_as_the_module_says"}),
        (KeepsDotDot, {"test_member_paths_are_always_safe_to_join_to_a_directory",
                       "test_member_paths_are_as_the_module_says"}),
        (NoId, {"test_declares_itself"}),
        (SchemeInHosts, {"test_declares_itself"}),
        (RateForAStranger, {"test_declares_itself"}),
        (UndeclaredDownloadHost, {"test_resolve_gives_the_documented_shape_from_recorded_responses"}),
        (RunTargetsCrash, {"test_nothing_in_an_archive_makes_run_targets_or_declared_fail_in_a_new_way"}),
        (DeclaredCrash, {"test_nothing_in_an_archive_makes_run_targets_or_declared_fail_in_a_new_way"}),
        (ContainerCrash, {"test_container_is_defined_for_every_file_name"}),
        (NotAResolution, {"test_resolve_gives_the_documented_shape_from_recorded_responses"}),
        (ArtifactsOutsideKinds, {"test_resolve_gives_the_documented_shape_from_recorded_responses"}),
        (RootWithoutSlash, {"test_the_archive_root_is_a_directory_the_member_rules_agree_with"}),
        (RootNobodyAgreesWith, {"test_the_archive_root_is_a_directory_the_member_rules_agree_with"}),
        (RootEscapes, {"test_the_archive_root_is_a_directory_the_member_rules_agree_with"}),
        (RootCrashesOnOddInput, {"test_the_archive_root_is_a_directory_the_member_rules_agree_with"}),
    )

    def test_the_toy_it_was_all_copied_from_passes(self):
        self.assertEqual(failing(Toy), set())

    def test_every_broken_module_fails_the_check_written_for_its_fault(self):
        for broken, wanted in self.CASES:
            with self.subTest(broken=broken.__name__):
                got = failing(broken)
                self.assertTrue(wanted <= got, "%s should fail %s, and failed %s"
                                % (broken.__name__, sorted(wanted - got), sorted(got)))

    def test_a_broken_module_fails_only_what_it_breaks(self):
        """A probe that fails everything proves nothing: each fault trips a few checks, not the whole mixin."""
        everything = len([n for n in dir(EcosystemContract) if n.startswith("test_")])
        for broken, _wanted in self.CASES:
            with self.subTest(broken=broken.__name__):
                self.assertLess(len(failing(broken)), everything // 2)


# ---------------------------------------------------------------------------
# The shared pieces
# ---------------------------------------------------------------------------

class SameAsRepoTests(unittest.TestCase):
    """`repo.py` re-exports the errors and `Resolution` (X-2's first step, Part C); the numbers it keeps are held to
    `base.py`'s."""

    def test_the_numbers_are_repos(self):
        self.assertEqual(base.MAX_DOCUMENT_BYTES, repo.MAX_FEED_BYTES)
        self.assertEqual(base.MAX_ARTIFACT_BYTES, repo.MAX_DOWNLOAD_BYTES)
        self.assertEqual(base.MAX_REDIRECTS, repo.MAX_REDIRECTS)
        self.assertEqual(base.METADATA_TIMEOUT, repo.METADATA_TIMEOUT)
        self.assertEqual(base.DOWNLOAD_TIMEOUT, repo.DOWNLOAD_TIMEOUT)
        self.assertEqual(base.VERSION_RE.pattern, repo.NAME_RE.pattern)
        self.assertEqual(base.VERSION_RE.flags, repo.NAME_RE.flags)

    def test_the_errors_are_the_same_errors(self):
        for ours, theirs in ((base.SpecError, repo.SpecError), (base.FetchError, repo.FetchError),
                             (base.DigestError, repo.DigestError)):
            self.assertIs(ours, theirs)
            self.assertEqual(ours.__mro__[1:], (ValueError,) + ValueError.__mro__[1:])
        self.assertIsNone(base.FetchError.status)
        self.assertIs(base.Resolution, repo.Resolution)

    def test_resolution_is_repos_shape(self):
        art = [{"url": "https://a/x", "container": "tgz", "artifact": "npm", "entry": {"k": 1}, "filename": "x"},
               {"url": "https://a/y", "container": "zip", "artifact": "wheel", "entry": None, "filename": "y"}]
        skipped = [{"filename": "z", "packagetype": "bdist_egg", "installable": False, "size": 3, "reason": "r"}]
        ours = base.Resolution("1.0", art, skipped, {"i": 1})
        theirs = repo.Resolution("1.0", art, skipped, {"i": 1})
        self.assertEqual(tuple(ours), tuple(theirs))
        self.assertEqual((ours.artifacts, ours.skipped, ours.info), (theirs.artifacts, theirs.skipped, theirs.info))
        self.assertEqual(inspect.signature(base.Resolution.__new__), inspect.signature(repo.Resolution.__new__))
        for bad in (None, 5, "x", [1]):
            self.assertEqual(base.Resolution("1", art, (), bad).info, repo.Resolution("1", art, (), bad).info)
        self.assertEqual(base.Resolution("1", art).skipped, [])
        with self.assertRaises(IndexError):                                  # (an empty release is an error)
            base.Resolution("1", [])
        with self.assertRaises(IndexError):
            repo.Resolution("1", [])

    def test_the_sdist_rule_is_repos(self):
        names = ["a/b", "x", "", ".", "./a/b", "/a/b/c", "C:/x/y", "a/../b", "a\\b\\c", "a//b", "a/./b/..", "../a",
                 "a/b/", "top/", "top", "/", "//", "C:\\top\\x", "top/C:/x", "a/b/../../..", "\\\\server\\share\\x",
                 "top/./././x", "top/x/./y", "top/.hidden", "top/..hidden", "top/a..b"]
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(base.top_directory_stripped(name), repo.canonical_member_path(name))

    def test_the_tail_of_the_npm_and_wheel_rules_is_repos(self):
        names = ["a", "/a", "C:/a", "//a", "..", ".", "", "a/./b", "a/b/", "///C:/a", "C:/C:/a", "a/../../b"]
        for name in names:
            with self.subTest(name=name):
                self.assertEqual(base.finish_member_path(name), repo.canonical_member_path(name, "wheel"))
        # (but pip resolves a `..` that stays in the folder, where cargo, go and yauzl refuse it: BR-4, F-11)
        self.assertEqual(base.finish_member_path("a/../b"), (None, "path contains '..'"))
        self.assertEqual(repo.canonical_member_path("a/../b", "wheel"), ("b", None))


class RootStrippedTests(unittest.TestCase):
    def test_a_member_must_sit_under_the_root(self):
        r = "mod@v1.0.0/"
        self.assertEqual(base.root_stripped("mod@v1.0.0/a/b.go", r), ("a/b.go", None))
        self.assertEqual(base.root_stripped("mod@v1.0.0\\a\\b.go", r), ("a/b.go", None))
        self.assertEqual(base.root_stripped("mod@v1.0.0/", r), (None, None))
        self.assertEqual(base.root_stripped("mod@v1.0.0//a.go", r), ("a.go", None))
        self.assertEqual(base.root_stripped("mod@v1.0.0/../x", r), (None, "path contains '..'"))
        self.assertEqual(base.root_stripped("mod@v1.0.0/C:/x", r), ("x", None))
        for outside in ("a.go", "mod@v1.0.1/a.go", "mod@v1.0.0", "Mod@v1.0.0/a.go", "/mod@v1.0.0/a.go",
                        "./mod@v1.0.0/a.go", "x/mod@v1.0.0/a.go", ""):
            self.assertEqual(base.root_stripped(outside, r), (None, "member outside the archive's root directory"),
                             outside)

    def test_an_empty_root_matches_nothing(self):
        for root in ("", None):
            self.assertEqual(base.root_stripped("a/b", root), (None, "member outside the archive's root directory"))


class ShowAndNameTests(unittest.TestCase):
    def test_show_escapes_and_cuts(self):
        self.assertEqual(base.show("abc"), "'abc'")
        self.assertEqual(base.show("\x1b[31m\u202e"), repr("\x1b[31m\u202e"))
        self.assertNotIn("\x1b", base.show("\x1b[31m"))
        self.assertNotIn("\u202e", base.show("a\u202eb"))
        self.assertEqual(base.show("x" * 120), repr("x" * 120))
        self.assertEqual(base.show("x" * 121), repr("x" * 120) + "…")
        self.assertEqual(base.show("x" * 50, limit=10), repr("x" * 10) + "…")
        self.assertEqual(base.show(5), "'5'")
        self.assertEqual(base.show(None), "'None'")
        self.assertEqual(base.show(b"ab"), repr("b'ab'"))
        for ch in ("\udcff", "\U0010ffff", "\u202e", "\x00", "'", "\"", "\\"):               # (a character whose repr is several)
            for limit in (120, 60, 10, 1):
                with self.subTest(ch=ascii(ch), limit=limit):
                    shown = base.show(ch * 500, limit=limit)
                    self.assertLessEqual(len(shown), limit + 3)                       # the quotes and the ellipsis
                    self.assertTrue(shown.endswith("…") and shown.isprintable())
        self.assertEqual(base.show("\udcff" * 3), repr("\udcff" * 3))                 # (short enough: all of it, no ellipsis)
        # (the cut is as long as the limit allows: a message that quotes a hostile name keeps all it can)
        self.assertEqual(base.show("\U0010ffff" * 500), repr("\U0010ffff" * 12) + "…")
        self.assertEqual(base.show("\udcff" * 500), repr("\udcff" * 20) + "…")
        self.assertEqual(base.show("\x00" * 500), repr("\x00" * 30) + "…")
        self.assertEqual(base.show("", limit=0), "''")
        self.assertEqual(base.show("abc", limit=0), "''…")
        self.assertTrue(base.show("\ud800").isprintable())

    def test_ascii_name(self):
        ok = re.compile(r"[a-z]")
        self.assertEqual(base.ascii_name("abc", "name", ok, 3), "abc")
        for bad, text in ((None, "empty name"), ("", "empty name"), (5, "empty name"),
                          ("abcd", "name longer than 3 characters"), ("aB", "invalid name 'aB'"),
                          ("a b", "invalid name 'a b'")):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(base.SpecError, "^" + re.escape(text) + "$"):
                    base.ascii_name(bad, "name", ok, 3)
        with self.assertRaisesRegex(base.SpecError, "^eco: invalid name 'A'$"):
            base.ascii_name("A", "name", ok, 3, "eco")
        with self.assertRaisesRegex(base.SpecError, "^eco: empty name$"):
            base.ascii_name("", "name", ok, 3, "eco")
        with self.assertRaisesRegex(base.SpecError, "^eco: name longer than 1 characters$"):
            base.ascii_name("ab", "name", ok, 1, "eco")
        message = ""
        try:
            base.ascii_name("a\x1b\u202eb", "name", ok, 9)
        except base.SpecError as exc:
            message = str(exc)
        self.assertTrue(message.isprintable() and "\x1b" not in message)

    def test_the_tables_are_what_the_contract_needs(self):
        for table in (base.HOSTILE_NAMES, base.HOSTILE_VERSIONS):
            self.assertEqual(len(set(table)), len(table), "a case twice")
            self.assertTrue(all(isinstance(x, str) for x in table))
        self.assertIn("..", base.HOSTILE_NAMES)
        self.assertIn("a\x00b", base.HOSTILE_NAMES)
        self.assertTrue(any(len(x) >= 5000 for x in base.HOSTILE_NAMES))
        self.assertNotIn("+", "".join(base.HOSTILE_VERSIONS))
        self.assertFalse(any(v.startswith("v") for v in base.HOSTILE_VERSIONS))


class ValueClassTests(unittest.TestCase):
    def test_run_targets_are_three_frozensets(self):
        t = base.RunTargets(["a", "a"], ("b",), iter(["c"]))
        self.assertEqual((t.entries, t.install_scripts, t.startup), (frozenset("a"), frozenset("b"), frozenset("c")))
        self.assertEqual(base.RunTargets(), base.RunTargets((), (), ()))
        self.assertEqual(base.RunTargets()._fields, ("entries", "install_scripts", "startup"))
        self.assertEqual(tuple(base.RunTargets()), (frozenset(), frozenset(), frozenset()))
        with self.assertRaises(AttributeError):
            base.RunTargets().extra = 1

    def test_declared_is_a_name_and_a_tuple(self):
        d = base.Declared("x", ["a", "b"])
        self.assertEqual((d.name, d.dependencies), ("x", ("a", "b")))
        self.assertEqual(base.Declared(), base.Declared(None, ()))
        self.assertEqual(base.Declared()._fields, ("name", "dependencies", "specs", "aliases"))
        self.assertEqual((d.specs, d.aliases), ({}, {}))
        with self.assertRaises(AttributeError):
            base.Declared().extra = 1

    def test_declared_keeps_each_dependencys_spec_and_its_rename_next_to_its_name(self):
        d = base.Declared("x", ["a", "b"], {"a": "^1.2", "b": None}, {"b": "local-b"})
        self.assertEqual((d.specs, d.aliases), ({"a": "^1.2", "b": None}, {"b": "local-b"}))
        self.assertEqual(d, base.Declared("x", ("a", "b"), {"b": None, "a": "^1.2"}, {"b": "local-b"}))
        self.assertNotEqual(d, base.Declared("x", ["a", "b"], {"a": "^1.3", "b": None}, {"b": "local-b"}))
        self.assertNotEqual(d, base.Declared("x", ["a", "b"], {"a": "^1.2", "b": None}))

    def test_declared_copies_what_it_is_given_so_a_later_change_changes_nothing(self):
        specs, aliases = {"a": "1"}, {"a": "z"}
        d = base.Declared("x", ["a"], specs, aliases)
        specs["a"], aliases["a"] = "2", "y"
        specs["extra"] = "3"
        self.assertEqual((d.specs, d.aliases), ({"a": "1"}, {"a": "z"}))

    def test_a_spec_or_a_rename_for_a_name_that_is_not_a_dependency_is_a_bug_and_says_so(self):
        for kwargs in ({"specs": {"b": "1"}}, {"aliases": {"b": "z"}}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "which is not a dependency"):
                base.Declared("x", ["a"], **kwargs)
        with self.assertRaisesRegex(ValueError, r"a spec for '\\u202e', which"):
            base.Declared("x", ["a"], {"\u202e": "1"})

    def test_a_spec_is_text_or_none_and_a_rename_is_text(self):
        for kwargs in ({"specs": {"a": 1}}, {"specs": {"a": b"1"}}, {"aliases": {"a": None}}, {"aliases": {"a": 1}}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "is not text"):
                base.Declared("x", ["a"], **kwargs)
        self.assertEqual(base.Declared("x", ["a"], {"a": None}).specs, {"a": None})
        self.assertEqual(base.Declared("x", ["a"], {"a": ""}).specs, {"a": ""})


# ---------------------------------------------------------------------------
# The fetch seam
# ---------------------------------------------------------------------------

class Recorder:
    """A transport that answers from a table, remembers what it was asked, and can be told to misbehave."""

    def __init__(self, answers=None, default=b"{}"):
        self.answers, self.default, self.calls = answers or {}, default, []
        self.lock = threading.Lock()

    def __call__(self, url, **kwargs):
        with self.lock:
            self.calls.append((url, kwargs))
        answer = self.answers.get(url, self.default)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(url, **kwargs)
        return answer


class Clock:
    def __init__(self):
        self.now, self.slept, self.lock = 0.0, [], threading.Lock()

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        with self.lock:
            self.slept.append(seconds)


class FetchRuleTests(unittest.TestCase):
    def setUp(self):
        self.eco = Toy()
        self.rec = Recorder()
        self.clock = Clock()
        self.fetch = base.Fetch(self.eco, self.rec, clock=self.clock, sleep=self.clock.sleep)

    def refused(self, url):
        with self.assertRaises(base.FetchError) as caught:
            self.fetch.check_url(url)
        message = str(caught.exception)
        self.assertTrue(message.isprintable(), repr(message))
        return message

    def test_https_to_a_declared_host_passes_and_comes_back_unchanged(self):
        for url in ("https://reg.example/x", "https://REG.example/x", "https://reg.example:443/x",
                    "https://dl.example/a/b?c=d#e"):
            with self.subTest(url=url):
                self.assertIs(self.fetch.check_url(url), url)

    def test_the_url_may_use_every_printable_ascii_character_and_be_2048_long(self):
        for url in ("https://reg.example/!", "https://reg.example/~", "https://reg.example/!~", "https://reg.example/%7e%21"):
            with self.subTest(url=url):
                self.assertIs(self.fetch.check_url(url), url)
        fits = "https://reg.example/" + "x" * (2048 - len("https://reg.example/"))
        self.assertEqual(len(fits), 2048)
        self.assertIs(self.fetch.check_url(fits), fits)
        self.refused(fits + "x")
        self.assertEqual(base.MAX_URL_LENGTH, 2048)
        for edge in (" ", "\x7f", "\x20", "\x80"):
            self.refused("https://reg.example/a" + edge + "b")

    def test_everything_else_is_refused_before_a_request(self):
        for url in ("http://reg.example/x", "ftp://reg.example/x", "file:///etc/passwd", "//reg.example/x",
                    "reg.example/x", "https:/reg.example/x", "https:///x", "https://", "javascript:alert(1)",
                    "https://evil.example/x", "https://reg.example.evil.example/x", "https://evilreg.example/x",
                    "https://reg.example:444/x", "https://reg.example:0/x", "https://reg.example:99999/x",
                    "https://reg.example:abc/x", "https://u@reg.example/x", "https://u:p@reg.example/x",
                    "https://reg.example@evil.example/x", "https://reg.example\\@evil.example/x",
                    "https://evil.example\\.reg.example/x", "https://reg.example\\x", "https://127.0.0.1/x",
                    "https://[::1]/x", "https://2130706433/x", "https://reg.example /x", "https://reg.example/x y",
                    "https://reg.example/\n", "https://reg.example/\x00", "https://reg.example/\x1b[31m",
                    "https://reg.example/\x7f", "https://reg.example/\u202e", "https://reg.example/é",
                    "https://reg.example/\ud800", "https://rég.example/x", "https://reg.example\u3002evil/x",
                    "", " ", "https://reg.example/" + "x" * 3000, None, 5, b"https://reg.example/x",
                    ["https://reg.example/x"], "HTTPS://reg.example:abc"):
            with self.subTest(url=str(url)[:50]):
                self.refused(url)
                with self.assertRaises(base.FetchError):
                    self.fetch.json(url)
        self.assertEqual(self.rec.calls, [])
        self.assertEqual(self.fetch.requests, [])

    def test_a_refusal_names_what_was_wrong_and_shows_the_url_as_an_escaped_cut_string(self):
        self.assertRegex(self.refused("http://reg.example/x"), r"^non-https registry URL blocked \('http'\)")
        self.assertRegex(self.refused("//reg.example/x"), r"\('no scheme'\)")
        self.assertRegex(self.refused("https://evil.example/x"), r"^registry host not allowlisted: 'evil.example'$")
        self.assertRegex(self.refused("https://u:p@reg.example/x"), r"^registry URL with credentials blocked")
        self.assertRegex(self.refused("https://reg.example:abc/x"), r"^unparseable registry URL")
        self.assertRegex(self.refused(""), r"empty, not text, or too long")
        self.assertRegex(self.refused("https://reg.example/" + "x" * 3000), r"empty, not text, or too long")
        long_bad = self.refused("http://reg.example/" + "x" * 1000)
        self.assertLess(len(long_bad), 400)
        painted = self.refused("https://reg.example/\x1b[2J\u202e")
        self.assertNotIn("\x1b", painted)
        self.assertNotIn("\u202e", painted)
        self.assertRegex(painted, r"characters that do not belong")

    def test_a_declared_host_with_a_port_matches_only_that_port(self):
        eco = Toy()
        eco.hosts = frozenset({"reg.example", "dl.example:8443"})
        fetch = base.Fetch(eco, self.rec)
        fetch.check_url("https://dl.example:8443/x")
        for url in ("https://dl.example/x", "https://dl.example:443/x", "https://dl.example:8444/x"):
            with self.assertRaises(base.FetchError, msg=url):
                fetch.check_url(url)
        fetch.check_url("https://reg.example:443/x")

    def test_the_hosts_are_lowercased_and_kept_as_a_set(self):
        eco = Toy()
        eco.hosts = ["Reg.Example", "DL.example"]
        fetch = base.Fetch(eco, self.rec)
        self.assertEqual(fetch.hosts, frozenset({"reg.example", "dl.example"}))
        eco.rate = {"Reg.Example": 2}
        self.assertEqual(base.Fetch(eco, self.rec).rate, {"reg.example": 2.0})

    def test_the_transport_gets_the_request_and_the_redirect_check(self):
        self.rec.answers["https://reg.example/a"] = b'{"a": 1}'
        self.assertEqual(self.fetch.json("https://reg.example/a", accept="application/json"), {"a": 1})
        url, kw = self.rec.calls[0]
        self.assertEqual((url, kw["max_bytes"], kw["accept"], kw["timeout"]),
                         ("https://reg.example/a", base.MAX_DOCUMENT_BYTES, "application/json", base.METADATA_TIMEOUT))
        self.assertEqual(kw["check_redirect"], self.fetch.check_url)
        self.fetch.bytes("https://dl.example/b")
        kw = self.rec.calls[1][1]
        self.assertEqual((kw["max_bytes"], kw["timeout"], kw["accept"]),
                         (base.MAX_ARTIFACT_BYTES, base.DOWNLOAD_TIMEOUT, None))
        self.fetch.text("https://reg.example/t", max_bytes=10)
        kw = self.rec.calls[2][1]
        self.assertEqual((kw["max_bytes"], kw["timeout"]), (10, base.METADATA_TIMEOUT))
        self.assertEqual(self.fetch.requests, ["https://reg.example/a", "https://dl.example/b", "https://reg.example/t"])
        self.assertEqual(set(kw), {"max_bytes", "accept", "timeout", "check_redirect"})

    def test_the_redirect_check_the_transport_is_given_refuses_what_the_seam_refuses(self):
        seen = []

        def following(url, *, check_redirect, **kw):
            for hop in ("https://reg.example/next", "http://reg.example/down", "https://evil.example/x",
                        "file:///etc/passwd", "https://reg.example@evil.example/"):
                try:
                    check_redirect(hop)
                    seen.append((hop, "followed"))
                except base.FetchError:
                    seen.append((hop, "blocked"))
            return b"{}"

        self.rec.answers["https://reg.example/r"] = following
        self.fetch.json("https://reg.example/r")
        self.assertEqual(seen, [("https://reg.example/next", "followed"), ("http://reg.example/down", "blocked"),
                                ("https://evil.example/x", "blocked"), ("file:///etc/passwd", "blocked"),
                                ("https://reg.example@evil.example/", "blocked")])

    def test_what_the_transport_raises_comes_out_as_a_fetch_error_without_the_text_it_raised_with(self):
        for failure in (OSError("\x1b[2J secret"), TimeoutError("t"), ConnectionResetError("r"), ValueError("\u202e"),
                        http.client.IncompleteRead(b"ab"), http.client.BadStatusLine("\x00")):
            with self.subTest(failure=type(failure).__name__):
                self.rec.answers["https://reg.example/f"] = failure
                with self.assertRaises(base.FetchError) as caught:
                    self.fetch.bytes("https://reg.example/f")
                text = str(caught.exception)
                self.assertIn(type(failure).__name__, text)
                self.assertNotIn("secret", text)
                self.assertTrue(text.isprintable())
                self.assertIs(caught.exception.__cause__, None)

    def test_a_fetch_error_the_transport_raises_keeps_its_status(self):
        err = base.FetchError("HTTP 404")
        err.status = 404
        self.rec.answers["https://reg.example/gone"] = err
        with self.assertRaises(base.FetchError) as caught:
            self.fetch.json("https://reg.example/gone")
        self.assertIs(caught.exception, err)
        self.assertEqual(caught.exception.status, 404)

    def test_other_exceptions_are_bugs_and_are_not_swallowed(self):
        for failure in (KeyError("k"), RuntimeError("r"), AttributeError("a"), RecursionError()):
            self.rec.answers["https://reg.example/bug"] = failure
            with self.assertRaises(type(failure)):
                self.fetch.bytes("https://reg.example/bug")

    def test_a_transport_that_answers_with_something_else_than_bytes_is_refused(self):
        for answer in ("text", None, 5, ["x"], {"a": 1}):
            self.rec.answers["https://reg.example/w"] = answer
            with self.assertRaisesRegex(base.FetchError, "^the transport gave no bytes for"):
                self.fetch.bytes("https://reg.example/w")
        self.rec.answers["https://reg.example/w"] = bytearray(b"ok")
        self.assertEqual(self.fetch.bytes("https://reg.example/w"), b"ok")
        self.assertIs(type(self.fetch.bytes("https://reg.example/w")), bytes)

    def test_a_body_over_the_budget_is_refused_even_if_the_transport_let_it_through(self):
        self.rec.answers["https://reg.example/big"] = b"x" * 11
        with self.assertRaisesRegex(base.FetchError, "^response exceeds 1MB budget"):
            self.fetch.bytes("https://reg.example/big", max_bytes=10)
        self.assertEqual(self.fetch.bytes("https://reg.example/big", max_bytes=11), b"x" * 11)
        self.rec.answers["https://reg.example/big"] = b"x" * (5 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(base.FetchError, "^response exceeds 5MB budget"):
            self.fetch.json("https://reg.example/big")
        with self.assertRaisesRegex(base.FetchError, "^response exceeds 5MB budget"):
            self.fetch.text("https://reg.example/big")
        with self.assertRaisesRegex(base.FetchError, "^response exceeds 5MB budget"):
            self.fetch.json_lines("https://reg.example/big")
        self.assertEqual(len(self.fetch.bytes("https://reg.example/big")), 5 * 1024 * 1024 + 1)

    def test_text_is_utf8(self):
        self.rec.answers["https://reg.example/t"] = "héllo \u202e".encode("utf-8")
        self.assertEqual(self.fetch.text("https://reg.example/t"), "héllo \u202e")
        self.rec.answers["https://reg.example/t"] = b"\xff\xfe"
        with self.assertRaisesRegex(base.FetchError, "^registry response is not UTF-8 text"):
            self.fetch.text("https://reg.example/t")

    def test_json_is_bounded_and_every_failure_is_a_fetch_error(self):
        self.rec.answers["https://reg.example/j"] = b'{"a": [1, 2, {"b": null}]}'
        self.assertEqual(self.fetch.json("https://reg.example/j"), {"a": [1, 2, {"b": None}]})
        for body, text in ((b"[" * 5000, "too deeply nested"), (b"{", "invalid JSON"), (b"", "invalid JSON"),
                           (b"\xff\xff\xff", "invalid JSON"), (b'{"a": ' + b"9" * 6000 + b"}", "invalid JSON"),
                           (b"not json", "invalid JSON")):
            with self.subTest(body=body[:20]):
                self.rec.answers["https://reg.example/j"] = body
                with self.assertRaisesRegex(base.FetchError, text):
                    self.fetch.json("https://reg.example/j")

    def test_json_lines_is_one_value_per_line_and_a_bad_line_fails_the_whole_document(self):
        url = "https://reg.example/l"
        self.rec.answers[url] = b'{"a": 1}\n\n  \n[2]\r\n"x"\n{"b": {"c": 3}}'
        self.assertEqual(self.fetch.json_lines(url), [{"a": 1}, [2], "x", {"b": {"c": 3}}])
        self.rec.answers[url] = b""
        self.assertEqual(self.fetch.json_lines(url), [])
        self.rec.answers[url] = b'\n\n{"a": 1}\n'
        self.assertEqual(self.fetch.json_lines(url), [{"a": 1}])
        for body in (b'{"a": 1}\nnot json\n{"b": 2}', b'{"a": 1}\n{', b'{"a": 1}\n' + b"[" * 5000, b'{"a": 1}\n\xff'):
            with self.subTest(body=body[:20]):
                self.rec.answers[url] = body
                with self.assertRaises(base.FetchError):
                    self.fetch.json_lines(url)

    def test_json_lines_may_start_with_an_empty_line_and_keeps_what_follows_it_separate(self):
        url = "https://reg.example/l"
        self.rec.answers[url] = b'\n{"a": 1}\n{"b": 2}'
        self.assertEqual(self.fetch.json_lines(url), [{"a": 1}, {"b": 2}])
        self.rec.answers[url] = b'\n{"a": 1}\n{"b": 2}\n'
        self.assertEqual(self.fetch.json_lines(url), [{"a": 1}, {"b": 2}])

    def test_json_lines_select_turns_each_line_into_what_is_kept_and_none_drops_it(self):
        url = "https://reg.example/l"
        self.rec.answers[url] = b'{"a": 1}\n\n{"a": null}\n{"a": 0}\n{"a": 3}\n{"b": 4}'
        self.assertEqual(self.fetch.json_lines(url), [{"a": 1}, {"a": None}, {"a": 0}, {"a": 3}, {"b": 4}])
        self.assertEqual(self.fetch.json_lines(url, select=lambda v: v.get("a")), [1, 0, 3])          # (None drops; 0 is kept)
        seen = []
        self.fetch.json_lines(url, select=lambda v: seen.append(v))
        self.assertEqual(len(seen), 5)                                                                 # (each line, once)
        self.assertEqual(self.fetch.json_lines(url, select=lambda v: None), [])

    def test_a_select_that_refuses_a_line_fails_the_document_as_it_says(self):
        url = "https://reg.example/l"
        self.rec.answers[url] = b'{"a": 1}\n{"a": 2}'

        def select(v):
            if v["a"] == 2:
                raise base.FetchError("select: line 2 is wrong")
            return v
        with self.assertRaisesRegex(base.FetchError, "^select: line 2 is wrong$"):
            self.fetch.json_lines(url, select=select)

    def test_a_line_over_the_line_limit_fails_the_document(self):
        url = "https://reg.example/l"
        fits = b'{"a": "' + b"x" * (base.MAX_LINE_BYTES - 20) + b'"}'
        self.assertLessEqual(len(fits), base.MAX_LINE_BYTES)
        self.rec.answers[url] = fits + b"\n" + fits
        self.assertEqual(len(self.fetch.json_lines(url, max_bytes=3 * 1024 * 1024)), 2)
        exact = b'{"a": "' + b"x" * (base.MAX_LINE_BYTES - 9) + b'"}'
        self.assertEqual(len(exact), base.MAX_LINE_BYTES)
        self.rec.answers[url] = exact
        self.assertEqual(len(self.fetch.json_lines(url, max_bytes=3 * 1024 * 1024)), 1)
        self.rec.answers[url] = b'{"a": "' + b"x" * (base.MAX_LINE_BYTES - 8) + b'"}'
        with self.assertRaisesRegex(base.FetchError, "^a line of the registry response is over 1024KB"):
            self.fetch.json_lines(url, max_bytes=3 * 1024 * 1024)

    def test_requests_are_remembered_in_order_and_only_when_they_were_made(self):
        self.fetch.json("https://reg.example/1")
        with self.assertRaises(base.FetchError):
            self.fetch.json("https://evil.example/2")
        self.fetch.json("https://dl.example/3")
        self.assertEqual(self.fetch.requests, ["https://reg.example/1", "https://dl.example/3"])
        self.assertEqual([c[0] for c in self.rec.calls], self.fetch.requests)


class RateTests(unittest.TestCase):
    def setUp(self):
        self.eco = Toy()
        self.rec = Recorder()
        self.clock = Clock()
        self.fetch = base.Fetch(self.eco, self.rec, clock=self.clock, sleep=self.clock.sleep)

    def test_a_rated_host_is_asked_no_faster_than_its_interval(self):
        for i in range(4):
            self.fetch.json("https://reg.example/%d" % i)
        self.assertEqual(self.clock.slept, [0.5, 1.0, 1.5])

    def test_time_passing_pays_for_the_wait(self):
        self.fetch.json("https://reg.example/1")
        self.clock.now = 0.3
        self.fetch.json("https://reg.example/2")
        self.assertEqual(self.clock.slept, [0.2])
        self.clock.now = 5.0
        self.fetch.json("https://reg.example/3")
        self.assertEqual(self.clock.slept, [0.2])
        self.fetch.json("https://reg.example/4")
        self.assertEqual(self.clock.slept, [0.2, 0.5])

    def test_a_host_without_a_rate_is_never_waited_for_and_hosts_do_not_share_a_turn(self):
        for i in range(3):
            self.fetch.json("https://dl.example/%d" % i)
        self.assertEqual(self.clock.slept, [])
        self.fetch.json("https://reg.example/1")
        self.fetch.json("https://dl.example/9")
        self.assertEqual(self.clock.slept, [])

    def test_a_refused_url_does_not_use_up_a_turn(self):
        for url in ("http://reg.example/x", "https://evil.example/x"):
            with self.assertRaises(base.FetchError):
                self.fetch.json(url)
        self.fetch.json("https://reg.example/1")
        self.assertEqual(self.clock.slept, [])

    def test_the_rate_is_by_host_whatever_the_case_and_the_path(self):
        self.fetch.json("https://REG.example/a")
        self.fetch.json("https://reg.example/b?c=d")
        self.assertEqual(self.clock.slept, [0.5])

    def test_a_zero_or_missing_interval_means_no_wait(self):
        eco = Toy()
        eco.rate = {"reg.example": 0}
        fetch = base.Fetch(eco, self.rec, clock=self.clock, sleep=self.clock.sleep)
        fetch.json("https://reg.example/1")
        fetch.json("https://reg.example/2")
        self.assertEqual(self.clock.slept, [])

    def test_the_default_clock_and_sleep_are_the_real_ones(self):
        import time
        fetch = base.Fetch(self.eco, self.rec)
        self.assertIs(fetch._clock, time.monotonic)
        self.assertIs(fetch._sleep, time.sleep)

    def test_threads_each_get_their_own_turn(self):
        done, errors = [], []

        def work(i):
            try:
                self.fetch.json("https://reg.example/%d" % i)
                done.append(i)
            except BaseException as exc:
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual((errors, sorted(done)), ([], list(range(8))))
        self.assertEqual(sorted(self.clock.slept), [0.5 * i for i in range(1, 8)])
        self.assertEqual(len(self.fetch.requests), 8)


# ---------------------------------------------------------------------------
# The download budget (P-9: the artifacts of a release downloaded from several threads)
# ---------------------------------------------------------------------------

class DownloadBudgetTests(unittest.TestCase):
    def test_reserve_takes_what_is_left_and_says_so(self):
        b = base.DownloadBudget(100)
        self.assertEqual((b.total, b.left), (100, 100))
        self.assertTrue(b.reserve(60))
        self.assertEqual(b.left, 40)
        self.assertTrue(b.reserve(40))                         # (exactly what is left)
        self.assertEqual(b.left, 0)
        self.assertFalse(b.reserve(1))
        self.assertTrue(b.reserve(0))                          # (nothing is always there)
        self.assertEqual(b.left, 0)

    def test_a_reservation_that_does_not_fit_takes_nothing(self):
        b = base.DownloadBudget(100)
        self.assertFalse(b.reserve(101))
        self.assertEqual(b.left, 100)
        self.assertTrue(b.reserve(100))

    def test_what_is_given_back_can_be_taken_again_and_never_exceeds_the_total(self):
        b = base.DownloadBudget(100)
        b.reserve(70)
        b.give_back(20)
        self.assertEqual(b.left, 50)
        b.give_back(50)                                        # (back to the whole)
        self.assertEqual(b.left, 100)
        with self.assertRaisesRegex(ValueError, "more was given back than was taken"):
            b.give_back(1)
        self.assertEqual(b.left, 100)
        b.give_back(0)
        self.assertTrue(base.DownloadBudget(0).reserve(0))

    def test_numbers_that_are_not_byte_counts_are_refused(self):
        for bad in (-1, 1.5, "1", None, True, False, b"1", float("nan")):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    base.DownloadBudget(bad)
                b = base.DownloadBudget(10)
                with self.assertRaises(ValueError):
                    b.reserve(bad)
                with self.assertRaises(ValueError):
                    b.give_back(bad)
                self.assertEqual(b.left, 10)

    def test_threads_that_all_want_the_last_share_cannot_all_have_it(self):
        for total, want, threads in ((100, 10, 16), (7, 7, 8), (1, 1, 32)):
            with self.subTest(total=total):
                b = base.DownloadBudget(total)
                gate, won = threading.Barrier(threads), []

                def work():
                    gate.wait(30)
                    won.append(b.reserve(want))

                pool = [threading.Thread(target=work) for _ in range(threads)]
                for t in pool:
                    t.start()
                for t in pool:
                    t.join(30)
                self.assertEqual(sum(won), total // want)
                self.assertEqual(len(won), threads)
                self.assertEqual(b.left, total - want * (total // want))

    def test_reserving_and_giving_back_from_many_threads_ends_where_it_began(self):
        b = base.DownloadBudget(50)
        errors = []

        def work():
            try:
                for _ in range(500):
                    if b.reserve(7):
                        b.give_back(7)
            except BaseException as exc:
                errors.append(exc)

        pool = [threading.Thread(target=work) for _ in range(8)]
        for t in pool:
            t.start()
        for t in pool:
            t.join(60)
        self.assertEqual((errors, b.left), ([], 50))


class FetchBudgetTests(unittest.TestCase):
    URL = "https://dl.example/pkg.tgz"

    def setUp(self):
        self.eco = Toy()
        self.rec = Recorder({self.URL: b"x" * 30, "https://dl.example/small": b"s" * 5})
        self.clock = Clock()
        self.fetch = base.Fetch(self.eco, self.rec, clock=self.clock, sleep=self.clock.sleep)
        self.budget = base.DownloadBudget(100)

    def test_a_download_is_charged_for_what_it_received_and_the_rest_comes_back(self):
        self.assertEqual(self.fetch.bytes(self.URL, max_bytes=80, budget=self.budget), b"x" * 30)
        self.assertEqual(self.budget.left, 70)

    def test_while_it_runs_it_holds_its_whole_share(self):
        seen = []

        def transport(url, **kwargs):
            seen.append(self.budget.left)
            return b"x" * 5

        fetch = base.Fetch(self.eco, transport, clock=self.clock, sleep=self.clock.sleep)
        fetch.bytes(self.URL, max_bytes=80, budget=self.budget)
        self.assertEqual((seen, self.budget.left), ([20], 95))

    def test_a_spent_budget_is_a_fetch_error_and_no_request_is_made(self):
        self.budget.reserve(90)
        with self.assertRaisesRegex(base.FetchError, r"^the release's download budget is spent: 'https://dl.example/pkg.tgz'$"):
            self.fetch.bytes(self.URL, max_bytes=11, budget=self.budget)
        self.assertEqual((self.rec.calls, self.fetch.requests, self.budget.left), ([], [], 10))
        self.assertEqual(self.fetch.bytes("https://dl.example/small", max_bytes=10, budget=self.budget), b"s" * 5)   # (what is left is enough)
        self.assertEqual((len(self.rec.calls), self.budget.left), (1, 5))

    def test_a_request_that_fails_gives_the_whole_share_back(self):
        for what in (base.FetchError("no"), OSError("down"), http.client.HTTPException("x"), ValueError("v")):
            with self.subTest(what=type(what).__name__):
                fetch = base.Fetch(self.eco, Recorder({self.URL: what}), clock=self.clock, sleep=self.clock.sleep)
                with self.assertRaises(base.FetchError):
                    fetch.bytes(self.URL, max_bytes=80, budget=self.budget)
                self.assertEqual(self.budget.left, 100)

    def test_an_answer_that_is_not_bytes_gives_the_share_back(self):
        fetch = base.Fetch(self.eco, Recorder({self.URL: "text"}), clock=self.clock, sleep=self.clock.sleep)
        with self.assertRaisesRegex(base.FetchError, "gave no bytes"):
            fetch.bytes(self.URL, max_bytes=80, budget=self.budget)
        self.assertEqual(self.budget.left, 100)

    def test_a_body_over_the_limit_is_charged_the_limit(self):
        fetch = base.Fetch(self.eco, Recorder({self.URL: b"x" * 90}), clock=self.clock, sleep=self.clock.sleep)
        with self.assertRaisesRegex(base.FetchError, "exceeds"):
            fetch.bytes(self.URL, max_bytes=80, budget=self.budget)
        self.assertEqual(self.budget.left, 20)

    def test_a_signal_in_the_transport_gives_the_share_back_too(self):
        def transport(url, **kwargs):
            raise KeyboardInterrupt

        fetch = base.Fetch(self.eco, transport, clock=self.clock, sleep=self.clock.sleep)
        with self.assertRaises(KeyboardInterrupt):
            fetch.bytes(self.URL, max_bytes=80, budget=self.budget)
        self.assertEqual(self.budget.left, 100)

    def test_a_refused_url_takes_nothing_and_neither_does_a_download_without_a_budget(self):
        for url in ("http://dl.example/x", "https://evil.example/x", ""):
            with self.assertRaises(base.FetchError):
                self.fetch.bytes(url, max_bytes=80, budget=self.budget)
        self.assertEqual(self.budget.left, 100)
        self.assertEqual(self.fetch.bytes(self.URL, max_bytes=80), b"x" * 30)
        self.assertEqual(self.budget.left, 100)

    def test_a_spent_budget_does_not_use_up_a_turn_of_a_rated_host(self):
        self.budget.reserve(100)
        for _ in range(3):
            with self.assertRaises(base.FetchError):
                self.fetch.bytes("https://reg.example/x", max_bytes=10, budget=self.budget)
        self.budget.give_back(100)
        self.fetch.bytes("https://reg.example/x", max_bytes=10, budget=self.budget)
        self.assertEqual(self.clock.slept, [])

    def test_two_downloads_that_cannot_both_fit_are_not_both_started(self):
        started, release, results = threading.Event(), threading.Event(), {}

        def transport(url, **kwargs):
            started.set()
            release.wait(30)
            return b"y" * 10

        fetch = base.Fetch(self.eco, transport, clock=self.clock, sleep=self.clock.sleep)

        def first():
            results["first"] = fetch.bytes("https://dl.example/a", max_bytes=60, budget=self.budget)

        t = threading.Thread(target=first)
        t.start()
        self.assertTrue(started.wait(30))
        try:
            with self.assertRaisesRegex(base.FetchError, "download budget is spent"):
                fetch.bytes("https://dl.example/b", max_bytes=60, budget=self.budget)       # (the first still holds its 60)
            self.assertEqual(self.budget.left, 40)
        finally:
            release.set()
            t.join(30)
        self.assertEqual((results, self.budget.left), ({"first": b"y" * 10}, 90))
        self.assertEqual(fetch.requests, ["https://dl.example/a"])

    def test_json_and_text_do_not_take_a_budget(self):
        import inspect
        for name in ("json", "text", "json_lines"):
            self.assertNotIn("budget", inspect.signature(getattr(base.Fetch, name)).parameters, name)


# ---------------------------------------------------------------------------
# The Ecosystem defaults, and the registry of modules
# ---------------------------------------------------------------------------

class Bare(base.Ecosystem):
    id = "bare"

    def check_name(self, name):
        if not isinstance(name, str) or not re.fullmatch(r"(@[a-z]+/)?[a-z]+", name):
            raise base.SpecError("bare: invalid name")
        return name


class DefaultsTests(unittest.TestCase):
    def setUp(self):
        self.eco = Bare()

    def test_what_a_module_must_write_raises_not_implemented(self):
        eco = base.Ecosystem()
        for call in (lambda: eco.check_name("x"), lambda: eco.resolve("x", None, None),
                     lambda: eco.member_path("k", "x")):
            with self.assertRaises(NotImplementedError):
                call()

    def test_the_defaults_say_nothing_is_published_and_nothing_runs(self):
        eco = base.Ecosystem()
        self.assertIsNone(eco.verify(b"", {}, "n", "1"))
        self.assertIsNone(eco.container("x.zip"))
        self.assertIs(eco.links_extracted("any"), True)
        self.assertEqual(eco.run_targets("k", {}, []), base.RunTargets())
        self.assertEqual(eco.declared("k", {}, []), base.Declared())
        self.assertIsNone(eco.archive_root(None, {}))
        self.assertIsNone(eco.dependencies(None, None))
        self.assertIsNone(eco.discover(None, 10, None))
        self.assertIsNone(eco.popular_names())
        self.assertEqual((eco.id, eco.title, eco.hosts, eco.artifact_kinds, eco.rate, eco.manifest_names),
                         ("", "", frozenset(), (), {}, frozenset()))

    def test_identity_is_the_checked_name(self):
        self.assertEqual(self.eco.identity("abc"), "abc")
        with self.assertRaises(base.SpecError):
            self.eco.identity("A")

    def test_check_version(self):
        for good in ("1", "1.0.0", "a_b-c.D", "1" * 100):
            self.assertEqual(self.eco.check_version(good), good)
            self.assertEqual(self.eco.check_version(" %s\t" % good), good)
        self.assertIsNone(self.eco.check_version(None))
        for bad in ("", " ", ".", "..", " .. ", "1" * 101, "1 2", "1/2", "+1", "1+2", 1, b"1", [], True):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(base.SpecError, "^bare: invalid version"):
                    self.eco.check_version(bad)

    def test_parse_spec_splits_at_the_last_at_sign_that_is_not_the_first_character(self):
        self.assertEqual(self.eco.parse_spec("abc"), ("abc", None))
        self.assertEqual(self.eco.parse_spec("abc@1.0"), ("abc", "1.0"))
        self.assertEqual(self.eco.parse_spec("  abc@1.0 "), ("abc", "1.0"))
        self.assertEqual(self.eco.parse_spec("@scope/abc"), ("@scope/abc", None))
        self.assertEqual(self.eco.parse_spec("@scope/abc@2"), ("@scope/abc", "2"))
        self.assertEqual(self.eco.parse_spec("abc@1@2".replace("@2", "")), ("abc", "1"))
        for bad in ("abc@", "abc@@1", "@", "@@", "", " ", "abc@1@2", "ab c", "@abc", "@abc@1", 5, None, b"abc"):
            with self.subTest(bad=bad):
                with self.assertRaises(base.SpecError):
                    self.eco.parse_spec(bad)
        with self.assertRaisesRegex(base.SpecError, "^bare: a spec is text$"):
            self.eco.parse_spec(5)

    def test_segment_quotes_everything(self):
        self.assertEqual(self.eco.segment("abc"), "abc")
        self.assertEqual(self.eco.segment("a/b c?d#e%f@g"), "a%2Fb%20c%3Fd%23e%25f%40g")
        self.assertEqual(self.eco.segment(5), "5")
        self.assertEqual(self.eco.segment("é"), "%C3%A9")


class RegistryOfModulesTests(unittest.TestCase):
    def test_importing_the_package_registers_nothing(self):
        import subprocess
        import sys
        out = subprocess.run([sys.executable, "-c", "from lazaret.registry import ecosystems as e; print(len(e.ECOSYSTEMS))"],
                             capture_output=True, encoding="utf-8", errors="replace", timeout=60, env=_env())
        self.assertEqual(out.stdout.strip(), "0", out.stderr)

    def test_register_and_get(self):
        with mock.patch.dict(ecosystems.ECOSYSTEMS, clear=True):
            toy = Toy()
            self.assertIs(ecosystems.register(toy), toy)
            self.assertIs(ecosystems.get("toy"), toy)
            self.assertIs(ecosystems.register(toy), toy)                      # (the same module again is fine)
            self.assertIsNone(ecosystems.get("nope"))
            self.assertIsNone(ecosystems.get(None))
            with self.assertRaisesRegex(ValueError, "already registered"):
                ecosystems.register(Toy())
            for nameless in (base.Ecosystem(), object()):
                with self.assertRaisesRegex(ValueError, "needs an id"):
                    ecosystems.register(nameless)
            self.assertEqual(list(ecosystems.ECOSYSTEMS), ["toy"])


def _env():
    import os
    env = dict(os.environ)
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env["PYTHONPATH"] = os.pathsep.join([os.path.join(here, "src")] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


if __name__ == "__main__":
    unittest.main()
