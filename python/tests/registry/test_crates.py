"""`registry/ecosystems/crates.py` (0.1.9, R-1): crates.io from recorded responses.

* The whole conformance contract (`ecosystem_contract.py`), over the real index file of `fnv`.
* The real responses (`recorded/crates/`): `fnv`'s index and archive (the `cksum` is the SHA-256 of the file, checked),
  `Inflector`'s mixed-case name (the download URL needs the index's spelling), `paste`'s manifest (a proc-macro crate with a
  build script).
* The rules that are the module's own: the index path, SemVer order, which version "latest" is, yanked versions, duplicates
  and other crates in an index file, every shape an index line can have wrong, the size bounds, and what runs.
Nothing here opens a socket."""

import hashlib
import json
import os
import unittest
from unittest import mock

from lazaret.registry.ecosystems import base, crates
from tests.registry.ecosystem_contract import EcosystemContract

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "crates")
INDEX = "https://index.crates.io/"


def recorded(name):
    with open(os.path.join(HERE, name), "rb") as fh:
        return fh.read()


def text_of(name):
    return recorded(name).decode("utf-8")


FNV_INDEX, FNV_CRATE = recorded("fnv.index"), recorded("fnv-1.0.7.crate")


def line(vers, name="demo", yanked=False, cksum=None, deps=(), **extra):
    rec = {"name": name, "vers": vers, "deps": list(deps), "cksum": cksum or hashlib.sha256(vers.encode()).hexdigest(),
           "features": {"default": []}, "yanked": yanked, "v": 2}
    rec.update(extra)
    return json.dumps(rec)


def index(*lines):
    return ("\n".join(lines) + "\n").encode()


def dep(name, kind="normal", package=None, **extra):
    d = {"name": name, "req": "^1", "features": [], "optional": False, "default_features": True, "target": None,
         "kind": kind}
    if package is not None:
        d["package"] = package
    d.update(extra)
    return d


class Served:
    """A `Fetch` over a recorded transport, remembering what the transport was asked."""

    def __init__(self, responses):
        self.calls = []
        crates_eco = crates.Crates()

        def transport(url, **kw):
            self.calls.append((url, kw))
            body = responses.get(url)
            if body is None:
                err = base.FetchError("not found")
                err.status = 404
                raise err
            return body
        self.fetch = base.Fetch(crates_eco, transport, clock=lambda: 0.0, sleep=lambda s: None)


def resolve(name, version, doc, path=None):
    eco = crates.Crates()
    served = Served({INDEX + (path or crates.index_path(name)): doc})
    return eco.resolve(name, version, served.fetch), served


class CratesContract(EcosystemContract, unittest.TestCase):
    GOOD_NAMES = ("serde", "a", "ab", "abc", "Foo_Bar", "foo-bar", "a1", "9lives", "x" * 64)
    GOOD_VERSIONS = ("1.0.0", "0.1.0-alpha.1", "1.2.3+build.5", "0.0.0", "10.20.30-rc.1.2", "1.0.0-x.7.z.92")
    GOOD_SPEC = ("fnv", "1.0.7")
    SAME_IDENTITY = (("Foo_Bar", "foo-bar"), ("serde", "SERDE"), ("a_b", "a-b"))
    DIFFERENT_IDENTITY = (("ab", "a-b"), ("foo", "fo0"), ("serde", "serde1"))
    EXTRA_BAD_NAMES = ("-a", "_a", "a" * 65, "é", "\uff41", "a.b", "a+b", "a=b", "a,b", "a'b", "a\"b")
    EXTRA_BAD_VERSIONS = ("1", "1.0", "1.0.0.0", "01.0.0", "1.0.0-", "1.0.0-01", "1.0.0+", "v1.0.0", "1.0.0-\u03b1",
                          "1.0.0+a..b", "1.0.0-a..b", "latest", "*", "^1.0", ">=1.0.0", "1.0.0 - 2.0.0", "1.x", "-1.0.0",
                          "1.-1.0", "1.0.0-" + "a" * 100)
    MISSING_VERSION = "9999.0.0"
    MEMBER_PATHS = (
        ("crate", "fnv-1.0.7/lib.rs", "fnv-1.0.7/", ("lib.rs", None)),
        ("crate", "fnv-1.0.7/src/a/b.rs", "fnv-1.0.7/", ("src/a/b.rs", None)),
        ("crate", "fnv-1.0.7\\src\\a.rs", "fnv-1.0.7/", ("src/a.rs", None)),
        ("crate", "fnv-1.0.7/.cargo-ok", "fnv-1.0.7/", (None, None)),
        ("crate", "fnv-1.0.7/a/b/.cargo-ok", "fnv-1.0.7/", (None, None)),
        ("crate", "fnv-1.0.7/.cargo-ok.rs", "fnv-1.0.7/", (".cargo-ok.rs", None)),
        ("crate", "fnv-1.0.7/.cargo_vcs_info.json", "fnv-1.0.7/", (".cargo_vcs_info.json", None)),
        ("crate", "fnv-1.0.7/../x", "fnv-1.0.7/", (None, "path contains '..'")),
        ("crate", "fnv-1.0.7/", "fnv-1.0.7/", (None, None)),
        ("crate", "other-1.0.0/lib.rs", "fnv-1.0.7/", (None, "member outside the archive's root directory")),
        ("crate", "fnv-1.0.70/lib.rs", "fnv-1.0.7/", (None, "member outside the archive's root directory")),
        ("crate", "lib.rs", "fnv-1.0.7/", (None, "member outside the archive's root directory")),
        ("crate", "fnv-1.0.7/lib.rs", None, ("lib.rs", None)),
        ("crate", "any-9/.cargo-ok", None, (None, None)),
    )

    GOOD_ARCHIVE_MEMBERS = tuple(text_of("fnv-1.0.7.members").split())

    def make(self):
        return crates.Crates()

    def responses(self):
        return {INDEX + "3/f/fnv": FNV_INDEX}

    def verify_case(self):
        res, _ = resolve("fnv", "1.0.7", FNV_INDEX)
        return FNV_CRATE, res.artifacts[0]["entry"], "fnv", "1.0.7"

    def malformed_digests(self):
        return [{"cksum": "zz"}, {"cksum": 5}, {"cksum": ""}, {}, {"cksum": "a" * 63}, {"cksum": "a" * 65},
                {"cksum": "g" * 64}, {"cksum": ["a" * 64]}, {"cksum": None}]

    def roots(self):
        return {"crate": "fnv-1.0.7/"}


class NameAndPathTests(unittest.TestCase):
    def test_the_index_path(self):
        for name, path in (("a", "1/a"), ("A", "1/a"), ("ab", "2/ab"), ("Ab", "2/ab"), ("abc", "3/a/abc"),
                           ("ABC", "3/a/abc"), ("abcd", "ab/cd/abcd"), ("serde", "se/rd/serde"),
                           ("Inflector", "in/fl/inflector"), ("foo_bar", "fo/o_/foo_bar"), ("Foo-Bar", "fo/o-/foo-bar"),
                           ("a-b", "3/a/a-b"), ("a-bc", "a-/bc/a-bc"), ("9lives", "9l/iv/9lives"), ("x" * 64, "xx/xx/" + "x" * 64), ("fnv", "3/f/fnv")):
            self.assertEqual(crates.index_path(name), path, name)

    def test_the_index_path_is_only_ever_safe_characters(self):
        eco = crates.Crates()
        for name in ("a", "ab", "abc", "abcd", "Foo_Bar", "a-b-c", "x" * 64):
            path = crates.index_path(eco.check_name(name))
            self.assertRegex(path, r"^[a-z0-9_/-]+$")
            self.assertNotIn("//", path)
            self.assertNotIn("..", path)

    def test_a_name_starts_with_a_letter_or_a_digit_and_is_at_most_64(self):
        eco = crates.Crates()
        for good in ("a", "0", "9lives", "a-", "a_", "a--b", "a__b", "A" * 64):
            self.assertEqual(eco.check_name(good), good)
        for bad in ("-", "_", "-a", "_a", "a" * 65, "", "a b", "a.b"):
            with self.assertRaises(base.SpecError, msg=bad):
                eco.check_name(bad)
        with self.assertRaisesRegex(base.SpecError, "^crates: a crate name starts with a letter or a digit$"):
            eco.check_name("_x")

    def test_identity_folds_case_hyphen_and_underscore_and_nothing_else(self):
        eco = crates.Crates()
        self.assertEqual(eco.identity("Foo_Bar-Baz"), "foo-bar-baz")
        self.assertEqual(eco.identity("Foo_Bar-Baz"), eco.identity("foo-bar_baz"))
        self.assertNotEqual(eco.identity("foobar"), eco.identity("foo-bar"))
        self.assertNotEqual(eco.identity("foo1"), eco.identity("fool"))

    def test_the_module_declares_what_it_reaches(self):
        eco = crates.Crates()
        # (the API only for a crate's owners, SC-NEW-DEPENDENCY's, at one request a second: the crawler policy's)
        self.assertEqual((eco.id, eco.hosts, eco.artifact_kinds, eco.rate, eco.manifest_names),
                         ("crates", frozenset({"index.crates.io", "static.crates.io", "crates.io"}), ("crate",),
                          {"crates.io": 1.0}, frozenset({"Cargo.toml"})))
        self.assertIsInstance(crates.ECOSYSTEM, crates.Crates)
        self.assertEqual(crates.MAX_NAME, 64)
        self.assertEqual(crates.MAX_INDEX_BYTES, 64 * 1024 * 1024)

    def test_the_segment_quotes_a_plus(self):
        self.assertEqual(crates.Crates().segment("1.2.3+build.5"), "1.2.3%2Bbuild.5")


class SemverTests(unittest.TestCase):
    ORDER = ("0.0.0", "0.0.1", "0.1.0", "0.9.9", "0.10.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
             "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.9.0", "1.10.0", "2.0.0",
             "10.0.0")

    def test_the_order_is_semvers(self):
        keys = [crates.semver_key(v) for v in self.ORDER]
        self.assertTrue(all(k is not None for k in keys))
        self.assertEqual(sorted(keys), keys)
        self.assertEqual(len(set(keys)), len(keys))

    def test_build_metadata_does_not_order(self):
        self.assertEqual(crates.semver_key("1.0.0+a"), crates.semver_key("1.0.0+b"))
        self.assertEqual(crates.semver_key("1.0.0+a"), crates.semver_key("1.0.0"))
        self.assertLess(crates.semver_key("1.0.0-rc.1+z"), crates.semver_key("1.0.0+a"))

    def test_numbers_are_compared_as_numbers_and_digits_sort_below_letters(self):
        self.assertLess(crates.semver_key("1.0.0-9"), crates.semver_key("1.0.0-10"))
        self.assertLess(crates.semver_key("1.0.0-9"), crates.semver_key("1.0.0-a"))
        self.assertLess(crates.semver_key("1.0.0-1.2"), crates.semver_key("1.0.0-1.10"))
        self.assertLess(crates.semver_key("1.0.0-a"), crates.semver_key("1.0.0-a.0"))
        self.assertLess(crates.semver_key("1.0.0-a"), crates.semver_key("1.0.0-b"))
        self.assertLess(crates.semver_key("1.0.0-A"), crates.semver_key("1.0.0-a"))
        self.assertLess(crates.semver_key("1.0.0-9a"), crates.semver_key("1.0.0-a"))

    def test_what_is_not_a_version_has_no_key(self):
        for bad in ("", "1", "1.0", "1.0.0.0", "01.0.0", "1.00.0", "1.0.00", "1.0.0-", "1.0.0-01", "1.0.0+", "v1.0.0",
                    "1.0.0-a..b", "1.0.0 ", " 1.0.0", "1.0.0\n", "-1.0.0", "1.0.0-\u03b1", "\uff11.0.0", None, 1, b"1.0.0",
                    "1.0.0-" + "a" * 100, "1" * 101 + ".0.0"):
            self.assertIsNone(crates.semver_key(bad), repr(bad)[:30])
        for good in ("0.0.0", "1.0.0-0", "1.0.0-0.0", "1.0.0-a-b", "1.0.0-0a", "1.0.0+0.1", "1.0.0-x+y", "1.0.0--",
                     "1.0.0+-", "99999999999999999999.0.0"):
            self.assertIsNotNone(crates.semver_key(good), good)

    def test_version_checking_is_semver_and_strips(self):
        eco = crates.Crates()
        self.assertEqual(eco.check_version(" 1.0.0 "), "1.0.0")
        self.assertEqual(eco.check_version("1.2.3+build.5"), "1.2.3+build.5")
        self.assertIsNone(eco.check_version(None))
        with self.assertRaisesRegex(base.SpecError, "^crates: invalid version '1.0'$"):
            eco.check_version("1.0")
        with self.assertRaisesRegex(base.SpecError, "^crates: invalid version '\\\\u202e1'"):
            eco.check_version("\u202e1")


class ResolveTests(unittest.TestCase):
    def test_latest_is_the_highest_release_that_is_not_yanked(self):
        doc = index(line("0.9.0"), line("1.0.0"), line("1.1.0", yanked=True), line("1.2.0-beta.1"), line("1.0.1"),
                    line("0.10.0"))
        res, served = resolve("demo", None, doc)
        self.assertEqual(res[0], "1.0.1")
        self.assertEqual(res.artifacts[0]["url"], "https://static.crates.io/crates/demo/demo-1.0.1.crate")
        self.assertEqual(len(served.calls), 1)

    def test_a_yanked_release_is_never_latest_even_if_it_is_the_highest(self):
        doc = index(line("1.0.0"), line("2.0.0", yanked=True))
        self.assertEqual(resolve("demo", None, doc)[0][0], "1.0.0")

    def test_with_only_pre_releases_the_highest_pre_release_is_latest(self):
        doc = index(line("1.0.0-alpha"), line("1.0.0-beta.11"), line("1.0.0-beta.2"), line("0.9.0-rc.1", yanked=True))
        self.assertEqual(resolve("demo", None, doc)[0][0], "1.0.0-beta.11")

    def test_a_release_beats_a_higher_pre_release(self):
        doc = index(line("1.0.0"), line("2.0.0-alpha.1"))
        self.assertEqual(resolve("demo", None, doc)[0][0], "1.0.0")

    def test_when_every_version_is_yanked_there_is_no_latest(self):
        doc = index(line("1.0.0", yanked=True), line("1.0.1", yanked=True))
        with self.assertRaisesRegex(base.FetchError, "^crates: every version of 'demo' is yanked$"):
            resolve("demo", None, doc)

    def test_a_yanked_version_asked_for_by_number_resolves_and_says_so(self):
        doc = index(line("1.0.0"), line("1.1.0", yanked=True))
        res, _ = resolve("demo", "1.1.0", doc)
        self.assertEqual((res[0], res.info["yanked"]), ("1.1.0", True))
        self.assertTrue(res.artifacts[0]["entry"]["yanked"])
        self.assertFalse(resolve("demo", "1.0.0", doc)[0].info["yanked"])

    def test_a_version_is_matched_without_its_build_metadata_and_the_index_spelling_is_returned(self):
        doc = index(line("1.0.0"), line("1.2.3+build.5"))
        for asked in ("1.2.3", "1.2.3+build.5", "1.2.3+other"):
            res, _ = resolve("demo", asked, doc)
            self.assertEqual(res[0], "1.2.3+build.5", asked)
            # (the version as cargo inserts it in the download URL: its `+` as it is, RM-3)
            self.assertEqual(res.artifacts[0]["url"], "https://static.crates.io/crates/demo/demo-1.2.3+build.5.crate")
            self.assertEqual(base.Fetch(crates.Crates(), None).check_url(res.artifacts[0]["url"]), res.artifacts[0]["url"])
            self.assertEqual(res.artifacts[0]["filename"], "demo-1.2.3+build.5.crate")

    def test_a_version_the_index_does_not_list_is_a_spec_error_that_names_it_safely(self):
        with self.assertRaisesRegex(base.SpecError, "^crates: no version '2.0.0' of 'demo'$"):
            resolve("demo", "2.0.0", index(line("1.0.0")))

    def test_the_index_may_not_list_a_version_twice_even_with_other_build_metadata(self):
        for a, b in (("1.0.0", "1.0.0"), ("1.0.7", "1.0.7+extra"), ("1.0.7+a", "1.0.7+b")):
            with self.subTest(a=a, b=b), self.assertRaisesRegex(base.FetchError, "lists a version twice"):
                resolve("demo", None, index(line(a), line(b)))
        resolve("demo", None, index(line("1.0.0"), line("1.0.1")))

    def test_the_index_file_of_one_crate_may_not_list_another(self):
        with self.assertRaisesRegex(base.FetchError, "lists another crate"):
            resolve("demo", None, index(line("1.0.0"), line("1.0.1", name="other")))
        with self.assertRaisesRegex(base.FetchError, "lists another crate"):
            resolve("foo-bar", None, index(line("1.0.0", name="foo_bar")), path="fo/o-/foo-bar")
        with self.assertRaisesRegex(base.FetchError, "lists another crate"):
            resolve("demo", None, index(line("1.0.0", name="\u202edemo")))

    def test_a_name_that_differs_only_in_case_is_the_same_crate_and_the_download_uses_the_index_spelling(self):
        doc = index(line("1.0.0", name="Demo"))
        for asked in ("demo", "DEMO", "Demo"):
            res, served = resolve(asked, None, doc, path="de/mo/demo")
            self.assertEqual(served.calls[0][0], "https://index.crates.io/de/mo/demo")
            self.assertEqual(res.artifacts[0]["url"], "https://static.crates.io/crates/Demo/Demo-1.0.0.crate")
            self.assertEqual(res.info["name"], "Demo")

    def test_resolving_asks_the_index_once_with_its_bound_and_downloads_nothing(self):
        res, served = resolve("demo", None, index(line("1.0.0")))
        (url, kw), = served.calls
        self.assertEqual(url, "https://index.crates.io/de/mo/demo")
        self.assertEqual(kw["max_bytes"], crates.MAX_INDEX_BYTES)
        self.assertEqual(served.fetch.requests, [url])

    def test_the_artifact_is_a_crate_in_a_tgz_with_the_index_line_as_its_entry(self):
        res, _ = resolve("demo", "1.0.0", index(line("1.0.0", links="native", rust_version="1.60")))
        art, = res.artifacts
        self.assertEqual((art["container"], art["artifact"], art["filename"]), ("tgz", "crate", "demo-1.0.0.crate"))
        self.assertEqual(res.skipped, [])
        self.assertEqual(tuple(res)[1:4], (art["url"], "tgz", "crate"))
        self.assertEqual(art["entry"]["links"], "native")
        self.assertEqual(res.info, {"name": "demo", "yanked": False, "rust_version": "1.60", "links": "native"})

    def test_what_a_scan_does_not_need_from_a_line_is_not_kept(self):
        big = {"default": ["f%d" % i for i in range(5000)]}
        res, _ = resolve("demo", None, index(line("1.0.0", features=big, features2=big)))
        entry = res.artifacts[0]["entry"]
        self.assertEqual(set(entry), {"name", "vers", "cksum", "yanked", "deps", "rust_version", "links", "pubtime"})
        self.assertLess(len(json.dumps(entry)), 400)

    def test_a_lines_publishing_time_is_kept_when_it_is_one(self):
        for value, kept in (("2026-05-02T10:00:00Z", "2026-05-02T10:00:00Z"), (None, None), (17, None), ("x" * 41, None)):
            with self.subTest(value):
                rec = json.loads(line("1.0.0"))
                rec["pubtime"] = value
                res, _ = resolve("demo", None, (json.dumps(rec) + "\n").encode())
                self.assertEqual(res.artifacts[0]["entry"]["pubtime"], kept)

    def test_a_missing_index_file_is_a_404_fetch_error(self):
        eco = crates.Crates()
        with self.assertRaises(base.FetchError) as caught:
            eco.resolve("nope", None, Served({}).fetch)
        self.assertEqual(caught.exception.status, 404)

    def test_an_empty_index_file_is_an_error_and_not_an_empty_release(self):
        for doc in (b"", b"\n", b" \n \n"):
            with self.assertRaisesRegex(base.FetchError, "lists no versions"):
                resolve("demo", None, doc)

    def test_every_wrong_shape_of_an_index_line_is_refused_without_its_text(self):
        good = json.loads(line("1.0.0"))
        wrong = {
            "not an object": "[]", "name missing": {k: v for k, v in good.items() if k != "name"},
            "name a number": dict(good, name=5), "vers missing": {k: v for k, v in good.items() if k != "vers"},
            "vers a number": dict(good, vers=1), "vers not semver": dict(good, vers="1.0"),
            "vers hostile": dict(good, vers="1.0.0\u202e"), "vers long": dict(good, vers="1.0.0-" + "a" * 120),
            "cksum missing": {k: v for k, v in good.items() if k != "cksum"}, "cksum short": dict(good, cksum="ab"),
            "cksum a number": dict(good, cksum=5), "cksum not hex": dict(good, cksum="z" * 64),
            "yanked missing": {k: v for k, v in good.items() if k != "yanked"}, "yanked a string": dict(good, yanked="no"),
            "yanked a number": dict(good, yanked=0), "deps a string": dict(good, deps="x"),
            "deps a dict": dict(good, deps={"name": "x"}), "dep a string": dict(good, deps=["x"]),
            "dep without a name": dict(good, deps=[{"kind": "normal"}]), "dep name a number": dict(good, deps=[dep(5)]),
            "dep kind unknown": dict(good, deps=[dep("x", kind="weird")]),
            "dep kind a list": dict(good, deps=[dep("x", kind=["normal"])]),
            "dep package a number": dict(good, deps=[dep("x", package=5)]),
            "too many deps": dict(good, deps=[dep("x")] * (crates.MAX_DEPS + 1)),
        }
        for what, rec in wrong.items():
            body = (rec if isinstance(rec, str) else json.dumps(rec)).encode() + b"\n"
            with self.subTest(what=what):
                try:
                    resolve("demo", None, body)
                except base.FetchError as exc:
                    self.assertTrue(str(exc).startswith("crates: "), str(exc))
                    self.assertNotIn("\u202e", str(exc))
                    self.assertLess(len(str(exc)), 200)
                else:
                    self.fail("accepted")

    def test_the_other_fields_may_be_missing_or_odd_and_are_not_kept_when_odd(self):
        rec = json.loads(line("1.0.0"))
        del rec["deps"], rec["features"], rec["v"]
        res, _ = resolve("demo", None, (json.dumps(dict(rec, rust_version=5, links=["x"])) + "\n").encode())
        entry = res.artifacts[0]["entry"]
        self.assertEqual((entry["deps"], entry["rust_version"], entry["links"]), ([], None, None))
        res, _ = resolve("demo", None, (json.dumps(dict(rec, rust_version="1" * 41, links="l" * 101)) + "\n").encode())
        self.assertEqual((res.info["rust_version"], res.info["links"]), (None, None))
        res, _ = resolve("demo", None, (json.dumps(dict(rec, cksum="A" * 64)) + "\n").encode())
        self.assertEqual(res.artifacts[0]["entry"]["cksum"], "a" * 64)

    def test_a_line_that_is_not_json_fails_the_whole_index_file(self):
        with self.assertRaisesRegex(base.FetchError, "invalid JSON"):
            resolve("demo", "1.0.0", index(line("1.0.0"), "{not json", line("1.0.1")))

    def test_a_crates_dot_io_line_can_be_long_but_not_over_a_megabyte(self):
        long_ok = line("1.0.0", features={"f": ["x" * 1000] * 900})
        self.assertLess(len(long_ok), base.MAX_LINE_BYTES)
        self.assertEqual(resolve("demo", None, index(long_ok))[0][0], "1.0.0")
        too_long = line("1.0.0", features={"f": "x" * base.MAX_LINE_BYTES})
        with self.assertRaisesRegex(base.FetchError, "a line of the registry response is over"):
            resolve("demo", None, index(too_long))

    def test_the_number_of_versions_is_bounded(self):
        with mock.patch.object(crates, "MAX_VERSIONS", 3):
            resolve("demo", None, index(line("1.0.0"), line("1.0.1"), line("1.0.2")))
            with self.assertRaisesRegex(base.FetchError, "too many versions"):
                resolve("demo", None, index(line("1.0.0"), line("1.0.1"), line("1.0.2"), line("1.0.3")))

    def test_a_file_without_a_final_newline_and_with_windows_line_ends_reads_the_same(self):
        lines = [line("1.0.0"), line("1.0.1")]
        for doc in ("\n".join(lines), "\r\n".join(lines) + "\r\n", "\n\n".join(lines) + "\n\n"):
            self.assertEqual(resolve("demo", None, doc.encode())[0][0], "1.0.1")

    def test_a_dependency_with_a_hostile_name_is_kept_as_text_and_never_used_for_a_url(self):
        res, served = resolve("demo", None, index(line("1.0.0", deps=[dep("../../x"), dep("a\u202eb")])))
        self.assertEqual(served.fetch.requests, ["https://index.crates.io/de/mo/demo"])
        self.assertEqual(crates.Crates().dependencies(res, served.fetch), ())


class RecordedTests(unittest.TestCase):
    def test_fnv_resolves_to_its_last_version_and_the_archive_matches_the_published_checksum(self):
        eco = crates.Crates()
        res, served = resolve("fnv", None, FNV_INDEX)
        self.assertEqual(res[0], "1.0.7")
        self.assertEqual(res.artifacts[0]["url"], "https://static.crates.io/crates/fnv/fnv-1.0.7.crate")
        self.assertEqual(served.fetch.requests, ["https://index.crates.io/3/f/fnv"])
        entry = res.artifacts[0]["entry"]
        self.assertEqual(entry["cksum"], hashlib.sha256(FNV_CRATE).hexdigest())
        self.assertEqual(eco.verify(FNV_CRATE, entry, "fnv", "1.0.7"), ("sha256", entry["cksum"]))
        for i in (0, len(FNV_CRATE) // 2, len(FNV_CRATE) - 1):
            bad = bytearray(FNV_CRATE)
            bad[i] ^= 0x01
            with self.assertRaisesRegex(base.DigestError, "does not match the cksum the index published for 'fnv' '1.0.7'"):
                eco.verify(bytes(bad), entry, "fnv", "1.0.7")

    def test_every_version_in_fnvs_index_resolves_and_has_a_different_checksum(self):
        eco = crates.Crates()
        versions = [json.loads(l)["vers"] for l in FNV_INDEX.decode().splitlines()]
        self.assertEqual(versions, ["1.0.%d" % i for i in range(8)])
        sums = set()
        for v in versions:
            res, _ = resolve("fnv", v, FNV_INDEX)
            self.assertEqual(res[0], v)
            sums.add(res.artifacts[0]["entry"]["cksum"])
            self.assertEqual(eco.check_version(res[0]), v)
        self.assertEqual(len(sums), 8)

    def test_a_crate_registered_with_capitals_is_asked_for_in_lowercase_and_downloaded_in_capitals(self):
        res, served = resolve("Inflector", None, recorded("inflector.index"), path="in/fl/inflector")
        self.assertEqual(served.calls[0][0], "https://index.crates.io/in/fl/inflector")
        self.assertEqual(res[0], "0.11.4")
        self.assertEqual(res.artifacts[0]["url"], "https://static.crates.io/crates/Inflector/Inflector-0.11.4.crate")
        self.assertEqual(res.info["name"], "Inflector")
        self.assertEqual(crates.Crates().dependencies(res, served.fetch), ("lazy_static", "regex"))

    def test_paste_has_a_dev_dependency_list_that_is_not_what_a_user_builds(self):
        doc = recorded("paste-1.0.15.index")
        res, served = resolve("paste", None, doc)
        self.assertEqual((res[0], res.info["rust_version"]), ("1.0.15", "1.31"))
        self.assertEqual(crates.Crates().dependencies(res, served.fetch), ())
        kinds = {kind for _name, kind in res.artifacts[0]["entry"]["deps"]}
        self.assertEqual(kinds, {"dev"})

    def test_the_members_of_the_real_archives_map_to_paths_under_the_crate(self):
        eco = crates.Crates()
        for crate, root in (("fnv-1.0.7", "fnv-1.0.7/"), ("paste-1.0.15", "paste-1.0.15/")):
            members = text_of(crate + ".members").split()
            for m in members:
                rel, problem = eco.member_path("crate", m, root)
                self.assertIsNone(problem, m)
                if m.endswith("/"):
                    self.assertIsNone(rel)
                else:
                    self.assertEqual(rel, m[len(root):])

    def test_fnvs_library_is_at_the_root_and_nothing_runs_at_build(self):
        eco = crates.Crates()
        members = [m.split("/", 1)[1] for m in text_of("fnv-1.0.7.members").split()]
        targets = eco.run_targets("crate", {"Cargo.toml": text_of("fnv-1.0.7.Cargo.toml")}, members)
        self.assertEqual(targets, base.RunTargets(entries={"lib.rs"}))
        self.assertEqual(eco.declared("crate", {"Cargo.toml": text_of("fnv-1.0.7.Cargo.toml")}, members),
                         base.Declared("fnv", ()))

    def test_paste_is_a_proc_macro_with_a_build_script_and_both_run_when_it_is_built(self):
        eco = crates.Crates()
        members = [m.split("/", 1)[1] for m in text_of("paste-1.0.15.members").split()]
        manifest = {"Cargo.toml": text_of("paste-1.0.15.Cargo.toml")}
        targets = eco.run_targets("crate", manifest, members)
        self.assertEqual(targets.install_scripts, frozenset({"build.rs", "src/lib.rs"}))
        self.assertEqual(targets.entries, frozenset({"src/lib.rs"}))
        self.assertEqual(targets.startup, frozenset())
        declared = eco.declared("crate", manifest, members)
        self.assertEqual(declared.name, "paste")


MANIFEST = "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n"


class RunTargetsTests(unittest.TestCase):
    def run_targets(self, manifest, members, **kw):
        manifests = {} if manifest is None else {"Cargo.toml": manifest}
        return crates.Crates().run_targets("crate", manifests, members)

    def test_a_build_script_beside_the_manifest_runs_without_being_named(self):
        t = self.run_targets(MANIFEST, ["build.rs", "src/lib.rs", "Cargo.toml"])
        self.assertEqual((t.install_scripts, t.entries), (frozenset({"build.rs"}), frozenset({"src/lib.rs"})))

    def test_build_false_turns_it_off_and_a_named_path_replaces_it(self):
        members = ["build.rs", "ci/build.rs", "src/lib.rs"]
        self.assertEqual(self.run_targets(MANIFEST + "build = false\n", members).install_scripts, frozenset())
        self.assertEqual(self.run_targets(MANIFEST + "build = true\n", members).install_scripts, frozenset({"build.rs"}))
        self.assertEqual(self.run_targets(MANIFEST + "build = \"ci/build.rs\"\n", members).install_scripts,
                         frozenset({"ci/build.rs"}))
        self.assertEqual(self.run_targets(MANIFEST + "build = \"./ci\\\\build.rs\"\n", members).install_scripts,
                         frozenset({"ci/build.rs"}))
        self.assertEqual(self.run_targets(MANIFEST + "build = \"nowhere.rs\"\n", members).install_scripts, frozenset())
        self.assertEqual(self.run_targets(MANIFEST + "build = \"../build.rs\"\n", members + ["../build.rs"]).install_scripts,
                         frozenset())
        self.assertEqual(self.run_targets(MANIFEST + "build = 5\n", members).install_scripts, frozenset({"build.rs"}))

    def test_a_proc_macro_library_runs_in_the_compiler_of_everything_that_uses_it(self):
        manifest = MANIFEST + "[lib]\nproc-macro = true\n"
        t = self.run_targets(manifest, ["src/lib.rs"])
        self.assertEqual((t.entries, t.install_scripts), (frozenset({"src/lib.rs"}), frozenset({"src/lib.rs"})))
        t = self.run_targets(MANIFEST + "[lib]\nproc_macro = true\npath = \"macros/m.rs\"\n", ["macros/m.rs", "src/lib.rs"])
        self.assertEqual((t.entries, t.install_scripts), (frozenset({"macros/m.rs"}), frozenset({"macros/m.rs"})))
        t = self.run_targets(MANIFEST + "[lib]\nproc-macro = false\n", ["src/lib.rs"])
        self.assertEqual(t.install_scripts, frozenset())
        t = self.run_targets(MANIFEST + "[lib]\nproc-macro = \"true\"\n", ["src/lib.rs"])
        self.assertEqual(t.install_scripts, frozenset())
        # crate-type = ["proc-macro"]: cargo builds a procedural macro too, proc-macro = false or not
        for lib in ('crate-type = ["proc-macro"]', "crate_type = ['proc-macro']",
                    'proc-macro = false\ncrate-type = ["proc-macro"]'):
            with self.subTest(lib):
                t = self.run_targets(MANIFEST + f"[lib]\n{lib}\n", ["src/lib.rs"])
                self.assertEqual(t.install_scripts, frozenset({"src/lib.rs"}))
        t = self.run_targets(MANIFEST + '[lib]\ncrate-type = ["rlib", "cdylib"]\n', ["src/lib.rs"])
        self.assertEqual(t.install_scripts, frozenset())

    def test_binaries_are_entries_declared_or_found(self):
        manifest = MANIFEST + "[[bin]]\nname = \"t\"\npath = \"tools/t.rs\"\n[[bin]]\nname = \"u\"\npath = \"tools/missing.rs\"\n"
        members = ["tools/t.rs", "src/main.rs", "src/bin/a.rs", "src/bin/b/main.rs", "src/bin/b/other.rs",
                   "src/bin/c/d/main.rs", "src/bin/e.txt", "src/bin/f.rs/x", "src/lib.rs", "examples/x.rs", "tests/y.rs"]
        t = self.run_targets(manifest, members)
        self.assertEqual(t.entries, frozenset({"tools/t.rs", "src/main.rs", "src/bin/a.rs", "src/bin/b/main.rs",
                                               "src/lib.rs"}))
        self.assertEqual(t.install_scripts, frozenset())

    def test_a_manifest_that_cannot_be_read_still_has_its_build_script(self):
        for manifest in ("[package\nname =", "\0", "x" * 100_000, "[" * 5000, "build = false\n[[[[", None, ""):
            with self.subTest(manifest=(manifest or "")[:12]):
                t = self.run_targets(manifest, ["build.rs", "src/lib.rs"])
                self.assertEqual(t.install_scripts, frozenset({"build.rs"}))
                self.assertEqual(t.entries, frozenset({"src/lib.rs"}))

    def test_odd_types_in_a_readable_manifest_are_ignored_not_trusted(self):
        members = ["build.rs", "src/lib.rs", "src/main.rs"]
        for manifest in ("package = 5\n", "lib = [1]\nbin = {a = 1}\n", "bin = [5, \"x\", {path = 5}]\n",
                         "[package]\nbuild = [\"x\"]\n[lib]\npath = 5\nproc-macro = 1\n", "[project]\nname = 5\n"):
            with self.subTest(manifest=manifest[:20]):
                t = self.run_targets(manifest, members)
                self.assertEqual(t.install_scripts, frozenset({"build.rs"}))
                self.assertEqual(t.entries, frozenset({"src/lib.rs", "src/main.rs"}))

    def test_the_old_project_table_is_read_like_package(self):
        t = self.run_targets("[project]\nbuild = false\n", ["build.rs"])
        self.assertEqual(t.install_scripts, frozenset())

    def test_targets_that_are_not_in_the_archive_are_not_reported(self):
        t = self.run_targets(MANIFEST, [])
        self.assertEqual(t, base.RunTargets())
        t = self.run_targets(MANIFEST, [5, None, b"build.rs", "build.rs"])
        self.assertEqual(t.install_scripts, frozenset({"build.rs"}))
        self.assertEqual(self.run_targets(MANIFEST, None), base.RunTargets())

    def test_a_path_in_a_manifest_is_taken_as_a_path_in_the_archive_and_never_from_outside_it(self):
        for given in ("/etc/passwd", "C:/x.rs", "a/../../b.rs", "x" * 600):
            t = self.run_targets(MANIFEST + "build = %s\n" % json.dumps(given), ["etc/passwd", "x.rs", "b.rs", "x" * 600])
            self.assertLessEqual(t.install_scripts, {"etc/passwd", "x.rs"}, given)
        self.assertEqual(self.run_targets(MANIFEST + "build = \"/etc/passwd\"\n", ["etc/passwd"]).install_scripts,
                         frozenset({"etc/passwd"}))                       # (a leading slash comes off, as an extractor's does)


class DeclaredAndDependenciesTests(unittest.TestCase):
    def declared(self, manifest):
        return crates.Crates().declared("crate", {"Cargo.toml": manifest}, [])

    def test_the_name_and_the_dependencies_a_build_pulls_in(self):
        manifest = MANIFEST + (
            "[dependencies]\nserde = \"1\"\nrand = {version = \"0.8\", features = [\"x\"]}\n"
            "[build-dependencies]\ncc = \"1\"\n[dev-dependencies]\ncriterion = \"0.5\"\n"
            "[target.'cfg(windows)'.dependencies]\nwinapi = \"0.3\"\n"
            "[target.'cfg(unix)'.build-dependencies]\npkg-config = \"0.3\"\n"
            "[target.'cfg(unix)'.dev-dependencies]\ntempfile = \"3\"\n")
        d = self.declared(manifest)
        self.assertEqual(d.name, "demo")
        self.assertEqual(d.dependencies, ("cc", "pkg-config", "rand", "serde", "winapi"))

    def test_a_renamed_dependency_is_the_crate_it_renames(self):
        d = self.declared(MANIFEST + "[dependencies]\nmy-rand = {package = \"rand\", version = \"0.8\"}\nplain = \"1\"\n"
                          "[dependencies.other]\npackage = \"real-other\"\nversion = \"2\"\n")
        self.assertEqual(d.dependencies, ("plain", "rand", "real-other"))

    def test_the_spec_of_each_dependency_is_kept_next_to_its_name(self):
        d = self.declared(MANIFEST + "[dependencies]\nplain = \"1.2\"\ntable = {version = \"^0.8\", features = [\"x\"]}\n"
                          "no-version = {path = \"../x\"}\nodd = 5\n"
                          "[build-dependencies]\ncc = \"1.0.3\"\n[dev-dependencies]\ncriterion = \"0.5\"\n")
        self.assertEqual(d.dependencies, ("cc", "no-version", "odd", "plain", "table"))
        self.assertEqual(d.specs, {"cc": "1.0.3", "no-version": None, "odd": None, "plain": "1.2", "table": "^0.8"})
        self.assertEqual(d.aliases, {})

    def test_the_first_table_that_names_a_dependency_gives_its_spec(self):
        d = self.declared(MANIFEST + "[build-dependencies]\ncc = \"2\"\n[dependencies]\ncc = \"1\"\n"
                          "[target.'cfg(unix)'.dependencies]\ncc = \"3\"\n")
        self.assertEqual(d.dependencies, ("cc",))
        self.assertEqual(d.specs, {"cc": "1"})                           # ([dependencies] is read before [build-dependencies])

    def test_a_spec_is_kept_as_written_up_to_the_bound(self):
        for size, kept in ((crates.MAX_SPEC, True), (crates.MAX_SPEC + 1, False)):
            with self.subTest(size=size):
                spec = ">=" + "1" * (size - 2)
                got = self.declared(MANIFEST + "[dependencies]\nbig = \"%s\"\n" % spec).specs["big"]
                self.assertEqual(got, spec if kept else spec[:crates.MAX_SPEC])
                self.assertEqual(len(got), crates.MAX_SPEC)

    def test_a_rename_says_which_name_the_code_uses(self):
        d = self.declared(MANIFEST + "[dependencies]\nmy-rand = {package = \"rand\", version = \"0.8\"}\nplain = \"1\"\n"
                          "[dependencies.other]\npackage = \"real-other\"\nversion = \"2\"\n"
                          "[build-dependencies]\nsame = {package = \"same\", version = \"1\"}\n")
        self.assertEqual(d.dependencies, ("plain", "rand", "real-other", "same"))
        self.assertEqual(d.aliases, {"rand": "my-rand", "real-other": "other"})            # (a name that is its own name has none)
        self.assertEqual(d.specs, {"plain": "1", "rand": "0.8", "real-other": "2", "same": "1"})

    def test_a_rename_whose_local_name_is_not_a_name_has_no_alias_and_the_first_one_stays(self):
        d = self.declared(MANIFEST + "[dependencies]\n\"a b\" = {package = \"rand\"}\n"
                          "first = {package = \"twice\"}\nsecond = {package = \"twice\"}\n")
        self.assertEqual(d.dependencies, ("rand", "twice"))
        self.assertEqual(d.aliases, {"twice": "first"})

    def test_the_underscore_spelling_of_the_table_names_is_read_too(self):
        d = self.declared(MANIFEST + "[build_dependencies]\ncc = \"1\"\n[dev_dependencies]\ncriterion = \"1\"\n")
        self.assertEqual(d.dependencies, ("cc",))

    def test_names_that_are_not_crate_names_are_dropped(self):
        d = self.declared(MANIFEST + "[dependencies]\n\"../x\" = \"1\"\n\"a b\" = \"1\"\nok = \"1\"\n"
                          "renamed = {package = \"-bad\"}\n\"\u202e\" = \"1\"\n")
        self.assertEqual(d.dependencies, ("ok",))
        self.assertIsNone(self.declared("[package]\nname = \"../x\"\n").name)
        self.assertIsNone(self.declared("[package]\nname = 5\n").name)
        self.assertEqual(self.declared("[project]\nname = \"old\"\n").name, "old")

    def test_a_manifest_that_is_not_readable_declares_nothing(self):
        for manifest in ("[package\n", "", "dependencies = 5\n", "[dependencies]\nx = 5\n[target]\ny = 5\n", "target = []\n"):
            d = self.declared(manifest)
            self.assertIsInstance(d, base.Declared)
        self.assertEqual(self.declared("dependencies = 5\ntarget = [1]\n"), base.Declared())
        self.assertEqual(crates.Crates().declared("crate", {}, []), base.Declared())
        self.assertEqual(crates.Crates().declared("crate", None, []), base.Declared())

    def test_the_dependencies_of_a_release_are_the_index_lines_normal_and_build_ones(self):
        deps = [dep("serde"), dep("cc", kind="build"), dep("criterion", kind="dev"), dep("a", package="real-a"),
                dep("serde"), dep("x y"), dep("-no")]
        res, served = resolve("demo", None, index(line("1.0.0", deps=deps)))
        self.assertEqual(crates.Crates().dependencies(res, served.fetch), ("cc", "real-a", "serde"))

    def test_without_an_index_line_there_is_no_answer_and_no_guess(self):
        eco = crates.Crates()
        for resolved in (None, 5, base.Resolution("1.0.0", [{"url": "u", "container": "tgz", "artifact": "crate",
                                                            "entry": None, "filename": "f"}])):
            self.assertIsNone(eco.dependencies(resolved, None))


class ArchiveRulesTests(unittest.TestCase):
    def test_links_are_never_extracted_because_cargo_refuses_a_crate_that_has_one(self):
        eco = crates.Crates()
        self.assertIs(eco.links_extracted("crate"), False)
        self.assertIs(eco.links_extracted("anything"), False)

    def test_container_is_by_file_name(self):
        eco = crates.Crates()
        self.assertEqual(eco.container("serde-1.0.0.crate"), "tgz")
        for other in ("serde-1.0.0.tar.gz", "serde-1.0.0.CRATE", "x.crate/", "", None, 5, "crate"):
            self.assertIsNone(eco.container(other))

    def test_a_member_outside_the_crates_directory_is_a_problem_and_a_marker_file_is_not_extracted(self):
        eco = crates.Crates()
        self.assertEqual(eco.member_path("crate", "demo-1.0.0/src/lib.rs", "demo-1.0.0/"), ("src/lib.rs", None))
        self.assertEqual(eco.member_path("crate", "evil/src/lib.rs", "demo-1.0.0/"),
                         (None, "member outside the archive's root directory"))
        self.assertEqual(eco.member_path("crate", "demo-1.0.0/.cargo-ok", "demo-1.0.0/"), (None, None))

    def test_the_root_is_the_name_the_index_spells_and_the_version(self):
        eco = crates.Crates()
        res, _ = resolve("fnv", "1.0.7", FNV_INDEX)
        self.assertEqual(eco.archive_root(res, res.artifacts[0]), "fnv-1.0.7/")
        res, _ = resolve("Inflector", None, recorded("inflector.index"), path="in/fl/inflector")
        self.assertEqual(res.info["name"], "Inflector")
        self.assertEqual(eco.archive_root(res, res.artifacts[0]), "Inflector-%s/" % res[0], "(the name keeps its capital letters)")

    def test_a_version_with_a_pre_release_or_build_part_is_in_the_root_as_written(self):
        eco = crates.Crates()
        for version in ("1.0.0-alpha.1", "0.1.0-rc.1.2", "1.2.3+build.5"):
            res = base.Resolution(version, [{"url": "u", "container": "tgz", "artifact": "crate", "entry": {"cksum": "a" * 64}}],
                                  info={"name": "demo"})
            with self.subTest(version=version):
                self.assertEqual(eco.archive_root(res, res.artifacts[0]), "demo-%s/" % version)

    def test_no_root_is_made_from_what_is_not_a_name_and_a_version(self):
        eco = crates.Crates()
        art = {"url": "u", "container": "tgz", "artifact": "crate", "entry": {}}
        for name, version in (("a/b", "1.0.0"), ("..", "1.0.0"), ("demo", "1"), ("demo", "../1.0.0"), ("demo", 5), ("", "1.0.0"),
                              ("demo", ""), (5, "1.0.0"), ("de mo", "1.0.0"), ("demo\n", "1.0.0")):
            res = base.Resolution(version, [art], info={"name": name})
            with self.subTest(name=name, version=version):
                self.assertIsNone(eco.archive_root(res, art))
        self.assertIsNone(eco.archive_root(base.Resolution("1.0.0", [art], info={}), art))


class BoundaryTests(unittest.TestCase):
    """Each limit is exactly where the module says: one under is read, one over is refused."""

    def test_the_limits_are_what_the_module_says(self):
        self.assertEqual((crates.MAX_NAME, crates.MAX_VERSION, crates.MAX_INDEX_BYTES, crates.MAX_VERSIONS, crates.MAX_DEPS),
                         (64, 100, 64 * 1024 * 1024, 100_000, 5_000))

    def test_a_version_of_100_characters_is_a_version_and_one_of_101_is_not(self):
        ok = "1.0.0-" + "a" * 94
        bad = ok + "a"
        self.assertEqual((len(ok), len(bad)), (100, 101))
        self.assertIsNotNone(crates.semver_key(ok))
        self.assertIsNone(crates.semver_key(bad))
        eco = crates.Crates()
        self.assertEqual(eco.check_version(ok), ok)
        with self.assertRaises(base.SpecError):
            eco.check_version(bad)

    def test_an_index_may_list_exactly_as_many_versions_as_the_limit_says(self):
        with mock.patch.object(crates, "MAX_VERSIONS", 3):
            self.assertEqual(resolve("demo", None, index(line("1.0.0"), line("1.0.1"), line("1.0.2")))[0][0], "1.0.2")
            with self.assertRaisesRegex(base.FetchError, "lists too many versions"):
                resolve("demo", None, index(line("1.0.0"), line("1.0.1"), line("1.0.2"), line("1.0.3")))

    def test_an_index_line_may_list_exactly_as_many_dependencies_as_the_limit_says(self):
        with mock.patch.object(crates, "MAX_DEPS", 3):
            res, _ = resolve("demo", None, index(line("1.0.0", deps=[dep("a"), dep("b"), dep("c")])))
            self.assertEqual(crates.Crates().dependencies(res, None), ("a", "b", "c"))
            with self.assertRaisesRegex(base.FetchError, "dependency list that is not a list, or is too long"):
                resolve("demo", None, index(line("1.0.0", deps=[dep("a"), dep("b"), dep("c"), dep("d")])))

    def test_a_rust_version_of_40_characters_and_a_links_of_100_are_kept_and_one_more_is_not(self):
        for field, size in (("rust_version", 40), ("links", 100)):
            with self.subTest(field=field):
                kept = resolve("demo", None, index(line("1.0.0", **{field: "x" * size})))[0].info[field]
                dropped = resolve("demo", None, index(line("1.0.0", **{field: "x" * (size + 1)})))[0].info[field]
                self.assertEqual((kept, dropped), ("x" * size, None))

    def test_a_path_the_manifest_names_may_be_512_characters_and_not_513(self):
        eco = crates.Crates()
        for size, runs in ((512, True), (513, False)):
            name = "b" * (size - 3) + ".rs"
            manifest = '[package]\nname = "demo"\nbuild = "%s"\n' % name
            got = eco.run_targets("crate", {"Cargo.toml": manifest}, [name])
            self.assertEqual(got.install_scripts, frozenset({name}) if runs else frozenset(), size)

    def test_only_the_first_1000_target_tables_of_a_manifest_are_read(self):
        text = '[package]\nname = "demo"\n' + "".join('[target.t%d.dependencies]\nd%d = "1"\n' % (i, i) for i in range(1001))
        got = crates.Crates().declared("crate", {"Cargo.toml": text}, [])
        self.assertEqual(len(got.dependencies), 1000)
        self.assertIn("d999", got.dependencies)
        self.assertNotIn("d1000", got.dependencies)


if __name__ == "__main__":
    unittest.main()
