"""`registry/ecosystems/golang.py` (0.1.9, G-1): Go modules from recorded responses and from Go's own answers.

* The whole conformance contract (`ecosystem_contract.py`), over a real module: `github.com/pmezard/go-difflib` v1.0.0,
  whose zip was built by Go from the git tag and whose `h1:` is the one published go.sum files carry.
* `recorded/go/golden.json`: what Go (`golang.org/x/mod`, through `scripts/gooracle/`) answers for module paths, `!`
  escapes, path splits, versions, path-major checks, zip member paths, go.mod files and the `h1:` hash of zips of every odd
  shape, and three real modules (two zips committed) with the hashes of real go.sum files. Python must give the same answers.
  The tests do not run Go; `gooracle.py diff` runs the same comparison on tens of thousands of cases when Go is there.
* The rules that are the module's own: what resolve asks for and in what order, the checksum database's response, the
  digest, `go.mod` dependencies, the member rules, what runs, and the bounds.
What was not recorded: the module proxy's own responses (it could not be reached when this was written). `.info` is the
document `go help goproxy` describes; the checksum database response is made by the code of Go's checksum database server
over the real hashes, signed with a test key. Nothing here opens a socket."""

import hashlib
import io
import json
import os
import unittest
import warnings
import zipfile
from unittest import mock

from lazaret.registry.ecosystems import base, golang
from tests import _support
from tests.registry.ecosystem_contract import EcosystemContract

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "go")
PROXY = "https://proxy.golang.org/"
SUMDB = "https://sum.golang.org/lookup/"
gooracle = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "gooracle", "gooracle.py"), "gooracle_for_tests")


def recorded(name):
    with open(os.path.join(HERE, name), "rb") as fh:
        return fh.read()


GOLDEN = json.loads(recorded("golden.json").decode("utf-8"))
REAL = {row["module"]: row for row in GOLDEN["real"]}
LOOKUPS = {row["module"]: row["body"] for row in GOLDEN["lookups"]}
MOD = "github.com/pmezard/go-difflib"
DIFFLIB = REAL[MOD]
DIFFLIB_ZIP = recorded(DIFFLIB["zip"])
ERRORS = REAL["github.com/pkg/errors"]
ERRORS_ZIP = recorded(ERRORS["zip"])
ROOT = "example.com/m@v1.0.0/"
DIFFLIB_ROOT = f"{MOD}@v1.0.0/"
# The document the proxy answers `.info` and `@latest` with (`go help goproxy`): the tag's commit time.
INFO = json.dumps({"Version": "v1.0.0", "Time": "2016-01-10T10:55:54Z"}).encode("utf-8")
HASH_A, HASH_B = "h1:" + "A" * 43 + "=", "h1:" + "B" * 43 + "="


def difflib_responses():
    return {PROXY + MOD + "/@v/v1.0.0.info": INFO, PROXY + MOD + "/@latest": INFO,
            SUMDB + MOD + "@v1.0.0": LOOKUPS[MOD].encode("utf-8"), PROXY + MOD + "/@v/v1.0.0.zip": DIFFLIB_ZIP,
            PROXY + MOD + "/@v/v1.0.0.mod": DIFFLIB["gomod"].encode("utf-8")}


def lookup_text(module, version, zip_hash=HASH_A, mod_hash=HASH_B, record_id="7", tree=True, extra=""):
    """A checksum database response of the layout Go's server writes, for tests that change one thing in it."""
    record = f"{module} {version} {zip_hash}\n" + (f"{module} {version}/go.mod {mod_hash}\n" if mod_hash else "") + extra
    note = "go.sum database tree\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\n— test.sum.example c2lnbmF0dXJl\n" if tree else ""
    return f"{record_id}\n{record}\n{note}"


class Served:
    """A `Fetch` over recorded responses, remembering what the transport was asked for."""

    def __init__(self, responses):
        self.calls = []
        eco = golang.Go()

        def transport(url, **kw):
            self.calls.append((url, kw))
            body = responses.get(url)
            if body is None:
                err = base.FetchError("not found")
                err.status = 404
                raise err
            if isinstance(body, BaseException):
                raise body
            return body
        self.fetch = base.Fetch(eco, transport, clock=lambda: 0.0, sleep=lambda s: None)
        self.urls = lambda: [url for url, _ in self.calls]


def resolve(name=MOD, version="v1.0.0", responses=None):
    served = Served(difflib_responses() if responses is None else responses)
    return golang.Go().resolve(name, version, served.fetch), served


def rewrite(data, change):
    """The zip `data` with each member passed through `change(zip_out, info, content)`."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            change(dst, info, src.read(info))
    return out.getvalue()


def zip_of(entries, comment=b""):
    """entries: (name, data) or (name, data, flags, method)."""
    return gooracle.build_zip([(e[0] if isinstance(e[0], bytes) else e[0].encode("utf-8"), e[1], e[2] if len(e) > 2 else 0,
                                e[3] if len(e) > 3 else 8) for e in entries], comment)


class GoContract(EcosystemContract, unittest.TestCase):
    GOOD_NAMES = ("github.com/pkg/errors", "golang.org/x/mod", "github.com/Azure/azure-sdk-for-go", "gopkg.in/yaml.v3",
                  "github.com/x/y/v2", "k8s.io/api", "example.com/a.b-c_d~e", "a.b", "x.io/" + "a/" * 20 + "z")
    GOOD_VERSIONS = ("v1.0.0", "v0.1.0-alpha.1", "v1.2.3+incompatible", "v0.0.0-20190101000000-abcdefabcdef", "v2.0.0-RC.1",
                     "v10.20.30", "v1.0.0-x.7.z.92")
    GOOD_SPEC = (MOD, "v1.0.0")
    SAME_IDENTITY = ((MOD, MOD), ("github.com/x/y/v2", "github.com/x/y/v2"))
    DIFFERENT_IDENTITY = (("github.com/Azure/x", "github.com/azure/x"), ("github.com/x/y", "github.com/x/y/v2"),
                          ("golang.org/x/mod", "golang.org/x/Mod"))
    EXTRA_BAD_NAMES = ("example.com/", "/example.com", "example.com//x", "example.com/../x", "example.com/./x", "example.com/.x",
                       "example.com/x.", "Example.com/x", "-example.com/x", "example.com/CON", "example.com/x y", "example.com/é",
                       "example.com/a:b", "example.com/a@b", "example.com/a%2fb", "example.com/v1", "example.com/v0", "example.com/x/v2.0",
                       "example.com/x/v02", "gopkg.in/yaml", "gopkg.in/yaml.v01", "example", "x/y",
                       "example.com/a+b", "example.com/x~1", "github.com/" + "a" * 250, "exämple.com/x", "example.com/x?y=1",
                       "example.com/x#y", "example.com\\x", "https://example.com/x", "example.com/NUL.txt", "example.com/lpt1")
    EXTRA_BAD_VERSIONS = ("v1", "v1.0", "v01.0.0", "v1.0.0-", "v1.0.0+meta", "v1.0.0+incompatible+incompatible", "V1.0.0", "1.0.0",
                          "v1.0.0-01", "latest", "master", "v1.0.0-α", "v1.0.0+a..b", "v1.0.0-a..b", "v1.0.0+INCOMPATIBLE", "vv1.0.0",
                          "v1.0.0.0", "v-1.0.0", "v1.-1.0", "v1.0.0-" + "a" * 100, "go1.0.0", "v1.0.0 +incompatible", "@v1.0.0")
    MISSING_VERSION = "v9.9.9"
    DIGEST_COVERS_EVERY_BYTE = False
    GOOD_ARCHIVE_MEMBERS = tuple(zipfile.ZipFile(io.BytesIO(DIFFLIB_ZIP)).namelist())
    MEMBER_PATHS = (
        ("gomod", DIFFLIB_ROOT + "difflib/difflib.go", DIFFLIB_ROOT, ("difflib/difflib.go", None)),
        ("gomod", DIFFLIB_ROOT + "LICENSE", DIFFLIB_ROOT, ("LICENSE", None)),
        ("gomod", DIFFLIB_ROOT + "go.mod", DIFFLIB_ROOT, ("go.mod", None)),
        ("gomod", DIFFLIB_ROOT + "a b/c d.go", DIFFLIB_ROOT, ("a b/c d.go", None)),
        ("gomod", DIFFLIB_ROOT + "é/中.go", DIFFLIB_ROOT, ("é/中.go", None)),
        ("gomod", DIFFLIB_ROOT + "sub/", DIFFLIB_ROOT, (None, None)),
        ("gomod", DIFFLIB_ROOT, DIFFLIB_ROOT, (None, None)),
        ("gomod", DIFFLIB_ROOT + "sub/go.mod", DIFFLIB_ROOT, (None, "go.mod not in the module root directory, or not spelled go.mod")),
        ("gomod", DIFFLIB_ROOT + "GO.MOD", DIFFLIB_ROOT, (None, "go.mod not in the module root directory, or not spelled go.mod")),
        ("gomod", DIFFLIB_ROOT + "../x", DIFFLIB_ROOT, (None, "member path refused by Go (a path element made of dots)")),
        ("gomod", DIFFLIB_ROOT + "a//b", DIFFLIB_ROOT, (None, "member path refused by Go (double slash)")),
        ("gomod", DIFFLIB_ROOT + "a\\b", DIFFLIB_ROOT, (None, "member path refused by Go (invalid character in a path element)")),
        ("gomod", DIFFLIB_ROOT + "/a", DIFFLIB_ROOT, (None, "member path refused by Go (empty path element)")),
        ("gomod", DIFFLIB_ROOT + "CON", DIFFLIB_ROOT, (None, "member path refused by Go (a Windows device name as a path element)")),
        ("gomod", "other@v1.0.0/x.go", DIFFLIB_ROOT, (None, "member outside the archive's root directory")),
        ("gomod", MOD + "@v1.0.00/x.go", DIFFLIB_ROOT, (None, "member outside the archive's root directory")),
        ("gomod", "x.go", DIFFLIB_ROOT, (None, "member outside the archive's root directory")),
        ("gomod", DIFFLIB_ROOT + "x.go", None, ("x.go", None)),
        ("gomod", "a/b/c@v1.2.3/d/e.go", None, ("d/e.go", None)),
        ("gomod", "x.go", None, (None, "member outside the archive's root directory")),
        ("gomod", "a/b/x.go", None, (None, "member outside the archive's root directory")),
    )

    def make(self):
        return golang.Go()

    def responses(self):
        return difflib_responses()

    def verify_case(self):
        res, _ = resolve()
        return DIFFLIB_ZIP, res.artifacts[0]["entry"], MOD, "v1.0.0"

    def malformed_digests(self):
        return [{"h1": "zz"}, {"h1": 5}, {"h1": ""}, {}, {"h1": "h1:"}, {"h1": "h1:" + "A" * 44}, {"h1": "h1:" + "A" * 43 + "x"},
                {"h1": "H1:" + "A" * 43 + "="}, {"h1": ["h1:" + "A" * 43 + "="]}, {"h1": None}, {"h1": "h1:" + "A" * 43 + "=\n"},
                {"h1": " h1:" + "A" * 43 + "="}, {"h1": "h2:" + "A" * 43 + "="}]

    def roots(self):
        return {"gomod": DIFFLIB_ROOT}

    def changed_downloads(self, data):
        first = zipfile.ZipFile(io.BytesIO(data)).infolist()[0]

        def plain(dst, info, content):
            dst.writestr(info.filename, content)

        def one_byte(dst, info, content):
            dst.writestr(info.filename, content[:-1] + bytes([content[-1] ^ 1]) if info is not None and info.filename == first.filename and content else content)

        def added(dst, info, content):
            dst.writestr(info.filename, content)
            if info.filename == first.filename:
                dst.writestr(DIFFLIB_ROOT + "evil.go", b"package evil\n")

        def removed(dst, info, content):
            if info.filename != first.filename:
                dst.writestr(info.filename, content)

        def renamed(dst, info, content):
            dst.writestr(info.filename + "x" if info.filename == first.filename else info.filename, content)

        def recased(dst, info, content):
            dst.writestr(info.filename.swapcase() if info.filename == first.filename else info.filename, content)
        return [rewrite(data, f) for f in (one_byte, added, removed, renamed, recased)]


class GoldenTests(unittest.TestCase):
    """Go's answers (`recorded/go/golden.json`, from `gooracle.py golden`), compared with this module's."""

    def test_the_file_says_where_it_came_from_and_is_not_small(self):
        self.assertIn("golang.org/x/mod", GOLDEN["oracle"])
        for table, least in (("paths", 150), ("splits", 100), ("versions", 150), ("majors", 100), ("members", 300), ("gomods", 50),
                             ("zips", 80)):
            self.assertGreaterEqual(len(GOLDEN[table]), least, table)
        self.assertTrue(any(row[1] for row in GOLDEN["paths"]) and not all(row[1] for row in GOLDEN["paths"]))

    def test_module_paths_are_valid_when_go_says_so_and_escape_the_way_go_does(self):
        eco = golang.Go()
        for path, ok, escaped in GOLDEN["paths"]:
            with self.subTest(path=path[:50]):
                self.assertEqual(golang.check_module_path(path) is None, ok)
                if ok and len(path) <= golang.MAX_NAME:
                    self.assertEqual(eco.check_name(path), path)
                    self.assertEqual(golang.escape(path), escaped)
                    self.assertEqual(eco.segment(path), escaped)
                else:
                    with self.assertRaises(base.SpecError):
                        eco.check_name(path)

    def test_path_splits_are_gos(self):
        for path, prefix, major, ok in GOLDEN["splits"]:
            with self.subTest(path=path[:50]):
                self.assertEqual(golang.split_path_version(path), (prefix, major, ok))

    def test_versions_are_module_versions_when_go_says_so(self):
        eco = golang.Go()
        for version, ok, canonical, pseudo in GOLDEN["versions"]:
            with self.subTest(version=version[:50]):
                self.assertEqual(golang.canonical_version(version), canonical)
                self.assertEqual(golang.is_pseudo_version(version), pseudo)
                if len(version) <= golang.MAX_VERSION and version == version.strip():
                    if ok:
                        self.assertEqual(eco.check_version(version), version)
                    else:
                        with self.assertRaises(base.SpecError):
                            eco.check_version(version)

    def test_path_major_checks_are_gos(self):
        for version, major, ok in GOLDEN["majors"]:
            with self.subTest(version=version, major=major):
                self.assertEqual(golang.check_path_major(version, major), ok)

    def test_zip_member_paths_are_accepted_when_gos_check_accepts_them(self):
        eco = golang.Go()
        for name, ok in GOLDEN["members"]:
            with self.subTest(name=name[:50]):
                rel, problem = eco.member_path("gomod", ROOT + name, ROOT)
                self.assertEqual(problem is None, ok)
                self.assertEqual(eco.member_path("gomod", ROOT + name), (rel, problem), "the derived root is another")
                if ok:
                    self.assertEqual(rel is None, name.endswith("/"))

    def test_go_mod_files_read_the_way_modfile_reads_them(self):
        for text, module, requires in GOLDEN["gomods"]:
            with self.subTest(text=text[:60]):
                got = golang.parse_gomod(text)
                self.assertEqual(got["module"], module)
                self.assertEqual([list(r) for r in got["require"]], requires)

    def test_zip_hashes_are_gos_on_every_shape_of_zip(self):
        refused = 0
        for case in GOLDEN["zips"]:
            with self.subTest(case=case["label"]):
                data = gooracle.zip_of(case)
                if case["h1"] is None:
                    refused += 1
                    with self.assertRaises(base.DigestError):
                        golang.zip_h1(data)
                else:
                    self.assertEqual(golang.zip_h1(data), case["h1"])
        self.assertTrue(0 < refused < len(GOLDEN["zips"]))

    def test_real_modules_hash_to_the_published_go_sum_lines(self):
        self.assertEqual(golang.zip_h1(DIFFLIB_ZIP), "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=")
        self.assertEqual(golang.zip_h1(ERRORS_ZIP), "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=")
        for row in GOLDEN["real"]:
            with self.subTest(module=row["module"]):
                self.assertEqual(golang.file_h1(row["gomod"].encode("utf-8")), row["gomod_h1"])
                if "zip" in row:
                    self.assertEqual(golang.zip_h1(recorded(row["zip"])), row["h1"])

    def test_the_lookups_made_by_gos_server_parse_to_the_real_hashes(self):
        for row in GOLDEN["real"]:
            with self.subTest(module=row["module"]):
                got = golang.parse_lookup(LOOKUPS[row["module"]], row["module"], row["version"])
                self.assertEqual((got["h1"], got["gomod_h1"]), (row["h1"], row["gomod_h1"]))
                self.assertIsInstance(got["id"], int)


class NameTests(unittest.TestCase):
    def setUp(self):
        self.eco = golang.Go()

    def test_a_capital_letter_is_a_bang_and_its_lower_case(self):
        self.assertEqual(golang.escape("github.com/Azure/azure-sdk-for-go"), "github.com/!azure/azure-sdk-for-go")
        self.assertEqual(golang.escape("v1.0.0-RC.1"), "v1.0.0-!r!c.1")
        self.assertEqual(golang.escape("abc"), "abc")
        self.assertEqual(golang.escape(""), "")

    def test_segment_is_the_escaped_form_of_a_checked_name_or_version(self):
        self.assertEqual(self.eco.segment("github.com/Azure/x"), "github.com/!azure/x")
        self.assertEqual(self.eco.segment("v1.2.3+incompatible"), "v1.2.3+incompatible")
        self.assertEqual(self.eco.segment("v1.0.0-RC.1"), "v1.0.0-!r!c.1")

    def test_segment_of_anything_else_is_quoted_whole(self):
        for value in ("../..", "a/../b", "x?y", "x#y", "a b", "%2e%2e", "é", "x\x00y", "", "example.com/x/", "github.com/" + "a" * 300):
            with self.subTest(value=value[:30]):
                seg = self.eco.segment(value)
                self.assertNotIn("/", seg)
                self.assertNotIn("..", seg.replace("%2E", "").replace("%2e", "") if value == "x" else "")
        self.assertEqual(self.eco.segment("../.."), "..%2F..")
        self.assertEqual(self.eco.segment(5), "5")

    def test_names_are_case_sensitive_and_identity_keeps_them_apart(self):
        self.assertNotEqual(self.eco.identity("github.com/Azure/x"), self.eco.identity("github.com/azure/x"))
        self.assertEqual(self.eco.identity("github.com/x/y"), "github.com/x/y")

    def test_the_length_limit_is_255(self):
        ok = "github.com/" + "a" * (255 - 11)
        self.assertEqual(len(ok), 255)
        self.assertEqual(self.eco.check_name(ok), ok)
        with self.assertRaises(base.SpecError) as caught:
            self.eco.check_name(ok + "a")
        self.assertNotIn("aaaa", str(caught.exception))

    def test_a_refused_name_is_cut_in_the_message(self):
        with self.assertRaises(base.SpecError) as caught:
            self.eco.check_name("example.com/" + "x" * 100 + "‮")
        self.assertNotIn("‮", str(caught.exception))
        self.assertLess(len(str(caught.exception)), 200)

    def test_the_reason_is_a_fixed_sentence(self):
        for path, why in (("example", "missing dot in the first path element"), ("example.com//x", "double slash"),
                          ("example.com/x/", "trailing slash"), ("-a.com/x", "leading dash"), ("", "empty"),
                          ("A.com/x", "invalid character in the first path element"), ("example.com/v1", "invalid major version suffix"),
                          ("example.com/a\ud800", "invalid UTF-8"), ("example.com/.x", "leading dot in a path element"),
                          ("example.com/x.", "trailing dot in a path element"), ("example.com/x~12", "trailing tilde and digits in a path element"),
                          ("example.com/aux.x", "a Windows device name as a path element"), ("example.com/..", "a path element made of dots"),
                          ("example.com/a b", "invalid character in a path element"), ("/example.com", "empty path element"), (5, "not text")):
            with self.subTest(path=repr(path)[:30]):
                self.assertEqual(golang.check_module_path(path), why)

    def test_a_spec_may_say_a_version(self):
        self.assertEqual(self.eco.parse_spec("github.com/pkg/errors@v0.9.1"), ("github.com/pkg/errors", "v0.9.1"))
        self.assertEqual(self.eco.parse_spec("github.com/pkg/errors"), ("github.com/pkg/errors", None))
        self.assertEqual(self.eco.parse_spec("gopkg.in/yaml.v3@v3.0.1+incompatible"), ("gopkg.in/yaml.v3", "v3.0.1+incompatible"))


class VersionTests(unittest.TestCase):
    def test_the_canonical_form_fills_in_what_is_short_and_drops_build_metadata(self):
        for version, want in (("v1", "v1.0.0"), ("v1.2", "v1.2.0"), ("v1.2.3", "v1.2.3"), ("v1.2.3-pre", "v1.2.3-pre"),
                              ("v1.2.3+meta", "v1.2.3"), ("v1.2.3+incompatible", "v1.2.3+incompatible"),
                              ("v1.2.3-pre+incompatible", "v1.2.3-pre+incompatible"), ("v1-pre", ""), ("v1.2+build", ""),
                              ("1.2.3", ""), ("", ""), ("v", ""), ("v01.2.3", ""), (5, ""), (None, ""), ("v1.2.3" + "x" * 100, "")):
            with self.subTest(version=version):
                self.assertEqual(golang.canonical_version(version), want)

    def test_a_pseudo_version_has_a_timestamp_and_a_commit(self):
        for version in ("v0.0.0-20190101000000-abcdefabcdef", "v1.2.3-0.20190101000000-abcdefabcdef", "v1.2.4-pre.0.20190101000000-abcdefabcdef",
                        "v0.0.0-20190101000000-abcdefabcdef+incompatible"):
            self.assertTrue(golang.is_pseudo_version(version), version)
        for version in ("v1.0.0", "v1.0.0-rc.1", "v0.0.0-2019", "v0.0.0-20190101000000", "v1.2.3-20190101000000-abcdefabcdef",
                        "v01.0.0-20190101000000-abcdefabcdef", ""):
            self.assertFalse(golang.is_pseudo_version(version), version)

    def test_a_version_with_surrounding_space_is_stripped_and_none_is_latest(self):
        eco = golang.Go()
        self.assertEqual(eco.check_version("  v1.0.0\n"), "v1.0.0")
        self.assertIsNone(eco.check_version(None))
        for bad in ("", "   ", "\n"):
            with self.assertRaises(base.SpecError):
                eco.check_version(bad)

    def test_a_version_must_fit_the_major_version_in_the_path(self):
        for path, version, ok in (("github.com/x/y", "v1.2.3", True), ("github.com/x/y", "v0.1.0", True), ("github.com/x/y", "v2.0.0", False),
                                  ("github.com/x/y", "v2.0.0+incompatible", True), ("github.com/x/y/v2", "v2.1.0", True),
                                  ("github.com/x/y/v2", "v1.1.0", False), ("github.com/x/y/v2", "v2.1.0+incompatible", True),
                                  ("gopkg.in/yaml.v3", "v3.0.1", True), ("gopkg.in/yaml.v3", "v2.0.0", False),
                                  ("gopkg.in/yaml.v1", "v0.0.0-20190101000000-abcdefabcdef", True),
                                  ("gopkg.in/yaml.v3-unstable", "v3.0.0", True)):
            with self.subTest(path=path, version=version):
                self.assertEqual(golang.check_path_major(version, golang.split_path_version(path)[1]), ok)


class ResolveTests(unittest.TestCase):
    def test_a_version_asks_for_its_info_and_its_checksum_and_names_the_zip(self):
        res, served = resolve()
        self.assertEqual(res[0], "v1.0.0")
        self.assertEqual(served.urls(), [PROXY + MOD + "/@v/v1.0.0.info", SUMDB + MOD + "@v1.0.0"])
        art = res.artifacts[0]
        self.assertEqual(art["url"], PROXY + MOD + "/@v/v1.0.0.zip")
        self.assertEqual((art["container"], art["artifact"], art["filename"]), ("zip", "gomod", "go-difflib@v1.0.0.zip"))
        self.assertEqual(art["entry"], {"h1": DIFFLIB["h1"], "gomod_h1": DIFFLIB["gomod_h1"]})
        self.assertEqual(res.skipped, [])
        self.assertEqual(res.info, {"module": MOD, "root": DIFFLIB_ROOT, "pseudo": False, "sumdb": "tls", "time": "2016-01-10T10:55:54Z"})
        self.assertEqual(tuple(res), ("v1.0.0", art["url"], "zip", "gomod", art["entry"]))

    def test_no_version_asks_for_latest(self):
        res, served = resolve(version=None)
        self.assertEqual(served.urls(), [PROXY + MOD + "/@latest", SUMDB + MOD + "@v1.0.0"])
        self.assertEqual(res[0], "v1.0.0")

    def test_capitals_are_escaped_in_every_url(self):
        name, version = "github.com/Azure/azure-sdk-for-go", "v1.0.0-RC.1"
        urls = {PROXY + "github.com/!azure/azure-sdk-for-go/@v/v1.0.0-!r!c.1.info": json.dumps({"Version": version}).encode(),
                SUMDB + "github.com/!azure/azure-sdk-for-go@v1.0.0-!r!c.1": lookup_text(name, version).encode()}
        res, served = resolve(name, version, urls)
        self.assertEqual(served.urls(), list(urls))
        self.assertEqual(res.artifacts[0]["url"], PROXY + "github.com/!azure/azure-sdk-for-go/@v/v1.0.0-!r!c.1.zip")
        self.assertEqual(res.artifacts[0]["filename"], "azure-sdk-for-go@v1.0.0-RC.1.zip")
        self.assertEqual(res.info["root"], "github.com/Azure/azure-sdk-for-go@v1.0.0-RC.1/")
        self.assertIsNone(res.info["time"])

    def test_a_pseudo_version_is_said_to_be_one(self):
        version = "v0.0.0-20190101000000-abcdefabcdef"
        res, _ = resolve(MOD, version, {PROXY + MOD + "/@v/" + version + ".info": json.dumps({"Version": version}).encode(),
                                        SUMDB + MOD + "@" + version: lookup_text(MOD, version).encode()})
        self.assertTrue(res.info["pseudo"])

    def test_a_plus_incompatible_version_keeps_its_plus(self):
        name, version = "github.com/x/y", "v2.1.0+incompatible"
        res, served = resolve(name, version, {PROXY + name + "/@v/" + version + ".info": json.dumps({"Version": version}).encode(),
                                              SUMDB + name + "@" + version: lookup_text(name, version).encode()})
        self.assertEqual(res.artifacts[0]["url"], PROXY + name + "/@v/" + version + ".zip")

    def test_a_version_that_does_not_fit_the_path_is_refused_before_a_request(self):
        served = Served(difflib_responses())
        for name, version in (("github.com/x/y", "v2.0.0"), ("github.com/x/y/v2", "v1.0.0"), ("gopkg.in/yaml.v3", "v2.0.0")):
            with self.assertRaises(base.SpecError):
                golang.Go().resolve(name, version, served.fetch)
        self.assertEqual(served.calls, [])

    def test_a_name_or_version_that_is_not_valid_is_refused_before_a_request(self):
        served = Served(difflib_responses())
        for name, version in (("example", None), (MOD, "latest"), (MOD, "v1"), ("../x", "v1.0.0")):
            with self.assertRaises(base.SpecError):
                golang.Go().resolve(name, version, served.fetch)
        self.assertEqual(served.calls, [])

    def test_the_proxy_answering_for_another_version_is_refused(self):
        for answer in ({"Version": "v1.0.1"}, {"Version": "v2.0.0"}, {"Version": "v1.0.0+incompatible"}):
            with self.subTest(answer=answer):
                responses = dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.info": json.dumps(answer).encode()})
                with self.assertRaises(base.FetchError):
                    resolve(responses=responses)

    def test_latest_answering_with_a_version_of_another_major_is_refused(self):
        responses = dict(difflib_responses(), **{PROXY + MOD + "/@latest": json.dumps({"Version": "v2.0.0"}).encode()})
        with self.assertRaises(base.FetchError):
            resolve(version=None, responses=responses)

    def test_an_info_document_of_the_wrong_shape_is_a_fetch_error(self):
        for doc in (b"[]", b"{}", b'{"Version": 5}', b'{"Version": null}', b'{"Version": "v1"}', b'{"Version": "../x"}', b"not json",
                    b'{"Version": "v1.0.0\\u202e"}', b'"v1.0.0"', b'{"version": "v1.0.0"}'):
            with self.subTest(doc=doc):
                with self.assertRaises(base.FetchError):
                    resolve(responses=dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.info": doc}))

    def test_a_time_that_is_not_a_time_is_dropped(self):
        for stamp, kept in (("2016-01-10T10:55:54Z", True), ("2016-01-10T10:55:54.123456Z", True), ("2016-01-10T11:55:54+01:00", True),
                            (5, False), ("yesterday", False), ("2016-01-10T10:55:54Z\n<script>", False), ("", False), (None, False)):
            doc = json.dumps({"Version": "v1.0.0", "Time": stamp}).encode()
            res, _ = resolve(responses=dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.info": doc}))
            self.assertEqual(res.info["time"], stamp if kept else None, stamp)

    def test_a_module_the_proxy_does_not_have_is_a_fetch_error_with_the_status(self):
        with self.assertRaises(base.FetchError) as caught:
            resolve("github.com/none/none", "v1.0.0")
        self.assertEqual(caught.exception.status, 404)

    def test_a_checksum_database_that_fails_fails_the_resolve(self):
        for failure in (base.FetchError("budget"), OSError("down"), None):
            responses = dict(difflib_responses())
            responses[SUMDB + MOD + "@v1.0.0"] = failure
            if failure is None:
                del responses[SUMDB + MOD + "@v1.0.0"]
            with self.subTest(failure=repr(failure)):
                with self.assertRaises(base.FetchError):
                    resolve(responses=responses)

    def test_a_checksum_response_over_64_kib_is_refused(self):
        responses = dict(difflib_responses(), **{SUMDB + MOD + "@v1.0.0": b" " * (64 * 1024 + 1)})
        with self.assertRaises(base.FetchError):
            resolve(responses=responses)

    def test_the_checksum_request_is_bounded_and_the_hosts_are_the_two(self):
        res, served = resolve()
        by_url = {url: kw for url, kw in served.calls}
        self.assertEqual(by_url[SUMDB + MOD + "@v1.0.0"]["max_bytes"], golang.MAX_LOOKUP_BYTES)
        self.assertEqual(golang.Go().hosts, frozenset({"proxy.golang.org", "sum.golang.org"}))
        with self.assertRaises(base.FetchError):
            served.fetch.check_url("https://index.golang.org/index?since=2019-04-10T19:08:52.997264Z")

    def test_two_threads_asking_get_one_answer(self):
        import threading
        served = Served(difflib_responses())
        answers = []

        def work():
            answers.append(tuple(golang.Go().resolve(MOD, "v1.0.0", served.fetch)))
        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(len(answers), 4)
        self.assertTrue(all(a == answers[0] for a in answers))


class LookupTests(unittest.TestCase):
    GOOD = lookup_text("example.com/m", "v1.0.0")

    def parse(self, text, name="example.com/m", version="v1.0.0"):
        return golang.parse_lookup(text, name, version)

    def test_the_layout_gos_server_writes(self):
        got = self.parse(self.GOOD)
        self.assertEqual(got, {"id": 7, "h1": HASH_A, "gomod_h1": HASH_B})

    def test_a_record_without_a_go_mod_line_has_no_go_mod_hash(self):
        self.assertEqual(self.parse(lookup_text("example.com/m", "v1.0.0", mod_hash=None))["gomod_h1"], None)

    def test_lines_about_other_modules_or_versions_are_read_and_ignored(self):
        extra = f"example.com/m v1.0.1 {HASH_B}\nexample.com/n v1.0.0 {HASH_B}\n"
        self.assertEqual(self.parse(lookup_text("example.com/m", "v1.0.0", extra=extra))["h1"], HASH_A)

    def test_a_response_that_is_not_that_layout_is_refused(self):
        good = self.GOOD
        for label, text in (("empty", ""), ("no record", "7\n\n" + good.split("\n\n", 1)[1]), ("id is not a number", good.replace("7\n", "x\n", 1)),
                            ("id is signed", good.replace("7\n", "-7\n", 1)), ("id is huge", good.replace("7\n", "1" * 19 + "\n", 1)),
                            ("id is empty", good.replace("7\n", "\n", 1)), ("no id line", good.split("\n", 1)[1]),
                            ("no tree head", lookup_text("example.com/m", "v1.0.0", tree=False)),
                            ("no blank line", good.replace("\n\n", "\n", 1)), ("no signature", good.split("—")[0]),
                            ("html", "<html>502 Bad Gateway</html>"), ("json", '{"error": "x"}'), ("only an id", "7\n")):
            with self.subTest(label=label):
                with self.assertRaises(base.FetchError):
                    self.parse(text)

    def test_a_record_line_that_is_not_valid_is_refused(self):
        for label, line in (("two fields", "example.com/m v1.0.0"), ("four fields", f"example.com/m v1.0.0 {HASH_A} x"),
                            ("hash too short", "example.com/m v1.0.0 h1:AAAA="), ("hash not base64", "example.com/m v1.0.0 h1:" + "!" * 43 + "="),
                            ("hash is h2", "example.com/m v1.0.0 h2:" + "A" * 43 + "="), ("two spaces", f"example.com/m  v1.0.0 {HASH_A}"),
                            ("tab", f"example.com/m\tv1.0.0 {HASH_A}"), ("control character", f"example.com/m v1.0.0 {HASH_A}\x01"),
                            ("empty line in the record", f"\n{HASH_A}")):
            with self.subTest(label=label):
                text = f"7\n{line}\n\n" + self.GOOD.split("\n\n", 1)[1]
                with self.assertRaises(base.FetchError):
                    self.parse(text)

    def test_two_hashes_for_one_file_are_refused(self):
        with self.assertRaises(base.FetchError):
            self.parse(lookup_text("example.com/m", "v1.0.0", extra=f"example.com/m v1.0.0 {HASH_B}\n"))
        with self.assertRaises(base.FetchError):
            self.parse(lookup_text("example.com/m", "v1.0.0", extra=f"example.com/m v1.0.0/go.mod {HASH_A}\n"))

    def test_a_record_that_is_about_something_else_is_refused(self):
        for name, version in (("example.com/n", "v1.0.0"), ("example.com/m", "v1.0.1"), ("example.com/M", "v1.0.0"), ("example.com/m/v2", "v1.0.0")):
            with self.subTest(name=name, version=version):
                with self.assertRaises(base.FetchError):
                    self.parse(self.GOOD, name, version)

    def test_only_a_go_mod_line_is_no_hash_for_the_zip(self):
        text = f"7\nexample.com/m v1.0.0/go.mod {HASH_B}\n\n" + self.GOOD.split("\n\n", 1)[1]
        with self.assertRaises(base.FetchError):
            self.parse(text)

    def test_errors_do_not_contain_the_response(self):
        with self.assertRaises(base.FetchError) as caught:
            self.parse("<html>" + "SECRET" * 50 + "</html>")
        self.assertNotIn("SECRET", str(caught.exception))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.eco = golang.Go()
        self.entry = {"h1": DIFFLIB["h1"], "gomod_h1": DIFFLIB["gomod_h1"]}

    def test_the_real_zip_matches_and_reports_the_hash_the_way_go_sum_writes_it(self):
        self.assertEqual(self.eco.verify(DIFFLIB_ZIP, self.entry, MOD, "v1.0.0"), ("h1", DIFFLIB["h1"][3:]))

    def test_a_zip_of_other_contents_is_a_mismatch(self):
        with self.assertRaises(base.DigestError) as caught:
            self.eco.verify(ERRORS_ZIP, self.entry, MOD, "v1.0.0")
        self.assertIn("h1", str(caught.exception))
        self.assertNotIn("PK", str(caught.exception))

    def test_the_bytes_of_a_zip_are_not_what_is_hashed(self):
        """Go hashes the names and the contents. The same files in another order, compressed another way or with a comment
        are the same module, and a proxy's zip need not be the bytes another proxy's is."""
        names = zipfile.ZipFile(io.BytesIO(DIFFLIB_ZIP)).namelist()
        contents = {n: zipfile.ZipFile(io.BytesIO(DIFFLIB_ZIP)).read(n) for n in names}
        for entries, comment in (([(n, contents[n], 0, 0) for n in reversed(names)], b""), ([(n, contents[n], 0x800, 8) for n in names], b"a comment"),
                                 ([(n, contents[n], 0, 8) for n in sorted(names)], b"")):
            blob = zip_of(entries, comment)
            self.assertNotEqual(blob, DIFFLIB_ZIP)
            self.assertEqual(self.eco.verify(blob, self.entry, MOD, "v1.0.0"), ("h1", DIFFLIB["h1"][3:]))

    def test_no_published_hash_is_no_digest(self):
        for entry in (None, {}, {"gomod_h1": HASH_B}, {"h1": None}, 5, "x", []):
            self.assertIsNone(self.eco.verify(DIFFLIB_ZIP, entry, MOD, "v1.0.0"))

    def test_a_download_that_is_not_a_zip_fails_closed(self):
        for blob in (b"", b"PK", b"PK\x05\x06" + b"\x00" * 17, b"not a zip", DIFFLIB_ZIP[:100], DIFFLIB_ZIP[:-30], b"\x1f\x8b\x08" + b"\x00" * 50):
            with self.subTest(size=len(blob)):
                with self.assertRaises(base.DigestError):
                    golang.zip_h1(blob)
                with self.assertRaises(base.DigestError):
                    self.eco.verify(blob, self.entry, MOD, "v1.0.0")

    def test_an_empty_zip_is_a_zip_Go_hashes_and_is_no_match(self):
        empty = b"PK\x05\x06" + b"\x00" * 18
        for blob in (empty, empty + b"x"):                     # (Go reads both; the second has a stray byte after the end record)
            with self.subTest(size=len(blob)):
                self.assertEqual(golang.zip_h1(blob), "h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
                with self.assertRaises(base.DigestError):
                    self.eco.verify(blob, self.entry, MOD, "v1.0.0")

    def test_two_members_that_start_at_one_place_are_refused_and_nothing_is_printed(self):
        blob = bytearray(zip_of([("a.go", b"package a\n", 0, 8), ("b.go", b"package b\n", 0, 8)]))
        first, second = [i for i in range(len(blob)) if blob[i:i + 4] == b"PK\x01\x02"]
        blob[second + 42:second + 46] = blob[first + 42:first + 46]                  # (the second entry's local header offset)
        with warnings.catch_warnings(record=True) as printed:
            warnings.simplefilter("always")
            with self.assertRaisesRegex(base.DigestError, "start at one place"):
                golang.zip_h1(bytes(blob))
            with self.assertRaises(base.DigestError):
                self.eco.verify(bytes(blob), self.entry, MOD, "v1.0.0")
        self.assertEqual([str(w.message) for w in printed], [])

    def test_a_member_with_a_wrong_checksum_fails_closed(self):
        data = bytearray(zip_of([("a.go", b"package a\n", 0, 0)]))
        data[data.index(b"package a") + 3] ^= 1
        with self.assertRaises(base.DigestError):
            golang.zip_h1(bytes(data))

    def test_what_go_refuses_to_hash_fails_closed(self):
        for label, blob in (
                ("two members of one name", zip_of([("a.go", b"1"), ("a.go", b"2")])),
                ("a newline in a name", zip_of([(b"a\nb.go", b"1")])),
                ("a name that says UTF-8 and is not", zip_of([(b"\xff\xfe", b"1", 0x800, 8)])),
                ("a directory with data", zip_of([("d/", b"data")])),
                ("bzip2", zip_of([("a.go", b"x", 0, 12)])),
                ("lzma", zip_of([("a.go", b"x", 0, 14)])),
                ("an encrypted member", zip_of([("a.go", b"x", 0x1, 0)]))):
            with self.subTest(label=label):
                with self.assertRaises(base.DigestError):
                    golang.zip_h1(blob)

    def test_a_directory_is_hashed_as_empty_and_a_name_is_read_as_go_reads_it(self):
        golden = {case["label"]: case for case in GOLDEN["zips"]}
        self.assertTrue(golden)
        with_dir = zip_of([(b"d/", b"", 0, 0), (b"d/a.go", b"x", 0, 8)])
        without = zip_of([(b"d/a.go", b"x", 0, 8)])
        self.assertNotEqual(golang.zip_h1(with_dir), golang.zip_h1(without))

    def test_names_sort_as_bytes_whatever_the_flag(self):
        names = [b"b", b"B", b"a", b"\xc3\xa9", b"z", b"\xe4\xb8\xad", b"A"]
        flagged = zip_of([(n, b"x", 0x800, 0) for n in names])
        shuffled = zip_of([(n, b"x", 0x800, 0) for n in reversed(names)])
        self.assertEqual(golang.zip_h1(flagged), golang.zip_h1(shuffled))
        raw = zip_of([(n, b"x", 0, 0) for n in names])                       # (no UTF-8 flag: cp437 names, the same bytes)
        self.assertEqual(golang.zip_h1(raw), golang.zip_h1(flagged))

    def test_the_limits_are_go_s(self):
        blob = zip_of([("a.go", b"x"), ("b.go", b"y")])
        with mock.patch.object(golang, "MAX_ENTRIES", 1):
            with self.assertRaises(base.DigestError):
                golang.zip_h1(blob)
        with mock.patch.object(golang, "MAX_ZIP_CONTENT", 1):
            with self.assertRaises(base.DigestError):
                golang.zip_h1(blob)
        with mock.patch.object(golang, "MAX_ENTRIES", 2), mock.patch.object(golang, "MAX_ZIP_CONTENT", 2):
            self.assertTrue(golang.zip_h1(blob).startswith("h1:"))
        self.assertEqual((golang.MAX_ZIP_CONTENT, golang.MAX_GOMOD), (500 * 1024 * 1024, 16 * 1024 * 1024))
        self.assertEqual((golang.MAX_NAME, golang.MAX_VERSION, golang.MAX_ENTRIES, golang.MAX_REQUIRES, golang.MAX_LOOKUP_BYTES),
                         (255, 100, 250_000, 20_000, 64 * 1024))

    def test_a_member_is_read_in_pieces(self):
        body = b"abcdefghij" * 300_000                                          # 3 MB: more than one piece
        want = hashlib.sha256(body).hexdigest().encode()
        manual = golang.zip_h1(zip_of([("big.go", body, 0, 8)]))
        line = want + b"  big.go\n"
        self.assertEqual(manual, "h1:" + __import__("base64").b64encode(hashlib.sha256(line).digest()).decode())

    def test_an_error_does_not_contain_the_download(self):
        with self.assertRaises(base.DigestError) as caught:
            golang.zip_h1(b"SECRET" * 100)
        self.assertNotIn("SECRET", str(caught.exception))

    def test_file_h1_is_the_h1_of_one_file_called_go_mod(self):
        data = b"module example.com/m\n"
        line = hashlib.sha256(data).hexdigest().encode() + b"  go.mod\n"
        self.assertEqual(golang.file_h1(data), "h1:" + __import__("base64").b64encode(hashlib.sha256(line).digest()).decode())
        self.assertNotEqual(golang.file_h1(data), golang.file_h1(data, "other.mod"))


class DependencyTests(unittest.TestCase):
    def resolved(self, mod_text=None, mod_hash=None):
        responses = difflib_responses()
        res, _ = resolve(responses=responses)
        if mod_hash is not None:
            res.artifacts[0]["entry"]["gomod_h1"] = mod_hash
        return res

    def test_the_requirements_come_from_the_mod_file_the_proxy_serves(self):
        text = "module example.com/m\n\ngo 1.21\n\nrequire (\n\tgithub.com/b/b v1.0.0\n\tgithub.com/a/a v1.2.0 // indirect\n)\nrequire github.com/a/a v1.2.0\n"
        res = self.resolved(mod_hash=golang.file_h1(text.encode()))
        served = Served(dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.mod": text.encode()}))
        self.assertEqual(golang.Go().dependencies(res, served.fetch), ("github.com/a/a", "github.com/b/b"))
        self.assertEqual(served.urls(), [PROXY + MOD + "/@v/v1.0.0.mod"])

    def test_the_real_mod_file_has_none(self):
        res = self.resolved()
        served = Served(difflib_responses())
        self.assertEqual(golang.Go().dependencies(res, served.fetch), ())

    def test_a_mod_file_that_is_not_the_published_one_is_a_mismatch(self):
        res = self.resolved()
        served = Served(dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.mod": b"module github.com/pmezard/go-difflib\nrequire evil.example/x v1.0.0\n"}))
        with self.assertRaises(base.DigestError):
            golang.Go().dependencies(res, served.fetch)

    def test_names_that_are_not_module_paths_are_dropped(self):
        text = "module example.com/m\nrequire (\n\tgood.example/x v1.0.0\n\tbad v1.0.0\n\t../x v1.0.0\n\tgood.example/Y v1.0.0\n)\n"
        res = self.resolved(mod_hash=golang.file_h1(text.encode()))
        served = Served(dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.mod": text.encode()}))
        self.assertEqual(golang.Go().dependencies(res, served.fetch), ("good.example/Y", "good.example/x"))

    def test_a_missing_published_go_mod_hash_is_not_a_check(self):
        text = "module example.com/m\nrequire a.example/x v1.0.0\n"
        res = self.resolved()
        res.artifacts[0]["entry"]["gomod_h1"] = None
        served = Served(dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.mod": text.encode()}))
        self.assertEqual(golang.Go().dependencies(res, served.fetch), ("a.example/x",))

    def test_a_mod_file_that_is_not_text_is_a_fetch_error(self):
        res = self.resolved(mod_hash=golang.file_h1(b"\xff\xfe"))
        served = Served(dict(difflib_responses(), **{PROXY + MOD + "/@v/v1.0.0.mod": b"\xff\xfe"}))
        with self.assertRaises(base.FetchError):
            golang.Go().dependencies(res, served.fetch)

    def test_a_missing_mod_file_is_a_fetch_error(self):
        res = self.resolved()
        responses = difflib_responses()
        del responses[PROXY + MOD + "/@v/v1.0.0.mod"]
        with self.assertRaises(base.FetchError):
            golang.Go().dependencies(res, Served(responses).fetch)

    def test_the_mod_file_is_asked_for_with_the_go_mod_limit(self):
        res = self.resolved()
        served = Served(difflib_responses())
        golang.Go().dependencies(res, served.fetch)
        self.assertEqual(served.calls[0][1]["max_bytes"], golang.MAX_GOMOD)

    def test_something_that_is_not_a_resolution_is_none(self):
        served = Served({})
        for odd in (None, 5, "x", (), object(), {"info": {}}):
            self.assertIsNone(golang.Go().dependencies(odd, served.fetch))
        self.assertEqual(served.calls, [])

    def test_a_resolution_with_a_name_that_was_not_checked_asks_nothing(self):
        res = self.resolved()
        res.info["module"] = "../../etc/passwd"
        served = Served({})
        self.assertIsNone(golang.Go().dependencies(res, served.fetch))
        self.assertEqual(served.calls, [])


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.eco = golang.Go()

    def test_the_root_is_the_module_at_the_version(self):
        res, _ = resolve()
        self.assertEqual(self.eco.archive_root(res, res.artifacts[0]), DIFFLIB_ROOT)
        self.assertEqual(res.info["root"], DIFFLIB_ROOT)

    def test_the_root_keeps_the_capitals_of_the_path_and_the_version(self):
        name, version = "github.com/Azure/x", "v1.0.0-RC.1"
        res, _ = resolve(name, version, {PROXY + "github.com/!azure/x/@v/v1.0.0-!r!c.1.info": json.dumps({"Version": version}).encode(),
                                         SUMDB + "github.com/!azure/x@v1.0.0-!r!c.1": lookup_text(name, version).encode()})
        self.assertEqual(self.eco.archive_root(res, res.artifacts[0]), "github.com/Azure/x@v1.0.0-RC.1/")

    def test_a_root_is_not_made_of_what_was_not_checked(self):
        res, _ = resolve()
        for module in ("../x", "", None, 5, "example"):
            res.info["module"] = module
            self.assertIsNone(self.eco.archive_root(res, res.artifacts[0]))

    def test_the_real_archive_sits_under_its_root_and_nothing_is_a_link(self):
        for blob, root in ((DIFFLIB_ZIP, DIFFLIB_ROOT), (ERRORS_ZIP, "github.com/pkg/errors@v0.9.1/")):
            for name in zipfile.ZipFile(io.BytesIO(blob)).namelist():
                rel, problem = self.eco.member_path("gomod", name, root)
                self.assertIsNone(problem, name)
                self.assertTrue(rel)
        self.assertIs(self.eco.links_extracted("gomod"), False)

    def test_a_name_is_taken_as_text(self):
        self.assertEqual(self.eco.member_path("gomod", 5, "5/"), (None, "member outside the archive's root directory"))
        self.assertEqual(self.eco.member_path("gomod", b"x", None), (None, "member outside the archive's root directory"))

    def test_container(self):
        for name, want in (("errors@v0.9.1.zip", "zip"), ("x.zip", "zip"), ("x.tar.gz", None), ("x.ZIP", None), ("x", None), (None, None), (5, None)):
            self.assertEqual(self.eco.container(name), want)

    def test_an_odd_root_is_still_safe(self):
        for root in ("a@b/", "x@v1.0.0/y@v2.0.0/", "@/", "a@/"):
            for name in (root + "a.go", root + "../a.go", root + "a/../b.go"):
                rel, problem = self.eco.member_path("gomod", name, root)
                self.assertTrue(rel is None or (rel and ".." not in rel.split("/") and not rel.startswith("/")), (root, name, rel, problem))


class RunTests(unittest.TestCase):
    def setUp(self):
        self.eco = golang.Go()

    def targets(self, *members):
        return self.eco.run_targets("gomod", {}, list(members))

    def test_the_programs_a_go_install_builds_are_entries(self):
        got = self.targets("main.go", "cmd/tool/main.go", "cmd/tool/flags.go", "lib/lib.go", "sub/main.go", "cmd/tool/main_test.go",
                           "cmd/tool/internal/x.go", "cmd/readme.md")
        self.assertEqual(got.entries, frozenset({"main.go", "cmd/tool/main.go", "cmd/tool/flags.go", "sub/main.go"}))
        self.assertEqual(got.install_scripts, frozenset())
        self.assertEqual(got.startup, frozenset())

    def test_what_is_handed_to_other_tools_is_an_install_script(self):
        got = self.targets("a.c", "a.h", "b.cc", "b.cpp", "c.s", "d.S", "e.syso", "f.swig", "g.m", "x/y.cxx", "lib.go", "README.md", "_skip.c", ".hidden.s",
                           "dir.c/x.txt", "noext", "a.C")
        # (`a.C` is not an extension Go's build knows; it is marked anyway, which only means it is read with the rest)
        self.assertEqual(got.install_scripts, frozenset({"a.c", "b.cc", "b.cpp", "c.s", "d.S", "e.syso", "f.swig", "g.m", "x/y.cxx", "a.C"}))
        for not_want in ("a.h", "lib.go", "README.md", "_skip.c", ".hidden.s", "dir.c/x.txt", "noext"):
            self.assertNotIn(not_want, got.install_scripts)

    def test_test_files_are_not_run(self):
        got = self.targets("main_test.go", "cmd/x/main_test.go", "a_test.c")
        self.assertEqual(got.entries, frozenset())

    def test_odd_members_do_nothing(self):
        got = self.eco.run_targets("gomod", {}, [None, 5, b"x", "", "/", "//", "cmd/", "cmd//x.go", ".", ".go"] + [chr(i) + ".go" for i in range(32)])
        self.assertIsInstance(got, base.RunTargets)
        self.assertEqual(self.eco.run_targets("gomod", {}, None), base.RunTargets())

    def test_the_real_module_has_nothing_that_runs_at_build(self):
        names = zipfile.ZipFile(io.BytesIO(DIFFLIB_ZIP)).namelist()
        members = [self.eco.member_path("gomod", n, DIFFLIB_ROOT)[0] for n in names]
        self.assertEqual(self.eco.run_targets("gomod", {}, members), base.RunTargets())

    def test_declared_is_the_module_line_and_the_requirements(self):
        text = 'module example.com/m\n\ngo 1.22\n\nrequire (\n\tb.example/x v1.0.0\n\ta.example/y v1.0.0 // indirect\n)\nrequire "c.example/z" v2.0.0+incompatible\n'
        got = self.eco.declared("gomod", {"go.mod": text}, [])
        self.assertEqual(got, base.Declared("example.com/m", ["a.example/y", "b.example/x", "c.example/z"],
                                            {"a.example/y": "v1.0.0", "b.example/x": "v1.0.0", "c.example/z": "v2.0.0+incompatible"}))
        self.assertEqual(got.aliases, {})

    def test_declared_drops_what_is_not_a_module_path(self):
        text = "module not-a-path\nrequire (\n\tbad v1.0.0\n\tgood.example/x v1.0.0\n\tgood.example/x v1.1.0\n)\n"
        self.assertEqual(self.eco.declared("gomod", {"go.mod": text}, []),
                         base.Declared(None, ["good.example/x"], {"good.example/x": "v1.0.0"}))      # (a module listed twice: the first line's version)

    def test_declared_of_nothing_is_nothing(self):
        for manifests in ({}, {"go.mod": ""}, {"go.mod": None}, {"go.mod": 5}, None, {"other": "module a.b/c"}):
            self.assertEqual(self.eco.declared("gomod", manifests, []), base.Declared())

    def test_the_manifests_it_wants_are_go_mod(self):
        self.assertEqual(self.eco.manifest_names, frozenset({"go.mod"}))


class GoModTests(unittest.TestCase):
    def test_a_block_a_single_line_quotes_comments_and_crlf(self):
        text = ('// the module\r\nmodule "example.com/m" // comment\r\n\r\ngo 1.22\r\ntoolchain go1.22.1\r\n\r\nrequire (\r\n'
                '\ta.example/x v1.0.0 // indirect\r\n\t`b.example/y` v1.2.3\r\n\t// a comment line\r\n\tc.example/z v0.1.0 //indirect\r\n)\r\n'
                'require d.example/w v2.0.0+incompatible\r\nreplace a.example/x => ./x\r\nexclude e.example/v v1.0.0\r\nretract v0.9.0\r\n')
        got = golang.parse_gomod(text)
        self.assertEqual(got["module"], "example.com/m")
        self.assertEqual(got["go"], "1.22")
        self.assertEqual(got["require"], [("a.example/x", "v1.0.0", True), ("b.example/y", "v1.2.3", False), ("c.example/z", "v0.1.0", True),
                                          ("d.example/w", "v2.0.0+incompatible", False)])

    def test_the_first_module_and_go_lines_win(self):
        got = golang.parse_gomod("module a.example/one\nmodule a.example/two\ngo 1.20\ngo 1.21\n")
        self.assertEqual((got["module"], got["go"]), ("a.example/one", "1.20"))

    def test_the_module_may_be_in_a_block(self):
        self.assertEqual(golang.parse_gomod("module (\n\ta.example/m\n)\n")["module"], "a.example/m")

    def test_a_line_it_cannot_read_is_skipped_and_the_rest_is_read(self):
        text = 'module a.example/m\nrequire "unterminated v1.0.0\nrequire b.example/x\nrequire c.example/y v1.0.0\nrequire d.example/z not-a-version\n'
        self.assertEqual([r[0] for r in golang.parse_gomod(text)["require"]], ["c.example/y"])

    def test_a_version_is_made_canonical_the_way_go_does(self):
        text = "module a.example/m\nrequire a.example/x v1\nrequire a.example/y v1.2\nrequire a.example/z v1.2.3+meta\n"
        self.assertEqual([r[1] for r in golang.parse_gomod(text)["require"]], ["v1.0.0", "v1.2.0", "v1.2.3"])

    def test_indirect_is_the_comment_and_only_the_comment(self):
        text = ("module a.example/m\nrequire a.example/a v1.0.0 // indirect\nrequire a.example/b v1.0.0 // indirect; extra\n"
                "require a.example/c v1.0.0 // not indirect\nrequire a.example/d v1.0.0 //indirect\nrequire a.example/e v1.0.0\n")
        self.assertEqual([r[2] for r in golang.parse_gomod(text)["require"]], [True, True, False, True, False])

    def test_text_that_is_not_text_is_nothing(self):
        for value in (None, 5, b"module a.example/m", [], {}):
            self.assertEqual(golang.parse_gomod(value), {"module": None, "go": None, "require": []})

    def test_the_number_of_requirements_is_bounded(self):
        with mock.patch.object(golang, "MAX_REQUIRES", 3):
            text = "module a.example/m\n" + "".join("require a.example/x%d v1.0.0\n" % i for i in range(10))
            self.assertEqual(len(golang.parse_gomod(text)["require"]), 3)

    def test_only_the_first_16_mib_are_read(self):
        text = "module a.example/m\n" + " " * golang.MAX_GOMOD + "\nrequire a.example/x v1.0.0\n"
        self.assertEqual(golang.parse_gomod(text)["require"], [])

    def test_a_very_long_line_and_many_lines_are_fine(self):
        self.assertEqual(golang.parse_gomod("module " + "a" * 1_000_000 + "\n")["module"], "a" * 1_000_000)
        many = "module a.example/m\n" + "\n" * 200_000 + "require a.example/x v1.0.0\n"
        self.assertEqual(len(golang.parse_gomod(many)["require"]), 1)

    def test_the_tokens(self):
        cases = (('require "a b" v1.0.0 // indirect', (["require", "a b", "v1.0.0"], " indirect")),
                 ('foo"bar `x y` "a\\"b" "bad\\n"', (['foo"bar', "x y", 'a"b', None], None)),
                 ("a(b)c", (["a", "(", "b", ")", "c"], None)), ("a // b // c", (["a"], " b // c")), ("a//b", (["a"], "b")),
                 ('"unterminated', ([None], None)), ("`unterminated", ([None], None)), ("\x00", ([None], None)), ("a b", (["a", None, "b"], None)),
                 ("[a, b]", (["[", "a", ",", "b", "]"], None)), ("", ([], None)), ("   \t\r", ([], None)), ("=>", (["=>"], None)),
                 ('"x"y z', (["x", "y", "z"], None)), ('"x"', (["x"], None)), ('"abc\\', ([None], None)), ('"a\\"b"', (['a"b'], None)),
                 ('"a\\\\b"', (["a\\b"], None)), ('"a\\nb"', ([None], None)))
        for line, want in cases:
            with self.subTest(line=line):
                self.assertEqual(golang._tokens(line), want)


class WhatTheFirstMutationRunFoundUntestedTests(unittest.TestCase):
    """Limits that were not at their edge, messages that were not read to the end, and Go's own answers for the short and
    odd cases the golden file does not have. The expected values of the Go cases are `golang.org/x/mod` v0.22.0's
    (`scripts/gooracle`, Oct 3); the others are the module's own bounds, tested one under and one over."""

    def test_paths_whose_last_element_ends_in_a_tilde_and_digits_are_refused_as_go_refuses_them(self):
        for path, ok in (("example.com/a~1", False), ("example.com/a~", True), ("example.com/~1", False), ("example.com/ab~12", False),
                         ("example.com/a~b", True), ("example.com/a~1.txt", False), ("example.com/a~1b", True), ("example.com/~", True)):
            with self.subTest(path=path):
                self.assertEqual(golang.check_module_path(path) is None, ok)

    def test_windows_device_names_are_refused_up_to_9_and_in_any_case(self):
        for path, ok in (("example.com/com9", False), ("example.com/COM1", False), ("example.com/com1.txt", False), ("example.com/lpt9", False),
                         ("example.com/nul", False), ("example.com/nul.x", False), ("example.com/Con", False), ("example.com/aux.v", False),
                         ("example.com/prn", False), ("example.com/com10", True), ("example.com/com0", True), ("example.com/lpt10", True),
                         ("example.com/lpt0", True), ("example.com/nuls", True), ("example.com/com1x", True)):
            with self.subTest(path=path):
                self.assertEqual(golang.check_module_path(path) is None, ok)

    def test_the_first_element_and_the_empty_cases(self):
        for path, ok in (("-a.com/x", False), ("a.com/-x", True), ("/a.com/x", False), ("a/b", False), ("a.b//c", False), ("a.b/c/", False),
                         (".a.com/x", False), ("a.com/.x", False), ("a.com/x.", False), ("a..com/x", True), ("a.com/..", False),
                         ("a.com/x y", False), ("a.com/\u00e9", False)):
            with self.subTest(path=path):
                self.assertEqual(golang.check_module_path(path) is None, ok)
        self.assertEqual(golang.check_module_path("-a.com/x"), "leading dash")
        self.assertEqual(golang.check_module_path("/a.com/x"), "empty path element")

    def test_the_split_of_a_path_at_its_major_version_is_go_s_on_the_short_and_odd_paths(self):
        cases = (("", "", "", True), ("1", "1", "", True), ("v", "v", "", True), ("v2", "v2", "", True), ("/v2", "", "/v2", True),
                 ("a/v2", "a", "/v2", True), ("a/v1", "a/v1", "", False), ("a/v0", "a/v0", "", False), ("a/v02", "a/v02", "", False),
                 ("a/v2.1", "a/v2.1", "", False), ("a/v10", "a", "/v10", True), ("a/v2/", "a/v2/", "", True), (".v2", ".v2", "", True),
                 ("1.2", "1.2", "", True), ("123", "123", "", True), ("a/1.2", "a/1.2", "", True), ("a/v", "a/v", "", True),
                 ("a/v.", "a/v.", "", False), ("/v", "/v", "", True), ("//v2", "/", "/v2", True), ("x.y/v2", "x.y", "/v2", True),
                 ("x.y/v1", "x.y/v1", "", False), ("x.y/v3.0", "x.y/v3.0", "", False), ("x.y/v3.", "x.y/v3.", "", False),
                 ("x.y/v.3", "x.y/v.3", "", False),
                 ("gopkg.in/x.v2", "gopkg.in/x", ".v2", True), ("gopkg.in/x.v0", "gopkg.in/x", ".v0", True),
                 ("gopkg.in/x.v1", "gopkg.in/x", ".v1", True), ("gopkg.in/x.v02", "gopkg.in/x.v02", "", False),
                 ("gopkg.in/x.v2-unstable", "gopkg.in/x", ".v2-unstable", True), ("gopkg.in/x.v0-unstable", "gopkg.in/x.v0-unstable", "", False),
                 ("gopkg.in/v2", "gopkg.in/v2", "", False), ("gopkg.in/.v2", "gopkg.in/", ".v2", True),
                 ("gopkg.in/x.v", "gopkg.in/x.v", "", False), ("gopkg.in/123", "gopkg.in/123", "", False),
                 ("gopkg.in/x.v2.1", "gopkg.in/x.v2.1", "", False), ("gopkg.in/x.v10", "gopkg.in/x", ".v10", True),
                 ("gopkg.in/x.v1-unstable", "gopkg.in/x", ".v1-unstable", True), ("gopkg.in/x-unstable", "gopkg.in/x-unstable", "", False),
                 ("gopkg.in/.v1", "gopkg.in/", ".v1", True), ("gopkg.in/x/y.v3", "gopkg.in/x/y", ".v3", True), ("gopkg.in/", "gopkg.in/", "", False),
                 ("gopkg.in/1", "gopkg.in/1", "", False), ("gopkg.in/.v0", "gopkg.in/", ".v0", True), ("gopkg.in/y.v0", "gopkg.in/y", ".v0", True),
                 ("gopkg.in/y.v1x", "gopkg.in/y.v1x", "", False))
        for path, prefix, major, ok in cases:
            with self.subTest(path=path):
                self.assertEqual(golang.split_path_version(path), (prefix, major, ok))

    def test_the_case_escape_covers_every_capital_and_nothing_next_to_them(self):
        import string
        self.assertEqual(golang.escape(string.ascii_uppercase), "".join("!" + c for c in string.ascii_lowercase))
        self.assertEqual(golang.escape("@AZ[`az{"), "@!a!z[`az{")

    def test_a_name_may_be_255_characters_and_a_version_100(self):
        eco = golang.Go()
        name255, name256 = "a.b/" + "C" * 251, "a.b/" + "C" * 252
        self.assertEqual(eco.check_name(name255), name255)
        with self.assertRaisesRegex(base.SpecError, "longer than 255 characters"):
            eco.check_name(name256)
        self.assertEqual(eco.segment(name255), "a.b/" + "!c" * 251)           # (a module path: escaped)
        self.assertEqual(eco.segment(name256), "a.b%2FCCC" + "C" * 249)         # (too long for a path: quoted, nothing escaped)
        v100, v101 = "v1.0.0-" + "A" * 93, "v1.0.0-" + "A" * 94
        self.assertEqual(eco.check_version(v100), v100)
        with self.assertRaisesRegex(base.SpecError, "invalid version"):
            eco.check_version(v101)
        self.assertEqual(eco.segment(v100), "v1.0.0-" + "!a" * 93)
        self.assertEqual(eco.segment(v101), v101)
        self.assertEqual(golang.canonical_version(v100), v100)
        self.assertEqual(golang.canonical_version(v101), "")

    def test_a_name_that_is_not_one_is_false_and_not_just_false_y(self):
        eco = golang.Go()
        self.assertIs(eco._name_ok("example.com/m"), True)
        self.assertIs(eco._name_ok("nope"), False)
        self.assertIs(eco._name_ok(None), False)

    def test_the_messages_quote_at_most_60_characters_of_a_name(self):
        eco = golang.Go()
        long_name = "example.com/" + "a" * 70 + " b"
        with self.assertRaises(base.SpecError) as caught:
            eco.check_name(long_name)
        self.assertEqual(str(caught.exception),
                         "go: invalid module path (invalid character in a path element): " + repr(long_name[:60]) + "\u2026")
        major = "example.com/" + "a" * 60 + "/v2"
        with self.assertRaises(base.SpecError) as caught:
            resolve(major, "v1.0.0", {})
        self.assertEqual(str(caught.exception), "go: version 'v1.0.0' does not fit the major version of " + repr(major[:60]) + "\u2026")
        entry = {"h1": HASH_A, "gomod_h1": HASH_B}
        with self.assertRaises(base.DigestError) as caught:
            eco.verify(DIFFLIB_ZIP, entry, major, "v1.0.0")
        self.assertEqual(str(caught.exception), "go: the h1 hash of the download does not match the one the checksum database "
                                                "published for " + repr(major[:60]) + "\u2026 'v1.0.0'")
        art = {"url": "x", "container": "zip", "artifact": "gomod", "entry": entry, "filename": "x"}
        res = base.Resolution("v1.0.0", [art], [], {"module": major})
        mod_url = PROXY + major + "/@v/v1.0.0.mod"
        served = Served({mod_url: b"module " + major.encode() + b"\n"})
        with self.assertRaises(base.DigestError) as caught:
            eco.dependencies(res, served.fetch)
        self.assertEqual(str(caught.exception), "go: the go.mod of " + repr(major[:60]) + "\u2026 'v1.0.0' does not match the hash "
                                                "the checksum database published")

    def test_the_proxy_must_answer_for_the_version_asked_and_for_the_major_version_of_the_path(self):
        def answer(path, asked, given):
            doc = json.dumps({"Version": given}).encode()
            url = PROXY + path + ("/@latest" if asked is None else f"/@v/{asked}.info")
            return resolve(path, asked, {url: doc, SUMDB + path + "@" + given: lookup_text(path, given).encode()})[0]

        self.assertEqual(answer("example.com/m", "v1.0.0", "v1.0.0")[0], "v1.0.0")
        for path, asked, given in (("example.com/m", "v1.0.0", "v1.0.1"), ("example.com/m", "v1.0.0", "v1.0.0+incompatible"),
                                   ("example.com/m/v2", "v2.0.0", "v2.0.1"), ("example.com/m/v2", None, "v1.5.0"), ("example.com/m", None, "v2.0.0"),
                                   ("example.com/m/v2", None, "v3.0.0")):
            with self.subTest(path=path, asked=asked, given=given), self.assertRaisesRegex(base.FetchError, "another version than the one asked for"):
                answer(path, asked, given)
        self.assertEqual(answer("example.com/m/v2", None, "v2.3.4")[0], "v2.3.4")
        self.assertEqual(answer("example.com/m", None, "v1.9.9")[0], "v1.9.9")

    def test_a_member_compressed_in_a_way_go_does_not_read_is_refused_for_that(self):
        for name, method in (("bzip2", zipfile.ZIP_BZIP2), ("lzma", zipfile.ZIP_LZMA)):
            out = io.BytesIO()
            try:
                with zipfile.ZipFile(out, "w", method) as z:
                    z.writestr("a.go", b"package a\n" * 100)
            except RuntimeError:
                self.skipTest(f"no {name} here")
            with self.subTest(method=name), self.assertRaisesRegex(base.DigestError, "uses a compression Go does not read"):
                golang.zip_h1(out.getvalue())

    def test_the_checksum_databases_record_text_is_checked_as_go_checks_it(self):
        ok = golang._valid_record_text
        self.assertTrue(ok("a b c\nd e f\n"))
        self.assertFalse(ok(""))
        self.assertFalse(ok("a b c"))                               # no newline at the end
        self.assertFalse(ok("a b c\n\nd e f\n"))                   # an empty line
        self.assertFalse(ok("a b c\n\n"))
        for bad in ("\x00", "\x01", "\t", "\r", "\x1f"):
            self.assertFalse(ok(f"a{bad}b c\n"), repr(bad))
        self.assertTrue(ok("a \u00e9 \x7f\n"))                     # (only characters below a space are control characters here)

    def test_a_record_with_a_control_character_is_refused_for_that_and_not_as_another_kind_of_line(self):
        text = lookup_text("example.com/m", "v1.0.0", extra=f"a\x01b v1.0.0 {HASH_B}\n")
        with self.assertRaisesRegex(base.FetchError, "sent a record that is not valid"):
            golang.parse_lookup(text, "example.com/m", "v1.0.0")

    def test_a_record_number_may_have_18_digits_and_not_19(self):
        self.assertEqual(golang.parse_lookup(lookup_text("example.com/m", "v1.0.0", record_id="1" * 18), "example.com/m", "v1.0.0")["id"], int("1" * 18))
        with self.assertRaisesRegex(base.FetchError, "layout it does not have"):
            golang.parse_lookup(lookup_text("example.com/m", "v1.0.0", record_id="1" * 19), "example.com/m", "v1.0.0")

    def test_go_mod_lines_as_go_reads_them_that_the_first_tests_did_not_have(self):
        def req(text):
            return golang.parse_gomod("module m\n" + text)["require"]

        self.assertEqual(req('require "x.example/y"v1.0.0\n'), [("x.example/y", "v1.0.0", False)])
        # a block whose first word cannot be read is skipped as a whole, as Go skips a block it does not know
        self.assertEqual(req('"bad\\q" (\nrequire x.example/y v1.0.0\n)\nrequire a.example/b v1.0.0\n'), [("a.example/b", "v1.0.0", False)])
        for comment, indirect in (("// indirect;", False), ("// indirect; more", True), ("// indirect", True), ("//indirect", True),
                                  ("// indirectly", False), ("// indirect more", False)):
            with self.subTest(comment=comment):
                self.assertEqual(req(f"require x.example/y v1.0.0 {comment}\n"), [("x.example/y", "v1.0.0", indirect)])
        self.assertEqual(req('require "x.example/\\"y" v1.0.0\n'), [('x.example/"y', "v1.0.0", False)])
        self.assertEqual(req('require "x.example/y\\\\z" v1.0.0\n'), [("x.example/y\\z", "v1.0.0", False)])
        self.assertEqual(req('require "x.example/y\\'), [])                  # (Go: unexpected EOF in string; this reader goes on)
        self.assertEqual(req("require x.example/y v1.0.0\nrequire x.example/y v1.1.0\n"),
                         [("x.example/y", "v1.0.0", False), ("x.example/y", "v1.1.0", False)])


class ModuleDeclarationTests(unittest.TestCase):
    def test_it_says_what_it_is(self):
        eco = golang.ECOSYSTEM
        self.assertIsInstance(eco, golang.Go)
        self.assertEqual((eco.id, eco.title, eco.artifact_kinds, eco.rate), ("go", "Go modules", ("gomod",), {}))

    def test_it_has_no_feed_and_no_corpus_yet(self):
        eco = golang.Go()
        self.assertIsNone(eco.discover(None, 10, None))
        self.assertIsNone(eco.popular_names())

    def test_the_numbers(self):
        self.assertEqual((golang.MAX_NAME, golang.MAX_VERSION, golang.MAX_LOOKUP_BYTES), (255, 100, 64 * 1024))


if __name__ == "__main__":
    unittest.main()
