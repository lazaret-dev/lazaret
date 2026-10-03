"""lazaret-sca --update-bundle (lazaret.scanner.sca_feeds): building the CVE
bundle from OSV, CISA KEV and EPSS data, and the matcher's exact entries.

No network: every feed is a small file written here (OSV export zips, a KEV
catalog, a gzipped EPSS file) and read through a local path or a file: URL,
the same code path an air-gapped mirror uses. The package names, CVE ids and
hosts are synthetic (CVE-2099-*, .invalid). One live test runs against the
real feeds when LAZARET_TEST_FEEDS is set.
"""
import copy
import gzip
import io
import json
import os
import pathlib
import random
import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from contextlib import redirect_stderr, redirect_stdout

from tests import _support
from lazaret.scanner import sca, sca_feeds

# ---------------------------------------------------------------------------
# Fixture feeds
# ---------------------------------------------------------------------------


def ghsa(gid, cves, name, events, eco="npm", **extra):
    rec = {"id": gid, "aliases": list(cves), "summary": "%s issue in %s" % (gid, name),
           "published": "2099-01-02T10:00:00Z", "modified": "2099-01-03T10:00:00Z",
           "affected": [{"package": {"ecosystem": eco, "name": name},
                         "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}
    rec.update(extra)
    return rec


LODASH = ghsa("GHSA-aaaa-0001-0001", ["CVE-2099-1001"], "lodash",
              [{"introduced": "0"}, {"fixed": "4.17.12"}],
              severity=[{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
              database_specific={"severity": "CRITICAL", "cwe_ids": ["CWE-1321", "bogus"]},
              references=[{"type": "WEB", "url": "https://example.invalid/web"},
                          {"type": "ADVISORY", "url": "https://example.invalid/advisory"},
                          {"type": "WEB", "url": "javascript:alert(1)"},
                          {"type": "WEB", "url": "http://example.invalid/plain-http"}])
# GitHub lists one package once per range
VITE = {"id": "GHSA-aaaa-0002-0002", "aliases": ["CVE-2099-1002"], "summary": "vite fs.deny bypass",
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
        "affected": [
            {"package": {"ecosystem": "npm", "name": "vite"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "6.2.0"}, {"fixed": "6.2.4"}]}]},
            {"package": {"ecosystem": "npm", "name": "vite"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.5.11"}]}]}]}
MAL_TYPO = {"id": "MAL-2099-0001", "summary": "Malicious code in lodahs (npm)",
            "modified": "2099-01-04T00:00:00Z",
            "details": "Any computer that has this package installed should be considered compromised.",
            "affected": [{"package": {"ecosystem": "npm", "name": "lodahs"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
# a hijacked release: two versions only; GitHub's advisory for it is an alias
MAL_HIJACK = {"id": "MAL-2099-0002", "aliases": ["GHSA-mmmm-0003-0003"],
              "summary": "Malicious code in colorz (npm)",
              "affected": [{"package": {"ecosystem": "npm", "name": "colorz"},
                            "versions": ["2.1.1", "2.1.2"]}]}
GHSA_HIJACK = {"id": "GHSA-mmmm-0003-0003", "summary": "Malware in colorz",
               "database_specific": {"severity": "CRITICAL"},
               "affected": [{"package": {"ecosystem": "npm", "name": "colorz"},
                             "versions": ["2.1.2"]}]}
# an npm package named like a PyPI one: must never touch the PyPI package
MAL_CONFUSION = {"id": "MAL-2099-0003", "summary": "Malicious code in requests (npm)",
                 "affected": [{"package": {"ecosystem": "npm", "name": "requests"},
                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
BABEL = ghsa("GHSA-aaaa-0004-0004", ["CVE-2099-1004"], "babel-core", [{"introduced": "0"}])
WITHDRAWN = dict(ghsa("GHSA-aaaa-0005-0005", ["CVE-2099-1005"], "left-pad", [{"introduced": "0"}]),
                 withdrawn="2099-01-05T00:00:00Z")
MAVEN = ghsa("GHSA-aaaa-0006-0006", ["CVE-2099-1006"], "org.example:lib", [{"introduced": "0"}],
             eco="Maven")
# one advisory for a library published to both registries (in both exports)
SHARED = {"id": "GHSA-aaaa-0007-0007", "aliases": ["CVE-2099-1007"], "summary": "shared-lib parser",
          "modified": "2099-01-03T00:00:00Z",
          "affected": [
              {"package": {"ecosystem": "npm", "name": "shared-lib"},
               "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.4.0"}]}]},
              {"package": {"ecosystem": "PyPI", "name": "shared_lib"},
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.4"}]}]}]}
# the PyPA record and GitHub's for one CVE (KEV-listed)
PYSEC_URLLIB3 = {"id": "PYSEC-2099-0001", "aliases": ["CVE-2099-2001", "GHSA-uuuu-0008-0008"],
                 "details": "\n## urllib3 forwards the Cookie header\nacross origins.",
                 "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3",
                                           "purl": "pkg:pypi/urllib3"},
                               "ranges": [
                                   {"type": "GIT", "repo": "https://example.invalid/urllib3",
                                    "events": [{"introduced": "0"}, {"fixed": "0123abcd"}]},
                                   {"type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.26.17"},
                                               {"introduced": "2.0.0"}, {"fixed": "2.0.6"}]}],
                               "versions": ["1.26.16", "2.0.0", "2.0.5"]}]}
GHSA_URLLIB3 = ghsa("GHSA-uuuu-0008-0008", ["CVE-2099-2001"], "urllib3",
                    [{"introduced": "2.0.0"}, {"fixed": "2.0.6"}], eco="PyPI",
                    severity=[{"type": "CVSS_V4",
                               "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}],
                    database_specific={"severity": "HIGH"})
DJANGO = ghsa("GHSA-dddd-0009-0009", ["CVE-2099-2002"], "Django",
              [{"introduced": "4.2"}, {"last_affected": "4.2.7"}], eco="PyPI")
# no fix yet: every version from 1.0 up
UNFIXED = ghsa("GHSA-dddd-0010-0010", [], "yaml-thing", [{"introduced": "1.0"}], eco="PyPI")

# Go and crates.io, in the shapes the real exports have (api.osv.dev: GO-2022-0969, GHSA-69cg-p879-7622, RUSTSEC-2020-0071,
# RUSTSEC-2021-0139): the Go database names the standard library as a package, a version may be a pseudo-version, and a GitHub
# advisory names import paths; RustSec opens its ranges at `0.0.0-0` and says in `database_specific` what is no flaw.
GO_NET = {"id": "GO-2099-0001", "aliases": ["CVE-2099-3001", "GHSA-gggg-0011-0011"], "summary": "net/http2 flood",
          "modified": "2099-01-03T00:00:00Z",
          "affected": [
              {"package": {"name": "stdlib", "ecosystem": "Go", "purl": "pkg:golang/stdlib"},
               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.18.6"}, {"introduced": "1.19.0-0"},
                                                          {"fixed": "1.19.1"}]}],
               "ecosystem_specific": {"imports": [{"path": "net/http", "symbols": ["Serve"]}]}},
              {"package": {"name": "golang.org/x/net", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/net"},
               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.0.0-20990101000000-aaaaaaaaaaaa"}]}],
               "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/http2", "symbols": ["Server.ServeConn"]}]}}],
          "database_specific": {"review_status": "REVIEWED", "url": "https://pkg.go.dev/vuln/GO-2099-0001"}}
GHSA_GO_NET = {"id": "GHSA-gggg-0011-0011", "aliases": ["CVE-2099-3001", "GO-2099-0001"], "summary": "http2 Denial of Service",
               "database_specific": {"severity": "HIGH", "cwe_ids": []},
               "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
               "affected": [{"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                                       {"fixed": "0.0.0-20990101000000-aaaaaaaaaaaa"}]}]},
                            {"package": {"name": "golang.org/x/net/http2", "ecosystem": "Go"},
                             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                                       {"fixed": "0.0.0-20990101000000-aaaaaaaaaaaa"}]}]}]}
GO_UPPER = {"id": "GO-2099-0002", "summary": "a module whose path has capitals", "modified": "2099-01-03T00:00:00Z",
            "affected": [{"package": {"name": "github.com/Example/Lib/v2", "ecosystem": "Go"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.3.1"}]}]}]}
GO_TOOLCHAIN = {"id": "GO-2099-0003", "summary": "the go command", "modified": "2099-01-03T00:00:00Z",
                "affected": [{"package": {"name": "toolchain", "ecosystem": "Go"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.21.1"}]}]}]}
RUSTSEC_TIME = {"id": "RUSTSEC-2099-0001", "aliases": ["CVE-2099-4001"], "summary": "Potential segfault in the time crate",
                "modified": "2099-01-03T00:00:00Z",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
                "affected": [{"package": {"name": "time", "ecosystem": "crates.io", "purl": "pkg:cargo/time"},
                              "ranges": [{"type": "SEMVER", "events": [
                                  {"introduced": "0.0.0-0"}, {"fixed": "0.2.0"}, {"introduced": "0.2.1-0"}, {"fixed": "0.2.23"}]}],
                              "database_specific": {"categories": ["memory-corruption"], "informational": None}}],
                "database_specific": {"license": "CC0-1.0"}}
RUSTSEC_UNMAINTAINED = {"id": "RUSTSEC-2099-0002", "summary": "ansi_term is Unmaintained",
                        "affected": [{"package": {"name": "ansi_term", "ecosystem": "crates.io"},
                                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}]}],
                                      "database_specific": {"informational": "unmaintained"}}]}
RUSTSEC_UNSOUND = {"id": "RUSTSEC-2099-0003", "summary": "Some_Crate is unsound", "modified": "2099-01-03T00:00:00Z",
                   "affected": [{"package": {"name": "Some_Crate", "ecosystem": "crates.io"},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0.0.0-0"}, {"fixed": "1.2.3"}]}],
                                 "database_specific": {"informational": "unsound"}}]}

NPM_RECORDS = [LODASH, VITE, MAL_TYPO, MAL_HIJACK, GHSA_HIJACK, MAL_CONFUSION, BABEL, WITHDRAWN,
               MAVEN, SHARED]
PYPI_RECORDS = [PYSEC_URLLIB3, GHSA_URLLIB3, DJANGO, UNFIXED, SHARED]
GO_RECORDS = [GO_NET, GHSA_GO_NET, GO_UPPER, GO_TOOLCHAIN]
CRATES_RECORDS = [RUSTSEC_TIME, RUSTSEC_UNMAINTAINED, RUSTSEC_UNSOUND]

KEV_DOC = {"title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2099.01.06",
           "dateReleased": "2099-01-06T12:00:00.000Z", "count": 3, "vulnerabilities": [
               {"cveID": "CVE-2099-2001", "vendorProject": "urllib3", "product": "urllib3",
                "dateAdded": "2099-01-06", "dueDate": "2099-01-27",
                "knownRansomwareCampaignUse": "Known"},
               {"cveID": "cve-2099-1002", "dateAdded": "2099-01-06", "dueDate": "2099-01-20",
                "knownRansomwareCampaignUse": "Unknown"},
               {"cveID": "CVE-2098-9999", "dueDate": "2098-01-01"}]}
EPSS_TEXT = ("#model_version:v2099.01.01,score_date:2099-01-06T00:00:00+0000\n"
             "cve,epss,percentile\n"
             "CVE-2099-1001,0.25,0.91\n"
             "CVE-2099-2001,0.97,0.999\n"
             "CVE-2099-1002,1.5,0.5\n"          # out of range: ignored
             "CVE-1999-0001,0.1,0.2\n")


def write_zip(path, records, extra=()):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for rec in records:
            zf.writestr(rec["id"] + ".json", json.dumps(rec))
        for name, data in extra:
            zf.writestr(name, data)


def write_epss(path, text=EPSS_TEXT):
    with open(path, "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", mtime=0) as gz:
            gz.write(text.encode("utf-8"))


class Feeds(unittest.TestCase):
    """A directory holding a complete set of feeds, as a mirror would."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lz-feeds-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        write_zip(os.path.join(self.dir, "npm", "all.zip"), NPM_RECORDS,
                  extra=[("broken.json", "{not json"), ("README.txt", "not a record")])
        write_zip(os.path.join(self.dir, "PyPI", "all.zip"), PYPI_RECORDS)
        write_zip(os.path.join(self.dir, "Go", "all.zip"), GO_RECORDS)
        write_zip(os.path.join(self.dir, "crates.io", "all.zip"), CRATES_RECORDS)
        with open(os.path.join(self.dir, "kev.json"), "w", encoding="utf-8") as fh:
            json.dump(KEV_DOC, fh)
        write_epss(os.path.join(self.dir, "epss.csv.gz"))
        self.osv = os.path.join(self.dir, "{ecosystem}", "all.zip")
        self.kev = pathlib.Path(self.dir, "kev.json").as_uri()           # a file: URL
        self.epss = os.path.join(self.dir, "epss.csv.gz")                # a plain path

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def build(self, **kw):
        args = {"osv_url": self.osv, "kev_urls": [self.kev], "epss_url": self.epss}
        args.update(kw)
        return sca_feeds.build_bundle(**args)

    def by_id(self, doc):
        return {a["cve"]: a for a in doc["advisories"]}


# ---------------------------------------------------------------------------
# CVSS
# ---------------------------------------------------------------------------

class CvssTests(unittest.TestCase):
    def test_base_scores(self):
        for vector, score in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", 5.3),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O", 9.8),   # temporal ignored
        ]:
            with self.subTest(vector=vector):
                self.assertEqual(sca_feeds.cvss3_base_score(vector), score)

    def test_not_a_cvss3_vector(self):
        for vector in ["AV:N/AC:L/Au:N/C:P/I:P/A:P",
                       "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                       "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",          # no scope
                       "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # repeated metric
                       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A", "", None, 9.8, "x" * 300]:
            with self.subTest(vector=vector):
                self.assertIsNone(sca_feeds.cvss3_base_score(vector))

    def test_an_osv_severity_list(self):
        v4 = {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}
        self.assertIsNone(sca_feeds._cvss_of([v4]))
        self.assertEqual(sca_feeds._cvss_of([v4, {"type": "CVSS_V3",
                                                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]), 7.5)
        self.assertEqual(sca_feeds._cvss_of([{"type": "CVSS_V3", "score": "8.1"}]), 8.1)
        self.assertIsNone(sca_feeds._cvss_of("CVSS:3.1/..."))


# ---------------------------------------------------------------------------
# OSV ranges
# ---------------------------------------------------------------------------

def affected(version, ranges, eco):
    return any(sca.version_in_range(version, r, eco) is True for r in ranges)


class IntervalTests(unittest.TestCase):
    def test_event_lists(self):
        I = sca_feeds.osv_intervals
        self.assertEqual(I([{"introduced": "0"}, {"fixed": "4.17.12"}], "npm"),
                         [{"toVersion": "4.17.12", "toInclusive": False}])
        self.assertEqual(I([{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}], "npm"),
                         [{"fromVersion": "1.0.0", "fromInclusive": True,
                           "toVersion": "1.4.0", "toInclusive": True}])
        self.assertEqual(I([{"introduced": "2.0.0"}], "npm"),
                         [{"fromVersion": "2.0.0", "fromInclusive": True}])
        self.assertEqual(I([{"introduced": "0"}], "npm"), [{}])
        self.assertEqual(I([{"introduced": "0"}, {"limit": "3.0.0"}], "npm"),
                         [{"toVersion": "3.0.0", "toInclusive": False}])

    def test_nothing_affected(self):
        I = sca_feeds.osv_intervals
        for events in [None, [], "x", [{"fixed": "1.0"}], [{"introduced": "1.0"}, {"fixed": "1.0"}],
                       [{"introduced": "2.0"}, {"fixed": "1.0"}], [{"unknown": "1.0"}, 5]]:
            with self.subTest(events=events):
                self.assertEqual(I(events, "pypi"), [] if events != [{"introduced": "2.0"}, {"fixed": "1.0"}]
                                 else [{"fromVersion": "2.0", "fromInclusive": True}])

    def test_several_intervals_in_any_order(self):
        """The PyPA shape: introduced/fixed pairs in one list. OSV evaluates
        events in version order, so shuffled events mean the same thing."""
        events = [{"introduced": "0"}, {"fixed": "1.26.17"}, {"introduced": "2.0.0"}, {"fixed": "2.0.6"}]
        want = sca_feeds.osv_intervals(events, "pypi")
        self.assertEqual(len(want), 2)
        rng = random.Random(5)
        for _ in range(10):
            shuffled = events[:]
            rng.shuffle(shuffled)
            self.assertEqual(sca_feeds.osv_intervals(shuffled, "pypi"), want)
        for version, hit in [("1.0", True), ("1.26.16", True), ("1.26.17", False), ("1.26.18", False),
                             ("2.0.0a1", False), ("2.0.0", True), ("2.0.5", True), ("2.0.6", False)]:
            with self.subTest(version=version):
                self.assertEqual(affected(version, want, "pypi"), hit)

    def test_prerelease_order(self):
        npm = sca_feeds.osv_intervals([{"fixed": "2.0.0"}, {"introduced": "2.0.0-beta.2"}], "npm")
        self.assertEqual(npm, [{"fromVersion": "2.0.0-beta.2", "fromInclusive": True,
                                "toVersion": "2.0.0", "toInclusive": False}])
        self.assertTrue(affected("2.0.0-beta.10", npm, "npm"))
        self.assertFalse(affected("2.0.0-beta.1", npm, "npm"))

    def test_affected_entry(self):
        R = sca_feeds.affected_ranges
        # GIT ranges name commits: only the listed versions remain
        git_only = {"ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "abc"}]}],
                    "versions": ["1.0", "1.1", "1.1", " 1.2 "]}
        self.assertEqual([r["fromVersion"] for r in R(git_only, "pypi")], ["1.0", "1.1", "1.2"])
        # listed versions the intervals already cover add nothing; the others are exact
        both = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
                "versions": ["1.0", "1.9", "2.5"]}
        self.assertEqual(R(both, "pypi"), [{"toVersion": "2.0", "toInclusive": False},
                                           {"fromVersion": "2.5", "fromInclusive": True,
                                            "toVersion": "2.5", "toInclusive": True}])
        counts = sca_feeds.Counts()
        odd = {"versions": ["1.0", "latest", "*", 7]}
        self.assertEqual(len(R(odd, "npm", counts)), 1)
        self.assertEqual((dict(counts), counts.notes),
                         ({}, {"listed versions that can't be compared (skipped)": 2}))
        # an all-versions interval makes the list moot
        self.assertEqual(R({"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                            "versions": ["1.0.0", "1.0.1"]}, "npm"), [{}])
        self.assertEqual(R({}, "npm"), [])


# ---------------------------------------------------------------------------
# OSV records
# ---------------------------------------------------------------------------

class RecordTests(unittest.TestCase):
    def test_a_github_advisory(self):
        rec = sca_feeds.osv_record(LODASH)
        self.assertEqual(rec["id"], "GHSA-aaaa-0001-0001")
        self.assertEqual(rec["aliases"], ["CVE-2099-1001"])
        self.assertEqual(rec["title"], "GHSA-aaaa-0001-0001 issue in lodash")
        self.assertEqual((rec["label"], rec["cvss"], rec["cwes"]), ("critical", 9.8, ["CWE-1321"]))
        self.assertEqual(rec["published"], "2099-01-02")
        # https only, ADVISORY first; javascript: and plain http never reach a report
        self.assertEqual(rec["refs"], ["https://example.invalid/advisory", "https://example.invalid/web"])
        self.assertEqual(rec["packages"], [("npm", "lodash", [{"toVersion": "4.17.12", "toInclusive": False}])])
        self.assertFalse(rec["malicious"])

    def test_one_package_listed_per_range(self):
        rec = sca_feeds.osv_record(VITE)
        self.assertEqual(len(rec["packages"]), 1)
        eco, name, ranges = rec["packages"][0]
        self.assertEqual((eco, name, len(ranges)), ("npm", "vite", 2))
        self.assertEqual((rec["label"], rec["cvss"]), ("medium", 5.3))

    def test_title_from_details(self):
        rec = sca_feeds.osv_record(PYSEC_URLLIB3)
        self.assertEqual(rec["title"], "urllib3 forwards the Cookie header")
        long = dict(LODASH, summary="word " * 100)
        self.assertLessEqual(len(sca_feeds.osv_record(long)["title"]), 200)

    def test_what_is_skipped(self):
        counts = sca_feeds.Counts()
        self.assertIsNone(sca_feeds.osv_record(WITHDRAWN, counts))
        self.assertIsNone(sca_feeds.osv_record(MAVEN, counts))
        self.assertEqual(counts, {})                        # not problems, just not ours
        for bad in [[], "x", {"id": "no id here"}, {"id": 5}, {"summary": "no id"}]:
            self.assertIsNone(sca_feeds.osv_record(bad, counts))
        self.assertEqual(sum(counts.values()), 5)
        names = copy.deepcopy(LODASH)
        names["affected"] += [{"package": {"ecosystem": "npm", "name": bad}}
                              for bad in ["", "two words", "bad\x1bname", "x" * 300, 5, "a/b/c"]]
        names["affected"].append({"package": {"ecosystem": "PyPI", "name": "-dash-first"}})
        counts = sca_feeds.Counts()
        rec = sca_feeds.osv_record(names, counts)
        self.assertEqual([p[1] for p in rec["packages"]], ["lodash"])
        self.assertEqual(sum(counts.values()), 7)

    def test_malicious_and_aliases(self):
        rec = sca_feeds.osv_record(MAL_HIJACK)
        self.assertTrue(rec["malicious"])
        self.assertEqual(rec["aliases"], ["GHSA-mmmm-0003-0003"])
        weird = dict(LODASH, aliases=["cve-2099-1001", "CVE-2099-1001", LODASH["id"], "has space", 7])
        self.assertEqual(sca_feeds.osv_record(weird)["aliases"], ["CVE-2099-1001"])

    def test_package_names(self):
        ok = sca_feeds._package_name
        self.assertEqual(ok("@scope/pkg", "npm"), "@scope/pkg")
        self.assertEqual(ok(" JSONStream ", "npm"), "JSONStream")
        self.assertEqual(ok("zope.interface", "pypi"), "zope.interface")
        for bad, eco in [("@scope/", "npm"), ("@/x", "npm"), ("a b", "npm"), ("a/b", "npm"),
                         ("_x", "pypi"), ("x_", "pypi"), ("a b", "pypi"), ("é", "pypi")]:
            with self.subTest(name=bad):
                self.assertIsNone(ok(bad, eco))


class GoAndCratesRecordTests(unittest.TestCase):
    def test_a_go_record_names_modules_and_leaves_the_standard_library(self):
        counts = sca_feeds.Counts()
        rec = sca_feeds.osv_record(GO_NET, counts)
        self.assertEqual(rec["packages"], [("go", "golang.org/x/net", [
            {"toVersion": "0.0.0-20990101000000-aaaaaaaaaaaa", "toInclusive": False}])])
        self.assertEqual(rec["aliases"], ["CVE-2099-3001", "GHSA-gggg-0011-0011"])
        self.assertEqual(counts, {})
        self.assertEqual(counts.notes, {"Go standard library and toolchain entries (not modules; skipped)": 1})
        self.assertIsNone(sca_feeds.osv_record(GO_TOOLCHAIN, counts))             # nothing else in it: no record
        self.assertEqual(counts.notes, {"Go standard library and toolchain entries (not modules; skipped)": 2})

    def test_stdlib_and_toolchain_are_only_not_modules_in_go(self):
        for eco, name in (("crates.io", "stdlib"), ("npm", "toolchain"), ("PyPI", "stdlib")):
            rec = dict(GO_TOOLCHAIN, affected=[dict(GO_TOOLCHAIN["affected"][0], package={"name": name, "ecosystem": eco})])
            with self.subTest(ecosystem=eco):
                self.assertEqual([p[1] for p in sca_feeds.osv_record(rec)["packages"]], [name])
        for name in ("std", "stdlib/x", "Stdlib", "go"):                           # (only the two names OSV uses)
            rec = dict(GO_TOOLCHAIN, affected=[dict(GO_TOOLCHAIN["affected"][0], package={"name": name, "ecosystem": "Go"})])
            with self.subTest(name=name):
                self.assertEqual([p[1] for p in sca_feeds.osv_record(rec)["packages"]], [name])

    def test_a_pseudo_version_bound_orders_with_the_modules_versions(self):
        ranges = sca_feeds.osv_record(GO_NET)["packages"][0][2]
        for version, hit in (("v0.0.0-20980101000000-bbbbbbbbbbbb", True), ("v0.0.0-20990101000000-aaaaaaaaaaaa", False),
                             ("v0.0.0-20990102000000-aaaaaaaaaaaa", False), ("v0.1.0", False), ("v0.0.0", False),
                             ("v1.2.3-0.20980101000000-bbbbbbbbbbbb", False)):
            with self.subTest(version=version):
                self.assertEqual(affected(version, ranges, "go"), hit)

    def test_go_versions_with_a_prefix_or_incompatible_are_compared(self):
        ranges = sca_feeds.osv_record(GO_UPPER)["packages"][0][2]
        for version, hit in (("v2.0.0", True), ("v2.3.0", True), ("v2.3.1", False), ("v1.9.9", False), ("v2.2.0+incompatible", True),
                             ("v2.3.1+incompatible", False), ("v2.3.1-rc.1", True)):
            with self.subTest(version=version):
                self.assertEqual(affected(version, ranges, "go"), hit)

    def test_a_module_path_keeps_its_case(self):
        rec = sca_feeds.osv_record(GO_UPPER)
        self.assertEqual([p[1] for p in rec["packages"]], ["github.com/Example/Lib/v2"])
        both = dict(GO_UPPER, affected=GO_UPPER["affected"] + [
            {"package": {"name": "github.com/example/lib/v2", "ecosystem": "Go"}, "ranges": []}])
        self.assertEqual([p[1] for p in sca_feeds.osv_record(both)["packages"]],
                         ["github.com/Example/Lib/v2", "github.com/example/lib/v2"])      # two modules

    def test_a_rustsec_range_opens_at_a_prerelease(self):
        rec = sca_feeds.osv_record(RUSTSEC_TIME)
        self.assertEqual(rec["packages"][0][:2], ("crates", "time"))
        ranges = rec["packages"][0][2]
        self.assertEqual(len(ranges), 2)
        for version, hit in (("0.1.0", True), ("0.2.0-alpha.1", True), ("0.2.0", False), ("0.2.1-0", True), ("0.2.1", True),
                             ("0.2.22", True), ("0.2.23", False), ("0.3.0", False), ("0.0.0", True)):
            with self.subTest(version=version):
                self.assertEqual(affected(version, ranges, "crates"), hit)

    def test_rustsec_entries_that_are_no_flaw_are_left_out(self):
        counts = sca_feeds.Counts()
        self.assertIsNone(sca_feeds.osv_record(RUSTSEC_UNMAINTAINED, counts))
        self.assertEqual(counts.notes, {"RustSec informational entries (unmaintained or notice; not vulnerabilities; skipped)": 1})
        self.assertEqual(counts, {})
        for kind, kept in (("notice", False), ("unmaintained", False), ("unsound", True), (None, True), ("future", True), ("", True),
                           (["unmaintained"], True)):
            rec = copy.deepcopy(RUSTSEC_UNMAINTAINED)
            rec["affected"][0]["database_specific"]["informational"] = kind
            with self.subTest(informational=kind):
                self.assertEqual(sca_feeds.osv_record(rec) is not None, kept)
        rec = copy.deepcopy(RUSTSEC_UNMAINTAINED)
        del rec["affected"][0]["database_specific"]
        self.assertIsNotNone(sca_feeds.osv_record(rec))                               # (no word on it: a vulnerability)
        rec["affected"][0]["database_specific"] = "unmaintained"
        self.assertIsNotNone(sca_feeds.osv_record(rec))
        for eco in ("Go", "npm", "PyPI"):                                             # (a RustSec word in another ecosystem's record)
            other = copy.deepcopy(LODASH)
            other["affected"][0]["package"]["ecosystem"] = eco
            other["affected"][0]["database_specific"] = {"informational": "unmaintained"}
            self.assertIsNotNone(sca_feeds.osv_record(other), eco)

    def test_a_crate_name_is_as_written_and_one_name_with_underscores_or_hyphens(self):
        rec = sca_feeds.osv_record(RUSTSEC_UNSOUND)
        self.assertEqual(rec["packages"][0][:2], ("crates", "Some_Crate"))
        both = copy.deepcopy(RUSTSEC_UNSOUND)
        both["affected"].append({"package": {"name": "some-crate", "ecosystem": "crates.io"},
                                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}]}]})
        got = sca_feeds.osv_record(both)["packages"]
        self.assertEqual([(p[0], p[1], len(p[2])) for p in got], [("crates", "Some_Crate", 2)])        # (crates.io holds one of the two)

    def test_names(self):
        ok = sca_feeds._package_name
        for name in ("github.com/a/b", "golang.org/x/net", "gopkg.in/yaml.v3", "github.com/A/b/v2", "k8s.io/api", "x.y/z~1", "a+b/c"):
            self.assertEqual(ok(name, "go"), name)
        for name in ("", "/a", ".a", "-a", "a b", "a\nb", "é.example/x", "a" * 215, "a\\b"):
            self.assertIsNone(ok(name, "go"), name)
        for name in ("time", "serde_json", "Some_Crate", "a-b", "_x", "x" * 64, "0x"):
            self.assertEqual(ok(name, "crates"), name)
        for name in ("", "-x", "a.b", "a/b", "a b", "é", "a" * 215):
            self.assertIsNone(ok(name, "crates"), name)
        for ecosystem in ("go", "crates"):
            self.assertEqual(ok("a" * 214, ecosystem), "a" * 214)              # (the longest name there is: 214)
            self.assertIsNone(ok("a" * 215, ecosystem))

    def test_versions_are_bounded(self):
        for n, kept in ((128, True), (129, False)):
            v = "v1.0.0-" + "a" * (n - 7)
            self.assertEqual(len(v), n)
            got = sca_feeds.osv_intervals([{"introduced": "0"}, {"fixed": v}], "go")
            self.assertEqual(got, [{"toVersion": v, "toInclusive": False}] if kept else [{}], n)        # (an event too long is not read)

    def test_a_github_advisory_names_import_paths_too(self):
        rec = sca_feeds.osv_record(GHSA_GO_NET)
        self.assertEqual([p[1] for p in rec["packages"]], ["golang.org/x/net", "golang.org/x/net/http2"])
        self.assertEqual((rec["label"], rec["cvss"]), ("high", 7.5))


# ---------------------------------------------------------------------------
# KEV and EPSS
# ---------------------------------------------------------------------------

class KevTests(unittest.TestCase):
    def test_the_catalog(self):
        kev, meta = sca_feeds.read_kev(json.dumps(KEV_DOC).encode())
        self.assertEqual(set(kev), {"CVE-2099-2001", "CVE-2099-1002", "CVE-2098-9999"})
        self.assertEqual(kev["CVE-2099-2001"], {"dueDate": "2099-01-27", "ransomware": True,
                                                "dateAdded": "2099-01-06"})
        self.assertFalse(kev["CVE-2099-1002"]["ransomware"])
        self.assertEqual(meta, {"entries": 3, "catalogVersion": "2099.01.06",
                                "dateReleased": "2099-01-06T12:00:00.000Z"})

    def test_not_a_usable_catalog(self):
        for data in [b"<html>Access denied</html>", b"[]", b'{"vulnerabilities": {}}',
                     b'{"vulnerabilities": []}', b'{"vulnerabilities": [{"cveID": "nope"}]}',
                     b"[" * 5000 + b"]" * 5000]:
            with self.subTest(data=data[:40]):
                with self.assertRaises(sca_feeds.FeedError):
                    sca_feeds.read_kev(data)


def gz(text):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
        g.write(text.encode("utf-8"))
    buf.seek(0)
    return buf


class EpssTests(unittest.TestCase):
    def test_scores(self):
        scores, meta = sca_feeds.read_epss(gz(EPSS_TEXT))
        self.assertEqual(scores, {"CVE-2099-1001": (0.25, 0.91), "CVE-2099-2001": (0.97, 0.999),
                                  "CVE-1999-0001": (0.1, 0.2)})
        self.assertEqual(meta, {"rows": 4, "modelVersion": "v2099.01.01",
                                "scoreDate": "2099-01-06T00:00:00+0000"})
        wanted, _ = sca_feeds.read_epss(gz(EPSS_TEXT), {"CVE-2099-2001", "CVE-2099-1002"})
        self.assertEqual(wanted, {"CVE-2099-2001": (0.97, 0.999)})

    def test_no_comment_line_and_other_column_order(self):
        scores, meta = sca_feeds.read_epss(gz("percentile,cve,epss\n0.5,CVE-2099-10001,0.01\n"
                                              "0.5,not-a-cve,0.01\n"))
        self.assertEqual(scores, {"CVE-2099-10001": (0.01, 0.5)})
        self.assertEqual(meta, {"rows": 2})

    def test_unusable(self):
        for fileobj in [io.BytesIO(b"cve,epss,percentile\nCVE-2099-1,0.1,0.2\n"),   # not gzipped
                        gz("cve,score\nCVE-2099-1,0.1\n"), gz("#only a comment\n"),
                        gz("cve,epss,percentile\n"), io.BytesIO(gz(EPSS_TEXT).getvalue()[:30])]:
            with self.assertRaises(sca_feeds.FeedError):
                sca_feeds.read_epss(fileobj)
        with self.assertRaises(sca_feeds.FeedError):
            sca_feeds.read_epss(gz(EPSS_TEXT), max_rows=2)

    def test_crlf_lines(self):
        scores, _ = sca_feeds.read_epss(gz(EPSS_TEXT.replace("\n", "\r\n")))
        self.assertEqual(scores["CVE-2099-2001"], (0.97, 0.999))

    def test_a_line_with_no_end_is_refused_early(self):
        # audit L1: a 600 KB gzip held one 600 MB line, which TextIOWrapper
        # buffered whole before csv's field limit saw it (1.2 GB of memory)
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
            g.write(b"cve,epss,percentile\nCVE-2099-0001,")
            for _ in range(32):
                g.write(b"A" * (1 << 20))                  # 32 MiB, no newline
        buf.seek(0)
        with self.assertRaises(sca_feeds.FeedError) as cm:
            sca_feeds.read_epss(buf)
        self.assertIn("line longer than", str(cm.exception))

    def test_decompressed_bytes_are_budgeted(self):
        lines = list(sca_feeds.bounded_lines(io.BytesIO(b"a,b\nc,d\n"), 100, 10, "x"))
        self.assertEqual(lines, ["a,b", "c,d"])
        self.assertEqual(list(sca_feeds.bounded_lines(io.BytesIO(b"a\nb"), 100, 10, "x")), ["a", "b"])
        with self.assertRaises(sca_feeds.FeedError) as cm:
            list(sca_feeds.bounded_lines(io.BytesIO(b"abc\n" * 100), 100, 10, "the file"))
        self.assertIn("decompresses to more than", str(cm.exception))
        with self.assertRaises(sca_feeds.FeedError):                   # a whole long line in one chunk
            list(sca_feeds.bounded_lines(io.BytesIO(b"x" * 50 + b"\n"), 1000, 10, "the file"))
        head, _, body = EPSS_TEXT.partition("cve,epss,percentile\n")
        text = head + "cve,epss,percentile\n" + body * 50                     # 200 rows
        saved = sca_feeds.MAX_EPSS_CSV_BYTES
        sca_feeds.MAX_EPSS_CSV_BYTES = len(text) - 1
        try:
            with self.assertRaises(sca_feeds.FeedError):
                sca_feeds.read_epss(gz(text))
        finally:
            sca_feeds.MAX_EPSS_CSV_BYTES = saved
        self.assertEqual(sca_feeds.read_epss(gz(text))[1]["rows"], 200)


def zip_bytes(n):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(n):
            zf.writestr("GHSA-%04d.json" % i, json.dumps(ghsa("GHSA-%04d" % i, [], "p%d" % i,
                                                               [{"introduced": "0"}])))
    return buf.getvalue()


def patch_eocd(data, **fields):
    """The zip `data` with End Of Central Directory fields replaced."""
    raw = bytearray(data)
    pos = raw.rfind(b"PK\x05\x06")
    names = ["sig", "disk", "cd_disk", "count_disk", "count", "cd_size", "cd_offset", "comment"]
    values = dict(zip(names, sca_feeds._ZIP_EOCD.unpack_from(raw, pos)))
    values.update(fields)
    sca_feeds._ZIP_EOCD.pack_into(raw, pos, *(values[k] for k in names))
    return bytes(raw)


def as_zip64(data, count=None):
    """The zip `data` rewritten with a ZIP64 end record and locator, the
    classic fields saturated, as writers do past 65,535 entries."""
    pos = data.rfind(b"PK\x05\x06")
    (_s, _d, _cdd, cnt_disk, cnt, cd_size, cd_off, _c) = sca_feeds._ZIP_EOCD.unpack_from(data, pos)
    count = cnt if count is None else count
    z64 = sca_feeds._ZIP64_EOCD.pack(b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, cd_size, cd_off)
    loc = sca_feeds._ZIP64_LOC.pack(b"PK\x06\x07", 0, pos, 1)
    eocd = sca_feeds._ZIP_EOCD.pack(b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    return data[:pos] + z64 + loc + eocd


class OsvZipPreflightTests(unittest.TestCase):
    """The central directory is checked before zipfile parses it (audit L1:
    zipfile parses every record before read_osv_zip's budget applied)."""

    def records(self, data, **kw):
        return list(sca_feeds.read_osv_zip(io.BytesIO(data), **kw))

    def test_ordinary_exports_pass(self):
        data = zip_bytes(5)
        fh = io.BytesIO(data)
        sca_feeds.osv_zip_preflight(fh, 5)
        self.assertEqual(fh.tell(), 0)
        self.assertEqual(len(self.records(data, max_records=5)), 5)
        self.assertEqual(len(self.records(as_zip64(data), max_records=5)), 5)   # zipfile reads it too
        self.assertEqual(len(self.records(data + b"", max_records=5)), 5)

    def test_declared_count_over_budget(self):
        with self.assertRaises(sca_feeds.FeedError) as cm:
            self.records(zip_bytes(5), max_records=3)
        self.assertIn("declares 5 records", str(cm.exception))
        with self.assertRaises(sca_feeds.FeedError):
            self.records(as_zip64(zip_bytes(2), count=10 ** 9), max_records=3)

    def test_a_count_that_lies(self):
        # the count says 1, the directory holds 5 records: zipfile would parse all 5
        with self.assertRaises(sca_feeds.FeedError) as cm:
            self.records(patch_eocd(zip_bytes(5), count=1, count_disk=1), max_records=3)
        self.assertIn("holds more than 3 records", str(cm.exception))

    def test_declared_directory_size_over_budget(self):
        data = patch_eocd(zip_bytes(2), cd_size=0xFFFFFFF0)
        with self.assertRaises(sca_feeds.FeedError) as cm:
            sca_feeds.osv_zip_preflight(io.BytesIO(data), 10, max_cd_bytes=1 << 20)
        self.assertIn("central directory declares", str(cm.exception))

    def test_signature_split_across_chunks_counts_once(self):
        # records straddling the 1 MiB read boundary are counted exactly once
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            for i in range(3000):
                zf.writestr("R%05d-%s.json" % (i, "x" * 300), b"{}")
        data = buf.getvalue()
        sca_feeds.osv_zip_preflight(io.BytesIO(data), 3000)
        with self.assertRaises(sca_feeds.FeedError):
            sca_feeds.osv_zip_preflight(io.BytesIO(patch_eocd(data, count=1, count_disk=1)), 2999)

    def test_what_it_cannot_read_is_left_to_zipfile(self):
        for data in (b"", b"not a zip at all", zip_bytes(2)[:-10]):
            sca_feeds.osv_zip_preflight(io.BytesIO(data), 3)
            with self.assertRaises(sca_feeds.FeedError):
                self.records(data)


# ---------------------------------------------------------------------------
# One advisory per vulnerability
# ---------------------------------------------------------------------------

class GroupingTests(unittest.TestCase):
    def records(self, *raws):
        return [sca_feeds.osv_record(r) for r in raws]

    def test_aliases_join_records_in_any_order(self):
        recs = self.records(PYSEC_URLLIB3, GHSA_URLLIB3, MAL_HIJACK, GHSA_HIJACK, LODASH)
        want = sorted(sorted(r["id"] for r in g) for g in sca_feeds.group_records(recs))
        self.assertEqual(want, [["GHSA-aaaa-0001-0001"], ["GHSA-mmmm-0003-0003", "MAL-2099-0002"],
                                ["GHSA-uuuu-0008-0008", "PYSEC-2099-0001"]])
        rng = random.Random(3)
        for _ in range(10):
            rng.shuffle(recs)
            got = sorted(sorted(r["id"] for r in g) for g in sca_feeds.group_records(recs))
            self.assertEqual(got, want)

    def test_the_advisory_name(self):
        rank = sca_feeds._id_rank
        ids = ["MAL-2099-1", "PYSEC-2099-1", "GHSA-zzzz-zzzz-zzzz", "CVE-2099-10000", "CVE-2099-9999",
               "OSV-2099-1", "CVE-2098-99999", "RUSTSEC-2099-1", "GO-2099-1"]
        self.assertEqual(sorted(ids, key=rank),
                         ["CVE-2098-99999", "CVE-2099-9999", "CVE-2099-10000", "GHSA-zzzz-zzzz-zzzz", "PYSEC-2099-1",
                          "MAL-2099-1", "GO-2099-1", "RUSTSEC-2099-1", "OSV-2099-1"])

    def test_merged_advisory(self):
        kev, _ = sca_feeds.read_kev(json.dumps(KEV_DOC).encode())
        epss = {"CVE-2099-2001": (0.97, 0.999)}
        adv = sca_feeds.advisory(self.records(PYSEC_URLLIB3, GHSA_URLLIB3), kev, epss)
        self.assertEqual(adv["cve"], "CVE-2099-2001")
        self.assertEqual(adv["aliases"], ["GHSA-uuuu-0008-0008", "PYSEC-2099-0001"])
        self.assertEqual(adv["title"], "GHSA-uuuu-0008-0008 issue in urllib3")    # GitHub's title first
        self.assertEqual(adv["severity"], "high")
        self.assertNotIn("cvss", adv)                                  # CVSS 4.0 only: not scored
        self.assertEqual((adv["knownExploited"], adv["ransomware"], adv["dueDate"]),
                         (True, True, "2099-01-27"))
        self.assertEqual((adv["epss"], adv["epssPercentile"]), (0.97, 0.999))
        self.assertEqual(adv["sources"], ["osv:ghsa", "osv:pysec", "cisa-kev", "epss"])
        self.assertEqual(adv["refs"][0], "https://osv.dev/vulnerability/GHSA-uuuu-0008-0008")
        (pkg,) = adv["packages"]
        self.assertEqual((pkg["name"], pkg["ecosystem"], pkg["exact"]), ("urllib3", "pypi", True))
        self.assertEqual(len(pkg["ranges"]), 2)                        # the shared interval once

    def test_malicious_advisory(self):
        adv = sca_feeds.advisory(self.records(MAL_HIJACK, GHSA_HIJACK), {}, {})
        self.assertEqual(adv["cve"], "GHSA-mmmm-0003-0003")
        self.assertEqual((adv["severity"], adv["malicious"]), ("critical", True))
        self.assertNotIn("knownExploited", adv)
        (pkg,) = adv["packages"]
        self.assertEqual([r["fromVersion"] for r in pkg["ranges"]], ["2.1.2", "2.1.1"])


# ---------------------------------------------------------------------------
# Building a bundle
# ---------------------------------------------------------------------------

class BuildTests(Feeds):
    def test_the_bundle(self):
        doc, counts = self.build(now=sca_feeds._utc_now())
        self.assertEqual(doc["bundleVersion"], 1)
        self.assertEqual(doc["sources"], ["osv:npm", "osv:pypi", "osv:go", "osv:crates", "cisa-kev", "epss"])
        self.assertTrue(doc["generator"].startswith("lazaret-sca "))
        self.assertEqual(len(doc["attribution"]), 3)                  # OSV sources, KEV, EPSS
        self.assertEqual(counts, {"OSV records that are not valid JSON (skipped)": 1})
        advs = self.by_id(doc)
        self.assertEqual(sorted(advs), [
            "CVE-2099-1001", "CVE-2099-1002", "CVE-2099-1004", "CVE-2099-1007", "CVE-2099-2001",
            "CVE-2099-2002", "CVE-2099-3001", "CVE-2099-4001", "GHSA-dddd-0010-0010", "GHSA-mmmm-0003-0003",
            "GO-2099-0002", "MAL-2099-0001", "MAL-2099-0003", "RUSTSEC-2099-0003"])
        self.assertEqual(doc["counts"], {"advisories": 14, "packages": 16, "withRanges": 16,
                                         "knownExploited": 2, "malicious": 3})
        self.assertEqual([(p["ecosystem"], p["name"]) for p in advs["CVE-2099-3001"]["packages"]],        # (GO- and GHSA- records: one)
                         [("go", "golang.org/x/net"), ("go", "golang.org/x/net/http2")])
        self.assertEqual(advs["CVE-2099-3001"]["aliases"], ["GHSA-gggg-0011-0011", "GO-2099-0001"])
        self.assertEqual(advs["CVE-2099-3001"]["sources"], ["osv:ghsa", "osv:go"])
        self.assertEqual((advs["CVE-2099-3001"]["severity"], advs["CVE-2099-3001"]["cvss"]), ("high", 7.5))
        self.assertEqual(advs["CVE-2099-4001"]["packages"][0]["ecosystem"], "crates")
        self.assertEqual(advs["RUSTSEC-2099-0003"]["packages"][0]["name"], "Some_Crate")
        self.assertEqual(advs["GO-2099-0002"]["sources"], ["osv:go"])
        self.assertTrue(advs["CVE-2099-1002"]["knownExploited"])      # KEV id was lowercase
        self.assertNotIn("epss", advs["CVE-2099-1002"])               # out-of-range score dropped
        shared = advs["CVE-2099-1007"]["packages"]                    # in both exports: once
        self.assertEqual([(p["ecosystem"], p["name"]) for p in shared],
                         [("npm", "shared-lib"), ("pypi", "shared_lib")])
        feeds = doc["feeds"]
        self.assertEqual(feeds["cisa-kev"]["url"], self.kev)
        self.assertEqual([e["ecosystems"] for e in feeds["osv"]["exports"]], [["npm"], ["PyPI"], ["Go"], ["crates.io"]])
        self.assertEqual([(e["records"], e["keptRecords"]) for e in feeds["osv"]["exports"]], [(10, 8), (5, 5), (4, 3), (3, 2)])
        self.assertEqual(feeds["osv"]["newestModified"], "2099-01-04T00:00:00Z")
        self.assertEqual(feeds["epss"]["modelVersion"], "v2099.01.01")
        loaded = sca.CveBundle(doc)                                   # what lazaret-sca reads
        self.assertEqual(loaded.warnings.lines(), [])
        self.assertEqual(len(loaded.advisories), 14)

    def test_deterministic(self):
        now = sca_feeds._utc_now()
        first, _ = self.build(now=now)
        write_zip(self.path("npm", "all.zip"), list(reversed(NPM_RECORDS)))
        second, _ = self.build(now=now)
        self.assertEqual(first["advisories"], second["advisories"])

    def test_one_combined_archive(self):
        write_zip(self.path("all.zip"), NPM_RECORDS + [r for r in PYPI_RECORDS if r is not SHARED] + GO_RECORDS + CRATES_RECORDS)
        doc, _ = self.build(osv_url=self.path("all.zip"))
        self.assertEqual(len(doc["feeds"]["osv"]["exports"]), 1)
        self.assertEqual(doc["counts"]["advisories"], 14)

    def test_without_epss(self):
        doc, _ = self.build(epss_url=None)
        self.assertEqual(doc["sources"], ["osv:npm", "osv:pypi", "osv:go", "osv:crates", "cisa-kev"])
        self.assertFalse(any("epss" in a for a in doc["advisories"]))
        self.assertFalse(any("EPSS" in line for line in doc["attribution"]))

    def test_kev_falls_back_to_the_mirror(self):
        missing = self.path("no-such-kev.json")
        lines = []
        doc, _ = self.build(kev_urls=[missing, self.kev], log=lines.append)
        self.assertEqual(doc["feeds"]["cisa-kev"]["url"], self.kev)
        self.assertTrue(any("trying the next source" in s for s in lines))
        with open(self.path("html.json"), "w", encoding="utf-8") as fh:
            fh.write("<html>blocked</html>")
        with self.assertRaises(sca_feeds.FeedError) as cm:
            self.build(kev_urls=[missing, self.path("html.json")])
        self.assertIn("no-such-kev.json", str(cm.exception))
        self.assertIn("not valid JSON", str(cm.exception))

    def test_an_ecosystem_with_no_advisories_is_refused(self):
        """Per export: the npm export's record for a PyPI package (SHARED)
        does not stand in for an empty PyPI export."""
        write_zip(self.path("PyPI", "all.zip"), [MAVEN])
        with self.assertRaises(sca_feeds.FeedError) as cm:
            self.build()
        self.assertIn("no pypi advisories", str(cm.exception))
        self.assertIn("PyPI", str(cm.exception))
        write_zip(self.path("all.zip"), [LODASH, MAVEN])                 # one archive, npm only
        with self.assertRaises(sca_feeds.FeedError) as cm:
            self.build(osv_url=self.path("all.zip"))
        self.assertIn("no pypi or go or crates advisories", str(cm.exception))

    def test_a_go_or_crates_export_with_no_module_or_crate_is_refused(self):
        """An export of the Go database that holds only the standard library (or the other ecosystems' records) would
        clear every Go module: refused, as an empty one is."""
        for export, records, want in (("Go", [GO_TOOLCHAIN], "no go advisories"), ("Go", [LODASH], "no go advisories"),
                                      ("crates.io", [RUSTSEC_UNMAINTAINED], "no crates advisories"),
                                      ("crates.io", [GO_UPPER], "no crates advisories")):
            with self.subTest(export=export, records=[r["id"] for r in records]):
                write_zip(self.path(export, "all.zip"), records)
                with self.assertRaises(sca_feeds.FeedError) as cm:
                    self.build()
                self.assertIn(want, str(cm.exception))
                self.assertIn(export, str(cm.exception))
            write_zip(self.path("Go", "all.zip"), GO_RECORDS)
            write_zip(self.path("crates.io", "all.zip"), CRATES_RECORDS)

    def test_damaged_archives(self):
        with open(self.path("npm", "all.zip"), "rb") as fh:
            data = fh.read()
        with open(self.path("npm", "all.zip"), "wb") as fh:
            fh.write(data[: len(data) // 2])                          # a cut-off download
        with self.assertRaises(sca_feeds.FeedError):
            self.build()
        # a member whose bytes were altered in transit: the CRC check catches it
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("GHSA-x.json", json.dumps(LODASH))
        raw = bytearray(buf.getvalue())
        at = raw.index(b"lodash")
        raw[at] = ord("L")
        with self.assertRaises(sca_feeds.FeedError):
            list(sca_feeds.read_osv_zip(io.BytesIO(bytes(raw))))

    def test_record_budget(self):
        with open(self.path("npm", "all.zip"), "rb") as fh:
            with self.assertRaises(sca_feeds.FeedError):
                list(sca_feeds.read_osv_zip(fh, max_records=3))

    def test_stale_mirror_warning(self):
        doc, _ = self.build()
        now = sca.parse_generated_at("2099-02-01T00:00:00Z")
        self.assertEqual(len(sca_feeds.stale_feed_warnings(doc, now)), 2)
        self.assertEqual(sca_feeds.stale_feed_warnings(doc, sca.parse_generated_at("2099-01-07T00:00:00Z")), [])

    def test_dump_is_one_advisory_per_line(self):
        doc, _ = self.build()
        buf = io.StringIO()
        sca_feeds.dump_bundle(doc, buf)
        text = buf.getvalue()
        self.assertEqual(json.loads(text), doc)
        lines = text.splitlines()
        first = lines.index('"advisories": [') + 1
        self.assertEqual(len(lines) - first - 2, len(doc["advisories"]))
        self.assertTrue(text.isascii())


class FetchTests(Feeds):
    def test_local_paths_and_file_urls(self):
        for location in [self.path("kev.json"), pathlib.Path(self.path("kev.json")).as_uri()]:
            buf = io.BytesIO()
            self.assertEqual(sca_feeds.fetch(location, buf, 1 << 20), os.path.getsize(self.path("kev.json")))

    def test_refused_locations(self):
        for location in ["http://example.invalid/kev.json", "ftp://example.invalid/kev.json",
                         "data:,hello", "file://fileserver/share/kev.json", self.path("missing.json"),
                         self.dir]:
            with self.subTest(location=location):
                with self.assertRaises(sca_feeds.FeedError):
                    sca_feeds.fetch(location, io.BytesIO(), 1 << 20)

    def test_budget(self):
        with self.assertRaises(sca_feeds.FeedError) as cm:
            sca_feeds.fetch(self.path("kev.json"), io.BytesIO(), 16)
        self.assertIn("budget", str(cm.exception))

    def test_redirects_stay_on_https(self):
        handler = sca_feeds._HttpsRedirects()
        req = urllib.request.Request("https://example.invalid/feed")
        new = handler.redirect_request(req, None, 302, "Found", {}, "https://mirror.invalid/feed")
        self.assertEqual(new.full_url, "https://mirror.invalid/feed")
        for target in ["http://example.invalid/feed", "file:///etc/passwd", "ftp://example.invalid/f"]:
            with self.assertRaises(urllib.error.URLError):
                handler.redirect_request(req, None, 302, "Found", {}, target)


# ---------------------------------------------------------------------------
# The matcher: exact entries
# ---------------------------------------------------------------------------

def bundle_of(*packages, **adv):
    doc = {"bundleVersion": 1, "advisories": [dict({"cve": "CVE-2099-0001", "packages": list(packages)},
                                                   **adv)]}
    return sca.CveBundle(doc)


def exact(name, eco, ranges=None):
    return {"name": name, "ecosystem": eco, "exact": True, "ranges": ranges if ranges is not None else [{}]}


class ExactMatchingTests(unittest.TestCase):
    def hits(self, bundle, name, eco):
        return len(bundle.advisories_for(name, eco))

    def test_own_ecosystem_and_name_only(self):
        b = bundle_of(exact("babel-core", "npm"))
        self.assertEqual(self.hits(b, "babel-core", "npm"), 1)
        self.assertEqual(self.hits(b, "@babel/core", "npm"), 0)       # a loose entry would match
        self.assertEqual(self.hits(b, "babel-core", "pypi"), 0)
        b = bundle_of(exact("requests", "npm"))
        self.assertEqual(self.hits(b, "requests", "pypi"), 0)
        b = bundle_of(exact("JSONStream", "npm"))
        self.assertEqual(self.hits(b, "jsonstream", "npm"), 0)
        self.assertEqual(self.hits(b, "JSONStream", "npm"), 1)
        b = bundle_of(exact("Foo_Bar.baz", "pypi"))
        for name in ["foo-bar-baz", "FOO.BAR_BAZ", "foo__bar--baz"]:
            self.assertEqual(self.hits(b, name, "pypi"), 1, name)
        b = bundle_of(exact("python-dateutil", "pypi"))
        self.assertEqual(self.hits(b, "dateutil", "pypi"), 0)          # no CPE alias folding
        self.assertEqual(self.hits(b, "python_dateutil", "pypi"), 1)
        self.assertEqual(self.hits(b, "python-dateutil", None), 1)     # no ecosystem: both are tried

    def test_loose_entries_keep_cpe_matching(self):
        b = bundle_of({"name": "babel-core", "ecosystem": "npm", "ranges": []})
        self.assertEqual(self.hits(b, "@babel/core", "npm"), 1)
        b = bundle_of({"name": "requests", "ecosystem": "npm", "exact": "yes", "ranges": []})
        self.assertEqual(self.hits(b, "requests", "pypi"), 1)           # only true is exact

    def test_exact_needs_an_ecosystem(self):
        b = bundle_of({"name": "lodash", "ecosystem": "maven", "exact": True, "ranges": []})
        self.assertEqual(b.warnings.lines(),
                         ["1 exact package entries without a known ecosystem (matched by name)"])
        self.assertEqual(self.hits(b, "lodash", "npm"), 1)

    def test_every_version_affected_needs_no_version(self):
        b = bundle_of(exact("lodahs", "npm"), malicious=True)
        inv = [("npm", "lodahs", "", "package.json"), ("npm", "lodahs", "git+https://x.invalid/r", "package.json")]
        matches, unknown = sca.match_inventory(inv, b)
        self.assertEqual((len(matches), len(unknown)), (2, 0))
        b = bundle_of(exact("lodash", "npm", [{"toVersion": "4.17.12", "toInclusive": False}]))
        matches, unknown = sca.match_inventory([("npm", "lodash", "", "package.json")], b)
        self.assertEqual((len(matches), len(unknown)), (0, 1))          # a real bound still needs one


# ---------------------------------------------------------------------------
# The CLI
# ---------------------------------------------------------------------------

class CliTests(Feeds):
    def setUp(self):
        super().setUp()
        self.out = self.path("out", "cve-bundle.json")
        os.makedirs(os.path.dirname(self.out))

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sca.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def update(self, *extra, bundle=None):
        return self.main("--update-bundle", "--bundle", bundle or self.out, "--osv-url", self.osv,
                         "--kev-url", self.kev, "--epss-url", self.epss, *extra)

    def project(self):
        root = self.path("proj")
        for rel, data in {
            "node_modules/lodash/package.json": {"name": "lodash", "version": "4.17.11"},
            "node_modules/@babel/core/package.json": {"name": "@babel/core", "version": "7.0.0"},
            "node_modules/lodahs/package.json": {"name": "lodahs", "version": "1.0.0"},
            "node_modules/vite/package.json": {"name": "vite", "version": "6.2.3"},
            "venv/lib/python3.12/site-packages/urllib3-2.0.5.dist-info/METADATA":
                "Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.5\n",
            "venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA":
                "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
        }.items():
            p = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(data if isinstance(data, str) else json.dumps(data))
        return root

    def test_update(self):
        rc, out, err = self.update()
        self.assertEqual(rc, 0, err)
        self.assertIn("14 advisories", out)
        self.assertIn("OSV records that are not valid JSON (skipped): 1", err)
        self.assertIn("note: Go standard library and toolchain entries (not modules; skipped): 2", out)
        self.assertIn("note: RustSec informational entries (unmaintained or notice; not vulnerabilities; skipped): 1", out)
        with open(self.out, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["counts"]["advisories"], 14)
        self.assertEqual(sca.CveBundle.load(self.out).warnings.lines(), [])
        rc, out, _ = self.update("-q")                                  # replaces its own bundle
        self.assertEqual(rc, 0)
        self.assertEqual(len(out.strip().splitlines()), 2)             # the summary only

    def test_update_then_scan(self):
        root = self.project()
        rc, out, err = self.main(root, "--update-bundle", "--bundle", self.out, "--osv-url", self.osv,
                                 "--kev-url", self.kev, "--epss-url", self.epss, "--no-json", "--ci")
        self.assertEqual(rc, 1, err)
        res_out = out[out.index("Lazaret SCA — " + os.path.abspath(root)):]
        self.assertIn("✗ No known malicious packages", res_out)
        self.assertIn("✗ No known-exploited (KEV) dependencies", res_out)
        inv = sca.scan_all(root)
        matches, unknown = sca.match_inventory(inv, sca.CveBundle.load(self.out))
        self.assertEqual(sorted((m[2][1], m[0]["cve"]) for m in matches), [
            ("lodahs", "MAL-2099-0001"), ("lodash", "CVE-2099-1001"), ("urllib3", "CVE-2099-2001"),
            ("vite", "CVE-2099-1002")])
        self.assertEqual(unknown, [])

    def test_malicious_finding(self):
        root = self.project()
        self.assertEqual(self.update()[0], 0)
        rep = self.path("out", "sca.json")
        rc, _, err = self.main(root, "--bundle", self.out, "--json", rep, "-q")
        self.assertEqual(rc, 0, err)
        with open(rep, encoding="utf-8") as fh:
            res = json.load(fh)
        (mal,) = [i for i in res["issues"] if i["rule"] == "SCA-MALICIOUS"]
        self.assertEqual(mal["sev"], "BLOCKER")
        self.assertIn("lodahs 1.0.0 is a reported malicious package version", mal["msg"])
        self.assertTrue(mal["detail"]["malicious"])
        self.assertIn("rotate the credentials", mal["fix"])
        (kev,) = [i for i in res["issues"] if i["rule"] == "SCA-CVE-KEV" and i["detail"]["package"] == "urllib3"]
        self.assertEqual((kev["sev"], kev["fix"]), ("BLOCKER", "Upgrade to >= 2.0.6"))
        cond = {c["label"]: c["ok"] for c in res["conditions"]}
        self.assertFalse(cond["No known malicious packages"])

    def test_a_failed_update_changes_nothing(self):
        self.assertEqual(self.update()[0], 0)
        with open(self.out, "rb") as fh:
            before = fh.read()
        os.remove(self.path("PyPI", "all.zip"))
        rc, _, err = self.update()
        self.assertEqual(rc, 4)
        self.assertIn("the bundle was not changed", err)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.out))), ["cve-bundle.json"])

    def test_output_paths(self):
        rc, _, err = self.update(bundle=self.dir)                       # a directory
        self.assertEqual(rc, 3, err)
        rc, _, err = self.update(bundle=self.path("nowhere", "b.json"))  # a missing directory
        self.assertEqual(rc, 3, err)
        notes = self.path("out", "notes.txt")
        with open(notes, "w", encoding="utf-8") as fh:
            fh.write("keep me")
        rc, _, err = self.update(bundle=notes)
        self.assertEqual(rc, 3)
        self.assertIn("not a CVE bundle", err)
        with open(notes, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "keep me")
        self.assertEqual(self.update("--force-overwrite", bundle=notes)[0], 0)

    def test_never_writes_through_a_symlink(self):
        target = self.path("out", "target.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write('{"bundleVersion": 1}')
        link = self.path("out", "link.json")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available")
        rc, _, err = self.update("--force-overwrite", bundle=link)
        self.assertEqual(rc, 3)
        self.assertIn("symlink", err)
        with open(target, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), '{"bundleVersion": 1}')

    def test_default_path(self):
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        os.chdir(self.path("out"))
        rc, _, err = self.main("--update-bundle", "--osv-url", self.osv, "--kev-url", self.kev,
                               "--no-epss", "-q")
        self.assertEqual(rc, 0, err)
        self.assertTrue(os.path.isfile(self.path("out", sca.DEFAULT_BUNDLE)))

    def test_usage(self):
        for argv in [[], ["--bundle", "b.json"], [self.dir], [self.dir, "--osv-url", "x", "--bundle", "b"],
                     [self.dir, "--no-epss", "--bundle", "b"],
                     ["--update-bundle", "--no-epss", "--epss-url", "x"]]:
            with self.subTest(argv=argv):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as cm:
                        sca.main(argv)
                self.assertEqual(cm.exception.code, 2)
        self.assertEqual(self.main(self.project(), "--inventory-only")[0], 0)   # needs no bundle

    def test_help_names_the_real_defaults(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            sca.main(["--help"])
        text = "".join(out.getvalue().split())      # argparse wraps to the terminal, mid-URL too
        for url in (sca_feeds.OSV_URL, sca_feeds.EPSS_URL):
            self.assertIn(url, text)
        self.assertEqual(sca.DEFAULT_BUNDLE, sca_feeds.DEFAULT_BUNDLE)

    def test_no_advisories_message(self):
        empty = self.path("out", "empty.json")
        with open(empty, "w", encoding="utf-8") as fh:
            json.dump({"bundleVersion": 1, "advisories": []}, fh)
        rc, _, err = self.main(self.project(), "--bundle", empty, "--no-json")
        self.assertEqual(rc, 4)
        self.assertIn("--update-bundle", err)


@_support.requires_env("LAZARET_TEST_FEEDS")
class LiveFeedsTests(unittest.TestCase):
    """The real feeds, over the network: LAZARET_TEST_FEEDS=1."""

    def test_the_real_feeds(self):
        lines = []
        doc, counts = sca_feeds.build_bundle(log=lines.append)
        sys.stderr.write("\n".join(lines) + "\n")
        c = doc["counts"]
        self.assertGreater(c["advisories"], 10000)
        self.assertGreater(c["knownExploited"], 5)
        self.assertGreater(doc["feeds"]["cisa-kev"]["entries"], 1000)
        self.assertGreater(len([a for a in doc["advisories"] if "epss" in a]), 1000)
        for eco in ("npm", "pypi"):
            self.assertTrue(any(p["ecosystem"] == eco for a in doc["advisories"] for p in a["packages"]))
        self.assertEqual(sca.CveBundle(doc).warnings.lines(), [])
        self.assertEqual(sca_feeds.stale_feed_warnings(doc), [])


if __name__ == "__main__":
    unittest.main()
