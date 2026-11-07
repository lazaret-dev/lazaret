"""RA-10 (registry/yanks.py): SC-YANK-TO-PUSH, a crate release published within a day of yanks of the crate's earlier
stable versions by the account that published it (arrayref's attacker yanked versions to push users to the new ones),
read from crates.io's version records (`audit_actions`) and compared as a weaker indicator: SC-NEW-INDICATOR when the
established predecessor's own publication came with no such yanks.

crates.io's answers are built here in the shape its API served on Oct 17, 2026 (`versions`, each with `num`,
`yanked`, `created_at`, `published_by` and `audit_actions` of `action`, `user` and `time`; read live once for a crate
without yanks and one with, with the scanner's own client); the crate `kit` and its accounts are made up, the crates
inert. Nothing reaches the network: the registry scan reads the crates module's answers through a patched
`repo.module_transport`, the Cargo guard a loopback registry (tests/registry/_cargo_support.py) and a mapped fetcher."""

import datetime
import hashlib
import json
import os
import unittest
import urllib.request
from unittest import mock

from lazaret.registry import cargosrc, guard, prior, repo, yanks
from lazaret.registry.ecosystems import crates
from lazaret.scanner import _native
from tests.registry import _cargo_support as cs
from tests.registry.test_guard_cargo import INDEX, STATIC, CrateCase
from tests.registry.test_registry_go_crates import Served

ON = {prior.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": ""}
UTC = datetime.timezone.utc
RELEASE = datetime.datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
HOUR, DAY = datetime.timedelta(hours=1), datetime.timedelta(days=1)
PUB, OTHER = (101, "kit-maintainer"), (202, "someone-else")
API_URL = "https://crates.io/api/v1/crates/kit/versions"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def user(who):
    return {"id": who[0], "login": who[1], "name": None, "avatar": None, "url": f"https://github.com/{who[1]}"}


def action(kind, who, when):
    return {"action": kind, "user": user(who), "time": iso(when)}


def version(num, when, by=PUB, yanked=False, actions=()):
    """One version's record as crates.io's API answers it (its publish action first, then `actions`)."""
    return {"id": abs(hash(num)) % 10_000_000, "crate": "kit", "num": num, "created_at": iso(when),
            "updated_at": iso(when), "yanked": yanked, "yank_message": None, "published_by": user(by),
            "audit_actions": [action("publish", by, when), *actions], "checksum": "00" * 32}


def answer(*versions):
    return {"versions": list(versions), "meta": {"total": len(versions), "next_page": None}}


def arrayref_like(yanker=PUB, yanked_at=RELEASE - 3 * HOUR, prerelease=False):
    """kit 0.3.5 (60 days before), 0.3.6 to 0.3.9 (50 to 20 days before) yanked by `yanker` at `yanked_at`, and 0.3.10,
    published at RELEASE by PUB; with `prerelease`, 0.3.10-rc.1 too, yanked with them."""
    out = [version("0.3.10", RELEASE)]
    for k, num in enumerate(("0.3.9", "0.3.8", "0.3.7", "0.3.6")):
        out.append(version(num, RELEASE - (20 + 10 * k) * DAY, yanked=True, actions=[action("yank", yanker, yanked_at)]))
    if prerelease:
        out.append(version("0.3.10-rc.1", RELEASE - 5 * DAY, yanked=True, actions=[action("yank", yanker, yanked_at)]))
    out.append(version("0.3.5", RELEASE - 60 * DAY))
    return answer(*out)


class ReasonTests(unittest.TestCase):
    def test_yanks_by_the_publisher_within_hours_of_the_release(self):
        found = yanks.reason(arrayref_like(), "0.3.10")
        self.assertEqual(found, (PUB, ["0.3.6", "0.3.7", "0.3.8", "0.3.9"], 3 * HOUR))
        issue = yanks.issue(found)
        self.assertEqual((issue["rule"], issue["sev"], issue["file"]), ("SC-YANK-TO-PUSH", "MAJOR", "(release)"))
        self.assertEqual(issue["msg"], "Its earlier releases were yanked as it was published: 4 stable versions before it "
                                       "(0.3.6, 0.3.7, 0.3.8, 0.3.9) yanked by kit-maintainer, the account that published "
                                       "it, within 3 hours of its publication.")
        self.assertIn("arrayref", issue["why"])
        # after its publication too, within the day
        self.assertIsNotNone(yanks.reason(arrayref_like(yanked_at=RELEASE + 20 * HOUR), "0.3.10"))

    def test_yanks_by_another_account_are_nothing(self):
        self.assertIsNone(yanks.reason(arrayref_like(yanker=OTHER), "0.3.10"))
        # the same login and another id is another account; an id alone matches by the id
        self.assertIsNone(yanks.reason(arrayref_like(yanker=(999, PUB[1])), "0.3.10"))
        self.assertIsNotNone(yanks.reason(arrayref_like(yanker=(PUB[0], "renamed")), "0.3.10"))

    def test_yanks_a_month_earlier_are_nothing(self):
        self.assertIsNone(yanks.reason(arrayref_like(yanked_at=RELEASE - 30 * DAY), "0.3.10"))
        self.assertIsNone(yanks.reason(arrayref_like(yanked_at=RELEASE + DAY + HOUR), "0.3.10"))

    def test_a_pre_release_yanked_is_not_counted(self):
        found = yanks.reason(arrayref_like(prerelease=True), "0.3.10")
        self.assertEqual(found[1], ["0.3.6", "0.3.7", "0.3.8", "0.3.9"])
        # one stable version and a pre-release: one yank, the broken release its fix replaces, is not it
        doc = answer(version("0.3.10", RELEASE),
                     version("0.3.10-rc.1", RELEASE - 5 * DAY, yanked=True, actions=[action("yank", PUB, RELEASE)]),
                     version("0.3.9", RELEASE - 20 * DAY, yanked=True, actions=[action("yank", PUB, RELEASE)]),
                     version("0.3.5", RELEASE - 60 * DAY))
        self.assertIsNone(yanks.reason(doc, "0.3.10"))

    def test_what_is_not_counted(self):
        base = arrayref_like()["versions"]
        # a version yanked and unyanked since, a later version yanked: not counted (two left: still MAJOR)
        unyanked = dict(base[1], yanked=False, audit_actions=base[1]["audit_actions"] + [action("unyank", PUB, RELEASE)])
        later = version("0.4.0", RELEASE + HOUR, yanked=True, actions=[action("yank", PUB, RELEASE + 2 * HOUR)])
        found = yanks.reason(answer(base[0], unyanked, base[2], base[3], later, base[5]), "0.3.10")
        self.assertEqual(found[1], ["0.3.7", "0.3.8"])
        # a release the answer does not list, or with no publisher: nothing
        self.assertIsNone(yanks.reason(arrayref_like(), "0.3.11"))
        nobody = dict(base[0], published_by=None, audit_actions=[])
        self.assertIsNone(yanks.reason(answer(nobody, *base[1:]), "0.3.10"))
        # an answer of another shape
        for bad in ({"versions": 5}, [], {"crate": {}}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                yanks.reason(bad, "0.3.10")

    def test_the_index_says_when_to_ask(self):
        lines = "\n".join(json.dumps({"name": "kit", "vers": v, "cksum": "00" * 32, "yanked": y, "deps": []})
                          for v, y in (("0.3.5", False), ("0.3.6", True), ("0.3.7", True), ("0.3.10-rc.1", True),
                                       ("0.3.10", False), ("0.4.0", True))) + "\nnot json, yanked: true\n"
        self.assertEqual(yanks.earlier_yanked_text(lines, "0.3.10"), ["0.3.6", "0.3.7"])
        self.assertEqual(yanks.earlier_yanked_text(lines, "0.3.6"), [])
        self.assertEqual(yanks.earlier_yanked([{"vers": "0.1.0", "yanked": True}], "x"), [])


def crate_files(name, num):
    return cs.crate_tgz(name, num, {})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RegistryScanTests(unittest.TestCase):
    """`lazaret-registry crates:kit@0.3.10` over the crates module's real fetch (repo.module_transport patched): the
    index file, the .crate files, and crates.io's versions answer."""

    def served(self, doc, yanked=("0.3.6", "0.3.7", "0.3.8", "0.3.9")):
        out, lines = {}, []
        times = {v["num"]: v["created_at"] for v in doc["versions"]}
        for num in sorted(times, key=crates.semver_key):
            data = crate_files("kit", num)
            out[STATIC + f"kit/kit-{num}.crate"] = data
            lines.append(json.dumps({"name": "kit", "vers": num, "deps": [], "features": {},
                                     "cksum": hashlib.sha256(data).hexdigest(), "yanked": num in yanked,
                                     "pubtime": times[num][:19] + "Z"}))
        out[INDEX + crates.index_path("kit")] = ("\n".join(lines) + "\n").encode()
        out[API_URL] = json.dumps(doc).encode()
        return Served(out)

    def scan(self, served, env=ON):
        with mock.patch.object(repo, "module_transport", served), \
                mock.patch.object(repo._base.Fetch, "_wait_turn", lambda self, url: None), mock.patch.dict(os.environ, env):
            return repo.scan_package("crates", "kit", "0.3.10")

    def found(self, res, rule=yanks.RULE):
        return [i for i in res["issues"] if i["rule"] == rule]

    def test_yanks_as_it_was_published_feed_the_comparison(self):
        served = self.served(arrayref_like())
        res = self.scan(served)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        [yank] = self.found(res)
        self.assertEqual((yank["sev"], yank["file"]), ("MAJOR", "(release)"))
        [new] = self.found(res, prior.RULE)
        self.assertEqual(new["sev"], "CRITICAL")
        self.assertIn("(SC-YANK-TO-PUSH) is new in this release: 0.3.5, published 60 days before it", new["msg"])
        self.assertEqual(res["priorRelease"], {"version": "0.3.5", "publishedBefore": "60 days", "files": [],
                                               "newRules": ["SC-YANK-TO-PUSH"]})
        # crates.io's API asked once (the predecessor's publication read from the same answer), nothing of 0.3.5
        # downloaded (the yanks are the release's own)
        self.assertEqual(served.urls().count(API_URL), 1)
        self.assertNotIn(STATIC + "kit/kit-0.3.5.crate", served.urls())

    def test_a_predecessor_published_with_yanks_too(self):
        # (a maintainer who yanks as a habit: 0.3.5 came with 0.3.3 and 0.3.4 yanked; the release stays MAJOR)
        doc = arrayref_like()
        doc["versions"] += [version(num, RELEASE - (70 + k) * DAY, yanked=True,
                                    actions=[action("yank", PUB, RELEASE - 60 * DAY + HOUR)])
                            for k, num in enumerate(("0.3.4", "0.3.3"))]
        res = self.scan(self.served(doc, yanked=("0.3.3", "0.3.4", "0.3.6", "0.3.7", "0.3.8", "0.3.9")))
        self.assertEqual((res["verdict"], [i["sev"] for i in self.found(res)], self.found(res, prior.RULE)),
                         ("WARN", ["MAJOR"], []))
        self.assertEqual(res["priorRelease"]["newRules"], [])

    def test_the_api_is_asked_only_when_the_index_lists_yanks(self):
        served = self.served(arrayref_like(), yanked=("0.3.9",))
        res = self.scan(served)
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []))
        self.assertNotIn(API_URL, served.urls())

    def test_an_api_that_does_not_answer_and_off_are_nothing(self):
        served = self.served(arrayref_like())
        del served.responses[API_URL]
        res = self.scan(served)
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []))
        self.assertIn(API_URL, served.urls())
        served = self.served(arrayref_like())
        served.responses[API_URL] = json.dumps({"versions": "not a list"}).encode()      # (an answer of another shape)
        self.assertEqual(self.scan(served)["verdict"], "OK")
        served = self.served(arrayref_like())
        res = self.scan(served, env={prior.OFF_ENV: "1"})
        self.assertEqual((res["verdict"], self.found(res)), ("OK", []))
        self.assertNotIn(API_URL, served.urls())

    def test_another_accounts_yanks(self):
        res = self.scan(self.served(arrayref_like(yanker=OTHER)))
        self.assertEqual((res["verdict"], self.found(res), "priorRelease" in res), ("OK", [], False))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
@mock.patch.dict(os.environ, ON)
@mock.patch.object(guard, "CRATES_API_INTERVAL", 0)
class CargoGuardTests(CrateCase):
    """The Cargo guard's check of kit 0.3.10 (2 days old, in the window) from the public index (the loopback registry
    taken for it, as test_guard_cargo's CratePriorTests take it), the real scanner, crates.io's versions answer from a
    mapped fetcher."""

    def setUp(self):
        super().setUp()
        self.release = cs.NOW - 2 * DAY
        self.reg.add("kit", "0.3.5", published=self.release - 60 * DAY)
        for k, num in enumerate(("0.3.9", "0.3.8", "0.3.7", "0.3.6")):
            self.reg.add("kit", num, published=self.release - (20 + 10 * k) * DAY, yanked=True)
        self.reg.add("kit", "0.3.10", published=self.release)
        self.cache = guard.VerdictCache(None)
        self.doc, self.asked, self.module_urls = None, [], []

    def api_answer(self, yanker=PUB, at=None):
        at = at or self.release - 3 * HOUR
        versions = [version("0.3.10", self.release)]
        versions += [version(num, self.release - (20 + 10 * k) * DAY, yanked=True, actions=[action("yank", yanker, at)])
                     for k, num in enumerate(("0.3.9", "0.3.8", "0.3.7", "0.3.6"))]
        return answer(*versions, version("0.3.5", self.release - 60 * DAY))

    def loopback(self, path):
        with urllib.request.urlopen(self.reg.url.rstrip("/") + path) as r:
            return r.read()

    def transport(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None, data=None,
                  content_type=None):
        self.module_urls.append(url)
        check_redirect(url)
        if url.startswith(INDEX):
            return self.loopback("/" + url[len(INDEX):])
        raise repo.FetchError("not served here: " + url)

    def check_crate(self, offline=False):
        case = self

        class Mapped(guard.Fetcher):
            def fetch(self, url, max_bytes=repo.MAX_DOWNLOAD_BYTES, accept=None, timeout=repo.DOWNLOAD_TIMEOUT):
                case.asked.append(url)
                if url == API_URL:
                    if case.doc is None:
                        raise repo.FetchError("HTTP 503 fetching " + url)
                    return json.dumps(case.doc).encode(), {}
                self.check(url)
                if url.startswith(STATIC):
                    return case.loopback("/dl/" + url[len(STATIC):]), {}
                return super().fetch(url, max_bytes, accept, timeout)

        f = Mapped({guard.netloc(self.reg.url)})
        self.addCleanup(f.close)
        scanner = guard.Scanner(self.cache, jobs=1, isolate=False)
        self.addCleanup(scanner.close)
        ctx = self.context(scanner=scanner)
        if offline:
            reg = guard._offline_registry(cargosrc.DEFAULT_INDEX)
            self.put_in_cargo_cache("kit", "0.3.10")
        else:
            reg = self.registry(f)
            reg.default = True
            f.allow(STATIC)
        self.asked.clear()
        with mock.patch.object(repo, "module_transport", self.transport):
            return guard.check_crate(ctx, f, reg, self.pkg("kit", "0.3.10"), self.home, offline)

    def test_yanks_by_its_publisher_block_it(self):
        self.doc = self.api_answer()
        check = self.check_crate()
        self.assertEqual(check.verdict, "SUSPICIOUS")
        self.assertTrue(check.blocked and check.blocked[0].startswith("SUSPICIOUS: A release's earlier versions yanked "
                                                                      "as it was published (SC-YANK-TO-PUSH) is new"),
                        check.blocked)
        self.assertTrue(check.indicators[0].startswith("SC-NEW-INDICATOR (CRITICAL)"), check.indicators)
        self.assertTrue(check.indicators[1].startswith("SC-YANK-TO-PUSH (MAJOR) (release): Its earlier releases were "
                                                       "yanked as it was published: 4 stable versions"), check.indicators)
        self.assertEqual(check.prior["newRules"], ["SC-YANK-TO-PUSH"])
        self.assertEqual(self.asked.count(API_URL), 1)
        self.assertNotIn(STATIC + "kit/kit-0.3.5.crate", self.asked)        # (the yanks are the release's own)
        # the verdict cached with the comparison: nothing asked again
        check = self.check_crate()
        self.assertEqual((check.verdict, self.asked), ("SUSPICIOUS", []))

    def test_another_accounts_yanks_and_settled(self):
        self.doc = self.api_answer(yanker=OTHER)
        check = self.check_crate()
        self.assertEqual((check.verdict, check.blocked, check.prior), ("OK", [], None))
        self.assertEqual(self.asked.count(API_URL), 1)
        # read two days after its publication: settled, and neither the index nor the API asked again
        key = guard.VerdictCache.key("crates", "kit", "0.3.10", "sha256:" + self.reg.checksum("kit", "0.3.10"))
        self.assertIs(self.cache.get(key)["yanks"], True)
        check = self.check_crate()
        self.assertEqual((check.verdict, self.asked), ("OK", []))

    def test_an_api_that_does_not_answer_is_nothing_and_asked_again(self):
        check = self.check_crate()
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertEqual(self.asked.count(API_URL), 1)
        self.doc = self.api_answer()
        check = self.check_crate()
        self.assertEqual(check.verdict, "SUSPICIOUS")

    def test_too_few_yanks_in_the_index_and_offline_ask_nothing(self):
        for num in ("0.3.6", "0.3.7", "0.3.8"):
            self.reg.versions["kit"][num]["yanked"] = False
        self.doc = self.api_answer()
        check = self.check_crate()
        self.assertEqual((check.verdict, API_URL in self.asked), ("OK", False))
        self.cache = guard.VerdictCache(None)
        check = self.check_crate(offline=True)
        self.assertEqual((check.verdict, self.asked, self.module_urls), ("OK", [], []))


if __name__ == "__main__":
    unittest.main()
