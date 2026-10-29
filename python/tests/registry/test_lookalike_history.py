"""TYPO-ESTABLISHED (registry/lookalike_history.py): a release's look-alike dependency (SC-TYPOSQUAT) that is itself an
established package — first published more than a year before the release, at least three versions, and on npm no new
publisher — is INFO, its message saying why; a new one, one with a new publisher, or one whose history did not come
back is MAJOR, as before. djotls 0.1.0's shape (October 2026): a crate two hours old that depends on `roman` (2015, 13
versions), one change from `rowan`.

The registries are fakes served by URL (`repo._fetch`, the guard's fetcher, the crates module's index lines); nothing
reaches the network. Names are made up or the packages' own, the archives built in memory, nothing in them runs."""
import base64
import contextlib
import datetime
import email.utils
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from unittest import mock

from lazaret.registry import guard, lookalike_history as lh, prior, repo
from lazaret.registry.ecosystems import base
from lazaret.scanner import _native
from tests import _support
from tests.registry import _cargo_support as cs
from tests.registry._review_support import manifest, tarball
from tests.registry.test_guard import context
from tests.registry.test_guard_cargo import CrateCase

UTC = datetime.timezone.utc
DAY = datetime.timedelta(days=1)
NOW = datetime.datetime.now(UTC)
DJOTLS = datetime.datetime(2026, 10, 16, 2, 28, 10, tzinfo=UTC)          # djotls 0.1.0 on the crates index
ROMAN = datetime.datetime(2015, 3, 29, 7, 8, 22, tzinfo=UTC)             # roman 0.0.1
ON = {lh.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": ""}
NPM = "https://registry.npmjs.org/"
BLOB = base64.b64encode(bytes(range(256)) * 2).decode()


def iso(dt):
    return dt.isoformat().replace("+00:00", "Z")


def typos(res):
    return [(i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-TYPOSQUAT"]


class Registry:
    """Documents by URL (a URL it does not know is a 404), and the URLs asked for."""

    def __init__(self, docs=None):
        self.docs, self.files, self.fetched = dict(docs or {}), {}, []

    def fetch(self, url, max_bytes=None, timeout=None, accept=None, **_kw):
        self.fetched.append(url)
        doc = self.docs.get(url)
        if isinstance(doc, Exception):
            raise doc
        if doc is None:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return json.dumps(doc).encode()

    def bytes(self, url):
        self.fetched.append(url)
        if url not in self.files:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.files[url]

    def asked(self, url):
        return self.fetched.count(url)


def npm_doc(name, versions):
    """[(version, published, publisher)] -> an npm packument (no e-mail addresses: the parts read are names)."""
    times = {"created": iso(min(t for _v, t, _p in versions)), **{v: iso(t) for v, t, _p in versions}}
    return {"name": name, "time": times,
            "versions": {v: {"name": name, "version": v, "_npmUser": {"name": who}} for v, _t, who in versions}}


def lived(first, count, publisher="ana", newest_by=None):
    """`count` versions a year apart from `first`, by `publisher` (the newest by `newest_by` when given)."""
    out = [(f"1.0.{n}", first + 365 * DAY * n / max(1, count - 1), publisher) for n in range(count)]
    if newest_by:
        out[-1] = out[-1][:2] + (newest_by,)
    return out


def crate_records(name, first, count, yanked=(), undated=0):
    """`count` index lines of crate `name`, a month apart from `first` (the first `undated` without `pubtime`)."""
    return [{"name": name, "vers": f"0.{n}.0", "cksum": "ab" * 32, "yanked": n in yanked, "deps": [],
             "pubtime": None if n < undated else iso(first + 30 * DAY * n)} for n in range(count)]


class FakeCrates:
    """The crates module as a registry scan asks it: the release's index line and .crate, each crate's index lines."""

    def __init__(self, release, data, records):
        self.release, self.data, self.records_of, self.asked = release, data, records, []

    def resolve(self, name, version, fetch):
        art = {"url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate", "container": "tgz",
               "artifact": "crate", "entry": {"vers": version, "pubtime": iso(self.release)},
               "filename": f"{name}-{version}.crate"}
        return repo.Resolution(version, [art])

    def verify(self, data, entry, name, version):
        return None

    def bytes(self, url, max_bytes):
        return self.data

    def records(self, name, fetch):
        self.asked.append(name)
        found = self.records_of.get(name)
        if isinstance(found, Exception):
            raise found
        if found is None:
            raise base.FetchError("HTTP 404 fetching the index file")
        return found


def djotls_crate(dep="roman", extra=None):
    files = {"Cargo.toml": f'[package]\nname = "djotls"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n'
                           f'{dep} = "0.2"\n', "src/lib.rs": "pub fn render() -> u8 { 1 }\n", **(extra or {})}
    return tarball(files, root="djotls-0.1.0/")


def scan_crate(records, env=ON, data=None):
    fake = FakeCrates(DJOTLS, data or djotls_crate(), records)
    with mock.patch.object(repo, "registry_module", return_value=fake), \
            mock.patch.object(repo, "module_fetch", return_value=fake), mock.patch.dict(os.environ, env):
        return repo.scan_package("crates", "djotls", "0.1.0"), fake


def npm_tarball(deps, **files):
    return tarball({"package.json": manifest(main="index.js", dependencies=deps), "index.js": "module.exports = 1;\n",
                    **files})


def scan_npm(reg, data, env=ON, name="x", version="1.0.0"):
    rv = (version, f"{NPM}{name}/-/{name}-{version}.tgz", "tgz", "npm", {"name": name, "version": version})
    with mock.patch.object(repo, "resolve_npm", return_value=rv), \
            mock.patch.object(repo, "http_bytes", return_value=data), \
            mock.patch.object(repo, "verify_digest", return_value=None), mock.patch.object(repo, "_fetch", reg.fetch), \
            mock.patch.dict(os.environ, env):
        return repo.scan_package("npm", name, version)


def wheel(requires, name="lit", version="1.0"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{name}/__init__.py", "VALUE = 1\n")
        z.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
                   + "".join(f"Requires-Dist: {r}\n" for r in requires) + "\nA description.\n")
        z.writestr(f"{name}-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\n")
        z.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return buf.getvalue()


def simple_doc(name, versions, yanked=()):
    """[(version, uploaded)] -> PyPI's Simple API (JSON) for `name`: an sdist of each version."""
    return {"name": name, "versions": [v for v, _t in versions],
            "files": [{"filename": f"{name}-{v}.tar.gz", "url": f"https://files.pythonhosted.org/x/{name}-{v}.tar.gz",
                       "hashes": {"sha256": "ab" * 32}, "upload-time": iso(t), "yanked": v in yanked}
                      for v, t in versions]}


def scan_wheel(reg, data, env=ON, uploaded=DJOTLS):
    url = "https://files.pythonhosted.org/packages/xx/lit-1.0-py3-none-any.whl"
    art = {"url": url, "container": "zip", "artifact": "wheel", "filename": url.rsplit("/", 1)[-1],
           "entry": {"digests": {"sha256": hashlib.sha256(data).hexdigest()}, "upload_time_iso_8601": iso(uploaded)}}
    with mock.patch.object(repo, "resolve_pypi", return_value=repo.Resolution("1.0", [art])), \
            mock.patch.object(repo, "_fetch", reg.fetch), mock.patch.object(repo, "http_bytes", return_value=data), \
            mock.patch.dict(os.environ, env):
        return repo.scan_package("pypi", "lit", "1.0")


class PartsTests(unittest.TestCase):
    def test_the_judgement(self):
        old = lh.History(ROMAN, False, 13, None)
        self.assertEqual(lh.established(old, DJOTLS), "first published 2015, 13 versions")
        self.assertEqual(lh.established(old._replace(publisher=True), DJOTLS),
                         "first published 2015, 13 versions, the newest by an account that published earlier ones")
        for why, history in (("a new publisher", old._replace(publisher=False)),
                             ("two versions", old._replace(versions=lh.MIN_VERSIONS - 1)),
                             ("a year to the day", old._replace(first=DJOTLS - lh.MIN_AGE)),
                             ("two weeks old", old._replace(first=DJOTLS - 14 * DAY)),
                             ("no history", None)):
            with self.subTest(why):
                self.assertIsNone(lh.established(history, DJOTLS))
        self.assertEqual(lh.established(lh.History(None, True, 3, None), DJOTLS),
                         "first published before its registry recorded publish times, 3 versions")

    def test_npm_history(self):
        doc = npm_doc("lodahs", lived(ROMAN, 4))
        self.assertEqual(lh.npm_history(doc), lh.History(ROMAN, False, 4, True))
        self.assertIs(lh.npm_history(npm_doc("lodahs", lived(ROMAN, 4, newest_by="mallory"))).publisher, False)
        doc["versions"]["1.0.3"] = {"maintainers": [{"name": "ana"}]}          # (no _npmUser: its maintainers)
        self.assertIs(lh.npm_history(doc).publisher, True)
        doc["versions"]["1.0.3"] = {}                                         # (who published it is not said)
        self.assertIs(lh.npm_history(doc).publisher, False)
        del doc["time"]["1.0.0"]                                               # (a version without a time is not one)
        self.assertEqual(lh.npm_history(doc).versions, 3)
        for bad in (None, [], {"time": {}}, {"versions": {}}, {"time": {}, "versions": {"1.0.0": {}}}):
            self.assertIsNone(lh.npm_history(bad))

    def test_pypi_history(self):
        doc = simple_doc("reqeusts", [("0.9", ROMAN), ("1.0", ROMAN + 400 * DAY), ("1.1", ROMAN + 800 * DAY)],
                         yanked=("1.1",))
        self.assertEqual(lh.pypi_history(doc), lh.History(ROMAN, False, 2, None))     # (a yanked file left out)
        for bad in (None, {"versions": ["1"]}, {"versions": ["1.0"], "files": [{"filename": "x-1.0.tar.gz"}]}):
            self.assertIsNone(lh.pypi_history(bad))

    def test_crates_history(self):
        self.assertEqual(lh.crates_history(crate_records("roman", ROMAN, 13)), lh.History(ROMAN, False, 13, None))
        self.assertEqual(lh.crates_history(crate_records("roman", ROMAN, 4, yanked=(3,))).versions, 3)
        older = lh.crates_history(crate_records("roman", ROMAN, 4, undated=1))
        self.assertEqual((older.first, older.undated), (ROMAN + 30 * DAY, True))
        self.assertIsNone(lh.crates_history(crate_records("roman", ROMAN, 1, yanked=(0,))))

    def test_the_cache_reads_each_once(self):
        cache, reads = lh.Cache(), []

        def read():
            reads.append(1)
            raise base.FetchError("HTTP 503")
        self.assertIsNone(cache.get(("npm", "x"), read))                    # (one that failed is kept as None)
        self.assertIsNone(cache.get(("npm", "x"), read))
        self.assertEqual(len(reads), 1)
        cache.seconds = 0                                                    # (kept no longer: read again)
        cache.get(("npm", "x"), read)
        self.assertEqual(len(reads), 2)
        small = lh.Cache(size=2)
        for n in "abc":
            small.get(("npm", n), lambda: None)
        self.assertEqual(list(small.kept), [("npm", "b"), ("npm", "c")])


class RegistryCase(unittest.TestCase):
    def setUp(self):
        lh.RUN.clear()
        self.addCleanup(lh.RUN.clear)


class CratesTests(RegistryCase):
    def test_djotls_depending_on_roman_is_not_warn(self):
        roman = crate_records("roman", ROMAN, 13)
        before, fake = scan_crate({"roman": roman}, env={lh.OFF_ENV: "1"})
        self.assertEqual(before["verdict"], "WARN", before["verdictReason"])
        self.assertEqual(typos(before), [("MAJOR", 'Depends on "roman", one change from "rowan" (a character changed), '
                                                   'one of the 5,000 most-downloaded crates.')])
        self.assertEqual(fake.asked, [])                                     # (off: nothing read)
        after, fake = scan_crate({"roman": roman})
        self.assertEqual(after["verdict"], "OK", after["verdictReason"])
        self.assertEqual(typos(after), [("INFO", 'Depends on "roman", one change from "rowan" (a character changed), '
                                                 'one of the 5,000 most-downloaded crates; it is an established '
                                                 'package: first published 2015, 13 versions.')])
        self.assertEqual(after["artifacts"][0]["verdict"], "OK")            # (the file's verdict too)
        self.assertEqual(fake.asked, ["roman"])                              # one index file, the dependency's
        again, fake = scan_crate({"roman": roman})                           # (the run's cache: not read again)
        self.assertEqual((again["verdict"], fake.asked), ("OK", []))

    def test_a_two_week_old_lookalike_stays_major(self):
        res, fake = scan_crate({"roman": crate_records("roman", DJOTLS - 14 * DAY, 3)})
        self.assertEqual((res["verdict"], [s for s, _m in typos(res)], fake.asked), ("WARN", ["MAJOR"], ["roman"]))
        res, _fake = scan_crate({"roman": crate_records("roman", ROMAN, 2)})   # (old, but two versions)
        self.assertEqual([s for s, _m in typos(res)], ["MAJOR"])

    def test_a_history_that_does_not_come_back_stays_major(self):
        for why, found in (("an error", base.FetchError("HTTP 503 fetching the index file")), ("not there", None),
                           ("an answer it cannot read", ValueError("not JSON lines"))):
            with self.subTest(why):
                lh.RUN.clear()
                res, fake = scan_crate({"roman": found} if found is not None else {})
                self.assertEqual((res["verdict"], [s for s, _m in typos(res)], fake.asked),
                                 ("WARN", ["MAJOR"], ["roman"]))

    def test_nothing_flagged_nothing_read(self):
        res, fake = scan_crate({}, data=djotls_crate(dep="serde"))
        self.assertEqual((res["verdict"], typos(res), fake.asked), ("OK", [], []))

    def test_off_and_offline_read_nothing(self):
        for env in ({lh.OFF_ENV: "1"}, {lh.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": "1"}):
            with self.subTest(env=env):
                res, fake = scan_crate({"roman": crate_records("roman", ROMAN, 13)}, env=env)
                self.assertEqual((res["verdict"], fake.asked), ("WARN", []))


class NpmTests(RegistryCase):
    def test_an_established_dependency_is_info(self):
        reg = Registry({NPM + "lodahs": npm_doc("lodahs", lived(ROMAN, 5))})
        res = scan_npm(reg, npm_tarball({"lodahs": "^1.0.0"}))
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(typos(res), [("INFO", 'Depends on "lodahs", one change from "lodash" (two characters '
                                               'swapped), one of the 5,000 most-downloaded npm packages; it is an '
                                               'established package: first published 2015, 5 versions, the newest by '
                                               'an account that published earlier ones.')])
        self.assertEqual(reg.asked(NPM + "lodahs"), 1)

    def test_a_new_publisher_of_its_newest_version_stays_major(self):
        reg = Registry({NPM + "lodahs": npm_doc("lodahs", lived(ROMAN, 5, newest_by="mallory"))})
        res = scan_npm(reg, npm_tarball({"lodahs": "^1.0.0"}))
        self.assertEqual((res["verdict"], [s for s, _m in typos(res)]), ("WARN", ["MAJOR"]))
        self.assertEqual(typos(res)[0][1], 'Depends on "lodahs", one change from "lodash" (two characters swapped), '
                                           'one of the 5,000 most-downloaded npm packages.')         # (unchanged)

    def test_a_young_one_and_a_failed_read_stay_major(self):
        for why, doc in (("two weeks old", npm_doc("lodahs", lived(NOW - 14 * DAY, 3))),
                         ("the registry did not answer", repo.FetchError("HTTP 503 fetching the packument")),
                         ("over the budget", repo.FetchError("response exceeds 16MB budget"))):
            with self.subTest(why):
                lh.RUN.clear()
                res = scan_npm(Registry({NPM + "lodahs": doc}), npm_tarball({"lodahs": "^1.0.0"}))
                self.assertEqual((res["verdict"], [s for s, _m in typos(res)]), ("WARN", ["MAJOR"]))

    def test_one_read_for_each_dependency_and_the_first_five_alone(self):
        names = ["axois", "chalkk", "expresss", "lodahs", "momment", "reacct"]           # (sorted)
        reg = Registry({NPM + n: npm_doc(n, lived(ROMAN, 3)) for n in names})
        res = scan_npm(reg, npm_tarball({n: "1" for n in names}))
        sevs = {m.split('"')[1]: s for s, m in typos(res)}
        self.assertEqual(sevs, {**{n: "INFO" for n in names[:lh.MAX_LOOKUPS]}, "reacct": "MAJOR"})
        self.assertEqual(sorted(u for u in reg.fetched if u.startswith(NPM)),
                         sorted(NPM + n for n in names[:lh.MAX_LOOKUPS]))
        res = scan_npm(reg, npm_tarball({n: "1" for n in names}))           # (the run's cache)
        self.assertEqual(sum(reg.asked(NPM + n) for n in names), lh.MAX_LOOKUPS)

    def test_the_release_s_own_name_and_a_node_builtin_are_not_read(self):
        reg = Registry()
        res = scan_npm(reg, tarball({"package.json": manifest(name="lodahs", dependencies={"child-process": "1"})}),
                       name="lodahs")
        self.assertEqual([s for s, _m in typos(res)], ["MAJOR", "MAJOR"])
        self.assertEqual(reg.fetched, [])

    def test_an_info_lookalike_is_not_a_new_indicator(self):
        # the release before had the blob and no look-alike: an established one is not asked about; a young one is
        # (SC-NEW-INDICATOR, as before)
        env = {**ON, prior.OFF_ENV: ""}
        old = npm_tarball({}, **{"index.js": f"module.exports = '{BLOB}';\n"})
        new = npm_tarball({"lodahs": "^1"}, **{"index.js": f"module.exports = '{BLOB}';\n"})
        times = {"created": iso(NOW - 40 * DAY), "1.0.0": iso(NOW - 40 * DAY), "1.0.1": iso(NOW - DAY)}
        packument = {"name": "files-kit", "time": times, "versions": {
            v: {"name": "files-kit", "version": v, "dist": {"tarball": f"{NPM}files-kit/-/files-kit-{v}.tgz",
                                                            "integrity": "sha512-" + base64.b64encode(
                                                                hashlib.sha512(d).digest()).decode()}}
            for v, d in (("1.0.0", old), ("1.0.1", new))}}
        for dep, verdict, new_rules in ((lived(ROMAN, 4), "WARN", []), (lived(NOW - 14 * DAY, 3), "SUSPICIOUS",
                                                                         ["SC-TYPOSQUAT"])):
            with self.subTest(verdict=verdict):
                lh.RUN.clear()
                reg = Registry({NPM + "files-kit": packument, NPM + "lodahs": npm_doc("lodahs", dep)})
                reg.files[f"{NPM}files-kit/-/files-kit-1.0.0.tgz"] = old
                entry = packument["versions"]["1.0.1"]
                rv = ("1.0.1", entry["dist"]["tarball"], "tgz", "npm", {**entry, "dependencies": {"lodahs": "^1"}})
                with mock.patch.object(repo, "resolve_npm", return_value=rv), \
                        mock.patch.object(repo, "_fetch", reg.fetch), \
                        mock.patch.object(repo, "http_bytes", lambda url: new if url.endswith("1.0.1.tgz")
                                          else reg.bytes(url)), mock.patch.dict(os.environ, env):
                    res = repo.scan_package("npm", "files-kit", "1.0.1")
                self.assertEqual(res["verdict"], verdict, res["verdictReason"])
                self.assertEqual(res["priorRelease"]["newRules"], new_rules)


class PypiTests(RegistryCase):
    def test_an_established_requirement_is_info(self):
        reg = Registry({"https://pypi.org/simple/reqeusts/": simple_doc(
            "reqeusts", [("0.9", ROMAN), ("1.0", ROMAN + 100 * DAY), ("2.0", DJOTLS - 30 * DAY)])})
        res = scan_wheel(reg, wheel(["reqeusts>=1"]))
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(typos(res), [("INFO", 'Depends on "reqeusts", one change from "requests" (two characters '
                                               'swapped), one of the 5,000 most-downloaded PyPI projects; it is an '
                                               'established package: first published 2015, 3 versions.')])
        self.assertEqual(reg.asked("https://pypi.org/simple/reqeusts/"), 1)

    def test_judged_by_the_release_s_upload_time(self):
        # the release uploaded six months after the requirement's first version: not a year
        reg = Registry({"https://pypi.org/simple/reqeusts/": simple_doc(
            "reqeusts", [("0.9", ROMAN), ("1.0", ROMAN + DAY), ("2.0", ROMAN + 2 * DAY)])})
        res = scan_wheel(reg, wheel(["reqeusts>=1"]), uploaded=ROMAN + 180 * DAY)
        self.assertEqual((res["verdict"], [s for s, _m in typos(res)]), ("WARN", ["MAJOR"]))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class GuardTests(RegistryCase):
    """The guard reads a fresh scan's look-alike dependencies' histories over its fetcher (npm, PyPI) before it applies
    the verdict; what it keeps in its verdict cache is the verdict so made."""

    class Fetcher:
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

    def npm_check(self, dep_doc, cache):
        data = npm_tarball({"lodahs": "^1"})
        url = f"{NPM}x/-/x-1.0.0.tgz"
        answers = {url: data, **({NPM + "lodahs": json.dumps(dep_doc).encode()} if dep_doc else {})}
        fetcher = self.Fetcher(answers, NOW - 3 * DAY)
        ctx = context(tool="npm")
        ctx.scanner.close()
        ctx.scanner = guard.Scanner(cache, jobs=1, isolate=False)
        self.addCleanup(ctx.scanner.close)
        pkg = {"name": "x", "version": "1.0.0", "tarball": url, "registry": NPM, "lock_digest": None,
               "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}
        with mock.patch.dict(os.environ, ON):
            return guard.check_npm_package(ctx, fetcher, pkg), fetcher

    def test_npm(self):
        cache = guard.VerdictCache(None)
        check, fetcher = self.npm_check(npm_doc("lodahs", lived(ROMAN, 4)), cache)
        self.assertEqual((check.verdict, check.reason, check.indicators), ("OK", "no supply-chain indicators", []))
        self.assertEqual(fetcher.asked.count(NPM + "lodahs"), 1)
        hit = next(iter(cache.data.values()))
        self.assertEqual((hit["verdict"], "lookalikes" in hit, "rules" in hit), ("OK", False, False))
        check, fetcher = self.npm_check(None, cache)                          # (known by its digest: nothing read)
        self.assertEqual((check.verdict, fetcher.asked.count(NPM + "lodahs")), ("OK", 0))
        lh.RUN.clear()
        check, fetcher = self.npm_check(npm_doc("lodahs", lived(ROMAN, 4, newest_by="mallory")),
                                        guard.VerdictCache(None))
        self.assertEqual((check.verdict, check.reason), ("WARN", "1 weaker supply-chain indicator to review"))
        self.assertTrue(check.indicators[0].startswith('SC-TYPOSQUAT (MAJOR) package.json: Depends on "lodahs"'))

    def test_the_hit_settled(self):
        # another weaker indicator stays: WARN, one fewer counted; the rule kept by a finding that stays
        mine = {"rule": "SC-TYPOSQUAT", "sev": "MAJOR", "name": "n", "file": "package.json", "line": 3,
                "msg": 'Depends on "lodahs"', "indicator": "SC-TYPOSQUAT (MAJOR) package.json: lodahs",
                "dependency": "lodahs"}
        own = dict(mine, line=2, msg='The package is named "lodahs"',
                   indicator="SC-TYPOSQUAT (MAJOR) package.json: own")
        del own["dependency"]
        hit = {"verdict": "WARN", "reason": "3 weaker supply-chain indicators to review",
               "indicators": [mine["indicator"], own["indicator"], "SC-B64 (MAJOR) index.js: b"],
               "rules": {"SC-TYPOSQUAT": {k: mine[k] for k in ("rule", "sev", "name", "file", "line", "msg")},
                         "SC-B64": {"rule": "SC-B64"}},
               "lookalikes": {"weak": 3, "findings": [mine, own]}}
        with mock.patch.dict(os.environ, ON), mock.patch.object(lh, "fetch_history",
                                                                return_value=lh.History(ROMAN, False, 4, True)) as read:
            out = lh.guard_settle("npm", hit, NOW, lambda url, accept: None)
            self.assertEqual(read.call_count, 1)
            self.assertEqual((out["verdict"], out["reason"]), ("WARN", "2 weaker supply-chain indicators to review"))
            self.assertEqual(out["indicators"], [own["indicator"], "SC-B64 (MAJOR) index.js: b"])
            self.assertEqual(out["rules"]["SC-TYPOSQUAT"]["line"], 2)
            self.assertNotIn("lookalikes", out)
            self.assertEqual(lh.guard_settle("npm", hit, NOW, None), {k: v for k, v in hit.items()
                                                                       if k != "lookalikes"})   # (not due: unread)
            self.assertEqual(read.call_count, 1)

    def test_pypi(self):
        data = wheel(["reqeusts>=1"])
        url = "https://files.pythonhosted.org/packages/xx/lit-1.0-py3-none-any.whl"
        doc = simple_doc("reqeusts", [("0.9", ROMAN), ("1.0", ROMAN + DAY), ("2.0", ROMAN + 2 * DAY)])
        fetcher = self.Fetcher({url: data, "https://pypi.org/simple/reqeusts/": json.dumps(doc).encode()},
                               NOW - 3 * DAY)
        ctx = context(tool="pip")
        ctx.scanner.close()
        ctx.scanner = guard.Scanner(guard.VerdictCache(None), jobs=1, isolate=False)
        self.addCleanup(ctx.scanner.close)
        f = {"url": url, "hash": "sha256:" + hashlib.sha256(data).hexdigest(), "upload-time": iso(NOW - 3 * DAY),
             "filename": url.rsplit("/", 1)[-1]}
        with mock.patch.dict(os.environ, ON):
            check = guard.check_file(ctx, fetcher, "lit", "1.0", f)
        self.assertEqual((check.verdict, check.indicators), ("OK", []))
        self.assertEqual(fetcher.asked.count("https://pypi.org/simple/reqeusts/"), 1)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class GuardCargoTests(CrateCase):
    """check_crate reads a WARN crate's look-alike dependency's history from crates.io's index (the crates module's
    fetch, mocked here: the parsing is CratesTests'), for a crate of the public index, and not offline."""

    def setUp(self):
        super().setUp()
        lh.RUN.clear()
        self.addCleanup(lh.RUN.clear)

    def check_djotls(self, offline=False, default=True):
        self.reg.add("djotls", "0.1.0", deps=[("roman", "0.2")], published=cs.NOW - 3 * DAY)
        scanner = guard.Scanner(guard.VerdictCache(None), jobs=1, isolate=False)
        self.addCleanup(scanner.close)
        ctx = self.context(scanner=scanner)
        if offline:
            self.put_in_cargo_cache("djotls", "0.1.0")
        f = self.fetcher()
        reg = guard._offline_registry(self.reg.url) if offline else self.registry(f)
        reg.default = default
        with mock.patch.dict(os.environ, ON), mock.patch.object(
                lh, "fetch_history", return_value=lh.crates_history(crate_records("roman", ROMAN, 13))) as read:
            check = guard.check_crate(ctx, f, reg, self.pkg("djotls", "0.1.0"), self.home, offline)
        return check, read

    def test_online_the_history_is_read(self):
        check, read = self.check_djotls()
        self.assertEqual((check.verdict, check.indicators), ("OK", []))
        self.assertEqual(read.call_args.args[:2], ("crates", "roman"))

    def test_offline_or_another_registry_reads_nothing(self):
        for kw in ({"offline": True}, {"default": False}):
            with self.subTest(**kw):
                check, read = self.check_djotls(**kw)
                self.assertEqual((check.verdict, read.call_count), ("WARN", 0))
                self.assertTrue(check.indicators[0].startswith('SC-TYPOSQUAT (MAJOR) Cargo.toml: Depends on "roman"'),
                                check.indicators)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class BenchTests(RegistryCase):
    def test_lookalikes_reads_the_warn_releases_with_a_lookalike(self):
        # `bench.py lookalikes`: what John runs on the popular sets (`run` scans the files alone)
        bench = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "bench.py"), "bench_for_lookalikes")
        with tempfile.TemporaryDirectory() as tmp:
            rows, run = [], []
            for rid, deps, weak in (("benign:npm:x@1.0.0", {"lodahs": "1"}, ["SC-TYPOSQUAT"]),
                                    ("benign:npm:y@1.0.0", {"axois": "1"}, ["SC-TYPOSQUAT"]),
                                    ("benign:npm:z@1.0.0", {}, ["SC-B64"])):
                path = os.path.join(tmp, rid.replace(":", "_") + ".tgz")
                with open(path, "wb") as f:
                    f.write(npm_tarball(deps))
                rows.append({"id": rid, "cat": "benign", "artifact_path": path, "container": "tgz", "kind": "npm"})
                run.append({"id": rid, "cat": "benign", "verdict": "WARN", "weak": weak})
            paths = [os.path.join(tmp, n) for n in ("run.jsonl", "m.jsonl", "out.jsonl")]       # RUN MANIFEST OUT
            for path, lines in zip(paths, (run, rows)):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in lines))
            reg = Registry({NPM + "lodahs": npm_doc("lodahs", lived(ROMAN, 4)),
                            NPM + "axois": npm_doc("axois", lived(NOW - 14 * DAY, 3))})
            out = io.StringIO()
            with mock.patch.object(repo, "_fetch", reg.fetch), mock.patch.dict(os.environ, ON), \
                    contextlib.redirect_stdout(out):
                self.assertEqual(bench.main(["lookalikes", *paths]), 0)
            lines = bench.read_jsonl(paths[2])
        self.assertEqual([x["id"] for x in lines], ["benign:npm:x@1.0.0", "benign:npm:y@1.0.0"])
        self.assertEqual(lines[0]["lookalikes"], {"flagged": ["lodahs"], "verdict": "OK", "established": {
            "lodahs": "first published 2015, 4 versions, the newest by an account that published earlier ones"}})
        self.assertEqual(lines[1]["lookalikes"], {"flagged": ["axois"], "established": {}, "verdict": "WARN"})
        self.assertIn("benign WARN releases with a look-alike: OK with the established ones INFO 1, each kept MAJOR 1",
                      out.getvalue())


if __name__ == "__main__":
    unittest.main()
