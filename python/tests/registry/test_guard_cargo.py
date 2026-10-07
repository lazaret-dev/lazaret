"""lazaret guard cargo (0.1.9, R-3): the crates a cargo command will fetch are read from Cargo.lock, checked and scanned before cargo
fetches or builds anything.

Four kinds of test. The check of one crate and of a lockfile's crates, in this process, against a fake crates.io registry
(tests/registry/_cargo_support.py) with a stand-in scanner. The command, run as `python -m lazaret.registry.guard cargo …`, with a
fake `cargo` that does exactly what each case needs (write this Cargo.lock, unpack that crate), so the exit codes, the files put
back and the report are known. `cargo install`, the same way. And the real cargo, against the fake registry through cargo's own
source replacement, where cargo is installed (skipped where it is not).

What the scan finds in a crate today is what it finds in any archive (JavaScript and Python files, install hooks, binaries, the
structure of the archive); the Rust rules of the engine read `.rs` files from the 0.1.9 wiring on."""

import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from lazaret.registry import cargosrc, guard, pmsettings, repo
from tests.registry import _cargo_support as cs
from tests.registry import _guard_support as gs
from tests.registry.test_guard import options

HEX = "ab" * 32
OLD_LOCK = "version = 4\n"


class CrateScanner:
    """Stands in for guard.Scanner: a crate with a JavaScript file in it is SUSPICIOUS, any other is OK. `known` is a verdict cache."""

    def __init__(self, known=None):
        self.known = dict(known or {})
        self.calls = []
        self.remembered = []

    def cached(self, key):
        return self.known.get(key)

    def remember(self, key, hit, published):
        self.remembered.append((key, hit["verdict"], published))

    def scan(self, data, container, kind):
        self.calls.append((container, kind))
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
        if any(n.endswith(".js") for n in names):
            return {"verdict": "SUSPICIOUS", "reason": "1 strong supply-chain indicator", "indicators": ["SC-USE-RISK x.js"]}
        return {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": []}

    def close(self):
        pass


def lock_of(reg, *crates):
    """The Cargo.lock of a project `app` that needs the given [(name, version)] of the registry."""
    return cs.lock_text([("app", "0.1.0", None, [n for n, _ in crates])]
                        + [(n, v, reg.checksum(n, v), []) for n, v in crates])


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-guard-cargo-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class CrateCase(TmpCase):
    """One crate or a lockfile's crates, checked in this process."""

    def setUp(self):
        super().setUp()
        self.reg = cs.CratesRegistry()
        self.sums = cs.default_crates(self.reg)
        self.addCleanup(self.reg.close)
        self.home = os.path.join(self.tmp, "cargo-home")
        self.out = io.StringIO()
        self.fetchers = []

    def context(self, scanner=None, **kw):
        ctx = guard.Context(options(tool="cargo", **kw), out=self.out)
        ctx.scanner = scanner or CrateScanner()
        self.addCleanup(ctx.close)
        return ctx

    def fetcher(self):
        f = guard.Fetcher({guard.netloc(self.reg.url)})
        self.addCleanup(f.close)
        return f

    def registry(self, fetcher, reg=None):
        return guard.CrateRegistry(fetcher, (reg or self.reg).url)

    def pkg(self, name, version="1.0.0", checksum="registry", source=cs.CRATES_IO):
        if checksum == "registry":
            checksum = self.reg.checksum(name, version)
        return cargosrc.Package(name, version, source, checksum)

    def check(self, ctx, pkg, **kw):
        f = self.fetcher()
        return guard.check_crate(ctx, f, self.registry(f), pkg, self.home, kw.pop("offline", False), **kw)

    def put_in_cargo_cache(self, name, version):
        folder = os.path.join(self.home, "registry", "cache", "index.crates.io-0000000000000000")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{name}-{version}.crate"), "wb") as f:
            f.write(self.reg.versions[name][version]["data"])


class CheckCrateTests(CrateCase):
    def test_a_clean_crate_is_fetched_where_the_registry_says_and_scanned_as_a_crate(self):
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf"))
        self.assertEqual((check.eco, check.name, check.version, check.verdict, check.blocked), ("crates", "leaf", "1.0.0", "OK", []))
        self.assertEqual(check.digest, "sha256:" + self.sums["leaf"])
        self.assertEqual(ctx.scanner.calls, [("tgz", "crate")])
        self.assertEqual(self.reg.paths("/dl/"), ["/dl/leaf/leaf-1.0.0.crate"])
        self.assertEqual([r[1] for r in ctx.scanner.remembered], ["OK"])

    def test_a_download_url_without_markers_is_the_name_and_version_and_download(self):
        self.reg.close()
        self.reg = cs.CratesRegistry(plain_dl=True)
        cs.default_crates(self.reg)
        self.addCleanup(self.reg.close)
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf"))
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertEqual(self.reg.paths("/dl/"), ["/dl/leaf/1.0.0/download"])

    def test_a_hostile_crate_is_blocked(self):
        ctx = self.context()
        check = self.check(ctx, self.pkg("evil"))
        self.assertEqual(check.verdict, "SUSPICIOUS")
        self.assertEqual(check.blocked, ["SUSPICIOUS: 1 strong supply-chain indicator"])

    def test_trust_lets_it_through_and_says_so(self):
        ctx = self.context(trust=["evil"])
        check = self.check(ctx, self.pkg("evil"))
        self.assertEqual(check.blocked, [])
        self.assertTrue(check.trusted)

    def test_trust_reads_a_crate_name_as_the_registry_does(self):
        ctx = self.context(trust=["foo-bar"])                           # (crates.io holds one of foo-bar and foo_bar)
        self.reg.add("foo_bar", "0.3.0", files={"web/x.js": cs.EXFIL_JS})
        check = self.check(ctx, self.pkg("foo_bar", "0.3.0"))
        self.assertEqual((check.verdict, check.blocked, check.trusted), ("SUSPICIOUS", [], True))

    def test_bytes_that_are_not_the_lockfiles_checksum_are_blocked_before_they_are_scanned(self):
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf", checksum=HEX))
        self.assertEqual(check.blocked, ["its sha256 is not the lockfile's"])
        self.assertEqual(ctx.scanner.calls, [])
        self.assertIsNone(check.verdict)

    def test_with_no_checksum_in_the_lock_the_index_gives_one(self):
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf", checksum=None))
        self.assertEqual((check.verdict, check.blocked, check.digest), ("OK", [], "sha256:" + self.sums["leaf"]))
        self.assertEqual(self.reg.paths("/le/af/"), ["/le/af/leaf"] * 1)           # (the index is read once, for both the checksum and the time)

    def test_bytes_that_are_not_the_indexs_checksum_are_blocked(self):
        self.reg.versions["leaf"]["1.0.0"]["cksum"] = HEX
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf", checksum=None))
        self.assertEqual(check.blocked, ["its sha256 is not the index's"])

    def test_no_checksum_anywhere_is_a_crate_that_could_not_be_checked(self):
        self.reg.versions["leaf"]["1.0.0"]["cksum"] = "short"
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf", checksum=None))
        self.assertEqual(len(check.blocked), 1)
        self.assertIn("could not be checked: neither the lockfile nor the registry's index gives a checksum", check.blocked[0])
        check = self.check(self.context(), self.pkg("leaf", "9.9.9", checksum=None))                  # (a version the index does not list)
        self.assertIn("neither the lockfile nor", check.blocked[0])

    def test_a_crate_the_registry_does_not_have_could_not_be_checked(self):
        check = self.check(self.context(), self.pkg("leaf", "1.0.0", checksum=HEX).__class__("nosuch", "1.0.0", cs.CRATES_IO, HEX))
        self.assertEqual(len(check.blocked), 1)
        self.assertIn("could not be checked: HTTP 404", check.blocked[0])

    def test_a_name_or_version_that_cannot_be_a_url_is_never_fetched(self):
        for name, version in (("../etc", "1.0.0"), ("leaf", "1.0.0/../../x"), ("a b", "1.0.0"), ("leaf", "latest")):
            with self.subTest(name=name, version=version):
                before = len(self.reg.requests)
                check = self.check(self.context(), cargosrc.Package(name, version, cs.CRATES_IO, HEX))
                self.assertIn("could not be checked: not a crate name and version the guard fetches", check.blocked[0])
                self.assertEqual(len(self.reg.requests), before + 1)                    # (config.json only)

    def test_a_registry_that_has_no_config_blocks_what_it_would_have_given(self):
        self.reg.fail["/config.json"] = (404, b"not found\n")
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertIn("could not be checked: HTTP 404", check.blocked[0])
        self.assertEqual(self.reg.paths("/dl/"), [])

    def test_a_config_with_no_download_url_is_not_used(self):
        for body in (b"{}", b'{"dl": 5}', b'{"dl": ""}', b"[]", b'{"dl": "' + b"x" * 513 + b'"}'):
            with self.subTest(body[:20]):
                self.reg.fail["/config.json"] = (200, body)
                check = self.check(self.context(), self.pkg("leaf"))
                self.assertIn("could not be checked", check.blocked[0])
                self.assertEqual(self.reg.paths("/dl/"), [])
        self.reg.fail["/config.json"] = (200, json.dumps({"dl": "http://127.0.0.1:1/x/{crate}/{version}", "api": ""}).encode())
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertIn("could not be checked", check.blocked[0])                          # (the download host is allowed; nothing listens there)

    def test_a_crate_cargo_already_holds_is_not_downloaded(self):
        self.put_in_cargo_cache("leaf", "1.0.0")
        ctx = self.context()
        check = self.check(ctx, self.pkg("leaf"))
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertEqual(self.reg.paths("/dl/"), [])

    def test_a_cached_crate_with_other_bytes_is_not_used(self):
        folder = os.path.join(self.home, "registry", "cache", "idx")
        os.makedirs(folder)
        with open(os.path.join(folder, "leaf-1.0.0.crate"), "wb") as f:
            f.write(self.reg.versions["leaf"]["1.0.0"]["data"] + b"x")
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertEqual((check.verdict, self.reg.paths("/dl/")), ("OK", ["/dl/leaf/leaf-1.0.0.crate"]))

    def test_offline_only_cargos_cache_is_read(self):
        ctx = self.context()
        f = self.fetcher()
        registry = guard._offline_registry(self.reg.url)
        check = guard.check_crate(ctx, f, registry, self.pkg("leaf"), self.home, True)
        self.assertEqual(check.blocked, ["could not be checked: offline, and cargo's cache does not hold it"])
        self.assertEqual(self.reg.requests, [])
        self.put_in_cargo_cache("leaf", "1.0.0")
        ctx = self.context()
        check = guard.check_crate(ctx, f, registry, self.pkg("leaf"), self.home, True)
        self.assertEqual((check.verdict, check.blocked, check.age), ("OK", [], None))        # (no time asked for either)
        self.assertEqual(self.reg.requests, [])

    def test_offline_an_entry_without_a_checksum_asks_the_index_nothing(self):
        # (the lockfile's checksum, or nothing: the index is not fetched when offline: the Go/Rust review's CG-9, GR-3)
        ctx = self.context()
        registry = guard._offline_registry(self.reg.url)
        pkg = self.pkg("leaf")._replace(checksum=None)
        check = guard.check_crate(ctx, self.fetcher(), registry, pkg, self.home, True)
        self.assertEqual(check.blocked, ["could not be checked: offline, and the lockfile gives no checksum to check it against"])
        self.assertEqual(self.reg.requests, [])

    def test_a_verdict_that_is_known_by_checksum_is_not_fetched_again(self):
        key = guard.VerdictCache.key("crates", "leaf", "1.0.0", "sha256:" + self.sums["leaf"])
        known = {key: {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": [], "published": "2020-01-01T00:00:00Z"}}
        ctx = self.context(scanner=CrateScanner(known))
        check = self.check(ctx, self.pkg("leaf"))
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        self.assertEqual(self.reg.requests, ["/config.json"])                           # (no index, no download: the cache has the time too)
        self.assertEqual(ctx.scanner.calls, [])

    def test_a_known_verdict_that_blocks_blocks_without_a_download(self):
        key = guard.VerdictCache.key("crates", "evil", "1.0.0", "sha256:" + self.sums["evil"])
        known = {key: {"verdict": "SUSPICIOUS", "reason": "bad", "indicators": ["SC-X"], "published": None}}
        ctx = self.context(scanner=CrateScanner(known))
        check = self.check(ctx, self.pkg("evil"))
        self.assertEqual(check.blocked, ["SUSPICIOUS: bad"])
        self.assertEqual(self.reg.paths("/dl/"), [])

    def test_keeping_the_bytes_fetches_them_even_when_the_verdict_is_known(self):
        key = guard.VerdictCache.key("crates", "leaf", "1.0.0", "sha256:" + self.sums["leaf"])
        known = {key: {"verdict": "OK", "reason": "ok", "indicators": [], "published": "2020-01-01T00:00:00Z"}}
        ctx = self.context(scanner=CrateScanner(known))
        kept = {}
        self.check(ctx, self.pkg("leaf"), keep=kept)
        self.assertEqual(kept, {("leaf", "1.0.0"): self.reg.versions["leaf"]["1.0.0"]["data"]})
        self.assertEqual(ctx.scanner.calls, [])


class AgeTests(CrateCase):
    def test_a_release_younger_than_min_age_is_blocked_by_the_indexs_pubtime(self):
        ctx = self.context()
        check = self.check(ctx, self.pkg("onlynew"))
        self.assertEqual(len(check.blocked), 1)
        self.assertRegex(check.blocked[0], r"^published 1 hour ago, under --min-age 2 days \(--allow-new onlynew lets it through\)$")
        self.assertEqual(check.verdict, "OK")                                             # (and it was scanned)
        self.assertEqual(self.reg.paths("/api/"), [])

    def test_a_release_whose_publish_time_is_not_known_is_said_and_blocked_under_block_warn(self):
        # (a mirror whose index has no pubtime, and no API to ask: it used to pass with nothing said: CG-4)
        reg = cs.CratesRegistry(pubtimes=False, api=False)
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        ctx = self.context()
        check = self.check(ctx, self.pkg("onlynew"))
        self.assertEqual((check.blocked, check.age), ([], None))
        self.assertEqual(ctx.age_unknown, ["onlynew@1.0.0"])
        guard.finish(ctx, installed=True, code=0)
        self.assertIn("the publish time of 1 release is not known, so --min-age could not hold it: onlynew@1.0.0", self.out.getvalue())
        ctx = self.context(block_warn=True)
        check = self.check(ctx, self.pkg("onlynew"))
        self.assertEqual(check.blocked, ["its publish time is not known, so --min-age cannot hold it (--block-warn)"])
        ctx = self.context(allow_new=["onlynew"], block_warn=True)
        self.assertEqual((self.check(ctx, self.pkg("onlynew")).blocked, ctx.age_unknown), ([], []))

    def test_allow_new_lets_it_through_and_says_so(self):
        ctx = self.context(allow_new=["onlynew"])
        check = self.check(ctx, self.pkg("onlynew"))
        self.assertEqual(check.blocked, [])
        self.assertEqual(check.notes, ["published 1 hour ago; let through by --allow-new"])

    def test_an_old_release_is_not_held_back(self):
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertEqual(check.blocked, [])
        self.assertGreater(check.age, 29 * 86400)

    def test_min_age_zero_asks_for_no_time_at_all(self):
        ctx = self.context(min_age=0)
        check = self.check(ctx, self.pkg("onlynew"))
        self.assertEqual((check.blocked, check.age), ([], None))
        self.assertEqual(self.reg.paths("/on/ly/"), [])                                  # (no index file either: the lock has the checksum)

    def test_the_time_of_a_crate_checked_before_is_remembered_with_its_verdict(self):
        ctx = self.context()
        self.check(ctx, self.pkg("leaf"))
        ((key, verdict, published),) = ctx.scanner.remembered
        self.assertEqual(verdict, "OK")
        self.assertEqual(published, guard.parse_time(cs.pubtime(cs.OLD)))

    def test_a_cached_time_is_the_one_used(self):
        key = guard.VerdictCache.key("crates", "leaf", "1.0.0", "sha256:" + self.sums["leaf"])
        fresh = cs.pubtime(cs.FRESH)
        known = {key: {"verdict": "OK", "reason": "ok", "indicators": [], "published": fresh}}
        check = self.check(self.context(scanner=CrateScanner(known)), self.pkg("leaf"))
        self.assertIn("published", check.blocked[0])

    def test_with_no_pubtime_crates_io_s_own_api_says_when(self):
        reg = cs.CratesRegistry(pubtimes=False)
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        with mock.patch.object(cargosrc, "DEFAULT_INDEX", reg.url), mock.patch.object(guard, "CRATES_API", reg.url + "api/v1/crates/"), \
                mock.patch.object(guard, "CRATES_API_INTERVAL", 0):
            check = self.check(self.context(), self.pkg("onlynew"))
            self.assertIn("published 1 hour ago, under --min-age 2 days", check.blocked[0])
            self.assertEqual(reg.paths("/api/"), ["/api/v1/crates/onlynew/1.0.0"])
            old = self.check(self.context(), self.pkg("leaf"))
            self.assertEqual(old.blocked, [])

    def test_the_api_is_asked_one_crate_at_a_time_a_second_apart(self):
        reg = cs.CratesRegistry(pubtimes=False)
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        pauses = []
        with mock.patch.object(cargosrc, "DEFAULT_INDEX", reg.url), mock.patch.object(guard, "CRATES_API", reg.url + "api/v1/crates/"), \
                mock.patch.object(guard.time, "sleep", pauses.append):
            self.check(self.context(), self.pkg("leaf"))
            self.check(self.context(), self.pkg("good"))
        self.assertEqual(pauses, [guard.CRATES_API_INTERVAL, guard.CRATES_API_INTERVAL])
        self.assertEqual(guard.CRATES_API_INTERVAL, 1.0)

    def test_another_registry_with_no_pubtime_has_no_api_to_ask_and_nothing_is_held_back(self):
        reg = cs.CratesRegistry(pubtimes=False)
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        with mock.patch.object(guard, "CRATES_API", reg.url + "api/v1/crates/"), mock.patch.object(guard, "CRATES_API_INTERVAL", 0):
            check = self.check(self.context(), self.pkg("onlynew"))                  # (here the API is at hand: it is not asked)
        self.assertEqual((check.blocked, check.age), ([], None))
        self.assertEqual(reg.paths("/api/"), [])

    def test_an_api_that_cannot_say_leaves_the_time_unknown(self):
        reg = cs.CratesRegistry(pubtimes=False, api=False)
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        with mock.patch.object(cargosrc, "DEFAULT_INDEX", reg.url), mock.patch.object(guard, "CRATES_API", reg.url + "api/v1/crates/"), \
                mock.patch.object(guard, "CRATES_API_INTERVAL", 0):
            check = self.check(self.context(), self.pkg("onlynew"))
        self.assertEqual((check.blocked, check.age), ([], None))

    def test_an_index_that_cannot_be_read_leaves_the_time_unknown(self):
        self.reg.fail["/on/ly/onlynew"] = (500, b"oops")
        check = self.check(self.context(), self.pkg("onlynew"))
        self.assertEqual((check.blocked, check.age), ([], None))

    def test_a_yanked_release_is_noted(self):
        self.reg.add("gone", "1.0.0", yanked=True)
        check = self.check(self.context(), self.pkg("gone"))
        self.assertEqual((check.blocked, check.notes), ([], ["yanked on the registry"]))


class AuthTests(CrateCase):
    def test_a_registry_that_wants_credentials_is_incomplete_not_checked_unless_it_is_crates_io(self):
        # (INCOMPLETE, where it was a note only: it is counted, and --block-warn blocks it, so a registry that refuses only the
        # guard cannot wave a crate through: the Go/Rust review's CG-4)
        reg = cs.CratesRegistry(auth="secret-token")
        cs.default_crates(reg)
        self.addCleanup(reg.close)
        self.reg = reg
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertEqual(check.blocked, [])
        self.assertEqual((check.verdict, check.reason),
                         ("INCOMPLETE", "the registry asked for credentials the guard does not read: not checked"))
        self.assertEqual(check.notes, [])
        check = self.check(self.context(block_warn=True), self.pkg("leaf"))
        self.assertEqual(len(check.blocked), 1)
        self.assertIn("INCOMPLETE (--block-warn)", check.blocked[0])
        with mock.patch.object(cargosrc, "DEFAULT_INDEX", reg.url):
            check = self.check(self.context(), self.pkg("leaf"))
        self.assertIn("could not be checked: HTTP 401", check.blocked[0])

    def test_a_server_error_is_a_block_on_any_registry(self):
        self.reg.fail["/config.json"] = (500, b"oops")
        check = self.check(self.context(), self.pkg("leaf"))
        self.assertIn("could not be checked: HTTP 500", check.blocked[0])


class PackagesTests(CrateCase):
    def run_packages(self, packages, registry=None, skip=(), ctx=None, offline=False, known=frozenset(), **kw):
        ctx = ctx or self.context(**kw)
        registry = registry or cargosrc.Registry("sparse", self.reg.url)
        listed = guard.check_cargo_packages(ctx, packages, registry, self.home, offline, "Cargo.lock", skip=skip, known=known)
        return ctx, listed

    def test_a_plain_http_registry_only_the_lockfile_names_is_not_followed(self):
        # (a lockfile is the project's: the guard takes plain http only to this machine or to a registry cargo's settings name,
        # as its fetcher does: GR-3)
        far = "http://192.0.2.1/index/"
        pkgs = [cargosrc.Package("faraway", "1.0.0", "sparse+" + far, "0" * 64)]
        asked = []
        with mock.patch.object(guard.Fetcher, "get", side_effect=lambda *a, **k: asked.append(a) or b""):
            ctx, listed = self.run_packages(pkgs)
        (check,) = ctx.checks
        self.assertEqual((check.name, check.verdict), ("faraway", "INCOMPLETE"))
        self.assertIn("a plain-http registry (http://192.0.2.1/index/) that the lockfile names and cargo's settings do not",
                      check.reason)
        self.assertEqual((asked, listed), ([], {"faraway-1.0.0"}))
        # one cargo's settings name is read, as cargo reads it (unreachable here: not checked, for that reason)
        with mock.patch.object(guard.Fetcher, "json", side_effect=repo.FetchError("unreachable")) as read:
            ctx, _ = self.run_packages(pkgs, known={far})
        self.assertEqual(read.call_args[0][0], far + "config.json")
        self.assertEqual(ctx.checks[0].blocked, ["could not be checked: unreachable"])            # (fails closed)

    def test_registry_crates_are_checked_and_the_names_cargo_may_unpack_come_back(self):
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0"), ("leaf", "1.0.0")))
        ctx, listed = self.run_packages(pkgs)
        self.assertEqual(sorted((c.name, c.verdict) for c in ctx.checks), [("good", "OK"), ("leaf", "OK")])
        self.assertEqual(listed, {"good-1.0.0", "leaf-1.0.0"})
        self.assertIn("lazaret guard: 2 crates to check (Cargo.lock)\n", self.out.getvalue())

    def test_the_fetcher_is_closed_when_the_checks_are_done_and_when_one_of_them_raises(self):
        closed, original = [], guard.Fetcher.close

        def spy(fetcher):
            closed.append(fetcher)
            original(fetcher)

        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0")))
        with mock.patch.object(guard.Fetcher, "close", spy):
            self.run_packages(pkgs)
            self.assertEqual(len(closed), 1)
            with mock.patch.object(guard, "check_crate", side_effect=RuntimeError("boom")), self.assertRaises(RuntimeError):
                self.run_packages(pkgs)
        self.assertEqual(len(closed), 2)

    def test_a_crate_to_skip_is_not_checked_and_is_still_listed(self):
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0"), ("evil", "1.0.0")))
        ctx, listed = self.run_packages(pkgs, skip={"evil-1.0.0"})
        self.assertEqual([c.name for c in ctx.checks], ["good"])
        self.assertEqual(listed, {"good-1.0.0", "evil-1.0.0"})
        self.assertEqual(ctx.blocked(), [])

    def test_a_path_dependency_is_the_projects_own(self):
        pkgs = [cargosrc.Package("app", "0.1.0", "", None), cargosrc.Package("member", "0.2.0", "", None)]
        ctx, listed = self.run_packages(pkgs)
        self.assertEqual((ctx.checks, listed), ([], set()))

    def test_git_and_other_sources_are_incomplete_not_checked(self):
        pkgs = [cargosrc.Package("fromgit", "0.1.0", "git+https://github.com/x/y#abc", None),
                cargosrc.Package("gitidx", "0.1.0", "registry+https://git.example/index", HEX),
                cargosrc.Package("weird", "0.1.0", "ftp://somewhere", None)]
        ctx, listed = self.run_packages(pkgs)
        self.assertEqual(sorted((c.name, c.source) for c in ctx.checks), [("fromgit", "git"), ("gitidx", "git-index"), ("weird", "other")])
        got = {c.name: (c.verdict, c.reason) for c in ctx.checks}
        self.assertEqual(got["fromgit"], ("INCOMPLETE", "from a git repository: not checked"))
        self.assertEqual(got["gitidx"][0], "INCOMPLETE")
        self.assertIn("from a registry the guard cannot read", got["gitidx"][1])
        self.assertEqual(listed, {"fromgit-0.1.0", "gitidx-0.1.0", "weird-0.1.0"})        # (named: never reported as unpacked unchecked too)
        self.assertEqual(ctx.blocked(), [])
        self.assertEqual(self.reg.requests, [])
        ctx, _ = self.run_packages(pkgs, block_warn=True)
        self.assertEqual(len(ctx.blocked()), 3)

    def test_another_registry_is_read_at_its_own_index(self):
        other = cs.CratesRegistry()
        other.add("elsewhere", "1.0.0")
        self.addCleanup(other.close)
        pkgs = [cargosrc.Package("elsewhere", "1.0.0", "sparse+" + other.url, other.checksum("elsewhere", "1.0.0")),
                cargosrc.Package("leaf", "1.0.0", cs.CRATES_IO, self.sums["leaf"])]
        ctx, listed = self.run_packages(pkgs)
        self.assertEqual(sorted((c.name, c.verdict) for c in ctx.checks), [("elsewhere", "OK"), ("leaf", "OK")])
        self.assertEqual(other.paths("/dl/"), ["/dl/elsewhere/elsewhere-1.0.0.crate"])
        self.assertEqual(self.reg.paths("/dl/"), ["/dl/leaf/leaf-1.0.0.crate"])

    def test_crates_io_s_api_host_is_let_through_only_when_crates_io_is_one_of_the_registries(self):
        asked, original = [], guard.Fetcher

        def spy(hosts, *args, **kwargs):
            asked.append(set(hosts))
            return original(hosts, *args, **kwargs)

        other = cs.CratesRegistry()
        other.add("elsewhere", "1.0.0")
        self.addCleanup(other.close)
        away = [cargosrc.Package("elsewhere", "1.0.0", "sparse+" + other.url, other.checksum("elsewhere", "1.0.0"))]
        mine = cargosrc.parse_lock(lock_of(self.reg, ("leaf", "1.0.0")))
        with mock.patch.object(cargosrc, "DEFAULT_INDEX", self.reg.url), \
                mock.patch.object(guard, "CRATES_API", "https://api.example.test/api/v1/crates/"), mock.patch.object(guard, "Fetcher", spy):
            self.run_packages(away)
            self.run_packages(mine)
        self.assertNotIn("api.example.test", asked[0])
        self.assertIn("api.example.test", asked[1])

    def test_a_download_pattern_is_at_most_512_characters(self):
        class Config:
            def __init__(self, doc):
                self.doc, self.allowed = doc, []

            def json(self, url):
                return self.doc

            def allow(self, url):
                self.allowed.append(url)

        stem = "https://dl.example/"
        for length, fine in ((512, True), (513, False)):
            with self.subTest(length):
                fetcher = Config({"dl": stem + "a" * (length - len(stem))})
                reg = guard.CrateRegistry(fetcher, "https://index.example/")
                self.assertEqual((reg.dl is not None, reg.error is None, len(fetcher.allowed)), (fine, fine, int(fine)))
        for doc in ({"dl": ""}, {"dl": 5}, {}, [], None):
            with self.subTest(doc):
                self.assertIsNotNone(guard.CrateRegistry(Config(doc), "https://index.example/").error)

    def test_a_registry_whose_downloads_are_at_another_host_is_reached_there_and_only_there(self):
        other = cs.CratesRegistry(dl_host="localhost")
        other.add("elsewhere", "1.0.0")
        self.addCleanup(other.close)
        pkgs = [cargosrc.Package("elsewhere", "1.0.0", "sparse+" + other.url, other.checksum("elsewhere", "1.0.0"))]
        ctx, _ = self.run_packages(pkgs)
        self.assertEqual([(c.name, c.verdict) for c in ctx.checks], [("elsewhere", "OK")])
        self.assertEqual(other.paths("/dl/"), ["/dl/elsewhere/elsewhere-1.0.0.crate"])

    def test_crates_io_replaced_by_a_source_the_guard_cannot_read_is_incomplete_for_each_crate(self):
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0"), ("leaf", "1.0.0")))
        pkgs.append(cargosrc.Package("fromgit", "0.1.0", "git+https://github.com/x/y#abc", None))
        ctx, listed = self.run_packages(pkgs, registry=cargosrc.Registry("directory", "vendor"))
        by_name = {c.name: c for c in ctx.checks}
        self.assertEqual(sorted(by_name), ["fromgit", "good", "leaf"])
        self.assertEqual((by_name["good"].verdict, by_name["good"].reason, by_name["good"].source),
                         ("INCOMPLETE", "cargo reads crates.io from a directory source (vendor): not checked", "directory"))
        self.assertEqual(self.reg.requests, [])
        self.assertEqual(listed, {"good-1.0.0", "leaf-1.0.0", "fromgit-0.1.0"})

    def test_no_note_when_there_is_no_crates_io_crate(self):
        ctx, _ = self.run_packages([cargosrc.Package("app", "0.1.0", "", None)], registry=cargosrc.Registry("git", "https://x/y"))
        self.assertEqual(ctx.checks, [])

    def test_a_replaced_source_with_a_git_index_is_named_as_such(self):
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("leaf", "1.0.0")))
        ctx, _ = self.run_packages(pkgs, registry=cargosrc.Registry("local-registry", "/x"))
        self.assertIn("from a local registry source (/x)", ctx.checks[0].reason)

    def test_over_the_limit_it_does_not_start(self):
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0"), ("leaf", "1.0.0"), ("mixed", "1.0.0")))
        with mock.patch.object(cargosrc, "MAX_PACKAGES", 3):
            self.run_packages(pkgs)                                                       # (three crates: at the limit)
            with self.assertRaises(guard.GuardError):
                self.run_packages(pkgs + [cargosrc.Package("onlynew", "1.0.0", cs.CRATES_IO, self.sums["onlynew"])])

    def test_the_same_release_from_one_registry_is_checked_once(self):
        leaf = cargosrc.Package("leaf", "1.0.0", cs.CRATES_IO, self.sums["leaf"])
        ctx, _ = self.run_packages([leaf, leaf])
        self.assertEqual(len(ctx.checks), 1)

    def test_offline_nothing_is_fetched_and_what_cargo_has_is_read(self):
        self.put_in_cargo_cache("leaf", "1.0.0")
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("leaf", "1.0.0"), ("good", "1.0.0")))
        ctx, _ = self.run_packages(pkgs, offline=True)
        verdicts = {c.name: (c.verdict, c.blocked) for c in ctx.checks}
        self.assertEqual(verdicts["leaf"], ("OK", []))
        self.assertEqual(verdicts["good"][1], ["could not be checked: offline, and cargo's cache does not hold it"])
        self.assertEqual(self.reg.requests, [])

    def test_a_registry_that_is_down_blocks_each_of_its_crates(self):
        self.reg.fail["/config.json"] = (503, b"down")
        pkgs = cargosrc.parse_lock(lock_of(self.reg, ("good", "1.0.0"), ("leaf", "1.0.0")))
        ctx, _ = self.run_packages(pkgs)
        self.assertEqual(len(ctx.blocked()), 2)
        self.assertEqual(self.reg.paths("/config.json"), ["/config.json"])                # (asked once for the registry, not once a crate)


class HelperTests(TmpCase):
    def test_a_toolchain_choice_comes_first(self):
        self.assertEqual(guard.cargo_toolchain(["+nightly", "build", "--release"]), (["+nightly"], ["build", "--release"]))
        self.assertEqual(guard.cargo_toolchain(["build", "+x"]), ([], ["build", "+x"]))
        self.assertEqual(guard.cargo_toolchain([]), ([], []))
        self.assertEqual(guard.cargo_toolchain(["+1.90"]), (["+1.90"], []))

    def test_the_workspace_is_what_cargo_metadata_says(self):
        fake = cs.install_fake_cargo(self.tmp)
        env = dict(os.environ, FAKE_CARGO_ROOT=self.tmp)
        root, members = guard.cargo_workspace(fake, [], env, self.tmp, None)
        self.assertEqual((root, members), (self.tmp, [os.path.join(self.tmp, "Cargo.toml")]))
        meta = {"workspace_root": "/w", "packages": [{"manifest_path": "/w/a/Cargo.toml"}, {"manifest_path": "/w/b/Cargo.toml"},
                                                     {"manifest_path": 5}, "junk"]}
        env["FAKE_CARGO_META"] = json.dumps(meta)
        self.assertEqual(guard.cargo_workspace(fake, [], env, self.tmp, "x/Cargo.toml"), ("/w", ["/w/a/Cargo.toml", "/w/b/Cargo.toml"]))

    def test_what_cargo_metadata_gets(self):
        fake = cs.install_fake_cargo(self.tmp)
        log = os.path.join(self.tmp, "log")
        env = dict(os.environ, FAKE_CARGO_LOG=log)
        guard.cargo_workspace(fake, ["+nightly"], env, self.tmp, "sub/Cargo.toml")
        with open(log, encoding="utf-8") as f:
            (run,) = [json.loads(line) for line in f]
        self.assertEqual(run["argv"], ["+nightly", "metadata", "--no-deps", "--format-version", "1", "--offline", "--manifest-path",
                                       "sub/Cargo.toml"])

    def test_a_project_cargo_cannot_read_is_an_error_with_a_reason(self):
        fake = cs.install_fake_cargo(self.tmp)
        env = dict(os.environ, FAKE_CARGO_META="null")
        with self.assertRaisesRegex(guard.GuardError, "cargo cannot read the project here"):
            guard.cargo_workspace(fake, [], env, self.tmp, None)
        for meta in ({"workspace_root": 5}, {"workspace_root": ""}, [1], "text", 7, {"packages": []}):      # (an answer that is no mapping too)
            env["FAKE_CARGO_META"] = json.dumps(meta)
            with self.subTest(meta), self.assertRaises(guard.GuardError):
                guard.cargo_workspace(fake, [], env, self.tmp, None)

    def test_the_members_listed_are_bounded(self):
        fake = cs.install_fake_cargo(self.tmp)
        meta = {"workspace_root": "/w", "packages": [{"manifest_path": f"/w/{k}/Cargo.toml"} for k in range(guard.MAX_MEMBERS + 5)]}
        env = dict(os.environ, FAKE_CARGO_META=json.dumps(meta))
        self.assertEqual(len(guard.cargo_workspace(fake, [], env, self.tmp, None)[1]), guard.MAX_MEMBERS)

    def test_the_install_root_is_the_one_registry_crate_of_the_name(self):
        pkgs = [cargosrc.Package("lazaret-guard-plan", "0.0.0", "", None), cargosrc.Package("Foo_Bar", "0.2.0", cs.CRATES_IO, HEX),
                cargosrc.Package("Foo_Bar", "0.10.0", cs.CRATES_IO, HEX), cargosrc.Package("other", "1.0.0", cs.CRATES_IO, HEX)]
        self.assertEqual(guard._install_root(pkgs, "foo-bar").version, "0.10.0")                 # (the highest, by SemVer)
        self.assertIsNone(guard._install_root(pkgs, "nosuch"))
        self.assertIsNone(guard._install_root([cargosrc.Package("x", "1.0.0", "", None)], "x"))        # (a path dependency is not it)

    def test_a_lock_that_cannot_be_read_is_an_error_and_a_missing_one_is_empty(self):
        self.assertEqual(guard.read_cargo_lock(os.path.join(self.tmp, "none.lock")), [])
        path = os.path.join(self.tmp, "Cargo.lock")
        with open(path, "w", encoding="utf-8") as f:
            f.write("[[package")
        with self.assertRaisesRegex(guard.GuardError, "Cargo.lock cannot be read"):
            guard.read_cargo_lock(path)
        self.assertEqual(guard.read_cargo_lock(path, strict=False), [])                     # (a caller that leaves it to cargo to say)

    def test_the_lock_a_crate_was_published_with(self):
        lock = lock_of_text = cs.lock_text([("tool", "1.0.0", None, ["leaf"]), ("leaf", "1.0.0", HEX, [])])
        ctx = guard.Context(options(tool="cargo"), out=io.StringIO())
        self.addCleanup(ctx.close)
        root = cargosrc.Package("tool", "1.0.0", cs.CRATES_IO, HEX)
        data = cs.crate_tgz("tool", "1.0.0", {"Cargo.lock": lock})
        got = guard._published_lock(ctx, data, root)
        self.assertEqual([(p.name, p.version) for p in got], [("tool", "1.0.0"), ("leaf", "1.0.0")])
        self.assertIsNone(guard._published_lock(ctx, cs.crate_tgz("tool", "1.0.0", {}), root))        # (it has none)
        self.assertIsNone(guard._published_lock(ctx, None, root))
        self.assertEqual(ctx.blocked(), [])

    def test_a_published_lock_the_guard_cannot_be_sure_of_is_blocked(self):
        # (the guard read the first of two, cargo unpacks the last; one too large or not a lockfile was replaced by a fresh
        # resolution, which is not what cargo install --locked builds: the Go/Rust review's CG-5)
        lock = cs.lock_text([("tool", "1.0.0", None, ["leaf"]), ("leaf", "1.0.0", HEX, [])])
        root = cargosrc.Package("tool", "1.0.0", cs.CRATES_IO, HEX)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for member, raw in (("Cargo.toml", b'[package]\nname = "tool"\nversion = "1.0.0"\n'), ("Cargo.lock", lock.encode()),
                                ("Cargo.lock", lock.replace("1.0.0", "1.0.1").encode())):
                info = tarfile.TarInfo(f"tool-1.0.0/{member}")
                info.size = len(raw)
                tf.addfile(info, io.BytesIO(raw))
        cases = (("two", buf.getvalue(), "holds two Cargo.lock files"),
                 ("not a lock", cs.crate_tgz("tool", "1.0.0", {"Cargo.lock": "[[package"}), "not a lockfile"),
                 ("not text", cs.crate_tgz("tool", "1.0.0", {"Cargo.lock": b"\xff\xfe"}), "not a lockfile"))
        for label, data, says in cases:
            with self.subTest(label):
                ctx = guard.Context(options(tool="cargo"), out=io.StringIO())
                self.addCleanup(ctx.close)
                self.assertEqual(guard._published_lock(ctx, data, root), [])
                (blocked,) = ctx.blocked()
                self.assertIn(says, blocked.blocked[0])
        ctx = guard.Context(options(tool="cargo"), out=io.StringIO())
        self.addCleanup(ctx.close)
        with mock.patch.object(repo, "MAX_MEMBER", 10):
            self.assertEqual(guard._published_lock(ctx, cs.crate_tgz("tool", "1.0.0", {"Cargo.lock": lock}), root), [])
        self.assertIn("too large to read", ctx.blocked()[0].blocked[0])


class InterruptTests(TmpCase):
    def test_the_manifest_and_the_lock_are_put_back_when_the_run_is_cut_short(self):
        lock, manifest = os.path.join(self.tmp, "Cargo.lock"), os.path.join(self.tmp, "Cargo.toml")
        for path, text in ((lock, OLD_LOCK), (manifest, '[package]\nname = "app"\n')):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

        def cut_short(argv, env, cwd=None, capture=False):
            with open(lock, "a", encoding="utf-8") as f:
                f.write("# cargo was here\n")
            with open(manifest, "a", encoding="utf-8") as f:
                f.write('serde = "1"\n')
            raise KeyboardInterrupt

        ctx = guard.Context(options(tool="cargo"), out=io.StringIO())
        ctx.scanner = CrateScanner()
        self.addCleanup(ctx.close)
        with mock.patch.object(guard, "find_tool", return_value="cargo"), mock.patch.object(guard, "run_tool", side_effect=cut_short), \
                mock.patch.object(guard, "cargo_workspace", return_value=(self.tmp, [manifest])), \
                mock.patch.object(cargosrc, "cargo_home", return_value=self.tmp), mock.patch.object(cargosrc, "sources", return_value={}):
            with self.assertRaises(KeyboardInterrupt):
                guard.guard_cargo(ctx, ["add", "serde"])
        self.assertEqual(gs.read(lock), OLD_LOCK)
        self.assertEqual(gs.read(manifest), '[package]\nname = "app"\n')


class FlowCase(TmpCase):
    """`lazaret guard cargo …` run as the command, with a fake cargo: what it does is the test's to say."""

    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.mkdtemp(prefix="lazaret-guard-cargo-shared-")
        cls.bin = os.path.join(cls.shared, "bin")
        os.makedirs(cls.bin)
        cs.install_fake_cargo(cls.bin)
        cls.reg = cs.CratesRegistry()
        cls.sums = cs.default_crates(cls.reg)
        cls.reg.add("leaf", "1.1.0")

    @classmethod
    def tearDownClass(cls):
        cls.reg.close()
        shutil.rmtree(cls.shared, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.dir = os.path.join(self.tmp, "proj")
        os.makedirs(self.dir)
        self.home = os.path.join(self.tmp, "cargo-home")
        self.manifest = os.path.join(self.dir, "Cargo.toml")
        self.lock = os.path.join(self.dir, "Cargo.lock")
        self.log = os.path.join(self.tmp, "cargo.log")
        self.write(self.manifest, '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n')
        self.config(f'[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "sparse+{self.reg.url}"\n')
        self.plan = {}
        self.scratch = {}
        self.root = self.dir
        self.meta = None
        self.base = len(self.reg.requests)                     # (the registry is shared by the tests of a class: this test's are after)

    def config(self, text):
        self.write(os.path.join(self.home, "config.toml"), text)

    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, path):
        return gs.read(path)

    def lock_of(self, *crates):
        return lock_of(self.reg, *crates)

    def unpack(self, *names):
        return [["unpack", self.home, n] for n in names]

    def run_guard(self, *args, cwd=None, cache=False, timeout=60):
        env = gs.base_env(self.tmp)
        env.update(PATH=self.bin + os.pathsep + os.environ.get("PATH", ""), CARGO_HOME=self.home, HOME=self.tmp,
                   FAKE_CARGO_ROOT=self.root, FAKE_CARGO_PLAN=json.dumps(self.plan), FAKE_CARGO_SCRATCH=json.dumps(self.scratch),
                   FAKE_CARGO_LOG=self.log)
        if self.meta is not None:
            env["FAKE_CARGO_META"] = json.dumps(self.meta)
        flags = ["--jobs", "1"] + ([] if cache else ["--no-cache"])
        return gs.run_guard([*flags, *args], cwd or self.dir, env, timeout)

    def requested(self, prefix=""):
        """The registry paths this test's run asked for (those starting with `prefix`), in order."""
        return [p for p in self.reg.requests[self.base:] if p.startswith(prefix)]

    def runs(self):
        try:
            with open(self.log, encoding="utf-8") as f:
                return [json.loads(line) for line in f]
        except OSError:
            return []

    def commands(self):
        """The cargo commands that ran, without the metadata the guard asks for: [argv]."""
        return [r["argv"] for r in self.runs() if "metadata" not in r["argv"]]


class BuildCommandTests(FlowCase):
    def test_the_resolution_is_made_the_crates_are_checked_and_then_the_command_runs_as_given(self):
        self.plan = {"update": [["lock", self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]], "build": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "build", "--release")
        self.assertEqual(code, 0, out)
        # (with --locked: cargo builds the lock that was checked, and stops rather than resolve to crates it was not: CG-9)
        self.assertEqual(self.commands(), [["update", "--workspace"], ["build", "--locked", "--release"]])
        self.assertIn("lazaret guard: 2 crates to check (Cargo.lock)\n", out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertNotIn("installed but not checked", out)
        self.assertIn('name = "good"', self.read(self.lock))                               # (the resolution stays)

    def test_unstable_flags_reach_the_resolution_and_another_lockfile_is_the_one_checked(self):
        # (nightly's --lockfile-path: cargo reads and writes that lock instead of Cargo.lock; and the guard's own run of cargo
        # takes the command's -Z flags, so that it resolves as the command will: GR-3)
        other = os.path.join(self.dir, "other.lock")
        self.plan = {"update": [["write", other, self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]],
                     "build": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "build", "-Z", "unstable-options", "--lockfile-path", "other.lock", "-Zminimal-versions")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands(), [
            ["update", "-Z", "unstable-options", "-Z", "minimal-versions", "--workspace", "--lockfile-path", "other.lock"],
            ["build", "--locked", "-Z", "unstable-options", "--lockfile-path", "other.lock", "-Zminimal-versions"]])
        self.assertIn("lazaret guard: 2 crates to check (other.lock)\n", out)
        self.assertFalse(os.path.exists(self.lock))
        # a hostile crate in it: blocked, and that lock put back (removed: it did not exist)
        os.remove(other)
        self.plan = {"update": [["write", other, self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build", "-Z", "unstable-options", "--lockfile-path", "other.lock")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertFalse(os.path.exists(other))

    def test_a_hostile_crate_stops_the_command_and_puts_the_lock_back(self):
        old = self.lock_of(("leaf", "1.0.0"))
        self.write(self.lock, old)
        self.plan = {"update": [["lock", self.lock_of(("parent", "1.0.0"), ("evil", "1.0.0"))]], "build": self.unpack("evil-1.0.0")}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertIn("1 blocked — nothing was installed; Cargo.lock put back", out)
        self.assertEqual(self.commands(), [["update", "--workspace"]])                       # (cargo build never ran)
        self.assertEqual(self.read(self.lock), old)

    def test_a_lock_that_did_not_exist_is_removed_again(self):
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "check")
        self.assertEqual(code, 1, out)
        self.assertFalse(os.path.exists(self.lock))

    def test_every_command_that_builds_is_wrapped(self):
        for sub in sorted(guard.CARGO_BUILDS):
            with self.subTest(sub):
                if os.path.exists(self.log):
                    os.remove(self.log)
                self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]]}
                code, out = self.run_guard("cargo", sub)
                self.assertEqual(code, 0, out)
                self.assertEqual(self.commands(), [["update", "--workspace"], [sub, "--locked"]])

    def test_what_comes_after_two_dashes_is_the_programs_own(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "run", "--", "--locked", "--manifest-path", "x")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands(), [["update", "--workspace"], ["run", "--locked", "--", "--locked", "--manifest-path", "x"]])

    def test_cargos_own_exit_code_is_the_guards(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]], "test": [["exit", 101]]}
        code, out = self.run_guard("cargo", "test")
        self.assertEqual(code, 101, out)
        self.assertNotIn("nothing was installed", out)

    def test_a_command_that_failed_still_says_what_it_fetched_unchecked(self):
        # (a build script runs before the build can fail: the guard said nothing of what cargo fetched unchecked then: CG-9)
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]], "build": self.unpack("leaf-1.0.0", "stray-9.9.9") + [["exit", 101]]}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 101, out)
        self.assertIn("fetched but not checked (the command then failed): stray-9.9.9", out)

    def test_a_resolution_that_fails_is_reported_and_the_files_are_put_back(self):
        self.write(self.lock, OLD_LOCK)
        self.plan = {"update": [["write", self.lock, "half = broken\n"], ["say", "error: failed to select a version"], ["exit", 101]]}
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "build")
        self.assertEqual(code, 3, out)
        self.assertEqual(json.loads(self.read(report))["installed"], False)
        self.assertIn("lazaret guard: resolving (cargo build) failed (exit 101):", out)
        self.assertIn("\n  error: failed to select a version", out)                       # (what cargo said, kept and shown by the guard)
        self.assertEqual(self.read(self.lock), OLD_LOCK)
        self.assertEqual(self.commands(), [["update", "--workspace"]])

    def test_a_project_cargo_cannot_read_is_a_usage_error(self):
        self.meta = {"workspace_root": ""}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 2, out)
        self.assertIn("cargo cannot read the project here", out)

    def test_a_command_the_guard_does_not_wrap_is_a_usage_error(self):
        for args in (["cargo"], ["cargo", "publish"], ["cargo", "tree"], ["cargo", "--release", "build"], ["cargo", "+nightly"]):
            with self.subTest(args):
                code, out = self.run_guard(*args)
                self.assertEqual(code, 2, out)
                self.assertIn("lazaret guard wraps cargo's commands that fetch crates", out)
        self.assertEqual(self.runs(), [])

    def test_trust_lets_a_flagged_crate_through(self):
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"))]], "build": self.unpack("evil-1.0.0")}
        code, out = self.run_guard("--trust", "evil", "cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertIn("TRUSTED    evil@1.0.0: installed anyway (--trust): SUSPICIOUS", out)

    def test_a_release_younger_than_min_age_blocks_and_allow_new_lets_it_through(self):
        self.plan = {"update": [["lock", self.lock_of(("mixed", "1.1.0"))]], "build": self.unpack("mixed-1.1.0")}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertRegex(out, r"BLOCKED    mixed@1\.1\.0: published 1 hour ago, under --min-age 2 days")
        code, out = self.run_guard("--allow-new", "mixed", "cargo", "build")
        self.assertEqual(code, 0, out)
        code, out = self.run_guard("--min-age", "0", "cargo", "build")
        self.assertEqual(code, 0, out)

    def test_a_crate_that_does_not_match_its_checksum_is_blocked(self):
        text = self.lock_of(("leaf", "1.0.0")).replace(self.sums["leaf"], HEX)
        self.plan = {"update": [["lock", text]]}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    leaf@1.0.0: its sha256 is not the lockfile's", out)

    def test_crates_cargo_has_unpacked_are_checked_too(self):
        # (another tool, an editor or `cargo tree`, unpacks crates without running them, and cargo builds an unpacked one
        # without fetching it again: they were left out, and a hostile one was built: the Go/Rust review's CG-3)
        os.makedirs(os.path.join(self.home, "registry", "src", "index.crates.io-0000000000000000", "evil-1.0.0"))
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"), ("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("2 crates to check", out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertEqual(self.commands(), [["update", "--workspace"]])

    def test_a_crate_checked_before_is_not_fetched_or_scanned_again(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]], "build": self.unpack("leaf-1.0.0")}
        code, out = self.run_guard("cargo", "build", cache=True)
        self.assertEqual(code, 0, out)
        before = len(self.requested("/dl/"))
        code, out = self.run_guard("cargo", "build", cache=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.requested("/dl/")), before)                                # (its verdict, by its checksum)

    def test_a_crate_cargo_unpacks_that_the_lock_does_not_name_fails_the_run(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]], "build": self.unpack("leaf-1.0.0", "stray-9.9.9")}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("installed but not checked: stray-9.9.9", out)
        self.assertIn("cargo got them from somewhere the guard did not look", out)

    def test_a_crate_from_git_is_incomplete_and_not_fetched(self):
        text = self.lock_of(("leaf", "1.0.0")) + '\n[[package]]\nname = "fromgit"\nversion = "0.1.0"\nsource = "git+https://github.com/x/y#abc"\n'
        self.plan = {"update": [["lock", text]], "build": self.unpack("leaf-1.0.0")}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertIn("fromgit@0.1.0", out)
        self.assertIn("from a git repository: not checked", out)
        code, out = self.run_guard("--block-warn", "cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    fromgit@0.1.0: INCOMPLETE (--block-warn): from a git repository: not checked", out)

    def test_a_crate_of_a_registry_the_guard_cannot_read_is_noted_once_and_not_also_reported_as_unchecked(self):
        text = self.lock_of(("leaf", "1.0.0")) + ('\n[[package]]\nname = "gitidx"\nversion = "0.1.0"\n'
                                                 'source = "registry+https://git.example/index"\nchecksum = "' + "ab" * 32 + '"\n')
        self.plan = {"update": [["lock", text]], "build": self.unpack("leaf-1.0.0", "gitidx-0.1.0")}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertIn("gitidx@0.1.0", out)
        self.assertIn("from a registry the guard cannot read", out)
        self.assertNotIn("installed but not checked", out)

    def test_a_vendored_crates_io_is_incomplete_and_the_command_runs(self):
        self.config('[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "vendor"\n')
        self.plan = {"update": [["lock", self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
        self.assertIn("cargo reads crates.io from a directory source (vendor): not checked", out)
        self.assertEqual(self.commands(), [["update", "--workspace"], ["build", "--locked"]])

    def test_a_config_option_on_the_command_line_is_read(self):
        # (cargo reads `--config`: the guard did not, and checked crates.io's bytes while cargo built a vendor folder's: CG-6)
        self.plan = {"update": [["lock", self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build", "--config", 'source.crates-io.replace-with = "vendored"', "--config",
                                   'source.vendored.directory = "vendor"')
        self.assertEqual(code, 0, out)
        self.assertIn("cargo reads crates.io from a directory source (vendor): not checked", out)
        self.assertEqual(self.requested("/dl/"), [])

    def test_a_toolchain_choice_is_passed_to_every_command(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "+nightly", "build")
        self.assertEqual(code, 0, out)
        self.assertEqual([r["argv"][0] for r in self.runs()], ["+nightly"] * 3)
        self.assertEqual(self.commands(), [["+nightly", "update", "--workspace"], ["+nightly", "build", "--locked"]])

    def test_a_manifest_path_and_offline_go_to_the_resolution(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]]}
        self.put_cache("leaf", "1.0.0")
        code, out = self.run_guard("cargo", "build", "--manifest-path", "sub/Cargo.toml", "--offline")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands()[0], ["update", "--workspace", "--manifest-path", "sub/Cargo.toml", "--offline"])
        self.assertEqual(self.runs()[0]["argv"], ["metadata", "--no-deps", "--format-version", "1", "--offline", "--manifest-path",
                                                  "sub/Cargo.toml"])
        self.assertEqual(self.requested("/dl/"), [])                                        # (offline: nothing is fetched)

    def put_cache(self, name, version):
        folder = os.path.join(self.home, "registry", "cache", "index.crates.io-0000000000000000")
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, f"{name}-{version}.crate"), "wb") as f:
            f.write(self.reg.versions[name][version]["data"])

    def test_the_lock_of_a_workspace_is_at_its_root(self):
        member = os.path.join(self.dir, "crates", "member")
        os.makedirs(member)
        self.write(os.path.join(member, "Cargo.toml"), '[package]\nname = "member"\nversion = "0.1.0"\n')
        self.write(self.manifest, '[workspace]\nmembers = ["crates/member"]\n')
        self.write(self.lock, OLD_LOCK)
        self.meta = {"workspace_root": self.dir, "packages": [{"manifest_path": os.path.join(member, "Cargo.toml")}]}
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build", cwd=member)
        self.assertEqual(code, 1, out)
        self.assertEqual(self.read(self.lock), OLD_LOCK)

    def test_a_member_s_manifest_a_resolution_changed_is_put_back_too(self):
        member = os.path.join(self.dir, "m")
        self.write(os.path.join(member, "Cargo.toml"), "[package]\nname = 'm'\n")
        self.meta = {"workspace_root": self.dir, "packages": [{"manifest_path": os.path.join(member, "Cargo.toml")}]}
        self.plan = {"add": [["append", os.path.join(member, "Cargo.toml"), "evil = '1'\n"], ["lock", self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "add", "evil", "-p", "m")
        self.assertEqual(code, 1, out)
        self.assertEqual(self.read(os.path.join(member, "Cargo.toml")), "[package]\nname = 'm'\n")
        self.assertFalse(os.path.exists(self.lock))
        self.assertIn("Cargo.lock and Cargo.toml put back", out)


class LockedAndPlanTests(FlowCase):
    def test_with_locked_cargo_is_not_asked_to_resolve_and_the_lock_in_place_is_read(self):
        self.write(self.lock, self.lock_of(("evil", "1.0.0")))
        code, out = self.run_guard("cargo", "build", "--locked")
        self.assertEqual(code, 1, out)
        self.assertEqual(self.commands(), [])
        self.assertIn("BLOCKED    evil@1.0.0", out)
        self.write(self.lock, self.lock_of(("leaf", "1.0.0")))
        code, out = self.run_guard("cargo", "build", "--locked")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands(), [["build", "--locked"]])

    def test_frozen_is_locked_and_offline(self):
        self.write(self.lock, self.lock_of(("leaf", "1.0.0")))
        code, out = self.run_guard("cargo", "build", "--frozen")
        self.assertEqual(code, 1, out)                                                      # (offline, and nothing in cargo's cache)
        self.assertIn("offline, and cargo's cache does not hold it", out)
        self.assertEqual(self.commands(), [])
        self.assertEqual(self.requested("/dl/leaf"), [])

    def test_with_locked_and_no_lock_there_is_nothing_to_check_and_cargo_says_so_itself(self):
        self.plan = {"build": [["exit", 101]]}
        code, out = self.run_guard("cargo", "build", "--locked")
        self.assertEqual(code, 101, out)

    def test_a_plan_resolves_and_checks_and_runs_nothing(self):
        self.write(self.lock, OLD_LOCK)
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]]}
        code, out = self.run_guard("--plan", "cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands(), [["update", *guard.CARGO_PLAN_CONFIG, "--workspace"]])   # (GR-1)
        self.assertIn("nothing blocked (--plan: nothing was installed; Cargo.lock put back)", out)
        self.assertEqual(self.read(self.lock), OLD_LOCK)

    def test_a_plan_of_a_blocked_crate_is_blocked(self):
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("--plan", "cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertEqual(self.commands(), [["update", *guard.CARGO_PLAN_CONFIG, "--workspace"]])

    def test_json_says_what_was_checked(self):
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"), ("evil", "1.0.0"))]]}
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "build")
        self.assertEqual(code, 1, out)
        doc = json.loads(self.read(report))
        self.assertEqual((doc["tool"], doc["command"], doc["blocked"], doc["exitCode"], doc["installed"]),
                         ("cargo", ["build"], 1, 1, False))
        self.assertEqual({(p["ecosystem"], p["name"], p["verdict"]) for p in doc["packages"]},
                         {("crates", "leaf", "OK"), ("crates", "evil", "SUSPICIOUS")})

    def test_json_says_whether_the_command_ran_and_what_it_returned(self):
        report = os.path.join(self.tmp, "report.json")
        for tail, want_code, ran in (([], 0, True), ([["exit", 101]], 101, False)):
            with self.subTest(want_code):
                self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"))]], "build": self.unpack("leaf-1.0.0") + tail}
                code, out = self.run_guard("--json", report, "cargo", "build")
                self.assertEqual(code, want_code, out)
                doc = json.loads(self.read(report))
                self.assertEqual((doc["installed"], doc["exitCode"], doc["blocked"]), (ran, want_code, 0))

    def test_a_second_run_does_not_fetch_what_the_first_checked(self):
        self.plan = {"update": [["lock", self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "build", cache=True)
        self.assertEqual(code, 0, out)
        before = self.requested("/dl/")
        self.assertTrue(before)
        count = len(self.requested())
        code, out = self.run_guard("cargo", "build", cache=True)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.requested()[count:], ["/config.json"])


class ResolvingCommandTests(FlowCase):
    def test_add_runs_in_place_and_what_it_added_is_checked(self):
        self.write(self.lock, self.lock_of(("leaf", "1.0.0")))
        self.plan = {"add": [["append", self.manifest, 'good = "1"\n'], ["lock", self.lock_of(("leaf", "1.0.0"), ("good", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "add", "good")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands(), [["add", "good"]])
        self.assertIn("1 crate to check (what the command added to Cargo.lock)", out)
        self.assertIn("checked 1 OK", out)
        self.assertIn('good = "1"', self.read(self.manifest))
        self.assertEqual(self.requested("/dl/"), ["/dl/good/good-1.0.0.crate"])               # (leaf was there before: not fetched)

    def test_a_crate_whose_build_script_runs_a_download_is_blocked(self):
        """Part C (0.1.9): a crate's Rust code is read (it was SC-UNREAD-CODE, INCOMPLETE, and built): a build script that runs a
        download through a shell is SUSPICIOUS, and the guard blocks the crate before cargo builds it."""
        before = self.lock_of(("leaf", "1.0.0"))
        self.write(self.lock, before)
        self.plan = {"add": [["append", self.manifest, 'buildevil = "1"\n'],
                             ["lock", self.lock_of(("leaf", "1.0.0"), ("buildevil", "1.0.0"))]]}
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "add", "buildevil")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    buildevil@1.0.0: SUSPICIOUS", out)
        self.assertEqual(self.read(self.lock), before)
        (pkg,) = json.loads(self.read(report))["packages"]
        self.assertTrue(any("SC-INSTALL-HOOK" in i and "build.rs" in i for i in pkg["indicators"]), pkg)

    def test_json_says_an_add_was_made(self):
        self.write(self.lock, self.lock_of(("leaf", "1.0.0")))
        self.plan = {"add": [["append", self.manifest, 'good = "1"\n'], ["lock", self.lock_of(("leaf", "1.0.0"), ("good", "1.0.0"))]]}
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "add", "good")
        self.assertEqual(code, 0, out)
        doc = json.loads(self.read(report))
        self.assertEqual((doc["installed"], doc["exitCode"], doc["blocked"]), (True, 0, 0))

    def test_a_lock_that_could_not_be_read_before_the_command_makes_everything_in_the_new_one_new(self):
        self.write(self.lock, "[[package")                                    # (cargo is the one to say what is wrong with it)
        self.plan = {"update": [["lock", self.lock_of(("leaf", "1.0.0"), ("good", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "update")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(self.requested("/dl/")), ["/dl/good/good-1.0.0.crate", "/dl/leaf/leaf-1.0.0.crate"])

    def test_a_blocked_add_puts_back_the_manifest_and_the_lock(self):
        before_manifest = self.read(self.manifest)
        before_lock = self.lock_of(("leaf", "1.0.0"))
        self.write(self.lock, before_lock)
        self.plan = {"add": [["append", self.manifest, 'parent = "1"\n'], ["lock", self.lock_of(("leaf", "1.0.0"), ("parent", "1.0.0"), ("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "add", "parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertIn("Cargo.lock and Cargo.toml put back", out)
        self.assertEqual(self.read(self.manifest), before_manifest)
        self.assertEqual(self.read(self.lock), before_lock)

    def test_update_checks_only_what_changed(self):
        old = self.lock_of(("evil", "1.0.0"), ("leaf", "1.0.0"))
        self.write(self.lock, old)
        self.plan = {"update": [["lock", self.lock_of(("evil", "1.0.0"), ("leaf", "1.1.0"))]]}
        code, out = self.run_guard("cargo", "update")
        self.assertEqual(code, 0, out)                                                       # (the evil one was in the lock before)
        self.assertEqual(self.commands(), [["update"]])
        self.assertEqual(self.requested("/dl/"), ["/dl/leaf/leaf-1.1.0.crate"])

    def test_a_new_checksum_for_the_same_version_counts_as_changed(self):
        self.write(self.lock, self.lock_of(("leaf", "1.0.0")))
        evil_sum = self.sums["evil"]
        text = self.lock_of(("leaf", "1.0.0")).replace(self.sums["leaf"], evil_sum)
        self.plan = {"update": [["lock", text]]}
        code, out = self.run_guard("cargo", "update")
        self.assertEqual(code, 1, out)
        self.assertIn("leaf@1.0.0: its sha256 is not the lockfile's", out)

    def test_generate_lockfile_is_a_resolution_too(self):
        self.plan = {"generate-lockfile": [["lock", self.lock_of(("evil", "1.0.0"))]]}
        code, out = self.run_guard("cargo", "generate-lockfile")
        self.assertEqual(code, 1, out)
        self.assertFalse(os.path.exists(self.lock))

    def test_a_command_that_fails_is_not_checked_and_its_files_are_put_back(self):
        self.write(self.lock, OLD_LOCK)
        self.plan = {"add": [["write", self.lock, "half = broken\n"], ["exit", 101]]}
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "add", "nosuch")
        self.assertEqual(code, 101, out)
        self.assertEqual(self.read(self.lock), OLD_LOCK)
        self.assertNotIn("crates to check", out)
        doc = json.loads(self.read(report))
        self.assertEqual((doc["installed"], doc["exitCode"]), (False, 101))

    def test_a_plan_of_add_runs_it_and_puts_everything_back(self):
        self.plan = {"add": [["append", self.manifest, 'good = "1"\n'], ["lock", self.lock_of(("good", "1.0.0"), ("leaf", "1.0.0"))]]}
        before = self.read(self.manifest)
        code, out = self.run_guard("--plan", "cargo", "add", "good")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read(self.manifest), before)
        self.assertFalse(os.path.exists(self.lock))
        self.assertIn("nothing blocked (--plan: nothing was installed; Cargo.lock and Cargo.toml put back)", out)

    def test_add_to_a_project_with_a_lock_of_old_style_checksums_in_metadata(self):
        old = self.lock_of(("leaf", "1.0.0"))
        meta_lock = (f'[[package]]\nname = "app"\nversion = "0.1.0"\n\n[[package]]\nname = "good"\nversion = "1.0.0"\nsource = "{cs.CRATES_IO}"\n'
                     f'\n[metadata]\n"checksum good 1.0.0 ({cs.CRATES_IO})" = "{self.sums["good"]}"\n')
        self.write(self.lock, old)
        self.plan = {"update": [["lock", meta_lock]]}
        code, out = self.run_guard("cargo", "update")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.requested("/dl/"), ["/dl/good/good-1.0.0.crate"])


class InstallTests(FlowCase):
    def setUp(self):
        super().setUp()
        self.scratch = {"good": cs.lock_text([("lazaret-guard-plan", "0.0.0", None, ["good"]), ("good", "1.0.0", self.sums["good"], ["leaf"]),
                                              ("leaf", "1.0.0", self.sums["leaf"], [])]),
                        "parent": cs.lock_text([("lazaret-guard-plan", "0.0.0", None, ["parent"]),
                                                ("parent", "1.0.0", self.sums["parent"], ["evil"]),
                                                ("evil", "1.0.0", self.sums["evil"], [])]),
                        "foo_bar": cs.lock_text([("lazaret-guard-plan", "0.0.0", None, ["foo_bar"]),
                                                 ("foo_bar", "0.2.0", self.sums["foo_bar"], ["leaf"]),
                                                 ("leaf", "1.0.0", self.sums["leaf"], [])])}

    def installs(self):
        return [a for a in self.commands() if a and a[0] in ("install", "+nightly")]

    def resolutions(self):
        """The two resolutions of a crate: the scratch project that needs it (which version cargo picks), then the crate itself
        as the root of its own workspace (what it builds) -> [(kind, run)]."""
        return [("dependent" if "lazaret-guard-plan" in r["manifest"] else "crate", r) for r in self.runs()
                if r["argv"][0] == "generate-lockfile"]

    def test_the_crate_and_what_it_builds_are_checked_and_then_cargo_installs(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "good")
        self.assertEqual(code, 0, out)
        self.assertIn("1 crate to check (good, the crate cargo install builds)", out)
        self.assertIn("1 crate to check (what cargo install good builds)", out)
        (dep_kind, dependent), (crate_kind, crate) = self.resolutions()
        self.assertEqual((dep_kind, crate_kind), ("dependent", "crate"))
        self.assertIn('[workspace]\n\n[dependencies]\ngood = "*"\n', dependent["manifest"])
        self.assertIn('name = "good"', crate["manifest"])                                    # (the crate's own manifest…)
        self.assertTrue(crate["manifest"].endswith("\n[workspace]\n"))                      # (…as a workspace of its own)
        self.assertEqual(self.commands()[-1], ["install", "good@=1.0.0"])                    # (the release checked, pinned)
        for _kind, run in self.resolutions():
            self.assertFalse(os.path.exists(run["argv"][2]))                                  # (the scratch projects are gone)
            self.assertEqual(run["argv"][:2], ["generate-lockfile", "--manifest-path"])
            self.assertNotIn("--offline", run["argv"])                                        # (only a run that is offline resolves so)
            self.assertEqual(os.path.realpath(run["cwd"]), os.path.realpath(self.dir))        # (cargo's settings are the user's folder's)

    def test_unstable_flags_reach_both_resolutions_and_another_lockfile_is_refused(self):
        # (GR-3: the guard resolves the crate as cargo install will, with its -Z flags; --lockfile-path would make cargo build
        # from another lock than the one checked, so it is refused)
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "-Zbuild-std", "good")
        self.assertEqual(code, 0, out)
        for _kind, run in self.resolutions():
            self.assertEqual(run["argv"][:3], ["generate-lockfile", "-Z", "build-std"])
        self.assertEqual(self.commands()[-1], ["install", "-Zbuild-std", "good@=1.0.0"])
        code, out = self.run_guard("cargo", "install", "--lockfile-path", "x.lock", "good")
        self.assertNotEqual(code, 0, out)
        self.assertIn("--lockfile-path is not one the guard reads", out)

    def test_what_a_feature_brings_in_is_checked_whatever_features_are_asked(self):
        # (cargo install resolves a crate's lock with every feature of it on; the scratch project asked for its default
        # features only, so an optional dependency `--features` turned on was built unchecked: the Go/Rust review's CG-2)
        self.scratch["crate:good"] = cs.lock_text([("good", "1.0.0", None, ["leaf", "evil"]), ("leaf", "1.0.0", self.sums["leaf"], []),
                                                   ("evil", "1.0.0", self.sums["evil"], [])])
        code, out = self.run_guard("cargo", "install", "good")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertEqual(self.installs(), [])

    def test_vers_is_read_as_version(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "--vers", "1.0.0", "good")
        self.assertEqual(code, 0, out)
        self.assertIn('good = "=1.0.0"\n', self.resolutions()[0][1]["manifest"])
        self.assertEqual(self.commands()[-1], ["install", "good@=1.0.0"])

    def test_an_option_the_guard_does_not_know_is_a_usage_error(self):
        code, out = self.run_guard("cargo", "install", "--frobnicate", "x", "good")
        self.assertEqual(code, 2, out)
        self.assertIn("not an option the guard knows", out)
        self.assertEqual(self.runs(), [])

    def test_json_says_whether_cargo_installed_it(self):
        report = os.path.join(self.tmp, "report.json")
        for tail, want_code, installed in (([], 0, True), ([["exit", 101]], 101, False)):
            with self.subTest(want_code):
                self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0") + tail}
                code, out = self.run_guard("--json", report, "cargo", "install", "good")
                self.assertEqual(code, want_code, out)
                doc = json.loads(self.read(report))
                self.assertEqual((doc["installed"], doc["exitCode"]), (installed, want_code))

    def test_an_offline_install_resolves_offline_too_and_fetches_nothing(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        self.run_guard("cargo", "install", "--offline", "good")
        (run,) = [r for r in self.runs() if r["argv"][0] == "generate-lockfile"]
        self.assertEqual(run["argv"][-1], "--offline")
        self.assertEqual(self.requested("/dl/"), [])

    def test_a_hostile_dependency_stops_the_install(self):
        self.plan = {"install": self.unpack("parent-1.0.0", "evil-1.0.0")}
        code, out = self.run_guard("cargo", "install", "parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertNotIn(["install", "parent"], self.commands())
        self.assertIn("1 blocked — nothing was installed", out)

    def test_a_version_asked_for_is_the_requirement_of_the_scratch_project(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        for args, line in ((["good@1.0.0"], 'good = "=1.0.0"'), (["--version", "1.0.0", "good"], 'good = "=1.0.0"'),
                           (["good@^1"], 'good = "^1"')):
            with self.subTest(args):
                os.remove(self.log) if os.path.exists(self.log) else None
                code, out = self.run_guard("cargo", "install", *args)
                self.assertEqual(code, 0, out)
                (run,) = [r for kind, r in self.resolutions() if kind == "dependent"]
                self.assertIn(line + "\n", run["manifest"])
                self.assertEqual(self.commands()[-1], ["install", "good@=1.0.0"])

    def test_two_crates_are_resolved_apart_and_what_they_share_is_checked_once(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0", "foo_bar-0.2.0")}
        code, out = self.run_guard("cargo", "install", "good", "foo_bar")
        self.assertEqual(code, 0, out)
        self.assertEqual([kind for kind, _ in self.resolutions()], ["dependent", "crate", "dependent", "crate"])
        self.assertEqual(self.commands()[-1], ["install", "good@=1.0.0", "foo_bar@=0.2.0"])
        self.assertEqual(sorted(p for p in self.requested("/dl/")), ["/dl/foo_bar/foo_bar-0.2.0.crate", "/dl/good/good-1.0.0.crate",
                                                                    "/dl/leaf/leaf-1.0.0.crate"])
        self.assertEqual(sorted(c for c in out.split("\n") if "checked" in c), ["lazaret guard: checked 3 OK"])

    def test_the_options_after_install_go_to_cargo_as_given(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "--root", "/tmp/x", "--features", "a,b", "good")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.commands()[-1], ["install", "--root", "/tmp/x", "--features", "a,b", "good@=1.0.0"])

    def test_what_the_guard_does_not_read_is_a_usage_error(self):
        for args in (["install", "--git", "https://x/y"], ["install", "--path", "."], ["install"], ["install", "--registry", "r", "good"],
                     ["install", "--list"]):
            with self.subTest(args):
                code, out = self.run_guard("cargo", *args)
                self.assertEqual(code, 2, out)
        self.assertEqual(self.runs(), [])

    def test_a_crate_that_does_not_resolve_is_a_failed_resolution(self):
        report = os.path.join(self.tmp, "report.json")
        code, out = self.run_guard("--json", report, "cargo", "install", "nosuch")
        self.assertEqual(code, 3, out)
        self.assertEqual(json.loads(self.read(report))["installed"], False)
        self.assertIn("resolving (cargo install nosuch) failed", out)
        self.assertIn("\n  error: no matching package named `nosuch` found", out)             # (what cargo said, kept and shown by the guard)
        self.assertEqual(self.installs(), [])

    def test_a_plan_installs_nothing(self):
        code, out = self.run_guard("--plan", "cargo", "install", "good")
        self.assertEqual(code, 0, out)
        self.assertEqual([c[0] for c in self.commands()], ["generate-lockfile"] * 2)  # (the two resolutions: no `install`)
        self.assertIn("nothing blocked (--plan: nothing was installed)", out)

    def test_a_crate_unpacked_that_was_never_checked_fails_the_run(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0", "other-2.0.0")}
        code, out = self.run_guard("cargo", "install", "good")
        self.assertEqual(code, 1, out)
        self.assertIn("installed but not checked: other-2.0.0", out)

    def test_an_install_that_failed_still_says_what_it_fetched_unchecked(self):
        # (a build script runs before the build can fail: what cargo fetched unchecked is said whether it failed or not)
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0", "other-2.0.0") + [["exit", 101]]}
        code, out = self.run_guard("cargo", "install", "good")
        self.assertEqual(code, 101, out)
        self.assertNotIn("installed but not checked", out)
        self.assertIn("fetched but not checked (the command then failed): other-2.0.0", out)

    def test_the_toolchain_choice_goes_to_every_command(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "+nightly", "install", "good")
        self.assertEqual(code, 0, out)
        self.assertTrue(all(r["argv"][0] == "+nightly" for r in self.runs()))

    def test_locked_checks_the_crates_of_the_lock_the_crate_was_published_with(self):
        self.reg.add("leaf", "1.0.1")                                             # (a fresh resolution would take this one)
        published = cs.lock_text([("tool", "2.0.0", None, ["leaf"]), ("leaf", "1.0.0", self.sums["leaf"], [])])
        tool_sum = self.reg.add("tool", "2.0.0", files={"Cargo.lock": published}, deps=[("leaf", "^1")])
        self.scratch["tool"] = cs.lock_text([("lazaret-guard-plan", "0.0.0", None, ["tool"]), ("tool", "2.0.0", tool_sum, ["leaf"]),
                                             ("leaf", "1.0.1", self.reg.checksum("leaf", "1.0.1"), [])])
        self.plan = {"install": self.unpack("tool-2.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "--locked", "tool")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted(self.requested("/dl/tool") + self.requested("/dl/leaf")),
                         ["/dl/leaf/leaf-1.0.0.crate", "/dl/tool/tool-2.0.0.crate"])           # (not leaf 1.0.1)

    def test_locked_with_a_crate_that_has_no_lock_checks_the_fresh_resolution(self):
        self.plan = {"install": self.unpack("good-1.0.0", "leaf-1.0.0")}
        code, out = self.run_guard("cargo", "install", "--locked", "good")
        self.assertEqual(code, 0, out)
        self.assertIn("checked 2 OK", out)

    def test_locked_and_a_hostile_crate_in_the_published_lock_blocks(self):
        published = cs.lock_text([("tool", "3.0.0", None, ["evil"]), ("evil", "1.0.0", self.sums["evil"], [])])
        tool_sum = self.reg.add("tool", "3.0.0", files={"Cargo.lock": published})
        self.scratch["tool"] = cs.lock_text([("lazaret-guard-plan", "0.0.0", None, ["tool"]), ("tool", "3.0.0", tool_sum, [])])
        code, out = self.run_guard("cargo", "install", "--locked", "tool")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0", out)
        self.assertEqual(self.installs(), [])


def have_cargo():
    return shutil.which("cargo") is not None


class CommandLineTests(unittest.TestCase):
    """`lazaret guard cargo …` is routed to the guard, and the parser takes cargo as a tool."""

    def test_the_command_line_is_the_guards(self):
        from lazaret import _cli
        self.assertIn("cargo", _cli.GUARD_TOOLS)
        self.assertTrue(_cli.is_guard(["guard", "cargo", "build"]))
        self.assertTrue(_cli.is_guard(["guard", "--min-age", "7d", "cargo", "add", "serde"]))
        self.assertFalse(_cli.is_guard(["cargo", "build"]))

    def test_the_parser_takes_cargo_and_its_command_whole(self):
        opts = guard.build_parser().parse_args(["--plan", "cargo", "install", "--locked", "ripgrep@14.0.0"])
        self.assertEqual((opts.tool, opts.args, opts.plan), ("cargo", ["install", "--locked", "ripgrep@14.0.0"], True))
        self.assertIn("cargo", guard.build_parser().format_help())

    def test_the_limits_are_the_documented_ones(self):
        self.assertEqual((guard.MAX_MEMBERS, guard.MAX_CRATE_INDEX, guard.CRATES_API_INTERVAL), (2000, 16 * 1024 * 1024, 1.0))


@unittest.skipUnless(have_cargo(), "cargo is not installed")
class RealCargoTests(TmpCase):
    """The real cargo, against the fake registry through cargo's own source replacement: what the guard reads is what cargo uses."""

    @classmethod
    def setUpClass(cls):
        cls.reg = cs.CratesRegistry()
        cls.sums = cs.default_crates(cls.reg)
        cls.reg.add("tool", "1.0.0", files={"src/main.rs": "fn main() { println!(\"tool\"); }\n"}, deps=[("leaf", "^1")])
        cls.reg.add("badtool", "1.0.0", files={"src/main.rs": "fn main() {}\n"}, deps=[("evil", "^1")])

    @classmethod
    def tearDownClass(cls):
        cls.reg.close()

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "cargo-home")
        os.makedirs(self.home)
        with open(os.path.join(self.home, "config.toml"), "w", encoding="utf-8") as f:
            f.write(f'[source.crates-io]\nreplace-with = "mirror"\n[source.mirror]\nregistry = "sparse+{self.reg.url}"\n')
        self.dir = os.path.join(self.tmp, "proj")
        os.makedirs(os.path.join(self.dir, "src"))
        self.write("src/lib.rs", "")
        self.write("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n')
        self.env = gs.base_env(self.tmp)
        # (HOME moves into the test's folder, and rustup reads its toolchains and its default from $HOME/.rustup unless
        # RUSTUP_HOME names the place: on a CI runner nothing does, and cargo stopped at "no default is configured")
        self.env.setdefault("RUSTUP_HOME", os.path.join(os.path.expanduser("~"), ".rustup"))
        self.env.update(CARGO_HOME=self.home, HOME=self.tmp, CARGO_TARGET_DIR=os.path.join(self.tmp, "target"), CARGO_NET_RETRY="0",
                        CARGO_TERM_COLOR="never")
        self.env.pop("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", None)

    def write(self, name, text):
        with open(os.path.join(self.dir, name), "w", encoding="utf-8") as f:
            f.write(text)

    def read(self, name):
        return gs.read(os.path.join(self.dir, name))

    def latest_leaf(self):
        return max(self.reg.versions["leaf"], key=lambda v: tuple(int(n) for n in v.split(".")))

    def depend(self, name):
        self.write("Cargo.toml", self.read("Cargo.toml") + f'\n[dependencies]\n{name} = "1"\n')

    def guard(self, *args, timeout=100):
        return gs.run_guard(["--jobs", "1", "--no-cache", *args], self.dir, self.env, timeout)

    def test_a_clean_dependency_is_checked_and_then_built(self):
        self.depend("good")
        code, out = self.guard("cargo", "build")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: 2 crates to check (Cargo.lock)\n", out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertNotIn("installed but not checked", out)
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "target", "debug")))
        self.assertTrue(os.path.isdir(os.path.join(self.home, "registry", "src")))

    def test_a_plan_runs_no_compiler_or_wrapper_the_project_names(self):
        """GR-1: cargo asks the compiler's version while it resolves (`rustc -vV`), through the project's
        build.rustc-wrapper, build.rustc-workspace-wrapper and build.rustc; under --plan it runs none of them. Without
        --plan the command runs as the project configures it, and cargo runs them."""
        marker = os.path.join(self.tmp, "ran.log")
        script = os.path.join(self.tmp, "wrap.sh")
        with open(script, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\necho "$*" >> "{marker}"\nif [ "$1" = "-vV" ]; then exec rustc "$@"; fi\nexec "$@"\n')
        os.chmod(script, 0o755)
        os.makedirs(os.path.join(self.dir, ".cargo"))
        # (cargo 1.95 asks the compiler when it updates a lock that exists)
        lock = 'version = 4\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n'
        for k, key in enumerate(("rustc-wrapper", "rustc-workspace-wrapper", "rustc")):
            with self.subTest(key=key):
                self.write(".cargo/config.toml", f'[build]\n{key} = "{script}"\n')
                self.write("Cargo.lock", lock)
                # (each run with a target folder of its own: cargo keeps what the compiler said there)
                self.env["CARGO_TARGET_DIR"] = os.path.join(self.tmp, f"target-{k}")
                code, out = self.guard("cargo", "update")
                self.assertEqual(code, 0, out)
                self.assertTrue(os.path.exists(marker), "cargo itself runs what the project names")
                os.remove(marker)
                self.env["CARGO_TARGET_DIR"] = os.path.join(self.tmp, f"target-{k}-plan")
                self.write("Cargo.lock", lock)
                code, out = self.guard("--plan", "cargo", "update")
                self.assertEqual(code, 0, out)
                self.assertFalse(os.path.exists(marker), gs.read(marker))

    def test_a_hostile_dependency_never_reaches_cargo(self):
        self.depend("parent")
        code, out = self.guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertIsNone(self.read("Cargo.lock"))                                      # (put back: there was none)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "target")))
        self.assertFalse(os.path.exists(os.path.join(self.home, "registry", "src")))     # (cargo did not unpack anything)
        self.assertFalse(os.path.exists(os.path.join(self.home, "registry", "cache")))   # (nor download it)

    def test_cargo_add_of_a_hostile_crate_leaves_the_manifest_as_it_was(self):
        before = self.read("Cargo.toml")
        code, out = self.guard("cargo", "add", "parent")
        self.assertEqual(code, 1, out)
        self.assertEqual(self.read("Cargo.toml"), before)
        self.assertIsNone(self.read("Cargo.lock"))
        code, out = self.guard("cargo", "add", "good")
        self.assertEqual(code, 0, out)
        self.assertIn("good", self.read("Cargo.toml"))
        self.assertIn('name = "leaf"', self.read("Cargo.lock"))

    def test_the_crates_cargo_unpacked_are_the_ones_the_lock_names(self):
        self.depend("good")
        code, out = self.guard("cargo", "fetch")
        self.assertEqual(code, 0, out)
        locked = {f"{p.name}-{p.version}" for p in cargosrc.parse_lock(self.read("Cargo.lock")) if p.source}
        self.assertEqual(locked, {"good-1.0.0", f"leaf-{self.latest_leaf()}"})
        self.assertEqual(cargosrc.crate_dirs(self.home), locked)

    def test_a_release_too_new_is_held_off(self):
        self.depend("onlynew")
        code, out = self.guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    onlynew@1.0.0: published 1 hour ago, under --min-age 2 days", out)
        code, out = self.guard("--allow-new", "onlynew", "cargo", "build")
        self.assertEqual(code, 0, out)

    def test_cargo_install_checks_what_it_would_build_and_installs(self):
        root = os.path.join(self.tmp, "root")
        code, out = self.guard("cargo", "install", "--root", root, "tool")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertTrue(os.path.exists(os.path.join(root, "bin", "tool")))

    def test_cargo_install_of_a_tool_with_a_hostile_dependency_installs_nothing(self):
        root = os.path.join(self.tmp, "root")
        code, out = self.guard("cargo", "install", "--root", root, "badtool")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0", out)
        self.assertFalse(os.path.exists(root))
        self.assertFalse(os.path.exists(os.path.join(self.home, "registry", "src")))

    def test_what_a_feature_of_an_installed_crate_brings_in_is_checked(self):
        # (cargo install resolves a crate's lock with every feature of it on, and `--features` turns one on; the guard asked
        # for the default features only, so a dependency a feature brings in was built unchecked: the Go/Rust review's CG-2)
        self.reg.add("feattool", "1.0.0", files={"src/main.rs": "fn main() {}\n"}, deps=[("leaf", "^1")],
                     optional=[("evil", "^1")], features={"extra": ["dep:evil"]})
        root = os.path.join(self.tmp, "root")
        code, out = self.guard("cargo", "install", "--root", root, "--features", "extra", "feattool")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0", out)
        self.assertFalse(os.path.exists(root))

    def test_a_crate_another_tool_unpacked_is_checked_before_cargo_builds_it(self):
        # (an editor or `cargo tree` unpacks crates without running them; the guard left unpacked crates out, and cargo built
        # them without fetching them again: the Go/Rust review's CG-3)
        self.depend("parent")
        tree = subprocess.run(["cargo", "tree"], cwd=self.dir, env=self.env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=40)
        self.assertEqual(tree.returncode, 0, tree.stderr)
        self.assertIn("evil-1.0.0", cargosrc.crate_dirs(self.home))
        code, out = self.guard("cargo", "build")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0: SUSPICIOUS", out)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "target")))

    def test_cargo_install_reads_no_settings_from_the_folders_above_its_scratch_project(self):
        # (the Go/Rust review's CG-1: the scratch project sat in /tmp, and cargo looks for its configuration and a
        # workspace, and rustup for a toolchain file, in every folder above where cargo runs or the manifest is: files
        # another user planted there ran a program of theirs, or made the scratch lock empty, so nothing was checked)
        base = self.env["LAZARET_GUARD_SCRATCH"]
        marker = os.path.join(self.tmp, "planted-ran")
        planted = os.path.join(self.tmp, "planted", "bin")
        os.makedirs(planted)
        for tool in ("planted.sh", "cargo", "rustc"):
            with open(os.path.join(planted, tool), "w", encoding="utf-8") as f:
                f.write(f'#!/bin/sh\necho "$0" >> "{marker}"\n' + ('exec "$@"\n' if tool == "planted.sh" else "exit 1\n"))
            os.chmod(os.path.join(planted, tool), 0o755)
        os.makedirs(os.path.join(base, ".cargo"))
        with open(os.path.join(base, ".cargo", "config.toml"), "w", encoding="utf-8") as f:
            f.write(f'[resolver]\nincompatible-rust-versions = "fallback"\n[build]\nrustc-wrapper = "{planted}/planted.sh"\n')
        with open(os.path.join(base, "Cargo.toml"), "w", encoding="utf-8") as f:
            f.write('[workspace]\nmembers = ["*/*"]\nresolver = "2"\n')
        with open(os.path.join(base, "rust-toolchain.toml"), "w", encoding="utf-8") as f:
            f.write(f'[toolchain]\npath = "{os.path.dirname(planted)}"\n')
        root = os.path.join(self.tmp, "root")
        code, out = self.guard("cargo", "install", "--root", root, "badtool")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil@1.0.0", out)
        self.assertFalse(os.path.exists(marker), out)
        self.assertFalse(os.path.exists(os.path.join(base, "Cargo.lock")))

    def test_cargo_install_locked_uses_the_lock_the_crate_was_published_with(self):
        self.reg.add("pleaf", "1.0.0")
        self.reg.add("pleaf", "1.0.1")                                                      # (a fresh resolution would take this one)
        published = cs.lock_text([("pinned", "1.0.0", None, ["pleaf"]), ("pleaf", "1.0.0", self.reg.checksum("pleaf", "1.0.0"), [])])
        self.reg.add("pinned", "1.0.0", files={"src/main.rs": "fn main() {}\n", "Cargo.lock": published}, deps=[("pleaf", "^1")])
        root = os.path.join(self.tmp, "root")
        before = len(self.reg.requests)
        code, out = self.guard("cargo", "install", "--locked", "--root", root, "pinned")
        self.assertEqual(code, 0, out)
        asked = self.reg.requests[before:]
        self.assertIn("/dl/pleaf/pleaf-1.0.0.crate", asked)
        self.assertNotIn("/dl/pleaf/pleaf-1.0.1.crate", asked)
        self.assertTrue(os.path.exists(os.path.join(root, "bin", "pinned")))

if __name__ == "__main__":
    unittest.main()
