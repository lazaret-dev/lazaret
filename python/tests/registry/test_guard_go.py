"""lazaret guard go (0.1.9, G-3): the Go proxy on this machine that scans each module zip before the go command has it.

Four kinds of test. The relay on its own, asked over HTTP what the go command asks, with a stand-in scanner and a fake module proxy
(tests/registry/_go_support.py). The helpers that read go's settings and the module cache. The command, run as `python -m
lazaret.registry.guard go …`, with a fake `go` that does exactly what each case needs (fetch this path, leave that in the module
cache), so the exit codes, the files put back and the report are known. And the real go command, against the fake proxy, where go
is installed (skipped where it is not).

What the scan finds in a Go module today is what it finds in any archive (JavaScript and Python files, install hooks, binaries,
archive structure); the Go and Rust rules of the engine read `.go` files from the 0.1.9 wiring on."""

import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
import zipfile
from unittest import mock

from lazaret.registry import goproxy, guard, pmsettings, repo
from tests.registry import _go_support as go
from tests.registry import _guard_support as gs
from tests.registry.test_guard import options

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class FakeScanner:
    """Stands in for guard.Scanner: a zip with a JavaScript file in it is SUSPICIOUS, any other is OK."""

    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.remembered = []

    def cached(self, key):
        return None

    def remember(self, key, hit, published):
        self.remembered.append((key, hit["verdict"], published))

    def scan(self, data, container, kind):
        self.calls.append((container, kind))
        if self.error is not None:
            raise self.error
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        if any(n.endswith(".js") for n in names):
            return {"verdict": "SUSPICIOUS", "reason": "1 strong supply-chain indicator", "indicators": ["SC-USE-RISK x.js"]}
        return {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": []}

    def close(self):
        pass


def ask(base, path):
    """GET base+path -> (status, body)."""
    try:
        with OPENER.open(urllib.request.Request(base + path), timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class RelayCase(unittest.TestCase):
    def setUp(self):
        self.proxy = go.GoProxy()
        go.default_modules(self.proxy)
        self.addCleanup(self.proxy.close)
        self.out = io.StringIO()

    def context(self, **kw):
        ctx = guard.Context(options(tool="go", **kw), out=self.out)
        ctx.scanner = FakeScanner()
        self.addCleanup(ctx.close)
        return ctx

    def serve(self, ctx, proxies=None, creds=None):
        lp = guard.LocalGoProxy(ctx, proxies or [goproxy.Proxy(self.proxy.url, False)], creds or pmsettings.Credentials())
        lp.__enter__()
        self.addCleanup(lp.__exit__, None, None, None)
        return lp


class ZipTests(RelayCase):
    def test_a_clean_zip_is_handed_over_as_it_came(self):
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual((status, body), (200, self.proxy.modules["example.test/good"]["v1.0.0"]["zip"]))
        (check,) = ctx.checks
        self.assertEqual((check.eco, check.name, check.version, check.verdict, check.blocked), ("go", "example.test/good", "v1.0.0", "OK", []))
        self.assertRegex(check.digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(ctx.scanner.calls, [("zip", "gomod")])
        self.assertEqual([r[1] for r in ctx.scanner.remembered], ["OK"])

    def test_a_zip_is_fetched_and_scanned_once(self):
        ctx = self.context()
        lp = self.serve(ctx)
        for _ in range(3):
            self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(len(ctx.scanner.calls), 1)
        self.assertEqual(len(self.proxy.paths("/example.test/good/@v/v1.0.0.zip")), 1)
        self.assertEqual(len(ctx.checks), 1)

    def test_a_suspicious_zip_is_refused_and_says_why(self):
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/evil/@v/v1.0.0.zip")
        self.assertEqual(status, 403)
        self.assertEqual(body, b"blocked by lazaret guard: SUSPICIOUS: 1 strong supply-chain indicator\n")
        (check,) = ctx.blocked()
        self.assertEqual((check.name, check.version), ("example.test/evil", "v1.0.0"))
        self.assertEqual(ask(lp.base, "/example.test/evil/@v/v1.0.0.zip")[0], 403)           # (again: not scanned again)
        self.assertEqual(len(ctx.scanner.calls), 1)

    def test_trust_lets_a_flagged_zip_through_and_says_so(self):
        ctx = self.context(trust=["example.test/evil"])
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/evil/@v/v1.0.0.zip")[0], 200)
        (check,) = ctx.checks
        self.assertTrue(check.trusted)
        self.assertEqual(check.blocked, [])
        self.assertIn("installed anyway (--trust): SUSPICIOUS", check.notes[0])

    def test_block_warn_refuses_what_could_not_be_scanned_fully(self):
        with mock.patch.object(repo, "MAX_DOWNLOAD_BYTES", 100):
            for block_warn, status in ((False, 200), (True, 403)):
                with self.subTest(block_warn=block_warn):
                    ctx = self.context(block_warn=block_warn)
                    lp = self.serve(ctx)
                    got = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
                    self.assertEqual(got[0], status)
                    if status == 200:                                                # (relayed as it comes)
                        self.assertEqual(got[1], self.proxy.modules["example.test/good"]["v1.0.0"]["zip"])
                    (check,) = ctx.checks
                    self.assertEqual(check.verdict, "INCOMPLETE")
                    self.assertEqual(ctx.scanner.calls, [])

    def test_a_zip_that_cannot_be_scanned_is_refused(self):
        ctx = self.context()
        ctx.scanner = FakeScanner(error=guard.ScanError("the scan did not finish"))
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual(status, 403)
        self.assertIn(b"could not be checked: the scan did not finish", body)
        self.assertEqual(len(ctx.blocked()), 1)

    def test_a_module_with_capitals_is_asked_for_encoded_and_named_decoded(self):
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/!big!case/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(ctx.checks[0].name, "example.test/BigCase")
        self.assertIn("/example.test/!big!case/@v/v1.0.0.zip", self.proxy.paths())
        self.assertEqual(ask(lp.base, "/example.test/BigCase/@v/v1.0.0.zip")[0], 404)         # (not encoded: not a request)

    def test_a_zip_the_proxy_does_not_have_is_not_found_and_leaves_no_check(self):
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/v9.9.9.zip")[0], 404)
        self.assertEqual(ask(lp.base, "/example.test/nothing/@v/v1.0.0.zip")[0], 404)
        self.assertEqual(ctx.checks, [])

    def test_a_go_toolchain_is_handed_over_unscanned(self):
        self.proxy.add("golang.org/toolchain", "v0.0.1-go1.99.0.linux-amd64", files={"VERSION": "go1.99.0\n"})
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/golang.org/toolchain/@v/v0.0.1-go1.99.0.linux-amd64.zip")
        self.assertEqual(status, 200)
        self.assertEqual(body, self.proxy.modules["golang.org/toolchain"]["v0.0.1-go1.99.0.linux-amd64"]["zip"])
        self.assertEqual(ctx.scanner.calls, [])
        self.assertIn("checks it against the checksum database itself", ctx.checks[0].notes[0])

    def test_what_a_proxy_redirects_to_is_followed(self):
        self.proxy.redirect = True
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual((status, body), (200, self.proxy.modules["example.test/good"]["v1.0.0"]["zip"]))
        self.assertEqual(len([p for p in self.proxy.paths() if p.startswith("/blob/")]), 1)


class AgeTests(RelayCase):
    def test_a_zip_younger_than_min_age_is_refused_before_it_is_fetched(self):
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/onlynew/@v/v1.0.0.zip")
        self.assertEqual(status, 403)
        self.assertIn(b"published 1 hour ago, under --min-age 2 days (--allow-new example.test/onlynew lets it through)", body)
        self.assertEqual(self.proxy.paths(".zip"), [])
        self.assertEqual(ctx.scanner.calls, [])
        (check,) = ctx.blocked()
        self.assertEqual(check.age // 3600, 1)

    def test_allow_new_lets_it_in_and_it_is_still_scanned(self):
        ctx = self.context(allow_new=["example.test/onlynew"])
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/onlynew/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(len(ctx.scanner.calls), 1)
        self.assertIn("let through by --allow-new", ctx.checks[0].notes[0])

    def test_min_age_zero_holds_nothing_back(self):
        ctx = self.context(min_age=0)
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/onlynew/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(ask(lp.base, "/example.test/mixed/@v/list")[1], b"v1.0.0\nv1.1.0\n")
        self.assertEqual(self.proxy.paths(".info"), [])

    def test_a_list_leaves_out_the_versions_younger_than_min_age(self):
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/mixed/@v/list")
        self.assertEqual((status, body), (200, b"v1.0.0\n"))
        held = lp.relay.held_back
        self.assertEqual(list(held), ["example.test/mixed"])
        self.assertEqual(list(held["example.test/mixed"]), ["v1.1.0"])
        self.assertEqual(ctx.blocked(), [])                                                 # (held back is not blocked)

    def test_a_list_with_nothing_new_in_it_is_the_proxys(self):
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list"), (200, b"v1.0.0\n"))
        self.assertEqual(lp.relay.held_back, {})

    def test_allow_new_keeps_a_new_version_in_the_list(self):
        ctx = self.context(allow_new=["example.test/mixed"])
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/mixed/@v/list")[1], b"v1.0.0\nv1.1.0\n")

    def test_only_the_newest_versions_are_looked_up(self):
        for minor in range(40):
            self.proxy.add("example.test/many", f"v1.{minor}.0")
        ctx = self.context()
        lp = self.serve(ctx)
        with mock.patch.object(guard, "GO_PROBES", 5):
            status, body = ask(lp.base, "/example.test/many/@v/list")
        self.assertEqual(status, 200)
        self.assertEqual(len(body.split()), 40)
        asked = sorted(p.rsplit("/", 1)[1] for p in self.proxy.paths(".info"))
        self.assertEqual(asked, sorted(f"v1.{m}.0.info" for m in range(35, 40)))

    def test_what_is_not_a_version_is_not_listed(self):
        self.proxy.fail["/example.test/good/@v/list"] = (200, b"v1.0.0\n\nnot-a-version\n../../x\nv1.1.0\n")
        ctx = self.context(min_age=0)
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[1], b"v1.0.0\nv1.1.0\n")

    def test_an_info_of_a_new_version_is_refused_and_is_not_a_block(self):
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/mixed/@v/v1.1.0.info")
        self.assertEqual(status, 403)
        self.assertEqual(body, b"lazaret guard: example.test/mixed@v1.1.0 was published 1 hour ago, under --min-age 2 days\n")
        self.assertEqual(list(lp.relay.held_back["example.test/mixed"]), ["v1.1.0"])
        self.assertEqual(ctx.blocked(), [])

    def test_an_info_of_an_old_version_is_the_proxys_and_asked_for_once(self):
        ctx = self.context()
        lp = self.serve(ctx)
        ask(lp.base, "/example.test/mixed/@v/list")                                         # (looks both up)
        status, body = ask(lp.base, "/example.test/mixed/@v/v1.0.0.info")
        self.assertEqual((status, body), (200, self.proxy.info("example.test/mixed", "v1.0.0")))
        self.assertEqual(len(self.proxy.paths("/example.test/mixed/@v/v1.0.0.info")), 1)

    def test_a_branch_or_latest_is_judged_by_the_version_it_names(self):
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/good/@latest")[0], 200)
        self.assertEqual(ask(lp.base, "/example.test/mixed/@latest")[0], 403)                # (v1.1.0 is the latest)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/main.info")[0], 404)            # (the fake proxy knows no branches)
        self.assertEqual(ctx.blocked(), [])

    def test_a_go_mod_is_the_proxys_whatever_its_age(self):
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/onlynew/@v/v1.0.0.mod"),
                         (200, self.proxy.modules["example.test/onlynew"]["v1.0.0"]["mod"].encode()))

    def test_an_answer_that_is_not_a_version_is_an_error_not_a_pass(self):
        for body in (b"[]", b'{"Time": "2020-01-01T00:00:00Z"}', b'{"Version": "../x"}', b"not json"):
            with self.subTest(body):
                self.proxy.fail["/example.test/good/@latest"] = (200, body)
                ctx = self.context()
                lp = self.serve(ctx)
                self.assertEqual(ask(lp.base, "/example.test/good/@latest")[0], 502)


class RequestTests(RelayCase):
    def test_a_request_that_is_not_the_protocols_is_not_asked_of_the_proxy(self):
        ctx = self.context()
        lp = self.serve(ctx)
        for path in ("/", "/etc/passwd", "/example.test/good/@v/../x.zip", "/example.test/good/@v/v1.0.0.txt",
                     "/example.test/good/@x", "/example.test/GOOD/@v/list", "/sumdb/../etc"):
            with self.subTest(path):
                self.assertEqual(ask(lp.base, path)[0], 404)
        self.assertEqual(self.proxy.requests, [])

    def test_the_checksum_database_is_relayed(self):
        self.proxy.sumdb["/sumdb/sum.golang.org/supported"] = b""
        self.proxy.sumdb["/sumdb/sum.golang.org/tile/8/0/001"] = b"\x00\x01tile"
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/sumdb/sum.golang.org/supported"), (200, b""))
        self.assertEqual(ask(lp.base, "/sumdb/sum.golang.org/tile/8/0/001"), (200, b"\x00\x01tile"))
        self.assertEqual(ask(lp.base, "/sumdb/sum.golang.org/lookup/x")[0], 404)
        self.assertEqual(ctx.checks, [])

    def test_head_gets_the_headers_of_the_answer(self):
        ctx = self.context()
        lp = self.serve(ctx)
        req = urllib.request.Request(lp.base + "/example.test/good/@v/list", method="HEAD")
        with OPENER.open(req, timeout=30) as r:
            self.assertEqual((r.status, r.read()), (200, b""))


class ProxyListTests(RelayCase):
    def two(self):
        first = go.GoProxy()
        self.addCleanup(first.close)
        return first

    def test_a_missing_module_goes_on_to_the_next_proxy(self):
        first = self.two()
        ctx = self.context()
        lp = self.serve(ctx, [goproxy.Proxy(first.url, False), goproxy.Proxy(self.proxy.url, False)])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 200)
        self.assertEqual([p for _, p in first.requests], ["/example.test/good/@v/list", "/example.test/good/@v/v1.0.0.info"])
        self.assertEqual(ctx.checks, [])

    def test_a_gone_module_does_too(self):
        first = self.two()
        first.fail[""] = (410, b"gone")
        ctx = self.context()
        lp = self.serve(ctx, [goproxy.Proxy(first.url, False), goproxy.Proxy(self.proxy.url, False)])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 200)

    def test_an_error_stops_at_a_comma_and_goes_on_after_a_bar(self):
        for fall_back, status in ((False, 502), (True, 200)):
            with self.subTest(fall_back=fall_back):
                first = self.two()
                first.fail[""] = (500, b"broken")
                ctx = self.context()
                lp = self.serve(ctx, [goproxy.Proxy(first.url, fall_back), goproxy.Proxy(self.proxy.url, False)])
                self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], status)

    def test_a_list_that_ends_in_direct_does_not_fetch_from_version_control(self):
        ctx = self.context()
        lp = self.serve(ctx, [goproxy.Proxy(self.proxy.url, False), goproxy.Proxy("direct", False)])
        self.assertEqual(ask(lp.base, "/example.test/nothing/@v/list")[0], 404)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 200)

    def test_an_error_before_direct_is_an_error_and_a_missing_module_is_not_found(self):
        for failure, status in (((500, b"broken"), 502), ((404, b"missing"), 404)):
            with self.subTest(failure=failure):
                first = self.two()
                first.fail[""] = failure
                ctx = self.context()
                lp = self.serve(ctx, [goproxy.Proxy(first.url, True), goproxy.Proxy("direct", False)])
                self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], status)

    def test_off_is_an_error(self):
        ctx = self.context()
        lp = self.serve(ctx, [goproxy.Proxy("off", False)])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 502)
        self.assertIn("GOPROXY is off", lp.relay.errors[0])

    def test_the_tool_gets_fixed_text_and_the_reason_goes_in_the_report(self):
        self.proxy.fail["/example.test/good/@v/v1.0.0.zip"] = (500, b"secret detail of the proxy")
        ctx = self.context()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual(status, 403)                         # (a zip that could not be fetched is blocked: it was not checked)
        self.assertNotIn(b"secret detail", body)
        status, body = ask(lp.base, "/example.test/good/@v/list")
        self.assertEqual(status, 200)
        self.proxy.fail["/example.test/leaf/@v/list"] = (500, b"secret detail of the proxy")
        status, body = ask(lp.base, "/example.test/leaf/@v/list")
        self.assertEqual((status, body), (502, b"lazaret guard could not fetch this from the proxy it relays\n"))
        self.assertIn("HTTP 500", lp.relay.errors[-1])

    def test_credentials_are_sent_to_the_proxy_that_wants_them(self):
        header = pmsettings.basic("user", "secret")
        self.proxy.auth = header
        creds = pmsettings.Credentials()
        creds.login(self.proxy.url + "/", "user", "secret", whole_host=True)
        ctx = self.context()
        lp = self.serve(ctx, creds=creds)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.zip")[0], 200)
        self.assertTrue(self.proxy.authorizations)
        self.assertEqual({a for _, a in self.proxy.authorizations}, {header})

    def test_without_them_the_tool_gets_an_error_and_the_report_says_why(self):
        self.proxy.auth = pmsettings.basic("user", "secret")
        ctx = self.context()
        lp = self.serve(ctx)
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 502)
        self.assertIn("HTTP 401", lp.relay.errors[0])

    def test_redirects_may_lead_to_any_https_host_when_the_fetcher_is_told_so(self):
        for allowed in (False, True):
            f = guard.Fetcher({"proxy.example"}, https_redirects=allowed)
            f.check("https://proxy.example/x")
            for url, redirect, ok in (("https://storage.example/blob", True, allowed), ("https://storage.example/blob", False, False),
                                      ("http://storage.example/blob", True, False), ("https://proxy.example/y", True, True)):
                with self.subTest(allowed=allowed, url=url, redirect=redirect):
                    if ok:
                        self.assertEqual(f.check(url, redirect=redirect), url)
                    else:
                        with self.assertRaises(repo.FetchError):
                            f.check(url, redirect=redirect)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        self.addCleanup(guard.remove_tree, self.tmp)

    def touch(self, *parts):
        path = os.path.join(self.tmp, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"x")
        return path

    def test_the_module_cache_lists_the_zips_by_their_decoded_names(self):
        self.touch("cache", "download", "example.test", "!big!case", "@v", "v1.0.0.zip")
        self.touch("cache", "download", "example.test", "!big!case", "@v", "v1.0.0.mod")
        self.touch("cache", "download", "example.test", "!big!case", "@v", "v1.0.0.info")
        self.touch("cache", "download", "golang.org", "x", "net", "@v", "v0.1.0.zip")
        self.touch("cache", "download", "golang.org", "x", "net", "@v", "v0.2.0.zip")
        self.touch("cache", "download", "sumdb", "sum.golang.org", "x", "@v", "v9.zip")      # (not a module)
        self.touch("cache", "download", "example.test", "bad!", "@v", "v1.0.0.zip")           # (not an encoding)
        self.touch("cache", "download", "example.test", "good", "@v", "V1.zip")
        self.touch("example.test", "BigCase@v1.0.0", "m.go")                                  # (an unpacked module is not a zip)
        self.assertEqual(guard.cached_modules(self.tmp),
                         {("example.test/BigCase", "v1.0.0"), ("golang.org/x/net", "v0.1.0"), ("golang.org/x/net", "v0.2.0")})

    def test_no_module_cache_is_nothing_cached(self):
        self.assertEqual(guard.cached_modules(os.path.join(self.tmp, "none")), set())
        self.assertEqual(guard.cached_modules(""), set())

    def test_the_files_a_go_command_may_change(self):
        gomod = os.path.join(self.tmp, "proj", "go.mod")
        settings = {"GOMOD": gomod, "GOWORK": ""}
        self.assertEqual(guard.go_module_files(settings, ["get", "x"], self.tmp), [gomod, os.path.join(self.tmp, "proj", "go.sum")])
        self.assertEqual(guard.go_module_files({"GOMOD": os.devnull, "GOWORK": ""}, ["get", "x"], self.tmp), [])
        self.assertEqual(guard.go_module_files({}, ["get", "x"], self.tmp), [])
        work = os.path.join(self.tmp, "go.work")
        self.assertEqual(guard.go_module_files({"GOMOD": os.devnull, "GOWORK": work}, ["get"], self.tmp), [work, work + ".sum"])
        self.assertEqual(guard.go_module_files({"GOWORK": "off"}, ["get"], self.tmp), [])
        files = guard.go_module_files(settings, ["build", "-modfile=alt.mod", "./..."], os.path.join(self.tmp, "proj"))
        self.assertEqual(files[2:], [os.path.join(self.tmp, "proj", "alt.mod"), os.path.join(self.tmp, "proj", "alt.sum")])
        files = guard.go_module_files(settings, ["build", "-modfile", "alt", "./..."], os.path.join(self.tmp, "proj"))
        self.assertEqual(files[2:], [os.path.join(self.tmp, "proj", "alt"), os.path.join(self.tmp, "proj", "alt.sum")])

    def test_flags(self):
        self.assertEqual(guard._go_flag(["-modfile", "a.mod", "x"], "modfile"), "a.mod")
        self.assertEqual(guard._go_flag(["-modfile=a.mod"], "modfile"), "a.mod")
        self.assertEqual(guard._go_flag(["--modfile=a.mod"], "modfile"), "a.mod")
        self.assertIsNone(guard._go_flag(["-modfile"], "modfile"))
        self.assertIsNone(guard._go_flag(["-modfiles=a.mod", "x"], "modfile"))
        self.assertEqual(guard._go_chdir(["build", "-C", "d", "./..."]), "d")
        self.assertEqual(guard._go_chdir(["build", "-C=d"]), "d")
        self.assertEqual(guard._go_chdir(["build", "--C=d"]), "d")
        self.assertIsNone(guard._go_chdir(["build", "-C"]))
        self.assertIsNone(guard._go_chdir(["build", "./...", "-C", "d"]))                    # (go wants it first)
        self.assertIsNone(guard._go_chdir(["build"]))
        self.assertIsNone(guard._go_chdir([]))

    def test_what_a_plan_fetches(self):
        plan = guard.go_plan
        self.assertEqual(plan(["get", "-u", "x.io/m@v1"], "S"), (["get", "-u", "x.io/m@v1"], None))
        self.assertEqual(plan(["mod", "tidy"], "S"), (["mod", "tidy"], None))
        self.assertEqual(plan(["mod", "download"], "S"), (["mod", "download"], None))
        self.assertEqual(plan(["install", "x.io/a@v1", "x.io/b@latest"], "S"), (["get", "x.io/a@v1", "x.io/b@latest"], "S"))
        self.assertEqual(plan(["install", "-v", "x.io/a@v1"], "S"), (["get", "x.io/a@v1"], "S"))
        self.assertEqual(plan(["run", "x.io/a@v1", "arg@here"], "S"), (["get", "x.io/a@v1"], "S"))
        for command in (["install", "./cmd/x"], ["run", "."], ["build", "./..."], ["test", "./..."], ["vet", "./..."], ["list", "-m", "all"]):
            with self.subTest(command):
                self.assertEqual(plan(command, "S"), (["mod", "download"], None))
        self.assertEqual(plan(["build", "-C", "d", "./..."], "S"), (["mod", "download", "-C", "d"], None))

    def test_a_read_only_folder_is_removed(self):
        path = self.touch("ro", "a", "b", "f")
        os.chmod(os.path.dirname(path), stat.S_IRUSR | stat.S_IXUSR)
        os.chmod(os.path.dirname(os.path.dirname(path)), stat.S_IRUSR | stat.S_IXUSR)
        guard.remove_tree(os.path.join(self.tmp, "ro"))
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ro")))


class FlowCase(unittest.TestCase):
    """`lazaret guard go …` run as the command, with a fake go: what it does is the test's to say."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        cls.bin = os.path.join(cls.tmp, "bin")
        os.makedirs(cls.bin)
        go.install_fake_go(cls.bin)
        cls.proxy = go.GoProxy()
        go.default_modules(cls.proxy)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.close()
        guard.remove_tree(cls.tmp)

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="proj-", dir=self.tmp)
        self.modcache = os.path.join(self.dir, "modcache")
        self.gomod = os.path.join(self.dir, "go.mod")
        self.gosum = os.path.join(self.dir, "go.sum")
        self.log = os.path.join(self.dir, "go.log")
        with open(self.gomod, "w", encoding="utf-8") as f:
            f.write("module example.test/app\n\ngo 1.21\n")
        self.goenv = {"GOPROXY": self.proxy.url, "GOMODCACHE": self.modcache, "GOMOD": self.gomod, "GOPRIVATE": ""}
        self.plan = []

    def run_guard(self, *args, goenv=None, broken=False, timeout=40):
        env = gs.base_env(self.tmp)
        env.update(PATH=self.bin + os.pathsep + os.environ.get("PATH", ""),
                   FAKE_GO_ENV=json.dumps(None if broken else (goenv if goenv is not None else self.goenv)),
                   FAKE_GO_PLAN=json.dumps(self.plan), FAKE_GO_LOG=self.log)
        return gs.run_guard(["--jobs", "1", "--no-cache", *args], self.dir, env, timeout)

    def runs(self):
        with open(self.log, encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def zip_step(self, module, version, dest=None):
        return ["get", f"/{go.encode(module)}/@v/{version}.zip", dest or os.path.join(self.dir, "got", module + "@" + version)]

    def read(self, path):
        return gs.read(path)


class CommandTests(FlowCase):
    def test_the_command_runs_as_given_against_the_guards_proxy(self):
        self.plan = [self.zip_step("example.test/good", "v1.0.0")]
        code, out = self.run_guard("go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        (run,) = self.runs()
        self.assertEqual(run["argv"], ["get", "example.test/good@v1.0.0"])
        self.assertRegex(run["GOPROXY"], r"^http://127\.0\.0\.1:\d+$")
        self.assertNotEqual(run["GOPROXY"], self.proxy.url)
        self.assertIsNone(run["GOMODCACHE"])                                                 # (the tool's own, as `go env` said)
        self.assertTrue(os.path.samefile(run["cwd"], self.dir))
        self.assertIn("lazaret guard: relaying " + self.proxy.url + "/", out)
        self.assertIn("lazaret guard: releases younger than 2 days are held back at the proxy", out)
        self.assertIn("lazaret guard: checked 1 OK", out)

    def test_nothing_is_said_of_holding_back_with_no_age(self):
        self.plan = [self.zip_step("example.test/good", "v1.0.0")]
        code, out = self.run_guard("--min-age", "0", "go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertNotIn("held back at the proxy", out)

    def test_a_blocked_module_puts_back_go_mod_and_go_sum_and_stops_the_run(self):
        before = self.read(self.gomod)
        self.plan = [["append", self.gomod, "\nrequire example.test/parent v1.0.0\n"], ["write", self.gosum, "sum\n"],
                     self.zip_step("example.test/good", "v1.0.0"), self.zip_step("example.test/evil", "v1.0.0")]
        code, out = self.run_guard("go", "get", "example.test/parent@v1.0.0")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    example.test/evil@v1.0.0: SUSPICIOUS", out)
        self.assertIn("1 blocked — nothing was installed; go.mod and go.sum put back", out)
        self.assertIn("modules that passed are in go's module cache", out)
        self.assertEqual(self.read(self.gomod), before)
        self.assertFalse(os.path.exists(self.gosum))

    def test_what_passed_keeps_its_changes(self):
        self.plan = [["append", self.gomod, "\nrequire example.test/good v1.0.0\n"], ["write", self.gosum, "sum\n"],
                     self.zip_step("example.test/good", "v1.0.0")]
        code, out = self.run_guard("go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("require example.test/good v1.0.0", self.read(self.gomod))
        self.assertEqual(self.read(self.gosum), "sum\n")
        self.assertNotIn("put back", out)

    def test_trust_lets_a_flagged_module_through(self):
        self.plan = [self.zip_step("example.test/evil", "v1.0.0")]
        code, out = self.run_guard("--trust", "example.test/evil", "go", "get", "example.test/evil@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("TRUSTED    example.test/evil@v1.0.0: installed anyway (--trust): SUSPICIOUS", out)

    def test_go_s_own_exit_code_is_the_guards(self):
        self.plan = [["exit", 7]]
        code, out = self.run_guard("go", "mod", "tidy")
        self.assertEqual(code, 7, out)

    def test_a_module_held_back_as_too_new_is_reported_and_go_fails_as_it_does(self):
        self.plan = [["get", "/example.test/mixed/@v/v1.1.0.info"]]
        code, out = self.run_guard("go", "get", "example.test/mixed@v1.1.0")
        self.assertEqual(code, 1, out)
        self.assertIn("held back  example.test/mixed: 1 release younger than 2 days", out)
        self.assertIn("--allow-new example.test/mixed lets them in", out)

    def test_json_says_what_was_checked(self):
        self.plan = [self.zip_step("example.test/good", "v1.0.0"), self.zip_step("example.test/evil", "v1.0.0")]
        out_json = os.path.join(self.dir, "report.json")
        code, out = self.run_guard("--json", out_json, "go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 1, out)
        doc = json.loads(self.read(out_json))
        self.assertEqual((doc["tool"], doc["command"], doc["blocked"], doc["exitCode"], doc["installed"]),
                         ("go", ["get", "example.test/good@v1.0.0"], 1, 1, False))
        names = {(p["ecosystem"], p["name"], p["verdict"]) for p in doc["packages"]}
        self.assertEqual(names, {("go", "example.test/good", "OK"), ("go", "example.test/evil", "SUSPICIOUS")})
        self.assertEqual(doc["heldBack"], {})


class PlanTests(FlowCase):
    def test_a_plan_runs_in_a_cache_of_its_own_and_puts_the_files_back(self):
        before = self.read(self.gomod)
        self.plan = [["append", self.gomod, "\nrequire example.test/good v1.0.0\n"], ["write", self.gosum, "sum\n"],
                     self.zip_step("example.test/good", "v1.0.0")]
        code, out = self.run_guard("--plan", "go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        (run,) = self.runs()
        self.assertEqual(run["argv"], ["get", "example.test/good@v1.0.0"])
        self.assertNotEqual(run["GOMODCACHE"], self.modcache)
        self.assertFalse(os.path.exists(run["GOMODCACHE"]))                                  # (and it is gone)
        self.assertEqual(self.read(self.gomod), before)
        self.assertFalse(os.path.exists(self.gosum))
        self.assertIn("nothing blocked (--plan: nothing was installed; go.mod and go.sum put back)", out)

    def test_a_plan_of_a_build_downloads_instead_of_building(self):
        code, out = self.run_guard("--plan", "go", "build", "./...")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.runs()[0]["argv"], ["mod", "download"])

    def test_a_plan_of_an_install_is_a_get_in_a_module_of_its_own(self):
        code, out = self.run_guard("--plan", "go", "install", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        (run,) = self.runs()
        self.assertEqual(run["argv"], ["get", "example.test/good@v1.0.0"])
        self.assertNotEqual(os.path.realpath(run["cwd"]), os.path.realpath(self.dir))
        self.assertFalse(os.path.exists(run["cwd"]))

    def test_a_plan_that_blocks_says_so(self):
        self.plan = [self.zip_step("example.test/evil", "v1.0.0")]
        code, out = self.run_guard("--plan", "go", "get", "example.test/evil@v1.0.0")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    example.test/evil@v1.0.0", out)
        self.assertNotIn("modules that passed", out)

    def test_a_plan_whose_command_fails_shows_its_output(self):
        self.plan = [["get", "/example.test/nothing/@v/v1.0.0.zip"]]
        code, out = self.run_guard("--plan", "go", "get", "example.test/nothing@v1.0.0")
        self.assertEqual(code, 3, out)
        self.assertIn("lazaret guard: resolving (go get) failed (exit 1):", out)


class CacheTests(FlowCase):
    def cache_zip(self, module, version):
        path = os.path.join(self.modcache, "cache", "download", go.encode(module), "@v", version + ".zip")
        return ["write", path, "zip"]

    def test_a_module_that_did_not_come_through_the_proxy_fails_the_run(self):
        self.plan = [self.zip_step("example.test/good", "v1.0.0"), self.cache_zip("example.test/sneaky", "v1.0.0")]
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 1, out)
        self.assertIn("lazaret guard: installed but not checked: example.test/sneaky@v1.0.0", out)
        self.assertIn("go did not fetch them through the guard's proxy", out)
        self.assertNotIn("the registry changed", out)

    def test_a_module_that_was_cached_before_is_not_new(self):
        path = os.path.join(self.modcache, "cache", "download", "example.test", "old", "@v", "v1.0.0.zip")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(b"zip")
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertNotIn("not checked", out)

    def test_a_private_module_is_noted_not_failed(self):
        self.goenv["GOPRIVATE"] = "example.test/priv,other.test"
        self.plan = [self.cache_zip("example.test/priv", "v1.2.3"), self.cache_zip("other.test/x/y", "v0.1.0")]
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertIn("example.test/priv@v1.2.3: fetched straight from its repository (GOPRIVATE or GONOPROXY names it): not checked", out)
        self.assertIn("other.test/x/y@v0.1.0", out)

    def test_gonoproxy_names_them_too(self):
        self.goenv["GONOPROXY"] = "example.test/priv"
        self.plan = [self.cache_zip("example.test/priv", "v1.2.3")]
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertIn("fetched straight from its repository", out)

    def test_nothing_is_compared_after_a_block_or_a_failure(self):
        self.plan = [self.zip_step("example.test/evil", "v1.0.0"), self.cache_zip("example.test/sneaky", "v1.0.0")]
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 1, out)
        self.assertNotIn("sneaky", out)


class RefusalTests(FlowCase):
    def refused(self, *args, goenv=None):
        code, out = self.run_guard(*args, goenv=goenv)
        self.assertEqual(code, 2, out)
        self.assertFalse(os.path.exists(self.log), out)                                      # (go was not run)
        return out

    def test_commands_that_do_not_fetch_modules(self):
        for command in (["go"], ["go", "fmt", "./..."], ["go", "env"], ["go", "mod"], ["go", "mod", "graph"], ["go", "mod", "vendor"],
                        ["go", "work", "sync"]):
            with self.subTest(command):
                out = self.refused(*command)
                self.assertIn("lazaret guard wraps go's commands that fetch modules", out)

    def test_a_goproxy_with_nothing_to_relay(self):
        for value in ("off", "direct", "", "direct,https://x.example"):
            with self.subTest(value):
                out = self.refused("go", "get", "x", goenv=dict(self.goenv, GOPROXY=value))
                self.assertIn("GOPROXY names no module proxy", out)

    def test_a_proxy_that_is_a_folder(self):
        out = self.refused("go", "get", "x", goenv=dict(self.goenv, GOPROXY="file:///tmp/proxy"))
        self.assertIn("the guard relays https and http proxies, not other kinds", out)

    def test_gopath_mode(self):
        out = self.refused("go", "get", "x", goenv=dict(self.goenv, GO111MODULE="off"))
        self.assertIn("GO111MODULE=off", out)

    def test_go_that_cannot_say_its_settings(self):
        code, out = self.run_guard("go", "get", "x", broken=True)
        self.assertEqual(code, 2, out)
        self.assertIn("could not read go's settings", out)

    def test_go_that_is_not_installed(self):
        env = gs.base_env(self.tmp)
        env["PATH"] = os.path.dirname(sys.executable)
        code, out = gs.run_guard(["go", "get", "x"], self.dir, env)
        self.assertEqual(code, 2, out)
        self.assertIn("go is not on PATH", out)


class CommandLineTests(unittest.TestCase):
    """`lazaret guard go …` is routed to the guard, and the parser takes go as a tool."""

    def test_the_limits_are_the_documented_ones(self):
        self.assertEqual((guard.GO_PROBES, guard.MAX_GO_ANSWER), (24, 16 * 1024 * 1024))

    def test_the_command_line_is_the_guards(self):
        from lazaret import _cli
        self.assertIn("go", _cli.GUARD_TOOLS)
        self.assertTrue(_cli.is_guard(["guard", "go", "get", "example.test/x"]))
        self.assertTrue(_cli.is_guard(["guard", "--min-age", "7d", "go", "mod", "download"]))
        self.assertFalse(_cli.is_guard(["go", "get", "x"]))

    def test_the_parser_takes_go_and_its_command_whole(self):
        opts = guard.build_parser().parse_args(["--plan", "go", "get", "-u", "example.test/x@v1.0.0"])
        self.assertEqual((opts.tool, opts.args, opts.plan), ("go", ["get", "-u", "example.test/x@v1.0.0"], True))
        self.assertIn("go", guard.TOOLS)
        self.assertIn("go", guard.build_parser().format_help())


@unittest.skipUnless(shutil.which("go"), "go is not installed")
class RealGoTests(unittest.TestCase):
    """The real go command, against the fake proxy; the module cache, go.mod and go.sum are the tool's own."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        cls.proxy = go.GoProxy()
        go.default_modules(cls.proxy)

    @classmethod
    def tearDownClass(cls):
        cls.proxy.close()
        guard.remove_tree(cls.tmp)

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="proj-", dir=self.tmp)
        self.modcache = os.path.join(self.dir, "modcache")
        self.gomod = os.path.join(self.dir, "go.mod")
        self.write(self.gomod, "module example.test/app\n\ngo 1.21\n")
        self.env = gs.base_env(self.tmp)
        self.env.update(GOPROXY=self.proxy.url, GOMODCACHE=self.modcache, GOFLAGS="-modcacherw", GOSUMDB="off", GOENV="off",
                        GOTOOLCHAIN="local", GOPATH=os.path.join(self.dir, "gopath"), GOCACHE=os.path.join(self.tmp, "gocache"),
                        GOTELEMETRY="off")
        self.env.pop("GOPRIVATE", None)

    def write(self, path, text):
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def run_guard(self, *args):
        return gs.run_guard(["--jobs", "1", "--no-cache", *args], self.dir, self.env, 60)

    def cached(self):
        return sorted(f"{m}@{v}" for m, v in guard.cached_modules(self.modcache))

    def test_a_clean_module_and_what_it_needs_are_checked_and_added(self):
        code, out = self.run_guard("go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        text = gs.read(self.gomod)
        self.assertIn("example.test/good v1.0.0", text)
        self.assertIn("example.test/leaf v1.0.0", text)
        self.assertEqual(self.cached(), ["example.test/good@v1.0.0", "example.test/leaf@v1.0.0"])

    def test_a_hostile_dependency_blocks_the_get_and_never_reaches_the_cache(self):
        before = gs.read(self.gomod)
        code, out = self.run_guard("go", "get", "example.test/parent@v1.0.0")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    example.test/evil@v1.0.0: SUSPICIOUS", out)
        self.assertIn("SC-USE-RISK (CRITICAL)", out)
        self.assertEqual(gs.read(self.gomod), before)
        self.assertNotIn("example.test/evil@v1.0.0", self.cached())

    def test_the_newest_release_that_is_old_enough_is_the_one_go_picks(self):
        code, out = self.run_guard("go", "get", "example.test/mixed")
        self.assertEqual(code, 0, out)
        self.assertIn("example.test/mixed v1.0.0", gs.read(self.gomod))
        self.assertIn("held back  example.test/mixed: 1 release younger than 2 days", out)

    def test_a_new_version_asked_for_by_name_is_refused_and_go_fails(self):
        before = gs.read(self.gomod)
        code, out = self.run_guard("go", "get", "example.test/mixed@v1.1.0")
        self.assertNotEqual(code, 0, out)
        self.assertIn("was published 1 hour ago, under --min-age 2 days", out)
        self.assertEqual(gs.read(self.gomod), before)
        self.assertEqual(self.cached(), [])

    def test_allow_new_takes_a_new_version_and_scans_it(self):
        code, out = self.run_guard("--allow-new", "example.test/mixed", "go", "get", "example.test/mixed@v1.1.0")
        self.assertEqual(code, 0, out)
        self.assertIn("example.test/mixed v1.1.0", gs.read(self.gomod))
        self.assertIn("let through by --allow-new", out)

    def test_trust_takes_a_flagged_module(self):
        code, out = self.run_guard("--trust", "example.test/evil", "go", "get", "example.test/evil@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("TRUSTED    example.test/evil@v1.0.0", out)
        self.assertEqual(self.cached(), ["example.test/evil@v1.0.0"])

    def test_a_plan_changes_nothing(self):
        before = gs.read(self.gomod)
        code, out = self.run_guard("--plan", "go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertEqual(gs.read(self.gomod), before)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "go.sum")))
        self.assertFalse(os.path.exists(self.modcache))

    def test_a_plan_of_an_install_changes_nothing_either(self):
        code, out = self.run_guard("--plan", "go", "install", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertFalse(os.path.exists(self.modcache))

    def test_mod_download_of_what_go_mod_lists(self):
        self.write(self.gomod, "module example.test/app\n\ngo 1.21\n\nrequire (\n\texample.test/good v1.0.0\n"
                               "\texample.test/leaf v1.0.0 // indirect\n)\n")
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertTrue(os.path.exists(os.path.join(self.dir, "go.sum")))

    def test_a_hostile_module_in_go_mod_blocks_the_download_and_go_sum_is_not_left(self):
        self.write(self.gomod, "module example.test/app\n\ngo 1.21\n\nrequire (\n\texample.test/good v1.0.0\n\texample.test/evil v1.0.0\n)\n")
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    example.test/evil@v1.0.0", out)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "go.sum")))
        self.assertIn("go.sum put back", out)

    def test_tidy_and_build_in_a_project(self):
        self.write(os.path.join(self.dir, "main.go"),
                   'package main\n\nimport "example.test/good"\n\nfunc main() { _ = good.F() }\n')
        code, out = self.run_guard("go", "mod", "tidy")
        self.assertEqual(code, 0, out)
        self.assertIn("example.test/good v1.0.0", gs.read(self.gomod))
        guard.remove_tree(self.modcache)
        code, out = self.run_guard("go", "build", "./...")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 OK", out)
        self.assertEqual(self.cached(), ["example.test/good@v1.0.0", "example.test/leaf@v1.0.0"])

    def test_a_module_cached_already_is_not_fetched_or_checked_again(self):
        self.assertEqual(self.run_guard("go", "get", "example.test/good@v1.0.0")[0], 0)
        before = len(self.proxy.paths(".zip"))
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertEqual(len(self.proxy.paths(".zip")), before)
        self.assertNotIn("lazaret guard: checked", out)

    def test_a_module_with_capitals_in_its_path(self):
        code, out = self.run_guard("go", "get", "example.test/BigCase@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.cached(), ["example.test/BigCase@v1.0.0"])

    def test_a_proxy_that_redirects_and_one_that_wants_credentials(self):
        self.proxy.redirect = True
        self.addCleanup(setattr, self.proxy, "redirect", False)
        code, out = self.run_guard("go", "get", "example.test/leaf@v1.0.0")
        self.assertEqual(code, 0, out)
        private = go.GoProxy(auth=pmsettings.basic("user", "secret"))
        go.default_modules(private)
        self.addCleanup(private.close)
        self.env["GOPROXY"] = private.url.replace("http://", "http://user:secret@")
        code, out = self.run_guard("go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertNotIn("secret", out)
        self.assertEqual({a for _, a in private.authorizations}, {pmsettings.basic("user", "secret")})


if __name__ == "__main__":
    unittest.main()
