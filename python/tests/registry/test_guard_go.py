"""lazaret guard go (0.1.9, G-3): the Go proxy on this machine that scans each module zip before the go command has it.

Four kinds of test. The relay on its own, asked over HTTP what the go command asks, with a stand-in scanner and a fake module proxy
(tests/registry/_go_support.py). The helpers that read go's settings and the module cache. The command, run as `python -m
lazaret.registry.guard go …`, with a fake `go` that does exactly what each case needs (fetch this path, leave that in the module
cache), so the exit codes, the files put back and the report are known. And the real go command, against the fake proxy, where go
is installed (skipped where it is not).

What the scan finds in a Go module today is what it finds in any archive (JavaScript and Python files, install hooks, binaries,
archive structure); the Go and Rust rules of the engine read `.go` files from the 0.1.9 wiring on."""

import datetime
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
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


class StubRelay:
    """Stands in for GoRelay behind the server: `reply` is called for each request and gives the GoReply (or raises)."""

    def __init__(self, reply):
        self.reply = reply
        self.asked = []

    def handle(self, req):
        self.asked.append(req)
        return self.reply()


class FakeResponse(io.BytesIO):
    """What a Fetcher.open gives: a body, and the headers it came with."""

    def __init__(self, body, headers):
        super().__init__(body)
        self.headers = headers


def reach(base, path, method="GET"):
    """-> (status, headers, body) of one request, with no wait longer than five seconds."""
    try:
        with OPENER.open(urllib.request.Request(base + path, method=method), timeout=5) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


class ServerTests(unittest.TestCase):
    """What the Go proxy on this machine says over HTTP, whatever the relay behind it answers."""
    PATH = "/example.test/good/@v/list"

    def serve(self, reply):
        relay = StubRelay(reply)
        server = guard.make_go_server(relay)
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = server
        return relay, f"http://127.0.0.1:{server.server_address[1]}"

    def test_a_text_reply_has_its_type_its_length_and_is_not_cached(self):
        _relay, base = self.serve(lambda: guard.GoReply(200, b"v1.0.0\n", "text/x-test", None, None))
        status, headers, body = reach(base, self.PATH)
        self.assertEqual((status, body), (200, b"v1.0.0\n"))
        self.assertEqual((headers["Content-Type"], headers["Content-Length"], headers["Cache-Control"]), ("text/x-test", "7", "no-store"))
        status, headers, body = reach(base, self.PATH, "HEAD")
        self.assertEqual((status, body, headers["Content-Length"], headers["Content-Type"]), (200, b"", "7", "text/x-test"))

    def test_a_head_request_is_answered_with_no_body_at_all(self):
        folder = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        self.addCleanup(guard.remove_tree, folder)
        path = os.path.join(folder, "m.zip")
        with open(path, "wb") as f:
            f.write(b"zipzipzip")
        replies = (lambda: guard.GoReply(200, b"v1.0.0\n", "text/plain", None, None),
                   lambda: guard.GoReply(200, None, "application/zip", path, None),
                   lambda: guard.GoReply(200, None, "application/zip", None, FakeResponse(b"hello", {"Content-Length": "5"})),
                   lambda: guard.GoReply(200, None, "application/zip", None, FakeResponse(b"hello", {})))
        for number, reply in enumerate(replies):
            with self.subTest(number):
                _relay, base = self.serve(reply)
                with socket.create_connection(("127.0.0.1", int(base.rsplit(":", 1)[1])), timeout=5) as conn:
                    conn.sendall(f"HEAD {self.PATH} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
                    data = b""
                    while True:
                        block = conn.recv(65536)
                        if not block:
                            break
                        data += block
                head, _, body = data.partition(b"\r\n\r\n")
                self.assertTrue(head.startswith(b"HTTP/1.1 200"), head)
                self.assertEqual(body, b"")

    def test_a_status_that_is_not_200_is_the_replys(self):
        _relay, base = self.serve(lambda: guard.GoReply(403, b"no\n", "text/plain", None, None))
        self.assertEqual(reach(base, self.PATH)[::2], (403, b"no\n"))

    def test_a_file_is_sent_with_its_type_and_length(self):
        folder = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        self.addCleanup(guard.remove_tree, folder)
        path = os.path.join(folder, "m.zip")
        data = bytes(range(256)) * 17
        with open(path, "wb") as f:
            f.write(data)
        _relay, base = self.serve(lambda: guard.GoReply(200, None, "application/zip", path, None))
        status, headers, body = reach(base, self.PATH)
        self.assertEqual((status, body, headers["Content-Type"], headers["Content-Length"]), (200, data, "application/zip", str(len(data))))
        status, headers, body = reach(base, self.PATH, "HEAD")
        self.assertEqual((status, body, headers["Content-Type"], headers["Content-Length"]), (200, b"", "application/zip", str(len(data))))

    def test_a_stream_is_passed_on_with_its_length(self):
        _relay, base = self.serve(lambda: guard.GoReply(200, None, "application/zip", None, FakeResponse(b"hello", {"Content-Length": "5"})))
        status, headers, body = reach(base, self.PATH)
        self.assertEqual((status, body, headers["Content-Type"], headers["Content-Length"]), (200, b"hello", "application/zip", "5"))
        status, headers, body = reach(base, self.PATH, "HEAD")
        self.assertEqual((status, body, headers["Content-Length"]), (200, b"", "5"))

    def test_a_stream_of_unknown_length_ends_when_the_connection_does(self):
        for length in (None, "", "five", "5, 5", "-5"):
            with self.subTest(length=length):
                headers = {} if length is None else {"Content-Length": length}
                _relay, base = self.serve(lambda: guard.GoReply(200, None, "application/zip", None, FakeResponse(b"hello", headers)))
                status, got, body = reach(base, self.PATH)
                self.assertEqual((status, body), (200, b"hello"))
                self.assertIsNone(got["Content-Length"])

    def test_a_relay_that_fails_gets_a_500_and_the_server_goes_on(self):
        def boom():
            raise RuntimeError("a bug")

        relay, base = self.serve(boom)
        status, headers, body = reach(base, self.PATH)
        self.assertEqual((status, body, headers["Content-Length"]), (500, b"lazaret guard: internal error\n", "30"))
        relay.reply = lambda: guard.GoReply(200, b"ok\n", "text/plain", None, None)
        self.assertEqual(reach(base, self.PATH)[::2], (200, b"ok\n"))

    def test_the_request_the_relay_is_asked_is_the_decoded_one(self):
        relay, base = self.serve(lambda: guard.GoReply(200, b"", "text/plain", None, None))
        reach(base, "/example.test/%21big/@v/v1.0.0.info")
        (req,) = relay.asked
        self.assertEqual((req.kind, req.module, req.version), ("info", "example.test/Big", "v1.0.0"))

    def test_the_server_is_for_this_machine_and_does_not_wait_on_its_threads(self):
        server = guard.make_go_server(StubRelay(lambda: None))
        self.addCleanup(server.server_close)
        self.assertEqual(server.server_address[0], "127.0.0.1")
        self.assertTrue(server.daemon_threads)
        self.assertTrue(server.allow_reuse_address)


class TeardownTests(RelayCase):
    def make(self):
        return guard.LocalGoProxy(self.context(), [goproxy.Proxy(self.proxy.url, False)], pmsettings.Credentials())

    def test_closing_it_stops_the_server_and_removes_what_it_spooled(self):
        lp = self.make()
        self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(len(os.listdir(lp.spool)), 1)
        with mock.patch.object(lp.server, "shutdown", wraps=lp.server.shutdown) as shutdown, \
                mock.patch.object(lp.server, "server_close", wraps=lp.server.server_close) as server_close, \
                mock.patch.object(lp.fetcher, "close", wraps=lp.fetcher.close) as fetcher_close:
            lp.__exit__(None, None, None)
        for call in (shutdown, server_close, fetcher_close):
            call.assert_called_once_with()
        self.assertFalse(os.path.exists(lp.spool))
        with self.assertRaises(urllib.error.URLError):
            OPENER.open(lp.base + "/example.test/good/@v/list", timeout=5)

    def test_closing_it_is_not_troubled_by_a_spool_that_is_gone(self):
        lp = self.make()
        shutil.rmtree(lp.spool)
        lp.__exit__(None, None, None)

    def test_a_blocked_zip_is_not_kept_and_a_clean_one_is(self):
        lp = self.serve(self.context())
        self.assertEqual(ask(lp.base, "/example.test/evil/@v/v1.0.0.zip")[0], 403)
        self.assertEqual(os.listdir(lp.spool), [])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.zip")[0], 200)
        self.assertEqual(len(os.listdir(lp.spool)), 1)

    def test_the_fetcher_follows_a_redirect_to_any_https_host_and_the_checks_name_the_first_proxy(self):
        lp = self.serve(self.context())
        self.assertTrue(lp.fetcher.https_redirects)
        ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual(lp.relay.source, self.proxy.url)
        self.assertEqual(lp.relay.ctx.checks[0].source, self.proxy.url)
        lp2 = guard.LocalGoProxy(self.context(), [goproxy.Proxy("direct", False)], pmsettings.Credentials())
        self.addCleanup(lp2.__exit__, None, None, None)
        self.assertEqual(lp2.relay.source, "")


class RelayDetailTests(RelayCase):
    def test_the_notes_for_the_report_are_few_and_not_repeated(self):
        relay = guard.GoRelay(self.context(), None, [], "")
        for n in range(30):
            relay.note(f"m{n}")
            relay.note("m0")
        self.assertEqual(relay.errors, [f"m{n}" for n in range(20)])

    def test_a_release_time_that_cannot_be_read_is_noted_and_holds_nothing_back(self):
        self.proxy.fail["/example.test/mixed/@v/v1.1.0.info"] = (200, b"[1]")
        lp = self.serve(self.context())
        self.assertEqual(ask(lp.base, "/example.test/mixed/@v/list"), (200, b"v1.0.0\nv1.1.0\n"))
        self.assertEqual(lp.relay.errors, ["example.test/mixed@v1.1.0: no release time (not a JSON object)"])
        self.assertEqual(lp.relay.held_back, {})

    def test_a_release_time_the_proxy_cannot_give_is_noted_too(self):
        self.proxy.fail["/example.test/mixed/@v/v1.1.0.info"] = (500, b"broken")
        lp = self.serve(self.context())
        self.assertEqual(ask(lp.base, "/example.test/mixed/@v/list")[0], 200)
        (note,) = lp.relay.errors
        self.assertTrue(note.startswith("example.test/mixed@v1.1.0: no release time ("), note)
        self.proxy.fail["/example.test/mixed/@v/v1.1.0.info"] = (404, b"missing")
        lp = self.serve(self.context())
        ask(lp.base, "/example.test/mixed/@v/list")
        self.assertEqual(lp.relay.errors, ["example.test/mixed@v1.1.0: no release time (not found)"])

    def test_a_release_exactly_at_the_cutoff_is_old_enough(self):
        ctx = self.context()
        lp = self.serve(ctx)
        step = datetime.timedelta(seconds=1)
        self.assertFalse(lp.relay._too_new("example.test/mixed", ctx.cutoff))
        self.assertTrue(lp.relay._too_new("example.test/mixed", ctx.cutoff + step))
        self.assertFalse(lp.relay._too_new("example.test/mixed", ctx.cutoff - step))
        self.assertFalse(lp.relay._too_new("example.test/mixed", None))
        self.assertFalse(lp.relay._too_new("golang.org/toolchain", ctx.cutoff + step))

    def test_an_info_is_asked_of_the_proxy_once(self):
        lp = self.serve(self.context())
        for _ in range(3):
            self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.info")[0], 200)
        self.assertEqual(len(self.proxy.paths("/example.test/good/@v/v1.0.0.info")), 1)

    def test_the_newest_24_versions_are_looked_up_by_default(self):
        for minor in range(40):
            self.proxy.add("example.test/many", f"v1.{minor}.0")
        lp = self.serve(self.context())
        self.assertEqual(len(ask(lp.base, "/example.test/many/@v/list")[1].split()), 40)
        self.assertEqual(len(self.proxy.paths(".info")), 24)

    def test_a_missing_or_gone_answer_is_not_found_for_the_tool_and_not_a_fault(self):
        for status in (404, 410):
            for path in ("/example.test/good/@v/list", "/example.test/good/@v/v1.0.0.zip", "/example.test/good/@v/v1.0.0.mod",
                         "/example.test/good/@latest", "/example.test/good/@v/v1.0.0.info"):
                with self.subTest(status=status, path=path):
                    self.proxy.fail[""] = (status, b"nope")
                    lp = self.serve(self.context())
                    self.assertEqual(ask(lp.base, path)[0], 404)
                    self.assertEqual([e for e in lp.relay.errors if "no release time" not in e], [])
                    self.assertEqual(lp.relay.ctx.checks, [])

    def test_a_list_with_nothing_but_direct_has_nothing_to_relay_and_says_not_found(self):
        lp = self.serve(self.context(), [goproxy.Proxy("direct", False)])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/list")[0], 404)
        self.assertEqual(lp.relay.errors, [])
        self.assertEqual(ask(lp.base, "/example.test/good/@v/v1.0.0.zip")[0], 404)
        self.assertEqual(self.proxy.requests, [])

    def test_any_other_failure_is_a_502_with_fixed_text_and_the_reason_is_kept(self):
        self.proxy.fail[""] = (500, b"secret detail")
        lp = self.serve(self.context())
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.mod")
        self.assertEqual((status, body), (502, b"lazaret guard could not fetch this from the proxy it relays\n"))
        self.assertEqual(len(lp.relay.errors), 1)

    def test_the_reason_a_zip_is_refused_is_short_and_on_one_line(self):
        class Long(FakeScanner):
            def scan(self, data, container, kind):
                return {"verdict": "SUSPICIOUS", "reason": "a\n" + "x" * 500, "indicators": []}

        ctx = self.context()
        ctx.scanner = Long()
        lp = self.serve(ctx)
        status, body = ask(lp.base, "/example.test/good/@v/v1.0.0.zip")
        self.assertEqual(status, 403)
        self.assertEqual(body, b"blocked by lazaret guard: " + (b"SUSPICIOUS: a " + b"x" * 286) + b"\n")


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

    def test_a_module_may_have_a_folder_called_sumdb(self):
        self.touch("cache", "download", "example.test", "sumdb", "@v", "v1.0.0.zip")
        self.touch("cache", "download", "sumdb", "sum.golang.org", "x", "@v", "v9.zip")
        self.assertEqual(guard.cached_modules(self.tmp), {("example.test/sumdb", "v1.0.0")})

    def test_no_module_cache_is_nothing_cached(self):
        self.assertEqual(guard.cached_modules(os.path.join(self.tmp, "none")), set())
        self.assertEqual(guard.cached_modules(""), set())

    def test_no_module_cache_does_not_mean_the_current_folder(self):
        self.touch("cache", "download", "example.test", "x", "@v", "v1.0.0.zip")
        here = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, here)
        self.assertEqual(guard.cached_modules(""), set())
        self.assertEqual(guard.cached_modules(self.tmp), {("example.test/x", "v1.0.0")})

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

    def test_a_flag_and_its_value_at_the_end_of_the_command(self):
        self.assertEqual(guard._go_flag(["-modfile", "a.mod"], "modfile"), "a.mod")
        self.assertEqual(guard._go_flag(["x", "--modfile", "a.mod"], "modfile"), "a.mod")
        self.assertEqual(guard._go_chdir(["build", "-C", "d"]), "d")
        self.assertEqual(guard._go_chdir(["build", "--C", "d"]), "d")

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

    def test_every_folder_is_made_writable_before_it_is_removed(self):
        path = self.touch("ro", "a", "b", "f")
        with mock.patch.object(guard.os, "chmod", wraps=os.chmod) as chmod:
            guard.remove_tree(os.path.dirname(os.path.dirname(os.path.dirname(path))))
        self.assertTrue({(os.path.join(self.tmp, "ro", "a"), 0o700), (os.path.join(self.tmp, "ro", "a", "b"), 0o700)}
                        <= {c.args for c in chmod.call_args_list})
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "ro")))

    def test_what_is_not_there_is_removed_without_a_fuss(self):
        guard.remove_tree(os.path.join(self.tmp, "none"))

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

    def run_guard(self, *args, goenv=None, broken=False, timeout=40, **extra):
        env = gs.base_env(self.tmp)
        env.update(PATH=self.bin + os.pathsep + os.environ.get("PATH", ""),
                   FAKE_GO_ENV=json.dumps(None if broken else (goenv if goenv is not None else self.goenv)),
                   FAKE_GO_PLAN=json.dumps(self.plan), FAKE_GO_LOG=self.log, **extra)
        return gs.run_guard(["--jobs", "1", "--no-cache", *args], self.dir, env, timeout)

    def report(self, *args, **kw):
        """-> (exit code, output, the --json report) of a run."""
        path = os.path.join(self.dir, "report.json")
        code, out = self.run_guard("--json", path, *args, **kw)
        return code, out, json.loads(self.read(path))

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
        self.assertIn("lazaret guard: checked 1 INCOMPLETE", out)

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

    def test_a_block_is_exit_1_whatever_go_exits_with(self):
        for gos in (0, 7):
            with self.subTest(go=gos):
                self.plan = [self.zip_step("example.test/evil", "v1.0.0"), ["exit", gos]]
                code, out = self.run_guard("go", "get", "example.test/evil@v1.0.0")
                self.assertEqual(code, 1, out)
                self.assertIn("BLOCKED    example.test/evil@v1.0.0", out)

    def test_a_plan_that_blocks_is_exit_1_and_one_that_does_not_is_exit_0(self):
        self.plan = [self.zip_step("example.test/evil", "v1.0.0"), ["exit", 0]]
        code, out = self.run_guard("--plan", "go", "get", "example.test/evil@v1.0.0")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    example.test/evil@v1.0.0", out)
        self.plan = [self.zip_step("example.test/good", "v1.0.0"), ["exit", 0]]
        code, out = self.run_guard("--plan", "go", "get", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)

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
        self.assertEqual(names, {("go", "example.test/good", "INCOMPLETE"), ("go", "example.test/evil", "SUSPICIOUS")})
        self.assertEqual(doc["heldBack"], {})


    def test_json_says_whether_anything_was_installed_and_what_the_exit_code_was(self):
        good, evil = self.zip_step("example.test/good", "v1.0.0"), self.zip_step("example.test/evil", "v1.0.0")
        cases = (("a run that went well", [good], (), 0, True),
                 ("a go that failed", [good, ["exit", 3]], (), 3, False),
                 ("a block, though go went on and said all was well", [evil, ["exit", 0]], (), 1, False),
                 ("a plan", [good], ("--plan",), 0, False),
                 ("a plan that failed", [["exit", 1]], ("--plan",), 3, False))
        for name, plan, flags, code_wanted, installed in cases:
            with self.subTest(name):
                self.plan = plan
                code, out, doc = self.report(*flags, "go", "get", "example.test/good@v1.0.0")
                self.assertEqual((code, doc["exitCode"], doc["installed"]), (code_wanted, code_wanted, installed), out)

    def test_a_list_that_ends_in_direct_says_the_guard_does_not_fetch_from_version_control(self):
        code, out = self.run_guard("go", "mod", "download", goenv=dict(self.goenv, GOPROXY=self.proxy.url + ",direct"))
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: relaying " + self.proxy.url + "/ (the guard does not fetch from version control: "
                      "a module the proxy lacks is not fetched, unless GOPRIVATE names it)", out)
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertNotIn("does not fetch from version control", out)

    def test_an_https_proxy_is_relayed_too(self):
        code, out = self.run_guard("go", "mod", "download", goenv=dict(self.goenv, GOPROXY="https://proxy.example.test"))
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: relaying https://proxy.example.test/", out)

    def test_go_s_settings_are_read_where_the_command_runs(self):
        sub = os.path.join(self.dir, "sub")
        os.makedirs(sub)
        for args, folder in ((["go", "build", "-C", "sub", "./..."], sub), (["go", "build", "./..."], self.dir)):
            with self.subTest(args):
                envlog = os.path.join(self.dir, f"env-{len(args)}.log")
                code, out = self.run_guard(*args, FAKE_GO_ENV_LOG=envlog)
                self.assertEqual(code, 0, out)
                self.assertEqual([os.path.realpath(line) for line in self.read(envlog).splitlines()], [os.path.realpath(folder)])

    def test_mod_download_and_mod_tidy_are_wrapped_as_they_are(self):
        for command in (["mod", "download"], ["mod", "tidy"]):
            with self.subTest(command):
                code, out = self.run_guard("go", *command)
                self.assertEqual(code, 0, out)
                self.assertEqual(self.runs()[-1]["argv"], command)


class InterruptTests(unittest.TestCase):
    def test_go_mod_is_put_back_when_the_run_is_cut_short(self):
        tmp = tempfile.mkdtemp(prefix="lazaret-guard-go-")
        self.addCleanup(guard.remove_tree, tmp)
        gomod = os.path.join(tmp, "go.mod")
        with open(gomod, "w", encoding="utf-8") as f:
            f.write("module example.test/app\n")
        settings = {"GOPROXY": "http://127.0.0.1:9", "GOMOD": gomod, "GOMODCACHE": os.path.join(tmp, "modcache"), "GOPRIVATE": ""}

        def cut_short(argv, env, cwd=None, capture=False):
            with open(gomod, "a", encoding="utf-8") as f:
                f.write("require example.test/x v1.0.0\n")
            raise KeyboardInterrupt

        ctx = guard.Context(options(tool="go"), out=io.StringIO())
        ctx.scanner = FakeScanner()
        self.addCleanup(ctx.close)
        with mock.patch.object(guard, "find_tool", return_value="go"), mock.patch.object(guard, "go_settings", return_value=settings), \
                mock.patch.object(guard, "run_tool", side_effect=cut_short):
            with self.assertRaises(KeyboardInterrupt):
                guard.guard_go(ctx, ["get", "example.test/x@v1.0.0"])
        self.assertEqual(gs.read(gomod), "module example.test/app\n")


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

    def test_a_plan_is_silent_where_a_run_shows_what_go_says(self):
        self.plan = [["say", "go says hello"]]
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertIn("go says hello", out)
        code, out = self.run_guard("--plan", "go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertNotIn("go says hello", out)

    def test_the_module_a_plan_of_an_install_runs_in_is_a_module(self):
        seen = os.path.join(self.dir, "seen-go.mod")
        self.plan = [["copy", "go.mod", seen]]
        code, out = self.run_guard("--plan", "go", "install", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read(seen), "module lazaret.guard/plan\n\ngo 1.21\n")

    def test_a_plan_does_not_compare_a_module_cache_it_does_not_use(self):
        path = os.path.join(self.modcache, "cache", "download", "example.test", "other", "@v", "v1.0.0.zip")
        self.plan = [["write", path, "zip"]]
        code, out = self.run_guard("--plan", "go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertNotIn("not checked", out)

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
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
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
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
        self.assertEqual(gs.read(self.gomod), before)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "go.sum")))
        self.assertFalse(os.path.exists(self.modcache))

    def test_a_plan_of_an_install_changes_nothing_either(self):
        code, out = self.run_guard("--plan", "go", "install", "example.test/good@v1.0.0")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
        self.assertFalse(os.path.exists(self.modcache))

    def test_mod_download_of_what_go_mod_lists(self):
        self.write(self.gomod, "module example.test/app\n\ngo 1.21\n\nrequire (\n\texample.test/good v1.0.0\n"
                               "\texample.test/leaf v1.0.0 // indirect\n)\n")
        code, out = self.run_guard("go", "mod", "download")
        self.assertEqual(code, 0, out)
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
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
        self.assertIn("lazaret guard: checked 2 INCOMPLETE", out)
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
