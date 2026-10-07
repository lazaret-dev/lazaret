"""The native transport (0.1.9, NET-1): the native library's HTTPS client (rust/crates/lazaret-net, on tiny_https)
from Python, against a local HTTPS server that Python's ssl serves with a root made for the test.

The root and the server's certificate are made with the `openssl` command when the tests start (none is kept in the
repository); without it, or without the native library's network layer, the tests skip. Python's server speaks
HTTP/1.1 (the native client offers h2 and takes HTTP/1.1 when the server does not pick it; the HTTP/2 path is held by
lazaret-net's own tests against tiny_https's server). Hosts are `localhost` on the server's port; nothing leaves the
machine."""

import http.server
import json
import os
import pathlib
import shutil
import ssl
import subprocess
import tempfile
import threading
import types
import time
import unittest
import urllib.request
from unittest import mock

from lazaret.registry import repo
from lazaret.registry.ecosystems import base
from lazaret.scanner import nativenet


def _openssl(args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=30)


def make_pki(folder):
    """(the root's PEM, the server's certificate file, its key file): a root, and a certificate for localhost and
    127.0.0.1 under it, both for a day."""
    ext = pathlib.Path(folder, "leaf.ext")
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
                   "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    _openssl(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
              "-out", "ca.pem", "-days", "1", "-subj", "/CN=Lazaret test root",
              "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], folder)
    _openssl(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "leaf.key",
              "-out", "leaf.csr", "-subj", "/CN=localhost"], folder)
    _openssl(["x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
              "-out", "leaf.pem", "-days", "1", "-extfile", "leaf.ext"], folder)
    return (pathlib.Path(folder, "ca.pem").read_text(encoding="ascii"), os.path.join(folder, "leaf.pem"),
            os.path.join(folder, "leaf.key"))


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status, body=b"", headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):                                      # noqa: N802 (http.server's name)
        port = self.server.server_address[1]
        if self.path == "/ok":
            self._send(200, b"hello", [("X-Test", "1")])
        elif self.path == "/json":
            self._send(200, json.dumps({"a": [1, 2]}).encode(), [("Content-Type", "application/json")])
        elif self.path == "/headers":
            self._send(200, json.dumps({k.lower(): v for k, v in self.headers.items()}).encode())
        elif self.path.startswith("/size/"):
            self._send(200, b"x" * int(self.path[6:]))
        elif self.path == "/missing":
            self._send(404, b"no")
        elif self.path == "/in":
            self._send(302, headers=[("Location", "/ok")])
        elif self.path == "/out":
            self._send(302, headers=[("Location", f"https://127.0.0.1:{port}/ok")])
        elif self.path == "/to-headers":                   # (the same host)
            self._send(302, headers=[("Location", "/headers")])
        elif self.path == "/out-headers":                  # (another host: 127.0.0.1)
            self._send(302, headers=[("Location", f"https://127.0.0.1:{port}/headers")])
        elif self.path.startswith("/to-localhost/"):      # (the same server, as another origin when asked as 127.0.0.1)
            self._send(302, headers=[("Location", f"https://localhost:{port}/{self.path[len('/to-localhost/'):]}")])
        elif self.path.startswith("/to-port/"):           # (to localhost on another port: a server of the test's)
            self._send(302, headers=[("Location", f"https://localhost:{self.path[len('/to-port/'):]}/ok")])
        elif self.path.split("?")[0].endswith("/echo"):    # (the path as the server got it, and the fields)
            self._send(200, json.dumps({"path": self.path, **{k.lower(): v for k, v in self.headers.items()}}).encode())
        elif self.path in ("/to-dots", "/to-abs-dots", "/to-into-team"):
            self._send(302, headers=[("Location", {"/to-dots": "/team/../echo",
                                                   "/to-abs-dots": f"https://localhost:{port}/team/%2e%2e/echo",
                                                   "/to-into-team": f"https://localhost:{port}/x/../team/echo"}[self.path])])
        elif self.path == "/drip":                         # (40 chunks of 64 KiB, 0.1 s apart: each read is quick)
            self.send_response(200)
            self.send_header("Content-Length", str(40 * 65536))
            self.end_headers()
            for _ in range(40):
                self.wfile.write(b"x" * 65536)
                self.wfile.flush()
                time.sleep(0.1)
        else:
            self._send(500)

    def do_POST(self):                                     # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self._send(200, json.dumps({"body": body.decode(), "type": self.headers.get("Content-Type"),
                                    "accept": self.headers.get("Accept")}).encode())

    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass                                               # (a client that leaves mid-answer: the test says what it saw)

    def stop(self):
        self.shutdown()
        self.server_close()


def serve(cert, key, max_version=None):
    """A local HTTPS server (TLS 1.3, or at most `max_version`) in a thread: (server, port)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    if max_version is not None:
        context.maximum_version = max_version
    else:
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    server = Server(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


NO_PROXY_ENV = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy")}


@unittest.skipUnless(shutil.which("openssl"), "no openssl command to make the test's certificates with")
class NativeTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get(nativenet.ENV, "").strip().lower() == "python":
            raise unittest.SkipTest("LAZARET_NETWORK=python")
        if not nativenet.available():
            raise unittest.SkipTest(f"no native transport here ({nativenet.why_not()})")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root, cls.cert, cls.key = make_pki(cls.tmp.name)
        nativenet.configure_roots(cls.root)
        cls.server, cls.port = serve(cls.cert, cls.key)
        cls.host = f"localhost:{cls.port}"
        cls.env = mock.patch.dict(os.environ, NO_PROXY_ENV, clear=True)
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.stop()
        nativenet.configure_roots(None)
        cls.tmp.cleanup()

    def url(self, path):
        return f"https://{self.host}{path}"

    def test_a_request_is_answered(self):
        reply = nativenet.request(self.url("/ok"), hosts=[self.host], max_bytes=100, timeout=10)
        self.assertEqual((reply.status, reply.body, reply.header("x-test")), (200, b"hello", "1"))
        self.assertEqual((reply.version, reply.url), ("HTTP/1.1", self.url("/ok")))

    def test_its_fields_are_sent(self):
        reply = nativenet.request(self.url("/headers"), hosts=[self.host], max_bytes=10_000, timeout=10,
                                  headers=[("User-Agent", repo.USER_AGENT), ("Accept", "application/json")])
        seen = json.loads(reply.body)
        self.assertEqual((seen["user-agent"], seen["accept"]), (repo.USER_AGENT, "application/json"))
        with self.assertRaises(nativenet.NetError) as caught:
            nativenet.request(self.url("/ok"), hosts=[self.host], max_bytes=100, timeout=10,
                              headers=[("X-Bad", "a\r\nInjected: 1")])
        self.assertEqual(caught.exception.kind, "setup")

    def test_a_post_carries_its_body(self):
        reply = nativenet.request(self.url("/post"), hosts=[self.host], method="POST", data=b'{"q":1}', max_bytes=1000,
                                  timeout=10, headers=[("Content-Type", "application/json"), ("Accept", "x/y")])
        self.assertEqual(json.loads(reply.body), {"body": '{"q":1}', "type": "application/json", "accept": "x/y"})

    def test_a_redirect_is_followed_only_within_the_rule(self):
        self.assertEqual(nativenet.request(self.url("/in"), hosts=[self.host], max_bytes=100, timeout=10).body, b"hello")
        with self.assertRaises(nativenet.NetError) as caught:
            nativenet.request(self.url("/out"), hosts=[self.host], max_bytes=100, timeout=10)
        self.assertEqual(caught.exception.kind, "refused")
        with self.assertRaises(nativenet.NetError) as caught:
            nativenet.request(self.url("/in"), hosts=[self.host], max_bytes=100, timeout=10, max_redirects=0)
        self.assertEqual(caught.exception.kind, "http")

    def test_the_budget_and_the_url_rules(self):
        self.assertEqual(len(nativenet.request(self.url("/size/5000"), hosts=[self.host], max_bytes=5000,
                                               timeout=10).body), 5000)
        with self.assertRaises(nativenet.NetError) as caught:
            nativenet.request(self.url("/size/5001"), hosts=[self.host], max_bytes=5000, timeout=10)
        self.assertEqual(caught.exception.kind, "too-large")
        for url in (f"http://{self.host}/ok", f"https://user:pw@{self.host}/ok", f"https://other.invalid:{self.port}/ok"):
            with self.subTest(url=url), self.assertRaises(nativenet.NetError) as caught:
                nativenet.request(url, hosts=[self.host], max_bytes=100, timeout=10)
            self.assertEqual(caught.exception.kind, "refused")
        with self.assertRaises(nativenet.NetError):
            nativenet.request(self.url("/ok"), hosts=[], max_bytes=100, timeout=10)

    def test_a_status_is_an_answer_here_and_an_error_in_the_registry(self):
        self.assertEqual(nativenet.request(self.url("/missing"), hosts=[self.host], max_bytes=100, timeout=10).status, 404)
        with self.assertRaises(repo.FetchError) as caught:
            repo._native_body(self.url("/missing"), [self.host], {"User-Agent": repo.USER_AGENT}, None, 100, 10)
        self.assertEqual(caught.exception.status, 404)

    def test_a_stream_reads_in_pieces(self):
        with nativenet.open_stream(self.url("/size/200000"), hosts=[self.host], max_bytes=200_000, timeout=10) as stream:
            self.assertEqual(stream.status, 200)
            self.assertEqual(sum(len(c) for c in stream), 200_000)
        with self.assertRaises(nativenet.NetError) as caught:
            with nativenet.open_stream(self.url("/size/200000"), hosts=[self.host], max_bytes=199_999, timeout=10) as stream:
                for _ in stream:
                    pass
        self.assertEqual(caught.exception.kind, "too-large")

    def test_a_module_fetch_goes_native_with_the_modules_hosts(self):
        eco = types.SimpleNamespace(id="local", hosts=frozenset({self.host}), rate={})
        fetch = base.Fetch(eco, repo.module_transport)
        with mock.patch.object(repo, "_module_opener", side_effect=AssertionError("urllib was used")):
            self.assertEqual(fetch.json(self.url("/json")), {"a": [1, 2]})
            with self.assertRaises(repo.FetchError) as caught:
                fetch.text(self.url("/out"))
            self.assertIn("redirect blocked", str(caught.exception))
            with self.assertRaises(repo.FetchError) as caught:
                fetch.bytes(self.url("/size/5001"), max_bytes=5000)
            self.assertIn("exceeds", str(caught.exception))
            with self.assertRaises(repo.FetchError) as caught:
                fetch.text(self.url("/missing"))
            self.assertEqual(caught.exception.status, 404)
        self.assertEqual(repo._module_hosts(fetch.check_url), frozenset({self.host}))
        self.assertIsNone(repo._module_hosts(lambda url: url), "a rule given as a function goes through urllib")

    def test_lazaret_network_python_asks_for_urllib(self):
        eco = types.SimpleNamespace(id="local", hosts=frozenset({self.host}), rate={})
        fetch = base.Fetch(eco, repo.module_transport)

        class Opener:
            def open(self, req, timeout=None):
                raise urllib.error.URLError("the urllib path")

        with mock.patch.dict(os.environ, {nativenet.ENV: "python"}), \
                mock.patch.object(repo, "_module_opener", lambda check: Opener()), \
                self.assertRaises(repo.FetchError) as caught:
            fetch.text(self.url("/ok"))
        self.assertIn("the urllib path", str(caught.exception))
        self.assertFalse(nativenet.chosen(self.url("/ok")) and os.environ.get(nativenet.ENV) == "python")

    def test_a_server_without_tls13_is_left_to_python(self):
        server, port = serve(self.cert, self.key, max_version=ssl.TLSVersion.TLSv1_2)
        host = f"localhost:{port}"
        try:
            with self.assertRaises(nativenet.UsePython):
                nativenet.request(f"https://{host}/ok", hosts=[host], max_bytes=100, timeout=10)
            self.assertIn(host, nativenet.python_hosts())
            self.assertFalse(nativenet.chosen(f"https://{host}/x"), "that host goes to Python's transport from then on")
            # and the registry's fetch does so: urllib, trusting the test's root, gets the answer
            context = ssl.create_default_context(cadata=self.root)
            eco = types.SimpleNamespace(id="local", hosts=frozenset({host}), rate={})
            fetch = base.Fetch(eco, repo.module_transport)

            def opener(check):
                return urllib.request.build_opener(repo._ModuleRedirects(check), urllib.request.HTTPSHandler(context=context))
            with mock.patch.object(repo, "_module_opener", opener):
                self.assertEqual(fetch.text(f"https://{host}/ok"), "hello")
        finally:
            server.stop()

    def test_a_redirect_to_a_server_without_tls13_leaves_that_one_to_python(self):
        # (the credentials review of decision 14: it used to put the first URL's host on Python's transport)
        server, port = serve(self.cert, self.key, max_version=ssl.TLSVersion.TLSv1_2)
        old = f"localhost:{port}"
        try:
            with self.assertRaises(nativenet.UsePython):
                nativenet.request(self.url(f"/to-port/{port}"), hosts=[self.host, old], max_bytes=100, timeout=10)
            self.assertIn(old, nativenet.python_hosts())
            self.assertNotIn(self.host, nativenet.python_hosts())
            self.assertTrue(nativenet.chosen(self.url("/ok")), "the first URL's host stays on the native transport")
        finally:
            server.stop()
            with nativenet._lock:
                nativenet._python_hosts.discard(old)

    def seen(self, path, credentials, hosts=None, **kw):
        """The request's fields as the server saw them (on the last hop)."""
        reply = nativenet.request(self.url(path), hosts=hosts or [self.host, f"127.0.0.1:{self.port}"], max_bytes=10_000,
                                  timeout=10, credentials=credentials, **kw)
        self.assertEqual(reply.status, 200)
        return json.loads(reply.body)

    def test_a_credential_goes_to_its_own_host_alone(self):
        # (decision 14: credentials over tiny_https, each given by its hop hook to the hops to its own host)
        token = nativenet.Credential(self.host, "/", "Authorization", "Bearer t0ken")
        gitlab = nativenet.Credential(self.host, "/", "PRIVATE-TOKEN", "glpat-t0ken")
        seen = self.seen("/headers", [token, gitlab])
        self.assertEqual((seen.get("authorization"), seen.get("private-token")), ("Bearer t0ken", "glpat-t0ken"))
        seen = self.seen("/to-headers", [token, gitlab])
        self.assertEqual((seen.get("authorization"), seen.get("private-token")), ("Bearer t0ken", "glpat-t0ken"),
                         "a redirect to the same host")
        seen = self.seen("/out-headers", [token, gitlab])
        self.assertEqual((seen.get("authorization"), seen.get("private-token")), (None, None),
                         "a redirect to another host gets none (PRIVATE-TOKEN included)")
        there = nativenet.Credential(f"127.0.0.1:{self.port}", "/", "Authorization", "Bearer there")
        self.assertEqual(self.seen("/out-headers", [token, there]).get("authorization"), "Bearer there")
        self.assertIsNone(self.seen("/headers", [there]).get("authorization"))
        self.assertIsNone(self.seen("/headers", [nativenet.Credential(self.host, "/elsewhere/", "Authorization", "x")])
                          .get("authorization"), "a path the credential is not for")
        self.assertIsNone(self.seen("/headers", []).get("authorization"), "the next request carries none")

    def test_the_urls_own_login_goes_with_the_request_alone(self):
        own = nativenet.Credential(self.host, "/", "Authorization", "Basic b3du", first=True)
        settings = nativenet.Credential(self.host, "/", "Authorization", "Bearer settings")
        self.assertEqual(self.seen("/headers", [settings, own])["authorization"], "Basic b3du")
        self.assertEqual(self.seen("/to-headers", [settings, own])["authorization"], "Bearer settings")
        self.assertIsNone(self.seen("/to-headers", [own]).get("authorization"))

    def test_a_credential_is_never_a_header(self):
        for name in ("Authorization", "PRIVATE-TOKEN", "Cookie"):
            with self.subTest(name=name), self.assertRaises(nativenet.NetError) as caught:
                nativenet.request(self.url("/headers"), hosts=[self.host], max_bytes=10_000, timeout=10,
                                  headers=[(name, "s3cret")])
            self.assertEqual(caught.exception.kind, "setup")
            self.assertNotIn("s3cret", str(caught.exception))
        for bad in (nativenet.Credential(self.host, "/", "Authorization", "Bearer töken"),
                    nativenet.Credential(self.host, "/päth/", "Authorization", "x"),
                    nativenet.Credential(self.host.upper(), "/", "Authorization", "x"),
                    nativenet.Credential(self.host, "/", "Authorization", "a\r\nInjected: 1")):
            with self.subTest(bad=bad), self.assertRaises(nativenet.UsePython):
                nativenet.request(self.url("/headers"), hosts=[self.host], max_bytes=10_000, timeout=10, credentials=[bad])

    def test_a_sources_token_goes_native_to_its_api_host_alone(self):
        from lazaret.registry import sources
        headers = {"User-Agent": repo.USER_AGENT, "Authorization": "Bearer t0ken", "PRIVATE-TOKEN": "glpat"}
        hosts = {self.host, f"127.0.0.1:{self.port}"}
        with mock.patch.object(sources.urllib.request, "build_opener", side_effect=AssertionError("urllib was used")):
            seen = json.loads(sources._http(self.url("/headers"), dict(headers), 10_000, hosts, self.host))
            self.assertEqual((seen.get("authorization"), seen.get("private-token")), ("Bearer t0ken", "glpat"))
            seen = json.loads(sources._http(self.url("/out-headers"), dict(headers), 10_000, hosts, self.host))
            self.assertEqual((seen.get("authorization"), seen.get("private-token")), (None, None))
            self.assertEqual(seen.get("user-agent"), repo.USER_AGENT)
            # a GitLab under a path prefix: the token goes with the paths under it alone
            gitlab = {"User-Agent": repo.USER_AGENT, "PRIVATE-TOKEN": "glpat"}
            seen = json.loads(sources._http(self.url("/gitlab/echo"), dict(gitlab), 10_000, hosts, self.host,
                                            auth_path="/gitlab/"))
            self.assertEqual((seen["path"], seen.get("private-token")), ("/gitlab/echo", "glpat"))
            seen = json.loads(sources._http(self.url("/gitlab/../echo"), dict(gitlab), 10_000, hosts, self.host,
                                            auth_path="/gitlab/"))
            self.assertEqual((seen["path"], seen.get("private-token")), ("/gitlab/../echo", None), "/echo, to a server")

    def test_a_root_it_was_not_given_is_refused(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            _root, cert, key = make_pki(tmp.name)
            server, port = serve(cert, key)
            host = f"localhost:{port}"
            with self.assertRaises(nativenet.NetError) as caught:
                nativenet.request(f"https://{host}/ok", hosts=[host], max_bytes=100, timeout=10)
            self.assertEqual(caught.exception.kind, "tls")
            server.stop()
        finally:
            tmp.cleanup()


class ChoiceTests(unittest.TestCase):
    """What decides the transport, without a network."""

    def test_the_environment_asks_for_python(self):
        with mock.patch.dict(os.environ, {nativenet.ENV: "python"}):
            self.assertTrue(nativenet.disabled())
            self.assertFalse(nativenet.available())
            self.assertFalse(nativenet.chosen("https://registry.npmjs.org/x"))
            self.assertEqual(nativenet.why_not(), "LAZARET_NETWORK=python")
            with self.assertRaises(nativenet.UsePython):
                nativenet.request("https://registry.npmjs.org/x", hosts=["registry.npmjs.org"], max_bytes=1, timeout=1)
        with mock.patch.dict(os.environ, {nativenet.ENV: "native"}):
            self.assertFalse(nativenet.disabled())

    def test_the_proxy_is_urllibs(self):
        env = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "no_proxy")}
        with mock.patch.dict(os.environ, {**env, "HTTPS_PROXY": "http://proxy.invalid:3128"}, clear=True):
            self.assertEqual(nativenet._proxy_for("https://registry.npmjs.org/x"), "env")
        with mock.patch.dict(os.environ, {**env, "HTTPS_PROXY": "https://proxy.invalid:3128"}, clear=True), \
                self.assertRaises(nativenet.UsePython):
            nativenet._proxy_for("https://registry.npmjs.org/x")
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(urllib.request, "getproxies", lambda: {"https": "http://sys.invalid:8080"}), \
                mock.patch.object(urllib.request, "proxy_bypass", lambda host: host == "pypi.org"):
            self.assertEqual(nativenet._proxy_for("https://registry.npmjs.org/x"), "http://sys.invalid:8080")
            self.assertEqual(nativenet._proxy_for("https://pypi.org/x"), "direct")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(urllib.request, "getproxies", lambda: {}):
            self.assertEqual(nativenet._proxy_for("https://registry.npmjs.org/x"), "direct")
        if os.name != "nt":           # (one variable to Windows, whatever its case)
            # what urllib and the native client read differently goes to urllib: the lower-case name first to urllib,
            # and an empty one unsets the setting; the upper-case name first to tiny_https (the credentials review)
            for differ in ({"HTTPS_PROXY": "http://a.invalid:3128", "https_proxy": "http://b.invalid:3128"},
                           {"HTTPS_PROXY": "", "https_proxy": "http://b.invalid:3128"},
                           {"HTTPS_PROXY": "http://a.invalid:3128", "https_proxy": ""},
                           {"HTTPS_PROXY": "http://a.invalid:3128", "NO_PROXY": "x.example", "no_proxy": "y.example"}):
                with self.subTest(differ), mock.patch.dict(os.environ, {**env, **differ}, clear=True), \
                        self.assertRaises(nativenet.UsePython):
                    nativenet._proxy_for("https://registry.npmjs.org/x")
            same = {"HTTPS_PROXY": "http://a.invalid:3128", "https_proxy": "http://a.invalid:3128", "no_proxy": "x.example"}
            with mock.patch.dict(os.environ, {**env, **same}, clear=True):
                self.assertEqual(nativenet._proxy_for("https://registry.npmjs.org/x"), "env")
        # one setting that the two read differently: tiny_https takes port 8080 when a path follows the port or none is
        # given (urllib: the port, or 443), "*" anywhere in NO_PROXY, and no entry with a port (the second review)
        npm = "https://registry.npmjs.org/x"
        for differ, url in [({"HTTPS_PROXY": "http://a.invalid:3128/"}, npm), ({"HTTPS_PROXY": "http://a.invalid"}, npm),
                            ({"HTTPS_PROXY": "http://a.invalid:3128", "NO_PROXY": "localhost,*"}, npm),
                            ({"HTTPS_PROXY": "http://a.invalid:3128", "NO_PROXY": "registry.npmjs.org:443"},
                             "https://registry.npmjs.org:443/x"),
                            ({"HTTPS_PROXY": "http://u%40x:p@a.invalid:3128"}, npm)]:
            with self.subTest(differ), mock.patch.dict(os.environ, {**env, **differ}, clear=True), \
                    self.assertRaises(nativenet.UsePython):
                nativenet._proxy_for(url)
        for alike, url, want in [({"HTTPS_PROXY": "http://a.invalid:3128", "NO_PROXY": ".npmjs.org,::1"}, "https://registry.npmjs.org/x",
                                  "env"),
                                 ({"HTTPS_PROXY": "a.invalid:3128", "NO_PROXY": "*"}, "https://registry.npmjs.org/x", "env"),
                                 ({"HTTPS_PROXY": "http://u:p@a.invalid:3128"}, "https://pypi.org/simple/", "env")]:
            with self.subTest(alike), mock.patch.dict(os.environ, {**env, **alike}, clear=True):
                self.assertEqual(nativenet._proxy_for(url), want)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(urllib.request, "getproxies", lambda: {"https": "http://sys.invalid:3128/"}), \
                mock.patch.object(urllib.request, "proxy_bypass", lambda host: False), \
                self.assertRaises(nativenet.UsePython):
            nativenet._proxy_for("https://registry.npmjs.org/x")

    def test_the_request_description(self):
        with mock.patch.object(nativenet, "_proxy_for", lambda url: "direct"):
            spec = json.loads(nativenet._spec("https://a.example/x", {"b.example", "a.example"}, "GET",
                                              [("Accept", "x")], 10, 2.5, 3, None))
        self.assertEqual(spec, {"method": "GET", "url": "https://a.example/x", "headers": [["Accept", "x"]],
                                "hosts": ["a.example", "b.example"], "any_host": False, "max_bytes": 10,
                                "timeout_ms": 2500, "total_timeout_ms": None, "max_redirects": 3, "proxy": "direct",
                                "http2": True})
        spec = json.loads(nativenet._spec("https://a.example/x", None, "GET", [], 10, 1, 3, None, None, "direct"))
        self.assertEqual((spec["hosts"], spec["any_host"], spec["proxy"]), ([], True, "direct"), "no host rule")
        with self.assertRaises(nativenet.NetError):
            nativenet._spec("https://a.example/x", [], "GET", [], 10, 1, 3, None, None, "direct")
        spec = json.loads(nativenet._spec("https://a.example/x", None, "GET", [], 10, 1, 3, None, None, "direct",
                                          [nativenet.Credential("a.example", "/x/", "Authorization", "Bearer t", True)]))
        self.assertEqual(spec["credentials"], [{"host": "a.example", "path": "/x/", "name": "Authorization",
                                                "value": "Bearer t", "first": True}])

    def test_a_credentials_host_is_written_as_a_host_header_is(self):
        key = nativenet.host_key
        self.assertEqual(key("https://API.GitHub.com/repos"), "api.github.com")
        self.assertEqual(key("https://gl.example.org:443/x"), "gl.example.org")
        self.assertEqual(key("https://gl.example.org:8443/x"), "gl.example.org:8443")
        self.assertEqual(key("https://[::1]:8443/x"), "[::1]:8443")
        self.assertEqual(key("https://user:pw@gl.example.org/x"), "gl.example.org")
        self.assertEqual((key("https:///x"), key("https://h:99999/")), ("", ""))
        from lazaret.registry import pmsettings
        for url in ("https://API.example.org/a/", "https://h.example:8443/b/", "https://[::1]:8443/c/"):
            with self.subTest(url=url):
                self.assertEqual(key(url), pmsettings._origin(url)[2], "as pmsettings.Credentials keys a host")
        shown = repr(nativenet.Credential("a.example", "/", "Authorization", "Bearer s3cret"))
        self.assertNotIn("s3cret", shown)
        self.assertNotIn("s3cret", str([nativenet.Credential("a.example", "/", "Authorization", "Bearer s3cret")]))

    def test_documents_go_over_http2_and_downloads_over_http11(self):
        def offered(budget, mode=None, h2=None):
            env = {k: v for k, v in os.environ.items() if k != nativenet.HTTP_ENV}
            if mode is not None:
                env[nativenet.HTTP_ENV] = mode
            with mock.patch.object(nativenet, "_proxy_for", lambda url: "direct"), mock.patch.dict(os.environ, env, clear=True):
                return json.loads(nativenet._spec("https://a.example/x", {"a.example"}, "GET", [], budget, 1, 3, None, h2))["http2"]
        self.assertTrue(offered(repo.MAX_FEED_BYTES), "a registry document")
        self.assertTrue(offered(nativenet.DOCUMENT_BUDGET), "the Marketplace's query, PyPI's XML-RPC")
        self.assertFalse(offered(repo.MAX_DOWNLOAD_BYTES), "an artifact")
        self.assertTrue(offered(repo.MAX_DOWNLOAD_BYTES, "2"))
        self.assertFalse(offered(repo.MAX_FEED_BYTES, "1.1"))
        self.assertTrue(offered(repo.MAX_FEED_BYTES, "auto"))
        self.assertFalse(offered(repo.MAX_FEED_BYTES, h2=False), "the caller's choice")
        self.assertTrue(offered(repo.MAX_DOWNLOAD_BYTES, h2=True))


if __name__ == "__main__":
    unittest.main()
