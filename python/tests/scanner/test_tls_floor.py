"""TLS 1.2 is the floor of every transport Lazaret has (John, Oct 7: "Realistically we should avoid any tls < 1.2 as
that would be horrible security stance by a provider"). The native client speaks TLS 1.3 and 1.2 and refuses a server
that speaks neither, without handing it to Python's transport (test_nativenet.py). This file holds Python's transport
to the same floor: each connection it makes states the floor in its context, so a process that lowered Python's
default does not lower Lazaret's; and a source check holds every urllib opener, HTTPS connection and TLS context under
python/src to it.

The server is local: Python's ssl speaking TLS 1.0 and 1.1 and nothing newer (OpenSSL's security level 0 allows it),
with a root and a certificate the `openssl` command makes when the tests start. Those tests skip where the command is
missing or this OpenSSL no longer speaks TLS 1.1. Nothing leaves the machine."""

import ast
import contextlib
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import warnings
from unittest import mock

from lazaret.registry import keepalive, repo
from lazaret.scanner import nativenet, sca_feeds, secretverify_http
from tests.scanner.test_nativenet import NO_PROXY_ENV, Handler, Server

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "lazaret"
#: a name for the secret transport, which takes a DNS name with a dot in it; it is reached at 127.0.0.1
NAME = "api.lazaret.invalid"


def make_pki(folder):
    """(the root's file, the server's certificate file, its key file): a root, and a certificate under it for
    localhost, 127.0.0.1 and NAME, both for a day."""
    def run(*args):
        subprocess.run(["openssl", *args], cwd=folder, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=30)
    pathlib.Path(folder, "leaf.ext").write_text(
        f"subjectAltName=DNS:localhost,IP:127.0.0.1,DNS:{NAME}\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="ascii")
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
        "-out", "ca.pem", "-days", "1", "-subj", "/CN=Lazaret TLS floor test root",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "leaf.key",
        "-out", "leaf.csr", "-subj", "/CN=localhost")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "leaf.pem",
        "-days", "1", "-extfile", "leaf.ext")
    return tuple(os.path.join(folder, f) for f in ("ca.pem", "leaf.pem", "leaf.key"))


def _speak_old_versions(context):
    with warnings.catch_warnings():                         # (Python says TLS 1.0 and 1.1 are deprecated: that is the point)
        warnings.simplefilter("ignore", DeprecationWarning)
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        context.minimum_version = ssl.TLSVersion.TLSv1


def lowered(cafile):
    """What a process that lowered Python's default would hand out: a client context that speaks TLS 1.0 and 1.1 too,
    trusting the test's root (and checking the hostname, as the default does)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile)
    _speak_old_versions(context)
    return context


def serve_old(cert, key):
    """A local HTTPS server that speaks TLS 1.0 and 1.1 and nothing newer: (server, port)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    _speak_old_versions(context)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    server = Server(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


@unittest.skipUnless(shutil.which("openssl"), "no openssl command to make the test's certificates with")
class PythonTransportFloorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root, cert, key = make_pki(cls.tmp.name)
        try:
            cls.server, cls.port = serve_old(cert, key)
        except (ssl.SSLError, ValueError) as exc:
            raise unittest.SkipTest(f"this OpenSSL does not serve TLS 1.1 ({exc})") from None
        cls.addClassCleanup(cls.server.stop)
        try:                                                # (the server speaks TLS 1.1 to a client that would)
            with socket.create_connection(("127.0.0.1", cls.port), timeout=10) as raw, \
                    lowered(cls.root).wrap_socket(raw, server_hostname="localhost") as tls:
                cls.version = tls.version()
        except (ssl.SSLError, OSError) as exc:
            raise unittest.SkipTest(f"this OpenSSL does not speak TLS 1.1 ({exc})") from None
        env = mock.patch.dict(os.environ, NO_PROXY_ENV, clear=True)
        env.start()
        cls.addClassCleanup(env.stop)

    def url(self, path="/ok"):
        return f"https://localhost:{self.port}{path}"

    def lowered_default(self):
        """Python's defaults lowered, as a process might have them: urllib's context (what PEP 476 lets a program
        replace) and `ssl.create_default_context`."""
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(ssl, "_create_default_https_context", lambda: lowered(self.root)))
        stack.enter_context(mock.patch.object(ssl, "create_default_context", lambda *a, **k: lowered(self.root)))
        return stack

    def assert_refused(self, open_url):
        with self.assertRaises((urllib.error.URLError, ssl.SSLError, OSError)) as caught:
            open_url()
        error = caught.exception.reason if isinstance(caught.exception, urllib.error.URLError) else caught.exception
        self.assertIsInstance(error, ssl.SSLError, f"not refused in the handshake: {caught.exception!r}")
        self.assertIn("PROTOCOL", error.reason or "", f"not refused for its TLS version: {error!r}")

    def test_the_server_speaks_tls11_to_a_client_that_would(self):
        self.assertEqual(self.version, "TLSv1.1")
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=lowered(self.root)))
        with opener.open(self.url(), timeout=10) as answer:
            self.assertEqual(answer.read(), b"hello")

    def test_urllibs_own_default_lowered_would_speak_it(self):
        # (the control for the tests below: with this patch, an opener urllib builds by itself gets the answer)
        with self.lowered_default(), urllib.request.build_opener().open(self.url(), timeout=10) as answer:
            self.assertEqual(answer.read(), b"hello")

    def test_lazarets_urllib_openers_refuse_it(self):
        with self.lowered_default():
            for name, opener in (("nativenet.HTTPSHandler", urllib.request.build_opener(nativenet.HTTPSHandler())),
                                 ("repo's registry opener", repo._OPENER),
                                 ("repo's module opener", repo._module_opener(lambda url: url)),
                                 ("the SCA feeds' opener", sca_feeds._OPENER)):
                with self.subTest(name):
                    self.assert_refused(lambda: opener.open(self.url(), timeout=10).read())

    def test_the_kept_alive_connections_refuse_it(self):
        control = keepalive.Pool(context=lowered(self.root))                 # (the pool reaches it, given that context)
        self.addCleanup(control.close)
        with control.request(self.url(), {}, 10) as answer:
            self.assertEqual((answer.status, answer.read()), (200, b"hello"))
        pool = keepalive.Pool()
        self.addCleanup(pool.close)
        with self.lowered_default():
            self.assert_refused(lambda: pool.request(self.url(), {}, 10))

    def test_the_secret_transport_refuses_it(self):
        ask = secretverify_http.Request("GET", NAME, "/ok", {}, None)
        control = secretverify_http.https_transport(lowered(self.root), ("127.0.0.1", self.port), {})
        self.assertEqual(control(ask, 10, 1000).status, 200)
        with self.lowered_default():
            send = secretverify_http.https_transport(None, ("127.0.0.1", self.port), {})
            with self.assertRaises(secretverify_http.TransportError) as caught:
                send(ask, 10, 1000)
        self.assertEqual(caught.exception.kind, "tls")


class ContextTests(unittest.TestCase):
    """The contexts themselves, without a network."""

    def lowered_to(self, version):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
        return context

    def test_the_floor_is_tls12(self):
        self.assertEqual(nativenet.TLS_FLOOR, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(secretverify_http.TLS_FLOOR, nativenet.TLS_FLOOR)

    def test_a_lowered_default_is_raised_to_the_floor_and_a_higher_one_kept(self):
        for low, want in ((ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.TLSv1_2),
                          (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2),
                          (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2),
                          (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
                          (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)):
            with self.subTest(low):
                with mock.patch.object(ssl, "_create_default_https_context", lambda: self.lowered_to(low)):
                    self.assertEqual(nativenet.tls_context().minimum_version, want)
                with mock.patch.object(ssl, "create_default_context", lambda *a, **k: self.lowered_to(low)):
                    self.assertEqual(secretverify_http.default_context().minimum_version, want)

    def test_the_context_is_urllibs_default_otherwise(self):
        context = nativenet.tls_context()
        self.assertEqual((context.verify_mode, context.check_hostname), (ssl.CERT_REQUIRED, True))
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        made = []
        with mock.patch.object(ssl, "_create_default_https_context", lambda: made.append(1) or ssl.create_default_context()):
            nativenet.tls_context()
        self.assertEqual(made, [1], "built on urllib's default (PEP 476's)")

    def test_the_handler_makes_its_context_when_the_first_request_goes(self):
        handler = nativenet.HTTPSHandler()
        self.assertIsNone(handler._context)
        self.assertIsInstance(handler, urllib.request.HTTPSHandler)
        opener = urllib.request.build_opener(handler)
        self.assertEqual([h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)], [handler],
                         "an opener given one uses it in place of urllib's own")


#: where Python's transport may make a TLS context, and why: each states the floor, or makes no connection
CONTEXT_MAKERS = {
    ("scanner/nativenet.py", "tls_context"): "urllib's default with TLS_FLOOR",
    ("scanner/nativenet.py", "python_roots"): "reads the certificates Python trusts; connects nowhere",
    ("scanner/secretverify_http.py", "default_context"): "Python's default with its TLS_FLOOR",
    ("pg/connection.py", "_ssl_context"): "the minimum from the settings, which refuse anything below TLS 1.2 (pg/_dsn.py)",
}
_MAKERS = {"create_default_context", "SSLContext", "_create_default_https_context", "_create_unverified_context",
           "wrap_socket", "PROTOCOL_TLS", "PROTOCOL_SSLv23"}


class _Sites(ast.NodeVisitor):
    def __init__(self, path):
        self.path, self.stack, self.found = path, [], []

    def visit_FunctionDef(self, node):                       # noqa: N802 (ast's name)
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def note(self, node, what):
        self.found.append((self.path, self.stack[-1] if self.stack else "<module>", node.lineno, what))

    def visit_Attribute(self, node):                         # noqa: N802
        if isinstance(node.value, ast.Name) and node.value.id == "ssl" and node.attr in _MAKERS:
            self.note(node, f"ssl.{node.attr}")
        self.generic_visit(node)

    def visit_Constant(self, node):                          # noqa: N802
        if isinstance(node.value, str) and node.value in _MAKERS:
            self.note(node, repr(node.value))

    def visit_Call(self, node):                              # noqa: N802
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
        if name == "build_opener":
            given = [a for a in node.args if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute)
                     and a.func.attr == "HTTPSHandler" and isinstance(a.func.value, ast.Name)
                     and a.func.value.id in ("nativenet", "_net")]
            unpacked = any(isinstance(a, ast.Starred) for a in node.args)
            if not given and not unpacked:
                self.note(node, "an opener without nativenet.HTTPSHandler()")
        elif name in ("urlopen", "urlretrieve"):
            self.note(node, f"urllib.request.{name} (urllib's default context)")
        elif name == "HTTPSConnection" and not any(k.arg == "context" for k in node.keywords):
            self.note(node, "an HTTPSConnection without a context")
        self.generic_visit(node)


class SourceTests(unittest.TestCase):
    """Every HTTPS connection Python's transport makes is held to the floor: a urllib opener is given
    nativenet.HTTPSHandler, an HTTPSConnection its context, and a context is made only where CONTEXT_MAKERS says."""

    def sites(self):
        found = []
        for path in sorted(SRC.rglob("*.py"), key=lambda p: p.as_posix()):
            rel = path.relative_to(SRC).as_posix()
            visitor = _Sites(rel)
            visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
            found += visitor.found
        return found

    def test_every_https_connection_states_the_floor(self):
        found = self.sites()
        makers = [(p, f) for p, f, _, what in found if what.startswith(("ssl.", "'"))]
        self.assertTrue(set(makers) >= {("scanner/nativenet.py", "tls_context")}, "the check reads the source")
        stray = [s for s in found if (s[0], s[1]) not in CONTEXT_MAKERS or not s[3].startswith(("ssl.", "'"))]
        self.assertEqual(stray, [])

    def test_a_starred_opener_is_one_the_check_reads(self):
        # (guard.py builds its opener from a list: the list must hold the handler)
        guard = (SRC / "registry" / "guard.py").read_text(encoding="utf-8")
        self.assertIn("handlers = [Redirects, nativenet.HTTPSHandler()]", guard)


if __name__ == "__main__":
    unittest.main()
