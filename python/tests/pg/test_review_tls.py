"""Review fixes in TLS policy: sslmode=require becomes verify-ca when libpq's
default root certificate exists (repro r11); a password (cleartext or MD5)
is not handed to a server whose certificate was not verified (repro r3)."""

import base64
import os
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest import mock

from lazaret import pg
from lazaret.pg._dsn import default_root_cert, resolve
from lazaret.pg.connection import Connection
from tests import _support
from tests.pg.test_hostile_server import FakeServer, auth, recv_exact
from tests.pg.test_hostile_server import connect as fake_connect
from tests.pg.test_scram import CA_PEM   # an unrelated test CA (public certificate only)

MATRIX = (os.environ.get("LAZARET_TEST_PG_MATRIX") or "x 0 x x").split()


class HomeDirCase(unittest.TestCase):
    """A private HOME / APPDATA, so libpq's default files can be staged."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        clean.update(HOME=self.home, APPDATA=os.path.join(self.home, "AppData"))
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def install_root_cert(self):
        path = default_root_cert()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(CA_PEM + "\n")
        return path


class DefaultRootCertTests(HomeDirCase):
    def context(self, **kw):
        return Connection(resolve(host="db.example.invalid", user="u", **kw))._ssl_context()

    def test_require_verifies_the_chain_when_root_crt_exists(self):
        self.assertEqual(self.context(sslmode="require").verify_mode, ssl.CERT_NONE)
        self.install_root_cert()
        ctx = self.context(sslmode="require")
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_REQUIRED, False))  # verify-ca
        self.assertEqual(self.context(sslmode="prefer").verify_mode, ssl.CERT_NONE)  # unchanged, as in libpq

    def test_verify_modes_use_the_default_path(self):
        with self.assertRaisesRegex(pg.OperationalError, "root.crt does not exist"):
            self.context(sslmode="verify-full")
        self.install_root_cert()
        ctx = self.context(sslmode="verify-full")
        self.assertEqual((ctx.verify_mode, ctx.check_hostname), (ssl.CERT_REQUIRED, True))

    def test_windows_location(self):
        with mock.patch.object(os, "name", "nt"):
            path = default_root_cert()
        self.assertEqual(path, os.path.join(self.home, "AppData", "postgresql", "root.crt"))


def password_phishing_server(request, tls_context=None):
    """Plays a man-in-the-middle that terminates TLS (if tls_context) and asks
    for the password with auth request `request`. Records any reply."""
    def script(conn, srv):
        if tls_context is not None:
            recv_exact(conn, 8)  # SSLRequest
            conn.sendall(b"S")
            # wrap_socket takes over the socket: FakeServer's close() of the
            # plain one is then a no-op, so this one is closed here
            conn = tls_context.wrap_socket(conn, server_side=True)
        try:
            srv.read_startup(conn)
            conn.sendall(request)
            try:
                srv.read_message(conn)
            except OSError:
                pass
        finally:
            conn.close()
    return FakeServer(script)


CLEARTEXT, MD5 = auth(3), auth(5, b"salt")


class UnverifiedTlsPolicyTests(unittest.TestCase):
    """The rule itself, with TLS negotiation stubbed out: `verified` says
    whether the certificate chain was checked."""

    def run_case(self, request, verified, **kw):
        def fake_tls(conn, sock):
            conn.ssl_in_use, conn._tls_verified = True, verified
            return sock
        srv = password_phishing_server(request)
        with mock.patch.object(Connection, "_negotiate_ssl", fake_tls):
            try:
                fake_connect(srv, sslmode="require", **kw).close()
            except pg.Error as exc:
                error = exc
            else:
                error = None
        srv.thread.join(5)
        return error, b"p" in srv.received

    def test_refused_without_verification(self):
        for request, word in ((CLEARTEXT, "cleartext"), (MD5, "MD5")):
            with self.subTest(word):
                error, sent = self.run_case(request, verified=False)
                self.assertIsInstance(error, pg.AuthenticationError)
                self.assertIn(word, str(error))
                self.assertFalse(sent)

    def test_opt_ins(self):
        self.assertTrue(self.run_case(CLEARTEXT, verified=False, allow_cleartext_password=True)[1])
        self.assertTrue(self.run_case(MD5, verified=False, allow_md5_over_unverified_tls=True)[1])
        self.assertFalse(self.run_case(MD5, verified=False, allow_cleartext_password=True)[1])

    def test_allowed_with_a_verified_certificate(self):
        self.assertTrue(self.run_case(CLEARTEXT, verified=True)[1])
        self.assertTrue(self.run_case(MD5, verified=True)[1])

    def test_md5_without_tls_is_unchanged(self):
        srv = password_phishing_server(MD5)
        try:
            fake_connect(srv, sslmode="disable")
        except pg.Error:
            pass
        srv.thread.join(5)
        self.assertIn(b"p", srv.received)


@unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a throwaway certificate")
class TlsTerminatingMitmTests(unittest.TestCase):
    """Real TLS with a self-signed certificate made for the test (repro r3)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        key, crt = os.path.join(cls.dir, "mitm.key"), os.path.join(cls.dir, "mitm.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key,
                        "-out", crt, "-days", "1", "-subj", "/CN=mitm.invalid"],
                       check=True, capture_output=True, timeout=40)
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(crt, key)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir)

    def test_password_never_reaches_the_mitm(self):
        for sslmode in ("prefer", "require"):
            for request in (CLEARTEXT, MD5):
                with self.subTest(sslmode=sslmode, request=request[5:9]):
                    srv = password_phishing_server(request, self.ctx)
                    with self.assertRaises(pg.AuthenticationError):
                        fake_connect(srv, sslmode=sslmode)
                    srv.thread.join(5)
                    self.assertNotIn(b"p", srv.received)

    def test_scram_still_works_over_unverified_tls(self):
        seen = {}

        def script(conn, srv):
            recv_exact(conn, 8)
            conn.sendall(b"S")
            with self.ctx.wrap_socket(conn, server_side=True) as conn:
                srv.read_startup(conn)
                conn.sendall(auth(10, b"SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00"))
                _, body = srv.read_message(conn)
                seen["mechanism"] = body[:body.index(b"\x00")]
                first = body[body.index(b"\x00") + 5:].decode()
                nonce = first.split("r=")[1]
                conn.sendall(auth(11, f"r={nonce}MITM,s={base64.b64encode(b'salt').decode()},i=4096".encode()))
                srv.read_message(conn)
        srv = FakeServer(script)
        with self.assertRaises(pg.Error):   # the fake can't finish SCRAM, but it was attempted
            fake_connect(srv, sslmode="require")
        srv.thread.join(5)
        self.assertEqual(seen["mechanism"], b"SCRAM-SHA-256-PLUS")  # bound to the MITM's certificate


@_support.requires_env("LAZARET_TEST_PG_MATRIX")
class LiveDefaultRootCertTests(HomeDirCase):
    """Against the auth-matrix server (see test_auth_matrix.py)."""

    def connect(self, **kw):
        host, port, _, _ = MATRIX
        return pg.connect(host=host, port=int(port), user="scram_user", password="scram secret",
                          dbname="postgres", connect_timeout=5, **kw)

    def test_require_with_an_unrelated_root_crt_is_refused(self):
        self.install_root_cert()   # not the CA that signed the server's certificate
        with self.assertRaisesRegex(pg.OperationalError, "verification failed"):
            self.connect(sslmode="require")

    def test_require_with_the_right_root_crt_verifies(self):
        path = self.install_root_cert()
        shutil.copy(MATRIX[2], path)
        c = self.connect(sslmode="require")
        self.addCleanup(c.close)
        self.assertTrue(c.ssl_in_use)
        self.assertEqual(c.fetchval("SELECT 1"), 1)


if __name__ == "__main__":
    unittest.main()
