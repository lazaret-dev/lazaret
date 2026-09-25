"""Review fix: common libpq connection parameters are accepted instead of
being hard errors (repro r16). Cheap ones are implemented, ones without an
effect here warn (warnings.warn), and ones that would change where or how we
connect are refused. Also: sslrootcert=system defaults to verify-full, only
the default Unix-socket directory matches "localhost" in ~/.pgpass, and
libpq's default client certificate is used."""

import getpass
import os
import shutil
import socket
import ssl
import struct
import tempfile
import unittest
import warnings
from unittest import mock

from lazaret import pg
from lazaret.pg._dsn import default_ssl_dir, lookup_pgpass, resolve
from lazaret.pg.connection import Connection, _check_peer
from tests.pg.test_hostile_server import FakeServer, auth, msg
from tests.pg.test_hostile_server import connect as fake_connect
from tests import _support
from tests.pg.test_review_tls import MATRIX, HomeDirCase


class CleanEnvCase(unittest.TestCase):
    def setUp(self):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)


class AcceptedParameterTests(CleanEnvCase):
    def resolve_quietly(self, dsn=None, **kw):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            return resolve(dsn, **kw)

    def test_implemented_parameters(self):
        p = self.resolve_quietly(
            "postgresql://db.example.invalid/lz?target_session_attrs=read-write&gssencmode=disable"
            "&keepalives_idle=30&connect_timeout=7&tcp_user_timeout=9000&client_encoding=UTF8"
            "&fallback_application_name=tool&sslsni=0&ssl_min_protocol_version=TLSv1.3"
            "&sslcertmode=disable&sslcrl=/etc/x.crl&sslcompression=0&load_balance_hosts=disable")
        self.assertEqual((p.target_session_attrs, p.keepalives_idle, p.connect_timeout, p.tcp_user_timeout),
                         ("read-write", 30, 7.0, 9000))
        self.assertEqual((p.application_name, p.sslsni, p.ssl_min_protocol_version, p.sslcertmode, p.sslcrl),
                         ("tool", False, "TLSv1.3", "disable", "/etc/x.crl"))
        self.assertEqual(self.resolve_quietly(application_name="app", fallback_application_name="tool")
                         .application_name, "app")
        self.assertEqual(self.resolve_quietly("host=h requiressl=1").sslmode, "require")
        self.assertEqual(self.resolve_quietly("host=h gssencmode=prefer").host, "h")

    def test_ignored_parameters_warn(self):
        for kw in ({"krbsrvname": "postgres"}, {"sslnegotiation": "direct"}, {"gsslib": "gssapi"},
                   {"load_balance_hosts": "random"}):
            with self.subTest(**kw), self.assertWarnsRegex(UserWarning, list(kw)[0]):
                resolve(host="h", **kw)

    def test_refused_parameters(self):
        for kw in ({"gssencmode": "require"}, {"sslcertmode": "require"}, {"client_encoding": "LATIN1"},
                   {"service": "prod"}, {"replication": "database"}, {"target_session_attrs": "sometimes"},
                   {"hostaddr": "db.example.invalid"}, {"keepalives_idle": "-1"},
                   {"ssl_min_protocol_version": "TLSv1.3", "ssl_max_protocol_version": "TLSv1.2"}):
            with self.subTest(**kw), self.assertRaises(pg.InterfaceError):
                resolve(host="h", **kw)
        self.assertEqual(self.resolve_quietly(host="h", replication="false").host, "h")

    def test_old_tls_versions_are_not_allowed(self):
        with self.assertWarnsRegex(UserWarning, "TLS 1.2"):
            p = resolve(host="h", ssl_min_protocol_version="TLSv1")
        self.assertEqual(p.ssl_min_protocol_version, "TLSv1.2")

    def test_sslrootcert_system_defaults_to_verify_full(self):
        self.assertEqual(resolve("host=h sslrootcert=system").sslmode, "verify-full")
        with self.assertRaisesRegex(pg.InterfaceError, "verify-full"):
            resolve("host=h sslrootcert=system sslmode=require")
        os.environ["PGSSLMODE"] = "verify-ca"
        with self.assertRaises(pg.InterfaceError):
            resolve("host=h sslrootcert=system")

    def test_hostaddr(self):
        p = resolve(host="db.example.invalid", hostaddr="127.0.0.1")
        self.assertEqual((p.host, p.hostaddr, p.is_unix_socket), ("db.example.invalid", "127.0.0.1", False))
        self.assertEqual(resolve(hostaddr="::1").host, "::1")

        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(0) + msg(b"Z", b"I"))
        srv = FakeServer(script)
        c = pg.connect(host="db.example.invalid", hostaddr="127.0.0.1", port=srv.port, user="u",
                       dbname="d", sslmode="disable", connect_timeout=5)
        self.assertIn("db.example.invalid", repr(c))
        c.close()


class PgpassSocketDirectoryTests(CleanEnvCase):
    def test_only_the_default_socket_directory_is_localhost(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        path = os.path.join(d, "pgpass")
        with open(path, "w") as f:
            f.write("/custom/sock:5432:*:*:right\nlocalhost:5432:*:*:local\n")
        os.chmod(path, 0o600)
        self.assertEqual(lookup_pgpass(resolve(host="/custom/sock", user="u", passfile=path)), "right")
        for default in ("/tmp", "/tmp/", "/var/run/postgresql", "/run/postgresql"):
            with self.subTest(default=default):
                self.assertEqual(lookup_pgpass(resolve(host=default, user="u", passfile=path)), "local")
        self.assertIsNone(lookup_pgpass(resolve(host="/elsewhere", user="u", passfile=path)))


class DefaultClientCertificateTests(HomeDirCase):
    def context(self, **kw):
        return Connection(resolve(host="db.example.invalid", user="u", **kw))._ssl_context()

    def test_certificate_without_key_is_an_error(self):
        os.makedirs(default_ssl_dir())
        with open(os.path.join(default_ssl_dir(), "postgresql.crt"), "w") as f:
            f.write("placeholder\n")
        with self.assertRaisesRegex(pg.OperationalError, "not private key file"):
            self.context(sslmode="require")
        self.context(sslmode="require", sslcertmode="disable")  # not loaded at all

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a throwaway key")
    def test_default_certificate_is_loaded(self):
        import subprocess
        os.makedirs(default_ssl_dir())
        key, crt = (os.path.join(default_ssl_dir(), n) for n in ("postgresql.key", "postgresql.crt"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "1", "-subj", "/CN=u"], check=True, capture_output=True, timeout=40)
        with mock.patch.object(ssl.SSLContext, "load_cert_chain") as load:
            self.context(sslmode="require")
        load.assert_called_once_with(crt, key, password="")

    @unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a throwaway key")
    def test_encrypted_key_uses_sslpassword_and_never_prompts(self):
        import subprocess
        os.makedirs(default_ssl_dir())
        key, crt = (os.path.join(default_ssl_dir(), n) for n in ("postgresql.key", "postgresql.crt"))
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-passout", "pass:dummy-pass",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=u"],
                       check=True, capture_output=True, timeout=40)
        with self.assertRaisesRegex(pg.OperationalError, "sslpassword"):
            self.context(sslmode="require")
        self.context(sslmode="require", sslpassword="dummy-pass")

    def test_revocation_lists(self):
        crldir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, crldir)
        root = os.path.join(self.home, "root.pem")
        from tests.pg.test_scram import CA_PEM
        with open(root, "w") as f:
            f.write(CA_PEM + "\n")
        ctx = self.context(sslmode="verify-ca", sslrootcert=root, sslcrldir=crldir)
        self.assertTrue(ctx.verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN)
        self.assertFalse(self.context(sslmode="verify-ca", sslrootcert=root).verify_flags & ssl.VERIFY_CRL_CHECK_CHAIN)
        with self.assertRaisesRegex(pg.OperationalError, "revocation list"):
            self.context(sslmode="verify-ca", sslrootcert=root, sslcrl=os.path.join(crldir, "missing.crl"))


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED (Linux)")
class RequirePeerTests(unittest.TestCase):
    def test_peer_user_name(self):
        a, b = socket.socketpair(socket.AF_UNIX)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        import pwd
        me = pwd.getpwuid(os.getuid()).pw_name
        _check_peer(a, me)
        with self.assertRaisesRegex(pg.OperationalError, "requirepeer"):
            _check_peer(a, me + "-not")


@_support.requires_env("LAZARET_TEST_PG_MATRIX")
@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED (Linux)")
class LiveRequirePeerTests(unittest.TestCase):
    def test_wrong_server_user_is_refused(self):
        _, port, _, sockdir = MATRIX
        with self.assertRaisesRegex(pg.OperationalError, "requirepeer"):
            pg.connect(host=sockdir, port=int(port), user="scram_user", password="scram secret",
                       dbname="postgres", requirepeer="lazaret-no-such-user")


class TargetSessionAttrsTests(unittest.TestCase):
    def server(self, read_only, standby):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(0) + msg(b"S", b"default_transaction_read_only\x00" + read_only + b"\x00")
                         + msg(b"S", b"in_hot_standby\x00" + standby + b"\x00") + msg(b"Z", b"I"))
            try:
                srv.read_message(conn)
            except OSError:
                pass
        return FakeServer(script)

    def test_single_host_checks(self):
        cases = [(b"off", b"off", "read-write", None), (b"off", b"on", "read-write", "read-only"),
                 (b"on", b"off", "read-write", "read-only"), (b"off", b"off", "read-only", "not read-only"),
                 (b"on", b"off", "read-only", None), (b"off", b"on", "primary", "hot standby"),
                 (b"off", b"off", "standby", "not in hot standby"), (b"off", b"on", "standby", None),
                 (b"off", b"off", "prefer-standby", None), (b"on", b"on", "any", None)]
        for read_only, standby, attrs, problem in cases:
            with self.subTest(read_only=read_only, standby=standby, attrs=attrs):
                srv = self.server(read_only, standby)
                if problem:
                    with self.assertRaisesRegex(pg.OperationalError, problem):
                        fake_connect(srv, target_session_attrs=attrs)
                else:
                    fake_connect(srv, target_session_attrs=attrs).close()


if __name__ == "__main__":
    unittest.main()
