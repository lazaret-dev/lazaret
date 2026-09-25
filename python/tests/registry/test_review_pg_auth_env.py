"""Review follow-up: opting the registry's Postgres state DB into MD5 or
cleartext-password authentication over unverified TLS.

lazaret.pg refuses MD5 and cleartext passwords over TLS whose certificate
was not verified (sslmode=prefer/require) unless pg.connect() gets
allow_md5_over_unverified_tls / allow_cleartext_password. Those are Python
keywords, not libpq parameters, and the DSN parser rejects unknown keys, so
a LAZARET_DB DSN could not carry them: a registry whose Postgres role still
used MD5 behind sslmode=require could not connect at all. Store now passes
them when LAZARET_PG_ALLOW_MD5_OVER_UNVERIFIED_TLS=1 /
LAZARET_PG_ALLOW_CLEARTEXT_PASSWORD=1 (insecure escape hatches, off by
default). The fake servers below only ask for a password: dummy
credentials, loopback only, nothing is executed.
"""
import os
import unittest
from unittest import mock

from lazaret import pg
from lazaret.pg import _dsn
from lazaret.pg.connection import Connection
from lazaret.registry import repo
from tests.pg.test_review_tls import CLEARTEXT, MD5, password_phishing_server

MD5_VAR = "LAZARET_PG_ALLOW_MD5_OVER_UNVERIFIED_TLS"
CLEAR_VAR = "LAZARET_PG_ALLOW_CLEARTEXT_PASSWORD"


def clean_env(**set_vars):
    env = {k: v for k, v in os.environ.items() if k not in (MD5_VAR, CLEAR_VAR)}
    env.update(set_vars)
    return mock.patch.dict(os.environ, env, clear=True)


class Options(unittest.TestCase):
    def test_off_by_default(self):
        self.assertEqual(repo.pg_insecure_auth_options({}), {})

    def test_exactly_1_enables(self):
        self.assertEqual(repo.pg_insecure_auth_options({MD5_VAR: "1"}),
                         {"allow_md5_over_unverified_tls": True})
        self.assertEqual(repo.pg_insecure_auth_options({CLEAR_VAR: "1"}),
                         {"allow_cleartext_password": True})
        self.assertEqual(repo.pg_insecure_auth_options({MD5_VAR: "1", CLEAR_VAR: "1"}),
                         {"allow_md5_over_unverified_tls": True, "allow_cleartext_password": True})
        for value in ("0", "", "true", "yes", " 1"):
            self.assertEqual(repo.pg_insecure_auth_options({MD5_VAR: value, CLEAR_VAR: value}), {})

    def test_the_dsn_cannot_carry_them(self):
        # why the variables exist: libpq has no such parameters
        for dsn in ("postgres://u@192.0.2.1/d?allow_md5_over_unverified_tls=1",
                    "host=192.0.2.1 dbname=d allow_cleartext_password=1"):
            with self.assertRaises(pg.InterfaceError):
                _dsn.resolve(dsn)

    def test_store_passes_them_to_connect(self):
        conn = mock.MagicMock()
        for env, want in (({}, {}),
                          ({MD5_VAR: "1"}, {"allow_md5_over_unverified_tls": True}),
                          ({CLEAR_VAR: "1"}, {"allow_cleartext_password": True})):
            with self.subTest(env=env), clean_env(**env), \
                    mock.patch.object(pg, "connect", return_value=conn) as connect:
                repo.Store("postgres://lazaret@192.0.2.1/lazaret?sslmode=require")
                kwargs = connect.call_args.kwargs
                self.assertEqual({k: v for k, v in kwargs.items() if k.startswith("allow_")}, want)
                self.assertEqual(connect.call_args.args,
                                 ("postgres://lazaret@192.0.2.1/lazaret?sslmode=require",))


class EndToEnd(unittest.TestCase):
    """Store against a server that asks for a password over TLS whose
    certificate was not verified (TLS negotiation stubbed, as in
    tests/pg/test_review_tls.py). Records whether the password was sent."""

    def run_case(self, request, **env):
        def fake_tls(conn, sock):
            conn.ssl_in_use, conn._tls_verified = True, False
            return sock
        srv = password_phishing_server(request)
        dsn = f"postgres://u:dummy-pw@127.0.0.1:{srv.port}/d?sslmode=require&connect_timeout=5"
        with clean_env(**env), mock.patch.object(Connection, "_negotiate_ssl", fake_tls):
            with self.assertRaises(RuntimeError) as cm:     # the fake server never finishes
                repo.Store(dsn)
        srv.thread.join(5)
        return str(cm.exception), b"p" in srv.received

    def test_refused_by_default(self):
        for request, word in ((MD5, "MD5"), (CLEARTEXT, "cleartext")):
            with self.subTest(word):
                msg, sent = self.run_case(request)
                self.assertIn("Postgres backend unreachable", msg)
                self.assertIn(word, msg)
                self.assertFalse(sent, "no password may reach an unverified server")

    def test_md5_opt_in(self):
        self.assertTrue(self.run_case(MD5, **{MD5_VAR: "1"})[1])
        self.assertFalse(self.run_case(MD5, **{CLEAR_VAR: "1"})[1])

    def test_cleartext_opt_in(self):
        self.assertTrue(self.run_case(CLEARTEXT, **{CLEAR_VAR: "1"})[1])
        self.assertFalse(self.run_case(CLEARTEXT, **{MD5_VAR: "1"})[1])


if __name__ == "__main__":
    unittest.main()
