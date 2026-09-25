import os
import tempfile
import unittest
from unittest import mock

from lazaret.pg._dsn import lookup_pgpass, parse_dsn, resolve
from lazaret.pg.errors import InterfaceError


class DsnTests(unittest.TestCase):
    def setUp(self):
        # isolate from the developer's PG* environment variables
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_url(self):
        d = parse_dsn("postgresql://al%40ice:p%3Ass@db.example.com:6543/my%20db?sslmode=verify-full&application_name=x")
        self.assertEqual(d, {"user": "al@ice", "password": "p:ss", "host": "db.example.com", "port": "6543",
                             "dbname": "my db", "sslmode": "verify-full", "application_name": "x"})

    def test_url_ipv6_and_unix_socket(self):
        self.assertEqual(parse_dsn("postgres://[::1]:5433/db"), {"host": "::1", "port": "5433", "dbname": "db"})
        self.assertEqual(parse_dsn("postgresql://%2FVar%2Frun%2Fpg/db")["host"], "/Var/run/pg")
        self.assertEqual(parse_dsn("postgresql:///db?host=/tmp")["host"], "/tmp")

    def test_keyvalue(self):
        d = parse_dsn(r"host=localhost port=5432 dbname = 'my db' password='it\'s \\ ok' user=bob")
        self.assertEqual(d, {"host": "localhost", "port": "5432", "dbname": "my db",
                             "password": "it's \\ ok", "user": "bob"})

    def test_bad_dsns(self):
        for bad in ("host", "host='x", "bogus=1", "postgresql://h1,h2/db"):
            with self.subTest(bad=bad), self.assertRaises(InterfaceError):
                parse_dsn(bad)

    def test_precedence_kwargs_over_dsn_over_env(self):
        os.environ.update(PGHOST="envhost", PGUSER="envuser", PGPORT="1111")
        p = resolve("postgresql://dsnuser@dsnhost/db", port=2222)
        self.assertEqual((p.host, p.user, p.port, p.database), ("dsnhost", "dsnuser", 2222, "db"))
        p = resolve()
        self.assertEqual((p.host, p.user, p.port, p.database), ("envhost", "envuser", 1111, "envuser"))

    def test_defaults_and_validation(self):
        p = resolve(user="u")
        self.assertEqual((p.host, p.port, p.database, p.sslmode, p.channel_binding),
                         ("localhost", 5432, "u", "prefer", "prefer"))
        for kwargs in ({"sslmode": "allow"}, {"sslmode": "verify-ca", "sslrootcert": "system"},
                       {"channel_binding": "sometimes"}, {"nonsense": 1}):
            with self.subTest(**{k: str(v) for k, v in kwargs.items()}), self.assertRaises(InterfaceError):
                resolve(**kwargs)

    def test_require_auth(self):
        self.assertEqual(resolve(require_auth="scram-sha-256").require_auth, (False, frozenset({"scram-sha-256"})))
        self.assertEqual(resolve(require_auth="!password,!md5").require_auth, (True, frozenset({"password", "md5"})))
        for bad in ("!md5,scram-sha-256", "kerberos"):
            with self.subTest(bad=bad), self.assertRaises(InterfaceError):
                resolve(require_auth=bad)

    def test_password_hidden_from_repr(self):
        self.assertNotIn("hunter2", repr(resolve(password="hunter2")))

    def _pgpass(self, content, mode=0o600):
        d = tempfile.mkdtemp(); self.addCleanup(__import__("shutil").rmtree, d)
        path = os.path.join(d, "pgpass")
        with open(path, "w") as f:
            f.write(content)
        os.chmod(path, mode)
        return path

    def test_pgpass_lookup(self):
        path = self._pgpass("# comment\nother:*:*:*:nope\ndb.example.com:5432:*:alice:s3cr\\:et\\\\x\n*:*:*:*:fallback\n")
        self.assertEqual(lookup_pgpass(resolve(host="db.example.com", user="alice", passfile=path)), "s3cr:et\\x")
        self.assertEqual(lookup_pgpass(resolve(host="elsewhere", user="bob", passfile=path)), "fallback")
        self.assertEqual(lookup_pgpass(resolve(host="/var/run/postgresql", user="z", passfile=path)), "fallback")

    @unittest.skipIf(os.name != "posix", "permission check is POSIX-only")
    def test_pgpass_ignored_when_group_readable(self):
        path = self._pgpass("*:*:*:*:pw\n", mode=0o644)
        with self.assertLogs("lazaret.pg", "WARNING"):
            self.assertIsNone(lookup_pgpass(resolve(user="u", passfile=path)))


if __name__ == "__main__":
    unittest.main()
