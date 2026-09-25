"""Review fixes in connection-string parsing (lazaret.pg._dsn).

URLs are parsed by hand like libpq rather than with urllib.parse, and error
messages never repeat parsed values, since a malformed string can put part of
the password where another value was expected."""

import os
import unittest
from unittest import mock

from lazaret.pg._dsn import parse_dsn, resolve
from lazaret.pg.errors import InterfaceError


class UrlParsingTests(unittest.TestCase):
    def test_unencoded_hash_and_question_mark_in_password(self):
        for password in ("s3cr#et", "s3cr?et", "84#xyz", "a#b?c#", "?#"):
            with self.subTest(password=password):
                d = parse_dsn(f"postgresql://app:{password}@db.example.invalid:6543/lz")
                self.assertEqual(d, {"user": "app", "password": password, "host": "db.example.invalid",
                                     "port": "6543", "dbname": "lz"})

    def test_credentials_end_at_the_last_at_sign_before_the_path(self):
        d = parse_dsn("postgresql://app:p@ss@db.example.invalid/lz?application_name=me@home")
        self.assertEqual((d["user"], d["password"], d["host"], d["dbname"], d["application_name"]),
                         ("app", "p@ss", "db.example.invalid", "lz", "me@home"))
        self.assertEqual(parse_dsn("postgresql://db.example.invalid/l@z"),
                         {"host": "db.example.invalid", "dbname": "l@z"})

    def test_plus_is_not_a_space(self):
        d = parse_dsn("postgresql://a+b:c+d@db.example.invalid/lz"
                      "?password=a+b&application_name=my+app&options=-c%20search_path%3Dx+y")
        self.assertEqual((d["user"], d["password"], d["application_name"], d["options"]),
                         ("a+b", "a+b", "my+app", "-c search_path=x+y"))

    def test_percent_decoding(self):
        d = parse_dsn("postgresql://%61pp:%23%3F%2F%40%25@%2Fvar%2Frun/lz%20db?sslmode=verify%2Dfull")
        self.assertEqual(d, {"user": "app", "password": "#?/@%", "host": "/var/run",
                             "dbname": "lz db", "sslmode": "verify-full"})
        raw = parse_dsn("postgresql://app:%FF%FE@db.example.invalid/lz")["password"]
        self.assertEqual(raw.encode("utf-8", "surrogateescape"), b"\xff\xfe")  # sent unchanged
        for bad in ("postgresql://app:pw%zzsecret@h/db", "postgresql://app:pw%4@h/db",
                    "postgresql://app:pw%00secret@h/db"):
            with self.subTest(bad=bad), self.assertRaises(InterfaceError) as info:
                parse_dsn(bad)
            self.assertNotIn("secret", str(info.exception))
            self.assertNotIn("pw", str(info.exception))

    def test_libpq_details(self):
        self.assertNotIn("password", parse_dsn("postgresql://app:@db.example.invalid/lz"))  # empty: not set
        self.assertEqual(parse_dsn("postgresql://db.example.invalid?ssl=true")["sslmode"], "require")
        self.assertEqual(parse_dsn("postgres://[2001:db8::1]:5433"), {"host": "2001:db8::1", "port": "5433"})
        self.assertEqual(parse_dsn("postgresql://"), {})
        self.assertEqual(parse_dsn("postgresql://h?&application_name=x&"), {"host": "h", "application_name": "x"})
        for bad in ("postgresql://[::1", "postgresql://[::1]x/db", "postgresql://h/db?sslmode",
                    "postgresql://h1,h2/db"):
            with self.subTest(bad=bad), self.assertRaises(InterfaceError):
                parse_dsn(bad)


class ErrorMessagesDontLeakPasswordsTests(unittest.TestCase):
    def setUp(self):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_refused_without(self, dsn, *secrets):
        with self.assertRaises(InterfaceError) as info:
            resolve(dsn)
        for secret in secrets:
            self.assertNotIn(secret, str(info.exception))

    def test_unencoded_slash_in_password(self):
        # libpq also needs %2F here; the port error must not show "Tr0ub".
        self.assert_refused_without("postgresql://app:Tr0ub/4dor@db.example.invalid/lz", "Tr0ub", "4dor")

    def test_unquoted_space_in_keyvalue_password(self):
        self.assert_refused_without("host=db.example.invalid user=app password=correct horse battery",
                                    "correct", "horse", "battery")

    def test_password_fragment_that_looks_like_a_key(self):
        self.assert_refused_without("host=db.example.invalid password=correct horse=battery", "horse", "battery")
        self.assert_refused_without("postgresql://db.example.invalid/lz?password=a&horse=battery", "horse")

    def test_unknown_keys_are_named_when_no_password_is_present(self):
        with self.assertRaisesRegex(InterfaceError, "sslmdoe"):
            parse_dsn("host=db.example.invalid sslmdoe=require")

    def test_bad_numbers(self):
        self.assert_refused_without("postgresql://app:pw@db.example.invalid:99999/lz", "99999")
        self.assert_refused_without("host=h port=secret", "secret")
        self.assert_refused_without("host=h connect_timeout=secret", "secret")


if __name__ == "__main__":
    unittest.main()
