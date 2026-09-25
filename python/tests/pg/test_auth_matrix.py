"""Every authentication method and TLS mode against a real server.

Needs a server configured as below, then:
    LAZARET_TEST_PG_MATRIX="<host> <port> <ca.crt path> <unix socket dir>"

    -- server has ssl = on with a certificate for "localhost" signed by ca.crt
    CREATE ROLE trust_user LOGIN;
    CREATE ROLE pw_user LOGIN PASSWORD 'pw secret';
    SET password_encryption = 'md5';
    CREATE ROLE md5_user LOGIN PASSWORD 'md5 secret';
    SET password_encryption = 'scram-sha-256';
    CREATE ROLE scram_user LOGIN PASSWORD 'scram secret';
    CREATE ROLE unicode_user LOGIN PASSWORD 'pässwörd ℌ';

    # pg_hba.conf
    local all all                  scram-sha-256
    host  all trust_user   <host>/32 trust
    host  all pw_user      <host>/32 password
    host  all md5_user     <host>/32 md5
    host  all scram_user   <host>/32 scram-sha-256
    host  all unicode_user <host>/32 scram-sha-256
"""

import os
import tempfile
import unittest

from lazaret import pg
from tests import _support

HOST, PORT, CA, SOCKDIR = (os.environ.get("LAZARET_TEST_PG_MATRIX") or "x 0 x x").split()


def connect(user, password=None, **kw):
    kw.setdefault("sslmode", "disable")
    return pg.connect(host=kw.pop("host", HOST), port=int(PORT), user=user, password=password,
                      dbname="postgres", connect_timeout=5, **kw)


@_support.requires_env("LAZARET_TEST_PG_MATRIX")
class AuthMatrixTests(unittest.TestCase):
    def check(self, c, method, tls, binding=False):
        try:
            self.assertEqual(c.fetchval("SELECT current_user"), c._params.user)
            self.assertEqual((c.auth_method, c.ssl_in_use, c.channel_binding_used), (method, tls, binding))
            self.assertIs(c.fetchval("SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()"), tls)
        finally:
            c.close()

    def test_trust(self):
        self.check(connect("trust_user"), "none", False)

    def test_cleartext_password_needs_tls_or_opt_in(self):
        with self.assertRaisesRegex(pg.AuthenticationError, "cleartext"):
            connect("pw_user", "pw secret")
        self.check(connect("pw_user", "pw secret", allow_cleartext_password=True), "password", False)
        self.check(connect("pw_user", "pw secret", sslmode="require"), "password", True)

    def test_md5(self):
        self.check(connect("md5_user", "md5 secret"), "md5", False)

    def test_scram_plain_and_with_channel_binding(self):
        self.check(connect("scram_user", "scram secret"), "scram-sha-256", False)
        self.check(connect("scram_user", "scram secret", sslmode="require"), "scram-sha-256", True, binding=True)
        self.check(connect("scram_user", "scram secret", sslmode="require", channel_binding="disable"),
                   "scram-sha-256", True, binding=False)
        self.check(connect("scram_user", "scram secret", sslmode="require", channel_binding="require"),
                   "scram-sha-256", True, binding=True)

    def test_saslprep_password(self):
        self.check(connect("unicode_user", "pässwörd ℌ"), "scram-sha-256", False)
        self.check(connect("unicode_user", "pässwörd H"), "scram-sha-256", False)  # NFKC-equivalent

    def test_wrong_password(self):
        for user, password in (("md5_user", "wrong"), ("scram_user", "wrong"), ("unicode_user", "passwörd ℌ")):
            with self.subTest(user=user):
                with self.assertRaises(pg.InvalidAuthorization) as info:
                    connect(user, password)
                self.assertEqual(info.exception.sqlstate, "28P01")

    def test_missing_password(self):
        with self.assertRaisesRegex(pg.AuthenticationError, "none was provided"):
            connect("scram_user", passfile="/nonexistent")

    def test_require_auth(self):
        self.check(connect("scram_user", "scram secret", require_auth="scram-sha-256"), "scram-sha-256", False)
        for kwargs in ({"user": "md5_user", "password": "md5 secret", "require_auth": "scram-sha-256"},
                       {"user": "trust_user", "require_auth": "!none"},
                       {"user": "pw_user", "password": "pw secret", "sslmode": "require", "require_auth": "!password"}):
            with self.subTest(**kwargs), self.assertRaisesRegex(pg.AuthenticationError, "require_auth"):
                connect(**kwargs)

    def test_channel_binding_require_refuses_non_scram_and_plaintext(self):
        with self.assertRaisesRegex(pg.AuthenticationError, "channel_binding=require"):
            connect("md5_user", "md5 secret", sslmode="require", channel_binding="require")
        with self.assertRaisesRegex(pg.AuthenticationError, "channel_binding=require"):
            connect("scram_user", "scram secret", channel_binding="require")

    def test_certificate_verification(self):
        self.check(connect("scram_user", "scram secret", sslmode="verify-full", sslrootcert=CA, host="localhost"),
                   "scram-sha-256", True, binding=True)
        self.check(connect("scram_user", "scram secret", sslmode="verify-ca", sslrootcert=CA),
                   "scram-sha-256", True, binding=True)
        with self.assertRaisesRegex(pg.OperationalError, "verification failed"):
            connect("scram_user", "scram secret", sslmode="verify-full", sslrootcert="system", host="localhost")
        with self.assertRaisesRegex(pg.OperationalError, "root certificate"):
            connect("scram_user", "scram secret", sslmode="verify-ca", sslrootcert="/nonexistent/root.crt")

    def test_unix_socket(self):
        self.check(connect("scram_user", "scram secret", host=SOCKDIR), "scram-sha-256", False)

    def test_pgpass(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "pgpass")
            with open(path, "w") as f:
                f.write(f"{HOST}:{PORT}:*:scram_user:scram secret\n")
            os.chmod(path, 0o600)
            self.check(connect("scram_user", passfile=path), "scram-sha-256", False)
            os.chmod(path, 0o644)  # libpq ignores a group/world-readable file, and so do we
            with self.assertLogs("lazaret.pg", "WARNING"), \
                    self.assertRaisesRegex(pg.AuthenticationError, "none was provided"):
                connect("scram_user", passfile=path)


if __name__ == "__main__":
    unittest.main()
