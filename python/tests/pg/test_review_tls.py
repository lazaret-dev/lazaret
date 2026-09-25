"""Review fixes in TLS policy: sslmode=require becomes verify-ca when libpq's
default root certificate exists (repro r11); a password (cleartext or MD5)
is not handed to a server whose certificate was not verified (repro r3)."""

import os
import shutil
import ssl
import tempfile
import unittest
from unittest import mock

from lazaret import pg
from lazaret.pg._dsn import default_root_cert, resolve
from lazaret.pg.connection import Connection
from tests import _support
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
        with open(path, "w") as f:
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
