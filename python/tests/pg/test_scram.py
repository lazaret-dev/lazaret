import base64
import hashlib
import ssl
import unittest

from lazaret.pg._scram import ScramClient, saslprep, signature_algorithm_oid, tls_server_end_point
from lazaret.pg.errors import AuthenticationError

# RFC 7677 section 3 test vector
NONCE = "rOprNGfwEbeRWgbNEkqO"
SERVER_FIRST = b"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096"
CLIENT_FINAL = (b"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                b"p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
SERVER_FINAL = b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="

CA_PEM = """-----BEGIN CERTIFICATE-----
MIIDFTCCAf2gAwIBAgIUfHEils//+cTEHzTARpX6/5WVhFEwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPbGF6YXJldC10ZXN0LWNhMB4XDTI2MDkyNDE5MzQwM1oX
DTI2MTAyNDE5MzQwM1owGjEYMBYGA1UEAwwPbGF6YXJldC10ZXN0LWNhMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtRjCFtc9MVt3FaZ4nHB0P+QJ8Dq1
8zJZrEjfDV/4ziY1gdNYtK0Nr0TzCf1ULWrhNHBC4Fk42cJaPeEZSXrXpkfiPVX3
i6+iamL6Ah4BtJoL4SCKbXWo0ZJpKuIG8t6N4CqfM7VzixJPtEgUb4WxaMC1x/+K
8O1ZXeZor/ylKykI1eaPFZ6y1kJp78TsDKGDG7R+sIBilchL01MJj86pIluQqPV4
8BC8V0QwgKYsoNcROWo5Ko2732UTcSYj/s9r9qFUruSOlLqz/7kJRgC4uPuib59r
zKDrzxvKt6I/Zdk+bRV2RHjLSqn/Ttg+4YtGYG7o/0XY4SVKUQtzKzXrtwIDAQAB
o1MwUTAdBgNVHQ4EFgQUqQ2DcCZ4qqEsOZDLEaBe8RSjlakwHwYDVR0jBBgwFoAU
qQ2DcCZ4qqEsOZDLEaBe8RSjlakwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAqJ/fEEkbC4VgxPb768Ge0P7i00t9c/SXNqP3IHtwyjQ18dReuxFG
Ac9TlSHrEc8QXsDPJkkKk4/kIWPBCqAuB5irV9GQYkyI/8tsUxFXRazvKVB/U3ma
m+ST01TxJjr1n1ZqSYc6EtksSN4tpjb6drDG8ba0KdPFo55po9HXISI/E7pnmqDb
ScwtlbZOx+Pe9ethyeWqVCsiOji6amlwfWYPO+DWMOWRcF4maiWUBMORpZ8c7UDl
j6/NVxX97GlP2QzC0y48nNVTfy4VmjbM85lAL+HoExgBi57MUaMjIK4Okk+gI0Gm
k/JjhadJa00b4ieidxRw5qoQ6hj/JWDpNw==
-----END CERTIFICATE-----"""


def client():
    return ScramClient("pencil", username="user", nonce=NONCE)


class ScramTests(unittest.TestCase):
    def test_rfc7677_vector(self):
        c = client()
        self.assertEqual(c.client_first(), b"n,,n=user,r=" + NONCE.encode())
        self.assertEqual(c.client_final(SERVER_FIRST), CLIENT_FINAL)
        c.verify_server_final(SERVER_FINAL)
        self.assertTrue(c.verified)

    def test_wrong_server_signature_is_rejected(self):
        c = client()
        c.client_final(SERVER_FIRST)
        with self.assertRaisesRegex(AuthenticationError, "signature mismatch"):
            c.verify_server_final(b"v=" + base64.b64encode(b"\x00" * 32))
        self.assertFalse(c.verified)

    def test_server_error_attribute(self):
        c = client()
        c.client_final(SERVER_FIRST)
        with self.assertRaisesRegex(AuthenticationError, "invalid-proof"):
            c.verify_server_final(b"e=invalid-proof")

    def test_nonce_must_extend_client_nonce(self):
        with self.assertRaisesRegex(AuthenticationError, "nonce"):
            client().client_final(b"r=somethingelse,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")
        with self.assertRaisesRegex(AuthenticationError, "nonce"):
            client().client_final(b"r=" + NONCE.encode() + b",s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096")

    def test_iteration_count_is_bounded(self):
        for iterations in (b"0", b"99999999999", b"x"):
            with self.subTest(iterations=iterations), self.assertRaises(AuthenticationError):
                client().client_final(b"r=" + NONCE.encode() + b"xyz,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=" + iterations)

    def test_gs2_headers(self):
        self.assertTrue(ScramClient("pw").client_first().startswith(b"n,,"))
        self.assertTrue(ScramClient("pw", client_supports_cb=True).client_first().startswith(b"y,,"))
        plus = ScramClient("pw", cbind_data=b"\x01" * 32)
        self.assertEqual(plus.mechanism, "SCRAM-SHA-256-PLUS")
        self.assertTrue(plus.client_first().startswith(b"p=tls-server-end-point,,"))

    def test_saslprep(self):
        cases = [
            ("password", "password"),
            ("I\u00adX", "IX"),               # soft hyphen is mapped to nothing
            ("user\u00a0name", "user name"),  # non-ASCII space maps to space
            ("\u2168", "IX"),                 # NFKC: roman numeral nine
            ("\u210c", "H"),                  # NFKC: black-letter H
            ("a\u0007", None),                # control character is prohibited
            ("\u0627\u0031", None),           # RandALCat string must end with RandALCat
        ]
        for raw, prepared in cases:
            with self.subTest(raw=raw):
                self.assertEqual(saslprep(raw), prepared)

    def test_certificate_signature_algorithm_and_endpoint_hash(self):
        der = ssl.PEM_cert_to_DER_cert(CA_PEM)
        self.assertEqual(signature_algorithm_oid(der), "1.2.840.113549.1.1.11")  # sha256WithRSA
        self.assertEqual(tls_server_end_point(der), hashlib.sha256(der).digest())

    def test_garbage_certificate_gives_no_binding(self):
        self.assertIsNone(tls_server_end_point(b"\x30\x03\x02\x01"))


if __name__ == "__main__":
    unittest.main()
