"""Review fix: SASLprep must match PostgreSQL's pg_saslprep() exactly, or a
role whose password contains certain Unicode characters can never log in.

The verifiers below were produced by PostgreSQL 16 (CREATE ROLE ... PASSWORD
'<password>' with password_encryption = scram-sha-256; SELECT rolpassword FROM
pg_authid). For each one, the key the client derives must equal the server's
StoredKey. The passwords are dummy test values."""

import base64
import hashlib
import hmac
import unittest

from lazaret.pg._scram import ScramClient, saslprep

PG16_VERIFIERS = {
    "a\u00adb\u00e9": "4096:/mdlgrtarJPSnjNEHnOTFg==$mvngpSPrhY/e97CRJhZ/pWxvrs26/2B66NlP7kO6ol4=",
    "\u00ad\u00ad": "4096:HivWLoFDENJzmfo9rgtCow==$r0u3lC2AGBr1o9IGVm1KVFsyI/TdniY/aNNOez8gMqA=",
    "\u00e9\tz": "4096:Ub1E/BFVfEcFpjLS35oWmA==$t+T57NvtHHb2e70TjTr+pKYNs48X9DlTs22jOG7YxWs=",
    "\u06271\u0628": "4096:Tf4h2yeJnl7Sd9FC7L/biQ==$LyTelqYeH0fKO7HPi6jdf272vVW06hfYb83+RWWkCt0=",
    "\u0627a": "4096:3ARLLKbVMDkgbOacK1gN7g==$5OyhZ8q4M8vpwnJi07QGD8Y8ujaSJZhunlJeXFKm+9I=",
    "\ufb01x": "4096:pHN1KLMMGNODfXzZZ/jM+g==$1HMHiGlmEWVnCwyOgAxf45Rxa9g7/YecN1FUuJFAWpM=",
    "a\u00a0b\u00e9": "4096:at9w5twGrEHzw2DwHJKT3g==$gfJJu12kLdOeaWEZN8pYG3u/+TmehwDHQOaQsu8G3As=",
    "\u00e9\x7f": "4096:2kOiitgLJ2dSJuruKSg10A==$GtnWtrwrYQRzDFsHK2/ot5mSfEvVucoeC01wphB9kag=",
    "\U0001f100x": "4096:HzeCRvmS2/jezCUsYbrjJQ==$QJBrf91O7RFSZc2Lsl56P5Z7HtUyHH/EBhXE5yjxwbM=",
    "e\u0341x": "4096:BCG0zr+CIbCd8kuK9rj0WQ==$TNWyCDxqLkdW2cqPZdSDp8lFIIB/HEBHzVhmzdyyevQ=",
    "\ufa70x": "4096:SdWF3X2PP/EICfuOsFsL9g==$0ESx9OrTA1A21CCYCD2FqKqqaZQeDaCM6IFQdwh3Tq0=",
    "\u2150x": "4096:lraE57+vlWa2G2e8z290nQ==$1I0hp4VGapaLhM8Vl53+svpO+pQhJ7iF7IjgwbCM7Us=",
    "\U0001f130bc": "4096:ihbG16+nSvCcXGplN6/dvA==$zBYB/ihDEqX/rmBnVkIhQjYgHhEVIF3FNP8NEOy43io=",
    "\u210c\U0001f642": "4096:A395lVCKK7SfkzraRlY9sA==$9iiLylEdzm7xR5y4rNEtISirvKngkiAdHRS0Y7WvJ48=",
    "p\u00e4ssw\u00f6rd \u210c": "4096:Dqp1/RqdYXO44a7W0MpNxQ==$dpHfVPbREXYQZ6QmiG6Fez8Y81q89EvGiYIer/0lml8=",
    # Unicode Corrigendum #4 characters: the server normalizes with current
    # Unicode tables, not the Unicode 3.2 ones.
    "\U0002f868x": "4096:ZiSCD51Eeh2VssA3tQiVTg==$SH5XsLu0Py/x0qRMvdRAGvNkhgg62OBvt3uTA3nPWtg=",
    "\U0002f874x": "4096:Flan1uuWb8F3G7ytdkbxxg==$RfqYKmWlPjRvsHi8VEsq87OqD4WawvtkKsxXsAWLFCc=",
    "\U0002f91fx": "4096:L2mkKAosDWnd3SkeXV7a7w==$ah5mo3Z0geWoWdeCdb6Rcspp5LgpJOAQc0gNHkJaxP4=",
    "\U0002f95fx": "4096:PBYdCLMmxUvpjRWK1BzWiA==$aIzLNye1XeFbwDJpdK/VgEoh7i+neaV6voiwDva50xA=",
    "\U0002f9bfx": "4096:LI1rht0i7l5w4AIC/V4YLg==$o5eE1KwPYWDhes5flH3TfoetYwFuOgF2QKhhQ/Cs6xw=",
}


def stored_key(password_bytes, verifier):
    head, stored = verifier.split("$")
    iterations, salt = head.split(":")
    salted = hashlib.pbkdf2_hmac("sha256", password_bytes, base64.b64decode(salt), int(iterations))
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    return hashlib.sha256(client_key).digest(), base64.b64decode(stored)


class SaslprepMatchesPostgresTests(unittest.TestCase):
    def test_client_derives_the_servers_stored_key(self):
        for password, verifier in PG16_VERIFIERS.items():
            with self.subTest(password=ascii(password)):
                derived, expected = stored_key(ScramClient(password)._password, verifier)
                self.assertEqual(derived, expected)

    def test_unassigned_in_unicode_3_2_falls_back_to_raw_bytes(self):
        # Each has a compatibility decomposition in today's Unicode but was
        # unassigned under Unicode 3.2, which stringprep is defined against
        # (U+0341 is prohibited outright): PostgreSQL uses the raw bytes.
        for password in ("\U0001f100x", "\ufa70x", "\u2150x", "\U0001f130bc", "e\u0341x"):
            with self.subTest(password=ascii(password)):
                self.assertIsNone(saslprep(password))

    def test_normalization(self):
        self.assertEqual(saslprep("\U0002f874x"), "\u5f53x")   # corrected mapping, not 3.2's U+5F33
        self.assertEqual(saslprep("\ufb01x"), "fix")
        self.assertEqual(saslprep("a\u00adb\u00e9"), "ab\u00e9")

    def test_undecodable_environment_password_uses_its_raw_bytes(self):
        # os.environ decodes invalid UTF-8 with surrogateescape; the server
        # hashes such a password's raw bytes.
        raw = b"pw\xff\xfe"
        self.assertEqual(ScramClient(raw.decode("utf-8", "surrogateescape"))._password, raw)


if __name__ == "__main__":
    unittest.main()
