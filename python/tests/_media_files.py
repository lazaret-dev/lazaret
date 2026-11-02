"""Media files and keystores for FP-OPAQUE-MEDIA's tests.

The media: the files the real encoders wrote (tests/fixtures/media, scripts/make_media_fixtures.py: ffmpeg, Pillow
and fontTools on seeded noise), and the shapes of the false positives of John's tally of Oct 21 (an MP3 with no ID3v2
tag, starting at its first frame, as music/music1.mp3; Pillow's IM Tools test image, Tests/images/bw_gradient.imt; a
debug signing keystore, signing/tiles-foss-debug.pkcs12), and those files changed so that they must stay opaque: a
payload appended, a format's first bytes glued onto random bytes.

The keystores are built here as keytool, OpenSSL and Bouncy Castle lay them out (PKCS#12's DER and bags, JKS and
JCEKS entries, a JCEKS secret key's serialized SealedObject, BKS), each part in its own shape (a certificate a DER
Certificate, an encrypted key an EncryptedPrivateKeyInfo, a key in the clear a PrivateKeyInfo), with random bytes
where their keys, signatures and encrypted data are: nothing in them is a key. All content is inert.
"""
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA = os.path.join(os.path.dirname(os.path.dirname(HERE)), "tests", "fixtures", "media")


def fixture(name):
    with open(os.path.join(MEDIA, name), "rb") as f:
        return f.read()


def fixtures():
    """{name: bytes} of every media fixture."""
    return {n: fixture(n) for n in sorted(os.listdir(MEDIA)) if n not in ("MANIFEST", "README.md")}


def noise(seed, n):
    """Seeded bytes, none of them zero."""
    rnd = random.Random(seed)
    return bytes(rnd.randrange(1, 256) for _ in range(n))


# ---- the tally's shapes ------------------------------------------------------------------------------------------

def raw_mp3(frames=40, seed=1):
    """MPEG-1 Layer III frames from the first byte, no ID3v2 tag (music1.mp3's shape): 128 kbit/s, 44.1 kHz."""
    out = bytearray()
    for k in range(frames):
        pad = int(k % 3 == 0)
        out += bytes([0xFF, 0xFB, 0x90 | (pad << 1), 0x64]) + noise(seed + k, 413 + pad)
    return bytes(out)


def imt_gradient():
    """Pillow's Tests/images/bw_gradient.imt, byte for byte: an IM Tools header, then 10 rows of 0..255."""
    return b"*comment\nwidth 256\nheight 10\npixel n8\n\x0c" + bytes(range(256)) * 10


# ---- keystores ---------------------------------------------------------------------------------------------------

def der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([tag, n])
    elif n < 0x100:
        head = bytes([tag, 0x81, n])
    else:
        head = bytes([tag, 0x82, n >> 8, n & 0xFF])
    return head + body


DATA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
ENCRYPTED = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x06"
#: pbeWithSHAAnd3-KeyTripleDES-CBC, rsaEncryption, sha256WithRSAEncryption, x509Certificate (PKCS#9), commonName
PBE = b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01\x03"
RSA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
SHA256_RSA = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
X509_CERT = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x16\x01"
CN = b"\x55\x04\x03"
SHROUDED, CERT, SECRET = 2, 3, 5


def _bag(kind, body):
    return der(0x30, der(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x0a\x01" + bytes([kind])) + der(0xA0, body))


def _pbe(seed):
    return der(0x30, der(0x06, PBE) + der(0x30, der(0x04, noise(seed, 20)) + der(0x02, b"\x08\x00")))


def certificate(seed=31, key=270):
    """A DER Certificate's shape: tbs {version, serial, algorithm, issuer, validity, subject, public key}, the
    algorithm, a signature (random bytes: it signs nothing)."""
    alg = der(0x30, der(0x06, SHA256_RSA) + der(0x05, b""))
    name = der(0x30, der(0x31, der(0x30, der(0x06, CN) + der(0x0C, b"Lazaret test"))))
    validity = der(0x30, der(0x17, b"261021000000Z") + der(0x17, b"361021000000Z"))
    spki = der(0x30, der(0x30, der(0x06, RSA) + der(0x05, b"")) + der(0x03, b"\x00" + noise(seed, key)))
    tbs = der(0x30, der(0xA0, der(0x02, b"\x02")) + der(0x02, noise(seed + 1, 16)) + alg + name + validity + name + spki)
    return der(0x30, tbs + alg + der(0x03, b"\x00" + noise(seed + 2, 256)))


def encrypted_key(seed=32, n=1232):
    """An EncryptedPrivateKeyInfo: its algorithm, then `n` random bytes where the encrypted key is."""
    return der(0x30, _pbe(seed) + der(0x04, noise(seed + 1, n)))


def plain_key(seed=33, n=1190):
    """A PrivateKeyInfo's shape: version, algorithm, `n` random bytes where the key is."""
    return der(0x30, der(0x02, b"\x00") + der(0x30, der(0x06, RSA) + der(0x05, b"")) + der(0x04, noise(seed, n)))


def pkcs12(key=True, encrypted_certs=True, clear_certs=False, secret=False, seed=7):
    """A PFX as keytool -genkeypair -storetype PKCS12 writes one: the key in a shrouded key bag of an unencrypted
    part, the certificate chain in an encrypted part, then the MAC (an Android debug keystore's shape). key=False,
    encrypted_certs=True: keytool -importcert's truststore; clear_certs: OpenSSL's -certpbe NONE."""
    infos = b""
    bags = b""
    if key:
        bags += _bag(SHROUDED, encrypted_key(seed, 1217))
    if secret:
        bags += _bag(SECRET, der(0x30, der(0x06, RSA) + der(0xA0, der(0x04, noise(seed + 1, 32)))))
    if bags:
        infos += der(0x30, der(0x06, DATA) + der(0xA0, der(0x04, der(0x30, bags))))
    if clear_certs:
        cert_bag = _bag(CERT, der(0x30, der(0x06, X509_CERT) + der(0xA0, der(0x04, certificate(seed + 2)))))
        infos += der(0x30, der(0x06, DATA) + der(0xA0, der(0x04, der(0x30, cert_bag))))
    if encrypted_certs:
        infos += der(0x30, der(0x06, ENCRYPTED) + der(0xA0, encrypted_data(seed + 3, 900)))
    auth = der(0x30, infos)
    ci = der(0x30, der(0x06, DATA) + der(0xA0, der(0x04, auth)))
    mac = der(0x30, noise(seed + 4, 75))
    return der(0x30, der(0x02, b"\x03") + ci + mac)


def encrypted_data(seed=34, n=900):
    """A PKCS#7 EncryptedData: version, then {data, its algorithm, [0] `n` random bytes where the encrypted content
    is}."""
    return der(0x30, der(0x02, b"\x00") + der(0x30, der(0x06, DATA) + _pbe(seed) + der(0x80, noise(seed + 1, n))))


def _utf(s):
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


def _cert(seed):
    c = certificate(seed)
    return _utf("X.509") + len(c).to_bytes(4, "big") + c


def jks(entries, magic=b"\xfe\xed\xfe\xed", seed=11):
    """A JKS (or JCEKS) keystore: entries [(tag, body)], each after its alias and date, then a SHA-1's 20 bytes."""
    out = magic + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for k, (tag, body) in enumerate(entries):
        out += tag.to_bytes(4, "big") + _utf(f"alias{k}") + bytes(8) + body
    return out + noise(seed, 20)


def jks_key_entry(seed=12, n=1230):
    key = encrypted_key(seed, n)
    return len(key).to_bytes(4, "big") + key + (1).to_bytes(4, "big") + _cert(seed + 1)


def jks_cert_entry(seed=13):
    return _cert(seed)


def sealed_object(seed=14):
    """A JCEKS secret key as keytool -genseckey writes it: a SealedObjectForKeyProtector, serialized."""
    o = b"\xac\xed\x00\x05\x73\x72" + _utf("com.sun.crypto.provider.SealedObjectForKeyProtector") + noise(seed, 8)
    o += b"\x02\x00\x00\x78"
    o += b"\x72" + _utf("javax.crypto.SealedObject") + noise(seed + 1, 8) + b"\x02\x00\x04"
    o += b"[" + _utf("encodedParams") + b"\x74" + _utf("[B")
    o += b"[" + _utf("encryptedContent") + b"\x71\x00\x7e\x00\x02"
    o += b"L" + _utf("paramsAlg") + b"\x74" + _utf("Ljava/lang/String;")
    o += b"L" + _utf("sealAlg") + b"\x71\x00\x7e\x00\x03"
    o += b"\x78\x70"
    for n in (20, 32):
        o += b"\x75\x72" + _utf("[B") + noise(seed + 2, 8) + b"\x02\x00\x00\x78\x70" + n.to_bytes(4, "big")
        o += noise(seed + n, n)
    o += b"\x74" + _utf("PBEWithMD5AndTripleDES") + b"\x71\x00\x7e\x00\x08"
    return o


def bks(entries, seed=15):
    """A Bouncy Castle BKS keystore: version 2, a 20-byte salt, an iteration count, entries [(type, body)] (after
    their alias, date and an empty chain), a 0, then the HMAC's 20 bytes."""
    out = (2).to_bytes(4, "big") + (20).to_bytes(4, "big") + noise(seed, 20) + (1024).to_bytes(4, "big")
    for kind, body in entries:
        out += bytes([kind]) + _utf("key") + bytes(8) + bytes(4) + body
    return out + b"\x00" + noise(seed + 1, 20)


def bks_cert(seed=16):
    return _cert(seed)


def bks_key(seed=17):
    """A private key in the clear: its type (0), format, algorithm and PrivateKeyInfo."""
    key = plain_key(seed)
    return b"\x00" + _utf("PKCS#8") + _utf("RSA") + len(key).to_bytes(4, "big") + key


# ---- what must stay opaque ---------------------------------------------------------------------------------------

def appended(data, n=2048, seed=21):
    """`data` with a payload after its end."""
    return data + noise(seed, n)


def glued(data, n=6000, head=64, seed=22):
    """`data`'s first bytes, then random bytes."""
    return data[:head] + noise(seed, n)
