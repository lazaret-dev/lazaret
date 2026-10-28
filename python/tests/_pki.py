"""The tests' TLS certificates, made in Python: a root, and a certificate under it for the hosts a test serves, each
key ECDSA on P-256 (a named curve) and each certificate signed with ECDSA-SHA256. Nothing here is a test.

The tests used to make these with the `openssl` command on PATH, and what it made depended on which one that was:
macOS's /usr/bin/openssl is LibreSSL, whose `req -newkey ec` writes the curve's parameters out in full (explicit
parameters, which Python's ssl refuses under its strict checks, the default since 3.13: "Certificate public key has
explicit ECC parameters") and whose `x509 -req` signs an EC key's certificate with SHA-1 (which pratique, the native
client, reads as no signature algorithm: "unsupported certificate signature algorithm"), where OpenSSL 3 writes the
curve's name and signs with SHA-256 (MAC-TESTS). Made here, the certificates are the same on every machine, and the
tests need no `openssl`: the same extensions OpenSSL 3 gives them (the root's basic constraints and key usage, the
server's names, key usage and purpose, and each certificate's key identifiers), valid from an hour ago (a clock a
little behind) for `days` days.

The arithmetic is P-256's as SEC 1 and FIPS 186 give it, in affine coordinates, with a random nonce from `secrets`: a
throwaway key for a server on 127.0.0.1, made in a few milliseconds, not a signer for anything else. A key with a
password is written as OpenSSL 3 writes one (PKCS #8's EncryptedPrivateKeyInfo: PBES2, PBKDF2 with HMAC-SHA256,
AES-256-CBC), the cipher FIPS 197's, encrypting only."""

import base64
import datetime
import hashlib
import ipaddress
import os
import secrets
import textwrap

# P-256 (secp256r1, prime256v1): SEC 2 section 2.4.2
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
OID_P256 = "1.2.840.10045.3.1.7"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_CN = "2.5.4.3"
OID_SKI, OID_KEY_USAGE, OID_SAN, OID_BASIC, OID_AKI, OID_EKU = (
    "2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.35", "2.5.29.37")
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_CERT_POLICIES, OID_POLICY_MAPPINGS, OID_POLICY_CONSTRAINTS, OID_INHIBIT_ANY_POLICY = (
    "2.5.29.32", "2.5.29.33", "2.5.29.36", "2.5.29.54")
OID_PBES2, OID_PBKDF2, OID_HMAC_SHA256, OID_AES256_CBC = (
    "1.2.840.113549.1.5.13", "1.2.840.113549.1.5.12", "1.2.840.113549.2.9", "2.16.840.1.101.3.4.1.42")


# ---------------------------------------------------------------- the curve
def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def _mul(k, point=G):
    out = None
    while k:
        if k & 1:
            out = _add(out, point)
        point = _add(point, point)
        k >>= 1
    return out


def _on_curve(point):
    x, y = point
    return (y * y - (x * x * x + A * x + B)) % P == 0


class Key:
    """An ECDSA key on P-256."""

    def __init__(self):
        self.d = secrets.randbelow(N - 1) + 1
        self.public = _mul(self.d)
        assert _on_curve(self.public)

    def point(self):
        """The public key as SEC 1 writes it uncompressed: 04, x, y."""
        return b"\x04" + self.public[0].to_bytes(32, "big") + self.public[1].to_bytes(32, "big")

    def sign(self, data):
        """ECDSA-SHA256 over `data`: the DER Ecdsa-Sig-Value."""
        z = int.from_bytes(hashlib.sha256(data).digest(), "big")
        while True:
            k = secrets.randbelow(N - 1) + 1
            r = _mul(k)[0] % N
            if r == 0:
                continue
            s = pow(k, -1, N) * (z + r * self.d) % N
            if s:
                return _seq(_int(r), _int(s))

    def pkcs8(self):
        """The private key as PKCS #8 (RFC 5208) holds it, SEC 1's ECPrivateKey inside, the curve named."""
        inner = _seq(_int(1), _tlv(0x04, self.d.to_bytes(32, "big")), _tlv(0xa1, _bits(self.point())))
        return _seq(_int(0), _seq(_oid(OID_EC_PUBLIC_KEY), _oid(OID_P256)), _tlv(0x04, inner))


# ---------------------------------------------------------------- AES-256-CBC (FIPS 197, SP 800-38A), encrypting
def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1


def _sbox():
    """The S-box: each byte's inverse in GF(2^8), then FIPS 197's affine map (walking the field by 3 and 1/3)."""
    box, p, q = [0x63] * 256, 1, 1
    while True:
        p = p ^ _xtime(p)                                               # p * 3
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xff
        if q & 0x80:
            q ^= 0x09                                                   # q / 3
        x = q
        for shift in range(1, 5):
            x ^= ((q << shift) | (q >> (8 - shift))) & 0xff
        box[p] = x ^ 0x63
        if p == 1:
            return box


SBOX = _sbox()


def _round_keys(key):
    nk = len(key) // 4
    words, rcon = [list(key[4 * i:4 * i + 4]) for i in range(nk)], 1
    for i in range(nk, 4 * (nk + 7)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - nk], t)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(nk + 7)]


def _encrypt_block(keys, block):
    s = [b ^ k for b, k in zip(block, keys[0])]                         # (column by column: s[4 * column + row])
    for n, key in enumerate(keys[1:], 1):
        s = [SBOX[s[4 * ((c + r) % 4) + r]] for c in range(4) for r in range(4)]          # SubBytes, ShiftRows
        if n < len(keys) - 1:                                                               # MixColumns
            mixed = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                mixed += [_xtime(a[r]) ^ _xtime(a[(r + 1) % 4]) ^ a[(r + 1) % 4] ^ a[(r + 2) % 4] ^ a[(r + 3) % 4]
                          for r in range(4)]
            s = mixed
        s = [b ^ k for b, k in zip(s, key)]
    return bytes(s)


def aes_cbc_encrypt(key, iv, data):
    """`data` under AES (a 16, 24 or 32-byte key) in CBC mode, padded as PKCS #7 pads it."""
    keys, pad = _round_keys(key), 16 - len(data) % 16
    data, out, prev = data + bytes([pad]) * pad, bytearray(), iv
    for i in range(0, len(data), 16):
        prev = _encrypt_block(keys, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)


def encrypted_pkcs8(der, password, iterations=2048):
    """A PKCS #8 key (DER) under `password`, as `openssl pkcs8 -topk8 -v2 aes-256-cbc` writes it."""
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, 32)
    kdf = _seq(_oid(OID_PBKDF2), _seq(_tlv(0x04, salt), _int(iterations),
                                       _seq(_oid(OID_HMAC_SHA256), _tlv(0x05, b""))))
    scheme = _seq(_oid(OID_AES256_CBC), _tlv(0x04, iv))
    return _seq(_seq(_oid(OID_PBES2), _seq(kdf, scheme)), _tlv(0x04, aes_cbc_encrypt(key, iv, der)))


# ---------------------------------------------------------------- DER (X.690)
def _tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _int(n):
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")      # (a leading 0 keeps it positive)
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
        raw = raw[1:]
    return _tlv(0x02, raw)


def _oid(text):
    first, second, *rest = (int(p) for p in text.split("."))
    out = bytearray([40 * first + second])
    for value in rest:
        chunk = [value & 0x7f]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7f))
            value >>= 7
        out += bytes(reversed(chunk))
    return _tlv(0x06, bytes(out))


def _bits(data, unused=0):
    return _tlv(0x03, bytes([unused]) + data)


def _time(when):
    if 1950 <= when.year < 2050:
        return _tlv(0x17, when.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return _tlv(0x18, when.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def _name(common_name, tag=0x0c):
    """A name of one common name, a UTF8String (or the string type `tag` names: 0x13 PrintableString)."""
    return _seq(_tlv(0x31, _seq(_oid(OID_CN), _tlv(tag, common_name.encode("utf-8")))))


def _extension(oid, value, critical=False):
    return _seq(_oid(oid), *([_tlv(0x01, b"\xff")] if critical else []), _tlv(0x04, value))


def certificate_policies(*oids):
    """certificatePolicies' value (RFC 5280 4.2.1.4): a PolicyInformation of each policy's OID, no qualifier."""
    return _seq(*(_seq(_oid(o)) for o in oids))


def policy_mappings(*pairs):
    """policyMappings' value (RFC 5280 4.2.1.5): each (issuerDomainPolicy, subjectDomainPolicy) pair of OIDs."""
    return _seq(*(_seq(_oid(issuer), _oid(subject)) for issuer, subject in pairs))


def require_explicit_policy(skip_certs):
    """policyConstraints' value (RFC 5280 4.2.1.11) with requireExplicitPolicy alone."""
    return _seq(_tlv(0x80, _int(skip_certs)[2:]))


def inhibit_any_policy(skip_certs):
    """inhibitAnyPolicy's value (RFC 5280 4.2.1.14)."""
    return _int(skip_certs)


def _pem(label, der):
    body = "\n".join(textwrap.wrap(base64.b64encode(der).decode("ascii"), 64))
    return f"-----BEGIN {label}-----\n{body}\n-----END {label}-----\n"


# ---------------------------------------------------------------- certificates
def _certificate(subject, subject_key, issuer, issuer_key, issuer_id, extensions, days, issuer_tag=0x0c):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    spki = _seq(_seq(_oid(OID_EC_PUBLIC_KEY), _oid(OID_P256)), _bits(subject_key.point()))
    serial = secrets.randbits(127) | 1 << 126
    tbs = _seq(_tlv(0xa0, _int(2)), _int(serial), _seq(_oid(OID_ECDSA_SHA256)), _name(issuer, issuer_tag),
               _seq(_time(now - datetime.timedelta(hours=1)), _time(now + datetime.timedelta(days=days))),
               _name(subject), spki, _tlv(0xa3, _seq(*extensions)))
    return _seq(tbs, _seq(_oid(OID_ECDSA_SHA256)), _bits(issuer_key.sign(tbs)))


def _key_id(key):
    return hashlib.sha1(key.point()).digest()                       # (RFC 5280 4.2.1.2's method 1)


class Pki:
    """A root and a server's certificate under it. `root_pem`: the root's PEM text; `root`, `cert`, `key`: the files
    (in `folder`) of the root, the server's certificate and the server's key (PKCS #8; encrypted under `password` when
    one is given).

    Two choices make the server's certificate one that a private CA may issue and that the CA/Browser Forum's rules
    for a public one refuse (pratique's B-92): `server_auth=False`, no extended key usage at all; `issuer_as`, the
    issuer's name written in the server's certificate as RFC 5280 still matches it with the root's (another case, as a
    PrintableString).

    `intermediate`, a list of extensions (`(oid, value, critical)`), puts a CA between them, "Lazaret test
    intermediate", with its basic constraints, key usage and key identifiers and those extensions; `cert` is then the
    server's certificate and the intermediate's, the chain a server sends. `leaf_extensions` are more of the server's
    certificate's, and `root_extensions` more of the root's (the trust anchor's). (`certificate_policies`,
    `policy_mappings`, `require_explicit_policy` and `inhibit_any_policy` make the values of the policy extensions, which
    pratique processes no policy of: the external report LZ-01.)"""

    def __init__(self, folder, dns=("localhost",), ips=("127.0.0.1",), days=2, root_name="Lazaret test root",
                 server_name="localhost", password=None, server_auth=True, issuer_as=None, intermediate=None,
                 leaf_extensions=(), root_extensions=()):
        root_key, server_key = Key(), Key()
        root_id = _key_id(root_key)
        root = _certificate(root_name, root_key, root_name, root_key, root_id, [
            _extension(OID_BASIC, _seq(_tlv(0x01, b"\xff")), critical=True),
            _extension(OID_KEY_USAGE, _bits(b"\x06", unused=1), critical=True),        # keyCertSign, cRLSign
            _extension(OID_SKI, _tlv(0x04, root_id)),
            _extension(OID_AKI, _seq(_tlv(0x80, root_id))),
            *(_extension(oid, value, critical) for oid, value, critical in root_extensions)], days)
        names = [_tlv(0x82, h.encode("ascii")) for h in dns] + [_tlv(0x87, ipaddress.ip_address(a).packed)
                                                                  for a in ips]
        issuer, issuer_key, issuer_id, chain = root_name, root_key, root_id, b""
        if intermediate is not None:
            inter_key = Key()
            issuer, issuer_key, issuer_id = "Lazaret test intermediate", inter_key, _key_id(inter_key)
            chain = _certificate(issuer, inter_key, root_name, root_key, root_id, [
                _extension(OID_BASIC, _seq(_tlv(0x01, b"\xff")), critical=True),
                _extension(OID_KEY_USAGE, _bits(b"\x06", unused=1), critical=True),    # keyCertSign, cRLSign
                _extension(OID_SKI, _tlv(0x04, issuer_id)),
                _extension(OID_AKI, _seq(_tlv(0x80, root_id))),
                *(_extension(oid, value, critical) for oid, value, critical in intermediate)], days)
        server = _certificate(server_name, server_key, issuer_as or issuer, issuer_key, issuer_id, [
            _extension(OID_SAN, _seq(*names)),
            _extension(OID_BASIC, _seq(), critical=True),
            _extension(OID_KEY_USAGE, _bits(b"\x80", unused=7), critical=True),        # digitalSignature
            *([_extension(OID_EKU, _seq(_oid(OID_SERVER_AUTH)))] if server_auth else []),
            _extension(OID_SKI, _tlv(0x04, _key_id(server_key))),
            _extension(OID_AKI, _seq(_tlv(0x80, issuer_id))),
            *(_extension(oid, value, critical) for oid, value, critical in leaf_extensions)], days,
            issuer_tag=0x13 if issuer_as else 0x0c)
        self.root_pem = _pem("CERTIFICATE", root)
        self.root, self.cert, self.key = (os.path.join(folder, n) for n in ("root.pem", "cert.pem", "key.pem"))
        key = (_pem("PRIVATE KEY", server_key.pkcs8()) if password is None
               else _pem("ENCRYPTED PRIVATE KEY", encrypted_pkcs8(server_key.pkcs8(), password)))
        served = _pem("CERTIFICATE", server) + (_pem("CERTIFICATE", chain) if chain else "")
        for path, text in ((self.root, self.root_pem), (self.cert, served), (self.key, key)):
            with open(path, "w", encoding="ascii", newline="\n") as f:
                f.write(text)
