"""SCRAM-SHA-256 client (RFC 5802 / RFC 7677) with optional tls-server-end-point
channel binding (RFC 5929), as used by PostgreSQL. Standard library only."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import stringprep
import unicodedata

from .errors import AuthenticationError

# A hostile server could send a huge iteration count to burn client CPU.
MAX_ITERATIONS = 1_000_000


_PROHIBITED = (
    stringprep.in_table_c12, stringprep.in_table_c21, stringprep.in_table_c22,
    stringprep.in_table_c3, stringprep.in_table_c4, stringprep.in_table_c5,
    stringprep.in_table_c6, stringprep.in_table_c7, stringprep.in_table_c8,
    stringprep.in_table_c9, stringprep.in_table_a1,
)


def _has_prohibited(s: str) -> bool:
    return any(check(c) for c in s for check in _PROHIBITED)


def saslprep(s: str) -> str | None:
    """RFC 4013 SASLprep, matching PostgreSQL's pg_saslprep(). Returns None if
    the string is not a valid SASLprep string, in which case PostgreSQL uses
    the raw password bytes instead (and so does ScramClient).

    Like PostgreSQL, unassigned (in Unicode 3.2, which stringprep is defined
    against) and prohibited code points are checked on the mapped input BEFORE
    normalizing as well as after. Otherwise a character that was unassigned in
    3.2 but has a compatibility mapping today (e.g. U+1F100 DIGIT ZERO FULL
    STOP) normalizes into an allowed string, while the server rejects it and
    hashes the raw bytes, so the login fails. The NFKC step itself uses the
    current Unicode tables, as PostgreSQL does: the five CJK compatibility
    ideographs fixed by Unicode Corrigendum #4 (e.g. U+2F874) normalize to the
    corrected characters on the server, not to their Unicode 3.2 mappings."""
    if s.isascii() and all(0x20 <= ord(c) < 0x7F for c in s):
        return s
    mapped = "".join(
        " " if stringprep.in_table_c12(c) else "" if stringprep.in_table_b1(c) else c for c in s
    )
    if not mapped or _has_prohibited(mapped):
        return None
    norm = unicodedata.normalize("NFKC", mapped)
    if not norm or _has_prohibited(norm):
        return None
    if any(stringprep.in_table_d1(c) for c in norm):
        if any(stringprep.in_table_d2(c) for c in norm):
            return None
        if not (stringprep.in_table_d1(norm[0]) and stringprep.in_table_d1(norm[-1])):
            return None
    return norm


# --- tls-server-end-point: hash of the server certificate --------------------

# Signature algorithm OID -> hash to use (RFC 5929 section 4.1: MD5/SHA-1 map to SHA-256).
_SIG_HASH = {
    "1.2.840.113549.1.1.4": "sha256",   # md5WithRSAEncryption
    "1.2.840.113549.1.1.5": "sha256",   # sha1WithRSAEncryption
    "1.2.840.113549.1.1.14": "sha224",
    "1.2.840.113549.1.1.11": "sha256",
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.10045.4.1": "sha256",      # ecdsa-with-SHA1
    "1.2.840.10045.4.3.1": "sha224",
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
    "2.16.840.1.101.3.4.3.2": "sha256", # dsa-with-sha256
}


def _read_tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ValueError("truncated DER")
    return tag, pos, pos + length


def _decode_oid(b: bytes) -> str:
    values, cur = [], 0
    for byte in b:
        cur = (cur << 7) | (byte & 0x7F)
        if not byte & 0x80:
            values.append(cur)
            cur = 0
    first = values[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(v) for v in head + values[1:])


def signature_algorithm_oid(der: bytes) -> str:
    _, start, _ = _read_tlv(der, 0)          # Certificate
    _, _, tbs_end = _read_tlv(der, start)    # tbsCertificate
    _, alg_start, _ = _read_tlv(der, tbs_end)  # signatureAlgorithm
    tag, oid_start, oid_end = _read_tlv(der, alg_start)
    if tag != 0x06:
        raise ValueError("expected OID")
    return _decode_oid(der[oid_start:oid_end])


def tls_server_end_point(der_cert: bytes) -> bytes | None:
    """Channel-binding data for the certificate, or None if its signature
    algorithm has no defined hash (e.g. Ed25519, RSA-PSS)."""
    try:
        name = _SIG_HASH.get(signature_algorithm_oid(der_cert))
    except (ValueError, IndexError):
        return None
    return hashlib.new(name, der_cert).digest() if name else None


# --- SCRAM exchange -----------------------------------------------------------

def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _parse_attrs(msg: str) -> dict[str, str]:
    out = {}
    for part in msg.split(","):
        key, sep, value = part.partition("=")
        if not sep or len(key) != 1:
            raise AuthenticationError("malformed SCRAM message from server")
        out[key] = value
    return out


class ScramClient:
    """One SCRAM-SHA-256 exchange.

    cbind_data: tls-server-end-point bytes to bind to (selects SCRAM-SHA-256-PLUS).
    client_supports_cb: True when on TLS but the server did not offer -PLUS
    (sends the "y" flag so a downgrade by a man-in-the-middle is detected).
    """

    def __init__(self, password: str, *, cbind_data: bytes | None = None,
                 client_supports_cb: bool = False, username: str = "", nonce: str | None = None):
        prepared = saslprep(password)
        # surrogateescape restores the original bytes of a password that came
        # from a non-UTF-8 environment variable (the server uses raw bytes then).
        self._password = (prepared if prepared is not None else password).encode("utf-8", "surrogateescape")
        self._cbind_data = cbind_data
        if cbind_data is not None:
            self.mechanism = "SCRAM-SHA-256-PLUS"
            self._gs2 = "p=tls-server-end-point,,"
        else:
            self.mechanism = "SCRAM-SHA-256"
            self._gs2 = "y,," if client_supports_cb else "n,,"
        self._nonce = nonce or base64.b64encode(secrets.token_bytes(18)).decode("ascii")
        escaped = username.replace("=", "=3D").replace(",", "=2C")
        self._client_first_bare = f"n={escaped},r={self._nonce}"
        self._server_signature: bytes | None = None
        self.verified = False

    @property
    def uses_channel_binding(self) -> bool:
        return self._cbind_data is not None

    def client_first(self) -> bytes:
        return (self._gs2 + self._client_first_bare).encode("utf-8")

    def client_final(self, server_first: bytes) -> bytes:
        server_first_str = server_first.decode("utf-8")
        attrs = _parse_attrs(server_first_str)
        if "m" in attrs:
            raise AuthenticationError("server requires an unsupported SCRAM extension")
        try:
            nonce, salt_b64, iterations = attrs["r"], attrs["s"], int(attrs["i"])
        except (KeyError, ValueError):
            raise AuthenticationError("malformed SCRAM server-first message") from None
        if not nonce.startswith(self._nonce) or len(nonce) <= len(self._nonce):
            raise AuthenticationError("SCRAM server nonce does not extend the client nonce")
        if not 1 <= iterations <= MAX_ITERATIONS:
            raise AuthenticationError(f"SCRAM iteration count out of range: {iterations}")
        try:
            salt = base64.b64decode(salt_b64, validate=True)
        except ValueError:
            raise AuthenticationError("malformed SCRAM salt") from None

        salted = hashlib.pbkdf2_hmac("sha256", self._password, salt, iterations)
        client_key = _hmac(salted, b"Client Key")
        stored_key = hashlib.sha256(client_key).digest()
        cbind = base64.b64encode(self._gs2.encode("ascii") + (self._cbind_data or b"")).decode("ascii")
        final_without_proof = f"c={cbind},r={nonce}"
        auth_message = f"{self._client_first_bare},{server_first_str},{final_without_proof}".encode("utf-8")
        signature = _hmac(stored_key, auth_message)
        proof = bytes(a ^ b for a, b in zip(client_key, signature))
        self._server_signature = _hmac(_hmac(salted, b"Server Key"), auth_message)
        return f"{final_without_proof},p={base64.b64encode(proof).decode('ascii')}".encode("ascii")

    def verify_server_final(self, server_final: bytes) -> None:
        attrs = _parse_attrs(server_final.decode("utf-8"))
        if "e" in attrs:
            raise AuthenticationError(f"server rejected SCRAM authentication: {attrs['e']}")
        if self._server_signature is None or "v" not in attrs:
            raise AuthenticationError("unexpected SCRAM server-final message")
        try:
            received = base64.b64decode(attrs["v"], validate=True)
        except ValueError:
            raise AuthenticationError("malformed SCRAM server signature") from None
        if not hmac.compare_digest(received, self._server_signature):
            raise AuthenticationError("SCRAM server signature mismatch: server did not prove it knows the password")
        self.verified = True
