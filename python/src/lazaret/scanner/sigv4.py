"""AWS Signature Version 4 for one request (0.1.9, V-1 stage 1).

Live secret verification asks AWS STS who an access key belongs to (`GetCallerIdentity`), and AWS wants that request signed.
This is the signing process of the AWS documentation ("Signature Version 4 signing process") with HMAC-SHA256 and nothing
else: the standard library. It signs one request in the one way it needs: the headers and the body it is given, a path that is
already encoded, a query that is a mapping.

The test vectors are AWS's own: the signing-key derivation example of the documentation and the `get-vanilla` case of its
signature test suite (`tests/scanner/test_sigv4.py`).

Standard library only; imports nothing else from Lazaret."""

import datetime
import hashlib
import hmac
import urllib.parse

__all__ = ["ALGORITHM", "signing_key", "sign"]

ALGORITHM = "AWS4-HMAC-SHA256"
_UNRESERVED = "-_.~"


def _hmac(key, text):
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret_key, date, region, service):
    """The key the request is signed with: HMAC over the date (`YYYYMMDD`), the region, the service and `aws4_request`,
    starting from `AWS4` and the secret access key."""
    key = _hmac(("AWS4" + secret_key).encode("utf-8"), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    return key


def _quote(text):
    return urllib.parse.quote(text, safe=_UNRESERVED)


def sign(method, host, path, query, body, headers, access_key, secret_key, region, service, now):
    """The headers to send with this request -> a new dict: `headers` as given, `host` is left to the transport (it is signed, and
    must be the host the request goes to), and `x-amz-date` and `authorization` are added.

    `path` is the request path as it is sent (already percent-encoded); `query` is a mapping of names to values (encoded here,
    sorted by name); `body` is bytes or None; `now` is a `datetime` in UTC. Every header given is signed, with `host` and
    `x-amz-date`."""
    if now.tzinfo is not None:
        now = now.astimezone(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = amz_date[:8]
    signed = {name.lower(): " ".join(str(value).split()) for name, value in headers.items()}
    signed["host"] = host
    signed["x-amz-date"] = amz_date
    names = sorted(signed)
    canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in names)
    signed_headers = ";".join(names)
    canonical_query = "&".join(f"{_quote(k)}={_quote(v)}" for k, v in sorted(query.items()))
    payload = hashlib.sha256(body or b"").hexdigest()
    canonical = "\n".join((method, path, canonical_query, canonical_headers, signed_headers, payload))
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join((ALGORITHM, amz_date, scope, hashlib.sha256(canonical.encode("utf-8")).hexdigest()))
    signature = hmac.new(signing_key(secret_key, date, region, service), to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = dict(headers)
    out["x-amz-date"] = amz_date
    out["authorization"] = f"{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    return out
