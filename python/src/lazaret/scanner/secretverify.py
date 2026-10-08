"""Is this credential live? (0.1.9, V-1)

A secret found in a file is a finding of one severity. A secret the provider still accepts is the finding someone acts on first,
and one it has revoked is the finding someone can close. This module asks the provider, with a call that only authenticates (the
rule pack's `_VERIFY_PROVIDERS`: GitHub's `GET /user`, Slack's `auth.test`, AWS STS's `GetCallerIdentity`, ...), and answers with
one of three outcomes:

- `live`: the provider says the credential works.
- `rejected`: the provider says it does not (revoked, expired, never valid). It is still a leak: the history keeps it.
- `unknown`: the call was not made or did not settle it (no network, a timeout, a rate limit, a 5xx, an answer this module does not
  recognise, a budget spent, a text that is not this provider's format). **A failed call is never `rejected`**: the caller
  keeps the finding's severity.

**What is promised, and tested** (`tests/scanner/test_secretverify.py`, the fuzz target `verify-answers`):

- The host a credential is sent to is in the provider table and nowhere else: not in the text scanned, not in an answer, not in
  an argument. https only; a redirect is never followed.
- The credential goes in a header (or, for AWS, in a signature), never in a URL, and is sent only if it matches the provider's
  pattern in full: printable characters, no line break, so a crafted string cannot add a header.
- Nothing returned holds the credential: not the detail, not the `who`; a part that appears in either is replaced.
- The verdict cache is per run, keyed by provider, endpoint and the SHA-256 of the credential (a cache keyed by the secret alone
  gave two detectors one answer: TruffleHog's issue 3984). The credential is never written anywhere.
- Bounded: a timeout per call, a budget of time and of calls for the run, at most `per_provider` calls at once to one provider and
  a least interval between them, `HTTPS_PROXY` honoured, an answer read to `MAX_ANSWER_BYTES`.
- Hostile answers (huge, not UTF-8, not JSON, JSON nested to the stack's limit, a `who` of control characters) are `unknown` or
  read as text that is safe to print; nothing raises.

**The table and the logic are the engine's** (stage 2; John's decision 7, Oct 7: one copy for both packages): the providers are
the rule pack's `_VERIFY_PROVIDERS` (rust/crates/lazaret-engine/rules/lazaret-rules.json), and which provider a credential is, the
request that asks it (AWS's signed with Signature Version 4) and what its answer says are the engine's `secrets.identify`,
`secrets.request` and `secrets.judge` (rust/crates/lazaret-engine/src/secrets.rs). This module keeps what is about a run (the
cache, the budgets, the calls in flight) and makes the call (`secretverify_http`); `validate` is the table's rules, which
`scripts/make_rust_tables.py --check` holds the pack to. Nothing calls it yet: `lazaret scan --verify-secrets` is stage 2's
third step. Never in `guard`, the registry auditor or the MCP server.

Imports the engine's calls (`_native`, `engine`) and `secretverify_http` of this package."""

import collections
import concurrent.futures
import datetime
import hashlib
import re
import threading
import time

from . import _native, engine
from . import secretverify_http as http

__all__ = ["LIVE", "REJECTED", "UNKNOWN", "OUTCOMES", "Result", "Verifier", "identify", "provider_ids", "provider_info", "validate",
           "interpret", "build_request", "TABLE"]                # (and PROVIDERS, the pack's table: read when first asked for)

LIVE, REJECTED, UNKNOWN = "live", "rejected", "unknown"
OUTCOMES = (LIVE, REJECTED, UNKNOWN)
MAX_WHO = 80                                    # (the engine's: secrets.rs)
MAX_CREDENTIAL = 512
#: the table's name in the engine's rule pack
TABLE = "_VERIFY_PROVIDERS"
NOT_THIS_FORMAT = "not this provider's format, so nothing was sent"

Result = collections.namedtuple("Result", "provider outcome detail who status")

_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
_PART_RE = re.compile(r"[a-z][a-z0-9_]{0,15}")
_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_PRINTABLE = re.compile(r"[\x21-\x7e]+")
_STATUS = range(100, 600)
_RULE_KEYS = {"status", "json", "code", "outcome", "why", "who"}


# ------------------------------------------------------------------------------------------------ the table

def validate(providers):
    """`providers` as a tuple of checked entries; ValueError that says where, for an entry that breaks the table's rules (the
    module documentation of the engine's secrets.rs, which checks them too when it reads the table). The pack's table is checked
    when it is first read, and by `scripts/make_rust_tables.py --check`."""
    if not isinstance(providers, (list, tuple)):
        raise ValueError("the table is not a list")
    seen = set()
    for entry in providers:
        pid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(pid, str) or not _ID_RE.fullmatch(pid) or pid in seen:
            raise ValueError(f"provider id {pid!r} is not a short name or is repeated")
        seen.add(pid)
        _validate_one(pid, entry)
    return tuple(providers)


def _validate_one(pid, entry):
    def bad(message):
        raise ValueError(f"{pid}: {message}")

    if not isinstance(entry.get("label"), str) or not 0 < len(entry["label"]) <= 60:
        bad("label")
    parts = entry.get("parts")
    if not isinstance(parts, dict) or not parts or "secret" not in parts:
        bad("parts must be a mapping that has a secret")
    for name, pattern in parts.items():
        if not isinstance(name, str) or not _PART_RE.fullmatch(name) or not isinstance(pattern, str):
            bad("a part")
        try:
            re.compile(pattern)
        except re.error:
            bad(f"the pattern of {name} does not compile")
    host = entry.get("host")
    if not isinstance(host, str) or not http.HOST_RE.fullmatch(host) or len(host) > 253:
        bad("host is not a lower-case DNS name")
    request = entry.get("request")
    if not isinstance(request, dict) or request.get("method") not in ("GET", "POST"):
        bad("request.method")
    path = request.get("path")
    if not isinstance(path, str) or not path.startswith("/") or "{" in path or not _PRINTABLE.fullmatch(path):
        bad("request.path must be printable, start with / and hold no part")
    query = request.get("query", {})
    if not isinstance(query, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "{" in k or "{" in v
                                          for k, v in query.items()):
        bad("request.query is a mapping of text that holds no part")
    headers = request.get("headers")
    if headers is not None and not isinstance(headers, dict):
        bad("request.headers holds something that is not text")
    used = set()
    for where, templates in (("headers", list((headers or {}).items())),
                             ("body", [("body", request["body"])] if request.get("body") is not None else [])):
        for name, text in templates:
            if not isinstance(name, str) or not isinstance(text, str):
                bad(f"request.{where} holds something that is not text")
            for ref in _PLACEHOLDER.findall(text):
                if ref not in parts:
                    bad(f"request.{where} names the part {ref!r}, which is not one")
                used.add(ref)
    if request.get("body") is not None and request["method"] != "POST":
        bad("a body is for a POST")
    sig = request.get("sigv4")
    if sig is not None:
        if not isinstance(sig, dict) or set(sig) != {"service", "region"} or not all(isinstance(v, str) and v for v in sig.values()):
            bad("request.sigv4 is a service and a region")
        if set(parts) != {"id", "secret"}:
            bad("a signed request is signed with an id and a secret")
        if "secret" in used:
            bad("a signed request does not send its secret")
    elif "secret" not in used:
        bad("the secret is sent nowhere")
    answers = entry.get("answers")
    if not isinstance(answers, list) or not answers:
        bad("answers")
    for rule in answers:
        if not isinstance(rule, dict) or not set(rule) <= _RULE_KEYS or rule.get("outcome") not in OUTCOMES:
            bad("an answer rule")
        status = rule.get("status")
        if not isinstance(status, list) or not status or any(not isinstance(s, int) or s not in _STATUS for s in status):
            bad("an answer rule needs a status list")
        cond = rule.get("json")
        if cond is not None and (not isinstance(cond, dict) or not cond or any(
                not isinstance(k, str) or not k or not _scalar_or_list(v) for k, v in cond.items())):
            bad("an answer rule's json condition")
        code = rule.get("code")
        if code is not None and (not isinstance(code, list) or not code or any(not isinstance(c, str) or not c for c in code)):
            bad("an answer rule's code condition")
        why = rule.get("why")
        if why is not None and (not isinstance(why, str) or len(why) > 100):
            bad("an answer rule's why")
        if rule.get("who") is not None:
            who = rule["who"]
            if rule["outcome"] != LIVE or not isinstance(who, dict) or len(who) != 1 or not (
                    isinstance(who.get("json"), str) or isinstance(who.get("xml"), str)):
                bad("who belongs to a live rule and is a json path or an xml tag")


def _scalar_or_list(value):
    if isinstance(value, list):
        return bool(value) and all(isinstance(v, (str, bool)) for v in value)
    return isinstance(value, (str, bool))


_table = None
_table_lock = threading.Lock()


def _providers():
    """The pack's table, read from the engine and checked the first time it is asked for."""
    global _table
    if _table is None:
        with _table_lock:
            if _table is None:
                _table = validate(engine.pack_value(TABLE))
    return _table


def __getattr__(name):
    if name == "PROVIDERS":                         # (the pack's table, read when it is first asked for)
        return _providers()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _by_id():
    return {p["id"]: p for p in _providers()}


def provider_ids():
    """The providers a credential can be verified with, in the table's order."""
    return [p["id"] for p in _providers()]


def provider_info():
    """[(id, label, host)] for a report that says what is verified and where a credential would go."""
    return [(p["id"], p["label"], p["host"]) for p in _providers()]


def identify(text):
    """The providers whose one-part pattern matches all of `text` (a credential found in a file): a list, empty when none does.
    The patterns do not overlap (OpenAI's leaves out Anthropic's `sk-ant-`), so a credential names one provider. A provider whose
    credential is a pair (AWS) is not named by one part. (The engine's `secrets.identify`.)"""
    if not isinstance(text, str) or not 0 < len(text) <= MAX_CREDENTIAL:
        return []
    return list(_native.call("secrets.identify", {}, text))


def _own(provider):
    """The id of a table entry that is the pack's own, or None for one of the caller's."""
    pid = provider.get("id") if isinstance(provider, dict) else None
    return pid if isinstance(pid, str) and _by_id().get(pid) == provider else None


# ------------------------------------------------------------------------------------------------ reading an answer

def interpret(provider, response, secrets=()):
    """What a provider's answer says -> (outcome, detail, who): the engine's `secrets.judge`. `provider` is a table entry (the
    pack's, named by its id; or one of the caller's, whose answer rules are given), `response` a `Response`, `secrets` the
    credential's parts (so that none is echoed). The first rule whose conditions hold decides; no rule is unknown. An answer cut
    short by the size limit is read by its status alone: a condition on its body does not hold."""
    pid = _own(provider)
    body = response.body if isinstance(response.body, (bytes, bytearray)) else b""
    args = {"provider": pid} if pid is not None else {"answers": provider.get("answers")}
    args.update(status=int(response.status), truncated=bool(response.truncated) or len(body) > http.MAX_ANSWER_BYTES,
                secrets=[part for part in secrets if isinstance(part, str)])
    outcome, detail, who = _native.call("secrets.judge", args, bytes(body[:http.MAX_ANSWER_BYTES]).decode("latin-1"))
    return outcome, detail, who


# ------------------------------------------------------------------------------------------------ the request

def _amz_date(now):
    if now.tzinfo is not None:
        now = now.astimezone(datetime.timezone.utc)
    return now.strftime("%Y%m%dT%H%M%SZ")


def build_request(provider, parts, now):
    """The `Request` that asks this provider whether the credential (`parts`, {part: text}) is live, at `now` (a `datetime`, UTC if
    it has no zone: AWS's signature holds the time): the engine's `secrets.request`. ValueError when the parts are not the
    provider's format (nothing is to be sent)."""
    pid = _own(provider)
    args = {"provider": pid} if pid is not None else {"entry": provider}
    args.update(parts=dict(parts), time=_amz_date(now))
    answer = _native.call("secrets.request", args)
    if "refused" in answer:
        raise ValueError(answer["refused"])
    body = answer["body"]
    return http.Request(answer["method"], answer["host"], answer["path"], dict(answer["headers"]),
                        None if body is None else body.encode("utf-8"))


class Verifier:
    """Asks providers whether credentials are live, for one run.

    `transport(request, timeout, max_bytes) -> Response` is `secretverify_http.https_transport()` by default; a test gives its own.
    `timeout` bounds one call; `budget` (seconds) and `max_calls` bound the run; `per_provider` is how many calls may be in flight
    to one provider and `interval` the least time between the starts of two calls to it. `clock` and `sleep` are for tests."""

    def __init__(self, transport=None, *, timeout=http.DEFAULT_TIMEOUT, budget=120.0, max_calls=500, per_provider=2, interval=0.0,
                 clock=time.monotonic, sleep=time.sleep, now=None):
        self._transport = transport if transport is not None else http.https_transport()
        self.timeout = timeout
        self.budget = budget
        self.max_calls = max_calls
        self.interval = interval
        self._clock, self._sleep = clock, sleep
        self._now = now or (lambda: datetime.datetime.now(datetime.timezone.utc))
        self._lock = threading.Lock()
        self._started = None
        self._calls = 0
        self._cache = {}
        self._by_id = _by_id()
        self._slots = {pid: threading.BoundedSemaphore(per_provider) for pid in self._by_id}
        self._next = {}
        self.requests = []                                      # (provider, host, path) of each call made, for a report and tests

    # ---- the credential
    @staticmethod
    def _parts(credential):
        """The credential as {part: text}, or None for what cannot be one (the engine checks the rest: the provider's parts, each
        printable, at most MAX_CREDENTIAL characters, all of it the part's format)."""
        if isinstance(credential, str):
            credential = {"secret": credential}
        if not isinstance(credential, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in credential.items()):
            return None
        return dict(credential)

    @staticmethod
    def _key(provider, parts):
        digest = hashlib.sha256("\0".join(f"{name}={parts[name]}" for name in sorted(parts)).encode("utf-8")).hexdigest()
        return (provider["id"], provider["host"] + provider["request"]["path"], digest)

    # ---- the run's limits
    def _admit(self):
        with self._lock:
            now = self._clock()
            if self._started is None:
                self._started = now
            if now - self._started > self.budget:
                return "the time budget for verification is spent"
            if self._calls >= self.max_calls:
                return "the limit on verification calls is reached"
            self._calls += 1
        return None

    def _wait_turn(self, pid):
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            start = max(now, self._next.get(pid, 0.0))
            self._next[pid] = start + self.interval
        if start > now:
            self._sleep(start - now)

    # ---- one credential
    def verify(self, provider_id, credential):
        """One credential, as one secret (text) or, for a pair, a mapping of its parts -> a Result. An unknown provider is a
        KeyError; nothing else raises."""
        provider = self._by_id[provider_id]
        parts = self._parts(credential)
        if parts is None:
            return Result(provider_id, UNKNOWN, NOT_THIS_FORMAT, None, None)
        try:
            request = build_request(provider, parts, self._now())
        except ValueError:
            return Result(provider_id, UNKNOWN, NOT_THIS_FORMAT, None, None)
        except Exception as exc:                                # (the engine could not answer: nothing was sent)
            return Result(provider_id, UNKNOWN, f"the request could not be made ({type(exc).__name__})", None, None)
        key = self._key(provider, parts)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        refused = self._admit()
        if refused:
            return Result(provider_id, UNKNOWN, refused, None, None)
        secrets = sorted(parts.values(), key=len, reverse=True)
        try:
            with self._slots[provider_id]:
                self._wait_turn(provider_id)
                with self._lock:
                    self.requests.append((provider_id, request.host, request.path))
                response = self._transport(request, self.timeout, http.MAX_ANSWER_BYTES)
        except http.TransportError as exc:
            return Result(provider_id, UNKNOWN, _TRANSPORT_WORDS.get(exc.kind, "the call failed"), None, None)
        except Exception as exc:                                # (a transport that is not this module's: what it says may hold anything)
            return Result(provider_id, UNKNOWN, f"the call failed unexpectedly ({type(exc).__name__})", None, None)
        try:
            outcome, detail, who = interpret(provider, response, secrets)
        except Exception as exc:                                # (the engine could not read it: the call settled nothing)
            return Result(provider_id, UNKNOWN, f"the answer could not be read ({type(exc).__name__})", None, None)
        result = Result(provider_id, outcome, detail, who, response.status)
        if outcome != UNKNOWN:
            with self._lock:
                self._cache[key] = result
        return result

    def verify_all(self, items, workers=4):
        """[(provider_id, credential), ...] -> [Result, ...] in the same order. The same credential asked twice is asked once."""
        items = list(items)
        unique = {}
        for pid, credential in items:
            unique.setdefault(self._ident(pid, credential), (pid, credential))
        done = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(unique) or 1))) as pool:
            futures = {ident: pool.submit(self.verify, *pair) for ident, pair in unique.items()}
            for ident, future in futures.items():
                done[ident] = future.result()
        return [done[self._ident(pid, credential)] for pid, credential in items]

    @staticmethod
    def _ident(pid, credential):
        if isinstance(credential, dict):
            credential = tuple(sorted((str(k), repr(v)) for k, v in credential.items()))
        return (pid, credential if isinstance(credential, (str, tuple)) else repr(credential))


_TRANSPORT_WORDS = {
    "timeout": "the provider did not answer in time",
    "connection": "the provider could not be reached",
    "tls": "the provider's certificate could not be checked",
    "proxy": "the proxy could not be used",
    "refused": "the request was not allowed",
}
