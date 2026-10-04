"""The providers a secret can be verified with (0.1.9, V-1 stage 1): data, read by `secretverify`.

Each entry says how to ask one provider whether a credential is live, with a call that only authenticates: it changes nothing and
costs nothing (the provider's own "who am I" call, or a read of something small). The host is fixed here and nowhere else.

    id        short name; the key of the verdict cache and of the report
    label     what a person calls it
    parts     {part: pattern}: the credential's parts and the whole-text pattern each must match before anything is sent (a
              part that does not match is "not this provider's format", never a request). One secret is `secret`; AWS is a pair,
              `id` and `secret`. The patterns hold printable characters only, so no part can carry a line break into a header.
    host      the one host the credential is sent to (https, port 443, no redirect followed)
    request   method, path, `query` (a mapping: never a secret), `headers` and `body` (text, with `{part}` where a part goes:
              only in headers and in the body, never in the path or the query, so the secret is not in a URL), and `sigv4`
              (service and region) for AWS, which signs the request with the key pair
    answers   rules, tried in order; the first whose conditions hold gives the outcome. Conditions: `status` (a list), `json`
              ({"path.to.key": value or [values]}, all must hold), `code` (the `<Code>` of an XML error). Outcomes: live (the
              provider says the credential works), rejected (the provider says it does not), unknown. `why` is the reason the
              report gives; `who` names where in a live answer the credential's owner is (`json` path or `xml` tag).
              An answer no rule holds for is unknown.

What is *not* here is what the audit of Oct 2 left out on purpose: Google API keys, JWTs and private keys have no general identity
call, so they are not verified, and a report says why. Databases are out of scope.

**These answers are written from each provider's documentation and are not recorded from the services** (the build has no
network access to them); `scripts/verifylive.py` is the check to run, with one's own test keys, before a release.
"""

__all__ = ["PROVIDERS"]

_UA = {"User-Agent": "lazaret-secret-verify"}

PROVIDERS = (
    {
        "id": "github",
        "label": "GitHub token",
        "parts": {"secret": r"(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,255})"},
        "host": "api.github.com",
        "request": {
            "method": "GET", "path": "/user", "query": {},
            "headers": {**_UA, "Authorization": "Bearer {secret}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"},
        },
        "answers": [
            {"status": [200], "outcome": "live", "who": {"json": "login"}},
            {"status": [401], "outcome": "rejected", "why": "GitHub says the token is not valid"},
            {"status": [403, 429], "outcome": "unknown", "why": "GitHub refused or rate limited the call"},
        ],
    },
    {
        "id": "slack",
        "label": "Slack token",
        "parts": {"secret": r"xox[baprs]-[A-Za-z0-9-]{10,250}"},
        "host": "slack.com",
        "request": {
            "method": "GET", "path": "/api/auth.test", "query": {},
            "headers": {**_UA, "Authorization": "Bearer {secret}"},
        },
        "answers": [
            {"status": [200], "json": {"ok": True}, "outcome": "live", "who": {"json": "user"}},
            {"status": [200], "json": {"ok": False, "error": ["invalid_auth", "not_authed", "token_revoked", "token_expired",
                                                             "account_inactive"]},
             "outcome": "rejected", "why": "Slack says the token is not valid"},
            {"status": [429], "outcome": "unknown", "why": "Slack rate limited the call"},
        ],
    },
    {
        "id": "stripe",
        "label": "Stripe live key",
        "parts": {"secret": r"(?:sk|rk)_live_[A-Za-z0-9]{16,247}"},
        "host": "api.stripe.com",
        "request": {
            "method": "GET", "path": "/v1/balance", "query": {},
            "headers": {**_UA, "Authorization": "Bearer {secret}"},
        },
        "answers": [
            {"status": [200], "outcome": "live"},
            {"status": [403], "json": {"error.type": "permission_error"}, "outcome": "live",
             "why": "Stripe knows the key but it may not read the balance"},
            {"status": [401], "outcome": "rejected", "why": "Stripe says the key is not valid"},
            {"status": [429], "outcome": "unknown", "why": "Stripe rate limited the call"},
        ],
    },
    {
        "id": "npm",
        "label": "npm token",
        "parts": {"secret": r"npm_[A-Za-z0-9]{36}"},
        "host": "registry.npmjs.org",
        "request": {
            "method": "GET", "path": "/-/whoami", "query": {},
            "headers": {**_UA, "Authorization": "Bearer {secret}", "Accept": "application/json"},
        },
        "answers": [
            {"status": [200], "outcome": "live", "who": {"json": "username"}},
            {"status": [401], "outcome": "rejected", "why": "npm says the token is not valid"},
            {"status": [403, 429], "outcome": "unknown", "why": "npm refused or rate limited the call"},
        ],
    },
    {
        "id": "openai",
        "label": "OpenAI API key",
        "parts": {"secret": r"sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}"},
        "host": "api.openai.com",
        "request": {
            "method": "GET", "path": "/v1/models", "query": {},
            "headers": {**_UA, "Authorization": "Bearer {secret}"},
        },
        "answers": [
            {"status": [200], "outcome": "live"},
            {"status": [401], "outcome": "rejected", "why": "OpenAI says the key is not valid"},
            {"status": [403, 429], "outcome": "unknown", "why": "OpenAI refused or rate limited the call"},
        ],
    },
    {
        "id": "anthropic",
        "label": "Anthropic API key",
        "parts": {"secret": r"sk-ant-[A-Za-z0-9_-]{20,200}"},
        "host": "api.anthropic.com",
        "request": {
            "method": "GET", "path": "/v1/models", "query": {},
            "headers": {**_UA, "x-api-key": "{secret}", "anthropic-version": "2023-06-01"},
        },
        "answers": [
            {"status": [200], "outcome": "live"},
            {"status": [401], "outcome": "rejected", "why": "Anthropic says the key is not valid"},
            {"status": [403, 429], "outcome": "unknown", "why": "Anthropic refused or rate limited the call"},
        ],
    },
    {
        "id": "aws",
        "label": "AWS access key",
        "parts": {"id": r"AKIA[0-9A-Z]{16}", "secret": r"[A-Za-z0-9/+=]{40}"},
        "host": "sts.amazonaws.com",
        "request": {
            "method": "POST", "path": "/", "query": {},
            "headers": {**_UA, "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "Accept": "application/xml"},
            "body": "Action=GetCallerIdentity&Version=2011-06-15",
            "sigv4": {"service": "sts", "region": "us-east-1"},
        },
        "answers": [
            {"status": [200], "outcome": "live", "who": {"xml": "Arn"}},
            {"status": [403], "code": ["InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken"], "outcome": "rejected",
             "why": "AWS says the key pair is not valid"},
            {"status": [400, 403, 429, 503], "code": ["Throttling", "ThrottlingException", "RequestLimitExceeded",
                                                      "ServiceUnavailable"],
             "outcome": "unknown", "why": "AWS throttled the call"},
        ],
    },
)
