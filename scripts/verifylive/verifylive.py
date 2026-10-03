#!/usr/bin/env python3
"""The manual live check of secret verification (0.1.9, V-1 stage 1). Standard library plus this checkout.

    python3 scripts/verifylive/verifylive.py --list
    python3 scripts/verifylive/verifylive.py --yes [--only github,npm] [--no-made-up] [--timeout S]

CI makes no call to a real service: the answers the provider table reads were written from each provider's documentation, and
the tests run them against a stub. This script is how the table is held to the real services, before a release. For each
provider it asks about

- **a made-up credential** in the provider's format (it exists nowhere): the provider should say it is not valid, so the
  reading of "rejected" is checked without a key of anyone's, and
- **a credential of yours, if you give one**, in the environment: `LAZARET_VERIFY_<ID>` (the secret; for AWS
  `LAZARET_VERIFY_AWS_ID` and `LAZARET_VERIFY_AWS_SECRET`). It is expected to be `live`, or what
  `LAZARET_VERIFY_<ID>_EXPECT` says (`live`, `rejected` or `unknown`): a revoked key of your own is a second way to check
  "rejected" against the real thing.

It sends the credentials it is given, and made-up ones, to the providers' hosts in the table and to nobody else, and needs
`--yes` to say that is meant. It prints each provider, which credential, what was expected, what came back, the HTTP status
and the reason the table gives, and for a live key the account name the provider reports; never a credential. `HTTPS_PROXY`
is honoured. Exit status: 0 every expectation held, 1 one did not, 2 usage (including no `--yes`).

An answer that does not match is a reason to read the provider's documentation again and change the table
(`scanner/secretverify_providers.py`), not the check."""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "python", "src")
EXIT_OK, EXIT_MISMATCH, EXIT_USAGE = 0, 1, 2

#: Made-up credentials in each provider's format: they belong to no account.
MADE_UP = {
    "github": "ghp_" + "0" * 36,
    "slack": "xoxb-0000000000-0000000000",
    "stripe": "sk_live_" + "0" * 24,
    "npm": "npm_" + "0" * 36,
    "openai": "sk-" + "0" * 48,
    "anthropic": "sk-ant-" + "0" * 40,
    "aws": {"id": "AKIA" + "0" * 16, "secret": "0" * 40},
}


def configure_stdio():
    """Redirected output is UTF-8, and never raises on a character the stream cannot encode (STRUCTURE.md, "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def yours(pid, environ):
    """The credential of this provider the environment gives, or None (for AWS, both parts or none)."""
    key = f"LAZARET_VERIFY_{pid.upper()}"
    if pid == "aws":
        parts = {"id": environ.get(key + "_ID", ""), "secret": environ.get(key + "_SECRET", "")}
        return parts if parts["id"] and parts["secret"] else None
    return environ.get(key) or None


def plan(ids, environ, made_up=True):
    """[(provider, which, credential, expected)] for these providers."""
    rows = []
    for pid in ids:
        if made_up:
            rows.append((pid, "made-up", MADE_UP[pid], "rejected"))
        own = yours(pid, environ)
        if own is not None:
            rows.append((pid, "yours", own, environ.get(f"LAZARET_VERIFY_{pid.upper()}_EXPECT") or "live"))
    return rows


def main(argv=None, environ=None, verifier_factory=None, out=None):
    out = out or sys.stdout
    environ = os.environ if environ is None else environ
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
    from lazaret.scanner import secretverify as sv

    parser = argparse.ArgumentParser(prog="verifylive.py", description="Check the secret-verification table against the real providers.")
    parser.add_argument("--list", action="store_true", help="say which providers there are and where a credential would go, and stop")
    parser.add_argument("--yes", action="store_true", help="say that sending the credentials in the environment, and made-up ones, to the providers is meant")
    parser.add_argument("--only", default="", help="comma-separated provider ids (default: all)")
    parser.add_argument("--no-made-up", action="store_true", help="ask only about the credentials in the environment")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds for one call (default 10)")
    try:
        opts = parser.parse_args(argv)
    except SystemExit as exc:
        return EXIT_USAGE if exc.code else EXIT_OK
    if opts.list:
        for pid, label, host in sv.provider_info():
            print(f"{pid:<10} {label:<20} {host}", file=out)
        return EXIT_OK
    known = sv.provider_ids()
    ids = [x for x in (s.strip() for s in opts.only.split(",")) if x] or known
    unknown = [x for x in ids if x not in known]
    if unknown or not opts.timeout > 0:
        print("verifylive: " + (f"no such provider: {', '.join(unknown)}" if unknown else "--timeout must be above 0"), file=sys.stderr)
        return EXIT_USAGE
    if not opts.yes:
        print("verifylive: this sends credentials (the ones in the environment, and made-up ones) to the providers' hosts; "
              "run it with --yes to say that is meant", file=sys.stderr)
        return EXIT_USAGE
    rows = plan(ids, environ, not opts.no_made_up)
    if not rows:
        print("verifylive: nothing to ask: no credential in the environment and --no-made-up", file=sys.stderr)
        return EXIT_USAGE
    verifier = (verifier_factory or (lambda timeout: sv.Verifier(timeout=timeout, per_provider=1, interval=1.0)))(opts.timeout)
    print(f"{'provider':<10} {'credential':<9} {'expected':<9} {'got':<9} {'status':<6} detail", file=out)
    failed = 0
    for pid, which, credential, expected in rows:
        result = verifier.verify(pid, credential)
        held = result.outcome == expected
        failed += 0 if held else 1
        who = f" ({result.who})" if result.who else ""
        print(f"{pid:<10} {which:<9} {expected:<9} {result.outcome:<9} {result.status if result.status is not None else '-':<6} "
              f"{result.detail}{who}{'' if held else '   <-- not what was expected'}", file=out)
    print(f"{len(rows) - failed} of {len(rows)} as expected", file=out)
    return EXIT_MISMATCH if failed else EXIT_OK


if __name__ == "__main__":
    configure_stdio()
    sys.exit(main())
