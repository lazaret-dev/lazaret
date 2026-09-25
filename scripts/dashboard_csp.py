#!/usr/bin/env python3
"""Keep the dashboard's Content-Security-Policy in step with its inline script.

python/src/lazaret/web/lazaret.html allows exactly one script: its own inline
<script>, by hash (script-src 'sha256-...'). Injected markup can't run code:
there is no 'unsafe-inline', so neither a planted <script> nor an inline event
handler (onerror=...) executes. The price is that any edit to the script
changes its hash, and the page stops working until the CSP is updated.

    python3 scripts/dashboard_csp.py            # rewrite script-src with the current hash
    python3 scripts/dashboard_csp.py --check    # exit 1 if the CSP is out of date

The hash is taken the way browsers take it: over the UTF-8 text between
<script> and </script>, after the HTML parser's newline normalization (CRLF
and lone CR become LF), so a CRLF checkout computes the same value.
tests/scanner/test_dashboard.py runs the same check.
"""
import base64
import hashlib
import os
import re
import sys

DASHBOARD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "python", "src", "lazaret", "web", "lazaret.html")
SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)
CSP_RE = re.compile(r"""<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content=(["'])(.*?)\1""",
                    re.I | re.S)


def normalize_newlines(text):
    return text.replace("\r\n", "\n").replace("\r", "\n")


def inline_script_hashes(html):
    """CSP source expressions ('sha256-...') for every inline script."""
    html = normalize_newlines(html)
    out = []
    for attrs, body in SCRIPT_RE.findall(html):
        if re.search(r"\bsrc\s*=", attrs, re.I):
            continue
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        out.append("'sha256-" + base64.b64encode(digest).decode("ascii") + "'")
    return out


def csp_of(html):
    m = CSP_RE.search(html)
    return m.group(2) if m else None


def with_hashes(html):
    """html with script-src set to exactly the inline scripts' hashes."""
    hashes = " ".join(inline_script_hashes(html))
    m = CSP_RE.search(html)
    if not m:
        raise SystemExit("error: no Content-Security-Policy meta tag found")
    directives = [d.strip() for d in m.group(2).split(";") if d.strip()]
    directives = [f"script-src {hashes}" if d.split()[0] == "script-src" else d for d in directives]
    if not any(d.split()[0] == "script-src" for d in directives):
        directives.insert(1, f"script-src {hashes}")
    return html[:m.start(2)] + "; ".join(directives) + html[m.end(2):]


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    check = "--check" in args
    paths = [a for a in args if a != "--check"] or [DASHBOARD]
    status = 0
    for path in paths:
        with open(path, encoding="utf-8", newline="") as f:
            html = f.read()
        updated = with_hashes(html)
        if updated == html:
            print(f"{path}: CSP up to date ({' '.join(inline_script_hashes(html))})")
        elif check:
            print(f"{path}: CSP script hash is out of date; run python3 scripts/dashboard_csp.py",
                  file=sys.stderr)
            status = 1
        else:
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(updated)
            print(f"{path}: script-src set to {' '.join(inline_script_hashes(updated))}")
    return status


if __name__ == "__main__":
    sys.exit(main())
