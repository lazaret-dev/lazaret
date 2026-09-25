"""The browser dashboard (lazaret/web/lazaret.html) is fully self-contained:
it loads nothing from the network, and its content-security policy forbids
doing so, so pasting code into it can't leak that code anywhere. Its CSP
allows exactly its own inline script, by hash: injected markup can't run
code (no 'unsafe-inline', no inline event handlers)."""

import base64
import hashlib
import os
import re
import unittest

from tests import _support

HTML = os.path.join(_support.PKG, "web", "lazaret.html")
CDN_HOSTS = ["unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
             "fonts.googleapis.com", "fonts.gstatic.com", "maxcdn.bootstrapcdn.com",
             "stackpath.bootstrapcdn.com", "cdn.tailwindcss.com", "esm.sh", "raw.githack.com"]


SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)


def csp_policy(html):
    match = re.search(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=(["\'])(.*?)\1',
                      html, re.I | re.S)
    return match.group(2) if match else None


def script_hash(body):
    """CSP hash of an inline script: sha256 over its UTF-8 text after the HTML
    parser's newline normalization (so a CRLF checkout hashes the same)."""
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HTML, encoding="utf-8", newline="") as f:
            cls.html = f.read()

    def test_no_external_subresources(self):
        external = re.findall(r"""<(?:script|link|img|iframe|source|audio|video)\b[^>]*\b(?:src|href)\s*=\s*["']?(?:https?:)?//""",
                              self.html, re.I)
        self.assertEqual(external, [])

    def test_no_cdn_hosts_or_web_fonts(self):
        self.assertEqual([h for h in CDN_HOSTS if h in self.html], [])
        self.assertNotRegex(self.html, r"@import\s+url\(\s*['\"]?https?:")

    def test_csp_forbids_external_sources(self):
        match = re.search(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=(["\'])(.*?)\1',
                          self.html, re.I)
        self.assertIsNotNone(match, "dashboard has no Content-Security-Policy")
        policy = match.group(2)
        self.assertIn("default-src 'none'", policy)
        self.assertNotRegex(policy, r"https?:|\*")  # no remote origins, no wildcards
        # fetch/XHR/WebSocket: an absent connect-src falls back to default-src 'none'
        connect = re.search(r"connect-src([^;]*)", policy)
        self.assertTrue(connect is None or connect.group(1).strip() == "'none'", policy)

    def test_csp_allows_only_the_page_script_by_hash(self):
        policy = csp_policy(self.html)
        scripts = SCRIPT_RE.findall(self.html)
        self.assertEqual(len(scripts), 1, "the dashboard has exactly one script")
        attrs, body = scripts[0]
        self.assertNotRegex(attrs, r"\bsrc\s*=")
        script_src = re.search(r"script-src([^;]*)", policy).group(1).split()
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertEqual(script_src, [script_hash(body)],
                         "the inline script changed but the CSP hash didn't, so browsers "
                         "would block the page: run python3 scripts/dashboard_csp.py")
        # the same hash from a CRLF checkout (browsers normalize before hashing)
        self.assertEqual(script_hash(body.replace("\n", "\r\n")), script_hash(body))

    def test_no_inline_event_handlers_or_javascript_urls(self):
        # CSP blocks both, so any would be a dead control (and a sign that
        # 'unsafe-inline' is about to come back). Checked in the markup and in
        # the HTML the script builds.
        self.assertEqual(re.findall(r"<[a-zA-Z][^<>]*?\son[a-z]+\s*=", self.html), [])
        self.assertEqual(re.findall(r"\.setAttribute\(\s*[\"']on[a-z]+", self.html), [])
        self.assertNotRegex(self.html, r"(?i)javascript\s*:")


if __name__ == "__main__":
    unittest.main()
