"""The browser dashboard (lazaret/web/lazaret.html) is fully self-contained:
it loads nothing from the network, and its content-security policy forbids
doing so, so pasting code into it can't leak that code anywhere."""

import os
import re
import unittest

from tests import _support

HTML = os.path.join(_support.PKG, "web", "lazaret.html")
CDN_HOSTS = ["unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
             "fonts.googleapis.com", "fonts.gstatic.com", "maxcdn.bootstrapcdn.com",
             "stackpath.bootstrapcdn.com", "cdn.tailwindcss.com", "esm.sh", "raw.githack.com"]


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HTML, encoding="utf-8") as f:
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


if __name__ == "__main__":
    unittest.main()
