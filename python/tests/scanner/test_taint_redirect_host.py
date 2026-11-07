"""Q-5 (0.1.9): a check of the parsed URL's host against a collection guards an open redirect.

BenchmarkPython's safe redirect cases (scanned and scored, their sources never read: the project's licence rule) parse
the URL and check its host against a list before redirecting to it, which the intra-file taint pass's allowlist guard
(`if url in ALLOWED:`) did not read, so it reported them (T-REDIR). Now the pass reads the host of a parsed URL —
`urlparse(u).netloc` (or `.hostname`, `urlsplit`, `urllib.parse.urlparse`), `p.netloc` for `p = urlparse(u)`, `h` for
`h = urlparse(u).netloc` — checked against a collection (a name, a call of one, or a list, set or tuple display) as a
guard of the redirect: `in` for the `if`'s block when the whole test needs it (an `and` of it, no `or`); `not in`
for what follows a block that leaves (`return`, `raise`, `abort(…)`) when the test holds whenever it does (an `or`
of it, alone). It clears the URL for the redirect alone: the rest of the URL is still the request's.

Not a guard: a substring test of the raw string (`'example.com' in u`, `u.startswith(…)`, `….endswith(…)`) or of
the host (`… in 'example.com'`): a URL the attacker writes passes them. Nor the `else` of an `in` check, the block of
a `not in` check, a `not in` check that does not leave, or the host of a URL parsed before the URL was assigned again.

The pass is the engine's, so the npm package answers the same (js/test/taint-redirect-host.test.js, and the parity
tree of tests/architecture/test_js_parity_taint.py). All content is inert: hosts are .invalid, nothing is run.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

FLASK = ("from flask import Flask, request, redirect, abort\nfrom urllib.parse import urlparse, urlsplit\n"
         "import urllib.parse, os\napp = Flask(__name__)\nALLOWED = {'example.invalid', 'www.example.invalid'}\n")
VIEW = FLASK + "@app.route('/go')\ndef go():\n    url = request.args.get('next', '')\n"   # the body starts on line 9

# (lang, source, {(rule, line)}): the T-* findings
REPORTED = [
    # no check
    ("py", VIEW + "    return redirect(url)\n", {("T-REDIR", 9)}),
    # substring tests of the raw string or of the host
    ("py", VIEW + "    if 'example.invalid' in url:\n        return redirect(url)\n", {("T-REDIR", 10)}),
    ("py", VIEW + "    if url.startswith('https://example.invalid'):\n        return redirect(url)\n", {("T-REDIR", 10)}),
    ("py", VIEW + "    if urlparse(url).netloc.endswith('.example.invalid'):\n        return redirect(url)\n",
     {("T-REDIR", 10)}),
    ("py", VIEW + "    if urlparse(url).netloc in 'www.example.invalid':\n        return redirect(url)\n",
     {("T-REDIR", 10)}),
    # the branch the check does not guard
    ("py", VIEW + "    if urlparse(url).netloc in ALLOWED:\n        pass\n    else:\n        return redirect(url)\n",
     {("T-REDIR", 12)}),
    ("py", VIEW + "    if urlparse(url).netloc in ALLOWED:\n        print('ok')\n    return redirect(url)\n",
     {("T-REDIR", 11)}),
    ("py", VIEW + "    if urlparse(url).netloc not in ALLOWED:\n        return redirect(url)\n    return 'ok'\n",
     {("T-REDIR", 10)}),
    ("py", VIEW + "    if urlparse(url).netloc not in ALLOWED: return redirect(url)\n    return 'ok'\n",
     {("T-REDIR", 9)}),
    # a not-in check that does not leave
    ("py", VIEW + "    if urlparse(url).netloc not in ALLOWED:\n        print('other host')\n    return redirect(url)\n",
     {("T-REDIR", 11)}),
    # tests that do not need the host in the collection
    ("py", VIEW + "    if urlparse(url).netloc in ALLOWED or url.startswith('/'):\n        return redirect(url)\n",
     {("T-REDIR", 10)}),
    ("py", VIEW + "    if urlparse(url).netloc not in ALLOWED and url:\n        abort(400)\n    return redirect(url)\n",
     {("T-REDIR", 11)}),
    ("py", VIEW + "    if not urlparse(url).netloc in ALLOWED:\n        print('x')\n    return redirect(url)\n",
     {("T-REDIR", 11)}),
    # the URL assigned again after it was parsed; a collection the request gives
    ("py", VIEW + "    parsed = urlparse(url)\n    url = request.args['other']\n    if parsed.netloc in ALLOWED:\n"
                  "        return redirect(url)\n", {("T-REDIR", 12)}),
    ("py", VIEW + "    if urlparse(url).netloc in request.args.getlist('hosts'):\n        return redirect(url)\n",
     {("T-REDIR", 10)}),
    # the check guards the redirect alone
    ("py", VIEW + "    if urlparse(url).netloc in ALLOWED:\n        os.system('curl ' + url)\n"
                  "        return redirect(url)\n", {("T-CMD", 10)}),
    # a parsed result held in another function is not this one's
    ("py", FLASK + "def check(url):\n    parsed = urlparse(url)\n    return parsed\n@app.route('/go')\ndef go():\n"
                   "    url = request.args.get('next', '')\n    if parsed.netloc in ALLOWED:\n        return redirect(url)\n",
     {("T-REDIR", 13)}),
]

# no T-* finding
QUIET = [
    # in place: in, not in and leave
    ("py", VIEW + "    if urlparse(url).netloc in ALLOWED:\n        return redirect(url)\n    return 'no'\n"),
    ("py", VIEW + "    if urllib.parse.urlparse(url).hostname not in ['example.invalid']:\n        abort(400)\n"
                  "    return redirect(url)\n"),
    ("py", VIEW + "    if urlsplit(url).netloc not in ('example.invalid', ''): raise ValueError(url)\n"
                  "    return redirect(url)\n"),
    # through the parsed result, with a test of its scheme beside it, in a try block
    ("py", VIEW + "    try:\n        parsed = urlparse(url)\n"
                  "        if parsed.netloc not in ['example.invalid', ''] or parsed.scheme not in ('http', 'https', ''):\n"
                  "            print('refused')\n            return 'refused', 400\n    except ValueError:\n"
                  "        return 'bad', 400\n    return redirect(url)\n"),
    ("py", VIEW + "    parsed = urlparse(url)\n    if parsed.scheme == 'https' and parsed.netloc in ALLOWED:\n"
                  "        return redirect(url)\n"),
    # through a name holding the host
    ("py", VIEW + "    host = urlsplit(url).hostname\n    if host not in ALLOWED: return 'refused', 400\n"
                  "    return redirect(url)\n"),
    ("py", VIEW + "    parsed = urlparse(url)\n    host = parsed.netloc.lower()\n    if (host in ALLOWED):\n"
                  "        return redirect(url)\n"),
    # elif and else
    ("py", VIEW + "    if not url:\n        return 'none'\n    elif urlparse(url).netloc in ALLOWED:\n"
                  "        return redirect(url)\n"),
    ("py", VIEW + "    if urlparse(url).netloc not in ALLOWED:\n        abort(400)\n    else:\n"
                  "        return redirect(url)\n"),
]


def t_findings(lang, src):
    return {(i["rule"], i["line"]) for i in core.taint_scan(f"x.{lang}", src.split("\n"), lang) if i["rule"].startswith("T-")}


class RedirectHostTests(unittest.TestCase):
    maxDiff = None

    def test_reported(self):
        for lang, src, want in REPORTED:
            with self.subTest(src=src[len(FLASK):]):
                self.assertEqual(t_findings(lang, src), want)

    def test_quiet(self):
        for lang, src in QUIET:
            with self.subTest(src=src[len(FLASK):]):
                self.assertEqual(t_findings(lang, src), set())

    def test_other_frameworks(self):
        django = ("from django.http import HttpResponseRedirect\nfrom urllib.parse import urlparse\n"
                  "def go(request):\n    url = request.GET['next']\n    if urlparse(url).netloc in HOSTS:\n"
                  "        return HttpResponseRedirect(url)\n    return HttpResponseRedirect(url)\n")
        self.assertEqual(t_findings("py", django), {("T-REDIR", 7)})

    def test_bounded_work(self):
        import time
        for text in ("q = input()\nif " + "(" * 30_000 + "urlparse(q).netloc in A" + ")" * 30_000 + ":\n    redirect(q)\n",
                     "q = input()\nif " + "urlparse(q).netloc in A or " * 10_000 + "x:\n    redirect(q)\n",
                     "q = input()\np = " + "a." * 30_000 + "netloc\nif p in A:\n    redirect(q)\n",
                     "q = input()\n" + "p = urlparse(q)\n" * 5_000 + "if p.netloc in A:\n    redirect(q)\n"):
            t0 = time.monotonic()
            core.taint_scan("x.py", text.split("\n"), "py")
            self.assertLess(time.monotonic() - t0, 10, text[:30])


if __name__ == "__main__":
    unittest.main()
