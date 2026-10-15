"""Q-2 and Q-3 (0.1.9): BenchmarkPython's categories without a rule, and two pattern rules that flagged its safe code.

OWASP's BenchmarkPython (0.1, GPL: scanned and scored here and in the audits, its test sources never read) scores a
tool per category, true positives against false positives. Five of its fourteen categories had no rule (208 of its
452 flaws), and the code-injection and XXE pattern rules flagged its safe cases. Now:

* Sinks of the intra-file taint pass: a value or a key put in the session (trust boundary, CWE-501: Flask's
  `session[k] = v`, Django's `request.session`, `session.update(…)`); an LDAP search (ldap3's `search`, python-ldap's
  `search_s` & co., in a file that imports one: `re.search` is not one; ldap3's and python-ldap's escapes clear it);
  an XPath expression (lxml's `.xpath()` and `XPath()`, elementpath's `select`: not the variables passed beside it;
  a quote replaced in the value clears it). A sink row's seventh field names the arguments it reads.
* What the pass follows: a Python string literal's escapes (`'…=\\'' + name + '\\']'` hid `name`), a `for`
  statement's targets (`for name in request.args.keys():`), and `set()` under literal keys read back by `get()`
  (configparser's `set(section, option, value)`, a dict's `get(key)`).
* S-WEAKRAND (a hotspot): any call of the random module's generators on a line S-RANDOM does not take.
* S-COOKIE (a hotspot, the project pass): `set_cookie` without `secure=True`.
* S-XML: a parser set to resolve external entities, no longer an import of xml.etree, xml.dom or xml.sax.

The dashboard is held to the same answers by the dashboard parity test. All content is inert: hosts are .invalid,
nothing is run.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

FLASK = "from flask import Flask, request, session, make_response\nimport os, subprocess, configparser\napp = Flask(__name__)\n"
LDAP = FLASK + "import ldap3\nfrom ldap3.utils.conv import escape_filter_chars\n"
XML = FLASK + "import lxml.etree\nimport elementpath\n"

# (lang, source, {(rule, line)}): the T-* findings
REPORTED = [
    # a for statement's targets
    ("py", FLASK + "@app.route('/a')\ndef a():\n    param = ''\n    for name in request.args.keys():\n"
                   "        if request.args.get(name) == 'x':\n            param = name\n    os.system('ls ' + param)\n",
     {("T-CMD", 10)}),
    ("py", FLASK + "@app.route('/b')\ndef b():\n    for (k, v) in request.form.items():\n"
                   "        subprocess.run(v, shell=True)\n", {("T-CMD", 7)}),
    # escaped quotes in a literal
    ("py", XML + "@app.route('/c')\ndef c():\n    name = request.args['n']\n"
                 "    q = '/Users/User[@name=\\'' + name + '\\']'\n    nodes = root.xpath(q)\n", {("T-XPATH", 10)}),
    # set() and get() under literal keys
    ("py", FLASK + "@app.route('/d')\ndef d():\n    conf = configparser.ConfigParser()\n    conf.add_section('s')\n"
                   "    conf.set('s', 'keyA', 'a_value')\n    conf.set('s', 'keyB', request.args['p'])\n"
                   "    bar = conf.get('s', 'keyB')\n    eval(bar)\n", {("T-CODE", 11)}),
    # trust boundary: a value, a key, a method
    ("py", FLASK + "@app.route('/e')\ndef e():\n    session['user'] = request.args.get('u')\n"
                   "    session[request.args['k']] = '1'\n    request.session['n'] = request.form['n']\n"
                   "    session.update(name=request.args['x'])\n",
     {("T-TRUST", 6), ("T-TRUST", 7), ("T-TRUST", 8), ("T-TRUST", 9)}),
    # LDAP
    ("py", LDAP + "@app.route('/f')\ndef f():\n    user = request.args['u']\n    flt = '(uid=' + user + ')'\n"
                  "    conn.search('dc=example,dc=invalid', flt, attributes=['cn'])\n"
                  "    conn.search(search_base='dc=example,dc=invalid', search_filter=f'(cn={user})')\n"
                  "    l.search_s('dc=example,dc=invalid', 2, flt)\n",
     {("T-LDAP", 10), ("T-LDAP", 11), ("T-LDAP", 12)}),
    # XPath
    ("py", XML + "@app.route('/g')\ndef g():\n    p = request.form['p']\n"
                 "    root.xpath(\"//u[@n='\" + p + \"']\")\n    elementpath.select(root, f\"//u[@n='{p}']\")\n"
                 "    find = lxml.etree.XPath('//u[@n=\"' + p + '\"]')\n",
     {("T-XPATH", 9), ("T-XPATH", 10), ("T-XPATH", 11)}),
]

# no T-* finding
QUIET = [
    ("py", FLASK + "@app.route('/a')\ndef a():\n    for i in range(3):\n        os.system('ls %d' % i)\n"
                   "    for k in KEYS:\n        os.system('ls ' + k)\n"),
    ("py", FLASK + "@app.route('/d')\ndef d():\n    conf = configparser.ConfigParser()\n"
                   "    conf.set('s', 'keyA', 'a_value')\n    conf.set('s', 'keyB', request.args['p'])\n"
                   "    bar = conf.get('s', 'keyA')\n    eval(bar)\n"
                   "    m = {}\n    m['a'] = 'x'\n    m['b'] = request.args['q']\n    os.system(m.get('a'))\n"),
    ("py", FLASK + "@app.route('/e')\ndef e():\n    session['n'] = 'x'\n    if session['n'] == request.args['n']:\n"
                   "        pass\n    session['count'] = len(session)\n"),
    ("py", LDAP + "@app.route('/f')\ndef f():\n    user = escape_filter_chars(request.args['u'])\n"
                  "    conn.search('dc=example,dc=invalid', '(uid=' + user + ')')\n"
                  "    m = re.search(request.args['p'], 'text')\n"),
    ("py", FLASK + "import re\nPATTERN = re.compile('a+')\n@app.route('/f')\ndef f():\n"
                   "    m = PATTERN.search(request.args['u'])\n    return 'ok'\n"),
    ("py", XML + "@app.route('/g')\ndef g():\n    p = request.form['p']\n    root.xpath('//u[@n=$n]', n=p)\n"
                 "    safe = p.replace(\"'\", '&apos;')\n    root.xpath(\"//u[@n='\" + safe + \"']\")\n"
                 "    elementpath.select(root, '//u[@n=$n]', variables={'n': p})\n"),
]


RANDOMS = ("import random, secrets\nn = random.randint(1, 6)\nvalue = str(random.random())[2:]\n"
           "token = random.random()\npick = random.sample(ITEMS, 3)\nkey = random.sample(ALPHABET, 16)\n"
           "ok = secrets.token_hex(16)\nr = random.SystemRandom().random()\nnp.random.rand(3)\n"
           "# random.random()\n")
COOKIES = (FLASK + "@app.route('/c')\ndef c():\n    resp = make_response('ok')\n"
           "    resp.set_cookie('lang', 'en')\n"                                   # 7: missing
           "    resp.set_cookie(\n        'rememberMe', value,\n        secure=False,\n        httponly=True,\n"
           "        path=request.path,\n    )\n"                                   # 8: secure=False
           "    resp.set_cookie('a', v, None, None, '/', None, False)\n"           # 14: positional
           "    resp.set_cookie('a', v, secure=True, httponly=True)\n"
           "    resp.set_cookie('a', v, None, None, '/', None, True)\n"
           "    resp.set_cookie('a', v, secure=settings.SECURE)\n"
           "    resp.set_cookie('a', v, **COOKIE_OPTIONS)\n"
           "    # resp.set_cookie('a', v)\n    return resp\n")
XMLS = ("import xml.etree.ElementTree as ET\nfrom xml.dom import minidom\nimport xml.sax\n"
        "from xml.sax.handler import feature_external_ges\nparser = xml.sax.make_parser()\n"
        "parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
        "parser.setFeature(feature_external_ges, False)\n"
        "parser.setFeature('http://xml.org/sax/features/external-general-entities', 1)\n"
        "p2 = lxml.etree.XMLParser(resolve_entities=True)\np3 = lxml.etree.XMLParser(resolve_entities=False)\n")


def t_findings(lang, src):
    lines = src.split("\n")
    return {(i["rule"], i["line"]) for i in core.taint_scan(f"x.{lang}", lines, lang) if i["rule"].startswith("T-")}


def findings(src, prefix):
    return sorted((i["rule"], i["line"]) for i in core.scan_file("x.py", src, "py") if i["rule"].startswith(prefix))


class TaintTests(unittest.TestCase):
    maxDiff = None

    def test_reported(self):
        for lang, src, want in REPORTED:
            with self.subTest(src=src[-160:]):
                self.assertEqual(t_findings(lang, src), want)

    def test_quiet(self):
        for lang, src in QUIET:
            with self.subTest(src=src[-160:]):
                self.assertEqual(t_findings(lang, src), set())

    def test_ldap_needs_an_import(self):
        src = FLASK + "@app.route('/f')\ndef f():\n    conn.search('dc=example,dc=invalid', request.args['u'])\n"
        self.assertEqual(t_findings("py", src), set())
        self.assertEqual(t_findings("py", "import ldap\n" + src), {("T-LDAP", 7)})

    def test_what_the_sinks_say(self):
        src = REPORTED[4][1]
        (first,) = [i for i in core.taint_scan("x.py", src.split("\n"), "py") if i["line"] == 6]
        self.assertEqual((first["rule"], first["sev"], first["ref"]), ("T-TRUST", "MINOR", "CWE-501 · Taint analysis"))
        self.assertIn("trust boundary violation", first["msg"])
        kinds = {i["rule"]: (i["sev"], i["ref"]) for _l, s, _w in REPORTED[5:] for i in core.taint_scan("x.py", s.split("\n"), "py")}
        self.assertEqual(kinds, {"T-LDAP": ("MAJOR", "CWE-90 · Taint analysis"), "T-XPATH": ("MAJOR", "CWE-643 · Taint analysis")})

    def test_bounded_work(self):
        import time
        for text in ("for " + "a, " * 30_000 + "b in x:\n", "for x in " + "(" * 30_000 + ":\n",
                     "x = d.get(" + "'k', " * 30_000 + "'k')\n", "d.set(" + "'k', " * 30_000 + "q)\n" * 3,
                     "session" + "[" * 30_000 + "] = q\n", "q = input()\n" + "session[a" + "]" * 30_000 + " = q\n",
                     "import ldap3\nq = input()\n" + "a." * 30_000 + "search(q)\n",
                     "q = input()\nx = '" + "\\'" * 50_000 + "' + q\n", "q = input()\n" + "s.replace('\"', " * 20_000 + "\n"):
            t0 = time.monotonic()
            core.taint_scan("x.py", text.split("\n"), "py")
            self.assertLess(time.monotonic() - t0, 10, text[:30])


class RandomTests(unittest.TestCase):
    def test_weak_randomness(self):
        src = RANDOMS
        self.assertEqual(findings(src, "S-WEAKRAND"), [("S-WEAKRAND", 2), ("S-WEAKRAND", 3), ("S-WEAKRAND", 5)])
        self.assertEqual(findings(src, "S-RANDOM"), [("S-RANDOM", 4), ("S-RANDOM", 6)])
        (weak,) = [i for i in core.scan_file("x.py", src, "py") if i["rule"] == "S-WEAKRAND"][:1]
        self.assertEqual((weak["type"], weak["sev"], weak["ref"]), ("HOTSPOT", "MINOR", "CWE-330"))


class CookieTests(unittest.TestCase):
    def test_without_the_secure_flag(self):
        src = COOKIES
        found = [(i["rule"], i["line"], i["msg"]) for i in core.scan_file("x.py", src, "py") if i["rule"] == "S-COOKIE"]
        self.assertEqual(found, [
            ("S-COOKIE", 7, "Cookie set without secure=True: the browser also sends it over plain HTTP."),
            ("S-COOKIE", 8, "Cookie set with secure=False: the browser also sends it over plain HTTP."),
            ("S-COOKIE", 14, "Cookie set with secure=False: the browser also sends it over plain HTTP.")])
        (one,) = [i for i in core.scan_file("x.py", src, "py") if i["rule"] == "S-COOKIE"][:1]
        self.assertEqual((one["type"], one["sev"], one["ref"]), ("HOTSPOT", "MINOR", "CWE-614 · OWASP A05"))

    def test_marker_and_other_languages(self):
        self.assertEqual(findings("resp.set_cookie('a', v)  # nosec\n", "S-COOKIE"), [])
        js = [i for i in core.scan_file("x.js", "res.set_cookie('a', v);\n", "js") if i["rule"] == "S-COOKIE"]
        self.assertEqual(js, [])


class XmlTests(unittest.TestCase):
    def test_external_entities_enabled(self):
        src = XMLS
        self.assertEqual(findings(src, "S-XML"), [("S-XML", 6), ("S-XML", 8), ("S-XML", 9)])
        (one,) = [i for i in core.scan_file("x.py", src, "py") if i["rule"] == "S-XML"][:1]
        self.assertEqual((one["type"], one["sev"], one["ref"]), ("VULN", "MAJOR", "CWE-611"))


if __name__ == "__main__":
    unittest.main()
