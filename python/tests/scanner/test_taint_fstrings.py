"""Audit P0: taint follows a value into a Python f-string or a JavaScript
template literal, across the lines of one statement and through augmented
assignments; codecs.open and the Flask / Django response sinks; and the
precision that comes with them (only a sink's injectable arguments are read,
path guards, where a taint lives).

REPORTED and QUIET are the expectations, one small file each; the engines are
held to each other on the same cases by tests/architecture/test_js_parity_taint.py
and js/test/taint-fstrings.test.js. Hosts are .invalid; nothing runs.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

FLASK = "from flask import Flask, request, redirect, url_for, make_response, jsonify, render_template, abort\n"
DJANGO = "from django.http import HttpResponse, HttpResponseRedirect\nfrom django.utils.safestring import mark_safe\n"

# (lang, source, the exact set of (T-* rule, line) it reports)
REPORTED = [
    # f-strings and template literals
    ("py", "import codecs\nname = input()\nf = codecs.open(f'/srv/files/{name}', 'r', 'utf-8')\n",
     {("T-PATH", 3)}),
    ("py", "name = input()\nopen(f\"/srv/{name}\").read()\n", {("T-PATH", 2)}),
    ("py", "import os\nd = input()\nos.system(rf\"ls {d}\")\nos.system(Fr'ls {d!r}')\n",
     {("T-CMD", 3), ("T-CMD", 4)}),
    ("py", "import os\nf = input()\nname = 'x'\nos.system(f\"ls {name}\")\nos.system(f'ls {f}')\n",
     {("T-CMD", 5)}),
    ("js", "const { exec } = require('child_process');\nconst name = process.argv[2];\nexec(`ls ${name}`);\n",
     {("T-CMD", 3)}),
    ("js", "const fs = require('fs');\nconst p = `/srv/${process.argv[2]}`;\nfs.readFileSync(p);\n",
     {("T-PATH", 3)}),
    ("js", "const q = new URLSearchParams(location.search).get('u');\nfetch(`${q}/x`);\n", {("T-SSRF", 2)}),
    # one statement over several lines
    ("py", "import subprocess\nq = input()\nsubprocess.run(\n    f\"echo {q}\",\n    shell=True,\n)\n",
     {("T-CMD", 3)}),
    ("js", "const cp = require('child_process');\nconst n = process.argv[2];\ncp.exec(\n  `ls ${n}`\n);\n",
     {("T-CMD", 3)}),
    # augmented assignments
    ("py", "import os\nq = input()\ncmd = 'ls '\ncmd += q\ncmd += ' -l'\nos.system(cmd)\n", {("T-CMD", 6)}),
    ("js", "const cp = require('child_process');\nlet cmd = 'ls ';\ncmd += process.argv[2];\ncp.exec(cmd);\n",
     {("T-CMD", 4)}),
    # Flask views: what a view returns is the body
    ("py", FLASK + "app = Flask(__name__)\n@app.route('/a')\ndef a():\n    q = request.args.get('q', '')\n"
             "    return f'<p>{q}</p>'\n", {("T-XSS", 6)}),
    ("py", FLASK + "app = Flask(__name__)\n@app.get('/a')\ndef a():\n    q = request.args['q']\n"
             "    html = '<ul>'\n    html += f'<li>{q}</li>'\n    return html, 200\n", {("T-XSS", 8)}),
    ("py", FLASK + "bp = None\n@bp.route('/a',\n          methods=['POST'])\ndef a():\n"
             "    return f\"{{x}} {request.form['n']}\"\n", {("T-XSS", 6)}),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    return str(request.args.get('n'))\n", {("T-XSS", 4)}),
    # response objects and markup
    ("py", FLASK + "def a():\n    q = request.args['q']\n    resp = make_response(\n        '<b>' + q + '</b>'\n    )\n"
             "    return resp\n", {("T-XSS", 4)}),
    ("py", "from markupsafe import Markup\nfrom flask import request\nhtml = Markup(request.args['h'])\n",
     {("T-XSS", 3)}),
    ("py", "from markupsafe import Markup\nimport html\nq = input()\nMarkup(html.unescape(q))\n", {("T-XSS", 4)}),
    # Django
    ("py", DJANGO + "def v(request):\n    q = request.GET.get('q', '')\n    return HttpResponse(f'<p>{q}</p>')\n",
     {("T-XSS", 5)}),
    ("py", DJANGO + "def v(request):\n    return HttpResponseRedirect(request.POST['next'])\n", {("T-REDIR", 4)}),
    ("py", DJANGO + "def v(request):\n    return mark_safe(request.COOKIES['c'])\n", {("T-XSS", 4)}),
    # only the injectable arguments are read
    ("py", "q = input()\ncur.execute(f\"SELECT * FROM t WHERE a = '{q}'\")\n", {("T-SQL", 2)}),
    ("py", "import requests\nurl = input()\nrequests.get(url, timeout=5)\n", {("T-SSRF", 3)}),
    ("py", "import requests, subprocess\nu = input()\nrequests.get(url=u)\nsubprocess.run(args=u, shell=True)\n",
     {("T-SSRF", 3), ("T-CMD", 4)}),
    ("py", "from flask import redirect, request\nredirect(request.args['next'])\n", {("T-REDIR", 2)}),
    ("js", "app.get('/r', (req, res) => {\n  res.redirect(301, req.query.next);\n});\n", {("T-REDIR", 2)}),
    ("js", "const q = process.argv[2];\ndb.query(`SELECT * FROM t WHERE a = '${q}'`);\n", {("T-SQL", 2)}),
    # a guard that does not leave keeps the taint
    ("py", "import logging\nname = input()\nif '..' in name:\n    logging.warning('odd name')\nopen(name)\n",
     {("T-PATH", 5)}),
    # a reassignment in a branch adds to the value
    ("py", "import os\nname = input()\nif name == 'x':\n    name = 'fixed'\nos.system(name)\n", {("T-CMD", 5)}),
    ("py", "import os\nfrom werkzeug.utils import secure_filename\np = secure_filename(input())\n"
           "if p == 'a':\n    p = input()\nopen(p)\n", {("T-PATH", 6)}),
    # a nested function still sees its enclosing function's taint
    ("py", "import os\ndef outer():\n    cmd = input()\n    def inner():\n        os.system(cmd)\n    return inner\n",
     {("T-CMD", 5)}),
    ("js", "const cp = require('child_process');\nfunction outer(req) {\n  const c = req.query.c;\n"
           "  return function inner() {\n    cp.exec(c);\n  };\n}\n", {("T-CMD", 5)}),
]

# (lang, source) that reports no T-* finding
QUIET = [
    # an empty URLSearchParams is not the page's query string
    ("js", "const params = new URLSearchParams();\nparams.append('a', '1');\nfetch(`/api/x?${params.toString()}`);\n"),
    # a tagged template is parameterized; a literal field is text
    ("js", "const n = process.argv[2];\ndb.query(sql`SELECT * FROM t WHERE n = ${n}`);\n"),
    ("py", "import os\nq = input()\nos.system(f'ls {{q}}')\n"),
    # parameterized queries, a response's headers, keyword arguments
    ("py", "q = input()\ncur.execute('SELECT * FROM t WHERE a = ?', (q,))\ncur.executemany(sql, [(q,)])\n"),
    ("js", "const q = process.argv[2];\ndb.query('SELECT * FROM t WHERE a = ?', [q]);\n"),
    ("py", FLASK + "def a():\n    bar = request.args['b']\n    return make_response(('text', {'X-B': bar}))\n"),
    ("py", "import requests\nq = input()\nrequests.post('https://api.invalid/x', data={'q': q}, headers={'X': q})\n"),
    ("py", "from flask import send_file, request\nn = request.args['n']\nsend_file('/srv/report.csv', download_name=n)\n"),
    ("py", "import subprocess\nd = input()\nsubprocess.run(['ls'], cwd=d)\n"),
    ("py", "from flask import render_template_string, request\n"
           "render_template_string('Hello {{ n }}', n=request.args['n'])\n"),
    # the code after the call on the same line is not an argument
    ("js", "const cp = require('child_process');\ncp.exec('ls'); console.log(location.search);\n"),
    # sanitizers
    ("py", FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n    return f'<p>{escape(q)}</p>'\n"),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    return render_template(\n        'a.html',\n"
             "        q=request.args['q'],\n    )\n"),
    ("py", FLASK + "def a():\n    return redirect(url_for('auth.login', next=request.full_path))\n"),
    ("py", "import os\nfrom flask import request\nn = request.args.get('n', 1, type=int)\nos.system(f'sleep {n}')\n"),
    ("py", "from werkzeug.utils import safe_join\nfrom flask import request\nopen(safe_join('/srv', request.args['p']))\n"),
    # views: JSON, redirects, files and other functions' values are what they are
    ("py", FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n    return {'q': q}\n"),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    return jsonify(q=request.args['q']), 201\n"),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    return request.get_json()\n"),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n    return User.to_dict(q, page=1)\n"),
    ("py", FLASK + "@app.route('/a')\ndef a():\n    q = request.args['q']\n    def helper():\n        return q\n"
             "    return 'ok'\n"),
    ("py", FLASK + "def not_a_view():\n    return request.args['q']\n"),
    ("py", "from fastapi import FastAPI, Request\napp = FastAPI()\n@app.get('/a')\n"
           "def a(request: Request):\n    return request.query_params\n"),
    # redirects to this site
    ("py", "from flask import redirect, request\nredirect('/user/' + request.args['id'])\n"
           "redirect(f\"/search?q={request.args['q']}\")\n"),
    ("js", "app.get('/u', (req, res) => {\n  res.redirect('/user/' + req.params.id);\n});\n"),
    # path guards that leave
    ("py", "from flask import request, abort\nname = request.args['n']\nif '..' in name:\n    abort(400)\n"
           "open(name)\n"),
    ("py", "import os\nfrom flask import request\nBASE = '/srv'\np = os.path.realpath(os.path.join(BASE, request.args['p']))\n"
           "if not p.startswith(BASE):\n    raise ValueError(p)\nopen(p)\n"),
    ("js", "const fs = require('fs');\napp.get('/f', (req, res) => {\n  const name = req.query.name;\n"
           "  if (name.includes('..')) return res.sendStatus(400);\n  res.send(fs.readFileSync(name));\n});\n"),
    # where a taint lives
    ("py", "import os\ndef a():\n    name = input()\n    return name\ndef b():\n    name = 'ls'\n    os.system(name)\n"),
    ("py", "import os\nfrom werkzeug.utils import secure_filename\np = input()\np = secure_filename(p)\nopen(p)\n"),
    ("py", "import os\nif True:\n    c = input()\nc = 'ls'\nos.system(c)\n"),
    ("py", "import os\nq = input()\nsql = \"\"\"\nSELECT (\n\"\"\"\nq = 'x'\nos.system(q)\n"),
    ("js", "const fs = require('fs');\napp.get('/a', (req, res) => {\n  const f = req.query.f;\n  res.json({ f });\n});\n"
           "app.get('/b', (req, res) => {\n  const f = '/srv/index.html';\n  res.sendFile(f);\n});\n"),
]


def t_findings(lang, src):
    return {(i["rule"], i["line"]) for i in core.scan_file("x." + lang, src, lang)
            if i["rule"].startswith("T-")}


class TaintExpectations(unittest.TestCase):
    maxDiff = None

    def test_reported(self):
        for lang, src, want in REPORTED:
            with self.subTest(src=src):
                self.assertEqual(t_findings(lang, src), want)

    def test_quiet(self):
        for lang, src in QUIET:
            with self.subTest(src=src):
                self.assertEqual(t_findings(lang, src), set())


class CrossFileTests(unittest.TestCase):
    """The cross-file flow engine (X-*) knows the same sources and sinks."""

    def flows(self, files):
        from lazaret.scanner import flow
        return {(i["rule"], i["file"], i["line"]) for i in flow.analyze(
            [{"path": p, "content": c, "lang": "py"} for p, c in files.items()])}

    def test_new_sinks_across_files(self):
        found = self.flows({
            "sinks.py": "import codecs\nfrom flask import make_response\nfrom django.http import HttpResponseRedirect\n"
                        "def read(name):\n    return codecs.open(name).read()\n"
                        "def show(v):\n    return make_response(v)\n"
                        "def headers(v):\n    return make_response(('ok', {'X-V': v}))\n"
                        "def go(v):\n    return HttpResponseRedirect(v)\n",
            "views.py": "from flask import request\nfrom sinks import read, show, headers, go\n"
                        "def a():\n    read(request.get_data())\n    show(request.args['q'])\n"
                        "    headers(request.args['h'])\n    go(request.full_path)\n"})
        self.assertEqual({(r, line) for r, _, line in found},
                         {("X-PATH", 4), ("X-XSS", 5), ("X-REDIR", 7)})

    def test_new_sanitizers_across_files(self):
        found = self.flows({
            "sinks.py": "from flask import make_response, redirect\ndef show(v):\n    return make_response(v)\n"
                        "def go(v):\n    return redirect(v)\n",
            "views.py": "from flask import request, url_for, render_template\nfrom sinks import show, go\n"
                        "from app.util import escape_html\ndef a():\n    show(escape_html(request.args['q']))\n"
                        "    show(render_template('t.html', q=request.args['q']))\n"
                        "    go(url_for('x', next=request.args['n']))\n"})
        self.assertEqual(found, set())


class HelperTests(unittest.TestCase):
    def test_taint_code_keeps_fields(self):
        self.assertEqual(core._taint_code('os.system(f"ls {d!r} {{x}}" + rb"q")', "py").split(),
                         ["os.system(", "d!r", "+", ")"])
        self.assertEqual(core._taint_code("exec(`ls ${a}`); q = sql`x ${b}`; return `${c}`", "js").split(),
                         ["exec(", "a", ");", "q", "=", "sql;", "return", "c"])

    def test_arguments(self):
        self.assertEqual(core._first_arg(" (body, {'h': bar}))"), "body")
        self.assertEqual(core._first_arg(" sql, (x,))"), " sql")
        self.assertEqual(core._positional_args(" url, data=d, headers=h)"), " url")
        self.assertEqual(core._extent("cmd); log(location.href)"), "cmd")
        self.assertEqual(core._extent(" q; other(req.query)"), " q")
        self.assertEqual(core._offsite_args(" 301, '/x' + y"), " 301")

    def test_linear_time(self):
        import time
        for text in ["(" * 200_000, "'" * 200_000, "a," * 200_000, "f'{" * 100_000, "=>" * 200_000 + " {",
                     "a." * 200_000 + "get(type=int)", " " * 100_000 + "if '..' in x:"]:
            t0 = time.monotonic()
            core._first_arg(text), core._positional_args(text), core._extent(text), core._offsite_args(text)
            core._taint_code(text, "py"), core._taint_code(text, "js")
            core._scope_opener(text, "js"), core._neutralize(text, "py", "XSS"), core._guarded_names(text, "py")
            self.assertLess(time.monotonic() - t0, 10, text[:12])


if __name__ == "__main__":
    unittest.main()
