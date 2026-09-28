"""Framework models for intra-file taint (0.1.7): Flask, Django, FastAPI and
Express.

* Route handlers: the parameters a framework fills from the request are
  sources — a Flask view's URL rule variables (not int / float / uuid / any
  converters), a FastAPI path operation's parameters (not what it injects or
  validates to no free text: Depends, Response, int, UUID, Literal, an Enum's
  member …), a Django view's URL parameters (not pk, id, slug …, not typed
  ones).
* Sources: Starlette's and DRF's query_params / path_params, a websocket's
  messages; Express's req.url, req.path, req.hostname, req.get(…) and a
  request object named `request`.
* Sinks: FastAPI's HTMLResponse, RedirectResponse, FileResponse; Django's
  Manager.raw, RawSQL, QuerySet.extra, SafeString; jinja2's Template and
  Environment.from_string; httpx; asyncio.create_subprocess_shell; Express's
  res.send / write / end (not a whole parsed object: JSON), res.location,
  fs writes, EJS / Pug / Handlebars / lodash templates, vm, knex's raw SQL.
* Sanitizers and precision: TemplateResponse and render_to_string (XSS),
  reverse() and the Referer (open redirect), ORM lookups and file reads
  (their results are not request data), a response with a non-HTML content
  type (XSS; in Express, a chain that sets one first), send_from_directory's
  file name and Express's sendFile / download given a root, a redirect to a
  fixed host,
  an index or a slice() argument (the container's element, not the key's),
  allowlist membership guards.
* Containers: a value written into one (`d["k"] = q`, `xs.append(q)`,
  `arr.push(q)`) taints it, followed by literal key.

The npm engine and the dashboard are held to the same answers by
tests/architecture/test_js_parity_taint.py and the dashboard parity test.
All content is inert.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

FLASK = "from flask import Flask, request, send_file, send_from_directory, abort\napp = Flask(__name__)\n"
FASTAPI = ("from fastapi import FastAPI, Depends, Request, WebSocket, BackgroundTasks\n"
           "from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse\n"
           "from typing import Optional, Annotated, Literal\nimport os, subprocess\napp = FastAPI()\n")
DJANGO = ("from django.http import HttpResponse, FileResponse, HttpResponsePermanentRedirect\n"
          "from django.shortcuts import redirect, get_object_or_404\nfrom django.urls import reverse\n"
          "from django.db import connection\n")
EXPRESS = "const express = require('express');\nconst fs = require('fs');\nconst app = express();\n"

# (lang, source, {(rule, line)})
REPORTED = [
    ("py", FLASK + "@app.route('/dl/<path:name>')\ndef dl(name):\n    return send_file('/srv/' + name)\n",
     {("T-PATH", 5)}),
    ("py", FLASK + "@app.get('/s/<q>')\ndef search(q, page=1):\n    return '<h1>' + q + '</h1>'\n",
     {("T-XSS", 5)}),
    ("py", FLASK + "@app.route('/a/<name>')\n@app.route('/b/<int:n>/<name>')\ndef two(name, n=0):\n"
                   "    return open(name).read()\n", {("T-PATH", 6)}),
    ("py", FASTAPI + "@app.get('/items/{item_id}')\nasync def read(item_id: int, q: Optional[str] = None):\n"
                     "    subprocess.run('grep ' + q, shell=True)\n", {("T-CMD", 8)}),
    ("py", FASTAPI + "@app.get('/go')\ndef go(\n    url: str,\n    tasks: BackgroundTasks,\n):\n"
                     "    return RedirectResponse(url)\n", {("T-REDIR", 11)}),
    ("py", FASTAPI + "@app.get(\n    '/p',\n    response_class=HTMLResponse,\n)\n"
                     "def page(name: Annotated[str, Query(max_length=40)] = 'x'):\n    return f'<p>{name}</p>'\n",
     {("T-XSS", 11)}),
    ("py", FASTAPI + "@app.get('/f')\ndef f(path: str, n: int | None = None, when: list[date] = []):\n"
                     "    return FileResponse(path)\n", {("T-PATH", 8)}),
    ("py", FASTAPI + "@app.post('/r')\nasync def r(request: Request):\n    q = request.query_params['q']\n"
                     "    return HTMLResponse('<p>' + q)\n", {("T-XSS", 9)}),
    ("py", FASTAPI + "@app.websocket('/ws')\nasync def ws(websocket: WebSocket):\n"
                     "    cmd = await websocket.receive_text()\n    os.system(cmd)\n", {("T-CMD", 9)}),
    ("py", FASTAPI + "@app.put('/user')\nasync def put_user(user: User):\n"
                     "    await db.execute(f'INSERT INTO u VALUES (\"{user.name}\")')\n", {("T-SQL", 8)}),
    ("py", DJANGO + "def detail(request, slug, name):\n    with connection.cursor() as c:\n"
                    "        c.execute(\"select * from t where slug = '%s'\" % slug)\n"
                    "    return HttpResponse('<p>%s</p>' % name)\n", {("T-XSS", 8)}),
    ("py", DJANGO + "def download(request, filename, pk):\n    return FileResponse(open('/srv/' + filename, 'rb'))\n",
     {("T-PATH", 6)}),
    ("py", DJANGO + "class V(View):\n    def get(self, request, *args, **kwargs):\n"
                    "        rows = Model.objects.raw(\"select * from t where x = '%s'\" % kwargs['x'])\n"
                    "        qs = Model.objects.extra(where=[\"name = '%s'\" % kwargs['n']])\n",
     {("T-SQL", 7), ("T-SQL", 8)}),
    ("py", DJANGO + "from jinja2 import Template\ndef hello(request, name):\n"
                    "    return HttpResponse(Template('<p>' + name + '</p>').render())\n", {("T-SSTI", 7), ("T-XSS", 7)}),
    ("py", DJANGO + "def slash(request, nxt):\n    return redirect('/' + nxt)\n", {("T-REDIR", 6)}),
    ("py", "import os\nfrom flask import request\nq = request.args['q']\nd = {}\nd['a'] = q\nd['b'] = 'fixed'\n"
           "os.system(d['b'])\nos.system(d['a'])\nxs = []\nxs.append(q)\nos.system(' '.join(xs))\n",
     {("T-CMD", 8), ("T-CMD", 11)}),
    ("js", EXPRESS + "app.get('/hello', (req, res) => {\n  res.send('<h1>Hello ' + req.query.name + '</h1>');\n});\n"
                     "app.get('/e', (req, res) => {\n  res.status(404).send(req.params.x);\n});\n",
     {("T-XSS", 5), ("T-XSS", 8)}),
    ("js", EXPRESS + "app.get('/r', (request, response) => {\n  response.redirect(request.query.next);\n"
                     "  res.location(req.get('x-next')).end();\n});\n", {("T-REDIR", 5), ("T-REDIR", 6)}),
    ("js", EXPRESS + "app.post('/w', (req, res) => {\n  const p = req.params.file;\n  fs.writeFile(p, 'x', () => {});\n"
                     "  fs.writeFile('/tmp/log', p, () => {});\n});\n", {("T-PATH", 6)}),
    ("js", EXPRESS + "app.post('/t', (req, res) => {\n  const html = ejs.render(req.body.tpl, {});\n"
                     "  vm.runInNewContext(req.body.code);\n  knex('users').whereRaw('name = ' + req.body.name);\n});\n",
     {("T-SSTI", 5), ("T-CODE", 6), ("T-SQL", 7)}),
    ("js", EXPRESS + "app.get('/c', (req, res) => {\n  const o = {};\n  o['x'] = req.query.x;\n  o['y'] = 'y';\n"
                     "  exec(o['y']);\n  exec(o['x']);\n  const arr = [];\n  arr.push(req.body.c);\n"
                     "  exec(arr.join(' '));\n});\n", {("T-CMD", 9), ("T-CMD", 12)}),
    ("js", EXPRESS + "app.get('/u', (req, res) => {\n  res.redirect(req.originalUrl);\n});\n", {("T-REDIR", 5)}),
    ("js", EXPRESS + "app.get('/h', (req, res) => {\n  res.type('html').send(req.query.q);\n"
                     "  res.sendFile(path.join(__dirname, req.params.name));\n"
                     "  res.download(req.params.f, (err) => { if (err) res.set('X-Root', 'n'); });\n});\n",
     {("T-XSS", 5), ("T-PATH", 6), ("T-PATH", 7)}),
]

QUIET = [
    ("py", FLASK + "@app.route('/u/<int:uid>')\ndef user(uid):\n    return open('/srv/%d' % uid).read()\n"),
    ("py", FLASK + "@app.route('/static/<path:name>')\ndef static2(name):\n"
                   "    return send_from_directory('/srv/static', name)\n"),
    ("py", FLASK + "@app.route('/p/<plugin>')\ndef plugin(plugin):\n    if plugin in PLUGINS:\n"
                   "        return open('/srv/plugins/' + plugin).read()\n    abort(404)\n"),
    ("py", FLASK + "@app.route('/q')\ndef q():\n    name = request.args['n']\n    if name not in PLUGINS:\n"
                   "        abort(404)\n    return open('/srv/' + name).read()\n"),
    ("py", FASTAPI + "@app.get('/items/{item_id}')\nasync def read(item_id: int, db = Depends(get_db)):\n"
                     "    return db.execute('select * from t where id = %d' % item_id)\n"),
    ("py", FASTAPI + "DbDep = Annotated[Session, Depends(get_db)]\n@app.get('/img/{file_name}')\n"
                     "async def img(file_name: ImageType = ImageType.original, db: DbDep = None, s: SessionDep = None,\n"
                     "              kind: Literal['a', 'b'] = 'a', ids: list[UUID] = []):\n"
                     "    return FileResponse(f'/srv/{kind}/{file_name}')\n"),
    ("py", FASTAPI + "@app.get('/s')\nasync def s(request: Request):\n    return FileResponse(request.state.path)\n"),
    ("py", FASTAPI + "@app.get('/u')\ndef u(q: str):\n    return RedirectResponse(USERS[q])\n"),
    ("py", DJANGO + "def v(request, pk, id, slug, user_id, year, code: UUID, n: int):\n"
                    "    return HttpResponse('<p>%s %s %s %s %s %s %s</p>' % (pk, id, slug, user_id, year, code, n))\n"),
    ("py", DJANGO + "def language(request, lang):\n    return redirect(DocumentRelease.objects.current(lang))\n"
                    "def svn(request, rev):\n    url = 'https://github.com/django/django/commit/%s' % rev\n"
                    "    return HttpResponsePermanentRedirect(url)\n"
                    "def back(request, q):\n    url = reverse('checks', args=[q])\n    return redirect(url)\n"
                    "def ref(request, x):\n    return redirect(request.META.get('HTTP_REFERER', '/'))\n"),
    ("py", DJANGO + "def body(request, name):\n    ping = get_object_or_404(Ping, owner=name)\n"
                    "    return HttpResponse(ping.body)\n"
                    "def text(request, name):\n    return HttpResponse(name, content_type='text/plain')\n"),
    ("py", "from string import Template\nfrom flask import request\nq = request.args['q']\n"
           "print(Template(q).substitute(x=1))\n"),
    ("js", EXPRESS + "app.get('/q', (req, res) => {\n  res.send(req.query);\n  res.json({ q: req.query.q });\n"
                     "  res.send(users[req.params.id] || {});\n"
                     "  res.send('users ' + names.slice(req.params.from, req.params.to).join(', '));\n"
                     "  res.redirect(req.get('Referrer') || '/');\n});\n"),
    ("js", EXPRESS + "app.get('/a', (req, res) => {\n  const f = req.query.f;\n  if (ALLOWED.includes(f)) {\n"
                     "    res.sendFile(f);\n  }\n  if (!allowed.has(f)) return res.sendStatus(404);\n"
                     "  res.sendFile(f);\n});\n"),
    ("js", EXPRESS + "app.get('/r', (req, res) => {\n  const name = req.query.name;\n"
                     "  if (name.includes('..')) return res.sendStatus(400);\n  res.send(fs.readFileSync(name));\n});\n"),
    ("js", EXPRESS + "app.get('/t', (req, res) => {\n  res.type('text/plain').send(req.query.q);\n"
                     "  res.status(400).set('Content-Type', 'application/json').end(req.query.q);\n"
                     "  res.sendFile(req.params.name, { root: PUBLIC_DIR });\n"
                     "  res.download(req.params.file.join('/'), { root }, function (err) {});\n});\n"),
]


def t_findings(lang, src):
    lines = src.split("\n")
    return {(i["rule"], i["line"]) for i in core.taint_scan(f"x.{lang}", lines, lang) if i["rule"].startswith("T-")}


class FrameworkModelTests(unittest.TestCase):
    maxDiff = None

    def test_reported(self):
        for lang, src, want in REPORTED:
            with self.subTest(src=src[-160:]):
                self.assertEqual(t_findings(lang, src), want)

    def test_quiet(self):
        for lang, src in QUIET:
            with self.subTest(src=src[-160:]):
                self.assertEqual(t_findings(lang, src), set())

    def test_route_parameters(self):
        ctx = core._FileCtx((FASTAPI + "@app.get('/x/{a}')\nasync def x(a: str, b: int, c = Depends(f), d: Kind = Kind.one,\n"
                                       "            e: Annotated[str, Query()] = None, f: Response = None):\n    pass\n"
                             ).split("\n"), "py")
        self.assertEqual(core._route_params(ctx), {6: ["a", "e"]})
        self.assertTrue(core._safe_type("Optional[Annotated[list[uuid.UUID], Query()]]"))
        self.assertTrue(core._safe_type("int | None"))
        self.assertFalse(core._safe_type("Union[int, str]"))
        self.assertFalse(core._safe_type("dict[str, int]"))
        self.assertEqual(core._signature_params("def f(self, a: dict[str, int] = {'x': 1}, *args, b=f(1, 2), **kw):"),
                         [("self", "", ""), ("a", "dict[str, int]", "{'x': 1}"), ("args", "", ""),
                          ("b", "", "f(1, 2)"), ("kw", "", "")])

    def test_bounded_work(self):
        import time
        for text in ("@app.get(" * 20_000 + "\ndef f(" + "a, " * 20_000 + "):\n    pass\n",
                     "from fastapi import FastAPI\n@app.get('/x')\ndef f(a: " + "Optional[" * 5_000 + "int" + "]" * 5_000 + "):\n",
                     "x = " + "y[" * 50_000 + "]" * 50_000 + "\n", "d['k'] = q\n" * 20_000,
                     "from django import x\ndef v(request, " + "p, " * 30_000 + "):\n    pass\n",
                     "except:" + "\n" * 200_000, " " * 200_000 + "from jinja2 import Template\n",
                     "a" * 200_000 + "[", "q = input()\nx = " + "a" * 100_000 + "[q" + "\n",
                     "if " + "x in " * 50_000 + "A:\n", "@app.route('" + "<" * 50_000 + "')\ndef f(a):\n"):
            for lang in ("py", "js"):
                t0 = time.monotonic()
                core.taint_scan(f"x.{lang}", text.split("\n"), lang)
                self.assertLess(time.monotonic() - t0, 10, f"{text[:30]} {lang}")


if __name__ == "__main__":
    unittest.main()
