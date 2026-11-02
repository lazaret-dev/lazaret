// Framework models for intra-file taint (0.1.7): Flask, Django, FastAPI and
// Express — route handler parameters as sources, the frameworks' sources,
// sinks and sanitizers, containers and allowlist guards. Twin of
// python/tests/scanner/test_taint_frameworks.py. Since Q-1 (0.1.9) the pass is
// the native engine's in both packages; its helpers are held by the engine's
// own tests (rust/crates/lazaret-engine/src/taint_tests.rs, pyflow/frameworks.rs).
// Nothing here runs.

import { test } from "node:test";
import assert from "node:assert/strict";
import { taintScan } from "../src/scanner/scan.js";

const FLASK = "from flask import Flask, request, send_file, send_from_directory, abort\napp = Flask(__name__)\n";
const FASTAPI = "from fastapi import FastAPI, Depends, Request, WebSocket, BackgroundTasks\n"
  + "from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse\n"
  + "from typing import Optional, Annotated, Literal\nimport os, subprocess\napp = FastAPI()\n";
const DJANGO = "from django.http import HttpResponse, FileResponse, HttpResponsePermanentRedirect\n"
  + "from django.shortcuts import redirect, get_object_or_404\nfrom django.urls import reverse\n"
  + "from django.db import connection\n";
const EXPRESS = "const express = require('express');\nconst fs = require('fs');\nconst app = express();\n";
const found = (lang, src) => new Set(taintScan(`x.${lang}`, src.split("\n"), lang)
  .filter((i) => i.rule.startsWith("T-")).map((i) => `${i.rule}:${i.line}`));

test("route handler parameters are sources", () => {
  const cases = [
    [FLASK + "@app.route('/dl/<path:name>')\ndef dl(name):\n    return send_file('/srv/' + name)\n", ["T-PATH:5"]],
    [FLASK + "@app.route('/u/<int:uid>')\ndef user(uid):\n    return open('/srv/%d' % uid).read()\n", []],
    [FASTAPI + "@app.get('/items/{item_id}')\nasync def read(item_id: int, q: Optional[str] = None):\n"
      + "    subprocess.run('grep ' + q, shell=True)\n", ["T-CMD:8"]],
    [FASTAPI + "@app.get('/items/{item_id}')\nasync def read(item_id: int, db = Depends(get_db)):\n"
      + "    return db.execute('select * from t where id = %d' % item_id)\n", []],
    [FASTAPI + "@app.websocket('/ws')\nasync def ws(websocket: WebSocket):\n"
      + "    cmd = await websocket.receive_text()\n    os.system(cmd)\n", ["T-CMD:9"]],
    [DJANGO + "def download(request, filename, pk):\n    return FileResponse(open('/srv/' + filename, 'rb'))\n", ["T-PATH:6"]],
    [DJANGO + "def v(request, pk, id, slug, user_id, year, code: UUID, n: int):\n"
      + "    return HttpResponse('<p>%s %s %s %s %s %s %s</p>' % (pk, id, slug, user_id, year, code, n))\n", []],
  ];
  for (const [src, want] of cases) assert.deepEqual(found("py", src), new Set(want), src.slice(-120));
});

test("Express sources and sinks, and what cleans them", () => {
  assert.deepEqual(found("js", EXPRESS + "app.get('/hello', (req, res) => {\n  res.send('<h1>Hello ' + req.query.name + '</h1>');\n});\n"
    + "app.get('/e', (req, res) => {\n  res.status(404).send(req.params.x);\n});\n"), new Set(["T-XSS:5", "T-XSS:8"]));
  assert.deepEqual(found("js", EXPRESS + "app.get('/r', (request, response) => {\n  response.redirect(request.query.next);\n"
    + "  res.location(req.get('x-next')).end();\n});\n"), new Set(["T-REDIR:5", "T-REDIR:6"]));
  assert.deepEqual(found("js", EXPRESS + "app.post('/t', (req, res) => {\n  const html = ejs.render(req.body.tpl, {});\n"
    + "  vm.runInNewContext(req.body.code);\n  knex('users').whereRaw('name = ' + req.body.name);\n});\n"),
  new Set(["T-SSTI:5", "T-CODE:6", "T-SQL:7"]));
  assert.deepEqual(found("js", EXPRESS + "app.get('/q', (req, res) => {\n  res.send(req.query);\n  res.json({ q: req.query.q });\n"
    + "  res.send(users[req.params.id] || {});\n"
    + "  res.send('users ' + names.slice(req.params.from, req.params.to).join(', '));\n"
    + "  res.redirect(req.get('Referrer') || '/');\n});\n"), new Set());
  assert.deepEqual(found("js", EXPRESS + "app.get('/h', (req, res) => {\n  res.type('html').send(req.query.q);\n"
    + "  res.sendFile(path.join(__dirname, req.params.name));\n"
    + "  res.download(req.params.f, (err) => { if (err) res.set('X-Root', 'n'); });\n});\n"),
  new Set(["T-XSS:5", "T-PATH:6", "T-PATH:7"]));
  assert.deepEqual(found("js", EXPRESS + "app.get('/t', (req, res) => {\n  res.type('text/plain').send(req.query.q);\n"
    + "  res.status(400).set('Content-Type', 'application/json').end(req.query.q);\n"
    + "  res.sendFile(req.params.name, { root: PUBLIC_DIR });\n"
    + "  res.download(req.params.file.join('/'), { root }, function (err) {});\n});\n"), new Set());
});

test("containers and allowlist guards", () => {
  assert.deepEqual(found("js", EXPRESS + "app.get('/c', (req, res) => {\n  const o = {};\n  o['x'] = req.query.x;\n  o['y'] = 'y';\n"
    + "  exec(o['y']);\n  exec(o['x']);\n  const arr = [];\n  arr.push(req.body.c);\n  exec(arr.join(' '));\n});\n"),
  new Set(["T-CMD:9", "T-CMD:12"]));
  assert.deepEqual(found("py", "import os\nfrom flask import request\nq = request.args['q']\nd = {}\nd['a'] = q\nd['b'] = 'fixed'\n"
    + "os.system(d['b'])\nos.system(d['a'])\nxs = []\nxs.append(q)\nos.system(' '.join(xs))\n"), new Set(["T-CMD:8", "T-CMD:11"]));
  assert.deepEqual(found("js", EXPRESS + "app.get('/a', (req, res) => {\n  const f = req.query.f;\n  if (ALLOWED.includes(f)) {\n"
    + "    res.sendFile(f);\n  }\n  if (!allowed.has(f)) return res.sendStatus(404);\n  res.sendFile(f);\n});\n"), new Set());
  assert.deepEqual(found("py", FLASK + "@app.route('/p/<plugin>')\ndef plugin(plugin):\n    if plugin in PLUGINS:\n"
    + "        return open('/srv/plugins/' + plugin).read()\n    abort(404)\n"), new Set());
});

test("bounded work on hostile files", () => {
  const texts = [
    "@app.get(".repeat(20_000) + "\ndef f(" + "a, ".repeat(20_000) + "):\n    pass\n",
    "from fastapi import FastAPI\n@app.get('/x')\ndef f(a: " + "Optional[".repeat(5_000) + "int" + "]".repeat(5_000) + "):\n",
    "x = " + "y[".repeat(50_000) + "]".repeat(50_000) + "\n", "d['k'] = q\n".repeat(20_000),
    "from django import x\ndef v(request, " + "p, ".repeat(30_000) + "):\n    pass\n",
    "except:" + "\n".repeat(200_000), " ".repeat(200_000) + "from jinja2 import Template\n",
    "a".repeat(200_000) + "[", "q = input()\nx = " + "a".repeat(100_000) + "[q" + "\n",
    "if " + "x in ".repeat(50_000) + "A:\n", "@app.route('" + "<".repeat(50_000) + "')\ndef f(a):\n",
  ];
  for (const text of texts) {
    for (const lang of ["py", "js"]) {
      const t0 = Date.now();
      taintScan(`x.${lang}`, text.split("\n"), lang);
      assert.ok(Date.now() - t0 < 10_000, `${text.slice(0, 30)} ${lang}`);
    }
  }
});
