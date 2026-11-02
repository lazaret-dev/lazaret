"""The project-mode corpus (Q-1): source files for test_snapshot_project.py,
which holds a project scan's per-file findings (scan_file with dep=False: the
rules part, then the SQL statements without WHERE, the intra-file taint, the
SQL-sink pass, the function metrics, the suppression markers and the cap) to
their recorded outputs.

Curated files for each pass (CURATED), then a seeded random stream of small
programs built line by line from the pieces those passes read: sources,
assignments of every form (annotated, augmented, destructured, into a
container, under a literal key, over several lines), sanitizers full and
partial, barrier and allowlist guards with and without an exit, scopes
(functions, methods, nested ones, blocks), sinks of every category, Flask,
FastAPI and Django views and route handlers, f-strings and template
literals tagged or not, SQL built into execute() and statements without
WHERE, function headers and branches, suppression markers in comments and in
strings, and lines enough to reach the cap. Not a test: a plain module of
shared data. Hosts are .invalid or TEST-NET; nothing here is run.
"""
import random

# ---------------------------------------------------------------- curated
PY_FLASK = '''from flask import Flask, request, redirect, make_response, send_file
import os, subprocess, sqlite3

app = Flask(__name__)


@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
    subprocess.run(cmd, shell=True)
    return "ok"


@app.route("/user/<name>")
def user(name):
    return f"<p>{name}</p>"


@app.route("/file")
def file():
    path = request.args.get("path")
    if ".." in path:
        abort(400)
    return send_file(path)


@app.route("/go")
def go():
    target = request.args.get("next")
    return redirect(target)


@app.route("/safe")
def safe():
    page = request.args.get("page", 1, type=int)
    n = int(request.args.get("n"))
    os.system("ls " + str(page) + str(n))
    return make_response(html.escape(request.args.get("q")))
'''

PY_SQL = '''import sqlite3
conn = sqlite3.connect("db")
cur = conn.cursor()
user = input()
sql = "SELECT * FROM t WHERE name = '%s'"
q = "SELECT * FROM t WHERE id = {}"
cur.execute(sql % user)
cur.execute(q.format(user))
cur.execute("SELECT * FROM t WHERE a = '" + user + "'")
cur.execute(f"SELECT * FROM t WHERE b = {user}")
cur.execute("SELECT * FROM t WHERE c = %s", (user,))
cur.execute(sql, [user])
static = "SELECT 1"
cur.execute(static)
built = "SELECT " + user
cur.execute(built)
built += " WHERE 1"
cur.executemany(built, rows)
cur.execute(sql%user); cur.execute(q .format(user))
'''

SQL_FILE = '''-- maintenance
DELETE FROM sessions;
DELETE FROM users WHERE id = 1;
UPDATE accounts SET balance = 0;
UPDATE accounts SET balance = 0 WHERE id = 2;
delete from logs; -- nosec
UPDATE t SET a = 1 -- no terminator
DELETE FROM a WHERE x IN (SELECT y FROM b); DELETE FROM c;
GRANT ALL ON db.* TO 'u'@'%' IDENTIFIED BY 'pw';
'''

JS_EXPRESS = '''const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();

app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  exec(cmd);
  exec(`ls ${req.query.dir}`);
  res.send("ok");
});

app.get("/file", function (req, res) {
  const { name, ...rest } = req.query;
  if (name.includes("..")) return res.status(400).end();
  fs.readFile(name, () => {});
  res.sendFile(rest.p, { root: "/srv" });
});

app.get("/q", async (req, res) => {
  const id = parseInt(req.params.id);
  db.query("SELECT * FROM t WHERE id = " + id);
  db.query(sql`SELECT * FROM t WHERE id = ${req.params.id}`);
  db.query("SELECT * FROM t WHERE n = " + req.params.n);
  res.redirect(req.get("referer"));
  res.redirect(req.query.next);
  res.type("text/plain").send(req.query.q);
  res.send(req.query);
  document.getElementById("x").innerHTML = location.hash;
  fetch(req.body.url);
});
'''

SUPPRESS = '''import os
x = input()
os.system(x)  # nosec
os.system(x)  # lazaret-ignore: T-CMD
os.system(x)  # lazaret-ignore: T-SQL
os.system(x)  # NOSONAR - reviewed by bob
# nosec
os.system(x)
s = "# nosec"; os.system(x)
os.system(x)  # noſec
eval(x)  # lazaret-ignore: T-CODE, T-CMD
password = "hunter22hunter"  # nosec
'''

JS_SUPPRESS = '''const x = req.query.x;
eval(x); // nosec
eval(x); // lazaret-ignore: T-CODE
const s = "// nosec"; eval(x);
// NOSONAR
eval(x);
/* nosec */ eval(x);
eval(`${x} // nosec`);
'''


def _long_py(n):
    body = "".join(f"    v{i} = {i}\n" for i in range(n))
    return f"def long_one(a):\n{body}    return a\n\n\ndef short():\n    return 1\n"


def _complex_py(n):
    body = "".join(f"    if a == {i} and b or c:\n        return {i}\n" for i in range(n))
    return f"def branches(a, b, c):\n{body}    return None\n"


def _long_js(n):
    body = "".join(f"  let v{i} = {i};\n" for i in range(n))
    return f"function longOne(a) {{\n{body}  return a;\n}}\nconst arrow = (x) => {{\n  return x && x || x ? 1 : 2;\n}};\n"


def _complex_js(n):
    body = "".join(f"  if (a === {i} && b || c) {{ return {i}; }}\n" for i in range(n))
    return f"function branches(a, b, c) {{\n{body}  return null;\n}}\n"


CURATED = [
    ("app.py", PY_FLASK),
    ("db.py", PY_SQL),
    ("schema.sql", SQL_FILE),
    ("server.js", JS_EXPRESS),
    ("suppress.py", SUPPRESS),
    ("suppress.js", JS_SUPPRESS),
    ("long.py", _long_py(70)),
    ("complex.py", _complex_py(14)),
    ("long.js", _long_js(70)),
    ("complex.js", _complex_js(14)),
    ("nested.py", "def outer():\n    def inner():\n" + "".join(f"        x{i} = {i}\n" for i in range(65))
                  + "        return 1\n    return inner\n"),
    ("unclosed.js", "function open(a) {\n" + "  a++;\n" * 900 + "\n"),
    ("minified.js", "function a(b){if(b&&c){return d}for(;;){}}function e(){while(x||y){}}" * 40 + "\n"),
    ("caps.py", "".join(f"# TODO item {i}\nx{i} = 1  # {'y' * 170}\n" for i in range(230))),
    ("caps.js", "".join(f"// FIXME {i}\nconst k{i} = eval(req.query.q{i});\n" for i in range(220))),
    ("templates.py", "from jinja2 import Template\nfrom flask import request, render_template_string\n"
                     "t = request.args.get('t')\nTemplate(t)\nrender_template_string(t)\n"
                     "env.from_string(t)\njinja2.Template(t)\n"),
    ("no_template_import.py", "from string import Template\nt = input()\nTemplate(t)\n"),
    ("fastapi_app.py", "from fastapi import FastAPI, Depends\nfrom fastapi.responses import HTMLResponse\n"
                       "app = FastAPI()\n\n\n@app.get('/items/{item_id}')\ndef read(item_id: str, q: str = None, "
                       "db = Depends(get_db)):\n    os.system(q)\n    return {'q': q}\n\n\n"
                       "@app.get('/page', response_class=HTMLResponse)\ndef page(name: str):\n"
                       "    return '<p>' + name + '</p>'\n"),
    ("django_views.py", "from django.http import HttpResponse\nfrom django.shortcuts import redirect\n\n\n"
                        "def show(request, slug, pk: int):\n    return HttpResponse(slug)\n\n\n"
                        "def plain(request, name):\n    return HttpResponse(name, content_type='text/plain')\n\n\n"
                        "class V:\n    def get(self, request, tail):\n        return redirect(tail)\n"),
    ("guards.py", "import os\nBASE = '/srv'\nALLOWED = {'a', 'b'}\n\n\ndef f(request):\n"
                  "    name = request.GET.get('name')\n    if name not in ALLOWED:\n        raise ValueError\n"
                  "    os.system(name)\n    p = request.GET.get('p')\n    if not os.path.realpath(p).startswith(BASE):\n"
                  "        return None\n    open(p)\n    q = request.GET.get('q')\n    if q in ALLOWED:\n"
                  "        os.system(q)\n    os.system(q)\n    r = request.GET.get('r')\n"
                  "    if os.path.commonpath([BASE, r]) != BASE:\n        return\n    open(r)\n"),
    ("containers.py", "d = {}\nd['k'] = input()\nd['safe'] = 'fixed'\nos.system(d['safe'])\nos.system(d['k'])\n"
                      "xs = []\nxs.append(sys.argv[1])\neval(xs[0])\nys = [1]\nys += [input()]\nexec(ys)\n"),
    ("multiline.py", "import subprocess\nx = request.args.get(\n    'x'\n)\nsubprocess.run(\n    x,\n    shell=True,\n)\n"
                     "y = (\n    'a' +\n    request.form['y']\n)\nos.system(\n    y\n)\n"),
    ("strings.py", 's = """\nos.system(request.args.get("x"))\n"""\nt = \'\'\'eval(input())\'\'\'\n'
                   "u = 'request.args'\nos.system(u)\n"),
    ("unicode.py", "x = request.args.get('x')\n\uff4f\uff53.system(x)\n\u00e9 = input()\neval(\u00e9)\n"),
    ("crlf.js", "const a = req.query.a;\r\neval(a);\r\n// nosec\r\neval(a);\r\n"),
    ("reassign.py", "def f():\n    p = request.args.get('p')\n    p = secure_filename(p)\n    open(p)\n"
                    "    if cond:\n        p = request.args.get('q')\n    open(p)\n    p = 'fixed'\n    open(p)\n"),
    ("scopes.js", "function a() {\n  const x = req.query.x;\n}\nfunction b() {\n  eval(x);\n}\n"
                  "class C {\n  m(req) {\n    const y = req.body.y;\n    exec(y);\n  }\n}\n"),
]

# ---------------------------------------------------------------- the random stream
PY_SOURCES = ["request.args.get('q')", "request.args['id']", "request.form.get('name')", "request.json",
              "request.get_json()", "request.data", "request.cookies.get('s')", "request.headers['X']",
              "request.GET.get('p')", "request.POST['p']", "request.META['HTTP_X']", "request.body",
              "request.query_params['q']", "input()", "sys.argv[1]", "base64.b64decode(data)",
              "zlib.decompress(blob)", "websocket.receive_text()", "request.files['f'].filename"]
PY_SANITIZED = ["int({v})", "float({v})", "shlex.quote({v})", "html.escape({v})", "secure_filename({v})",
                "os.path.basename({v})", "url_for('x', n={v})", "escape({v})", "bleach.clean({v})",
                "request.args.get('n', 0, type=int)", "get_object_or_404(M, pk={v})", "Model.objects.filter(name={v})",
                "open({v}).read()", "jsonify({v})", "uuid.UUID({v})"]
PY_SINKS = ["os.system({x})", "os.popen({x})", "subprocess.run({x}, shell=True)", "subprocess.Popen({x})",
            "eval({x})", "exec({x})", "cursor.execute({x})", "cur.executemany({x}, rows)", "Model.objects.raw({x})",
            "qs.extra(where=[{x}])", "open({x})", "open('/tmp/f', 'w').write({x})", "send_file({x})",
            "send_from_directory({x}, name)", "send_from_directory('/srv', {x})", "shutil.rmtree({x})",
            "requests.get({x})", "requests.post(url, data={x})", "httpx.get({x})", "urlopen({x})",
            "redirect({x})", "redirect('/home/' + {x})", "HttpResponseRedirect({x})", "render_template_string({x})",
            "Template({x})", "jinja2.Template({x})", "make_response({x})", "Response({x})",
            "HttpResponse({x}, content_type='text/plain')", "Markup({x})", "mark_safe({x})",
            "asyncio.create_subprocess_shell({x})", "FileResponse({x})", "os.remove({x})", "codecs.open({x})"]
PY_WRAP = ["{v}", "f'{{{v}}}'", "'ls ' + {v}", "'%s' % {v}", "'{{}}'.format({v})", "[{v}]", "({v}, 1)",
           "str({v})", "{v}.strip()", "'x'", "f'/srv/{{{v}}}'", "rf'{{{v}}}'", "'/home/' + {v}", "{v}[0]",
           "d[{v}]", "{v}.split(',')"]
PY_IMPORTS = ["from flask import Flask, request, redirect, make_response", "import os, subprocess, sys",
              "from fastapi import FastAPI", "from django.http import HttpResponse", "from jinja2 import Template",
              "import sqlite3", "import shlex, html", "from quart import Quart"]
JS_SOURCES = ["req.query.q", "req.body.name", "req.params.id", "req.headers['x']", "req.cookies.s",
              "req.get('referer')", "req.header('host')", "request.query", "process.argv[2]", "location.search",
              "location.hash", "document.URL", "new URLSearchParams(location.search)", "atob(data)",
              "decodeURIComponent(s)", "req.originalUrl", "req.files[0]"]
JS_SANITIZED = ["parseInt({v})", "Number({v})", "escapeHtml({v})", "DOMPurify.sanitize({v})", "path.basename({v})",
                "encodeURIComponent({v})", "mysql.escape({v})", "shellQuote({v})", "fs.readFileSync({v})"]
JS_SINKS = ["exec({x})", "execSync({x})", "spawn({x})", "eval({x})", "new Function({x})", "vm.runInNewContext({x})",
            "db.query({x})", "conn.execute({x})", "knex.raw({x})", "q.whereRaw({x})", "fs.readFile({x}, cb)",
            "fs.writeFileSync({x}, data)", "fs.writeFile('/tmp/x', {x})", "res.sendFile({x})",
            "res.sendFile({x}, {{ root: dir }})", "fetch({x})", "axios.get({x})", "https.get({x})", "got({x})",
            "res.redirect({x})", "res.location({x})", "ejs.render({x})", "Handlebars.compile({x})",
            "el.innerHTML = {x}", "document.write({x})", "res.send({x})", "res.status(200).send({x})",
            "res.type('json').send({x})", "res.set('Content-Type', 'text/plain').end({x})", "res.write({x})"]
JS_WRAP = ["{v}", "`ls ${{{v}}}`", "sql`select ${{{v}}}`", "'a' + {v}", "[{v}]", "{{ k: {v} }}", "String({v})",
           "{v}.trim()", "'fixed'", "{v}.slice(1)", "names[{v}]", "`${{{v}}}/x`", "html`<p>${{{v}}}</p>`"]
VARS = ["x", "q", "name", "path", "cmd", "url", "data", "target", "sql", "body", "page", "user_id", "d", "xs"]
MARKERS = ["", "", "", "", "  # nosec", "  # lazaret-ignore: T-CMD", "  # lazaret-ignore: T-PATH, T-SQL",
           "  # NOSONAR", "  # lazaret-ignore", "  # TODO"]
JS_MARKERS = ["", "", "", "", " // nosec", " // lazaret-ignore: T-CODE", " // NOSONAR", " /* nosec */",
              " // lazaret-ignore: T-XSS", " // FIXME"]


def _py_program(rnd):
    lines, ind = [], 0
    for imp in rnd.sample(PY_IMPORTS, rnd.randint(0, 3)):
        lines.append(imp)
    for _ in range(rnd.randint(3, 40)):
        pad = " " * ind
        v = rnd.choice(VARS)
        kind = rnd.random()
        if kind < 0.07 and ind < 12:
            if rnd.random() < 0.5:
                lines.append(f"{pad}@app.{rnd.choice(['route', 'get', 'post'])}('/{v}/<{rnd.choice(VARS)}>')")
            params = ", ".join(rnd.sample(VARS, rnd.randint(0, 3)))
            lines.append(f"{pad}{rnd.choice(['def', 'async def'])} f{len(lines)}({rnd.choice(['', 'request, ', 'self, request, '])}{params}):")
            ind += 4
        elif kind < 0.11 and ind < 12:
            head = rnd.choice(["if", "elif", "while", "for _ in", "with"])
            cond = rnd.choice([v, repr(v) + " in ALLOWED", v + " not in ALLOWED", '".." in ' + v,
                               "not " + v + ".startswith(BASE)"])
            lines.append(pad + head + " " + cond + ":")
            ind += 4
            if rnd.random() < 0.4:
                lines.append(" " * ind + rnd.choice(["return", "abort(400)", "raise ValueError", "continue", "pass"]))
        elif kind < 0.16 and ind:
            ind -= 4
        elif kind < 0.45:
            src = rnd.choice([rnd.choice(PY_SOURCES), rnd.choice(VARS), rnd.choice(PY_SANITIZED).format(v=rnd.choice(VARS))])
            rhs = rnd.choice(PY_WRAP).format(v=src)
            form = rnd.choice(["{v} = {r}", "{v}: str = {r}", "{v} += {r}", "{v}['k'] = {r}", "{v}.append({r})",
                               "{v} = (\n" + pad + "    {r}\n" + pad + ")"])
            lines.append(pad + form.format(v=v, r=rhs) + rnd.choice(MARKERS))
        elif kind < 0.8:
            arg = rnd.choice(PY_WRAP).format(v=rnd.choice([rnd.choice(VARS), rnd.choice(PY_SOURCES)]))
            lines.append(pad + rnd.choice(PY_SINKS).format(x=arg) + rnd.choice(MARKERS))
        elif kind < 0.86:
            lines.append(pad + f"return {rnd.choice(PY_WRAP).format(v=rnd.choice(VARS))}")
        elif kind < 0.9:
            lines.append(pad + rnd.choice(["# a comment", "# nosec", "# lazaret-ignore: T-CMD", "'''doc'''",
                                           '"""request.args"""', "# request.args.get('x')"]))
        elif kind < 0.94:
            lines.append(pad + rnd.choice(["sql = 'SELECT * FROM t WHERE a = %s'", "q = 'SELECT {}'",
                                           f"cur.execute(sql % {v})", f"cur.execute(q.format({v}))",
                                           f"cur.execute('SELECT ' + {v})", f"cur.execute(sql, ({v},))",
                                           f"cur.execute(f'SELECT {{{v}}}')", "cur.execute(sql)"]))
        else:
            lines.append("")
    return "\n".join(lines) + rnd.choice(["\n", "", "\n\n"])


def _js_program(rnd):
    lines, depth = [], 0
    for _ in range(rnd.randint(3, 40)):
        pad = "  " * depth
        v = rnd.choice(VARS)
        kind = rnd.random()
        if kind < 0.08 and depth < 6:
            lines.append(pad + rnd.choice(["function f(req, res) {", "app.get('/x', (req, res) => {",
                                           "router.post('/y', async function (req, res) {", "const g = (a) => {",
                                           "m(req) {", "if (" + v + ".includes('..')) {",
                                           "if (!allowed.includes(" + v + ")) {", "for (const k of xs) {",
                                           "try {"]))
            depth += 1
            if rnd.random() < 0.3:
                lines.append("  " * depth + rnd.choice(["return;", "return next(err);", "throw new Error('x');"]))
        elif kind < 0.14 and depth:
            depth -= 1
            lines.append("  " * depth + rnd.choice(["}", "});", "} catch (e) {}", "};"]))
        elif kind < 0.45:
            src = rnd.choice([rnd.choice(JS_SOURCES), rnd.choice(VARS), rnd.choice(JS_SANITIZED).format(v=rnd.choice(VARS))])
            rhs = rnd.choice(JS_WRAP).format(v=src)
            form = rnd.choice(["const {v} = {r};", "let {v} = {r};", "{v} = {r};", "{v} += {r};", "{v}['k'] = {r};",
                               "{v}.push({r});", "const {{ {v}, ...rest }} = {r};", "var [{v}] = {r};",
                               "const {v} =\n" + pad + "  {r};"])
            lines.append(pad + form.format(v=v, r=rhs) + rnd.choice(JS_MARKERS))
        elif kind < 0.85:
            arg = rnd.choice(JS_WRAP).format(v=rnd.choice([rnd.choice(VARS), rnd.choice(JS_SOURCES)]))
            lines.append(pad + rnd.choice(JS_SINKS).format(x=arg) + ";" + rnd.choice(JS_MARKERS))
        elif kind < 0.92:
            lines.append(pad + rnd.choice(["// a comment", "// nosec", "/* req.query */", "// lazaret-ignore: T-CMD",
                                           "const s = '// nosec';", "`multi", "line ${x}`;"]))
        else:
            lines.append("")
    lines += ["}"] * depth
    return "\n".join(lines) + rnd.choice(["\n", "", "\r\n"])


def _sql_program(rnd):
    stmts = ["DELETE FROM t;", "DELETE FROM t WHERE id = 1;", "UPDATE t SET a = 1;", "UPDATE t SET a = 1 WHERE b;",
             "delete from logs", "-- nosec", "-- DELETE FROM x;", "/* UPDATE y SET z = 1; */", "SELECT * FROM t;",
             "UPDATE \"s\".\"t\" SET a = 1;", "DELETE FROM a WHERE x IN (SELECT 1); DELETE FROM b;", ";",
             "GRANT ALL ON *.* TO 'u'@'%';", "CREATE TABLE t (id INT);", "update t set a = 1 -- nosec"]
    return "\n".join(rnd.choice(stmts) for _ in range(rnd.randint(1, 12))) + "\n"


def corpus(seed=20261007, scale=1):
    """(path, text) cases: CURATED, then random programs in Python,
    JavaScript and SQL."""
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(1500 * scale):
        k = rnd.random()
        if k < 0.5:
            cases.append((rnd.choice(["x.py", "views.py", "app.py"]), _py_program(rnd)))
        elif k < 0.92:
            cases.append((rnd.choice(["x.js", "server.js", "x.ts", "x.jsx", "x.mjs"]), _js_program(rnd)))
        else:
            cases.append(("x.sql", _sql_program(rnd)))
    return cases
