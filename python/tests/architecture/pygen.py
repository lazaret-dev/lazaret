"""Seeded random Python projects for the engine's tests of the cross-file
Python taint pass (`py_flow`).

Every program is valid Python 3.13 (the parser must accept it) and built
from the shapes the pass follows: modules in packages importing each other
(absolute, relative, aliased, star imports, re-exports), functions of every
signature (positional-only, defaults, *args, keyword-only, **kwargs),
classes (bases, constructors, self attributes, static and class methods,
super()), Flask, FastAPI and Django route handlers, request data and
sys.argv, sinks of every category, sanitizers, guards (path checks,
allowlists), locals, branches, loops, with, try, match, comprehensions,
f-strings, walrus, lambdas, yields and module globals. The same seed gives
the same project (random.Random only).

Inert text only: nothing here is executed.
"""
import random

SOURCES = ["request.args.get('q')", "request.form['name']", "request.values.get('v')", "request.json",
           "request.get_json()", "request.cookies.get('sid')", "request.headers['X-Id']", "sys.argv[1]", "input()",
           "request.GET.get('p')", "request.POST['f']", "request.query_params['x']", "flask.request.args['a']",
           "websocket.receive_text()", "request.data", "request.files['up'].filename"]
SINKS = ["os.system({})", "os.popen('ls ' + {})", "subprocess.run({}, shell=True)", "subprocess.check_output(['sh', '-c', {}])",
         "cur.execute('SELECT * FROM t WHERE a = ' + {})", "cur.execute('SELECT ?', ({},))",
         "cursor.executemany({}, rows)", "conn.execute(f'DELETE FROM t WHERE id = {{ {} }}')",
         "User.objects.raw({})", "eval({})", "exec({})", "open({})", "open(os.path.join(BASE, {}))",
         "send_file({})", "shutil.rmtree({})", "os.remove({})", "requests.get({})",
         "requests.post('https://api.example.com/x', data={})", "httpx.get({})", "urlopen({})",
         "redirect({})", "HttpResponseRedirect({})", "make_response({})", "HttpResponse({})", "Markup({})",
         "mark_safe({})", "render_template_string({})", "jinja2.Template({})", "env.from_string({})",
         "asyncio.create_subprocess_shell({})", "sp.run({}, shell=True)", "check_output({})"]
SANITIZERS = ["int({})", "float({})", "shlex.quote({})", "html.escape({})", "escape({})", "os.path.basename({})",
              "secure_filename({})", "bleach.clean({})", "str({})", "len({})", "({}).strip()", "({}).lower()",
              "uuid.UUID({})", "url_for('x', v={})", "json.dumps({})", "escape_html({})", "({}).startswith('x')",
              "isinstance({}, str)", "hashlib.sha256({}).hexdigest()", "select(Model).where(Model.a == {})",
              "get_object_or_404(Model, pk={})"]
STDLIB = ["import os", "import sys", "import subprocess", "import subprocess as sp", "import shlex", "import html",
          "import json", "import shutil", "import sqlite3", "import requests", "import httpx", "import hashlib",
          "import uuid", "import asyncio", "import jinja2", "from urllib.request import urlopen",
          "from subprocess import check_output", "from markupsafe import Markup, escape",
          "from werkzeug.utils import secure_filename", "import bleach"]
FRAMEWORK = {
    "flask": ["from flask import Flask, request, redirect, make_response, render_template_string, send_file, abort",
              "import flask"],
    "fastapi": ["from fastapi import FastAPI, APIRouter, Depends, Query, Request",
                "from typing import Annotated, Optional"],
    "django": ["from django.http import HttpResponse, HttpResponseRedirect",
               "from django.shortcuts import get_object_or_404", "from django.utils.safestring import mark_safe"],
}
PATHS = ["app/__init__.py", "app/views.py", "app/util.py", "app/models.py", "lib/db.py", "lib/run.py",
         "lib/__init__.py", "main.py", "cli.py", "app/api/routes.py", "app/api/__init__.py", "helpers.py",
         "app/services/files.py", "app/services/__init__.py", "src/pkg/core.py", "src/pkg/__init__.py"]


def modname(path):
    stem = path[:-3]
    if stem.endswith("/__init__"):
        stem = stem[: -len("/__init__")]
    return stem.replace("/", ".")


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.n = 0
        self.funcs = []           # module-level functions visible to call: (module, name, nparams)
        self.methods = []         # method names
        self.classes = []         # class names

    def pick(self, seq):
        return seq[self.r.randrange(len(seq))]

    def chance(self, p):
        return self.r.random() < p

    def fresh(self, base="v"):
        self.n += 1
        return f"{base}{self.n}"

    # ---- expressions ----
    def value(self, names, depth=0, local_funcs=()):
        k = self.r.randrange(16 if depth < 3 else 4)
        if k == 0 or not names:
            if self.chance(0.6):
                return self.pick(SOURCES)
            return self.pick(["'lit'", "42", "None", "b'x'", "3.5", "BASE", "CONFIG['k']", "True", "...", "2j"])
        if k in (1, 2):
            return self.pick(names)
        if k == 3:
            return self.pick(SANITIZERS).format(self.value(names, depth + 1, local_funcs))
        if k == 4:
            return f"{self.value(names, depth + 1, local_funcs)} + {self.value(names, depth + 1, local_funcs)}"
        if k == 5:
            return f"f'pre {{ {self.value(names, depth + 1, local_funcs)} }} post'"
        if k == 6:
            pool = list(local_funcs) + [f for _m, f, _n in self.funcs]
            if pool:
                f = self.pick(pool)
                args = ", ".join(self.value(names, depth + 1, local_funcs) for _ in range(self.r.randrange(3)))
                if self.chance(0.2):
                    args = (args + ", " if args else "") + f"k={self.value(names, depth + 1, local_funcs)}"
                if self.chance(0.1):
                    args = (args + ", " if args else "") + f"*{self.pick(names)}"
                if self.chance(0.1):
                    args = (args + ", " if args else "") + f"**{self.pick(names)}"
                return f"{f}({args})"
            return self.pick(names)
        if k == 7:
            return f"{self.value(names, depth + 1, local_funcs)} or {self.value(names, depth + 1, local_funcs)}"
        if k == 8:
            a, b, c = (self.value(names, depth + 1, local_funcs) for _ in range(3))
            return f"({a} if {b} else {c})"
        if k == 9:
            return f"[{self.value(names, depth + 1, local_funcs)}, 1]"
        if k == 10:
            return f"{{'a': {self.value(names, depth + 1, local_funcs)}, **{self.pick(names)}}}"
        if k == 11:
            return f"[x for x in {self.value(names, depth + 1, local_funcs)} if x]"
        if k == 12 and self.methods:
            recv = self.pick(names + ["self.helper", "obj", "self", "cls_inst"])
            return f"{recv}.{self.pick(self.methods)}({self.value(names, depth + 1, local_funcs)})"
        if k == 13:
            return f"'%s-%s' % ({self.value(names, depth + 1, local_funcs)}, 1)"
        if k == 14:
            return f"{self.pick(names)}[{self.value(names, depth + 1, local_funcs)}]"
        return f"(lambda z: {self.value(names + ['z'], depth + 1, local_funcs)})"

    # ---- statements ----
    def block(self, names, depth, out, indent, local_funcs=(), in_loop=False):
        before = len(out)
        for _ in range(self.r.randint(1, 4 if depth < 2 else 2)):
            self.stmt(names, depth, out, indent, local_funcs, in_loop)
        if len(out) == before:
            out.append("    " * indent + "pass")

    def stmt(self, names, depth, out, indent, local_funcs=(), in_loop=False):
        pad = "    " * indent
        k = self.r.randrange(22 if depth < 3 else 10)
        v = lambda: self.value(names, 0, local_funcs)  # noqa: E731
        if k in (0, 1):
            n = self.fresh()
            out.append(f"{pad}{n} = {v()}")
            names.append(n)
        elif k == 2:
            out.append(f"{pad}{self.pick(SINKS).format(v())}")
        elif k == 3:
            out.append(f"{pad}return {v()}")
        elif k == 4:
            n = self.pick(names) if names else self.fresh()
            out.append(f"{pad}{n} += {v()}")
        elif k == 5:
            a, b = self.fresh(), self.fresh()
            out.append(f"{pad}{a}, {b} = {v()}, {v()}")
            names += [a, b]
        elif k == 6:
            n = self.fresh()
            out.append(f"{pad}{n}: str = {v()}")
            names.append(n)
        elif k == 7:
            out.append(f"{pad}self.{self.pick(['data', 'cmd', 'path', 'q'])} = {v()}")
        elif k == 8:
            out.append(f"{pad}yield {v()}")
        elif k == 9:
            out.append(f"{pad}print({v()})")
        elif k == 10:
            target = self.pick(names) if names else "x"
            guard = self.pick([f"{target}.startswith(BASE)", f"not {target}.startswith(BASE)",
                               f"{target} in ALLOWED", f"{target} not in ALLOWED", f"'..' in {target}",
                               f"'..' not in {target}", f"os.path.realpath({target}).startswith(BASE)",
                               f"{target}.is_relative_to(BASE)", f"{v()}", f"not {target}"])
            out.append(f"{pad}if {guard}:")
            self.block(names, depth + 1, out, indent + 1, local_funcs, in_loop)
            if self.chance(0.3):
                out.append(f"{pad}    {self.pick(['return', 'abort(400)', 'raise ValueError()', 'sys.exit(1)'])}")
            if self.chance(0.4):
                out.append(f"{pad}else:")
                self.block(names, depth + 1, out, indent + 1, local_funcs, in_loop)
        elif k == 11:
            it = self.fresh("it")
            out.append(f"{pad}for {it} in {v()}:")
            self.block(names + [it], depth + 1, out, indent + 1, local_funcs, True)
        elif k == 12:
            out.append(f"{pad}while {v()}:")
            self.block(names, depth + 1, out, indent + 1, local_funcs, True)
            out.append(f"{pad}    break")
        elif k == 13:
            n = self.fresh("fh")
            out.append(f"{pad}with open({v()}) as {n}:")
            self.block(names + [n], depth + 1, out, indent + 1, local_funcs, in_loop)
        elif k == 14:
            out.append(f"{pad}try:")
            self.block(names, depth + 1, out, indent + 1, local_funcs, in_loop)
            out.append(f"{pad}except Exception as err:")
            self.block(names + ["err"], depth + 1, out, indent + 1, local_funcs, in_loop)
            if self.chance(0.3):
                out.append(f"{pad}else:")
                self.block(names, depth + 1, out, indent + 1, local_funcs, in_loop)
            if self.chance(0.3):
                out.append(f"{pad}finally:")
                self.block(names, depth + 1, out, indent + 1, local_funcs, in_loop)
        elif k == 15:
            out.append(f"{pad}match {v()}:")
            out.append(f"{pad}    case {{'k': kv, **rest}}:")
            self.block(names + ["kv", "rest"], depth + 2, out, indent + 2, local_funcs, in_loop)
            out.append(f"{pad}    case [first, *others] if first:")
            self.block(names + ["first", "others"], depth + 2, out, indent + 2, local_funcs, in_loop)
            out.append(f"{pad}    case Point(x=px) | str(px):")
            self.block(names + ["px"], depth + 2, out, indent + 2, local_funcs, in_loop)
            out.append(f"{pad}    case _:")
            out.append(f"{pad}        pass")
        elif k == 16:
            n = self.fresh("w")
            out.append(f"{pad}if ({n} := {v()}):")
            self.block(names + [n], depth + 1, out, indent + 1, local_funcs, in_loop)
            names.append(n)
        elif k == 17:
            f = self.fresh("inner")
            p = self.fresh("p")
            out.append(f"{pad}def {f}({p}):")
            self.block([p] + names, depth + 1, out, indent + 1, local_funcs, False)
            local_funcs = list(local_funcs) + [f]
            out.append(f"{pad}{self.fresh()} = {f}({v()})")
        elif k == 18:
            n = self.fresh("d")
            out.append(f"{pad}{n} = {{}}")
            out.append(f"{pad}{n}['k'] = {v()}")
            names.append(n)
        elif k == 19:
            out.append(f"{pad}assert {v()}, {v()}")
        elif k == 20 and in_loop:
            out.append(f"{pad}continue")
        else:
            out.append(f"{pad}raise RuntimeError({v()})")

    # ---- definitions ----
    def signature(self):
        params = [self.fresh("a") for _ in range(self.r.randint(0, 3))]
        parts = list(params)
        if params and self.chance(0.15):
            parts.insert(1, "/")
        if self.chance(0.3):
            d = self.fresh("o")
            parts.append(f"{d}={self.pick(['None', '1', repr('x')])}")
            params.append(d)
        if self.chance(0.2):
            star = self.fresh("rest")
            parts.append(f"*{star}")
            params.append(star)
            if self.chance(0.5):
                kw = self.fresh("kw")
                parts.append(f"{kw}=None")
                params.append(kw)
        elif self.chance(0.1):
            kw = self.fresh("kw")
            parts.append(f"*, {kw}")
            params.append(kw)
        if self.chance(0.15):
            kwa = self.fresh("kwargs")
            parts.append(f"**{kwa}")
            params.append(kwa)
        return params, ", ".join(parts)

    def function(self, out, indent=0, method=False, module=""):
        pad = "    " * indent
        name = self.fresh("method_" if method else "fn_")
        params, sig = self.signature()
        if method:
            kind = self.pick(["self", "self", "self", "static", "cls"])
            if kind == "static":
                out.append(f"{pad}@staticmethod")
            elif kind == "cls":
                out.append(f"{pad}@classmethod")
            if kind != "static":
                sig = (kind if kind == "self" else "cls") + (", " + sig if sig else "")
                if "/" in sig.split(", ")[1:2]:
                    sig = sig.replace(", /", "", 1)
            self.methods.append(name)
        if self.chance(0.1):
            out.append(f"{pad}@functools.lru_cache")
        out.append(f"{pad}{'async ' if self.chance(0.1) else ''}def {name}({sig}):")
        self.block(list(params), 0, out, indent + 1)
        if not method:
            self.funcs.append((module, name, len(params)))
        return name

    def route(self, out, fw):
        name = self.fresh("view_")
        if fw == "flask":
            conv = self.pick(["", "int:", "path:", "uuid:", "string:"])
            var = self.fresh("arg")
            out.append(f"@app.route('/p/<{conv}{var}>', methods=['GET', 'POST'])")
            out.append(f"def {name}({var}):")
            self.block([var], 0, out, 1)
        elif fw == "fastapi":
            dec = self.pick(["app.get", "router.post", "app.api_route", "router.websocket"])
            p1, p2, p3 = self.fresh("q"), self.fresh("n"), self.fresh("db")
            ann = self.pick(["str", "int", "Optional[str]", "Annotated[str, Query()]", "list[int]", "UUID", "str | None",
                             "Kind"])
            dflt = self.pick(["None", "Query(None)", "Kind.a", "'x'"])
            out.append(f"@{dec}('/items/{{{p2}}}')")
            out.append(f"async def {name}({p1}: {ann} = {dflt}, {p2}: int = 0, {p3}: Session = Depends(get_db), "
                       f"request: Request = None):")
            self.block([p1, p2, p3, "request"], 0, out, 1)
        else:
            p1, p2 = self.fresh("slug"), self.pick(["pk", "name", "user_id", "q"])
            out.append(f"def {name}(request, {p1}, {p2}: str = ''):")
            self.block(["request", p1, p2], 0, out, 1)
        return name

    def klass(self, out, module):
        name = self.fresh("C")
        base = self.pick(["", "(object)", "(Base)"] + [f"({c})" for c in self.classes[-2:]])
        out.append(f"class {name}{base}:")
        params, sig = self.signature()
        out.append(f"    def __init__(self{', ' + sig if sig else ''}):")
        if base not in ("", "(object)") and self.chance(0.5):
            out.append("        super().__init__()")
        for p in params[:2]:
            out.append(f"        self.{self.pick(['data', 'cmd', 'path', 'q'])} = {p}")
        out.append("        pass")
        for _ in range(self.r.randint(1, 3)):
            self.function(out, 1, True, module)
        self.classes.append(name)
        return name

    def module(self, path, modules, fw):
        out = []
        mod = modname(path)
        for imp in self.r.sample(STDLIB, self.r.randint(2, 6)):
            out.append(imp)
        out.append("import functools")
        for line in FRAMEWORK.get(fw, []):
            out.append(line)
        others = [m for m in modules if m != path]
        for other in self.r.sample(others, min(len(others), self.r.randint(0, 3))):
            om = modname(other)
            names = [f for m, f, _ in self.funcs if m == om] + [c for c in self.classes]
            style = self.r.randrange(5)
            if style == 0 and names:
                out.append(f"from {om} import {', '.join(self.r.sample(names, min(2, len(names))))}")
            elif style == 1:
                out.append(f"import {om}")
            elif style == 2 and names:
                out.append(f"from {om} import {self.pick(names)} as {self.fresh('alias')}")
            elif style == 3:
                out.append(f"from {om} import *")
            elif names and "/" in path and other.rsplit('/', 1)[0] == path.rsplit('/', 1)[0]:
                out.append(f"from .{om.rsplit('.', 1)[-1]} import {self.pick(names)}")
        out.append("BASE = '/srv/data'")
        out.append("ALLOWED = {'a', 'b'}")
        out.append("CONFIG = {'k': 'v'}")
        if fw == "flask":
            out.append("app = Flask(__name__)")
        elif fw == "fastapi":
            out.append("app = FastAPI()")
            out.append("router = APIRouter()")
            out.append("SessionDep = Annotated[Session, Depends(get_db)]")
        if self.chance(0.3):
            out.append(f"GLOBAL_{self.n} = {self.pick(SOURCES)}")
        for _ in range(self.r.randint(1, 4)):
            k = self.r.randrange(5)
            if k in (0, 1):
                self.function(out, 0, False, mod)
            elif k == 2:
                self.klass(out, mod)
            elif fw:
                self.route(out, fw)
            else:
                self.function(out, 0, False, mod)
            out.append("")
        if self.chance(0.4):
            out.append("if __name__ == '__main__':")
            self.block(["BASE"], 0, out, 1)
        return "\n".join(out) + "\n"


def projects(seed, count):
    """`count` projects of 2 to 6 modules each: [{"path", "content"}]."""
    out = []
    r = random.Random(seed)
    for k in range(count):
        g = Gen(r.randrange(1 << 30))
        paths = r.sample(PATHS, r.randint(2, 6))
        fw = r.choice(["flask", "fastapi", "django", "", ""])
        files = []
        for path in paths:
            files.append({"path": path, "content": g.module(path, paths, fw if r.random() < 0.7 else "")})
        out.append(files)
    return out
