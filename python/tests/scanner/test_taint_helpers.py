"""Q-4 (0.1.9): the intra-file taint pass follows a call into the helper it names.

BenchmarkPython's cases (scanned and scored, their sources never read: the project's licence rule) read the request
parameter through a method of a helper object given a string (`param = x.y('...')`): 28 real ones whose method returns
the request's data, which the pass, reading the call as text, missed. Now a helper (a module-level function, a method
of a class) defined in the file, or in another file of the project, that returns untrusted data of its own (it reads
the request) gets a summary — the categories what it returns is clean for — and its calls carry that data too:
`f()`, `mod.f()`, `self.m()`, `x.m()` with `x = C(...)` in the same function, `C(...).m()`, `C.m()`.

Following only adds (reworked after two independent reviews): the call's text is read as before, and what the helper
returns is added to it; nothing the text carries is ever taken away, so a helper returning a constant does not clear
what it was given (KEPT, PROJECT_KEPT: each reported before Q-4, and lost by one of its earlier versions). A call the
pass cannot name, and a helper returning no untrusted data of its own, are read as text, as before.

The work is bounded: a chain of helpers is followed six deep, recursion is read as text where it recurses, and a
file's helpers are read for at most a few times its lines. The pass is the engine's, so the npm package answers the
same (js/test/taint-helpers.test.js, and the parity tree of tests/architecture/test_js_parity_taint.py). All content
is inert: nothing is run, the hosts are .invalid.
"""
import os
import tempfile
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

FLASK = "from flask import Flask, request\nimport os, html, subprocess\napp = Flask(__name__)\n"
# a helper object holding the request: three of its methods read the request, one returns a constant
WRAPPER = ("class Wrapper:\n"
           "    def __init__(self, request):\n"
           "        self.request = request\n"
           "    def get_param(self, name):\n"
           "        return self.request.args.get(name)\n"
           "    def get_header(self, name):\n"
           "        value = self.request.headers.get(name, '')\n"
           "        return value.strip()\n"
           "    def get_value(self, name):\n"
           "        return 'bar'\n"
           "    def echo(self, text):\n"
           "        return text\n"
           "    @staticmethod\n"
           "    def plain(text):\n"
           "        return text.upper()\n"
           "    @classmethod\n"
           "    def make(cls, request):\n"
           "        return cls(request)\n")
HELPERS = ("def passthru(x, suffix=''):\n    return x.strip() + suffix\n"
           "def constant(x):\n    return 'safe'\n"
           "def number(x):\n    return int(x)\n"
           "def escaped(x):\n    return html.escape(x)\n"
           "def read_param():\n    return request.args.get('p')\n"
           "def one_line(x): return x\n"
           "def first(a, *rest, **kw):\n    return rest\n"
           "def named(a, b=None, **kw):\n    return kw\n")


def view(body):
    """A Flask view of `body` (its lines indented), after the helpers."""
    return FLASK + WRAPPER + HELPERS + "@app.route('/a')\ndef a():\n" + "".join("    " + ln + "\n" for ln in body)


def marked(src):
    """The lines marked `# !` (1-based)."""
    return [k + 1 for k, ln in enumerate(src.split("\n")) if ln.rstrip().endswith("# !")]


def case(body, rule):
    src = view(body)
    return ("py", src, {(rule, n) for n in marked(src)})


# (lang, source, {(rule, line)}): the T-* findings
REPORTED = [
    # a method that reads the request, on an instance made in the same function
    case(["w = Wrapper(request)", "param = w.get_param('id')", "os.system('ls ' + param)  # !"], "T-CMD"),
    case(["w = Wrapper(request)", "param = w.get_header('X-Id')", "subprocess.run(param, shell=True)  # !"], "T-CMD"),
    # on an instance made in place, and in a sink's own arguments
    case(["param = Wrapper(request).get_param('id')", "os.system(param)  # !"], "T-CMD"),
    case(["w = Wrapper(request)", "os.system(w.get_param('id'))  # !"], "T-CMD"),
    # a function that reads the request
    case(["v = read_param()", "os.system(v)  # !"], "T-CMD"),
    # what a helper is given and returns without a sanitizer
    case(["v = passthru(request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["v = passthru('x', suffix=request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["v = one_line(request.form['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["w = Wrapper(request)", "v = w.echo(request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["v = Wrapper.plain(request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["v = first('a', request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["v = named('a', other=request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    case(["args = [request.args['q']]", "v = first('a', *args)", "os.system(v)  # !"], "T-CMD"),
    # escaped for HTML is not escaped for a shell
    case(["v = escaped(request.args['q'])", "os.system(v)  # !"], "T-CMD"),
    # nested calls of helpers
    case(["w = Wrapper(request)", "v = passthru(w.get_param('id'))", "os.system(v)  # !"], "T-CMD"),
    case(["v = str(read_param())", "os.system(v)  # !"], "T-CMD"),
    # a method through self, in the helper's own class
    ("py", FLASK + "class Page:\n    def __init__(self, request):\n        self.request = request\n"
                   "    def q(self):\n        return self.request.args['q']\n"
                   "    def run(self):\n        os.system(self.q())\n", {("T-CMD", 10)}),
    # a chain of helpers six deep
    ("py", FLASK + "".join(f"def h{k}():\n    return h{k + 1}()\n" for k in range(5))
     + "def h5():\n    return request.args['q']\n@app.route('/c')\ndef c():\n    os.system(h0())\n", {("T-CMD", 18)}),
    # recursion: the call that recurses is read as text
    ("py", FLASK + "def r(x, n):\n    if n:\n        return r(x, n - 1)\n    return x\n"
                   "@app.route('/r')\ndef rr():\n    os.system(r(request.args['q'], 3))\n", {("T-CMD", 10)}),
    ("py", FLASK + "def ping(x, n):\n    return pong(x, n - 1) if n else x\ndef pong(x, n):\n    return ping(x, n)\n"
                   "@app.route('/p')\ndef pp():\n    os.system(pong(request.args['q'], 2))\n", {("T-CMD", 10)}),
]

QUIET = [
    # nothing the call's text carries, and a helper that returns no untrusted data of its own: nothing is added
    ("py", view(["w = Wrapper(request)", "param = w.get_value('id')", "os.system('ls ' + param)"])),
    ("py", view(["param = Wrapper(request).get_value('id')", "os.system(param)"])),
    ("py", view(["v = passthru('x')", "os.system(v)"])),
    ("py", view(["w = Wrapper(request)", "v = w.echo('safe')", "os.system(v)"])),
    # a call named like a sanitizer stays one
    ("py", view(["v = escaped(request.args['q'])", "return '<p>' + v"])),
]

# (following only adds) each reported before Q-4, the call read as text: (helpers, the view's lines)
Q = "request.args['q']"
KEPT_TEXT = [  # what a helper returns, however it is written, never takes from what its call's text carries
    (WRAPPER, ["w = Wrapper(request.args)", "param = w.get_value('id')", "os.system(param)  # !"]),
    (HELPERS, ["v = constant(request.args['q'])", "os.system(v)  # !"]),
    (HELPERS, ["v = number(request.args['q'])", "os.system('kill ' + str(v))  # !"]),
    (HELPERS, ["v = named(request.args['q'], b=request.args['r'])", "os.system(v)  # !"]),
    (WRAPPER, ["w = Wrapper(request.args)", "v = w.echo('safe')", "os.system(v)  # !"]),
]
INCOMPLETE = [  # a helper whose body a summary does not model (lost by the first version, 49918e8)
    ("def gen(p):\n    for x in p:\n        yield x\n", [f"os.system(''.join(gen({Q})))  # !"]),
    ("def gen(p):\n    yield from p.split(',')\n", [f"for v in gen({Q}):", "    os.system(v)  # !"]),
    ("async def agen(p):\n    yield p\n", [f"os.system(agen({Q}))  # !"]),
    ("def pick(p):\n    if p: return p\n    return 'g'\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    try: return p.strip()\n    except AttributeError: return ''\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    for x in p.split(','): return x\n    return ''\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    with lock: return p\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    k, v = p.split('=', 1)\n    return v\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    if (v := p.strip()):\n        return v\n    return ''\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    with ctx(p) as v:\n        return v\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    try:\n        return int(p)\n    except ValueError as e:\n        return str(e)\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    match p:\n        case str():\n            return p\n    return ''\n", [f"os.system(pick({Q}))  # !"]),
    ("def pick(p):\n    def inner():\n        return p\n    return inner()\n", [f"os.system(pick({Q}))  # !"]),
    ("class W:\n    def set(self, p):\n        self.v = p\n        return self.v\n", [f"os.system(W().set({Q}))  # !"]),
    ("def pick(p):\n    o = Box()\n    setattr(o, 'v', p)\n    return o.v\n", [f"os.system(pick({Q}))  # !"]),
    ("class B:\n    def get(self, p):\n        return p\nclass S(B):\n    def get(self, p):\n        return super().get(p)\n",
     [f"os.system(S().get({Q}))  # !"]),
]
BASE_SUB = ("class Base:\n    def __init__(self, p):\n        self.p = p\n    def get(self):\n        return self.p\n"
            "class Sub(Base):\n    def get(self):\n        return 'const'\n")
PICK = "def pick(p):\n    return 'x'\n"
UNSOUND = [  # a call that may reach another definition (lost by 49918e8)
    (BASE_SUB, ["if request.args.get('m'):", f"    x = Base({Q})", "else:", f"    x = Sub({Q})", "os.system(x.get())  # !"]),
    (BASE_SUB, [f"x = Sub({Q})", "for k in range(2):", f"    x = Base({Q})", "os.system(x.get())  # !"]),
    (BASE_SUB, [f"x = Sub({Q})", f"with Base({Q}) as x:", "    os.system(x.get())  # !"]),
    (BASE_SUB, [f"x = Sub({Q})", f"if (x := Base({Q})):", "    os.system(x.get())  # !"]),
    (BASE_SUB, [f"x = Sub({Q})", f"x, y = Base({Q}), 1", "os.system(x.get())  # !"]),
    (BASE_SUB, [f"x = Sub({Q})", "x.get = lambda: x.p", "os.system(x.get())  # !"]),
    ("class T:\n    def run(self, p):\n        return 'x'\n    def go(self, p):\n        return self.run(p)\n"
     "class U(T):\n    def run(self, p):\n        return p\n", [f"os.system(U().go({Q}))  # !"]),
    ("class K:\n    def get(self, p):\n        return 'x'\nK.get = lambda self, p: p\n", [f"os.system(K().get({Q}))  # !"]),
    (PICK + "def ident(p):\n    return p\npick = ident\n", [f"os.system(pick({Q}))  # !"]),
    (PICK + "pick = lambda p: p\n", [f"os.system(pick({Q}))  # !"]),
    (PICK + "from helpers import pick\n", [f"os.system(pick({Q}))  # !"]),
    ("try:\n    from fast import pick\nexcept ImportError:\n    def pick(p):\n        return 'x'\n", [f"os.system(pick({Q}))  # !"]),
    (PICK + "from helpers import *\n", [f"os.system(pick({Q}))  # !"]),
    (PICK, ["pick = lambda p: p", f"os.system(pick({Q}))  # !"]),
    (PICK, ["from shlex import quote as pick", f"os.system(pick({Q}))  # !"]),
    (PICK + "@app.route('/b')\ndef b(pick):\n    os.system(pick(request.args['q']))  # !\n", ["return 'ok'"]),
    ("def wrap(f):\n    return lambda p: p\n@wrap\n" + PICK, [f"os.system(pick({Q}))  # !"]),
    ("import functools\n@functools.singledispatch\n" + PICK, [f"os.system(pick({Q}))  # !"]),
    ("import functools\nclass K:\n    @functools.singledispatchmethod\n    def get(self, p):\n        return 'x'\n",
     [f"os.system(K().get({Q}))  # !"]),
]


STATE = [  # what the helper reads beside its parameters, a class or instance changed (lost by 1caec6f)
    ("CONFIG = {'cmd': 'ls'}\ndef current(p):\n    return CONFIG['cmd']\n", [f"CONFIG['cmd'] = {Q}", f"os.system(current({Q}))  # !"]),
    ("LAST = 'ls'\ndef current(p):\n    return LAST\n", [f"os.system(current({Q}))  # !"]),
    ("import sys\nARG = sys.argv[1]\ndef target(p, d=ARG):\n    return d\n", [f"os.system(target({Q}))  # !"]),
    ("from flask import g\ndef user(r):\n    return g.user\n", ["os.system('id ' + user(request.args))  # !"]),
    ("class Cfg:\n    cmd = 'ls'\n    def get(self, p):\n        return self.cmd\n", [f"Cfg.cmd = {Q}", f"os.system(Cfg().get({Q}))  # !"]),
    ("class Box:\n    def put(self, v):\n        self.v = v\n    def get(self, p):\n        return self.v\n",
     ["b = Box()", f"b.put({Q})", f"os.system(b.get({Q}))  # !"]),
    ("class C:\n    def __init__(self, f):\n        self.get = f\n    def get(self, p):\n        return 'safe'\n",
     ["x = C(str.strip)", f"os.system(x.get({Q}))  # !"]),
    (PICK, [f"os.system(pick(v := {Q}) + v)  # !"]),
    ("def norm(x):\n    return 'n'\ndef build(p):\n    return " + " + ".join(["norm('a')"] * 33) + " + p\n", [f"os.system(build({Q}))  # !"]),
    ("".join(f"def h{k}(p):\n    return h{k + 1}(p)\n" for k in range(7)) + "def h7(p):\n    return p\n", [f"os.system(h0({Q}))  # !"]),
]


def kept_case(helpers, body):
    src = FLASK + helpers + "@app.route('/a')\ndef a():\n" + "".join("    " + ln + "\n" for ln in body)
    return src, {("T-CMD", n) for n in marked(src)}


def project(files, view_imports, body):
    """A project of `files` and app/view.py, importing as `view_imports` says."""
    return dict(files, **{"app/__init__.py": "", "app/view.py": view_imports + "\n" + VIEW + "".join("    " + ln + "\n" for ln in body)})


# (Q-4) the helper in another file of the project: {path: source} trees, with the findings expected in them
HELPER_MODULE = "from flask import request\n" + WRAPPER + HELPERS.replace("html.escape", "escape").replace(
    "def passthru", "from html import escape\ndef passthru")
VIEW = "from flask import Flask, request\nimport os\napp = Flask(__name__)\n@app.route('/a')\ndef a():\n"


def tree(imports, body):
    """A project of helpers/wrap.py and app/view.py, the view importing as `imports` says."""
    src = imports + "\n" + VIEW + "".join("    " + ln + "\n" for ln in body)
    return {"helpers/__init__.py": "", "helpers/wrap.py": HELPER_MODULE, "app/__init__.py": "", "app/view.py": src}


PROJECT_REPORTED = [
    (tree("import helpers.wrap", ["x = helpers.wrap.Wrapper(request)", "param = x.get_param('id')", "os.system(param)  # !"]),
     "T-CMD"),
    (tree("from helpers.wrap import Wrapper", ["x = Wrapper(request)", "os.system(x.get_header('h'))  # !"]), "T-CMD"),
    (tree("from helpers import wrap", ["v = wrap.read_param()", "os.system(v)  # !"]), "T-CMD"),
    (tree("import helpers.wrap as hw", ["v = hw.passthru(request.args['q'])", "os.system(v)  # !"]), "T-CMD"),
    (tree("from helpers.wrap import Wrapper as W", ["param = W(request).get_param('id')", "os.system(param)  # !"]), "T-CMD"),
]
# the cross-file versions: each reported before Q-4
PROJECT_KEPT = [
    tree("from helpers.wrap import constant", ["v = constant(request.args['q'])", "os.system(v)  # !"]),
    # a module that patches another's helper, as the importing file does, or replaces the module
    project({"helpers.py": "class C:\n    def get(self, p):\n        return 'safe'\n", "patch.py": "import helpers\nhelpers.C.get = lambda self, p: p\n"},
            "import patch\nfrom helpers import C", ["x = C()", f"os.system(x.get({Q}))  # !"]),
    project({"helpers.py": "class C:\n    def get(self, p):\n        return 'safe'\n"},
            "from helpers import C\nC.get = lambda self, p: p", [f"os.system(C().get({Q}))  # !"]),
    project({"helpers.py": "def clean(p):\n    return 'safe'\n", "fake.py": "def clean(p):\n    return p\n",
             "boot.py": "import sys, fake\nsys.modules['helpers'] = fake\n"}, "import boot\nimport helpers", [f"os.system(helpers.clean({Q}))  # !"]),

    project({"helpers.py": "def gen(p):\n    yield p\n"}, "from helpers import gen", [f"for v in gen({Q}):", "    os.system(v)  # !"]),
    project({"helpers.py": "def pick(p):\n    if p: return p\n    return 'g'\n"}, "from helpers import pick", [f"os.system(pick({Q}))  # !"]),
    project({"helpers.py": "def pick(p):\n    k, v = p.split('=', 1)\n    return v\n"}, "import helpers as h", [f"os.system(h.pick({Q}))  # !"]),
    project({"helpers.py": "def ident(p):\n    return p\ndef pick(p):\n    return 'x'\npick = ident\n"}, "from helpers import pick",
            [f"os.system(pick({Q}))  # !"]),
    project({"helpers.py": "def pick(p):\n    return p\n"}, "def pick(p):\n    return 'x'\nfrom helpers import *",
            [f"os.system(pick({Q}))  # !"]),
    project({"pkg/__init__.py": "def pick(p):\n    return ''\nfrom .impl import pick\n", "pkg/impl.py": "def pick(p):\n    return p\n"},
            "from pkg import pick", [f"os.system(pick({Q}))  # !"]),
    project({"models.py": BASE_SUB}, "from models import Base, Sub",
            ["if request.args.get('m'):", f"    x = Base({Q})", "else:", f"    x = Sub({Q})", "os.system(x.get())  # !"]),
    # a module two files could be: app/utils.py is the nearer, utils.py may be the one imported
    project({"utils.py": "def pick(p):\n    return p\n", "app/utils.py": "def pick(p):\n    return 'x'\n"}, "import utils",
            [f"os.system(utils.pick({Q}))  # !"]),
]
PROJECT_QUIET = [
    tree("import helpers.wrap", ["x = helpers.wrap.Wrapper(request)", "param = x.get_value('id')", "os.system(param)"]),
    tree("import helpers.wrap as hw", ["v = hw.passthru('x')", "os.system(v)"]),
]


def t_findings(lang, src):
    return {(i["rule"], i["line"]) for i in core.taint_scan(f"x.{lang}", src.split("\n"), lang) if i["rule"].startswith("T-")}


def write(root, files):
    for rel, src in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(src)


def project_findings(files):
    with tempfile.TemporaryDirectory() as root:
        write(root, files)
        res = core.scan_project(root)
    return {(i["file"].replace(os.sep, "/"), i["rule"], i["line"]) for i in res["issues"] if i["rule"].startswith("T-")}


def project_want(files, rule):
    return {(rel, rule, n) for rel, src in files.items() for n in marked(src)}


class HelperTests(unittest.TestCase):
    maxDiff = None

    def test_reported(self):
        for lang, src, want in REPORTED:
            with self.subTest(src=src[len(FLASK):][-160:]):
                self.assertTrue(want)
                self.assertEqual(t_findings(lang, src), want)

    def test_quiet(self):
        for lang, src in QUIET:
            with self.subTest(src=src[-160:]):
                self.assertEqual(t_findings(lang, src), set())

    def test_kept(self):
        # (reworked after two independent reviews) following only adds: what a call's text carries stays
        for helpers, body in KEPT_TEXT + INCOMPLETE + UNSOUND + STATE:
            src, want = kept_case(helpers, body)
            with self.subTest(src=src[len(FLASK):][-200:]):
                self.assertTrue(want)
                self.assertEqual(t_findings("py", src), want)
        for files in PROJECT_KEPT:
            with self.subTest(files=sorted(files)):
                want = project_want({"app/view.py": files["app/view.py"]}, "T-CMD")
                self.assertTrue(want)
                self.assertEqual({k for k in project_findings(files) if k[0] == "app/view.py"}, want)

    def test_what_the_finding_says(self):
        src = view(["w = Wrapper(request)", "os.system(w.get_param('id'))"])
        msgs = [i["msg"] for i in core.taint_scan("x.py", src.split("\n"), "py") if i["rule"] == "T-CMD"]
        self.assertEqual(msgs, ["Possible command injection: untrusted data that 'w.get_param()' returns reaches this sink."])

    def test_what_following_adds(self):
        # a request read in a helper is added; what the call's text carries stays, a constant helper or not
        for body in (["v = read_param()", "os.system(v)  # !"], ["v = constant(request.args['q'])", "os.system(v)  # !"]):
            src = view(body)
            self.assertEqual(t_findings("py", src), {("T-CMD", n) for n in marked(src)})

    def test_not_followed(self):
        # a helper defined twice, a property, a nested def, an unknown receiver: read as text, as before
        twice = FLASK + "def g():\n    return 'a'\ndef g():\n    return request.args['q']\n" \
                        "@app.route('/t')\ndef t():\n    os.system(g(request.args['x']))\n"
        self.assertEqual(t_findings("py", twice), {("T-CMD", 10)})
        prop = FLASK + "class P:\n    @property\n    def v(self):\n        return request.args['q']\n" \
                       "@app.route('/t')\ndef t():\n    p = P()\n    os.system(p.v())\n"
        self.assertEqual(t_findings("py", prop), set())
        unknown = FLASK + "@app.route('/t')\ndef t():\n    w = make()\n    os.system(w.get_param('id'))\n"
        self.assertEqual(t_findings("py", unknown), set())
        # an instance made in another function, or a name assigned again, is not followed
        other = view(["w = Wrapper(request)", "w = make()", "os.system(w.get_param('id'))"])
        self.assertEqual(t_findings("py", other), set())
        # nor one a classmethod makes
        made = view(["w = Wrapper.make(request)", "os.system(w.get_param('id'))"])
        self.assertEqual(t_findings("py", made), set())

    def test_a_chain_past_the_depth_is_read_as_text(self):
        src = FLASK + "".join(f"def h{k}():\n    return h{k + 1}()\n" for k in range(12)) \
            + "def h12():\n    return request.args['q']\n@app.route('/c')\ndef c():\n    os.system(h0())\n"
        self.assertEqual(t_findings("py", src), set())

    def test_project_helpers(self):
        for files, rule in PROJECT_REPORTED:
            with self.subTest(view=files["app/view.py"][:60]):
                want = project_want(files, rule)
                self.assertTrue(want)
                self.assertEqual({k for k in project_findings(files) if k[0] == "app/view.py"}, want)
        for files in PROJECT_QUIET:
            with self.subTest(view=files["app/view.py"][:60]):
                self.assertEqual({k for k in project_findings(files) if k[0] == "app/view.py"}, set())

    def test_project_chains_and_relative_imports(self):
        files = {
            "pkg/__init__.py": "",
            "pkg/a.py": "from .b import inner\ndef outer(name):\n    return inner(name)\n",
            "pkg/b.py": "from flask import request\ndef inner(name):\n    return request.args.get(name)\n",
            "pkg/c.py": "def cycle(x):\n    from pkg.d import back\n    return back(x)\n",
            "pkg/d.py": "def back(x):\n    from pkg.c import cycle\n    return cycle(x) if x else x\n",
            "pkg/view.py": "import os\nfrom flask import request\nfrom pkg.a import outer\nfrom pkg import c\n"
                           "def v():\n    os.system(outer('q'))  # !\n    os.system(c.cycle(request.args['q']))  # !\n",
        }
        self.assertEqual({k for k in project_findings(files) if k[0] == "pkg/view.py"}, project_want(
            {"pkg/view.py": files["pkg/view.py"]}, "T-CMD"))

    def test_engine_call(self):
        from lazaret.scanner import engine
        files = tree("import helpers.wrap", ["x = helpers.wrap.Wrapper(request)"])
        got = engine.taint_helpers(sorted(files.items()))
        self.assertEqual(sorted(got), ["app/view.py"])
        names = [entry[0] for entry in got["app/view.py"]]
        self.assertEqual(names, ["helpers.wrap"])
        # a module imported whole names the members the file uses
        self.assertEqual([m[0] for m in got["app/view.py"][0][1][1]], ["Wrapper"])

    def test_bounded_work(self):
        many = FLASK + "".join(f"def f{k}(a, b, c):\n    return f{k + 1}(a, b, c) + a\n" for k in range(3000)) \
            + "@app.route('/m')\ndef m():\n" + "".join(f"    v{k} = f{k}(request.args['q'], 1, 2)\n" for k in range(0, 3000, 7))
        deep = FLASK + "def g(x):\n    return x\n@app.route('/d')\ndef d():\n    v = " + "g(" * 3000 + "request.args['q']" \
            + ")" * 3000 + "\n    os.system(v)\n"
        wide = FLASK + "def g(x):\n    return x\nv = " + " + ".join(["g(input())"] * 20_000) + "\nos.system(v)\n"
        chain = FLASK + "class C:\n    def m(self, x):\n        return x\n" \
            + "v = C()" + ".m(input())" * 20_000 + "\nos.system(v)\n"
        for src in (many, deep, wide, chain):
            t0 = time.monotonic()
            core.taint_scan("x.py", src.split("\n"), "py")
            self.assertLess(time.monotonic() - t0, 15, src[len(FLASK):len(FLASK) + 40])

    def test_many_definitions_of_one_name_take_linear_time(self):
        # 8x the definitions of one name: about 8x the time (49918e8 linked each call of it to each of them: 64x)
        classes = lambda n: FLASK + "".join(f"class C{k}:\n    def get(self):\n        return request.args.get('q')\n"
                                            f"    def run(self):\n        os.system(self.get())\n" for k in range(n))
        functions = lambda n: FLASK + "".join(f"def get():\n    return request.args.get('q{k}')\n"
                                              f"def run{k}():\n    os.system(get())\n" for k in range(n))

        def best(src):
            lines = src.split("\n")
            times = []
            for _ in range(3):
                t0 = time.perf_counter()
                core.taint_scan("x.py", lines, "py")
                times.append(time.perf_counter() - t0)
            return min(times)
        for make in (classes, functions):
            small, big = best(make(500)), best(make(4000))
            self.assertLess(big, 24 * max(small, 0.002), (make(1)[len(FLASK):len(FLASK) + 30], small, big))


if __name__ == "__main__":
    unittest.main()
