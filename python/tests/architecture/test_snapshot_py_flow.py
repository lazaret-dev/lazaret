"""The engine's cross-file Python taint pass (the `py_flow` call: rust/crates/
lazaret-engine/src/pyflow/, where both packages' project-mode X-* flows and
Q-FLOW-* notes for Python come from), held to its recorded outputs
(_snapshots.py) — every output, in order: each issue's category, file, line,
source, sink, chain and the index of its file; each note's fields — on a
corpus of the review's cases (review_cases: routes of each framework,
modules and imports, classes, returned values, sanitizers and guards,
globals, every sink category, the syntax the pass follows, files the parser
rejects or that overflow it) and seeded generated projects (pygen.py), with
the default model and with a configured one (sources, sinks, full and
partial sanitizers, as taintspec validates them); and on the call's own
cases: files that are not text, each limit lowered (and not raised), the
nesting the frames hold, and a chain whose every link reads the chain again
(its work counts).

Until phase 3 of the Rust-first refactor the pass was flow.py's own, on
Python's ast; the port was held to it output for output on this corpus, on
the sets of files the test suite hands it, on 1,200 more generated projects
and on 455 installed packages and standard-library modules read as projects,
with both models (docs/RUST_ENGINE.md). All content is inert: nothing is
executed.
"""
import collections
import unittest

from lazaret.scanner import _native, taintspec
from tests.architecture import _snapshots, pygen

CATS = ("SQL injection", "command injection", "code injection", "template injection", "path traversal",
        "server-side request forgery", "open redirect", "cross-site scripting")
CONFIG = {"python": {
    "sources": [r"\bos\.environ\b", r"\bkwargs\b", r"\bconfig\b"],
    "sinks": [{"pattern": r"\.write\b", "category": "path traversal"},
              {"pattern": r"\bsetattr\b", "category": "code injection"},
              {"pattern": r"\bPopen\b", "category": "command injection"}],
    "sanitizers": {"full": ["os.fspath", "validate"],
                   "partial": {"strip": ["command injection"], "escape": ["SQL injection"]}},
}}
RUNNER = "import os\n\ndef run_cmd(c):\n    os.system(c)\n"
VIEW = "from flask import request\nfrom runner import run_cmd\n\ndef view():\n    run_cmd(request.args['q'])\n"


def files(*pairs):
    return [{"path": p, "content": c} for p, c in pairs]


def review_cases():
    """The review's cases (tests/scanner/test_review_flow*.py,
    test_taint_frameworks.py, test_taint_fstrings.py …), as file sets."""
    sets = []
    # a flow across files, and each sink category through a helper
    sinks = {"SQL injection": "cur.execute('SELECT * FROM t WHERE a = ' + x)", "command injection": "os.system(x)",
             "code injection": "eval(x)", "template injection": "render_template_string(x)",
             "path traversal": "open(x)", "server-side request forgery": "requests.get(x)",
             "open redirect": "redirect(x)", "cross-site scripting": "make_response(x)"}
    lib = "import os\nimport requests\nfrom flask import redirect, make_response, render_template_string\n\n" + "".join(
        f"def h{k}(x):\n    return {sink}\n\n" for k, sink in enumerate(sinks.values()))
    app = ("from flask import request\nfrom lib import " + ", ".join(f"h{k}" for k in range(len(sinks)))
           + "\n\ndef view():\n    q = request.args.get('q')\n" + "".join(f"    h{k}(q)\n" for k in range(len(sinks))))
    sets.append(files(("lib.py", lib), ("app.py", app)))
    # routes: Flask converters, FastAPI parameters, Django views
    sets.append(files(("runner.py", RUNNER), ("app.py", (
        "from flask import Flask\nfrom runner import run_cmd\napp = Flask(__name__)\n\n"
        "@app.route('/a/<cmd>')\ndef a(cmd):\n    run_cmd(cmd)\n\n@app.route('/b/<int:n>')\ndef b(n):\n    run_cmd(n)\n\n"
        "@app.route('/c/<path:p>', methods=['POST'])\ndef c(p, other=None):\n    run_cmd(p)\n    run_cmd(other)\n"))))
    sets.append(files(("runner.py", RUNNER), ("api.py", (
        "from enum import Enum\nfrom typing import Annotated, Optional\nfrom uuid import UUID\n"
        "from fastapi import APIRouter, Depends, FastAPI, Query, Request\nfrom runner import run_cmd\n"
        "app = FastAPI()\nrouter = APIRouter()\n\nclass Kind(str, Enum):\n    a = 'a'\n\n"
        "def get_db():\n    return None\n\n"
        "@app.get('/items/{item}')\nasync def items(item: str, q: Optional[str] = None, n: int = 0, u: UUID = None,\n"
        "                k: Kind = Kind.a, db=Depends(get_db), request: Request = None):\n"
        "    run_cmd(item)\n    run_cmd(q)\n    run_cmd(n)\n    run_cmd(u)\n    run_cmd(k)\n    run_cmd(db)\n\n"
        "@router.post('/x')\ndef x(body: Annotated[str, Query()], tags: list[int] = Query([])):\n"
        "    run_cmd(body)\n    run_cmd(tags)\n"))))
    sets.append(files(("runner.py", RUNNER), ("views.py", (
        "from django.http import HttpResponse\nfrom runner import run_cmd\n\n"
        "def detail(request, slug, pk: int = 0):\n    run_cmd(slug)\n    run_cmd(pk)\n    run_cmd(request.GET.get('q'))\n"
        "    return HttpResponse('ok')\n"))))
    # a source returned by a helper; a sanitizing wrapper; partial sanitizers per category
    sets.append(files(("a.py", "from flask import request\ndef fetch_name():\n    return request.args.get('q')\n"),
                      ("b.py", "import subprocess\nfrom a import fetch_name\n"
                               "def run():\n    subprocess.check_output(fetch_name(), shell=False)\n"
                               "def run2():\n    x = fetch_name()\n    eval(x)\n")))
    sets.append(files(("util.py", "import shlex\ndef safe_arg(x):\n    return shlex.quote(x)\n"),
                      ("runner.py", RUNNER), ("c.py", "def run_code(c):\n    eval(c)\n"),
                      ("a.py", "from flask import request\nfrom util import safe_arg\nfrom runner import run_cmd\n"
                               "from c import run_code\n\ndef view():\n    run_cmd(safe_arg(request.args['q']))\n"
                               "    run_code(safe_arg(request.args['q']))\n    run_cmd(int(request.args['n']))\n"
                               "    run_cmd(__import__('shlex').quote(request.args['q']))\n")))
    sets.append(files(("b.py", "import os\ndef both(x):\n    eval(x)\n    os.system(x)\n"),
                      ("a.py", "import shlex\nfrom flask import request\nfrom b import both\n"
                               "def view():\n    both(shlex.quote(request.args['q']))\n")))
    # imports: aliases, relative, star, re-exports, modules
    sets.append(files(("pkg/__init__.py", "from .core import run_cmd as go\n"),
                      ("pkg/core.py", RUNNER),
                      ("pkg/sub/__init__.py", ""),
                      ("pkg/sub/m.py", "from ..core import run_cmd\nfrom .. import go\n"
                                       "from flask import request\n\ndef v():\n    run_cmd(request.form['a'])\n"
                                       "    go(request.form['b'])\n"),
                      ("star.py", "from pkg.core import *\nimport pkg.core as pc\nimport pkg\nfrom flask import request\n"
                                  "def w():\n    run_cmd(request.json)\n    pc.run_cmd(request.data)\n"
                                  "    pkg.go(request.values.get('x'))\n")))
    # classes: self attributes, constructors, bases, super(), class and static methods, duck typing
    sets.append(files(("repo.py", (
        "import os\n\nclass Base:\n    def run(self, c):\n        os.system(c)\n\n"
        "class Repo(Base):\n    def __init__(self, cmd):\n        self.cmd = cmd\n    def go(self):\n        self.run(self.cmd)\n"
        "    def again(self, c):\n        super().run(c)\n    @classmethod\n    def make(cls, c):\n        cls().run(c)\n"
        "    @staticmethod\n    def static_run(c):\n        os.system(c)\n\n"
        "class Other:\n    def handle(self, x):\n        eval(x)\n")),
        ("app.py", "from flask import request\nfrom repo import Repo, Other\n\ndef view(obj):\n"
                   "    r = Repo(request.args['c'])\n    r.go()\n    r.again(request.args['d'])\n"
                   "    Repo.make(request.args['e'])\n    Repo.static_run(request.args['f'])\n"
                   "    obj.handle(request.args['g'])\n    obj.get(request.args['h'])\n")))
    # guards: path checks, allowlists, exits
    sets.append(files(("io.py", "def read(p):\n    return open(p).read()\n"
                                "def checked(p):\n    if not p.startswith('/srv/'):\n        return None\n"
                                "    return open(p).read()\n"),
                      ("app.py", "import os\nfrom flask import request, abort\nfrom io import read, checked\n"
                                 "ALLOWED = {'a', 'b'}\nBASE = '/srv'\n\ndef v():\n    p = request.args['p']\n"
                                 "    if p not in ALLOWED:\n        abort(400)\n    read(p)\n\ndef w():\n"
                                 "    p = request.args['p']\n    if os.path.realpath(p).startswith(BASE):\n        read(p)\n"
                                 "    checked(p)\n    read(p)\n")))
    # globals and module-level code, scripts
    sets.append(files(("cfg.py", "import sys\nTARGET = sys.argv[1]\n"),
                      ("run.py", "import os\nfrom cfg import TARGET\n\ndef go():\n    os.system('ping ' + TARGET)\n\n"
                                 "if __name__ == '__main__':\n    import sys\n    eval(sys.argv[2])\n    go()\n"),
                      ("cli.py", "import os\nimport sys\n\ndef main(args):\n    os.system(args[0])\n\nmain(sys.argv[1:])\n")))
    # the syntax the pass follows: f-strings, comprehensions, match, walrus, lambdas, await, with, try, *args
    sets.append(files(("runner.py", RUNNER), ("s.py", (
        "from flask import request\nfrom runner import run_cmd\n\nasync def fetch():\n    return request.args['x']\n\n"
        "async def v():\n    q = request.args['q']\n    run_cmd(f'echo {q}')\n    run_cmd([c for c in q if c][0])\n"
        "    match q:\n        case {'k': kv}:\n            run_cmd(kv)\n        case [first, *rest]:\n            run_cmd(first)\n"
        "    if (w := request.args.get('w')):\n        run_cmd(w)\n    f = lambda z: z\n    run_cmd(f(q))\n"
        "    run_cmd(await fetch())\n    with open(q) as fh:\n        run_cmd(fh)\n    try:\n        run_cmd(q)\n"
        "    except Exception as err:\n        run_cmd(str(err))\n    args = [q]\n    run_cmd(*args)\n"
        "    kw = {'c': q}\n    run_cmd(**kw)\n    run_cmd('%s' % q)\n    run_cmd('{}'.format(q))\n"))))
    # every sink category's built-in forms, and results that are not request text
    sets.append(files(("sinks.py", (
        "import os, subprocess, sqlite3, shutil, requests, httpx, jinja2\nfrom urllib.request import urlopen\n"
        "from flask import redirect, send_file, Markup, render_template_string\n"
        "from django.utils.safestring import mark_safe\nfrom django.http import HttpResponseRedirect, HttpResponse\n\n"
        "def s1(x):\n    subprocess.run(x, shell=True)\ndef s2(x):\n    subprocess.Popen(['sh', '-c', x])\n"
        "def s3(x):\n    cur.executemany(x, rows)\ndef s4(x):\n    User.objects.raw(x)\ndef s5(x):\n    jinja2.Template(x)\n"
        "def s6(x):\n    send_file(x)\ndef s7(x):\n    shutil.rmtree(x)\ndef s8(x):\n    httpx.get(x)\n"
        "def s9(x):\n    urlopen(x)\ndef s10(x):\n    HttpResponseRedirect(x)\ndef s11(x):\n    Markup(x)\n"
        "def s12(x):\n    mark_safe(x)\ndef s13(x):\n    HttpResponse(x)\ndef s14(x):\n    exec(x)\n"
        "def s15(x):\n    env.from_string(x)\ndef s16(x):\n    os.popen(x)\n")),
        ("app.py", "from flask import request\nfrom sinks import *\nfrom django.shortcuts import get_object_or_404\n\n"
                   "def v():\n    q = request.args['q']\n" + "".join(f"    s{k}(q)\n" for k in range(1, 17))
                   + "    s1(len(q))\n    s1(get_object_or_404(M, pk=q))\n    s1(M.objects.filter(a=q).first())\n"
                     "    s1(q.startswith('x'))\n    s4(select(M).where(M.a == q))\n")))
    # what the parser rejects or overflows on, beside a flow
    for name, src in (("broken.py", "def f(:\n    pass\n"), ("old.py", "print 'hello'\n"),
                      ("nul.py", "x = 1  # \0 stray\n"), ("sur.py", "x = '\ud800'\n"),
                      ("gen.py", "x = " + "-" * 6000 + "1\n"), ("deep.py", "x = 1" + " + 1" * 10000 + "\n"),
                      ("chain.py", "import os\n\ndef f(x):\n    os.system(x" + " + x" * 1200 + ")\n")):
        sets.append(files(("runner.py", RUNNER), ("view.py", VIEW), (name, src)))
    # a recursive pair, long wrapper chains written both ways, many same-named methods
    sets.append(files(("r.py", "import os\nfrom flask import request\ndef a(x):\n    b(x)\n    return x\n"
                               "def b(x):\n    a(x)\n    os.system(x)\ndef v():\n    a(request.args['q'])\n")))
    for first in (True, False):
        defs = [f"def w{k}(x):\n    w{k + 1}(x)\n" for k in range(1, 30)] + ["def w30(x):\n    os.system(x)\n"]
        if not first:
            defs.reverse()
        sets.append(files(("w.py", "import os\nfrom flask import request\ndef view():\n    w1(request.args['q'])\n"
                                   + "".join(defs))))
    sets.append(files(*[(f"m{k}.py", f"class C{k}:\n    def get(self, key):\n        return key\n"
                                     f"    def save(self, data):\n        eval(data)\n") for k in range(6)],
                      ("app.py", "from flask import request\ndef v(o):\n    o.save(request.args['q'])\n")))
    return sets


def model(spec):
    """The call's arguments for a validated taintspec section."""
    return {"sources": [g.pattern for g in spec.sources], "sinks": [[g.pattern, c] for g, c in spec.sinks],
            "full": sorted(spec.full), "partial": [[n, sorted(c)] for n, c in sorted(spec.partial.items())]}


def call(sets_files, extra=None):
    """The py_flow call for files ({"path", "content"}: content None is not text)."""
    text = [f["content"] for f in sets_files if isinstance(f["content"], str)]
    args = {"files": [[f["path"], len(f["content"]) if isinstance(f["content"], str) else None] for f in sets_files]}
    args.update(extra or {})
    return ("py_flow", args, "".join(text))


def corpus():
    return review_cases() + pygen.projects(20261001, 200)


def own_cases():
    two = files(("runner.py", RUNNER), ("view.py", VIEW))
    pair = files(("r.py", "import os\ndef a(x):\n    b(x)\n    return x\ndef b(x):\n    a(x)\n    os.system(x)\n"))
    chain = lambda n: files(("m.py", "import os\n\ndef f(x):\n    os.system(x" + " + x" * n + ")\n"))  # noqa: E731
    out = [call(two), call(two, {"max_iters": 10 ** 9, "max_files": 10 ** 9, "max_bytes": 10 ** 12,
                                 "work_limit": [10 ** 12, 10 ** 12], "run_limit": [10 ** 12, 10 ** 12]}),
           call(two + files(("a.py", None), ("b.py", None))),
           call(pair, {"max_iters": 1}), call(two, {"max_files": 1}), call(two, {"max_bytes": 60}),
           call(two, {"work_limit": [0, 0]}), call(two, {"run_limit": [3, 0]}),
           call(chain(986)), call(chain(987)),
           call(files(("c.py", "def f(x):\n    y = x" + "()" * 9000 + "\n")))]
    # the review's cases with a low limit for each reading, and a low budget
    out += [call(fs, {"run_limit": [200, 2]}) for fs in review_cases()]
    out += [call(fs, {"work_limit": [100, 1]}) for fs in review_cases()]
    return out


def snapshot_sets():
    return {"py_flow": lambda: [call(fs) for fs in corpus()],
            "py_flow_configured": lambda: [call(fs, model(taintspec.validate(CONFIG).python)) for fs in corpus()],
            "py_flow_calls": own_cases}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class PyFlowSnapshotTests(unittest.TestCase):
    maxDiff = None

    def check(self, name):
        calls = snapshot_sets()[name]()
        answers = _snapshots.run(calls)
        self.assertEqual([a for a in answers if "ok" not in a][:5], [])
        _snapshots.check(self, name, answers)
        outs = [a["ok"] for a in answers]
        for (_, args, _), out in zip(calls, outs):          # an issue names its file and the file's index
            for o in out:
                if o[0] == "issue":
                    self.assertEqual(args["files"][o[7]][0], o[2], o)
        return outs

    def test_the_default_model(self):
        outs = self.check("py_flow")
        kinds = collections.Counter((o[0], o[1]) for out in outs for o in out)
        self.assertGreater(sum(kinds.values()), 1000)
        # not vacuous: every category, each note
        self.assertTrue({("issue", c) for c in CATS} | {("note", "Q-FLOW-SKIPPED"), ("note", "Q-FLOW-RECURSION")}
                        <= set(kinds), kinds)

    def test_a_configured_model(self):
        spec = taintspec.validate(CONFIG).python
        self.assertTrue(spec.sources and spec.sinks and spec.full and spec.partial)
        outs = self.check("py_flow_configured")
        default = [a["ok"] for a in _snapshots.run(snapshot_sets()["py_flow"]())]
        self.assertGreater(sum(len(o) for o in outs), 1000)
        self.assertGreater(sum(a != b for a, b in zip(outs, default)), 10)     # the model changes what is found

    def test_the_calls_own_cases(self):
        outs = self.check("py_flow_calls")
        plain, high, not_text, iters, nfiles, nbytes, work, run, c986, c987, links = outs[:11]
        self.assertEqual([o[:5] for o in plain], [["issue", "command injection", "view.py", 5, "view.py:5"]])
        self.assertEqual(high, plain)                       # a limit is lowered, never raised
        self.assertEqual([(o[1], o[3], o[5]) for o in not_text if o[0] == "note"],
                         [("Q-FLOW-SKIPPED", "a.py", "Cross-file taint analysis skipped 'a.py': content is not text."),
                          ("Q-FLOW-SKIPPED", "b.py", "Cross-file taint analysis skipped 'b.py': content is not text.")])
        self.assertEqual([o[2] for o in iters], ["Flow analysis incomplete (iteration cap)"])
        self.assertIn("did not converge within 1 re-analyses", iters[0][5])
        for out, text in ((nfiles, "beyond its budget (1 files / 64,000,000 characters), starting with 'view.py'"),
                          (nbytes, "beyond its budget (20000 files / 60 characters), starting with 'view.py'")):
            self.assertEqual([(o[1], o[2]) for o in out], [("Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)")])
            self.assertIn(text, out[0][5])
        self.assertEqual([o[1] for o in work], ["Q-FLOW-INCOMPLETE"] * 2)
        self.assertIn("stopped following values at", work[0][5])
        self.assertIn("stopped reporting at", work[1][5])
        self.assertEqual([(o[1], o[3]) for o in run], [("Q-FLOW-INCOMPLETE", "runner.py"), ("Q-FLOW-INCOMPLETE", "view.py")])
        self.assertIn("stopped reading run_cmd() in 'runner.py' at its limit of 3 + 0 steps per syntax tree node", run[0][5])
        self.assertEqual((c986, [o[1] for o in c987]), ([], ["Q-FLOW-RECURSION"]))
        self.assertEqual([o[1] for o in links], ["Q-FLOW-INCOMPLETE"])

    def test_bad_arguments_are_refused(self):
        for args in ({"files": [["a.py", 5]]}, {"files": [["a.py", 1]]}, {"files": "x"},
                     {"files": [["a.py", 3]], "sinks": [["x", "not a category"]]},
                     {"files": [["a.py", 3]], "work_limit": [1]}, {"files": [["a.py", 3]], "run_limit": [-1, 2]},
                     {"files": [["a.py", 3]], "max_iters": -1}, {"files": [["a.py", 3]], "max_files": "x"},
                     {"files": [["a.py", None], ["b.py", 2]]}):
            with self.subTest(args=args), self.assertRaises(_native.NativeError):
                _native.call("py_flow", args, "abc")


if __name__ == "__main__":
    unittest.main()
