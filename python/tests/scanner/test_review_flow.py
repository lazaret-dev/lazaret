"""Review findings 6-11 and 13 — the Python interprocedural engine (flow.py).

 6  one unparseable file (parser MemoryError, NUL bytes, Python 2, syntax
    errors) dropped the WHOLE cross-file pass; flow.analyze could raise.
 7  a source returned by a helper and passed straight into a sink in the
    caller was never reported.
 8  one sink category per parameter (last wins, never converged) and
    param_to_return dropped the callee's sanitization.
 9  argument binding ignored self, keywords and positional-only params.
10  bare-name resolution merged every same-named function project-wide.
11  taint was dropped through await, IfExp, dicts, comprehensions, for, match,
    walrus, *args/**kw, self.attr, `import … as`, unknown library calls, and
    module-level code was never analyzed.
13  every call site looped over all same-named functions; MAX_ITERS=6 cut
    off silently.

Every fixture is inert source text handed to flow.analyze(); nothing runs.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from tests import _support
from lazaret.scanner import flow

PY = sys.executable or "python3"
RUNNER = "import os\ndef run_cmd(c):\n    os.system(c)\n"


def analyze(files):
    return flow.analyze([{"path": p, "content": textwrap.dedent(c), "lang": "py"}
                         for p, c in files.items()])


def xs(findings):
    """(rule, file, line) of the X-* findings."""
    return sorted((f["rule"], f["file"], f["line"]) for f in findings
                  if f["rule"].startswith("X-"))


class ParseFailuresCostOneFile(unittest.TestCase):
    VIEW = ("from flask import request\nfrom b import run_cmd\n"
            "def view():\n    run_cmd(request.args['q'])\n")

    def check(self, bad_name, bad_src, rule, text):
        out = analyze({"a.py": self.VIEW, "b.py": RUNNER, bad_name: bad_src})
        self.assertEqual(xs(out), [("X-CMD", "a.py", 4)])
        notes = [f for f in out if f["rule"] == rule]
        self.assertEqual([n["file"] for n in notes], [bad_name], out)
        self.assertEqual(notes[0]["sev"], "INFO")
        self.assertIn(text, notes[0]["msg"])

    def test_parser_memory_error(self):
        """Reviewer repro projMEM: 'x = ' + '-'*6000 + '1'."""
        self.check("gen.py", "x = " + "-" * 6000 + "1\n", "Q-FLOW-RECURSION", "gen.py")

    def test_nul_byte(self):
        self.check("c.py", "x = 1  # \0 stray nul\n", "Q-FLOW-SKIPPED", "NUL")

    def test_python2_file(self):
        self.check("old.py", "print 'hello'\n", "Q-FLOW-SKIPPED", "Python 2")

    def test_syntax_error(self):
        self.check("broken.py", "def f(:\n    pass\n", "Q-FLOW-SKIPPED", "syntax error")

    def test_parser_raising_anything_is_contained(self):
        real = flow.ast.parse

        def parse(src, *a, **k):
            if "BOOM" in src:
                raise ValueError("source code string cannot contain null bytes")
            return real(src, *a, **k)
        with mock.patch.object(flow.ast, "parse", side_effect=parse):
            self.check("boom.py", "BOOM = 1\n", "Q-FLOW-SKIPPED", "NUL")

    def test_analyze_never_raises(self):
        with mock.patch.object(flow._Analyzer, "run", side_effect=ZeroDivisionError):
            out = analyze({"a.py": self.VIEW, "b.py": RUNNER})
        self.assertIn("Q-FLOW-INCOMPLETE", [f["rule"] for f in out])
        # garbage input shapes
        self.assertEqual(flow.analyze([None, 5, {"lang": "py"}, {"path": "x.py", "lang": "py",
                                                               "content": None}])[0]["rule"],
                         "Q-FLOW-SKIPPED")
        self.assertEqual(flow.analyze(None), [])

    def test_cli_keeps_cross_file_findings(self):
        root = tempfile.mkdtemp(prefix="lz-review-flow-")
        self.addCleanup(shutil.rmtree, root, True)
        for name, src in (("a.py", self.VIEW), ("b.py", RUNNER),
                          ("gen.py", "x = " + "-" * 6000 + "1\n"), ("c.py", "x = 1  # \0\n")):
            with open(os.path.join(root, name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(src)
        p = subprocess.run([PY, _support.CLI, root, "--no-html", "--no-json"],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertNotIn("interprocedural taint analysis skipped", p.stderr)
        self.assertIn("X-CMD", p.stdout)
        self.assertIn("✗ No cross-file taint flows", p.stdout)


class ReturnedSourceReachesSink(unittest.TestCase):
    def test_helper_return_into_sink(self):
        """Reviewer repro (finding 7)."""
        out = analyze({
            "a.py": "from flask import request\ndef fetch_name():\n    return request.args.get('q')\n",
            "b.py": ("import subprocess\nfrom a import fetch_name\n"
                     "def run():\n    subprocess.check_output(fetch_name(), shell=False)\n"
                     "def run2():\n    x = fetch_name()\n    eval(x)\n")})
        self.assertEqual(xs(out), [("X-CMD", "b.py", 4), ("X-CODE", "b.py", 7)])
        msg = [f["msg"] for f in out if f["rule"] == "X-CMD"][0]
        self.assertIn("a.py:3", msg)                      # names the real source

    def test_same_function_source_not_duplicated(self):
        # intra-procedural flows belong to the per-file engine (T-*)
        out = analyze({"a.py": "import os\nfrom flask import request\n"
                               "def v():\n    os.system(request.args['q'])\n"})
        self.assertEqual(xs(out), [])


class SummariesPerCategory(unittest.TestCase):
    BOTH_EVAL_FIRST = "import os\ndef both(x):\n    eval(x)\n    os.system(x)\n"
    BOTH_SYSTEM_FIRST = "import os\ndef both(x):\n    os.system(x)\n    eval(x)\n"
    CALLER = ("import shlex\nfrom flask import request\nfrom b import both\n"
              "def view():\n    both(shlex.quote(request.args['q']))\n")

    def test_partial_sanitizer_order_independent(self):
        for body in (self.BOTH_EVAL_FIRST, self.BOTH_SYSTEM_FIRST):
            with self.subTest(body=body):
                out = analyze({"a.py": self.CALLER, "b.py": body})
                self.assertEqual([r for r, _, _ in xs(out)], ["X-CODE"])

    def test_converges(self):
        runs = []
        orig = flow._Analyzer.run

        def counting(self):
            runs.append(self.fn.qualname)
            return orig(self)
        with mock.patch.object(flow._Analyzer, "run", counting):
            analyze({"b.py": self.BOTH_EVAL_FIRST})
        self.assertLessEqual(runs.count("both"), 3, runs)

    def test_sanitizing_wrapper_clears_across_functions(self):
        """Reviewer repro W1: safe_arg() wraps shlex.quote."""
        out = analyze({
            "util.py": "import shlex\ndef safe_arg(x):\n    return shlex.quote(x)\n",
            "b.py": RUNNER,
            "a.py": ("from flask import request\nfrom util import safe_arg\nfrom b import run_cmd\n"
                     "def view():\n    run_cmd(safe_arg(request.args['q']))\n"
                     "def inline():\n    run_cmd(__import__('shlex').quote(request.args['q']))\n"
                     "def wrong():\n    eval(safe_arg(request.args['q']))\n")})
        self.assertEqual(xs(out), [])       # eval sink is same-function: T-* territory
        out = analyze({
            "util.py": "import shlex\ndef safe_arg(x):\n    return shlex.quote(x)\n",
            "c.py": "def run_code(c):\n    eval(c)\n",
            "a.py": ("from flask import request\nfrom util import safe_arg\nfrom c import run_code\n"
                     "def view():\n    run_code(safe_arg(request.args['q']))\n")})
        self.assertEqual(xs(out), [("X-CODE", "a.py", 5)])   # quoting is not a CODE sanitizer


class ArgumentBinding(unittest.TestCase):
    RUNNER_CLS = ("import os\nclass Runner:\n    def run(self, cmd, label=None):\n"
                  "        os.system(cmd)\n        print(label)\n")

    def run_case(self, call, callee=None):
        return xs(analyze({
            "b.py": callee or self.RUNNER_CLS,
            "a.py": ("from flask import request\nfrom b import Runner, go, run_cmd\n"
                     f"def view():\n    {call}\n")}))

    def test_method_receiver_skipped(self):
        self.assertEqual(self.run_case("Runner().run(request.args['q'])"), [("X-CMD", "a.py", 4)])
        self.assertEqual(self.run_case("Runner().run('ls', request.args['q'])"), [])

    def test_keywords_bind_by_name(self):
        go = "import os\ndef go(note, cmd):\n    os.system(cmd)\n"
        self.assertEqual(self.run_case("go(cmd='ls', note=request.args['q'])", go), [])
        self.assertEqual(self.run_case("go(cmd=request.args['q'], note='x')", go),
                         [("X-CMD", "a.py", 4)])

    def test_positional_only(self):
        p1 = "import os\ndef run_cmd(c, /, flag=False):\n    os.system(c)\n"
        p2 = "import os\ndef run_cmd(label, /, c):\n    print(label)\n    os.system(c)\n"
        self.assertEqual(self.run_case("run_cmd(request.args['q'])", p1), [("X-CMD", "a.py", 4)])
        self.assertEqual(self.run_case("run_cmd(request.args['q'], 'ls')", p2), [])

    def test_star_args_and_kwargs(self):
        self.assertEqual(self.run_case("run_cmd(*[request.args['q']])", RUNNER), [("X-CMD", "a.py", 4)])
        self.assertEqual(self.run_case("run_cmd(**{'c': request.args['q']})", RUNNER),
                         [("X-CMD", "a.py", 4)])
        va = "import os\ndef run_cmd(*parts, **opts):\n    os.system(parts[0])\n"
        self.assertEqual(self.run_case("run_cmd('x', request.args['q'])", va), [("X-CMD", "a.py", 4)])


class NameResolution(unittest.TestCase):
    def test_user_get_does_not_poison_dict_get(self):
        """Reviewer repro N1: a user `def get()` made os.environ.get a source."""
        out = analyze({
            "helpers.py": "from flask import request\ndef get(name):\n    return request.args.get(name)\n",
            "db.py": "def fetch(sql):\n    cursor.execute(sql)\n",
            "config.py": ("import os\nfrom db import fetch\ndef load_table():\n"
                          "    table = os.environ.get('TABLE', 'users')\n"
                          "    fetch('SELECT * FROM ' + table)\n")})
        self.assertEqual(xs(out), [])

    def test_same_name_in_two_modules(self):
        """Reviewer repro N2: only the imported process() counts."""
        out = analyze({
            "safe.py": "def process(v):\n    return int(v)\n",
            "unsafe_other.py": "import os\ndef process(v):\n    os.system(v)\n",
            "view.py": ("from flask import request\nfrom safe import process\n"
                        "def view():\n    return process(request.args['n'])\n")})
        self.assertEqual(xs(out), [])

    def test_import_forms(self):
        cases = {
            "from b import run_cmd as rc\ndef v():\n    rc(request.args['q'])\n": 3,
            "import b\ndef v():\n    b.run_cmd(request.args['q'])\n": 3,
            "import b as bee\ndef v():\n    bee.run_cmd(request.args['q'])\n": 3,
        }
        for body, line in cases.items():
            with self.subTest(body=body):
                out = analyze({"b.py": RUNNER, "a.py": "from flask import request\n" + body})
                self.assertEqual(xs(out), [("X-CMD", "a.py", line + 1)])

    def test_relative_import_and_reexport(self):
        out = analyze({
            "pkg/__init__.py": "from .runner import run_cmd\n",
            "pkg/runner.py": RUNNER,
            "pkg/views.py": ("from flask import request\nfrom .runner import run_cmd\n"
                             "def v():\n    run_cmd(request.args['q'])\n"),
            "app.py": ("from flask import request\nfrom pkg import run_cmd\n"
                       "def w():\n    run_cmd(request.args['q'])\n")})
        self.assertEqual(xs(out), [("X-CMD", "app.py", 4), ("X-CMD", "pkg/views.py", 4)])

    def test_method_calls_never_match_module_functions(self):
        out = analyze({
            "b.py": RUNNER,
            "a.py": ("from flask import request\ndef v(obj):\n"
                     "    obj.run_cmd(request.args['q'])\n")})
        self.assertEqual(xs(out), [])

    def test_common_method_names_not_duck_typed(self):
        out = analyze({
            "svc.py": "import os\nclass Svc:\n    def run(self, c):\n        os.system(c)\n",
            "a.py": ("from flask import request\nimport threading\ndef v(t):\n"
                     "    t.run(request.args['q'])\n")})
        self.assertEqual(xs(out), [])

    def test_unknown_receiver_rare_method_is_resolved(self):
        out = analyze({
            "svc.py": "import os\nclass Svc:\n    def launch_job(self, c):\n        os.system(c)\n",
            "a.py": ("from flask import request\ndef v(svc):\n"
                     "    svc.launch_job(request.args['q'])\n")})
        self.assertEqual(xs(out), [("X-CMD", "a.py", 3)])

    def test_typed_local_and_self_calls(self):
        out = analyze({
            "svc.py": ("import os\nclass Svc:\n    def go(self, c):\n        self._really(c)\n"
                       "    def _really(self, c):\n        os.system(c)\n"),
            "a.py": ("from flask import request\nfrom svc import Svc\ndef v():\n"
                     "    s = Svc()\n    s.go(request.args['q'])\n")})
        self.assertEqual(xs(out), [("X-CMD", "a.py", 5)])


class TaintPropagation(unittest.TestCase):
    def one(self, body, extra_imports=""):
        out = analyze({"b.py": RUNNER,
                       "a.py": "from flask import request\nfrom b import run_cmd\n" + extra_imports
                               + textwrap.dedent(body)})
        return [r for r, f, _ in xs(out) if f == "a.py"]

    def test_expression_forms(self):
        cases = {
            "await": "async def v(request):\n    data = await request.json()\n    run_cmd(data)\n",
            "ifexp": "def v():\n    q = request.args.get('q')\n    run_cmd(q if q else 'x')\n",
            "dict": "def v():\n    d = {'c': request.args['q']}\n    run_cmd(d['c'])\n",
            "listcomp": "def v():\n    xs = [x for x in request.args.getlist('q')]\n    run_cmd(xs[0])\n",
            "dictcomp": "def v():\n    d = {k: v for k, v in request.args.items()}\n    run_cmd(d['a'])\n",
            "genexp": "def v():\n    run_cmd(''.join(x for x in request.args['q']))\n",
            "for": "import sys\ndef v():\n    for arg in sys.argv[1:]:\n        run_cmd(arg)\n",
            "walrus": "def v():\n    if (q := request.args.get('q')):\n        run_cmd(q)\n",
            "match": ("def v(kind):\n    q = request.args['q']\n    match kind:\n"
                      "        case 'a':\n            run_cmd(q)\n"),
            "match-capture": ("def v():\n    match request.args['q']:\n"
                              "        case str() as s:\n            run_cmd(s)\n"),
            "with": "def v():\n    with ctx(request.args['q']) as c:\n        run_cmd(c)\n",
            "try": "def v():\n    try:\n        q = request.args['q']\n    except KeyError:\n        q = ''\n    run_cmd(q)\n",
            "branch-merge": "def v(flag):\n    q = 'safe'\n    if flag:\n        q = request.args['q']\n    run_cmd(q)\n",
            "urljoin": "from urllib.parse import urljoin\ndef v():\n    run_cmd(urljoin('http://192.0.2.1/', request.args['u']))\n",
            "fstring": "def v():\n    run_cmd(f\"ls {request.args['q']}\")\n",
            "generator-helper": ("def gen():\n    yield request.args['q']\n"
                                 "def v():\n    for x in gen():\n        run_cmd(x)\n"),
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.one(body), ["X-CMD"])

    def test_self_attribute_across_methods(self):
        body = ("class V:\n    def load(self):\n        self.q = request.args['q']\n"
                "    def use(self):\n        run_cmd(self.q)\n")
        self.assertEqual(self.one(body), ["X-CMD"])

    def test_module_level_and_main_guard(self):
        """Reviewer repro t1 B / projB: script code was never analyzed."""
        out = analyze({"b.py": RUNNER,
                       "a.py": ("import sys\nfrom b import run_cmd\nrun_cmd(sys.argv[1])\n"
                                "if __name__ == '__main__':\n    run_cmd(sys.argv[1])\n")})
        self.assertEqual(xs(out), [("X-CMD", "a.py", 3), ("X-CMD", "a.py", 5)])

    def test_module_global_read_in_function(self):
        out = analyze({"b.py": RUNNER,
                       "a.py": ("import sys\nfrom b import run_cmd\nARG = sys.argv[1]\n"
                                "def main():\n    run_cmd(ARG)\n")})
        self.assertEqual(xs(out), [("X-CMD", "a.py", 5)])

    def test_clean_results_do_not_propagate(self):
        self.assertEqual(self.one("def v():\n    run_cmd(str(len(request.args['q'])))\n"), [])
        self.assertEqual(self.one("def v():\n    run_cmd(int(request.args['q']))\n"), [])


class ConvergenceAndPerformance(unittest.TestCase):
    def chain(self, depth, caller_first=True):
        defs = [f"def w{i}(x):\n    w{i + 1}(x)\n" for i in range(1, depth)]
        defs.append(f"def w{depth}(x):\n    os.system(x)\n")
        if not caller_first:
            defs.reverse()
        return ("import os\nfrom flask import request\n"
                "def view():\n    w1(request.args['q'])\n" + "".join(defs))

    def test_deep_wrapper_chains(self):
        """MAX_ITERS=6 used to cut chains >= 7 written caller-first."""
        for depth in (7, 12, 30):
            for first in (True, False):
                with self.subTest(depth=depth, caller_first=first):
                    out = analyze({"a.py": self.chain(depth, first)})
                    self.assertEqual([r for r, _, _ in xs(out)], ["X-CMD"])

    def test_iteration_cap_is_visible(self):
        with mock.patch.object(flow, "MAX_ITERS", 1):
            # w1 must be re-analyzed after its callee's summary changes, and
            # the callee is analyzed later (a recursive pair defeats ordering)
            src = ("import os\ndef a(x):\n    b(x)\n    return x\n"
                   "def b(x):\n    a(x)\n    os.system(x)\n")
            out = analyze({"a.py": src})
        self.assertIn("Q-FLOW-INCOMPLETE", [f["rule"] for f in out])

    def test_budgets_are_visible(self):
        findings = []
        files = [{"path": "a.py", "content": self.chain(3), "lang": "py"}]
        flow._analyze_python(files, findings, time_budget=-1)
        self.assertIn("time budget", " ".join(f["name"] for f in findings))
        with mock.patch.object(flow, "FLOW_MAX_FILES", 1):
            out = analyze({"a.py": RUNNER, "b.py": RUNNER})
        notes = [f for f in out if f["rule"] == "Q-FLOW-INCOMPLETE"]
        self.assertEqual(len(notes), 1)
        self.assertIn("1 Python file", notes[0]["msg"])

    def test_many_same_named_methods_scale(self):
        """Reviewer t_perf: 5,000 methods took 27.9 s."""
        files = []
        for k in range(1000):
            files.append({"path": f"m{k}.py", "lang": "py", "content": textwrap.dedent(f"""
                class C{k}(Base):
                    def __init__(self, a, b=None):
                        super().__init__(a)
                        self.a = a
                    def get(self, key, default=None):
                        return self.a.get(key, default)
                    def save(self, data):
                        self.validate(data)
                        return self.get(data)
                    def validate(self, data):
                        return self.get(data)
                    def run(self, x):
                        y = self.get(x)
                        self.save(y)
                        return self.validate(y)
                """)})
        t = time.time()
        flow.analyze(files)
        self.assertLess(time.time() - t, 15)


if __name__ == "__main__":
    unittest.main()
