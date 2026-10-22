"""The route parameters a handler takes from the request, as the engine's two
Python taint passes read them (rust/crates/lazaret-engine/src/pyflow/
frameworks.rs): the cross-file pass (py_flow) and project mode's intra-file
pass (scan_file, taint.rs) must agree on what a handler receives, and both
are held to the decisions recorded here from lazaret.scanner.frameworks when
the intra-file pass moved into the engine (Q-1, 0.1.9) and that module was
retired: a change in one is a change in what both report.

Each case is a handler whose parameter reaches a sink, through a project
function (the cross-file pass) or in its own body (the intra-file pass):
the pass reports the flow exactly when the framework fills that parameter
with request data — FastAPI's annotations and defaults (as ast.unparse
writes them, which is how the passes read them), Django's names and
annotations, Flask's URL rule converters. All content is inert: nothing is
executed.
"""
import ast
import itertools
import unittest

from lazaret.scanner import _native
from tests.architecture import test_snapshot_py_flow as snap

FASTAPI_ANNS = ["", "str", "int", "float", "bool", "UUID", "uuid.UUID", "Optional[str]", "Optional[int]",
                "Annotated[str, Query()]", "Annotated[int, Query(gt=0)]", "Annotated[Session, Depends(get_db)]",
                "list[int]", "list[str]", "List[int]", "set[UUID]", "dict[str, int]", "str | None", "int | None",
                "int | str", "Literal['a', 'b']", "Kind", "conint(gt=1)", "pydantic.constr(max_length=3)",
                "Request", "Response", "BackgroundTasks", "WebSocket", "Session", "SessionDep", "UserDeps",
                "typing.Optional[str]", "tuple[int, ...]", "Union[int, float]", "Union[int, str]", "datetime",
                "Path", "EmailStr", "Annotated[str, Security(scheme)]", "Optional[Annotated[int, Query()]]"]
FASTAPI_DEFAULTS = ["", "None", "Query(None)", "Depends(get_db)", "Security(scheme)", "Kind.a", "Other.a", "'x'",
                    "0", "Body(...)", "fastapi.Depends()"]
DJANGO = [("slug", ""), ("pk", ""), ("user_id", ""), ("name", ""), ("q", "str"), ("q", "int"), ("year", ""),
          ("term", "Optional[int]"), ("term", "Optional[str]"), ("page_slug", ""), ("ident", "UUID")]
FLASK = ["<cmd>", "<int:n>", "<path:p>", "<uuid:u>", "<string:s>", "<float:f>", "<any(a, b):k>", "<custom:c>"]
SINK = "\n\ndef run_it(x):\n    os.system(x)\n"
# Is the parameter request data? One row per annotation of FASTAPI_ANNS, one column per default of
# FASTAPI_DEFAULTS; Django's cases and Flask's rules in their order (frameworks.py's answers, Oct 7, 2026).
FASTAPI_WANT = ("11100111110", "11100111110", "00000000000", "00000000000", "00000000000", "00000000000",
                "00000000000", "11100111110", "00000000000", "11100111110", "00000000000", "00000000000",
                "00000000000", "11100111110", "00000000000", "00000000000", "11100111110", "11100111110",
                "00000000000", "11100111110", "00000000000", "11100011110", "00000000000", "11100111110",
                "00000000000", "00000000000", "00000000000", "00000000000", "11100111110", "00000000000",
                "00000000000", "11100111110", "00000000000", "00000000000", "11100111110", "00000000000",
                "11100111110", "11100111110", "00000000000", "00000000000")
DJANGO_WANT = "00011000100"
FLASK_WANT = "10101001"


def fastapi_cases():
    head = ("import os\nimport uuid\nimport pydantic\nimport fastapi\nfrom enum import Enum\nfrom datetime import datetime\n"
            "from typing import Annotated, List, Literal, Optional, Union\nfrom uuid import UUID\n"
            "from fastapi import APIRouter, BackgroundTasks, Body, Depends, FastAPI, Query, Request, Response, "
            "Security, WebSocket\nfrom pydantic import EmailStr, conint\napp = FastAPI()\n"
            "SessionDep = Annotated[Session, Depends(get_db)]\n\nclass Kind(str, Enum):\n    a = 'a'\n")
    out = []
    for ann, default in itertools.product(FASTAPI_ANNS, FASTAPI_DEFAULTS):
        sig = "p" + (f": {ann}" if ann else "") + (f" = {default}" if default else "")
        src = head + SINK + f"\n\n@app.get('/x')\ndef handler({sig}):\n    run_it(p)\n"
        out.append((src, ann, default))
    return out


def flows(src):
    """Does the cross-file pass report the handler's flow into run_it's sink?"""
    _, args, text = snap.call(snap.files(("m.py", src)))
    return any(o[0] == "issue" for o in _native.call("py_flow", args, text))


def flows_here(src):
    """Does project mode's intra-file pass report the handler's own sink (T-CMD)?"""
    args = {"lang": "py", "dep": False, "jsx": True, "redact": True}
    return any(i[0] == "T-CMD" for i in _native.call("scan_file", args, src))


def wanted(row):
    return [c == "1" for c in row]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RouteParametersTests(unittest.TestCase):
    maxDiff = None

    def test_fastapi(self):
        want = [w for row in FASTAPI_WANT for w in wanted(row)]
        cases = fastapi_cases()
        self.assertEqual(len(cases), len(want))
        found = []
        for (src, ann, default), w in zip(cases, want):
            here = src.replace("    run_it(p)\n", "    os.system(p)\n")
            if flows(src) != w or flows_here(here) != w:
                found.append((ann, default, w, flows(src), flows_here(here)))
        self.assertEqual(found, [])
        # not vacuous: both answers, many times
        self.assertGreater(want.count(True), 50)
        self.assertGreater(want.count(False), 200)

    def test_django(self):
        head = "import os\nfrom typing import Optional\nfrom uuid import UUID\nfrom django.http import HttpResponse\n"
        found = []
        for (name, ann), w in zip(DJANGO, wanted(DJANGO_WANT)):
            sig = name + (f": {ann}" if ann else "")
            src = head + SINK + f"\n\ndef view(request, {sig}):\n    run_it({name})\n    return HttpResponse('x')\n"
            here = src.replace(f"    run_it({name})\n", f"    os.system({name})\n")
            if flows(src) != w or flows_here(here) != w:
                found.append((name, ann, w))
        self.assertEqual(found, [])

    def test_flask(self):
        found = []
        for rule, w in zip(FLASK, wanted(FLASK_WANT)):
            var = rule[1:-1].split(":")[-1]
            src = ("import os\nfrom flask import Flask\napp = Flask(__name__)\n" + SINK
                   + f"\n\n@app.route('/x/{rule}')\ndef view({var}):\n    run_it({var})\n")
            here = src.replace(f"    run_it({var})\n", f"    os.system({var})\n")
            if flows(src) != w or flows_here(here) != w:
                found.append((rule, w))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
