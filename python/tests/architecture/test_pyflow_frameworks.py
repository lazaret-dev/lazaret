"""The route parameters the engine's Python taint pass takes as request data
(rust/crates/lazaret-engine/src/pyflow/frameworks.rs) against
lazaret.scanner.frameworks, whose decisions the intra-file engine makes:
the two passes must agree on what a handler receives, and until the
intra-file pass is the engine's too (phase 3 of the Rust-first refactor)
the decisions live in both, so a change to one is a change to both.

Each case is a handler whose parameter reaches a project function's sink:
the pass reports the flow exactly when frameworks.py says the framework
fills that parameter with request data — FastAPI's annotations and
defaults (as ast.unparse writes them, which is how the pass reads them),
Django's names and annotations, Flask's URL rule converters. All content
is inert: nothing is executed.
"""
import ast
import itertools
import unittest

from lazaret.scanner import _native, frameworks
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


def unparsed(text):
    return ast.unparse(ast.parse(text, mode="eval")) if text else ""


def flows(src):
    _, args, text = snap.call(snap.files(("m.py", src)))
    return any(o[0] == "issue" for o in _native.call("py_flow", args, text))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RouteParametersAgreeTests(unittest.TestCase):
    maxDiff = None

    def test_fastapi(self):
        aliases = frameworks.dep_aliases("SessionDep = Annotated[Session, Depends(get_db)]\n")
        found = []
        for src, ann, default in fastapi_cases():
            want = frameworks.fastapi_param("p", unparsed(ann), unparsed(default), aliases)
            if flows(src) != want:
                found.append((ann, default, want))
        self.assertEqual(found, [])
        # not vacuous: both answers, many times
        answers = [frameworks.fastapi_param("p", unparsed(a), unparsed(d), aliases) for _, a, d in fastapi_cases()]
        self.assertGreater(answers.count(True), 50)
        self.assertGreater(answers.count(False), 200)

    def test_django(self):
        head = "import os\nfrom typing import Optional\nfrom uuid import UUID\nfrom django.http import HttpResponse\n"
        found = []
        for name, ann in DJANGO:
            sig = name + (f": {ann}" if ann else "")
            src = head + SINK + f"\n\ndef view(request, {sig}):\n    run_it({name})\n    return HttpResponse('x')\n"
            want = frameworks.django_param(name, unparsed(ann))
            if flows(src) != want:
                found.append((name, ann, want))
        self.assertEqual(found, [])

    def test_flask(self):
        found = []
        for rule in FLASK:
            var = rule[1:-1].split(":")[-1]
            src = ("import os\nfrom flask import Flask\napp = Flask(__name__)\n" + SINK
                   + f"\n\n@app.route('/x/{rule}')\ndef view({var}):\n    run_it({var})\n")
            want = var in frameworks.flask_free_vars(f"/x/{rule}")
            if flows(src) != want:
                found.append((rule, want))
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
