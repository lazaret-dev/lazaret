"""Web framework models shared by both taint engines (0.1.7).

The intra-file engine (lazaret.scanner.core, line-based: _route_params) and
the interprocedural engine (the native engine's Python taint pass) both need
to know which parameters of a route handler a framework fills from the
request. The decisions live here, over the text of a parameter's name,
annotation and default, and in the native engine's port of them
(rust/crates/lazaret-engine/src/pyflow/frameworks.rs), which
tests/architecture/test_pyflow_frameworks.py holds to the same answers, so
the two engines agree: a change here is a change there. The npm engine's
twin of the intra-file half is js/src/scanner/taint.js (routeParams).

* Flask / Quart: a view takes the variables of its URL rules (`<name>`,
  `<path:name>`); an int, float, uuid or any(…) converter gives no text an
  attacker chooses (flask_free_vars).
* FastAPI: a path operation takes every parameter from the request but what
  FastAPI injects — a Depends(…) or Security(…) default or annotation, an
  alias of one (`SessionDep = Annotated[Session, Depends(get_db)]` in the
  file: dep_aliases; an annotation named …Dep / …Deps imported from another),
  Response, BackgroundTasks, SecurityScopes — and what it validates to no
  free text: int, float, bool, UUID, Decimal, the date and time types,
  constrained numbers and Literal[…], also inside Optional[…], Annotated[…],
  a list, set or tuple, or a union with None (safe_type), and an Enum's
  value (a parameter whose default is a member of its annotation, `kind:
  Kind = Kind.a`). A Request, WebSocket or HTTPConnection parameter is not a
  source itself — much of it is the server's (request.state, request.app) —
  but what is read from it is (request.query_params, request.headers,
  websocket.receive_text()): fastapi_param.
* Django: a view's parameters after `request` come from the URL pattern, but
  for the names a pattern fills with an int or a slug by convention (pk, id,
  slug, year, month, day, …_id, …_pk, …_slug) and those annotated with a
  type as above (`code: UUID, n: int`): django_param.

Pure functions over text; no Lazaret imports.
"""
import re

FLASK_VAR_RE = re.compile(r"<(?:(\w+)(?:\([^()<>]*\))?:)?(\w+)>")
FLASK_SAFE_CONVERTERS = frozenset(("int", "float", "uuid", "any"))
FASTAPI_INJECTED_RE = re.compile(r"(?<![\w.])(?:[\w.]*\.)?(?:Depends|Security)\s*\(")
FASTAPI_FRAMEWORK_TYPES = frozenset((
    "Response", "BackgroundTasks", "SecurityScopes", "Request", "WebSocket", "HTTPConnection",
    "fastapi.Response", "fastapi.BackgroundTasks", "fastapi.security.SecurityScopes", "fastapi.Request",
    "fastapi.WebSocket", "starlette.requests.Request", "starlette.requests.HTTPConnection",
    "starlette.websockets.WebSocket", "starlette.responses.Response", "starlette.background.BackgroundTasks"))
SAFE_TYPES = frozenset((
    "int", "float", "bool", "complex", "None", "UUID", "uuid.UUID", "UUID1", "UUID3", "UUID4", "UUID5",
    "pydantic.UUID4", "Decimal", "decimal.Decimal", "datetime", "datetime.datetime", "date", "datetime.date",
    "time", "datetime.time", "timedelta", "datetime.timedelta", "AwareDatetime", "NaiveDatetime", "PastDate",
    "FutureDate", "PastDatetime", "FutureDatetime", "StrictInt", "StrictFloat", "StrictBool", "PositiveInt",
    "NegativeInt", "NonNegativeInt", "NonPositiveInt", "PositiveFloat", "NegativeFloat", "NonNegativeFloat",
    "NonPositiveFloat", "FiniteFloat"))
TYPE_ARG_RE = re.compile(r"(?:typing(?:_extensions)?\.)?(\w+)\s*\[(.*)\]\s*\Z", re.S)
CONSTRAINED_NUMBER_RE = re.compile(r"(?:pydantic\.)?con(?:int|float|decimal)\s*\(")
TYPE_ALL_MEMBERS = frozenset(("Union", "List", "list", "Set", "set", "FrozenSet", "frozenset", "Sequence",
                              "Tuple", "tuple", "Iterable", "Collection"))
DJANGO_ID_RE = re.compile(r"(?:pk|id|slug|year|month|day|\w+_(?:id|pk|slug))\Z")
DEP_ALIAS_NAME_RE = re.compile(r"(?:[\w.]*\.)?\w*Deps?\Z")
DEP_ALIAS_DEF_RE = re.compile(
    r"(?<![^\n])([A-Za-z_]\w*)[ \t]*(?::[ \t]*[\w.]+[ \t]*)?=[ \t]*(?:typing(?:_extensions)?\.)?Annotated[ \t]*\["
    r"[^\n]*\b(?:Depends|Security)\s*\(")
ENUM_DEFAULT_RE = re.compile(r"([A-Za-z_][\w.]*)\.[A-Za-z_]\w*\Z")
ROUTE_TYPE_DEPTH = 8             # wrappers read inside one annotation
# the decorators that route a request to a function, by framework
FLASK_ROUTE_METHODS = frozenset(("route", "get", "post", "put", "patch", "delete"))
FASTAPI_ROUTE_METHODS = frozenset(("get", "post", "put", "patch", "delete", "options", "head", "api_route",
                                   "websocket"))


def top_split(text, sep):
    """`text` split at the `sep` characters outside brackets and string
    literals."""
    parts, depth, start, i, n = [], 0, 0, 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = text.find(ch, i + 1)
            if j < 0:
                break
            i = j + 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == sep and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def safe_type(ann, depth=0):
    """Does FastAPI validate a value of annotation `ann` to no free text?"""
    ann = ann.strip()
    if not ann or depth > ROUTE_TYPE_DEPTH:
        return False
    union = top_split(ann, "|")
    if len(union) > 1:
        return all(safe_type(member, depth + 1) for member in union)
    if ann in SAFE_TYPES or CONSTRAINED_NUMBER_RE.match(ann):
        return True
    m = TYPE_ARG_RE.match(ann)
    if not m:
        return False
    kind, args = m.group(1), top_split(m.group(2), ",")
    if kind == "Literal":
        return True
    if kind in ("Optional", "Annotated", "Required", "NotRequired"):
        return safe_type(args[0], depth + 1)
    if kind in TYPE_ALL_MEMBERS:
        return all(safe_type(a, depth + 1) for a in args if a.strip() != "...")
    return False


def enum_default(ann, default):
    """Is `default` a member of the class `ann` names (an Enum's value)?"""
    m = ENUM_DEFAULT_RE.match(default)
    return bool(m) and m.group(1) == ann


def dep_aliases(text):
    """The names `text` binds to an Annotated[…, Depends(…)] alias."""
    return frozenset(m.group(1) for m in DEP_ALIAS_DEF_RE.finditer(text))


def fastapi_param(name, ann, default, aliases=frozenset()):
    """Does a FastAPI path operation fill parameter `name` (annotation
    `ann`, default `default`, as text) with request data?"""
    if name in ("self", "cls") or FASTAPI_INJECTED_RE.search(ann) or FASTAPI_INJECTED_RE.search(default):
        return False
    if ann in FASTAPI_FRAMEWORK_TYPES or ann in aliases or DEP_ALIAS_NAME_RE.match(ann):
        return False
    return not (ann and (safe_type(ann) or enum_default(ann, default)))


def flask_free_vars(rule):
    """The variables of Flask URL rule `rule` that hold free text."""
    return {m.group(2) for m in FLASK_VAR_RE.finditer(rule or "")
            if (m.group(1) or "string") not in FLASK_SAFE_CONVERTERS}


def django_param(name, ann):
    """Does a Django URL pattern fill a view's parameter `name` (after
    `request`; annotation `ann`) with free text?"""
    return not DJANGO_ID_RE.match(name) and not (ann and safe_type(ann))
