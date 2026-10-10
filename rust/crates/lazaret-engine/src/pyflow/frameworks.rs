//! Web framework models (lazaret.scanner.frameworks, 0.1.7): which
//! parameters of a route handler a framework fills from the request,
//! decided over the text of a parameter's name, annotation and default (as
//! `ast.unparse` writes them: `unparse.rs`).
//!
//! * Flask / Quart: a view takes the variables of its URL rules (`<name>`,
//!   `<path:name>`); an int, float, uuid or any(…) converter gives no text an
//!   attacker chooses (`flask_free_vars`).
//! * FastAPI: a path operation takes every parameter from the request but
//!   what FastAPI injects (Depends / Security, an alias of one, Response,
//!   BackgroundTasks, SecurityScopes, Request, WebSocket, HTTPConnection)
//!   and what it validates to no free text (`safe_type`, an Enum's value):
//!   `fastapi_param`.
//! * Django: a view's parameters after `request`, but for the names a URL
//!   pattern fills with an int or a slug by convention and those annotated
//!   with a safe type: `django_param`.
//!
//! The intra-file engine (Python's core, and the npm package's taint.js)
//! decides with lazaret.scanner.frameworks itself, so the two passes must
//! agree on what a handler receives: a change to one is a change to the
//! other (python/tests/architecture/test_pyflow_frameworks.py holds them to
//! the same answers).

use crate::pyre::Regex;
use crate::pystr::{self, PyStr};
use std::rc::Rc;

pub const FLASK_VAR_RE: &str = r"<(?:(\w+)(?:\([^()<>]*\))?:)?(\w+)>";
pub const FLASK_SAFE_CONVERTERS: &[&str] = &["int", "float", "uuid", "any"];
pub const FASTAPI_INJECTED_RE: &str = r"(?<![\w.])(?:[\w.]*\.)?(?:Depends|Security)\s*\(";
pub const FASTAPI_FRAMEWORK_TYPES: &[&str] = &[
    "Response", "BackgroundTasks", "SecurityScopes", "Request", "WebSocket", "HTTPConnection", "fastapi.Response",
    "fastapi.BackgroundTasks", "fastapi.security.SecurityScopes", "fastapi.Request", "fastapi.WebSocket",
    "starlette.requests.Request", "starlette.requests.HTTPConnection", "starlette.websockets.WebSocket",
    "starlette.responses.Response", "starlette.background.BackgroundTasks",
];
pub const SAFE_TYPES: &[&str] = &[
    "int", "float", "bool", "complex", "None", "UUID", "uuid.UUID", "UUID1", "UUID3", "UUID4", "UUID5",
    "pydantic.UUID4", "Decimal", "decimal.Decimal", "datetime", "datetime.datetime", "date", "datetime.date", "time",
    "datetime.time", "timedelta", "datetime.timedelta", "AwareDatetime", "NaiveDatetime", "PastDate", "FutureDate",
    "PastDatetime", "FutureDatetime", "StrictInt", "StrictFloat", "StrictBool", "PositiveInt", "NegativeInt",
    "NonNegativeInt", "NonPositiveInt", "PositiveFloat", "NegativeFloat", "NonNegativeFloat", "NonPositiveFloat",
    "FiniteFloat",
];
/// (matched with re.S)
pub const TYPE_ARG_RE: &str = r"(?:typing(?:_extensions)?\.)?(\w+)\s*\[(.*)\]\s*\Z";
pub const CONSTRAINED_NUMBER_RE: &str = r"(?:pydantic\.)?con(?:int|float|decimal)\s*\(";
pub const TYPE_ALL_MEMBERS: &[&str] =
    &["Union", "List", "list", "Set", "set", "FrozenSet", "frozenset", "Sequence", "Tuple", "tuple", "Iterable", "Collection"];
pub const DJANGO_ID_RE: &str = r"(?:pk|id|slug|year|month|day|\w+_(?:id|pk|slug))\Z";
pub const DEP_ALIAS_NAME_RE: &str = r"(?:[\w.]*\.)?\w*Deps?\Z";
pub const DEP_ALIAS_DEF_RE: &str = concat!(
    r"(?<![^\n])([A-Za-z_]\w*)[ \t]*(?::[ \t]*[\w.]+[ \t]*)?=[ \t]*(?:typing(?:_extensions)?\.)?Annotated[ \t]*\[",
    r"[^\n]*\b(?:Depends|Security)\s*\("
);
pub const ENUM_DEFAULT_RE: &str = r"([A-Za-z_][\w.]*)\.[A-Za-z_]\w*\Z";
/// wrappers read inside one annotation
pub const ROUTE_TYPE_DEPTH: usize = 8;
/// the decorators that route a request to a function, by framework
pub const FLASK_ROUTE_METHODS: &[&str] = &["route", "get", "post", "put", "patch", "delete"];
pub const FASTAPI_ROUTE_METHODS: &[&str] =
    &["get", "post", "put", "patch", "delete", "options", "head", "api_route", "websocket"];

const DOTALL: u32 = 16;

fn rx(src: &str, flags: u32) -> Rc<Regex> {
    crate::rxutil::dynamic(pystr::u(src), flags)
}

pub fn is_in(s: &[u32], list: &[&str]) -> bool {
    list.iter().any(|w| pystr::eq(s, w))
}

/// `text` split at the `sep` characters outside brackets and string
/// literals (frameworks.top_split).
pub fn top_split(text: &[u32], sep: u32) -> Vec<&[u32]> {
    let mut parts = Vec::new();
    let (mut depth, mut start, mut i, n) = (0i64, 0usize, 0usize, text.len());
    while i < n {
        let ch = text[i];
        if ch == 0x22 || ch == 0x27 {
            match text[i + 1..].iter().position(|&c| c == ch) {
                None => break,
                Some(k) => {
                    i = i + 1 + k + 1;
                    continue;
                }
            }
        }
        if ch == 0x28 || ch == 0x5B || ch == 0x7B {
            depth += 1;
        } else if ch == 0x29 || ch == 0x5D || ch == 0x7D {
            depth = (depth - 1).max(0);
        } else if ch == sep && depth == 0 {
            parts.push(&text[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    parts.push(&text[start..]);
    parts
}

/// Does FastAPI validate a value of annotation `ann` to no free text?
pub fn safe_type(ann: &[u32], depth: usize) -> bool {
    let ann = pystr::strip(ann);
    if ann.is_empty() || depth > ROUTE_TYPE_DEPTH {
        return false;
    }
    let union = top_split(ann, 0x7C);
    if union.len() > 1 {
        return union.iter().all(|m| safe_type(m, depth + 1));
    }
    if is_in(ann, SAFE_TYPES) || rx(CONSTRAINED_NUMBER_RE, 0).match_(ann).is_some() {
        return true;
    }
    let r = rx(TYPE_ARG_RE, DOTALL);
    let m = match r.match_(ann) {
        Some(m) => m,
        None => return false,
    };
    let kind = m.group(1).unwrap_or(&[]).to_vec();
    let inner = m.group(2).unwrap_or(&[]).to_vec();
    let args = top_split(&inner, 0x2C);
    if pystr::eq(&kind, "Literal") {
        return true;
    }
    if is_in(&kind, &["Optional", "Annotated", "Required", "NotRequired"]) {
        return safe_type(args[0], depth + 1);
    }
    if is_in(&kind, TYPE_ALL_MEMBERS) {
        return args.iter().filter(|a| !pystr::eq(pystr::strip(a), "...")).all(|a| safe_type(a, depth + 1));
    }
    false
}

/// Is `default` a member of the class `ann` names (an Enum's value)?
pub fn enum_default(ann: &[u32], default: &[u32]) -> bool {
    let r = rx(ENUM_DEFAULT_RE, 0);
    match r.match_(default) {
        Some(m) => m.group(1).unwrap_or(&[]) == ann,
        None => false,
    }
}

/// The names `text` binds to an Annotated[…, Depends(…)] alias.
pub fn dep_aliases(text: &[u32]) -> Vec<PyStr> {
    let r = rx(DEP_ALIAS_DEF_RE, 0);
    let mut out: Vec<PyStr> = Vec::new();
    for m in r.finditer(text) {
        let name = m.group(1).unwrap_or(&[]).to_vec();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Does a FastAPI path operation fill parameter `name` (annotation `ann`,
/// default `default`, as text) with request data?
pub fn fastapi_param(name: &[u32], ann: &[u32], default: &[u32], aliases: &[PyStr]) -> bool {
    let injected = rx(FASTAPI_INJECTED_RE, 0);
    if pystr::eq(name, "self")
        || pystr::eq(name, "cls")
        || injected.search(ann).is_some()
        || injected.search(default).is_some()
    {
        return false;
    }
    if is_in(ann, FASTAPI_FRAMEWORK_TYPES)
        || aliases.iter().any(|a| a.as_slice() == ann)
        || rx(DEP_ALIAS_NAME_RE, 0).match_(ann).is_some()
    {
        return false;
    }
    !(!ann.is_empty() && (safe_type(ann, 0) || enum_default(ann, default)))
}

/// The variables of Flask URL rule `rule` that hold free text.
pub fn flask_free_vars(rule: &[u32]) -> Vec<PyStr> {
    let r = rx(FLASK_VAR_RE, 0);
    let mut out: Vec<PyStr> = Vec::new();
    for m in r.finditer(rule) {
        let conv = match m.group(1) {
            Some(g) => g.to_vec(),
            None => pystr::u("string"),
        };
        if is_in(&conv, FLASK_SAFE_CONVERTERS) {
            continue;
        }
        let name = m.group(2).unwrap_or(&[]).to_vec();
        if !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Does a Django URL pattern fill a view's parameter `name` (after
/// `request`; annotation `ann`) with free text?
pub fn django_param(name: &[u32], ann: &[u32]) -> bool {
    rx(DJANGO_ID_RE, 0).match_(name).is_none() && !(!ann.is_empty() && safe_type(ann, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> PyStr {
        pystr::u(s)
    }

    #[test]
    fn annotations_fastapi_validates_to_no_free_text() {
        // (the cases lazaret.scanner.frameworks was held to until it was retired: Q-1, 0.1.9)
        assert!(safe_type(&u("Optional[Annotated[list[uuid.UUID], Query()]]"), 0));
        assert!(safe_type(&u("int | None"), 0));
        assert!(safe_type(&u("Literal['a', 'b']"), 0));
        assert!(safe_type(&u("conint(gt=1)"), 0));
        assert!(!safe_type(&u("Union[int, str]"), 0));
        assert!(!safe_type(&u("dict[str, int]"), 0));
        assert!(!safe_type(&u("str"), 0));
        let deep = format!("{}int{}", "Optional[".repeat(20), "]".repeat(20));
        assert!(!safe_type(&u(&deep), 0), "wrappers past ROUTE_TYPE_DEPTH are not read");
        assert_eq!(flask_free_vars(&u("/x/<cmd>/<int:n>/<path:p>/<any(a, b):k>")), vec![u("cmd"), u("p")]);
        assert!(django_param(&u("q"), &u("")) && !django_param(&u("user_id"), &u("")) && !django_param(&u("q"), &u("int")));
    }
}
