//! The intra-file taint pass's helpers (Q-1), on the cases core's own tests held them to when they were core's
//! (test_taint_fstrings, test_review_taint, test_taint_frameworks): what a line's code is once its literals are
//! read, a call's arguments, the names an assignment binds, a handler's parameters, and linear time on the texts
//! built against each. The pass as a whole is held by the recorded sets (test_snapshot_project.py).

use super::*;
use crate::filectx::FileCtx;

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn st(s: &[u32]) -> String {
    pystr::to_string(s)
}

fn words(s: &[u32]) -> Vec<String> {
    st(s).split_whitespace().map(|w| w.to_string()).collect()
}

#[test]
fn code_keeps_the_fields_of_formatted_strings() {
    let p = crate::pack::current();
    assert_eq!(words(&taint_code(&p, &cps(r#"os.system(f"ls {d!r} {{x}}" + rb"q")"#), Lang::Py)),
               ["os.system(", "d!r", "+", ")"]);
    assert_eq!(words(&taint_code(&p, &cps("exec(`ls ${a}`); q = sql`x ${b}`; return `${c}`"), Lang::Js)),
               ["exec(", "a", ");", "q", "=", "sql;", "return", "c"]);
}

#[test]
fn a_calls_arguments() {
    let p = crate::pack::current();
    assert_eq!(st(first_arg(&cps(" (body, {'h': bar}))"))), "body");
    assert_eq!(st(first_arg(&cps(" sql, (x,))"))), " sql");
    let kw = p.re("_KWARG_RE");
    assert_eq!(st(&args_where(&cps(" url, data=d, headers=h)"), |a| kw.match_(a).is_none())), " url");
    assert_eq!(st(extent(&cps("cmd); log(location.href)"))), "cmd");
    assert_eq!(st(extent(&cps(" q; other(req.query)"))), " q");
    let same = p.re("_SAME_SITE_RE");
    assert_eq!(st(&args_where(&cps(" 301, '/x' + y"), |a| same.match_(a).is_none())), " 301");
}

#[test]
fn what_an_assignment_binds() {
    let p = crate::pack::current();
    let bound = |line: &str, lang| assignment(&p, &cps(line), lang).map(|(names, rhs)| {
        (names.iter().map(|n| st(n)).collect::<Vec<_>>(), st(&rhs))
    });
    // a keyword is not a name; a soft keyword is, unless a block follows it
    assert_eq!(bound("else: x = request.args['a']", Lang::Py), None);
    assert_eq!(bound("case y: z = input()", Lang::Py), None);
    assert_eq!(bound("match = input()", Lang::Py), Some((vec!["match".to_string()], "input()".to_string())));
    assert_eq!(bound("x == input()", Lang::Py), None);
    assert_eq!(bound("const { id, path: p } = req.params;", Lang::Js),
               Some((vec!["id".to_string(), "p".to_string()], "req.params;".to_string())));
    let names = |pat: &str| destructured_names(&p, &cps(pat)).iter().map(|n| st(n)).collect::<Vec<_>>();
    assert_eq!(names("{ a, b: c, d = 1, ...e }"), ["a", "c", "d", "e"]);
    assert_eq!(names("[a, , b = 2, ...c]"), ["a", "b", "c"]);
}

#[test]
fn indexes_guards_and_containers() {
    // (the cases the npm package's twin of this pass was held to: js/test/taint-frameworks.test.js)
    let p = crate::pack::current();
    assert_eq!(st(&drop_indexes(&p, cps("exec(o['x'] + xs[i])"))), format!("exec(o{} + xs{})", " ".repeat(5), " ".repeat(3)));
    let guard = |stmt: &str, lang| allow_guard(&p, &cps(stmt), lang).map(|(n, c, neg)| (st(&n), st(&c), neg));
    assert_eq!(guard("if (ALLOWED.includes(f)) {", Lang::Js), Some(("f".to_string(), "ALLOWED".to_string(), false)));
    assert_eq!(guard("if name not in PLUGINS:", Lang::Py), Some(("name".to_string(), "PLUGINS".to_string(), true)));
    let write = |line: &str, lang| container_write(&p, &cps(line), lang).map(|(c, v)| (st(&c), st(&v)));
    assert_eq!(write("  arr.push(q);", Lang::Js), Some(("arr".to_string(), "q".to_string())));
    assert_eq!(write("d['k'] = q", Lang::Py), Some(("d".to_string(), "q".to_string())));
    assert_eq!(write("if x[0] = q", Lang::Py), None);
    let parts: Vec<String> = frameworks::top_split(&cps("a, (b, c), 'd,e', f"), ',' as u32).iter().map(|x| st(x)).collect();
    assert_eq!(parts, ["a", " (b, c)", " 'd,e'", " f"]);
}

#[test]
fn view_bodies_scopes_and_guards() {
    let p = crate::pack::current();
    assert!(!view_body(&p, &cps(" User.to_dict(q, page=1)")), "a call of a function that builds no string");
    assert!(view_body(&p, &cps(" str(q)")));
    assert!(scope_opener(&p, &cps("app.get('/a', (req, res) => {"), Lang::Js));
    assert!(!scope_opener(&p, &cps("if (x) {"), Lang::Js));
    assert!(scope_opener(&p, &cps("async def f(a):"), Lang::Py));
    let names: Vec<String> = guarded_names(&p, &cps("if '..' in name or not p.startswith(BASE):"), Lang::Py)
        .iter().map(|n| st(n)).collect();
    assert_eq!(names, ["name", "p"]);
}

#[test]
fn a_handlers_parameters() {
    let p = crate::pack::current();
    let sig = cps("def f(self, a: dict[str, int] = {'x': 1}, *args, b=f(1, 2), **kw):");
    let got: Vec<(String, String, String)> =
        signature_params(&p, &sig).iter().map(|(n, a, d)| (st(n), st(a), st(d))).collect();
    let want = [("self", "", ""), ("a", "dict[str, int]", "{'x': 1}"), ("args", "", ""), ("b", "", "f(1, 2)"),
                ("kw", "", "")];
    assert_eq!(got, want.iter().map(|(n, a, d)| (n.to_string(), a.to_string(), d.to_string())).collect::<Vec<_>>());
    let src = cps("from fastapi import FastAPI, Depends, Request, WebSocket, BackgroundTasks\n\
                   from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse\n\
                   from typing import Optional, Annotated, Literal\nimport os, subprocess\napp = FastAPI()\n\
                   @app.get('/x/{a}')\nasync def x(a: str, b: int, c = Depends(f), d: Kind = Kind.one,\n            \
                   e: Annotated[str, Query()] = None, f: Response = None):\n    pass\n");
    let ctx = FileCtx::new(&p, &src, Lang::Py, false);
    let routes = route_params(&p, &ctx);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[&6].iter().map(|n| st(n)).collect::<Vec<_>>(), ["a", "e"]);
}

#[test]
fn the_helpers_take_linear_time() {
    let p = crate::pack::current();
    let texts = ["(".repeat(200_000), "'".repeat(200_000), "a,".repeat(200_000), "f'{".repeat(100_000),
                 "=>".repeat(200_000) + " {", "a.".repeat(200_000) + "get(type=int)", " ".repeat(100_000) + "if '..' in x:"];
    let kw = p.re("_KWARG_RE");
    let same = p.re("_SAME_SITE_RE");
    for text in &texts {
        let t = cps(text);
        let t0 = std::time::Instant::now();
        let _ = (first_arg(&t), args_where(&t, |a| kw.match_(a).is_none()), extent(&t),
                 args_where(&t, |a| same.match_(a).is_none()));
        let _ = (taint_code(&p, &t, Lang::Py), taint_code(&p, &t, Lang::Js));
        let _ = (scope_opener(&p, &t, Lang::Js), guarded_names(&p, &t, Lang::Py), assignment(&p, &t, Lang::Py));
        assert!(t0.elapsed().as_secs() < 10, "{}", &text[..12]);
    }
}
