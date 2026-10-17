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
fn what_a_for_statement_binds() {
    // (Q-2) its targets, to what it iterates over
    let p = crate::pack::current();
    let bound = |line: &str| for_targets(&p, &cps(line)).map(|(names, rhs)| {
        (names.iter().map(|n| st(n)).collect::<Vec<_>>(), st(&rhs))
    });
    let one = |n: &str, rhs: &str| Some((vec![n.to_string()], rhs.to_string()));
    assert_eq!(bound("for name in request.args.keys():"), one("name", "request.args.keys()"));
    assert_eq!(bound("    async for (k, v) in items(q): pass"), Some((vec!["k".to_string(), "v".to_string()], "items(q)".to_string())));
    assert_eq!(bound("for x in d[1:]:"), one("x", "d[1:]"));
    assert_eq!(bound("for index in range(3):"), one("index", "range(3)"));
    assert_eq!(bound("for a.b in xs:"), None);
    assert_eq!(bound("for x[0] in xs:"), None);
    assert_eq!(bound("format = input()"), None);
    // what assignment() answers for a Python line, not a JavaScript one
    assert_eq!(assignment(&p, &cps("for q in input():"), Lang::Py).map(|(n, _)| n.len()), Some(1));
    assert_eq!(assignment(&p, &cps("for q in input():"), Lang::Js), None);
}

#[test]
fn keyed_sets_and_gets() {
    // (Q-2) set(<literals>, value) under the key its literals make; get(<literals>) reading it, in Python
    let p = crate::pack::current();
    let key = |stmt: &str, name: &str| keyed_set(&p, &cps(stmt), &cps(name)).map(|k| st(&k));
    assert_eq!(key("conf.set('s', \"keyB\", value)", "conf"), Some("s\u{0}keyB".to_string()));
    assert_eq!(key("cache.set('k', v,)", "cache"), Some("k".to_string()));
    assert_eq!(key("conf.set(section, 'k', v)", "conf"), None);
    assert_eq!(key("conf.set('k')", "conf"), None);
    assert_eq!(key("conf.set('a', 'b', v)", "other"), None);
    let mut keyed: Keyed = HashMap::new();
    keyed.insert(cps("conf"), vec![(cps("s\u{0}a"), None), (cps("s\u{0}b"), Some(Vec::new()))]);
    keyed.insert(cps("d"), vec![(cps("k"), None)]);
    let text = "x = conf.get('s', 'a') + conf.get('s', 'b') + d.get('k') + d['k'] + d.get('k', 'z')";
    assert_eq!(st(&keyed_reads(&p, &cps(text), &keyed, Lang::Py)),
               format!("x = {} + conf.get('s', 'b') + {} + {} + d.get('k', 'z')", " ".repeat(18), " ".repeat(10), " ".repeat(6)));
    assert_eq!(st(&keyed_reads(&p, &cps("y = d.get('k') + d['k']"), &keyed, Lang::Js)), format!("y = d.get('k') + {}", " ".repeat(6)));
    assert_eq!(call_args(&cps(" a, f(b, c), 'd,e',)")).iter().map(|a| st(a)).collect::<Vec<_>>(), [" a", " f(b, c)", " 'd,e'"]);
}

#[test]
fn a_rows_named_arguments() {
    // (Q-2) a sink row's seventh field; the rest of the statement for the session's key and value
    let p = crate::pack::current();
    assert!(ArgMode::named(&cps("rest")) == Some(ArgMode::Rest) && ArgMode::named(&cps("all")).is_none());
    assert_eq!(st(&sink_args(&p, &cps("[key] = value; other(q)"), ArgMode::Rest, &cps("TRUST"))), "[key] = value; other(q)");
    let rows = base_sinks(&p, "py");
    let mode = |suffix: &str| rows.iter().filter(|r| st(&r.suffix) == suffix).map(|r| r.mode).collect::<Vec<_>>();
    assert!(mode("TRUST") == [ArgMode::Rest, ArgMode::Extent] && mode("XPATH") == [ArgMode::First, ArgMode::Positional]);
    assert!(mode("LDAP") == [ArgMode::Extent] && mode("SQL") == [ArgMode::First, ArgMode::Extent]);
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
fn a_parsed_urls_host_checked() {
    // (Q-5) what a name holds of a parsed URL, and the checks of its host that guard a redirect
    let p = crate::pack::current();
    let none = |_: &[u32], _: bool| -> Option<PyStr> { None };
    let held = |rhs: &str| parsed_value(&p, &cps(rhs), &none).map(|(u, h)| (st(&u), h));
    assert_eq!(held(" urllib.parse.urlparse(next_url)"), Some(("next_url".to_string(), false)));
    assert_eq!(held("urlsplit( u, scheme='https' ).hostname.lower()"), Some(("u".to_string(), true)));
    assert_eq!(held("urlparse(a + b)"), None);
    assert_eq!(held("urlparse(u)[1]"), None);
    assert_eq!(held("p.netloc"), None, "p holds no parsed URL");
    let live = |n: &[u32], host: bool| -> Option<PyStr> {
        match (st(n).as_str(), host) {
            ("p", false) => Some(cps("u")),
            ("h", true) => Some(cps("w")),
            _ => None,
        }
    };
    assert_eq!(parsed_value(&p, &cps("p.hostname"), &live).map(|(u, h)| (st(&u), h)), Some(("u".to_string(), true)));
    assert_eq!(if_test(&p, &cps("elif (x := f(a)) in {'k': 1} or y: return")).map(st), Some(" (x := f(a)) in {'k': 1} or y".to_string()));
    let parts = |t: &str, w: &str| bool_parts(&cps(t), w).iter().map(|x| st(x)).collect::<Vec<_>>();
    assert_eq!(parts("a or (b or c) or 'x or y' or floor or order", "or"), ["a ", " (b or c) ", " 'x or y' ", " floor ", " order"]);
    assert_eq!(st(unparen(&cps(" ((a and b)) "))), "a and b");
    assert_eq!(st(unparen(&cps("(a) or (b)"))), "(a) or (b)");
    let guards = |stmt: &str| host_guards(&p, &cps(stmt), &live).iter().map(|(u, c, n)| (st(u), st(c), *n)).collect::<Vec<_>>();
    let one = |u: &str, c: &str, n: bool| vec![(u.to_string(), c.to_string(), n)];
    assert_eq!(guards("if urlparse(x).netloc in ALLOWED:"), one("x", "ALLOWED", false));
    assert_eq!(guards("if p.netloc not in ['a.invalid', ''] or p.scheme not in ('http', 'https'):"),
               one("u", "['a.invalid', '']", true));
    assert_eq!(guards("if (p.scheme == 'https' and (h in settings.HOSTS)):"), one("w", "settings.HOSTS", false));
    assert_eq!(guards("if urllib.parse.urlsplit(x).hostname.lower() not in allowed(): abort(400)"), one("x", "allowed()", true));
    for stmt in ["if urlparse(x).netloc in ALLOWED or x:", "if urlparse(x).netloc not in ALLOWED and x:",
                 "if urlparse(x).netloc in 'a.invalid':", "if 'a.invalid' in x:", "if x.startswith('https://a.invalid/'):",
                 "if urlparse(x).netloc.endswith('.a.invalid'):", "if not urlparse(x).netloc in ALLOWED:",
                 "if q.netloc in ALLOWED:", "if p in ALLOWED:", "if urlparse(x) in ALLOWED:", "x = urlparse(y).netloc in A"] {
        assert_eq!(guards(stmt), Vec::new(), "{stmt}");
    }
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
    // (Q-5) the host checks' readers
    let live = |_: &[u32], _: bool| -> Option<PyStr> { Some(cps("u")) };
    let texts = ["if ".to_string() + &"(".repeat(100_000) + "p.netloc in A" + &")".repeat(100_000) + ":",
                 "if ".to_string() + &"p.netloc in A or ".repeat(30_000) + "x:",
                 "if ".to_string() + &"a.".repeat(100_000) + "netloc in A:",
                 "if ".to_string() + &"urlparse(".repeat(50_000) + "x).netloc in A:",
                 "if p.netloc in [".to_string() + &"'a', ".repeat(50_000) + ":",
                 "if ".to_string() + &"'".repeat(200_000), "x = ".to_string() + &"a.".repeat(100_000) + "netloc"];
    for text in &texts {
        let t = cps(text);
        let t0 = std::time::Instant::now();
        let _ = (host_guards(&p, &t, &live), parsed_value(&p, &t[4..], &live));
        assert!(t0.elapsed().as_secs() < 10, "{}", &text[..12]);
    }
}
