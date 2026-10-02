//! The pass's own checks; python/tests/architecture/test_snapshot_py_flow.py
//! holds its outputs to the recorded ones.

use super::*;

fn cp(s: &str) -> PyStr {
    s.chars().map(|c| c as u32).collect()
}

fn run(files: &[(&str, &str)]) -> Vec<Out> {
    let files: Vec<(PyStr, Option<PyStr>)> = files.iter().map(|(p, c)| (cp(p), Some(cp(c)))).collect();
    analyze(&files, Config::new(&[], &[], &[], &[]))
}

#[test]
fn a_flow_across_files() {
    let out = run(&[
        ("api.py", "from flask import request\nfrom store import db_run\n\ndef handler():\n    q = request.args.get('q')\n    return db_run(q)\n"),
        ("store.py", "def db_run(x):\n    return cur.execute('SELECT * FROM t WHERE a = ' + x)\n"),
    ]);
    assert_eq!(
        out,
        vec![Out::Issue {
            cat: SQL,
            path: cp("api.py"),
            file: 0,
            line: 6,
            source: cp("api.py:5"),
            sink: cp("store.py:2 (in db_run())"),
            via: cp("the call to db_run()"),
        }]
    );
}

fn rules(out: &[Out]) -> Vec<&'static str> {
    out.iter()
        .map(|o| match o {
            Out::Note { rule, .. } => *rule,
            _ => "issue",
        })
        .collect()
}

#[test]
fn the_frames_stop_where_the_lazaret_command_stopped() {
    // flow.py, entered from the `lazaret` command, read a chain of 986
    // binary operators and stopped at 987 (Python's recursion limit)
    let chain = |n: usize| format!("import os\n\ndef f(x):\n    os.system(x{})\n", " + x".repeat(n));
    assert_eq!(rules(&run(&[("m.py", &chain(986))])), Vec::<&str>::new());
    let out = run(&[("m.py", &chain(987))]);
    assert_eq!(rules(&out), vec!["Q-FLOW-RECURSION"]);
    match &out[0] {
        Out::Note { path, line, .. } => assert_eq!((path.clone(), *line), (cp("m.py"), 3)),
        o => panic!("{:?}", o),
    }
}

#[test]
fn a_chain_read_at_every_link_is_paid_for() {
    // `x()()()…`: each call's callee is the chain under it, so reading each
    // call's callee reads the chain again (40 million links for 9000 calls):
    // that work counts, and the budget stops it with a note
    let src = format!("def f(x):\n    y = x{}\n", "()".repeat(9000));
    let started = std::time::Instant::now();
    let out = run(&[("m.py", &src)]);
    assert_eq!(rules(&out), vec!["Q-FLOW-INCOMPLETE"]);
    assert!(started.elapsed().as_secs() < 20);
    // a short one costs no more than its nodes
    let src = format!("def f(x):\n    y = x{}\n", "()".repeat(30));
    assert_eq!(rules(&run(&[("m.py", &src)])), Vec::<&str>::new());
}

#[test]
fn a_callee_text_too_long_to_keep_is_still_read() {
    // a source whose dotted text is longer than MEMO_TEXT: classified at the
    // call (not kept), a source all the same
    let src = format!(
        "from flask import request\nimport os\n\ndef run(x):\n    os.system(x)\n\ndef handler():\n    run(request.args{}.get('q'))\n",
        ".a".repeat(200)
    );
    let out = run(&[("m.py", &src)]);
    assert_eq!(rules(&out), vec!["issue"]);
    match &out[0] {
        Out::Issue { cat, line, sink, .. } => assert_eq!((*cat, *line, sink.clone()), (CMD, 8, cp("m.py:5 (in run())"))),
        o => panic!("{:?}", o),
    }
}

#[test]
fn collecting_a_modules_definitions_holds_frames_too() {
    // flow.py collected a module's definitions recursively: past its frames
    // (an `elif` chain of 992, from the `lazaret` command) what it had
    // collected stayed, the rest of the module was not added, and the file
    // was noted; reading the module's code stops sooner (494)
    let deep = |n: usize| format!("import os\nif a: pass\n{}def sink_fn(x):\n    os.system(x)\n", "elif b: pass\n".repeat(n));
    let app = "from flask import request\nfrom deep import sink_fn\n\ndef v():\n    sink_fn(request.args['q'])\n";
    let notes = |out: &[Out]| rules(out).into_iter().filter(|r| *r != "issue").collect::<Vec<_>>();
    let out = run(&[("deep.py", &deep(493)), ("app.py", app)]);
    assert_eq!(rules(&out), vec!["issue"]);
    let out = run(&[("deep.py", &deep(494)), ("app.py", app)]);
    assert_eq!((rules(&out).contains(&"issue"), notes(&out)), (true, vec!["Q-FLOW-RECURSION"]));
    let out = run(&[("deep.py", &deep(991)), ("app.py", app)]);
    assert_eq!((rules(&out).contains(&"issue"), notes(&out)), (true, vec!["Q-FLOW-RECURSION"]));
    let out = run(&[("deep.py", &deep(992)), ("app.py", app)]);
    assert_eq!(rules(&out), vec!["Q-FLOW-RECURSION"]);
}
