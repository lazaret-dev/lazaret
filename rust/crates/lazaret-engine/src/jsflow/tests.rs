//! The pass's own checks; python/tests/architecture/test_snapshot_js_flow.py
//! holds its outputs to the recorded ones (it was held to jsflow.py, output
//! for output, until jsflow.py retired).

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
        ("lib/run.js", "const { exec } = require('child_process');\nfunction runIt(cmd) {\n  exec('ls ' + cmd);\n}\nmodule.exports = { runIt };\n"),
        ("routes/app.js", "const { runIt } = require('../lib/run');\napp.get('/x', (req, res) => {\n  runIt(req.query.q);\n});\n"),
    ]);
    assert_eq!(
        out,
        vec![Out::Issue {
            cat: CMD,
            path: cp("routes/app.js"),
            file: 1,
            line: 3,
            source: cp("routes/app.js:3"),
            sink: cp("lib/run.js:3 (in runIt())"),
            via: cp("the call to runIt()"),
        }]
    );
}

#[test]
fn what_is_not_read() {
    let out = run(&[("a.d.ts", "export declare function f(): void;\n"), ("b.js", "function (\n")]);
    assert_eq!(out.len(), 1);
    assert!(matches!(&out[0], Out::Note { rule: "Q-FLOW-SKIPPED", .. }));
}

#[test]
fn a_file_that_is_not_text_is_noted_with_the_others() {
    let files = vec![(cp("c.js"), Some(cp("function (\n"))), (cp("a.js"), None), (cp("b.d.ts"), None)];
    let out = analyze(&files, Config::new(&[], &[], &[], &[]));
    let notes: Vec<(PyStr, PyStr)> = out
        .iter()
        .map(|o| match o {
            Out::Note { rule: "Q-FLOW-SKIPPED", path, msg, .. } => (path.clone(), msg.clone()),
            other => panic!("{:?}", other),
        })
        .collect();
    // sorted by path with the files that do not parse; a declaration file is not read at all
    assert_eq!(notes.len(), 2);
    assert_eq!(notes[0], (cp("a.js"), cp("Cross-file taint analysis skipped 'a.js': its content is not text.")));
    assert_eq!(notes[1].0, cp("c.js"));
}

#[test]
fn the_run_limit_is_lowered_never_raised() {
    let lib = "function runIt(list) {\n  for (const c of list) {\n    if (c) exec(c);\n  }\n}\nmodule.exports = { runIt };\n";
    let app = "const { runIt } = require('./lib');\napp.get('/', (req) => {\n  runIt(req.query.q);\n});\n";
    let files = vec![(cp("lib.js"), Some(cp(lib))), (cp("app.js"), Some(cp(app)))];
    let plain = analyze(&files, Config::new(&[], &[], &[], &[]));
    assert!(matches!(&plain[..], [Out::Issue { cat: CMD, file: 1, line: 3, .. }]), "{:?}", plain);
    assert_eq!(analyze(&files, Config::new(&[], &[], &[], &[]).with_run_limit(u64::MAX, u64::MAX)), plain);
    let low = analyze(&files, Config::new(&[], &[], &[], &[]).with_run_limit(0, 1));
    match &low[..] {
        [Out::Note { rule: "Q-FLOW-INCOMPLETE", path, line: 1, msg, .. }] => {
            assert_eq!(path, &cp("lib.js"));
            let msg: String = msg.iter().map(|&c| char::from_u32(c).unwrap()).collect();
            assert!(msg.contains("stopped reading runIt() in 'lib.js' at its limit of 0 + 1 steps per syntax tree node"), "{}", msg);
        }
        other => panic!("{:?}", other),
    }
}

/// The deepest nesting of each construct the parser reads, as a file with
/// request data at the bottom and a project function's sink around it.
fn deepest() -> Vec<(String, String)> {
    use crate::jsparse::tests::{nested, NESTINGS};
    NESTINGS
        .iter()
        .map(|n| {
            let path = if n.1 { "a.ts" } else { "a.jsx" };
            let src = nested(n, n.8).replace('x', "req.query.q");
            (path.to_string(), format!("function run(c) {{ exec(c); }}\napp.get('/x', (req, res) => {{ run({}); }});\n{}", "req.query.q", src))
        })
        .collect()
}

/// deepest(), read by the pass on a thread with `kib` KiB of stack.
fn deepest_on_a_stack(kib: usize) {
    let inputs = deepest();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for (path, src) in &inputs {
                let files = vec![(cp(path), Some(cp(src)))];
                let _ = analyze(&files, Config::new(&[], &[], &[], &[]));
            }
        })
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn the_deepest_nesting_fits_a_thread_stack() {
    // a release build fits 2 MiB, a thread's default (cargo test --release);
    // a debug build's frames are several times larger
    deepest_on_a_stack(if cfg!(debug_assertions) { 32 * 1024 } else { 2 * 1024 });
}

#[test]
fn the_call_brings_its_own_stack() {
    // the `js_flow` call runs the pass on a thread of its own
    // (api::OWN_STACK), whatever the caller's: here 128 KiB
    use crate::json::Value;
    let inputs = deepest();
    let worker = std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(move || {
            for (path, src) in &inputs {
                let text = cp(src);
                let file = Value::Arr(vec![Value::Str(cp(path)), Value::Int(text.len() as i64)]);
                let args = Value::obj(vec![("files", Value::Arr(vec![file]))]);
                assert!(crate::api::call("js_flow", &args, &text).is_ok(), "{}", path);
            }
        })
        .unwrap();
    worker.join().unwrap();
}
