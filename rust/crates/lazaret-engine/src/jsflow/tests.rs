//! The port's own checks; tests/architecture/test_jsflow_reference.py
//! holds it to jsflow.py, output for output.

use super::*;

fn cp(s: &str) -> PyStr {
    s.chars().map(|c| c as u32).collect()
}

fn run(files: &[(&str, &str)]) -> Vec<Out> {
    let files: Vec<(PyStr, PyStr)> = files.iter().map(|(p, c)| (cp(p), cp(c))).collect();
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

/// The deepest nesting of each construct the parser reads, read by the pass
/// on a thread with `kib` KiB of stack.
fn deepest_on_a_stack(kib: usize) {
    use crate::jsparse::tests::{nested, NESTINGS};
    let inputs: Vec<(String, String)> = NESTINGS
        .iter()
        .map(|n| {
            let path = if n.1 { "a.ts" } else { "a.jsx" };
            // (request data at the bottom, a project function's sink around it)
            let src = nested(n, n.8).replace('x', "req.query.q");
            (path.to_string(), format!("function run(c) {{ exec(c); }}\napp.get('/x', (req, res) => {{ run({}); }});\n{}", "req.query.q", src))
        })
        .collect();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for (path, src) in &inputs {
                let files = vec![(cp(path), cp(src))];
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
