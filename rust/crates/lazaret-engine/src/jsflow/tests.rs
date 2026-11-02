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

#[test]
fn a_sparse_mark_reads_as_a_vector_does() {
    // set as a map or a vector, frozen (a bit for each node, the marks counted), and thawed by a later set
    let marked: Vec<(usize, u32)> = (0..5000).filter(|k| k % 7 == 0 || k % 64 == 63 || (300..340).contains(k)).map(|k| (k, k as u32 * 3 + 1)).collect();
    let want = |k: usize| marked.iter().find(|&&(x, _)| x == k).map_or(u32::MAX, |&(_, v)| v);
    for dense in [false, true] {
        let mut s = if dense { Sparse::dense(4000, u32::MAX) } else { Sparse::new(u32::MAX) };
        for &(k, v) in &marked {
            s[k] = v;
        }
        // (a mark set back to none is no mark)
        s[1] = 9;
        s[1] = u32::MAX;
        for frozen in [false, true] {
            if frozen {
                s.freeze();
                assert_eq!(s.len(), marked.len());
            }
            for k in 0..5200 {
                assert_eq!(s[k], want(k), "node {k}, dense {dense}, frozen {frozen}");
            }
        }
        s[4999] = 7;
        s[2] = 8;
        assert_eq!((s[4999], s[2], s[0], s[3], s[63]), (7, 8, want(0), u32::MAX, want(63)));
    }
    let mut empty: Sparse<u32> = Sparse::new(0);
    empty.freeze();
    assert_eq!((empty[0], empty[1 << 20]), (0, 0));
}

#[test]
fn scope_names_freeze_and_take_later_names() {
    let mut names = ScopeNames::default();
    names.map.insert((0, 5), 1);
    names.map.insert((2, 3), 2);
    names.map.insert((2, 1), 3);
    names.freeze(4);
    assert_eq!((names.get(0, 5), names.get(2, 3), names.get(2, 1), names.get(2, 2), names.get(1, 5), names.get(9, 5)), (Some(1), Some(2), Some(3), None, None, None));
    // declared after: a name of its own, or one the row has, which the later declaration wins
    names.map.insert((1, 4), 4);
    names.map.insert((2, 3), 5);
    names.map.insert((7, 0), 6);
    assert_eq!((names.get(1, 4), names.get(2, 3), names.get(7, 0)), (Some(4), Some(5), Some(6)));
    names.freeze(4);
    assert!(names.map.is_empty());
    assert_eq!((names.get(0, 5), names.get(1, 4), names.get(2, 3), names.get(2, 1), names.get(7, 0), names.get(3, 0)), (Some(1), Some(4), Some(5), Some(3), Some(6), None));
    assert_eq!(names.len(), 5);
}

#[test]
fn object_keys_keep_their_order_frozen() {
    let mut props = ObjProps::default();
    props.map.insert((1, 7), vec![(10, 0), (11, 1)]);
    props.map.insert((0, 7), vec![(12, 0)]);
    props.map.insert((1, 2), vec![(13, 2)]);
    let before: Vec<_> = [(1, 7), (0, 7), (1, 2), (1, 3), (2, 7)].iter().map(|&(o, n)| props.get(o, n)).collect();
    props.freeze();
    assert!(props.map.is_empty());
    let after: Vec<_> = [(1, 7), (0, 7), (1, 2), (1, 3), (2, 7)].iter().map(|&(o, n)| props.get(o, n)).collect();
    assert_eq!(before, after);
    assert_eq!(after[0], vec![(10, 0), (11, 1)]);
    props.map.insert((2, 7), vec![(14, 3)]);
    props.freeze();
    assert_eq!((props.get(2, 7), props.get(1, 7)), (vec![(14, 3)], vec![(10, 0), (11, 1)]));
    assert_eq!(props.items_len(), 5);
}

#[test]
fn callers_keep_what_each_last_passed() {
    let mut callers = Callers::default();
    assert!(callers.is_empty());
    callers.set(5, &[1, 3]);
    callers.set(2, &[]);
    callers.set(9, &[0]);
    assert_eq!(callers.groups(), vec![(2, vec![]), (5, vec![1, 3]), (9, vec![0])]);
    // a reading replaces what the caller passed; a replay adds to it
    callers.set(5, &[2]);
    callers.merge(9, &[2, 0]);
    callers.merge(2, &[]);
    callers.merge(2, &[4]);
    callers.merge(7, &[]);
    assert_eq!(callers.groups(), vec![(2, vec![4]), (5, vec![2]), (7, vec![]), (9, vec![0, 2])]);
    callers.set(2, &[]);
    assert_eq!(callers.groups()[0], (2, vec![]));
    assert_eq!(callers.counts(), (4, 5));
}

#[test]
fn a_chunked_vector_reads_as_a_vector_does() {
    let mut c: Chunked<u32> = Chunked::new();
    assert!(c.is_empty());
    let n = 3 * 4096 + 17;
    for k in 0..n as u32 {
        c.push(k * 2);
    }
    assert_eq!(c.len(), n);
    assert!((0..n).all(|k| c[k] == k as u32 * 2));
    c[4096] = 1;
    for x in &mut c {
        *x += 1;
    }
    let all: Vec<u32> = c.iter().copied().collect();
    assert_eq!(all.len(), n);
    assert_eq!((all[0], all[4095], all[4096], all[n - 1]), (1, 8191, 2, (n as u32 - 1) * 2 + 1));
    c.shrink_to_fit();
    assert_eq!(c.capacity(), n);
}

#[test]
fn a_vec_map_is_ordered_as_a_btree_map_is() {
    let mut m: VecMap<u32, &str> = VecMap::new();
    assert_eq!(m.insert(5, "e"), None);
    assert_eq!(m.insert(1, "a"), None);
    assert_eq!(m.insert(5, "E"), Some("e"));
    *m.slot(3, || "c") = "C";
    m.slot(1, || "x");
    assert_eq!(m.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(), vec![(1, "a"), (3, "C"), (5, "E")]);
    assert_eq!((m.get(&3), m.get(&4), m.contains_key(&5), m.len()), (Some(&"C"), None, true, 3));
    let mut bits = NodeBits::new(10);
    bits.set(3);
    bits.set(700);
    assert_eq!((bits.get(3), bits.get(4), bits.get(700), bits.get(100_000)), (true, false, true, false));
    let mut v: Vec<u8> = Vec::new();
    for k in 0..5 {
        v.push_slim(k);
    }
    assert_eq!((v.as_slice(), v.capacity()), (&[0u8, 1, 2, 3, 4][..], 8));
}
