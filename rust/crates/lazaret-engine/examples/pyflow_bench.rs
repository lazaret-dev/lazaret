//! The Python cross-file pass's numbers (docs/RUST_ENGINE.md, "The Python
//! taint pass").
//!
//! `pyflow_bench CORPUS.json [REPEAT]`: CORPUS.json holds projects, each a
//! list of `{"path", "content"}` (content null: not text). Every project is
//! read by the pass on its default model, REPEAT times (default 3), best
//! run kept: the time of the parse and of the pass, and the outputs.

use lazaret_engine::json::{self, Value};
use lazaret_engine::pyflow::driver::{analyze, Config};
use std::time::Instant;

type Files = Vec<(Vec<u32>, Option<Vec<u32>>)>;

fn projects(v: &Value) -> Vec<Files> {
    let mut out = Vec::new();
    if let Value::Arr(sets) = v {
        for set in sets {
            let mut files = Vec::new();
            if let Value::Arr(items) = set {
                for f in items {
                    let path = match f.get("path") {
                        Some(Value::Str(s)) => s.clone(),
                        _ => continue,
                    };
                    let content = match f.get("content") {
                        Some(Value::Str(s)) => Some(s.clone()),
                        _ => None,
                    };
                    files.push((path, content));
                }
            }
            out.push(files);
        }
    }
    out
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: pyflow_bench CORPUS.json [REPEAT]");
        std::process::exit(2);
    }
    let repeat: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(3);
    let text = std::fs::read_to_string(&args[1]).expect("corpus");
    let sets = projects(&json::parse_str(&text).expect("corpus JSON"));
    let chars: usize = sets.iter().flat_map(|s| s.iter()).map(|(_, c)| c.as_ref().map_or(0, |c| c.len())).sum();
    let mut best_parse = f64::MAX;
    let mut best_pass = f64::MAX;
    let mut outputs = 0;
    for _ in 0..repeat {
        let t0 = Instant::now();
        for set in &sets {
            for (_, c) in set {
                if let Some(c) = c {
                    let _ = lazaret_engine::pyparse::parse(c);
                }
            }
        }
        best_parse = best_parse.min(t0.elapsed().as_secs_f64());
        let t0 = Instant::now();
        outputs = 0;
        for set in &sets {
            outputs += analyze(set, Config::new(&[], &[], &[], &[])).len();
        }
        best_pass = best_pass.min(t0.elapsed().as_secs_f64());
    }
    println!(
        "{} projects, {} characters, {} outputs: parse {:.0} ms ({:.1} MB/s), pass with parse {:.0} ms ({:.1} MB/s)",
        sets.len(),
        chars,
        outputs,
        best_parse * 1e3,
        chars as f64 / best_parse / 1e6,
        best_pass * 1e3,
        chars as f64 / best_pass / 1e6
    );
}
