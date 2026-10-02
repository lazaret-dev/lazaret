//! The Python parser's numbers (docs/RUST_ENGINE.md, "The Python parser").
//!
//! `pyparse_bench throughput DIR…`: every .py file under the directories
//! (UTF-8, a leading byte order mark dropped), read on one thread: MB/s of
//! the parse alone (the tree, compacted) and of the parse with the tree's
//! JSON, best of three runs.
//!
//! `pyparse_bench stack KIB CASES.json`: each source of the file (a JSON
//! list of strings) parsed, and written as JSON, on a thread with KIB KiB of
//! stack (a stack overflow aborts the process: run it in a loop to find the
//! least that fits).

use lazaret_engine::pyparse;
use std::time::Instant;

fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    let mut entries: Vec<_> = match std::fs::read_dir(dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.path()).collect(),
        Err(_) => return,
    };
    entries.sort();
    for p in entries {
        let meta = match std::fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk(&p, out);
        } else if meta.is_file() && p.to_string_lossy().ends_with(".py") {
            out.push(p);
        }
    }
}

fn throughput(dirs: &[String]) {
    let mut paths = Vec::new();
    for d in dirs {
        walk(std::path::Path::new(d), &mut paths);
    }
    let mut files: Vec<Vec<u32>> = Vec::new();
    let mut bytes = 0usize;
    for p in &paths {
        if let Ok(b) = std::fs::read(p) {
            bytes += b.len();
            let text = String::from_utf8_lossy(&b);
            let text = text.strip_prefix('\u{FEFF}').unwrap_or(&text);
            files.push(text.chars().map(|c| c as u32).collect());
        }
    }
    let chars: usize = files.iter().map(|f| f.len()).sum();
    println!("{} files, {:.1} MB ({:.1} M code points)", files.len(), bytes as f64 / 1e6, chars as f64 / 1e6);
    let mut best_parse = f64::MAX;
    let mut best_json = f64::MAX;
    let (mut trees, mut nodes) = (0, 0usize);
    for _ in 0..3 {
        let t = Instant::now();
        trees = 0;
        nodes = 0;
        for src in &files {
            if let Ok(tree) = pyparse::parse(src) {
                trees += 1;
                nodes += tree.nodes.len();
            }
        }
        best_parse = best_parse.min(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let mut out_bytes = 0usize;
        for src in &files {
            out_bytes += pyparse::to_json(src, false).len();
        }
        best_json = best_json.min(t.elapsed().as_secs_f64());
        std::hint::black_box(out_bytes);
    }
    println!("{} trees, {} nodes", trees, nodes);
    println!("parse: {:.2} s, {:.1} MB/s", best_parse, bytes as f64 / 1e6 / best_parse);
    println!("parse and JSON: {:.2} s, {:.1} MB/s", best_json, bytes as f64 / 1e6 / best_json);
}

fn stack(kib: usize, cases: &str) {
    let text = std::fs::read_to_string(cases).expect("cases");
    let v = lazaret_engine::json::parse_str(&text).expect("JSON");
    let items: Vec<Vec<u32>> =
        v.as_arr().unwrap_or(&[]).iter().filter_map(|c| c.as_str().map(|s| s.to_vec())).collect();
    let n = items.len();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            let mut trees = 0;
            for src in &items {
                if pyparse::parse(src).is_ok() {
                    trees += 1;
                }
                let _ = pyparse::to_json(src, true);
            }
            trees
        })
        .expect("thread");
    let trees = worker.join().expect("join");
    println!("{} cases ({} trees) fit {} KiB", n, trees, kib);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("throughput") => throughput(&args[1..]),
        Some("stack") if args.len() == 3 => stack(args[1].parse().expect("KiB"), &args[2]),
        _ => eprintln!("usage: pyparse_bench throughput DIR… | pyparse_bench stack KIB CASES.json"),
    }
}
