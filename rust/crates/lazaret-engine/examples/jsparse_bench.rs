//! The JavaScript parser's numbers (docs/RUST_ENGINE.md, "The JavaScript
//! parser").
//!
//! `jsparse_bench throughput DIR…`: every .js .mjs .cjs .jsx .ts .tsx .mts
//! .cts file under the directories, read on one thread in the dialect its
//! name gives: MB/s of the parse alone (the tree, compacted) and of the
//! parse with the tree's JSON, best of three runs.
//!
//! `jsparse_bench stack KIB CASES.json`: each `[path, source]` of the file
//! parsed on a thread with KIB KiB of stack (a stack overflow aborts the
//! process: run it in a loop to find the least that fits).

use lazaret_engine::jsparse;
use std::time::Instant;

const EXTS: &[&str] = &[".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"];

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
        } else if meta.is_file() {
            let name = p.to_string_lossy().to_lowercase();
            if EXTS.iter().any(|e| name.ends_with(e)) {
                out.push(p);
            }
        }
    }
}

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn throughput(dirs: &[String]) {
    let mut paths = Vec::new();
    for d in dirs {
        walk(std::path::Path::new(d), &mut paths);
    }
    let mut files: Vec<(Vec<u32>, Vec<u32>, usize)> = Vec::new();
    let mut bytes = 0usize;
    for p in &paths {
        if let Ok(b) = std::fs::read(p) {
            bytes += b.len();
            let text = String::from_utf8_lossy(&b);
            files.push((cps(&p.to_string_lossy()), cps(&text), b.len()));
        }
    }
    let chars: usize = files.iter().map(|f| f.1.len()).sum();
    println!("{} files, {:.1} MB ({:.1} M code points)", files.len(), bytes as f64 / 1e6, chars as f64 / 1e6);
    let mut best_parse = f64::MAX;
    let mut best_json = f64::MAX;
    let mut trees = 0;
    let mut nodes = 0usize;
    for _ in 0..3 {
        let t = Instant::now();
        trees = 0;
        nodes = 0;
        for (path, src, _) in &files {
            if let Ok(tree) = jsparse::parse_file(path, src) {
                trees += 1;
                nodes += tree.nodes.len();
            }
        }
        best_parse = best_parse.min(t.elapsed().as_secs_f64());
        let t = Instant::now();
        let mut out_bytes = 0usize;
        for (path, src, _) in &files {
            let (ts, jsx) = jsparse::dialect(path);
            out_bytes += jsparse::to_json(src, ts, jsx, false).len();
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
    let items: Vec<(Vec<u32>, Vec<u32>)> = v
        .as_arr()
        .unwrap_or(&[])
        .iter()
        .filter_map(|c| {
            let c = c.as_arr()?;
            Some((c.first()?.as_str()?.to_vec(), c.get(1)?.as_str()?.to_vec()))
        })
        .collect();
    let n = items.len();
    let worker = std::thread::Builder::new()
        .stack_size(kib * 1024)
        .spawn(move || {
            for (path, src) in &items {
                let _ = jsparse::parse_file(path, src);
                let (ts, jsx) = jsparse::dialect(path);
                let _ = jsparse::to_json(src, ts, jsx, false);
            }
        })
        .expect("thread");
    worker.join().expect("join");
    println!("{} cases fit {} KiB", n, kib);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("throughput") => throughput(&args[1..]),
        Some("stack") if args.len() == 3 => stack(args[1].parse().expect("KiB"), &args[2]),
        _ => eprintln!("usage: jsparse_bench throughput DIR… | jsparse_bench stack KIB CASES.json"),
    }
}
