//! Run scan_file (dependency mode) over the files of a JSON list
//! [[path, lang, text], …] (for a profiler, or to time it):
//!     cargo run --release --example profile_scanfile -- files.json [FIRST] [COUNT] [REPS]
use lazaret_engine::{api, json};
use std::time::Instant;

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("a JSON file of [path, lang, text]");
    let first: usize = a.next().map(|r| r.parse().unwrap_or(0)).unwrap_or(0);
    let count: usize = a.next().map(|r| r.parse().unwrap_or(usize::MAX)).unwrap_or(usize::MAX);
    let reps: usize = a.next().map(|r| r.parse().unwrap_or(1)).unwrap_or(1);
    let text = std::fs::read_to_string(path).expect("readable");
    let files = json::parse_str(&text).expect("JSON");
    let files: Vec<(String, Vec<u32>)> = files
        .as_arr()
        .unwrap()
        .iter()
        .skip(first)
        .take(count)
        .filter_map(|f| {
            let f = f.as_arr()?;
            Some((f.get(1)?.as_string()?, f.get(2)?.as_str()?.to_vec()))
        })
        .collect();
    let chars: usize = files.iter().map(|(_, t)| t.len()).sum();
    let start = Instant::now();
    let mut found = 0;
    for _ in 0..reps {
        for (lang, t) in &files {
            let args = json::Value::obj(vec![("lang", json::Value::str(lang)), ("dep", json::Value::Bool(true))]);
            if let Ok(json::Value::Arr(v)) = api::call("scan_file", &args, t) {
                found += v.len();
            }
        }
    }
    let secs = start.elapsed().as_secs_f64();
    eprintln!(
        "{} files, {} chars, {} findings, {:.2} s ({:.1} M chars/s)",
        files.len(),
        chars,
        found,
        secs,
        (chars * reps) as f64 / secs / 1e6
    );
    #[cfg(feature = "stats")]
    {
        // time in each pattern (build with --features stats)
        use lazaret_engine::{pack, pyre};
        let p = pack::current();
        let mut names = std::collections::HashMap::new();
        for n in p.names() {
            if p.raw(n).and_then(|r| r.get("re")).is_some() {
                names.insert(p.re(n).pattern.clone(), n.to_string());
            }
        }
        let mut rows = pyre::stats::take();
        rows.sort_by(|a, b| b.2.cmp(&a.2));
        let inside: u128 = rows.iter().map(|r| r.2).sum();
        eprintln!("{:.1} ms in patterns", inside as f64 / 1e6);
        for (pat, n, ns) in rows.iter().take(30) {
            let label = names.get(pat).cloned().unwrap_or_else(|| {
                String::from_utf8_lossy(&pat.iter().take(60).map(|&c| c as u8).collect::<Vec<_>>()).into_owned()
            });
            eprintln!("{:>9.1} ms {:>9} calls  {}", *ns as f64 / 1e6, n, label);
        }
    }
}
