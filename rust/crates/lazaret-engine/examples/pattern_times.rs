//! Time pattern.search over a JSON list of texts, for every pattern of the
//! rule pack (a development aid): prints "name microseconds matches".
//!     cargo run --release --example pattern_times -- cases.json [NAME [REPS]]
use lazaret_engine::{json, pack};
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("a JSON file of texts");
    let text = std::fs::read_to_string(path).expect("readable");
    let cases = json::parse_str(&text).expect("JSON");
    let cases: Vec<Vec<u32>> = cases.as_arr().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect();
    let only = std::env::args().nth(2);
    let reps: usize = std::env::args().nth(3).and_then(|r| r.parse().ok()).unwrap_or(1);
    let p = pack::current();
    for name in p.names() {
        if p.raw(name).and_then(|r| r.get("re")).is_none() || only.as_deref().is_some_and(|o| o != name) {
            continue;
        }
        let rx = p.re(name);
        let t = Instant::now();
        let mut n = 0;
        for _ in 0..reps {
            for c in &cases {
                if rx.search(c).is_some() {
                    n += 1;
                }
            }
        }
        println!("{} {:.0} {}", name, t.elapsed().as_secs_f64() * 1e6, n);
    }
}
