//! Run one engine call over a JSON list of texts (for a profiler):
//!     cargo run --release --example profile_one -- cases.json install_script_risk
use lazaret_engine::{api, json};

fn main() {
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("a JSON file of texts");
    let name = a.next().expect("a call");
    let reps: usize = a.next().map(|r| r.parse().unwrap_or(1)).unwrap_or(1);
    let text = std::fs::read_to_string(path).expect("readable");
    let cases = json::parse_str(&text).expect("JSON");
    let cases: Vec<Vec<u32>> = cases.as_arr().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect();
    let empty = json::Value::Obj(Vec::new());
    for _ in 0..reps {
        for c in &cases {
            let _ = api::call(&name, &empty, c);
        }
    }
}
