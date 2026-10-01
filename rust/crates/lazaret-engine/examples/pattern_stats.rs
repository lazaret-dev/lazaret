//! Time spent in each pattern during one engine call over a JSON list of
//! texts (a development aid):
//!     cargo run --release --features stats --example pattern_stats -- cases.json install_script_risk
//! (texts under 5,000 characters; MAX_CHARS=n reads longer ones too)
#[cfg(feature = "stats")]
fn main() {
    use lazaret_engine::{api, json, pack, pyre};
    let mut a = std::env::args().skip(1);
    let path = a.next().expect("a JSON file of texts");
    let name = a.next().expect("a call");
    let args = json::parse_str(&a.next().unwrap_or_else(|| "{}".into())).expect("JSON args");
    let text = std::fs::read_to_string(path).expect("readable");
    let cases = json::parse_str(&text).expect("JSON");
    let cases: Vec<Vec<u32>> = cases.as_arr().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect();
    let most: usize = std::env::var("MAX_CHARS").ok().and_then(|v| v.parse().ok()).unwrap_or(5000);
    let small: Vec<&Vec<u32>> = cases.iter().filter(|c| c.len() < most).collect();
    let t = std::time::Instant::now();
    for c in &small {
        let _ = api::call(&name, &args, c);
    }
    let total = t.elapsed().as_nanos();
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
    println!("{} over {} cases: {:.1} ms, {:.1} ms in patterns", name, small.len(), total as f64 / 1e6, inside as f64 / 1e6);
    let mut scans: Vec<(String, [u64; 4])> = names.values().map(|n| (n.clone(), p.re(n).scanned())).filter(|(_, s)| s[1] + s[2] + s[3] > 0).collect();
    scans.sort_by_key(|(_, s)| std::cmp::Reverse(s[1] + s[3]));
    let (tn, tl): (u64, u64) = scans.iter().fold((0, 0), |a, (_, s)| (a.0 + s[1], a.1 + s[3]));
    println!("need scans {:.1} ms, lead scans {:.1} ms", tn as f64 / 1e6, tl as f64 / 1e6);
    for (n, s) in scans.iter().take(25) {
        println!("{:>8} {:>9.1} ms {:>8} {:>9.1} ms  {}", s[0], s[1] as f64 / 1e6, s[2], s[3] as f64 / 1e6, n);
    }
    for (pat, n, ns) in rows.iter().take(25) {
        let label = names.get(pat).cloned().unwrap_or_else(|| String::from_utf8_lossy(&pat.iter().take(60).map(|&c| c as u8).collect::<Vec<_>>()).into_owned());
        println!("{:>9.1} ms {:>8} calls  {}", *ns as f64 / 1e6, n, label);
    }
}

#[cfg(not(feature = "stats"))]
fn main() {
    eprintln!("build with --features stats");
}
