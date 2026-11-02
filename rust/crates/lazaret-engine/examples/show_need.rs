//! Print what the search of each named pack pattern needs the text to hold
//! (linre/literal.rs: the strings one of which every match holds, or those
//! every match starts with), a development aid:
//!     cargo run --release --example show_need -- NAME...
use lazaret_engine::pack;

fn main() {
    let p = pack::current();
    let names: Vec<String> = std::env::args().skip(1).collect();
    let (mut with, mut total) = (0, 0);
    for name in p.names() {
        if p.raw(name).and_then(|r| r.get("re")).is_none() {
            continue;
        }
        let need = p.re(name).need().map(|n| n.describe());
        total += 1;
        with += need.is_some() as usize;
        if names.is_empty() || names.iter().any(|n| n == name) {
            if !names.is_empty() || need.is_none() {
                println!("{}: {}", name, need.unwrap_or_else(|| "(nothing)".into()));
            }
        }
    }
    println!("{} of {} patterns need text", with, total);
}
