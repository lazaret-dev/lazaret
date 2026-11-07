//! Fuzzes the Go and Rust lexers (harness.rs says how).
//!
//!     cargo run --release --example fuzz_lex -- [go|rs|all] [--iters N]
//!         [--seconds S] [--seed N] [--iter I]
//!
//! Defaults: both languages, 20,000 iterations each, a seed from the clock.
//! `--seconds` stops each language when the time is spent. A failure prints
//! its seed and iteration; `--seed S --iter I` runs only that one. Exit
//! code 1 on a failure.

mod harness;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut which = "all".to_string();
    let (mut iters, mut seconds, mut seed, mut only) = (20_000u64, None, None, None);
    let mut i = 0;
    while i < args.len() {
        let value = |i: usize| -> u64 { args.get(i + 1).and_then(|v| v.parse().ok()).unwrap_or_else(|| { eprintln!("{} needs a number", args[i]); std::process::exit(2) }) };
        match args[i].as_str() {
            "go" | "rs" | "all" => which = args[i].clone(),
            "--iters" => { iters = value(i); i += 1 }
            "--seconds" => { seconds = Some(value(i)); i += 1 }
            "--seed" => { seed = Some(value(i)); i += 1 }
            "--iter" => { only = Some(value(i)); i += 1 }
            other => { eprintln!("unknown argument {other:?}"); std::process::exit(2) }
        }
        i += 1;
    }
    let seed = seed.unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(1));
    let mut failed = false;
    for lang in harness::langs() {
        if which != "all" && which != lang.name {
            continue;
        }
        if let Err(e) = harness::probe_quadratic(&lang) {
            println!("{}: NOT LINEAR: {e}", lang.name);
            failed = true;
            continue;
        }
        match harness::run(&lang, seed, iters, only, seconds.map(Duration::from_secs)) {
            Ok(s) => println!("{}: ok, seed {seed}: {} programs, {} mutants, {} characters", lang.name, s.programs, s.mutants, s.chars),
            Err(f) => {
                println!("{f}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
