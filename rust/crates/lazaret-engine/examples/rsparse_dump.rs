//! rsparse_dump [FILE…]: the items of each Rust file named (or listed one per line on the standard input), in
//! `scripts/rsparse/rustc_items.py`'s format: `== path`, then the `item`, `use` and `crate` lines (see
//! `rsparse/out.rs`), or `!! message` for a file that cannot be read. `scripts/rsparse/diff.py` compares the two.

use lazaret_engine::rsparse;
use std::io::{BufRead, Write};

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            args.push(line);
        }
    }
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::with_capacity(1 << 20, stdout.lock());
    for path in &args {
        let _ = writeln!(out, "== {}", path);
        match std::fs::read(path) {
            Err(e) => {
                let _ = writeln!(out, "!! {}", e);
            }
            Ok(bytes) => match String::from_utf8(bytes) {
                Err(_) => {
                    let _ = writeln!(out, "!! illegal UTF-8");
                }
                Ok(s) => {
                    // the compiler takes a leading byte order mark off
                    let s = s.strip_prefix('\u{feff}').unwrap_or(&s);
                    let src: Vec<u32> = s.chars().map(|c| c as u32).collect();
                    let tree = rsparse::parse(&src);
                    let mut text = String::new();
                    rsparse::out::write_items(&tree, &src, &mut text);
                    let _ = out.write_all(text.as_bytes());
                    if tree.problems > 0 {
                        let _ = writeln!(out, "problems {}", tree.problems);
                    }
                }
            },
        }
    }
}
