//! goparse_dump [FILE…]: the tree of each Go file named (or listed one per line on the standard input), in
//! `scripts/goparse/astdump.go`'s format: `== path`, then `Kind start end` per node, or `!! message` for a file that
//! does not parse. The differential driver (`scripts/goparse/diff.py`) compares the two.

use lazaret_engine::goparse;
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
        let mut text = String::new();
        let _ = writeln!(out, "== {}", path);
        match std::fs::read(path) {
            Err(e) => {
                let _ = writeln!(out, "!! {}", e);
            }
            Ok(bytes) => match String::from_utf8(bytes) {
                Err(_) => {
                    let _ = writeln!(out, "!! illegal UTF-8 encoding");
                }
                Ok(s) => {
                    let src: Vec<u32> = s.chars().map(|c| c as u32).collect();
                    match goparse::parse(&src) {
                        Err(e) => {
                            let _ = writeln!(out, "!! {} at {}", e.message(), e.pos);
                        }
                        Ok(tree) => {
                            goparse::out::write_nodes(&tree, &mut text);
                            let _ = out.write_all(text.as_bytes());
                        }
                    }
                }
            },
        }
    }
}
