//! The lexer fuzzer's short, deterministic run: a gate in `cargo test`
//! (examples/fuzz_lex runs it for as long as you like).

#[path = "../../examples/fuzz_lex/harness.rs"]
mod harness;

#[test]
fn go_survives_the_fuzzer() {
    let lang = harness::go();
    harness::probe_quadratic(&lang).unwrap();
    for seed in [1u64, 2, 3] {
        if let Err(f) = harness::run(&lang, seed, 1500, None, None) {
            panic!("{f}");
        }
    }
}

#[test]
fn rust_survives_the_fuzzer() {
    let lang = harness::rs();
    harness::probe_quadratic(&lang).unwrap();
    for seed in [1u64, 2, 3] {
        if let Err(f) = harness::run(&lang, seed, 1500, None, None) {
            panic!("{f}");
        }
    }
}
