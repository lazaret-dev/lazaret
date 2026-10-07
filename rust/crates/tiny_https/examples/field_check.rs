//! The two checks of `tools/mac_field_check.sh` that need the library: BACKLOG B-06 (a smoke test against real public
//! servers) and B-08 (real certificate chains, kept as fixtures). The script builds and runs this for you; by hand:
//!
//! ```text
//! cargo run --release --example field_check -- smoke  tools/field_hosts.txt [--cacert FILE] [--tsv FILE] [--tls-only] [--proxy] [--timeout SECONDS]
//! cargo run --release --example field_check -- verify field_results [--cacert FILE]
//! ```
//!
//! `smoke` connects to every host of the list with the library's own TLS 1.3 client and the system CA bundle, directly (the
//! environment's proxy variables are not read unless `--proxy` is given), and says for each whether it did what the list
//! expects of that host:
//!
//! * `ok`: the handshake must succeed, the chain must verify through the public `verify_chain` too, and a GET of `/` must
//!   answer (any status; a 404 or a 403 is an answer);
//! * `refuse`: the certificate is expired, self-signed, for another host or from a root nobody trusts, and must be refused
//!   as a certificate error;
//! * `info`: whatever happens is written down and is not a pass or a fail (a revoked certificate, a chain with the
//!   intermediate left out, a 100 KB certificate, a server that speaks only TLS 1.2).
//!
//! A host that cannot be reached at all (no address, no route, a connect timeout) is `SKIP`, never a failure. Only a
//! `FAIL` makes the exit status 1.
//!
//! `verify` reads what `mac_field_check.sh capture` wrote (`manifest.tsv` and `chains/`, chains captured by OpenSSL, not by
//! this library) and checks each chain with the library at the moment it was captured, so that a certificate that has
//! expired since still counts. It compares the verdict with OpenSSL's, tries to break every chain that verified (another host
//! name, a second outside the validity, a flipped bit in the leaf) and must see all of those refused, and writes
//! `real_chains/` (`fixtures.tsv`, `chains/`, `anchors/`): the fixtures that `tests/real_chains.rs` replays on any machine.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tiny_https::error::Error;
use tiny_https::tls::{ClientConfig, TlsStream};
use tiny_https::x509::{Certificate, PublicKey, TrustStore, VerifyOptions};
use tiny_https::{pem, sys, Client};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(|s| s.as_str()) {
        Some("smoke") if args.len() >= 2 => smoke(&args[1..]),
        Some("verify") if args.len() >= 2 => verify(&args[1..]),
        _ => {
            eprintln!("usage: field_check smoke HOSTS_FILE [--cacert FILE] [--tsv FILE] [--tls-only] [--proxy] [--timeout SECONDS]");
            eprintln!("       field_check verify DIR [--cacert FILE]");
            2
        }
    };
    std::process::exit(code);
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn load_trust(cacert: &Option<String>) -> Result<TrustStore, Error> {
    match cacert {
        Some(path) => sys::trust_store_from_pem_file(path),
        None => sys::system_trust_store(),
    }
}

/// One line of a tab-separated file: no tab or line break may be left in a field.
fn field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

fn key_name(key: &PublicKey) -> String {
    match key {
        PublicKey::Rsa(_) => "RSA".to_string(),
        PublicKey::Ec { curve, .. } => format!("EC-{:?}", curve),
        PublicKey::Ed25519(_) => "Ed25519".to_string(),
        _ => "other".to_string(),
    }
}

fn pem_encode(der: &[u8]) -> String {
    let b64 = pem::base64_encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn read_chain(path: &Path) -> Vec<Vec<u8>> {
    let Ok(text) = std::fs::read_to_string(path) else { return Vec::new() };
    pem::parse(&text).into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.data).collect()
}

/// The part of a name that is the host: `host:port` without the port.
fn host_part(host: &str) -> &str {
    host.rsplit_once(':').map_or(host, |(h, _)| h)
}

// ------------------------------------------------------------------------------------------------ smoke

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Group {
    Ok,
    Refuse,
    Info,
}

struct Site {
    group: Group,
    host: String,
    port: u16,
}

fn parse_hosts(text: &str) -> Vec<Site> {
    let mut sites = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let (Some(group), Some(target)) = (words.next(), words.next()) else { continue };
        let group = match group {
            "ok" => Group::Ok,
            "refuse" => Group::Refuse,
            "info" => Group::Info,
            other => {
                eprintln!("hosts file: unknown group {other:?} (ok, refuse or info) in: {line}");
                continue;
            }
        };
        let (host, port) = match target.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(p) => (h.to_string(), p),
                Err(_) => continue,
            },
            None => (target.to_string(), 443),
        };
        sites.push(Site { group, host, port });
    }
    sites
}

/// What one attempt to reach a host came to.
enum Attempt {
    /// No address, no route, a connect timeout: nothing about the library.
    Unreachable(String),
    /// It worked; what was seen.
    Accepted(String),
    /// The library refused (or the server did), and in what class: `cert`, `tls`, `timeout`, `io`, `http`, `refused` or `other`.
    Rejected(&'static str, String),
    /// Two parts of the library disagree about the same chain: always a failure.
    Bug(String),
}

fn class_of(e: &Error) -> &'static str {
    match e {
        Error::Verify(_) => "cert",
        Error::Tls(_) | Error::Alert(..) => "tls",
        Error::Io(io) if matches!(io.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => "timeout",
        Error::Io(_) => "io",
        Error::Http(_) => "http",
        Error::Refused(_) => "refused",
    }
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addrs = (host, port).to_socket_addrs().map_err(|e| format!("no address: {e}"))?;
    let mut last = "no address".to_string();
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// The handshake alone, over a direct connection, and then the same chain through the public `verify_chain`.
fn attempt_direct(site: &Site, config: &ClientConfig, timeout: Duration) -> Attempt {
    let tcp = match connect(&site.host, site.port, timeout) {
        Ok(t) => t,
        Err(e) => return Attempt::Unreachable(e),
    };
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let _ = tcp.set_nodelay(true);
    let tls = match TlsStream::connect(tcp, &site.host, config) {
        Ok(t) => t,
        Err(e) => return Attempt::Rejected(class_of(&e), e.to_string()),
    };
    let now = sys::now_unix();
    let chain = tls.peer_certificates();
    let verified = match config.trust_store.verify_chain(chain, &VerifyOptions::tls_server(&site.host, now)) {
        Ok(v) => v,
        Err(e) => return Attempt::Bug(format!("the handshake accepted the chain but verify_chain refuses it: {e}")),
    };
    let anchor = Certificate::from_der(verified.anchor()).map(|c| c.subject_summary()).unwrap_or_else(|_| "?".to_string());
    Attempt::Accepted(format!(
        "{} alpn={} sent={} path={} leaf={} issuer=[{}] anchor=[{}] expires_in={}d",
        tls.cipher_suite().map_or("?", |s| s.name()),
        tls.alpn_protocol().map_or("-".to_string(), |p| String::from_utf8_lossy(p).into_owned()),
        chain.len(),
        verified.path.len(),
        key_name(&verified.leaf.public_key),
        verified.leaf.issuer_summary(),
        anchor,
        (verified.leaf.not_after - now) / 86_400
    ))
}

/// A GET of `/` (redirects followed), reading at most 64 KiB of the body.
fn attempt_http(site: &Site, config: &ClientConfig, via_proxy: bool, timeout: Duration) -> Attempt {
    let mut client = Client::with_tls_config(config.clone())
        .http2(true)
        .timeout(timeout)
        .connect_timeout(timeout)
        .total_timeout(timeout * 3)
        .max_redirects(5)
        .user_agent("tiny_https-field-check");
    if via_proxy {
        client = client.proxy_from_env();
    }
    let url = if site.port == 443 { format!("https://{}/", site.host) } else { format!("https://{}:{}/", site.host, site.port) };
    let started = Instant::now();
    let mut stream = match client.get_stream(&url) {
        Ok(s) => s,
        Err(e) => return Attempt::Rejected(class_of(&e), e.to_string()),
    };
    let mut buf = vec![0u8; 16 * 1024];
    let mut total = 0usize;
    while total < 64 * 1024 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) => return Attempt::Rejected("io", format!("reading the body of {} after {} bytes: {e}", stream.status, total)),
        }
    }
    Attempt::Accepted(format!("{} {} {} bytes read, {} ms", stream.version, stream.status, total, started.elapsed().as_millis()))
}

/// (verdict, class, detail) for one site.
fn judge(group: Group, first: Attempt, second: Option<Attempt>) -> (&'static str, String, String) {
    match (group, first) {
        (_, Attempt::Bug(m)) => ("FAIL", "inconsistent".to_string(), m),
        (_, Attempt::Unreachable(m)) => ("SKIP", "unreachable".to_string(), m),
        (Group::Ok, Attempt::Accepted(s)) => match second {
            Some(Attempt::Rejected(c, m)) => ("FAIL", c.to_string(), format!("the handshake worked ({s}) but the request failed: {m}")),
            Some(Attempt::Bug(m)) => ("FAIL", "inconsistent".to_string(), m),
            Some(Attempt::Accepted(h)) => ("PASS", "-".to_string(), format!("{s}; {h}")),
            Some(Attempt::Unreachable(m)) => ("FAIL", "unreachable".to_string(), format!("the handshake worked ({s}) but the request could not connect: {m}")),
            None => ("PASS", "-".to_string(), s),
        },
        (Group::Ok, Attempt::Rejected(c, m)) => ("FAIL", c.to_string(), m),
        (Group::Refuse, Attempt::Accepted(s)) => ("FAIL", "accepted".to_string(), format!("a certificate that must be refused was accepted: {s}")),
        (Group::Refuse, Attempt::Rejected("cert", m)) => ("PASS", "cert".to_string(), m),
        (Group::Refuse, Attempt::Rejected(c, m)) => ("WEAK", c.to_string(), format!("refused, but not as a certificate error: {m}")),
        (Group::Info, Attempt::Accepted(s)) => ("INFO", "accepted".to_string(), s),
        (Group::Info, Attempt::Rejected(c, m)) => ("INFO", c.to_string(), format!("refused: {m}")),
    }
}

fn smoke(args: &[String]) -> i32 {
    let hosts_path = &args[0];
    let cacert = option(args, "--cacert");
    let tsv_path = option(args, "--tsv");
    let via_proxy = flag(args, "--proxy");
    let tls_only = flag(args, "--tls-only");
    let timeout = Duration::from_secs(option(args, "--timeout").and_then(|s| s.parse().ok()).unwrap_or(15));
    let text = match std::fs::read_to_string(hosts_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {hosts_path}: {e}");
            return 2;
        }
    };
    let sites = parse_hosts(&text);
    if sites.is_empty() {
        eprintln!("{hosts_path} lists no hosts");
        return 2;
    }
    let trust = match load_trust(&cacert) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot load the CA bundle: {e}");
            return 2;
        }
    };
    println!(
        "smoke test: {} hosts, {} trust anchors, {}, timeout {} s{}",
        sites.len(),
        trust.len(),
        if via_proxy { "through the proxy of the environment (a test of the mechanics, not of B-06)" } else { "direct" },
        timeout.as_secs(),
        if tls_only { ", handshakes only" } else { "" }
    );
    let config = ClientConfig::new(trust);

    let mut rows: Vec<(Group, String, &'static str, String, u128, String)> = Vec::new();
    for site in &sites {
        let started = Instant::now();
        let (first, second) = if via_proxy {
            // through a proxy there is no handshake of ours to look at on its own: the request is the attempt
            (attempt_http(site, &config, true, timeout), None)
        } else {
            let first = attempt_direct(site, &config, timeout);
            let second = if site.group == Group::Ok && !tls_only && matches!(first, Attempt::Accepted(_)) {
                Some(attempt_http(site, &config, false, timeout))
            } else {
                None
            };
            (first, second)
        };
        let (verdict, class, detail) = judge(site.group, first, second);
        let ms = started.elapsed().as_millis();
        let name = if site.port == 443 { site.host.clone() } else { format!("{}:{}", site.host, site.port) };
        let group = match site.group {
            Group::Ok => "ok",
            Group::Refuse => "refuse",
            Group::Info => "info",
        };
        println!("{verdict:<5} {group:<6} {name:<48} {ms:>5} ms  {class:<12} {detail}");
        rows.push((site.group, name, verdict, class, ms, detail));
    }

    if let Some(path) = tsv_path {
        let mut out = String::from("group\thost\tverdict\tclass\tms\tdetail\n");
        for (group, name, verdict, class, ms, detail) in &rows {
            let g = match group {
                Group::Ok => "ok",
                Group::Refuse => "refuse",
                Group::Info => "info",
            };
            out.push_str(&format!("{g}\t{name}\t{verdict}\t{class}\t{ms}\t{}\n", field(detail)));
        }
        if let Err(e) = std::fs::write(&path, out) {
            eprintln!("cannot write {path}: {e}");
        }
    }

    let count = |v: &str| rows.iter().filter(|r| r.2 == v).count();
    let ok_passed = rows.iter().filter(|r| r.0 == Group::Ok && r.2 == "PASS").count();
    let ok_total = rows.iter().filter(|r| r.0 == Group::Ok).count();
    let refuse_passed = rows.iter().filter(|r| r.0 == Group::Refuse && r.2 == "PASS").count();
    let refuse_total = rows.iter().filter(|r| r.0 == Group::Refuse).count();
    println!();
    println!(
        "PASS {}  FAIL {}  WEAK {}  SKIP {}  INFO {}   (hosts that must connect: {}/{}; that must be refused: {}/{})",
        count("PASS"),
        count("FAIL"),
        count("WEAK"),
        count("SKIP"),
        count("INFO"),
        ok_passed,
        ok_total,
        refuse_passed,
        refuse_total
    );
    for (_, name, verdict, class, _, detail) in rows.iter().filter(|r| r.2 == "FAIL" || r.2 == "WEAK") {
        println!("  {verdict} {name} [{class}]: {detail}");
    }
    let mut code = 0;
    if count("FAIL") > 0 {
        println!("RESULT: FAIL. Each FAIL above is a new backlog item (a bug, or a server doing something the library should cope with).");
        code = 1;
    }
    if ok_passed < 10 && !via_proxy {
        println!("NOTE: fewer than 10 hosts answered ({ok_passed}); B-06 asks for at least 10. Hosts that were SKIPped could not be reached at all.");
        code = 1;
    }
    if code == 0 {
        println!("RESULT: ok");
    }
    code
}

// ------------------------------------------------------------------------------------------------ verify

struct Entry {
    name: String,
    host: String,
    time: i64,
    group: String,
    openssl: Option<i32>,
}

fn read_manifest(dir: &Path) -> Result<Vec<Entry>, String> {
    let path = dir.join("manifest.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut entries = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 5 {
            return Err(format!("{}: a line with fewer than 5 columns: {line}", path.display()));
        }
        entries.push(Entry {
            name: cols[0].to_string(),
            host: cols[1].to_string(),
            time: cols[2].parse().map_err(|_| format!("{}: bad time in: {line}", path.display()))?,
            group: cols[3].to_string(),
            openssl: cols[4].trim().parse().ok(),
        });
    }
    Ok(entries)
}

/// A name the leaf is valid for, with a wildcard replaced by a label: what a client would have asked for.
fn a_name_of(leaf: &Certificate) -> Option<String> {
    leaf.dns_names.first().map(|n| n.strip_prefix("*.").map_or(n.clone(), |rest| format!("www.{rest}")))
}

/// The ways of altering a chain that verified, none of which may be accepted. Returns those that were.
fn accepted_alterations(trust: &TrustStore, chain: &[Vec<u8>], host: &str, time: i64, leaf: &Certificate) -> Vec<String> {
    let mut accepted = Vec::new();
    let mut try_it = |what: String, chain: &[Vec<u8>], host: &str, time: i64| {
        if trust.verify_chain(chain, &VerifyOptions::tls_server(host, time)).is_ok() {
            accepted.push(what);
        }
    };
    try_it("another host name".to_string(), chain, &format!("{host}.invalid"), time);
    try_it("one second after the leaf expires".to_string(), chain, host, leaf.not_after + 1);
    try_it("one second before the leaf is valid".to_string(), chain, host, leaf.not_before - 1);
    for (what, at) in [("the last byte of the leaf (the signature)", chain[0].len() - 1), ("a byte in the middle of the leaf", chain[0].len() / 2)] {
        let mut altered = chain.to_vec();
        altered[0][at] ^= 0x01;
        try_it(format!("a flipped bit in {what}"), &altered, host, time);
    }
    accepted
}

fn verify(args: &[String]) -> i32 {
    let dir = PathBuf::from(&args[0]);
    let cacert = option(args, "--cacert");
    let trust = match load_trust(&cacert) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot load the CA bundle: {e}");
            return 2;
        }
    };
    let entries = match read_manifest(&dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let out = dir.join("real_chains");
    let _ = std::fs::remove_dir_all(&out);
    for sub in ["chains", "anchors"] {
        if let Err(e) = std::fs::create_dir_all(out.join(sub)) {
            eprintln!("cannot create {}: {e}", out.join(sub).display());
            return 2;
        }
    }
    println!("verify: {} captured chains, {} trust anchors", entries.len(), trust.len());

    let mut fixtures = String::from("# name\thost\ttime\texpect\tanchor\n");
    let mut table = String::from("name\thost\ttime\tverdict\tdetail\n");
    let (mut pass, mut fail, mut weak, mut skip) = (0, 0, 0, 0);
    let (mut ok_fixtures, mut refusal_fixtures) = (0, 0);
    let mut keys: BTreeMap<String, usize> = BTreeMap::new();
    let mut anchors: BTreeMap<String, usize> = BTreeMap::new();

    for e in &entries {
        let chain = read_chain(&dir.join("chains").join(format!("{}.pem", e.name)));
        let host = host_part(&e.host).to_string();
        let mut anchor_der: Option<Vec<u8>> = None;
        let (verdict, expect, detail): (&str, Option<String>, String) = 'entry: {
            if chain.is_empty() {
                break 'entry ("SKIP", None, "no certificate was captured".to_string());
            }
            let Ok(leaf) = Certificate::from_der(&chain[0]) else {
                break 'entry ("WEAK", None, "the library cannot parse the leaf".to_string());
            };
            let ours = trust.verify_chain(&chain, &VerifyOptions::tls_server(&host, e.time));
            if e.group == "refuse" {
                match ours {
                    Ok(_) => break 'entry ("FAIL", None, "a chain that must be refused was accepted".to_string()),
                    Err(err) => {
                        // why: the same chain in the middle of its validity, or for a name it is valid for, or neither
                        let middle = (leaf.not_before + leaf.not_after) / 2;
                        if let Ok(v) = trust.verify_chain(&chain, &VerifyOptions::tls_server(&host, middle)) {
                            anchor_der = Some(v.anchor().to_vec());
                            break 'entry ("PASS", Some("refuse-time".to_string()), format!("refused ({err}); accepted in the middle of its validity"));
                        }
                        if let Some(name) = a_name_of(&leaf) {
                            if let Ok(v) = trust.verify_chain(&chain, &VerifyOptions::tls_server(&name, e.time)) {
                                anchor_der = Some(v.anchor().to_vec());
                                break 'entry ("PASS", Some("refuse-host".to_string()), format!("refused ({err}); accepted for {name}"));
                            }
                        }
                        break 'entry ("PASS", Some("refuse-path".to_string()), format!("refused ({err})"));
                    }
                }
            }
            match ours {
                Err(err) => {
                    if e.openssl == Some(0) {
                        ("FAIL", None, format!("the library refuses a chain that OpenSSL accepted: {err}"))
                    } else {
                        ("WEAK", None, format!("both refuse (OpenSSL code {:?}); does this network re-sign TLS? {err}", e.openssl))
                    }
                }
                Ok(v) => {
                    let wrongly = accepted_alterations(&trust, &chain, &host, e.time, &leaf);
                    anchor_der = Some(v.anchor().to_vec());
                    *keys.entry(key_name(&leaf.public_key)).or_insert(0) += 1;
                    let anchor_name = Certificate::from_der(v.anchor()).map(|c| c.subject_summary()).unwrap_or_default();
                    *anchors.entry(anchor_name.clone()).or_insert(0) += 1;
                    if !wrongly.is_empty() {
                        ("FAIL", None, format!("accepted an altered chain: {}", wrongly.join("; ")))
                    } else if e.openssl.is_some_and(|c| c != 0) {
                        ("WEAK", Some("ok".to_string()), format!("verified (path of {}, anchor [{anchor_name}]), but OpenSSL refused it (code {:?})", v.path.len(), e.openssl))
                    } else {
                        ("PASS", Some("ok".to_string()), format!("{} path of {} to [{anchor_name}]; every alteration refused", key_name(&leaf.public_key), v.path.len()))
                    }
                }
            }
        };
        match verdict {
            "PASS" => pass += 1,
            "FAIL" => fail += 1,
            "WEAK" => weak += 1,
            _ => skip += 1,
        }
        println!("{verdict:<5} {:<48} {}", e.name, detail);
        table.push_str(&format!("{}\t{}\t{}\t{verdict}\t{}\n", e.name, e.host, e.time, field(&detail)));

        // A fixture is kept for a chain whose verdict the library and the world agree on, and nothing else.
        if let (Some(expect), true) = (expect, verdict != "FAIL") {
            let anchor_file = match &anchor_der {
                Some(der) => {
                    let _ = std::fs::write(out.join("anchors").join(format!("{}.pem", e.name)), pem_encode(der));
                    format!("anchors/{}.pem", e.name)
                }
                None => "-".to_string(),
            };
            let chain_pem: String = chain.iter().map(|c| pem_encode(c)).collect();
            let _ = std::fs::write(out.join("chains").join(format!("{}.pem", e.name)), chain_pem);
            fixtures.push_str(&format!("{}\t{}\t{}\t{}\t{}\n", e.name, host, e.time, expect, anchor_file));
            if expect == "ok" {
                ok_fixtures += 1;
            } else {
                refusal_fixtures += 1;
            }
        }
    }
    let _ = std::fs::write(out.join("fixtures.tsv"), &fixtures);
    let _ = std::fs::write(dir.join("verify.tsv"), table);

    println!();
    println!("PASS {pass}  FAIL {fail}  WEAK {weak}  SKIP {skip}");
    println!("fixtures kept: {ok_fixtures} chains that verify, {refusal_fixtures} that must be refused; leaf keys: {keys:?}");
    println!("trust anchors reached: {}", anchors.iter().map(|(k, v)| format!("[{k}] x{v}")).collect::<Vec<_>>().join(", "));
    println!("written to {}", out.display());
    let mut code = 0;
    if fail > 0 {
        println!("RESULT: FAIL. Each FAIL above is a new backlog item.");
        code = 1;
    }
    if ok_fixtures < 10 {
        println!("NOTE: {ok_fixtures} real chains verified; B-08 asks for at least 10.");
        code = 1;
    }
    if !keys.contains_key("RSA") || !keys.keys().any(|k| k.starts_with("EC")) {
        println!("NOTE: the chains do not include both an RSA leaf and an ECDSA leaf (B-06 asks for both).");
    }
    if code == 0 {
        println!("RESULT: ok");
    }
    code
}
