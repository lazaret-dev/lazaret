//! Live secret verification's table and logic (0.1.9, V-1 stage 2; John's decision 7, Oct 7: the provider table and
//! the logic, "each request, AWS's signing, reading the answer as live, rejected or unknown", in the engine, one copy
//! for both packages). Which provider a credential is ([`identify`]), the one request that asks that provider whether
//! it is live ([`request`]: a call that only authenticates, the credential in a header and never in a URL, AWS's
//! signed with Signature Version 4), and what the provider's answer says ([`judge`]: live, rejected or unknown, why,
//! and whose the credential is).
//!
//! The table is the pack's (`_VERIFY_PROVIDERS`), read and checked once ([`table`]) by the rules
//! `scripts/make_rust_tables.py --check` holds it to (lazaret/scanner/secretverify.py's `validate`); a call may give an
//! entry of its own instead (the tests'). No network and no clock: each package makes the call over its own HTTPS
//! client (Python's lazaret-net, the npm package's `node:https`) and gives the time. Nothing returned holds a part of
//! the credential: a part found in what an answer says is replaced.
//!
//! The answer's body comes as bytes (each a code point below 256), at most [`MAX_ANSWER_BYTES`] of them: as JSON only
//! if it is whole and UTF-8 (the reading is the engine's own JSON reader, a duplicate key's last value counting, as
//! Python's), as text (UTF-8, every bad sequence one U+FFFD) for an XML error's `<Code>` and a tag's text.

use crate::json::{self, Value};
use crate::pack::Pack;
use crate::pyre::Regex;
use crate::pystr;
use crate::unicode;
use lazaret_verify::crypto::sha2::{Hash, Sha256};

/// The most characters of the owner's name an answer gives that are kept.
pub const MAX_WHO: usize = 80;
/// The longest credential part looked at.
pub const MAX_CREDENTIAL: usize = 512;
/// The most bytes of an answer the packages read (the rest is not read, and the answer is cut).
pub const MAX_ANSWER_BYTES: usize = 64 * 1024;
/// The table's name in the pack.
pub const TABLE: &str = "_VERIFY_PROVIDERS";
pub const NOT_THIS_FORMAT: &str = "not this provider's format, so nothing was sent";
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Live,
    Rejected,
    Unknown,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Live => "live",
            Outcome::Rejected => "rejected",
            Outcome::Unknown => "unknown",
        }
    }

    fn parse(s: &str) -> Option<Outcome> {
        match s {
            "live" => Some(Outcome::Live),
            "rejected" => Some(Outcome::Rejected),
            "unknown" => Some(Outcome::Unknown),
            _ => None,
        }
    }
}

/// A json condition's value: the text, the boolean, or one of several.
#[derive(Debug)]
enum Want {
    Str(Vec<u32>),
    Bool(bool),
    Any(Vec<Want>),
}

/// Where a live answer names the credential's owner.
#[derive(Debug)]
enum Who {
    Json(String),
    Xml(Regex),
}

/// One answer rule: when its conditions hold, its outcome.
#[derive(Debug)]
pub struct Rule {
    status: Vec<i64>,
    json: Vec<(String, Want)>,
    code: Option<Vec<Vec<u32>>>,
    outcome: Outcome,
    why: Option<Vec<u32>>,
    who: Option<Who>,
}

/// One provider of the table.
#[derive(Debug)]
pub struct Provider {
    pub id: String,
    pub label: String,
    pub host: String,
    /// (part, the pattern all of it must match), in the entry's order
    parts: Vec<(String, Regex)>,
    pub method: String,
    pub path: String,
    /// sorted by name
    query: Vec<(String, String)>,
    /// (field, template with `{part}` where a part goes)
    headers: Vec<(String, Vec<u32>)>,
    body: Option<Vec<u32>>,
    /// (service, region)
    sigv4: Option<(String, String)>,
    rules: Vec<Rule>,
}

impl Provider {
    pub fn part_names(&self) -> Vec<&str> {
        self.parts.iter().map(|(n, _)| n.as_str()).collect()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// The request a provider is asked with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub host: String,
    /// the path and the query, as sent
    pub path: String,
    /// (field, value), in the table's order (AWS's `x-amz-date` and `authorization` last)
    pub headers: Vec<(String, String)>,
    /// the fields that carry the credential or a signature by it (a transport gives them to the host alone)
    pub secret_headers: Vec<String>,
    pub body: Option<String>,
}

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn text_of(v: Option<&Value>) -> Option<String> {
    v.and_then(|v| v.as_str()).map(pystr::to_string)
}

// ------------------------------------------------------------------------------------------------ the table

fn is_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 32 && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn is_part_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty() && b.len() <= 16 && b[0].is_ascii_lowercase()
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// A lower-case DNS name with a dot in it, at most 253 characters (secretverify_http.HOST_RE): labels of letters,
/// digits and inner hyphens, the last one starting with a letter and two characters long at least.
pub fn is_host(s: &str) -> bool {
    if s.is_empty() || s.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let ok = |l: &str| {
        let b = l.as_bytes();
        !b.is_empty() && b.len() <= 63
            && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            && b[0] != b'-' && b[b.len() - 1] != b'-'
    };
    let last = labels[labels.len() - 1].as_bytes();
    labels.iter().all(|l| ok(l)) && last.len() >= 2 && last[0].is_ascii_lowercase()
}

/// Every character printable ASCII, no space (and one at least).
fn printable_ascii(s: &[u32]) -> bool {
    !s.is_empty() && s.iter().all(|c| (0x21..=0x7e).contains(c))
}

/// The placeholder at `i` (`{part}`, a lower-case name: `\{([a-z][a-z0-9_]*)\}`): (the name, the index after it).
fn placeholder_at(t: &[u32], i: usize) -> Option<(String, usize)> {
    let lower = |c: u32| (b'a' as u32..=b'z' as u32).contains(&c);
    if t.get(i) != Some(&('{' as u32)) || !t.get(i + 1).map_or(false, |&c| lower(c)) {
        return None;
    }
    let mut j = i + 2;
    while j < t.len() && (lower(t[j]) || (b'0' as u32..=b'9' as u32).contains(&t[j]) || t[j] == '_' as u32) {
        j += 1;
    }
    (t.get(j) == Some(&('}' as u32))).then(|| (pystr::to_string(&t[i + 1..j]), j + 1))
}

/// The parts a template names, in order.
fn placeholders(t: &[u32]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < t.len() {
        match placeholder_at(t, i) {
            Some((name, next)) => {
                out.push(name);
                i = next;
            }
            None => i += 1,
        }
    }
    out
}

/// `t` with each placeholder replaced by its part's text (every one names a part: the table is checked).
fn fill(t: &[u32], parts: &[(String, Vec<u32>)]) -> Vec<u32> {
    let mut out = Vec::with_capacity(t.len());
    let mut i = 0;
    while i < t.len() {
        if let Some((name, next)) = placeholder_at(t, i) {
            if let Some((_, v)) = parts.iter().find(|(n, _)| *n == name) {
                out.extend_from_slice(v);
                i = next;
                continue;
            }
        }
        out.push(t[i]);
        i += 1;
    }
    out
}

fn want_of(v: &Value) -> Option<Want> {
    match v {
        Value::Str(s) => Some(Want::Str(s.clone())),
        Value::Bool(b) => Some(Want::Bool(*b)),
        _ => None,
    }
}

/// One provider entry, checked (the rules of secretverify.py's `validate`, whose messages these are).
pub fn provider_of(entry: &Value) -> Result<Provider, String> {
    let pid = text_of(entry.get("id")).filter(|s| is_id(s)).ok_or_else(|| "provider id is not a short name".to_string())?;
    let bad = |m: &str| Err(format!("{pid}: {m}"));
    let label = match text_of(entry.get("label")) {
        Some(l) if !l.is_empty() && l.chars().count() <= 60 => l,
        _ => return bad("label"),
    };
    let parts_v = match entry.get("parts").and_then(|p| p.as_obj()) {
        Some(p) if !p.is_empty() => p,
        _ => return bad("parts must be a mapping that has a secret"),
    };
    let mut parts = Vec::new();
    for (name, pattern) in parts_v {
        let name = pystr::to_string(name);
        let Some(pat) = pattern.as_str() else { return bad("a part") };
        if !is_part_name(&name) {
            return bad("a part");
        }
        match Regex::new(pat, 0) {
            Ok(rx) => parts.push((name, rx)),
            Err(_) => return bad(&format!("the pattern of {name} does not compile")),
        }
    }
    if !parts.iter().any(|(n, _)| n == "secret") {
        return bad("parts must be a mapping that has a secret");
    }
    let host = match text_of(entry.get("host")) {
        Some(h) if is_host(&h) => h,
        _ => return bad("host is not a lower-case DNS name"),
    };
    let Some(req) = entry.get("request").filter(|r| r.as_obj().is_some()) else { return bad("request.method") };
    let method = match text_of(req.get("method")) {
        Some(m) if m == "GET" || m == "POST" => m,
        _ => return bad("request.method"),
    };
    let path = match req.get("path").and_then(|p| p.as_str()) {
        Some(p) if p.first() == Some(&('/' as u32)) && !p.contains(&('{' as u32)) && printable_ascii(p) => pystr::to_string(p),
        _ => return bad("request.path must be printable, start with / and hold no part"),
    };
    let mut query = Vec::new();
    match req.get("query") {
        None => {}
        Some(Value::Obj(items)) => {
            for (k, v) in items {
                match v.as_str() {
                    Some(v) if !k.contains(&('{' as u32)) && !v.contains(&('{' as u32)) => {
                        query.push((pystr::to_string(k), pystr::to_string(v)))
                    }
                    _ => return bad("request.query is a mapping of text that holds no part"),
                }
            }
        }
        Some(_) => return bad("request.query is a mapping of text that holds no part"),
    }
    query.sort();
    let mut used: Vec<String> = Vec::new();
    let mut headers = Vec::new();
    match req.get("headers") {
        None | Some(Value::Null) => {}
        Some(Value::Obj(items)) => {
            for (name, t) in items {
                let Some(t) = t.as_str() else { return bad("request.headers holds something that is not text") };
                for r in placeholders(t) {
                    if !parts.iter().any(|(n, _)| *n == r) {
                        return bad(&format!("request.headers names the part '{r}', which is not one"));
                    }
                    used.push(r);
                }
                headers.push((pystr::to_string(name), t.to_vec()));
            }
        }
        Some(_) => return bad("request.headers holds something that is not text"),
    }
    let body = match req.get("body") {
        None | Some(Value::Null) => None,
        Some(Value::Str(t)) => {
            for r in placeholders(t) {
                if !parts.iter().any(|(n, _)| *n == r) {
                    return bad(&format!("request.body names the part '{r}', which is not one"));
                }
                used.push(r);
            }
            if method != "POST" {
                return bad("a body is for a POST");
            }
            Some(t.clone())
        }
        Some(_) => return bad("request.body holds something that is not text"),
    };
    let sigv4 = match req.get("sigv4") {
        None | Some(Value::Null) => None,
        Some(Value::Obj(items)) => {
            let service = text_of(req.get("sigv4").and_then(|s| s.get("service"))).unwrap_or_default();
            let region = text_of(req.get("sigv4").and_then(|s| s.get("region"))).unwrap_or_default();
            if items.len() != 2 || service.is_empty() || region.is_empty() {
                return bad("request.sigv4 is a service and a region");
            }
            Some((service, region))
        }
        Some(_) => return bad("request.sigv4 is a service and a region"),
    };
    if sigv4.is_some() {
        let mut names: Vec<&str> = parts.iter().map(|(n, _)| n.as_str()).collect();
        names.sort();
        if names != ["id", "secret"] {
            return bad("a signed request is signed with an id and a secret");
        }
        if used.iter().any(|u| u == "secret") {
            return bad("a signed request does not send its secret");
        }
    } else if !used.iter().any(|u| u == "secret") {
        return bad("the secret is sent nowhere");
    }
    let rules = match entry.get("answers").and_then(|a| a.as_arr()) {
        Some(a) if !a.is_empty() => rules_of(a).map_err(|m| format!("{pid}: {m}"))?,
        _ => return bad("answers"),
    };
    Ok(Provider { id: pid, label, host, parts, method, path, query, headers, body, sigv4, rules })
}

/// Answer rules, checked (as `provider_of` checks a provider's).
pub fn rules_of(answers: &[Value]) -> Result<Vec<Rule>, String> {
    const KEYS: [&str; 6] = ["status", "json", "code", "outcome", "why", "who"];
    let mut rules = Vec::new();
    for rule in answers {
        let Some(items) = rule.as_obj() else { return Err("an answer rule".into()) };
        if items.iter().any(|(k, _)| !KEYS.contains(&pystr::to_string(k).as_str())) {
            return Err("an answer rule".into());
        }
        let Some(outcome) = text_of(rule.get("outcome")).and_then(|o| Outcome::parse(&o)) else {
            return Err("an answer rule".into());
        };
        let status = match rule.get("status").and_then(|s| s.as_arr()) {
            Some(list) if !list.is_empty() && list.iter().all(|s| matches!(s, Value::Int(n) if (100..600).contains(n))) => {
                list.iter().filter_map(|s| s.as_i64()).collect()
            }
            _ => return Err("an answer rule needs a status list".into()),
        };
        let mut json_cond = Vec::new();
        match rule.get("json") {
            None | Some(Value::Null) => {}
            Some(Value::Obj(items)) if !items.is_empty() => {
                for (k, v) in items {
                    let want = match v {
                        Value::Arr(list) if !list.is_empty() => {
                            let wants: Option<Vec<Want>> = list.iter().map(want_of).collect();
                            wants.map(Want::Any)
                        }
                        other => want_of(other),
                    };
                    match want {
                        Some(w) if !k.is_empty() => json_cond.push((pystr::to_string(k), w)),
                        _ => return Err("an answer rule's json condition".into()),
                    }
                }
            }
            Some(_) => return Err("an answer rule's json condition".into()),
        }
        let code = match rule.get("code") {
            None | Some(Value::Null) => None,
            Some(Value::Arr(list)) if !list.is_empty() && list.iter().all(|c| matches!(c, Value::Str(s) if !s.is_empty())) => {
                Some(list.iter().filter_map(|c| c.as_str().map(|s| s.to_vec())).collect())
            }
            Some(_) => return Err("an answer rule's code condition".into()),
        };
        let why = match rule.get("why") {
            None | Some(Value::Null) => None,
            Some(Value::Str(s)) if s.len() <= 100 => Some(s.clone()),
            Some(_) => return Err("an answer rule's why".into()),
        };
        let who = match rule.get("who") {
            None | Some(Value::Null) => None,
            Some(Value::Obj(items)) if outcome == Outcome::Live && items.len() == 1 => {
                let (k, v) = &items[0];
                match (pystr::to_string(k).as_str(), v.as_str()) {
                    ("json", Some(path)) => Some(Who::Json(pystr::to_string(path))),
                    ("xml", Some(tag)) => {
                        let mut pattern = cps("<");
                        pattern.extend(crate::pyre::escape(tag));
                        pattern.extend(cps(">([^<]{1,300})</"));
                        pattern.extend(crate::pyre::escape(tag));
                        pattern.extend(cps(">"));
                        Some(Who::Xml(Regex::new(&pattern, 0).map_err(|_| "who belongs to a live rule and is a json path or an xml tag")?))
                    }
                    _ => return Err("who belongs to a live rule and is a json path or an xml tag".into()),
                }
            }
            Some(_) => return Err("who belongs to a live rule and is a json path or an xml tag".into()),
        };
        rules.push(Rule { status, json: json_cond, code, outcome, why, who });
    }
    Ok(rules)
}

/// The pack's table, read and checked once: its providers, or why it is not one (a table that is not one verifies
/// nothing; `scripts/make_rust_tables.py --check` keeps one from shipping).
pub fn table(p: &Pack) -> &Result<Vec<Provider>, String> {
    p.derived(TABLE, |raw| {
        let entries = raw.get("value").and_then(|v| v.as_arr()).ok_or_else(|| "the table is not a list".to_string())?;
        let mut out: Vec<Provider> = Vec::new();
        for e in entries {
            let provider = provider_of(e)?;
            if out.iter().any(|q| q.id == provider.id) {
                return Err(format!("provider id {:?} is not a short name or is repeated", provider.id));
            }
            out.push(provider);
        }
        Ok(out)
    })
}

/// A provider of the pack's table, by its id.
pub fn by_id<'p>(p: &'p Pack, id: &str) -> Result<&'p Provider, String> {
    match table(p) {
        Ok(t) => t.iter().find(|q| q.id == id).ok_or_else(|| format!("no provider {id:?}")),
        Err(m) => Err(m.clone()),
    }
}

/// The providers whose one-part pattern matches all of `text` (a credential found in a file). The patterns do not
/// overlap, so it names one at most; a provider whose credential is a pair (AWS) is not named by one part.
pub fn identify(providers: &[Provider], text: &[u32]) -> Vec<String> {
    if text.is_empty() || text.len() > MAX_CREDENTIAL {
        return Vec::new();
    }
    providers
        .iter()
        .filter(|q| q.parts.len() == 1 && q.parts[0].0 == "secret" && q.parts[0].1.fullmatch(text).is_some())
        .map(|q| q.id.clone())
        .collect()
}

// ------------------------------------------------------------------------------------------------ in a file's lines

/// The most pairs of a credential of two parts (AWS's key id and secret key) asked about for one file.
pub const MAX_PAIRS: usize = 8;
/// The most ids, and the most secrets, of a credential of two parts that one file's lines are read for.
pub const MAX_HALVES: usize = 64;

/// A credential a provider names in a file's lines: its parts (in the table's order) and the lines it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub provider: String,
    pub parts: Vec<(String, Vec<u32>)>,
    pub lines: Vec<i64>,
}

fn word_char(c: u32) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A) || [b'_', b'-', b'+', b'/'].iter().any(|&b| c == b as u32)
}

/// The words of a line a credential may be: its longest runs of letters, digits and `_-+/` (a credential holds no other
/// character the table's patterns take: no quote, space, `=`, `:`, `@` or `.`), and, of a run with a slash in it, the
/// pieces between its slashes too (a token at the end of a URL's path); none longer than [`MAX_CREDENTIAL`].
fn words(line: &[u32]) -> Vec<&[u32]> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < line.len() {
        if !word_char(line[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < line.len() && word_char(line[i]) {
            i += 1;
        }
        let run = &line[start..i];
        if run.len() <= MAX_CREDENTIAL {
            out.push(run);
        }
        if run.contains(&('/' as u32)) {
            out.extend(run.split(|&c| c == '/' as u32).filter(|w| !w.is_empty() && w.len() <= MAX_CREDENTIAL));
        }
    }
    out
}

fn found(out: &mut Vec<Found>, provider: &str, parts: Vec<(String, Vec<u32>)>, lines: &[i64]) {
    match out.iter_mut().find(|f| f.provider == provider && f.parts == parts) {
        Some(f) => {
            for n in lines {
                if !f.lines.contains(n) {
                    f.lines.push(*n);
                }
            }
            f.lines.sort_unstable();
        }
        None => {
            let mut lines = lines.to_vec();
            lines.sort_unstable();
            lines.dedup();
            out.push(Found { provider: provider.to_string(), parts, lines })
        }
    }
}

/// The values of `lines`' words that `rx` matches all of, each with the lines it is on (at most [`MAX_HALVES`]).
fn halves(lines: &[(i64, Vec<u32>)], rx: &Regex) -> Vec<(Vec<u32>, Vec<i64>)> {
    let mut out: Vec<(Vec<u32>, Vec<i64>)> = Vec::new();
    for (n, text) in lines {
        for w in words(text) {
            if rx.fullmatch(w).is_none() {
                continue;
            }
            let room = out.len() < MAX_HALVES;
            match out.iter_mut().find(|(v, _)| v.as_slice() == w) {
                Some((_, at)) if !at.contains(n) => at.push(*n),
                Some(_) => {}
                None if room => out.push((w.to_vec(), vec![*n])),
                None => {}
            }
        }
    }
    out
}

/// The credentials the providers name in `lines` (a file's lines that hold a secret finding: (number, text)), each once,
/// with the lines it is on: a one-part provider's where a word is all of one ([`identify`]); a provider's of an id and a
/// secret (AWS's key pair) an id and a secret among the words, paired nearest lines first, at most [`MAX_PAIRS`] pairs.
/// Only what is on the lines given is read: a pair is of one file, never of two.
pub fn find(providers: &[Provider], lines: &[(i64, Vec<u32>)]) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    for (n, text) in lines {
        for w in words(text) {
            for pid in identify(providers, w) {
                found(&mut out, &pid, vec![("secret".to_string(), w.to_vec())], &[*n]);
            }
        }
    }
    for q in providers {
        let mut names = q.part_names();
        names.sort_unstable();
        if names != ["id", "secret"] {
            continue;
        }
        let rx = |name: &str| &q.parts.iter().find(|(n, _)| n == name).expect("the part is there").1;
        let (ids, secrets) = (halves(lines, rx("id")), halves(lines, rx("secret")));
        let mut pairs: Vec<(i64, usize, usize)> = Vec::new();
        for (a, (id, id_lines)) in ids.iter().enumerate() {
            for (b, (secret, secret_lines)) in secrets.iter().enumerate() {
                if id == secret {
                    continue;
                }
                let near = id_lines.iter().flat_map(|x| secret_lines.iter().map(move |y| (x - y).abs())).min().unwrap_or(i64::MAX);
                pairs.push((near, a, b));
            }
        }
        pairs.sort_unstable();
        for (_, a, b) in pairs.into_iter().take(MAX_PAIRS) {
            let parts = q.parts.iter().map(|(name, _)| {
                let value = if name == "id" { &ids[a].0 } else { &secrets[b].0 };
                (name.clone(), value.clone())
            }).collect();
            let at: Vec<i64> = ids[a].1.iter().chain(&secrets[b].1).copied().collect();
            found(&mut out, &q.id, parts, &at);
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ the request

/// Percent-encoding of everything but letters, digits and `-_.~` (Python's `urllib.parse.quote(t, safe="")`).
fn quote(t: &str) -> String {
    let mut out = String::new();
    for b in t.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HMAC-SHA-256 (RFC 2104) over pratique's SHA-256 (its pure part keeps HMAC behind the network feature).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = if key.len() > 64 { Sha256::digest(key) } else { key.to_vec() };
    k.resize(64, 0);
    let mut inner = Sha256::new();
    inner.update(&k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(&inner);
    outer.finalize()
}

/// The key a request is signed with (AWS's "Signature Version 4 signing process"): HMAC over the date (`YYYYMMDD`),
/// the region, the service and `aws4_request`, from `AWS4` and the secret access key.
pub fn signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = hmac_sha256(format!("AWS4{secret_key}").as_bytes(), date.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    key
}

/// The fields to send with a request signed with Signature Version 4: `headers` as given, then `x-amz-date` and
/// `authorization`. Every field given is signed, with `host` and `x-amz-date`; `path` is the request's path as sent
/// (encoded), without its query; `amz_date` is `YYYYMMDDTHHMMSSZ` (UTC).
#[allow(clippy::too_many_arguments)]
pub fn sigv4(method: &str, host: &str, path: &str, query: &[(String, String)], body: &[u8], headers: &[(String, String)],
             access_key: &str, secret_key: &str, region: &str, service: &str, amz_date: &str) -> Vec<(String, String)> {
    let date = &amz_date[..8];
    let mut signed: Vec<(String, String)> = Vec::new();
    let mut put = |name: String, value: String| match signed.iter_mut().find(|(n, _)| *n == name) {
        Some(slot) => slot.1 = value,
        None => signed.push((name, value)),
    };
    for (name, value) in headers {
        // (the value's runs of white space as one space, ends trimmed: Python's " ".join(value.split()))
        let collapsed: Vec<String> = value
            .split(|c: char| unicode::is_space(c as u32))
            .filter(|w| !w.is_empty())
            .map(|w| w.to_string())
            .collect();
        put(name.to_lowercase(), collapsed.join(" "));
    }
    put("host".to_string(), host.to_string());
    put("x-amz-date".to_string(), amz_date.to_string());
    signed.sort();
    let canonical_headers: String = signed.iter().map(|(n, v)| format!("{n}:{v}\n")).collect();
    let signed_headers = signed.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(";");
    let mut q = query.to_vec();
    q.sort();
    let canonical_query = q.iter().map(|(k, v)| format!("{}={}", quote(k), quote(v))).collect::<Vec<_>>().join("&");
    let payload = hex(&Sha256::digest(body));
    let canonical = [method, path, &canonical_query, &canonical_headers, &signed_headers, &payload].join("\n");
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = [ALGORITHM, amz_date, &scope, &hex(&Sha256::digest(canonical.as_bytes()))].join("\n");
    let signature = hex(&hmac_sha256(&signing_key(secret_key, date, region, service), to_sign.as_bytes()));
    let mut out = headers.to_vec();
    out.push(("x-amz-date".to_string(), amz_date.to_string()));
    out.push((
        "authorization".to_string(),
        format!("{ALGORITHM} Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"),
    ));
    out
}

/// `YYYYMMDDTHHMMSSZ`?
pub fn is_amz_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 16 && b[8] == b'T' && b[15] == b'Z'
        && b[..8].iter().chain(&b[9..15]).all(|c| c.is_ascii_digit())
}

/// The credential's parts if they are this provider's: the same parts, each printable ASCII (no space, no line
/// break, so no part can add a field to a request), at most MAX_CREDENTIAL characters, all of it matching the part's
/// pattern.
fn checked_parts(q: &Provider, parts: &[(String, Vec<u32>)]) -> Option<Vec<(String, Vec<u32>)>> {
    if parts.len() != q.parts.len() {
        return None;
    }
    let mut out = Vec::new();
    for (name, rx) in &q.parts {
        let (_, value) = parts.iter().find(|(n, _)| n == name)?;
        if value.len() > MAX_CREDENTIAL || !printable_ascii(value) || rx.fullmatch(value).is_none() {
            return None;
        }
        out.push((name.clone(), value.clone()));
    }
    Some(out)
}

/// The request that asks `q` whether the credential (`parts`) is live, at `amz_date` (the signed requests' time), or
/// why none is made (`NOT_THIS_FORMAT`).
pub fn request(q: &Provider, parts: &[(String, Vec<u32>)], amz_date: &str) -> Result<Request, &'static str> {
    let parts = checked_parts(q, parts).ok_or(NOT_THIS_FORMAT)?;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut secret_headers = Vec::new();
    for (name, t) in &q.headers {
        if !placeholders(t).is_empty() {
            secret_headers.push(name.clone());
        }
        headers.push((name.clone(), pystr::to_string(&fill(t, &parts))));
    }
    let body = q.body.as_ref().map(|t| pystr::to_string(&fill(t, &parts)));
    let mut path = q.path.clone();
    if !q.query.is_empty() {
        path.push('?');
        path.push_str(&q.query.iter().map(|(k, v)| format!("{}={}", quote(k), quote(v))).collect::<Vec<_>>().join("&"));
    }
    if let Some((service, region)) = &q.sigv4 {
        let part = |n: &str| parts.iter().find(|(p, _)| p == n).map(|(_, v)| pystr::to_string(v)).unwrap_or_default();
        headers = sigv4(&q.method, &q.host, &q.path, &q.query, body.as_deref().unwrap_or("").as_bytes(), &headers,
                        &part("id"), &part("secret"), region, service, amz_date);
        secret_headers.push("authorization".to_string());
    }
    Ok(Request { method: q.method.clone(), host: q.host.clone(), path, headers, secret_headers, body })
}

// ------------------------------------------------------------------------------------------------ reading an answer

/// `value` as text that is safe to print, or None: printable characters only (the others, and the line and paragraph
/// separators, "?"), at most MAX_WHO of them, with a credential's part (which should not be in an answer at all)
/// replaced: each run of characters that some occurrence of a part covers, overlapping or side by side, is one
/// `[redacted]`. The parts are looked for in all of the text, as shown, before it is cut (stage 1 looked in its first
/// 320 characters, so a part over 240 characters long that began in the first 80 and ran past them kept its start).
pub fn safe_text(value: &[u32], secrets: &[Vec<u32>]) -> Option<Vec<u32>> {
    if value.is_empty() {
        return None;
    }
    let shown = |c: u32| if unicode::is_printable(c) && c != 0x2028 && c != 0x2029 { c } else { '?' as u32 };
    let parts: Vec<&Vec<u32>> = secrets.iter().filter(|s| !s.is_empty()).collect();
    let redacted = cps("[redacted]");
    let mut out = Vec::new();
    let mut covered = 0; // (the end of the occurrences found so far)
    let mut in_run = false;
    let mut i = 0;
    while i < value.len() && out.len() < MAX_WHO {
        for s in &parts {
            if i + s.len() > covered && value.len() - i >= s.len() && s.iter().zip(&value[i..]).all(|(a, &b)| *a == shown(b)) {
                covered = i + s.len();
            }
        }
        if i < covered {
            if !in_run {
                out.extend_from_slice(&redacted);
                in_run = true;
            }
        } else {
            out.push(shown(value[i]));
            in_run = false;
        }
        i += 1;
    }
    out.truncate(MAX_WHO);
    Some(out)
}

/// The body of an answer, read as JSON or as text when a rule first asks.
struct Answer<'a> {
    bytes: &'a [u8],
    truncated: bool,
    json: std::cell::OnceCell<Option<Value>>,
    text: std::cell::OnceCell<Vec<u32>>,
}

impl Answer<'_> {
    fn json(&self) -> Option<&Value> {
        self.json
            .get_or_init(|| {
                if self.truncated {
                    return None;
                }
                let text = std::str::from_utf8(self.bytes).ok()?;
                json::parse(&cps(text)).ok()
            })
            .as_ref()
    }

    fn text(&self) -> &[u32] {
        self.text.get_or_init(|| cps(&String::from_utf8_lossy(self.bytes)))
    }
}

/// The value at a dotted path of a JSON document (an object's last value for a key, as Python's json keeps it).
fn dig<'v>(doc: &'v Value, path: &str) -> Option<&'v Value> {
    let mut at = doc;
    for key in path.split('.') {
        let k = cps(key);
        at = at.as_obj()?.iter().rev().find(|(n, _)| *n == k).map(|(_, v)| v)?;
    }
    Some(at)
}

fn equal(actual: Option<&Value>, want: &Want) -> bool {
    match want {
        Want::Any(ws) => ws.iter().any(|w| equal(actual, w)),
        Want::Bool(b) => matches!(actual, Some(Value::Bool(a)) if a == b),
        Want::Str(s) => matches!(actual, Some(Value::Str(a)) if a == s),
    }
}

/// What a provider's answer says: (outcome, the reason, the owner's name). The first rule whose conditions hold
/// decides; no rule is unknown. An answer cut short is read by its status alone: a condition on its body does not hold.
pub fn judge(rules: &[Rule], status: i64, body: &[u8], truncated: bool, secrets: &[Vec<u32>]) -> (Outcome, Vec<u32>, Option<Vec<u32>>) {
    static CODE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let code_rx = CODE.get_or_init(|| {
        Regex::new(&cps(r"<Code>\s*([A-Za-z0-9_.:-]{1,80})\s*</Code>"), 0).expect("the code pattern compiles")
    });
    let answer = Answer { bytes: body, truncated, json: Default::default(), text: Default::default() };
    for rule in rules {
        if !rule.status.contains(&status) {
            continue;
        }
        if !rule.json.is_empty() {
            let Some(doc) = answer.json().filter(|d| d.as_obj().is_some()) else { continue };
            if !rule.json.iter().all(|(path, want)| equal(dig(doc, path), want)) {
                continue;
            }
        }
        if let Some(codes) = &rule.code {
            if truncated {
                continue;
            }
            let found = code_rx.search(answer.text()).map(|m| m.group(1).unwrap_or(&[]).to_vec());
            if !found.map_or(false, |c| codes.contains(&c)) {
                continue;
            }
        }
        let who = match &rule.who {
            Some(Who::Json(path)) => match answer.json().filter(|d| d.as_obj().is_some()) {
                Some(doc) => match dig(doc, path) {
                    Some(Value::Str(s)) => safe_text(s, secrets),
                    _ => None,
                },
                None => None,
            },
            Some(Who::Xml(rx)) if !truncated => {
                rx.search(answer.text()).and_then(|m| m.group(1).map(|g| g.to_vec())).and_then(|g| safe_text(&g, secrets))
            }
            _ => None,
        };
        let detail = rule.why.as_ref().and_then(|w| safe_text(w, secrets)).unwrap_or_else(|| cps(&format!("HTTP {status}")));
        return (rule.outcome, detail, who);
    }
    let detail = if truncated {
        format!("the answer was larger than {MAX_ANSWER_BYTES} bytes (HTTP {status})")
    } else if (500..=599).contains(&status) {
        format!("the provider failed (HTTP {status})")
    } else {
        format!("the answer was not one this module knows (HTTP {status})")
    };
    (Outcome::Unknown, cps(&detail), None)
}

#[cfg(test)]
#[path = "secrets_tests.rs"]
mod tests;
