//! The install-script and import-time tests: a port of lazaret.scanner.core's
//! `install_script_risk`, `import_time_risk`, `import_time_severity` and the
//! detectors they read (sections "Install-script and import-time
//! inspection" to "Code hidden off-screen", and "Import-time inspection"),
//! function for function. Offsets are code-point indices, as in Python.

use crate::lexer;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::received;
use crate::rxutil;
use std::collections::HashSet;

const fn c(ch: char) -> u32 {
    ch as u32
}

fn has(text: &[u32], needle: &str) -> bool {
    pystr::contains(text, needle)
}

fn any_in(text: &[u32], needles: &pystr::Needles) -> bool {
    needles.any_in(text)
}

fn cat_reason(p: &Pack, cat: &str) -> PyStr {
    p.map_strs("_DL_CATEGORY_REASON")
        .iter()
        .find(|(k, _)| pystr::eq(k, cat))
        .and_then(|(_, v)| v.first().cloned())
        .unwrap_or_default()
}

fn cat(parts: &[&[u32]]) -> PyStr {
    pystr::concat(parts)
}

/// s[:n] (code points)
fn head(s: &[u32], n: usize) -> &[u32] {
    pystr::upto(s, n)
}

/// text.count("\n", 0, at) + 1
fn line_of(text: &[u32], at: usize) -> usize {
    pystr::count_char(text, c('\n'), 0, at) + 1
}

// ---------------- pipes and substitutions ----------------

/// core._pipes_download_to_shell
pub fn pipes_download_to_shell(p: &Pack, text: &[u32]) -> bool {
    let mut download = false;
    for m in p.re("_PIPE_SCAN_RE").finditer(text) {
        let token = m.group0();
        if token.first() == Some(&c('|')) && token.len() > 1 {
            if download {
                return true;
            }
            download = false;
        } else if token.len() == 1 && matches!(token[0], 0x0A | 0x7C | 0x3B | 0x26) {
            download = false;
        } else {
            download = true;
        }
    }
    false
}

/// core.runs_substituted_download
pub fn runs_substituted_download(p: &Pack, row: &[u32]) -> bool {
    (has(row, "curl") || has(row, "wget"))
        && p.re("_DL_SUBST_NEEDLE_RE").search(row).is_some()
        && p.re("_DL_SUBST_RE").search(row).is_some()
}

// ---------------- PowerShell ----------------

fn powershell_script_risk(p: &Pack, ps: &[u32]) -> Option<&'static str> {
    if p.re("_PS_CRADLE_RE").search(ps).is_some()
        || (p.re("_PS_DOWNLOAD_FILE_RE").search(ps).is_some() && p.re("_PS_START_RE").search(ps).is_some())
    {
        Some("downloads and runs code")
    } else {
        None
    }
}

fn b64_value(ch: u32) -> Option<u32> {
    match ch {
        0x41..=0x5A => Some(ch - 0x41),
        0x61..=0x7A => Some(ch - 0x61 + 26),
        0x30..=0x39 => Some(ch - 0x30 + 52),
        0x2B => Some(62),
        0x2F => Some(63),
        _ => None,
    }
}

/// base64.b64decode(s, validate=True) for text of the alphabet and at most
/// two trailing '=' (what the callers hand it): None where Python raises.
pub fn b64decode_strict(s: &[u32]) -> Option<Vec<u8>> {
    let pads = s.iter().rev().take_while(|&&x| x == c('=')).count();
    if pads > 2 || s.len() % 4 != 0 {
        return None;
    }
    let data = &s[..s.len() - pads];
    if data.len() % 4 == 1 {
        return None;
    }
    if pads > 0 && data.len() % 4 + pads != 4 {
        return None;
    }
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &ch in data {
        acc = (acc << 6) | b64_value(ch)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// bytes.decode("utf-16-le", "replace") for an even number of bytes.
pub fn utf16le_replace(data: &[u8]) -> PyStr {
    let units: Vec<u32> = data.chunks(2).filter(|w| w.len() == 2).map(|w| w[0] as u32 | (w[1] as u32) << 8).collect();
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let w = units[i];
        if (0xD800..0xDC00).contains(&w) {
            if let Some(&lo) = units.get(i + 1) {
                if (0xDC00..0xE000).contains(&lo) {
                    out.push(0x10000 + ((w - 0xD800) << 10) + (lo - 0xDC00));
                    i += 2;
                    continue;
                }
            }
            out.push(0xFFFD);
        } else if (0xDC00..0xE000).contains(&w) {
            out.push(0xFFFD);
        } else {
            out.push(w);
        }
        i += 1;
    }
    out
}

fn decode_powershell(p: &Pack, b64: &[u32]) -> PyStr {
    let b64 = head(b64, p.usize("_PS_ENCODED_MAX"));
    let mut s: PyStr = b64.to_vec();
    if s.last() == Some(&c('=')) {
        s.truncate(s.len() - s.len() % 4);
    } else {
        let pad = (4 - s.len() % 4) % 4;
        s.extend(std::iter::repeat(c('=')).take(pad));
    }
    match b64decode_strict(&s) {
        None => Vec::new(),
        Some(data) => utf16le_replace(&data[..data.len() / 2 * 2]),
    }
}

/// core.powershell_risk
pub fn powershell_risk(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    if p.re("_PS_RE").search(text).is_none() {
        return Vec::new();
    }
    let mut reasons = Vec::new();
    if let Some(m) = p.re("_PS_ENCODED_RE").search(text) {
        let decoded = decode_powershell(p, m.group(1).unwrap_or(&[]));
        let mut r = u("runs an encoded PowerShell command");
        if let Some(does) = powershell_script_risk(p, &decoded) {
            r.extend(u(" that "));
            r.extend(u(does));
        }
        reasons.push(r);
    }
    if reasons.is_empty() {
        if let Some(does) = powershell_script_risk(p, text) {
            reasons.push(cat(&[&u("runs PowerShell that "), &u(does)]));
        }
    }
    reasons
}

// ---------------- stagers ----------------

/// core._string_literals: (offset, contents), at most _STAGER_MAX_LITERALS.
fn string_literals(p: &Pack, text: &[u32]) -> Vec<(usize, PyStr)> {
    let max = p.usize("_STAGER_MAX_LITERALS");
    let n = text.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n && out.len() < max {
        let ch = text[i];
        if !matches!(ch, 0x22 | 0x27 | 0x60) {
            i += 1;
            continue;
        }
        let triple = [ch, ch, ch];
        if ch != c('`') && text.len() >= i + 3 && text[i..i + 3] == triple {
            let end = pystr::find(text, &triple, i + 3).unwrap_or(n);
            out.push((i, pystr::sub(text, i + 3, end).to_vec()));
            i = end + 3;
            continue;
        }
        let mut j = i + 1;
        while j < n && text[j] != ch && (ch == c('`') || text[j] != c('\n')) {
            j += if text[j] == c('\\') { 2 } else { 1 };
        }
        out.push((i, pystr::sub(text, i + 1, j.min(n)).to_vec()));
        i = j + 1;
    }
    out
}

/// core.stager_at
pub fn stager_at(p: &Pack, text: &[u32]) -> isize {
    let net = p.needles("_STAGER_NET_NEEDLES");
    if !any_in(text, net) {
        return -1;
    }
    let run = p.needles("_STAGER_RUN_NEEDLES");
    let min = p.usize("_STAGER_MIN");
    for (at, lit) in string_literals(p, text) {
        if lit.len() >= min && any_in(&lit, run) && any_in(&lit, net) {
            let code = pystr::replace_char(&lit, c(';'), c('\n'));
            if let Some((_, kind)) = received::received_code_kind(p, &code, &[], &[]) {
                if kind == "run" {
                    return at as isize;
                }
            }
        }
    }
    -1
}

// ---------------- reverse shells, host information ----------------

/// core.reverse_shell_at
pub fn reverse_shell_at(p: &Pack, text: &[u32]) -> isize {
    if let Some(m) = p.re("_REVSHELL_LINE_RE").search(text) {
        return m.start() as isize;
    }
    if has(text, "dup2") {
        if let Some(m) = p.re("_REVSHELL_DUP2_RE").search(text) {
            if p.re("_REVSHELL_SHELL_RE").search(text).is_some() {
                return m.start() as isize;
            }
        }
    }
    if has(text, "pty") && has(text, "socket") && has(text, "connect") && has(text, "pty.spawn") {
        return pystr::find_str(text, "pty.spawn", 0).map(|i| i as isize).unwrap_or(-1);
    }
    if has(text, "spawn") {
        if let Some(m) = p.re("_REVSHELL_JS_SPAWN_RE").search(text) {
            if p.re("_REVSHELL_JS_PIPE_RE").search(text).is_some() && p.re("_REVSHELL_JS_NET_RE").search(text).is_some()
            {
                return m.start() as isize;
            }
        }
    }
    // an argument list, or a shell or netcat run with an ngrok TCP address (0.1.8)
    if any_in(text, p.needles("_REVSHELL_ARGS_NEEDLES")) {
        if let Some(m) = p.re("_REVSHELL_ARGS_RE").search(text) {
            return m.start() as isize;
        }
    }
    if any_in(text, p.needles("_REVSHELL_NGROK_NEEDLES")) {
        if let Some(m) = p.re("_REVSHELL_NGROK_TCP_RE").search(text) {
            if p.re("_REVSHELL_ARG_SHELL_RE").search(text).is_some() && p.re("_EXEC_CALL_RE").search(text).is_some() {
                return m.start() as isize;
            }
        }
    }
    -1
}

/// core.sends_host_info
pub fn sends_host_info(p: &Pack, text: &[u32]) -> bool {
    p.re("_HOST_INFO_RE").search(text).is_some()
        && (p.re("_NETWORK_RE").search(text).is_some() || p.re("_EXFIL_SERVICE_RE").search(text).is_some())
}

// ---------------- exfiltration shapes (0.1.8) ----------------

/// core.capture_service: the first data-capture service the text names,
/// else an ngrok tunnel's address (searched only where "ngrok" is).
pub fn capture_service<'s>(p: &'s Pack, text: &'s [u32]) -> Option<crate::pyre::Match<'s>> {
    if let Some(m) = p.re("_CAPTURE_SERVICE_RE").search(text) {
        return Some(m);
    }
    if has(text, "ngrok") {
        return p.re("_NGROK_TUNNEL_RE").search(text);
    }
    None
}

/// s.rsplit(sep, maxsplit)
fn rsplit_char(s: &[u32], sep: u32, maxsplit: usize) -> Vec<&[u32]> {
    let mut parts: Vec<&[u32]> = Vec::new();
    let mut end = s.len();
    let mut splits = 0;
    let mut i = s.len();
    while i > 0 && splits < maxsplit {
        i -= 1;
        if s[i] == sep {
            parts.push(&s[i + 1..end]);
            end = i;
            splits += 1;
        }
    }
    parts.push(&s[..end]);
    parts.reverse();
    parts
}

/// len(set(s))
fn distinct(s: &[u32]) -> usize {
    s.iter().collect::<HashSet<_>>().len()
}

/// core.chat_secret_at: (offset, reason) of the first chat bot or webhook
/// secret written in a text that makes network calls.
pub fn chat_secret_at(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    if !any_in(text, p.needles("_CHAT_SECRET_NEEDLES")) {
        return None;
    }
    p.re("_NETWORK_RE").search(text)?;
    let max = p.usize("_CHAT_SECRET_MAX");
    let min_distinct = p.usize("_CHAT_SECRET_MIN_DISTINCT");
    for (k, m) in p.re("_CHAT_SECRET_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let found = m.group0();
        if pystr::starts_with(found, "discord") || pystr::starts_with(found, "Discord") {
            let parts = rsplit_char(found, c('/'), 2);
            let (hook, secret) = (parts[1], parts[2]);
            if distinct(secret) >= min_distinct {
                return Some((
                    m.start(),
                    cat(&[&u("sends data to a Discord webhook whose token is written in the code (webhook "), hook, &u(")")]),
                ));
            }
        } else if pystr::starts_with(found, "hooks.") {
            let parts = rsplit_char(found, c('/'), 3);
            let (team, secret) = (parts[1], parts[3]);
            if distinct(secret) >= min_distinct && !pystr::strip_chars(team, "T0").is_empty() {
                return Some((
                    m.start(),
                    cat(&[&u("sends data to a Slack webhook whose key is written in the code ("), team, &u(")")]),
                ));
            }
        } else {
            let colon = pystr::find_char(found, c(':'), 0).unwrap_or(found.len());
            let (bot, secret) = (&found[..colon], pystr::from(found, colon + 1));
            if distinct(secret) >= min_distinct && p.re("_TELEGRAM_API_RE").search(text).is_some() {
                return Some((
                    m.start(),
                    cat(&[&u("sends data to a Telegram bot whose token is written in the code (bot "), bot, &u(")")]),
                ));
            }
        }
    }
    None
}

/// core.credential_sweep_at: (offset, folder names) where the text names
/// _CRED_SWEEP_MIN distinct credential folders within _CRED_SWEEP_SPAN.
pub fn credential_sweep_at(p: &Pack, text: &[u32]) -> Option<(usize, Vec<PyStr>)> {
    let min = p.usize("_CRED_SWEEP_MIN");
    if p.strs("_CRED_SWEEP_NEEDLES").iter().filter(|nd| pystr::find(text, nd, 0).is_some()).count() < min {
        return None;
    }
    let span = p.usize("_CRED_SWEEP_SPAN");
    let max = p.usize("_CRED_SWEEP_MAX");
    let mut found: Vec<(usize, PyStr)> = Vec::new();
    for (k, m) in p.re("_CRED_DIR_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        found.push((m.start(), pystr::replace_char(m.group(1).unwrap_or(&[]), c('\\'), c('/'))));
    }
    for i in 0..found.len() {
        let at = found[i].0;
        let mut names: Vec<PyStr> = Vec::new();
        for (at2, name) in &found[i..] {
            if at2 - at > span {
                break;
            }
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
        if names.len() >= min {
            return Some((at, names));
        }
    }
    None
}

/// core.env_copy_serialized_at: where the text serializes a copy of the
/// whole environment it made, else -1.
pub fn env_copy_serialized_at(p: &Pack, text: &[u32]) -> isize {
    if (!has(text, "os.environ") && !has(text, "process.env")) || p.re("_ENV_COPY_ANCHOR_RE").search(text).is_none() {
        return -1;
    }
    let max = p.usize("_ENV_COPY_MAX");
    let head_src = p.text("_ENV_COPY_USE_HEAD");
    let tail_src = p.text("_ENV_COPY_USE_TAIL");
    for (k, m) in p.re("_ENV_COPY_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let name = m.group(1).unwrap_or(&[]);
        let rx = rxutil::dynamic(cat(&[&head_src, &crate::pyre::escape(name), &tail_src]), 0);
        if let Some(used) = rx.search_at(text, m.end() as isize, text.len() as isize) {
            return used.start() as isize;
        }
    }
    -1
}

/// core.dns_beacon_at: the offset of a DNS lookup of a name built from
/// values, else -1.
pub fn dns_beacon_at(p: &Pack, text: &[u32]) -> isize {
    let max = p.usize("_DNS_LOOKUP_MAX");
    let built = p.re("_DNS_BUILT_NAME_RE");
    for (k, m) in p.re("_DNS_LOOKUP_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if built.search(m.first_group().unwrap_or(&[])).is_some() {
            return m.start() as isize;
        }
    }
    -1
}

/// core.miner_at: the offset of the Monero wallet address a miner is run
/// with, else -1.
pub fn miner_at(p: &Pack, text: &[u32]) -> isize {
    if !any_in(text, p.needles("_MINER_ARG_NEEDLES")) || p.re("_MINER_ARG_RE").search(text).is_none() {
        return -1;
    }
    if let Some(m) = p.re("_MONERO_ADDR_RE").search(text) {
        if p.re("_EXEC_CALL_RE").search(text).is_some() {
            return m.start() as isize;
        }
    }
    -1
}

/// core._exfil_signs: (offset, reason) of the exfiltration shapes and a
/// miner. `host`: where _HOST_INFO_RE matches.
pub fn exfil_signs(p: &Pack, text: &[u32], host: Option<usize>) -> Vec<(usize, PyStr)> {
    let mut signs: Vec<(usize, PyStr)> = Vec::new();
    let at = miner_at(p, text);
    if at >= 0 {
        signs.push((at as usize, u("runs a cryptocurrency miner (a Monero wallet address)")));
    }
    if let Some(chat) = chat_secret_at(p, text) {
        signs.push(chat);
    }
    let mut net: Option<bool> = None;
    let mut network = || -> bool {
        if net.is_none() {
            net = Some(p.re("_NETWORK_RE").search(text).is_some());
        }
        net.unwrap_or(false)
    };
    if let Some(ip) = p.re("_PUBLIC_IP_URL_RE").search(text) {
        if let Some(cred) = p.re("_CRED_FILE_RE").search(text) {
            if network() {
                let g = ip.group0();
                let rest = match pystr::find_str(g, "//", 0) {
                    Some(i) => pystr::from(g, i + 2),
                    None => &[][..],
                };
                signs.push((cred.start(), cat(&[&u("reads credential files and sends data to an IP address ("), rest, &u(")")])));
            }
        }
    }
    if let Some((at, names)) = credential_sweep_at(p, text) {
        if network() {
            let shown: Vec<PyStr> = names.iter().take(4).map(|n| cat(&[&u("."), n])).collect();
            let parts: Vec<&[u32]> = shown.iter().map(|x| x.as_slice()).collect();
            signs.push((
                at,
                cat(&[
                    &u("collects files from several credential folders and sends data over the network ("),
                    &pystr::join(&u(", "), &parts),
                    &u(")"),
                ]),
            ));
        }
    }
    if let Some(h) = host {
        if p.re("_B64_URL_LITERAL_RE").search(text).is_some() && network() {
            signs.push((h, u("sends the machine's user or host name to an address it hides in base64")));
        }
        let at = dns_beacon_at(p, text);
        if at >= 0 {
            signs.push((at as usize, u("sends the machine's user or host name in a DNS lookup of a name it builds")));
        }
    } else if any_in(text, p.needles("_PUBLIC_IP_LOOKUP_NEEDLES")) {
        if let Some(lookup) = p.re("_PUBLIC_IP_LOOKUP_RE").search(text) {
            if let Some(capture) = capture_service(p, text) {
                signs.push((
                    lookup.start(),
                    cat(&[
                        &u("sends the machine's public IP address to a data-capture service ("),
                        head(capture.group0(), 40),
                        &u(")"),
                    ]),
                ));
            }
        }
    }
    signs
}

/// core.raw_ip_connect: the first hard-coded IP address a raw socket is
/// opened to (install time only), else None.
pub fn raw_ip_connect(p: &Pack, text: &[u32]) -> Option<PyStr> {
    if !has(text, "connect") && !has(text, "Socket") {
        return None;
    }
    let max = p.usize("_IP_LITERAL_MAX");
    let span = p.usize("_RAW_CONNECT_SPAN");
    let resolvers = p.strs("_PUBLIC_RESOLVERS");
    let connect = p.re("_RAW_CONNECT_RE");
    for (k, m) in p.re("_IP_LITERAL_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let ip = m.group(1).unwrap_or(&[]);
        if resolvers.iter().any(|r| r.as_slice() == ip) {
            continue;
        }
        if connect.search_at(text, m.end() as isize, (m.end() + span) as isize).is_some() {
            return Some(ip.to_vec());
        }
    }
    None
}

// ---------------- code read back from the file itself ----------------

/// core.reads_own_source
pub fn reads_own_source(p: &Pack, text: &[u32]) -> bool {
    p.re("_SELF_READ_RE").search(text).is_some()
}

/// len(core._call_args(text))
fn call_args_len(text: &[u32]) -> usize {
    let n = text.len();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < n {
        let ch = text[i];
        if matches!(ch, 0x22 | 0x27 | 0x60) {
            match pystr::find_char(text, ch, i + 1) {
                None => return n,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        if matches!(ch, 0x28 | 0x5B | 0x7B) {
            depth += 1;
        } else if matches!(ch, 0x29 | 0x5D | 0x7D) {
            if depth == 0 {
                return i;
            }
            depth -= 1;
        }
        i += 1;
    }
    n
}

/// core._literal_spans
fn literal_spans(p: &Pack, text: &[u32]) -> Vec<(usize, usize)> {
    let max = p.usize("_LITERAL_SPANS_MAX");
    let n = text.len();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < n && out.len() < max {
        let ch = text[i];
        if !matches!(ch, 0x22 | 0x27 | 0x60) {
            i += 1;
            continue;
        }
        let triple = [ch, ch, ch];
        if ch != c('`') && text.len() >= i + 3 && text[i..i + 3] == triple {
            let end = match pystr::find(text, &triple, i + 3) {
                None => n,
                Some(j) => j + 3,
            };
            out.push((i, end));
            i = end;
            continue;
        }
        let mut j = i + 1;
        while j < n && text[j] != ch && (ch == c('`') || text[j] != c('\n')) {
            j += if text[j] == c('\\') { 2 } else { 1 };
        }
        let end = (j + 1).min(n);
        out.push((i, end));
        i = end;
    }
    out
}

/// core.runs_own_source_at
pub fn runs_own_source_at(p: &Pack, text: &[u32]) -> isize {
    let self_read = p.re("_SELF_READ_RE");
    let sibling = p.re("_SIBLING_DATA_RE");
    let sibling_path = p.re("_SIBLING_PATH_RE");
    if self_read.search(text).is_none() && sibling.search(text).is_none() && sibling_path.search(text).is_none() {
        return -1;
    }
    let spans = literal_spans(p, text);
    let starts: Vec<usize> = spans.iter().map(|&(s, _)| s).collect();
    let literal_at = |pos: usize| -> Option<(usize, usize)> {
        let k = starts.partition_point(|&s| s <= pos);
        if k > 0 && pos < spans[k - 1].1 {
            Some(spans[k - 1])
        } else {
            None
        }
    };
    let in_literal = |pos: usize| -> bool { literal_at(pos).is_some() };
    let reads = |lo: usize, hi: usize| -> bool {
        let part = pystr::sub(text, lo, hi);
        [self_read, sibling].iter().any(|rx| rx.finditer(part).any(|m| !in_literal(lo + m.start())))
    };
    let ident = p.re("_IDENT_TOKEN_RE");
    let uses = |lo: usize, hi: usize, names: &HashSet<PyStr>| -> bool {
        if names.is_empty() {
            return false;
        }
        let part = pystr::sub(text, lo, hi);
        ident.finditer(part).any(|m| names.contains(m.group0()) && !in_literal(lo + m.start()))
    };
    let max_assigns = p.usize("_SELF_READ_MAX_ASSIGNS");
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new();
    for (k, m) in p.re("_SELF_READ_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if !in_literal(m.start_of(1) as usize) {
            assigns.push((m.group(1).unwrap_or(&[]).to_vec(), m.start_of(2) as usize, m.end_of(2) as usize));
        }
    }
    // names of data files' paths (a template's `${__dirname}` counts)
    let mut paths: HashSet<PyStr> = HashSet::new();
    for (name, lo, hi) in &assigns {
        for m in sibling_path.finditer(pystr::sub(text, *lo, *hi)) {
            match literal_at(lo + m.start()) {
                Some((s, _)) if text[s] != c('`') => continue,
                _ => {
                    paths.insert(name.clone());
                    break;
                }
            }
        }
    }
    let path_read = p.re("_PATH_READ_RE");
    let path_reads = |lo: usize, hi: usize| -> bool {
        if paths.is_empty() {
            return false;
        }
        let part = pystr::sub(text, lo, hi);
        path_read.finditer(part).any(|m| {
            let name = m.group(1).filter(|g| !g.is_empty()).or_else(|| m.group(2)).unwrap_or(&[]);
            paths.contains(name) && !in_literal(lo + m.start())
        })
    };
    if !reads(0, text.len()) && !path_reads(0, text.len()) {
        return -1;
    }
    let mut names: HashSet<PyStr> = HashSet::new(); // values of a read written out: any runner
    let mut code_names: HashSet<PyStr> = HashSet::new(); // values of a path read by name: code runners only
    let max_calls = p.usize("_SELF_READ_MAX_CALLS");
    let span = p.usize("_SELF_READ_ARG_SPAN");
    let then_span = p.usize("_SELF_READ_THEN_SPAN");
    let callback = p.re("_READ_CALLBACK_RE");
    let then_re = p.re("_READ_THEN_RE");
    for (k, h) in p.re("_READ_HEAD_RE").finditer(text).enumerate() {
        if k >= max_calls {
            break;
        }
        if in_literal(h.start()) {
            continue;
        }
        let args = pystr::sub(text, h.end(), h.end() + span);
        let args = &args[..call_args_len(args)];
        let close = h.end() + args.len(); // the closing bracket, when there is one
        let into_names = if reads(h.start(), close + 1) {
            true
        } else if path_reads(h.start(), close + 1) {
            false
        } else {
            continue;
        };
        let mut bound: Vec<PyStr> = Vec::new();
        if let Some(cb) = callback.search(args) {
            if !in_literal(h.end() + cb.start()) {
                bound.push(cb.group(1).unwrap_or(&[]).to_vec());
            }
        }
        if close < text.len() && text[close] == c(')') {
            if let Some(then) = then_re.match_(pystr::sub(text, close + 1, close + 1 + then_span)) {
                let g = match then.group(1) {
                    Some(g) if !g.is_empty() => g,
                    _ => then.group(2).unwrap_or(&[]),
                };
                bound.push(g.to_vec());
            }
        }
        for b in bound {
            if into_names {
                names.insert(b);
            } else {
                code_names.insert(b);
            }
        }
    }
    for _ in 0..p.usize("_SELF_READ_PASSES") {
        let mut grown = false;
        for (name, lo, hi) in &assigns {
            if names.contains(name) {
                continue;
            }
            if reads(*lo, *hi) || uses(*lo, *hi, &names) {
                names.insert(name.clone());
                grown = true;
            } else if !code_names.contains(name) && (path_reads(*lo, *hi) || uses(*lo, *hi, &code_names)) {
                code_names.insert(name.clone());
                grown = true;
            }
        }
        if !grown {
            break;
        }
    }
    let shell_runners = p.strs("_SELF_SHELL_RUNNERS");
    for (k, m) in p.re("_SELF_RUN_RE").finditer(text).enumerate() {
        if k >= max_calls {
            break;
        }
        if in_literal(m.start()) {
            continue;
        }
        let hi = m.end() + call_args_len(pystr::sub(text, m.end(), m.end() + span));
        if reads(m.end(), hi) || uses(m.end(), hi, &names) {
            return m.start() as isize;
        }
        let shell = shell_runners.iter().any(|r| m.group0().starts_with(r));
        if !shell && (path_reads(m.end(), hi) || uses(m.end(), hi, &code_names)) {
            return m.start() as isize;
        }
    }
    -1
}

// ---------------- persistence targets ----------------

fn persist_agent_file(p: &Pack, text: &[u32]) -> Option<PyStr> {
    let mut found: Option<(usize, PyStr)> =
        p.re("_PERSIST_AGENT_RE").search(text).map(|m| (m.start(), pystr::replace_char(m.group0(), c('\\'), c('/'))));
    let pairs = p.map_strs("_PERSIST_AGENT_PAIRS");
    let max = p.usize("_PERSIST_MAX_LINES");
    for (k, s) in p.re("_PERSIST_AGENT_SPLIT_RE").finditer(text).enumerate() {
        if k >= max || found.as_ref().map(|f| s.start() > f.0).unwrap_or(false) {
            break;
        }
        let g1 = s.group(1).unwrap_or(&[]);
        let g2 = s.group(2).unwrap_or(&[]);
        let allowed = pairs.iter().find(|(k, _)| k.as_slice() == g1).map(|(_, v)| v.as_slice()).unwrap_or(&[]);
        if allowed.iter().any(|a| a.as_slice() == g2) {
            found = Some((s.start(), cat(&[&u("."), g1, &u("/"), g2, &u(".json")])));
            break;
        }
    }
    found.map(|f| f.1)
}

fn shell_writes(p: &Pack, text: &[u32], target: &crate::pyre::Regex) -> bool {
    let shell_write = p.re("_PERSIST_SHELL_WRITE_RE");
    let max = p.usize("_PERSIST_MAX_LINES");
    let mut m = target.search(text);
    let mut lines = 0usize;
    while let Some(mm) = m {
        if lines >= max {
            break;
        }
        let start = pystr::rfind_char(text, c('\n'), 0, mm.start()).map(|i| i + 1).unwrap_or(0);
        let end = pystr::find_char(text, c('\n'), mm.end()).unwrap_or(text.len());
        if shell_write.search_at(text, start as isize, end as isize).is_some() {
            return true;
        }
        lines += 1;
        m = target.search_at(text, end as isize, text.len() as isize);
    }
    false
}

fn after_on_line(text: &[u32], first: &crate::pyre::Regex, then: &crate::pyre::Regex) -> bool {
    let mut m = first.search(text);
    while let Some(mm) = m {
        let end = pystr::find_char(text, c('\n'), mm.end()).unwrap_or(text.len());
        if then.search_at(text, mm.end() as isize, end as isize).is_some() {
            return true;
        }
        m = first.search_at(text, end as isize, text.len() as isize);
    }
    false
}

fn writes_named(p: &Pack, text: &[u32], target: &crate::pyre::Regex) -> bool {
    target.search(text).is_some() && (p.re("_PERSIST_WRITE_RE").search(text).is_some() || shell_writes(p, text, target))
}

/// core.dumps_workflow_secrets
pub fn dumps_workflow_secrets(p: &Pack, text: &[u32]) -> bool {
    p.re("_SECRETS_DUMP_RE").search(text).is_some() && p.re("_PERSIST_WORKFLOW_RE").search(text).is_some()
}

/// core.persistence_reasons
pub fn persistence_reasons(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut reasons = Vec::new();
    if let Some(agent) = persist_agent_file(p, text) {
        if p.re("_PERSIST_WRITE_RE").search(text).is_some()
            || shell_writes(p, text, p.re("_PERSIST_AGENT_RE"))
            || shell_writes(p, text, p.re("_PERSIST_AGENT_SPLIT_RE"))
        {
            reasons.push(cat(&[&u("writes an AI agent's or editor's auto-run settings ("), &agent, &u(")")]));
        }
    }
    let workflow = p.re("_PERSIST_WORKFLOW_RE");
    if dumps_workflow_secrets(p, text) {
        reasons.push(u("carries a GitHub Actions workflow that dumps every repository secret"));
    } else if workflow.search(text).is_some() && (writes_named(p, text, workflow) || has(text, "/contents/")) {
        reasons.push(u("writes a GitHub Actions workflow"));
    }
    let install = p.re("_PERSIST_EXT_INSTALL_RE").search(text).is_some();
    if (install
        && (p.re("_EXEC_CALL_RE").search(text).is_some()
            || after_on_line(text, p.re("_PERSIST_EXT_CLI_RE"), p.re("_PERSIST_EXT_INSTALL_RE"))))
        || writes_named(p, text, p.re("_PERSIST_EXT_DIR_RE"))
    {
        reasons.push(u("installs an editor extension"));
    }
    if p.re("_PERSIST_RUNNER_RE").search(text).is_some()
        || after_on_line(text, p.re("_PERSIST_RUNNER_CONFIG_RE"), p.re("_PERSIST_RUNNER_ARG_RE"))
    {
        reasons.push(u("registers the machine as a GitHub Actions self-hosted runner"));
    }
    if p.re("_BUN_RELEASES_RE").search(text).is_some() && p.re("_EXEC_CALL_RE").search(text).is_some() {
        reasons.push(u("downloads the Bun runtime from GitHub and runs code with it"));
    }
    if has(text, "--load-extension") && p.re("_PERSIST_SHORTCUT_RE").search(text).is_some() {
        reasons.push(u("rewrites browser shortcuts to load an extension"));
    }
    reasons.extend(service_reasons(p, text));
    reasons
}

// ---------------- programs set to start at login or boot (0.1.8) ----------------

/// core._writes_on_line: a write call or a shell write on a line (of at
/// most _SVC_LINE_MAX characters) on which `target` matches.
fn writes_on_line(p: &Pack, text: &[u32], target: &crate::pyre::Regex) -> bool {
    let write = p.re("_PERSIST_WRITE_RE");
    let shell_write = p.re("_PERSIST_SHELL_WRITE_RE");
    let max = p.usize("_PERSIST_MAX_LINES");
    let line_max = p.usize("_SVC_LINE_MAX");
    let mut m = target.search(text);
    let mut lines = 0usize;
    while let Some(mm) = m {
        if lines >= max {
            break;
        }
        let start = pystr::rfind_char(text, c('\n'), 0, mm.start()).map(|i| i + 1).unwrap_or(0);
        let end = pystr::find_char(text, c('\n'), mm.end()).unwrap_or(text.len());
        if end - start <= line_max
            && (write.search_at(text, start as isize, end as isize).is_some()
                || shell_write.search_at(text, start as isize, end as isize).is_some())
        {
            return true;
        }
        lines += 1;
        m = target.search_at(text, end as isize, text.len() as isize);
    }
    false
}

/// core._run_key_written: a registry write within _SVC_RUNKEY_SPAN code
/// points of a Run key.
fn run_key_written(p: &Pack, text: &[u32]) -> bool {
    let max = p.usize("_PERSIST_MAX_LINES");
    let span = p.usize("_SVC_RUNKEY_SPAN");
    let write = p.re("_SVC_REG_WRITE_RE");
    for (k, m) in p.re("_SVC_RUNKEY_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if write.search(pystr::sub(text, m.start().saturating_sub(span), m.end() + span)).is_some() {
            return true;
        }
    }
    false
}

/// core.service_reasons: how the text sets a program to start at login or
/// boot, in a fixed order.
pub fn service_reasons(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut reasons = Vec::new();
    let mut runs: Option<bool> = None;
    let mut run_context = || -> bool {
        if runs.is_none() {
            runs = Some(p.re("_EXEC_CALL_RE").search(text).is_some() || p.re("_SVC_CMD_START_RE").search(text).is_some());
        }
        runs.unwrap_or(false)
    };
    let writes = p.re("_PERSIST_WRITE_RE").search(text).is_some();
    let systemd = p.re("_SVC_SYSTEMD_DIR_RE");
    if (systemd.search(text).is_some()
        && ((writes && p.re("_SVC_UNIT_RE").search(text).is_some()) || writes_on_line(p, text, systemd)))
        || (p.re("_SVC_SYSTEMCTL_RE").search(text).is_some() && run_context())
    {
        reasons.push(u("installs a systemd service"));
    }
    let launchd = p.re("_SVC_LAUNCHD_DIR_RE");
    if (launchd.search(text).is_some()
        && ((writes && p.re("_SVC_PLIST_RE").search(text).is_some()) || writes_on_line(p, text, launchd)))
        || (p.re("_SVC_LAUNCHCTL_RE").search(text).is_some() && run_context())
    {
        reasons.push(u("installs a launchd agent or daemon"));
    }
    if (p.re("_SVC_CRONTAB_RE").search(text).is_some() && run_context())
        || (p.re("_SVC_PYCRON_RE").search(text).is_some() && p.re("_SVC_PYCRON_WRITE_RE").search(text).is_some())
        || writes_on_line(p, text, p.re("_SVC_CRON_DIR_RE"))
    {
        reasons.push(u("adds a cron job"));
    }
    if run_key_written(p, text) {
        reasons.push(u("adds a program to a Windows Run key"));
    }
    if (p.re("_SVC_SCHTASKS_RE").search(text).is_some() && run_context())
        || p.re("_SVC_TASK_API_RE").search(text).is_some()
        || (p.re("_SVC_TASK_COM_RE").search(text).is_some() && p.re("_SVC_TASK_REGISTER_RE").search(text).is_some())
    {
        reasons.push(u("creates a Windows scheduled task"));
    }
    let startup = p.re("_SVC_STARTUP_RE");
    if startup.search(text).is_some()
        && (writes || p.re("_PERSIST_SHORTCUT_RE").search(text).is_some() || shell_writes(p, text, startup))
    {
        reasons.push(u("puts a program in the Windows Startup folder"));
    }
    let autostart = p.re("_SVC_AUTOSTART_RE");
    if autostart.search(text).is_some() && (writes || shell_writes(p, text, autostart)) {
        reasons.push(u("adds a desktop autostart entry"));
    }
    reasons
}

// ---------------- code that publishes packages ----------------

/// core.self_publish_at
pub fn self_publish_at(p: &Pack, text: &[u32]) -> isize {
    if !has(text, "publish") || !has(text, "package.json") {
        return -1;
    }
    let publish = match p.re("_PUBLISH_CMD_RE").search(text) {
        None => return -1,
        Some(m) => m.start(),
    };
    let max = p.usize("_SELF_PUB_MAX");
    let span = p.usize("_SELF_PUB_SPAN");
    let mut names: HashSet<PyStr> = HashSet::new();
    for (k, m) in p.re("_NAME_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        names.insert(m.group(1).unwrap_or(&[]).to_vec());
    }
    if names.is_empty() {
        return -1;
    }
    let ident = p.re("_JS_IDENT_RE");
    for (k, w) in p.re("_MANIFEST_WRITE_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let args = pystr::sub(text, w.end(), w.end() + span);
        let before = pystr::sub(text, w.start().saturating_sub(span), w.start());
        if !has(args, "package.json") && !has(before, "package.json") {
            continue;
        }
        if ident.findall(args).iter().any(|n| names.contains(*n)) {
            return publish as isize;
        }
    }
    -1
}

// ---------------- an install script that runs a DLL ----------------

/// core.join_string_pieces
pub fn join_string_pieces(p: &Pack, text: &[u32]) -> PyStr {
    if text.contains(&c('+')) {
        p.re("_STRING_JOIN_RE").sub(text, &[], 0)
    } else {
        text.to_vec()
    }
}

/// core.runs_dll
pub fn runs_dll(p: &Pack, text: &[u32]) -> Option<PyStr> {
    if !has(text, "32") && !text.contains(&c('+')) {
        return None;
    }
    let joined = join_string_pieces(p, text);
    let system = p.strs("_SYSTEM_DLLS");
    for view in [text, joined.as_slice()] {
        if p.re("_DLL_LOADER_RE").search(view).is_none() {
            continue;
        }
        for m in p.re("_DLL_NAME_RE").finditer(view) {
            let g = m.group0();
            let after_slash = match g.iter().rposition(|&x| x == c('/')) {
                Some(k) => &g[k + 1..],
                None => g,
            };
            let base = match after_slash.iter().rposition(|&x| x == c('\\')) {
                Some(k) => &after_slash[k + 1..],
                None => after_slash,
            };
            let name = pystr::lower(base);
            if !name.is_empty() && !pystr::eq(&name, ".dll") && !system.iter().any(|s| *s == name) {
                return Some(name);
            }
        }
    }
    None
}

// ---------------- names in strings a file decodes as it runs ----------------

fn dv_decode(p: &Pack, kind_hex: bool, s: &[u32]) -> Option<PyStr> {
    let data: Vec<u8> = if kind_hex {
        if s.len() % 2 != 0 || p.re("_DV_HEX_RE").fullmatch(s).is_none() {
            return None;
        }
        s.chunks(2)
            .map(|w| {
                let v = |x: u32| -> u8 {
                    (match x {
                        0x30..=0x39 => x - 0x30,
                        0x61..=0x66 => x - 0x61 + 10,
                        _ => x - 0x41 + 10,
                    }) as u8
                };
                v(w[0]) << 4 | v(w[1])
            })
            .collect()
    } else {
        if s.len() % 4 != 0 || p.re("_DV_B64_RE").fullmatch(s).is_none() {
            return None;
        }
        b64decode_strict(s)?
    };
    if data.is_empty() || data.iter().any(|&b| !(0x20..=0x7E).contains(&b)) {
        return None;
    }
    Some(data.iter().map(|&b| b as u32).collect())
}

fn dv_quote(s: &[u32]) -> PyStr {
    let mut out = vec![c('\'')];
    for &ch in s {
        if ch == c('\\') {
            out.extend([c('\\'), c('\\')]);
        } else if ch == c('\'') {
            out.extend([c('\\'), c('\'')]);
        } else {
            out.push(ch);
        }
    }
    out.push(c('\''));
    out
}

/// core._dv_helpers: [(name, is_hex)] in the order found.
fn dv_helpers(p: &Pack, text: &[u32]) -> Vec<(PyStr, bool)> {
    let mut out: Vec<(PyStr, bool)> = Vec::new();
    let body_len = p.usize("_DV_BODY");
    let max = p.usize("_DV_MAX_HELPERS");
    for m in p.re("_DV_HELPER_RE").finditer(text) {
        let name = rxutil::or_groups(&m, &["a", "b", "c"]).unwrap_or(&[]).to_vec();
        if out.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let body = pystr::sub(text, m.end(), m.end() + body_len);
        let kind = if (has(body, "fromCharCode") && has(body, "parseInt") && has(body, "16"))
            || has(body, "'hex'")
            || has(body, "\"hex\"")
            || has(body, "fromhex(")
            || has(body, "unhexlify(")
        {
            true
        } else if has(body, "base64") || has(body, "atob(") || has(body, "b64decode(") {
            false
        } else {
            continue;
        };
        out.push((name, kind));
        if out.len() >= max {
            break;
        }
    }
    out
}

/// core._dv_bytes: the bytes a literal holds as hex (an even run of hex
/// digits) or as base64 (padded; or unpadded, but not 4k+1 long).
fn dv_bytes(p: &Pack, s: &[u32], hex: bool) -> Option<Vec<u8>> {
    if hex {
        if s.len() % 2 != 0 || p.re("_DV_HEX_RE").fullmatch(s).is_none() {
            return None;
        }
        return Some(
            s.chunks(2)
                .map(|w| {
                    let v = |x: u32| -> u8 {
                        (match x {
                            0x30..=0x39 => x - 0x30,
                            0x61..=0x66 => x - 0x61 + 10,
                            _ => x - 0x41 + 10,
                        }) as u8
                    };
                    v(w[0]) << 4 | v(w[1])
                })
                .collect(),
        );
    }
    if p.re("_DV_B64_RE").fullmatch(s).is_none() || s.len() % 4 == 1 || (s.contains(&c('=')) && s.len() % 4 != 0) {
        return None;
    }
    let mut padded = s.to_vec();
    while padded.len() % 4 != 0 {
        padded.push(c('='));
    }
    b64decode_strict(&padded)
}

/// core._dv_xor_printable: is every byte XORed with the key (repeated) printable ASCII?
fn dv_xor_printable(data: &[u8], key: &[u8]) -> bool {
    data.iter().enumerate().all(|(i, &b)| (0x20..=0x7E).contains(&(b ^ key[i % key.len()])))
}

/// core._dv_xor_decoders: [(name, hex, key)] the view calls as XOR decoders,
/// in the order of their first calls.
fn dv_xor_decoders(p: &Pack, view: &[u32]) -> Vec<(PyStr, bool, Vec<u8>)> {
    let min_calls = p.usize("_DV_XOR_MIN_CALLS");
    let max_calls = p.usize("_DV_XOR_MAX_CALLS");
    let min_bytes = p.usize("_DV_XOR_MIN_BYTES");
    let max_keys = p.usize("_DV_XOR_MAX_KEYS");
    let max_helpers = p.usize("_DV_MAX_HELPERS");
    let hex_re = p.re("_DV_HEX_RE");
    let mut order: Vec<PyStr> = Vec::new();
    let mut calls: std::collections::HashMap<PyStr, Vec<PyStr>> = std::collections::HashMap::new();
    for m in p.re("_DV_CALL_RE").finditer(view) {
        let name = m.name("name").unwrap_or(&[]).to_vec();
        let lits = calls.entry(name.clone()).or_insert_with(|| {
            order.push(name);
            Vec::new()
        });
        if lits.len() < max_calls {
            lits.push(dv_literal(&m).unwrap_or(&[]).to_vec());
        }
    }
    let mut out: Vec<(PyStr, bool, Vec<u8>)> = Vec::new();
    let mut keys: Option<Vec<Vec<u8>>> = None;
    for name in order {
        let lits = &calls[&name];
        if lits.len() < min_calls {
            continue;
        }
        let hex = lits.iter().all(|x| x.len() % 2 == 0 && hex_re.fullmatch(x).is_some());
        let data: Vec<Option<Vec<u8>>> = lits.iter().map(|x| dv_bytes(p, x, hex)).collect();
        let read = data.iter().filter(|d| d.is_some()).count();
        let bytes: usize = data.iter().map(|d| d.as_ref().map(|v| v.len()).unwrap_or(0)).sum();
        if read < min_calls || bytes < min_bytes {
            continue;
        }
        let keys = keys.get_or_insert_with(|| {
            let mut found: Vec<Vec<u8>> = Vec::new();
            let mut seen: HashSet<PyStr> = HashSet::new();
            for k in p.re("_DV_KEY_RE").finditer(view) {
                let key = rxutil::or_groups(&k, &["a", "b", "c"]).unwrap_or(&[]);
                if seen.contains(key) || !key.iter().all(|&ch| (0x20..=0x7E).contains(&ch)) {
                    continue;
                }
                seen.insert(key.to_vec());
                found.push(key.iter().map(|&ch| ch as u8).collect());
                if found.len() >= max_keys {
                    break;
                }
            }
            found
        });
        let allowed = lits.len() / 10; // calls that may stay unread
        for key in keys.iter() {
            let mut bad = 0usize;
            for d in &data {
                let ok = matches!(d, Some(d) if dv_xor_printable(d, key));
                if !ok {
                    bad += 1;
                    if bad > allowed {
                        break;
                    }
                }
            }
            if bad <= allowed {
                out.push((name.clone(), hex, key.clone()));
                break;
            }
        }
        if out.len() >= max_helpers {
            break;
        }
    }
    out
}

/// core._dv_literal: group a, b or c (c only where the pattern has it).
fn dv_literal<'s>(m: &crate::pyre::Match<'s>) -> Option<&'s [u32]> {
    rxutil::or_groups(m, &["a", "b", "c"])
}

fn sub_decoded(rx: &crate::pyre::Regex, view: &[u32], f: impl Fn(&crate::pyre::Match) -> Option<PyStr>) -> PyStr {
    rx.sub_fn(view, 0, |m| match f(m) {
        None => m.group0().to_vec(),
        Some(d) => dv_quote(&d),
    })
}

/// core.decoded_view
pub fn decoded_view(p: &Pack, text: &[u32]) -> PyStr {
    if text.len() > p.usize("_DV_MAX_CHARS") || !any_in(text, p.needles("_DV_NEEDLES")) {
        return text.to_vec();
    }
    let joined: PyStr =
        if text.contains(&c('+')) { p.re("_DV_JOIN_RE").sub(text, &[], 0) } else { text.to_vec() };
    let mut view = joined.clone();
    if has(&view, "Buffer") {
        view = sub_decoded(p.re("_DV_BUFFER_RE"), &view, |m| {
            let enc = m.name("enc").unwrap_or(&[]);
            dv_decode(p, pystr::eq(enc, "hex"), dv_literal(m).unwrap_or(&[]))
        });
    }
    if has(&view, "atob") {
        view = sub_decoded(p.re("_DV_ATOB_RE"), &view, |m| dv_decode(p, false, dv_literal(m).unwrap_or(&[])));
    }
    if has(&view, "fromhex") || has(&view, "unhexlify") || has(&view, "b64decode") {
        view = sub_decoded(p.re("_DV_PY_RE"), &view, |m| {
            let hex = m.name("fh").is_some() || m.name("uh").is_some();
            dv_decode(p, hex, dv_literal(m).unwrap_or(&[]))
        });
    }
    let helpers = dv_helpers(p, &view);
    if !helpers.is_empty() {
        let mut names: Vec<&PyStr> = helpers.iter().map(|(n, _)| n).collect();
        names.sort();
        let alternation: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = alternation.iter().map(|x| x.as_slice()).collect();
        let src = cat(&[&p.text("_DV_NAME_HEAD"), &u("(?P<name>"), &pystr::join(&[c('|')], &parts), &p.text("_DV_HELPER_CALL_TAIL")]);
        let call = rxutil::dynamic(src, 0);
        view = sub_decoded(&call, &view, |m| {
            let name = m.name("name").unwrap_or(&[]);
            let hex = helpers.iter().find(|(n, _)| n.as_slice() == name).map(|(_, h)| *h).unwrap_or(false);
            dv_decode(p, hex, dv_literal(m).unwrap_or(&[]))
        });
    }
    if has(&view, "^") {
        let xors = dv_xor_decoders(p, &view);
        if !xors.is_empty() {
            let mut names: Vec<&PyStr> = xors.iter().map(|(n, _, _)| n).collect();
            names.sort();
            let alternation: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
            let parts: Vec<&[u32]> = alternation.iter().map(|x| x.as_slice()).collect();
            let src = cat(&[&p.text("_DV_NAME_HEAD"), &u("(?P<name>"), &pystr::join(&[c('|')], &parts), &p.text("_DV_HELPER_CALL_TAIL")]);
            let call = rxutil::dynamic(src, 0);
            view = call.sub_fn(&view, 0, |m| {
                let name = m.name("name").unwrap_or(&[]);
                let Some((_, hex, key)) = xors.iter().find(|(n, _, _)| n.as_slice() == name) else {
                    return m.group0().to_vec();
                };
                match dv_bytes(p, dv_literal(m).unwrap_or(&[]), *hex) {
                    Some(d) if dv_xor_printable(&d, key) => {
                        let text: PyStr = d.iter().enumerate().map(|(i, &b)| (b ^ key[i % key.len()]) as u32).collect();
                        dv_quote(&text)
                    }
                    _ => m.group0().to_vec(),
                }
            });
        }
    }
    if view == joined {
        return text.to_vec();
    }
    let max_arrays = p.usize("_DV_MAX_ARRAYS");
    let found: Vec<(PyStr, Vec<PyStr>)> = p
        .re("_DV_ARRAY_RE")
        .finditer(&view)
        .map(|m| {
            let items = p.re("_DV_STR_ITEM_RE").findall(m.name("items").unwrap_or(&[])).into_iter().map(|s| s.to_vec()).collect();
            (m.name("name").unwrap_or(&[]).to_vec(), items)
        })
        .collect();
    let mut arrays = 0usize;
    let head_src = p.text("_DV_NAME_HEAD");
    for (name, items) in found {
        if arrays >= max_arrays {
            break;
        }
        let esc = crate::pyre::escape(&name);
        let mutated = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_MUTATED_TAIL")]), 0);
        let assigned = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_ASSIGNED_TAIL")]), 0);
        if mutated.search(&view).is_some() || assigned.finditer(&view).count() != 1 {
            continue;
        }
        arrays += 1;
        let index = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_INDEX_TAIL")]), 0);
        view = index.sub_fn(&view, 0, |m| {
            let k = pystr::int_of_digits(m.group(1).unwrap_or(&[]));
            match k {
                Some(k) if (k as usize) < items.len() => items[k as usize].clone(),
                _ => m.group0().to_vec(),
            }
        });
    }
    if view.contains(&c('[')) {
        p.re("_DV_MEMBER_RE").sub_fn(&view, 0, |m| {
            let name = rxutil::or_groups(m, &["a", "b"]).unwrap_or(&[]);
            cat(&[&u("."), name])
        })
    } else {
        view
    }
}

// ---------------- scripts a script starts with node or python ----------------

/// core._spawn_args: the stripped arguments, or [] when it does not close.
fn spawn_args(text: &[u32], i: usize, limit: usize) -> Vec<PyStr> {
    let mut args: Vec<PyStr> = Vec::new();
    let mut depth = 0usize;
    let mut start = i;
    let mut j = i;
    let end = text.len().min(i + limit);
    let mut quote: Option<u32> = None;
    while j < end {
        let ch = text[j];
        if let Some(q) = quote {
            if ch == c('\\') {
                j += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else if matches!(ch, 0x27 | 0x22 | 0x60) {
            quote = Some(ch);
        } else if matches!(ch, 0x28 | 0x5B | 0x7B) {
            depth += 1;
        } else if matches!(ch, 0x29 | 0x5D | 0x7D) {
            if depth == 0 {
                args.push(pystr::sub(text, start, j).to_vec());
                return args.iter().map(|a| pystr::strip(a).to_vec()).collect();
            }
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            args.push(pystr::sub(text, start, j).to_vec());
            start = j + 1;
        }
        j += 1;
    }
    Vec::new()
}

fn lit_value<'s>(m: &crate::pyre::Match<'s>) -> Option<&'s [u32]> {
    rxutil::or_groups(m, &["a", "b", "c"])
}

/// core._spawn_path: (base is 'dir', path) or None.
fn spawn_path(p: &Pack, expr: &[u32], text: &[u32], names: usize) -> Option<(bool, PyStr)> {
    let expr = pystr::strip(expr);
    let lit_re = p.re("_SPAWN_LIT_RE");
    if let Some(m) = lit_re.fullmatch(expr) {
        let lit = lit_value(&m).unwrap_or(&[]);
        return if pystr::starts_with(lit, "-") { None } else { Some((false, lit.to_vec())) };
    }
    if let Some(m) = p.re("_SPAWN_CONCAT_RE").fullmatch(expr) {
        return Some((true, rxutil::or_groups(&m, &["a", "b", "c", "t"]).unwrap_or(&[]).to_vec()));
    }
    if let Some(m) = p.re("_SPAWN_JOIN_RE").match_(expr) {
        let parts = spawn_args(expr, m.end(), 400);
        if parts.is_empty() || !pystr::ends_with(pystr::rstrip(expr), ")") {
            return None;
        }
        let first = &parts[0];
        let rest = &parts[1..];
        let (base, mut segs): (bool, Vec<PyStr>) = if p.re("_SPAWN_DIR_RE").fullmatch(first).is_some() {
            (true, Vec::new())
        } else {
            let head = spawn_path(p, first, text, names)?;
            (head.0, vec![head.1])
        };
        for part in rest {
            let lit = lit_re.fullmatch(part)?;
            segs.push(lit_value(&lit).unwrap_or(&[]).to_vec());
        }
        if segs.is_empty() {
            return None;
        }
        let parts: Vec<&[u32]> = segs.iter().map(|s| s.as_slice()).collect();
        return Some((base, pystr::join(&[c('/')], &parts)));
    }
    if p.re("_SPAWN_NAME_RE").fullmatch(expr).is_some() && names > 0 {
        let src = cat(&[&p.text("_SPAWN_ASSIGN_HEAD"), &crate::pyre::escape(expr), &p.text("_SPAWN_ASSIGN_TAIL")]);
        let rx = rxutil::dynamic(src, 0);
        if let Some(am) = rx.search(text) {
            let value = am.name("e").unwrap_or(&[]).to_vec();
            let mut closed = value.clone();
            closed.push(c(')'));
            let parts = spawn_args(&closed, 0, 400);
            let first = if parts.is_empty() { value } else { parts[0].clone() };
            return spawn_path(p, &first, text, names - 1);
        }
    }
    None
}

/// core.spawned_scripts: [(base, path)], base "dir" or "cwd".
pub fn spawned_scripts(p: &Pack, text: &[u32]) -> Vec<(&'static str, PyStr)> {
    if !["spawn", "execFile", "fork", "Popen", "run", "call", "check_"].iter().any(|n| has(text, n)) {
        return Vec::new();
    }
    let lit_re = p.re("_SPAWN_LIT_RE");
    let no_script = p.strs("_SPAWN_NO_SCRIPT_FLAGS");
    let value_flags = p.strs("_SPAWN_VALUE_FLAGS");
    let depth = p.usize("_SPAWN_NAME_DEPTH");
    let max = p.usize("_SPAWN_MAX_TARGETS");
    let mut out: Vec<(&'static str, PyStr)> = Vec::new();
    for m in p.re("_SPAWN_CALL_RE").finditer(text) {
        let args = spawn_args(text, m.end(), 400);
        let mut skip = false;
        for arg in args.iter().take(6) {
            if skip {
                skip = false;
                continue;
            }
            let value = lit_re.fullmatch(arg).and_then(|l| lit_value(&l).map(|v| v.to_vec()));
            if let Some(value) = &value {
                if pystr::starts_with(value, "-") {
                    let flag = match value.iter().position(|&x| x == c('=')) {
                        Some(k) => &value[..k],
                        None => &value[..],
                    };
                    if no_script.iter().any(|f| f.as_slice() == flag) {
                        break;
                    }
                    skip = value_flags.iter().any(|f| f.as_slice() == flag) && !value.contains(&c('='));
                    continue;
                }
            }
            if let Some((is_dir, path)) = spawn_path(p, arg, text, depth) {
                let path = pystr::normpath(&pystr::replace_char(&path, c('\\'), c('/')));
                let base = if is_dir { "dir" } else { "cwd" };
                if !(pystr::eq(&path, ".") || path.is_empty())
                    && !pystr::starts_with(&path, "/")
                    && !out.iter().any(|(b, q)| *b == base && *q == path)
                {
                    out.push((base, path));
                }
            }
            break;
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

// ---------------- code hidden off-screen ----------------

fn code_prefix(prefix: &[u32], lang_js: bool) -> bool {
    let n = prefix.len();
    let mut quote: Option<u32> = None;
    let mut i = 0usize;
    while i < n {
        let ch = prefix[i];
        if let Some(q) = quote {
            if ch == c('\\') {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else if ch == c('"') || ch == c('\'') || (ch == c('`') && lang_js) {
            quote = Some(ch);
        } else if !lang_js && ch == c('#') {
            return false;
        } else if lang_js && ch == c('/') && pystr::starts_with_at(prefix, i, "//") {
            return false;
        } else if lang_js && ch == c('/') && pystr::starts_with_at(prefix, i, "/*") {
            match pystr::find_str(prefix, "*/", i + 2) {
                None => return false,
                Some(e) => {
                    i = e + 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    quote.is_none()
}

/// core.offscreen_code: (column, blanks, hidden text, runs code) or None.
pub fn offscreen_code(p: &Pack, line: &[u32], lang: &str) -> Option<(usize, usize, PyStr, bool)> {
    let min = p.usize("_OFFSCREEN_MIN");
    if line.len() <= min {
        return None;
    }
    let spaces: PyStr = vec![c(' '); 16];
    let tabs: PyStr = vec![c('\t'); 16];
    if pystr::find(line, &spaces, 0).is_none() && pystr::find(line, &tabs, 0).is_none() {
        return None;
    }
    let m = p.re("_OFFSCREEN_RE").search(line)?;
    if p.re("_OFFSCREEN_CODE_RE").match_at(line, m.end() as isize, line.len() as isize).is_none()
        || !code_prefix(&line[..m.start()], lang == "js")
    {
        return None;
    }
    let hidden = pystr::sub(line, m.end(), m.end() + p.usize("_OFFSCREEN_READ")).to_vec();
    let runs = p.re("_OFFSCREEN_EXEC_RE").search(&hidden).is_some();
    Some((m.end(), m.end() - m.start(), hidden, runs))
}

// ---------------- the install-script test ----------------

/// core.install_script_risk
pub fn install_script_risk(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut reasons = install_script_risk_of(p, text);
    let view = decoded_view(p, text);
    if view != text {
        let note = p.text("_DV_NOTE");
        for r in install_script_risk_of(p, &view) {
            if !reasons.contains(&r) {
                reasons.push(cat(&[&r, &note]));
            }
        }
    }
    reasons
}

fn py_run_or<'a>(p: &Pack, text: &[u32], interp: &'a Option<PyStr>) -> Option<PyStr> {
    if p.re("_PY_RUN_RE").search(text).is_some() {
        Some(u("Python"))
    } else {
        interp.clone()
    }
}

fn install_script_risk_of(p: &Pack, text: &[u32]) -> Vec<PyStr> {
    let mut reasons: Vec<PyStr> = Vec::new();
    let network = p.re("_NETWORK_RE").search(text).is_some();
    if network && p.re("_SECRET_SOURCE_RE").search(text).is_some() {
        reasons.push(u("reads environment variables or credential files and sends data over the network"));
    }
    let dest = p.re("_EXFIL_DEST_RE").search(text);
    if let Some(dest) = &dest {
        reasons.push(cat(&[&u("contacts an address typical of data exfiltration ("), head(dest.group0(), 40), &u(")")]));
    }
    if pipes_download_to_shell(p, text) {
        reasons.push(u("pipes a download into a shell"));
    }
    let substituted = (has(text, "curl") || has(text, "wget"))
        && pystr::split_char(text, c('\n')).iter().any(|row| runs_substituted_download(p, row));
    let received = received::received_code_kind(p, text, &[], &[]);
    if substituted {
        reasons.push(cat_reason(p, "run"));
    } else if let Some((_, kind)) = &received {
        reasons.push(cat_reason(p, kind));
    }
    reasons.extend(powershell_risk(p, text));
    let received_runs = matches!(&received, Some((_, k)) if *k == "run");
    if !received_runs && !substituted && stager_at(p, text) >= 0 {
        reasons.push(u("carries a script that downloads and runs code"));
    }
    if reverse_shell_at(p, text) >= 0 {
        reasons.push(u("opens a reverse shell"));
    }
    let host = p.re("_HOST_INFO_RE").search(text).map(|m| m.start());
    if host.is_some() && (network || p.re("_EXFIL_SERVICE_RE").search(text).is_some()) {
        reasons.push(u("sends the machine's user or host name over the network"));
    }
    for (_at, reason) in exfil_signs(p, text, host) {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    if dest.is_none() {
        if let Some(ip) = raw_ip_connect(p, text) {
            reasons.push(cat(&[&u("contacts an address typical of data exfiltration ("), &ip, &u(")")]));
        }
    }
    if runs_own_source_at(p, text) >= 0 {
        reasons.push(u("runs code it reads back from its own file or a data file shipped with it"));
    }
    reasons.extend(persistence_reasons(p, text));
    if p.re("_PUBLISH_CMD_RE").search(text).is_some() {
        reasons.push(u("publishes a package to a registry (npm publish)"));
    }
    if p.re("_NPM_TOKEN_READ_RE").search(text).is_some() {
        reasons.push(u("collects npm access tokens"));
    }
    if let Some(dll) = runs_dll(p, text) {
        reasons.push(cat(&[&u("runs a DLL with rundll32 or regsvr32 ("), head(&dll, 40), &u(")")]));
    }
    if let Some((_, interp)) = received::downloads_and_runs(p, text) {
        if let Some(interp) = py_run_or(p, text, &interp) {
            if !interp.is_empty() {
                reasons.push(cat(&[&u("downloads a script and runs it with "), &interp]));
            }
        }
    }
    if let Some((_, interp)) = received::decodes_and_runs(p, text) {
        match py_run_or(p, text, &interp).filter(|i| !i.is_empty()) {
            Some(interp) => reasons.push(cat(&[&u("writes code it decodes to a file and runs it with "), &interp])),
            None => reasons.push(u("writes a file it decodes and runs it")),
        }
    }
    reasons
}

// ---------------- the import-time test ----------------

/// core.import_time_severity
pub fn import_time_severity(p: &Pack, reasons: &[PyStr]) -> &'static str {
    let strong = p.strs("_STRONG_IMPORT_REASONS");
    if reasons.iter().any(|r| strong.iter().any(|s| r.starts_with(s))) {
        "CRITICAL"
    } else {
        "MAJOR"
    }
}

/// core.import_time_risk: (reasons, 1-based line of the first sign).
pub fn import_time_risk(p: &Pack, text: &[u32], lang: Option<&str>) -> (Vec<PyStr>, Option<usize>) {
    let (mut reasons, mut line) = import_time_reading(p, text, lang);
    let view = decoded_view(p, text);
    if view != text {
        let (more, at) = import_time_reading(p, &view, lang);
        let note = p.text("_DV_NOTE");
        for r in more {
            if !reasons.contains(&r) {
                reasons.push(cat(&[&r, &note]));
                line = line.or(at);
            }
        }
    }
    (reasons, line)
}

fn import_time_reading(p: &Pack, text: &[u32], lang: Option<&str>) -> (Vec<PyStr>, Option<usize>) {
    let (reasons, line) = import_time_risk_of(p, text);
    if !reasons.is_empty() {
        if let Some(lang) = lang.filter(|l| *l == "py" || *l == "js") {
            let code = import_code(p, text, lang);
            if code != text {
                return import_time_risk_of(p, &code);
            }
        }
    }
    (reasons, line)
}

/// core._py_statement_literals
fn py_statement_literals(p: &Pack, text: &[u32], literals: &[(usize, usize)], comments: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let joins: PyStr = p.text("_PY_JOINS");
    let bracket = p.re("_BRACKET_RE");
    let doc_head = p.re("_PY_DOC_HEAD_RE");
    let space_tab = p.re("_SPACE_TAB_RE");
    let mut marks: Vec<(usize, usize, bool)> =
        literals.iter().map(|&(s, e)| (s, e, true)).chain(comments.iter().map(|&(s, e)| (s, e, false))).collect();
    marks.sort();
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut pos = 0usize;
    let mut last: Option<u32> = None;
    for (s, e, is_literal) in marks {
        if s < pos {
            continue;
        }
        let k = pystr::rfind_char(text, c('\n'), pos, s);
        let ls: isize = match k {
            Some(k) => k as isize + 1,
            None => {
                if pos == 0 {
                    0
                } else {
                    -1
                }
            }
        };
        let mut prior = last;
        if ls > pos as isize {
            let code = pystr::rstrip(pystr::sub(text, pos, ls as usize));
            if let Some(&ch) = code.last() {
                prior = Some(ch);
            }
        }
        let gap = pystr::sub(text, pos, s);
        for b in bracket.finditer(gap) {
            let g = b.group0()[0];
            depth = if matches!(g, 0x28 | 0x5B | 0x7B) { depth + 1 } else { depth.saturating_sub(1) };
        }
        let code = pystr::rstrip(gap);
        if let Some(&ch) = code.last() {
            last = Some(ch);
        }
        pos = e;
        if !is_literal {
            continue;
        }
        if e > s {
            last = text.get(e - 1).copied();
        }
        let j = space_tab.match_at(text, e as isize, text.len() as isize).map(|m| m.end()).unwrap_or(e);
        let prior_ok = match prior {
            None => true,
            Some(ch) => !joins.contains(&ch),
        };
        if ls >= 0
            && depth == 0
            && prior_ok
            && doc_head.match_at(text, ls, s as isize).is_some()
            && !(ls >= 2 && text[ls as usize - 2] == c('\\'))
            && (j == text.len() || text[j] == c('\n') || text[j] == c('#'))
        {
            out.push((s, e));
        }
    }
    out
}

/// core._blank
pub fn blank(text: &[u32], spans: &[(usize, usize)]) -> PyStr {
    if spans.is_empty() {
        return text.to_vec();
    }
    let mut out = Vec::with_capacity(text.len());
    let mut p = 0usize;
    for &(s, e) in spans {
        let s = s.max(p);
        if e <= s {
            continue;
        }
        out.extend_from_slice(pystr::sub(text, p, s));
        for &ch in pystr::sub(text, s, e) {
            out.push(if ch == c('\n') { ch } else { c(' ') });
        }
        p = e;
    }
    out.extend_from_slice(pystr::from(text, p));
    out
}

/// core._import_code
fn import_code(p: &Pack, text: &[u32], lang: &str) -> PyStr {
    if reads_own_source(p, text) {
        return text.to_vec();
    }
    let mut literals: Vec<(usize, usize)> = Vec::new();
    let py = lang == "py";
    let comments = lexer::lex_comment_spans(p, text, Some(lang), None, true, if py { Some(&mut literals) } else { None });
    let mut spans = comments.clone();
    if !literals.is_empty() {
        spans.extend(py_statement_literals(p, text, &literals, &comments));
        spans.sort();
    }
    blank(text, &spans)
}

fn call_open(p: &Pack, rest: &[u32]) -> bool {
    let mut depth: isize = 1;
    for b in p.re("_BRACKET_RE").finditer(rest) {
        depth += if matches!(b.group0()[0], 0x28 | 0x5B | 0x7B) { 1 } else { -1 };
        if depth == 0 {
            return false;
        }
    }
    true
}

fn powershell_run_at(p: &Pack, text: &[u32]) -> isize {
    let back = p.usize("_PS_EXEC_BACK");
    let max = p.usize("_PS_EXEC_MAX_NAMES");
    let exec = p.re("_EXEC_CALL_RE");
    for (k, m) in p.re("_PS_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let window = pystr::sub(text, m.start().saturating_sub(back), m.start());
        if exec.finditer(window).any(|cm| call_open(p, pystr::from(window, cm.end()))) {
            return m.start() as isize;
        }
    }
    -1
}

fn runs_download_through_shell(p: &Pack, row: &[u32]) -> bool {
    (has(row, "curl") || has(row, "wget"))
        && p.re("_EXEC_CALL_RE").search(row).is_some()
        && (pipes_download_to_shell(p, row) || runs_substituted_download(p, row))
}

/// core._import_harvest_at: where the text harvests (_IMPORT_HARVEST_RE), or
/// serializes a copy of the whole environment it made.
fn import_harvest_at(p: &Pack, text: &[u32]) -> Option<usize> {
    let harvest = if any_in(text, p.needles("_IMPORT_HARVEST_NEEDLES")) {
        p.re("_IMPORT_HARVEST_RE").search(text).map(|m| m.start())
    } else {
        None
    };
    harvest.or_else(|| {
        let at = env_copy_serialized_at(p, text);
        if at >= 0 {
            Some(at as usize)
        } else {
            None
        }
    })
}

fn import_time_risk_of(p: &Pack, text: &[u32]) -> (Vec<PyStr>, Option<usize>) {
    let mut reasons: Vec<PyStr> = Vec::new();
    let mut line: Option<usize> = None;
    let harvest = import_harvest_at(p, text);
    if let Some(at) = harvest {
        if let Some(service) = p.re("_EXFIL_SERVICE_RE").search(text) {
            reasons.push(cat(&[
                &u("reads credentials or the whole environment and sends them to an exfiltration service ("),
                head(service.group0(), 40),
                &u(")"),
            ]));
        } else if p.re("_NETWORK_RE").search(text).is_some() {
            reasons.push(u("reads credentials or the whole environment and sends data over the network"));
        }
        if !reasons.is_empty() {
            line = Some(line_of(text, at));
        }
    }
    if has(text, "curl") || has(text, "wget") {
        for (i, row) in pystr::split_char(text, c('\n')).iter().enumerate() {
            if runs_download_through_shell(p, row) {
                reasons.push(u("runs a downloaded script through a shell"));
                line = line.or(Some(i + 1));
                break;
            }
        }
    }
    let received = received::received_code_kind(p, text, &[], &[]);
    if let Some((at, kind)) = &received {
        reasons.push(cat_reason(p, kind));
        line = line.or(Some(*at));
    }
    if let Some((at, interp)) = received::downloads_and_runs(p, text) {
        match py_run_or(p, text, &interp).filter(|i| !i.is_empty()) {
            Some(i) => reasons.push(cat(&[&u("downloads a script and runs it with "), &i])),
            None => reasons.push(u("downloads a file and then runs it")),
        }
        line = line.or(Some(at));
    }
    if let Some((at, interp)) = received::decodes_and_runs(p, text) {
        match py_run_or(p, text, &interp).filter(|i| !i.is_empty()) {
            Some(i) => reasons.push(cat(&[&u("writes code it decodes to a file and runs it with "), &i])),
            None => reasons.push(u("writes a file it decodes and runs it")),
        }
        line = line.or(Some(at));
    }
    let mut signs: Vec<(usize, PyStr)> = Vec::new();
    let ps = powershell_risk(p, text);
    if let Some(first) = ps.first() {
        let at = powershell_run_at(p, text);
        if at >= 0 {
            signs.push((at as usize, first.clone()));
        }
    }
    let received_runs = matches!(&received, Some((_, k)) if *k == "run");
    if !received_runs {
        let at = stager_at(p, text);
        if at >= 0 {
            signs.push((at as usize, u("carries a script that downloads and runs code")));
        }
    }
    let at = reverse_shell_at(p, text);
    if at >= 0 {
        signs.push((at as usize, u("opens a reverse shell")));
    }
    let host = p.re("_HOST_INFO_RE").search(text).map(|m| m.start());
    if let Some(host) = host {
        if let Some(capture) = capture_service(p, text) {
            signs.push((
                host,
                cat(&[
                    &u("sends the machine's user or host name to a data-capture service ("),
                    head(capture.group0(), 40),
                    &u(")"),
                ]),
            ));
        }
    }
    let at = runs_own_source_at(p, text);
    if at >= 0 {
        signs.push((at as usize, u("runs code it reads back from its own file or a data file shipped with it")));
    }
    if dumps_workflow_secrets(p, text) {
        if let Some(m) = p.re("_SECRETS_DUMP_RE").search(text) {
            signs.push((m.start(), u("carries a GitHub Actions workflow that dumps every repository secret")));
        }
    }
    signs.extend(exfil_signs(p, text, host));
    for (at, reason) in signs {
        reasons.push(reason);
        line = line.or(Some(line_of(text, at)));
    }
    (reasons, line)
}
