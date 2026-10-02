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

pub(crate) fn cat_reason(p: &Pack, cat: &str) -> PyStr {
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

/// core._call_first_arg: a call's first argument (what follows its '(', as
/// _call_args gives it, up to a comma outside brackets and string
/// literals), stripped.
pub(crate) fn first_arg(args: &[u32]) -> &[u32] {
    let n = args.len();
    let mut depth: isize = 0;
    let mut i = 0usize;
    while i < n {
        let ch = args[i];
        if matches!(ch, 0x22 | 0x27 | 0x60) {
            match pystr::find_char(args, ch, i + 1) {
                None => break,
                Some(j) => {
                    i = j + 1;
                    continue;
                }
            }
        }
        if matches!(ch, 0x28 | 0x5B | 0x7B) {
            depth += 1;
        } else if matches!(ch, 0x29 | 0x5D | 0x7D) {
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            return pystr::strip(&args[..i]);
        }
        i += 1;
    }
    pystr::strip(args)
}

/// core._dns_domain_ok
fn dns_domain_ok(p: &Pack, tld: Option<&[u32]>) -> bool {
    match tld {
        Some(t) if !t.is_empty() => {
            let low = pystr::lower(t);
            !p.strs("_DNS_LOCAL_TLDS").iter().any(|r| r.as_slice() == low.as_slice())
        }
        _ => false,
    }
}

/// A value in a sum: something besides string literals (core._dns_built).
fn dns_value(p: &Pack, part: &[u32]) -> bool {
    let rest = p.re("_DNS_LITERAL_RE").sub_fn(part, 0, |_| Vec::new());
    p.re("_DNS_VALUE_RE").search(&rest).is_some()
}

fn first_of<'s>(m: &crate::pyre::Match<'s>, groups: &[usize]) -> Option<&'s [u32]> {
    groups.iter().filter_map(|&g| m.group(g)).find(|g| !g.is_empty())
}

/// core._dns_built: does the expression build a name from values and a
/// literal domain?
fn dns_built(p: &Pack, expr: &[u32]) -> bool {
    if let Some(m) = p.re("_DNS_TEMPLATE_RE").match_(expr) {
        let name = first_of(&m, &[1, 2, 3]).unwrap_or(&[]);
        return match p.re("_DNS_BUILT_NAME_RE").search(name) {
            Some(b) => dns_domain_ok(p, b.group(1)),
            None => false,
        };
    }
    if let Some(m) = p.re("_DNS_SUM_RE").search(expr) {
        return dns_domain_ok(p, first_of(&m, &[1, 2, 3])) && dns_value(p, &expr[..m.start()]);
    }
    match p.re("_DNS_FORMAT_RE").match_(expr) {
        Some(m) => dns_domain_ok(p, first_of(&m, &[1, 2])),
        None => false,
    }
}

/// core._dns_call_at: the offset of a lookup call of a built name, else -1.
fn dns_call_at(p: &Pack, text: &[u32]) -> isize {
    let max = p.usize("_DNS_LOOKUP_MAX");
    let span = p.usize("_DNS_ARG_SPAN");
    let assign_span = p.usize("_DNS_ASSIGN_SPAN");
    for (k, m) in p.re("_DNS_CALL_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let args = pystr::sub(text, m.end(), m.end() + span);
        let arg = first_arg(&args[..call_args_len(args)]);
        if dns_built(p, arg) {
            return m.start() as isize;
        }
        if p.re("_DNS_NAME_RE").match_(arg).is_some() {
            let src = cat(&[&p.text("_DNS_ASSIGN_HEAD"), &crate::pyre::escape(arg), &p.text("_DNS_ASSIGN_TAIL")]);
            let rx = rxutil::dynamic(src, 0);
            let lo = m.start().saturating_sub(assign_span);
            let mut last: Option<PyStr> = None;
            for a in rx.finditer_at(text, lo as isize, m.start() as isize) {
                last = Some(a.group(1).unwrap_or(&[]).to_vec());
            }
            if let Some(expr) = last {
                if dns_built(p, pystr::strip(&expr)) {
                    return m.start() as isize;
                }
            }
        }
    }
    -1
}

/// core._dns_command_at: the offset of a lookup command code writes with a
/// built name, else -1.
fn dns_command_at(p: &Pack, text: &[u32]) -> isize {
    let max = p.usize("_DNS_LOOKUP_MAX");
    let mut found: Vec<usize> = Vec::new();
    for (k, m) in p.re("_DNS_CMD_SUM_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let tail_text = m.group(2).unwrap_or(&[]);
        let rest = first_arg(&tail_text[..call_args_len(tail_text)]);
        let plus = cat(&[&u("+"), rest]);
        if let Some(t) = p.re("_DNS_SUM_RE").search(&plus) {
            if dns_domain_ok(p, first_of(&t, &[1, 2, 3])) && dns_value(p, &rest[..t.start().saturating_sub(1)]) {
                found.push(m.start());
                break;
            }
        }
    }
    for (k, m) in p.re("_DNS_CMD_TEMPLATE_RE").finditer(text).enumerate() {
        if k >= max {
            break;
        }
        if dns_domain_ok(p, m.group(1)) {
            found.push(m.start());
            break;
        }
    }
    found.into_iter().min().map(|a| a as isize).unwrap_or(-1)
}

/// core._dns_shell_at: the offset of a shell command that looks up a name
/// holding the machine's user or host name, else -1.
fn dns_shell_at(p: &Pack, text: &[u32]) -> isize {
    let max = p.usize("_DNS_LOOKUP_MAX");
    let span = p.usize("_DNS_SHELL_SPAN");
    let id = p.re("_DNS_SHELL_ID_RE");
    let cut = p.re("_DNS_SHELL_CUT_RE");
    for (k, m) in id.finditer(text).enumerate() {
        if k >= max {
            break;
        }
        let mut head = pystr::sub(text, m.start().saturating_sub(span), m.start());
        if let Some(last) = cut.finditer(head).last() {
            head = &head[last.end()..];
        }
        let cmd = match p.re("_DNS_SHELL_CMD_RE").search(head) {
            Some(x) => x,
            None => continue,
        };
        let mut tail = pystr::sub(text, m.end(), m.end() + span);
        if let Some(x) = cut.search(tail) {
            tail = &tail[..x.start()];
        }
        let tail = id.sub_fn(tail, 0, |_| vec![0]);
        let left = p.re("_DNS_SHELL_LEFT_RE").search(head).map(|x| x.group0().to_vec()).unwrap_or_default();
        let right = p.re("_DNS_SHELL_RIGHT_RE").match_(&tail).map(|x| x.group0().to_vec()).unwrap_or_default();
        let token = cat(&[&left, &[0], &right]);
        if let Some(found) = p.re("_DNS_SHELL_HOST_RE").match_(&token) {
            if dns_domain_ok(p, found.group(1)) {
                return (m.start() - head.len() + cmd.start()) as isize;
            }
        }
    }
    -1
}

/// core.dns_beacon_at: the offset of a DNS lookup of a name built from
/// values and a literal domain, else -1. `host`: does the text read the
/// machine's user or host name? Without, only a shell command's name that
/// holds it counts.
pub fn dns_beacon_at(p: &Pack, text: &[u32], host: bool) -> isize {
    let mut found: Vec<isize> = Vec::new();
    if host {
        found.extend([dns_call_at(p, text), dns_command_at(p, text)].into_iter().filter(|&a| a >= 0));
    }
    let at = dns_shell_at(p, text);
    if at >= 0 {
        found.push(at);
    }
    found.into_iter().min().unwrap_or(-1)
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

/// core.wallet_swap_at: (offset, where) of the wallet addresses a script
/// swaps for its own — patterns of two kinds of address or more, the user's
/// addresses intercepted (the clipboard read and written, or the page's
/// requests and its wallet), an address written in the code — else None.
pub fn wallet_swap_at(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    if !any_in(text, p.needles("_WS_NEEDLES")) {
        return None;
    }
    let mut kinds: Vec<usize> = Vec::new();
    let mut first: Option<usize> = None;
    for (k, m) in p.re("_WS_PATTERN_RE").finditer(text).enumerate() {
        if k >= p.usize("_WS_MAX") {
            break;
        }
        if let Some(g) = (1..=5).rev().find(|&g| m.group(g).is_some()) {
            if !kinds.contains(&g) {
                kinds.push(g);
            }
        }
        first.get_or_insert(m.start());
    }
    if kinds.len() < 2 || p.re("_WS_ADDRESS_RE").search(text).is_none() {
        return None;
    }
    let first = first.unwrap_or(0);
    if p.re("_WS_HOOK_RE").search(text).is_some() {
        return Some((first, u("the page's requests and its wallet")));
    }
    if p.re("_WS_CLIP_READ_RE").search(text).is_some() && p.re("_WS_CLIP_WRITE_RE").search(text).is_some() {
        return Some((first, u("the clipboard")));
    }
    None
}

/// core._exfil_signs: (offset, reason) of the exfiltration shapes and a
/// miner. `host`: where _HOST_INFO_RE matches.
pub fn exfil_signs(p: &Pack, text: &[u32], host: Option<usize>) -> Vec<(usize, PyStr)> {
    let mut signs: Vec<(usize, PyStr)> = Vec::new();
    let at = miner_at(p, text);
    if at >= 0 {
        signs.push((at as usize, u("runs a cryptocurrency miner (a Monero wallet address)")));
    }
    if let Some((at, place)) = wallet_swap_at(p, text) {
        signs.push((
            at,
            cat(&[&u("swaps the cryptocurrency wallet addresses its user copies or sends for its own ("), &place, &u(")")]),
        ));
    }
    if let Some(endpoint) = crate::flow::secret_endpoint_at(p, text) {
        signs.push(endpoint);
    }
    let mut net: Option<bool> = None;
    let mut network = || -> bool {
        if net.is_none() {
            net = Some(p.re("_NETWORK_RE").search(text).is_some());
        }
        net.unwrap_or(false)
    };
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
    }
    let at = dns_beacon_at(p, text, host.is_some());
    if at >= 0 {
        signs.push((at as usize, u("sends the machine's user or host name in a DNS lookup of a name it builds")));
    }
    if host.is_some() {
        if let Some((at, origin)) = dead_drop_at(p, text) {
            signs.push((
                at,
                cat(&[&u("sends the machine's user or host name to an address it fetches at run time (from "), &origin, &u(")")]),
            ));
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

// ---------------- dead drops (0.1.8) ----------------

/// core.dead_drop_at: (offset, host) of a send whose address the text fetched
/// at run time from a literal URL on host, else None. The caller checks that
/// the text reads the machine's user or host name.
pub fn dead_drop_at(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    if !has(text, "http") || p.re("_DD_FETCH_RE").search(text).is_none() || p.re("_DD_SEND_RE").search(text).is_none() {
        return None;
    }
    let spans = literal_spans(p, text);
    let starts: Vec<usize> = spans.iter().map(|&(s, _)| s).collect();
    let in_literal = |pos: usize| -> bool {
        let k = starts.partition_point(|&s| s <= pos);
        k > 0 && pos < spans[k - 1].1
    };
    let ident = p.re("_IDENT_TOKEN_RE");
    let uses = |lo: usize, hi: usize, names: &HashSet<PyStr>| -> bool {
        if names.is_empty() {
            return false;
        }
        let part = pystr::sub(text, lo, hi);
        ident.finditer(part).any(|m| names.contains(m.group0()) && !in_literal(lo + m.start()))
    };
    let max_assigns = p.usize("_DD_MAX_ASSIGNS");
    let max_calls = p.usize("_DD_MAX_CALLS");
    let span = p.usize("_DD_ARG_SPAN");
    let url_in = p.re("_DD_URL_IN_RE");
    let mut assigns: Vec<(PyStr, usize, usize)> = Vec::new(); // what is assigned
    let mut url_names: Vec<(PyStr, PyStr)> = Vec::new(); // name -> the host of the URL literal assigned to it
    for (k, m) in p.re("_DD_ASSIGN_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if in_literal(m.start_of(1) as usize) {
            continue;
        }
        let name = m.group(1).unwrap_or(&[]).to_vec();
        if let Some(url) = url_in.search(m.group(2).unwrap_or(&[])) {
            if !url_names.iter().any(|(n, _)| *n == name) {
                url_names.push((name.clone(), url.group(1).unwrap_or(&[]).to_vec()));
            }
        }
        assigns.push((name, m.start_of(2) as usize, m.end_of(2) as usize));
    }
    let destruct_name = p.re("_DD_DESTRUCT_NAME_RE");
    for (k, m) in p.re("_DD_DESTRUCT_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if in_literal(m.start()) {
            continue;
        }
        for part in pystr::split_char(m.group(1).unwrap_or(&[]), c(',')) {
            if let Some(name) = destruct_name.search(pystr::strip(part)) {
                assigns.push((name.group(1).unwrap_or(&[]).to_vec(), m.start_of(2) as usize, m.end_of(2) as usize));
            }
        }
    }
    let mut followed: HashSet<PyStr> = HashSet::new();
    let mut origin: Option<PyStr> = None;
    let url_re = p.re("_DD_URL_RE");
    let arg_callback = p.re("_DD_ARG_CALLBACK_RE");
    let as_re = p.re("_DD_AS_RE");
    let then_head = p.re("_DD_THEN_HEAD_RE");
    let param_re = p.re("_DD_PARAM_RE");
    let then_max = p.usize("_DD_THEN_MAX");
    for (k, f) in p.re("_DD_FETCH_RE").finditer(text).enumerate() {
        if k >= max_calls {
            break;
        }
        if in_literal(f.start()) {
            continue;
        }
        let window = pystr::sub(text, f.end(), f.end() + span);
        let args = &window[..call_args_len(window)];
        let first = first_arg(args);
        let host: PyStr = match url_re.match_(first) {
            Some(url) => url.group(1).unwrap_or(&[]).to_vec(),
            None => match url_names.iter().find(|(n, _)| n.as_slice() == first) {
                Some((_, h)) => h.clone(),
                None => continue,
            },
        };
        let before = followed.len();
        for (name, lo, hi) in &assigns {
            if *lo <= f.start() && f.start() < *hi {
                followed.insert(name.clone());
            }
        }
        if let Some(cb) = arg_callback.search(args) {
            if !in_literal(f.end() + cb.start()) {
                followed.insert(first_of(&cb, &[1, 2, 3]).unwrap_or(&[]).to_vec());
            }
        }
        let mut pos = f.end() + args.len() + 1; // after the call's closing bracket
        if let Some(m) = as_re.match_at(text, pos as isize, text.len() as isize) {
            followed.insert(m.group(1).unwrap_or(&[]).to_vec());
        }
        for _ in 0..then_max {
            let h = match then_head.match_at(text, pos as isize, text.len() as isize) {
                Some(h) => h,
                None => break,
            };
            let window = pystr::sub(text, h.end(), h.end() + span);
            let then_args = &window[..call_args_len(window)];
            if let Some(param) = param_re.match_(then_args) {
                followed.insert(param.group(1).unwrap_or(&[]).to_vec());
            }
            pos = h.end() + then_args.len() + 1;
        }
        if origin.is_none() && followed.len() > before {
            origin = Some(host);
        }
    }
    if followed.is_empty() {
        return None;
    }
    let mut funcs: Vec<(usize, PyStr)> = Vec::new(); // the functions defined
    for (k, m) in p.re("_DD_FUNC_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        funcs.push((m.start(), first_of(&m, &[1, 2, 3]).unwrap_or(&[]).to_vec()));
    }
    let mut loops: Vec<(PyStr, usize, usize)> = Vec::new();
    for (k, m) in p.re("_DD_FOR_RE").finditer(text).enumerate() {
        if k >= max_assigns {
            break;
        }
        if in_literal(m.start()) {
            continue;
        }
        if m.group(2).map_or(false, |g| !g.is_empty()) {
            loops.push((m.group(1).unwrap_or(&[]).to_vec(), m.start_of(2) as usize, m.end_of(2) as usize));
        } else {
            loops.push((m.group(3).unwrap_or(&[]).to_vec(), m.start_of(4) as usize, m.end_of(4) as usize));
        }
    }
    let callback = p.re("_DD_CALLBACK_RE");
    let ret = p.re("_DD_RETURN_RE");
    for _ in 0..p.usize("_DD_PASSES") {
        let mut grown = false;
        for (name, lo, hi) in assigns.iter().chain(loops.iter()) {
            if !followed.contains(name) && uses(*lo, *hi, &followed) {
                followed.insert(name.clone());
                grown = true;
            }
        }
        for (k, m) in callback.finditer(text).enumerate() {
            if k >= max_calls {
                break;
            }
            let obj = m.group(1).unwrap_or(&[]);
            let param = m.group(2).unwrap_or(&[]);
            if followed.contains(obj) && !followed.contains(param) && !in_literal(m.start()) {
                followed.insert(param.to_vec());
                grown = true;
            }
        }
        for (k, m) in ret.finditer(text).enumerate() {
            if k >= max_calls {
                break;
            }
            if in_literal(m.start()) || !uses(m.start_of(1) as usize, m.end_of(1) as usize, &followed) {
                continue;
            }
            let at = funcs.partition_point(|(s, _)| *s <= m.start());
            if at > 0 && !followed.contains(&funcs[at - 1].1) {
                followed.insert(funcs[at - 1].1.clone());
                grown = true;
            }
        }
        if !grown {
            break;
        }
    }
    let data = p.re("_DD_DATA_RE");
    for (k, s) in p.re("_DD_SEND_RE").finditer(text).enumerate() {
        if k >= max_calls {
            break;
        }
        if in_literal(s.start()) {
            continue;
        }
        let window = pystr::sub(text, s.end(), s.end() + span);
        let args = &window[..call_args_len(window)];
        let first = first_arg(args);
        let lead = args.len() - pystr::lstrip(args).len();
        if !uses(s.end() + lead, s.end() + lead + first.len(), &followed) {
            continue;
        }
        let method = s.group(1).map_or(false, |g| !g.is_empty()) || s.group(2).map_or(false, |g| !g.is_empty());
        if method || data.search(args).is_some() {
            return Some((s.start(), origin.unwrap_or_default()));
        }
    }
    None
}

// ---------------- code read back from the file itself ----------------

/// core.reads_own_source
pub fn reads_own_source(p: &Pack, text: &[u32]) -> bool {
    p.re("_SELF_READ_RE").finditer(text).any(|m| reads_prose(text, m.start()))
}

/// Does the read of its own source _SELF_READ_RE found at `at` read
/// something that is not code? Its last form, a function's source
/// (`}).toString()`), only where the function ends in a comment (`/* … */
/// }).toString()`, a payload kept there): one that ends in code is source
/// handed on to run elsewhere (a browser-automation tool's evaluate), not
/// read back. Every other form: yes.
fn reads_prose(text: &[u32], at: usize) -> bool {
    if text.get(at) != Some(&c('}')) {
        return true;
    }
    let mut k = at;
    while k > 0 && pystr::is_space(text[k - 1]) {
        k -= 1;
    }
    k >= 2 && text[k - 2] == c('*') && text[k - 1] == c('/')
}

/// len(core._call_args(text))
pub(crate) fn call_args_len(text: &[u32]) -> usize {
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
pub(crate) fn literal_spans(p: &Pack, text: &[u32]) -> Vec<(usize, usize)> {
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

/// The spans of `text` that are not code: in JavaScript or Python (`lang`),
/// its literals and comments as the language's lexers read them (crate::lex:
/// what both readings agree on; a template's or an f-string's text is a
/// literal, their holes code); in a text of no language the lexers read,
/// its quoted literals paired as they come (`literal_spans`). Sorted,
/// disjoint.
fn prose_spans(p: &Pack, text: &[u32], lang: Option<&str>) -> Vec<(usize, usize)> {
    let st = match lang.and_then(|l| crate::lex::structure(text, l, true)) {
        Some(st) => st,
        None => return literal_spans(p, text),
    };
    let mut all = st.literals;
    all.extend(st.comments);
    all.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(all.len());
    for (a, b) in all {
        match out.last_mut() {
            Some(last) if a <= last.1 => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
}

/// Does `lang` name a language the lexers read?
fn lexed(lang: Option<&str>) -> bool {
    matches!(lang, Some("js" | "py"))
}

/// core.runs_own_source_at. `lang`: the text's language, when the lexers
/// read it (what is code is then the lexers' reading: `prose_spans`).
pub fn runs_own_source_at(p: &Pack, text: &[u32], lang: Option<&str>) -> isize {
    let self_read = p.re("_SELF_READ_RE");
    let sibling = p.re("_SIBLING_DATA_RE");
    let sibling_path = p.re("_SIBLING_PATH_RE");
    if self_read.search(text).is_none() && sibling.search(text).is_none() && sibling_path.search(text).is_none() {
        return -1;
    }
    let spans = prose_spans(p, text, lang);
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
        self_read.finditer(part).any(|m| !in_literal(lo + m.start()) && reads_prose(text, lo + m.start()))
            || sibling.finditer(part).any(|m| !in_literal(lo + m.start()))
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
    // names of data files' paths (a template's `${__dirname}` counts: read
    // by the lexers, its hole is code; else the whole template counts)
    let lexed = lexed(lang);
    let mut paths: HashSet<PyStr> = HashSet::new();
    for (name, lo, hi) in &assigns {
        for m in sibling_path.finditer(pystr::sub(text, *lo, *hi)) {
            match literal_at(lo + m.start()) {
                Some((s, _)) if lexed || text[s] != c('`') => continue,
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
    if p.re("_SHORTCUT_FOUND_RE").search(text).is_some()
        && has(text, "CreateShortcut")
        && p.re("_SHORTCUT_SET_RE").search(text).is_some()
    {
        reasons.push(u("rewrites the shortcuts of programs on the machine"));
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

// ---------------- code that drives an AI coding agent ----------------

/// A match's text without the quotes around it (Python's `.strip("'\"")`).
fn unquoted(s: &[u32]) -> PyStr {
    pystr::strip_chars(s, "'\"").to_vec()
}

/// core.agent_hijack: (agent, flag, line) for the first line of dependency
/// code that hands a known AI-agent CLI, with a flag that turns off its
/// confirmations, to an exec or spawn call. `text` has \n line endings.
pub fn agent_hijack(p: &Pack, text: &[u32]) -> Option<(PyStr, PyStr, usize)> {
    let flag_re = p.re("_AGENT_FLAG_RE");
    flag_re.search(text)?;
    let exec = p.re("_EXEC_CALL_RE");
    let bin = p.re("_AGENT_BIN_RE");
    for (i, row) in pystr::split_char(text, c('\n')).into_iter().enumerate() {
        if exec.search(row).is_none() {
            continue;
        }
        if let (Some(flag), Some(binm)) = (flag_re.search(row), bin.search(row)) {
            return Some((unquoted(binm.group0()), flag.group0().to_vec(), i + 1));
        }
    }
    None
}

/// core.agent_hijack_in_command: (agent, flag) when an install hook's
/// command launches the agent itself (the shell is the exec call).
pub fn agent_hijack_in_command(p: &Pack, cmd: &[u32]) -> Option<(PyStr, PyStr)> {
    let flag = p.re("_AGENT_FLAG_RE").search(cmd);
    let binm = p.re("_AGENT_BIN_CMD_RE").search(cmd);
    match (flag, binm) {
        (Some(flag), Some(binm)) => Some((unquoted(binm.group0()), flag.group0().to_vec())),
        _ => None,
    }
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

// ---------------- character codes (core's comment above _DV_CC_BODY) ----------------

/// A value core's character-code evaluator works with: an integer, a list of
/// integers, a string (Char: a string of one character, what indexing a
/// string gives).
#[derive(Clone)]
enum CcVal {
    Int(i64),
    List(std::rc::Rc<Vec<i64>>),
    Str(std::rc::Rc<Vec<u32>>),
    Char(u32),
}

#[derive(Clone, Copy)]
enum CcOp {
    Or,
    Xor,
    And,
    Shl,
    Shr,
    Ushr,
    Add,
    Sub,
    Mul,
    Mod,
}

/// core._cc_parse's syntax tree; a name is resolved to its slot when a
/// decoder is made (CcSlot).
enum CcNode {
    Num(i64),
    Var(PyStr),
    Slot(CcSlot),
    Neg(Box<CcNode>),
    Not(Box<CcNode>),
    Plus(Box<CcNode>),
    Bin(CcOp, Box<CcNode>, Box<CcNode>),
    Index(Box<CcNode>, Box<CcNode>),
    CharCode(Box<CcNode>, Box<CcNode>),
    Len(Box<CcNode>),
    Ord(Box<CcNode>),
}

#[derive(Clone, Copy)]
enum CcSlot {
    Param(usize),
    Elem,
    Index,
}

enum CcTok {
    Num(PyStr),
    Name(PyStr),
    Op(PyStr),
}

/// core._cc_int_literal
fn cc_int_literal(p: &Pack, s: &[u32]) -> Result<i64, ()> {
    if p.re("_DV_CC_INT_RE").fullmatch(s).is_none() {
        return Err(());
    }
    let hex = s.len() >= 2 && s[0] == c('0') && (s[1] == c('x') || s[1] == c('X'));
    let mut v: i64 = 0;
    for &ch in if hex { &s[2..] } else { s } {
        let d = match ch {
            0x30..=0x39 => ch - 0x30,
            0x61..=0x66 => ch - 0x61 + 10,
            0x41..=0x46 => ch - 0x41 + 10,
            _ => return Err(()),
        } as i64;
        v = v * if hex { 16 } else { 10 } + d;
    }
    if v > p.int("_DV_CC_INT_MAX") {
        return Err(());
    }
    Ok(v)
}

/// core._cc_ints
fn cc_ints(p: &Pack, items: &[u32]) -> Result<Vec<i64>, ()> {
    let mut parts: Vec<&[u32]> = pystr::split_char(items, c(',')).into_iter().map(pystr::strip).collect();
    if parts.last().is_some_and(|x| x.is_empty()) {
        parts.pop();
    }
    parts.iter().map(|x| cc_int_literal(p, x)).collect()
}

/// core._cc_parse: the transform's tree, else None.
fn cc_parse(p: &Pack, expr: &[u32]) -> Option<CcNode> {
    let token = p.re("_DV_CC_TOKEN_RE");
    let max_tokens = p.usize("_DV_CC_MAX_TOKENS");
    let mut toks: Vec<CcTok> = Vec::new();
    let mut pos = 0usize;
    while pos < expr.len() {
        let Some(m) = token.match_at(expr, pos as isize, expr.len() as isize) else {
            if !pystr::strip_chars(&expr[pos..], " \t").is_empty() {
                return None;
            }
            break;
        };
        if let Some(n) = m.name("num") {
            toks.push(CcTok::Num(n.to_vec()));
        } else if let Some(n) = m.name("name") {
            toks.push(CcTok::Name(n.to_vec()));
        } else {
            toks.push(CcTok::Op(m.name("op").unwrap_or(&[]).to_vec()));
        }
        pos = m.end();
        if toks.len() > max_tokens {
            return None;
        }
    }
    let binary: &Vec<(PyStr, i64)> = p.derived("_DV_CC_BINARY", |v| {
        v.get("map")
            .and_then(|m| m.as_obj())
            .unwrap_or(&[])
            .iter()
            .map(|(k, x)| (k.clone(), x.get("value").and_then(|y| y.as_i64()).unwrap_or(0)))
            .collect()
    });
    let mut parser = CcParser { p, toks: &toks, at: 0, binary, max_depth: p.usize("_DV_CC_MAX_DEPTH") };
    let tree = parser.expression(1, 0).ok()?;
    if parser.at == toks.len() {
        Some(tree)
    } else {
        None
    }
}

struct CcParser<'a> {
    p: &'a Pack,
    toks: &'a [CcTok],
    at: usize,
    binary: &'a [(PyStr, i64)],
    max_depth: usize,
}

impl CcParser<'_> {
    fn peek_op(&self, v: &str) -> bool {
        matches!(self.toks.get(self.at), Some(CcTok::Op(o)) if pystr::eq(o, v))
    }

    fn take(&mut self, v: &str) -> Result<(), ()> {
        if !self.peek_op(v) {
            return Err(());
        }
        self.at += 1;
        Ok(())
    }

    fn expression(&mut self, min_prec: i64, depth: usize) -> Result<CcNode, ()> {
        if depth > self.max_depth {
            return Err(());
        }
        let mut left = self.unary(depth)?;
        loop {
            let Some(CcTok::Op(op)) = self.toks.get(self.at) else {
                return Ok(left);
            };
            let Some(prec) = self.binary.iter().find(|(k, _)| k == op).map(|(_, v)| *v) else {
                return Ok(left);
            };
            if prec < min_prec {
                return Ok(left);
            }
            let kind = match crate::pystr::to_string(op).as_str() {
                "|" => CcOp::Or,
                "^" => CcOp::Xor,
                "&" => CcOp::And,
                "<<" => CcOp::Shl,
                ">>" => CcOp::Shr,
                ">>>" => CcOp::Ushr,
                "+" => CcOp::Add,
                "-" => CcOp::Sub,
                "*" => CcOp::Mul,
                "%" => CcOp::Mod,
                _ => return Err(()),
            };
            self.at += 1;
            let right = self.expression(prec + 1, depth + 1)?;
            left = CcNode::Bin(kind, Box::new(left), Box::new(right));
        }
    }

    fn unary(&mut self, depth: usize) -> Result<CcNode, ()> {
        for (op, which) in [("-", 0u8), ("~", 1), ("+", 2)] {
            if self.peek_op(op) {
                if depth >= self.max_depth {
                    return Err(());
                }
                self.at += 1;
                let arg = Box::new(self.unary(depth + 1)?);
                return Ok(match which {
                    0 => CcNode::Neg(arg),
                    1 => CcNode::Not(arg),
                    _ => CcNode::Plus(arg),
                });
            }
        }
        self.postfix(depth)
    }

    fn postfix(&mut self, depth: usize) -> Result<CcNode, ()> {
        let mut node = self.primary(depth)?;
        loop {
            if self.peek_op("[") {
                self.at += 1;
                let index = self.expression(1, depth + 1)?;
                self.take("]")?;
                node = CcNode::Index(Box::new(node), Box::new(index));
            } else if self.peek_op(".") {
                self.at += 1;
                let length = match self.toks.get(self.at) {
                    Some(CcTok::Name(n)) if pystr::eq(n, "length") => true,
                    Some(CcTok::Name(n)) if pystr::eq(n, "charCodeAt") => false,
                    _ => return Err(()),
                };
                self.at += 1;
                if length {
                    node = CcNode::Len(Box::new(node));
                } else {
                    self.take("(")?;
                    let arg = if self.peek_op(")") { CcNode::Num(0) } else { self.expression(1, depth + 1)? };
                    self.take(")")?;
                    node = CcNode::CharCode(Box::new(node), Box::new(arg));
                }
            } else {
                return Ok(node);
            }
        }
    }

    fn primary(&mut self, depth: usize) -> Result<CcNode, ()> {
        let tok = self.toks.get(self.at).ok_or(())?;
        self.at += 1;
        match tok {
            CcTok::Num(s) => Ok(CcNode::Num(cc_int_literal(self.p, s)?)),
            CcTok::Name(n) => {
                let (ord, len) = (pystr::eq(n, "ord"), pystr::eq(n, "len"));
                if (ord || len) && self.peek_op("(") {
                    self.at += 1;
                    let arg = Box::new(self.expression(1, depth + 1)?);
                    self.take(")")?;
                    return Ok(if ord { CcNode::Ord(arg) } else { CcNode::Len(arg) });
                }
                Ok(CcNode::Var(n.clone()))
            }
            CcTok::Op(o) if pystr::eq(o, "(") => {
                let inner = self.expression(1, depth + 1)?;
                self.take(")")?;
                Ok(inner)
            }
            CcTok::Op(_) => Err(()),
        }
    }
}

/// core._cc_names: the names a transform reads.
fn cc_names(tree: &CcNode, out: &mut HashSet<PyStr>) {
    match tree {
        CcNode::Var(n) => {
            out.insert(n.clone());
        }
        CcNode::Num(_) | CcNode::Slot(_) => {}
        CcNode::Neg(a) | CcNode::Not(a) | CcNode::Plus(a) | CcNode::Len(a) | CcNode::Ord(a) => cc_names(a, out),
        CcNode::Bin(_, a, b) | CcNode::Index(a, b) | CcNode::CharCode(a, b) => {
            cc_names(a, out);
            cc_names(b, out);
        }
    }
}

/// The tree with each name read from its slot (params, then the walk's
/// element and position: the element's when both have one name, as core's
/// env gives it).
fn cc_resolve(tree: CcNode, params: &[PyStr], elem: Option<&PyStr>, index: Option<&PyStr>) -> CcNode {
    let r = |t: Box<CcNode>| Box::new(cc_resolve(*t, params, elem, index));
    match tree {
        CcNode::Var(n) => {
            if elem == Some(&n) {
                CcNode::Slot(CcSlot::Elem)
            } else if index == Some(&n) {
                CcNode::Slot(CcSlot::Index)
            } else if let Some(k) = params.iter().position(|x| *x == n) {
                CcNode::Slot(CcSlot::Param(k))
            } else {
                CcNode::Var(n)
            }
        }
        CcNode::Neg(a) => CcNode::Neg(r(a)),
        CcNode::Not(a) => CcNode::Not(r(a)),
        CcNode::Plus(a) => CcNode::Plus(r(a)),
        CcNode::Len(a) => CcNode::Len(r(a)),
        CcNode::Ord(a) => CcNode::Ord(r(a)),
        CcNode::Bin(op, a, b) => CcNode::Bin(op, r(a), r(b)),
        CcNode::Index(a, b) => CcNode::Index(r(a), r(b)),
        CcNode::CharCode(a, b) => CcNode::CharCode(r(a), r(b)),
        other => other,
    }
}

const CC_INT_MIN: i64 = -2147483648;
const CC_INT_MAX: i64 = 2147483647;

fn cc_check(v: i64) -> Result<CcVal, ()> {
    if (CC_INT_MIN..=CC_INT_MAX).contains(&v) {
        Ok(CcVal::Int(v))
    } else {
        Err(())
    }
}

fn cc_num(v: CcVal) -> Result<i64, ()> {
    match v {
        CcVal::Int(i) => Ok(i),
        _ => Err(()),
    }
}

struct CcEnv<'a> {
    args: &'a [CcVal],
    elem: CcVal,
    index: i64,
}

/// core._cc_compile's function, worked out for one element.
fn cc_eval(tree: &CcNode, env: &CcEnv) -> Result<CcVal, ()> {
    Ok(match tree {
        CcNode::Num(v) => CcVal::Int(*v),
        CcNode::Var(_) => return Err(()),
        CcNode::Slot(CcSlot::Param(k)) => env.args.get(*k).cloned().ok_or(())?,
        CcNode::Slot(CcSlot::Elem) => env.elem.clone(),
        CcNode::Slot(CcSlot::Index) => CcVal::Int(env.index),
        CcNode::Neg(a) => return cc_check(-cc_num(cc_eval(a, env)?)?),
        CcNode::Not(a) => CcVal::Int(!cc_num(cc_eval(a, env)?)?),
        CcNode::Plus(a) => CcVal::Int(cc_num(cc_eval(a, env)?)?),
        CcNode::Bin(op, l, r) => {
            let a = cc_num(cc_eval(l, env)?)?;
            let b = cc_num(cc_eval(r, env)?)?;
            match op {
                CcOp::Add => return cc_check(a + b),
                CcOp::Sub => return cc_check(a - b),
                CcOp::Mul => return cc_check(a * b),
                CcOp::Mod => {
                    if a < 0 || b <= 0 {
                        return Err(());
                    }
                    CcVal::Int(a % b)
                }
                CcOp::And => CcVal::Int(a & b),
                CcOp::Or => CcVal::Int(a | b),
                CcOp::Xor => CcVal::Int(a ^ b),
                CcOp::Shl | CcOp::Shr | CcOp::Ushr => {
                    if !(0..=31).contains(&b) {
                        return Err(());
                    }
                    match op {
                        CcOp::Shl => return cc_check(a << b),
                        CcOp::Ushr if a < 0 => return Err(()),
                        _ => CcVal::Int(a >> b),
                    }
                }
            }
        }
        CcNode::Index(o, i) | CcNode::CharCode(o, i) => {
            let chars = matches!(tree, CcNode::CharCode(..));
            let seq = cc_eval(o, env)?;
            let k = cc_num(cc_eval(i, env)?)?;
            let len = match &seq {
                CcVal::Str(s) => s.len(),
                CcVal::Char(_) => 1,
                CcVal::List(l) if !chars => l.len(),
                _ => return Err(()),
            } as i64;
            if !(0..len).contains(&k) {
                return Err(());
            }
            let k = k as usize;
            match (&seq, chars) {
                (CcVal::Str(s), true) => CcVal::Int(s[k] as i64),
                (CcVal::Char(ch), true) => CcVal::Int(*ch as i64),
                (CcVal::Str(s), false) => CcVal::Char(s[k]),
                (CcVal::Char(ch), false) => CcVal::Char(*ch),
                (CcVal::List(l), false) => CcVal::Int(l[k]),
                _ => return Err(()),
            }
        }
        CcNode::Len(a) => match cc_eval(a, env)? {
            CcVal::Str(s) => CcVal::Int(s.len() as i64),
            CcVal::Char(_) => CcVal::Int(1),
            CcVal::List(l) => CcVal::Int(l.len() as i64),
            CcVal::Int(_) => return Err(()),
        },
        CcNode::Ord(a) => match cc_eval(a, env)? {
            CcVal::Char(ch) => CcVal::Int(ch as i64),
            CcVal::Str(s) if s.len() == 1 => CcVal::Int(s[0] as i64),
            _ => return Err(()),
        },
    })
}

/// core._cc_balanced: (text[i:j], j) up to the ')' that closes the call
/// opened just before i, else None.
fn cc_balanced(text: &[u32], i: usize, limit: usize) -> Option<(&[u32], usize)> {
    let mut depth = 0usize;
    let mut j = i;
    let end = text.len().min(i.saturating_add(limit));
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
                return if ch == c(')') { Some((&text[i..j], j)) } else { None };
            }
            depth -= 1;
        }
        j += 1;
    }
    None
}

/// core._cc_params
fn cc_params(p: &Pack, s: &[u32]) -> Option<Vec<PyStr>> {
    let names: Vec<&[u32]> = if pystr::strip(s).is_empty() {
        Vec::new()
    } else {
        pystr::split_char(s, c(',')).into_iter().map(pystr::strip).collect()
    };
    let name_re = p.re("_DV_CC_NAME_RE");
    if !(1..=p.usize("_DV_CC_MAX_PARAMS")).contains(&names.len()) || names.iter().any(|n| name_re.fullmatch(n).is_none()) {
        return None;
    }
    let unique: HashSet<&[u32]> = names.iter().copied().collect();
    if unique.len() != names.len() {
        return None;
    }
    Some(names.into_iter().map(|n| n.to_vec()).collect())
}

/// The first group of `names` that took part (Python's `m.group("a") or
/// m.group("b")` over groups that never match empty).
fn cc_group<'s>(m: &crate::pyre::Match<'s>, names: &[&str]) -> Option<&'s [u32]> {
    names.iter().find_map(|n| if m.regex().has_group(n) { m.name(n) } else { None })
}

/// A walk over a parameter (core._cc_walks' tuple).
struct CcWalk {
    at: usize,
    data: PyStr,
    elem: Option<PyStr>,
    index: Option<PyStr>,
    split: bool,
    js_map: bool,
}

/// core._cc_walks
fn cc_walks(p: &Pack, body: &[u32]) -> Vec<CcWalk> {
    let own = |g: Option<&[u32]>| g.map(|x| x.to_vec());
    let mut out: Vec<CcWalk> = Vec::new();
    for m in p.re("_DV_CC_FOR_RE").finditer(body) {
        out.push(CcWalk { at: m.start(), data: m.name("d").unwrap_or(&[]).to_vec(), elem: None,
                          index: own(m.name("i")), split: false, js_map: false });
    }
    for m in p.re("_DV_CC_MAP_RE").finditer(body) {
        out.push(CcWalk { at: m.start(), data: m.name("d").unwrap_or(&[]).to_vec(), elem: own(cc_group(&m, &["e", "e2", "e3"])),
                          index: own(cc_group(&m, &["i", "i2"])), split: m.name("split").is_some(), js_map: true });
    }
    for m in p.re("_DV_CC_PYFOR_RE").finditer(body) {
        out.push(CcWalk { at: m.start(), data: m.name("d").unwrap_or(&[]).to_vec(), elem: None,
                          index: own(m.name("i")), split: false, js_map: false });
    }
    for m in p.re("_DV_CC_PYITER_RE").finditer(body) {
        out.push(CcWalk { at: m.start(), data: cc_group(&m, &["d", "d2"]).unwrap_or(&[]).to_vec(),
                          elem: own(cc_group(&m, &["e", "e2"])), index: own(m.name("i")), split: false, js_map: false });
    }
    out.sort_by_key(|w| w.at);
    out
}

/// A decoder of the file's own (core._cc_decoders' tuple).
struct CcDecoder {
    params: usize,
    data_at: usize,
    elem: bool,
    index: bool,
    split: bool,
    js_map: bool,
    tree: CcNode,
}

/// core._cc_decoders: [(name, decoder)] in the order of their transforms.
fn cc_decoders(p: &Pack, view: &[u32]) -> Vec<(PyStr, CcDecoder)> {
    let body_len = p.usize("_DV_CC_BODY");
    let max = p.usize("_DV_CC_MAX_DECODERS");
    let map_re = p.re("_DV_CC_MAP_RE");
    let mut out: Vec<(PyStr, CcDecoder)> = Vec::new();
    let mut heads: Option<Vec<crate::pyre::Match>> = None;
    for site in p.re("_DV_CC_SITE_RE").finditer(view) {
        let heads = heads.get_or_insert_with(|| p.re("_DV_CC_FUNC_RE").finditer(view).collect());
        let k = heads.partition_point(|h| h.end() <= site.start());
        if k == 0 || site.start() >= heads[k - 1].end() + body_len {
            continue;
        }
        let head = &heads[k - 1];
        let name = cc_group(head, &["a", "b", "c"]).unwrap_or(&[]).to_vec();
        let param_list = ["pa", "pb", "pc", "pd"].iter().find_map(|g| head.name(g)).unwrap_or(&[]);
        let Some(params) = cc_params(p, param_list) else {
            continue;
        };
        if out.iter().any(|(n, _)| *n == name) {
            continue;
        }
        let Some((got, _)) = cc_balanced(view, site.end(), body_len) else {
            continue;
        };
        let arg = pystr::strip(got);
        let body = pystr::sub(view, head.end(), head.end() + body_len);
        let (walks, expr): (Vec<CcWalk>, &[u32]) = if pystr::starts_with(arg, "...") {
            let spread = pystr::lstrip_chars(&arg[3..], " \t");
            let Some(m) = map_re.match_(spread) else {
                continue;
            };
            if m.name("e").is_some() || !pystr::ends_with(spread, ")") {
                continue;
            }
            let walk = CcWalk { at: 0, data: m.name("d").unwrap_or(&[]).to_vec(),
                                elem: cc_group(&m, &["e2", "e3"]).map(|x| x.to_vec()),
                                index: m.name("i2").map(|x| x.to_vec()), split: m.name("split").is_some(), js_map: true };
            (vec![walk], pystr::sub(spread, m.end(), spread.len() - 1))
        } else {
            (cc_walks(p, body), arg)
        };
        let Some(tree) = cc_parse(p, expr) else {
            continue;
        };
        let mut names: HashSet<PyStr> = HashSet::new();
        cc_names(&tree, &mut names);
        let param_set: HashSet<&PyStr> = params.iter().collect();
        let mut tree = Some(tree);
        for w in walks {
            let bound: HashSet<&PyStr> = [w.elem.as_ref(), w.index.as_ref()].into_iter().flatten().filter(|v| !v.is_empty()).collect();
            if !param_set.contains(&w.data)
                || !bound.iter().any(|b| names.contains(*b))
                || bound.iter().any(|b| param_set.contains(*b))
                || !names.iter().all(|n| param_set.contains(n) || bound.contains(n))
            {
                continue;
            }
            let data_at = params.iter().position(|x| *x == w.data).unwrap_or(0);
            let resolved = cc_resolve(tree.take().unwrap_or(CcNode::Num(0)), &params, w.elem.as_ref(), w.index.as_ref());
            out.push((name, CcDecoder { params: params.len(), data_at, elem: w.elem.is_some(), index: w.index.is_some(),
                                        split: w.split, js_map: w.js_map, tree: resolved }));
            break;
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

/// core._cc_argument
fn cc_argument(
    p: &Pack,
    s: &[u32],
    view: &[u32],
    arrays: &mut std::collections::HashMap<PyStr, Option<std::rc::Rc<Vec<i64>>>>,
) -> Result<CcVal, ()> {
    let s = pystr::strip(s);
    if p.re("_DV_CC_ARG_INT_RE").fullmatch(s).is_some() {
        return Ok(CcVal::Int(if pystr::starts_with(s, "-") { -cc_int_literal(p, &s[1..])? } else { cc_int_literal(p, s)? }));
    }
    if s.len() >= 2 && matches!(s[0], 0x5B | 0x28) && matches!(s[s.len() - 1], 0x5D | 0x29) {
        let inner = &s[1..s.len() - 1];
        if pystr::strip(inner).is_empty() {
            return Err(());
        }
        return Ok(CcVal::List(std::rc::Rc::new(cc_ints(p, inner)?)));
    }
    if let Some(m) = p.re("_DV_CC_ARG_STR_RE").fullmatch(s) {
        let v = match m.name("a") {
            Some(a) => a,
            None => m.name("b").unwrap_or(&[]),
        };
        return Ok(CcVal::Str(std::rc::Rc::new(v.to_vec())));
    }
    if p.re("_DV_CC_NAME_RE").fullmatch(s).is_some() {
        if !arrays.contains_key(s) {
            let esc = crate::pyre::escape(s);
            let head_src = p.text("_DV_NAME_HEAD");
            let array = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_CC_ARRAY_TAIL")]), 0);
            let value = match array.search(view) {
                None => None,
                Some(a) => {
                    let mutated = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_MUTATED_TAIL")]), 0);
                    let assigned = rxutil::dynamic(cat(&[&head_src, &esc, &p.text("_DV_ASSIGNED_TAIL")]), 0);
                    if mutated.search(view).is_some() || assigned.finditer(view).count() != 1 {
                        None
                    } else {
                        cc_ints(p, a.name("items").unwrap_or(&[])).ok().map(std::rc::Rc::new)
                    }
                }
            };
            arrays.insert(s.to_vec(), value);
        }
        if let Some(Some(v)) = arrays.get(s) {
            return Ok(CcVal::List(v.clone()));
        }
    }
    Err(())
}

/// core._cc_run: the text a decoder gives for a call's arguments; `work`
/// (codes left) is spent.
fn cc_run(p: &Pack, d: &CcDecoder, args: &[CcVal], work: &mut usize) -> Result<PyStr, ()> {
    if args.len() < d.params {
        return Err(());
    }
    let data = &args[d.data_at];
    let n = match data {
        CcVal::List(l) if !d.js_map || !d.split => l.len(),
        CcVal::Str(s) if !d.js_map || d.split => s.len(),
        _ => return Err(()),
    };
    if n == 0 || n > p.usize("_DV_CC_MAX_CODES") || n > *work {
        return Err(());
    }
    *work -= n;
    let mut env = CcEnv { args: &args[..d.params], elem: CcVal::Int(0), index: 0 };
    let mut out: PyStr = Vec::with_capacity(n);
    for k in 0..n {
        if d.index {
            env.index = k as i64;
        }
        if d.elem {
            env.elem = match data {
                CcVal::List(l) => CcVal::Int(l[k]),
                CcVal::Str(s) => CcVal::Char(s[k]),
                _ => return Err(()),
            };
        }
        match cc_eval(&d.tree, &env)? {
            CcVal::Int(v) if (0x20..=0x7E).contains(&v) => out.push(v as u32),
            _ => return Err(()),
        }
    }
    Ok(out)
}

/// core._cc_split_args
fn cc_split_args(s: &[u32]) -> Vec<&[u32]> {
    let mut parts: Vec<&[u32]> = Vec::new();
    let mut depth = 0i64;
    let mut start = 0usize;
    let mut quote: Option<u32> = None;
    for (k, &ch) in s.iter().enumerate() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == c('\'') || ch == c('"') {
            quote = Some(ch);
        } else if ch == c('[') || ch == c('(') {
            depth += 1;
        } else if ch == c(']') || ch == c(')') {
            depth -= 1;
        } else if ch == c(',') && depth == 0 {
            parts.push(&s[start..k]);
            start = k + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

/// core._cc_literal_sub
fn cc_literal_sub(p: &Pack, m: &crate::pyre::Match) -> PyStr {
    let items = ["a", "b", "c", "d", "e", "f"].iter().find_map(|g| m.name(g)).unwrap_or(&[]);
    match cc_ints(p, items) {
        Ok(codes) if !codes.is_empty() && codes.iter().all(|v| (0x20..=0x7E).contains(v)) => {
            dv_quote(&codes.iter().map(|&v| v as u32).collect::<Vec<u32>>())
        }
        _ => m.group0().to_vec(),
    }
}

/// core._dv_char_codes: the view with the character codes it holds and the
/// calls of its own character-code decoders read as their text.
fn dv_char_codes(p: &Pack, view: &[u32]) -> PyStr {
    let view = p.re("_DV_CC_LITERAL_RE").sub_fn(view, 0, |m| cc_literal_sub(p, m));
    let decoders = cc_decoders(p, &view);
    if decoders.is_empty() {
        return view;
    }
    let mut names: Vec<&PyStr> = decoders.iter().map(|(n, _)| n).collect();
    names.sort();
    let alternation: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
    let parts: Vec<&[u32]> = alternation.iter().map(|x| x.as_slice()).collect();
    let src = cat(&[&p.text("_DV_NAME_HEAD"), &u("(?P<name>"), &pystr::join(&[c('|')], &parts), &u(")"),
                    &p.text("_DV_CC_CALL_TAIL")]);
    let call = rxutil::dynamic(src, 0);
    let max_calls = p.usize("_DV_CC_MAX_CALLS");
    let mut work = p.usize("_DV_CC_MAX_WORK");
    let mut calls = 0usize;
    let mut arrays = std::collections::HashMap::new();
    call.sub_fn(&view, 0, |m| {
        if calls >= max_calls {
            return m.group0().to_vec();
        }
        calls += 1;
        let args: Result<Vec<CcVal>, ()> =
            cc_split_args(m.name("args").unwrap_or(&[])).iter().map(|a| cc_argument(p, a, &view, &mut arrays)).collect();
        let name = m.name("name").unwrap_or(&[]);
        let got = args.and_then(|args| {
            let (_, d) = decoders.iter().find(|(n, _)| n.as_slice() == name).ok_or(())?;
            cc_run(p, d, &args, &mut work)
        });
        match got {
            Ok(text) => dv_quote(&text),
            Err(()) => m.group0().to_vec(),
        }
    })
}

/// A text's decoded view and the line of the string array it reads.
type Reading = (PyStr, Option<usize>);

/// The language a decoded view reads its literals in: JavaScript or Python
/// (with the lexers), else none (the patterns: a shell script, a command).
fn dv_lang(lang: Option<&str>) -> Option<&'static str> {
    match lang {
        Some("js") => Some("js"),
        Some("py") => Some("py"),
        _ => None,
    }
}

thread_local! {
    // the last text decoded_view read (in its language), its view and its
    // string array's line (core's _DV_MEMO): the install-script test, the
    // import-time test and the spawned-script follower read the same file
    static DV_MEMO: std::cell::RefCell<Option<(PyStr, Option<&'static str>, Reading)>> = const { std::cell::RefCell::new(None) };
}

/// core._dv_reading: decoded_view's reading of `text` and the line of the
/// string array it reads, the last text's kept.
fn dv_reading(p: &Pack, text: &[u32], lang: Option<&str>) -> Reading {
    let lang = dv_lang(lang);
    if let Some(r) = DV_MEMO
        .with(|m| m.borrow().as_ref().filter(|(t, l, _)| *l == lang && t.as_slice() == text).map(|(_, _, r)| r.clone()))
    {
        return r;
    }
    let r = decoded_view_of(p, text, lang);
    // (a reading the work budget cut short is no answer: the call fails,
    // and a later call must not be given it)
    if !crate::budget::exhausted() {
        DV_MEMO.with(|m| *m.borrow_mut() = Some((text.to_vec(), lang, r.clone())));
    }
    r
}

/// core.decoded_view: `text` (in `lang`, "js" or "py", when known) with the
/// strings it decodes as it runs written as their text; `text` itself when
/// it decodes none.
pub fn decoded_view(p: &Pack, text: &[u32], lang: Option<&str>) -> PyStr {
    dv_reading(p, text, lang).0
}

/// core.string_array_line: the 1-based line of the string array `text` is
/// built around (one whose calls decoded_view reads), else None.
pub fn string_array_line(p: &Pack, text: &[u32], lang: Option<&str>) -> Option<usize> {
    dv_reading(p, text, lang).1
}

/// Is a string value one the decoded view writes as a literal: printable
/// ASCII without a quote or a backslash (what its patterns read)?
fn dv_plain(v: &[u32]) -> bool {
    v.iter().all(|&ch| (c(' ')..=c('~')).contains(&ch) && ch != c('\'') && ch != c('"') && ch != c('\\'))
}

/// The decoded view's first step for JavaScript or Python (phase 2): the
/// text's string literals read as its runtime reads them (lex/value.rs) —
/// a literal that writes characters by their codes (`'child_pro\x63ess'`,
/// `'\N{…}'`) as its value, a run of literals the runtime joins (`'chi' +
/// "ld_" + `process``, Python's adjacent `'a' 'b'`) as one —, each written
/// as a literal where its value is printable ASCII without a quote or a
/// backslash. Where JavaScript may hold JSX, only what both readings agree
/// on. The line breaks a run spans follow it on its line, so that the
/// lines after it keep their numbers. (view, whether a code escape was
/// read: joins alone decode nothing.)
fn dv_literals(p: &Pack, text: &[u32], lang: &'static str) -> (PyStr, bool) {
    // (a run's value is never longer than its text: the view never grows)
    let max = p.usize("_DV_MAX_CHARS");
    let found = if lang == "py" {
        crate::lex::value::runs(text, &crate::lex::py::tokens(text), "py", max)
    } else {
        let plain = crate::lex::value::runs(text, &crate::lex::js::tokens(text, false), "js", max);
        if plain.is_empty() {
            plain
        } else {
            let jsx = crate::lex::value::runs(text, &crate::lex::js::tokens(text, true), "js", max);
            plain.into_iter().filter(|r| jsx.contains(r)).collect()
        }
    };
    let mut out: PyStr = Vec::with_capacity(text.len());
    let mut pos = 0usize;
    let mut pending = 0usize; // line breaks to write at the next one
    let mut decoded = false;
    let copy = |out: &mut PyStr, part: &[u32], pending: &mut usize| {
        if *pending > 0 {
            if let Some(k) = part.iter().position(|&ch| ch == c('\n')) {
                out.extend_from_slice(&part[..k]);
                out.extend(std::iter::repeat(c('\n')).take(*pending));
                *pending = 0;
                out.extend_from_slice(&part[k..]);
                return;
            }
        }
        out.extend_from_slice(part);
    };
    for r in found {
        if r.start < pos || !dv_plain(&r.value.chars) {
            continue;
        }
        copy(&mut out, &text[pos..r.start], &mut pending);
        if r.value.bytes {
            out.push(c('b'));
        }
        // its first literal's quote ('…' for a template)
        let q = text[r.start..r.end].iter().copied().find(|&ch| ch == c('\'') || ch == c('"') || ch == c('`'));
        let q = if q == Some(c('"')) { c('"') } else { c('\'') };
        out.push(q);
        out.extend_from_slice(&r.value.chars);
        out.push(q);
        pending += text[r.start..r.end].iter().filter(|&&ch| ch == c('\n')).count();
        decoded |= r.code_escape;
        pos = r.end;
    }
    if pos == 0 {
        return (text.to_vec(), false);
    }
    copy(&mut out, &text[pos..], &mut pending);
    out.extend(std::iter::repeat(c('\n')).take(pending));
    (out, decoded)
}

/// core._dv_unescape: `text` with its string literals written wholly in
/// \\x and \\u escapes, three or more, read as their text where that is
/// printable ASCII without a quote or a backslash; None when there is none.
fn dv_unescape(p: &Pack, text: &[u32]) -> Option<PyStr> {
    if !pystr::contains(text, "\\x") && !pystr::contains(text, "\\u") {
        return None;
    }
    let escape = p.re("_DV_ESCAPE_RE");
    let out = p.re("_DV_ESCAPED_LITERAL_RE").sub_fn(text, 0, |m| {
        let body = m.group(2).unwrap_or(&[]);
        let mut s: PyStr = Vec::with_capacity(body.len());
        let mut pos = 0usize;
        for e in escape.finditer(body) {
            s.extend_from_slice(&body[pos..e.start()]);
            let hex = e.group(1).or_else(|| e.group(2)).unwrap_or(&[]);
            s.push(hex.iter().fold(0u32, |acc, &d| acc * 16 + char::from_u32(d).and_then(|ch| ch.to_digit(16)).unwrap_or(0)));
            pos = e.end();
        }
        s.extend_from_slice(&body[pos..]);
        if s.iter().any(|&ch| !(c(' ')..=c('~')).contains(&ch) || ch == c('\'') || ch == c('"') || ch == c('\\')) {
            return m.group0().to_vec();
        }
        let q = m.group(1).unwrap_or(&[]);
        cat(&[q, &s, q])
    });
    if out == text {
        None
    } else {
        Some(out)
    }
}

/// core._dv_read: (decoded_view's reading of a text, the 1-based line of
/// the string array it reads). In JavaScript and Python its literals are
/// read with the lexers first (dv_literals); in another language (or none
/// known) literals written wholly in \\x and \\u escapes are (dv_unescape).
fn decoded_view_of(p: &Pack, text: &[u32], lang: Option<&'static str>) -> Reading {
    let (source, unescaped): (PyStr, bool) = match lang {
        Some(l) => dv_literals(p, text, l),
        None => match dv_unescape(p, text) {
            Some(v) => (v, true),
            None => (text.to_vec(), false),
        },
    };
    let (arrays, line) = match crate::strarr::sa_read(p, &source) {
        // (unescaping and joining keep the rows)
        Some((view, at)) => (Some(view), Some(1 + source[..at.min(source.len())].iter().filter(|&&ch| ch == c('\n')).count())),
        None => (None, None),
    };
    let proxies = crate::strarr::dv_proxies(p, arrays.as_deref().unwrap_or(&source));
    let base: PyStr = match (proxies, arrays) {
        (Some(x), _) => x,
        (None, Some(a)) => a,
        (None, None) => source.clone(),
    };
    // (an escape read, a string array or a proxy object read)
    let read_any = unescaped || base != source;
    let max = p.usize("_DV_MAX_CHARS");
    if !read_any && (text.len() > max || !any_in(text, p.needles("_DV_NEEDLES"))) {
        return (text.to_vec(), None);
    }
    let joined: PyStr = match lang {
        // (the literals a string array or a proxy object was read as, joined)
        Some(l) if base != source => dv_literals(p, &base, l).0,
        Some(_) => base.clone(),
        None if base.contains(&c('+')) => p.re("_DV_JOIN_RE").sub(&base, &[], 0),
        None => base.clone(),
    };
    let mut view = joined.clone();
    // (a longer text with a string array: its strings only)
    if base.len() <= max && any_in(&base, p.needles("_DV_NEEDLES")) {
        view = dv_decoders(p, view);
    }
    if view == joined && !read_any {
        return (text.to_vec(), None);
    }
    (dv_arrays_and_members(p, view), line)
}

/// core._dv_decoders: the decoders' calls on literals read as their text.
fn dv_decoders(p: &Pack, mut view: PyStr) -> PyStr {
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
    if has(&view, "fromCharCode") || has(&view, "chr") || has(&view, "byte") {
        view = dv_char_codes(p, &view);
    }
    view
}

/// The last steps of core._decoded_view: constant arrays read where
/// indexed, members named by literals.
fn dv_arrays_and_members(p: &Pack, mut view: PyStr) -> PyStr {
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

/// core._spawn_pieces: the operands of `expr` split at its top-level '/'
/// (Python's `Path / 'x'`), outside quotes and brackets.
fn spawn_pieces(expr: &[u32]) -> Vec<PyStr> {
    let mut pieces: Vec<PyStr> = Vec::new();
    let (mut depth, mut start, mut j) = (0isize, 0usize, 0usize);
    let mut quote: Option<u32> = None;
    while j < expr.len() {
        let ch = expr[j];
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
            depth -= 1;
        } else if ch == c('/') && depth == 0 {
            pieces.push(pystr::strip(&expr[start..j]).to_vec());
            start = j + 1;
        }
        j += 1;
    }
    pieces.push(pystr::strip(&expr[start.min(expr.len())..]).to_vec());
    pieces
}

/// core._spawn_join: a path joined from `parts` — a path or the script's own
/// directory, then literals (or names given one).
fn spawn_join(p: &Pack, parts: &[PyStr], text: &[u32], names: usize) -> Option<(bool, PyStr)> {
    let head = spawn_path(p, &parts[0], text, names)?;
    let mut segs: Vec<PyStr> = vec![head.1];
    for part in &parts[1..] {
        let piece = spawn_path(p, part, text, names)?;
        if piece.0 {
            return None;
        }
        segs.push(piece.1);
    }
    let refs: Vec<&[u32]> = segs.iter().map(|s| s.as_slice()).collect();
    Some((head.0, pystr::join(&[c('/')], &refs)))
}

/// core._spawn_path: (base is 'dir', path) or None; the script's own
/// directory is ('dir', '.').
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
    if p.re("_SPAWN_DIR_RE").fullmatch(expr).is_some() {
        return Some((true, u(".")));
    }
    if let Some(m) = p.re("_SPAWN_STR_RE").fullmatch(expr) {
        let inner = m.group(1).unwrap_or(&[]).to_vec();
        return spawn_path(p, &inner, text, names);
    }
    if let Some(m) = p.re("_SPAWN_JOIN_RE").match_(expr) {
        let parts = spawn_args(expr, m.end(), 400);
        if parts.is_empty() || !pystr::ends_with(pystr::rstrip(expr), ")") {
            return None;
        }
        return spawn_join(p, &parts, text, names);
    }
    if expr.contains(&c('/')) {
        let pieces = spawn_pieces(expr);
        if pieces.len() > 1 && pieces.iter().all(|x| !x.is_empty()) {
            return spawn_join(p, &pieces, text, names);
        }
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

/// core.spawned_scripts: [(base, path)], base "dir" or "cwd": read as
/// written, then with the strings it decodes as it runs decoded.
pub fn spawned_scripts(p: &Pack, text: &[u32], lang: Option<&str>) -> Vec<(&'static str, PyStr)> {
    let mut out = spawned_scripts_of(p, text);
    let max = p.usize("_SPAWN_MAX_TARGETS");
    if out.len() < max {
        let view = decoded_view(p, text, lang);
        if view != text {
            for target in spawned_scripts_of(p, &view) {
                if !out.contains(&target) {
                    out.push(target);
                    if out.len() >= max {
                        break;
                    }
                }
            }
        }
    }
    out
}

/// core._spawned_scripts: spawned_scripts' reading of one text.
fn spawned_scripts_of(p: &Pack, text: &[u32]) -> Vec<(&'static str, PyStr)> {
    if !["spawn", "execFile", "fork", "Popen", "run", "call", "check_"].iter().any(|n| has(text, n)) {
        return Vec::new();
    }
    let lit_re = p.re("_SPAWN_LIT_RE");
    let no_script = p.strs("_SPAWN_NO_SCRIPT_FLAGS");
    let value_flags = p.strs("_SPAWN_VALUE_FLAGS");
    let depth = p.usize("_SPAWN_NAME_DEPTH");
    let max = p.usize("_SPAWN_MAX_TARGETS");
    let max_named = p.usize("_SPAWN_MAX_NAMED");
    let script_ext = p.re("_SPAWN_SCRIPT_EXT_RE");
    let runtimes = p.map_strs("_JS_RUNTIMES");
    let mut out: Vec<(&'static str, PyStr)> = Vec::new();
    let mut named_calls = 0usize;
    for m in p.re("_SPAWN_CALL_RE").finditer(text) {
        let named = m.name("js").is_some() || m.name("py").is_some();
        if named {
            named_calls += 1;
            if named_calls > max_named {
                continue;
            }
        }
        let args = spawn_args(text, m.end(), 400);
        let mut skip = false;
        // `bun run x.js`: the runtime's subcommand that runs a file
        let mut runs: &[PyStr] = match m.name("rt") {
            Some(rt) => runtimes.iter().find(|(k, _)| k.as_slice() == rt).map(|(_, v)| v.as_slice()).unwrap_or(&[]),
            None => &[],
        };
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
                if runs.iter().any(|r| r.as_slice() == value.as_slice()) {
                    runs = &[];
                    continue;
                }
            }
            if let Some((is_dir, path)) = spawn_path(p, arg, text, depth) {
                let path = pystr::normpath(&pystr::replace_char(&path, c('\\'), c('/')));
                let base = if is_dir { "dir" } else { "cwd" };
                if !(pystr::eq(&path, ".") || path.is_empty())
                    && !pystr::starts_with(&path, "/")
                    && !out.iter().any(|(b, q)| *b == base && *q == path)
                    && (!named || script_ext.search(&path).is_some())
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

/// core.install_script_risk (a script: shell=True, command=False)
pub fn install_script_risk(p: &Pack, text: &[u32], lang: Option<&str>) -> Vec<PyStr> {
    install_script_risk_with(p, text, true, false, lang)
}

/// core.install_script_risk(text, shell, command, lang): `shell`, read a
/// shell script with the shell reader; `command`, the text is a hook's
/// command; `lang`, the script's language when known ("js", "py": its
/// strings are read as its runtime reads them).
pub fn install_script_risk_with(p: &Pack, text: &[u32], shell: bool, command: bool, lang: Option<&str>) -> Vec<PyStr> {
    let mut reasons = install_script_risk_of(p, text, shell, command, lang);
    let view = decoded_view(p, text, lang);
    if view != text {
        let _gate = crate::textgate::open(&view);
        let note = p.text("_DV_NOTE");
        for r in install_script_risk_of(p, &view, shell, command, lang) {
            if !reasons.contains(&r) {
                reasons.push(cat(&[&r, &note]));
            }
        }
    }
    if string_array_line(p, text, lang).is_some() {
        reasons.push(p.text("_SA_TECHNIQUE_REASON"));
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

/// core._destination: the data-capture or exfiltration service text names.
fn destination<'s>(p: &'s Pack, text: &'s [u32]) -> Option<crate::pyre::Match<'s>> {
    capture_service(p, text).or_else(|| p.re("_EXFIL_SERVICE_RE").search(text))
}

/// core._label_sends: adds the label of where the data goes, when one of the reasons sends it.
pub(crate) fn label_sends(p: &Pack, text: &[u32], reasons: &mut Vec<PyStr>) {
    let sends = p.strs("_SEND_REASONS");
    if reasons.iter().any(|r| sends.iter().any(|s| r.starts_with(s))) {
        if let Some(m) = destination(p, text) {
            let label = cat(&[&u("contacts an address typical of data exfiltration ("), head(m.group0(), 40), &u(")")]);
            if !reasons.contains(&label) {
                reasons.push(label);
            }
        }
    }
}

fn push_new(reasons: &mut Vec<PyStr>, r: PyStr) {
    if !reasons.contains(&r) {
        reasons.push(r);
    }
}

/// The data flow: local data a text sends (offset, kind, what, whether only
/// an address held it). JavaScript is read on its tree (the supply-chain
/// model of jsflow, phase 3 step 3), unless it doesn't parse or passes the
/// pass's bounds; any other text, and those, by the text follower.
pub(crate) fn local_data_sent(p: &Pack, text: &[u32], lang: Option<&str>) -> Option<(usize, &'static str, PyStr, bool)> {
    if lang == Some("js") {
        match crate::jsflow::supply::local_data_sent(text) {
            crate::jsflow::supply::Answer::Found(at, kind, what, in_address) => return Some((at, kind, what, in_address)),
            crate::jsflow::supply::Answer::Nothing => return None,
            crate::jsflow::supply::Answer::Unread => {}
        }
    }
    crate::flow::local_data_sent_at(p, text)
}

fn install_script_risk_of(p: &Pack, text: &[u32], shell: bool, command: bool, lang: Option<&str>) -> Vec<PyStr> {
    let mut reasons: Vec<PyStr> = Vec::new();
    // a download piped or substituted into a shell, and PowerShell: in code, where an exec call is handed them
    let code = !command && crate::shell::code_text(p, text);
    let rows: Vec<&[u32]> = if has(text, "curl") || has(text, "wget") { pystr::split_char(text, c('\n')) } else { Vec::new() };
    let exec = p.re("_EXEC_CALL_RE");
    let piped = if code {
        rows.iter().any(|row| pipes_download_to_shell(p, row) && exec.search(row).is_some())
    } else {
        pipes_download_to_shell(p, text)
    };
    if piped {
        reasons.push(u("pipes a download into a shell"));
    }
    let substituted = rows.iter().any(|row| runs_substituted_download(p, row) && (!code || exec.search(row).is_some()));
    let received = received::received_code_kind(p, text, &[], &[]);
    if substituted {
        reasons.push(cat_reason(p, "run"));
    } else if let Some((_, kind)) = &received {
        reasons.push(cat_reason(p, kind));
    }
    let ps = powershell_risk(p, text);
    if !ps.is_empty() && (!code || powershell_run_at(p, text) >= 0) {
        reasons.extend(ps);
    }
    let received_runs = matches!(&received, Some((_, k)) if *k == "run");
    if !received_runs && !substituted && stager_at(p, text) >= 0 {
        reasons.push(u("carries a script that downloads and runs code"));
    }
    if reverse_shell_at(p, text) >= 0 {
        reasons.push(u("opens a reverse shell"));
    }
    let host = p.re("_HOST_INFO_RE").search(text).map(|m| m.start());
    for (_at, reason) in exfil_signs(p, text, host) {
        push_new(&mut reasons, reason);
    }
    let ip: Option<PyStr> = match p.re("_RAW_IP_URL_RE").search(text) {
        Some(m) => Some(head(m.group0(), 40).to_vec()),
        None => raw_ip_connect(p, text),
    };
    if let Some(ip) = ip {
        reasons.push(cat(&[&u("contacts an address typical of data exfiltration ("), &ip, &u(")")]));
    }
    if runs_own_source_at(p, text, None) >= 0 {
        reasons.push(u("runs code it reads back from its own file or a data file shipped with it"));
    }
    // (0.1.8) data read from the machine and sent, whatever the address; the
    // commands the script runs, read as programs; where the data goes
    if let Some((_at, kind, what, in_address)) = local_data_sent(p, text, lang) {
        let sent = p.map_text("_LD_REASONS", kind);
        let mut reason = sent.clone();
        if kind == "environment" || kind == "file" || kind == "report" {
            reason = cat(&[&sent, &u(" ("), head(&what, 60), &u(")")]);
        }
        if !reasons.iter().any(|r| r.starts_with(&sent)) && (!in_address || capture_service(p, text).is_some()) {
            reasons.push(reason);
        }
    }
    for r in crate::shell::exec_command_reasons(p, text) {
        push_new(&mut reasons, r);
    }
    if shell && crate::shell::shell_text(p, text) {
        let mut walk = crate::shell::HookWalk::new();
        for r in crate::shell::sh_reasons(p, text, 0, false, &mut walk) {
            push_new(&mut reasons, r);
        }
    }
    label_sends(p, text, &mut reasons);
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
    let view = decoded_view(p, text, lang);
    if view != text {
        let _gate = crate::textgate::open(&view);
        let (more, at) = import_time_reading(p, &view, lang);
        let note = p.text("_DV_NOTE");
        for r in more {
            if !reasons.contains(&r) {
                reasons.push(cat(&[&r, &note]));
                line = line.or(at);
            }
        }
    }
    if let Some(sa) = string_array_line(p, text, lang) {
        reasons.push(p.text("_SA_TECHNIQUE_REASON"));
        line = line.or(Some(sa));
    }
    (reasons, line)
}

fn import_time_reading(p: &Pack, text: &[u32], lang: Option<&str>) -> (Vec<PyStr>, Option<usize>) {
    let (reasons, line) = import_time_risk_of(p, text, lang);
    if !reasons.is_empty() {
        if let Some(l) = lang.filter(|l| *l == "py" || *l == "js") {
            let code = import_code(p, text, l);
            if code != text {
                let _gate = crate::textgate::open(&code);
                return import_time_risk_of(p, &code, lang);
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
            && (j == text.len() || text[j] == c('\n') || text[j] == c('\r') || text[j] == c('#'))
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

/// core._import_code: `text` with its prose blanked (comments, and in
/// Python the string statements), unchanged when it reads its own source.
pub fn import_code(p: &Pack, text: &[u32], lang: &str) -> PyStr {
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
    // a command line an exec call is handed by a name given it
    let ps = p.re("_PS_RE");
    for (at, cmd) in crate::shell::exec_command_lines(p, text) {
        if ps.search(&cmd).is_some() {
            return at as isize;
        }
    }
    -1
}

fn runs_download_through_shell(p: &Pack, row: &[u32]) -> bool {
    (has(row, "curl") || has(row, "wget"))
        && p.re("_EXEC_CALL_RE").search(row).is_some()
        && (pipes_download_to_shell(p, row) || runs_substituted_download(p, row))
}

/// core._import_flow: (offset, kind, what, in_address) of the first local
/// data text sends (local_data_sent_at, then the command lines it hands a
/// shell), else None. `flows`: exec_command_flows(text).
fn import_flow(p: &Pack, text: &[u32], flows: &[(usize, PyStr)], lang: Option<&str>) -> Option<(usize, &'static str, PyStr, bool)> {
    if let Some(flow) = local_data_sent(p, text, lang) {
        return Some(flow);
    }
    for (at, reason) in flows {
        for kind in ["identity", "lookup-identity", "environment", "file", "report", "credentials", "address"] {
            let sent = p.map_text("_SH_DATA_REASONS", kind);
            if reason.starts_with(&sent) {
                let what = pystr::slice(reason, sent.len() as isize + 2, -1).to_vec();
                return Some((*at, if kind == "lookup-identity" { "identity" } else { kind }, what, false));
            }
        }
    }
    None
}

fn import_time_risk_of(p: &Pack, text: &[u32], lang: Option<&str>) -> (Vec<PyStr>, Option<usize>) {
    let mut reasons: Vec<PyStr> = Vec::new();
    let mut line: Option<usize> = None;
    let flows = crate::shell::exec_command_flows(p, text);
    if let Some((at, kind, what, in_address)) = import_flow(p, text, &flows, lang) {
        // a data-capture service for any local data; a service a client talks
        // to with its user's key for what no client sends: the whole
        // environment, the instance's credentials, a credential store
        let whole = p.text("_LD_WHOLE_ENV");
        let harvest = !in_address
            && ((kind == "environment" && what == whole)
                || kind == "credentials"
                || (kind == "file"
                    && p.re("_CRED_STORE_RE").search(&what).is_some()
                    && p.re("_PUBLIC_KEY_FILE_RE").search(&what).is_none()));
        let dest = capture_service(p, text).or_else(|| if harvest { p.re("_EXFIL_SERVICE_RE").search(text) } else { None });
        let ip = if dest.is_none() && !in_address { p.re("_PUBLIC_IP_URL_RE").search(text) } else { None };
        if let Some(dest) = dest {
            reasons.push(cat(&[&p.map_text("_IMPORT_SENT_REASONS", kind), &u(" ("), head(dest.group0(), 40), &u(")")]));
        } else if let Some(ip) = ip {
            let g = ip.group0();
            let rest = match pystr::find_str(g, "//", 0) {
                Some(i) => pystr::from(g, i + 2),
                None => g,
            };
            reasons.push(cat(&[&p.map_text("_IMPORT_SENT_IP_REASONS", kind), &u(" ("), rest, &u(")")]));
        } else if harvest && kind != "credentials" {
            reasons.push(u("reads credentials or the whole environment and sends data over the network"));
        }
        if !reasons.is_empty() {
            line = Some(line_of(text, at));
        }
    }
    if has(text, "curl") || has(text, "wget") {
        let mut piped = false;
        for (i, row) in pystr::split_char(text, c('\n')).iter().enumerate() {
            if runs_download_through_shell(p, row) {
                reasons.push(u("runs a downloaded script through a shell"));
                line = line.or(Some(i + 1));
                piped = true;
                break;
            }
        }
        if !piped {
            // (0.1.8) or a command line built in names, handed to an exec call
            let run = cat_reason(p, "run");
            for (at, r) in &flows {
                if pystr::eq(r, "pipes a download into a shell") || *r == run {
                    reasons.push(u("runs a downloaded script through a shell"));
                    line = line.or(Some(line_of(text, *at)));
                    break;
                }
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
    let at = runs_own_source_at(p, text, lang);
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
