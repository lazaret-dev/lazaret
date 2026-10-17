//! Config and data files, read for credentials (BR-7 step 3, 0.1.9; core.scan_config_file, scanner/configsecrets.py
//! and their npm twins until then).
//!
//! A credential is at least as often in a config or data file — .env, JSON, YAML, TOML, INI, .properties, a shell
//! script, a PEM key, a Dockerfile, .npmrc / .pypirc, Terraform variables — as in code. Such a file is read as text
//! and checked by the two credential rules only, never as code, and it counts in no code metric:
//!
//!   S-TOKEN   the provider token formats and private-key blocks of the code rule, on every line, comment lines
//!             included; the AWS documentation key (AKIA…EXAMPLE) and jwt.io's sample token are not reported;
//!   S-SECRET  a key named like a credential whose value is a literal that looks like one, outside comments; a
//!             password in a URL's userinfo; a Slack or Discord webhook; and in a .netrc a password token's value,
//!             unless the entry's login is anonymous FTP's.
//!
//! An editor's or AI agent's settings that run commands get SC-AUTORUN too (autorun.rs) and a CI file its checks
//! (ci/). Suppression markers work in the file's comments, as in code. Every snippet shows a line with the value of
//! every credential-named key redacted. The patterns, sets and rule texts are the pack's (`_CFG_*`).

use crate::autorun::{self, Tree};
use crate::filectx::{FileCtx, Lang};
use crate::findings::{self, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::collections::HashMap;

const fn c(ch: char) -> u32 {
    ch as u32
}

fn any_of(ch: u32, set: &str) -> bool {
    set.chars().any(|x| x as u32 == ch)
}

fn has(list: &[PyStr], x: &[u32]) -> bool {
    list.iter().any(|y| y.as_slice() == x)
}

// ---------------------------------------------------------------- comments

/// Where a line's comment starts: a '#' or '// ' (a space, tab or the end of the line after it: .npmrc's
/// `//registry.invalid/:_authToken=…` is a setting) at the start of a line or after a space or tab, or a ';' at the
/// start of a line — outside '…' and "…" quotes (a backslash escapes in "…"). JSON has none; JSONC, YAML, TOML, INI,
/// .env, .properties, shell and Dockerfiles use these.
fn comment_start(line: &[u32]) -> Option<usize> {
    if !line.iter().any(|&ch| ch == c('#') || ch == c(';')) && !pystr::contains(line, "//") {
        return None;
    }
    let mut quote: Option<u32> = None;
    let mut blank = true; // only spaces and tabs so far
    let (mut i, n) = (0, line.len());
    while i < n {
        let ch = line[i];
        if let Some(q) = quote {
            if ch == c('\\') && q == c('"') {
                i += 2;
                continue;
            }
            if ch == q {
                quote = None;
            }
        } else if ch == c('"') || ch == c('\'') {
            quote = Some(ch);
        } else if (ch == c('#')
            || (ch == c('/') && pystr::starts_with_at(line, i, "//") && line.get(i + 2).map_or(true, |&x| x == c(' ') || x == c('\t'))))
            && (blank || any_of(line[i - 1], " \t"))
        {
            return Some(i);
        } else if ch == c(';') && blank {
            return Some(i);
        }
        if ch != c(' ') && ch != c('\t') {
            blank = false;
        }
        i += 1;
    }
    None
}

/// Absolute (start, end) spans of the comments of a config file.
pub fn comment_spans(content: &[u32]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut pos = 0;
    for line in content.split(|&ch| ch == c('\n')) {
        if let Some(k) = comment_start(line) {
            spans.push((pos + k, pos + line.len()));
        }
        pos += line.len() + 1;
    }
    spans
}

// ---------------------------------------------------------------- S-SECRET

fn unquote(value: &[u32]) -> &[u32] {
    if value.len() >= 2 && value[0] == value[value.len() - 1] && any_of(value[0], "\"'") {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Shannon entropy of `v` in bits per character, its characters counted in the order they first appear.
fn entropy(v: &[u32]) -> f64 {
    let mut order: Vec<u32> = Vec::new();
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for &ch in v {
        let e = counts.entry(ch).or_insert(0);
        if *e == 0 {
            order.push(ch);
        }
        *e += 1;
    }
    let n = v.len() as f64;
    let mut h = 0.0f64;
    for ch in order {
        let q = counts[&ch] as f64 / n;
        h -= q * q.log2();
    }
    h
}

/// A (quoted or bare) value that looks like a credential: at least 8 ASCII characters, no whitespace, letters and
/// something else, not a reference ($VAR, ${…}, {{…}}, %(…)s, @Vault(…)), a YAML anchor or tag, a path, a URL, a name
/// or a placeholder, and not repeating itself (entropy 2.5 bits or more).
pub fn secret_value(p: &Pack, value: &[u32]) -> bool {
    let v = unquote(value);
    if v.len() < 8 || !pystr::is_ascii(v) || v.iter().any(|&ch| pystr::is_space(ch)) || any_of(v[0], "$%<{@!(*&~/.\\#[|>") {
        return false;
    }
    if p.re("_CFG_URL_START_RE").match_(v).is_some()
        || p.re("_CFG_PLACEHOLDER_RE").search(v).is_some()
        || p.re("_CFG_NAME_RE").fullmatch(v).is_some()
    {
        return false;
    }
    let letter = |ch: u32| (c('A')..=c('Z')).contains(&ch) || (c('a')..=c('z')).contains(&ch);
    v.iter().any(|&ch| letter(ch)) && v.iter().any(|&ch| !letter(ch)) && entropy(v) >= 2.5
}

/// A value in code that a credential could be (SECRET-FP, 0.1.9: S-SECRET in code had no test of its value): at
/// least 8 ASCII characters, not a reference, a URL or a placeholder (`_SRC_PLACEHOLDER_RE`: the config reader's
/// placeholders without the words a weak password holds, `secret`, `passw`, `123456`), and not a name: words joined
/// by separators (`_CFG_NAME_RE`: `tapes-gateway`, `KANADE_JWT_SECRET`), a qualified name (`a.b.c`, `a::b::c`) or
/// CamelCase words (`JwtSecret`). A blank is allowed (a passphrase has them: N-24, John, Oct 15); letters alone count
/// in both cases (a key's base64, `MIIEow…`), not in one (a word).
pub fn secret_value_in_code(p: &Pack, value: &[u32]) -> bool {
    let v = value;
    if v.len() < 8 || !pystr::is_ascii(v) || pystr::is_space(v[0]) || any_of(v[0], "$%<{@!(*&~/.\\#[|>") {
        return false;
    }
    if p.re("_CFG_URL_START_RE").match_(v).is_some()
        || p.re("_SRC_PLACEHOLDER_RE").search(v).is_some()
        || p.re("_CFG_NAME_RE").fullmatch(v).is_some()
        || p.re("_SRC_QUALIFIED_NAME_RE").fullmatch(v).is_some()
        || p.re("_SRC_CAMEL_NAME_RE").fullmatch(v).is_some()
    {
        return false;
    }
    let letter = |ch: u32| (c('A')..=c('Z')).contains(&ch) || (c('a')..=c('z')).contains(&ch);
    if !v.iter().any(|&ch| letter(ch)) {
        return false;
    }
    if v.iter().all(|&ch| letter(ch)) {
        let upper = v.iter().any(|&ch| (c('A')..=c('Z')).contains(&ch));
        let lower = v.iter().any(|&ch| (c('a')..=c('z')).contains(&ch));
        return upper && lower && entropy(v) >= 3.0;
    }
    entropy(v) >= 2.5
}

/// A key named like a credential, and not a page cursor's or an anti-CSRF token's.
pub fn secret_key(p: &Pack, key: &[u32]) -> bool {
    p.re("_CFG_SECRET_KEY_RE").search(key).is_some() && p.re("_CFG_NOT_SECRET_KEY_RE").search(key).is_none()
}

/// {line index: columns} of the password values of a .netrc's entries whose login is anonymous FTP's, which S-SECRET
/// does not report. An entry runs from `machine NAME` or `default` to the next one, over as many lines as it takes,
/// its login before or after its password; a `macdef`'s lines, up to an empty one, are not tokens. `code_lines`: the
/// file's lines, comments removed.
fn netrc_anonymous(p: &Pack, code_lines: &[&[u32]]) -> HashMap<usize, Vec<usize>> {
    let anonymous = p.strs("_CFG_NETRC_ANONYMOUS");
    let token_re = p.re("_CFG_NETRC_TOKEN_RE");
    let mut skip: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut login: Option<PyStr> = None;
    let mut passwords: Vec<(usize, usize)> = Vec::new();
    let mut pending: Option<&'static str> = None;
    let mut in_macro = false;
    let close = |login: &Option<PyStr>, passwords: &[(usize, usize)], skip: &mut HashMap<usize, Vec<usize>>| {
        if let Some(l) = login {
            if has(anonymous, &pystr::lower(unquote(l))) {
                for &(i, col) in passwords {
                    let cols = skip.entry(i).or_default();
                    if !cols.contains(&col) {
                        cols.push(col);
                    }
                }
            }
        }
    };
    for (i, line) in code_lines.iter().enumerate() {
        if in_macro {
            in_macro = !pystr::strip(line).is_empty();
            continue;
        }
        for m in token_re.finditer(line) {
            let token = m.group0();
            if let Some(what) = pending.take() {
                match what {
                    "login" => login = Some(token.to_vec()),
                    "password" => passwords.push((i, m.start())),
                    "macdef" => in_macro = true, // (its body is the lines that follow, to an empty one)
                    _ => {}
                }
                if in_macro {
                    break;
                }
                continue;
            }
            if pystr::eq(token, "machine") || pystr::eq(token, "default") {
                close(&login, &passwords, &mut skip);
                login = None;
                passwords.clear();
                pending = if pystr::eq(token, "machine") { Some("machine") } else { None };
            } else if pystr::eq(token, "login") {
                pending = Some("login");
            } else if pystr::eq(token, "password") {
                pending = Some("password");
            } else if pystr::eq(token, "account") {
                pending = Some("account");
            } else if pystr::eq(token, "macdef") {
                pending = Some("macdef");
            }
        }
    }
    close(&login, &passwords, &mut skip);
    skip
}

/// Column of the first credential S-SECRET reports on a config line (its comment text removed). `netrc`: the line is
/// a .netrc's; `skip`: the columns of its password values that are not secrets (netrc_anonymous).
pub fn secret_col(p: &Pack, code: &[u32], netrc: bool, skip: &[usize]) -> Option<usize> {
    if netrc {
        for m in p.re("_CFG_NETRC_PASSWORD_RE").finditer(code) {
            let at = m.start_of(1) as usize;
            if !skip.contains(&at) && secret_value(p, m.group(1).unwrap_or(&[])) {
                return Some(at);
            }
        }
    }
    for m in p.re("_CFG_KV_RE").finditer(code) {
        let value = m.group(3).unwrap_or(&[]);
        if !value.is_empty() && !any_of(value[0], "\"'") {
            let after = &code[m.end_of(3) as usize..];
            if after.first().is_some_and(|&ch| ch == c('{') || ch == c('}')) {
                continue; // part of a template: ${VAR:default}, pre${VAR}
            }
            if m.group(2).is_some_and(|s| pystr::eq(s, ":")) && !pystr::strip(after).is_empty() {
                continue; // a YAML phrase: `key: some words` is all value
            }
        }
        if secret_key(p, m.group(1).unwrap_or(&[])) && secret_value(p, value) {
            return Some(m.start_of(1) as usize);
        }
    }
    if pystr::contains(code, "://") {
        let local = p.strs("_CFG_LOCAL_HOSTS");
        for m in p.re("_CFG_URL_CRED_RE").finditer(code) {
            let (user, password, host) = (m.group(1).unwrap_or(&[]), m.group(2).unwrap_or(&[]), m.group(3).unwrap_or(&[]));
            if password != user && !has(local, &pystr::lower(host)) && secret_value(p, password) {
                return Some(m.start_of(2) as usize);
            }
        }
        if let Some(m) = p.re("_CFG_WEBHOOK_RE").search(code) {
            return Some(m.start());
        }
    }
    None
}

/// `line` with the value of every credential-named key replaced by [redacted] — whatever the value looks like, unless
/// it is a reference or a template ($VAR, {{…}}, <…>, %…): a snippet's context lines are shown only as far as they
/// cannot carry a credential. `netrc`: a .netrc's line, whose password tokens' values are redacted too.
pub fn redact_values(p: &Pack, line: &[u32], netrc: bool) -> PyStr {
    let redacted = u("[redacted]");
    let netrc_line;
    let line: &[u32] = if netrc {
        netrc_line = p.re("_CFG_NETRC_PASSWORD_RE").sub_fn(line, 0, |m| {
            let keep = (m.start_of(1) - m.start_of(0)) as usize;
            pystr::concat(&[&m.group0()[..keep], &redacted])
        });
        &netrc_line
    } else {
        line
    };
    let mut out: PyStr = Vec::new();
    let mut pos = 0;
    let mut any = false;
    for m in p.re("_CFG_KV_RE").finditer(line) {
        let value = unquote(m.group(3).unwrap_or(&[]));
        if !secret_key(p, m.group(1).unwrap_or(&[])) || value.is_empty() || any_of(value[0], "${<%") {
            continue;
        }
        let (a, b) = (m.start_of(3) as usize, m.end_of(3) as usize);
        out.extend_from_slice(&line[pos..a]);
        out.extend_from_slice(&redacted);
        pos = b;
        any = true;
    }
    if !any {
        return line.to_vec();
    }
    out.extend_from_slice(&line[pos..]);
    out
}

// ---------------------------------------------------------------- S-TOKEN in config files

/// The index past what a string or a concatenation puts between a private-key header and its key: blanks, the
/// escapes \n \r \t (with any number of backslashes), backslashes that end the line, quotes and a string's prefix
/// before one (`b"`, `rb'`, `u8"`, Rust's `r#"`), `#`, `+`, `,` and `.`; at the start of a line after the header's, a
/// comment's `*` and `/` too.
fn past_pem_separators(p: &Pack, text: &[u32], mut k: usize, line_start: bool) -> usize {
    let prefix = p.re("_CFG_STRING_PREFIX_RE");
    while k < text.len() {
        let ch = text[k];
        if pystr::is_space(ch) || any_of(ch, "\"'`+,.#") || (line_start && any_of(ch, "*/")) {
            k += 1;
        } else if ch == c('\\') {
            let mut j = k + 1;
            while j < text.len() && text[j] == c('\\') {
                j += 1;
            }
            if j < text.len() && any_of(text[j], "nrt") {
                k = j + 1;
                continue;
            }
            while j < text.len() && pystr::is_space(text[j]) {
                j += 1;
            }
            if j < text.len() {
                break;
            }
            k = j;
        } else {
            match prefix.match_at(text, k as isize, text.len() as isize) {
                Some(m) => k = m.end(),
                None => break,
            }
        }
    }
    k
}

/// A private key begins at `text[k]`: a base64 run of 40 or more characters mixing upper case, lower case and
/// digits, or an encrypted key's "Proc-Type:".
fn key_at(p: &Pack, text: &[u32], k: usize) -> bool {
    if let Some(m) = p.re("_CFG_PEM_BODY_RE").match_at(text, k as isize, text.len() as isize) {
        let run = m.group0();
        let any = |lo: char, hi: char| run.iter().any(|&ch| (c(lo)..=c(hi)).contains(&ch));
        if any('A', 'Z') && any('a', 'z') && any('0', '9') {
            return true;
        }
    }
    pystr::starts_with(&text[k.min(text.len())..], "Proc-Type:")
}

/// A private-key header's key comes right after it (S-TOKEN-PEM), on its line (the header ending at `end`) or, where
/// that line ends with separators, at the start of the first of the `following` lines that holds anything.
pub fn key_follows(p: &Pack, line: &[u32], end: usize, following: &[&[u32]]) -> bool {
    let k = past_pem_separators(p, line, end, false);
    if k < line.len() {
        return key_at(p, line, k);
    }
    for next in following {
        let k = past_pem_separators(p, next, 0, true);
        if k < next.len() {
            return key_at(p, next, k);
        }
    }
    false
}

/// A token-rule match that is a documentation sample: AWS's example access key ids (AKIA…EXAMPLE) and jwt.io's sample
/// token.
pub fn documentation_token(p: &Pack, text: &[u32]) -> bool {
    if pystr::starts_with(text, "AKIA") {
        return pystr::ends_with(text, "EXAMPLE");
    }
    if pystr::starts_with(text, "eyJ") {
        let rest = match text.iter().position(|&ch| ch == c('.')) {
            Some(k) => &text[k + 1..],
            None => &text[text.len()..],
        };
        return rest == p.text("_CFG_JWT_IO_PAYLOAD").as_slice();
    }
    false
}

/// A token-rule match (`line[a..b]`) that is a sample, not a credential (SECRET-FP, 0.1.9): a documentation sample
/// (`documentation_token`); one that says so (`EXAMPLE`, `FAKE`, `DUMMY`, `SAMPLE` in it: AWS's, a secret scanner's own
/// examples, `eyJFAKE…`); and a JWT with no signature, or a word for one (`….SIGNATURE`: a real one is 43 characters
/// or more).
pub fn sample_token(p: &Pack, line: &[u32], a: usize, b: usize) -> bool {
    let text = &line[a..b];
    if documentation_token(p, text) {
        return true;
    }
    if pystr::starts_with(text, "-----BEGIN") {
        return false;
    }
    let lower = pystr::to_string(text).to_ascii_lowercase();
    if ["example", "fake", "dummy", "sample"].iter().any(|w| lower.contains(w)) {
        return true;
    }
    if pystr::starts_with(text, "eyJ") {
        let sig = if line.get(b) == Some(&c('.')) {
            let rest = &line[b + 1..];
            let n = rest.iter().take_while(|&&ch| matches!(char::from_u32(ch), Some('A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-'))).count();
            &rest[..n]
        } else {
            &line[b..b]
        };
        return sig.len() < 16 || sig.iter().all(|&ch| matches!(char::from_u32(ch), Some('A'..='Z' | 'a'..='z')));
    }
    false
}

/// The S-TOKEN rule and its matcher.
fn token_rule(p: &Pack) -> &crate::scanfile::Rule {
    crate::scanfile::rules(p).iter().find(|r| pystr::eq(&r.text.id, "S-TOKEN")).expect("the pack has S-TOKEN")
}

/// Column of the first S-TOKEN match on a config line that is reported: not a documentation sample, and a private-key
/// header only with its key right after it, on the line or at the start of the next two (key_follows).
fn token_col(p: &Pack, lines: &[&[u32]], i: usize) -> Option<usize> {
    let line = lines[i];
    let following: Vec<&[u32]> = lines[(i + 1).min(lines.len())..(i + 3).min(lines.len())].to_vec();
    let rule = token_rule(p);
    let spans: Vec<(usize, usize)> = match &rule.re {
        crate::scanfile::Matcher::Token(t) => t.iter(line, 0).collect(),
        other => other.search(line).into_iter().collect(),
    };
    for (a, b) in spans {
        let text = &line[a..b];
        if sample_token(p, line, a, b) {
            continue;
        }
        if pystr::starts_with(text, "-----BEGIN") && !key_follows(p, line, b, &following) {
            continue;
        }
        return Some(a);
    }
    None
}

// ---------------------------------------------------------------- the scan

/// Is this the name of a .netrc (curl's, git's, pip's and ftp's credentials; _netrc on Windows)?
fn is_netrc(p: &Pack, path: &[u32]) -> bool {
    let p2 = pystr::replace_char(path, c('\\'), c('/'));
    let base = p2.rsplit(|&ch| ch == c('/')).next().unwrap_or(&[]);
    has(p.strs("_CFG_NETRC_NAMES"), &pystr::lower(base))
}

pub struct Options {
    /// Snippets and messages redacted (core.REDACT_SECRETS).
    pub redact: bool,
    /// This Python's sum() adds floats with Neumaier's compensation (the entropy literals' test).
    pub neumaier: bool,
}

/// The issues of a config or data file at `path` (core.scan_config_file): SC-AUTORUN for an editor's or agent's
/// settings, a CI file's checks, S-TOKEN and S-SECRET, those no marker suppresses, capped, as scan_file answers them;
/// or Err(need): the files of the tree a settings file's commands run, still to be read (`tree`).
pub fn scan(p: &Pack, path: &[u32], text: &[u32], opts: &Options, tree: &mut Tree) -> Result<Vec<Value>, Vec<PyStr>> {
    let ctx = FileCtx::new(p, text, Lang::Cfg, false);
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
    let netrc = is_netrc(p, path);
    let mut found: Vec<Finding> = Vec::new();
    if autorun::config_kind(path).is_some() {
        for (line, r) in autorun::issues(p, path, &ctx.content, tree)? {
            found.push(Finding::new(r, line, None));
        }
    }
    for (line, r) in crate::ci::issues(p, path, &ctx.content) {
        found.push(Finding::new(r, line, None));
    }
    let codes: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.code(i)).collect();
    let anonymous = if netrc { netrc_anonymous(p, &codes) } else { HashMap::new() };
    let token = RuleText::clone(&token_rule(p).text);
    let secret = RuleText::of(p, "CONFIG_SECRET_RULE");
    let hint = p.re("_CFG_SECRET_KV_HINT_RE");
    for i in 0..lines.len() {
        let line = lines[i];
        if line.iter().all(|&ch| pystr::is_space(ch)) {
            continue;
        }
        if let Some(col) = token_col(p, &lines, i) {
            found.push(Finding::new(token.clone(), i + 1, Some(col)));
        }
        let code = codes[i];
        if !ctx.cmask[i] && (netrc || hint.search(&pystr::lower(code)).is_some() || pystr::contains(code, "://")) {
            let skip = anonymous.get(&i).map(|v| v.as_slice()).unwrap_or(&[]);
            if let Some(col) = secret_col(p, code, netrc, skip) {
                found.push(Finding::new(secret.clone(), i + 1, Some(col)));
            }
        }
    }
    let found = crate::project::unsuppressed(&ctx, found);
    let snippets = Snippets::new(p, lines, opts.redact, opts.neumaier).config(netrc);
    let found = findings::cap(p, &snippets, found);
    Ok(found.iter().map(|f| snippets.issue(f)).collect())
}
