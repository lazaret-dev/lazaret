//! AI-agent skill and instruction files, read for what they tell the agent to do (RA-3, 0.1.9). These are
//! markdown or plain-text files an agent reads as instructions (`is_agent_doc`): `SKILL.md`, `AGENTS.md`,
//! `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `.github/copilot-instructions.md`,
//! `.github/instructions/**/*.instructions.md`, `.claude/commands/**/*.md`, `.claude/agents/**/*.md`,
//! `.cursorrules`, `.cursor/rules/**/*.md|*.mdc`, `.windsurfrules`, `.windsurf/rules/**/*.md` and `.clinerules` (a
//! file, or a folder of them). A dependency ships one so the agent runs its commands; the clawdhub / ClawHavoc
//! campaign (Snyk, Feb 2026) used a `SKILL.md` as a lure that pointed the agent at an external snippet which decoded
//! base64 into a shell and fetched a second stage from a raw IP, with a password-protected archive to hide the
//! payload from scanners.
//!
//! The reading, in one SC-AGENT-SKILL finding (nothing for a clean file — a benign skill's `npm install` block is
//! no reason):
//! - the commands it tells the agent to run — fenced shell, PowerShell and cmd blocks, unlabeled and `text` blocks
//!   (whatever their lines look like), indented code blocks, inline code spans, and the text of HTML comments
//!   (hidden from a human reader) — each read with the hook-command test (`shell::hook_command_risk`), a block
//!   longer than HOOK_MAX_CHARS in pieces cut at line ends; fenced Python and JavaScript/TypeScript blocks with the
//!   install-script test in their language;
//! - a script of the skill's own folder that such a command runs (with an interpreter and its flags, `uv run`,
//!   `. x.sh` / `source x.sh`, `./x.sh`, a bare `scripts/x.sh`, after a `cd`), followed and read with the
//!   install-script test in its language (a .rb or .pl script as text, not as JavaScript);
//! - an install from a password-protected archive (a download and a stated password in one paragraph);
//! - a paste or snippet host, or a public raw IP address, it points the agent at (loopback and private addresses
//!   are no install source, there or in a command's reasons);
//! - text hidden from a human reader: invisible carrier characters (`scanfile::hidden_unicode_run`), a run of
//!   zero-width characters, or bidirectional controls;
//! - an instruction to send the conversation, the environment or credentials out, unless it is negated ("do not
//!   send credentials …"): with an address in the same paragraph a hostile shape, without one a weaker indicator.
//!
//! How much it counts depends on whose file it is (`dep`). A dependency's (a `--deps` tree's, a registry package's)
//! is CRITICAL for a hostile shape and MAJOR for a weaker indicator; the project's own is INFO, listed with what was
//! found but never failing the gate (its own instructions are the developers' to keep: a CLAUDE.md that installs
//! rustup is not an attack on them).
//!
//! The patterns, host list and rule text are the pack's (`_AGENTDOC_*`). Both packages read this through the
//! engine (the `agentdoc_issues` call and the config scan); nothing in the file is fetched or run.

use crate::findings::{self, Arg, RuleText};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};

const fn c(ch: char) -> u32 {
    ch as u32
}

const SHOW: usize = 120; // characters of a command shown in a message
/// The exfiltration orders (and the password statements) looked at, at most: a file that repeats one is read for
/// its first ones.
const ORDERS_MAX: usize = 64;

/// The kind of agent file `path` is (a label for the message), or None. '/'- or '\\'-separated, any case.
pub fn is_agent_doc(path: &[u32]) -> Option<&'static str> {
    let p = pystr::replace_char(path, c('\\'), c('/'));
    let parts: Vec<PyStr> = pystr::split_char(&p, c('/')).iter().map(|x| pystr::lower(x)).collect();
    let n = parts.len();
    let name: &[u32] = parts.last().map(|x| x.as_slice()).unwrap_or(&[]);
    let dirs = &parts[..n.saturating_sub(1)];
    let is = |s: &str| pystr::eq(name, s);
    // `a/b` among the folders above the file (at any depth: rules and commands may be grouped in subfolders)
    let below = |a: &str, b: &str| (0..dirs.len().saturating_sub(1)).any(|k| pystr::eq(&dirs[k], a) && pystr::eq(&dirs[k + 1], b));
    let md = pystr::ends_with(name, ".md");
    let mdc = pystr::ends_with(name, ".mdc");
    if is("skill.md") {
        Some("agent skill")
    } else if is("agents.md") || is("claude.md") || is("claude.local.md") || is("gemini.md") || is("copilot-instructions.md")
        || (pystr::ends_with(name, ".instructions.md") && below(".github", "instructions"))
    {
        Some("agent instructions")
    } else if md && below(".claude", "commands") {
        Some("agent command")
    } else if md && below(".claude", "agents") {
        Some("agent definition")
    } else if is(".cursorrules") || is(".windsurfrules") || is(".clinerules")
        || (dirs.last().is_some_and(|d| pystr::eq(d, ".cursor")) && (is("rules") || mdc))
        || ((md || mdc) && below(".cursor", "rules"))
        || (md && below(".windsurf", "rules"))
        || ((md || mdc || pystr::ends_with(name, ".txt")) && dirs.iter().any(|d| pystr::eq(d, ".clinerules")))
    {
        Some("editor rules")
    } else {
        None
    }
}

fn dirname(path: &[u32]) -> PyStr {
    let p = pystr::replace_char(path, c('\\'), c('/'));
    match p.iter().rposition(|&ch| ch == c('/')) {
        Some(k) => p[..k].to_vec(),
        None => Vec::new(),
    }
}

fn shown(cmd: &[u32]) -> PyStr {
    let one: PyStr = cmd.iter().map(|&ch| if ch == c('\n') || ch == c('\t') { c(' ') } else { ch }).collect();
    let one = pystr::strip(&one).to_vec();
    if one.len() <= SHOW {
        one
    } else {
        pystr::concat(&[&one[..SHOW], &[0x2026]])
    }
}

/// How a candidate is read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    /// as commands: the hook-command test
    Command,
    /// as a script in this language ("py", "js"): the install-script test
    Code(&'static str),
}

/// A code candidate the file hands the agent: (1-based line it is reported at — a fenced block's opening fence —,
/// the 1-based line of its text's first line, the text, whether it was hidden from a human reader, how it is read).
struct Candidate {
    line: usize,
    first: usize,
    text: PyStr,
    hidden: bool,
    reader: Reader,
}

/// How a fenced block with this info string (its first word, lowercased) is read, or None when it is not read (a
/// data format, another language). No info string, or `text`, is read as commands whatever its lines look like.
fn block_reader(lang: &[u32]) -> Option<Reader> {
    const COMMANDS: &[&str] = &["", "sh", "bash", "zsh", "shell", "console", "shell-session", "sh-session", "bash-session",
        "shellsession", "ksh", "dash", "fish", "command", "terminal", "text", "txt", "plain", "plaintext",
        "powershell", "pwsh", "ps1", "ps", "posh", "cmd", "bat", "batch", "dos"];
    const PY: &[&str] = &["python", "py", "python3", "py3"];
    const JS: &[&str] = &["js", "javascript", "node", "nodejs", "mjs", "cjs", "jsx", "ts", "typescript", "tsx", "mts", "cts"];
    let is = |set: &[&str]| set.iter().any(|s| pystr::eq(lang, s));
    if is(COMMANDS) {
        Some(Reader::Command)
    } else if is(PY) {
        Some(Reader::Code("py"))
    } else if is(JS) {
        Some(Reader::Code("js"))
    } else {
        None
    }
}

fn blank(line: &[u32]) -> bool {
    line.iter().all(|&ch| pystr::is_space(ch))
}

/// The text of an indented code block's line (four spaces or a tab, removed), or None for a line that is not one.
fn indented(line: &[u32]) -> Option<&[u32]> {
    if line.first() == Some(&c('\t')) {
        Some(&line[1..])
    } else if line.len() >= 4 && line[..4].iter().all(|&ch| ch == c(' ')) {
        Some(&line[4..])
    } else {
        None
    }
}

/// The fenced and indented code blocks, inline code spans and HTML-comment bodies of a markdown/plain instruction
/// file.
fn candidates(p: &Pack, text: &[u32]) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let lines: Vec<&[u32]> = pystr::split_char(text, c('\n'));
    let mut i = 0;
    let mut prev_blank = true;
    let mut inline_lines: Vec<(usize, &[u32])> = Vec::new();
    while i < lines.len() {
        let stripped = pystr::strip(lines[i]);
        if let Some((ch, count, lang)) = fence_open(stripped) {
            // a fenced code block
            let start = i + 1;
            let mut body: Vec<&[u32]> = Vec::new();
            i += 1;
            while i < lines.len() {
                if fence_close(pystr::strip(lines[i]), ch, count) {
                    break;
                }
                body.push(lines[i]);
                i += 1;
            }
            i += 1; // past the closing fence
            if let Some(reader) = block_reader(&lang) {
                out.push(Candidate { line: start, first: start + 1, text: pystr::join(&u("\n"), &body), hidden: false, reader });
            }
            prev_blank = false;
            continue;
        }
        if prev_blank && !blank(lines[i]) && indented(lines[i]).is_some() {
            // an indented code block: indented lines (and blank ones between them) after a blank line
            let start = i;
            let mut body: Vec<&[u32]> = Vec::new();
            while i < lines.len() && fence_open(pystr::strip(lines[i])).is_none() {
                match indented(lines[i]) {
                    Some(rest) => body.push(rest),
                    None if blank(lines[i]) => body.push(&[]),
                    None => break,
                }
                i += 1;
            }
            while body.last().is_some_and(|l| blank(l)) {
                body.pop();
                i -= 1;
            }
            out.push(Candidate { line: start + 1, first: start + 1, text: pystr::join(&u("\n"), &body), hidden: false, reader: Reader::Command });
            prev_blank = false;
            continue;
        }
        prev_blank = blank(lines[i]);
        inline_lines.push((i + 1, lines[i]));
        i += 1;
    }
    // inline code spans, outside the blocks
    let span = p.re("_AGENTDOC_INLINE_RE");
    for (ln, line) in &inline_lines {
        for m in span.finditer(line) {
            if let Some(g) = m.group(1) {
                if !g.is_empty() {
                    out.push(Candidate { line: *ln, first: *ln, text: g.to_vec(), hidden: false, reader: Reader::Command });
                }
            }
        }
    }
    // HTML comment bodies (hidden from a human reader), possibly spanning lines
    for (start, inner) in html_comments(text) {
        let line = line_of(text, start);
        out.push(Candidate { line, first: line, text: inner, hidden: true, reader: Reader::Command });
    }
    out
}

/// `(fence char, count, info string's first word lowercased)` when `stripped` opens a code fence (``` or ~~~, 3+),
/// else None.
fn fence_open(stripped: &[u32]) -> Option<(u32, usize, PyStr)> {
    let ch = *stripped.first()?;
    if ch != c('`') && ch != c('~') {
        return None;
    }
    let count = stripped.iter().take_while(|&&x| x == ch).count();
    if count < 3 {
        return None;
    }
    let info = pystr::strip(&stripped[count..]);
    // a ``` info string may not itself contain a backtick
    if ch == c('`') && info.contains(&c('`')) {
        return None;
    }
    let word: PyStr = info.iter().take_while(|&&x| x != c(' ') && x != c('\t') && x != c(',') && x != c('{')).copied().collect();
    Some((ch, count, pystr::lower(&word)))
}

fn fence_close(stripped: &[u32], ch: u32, count: usize) -> bool {
    stripped.len() >= count && stripped.iter().all(|&x| x == ch) && stripped.len() >= 3
}

/// The HTML comments of `text`: (start offset, inner text). `<!-- … -->`, the longest that closes.
fn html_comments(text: &[u32]) -> Vec<(usize, PyStr)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= text.len() {
        if pystr::starts_with_at(text, i, "<!--") {
            let from = i + 4;
            let end = find_str(text, "-->", from);
            let stop = end.unwrap_or(text.len());
            out.push((i, text[from..stop].to_vec()));
            i = end.map(|e| e + 3).unwrap_or(text.len());
        } else {
            i += 1;
        }
    }
    out
}

fn find_str(text: &[u32], needle: &str, from: usize) -> Option<usize> {
    let n: Vec<u32> = needle.chars().map(|x| x as u32).collect();
    if n.is_empty() || from >= text.len() {
        return None;
    }
    (from..=text.len().saturating_sub(n.len())).find(|&i| text[i..i + n.len()] == n[..])
}

fn line_of(text: &[u32], offset: usize) -> usize {
    1 + text[..offset.min(text.len())].iter().filter(|&&ch| ch == c('\n')).count()
}

/// The first `n` characters of `s`, with an ellipsis when it is longer.
fn head(s: &[u32], n: usize) -> PyStr {
    if s.len() <= n {
        s.to_vec()
    } else {
        pystr::concat(&[&s[..n], &[0x2026]])
    }
}

/// `text` in pieces of at most `max` characters, cut at line ends (a line longer than that alone, in pieces of its
/// own): (lines before the piece, the piece). A block longer than the hook-command test reads is read this way.
fn pieces(text: &[u32], max: usize) -> Vec<(usize, PyStr)> {
    if text.len() <= max {
        return vec![(0, text.to_vec())];
    }
    let mut out: Vec<(usize, PyStr)> = Vec::new();
    let mut cur: PyStr = Vec::new();
    let mut cur_line = 0usize;
    for (k, line) in pystr::split_char(text, c('\n')).into_iter().enumerate() {
        if line.len() > max {
            if !cur.is_empty() {
                out.push((cur_line, std::mem::take(&mut cur)));
            }
            out.extend(line.chunks(max).map(|piece| (k, piece.to_vec())));
            continue;
        }
        if !cur.is_empty() && cur.len() + 1 + line.len() > max {
            out.push((cur_line, std::mem::take(&mut cur)));
        }
        if cur.is_empty() {
            cur_line = k;
        } else {
            cur.push(c('\n'));
        }
        cur.extend_from_slice(line);
    }
    if !cur.is_empty() {
        out.push((cur_line, cur));
    }
    out
}

/// The paragraphs of a text: the offsets where each starts (a paragraph is a run of lines between blank lines; a
/// blank line belongs to the paragraph before it).
struct Paragraphs {
    starts: Vec<usize>,
    len: usize,
}

impl Paragraphs {
    fn new(text: &[u32]) -> Paragraphs {
        let mut starts = vec![0usize];
        let mut off = 0usize;
        let mut after_blank = false;
        for line in pystr::split_char(text, c('\n')) {
            let is_blank = blank(line);
            if after_blank && !is_blank {
                starts.push(off);
            }
            after_blank = is_blank;
            off += line.len() + 1;
        }
        Paragraphs { starts, len: text.len() }
    }

    /// (its index, start, end) of the paragraph that holds offset `at`.
    fn around(&self, at: usize) -> (usize, usize, usize) {
        let k = self.starts.partition_point(|&s| s <= at).saturating_sub(1);
        let end = self.starts.get(k + 1).copied().unwrap_or(self.len).min(self.len);
        (k, self.starts[k], end)
    }
}

/// The IPv4 address of `s` when it is one, written alone or as a URL's host (`http://10.0.0.5`).
fn ipv4_of(s: &[u32]) -> Option<PyStr> {
    let low = pystr::lower(s);
    let rest: &[u32] = match low.iter().position(|&ch| ch == c(':')) {
        Some(k) if pystr::starts_with_at(&low, k, "://") => &low[k + 3..],
        _ => &low,
    };
    let host: PyStr = rest.iter().take_while(|&&ch| ch != c('/') && ch != c(':') && ch != c('?') && ch != c('#')).copied().collect();
    let parts = pystr::split_char(&host, c('.'));
    (parts.len() == 4 && parts.iter().all(|o| !o.is_empty() && o.len() <= 3 && o.iter().all(|&d| (0x30..=0x39).contains(&d)))).then_some(host)
}

/// Is a URL's host this machine or a private network: localhost, a loopback, private, link-local or unspecified
/// IPv4 address (`crate::signs::public_ipv4`), `[::1]` or `[::]`?
fn local_url(url: &[u32]) -> bool {
    let low = pystr::lower(url);
    let rest: &[u32] = match low.iter().position(|&ch| ch == c(':')) {
        Some(k) if pystr::starts_with_at(&low, k, "://") => &low[k + 3..],
        _ => return false,
    };
    let rest: &[u32] = match rest.iter().position(|&ch| ch == c('@')) {
        Some(k) if !rest[..k].contains(&c('/')) => &rest[k + 1..],
        _ => rest,
    };
    if pystr::starts_with(rest, "[::1]") || pystr::starts_with(rest, "[::]") {
        return true;
    }
    let host: PyStr = rest.iter().take_while(|&&ch| ch != c('/') && ch != c(':') && ch != c('?') && ch != c('#')).copied().collect();
    if pystr::eq(&host, "localhost") || pystr::ends_with(&host, ".localhost") {
        return true;
    }
    ipv4_of(&host).is_some_and(|ip| !crate::signs::public_ipv4(&ip))
}

/// The first raw-IP URL of `text` whose address is public: (its offset, its first characters).
fn public_ip_url(p: &Pack, text: &[u32]) -> Option<(usize, PyStr)> {
    p.re("_RAW_IP_URL_RE")
        .finditer(text)
        .find(|m| ipv4_of(m.group0()).is_some_and(|ip| crate::signs::public_ipv4(&ip)))
        .map(|m| (m.start(), head(m.group0(), 40)))
}

/// The hook-command or install-script test's reasons with those that only contact a loopback or private address
/// taken out (a dev server is no exfiltration endpoint), and the first public raw-IP URL of `text` named instead
/// when there is one (the tests name only the first address they meet).
fn without_local_addresses(p: &Pack, text: &[u32], reasons: Vec<PyStr>) -> Vec<PyStr> {
    let lead = u("contacts an address typical of data exfiltration (");
    let mut out = Vec::new();
    let mut dropped = false;
    for r in reasons {
        if r.starts_with(&lead) && r.last() == Some(&c(')')) {
            if let Some(ip) = ipv4_of(&r[lead.len()..r.len() - 1]) {
                if !crate::signs::public_ipv4(&ip) {
                    dropped = true;
                    continue;
                }
            }
        }
        out.push(r);
    }
    if dropped {
        if let Some((_, url)) = public_ip_url(p, text) {
            let r = pystr::concat(&[&lead, &url, &u(")")]);
            if !out.contains(&r) {
                out.push(r);
            }
        }
    }
    out
}

/// The hook-command test's reasons for a command (or block of commands), loopback and private addresses aside.
fn command_risk(p: &Pack, cmd: &[u32]) -> Vec<PyStr> {
    without_local_addresses(p, cmd, crate::shell::hook_command_risk(p, cmd, false))
}

/// For a block of commands longer than a message shows (SHOW): (its index, the line) of its first line the
/// hook-command test finds hostile on its own, or None (a block shorter than that, or whose reasons span lines).
fn hostile_line(p: &Pack, block: &[u32]) -> Option<(usize, PyStr)> {
    if block.len() <= SHOW {
        return None;
    }
    pystr::split_char(block, c('\n'))
        .into_iter()
        .enumerate()
        .find(|(_, line)| !blank(line) && !command_risk(p, line).is_empty())
        .map(|(k, line)| (k, line.to_vec()))
}

/// The install-script test's reasons for a script or code block in `lang` (None: read as text, as a shell script
/// is), loopback and private addresses aside.
fn script_risk(p: &Pack, text: &[u32], lang: Option<&str>) -> Vec<PyStr> {
    without_local_addresses(p, text, crate::signs::install_script_risk(p, text, lang))
}

/// A finding reason: (1-based line, whether it is a hostile shape, the phrase for the message).
struct Reason {
    line: usize,
    strong: bool,
    phrase: PyStr,
}

fn said(risk: &[PyStr]) -> PyStr {
    let refs: Vec<&[u32]> = risk.iter().map(|x| x.as_slice()).collect();
    pystr::join(&u("; and "), &refs)
}

/// Is the order whose verb starts at `at` negated ("do not send", "never upload", "don't share")? The words before
/// it in its sentence are read.
fn negated(p: &Pack, text: &[u32], at: usize) -> bool {
    let from = at.saturating_sub(60);
    let start = text[from..at]
        .iter()
        .rposition(|&ch| [c('.'), c('!'), c('?'), c(';'), c(':'), c('\n')].contains(&ch))
        .map(|k| from + k + 1)
        .unwrap_or(from);
    p.re("_AGENTDOC_NEGATION_RE").search(&text[start..at]).is_some()
}

/// The address a send order names in its paragraph: a data-capture service, a public raw IP (a URL, or one a raw
/// socket is opened to), an exfiltration service, else any URL that is not this machine's or a private network's.
fn exfil_address(p: &Pack, para: &[u32]) -> Option<PyStr> {
    if let Some(m) = crate::signs::capture_service(p, para) {
        return Some(m.group0().to_vec());
    }
    if let Some((_, url)) = public_ip_url(p, para) {
        return Some(url);
    }
    if let Some(ip) = crate::signs::raw_ip_connect(p, para).filter(|ip| crate::signs::public_ipv4(ip)) {
        return Some(ip);
    }
    if let Some(m) = p.re("_EXFIL_SERVICE_RE").search(para) {
        return Some(m.group0().to_vec());
    }
    p.re("_AGENTDOC_URL_RE").finditer(para).find(|m| !local_url(m.group0())).map(|m| m.group0().to_vec())
}

/// RA-3: the SC-AGENT-SKILL finding(s) for an agent skill or instruction file, or [] for a clean one. `dep`: the file
/// is a dependency's (a `--deps` tree's, a registry package's: CRITICAL or MAJOR), not the project's own (INFO).
/// `tree` follows a script of the skill's own folder that a command runs (the need-protocol, as autorun::issues).
pub fn issues(
    p: &Pack,
    path: &[u32],
    text: &[u32],
    tree: &mut crate::autorun::Tree,
    dep: bool,
) -> Result<Vec<(usize, RuleText)>, Vec<PyStr>> {
    let kind = match is_agent_doc(path) {
        Some(k) => k,
        None => return Ok(Vec::new()),
    };
    let base = dirname(path);
    let max = p.usize("HOOK_MAX_CHARS").max(1);
    let mut reasons: Vec<Reason> = Vec::new();

    // 1) commands and code the file tells the agent to run (and the local scripts the commands run)
    for cand in candidates(p, text) {
        match cand.reader {
            Reader::Code(lang) => {
                let risk = script_risk(p, &cand.text, Some(lang));
                if !risk.is_empty() {
                    reasons.push(Reason {
                        line: cand.line,
                        strong: crate::signs::strong_install_reasons(p, &risk),
                        phrase: pystr::concat(&[&u("tells the agent to run code that "), &said(&risk), &u(" (`"), &shown(&cand.text), &u("`)")]),
                    });
                }
            }
            Reader::Command => {
                let lead = if cand.hidden {
                    u("hides a command from a human reader that ")
                } else {
                    u("tells the agent to run a command that ")
                };
                for (before, piece) in pieces(&cand.text, max) {
                    let risk = command_risk(p, &piece);
                    if !risk.is_empty() {
                        // (a block longer than a message shows: the line that reads hostile on its own, when one does)
                        let (at, what) = match hostile_line(p, &piece) {
                            Some((k, l)) => (cand.first + before + k, l),
                            None => (if before == 0 { cand.line } else { cand.first + before }, piece.clone()),
                        };
                        reasons.push(Reason {
                            line: at,
                            strong: crate::signs::strong_install_reasons(p, &risk),
                            phrase: pystr::concat(&[&lead, &said(&risk), &u(" (`"), &shown(&what), &u("`)")]),
                        });
                    }
                }
                // a local script a command runs, followed and read as an install script (only when following)
                if !tree.follow {
                    continue;
                }
                for (target, joined) in local_scripts(p, &cand.text) {
                    let Some(rel) = crate::autorun::tree_join(&base, &joined) else { continue };
                    if let Some(t) = tree.read(&rel) {
                        let risk = script_risk(p, &t, crate::deps::script_lang(p, &rel, &t));
                        if !risk.is_empty() {
                            reasons.push(Reason {
                                line: cand.line,
                                strong: crate::signs::strong_install_reasons(p, &risk),
                                phrase: pystr::concat(&[&u("points the agent at "), &target, &u(", which "), &said(&risk)]),
                            });
                        }
                    }
                }
            }
        }
    }

    let paras = Paragraphs::new(text);

    // 2) a password-protected archive install (hides its contents from scanners): a download and a stated password
    //    in one paragraph
    let archive_paras: std::collections::HashSet<usize> =
        p.re("_AGENTDOC_ARCHIVE_RE").finditer(text).map(|m| paras.around(m.start()).0).collect();
    if !archive_paras.is_empty() {
        for m in p.re("_AGENTDOC_PASSWORD_RE").finditer(text).take(ORDERS_MAX) {
            if archive_paras.contains(&paras.around(m.start()).0) {
                reasons.push(Reason {
                    line: line_of(text, m.start()),
                    strong: true,
                    phrase: u("installs from a password-protected archive, which hides its contents from scanners"),
                });
                break;
            }
        }
    }

    // 3) an instruction to send the conversation, the environment or credentials out (not a negated one), to an
    //    address in its paragraph
    let mut weak_order: Option<Reason> = None;
    let mut addresses: std::collections::HashMap<usize, Option<PyStr>> = std::collections::HashMap::new();
    for m in p.re("_AGENTDOC_EXFIL_RE").finditer(text).take(ORDERS_MAX) {
        if negated(p, text, m.start()) {
            continue;
        }
        let (k, a, b) = paras.around(m.start());
        let addr = addresses.entry(k).or_insert_with(|| exfil_address(p, &text[a..b])).clone();
        let what = shown(m.group0());
        match addr {
            Some(a) => {
                reasons.push(Reason {
                    line: line_of(text, m.start()),
                    strong: true,
                    phrase: pystr::concat(&[&u("tells the agent to send data out ("), &what, &u(" \u{2192} "), &head(&a, 40), &u(")")]),
                });
                weak_order = None;
                break;
            }
            None => {
                if weak_order.is_none() {
                    weak_order = Some(Reason {
                        line: line_of(text, m.start()),
                        strong: false,
                        phrase: pystr::concat(&[&u("tells the agent to send data out ("), &what, &u(")")]),
                    });
                }
            }
        }
    }
    reasons.extend(weak_order);

    // 4) a paste/snippet host, or a public raw IP address, it points the agent at
    if let Some(m) = p.re("_AGENTDOC_PASTE_RE").search(text) {
        reasons.push(Reason { line: line_of(text, m.start()), strong: false, phrase: pystr::concat(&[&u("points the agent at a paste or snippet host ("), &head(m.group0(), 40), &u(")")]) });
    }
    let ip = public_ip_url(p, text).or_else(|| {
        crate::signs::raw_ip_connect(p, text)
            .filter(|ip| crate::signs::public_ipv4(ip))
            .map(|ip| (pystr::find(text, &ip, 0).unwrap_or(0), head(&ip, 40)))
    });
    if let Some((at, shown_ip)) = ip {
        reasons.push(Reason { line: line_of(text, at), strong: false, phrase: pystr::concat(&[&u("points the agent at a raw IP address ("), &shown_ip, &u(")")]) });
    }

    // 5) text hidden from a human reader: invisible carriers, a run of zero-width characters, bidirectional controls
    let zero_width = p.re("_AGENTDOC_ZERO_WIDTH_RE");
    let bidi = p.re("_AGENTDOC_BIDI_RE");
    let (mut invisible, mut reordered) = (false, false);
    for (i, line) in pystr::split_char(text, c('\n')).iter().enumerate() {
        if !invisible && (crate::scanfile::hidden_unicode_run(p, line).is_some() || zero_width.search(line).is_some()) {
            reasons.push(Reason { line: i + 1, strong: false, phrase: u("hides text from a human reader with invisible characters") });
            invisible = true;
        }
        if !reordered && bidi.search(line).is_some() {
            reasons.push(Reason { line: i + 1, strong: false, phrase: u("hides text from a human reader with bidirectional control characters") });
            reordered = true;
        }
        if invisible && reordered {
            break;
        }
    }

    if !tree.need.is_empty() {
        return Err(std::mem::take(&mut tree.need));
    }
    if reasons.is_empty() {
        return Ok(Vec::new());
    }
    // one finding: strong if any reason is a hostile shape, at the first such reason's line
    let strong = reasons.iter().any(|r| r.strong);
    let mut chosen: Vec<&Reason> = Vec::new();
    for r in reasons.iter().filter(|r| r.strong == strong) {
        if !chosen.iter().any(|x| x.phrase == r.phrase) {
            chosen.push(r);
        }
    }
    let line = chosen.first().map(|r| r.line).unwrap_or(1);
    let refs: Vec<&[u32]> = chosen.iter().map(|r| r.phrase.as_slice()).collect();
    let said = pystr::join(&u("; and "), &refs);
    let mut rule = RuleText::of(p, "_AGENTDOC_RULE");
    let args = [("kind", Arg::S(u(kind))), ("said", Arg::S(said))];
    if dep {
        rule.msg = findings::format(&rule.msg, &args);
        rule.sev = u(if strong { "CRITICAL" } else { "MAJOR" });
    } else {
        // the project's own instructions: listed with what was found, never counted (INFO)
        rule.msg = findings::format(&p.text("_AGENTDOC_OWN_MSG"), &args);
        rule.sev = u("INFO");
        rule.fix = p.text("_AGENTDOC_OWN_FIX");
    }
    Ok(vec![(line, rule)])
}

/// The local scripts a command runs, for following: (the path as written, the path below the file's folder after
/// the `cd`s before it). A script named after an interpreter (and its flags: `bash -e`, `python3 -u`, `uv run`,
/// `npx tsx`, `pwsh -File`, `.`, `source`) or as `./x`, any of .sh .bash .py .js .mjs .cjs .ts .mts .cts .ps1 .rb
/// .pl; a bare path at a command's place only for a shell or PowerShell script (`scripts/x.sh`). A `cd` to a folder
/// that is not relative (`/tmp`, `~`, `$X`, `-`) leaves the scripts after it unfollowed.
fn local_scripts(p: &Pack, cmd: &[u32]) -> Vec<(PyStr, PyStr)> {
    let cds: Vec<(usize, PyStr)> = p.re("_AGENTDOC_CD_RE")
        .finditer(cmd)
        .filter_map(|m| m.group(1).map(|d| (m.end(), d.to_vec())))
        .collect();
    let mut out: Vec<(PyStr, PyStr)> = Vec::new();
    for m in p.re("_AGENTDOC_LOCAL_SCRIPT_RE").finditer(cmd) {
        let Some(path) = m.group(1).or_else(|| m.group(2)).or_else(|| m.group(3)) else { continue };
        if path.is_empty() {
            continue;
        }
        let mut dir: Option<PyStr> = Some(Vec::new());
        for (end, d) in &cds {
            if *end <= m.start() {
                dir = dir.and_then(|cur| cd_into(&cur, d));
            }
        }
        let Some(dir) = dir else { continue };
        let path = pystr::replace_char(path, c('\\'), c('/'));
        let joined = if dir.is_empty() { path.clone() } else { pystr::concat(&[&dir, &u("/"), &path]) };
        if !out.iter().any(|(_, j)| *j == joined) {
            out.push((path, joined));
        }
    }
    out
}

/// The folder after `cd d` from `cur` (both relative to the file's folder), or None when `d` is not relative.
fn cd_into(cur: &[u32], d: &[u32]) -> Option<PyStr> {
    let d = pystr::replace_char(d, c('\\'), c('/'));
    let first = *d.first()?;
    if [c('/'), c('~'), c('$'), c('-'), c('%')].contains(&first) || (d.len() >= 2 && d[1] == c(':')) {
        return None;
    }
    Some(if cur.is_empty() { d } else { pystr::concat(&[cur, &u("/"), &d]) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_doc_names() {
        let kind = |s: &str| is_agent_doc(&u(s));
        for (path, want) in [
            ("SKILL.md", Some("agent skill")),
            ("skills/x/Skill.md", Some("agent skill")),
            ("CLAUDE.local.md", Some("agent instructions")),
            ("a\\AGENTS.md", Some("agent instructions")),
            (".github/instructions/py.instructions.md", Some("agent instructions")),
            (".github/instructions/sub/py.instructions.md", Some("agent instructions")),
            (".github/instructions/py.md", None),
            (".claude/commands/review.md", Some("agent command")),
            (".claude/commands/fe/review.md", Some("agent command")),
            (".claude/agents/tester.md", Some("agent definition")),
            (".claude/settings.json", None),
            (".cursor/rules/style.mdc", Some("editor rules")),
            (".cursor/rules/sub/deep/style.mdc", Some("editor rules")),
            (".cursor/rules", Some("editor rules")),
            (".windsurf/rules/x.md", Some("editor rules")),
            (".clinerules", Some("editor rules")),
            (".clinerules/style.md", Some("editor rules")),
            (".clinerules/notes.txt", Some("editor rules")),
            ("README.md", None),
            ("docs/commands/x.md", None),
        ] {
            assert_eq!(kind(path), want, "{path}");
        }
    }

    #[test]
    fn pieces_cut_at_line_ends() {
        let text = u("aaaa\nbbbb\ncc\ndddddddddd\ne");
        let got: Vec<(usize, String)> = pieces(&text, 9).into_iter().map(|(k, s)| (k, pystr::to_string(&s))).collect();
        assert_eq!(got, vec![(0, "aaaa\nbbbb".into()), (2, "cc".into()), (3, "ddddddddd".into()), (3, "d".into()), (4, "e".into())]);
        assert_eq!(pieces(&u("short"), 9).len(), 1);
    }

    #[test]
    fn local_and_public_addresses() {
        for url in ["http://127.0.0.1:8000", "http://localhost/x", "https://10.1.2.3/", "http://192.168.0.4", "http://0.0.0.0:3000",
            "http://[::1]:8080/", "http://172.20.0.1/", "http://api.localhost/"] {
            assert!(local_url(&u(url)), "{url}");
        }
        for url in ["http://203.0.113.9/x", "https://example.invalid/", "http://8.8.8.8"] {
            assert!(!local_url(&u(url)), "{url}");
        }
        assert_eq!(ipv4_of(&u("http://10.0.0.5")).map(|x| pystr::to_string(&x)), Some("10.0.0.5".into()));
        assert_eq!(ipv4_of(&u("10.0.0.5")).map(|x| pystr::to_string(&x)), Some("10.0.0.5".into()));
        assert!(ipv4_of(&u("example.invalid")).is_none());
    }

    #[test]
    fn scripts_a_command_runs() {
        let p = crate::pack::current();
        let got = |cmd: &str| -> Vec<String> { local_scripts(&p, &u(cmd)).into_iter().map(|(_, j)| pystr::to_string(&j)).collect() };
        assert_eq!(got("bash -e scripts/x.sh"), vec!["scripts/x.sh"]);
        assert_eq!(got("python3 -u tools/a.py --fast"), vec!["tools/a.py"]);
        assert_eq!(got("uv run scripts/x.py"), vec!["scripts/x.py"]);
        assert_eq!(got(". scripts/x.sh"), vec!["scripts/x.sh"]);
        assert_eq!(got("source scripts/x.sh"), vec!["scripts/x.sh"]);
        assert_eq!(got("scripts/x.sh"), vec!["scripts/x.sh"]);
        assert_eq!(got("./x.sh"), vec!["x.sh"]);
        assert_eq!(got("cd scripts && ./x.sh"), vec!["scripts/x.sh"]);
        assert_eq!(got("cd scripts\ncd sub\n./x.sh"), vec!["scripts/sub/x.sh"]);
        assert_eq!(got("cd /tmp && ./x.sh"), Vec::<String>::new());
        assert_eq!(got("npx tsx scripts/x.ts"), vec!["scripts/x.ts"]);
        assert_eq!(got("pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/x.ps1"), vec!["scripts/x.ps1"]);
        assert_eq!(got("& .\\tools\\x.ps1"), vec!["tools/x.ps1"]);
        assert_eq!(got("ruby scripts/x.rb"), vec!["scripts/x.rb"]);
        // a file named, not run: a bare JavaScript or Python path is no command
        assert_eq!(got("src/index.js"), Vec::<String>::new());
        assert_eq!(got("edit src/x.sh first"), Vec::<String>::new());
    }

    #[test]
    fn script_languages() {
        // a followed script is read in deps::script_lang's language: never Ruby, Perl or PowerShell as JavaScript
        let p = crate::pack::current();
        let lang = |path: &str| crate::deps::script_lang(&p, &u(path), &u(""));
        assert_eq!(lang("a/x.py"), Some("py"));
        assert_eq!(lang("a/x.ts"), Some("js"));
        assert_eq!(lang("a/x.MJS"), Some("js"));
        assert_eq!(lang("a/x.rb"), Some("other"));
        assert_eq!(lang("a/x.pl"), Some("other"));
        assert_eq!(lang("a/x.ps1"), Some("other"));
        assert_eq!(lang("a/x.sh"), None);
    }
}
