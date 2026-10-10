//! What a reader records code doing, and the language-neutral parts of reading it (0.1.9).
//!
//! A reader (Rust's `rsread`, Go's `goread`) evaluates a language's code and records what it does as
//! events: a process started ([`Ev::Run`]), data sent ([`Ev::Send`]), a file written ([`Ev::Write`]), a
//! name looked up in the DNS ([`Ev::Lookup`]), a library loaded ([`Ev::Load`]). What is the same in every
//! language is here: the handles' states, a command's line as a shell reads it (with `sh -c`, `cmd /c` and
//! PowerShell's `-Command` scripts pulled out), the download a command writes to a file, what an
//! environment variable, a file read or a command's output gives, and the decodings.

use super::val::{self, Val, UNKNOWN};
use crate::jsflow::supply::{K_ENV, K_FILE, K_IDENTITY, K_PATH, K_RECEIVED};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use std::rc::Rc;

fn eqs(a: &[u32], b: &str) -> bool {
    pystr::eq(a, b)
}

/// A command being built or run.
#[derive(Clone, Debug, Default)]
pub struct CmdState {
    pub prog: Val,
    pub args: Vec<Val>,
    pub file: u16,
    pub at: u32,
    /// stdin, stdout or stderr given a connection: a shell's input and output on the network.
    pub conn_io: bool,
    /// Its output thrown away or its window hidden: run out of sight.
    pub hidden: bool,
    pub ran: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ReqState {
    pub url: Val,
    pub body: Val,
}

#[derive(Clone, Debug, Default)]
pub struct ConnState {
    pub addr: Val,
}

#[derive(Clone, Debug, Default)]
pub struct WState {
    pub path: Val,
    pub append: bool,
}


/// What the code does.
#[derive(Clone, Debug)]
pub enum Ev {
    /// A process started: its command line as a shell would read it, its program and arguments.
    Run { file: u16, at: u32, line: PyStr, prog: Val, args: Vec<Val>, script: Option<Val>, conn_io: bool, hidden: bool },
    /// Data sent to an address (`in_address`: the data is in the address itself).
    Send { file: u16, at: u32, data: Val, dest: Val, in_address: bool },
    /// A file written.
    Write { file: u16, at: u32, path: Val, data: Val, append: bool },
    /// A name looked up in the DNS (`txt`: its TXT records read).
    Lookup { file: u16, at: u32, name: Val, txt: bool },
    /// A library loaded from a path.
    Load { file: u16, at: u32, path: Val },
}


/// The shells and interpreters a command line names, to read what they are handed.
pub const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "busybox"];


/// The file an event happened in.
pub fn ev_file(e: &Ev) -> u16 {
    match e {
        Ev::Run { file, .. } | Ev::Send { file, .. } | Ev::Write { file, .. } | Ev::Lookup { file, .. } | Ev::Load { file, .. } => *file,
    }
}


/// The value a field, an item or an unknown call gives of `v`: its kinds, nothing else.
pub fn derived(v: &Val) -> Val {
    let mut d = Val::unknown();
    d.add_kinds(v);
    d
}

pub fn map_text(v: &Val, f: impl Fn(&[u32]) -> PyStr) -> Val {
    match &v.s {
        Some(s) => {
            let mut out = Val::text(f(s));
            out.add_kinds(v);
            out
        }
        None => derived(v),
    }
}

pub fn cat(parts: &[&[u32]]) -> PyStr {
    pystr::concat(parts)
}


/// `a` joined to `b` as a path: `a/b` (b absolute: b).
pub fn path_join(a: &Val, b: &Val) -> Val {
    let bt = b.text_or_unknown();
    if bt.first() == Some(&('/' as u32)) || bt.first() == Some(&('~' as u32)) {
        return b.clone().with_kinds(a);
    }
    let mut s = a.text_or_unknown();
    if !s.is_empty() && s.last() != Some(&('/' as u32)) && s.last() != Some(&('\\' as u32)) {
        s.push('/' as u32);
    }
    s.extend(bt);
    let mut v = Val::text(val::collapse(s));
    v.add_kinds(a);
    v.add_kinds(b);
    v
}


/// A list's items as integers, if they all are.
pub fn list_ints(v: &Val) -> Option<Vec<i128>> {
    if let Some(items) = &v.items {
        return items.iter().map(|i| i.int).collect();
    }
    v.s.as_ref().filter(|s| !s.contains(&UNKNOWN)).map(|s| s.iter().map(|&c| c as i128).collect())
}


/// Bytes read as text: a list of numbers, or a text's code points.
pub fn text_of_bytes(v: &Val) -> Val {
    if let Some(items) = &v.items {
        if let Some(ints) = items.iter().map(|i| i.int).collect::<Option<Vec<i128>>>() {
            let bytes: PyStr = ints.iter().map(|&n| (n & 0xFF) as u32).collect();
            let mut out = Val::text(val::utf8(&bytes));
            out.add_kinds(v);
            return out;
        }
    }
    match &v.s {
        Some(s) => {
            let mut out = Val::text(val::utf8(s));
            out.add_kinds(v);
            out
        }
        None => derived(v),
    }
}


/// A command's line as a shell would read it: an interpreter's `-c` script, or the program and its arguments.
pub fn command_line(c: &CmdState) -> PyStr {
    if let Some(script) = shell_script(c) {
        return script.text_or_unknown();
    }
    let mut out = quote_word(&c.prog.text_or_unknown());
    for a in &c.args {
        out.push(' ' as u32);
        out.extend(quote_word(&a.text_or_unknown()));
    }
    out
}


/// What a shell given `-c` (cmd `/c`, PowerShell `-Command`) runs, if the command is one.
pub fn shell_script(c: &CmdState) -> Option<Val> {
    let prog = c.prog.text_or_unknown();
    let base: PyStr = {
        let p = prog.iter().rposition(|&ch| ch == '/' as u32 || ch == '\\' as u32).map(|k| prog[k + 1..].to_vec()).unwrap_or(prog.clone());
        let lower = pystr::lower(&p);
        lower.strip_suffix(&u(".exe")[..]).map(|x| x.to_vec()).unwrap_or(lower)
    };
    let shell = SHELLS.iter().any(|s| eqs(&base, s));
    let cmd = eqs(&base, "cmd");
    let ps = eqs(&base, "powershell") || eqs(&base, "pwsh");
    if !(shell || cmd || ps) {
        return None;
    }
    for (k, a) in c.args.iter().enumerate() {
        let t = a.text_or_unknown();
        let lt = pystr::lower(&t);
        // (the shell reader's rule: a short flag that holds `c`, `-c`, `-lc`, `-ec`)
        let short_c = t.len() >= 2 && t[0] == '-' as u32 && t[1] != '-' as u32 && t[1..].iter().all(|&x| char::from_u32(x).is_some_and(|ch| ch.is_ascii_alphabetic())) && t[1..].contains(&('c' as u32));
        let flag = (shell && short_c)
            || (cmd && (eqs(&lt, "/c") || eqs(&lt, "/k")))
            || (ps && (eqs(&lt, "-command") || eqs(&lt, "-c") || eqs(&lt, "/c") || eqs(&lt, "-encodedcommand") || eqs(&lt, "-enc") || eqs(&lt, "-e")));
        if flag {
            let rest = &c.args[k + 1..];
            if rest.is_empty() {
                return None;
            }
            if ps && (eqs(&lt, "-encodedcommand") || eqs(&lt, "-enc") || eqs(&lt, "-e")) {
                // PowerShell's own command line, for the PowerShell reader
                let mut line = cat(&[&prog, &u(" "), &t]);
                for r in rest {
                    line.push(' ' as u32);
                    line.extend(r.text_or_unknown());
                }
                let mut v = Val::text(line);
                for r in rest {
                    v.add_kinds(r);
                }
                return Some(v);
            }
            let mut v = Val::text(Vec::new());
            for (j, r) in rest.iter().enumerate() {
                if j > 0 {
                    v = Val::concat(&v, &Val::text(u(" ")));
                }
                v = Val::concat(&v, r);
            }
            if ps {
                let mut line = cat(&[&u("powershell -Command \""), &v.text_or_unknown(), &u("\"")]);
                line = val::collapse(line);
                let mut out = Val::text(line);
                out.add_kinds(&v);
                return Some(out);
            }
            return Some(v);
        }
    }
    None
}


/// A word quoted for a shell where it needs it.
pub fn quote_word(w: &[u32]) -> PyStr {
    if !w.is_empty() && w.iter().all(|&c| char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || "-_./:=@%+,~$&|>".contains(ch)) || c == UNKNOWN) {
        return w.to_vec();
    }
    let mut out = vec!['\'' as u32];
    for &c in w {
        if c == '\'' as u32 {
            out.extend(u("'\\''"));
        } else {
            out.push(c);
        }
    }
    out.push('\'' as u32);
    out
}


/// A download a command writes to a file: (the file, the address), for curl `-o`, wget `-O`, PowerShell's
/// `Invoke-WebRequest -OutFile`, certutil and bitsadmin. (A shell's or cmd's script is read command by command, by
/// [`run_events`].)
pub fn download_target(c: &CmdState) -> Option<(Val, Val)> {
    let prog = pystr::lower(&c.prog.text_or_unknown());
    let base: PyStr = prog.iter().rposition(|&ch| ch == '/' as u32 || ch == '\\' as u32).map(|k| prog[k + 1..].to_vec()).unwrap_or(prog.clone());
    let base = base.strip_suffix(&u(".exe")[..]).map(|x| x.to_vec()).unwrap_or(base);
    let args = &c.args;
    let url = || args.iter().find(|a| a.s.as_ref().is_some_and(|s| pystr::starts_with(s, "http") || pystr::find_str(s, "://", 0).is_some())).cloned();
    if eqs(&base, "curl") || eqs(&base, "wget") {
        for (k, a) in args.iter().enumerate() {
            let t = a.text_or_unknown();
            let out_flag = if eqs(&base, "curl") { eqs(&t, "-o") || eqs(&t, "--output") } else { eqs(&t, "-O") || eqs(&t, "--output-document") };
            if out_flag {
                let path = args.get(k + 1)?.clone();
                if eqs(&path.text_or_unknown(), "-") {
                    return None;
                }
                return Some((path, url().unwrap_or_default()));
            }
        }
        return None;
    }
    if eqs(&base, "certutil") || eqs(&base, "bitsadmin") {
        let url = url()?;
        let last = args.last()?.clone();
        return Some((last, url));
    }
    if ["invoke-webrequest", "iwr", "invoke-restmethod", "irm", "start-bitstransfer"].iter().any(|w| eqs(&base, w)) {
        for (k, a) in args.iter().enumerate() {
            let t = pystr::lower(&a.text_or_unknown());
            if eqs(&t, "-outfile") || eqs(&t, "-destination") || eqs(&t, "-o") {
                let path = args.get(k + 1)?.clone();
                return Some((path, url().unwrap_or_default()));
            }
        }
    }
    None
}

/// The simple commands of a script as a shell or cmd runs them one after another (`a && b; c | d`): each as its
/// words, quotes taken off. At most 64 commands of 256 words.
pub fn script_commands(script: &[u32]) -> Vec<Vec<PyStr>> {
    let mut cmds: Vec<Vec<PyStr>> = Vec::new();
    let mut words: Vec<PyStr> = Vec::new();
    let mut word: PyStr = Vec::new();
    let mut in_word = false;
    let mut quote: Option<u32> = None;
    let flush_word = |words: &mut Vec<PyStr>, word: &mut PyStr, in_word: &mut bool| {
        if *in_word && words.len() < 256 {
            words.push(std::mem::take(word));
        }
        word.clear();
        *in_word = false;
    };
    for &c in script {
        if cmds.len() >= 64 {
            break;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        match char::from_u32(c) {
            Some('\'' | '"') => {
                quote = Some(c);
                in_word = true;
            }
            Some(' ' | '\t' | '\r') => flush_word(&mut words, &mut word, &mut in_word),
            Some(';' | '\n' | '|' | '&' | '(' | ')') => {
                flush_word(&mut words, &mut word, &mut in_word);
                if !words.is_empty() {
                    cmds.push(std::mem::take(&mut words));
                }
            }
            _ => {
                word.push(c);
                in_word = true;
            }
        }
    }
    flush_word(&mut words, &mut word, &mut in_word);
    if !words.is_empty() && cmds.len() < 64 {
        cmds.push(words);
    }
    cmds
}


/// Is a path's text one outside the package (the machine's files: an absolute path, the home folder, a
/// credential file)?
pub fn outside_path(p: &Pack, text: &[u32]) -> bool {
    if text.first() == Some(&UNKNOWN) && text.len() > 1 {
        let rest = &text[1..];
        let quoted = cat(&[&u("\""), rest, &u("\"")]);
        return p.re("_LD_CRED_FILE_RE").match_(&quoted).is_some() || crate::jsflow::supply::cred_store(p, rest);
    }
    let quoted = cat(&[&u("\""), text, &u("\"")]);
    p.re("_LD_FS_ROOT_RE").match_(&quoted).is_some() || p.re("_LD_ABSOLUTE_RE").match_(&quoted).is_some() || p.re("_LD_CRED_FILE_RE").match_(&quoted).is_some()
}


/// A path as a finding shows it: its unknown pieces as `…`.
pub fn shown_path(text: &[u32]) -> PyStr {
    let mut out = Vec::with_capacity(text.len());
    for &c in text {
        if c == UNKNOWN {
            out.push(0x2026);
        } else {
            out.push(c);
        }
    }
    out
}

// ---------------------------------------------------------------- sources --

/// An environment variable read: the kind its name says (an identity, a secret; a home folder is a path).
pub fn env_var(p: &Pack, name: &[u32], at: u32) -> Val {
    if p.re("_SH_IDENTITY_VAR_RE").match_(name).is_some() {
        return Val::source(K_IDENTITY, name.to_vec(), at);
    }
    if p.re("_SH_SECRET_VAR_RE").search(name).is_some() && p.re("_LD_ENV_QUIET_RE").match_(name).is_none() {
        let mut v = Val::source(K_ENV, name.to_vec(), at);
        v.s = Some(Rc::new(cat(&[&u("$"), name])));
        return v;
    }
    if ["HOME", "USERPROFILE"].iter().any(|h| eqs(name, h)) {
        let mut v = Val::text(u("~"));
        v.add_kinds(&Val::source(K_PATH, name.to_vec(), at));
        return v;
    }
    if ["APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "TMPDIR", "PROGRAMDATA"].iter().any(|h| eqs(name, h)) {
        return Val::text(cat(&[&u("%"), name, &u("%")]));
    }
    let mut v = Val::unknown();
    v.s = Some(Rc::new(cat(&[&u("${"), name, &u("}")])));
    v
}

/// What a file read gives: data read from the machine when the path is outside the package.
pub fn file_read(p: &Pack, path: &Val, at: u32) -> Val {
    let text = path.text_or_unknown();
    let outside = path.kinds & K_PATH != 0 || outside_path(p, &text);
    if !outside {
        let mut v = Val::unknown();
        v.add_kinds(path);
        return v;
    }
    let shown = shown_path(&text);
    let mut v = Val::source(K_FILE, shown.clone(), at);
    if crate::jsflow::supply::cred_store(p, &shown) {
        let c = Val::source(crate::jsflow::supply::K_CRED_FILE, shown, at);
        v.add_kinds(&c);
    }
    v
}

/// What a command prints: the machine's data the shell reader says the command reports (what other
/// commands print is not the machine's data).
pub fn output_of(p: &Pack, c: &CmdState) -> Val {
    let line = command_line(c);
    let data = crate::shell::sh_output_data(p, &line, 0, None);
    let whole = p.text("_LD_WHOLE_ENV");
    let mut v = Val::unknown();
    for (kind, what) in data {
        let bit = crate::jsflow::supply::kind_bit(kind, &what, &whole);
        v.add_kinds(&Val::source(bit, what, c.at));
    }
    v
}

/// What a response or a connection gives: data received from `what`.
pub fn received(at: u32, what: &Val) -> Val {
    let mut v = Val::source(K_RECEIVED, what.text_or_unknown(), at);
    v.id = 0;
    v
}

/// Base64 decoded: the text where the input is known, marked decoded.
pub fn decode_b64(a: &Val, at: u32) -> Val {
    let mut v = match a.s.as_ref().filter(|_| a.known()).and_then(|s| val::base64(s)) {
        Some(bytes) => Val::text(val::utf8(&bytes)),
        None => Val::unknown(),
    };
    v.add_kinds(a);
    v.decoded(at)
}

/// Hex decoded: the text where the input is known, marked decoded.
pub fn decode_hex(a: &Val, at: u32) -> Val {
    let mut v = match a.s.as_ref().filter(|_| a.known()).and_then(|s| val::hex(s)) {
        Some(bytes) => Val::text(val::utf8(&bytes)),
        None => Val::unknown(),
    };
    v.add_kinds(a);
    v.decoded(at)
}

/// A value marked decoded, unknown text (an XOR, a reversal of what is not known).
pub fn decoded_unknown(v: &Val, at: u32) -> Val {
    derived(v).decoded(at)
}

// ---------------------------------------------------------------- sinks --

/// The events a command's run gives: the run, and a download it writes to a file (curl `-o`, wget `-O`,
/// PowerShell's `-OutFile`, certutil) as the address contacted and the file written with what it received.
pub fn run_events(c: &CmdState) -> Vec<Ev> {
    let line = command_line(c);
    let script = shell_script(c);
    let mut out = vec![Ev::Run { file: c.file, at: c.at, line, prog: c.prog.clone(), args: c.args.clone(), script: script.clone(), conn_io: c.conn_io, hidden: c.hidden }];
    push_download(&mut out, c);
    // a shell's or cmd's script, command by command: the download each writes, and each command run when there are
    // several (`certutil … %TEMP%\\u.exe && %TEMP%\\u.exe`: a file written by one and run by the next)
    if let Some(text) = script.as_ref().and_then(|v| v.s.clone()) {
        let sv = script.unwrap_or_default();
        let subs = script_commands(&text);
        let several = subs.len() > 1;
        for words in subs {
            let mut it = words.into_iter().map(|w| Val::text(w).with_kinds(&sv));
            let Some(prog) = it.next() else { continue };
            let sub = CmdState { prog, args: it.collect(), file: c.file, at: c.at, hidden: c.hidden, ..CmdState::default() };
            push_download(&mut out, &sub);
            if several {
                out.push(Ev::Run { file: c.file, at: c.at, line: command_line(&sub), prog: sub.prog.clone(), args: sub.args.clone(), script: shell_script(&sub), conn_io: false, hidden: c.hidden });
            }
        }
    }
    out
}

/// The address a command contacts and the file it writes, for a download it writes to a file.
fn push_download(out: &mut Vec<Ev>, c: &CmdState) {
    if let Some((path, url)) = download_target(c) {
        let mut data = Val::source(K_RECEIVED, url.text_or_unknown(), c.at);
        data.add_kinds(&url);
        out.push(Ev::Send { file: c.file, at: c.at, data: url.clone(), dest: url.clone(), in_address: true });
        out.push(Ev::Write { file: c.file, at: c.at, path, data, append: false });
    }
}

/// The events of data sent to an address: the address itself (what it holds is in the request), and the
/// body when there is one.
pub fn send_events(file: u16, at: u32, url: &Val, body: &Val) -> Vec<Ev> {
    let mut out = vec![Ev::Send { file, at, data: url.clone(), dest: url.clone(), in_address: true }];
    if body.kinds != 0 || body.s.is_some() {
        out.push(Ev::Send { file, at, data: body.clone(), dest: url.clone(), in_address: false });
    }
    out
}
