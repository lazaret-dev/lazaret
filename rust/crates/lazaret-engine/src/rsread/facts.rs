//! A reading's events turned into what the install-script and import-time tests ask (0.1.9).
//!
//! The tests ask Python's and JavaScript's trees the same questions ([`ModelFacts`]): the strongest send of
//! the machine's data and where data goes, code received and run, a file written and then run, the
//! commands run (read by the shell reader as an install hook's command), and what only a model sees (a
//! shell whose input and output are a connection, a DNS lookup of a name built from the machine's names).
//! A write to a file a shell or the system runs at login is handed to the persistence readers as the shell
//! line that would write it.

use super::eval::{Ev, Krate};
use super::val::{Val, UNKNOWN};
use crate::jsflow::supply::{cred_store, K_ADDRESS, K_BYTES, K_CARVED, K_CREDENTIALS, K_CRED_FILE, K_DECODED, K_ENV, K_FILE, K_IDENTITY, K_RECEIVED, K_REPORT, K_WHOLE_ENV};
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};
use crate::signs::ModelFacts;

/// The kinds of the machine's data, strongest first: the kind a send is reported as.
const LOCAL: [u16; 8] = [K_CREDENTIALS, K_CRED_FILE, K_WHOLE_ENV, K_ENV, K_FILE, K_REPORT, K_IDENTITY, K_ADDRESS];
/// What a file run held when the code wrote it: downloaded, decoded, carried.
const DROPPED: u16 = K_RECEIVED | K_DECODED | K_CARVED | K_BYTES;
/// Interpreters, and the names a written script is run with.
const INTERPRETERS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "python", "python3", "node", "perl", "ruby", "powershell", "pwsh", "cmd", "wscript", "cscript", "osascript"];

pub struct FileFacts {
    pub facts: ModelFacts,
    /// The line of the first event in the anchor file that gave a fact.
    pub first_line: Option<usize>,
}

/// The keys a path is matched by: its text where known (`=…`), its known end after an unknown start (`~…`),
/// the variable it came from (`#…`).
pub fn keys(v: &Val) -> Vec<PyStr> {
    let mut out = Vec::new();
    if let Some(s) = &v.s {
        if !s.contains(&UNKNOWN) {
            let t: PyStr = pystr::lstrip_chars(s, "./").to_vec();
            if !t.is_empty() {
                let mut k = u("=");
                k.extend(t.iter().copied());
                out.push(k);
            }
        } else if let Some(p) = s.iter().rposition(|&c| c == UNKNOWN) {
            let tail = &s[p + 1..];
            if tail.len() >= 2 {
                let mut k = u("~");
                k.extend_from_slice(tail);
                out.push(k);
            }
        }
    }
    if v.id != 0 {
        out.push(u(&format!("#{}", v.id)));
    }
    out
}

fn base_name(v: &Val) -> PyStr {
    let t = pystr::lower(&v.text_or_unknown());
    let b: PyStr = t.iter().rposition(|&c| c == '/' as u32 || c == '\\' as u32).map(|k| t[k + 1..].to_vec()).unwrap_or(t);
    b.strip_suffix(&u(".exe")[..]).map(|x| x.to_vec()).unwrap_or(b)
}

fn line_in(text: &[u32], at: u32) -> usize {
    let at = (at as usize).min(text.len());
    text[..at].iter().filter(|&&c| c == 10).count() + 1
}

/// The kind a value is sent as: its strongest kind of the machine's data, (kind name, what).
fn sent_kind(p: &Pack, v: &Val) -> Option<(&'static str, PyStr)> {
    for bit in LOCAL {
        if v.kinds & bit != 0 {
            let what = match v.first(bit) {
                Some((w, _)) => (*w).clone(),
                None => PyStr::new(),
            };
            let what = if bit == K_WHOLE_ENV { p.text("_LD_WHOLE_ENV") } else { what };
            return Some((Val::kind_name(bit), what));
        }
    }
    None
}

fn harvest(p: &Pack, kind: &str, what: &[u32]) -> bool {
    (kind == "environment" && what == p.text("_LD_WHOLE_ENV").as_slice()) || kind == "credentials" || (kind == "file" && cred_store(p, what))
}

/// The reason a file written and run gets, by what it held (`signs::dropped_reason`'s words).
fn dropped_reason(kinds: u16, what: &[u32], interp: Option<&PyStr>) -> PyStr {
    let what60: PyStr = what.iter().take(60).copied().collect();
    if kinds & (K_CARVED | K_BYTES) != 0 {
        return pystr::concat(&[&u("runs a program it extracts from inside another file ("), &what60, &u(")")]);
    }
    if kinds & K_DECODED != 0 && kinds & K_RECEIVED == 0 {
        return match interp {
            Some(i) => pystr::concat(&[&u("writes code it decodes to a file and runs it with "), i]),
            None => u("writes a file it decodes and runs it"),
        };
    }
    match interp {
        Some(i) => pystr::concat(&[&u("downloads a script and runs it with "), i]),
        None => u("downloads a file and then runs it"),
    }
}

/// A shell line that writes `data` to `path` (for the persistence readers).
fn write_line(path: &Val, data: &Val, append: bool) -> Option<PyStr> {
    let p = path.text_or_unknown();
    if p.iter().all(|&c| c == UNKNOWN) {
        return None;
    }
    let content: PyStr = data.text_or_unknown().iter().map(|&c| if c == '\'' as u32 { '"' as u32 } else { c }).collect();
    Some(pystr::concat(&[&u("printf '%s\\n' '"), &content, &u(if append { "' >> '" } else { "' > '" }), &p, &u("'")]))
}

pub fn facts(p: &Pack, k: &Krate, events: &[Ev], anchor: usize) -> FileFacts {
    let text = k.files[anchor].src;
    let mut out = ModelFacts::default();
    let mut first: Option<usize> = None;
    let mut written: Vec<(Vec<PyStr>, u16, PyStr)> = Vec::new();
    // (offset, kind, what, in_address, harvest)
    let mut best: Option<((bool, bool, usize), &'static str, PyStr)> = None;
    let off = |file: u16, at: u32| -> usize { if file as usize == anchor { at as usize } else { 0 } };
    let line = |file: u16, at: u32| -> usize { if file as usize == anchor { line_in(text, at) } else { 1 } };
    let note = |file: u16, at: u32, first: &mut Option<usize>| {
        if file as usize == anchor {
            let l = line_in(text, at);
            *first = Some(first.map_or(l, |f: usize| f.min(l)));
        }
    };
    let dest = |out: &mut ModelFacts, v: &Val| {
        let t = v.text_or_unknown();
        if t.iter().any(|&c| c != UNKNOWN) && !out.dests.contains(&t) && out.dests.len() < 64 {
            out.dests.push(t);
        }
    };
    for e in events {
        match e {
            Ev::Write { file, at, path, data, append } => {
                let kinds = data.kinds & DROPPED;
                if kinds != 0 {
                    let what = [K_CARVED, K_BYTES, K_RECEIVED, K_DECODED]
                        .iter()
                        .find_map(|&b| (kinds & b != 0).then(|| data.first(b)).flatten())
                        .map(|(w, _)| (*w).clone())
                        .unwrap_or_default();
                    written.push((keys(path), kinds, what));
                }
                // a file the system or a shell runs: the persistence readers read the write as a shell's
                if let Some(l) = write_line(path, data, *append) {
                    let reasons = crate::signs::persistence_reasons(p, &l);
                    if !reasons.is_empty() {
                        note(*file, *at, &mut first);
                        for r in reasons {
                            if !out.signs.iter().any(|(_, x)| *x == r) {
                                out.signs.push((off(*file, *at), r));
                            }
                        }
                    }
                }
            }
            Ev::Run { file, at, line: cmd, prog, args, script, conn_io, hidden: _ } => {
                // a file it wrote, run: by itself, or as the script an interpreter is given
                let base = base_name(prog);
                let interp = INTERPRETERS.iter().any(|i| pystr::eq(&base, i));
                let run_keys = if interp {
                    args.iter().find(|a| !a.text_or_unknown().first().is_some_and(|&c| c == '-' as u32 || c == '/' as u32 && a.text_or_unknown().len() <= 3)).map(keys).unwrap_or_default()
                } else {
                    keys(prog)
                };
                if out.dropped.is_none() {
                    if let Some((_, kinds, what)) = written.iter().find(|(ks, _, _)| ks.iter().any(|x| run_keys.contains(x))) {
                        let r = dropped_reason(*kinds, what, if interp { Some(&base) } else { None });
                        out.dropped = Some((line(*file, *at), r));
                        note(*file, *at, &mut first);
                    }
                }
                // code it received, run
                let received = script.as_ref().is_some_and(|s| s.kinds & K_RECEIVED != 0) || prog.kinds & K_RECEIVED != 0;
                if received && out.received.is_none() {
                    out.received = Some((line(*file, *at), "run"));
                    note(*file, *at, &mut first);
                }
                if cmd.iter().any(|&c| c != UNKNOWN && c != ' ' as u32) {
                    out.commands.push((off(*file, *at), cmd.clone()));
                    let rs = crate::shell::hook_command_risk(p, cmd, true);
                    if !rs.is_empty() {
                        note(*file, *at, &mut first);
                    }
                }
                if *conn_io {
                    out.signs.push((off(*file, *at), u("opens a reverse shell")));
                    note(*file, *at, &mut first);
                }
                if cmd.windows(4).any(|w| pystr::eq(w, "curl") || pystr::eq(w, "wget")) {
                    out.network = true;
                }
            }
            Ev::Send { file, at, data, dest: d, in_address } => {
                out.network = true;
                dest(&mut out, d);
                if let Some((kind, what)) = sent_kind(p, data) {
                    let h = harvest(p, kind, &what);
                    let rank = (*in_address, !h, off(*file, *at));
                    if best.as_ref().map_or(true, |(r, _, _)| rank < *r) {
                        best = Some((rank, kind, what));
                        note(*file, *at, &mut first);
                    }
                }
            }
            Ev::Lookup { file, at, name, txt: _ } => {
                out.network = true;
                dest(&mut out, name);
                if name.kinds & K_IDENTITY != 0 {
                    let r = u("sends the machine's user or host name in a DNS lookup of a name it builds");
                    if !out.signs.iter().any(|(_, x)| *x == r) {
                        out.signs.push((off(*file, *at), r));
                        note(*file, *at, &mut first);
                    }
                } else if let Some((kind, what)) = sent_kind(p, name) {
                    let h = harvest(p, kind, &what);
                    let rank = (false, !h, off(*file, *at));
                    if best.as_ref().map_or(true, |(r, _, _)| rank < *r) {
                        best = Some((rank, kind, what));
                        note(*file, *at, &mut first);
                    }
                }
            }
            Ev::Load { file, at, path } => {
                let ks = keys(path);
                if out.dropped.is_none() {
                    if let Some((_, kinds, what)) = written.iter().find(|(wk, _, _)| wk.iter().any(|x| ks.contains(x))) {
                        out.dropped = Some((line(*file, *at), dropped_reason(*kinds, what, None)));
                        note(*file, *at, &mut first);
                    }
                }
                if path.kinds & K_RECEIVED != 0 && out.received.is_none() {
                    out.received = Some((line(*file, *at), "import"));
                    note(*file, *at, &mut first);
                }
            }
        }
    }
    if let Some(((in_address, _, at), kind, what)) = best {
        out.sent = Some((at, kind, what, in_address));
    }
    FileFacts { facts: out, first_line: first }
}
