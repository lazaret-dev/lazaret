//! Small helpers around pyre for the ported functions: patterns built at
//! run time (cached per thread, as Python's re caches compiled patterns),
//! and the idioms core's code uses on matches.

use crate::pyre::{Match, Regex};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

thread_local! {
    static CACHE: RefCell<HashMap<(Vec<u32>, u32, bool), Rc<Regex>>> = RefCell::new(HashMap::new());
}

/// Patterns the engine built that linre would not run (each compiled on
/// sre's matcher instead): none should be (linre.fallbacks, which the tests
/// read after their scans). At most FALLBACKS_KEPT are kept.
static FALLBACKS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
const FALLBACKS_KEPT: usize = 64;

/// The patterns linre would not run since the last call (and forget them).
pub fn take_fallbacks() -> Vec<String> {
    FALLBACKS.lock().map(|mut f| std::mem::take(&mut *f)).unwrap_or_default()
}

fn never() -> Regex {
    Regex::compile("(?!)", 0).unwrap_or_else(|_| panic!("pyre cannot compile (?!)"))
}

/// re.compile(src, flags) for a pattern built at run time (names escaped
/// into pattern text core composes), on linre. A pattern Python rejects is
/// one that never matches (core's never fail: they escape what they
/// insert); one linre would not run is answered by sre's matcher and noted
/// (take_fallbacks), so a pattern the tests missed is still answered right.
pub fn dynamic(src: Vec<u32>, flags: u32) -> Rc<Regex> {
    compiled(src, flags, false)
}

/// The same for a pattern a user wrote (a taint configuration's): linre's
/// when it runs it, sre's otherwise, and not noted.
pub fn dynamic_user(src: Vec<u32>, flags: u32) -> Rc<Regex> {
    compiled(src, flags, true)
}

fn compiled(src: Vec<u32>, flags: u32, user: bool) -> Rc<Regex> {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let key = (src, flags, user);
        if let Some(rx) = c.get(&key) {
            return rx.clone();
        }
        if c.len() >= 512 {
            c.clear();
        }
        let rx = if user {
            Regex::new_user(&key.0, flags).unwrap_or_else(|_| never())
        } else {
            match Regex::new(&key.0, flags) {
                Ok(rx) => rx,
                Err(e) => match Regex::new_user(&key.0, flags) {
                    Ok(rx) => {
                        let what = format!("{}: {}", crate::pystr::to_string(&key.0), e.0);
                        // (LAZARET_LINRE_FALLBACKS: say so on stderr too, for the gates' runs)
                        if std::env::var_os("LAZARET_LINRE_FALLBACKS").is_some() {
                            eprintln!("LINRE-FALLBACK {}", what);
                        }
                        if let Ok(mut f) = FALLBACKS.lock() {
                            if f.len() < FALLBACKS_KEPT {
                                f.push(what);
                            }
                        }
                        rx
                    }
                    Err(_) => never(),
                },
            }
        };
        let rx = Rc::new(rx);
        c.insert(key, rx.clone());
        rx
    })
}

/// pattern.finditer(s, pos, endpos) where a match must also pass `ok`: one
/// that does not is no match, and the search goes on from the next
/// position, as sre's does at a start where its pattern fails. For the few
/// patterns linre cannot run as they were written (P-16): a backreference
/// to a name, read as a second group checked here (`finditer_same`), and
/// counts larger than a program holds, read as unbounded repeats and
/// checked here. Their matches are never empty.
pub fn finditer_checked<'s>(re: &'s Regex, s: &'s [u32], pos: usize, endpos: usize, mut ok: impl FnMut(&Match<'s>) -> bool) -> Vec<Match<'s>> {
    let mut out = Vec::new();
    let end = endpos.min(s.len());
    let mut at = pos;
    while at <= end {
        let m = match re.search_at(s, at as isize, end as isize) {
            Some(m) => m,
            None => break,
        };
        if ok(&m) {
            at = m.end().max(m.start() + 1);
            out.push(m);
        } else {
            at = m.start() + 1;
        }
    }
    out
}

/// pattern.search(s, pos, endpos) where the match must also pass `ok` (see
/// finditer_checked): the first that does.
pub fn search_checked<'s>(re: &'s Regex, s: &'s [u32], pos: usize, endpos: usize, mut ok: impl FnMut(&Match<'s>) -> bool) -> Option<Match<'s>> {
    let end = endpos.min(s.len());
    let mut at = pos;
    while at <= end {
        let m = re.search_at(s, at as isize, end as isize)?;
        if ok(&m) {
            return Some(m);
        }
        at = m.start() + 1;
    }
    None
}

/// pattern.sub(f, s) over finditer_checked's matches.
pub fn sub_checked<'s>(re: &'s Regex, s: &'s [u32], ok: impl FnMut(&Match<'s>) -> bool, mut f: impl FnMut(&Match<'s>) -> Vec<u32>) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::with_capacity(s.len());
    let mut i = 0usize;
    for m in finditer_checked(re, s, 0, s.len(), ok) {
        out.extend_from_slice(&s[i..m.start()]);
        out.extend(f(&m));
        i = m.end();
    }
    out.extend_from_slice(&s[i..]);
    out
}

/// The number of items in a comma-separated list of numbers (`0x1F, 23,`).
pub fn count_numbers(list: &[u32]) -> usize {
    let mut n = 0usize;
    let mut inside = false;
    for &c in list {
        let alnum = c < 128 && (c as u8).is_ascii_alphanumeric();
        if alnum && !inside {
            n += 1;
        }
        inside = alnum;
    }
    n
}

/// Do the groups `same` names hold the same text, pair by pair, where the
/// second took part? (`(?P<i>…)…(?P<i_again>…)` for `(?P<i>…)…(?P=i)`.)
pub fn same_groups(m: &Match, same: &[(&str, &str)]) -> bool {
    same.iter().all(|&(a, b)| match m.name(b) {
        None => true,
        Some(t) => m.name(a) == Some(t),
    })
}

/// finditer_checked with `same_groups` as the check.
pub fn finditer_same<'s>(re: &'s Regex, s: &'s [u32], pos: usize, endpos: usize, same: &[(&str, &str)]) -> Vec<Match<'s>> {
    finditer_checked(re, s, pos, endpos, |m| same_groups(m, same))
}


/// The first group of a match that took part (`m.group("a") or m.group("b")
/// or …` over the named alternatives, in order): None when none did.
pub fn first_named<'s>(m: &Match<'s>, names: &[&str]) -> Option<&'s [u32]> {
    for n in names {
        if let Some(g) = m.name(n) {
            if !g.is_empty() {
                return Some(g);
            }
        }
    }
    None
}

/// Python's `a or b or c` over optional groups: the first non-empty one;
/// else the last one's value as Python would give it (None or '').
pub fn or_groups<'s>(m: &Match<'s>, names: &[&str]) -> Option<&'s [u32]> {
    let mut last: Option<&'s [u32]> = None;
    for n in names {
        let g = if m.regex().has_group(n) { m.name(n) } else { None };
        if let Some(v) = g {
            if !v.is_empty() {
                return Some(v);
            }
        }
        last = g;
    }
    last
}

#[cfg(test)]
#[path = "rxutil_tests.rs"]
mod tests;
