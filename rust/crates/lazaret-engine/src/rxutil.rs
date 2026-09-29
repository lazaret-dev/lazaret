//! Small helpers around pyre for the ported functions: patterns built at
//! run time (cached per thread, as Python's re caches compiled patterns),
//! and the idioms core's code uses on matches.

use crate::pyre::{Match, Regex};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

thread_local! {
    static CACHE: RefCell<HashMap<(Vec<u32>, u32), Rc<Regex>>> = RefCell::new(HashMap::new());
}

/// re.compile(src, flags) for a pattern built at run time (names escaped
/// into pattern text core composes). A pattern that fails to compile is one
/// that never matches (core's never fail: they escape what they insert).
pub fn dynamic(src: Vec<u32>, flags: u32) -> Rc<Regex> {
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        let key = (src, flags);
        if let Some(rx) = c.get(&key) {
            return rx.clone();
        }
        if c.len() >= 512 {
            c.clear();
        }
        let rx = Rc::new(Regex::new(&key.0, flags).unwrap_or_else(|_| {
            Regex::compile("(?!)", 0).unwrap_or_else(|_| panic!("pyre cannot compile (?!)"))
        }));
        c.insert(key, rx.clone());
        rx
    })
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
