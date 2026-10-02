//! The parsed pattern under its flags: character sets, zero-width tests,
//! groups, alternatives and repeats; and what linre refuses.
//!
//! Flags are resolved here, item by item, as re's compiler resolves them
//! (a group's `(?i-s:…)` over the pattern's own): each character item
//! becomes the set of text characters it accepts (charset.rs), each anchor
//! the position test it compiles to, each lookaround either a test of the
//! one character before or after the position (`(?<![\w$.])`, `(?=\()`) or
//! a sub-pattern of bounded width tried at the position.
//!
//! Refused, with the reason, because a linear-time matcher cannot run them
//! or cannot run them as sre does:
//! - backreferences and conditionals (they need what a group matched);
//! - a lookahead of unbounded width (trying it costs up to the rest of the
//!   text at every position);
//! - a repeat whose body can match the empty string, other than `?` (sre
//!   stops such a loop by rules of its own: zero-width iteration checks);
//! - a capturing group inside a positive lookaround;
//! - atomic groups, possessive repeats, `\N{…}`, the TEMPLATE flag;
//! - a program too large (counted repeats are expanded) or a lookaround
//!   wider than `MAX_LOOK`.

use super::charset::{self, CharSet, Fold};
use super::syntax::{self, At, Error, Node, RepKind, MAXREPEAT};
use std::collections::HashMap;

/// A lookaround wider than this is refused.
pub const MAX_LOOK: u64 = 1000;
/// Lookarounds nested deeper than this are refused.
const MAX_LOOK_NEST: usize = 8;

#[derive(Clone, Debug)]
pub enum Hir {
    Empty,
    /// one character of a set
    Char(u32),
    /// a zero-width test (an index into the looks)
    Look(u32),
    /// a capturing group (1-based)
    Group(usize, Box<Hir>),
    Concat(Vec<Hir>),
    Alt(Vec<Hir>),
    /// `simple`: sre's single-character repeat (it fails at once past the
    /// window's end; see Guard in nfa.rs)
    Repeat { min: u32, max: Option<u32>, greedy: bool, simple: bool, body: Box<Hir> },
}

/// A zero-width test of a position.
#[derive(Clone, Debug)]
pub enum Look {
    /// `^` without MULTILINE, `\A`: the start of the text
    Begin,
    /// `^` under MULTILINE: the start of the text or after "\n"
    BeginLine,
    /// `$` without MULTILINE: the end of the window, or before a "\n" that ends it
    End,
    /// `$` under MULTILINE: the end of the window or before "\n"
    EndLine,
    /// `\Z`: the end of the window
    EndString,
    /// `\b` (`negate`: `\B`), with Unicode or ASCII word characters
    Word { ascii: bool, negate: bool },
    /// a lookbehind of one character of a set
    Behind1 { set: u32, negate: bool },
    /// a lookahead of one character of a set
    Ahead1 { set: u32, negate: bool },
    /// any other lookaround: its sub-pattern, of width lo..=hi
    Around { behind: bool, negate: bool, body: Box<Hir>, lo: u32, hi: u32 },
}

pub struct Lowered {
    pub hir: Hir,
    pub sets: Vec<CharSet>,
    pub looks: Vec<Look>,
}

struct Lower {
    sets: Vec<CharSet>,
    set_ids: HashMap<CharSet, u32>,
    looks: Vec<Look>,
    look_nest: usize,
}

fn refuse<T>(why: &str) -> Result<T, Error> {
    Err(Error::Refused(why.to_string()))
}

/// re's _combine_flags: a group's flags over those around it.
fn combine(flags: u32, add: u32, del: u32) -> u32 {
    let type_flags = syntax::FLAG_ASCII | syntax::FLAG_LOCALE | syntax::FLAG_UNICODE;
    let mut f = flags;
    if add & type_flags != 0 {
        f &= !type_flags;
    }
    (f | add) & !del
}

fn fold_of(flags: u32) -> Fold {
    if flags & syntax::FLAG_IGNORECASE == 0 {
        Fold::None
    } else if flags & syntax::FLAG_UNICODE != 0 {
        Fold::Unicode
    } else {
        Fold::Ascii
    }
}

/// re's getwidth: the (min, max) width of a sub-pattern, capped as re caps
/// it (lookarounds and anchors count nothing; max MAXREPEAT is unbounded).
pub fn py_width(n: &Node) -> (u64, u64) {
    let (lo, hi) = width_raw(n);
    (lo.min(MAXREPEAT - 1), hi.min(MAXREPEAT))
}

fn width_raw(n: &Node) -> (u64, u64) {
    match n {
        Node::Lit(_) | Node::NotLit(_) | Node::Class(..) | Node::Any | Node::Named => (1, 1),
        Node::At(_) | Node::Look { .. } => (0, 0),
        Node::Backref(_) => (0, MAXREPEAT), // (refused; its width is the group's)
        Node::Group(_, _, _, b) | Node::Atomic(b) => py_width(b),
        Node::Seq(v) => {
            let mut lo = 0u64;
            let mut hi = 0u64;
            for x in v {
                let (a, b) = width_raw(x);
                lo = lo.saturating_add(a);
                hi = hi.saturating_add(b);
            }
            (lo, hi)
        }
        Node::Alt(v) => {
            let mut lo = MAXREPEAT - 1;
            let mut hi = 0u64;
            for x in v {
                let (a, b) = py_width(x);
                lo = lo.min(a);
                hi = hi.max(b);
            }
            (lo, hi)
        }
        Node::Repeat { min, max, body, .. } => {
            let (i, j) = py_width(body);
            let lo = i.saturating_mul(*min);
            let hi = if *max == MAXREPEAT && j > 0 { MAXREPEAT } else { j.saturating_mul(*max) };
            (lo, hi)
        }
        Node::Cond { yes, no, .. } => {
            let (mut i, mut j) = py_width(yes);
            match no {
                Some(n) => {
                    let (l, h) = py_width(n);
                    i = i.min(l);
                    j = j.max(h);
                }
                None => i = 0,
            }
            (i, j)
        }
    }
}

/// sre's single-character repeat: its body is one character item.
fn is_simple(n: &Node) -> bool {
    match n {
        Node::Lit(_) | Node::NotLit(_) | Node::Class(..) | Node::Any | Node::Named => true,
        Node::Group(None, _, _, b) => is_simple(b),
        Node::Seq(v) => v.len() == 1 && is_simple(&v[0]),
        _ => false,
    }
}

fn has_group(n: &Node) -> bool {
    match n {
        Node::Group(g, _, _, b) => g.is_some() || has_group(b),
        Node::Atomic(b) | Node::Look { body: b, .. } => has_group(b),
        Node::Seq(v) | Node::Alt(v) => v.iter().any(has_group),
        Node::Repeat { body, .. } => has_group(body),
        Node::Cond { yes, no, .. } => has_group(yes) || no.as_ref().is_some_and(|n| has_group(n)),
        _ => false,
    }
}

impl Lower {
    fn set(&mut self, s: CharSet) -> u32 {
        if let Some(&id) = self.set_ids.get(&s) {
            return id;
        }
        let id = self.sets.len() as u32;
        self.sets.push(s.clone());
        self.set_ids.insert(s, id);
        id
    }

    fn look(&mut self, l: Look) -> u32 {
        self.looks.push(l);
        (self.looks.len() - 1) as u32
    }

    fn lower(&mut self, n: &Node, flags: u32) -> Result<Hir, Error> {
        let fold = fold_of(flags);
        let ascii = flags & syntax::FLAG_UNICODE == 0;
        Ok(match n {
            Node::Lit(c) => Hir::Char(self.set(charset::literal_set(*c, false, fold))),
            Node::NotLit(c) => Hir::Char(self.set(charset::literal_set(*c, true, fold))),
            Node::Class(items, neg) => Hir::Char(self.set(charset::class_set(items, *neg, fold, ascii))),
            Node::Any => Hir::Char(self.set(charset::any_set(flags & syntax::FLAG_DOTALL != 0))),
            Node::At(a) => {
                let multi = flags & syntax::FLAG_MULTILINE != 0;
                let l = match a {
                    At::Beginning if multi => Look::BeginLine,
                    At::Beginning | At::BeginningString => Look::Begin,
                    At::End if multi => Look::EndLine,
                    At::End => Look::End,
                    At::EndString => Look::EndString,
                    At::Boundary => Look::Word { ascii, negate: false },
                    At::NonBoundary => Look::Word { ascii, negate: true },
                };
                Hir::Look(self.look(l))
            }
            Node::Group(g, add, del, body) => {
                let inner = self.lower(body, combine(flags, *add, *del))?;
                match g {
                    Some(g) => Hir::Group(*g, Box::new(inner)),
                    None => inner,
                }
            }
            Node::Seq(v) => {
                let mut out = Vec::with_capacity(v.len());
                for x in v {
                    out.push(self.lower(x, flags)?);
                }
                Hir::Concat(out)
            }
            Node::Alt(v) => {
                let mut out = Vec::with_capacity(v.len());
                for x in v {
                    out.push(self.lower(x, flags)?);
                }
                Hir::Alt(out)
            }
            Node::Repeat { min, max, kind, body } => {
                if *kind == RepKind::Possessive {
                    return refuse("a possessive repeat");
                }
                let (lo, _) = py_width(body);
                if lo == 0 && *max > 1 {
                    return refuse("a repeat whose body can match the empty string (sre's zero-width iteration rules)");
                }
                let inner = self.lower(body, flags)?;
                if *min > u32::MAX as u64 || (*max != MAXREPEAT && *max > u32::MAX as u64) {
                    return refuse("a repeat count too large");
                }
                Hir::Repeat {
                    min: *min as u32,
                    max: if *max == MAXREPEAT { None } else { Some(*max as u32) },
                    greedy: *kind == RepKind::Greedy,
                    simple: is_simple(body),
                    body: Box::new(inner),
                }
            }
            Node::Look { behind, negate, body } => {
                let (lo, hi) = py_width(body);
                if *behind {
                    if lo != hi {
                        return Err(Error::Syntax("look-behind requires fixed-width pattern".into()));
                    }
                } else if hi >= MAXREPEAT {
                    return refuse("a lookahead of unbounded width");
                }
                if hi > MAX_LOOK {
                    return refuse("a lookaround wider than 1000 characters");
                }
                if !*negate && has_group(body) {
                    return refuse("a capturing group inside a positive lookaround");
                }
                if self.look_nest >= MAX_LOOK_NEST {
                    return refuse("lookarounds nested too deep");
                }
                self.look_nest += 1;
                let inner = self.lower(body, flags);
                self.look_nest -= 1;
                let inner = strip_groups(inner?);
                let l = match inner {
                    Hir::Char(set) if lo == 1 && hi == 1 => {
                        if *behind {
                            Look::Behind1 { set, negate: *negate }
                        } else {
                            Look::Ahead1 { set, negate: *negate }
                        }
                    }
                    other => Look::Around {
                        behind: *behind,
                        negate: *negate,
                        body: Box::new(other),
                        lo: lo as u32,
                        hi: hi as u32,
                    },
                };
                Hir::Look(self.look(l))
            }
            Node::Backref(_) => return refuse("a backreference (it needs what a group matched: not a regular language)"),
            Node::Cond { .. } => return refuse("a conditional group (it needs whether a group matched)"),
            Node::Atomic(_) => return refuse("an atomic group"),
            Node::Named => return refuse("a \\N{...} escape (linre has no character names)"),
        })
    }
}

/// A negative lookaround's groups never take part: they are dropped.
fn strip_groups(h: Hir) -> Hir {
    match h {
        Hir::Group(_, b) => strip_groups(*b),
        Hir::Concat(v) => {
            let mut v: Vec<Hir> = v.into_iter().map(strip_groups).collect();
            if v.len() == 1 {
                v.pop().unwrap_or(Hir::Empty)
            } else {
                Hir::Concat(v)
            }
        }
        Hir::Alt(v) => Hir::Alt(v.into_iter().map(strip_groups).collect()),
        Hir::Repeat { min, max, greedy, simple, body } => {
            Hir::Repeat { min, max, greedy, simple, body: Box::new(strip_groups(*body)) }
        }
        other => other,
    }
}

/// Lower a parsed pattern.
pub fn lower(p: &syntax::Parsed) -> Result<Lowered, Error> {
    let mut l = Lower { sets: Vec::new(), set_ids: HashMap::new(), looks: Vec::new(), look_nest: 0 };
    let hir = l.lower(&p.node, p.flags)?;
    Ok(Lowered { hir, sets: l.sets, looks: l.looks })
}

/// (min, max) width of a lowered sub-pattern, in characters (None: unbounded).
pub fn width(h: &Hir) -> (u64, Option<u64>) {
    match h {
        Hir::Empty | Hir::Look(_) => (0, Some(0)),
        Hir::Char(_) => (1, Some(1)),
        Hir::Group(_, b) => width(b),
        Hir::Concat(v) => {
            let mut lo = 0u64;
            let mut hi = Some(0u64);
            for x in v {
                let (a, b) = width(x);
                lo = lo.saturating_add(a);
                hi = match (hi, b) {
                    (Some(p), Some(q)) => Some(p.saturating_add(q)),
                    _ => None,
                };
            }
            (lo, hi)
        }
        Hir::Alt(v) => {
            let mut lo = u64::MAX;
            let mut hi = Some(0u64);
            for x in v {
                let (a, b) = width(x);
                lo = lo.min(a);
                hi = match (hi, b) {
                    (Some(p), Some(q)) => Some(p.max(q)),
                    _ => None,
                };
            }
            (if v.is_empty() { 0 } else { lo }, hi)
        }
        Hir::Repeat { min, max, body, .. } => {
            let (a, b) = width(body);
            let lo = a.saturating_mul(*min as u64);
            let hi = match (b, max) {
                (Some(0), _) => Some(0),
                (Some(q), Some(m)) => Some(q.saturating_mul(*m as u64)),
                _ => None,
            };
            (lo, hi)
        }
    }
}
