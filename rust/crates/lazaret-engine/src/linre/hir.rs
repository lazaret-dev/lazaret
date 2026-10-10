//! The parsed pattern under its flags: character sets, zero-width tests,
//! groups, alternatives and repeats; and what linre refuses.
//!
//! Flags are resolved here, item by item, as re's compiler resolves them
//! (a group's `(?i-s:…)` over the pattern's own): each character item
//! becomes the set of text characters it accepts (charset.rs), each anchor
//! the position test it compiles to, each lookaround either a test of the
//! one character before or after the position (`(?<![\w$.])`, `(?=\()`) or
//! a sub-pattern tried at the position (a lookahead wider than `MAX_LOOK`,
//! of unbounded width included, with its walks memoized: looks.rs).
//!
//! A backreference to a group of one character of a few, none of them
//! cased (`(["'])…\1`: a quote matched again) is run as one branch per
//! character (`expand_backrefs`): exact, with the group numbers kept.
//!
//! Refused, with the reason, because a linear-time matcher cannot run them
//! or cannot run them as sre does:
//! - other backreferences, and conditionals (they need what a group matched);
//! - a repeat whose body can match the empty string, other than `?` (sre
//!   stops such a loop by rules of its own: zero-width iteration checks);
//! - a capturing group inside a positive lookaround;
//! - atomic groups, possessive repeats, `\N{…}`, the TEMPLATE flag;
//! - a program too large (counted repeats are expanded) or a lookbehind
//!   wider than `MAX_LOOK`.

use super::charset::{self, CharSet, Fold};
use super::syntax::{self, At, Error, Node, RepKind, MAXREPEAT};
use std::collections::HashMap;

/// A lookbehind wider than this is refused; a lookahead that may read
/// further is walked with a memo (looks.rs).
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
                    if hi > MAX_LOOK {
                        return refuse("a lookbehind wider than 1000 characters");
                    }
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
    let node = expand_backrefs(&p.node, p.flags);
    let hir = l.lower(&node, p.flags)?;
    Ok(Lowered { hir, sets: l.sets, looks: l.looks })
}

// ------------------------------------------- backreferences to a character

/// Characters a backreferenced group may have to be run as branches.
const MAX_BACKREF_CHARS: usize = 8;

fn children(n: &Node) -> Vec<&Node> {
    match n {
        Node::Group(_, _, _, b) | Node::Atomic(b) | Node::Look { body: b, .. } | Node::Repeat { body: b, .. } => vec![b],
        Node::Seq(v) | Node::Alt(v) => v.iter().collect(),
        Node::Cond { yes, no, .. } => {
            let mut v: Vec<&Node> = vec![yes];
            if let Some(n) = no {
                v.push(n);
            }
            v
        }
        _ => Vec::new(),
    }
}

/// The paths (child indices from `n`) of the nodes `want` picks.
fn paths_to(n: &Node, want: &dyn Fn(&Node) -> bool, path: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
    if want(n) {
        out.push(path.clone());
    }
    for (k, c) in children(n).into_iter().enumerate() {
        path.push(k);
        paths_to(c, want, path, out);
        path.pop();
    }
}

fn node_at<'a>(n: &'a Node, path: &[usize]) -> &'a Node {
    path.iter().fold(n, |n, &k| children(n)[k])
}

fn node_at_mut<'a>(n: &'a mut Node, path: &[usize]) -> &'a mut Node {
    let mut n = n;
    for &k in path {
        n = match n {
            Node::Group(_, _, _, b) | Node::Atomic(b) | Node::Look { body: b, .. } | Node::Repeat { body: b, .. } => b,
            Node::Seq(v) | Node::Alt(v) => &mut v[k],
            Node::Cond { yes, no, .. } => {
                if k == 0 {
                    yes
                } else {
                    no.as_mut().expect("a path through a conditional's no")
                }
            }
            _ => unreachable!("a path below a leaf"),
        };
    }
    n
}

/// The flags in force at the end of `path` (its groups' own over the
/// pattern's), and at the node itself when it is a group.
fn flags_along(n: &Node, path: &[usize], flags: u32, inside_last: bool) -> u32 {
    let mut f = flags;
    let mut n = n;
    for (i, &k) in path.iter().enumerate() {
        if let Node::Group(_, add, del, _) = n {
            f = combine(f, *add, *del);
        }
        n = children(n)[k];
        let _ = i;
    }
    if inside_last {
        if let Node::Group(_, add, del, _) = n {
            f = combine(f, *add, *del);
        }
    }
    f
}

/// The characters of a group's body when it is one character item of a
/// few, none of them cased under the flags of the group and of each of its
/// backreferences: each matches itself alone.
fn backref_chars(body: &Node, group_flags: u32, ref_flags: &[u32]) -> Option<Vec<u32>> {
    let set = match body {
        Node::Lit(c) => charset::literal_set(*c, false, fold_of(group_flags)),
        Node::Class(items, false) => charset::class_set(items, false, fold_of(group_flags), group_flags & syntax::FLAG_UNICODE == 0),
        Node::Seq(v) if v.len() == 1 => return backref_chars(&v[0], group_flags, ref_flags),
        Node::Group(None, add, del, b) => return backref_chars(b, combine(group_flags, *add, *del), ref_flags),
        _ => return None,
    };
    let chars = set.chars_upto(MAX_BACKREF_CHARS)?;
    for &c in &chars {
        for &f in std::iter::once(&group_flags).chain(ref_flags) {
            if charset::literal_set(c, false, fold_of(f)).single() != Some(c) {
                return None;
            }
        }
    }
    Some(chars)
}

/// Every backreference to group `g` read as `c`, and the group's body made
/// `c` (its capture kept).
fn put_char(n: &mut Node, g: usize, c: u32) {
    match n {
        Node::Backref(r) if *r == g => *n = Node::Lit(c),
        Node::Group(Some(k), _, _, b) if *k == g => **b = Node::Lit(c),
        Node::Group(_, _, _, b) | Node::Atomic(b) | Node::Look { body: b, .. } | Node::Repeat { body: b, .. } => put_char(b, g, c),
        Node::Seq(v) | Node::Alt(v) => v.iter_mut().for_each(|x| put_char(x, g, c)),
        Node::Cond { yes, no, .. } => {
            put_char(yes, g, c);
            if let Some(n) = no {
                put_char(n, g, c);
            }
        }
        _ => {}
    }
}

/// One group's backreferences run as branches, when they can be: the
/// group is one character of a few, uncased (`backref_chars`), it sits at
/// the head of an item of the innermost sequence holding it and its
/// backreferences (through groups only: so it always matches when that
/// item does), and every backreference is in a later item. Items i..=j of
/// that sequence become one alternative per character c, the group made c
/// and each backreference c. At a given position the alternatives begin
/// with different characters, so at most one goes on: they take sre's
/// path, with the same spans and groups.
fn expand_one(root: &mut Node, g: usize, flags: u32) -> bool {
    let mut gpaths = Vec::new();
    paths_to(root, &|n| matches!(n, Node::Group(Some(k), ..) if *k == g), &mut Vec::new(), &mut gpaths);
    let mut rpaths = Vec::new();
    paths_to(root, &|n| matches!(n, Node::Backref(k) if *k == g), &mut Vec::new(), &mut rpaths);
    let gpath = match gpaths.as_slice() {
        [p] => p.clone(),
        _ => return false,
    };
    if rpaths.is_empty() {
        return false;
    }
    // the innermost node holding the group and every backreference
    let mut lca = 0usize;
    while lca < gpath.len() && rpaths.iter().all(|r| r.len() > lca && r[lca] == gpath[lca]) {
        lca += 1;
    }
    let seq_path = &gpath[..lca];
    let len = match node_at(root, seq_path) {
        Node::Seq(v) => v.len(),
        _ => return false,
    };
    let i = gpath[lca];
    let j = match rpaths.iter().map(|r| r[lca]).max() {
        Some(j) => j,
        None => return false,
    };
    if rpaths.iter().any(|r| r[lca] <= i) || j >= len {
        return false;
    }
    // from item i down to the group: groups (and one-item sequences) only,
    // each the head of the one above
    let mut n = node_at(root, &gpath[..=lca]);
    for &k in &gpath[lca + 1..] {
        match n {
            Node::Group(..) if k == 0 => {}
            Node::Seq(_) if k == 0 => {}
            _ => return false,
        }
        n = children(n)[k];
    }
    let body = match n {
        Node::Group(Some(_), _, _, b) => b,
        _ => return false,
    };
    let group_flags = flags_along(root, &gpath, flags, true);
    let ref_flags: Vec<u32> = rpaths.iter().map(|r| flags_along(root, r, flags, false)).collect();
    let chars = match backref_chars(body, group_flags, &ref_flags) {
        Some(c) => c,
        None => return false,
    };
    let seq = match node_at_mut(root, seq_path) {
        Node::Seq(v) => v,
        _ => return false,
    };
    let items: Vec<Node> = seq.drain(i..=j).collect();
    let branches = chars
        .iter()
        .map(|&c| {
            let mut copy = Node::Seq(items.clone());
            put_char(&mut copy, g, c);
            copy
        })
        .collect();
    seq.insert(i, Node::Alt(branches));
    true
}

/// The pattern with each backreference linre can run (see `expand_one`)
/// read as branches; any other is left for `lower` to refuse.
fn expand_backrefs(node: &Node, flags: u32) -> Node {
    let mut refs = Vec::new();
    paths_to(node, &|n| matches!(n, Node::Backref(_)), &mut Vec::new(), &mut refs);
    if refs.is_empty() {
        return node.clone();
    }
    let mut groups: Vec<usize> = refs
        .iter()
        .filter_map(|p| match node_at(node, p) {
            Node::Backref(g) => Some(*g),
            _ => None,
        })
        .collect();
    groups.sort_unstable();
    groups.dedup();
    let mut out = node.clone();
    for g in groups {
        expand_one(&mut out, g, flags);
    }
    out
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
