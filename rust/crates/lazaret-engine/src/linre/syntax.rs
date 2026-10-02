//! Python's `re` syntax, for str patterns: the pattern text to a tree.
//!
//! The tree keeps what Python's parser keeps, because some of it changes
//! what a pattern matches under IGNORECASE (charset.rs): a one-character
//! class `[x]` is the literal `x` and `[^x]` its negation; alternatives that
//! all begin with the same simple item (a literal, a class, `.`, an anchor)
//! have it taken out in front (`ab|ac` is `a(?:b|c)`); alternatives that
//! are each one literal or one class become one class (`a|[bc]` is
//! `[abc]`); a non-capturing group without flags is spliced into the
//! sequence around it. Repeats remember whether their body is a single
//! character item (sre's single-character repeat, which tests the window's
//! end before anything else: see `Guard` in nfa.rs).
//!
//! Every pattern Python rejects is rejected (`Error::Syntax`); a construct
//! linre does not run (backreferences, conditionals, atomic groups,
//! possessive repeats, `\N{…}`) is parsed, checked as Python checks it, and
//! refused by the caller (hir.rs).

use super::charset::{Category, ClassItem};

pub const FLAG_TEMPLATE: u32 = 1;
pub const FLAG_IGNORECASE: u32 = 2;
pub const FLAG_LOCALE: u32 = 4;
pub const FLAG_MULTILINE: u32 = 8;
pub const FLAG_DOTALL: u32 = 16;
pub const FLAG_UNICODE: u32 = 32;
pub const FLAG_VERBOSE: u32 = 64;
pub const FLAG_DEBUG: u32 = 128;
pub const FLAG_ASCII: u32 = 256;
const TYPE_FLAGS: u32 = FLAG_ASCII | FLAG_LOCALE | FLAG_UNICODE;

/// Python's MAXREPEAT: a repeat count at or above it is too large, and
/// `{m,}` means up to it.
pub const MAXREPEAT: u64 = 0xFFFF_FFFF;
const MAXGROUPS: usize = 0x3FFF_FFFF;
/// Nesting deeper than this is refused (Python's own parser recurses).
const MAX_NEST: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Beginning,       // ^
    BeginningString, // \A
    End,             // $
    EndString,       // \Z
    Boundary,        // \b
    NonBoundary,     // \B
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepKind {
    Greedy,
    Lazy,
    Possessive,
}

#[derive(Clone, Debug)]
pub enum Node {
    Lit(u32),
    NotLit(u32),
    Class(Vec<ClassItem>, bool),
    Any,
    At(At),
    /// a group: its number (None: not capturing), the flags it turns on and off
    Group(Option<usize>, u32, u32, Box<Node>),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Repeat { min: u64, max: u64, kind: RepKind, body: Box<Node> },
    Look { behind: bool, negate: bool, body: Box<Node> },
    Backref(usize),
    Cond { group: usize, yes: Box<Node>, no: Option<Box<Node>> },
    Atomic(Box<Node>),
    /// `\N{name}`: a character linre has no names for
    Named,
}

impl Node {
    /// Python compares the first items of alternatives by value only for
    /// items without a sub-pattern (the others are distinct objects).
    fn same_simple(&self, other: &Node) -> bool {
        match (self, other) {
            (Node::Lit(a), Node::Lit(b)) | (Node::NotLit(a), Node::NotLit(b)) => a == b,
            (Node::Class(a, na), Node::Class(b, nb)) => na == nb && a == b,
            (Node::Any, Node::Any) => true,
            (Node::At(a), Node::At(b)) => a == b,
            (Node::Backref(a), Node::Backref(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Error {
    /// Python rejects the pattern
    Syntax(String),
    /// Python accepts it; linre does not run it
    Refused(String),
}

pub struct Parsed {
    pub node: Node,
    /// capturing groups
    pub groups: usize,
    pub names: Vec<(Vec<u32>, usize)>,
    /// the pattern's flags (the argument's and the inline global ones;
    /// UNICODE unless ASCII)
    pub flags: u32,
}

struct Parser<'a> {
    p: &'a [u32],
    i: usize,
    flags: u32,
    /// groups opened so far
    groups: usize,
    /// closed[g]: group g is closed
    closed: Vec<bool>,
    names: Vec<(Vec<u32>, usize)>,
    /// while inside a lookbehind: the groups opened before it
    lookbehind_groups: Option<usize>,
    /// conditionals' group numbers, checked at the end
    cond_refs: Vec<usize>,
}

fn err<T>(msg: &str) -> Result<T, Error> {
    Err(Error::Syntax(msg.to_string()))
}

const fn ch(c: char) -> u32 {
    c as u32
}

fn is_ws(c: u32) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0A | 0x0D | 0x0B | 0x0C)
}

fn is_digit(c: u32) -> bool {
    (0x30..=0x39).contains(&c)
}

fn is_oct(c: u32) -> bool {
    (0x30..=0x37).contains(&c)
}

fn hex_val(c: u32) -> Option<u32> {
    match c {
        0x30..=0x39 => Some(c - 0x30),
        0x41..=0x46 => Some(c - 0x41 + 10),
        0x61..=0x66 => Some(c - 0x61 + 10),
        _ => None,
    }
}

fn is_ascii_letter(c: u32) -> bool {
    (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

fn flag_of(c: u32) -> Option<u32> {
    Some(match char::from_u32(c)? {
        'i' => FLAG_IGNORECASE,
        'L' => FLAG_LOCALE,
        'm' => FLAG_MULTILINE,
        's' => FLAG_DOTALL,
        'x' => FLAG_VERBOSE,
        'a' => FLAG_ASCII,
        't' => FLAG_TEMPLATE,
        'u' => FLAG_UNICODE,
        _ => return None,
    })
}

/// What one escape stands for.
enum Esc {
    Lit(u32),
    Cat(Category),
    At(At),
    Backref(usize),
    Named,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u32> {
        self.p.get(self.i).copied()
    }

    fn peek_at(&self, k: usize) -> Option<u32> {
        self.p.get(self.i + k).copied()
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(ch(c)) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    /// The next token: one character, or a backslash and the character after
    /// it (Python's tokenizer); None at the end.
    fn token(&mut self) -> Option<(u32, bool)> {
        let c = self.peek()?;
        if c == ch('\\') {
            let d = self.peek_at(1)?; // (a lone trailing backslash is rejected up front)
            self.i += 2;
            Some((d, true))
        } else {
            self.i += 1;
            Some((c, false))
        }
    }

    /// Characters up to `term` (a group name), read as tokens.
    fn until(&mut self, term: char, what: &str) -> Result<Vec<u32>, Error> {
        let mut out = Vec::new();
        loop {
            match self.token() {
                None => {
                    return if out.is_empty() { err(&format!("missing {}", what)) } else { err("unterminated name") };
                }
                Some((c, false)) if c == ch(term) => {
                    if out.is_empty() {
                        return err(&format!("missing {}", what));
                    }
                    return Ok(out);
                }
                Some((c, esc)) => {
                    if esc {
                        out.push(ch('\\'));
                    }
                    out.push(c);
                }
            }
        }
    }

    fn check_name(&self, name: &[u32]) -> Result<(), Error> {
        if !crate::pystr::is_identifier(name) {
            return err("bad character in group name");
        }
        Ok(())
    }

    fn group_closed(&self, g: usize) -> bool {
        g >= 1 && g <= self.groups && self.closed[g]
    }

    fn check_lookbehind_ref(&self, g: usize) -> Result<(), Error> {
        if let Some(before) = self.lookbehind_groups {
            if !self.group_closed(g) {
                return err("cannot refer to an open group");
            }
            if g > before {
                return err("cannot refer to group defined in the same lookbehind subpattern");
            }
        }
        Ok(())
    }

    /// The hex digits of `\x`, `\u`, `\U`.
    fn hex_escape(&mut self, n: usize) -> Result<u32, Error> {
        let mut v = 0u32;
        for _ in 0..n {
            match self.peek().and_then(hex_val) {
                Some(d) => {
                    v = v * 16 + d;
                    self.i += 1;
                }
                None => return err("incomplete escape"),
            }
        }
        Ok(v)
    }

    /// `\N{name}`: checked for its shape only (linre has no character names).
    fn named_escape(&mut self) -> Result<Esc, Error> {
        if !self.eat('{') {
            return err("missing {");
        }
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == ch('}') {
                break;
            }
            self.i += 1;
        }
        if self.peek() != Some(ch('}')) || self.i == start {
            return err("missing character name");
        }
        self.i += 1;
        Ok(Esc::Named)
    }

    /// An escape inside a class (`c`: the character after the backslash).
    fn class_escape(&mut self, c: u32) -> Result<Esc, Error> {
        Ok(match char::from_u32(c) {
            Some('d') => Esc::Cat(Category::Digit),
            Some('D') => Esc::Cat(Category::NotDigit),
            Some('s') => Esc::Cat(Category::Space),
            Some('S') => Esc::Cat(Category::NotSpace),
            Some('w') => Esc::Cat(Category::Word),
            Some('W') => Esc::Cat(Category::NotWord),
            Some('a') => Esc::Lit(7),
            Some('b') => Esc::Lit(8),
            Some('f') => Esc::Lit(12),
            Some('n') => Esc::Lit(10),
            Some('r') => Esc::Lit(13),
            Some('t') => Esc::Lit(9),
            Some('v') => Esc::Lit(11),
            Some('\\') => Esc::Lit(c),
            Some('x') => Esc::Lit(self.hex_escape(2)?),
            Some('u') => Esc::Lit(self.hex_escape(4)?),
            Some('U') => {
                let v = self.hex_escape(8)?;
                if v > 0x10FFFF {
                    return err("bad escape");
                }
                Esc::Lit(v)
            }
            Some('N') => self.named_escape()?,
            Some('0'..='7') => {
                // octal: up to three digits
                let mut v = c - 0x30;
                for _ in 0..2 {
                    match self.peek() {
                        Some(d) if is_oct(d) => {
                            v = v * 8 + (d - 0x30);
                            self.i += 1;
                        }
                        _ => break,
                    }
                }
                if v > 0o377 {
                    return err("octal escape value outside of range 0-0o377");
                }
                Esc::Lit(v)
            }
            Some('8' | '9') => return err("bad escape"),
            _ if is_ascii_letter(c) => return err("bad escape"),
            _ => Esc::Lit(c),
        })
    }

    /// An escape outside a class.
    fn escape(&mut self, c: u32) -> Result<Esc, Error> {
        Ok(match char::from_u32(c) {
            Some('A') => Esc::At(At::BeginningString),
            Some('Z') => Esc::At(At::EndString),
            Some('b') => Esc::At(At::Boundary),
            Some('B') => Esc::At(At::NonBoundary),
            Some('0') => {
                let mut v = 0u32;
                for _ in 0..2 {
                    match self.peek() {
                        Some(d) if is_oct(d) => {
                            v = v * 8 + (d - 0x30);
                            self.i += 1;
                        }
                        _ => break,
                    }
                }
                Esc::Lit(v)
            }
            Some('1'..='9') => {
                // a group reference, or an octal escape of three digits
                let mut digits = vec![c];
                if let Some(d) = self.peek().filter(|&d| is_digit(d)) {
                    self.i += 1;
                    digits.push(d);
                    if is_oct(digits[0]) && is_oct(d) {
                        if let Some(e) = self.peek().filter(|&e| is_oct(e)) {
                            self.i += 1;
                            let v = (digits[0] - 0x30) * 64 + (d - 0x30) * 8 + (e - 0x30);
                            if v > 0o377 {
                                return err("octal escape value outside of range 0-0o377");
                            }
                            return Ok(Esc::Lit(v));
                        }
                    }
                }
                let g = digits.iter().fold(0usize, |a, &d| a * 10 + (d - 0x30) as usize);
                if g <= self.groups {
                    if !self.group_closed(g) {
                        return err("cannot refer to an open group");
                    }
                    self.check_lookbehind_ref(g)?;
                    Esc::Backref(g)
                } else {
                    return err("invalid group reference");
                }
            }
            // (\b is a boundary outside a class: handled above)
            _ => self.class_escape(c)?,
        })
    }

    fn parse_class(&mut self) -> Result<Node, Error> {
        let negate = self.eat('^');
        let mut items: Vec<ClassItem> = Vec::new();
        loop {
            let (c, esc) = match self.token() {
                None => return err("unterminated character set"),
                Some(t) => t,
            };
            if !esc && c == ch(']') && !items.is_empty() {
                break;
            }
            let first = if esc { self.class_escape(c)? } else { Esc::Lit(c) };
            let first = match first {
                Esc::Named => return Err(Error::Refused("a \\N{...} escape (linre has no character names)".into())),
                e => e,
            };
            if self.peek() == Some(ch('-')) {
                self.i += 1;
                let (d, desc) = match self.token() {
                    None => return err("unterminated character set"),
                    Some(t) => t,
                };
                if !desc && d == ch(']') {
                    items.push(item_of(&first));
                    items.push(ClassItem::Lit(ch('-')));
                    break;
                }
                let second = if desc { self.class_escape(d)? } else { Esc::Lit(d) };
                let (lo, hi) = match (&first, &second) {
                    (Esc::Lit(a), Esc::Lit(b)) => (*a, *b),
                    (_, Esc::Named) | (Esc::Named, _) => {
                        return Err(Error::Refused("a \\N{...} escape (linre has no character names)".into()))
                    }
                    _ => return err("bad character range"),
                };
                if hi < lo {
                    return err("bad character range");
                }
                items.push(ClassItem::Range(lo, hi));
            } else {
                items.push(item_of(&first));
            }
        }
        // (Python's _uniq: the first of equal items, in order)
        let mut uniq: Vec<ClassItem> = Vec::with_capacity(items.len());
        for it in items {
            if !uniq.contains(&it) {
                uniq.push(it);
            }
        }
        if let [ClassItem::Lit(c)] = uniq[..] {
            return Ok(if negate { Node::NotLit(c) } else { Node::Lit(c) });
        }
        Ok(Node::Class(uniq, negate))
    }

    /// The flags of `(?…)` after its first letter (or "-").
    fn parse_flags(&mut self, first: u32) -> Result<Flags, Error> {
        let mut add = 0u32;
        let mut del = 0u32;
        let mut c = first;
        if c != ch('-') {
            loop {
                let f = match flag_of(c) {
                    Some(f) => f,
                    None => return err("unknown flag"),
                };
                if c == ch('L') {
                    return err("bad inline flag: cannot use 'L' flag with a str pattern");
                }
                add |= f;
                if f & TYPE_FLAGS != 0 && add & TYPE_FLAGS != f {
                    return err("bad inline flag: flags 'a', 'u' and 'L' are incompatible");
                }
                c = match self.peek() {
                    None => return err("missing -, : or )"),
                    Some(c) => c,
                };
                self.i += 1;
                if c == ch(')') || c == ch('-') || c == ch(':') {
                    break;
                }
                if flag_of(c).is_none() {
                    return err("unknown flag");
                }
            }
        }
        if c == ch(')') {
            if add & FLAG_TEMPLATE != 0 {
                return Err(Error::Refused("the TEMPLATE flag".into()));
            }
            return Ok(Flags::Global(add));
        }
        if add & (FLAG_DEBUG | FLAG_TEMPLATE) != 0 {
            return err("bad inline flag: cannot turn on global flag");
        }
        if c == ch('-') {
            c = match self.peek() {
                None => return err("missing flag"),
                Some(c) => c,
            };
            self.i += 1;
            if flag_of(c).is_none() {
                return err("missing flag");
            }
            loop {
                let f = flag_of(c).unwrap_or(0);
                if f & TYPE_FLAGS != 0 {
                    return err("bad inline flag: cannot turn off flags 'a', 'u' and 'L'");
                }
                del |= f;
                c = match self.peek() {
                    None => return err("missing :"),
                    Some(c) => c,
                };
                self.i += 1;
                if c == ch(':') {
                    break;
                }
                if flag_of(c).is_none() {
                    return err("missing :");
                }
            }
        }
        if del & (FLAG_DEBUG | FLAG_TEMPLATE) != 0 {
            return err("bad inline flag: cannot turn off global flag");
        }
        if add & del != 0 {
            return err("bad inline flag: flag turned on and off");
        }
        Ok(Flags::Scoped(add, del))
    }

    /// Alternatives separated by "|", up to ")" or the end.
    fn parse_alt(&mut self, verbose: bool, depth: usize) -> Result<Node, Error> {
        if depth > MAX_NEST {
            return Err(Error::Refused("nesting too deep".into()));
        }
        let mut items: Vec<Vec<Node>> = Vec::new();
        let mut verbose = verbose;
        loop {
            let first = depth == 0 && items.is_empty();
            let (seq, v) = self.parse_seq(verbose, depth, first)?;
            if first {
                // (global flags at the start may turn VERBOSE on for the rest)
                verbose = v;
            }
            items.push(seq);
            if !self.eat('|') {
                break;
            }
        }
        Ok(join_alternatives(items))
    }

    /// One alternative: items up to "|", ")" or the end. Answers the items
    /// and the VERBOSE flag in effect at its end.
    fn parse_seq(&mut self, verbose: bool, depth: usize, first: bool) -> Result<(Vec<Node>, bool), Error> {
        let mut verbose = verbose;
        let mut seq: Vec<Node> = Vec::new();
        loop {
            let c = match self.peek() {
                None => break,
                Some(c) => c,
            };
            if c == ch('|') || c == ch(')') {
                break;
            }
            self.i += 1;
            if verbose {
                if is_ws(c) {
                    continue;
                }
                if c == ch('#') {
                    // a comment, to the end of the line (read as tokens)
                    while let Some((d, esc)) = self.token() {
                        if !esc && d == 0x0A {
                            break;
                        }
                    }
                    continue;
                }
            }
            match char::from_u32(c) {
                Some('\\') => {
                    let d = match self.peek() {
                        Some(d) => d,
                        None => return err("bad escape (end of pattern)"),
                    };
                    self.i += 1;
                    seq.push(match self.escape(d)? {
                        Esc::Lit(v) => Node::Lit(v),
                        Esc::Cat(k) => Node::Class(vec![ClassItem::Cat(k)], false),
                        Esc::At(a) => Node::At(a),
                        Esc::Backref(g) => Node::Backref(g),
                        Esc::Named => Node::Named,
                    });
                }
                Some('[') => seq.push(self.parse_class()?),
                Some('*' | '+' | '?' | '{') => {
                    let here = self.i;
                    let (min, max) = match char::from_u32(c) {
                        Some('*') => (0, MAXREPEAT),
                        Some('+') => (1, MAXREPEAT),
                        Some('?') => (0, 1),
                        _ => {
                            if self.peek() == Some(ch('}')) {
                                seq.push(Node::Lit(c));
                                continue;
                            }
                            let lo = self.digits();
                            let hi = if self.eat(',') { self.digits() } else { lo };
                            if !self.eat('}') {
                                // not a repeat: a literal "{"
                                self.i = here;
                                seq.push(Node::Lit(c));
                                continue;
                            }
                            let min = match lo {
                                Some(v) if v >= MAXREPEAT => return err("the repetition number is too large"),
                                Some(v) => v,
                                None => 0,
                            };
                            let max = match hi {
                                Some(v) if v >= MAXREPEAT => return err("the repetition number is too large"),
                                Some(v) => v,
                                None => MAXREPEAT,
                            };
                            if max < min {
                                return err("min repeat greater than max repeat");
                            }
                            (min, max)
                        }
                    };
                    let item = match seq.pop() {
                        None => return err("nothing to repeat"),
                        Some(Node::At(_)) => return err("nothing to repeat"),
                        Some(Node::Repeat { .. }) => return err("multiple repeat"),
                        Some(n) => n,
                    };
                    // (a non-capturing group without flags repeats its contents)
                    let item = match item {
                        Node::Group(None, 0, 0, body) => *body,
                        n => n,
                    };
                    let kind = if self.eat('?') {
                        RepKind::Lazy
                    } else if self.eat('+') {
                        RepKind::Possessive
                    } else {
                        RepKind::Greedy
                    };
                    seq.push(Node::Repeat { min, max, kind, body: Box::new(item) });
                }
                Some('.') => seq.push(Node::Any),
                Some('^') => seq.push(Node::At(At::Beginning)),
                Some('$') => seq.push(Node::At(At::End)),
                Some('(') => {
                    if let Some(node) = self.parse_group(verbose, depth, first && seq.is_empty(), &mut verbose)? {
                        seq.push(node);
                    }
                }
                _ => seq.push(Node::Lit(c)),
            }
        }
        // (non-capturing groups without flags are spliced in)
        let mut out = Vec::with_capacity(seq.len());
        for n in seq {
            match n {
                Node::Group(None, 0, 0, body) => match *body {
                    Node::Seq(items) => out.extend(items),
                    other => out.push(other),
                },
                n => out.push(n),
            }
        }
        Ok((out, verbose))
    }

    /// Decimal digits (Python's int() of them), or None for none.
    fn digits(&mut self) -> Option<u64> {
        let start = self.i;
        let mut v: u64 = 0;
        while let Some(c) = self.peek() {
            if !is_digit(c) {
                break;
            }
            v = v.saturating_mul(10).saturating_add((c - 0x30) as u64);
            self.i += 1;
        }
        if self.i == start {
            None
        } else {
            Some(v)
        }
    }

    /// After "(": a group, an extension, flags or a comment. None for what
    /// adds nothing (a comment, global flags).
    fn parse_group(&mut self, verbose: bool, depth: usize, at_start: bool, verbose_out: &mut bool) -> Result<Option<Node>, Error> {
        let mut capture = true;
        let mut name: Option<Vec<u32>> = None;
        let mut add = 0u32;
        let mut del = 0u32;
        let mut atomic = false;
        if self.eat('?') {
            let c = match self.peek() {
                None => return err("unexpected end of pattern"),
                Some(c) => c,
            };
            self.i += 1;
            match char::from_u32(c) {
                Some('P') => {
                    if self.eat('<') {
                        let n = self.until('>', "group name")?;
                        self.check_name(&n)?;
                        name = Some(n);
                    } else if self.eat('=') {
                        let n = self.until(')', "group name")?;
                        self.check_name(&n)?;
                        let g = match self.names.iter().find(|(k, _)| *k == n) {
                            Some(&(_, g)) => g,
                            None => return err("unknown group name"),
                        };
                        if !self.group_closed(g) {
                            return err("cannot refer to an open group");
                        }
                        self.check_lookbehind_ref(g)?;
                        return Ok(Some(Node::Backref(g)));
                    } else {
                        return err("unknown extension ?P");
                    }
                }
                Some(':') => capture = false,
                Some('#') => {
                    // a comment, to ")" (read as tokens)
                    loop {
                        match self.token() {
                            None => return err("missing ), unterminated comment"),
                            Some((d, false)) if d == ch(')') => break,
                            _ => {}
                        }
                    }
                    return Ok(None);
                }
                Some('=' | '!' | '<') => {
                    let mut behind = false;
                    let mut k = c;
                    if c == ch('<') {
                        k = match self.peek() {
                            None => return err("unexpected end of pattern"),
                            Some(k) => k,
                        };
                        self.i += 1;
                        if k != ch('=') && k != ch('!') {
                            return err("unknown extension ?<");
                        }
                        behind = true;
                    }
                    let saved = self.lookbehind_groups;
                    if behind && saved.is_none() {
                        self.lookbehind_groups = Some(self.groups);
                    }
                    let body = self.parse_alt(verbose, depth + 1)?;
                    if behind {
                        self.lookbehind_groups = saved;
                    }
                    if !self.eat(')') {
                        return err("missing ), unterminated subpattern");
                    }
                    return Ok(Some(Node::Look { behind, negate: k == ch('!'), body: Box::new(body) }));
                }
                Some('(') => {
                    let cname = self.until(')', "group name")?;
                    let group = if crate::pystr::is_identifier(&cname) {
                        match self.names.iter().find(|(k, _)| *k == cname) {
                            Some(&(_, g)) => g,
                            None => return err("unknown group name"),
                        }
                    } else {
                        // a number (Python's int(): digits of any script, signs, underscores)
                        let g = match py_int(&cname) {
                            Some(g) => g,
                            None => return err("bad character in group name"),
                        };
                        if g == 0 {
                            return err("bad group number");
                        }
                        if g >= MAXGROUPS as u64 {
                            return err("invalid group reference");
                        }
                        self.cond_refs.push(g as usize);
                        g as usize
                    };
                    self.check_lookbehind_ref(group)?;
                    let (yes, _) = self.parse_seq(verbose, depth + 1, false)?;
                    let no = if self.eat('|') {
                        let (no, _) = self.parse_seq(verbose, depth + 1, false)?;
                        if self.peek() == Some(ch('|')) {
                            return err("conditional backref with more than two branches");
                        }
                        Some(Box::new(Node::Seq(no)))
                    } else {
                        None
                    };
                    if !self.eat(')') {
                        return err("missing ), unterminated subpattern");
                    }
                    return Ok(Some(Node::Cond { group, yes: Box::new(Node::Seq(yes)), no }));
                }
                Some('>') => {
                    capture = false;
                    atomic = true;
                }
                _ if flag_of(c).is_some() || c == ch('-') => match self.parse_flags(c)? {
                    Flags::Global(a) => {
                        if !at_start {
                            return err("global flags not at the start of the expression");
                        }
                        // (the global flags of the whole pattern)
                        self.flags |= a;
                        *verbose_out = self.flags & FLAG_VERBOSE != 0;
                        return Ok(None);
                    }
                    Flags::Scoped(a, d) => {
                        add = a;
                        del = d;
                        capture = false;
                    }
                },
                _ => return err("unknown extension"),
            }
        }
        let group = if capture {
            self.groups += 1;
            if self.groups > MAXGROUPS {
                return err("too many groups");
            }
            self.closed.push(false);
            if let Some(n) = name {
                if self.names.iter().any(|(k, _)| *k == n) {
                    return err("redefinition of group name");
                }
                self.names.push((n, self.groups));
            }
            Some(self.groups)
        } else {
            None
        };
        let sub_verbose = (verbose || add & FLAG_VERBOSE != 0) && del & FLAG_VERBOSE == 0;
        let body = self.parse_alt(sub_verbose, depth + 1)?;
        if !self.eat(')') {
            return err("missing ), unterminated subpattern");
        }
        if let Some(g) = group {
            self.closed[g] = true;
        }
        if atomic {
            return Ok(Some(Node::Atomic(Box::new(body))));
        }
        Ok(Some(Node::Group(group, add, del, Box::new(body))))
    }

}

/// Inline flags: global (`(?i)`) or a group's (`(?i-s:…)`).
enum Flags {
    Global(u32),
    Scoped(u32, u32),
}

/// Python's int() of a group number in a conditional (an optional sign,
/// decimal digits of any script, underscores between digits).
fn py_int(s: &[u32]) -> Option<u64> {
    let mut t: &[u32] = s;
    // (int() strips whitespace)
    while let Some((&c, rest)) = t.split_first() {
        if crate::unicode::is_space(c) {
            t = rest;
        } else {
            break;
        }
    }
    while let Some((&c, rest)) = t.split_last() {
        if crate::unicode::is_space(c) {
            t = rest;
        } else {
            break;
        }
    }
    let mut neg = false;
    if let Some((&c, rest)) = t.split_first() {
        if c == ch('+') || c == ch('-') {
            neg = c == ch('-');
            t = rest;
        }
    }
    if t.is_empty() || t[0] == ch('_') || t[t.len() - 1] == ch('_') {
        return None;
    }
    let mut v: u64 = 0;
    let mut prev_us = false;
    for &c in t {
        if c == ch('_') {
            if prev_us {
                return None;
            }
            prev_us = true;
            continue;
        }
        prev_us = false;
        let d = crate::unicode::decimal_value(c)? as u64;
        v = v.saturating_mul(10).saturating_add(d);
    }
    if neg && v != 0 {
        return None; // (a negative group number is refused as "bad character")
    }
    Some(v)
}

fn item_of(e: &Esc) -> ClassItem {
    match *e {
        Esc::Lit(c) => ClassItem::Lit(c),
        Esc::Cat(k) => ClassItem::Cat(k),
        // (the other escapes are refused inside a class before this)
        _ => ClassItem::Lit(0),
    }
}

/// Python's handling of alternatives (`_parse_sub`): a prefix all share is
/// taken out in front; alternatives of one literal or class each become a
/// class.
fn join_alternatives(mut items: Vec<Vec<Node>>) -> Node {
    if items.len() == 1 {
        return seq_node(items.pop().unwrap_or_default());
    }
    let mut prefix: Vec<Node> = Vec::new();
    loop {
        if items.iter().any(|it| it.is_empty()) {
            break;
        }
        let head = &items[0][0];
        if !items[1..].iter().all(|it| it[0].same_simple(head)) {
            break;
        }
        prefix.push(items[0][0].clone());
        for it in items.iter_mut() {
            it.remove(0);
        }
    }
    // one literal or (not negated) class each: a class
    let mut set: Vec<ClassItem> = Vec::new();
    let mut all_single = true;
    for it in &items {
        if it.len() != 1 {
            all_single = false;
            break;
        }
        match &it[0] {
            Node::Lit(c) => set.push(ClassItem::Lit(*c)),
            Node::Class(cs, false) => set.extend_from_slice(cs),
            _ => {
                all_single = false;
                break;
            }
        }
    }
    let tail = if all_single {
        let mut uniq: Vec<ClassItem> = Vec::with_capacity(set.len());
        for it in set {
            if !uniq.contains(&it) {
                uniq.push(it);
            }
        }
        Node::Class(uniq, false)
    } else {
        Node::Alt(items.into_iter().map(seq_node).collect())
    };
    if prefix.is_empty() {
        tail
    } else {
        prefix.push(tail);
        Node::Seq(prefix)
    }
}

fn seq_node(mut v: Vec<Node>) -> Node {
    if v.len() == 1 {
        v.pop().unwrap_or(Node::Seq(Vec::new()))
    } else {
        Node::Seq(v)
    }
}

/// Parse a str pattern with re.compile's `flags`.
pub fn parse(pattern: &[u32], flags: u32) -> Result<Parsed, Error> {
    if flags & FLAG_LOCALE != 0 {
        return err("cannot use LOCALE flag with a str pattern");
    }
    if flags & FLAG_ASCII != 0 && flags & FLAG_UNICODE != 0 {
        return err("ASCII and UNICODE flags are incompatible");
    }
    if flags & FLAG_TEMPLATE != 0 {
        return Err(Error::Refused("the TEMPLATE flag".into()));
    }
    // (a lone backslash at the end: Python's tokenizer rejects it before anything)
    let mut k = 0;
    while k < pattern.len() {
        if pattern[k] == ch('\\') {
            if k + 1 == pattern.len() {
                return err("bad escape (end of pattern)");
            }
            k += 2;
        } else {
            k += 1;
        }
    }
    let mut p = Parser {
        p: pattern,
        i: 0,
        flags,
        groups: 0,
        closed: vec![false],
        names: Vec::new(),
        lookbehind_groups: None,
        cond_refs: Vec::new(),
    };
    let node = p.parse_alt(flags & FLAG_VERBOSE != 0, 0)?;
    if p.i < pattern.len() {
        // (only a ")" stops the top level)
        return err("unbalanced parenthesis");
    }
    for &g in &p.cond_refs {
        if g > p.groups {
            return err("invalid group reference");
        }
    }
    let mut f = p.flags;
    if f & FLAG_LOCALE != 0 {
        return err("cannot use LOCALE flag with a str pattern");
    }
    if f & FLAG_ASCII != 0 && f & FLAG_UNICODE != 0 {
        return err("ASCII and UNICODE flags are incompatible");
    }
    if f & FLAG_ASCII == 0 {
        f |= FLAG_UNICODE;
    }
    Ok(Parsed { node, groups: p.groups, names: p.names, flags: f })
}
