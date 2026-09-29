//! Python's `re` pattern parser (re/_parser.py, CPython 3.11-3.14), ported
//! line for line: the same parse tree, the same branch and set rewrites, the
//! same widths. Only what str patterns can hold (no LOCALE, no bytes).

use super::constants::*;
use crate::unicode;

/// MAXWIDTH of _parser.py: larger than any real width.
pub const MAXWIDTH: u128 = 1u128 << 64;
/// How deeply groups may nest (Python's recursion limit plays this role there).
pub const MAX_NESTING: usize = 200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SetItem {
    Literal(u32),
    Range(u32, u32),
    Category(u32),
    Negate,
}

#[derive(Clone, Debug)]
pub enum Node {
    Literal(u32),
    NotLiteral(u32),
    Any,
    In(Vec<SetItem>),
    At(u32),
    Category(u32),
    Branch(Vec<SubPattern>),
    Subpattern { group: Option<usize>, add: u32, del: u32, p: SubPattern },
    Atomic(SubPattern),
    Repeat { kind: RepeatKind, min: u32, max: u32, item: SubPattern },
    GroupRef(usize),
    GroupRefExists { group: usize, yes: SubPattern, no: Option<SubPattern> },
    Assert { dir: i32, p: SubPattern },
    AssertNot { dir: i32, p: SubPattern },
    Failure,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepeatKind {
    Max,
    Min,
    Possessive,
}

impl Node {
    /// Python's `item[0] != prefix` in _parse_sub: tuples compare by value,
    /// but a SubPattern only equals itself, so a node holding one never
    /// equals another node.
    fn same(&self, other: &Node) -> bool {
        match (self, other) {
            (Node::Literal(a), Node::Literal(b)) => a == b,
            (Node::NotLiteral(a), Node::NotLiteral(b)) => a == b,
            (Node::Any, Node::Any) => true,
            (Node::In(a), Node::In(b)) => a == b,
            (Node::At(a), Node::At(b)) => a == b,
            (Node::Category(a), Node::Category(b)) => a == b,
            (Node::GroupRef(a), Node::GroupRef(b)) => a == b,
            (Node::Failure, Node::Failure) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SubPattern {
    pub data: Vec<Node>,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub msg: String,
    pub pos: usize,
}

type R<T> = Result<T, Error>;

pub struct State {
    pub flags: u32,
    pub groupdict: Vec<(Vec<u32>, usize)>,
    pub groupwidths: Vec<Option<(u128, u128)>>,
    lookbehindgroups: Option<usize>,
    grouprefpos: Vec<(usize, usize)>,
}

impl State {
    fn new(flags: u32) -> Self {
        State { flags, groupdict: Vec::new(), groupwidths: vec![None], lookbehindgroups: None, grouprefpos: Vec::new() }
    }
    pub fn groups(&self) -> usize {
        self.groupwidths.len()
    }
    fn opengroup(&mut self, name: Option<Vec<u32>>) -> Result<usize, String> {
        let gid = self.groups();
        self.groupwidths.push(None);
        if self.groups() > MAXGROUPS {
            return Err("too many groups".into());
        }
        if let Some(name) = name {
            if self.groupdict.iter().any(|(n, _)| *n == name) {
                return Err("redefinition of group name".into());
            }
            self.groupdict.push((name, gid));
        }
        Ok(gid)
    }
    fn closegroup(&mut self, gid: usize, p: &SubPattern) {
        let w = p.getwidth(self);
        self.groupwidths[gid] = Some(w);
    }
    fn checkgroup(&self, gid: usize) -> bool {
        gid < self.groups() && self.groupwidths[gid].is_some()
    }
    fn checklookbehindgroup(&self, gid: usize, source: &Tokenizer) -> R<()> {
        if let Some(lb) = self.lookbehindgroups {
            if !self.checkgroup(gid) {
                return Err(source.error("cannot refer to an open group", 0));
            }
            if gid >= lb {
                return Err(source.error("cannot refer to group defined in the same lookbehind subpattern", 0));
            }
        }
        Ok(())
    }
    pub fn group_index(&self, name: &[u32]) -> Option<usize> {
        self.groupdict.iter().find(|(n, _)| n == name).map(|&(_, g)| g)
    }
}

impl SubPattern {
    fn new() -> Self {
        SubPattern { data: Vec::new() }
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// (min, max) width, as SubPattern.getwidth().
    pub fn getwidth(&self, state: &State) -> (u128, u128) {
        let mut lo: u128 = 0;
        let mut hi: u128 = 0;
        for node in &self.data {
            match node {
                Node::Branch(items) => {
                    let mut i = MAXWIDTH;
                    let mut j = 0;
                    for av in items {
                        let (l, h) = av.getwidth(state);
                        i = i.min(l);
                        j = j.max(h);
                    }
                    lo = lo.saturating_add(i);
                    hi = hi.saturating_add(j);
                }
                Node::Atomic(p) => {
                    let (i, j) = p.getwidth(state);
                    lo = lo.saturating_add(i);
                    hi = hi.saturating_add(j);
                }
                Node::Subpattern { p, .. } => {
                    let (i, j) = p.getwidth(state);
                    lo = lo.saturating_add(i);
                    hi = hi.saturating_add(j);
                }
                Node::Repeat { min, max, item, .. } => {
                    let (i, j) = item.getwidth(state);
                    lo = lo.saturating_add(i.saturating_mul(*min as u128));
                    if *max == MAXREPEAT && j != 0 {
                        hi = MAXWIDTH;
                    } else {
                        hi = hi.saturating_add(j.saturating_mul(*max as u128));
                    }
                }
                Node::Any | Node::In(_) | Node::Literal(_) | Node::NotLiteral(_) | Node::Category(_) => {
                    lo = lo.saturating_add(1);
                    hi = hi.saturating_add(1);
                }
                Node::GroupRef(g) => {
                    let (i, j) = state.groupwidths.get(*g).copied().flatten().unwrap_or((0, 0));
                    lo = lo.saturating_add(i);
                    hi = hi.saturating_add(j);
                }
                Node::GroupRefExists { yes, no, .. } => {
                    let (mut i, mut j) = yes.getwidth(state);
                    if let Some(no) = no {
                        let (l, h) = no.getwidth(state);
                        i = i.min(l);
                        j = j.max(h);
                    } else {
                        i = 0;
                    }
                    lo = lo.saturating_add(i);
                    hi = hi.saturating_add(j);
                }
                // AT, ASSERT, ASSERT_NOT, FAILURE add nothing; SUCCESS never occurs here
                _ => {}
            }
        }
        (lo.min(MAXWIDTH), hi.min(MAXWIDTH))
    }
}

/// One token: a character, or a backslash and the character after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Ch(u32),
    Esc(u32),
}

struct Tokenizer<'a> {
    s: &'a [u32],
    index: usize,
    next: Option<Tok>,
}

const fn ch(c: char) -> u32 {
    c as u32
}

fn is_digit(c: u32) -> bool {
    (ch('0')..=ch('9')).contains(&c)
}
fn is_octdigit(c: u32) -> bool {
    (ch('0')..=ch('7')).contains(&c)
}
fn is_hexdigit(c: u32) -> bool {
    is_digit(c) || (ch('a')..=ch('f')).contains(&c) || (ch('A')..=ch('F')).contains(&c)
}
fn is_asciiletter(c: u32) -> bool {
    (ch('a')..=ch('z')).contains(&c) || (ch('A')..=ch('Z')).contains(&c)
}
fn is_whitespace(c: u32) -> bool {
    matches!(c, 0x20 | 0x09 | 0x0A | 0x0D | 0x0B | 0x0C)
}
fn is_special(c: u32) -> bool {
    ".\\[{()*+?^$|".chars().any(|x| x as u32 == c)
}
fn is_repeat_char(c: u32) -> bool {
    "*+?{".chars().any(|x| x as u32 == c)
}

impl<'a> Tokenizer<'a> {
    fn new(s: &'a [u32]) -> R<Self> {
        let mut t = Tokenizer { s, index: 0, next: None };
        t.advance()?;
        Ok(t)
    }
    fn advance(&mut self) -> R<()> {
        let index = self.index;
        if index >= self.s.len() {
            self.next = None;
            return Ok(());
        }
        let c = self.s[index];
        if c == ch('\\') {
            if index + 1 >= self.s.len() {
                return Err(Error { msg: "bad escape (end of pattern)".into(), pos: self.s.len().saturating_sub(1) });
            }
            self.next = Some(Tok::Esc(self.s[index + 1]));
            self.index = index + 2;
        } else {
            self.next = Some(Tok::Ch(c));
            self.index = index + 1;
        }
        Ok(())
    }
    fn matches(&mut self, c: char) -> R<bool> {
        if self.next == Some(Tok::Ch(c as u32)) {
            self.advance()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn get(&mut self) -> R<Option<Tok>> {
        let this = self.next;
        self.advance()?;
        Ok(this)
    }
    /// The next single character, when the next token is one.
    fn next_ch(&self) -> Option<u32> {
        match self.next {
            Some(Tok::Ch(c)) => Some(c),
            _ => None,
        }
    }
    fn getwhile(&mut self, n: usize, pred: fn(u32) -> bool) -> R<Vec<u32>> {
        let mut out = Vec::new();
        for _ in 0..n {
            match self.next_ch() {
                Some(c) if pred(c) => {
                    out.push(c);
                    self.advance()?;
                }
                _ => break,
            }
        }
        Ok(out)
    }
    fn getuntil(&mut self, terminator: char, name: &str) -> R<Vec<u32>> {
        let mut result: Vec<u32> = Vec::new();
        loop {
            let c = self.next;
            self.advance()?;
            match c {
                None => {
                    return Err(if result.is_empty() {
                        self.error(&format!("missing {}", name), 0)
                    } else {
                        self.error(&format!("missing {}, unterminated name", terminator), result.len())
                    });
                }
                Some(Tok::Ch(x)) if x == terminator as u32 => {
                    if result.is_empty() {
                        return Err(self.error(&format!("missing {}", name), 1));
                    }
                    break;
                }
                Some(Tok::Ch(x)) => result.push(x),
                Some(Tok::Esc(x)) => {
                    result.push(ch('\\'));
                    result.push(x);
                }
            }
        }
        Ok(result)
    }
    fn tell(&self) -> usize {
        let len = match self.next {
            None => 0,
            Some(Tok::Ch(_)) => 1,
            Some(Tok::Esc(_)) => 2,
        };
        self.index - len
    }
    fn seek(&mut self, index: usize) -> R<()> {
        self.index = index;
        self.advance()
    }
    fn error(&self, msg: &str, offset: usize) -> Error {
        Error { msg: msg.into(), pos: self.tell().saturating_sub(offset) }
    }
    fn checkgroupname(&self, name: &[u32], offset: usize) -> R<()> {
        if !crate::pystr::is_identifier(name) {
            return Err(self.error("bad character in group name", name.len() + offset));
        }
        Ok(())
    }
}

enum Code {
    Node(Node),
}

fn escapes(c: u32) -> Option<u32> {
    match char::from_u32(c)? {
        'a' => Some(7),
        'b' => Some(8),
        'f' => Some(12),
        'n' => Some(10),
        'r' => Some(13),
        't' => Some(9),
        'v' => Some(11),
        '\\' => Some(ch('\\')),
        _ => None,
    }
}

/// CATEGORIES: \A \b \B \d \D \s \S \w \W \Z.
fn categories(c: u32) -> Option<Node> {
    Some(match char::from_u32(c)? {
        'A' => Node::At(AT_BEGINNING_STRING),
        'b' => Node::At(AT_BOUNDARY),
        'B' => Node::At(AT_NON_BOUNDARY),
        'd' => Node::In(vec![SetItem::Category(CATEGORY_DIGIT)]),
        'D' => Node::In(vec![SetItem::Category(CATEGORY_NOT_DIGIT)]),
        's' => Node::In(vec![SetItem::Category(CATEGORY_SPACE)]),
        'S' => Node::In(vec![SetItem::Category(CATEGORY_NOT_SPACE)]),
        'w' => Node::In(vec![SetItem::Category(CATEGORY_WORD)]),
        'W' => Node::In(vec![SetItem::Category(CATEGORY_NOT_WORD)]),
        'Z' => Node::At(AT_END_STRING),
        _ => return None,
    })
}

fn hexval(ds: &[u32]) -> u32 {
    ds.iter().fold(0u32, |a, &d| {
        let v = match d {
            0x30..=0x39 => d - 0x30,
            0x61..=0x66 => d - 0x61 + 10,
            _ => d - 0x41 + 10,
        };
        a.wrapping_mul(16).wrapping_add(v)
    })
}

fn octval(ds: &[u32]) -> u32 {
    ds.iter().fold(0u32, |a, &d| a * 8 + (d - 0x30))
}

fn decval(ds: &[u32]) -> u64 {
    ds.iter().fold(0u64, |a, &d| a.saturating_mul(10).saturating_add((d - 0x30) as u64))
}

/// The escapes shared by _class_escape and _escape after their tables:
/// \x \u \U (and \N, not supported). Some(literal) or None to go on.
fn hex_escape(source: &mut Tokenizer, c: u32) -> R<Option<u32>> {
    let (n, total) = match char::from_u32(c) {
        Some('x') => (2, 4),
        Some('u') => (4, 6),
        Some('U') => (8, 10),
        Some('N') => return Err(source.error("\\N{…} escapes are not supported by the Rust engine", 2)),
        _ => return Ok(None),
    };
    let ds = source.getwhile(n, is_hexdigit)?;
    if ds.len() + 2 != total {
        return Err(source.error("incomplete escape", ds.len() + 2));
    }
    let v = hexval(&ds);
    if c == ch('U') && v > 0x10FFFF {
        return Err(source.error("bad escape", total));
    }
    Ok(Some(v))
}

fn class_escape(source: &mut Tokenizer, c: u32) -> R<Code> {
    if let Some(v) = escapes(c) {
        return Ok(Code::Node(Node::Literal(v)));
    }
    if let Some(Node::In(items)) = categories(c) {
        return Ok(Code::Node(Node::In(items)));
    }
    if let Some(v) = hex_escape(source, c)? {
        return Ok(Code::Node(Node::Literal(v)));
    }
    if is_octdigit(c) {
        let mut ds = vec![c];
        ds.extend(source.getwhile(2, is_octdigit)?);
        let v = octval(&ds);
        if v > 0o377 {
            return Err(source.error("octal escape value outside of range 0-0o377", ds.len() + 1));
        }
        return Ok(Code::Node(Node::Literal(v)));
    }
    if is_digit(c) || is_asciiletter(c) {
        return Err(source.error("bad escape", 2));
    }
    Ok(Code::Node(Node::Literal(c)))
}

fn escape(source: &mut Tokenizer, c: u32, state: &State) -> R<Node> {
    if let Some(node) = categories(c) {
        return Ok(node);
    }
    if let Some(v) = escapes(c) {
        return Ok(Node::Literal(v));
    }
    if let Some(v) = hex_escape(source, c)? {
        return Ok(Node::Literal(v));
    }
    if c == ch('0') {
        let mut ds = vec![c];
        ds.extend(source.getwhile(2, is_octdigit)?);
        return Ok(Node::Literal(octval(&ds)));
    }
    if is_digit(c) {
        let mut ds = vec![c];
        if let Some(n) = source.next_ch().filter(|&n| is_digit(n)) {
            source.advance()?;
            ds.push(n);
            if is_octdigit(ds[0]) && is_octdigit(ds[1]) {
                if let Some(n3) = source.next_ch().filter(|&n| is_octdigit(n)) {
                    source.advance()?;
                    ds.push(n3);
                    let v = octval(&ds);
                    if v > 0o377 {
                        return Err(source.error("octal escape value outside of range 0-0o377", ds.len() + 1));
                    }
                    return Ok(Node::Literal(v));
                }
            }
        }
        let group = decval(&ds) as usize;
        if group < state.groups() {
            if !state.checkgroup(group) {
                return Err(source.error("cannot refer to an open group", ds.len() + 1));
            }
            state.checklookbehindgroup(group, source)?;
            return Ok(Node::GroupRef(group));
        }
        return Err(source.error("invalid group reference", ds.len()));
    }
    if is_asciiletter(c) {
        return Err(source.error("bad escape", 2));
    }
    Ok(Node::Literal(c))
}

fn uniq(items: Vec<SetItem>) -> Vec<SetItem> {
    let mut out: Vec<SetItem> = Vec::with_capacity(items.len());
    for it in items {
        if !out.contains(&it) {
            out.push(it);
        }
    }
    out
}

fn parse_sub(source: &mut Tokenizer, state: &mut State, mut verbose: bool, nested: usize) -> R<SubPattern> {
    if nested > MAX_NESTING {
        return Err(source.error("too deeply nested", 0));
    }
    let mut items: Vec<SubPattern> = Vec::new();
    loop {
        let first = nested == 0 && items.is_empty();
        items.push(parse(source, state, verbose, nested + 1, first)?);
        if !source.matches('|')? {
            break;
        }
        if nested == 0 {
            verbose = state.flags & FLAG_VERBOSE != 0;
        }
    }
    if items.len() == 1 {
        return Ok(items.pop().unwrap_or_default());
    }
    let mut subpattern = SubPattern::new();
    // check if all items share a common prefix
    loop {
        let mut prefix: Option<Node> = None;
        let mut all = true;
        for item in &items {
            match item.data.first() {
                None => {
                    all = false;
                    break;
                }
                Some(first) => match &prefix {
                    None => prefix = Some(first.clone()),
                    Some(p) => {
                        if !first.same(p) {
                            all = false;
                            break;
                        }
                    }
                },
            }
        }
        if all {
            for item in items.iter_mut() {
                item.data.remove(0);
            }
            if let Some(p) = prefix {
                subpattern.data.push(p);
            }
            continue;
        }
        break;
    }
    // check if the branch can be replaced by a character set
    let mut set: Vec<SetItem> = Vec::new();
    let mut ok = true;
    for item in &items {
        if item.data.len() != 1 {
            ok = false;
            break;
        }
        match &item.data[0] {
            Node::Literal(c) => set.push(SetItem::Literal(*c)),
            Node::In(av) if av.first() != Some(&SetItem::Negate) => set.extend(av.iter().cloned()),
            _ => {
                ok = false;
                break;
            }
        }
    }
    if ok {
        subpattern.data.push(Node::In(uniq(set)));
        return Ok(subpattern);
    }
    subpattern.data.push(Node::Branch(items));
    Ok(subpattern)
}

fn parse(source: &mut Tokenizer, state: &mut State, mut verbose: bool, nested: usize, first: bool) -> R<SubPattern> {
    let mut subpattern = SubPattern::new();
    loop {
        let this = match source.next {
            None => break,
            Some(t) => t,
        };
        if this == Tok::Ch(ch('|')) || this == Tok::Ch(ch(')')) {
            break;
        }
        source.get()?;
        if verbose {
            if let Tok::Ch(c) = this {
                if is_whitespace(c) {
                    continue;
                }
                if c == ch('#') {
                    loop {
                        match source.get()? {
                            None => break,
                            Some(Tok::Ch(0x0A)) => break,
                            _ => {}
                        }
                    }
                    continue;
                }
            }
        }
        let c = match this {
            Tok::Esc(e) => {
                subpattern.data.push(escape(source, e, state)?);
                continue;
            }
            Tok::Ch(c) => c,
        };
        if !is_special(c) {
            subpattern.data.push(Node::Literal(c));
        } else if c == ch('[') {
            let here = source.tell() - 1;
            let mut set: Vec<SetItem> = Vec::new();
            let negate = source.matches('^')?;
            loop {
                let this = match source.get()? {
                    None => return Err(source.error("unterminated character set", source.tell() - here)),
                    Some(t) => t,
                };
                if this == Tok::Ch(ch(']')) && !set.is_empty() {
                    break;
                }
                let code1 = match this {
                    Tok::Esc(e) => class_escape(source, e)?,
                    Tok::Ch(x) => Code::Node(Node::Literal(x)),
                };
                if source.matches('-')? {
                    let that = match source.get()? {
                        None => return Err(source.error("unterminated character set", source.tell() - here)),
                        Some(t) => t,
                    };
                    if that == Tok::Ch(ch(']')) {
                        set.push(to_set_item(code1));
                        set.push(SetItem::Literal(ch('-')));
                        break;
                    }
                    let code2 = match that {
                        Tok::Esc(e) => class_escape(source, e)?,
                        Tok::Ch(x) => Code::Node(Node::Literal(x)),
                    };
                    let (lo, hi) = match (code1, code2) {
                        (Code::Node(Node::Literal(lo)), Code::Node(Node::Literal(hi))) => (lo, hi),
                        _ => return Err(source.error("bad character range", 3)),
                    };
                    if hi < lo {
                        return Err(source.error("bad character range", 3));
                    }
                    set.push(SetItem::Range(lo, hi));
                } else {
                    set.push(to_set_item(code1));
                }
            }
            let mut set = uniq(set);
            if set.len() == 1 {
                if let SetItem::Literal(x) = set[0] {
                    subpattern.data.push(if negate { Node::NotLiteral(x) } else { Node::Literal(x) });
                    continue;
                }
            }
            if negate {
                set.insert(0, SetItem::Negate);
            }
            subpattern.data.push(Node::In(set));
        } else if is_repeat_char(c) {
            let here = source.tell();
            let (min, max): (u32, u32);
            if c == ch('?') {
                min = 0;
                max = 1;
            } else if c == ch('*') {
                min = 0;
                max = MAXREPEAT;
            } else if c == ch('+') {
                min = 1;
                max = MAXREPEAT;
            } else {
                // '{'
                if source.next == Some(Tok::Ch(ch('}'))) {
                    subpattern.data.push(Node::Literal(c));
                    continue;
                }
                let mut lo: Vec<u32> = Vec::new();
                let mut hi: Vec<u32> = Vec::new();
                while let Some(d) = source.next_ch().filter(|&d| is_digit(d)) {
                    source.advance()?;
                    lo.push(d);
                }
                if source.matches(',')? {
                    while let Some(d) = source.next_ch().filter(|&d| is_digit(d)) {
                        source.advance()?;
                        hi.push(d);
                    }
                } else {
                    hi = lo.clone();
                }
                if !source.matches('}')? {
                    subpattern.data.push(Node::Literal(c));
                    source.seek(here)?;
                    continue;
                }
                let mut mn = 0u32;
                let mut mx = MAXREPEAT;
                if !lo.is_empty() {
                    let v = decval(&lo);
                    if v >= MAXREPEAT as u64 {
                        return Err(source.error("the repetition number is too large", 0));
                    }
                    mn = v as u32;
                }
                if !hi.is_empty() {
                    let v = decval(&hi);
                    if v >= MAXREPEAT as u64 {
                        return Err(source.error("the repetition number is too large", 0));
                    }
                    mx = v as u32;
                    if mx < mn {
                        return Err(source.error("min repeat greater than max repeat", source.tell() - here));
                    }
                }
                min = mn;
                max = mx;
            }
            // figure out which item to repeat
            let last = match subpattern.data.last() {
                None => return Err(source.error("nothing to repeat", source.tell() - here + 1)),
                Some(n) => n.clone(),
            };
            let item = match last {
                Node::At(_) => return Err(source.error("nothing to repeat", source.tell() - here + 1)),
                Node::Repeat { .. } => return Err(source.error("multiple repeat", source.tell() - here + 1)),
                Node::Subpattern { group: None, add: 0, del: 0, p } => p,
                other => SubPattern { data: vec![other] },
            };
            let kind = if source.matches('?')? {
                RepeatKind::Min
            } else if source.matches('+')? {
                RepeatKind::Possessive
            } else {
                RepeatKind::Max
            };
            if let Some(slot) = subpattern.data.last_mut() {
                *slot = Node::Repeat { kind, min, max, item };
            }
        } else if c == ch('.') {
            subpattern.data.push(Node::Any);
        } else if c == ch('(') {
            let start = source.tell() - 1;
            let mut capture = true;
            let mut atomic = false;
            let mut name: Option<Vec<u32>> = None;
            let mut add_flags = 0u32;
            let mut del_flags = 0u32;
            if source.matches('?')? {
                let chr = match source.get()? {
                    None => return Err(source.error("unexpected end of pattern", 0)),
                    Some(t) => t,
                };
                match chr {
                    Tok::Ch(0x50) => {
                        // 'P'
                        if source.matches('<')? {
                            let n = source.getuntil('>', "group name")?;
                            source.checkgroupname(&n, 1)?;
                            name = Some(n);
                        } else if source.matches('=')? {
                            let n = source.getuntil(')', "group name")?;
                            source.checkgroupname(&n, 1)?;
                            let gid = match state.group_index(&n) {
                                None => return Err(source.error("unknown group name", n.len() + 1)),
                                Some(g) => g,
                            };
                            if !state.checkgroup(gid) {
                                return Err(source.error("cannot refer to an open group", n.len() + 1));
                            }
                            state.checklookbehindgroup(gid, source)?;
                            subpattern.data.push(Node::GroupRef(gid));
                            continue;
                        } else {
                            return Err(source.error("unknown extension ?P", 3));
                        }
                    }
                    Tok::Ch(0x3A) => capture = false, // ':'
                    Tok::Ch(0x23) => {
                        // '#': comment
                        loop {
                            if source.next.is_none() {
                                return Err(source.error("missing ), unterminated comment", source.tell() - start));
                            }
                            if source.get()? == Some(Tok::Ch(ch(')'))) {
                                break;
                            }
                        }
                        continue;
                    }
                    Tok::Ch(x) if x == ch('=') || x == ch('!') || x == ch('<') => {
                        let mut dir = 1;
                        let mut kindc = x;
                        let mut saved_lb: Option<usize> = None;
                        if x == ch('<') {
                            let c2 = match source.get()? {
                                None => return Err(source.error("unexpected end of pattern", 0)),
                                Some(t) => t,
                            };
                            match c2 {
                                Tok::Ch(y) if y == ch('=') || y == ch('!') => kindc = y,
                                _ => return Err(source.error("unknown extension ?<", 3)),
                            }
                            dir = -1;
                            saved_lb = state.lookbehindgroups;
                            if saved_lb.is_none() {
                                state.lookbehindgroups = Some(state.groups());
                            }
                        }
                        let p = parse_sub(source, state, verbose, nested + 1)?;
                        if dir < 0 && saved_lb.is_none() {
                            state.lookbehindgroups = None;
                        }
                        if !source.matches(')')? {
                            return Err(source.error("missing ), unterminated subpattern", source.tell() - start));
                        }
                        if kindc == ch('=') {
                            subpattern.data.push(Node::Assert { dir, p });
                        } else if !p.is_empty() {
                            subpattern.data.push(Node::AssertNot { dir, p });
                        } else {
                            subpattern.data.push(Node::Failure);
                        }
                        continue;
                    }
                    Tok::Ch(0x28) => {
                        // '(': conditional backreference group
                        let condname = source.getuntil(')', "group name")?;
                        let condgroup;
                        if !(condname.iter().all(|&d| is_digit(d))) {
                            source.checkgroupname(&condname, 1)?;
                            condgroup = match state.group_index(&condname) {
                                None => return Err(source.error("unknown group name", condname.len() + 1)),
                                Some(g) => g,
                            };
                        } else {
                            let g = decval(&condname);
                            if g == 0 {
                                return Err(source.error("bad group number", condname.len() + 1));
                            }
                            if g >= MAXGROUPS as u64 {
                                return Err(source.error("invalid group reference", condname.len() + 1));
                            }
                            condgroup = g as usize;
                            if !state.grouprefpos.iter().any(|&(k, _)| k == condgroup) {
                                let pos = source.tell() - condname.len() - 1;
                                state.grouprefpos.push((condgroup, pos));
                            }
                        }
                        state.checklookbehindgroup(condgroup, source)?;
                        let yes = parse(source, state, verbose, nested + 1, false)?;
                        let no = if source.matches('|')? {
                            let no = parse(source, state, verbose, nested + 1, false)?;
                            if source.next == Some(Tok::Ch(ch('|'))) {
                                return Err(source.error("conditional backref with more than two branches", 0));
                            }
                            Some(no)
                        } else {
                            None
                        };
                        if !source.matches(')')? {
                            return Err(source.error("missing ), unterminated subpattern", source.tell() - start));
                        }
                        subpattern.data.push(Node::GroupRefExists { group: condgroup, yes, no });
                        continue;
                    }
                    Tok::Ch(0x3E) => {
                        // '>'
                        capture = false;
                        atomic = true;
                    }
                    Tok::Ch(x) if flag_bit(x).is_some() || x == ch('-') => {
                        match parse_flags(source, state, x)? {
                            None => {
                                if !first || !subpattern.is_empty() {
                                    return Err(source.error(
                                        "global flags not at the start of the expression",
                                        source.tell() - start,
                                    ));
                                }
                                verbose = state.flags & FLAG_VERBOSE != 0;
                                continue;
                            }
                            Some((a, d)) => {
                                add_flags = a;
                                del_flags = d;
                                capture = false;
                            }
                        }
                    }
                    _ => return Err(source.error("unknown extension", 2)),
                }
            }
            let group = if capture {
                match state.opengroup(name) {
                    Ok(g) => Some(g),
                    Err(m) => return Err(source.error(&m, 1)),
                }
            } else {
                None
            };
            let sub_verbose = (verbose || add_flags & FLAG_VERBOSE != 0) && del_flags & FLAG_VERBOSE == 0;
            let p = parse_sub(source, state, sub_verbose, nested + 1)?;
            if !source.matches(')')? {
                return Err(source.error("missing ), unterminated subpattern", source.tell() - start));
            }
            if let Some(g) = group {
                state.closegroup(g, &p);
            }
            if atomic {
                subpattern.data.push(Node::Atomic(p));
            } else {
                subpattern.data.push(Node::Subpattern { group, add: add_flags, del: del_flags, p });
            }
        } else if c == ch('^') {
            subpattern.data.push(Node::At(AT_BEGINNING));
        } else if c == ch('$') {
            subpattern.data.push(Node::At(AT_END));
        } else {
            return Err(source.error("unsupported special character", 1));
        }
    }
    // unpack non-capturing groups
    let mut i = subpattern.data.len();
    while i > 0 {
        i -= 1;
        let unpack = matches!(&subpattern.data[i], Node::Subpattern { group: None, add: 0, del: 0, .. });
        if unpack {
            if let Node::Subpattern { p, .. } = subpattern.data.remove(i) {
                for (k, n) in p.data.into_iter().enumerate() {
                    subpattern.data.insert(i + k, n);
                }
            }
        }
    }
    Ok(subpattern)
}

fn to_set_item(code: Code) -> SetItem {
    match code {
        Code::Node(Node::Literal(x)) => SetItem::Literal(x),
        Code::Node(Node::In(items)) => items.into_iter().next().unwrap_or(SetItem::Negate),
        Code::Node(_) => SetItem::Negate,
    }
}

fn flag_bit(c: u32) -> Option<u32> {
    match char::from_u32(c)? {
        'i' => Some(FLAG_IGNORECASE),
        'L' => Some(FLAG_LOCALE),
        'm' => Some(FLAG_MULTILINE),
        's' => Some(FLAG_DOTALL),
        'x' => Some(FLAG_VERBOSE),
        'a' => Some(FLAG_ASCII),
        'u' => Some(FLAG_UNICODE),
        _ => None,
    }
}

fn parse_flags(source: &mut Tokenizer, state: &mut State, mut c: u32) -> R<Option<(u32, u32)>> {
    let mut add_flags = 0u32;
    let mut del_flags = 0u32;
    if c != ch('-') {
        loop {
            let flag = flag_bit(c).unwrap_or(0);
            if c == ch('L') {
                return Err(source.error("bad inline flags: cannot use 'L' flag with a str pattern", 0));
            }
            add_flags |= flag;
            if flag & TYPE_FLAGS != 0 && add_flags & TYPE_FLAGS != flag {
                return Err(source.error("bad inline flags: flags 'a', 'u' and 'L' are incompatible", 0));
            }
            c = match source.get()? {
                None => return Err(source.error("missing -, : or )", 0)),
                Some(Tok::Ch(x)) => x,
                Some(Tok::Esc(_)) => return Err(source.error("missing -, : or )", 2)),
            };
            if c == ch(')') || c == ch('-') || c == ch(':') {
                break;
            }
            if flag_bit(c).is_none() {
                return Err(source.error("unknown flag", 1));
            }
        }
    }
    if c == ch(')') {
        state.flags |= add_flags;
        return Ok(None);
    }
    if add_flags & GLOBAL_FLAGS != 0 {
        return Err(source.error("bad inline flags: cannot turn on global flag", 1));
    }
    if c == ch('-') {
        c = match source.get()? {
            None => return Err(source.error("missing flag", 0)),
            Some(Tok::Ch(x)) => x,
            Some(Tok::Esc(_)) => return Err(source.error("missing flag", 2)),
        };
        if flag_bit(c).is_none() {
            return Err(source.error("unknown flag", 1));
        }
        loop {
            let flag = flag_bit(c).unwrap_or(0);
            if flag & TYPE_FLAGS != 0 {
                return Err(source.error("bad inline flags: cannot turn off flags 'a', 'u' and 'L'", 0));
            }
            del_flags |= flag;
            c = match source.get()? {
                None => return Err(source.error("missing :", 0)),
                Some(Tok::Ch(x)) => x,
                Some(Tok::Esc(_)) => return Err(source.error("missing :", 2)),
            };
            if c == ch(':') {
                break;
            }
            if flag_bit(c).is_none() {
                return Err(source.error("unknown flag", 1));
            }
        }
    }
    if del_flags & GLOBAL_FLAGS != 0 {
        return Err(source.error("bad inline flags: cannot turn off global flag", 1));
    }
    if add_flags & del_flags != 0 {
        return Err(source.error("bad inline flags: flag turned on and off", 1));
    }
    Ok(Some((add_flags, del_flags)))
}

fn fix_flags(flags: u32) -> Result<u32, Error> {
    if flags & FLAG_LOCALE != 0 {
        return Err(Error { msg: "cannot use LOCALE flag with a str pattern".into(), pos: 0 });
    }
    if flags & FLAG_ASCII == 0 {
        Ok(flags | FLAG_UNICODE)
    } else if flags & FLAG_UNICODE != 0 {
        Err(Error { msg: "ASCII and UNICODE flags are incompatible".into(), pos: 0 })
    } else {
        Ok(flags)
    }
}

/// Parse a str pattern: its tree and the parser's state (groups, flags).
pub fn parse_pattern(pattern: &[u32], flags: u32) -> R<(SubPattern, State)> {
    let mut source = Tokenizer::new(pattern)?;
    let mut state = State::new(flags);
    let p = parse_sub(&mut source, &mut state, flags & FLAG_VERBOSE != 0, 0)?;
    state.flags = fix_flags(state.flags)?;
    if source.next.is_some() {
        return Err(source.error("unbalanced parenthesis", 0));
    }
    for &(g, pos) in &state.grouprefpos {
        if g >= state.groups() {
            return Err(Error { msg: "invalid group reference".into(), pos });
        }
    }
    let _ = unicode::is_word; // (the parser itself reads no character data)
    Ok((p, state))
}
