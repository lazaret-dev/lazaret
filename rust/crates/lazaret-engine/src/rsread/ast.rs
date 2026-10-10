//! Rust expressions and statements, read from rsparse's tokens for the reader (0.1.9).
//!
//! rsparse reads a file's items and keeps a function's body as tokens. This reads a body's
//! statements and expressions into a small tree: what the reader evaluates. It is not Rust's
//! parser and does not need to be: it reads what code that compiles holds, and anything else
//! (a construct it does not know, a macro's tokens, a group that does not close) becomes
//! [`Ex::Unknown`] at that place while the rest is read. Each delimited group is read on its own
//! (its end is its mate's), so a mistake inside one never spreads past it.
//!
//! Punctuation comes one character per token (`lex::rs`): `::`, `=>`, `..=` and the compound
//! operators are read from adjacent tokens. Generic arguments (`::<T>`), types (`as T`,
//! `let x: T`, a closure's parameters) and attributes are skipped. Nesting is bounded
//! ([`MAX_DEPTH`]): deeper groups are Unknown, so reading never recurses past it.

use crate::lex::{Kind as TK, Token};
use crate::pystr::PyStr;
use std::rc::Rc;

/// The deepest nesting read; deeper is Unknown.
pub const MAX_DEPTH: u32 = 96;
/// The longest chain of postfix operations read as one (`.f()`, `[i]`, `?`, `as T`): a longer one is Unknown, so no
/// chain builds a tree deeper than this (the Rust reader's review, RR-2).
pub const MAX_LINKS: usize = 64;

/// Where a body's tokens are.
#[derive(Clone, Copy)]
pub struct Toks<'a> {
    pub src: &'a [u32],
    pub toks: &'a [Token],
    pub mate: &'a [u32],
}

/// A binary operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    BitOr,
    BitXor,
    BitAnd,
    Shl,
    Shr,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

#[derive(Clone, Debug)]
pub enum Ex {
    Unknown(u32),
    /// A string's value (escapes read; a byte string's bytes as code points); bytes: `b"…"`.
    Str(PyStr, bool, u32),
    Int(i128, u32),
    Char(u32, u32),
    Bool(bool, u32),
    /// A path's segments, generic arguments left out (`std::process::Command`, `self`, `Self::new`).
    Path(Vec<PyStr>, u32),
    /// A macro call: its path and the tokens between its delimiters (open, close).
    Macro(Vec<PyStr>, u32, u32, u32),
    Call(Box<Ex>, Vec<Ex>, u32),
    Method(Box<Ex>, PyStr, Vec<Ex>, u32),
    Field(Box<Ex>, PyStr, u32),
    Index(Box<Ex>, Box<Ex>, u32),
    /// `-x`, `!x`, `*x`.
    Unary(u8, Box<Ex>, u32),
    Ref(Box<Ex>, u32),
    Try(Box<Ex>),
    Await(Box<Ex>),
    /// `x as T`: the type's first name (`char`, `u8`).
    Cast(Box<Ex>, PyStr),
    Bin(Op, Box<Ex>, Box<Ex>, u32),
    /// Two binary operators or more at one level (`a + b + c`), read left to right: flat, so a chain of any length
    /// is one node deep (each pair: the operator, its right operand and where it is).
    Chain(Box<Ex>, Vec<(Op, Ex, u32)>),
    /// `a = b`, `a += b` (the operator), …
    Assign(Option<Op>, Box<Ex>, Box<Ex>, u32),
    Range(Option<Box<Ex>>, Option<Box<Ex>>, u32),
    Tuple(Vec<Ex>, u32),
    Array(Vec<Ex>, u32),
    Repeat(Box<Ex>, Box<Ex>, u32),
    /// `Path { field: value, .. }`.
    Struct(Vec<PyStr>, Vec<(PyStr, Ex)>, u32),
    Block(Box<Block>),
    If(Box<Ex>, Box<Block>, Option<Box<Ex>>, u32),
    Match(Box<Ex>, Vec<Arm>, u32),
    Loop(Box<Block>, u32),
    While(Box<Ex>, Box<Block>, u32),
    For(Pat, Box<Ex>, Box<Block>, u32),
    /// A closure: its body is shared, not copied, by each value the closure expression gives.
    Closure(Vec<Pat>, Rc<Ex>, u32),
    Return(Option<Box<Ex>>, u32),
    Break(Option<Box<Ex>>, u32),
    Continue(u32),
    /// `let pat = e` in a condition (`if let`, `while let`, a let chain).
    Let(Pat, Box<Ex>, u32),
}

impl Ex {
    /// Where it starts (a code-point offset).
    pub fn at(&self) -> u32 {
        match self {
            Ex::Unknown(a) | Ex::Int(_, a) | Ex::Char(_, a) | Ex::Bool(_, a) | Ex::Continue(a) => *a,
            Ex::Str(_, _, a) | Ex::Path(_, a) | Ex::Macro(_, _, _, a) | Ex::Call(_, _, a) | Ex::Method(_, _, _, a) => *a,
            Ex::Field(_, _, a) | Ex::Index(_, _, a) | Ex::Unary(_, _, a) | Ex::Ref(_, a) | Ex::Bin(_, _, _, a) => *a,
            Ex::Assign(_, _, _, a) | Ex::Range(_, _, a) | Ex::Tuple(_, a) | Ex::Array(_, a) | Ex::Repeat(_, _, a) => *a,
            Ex::Struct(_, _, a) | Ex::If(_, _, _, a) | Ex::Match(_, _, a) | Ex::Loop(_, a) | Ex::While(_, _, a) => *a,
            Ex::For(_, _, _, a) | Ex::Closure(_, _, a) | Ex::Return(_, a) | Ex::Break(_, a) | Ex::Let(_, _, a) => *a,
            Ex::Try(e) | Ex::Await(e) | Ex::Cast(e, _) | Ex::Chain(e, _) => e.at(),
            Ex::Block(b) => b.at,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub tail: Option<Ex>,
    pub at: u32,
}

#[derive(Clone, Debug)]
pub enum Stmt {
    /// `let pat = init else { … };` (a local `const` or `static` too).
    Let(Pat, Option<Ex>, Option<Block>),
    Expr(Ex),
}

#[derive(Clone, Debug)]
pub struct Arm {
    pub pat: Pat,
    pub guard: Option<Ex>,
    pub body: Ex,
}

#[derive(Clone, Debug)]
pub enum Pat {
    Bind(PyStr),
    Wild,
    Rest,
    Tuple(Vec<Pat>),
    /// `Some(x)`, `Ok(x)`, `Variant(a, b)`: the path's last segment and the parts.
    TupleStruct(PyStr, Vec<Pat>),
    Struct(PyStr, Vec<(PyStr, Pat)>),
    Ref(Box<Pat>),
    Slice(Vec<Pat>),
    Or(Vec<Pat>),
    Other,
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return", "static", "struct",
    "super", "trait", "true", "type", "unsafe", "use", "where", "while", "macro_rules", "union", "yield",
];

fn is_word(t: &[u32], w: &str) -> bool {
    t.len() == w.len() && t.iter().zip(w.bytes()).all(|(&a, b)| a == b as u32)
}

/// A body's reader over the tokens [pos, end).
pub struct Reader<'a> {
    t: Toks<'a>,
    pos: usize,
    end: usize,
    depth: u32,
    /// (pat_list: the list ended with a comma, so `(x,)` is a tuple)
    trailing_comma: bool,
}

/// The statements of the block whose `{` is token `open`.
pub fn block(t: Toks, open: usize) -> Block {
    let close = t.mate.get(open).copied().unwrap_or(u32::MAX) as usize;
    let end = if close == u32::MAX as usize || close <= open { t.toks.len() } else { close };
    let at = t.toks.get(open).map(|k| k.start).unwrap_or(0);
    let mut r = Reader { t, pos: open + 1, end, depth: 0, trailing_comma: false };
    let mut b = r.stmts();
    b.at = at;
    b
}

/// The expression of the tokens [from, to) (a constant's initializer).
pub fn expr_of(t: Toks, from: usize, to: usize) -> Ex {
    let mut r = Reader { t, pos: from, end: to.min(t.toks.len()), depth: 0, trailing_comma: false };
    r.expr(false)
}

/// A macro's arguments, between its delimiters at `open` and `close`: expressions separated by commas, a
/// `name = value` one named (`format!("{x}", x = 1)`).
pub fn macro_args(t: Toks, open: usize, close: usize) -> Vec<(Option<PyStr>, Ex)> {
    let mut r = Reader { t, pos: open + 1, end: close.min(t.toks.len()), depth: 0, trailing_comma: false };
    let mut out = Vec::new();
    let mut guard = 0;
    while r.pos < r.end && guard < 10_000 {
        guard += 1;
        let start = r.pos;
        let mut name = None;
        if r.is_name(r.pos) && r.is_p_at(r.pos + 1, '=') && !r.seq_at(r.pos + 1, "==") && !r.seq_at(r.pos + 1, "=>") {
            name = Some(r.text(r.pos).to_vec());
            r.pos += 2;
        }
        let e = r.expr(false);
        out.push((name, e));
        if r.p(',') {
            r.pos += 1;
        } else {
            r.pos = r.skip_to_comma();
            if r.p(',') {
                r.pos += 1;
            }
        }
        if r.pos == start {
            r.pos += 1;
        }
    }
    out
}

/// `vec![x; n]`: (x, n).
pub fn macro_repeat(t: Toks, open: usize, close: usize) -> Option<(Ex, Ex)> {
    let mut r = Reader { t, pos: open + 1, end: close.min(t.toks.len()), depth: 0, trailing_comma: false };
    let mut i = r.pos;
    while i < r.end {
        if r.is_p_at(i, ';') {
            let x = expr_of(t, open + 1, i);
            r.pos = i + 1;
            let n = r.expr(false);
            return Some((x, n));
        }
        if r.is_p_at(i, ',') {
            return None;
        }
        i = if r.is_open(i) { r.after_group(i) } else { i + 1 };
    }
    None
}

/// Do a macro's tokens read as arguments (no `;`, `=>` or `$` at their level: not a pattern or a body)?
pub fn macro_looks_like_args(t: Toks, open: usize, close: usize) -> bool {
    let r = Reader { t, pos: open + 1, end: close.min(t.toks.len()), depth: 0, trailing_comma: false };
    let mut i = r.pos;
    while i < r.end {
        if r.is_p_at(i, ';') || r.is_p_at(i, '$') || r.seq_at(i, "=>") {
            return false;
        }
        i = if r.is_open(i) { r.after_group(i) } else { i + 1 };
    }
    true
}

/// The patterns of a parameter list between `(` at `open` and its mate: one per parameter, `self` as `Bind("self")`.
pub fn params(t: Toks, open: usize) -> Vec<Pat> {
    let close = t.mate.get(open).copied().unwrap_or(u32::MAX) as usize;
    if close == u32::MAX as usize || close <= open {
        return Vec::new();
    }
    let mut r = Reader { t, pos: open + 1, end: close, depth: 0, trailing_comma: false };
    let mut out = Vec::new();
    while r.pos < r.end {
        r.skip_attrs();
        if r.pos >= r.end {
            break;
        }
        let start = r.pos;
        let p = r.pat_top();
        if r.p(':') && !r.seq("::") {
            r.pos += 1;
            r.skip_type();
        }
        out.push(p);
        if r.p(',') {
            r.pos += 1;
        } else if r.pos == start || r.pos < r.end {
            // (not a parameter list read: what is left is skipped)
            r.pos = r.skip_to_comma();
            if r.p(',') {
                r.pos += 1;
            }
        }
    }
    out
}

impl<'a> Reader<'a> {
    // ---------------------------------------------------------------- depth --
    /// `f` read one level deeper: Unknown past [`MAX_DEPTH`] (the rest of this reader's tokens skipped). Every form the
    /// reader reads within itself goes through here or through a group's reader, so no input recurses past the bound
    /// (the Rust reader's review, RR-1: `a = a = …`, `else if` chains, `'a: 'a: …`, `move move …`).
    fn deeper(&mut self, at: u32, f: impl FnOnce(&mut Self) -> Ex) -> Ex {
        if self.depth > MAX_DEPTH {
            self.pos = self.end;
            return Ex::Unknown(at);
        }
        self.depth += 1;
        let e = f(self);
        self.depth -= 1;
        e
    }

    // ---------------------------------------------------------------- tokens --
    fn tok(&self, i: usize) -> Option<&Token> {
        if i < self.end {
            self.t.toks.get(i)
        } else {
            None
        }
    }

    fn text(&self, i: usize) -> &'a [u32] {
        match self.t.toks.get(i) {
            Some(k) => &self.t.src[(k.start as usize).min(self.t.src.len())..(k.end as usize).min(self.t.src.len())],
            None => &[],
        }
    }

    fn at(&self, i: usize) -> u32 {
        self.t.toks.get(i.min(self.t.toks.len().saturating_sub(1))).map(|k| k.start).unwrap_or(0)
    }

    fn is_p_at(&self, i: usize, c: char) -> bool {
        match self.tok(i) {
            Some(k) => k.kind == TK::Punct && self.t.src.get(k.start as usize) == Some(&(c as u32)),
            None => false,
        }
    }

    fn p(&self, c: char) -> bool {
        self.is_p_at(self.pos, c)
    }

    /// Do the tokens at `i` spell `s`, one punctuation character each, with nothing between them?
    fn seq_at(&self, i: usize, s: &str) -> bool {
        let mut prev_end: Option<u32> = None;
        for (k, c) in s.chars().enumerate() {
            match self.tok(i + k) {
                Some(t) if t.kind == TK::Punct && self.t.src.get(t.start as usize) == Some(&(c as u32)) => {
                    if let Some(e) = prev_end {
                        if t.start != e {
                            return false;
                        }
                    }
                    prev_end = Some(t.end);
                }
                _ => return false,
            }
        }
        true
    }

    fn seq(&self, s: &str) -> bool {
        self.seq_at(self.pos, s)
    }

    fn word_at(&self, i: usize, w: &str) -> bool {
        matches!(self.tok(i), Some(t) if t.kind == TK::Name) && is_word(self.text(i), w)
    }

    fn word(&self, w: &str) -> bool {
        self.word_at(self.pos, w)
    }

    fn is_name(&self, i: usize) -> bool {
        matches!(self.tok(i), Some(t) if t.kind == TK::Name) && self.text(i).first() != Some(&('\'' as u32))
    }

    fn is_keyword(&self, i: usize) -> bool {
        let t = self.text(i);
        KEYWORDS.iter().any(|k| is_word(t, k))
    }

    /// The token after a delimited group opening at `i` (its mate's next), or the end.
    fn after_group(&self, i: usize) -> usize {
        match self.t.mate.get(i) {
            Some(&m) if m != u32::MAX && (m as usize) > i && (m as usize) < self.end => m as usize + 1,
            _ => self.end,
        }
    }

    fn is_open(&self, i: usize) -> bool {
        self.is_p_at(i, '(') || self.is_p_at(i, '[') || self.is_p_at(i, '{')
    }

    /// A sub-reader for the group opening at `open`: (reader, the token after the group).
    fn group(&self, open: usize) -> (Reader<'a>, usize) {
        let next = self.after_group(open);
        let close = if next == self.end && !(self.t.mate.get(open).is_some_and(|&m| (m as usize) + 1 == next)) {
            self.end
        } else {
            next - 1
        };
        (Reader { t: self.t, pos: open + 1, end: close.max(open + 1), depth: self.depth + 1, trailing_comma: false }, next)
    }

    fn skip_attrs(&mut self) {
        while self.p('#') {
            let mut k = self.pos + 1;
            if self.is_p_at(k, '!') {
                k += 1;
            }
            if self.is_p_at(k, '[') {
                self.pos = self.after_group(k);
            } else {
                break;
            }
        }
    }

    /// The token where the next `,` at this level is (or the end).
    fn skip_to_comma(&self) -> usize {
        let mut i = self.pos;
        while i < self.end && !self.is_p_at(i, ',') {
            i = if self.is_open(i) { self.after_group(i) } else { i + 1 };
        }
        i
    }

    // ---------------------------------------------------------------- types --
    /// Skips `<…>` at pos (generic arguments), counting `>>` as two.
    fn skip_angles(&mut self) {
        if !self.p('<') {
            return;
        }
        let mut depth = 0i32;
        while self.pos < self.end {
            if self.is_open(self.pos) {
                self.pos = self.after_group(self.pos);
                continue;
            }
            if self.p('<') {
                depth += 1;
            } else if self.p('>') && !(self.pos > 0 && self.is_p_at(self.pos - 1, '-') && self.seq_at(self.pos - 1, "->")) {
                depth -= 1;
                if depth == 0 {
                    self.pos += 1;
                    return;
                }
            } else if self.p(';') || self.p('{') {
                return;
            }
            self.pos += 1;
        }
    }

    /// Skips a type at pos; the type's first name (`u8`, `String`, `char`), if any.
    fn skip_type(&mut self) -> PyStr {
        let mut first: PyStr = Vec::new();
        if self.depth > MAX_DEPTH {
            self.pos = self.end;
            return first;
        }
        let mut steps = 0;
        loop {
            steps += 1;
            if self.pos >= self.end || steps > 4096 {
                return first;
            }
            if self.p('&') || self.p('*') {
                self.pos += 1;
                if self.word("mut") || self.word("const") {
                    self.pos += 1;
                }
                // (a lifetime)
                if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Name) && self.text(self.pos).first() == Some(&('\'' as u32)) {
                    self.pos += 1;
                }
                continue;
            }
            if self.word("dyn") || self.word("impl") {
                self.pos += 1;
                continue;
            }
            if self.p('(') || self.p('[') {
                self.pos = self.after_group(self.pos);
            } else if self.p('!') || self.word("_") {
                self.pos += 1;
            } else if self.word("fn") || self.word("unsafe") || self.word("extern") {
                while self.word("unsafe") || self.word("extern") {
                    self.pos += 1;
                    if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Str) {
                        self.pos += 1;
                    }
                }
                if self.word("fn") {
                    self.pos += 1;
                    if self.p('(') {
                        self.pos = self.after_group(self.pos);
                    }
                    if self.seq("->") {
                        self.pos += 2;
                        continue;
                    }
                }
            } else if self.seq("::") || self.is_name(self.pos) || self.p('<') {
                // a path: segments, generic arguments
                if self.p('<') {
                    self.skip_angles();
                }
                loop {
                    if self.seq("::") {
                        self.pos += 2;
                    }
                    if self.is_name(self.pos) {
                        if first.is_empty() {
                            first = self.text(self.pos).to_vec();
                        }
                        self.pos += 1;
                    }
                    if self.p('<') {
                        self.skip_angles();
                    } else if self.seq("::") && self.is_p_at(self.pos + 2, '<') {
                        self.pos += 2;
                        self.skip_angles();
                    }
                    if self.p('(') && !self.is_open(self.pos.saturating_sub(1)) {
                        // `Fn(A) -> B`
                        let prev_name = self.pos > 0 && self.is_name(self.pos - 1);
                        if prev_name {
                            self.pos = self.after_group(self.pos);
                            if self.seq("->") {
                                self.pos += 2;
                                self.depth += 1;
                                self.skip_type();
                                self.depth -= 1;
                            }
                        }
                    }
                    if !self.seq("::") {
                        break;
                    }
                }
            } else if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Name) && self.text(self.pos).first() == Some(&('\'' as u32)) {
                self.pos += 1; // a lifetime bound
            } else {
                return first;
            }
            // `A + B` (bounds)
            if self.p('+') {
                self.pos += 1;
                continue;
            }
            return first;
        }
    }

    // ---------------------------------------------------------------- statements --
    fn stmts(&mut self) -> Block {
        let mut b = Block { at: self.at(self.pos), ..Block::default() };
        if self.depth > MAX_DEPTH {
            self.pos = self.end;
            return b;
        }
        let mut guard = 0usize;
        while self.pos < self.end {
            guard += 1;
            if guard > 1_000_000 {
                break;
            }
            let start = self.pos;
            self.skip_attrs();
            if self.pos >= self.end {
                break;
            }
            if self.p(';') {
                self.pos += 1;
                continue;
            }
            if self.word("let") {
                self.pos += 1;
                let pat = self.pat_top();
                if self.p(':') && !self.seq("::") {
                    self.pos += 1;
                    self.skip_type();
                }
                let mut init = None;
                if self.p('=') && !self.seq("==") && !self.seq("=>") {
                    self.pos += 1;
                    init = Some(self.expr(false));
                }
                let mut els = None;
                if self.word("else") && self.is_p_at(self.pos + 1, '{') {
                    let (mut g, next) = self.group(self.pos + 1);
                    els = Some(g.stmts());
                    self.pos = next;
                }
                self.end_stmt();
                b.stmts.push(Stmt::Let(pat, init, els));
                continue;
            }
            if let Some(s) = self.item() {
                if let Some(s) = s {
                    b.stmts.push(s);
                }
                if self.pos == start {
                    self.pos += 1;
                }
                continue;
            }
            let block_like = self.block_like_start();
            let e = self.expr(false);
            if self.p(';') {
                self.pos += 1;
                b.stmts.push(Stmt::Expr(e));
            } else if self.pos >= self.end {
                b.tail = Some(e);
            } else if block_like {
                b.stmts.push(Stmt::Expr(e));
            } else {
                // (not read to a statement's end: the rest of the statement is skipped)
                b.stmts.push(Stmt::Expr(e));
                if self.pos == start {
                    self.pos += 1;
                }
                while self.pos < self.end && !self.p(';') {
                    self.pos = if self.is_open(self.pos) { self.after_group(self.pos) } else { self.pos + 1 };
                }
            }
            if self.pos == start {
                self.pos += 1;
            }
        }
        // a block-like last statement is the block's value
        if b.tail.is_none() {
            if let Some(Stmt::Expr(e)) = b.stmts.last() {
                if matches!(e, Ex::If(..) | Ex::Match(..) | Ex::Block(..) | Ex::Loop(..)) {
                    if let Some(Stmt::Expr(e)) = b.stmts.pop() {
                        b.tail = Some(e);
                    }
                }
            }
        }
        b
    }

    fn end_stmt(&mut self) {
        while self.pos < self.end && !self.p(';') {
            self.pos = if self.is_open(self.pos) { self.after_group(self.pos) } else { self.pos + 1 };
        }
        if self.p(';') {
            self.pos += 1;
        }
    }

    fn block_like_start(&self) -> bool {
        let i = self.pos;
        (self.p('{'))
            || self.word("if")
            || self.word("match")
            || self.word("loop")
            || self.word("while")
            || self.word("for")
            || (self.word("unsafe") && self.is_p_at(i + 1, '{'))
            || (matches!(self.tok(i), Some(t) if t.kind == TK::Name) && self.text(i).first() == Some(&('\'' as u32)))
    }

    /// An item in a block: a local `const` or `static` becomes a `let`; any other item is skipped. None: not an
    /// item; Some(None): an item skipped.
    fn item(&mut self) -> Option<Option<Stmt>> {
        let mut i = self.pos;
        // visibility and qualifiers
        if self.word_at(i, "pub") {
            i += 1;
            if self.is_p_at(i, '(') {
                i = self.after_group(i);
            }
        }
        let kw_const = self.word_at(i, "const") && !self.is_p_at(i + 1, '{');
        let kw_static = self.word_at(i, "static");
        if (kw_const || kw_static) && !self.word_at(i + 1, "fn") && !self.word_at(i + 1, "unsafe") && !self.word_at(i + 1, "async") && !self.word_at(i + 1, "extern") {
            let mut j = i + 1;
            if self.word_at(j, "mut") {
                j += 1;
            }
            if self.is_name(j) {
                let name = self.text(j).to_vec();
                self.pos = j + 1;
                if self.p(':') {
                    self.pos += 1;
                    self.skip_type();
                }
                let mut init = None;
                if self.p('=') {
                    self.pos += 1;
                    init = Some(self.expr(false));
                }
                self.end_stmt();
                return Some(Some(Stmt::Let(Pat::Bind(name), init, None)));
            }
        }
        let starts = ["fn", "struct", "enum", "trait", "impl", "mod", "use", "extern", "type", "macro_rules", "const", "static", "async", "unsafe"];
        let is_item = starts.iter().any(|w| self.word_at(i, w))
            && !(self.word_at(i, "unsafe") && self.is_p_at(i + 1, '{'))
            && !(self.word_at(i, "async") && (self.is_p_at(i + 1, '{') || self.word_at(i + 1, "move")))
            && !(self.word_at(i, "const") && self.is_p_at(i + 1, '{'))
            || (self.word_at(i, "union") && self.is_name(i + 1));
        if !is_item {
            return None;
        }
        if self.word_at(i, "macro_rules") {
            let mut j = i + 1;
            while j < self.end && !self.is_open(j) {
                j += 1;
            }
            self.pos = self.after_group(j);
            if self.p(';') {
                self.pos += 1;
            }
            return Some(None);
        }
        // to the item's `;`, or the end of its first brace group
        let mut j = i;
        while j < self.end {
            if self.is_p_at(j, ';') {
                self.pos = j + 1;
                return Some(None);
            }
            if self.is_p_at(j, '{') {
                self.pos = self.after_group(j);
                return Some(None);
            }
            j = if self.is_open(j) { self.after_group(j) } else { j + 1 };
        }
        self.pos = self.end;
        Some(None)
    }

    // ---------------------------------------------------------------- patterns --
    fn pat_top(&mut self) -> Pat {
        if self.p('|') && !self.seq("||") {
            self.pos += 1;
        }
        let first = self.pat();
        if !(self.p('|') && !self.seq("||")) {
            return first;
        }
        let mut alts = vec![first];
        while self.p('|') && !self.seq("||") {
            self.pos += 1;
            alts.push(self.pat());
        }
        Pat::Or(alts)
    }

    fn pat(&mut self) -> Pat {
        if self.pos >= self.end {
            return Pat::Other;
        }
        if self.depth > MAX_DEPTH {
            self.pos = self.end;
            return Pat::Other;
        }
        if self.word("_") {
            self.pos += 1;
            return Pat::Wild;
        }
        if self.seq("..") {
            self.pos += 2;
            if self.p('=') {
                self.pos += 1;
            }
            // (a range pattern's end)
            if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Num || t.kind == TK::Str) {
                self.pos += 1;
            }
            return Pat::Rest;
        }
        if self.p('&') {
            self.pos += 1;
            if self.p('&') {
                self.pos += 1;
            }
            if self.word("mut") {
                self.pos += 1;
            }
            self.depth += 1;
            let inner = self.pat();
            self.depth -= 1;
            return Pat::Ref(Box::new(inner));
        }
        if self.p('(') {
            let (mut g, next) = self.group(self.pos);
            let items = g.pat_list();
            self.pos = next;
            if items.len() == 1 && !g.trailing_comma {
                return items.into_iter().next().unwrap_or(Pat::Other);
            }
            return Pat::Tuple(items);
        }
        if self.p('[') {
            let (mut g, next) = self.group(self.pos);
            let items = g.pat_list();
            self.pos = next;
            return Pat::Slice(items);
        }
        if self.p('-') || matches!(self.tok(self.pos), Some(t) if t.kind == TK::Num || t.kind == TK::Str) {
            if self.p('-') {
                self.pos += 1;
            }
            self.pos += 1;
            if self.seq("..=") {
                self.pos += 3;
                if self.p('-') {
                    self.pos += 1;
                }
                self.pos += 1;
            } else if self.seq("..") {
                self.pos += 2;
                if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Num || t.kind == TK::Str) {
                    self.pos += 1;
                }
            }
            return Pat::Other;
        }
        if self.word("ref") {
            self.pos += 1;
        }
        if self.word("mut") {
            self.pos += 1;
        }
        if self.word("box") {
            self.pos += 1;
        }
        if self.is_name(self.pos) || self.seq("::") || self.p('<') {
            let single = self.is_name(self.pos) && !self.seq_at(self.pos + 1, "::") && !self.is_p_at(self.pos + 1, '(') && !self.is_p_at(self.pos + 1, '{') && !self.is_p_at(self.pos + 1, '!');
            if single {
                let name = self.text(self.pos).to_vec();
                self.pos += 1;
                if self.p('@') {
                    self.pos += 1;
                    self.depth += 1;
                    self.pat();
                    self.depth -= 1;
                }
                // `true`/`false`, a constant or a unit variant (capitalized) are not bindings
                let lower = name.first().is_some_and(|&c| c == '_' as u32 || char::from_u32(c).is_some_and(|c| c.is_lowercase()));
                if is_word(&name, "true") || is_word(&name, "false") || !lower {
                    return Pat::Other;
                }
                return Pat::Bind(name);
            }
            let path = self.path_segs();
            let last = path.last().cloned().unwrap_or_default();
            if self.p('(') {
                let (mut g, next) = self.group(self.pos);
                let items = g.pat_list();
                self.pos = next;
                return Pat::TupleStruct(last, items);
            }
            if self.p('{') {
                let (mut g, next) = self.group(self.pos);
                let mut fields = Vec::new();
                while g.pos < g.end {
                    g.skip_attrs();
                    if g.seq("..") {
                        g.pos += 2;
                        continue;
                    }
                    let start = g.pos;
                    if g.word("ref") {
                        g.pos += 1;
                    }
                    if g.word("mut") {
                        g.pos += 1;
                    }
                    if g.is_name(g.pos) {
                        let f = g.text(g.pos).to_vec();
                        g.pos += 1;
                        if g.p(':') {
                            g.pos += 1;
                            let p = g.pat();
                            fields.push((f, p));
                        } else {
                            fields.push((f.clone(), Pat::Bind(f)));
                        }
                    } else {
                        g.pos = g.skip_to_comma();
                    }
                    if g.p(',') {
                        g.pos += 1;
                    } else if g.pos == start {
                        g.pos += 1;
                    }
                }
                self.pos = next;
                return Pat::Struct(last, fields);
            }
            if self.p('!') && self.is_open(self.pos + 1) {
                self.pos = self.after_group(self.pos + 1);
            }
            return Pat::Other;
        }
        self.pos += 1;
        Pat::Other
    }

    fn pat_list(&mut self) -> Vec<Pat> {
        let mut out = Vec::new();
        self.trailing_comma = false;
        while self.pos < self.end {
            let start = self.pos;
            out.push(self.pat_top());
            self.trailing_comma = false;
            if self.p(',') {
                self.pos += 1;
                self.trailing_comma = true;
            } else if self.pos == start || self.pos < self.end {
                self.pos = self.skip_to_comma();
                if self.p(',') {
                    self.pos += 1;
                    self.trailing_comma = true;
                }
            }
        }
        out
    }

    // ---------------------------------------------------------------- paths --
    /// Path segments at pos: `a::b::<T>::c`, `<T as Tr>::f` (its segments after the `>`).
    fn path_segs(&mut self) -> Vec<PyStr> {
        let mut segs: Vec<PyStr> = Vec::new();
        if self.p('<') {
            self.skip_angles();
        }
        if self.seq("::") {
            self.pos += 2;
        }
        let mut guard = 0;
        while self.pos < self.end && guard < 256 {
            guard += 1;
            if self.is_name(self.pos) {
                let t = self.text(self.pos);
                let t = if t.len() > 2 && t[0] == 'r' as u32 && t[1] == '#' as u32 { &t[2..] } else { t };
                segs.push(t.to_vec());
                self.pos += 1;
            } else {
                break;
            }
            if self.seq("::") {
                if self.is_p_at(self.pos + 2, '<') {
                    self.pos += 2;
                    self.skip_angles();
                    if !self.seq("::") {
                        break;
                    }
                }
                if self.seq("::") && (self.is_name(self.pos + 2) || self.is_p_at(self.pos + 2, '<')) {
                    self.pos += 2;
                    if self.p('<') {
                        self.skip_angles();
                        if self.seq("::") {
                            self.pos += 2;
                        }
                    }
                    continue;
                }
            }
            break;
        }
        segs
    }

    // ---------------------------------------------------------------- expressions --
    pub fn expr(&mut self, no_struct: bool) -> Ex {
        if self.depth > MAX_DEPTH {
            let at = self.at(self.pos);
            self.pos = self.end;
            return Ex::Unknown(at);
        }
        self.depth += 1;
        let e = self.assign(no_struct);
        self.depth -= 1;
        e
    }

    fn assign_op(&self) -> Option<(Option<Op>, usize)> {
        let ops: [(&str, Op); 10] = [
            ("<<=", Op::Shl),
            (">>=", Op::Shr),
            ("+=", Op::Add),
            ("-=", Op::Sub),
            ("*=", Op::Mul),
            ("/=", Op::Div),
            ("%=", Op::Rem),
            ("^=", Op::BitXor),
            ("&=", Op::BitAnd),
            ("|=", Op::BitOr),
        ];
        for (s, op) in ops {
            if self.seq(s) {
                return Some((Some(op), s.len()));
            }
        }
        if self.p('=') && !self.seq("==") && !self.seq("=>") {
            return Some((None, 1));
        }
        None
    }

    fn assign(&mut self, no_struct: bool) -> Ex {
        let at = self.at(self.pos);
        let lhs = self.range(no_struct);
        if let Some((op, len)) = self.assign_op() {
            self.pos += len;
            let rhs = self.expr(no_struct);
            return Ex::Assign(op, Box::new(lhs), Box::new(rhs), at);
        }
        lhs
    }

    fn can_start_expr(&self) -> bool {
        if self.pos >= self.end {
            return false;
        }
        !(self.p(')') || self.p(']') || self.p('}') || self.p(',') || self.p(';') || self.seq("=>") || (self.p('=') && !self.seq("==")))
    }

    fn range(&mut self, no_struct: bool) -> Ex {
        let at = self.at(self.pos);
        if self.seq("..") {
            self.pos += 2;
            if self.p('=') {
                self.pos += 1;
            }
            let hi = if self.can_start_expr() && !(no_struct && self.p('{')) { Some(Box::new(self.bin(1, no_struct))) } else { None };
            return Ex::Range(None, hi, at);
        }
        let lo = self.bin(1, no_struct);
        if self.seq("..") {
            self.pos += 2;
            if self.p('=') {
                self.pos += 1;
            }
            let hi = if self.can_start_expr() && !(no_struct && self.p('{')) { Some(Box::new(self.bin(1, no_struct))) } else { None };
            return Ex::Range(Some(Box::new(lo)), hi, at);
        }
        lo
    }

    /// The binary operator at pos: (operator, its tokens, precedence).
    fn bin_op(&self) -> Option<(Op, usize, u8)> {
        if self.pos >= self.end {
            return None;
        }
        if self.assign_op().is_some_and(|(o, _)| o.is_some()) {
            return None;
        }
        let two: [(&str, Op, u8); 10] = [
            ("||", Op::Or, 1),
            ("&&", Op::And, 2),
            ("==", Op::Eq, 3),
            ("!=", Op::Ne, 3),
            ("<=", Op::Le, 3),
            (">=", Op::Ge, 3),
            ("<<", Op::Shl, 7),
            (">>", Op::Shr, 7),
            ("..", Op::Add, 0), // (a range: not a binary operator here)
            ("=>", Op::Add, 0),
        ];
        for (s, op, prec) in two {
            if self.seq(s) {
                return if prec == 0 { None } else { Some((op, 2, prec)) };
            }
        }
        let one: [(char, Op, u8); 10] = [
            ('<', Op::Lt, 3),
            ('>', Op::Gt, 3),
            ('|', Op::BitOr, 4),
            ('^', Op::BitXor, 5),
            ('&', Op::BitAnd, 6),
            ('+', Op::Add, 8),
            ('-', Op::Sub, 8),
            ('*', Op::Mul, 9),
            ('/', Op::Div, 9),
            ('%', Op::Rem, 9),
        ];
        for (c, op, prec) in one {
            if self.p(c) {
                if c == '-' && self.seq("->") {
                    return None;
                }
                return Some((op, 1, prec));
            }
        }
        None
    }

    fn bin(&mut self, min: u8, no_struct: bool) -> Ex {
        let first = self.unary(no_struct);
        // (the operators of one level, read left to right: what `lhs = Bin(op, lhs, rhs)` built, but flat, as a chain
        // of any length is one node deep; an operand of a higher precedence is read whole by the call for its right side)
        let mut rest: Vec<(Op, Ex, u32)> = Vec::new();
        let mut guard = 0;
        while let Some((op, len, prec)) = self.bin_op() {
            guard += 1;
            if prec < min || guard > 1_000_000 {
                break;
            }
            let at = self.at(self.pos);
            self.pos += len;
            let rhs = self.bin(prec + 1, no_struct);
            rest.push((op, rhs, at));
        }
        match rest.len() {
            0 => first,
            1 => {
                let (op, rhs, at) = rest.pop().expect("one operator");
                Ex::Bin(op, Box::new(first), Box::new(rhs), at)
            }
            _ => Ex::Chain(Box::new(first), rest),
        }
    }

    fn unary(&mut self, no_struct: bool) -> Ex {
        let at = self.at(self.pos);
        if self.pos >= self.end {
            return Ex::Unknown(at);
        }
        if self.depth > MAX_DEPTH {
            self.pos = self.end;
            return Ex::Unknown(at);
        }
        if self.p('-') || self.p('!') || self.p('*') {
            let c = self.text(self.pos).first().copied().unwrap_or(0) as u8;
            self.pos += 1;
            self.depth += 1;
            let e = self.unary(no_struct);
            self.depth -= 1;
            return Ex::Unary(c, Box::new(e), at);
        }
        if self.p('&') {
            self.pos += 1;
            if self.p('&') {
                self.pos += 1;
            }
            if self.word("mut") {
                self.pos += 1;
            }
            if self.word("raw") && (self.word_at(self.pos + 1, "const") || self.word_at(self.pos + 1, "mut")) {
                self.pos += 2;
            }
            self.depth += 1;
            let e = self.unary(no_struct);
            self.depth -= 1;
            return Ex::Ref(Box::new(e), at);
        }
        let e = self.primary(no_struct);
        self.postfix(e, no_struct)
    }

    fn args(&mut self, open: usize) -> (Vec<Ex>, usize) {
        let (mut g, next) = self.group(open);
        let mut out = Vec::new();
        while g.pos < g.end {
            let start = g.pos;
            g.skip_attrs();
            out.push(g.expr(false));
            if g.p(',') {
                g.pos += 1;
            } else if g.pos == start || g.pos < g.end {
                g.pos = g.skip_to_comma();
                if g.p(',') {
                    g.pos += 1;
                }
            }
        }
        (out, next)
    }

    fn postfix(&mut self, mut e: Ex, no_struct: bool) -> Ex {
        let _ = no_struct;
        let mut guard = 0;
        let mut links = 0usize;
        loop {
            guard += 1;
            if guard > 1_000_000 || self.pos >= self.end {
                return e;
            }
            let at = self.at(self.pos);
            // (a chain past MAX_LINKS is read on, its value Unknown: no chain builds a tree deeper than that, RR-2)
            if links >= MAX_LINKS && self.link_starts() {
                e = Ex::Unknown(at);
                links = 0;
            }
            links += 1;
            if self.p('?') {
                self.pos += 1;
                e = Ex::Try(Box::new(e));
                continue;
            }
            if self.p('.') && !self.seq("..") {
                self.pos += 1;
                if self.word("await") {
                    self.pos += 1;
                    e = Ex::Await(Box::new(e));
                    continue;
                }
                if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Num) {
                    // `.0`, and `.0.1` read as one number
                    let t = self.text(self.pos).to_vec();
                    self.pos += 1;
                    for part in t.split(|&c| c == '.' as u32) {
                        e = Ex::Field(Box::new(e), part.to_vec(), at);
                    }
                    continue;
                }
                if self.is_name(self.pos) {
                    let name = self.text(self.pos).to_vec();
                    self.pos += 1;
                    if self.seq("::") && self.is_p_at(self.pos + 2, '<') {
                        self.pos += 2;
                        self.skip_angles();
                    }
                    if self.p('(') {
                        let (args, next) = self.args(self.pos);
                        self.pos = next;
                        e = Ex::Method(Box::new(e), name, args, at);
                    } else {
                        e = Ex::Field(Box::new(e), name, at);
                    }
                    continue;
                }
                return e;
            }
            if self.p('(') {
                let (args, next) = self.args(self.pos);
                self.pos = next;
                e = Ex::Call(Box::new(e), args, at);
                continue;
            }
            if self.p('[') {
                let (mut g, next) = self.group(self.pos);
                let idx = g.expr(false);
                self.pos = next;
                e = Ex::Index(Box::new(e), Box::new(idx), at);
                continue;
            }
            if self.word("as") {
                self.pos += 1;
                let ty = self.skip_type();
                e = Ex::Cast(Box::new(e), ty);
                continue;
            }
            return e;
        }
    }

    /// Does a postfix operation start at pos?
    fn link_starts(&self) -> bool {
        self.p('?') || (self.p('.') && !self.seq("..")) || self.p('(') || self.p('[') || self.word("as")
    }

    fn block_at(&mut self, open: usize) -> Block {
        let (mut g, next) = self.group(open);
        let mut b = g.stmts();
        b.at = self.at(open);
        self.pos = next;
        b
    }

    fn primary(&mut self, no_struct: bool) -> Ex {
        let at = self.at(self.pos);
        let Some(tok) = self.tok(self.pos).copied() else { return Ex::Unknown(at) };
        self.skip_attrs();
        if self.pos >= self.end {
            return Ex::Unknown(at);
        }
        match tok.kind {
            TK::Str => {
                self.pos += 1;
                let t = self.text(self.pos - 1);
                return match crate::rsread::lit::literal(t) {
                    Some(crate::rsread::lit::Lit::Str(s, bytes)) => Ex::Str(s, bytes, at),
                    Some(crate::rsread::lit::Lit::Char(c)) => Ex::Char(c, at),
                    None => Ex::Unknown(at),
                };
            }
            TK::Num => {
                self.pos += 1;
                return match crate::rsread::lit::int_literal(self.text(self.pos - 1)) {
                    Some(n) => Ex::Int(n, at),
                    None => Ex::Unknown(at),
                };
            }
            _ => {}
        }
        // a label: `'a: loop {}`
        if tok.kind == TK::Name && self.text(self.pos).first() == Some(&('\'' as u32)) {
            if self.is_p_at(self.pos + 1, ':') && !self.seq_at(self.pos + 1, "::") {
                self.pos += 2;
                return self.deeper(at, |r| r.primary(no_struct));
            }
            self.pos += 1;
            return Ex::Unknown(at);
        }
        if self.p('(') {
            let (mut g, next) = self.group(self.pos);
            let mut items = Vec::new();
            let mut trailing = false;
            while g.pos < g.end {
                let start = g.pos;
                items.push(g.expr(false));
                trailing = false;
                if g.p(',') {
                    g.pos += 1;
                    trailing = true;
                } else if g.pos == start || g.pos < g.end {
                    g.pos = g.skip_to_comma();
                    if g.p(',') {
                        g.pos += 1;
                        trailing = true;
                    }
                }
            }
            self.pos = next;
            if items.len() == 1 && !trailing {
                return items.pop().unwrap_or(Ex::Unknown(at));
            }
            return Ex::Tuple(items, at);
        }
        if self.p('[') {
            let (mut g, next) = self.group(self.pos);
            let mut items = Vec::new();
            if g.pos < g.end {
                let first = g.expr(false);
                if g.p(';') {
                    g.pos += 1;
                    let n = g.expr(false);
                    self.pos = next;
                    return Ex::Repeat(Box::new(first), Box::new(n), at);
                }
                items.push(first);
                loop {
                    if g.p(',') {
                        g.pos += 1;
                    } else if g.pos < g.end {
                        g.pos = g.skip_to_comma();
                        if g.p(',') {
                            g.pos += 1;
                        }
                    }
                    if g.pos >= g.end {
                        break;
                    }
                    let start = g.pos;
                    items.push(g.expr(false));
                    if g.pos == start {
                        g.pos += 1;
                    }
                }
            }
            self.pos = next;
            return Ex::Array(items, at);
        }
        if self.p('{') {
            let b = self.block_at(self.pos);
            return Ex::Block(Box::new(b));
        }
        if self.p('|') || (self.word("move") && self.is_p_at(self.pos + 1, '|')) || (self.word("async") && (self.word_at(self.pos + 1, "move") || self.is_p_at(self.pos + 1, '|'))) {
            return self.closure(at);
        }
        if self.seq("::") || self.p('<') {
            return self.path_expr(no_struct, at);
        }
        if !self.is_name(self.pos) {
            self.pos += 1;
            return Ex::Unknown(at);
        }
        let w = self.text(self.pos);
        if is_word(w, "true") || is_word(w, "false") {
            self.pos += 1;
            return Ex::Bool(is_word(w, "true"), at);
        }
        if is_word(w, "if") {
            return self.if_expr(at);
        }
        if is_word(w, "match") {
            self.pos += 1;
            let scrut = self.expr(true);
            if !self.p('{') {
                return Ex::Unknown(at);
            }
            let (mut g, next) = self.group(self.pos);
            let mut arms = Vec::new();
            while g.pos < g.end {
                let start = g.pos;
                g.skip_attrs();
                let pat = g.pat_top();
                let mut guard = None;
                if g.word("if") {
                    g.pos += 1;
                    guard = Some(g.expr(false));
                }
                if g.seq("=>") {
                    g.pos += 2;
                    let body = g.expr(false);
                    arms.push(Arm { pat, guard, body });
                } else {
                    g.pos = g.skip_to_comma();
                }
                if g.p(',') {
                    g.pos += 1;
                } else if g.pos == start {
                    g.pos += 1;
                }
            }
            self.pos = next;
            return Ex::Match(Box::new(scrut), arms, at);
        }
        if is_word(w, "loop") {
            self.pos += 1;
            if !self.p('{') {
                return Ex::Unknown(at);
            }
            let b = self.block_at(self.pos);
            return Ex::Loop(Box::new(b), at);
        }
        if is_word(w, "while") {
            self.pos += 1;
            let cond = self.cond();
            if !self.p('{') {
                return Ex::Unknown(at);
            }
            let b = self.block_at(self.pos);
            return Ex::While(Box::new(cond), Box::new(b), at);
        }
        if is_word(w, "for") {
            self.pos += 1;
            let pat = self.pat_top();
            if self.word("in") {
                self.pos += 1;
            }
            let iter = self.expr(true);
            if !self.p('{') {
                return Ex::Unknown(at);
            }
            let b = self.block_at(self.pos);
            return Ex::For(pat, Box::new(iter), Box::new(b), at);
        }
        if (is_word(w, "unsafe") || is_word(w, "async") || is_word(w, "const")) && self.is_p_at(self.pos + 1, '{') {
            self.pos += 1;
            let b = self.block_at(self.pos);
            return Ex::Block(Box::new(b));
        }
        if is_word(w, "async") && self.word_at(self.pos + 1, "move") && self.is_p_at(self.pos + 2, '{') {
            self.pos += 2;
            let b = self.block_at(self.pos);
            return Ex::Block(Box::new(b));
        }
        if is_word(w, "return") || is_word(w, "break") || is_word(w, "yield") || is_word(w, "become") {
            let ret = is_word(w, "return") || is_word(w, "yield") || is_word(w, "become");
            self.pos += 1;
            // (a label)
            if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Name) && self.text(self.pos).first() == Some(&('\'' as u32)) {
                self.pos += 1;
            }
            let v = if self.can_start_expr() && !(no_struct && self.p('{')) { Some(Box::new(self.expr(no_struct))) } else { None };
            return if ret { Ex::Return(v, at) } else { Ex::Break(v, at) };
        }
        if is_word(w, "continue") {
            self.pos += 1;
            if matches!(self.tok(self.pos), Some(t) if t.kind == TK::Name) && self.text(self.pos).first() == Some(&('\'' as u32)) {
                self.pos += 1;
            }
            return Ex::Continue(at);
        }
        if is_word(w, "let") {
            self.pos += 1;
            let pat = self.pat_top();
            if self.p('=') {
                self.pos += 1;
            }
            let e = self.bin(3, true);
            return Ex::Let(pat, Box::new(e), at);
        }
        if is_word(w, "move") {
            self.pos += 1;
            return self.deeper(at, |r| r.primary(no_struct));
        }
        if self.is_keyword(self.pos) && !(is_word(w, "self") || is_word(w, "Self") || is_word(w, "crate") || is_word(w, "super")) {
            self.pos += 1;
            return Ex::Unknown(at);
        }
        self.path_expr(no_struct, at)
    }

    fn cond(&mut self) -> Ex {
        self.expr(true)
    }

    fn if_expr(&mut self, at: u32) -> Ex {
        self.pos += 1;
        let cond = self.cond();
        if !self.p('{') {
            return Ex::Unknown(at);
        }
        let then = self.block_at(self.pos);
        let mut els = None;
        if self.word("else") {
            self.pos += 1;
            if self.word("if") {
                let a = self.at(self.pos);
                els = Some(Box::new(self.deeper(a, |r| r.if_expr(a))));
            } else if self.p('{') {
                let b = self.block_at(self.pos);
                els = Some(Box::new(Ex::Block(Box::new(b))));
            }
        }
        Ex::If(Box::new(cond), Box::new(then), els, at)
    }

    fn closure(&mut self, at: u32) -> Ex {
        if self.word("async") {
            self.pos += 1;
        }
        if self.word("move") {
            self.pos += 1;
        }
        let mut params = Vec::new();
        if self.seq("||") {
            self.pos += 2;
        } else if self.p('|') {
            self.pos += 1;
            let mut guard = 0;
            while self.pos < self.end && !self.p('|') && guard < 1000 {
                guard += 1;
                let start = self.pos;
                params.push(self.pat());
                if self.p(':') {
                    self.pos += 1;
                    self.skip_type();
                }
                if self.p(',') {
                    self.pos += 1;
                } else if self.pos == start {
                    self.pos += 1;
                }
            }
            if self.p('|') {
                self.pos += 1;
            }
        }
        if self.seq("->") {
            self.pos += 2;
            self.skip_type();
        }
        let body = self.expr(false);
        Ex::Closure(params, Rc::new(body), at)
    }

    fn path_expr(&mut self, no_struct: bool, at: u32) -> Ex {
        let start = self.pos;
        let segs = self.path_segs();
        if segs.is_empty() {
            if self.pos == start {
                self.pos += 1;
            }
            return Ex::Unknown(at);
        }
        // a macro call
        if self.p('!') && !self.seq("!=") && self.is_open(self.pos + 1) {
            let open = self.pos + 1;
            let next = self.after_group(open);
            let close = next.saturating_sub(1).max(open);
            self.pos = next;
            return Ex::Macro(segs, open as u32, close as u32, at);
        }
        // a struct literal
        if self.p('{') && !no_struct && self.looks_struct(self.pos) {
            let (mut g, next) = self.group(self.pos);
            let mut fields = Vec::new();
            while g.pos < g.end {
                let s = g.pos;
                g.skip_attrs();
                if g.seq("..") {
                    g.pos += 2;
                    let _base = g.expr(false);
                    continue;
                }
                if g.is_name(g.pos) || matches!(g.tok(g.pos), Some(t) if t.kind == TK::Num) {
                    let name = g.text(g.pos).to_vec();
                    let fat = g.at(g.pos);
                    g.pos += 1;
                    if g.p(':') && !g.seq("::") {
                        g.pos += 1;
                        let v = g.expr(false);
                        fields.push((name, v));
                    } else {
                        fields.push((name.clone(), Ex::Path(vec![name], fat)));
                    }
                } else {
                    g.pos = g.skip_to_comma();
                }
                if g.p(',') {
                    g.pos += 1;
                } else if g.pos == s {
                    g.pos += 1;
                }
            }
            self.pos = next;
            return Ex::Struct(segs, fields, at);
        }
        Ex::Path(segs, at)
    }

    /// Does the brace group at `open` hold a struct literal's fields (`{}`, `{ a: …`, `{ a, …`, `{ a }`, `{ ..x }`)?
    fn looks_struct(&self, open: usize) -> bool {
        let i = open + 1;
        let close = self.after_group(open).saturating_sub(1);
        if i >= close {
            return true;
        }
        if self.seq_at(i, "..") {
            return true;
        }
        if self.is_name(i) || matches!(self.tok(i), Some(t) if t.kind == TK::Num) {
            return (self.is_p_at(i + 1, ':') && !self.seq_at(i + 1, "::")) || self.is_p_at(i + 1, ',') || i + 1 == close;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsparse;

    fn u(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn body(src: &str) -> Block {
        let text = u(src);
        let tree = rsparse::parse(&text);
        let f = tree.items.iter().find(|it| it.kind == rsparse::Kind::Fn).expect("a function");
        let t = Toks { src: &text, toks: &tree.toks, mate: &tree.mate };
        block(t, f.body_open as usize)
    }

    fn s(v: &[u32]) -> String {
        v.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect()
    }

    #[test]
    fn statements_and_lets() {
        let b = body("fn main() { let x = 1; let mut y: Vec<u8> = vec![1, 2]; y.push(3); let Some(z) = f() else { return; }; x }");
        assert_eq!(b.stmts.len(), 4);
        assert!(matches!(&b.stmts[0], Stmt::Let(Pat::Bind(n), Some(Ex::Int(1, _)), None) if s(n) == "x"));
        assert!(matches!(&b.stmts[1], Stmt::Let(Pat::Bind(n), Some(Ex::Macro(..)), None) if s(n) == "y"));
        assert!(matches!(&b.stmts[2], Stmt::Expr(Ex::Method(_, m, a, _)) if s(m) == "push" && a.len() == 1));
        assert!(matches!(&b.stmts[3], Stmt::Let(Pat::TupleStruct(n, _), Some(Ex::Call(..)), Some(_)) if s(n) == "Some"));
        assert!(matches!(&b.tail, Some(Ex::Path(p, _)) if s(&p[0]) == "x"));
    }

    #[test]
    fn a_command_builder_chain() {
        let b = body("fn main() { std::process::Command::new(\"sh\").arg(\"-c\").args([\"a\", \"b\"]).spawn().unwrap(); }");
        let Stmt::Expr(e) = &b.stmts[0] else { panic!() };
        // unwrap( spawn( args( arg( new(…) ) ) ) )
        let Ex::Method(inner, m, _, _) = e else { panic!("{:?}", e) };
        assert_eq!(s(m), "unwrap");
        let Ex::Method(inner, m, _, _) = &**inner else { panic!() };
        assert_eq!(s(m), "spawn");
        let Ex::Method(inner, m, a, _) = &**inner else { panic!() };
        assert_eq!(s(m), "args");
        assert!(matches!(&a[0], Ex::Array(items, _) if items.len() == 2));
        let Ex::Method(inner, m, a, _) = &**inner else { panic!() };
        assert_eq!(s(m), "arg");
        assert!(matches!(&a[0], Ex::Str(v, false, _) if s(v) == "-c"));
        let Ex::Call(callee, a, _) = &**inner else { panic!() };
        assert!(matches!(&**callee, Ex::Path(p, _) if p.iter().map(|x| s(x)).collect::<Vec<_>>() == ["std", "process", "Command", "new"]));
        assert!(matches!(&a[0], Ex::Str(v, _, _) if s(v) == "sh"));
    }

    #[test]
    fn operators_casts_and_turbofish() {
        let b = body("fn f() { let a = x + y * 2 == 3 && !z; let c = b as char; let v = it.collect::<Vec<u8>>(); a ^= 0x42; }");
        // (the operators of one level read flat, left to right: ((x + y * 2) == 3) && !z)
        assert!(matches!(&b.stmts[0], Stmt::Let(_, Some(Ex::Chain(_, rest)), _) if rest.iter().map(|r| r.0).collect::<Vec<_>>() == [Op::Add, Op::Eq, Op::And]));
        assert!(matches!(&b.stmts[1], Stmt::Let(_, Some(Ex::Cast(_, t)), _) if s(t) == "char"));
        assert!(matches!(&b.stmts[2], Stmt::Let(_, Some(Ex::Method(_, m, _, _)), _) if s(m) == "collect"));
        assert!(matches!(&b.stmts[3], Stmt::Expr(Ex::Assign(Some(Op::BitXor), ..))));
    }

    #[test]
    fn conditions_are_not_struct_literals() {
        let b = body("fn f() { if a == B { g(); } else if let Some(x) = y { h(x); } else { k(); } let s = S { a: 1, b }; }");
        assert!(matches!(&b.stmts[0], Stmt::Expr(Ex::If(c, _, Some(_), _)) if matches!(&**c, Ex::Bin(Op::Eq, ..))));
        assert!(matches!(&b.stmts[1], Stmt::Let(_, Some(Ex::Struct(_, f, _)), _) if f.len() == 2));
    }

    #[test]
    fn closures_matches_loops_and_macros() {
        let b = body("fn f() { let d: Vec<u8> = v.iter().map(|b| b ^ 0x5a).collect(); match r { Ok(x) => x, Err(_) => return }; for (i, c) in s.chars().enumerate() { out.push(c); } let u = format!(\"{}/{}\", a, b); }");
        assert!(matches!(&b.stmts[0], Stmt::Let(_, Some(Ex::Method(_, m, _, _)), _) if s(m) == "collect"));
        assert!(matches!(&b.stmts[1], Stmt::Expr(Ex::Match(_, arms, _)) if arms.len() == 2));
        assert!(matches!(&b.stmts[2], Stmt::Expr(Ex::For(Pat::Tuple(p), _, _, _)) if p.len() == 2));
        assert!(matches!(&b.stmts[3], Stmt::Let(_, Some(Ex::Macro(p, _, _, _)), _) if s(&p[0]) == "format"));
    }

    #[test]
    fn local_constants_are_lets_and_items_are_skipped() {
        let b = body("fn f() { const C: &str = \"x\"; fn g() {} struct S; use std::fs; static mut N: u8 = 1; g(); }");
        assert!(matches!(&b.stmts[0], Stmt::Let(Pat::Bind(n), Some(Ex::Str(v, _, _)), None) if s(n) == "C" && s(v) == "x"));
        assert!(matches!(&b.stmts[1], Stmt::Let(Pat::Bind(n), Some(Ex::Int(1, _)), None) if s(n) == "N"));
        assert!(matches!(&b.stmts[2], Stmt::Expr(Ex::Call(..))));
        assert_eq!(b.stmts.len(), 3);
    }

    #[test]
    fn what_is_not_rust_is_unknown_and_the_rest_is_read() {
        let b = body("fn f() { let a = ) ; let b = \"ok\"; }");
        assert!(matches!(&b.stmts.last(), Some(Stmt::Let(Pat::Bind(n), Some(Ex::Str(v, _, _)), _)) if s(n) == "b" && s(v) == "ok"));
        // deep nesting reads without overflowing
        let deep = format!("fn f() {{ let a = {}1{}; }}", "(".repeat(5000), ")".repeat(5000));
        let _ = body(&deep);
        let deep = format!("fn f() {{ let a = {}1; }}", "-".repeat(20000));
        let _ = body(&deep);
    }
}
