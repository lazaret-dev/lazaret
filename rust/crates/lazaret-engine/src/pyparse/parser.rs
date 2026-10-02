//! The parser: Python 3.13's grammar, top-down, one token of look-ahead
//! (two or three where the grammar asks: a keyword argument's `=`, a
//! walrus's `:=`, `not in`, `is not`), building the tree bottom-up.
//! Statements are here; expressions, targets and strings in `expr.rs`,
//! match patterns in `pattern.rs`.
//!
//! The grammar is a PEG; where its ordered choices would read ahead without
//! bound, the parser decides another way that gives the same answer:
//!
//! - an assignment's targets are read as expressions, then checked and given
//!   their context (Store, Del) once the `=`, `:` or augmented operator after
//!   them says what they are;
//! - a `for`'s targets (and a comprehension's) are primaries, read up to the
//!   `in` they cannot hold;
//! - a statement starting with the soft keyword `match` is a match statement
//!   when its first line ends with `:` (any other reading of such a line is
//!   an error);
//! - `with (`: the parenthesized items are read first when the matching `)`
//!   is followed by `:`, and if they are not items, the parentheses are read
//!   again as an expression: the one place the parser backtracks, at most
//!   once over each token.
//!
//! Recursion follows the brackets (at most 200 deep: the tokenizer's limit),
//! blocks (at most 99) and f-strings; chains that nest without brackets
//! (unary operators, `**`, lambda bodies, conditional expressions, `elif`)
//! are read in loops. `level` follows what Python's parser keeps on its own
//! stack, which it refuses past 6000 ("too complex"), so that every input
//! Python refuses for nesting is refused here (`limits`).

use super::lexer::*;
use super::limits as L;
use super::tree::*;

/// Why a read stopped: a syntax error, which a speculative read may take
/// back, or one it may not (a literal's value, the nesting limit).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    Syntax,
    Fatal,
}

pub type R<X> = Result<X, Fail>;

/// An expression read: its node, and where its tokens start and end
/// (parentheses around it included; the node's own span is inside them).
#[derive(Clone, Copy, Debug)]
pub struct Ex {
    pub n: NodeId,
    pub s: u32,
    pub e: u32,
}

/// A piece of a string (an implicit concatenation of literals and
/// f-strings): text (in `Parser::text`) or a FormattedValue node.
#[derive(Clone, Copy, Debug)]
pub enum Piece {
    Text { at: u32, len: u32, s: u32, e: u32, u: bool },
    Node(NodeId),
}

pub struct Parser<'a> {
    pub src: &'a [u32],
    pub toks: Vec<Tok>,
    pub p: usize,
    pub tree: Tree,
    /// items of lists being built
    pub stack: Vec<u32>,
    /// comments inside f-strings' replacement fields
    pub comments: Vec<(u32, u32)>,
    /// string pieces and their text, being built
    pub pieces: Vec<Piece>,
    pub text: Vec<u32>,
    /// what Python's parser would have on its stack here (`limits`)
    pub level: u32,
    /// the deepest it went
    pub max_level: u32,
    pub err_at: u32,
    pub err_why: String,
    /// expressions inside `lambda` / `if … else` being read (expression())
    pub pending: Vec<Pending>,
    /// `from __future__ import barry_as_FLUFL` was read: `<>` is `!=`, and
    /// `!=` an error, from there on
    pub barry: bool,
    /// the token a bracket is cheap at (`limits`): where a statement or an
    /// assignment's value starts
    pub cheap_at: usize,
    /// … and where a statement starts with `((`, the second `(` is nearly free
    pub second_paren_at: usize,
    /// the token after the `(` a statement starts with (an f-string there
    /// costs less, `limits::FSTRING`)
    pub first_in_paren_at: usize,
    /// the `match` a line Python first reads as a match statement starts
    /// with (`limits::MATCH_LIKE`)
    pub subject_at: usize,
    /// f-strings and format specifiers being read
    pub fdepth: u32,
    pub spec_depth: u32,
    /// lambda defaults being read
    pub lambda_defaults: u32,
    /// the token the tokenizer refused (the last token, `T::Error`)
    pub lex_fail: Option<LexFail>,
    /// the furthest token reached before going back (`with (`, a read ahead)
    pub p_max: usize,
    /// the read stopped at the nesting limit
    pub too_deep: bool,
    /// reads ahead in progress (`read_ahead`) with the error pass's own
    /// checks off inside them, and with them on (at most one: `NAME expr`)
    pub ahead: u32,
    pub ahead_checked: u32,
    /// the token where `expression()` reads without the error pass's checks
    /// of its own level (a dict's key after its first item: Python reports
    /// "':' expected after dictionary key" there instead)
    pub unchecked_at: usize,
    /// the error is one Python raises (its error pass's, a literal's …),
    /// not its parser's generic one: even where the read stopped at an
    /// INDENT or a DEDENT, an error its tokenizer raises further on takes
    /// its place (`error`)
    pub err_specific: bool,
}

/// What a read ahead puts back.
struct Saved {
    p: usize,
    nodes: usize,
    lists: usize,
    level: u32,
    pending: usize,
    stack: usize,
    pieces: usize,
    text: usize,
    depths: (u32, u32, u32),
    cheap: (usize, usize, usize),
    err_at: u32,
    err_specific: bool,
    too_deep: bool,
}

/// A lambda or a conditional expression whose last part (the lambda's
/// body, the conditional's `else`) is being read.
#[derive(Clone, Copy, Debug)]
pub enum Pending {
    Lambda { args: NodeId, s: u32 },
    IfExp { body: Ex, test: Ex },
}

impl<'a> Parser<'a> {
    pub fn new(src: &'a [u32], lexed: super::lexer::Lexed) -> Parser<'a> {
        let mut tree = Tree::new();
        tree.strings = lexed.strings;
        tree.line_starts = lexed.line_starts;
        tree.nodes.reserve(lexed.toks.len());
        Parser {
            src,
            toks: lexed.toks,
            p: 0,
            tree,
            stack: Vec::new(),
            comments: lexed.comments,
            pieces: Vec::new(),
            text: Vec::new(),
            level: 0,
            max_level: 0,
            err_at: 0,
            err_why: String::new(),
            pending: Vec::new(),
            barry: false,
            cheap_at: usize::MAX,
            second_paren_at: usize::MAX,
            first_in_paren_at: usize::MAX,
            subject_at: usize::MAX,
            fdepth: 0,
            spec_depth: 0,
            lambda_defaults: 0,
            lex_fail: lexed.fail,
            p_max: 0,
            too_deep: false,
            ahead: 0,
            ahead_checked: 0,
            unchecked_at: usize::MAX,
            err_specific: false,
        }
    }

    /// Reads with `read`, then goes back to where it started (keeping the
    /// furthest token reached, `p_max`): the token index where the read
    /// ended if it read, None if it failed. An error no reading takes back
    /// (a literal's value, the nesting limit, an error of the error pass's
    /// checks when `checked`) is the read's error.
    pub fn read_ahead(&mut self, read: fn(&mut Self) -> R<Ex>, checked: bool) -> R<Option<usize>> {
        let saved = Saved {
            p: self.p,
            nodes: self.tree.nodes.len(),
            lists: self.tree.lists.len(),
            level: self.level,
            pending: self.pending.len(),
            stack: self.stack.len(),
            pieces: self.pieces.len(),
            text: self.text.len(),
            depths: (self.fdepth, self.spec_depth, self.lambda_defaults),
            cheap: (self.cheap_at, self.second_paren_at, self.first_in_paren_at),
            err_at: self.err_at,
            err_specific: self.err_specific,
            too_deep: self.too_deep,
        };
        let why = std::mem::take(&mut self.err_why);
        let counter = if checked { &mut self.ahead_checked } else { &mut self.ahead };
        *counter += 1;
        let r = read(self);
        if checked {
            self.ahead_checked -= 1;
        } else {
            self.ahead -= 1;
        }
        self.p_max = self.p_max.max(self.p);
        let end = self.p;
        if matches!(r, Err(Fail::Fatal)) {
            return Err(Fail::Fatal);
        }
        self.p = saved.p;
        self.tree.nodes.truncate(saved.nodes);
        self.tree.lists.truncate(saved.lists);
        self.level = saved.level;
        self.pending.truncate(saved.pending);
        self.stack.truncate(saved.stack);
        self.pieces.truncate(saved.pieces);
        self.text.truncate(saved.text);
        (self.fdepth, self.spec_depth, self.lambda_defaults) = saved.depths;
        (self.cheap_at, self.second_paren_at, self.first_in_paren_at) = saved.cheap;
        self.err_at = saved.err_at;
        self.err_specific = saved.err_specific;
        self.err_why = why;
        self.too_deep = saved.too_deep;
        Ok(if r.is_ok() { Some(end) } else { None })
    }

    /// The brackets open after the tokens before `upto`.
    pub fn brackets_open(&self, upto: usize) -> i64 {
        let mut depth = 0i64;
        for t in &self.toks[..upto.min(self.toks.len())] {
            if t.t == T::Op {
                match t.k {
                    LPAR | LSQB | LBRACE => depth += 1,
                    RPAR | RSQB | RBRACE => depth -= 1,
                    _ => {}
                }
            }
        }
        depth
    }

    /// The error Python reports, once the read has failed (line 0: Python's
    /// error has no line, a MemoryError).
    ///
    /// Python's parser takes tokens from its tokenizer as it goes: a token
    /// the tokenizer refuses at or before where the read stopped is the
    /// error. Past it, the parser's error stands, except that Python then
    /// tokenizes the rest of the text (unless the read stopped at an INDENT
    /// or a DEDENT with no error of its own raised: "unexpected indent",
    /// "unexpected unindent"; an "expected an indented block" is one) and an
    /// error its tokenizer raises there takes its place; one it leaves to
    /// the parser does not, but if brackets are open there, the innermost
    /// opened on a line before the one where the read stopped is reported as
    /// never closed (neither, where the tokenizer stopped inside an
    /// f-string).
    pub fn error(&mut self) -> (u32, String) {
        let reached = self.p_max.max(self.p);
        if let Some(f) = &self.lex_fail {
            if f.tok <= reached {
                return (f.line, f.reason.clone());
            }
        }
        if self.too_deep {
            return (0, std::mem::take(&mut self.err_why));
        }
        let stop = self.toks.get(self.p).map_or(T::End, |t| t.t);
        if let Some(f) = &self.lex_fail {
            if (!matches!(stop, T::Indent | T::Dedent) || self.err_specific) && !f.in_fstring {
                if f.raised {
                    return (f.line, f.reason.clone());
                }
                let stop_line = self.line_at(self.toks.get(reached).map_or(self.src.len() as u32, |t| t.s));
                if f.open.1 != 0 && f.open.1 < stop_line {
                    let ch = char::from_u32(f.open.0).unwrap_or('(');
                    return (f.open.1, format!("'{}' was never closed", ch));
                }
            }
        }
        (self.line_at(self.err_at), std::mem::take(&mut self.err_why))
    }

    /// The line of a code-point offset, as Python numbers the tokens at the
    /// end of the text: on the last line (the one a final line break ends).
    pub fn line_at(&self, at: u32) -> u32 {
        let n = self.src.len();
        if at as usize >= n && n > 0 && matches!(self.src[n - 1], 0x0A | 0x0D) {
            return self.tree.line_of(n as u32 - 1);
        }
        self.tree.line_of(at)
    }

    // ---- tokens ----

    /// The token at the read's position (past the last token, the last one:
    /// `End`, or `Error` where the tokenizer stopped).
    #[inline]
    pub fn tok(&self) -> Tok {
        match self.toks.get(self.p) {
            Some(&t) => t,
            None => self.last_tok(),
        }
    }

    #[inline]
    pub fn peek(&self, k: usize) -> Tok {
        match self.toks.get(self.p + k) {
            Some(&t) => t,
            None => self.last_tok(),
        }
    }

    #[cold]
    fn last_tok(&self) -> Tok {
        let n = self.src.len() as u32;
        self.toks.last().copied().unwrap_or(Tok { t: T::End, k: 0, s: n, e: n, v: 0 })
    }

    #[inline]
    pub fn at_op(&self, op: u8) -> bool {
        let t = self.tok();
        t.t == T::Op && t.k == op
    }

    #[inline]
    pub fn at_kw(&self, kw: u8) -> bool {
        let t = self.tok();
        t.t == T::Kw && t.k == kw
    }

    /// Is the token the soft keyword `id` (its text exactly the keyword)?
    #[inline]
    pub fn is_soft(t: Tok, id: u32) -> bool {
        t.t == T::Name && t.k == 0 && t.v == id
    }

    #[inline]
    pub fn advance(&mut self) -> Tok {
        let t = self.tok();
        if self.p < self.toks.len() {
            self.p += 1;
        }
        t
    }

    #[inline]
    pub fn eat_op(&mut self, op: u8) -> Option<Tok> {
        if self.at_op(op) {
            Some(self.advance())
        } else {
            None
        }
    }

    pub fn expect_op(&mut self, op: u8) -> R<Tok> {
        if self.at_op(op) {
            Ok(self.advance())
        } else {
            let what = format!("expected '{}'", OPS.get(op as usize).copied().unwrap_or("?"));
            self.fail(&what)
        }
    }

    pub fn expect_kw(&mut self, kw: u8) -> R<Tok> {
        if self.at_kw(kw) {
            Ok(self.advance())
        } else {
            let what = format!("expected '{}'", KEYWORDS.get(kw as usize).copied().unwrap_or("?"));
            self.fail(&what)
        }
    }

    pub fn expect_name(&mut self) -> R<Tok> {
        if self.tok().t == T::Name {
            Ok(self.advance())
        } else {
            self.fail("expected a name")
        }
    }

    /// The end of the last token read that is not a line's structure
    /// (NEWLINE, INDENT, DEDENT).
    pub fn last_end(&self) -> u32 {
        let mut k = self.p;
        while k > 0 {
            k -= 1;
            let t = self.toks[k];
            if !matches!(t.t, T::Newline | T::Indent | T::Dedent) {
                return t.e;
            }
        }
        0
    }

    /// A syntax error at the current token.
    pub fn fail<X>(&mut self, why: &str) -> R<X> {
        let at = self.tok().s;
        self.fail_at(at, why)
    }

    pub fn fail_at<X>(&mut self, at: u32, why: &str) -> R<X> {
        self.err_at = at;
        self.err_specific = false;
        self.err_why.clear();
        self.err_why.push_str(why);
        Err(Fail::Syntax)
    }

    /// A syntax error at the current token that Python raises itself (its
    /// error pass's: "expected an indented block" …), not its generic one.
    pub fn fail_specific<X>(&mut self, why: &str) -> R<X> {
        let r = self.fail(why);
        self.err_specific = true;
        r
    }

    /// An error of Python's error pass (one of its `invalid_` rules): no
    /// other reading takes it back, except in a read ahead without the error
    /// pass's checks.
    pub fn pass_fail_at<X>(&mut self, at: u32, why: &str) -> R<X> {
        if self.ahead == 0 {
            self.fatal_at(at, why)
        } else {
            self.fail_at(at, why)
        }
    }

    /// An error no other reading takes back.
    pub fn fatal_at<X>(&mut self, at: u32, why: &str) -> R<X> {
        self.err_at = at;
        self.err_specific = true;
        self.err_why.clear();
        self.err_why.push_str(why);
        Err(Fail::Fatal)
    }

    // ---- the tree ----

    #[inline]
    pub fn add(&mut self, kind: Kind, op: u8, s: u32, e: u32, f: [u32; 4]) -> NodeId {
        let id = self.tree.nodes.len() as u32;
        self.tree.nodes.push(Node { kind, op, flags: 0, start: s, end: e, f });
        id
    }

    /// A list of the stack's items from `mark` on (taken off the stack).
    #[inline]
    pub fn list_from(&mut self, mark: usize) -> u32 {
        let id = self.tree.push_list(&self.stack[mark..]);
        self.stack.truncate(mark);
        id
    }

    /// An extension list (`tree::ext_len`).
    pub fn ext(&mut self, items: &[u32]) -> u32 {
        let id = self.tree.lists.len() as u32;
        self.tree.lists.push(items.len() as u32);
        self.tree.lists.extend_from_slice(items);
        id
    }

    #[inline]
    pub fn kind(&self, id: NodeId) -> Kind {
        self.tree.nodes[id as usize].kind
    }

    // ---- the nesting limit ----

    /// Goes `cost` deeper (`limits`); refuses past the limit.
    #[inline]
    pub fn enter(&mut self, cost: u32) -> R<()> {
        self.level += cost;
        if self.level > self.max_level {
            self.max_level = self.level;
            if self.level > super::limits::MAX_LEVEL {
                let at = self.tok().s;
                self.too_deep = true;
                return self.fatal_at(at, "too complex: nesting too deep");
            }
        }
        Ok(())
    }

    #[inline]
    pub fn leave(&mut self, cost: u32) {
        self.level -= cost.min(self.level);
    }

    // ---- statements ----

    /// The module: statements up to the end.
    pub fn module(&mut self) -> R<NodeId> {
        self.enter(L::MODULE)?;
        let mark = self.stack.len();
        while self.tok().t != T::End {
            if self.tok().t == T::Indent {
                return self.fail("unexpected indent");
            }
            if self.tok().t == T::Dedent || self.tok().t == T::Newline {
                return self.fail("invalid syntax");
            }
            self.statement()?;
        }
        let body = self.list_from(mark);
        let id = self.add(Kind::Module, 0, 0, self.src.len() as u32, [body, NONE, NONE, NONE]);
        Ok(id)
    }

    /// One statement (a line of simple statements pushes each): its nodes go
    /// on the stack.
    pub fn statement(&mut self) -> R<()> {
        let t = self.tok();
        match t.t {
            T::Kw => match t.k {
                KW_DEF | KW_IF | KW_CLASS | KW_WITH | KW_FOR | KW_TRY | KW_WHILE | KW_ASYNC => {
                    let id = self.compound()?;
                    self.stack.push(id);
                    return Ok(());
                }
                _ => {}
            },
            T::Op if t.k == AT => {
                let id = self.compound()?;
                self.stack.push(id);
                return Ok(());
            }
            T::Name if Self::is_soft(t, S_MATCH) && self.subject_follows() => {
                if self.match_line() {
                    let id = self.match_stmt()?;
                    self.stack.push(id);
                    return Ok(());
                }
                // (Python reads the line as a match statement first)
                self.subject_at = self.p;
                self.enter(L::MATCH_LIKE)?;
                self.simple_stmts()?;
                self.leave(L::MATCH_LIKE);
                return Ok(());
            }
            _ => {}
        }
        self.simple_stmts()
    }

    /// Can the token after `match` start a subject?
    fn subject_follows(&self) -> bool {
        let next = self.peek(1);
        match next.t {
            T::Name | T::Number | T::Str | T::FStart => true,
            T::Kw => matches!(next.k, KW_NONE | KW_TRUE | KW_FALSE | KW_NOT | KW_LAMBDA | KW_AWAIT),
            T::Op => matches!(next.k, LPAR | LSQB | LBRACE | MINUS | PLUS | TILDE | STAR | ELLIPSIS),
            _ => false,
        }
    }

    /// Does the line the `match` starts end with `:` (a match statement)?
    fn match_line(&self) -> bool {
        if !self.subject_follows() {
            return false;
        }
        let mut k = self.p + 1;
        while let Some(t) = self.toks.get(k) {
            match t.t {
                T::Newline | T::End | T::Indent | T::Dedent => {
                    let last = self.toks.get(k - 1);
                    return matches!(last, Some(l) if l.t == T::Op && l.k == COLON) && k - 1 > self.p + 1;
                }
                _ => k += 1,
            }
        }
        false
    }

    /// Simple statements on one line, `;` between them.
    fn simple_stmts(&mut self) -> R<()> {
        let mut extra = 0;
        loop {
            let id = self.simple_stmt()?;
            self.stack.push(id);
            if self.eat_op(SEMI).is_some() {
                if self.tok().t == T::Newline {
                    break;
                }
                if extra == 0 {
                    extra = L::SEMI_STMT;
                    self.enter(extra)?;
                }
                continue;
            }
            break;
        }
        self.leave(extra);
        if self.tok().t != T::Newline {
            return self.fail("invalid syntax");
        }
        self.advance();
        Ok(())
    }

    fn simple_stmt(&mut self) -> R<NodeId> {
        let t = self.tok();
        let s = t.s;
        if t.t == T::Kw {
            match t.k {
                KW_PASS | KW_BREAK | KW_CONTINUE => {
                    self.advance();
                    let kind = match t.k {
                        KW_PASS => Kind::Pass,
                        KW_BREAK => Kind::Break,
                        _ => Kind::Continue,
                    };
                    return Ok(self.add(kind, 0, s, t.e, [NONE; 4]));
                }
                KW_RETURN => {
                    self.advance();
                    let (value, e) = if self.starts_expression() {
                        self.enter(L::STMT + L::RETURN)?;
                        let x = self.star_expressions()?;
                        self.leave(L::STMT + L::RETURN);
                        (x.n, x.e)
                    } else {
                        (NONE, t.e)
                    };
                    return Ok(self.add(Kind::Return, 0, s, e, [value, NONE, NONE, NONE]));
                }
                KW_RAISE => {
                    self.advance();
                    if !self.starts_expression() {
                        return Ok(self.add(Kind::Raise, 0, s, t.e, [NONE, NONE, NONE, NONE]));
                    }
                    self.enter(L::STMT)?;
                    let exc = self.expression()?;
                    let mut e = exc.e;
                    let mut cause = NONE;
                    if self.at_kw(KW_FROM) {
                        self.advance();
                        self.enter(L::SECOND_PART)?;
                        let c = self.expression()?;
                        self.leave(L::SECOND_PART);
                        cause = c.n;
                        e = c.e;
                    }
                    self.leave(L::STMT);
                    return Ok(self.add(Kind::Raise, 0, s, e, [exc.n, cause, NONE, NONE]));
                }
                KW_GLOBAL | KW_NONLOCAL => {
                    self.advance();
                    let mark = self.stack.len();
                    let mut e;
                    loop {
                        let n = self.expect_name()?;
                        self.stack.push(n.v);
                        e = n.e;
                        if self.eat_op(COMMA).is_none() {
                            break;
                        }
                    }
                    let names = self.list_from(mark);
                    let kind = if t.k == KW_GLOBAL { Kind::Global } else { Kind::Nonlocal };
                    return Ok(self.add(kind, 0, s, e, [names, NONE, NONE, NONE]));
                }
                KW_DEL => {
                    self.advance();
                    return self.del_stmt(s);
                }
                KW_ASSERT => {
                    self.advance();
                    self.enter(L::STMT)?;
                    let test = self.expression()?;
                    let mut e = test.e;
                    let mut msg = NONE;
                    if self.eat_op(COMMA).is_some() {
                        self.enter(L::SECOND_PART)?;
                        let m = self.expression()?;
                        self.leave(L::SECOND_PART);
                        msg = m.n;
                        e = m.e;
                    }
                    self.leave(L::STMT);
                    return Ok(self.add(Kind::Assert, 0, s, e, [test.n, msg, NONE, NONE]));
                }
                KW_IMPORT => return self.import_name(),
                KW_FROM => return self.import_from(),
                _ => {}
            }
        }
        if Self::is_soft(t, S_TYPE) && self.peek(1).t == T::Name {
            return self.type_alias();
        }
        self.expr_stmt()
    }

    /// An expression statement, an assignment, an augmented or annotated
    /// assignment.
    fn expr_stmt(&mut self) -> R<NodeId> {
        let s = self.tok().s;
        self.enter(L::STMT)?;
        self.cheap_at = if self.p == self.subject_at { usize::MAX } else { self.p };
        if self.at_op(LPAR) {
            self.first_in_paren_at = self.p + 1;
            if self.peek(1).t == T::Op && self.peek(1).k == LPAR {
                self.second_paren_at = self.p + 1;
            }
        }
        let first = if self.at_kw(KW_YIELD) {
            self.enter(L::YIELD_STMT)?;
            let y = self.yield_expr()?;
            self.leave(L::YIELD_STMT);
            y
        } else {
            self.star_expressions()?
        };
        // (a target is checked where Python's error pass checks it: an
        // assignment's at its `=`, before what follows is read; an augmented
        // or annotated one's once what follows begins to read)
        let t = self.tok();
        let r = if t.t == T::Op && t.k == EQUAL {
            let mark = self.stack.len();
            if self.to_target(first.n, STORE, true).is_err() {
                // (Python's error pass reads the bitwise_or after the `=`
                // first, its checks on: an error there comes first)
                if self.ahead == 0 && self.assignable_bitor(first) {
                    let at = self.p;
                    self.advance();
                    self.read_prefix(Self::bitor, true, false)?;
                    self.p = at;
                }
                return Err(Fail::Syntax);
            }
            self.stack.push(first.n);
            let value;
            self.enter(L::ASSIGN_VALUE)?;
            loop {
                self.advance(); // =
                self.cheap_at = self.p;
                let rhs = if self.at_kw(KW_YIELD) { self.yield_expr()? } else { self.star_expressions()? };
                if self.at_op(EQUAL) {
                    self.to_target(rhs.n, STORE, true)?;
                    self.stack.push(rhs.n);
                    continue;
                }
                value = rhs;
                break;
            }
            self.leave(L::ASSIGN_VALUE);
            let targets = self.list_from(mark);
            self.add(Kind::Assign, 0, s, value.e, [targets, value.n, NONE, NONE])
        } else if t.t == T::Op && aug_op(t.k).is_some() {
            let op = aug_op(t.k).unwrap_or(ADD);
            self.advance();
            let after = self.p;
            self.enter(L::ASSIGN_VALUE)?;
            let value = if self.at_kw(KW_YIELD) {
                self.yield_expr()
            } else {
                self.star_expressions()
            };
            let value = self.target_then(first, after, value)?;
            self.leave(L::ASSIGN_VALUE);
            self.add(Kind::AugAssign, op, s, value.e, [first.n, value.n, NONE, NONE])
        } else if t.t == T::Op && t.k == COLON {
            let simple = self.kind(first.n) == Kind::Name && first.s == self.tree.nodes[first.n as usize].start;
            self.advance();
            let after = self.p;
            let ann = self.expression();
            let ann = self.target_then(first, after, ann)?;
            let mut e = ann.e;
            let mut value = NONE;
            if self.eat_op(EQUAL).is_some() {
                self.enter(L::ANN_VALUE)?;
                let v = if self.at_kw(KW_YIELD) { self.yield_expr()? } else { self.star_expressions()? };
                self.leave(L::ANN_VALUE);
                value = v.n;
                e = v.e;
            }
            let id = self.add(Kind::AnnAssign, 0, s, e, [first.n, ann.n, value, NONE]);
            if simple {
                self.tree.nodes[id as usize].flags |= SIMPLE;
            }
            id
        } else {
            self.add(Kind::Expr, 0, first.s, first.e, [first.n, NONE, NONE, NONE])
        };
        self.leave(L::STMT);
        Ok(r)
    }

    /// An augmented or annotated assignment's target `x`, checked once what
    /// follows (`read`, from the token `after`) has been read: a target that
    /// is not one is the error even where what follows fails, if it begins
    /// with an expression (Python's error pass takes the longest part that
    /// reads).
    fn target_then(&mut self, x: Ex, after: usize, read: R<Ex>) -> R<Ex> {
        match read {
            Ok(v) => {
                self.single_target(x)?;
                Ok(v)
            }
            Err(Fail::Fatal) => Err(Fail::Fatal),
            Err(Fail::Syntax) => {
                let begins = self.toks.get(after).map_or(false, |&t| Self::starts_expr(t) || (t.t == T::Kw && t.k == KW_YIELD));
                if begins && !matches!(self.kind(x.n), Kind::Name | Kind::Attribute | Kind::Subscript) {
                    self.single_target(x)?;
                }
                Err(Fail::Syntax)
            }
        }
    }

    /// The target of an augmented or annotated assignment: a name, an
    /// attribute or a subscript (in parentheses or not), given Store.
    fn single_target(&mut self, x: Ex) -> R<()> {
        match self.kind(x.n) {
            Kind::Name | Kind::Attribute | Kind::Subscript => {
                self.tree.nodes[x.n as usize].op = STORE;
                Ok(())
            }
            _ => {
                let at = self.tree.nodes[x.n as usize].start;
                self.fail_at(at, "illegal target for this assignment")
            }
        }
    }

    fn del_stmt(&mut self, s: u32) -> R<NodeId> {
        let mark = self.stack.len();
        let mut e;
        self.enter(L::STMT + L::DEL)?;
        loop {
            self.cheap_at = self.p;
            let x = self.del_target_expr()?;
            self.to_target(x.n, DEL, false)?;
            self.stack.push(x.n);
            e = x.e;
            match self.eat_op(COMMA) {
                Some(c) => {
                    e = c.e;
                    let t = self.tok();
                    if t.t == T::Newline || (t.t == T::Op && t.k == SEMI) {
                        break;
                    }
                }
                None => break,
            }
        }
        self.leave(L::STMT + L::DEL);
        let t = self.tok();
        if !(t.t == T::Newline || (t.t == T::Op && t.k == SEMI)) {
            return self.fail("invalid syntax");
        }
        let targets = self.list_from(mark);
        Ok(self.add(Kind::Delete, 0, s, e, [targets, NONE, NONE, NONE]))
    }

    fn dotted_name(&mut self) -> R<(u32, u32, u32)> {
        // (the name, joined with dots; start; end)
        let first = self.expect_name()?;
        let s = first.s;
        let mut e = first.e;
        if !self.at_op(DOT) {
            return Ok((first.v, s, e));
        }
        let mut text: Vec<u32> = self.tree.str(first.v).to_vec();
        while self.at_op(DOT) {
            self.advance();
            let n = self.expect_name()?;
            text.push(0x2E);
            text.extend_from_slice(self.tree.str(n.v));
            e = n.e;
        }
        Ok((self.tree.strings.intern(&text), s, e))
    }

    fn import_name(&mut self) -> R<NodeId> {
        let s = self.advance().s;
        let mark = self.stack.len();
        let mut e;
        loop {
            let (name, as_, ae) = self.dotted_name()?;
            let mut asname = NONE;
            e = ae;
            if self.at_kw(KW_AS) {
                self.advance();
                let n = self.expect_name()?;
                asname = n.v;
                e = n.e;
            }
            let a = self.add(Kind::alias, 0, as_, e, [name, asname, NONE, NONE]);
            self.stack.push(a);
            if self.eat_op(COMMA).is_none() {
                break;
            }
        }
        let names = self.list_from(mark);
        Ok(self.add(Kind::Import, 0, s, e, [names, NONE, NONE, NONE]))
    }

    fn import_from(&mut self) -> R<NodeId> {
        let s = self.advance().s;
        let mut level: u32 = 0;
        loop {
            if self.eat_op(DOT).is_some() {
                level = level.saturating_add(1);
            } else if self.eat_op(ELLIPSIS).is_some() {
                level = level.saturating_add(3);
            } else {
                break;
            }
        }
        let module = if self.at_kw(KW_IMPORT) {
            if level == 0 {
                return self.fail("expected a module name");
            }
            NONE
        } else {
            self.dotted_name()?.0
        };
        self.expect_kw(KW_IMPORT)?;
        let mark = self.stack.len();
        let e;
        if let Some(star) = self.eat_op(STAR) {
            let star_name = self.tree.strings.intern(&[0x2A]);
            let a = self.add(Kind::alias, 0, star.s, star.e, [star_name, NONE, NONE, NONE]);
            self.stack.push(a);
            e = star.e;
        } else {
            let paren = self.eat_op(LPAR).is_some();
            let mut last;
            loop {
                let n = self.expect_name()?;
                let mut asname = NONE;
                last = n.e;
                if self.at_kw(KW_AS) {
                    self.advance();
                    let a = self.expect_name()?;
                    asname = a.v;
                    last = a.e;
                }
                let a = self.add(Kind::alias, 0, n.s, last, [n.v, asname, NONE, NONE]);
                self.stack.push(a);
                if self.at_op(COMMA) {
                    if !paren {
                        // a trailing comma needs the parentheses
                        if self.peek(1).t != T::Name {
                            return self.fail("trailing comma not allowed without surrounding parentheses");
                        }
                    }
                    self.advance();
                    if paren && self.at_op(RPAR) {
                        break;
                    }
                    continue;
                }
                break;
            }
            if paren {
                last = self.expect_op(RPAR)?.e;
            }
            e = last;
        }
        if level == 0 && module != NONE && self.tree.str(module) == FUTURE {
            for k in mark..self.stack.len() {
                let a = self.stack[k];
                if self.tree.str(self.tree.nodes[a as usize].f[A as usize]) == BARRY {
                    self.barry = true;
                }
            }
        }
        let names = self.list_from(mark);
        Ok(self.add(Kind::ImportFrom, 0, s, e, [module, names, level, NONE]))
    }

    fn type_alias(&mut self) -> R<NodeId> {
        let s = self.advance().s; // type
        let n = self.advance();
        let name = self.add(Kind::Name, STORE, n.s, n.e, [n.v, NONE, NONE, NONE]);
        let params = if self.at_op(LSQB) { self.type_params()? } else { 0 };
        self.expect_op(EQUAL)?;
        self.enter(L::STMT)?;
        let value = self.expression()?;
        self.leave(L::STMT);
        Ok(self.add(Kind::TypeAlias, 0, s, value.e, [name, params, value.n, NONE]))
    }

    /// `[T, *Ts, **P]`: a list of type parameters.
    pub fn type_params(&mut self) -> R<u32> {
        self.expect_op(LSQB)?;
        let mark = self.stack.len();
        loop {
            if self.at_op(RSQB) && self.stack.len() > mark {
                break;
            }
            let t = self.tok();
            let (kind, s) = if t.t == T::Op && t.k == STAR {
                self.advance();
                (Kind::TypeVarTuple, t.s)
            } else if t.t == T::Op && t.k == DOUBLESTAR {
                self.advance();
                (Kind::ParamSpec, t.s)
            } else {
                (Kind::TypeVar, t.s)
            };
            let n = self.expect_name()?;
            let mut e = n.e;
            let mut bound = NONE;
            if kind == Kind::TypeVar && self.eat_op(COLON).is_some() {
                self.enter(L::TYPE_PARAM)?;
                let b = self.expression()?;
                self.leave(L::TYPE_PARAM);
                bound = b.n;
                e = b.e;
            }
            let mut default = NONE;
            if self.eat_op(EQUAL).is_some() {
                self.enter(L::TYPE_PARAM)?;
                let d = if kind == Kind::TypeVarTuple { self.star_expression()? } else { self.expression()? };
                self.leave(L::TYPE_PARAM);
                default = d.n;
                e = d.e;
            }
            let id = match kind {
                Kind::TypeVar => self.add(kind, 0, s, e, [n.v, bound, default, NONE]),
                _ => self.add(kind, 0, s, e, [n.v, default, NONE, NONE]),
            };
            self.stack.push(id);
            if self.eat_op(COMMA).is_none() {
                break;
            }
        }
        self.expect_op(RSQB)?;
        Ok(self.list_from(mark))
    }

    // ---- blocks and compound statements ----

    /// A block: an indented suite of statements, or simple statements on
    /// the header's line. (its list, its end)
    pub fn block(&mut self, cost: u32) -> R<(u32, u32)> {
        self.enter(cost)?;
        let mark = self.stack.len();
        if self.tok().t == T::Newline {
            self.advance();
            if self.tok().t != T::Indent {
                return self.fail_specific("expected an indented block");
            }
            self.advance();
            loop {
                match self.tok().t {
                    T::Dedent => break,
                    T::End => return self.fail("expected a dedent"),
                    T::Indent => return self.fail("unexpected indent"),
                    _ => self.statement()?,
                }
            }
            self.advance(); // DEDENT
        } else {
            self.simple_stmts()?;
        }
        if self.stack.len() == mark {
            return self.fail("expected a statement");
        }
        // (the block's last token: a `;` after its last statement included)
        let end = self.last_end();
        let list = self.list_from(mark);
        self.leave(cost);
        Ok((list, end))
    }

    fn compound(&mut self) -> R<NodeId> {
        let t = self.tok();
        if t.t == T::Op && t.k == AT {
            return self.decorated();
        }
        match t.k {
            KW_DEF => self.function_def(NONE, t.s, false),
            KW_CLASS => self.class_def(NONE),
            KW_IF => self.if_stmt(),
            KW_WHILE => self.while_stmt(),
            KW_FOR => self.for_stmt(false, t.s),
            KW_WITH => self.with_stmt(false, t.s),
            KW_TRY => self.try_stmt(),
            _ => {
                // async def / for / with
                let next = self.peek(1);
                if next.t == T::Kw {
                    match next.k {
                        KW_DEF => {
                            self.advance();
                            return self.function_def(NONE, t.s, true);
                        }
                        KW_FOR => {
                            self.advance();
                            return self.for_stmt(true, t.s);
                        }
                        KW_WITH => {
                            self.advance();
                            return self.with_stmt(true, t.s);
                        }
                        _ => {}
                    }
                }
                self.fail("invalid syntax")
            }
        }
    }

    fn decorated(&mut self) -> R<NodeId> {
        let mark = self.stack.len();
        while self.at_op(AT) {
            self.advance();
            self.enter(L::STMT + L::DECORATOR)?;
            let d = self.named_expression()?;
            self.leave(L::STMT + L::DECORATOR);
            if self.tok().t != T::Newline {
                return self.fail("expected a newline after a decorator");
            }
            self.advance();
            self.stack.push(d.n);
        }
        let decorators = self.list_from(mark);
        let t = self.tok();
        match (t.t, t.k) {
            (T::Kw, KW_DEF) => self.function_def(decorators, t.s, false),
            (T::Kw, KW_CLASS) => self.class_def(decorators),
            (T::Kw, KW_ASYNC) if self.peek(1).t == T::Kw && self.peek(1).k == KW_DEF => {
                self.advance();
                self.function_def(decorators, t.s, true)
            }
            _ => self.fail("expected a function or class definition after decorators"),
        }
    }

    fn function_def(&mut self, decorators: u32, s: u32, is_async: bool) -> R<NodeId> {
        self.expect_kw(KW_DEF)?;
        let name = self.expect_name()?;
        let type_params = if self.at_op(LSQB) { self.type_params()? } else { 0 };
        let lpar = self.expect_op(LPAR)?;
        let args = self.parameters(true, lpar.e)?;
        self.expect_op(RPAR)?;
        let mut returns = NONE;
        if self.eat_op(RARROW).is_some() {
            self.enter(L::STMT + L::RETURNS)?;
            returns = self.expression()?.n;
            self.leave(L::STMT + L::RETURNS);
        }
        self.expect_op(COLON)?;
        let (body, end) = self.block(L::DEF_BLOCK)?;
        let decorators = if decorators == NONE { 0 } else { decorators };
        let ext = self.ext(&[decorators, returns, type_params]);
        let kind = if is_async { Kind::AsyncFunctionDef } else { Kind::FunctionDef };
        Ok(self.add(kind, 0, s, end, [name.v, args, body, ext]))
    }

    fn class_def(&mut self, decorators: u32) -> R<NodeId> {
        let s = self.expect_kw(KW_CLASS)?.s;
        let name = self.expect_name()?;
        let type_params = if self.at_op(LSQB) { self.type_params()? } else { 0 };
        let (mut bases, mut keywords) = (0, 0);
        if self.at_op(LPAR) {
            self.enter(L::STMT)?;
            let (b, k, _) = self.call_args(false, L::CHEAP_CALL)?;
            self.leave(L::STMT);
            bases = b;
            keywords = k;
        }
        self.expect_op(COLON)?;
        let (body, end) = self.block(L::DEF_BLOCK)?;
        let decorators = if decorators == NONE { 0 } else { decorators };
        let ext = self.ext(&[keywords, decorators, type_params]);
        Ok(self.add(Kind::ClassDef, 0, s, end, [name.v, bases, body, ext]))
    }

    /// `if`, its `elif`s (an If in the `orelse` of the one before) and `else`.
    fn if_stmt(&mut self) -> R<NodeId> {
        // (the If nodes of the chain are built from the last back)
        let mut chain: Vec<(u32, NodeId, u32, u32)> = Vec::new(); // (start, test, body, body end)
        let mut orelse = 0;
        let mut end;
        let mut levels = 0u32;
        loop {
            let s = self.advance().s; // if / elif
            let cost = if chain.is_empty() { L::STMT } else { L::STMT + L::ELIF_TEST };
            self.enter(cost)?;
            let test = self.named_expression()?;
            self.leave(cost);
            self.expect_op(COLON)?;
            let (body, body_end) = self.block(L::BLOCK)?;
            chain.push((s, test.n, body, body_end));
            end = body_end;
            if self.at_kw(KW_ELIF) {
                self.enter(L::ELIF)?;
                levels += L::ELIF;
                continue;
            }
            if self.at_kw(KW_ELSE) {
                self.advance();
                self.expect_op(COLON)?;
                let (b, e) = self.block(L::DEF_BLOCK)?;
                orelse = b;
                end = e;
            }
            break;
        }
        self.leave(levels);
        let mut id = NONE;
        while let Some((s, test, body, _)) = chain.pop() {
            let or = if id == NONE { orelse } else { self.tree.push_list(&[id]) };
            id = self.add(Kind::If, 0, s, end, [test, body, or, NONE]);
        }
        Ok(id)
    }

    fn else_block(&mut self) -> R<(u32, Option<u32>)> {
        if self.at_kw(KW_ELSE) {
            self.advance();
            self.expect_op(COLON)?;
            let (b, e) = self.block(L::DEF_BLOCK)?;
            return Ok((b, Some(e)));
        }
        Ok((0, None))
    }

    fn while_stmt(&mut self) -> R<NodeId> {
        let s = self.advance().s;
        self.enter(L::STMT)?;
        let test = self.named_expression()?;
        self.leave(L::STMT);
        self.expect_op(COLON)?;
        let (body, mut end) = self.block(L::BLOCK)?;
        let (orelse, e) = self.else_block()?;
        if let Some(e) = e {
            end = e;
        }
        Ok(self.add(Kind::While, 0, s, end, [test.n, body, orelse, NONE]))
    }

    fn for_stmt(&mut self, is_async: bool, s: u32) -> R<NodeId> {
        self.expect_kw(KW_FOR)?;
        self.enter(L::STMT + L::FOR)?;
        let target = self.star_targets()?;
        self.expect_kw(KW_IN)?;
        let iter = self.star_expressions()?;
        self.leave(L::STMT + L::FOR);
        self.expect_op(COLON)?;
        let (body, mut end) = self.block(L::BLOCK)?;
        let (orelse, e) = self.else_block()?;
        if let Some(e) = e {
            end = e;
        }
        let kind = if is_async { Kind::AsyncFor } else { Kind::For };
        Ok(self.add(kind, 0, s, end, [target.n, iter.n, body, orelse]))
    }

    /// The token index of the bracket closing the one at `open`.
    fn matching(&self, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        let mut k = open;
        while let Some(t) = self.toks.get(k) {
            if t.t == T::Op {
                match t.k {
                    LPAR | LSQB | LBRACE => depth += 1,
                    RPAR | RSQB | RBRACE => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(k);
                        }
                    }
                    _ => {}
                }
            } else if matches!(t.t, T::Newline | T::End) {
                return None;
            }
            k += 1;
        }
        None
    }

    fn with_stmt(&mut self, is_async: bool, s: u32) -> R<NodeId> {
        self.expect_kw(KW_WITH)?;
        self.enter(L::STMT + L::WITH_ITEM)?;
        let mark = self.stack.len();
        let mut done = false;
        if self.at_op(LPAR) {
            let close = self.matching(self.p);
            let colon_after = close.map_or(false, |c| matches!(self.toks.get(c + 1), Some(t) if t.t == T::Op && t.k == COLON));
            if colon_after {
                // `with (a as b, c):` — or, if they are not items, an expression in parentheses
                let saved = (self.p, self.tree.nodes.len(), self.tree.lists.len(), self.level, self.pending.len());
                let saved_text = (self.pieces.len(), self.text.len());
                let saved_depths = (self.fdepth, self.spec_depth, self.lambda_defaults);
                match self.paren_with_items() {
                    Ok(()) => done = true,
                    Err(Fail::Fatal) => return Err(Fail::Fatal),
                    Err(Fail::Syntax) => {
                        self.p_max = self.p_max.max(self.p);
                        self.p = saved.0;
                        self.tree.nodes.truncate(saved.1);
                        self.tree.lists.truncate(saved.2);
                        self.level = saved.3;
                        self.pending.truncate(saved.4);
                        self.pieces.truncate(saved_text.0);
                        self.text.truncate(saved_text.1);
                        (self.fdepth, self.spec_depth, self.lambda_defaults) = saved_depths;
                        self.stack.truncate(mark);
                    }
                }
            }
        }
        if !done {
            let mut extra = 0;
            loop {
                self.with_item(false)?;
                if self.eat_op(COMMA).is_none() {
                    break;
                }
                if extra == 0 {
                    extra = L::WITH_LATER_ITEM - L::WITH_ITEM;
                    self.enter(extra)?;
                }
            }
            self.leave(extra);
        }
        self.leave(L::STMT + L::WITH_ITEM);
        let items = self.list_from(mark);
        self.expect_op(COLON)?;
        let (body, end) = self.block(L::BLOCK)?;
        let kind = if is_async { Kind::AsyncWith } else { Kind::With };
        Ok(self.add(kind, 0, s, end, [items, body, NONE, NONE]))
    }

    fn paren_with_items(&mut self) -> R<()> {
        self.expect_op(LPAR)?;
        loop {
            self.with_item(true)?;
            if self.eat_op(COMMA).is_some() {
                if self.at_op(RPAR) {
                    break;
                }
                continue;
            }
            break;
        }
        self.expect_op(RPAR)?;
        if !self.at_op(COLON) {
            return self.fail("expected ':'");
        }
        Ok(())
    }

    /// `expression ['as' star_target]`: a withitem on the stack.
    fn with_item(&mut self, in_parens: bool) -> R<()> {
        let x = self.expression()?;
        let mut vars = NONE;
        let mut e = x.e;
        if self.at_kw(KW_AS) {
            self.advance();
            let t = self.star_target()?;
            self.to_target(t.n, STORE, true)?;
            // (after the target: `,`, `)` or `:`)
            let next = self.tok();
            let fine = next.t == T::Op && (next.k == COMMA || next.k == COLON || (next.k == RPAR && in_parens));
            if !fine && !(next.t == T::Op && next.k == RPAR) {
                return self.fail("invalid syntax");
            }
            vars = t.n;
            e = t.e;
        }
        let id = self.add(Kind::withitem, 0, x.s, e, [x.n, vars, NONE, NONE]);
        self.stack.push(id);
        Ok(())
    }

    fn try_stmt(&mut self) -> R<NodeId> {
        let s = self.advance().s;
        self.expect_op(COLON)?;
        let (body, mut end) = self.block(L::BLOCK)?;
        let mark = self.stack.len();
        let mut star: Option<bool> = None;
        while self.at_kw(KW_EXCEPT) {
            let hs = self.advance().s;
            let is_star = self.eat_op(STAR).is_some();
            match star {
                None => star = Some(is_star),
                Some(was) if was != is_star => {
                    return self.fail("cannot have both 'except' and 'except*' on the same 'try'");
                }
                _ => {}
            }
            let mut typ = NONE;
            let mut name = NONE;
            if !self.at_op(COLON) || is_star {
                self.enter(L::STMT + L::EXCEPT)?;
                let t = self.expression()?;
                self.leave(L::STMT + L::EXCEPT);
                typ = t.n;
                if self.at_kw(KW_AS) {
                    self.advance();
                    name = self.expect_name()?.v;
                }
            }
            self.expect_op(COLON)?;
            let (hbody, hend) = self.block(L::EXCEPT_BLOCK)?;
            let h = self.add(Kind::ExceptHandler, 0, hs, hend, [typ, name, hbody, NONE]);
            self.stack.push(h);
            end = hend;
        }
        let handlers = self.list_from(mark);
        let (mut orelse, mut finalbody) = (0, 0);
        if handlers != 0 {
            let (b, e) = self.else_block()?;
            orelse = b;
            if let Some(e) = e {
                end = e;
            }
        }
        if self.at_kw(KW_FINALLY) {
            self.advance();
            self.expect_op(COLON)?;
            let (b, e) = self.block(L::DEF_BLOCK)?;
            finalbody = b;
            end = e;
        } else if handlers == 0 {
            return self.fail_specific("expected 'except' or 'finally' block");
        }
        let kind = if star == Some(true) { Kind::TryStar } else { Kind::Try };
        Ok(self.add(kind, 0, s, end, [body, handlers, orelse, finalbody]))
    }

    fn match_stmt(&mut self) -> R<NodeId> {
        let s = self.advance().s; // match
        self.enter(L::STMT + L::SUBJECT)?;
        let first = self.star_named_expression()?;
        let subject = if self.at_op(COMMA) {
            let mark = self.stack.len();
            self.stack.push(first.n);
            let mut e = first.e;
            while let Some(c) = self.eat_op(COMMA) {
                e = c.e;
                if self.at_op(COLON) {
                    break;
                }
                self.enter(L::LATER_ITEM)?;
                let x = self.star_named_expression()?;
                self.leave(L::LATER_ITEM);
                self.stack.push(x.n);
                e = x.e;
            }
            let elts = self.list_from(mark);
            self.add(Kind::Tuple, LOAD, first.s, e, [elts, NONE, NONE, NONE])
        } else {
            if self.kind(first.n) == Kind::Starred && first.s == self.tree.nodes[first.n as usize].start {
                return self.fail("invalid syntax");
            }
            first.n
        };
        self.leave(L::STMT + L::SUBJECT);
        self.expect_op(COLON)?;
        if self.tok().t != T::Newline {
            return self.fail("expected a newline");
        }
        self.advance();
        if self.tok().t != T::Indent {
            return self.fail_specific("expected an indented block");
        }
        self.advance();
        let mark = self.stack.len();
        let mut end = s;
        while self.tok().t != T::Dedent {
            if !Self::is_soft(self.tok(), S_CASE) {
                return self.fail("expected 'case'");
            }
            self.advance();
            self.enter(L::CASE)?;
            self.enter(L::PATTERNS)?;
            let pattern = self.patterns()?;
            self.leave(L::PATTERNS);
            let mut guard = NONE;
            if self.at_kw(KW_IF) {
                self.advance();
                self.enter(L::GUARD)?;
                guard = self.named_expression()?.n;
                self.leave(L::GUARD);
            }
            self.expect_op(COLON)?;
            let (body, e) = self.block(0)?;
            self.leave(L::CASE);
            let ps = self.tree.nodes[pattern as usize].start;
            let c = self.add(Kind::match_case, 0, ps, e, [pattern, guard, body, NONE]);
            self.stack.push(c);
            end = e;
        }
        self.advance(); // DEDENT
        let cases = self.list_from(mark);
        Ok(self.add(Kind::Match, 0, s, end, [subject, cases, NONE, NONE]))
    }
}

const FUTURE: &[u32] = &[0x5F, 0x5F, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x5F, 0x5F];
const BARRY: &[u32] = &[0x62, 0x61, 0x72, 0x72, 0x79, 0x5F, 0x61, 0x73, 0x5F, 0x46, 0x4C, 0x55, 0x46, 0x4C];

/// The operator of an augmented assignment's token.
pub fn aug_op(k: u8) -> Option<u8> {
    Some(match k {
        PLUSEQUAL => ADD,
        MINEQUAL => SUB,
        STAREQUAL => MULT,
        ATEQUAL => MATMULT,
        SLASHEQUAL => DIV,
        PERCENTEQUAL => MOD,
        AMPEREQUAL => BITAND,
        VBAREQUAL => BITOR,
        CIRCUMFLEXEQUAL => BITXOR,
        LEFTSHIFTEQUAL => LSHIFT,
        RIGHTSHIFTEQUAL => RSHIFT,
        DOUBLESTAREQUAL => POW,
        DOUBLESLASHEQUAL => FLOORDIV,
        _ => return None,
    })
}
