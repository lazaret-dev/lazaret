//! The parser: jsparse.py's `_Parser`, function for function (the same
//! names, the same order of reads, peeks and speculative reads, so that
//! the budgets run out where they run out there). Statements, functions,
//! classes and modules are here; expressions and JSX in `expr.rs`,
//! TypeScript's types in `types.rs`.

use std::collections::HashMap;

use super::scan::*;
use super::tree::*;

/// Nested statements, expressions and types.
pub const MAX_DEPTH: u32 = 256;
/// Tokens one speculative read may consume.
pub const SPECULATION_TOKENS: i64 = 4096;
/// … and all of a file's: this plus 2 per code point of it.
pub const SPECULATION_TOTAL: i64 = 16 * SPECULATION_TOKENS;

/// Where jsparse.py, which recurses there without a depth check, runs out
/// of Python's recursion limit (parse() raises it to 40 * MAX_DEPTH + 3000
/// frames) and answers "nesting too deep" at line 1: a chain of this many
/// of Flow's `?` before a type, or a JSX name of this many members when
/// its closing tag is compared. (Python counts the frames its caller and
/// the parser already use too, so its threshold moves with them: this is
/// where it is for a program's top level, parse() called from a script's
/// top level; from 20 frames deeper it is 22 less.)
pub const PY_CHAIN_LIMIT: u32 = 40 * MAX_DEPTH + 3000 - 18;

/// A scan whose text runs this long or longer is kept, by its start, for
/// the speculative reads that read it again (they read it once).
const LONG: u32 = 48;

/// The longest text read (offsets, ids and lengths are u32).
pub const MAX_LEN: usize = (u32::MAX - 16) as usize;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum T {
    Eof,
    Name,
    Num,
    BigInt,
    Str,
    Tmpl,
    Regex,
    Priv,
    P,
    JsxText,
}

/// A token: its kind, its value (a string id: the literals' ids compare
/// with LITERALS; NONE for a template chunk or a regex, whose parts are in
/// `x` and `y`), where it is, and whether a line ends before it.
#[derive(Clone, Copy, Debug)]
pub struct Tok {
    pub t: T,
    pub v: u32,
    /// a template chunk's raw text (`y`: 1 for the tail); a regex's pattern (`y`: its flags)
    pub x: u32,
    pub y: u32,
    pub s: u32,
    pub e: u32,
    pub ln: u32,
    pub nl: bool,
    pub esc: bool,
    /// an HTML-like `<!--` comment is among the blanks and comments before it (skip())
    pub html: bool,
}

/// Where a node starts: its line and the offset of the token the line is
/// taken from.
#[derive(Clone, Copy, Debug)]
pub struct At {
    pub line: u32,
    pub start: u32,
}

/// Why a read stopped: a JsSyntaxError (its line and reason are in the
/// parser), a speculative read that did not fit, or what jsparse.py
/// raises past every catch (RecursionError, KeyError).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fail {
    Syntax,
    Backtrack,
    Fatal,
}

pub type R<X> = Result<X, Fail>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fatal {
    /// Python's RecursionError: parse() answers line 1, "nesting too deep"
    Recursion,
    /// `items["line"]` of a parenthesized list whose first item is a rest
    /// element (jsparse.py raises KeyError: 'line')
    KeyErrorLine,
}

/// A JsSyntaxError's reason, written out at the end.
#[derive(Clone, Copy, Debug)]
pub enum Reason {
    Text(&'static str),
    /// "unexpected token " and the token's text (its first 20 code points), quoted
    Token(u32, u32),
    /// "unexpected character " and the character, quoted
    Char(u32),
    /// next()'s own text for a backslash: "unexpected character '\'"
    Backslash,
}

#[derive(Clone, Copy, Debug)]
pub struct ScanErr {
    pub line: u32,
    pub reason: Reason,
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum Mode {
    Next = 0,
    JsxTag = 1,
    JsxText = 2,
    Regex = 3,
    Template = 4,
}

/// What save() keeps (jsparse.py's tuple, and the stacks a failed read
/// leaves items on).
#[derive(Clone, Copy)]
pub(super) struct Saved {
    tok: Tok,
    pe: u32,
    prev_rparen: bool,
    depth: u32,
    ncovers: u32,
    in_func: bool,
    in_async: bool,
    in_gen: bool,
    no_conditional: bool,
    ret_ok: bool,
    spec_budget: i64,
    html_after_code: bool,
    nnodes: u32,
    nlists: u32,
    nscratch: u32,
    noperands: u32,
    nops: u32,
    nprefix: u32,
}

pub struct Parser<'a> {
    pub(super) src: &'a [u32],
    pub(super) ts: bool,
    pub(super) jsx: bool,
    /// `<!--` opens a line comment (skip(): JavaScript's reading, not tsc's)
    html_open: bool,
    line_ends: Vec<u32>,
    /// (a position line_at answered for, the line ends before it)
    line_cursor: std::cell::Cell<(u32, u32)>,
    pub(super) tree: Tree,
    // ---- the state save() keeps ----
    pub(super) tok: Tok,
    /// the end of the token before this one
    pub(super) pe: u32,
    /// the token before this one was `)` (jsparse.py: pt == "p" and pv == ")")
    pub(super) prev_rparen: bool,
    pub(super) depth: u32,
    pub(super) in_func: bool,
    pub(super) in_async: bool,
    pub(super) in_gen: bool,
    /// in a conditional type's `extends` clause
    pub(super) no_conditional: bool,
    /// an arrow function may have a return type here
    pub(super) ret_ok: bool,
    pub(super) spec_budget: i64,
    /// a token read so far had an HTML-like `<!--` comment before it, and a token before that (Tree::html_after_code)
    html_after_code: bool,
    // ---- the rest ----
    /// the first token has been read (start())
    begun: bool,
    /// speculative reads under way
    pub(super) spec: u32,
    /// tokens every read ahead may still consume
    pub(super) spec_left: i64,
    /// shorthand properties with an initializer (`{ a = 1 }`) read so far
    pub(super) covers: Vec<NodeId>,
    peek_at: u32,
    peek_tok: Tok,
    /// in a `declare` statement: signatures without bodies
    pub(super) declaring: bool,
    /// the `<` of the closing tag parse_jsx_children stopped at
    pub(super) closer: At,
    pub(super) scratch: Vec<u32>,
    pub(super) operands: Vec<(NodeId, At)>,
    pub(super) ops: Vec<(u32, u8)>,
    pub(super) prefix: Vec<(Kind, u32, At)>,
    buf: Vec<u32>,
    pub(super) err_line: u32,
    pub(super) err: Reason,
    pub(super) fatal: Fatal,
    memo: HashMap<u64, Result<Tok, ScanErr>>,
    memo_bits: Vec<u64>,
}

/// The result of a parse: the tree, or a JsSyntaxError's line and reason.
pub enum Outcome {
    Tree(Tree),
    Error(u32, Vec<u32>),
}

pub fn parse(src: &[u32], ts: bool, jsx: bool) -> Outcome {
    parse_with(src, ts, jsx, !ts)
}

/// parse(), `<!--` opening a line comment or not (`html_open`: skip()).
pub fn parse_with(src: &[u32], ts: bool, jsx: bool, html_open: bool) -> Outcome {
    if src.len() >= MAX_LEN {
        // (offsets are u32: a text this long — 16 GB as code points — is refused, not wrapped)
        return Outcome::Error(0, u("the text is too long"));
    }
    let mut p = Parser::new(src, ts, jsx);
    p.html_open = html_open;
    let r = p.start().and_then(|_| p.parse_program());
    match r {
        Ok(root) => {
            p.tree.root = root;
            p.tree.html_after_code = p.html_after_code;
            Outcome::Tree(p.tree)
        }
        Err(Fail::Fatal) => match p.fatal {
            Fatal::Recursion => Outcome::Error(1, u("nesting too deep")),
            // (not a JsSyntaxError in jsparse.py: line 0 says so)
            Fatal::KeyErrorLine => Outcome::Error(0, u("KeyError: 'line'")),
        },
        // (a speculative read's failure never leaves one: the program's
        // own reads are not speculative)
        Err(_) => {
            let reason = p.reason_text();
            Outcome::Error(p.err_line, reason)
        }
    }
}

pub(super) fn u(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn memo_key(mode: Mode, pos: u32) -> u64 {
    ((mode as u64) << 32) | pos as u64
}

impl<'a> Parser<'a> {
    pub fn new(src: &'a [u32], ts: bool, jsx: bool) -> Parser<'a> {
        // _LINE_RE: \r\n (at its \r) or one of \n \r U+2028 U+2029
        let mut line_ends = Vec::new();
        let mut i = 0;
        while i < src.len() {
            let x = src[i];
            if is_lt(x) {
                line_ends.push(i as u32);
                if x == 0x0D && src.get(i + 1) == Some(&0x0A) {
                    i += 1;
                }
            }
            i += 1;
        }
        let eof = Tok { t: T::Eof, v: EMPTY, x: 0, y: 0, s: 0, e: 0, ln: 1, nl: false, esc: false, html: false };
        Parser {
            src,
            ts,
            jsx,
            html_open: !ts,
            line_ends,
            line_cursor: std::cell::Cell::new((0, 0)),
            tree: Tree::new(),
            tok: eof,
            pe: 0,
            prev_rparen: false,
            depth: 0,
            in_func: false,
            in_async: false,
            in_gen: false,
            no_conditional: false,
            ret_ok: true,
            spec_budget: 0,
            html_after_code: false,
            begun: false,
            spec: 0,
            spec_left: 2 * src.len() as i64 + SPECULATION_TOTAL,
            covers: Vec::new(),
            peek_at: NONE,
            peek_tok: eof,
            declaring: false,
            closer: At { line: 1, start: 0 },
            scratch: Vec::new(),
            operands: Vec::new(),
            ops: Vec::new(),
            prefix: Vec::new(),
            buf: Vec::new(),
            err_line: 0,
            err: Reason::Text(""),
            fatal: Fatal::Recursion,
            memo: HashMap::new(),
            memo_bits: Vec::new(),
        }
    }

    /// `#!` … skipped, then the first token.
    fn start(&mut self) -> R<()> {
        let src = self.src;
        if src.len() >= 2 && src[0] == '#' as u32 && src[1] == '!' as u32 {
            let mut e = 2;
            while e < src.len() && !is_lt(src[e]) {
                e += 1;
            }
            self.tok.e = e as u32;
        }
        self.next()
    }

    pub(super) fn reason_text(&self) -> Vec<u32> {
        match self.err {
            Reason::Text(t) => u(t),
            Reason::Token(s, e) => {
                let mut out = u("unexpected token ");
                let text = &self.src[s as usize..e as usize];
                quote(&text[..text.len().min(20)], &mut out);
                out
            }
            Reason::Char(ch) => {
                let mut out = u("unexpected character ");
                quote(&[ch], &mut out);
                out
            }
            Reason::Backslash => u("unexpected character '\\'"),
        }
    }

    // ---------------------------------------------------------- scanning --

    /// The line of `pos`: line ends before it, plus one (bisect_left).
    #[inline]
    pub(super) fn line_at(&self, pos: u32) -> u32 {
        let ends = &self.line_ends;
        // (from the last answer when pos is past it: tokens come in order)
        let (p0, i0) = self.line_cursor.get();
        let i = if pos >= p0 {
            let mut i = i0 as usize;
            let stop = (i + 8).min(ends.len());
            while i < stop && ends[i] < pos {
                i += 1;
            }
            if i == stop && i < ends.len() && ends[i] < pos {
                i + ends[i..].partition_point(|&x| x < pos)
            } else {
                i
            }
        } else {
            ends.partition_point(|&x| x < pos)
        };
        self.line_cursor.set((pos, i as u32));
        i as u32 + 1
    }

    #[inline]
    pub(super) fn at(&self) -> At {
        At { line: self.tok.ln, start: self.tok.s }
    }

    /// skip(): blanks and comments from pos: (the token start, a line
    /// terminator was passed, an HTML-like `<!--` comment was).
    ///
    /// Annex B's HTML-like comments (ECMA-262 B.1.1, for web compatibility;
    /// a script's, not a module's): `<!--` opens a line comment anywhere a
    /// token may begin (`SingleLineHTMLOpenComment`), and `-->` opens one
    /// where a line begins — the start of the input, or after only blanks
    /// and comments since a line terminator (`SingleLineHTMLCloseComment`).
    /// V8 reads a CommonJS file (a `.cjs`, and a `.js` whose package.json
    /// does not say `"type": "module"`) so, and refuses a module that holds
    /// either (Node: "HTML comments are not allowed in modules"); Bun (1.3)
    /// refuses `<!--` and takes a line's `-->` for a comment, in a module
    /// too. Before F-12 the parser read `<!--` as `<` `!` `--` and `-->` as
    /// `--` `>`, so a file that opened with `<!-- a banner` did not parse,
    /// and its supply-chain facts came from the text followers.
    ///
    /// `<!--` opens one only where `html_open` (JavaScript): tsc reads it as
    /// `<` `!` `--` (6.0.3 compiles `z = 5 <!--y, f()` to
    /// `z = 5 < !--y, f();`, which calls f), and so does a module by the
    /// standard, so TypeScript is read as tsc reads it. After a token such a
    /// reading can be code that the comment hides: the tree says so
    /// (Tree::html_after_code), and the supply-chain facts, which read a
    /// TypeScript file's text as JavaScript first, read that text without
    /// the comment (jsflow::supply::facts). `-->` where a line begins is
    /// never code in any reading (there `--` is a prefix operator, a line
    /// terminator before it, and `>` begins no operand), so it is a comment
    /// in either dialect: it hides nothing a runtime runs.
    fn skip(&self, pos: u32) -> Result<(u32, bool, bool), ScanErr> {
        let s = self.src;
        let n = s.len();
        let mut b = pos as usize;
        let mut nl = false;
        let mut html = false;
        let html_open = self.html_open;
        let is3 = |b: usize, a: u32, c2: u32, d: u32| b + 2 < n && s[b] == a && s[b + 1] == c2 && s[b + 2] == d;
        loop {
            while b < n {
                let x = s[b];
                if x != 0x20 {
                    if !is_blank(x) {
                        break;
                    }
                    if is_lt(x) {
                        nl = true;
                    }
                }
                b += 1;
            }
            if b + 1 < n && s[b] == '/' as u32 && s[b + 1] == '/' as u32 {
                b += 2;
                while b < n && !is_lt(s[b]) {
                    b += 1;
                }
            } else if html_open && b + 3 < n && s[b] == 0x3c && s[b + 1] == 0x21 && s[b + 2] == 0x2d && s[b + 3] == 0x2d {
                html = true;
                b += 4; // `<!--` to the line's end
                while b < n && !is_lt(s[b]) {
                    b += 1;
                }
            } else if (nl || pos == 0) && is3(b, 0x2d, 0x2d, 0x3e) {
                b += 3; // `-->` at a line's start (`pos == 0`: the input's), to the line's end
                while b < n && !is_lt(s[b]) {
                    b += 1;
                }
            } else if b + 1 < n && s[b] == '/' as u32 && s[b + 1] == '*' as u32 {
                let mut i = b + 2;
                loop {
                    if i + 1 >= n {
                        return Err(ScanErr {
                            line: self.line_at(b as u32),
                            reason: Reason::Text("unterminated comment"),
                        });
                    }
                    let x = s[i];
                    if x == '*' as u32 {
                        if s[i + 1] == '/' as u32 {
                            break;
                        }
                    } else if !nl && is_lt(x) {
                        nl = true;
                    }
                    i += 1;
                }
                b = i + 2;
            } else {
                break;
            }
        }
        Ok((b as u32, nl, html))
    }

    fn memo_get(&self, mode: Mode, pos: u32) -> Option<Result<Tok, ScanErr>> {
        let w = (pos / 64) as usize;
        match self.memo_bits.get(w) {
            Some(bits) if bits & (1u64 << (pos % 64)) != 0 => self.memo.get(&memo_key(mode, pos)).copied(),
            _ => None,
        }
    }

    #[inline]
    fn memo_put(&mut self, mode: Mode, pos: u32, r: Result<Tok, ScanErr>) {
        let long = match &r {
            Ok(t) => t.e.saturating_sub(pos) >= LONG,
            Err(_) => true,
        };
        if long {
            self.memo_keep(mode, pos, r);
        }
    }

    #[inline(never)]
    fn memo_keep(&mut self, mode: Mode, pos: u32, r: Result<Tok, ScanErr>) {
        if self.memo_bits.is_empty() {
            self.memo_bits = vec![0; self.src.len() / 64 + 2];
        }
        let w = (pos / 64) as usize;
        if w < self.memo_bits.len() {
            self.memo_bits[w] |= 1u64 << (pos % 64);
            self.memo.insert(memo_key(mode, pos), r);
        }
    }

    #[inline]
    fn intern(&mut self, a: usize, b: usize) -> u32 {
        self.tree.strings.intern(&self.src[a..b])
    }

    /// The token next() reads after `pos`.
    fn scan_next(&mut self, pos: u32) -> Result<Tok, ScanErr> {
        if let Some(r) = self.memo_get(Mode::Next, pos) {
            return r;
        }
        let r = self.scan_next_inner(pos);
        self.memo_put(Mode::Next, pos, r);
        r
    }

    fn scan_next_inner(&mut self, pos: u32) -> Result<Tok, ScanErr> {
        let (b, nl, html) = self.skip(pos)?;
        let ln = self.line_at(b);
        let mut tok = Tok { t: T::Eof, v: EMPTY, x: 0, y: 0, s: b, e: b, ln, nl, esc: false, html };
        let src = self.src;
        let bu = b as usize;
        if bu >= src.len() {
            return Ok(tok);
        }
        let ch = src[bu];
        let err = |reason| Err(ScanErr { line: ln, reason });
        // (ASCII letters, `_`, `$`, a backslash, or anything past ASCII: _IDENT_RE decides)
        if ch >= 128 || is_id_start(ch) || ch == '\\' as u32 {
            return match ident_end(src, bu) {
                Some((end, esc)) => {
                    tok.t = T::Name;
                    tok.e = end as u32;
                    if esc {
                        tok.esc = true;
                        unescape_ident(&src[bu..end], &mut self.buf);
                        tok.v = self.tree.strings.intern(&self.buf);
                    } else {
                        tok.v = self.intern(bu, end);
                    }
                    Ok(tok)
                }
                None if ch == '\\' as u32 => err(Reason::Backslash),
                None => err(Reason::Char(ch)),
            };
        }
        if is_digit(ch) || (ch == '.' as u32 && src.get(bu + 1).is_some_and(|&d| is_digit(d))) {
            let end = number_end(src, bu);
            tok.t = if src[end - 1] == 'n' as u32 { T::BigInt } else { T::Num };
            tok.e = end as u32;
            tok.v = self.intern(bu, end);
            return Ok(tok);
        }
        if ch == '\'' as u32 || ch == '"' as u32 {
            let end = match string_end(src, bu) {
                Some(e) => e,
                None => return err(Reason::Text("unterminated string")),
            };
            tok.t = T::Str;
            tok.e = end as u32;
            let raw = &src[bu + 1..end - 1];
            if raw.contains(&('\\' as u32)) {
                cook(raw, &mut self.buf);
                tok.v = self.tree.strings.intern(&self.buf);
            } else {
                tok.v = self.intern(bu + 1, end - 1);
            }
            return Ok(tok);
        }
        if ch == '`' as u32 {
            return match self.template_at(bu + 1, ln) {
                Ok((x, y, e)) => {
                    tok.t = T::Tmpl;
                    tok.v = NONE;
                    tok.x = x;
                    tok.y = y;
                    tok.e = e;
                    Ok(tok)
                }
                Err(e) => Err(e),
            };
        }
        if ch == '#' as u32 {
            if let Some((end, _)) = ident_end(src, bu + 1) {
                unescape_ident(&src[bu + 1..end], &mut self.buf);
                tok.t = T::Priv;
                tok.e = end as u32;
                tok.v = self.tree.strings.intern(&self.buf);
                return Ok(tok);
            }
        }
        match punct(src, bu) {
            Some((v, len)) => {
                tok.t = T::P;
                tok.v = v;
                tok.e = b + len as u32;
                Ok(tok)
            }
            None => err(Reason::Char(ch)),
        }
    }

    /// read_template(pos): (raw id, tail, end) of the chunk from pos.
    fn template_at(&mut self, pos: usize, ln: u32) -> Result<(u32, u32, u32), ScanErr> {
        let src = self.src;
        let end = template_end(src, pos);
        if end < src.len() && src[end] == '`' as u32 {
            let raw = self.intern(pos, end);
            Ok((raw, 1, end as u32 + 1))
        } else if end + 1 < src.len() && src[end] == '$' as u32 && src[end + 1] == '{' as u32 {
            let raw = self.intern(pos, end);
            Ok((raw, 0, end as u32 + 2))
        } else {
            Err(ScanErr { line: ln, reason: Reason::Text("unterminated template") })
        }
    }

    pub(super) fn raise_scan<X>(&mut self, e: ScanErr) -> R<X> {
        self.err_line = e.line;
        self.err = e.reason;
        Err(Fail::Syntax)
    }

    pub(super) fn next(&mut self) -> R<()> {
        if self.spec > 0 {
            self.spec_budget -= 1;
            self.spec_left -= 1;
            if self.spec_budget < 0 || self.spec_left < 0 {
                return Err(Fail::Backtrack);
            }
        }
        self.prev_rparen = self.tok.t == T::P && self.tok.v == P_RPAREN;
        self.pe = self.tok.e;
        let pos = self.tok.e;
        let r = if self.peek_at == pos { Ok(self.peek_tok) } else { self.scan_next(pos) };
        match r {
            Ok(t) => {
                // (a `<!--` before the first token is a comment in every reading that runs the file)
                self.html_after_code |= t.html && self.begun;
                self.begun = true;
                self.tok = t;
                Ok(())
            }
            Err(e) => self.raise_scan(e),
        }
    }

    pub(super) fn rescan_regex(&mut self) -> R<()> {
        let s0 = self.tok.s;
        let r = match self.memo_get(Mode::Regex, s0) {
            Some(r) => r,
            None => {
                let r = match regex_end(self.src, s0 as usize) {
                    None => Err(ScanErr { line: self.tok.ln, reason: Reason::Text("unterminated regular expression") }),
                    Some((close, e)) => {
                        let mut t = self.tok;
                        t.t = T::Regex;
                        t.v = NONE;
                        t.x = self.intern(s0 as usize + 1, close);
                        t.y = self.intern(close + 1, e);
                        t.e = e as u32;
                        Ok(t)
                    }
                };
                self.memo_put(Mode::Regex, s0, r);
                r
            }
        };
        match r {
            Ok(t) => {
                let keep = self.tok;
                self.tok = Tok { t: t.t, v: t.v, x: t.x, y: t.y, e: t.e, ..keep };
                Ok(())
            }
            Err(e) => self.raise_scan(e),
        }
    }

    /// At the `}` that closes a template substitution.
    pub(super) fn rescan_template_continuation(&mut self) -> R<()> {
        if !self.is_p(P_RBRACE) {
            return self.fail();
        }
        let pos = self.tok.s + 1;
        let r = match self.memo_get(Mode::Template, pos) {
            Some(r) => r,
            None => {
                let ln = self.tok.ln;
                let r = self.template_at(pos as usize, ln).map(|(x, y, e)| Tok { x, y, e, ..self.tok });
                self.memo_put(Mode::Template, pos, r);
                r
            }
        };
        match r {
            Ok(t) => {
                self.tok.t = T::Tmpl;
                self.tok.v = NONE;
                self.tok.x = t.x;
                self.tok.y = t.y;
                self.tok.e = t.e;
                Ok(())
            }
            Err(e) => self.raise_scan(e),
        }
    }

    /// The operator a `>` token starts (`>`, `>=`, `>>`, `>>=`, …).
    #[inline]
    pub(super) fn gt_op(&self) -> u32 {
        gt_op(self.src, self.tok.s as usize).0
    }

    pub(super) fn take_gt(&mut self) {
        let (op, len) = gt_op(self.src, self.tok.s as usize);
        self.tok.e = self.tok.s + len as u32;
        self.tok.v = op;
    }

    /// The next token inside a JSX tag: names may hold '-', strings have no
    /// escapes.
    pub(super) fn jsx_tag_next(&mut self) -> R<()> {
        self.pe = self.tok.e;
        let pos = self.tok.e;
        let r = match self.memo_get(Mode::JsxTag, pos) {
            Some(r) => r,
            None => {
                let r = self.scan_jsx_tag(pos);
                self.memo_put(Mode::JsxTag, pos, r);
                r
            }
        };
        match r {
            Ok(t) => {
                self.html_after_code |= t.html;
                self.tok = t;
                Ok(())
            }
            Err(e) => self.raise_scan(e),
        }
    }

    fn scan_jsx_tag(&mut self, pos: u32) -> Result<Tok, ScanErr> {
        let (b, nl, html) = self.skip(pos)?;
        let ln = self.line_at(b);
        let mut tok = Tok { t: T::Eof, v: EMPTY, x: 0, y: 0, s: b, e: b, ln, nl, esc: false, html };
        let src = self.src;
        let bu = b as usize;
        if bu >= src.len() {
            return Ok(tok);
        }
        let ch = src[bu];
        if ch == '\'' as u32 || ch == '"' as u32 {
            let end = match src[bu + 1..].iter().position(|&x| x == ch) {
                Some(k) => bu + 1 + k,
                None => return Err(ScanErr { line: ln, reason: Reason::Text("unterminated string") }),
            };
            tok.t = T::Str;
            tok.v = self.intern(bu + 1, end);
            tok.e = end as u32 + 1;
            return Ok(tok);
        }
        if let Some(end) = jsx_name_end(src, bu) {
            tok.t = T::Name;
            tok.v = self.intern(bu, end);
            tok.e = end as u32;
            return Ok(tok);
        }
        let v = match char::from_u32(ch).unwrap_or('\0') {
            '<' => P_LT,
            '>' => P_GT,
            '/' => P_SLASH,
            '{' => P_LBRACE,
            '}' => P_RBRACE,
            '=' => P_ASSIGN,
            '.' => P_DOT,
            ':' => P_COLON,
            _ => return Err(ScanErr { line: ln, reason: Reason::Char(ch) }),
        };
        tok.t = T::P;
        tok.v = v;
        tok.e = b + 1;
        Ok(tok)
    }

    /// The next child of a JSX element: text up to `{` or `<`, or one of them.
    pub(super) fn jsx_text_next(&mut self) {
        let pos = self.tok.e;
        self.pe = pos;
        let r = match self.memo_get(Mode::JsxText, pos) {
            Some(Ok(t)) => t,
            _ => {
                let t = self.scan_jsx_text(pos);
                self.memo_put(Mode::JsxText, pos, Ok(t));
                t
            }
        };
        self.tok = r;
    }

    fn scan_jsx_text(&mut self, pos: u32) -> Tok {
        let ln = self.line_at(pos);
        let mut tok = Tok { t: T::Eof, v: EMPTY, x: 0, y: 0, s: pos, e: pos, ln, nl: false, esc: false, html: false };
        let src = self.src;
        let p = pos as usize;
        if p >= src.len() {
            return tok;
        }
        let ch = src[p];
        if ch == '{' as u32 || ch == '<' as u32 {
            tok.t = T::P;
            tok.v = if ch == '{' as u32 { P_LBRACE } else { P_LT };
            tok.e = pos + 1;
            return tok;
        }
        let end = src[p..].iter().position(|&x| x == '{' as u32 || x == '<' as u32).map_or(src.len(), |k| p + k);
        tok.t = T::JsxText;
        tok.v = self.intern(p, end);
        tok.e = end as u32;
        tok
    }

    // -------------------------------------------------- reading ahead --

    /// (kind, value, newline before) of the token after this one.
    pub(super) fn peek(&mut self) -> (T, u32, bool) {
        if self.peek_at == self.tok.e {
            let p = self.peek_tok;
            return (p.t, p.v, p.nl);
        }
        // (jsparse.py reads it with next() as a read ahead of one token:
        // against the file's allowance, and the read in progress's)
        self.spec_left -= 1;
        if self.spec_budget < 0 || self.spec_left < 0 {
            return (T::Eof, EMPTY, false);
        }
        match self.scan_next(self.tok.e) {
            Ok(t) => {
                self.peek_at = self.tok.e;
                self.peek_tok = t;
                (t.t, t.v, t.nl)
            }
            Err(_) => (T::Eof, EMPTY, false),
        }
    }

    pub(super) fn save(&self) -> Saved {
        Saved {
            tok: self.tok,
            pe: self.pe,
            prev_rparen: self.prev_rparen,
            depth: self.depth,
            ncovers: self.covers.len() as u32,
            in_func: self.in_func,
            in_async: self.in_async,
            in_gen: self.in_gen,
            no_conditional: self.no_conditional,
            ret_ok: self.ret_ok,
            spec_budget: self.spec_budget,
            html_after_code: self.html_after_code,
            nnodes: self.tree.nodes.len() as u32,
            nlists: self.tree.lists.len() as u32,
            nscratch: self.scratch.len() as u32,
            noperands: self.operands.len() as u32,
            nops: self.ops.len() as u32,
            nprefix: self.prefix.len() as u32,
        }
    }

    pub(super) fn restore(&mut self, st: &Saved) {
        self.tok = st.tok;
        self.pe = st.pe;
        self.prev_rparen = st.prev_rparen;
        self.depth = st.depth;
        self.covers.truncate(st.ncovers as usize);
        self.in_func = st.in_func;
        self.in_async = st.in_async;
        self.in_gen = st.in_gen;
        self.no_conditional = st.no_conditional;
        self.ret_ok = st.ret_ok;
        self.spec_budget = st.spec_budget;
        self.html_after_code = st.html_after_code;
        // (what a read built after the save is unreachable now)
        self.tree.nodes.truncate(st.nnodes as usize);
        self.tree.lists.truncate(st.nlists as usize);
        self.scratch.truncate(st.nscratch as usize);
        self.operands.truncate(st.noperands as usize);
        self.ops.truncate(st.nops as usize);
        self.prefix.truncate(st.nprefix as usize);
    }

    /// f()'s value, read ahead; None, with the state as before, when it
    /// does not fit. A read inside another keeps using that one's budget:
    /// what a failed read consumed stays consumed.
    pub(super) fn speculate<X>(&mut self, f: impl FnOnce(&mut Self) -> R<X>) -> R<Option<X>> {
        let st = self.save();
        let outer = self.spec > 0;
        if !outer {
            self.spec_budget = SPECULATION_TOKENS;
        }
        self.spec += 1;
        match f(self) {
            Ok(x) => {
                self.spec -= 1;
                if !outer {
                    self.spec_budget = st.spec_budget;
                }
                Ok(Some(x))
            }
            Err(Fail::Fatal) => Err(Fail::Fatal),
            Err(_) => {
                self.spec -= 1;
                let spent = self.spec_budget;
                self.restore(&st);
                if outer {
                    self.spec_budget = spent;
                }
                Ok(None)
            }
        }
    }

    /// f() on a read ahead of at most `tokens` tokens; the state is always
    /// restored. False when the read fails.
    pub(super) fn look(&mut self, f: impl FnOnce(&mut Self) -> R<bool>, tokens: i64) -> R<bool> {
        let st = self.save();
        self.spec += 1;
        self.spec_budget += tokens;
        let r = f(self);
        self.spec -= 1;
        self.restore(&st);
        match r {
            Ok(b) => Ok(b),
            Err(Fail::Fatal) => Err(Fail::Fatal),
            Err(_) => Ok(false),
        }
    }

    // ------------------------------------------------------ token tests --

    #[inline]
    pub(super) fn is_p(&self, v: u32) -> bool {
        self.tok.t == T::P && self.tok.v == v
    }

    #[inline]
    pub(super) fn is_n(&self, v: u32) -> bool {
        self.tok.t == T::Name && self.tok.v == v && !self.tok.esc
    }

    pub(super) fn eat_p(&mut self, v: u32) -> R<bool> {
        if self.is_p(v) {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn eat_n(&mut self, v: u32) -> R<bool> {
        if self.is_n(v) {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn expect_p(&mut self, v: u32) -> R<()> {
        if !self.is_p(v) {
            return self.fail();
        }
        self.next()
    }

    pub(super) fn expect_n(&mut self, v: u32) -> R<()> {
        if !self.is_n(v) {
            return self.fail();
        }
        self.next()
    }

    pub(super) fn semicolon(&mut self) -> R<()> {
        if self.is_p(P_SEMI) {
            self.next()
        } else if !(self.tok.t == T::Eof || self.is_p(P_RBRACE) || self.tok.nl) {
            self.fail()
        } else {
            Ok(())
        }
    }

    pub(super) fn enter(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.fail_msg("nesting too deep");
        }
        Ok(())
    }

    /// fail() without a reason: what the current token is.
    pub(super) fn fail<X>(&mut self) -> R<X> {
        self.err = match self.tok.t {
            T::Eof => Reason::Text("unexpected end of input"),
            T::Str => Reason::Text("unexpected string"),
            T::Tmpl => Reason::Text("unexpected template"),
            _ => Reason::Token(self.tok.s, self.tok.e),
        };
        self.err_line = self.tok.ln;
        Err(Fail::Syntax)
    }

    pub(super) fn fail_msg<X>(&mut self, reason: &'static str) -> R<X> {
        self.err = Reason::Text(reason);
        self.err_line = self.tok.ln;
        Err(Fail::Syntax)
    }

    pub(super) fn fail_at<X>(&mut self, reason: &'static str, line: u32) -> R<X> {
        self.err = Reason::Text(reason);
        self.err_line = line;
        Err(Fail::Syntax)
    }

    pub(super) fn fatal<X>(&mut self, kind: Fatal) -> R<X> {
        self.fatal = kind;
        Err(Fail::Fatal)
    }

    // ------------------------------------------------------------ nodes --

    pub(super) fn mk(&mut self, kind: Kind, at: At, end: u32, op: u8, flags: u16, f: [u32; 4]) -> NodeId {
        let id = self.tree.nodes.len() as u32;
        self.tree.nodes.push(Node { kind, op, flags, line: at.line, start: at.start, end, f });
        id
    }

    /// A node ending where the last token read ends.
    #[inline]
    pub(super) fn fin(&mut self, kind: Kind, at: At, f: [u32; 4]) -> NodeId {
        let end = self.pe;
        self.mk(kind, at, end, 0, 0, f)
    }

    #[inline]
    pub(super) fn fin_x(&mut self, kind: Kind, at: At, op: u8, flags: u16, f: [u32; 4]) -> NodeId {
        let end = self.pe;
        self.mk(kind, at, end, op, flags, f)
    }

    #[inline]
    pub(super) fn node(&self, id: NodeId) -> &Node {
        &self.tree.nodes[id as usize]
    }

    #[inline]
    pub(super) fn at_of(&self, id: NodeId) -> At {
        let n = &self.tree.nodes[id as usize];
        At { line: n.line, start: n.start }
    }

    /// The list of what was pushed on the scratch stack since `mark`.
    pub(super) fn commit(&mut self, mark: usize) -> u32 {
        let n = self.scratch.len() - mark;
        if n == 0 {
            return 0;
        }
        let id = self.tree.lists.len() as u32;
        self.tree.lists.push(n as u32);
        self.tree.lists.extend_from_slice(&self.scratch[mark..]);
        self.scratch.truncate(mark);
        id
    }

    /// A list of the given items.
    pub(super) fn list_of(&mut self, items: &[u32]) -> u32 {
        if items.is_empty() {
            return 0;
        }
        let id = self.tree.lists.len() as u32;
        self.tree.lists.push(items.len() as u32);
        self.tree.lists.extend_from_slice(items);
        id
    }

    /// The items of list `id`, copied (the lists may grow meanwhile).
    pub(super) fn items(&self, id: u32) -> Vec<u32> {
        self.tree.list(id).to_vec()
    }

    pub(super) fn ident(&mut self, reserved_ok: bool) -> R<NodeId> {
        if self.tok.t != T::Name || (!reserved_ok && !self.tok.esc && reserved(self.tok.v)) {
            return self.fail();
        }
        let at = self.at();
        let (v, e) = (self.tok.v, self.tok.e);
        self.next()?;
        Ok(self.mk(Kind::Identifier, at, e, 0, 0, [v, NONE, NONE, NONE]))
    }

    pub(super) fn function_context(&mut self, is_async: bool, gen: bool) -> (bool, bool, bool) {
        let saved = (self.in_func, self.in_async, self.in_gen);
        self.in_func = true;
        self.in_async = is_async;
        self.in_gen = gen;
        saved
    }

    pub(super) fn restore_context(&mut self, saved: (bool, bool, bool)) {
        (self.in_func, self.in_async, self.in_gen) = saved;
    }

    // --------------------------------------------- program and statements --

    pub(super) fn parse_program(&mut self) -> R<NodeId> {
        let mark = self.scratch.len();
        while self.tok.t != T::Eof {
            if let Some(stmt) = self.parse_statement()? {
                self.scratch.push(stmt);
            }
        }
        for i in 0..self.covers.len() {
            let p = self.covers[i];
            let n = *self.node(p);
            if n.f[C as usize] != NONE {
                return self.fail_at("invalid shorthand property initializer", n.line);
            }
        }
        let body = self.commit(mark);
        let end = self.src.len() as u32;
        Ok(self.mk(Kind::Program, At { line: 1, start: 0 }, end, 0, 0, [body, NONE, NONE, NONE]))
    }

    pub(super) fn parse_statement(&mut self) -> R<Option<NodeId>> {
        self.enter()?;
        let stmt = self.parse_statement_inner()?;
        self.depth -= 1;
        Ok(stmt)
    }

    /// A statement that is part of another (a body): never None.
    pub(super) fn sub_statement(&mut self) -> R<NodeId> {
        let at = self.at();
        match self.parse_statement()? {
            Some(s) => Ok(s),
            None => Ok(self.fin(Kind::EmptyStatement, at, [NONE; 4])),
        }
    }

    fn parse_statement_inner(&mut self) -> R<Option<NodeId>> {
        let (t, v) = (self.tok.t, self.tok.v);
        let at = self.at();
        if t == T::P {
            if v == P_LBRACE {
                return self.parse_block().map(Some);
            }
            if v == P_SEMI {
                self.next()?;
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            }
            if v == P_AT {
                let decorators = self.parse_decorators()?;
                if self.is_n(W_EXPORT) {
                    return self.parse_export(decorators);
                }
                return self.parse_class(true, decorators).map(Some);
            }
        } else if t == T::Name && !self.tok.esc {
            let (pk, pv, pnl) = self.peek();
            if v == W_VAR || v == W_CONST {
                if v == W_CONST && pk == T::Name && pv == W_ENUM {
                    self.next()?;
                    return self.parse_enum(at).map(Some);
                }
                let node = self.parse_var(if v == W_VAR { VAR } else { CONST }, false)?;
                self.semicolon()?;
                return Ok(Some(self.extend_to_pe(node)));
            }
            if v == W_LET && let_declares(pk, pv) {
                let node = self.parse_var(LET, false)?;
                self.semicolon()?;
                return Ok(Some(self.extend_to_pe(node)));
            }
            if v == W_USING && pk == T::Name && !pnl && pv != W_IN && pv != W_OF && pv != W_INSTANCEOF {
                let node = self.parse_var(USING, false)?;
                self.semicolon()?;
                return Ok(Some(self.extend_to_pe(node)));
            }
            if v == W_AWAIT
                && pk == T::Name
                && pv == W_USING
                && !pnl
                && self.look(|p| p.await_using_ahead(), 3)?
            {
                self.next()?;
                let node = self.parse_var(AWAIT_USING, false)?;
                self.semicolon()?;
                return Ok(Some(self.extend_to_pe(node)));
            }
            if v == W_FUNCTION {
                return self.parse_function(true, false, at);
            }
            if v == W_ASYNC && pk == T::Name && pv == W_FUNCTION && !pnl {
                self.next()?;
                return self.parse_function(true, true, at);
            }
            if v == W_CLASS {
                return self.parse_class(true, NONE).map(Some);
            }
            if v == W_IF {
                return self.parse_if().map(Some);
            }
            if v == W_FOR {
                return self.parse_for().map(Some);
            }
            if v == W_WHILE {
                self.next()?;
                let test = self.parse_paren_expr()?;
                let body = self.sub_statement()?;
                return Ok(Some(self.fin(Kind::WhileStatement, at, [test, body, NONE, NONE])));
            }
            if v == W_DO {
                self.next()?;
                let body = self.sub_statement()?;
                self.expect_n(W_WHILE)?;
                let test = self.parse_paren_expr()?;
                self.eat_p(P_SEMI)?;
                return Ok(Some(self.fin(Kind::DoWhileStatement, at, [body, test, NONE, NONE])));
            }
            if v == W_RETURN {
                self.next()?;
                let mut arg = NONE;
                if !(self.tok.t == T::Eof || self.tok.nl || self.is_p(P_SEMI) || self.is_p(P_RBRACE)) {
                    arg = self.parse_expression(false)?;
                }
                self.semicolon()?;
                return Ok(Some(self.fin(Kind::ReturnStatement, at, [arg, NONE, NONE, NONE])));
            }
            if v == W_BREAK || v == W_CONTINUE {
                self.next()?;
                let mut label = NONE;
                if self.tok.t == T::Name && !self.tok.nl {
                    label = self.ident(true)?;
                }
                self.semicolon()?;
                let kind = if v == W_BREAK { Kind::BreakStatement } else { Kind::ContinueStatement };
                return Ok(Some(self.fin(kind, at, [label, NONE, NONE, NONE])));
            }
            if v == W_THROW {
                self.next()?;
                if self.tok.nl {
                    return self.fail_msg("illegal newline after throw");
                }
                let arg = self.parse_expression(false)?;
                self.semicolon()?;
                return Ok(Some(self.fin(Kind::ThrowStatement, at, [arg, NONE, NONE, NONE])));
            }
            if v == W_TRY {
                return self.parse_try().map(Some);
            }
            if v == W_SWITCH {
                return self.parse_switch().map(Some);
            }
            if v == W_WITH {
                self.next()?;
                let obj = self.parse_paren_expr()?;
                let body = self.sub_statement()?;
                return Ok(Some(self.fin(Kind::WithStatement, at, [obj, body, NONE, NONE])));
            }
            if v == W_DEBUGGER {
                self.next()?;
                self.semicolon()?;
                return Ok(Some(self.fin(Kind::DebuggerStatement, at, [NONE; 4])));
            }
            if v == W_IMPORT && !(pk == T::P && (pv == P_LPAREN || pv == P_DOT)) {
                return self.parse_import().map(Some);
            }
            if v == W_EXPORT {
                return self.parse_export(NONE);
            }
            if matches!(v, W_INTERFACE | W_TYPE | W_ENUM | W_DECLARE | W_NAMESPACE | W_MODULE | W_ABSTRACT | W_GLOBAL)
            {
                if let Some(node) = self.parse_ts_declaration(pk, pv, pnl)? {
                    return Ok(Some(node));
                }
            }
            if pk == T::P && pv == P_COLON && !reserved(v) {
                let label = self.ident(false)?;
                self.next()?;
                let body = self.sub_statement()?;
                return Ok(Some(self.fin(Kind::LabeledStatement, at, [label, body, NONE, NONE])));
            }
        }
        let expr = self.parse_expression(false)?;
        self.semicolon()?;
        Ok(Some(self.fin(Kind::ExpressionStatement, at, [expr, NONE, NONE, NONE])))
    }

    /// A declaration whose statement read its `;` after it: it ends there.
    fn extend_to_pe(&mut self, node: NodeId) -> NodeId {
        let pe = self.pe;
        self.tree.nodes[node as usize].end = pe;
        node
    }

    /// At `await using`: a name follows on the line (a declaration).
    pub(super) fn await_using_ahead(&mut self) -> R<bool> {
        self.next()?;
        self.next()?;
        Ok(self.tok.t == T::Name && !self.tok.nl && self.tok.v != W_IN && self.tok.v != W_OF && self.tok.v != W_INSTANCEOF)
    }

    pub(super) fn parse_block(&mut self) -> R<NodeId> {
        let at = self.at();
        self.expect_p(P_LBRACE)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RBRACE) {
            if self.tok.t == T::Eof {
                return self.fail();
            }
            if let Some(stmt) = self.parse_statement()? {
                self.scratch.push(stmt);
            }
        }
        self.next()?;
        let body = self.commit(mark);
        Ok(self.fin(Kind::BlockStatement, at, [body, NONE, NONE, NONE]))
    }

    pub(super) fn parse_paren_expr(&mut self) -> R<NodeId> {
        self.expect_p(P_LPAREN)?;
        let expr = self.parse_expression(false)?;
        self.expect_p(P_RPAREN)?;
        Ok(expr)
    }

    /// if / else if / … / else, the chain read in a loop.
    fn parse_if(&mut self) -> R<NodeId> {
        let mut chain: Vec<(At, NodeId, NodeId)> = Vec::new();
        let mut alt = NONE;
        loop {
            let at = self.at();
            self.next()?; // if
            let test = self.parse_paren_expr()?;
            let cons = self.sub_statement()?;
            chain.push((at, test, cons));
            if !self.is_n(W_ELSE) {
                break;
            }
            self.next()?;
            if !self.is_n(W_IF) {
                alt = self.sub_statement()?;
                break;
            }
        }
        for &(at, test, cons) in chain.iter().rev() {
            alt = self.fin(Kind::IfStatement, at, [test, cons, alt, NONE]);
        }
        Ok(alt)
    }

    fn parse_try(&mut self) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let block = self.parse_block()?;
        let mut handler = NONE;
        let mut finalizer = NONE;
        if self.is_n(W_CATCH) {
            let cat = self.at();
            self.next()?;
            let mut param = NONE;
            if self.eat_p(P_LPAREN)? {
                param = self.parse_binding_target()?;
                if self.eat_p(P_COLON)? {
                    self.parse_type()?;
                }
                self.expect_p(P_RPAREN)?;
            }
            let body = self.parse_block()?;
            handler = self.fin(Kind::CatchClause, cat, [param, body, NONE, NONE]);
        }
        if self.eat_n(W_FINALLY)? {
            finalizer = self.parse_block()?;
        }
        if handler == NONE && finalizer == NONE {
            return self.fail_msg("missing catch or finally");
        }
        Ok(self.fin(Kind::TryStatement, at, [block, handler, finalizer, NONE]))
    }

    fn parse_switch(&mut self) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let disc = self.parse_paren_expr()?;
        self.expect_p(P_LBRACE)?;
        let mark = self.scratch.len();
        while !self.eat_p(P_RBRACE)? {
            let cat = self.at();
            let test;
            if self.eat_n(W_CASE)? {
                test = self.parse_expression(false)?;
            } else if self.eat_n(W_DEFAULT)? {
                test = NONE;
            } else {
                return self.fail();
            }
            self.expect_p(P_COLON)?;
            let cmark = self.scratch.len();
            while !(self.is_p(P_RBRACE) || self.is_n(W_CASE) || self.is_n(W_DEFAULT)) {
                if self.tok.t == T::Eof {
                    return self.fail();
                }
                if let Some(stmt) = self.parse_statement()? {
                    self.scratch.push(stmt);
                }
            }
            let cons = self.commit(cmark);
            let case = self.fin(Kind::SwitchCase, cat, [test, cons, NONE, NONE]);
            self.scratch.push(case);
        }
        let cases = self.commit(mark);
        Ok(self.fin(Kind::SwitchStatement, at, [disc, cases, NONE, NONE]))
    }

    fn parse_for(&mut self) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let is_await = self.eat_n(W_AWAIT)?;
        self.expect_p(P_LPAREN)?;
        let mut init = NONE;
        if !self.is_p(P_SEMI) {
            let mut kind: Option<u8> = None;
            if self.tok.t == T::Name && !self.tok.esc {
                let (pk, pv, pnl) = self.peek();
                let v = self.tok.v;
                if v == W_VAR || v == W_CONST {
                    kind = Some(if v == W_VAR { VAR } else { CONST });
                } else if v == W_LET && let_declares(pk, pv) {
                    kind = Some(LET);
                } else if v == W_USING && pk == T::Name && pv != W_OF && pv != W_IN && !pnl {
                    kind = Some(USING);
                } else if v == W_AWAIT && pk == T::Name && pv == W_USING && self.look(|p| p.await_using_ahead(), 3)? {
                    self.next()?;
                    kind = Some(AWAIT_USING);
                }
            }
            init = match kind {
                Some(k) => self.parse_var(k, true)?,
                None => self.parse_expression(true)?,
            };
            if self.is_n(W_OF) || self.is_n(W_IN) {
                let of = self.tok.v == W_OF;
                self.next()?;
                if self.node(init).kind != Kind::VariableDeclaration {
                    init = self.assign_target(init)?;     // (a call too: `for (f() in x)`, as V8 reads it)
                }
                let right = if of { self.parse_maybe_assign(false, true)? } else { self.parse_expression(false)? };
                self.expect_p(P_RPAREN)?;
                let body = self.sub_statement()?;
                if of {
                    let flags = if is_await { AWAIT } else { 0 };
                    return Ok(self.fin_x(Kind::ForOfStatement, at, 0, flags, [init, right, body, NONE]));
                }
                return Ok(self.fin(Kind::ForInStatement, at, [init, right, body, NONE]));
            }
        }
        self.expect_p(P_SEMI)?;
        let test = if self.is_p(P_SEMI) { NONE } else { self.parse_expression(false)? };
        self.expect_p(P_SEMI)?;
        let update = if self.is_p(P_RPAREN) { NONE } else { self.parse_expression(false)? };
        self.expect_p(P_RPAREN)?;
        let body = self.sub_statement()?;
        Ok(self.fin(Kind::ForStatement, at, [init, test, update, body]))
    }

    pub(super) fn parse_var(&mut self, kind: u8, no_in: bool) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let mark = self.scratch.len();
        loop {
            let dat = self.at();
            let target = self.parse_binding_target()?;
            if self.ts && self.is_p(P_BANG) {
                self.next()?;
            }
            if self.eat_p(P_COLON)? {
                self.parse_type()?;
            }
            let mut init = NONE;
            if self.eat_p(P_ASSIGN)? {
                init = self.parse_maybe_assign(no_in, true)?;
            }
            let decl = self.fin(Kind::VariableDeclarator, dat, [target, init, NONE, NONE]);
            self.scratch.push(decl);
            if !self.eat_p(P_COMMA)? {
                break;
            }
        }
        let decls = self.commit(mark);
        Ok(self.fin_x(Kind::VariableDeclaration, at, kind, 0, [decls, NONE, NONE, NONE]))
    }

    // ---------------------------------------------------------- functions --

    /// `function …` (the current token): a declaration or an expression;
    /// None for a TypeScript signature without a body.
    pub(super) fn parse_function(&mut self, is_decl: bool, is_async: bool, at: At) -> R<Option<NodeId>> {
        self.next()?;
        let gen = self.eat_p(P_STAR)?;
        let mut fid = NONE;
        if self.tok.t == T::Name && !self.is_p(P_LPAREN) {
            let ok = self.tok.v == W_YIELD || self.tok.v == W_AWAIT;
            fid = self.ident(ok)?;
        }
        if self.is_p(P_LT) {
            self.parse_type_params()?;
        }
        let saved = self.function_context(is_async, gen);
        let r = self.function_rest(is_decl);
        self.restore_context(saved);
        let (params, body) = match r? {
            Some(pb) => pb,
            None => return Ok(None),
        };
        let kind = if is_decl { Kind::FunctionDeclaration } else { Kind::FunctionExpression };
        let flags = if gen { GENERATOR } else { 0 } | if is_async { ASYNC } else { 0 };
        Ok(Some(self.fin_x(kind, at, 0, flags, [fid, params, body, NONE])))
    }

    fn function_rest(&mut self, is_decl: bool) -> R<Option<(u32, NodeId)>> {
        let params = self.parse_params()?;
        if self.is_p(P_COLON) {
            self.parse_return_type()?;
        }
        if !self.is_p(P_LBRACE) {
            if is_decl
                && (self.ts || self.declaring)
                && (self.is_p(P_SEMI) || self.tok.nl || self.is_p(P_RBRACE) || self.tok.t == T::Eof)
            {
                self.eat_p(P_SEMI)?;
                return Ok(None);
            }
            return self.fail();
        }
        let body = self.parse_block()?;
        Ok(Some((params, body)))
    }

    /// A parameter list `( … )` (TypeScript's `this` parameter left out).
    pub(super) fn parse_params(&mut self) -> R<u32> {
        self.expect_p(P_LPAREN)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RPAREN) {
            if let Some(param) = self.parse_param()? {
                self.scratch.push(param);
            }
            if !self.is_p(P_RPAREN) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        Ok(self.commit(mark))
    }

    fn parse_param(&mut self) -> R<Option<NodeId>> {
        let at = self.at();
        let decorators = if self.is_p(P_AT) { self.parse_decorators()? } else { NONE };
        while self.tok.t == T::Name && param_modifier(self.tok.v) && !self.tok.esc {
            let (pk, pv, _) = self.peek();
            if pk == T::Name || (pk == T::P && (pv == P_LBRACK || pv == P_LBRACE)) {
                self.next()?;
            } else {
                break;
            }
        }
        if self.is_p(P_ELLIPSIS) {
            self.next()?;
            let arg = self.parse_binding_target()?;
            let node = self.fin(Kind::RestElement, at, [arg, NONE, NONE, NONE]);
            self.eat_p(P_QUESTION)?;
            if self.eat_p(P_COLON)? {
                self.parse_type()?;
            }
            if self.eat_p(P_ASSIGN)? {
                self.parse_maybe_assign(false, true)?;
            }
            return Ok(Some(node));
        }
        if self.is_n(W_THIS) {
            let (pk, pv, _) = self.peek();
            if pk == T::P && (pv == P_COLON || pv == P_COMMA || pv == P_RPAREN) {
                self.next()?;
                if self.eat_p(P_COLON)? {
                    self.parse_type()?;
                }
                return Ok(None);
            }
        }
        let tat = self.at();
        let mut target = self.parse_binding_target()?;
        self.eat_p(P_QUESTION)?;
        if self.eat_p(P_COLON)? {
            self.parse_type()?;
        }
        if self.eat_p(P_ASSIGN)? {
            let right = self.parse_maybe_assign(false, true)?;
            target = self.fin(Kind::AssignmentPattern, tat, [target, right, NONE, NONE]);
        }
        if decorators != NONE {
            self.tree.nodes[target as usize].f[D as usize] = decorators;
        }
        Ok(Some(target))
    }

    /// An identifier, or an array or object pattern.
    pub(super) fn parse_binding_target(&mut self) -> R<NodeId> {
        let at = self.at();
        if self.is_p(P_LBRACK) {
            self.enter()?;
            self.next()?;
            let mark = self.scratch.len();
            while !self.is_p(P_RBRACK) {
                if self.is_p(P_COMMA) {
                    self.next()?;
                    self.scratch.push(NONE);
                    continue;
                }
                let eat = self.at();
                if self.eat_p(P_ELLIPSIS)? {
                    let arg = self.parse_binding_target()?;
                    let el = self.fin(Kind::RestElement, eat, [arg, NONE, NONE, NONE]);
                    self.scratch.push(el);
                } else {
                    let mut el = self.parse_binding_target()?;
                    if self.eat_p(P_ASSIGN)? {
                        let right = self.parse_maybe_assign(false, true)?;
                        el = self.fin(Kind::AssignmentPattern, eat, [el, right, NONE, NONE]);
                    }
                    self.scratch.push(el);
                }
                if !self.is_p(P_RBRACK) {
                    self.expect_p(P_COMMA)?;
                }
            }
            self.next()?;
            self.depth -= 1;
            let elements = self.commit(mark);
            return Ok(self.fin(Kind::ArrayPattern, at, [elements, NONE, NONE, NONE]));
        }
        if self.is_p(P_LBRACE) {
            self.enter()?;
            self.next()?;
            let mark = self.scratch.len();
            while !self.is_p(P_RBRACE) {
                let pat = self.at();
                if self.eat_p(P_ELLIPSIS)? {
                    let arg = self.parse_binding_target()?;
                    let el = self.fin(Kind::RestElement, pat, [arg, NONE, NONE, NONE]);
                    self.scratch.push(el);
                } else {
                    let mut computed = false;
                    let key;
                    if self.eat_p(P_LBRACK)? {
                        key = self.parse_maybe_assign(false, true)?;
                        self.expect_p(P_RBRACK)?;
                        computed = true;
                    } else {
                        key = self.parse_property_name()?;
                    }
                    let mut value;
                    let vat;
                    let shorthand;
                    if self.eat_p(P_COLON)? {
                        vat = self.at();
                        value = self.parse_binding_target()?;
                        shorthand = false;
                    } else {
                        if self.node(key).kind != Kind::Identifier || computed {
                            return self.fail();
                        }
                        vat = self.at_of(key);
                        let k = *self.node(key);
                        value = self.mk(Kind::Identifier, vat, k.end, 0, 0, [k.f[A as usize], NONE, NONE, NONE]);
                        shorthand = true;
                    }
                    if self.eat_p(P_ASSIGN)? {
                        let right = self.parse_maybe_assign(false, true)?;
                        value = self.fin(Kind::AssignmentPattern, vat, [value, right, NONE, NONE]);
                    }
                    let flags = if shorthand { SHORTHAND } else { 0 } | if computed { COMPUTED } else { 0 };
                    let prop = self.fin_x(Kind::Property, pat, P_INIT, flags, [key, value, NONE, NONE]);
                    self.scratch.push(prop);
                }
                if !self.is_p(P_RBRACE) {
                    self.expect_p(P_COMMA)?;
                }
            }
            self.next()?;
            self.depth -= 1;
            let props = self.commit(mark);
            return Ok(self.fin(Kind::ObjectPattern, at, [props, NONE, NONE, NONE]));
        }
        if self.tok.t == T::Name {
            return self.ident(false);
        }
        self.fail()
    }

    /// A property key: any word, a string, a number, a private name.
    pub(super) fn parse_property_name(&mut self) -> R<NodeId> {
        let at = self.at();
        let (t, v, e) = (self.tok.t, self.tok.v, self.tok.e);
        let (kind, op) = match t {
            T::Name => (Kind::Identifier, 0),
            T::Str => (Kind::Literal, L_STRING),
            T::Num => (Kind::Literal, L_NUMBER),
            T::BigInt => (Kind::Literal, L_BIGINT),
            T::Priv => (Kind::PrivateIdentifier, 0),
            _ => return self.fail(),
        };
        self.next()?;
        Ok(self.mk(kind, at, e, op, 0, [v, NONE, NONE, NONE]))
    }

    // ------------------------------------------------------------ classes --

    /// The decorators from here: a list (NONE for none: no `@`).
    pub(super) fn parse_decorators(&mut self) -> R<u32> {
        let mark = self.scratch.len();
        while self.is_p(P_AT) {
            self.next()?;
            self.enter()?;
            let at = self.at();
            let mut expr;
            if self.is_p(P_LPAREN) {
                expr = self.parse_paren_expr()?;
            } else {
                expr = self.ident(true)?;
                while self.eat_p(P_DOT)? {
                    let prop = if self.tok.t == T::Priv { self.parse_property_name()? } else { self.ident(true)? };
                    expr = self.fin(Kind::MemberExpression, at, [expr, prop, NONE, NONE]);
                }
                if self.ts && self.is_p(P_LT) {
                    self.speculate(|p| p.parse_type_args())?;
                }
                if self.is_p(P_LPAREN) {
                    let args = self.parse_arguments()?;
                    expr = self.fin(Kind::CallExpression, at, [expr, args, NONE, NONE]);
                }
            }
            self.scratch.push(expr);
            self.depth -= 1;
        }
        let n = self.scratch.len() - mark;
        let list = self.commit(mark);
        Ok(if n == 0 { NONE } else { list })
    }

    /// Two decorator lists, one after the other (`decorators + more`).
    pub(super) fn join_decorators(&mut self, a: u32, b: u32) -> u32 {
        if a == NONE {
            return b;
        }
        if b == NONE {
            return a;
        }
        let mut items = self.items(a);
        items.extend_from_slice(self.tree.list(b));
        self.list_of(&items)
    }

    pub(super) fn parse_class(&mut self, is_decl: bool, decorators: u32) -> R<NodeId> {
        let at = self.at();
        self.eat_n(W_ABSTRACT)?;
        self.expect_n(W_CLASS)?;
        let mut cid = NONE;
        if self.tok.t == T::Name && !(self.is_n(W_EXTENDS) || self.is_n(W_IMPLEMENTS)) {
            cid = self.ident(false)?;
        }
        if self.is_p(P_LT) {
            self.parse_type_params()?;
        }
        let mut sup = NONE;
        if self.eat_n(W_EXTENDS)? {
            sup = self.parse_expr_subscripts()?;
            if self.is_p(P_LT) {
                self.parse_type_args()?;
            }
        }
        if self.eat_n(W_IMPLEMENTS)? {
            self.parse_type()?;
            while self.eat_p(P_COMMA)? {
                self.parse_type()?;
            }
        }
        let body = self.parse_class_body()?;
        let kind = if is_decl { Kind::ClassDeclaration } else { Kind::ClassExpression };
        Ok(self.fin(kind, at, [cid, sup, body, decorators]))
    }

    fn parse_class_body(&mut self) -> R<NodeId> {
        let at = self.at();
        self.expect_p(P_LBRACE)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RBRACE) {
            if self.eat_p(P_SEMI)? {
                continue;
            }
            if self.tok.t == T::Eof {
                return self.fail();
            }
            self.enter()?;
            let member = self.parse_class_member()?;
            self.depth -= 1;
            if let Some(m) = member {
                self.scratch.push(m);
            }
        }
        self.next()?;
        let members = self.commit(mark);
        Ok(self.fin(Kind::ClassBody, at, [members, NONE, NONE, NONE]))
    }

    /// Is the current word a modifier, a member's name following it?
    fn is_modifier(&mut self) -> bool {
        let (pk, pv, pnl) = self.peek();
        if self.tok.v == W_ASYNC && pnl {
            return false;
        }
        key_kind(pk) || (pk == T::P && (pv == P_LBRACK || pv == P_STAR))
    }

    fn parse_class_member(&mut self) -> R<Option<NodeId>> {
        let at = self.at();
        let decorators = if self.is_p(P_AT) { self.parse_decorators()? } else { NONE };
        let (mut is_static, mut is_async, mut gen, mut declare, mut abstract_) = (false, false, false, false, false);
        let mut kind = M_METHOD;
        while self.tok.t == T::Name && !self.tok.esc && class_modifier(self.tok.v) {
            let word = self.tok.v;
            if word == W_STATIC {
                let (pk, pv, _) = self.peek();
                if pk == T::P && pv == P_LBRACE {
                    self.next()?;
                    let saved = self.function_context(false, false);
                    let r = self.parse_block();
                    self.restore_context(saved);
                    let block = r?;
                    let body = self.node(block).f[A as usize];
                    return Ok(Some(self.fin(Kind::StaticBlock, at, [body, NONE, NONE, NONE])));
                }
            }
            if !self.is_modifier() {
                break;
            }
            self.next()?;
            match word {
                W_STATIC => is_static = true,
                W_ASYNC => is_async = true,
                W_GET => kind = M_GET,
                W_SET => kind = M_SET,
                W_DECLARE => declare = true,
                W_ABSTRACT => abstract_ = true,
                _ => {}
            }
        }
        if self.eat_p(P_STAR)? {
            gen = true;
        }
        if self.ts && self.is_p(P_LBRACK) && self.index_signature_ahead()? {
            self.parse_index_signature()?;
            self.member_end()?;
            return Ok(None);
        }
        let mut computed = false;
        let key;
        if self.is_p(P_LBRACK) {
            self.next()?;
            key = self.parse_maybe_assign(false, true)?;
            self.expect_p(P_RBRACK)?;
            computed = true;
        } else {
            key = self.parse_property_name()?;
        }
        if self.is_p(P_QUESTION) || (self.ts && self.is_p(P_BANG)) {
            self.next()?;
        }
        if self.is_p(P_LT) {
            self.parse_type_params()?;
        }
        if self.is_p(P_LPAREN) {
            let k = *self.node(key);
            // (a name or a string `constructor`: a Literal key here is a string's
            // or a number's, whose text is never "constructor")
            let is_ctor = !is_static
                && !computed
                && kind == M_METHOD
                && matches!(k.kind, Kind::Identifier | Kind::Literal)
                && k.f[A as usize] == W_CONSTRUCTOR;
            let func = self.parse_method(is_async, gen)?;
            let func = match func {
                Some(f) if !abstract_ && !declare => f,
                _ => return Ok(None),
            };
            let flags = if is_static { STATIC } else { 0 } | if computed { COMPUTED } else { 0 };
            let op = if is_ctor { M_CONSTRUCTOR } else { kind };
            return Ok(Some(self.fin_x(Kind::MethodDefinition, at, op, flags, [key, func, NONE, decorators])));
        }
        if kind != M_METHOD || gen {
            return self.fail();
        }
        if self.eat_p(P_COLON)? {
            self.parse_type()?;
        }
        let mut value = NONE;
        if self.eat_p(P_ASSIGN)? {
            let saved = self.function_context(false, false);
            let r = self.parse_maybe_assign(false, true);
            self.restore_context(saved);
            value = r?;
        }
        self.member_end()?;
        if declare || abstract_ {
            return Ok(None);
        }
        let flags = if is_static { STATIC } else { 0 } | if computed { COMPUTED } else { 0 };
        Ok(Some(self.fin_x(Kind::PropertyDefinition, at, 0, flags, [key, value, NONE, decorators])))
    }

    fn member_end(&mut self) -> R<()> {
        if self.eat_p(P_SEMI)? || self.eat_p(P_COMMA)? {
            return Ok(());
        }
        if !(self.is_p(P_RBRACE) || self.tok.nl || self.tok.t == T::Eof) {
            return self.fail();
        }
        Ok(())
    }

    /// A method's `(params) { body }` as a FunctionExpression (its line:
    /// the `(`'s); None for a signature without a body.
    pub(super) fn parse_method(&mut self, is_async: bool, gen: bool) -> R<Option<NodeId>> {
        let at = self.at();
        let saved = self.function_context(is_async, gen);
        let r = self.method_rest();
        self.restore_context(saved);
        let (params, body) = match r? {
            Some(pb) => pb,
            None => return Ok(None),
        };
        let flags = if gen { GENERATOR } else { 0 } | if is_async { ASYNC } else { 0 };
        Ok(Some(self.fin_x(Kind::FunctionExpression, at, 0, flags, [NONE, params, body, NONE])))
    }

    fn method_rest(&mut self) -> R<Option<(u32, NodeId)>> {
        let params = self.parse_params()?;
        if self.is_p(P_COLON) {
            self.parse_return_type()?;
        }
        if !self.is_p(P_LBRACE) {
            if self.is_p(P_SEMI) || self.is_p(P_COMMA) || self.is_p(P_RBRACE) || self.tok.nl || self.tok.t == T::Eof {
                self.eat_p(P_SEMI)?;
                return Ok(None);
            }
            return self.fail();
        }
        let body = self.parse_block()?;
        Ok(Some((params, body)))
    }

    /// `[name:` or `[name,` (a TypeScript index signature).
    pub(super) fn index_signature_ahead(&mut self) -> R<bool> {
        self.look(
            |p| {
                p.next()?;
                if p.tok.t != T::Name {
                    return Ok(false);
                }
                p.next()?;
                Ok(p.tok.t == T::P && (p.tok.v == P_COLON || p.tok.v == P_COMMA))
            },
            3,
        )
    }

    pub(super) fn parse_index_signature(&mut self) -> R<()> {
        self.expect_p(P_LBRACK)?;
        while !self.is_p(P_RBRACK) {
            self.ident(true)?;
            if self.eat_p(P_COLON)? {
                self.parse_type()?;
            }
            if !self.is_p(P_RBRACK) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        self.eat_p(P_QUESTION)?;
        if self.eat_p(P_COLON)? {
            self.parse_type()?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ modules --

    fn parse_module_source(&mut self) -> R<NodeId> {
        if self.tok.t != T::Str {
            return self.fail();
        }
        let at = self.at();
        let (v, e) = (self.tok.v, self.tok.e);
        self.next()?;
        let node = self.mk(Kind::Literal, at, e, L_STRING, 0, [v, NONE, NONE, NONE]);
        if (self.is_n(W_WITH) || self.is_n(W_ASSERT)) && !self.tok.nl {
            self.next()?;
            self.parse_object_like()?; // import attributes, left out
        }
        Ok(node)
    }

    fn parse_import(&mut self) -> R<NodeId> {
        let at = self.at();
        self.next()?;
        let mut type_only = false;
        if self.is_n(W_TYPE) || self.is_n(W_TYPEOF) {
            let (pk, pv, _) = self.peek();
            if (pk == T::Name && pv != W_FROM) || (pk == T::P && (pv == P_LBRACE || pv == P_STAR)) {
                self.next()?;
                type_only = true;
            }
        }
        if self.tok.t == T::Str {
            let source = self.parse_module_source()?;
            self.semicolon()?;
            return Ok(self.fin(Kind::ImportDeclaration, at, [0, source, NONE, NONE]));
        }
        let mark = self.scratch.len();
        if self.tok.t == T::Name {
            let local = self.ident(false)?;
            if self.is_p(P_ASSIGN) {
                self.next()?;
                return self.parse_import_equals(at, local, type_only);
            }
            let lat = self.at_of(local);
            let spec = self.fin(Kind::ImportDefaultSpecifier, lat, [local, NONE, NONE, NONE]);
            self.scratch.push(spec);
            if !self.eat_p(P_COMMA)? {
                self.expect_n(W_FROM)?;
                let source = self.parse_module_source()?;
                self.semicolon()?;
                let specs = self.commit(mark);
                let specs = if type_only { 0 } else { specs };
                return Ok(self.fin(Kind::ImportDeclaration, at, [specs, source, NONE, NONE]));
            }
        }
        if self.is_p(P_STAR) {
            let sat = self.at();
            self.next()?;
            self.expect_n(W_AS)?;
            let local = self.ident(false)?;
            let spec = self.fin(Kind::ImportNamespaceSpecifier, sat, [local, NONE, NONE, NONE]);
            self.scratch.push(spec);
        } else if self.is_p(P_LBRACE) {
            self.next()?;
            while !self.is_p(P_RBRACE) {
                let sat = self.at();
                let skip = self.type_modifier_here()?;
                let imported = if self.tok.t == T::Str {
                    let iat = self.at();
                    let (v, e) = (self.tok.v, self.tok.e);
                    self.next()?;
                    self.mk(Kind::Literal, iat, e, L_STRING, 0, [v, NONE, NONE, NONE])
                } else {
                    self.ident(true)?
                };
                let local;
                if self.eat_n(W_AS)? {
                    local = self.ident(false)?;
                } else if self.node(imported).kind == Kind::Identifier {
                    let i = *self.node(imported);
                    local = self.mk(Kind::Identifier, self.at_of(imported), i.end, 0, 0, [i.f[A as usize], NONE, NONE, NONE]);
                } else {
                    return self.fail();
                }
                if !skip {
                    let spec = self.fin(Kind::ImportSpecifier, sat, [imported, local, NONE, NONE]);
                    self.scratch.push(spec);
                }
                if !self.is_p(P_RBRACE) {
                    self.expect_p(P_COMMA)?;
                }
            }
            self.next()?;
        } else {
            return self.fail();
        }
        self.expect_n(W_FROM)?;
        let source = self.parse_module_source()?;
        self.semicolon()?;
        let specs = self.commit(mark);
        let specs = if type_only { 0 } else { specs };
        Ok(self.fin(Kind::ImportDeclaration, at, [specs, source, NONE, NONE]))
    }

    /// In `{ … }` of an import or export: a `type` modifier before a name
    /// (consumed; true), not a name `type` itself.
    fn type_modifier_here(&mut self) -> R<bool> {
        if !self.is_n(W_TYPE) {
            return Ok(false);
        }
        let (pk, pv, _) = self.peek();
        if pk == T::Str {
            self.next()?;
            return Ok(true);
        }
        if pk != T::Name {
            return Ok(false);
        }
        if pv != W_AS {
            self.next()?;
            return Ok(true);
        }
        // `type as …`: `type as x` renames `type`; `type as as x` and
        // `type as,` / `type as }` import `as` as a type
        let ahead = self.look(
            |p| {
                p.next()?; // as
                p.next()?;
                if p.tok.t == T::Name && p.tok.v == W_AS {
                    return Ok(true);
                }
                Ok(p.tok.t == T::P && (p.tok.v == P_COMMA || p.tok.v == P_RBRACE))
            },
            3,
        )?;
        if ahead {
            self.next()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// `import x = require('m')` / `import x = A.B` (after the `=`).
    fn parse_import_equals(&mut self, at: At, local: NodeId, type_only: bool) -> R<NodeId> {
        if self.is_n(W_REQUIRE) {
            let (pk, pv, _) = self.peek();
            if pk == T::P && pv == P_LPAREN {
                self.next()?;
                self.next()?;
                if self.tok.t != T::Str {
                    return self.fail();
                }
                let sat = self.at();
                let (v, e) = (self.tok.v, self.tok.e);
                self.next()?;
                let src = self.mk(Kind::Literal, sat, e, L_STRING, 0, [v, NONE, NONE, NONE]);
                self.expect_p(P_RPAREN)?;
                self.semicolon()?;
                if type_only {
                    return Ok(self.fin(Kind::EmptyStatement, at, [NONE; 4]));
                }
                return Ok(self.fin(Kind::TSImportEquals, at, [local, src, NONE, NONE]));
            }
        }
        let mut entity = self.ident(true)?;
        while self.eat_p(P_DOT)? {
            let prop = self.ident(true)?;
            let eat = self.at_of(entity);
            entity = self.fin(Kind::MemberExpression, eat, [entity, prop, NONE, NONE]);
        }
        self.semicolon()?;
        if type_only {
            return Ok(self.fin(Kind::EmptyStatement, at, [NONE; 4]));
        }
        Ok(self.fin(Kind::TSImportEquals, at, [local, NONE, entity, NONE]))
    }

    fn export_name(&mut self) -> R<NodeId> {
        if self.tok.t == T::Str {
            let at = self.at();
            let (v, e) = (self.tok.v, self.tok.e);
            self.next()?;
            return Ok(self.mk(Kind::Literal, at, e, L_STRING, 0, [v, NONE, NONE, NONE]));
        }
        self.ident(true)
    }

    fn parse_export(&mut self, decorators: u32) -> R<Option<NodeId>> {
        let mut decorators = decorators;
        let at = self.at();
        self.next()?;
        if self.is_p(P_AT) {
            let more = self.parse_decorators()?;
            decorators = self.join_decorators(decorators, more);
        }
        if self.is_p(P_ASSIGN) {
            self.next()?;
            let expr = self.parse_expression(false)?;
            self.semicolon()?;
            return Ok(Some(self.fin(Kind::TSExportAssignment, at, [expr, NONE, NONE, NONE])));
        }
        if self.is_n(W_AS) {
            self.next()?;
            self.expect_n(W_NAMESPACE)?;
            self.ident(true)?;
            self.semicolon()?;
            return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
        }
        if self.is_n(W_IMPORT) && self.peek().0 == T::Name {
            self.next()?;
            let local = self.ident(false)?;
            self.expect_p(P_ASSIGN)?;
            let node = self.parse_import_equals(at, local, false)?;
            if self.node(node).kind == Kind::TSImportEquals {
                self.tree.nodes[node as usize].flags |= EXPORTED;
            }
            return Ok(Some(node));
        }
        if self.is_n(W_DEFAULT) {
            self.next()?;
            let (pk, pv, pnl) = self.peek();
            let decl;
            if self.is_n(W_FUNCTION) {
                let fat = self.at();
                decl = self.parse_function(true, false, fat)?;
            } else if self.is_n(W_ASYNC) && pk == T::Name && pv == W_FUNCTION && !pnl {
                let aat = self.at();
                self.next()?;
                decl = self.parse_function(true, true, aat)?;
            } else if self.is_n(W_CLASS) || (self.is_n(W_ABSTRACT) && pk == T::Name && pv == W_CLASS) {
                decl = Some(self.parse_class(true, decorators)?);
            } else if self.is_p(P_AT) {
                let more = self.parse_decorators()?;
                let all = self.join_decorators(decorators, more);
                decl = Some(self.parse_class(true, all)?);
            } else if self.is_n(W_INTERFACE) && pk == T::Name && !pnl {
                self.parse_ts_declaration(pk, pv, pnl)?;
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            } else {
                let d = self.parse_maybe_assign(false, true)?;
                self.semicolon()?;
                decl = Some(d);
            }
            return Ok(Some(match decl {
                None => self.fin(Kind::EmptyStatement, at, [NONE; 4]),
                Some(d) => self.fin(Kind::ExportDefaultDeclaration, at, [d, NONE, NONE, NONE]),
            }));
        }
        if self.is_p(P_STAR) {
            self.next()?;
            let mut exported = NONE;
            if self.eat_n(W_AS)? {
                exported = self.export_name()?;
            }
            self.expect_n(W_FROM)?;
            let source = self.parse_module_source()?;
            self.semicolon()?;
            return Ok(Some(self.fin(Kind::ExportAllDeclaration, at, [exported, source, NONE, NONE])));
        }
        let mut type_only = false;
        if self.is_n(W_TYPE) {
            let (pk, pv, _) = self.peek();
            if pk == T::P && (pv == P_LBRACE || pv == P_STAR) {
                self.next()?;
                type_only = true;
                if self.is_p(P_STAR) {
                    self.next()?;
                    if self.eat_n(W_AS)? {
                        self.export_name()?;
                    }
                    self.expect_n(W_FROM)?;
                    self.parse_module_source()?;
                    self.semicolon()?;
                    return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
                }
            }
        }
        if self.is_p(P_LBRACE) {
            self.next()?;
            let mark = self.scratch.len();
            while !self.is_p(P_RBRACE) {
                let sat = self.at();
                let skip = self.type_modifier_here()?;
                let local = self.export_name()?;
                let exported = if self.eat_n(W_AS)? {
                    self.export_name()?
                } else {
                    let l = *self.node(local);
                    self.tree.nodes.push(l); // dict(local): a copy
                    self.tree.nodes.len() as u32 - 1
                };
                if !skip {
                    let spec = self.fin(Kind::ExportSpecifier, sat, [local, exported, NONE, NONE]);
                    self.scratch.push(spec);
                }
                if !self.is_p(P_RBRACE) {
                    self.expect_p(P_COMMA)?;
                }
            }
            self.next()?;
            let source = if self.eat_n(W_FROM)? { self.parse_module_source()? } else { NONE };
            self.semicolon()?;
            let specs = self.commit(mark);
            if type_only {
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            }
            return Ok(Some(self.fin(Kind::ExportNamedDeclaration, at, [NONE, specs, source, NONE])));
        }
        if self.is_p(P_AT) {
            let more = self.parse_decorators()?;
            decorators = self.join_decorators(decorators, more);
        }
        let (pk, pv, _) = self.peek();
        let decl = if self.is_n(W_CLASS) || (self.is_n(W_ABSTRACT) && pk == T::Name && pv == W_CLASS) {
            Some(self.parse_class(true, decorators)?)
        } else {
            self.parse_statement()?
        };
        let decl = match decl {
            Some(d) if self.node(d).kind != Kind::EmptyStatement => d,
            _ => return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4]))),
        };
        if !matches!(
            self.node(decl).kind,
            Kind::VariableDeclaration
                | Kind::FunctionDeclaration
                | Kind::ClassDeclaration
                | Kind::TSEnumDeclaration
                | Kind::TSModuleDeclaration
        ) {
            return self.fail_at("unexpected export", at.line);
        }
        Ok(Some(self.fin(Kind::ExportNamedDeclaration, at, [decl, 0, NONE, NONE])))
    }

    // ------------------------------------------ TypeScript declarations --

    /// interface / type / enum / declare / namespace / module / global /
    /// abstract class at a statement's start; None where the word is an
    /// identifier instead.
    pub(super) fn parse_ts_declaration(&mut self, pk: T, pv: u32, pnl: bool) -> R<Option<NodeId>> {
        let at = self.at();
        let v = self.tok.v;
        if v == W_ABSTRACT {
            if pk == T::Name && pv == W_CLASS && !pnl {
                return self.parse_class(true, NONE).map(Some);
            }
            return Ok(None);
        }
        if !self.ts && v != W_TYPE && v != W_INTERFACE && v != W_DECLARE {
            return Ok(None);
        }
        if v == W_INTERFACE {
            if pk != T::Name || pnl {
                return Ok(None);
            }
            self.next()?;
            self.ident(true)?;
            if self.is_p(P_LT) {
                self.parse_type_params()?;
            }
            if self.eat_n(W_EXTENDS)? {
                self.parse_type()?;
                while self.eat_p(P_COMMA)? {
                    self.parse_type()?;
                }
            }
            self.parse_object_type()?;
            return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
        }
        if v == W_TYPE {
            if pk != T::Name || pnl {
                return Ok(None);
            }
            self.next()?;
            self.ident(true)?;
            if self.is_p(P_LT) {
                self.parse_type_params()?;
            }
            self.expect_p(P_ASSIGN)?;
            self.parse_type()?;
            self.semicolon()?;
            return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
        }
        if v == W_ENUM {
            if pk != T::Name {
                return Ok(None);
            }
            return self.parse_enum(at).map(Some);
        }
        if v == W_DECLARE {
            if pk != T::Name || pnl {
                return Ok(None);
            }
            self.next()?;
            let saved = self.declaring;
            self.declaring = true;
            let r = self.parse_statement(); // read and left out
            self.declaring = saved;
            r?;
            return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
        }
        if v == W_NAMESPACE || v == W_MODULE {
            if pnl || !(pk == T::Name || (v == W_MODULE && pk == T::Str)) {
                return Ok(None);
            }
            self.next()?;
            if self.tok.t == T::Str {
                self.next()?;
                if self.is_p(P_LBRACE) {
                    self.parse_block()?;
                } else {
                    self.semicolon()?;
                }
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            }
            let name = self.ident(true)?;
            while self.eat_p(P_DOT)? {
                self.ident(true)?;
            }
            if !self.is_p(P_LBRACE) {
                self.semicolon()?;
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            }
            let body = self.parse_block()?;
            return Ok(Some(self.fin(Kind::TSModuleDeclaration, at, [name, body, NONE, NONE])));
        }
        if v == W_GLOBAL {
            if pk == T::P && pv == P_LBRACE {
                self.next()?;
                self.parse_block()?;
                return Ok(Some(self.fin(Kind::EmptyStatement, at, [NONE; 4])));
            }
            return Ok(None);
        }
        Ok(None)
    }

    fn parse_enum(&mut self, at: At) -> R<NodeId> {
        self.expect_n(W_ENUM)?;
        let eid = self.ident(true)?;
        self.expect_p(P_LBRACE)?;
        let mark = self.scratch.len();
        while !self.is_p(P_RBRACE) {
            let mat = self.at();
            let key;
            if self.eat_p(P_LBRACK)? {
                key = self.parse_maybe_assign(false, true)?;
                self.expect_p(P_RBRACK)?;
            } else {
                key = self.parse_property_name()?;
            }
            let init = if self.eat_p(P_ASSIGN)? { self.parse_maybe_assign(false, true)? } else { NONE };
            let member = self.fin(Kind::TSEnumMember, mat, [key, init, NONE, NONE]);
            self.scratch.push(member);
            if !self.is_p(P_RBRACE) {
                self.expect_p(P_COMMA)?;
            }
        }
        self.next()?;
        let members = self.commit(mark);
        Ok(self.fin(Kind::TSEnumDeclaration, at, [eid, members, NONE, NONE]))
    }
}

/// `let` followed by this token starts a declaration: a name, `[` or `{`; not `in` or `instanceof`, which make `let` a
/// name in sloppy code (`for (let in x)`, `let in x`, which V8 compiles in a script: JS-PARSE-STRICT).
fn let_declares(pk: T, pv: u32) -> bool {
    (pk == T::Name && pv != W_IN && pv != W_INSTANCEOF) || (pk == T::P && (pv == P_LBRACK || pv == P_LBRACE))
}

/// _PARAM_MODIFIERS
#[inline]
pub(super) fn param_modifier(v: u32) -> bool {
    matches!(v, W_PUBLIC | W_PRIVATE | W_PROTECTED | W_READONLY | W_OVERRIDE)
}

/// _CLASS_MODIFIERS
#[inline]
fn class_modifier(v: u32) -> bool {
    matches!(
        v,
        W_PUBLIC
            | W_PRIVATE
            | W_PROTECTED
            | W_READONLY
            | W_ABSTRACT
            | W_OVERRIDE
            | W_DECLARE
            | W_STATIC
            | W_ACCESSOR
            | W_ASYNC
            | W_GET
            | W_SET
    )
}

/// _KEY_KINDS
#[inline]
pub(super) fn key_kind(t: T) -> bool {
    matches!(t, T::Name | T::Str | T::Num | T::BigInt | T::Priv)
}
