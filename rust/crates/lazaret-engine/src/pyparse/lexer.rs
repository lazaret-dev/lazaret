//! The tokenizer: the whole text to tokens before the parser starts, as
//! Python 3.13 reads source text (its tokenizer does not depend on the
//! parser): names, numbers, strings, f-strings in pieces (PEP 701: the
//! literal parts, and the tokens of each replacement field), operators, and
//! NEWLINE, INDENT and DEDENT for the lines' structure.
//!
//! Lines end at "\r\n", "\r" or "\n". Indentation is measured with tabs to
//! the next multiple of 8 and, to catch an inconsistent mix (TabError), with
//! tabs as 1; a form feed starts the count again. A line of blanks and a
//! comment, or of nothing, is not a line of the program. Inside brackets
//! (an f-string's replacement field is one) lines go on. The limits are
//! Python's: 200 nested brackets ("too many nested parentheses"), 99
//! indentation levels, 149 nested f-strings, a format specifier nested in
//! at most 2 others.
//!
//! Python's parser takes its tokens one at a time, as it needs them, so a
//! syntax error before a token the tokenizer refuses is the error it
//! reports (and then, reading the rest of the text, the tokenizer's error
//! if it is one the tokenizer raises itself: see `Parser::error`). Here the
//! tokens end at the first token refused, with an `Error` token, and the
//! refusal is kept ([`LexFail`]) for the parser to report, or not.

use super::tree::Strings;
use super::unicode;

/// A token's type.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum T {
    Name,
    Number,
    Str,
    /// `f'`, `rf"""` …: an f-string's prefix and opening quote
    FStart,
    /// an f-string's literal text (escapes and doubled braces undecoded)
    FMiddle,
    /// an f-string's closing quote
    FEnd,
    Op,
    Kw,
    Newline,
    Indent,
    Dedent,
    End,
    /// where the tokenizer stopped: the last token (no rule takes it)
    Error,
}

/// One token: its type, a small value (`k`: the operator, the keyword, a
/// string's flags; for a name, 1 when its text is not ASCII), where it is,
/// and for a name its identifier (NFKC), a string id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tok {
    pub t: T,
    pub k: u8,
    pub s: u32,
    pub e: u32,
    pub v: u32,
}

// ---- operators (`Tok::k` of an Op) ----
pub const LPAR: u8 = 0;
pub const RPAR: u8 = 1;
pub const LSQB: u8 = 2;
pub const RSQB: u8 = 3;
pub const COLON: u8 = 4;
pub const COMMA: u8 = 5;
pub const SEMI: u8 = 6;
pub const PLUS: u8 = 7;
pub const MINUS: u8 = 8;
pub const STAR: u8 = 9;
pub const SLASH: u8 = 10;
pub const VBAR: u8 = 11;
pub const AMPER: u8 = 12;
pub const LESS: u8 = 13;
pub const GREATER: u8 = 14;
pub const EQUAL: u8 = 15;
pub const DOT: u8 = 16;
pub const PERCENT: u8 = 17;
pub const LBRACE: u8 = 18;
pub const RBRACE: u8 = 19;
pub const EQEQUAL: u8 = 20;
pub const NOTEQUAL: u8 = 21;
pub const LESSEQUAL: u8 = 22;
pub const GREATEREQUAL: u8 = 23;
pub const TILDE: u8 = 24;
pub const CIRCUMFLEX: u8 = 25;
pub const LEFTSHIFT: u8 = 26;
pub const RIGHTSHIFT: u8 = 27;
pub const DOUBLESTAR: u8 = 28;
pub const PLUSEQUAL: u8 = 29;
pub const MINEQUAL: u8 = 30;
pub const STAREQUAL: u8 = 31;
pub const SLASHEQUAL: u8 = 32;
pub const PERCENTEQUAL: u8 = 33;
pub const AMPEREQUAL: u8 = 34;
pub const VBAREQUAL: u8 = 35;
pub const CIRCUMFLEXEQUAL: u8 = 36;
pub const LEFTSHIFTEQUAL: u8 = 37;
pub const RIGHTSHIFTEQUAL: u8 = 38;
pub const DOUBLESTAREQUAL: u8 = 39;
pub const DOUBLESLASH: u8 = 40;
pub const DOUBLESLASHEQUAL: u8 = 41;
pub const AT: u8 = 42;
pub const ATEQUAL: u8 = 43;
pub const RARROW: u8 = 44;
pub const ELLIPSIS: u8 = 45;
pub const COLONEQUAL: u8 = 46;
pub const EXCLAMATION: u8 = 47;
/// `<>`: Python reads it only under `from __future__ import barry_as_FLUFL`,
/// which `ast.parse` does not honor; no rule takes it
pub const OLDNOTEQUAL: u8 = 48;
/// `$`, `?` or a backquote: a token for Python's tokenizer (an operator no
/// rule takes), so an error of the parser's where it stands, not the
/// tokenizer's
pub const UNKNOWN: u8 = 49;

/// The operators' text, by id.
pub const OPS: &[&str] = &[
    "(", ")", "[", "]", ":", ",", ";", "+", "-", "*", "/", "|", "&", "<", ">", "=", ".", "%", "{", "}", "==", "!=", "<=",
    ">=", "~", "^", "<<", ">>", "**", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "**=", "//", "//=",
    "@", "@=", "->", "...", ":=", "!", "<>", "$",
];

// ---- keywords (`Tok::k` of a Kw) ----
pub const KW_FALSE: u8 = 0;
pub const KW_NONE: u8 = 1;
pub const KW_TRUE: u8 = 2;
pub const KW_AND: u8 = 3;
pub const KW_AS: u8 = 4;
pub const KW_ASSERT: u8 = 5;
pub const KW_ASYNC: u8 = 6;
pub const KW_AWAIT: u8 = 7;
pub const KW_BREAK: u8 = 8;
pub const KW_CLASS: u8 = 9;
pub const KW_CONTINUE: u8 = 10;
pub const KW_DEF: u8 = 11;
pub const KW_DEL: u8 = 12;
pub const KW_ELIF: u8 = 13;
pub const KW_ELSE: u8 = 14;
pub const KW_EXCEPT: u8 = 15;
pub const KW_FINALLY: u8 = 16;
pub const KW_FOR: u8 = 17;
pub const KW_FROM: u8 = 18;
pub const KW_GLOBAL: u8 = 19;
pub const KW_IF: u8 = 20;
pub const KW_IMPORT: u8 = 21;
pub const KW_IN: u8 = 22;
pub const KW_IS: u8 = 23;
pub const KW_LAMBDA: u8 = 24;
pub const KW_NONLOCAL: u8 = 25;
pub const KW_NOT: u8 = 26;
pub const KW_OR: u8 = 27;
pub const KW_PASS: u8 = 28;
pub const KW_RAISE: u8 = 29;
pub const KW_RETURN: u8 = 30;
pub const KW_TRY: u8 = 31;
pub const KW_WHILE: u8 = 32;
pub const KW_WITH: u8 = 33;
pub const KW_YIELD: u8 = 34;

/// The keywords' text, by id.
pub const KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del",
    "elif", "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda", "nonlocal",
    "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

// ---- a string token's flags (`Tok::k` of a Str, FStart or FMiddle) ----
pub const S_RAW: u8 = 1;
pub const S_BYTES: u8 = 2;
/// a `u` prefix (Constant's kind 'u')
pub const S_U: u8 = 4;
pub const S_TRIPLE: u8 = 8;
/// an FMiddle in a format specifier (its braces are never doubled)
pub const S_SPEC: u8 = 16;

/// Brackets open at once, at most.
pub const MAX_PARENS: usize = 200;
/// Indentation levels, at most (the first line's included).
pub const MAX_INDENT: usize = 100;
/// f-strings open at once: fewer than this.
pub const MAX_FSTRINGS: usize = 150;
/// Format specifiers open at once in one f-string, at most.
pub const MAX_SPECS: usize = 2;

/// The tokens of a text, and what the parser and the tree need besides.
pub struct Lexed {
    pub toks: Vec<Tok>,
    pub strings: Strings,
    /// where each line starts
    pub line_starts: Vec<u32>,
    /// the comments inside f-strings' replacement fields: [start, end) (a
    /// field's text after `=` leaves them out)
    pub comments: Vec<(u32, u32)>,
    /// the token the tokenizer refused, if it refused one (the last token,
    /// `Error`, is where it stands)
    pub fail: Option<LexFail>,
}

/// A text the tokenizer refuses: the line, and why.
pub type LexError = (u32, String);

/// The token the tokenizer refused.
#[derive(Clone, Debug)]
pub struct LexFail {
    /// its index (the `Error` token's)
    pub tok: usize,
    pub line: u32,
    pub reason: String,
    /// Python's tokenizer raises this error itself (a bad character, an
    /// unterminated string, an unmatched bracket …), rather than leaving it
    /// to its parser (a bad unindent, a mix of tabs and spaces, too many
    /// indentation levels, a backslash before something other than a line
    /// break, the end of the text in brackets)
    pub raised: bool,
    /// … inside an f-string
    pub in_fstring: bool,
    /// the innermost bracket open there: the character and its line (0: none)
    pub open: (u32, u32),
}

enum Frame {
    /// an f-string: its literal text is read while this is on top
    FStr { quote: u32, triple: bool, raw: bool, start: u32 },
    /// a replacement field: tokens, until the bracket depth is back to
    /// `base` and a `}` (or a `:`) comes; `fs`: its f-string's frame
    Field { base: usize, fs: usize },
    /// a format specifier: literal text, until `}`
    Spec { fs: usize },
}

struct Lexer<'a> {
    src: &'a [u32],
    i: usize,
    toks: Vec<Tok>,
    strings: Strings,
    line_starts: Vec<u32>,
    comments: Vec<(u32, u32)>,
    /// (col, alt col) of each indentation level
    indents: Vec<(u32, u32)>,
    /// the open brackets: (the character, where)
    parens: Vec<(u32, u32)>,
    frames: Vec<Frame>,
    /// open f-strings (FStr frames)
    nfstrings: usize,
    at_bol: bool,
    line_has_tokens: bool,
    name_buf: Vec<u32>,
    /// the error being returned is one Python's tokenizer leaves to its
    /// parser (`LexFail::raised`)
    quiet: bool,
    /// a `t` prefix begins a template string, as in Python 3.14 (PEP 750)
    tstrings: bool,
}

#[inline]
fn is_newline(c: u32) -> bool {
    c == 0x0A || c == 0x0D
}

#[inline]
fn is_digit(c: u32) -> bool {
    (0x30..=0x39).contains(&c)
}

#[inline]
fn is_hex(c: u32) -> bool {
    is_digit(c) || (0x41..=0x46).contains(&c) || (0x61..=0x66).contains(&c)
}

/// A character an identifier may hold, as the tokenizer first reads it
/// (ASCII letters, digits, `_`, and any non-ASCII character: those are
/// checked once the identifier is read).
#[inline]
fn ident_char(c: u32) -> bool {
    c >= 0x80 || c == 0x5F || is_digit(c) || (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

#[inline]
fn ident_start(c: u32) -> bool {
    c >= 0x80 || c == 0x5F || (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c)
}

/// The start of each line of `src` (a line ends at "\r\n", "\r" or "\n").
pub fn line_starts(src: &[u32]) -> Vec<u32> {
    let mut out = vec![0u32];
    let mut i = 0;
    while i < src.len() {
        match src[i] {
            0x0A => out.push(i as u32 + 1),
            0x0D => {
                if src.get(i + 1) == Some(&0x0A) {
                    i += 1;
                }
                out.push(i as u32 + 1);
            }
            _ => {}
        }
        i += 1;
    }
    out
}

/// Tokenizes `src` (up to the first token refused: `Lexed::fail`). Refused
/// whole, with line 0 (Python's error has none): a text holding a NUL, or
/// what Python cannot encode (a lone surrogate, a value beyond U+10FFFF).
pub fn tokenize(src: &[u32]) -> Result<Lexed, LexError> {
    tokenize_with(src, false)
}

/// `tokenize`, and with `tstrings` a `t` prefix (`t`, `tr`, `rt`) begins a
/// template string, read as an f-string is (Python 3.14, PEP 750: the
/// lexers read what 3.14 runs; the parser stays 3.13's).
pub fn tokenize_with(src: &[u32], tstrings: bool) -> Result<Lexed, LexError> {
    if let Some(at) = src.iter().position(|&c| c == 0 || (0xD800..0xE000).contains(&c) || c > 0x10FFFF) {
        let why = if src[at] == 0 {
            "source code string cannot contain null bytes"
        } else {
            "source code cannot hold a surrogate or a value beyond U+10FFFF"
        };
        return Err((0, why.to_string()));
    }
    let starts = line_starts(src);
    let mut lx = Lexer {
        src,
        i: 0,
        toks: Vec::with_capacity(src.len() / 3 + 16),
        strings: Strings::new(),
        line_starts: starts,
        comments: Vec::new(),
        indents: vec![(0, 0)],
        parens: Vec::new(),
        frames: Vec::new(),
        nfstrings: 0,
        at_bol: true,
        line_has_tokens: false,
        name_buf: Vec::new(),
        quiet: false,
        tstrings,
    };
    let fail = match lx.run() {
        Ok(()) => None,
        Err((line, reason)) => {
            let tok = lx.toks.len();
            let at = lx.i.min(src.len()) as u32;
            lx.toks.push(Tok { t: T::Error, k: 0, s: at, e: at, v: 0 });
            let open = match lx.parens.last() {
                Some(&(c, pat)) => (c, lx.line_at(pat as usize)),
                None => (0, 0),
            };
            Some(LexFail { tok, line, reason, raised: !lx.quiet, in_fstring: !lx.frames.is_empty(), open })
        }
    };
    Ok(Lexed { toks: lx.toks, strings: lx.strings, line_starts: lx.line_starts, comments: lx.comments, fail })
}

impl<'a> Lexer<'a> {
    #[inline]
    fn peek(&self, k: usize) -> u32 {
        self.src.get(self.i + k).copied().unwrap_or(u32::MAX)
    }

    fn line_at(&self, at: usize) -> u32 {
        self.line_starts.partition_point(|&s| s as usize <= at) as u32
    }

    fn err<X>(&self, at: usize, why: &str) -> Result<X, LexError> {
        Err((self.line_at(at), why.to_string()))
    }

    /// An error Python's tokenizer leaves to its parser (`LexFail::raised`).
    fn quiet_err<X>(&mut self, at: usize, why: &str) -> Result<X, LexError> {
        self.quiet = true;
        self.err(at, why)
    }

    /// The end of the text where a token must follow (after a backslash
    /// and a line break): in brackets, the innermost was never closed.
    fn eof_err<X>(&mut self, at: usize) -> Result<X, LexError> {
        match self.parens.last() {
            Some(&(c, pat)) => {
                let ch = char::from_u32(c).unwrap_or('(');
                self.quiet_err(pat as usize, &format!("'{}' was never closed", ch))
            }
            None => self.quiet_err(at, "unexpected EOF while parsing"),
        }
    }

    #[inline]
    fn push(&mut self, t: T, k: u8, s: usize, e: usize, v: u32) {
        self.toks.push(Tok { t, k, s: s as u32, e: e as u32, v });
        if !matches!(t, T::Newline | T::Indent | T::Dedent | T::End) {
            self.line_has_tokens = true;
        }
    }

    /// The length of the line break at `at` (0: none).
    #[inline]
    fn newline_len(&self, at: usize) -> usize {
        match self.src.get(at) {
            Some(&0x0A) => 1,
            Some(&0x0D) => {
                if self.src.get(at + 1) == Some(&0x0A) {
                    2
                } else {
                    1
                }
            }
            _ => 0,
        }
    }

    fn run(&mut self) -> Result<(), LexError> {
        loop {
            match self.frames.last() {
                Some(Frame::FStr { .. }) => self.fstring_text(false)?,
                Some(Frame::Spec { .. }) => self.fstring_text(true)?,
                _ => {
                    if !self.token()? {
                        return Ok(());
                    }
                }
            }
        }
    }

    /// The indentation of a line, at its start: INDENT and DEDENT tokens;
    /// lines that are blank or a comment are passed over.
    fn indentation(&mut self) -> Result<(), LexError> {
        loop {
            let (mut col, mut alt, mut cont) = (0u32, 0u32, 0u32);
            loop {
                match self.peek(0) {
                    0x20 => {
                        col += 1;
                        alt += 1;
                        self.i += 1;
                    }
                    0x09 => {
                        col = (col / 8 + 1) * 8;
                        alt += 1;
                        self.i += 1;
                    }
                    0x0C => {
                        col = 0;
                        alt = 0;
                        self.i += 1;
                    }
                    0x5C => {
                        // a backslash and a line break: the line goes on (the
                        // first one's column is the line's indentation)
                        if cont == 0 {
                            cont = col;
                        }
                        let n = self.newline_len(self.i + 1);
                        if n == 0 {
                            if self.i + 1 >= self.src.len() {
                                return self.eof_err(self.i);
                            }
                            return self.quiet_err(self.i, "unexpected character after line continuation character");
                        }
                        self.i += 1 + n;
                        if self.i >= self.src.len() {
                            return self.eof_err(self.i - 1);
                        }
                    }
                    _ => break,
                }
            }
            let c = self.peek(0);
            if c == 0x23 || is_newline(c) || self.i >= self.src.len() {
                // a blank line, or a comment alone: not a line of the program
                if c == 0x23 {
                    while self.i < self.src.len() && !is_newline(self.src[self.i]) {
                        self.i += 1;
                    }
                }
                let n = self.newline_len(self.i);
                if n == 0 {
                    return Ok(()); // the end of the text
                }
                self.i += n;
                continue;
            }
            if cont != 0 {
                col = cont;
                alt = cont;
            }
            self.at_bol = false;
            let (top, alttop) = *self.indents.last().unwrap_or(&(0, 0));
            if col == top {
                if alt != alttop {
                    return self.quiet_err(self.i, "inconsistent use of tabs and spaces in indentation");
                }
            } else if col > top {
                if self.indents.len() >= MAX_INDENT {
                    return self.quiet_err(self.i, "too many levels of indentation");
                }
                if alt <= alttop {
                    return self.quiet_err(self.i, "inconsistent use of tabs and spaces in indentation");
                }
                self.indents.push((col, alt));
                self.push(T::Indent, 0, self.i, self.i, 0);
            } else {
                // (checked before any DEDENT is given, as Python's tokenizer does)
                let mut n = self.indents.len();
                while n > 1 && col < self.indents[n - 1].0 {
                    n -= 1;
                }
                let (top, alttop) = self.indents[n - 1];
                if col != top {
                    return self.quiet_err(self.i, "unindent does not match any outer indentation level");
                }
                if alt != alttop {
                    return self.quiet_err(self.i, "inconsistent use of tabs and spaces in indentation");
                }
                while self.indents.len() > n {
                    self.indents.pop();
                    self.push(T::Dedent, 0, self.i, self.i, 0);
                }
            }
            return Ok(());
        }
    }

    /// The end of the text: NEWLINE if a line is open, DEDENTs, the end.
    fn finish(&mut self) -> Result<(), LexError> {
        if !self.parens.is_empty() {
            return self.eof_err(self.src.len());
        }
        let at = self.src.len();
        if self.line_has_tokens {
            self.push(T::Newline, 0, at, at, 0);
            self.line_has_tokens = false;
        }
        while self.indents.len() > 1 {
            self.indents.pop();
            self.push(T::Dedent, 0, at, at, 0);
        }
        self.push(T::End, 0, at, at, 0);
        Ok(())
    }

    /// The field frame on top, if the tokens are a replacement field's.
    fn field_base(&self) -> Option<(usize, usize)> {
        match self.frames.last() {
            Some(&Frame::Field { base, fs }) => Some((base, fs)),
            _ => None,
        }
    }

    /// One token (or a line's structure); false at the end of the text.
    fn token(&mut self) -> Result<bool, LexError> {
        if self.at_bol {
            self.indentation()?;
        }
        loop {
            match self.peek(0) {
                0x20 | 0x09 | 0x0C => self.i += 1,
                _ => break,
            }
        }
        let start = self.i;
        let c = self.peek(0);
        if self.i >= self.src.len() {
            self.finish()?;
            return Ok(false);
        }
        match c {
            0x23 => {
                // a comment
                while self.i < self.src.len() && !is_newline(self.src[self.i]) {
                    self.i += 1;
                }
                if self.field_base().is_some() {
                    self.comments.push((start as u32, self.i as u32));
                }
            }
            0x0A | 0x0D => {
                let n = self.newline_len(self.i);
                if self.parens.is_empty() {
                    if self.line_has_tokens {
                        self.push(T::Newline, 0, start, start + n, 0);
                        self.line_has_tokens = false;
                    }
                    self.at_bol = true;
                }
                self.i += n;
            }
            0x5C => {
                // a line continuation
                let n = self.newline_len(self.i + 1);
                if n == 0 {
                    if self.i + 1 >= self.src.len() {
                        return self.eof_err(self.i);
                    }
                    return self.quiet_err(self.i, "unexpected character after line continuation character");
                }
                self.i += 1 + n;
                if self.i >= self.src.len() {
                    return self.eof_err(start);
                }
            }
            0x22 | 0x27 => self.string(start, start)?,
            _ if ident_start(c) => self.name(start)?,
            _ if is_digit(c) || (c == 0x2E && is_digit(self.peek(1))) => self.number(start)?,
            _ => self.operator(start)?,
        }
        Ok(true)
    }

    fn name(&mut self, start: usize) -> Result<(), LexError> {
        let mut ascii = true;
        while self.i < self.src.len() && ident_char(self.src[self.i]) {
            if self.src[self.i] >= 0x80 {
                ascii = false;
            }
            self.i += 1;
        }
        let end = self.i;
        let text = &self.src[start..end];
        // a string prefix?
        if ascii && text.len() <= 2 && matches!(self.peek(0), 0x22 | 0x27) {
            let mut flags = 0u8;
            let mut f = false;
            let mut ok = true;
            for &c in text {
                let (bit, isf) = match c | 0x20 {
                    0x72 => (S_RAW, false),
                    0x62 => (S_BYTES, false),
                    0x75 => (S_U, false),
                    0x66 => (0, true),
                    0x74 if self.tstrings => (0, true),
                    _ => {
                        ok = false;
                        (0, false)
                    }
                };
                if isf {
                    if f {
                        ok = false;
                    }
                    f = true;
                } else if flags & bit != 0 {
                    ok = false;
                } else {
                    flags |= bit;
                }
            }
            // r, u, b, br, rb, f, fr, rf
            let valid = ok
                && match text.len() {
                    1 => true,
                    _ => {
                        (flags == S_RAW | S_BYTES) || (f && flags == S_RAW)
                    }
                };
            if valid {
                return self.string(start, end);
            }
        }
        if ascii {
            if let Some(k) = KEYWORDS.iter().position(|kw| kw.len() == text.len() && kw.bytes().zip(text).all(|(a, &b)| a as u32 == b)) {
                self.push(T::Kw, k as u8, start, end, 0);
                return Ok(());
            }
            let v = self.strings.intern(text);
            self.push(T::Name, 0, start, end, v);
            return Ok(());
        }
        // a name with non-ASCII characters: each must be one an identifier may hold
        for (k, &c) in text.iter().enumerate() {
            let fine = if k == 0 { unicode::id_start(c) } else { unicode::id_continue(c) };
            if !fine {
                let ch = char::from_u32(c).unwrap_or('?');
                return self.err(start + k, &format!("invalid character '{}' (U+{:04X})", ch, c));
            }
        }
        self.name_buf = unicode::nfkc(text);
        let buf = std::mem::take(&mut self.name_buf);
        let v = self.strings.intern(&buf);
        self.name_buf = buf;
        self.push(T::Name, 1, start, end, v);
        Ok(())
    }

    /// A string or an f-string's start, its prefix at `start..qat`.
    fn string(&mut self, start: usize, qat: usize) -> Result<(), LexError> {
        let mut flags = 0u8;
        let mut f = false;
        for &c in &self.src[start..qat] {
            match c | 0x20 {
                0x72 => flags |= S_RAW,
                0x62 => flags |= S_BYTES,
                // (Constant's kind is 'u' for a lowercase `u` only)
                0x75 if c == 0x75 => flags |= S_U,
                0x75 => {}
                _ => f = true,
            }
        }
        let q = self.src[qat];
        let triple = self.src.get(qat + 1) == Some(&q) && self.src.get(qat + 2) == Some(&q);
        let qlen = if triple { 3 } else { 1 };
        if triple {
            flags |= S_TRIPLE;
        }
        if f {
            if self.nfstrings + 1 >= MAX_FSTRINGS {
                return self.err(start, "too many nested f-strings");
            }
            self.i = qat + qlen;
            self.push(T::FStart, flags, start, self.i, 0);
            self.frames.push(Frame::FStr { quote: q, triple, raw: flags & S_RAW != 0, start: start as u32 });
            self.nfstrings += 1;
            return Ok(());
        }
        let mut i = qat + qlen;
        loop {
            let c = match self.src.get(i) {
                Some(&c) => c,
                None => {
                    let why = if triple {
                        "unterminated triple-quoted string literal"
                    } else {
                        "unterminated string literal"
                    };
                    return self.err(start, why);
                }
            };
            if c == 0x5C {
                i += 1;
                let n = self.newline_len(i);
                i += if n > 0 { n } else { 1 };
                continue;
            }
            if is_newline(c) && !triple {
                return self.err(start, "unterminated string literal");
            }
            if c == q {
                if !triple {
                    i += 1;
                    break;
                }
                if self.src.get(i + 1) == Some(&q) && self.src.get(i + 2) == Some(&q) {
                    i += 3;
                    break;
                }
            }
            i += 1;
        }
        if i > self.src.len() {
            return self.err(start, "unterminated string literal");
        }
        self.i = i;
        self.push(T::Str, flags, start, i, 0);
        Ok(())
    }

    /// An f-string's literal text (in a format specifier: `spec`), up to a
    /// replacement field, the end of the specifier or the closing quote.
    fn fstring_text(&mut self, spec: bool) -> Result<(), LexError> {
        let fs = match self.frames.last() {
            Some(&Frame::Spec { fs }) => fs,
            _ => self.frames.len() - 1,
        };
        // (an unterminated f-string is reported on the line where it starts)
        let (q, triple, raw, fstart) = match self.frames.get(fs) {
            Some(&Frame::FStr { quote, triple, raw, start }) => (quote, triple, raw, start as usize),
            _ => return self.err(self.i, "f-string: internal state"),
        };
        let mut flags = if raw { S_RAW } else { 0 };
        if triple {
            flags |= S_TRIPLE;
        }
        if spec {
            flags |= S_SPEC;
        }
        let start = self.i;
        loop {
            let c = match self.src.get(self.i) {
                Some(&c) => c,
                None => {
                    let why = if triple {
                        "unterminated triple-quoted f-string literal"
                    } else {
                        "unterminated f-string literal"
                    };
                    return self.err(fstart, why);
                }
            };
            if c == q && (!triple || (self.peek(1) == q && self.peek(2) == q)) {
                if self.i > start {
                    self.push(T::FMiddle, flags, start, self.i, 0);
                }
                let qlen = if triple { 3 } else { 1 };
                self.push(T::FEnd, flags, self.i, self.i + qlen, 0);
                self.i += qlen;
                // (in a format specifier, the quote ends the f-string all the
                // same, its fields' brackets left open, as Python's tokenizer
                // has it: the parser refuses the FEnd, "expecting '}'")
                self.frames.truncate(fs);
                self.nfstrings -= 1;
                return Ok(());
            }
            if is_newline(c) {
                if !triple {
                    if spec {
                        let why = "f-string: newlines are not allowed in format specifiers for single quoted f-strings";
                        return self.err(self.i, why);
                    }
                    return self.err(fstart, "unterminated f-string literal");
                }
                self.i += self.newline_len(self.i);
                continue;
            }
            match c {
                0x5C => {
                    let next = self.peek(1);
                    if !raw && next == 0x4E && self.peek(2) == 0x7B {
                        // \N{...}: the braces are the escape's
                        self.i += 3;
                        while let Some(&d) = self.src.get(self.i) {
                            if d == 0x7D {
                                self.i += 1;
                                break;
                            }
                            if d == q || is_newline(d) {
                                break;
                            }
                            self.i += 1;
                        }
                    } else if next == 0x7B || next == 0x7D {
                        self.i += 1; // (a backslash does not escape a brace)
                    } else {
                        let n = self.newline_len(self.i + 1);
                        self.i += 1 + if n > 0 { n } else { 1 };
                        if self.i > self.src.len() {
                            self.i = self.src.len();
                        }
                    }
                }
                0x7B => {
                    if !spec && self.peek(1) == 0x7B {
                        self.i += 2;
                        continue;
                    }
                    if self.i > start {
                        self.push(T::FMiddle, flags, start, self.i, 0);
                    }
                    self.open_bracket(0x7B, self.i)?;
                    self.push(T::Op, LBRACE, self.i, self.i + 1, 0);
                    self.i += 1;
                    let base = self.parens.len();
                    self.frames.push(Frame::Field { base, fs });
                    return Ok(());
                }
                0x7D => {
                    if !spec {
                        if self.peek(1) == 0x7D {
                            self.i += 2;
                            continue;
                        }
                        return self.err(self.i, "f-string: single '}' is not allowed");
                    }
                    if self.i > start {
                        self.push(T::FMiddle, flags, start, self.i, 0);
                    }
                    // the end of the specifier and of its field
                    self.frames.pop(); // Spec
                    self.frames.pop(); // Field
                    self.parens.pop();
                    self.push(T::Op, RBRACE, self.i, self.i + 1, 0);
                    self.i += 1;
                    return Ok(());
                }
                _ => self.i += 1,
            }
        }
    }

    fn open_bracket(&mut self, c: u32, at: usize) -> Result<(), LexError> {
        if self.parens.len() >= MAX_PARENS {
            return self.err(at, "too many nested parentheses");
        }
        self.parens.push((c, at as u32));
        Ok(())
    }

    fn close_bracket(&mut self, c: u32, at: usize) -> Result<(), LexError> {
        let open = match c {
            0x29 => 0x28,
            0x5D => 0x5B,
            _ => 0x7B,
        };
        let ch = char::from_u32(c).unwrap_or(')');
        match self.parens.last() {
            None => self.err(at, &format!("unmatched '{}'", ch)),
            Some(&(o, _)) if o != open => {
                let oc = char::from_u32(o).unwrap_or('(');
                self.err(at, &format!("closing parenthesis '{}' does not match opening parenthesis '{}'", ch, oc))
            }
            Some(_) => {
                self.parens.pop();
                Ok(())
            }
        }
    }

    fn operator(&mut self, start: usize) -> Result<(), LexError> {
        let c = self.peek(0);
        let c1 = self.peek(1);
        let c2 = self.peek(2);
        let field = self.field_base();
        let at_field_depth = field.map_or(false, |(base, _)| self.parens.len() == base);
        let (op, len) = match c {
            0x28 => (LPAR, 1),
            0x29 => (RPAR, 1),
            0x5B => (LSQB, 1),
            0x5D => (RSQB, 1),
            0x7B => (LBRACE, 1),
            0x7D => (RBRACE, 1),
            0x2C => (COMMA, 1),
            0x3B => (SEMI, 1),
            0x7E => (TILDE, 1),
            0x3A => {
                if c1 == 0x3D && !at_field_depth {
                    (COLONEQUAL, 2)
                } else {
                    (COLON, 1)
                }
            }
            0x2B => if c1 == 0x3D { (PLUSEQUAL, 2) } else { (PLUS, 1) },
            0x2D => match c1 {
                0x3D => (MINEQUAL, 2),
                0x3E => (RARROW, 2),
                _ => (MINUS, 1),
            },
            0x2A => match (c1, c2) {
                (0x2A, 0x3D) => (DOUBLESTAREQUAL, 3),
                (0x2A, _) => (DOUBLESTAR, 2),
                (0x3D, _) => (STAREQUAL, 2),
                _ => (STAR, 1),
            },
            0x2F => match (c1, c2) {
                (0x2F, 0x3D) => (DOUBLESLASHEQUAL, 3),
                (0x2F, _) => (DOUBLESLASH, 2),
                (0x3D, _) => (SLASHEQUAL, 2),
                _ => (SLASH, 1),
            },
            0x7C => if c1 == 0x3D { (VBAREQUAL, 2) } else { (VBAR, 1) },
            0x26 => if c1 == 0x3D { (AMPEREQUAL, 2) } else { (AMPER, 1) },
            0x3C => match (c1, c2) {
                (0x3C, 0x3D) => (LEFTSHIFTEQUAL, 3),
                (0x3C, _) => (LEFTSHIFT, 2),
                (0x3D, _) => (LESSEQUAL, 2),
                (0x3E, _) => (OLDNOTEQUAL, 2),
                _ => (LESS, 1),
            },
            0x3E => match (c1, c2) {
                (0x3E, 0x3D) => (RIGHTSHIFTEQUAL, 3),
                (0x3E, _) => (RIGHTSHIFT, 2),
                (0x3D, _) => (GREATEREQUAL, 2),
                _ => (GREATER, 1),
            },
            0x3D => if c1 == 0x3D { (EQEQUAL, 2) } else { (EQUAL, 1) },
            0x2E => {
                if c1 == 0x2E && c2 == 0x2E {
                    (ELLIPSIS, 3)
                } else {
                    (DOT, 1)
                }
            }
            0x25 => if c1 == 0x3D { (PERCENTEQUAL, 2) } else { (PERCENT, 1) },
            0x5E => if c1 == 0x3D { (CIRCUMFLEXEQUAL, 2) } else { (CIRCUMFLEX, 1) },
            0x40 => if c1 == 0x3D { (ATEQUAL, 2) } else { (AT, 1) },
            0x21 => if c1 == 0x3D { (NOTEQUAL, 2) } else { (EXCLAMATION, 1) },
            0x24 | 0x3F | 0x60 => (UNKNOWN, 1),
            _ => {
                let ch = char::from_u32(c).unwrap_or('?');
                let why = if c < 0x20 || c == 0x7F {
                    format!("invalid non-printable character U+{:04X}", c)
                } else {
                    format!("invalid character '{}' (U+{:04X})", ch, c)
                };
                return self.err(start, &why);
            }
        };
        match op {
            LPAR | LSQB | LBRACE => self.open_bracket(c, start)?,
            RPAR | RSQB => {
                if at_field_depth {
                    let ch = char::from_u32(c).unwrap_or(')');
                    return self.err(start, &format!("f-string: unmatched '{}'", ch));
                }
                self.close_bracket(c, start)?
            }
            RBRACE => {
                if at_field_depth {
                    // the end of the replacement field
                    self.parens.pop();
                    self.frames.pop();
                    self.i = start + 1;
                    self.push(T::Op, RBRACE, start, start + 1, 0);
                    return Ok(());
                }
                self.close_bracket(c, start)?
            }
            COLON if at_field_depth => {
                // the format specifier
                let fs = field.map_or(0, |(_, fs)| fs);
                let open = self.frames[fs..].iter().filter(|f| matches!(f, Frame::Spec { .. })).count();
                if open >= MAX_SPECS {
                    return self.err(start, "f-string: expressions nested too deeply");
                }
                self.i = start + 1;
                self.push(T::Op, COLON, start, start + 1, 0);
                self.frames.push(Frame::Spec { fs });
                return Ok(());
            }
            _ => {}
        }
        self.i = start + len;
        self.push(T::Op, op, start, start + len, 0);
        Ok(())
    }

    /// After a number: what may follow it (Python allows the keywords `and`,
    /// `else`, `for`, `if`, `in`, `is`, `not`, `or` right after it, with a
    /// warning; any other identifier character is an error).
    fn end_of_number(&mut self, kind: &str) -> Result<(), LexError> {
        let c = self.peek(0);
        if c >= 0x80 || !ident_char(c) {
            return Ok(());
        }
        let rest = |k: usize, w: &str| -> bool {
            let n = w.len();
            let after = self.peek(k + n);
            w.bytes().enumerate().all(|(j, b)| self.peek(k + j) == b as u32) && (after == u32::MAX || !ident_char(after))
        };
        let fine = match c {
            0x61 => rest(1, "nd"),
            0x65 => rest(1, "lse"),
            0x66 => rest(1, "or"),
            0x69 => matches!(self.peek(1), 0x66 | 0x6E | 0x73),
            0x6F => rest(1, "r"),
            0x6E => rest(1, "ot"),
            _ => false,
        };
        if fine {
            Ok(())
        } else {
            self.err(self.i, &format!("invalid {} literal", kind))
        }
    }

    /// Digits with single underscores between them (at least one digit).
    fn digits(&mut self, ok: fn(u32) -> bool) -> bool {
        if !ok(self.peek(0)) {
            return false;
        }
        loop {
            while ok(self.peek(0)) {
                self.i += 1;
            }
            if self.peek(0) == 0x5F && ok(self.peek(1)) {
                self.i += 1;
                continue;
            }
            return true;
        }
    }

    fn number(&mut self, start: usize) -> Result<(), LexError> {
        let c = self.peek(0);
        if c == 0x30 {
            let x = self.peek(1) | 0x20;
            if x == 0x78 || x == 0x6F || x == 0x62 {
                // 0x… 0o… 0b…
                self.i += 2;
                let (ok, kind): (fn(u32) -> bool, &str) = match x {
                    0x78 => (is_hex, "hexadecimal"),
                    0x6F => (|c| (0x30..=0x37).contains(&c), "octal"),
                    _ => (|c| c == 0x30 || c == 0x31, "binary"),
                };
                if self.peek(0) == 0x5F {
                    self.i += 1;
                }
                if !self.digits(ok) {
                    if is_digit(self.peek(0)) && x != 0x78 {
                        let d = char::from_u32(self.peek(0)).unwrap_or('?');
                        return self.err(self.i, &format!("invalid digit '{}' in {} literal", d, kind));
                    }
                    return self.err(self.i, &format!("invalid {} literal", kind));
                }
                if self.peek(0) == 0x5F {
                    return self.err(self.i, &format!("invalid {} literal", kind));
                }
                if x != 0x78 && is_digit(self.peek(0)) {
                    let d = char::from_u32(self.peek(0)).unwrap_or('?');
                    return self.err(self.i, &format!("invalid digit '{}' in {} literal", d, kind));
                }
                self.end_of_number(kind)?;
                self.push(T::Number, 0, start, self.i, 0);
                return Ok(());
            }
            // 0, 00, 0_0 …; then maybe a float or an imaginary number
            let mut nonzero = false;
            self.i += 1;
            loop {
                if self.peek(0) == 0x5F {
                    if !is_digit(self.peek(1)) {
                        self.i += 1;
                        return self.err(self.i, "invalid decimal literal");
                    }
                    self.i += 1;
                }
                if self.peek(0) != 0x30 {
                    break;
                }
                self.i += 1;
            }
            if is_digit(self.peek(0)) {
                nonzero = true;
                self.digits(is_digit);
                if self.peek(0) == 0x5F {
                    return self.err(self.i, "invalid decimal literal");
                }
            }
            match self.peek(0) {
                0x2E => {
                    self.i += 1;
                    return self.fraction(start);
                }
                0x65 | 0x45 => return self.exponent(start),
                0x6A | 0x4A => {
                    self.i += 1;
                    self.end_of_number("imaginary")?;
                    self.push(T::Number, 0, start, self.i, 0);
                    return Ok(());
                }
                _ => {}
            }
            if nonzero {
                return self.err(
                    start,
                    "leading zeros in decimal integer literals are not permitted; use an 0o prefix for octal integers",
                );
            }
            self.end_of_number("decimal")?;
            self.push(T::Number, 0, start, self.i, 0);
            return Ok(());
        }
        if c == 0x2E {
            // .5
            self.i += 1;
            return self.fraction(start);
        }
        self.digits(is_digit);
        if self.peek(0) == 0x5F {
            return self.err(self.i, "invalid decimal literal");
        }
        match self.peek(0) {
            0x2E => {
                self.i += 1;
                self.fraction(start)
            }
            0x65 | 0x45 => self.exponent(start),
            0x6A | 0x4A => {
                self.i += 1;
                self.end_of_number("imaginary")?;
                self.push(T::Number, 0, start, self.i, 0);
                Ok(())
            }
            _ => {
                self.end_of_number("decimal")?;
                self.push(T::Number, 0, start, self.i, 0);
                Ok(())
            }
        }
    }

    /// After the point of a float.
    fn fraction(&mut self, start: usize) -> Result<(), LexError> {
        if is_digit(self.peek(0)) {
            self.digits(is_digit);
            if self.peek(0) == 0x5F {
                return self.err(self.i, "invalid decimal literal");
            }
        }
        match self.peek(0) {
            0x65 | 0x45 => self.exponent(start),
            0x6A | 0x4A => {
                self.i += 1;
                self.end_of_number("imaginary")?;
                self.push(T::Number, 0, start, self.i, 0);
                Ok(())
            }
            _ => {
                self.end_of_number("decimal")?;
                self.push(T::Number, 0, start, self.i, 0);
                Ok(())
            }
        }
    }

    /// At the `e` of a float's exponent (or of a keyword after a number).
    fn exponent(&mut self, start: usize) -> Result<(), LexError> {
        let e = self.i;
        let mut k = 1;
        if matches!(self.peek(1), 0x2B | 0x2D) {
            if !is_digit(self.peek(2)) {
                return self.err(self.i, "invalid decimal literal");
            }
            k = 2;
        } else if !is_digit(self.peek(1)) {
            // not an exponent: the number ends before the `e` (`1else`)
            self.end_of_number("decimal")?;
            self.i = e;
            self.push(T::Number, 0, start, e, 0);
            return Ok(());
        }
        self.i += k;
        self.digits(is_digit);
        if self.peek(0) == 0x5F {
            return self.err(self.i, "invalid decimal literal");
        }
        if matches!(self.peek(0), 0x6A | 0x4A) {
            self.i += 1;
            self.end_of_number("imaginary")?;
        } else {
            self.end_of_number("decimal")?;
        }
        self.push(T::Number, 0, start, self.i, 0);
        Ok(())
    }
}
