//! Go's scanner: `go/scanner`'s rules over a text of code points.
//!
//! The tokens a Go parser reads: names, the keywords, the operators, the
//! literals, and the semicolons Go inserts at the end of a line after a name,
//! a literal, `break` `continue` `fallthrough` `return`, `++` `--` `)` `]`
//! `}` (and at the end of the text). Comments are skipped; a `/* … */` that
//! holds a line break where a semicolon is due stands for the line break.
//!
//! `go/scanner` reports a malformed number, string, rune or escape as an
//! error; here the first one is kept in [`Scanner::error`] and the parser
//! refuses the file with it, as `go/parser` does.
//!
//! Linear in the text: every call to [`Scanner::scan`] consumes at least one
//! code point or reports the end.

use crate::unicode;

macro_rules! toks {
    ($($t:ident $s:literal),* $(,)?) => {
        /// A token, `go/token`'s.
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        #[repr(u8)]
        pub enum Tok { $($t),* }

        impl Tok {
            /// The token as Go writes it (`"ILLEGAL"`, `"IDENT"`… for the ones that are not text).
            pub fn name(self) -> &'static str {
                const NAMES: &[&str] = &[$($s),*];
                NAMES[self as usize]
            }
        }
    };
}

toks! {
    Illegal "ILLEGAL", Eof "EOF", Ident "IDENT", Int "INT", Float "FLOAT", Imag "IMAG", Char "CHAR", Str "STRING",
    Add "+", Sub "-", Mul "*", Quo "/", Rem "%", And "&", Or "|", Xor "^", Shl "<<", Shr ">>", AndNot "&^",
    AddAssign "+=", SubAssign "-=", MulAssign "*=", QuoAssign "/=", RemAssign "%=", AndAssign "&=", OrAssign "|=",
    XorAssign "^=", ShlAssign "<<=", ShrAssign ">>=", AndNotAssign "&^=",
    Land "&&", Lor "||", Arrow "<-", Inc "++", Dec "--", Eql "==", Lss "<", Gtr ">", Assign "=", Not "!", Tilde "~",
    Neq "!=", Leq "<=", Geq ">=", Define ":=", Ellipsis "...", Lparen "(", Lbrack "[", Lbrace "{", Comma ",",
    Period ".", Rparen ")", Rbrack "]", Rbrace "}", Semicolon ";", Colon ":",
    Break "break", Case "case", Chan "chan", Const "const", Continue "continue", Default "default", Defer "defer",
    Else "else", Fallthrough "fallthrough", For "for", Func "func", Go "go", Goto "goto", If "if", Import "import",
    Interface "interface", Map "map", Package "package", Range "range", Return "return", Select "select",
    Struct "struct", Switch "switch", Type "type", Var "var",
}

impl Tok {
    /// `go/token`'s precedence of a binary operator; 0 (`LowestPrec`) for any other token.
    pub fn precedence(self) -> u8 {
        match self {
            Tok::Lor => 1,
            Tok::Land => 2,
            Tok::Eql | Tok::Neq | Tok::Lss | Tok::Leq | Tok::Gtr | Tok::Geq => 3,
            Tok::Add | Tok::Sub | Tok::Or | Tok::Xor => 4,
            Tok::Mul | Tok::Quo | Tok::Rem | Tok::Shl | Tok::Shr | Tok::And | Tok::AndNot => 5,
            _ => 0,
        }
    }

    pub fn is_keyword(self) -> bool {
        self as u8 >= Tok::Break as u8
    }
}

/// The keyword a name is, if it is one.
pub fn keyword(name: &[u32]) -> Option<Tok> {
    if name.len() < 2 || name.len() > 11 {
        return None;
    }
    let mut buf = [0u8; 11];
    for (k, &c) in name.iter().enumerate() {
        if !(0x61..=0x7a).contains(&c) {
            return None;
        }
        buf[k] = c as u8;
    }
    Some(match &buf[..name.len()] {
        b"break" => Tok::Break,
        b"case" => Tok::Case,
        b"chan" => Tok::Chan,
        b"const" => Tok::Const,
        b"continue" => Tok::Continue,
        b"default" => Tok::Default,
        b"defer" => Tok::Defer,
        b"else" => Tok::Else,
        b"fallthrough" => Tok::Fallthrough,
        b"for" => Tok::For,
        b"func" => Tok::Func,
        b"go" => Tok::Go,
        b"goto" => Tok::Goto,
        b"if" => Tok::If,
        b"import" => Tok::Import,
        b"interface" => Tok::Interface,
        b"map" => Tok::Map,
        b"package" => Tok::Package,
        b"range" => Tok::Range,
        b"return" => Tok::Return,
        b"select" => Tok::Select,
        b"struct" => Tok::Struct,
        b"switch" => Tok::Switch,
        b"type" => Tok::Type,
        b"var" => Tok::Var,
        _ => return None,
    })
}

const BOM: u32 = 0xFEFF;

fn c(ch: char) -> u32 {
    ch as u32
}

fn lower(x: u32) -> u32 {
    x | 0x20
}

fn is_decimal(x: u32) -> bool {
    (0x30..=0x39).contains(&x)
}

fn is_hex(x: u32) -> bool {
    is_decimal(x) || (0x61..=0x66).contains(&lower(x))
}

/// `go/scanner`'s isLetter: `unicode.IsLetter` or `_`.
pub fn is_letter(x: u32) -> bool {
    if x < 0x80 {
        return x == 0x5f || (0x61..=0x7a).contains(&lower(x));
    }
    unicode::is_alpha(x)
}

/// `go/scanner`'s isDigit: `unicode.IsDigit` (the decimal digits).
pub fn is_digit(x: u32) -> bool {
    if x < 0x80 {
        return is_decimal(x);
    }
    unicode::is_decimal(x)
}

/// A token as the scanner leaves it.
#[derive(Clone, Copy, Debug)]
pub struct Token {
    pub tok: Tok,
    pub start: u32,
    pub end: u32,
    /// For a semicolon: it was inserted at a line break or at the end of the text (its `lit` is "\n" in Go).
    pub implicit: bool,
}

pub struct Scanner<'a> {
    src: &'a [u32],
    /// the offset of the next character to read (`ch` is `src[offset - 1]`... see `peek`)
    offset: usize,
    insert_semi: bool,
    /// where the semicolon owed to a `/* … */` that held a line break is
    nl_pos: Option<usize>,
    /// the first thing `go/scanner` would have reported, and where
    pub error: Option<(usize, &'static str)>,
}

impl<'a> Scanner<'a> {
    pub fn new(src: &'a [u32]) -> Scanner<'a> {
        let mut s = Scanner { src, offset: 0, insert_semi: false, nl_pos: None, error: None };
        if s.at(0) == BOM {
            s.offset = 1;
        }
        // `go/scanner` reports a NUL, and a byte order mark that is not the first character, wherever it is (in a
        // comment or a string too): found here, once, instead of in every loop that reads a character
        for (i, &ch) in src.iter().enumerate() {
            if ch == 0 {
                s.fail(i, "illegal character NUL");
                break;
            }
            if ch == BOM && i > 0 {
                s.fail(i, "illegal byte order mark");
                break;
            }
        }
        s
    }

    /// The character at `i`, or `u32::MAX` past the end (a value no character has).
    fn at(&self, i: usize) -> u32 {
        if i < self.src.len() {
            self.src[i]
        } else {
            u32::MAX
        }
    }

    fn ch(&self) -> u32 {
        self.at(self.offset)
    }

    fn fail(&mut self, at: usize, msg: &'static str) {
        if self.error.is_none() {
            self.error = Some((at, msg));
        }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The next token. After the end it gives `Eof` for ever.
    pub fn scan(&mut self) -> Token {
        loop {
            if let Some(p) = self.nl_pos.take() {
                return Token { tok: Tok::Semicolon, start: p as u32, end: p as u32, implicit: true };
            }
            // white space
            loop {
                let ch = self.ch();
                if ch == c(' ') || ch == c('\t') || ch == c('\r') || (ch == c('\n') && !self.insert_semi) {
                    self.offset += 1;
                } else {
                    break;
                }
            }
            let start = self.offset;
            let ch = self.ch();
            let mut insert_semi = false;
            let tok;
            if is_letter(ch) {
                let mut e = start + 1;
                while e < self.src.len() && (is_letter(self.src[e]) || is_digit(self.src[e])) {
                    e += 1;
                }
                self.offset = e;
                let kw = keyword(&self.src[start..e]);
                tok = kw.unwrap_or(Tok::Ident);
                insert_semi = matches!(tok, Tok::Ident | Tok::Break | Tok::Continue | Tok::Fallthrough | Tok::Return);
            } else if is_decimal(ch) || (ch == c('.') && is_decimal(self.at(start + 1))) {
                insert_semi = true;
                tok = self.number();
            } else {
                if ch == u32::MAX {
                    if self.insert_semi {
                        self.insert_semi = false;
                        return Token { tok: Tok::Semicolon, start: start as u32, end: start as u32, implicit: true };
                    }
                    return Token { tok: Tok::Eof, start: start as u32, end: start as u32, implicit: false };
                }
                self.offset += 1;
                if ch == c('\n') {
                    // only here if insert_semi was set
                    self.insert_semi = false;
                    return Token { tok: Tok::Semicolon, start: start as u32, end: start as u32 + 1, implicit: true };
                }
                let n = self.ch();
                fn sw2(s: &mut Scanner, a: Tok, b: Tok) -> Tok {
                    if s.ch() == c('=') {
                        s.offset += 1;
                        b
                    } else {
                        a
                    }
                }
                tok = match char::from_u32(ch).unwrap_or('\u{fffd}') {
                    '"' => {
                        insert_semi = true;
                        self.string();
                        Tok::Str
                    }
                    '\'' => {
                        insert_semi = true;
                        self.rune();
                        Tok::Char
                    }
                    '`' => {
                        insert_semi = true;
                        self.raw_string();
                        Tok::Str
                    }
                    ':' => sw2(self, Tok::Colon, Tok::Define),
                    '.' => {
                        if n == c('.') && self.at(self.offset + 1) == c('.') {
                            self.offset += 2;
                            Tok::Ellipsis
                        } else {
                            Tok::Period
                        }
                    }
                    ',' => Tok::Comma,
                    ';' => Tok::Semicolon,
                    '(' => Tok::Lparen,
                    ')' => {
                        insert_semi = true;
                        Tok::Rparen
                    }
                    '[' => Tok::Lbrack,
                    ']' => {
                        insert_semi = true;
                        Tok::Rbrack
                    }
                    '{' => Tok::Lbrace,
                    '}' => {
                        insert_semi = true;
                        Tok::Rbrace
                    }
                    '+' => {
                        if n == c('+') {
                            self.offset += 1;
                            insert_semi = true;
                            Tok::Inc
                        } else {
                            sw2(self, Tok::Add, Tok::AddAssign)
                        }
                    }
                    '-' => {
                        if n == c('-') {
                            self.offset += 1;
                            insert_semi = true;
                            Tok::Dec
                        } else {
                            sw2(self, Tok::Sub, Tok::SubAssign)
                        }
                    }
                    '*' => sw2(self, Tok::Mul, Tok::MulAssign),
                    '/' => {
                        if n == c('/') || n == c('*') {
                            self.comment(start); // (a semicolon owed to it comes first on the next turn)
                            continue;
                        }
                        sw2(self, Tok::Quo, Tok::QuoAssign)
                    }
                    '%' => sw2(self, Tok::Rem, Tok::RemAssign),
                    '^' => sw2(self, Tok::Xor, Tok::XorAssign),
                    '<' => {
                        if n == c('-') {
                            self.offset += 1;
                            Tok::Arrow
                        } else if n == c('<') {
                            self.offset += 1;
                            sw2(self, Tok::Shl, Tok::ShlAssign)
                        } else {
                            sw2(self, Tok::Lss, Tok::Leq)
                        }
                    }
                    '>' => {
                        if n == c('>') {
                            self.offset += 1;
                            sw2(self, Tok::Shr, Tok::ShrAssign)
                        } else {
                            sw2(self, Tok::Gtr, Tok::Geq)
                        }
                    }
                    '=' => sw2(self, Tok::Assign, Tok::Eql),
                    '!' => sw2(self, Tok::Not, Tok::Neq),
                    '&' => {
                        if n == c('^') {
                            self.offset += 1;
                            sw2(self, Tok::AndNot, Tok::AndNotAssign)
                        } else if n == c('&') {
                            self.offset += 1;
                            Tok::Land
                        } else {
                            sw2(self, Tok::And, Tok::AndAssign)
                        }
                    }
                    '|' => {
                        if n == c('|') {
                            self.offset += 1;
                            Tok::Lor
                        } else {
                            sw2(self, Tok::Or, Tok::OrAssign)
                        }
                    }
                    '~' => Tok::Tilde,
                    _ => {
                        if ch != BOM {
                            self.fail(start, "illegal character");
                        } else {
                            self.fail(start, "illegal byte order mark");
                        }
                        insert_semi = self.insert_semi;
                        Tok::Illegal
                    }
                };
            }
            self.insert_semi = insert_semi;
            let implicit = false;
            return Token { tok, start: start as u32, end: self.offset as u32, implicit };
        }
    }

    /// A comment at `start` (the `/` is consumed). When a semicolon is owed to a line break inside it, `nl_pos` is set.
    fn comment(&mut self, start: usize) {
        let general = self.ch() == c('*');
        self.offset += 1;
        let mut nl = 0usize;
        if !general {
            while self.offset < self.src.len() && self.src[self.offset] != c('\n') {
                self.offset += 1;
            }
            // (a `//line` directive counts only at the start of a line)
            if start == 0 || self.src[start - 1] == c('\n') {
                self.directive(start, self.offset);
            }
            return;
        }
        loop {
            let ch = self.ch();
            if ch == u32::MAX {
                self.fail(start, "comment not terminated");
                break;
            }
            if ch == c('\n') && nl == 0 {
                nl = self.offset;
            }
            self.offset += 1;
            if ch == c('*') && self.ch() == c('/') {
                self.offset += 1;
                self.directive(start, self.offset);
                break;
            }
        }
        if self.insert_semi && nl != 0 {
            self.nl_pos = Some(nl);
            self.insert_semi = false;
        }
    }

    /// A comment `src[start..end]` that is a line directive (`//line file:line` or `/*line file:line:col*/`) with a
    /// number `go/scanner` refuses (a line or a column that is 0 or above 2^30, or text after the last `:` that is no
    /// number) is an error; the rest of what a directive says changes nothing the parser sees.
    fn directive(&mut self, start: usize, end: usize) {
        let mut lit = &self.src[start..end];
        let line = |s: &str| -> Vec<u32> { s.chars().map(|ch| ch as u32).collect() };
        if lit.len() >= 2 && lit[1] == c('/') && lit[lit.len() - 1] == c('\r') {
            lit = &lit[..lit.len() - 1]; // (a \r\n line end is no part of the comment)
        }
        if lit.len() < 7 || lit[2..7] != line("line ")[..] {
            return;
        }
        let mut text = lit;
        if lit[1] == c('*') {
            text = &text[..text.len() - 2];
        }
        let text = &text[7..];
        // trailingDigits: the text after the last `:` as a number
        fn trailing(text: &[u32]) -> (usize, i64, bool) {
            let Some(i) = text.iter().rposition(|&ch| ch == ':' as u32) else { return (0, 0, false) };
            let digits = &text[i + 1..];
            let mut n: u64 = 0;
            let mut ok = !digits.is_empty();
            for &d in digits {
                if !(0x30..=0x39).contains(&d) {
                    ok = false;
                    break;
                }
                match n.checked_mul(10).and_then(|n| n.checked_add((d - 0x30) as u64)) {
                    Some(v) => n = v,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            (i + 1, if ok { n as i64 } else { 0 }, ok)
        }
        const MAX_LINE_COL: i64 = 1 << 30;
        let (i, n, ok) = trailing(text);
        if i == 0 {
            return; // no `:`: not a line directive
        }
        if !ok {
            self.fail(start, "invalid line number");
            return;
        }
        let (_, n2, ok2) = trailing(&text[..i - 1]);
        let line_no = if ok2 {
            // file:line:col
            if n == 0 || n > MAX_LINE_COL {
                self.fail(start, "invalid column number");
                return;
            }
            n2
        } else {
            n
        };
        if line_no == 0 || line_no > MAX_LINE_COL {
            self.fail(start, "invalid line number");
        }
    }

    fn digits(&mut self, base: u32, invalid: &mut Option<usize>) -> u8 {
        let mut digsep = 0u8;
        if base <= 10 {
            let max = c('0') + base;
            while is_decimal(self.ch()) || self.ch() == c('_') {
                let mut ds = 1;
                if self.ch() == c('_') {
                    ds = 2;
                } else if self.ch() >= max && invalid.is_none() {
                    *invalid = Some(self.offset);
                }
                digsep |= ds;
                self.offset += 1;
            }
        } else {
            while is_hex(self.ch()) || self.ch() == c('_') {
                digsep |= if self.ch() == c('_') { 2 } else { 1 };
                self.offset += 1;
            }
        }
        digsep
    }

    fn number(&mut self) -> Tok {
        let offs = self.offset;
        let mut tok = Tok::Illegal;
        let mut base = 10u32;
        let mut prefix = 0u32; // 0 (decimal), '0' (0-octal), 'x', 'o' or 'b'
        let mut digsep = 0u8;
        let mut invalid: Option<usize> = None;
        if self.ch() != c('.') {
            tok = Tok::Int;
            if self.ch() == c('0') {
                self.offset += 1;
                match lower(self.ch()) {
                    x if x == c('x') => {
                        self.offset += 1;
                        base = 16;
                        prefix = c('x');
                    }
                    x if x == c('o') => {
                        self.offset += 1;
                        base = 8;
                        prefix = c('o');
                    }
                    x if x == c('b') => {
                        self.offset += 1;
                        base = 2;
                        prefix = c('b');
                    }
                    _ => {
                        base = 8;
                        prefix = c('0');
                        digsep = 1; // leading 0
                    }
                }
            }
            digsep |= self.digits(base, &mut invalid);
        }
        if self.ch() == c('.') {
            tok = Tok::Float;
            if prefix == c('o') || prefix == c('b') {
                self.fail(self.offset, "invalid radix point");
            }
            self.offset += 1;
            digsep |= self.digits(base, &mut invalid);
        }
        if digsep & 1 == 0 {
            self.fail(self.offset, "literal has no digits");
        }
        let e = lower(self.ch());
        if e == c('e') || e == c('p') {
            if e == c('e') && prefix != 0 && prefix != c('0') {
                self.fail(self.offset, "exponent requires decimal mantissa");
            } else if e == c('p') && prefix != c('x') {
                self.fail(self.offset, "exponent requires hexadecimal mantissa");
            }
            self.offset += 1;
            tok = Tok::Float;
            if self.ch() == c('+') || self.ch() == c('-') {
                self.offset += 1;
            }
            let mut none = None;
            let ds = self.digits(10, &mut none);
            digsep |= ds;
            if ds & 1 == 0 {
                self.fail(self.offset, "exponent has no digits");
            }
        } else if prefix == c('x') && tok == Tok::Float {
            self.fail(self.offset, "hexadecimal mantissa requires a 'p' exponent");
        }
        if self.ch() == c('i') {
            tok = Tok::Imag;
            self.offset += 1;
        }
        if tok == Tok::Int {
            if let Some(at) = invalid {
                self.fail(at, "invalid digit in literal");
            }
        }
        if digsep & 2 != 0 {
            if let Some(i) = invalid_sep(&self.src[offs..self.offset]) {
                self.fail(offs + i, "'_' must separate successive digits");
            }
        }
        tok
    }

    /// `\` consumed; `quote` is the quote of the literal.
    fn escape(&mut self, quote: u32) -> bool {
        let offs = self.offset;
        let (n, base, max): (u32, u32, u32);
        let ch = self.ch();
        if matches!(char::from_u32(ch), Some('a' | 'b' | 'f' | 'n' | 'r' | 't' | 'v' | '\\')) || ch == quote {
            self.offset += 1;
            return true;
        }
        match char::from_u32(ch) {
            Some('0'..='7') => {
                n = 3;
                base = 8;
                max = 255;
            }
            Some('x') => {
                self.offset += 1;
                n = 2;
                base = 16;
                max = 255;
            }
            Some('u') => {
                self.offset += 1;
                n = 4;
                base = 16;
                max = 0x10FFFF;
            }
            Some('U') => {
                self.offset += 1;
                n = 8;
                base = 16;
                max = 0x10FFFF;
            }
            _ => {
                self.fail(offs, if ch == u32::MAX { "escape sequence not terminated" } else { "unknown escape sequence" });
                return false;
            }
        }
        let mut x: u64 = 0;
        for _ in 0..n {
            let d = digit_val(self.ch());
            if d >= base {
                let msg = if self.ch() == u32::MAX { "escape sequence not terminated" } else { "illegal character in escape sequence" };
                self.fail(self.offset, msg);
                return false;
            }
            x = x * base as u64 + d as u64;
            self.offset += 1;
        }
        if x > max as u64 || (0xD800..0xE000).contains(&x) {
            self.fail(offs, "escape sequence is invalid Unicode code point");
            return false;
        }
        true
    }

    /// `"` consumed.
    fn string(&mut self) {
        let offs = self.offset - 1;
        loop {
            let ch = self.ch();
            if ch == c('\n') || ch == u32::MAX {
                self.fail(offs, "string literal not terminated");
                break;
            }
            self.offset += 1;
            if ch == c('"') {
                break;
            }
            if ch == c('\\') {
                self.escape(c('"'));
            }
        }
    }

    /// `'` consumed.
    fn rune(&mut self) {
        let offs = self.offset - 1;
        let mut valid = true;
        let mut n = 0u32;
        loop {
            let ch = self.ch();
            if ch == c('\n') || ch == u32::MAX {
                if valid {
                    self.fail(offs, "rune literal not terminated");
                }
                valid = false;
                break;
            }
            self.offset += 1;
            if ch == c('\'') {
                break;
            }
            n += 1;
            if ch == c('\\') && !self.escape(c('\'')) {
                valid = false;
            }
        }
        if valid && n != 1 {
            self.fail(offs, "illegal rune literal");
        }
    }

    /// `` ` `` consumed.
    fn raw_string(&mut self) {
        let offs = self.offset - 1;
        loop {
            let ch = self.ch();
            if ch == u32::MAX {
                self.fail(offs, "raw string literal not terminated");
                break;
            }
            self.offset += 1;
            if ch == c('`') {
                break;
            }
        }
    }
}

fn digit_val(ch: u32) -> u32 {
    match char::from_u32(ch) {
        Some(d @ '0'..='9') => d as u32 - '0' as u32,
        Some(d @ 'a'..='f') => d as u32 - 'a' as u32 + 10,
        Some(d @ 'A'..='F') => d as u32 - 'A' as u32 + 10,
        _ => 16, // larger than any legal digit val
    }
}

/// `go/scanner`'s invalidSep: the index of the first misplaced `_` in a number, if any.
fn invalid_sep(x: &[u32]) -> Option<usize> {
    let mut x1 = c(' ');
    let mut d = c('.');
    let mut i = 0usize;
    if x.len() >= 2 && x[0] == c('0') {
        x1 = lower(x[1]);
        if x1 == c('x') || x1 == c('o') || x1 == c('b') {
            d = c('0');
            i = 2;
        }
    }
    while i < x.len() {
        let p = d;
        d = x[i];
        if d == c('_') {
            if p != c('0') {
                return Some(i);
            }
        } else if is_decimal(d) || (x1 == c('x') && is_hex(d)) {
            d = c('0');
        } else {
            if p == c('_') {
                return Some(i - 1);
            }
            d = c('.');
        }
        i += 1;
    }
    if d == c('_') {
        return Some(x.len() - 1);
    }
    None
}
