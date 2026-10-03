//! JavaScript and TypeScript (with JSX or without) read into tokens as an
//! engine reads them, without parsing.
//!
//! Each token is what jsparse's scanner takes at its place
//! (jsparse/scan.rs: strings, template text, regular expressions, numbers,
//! names, punctuators). What the parser decides from the grammar, the lexer
//! decides from what came before:
//!
//! - a `/` begins a regular expression where an expression may begin
//!   (`expr`): at the start, after a punctuator other than `)`, `]`, `}`,
//!   `.` and `?.`, after `return`, `typeof`, `case`, `else`, `do` and the
//!   other words an expression follows; after the `)` of an `if`, `for`,
//!   `while` or `with` head; after the `}` of a block (a statement may
//!   begin). After a name, a number, a string, a regular expression, a
//!   template, a `)`, a `]` or the `}` of an object literal, it divides.
//!   `++` and `--` leave it as it was. A `{` opens a block after `)`, `=>`,
//!   `;`, `{`, `}`, a block's `:` (a label, a `case`), `else`, `do`, `try`,
//!   `finally` or a name (`class A {`), and an object literal anywhere
//!   else.
//! - a template's text runs to its backtick or to `${`; the hole is code to
//!   its `}` (its braces counted, templates in it read the same way), and
//!   the text goes on from there.
//! - with JSX, a `<` where an expression may begin, before a name or `>`,
//!   opens an element (not `<T,>` or `<T extends …>`, TypeScript's generic
//!   arrows): its attributes' strings have no escapes, its children are
//!   text up to a `<` or a `{`, a `{…}` is code, elements nest; type
//!   arguments after a tag's name (`<Select<Option> …>`) are code.
//! - a hashbang `#!` at the start is a comment. Annex B's HTML-like
//!   comments (`<!--`, and `-->` where a line begins) are comments in a
//!   script and code in a module (`x <!--y` is `x < !--y`), and a `.js`
//!   file does not say which it is: they are read as code, so that nothing
//!   a module runs is taken for a comment.
//!
//! A quote not closed on its line begins a string to the line's end (an
//! error the runtime refuses the file for: read so, nothing after it on the
//! line opens a comment that would hide the lines below). A `/` that would
//! begin a regular expression not closed on its line divides, and so does
//! every later `/` on the line. Every character is in one token or a blank;
//! linear time; no input panics.

use super::{Kind, Token};
use crate::jsparse::scan::{
    ident_end, is_blank, is_digit, is_id_part, is_id_start, is_lt, jsx_name_end, number_end, punct, regex_end,
    string_end, template_end, P_ARROW, P_COLON, P_DEC, P_DOT, P_INC, P_LBRACE, P_LPAREN, P_OPTIONAL, P_RBRACE,
    P_RBRACK, P_RPAREN, P_SEMI,
};

const fn c(ch: char) -> u32 {
    ch as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Brace {
    Block,
    Object,
    /// a template's `${`
    Hole,
    /// a JSX `{`
    Jsx,
}

/// The last token that was not a comment, as the decisions need it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Last {
    None,
    /// a punctuator, by its literal id
    Punct(u32),
    /// the `}` that closed a brace of this kind
    Close(Brace),
    /// a name: a word an expression follows, one a block follows, or another
    Word(Word),
    /// a value: a string, a number, a regular expression, a template, JSX
    Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Word {
    /// `return`, `typeof` … (an expression follows)
    Before,
    /// `else`, `do`, `try`, `finally` (a block follows)
    Block,
    /// `if`, `for`, `while`, `with` (a head in parentheses follows)
    Head,
    Other,
}

fn word_of(s: &[u32]) -> Word {
    if s.len() > 10 || s.iter().any(|&x| x >= 128) {
        return Word::Other;
    }
    let w: String = s.iter().map(|&x| x as u8 as char).collect();
    match w.as_str() {
        "return" | "typeof" | "instanceof" | "in" | "of" | "new" | "delete" | "void" | "throw" | "case" | "yield"
        | "await" | "extends" | "default" => Word::Before,
        "else" | "do" | "try" | "finally" => Word::Block,
        "if" | "for" | "while" | "with" => Word::Head,
        _ => Word::Other,
    }
}

/// Where a string that `string_end` finds not closed stops: the line
/// terminator that ends it (a backslash before one continues it, as in a
/// string), or the end of the text.
fn unclosed_string_end(s: &[u32], b: usize) -> usize {
    let mut i = b + 1;
    while i < s.len() {
        let x = s[i];
        if x == c('\\') {
            i += if s.get(i + 1) == Some(&c('\r')) && s.get(i + 2) == Some(&c('\n')) { 3 } else { 2 };
            continue;
        }
        if x == 0x0A || x == 0x0D {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// An open JSX element: in its tag (reading attributes) or in its children,
/// and whether a `{…}` of it is open.
#[derive(Clone, Copy, Debug)]
struct Tag {
    children: bool,
    in_code: bool,
}

struct Lexer<'a> {
    s: &'a [u32],
    jsx: bool,
    i: usize,
    out: Vec<Token>,
    braces: Vec<Brace>,
    /// the open parentheses: true for an `if`/`for`/`while`/`with` head
    parens: Vec<bool>,
    /// may an expression begin here?
    expr: bool,
    last: Last,
    tags: Vec<Tag>,
    /// no regular expression begins before this: a `/` that would have begun
    /// one not closed on its line makes every later `/` on the line a
    /// division (each try reads to the line's end: so the lexer stays linear)
    no_regex_until: usize,
}

/// The tokens of `s` (`jsx`: elements may appear where an expression may
/// begin).
pub fn tokens(s: &[u32], jsx: bool) -> Vec<Token> {
    let mut lx = Lexer {
        s,
        jsx,
        i: 0,
        out: Vec::with_capacity(s.len() / 4 + 8),
        braces: Vec::new(),
        parens: Vec::new(),
        expr: true,
        last: Last::None,
        no_regex_until: 0,
        tags: Vec::new(),
    };
    lx.run();
    lx.out
}

impl<'a> Lexer<'a> {
    #[inline]
    fn at(&self, i: usize) -> u32 {
        self.s.get(i).copied().unwrap_or(u32::MAX)
    }

    fn push(&mut self, kind: Kind, start: usize, end: usize) {
        self.out.push(Token { kind, start: start as u32, end: end as u32 });
    }

    /// The end of the line from i (the line terminator's position).
    fn line_end(&self, mut i: usize) -> usize {
        while i < self.s.len() && !is_lt(self.s[i]) {
            i += 1;
        }
        i
    }

    fn run(&mut self) {
        let n = self.s.len();
        if n >= 2 && self.s[0] == c('#') && self.s[1] == c('!') {
            let e = self.line_end(0);
            self.push(Kind::Comment, 0, e);
            self.i = e;
        }
        while self.i < n {
            let in_jsx = matches!(self.tags.last(), Some(t) if !t.in_code);
            if in_jsx {
                self.jsx_step();
            } else {
                self.code_step();
            }
        }
    }

    // ---- code ----

    fn code_step(&mut self) {
        let s = self.s;
        let i = self.i;
        let x = s[i];
        if is_blank(x) {
            self.i += 1;
            return;
        }
        let x1 = self.at(i + 1);
        // comments
        if x == c('/') && x1 == c('/') {
            let e = self.line_end(i);
            self.push(Kind::Comment, i, e);
            self.i = e;
            return;
        }
        if x == c('/') && x1 == c('*') {
            let mut j = i + 2;
            while j < s.len() && !(s[j] == c('*') && self.at(j + 1) == c('/')) {
                j += 1;
            }
            let e = (j + 2).min(s.len());
            self.push(Kind::Comment, i, e);
            self.i = e;
            return;
        }
        // literals
        if x == c('"') || x == c('\'') {
            // (one not closed on its line: a string to the line's end)
            let e = string_end(s, i).unwrap_or_else(|| unclosed_string_end(s, i));
            self.value(Kind::Str, i, e);
            return;
        }
        if x == c('`') {
            self.template_text(i);
            return;
        }
        if x == c('/') && self.expr && i >= self.no_regex_until {
            if let Some((_close, e)) = regex_end(s, i) {
                self.value(Kind::Regex, i, e);
                return;
            }
            self.no_regex_until = self.line_end(i);
        }
        if is_digit(x) || (x == c('.') && is_digit(x1)) {
            let e = number_end(s, i);
            self.value(Kind::Num, i, e);
            return;
        }
        if x == c('#') && (is_id_start(x1) || x1 == c('\\')) {
            if let Some((e, _)) = ident_end(s, i + 1) {
                self.push(Kind::Name, i, e);
                self.i = e;
                self.expr = false;
                self.last = Last::Word(Word::Other);
                return;
            }
        }
        if let Some((e, _)) = ident_end(s, i) {
            let w = word_of(&s[i..e]);
            self.push(Kind::Name, i, e);
            self.i = e;
            // (after `else` and `do` a statement, so an expression, may begin)
            self.expr = matches!(w, Word::Before | Word::Block);
            self.last = Last::Word(w);
            return;
        }
        if self.jsx && x == c('<') && self.expr && self.jsx_opens(i) {
            self.open_tag(i);
            return;
        }
        match punct(s, i) {
            Some((id, len)) => self.punctuator(id, i, i + len),
            None => {
                self.push(Kind::Other, i, i + 1);
                self.i = i + 1;
                self.expr = true;
                self.last = Last::Punct(u32::MAX);
            }
        }
    }

    /// A string, number, regular expression: a value.
    fn value(&mut self, kind: Kind, a: usize, e: usize) {
        self.push(kind, a, e);
        self.i = e;
        self.expr = false;
        self.last = Last::Value;
    }

    /// A template's text from `a` (its backtick, or the `}` of a hole).
    fn template_text(&mut self, a: usize) {
        let s = self.s;
        let j = template_end(s, a + 1);
        if j < s.len() && s[j] == c('`') {
            self.value(Kind::Template, a, j + 1);
        } else if j + 1 < s.len() && s[j] == c('$') && s[j + 1] == c('{') {
            self.push(Kind::Template, a, j + 2);
            self.i = j + 2;
            self.braces.push(Brace::Hole);
            self.expr = true;
            self.last = Last::Punct(P_LBRACE);
        } else {
            // not closed: the rest of the text
            self.value(Kind::Template, a, s.len());
        }
    }

    fn punctuator(&mut self, id: u32, a: usize, e: usize) {
        if id == P_RBRACE {
            match self.braces.pop() {
                Some(Brace::Hole) => {
                    self.template_text(a);
                    return;
                }
                Some(Brace::Jsx) => {
                    self.push(Kind::Punct, a, e);
                    self.i = e;
                    if let Some(t) = self.tags.last_mut() {
                        t.in_code = false;
                    }
                    self.last = Last::Value;
                    return;
                }
                Some(b) => {
                    self.push(Kind::Punct, a, e);
                    self.i = e;
                    self.expr = b == Brace::Block;
                    self.last = Last::Close(b);
                    return;
                }
                None => {
                    self.push(Kind::Punct, a, e);
                    self.i = e;
                    self.expr = true;
                    self.last = Last::Close(Brace::Block);
                    return;
                }
            }
        }
        self.push(Kind::Punct, a, e);
        self.i = e;
        if id == P_LBRACE {
            let block = match self.last {
                Last::None | Last::Close(Brace::Block) => true,
                Last::Close(_) => false,
                Last::Punct(p) => {
                    p == P_RPAREN
                        || p == P_ARROW
                        || p == P_SEMI
                        || p == P_LBRACE
                        || (p == P_COLON && !matches!(self.braces.last(), Some(Brace::Object)))
                }
                Last::Word(w) => w != Word::Before,
                Last::Value => false,
            };
            self.braces.push(if block { Brace::Block } else { Brace::Object });
            self.expr = true;
        } else if id == P_LPAREN {
            self.parens.push(self.last == Last::Word(Word::Head));
            self.expr = true;
        } else if id == P_RPAREN {
            self.expr = self.parens.pop().unwrap_or(false);
        } else if id == P_RBRACK || id == P_DOT || id == P_OPTIONAL {
            // (`.` and `?.` are followed by a name, `(` or `[`: never by a
            // regular expression or an element)
            self.expr = false;
        } else if id == P_INC || id == P_DEC {
            // (postfix after a value, prefix before one: `expr` stays)
        } else {
            self.expr = true;
        }
        self.last = Last::Punct(id);
    }

    // ---- JSX ----

    /// Does the `<` at i open an element? A name or `>` follows; not
    /// TypeScript's `<T,>` or `<T extends …>`.
    fn jsx_opens(&self, i: usize) -> bool {
        let x1 = self.at(i + 1);
        if x1 == c('>') {
            return true;
        }
        let e = match jsx_name_end(self.s, i + 1) {
            Some(e) => e,
            None => return false,
        };
        let mut j = e;
        while j < self.s.len() && is_blank(self.s[j]) {
            j += 1;
        }
        if self.at(j) == c(',') {
            return false;
        }
        let ext: Vec<u32> = "extends".chars().map(|ch| ch as u32).collect();
        !(self.s.len() >= j + 7 && self.s[j..j + 7] == ext[..] && !is_id_part(self.at(j + 7)))
    }

    /// `<` and the tag's name; the element is open, reading its attributes.
    fn open_tag(&mut self, i: usize) {
        self.push(Kind::Punct, i, i + 1);
        self.i = i + 1;
        self.tag_name();
        self.type_arguments();
        self.tags.push(Tag { children: false, in_code: false });
    }

    /// TypeScript's type arguments right after a tag's name
    /// (`<Select<Option> …>`): code up to the `>` that closes them, `=>`
    /// not one; a quote's string is to its quote on the same line.
    fn type_arguments(&mut self) {
        let s = self.s;
        if self.at(self.i) != c('<') {
            return;
        }
        let mut depth = 0usize;
        let mut j = self.i;
        while j < s.len() {
            let x = s[j];
            if is_blank(x) {
                j += 1;
                continue;
            }
            if x == c('=') && self.at(j + 1) == c('>') {
                self.push(Kind::Punct, j, j + 2);
                j += 2;
                continue;
            }
            if x == c('<') || x == c('>') {
                self.push(Kind::Punct, j, j + 1);
                j += 1;
                if x == c('<') {
                    depth += 1;
                    continue;
                }
                depth -= 1;
                if depth == 0 {
                    break;
                }
                continue;
            }
            if x == c('"') || x == c('\'') {
                if let Some(e) = string_end(s, j) {
                    self.push(Kind::Str, j, e);
                    j = e;
                    continue;
                }
            }
            if let Some((e, _)) = ident_end(s, j) {
                self.push(Kind::Name, j, e);
                j = e;
                continue;
            }
            let kind = if is_digit(x) { Kind::Num } else { Kind::Punct };
            self.push(kind, j, j + 1);
            j += 1;
        }
        self.i = j;
    }

    /// A tag's name at self.i (`a`, `a-b`, `a:b`, `a.b.c`; none for a fragment).
    fn tag_name(&mut self) {
        let start = self.i;
        let mut j = self.i;
        while let Some(e) = jsx_name_end(self.s, j) {
            j = e;
            let sep = self.at(j);
            if (sep == c(':') || sep == c('.')) && jsx_name_end(self.s, j + 1).is_some() {
                j += 1;
                continue;
            }
            break;
        }
        if j > start {
            self.push(Kind::Name, start, j);
            self.i = j;
        }
    }

    fn jsx_step(&mut self) {
        let children = self.tags.last().map(|t| t.children).unwrap_or(false);
        if children {
            self.jsx_children();
        } else {
            self.jsx_attrs();
        }
    }

    /// The element just closed: back to its parent's children, or to code.
    fn close_element(&mut self) {
        self.tags.pop();
        if self.tags.is_empty() || matches!(self.tags.last(), Some(t) if t.in_code) {
            self.expr = false;
            self.last = Last::Value;
        }
    }

    fn jsx_attrs(&mut self) {
        let s = self.s;
        let i = self.i;
        let x = s[i];
        if is_blank(x) {
            self.i += 1;
            return;
        }
        let x1 = self.at(i + 1);
        if x == c('/') && x1 == c('/') {
            let e = self.line_end(i);
            self.push(Kind::Comment, i, e);
            self.i = e;
            return;
        }
        if x == c('/') && x1 == c('*') {
            let mut j = i + 2;
            while j < s.len() && !(s[j] == c('*') && self.at(j + 1) == c('/')) {
                j += 1;
            }
            let e = (j + 2).min(s.len());
            self.push(Kind::Comment, i, e);
            self.i = e;
            return;
        }
        if x == c('/') && x1 == c('>') {
            self.push(Kind::Punct, i, i + 2);
            self.i = i + 2;
            self.close_element();
            return;
        }
        if x == c('>') {
            self.push(Kind::Punct, i, i + 1);
            self.i = i + 1;
            if let Some(t) = self.tags.last_mut() {
                t.children = true;
            }
            return;
        }
        if x == c('{') {
            self.push(Kind::Punct, i, i + 1);
            self.i = i + 1;
            self.braces.push(Brace::Jsx);
            if let Some(t) = self.tags.last_mut() {
                t.in_code = true;
            }
            self.expr = true;
            self.last = Last::Punct(P_LBRACE);
            return;
        }
        if x == c('"') || x == c('\'') {
            let mut j = i + 1;
            while j < s.len() && s[j] != x {
                j += 1;
            }
            let e = (j + 1).min(s.len());
            self.push(Kind::JsxStr, i, e);
            self.i = e;
            return;
        }
        if x == c('<') && (x1 == c('>') || jsx_name_end(s, i + 1).is_some()) {
            // an element as an attribute's value
            self.open_tag(i);
            return;
        }
        if jsx_name_end(s, i).is_some() {
            self.tag_name();
            return;
        }
        let kind = if x == c('=') { Kind::Punct } else { Kind::Other };
        self.push(kind, i, i + 1);
        self.i = i + 1;
    }

    fn jsx_children(&mut self) {
        let s = self.s;
        let i = self.i;
        let x = s[i];
        if x == c('{') {
            self.push(Kind::Punct, i, i + 1);
            self.i = i + 1;
            self.braces.push(Brace::Jsx);
            if let Some(t) = self.tags.last_mut() {
                t.in_code = true;
            }
            self.expr = true;
            self.last = Last::Punct(P_LBRACE);
            return;
        }
        if x == c('<') {
            let x1 = self.at(i + 1);
            if x1 == c('/') {
                // a closing tag: `</`, its name, `>`
                self.push(Kind::Punct, i, i + 2);
                self.i = i + 2;
                while self.i < s.len() && is_blank(s[self.i]) {
                    self.i += 1;
                }
                self.tag_name();
                while self.i < s.len() && is_blank(s[self.i]) {
                    self.i += 1;
                }
                if self.at(self.i) == c('>') {
                    self.push(Kind::Punct, self.i, self.i + 1);
                    self.i += 1;
                }
                self.close_element();
                return;
            }
            if x1 == c('>') || jsx_name_end(s, i + 1).is_some() {
                self.open_tag(i);
                return;
            }
        }
        // text, up to a `<` or a `{` (a `<` that opens nothing is text)
        let mut j = i + 1;
        while j < s.len() && s[j] != c('<') && s[j] != c('{') {
            j += 1;
        }
        self.push(Kind::JsxText, i, j);
        self.i = j;
    }
}
