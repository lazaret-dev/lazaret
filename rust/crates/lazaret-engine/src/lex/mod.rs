//! Lexers for the detectors: a text read once into its language's tokens
//! (phase 2 of the Rust-first refactor, docs/RUST_ENGINE.md §8).
//!
//! The detectors found string literals and comments with scanners of their
//! own, each pairing quotes its own way (`signs::literal_spans`, the comment
//! lexer's two readings, `scanfile`'s blanked strings …): a template literal
//! nested in another's `${…}`, a quote in a regular expression, threw them
//! off for the rest of the text, and a template's holes, which are code,
//! were read as text. Here a text is read the way its runtime reads it:
//!
//! - [`js`]: JavaScript and TypeScript, with JSX or without: the tokens of
//!   jsparse's scanner, a regular expression told from a division by what
//!   comes before it, templates and their holes nested to any depth, a
//!   hashbang (Annex B's HTML-like comments, code in a module, are code);
//! - [`go`] and [`rs`]: Go and Rust (0.1.9), read as their specifications
//!   read them: raw strings, nested block comments, runes and characters,
//!   lifetimes told from characters;
//! - [`py`]: Python 3.13's tokenizer (pyparse's), f-strings in pieces
//!   (PEP 701), t-strings as 3.14 reads them, and after a token it refuses
//!   the rest read plainly, as Python 3.11 reads strings and comments.
//!
//! [`Structure`] is what the detectors ask of a text: its comments, its
//! literals (the text a program holds as data: strings, regular
//! expressions, a template's or an f-string's text, JSX text) and the code
//! in a template's or an f-string's holes.

pub mod go;
pub mod js;
pub mod py;
pub mod rs;
pub mod value;

/// A token's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// a comment, whole: `// …`, `/* … */`, a hashbang `#! …` (JS);
    /// `# …` (Python)
    Comment,
    /// a string literal, its quotes (and Python's prefix) included
    Str,
    /// a template's text: from its backtick, or the `}` that closes a hole,
    /// to the `${` that opens the next hole, or its closing backtick (both
    /// included); an f-string's text (FSTRING_START, FSTRING_MIDDLE and
    /// FSTRING_END in Python)
    Template,
    /// a regular expression literal: `/body/flags`
    Regex,
    /// JSX text between tags
    JsxText,
    /// a JSX attribute's string (no escapes in it)
    JsxStr,
    /// a name or a keyword
    Name,
    Num,
    Punct,
    /// a character no rule takes
    Other,
}

impl Kind {
    /// Its name in the `lex.tokens` call's answer.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Comment => "comment",
            Kind::Str => "str",
            Kind::Template => "template",
            Kind::Regex => "regex",
            Kind::JsxText => "jsx_text",
            Kind::JsxStr => "jsx_str",
            Kind::Name => "name",
            Kind::Num => "num",
            Kind::Punct => "punct",
            Kind::Other => "other",
        }
    }
}

/// A token: its kind and where it is (code-point offsets, half open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Token {
    pub kind: Kind,
    pub start: u32,
    pub end: u32,
}

impl Token {
    pub fn span(&self) -> (usize, usize) {
        (self.start as usize, self.end as usize)
    }
}

/// What the detectors ask of a text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Structure {
    /// every comment
    pub comments: Vec<(usize, usize)>,
    /// the string literals (quotes included; a JSX attribute's string too)
    pub strings: Vec<(usize, usize)>,
    /// every literal: strings, regular expressions, a template's or an
    /// f-string's text pieces (its holes left out), JSX text
    pub literals: Vec<(usize, usize)>,
}

impl Structure {
    /// From tokens, in order.
    pub fn of(tokens: &[Token]) -> Structure {
        let mut st = Structure::default();
        for t in tokens {
            let span = t.span();
            match t.kind {
                Kind::Comment => st.comments.push(span),
                Kind::Str | Kind::JsxStr => {
                    st.strings.push(span);
                    st.literals.push(span);
                }
                Kind::Template | Kind::Regex | Kind::JsxText => st.literals.push(span),
                _ => {}
            }
        }
        st
    }

    /// The spans two readings of a text agree on (each list sorted): what a
    /// reading cannot be sure of is left out.
    pub fn intersect(&self, other: &Structure) -> Structure {
        Structure {
            comments: intersect(&self.comments, &other.comments),
            strings: intersect(&self.strings, &other.strings),
            literals: intersect(&self.literals, &other.literals),
        }
    }
}

/// The overlaps of two sorted lists of disjoint spans.
pub fn intersect(a: &[(usize, usize)], b: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        let s = a[i].0.max(b[j].0);
        let e = a[i].1.min(b[j].1);
        if s < e {
            out.push((s, e));
        }
        if a[i].1 < b[j].1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Is `pos` inside one of the sorted, disjoint `spans`?
pub fn within(spans: &[(usize, usize)], pos: usize) -> bool {
    let k = spans.partition_point(|&(s, _)| s <= pos);
    k > 0 && pos < spans[k - 1].1
}

/// The structure of `text` in `lang` ("js" or "py"); None for another
/// language. Where two runtimes would read a text differently, what both
/// readings agree on is kept, so that what one of them runs is never taken
/// for a comment or a literal:
///
/// - a JavaScript file that may hold JSX (`jsx`) is read with JSX and
///   without;
/// - Python is read as 3.12 and later read it (f-strings in pieces, their
///   holes code, PEP 701; t-strings as 3.14 reads them, PEP 750) and as
///   3.11 and earlier did (an f-string a string to its first closing quote:
///   [`py::fallback`]; a `t` before a quote, a name, as 3.13 reads it, its
///   string the same).
pub fn structure(text: &[u32], lang: &str, jsx: bool) -> Option<Structure> {
    match lang {
        "js" => {
            let plain = Structure::of(&js::tokens(text, false));
            if !jsx {
                return Some(plain);
            }
            Some(plain.intersect(&Structure::of(&js::tokens(text, true))))
        }
        "py" => {
            let mut old = Vec::new();
            py::fallback(text, 0, &mut old);
            Some(Structure::of(&py::tokens(text)).intersect(&Structure::of(&old)))
        }
        "go" => Some(Structure::of(&go::tokens(text))),
        "rs" => Some(Structure::of(&rs::tokens(text))),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_go_rs;
#[cfg(test)]
mod tests_fuzz;
