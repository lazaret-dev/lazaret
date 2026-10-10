//! What the parser builds: the items of a Rust file, their attributes, their `use` leaves, and the tokens and
//! delimiter pairs they point into (see the module docs in `mod.rs`).

use crate::lex::Token;

/// No item, no token: a field that is absent.
pub const NONE: u32 = u32::MAX;

macro_rules! kinds {
    ($($k:ident),* $(,)?) => {
        /// An item's kind: `rustc_ast`'s `ItemKind` (an associated or foreign item has the kind of the item it is the
        /// same as: `type` in a trait is a `TyAlias`).
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Kind { $($k),* }

        impl Kind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Kind] = &[$(Kind::$k),*];
            /// `rustc_ast`'s name for the kind.
            pub fn name(self) -> &'static str {
                const NAMES: &[&str] = &[$(stringify!($k)),*];
                NAMES[self as usize]
            }
        }
    };
}

kinds! {
    ExternCrate, Use, Static, Const, Fn, Mod, ForeignMod, TyAlias, Enum, Struct, Union, Trait, TraitAlias, Impl,
    MacCall, MacroDef,
}

/// An item's visibility.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vis {
    /// nothing written
    Inherited,
    /// `pub`
    Pub,
    /// `pub(crate)`, `pub(self)`, `pub(super)`, `pub(in path)`
    Restricted,
}

// ---- an item's flags (`Item::flags`) ----
/// `unsafe fn`, `unsafe impl`, `unsafe trait`, `unsafe extern { … }`.
pub const UNSAFE: u16 = 1 << 0;
/// `async fn`.
pub const ASYNC: u16 = 1 << 1;
/// `const fn` (a `const` item is of the kind `Const`).
pub const CONST: u16 = 1 << 2;
/// `extern "C" fn`, `extern fn` (the ABI's string, if there is one, is [`Item::abi`]).
pub const EXTERN: u16 = 1 << 3;
/// `default fn` (specialization).
pub const DEFAULT: u16 = 1 << 4;
/// `auto trait`.
pub const AUTO: u16 = 1 << 5;
/// `safe fn`, `safe static` (in an `unsafe extern` block).
pub const SAFE: u16 = 1 << 6;
/// `static mut`.
pub const MUT: u16 = 1 << 7;
/// `impl !Trait for T`.
pub const NEGATIVE: u16 = 1 << 8;
/// Found in a function's body, in an initializer or among a block's statements: not a module's, a trait's, an
/// implementation's or a foreign block's own item.
pub const LOCAL: u16 = 1 << 9;
/// The item's end was not found where the grammar puts it (the text stopped, or a delimiter was missing): it ends
/// at the last token read.
pub const CUT: u16 = 1 << 10;

/// One item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Item {
    pub kind: Kind,
    pub vis: Vis,
    pub flags: u16,
    /// The item that holds this one (a module, a trait, an implementation, a foreign block, a function, a `const`
    /// or `static` whose initializer holds it), or [`NONE`] at the crate's top level.
    pub parent: u32,
    /// First and last-plus-one token of the item (visibility and qualifiers included, outer attributes not).
    pub tok_start: u32,
    pub tok_end: u32,
    /// The code-point offsets of the same: `rustc`'s span of the item.
    pub start: u32,
    pub end: u32,
    /// The token of the item's name (`Fn`, `Mod`, `Struct`, `Enum`, `Union`, `Trait`, `TraitAlias`, `TyAlias`,
    /// `Static`, `Const`, `MacroDef`; of `ExternCrate` the crate's; of `MacCall` the macro path's last segment);
    /// none for `Use`, `ForeignMod` and `Impl`.
    pub name: u32,
    /// `extern crate a as b`: the token of `b` (`_` included).
    pub alias: u32,
    /// `extern "C"`: the token of the string.
    pub abi: u32,
    /// The braces of a body: a module's, a trait's, an implementation's, a foreign block's, a function's, a
    /// `struct`'s, an `enum`'s, a `union`'s; of a macro definition or a macro call the delimiters of its tokens.
    pub body_open: u32,
    pub body_close: u32,
    /// `Impl`: the token of `for` (none for an inherent implementation); `Const`, `Static`: the token of `=`.
    pub extra: u32,
    /// The outer attributes: (first, count) in [`Tree::attrs`].
    pub attrs: (u32, u32),
    /// The inner attributes written at the start of the item's braces: (first, count).
    pub inner_attrs: (u32, u32),
}

/// An attribute, `#[…]` or `#![…]` (a doc comment is not one here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    /// The `#` and the token after the closing `]`.
    pub tok_start: u32,
    pub tok_end: u32,
    pub inner: bool,
    /// The item it is on (an inner attribute: the item whose braces hold it), or [`NONE`]: a crate's inner
    /// attribute, or an attribute no item followed.
    pub owner: u32,
}

/// One name a `use` brings in, or a glob: `use a::{b::c as d, e::*}` has two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UseLeaf {
    pub item: u32,
    /// The path's segments: (first, count) in [`Tree::segs`] (token indexes). A glob has the path to its `*`.
    pub segs: (u32, u32),
    /// `as b`: the token of `b` (`_` included).
    pub alias: u32,
    pub glob: bool,
}

/// The parsed file.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    /// The tokens of the text, comments left out.
    pub toks: Vec<Token>,
    /// For a token that opens `(`, `[` or `{`, the token that closes it, and the other way round; [`NONE`] for
    /// every other token and for a delimiter that has no mate.
    pub mate: Vec<u32>,
    /// The items, a container before what it holds, in the order they are written.
    pub items: Vec<Item>,
    pub attrs: Vec<Attr>,
    /// The crate's inner attributes (`#![no_std]`): (first, count) in [`Tree::attrs`].
    pub crate_attrs: (u32, u32),
    pub leaves: Vec<UseLeaf>,
    pub segs: Vec<u32>,
    /// Delimiters without a mate, stray closers, items cut short: the text is not Rust that compiles.
    pub problems: u32,
}

impl Tree {
    /// The text of token `t`.
    pub fn text(&self, src: &[u32], t: u32) -> String {
        match self.toks.get(t as usize) {
            Some(tok) => src[tok.start as usize..tok.end as usize].iter().map(|&x| char::from_u32(x).unwrap_or('\u{fffd}')).collect(),
            None => String::new(),
        }
    }

    /// The name of token `t`, without a raw identifier's `r#`.
    pub fn ident(&self, src: &[u32], t: u32) -> String {
        let s = self.text(src, t);
        match s.strip_prefix("r#") {
            Some(rest) => rest.to_string(),
            None => s,
        }
    }

    /// The name of item `i` ("" if it has none).
    pub fn name(&self, src: &[u32], i: usize) -> String {
        match self.items.get(i) {
            Some(it) if it.name != NONE => self.ident(src, it.name),
            _ => String::new(),
        }
    }

    /// The outer attributes of item `i`.
    pub fn attrs_of(&self, i: usize) -> &[Attr] {
        let (a, n) = self.items.get(i).map(|it| it.attrs).unwrap_or((0, 0));
        &self.attrs[a as usize..(a + n) as usize]
    }

    /// The inner attributes of item `i`.
    pub fn inner_attrs_of(&self, i: usize) -> &[Attr] {
        let (a, n) = self.items.get(i).map(|it| it.inner_attrs).unwrap_or((0, 0));
        &self.attrs[a as usize..(a + n) as usize]
    }

    /// Where an attribute's path and its arguments are: (the path's first token, the token after the path, the end
    /// of what is inside the brackets, written `unsafe(…)`). The path is the names and the colons from the first
    /// token inside the brackets; `#[unsafe(no_mangle)]` has the path of what is in its parentheses.
    fn attr_parts(&self, src: &[u32], a: &Attr) -> (usize, usize, usize, bool) {
        let close = (a.tok_end as usize).saturating_sub(1).min(self.toks.len());
        let first = a.tok_start as usize + if a.inner { 3 } else { 2 };
        let path_end = |from: usize, limit: usize| -> usize {
            let mut t = from;
            while t < limit {
                let tok = self.toks[t];
                let colon = tok.kind == crate::lex::Kind::Punct && src.get(tok.start as usize) == Some(&(':' as u32));
                if tok.kind == crate::lex::Kind::Name || colon {
                    t += 1;
                } else {
                    break;
                }
            }
            t
        };
        let end = path_end(first, close);
        let wrapped = end == first + 1
            && end + 1 < close
            && self.text(src, first as u32) == "unsafe"
            && self.mate.get(end).copied().unwrap_or(NONE) as usize == close - 1;
        if wrapped {
            let limit = close - 1;
            return (end + 1, path_end(end + 1, limit), limit, true);
        }
        (first, end, close, false)
    }

    /// An attribute's path, `a::b` (`#[rustfmt::skip]`, `#[no_mangle]`, `#[unsafe(no_mangle)]`, `#[cfg_attr(…)]` is
    /// `cfg_attr`).
    pub fn attr_path(&self, src: &[u32], a: &Attr) -> String {
        let (first, end, _, _) = self.attr_parts(src, a);
        let mut out = String::new();
        for t in first..end {
            let s = self.text(src, t as u32);
            out.push_str(s.strip_prefix("r#").unwrap_or(&s));
        }
        out
    }

    /// The attribute is written `#[unsafe(…)]`.
    pub fn attr_is_unsafe(&self, src: &[u32], a: &Attr) -> bool {
        self.attr_parts(src, a).3
    }

    /// The delimiters (token indexes of the opening and the closing one) of an attribute's arguments, `#[a(…)]`.
    pub fn attr_args(&self, src: &[u32], a: &Attr) -> Option<(u32, u32)> {
        let (_, end, limit, _) = self.attr_parts(src, a);
        if end < limit && self.mate.get(end).copied().unwrap_or(NONE) != NONE && self.mate[end] > end as u32 && (self.mate[end] as usize) < limit {
            return Some((end as u32, self.mate[end]));
        }
        None
    }

    /// `#[name = value]`: the token of the value's first token (a string, usually), if the attribute has one.
    pub fn attr_value(&self, src: &[u32], a: &Attr) -> Option<u32> {
        let (_, end, limit, _) = self.attr_parts(src, a);
        let tok = self.toks.get(end)?;
        if end + 1 < limit && tok.kind == crate::lex::Kind::Punct && src.get(tok.start as usize) == Some(&('=' as u32)) {
            return Some((end + 1) as u32);
        }
        None
    }

    /// The text of a string literal token without its quotes (a plain `"…"` or a raw `r#"…"#` one; the escapes are
    /// left as written), or None if token `t` is not a string.
    pub fn str_value(&self, src: &[u32], t: u32) -> Option<String> {
        let tok = self.toks.get(t as usize)?;
        if tok.kind != crate::lex::Kind::Str {
            return None;
        }
        let s: String = src[tok.start as usize..tok.end as usize].iter().map(|&x| char::from_u32(x).unwrap_or('\u{fffd}')).collect();
        let s = s.strip_prefix('r').unwrap_or(&s);
        let hashes = s.chars().take_while(|&c| c == '#').count();
        let inner = s.get(hashes..)?;
        let inner = inner.strip_prefix('"')?;
        let inner = inner.strip_suffix(&"#".repeat(hashes)[..])?;
        let inner = inner.strip_suffix('"')?;
        Some(inner.to_string())
    }

    /// The path of a use leaf: `a::b::c`, `a::*` for a glob.
    pub fn leaf_path(&self, src: &[u32], l: &UseLeaf) -> String {
        let mut out = String::new();
        for k in 0..l.segs.1 {
            if k > 0 {
                out.push_str("::");
            }
            out.push_str(&self.ident(src, self.segs[(l.segs.0 + k) as usize]));
        }
        if l.glob {
            if l.segs.1 > 0 {
                out.push_str("::");
            }
            out.push('*');
        }
        out
    }

    /// The item that holds `i`, and then the one that holds that: `i`'s ancestors, nearest first.
    pub fn ancestors(&self, i: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut p = self.items.get(i).map(|it| it.parent).unwrap_or(NONE);
        while p != NONE {
            out.push(p as usize);
            p = self.items[p as usize].parent;
        }
        out
    }
}
