//! The reader: the items of a Rust file, found over [`lex::rs`](crate::lex::rs)'s tokens.
//!
//! It is not Rust's parser. It reads what a detector asks of a Rust file: which items there are, of what kind,
//! with which name, visibility and attributes, where they start and end, what they `use`, and where their bodies
//! are. What is inside a body is kept as tokens: a function's body, an initializer and a macro's tokens are read
//! only for the items that stand in them (a `fn` inside a `fn`, a `static` in a block), and every delimited group
//! is matched once, so a body is a token range and its end is where its closing delimiter is.
//!
//! The grammar it follows is the item grammar of the Rust Reference (visibility, qualifiers, the item keywords, an
//! item's end: its `;` or its braces, with the angle brackets of generics told from the braces of a body). A
//! macro's tokens are never read as code: `m! { fn f() {} }` holds no item, as the compiler's parser sees it (the
//! items a macro makes are known only to its expansion). It never fails and never panics; a text that is not Rust
//! gives what could be read of it and a count of [`Tree::problems`].
//!
//! No recursion: the groups and bodies still to be read are a stack on the heap, so nesting costs memory in
//! proportion to the text and no stack. Every token is looked at a bounded number of times.

use super::tree::*;
use crate::lex::{rs as lexrs, Kind as TK};

/// The longest text read (offsets and ids are u32).
pub const MAX_LEN: usize = (u32::MAX - 16) as usize;
/// The most path segments the leaves of the `use` items of one file may hold (a `use` tree with a long prefix and
/// many leaves repeats the prefix for each).
pub const MAX_USE_SEGS: usize = 1 << 22;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kw {
    /// a name that is not a keyword (a raw identifier too)
    None,
    As,
    Async,
    Auto,
    Const,
    Crate,
    Default,
    Enum,
    Extern,
    Fn,
    For,
    Impl,
    In,
    MacroRules,
    Mod,
    Mut,
    Pub,
    Safe,
    SelfLower,
    SelfUpper,
    Static,
    Struct,
    Super,
    Trait,
    Type,
    Union,
    Unsafe,
    Use,
    Where,
    Underscore,
    /// any other reserved word: it cannot be an item's name
    Reserved,
}

impl Kw {
    /// The keyword a word is (`s` is ASCII, 1 to 12 characters).
    fn of(s: &[u8]) -> Kw {
        match s {
            b"as" => Kw::As,
            b"async" => Kw::Async,
            b"auto" => Kw::Auto,
            b"const" => Kw::Const,
            b"crate" => Kw::Crate,
            b"default" => Kw::Default,
            b"enum" => Kw::Enum,
            b"extern" => Kw::Extern,
            b"fn" => Kw::Fn,
            b"for" => Kw::For,
            b"impl" => Kw::Impl,
            b"in" => Kw::In,
            b"macro_rules" => Kw::MacroRules,
            b"mod" => Kw::Mod,
            b"mut" => Kw::Mut,
            b"pub" => Kw::Pub,
            b"safe" => Kw::Safe,
            b"self" => Kw::SelfLower,
            b"Self" => Kw::SelfUpper,
            b"static" => Kw::Static,
            b"struct" => Kw::Struct,
            b"super" => Kw::Super,
            b"trait" => Kw::Trait,
            b"type" => Kw::Type,
            b"union" => Kw::Union,
            b"unsafe" => Kw::Unsafe,
            b"use" => Kw::Use,
            b"where" => Kw::Where,
            b"_" => Kw::Underscore,
            // (`async`, `await`, `dyn`, `try` and `gen` are keywords in some editions only; the item reader is for all of
            // them, so they are names where a name is wanted)
            b"abstract" | b"become" | b"box" | b"break" | b"continue" | b"do" | b"else" | b"false" | b"final" | b"if" | b"let"
            | b"loop" | b"macro" | b"match" | b"move" | b"override" | b"priv" | b"ref" | b"return" | b"true" | b"typeof"
            | b"unsized" | b"virtual" | b"while" | b"yield" => Kw::Reserved,
            _ => Kw::None,
        }
    }
}

/// What a group of tokens holds, for the stack of what is left to read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctx {
    /// the items of a module (or the crate)
    Module,
    /// an implementation's
    Impl,
    /// a trait's
    Trait,
    /// a foreign block's
    Extern,
    /// the statements of a block (or the fields of a struct literal, the arms of a `match`: whatever `{…}` holds in
    /// an expression)
    Block,
    /// an expression's tokens: an initializer, the inside of `(…)` and `[…]`
    Expr,
}

struct Frame {
    pos: usize,
    end: usize,
    ctx: Ctx,
    parent: u32,
    /// the next token starts a statement: an item may be there
    start: bool,
    /// inner attributes may be at `pos`
    fresh: bool,
}

/// An item found, before it is added.
struct Found {
    item: Item,
    /// where the rest of the frame goes on
    next: usize,
    /// the tokens of an initializer, to be read for the items in it
    init: Option<(usize, usize)>,
    /// a `use`'s tokens (after the keyword, up to its `;`)
    use_range: Option<(usize, usize)>,
}

enum Stop {
    Brace(usize),
    Semi(usize),
    Eof,
}

struct P<'a> {
    src: &'a [u32],
    t: Tree,
    kw: Vec<Kw>,
    ch: Vec<u32>,
    /// the first token of a name starts with `'`: a lifetime or a label
    life: Vec<bool>,
    /// frames an item left to read, in text order, before its body (a head's or a field list's groups can hold items)
    pending: Vec<Frame>,
}

/// The items of the Rust text `src` (code points).
pub fn parse(src: &[u32]) -> Tree {
    let mut t = Tree::default();
    if src.len() >= MAX_LEN {
        t.problems = 1;
        return t;
    }
    for tok in lexrs::tokens(src) {
        if tok.kind != TK::Comment {
            t.toks.push(tok);
        }
    }
    let n = t.toks.len();
    let mut p = P { src, t, kw: Vec::with_capacity(n), ch: Vec::with_capacity(n), life: Vec::with_capacity(n), pending: Vec::new() };
    p.classify();
    p.match_delims();
    let mut stack = vec![Frame { pos: 0, end: n, ctx: Ctx::Module, parent: NONE, start: true, fresh: true }];
    while let Some(mut f) = stack.pop() {
        let mut child = None;
        while f.pos < f.end && child.is_none() && p.pending.is_empty() {
            child = p.step(&mut f);
        }
        if f.pos < f.end {
            stack.push(f);
        }
        if let Some(c) = child {
            stack.push(c);
        }
        // what an item left in its head (text order: the first is read first, so it goes on the stack last)
        while let Some(c) = p.pending.pop() {
            stack.push(c);
        }
    }
    p.t
}

impl<'a> P<'a> {
    fn classify(&mut self) {
        for tok in &self.t.toks {
            let first = self.src[tok.start as usize];
            self.ch.push(first);
            self.life.push(tok.kind == TK::Name && first == '\'' as u32);
            let mut kw = Kw::None;
            if tok.kind == TK::Name && first != '\'' as u32 && tok.end - tok.start <= 12 {
                let mut buf = [0u8; 12];
                let mut k = 0;
                let mut ascii = true;
                for &x in &self.src[tok.start as usize..tok.end as usize] {
                    if x < 128 {
                        buf[k] = x as u8;
                        k += 1;
                    } else {
                        ascii = false;
                        break;
                    }
                }
                if ascii {
                    kw = Kw::of(&buf[..k]);
                }
            }
            self.kw.push(kw);
        }
    }

    fn match_delims(&mut self) {
        let n = self.t.toks.len();
        self.t.mate = vec![NONE; n];
        let mut open: Vec<u32> = Vec::new();
        for i in 0..n {
            if self.t.toks[i].kind != TK::Punct {
                continue;
            }
            let c = self.ch[i];
            if c == '(' as u32 || c == '[' as u32 || c == '{' as u32 {
                open.push(i as u32);
            } else if c == ')' as u32 || c == ']' as u32 || c == '}' as u32 {
                let want = if c == ')' as u32 { '(' as u32 } else if c == ']' as u32 { '[' as u32 } else { '{' as u32 };
                // the nearest opener of this kind; the openers above it have no mate
                match open.iter().rposition(|&o| self.ch[o as usize] == want) {
                    Some(k) => {
                        let o = open[k] as usize;
                        self.t.problems += (open.len() - 1 - k) as u32;
                        open.truncate(k);
                        self.t.mate[o] = i as u32;
                        self.t.mate[i] = o as u32;
                    }
                    None => self.t.problems += 1,
                }
            }
        }
        self.t.problems += open.len() as u32;
    }

    // ---- looking at tokens ----

    fn kw(&self, i: usize) -> Kw {
        self.kw.get(i).copied().unwrap_or(Kw::None)
    }

    /// Token `i` is the punctuation character `c`.
    fn is(&self, i: usize, c: char) -> bool {
        i < self.t.toks.len() && self.t.toks[i].kind == TK::Punct && self.ch[i] == c as u32
    }

    /// Token `i` is a name or a keyword (not a lifetime).
    fn is_name(&self, i: usize) -> bool {
        i < self.t.toks.len() && self.t.toks[i].kind == TK::Name && !self.life[i]
    }

    /// Token `i` can be an item's name: a name that is not a reserved word (`union`, `auto`, `default`, `safe`
    /// and `macro_rules` are names too).
    fn is_ident(&self, i: usize) -> bool {
        self.is_name(i) && matches!(self.kw(i), Kw::None | Kw::Union | Kw::Auto | Kw::Default | Kw::Safe | Kw::MacroRules)
    }

    /// Token `i` is a string a `extern` can name an ABI with (`"C"`, `r"C"`).
    fn is_str(&self, i: usize) -> bool {
        i < self.t.toks.len() && self.t.toks[i].kind == TK::Str && (self.ch[i] == '"' as u32 || self.ch[i] == 'r' as u32)
    }

    /// `::` at `i`.
    fn colon2(&self, i: usize) -> bool {
        self.is(i, ':') && self.is(i + 1, ':') && self.t.toks[i].end == self.t.toks[i + 1].start
    }

    fn mate(&self, i: usize) -> usize {
        self.t.mate.get(i).copied().unwrap_or(NONE) as usize
    }

    /// Token `i` opens a group.
    fn opens(&self, i: usize) -> bool {
        self.is(i, '(') || self.is(i, '[') || self.is(i, '{')
    }

    /// The end of the group that opens at `i`, or `end` if it is not closed.
    fn close_of(&self, i: usize, end: usize) -> usize {
        match self.t.mate.get(i).copied().unwrap_or(NONE) {
            NONE => end,
            m => (m as usize).min(end),
        }
    }

    /// `pub ( crate | self | super | in … )` at `p` (the `(`).
    fn restricted_vis(&self, p: usize) -> bool {
        let m = self.mate(p);
        if m == NONE as usize || m <= p + 1 {
            return false;
        }
        if m == p + 2 {
            return matches!(self.kw(p + 1), Kw::Crate | Kw::SelfLower | Kw::Super);
        }
        self.kw(p + 1) == Kw::In
    }

    // ---- attributes ----

    fn outer_attrs(&mut self, mut p: usize, end: usize) -> (u32, u32, usize) {
        let first = self.t.attrs.len() as u32;
        while p < end && self.is(p, '#') && self.is(p + 1, '[') && self.mate(p + 1) != NONE as usize {
            let m = self.mate(p + 1);
            self.t.attrs.push(Attr { tok_start: p as u32, tok_end: (m + 1) as u32, inner: false, owner: NONE });
            p = m + 1;
        }
        (first, self.t.attrs.len() as u32 - first, p)
    }

    fn inner_attrs(&mut self, mut p: usize, end: usize) -> (u32, u32, usize) {
        let first = self.t.attrs.len() as u32;
        while p < end && self.is(p, '#') && self.is(p + 1, '!') && self.is(p + 2, '[') && self.mate(p + 2) != NONE as usize {
            let m = self.mate(p + 2);
            self.t.attrs.push(Attr { tok_start: p as u32, tok_end: (m + 1) as u32, inner: true, owner: NONE });
            p = m + 1;
        }
        (first, self.t.attrs.len() as u32 - first, p)
    }

    // ---- scanning an item's head ----

    /// Reads from `from` to the first `{` that is not in angle brackets or the first `;`, skipping groups.
    fn scan_head(&self, from: usize, end: usize) -> Stop {
        let mut i = from;
        let mut angle = 0i32;
        while i < end {
            if self.t.toks[i].kind == TK::Punct {
                let c = self.ch[i];
                if c == '(' as u32 || c == '[' as u32 {
                    if self.mate(i) == NONE as usize {
                        return Stop::Eof;
                    }
                    i = self.mate(i) + 1;
                    continue;
                } else if c == '{' as u32 {
                    if angle <= 0 {
                        return Stop::Brace(i);
                    }
                    if self.mate(i) == NONE as usize {
                        return Stop::Eof;
                    }
                    i = self.mate(i) + 1;
                    continue;
                } else if c == ';' as u32 {
                    return Stop::Semi(i);
                } else if c == '<' as u32 {
                    angle += 1;
                } else if c == '>' as u32 && !(i > from && self.is(i - 1, '-') && self.t.toks[i - 1].end == self.t.toks[i].start) && angle > 0 {
                    angle -= 1;
                }
            }
            i += 1;
        }
        Stop::Eof
    }

    /// Reads from `from` to the first `;`, skipping groups; and notes the first `=` outside angle brackets.
    fn scan_semi(&self, from: usize, end: usize) -> (usize, usize) {
        let mut i = from;
        let mut angle = 0i32;
        let mut eq = NONE as usize;
        while i < end {
            if self.t.toks[i].kind == TK::Punct {
                let c = self.ch[i];
                if self.opens(i) {
                    if self.mate(i) == NONE as usize {
                        return (eq, end);
                    }
                    i = self.mate(i) + 1;
                    continue;
                } else if c == ';' as u32 {
                    return (eq, i);
                } else if c == '<' as u32 {
                    angle += 1;
                } else if c == '>' as u32 {
                    let arrow = i > from && self.is(i - 1, '-') && self.t.toks[i - 1].end == self.t.toks[i].start;
                    if !arrow && angle > 0 {
                        angle -= 1;
                    }
                } else if c == '=' as u32 && angle <= 0 && eq == NONE as usize {
                    let eqeq = self.is(i + 1, '=') && self.t.toks[i].end == self.t.toks[i + 1].start;
                    if !eqeq {
                        eq = i;
                    }
                }
            }
            i += 1;
        }
        (eq, end)
    }

    /// The token after the generics at `j` (`<…>`), or `j` if there are none.
    fn skip_generics(&self, j: usize, end: usize) -> usize {
        if !self.is(j, '<') {
            return j;
        }
        let mut i = j;
        let mut angle = 0i32;
        while i < end {
            if self.t.toks[i].kind == TK::Punct {
                if self.opens(i) {
                    if self.mate(i) == NONE as usize {
                        return end;
                    }
                    i = self.mate(i) + 1;
                    continue;
                }
                if self.is(i, '<') {
                    angle += 1;
                } else if self.is(i, '>') && !(i > j && self.is(i - 1, '-') && self.t.toks[i - 1].end == self.t.toks[i].start) {
                    angle -= 1;
                    if angle == 0 {
                        return i + 1;
                    }
                } else if self.is(i, ';') || self.is(i, '{') {
                    return i;
                }
            }
            i += 1;
        }
        end
    }

    // ---- an item ----

    fn mk(&self, kind: Kind, vis: Vis, flags: u16, tok_start: usize, tok_end: usize) -> Item {
        let last = tok_end.saturating_sub(1).min(self.t.toks.len().saturating_sub(1));
        Item {
            kind,
            vis,
            flags,
            parent: NONE,
            tok_start: tok_start as u32,
            tok_end: tok_end as u32,
            start: self.t.toks[tok_start].start,
            end: self.t.toks[last].end,
            name: NONE,
            alias: NONE,
            abi: NONE,
            body_open: NONE,
            body_close: NONE,
            extra: NONE,
            attrs: (0, 0),
            inner_attrs: (0, 0),
        }
    }

    /// The item that starts at `p0` (after its attributes), if one does. `ctx` is what holds it.
    fn item_at(&mut self, p0: usize, end: usize, ctx: Ctx) -> Option<Found> {
        let mut p = p0;
        let mut vis = Vis::Inherited;
        let mut flags: u16 = 0;
        let mut abi = NONE;
        let mut foreign = false;
        if self.kw(p) == Kw::Pub {
            vis = Vis::Pub;
            p += 1;
            if self.is(p, '(') && self.restricted_vis(p) {
                vis = Vis::Restricted;
                p = self.mate(p) + 1;
            }
        }
        // qualifiers
        for _ in 0..8 {
            if p >= end {
                return None;
            }
            let k = self.kw(p);
            let nk = self.kw(p + 1);
            match k {
                Kw::Default if matches!(nk, Kw::Const | Kw::Fn | Kw::Unsafe | Kw::Async | Kw::Extern | Kw::Impl | Kw::Type | Kw::Safe | Kw::Static) => {
                    flags |= DEFAULT;
                }
                Kw::Const if matches!(nk, Kw::Fn | Kw::Unsafe | Kw::Async | Kw::Extern | Kw::Impl | Kw::Trait) => flags |= CONST,
                Kw::Async if matches!(nk, Kw::Fn | Kw::Unsafe | Kw::Extern | Kw::Const) => flags |= ASYNC,
                Kw::Unsafe if matches!(nk, Kw::Fn | Kw::Impl | Kw::Trait | Kw::Extern | Kw::Auto) => flags |= UNSAFE,
                Kw::Safe if matches!(nk, Kw::Fn | Kw::Static | Kw::Unsafe) => flags |= SAFE,
                Kw::Auto if nk == Kw::Trait => flags |= AUTO,
                Kw::Extern if nk != Kw::Crate => {
                    let mut q = p + 1;
                    if self.is_str(q) {
                        abi = q as u32;
                        q += 1;
                    }
                    if self.kw(q) == Kw::Fn {
                        flags |= EXTERN;
                        p = q;
                    } else if self.is(q, '{') {
                        flags |= EXTERN;
                        foreign = true;
                        p = q;
                    } else {
                        return None;
                    }
                    break;
                }
                _ => break,
            }
            p += 1;
        }
        if p >= end {
            return None;
        }
        let local = matches!(ctx, Ctx::Block | Ctx::Expr);
        let mut found: Option<Found> = None;
        let k = self.kw(p);
        if foreign {
            // `extern "C" { … }`
            let open = p;
            let close = self.mate(open);
            let (tok_end, cut) = if close == NONE as usize { (end, true) } else { (close + 1, false) };
            let mut item = self.mk(Kind::ForeignMod, vis, flags, p0, tok_end);
            item.abi = abi;
            item.body_open = open as u32;
            item.body_close = if cut { NONE } else { close as u32 };
            if cut {
                item.flags |= CUT;
            }
            found = Some(Found { item, next: tok_end, init: None, use_range: None });
        } else if k == Kw::Use && p + 1 < end && !self.is(p + 1, '<') {
            let (_, semi) = self.scan_semi(p + 1, end);
            let (tok_end, cut) = if semi >= end { (end, true) } else { (semi + 1, false) };
            let mut item = self.mk(Kind::Use, vis, flags, p0, tok_end);
            if cut {
                item.flags |= CUT;
            }
            found = Some(Found { item, next: tok_end, init: None, use_range: Some((p + 1, semi.min(end))) });
        } else if k == Kw::Extern && self.kw(p + 1) == Kw::Crate && (self.is_name(p + 2)) {
            let (_, semi) = self.scan_semi(p + 3, end);
            let (tok_end, cut) = if semi >= end { (end, true) } else { (semi + 1, false) };
            let mut item = self.mk(Kind::ExternCrate, vis, flags, p0, tok_end);
            item.name = (p + 2) as u32;
            if self.kw(p + 3) == Kw::As && self.is_name(p + 4) && p + 4 < tok_end {
                item.alias = (p + 4) as u32;
            }
            if cut {
                item.flags |= CUT;
            }
            found = Some(Found { item, next: tok_end, init: None, use_range: None });
        } else if k == Kw::Mod && self.is_ident(p + 1) {
            if self.is(p + 2, ';') {
                let mut item = self.mk(Kind::Mod, vis, flags, p0, p + 3);
                item.name = (p + 1) as u32;
                found = Some(Found { item, next: p + 3, init: None, use_range: None });
            } else if self.is(p + 2, '{') {
                found = Some(self.with_body(Kind::Mod, vis, flags, p0, p + 1, p + 2, end));
            }
        } else if matches!(k, Kw::Struct | Kw::Enum | Kw::Union) && self.is_ident(p + 1) {
            let named = k != Kw::Union || self.is(p + 2, '{') || self.is(p + 2, '<') || self.kw(p + 2) == Kw::Where;
            if named {
                let kind = match k {
                    Kw::Struct => Kind::Struct,
                    Kw::Enum => Kind::Enum,
                    _ => Kind::Union,
                };
                found = Some(match self.scan_head(p + 2, end) {
                    Stop::Brace(i) => self.with_body(kind, vis, flags, p0, p + 1, i, end),
                    Stop::Semi(i) => self.bare(kind, vis, flags, p0, p + 1, i + 1),
                    Stop::Eof => self.cut(kind, vis, flags, p0, p + 1, end),
                });
            }
        } else if k == Kw::Trait && self.is_ident(p + 1) {
            found = Some(match self.scan_head(p + 2, end) {
                Stop::Brace(i) => self.with_body(Kind::Trait, vis, flags, p0, p + 1, i, end),
                Stop::Semi(i) => self.bare(Kind::TraitAlias, vis, flags, p0, p + 1, i + 1),
                Stop::Eof => self.cut(Kind::Trait, vis, flags, p0, p + 1, end),
            });
        } else if k == Kw::Impl {
            let g = self.skip_generics(p + 1, end);
            let mut j = g;
            if self.kw(j) == Kw::Const {
                j += 1;
            }
            let negated = self.is(j, '!');
            let stop = self.scan_head(p + 1, end);
            let mut item = match stop {
                Stop::Brace(i) => self.with_body(Kind::Impl, vis, flags, p0, NONE as usize, i, end).item,
                Stop::Semi(i) => self.mk(Kind::Impl, vis, flags, p0, i + 1),
                Stop::Eof => {
                    let mut it = self.mk(Kind::Impl, vis, flags | CUT, p0, end);
                    it.tok_end = end as u32;
                    it
                }
            };
            // the `for` of `impl Trait for Type`: the first at the top level of the header
            let header_end = if item.body_open != NONE { item.body_open as usize } else { item.tok_end as usize };
            let mut i = g;
            let mut angle = 0i32;
            while i < header_end {
                if self.opens(i) && self.mate(i) != NONE as usize {
                    i = self.mate(i) + 1;
                    continue;
                }
                if self.is(i, '<') {
                    angle += 1;
                } else if self.is(i, '>') && !(i > g && self.is(i - 1, '-')) && angle > 0 {
                    angle -= 1;
                } else if angle == 0 && self.kw(i) == Kw::For {
                    item.extra = i as u32;
                    break;
                }
                i += 1;
            }
            // `impl !Trait for T`; `impl !{}` is an implementation for the type `!`
            if negated && item.extra != NONE {
                item.flags |= NEGATIVE;
            }
            let next = item.tok_end as usize;
            found = Some(Found { item, next, init: None, use_range: None });
        } else if k == Kw::Fn && self.is_ident(p + 1) {
            found = Some(match self.scan_head(p + 2, end) {
                Stop::Brace(i) => self.with_body(Kind::Fn, vis, flags, p0, p + 1, i, end),
                Stop::Semi(i) => self.bare(Kind::Fn, vis, flags, p0, p + 1, i + 1),
                Stop::Eof => self.cut(Kind::Fn, vis, flags, p0, p + 1, end),
            });
        } else if k == Kw::Static || (k == Kw::Const && (self.is_ident(p + 1) || self.kw(p + 1) == Kw::Underscore)) {
            let (kind, mut name_at) = if k == Kw::Static { (Kind::Static, p + 1) } else { (Kind::Const, p + 1) };
            if k == Kw::Static && self.kw(name_at) == Kw::Mut {
                flags |= MUT;
                name_at += 1;
            }
            let ok = self.is_ident(name_at) || (k == Kw::Const && self.kw(name_at) == Kw::Underscore);
            // a closure `static || …` or a block `const { … }` is not an item
            if ok && (self.is(name_at + 1, ':') || self.is(name_at + 1, '<') || self.is(name_at + 1, ';') || self.is(name_at + 1, '=')) {
                let (eq, semi) = self.scan_semi(name_at + 1, end);
                let (tok_end, cut) = if semi >= end { (end, true) } else { (semi + 1, false) };
                let mut item = self.mk(kind, vis, flags, p0, tok_end);
                item.name = name_at as u32;
                if cut {
                    item.flags |= CUT;
                }
                let mut init = None;
                if eq != NONE as usize && eq < semi {
                    item.extra = eq as u32;
                    init = Some((eq + 1, semi.min(end)));
                }
                found = Some(Found { item, next: tok_end, init, use_range: None });
            }
        } else if k == Kw::Type && self.is_ident(p + 1) {
            let (_, semi) = self.scan_semi(p + 2, end);
            let (tok_end, cut) = if semi >= end { (end, true) } else { (semi + 1, false) };
            let mut item = self.mk(Kind::TyAlias, vis, flags, p0, tok_end);
            item.name = (p + 1) as u32;
            if cut {
                item.flags |= CUT;
            }
            found = Some(Found { item, next: tok_end, init: None, use_range: None });
        } else if k == Kw::MacroRules && self.is(p + 1, '!') && self.is_ident(p + 2) && self.opens(p + 3) {
            found = Some(self.macro_item(Kind::MacroDef, vis, flags, p0, p + 2, p + 3, end));
        } else if !local && flags == 0 {
            // a macro call: `path!{…}` or `path!(…);`
            let mut j = p;
            if self.colon2(j) {
                j += 2;
            }
            let mut last = NONE as usize;
            while self.is_name(j) && !self.life[j] && !matches!(self.kw(j), Kw::Reserved) {
                last = j;
                if self.colon2(j + 1) {
                    j += 3;
                } else {
                    j += 1;
                    break;
                }
            }
            if last != NONE as usize && j == last + 1 && self.is(j, '!') && self.opens(j + 1) {
                found = Some(self.macro_item(Kind::MacCall, vis, flags, p0, last, j + 1, end));
            }
        }
        let mut f = found?;
        if abi != NONE && f.item.abi == NONE {
            f.item.abi = abi;
        }
        if local {
            f.item.flags |= LOCAL;
        }
        Some(f)
    }

    /// An item with a body in `{…}` that opens at `open`.
    fn with_body(&self, kind: Kind, vis: Vis, flags: u16, p0: usize, name: usize, open: usize, end: usize) -> Found {
        let close = self.mate(open);
        let (tok_end, cut) = if close == NONE as usize { (end, true) } else { (close + 1, false) };
        let mut item = self.mk(kind, vis, if cut { flags | CUT } else { flags }, p0, tok_end);
        if name != NONE as usize {
            item.name = name as u32;
        }
        item.body_open = open as u32;
        item.body_close = if cut { NONE } else { close as u32 };
        Found { item, next: tok_end, init: None, use_range: None }
    }

    /// An item with no body, ending at token `tok_end` (past its `;`).
    fn bare(&self, kind: Kind, vis: Vis, flags: u16, p0: usize, name: usize, tok_end: usize) -> Found {
        let mut item = self.mk(kind, vis, flags, p0, tok_end);
        item.name = name as u32;
        Found { item, next: tok_end, init: None, use_range: None }
    }

    /// An item whose end was not found: it runs to `end`.
    fn cut(&self, kind: Kind, vis: Vis, flags: u16, p0: usize, name: usize, end: usize) -> Found {
        let mut item = self.mk(kind, vis, flags | CUT, p0, end);
        item.name = name as u32;
        Found { item, next: end, init: None, use_range: None }
    }

    /// `macro_rules! name {…}` and `path!(…);`: tokens in a group at `open`, and a `;` after a group that is not braces.
    fn macro_item(&self, kind: Kind, vis: Vis, flags: u16, p0: usize, name: usize, open: usize, end: usize) -> Found {
        let close = self.mate(open);
        let mut cut = false;
        let mut tok_end = end;
        if close == NONE as usize {
            cut = true;
        } else {
            tok_end = close + 1;
            if !self.is(open, '{') && self.is(close + 1, ';') && close + 1 < end {
                tok_end = close + 2;
            }
        }
        let mut item = self.mk(kind, vis, if cut { flags | CUT } else { flags }, p0, tok_end);
        item.name = name as u32;
        item.body_open = open as u32;
        item.body_close = if cut { NONE } else { close as u32 };
        Found { item, next: tok_end, init: None, use_range: None }
    }

    // ---- use trees ----

    fn use_leaves(&mut self, item: u32, a: usize, b: usize) {
        let mut prefix: Vec<u32> = Vec::new();
        let mut bases: Vec<usize> = Vec::new();
        let mut i = a;
        while i < b {
            let base = bases.last().copied().unwrap_or(0);
            if self.t.segs.len() > MAX_USE_SEGS {
                self.t.problems += 1;
                return;
            }
            if self.is_name(i) && self.kw(i) != Kw::As {
                prefix.push(i as u32);
                i += 1;
                if self.kw(i) == Kw::As {
                    let alias = if i + 1 < b && (self.is_name(i + 1)) { (i + 1) as u32 } else { NONE };
                    self.emit_leaf(item, &prefix, alias, false);
                    prefix.truncate(base);
                    i += 2;
                } else if self.colon2(i) {
                    i += 2;
                } else {
                    self.emit_leaf(item, &prefix, NONE, false);
                    prefix.truncate(base);
                }
            } else if self.colon2(i) {
                i += 2;
            } else if self.is(i, '{') {
                bases.push(prefix.len());
                i += 1;
            } else if self.is(i, '}') {
                if let Some(b0) = bases.pop() {
                    prefix.truncate(b0);
                }
                i += 1;
            } else if self.is(i, ',') {
                prefix.truncate(base);
                i += 1;
            } else if self.is(i, '*') {
                self.emit_leaf(item, &prefix, NONE, true);
                prefix.truncate(base);
                i += 1;
            } else {
                i += 1;
            }
        }
    }

    fn emit_leaf(&mut self, item: u32, path: &[u32], alias: u32, glob: bool) {
        let first = self.t.segs.len() as u32;
        self.t.segs.extend_from_slice(path);
        self.t.leaves.push(UseLeaf { item, segs: (first, path.len() as u32), alias, glob });
    }

    // ---- the walk ----

    /// Reads one thing at `f.pos`: an item, a group or a token. A frame to read next, if the thing has one.
    fn step(&mut self, f: &mut Frame) -> Option<Frame> {
        if f.fresh {
            f.fresh = false;
            if f.ctx != Ctx::Expr {
                let (first, count, next) = self.inner_attrs(f.pos, f.end);
                if count > 0 {
                    if f.parent == NONE {
                        self.t.crate_attrs = (first, count);
                    } else {
                        self.t.items[f.parent as usize].inner_attrs = (first, count);
                        for a in first..first + count {
                            self.t.attrs[a as usize].owner = f.parent;
                        }
                    }
                    f.pos = next;
                    return None;
                }
            }
        }
        let i = f.pos;
        match f.ctx {
            Ctx::Module | Ctx::Impl | Ctx::Trait | Ctx::Extern => {
                let (a_first, a_count, p) = self.outer_attrs(i, f.end);
                if p >= f.end {
                    f.pos = f.end;
                    return None;
                }
                match self.item_at(p, f.end, f.ctx) {
                    Some(found) => self.add(f, found, a_first, a_count),
                    None => {
                        // not an item: skip it (its group, if it opens one)
                        self.t.problems += 1;
                        f.pos = if self.opens(p) { self.close_of(p, f.end) + 1 } else { p + 1 };
                        None
                    }
                }
            }
            Ctx::Block | Ctx::Expr => {
                if f.start {
                    let (a_first, a_count, p) = self.outer_attrs(i, f.end);
                    if p < f.end {
                        if let Some(found) = self.item_at(p, f.end, f.ctx) {
                            return self.add(f, found, a_first, a_count);
                        }
                    }
                    if p > i {
                        f.pos = p;
                        f.start = false;
                        return None;
                    }
                }
                if self.is(i, '#') && (self.is(i + 1, '[') || (self.is(i + 1, '!') && self.is(i + 2, '['))) {
                    // an attribute on an expression, a field, a parameter: its arguments hold no item
                    let open = if self.is(i + 1, '[') { i + 1 } else { i + 2 };
                    f.pos = self.close_of(open, f.end) + 1;
                    f.start = false;
                    return None;
                }
                if self.opens(i) {
                    let brace = self.is(i, '{');
                    let close = self.close_of(i, f.end);
                    let macro_call = i >= 2 && self.is(i - 1, '!') && self.is_name(i - 2) && self.kw(i - 2) != Kw::Reserved;
                    f.pos = close + 1;
                    f.start = brace;
                    if macro_call {
                        return None;
                    }
                    return Some(Frame {
                        pos: i + 1,
                        end: close,
                        ctx: if brace { Ctx::Block } else { Ctx::Expr },
                        parent: f.parent,
                        start: brace,
                        fresh: false,
                    });
                }
                f.start = self.is(i, ';');
                f.pos = i + 1;
                None
            }
        }
    }

    /// Adds a found item to the tree and says what is left to read of it.
    fn add(&mut self, f: &mut Frame, found: Found, a_first: u32, a_count: u32) -> Option<Frame> {
        let idx = self.t.items.len() as u32;
        let mut item = found.item;
        item.parent = f.parent;
        item.attrs = (a_first, a_count);
        for a in a_first..a_first + a_count {
            self.t.attrs[a as usize].owner = idx;
        }
        if item.flags & CUT != 0 {
            self.t.problems += 1;
        }
        let kind = item.kind;
        let (open, close) = (item.body_open, item.body_close);
        let (tok_start, tok_end, extra) = (item.tok_start as usize, item.tok_end as usize, item.extra);
        let cut = item.flags & CUT != 0;
        self.t.items.push(item);
        // The groups of an item's head (a parameter's or a field's type, a generic argument, a where clause) and of a
        // struct's or enum's fields can hold items: `[u8; { struct S; 1 }]`, `Foo<{ fn f() {} 1 }>`, `A = { fn f() {} 1 }`.
        // They are read as expressions, before the body (a body is later in the text).
        // (an item that was cut off by an unclosed group has the rest of the text for a head: that is not read for items)
        let in_head = !cut && !matches!(kind, Kind::Use | Kind::ExternCrate | Kind::MacroDef | Kind::MacCall | Kind::Mod | Kind::ForeignMod);
        if in_head {
            let head_end = if open != NONE {
                open as usize
            } else if matches!(kind, Kind::Const | Kind::Static) && extra != NONE {
                extra as usize
            } else {
                tok_end
            };
            let head_end = head_end.min(f.end);
            if tok_start < head_end {
                self.pending.push(Frame { pos: tok_start, end: head_end, ctx: Ctx::Expr, parent: idx, start: false, fresh: false });
            }
            if matches!(kind, Kind::Struct | Kind::Enum | Kind::Union) && open != NONE {
                let end = if close != NONE { close as usize } else { f.end };
                if open as usize + 1 < end {
                    self.pending.push(Frame { pos: open as usize + 1, end, ctx: Ctx::Expr, parent: idx, start: false, fresh: false });
                }
            }
        }
        if let Some((a, b)) = found.use_range {
            self.use_leaves(idx, a, b);
        }
        f.pos = found.next.min(f.end).max(f.pos + 1);
        f.start = true;
        let ctx = match kind {
            Kind::Mod => Some(Ctx::Module),
            Kind::Trait => Some(Ctx::Trait),
            Kind::Impl => Some(Ctx::Impl),
            Kind::ForeignMod => Some(Ctx::Extern),
            Kind::Fn => Some(Ctx::Block),
            _ => None,
        };
        if let (Some(ctx), true) = (ctx, open != NONE) {
            let end = if close != NONE { close as usize } else { f.end };
            return Some(Frame { pos: open as usize + 1, end, ctx, parent: idx, start: ctx == Ctx::Block, fresh: true });
        }
        if let Some((a, b)) = found.init {
            if a < b {
                return Some(Frame { pos: a, end: b, ctx: Ctx::Expr, parent: idx, start: false, fresh: false });
            }
        }
        None
    }
}
