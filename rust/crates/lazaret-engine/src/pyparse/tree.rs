//! The tree the parser builds: an arena of fixed-size nodes, the lists they
//! hold, an interned string table, and the source's line starts (see the
//! module docs in `mod.rs` for the layout and how to walk it).

/// A node's index in `Tree::nodes`.
pub type NodeId = u32;

/// No node: a `None` field, a dict's `**` key, a list or string that is absent.
pub const NONE: u32 = u32::MAX;

macro_rules! kinds {
    ($($k:ident),* $(,)?) => {
        /// A node's class: its name in Python's `ast` module.
        #[allow(non_camel_case_types)]
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Kind { $($k),* }

        impl Kind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Kind] = &[$(Kind::$k),*];
            /// The class name (`ast.<name>`).
            pub fn name(self) -> &'static str {
                const NAMES: &[&str] = &[$(stringify!($k)),*];
                NAMES[self as usize]
            }
        }
    };
}

kinds! {
    Module,
    // statements
    FunctionDef, AsyncFunctionDef, ClassDef, Return, Delete, Assign, TypeAlias, AugAssign, AnnAssign, For,
    AsyncFor, While, If, With, AsyncWith, Match, Raise, Try, TryStar, Assert, Import, ImportFrom, Global,
    Nonlocal, Expr, Pass, Break, Continue,
    // expressions
    BoolOp, NamedExpr, BinOp, UnaryOp, Lambda, IfExp, Dict, Set, ListComp, SetComp, DictComp, GeneratorExp,
    Await, Yield, YieldFrom, Compare, Call, FormattedValue, JoinedStr, Constant, Attribute, Subscript, Starred,
    Name, List, Tuple, Slice,
    // the other classes
    comprehension, ExceptHandler, arguments, arg, keyword, alias, withitem, match_case,
    // patterns
    MatchValue, MatchSingleton, MatchSequence, MatchMapping, MatchClass, MatchStar, MatchAs, MatchOr,
    // type parameters
    TypeVar, ParamSpec, TypeVarTuple,
}

impl Kind {
    /// Does the class have `lineno`, `col_offset`, `end_lineno` and
    /// `end_col_offset` (statements, expressions, handlers, arguments'
    /// `arg`, keywords, aliases, patterns, type parameters)?
    pub fn has_position(self) -> bool {
        !matches!(self, Kind::Module | Kind::comprehension | Kind::arguments | Kind::withitem | Kind::match_case)
    }

    /// Is it a statement?
    pub fn is_stmt(self) -> bool {
        (Kind::FunctionDef as u8..=Kind::Continue as u8).contains(&(self as u8))
    }

    /// Is it an expression?
    pub fn is_expr(self) -> bool {
        (Kind::BoolOp as u8..=Kind::Slice as u8).contains(&(self as u8))
    }

    /// Is it a pattern?
    pub fn is_pattern(self) -> bool {
        (Kind::MatchValue as u8..=Kind::MatchOr as u8).contains(&(self as u8))
    }
}

// ---- the small enumerations in `Node::op` ----

/// An expression's context (`ctx`): Load, Store, Del.
pub const CTX: &[&str] = &["Load", "Store", "Del"];
pub const LOAD: u8 = 0;
pub const STORE: u8 = 1;
pub const DEL: u8 = 2;

/// BoolOp's `op`.
pub const BOOLOPS: &[&str] = &["And", "Or"];
pub const AND: u8 = 0;
pub const OR: u8 = 1;

/// BinOp's and AugAssign's `op` (`ast.operator`).
pub const OPERATORS: &[&str] =
    &["Add", "Sub", "Mult", "MatMult", "Div", "Mod", "Pow", "LShift", "RShift", "BitOr", "BitXor", "BitAnd", "FloorDiv"];
pub const ADD: u8 = 0;
pub const SUB: u8 = 1;
pub const MULT: u8 = 2;
pub const MATMULT: u8 = 3;
pub const DIV: u8 = 4;
pub const MOD: u8 = 5;
pub const POW: u8 = 6;
pub const LSHIFT: u8 = 7;
pub const RSHIFT: u8 = 8;
pub const BITOR: u8 = 9;
pub const BITXOR: u8 = 10;
pub const BITAND: u8 = 11;
pub const FLOORDIV: u8 = 12;

/// UnaryOp's `op`.
pub const UNARYOPS: &[&str] = &["Invert", "Not", "UAdd", "USub"];
pub const INVERT: u8 = 0;
pub const NOT: u8 = 1;
pub const UADD: u8 = 2;
pub const USUB: u8 = 3;

/// Compare's `ops` (each item of the list is one of these).
pub const CMPOPS: &[&str] = &["Eq", "NotEq", "Lt", "LtE", "Gt", "GtE", "Is", "IsNot", "In", "NotIn"];
pub const EQ: u8 = 0;
pub const NOTEQ: u8 = 1;
pub const LT: u8 = 2;
pub const LTE: u8 = 3;
pub const GT: u8 = 4;
pub const GTE: u8 = 5;
pub const IS: u8 = 6;
pub const ISNOT: u8 = 7;
pub const IN: u8 = 8;
pub const NOTIN: u8 = 9;

/// FormattedValue's `conversion`: -1 (none), `!s`, `!r`, `!a`.
pub const CONVERSIONS: &[i32] = &[-1, 115, 114, 97];

/// A Constant's (and MatchSingleton's) value type, in `op`. A str, bytes or
/// int value is the string `f[A]` (bytes as code points below 256; an int
/// as its decimal digits, or `0x` and its hexadecimal digits past
/// `INT_DECIMAL_BITS` bits); a float is the f64 whose bits are `f[B]` (low)
/// and `f[C]` (high); a complex number is 0 plus that float times j.
pub const V_NONE: u8 = 0;
pub const V_TRUE: u8 = 1;
pub const V_FALSE: u8 = 2;
pub const V_ELLIPSIS: u8 = 3;
pub const V_STR: u8 = 4;
pub const V_BYTES: u8 = 5;
pub const V_INT: u8 = 6;
pub const V_FLOAT: u8 = 7;
pub const V_COMPLEX: u8 = 8;

/// An int up to this many bits is written in decimal, a larger one in
/// hexadecimal (`0x…`): every decimal literal Python reads (4,300 digits at
/// most) is below it, and converting a larger hexadecimal one to decimal
/// would take time quadratic in its length.
pub const INT_DECIMAL_BITS: u32 = 16384;

// ---- a node's flags (`Node::flags`) ----
/// comprehension: `is_async`
pub const ASYNC: u16 = 1 << 0;
/// AnnAssign: `simple`
pub const SIMPLE: u16 = 1 << 1;
/// Constant: `kind` is 'u'
pub const KIND_U: u16 = 1 << 2;
/// The parser's own: the expression came in parentheses (`(a)`), and the
/// node's span is inside them. Not a field.
pub const PAREN: u16 = 1 << 15;

/// One node: its kind, a small enumeration and flags, its span, and four
/// slots whose meaning the kind gives (`fields`). 28 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    /// A small enumeration: ctx, an operator, a conversion, a value type.
    pub op: u8,
    /// Boolean fields (ASYNC, SIMPLE, KIND_U) and PAREN.
    pub flags: u16,
    /// The code-point offset where the node starts (its first token).
    pub start: u32,
    /// The code-point offset just past the node's last token.
    pub end: u32,
    /// The slots A, B, C, D: node ids, list ids, string ids, an int.
    pub f: [u32; 4],
}

pub const A: u8 = 0;
pub const B: u8 = 1;
pub const C: u8 = 2;
pub const D: u8 = 3;

/// Where a field is kept: a slot of the node, or an item of the node's
/// extension list (FunctionDef, AsyncFunctionDef, ClassDef and arguments
/// have more fields than slots: slot D holds the id of a list of the rest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    Slot(u8),
    Ext(u8),
}

/// A field's type, and where the node keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    /// a child node, never absent
    Node(At),
    /// a child node or None
    Opt(At),
    /// a list of child nodes
    Nodes(At),
    /// a list of child nodes or Nones (Dict's keys, arguments' kw_defaults)
    OptNodes(At),
    /// a string (an id of the tree's string table)
    Str(At),
    /// a string or None
    OptStr(At),
    /// a list of strings
    Names(At),
    /// an int (ImportFrom's level)
    Int(At),
    /// a list of comparison operators (Compare's ops: CMPOPS)
    CmpOps(At),
    /// `op` read in a table of names: an `ast` class with no fields (ctx,
    /// an operator)
    Op(&'static [&'static str]),
    /// FormattedValue's conversion (CONVERSIONS[op])
    Conversion,
    /// a flag of `flags`, as the int 0 or 1
    Flag(u16),
    /// Constant's value (by `op`)
    Value,
    /// Constant's kind: 'u' or None
    ConstKind,
    /// MatchSingleton's value: None, True or False (`op`)
    Singleton,
    /// always None (type comments: the parser reads none)
    Null,
    /// always [] (Module's type_ignores)
    Empty,
}

/// A field: its name and type.
#[derive(Clone, Copy, Debug)]
pub struct Field {
    pub key: &'static str,
    pub ty: Ty,
}

macro_rules! f {
    ($key:literal, $ty:expr) => {
        Field { key: $key, ty: $ty }
    };
}

use At::{Ext, Slot};
use Ty::*;

const SA: At = Slot(A);
const SB: At = Slot(B);
const SC: At = Slot(C);
const SD: At = Slot(D);

/// The fields of each kind, in the order of its `_fields`.
pub fn fields(kind: Kind) -> &'static [Field] {
    use Kind::*;
    match kind {
        Module => &[f!("body", Nodes(SA)), f!("type_ignores", Empty)],
        FunctionDef | AsyncFunctionDef => &[
            f!("name", Str(SA)),
            f!("args", Node(SB)),
            f!("body", Nodes(SC)),
            f!("decorator_list", Nodes(Ext(0))),
            f!("returns", Opt(Ext(1))),
            f!("type_comment", Null),
            f!("type_params", Nodes(Ext(2))),
        ],
        ClassDef => &[
            f!("name", Str(SA)),
            f!("bases", Nodes(SB)),
            f!("keywords", Nodes(Ext(0))),
            f!("body", Nodes(SC)),
            f!("decorator_list", Nodes(Ext(1))),
            f!("type_params", Nodes(Ext(2))),
        ],
        Return => &[f!("value", Opt(SA))],
        Delete => &[f!("targets", Nodes(SA))],
        Assign => &[f!("targets", Nodes(SA)), f!("value", Node(SB)), f!("type_comment", Null)],
        TypeAlias => &[f!("name", Node(SA)), f!("type_params", Nodes(SB)), f!("value", Node(SC))],
        AugAssign => &[f!("target", Node(SA)), f!("op", Op(OPERATORS)), f!("value", Node(SB))],
        AnnAssign => &[
            f!("target", Node(SA)),
            f!("annotation", Node(SB)),
            f!("value", Opt(SC)),
            f!("simple", Flag(SIMPLE)),
        ],
        For | AsyncFor => &[
            f!("target", Node(SA)),
            f!("iter", Node(SB)),
            f!("body", Nodes(SC)),
            f!("orelse", Nodes(SD)),
            f!("type_comment", Null),
        ],
        While | If => &[f!("test", Node(SA)), f!("body", Nodes(SB)), f!("orelse", Nodes(SC))],
        With | AsyncWith => &[f!("items", Nodes(SA)), f!("body", Nodes(SB)), f!("type_comment", Null)],
        Match => &[f!("subject", Node(SA)), f!("cases", Nodes(SB))],
        Raise => &[f!("exc", Opt(SA)), f!("cause", Opt(SB))],
        Try | TryStar => {
            &[f!("body", Nodes(SA)), f!("handlers", Nodes(SB)), f!("orelse", Nodes(SC)), f!("finalbody", Nodes(SD))]
        }
        Assert => &[f!("test", Node(SA)), f!("msg", Opt(SB))],
        Import => &[f!("names", Nodes(SA))],
        ImportFrom => &[f!("module", OptStr(SA)), f!("names", Nodes(SB)), f!("level", Int(SC))],
        Global | Nonlocal => &[f!("names", Names(SA))],
        Expr => &[f!("value", Node(SA))],
        Pass | Break | Continue => &[],
        BoolOp => &[f!("op", Op(BOOLOPS)), f!("values", Nodes(SA))],
        NamedExpr => &[f!("target", Node(SA)), f!("value", Node(SB))],
        BinOp => &[f!("left", Node(SA)), f!("op", Op(OPERATORS)), f!("right", Node(SB))],
        UnaryOp => &[f!("op", Op(UNARYOPS)), f!("operand", Node(SA))],
        Lambda => &[f!("args", Node(SA)), f!("body", Node(SB))],
        IfExp => &[f!("test", Node(SA)), f!("body", Node(SB)), f!("orelse", Node(SC))],
        Dict => &[f!("keys", OptNodes(SA)), f!("values", Nodes(SB))],
        Set => &[f!("elts", Nodes(SA))],
        ListComp | SetComp | GeneratorExp => &[f!("elt", Node(SA)), f!("generators", Nodes(SB))],
        DictComp => &[f!("key", Node(SA)), f!("value", Node(SB)), f!("generators", Nodes(SC))],
        Await | YieldFrom => &[f!("value", Node(SA))],
        Yield => &[f!("value", Opt(SA))],
        Compare => &[f!("left", Node(SA)), f!("ops", CmpOps(SB)), f!("comparators", Nodes(SC))],
        Call => &[f!("func", Node(SA)), f!("args", Nodes(SB)), f!("keywords", Nodes(SC))],
        FormattedValue => &[f!("value", Node(SA)), f!("conversion", Conversion), f!("format_spec", Opt(SB))],
        JoinedStr => &[f!("values", Nodes(SA))],
        Constant => &[f!("value", Value), f!("kind", ConstKind)],
        Attribute => &[f!("value", Node(SA)), f!("attr", Str(SB)), f!("ctx", Op(CTX))],
        Subscript => &[f!("value", Node(SA)), f!("slice", Node(SB)), f!("ctx", Op(CTX))],
        Starred => &[f!("value", Node(SA)), f!("ctx", Op(CTX))],
        Name => &[f!("id", Str(SA)), f!("ctx", Op(CTX))],
        List | Tuple => &[f!("elts", Nodes(SA)), f!("ctx", Op(CTX))],
        Slice => &[f!("lower", Opt(SA)), f!("upper", Opt(SB)), f!("step", Opt(SC))],
        comprehension => {
            &[f!("target", Node(SA)), f!("iter", Node(SB)), f!("ifs", Nodes(SC)), f!("is_async", Flag(ASYNC))]
        }
        ExceptHandler => &[f!("type", Opt(SA)), f!("name", OptStr(SB)), f!("body", Nodes(SC))],
        arguments => &[
            f!("posonlyargs", Nodes(SA)),
            f!("args", Nodes(SB)),
            f!("vararg", Opt(SC)),
            f!("kwonlyargs", Nodes(Ext(0))),
            f!("kw_defaults", OptNodes(Ext(1))),
            f!("kwarg", Opt(Ext(2))),
            f!("defaults", Nodes(Ext(3))),
        ],
        arg => &[f!("arg", Str(SA)), f!("annotation", Opt(SB)), f!("type_comment", Null)],
        keyword => &[f!("arg", OptStr(SA)), f!("value", Node(SB))],
        alias => &[f!("name", Str(SA)), f!("asname", OptStr(SB))],
        withitem => &[f!("context_expr", Node(SA)), f!("optional_vars", Opt(SB))],
        match_case => &[f!("pattern", Node(SA)), f!("guard", Opt(SB)), f!("body", Nodes(SC))],
        MatchValue => &[f!("value", Node(SA))],
        MatchSingleton => &[f!("value", Singleton)],
        MatchSequence | MatchOr => &[f!("patterns", Nodes(SA))],
        MatchMapping => &[f!("keys", Nodes(SA)), f!("patterns", Nodes(SB)), f!("rest", OptStr(SC))],
        MatchClass => &[
            f!("cls", Node(SA)),
            f!("patterns", Nodes(SB)),
            f!("kwd_attrs", Names(SC)),
            f!("kwd_patterns", Nodes(SD)),
        ],
        MatchStar => &[f!("name", OptStr(SA))],
        MatchAs => &[f!("pattern", Opt(SA)), f!("name", OptStr(SB))],
        TypeVar => &[f!("name", Str(SA)), f!("bound", Opt(SB)), f!("default_value", Opt(SC))],
        ParamSpec | TypeVarTuple => &[f!("name", Str(SA)), f!("default_value", Opt(SB))],
    }
}

/// The number of items of a kind's extension list (0: it has none).
pub fn ext_len(kind: Kind) -> usize {
    match kind {
        Kind::FunctionDef | Kind::AsyncFunctionDef | Kind::ClassDef => 3,
        Kind::arguments => 4,
        _ => 0,
    }
}

// ---- the string table ----

/// Interned strings (code points): equal strings have equal ids.
#[derive(Clone, Debug)]
pub struct Strings {
    chars: Vec<u32>,
    spans: Vec<(u32, u32)>,
    hashes: Vec<u32>,
    /// open addressing: 0 empty, else id + 1
    slots: Vec<u32>,
}

#[inline]
fn hash(s: &[u32]) -> u32 {
    let mut h: u64 = s.len() as u64;
    for &c in s {
        h = (h.rotate_left(5) ^ c as u64).wrapping_mul(0x517c_c1b7_2722_0a95);
    }
    (h ^ (h >> 32)) as u32
}

/// The strings every table starts with, at these ids: the soft keywords
/// (`match`, `case`, `type`, `_`) and the empty string.
pub const S_MATCH: u32 = 0;
pub const S_CASE: u32 = 1;
pub const S_TYPE: u32 = 2;
pub const S_UNDERSCORE: u32 = 3;
pub const S_EMPTY: u32 = 4;
const SEEDED: &[&str] = &["match", "case", "type", "_", ""];

impl Default for Strings {
    fn default() -> Self {
        Strings::new()
    }
}

impl Strings {
    /// A table holding the seeded strings.
    pub fn new() -> Strings {
        let mut s = Strings { chars: Vec::new(), spans: Vec::new(), hashes: Vec::new(), slots: vec![0; 256] };
        for w in SEEDED {
            let cps: Vec<u32> = w.chars().map(|c| c as u32).collect();
            s.intern(&cps);
        }
        s
    }

    /// The number of strings.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The string `id` (empty for an id that is none).
    #[inline]
    pub fn get(&self, id: u32) -> &[u32] {
        match self.spans.get(id as usize) {
            Some(&(a, n)) => &self.chars[a as usize..(a + n) as usize],
            None => &[],
        }
    }

    /// The id of `s` (added if new).
    pub fn intern(&mut self, s: &[u32]) -> u32 {
        let h = hash(s);
        let mask = self.slots.len() - 1;
        let mut i = h as usize & mask;
        loop {
            let slot = self.slots[i];
            if slot == 0 {
                break;
            }
            let id = slot - 1;
            if self.hashes[id as usize] == h && self.get(id) == s {
                return id;
            }
            i = (i + 1) & mask;
        }
        let id = self.spans.len() as u32;
        self.spans.push((self.chars.len() as u32, s.len() as u32));
        self.chars.extend_from_slice(s);
        self.hashes.push(h);
        self.slots[i] = id + 1;
        if self.spans.len() * 2 > self.slots.len() {
            self.grow();
        }
        id
    }

    /// The id of `s` if the table holds it.
    pub fn find(&self, s: &[u32]) -> Option<u32> {
        let h = hash(s);
        let mask = self.slots.len() - 1;
        let mut i = h as usize & mask;
        loop {
            let slot = self.slots[i];
            if slot == 0 {
                return None;
            }
            let id = slot - 1;
            if self.hashes[id as usize] == h && self.get(id) == s {
                return Some(id);
            }
            i = (i + 1) & mask;
        }
    }

    fn grow(&mut self) {
        let size = self.slots.len() * 2;
        let mut slots = vec![0u32; size];
        let mask = size - 1;
        for (id, &h) in self.hashes.iter().enumerate() {
            let mut i = h as usize & mask;
            while slots[i] != 0 {
                i = (i + 1) & mask;
            }
            slots[i] = id as u32 + 1;
        }
        self.slots = slots;
    }
}

// ---- the tree ----

/// A parsed module: `nodes[root]` is its Module node.
#[derive(Clone, Debug)]
pub struct Tree {
    pub nodes: Vec<Node>,
    /// The lists: a list id is the index of its length, its items follow.
    /// List 0 is the empty list.
    pub lists: Vec<u32>,
    pub strings: Strings,
    pub root: NodeId,
    /// The code-point offset where each line starts (line 1 at index 0): a
    /// line ends at "\r\n", "\r" or "\n", as Python reads source text.
    pub line_starts: Vec<u32>,
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new()
    }
}

impl Tree {
    pub fn new() -> Tree {
        Tree { nodes: Vec::new(), lists: vec![0], strings: Strings::new(), root: NONE, line_starts: vec![0] }
    }

    /// The node `id`.
    #[inline]
    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    #[inline]
    pub fn kind(&self, id: NodeId) -> Kind {
        self.nodes[id as usize].kind
    }

    /// The items of list `id` (empty for NONE or an id that is no list).
    #[inline]
    pub fn list(&self, id: u32) -> &[u32] {
        let i = id as usize;
        match self.lists.get(i) {
            Some(&n) => self.lists.get(i + 1..i + 1 + n as usize).unwrap_or(&[]),
            None => &[],
        }
    }

    /// The string `id`.
    #[inline]
    pub fn str(&self, id: u32) -> &[u32] {
        self.strings.get(id)
    }

    /// A new list holding `items` (list 0 when empty).
    pub fn push_list(&mut self, items: &[u32]) -> u32 {
        if items.is_empty() {
            return 0;
        }
        let id = self.lists.len() as u32;
        self.lists.push(items.len() as u32);
        self.lists.extend_from_slice(items);
        id
    }

    /// The raw value of a field of node `n`: a slot, or an item of its
    /// extension list (NONE where the list is short).
    #[inline]
    pub fn raw(&self, n: &Node, at: At) -> u32 {
        match at {
            Slot(s) => n.f[s as usize],
            Ext(i) => self.list(n.f[D as usize]).get(i as usize).copied().unwrap_or(NONE),
        }
    }

    fn field(&self, id: NodeId, key: &str) -> Option<Ty> {
        fields(self.kind(id)).iter().find(|fd| fd.key == key).map(|fd| fd.ty)
    }

    /// The child node field `key` of node `id` (None when absent or None).
    pub fn child(&self, id: NodeId, key: &str) -> Option<NodeId> {
        let n = self.node(id);
        match self.field(id, key)? {
            Node(at) | Opt(at) => Some(self.raw(n, at)).filter(|&c| c != NONE),
            _ => None,
        }
    }

    /// The list field `key` of node `id` (empty when absent; a list of
    /// strings or of operators gives their ids or codes).
    pub fn children_of(&self, id: NodeId, key: &str) -> &[u32] {
        let n = self.node(id);
        match self.field(id, key) {
            Some(Nodes(at)) | Some(OptNodes(at)) | Some(Names(at)) | Some(CmpOps(at)) => self.list(self.raw(n, at)),
            _ => &[],
        }
    }

    /// The string field `key` of node `id` (a name, an attribute, a module).
    pub fn text_of(&self, id: NodeId, key: &str) -> Option<&[u32]> {
        let n = self.node(id);
        match self.field(id, key)? {
            Str(at) | OptStr(at) => {
                let s = self.raw(n, at);
                if s == NONE {
                    None
                } else {
                    Some(self.str(s))
                }
            }
            _ => None,
        }
    }

    /// Calls `visit` with each child of node `id` in field order (a list's
    /// items in order, Nones left out).
    pub fn each_child(&self, id: NodeId, mut visit: impl FnMut(NodeId)) {
        let n = self.node(id);
        for fd in fields(n.kind) {
            match fd.ty {
                Node(at) | Opt(at) => {
                    let c = self.raw(n, at);
                    if c != NONE {
                        visit(c);
                    }
                }
                Nodes(at) | OptNodes(at) => {
                    for &c in self.list(self.raw(n, at)) {
                        if c != NONE {
                            visit(c);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Each node's parent (NONE for the root), computed in one pass.
    pub fn parents(&self) -> Vec<NodeId> {
        let mut parent = vec![NONE; self.nodes.len()];
        for id in 0..self.nodes.len() as u32 {
            self.each_child(id, |c| {
                if let Some(p) = parent.get_mut(c as usize) {
                    *p = id;
                }
            });
        }
        parent
    }

    /// The line (1-based) of a code-point offset.
    pub fn line_of(&self, at: u32) -> u32 {
        self.line_starts.partition_point(|&s| s <= at).max(1) as u32
    }

    /// The tree from `self.root` alone, its nodes renumbered in document
    /// order (pre-order: a node before its children, children in field
    /// order), and the depth of the deepest node (the root is at depth 1).
    pub fn compact(mut self) -> (Tree, u32) {
        let mut out = Tree {
            nodes: Vec::with_capacity(self.nodes.len()),
            lists: Vec::with_capacity(self.lists.len()),
            strings: std::mem::take(&mut self.strings),
            root: NONE,
            line_starts: std::mem::take(&mut self.line_starts),
        };
        out.lists.push(0);
        if self.root == NONE {
            return (out, 0);
        }
        // pass 1: pre-order ids and depths, with an explicit stack (trees may be deep)
        let mut new_id: Vec<u32> = vec![NONE; self.nodes.len()];
        let mut order: Vec<NodeId> = Vec::with_capacity(self.nodes.len());
        let mut stack: Vec<(NodeId, u32)> = vec![(self.root, 1)];
        let mut kids: Vec<NodeId> = Vec::new();
        let mut deepest = 0;
        while let Some((id, depth)) = stack.pop() {
            if new_id[id as usize] != NONE {
                continue; // (a node reached twice: never built so; kept once)
            }
            new_id[id as usize] = order.len() as u32;
            order.push(id);
            deepest = deepest.max(depth);
            kids.clear();
            self.each_child(id, |c| kids.push(c));
            for &c in kids.iter().rev() {
                stack.push((c, depth + 1));
            }
        }
        let remap = |c: u32| if c == NONE { NONE } else { new_id.get(c as usize).copied().unwrap_or(NONE) };
        let mut new_ext: Vec<u32> = Vec::new();
        for &id in &order {
            let old = *self.node(id);
            let mut n = old;
            let xn = ext_len(n.kind);
            new_ext.clear();
            if xn > 0 {
                new_ext.extend_from_slice(self.list(old.f[D as usize]));
                new_ext.resize(xn, NONE);
            }
            for fd in fields(n.kind) {
                let value = match fd.ty {
                    Node(at) | Opt(at) => remap(self.raw(&old, at)),
                    Nodes(at) | OptNodes(at) => {
                        let items = self.list(self.raw(&old, at));
                        if items.is_empty() {
                            0
                        } else {
                            let lid = out.lists.len() as u32;
                            out.lists.push(items.len() as u32);
                            out.lists.extend(items.iter().map(|&c| remap(c)));
                            lid
                        }
                    }
                    Names(at) | CmpOps(at) => out.push_list(self.list(self.raw(&old, at))),
                    _ => continue,
                };
                match fd.ty {
                    Node(at) | Opt(at) | Nodes(at) | OptNodes(at) | Names(at) | CmpOps(at) => match at {
                        Slot(s) => n.f[s as usize] = value,
                        Ext(i) => {
                            if let Some(v) = new_ext.get_mut(i as usize) {
                                *v = value;
                            }
                        }
                    },
                    _ => {}
                }
            }
            if xn > 0 {
                // the extension list itself: always present, full length
                let lid = out.lists.len() as u32;
                out.lists.push(xn as u32);
                out.lists.extend_from_slice(&new_ext);
                n.f[D as usize] = lid;
            }
            n.flags &= !PAREN;
            out.nodes.push(n);
        }
        out.root = 0;
        (out, deepest)
    }
}

