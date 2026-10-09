//! The tree the parser builds: an arena of fixed-size nodes, the lists
//! they hold, and an interned string table (see the module docs in
//! `mod.rs` for the layout and how to walk it).

use super::scan::LITERALS;

/// A node's index in `Tree::nodes`.
pub type NodeId = u32;

/// No node: a null field, an array hole, a list or string that is absent.
pub const NONE: u32 = u32::MAX;

macro_rules! kinds {
    ($($k:ident),* $(,)?) => {
        /// A node's type: ESTree's name for it (acorn's and acorn-jsx's, and
        /// jsparse.py's TypeScript nodes).
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Kind { $($k),* }

        impl Kind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Kind] = &[$(Kind::$k),*];
            /// The node's `type` in the tree's JSON.
            pub fn name(self) -> &'static str {
                const NAMES: &[&str] = &[$(stringify!($k)),*];
                NAMES[self as usize]
            }
        }
    };
}

kinds! {
    Program, EmptyStatement, ExpressionStatement, BlockStatement, StaticBlock, IfStatement, WhileStatement,
    DoWhileStatement, ForStatement, ForInStatement, ForOfStatement, ReturnStatement, BreakStatement,
    ContinueStatement, ThrowStatement, TryStatement, CatchClause, SwitchStatement, SwitchCase, WithStatement,
    DebuggerStatement, LabeledStatement, VariableDeclaration, VariableDeclarator, FunctionDeclaration,
    FunctionExpression, ArrowFunctionExpression, ClassDeclaration, ClassExpression, ClassBody, MethodDefinition,
    PropertyDefinition, Identifier, PrivateIdentifier, Literal, TemplateLiteral, TemplateElement,
    TaggedTemplateExpression, ArrayPattern, ObjectPattern, Property, RestElement, AssignmentPattern,
    ImportDeclaration, ImportDefaultSpecifier, ImportNamespaceSpecifier, ImportSpecifier, ExportNamedDeclaration,
    ExportSpecifier, ExportDefaultDeclaration, ExportAllDeclaration, TSExportAssignment, TSImportEquals,
    TSEnumDeclaration, TSEnumMember, TSModuleDeclaration, SequenceExpression, AssignmentExpression,
    YieldExpression, ConditionalExpression, LogicalExpression, BinaryExpression, UnaryExpression,
    UpdateExpression, AwaitExpression, MemberExpression, CallExpression, ChainExpression, NewExpression,
    MetaProperty, ImportExpression, ThisExpression, Super, ArrayExpression, ObjectExpression, SpreadElement,
    JSXElement, JSXFragment, JSXOpeningElement, JSXClosingElement, JSXIdentifier, JSXNamespacedName,
    JSXMemberExpression, JSXAttribute, JSXSpreadAttribute, JSXExpressionContainer, JSXEmptyExpression,
    JSXSpreadChild, JSXText,
}

// ---- a node's boolean fields (`Node::flags`) ----
pub const COMPUTED: u16 = 1 << 0;
pub const OPTIONAL: u16 = 1 << 1;
pub const GENERATOR: u16 = 1 << 2;
pub const ASYNC: u16 = 1 << 3;
pub const EXPRESSION: u16 = 1 << 4;
pub const STATIC: u16 = 1 << 5;
pub const METHOD: u16 = 1 << 6;
pub const SHORTHAND: u16 = 1 << 7;
pub const PREFIX: u16 = 1 << 8;
pub const DELEGATE: u16 = 1 << 9;
pub const TAIL: u16 = 1 << 10;
pub const AWAIT: u16 = 1 << 11;
pub const SELF_CLOSING: u16 = 1 << 12;
/// TSImportEquals: `export import x = …` (the `exported` key, written only when set)
pub const EXPORTED: u16 = 1 << 13;
/// Literal of kind boolean: its value
pub const VALUE: u16 = 1 << 14;

// ---- the small enumerations in `Node::op` ----
/// VariableDeclaration's `kind`.
pub const VAR_KINDS: &[&str] = &["var", "let", "const", "using", "await using"];
pub const VAR: u8 = 0;
pub const LET: u8 = 1;
pub const CONST: u8 = 2;
pub const USING: u8 = 3;
pub const AWAIT_USING: u8 = 4;
/// MethodDefinition's `kind`.
pub const METHOD_KINDS: &[&str] = &["constructor", "method", "get", "set"];
pub const M_CONSTRUCTOR: u8 = 0;
pub const M_METHOD: u8 = 1;
pub const M_GET: u8 = 2;
pub const M_SET: u8 = 3;
/// Property's `kind`.
pub const PROPERTY_KINDS: &[&str] = &["init", "get", "set"];
pub const P_INIT: u8 = 0;
pub const P_GET: u8 = 1;
pub const P_SET: u8 = 2;
/// Literal's `kind`.
pub const LITERAL_KINDS: &[&str] = &["string", "number", "bigint", "boolean", "null", "regex"];
pub const L_STRING: u8 = 0;
pub const L_NUMBER: u8 = 1;
pub const L_BIGINT: u8 = 2;
pub const L_BOOLEAN: u8 = 3;
pub const L_NULL: u8 = 4;
pub const L_REGEX: u8 = 5;

/// One node: its kind, line and span, and four field slots whose meaning
/// the kind gives (`fields`). 32 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    /// A small enumeration (see `fields`: `Ty::Op`, `Ty::Operator`).
    pub op: u8,
    /// Boolean fields (COMPUTED, OPTIONAL, …).
    pub flags: u16,
    /// The line the node starts on (1-based), as jsparse.py gives it.
    pub line: u32,
    /// The code-point offset where the token the line is taken from starts.
    pub start: u32,
    /// The code-point offset just past the node's last token.
    pub end: u32,
    /// The field slots A, B, C, D: node ids, list ids or string ids.
    pub f: [u32; 4],
}

pub const A: u8 = 0;
pub const B: u8 = 1;
pub const C: u8 = 2;
pub const D: u8 = 3;

/// A field's type and where the node holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    /// a child node, never absent
    Node(u8),
    /// a child node or null
    Opt(u8),
    /// a list of child nodes
    List(u8),
    /// a list of child nodes or nulls (an array's holes)
    Holes(u8),
    /// a string (an id of the tree's string table)
    Str(u8),
    /// a boolean: a bit of `flags`
    Flag(u16),
    /// a string from a table, indexed by `op`
    Op(&'static [&'static str]),
    /// an operator: `op` is the literal id of its text (scan::LITERALS)
    Operator,
    /// always null
    Null,
    /// always false
    False,
    /// `decorators`: a list in slot D, written only when the node has some
    Decorators,
    /// `exported`: true, written only when the EXPORTED flag is set
    Exported,
    /// Literal's `value`: a string (slot A), a boolean (VALUE) or null, by its kind
    LitValue,
    /// Literal's `flags`: a regex's (slot B), written only for a regex
    LitFlags,
}

/// A field: its key in the tree's JSON and its type.
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

use Ty::*;

/// The fields of each kind, in the order jsparse.py's nodes hold them
/// (after `type` and `line`).
pub fn fields(kind: Kind) -> &'static [Field] {
    use Kind::*;
    match kind {
        Program | BlockStatement | StaticBlock | ClassBody => &[f!("body", List(A))],
        EmptyStatement | DebuggerStatement | ThisExpression | Super | JSXEmptyExpression => &[],
        ExpressionStatement => &[f!("expression", Node(A))],
        IfStatement => &[f!("test", Node(A)), f!("consequent", Node(B)), f!("alternate", Opt(C))],
        WhileStatement => &[f!("test", Node(A)), f!("body", Node(B))],
        DoWhileStatement => &[f!("body", Node(A)), f!("test", Node(B))],
        ForStatement => &[f!("init", Opt(A)), f!("test", Opt(B)), f!("update", Opt(C)), f!("body", Node(D))],
        ForInStatement => &[f!("left", Node(A)), f!("right", Node(B)), f!("body", Node(C))],
        ForOfStatement => &[f!("left", Node(A)), f!("right", Node(B)), f!("body", Node(C)), f!("await", Flag(AWAIT))],
        ReturnStatement => &[f!("argument", Opt(A))],
        BreakStatement | ContinueStatement => &[f!("label", Opt(A))],
        ThrowStatement => &[f!("argument", Node(A))],
        TryStatement => &[f!("block", Node(A)), f!("handler", Opt(B)), f!("finalizer", Opt(C))],
        CatchClause => &[f!("param", Opt(A)), f!("body", Node(B))],
        SwitchStatement => &[f!("discriminant", Node(A)), f!("cases", List(B))],
        SwitchCase => &[f!("test", Opt(A)), f!("consequent", List(B))],
        WithStatement => &[f!("object", Node(A)), f!("body", Node(B))],
        LabeledStatement => &[f!("label", Node(A)), f!("body", Node(B))],
        VariableDeclaration => &[f!("kind", Op(VAR_KINDS)), f!("declarations", List(A))],
        VariableDeclarator => &[f!("id", Node(A)), f!("init", Opt(B))],
        FunctionDeclaration | FunctionExpression => &[
            f!("id", Opt(A)),
            f!("params", List(B)),
            f!("body", Node(C)),
            f!("generator", Flag(GENERATOR)),
            f!("async", Flag(ASYNC)),
        ],
        ArrowFunctionExpression => &[
            f!("id", Null),
            f!("params", List(B)),
            f!("body", Node(C)),
            f!("expression", Flag(EXPRESSION)),
            f!("generator", False),
            f!("async", Flag(ASYNC)),
        ],
        ClassDeclaration | ClassExpression => {
            &[f!("id", Opt(A)), f!("superClass", Opt(B)), f!("body", Node(C)), f!("decorators", Decorators)]
        }
        MethodDefinition => &[
            f!("key", Node(A)),
            f!("value", Node(B)),
            f!("kind", Op(METHOD_KINDS)),
            f!("static", Flag(STATIC)),
            f!("computed", Flag(COMPUTED)),
            f!("decorators", Decorators),
        ],
        PropertyDefinition => &[
            f!("key", Node(A)),
            f!("value", Opt(B)),
            f!("static", Flag(STATIC)),
            f!("computed", Flag(COMPUTED)),
            f!("decorators", Decorators),
        ],
        Identifier => &[f!("name", Str(A)), f!("decorators", Decorators)],
        PrivateIdentifier | JSXIdentifier => &[f!("name", Str(A))],
        Literal => &[f!("kind", Op(LITERAL_KINDS)), f!("value", LitValue), f!("flags", LitFlags)],
        TemplateLiteral => &[f!("quasis", List(A)), f!("expressions", List(B))],
        TemplateElement => &[f!("raw", Str(A)), f!("tail", Flag(TAIL))],
        TaggedTemplateExpression => &[f!("tag", Node(A)), f!("quasi", Node(B))],
        ArrayPattern => &[f!("elements", Holes(A)), f!("decorators", Decorators)],
        ObjectPattern => &[f!("properties", List(A)), f!("decorators", Decorators)],
        Property => &[
            f!("key", Node(A)),
            f!("value", Node(B)),
            f!("kind", Op(PROPERTY_KINDS)),
            f!("method", Flag(METHOD)),
            f!("shorthand", Flag(SHORTHAND)),
            f!("computed", Flag(COMPUTED)),
        ],
        RestElement | SpreadElement | AwaitExpression | JSXSpreadAttribute => &[f!("argument", Node(A))],
        AssignmentPattern => &[f!("left", Node(A)), f!("right", Node(B)), f!("decorators", Decorators)],
        ImportDeclaration => &[f!("specifiers", List(A)), f!("source", Node(B))],
        ImportDefaultSpecifier | ImportNamespaceSpecifier => &[f!("local", Node(A))],
        ImportSpecifier => &[f!("imported", Node(A)), f!("local", Node(B))],
        ExportNamedDeclaration => &[f!("declaration", Opt(A)), f!("specifiers", List(B)), f!("source", Opt(C))],
        ExportSpecifier => &[f!("local", Node(A)), f!("exported", Node(B))],
        ExportDefaultDeclaration => &[f!("declaration", Node(A))],
        ExportAllDeclaration => &[f!("exported", Opt(A)), f!("source", Node(B))],
        TSExportAssignment | ChainExpression | JSXExpressionContainer | JSXSpreadChild => {
            &[f!("expression", Node(A))]
        }
        TSImportEquals => &[f!("id", Node(A)), f!("module", Opt(B)), f!("entity", Opt(C)), f!("exported", Exported)],
        TSEnumDeclaration => &[f!("id", Node(A)), f!("members", List(B))],
        TSEnumMember => &[f!("id", Node(A)), f!("initializer", Opt(B))],
        TSModuleDeclaration => &[f!("id", Node(A)), f!("body", Node(B))],
        SequenceExpression => &[f!("expressions", List(A))],
        AssignmentExpression | LogicalExpression | BinaryExpression => {
            &[f!("operator", Operator), f!("left", Node(A)), f!("right", Node(B))]
        }
        YieldExpression => &[f!("argument", Opt(A)), f!("delegate", Flag(DELEGATE))],
        ConditionalExpression => &[f!("test", Node(A)), f!("consequent", Node(B)), f!("alternate", Node(C))],
        UnaryExpression | UpdateExpression => {
            &[f!("operator", Operator), f!("prefix", Flag(PREFIX)), f!("argument", Node(A))]
        }
        MemberExpression => &[
            f!("object", Node(A)),
            f!("property", Node(B)),
            f!("computed", Flag(COMPUTED)),
            f!("optional", Flag(OPTIONAL)),
        ],
        CallExpression => &[f!("callee", Node(A)), f!("arguments", List(B)), f!("optional", Flag(OPTIONAL))],
        NewExpression => &[f!("callee", Node(A)), f!("arguments", List(B))],
        MetaProperty => &[f!("meta", Node(A)), f!("property", Node(B))],
        ImportExpression => &[f!("source", Node(A)), f!("options", Opt(B))],
        ArrayExpression => &[f!("elements", Holes(A))],
        ObjectExpression => &[f!("properties", List(A))],
        JSXElement => &[f!("openingElement", Node(A)), f!("closingElement", Opt(B)), f!("children", List(C))],
        JSXFragment => &[f!("children", List(A))],
        JSXOpeningElement => &[f!("name", Node(A)), f!("attributes", List(B)), f!("selfClosing", Flag(SELF_CLOSING))],
        JSXClosingElement => &[f!("name", Node(A))],
        JSXNamespacedName => &[f!("namespace", Node(A)), f!("name", Node(B))],
        JSXMemberExpression => &[f!("object", Node(A)), f!("property", Node(B))],
        JSXAttribute => &[f!("name", Node(A)), f!("value", Opt(B))],
        JSXText => &[f!("value", Str(A))],
    }
}

/// The node slot a kind keeps a field in, by the field's key (None: the
/// kind has no such node, list or string field).
pub fn slot(kind: Kind, key: &str) -> Option<u8> {
    fields(kind).iter().find(|fd| fd.key == key).and_then(|fd| match fd.ty {
        Node(s) | Opt(s) | List(s) | Holes(s) | Str(s) => Some(s),
        Decorators => Some(D),
        LitValue => Some(A),
        LitFlags => Some(B),
        _ => None,
    })
}

// ---- the string table ----

/// Interned strings (code points): equal strings have equal ids. Ids
/// `0..LITERALS.len()` are the literals of `scan::LITERALS`, in order.
#[derive(Clone, Debug, Default)]
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

impl Strings {
    /// A table holding the literals (built once, cloned).
    pub fn with_literals() -> Strings {
        static BASE: std::sync::OnceLock<Strings> = std::sync::OnceLock::new();
        BASE.get_or_init(|| {
            let mut s = Strings { slots: vec![0; 512], ..Strings::default() };
            for lit in LITERALS {
                let cps: Vec<u32> = lit.chars().map(|c| c as u32).collect();
                s.intern(&cps);
            }
            debug_assert_eq!(s.len(), LITERALS.len());
            s
        })
        .clone()
    }

    /// The number of strings.
    pub fn len(&self) -> usize {
        self.spans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    /// The string `id`.
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

/// A parsed program: `nodes[root]` is its Program node.
#[derive(Clone, Debug)]
pub struct Tree {
    pub nodes: Vec<Node>,
    /// The lists: a list id is the index of its length, its items follow.
    /// List 0 is the empty list.
    pub lists: Vec<u32>,
    pub strings: Strings,
    pub root: NodeId,
    /// The JavaScript reading took an HTML-like `<!--` for a comment after
    /// the program's first token (F-12): V8 reads a script so, but tsc reads
    /// `<` `!` `--` there, which may be code it runs (parser.rs, skip()).
    pub html_after_code: bool,
}

impl Tree {
    pub fn new() -> Tree {
        Tree { nodes: Vec::new(), lists: vec![0], strings: Strings::with_literals(), root: NONE, html_after_code: false }
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

    /// The items of list `id` (empty for NONE).
    #[inline]
    pub fn list(&self, id: u32) -> &[u32] {
        if id == NONE {
            return &[];
        }
        let i = id as usize;
        let n = self.lists[i] as usize;
        &self.lists[i + 1..i + 1 + n]
    }

    /// The string `id`.
    #[inline]
    pub fn str(&self, id: u32) -> &[u32] {
        self.strings.get(id)
    }

    /// The child node field `key` of node `id` (None when null or absent).
    pub fn child(&self, id: NodeId, key: &str) -> Option<NodeId> {
        let n = self.node(id);
        match fields(n.kind).iter().find(|fd| fd.key == key)?.ty {
            Node(s) | Opt(s) => Some(n.f[s as usize]).filter(|&c| c != NONE),
            _ => None,
        }
    }

    /// The list field `key` of node `id` (empty when absent).
    pub fn children_of(&self, id: NodeId, key: &str) -> &[NodeId] {
        let n = self.node(id);
        match fields(n.kind).iter().find(|fd| fd.key == key).map(|fd| fd.ty) {
            Some(List(s)) | Some(Holes(s)) => self.list(n.f[s as usize]),
            Some(Decorators) => self.list(n.f[D as usize]),
            _ => &[],
        }
    }

    /// The string field `key` of node `id` (a name, a value, a raw text).
    pub fn text_of(&self, id: NodeId, key: &str) -> Option<&[u32]> {
        let n = self.node(id);
        match fields(n.kind).iter().find(|fd| fd.key == key)?.ty {
            Str(s) => Some(self.str(n.f[s as usize])),
            LitValue if matches!(n.op, L_STRING | L_NUMBER | L_BIGINT | L_REGEX) => Some(self.str(n.f[A as usize])),
            LitFlags if n.op == L_REGEX => Some(self.str(n.f[B as usize])),
            _ => None,
        }
    }

    /// An operator node's operator (`+`, `typeof`, `>>>=` …).
    pub fn operator(&self, id: NodeId) -> &'static str {
        LITERALS.get(self.node(id).op as usize).copied().unwrap_or("")
    }

    /// Calls `visit` with each child of node `id` in field order (a list's
    /// items in order, holes left out).
    pub fn each_child(&self, id: NodeId, mut visit: impl FnMut(NodeId)) {
        let n = self.node(id);
        for fd in fields(n.kind) {
            match fd.ty {
                Node(s) | Opt(s) => {
                    let c = n.f[s as usize];
                    if c != NONE {
                        visit(c);
                    }
                }
                List(s) | Holes(s) => {
                    for &c in self.list(n.f[s as usize]) {
                        if c != NONE {
                            visit(c);
                        }
                    }
                }
                Decorators => {
                    for &c in self.list(n.f[D as usize]) {
                        visit(c);
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
            self.each_child(id, |c| parent[c as usize] = id);
        }
        parent
    }

    /// The tree from `self.root` alone, its nodes renumbered in document
    /// order (pre-order: a node before its children, children in field
    /// order): what parsing built and left behind (a speculative read's or
    /// a cover grammar's nodes, the expressions inside types) is dropped.
    pub fn compact(mut self) -> Tree {
        let root = self.root;
        let strings = std::mem::take(&mut self.strings);
        let html_after_code = self.html_after_code;
        if root == NONE {
            return Tree { nodes: Vec::new(), lists: vec![0], strings, root: NONE, html_after_code };
        }
        let mut out =
            Tree { nodes: Vec::with_capacity(self.nodes.len()), lists: vec![0], strings, root: NONE, html_after_code };
        // pass 1: pre-order ids, with an explicit stack (trees may be deep)
        let mut stack: Vec<NodeId> = vec![root];
        let mut order: Vec<NodeId> = Vec::with_capacity(self.nodes.len());
        let mut kids: Vec<NodeId> = Vec::new();
        while let Some(id) = stack.pop() {
            order.push(id);
            kids.clear();
            self.each_child(id, |c| kids.push(c));
            for &c in kids.iter().rev() {
                stack.push(c);
            }
        }
        // a node reached twice would be copied twice: give each visit its own id
        let mut new_id: Vec<u32> = vec![NONE; self.nodes.len()];
        let mut seen_twice = false;
        for (k, &id) in order.iter().enumerate() {
            if new_id[id as usize] != NONE {
                seen_twice = true;
            }
            new_id[id as usize] = k as u32;
        }
        if seen_twice {
            let strings = std::mem::take(&mut out.strings);
            return self.compact_by_copy(root, strings);
        }
        for &id in &order {
            let mut n = *self.node(id);
            for fd in fields(n.kind) {
                match fd.ty {
                    Node(s) | Opt(s) => {
                        let c = n.f[s as usize];
                        n.f[s as usize] = if c == NONE { NONE } else { new_id[c as usize] };
                    }
                    List(s) | Holes(s) => n.f[s as usize] = out.copy_list(self.list(n.f[s as usize]), &new_id),
                    Decorators => {
                        let d = n.f[D as usize];
                        n.f[D as usize] = if d == NONE { NONE } else { out.copy_list(self.list(d), &new_id) };
                    }
                    _ => {}
                }
            }
            if n.kind == Kind::Property {
                n.f[C as usize] = NONE; // (the cover initializer: never in a finished tree)
            }
            out.nodes.push(n);
        }
        out.root = 0;
        out
    }

    fn copy_list(&mut self, items: &[u32], new_id: &[u32]) -> u32 {
        if items.is_empty() {
            return 0;
        }
        let id = self.lists.len() as u32;
        self.lists.push(items.len() as u32);
        for &c in items {
            self.lists.push(if c == NONE { NONE } else { new_id[c as usize] });
        }
        id
    }

    /// compact() for a tree that holds a node twice: each place gets a copy.
    fn compact_by_copy(&self, root: NodeId, strings: Strings) -> Tree {
        let mut out = Tree { nodes: Vec::new(), lists: vec![0], strings, root: NONE, html_after_code: self.html_after_code };
        // (old id, the slot in `out` to point at it: (node index, slot) or a list position)
        enum At {
            Root,
            Slot(u32, u8),
            Item(u32),
        }
        let mut stack: Vec<(NodeId, At)> = vec![(root, At::Root)];
        while let Some((id, at)) = stack.pop() {
            let me = out.nodes.len() as u32;
            let n = *self.node(id);
            out.nodes.push(n);
            match at {
                At::Root => out.root = me,
                At::Slot(p, s) => out.nodes[p as usize].f[s as usize] = me,
                At::Item(pos) => out.lists[pos as usize] = me,
            }
            let mut pending: Vec<(NodeId, At)> = Vec::new();
            for fd in fields(n.kind) {
                match fd.ty {
                    Node(s) | Opt(s) => {
                        let c = n.f[s as usize];
                        if c != NONE {
                            pending.push((c, At::Slot(me, s)));
                        }
                    }
                    List(_) | Holes(_) | Decorators => {
                        let s = match fd.ty {
                            List(s) | Holes(s) => s,
                            _ => D,
                        };
                        let old = n.f[s as usize];
                        if old == NONE {
                            continue;
                        }
                        let items = self.list(old);
                        let lid = if items.is_empty() { 0 } else { out.lists.len() as u32 };
                        if !items.is_empty() {
                            out.lists.push(items.len() as u32);
                            for (k, &c) in items.iter().enumerate() {
                                out.lists.push(NONE);
                                if c != NONE {
                                    pending.push((c, At::Item(lid + 1 + k as u32)));
                                }
                            }
                        }
                        out.nodes[me as usize].f[s as usize] = lid;
                    }
                    _ => {}
                }
            }
            if n.kind == Kind::Property {
                out.nodes[me as usize].f[C as usize] = NONE;
            }
            for p in pending.into_iter().rev() {
                stack.push(p);
            }
        }
        out
    }
}

impl Default for Tree {
    fn default() -> Self {
        Tree::new()
    }
}
