//! The tree the parser builds: `go/ast`'s, in an arena of fixed-size nodes
//! (see the module docs in `mod.rs` for how to read it).

/// A node's index in `Tree::nodes`.
pub type NodeId = u32;

/// No node: a field that is absent, a list that is empty.
pub const NONE: u32 = u32::MAX;

macro_rules! kinds {
    ($($k:ident),* $(,)?) => {
        /// A node's type: `go/ast`'s name for it.
        #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum Kind { $($k),* }

        impl Kind {
            /// Every kind, in declaration order.
            pub const ALL: &'static [Kind] = &[$(Kind::$k),*];
            /// `go/ast`'s name for the kind (what `%T` prints without the package).
            pub fn name(self) -> &'static str {
                const NAMES: &[&str] = &[$(stringify!($k)),*];
                NAMES[self as usize]
            }
        }
    };
}

kinds! {
    File,
    // declarations and specs
    GenDecl, FuncDecl, ImportSpec, ValueSpec, TypeSpec,
    // parts
    Field, FieldList,
    // expressions
    Ident, Ellipsis, BasicLit, FuncLit, CompositeLit, ParenExpr, SelectorExpr, IndexExpr, IndexListExpr,
    SliceExpr, TypeAssertExpr, CallExpr, StarExpr, UnaryExpr, BinaryExpr, KeyValueExpr,
    // types
    ArrayType, StructType, FuncType, InterfaceType, MapType, ChanType,
    // statements
    DeclStmt, EmptyStmt, LabeledStmt, ExprStmt, SendStmt, IncDecStmt, AssignStmt, GoStmt, DeferStmt,
    ReturnStmt, BranchStmt, BlockStmt, IfStmt, CaseClause, SwitchStmt, TypeSwitchStmt, CommClause, SelectStmt,
    ForStmt, RangeStmt,
}

// ---- a node's flags (`Node::flags`) ----
/// GenDecl: written with parentheses.
pub const PAREN: u8 = 1 << 0;
/// TypeSpec: an alias (`type A = B`).
pub const ALIAS: u8 = 1 << 1;
/// CallExpr: the last argument is followed by `...`.
pub const ELLIPSIS: u8 = 1 << 2;
/// SliceExpr: `a[i:j:k]`.
pub const SLICE3: u8 = 1 << 3;
/// CompositeLit: elements were left out (an error was found in it).
pub const INCOMPLETE: u8 = 1 << 4;
/// EmptyStmt: the semicolon was inserted at a line break, not written.
pub const IMPLICIT: u8 = 1 << 5;
/// FieldList: written with its delimiters (`(…)`, `[…]` or `{…}`).
pub const DELIMITED: u8 = 1 << 6;

// ---- ChanType's direction (`Node::op`) ----
pub const CHAN_BOTH: u8 = 0;
/// `chan<- T`
pub const CHAN_SEND: u8 = 1;
/// `<-chan T`
pub const CHAN_RECV: u8 = 2;

/// One node: its kind, its span and four field slots whose meaning the kind
/// gives (`Kind`'s docs in `mod.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Node {
    pub kind: Kind,
    /// The operator or token of the kinds that have one (`scan::Tok as u8`): BasicLit's literal kind, UnaryExpr's
    /// and BinaryExpr's operator, AssignStmt's, IncDecStmt's, BranchStmt's, RangeStmt's (`:=` or `=`, or ILLEGAL for
    /// none) and GenDecl's keyword; for ChanType the direction.
    pub op: u8,
    pub flags: u8,
    /// Code-point offset where the node starts (`go/ast`'s `Pos`).
    pub start: u32,
    /// Code-point offset just past the node (`go/ast`'s `End`).
    pub end: u32,
    /// The slots A, B, C, D: node ids (NONE for none), or list ids (NONE for an empty list).
    pub f: [u32; 4],
}

/// The parsed file: an arena of nodes, and the lists they hold.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    pub nodes: Vec<Node>,
    /// A list id is an index here: `lists[id]` is the length and the items follow.
    pub lists: Vec<u32>,
    /// The File node.
    pub root: NodeId,
}

impl Tree {
    pub fn new() -> Tree {
        Tree { nodes: Vec::new(), lists: Vec::new(), root: NONE }
    }

    pub fn add(&mut self, kind: Kind, op: u8, flags: u8, start: u32, end: u32, f: [u32; 4]) -> NodeId {
        self.nodes.push(Node { kind, op, flags, start, end, f });
        (self.nodes.len() - 1) as NodeId
    }

    /// A new list holding `items`; NONE if there are none.
    pub fn list(&mut self, items: &[u32]) -> u32 {
        if items.is_empty() {
            return NONE;
        }
        let id = self.lists.len() as u32;
        self.lists.push(items.len() as u32);
        self.lists.extend_from_slice(items);
        id
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id as usize]
    }

    /// The items of a list (empty for NONE).
    pub fn items(&self, list: u32) -> &[u32] {
        if list == NONE {
            return &[];
        }
        let n = self.lists[list as usize] as usize;
        &self.lists[list as usize + 1..list as usize + 1 + n]
    }

    /// The children of `id` in the order `ast.Inspect` visits them.
    pub fn each_child(&self, id: NodeId, f: &mut dyn FnMut(NodeId)) {
        let n = self.node(id);
        let [a, b, c, d] = n.f;
        fn one(f: &mut dyn FnMut(NodeId), x: u32) {
            if x != NONE {
                f(x)
            }
        }
        match n.kind {
            Kind::File => {
                one(f, a);
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::Ident | Kind::BasicLit | Kind::EmptyStmt => {}
            Kind::GenDecl => {
                for &x in self.items(a) {
                    f(x);
                }
            }
            Kind::FuncDecl => {
                one(f, a);
                one(f, b);
                one(f, c);
                one(f, d);
            }
            Kind::ImportSpec => {
                one(f, a);
                one(f, b);
            }
            Kind::ValueSpec => {
                for &x in self.items(a) {
                    f(x);
                }
                one(f, b);
                for &x in self.items(c) {
                    f(x);
                }
            }
            Kind::TypeSpec => {
                one(f, a);
                one(f, b);
                one(f, c);
            }
            Kind::Field => {
                for &x in self.items(a) {
                    f(x);
                }
                one(f, b);
                one(f, c);
            }
            Kind::FieldList => {
                for &x in self.items(a) {
                    f(x);
                }
            }
            Kind::Ellipsis | Kind::ParenExpr | Kind::StarExpr | Kind::UnaryExpr | Kind::StructType
            | Kind::InterfaceType | Kind::ChanType | Kind::ExprStmt | Kind::IncDecStmt | Kind::GoStmt
            | Kind::DeferStmt | Kind::DeclStmt | Kind::SelectStmt | Kind::BranchStmt => one(f, a),
            Kind::FuncLit | Kind::SelectorExpr | Kind::IndexExpr | Kind::BinaryExpr | Kind::KeyValueExpr
            | Kind::ArrayType | Kind::MapType | Kind::LabeledStmt | Kind::SendStmt | Kind::TypeAssertExpr => {
                one(f, a);
                one(f, b);
            }
            Kind::CompositeLit => {
                one(f, a);
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::IndexListExpr => {
                one(f, a);
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::SliceExpr => {
                one(f, a);
                one(f, b);
                one(f, c);
                one(f, d);
            }
            Kind::CallExpr => {
                one(f, a);
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::FuncType => {
                one(f, a);
                one(f, b);
                one(f, c);
            }
            Kind::AssignStmt => {
                for &x in self.items(a) {
                    f(x);
                }
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::ReturnStmt | Kind::BlockStmt => {
                for &x in self.items(a) {
                    f(x);
                }
            }
            Kind::IfStmt | Kind::ForStmt | Kind::RangeStmt => {
                one(f, a);
                one(f, b);
                one(f, c);
                one(f, d);
            }
            Kind::CaseClause => {
                for &x in self.items(a) {
                    f(x);
                }
                for &x in self.items(b) {
                    f(x);
                }
            }
            Kind::SwitchStmt | Kind::TypeSwitchStmt => {
                one(f, a);
                one(f, b);
                one(f, c);
            }
            Kind::CommClause => {
                one(f, a);
                for &x in self.items(b) {
                    f(x);
                }
            }
        }
    }

    /// Every node reachable from the root, in the order `ast.Inspect` visits them (no recursion: a tree can be as deep
    /// as the parser lets it be).
    pub fn preorder(&self, mut visit: impl FnMut(NodeId)) {
        if self.root == NONE {
            return;
        }
        let mut stack = vec![self.root];
        let mut kids: Vec<u32> = Vec::new();
        while let Some(id) = stack.pop() {
            visit(id);
            kids.clear();
            self.each_child(id, &mut |x| kids.push(x));
            stack.extend(kids.iter().rev());
        }
    }
}
