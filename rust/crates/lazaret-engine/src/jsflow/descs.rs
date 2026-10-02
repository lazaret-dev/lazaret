//! What names and expressions may hold (jsflow.py's points-to): functions,
//! classes and their instances, object literals, modules, built-ins,
//! packages; the project functions a call may reach; route handlers; the
//! order the fixpoint reads functions in.

use super::*;

/// What an expression may be (jsflow.py's descriptor tuples).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum D {
    Fn(FnId),
    Class(ClassId),
    Inst(ClassId),
    Obj(ObjId),
    Mod(ModId),
    Builtin(PyStr),
    Pkg(PyStr),
    Open(PyStr),
    Global(PyStr),
    Local,
    Unknown,
}

/// How a call's targets were found: by binding only ("definite"), by name
/// only ("open"), both ("mixed"), or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    Definite,
    Open,
    Mixed,
    None,
}

/// `dict.fromkeys(xs)`: the items in order, each once.
pub(crate) fn dedupe<T: Clone + Eq + std::hash::Hash>(xs: Vec<T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::with_capacity(xs.len());
    xs.into_iter().filter(|x| seen.insert(x.clone())).collect()
}

fn unknown() -> Vec<D> {
    vec![D::Unknown]
}

fn dotted(a: &[u32], b: &[u32]) -> PyStr {
    let mut out = a.to_vec();
    out.push(0x2E);
    out.extend_from_slice(b);
    out
}

impl Program {
    pub fn descs_of_bind(&mut self, b: BindId, depth: u32) -> Rc<Vec<D>> {
        if let Some(got) = self.desc_memo.get(&b) {
            return got.clone();
        }
        if depth > ALIAS_DEPTH {
            return Rc::new(unknown());
        }
        // (a cycle reads as unknown)
        self.desc_memo.insert(b, Rc::new(unknown()));
        let writes = self.binds[b as usize].writes.clone();
        let (bmod, bname) = (self.binds[b as usize].module, self.binds[b as usize].name.clone());
        let mut out: Vec<D> = Vec::new();
        for w in writes {
            match w {
                Write::Fn { fid, .. } => out.push(D::Fn(fid)),
                Write::Class { cid, .. } => out.push(D::Class(cid)),
                Write::Import { spec, name, .. } => {
                    let target = self.resolve_spec(bmod, &spec);
                    if eq(&name, "*") || eq(&name, "=") {
                        out.push(target);
                    } else {
                        match target {
                            D::Mod(idx) => out.extend(self.member_descs(idx, &name, depth + 1, 0)),
                            D::Builtin(t) => out.push(D::Builtin(dotted(&t, &name))),
                            _ => out.push(D::Open(if eq(&name, "default") { bname.clone() } else { name.clone() })),
                        }
                    }
                }
                Write::Init { node, scope, path } | Write::Assign { node, scope, path } => {
                    let mut ds: Vec<D> = self.descs_of_expr(bmod, node, scope, depth + 1);
                    for name in &path {
                        match name {
                            None => {
                                ds = unknown();
                                break;
                            }
                            Some(name) => {
                                let mut next = Vec::new();
                                for d in &ds {
                                    next.extend(self.member_of(d, name, depth + 1));
                                }
                                ds = next;
                            }
                        }
                    }
                    out.extend(ds);
                }
                _ => out.push(D::Local),
            }
        }
        let mut out = dedupe(out);
        if out.is_empty() {
            out.push(D::Local);
        }
        let out = Rc::new(out);
        self.desc_memo.insert(b, out.clone());
        out
    }

    /// What an expression may be.
    pub fn descs_of_expr(&mut self, m: ModId, node: NodeId, scope: ScopeId, depth: u32) -> Vec<D> {
        use jt::{A, B, C};
        if depth > ALIAS_DEPTH {
            return unknown();
        }
        let t = self.mods[m as usize].tree.nodes[node as usize].kind;
        match t {
            Kind::Identifier => {
                let b = self.mods[m as usize].bind_at[node as usize];
                let b = if b == UNSET {
                    let name = Ast(&self.mods[m as usize].tree).name(node).to_vec();
                    self.lookup(scope, &name)
                } else if b == GLOBAL {
                    None
                } else {
                    Some(b)
                };
                match b {
                    None => vec![D::Global(Ast(&self.mods[m as usize].tree).name(node).to_vec())],
                    Some(b) => (*self.descs_of_bind(b, depth)).clone(),
                }
            }
            Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression => {
                vec![D::Fn(self.mods[m as usize].fid_at[node as usize])]
            }
            Kind::ClassExpression => vec![D::Class(self.mods[m as usize].cid_at[node as usize])],
            Kind::ObjectExpression => vec![D::Obj(self.mods[m as usize].oid_at[node as usize])],
            Kind::CallExpression => {
                let (callee, args) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.at(node, A), a.list(node, B).to_vec())
                };
                let is_require = Ast(&self.mods[m as usize].tree).is_ident_named(callee, "require");
                if is_require && !args.is_empty() && self.lookup(scope, &u("require")).is_none() {
                    let a = Ast(&self.mods[m as usize].tree);
                    let arg = args[0];
                    let fmod = self.fns[self.scopes[scope as usize].fid as usize].module;
                    if let Some(v) = a.str_value(arg) {
                        let v = v.to_vec();
                        return vec![self.resolve_spec(fmod, &v)];
                    }
                    if a.kind(arg) == Kind::TemplateLiteral && a.list(arg, B).is_empty() {
                        let q = a.list(arg, A);
                        let raw = q.first().map(|&e| a.s(e, A).to_vec()).unwrap_or_default();
                        return vec![self.resolve_spec(fmod, &raw)];
                    }
                }
                unknown()
            }
            Kind::NewExpression => {
                let callee = Ast(&self.mods[m as usize].tree).at(node, A);
                let mut out = Vec::new();
                for d in self.descs_of_expr(m, callee, scope, depth + 1) {
                    if let D::Class(c) = d {
                        out.push(D::Inst(c));
                    }
                }
                if out.is_empty() {
                    unknown()
                } else {
                    out
                }
            }
            Kind::MemberExpression => {
                let (name, obj) = {
                    let a = Ast(&self.mods[m as usize].tree);
                    (a.prop_name(node), a.at(node, A))
                };
                let name = match name {
                    None => return unknown(),
                    Some(n) => n,
                };
                let mut out = Vec::new();
                for d in self.descs_of_expr(m, obj, scope, depth + 1) {
                    out.extend(self.member_of(&d, &name, depth + 1));
                }
                let out = dedupe(out);
                if out.is_empty() {
                    unknown()
                } else {
                    out
                }
            }
            Kind::ChainExpression | Kind::AwaitExpression => {
                let e = Ast(&self.mods[m as usize].tree).at(node, A);
                self.descs_of_expr(m, e, scope, depth + 1)
            }
            Kind::SequenceExpression => {
                let last = Ast(&self.mods[m as usize].tree).list(node, A).last().copied();
                match last {
                    Some(e) => self.descs_of_expr(m, e, scope, depth + 1),
                    None => unknown(),
                }
            }
            Kind::AssignmentExpression if Ast(&self.mods[m as usize].tree).operator(node) == "=" => {
                let r = Ast(&self.mods[m as usize].tree).at(node, B);
                self.descs_of_expr(m, r, scope, depth + 1)
            }
            Kind::ConditionalExpression | Kind::LogicalExpression => {
                let parts = {
                    let a = Ast(&self.mods[m as usize].tree);
                    if t == Kind::ConditionalExpression {
                        [a.at(node, B), a.at(node, C)]
                    } else {
                        [a.at(node, A), a.at(node, B)]
                    }
                };
                let mut out = Vec::new();
                for p in parts {
                    out.extend(self.descs_of_expr(m, p, scope, depth + 1));
                }
                dedupe(out)
            }
            Kind::ThisExpression => self.this_descs(scope),
            Kind::Super => {
                if let Some(c) = self.method_class(scope) {
                    if let Some(sup) = self.superclass(c, depth) {
                        return vec![D::Inst(sup)];
                    }
                }
                unknown()
            }
            _ => unknown(),
        }
    }

    /// The method a scope's code belongs to, through arrow functions.
    fn method_fn(&self, scope: ScopeId) -> FnId {
        let mut f = self.scopes[scope as usize].fid;
        let mut seen = 0;
        loop {
            let fun = &self.fns[f as usize];
            let is_arrow =
                !fun.is_module && self.mods[fun.module as usize].tree.nodes[fun.node as usize].kind == Kind::ArrowFunctionExpression;
            match fun.parent {
                Some(p) if is_arrow && seen < ALIAS_DEPTH => {
                    f = p;
                    seen += 1;
                }
                _ => return f,
            }
        }
    }

    /// The class of the method whose code scope is (through arrows).
    pub fn method_class(&self, scope: ScopeId) -> Option<ClassId> {
        self.fns[self.method_fn(scope) as usize].cls
    }

    /// `this` in a method: an instance of its class, or its object.
    pub fn this_descs(&self, scope: ScopeId) -> Vec<D> {
        let f = &self.fns[self.method_fn(scope) as usize];
        if let Some(c) = f.cls {
            return vec![D::Inst(c)];
        }
        if let Some(o) = f.obj {
            return vec![D::Obj(o)];
        }
        unknown()
    }

    pub fn member_of(&mut self, d: &D, name: &[u32], depth: u32) -> Vec<D> {
        match d {
            D::Mod(idx) => self.member_descs(*idx, name, depth, 0),
            D::Obj(oid) => {
                let props: Vec<(NodeId, ScopeId)> = self.objs[*oid as usize].props.get(name).cloned().unwrap_or_default();
                let om = self.objs[*oid as usize].module;
                let mut out = Vec::new();
                for (node, scope) in props {
                    out.extend(self.descs_of_expr(om, node, scope, depth + 1));
                }
                if out.is_empty() {
                    vec![D::Open(name.to_vec())]
                } else {
                    out
                }
            }
            D::Class(cid) => match self.classes[*cid as usize].statics.get(name) {
                Some(&fid) => vec![D::Fn(fid)],
                None => vec![D::Open(name.to_vec())],
            },
            D::Inst(cid) => {
                let mut c = Some(*cid);
                let mut seen = 0;
                while let Some(cc) = c {
                    if seen >= ALIAS_DEPTH {
                        break;
                    }
                    seen += 1;
                    if let Some(&fid) = self.classes[cc as usize].methods.get(name) {
                        return vec![D::Fn(fid)];
                    }
                    c = self.superclass(cc, depth);
                }
                if !is_in(COMMON_METHODS, name) {
                    vec![D::Open(name.to_vec())]
                } else {
                    unknown()
                }
            }
            D::Builtin(b) => vec![D::Builtin(dotted(b, name))],
            D::Global(g) if is_in(GLOBAL_OBJECTS, g) => vec![D::Builtin(dotted(g, name))],
            _ => {
                if is_in(COMMON_METHODS, name) {
                    unknown()
                } else {
                    vec![D::Open(name.to_vec())]
                }
            }
        }
    }

    pub fn superclass(&mut self, c: ClassId, depth: u32) -> Option<ClassId> {
        let (m, node, scope) = self.classes[c as usize].sup?;
        if depth > ALIAS_DEPTH {
            return None;
        }
        for d in self.descs_of_expr(m, node, scope, depth + 1) {
            if let D::Class(x) = d {
                return Some(x);
            }
        }
        None
    }

    /// What export `name` of module `idx` may be.
    pub fn member_descs(&mut self, idx: ModId, name: &[u32], depth: u32, hops: u32) -> Vec<D> {
        let mut out: Vec<D> = Vec::new();
        let entries: Vec<Export> = self.mods[idx as usize].named.get(name).cloned().unwrap_or_default();
        for e in &entries {
            out.extend(self.export_entry(idx, e, depth));
        }
        let is_default = eq(name, "default");
        if !is_default || out.is_empty() {
            let props: Vec<(NodeId, ScopeId)> = self.mods[idx as usize].cjs_props.get(name).cloned().unwrap_or_default();
            for (node, scope) in props {
                out.extend(self.descs_of_expr(idx, node, scope, depth + 1));
            }
        }
        let cjs = self.mods[idx as usize].cjs.clone();
        for (node, scope) in cjs {
            for x in self.descs_of_expr(idx, node, scope, depth + 1) {
                if is_default {
                    if self.mods[idx as usize].named.get(name).map_or(true, |v| v.is_empty()) {
                        out.push(x);
                    }
                } else if matches!(x, D::Obj(_) | D::Mod(_) | D::Class(_) | D::Inst(_)) {
                    out.extend(self.member_of(&x, name, depth + 1));
                }
            }
        }
        if out.is_empty() && !is_default && hops < EXPORT_HOPS {
            let stars = self.mods[idx as usize].stars.clone();
            for spec in stars {
                if let D::Mod(t) = self.resolve_spec(idx, &spec) {
                    let got = self.member_descs(t, name, depth + 1, hops + 1);
                    out.extend(got.into_iter().filter(|x| !matches!(x, D::Open(_))));
                }
            }
        }
        let out = dedupe(out);
        if !out.is_empty() {
            return out;
        }
        if !is_default {
            vec![D::Open(name.to_vec())]
        } else {
            unknown()
        }
    }

    fn export_entry(&mut self, idx: ModId, entry: &Export, depth: u32) -> Vec<D> {
        match entry {
            Export::Binding { name, scope } => match self.lookup(*scope, name) {
                None => vec![D::Open(name.clone())],
                Some(b) => (*self.descs_of_bind(b, depth + 1)).clone(),
            },
            Export::Expr { node, scope } => {
                let k = self.mods[idx as usize].tree.nodes[*node as usize].kind;
                if k == Kind::FunctionDeclaration {
                    return vec![D::Fn(self.mods[idx as usize].fid_at[*node as usize])];
                }
                if k == Kind::ClassDeclaration {
                    return vec![D::Class(self.mods[idx as usize].cid_at[*node as usize])];
                }
                self.descs_of_expr(idx, *node, *scope, depth + 1)
            }
            Export::Reexport { spec, name } => {
                let target = self.resolve_spec(idx, spec);
                match target {
                    D::Mod(t) if depth < ALIAS_DEPTH => self.member_descs(t, name, depth + 1, 0),
                    _ => vec![D::Open(name.clone())],
                }
            }
            Export::Namespace { spec } => vec![self.resolve_spec(idx, spec)],
        }
    }

    /// The functions a module's `module.exports` may be.
    pub fn mod_callables(&mut self, idx: ModId, hops: u32) -> Vec<FnId> {
        let mut out = Vec::new();
        let cjs = self.mods[idx as usize].cjs.clone();
        for (node, scope) in cjs {
            for x in self.descs_of_expr(idx, node, scope, 1) {
                match x {
                    D::Fn(f) => out.push(f),
                    D::Class(c) => {
                        if let Some(ctor) = self.constructor(c) {
                            out.push(ctor);
                        }
                    }
                    D::Mod(t) if hops < EXPORT_HOPS => out.extend(self.mod_callables(t, hops + 1)),
                    _ => {}
                }
            }
        }
        out
    }

    pub fn constructor(&mut self, c: ClassId) -> Option<FnId> {
        let mut c = Some(c);
        let mut seen = 0;
        while let Some(cc) = c {
            if seen >= ALIAS_DEPTH {
                break;
            }
            seen += 1;
            if let Some(&fid) = self.classes[cc as usize].methods.get(&u("constructor")) {
                return Some(fid);
            }
            c = self.superclass(cc, 0);
        }
        None
    }

    /// (project functions the call may reach, how). Memoized per call.
    pub fn call_targets(&mut self, m: ModId, call: NodeId, scope: ScopeId) -> Rc<(Vec<FnId>, How)> {
        if let Some(got) = self.tg_memo.get(&(m, call)) {
            return got.clone();
        }
        let callee = {
            let a = Ast(&self.mods[m as usize].tree);
            a.unwrap(a.at(call, jt::A))
        };
        let ct = self.mods[m as usize].tree.nodes[callee as usize].kind;
        let mut fids: Vec<FnId> = Vec::new();
        let mut open_names: Vec<PyStr> = Vec::new();
        if matches!(ct, Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression) {
            fids.push(self.mods[m as usize].fid_at[callee as usize]);
        } else if ct == Kind::Super {
            let c = self.method_class(scope);
            let sup = match c {
                Some(c) => self.superclass(c, 0),
                None => None,
            };
            if let Some(sup) = sup {
                if let Some(ctor) = self.constructor(sup) {
                    fids.push(ctor);
                }
            }
        } else {
            for d in self.descs_of_expr(m, callee, scope, 0) {
                match d {
                    D::Fn(f) => fids.push(f),
                    D::Class(c) => {
                        if let Some(ctor) = self.constructor(c) {
                            fids.push(ctor);
                        }
                    }
                    D::Mod(idx) => {
                        let got = self.mod_callables(idx, 0);
                        fids.extend(got);
                    }
                    D::Open(n) => open_names.push(n),
                    D::Global(n) if ct == Kind::Identifier => open_names.push(n),
                    D::Unknown if ct == Kind::MemberExpression => {
                        if let Some(n) = Ast(&self.mods[m as usize].tree).prop_name(callee) {
                            if !is_in(COMMON_METHODS, &n) {
                                open_names.push(n);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        let fids = dedupe(fids);
        let mut opens: Vec<FnId> = Vec::new();
        for name in dedupe(open_names) {
            if let Some(cands) = self.by_name.get(&name) {
                if !cands.is_empty() && cands.len() <= MAX_OPEN {
                    for &c in cands {
                        if !fids.contains(&c) && !opens.contains(&c) {
                            opens.push(c);
                        }
                    }
                }
            }
        }
        let how = if !fids.is_empty() {
            if opens.is_empty() {
                How::Definite
            } else {
                How::Mixed
            }
        } else if !opens.is_empty() {
            How::Open
        } else {
            How::None
        };
        let mut all = fids;
        all.extend(opens);
        let out = Rc::new((all, how));
        self.tg_memo.insert((m, call), out.clone());
        out
    }

    /// The bindings an import binding reads (a module's exported
    /// variables), following re-exports.
    pub fn import_targets(&mut self, b: BindId) -> Vec<BindId> {
        if let Some(t) = &self.binds[b as usize].targets {
            return t.clone();
        }
        self.binds[b as usize].targets = Some(Vec::new());
        let writes = self.binds[b as usize].writes.clone();
        let bmod = self.binds[b as usize].module;
        let mut out = Vec::new();
        for w in writes {
            if let Write::Import { spec, name, .. } = w {
                if eq(&name, "*") || eq(&name, "=") {
                    continue;
                }
                if let D::Mod(t) = self.resolve_spec(bmod, &spec) {
                    self.export_binds(t, &name, &mut out, 0);
                }
            }
        }
        let out = dedupe(out);
        self.binds[b as usize].targets = Some(out.clone());
        out
    }

    fn export_binds(&mut self, idx: ModId, name: &[u32], out: &mut Vec<BindId>, hops: u32) {
        let entries: Vec<Export> = self.mods[idx as usize].named.get(name).cloned().unwrap_or_default();
        for e in &entries {
            match e {
                Export::Binding { name: n, scope } => {
                    if let Some(t) = self.lookup(*scope, n) {
                        if matches!(self.binds[t as usize].kind, BindKind::Var | BindKind::Let | BindKind::Const) {
                            out.push(t);
                        }
                    }
                }
                Export::Reexport { spec, name: n } if hops < EXPORT_HOPS => {
                    if let D::Mod(t) = self.resolve_spec(idx, spec) {
                        self.export_binds(t, n, out, hops + 1);
                    }
                }
                _ => {}
            }
        }
        if entries.is_empty() && !eq(name, "default") && hops < EXPORT_HOPS {
            let stars = self.mods[idx as usize].stars.clone();
            for spec in stars {
                if let D::Mod(t) = self.resolve_spec(idx, &spec) {
                    self.export_binds(t, name, out, hops + 1);
                }
            }
        }
    }

    /// Route handlers: functions registered with `app.get('/p', fn)`,
    /// `router.post([...], fn)`, `app.use(fn)`, `router.route('/p').get(fn)`.
    pub fn mark_routes(&mut self) {
        use jt::{A, B};
        for fi in 0..self.fns.len() {
            let calls = self.fns[fi].calls.clone();
            let m = self.fns[fi].module;
            for (node, scope) in calls {
                let handlers: Vec<NodeId> = {
                    let a = Ast(&self.mods[m as usize].tree);
                    if a.kind(node) != Kind::CallExpression {
                        continue;
                    }
                    let callee = a.unwrap(a.at(node, A));
                    if a.kind(callee) != Kind::MemberExpression {
                        continue;
                    }
                    let name = a.prop_name(callee);
                    let args = a.list(node, B);
                    let name = match name {
                        Some(n) if is_in(ROUTE_METHODS, &n) && !args.is_empty() => n,
                        _ => continue,
                    };
                    if a.route_path(args[0]) {
                        args[1..].to_vec()
                    } else if eq(&name, "use") || self.route_chain(m, a.at(callee, A)) {
                        args.to_vec()
                    } else {
                        continue;
                    }
                };
                for a_ in handlers {
                    let hs: Vec<NodeId> = {
                        let a = Ast(&self.mods[m as usize].tree);
                        if a.kind(a_) == Kind::ArrayExpression {
                            a.list(a_, A).to_vec()
                        } else {
                            vec![a_]
                        }
                    };
                    for h in hs {
                        let inner: Vec<NodeId> = {
                            let a = Ast(&self.mods[m as usize].tree);
                            if h == NONE || a.kind(h) == Kind::SpreadElement {
                                continue;
                            }
                            // a wrapped handler: asyncHandler(async (req, res) => …)
                            if a.kind(h) == Kind::CallExpression {
                                a.list(h, B).iter().copied().filter(|&x| a.kind(x) != Kind::SpreadElement).collect()
                            } else {
                                vec![h]
                            }
                        };
                        for x in inner {
                            for d in self.descs_of_expr(m, x, scope, 0) {
                                if let D::Fn(f) = d {
                                    let fun = &mut self.fns[f as usize];
                                    if !fun.is_module {
                                        fun.route = if fun.params.len() == 4 { 2 } else { 1 };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// `router.route('/p')`, or a route method called on one.
    fn route_chain(&self, m: ModId, mut obj: NodeId) -> bool {
        use jt::{A, B};
        let a = Ast(&self.mods[m as usize].tree);
        let mut seen = 0;
        while a.kind(obj) == Kind::CallExpression && seen < ALIAS_DEPTH {
            seen += 1;
            let callee = a.unwrap(a.at(obj, A));
            if a.kind(callee) != Kind::MemberExpression {
                return false;
            }
            let name = a.prop_name(callee);
            if name.as_deref().is_some_and(|n| eq(n, "route")) {
                let args = a.list(obj, B);
                return !args.is_empty() && a.route_path(args[0]);
            }
            if !name.as_deref().is_some_and(|n| is_in(ROUTE_METHODS, n)) {
                return false;
            }
            obj = a.at(callee, A);
        }
        false
    }

    /// Every function, the functions it calls and the functions defined in
    /// it first (DFS post-order, from each function in turn).
    pub fn order(&mut self) -> Vec<FnId> {
        let n = self.fns.len();
        let mut succ: Vec<Vec<FnId>> = vec![Vec::new(); n];
        for f in &self.fns {
            if let Some(p) = f.parent {
                succ[p as usize].push(f.fid);
            }
        }
        for fi in 0..n {
            let mut out = std::mem::take(&mut succ[fi]);
            let calls = self.fns[fi].calls.clone();
            let m = self.fns[fi].module;
            for (node, scope) in calls {
                let tg = self.call_targets(m, node, scope);
                for &x in &tg.0 {
                    if x as usize != fi {
                        out.push(x);
                    }
                }
            }
            succ[fi] = dedupe(out);
        }
        let mut seen = vec![false; n];
        let mut order = Vec::with_capacity(n);
        for root in 0..n {
            if seen[root] {
                continue;
            }
            seen[root] = true;
            let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
            while let Some(top) = stack.last_mut() {
                let (node, k) = *top;
                if k < succ[node].len() {
                    top.1 += 1;
                    let nxt = succ[node][k] as usize;
                    if !seen[nxt] {
                        seen[nxt] = true;
                        stack.push((nxt, 0));
                    }
                } else {
                    stack.pop();
                    order.push(node as FnId);
                }
            }
        }
        order
    }
}
