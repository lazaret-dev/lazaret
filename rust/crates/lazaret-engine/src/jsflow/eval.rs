//! One reading of one function (jsflow.py's _Eval): its summary and, with
//! `emit`, its findings.

use super::descs::How;
use super::driver::{Out, SINKS};
use super::*;

/// What ends a reading early: the pass's work budget spent (Stop), or this
/// reading past its own limit (Cut).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Halt {
    Stop,
    Cut,
}

pub(super) type R<T> = Result<T, Halt>;

/// An environment: what each of the function's own bindings holds.
type Env = HashMap<BindId, V>;

pub struct Eval<'p> {
    pub p: &'p mut Program,
    pub fid: FnId,
    pub m: ModId,
    pub emit: bool,
    pub findings: &'p mut Vec<Out>,
    pub env: Env,
    pub version: u64,
    pub cur: ScopeId,
    /// (key, category, sink entry)
    pub reach_adds: Vec<(u64, u8, Entry)>,
    pub ret_val: Option<V>,
    pub shared_writes: BTreeMap<BindId, V>,
    /// shared bindings read
    pub reads: BTreeSet<BindId>,
    /// fid -> the parameters of it this reading passed tainted values
    pub uses: BTreeMap<FnId, BTreeSet<usize>>,
    pub limit: u64,
    pub ancestors: BTreeSet<FnId>,
    /// (the supply-chain model) (key of this function's parameter, the
    /// closure variable it was written to)
    pub pw_adds: Vec<(u64, BindId)>,
    /// (the supply-chain model) (key of a parameter, the keys of the path of a file it is written to, where)
    pub pf_adds: Vec<(u64, Vec<PyStr>, u32)>,
    /// (the supply-chain model) the value a method call is made on, for the next apply: its receiver (B-3)
    pub recv_val: Option<V>,
}

/// The changes a reading made to summaries: fid -> (returned request data
/// changed, parameter indices, enclosing functions' parameter keys).
pub type Changes = BTreeMap<FnId, (bool, BTreeSet<usize>, BTreeSet<u64>)>;

impl<'p> Eval<'p> {
    pub fn new(p: &'p mut Program, fid: FnId, emit: bool, findings: &'p mut Vec<Out>) -> Eval<'p> {
        let m = p.fns[fid as usize].module;
        let cur = p.fns[fid as usize].scope;
        let limit = p.work + p.cfg.run_base + p.cfg.run_per_node * p.fns[fid as usize].size;
        let mut ancestors = BTreeSet::new();
        let mut f = Some(fid);
        while let Some(x) = f {
            ancestors.insert(x);
            f = p.fns[x as usize].parent;
        }
        Eval {
            p,
            fid,
            m,
            emit,
            findings,
            env: HashMap::new(),
            version: 0,
            cur,
            reach_adds: Vec::new(),
            ret_val: None,
            shared_writes: BTreeMap::new(),
            reads: BTreeSet::new(),
            uses: BTreeMap::new(),
            limit,
            ancestors,
            pw_adds: Vec::new(),
            pf_adds: Vec::new(),
            recv_val: None,
        }
    }

    #[inline]
    pub(super) fn a(&self) -> Ast<'_> {
        Ast(&self.p.mods[self.m as usize].tree)
    }

    // ---- budget ----
    pub(super) fn tick(&mut self, n: u64) -> R<()> {
        self.p.work += n;
        if self.p.work > self.p.budget {
            return Err(Halt::Stop);
        }
        if self.p.work > self.limit {
            return Err(Halt::Cut);
        }
        Ok(())
    }

    // ---- bindings ----
    pub(super) fn read(&mut self, b: BindId) -> V {
        let bind = &self.p.binds[b as usize];
        if bind.kind == BindKind::Import {
            let targets = bind.targets.clone().unwrap_or_default();
            if targets.is_empty() {
                return V::empty();
            }
            let name = bind.name.clone();
            let mut out = V::empty();
            for t in targets {
                self.reads.insert(t);
                if let Some(v) = self.p.shared.get(&t) {
                    if v.tainted() {
                        let mut v = v.clone();
                        if v.src && v.via.is_none() {
                            let tm = self.p.binds[t as usize].module;
                            let mut via = u("the value ");
                            via.extend_from_slice(&name);
                            via.extend(u(" imported from "));
                            via.extend_from_slice(&self.p.mods[tm as usize].path);
                            v = v.with_via(Rc::new(via));
                        }
                        out = out.union(&v.plain());
                    }
                }
            }
            return out;
        }
        if bind.fid == self.fid && !bind.shared {
            return self.env.get(&b).cloned().unwrap_or_else(V::empty);
        }
        let own = bind.fid == self.fid;
        self.reads.insert(b);
        let v = self.p.shared.get(&b).cloned().unwrap_or_else(V::empty);
        if own {
            return self.env.get(&b).cloned().unwrap_or_else(V::empty).union(&v);
        }
        v
    }

    pub(super) fn write(&mut self, b: BindId, v: V, strong: bool) {
        let (bfid, shared) = (self.p.binds[b as usize].fid, self.p.binds[b as usize].shared);
        if bfid == self.fid {
            let old = self.env.get(&b);
            let new = match (strong, old) {
                (true, _) | (_, None) => v.clone(),
                (false, Some(o)) => o.union(&v),
            };
            if old.map_or(true, |o| *o != new) {
                self.env.insert(b, new);
                self.version += 1;
            }
        }
        if shared {
            if self.p.cfg.supply.is_some() {
                // (the supply-chain model: a parameter written to a closure's
                // variable is in the function's summary, for its callers; so is
                // a parameter of a function around this one written to a
                // variable declared outside that function, which the value
                // written cannot carry there (D-15: `p = body` in the 'end'
                // callback, `body` the response https.get's callback was given
                // and `p` the module's))
                let fid = self.fid;
                let mine = self.p.scope_fns(fid);
                let outer = self.p.scope_fns(bfid);
                for &key in v.params.iter() {
                    let owner = key_owner(key);
                    if mine.contains(&owner) && !outer.contains(&owner) {
                        self.pw_adds.push((key, b));
                    }
                }
            }
            // a closure's variable carries the parameters of the function
            // that declares it and of the functions around that one
            let fids = self.p.scope_fns(bfid);
            let v = v.within(&fids);
            let nv = match self.shared_writes.get(&b) {
                None => v,
                Some(o) => o.union(&v),
            };
            self.shared_writes.insert(b, nv);
        }
    }

    fn copy_env(&mut self) -> R<Env> {
        self.tick(1 + (self.env.len() as u64 >> 5))?;
        Ok(self.env.clone())
    }

    /// Both environments' values (a branch's and another's).
    fn merge(&mut self, a: &Env, b: &Env) -> R<Env> {
        self.tick(1 + ((a.len() + b.len()) as u64 >> 5))?;
        let mut out = a.clone();
        for (k, v) in b {
            let nv = match out.get(k) {
                None => v.clone(),
                Some(o) => o.union(v),
            };
            out.insert(*k, nv);
        }
        Ok(out)
    }

    // ---- the function ----
    pub fn run(&mut self) -> R<()> {
        let f = &self.p.fns[self.fid as usize];
        let node = f.node;
        if f.is_module {
            let body = self.a().list(node, jt::A).to_vec();
            return self.stmts(&body);
        }
        let (params, scope, route, fid) = (f.params.clone(), f.scope, f.route, f.fid);
        for (i, &p) in params.iter().enumerate() {
            // (jsflow.py's _V(params=…): clean for no category)
            let mut v = if (i as u64) < PARAM_BASE { V::param(fid as u64 * PARAM_BASE + i as u64, 0, false, 0) } else { V::empty() };
            if route != 0 && !v.is_empty() {
                if i == route as usize - 1 {
                    v = V::new(false, None, None, None, v.params.clone(), 0, false, 1);
                } else if i == route as usize {
                    v = V::new(false, None, None, None, v.params.clone(), 0, false, 2);
                }
            }
            self.bind_pattern(p, v, scope)?;
        }
        let body = self.a().at(node, jt::C);
        if self.a().kind(body) == Kind::BlockStatement {
            let sts = self.a().list(body, jt::A).to_vec();
            self.stmts(&sts)
        } else {
            let v = self.expr(Some(body), scope)?;
            self.ret(v);
            Ok(())
        }
    }

    fn ret(&mut self, v: V) {
        self.ret_val = Some(match &self.ret_val {
            None => v,
            Some(r) => r.union(&v),
        });
    }

    // ---- statements ----
    fn stmts(&mut self, body: &[NodeId]) -> R<()> {
        for &st in body {
            self.stmt(st)?;
        }
        Ok(())
    }

    fn scope_or(&self, node: NodeId, cur: ScopeId) -> ScopeId {
        let s = self.p.mods[self.m as usize].scope_at[node as usize];
        if s == NONE {
            cur
        } else {
            s
        }
    }

    fn stmt(&mut self, st: NodeId) -> R<()> {
        use jt::{A, B, C};
        self.tick(1)?;
        let t = self.a().kind(st);
        let cur = self.cur;
        match t {
            Kind::ExpressionStatement => {
                let e = self.a().at(st, A);
                self.expr(Some(e), cur)?;
            }
            Kind::VariableDeclaration => {
                let (decls, is_var) = (self.a().list(st, A).to_vec(), self.a().op(st) == jt::VAR);
                for d in decls {
                    let (id, init) = (self.a().at(d, A), self.a().opt(d, B));
                    let v = match init {
                        Some(i) => self.expr(Some(i), cur)?,
                        None => V::empty(),
                    };
                    if init.is_some() || !is_var {
                        self.bind_pattern(id, v, cur)?;
                    } else {
                        self.pattern_parts(id, cur)?;
                    }
                }
            }
            Kind::ReturnStatement => {
                let v = match self.a().opt(st, A) {
                    Some(e) => self.expr(Some(e), cur)?,
                    None => V::empty(),
                };
                self.ret(v);
            }
            Kind::IfStatement => {
                let mut node = st;
                let mut outs: Vec<Env> = Vec::new();
                loop {
                    let test = self.a().at(node, A);
                    self.expr(Some(test), cur)?;
                    let before = self.copy_env()?;
                    let cons = self.a().at(node, B);
                    self.sub(cons)?;
                    outs.push(std::mem::replace(&mut self.env, before));
                    let alt = self.a().opt(node, C);
                    if let Some(alt) = alt {
                        if self.a().kind(alt) == Kind::IfStatement {
                            self.tick(1)?;
                            node = alt;
                            continue;
                        }
                        self.sub(alt)?;
                    }
                    outs.push(self.env.clone());
                    break;
                }
                let mut acc = outs.pop().expect("an else branch's environment");
                for o in &outs {
                    acc = self.merge(&acc, o)?;
                }
                self.env = acc;
            }
            Kind::BlockStatement => {
                self.cur = self.scope_or(st, cur);
                let sts = self.a().list(st, A).to_vec();
                self.stmts(&sts)?;
                self.cur = cur;
            }
            Kind::ForStatement | Kind::ForInStatement | Kind::ForOfStatement | Kind::WhileStatement | Kind::DoWhileStatement => {
                self.loop_(st)?;
            }
            Kind::TryStatement => {
                let before = self.copy_env()?;
                let block = self.a().at(st, A);
                self.stmt(block)?;
                if let Some(h) = self.a().opt(st, B) {
                    let after = self.env.clone();
                    self.env = self.merge(&before, &after)?;
                    self.cur = self.p.mods[self.m as usize].scope_at[h as usize];
                    if let Some(param) = self.a().opt(h, A) {
                        let c = self.cur;
                        self.bind_pattern(param, V::empty(), c)?;
                    }
                    let body = self.a().at(h, B);
                    let sts = self.a().list(body, A).to_vec();
                    self.stmts(&sts)?;
                    self.cur = cur;
                    let env = std::mem::take(&mut self.env);
                    self.env = self.merge(&after, &env)?;
                }
                if let Some(fin) = self.a().opt(st, C) {
                    self.stmt(fin)?;
                }
            }
            Kind::SwitchStatement => {
                self.cur = self.scope_or(st, cur);
                let disc = self.a().at(st, A);
                let c = self.cur;
                self.expr(Some(disc), c)?;
                let before = self.copy_env()?;
                let mut acc = before.clone();
                let cases = self.a().list(st, B).to_vec();
                for case in cases {
                    if let Some(test) = self.a().opt(case, A) {
                        let c = self.cur;
                        self.expr(Some(test), c)?;
                    }
                    let env = std::mem::take(&mut self.env);
                    self.env = self.merge(&before, &env)?;
                    let cons = self.a().list(case, B).to_vec();
                    self.stmts(&cons)?;
                    let env = self.env.clone();
                    acc = self.merge(&acc, &env)?;
                }
                self.env = acc;
                self.cur = cur;
            }
            Kind::LabeledStatement => {
                let body = self.a().at(st, B);
                self.stmt(body)?;
            }
            Kind::ThrowStatement => {
                let e = self.a().at(st, A);
                self.expr(Some(e), cur)?;
            }
            Kind::WithStatement => {
                let (obj, body) = (self.a().at(st, A), self.a().at(st, B));
                self.expr(Some(obj), cur)?;
                self.sub(body)?;
            }
            Kind::ClassDeclaration => self.class_parts(st, cur)?,
            Kind::ExportNamedDeclaration => {
                if let Some(d) = self.a().opt(st, A) {
                    self.stmt(d)?;
                }
            }
            Kind::ExportDefaultDeclaration => {
                let d = self.a().at(st, A);
                match self.a().kind(d) {
                    Kind::ClassDeclaration => self.class_parts(d, cur)?,
                    Kind::FunctionDeclaration => {}
                    _ => {
                        self.expr(Some(d), cur)?;
                    }
                }
            }
            Kind::TSModuleDeclaration => {
                // (its body: a block, or a nested namespace's declaration)
                if let Some(b) = self.a().opt(st, B) {
                    self.sub(b)?;
                }
            }
            Kind::TSExportAssignment => {
                let e = self.a().at(st, A);
                self.expr(Some(e), cur)?;
            }
            Kind::TSEnumDeclaration => {
                let members = self.a().list(st, B).to_vec();
                for mem in members {
                    if let Some(init) = self.a().opt(mem, B) {
                        self.expr(Some(init), cur)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn sub(&mut self, st: NodeId) -> R<()> {
        let cur = self.cur;
        let r = self.stmt(st);
        self.cur = cur;
        r
    }

    fn loop_(&mut self, st: NodeId) -> R<()> {
        use jt::{A, B, C, D};
        let t = self.a().kind(st);
        let cur = self.cur;
        self.cur = self.scope_or(st, cur);
        if t == Kind::ForStatement {
            if let Some(init) = self.a().opt(st, A) {
                if self.a().kind(init) == Kind::VariableDeclaration {
                    self.stmt(init)?;
                } else {
                    let c = self.cur;
                    self.expr(Some(init), c)?;
                }
            }
        }
        let mut it: Option<V> = None;
        if t == Kind::ForInStatement || t == Kind::ForOfStatement {
            let right = self.a().at(st, B);
            let c = self.cur;
            let mut v = self.expr(Some(right), c)?.plain();
            // (the supply-chain model: a loop that selects some of the
            // environment's variables does not read the whole of it)
            if self.p.cfg.supply.is_some() && self.sc_loop_selects_env(st, &v) {
                v = super::supply::sc_without(&v, super::supply::K_WHOLE_ENV);
            }
            it = Some(v);
        }
        let before = self.copy_env()?;
        for _k in 0..2 {
            let version = self.version;
            if let Some(it) = &it {
                let left = self.a().at(st, A);
                let c = self.cur;
                if self.a().kind(left) == Kind::VariableDeclaration {
                    let decls = self.a().list(left, A).to_vec();
                    for d in decls {
                        let id = self.a().at(d, A);
                        self.bind_pattern(id, it.clone(), c)?;
                    }
                } else {
                    self.assign_pattern(left, it.clone(), c)?;
                }
            }
            let c = self.cur;
            match t {
                Kind::ForStatement => {
                    if let Some(test) = self.a().opt(st, B) {
                        self.expr(Some(test), c)?;
                    }
                }
                Kind::WhileStatement => {
                    let test = self.a().at(st, A);
                    self.expr(Some(test), c)?;
                }
                _ => {}
            }
            let body = match t {
                Kind::ForStatement => self.a().at(st, D),
                Kind::ForInStatement | Kind::ForOfStatement => self.a().at(st, C),
                Kind::WhileStatement => self.a().at(st, B),
                _ => self.a().at(st, A), // do … while: body first
            };
            self.sub(body)?;
            let c = self.cur;
            if t == Kind::DoWhileStatement {
                let test = self.a().at(st, B);
                self.expr(Some(test), c)?;
            }
            if t == Kind::ForStatement {
                if let Some(up) = self.a().opt(st, C) {
                    self.expr(Some(up), c)?;
                }
            }
            if self.version == version {
                break;
            }
        }
        if t != Kind::DoWhileStatement {
            let env = std::mem::take(&mut self.env);
            self.env = self.merge(&before, &env)?;
        }
        self.cur = cur;
        Ok(())
    }

    /// A class's superclass, decorators, computed keys, field initializers
    /// and static blocks run where it is defined; its methods are functions
    /// of their own.
    fn class_parts(&mut self, node: NodeId, scope: ScopeId) -> R<()> {
        use jt::{A, B, C, D};
        let cscope = self.p.mods[self.m as usize].scope_at[node as usize];
        let decos = if self.a().at(node, D) != NONE { self.a().list(node, D).to_vec() } else { Vec::new() };
        for d in decos {
            self.expr(Some(d), scope)?;
        }
        if let Some(sup) = self.a().opt(node, B) {
            self.expr(Some(sup), scope)?;
        }
        let body = self.a().at(node, C);
        let members = self.a().list(body, A).to_vec();
        for member in members {
            let mt = self.a().kind(member);
            if mt == Kind::StaticBlock {
                let cur = self.cur;
                self.cur = self.p.mods[self.m as usize].scope_at[member as usize];
                let sts = self.a().list(member, A).to_vec();
                self.stmts(&sts)?;
                self.cur = cur;
                continue;
            }
            let mdecos = if self.a().at(member, D) != NONE { self.a().list(member, D).to_vec() } else { Vec::new() };
            for d in mdecos {
                self.expr(Some(d), scope)?;
            }
            if self.a().computed(member) {
                let key = self.a().at(member, A);
                self.expr(Some(key), scope)?;
            }
            if mt == Kind::PropertyDefinition {
                if let Some(v) = self.a().opt(member, B) {
                    if !self.a().is_function(v) {
                        self.expr(Some(v), cscope)?;
                    }
                }
            }
        }
        Ok(())
    }

    // ---- patterns ----
    pub(super) fn bind(&self, ident: NodeId, scope: ScopeId) -> Option<BindId> {
        let b = self.p.mods[self.m as usize].bind_at[ident as usize];
        if b == UNSET {
            let name = self.a().name(ident).to_vec();
            return self.p.lookup(scope, &name);
        }
        if b == GLOBAL {
            None
        } else {
            Some(b)
        }
    }

    fn bind_pattern(&mut self, pat: NodeId, v: V, scope: ScopeId) -> R<()> {
        let names = self.a().pattern_names(pat);
        for (ident, path) in names {
            let b = match self.bind(ident, scope) {
                None => continue,
                Some(b) => b,
            };
            let first_is_request_prop = matches!(path.first(), Some(Some(n)) if is_in(REQUEST_PROPS, n));
            let narrowed = if self.p.cfg.supply.is_some() { self.sc_pattern_value(&v, &path, ident) } else { None };
            let val = if let Some(nv) = narrowed {
                nv
            } else if !path.is_empty() && v.kind & 1 != 0 && first_is_request_prop {
                let line = self.a().line(ident);
                self.source(line).union(&v.plain())
            } else if !path.is_empty() {
                v.plain()
            } else {
                v.clone()
            };
            self.write(b, val, true);
        }
        self.pattern_parts(pat, scope)
    }

    /// A pattern's default values (a name gets its default too) and
    /// computed keys.
    fn pattern_parts(&mut self, pat: NodeId, scope: ScopeId) -> R<()> {
        use jt::{A, B};
        if self.a().kind(pat) == Kind::Identifier {
            return Ok(());
        }
        let mut todo = vec![pat];
        while let Some(p) = todo.pop() {
            if p == NONE {
                continue;
            }
            match self.a().kind(p) {
                Kind::AssignmentPattern => {
                    let (left, right) = (self.a().at(p, A), self.a().at(p, B));
                    let dv = self.expr(Some(right), scope)?;
                    let names = self.a().pattern_names(left);
                    for (ident, _) in names {
                        if let Some(b) = self.bind(ident, scope) {
                            self.write(b, dv.plain(), false);
                        }
                    }
                    todo.push(left);
                }
                Kind::ObjectPattern => {
                    let props = self.a().list(p, A).to_vec();
                    for &prop in props.iter().rev() {
                        if self.a().kind(prop) == Kind::RestElement {
                            todo.push(self.a().at(prop, A));
                        } else {
                            if self.a().computed(prop) {
                                let key = self.a().at(prop, A);
                                self.expr(Some(key), scope)?;
                            }
                            todo.push(self.a().at(prop, B));
                        }
                    }
                }
                Kind::ArrayPattern => {
                    let els = self.a().list(p, A).to_vec();
                    for &el in els.iter().rev() {
                        todo.push(el);
                    }
                }
                Kind::RestElement => todo.push(self.a().at(p, A)),
                Kind::MemberExpression => {
                    let obj = self.a().at(p, A);
                    self.expr(Some(obj), scope)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn assign_pattern(&mut self, pat: NodeId, v: V, scope: ScopeId) -> R<()> {
        use jt::{A, B};
        let t = self.a().kind(pat);
        if t == Kind::Identifier {
            if let Some(b) = self.bind(pat, scope) {
                self.write(b, v, true);
            } else if self.p.cfg.supply.is_some() {
                let b = self.sc_global_bind(pat);
                self.write(b, v, false);
            }
            return Ok(());
        }
        if t == Kind::MemberExpression {
            let obj = self.a().at(pat, A);
            self.expr(Some(obj), scope)?;
            if self.a().computed(pat) {
                let prop = self.a().at(pat, B);
                self.expr(Some(prop), scope)?;
            }
            self.member_write(pat, &v, scope);
            return Ok(());
        }
        let names = self.a().pattern_names(pat);
        for (ident, path) in names {
            if let Some(b) = self.bind(ident, scope) {
                self.write(b, if path.is_empty() { v.clone() } else { v.plain() }, true);
            }
        }
        let members = self.a().pattern_members(pat);
        for mem in members {
            self.member_write(mem, &v.plain(), scope);
        }
        self.pattern_parts(pat, scope)
    }

    /// `o.x = v`: the container o holds v too (a weak update).
    pub(super) fn member_write(&mut self, target: NodeId, v: &V, scope: ScopeId) {
        if self.p.cfg.supply.is_some() {
            // (the supply-chain model: `this.x = v`, `this.x.y = v` hold v in this.x;
            // a connection or a client too)
            let mut m = target;
            let mut seen = 0;
            while self.a().kind(self.a().at(m, jt::A)) == Kind::MemberExpression && seen < ALIAS_DEPTH {
                m = self.a().at(m, jt::A);
                seen += 1;
            }
            if let Some(b) = self.sc_this_member(m, scope) {
                if v.tainted() || v.kind & super::supply::MARKS != 0 {
                    let val = if m == target { v.clone() } else { v.plain() };
                    self.write(b, val, false);
                }
                return;
            }
            // (`process.env.NAME = v`: what reads it later gets v)
            if let Some(b) = self.sc_env_member(target, scope) {
                if v.tainted() {
                    self.write(b, v.plain(), false);
                }
                return;
            }
        }
        if !v.tainted() {
            return;
        }
        let mut obj = self.a().at(target, jt::A);
        let mut seen = 0;
        while self.a().kind(obj) == Kind::MemberExpression && seen < ALIAS_DEPTH {
            obj = self.a().at(obj, jt::A);
            seen += 1;
        }
        if self.a().kind(obj) == Kind::Identifier {
            if let Some(b) = self.bind(obj, scope) {
                if self.p.binds[b as usize].kind != BindKind::Import {
                    self.write(b, v.plain(), false);
                }
            }
        }
    }

    // ---- sources ----
    fn source(&self, line: u32) -> V {
        let f = &self.p.fns[self.fid as usize];
        let fname = if f.is_module { None } else { f.name.clone().map(Rc::new) };
        V::new(true, Some((self.m, line)), fname, None, V::empty().params, 0, false, 0)
    }

    fn is_source_text(&self, text: &[u32]) -> bool {
        !text.is_empty() && self.p.cfg.is_source(text)
    }

    // ---- expressions ----
    pub(super) fn expr(&mut self, e: Option<NodeId>, scope: ScopeId) -> R<V> {
        use jt::{A, B, C};
        let e = match e {
            None => return Ok(V::empty()),
            Some(e) => e,
        };
        self.tick(1)?;
        let t = self.a().kind(e);
        match t {
            Kind::Identifier => match self.bind(e, scope) {
                None if self.p.cfg.supply.is_some() => {
                    let b = self.sc_global_bind(e);
                    Ok(self.read(b))
                }
                None => Ok(V::empty()),
                Some(b) => Ok(self.read(b)),
            },
            Kind::Literal if self.p.cfg.supply.is_some() => Ok(self.sc_literal(e)),
            // (`this` in a method of a class made in several places: its receiver, B-3)
            Kind::ThisExpression if self.p.cfg.supply.is_some() => Ok(self.sc_this_value(scope)),
            Kind::Literal | Kind::ThisExpression | Kind::Super | Kind::MetaProperty => Ok(V::empty()),
            Kind::TemplateLiteral => {
                let exprs = self.a().list(e, B).to_vec();
                let mut out = V::empty();
                for (k, x) in exprs.into_iter().enumerate() {
                    let xv = self.expr(Some(x), scope)?.plain();
                    if k == 0 && self.p.cfg.supply.is_some() {
                        self.sc_host_built(e, &xv);
                    }
                    out = out.union(&xv);
                }
                out = out.with_built();
                if out.tainted() {
                    let q = self.a().list(e, A);
                    let raw = q.first().map(|&x| self.a().s(x, A).to_vec()).unwrap_or_default();
                    if self.p.cfg.fixed_prefix(&raw) {
                        out = out.sanitize(FIXED_HOST);
                    }
                }
                Ok(out)
            }
            Kind::MemberExpression | Kind::CallExpression | Kind::NewExpression | Kind::TaggedTemplateExpression
            | Kind::ChainExpression => self.chain(e, scope),
            Kind::BinaryExpression | Kind::LogicalExpression => self.binary(e, scope),
            Kind::AssignmentExpression => self.assignment(e, scope),
            Kind::ConditionalExpression => {
                let (test, cons, alt) = (self.a().at(e, A), self.a().at(e, B), self.a().at(e, C));
                self.expr(Some(test), scope)?;
                let a = self.expr(Some(cons), scope)?;
                let b = self.expr(Some(alt), scope)?;
                Ok(a.union(&b))
            }
            Kind::UnaryExpression | Kind::UpdateExpression => {
                let arg = self.a().at(e, A);
                self.expr(Some(arg), scope)?;
                Ok(V::empty())
            }
            Kind::AwaitExpression | Kind::SpreadElement => {
                let arg = self.a().at(e, A);
                self.expr(Some(arg), scope)
            }
            Kind::YieldExpression => {
                let arg = self.a().opt(e, A);
                let v = self.expr(arg, scope)?;
                self.ret(v);
                Ok(V::empty())
            }
            Kind::SequenceExpression => {
                let xs = self.a().list(e, A).to_vec();
                let mut v = V::empty();
                for x in xs {
                    v = self.expr(Some(x), scope)?;
                }
                Ok(v)
            }
            Kind::ArrayExpression => {
                let xs = self.a().list(e, A).to_vec();
                let mut out = V::empty();
                for x in xs {
                    if x != NONE {
                        out = out.union(&self.expr(Some(x), scope)?.plain());
                    }
                }
                Ok(out)
            }
            Kind::ObjectExpression => {
                let props = self.a().list(e, A).to_vec();
                let mut out = V::empty();
                for prop in props {
                    if self.a().kind(prop) == Kind::SpreadElement {
                        let arg = self.a().at(prop, A);
                        out = out.union(&self.expr(Some(arg), scope)?.plain());
                        continue;
                    }
                    if self.a().computed(prop) {
                        let key = self.a().at(prop, A);
                        self.expr(Some(key), scope)?;
                    }
                    let v = self.a().at(prop, B);
                    if self.a().is_function(v) {
                        continue;
                    }
                    out = out.union(&self.expr(Some(v), scope)?.plain());
                }
                Ok(out)
            }
            Kind::FunctionDeclaration | Kind::FunctionExpression | Kind::ArrowFunctionExpression => {
                let fid = self.p.mods[self.m as usize].fid_at[e as usize];
                Ok(self.function_value(fid))
            }
            Kind::ClassExpression => {
                self.class_parts(e, scope)?;
                Ok(V::empty())
            }
            Kind::ImportExpression => {
                let (src, opts) = (self.a().at(e, A), self.a().opt(e, B));
                let v = self.expr(Some(src), scope)?;
                if opts.is_some() {
                    self.expr(opts, scope)?;
                }
                if self.p.cfg.supply.is_some() {
                    // (the supply-chain model: a module named by received data)
                    let at = self.a().0.nodes[e as usize].start;
                    self.sc_sink(super::supply::LOAD_NAME, &v, at);
                }
                Ok(V::empty())
            }
            Kind::JSXElement | Kind::JSXFragment => {
                self.jsx(e, scope)?;
                Ok(V::empty())
            }
            _ => Ok(V::empty()),
        }
    }

    /// A function as a value: what it returns (request data, the
    /// parameters of functions around it) — a callback carries it.
    fn function_value(&mut self, fid: FnId) -> V {
        self.uses.entry(fid).or_default();
        let f = &self.p.fns[fid as usize];
        let mut out = V::empty();
        if let Some(rs) = &f.ret_src {
            out = out.union(rs);
        }
        for (&key, &(clean, built)) in &f.ret_outer {
            if self.ancestors.contains(&key_owner(key)) {
                out = out.union(&V::param(key, clean, built, 0));
            }
        }
        out
    }

    fn binary(&mut self, e: NodeId, scope: ScopeId) -> R<V> {
        use jt::{A, B};
        // a left-deep chain (a + b + c …) is read in a loop
        let mut chain = Vec::new();
        let mut n = e;
        while matches!(self.a().kind(n), Kind::BinaryExpression | Kind::LogicalExpression) {
            chain.push(n);
            n = self.a().at(n, A);
        }
        let mut v = self.expr(Some(n), scope)?;
        // 'https://host/' + … or '/path/' + …: a fixed host or this site
        let mut fixed = match self.a().leftmost_text(n) {
            Some(text) => {
                let text = text.to_vec();
                self.p.cfg.fixed_prefix(&text)
            }
            None => false,
        };
        let mut prev = n;
        for &node in chain.iter().rev() {
            self.tick(1)?;
            let op = self.a().operator(node);
            let right = self.a().at(node, B);
            let r = self.expr(Some(right), scope)?;
            if op == "+" && self.p.cfg.supply.is_some() {
                // ('https://' + host …: the host name is resolved)
                self.sc_host_built(prev, &r.plain());
            }
            prev = right;
            if op == "+" {
                v = v.plain().union(&r.plain()).with_built();
                if fixed && v.tainted() {
                    v = v.sanitize(FIXED_HOST);
                }
            } else if op == "&&" && self.p.cfg.supply.is_some() {
                // (`a && b` is b where a holds: a test, then the value)
                v = r;
                fixed = false;
            } else if op == "||" || op == "&&" || op == "??" {
                v = v.union(&r);
                fixed = false;
            } else {
                v = V::empty();
                fixed = false;
            }
        }
        Ok(v)
    }

    fn assignment(&mut self, e: NodeId, scope: ScopeId) -> R<V> {
        use jt::{A, B};
        let (left, right) = (self.a().at(e, A), self.a().at(e, B));
        let op = self.a().operator(e);
        let lk = self.a().kind(left);
        if op == "=" {
            let v = self.expr(Some(right), scope)?;
            if lk == Kind::Identifier {
                if let Some(b) = self.bind(left, scope) {
                    self.write(b, v.clone(), true);
                } else if self.p.cfg.supply.is_some() {
                    let b = self.sc_global_bind(left);
                    self.write(b, v.clone(), false);
                }
            } else if lk == Kind::MemberExpression {
                let obj = self.a().at(left, A);
                self.expr(Some(obj), scope)?;
                if self.a().computed(left) {
                    let prop = self.a().at(left, B);
                    self.expr(Some(prop), scope)?;
                }
                if self.p.cfg.supply.is_none() {
                    self.sink_assignment(left, &v);
                }
                self.member_write(left, &v, scope);
            } else {
                self.assign_pattern(left, v.clone(), scope)?;
            }
            return Ok(v);
        }
        // compound: x += v, x ||= v, …
        let old = self.expr(Some(left), scope)?;
        let v = self.expr(Some(right), scope)?;
        let nv = if op == "+=" {
            old.plain().union(&v.plain()).with_built()
        } else if op == "||=" || op == "&&=" || op == "??=" {
            old.union(&v)
        } else {
            V::empty()
        };
        if lk == Kind::Identifier {
            if let Some(b) = self.bind(left, scope) {
                self.write(b, nv.clone(), true);
            } else if self.p.cfg.supply.is_some() {
                let b = self.sc_global_bind(left);
                self.write(b, nv.clone(), false);
            }
        } else if lk == Kind::MemberExpression {
            if self.p.cfg.supply.is_none() {
                self.sink_assignment(left, &nv);
            }
            self.member_write(left, &nv, scope);
        }
        Ok(nv)
    }

    fn sink_assignment(&mut self, target: NodeId, v: &V) {
        let mut text = (*self.p.text(self.m, target)).clone();
        text.extend(u(" ="));
        let line = if self.a().computed(target) { self.a().line(target) } else { self.a().line(self.a().at(target, jt::B)) };
        if let Some(cat) = self.p.cfg.extra_sink(&text) {
            self.sink(cat, Some(v), line);
            return;
        }
        for (k, (_, cat, which)) in SINKS.iter().enumerate() {
            if *which == "value" && self.p.cfg.sink_matches(k, &text) {
                self.sink(*cat, Some(v), line);
                return;
            }
        }
    }

    /// A member, call, tagged template or new expression; its object /
    /// callee chain is read in a loop (deep chains need no recursion).
    fn chain(&mut self, e: NodeId, scope: ScopeId) -> R<V> {
        use jt::A;
        let mut spine = Vec::new();
        let mut n = e;
        loop {
            match self.a().kind(n) {
                Kind::MemberExpression | Kind::CallExpression | Kind::TaggedTemplateExpression => {
                    spine.push(n);
                    n = self.a().at(n, A);
                }
                Kind::ChainExpression => n = self.a().at(n, A),
                _ => break,
            }
        }
        let mut v = if self.a().kind(n) == Kind::NewExpression { self.new_expr(n, scope)? } else { self.expr(Some(n), scope)? };
        let mut recv = V::empty();
        for &node in spine.iter().rev() {
            self.tick(1)?;
            match self.a().kind(node) {
                Kind::MemberExpression => {
                    let nv = self.member(node, &v, scope)?;
                    recv = std::mem::replace(&mut v, nv);
                }
                Kind::CallExpression => {
                    let callee = self.a().unwrap(self.a().at(node, A));
                    let r = if self.a().kind(callee) == Kind::MemberExpression { recv.clone() } else { V::empty() };
                    v = self.call(node, &r, &v, scope)?;
                    recv = V::empty();
                }
                _ => {
                    v = self.tagged(node, scope)?;
                    recv = V::empty();
                }
            }
        }
        Ok(v)
    }

    fn member(&mut self, node: NodeId, obj: &V, scope: ScopeId) -> R<V> {
        use jt::B;
        let mut key = V::empty();
        if self.a().computed(node) {
            let prop = self.a().at(node, B);
            key = self.expr(Some(prop), scope)?;
        }
        if self.p.cfg.supply.is_some() {
            let v = if let Some(v) = self.sc_member(node, obj, &key, scope) {
                v
            } else if self.a().prop_name(node).as_deref().is_some_and(|n| eq(n, "length")) {
                V::empty()
            } else if obj.kind != 0 {
                obj.plain()
            } else {
                obj.clone()
            };
            // (and what was put into the member as a container of its own: `o.list` after `o.list.push(x)`, D-3b)
            return Ok(match self.sc_member_held(node, scope) {
                Some(held) => v.union(&held),
                None => v,
            });
        }
        let name = self.a().prop_name(node);
        let line = if self.a().computed(node) { self.a().line(node) } else { self.a().line(self.a().at(node, B)) };
        if obj.kind & 1 != 0 {
            if name.as_deref().is_some_and(|n| is_in(REQUEST_PROPS, n)) {
                return Ok(self.source(line));
            }
            if name.as_deref().is_some_and(|n| is_in(REQUEST_WRAPPERS, n)) {
                return Ok(obj.clone());
            }
        }
        let text = self.p.text(self.m, node);
        if self.is_source_text(&text) {
            return Ok(self.source(line));
        }
        if name.as_deref().is_some_and(|n| eq(n, "length")) {
            return Ok(V::empty());
        }
        Ok(if obj.kind != 0 { obj.plain() } else { obj.clone() })
    }

    /// The arguments' values, and the index of the first spread (or -1).
    fn args_of(&mut self, node: NodeId, scope: ScopeId) -> R<(Vec<V>, isize)> {
        let list = self.a().list(node, jt::B).to_vec();
        let mut args = Vec::with_capacity(list.len());
        let mut spread: isize = -1;
        for a in list {
            if self.a().kind(a) == Kind::SpreadElement {
                if spread < 0 {
                    spread = args.len() as isize;
                }
                let arg = self.a().at(a, jt::A);
                args.push(self.expr(Some(arg), scope)?.plain());
            } else {
                args.push(self.expr(Some(a), scope)?);
            }
        }
        Ok((args, spread))
    }

    fn new_expr(&mut self, node: NodeId, scope: ScopeId) -> R<V> {
        let callee = self.a().at(node, jt::A);
        if self.a().kind(callee) != Kind::Identifier {
            self.expr(Some(callee), scope)?;
        }
        let (args, spread) = self.args_of(node, scope)?;
        if self.p.cfg.supply.is_some() {
            let v = self.sc_new(node, &args, spread, scope);
            let tg = self.p.call_targets(self.m, node, scope);
            if !tg.0.is_empty() {
                let line = self.a().line(node);
                self.apply(node, &tg.0, &args, spread, line, true);
            }
            return Ok(v);
        }
        let mut text = u("new ");
        text.extend_from_slice(&self.p.text(self.m, callee));
        text.push(0x28);
        let tg = self.p.call_targets(self.m, node, scope);
        if tg.1 != How::Definite {
            if let Some((cat, which)) = self.p.cfg.sink_of(&text) {
                let line = self.a().line(node);
                let v = sink_value(which, &args);
                self.sink(cat, Some(&v), line);
            }
        }
        if !tg.0.is_empty() {
            let line = self.a().line(node);
            self.apply(node, &tg.0, &args, spread, line, true);
        }
        let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
        Ok(union_all(&plains))
    }

    fn tagged(&mut self, node: NodeId, scope: ScopeId) -> R<V> {
        let quasi = self.a().at(node, jt::B);
        let exprs = self.a().list(quasi, jt::B).to_vec();
        let mut args = Vec::with_capacity(exprs.len());
        for x in exprs {
            args.push(self.expr(Some(x), scope)?.plain());
        }
        let tg = self.p.call_targets(self.m, node, scope);
        if !tg.0.is_empty() {
            let mut all = vec![V::empty()];
            all.extend(args.iter().cloned());
            let line = self.a().line(node);
            let mut v = self.apply(node, &tg.0, &all, -1, line, false);
            if tg.1 != How::Definite {
                v = v.union(&union_all(&args));
            }
            return Ok(v);
        }
        Ok(union_all(&args))
    }

    pub(super) fn call_line(&self, node: NodeId) -> u32 {
        let callee = self.a().unwrap(self.a().at(node, jt::A));
        if self.a().kind(callee) == Kind::MemberExpression && !self.a().computed(callee) {
            return self.a().line(self.a().at(callee, jt::B));
        }
        self.a().line(callee)
    }

    /// A call: its sources and sinks, the functions it reaches, its value.
    fn call(&mut self, node: NodeId, recv: &V, callee_val: &V, scope: ScopeId) -> R<V> {
        let (args, spread) = self.args_of(node, scope)?;
        if self.p.cfg.supply.is_some() {
            return self.sc_call(node, recv, callee_val, &args, spread, scope);
        }
        let callee = self.a().unwrap(self.a().at(node, jt::A));
        let member = self.a().kind(callee) == Kind::MemberExpression;
        let ctext = self.p.text(self.m, callee);
        let mut text = (*ctext).clone();
        text.push(0x28);
        let name: Option<PyStr> = if member {
            if self.p.cfg.supply.is_some() {
                self.p.member_name(self.m, callee, scope)
            } else {
                self.a().prop_name(callee)
            }
        } else if self.a().is_ident(callee) {
            Some(self.a().name(callee).to_vec())
        } else {
            None
        };
        let line = self.call_line(node);
        let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
        // request data
        if member && recv.kind & 1 != 0 && name.as_deref().is_some_and(|n| is_in(REQUEST_CALLS, n)) {
            return Ok(self.source(line));
        }
        if self.is_source_text(&text) {
            return Ok(self.source(line));
        }
        let tg = self.p.call_targets(self.m, node, scope);
        let (fids, how): (Vec<FnId>, How) = if member && recv.kind != 0 {
            (Vec::new(), How::None) // a request's or a response's method is the framework's
        } else {
            (tg.0.clone(), tg.1)
        };
        let definite = how == How::Definite;
        // sinks: not a call that is known to reach project code
        if !definite {
            match self.p.cfg.sink_of(&text) {
                Some((cat, which)) => {
                    if !self.not_a_sink(cat, callee, node, scope) {
                        let v = sink_value(which, &args);
                        self.sink(cat, Some(&v), line);
                    }
                }
                None => {
                    if member && recv.kind & 2 != 0 {
                        self.response_sink(callee, node, &args, line);
                    }
                }
            }
        }
        let san = self.sanitizer(&ctext, name.as_deref(), &fids, definite);
        let mut v;
        if !fids.is_empty() {
            v = self.apply(node, &fids, &args, spread, line, false);
            if !definite {
                let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
                v = v.union(&union_all(&plains)).union(&recv.plain());
            }
        } else if name.as_deref().is_some_and(|n| is_in(CLEAN_RESULT, n)) {
            v = V::empty();
        } else {
            let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
            v = union_all(&plains).union(&recv.plain());
            if !member {
                v = v.union(&callee_val.plain());
            } else if named("join") || named("concat") {
                v = v.with_built();
            }
        }
        // a container a value is put into holds it
        if member && (named("push") || named("unshift")) {
            let obj = self.a().at(callee, jt::A);
            if self.a().kind(obj) == Kind::Identifier {
                if let Some(b) = self.bind(obj, scope) {
                    if self.p.binds[b as usize].kind != BindKind::Import {
                        let plains: Vec<V> = args.iter().map(|a| a.plain()).collect();
                        self.write(b, union_all(&plains), false);
                    }
                }
            }
        }
        if san == ALL {
            return Ok(V::empty());
        }
        if san != 0 {
            return Ok(v.sanitize(san));
        }
        Ok(v)
    }

    /// A RegExp's exec(), Express's sendFile / download given a root, a
    /// response sending a whole parsed object or set to a non-HTML type.
    fn not_a_sink(&mut self, cat: u8, callee: NodeId, node: NodeId, scope: ScopeId) -> bool {
        if self.a().kind(callee) != Kind::MemberExpression {
            return false;
        }
        let name = self.a().prop_name(callee);
        let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
        if cat == CMD && named("exec") {
            return self.regexp_receiver(callee, scope);
        }
        if cat == PATH && (named("sendFile") || named("download")) {
            return self.has_root(node);
        }
        if cat == XSS && (named("send") || named("write") || named("end")) {
            return self.not_html_response(callee, node);
        }
        false
    }

    fn has_root(&self, node: NodeId) -> bool {
        let a = self.a();
        for &arg in a.list(node, jt::B).iter().skip(1) {
            if a.kind(arg) == Kind::ObjectExpression {
                for &p in a.list(arg, jt::A) {
                    if a.kind(p) == Kind::Property && a.key_name(p).as_deref().is_some_and(|k| eq(k, "root")) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn not_html_response(&self, callee: NodeId, node: NodeId) -> bool {
        use jt::{A, B};
        let a = self.a();
        let args = a.list(node, B);
        if let Some(&first) = args.first() {
            if a.kind(first) == Kind::MemberExpression && a.prop_name(first).as_deref().is_some_and(|n| is_in(REQUEST_OBJECTS, n)) {
                return true;
            }
            if matches!(a.kind(first), Kind::ObjectExpression | Kind::ArrayExpression) {
                return true;
            }
            if let Some(text) = a.leftmost_text(first) {
                if self.p.cfg.sse(text) {
                    return true; // a Server-Sent Events frame
                }
            }
        }
        let mut obj = a.at(callee, A);
        let mut seen = 0;
        while a.kind(obj) == Kind::CallExpression && seen < ALIAS_DEPTH {
            seen += 1;
            let m = a.unwrap(a.at(obj, A));
            if a.kind(m) != Kind::MemberExpression {
                break;
            }
            let name = a.prop_name(m);
            let cargs = a.list(obj, B);
            let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
            if named("type") {
                if let Some(v) = cargs.first().and_then(|&c| a.str_value(c)) {
                    return !html_type(v);
                }
            }
            if (named("set") || named("header")) && cargs.len() >= 2 {
                if let (Some(k), Some(v)) = (a.str_value(cargs[0]), a.str_value(cargs[1])) {
                    if eq(&lower(k), "content-type") {
                        return !html_type(v);
                    }
                }
            }
            obj = a.at(m, A);
        }
        false
    }

    /// A route handler's response object, whatever its name.
    fn response_sink(&mut self, callee: NodeId, node: NodeId, args: &[V], line: u32) {
        let name = self.a().prop_name(callee);
        if args.is_empty() {
            return;
        }
        let named = |n: &str| name.as_deref().is_some_and(|x| eq(x, n));
        if named("send") || named("write") || named("end") {
            if !self.not_html_response(callee, node) {
                self.sink(XSS, Some(&args[0]), line);
            }
        } else if named("redirect") {
            self.sink(REDIRECT, Some(&args[args.len() - 1]), line);
        } else if named("location") {
            self.sink(REDIRECT, Some(&args[0]), line);
        } else if (named("sendFile") || named("download")) && !self.has_root(node) {
            self.sink(PATH, Some(&args[0]), line);
        }
    }

    /// Is exec()'s receiver proven to be a RegExp?
    fn regexp_receiver(&mut self, callee: NodeId, scope: ScopeId) -> bool {
        use jt::A;
        let (proto, eval_with) = (self.p.mods[self.m as usize].regexp_proto, self.p.mods[self.m as usize].eval_with);
        if proto || self.a().flag(callee, jt::OPTIONAL) {
            return false;
        }
        let obj = self.a().at(callee, A);
        if self.a().kind(obj) == Kind::Literal && self.a().op(obj) == jt::L_REGEX {
            return true;
        }
        if eval_with {
            return false;
        }
        if self.regexp_construction(obj, scope) {
            return true;
        }
        if self.a().kind(obj) != Kind::Identifier {
            return false;
        }
        let b = match self.bind(obj, scope) {
            None => return false,
            Some(b) => b,
        };
        let bind = &self.p.binds[b as usize];
        if !matches!(bind.kind, BindKind::Const | BindKind::Let | BindKind::Var) || bind.writes.len() != 1 {
            return false;
        }
        let (init, iscope) = match &bind.writes[0] {
            Write::Init { node, scope, path } if path.is_empty() => (*node, *scope),
            _ => return false,
        };
        let refs = bind.refs.clone();
        let is_regex_lit = self.a().kind(init) == Kind::Literal && self.a().op(init) == jt::L_REGEX;
        if !(is_regex_lit || self.regexp_construction(init, iscope)) {
            return false;
        }
        let a = self.a();
        for (r, parent) in refs {
            if parent == NONE || a.kind(parent) != Kind::MemberExpression || a.at(parent, A) != r || a.flag(parent, jt::OPTIONAL) {
                return false;
            }
            let name = a.prop_name(parent);
            if !name.as_deref().is_some_and(|n| is_in(REGEXP_MEMBERS, n)) {
                return false;
            }
            if self.p.mods[self.m as usize].asg[parent as usize] && !name.as_deref().is_some_and(|n| eq(n, "lastIndex")) {
                return false;
            }
        }
        true
    }

    /// `new RegExp(…)` / `RegExp(…)`, RegExp being the global.
    fn regexp_construction(&self, node: NodeId, scope: ScopeId) -> bool {
        let a = self.a();
        if !matches!(a.kind(node), Kind::NewExpression | Kind::CallExpression) {
            return false;
        }
        let callee = a.at(node, jt::A);
        if !a.is_ident_named(callee, "RegExp") {
            return false;
        }
        !self.p.mods[self.m as usize].regexp_rebound && self.p.lookup(scope, &u("RegExp")).is_none()
    }

    /// The categories the call's value is clean for (ALL: every one): a
    /// configured sanitizer always; a built-in one unless the call reaches a
    /// project function (by the name alone: one of that name shadows it).
    fn sanitizer(&self, ctext: &[u32], name: Option<&[u32]>, fids: &[FnId], definite: bool) -> u8 {
        let cfg = &self.p.cfg;
        let cands: [Option<&[u32]>; 2] = [Some(ctext), name];
        for cand in cands.iter().flatten() {
            if cand.is_empty() {
                continue;
            }
            if cfg.full.contains(*cand) {
                return ALL;
            }
            if let Some(&bits) = cfg.partial.get(*cand) {
                if bits != 0 {
                    return bits;
                }
            }
        }
        if definite {
            return 0;
        }
        for cand in cands.iter().flatten() {
            if cand.is_empty() || (!fids.is_empty() && !cand.contains(&0x2E)) {
                continue;
            }
            if let Some(bits) = builtin_sanitizer(cand) {
                return bits;
            }
        }
        0
    }

    // ---- sinks and calls into summaries ----
    fn sink(&mut self, cat: u8, v: Option<&V>, line: u32) {
        let v = match v {
            Some(v) if v.tainted() && v.clean & bit(cat) == 0 => v,
            _ => return,
        };
        let needs = cat == SQL && !v.built;
        let label = Rc::new(self.p.fns[self.fid as usize].label());
        let entry: Entry = (self.m, line, label, needs);
        for &key in v.params.iter() {
            self.reach_adds.push((key, cat, entry.clone()));
        }
        if v.src && v.via.is_some() && self.emit && !needs {
            let (om, oline) = v.origin.expect("request data has an origin");
            let mut src_loc = self.p.mods[om as usize].path.clone();
            src_loc.push(0x3A);
            src_loc.extend(u(&oline.to_string()));
            if let Some(f) = &v.fname {
                if !f.is_empty() {
                    src_loc.extend(u(" (in "));
                    src_loc.extend_from_slice(f);
                    src_loc.extend(u("())"));
                }
            }
            let path = self.p.mods[self.m as usize].path.clone();
            let mut sink_loc = path.clone();
            sink_loc.push(0x3A);
            sink_loc.extend(u(&line.to_string()));
            self.findings.push(Out::Issue {
                cat,
                path,
                file: self.p.mods[self.m as usize].file,
                line,
                source: src_loc,
                sink: sink_loc,
                via: (**v.via.as_ref().expect("checked")).clone(),
            });
        }
    }

    /// The functions a call reaches: their parameters' sinks (a finding
    /// when request data arrives; the reach of the caller's parameters when
    /// they do) and what they return.
    pub(super) fn apply(&mut self, node: NodeId, fids: &[FnId], args: &[V], spread: isize, line: u32, ctor: bool) -> V {
        // (the value a method is called on: the sinks it reaches through its receiver, `this`, are given it; what
        // it returns or keeps of `this` stays with B-1's instance (sc_call), B-3)
        let recv = self.recv_val.take().unwrap_or_else(V::empty);
        let mut out = V::empty();
        // (the supply-chain model: what the script's wrappers of exec print)
        let mut wrapped = V::empty();
        let mut reported: u8 = 0;
        let name = self.callee_name(node);
        for &fid in fids {
            let (nparams, rest) = {
                let f = &self.p.fns[fid as usize];
                let fm = f.module;
                let n = f.params.len();
                let rest = if n > 0 && self.p.mods[fm as usize].tree.nodes[f.params[n - 1] as usize].kind == Kind::RestElement {
                    n as isize - 1
                } else {
                    -1
                };
                (n, rest)
            };
            {
                let used = self.uses.entry(fid).or_default();
                for i in 0..nparams {
                    if bound(args, spread, rest, i).tainted() {
                        used.insert(i);
                    }
                }
            }
            let reach: Vec<(usize, BTreeMap<u8, Entry>)> =
                self.p.fns[fid as usize].reach.iter().map(|(&i, t)| (i, t.clone())).collect();
            for (i, table) in reach {
                let t = bound_or_recv(args, spread, rest, i, &recv);
                if !t.tainted() {
                    // (the supply-chain model: a constant command line given the script's
                    // wrapper of exec, a constant name its getEnv())
                    if self.p.cfg.supply.is_some() {
                        if table.contains_key(&super::supply::EXEC_CMD) {
                            if let Some(src) = self.sc_wrapper_output(node, i) {
                                wrapped = wrapped.union(&src);
                            }
                        }
                        if table.contains_key(&super::supply::ENV_NAME) {
                            if let Some(src) = self.sc_wrapper_read(node, super::supply::ENV_NAME, &t, i) {
                                wrapped = wrapped.union(&src);
                            }
                        }
                        // (the script's own downloader given its own address)
                        if table.contains_key(&super::supply::SEND_ADDR) {
                            if let Some(src) = self.sc_wrapper_receives(node, i, &t) {
                                wrapped = wrapped.union(&src);
                            }
                        }
                    }
                    continue;
                }
                for cat in 0..CATS.len() as u8 {
                    let entry = match table.get(&cat) {
                        Some(e) if t.clean & bit(cat) == 0 => e.clone(),
                        _ => continue,
                    };
                    let needs = entry.3 && !t.built;
                    if self.p.cfg.supply.is_some() {
                        // (a sink the parameter reaches through a member alone: not the whole environment, D-16)
                        let member = self.p.fns[fid as usize].reach_member.get(&(i, cat)).copied().unwrap_or(false);
                        let t = if member { super::supply::sc_through_member(&t) } else { t.clone() };
                        if cat == super::supply::EXEC_CMD || cat == super::supply::READ_PATH || cat == super::supply::ENV_NAME {
                            // (the script's wrappers: of exec given a command line, of a
                            // read given a path outside the package, of getEnv given a name)
                            let src = if cat == super::supply::EXEC_CMD {
                                self.sc_wrapper_output(node, i)
                            } else {
                                self.sc_wrapper_read(node, cat, &t, i)
                            };
                            if let Some(src) = src {
                                wrapped = wrapped.union(&src);
                            }
                            for &key in t.params.iter() {
                                self.reach_adds.push((key, cat, (entry.0, entry.1, entry.2.clone(), false)));
                            }
                            continue;
                        }
                        // (the script's own downloader given an address it read or received)
                        if cat == super::supply::SEND_ADDR && t.src && t.params.is_empty() {
                            if let Some(src) = self.sc_wrapper_receives(node, i, &t) {
                                wrapped = wrapped.union(&src);
                            }
                        }
                        // (received code the callee runs, loads or deserializes)
                        if let Some(rc) = super::supply::received_cat(cat) {
                            if t.src && self.emit && t.sc.as_ref().is_some_and(|s| s.kinds & super::supply::K_RECEIVED != 0) {
                                self.findings.push(Out::Received { at: entry.1, cat: rc });
                            }
                            // (code the script decodes, run by the callee)
                            if t.src && self.emit && cat == super::supply::RUN_CODE {
                                if let Some(from) = t.sc.as_ref().and_then(|s| super::supply::decoded_at(s)) {
                                    self.findings.push(Out::Decoded { at: entry.1, from });
                                }
                            }
                            for &key in t.params.iter() {
                                self.reach_adds.push((key, cat, (entry.0, entry.1, entry.2.clone(), false)));
                            }
                            continue;
                        }
                        // (the supply-chain model: local data at a send the callee reaches)
                        if t.src && self.emit {
                            if let Some(sc) = t.sc.clone() {
                                self.sc_emit(&sc, cat == super::supply::SEND_ADDR, entry.1);
                            }
                        }
                        for &key in t.params.iter() {
                            self.reach_adds.push((key, cat, (entry.0, entry.1, entry.2.clone(), false)));
                        }
                        continue;
                    }
                    if t.src && self.emit && !needs && reported & bit(cat) == 0 {
                        let path = self.p.mods[self.m as usize].path.clone();
                        let mut here = path.clone();
                        here.push(0x3A);
                        here.extend(u(&line.to_string()));
                        let mut there = self.p.mods[entry.0 as usize].path.clone();
                        there.push(0x3A);
                        there.extend(u(&entry.1.to_string()));
                        there.push(0x20);
                        there.extend_from_slice(&entry.2);
                        let mut via = u("the call to ");
                        via.extend_from_slice(&name);
                        via.extend(u("()"));
                        self.findings.push(Out::Issue { cat, path, file: self.p.mods[self.m as usize].file, line, source: here, sink: there, via });
                        reported |= bit(cat);
                    }
                    for &key in t.params.iter() {
                        self.reach_adds.push((key, cat, (entry.0, entry.1, entry.2.clone(), needs)));
                    }
                }
            }
            // (the supply-chain model) the closure variables a parameter is written to
            // (not the `this.x` of a class made in several places, from a call
            // on an instance: the instance holds it, sc_instance_call)
            let writes: Vec<(usize, Vec<BindId>)> =
                self.p.fns[fid as usize].param_writes.iter().map(|(&i, bs)| (i, bs.iter().copied().collect())).collect();
            let outside = !writes.is_empty() && self.sc_on_instance(node);
            for (i, binds) in writes {
                if i == RECV_INDEX {
                    continue; // (what a method keeps of its receiver stays with B-1's instance, B-3)
                }
                let t = bound(args, spread, rest, i);
                if t.tainted() {
                    for b in binds {
                        if outside && self.p.sc_this_class.get(&b).copied().is_some_and(|c| self.p.sc_made_widely(c)) {
                            continue;
                        }
                        self.write(b, t.plain(), false);
                    }
                }
            }
            // (the supply-chain model) the files a parameter is written to: what it is given here (D-2)
            if self.p.cfg.supply.is_some() {
                let files: Vec<(usize, Vec<(Vec<PyStr>, u32)>)> =
                    self.p.fns[fid as usize].param_files.iter().map(|(&i, fs)| (i, fs.iter().cloned().collect())).collect();
                for (i, fs) in files {
                    if i == RECV_INDEX {
                        continue;
                    }
                    let t = bound(args, spread, rest, i);
                    if t.tainted() {
                        for (keys, at) in fs {
                            self.sc_param_file(&t, keys, at);
                        }
                    }
                }
            }
            if ctor {
                continue;
            }
            let f = &self.p.fns[fid as usize];
            if let Some(rs) = &f.ret_src {
                let mut via = u("the value returned by ");
                match &f.name {
                    Some(n) if !n.is_empty() => via.extend_from_slice(n),
                    _ => via.extend(u("an anonymous function")),
                }
                via.extend(u("()"));
                out = out.union(
                    &V::new(true, rs.origin, rs.fname.clone(), Some(Rc::new(via)), V::empty().params, rs.clean, rs.built, 0)
                        .with_sc(rs.sc.clone()),
                );
            }
            let ret_params: Vec<(usize, (u8, bool, bool))> = f.ret_params.iter().map(|(&i, &x)| (i, x)).collect();
            let ret_outer: Vec<(u64, (u8, bool))> = f.ret_outer.iter().map(|(&k, &x)| (k, x)).collect();
            for (i, (clean, built, member)) in ret_params {
                if i == RECV_INDEX {
                    continue; // (what a method returns of its receiver: B-1's instance gives it, sc_call)
                }
                let mut b = bound(args, spread, rest, i);
                if b.tainted() {
                    b = b.plain();
                    // (returned through a member of a name that is not the environment's: not the whole of it, D-16)
                    if member && self.p.cfg.supply.is_some() {
                        b = super::supply::sc_through_member(&b);
                        if !b.tainted() {
                            continue;
                        }
                    }
                    if clean != 0 {
                        b = b.sanitize(clean);
                    }
                    out = out.union(&if built { b.with_built() } else { b });
                }
            }
            for (key, (clean, built)) in ret_outer {
                if self.ancestors.contains(&key_owner(key)) {
                    out = out.union(&V::param(key, clean, built, 0));
                }
            }
        }
        out.union(&wrapped)
    }

    fn callee_name(&self, node: NodeId) -> PyStr {
        let a = self.a();
        let callee = a.unwrap(a.at(node, jt::A));
        if a.is_ident(callee) {
            return a.name(callee).to_vec();
        }
        if a.kind(callee) == Kind::MemberExpression {
            if let Some(n) = a.prop_name(callee) {
                return n;
            }
        }
        u("an anonymous function")
    }

    // ---- JSX ----
    fn jsx(&mut self, e: NodeId, scope: ScopeId) -> R<()> {
        use jt::{A, B, C};
        let mut stack = vec![e];
        while let Some(n) = stack.pop() {
            self.tick(1)?;
            match self.a().kind(n) {
                Kind::JSXElement => {
                    let opening = self.a().at(n, A);
                    let attrs = self.a().list(opening, B).to_vec();
                    for attr in attrs {
                        if self.a().kind(attr) == Kind::JSXSpreadAttribute {
                            let arg = self.a().at(attr, A);
                            self.expr(Some(arg), scope)?;
                            continue;
                        }
                        let value = match self.a().opt(attr, B) {
                            None => continue,
                            Some(v) => v,
                        };
                        let vk = self.a().kind(value);
                        if vk == Kind::JSXElement || vk == Kind::JSXFragment {
                            stack.push(value);
                            continue;
                        }
                        if vk != Kind::JSXExpressionContainer {
                            continue;
                        }
                        let inner = self.a().at(value, A);
                        if self.a().kind(inner) == Kind::JSXEmptyExpression {
                            continue;
                        }
                        let aname = self.a().at(attr, A);
                        let dangerous = self.a().kind(aname) == Kind::JSXIdentifier && eq(self.a().name(aname), "dangerouslySetInnerHTML");
                        let attr_line = self.a().line(attr);
                        if dangerous && self.a().kind(inner) == Kind::ObjectExpression {
                            let props = self.a().list(inner, A).to_vec();
                            for prop in props {
                                let pk = self.a().kind(prop);
                                if pk == Kind::SpreadElement {
                                    let arg = self.a().at(prop, A);
                                    self.expr(Some(arg), scope)?;
                                } else if pk == Kind::Property
                                    && !self.a().computed(prop)
                                    && self.a().key_name(prop).as_deref().is_some_and(|k| eq(k, "__html"))
                                {
                                    let pv = self.a().at(prop, B);
                                    let v = self.expr(Some(pv), scope)?;
                                    self.sink(XSS, Some(&v), attr_line);
                                } else {
                                    let pv = self.a().at(prop, B);
                                    self.expr(Some(pv), scope)?;
                                }
                            }
                        } else {
                            let v = self.expr(Some(inner), scope)?;
                            if dangerous {
                                self.sink(XSS, Some(&v), attr_line);
                            }
                        }
                    }
                    let kids = self.a().list(n, C).to_vec();
                    for &c in kids.iter().rev() {
                        stack.push(c);
                    }
                }
                Kind::JSXFragment => {
                    let kids = self.a().list(n, A).to_vec();
                    for &c in kids.iter().rev() {
                        stack.push(c);
                    }
                }
                Kind::JSXExpressionContainer | Kind::JSXSpreadChild => {
                    let inner = self.a().at(n, A);
                    if self.a().kind(inner) != Kind::JSXEmptyExpression {
                        self.expr(Some(inner), scope)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    // ---- the summary ----

    /// This reading into the function's summary and the shared bindings
    /// (monotone). Returns the functions whose summaries changed, each with
    /// what changed, and the bindings whose value grew.
    pub fn commit(self) -> (Changes, Vec<BindId>) {
        let Eval { p, fid, emit, reach_adds, ret_val, shared_writes, reads, uses, pw_adds, pf_adds, .. } = self;
        let mut changes: Changes = BTreeMap::new();
        for (key, b) in pw_adds {
            let owner = key_owner(key);
            let i = key_index(key);
            if p.fns[owner as usize].param_writes.entry(i).or_default().insert(b) {
                changes.entry(owner).or_default().1.insert(i);
            }
        }
        for (key, keys, at) in pf_adds {
            let owner = key_owner(key);
            let i = key_index(key);
            if p.fns[owner as usize].param_files.entry(i).or_default().insert((keys, at)) {
                changes.entry(owner).or_default().1.insert(i);
            }
        }
        for (key, cat, entry) in reach_adds {
            let owner = key_owner(key);
            let i = key_index(key);
            // (reached through a member alone, D-16; once whole, whole)
            let member = key & MEMBER_KEY != 0;
            let rm = p.fns[owner as usize].reach_member.entry((i, cat)).or_insert(member);
            if *rm && !member {
                *rm = false;
                changes.entry(owner).or_default().1.insert(i);
            }
            let d = p.fns[owner as usize].reach.entry(i).or_default();
            let replace = match d.get(&cat) {
                None => true,
                Some(old) => old.3 && !entry.3,
            };
            if replace {
                d.insert(cat, entry);
                changes.entry(owner).or_default().1.insert(i);
            }
        }
        let is_module = p.fns[fid as usize].is_module;
        if let Some(rv) = ret_val {
            if !is_module && rv.tainted() {
                if rv.src {
                    let f = &mut p.fns[fid as usize];
                    match &f.ret_src {
                        None => {
                            f.ret_src = Some(
                                V::new(true, rv.origin, rv.fname.clone(), None, V::empty().params, rv.clean, rv.built, 0)
                                    .with_sc(rv.sc.clone()),
                            );
                            changes.entry(fid).or_default().0 = true;
                        }
                        Some(old) => {
                            let clean = old.clean & rv.clean;
                            let built = old.built || rv.built;
                            let sc = sc_union(&old.sc, &rv.sc);
                            if clean != old.clean || built != old.built || sc != old.sc {
                                f.ret_src = Some(
                                    V::new(true, old.origin, old.fname.clone(), None, V::empty().params, clean, built, 0)
                                        .with_sc(sc),
                                );
                                changes.entry(fid).or_default().0 = true;
                            }
                        }
                    }
                }
                // (a parameter returned through a member alone, and whole: whole; MEMBER_KEY, D-16)
                let whole: BTreeSet<u64> = rv.params.iter().filter(|&&k| k & MEMBER_KEY == 0).copied().collect();
                for &key in rv.params.iter() {
                    let f = &mut p.fns[fid as usize];
                    let merged = |old: Option<(u8, bool)>| match old {
                        None => (rv.clean, rv.built),
                        Some(o) => (o.0 & rv.clean, o.1 || rv.built),
                    };
                    if key_owner(key) == fid {
                        let k = key_index(key);
                        let member = key & MEMBER_KEY != 0 && !whole.contains(&(key & !MEMBER_KEY));
                        let old = f.ret_params.get(&k).copied();
                        let (clean, built) = merged(old.map(|o| (o.0, o.1)));
                        let new = (clean, built, old.map_or(member, |o| o.2 && member));
                        if old != Some(new) {
                            f.ret_params.insert(k, new);
                            changes.entry(fid).or_default().1.insert(k);
                        }
                    } else {
                        let old = f.ret_outer.get(&key).copied();
                        let new = merged(old);
                        if old != Some(new) {
                            f.ret_outer.insert(key, new);
                            changes.entry(fid).or_default().2.insert(key);
                        }
                    }
                }
            }
        }
        if !emit {
            for (u_fid, used) in uses {
                p.fns[u_fid as usize].callers.insert(fid, used);
            }
        }
        let mut grown = Vec::new();
        let marks = if p.cfg.supply.is_some() { super::supply::MARKS } else { 0 };
        for (bid, v) in shared_writes {
            // (the supply-chain model keeps what a value is, a connection
            // or a client, in a closure's variable too)
            if !v.tainted() && v.kind & marks == 0 {
                continue;
            }
            let old = p.shared.get(&bid);
            let new = match old {
                None => v.clone(),
                Some(o) => o.union(&v),
            };
            if old.map_or(true, |o| *o != new) {
                p.shared.insert(bid, new);
                grown.push(bid);
            }
        }
        for bid in reads {
            let r = p.readers.entry(bid).or_default();
            if !r.contains(&fid) {
                r.push(fid);
            }
        }
        (changes, grown)
    }
}

/// The value parameter i of a function receives, or the receiver a method is called on (RECV_INDEX, B-3), for the
/// sinks the parameter reaches.
fn bound_or_recv(args: &[V], spread: isize, rest: isize, i: usize, recv: &V) -> V {
    if i == RECV_INDEX {
        return recv.clone();
    }
    bound(args, spread, rest, i)
}

/// The value parameter i of a function receives.
fn bound(args: &[V], spread: isize, rest: isize, i: usize) -> V {
    if i as isize == rest {
        return union_all(args.iter().skip(i));
    }
    if spread >= 0 && spread as usize <= i {
        return union_all(args.iter().skip(spread as usize));
    }
    args.get(i).cloned().unwrap_or_else(V::empty)
}

fn sink_value(which: &str, args: &[V]) -> V {
    if args.is_empty() {
        return V::empty();
    }
    match which {
        "first" => args[0].clone(),
        "last" => args[args.len() - 1].clone(),
        "second" => args.get(1).cloned().unwrap_or_else(V::empty),
        _ => union_all(args),
    }
}

/// jsflow.py's FULL_SANITIZERS and PARTIAL_SANITIZERS.
fn builtin_sanitizer(name: &[u32]) -> Option<u8> {
    const FULL: &[&str] =
        &["parseInt", "parseFloat", "Number", "Boolean", "Math.floor", "Math.round", "Math.ceil", "Math.abs", "Math.trunc"];
    if is_in(FULL, name) {
        return Some(ALL);
    }
    const PARTIAL: &[(&str, u8)] = &[
        ("DOMPurify.sanitize", bit(XSS)),
        ("encodeURIComponent", bit(XSS)),
        ("escapeHtml", bit(XSS)),
        ("sanitizeHtml", bit(XSS)),
        ("mysql.escape", bit(SQL)),
        ("mysql2.escape", bit(SQL)),
        ("pool.escape", bit(SQL)),
        ("connection.escape", bit(SQL)),
        ("conn.escape", bit(SQL)),
        ("db.escape", bit(SQL)),
        ("SqlString.escape", bit(SQL)),
        ("path.basename", bit(PATH)),
        ("shellQuote", bit(CMD)),
        ("shell_quote", bit(CMD)),
        ("quote", bit(CMD)),
    ];
    PARTIAL.iter().find(|(n, _)| eq(name, n)).map(|&(_, b)| b)
}

