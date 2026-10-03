//! One reading of one function (flow._Analyzer): its summary's
//! contributions and, when `emit` is set, the findings at its call sites
//! and sinks.

use super::*;
use crate::jsflow::Out;

/// A value's place in a reading's environment: a name, or `name.attr`.
pub(super) type Key = u64;

pub(super) fn key(name: NameId) -> Key {
    name as u64
}

pub(super) fn attr_key(name: NameId, attr: NameId) -> Key {
    ((name as u64 + 1) << 32) | attr as u64
}

/// A sanitizer's effect: everything, or some categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum San {
    Full,
    Partial(u8),
}

pub struct Analyzer<'p> {
    pub p: &'p mut Project,
    pub f: FnId,
    pub m: ModId,
    pub emit: bool,
    pub findings: &'p mut Vec<Out>,
    pub(super) env: QuickMap<Key, Taint>,
    /// (parameter index, category, the sink's place)
    pub(super) sink_adds: Vec<(u16, u8, SinkLoc)>,
    /// parameter index -> the categories it is clean for where returned
    pub(super) ret_params: Vec<(u16, u8)>,
    pub(super) ret_source: Option<Taint>,
    /// self.<attr> written with request data
    pub(super) attr_writes: Vec<(NameId, Taint)>,
    /// the step count the reading may reach
    limit: u64,
    /// the supply-chain model (`supply.rs`) instead of project mode's
    pub(super) supply: bool,
    /// (the supply-chain model) the reading changed what every function reads
    pub(super) sc_dirty: bool,
    /// (the supply-chain model) the module's containers this function puts
    /// values in (`INFO['h'] = …`, `DATA.append(…)`; it binds no such name)
    pub(super) sc_mutated: Vec<NameId>,
    /// (the supply-chain model) the same for a function around this one: its
    /// variable, and the function
    pub(super) sc_mutated_back: Vec<(FnId, NameId)>,
    /// (the supply-chain model) lambdas being read at a call, inside each other
    pub(super) sc_inline: u8,
}

/// flow._bind: a call's argument values bound to `g`'s parameters as
/// inspect.signature binds them (name -> value).
pub(super) fn bind(g: &Func, pos: &[Taint], starred: Option<&Taint>, kws: &[(NameId, Taint)], dstar: Option<&Taint>, skip_first: bool) -> Vec<(NameId, Taint)> {
    let all_pos: Vec<NameId> = g.posonly.iter().chain(g.args.iter()).copied().collect();
    let positional: &[NameId] = if skip_first && !all_pos.is_empty() { &all_pos[1..] } else { &all_pos };
    let mut out: Vec<(NameId, Taint)> = Vec::new();
    fn put(out: &mut Vec<(NameId, Taint)>, name: NameId, t: &Taint) {
        match out.iter_mut().find(|(k, _)| *k == name) {
            Some(e) => e.1 = e.1.union(t),
            None => out.push((name, t.clone())),
        }
    }
    let mut i = 0;
    for t in pos {
        if i < positional.len() {
            put(&mut out, positional[i], t);
            i += 1;
        } else if let Some(v) = g.vararg {
            put(&mut out, v, t);
        }
    }
    if let Some(s) = starred {
        for &p in &positional[i..] {
            put(&mut out, p, s);
        }
        if let Some(v) = g.vararg {
            put(&mut out, v, s);
        }
    }
    let mut by_name: Vec<NameId> = Vec::new();
    for &n in g.args.iter().chain(g.kwonly.iter()) {
        if !by_name.contains(&n) {
            by_name.push(n);
        }
    }
    if skip_first && !all_pos.is_empty() {
        let first = all_pos[0];
        by_name.retain(|&n| n != first);
    }
    for (name, t) in kws {
        if by_name.contains(name) {
            put(&mut out, *name, t);
        } else if let Some(k) = g.kwarg {
            put(&mut out, k, t);
        }
    }
    if let Some(d) = dstar {
        for &p in &by_name {
            if !out.iter().any(|(k, _)| *k == p) {
                put(&mut out, p, d);
            }
        }
        if let Some(k) = g.kwarg {
            put(&mut out, k, d);
        }
    }
    out
}

fn bound_get(b: &[(NameId, Taint)], name: NameId) -> Option<&Taint> {
    b.iter().find(|(k, _)| *k == name).map(|(_, t)| t)
}

impl<'p> Analyzer<'p> {
    pub fn new(p: &'p mut Project, f: FnId, emit: bool, findings: &'p mut Vec<Out>) -> Analyzer<'p> {
        let m = p.fns[f as usize].module;
        let size = p.fns[f as usize].size;
        let limit = p.work + p.cfg.run.0 + p.cfg.run.1 * size;
        let mut env: QuickMap<Key, Taint> = QuickMap::default();
        let pnames = p.fns[f as usize].pnames.clone();
        for (k, &name) in pnames.iter().enumerate() {
            env.insert(key(name), Taint::param(k as u16));
        }
        let line = p.fns[f as usize].line;
        let supply = p.cfg.supply.is_some();
        let request_params = if supply { Rc::new(Vec::new()) } else { p.request_params(f) };
        for name in request_params.iter() {
            let params: Params = match pnames.iter().position(|&n| n == *name) {
                Some(k) => Rc::from(vec![k as u16]),
                None => no_params(),
            };
            env.insert(key(*name), Taint { params, ..Taint::src(0, Some((m, line)), None) });
        }
        if let Some(r) = p.fns[f as usize].receiver {
            env.insert(key(r), Taint::empty());
        }
        Analyzer {
            p,
            f,
            m,
            emit,
            findings,
            env,
            sink_adds: Vec::new(),
            ret_params: Vec::new(),
            ret_source: None,
            attr_writes: Vec::new(),
            limit,
            supply,
            sc_dirty: false,
            sc_mutated: Vec::new(),
            sc_mutated_back: Vec::new(),
            sc_inline: 0,
        }
    }

    #[inline]
    pub(super) fn t(&self) -> &Tree {
        &self.p.mods[self.m as usize].tree
    }

    #[inline]
    pub(super) fn step(&mut self) -> Result<(), Halt> {
        self.p.work += 1;
        if self.p.work > self.limit {
            return Err(Halt::Cut);
        }
        Ok(())
    }

    pub(super) fn line(&self, n: NodeId) -> u32 {
        let t = self.t();
        t.line_of(t.node(n).start)
    }

    pub(super) fn name_of(&mut self, sid: u32) -> NameId {
        self.p.name(self.m, sid)
    }

    // ---------- reporting / summaries ----------

    fn report(&mut self, cat: u8, line: u32, source: PyStr, sink: PyStr, chain: PyStr) {
        let md = &self.p.mods[self.m as usize];
        self.findings.push(Out::Issue { cat, path: md.path.clone(), file: md.file, line, source, sink, via: chain });
    }

    fn ret(&mut self, t: &Taint) {
        if t.source || t.marks != 0 {
            self.ret_source = Some(match &self.ret_source {
                None => t.clone(),
                Some(r) => r.union(t),
            });
        }
        for &p in t.params.iter() {
            match self.ret_params.iter_mut().find(|(k, _)| *k == p) {
                Some(e) => e.1 &= t.clean,
                None => self.ret_params.push((p, t.clean)),
            }
        }
    }

    fn sink(&mut self, cat: u8, t: Option<&Taint>, line: u32) {
        let t = match t {
            Some(t) if t.tainted() && t.clean & bit(cat) == 0 => t.clone(),
            _ => return,
        };
        for &p in t.params.iter() {
            self.sink_adds.push((p, cat, (self.f, line)));
        }
        if t.source && self.emit {
            if let (Some(via), Some(origin)) = (t.via, t.origin) {
                let source = self.p.origin_text(origin);
                let here = self.p.origin_text((self.m, line));
                let mut chain = pystr::u("the value returned by ");
                chain.extend(self.p.qualname(via));
                chain.extend(pystr::u("()"));
                self.report(cat, line, source, here, chain);
            }
        }
    }

    // ---------- statements ----------

    pub fn run(&mut self) -> Result<(), Halt> {
        let node = self.p.fns[self.f as usize].node;
        if self.supply && !self.p.fns[self.f as usize].pseudo {
            self.sc_defaults(node)?;
        }
        let body: Vec<u32> = body_of(self.t(), node).to_vec();
        self.stmts(&body)
    }

    fn stmts(&mut self, body: &[u32]) -> Result<(), Halt> {
        self.p.enter()?;
        let mut r = Ok(());
        for &st in body {
            r = self.stmt(st);
            if r.is_err() {
                break;
            }
        }
        self.p.leave();
        r
    }

    fn merge(a: &QuickMap<Key, Taint>, b: &QuickMap<Key, Taint>) -> QuickMap<Key, Taint> {
        let mut out = a.clone();
        for (k, v) in b {
            let nv = match out.get(k) {
                Some(o) => o.union(v),
                None => v.clone(),
            };
            out.insert(*k, nv);
        }
        out
    }

    pub(super) fn stmt(&mut self, st: NodeId) -> Result<(), Halt> {
        self.p.enter()?;
        let r = self.stmt_inner(st);
        self.p.leave();
        r
    }

    fn stmt_inner(&mut self, st: NodeId) -> Result<(), Halt> {
        self.step()?;
        let kind = self.t().kind(st);
        let (a, b, c, d) = {
            let t = self.t();
            (a_(t, st), b_(t, st), c_(t, st), d_(t, st))
        };
        match kind {
            Kind::FunctionDef | Kind::AsyncFunctionDef | Kind::ClassDef => {
                let decs: Vec<u32> = decorators(self.t(), st).to_vec();
                for dn in decs {
                    self.expr(dn)?;
                }
                if self.supply && kind == Kind::ClassDef {
                    self.sc_class_body(st)?;
                }
            }
            Kind::Assign => {
                let v = self.expr(b)?;
                let targets: Vec<u32> = self.t().list(a).to_vec();
                for tg in targets {
                    self.assign(tg, &v)?;
                }
            }
            Kind::AugAssign => {
                let v = self.expr(b)?;
                let cur = self.expr(a)?;
                self.assign(a, &cur.union(&v))?;
            }
            Kind::AnnAssign => {
                if c != NONE {
                    let v = self.expr(c)?;
                    self.assign(a, &v)?;
                }
            }
            Kind::Return => {
                let v = if a != NONE { self.expr(a)? } else { Taint::empty() };
                self.ret(&v);
            }
            Kind::Expr => {
                self.expr(a)?;
            }
            Kind::If => {
                self.expr(a)?;
                let guard = self.guard(a)?;
                let before = self.env.clone();
                if let Some((name, cats, true)) = guard {
                    let t = self.name_taint(name).sanitize(cats);
                    self.env.insert(key(name), t);
                }
                let body: Vec<u32> = self.t().list(b).to_vec();
                let orelse: Vec<u32> = self.t().list(c).to_vec();
                self.stmts(&body)?;
                let after_body = std::mem::replace(&mut self.env, before);
                let leaves_body = leaves(self.t(), &body);
                match guard {
                    Some((name, cats, false)) if leaves_body => {
                        let t = self.name_taint(name).sanitize(cats);
                        self.env.insert(key(name), t);
                        self.stmts(&orelse)?;
                    }
                    _ => {
                        self.stmts(&orelse)?;
                        self.env = Self::merge(&after_body, &self.env);
                    }
                }
            }
            Kind::For | Kind::AsyncFor => {
                let it = self.expr(b)?;
                let before = self.env.clone();
                let body: Vec<u32> = self.t().list(c).to_vec();
                for _ in 0..2 {
                    self.assign(a, &it)?;
                    self.stmts(&body)?;
                }
                self.env = Self::merge(&before, &self.env);
                let orelse: Vec<u32> = self.t().list(d).to_vec();
                self.stmts(&orelse)?;
            }
            Kind::While => {
                let before = self.env.clone();
                let body: Vec<u32> = self.t().list(b).to_vec();
                for _ in 0..2 {
                    self.expr(a)?;
                    self.stmts(&body)?;
                }
                self.env = Self::merge(&before, &self.env);
                let orelse: Vec<u32> = self.t().list(c).to_vec();
                self.stmts(&orelse)?;
            }
            Kind::With | Kind::AsyncWith => {
                let items: Vec<u32> = self.t().list(a).to_vec();
                for item in items {
                    let (ce, ov) = {
                        let t = self.t();
                        (a_(t, item), b_(t, item))
                    };
                    let v = self.expr(ce)?;
                    if ov != NONE {
                        self.assign(ov, &v)?;
                    }
                }
                let body: Vec<u32> = self.t().list(b).to_vec();
                self.stmts(&body)?;
            }
            Kind::Try | Kind::TryStar => {
                let before = self.env.clone();
                let body: Vec<u32> = self.t().list(a).to_vec();
                self.stmts(&body)?;
                let after = self.env.clone();
                let merged = Self::merge(&before, &after);
                let mut outs: Vec<QuickMap<Key, Taint>> = Vec::new();
                let handlers: Vec<u32> = self.t().list(b).to_vec();
                for h in handlers {
                    self.env = merged.clone();
                    let (htype, hname, hbody) = {
                        let t = self.t();
                        (a_(t, h), b_(t, h), t.list(c_(t, h)).to_vec())
                    };
                    if htype != NONE {
                        self.expr(htype)?;
                    }
                    if hname != NONE {
                        let k = self.name_of(hname);
                        self.env.insert(key(k), Taint::empty());
                    }
                    self.stmts(&hbody)?;
                    outs.push(std::mem::take(&mut self.env));
                }
                self.env = after;
                let orelse: Vec<u32> = self.t().list(c).to_vec();
                self.stmts(&orelse)?;
                let mut acc = std::mem::take(&mut self.env);
                for o in &outs {
                    acc = Self::merge(&acc, o);
                }
                self.env = acc;
                let finalbody: Vec<u32> = self.t().list(d).to_vec();
                self.stmts(&finalbody)?;
            }
            Kind::Match => {
                let subj = self.expr(a)?;
                let before = self.env.clone();
                let mut acc = before.clone();
                let cases: Vec<u32> = self.t().list(b).to_vec();
                for case in cases {
                    self.env = before.clone();
                    let (pat, guard, body) = {
                        let t = self.t();
                        (a_(t, case), b_(t, case), t.list(c_(t, case)).to_vec())
                    };
                    self.bind_pattern(pat, &subj);
                    if guard != NONE {
                        self.expr(guard)?;
                    }
                    self.stmts(&body)?;
                    acc = Self::merge(&acc, &self.env);
                }
                self.env = acc;
            }
            Kind::Raise => {
                if a != NONE {
                    self.expr(a)?;
                }
                if b != NONE {
                    self.expr(b)?;
                }
            }
            Kind::Assert => {
                self.expr(a)?;
                if b != NONE {
                    self.expr(b)?;
                }
            }
            Kind::Import
            | Kind::ImportFrom
            | Kind::Global
            | Kind::Nonlocal
            | Kind::Pass
            | Kind::Break
            | Kind::Continue
            | Kind::Delete => {}
            _ => {
                let mut kids: Vec<NodeId> = Vec::new();
                self.t().each_child(st, |x| kids.push(x));
                for x in kids {
                    let k = self.t().kind(x);
                    if k.is_expr() {
                        self.expr(x)?;
                    } else if k.is_stmt() {
                        self.stmt(x)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// (the name node's name, categories, positive) of a guard on a local
    /// name, its allowlist free of request data (flow._Analyzer.guard).
    fn guard(&mut self, test: NodeId) -> Result<Option<(NameId, u8, bool)>, Halt> {
        let g = guard_of(self.t(), test);
        let (name_node, cats, positive, coll) = match g {
            None => return Ok(None),
            Some(g) => g,
        };
        if coll != NONE && self.expr(coll)?.tainted() {
            return Ok(None);
        }
        let sid = a_(self.t(), name_node);
        let name = self.name_of(sid);
        Ok(Some((name, cats, positive)))
    }

    fn bind_pattern(&mut self, pat: NodeId, t: &Taint) {
        let mut stack = vec![pat];
        while let Some(p) = stack.pop() {
            if p == NONE {
                continue;
            }
            let kind = self.t().kind(p);
            let name_sid = match kind {
                Kind::MatchAs => b_(self.t(), p),
                Kind::MatchStar => a_(self.t(), p),
                Kind::MatchMapping => c_(self.t(), p),
                _ => NONE,
            };
            if name_sid != NONE {
                let k = self.name_of(name_sid);
                self.env.insert(key(k), t.clone());
            }
            let tr = self.t();
            match kind {
                Kind::MatchAs => {
                    let sub = a_(tr, p);
                    if sub != NONE {
                        stack.push(sub);
                    }
                }
                Kind::MatchOr | Kind::MatchSequence => stack.extend_from_slice(tr.list(a_(tr, p))),
                Kind::MatchMapping => stack.extend_from_slice(tr.list(b_(tr, p))),
                Kind::MatchClass => {
                    stack.extend_from_slice(tr.list(b_(tr, p)));
                    stack.extend_from_slice(tr.list(d_(tr, p)));
                }
                _ => {}
            }
        }
    }

    pub(super) fn assign(&mut self, tgt: NodeId, t: &Taint) -> Result<(), Halt> {
        self.p.enter()?;
        let r = self.assign_inner(tgt, t);
        self.p.leave();
        r
    }

    fn assign_inner(&mut self, tgt: NodeId, t: &Taint) -> Result<(), Halt> {
        let kind = self.t().kind(tgt);
        match kind {
            Kind::Name => {
                let sid = a_(self.t(), tgt);
                let k = self.name_of(sid);
                self.env.insert(key(k), t.clone());
            }
            Kind::Tuple | Kind::List => {
                let elts: Vec<u32> = self.t().list(a_(self.t(), tgt)).to_vec();
                for e in elts {
                    self.assign(e, t)?;
                }
            }
            Kind::Starred => {
                let v = a_(self.t(), tgt);
                self.assign(v, t)?;
            }
            Kind::Attribute => {
                let (v, attr) = {
                    let tr = self.t();
                    (a_(tr, tgt), b_(tr, tgt))
                };
                if self.t().kind(v) == Kind::Name {
                    let sid = a_(self.t(), v);
                    let base = self.name_of(sid);
                    let attr = self.name_of(attr);
                    self.env.insert(attr_key(base, attr), t.clone());
                    if self.supply && self.p.fns[self.f as usize].receiver != Some(base) {
                        self.sc_member_write(base, t);
                    }
                    let func = &self.p.fns[self.f as usize];
                    if func.cls.is_some() && func.receiver == Some(base) && (t.source || t.marks != 0) {
                        match self.attr_writes.iter_mut().find(|(k, _)| *k == attr) {
                            Some(e) => e.1 = e.1.union(t),
                            None => self.attr_writes.push((attr, t.clone())),
                        }
                    }
                } else {
                    self.expr(v)?;
                }
            }
            Kind::Subscript => {
                let (base, slice) = {
                    let tr = self.t();
                    (a_(tr, tgt), b_(tr, tgt))
                };
                self.expr(slice)?;
                if self.t().kind(base) == Kind::Name {
                    let sid = a_(self.t(), base);
                    let k = self.name_of(sid);
                    let nt = self.name_taint(k).union(t);
                    self.env.insert(key(k), nt);
                    if self.supply && (t.source || t.marks != 0) {
                        self.sc_mutate(k);
                    }
                } else {
                    let bv = self.expr(base)?;
                    if self.supply {
                        self.sc_env_write(&bv, slice, t);
                        // a container reached through an attribute or a
                        // subscript (`self.info['h'] = …`, `d['m']['h'] = …`)
                        // holds what it is given
                        let held = t.plain();
                        if (held.source || held.marks != 0) && matches!(self.t().kind(base), Kind::Attribute | Kind::Subscript) {
                            self.assign(base, &bv.plain().union(&held))?;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ---------- expressions ----------

    pub(super) fn name_taint(&self, name: NameId) -> Taint {
        if let Some(v) = self.env.get(&key(name)) {
            if self.supply {
                // (what a nested function gave the variable)
                if let Some(back) = self.p.closure_back.get(&self.f).and_then(|vars| vars.get(&name)) {
                    return v.union(back);
                }
            }
            return v.clone();
        }
        if self.supply {
            // (a closure's variable: what the function around it gives it)
            if let Some(v) = self.sc_closure(name) {
                return v;
            }
        }
        self.p.mods[self.m as usize].globals.get(&name).cloned().unwrap_or_else(Taint::empty)
    }

    fn source(&self, line: u32) -> Taint {
        Taint::src(0, Some((self.m, line)), None)
    }

    fn is_source_text(&mut self, s: &[u32]) -> bool {
        let canon = self.p.canonical(self.m, s);
        self.p.cfg.is_source(s) || self.p.cfg.is_source(&canon)
    }

    /// Is an attribute's or a subscript's dotted text a source: once per
    /// node (the answer is the same at every reading).
    fn is_source_node(&mut self, e: NodeId) -> bool {
        if let Some(&hit) = self.p.src_memo.get(&(self.m, e)) {
            return hit;
        }
        let (s, links) = dotted_links(self.t(), e);
        self.p.charge(links + 3 * s.len() as u64);
        let hit = self.is_source_text(&s);
        self.p.src_memo.insert((self.m, e), hit);
        hit
    }

    pub fn expr(&mut self, e: NodeId) -> Result<Taint, Halt> {
        if e == NONE {
            return Ok(Taint::empty());
        }
        self.p.enter()?;
        let r = self.expr_inner(e);
        self.p.leave();
        r
    }

    fn expr_inner(&mut self, e: NodeId) -> Result<Taint, Halt> {
        self.step()?;
        let kind = self.t().kind(e);
        let (a, b, c) = {
            let t = self.t();
            (a_(t, e), b_(t, e), c_(t, e))
        };
        match kind {
            Kind::Name => {
                let k = self.name_of(a);
                if self.supply {
                    if let Some(v) = self.sc_name(e, k) {
                        return Ok(v);
                    }
                }
                Ok(self.name_taint(k))
            }
            Kind::Constant => {
                if self.supply {
                    return Ok(self.sc_literal(e));
                }
                Ok(Taint::empty())
            }
            Kind::Call => self.call(e),
            Kind::Attribute => {
                if self.supply {
                    if let Some(v) = self.sc_attribute(e)? {
                        return Ok(v);
                    }
                } else if self.is_source_node(e) {
                    let line = self.line(e);
                    return Ok(self.source(line));
                }
                if self.t().kind(a) == Kind::Name {
                    let base_sid = a_(self.t(), a);
                    let base = self.name_of(base_sid);
                    let attr = self.name_of(b);
                    if let Some(v) = self.env.get(&attr_key(base, attr)) {
                        return Ok(v.clone());
                    }
                    let (cls, recv) = {
                        let func = &self.p.fns[self.f as usize];
                        (func.cls, func.receiver)
                    };
                    if let Some(c) = cls {
                        if recv == Some(base) {
                            if let Some(t) = self.p.mro_attr_taint(c, attr)? {
                                return Ok(t);
                            }
                        }
                    }
                }
                self.expr(a)
            }
            Kind::Subscript => {
                if !self.supply && self.is_source_node(e) {
                    self.expr(b)?;
                    let line = self.line(e);
                    return Ok(self.source(line));
                }
                let v = self.expr(a)?;
                let k = self.expr(b)?;
                if self.supply {
                    if let Some(x) = self.sc_subscript(e, &v, &k) {
                        return Ok(x);
                    }
                    // (a reversal decodes: `s[::-1]`)
                    if self.sc_reversal(b) {
                        let at = self.start(e);
                        return Ok(self.sc_decoded(&v, "a reversal", at));
                    }
                    // (a slice of a binary read past its start: bytes carved out of the file)
                    if let Some(c) = self.sc_carved(b, &v, self.start(e)) {
                        return Ok(c);
                    }
                    return Ok(v.plain());
                }
                Ok(v)
            }
            Kind::BinOp => {
                let l = self.expr(a)?;
                let r = self.expr(b)?;
                if self.supply {
                    self.sc_binop(e, &r);
                    // (an XOR decodes: `chr(ord(c) ^ k)`)
                    if self.t().node(e).op == pt::BITXOR {
                        let at = self.start(e);
                        return Ok(self.sc_decoded(&l.union(&r), "an XOR", at));
                    }
                    return Ok(l.plain().union(&r.plain()));
                }
                Ok(l.union(&r))
            }
            Kind::BoolOp => {
                let vals: Vec<u32> = self.t().list(a).to_vec();
                let mut out = Vec::with_capacity(vals.len());
                for v in vals {
                    out.push(self.expr(v)?);
                }
                Ok(union_all(&out))
            }
            Kind::UnaryOp => {
                let v = self.expr(a)?;
                if self.t().node(e).op == pt::NOT {
                    Ok(Taint::empty())
                } else {
                    Ok(v)
                }
            }
            Kind::Compare => {
                self.expr(a)?;
                let comps: Vec<u32> = self.t().list(c).to_vec();
                for x in comps {
                    self.expr(x)?;
                }
                Ok(Taint::empty())
            }
            Kind::IfExp => {
                self.expr(a)?;
                let l = self.expr(b)?;
                let r = self.expr(c)?;
                Ok(l.union(&r))
            }
            Kind::JoinedStr => {
                let vals: Vec<u32> = self.t().list(a).to_vec();
                let mut out = Vec::with_capacity(vals.len());
                for &v in &vals {
                    out.push(self.expr(v)?);
                }
                if self.supply {
                    let parts: Vec<(NodeId, Taint)> = vals.iter().copied().zip(out.iter().cloned()).collect();
                    self.sc_fstring(e, &parts);
                    let plains: Vec<Taint> = out.iter().map(|x| x.plain()).collect();
                    return Ok(union_all(&plains));
                }
                Ok(union_all(&out))
            }
            Kind::FormattedValue => {
                if b != NONE {
                    self.expr(b)?;
                }
                self.expr(a)
            }
            Kind::List | Kind::Tuple | Kind::Set => {
                let elts: Vec<u32> = self.t().list(a).to_vec();
                let mut out = Vec::with_capacity(elts.len());
                for x in elts {
                    out.push(self.expr(x)?);
                }
                Ok(union_all(&out))
            }
            Kind::Dict => {
                let keys: Vec<u32> = self.t().list(a).to_vec();
                let values: Vec<u32> = self.t().list(b).to_vec();
                let mut out = Vec::with_capacity(keys.len() + values.len());
                for k in keys {
                    if k != NONE {
                        out.push(self.expr(k)?);
                    }
                }
                for v in values {
                    out.push(self.expr(v)?);
                }
                Ok(union_all(&out))
            }
            Kind::Starred | Kind::Await => self.expr(a),
            Kind::Yield | Kind::YieldFrom => {
                let v = self.expr(a)?;
                self.ret(&v);
                Ok(Taint::empty())
            }
            Kind::NamedExpr => {
                let v = self.expr(b)?;
                self.assign(a, &v)?;
                Ok(v)
            }
            Kind::ListComp | Kind::SetComp | Kind::GeneratorExp => {
                let gens: Vec<u32> = self.t().list(b).to_vec();
                let v = self.comprehension(&gens, &[a])?;
                // (characters made of their codes decode: `chr(c) for c in codes`;
                // one `chr(n)` is a character)
                if self.supply && self.sc_chr_call(a) {
                    let at = self.start(e);
                    return Ok(self.sc_decoded(&v, "characters' codes", at));
                }
                Ok(v)
            }
            Kind::DictComp => {
                let gens: Vec<u32> = self.t().list(c).to_vec();
                self.comprehension(&gens, &[a, b])
            }
            Kind::Lambda => {
                if self.supply {
                    self.sc_lambda(e)?;
                }
                Ok(Taint::empty())
            }
            _ => {
                let mut kids: Vec<NodeId> = Vec::new();
                self.t().each_child(e, |x| kids.push(x));
                for x in kids {
                    if self.t().kind(x).is_expr() {
                        self.expr(x)?;
                    }
                }
                Ok(Taint::empty())
            }
        }
    }

    fn comprehension(&mut self, gens: &[u32], elts: &[NodeId]) -> Result<Taint, Halt> {
        self.p.enter()?;
        let saved = self.env.clone();
        let r = self.comprehension_inner(gens, elts);
        self.env = saved;
        self.p.leave();
        r
    }

    fn comprehension_inner(&mut self, gens: &[u32], elts: &[NodeId]) -> Result<Taint, Halt> {
        let mut selected = false;
        for &g in gens {
            let (target, iter, ifs) = {
                let t = self.t();
                (a_(t, g), b_(t, g), t.list(c_(t, g)).to_vec())
            };
            let v = self.expr(iter)?;
            if self.supply && self.sc_selects_env(&v, &ifs) {
                selected = true;
            }
            self.assign(target, &if self.supply { v.plain() } else { v })?;
            for cond in ifs {
                self.expr(cond)?;
            }
        }
        let mut out = Vec::with_capacity(elts.len());
        for &x in elts {
            out.push(self.expr(x)?);
        }
        if selected {
            // (the supply-chain model: some of the environment's variables)
            return Ok(Taint::empty());
        }
        Ok(union_all(&out))
    }

    fn call(&mut self, e: NodeId) -> Result<Taint, Halt> {
        self.p.enter()?;
        let r = self.call_inner(e);
        self.p.leave();
        r
    }

    fn call_inner(&mut self, e: NodeId) -> Result<Taint, Halt> {
        let (func, args, keywords) = {
            let t = self.t();
            (a_(t, e), t.list(b_(t, e)).to_vec(), t.list(c_(t, e)).to_vec())
        };
        let res = self.p.resolve_call(self.f, e)?;
        let func_is_attr = self.t().kind(func) == Kind::Attribute;
        let recv = if func_is_attr { self.expr(a_(self.t(), func))? } else { Taint::empty() };
        let mut pos: Vec<Taint> = Vec::new();
        let mut starred: Option<Taint> = None;
        let mut kws: Vec<(NameId, Taint)> = Vec::new();
        let mut dstar: Option<Taint> = None;
        let mut body: Option<Taint> = None;
        for a in args {
            let kind = self.t().kind(a);
            let tuple_elts: Vec<u32> = if kind == Kind::Tuple { self.t().list(a_(self.t(), a)).to_vec() } else { Vec::new() };
            if pos.is_empty() && starred.is_none() && kind == Kind::Tuple && !tuple_elts.is_empty() {
                let mut elts = Vec::with_capacity(tuple_elts.len());
                for x in tuple_elts {
                    elts.push(self.expr(x)?);
                }
                body = Some(elts[0].clone());
                pos.push(union_all(&elts));
            } else if kind == Kind::Starred {
                let v = self.expr(a_(self.t(), a))?;
                starred = Some(match starred {
                    None => v,
                    Some(s) => s.union(&v),
                });
            } else if let Some(s) = starred.take() {
                let v = self.expr(a)?;
                starred = Some(s.union(&v));
            } else {
                pos.push(self.expr(a)?);
            }
        }
        for k in keywords {
            let (karg, kv) = {
                let t = self.t();
                (a_(t, k), b_(t, k))
            };
            let v = self.expr(kv)?;
            if karg == NONE {
                dstar = Some(match dstar {
                    None => v,
                    Some(d) => d.union(&v),
                });
            } else {
                let name = self.name_of(karg);
                kws.push((name, v));
            }
        }
        let all_args = {
            let mut vals: Vec<&Taint> = pos.iter().collect();
            if let Some(s) = &starred {
                vals.push(s);
            }
            if let Some(d) = &dstar {
                vals.push(d);
            }
            vals.extend(kws.iter().map(|(_, v)| v));
            union_all(vals)
        };
        let line = self.line(e);
        if self.supply {
            return self.sc_call(e, &res, &recv, &pos, starred.as_ref(), &kws, dstar.as_ref());
        }

        let class = res.class;

        // 1) sources: request.args.get(...), input(), sys.argv, …
        if class.source {
            return Ok(self.source(line));
        }

        // 2) a direct sink: only the primary data argument is a sink position
        if let Some(c) = class.sink {
            let first: Option<Taint> = if body.is_some() && c == XSS {
                body.clone()
            } else if !pos.is_empty() {
                Some(pos[0].clone())
            } else if starred.is_some() {
                starred.clone()
            } else if !kws.is_empty() {
                Some(kws[0].1.clone())
            } else {
                dstar.clone()
            };
            self.sink(c, first.as_ref(), line);
        }

        // 3) calls into project functions whose parameters reach sinks
        let mut bound_all: Vec<(FnId, Vec<(NameId, Taint)>)> = Vec::new();
        for &(g, skip) in &res.targets {
            let bound = bind(&self.p.fns[g as usize], &pos, starred.as_ref(), &kws, dstar.as_ref(), skip);
            let pts = self.p.fns[g as usize].param_to_sink.clone();
            for (pname, cats) in pts {
                let t = match bound_get(&bound, pname) {
                    Some(t) if t.tainted() => t.clone(),
                    _ => continue,
                };
                for (c, loc) in cats {
                    if t.clean & bit(c) != 0 {
                        continue;
                    }
                    if t.source && self.emit {
                        if let Some(origin) = t.origin {
                            let source = self.p.origin_text(origin);
                            let sink = self.p.sink_text(loc);
                            let mut chain = pystr::u("the call to ");
                            chain.extend(self.p.qualname(g));
                            chain.extend(pystr::u("()"));
                            self.report(c, line, source, sink, chain);
                        }
                    }
                    for &q in t.params.iter() {
                        self.sink_adds.push((q, c, loc));
                    }
                }
            }
            bound_all.push((g, bound));
        }

        // 4) the call's own value
        match class.config_san {
            Some(San::Full) => return Ok(Taint::empty()),
            Some(San::Partial(cats)) => return Ok(all_args.sanitize(cats)),
            None => {}
        }
        if !bound_all.is_empty() || res.ctor.is_some() {
            let mut t = Taint::empty();
            for (g, bound) in &bound_all {
                let gf = &self.p.fns[*g as usize];
                if let Some(rs) = &gf.ret_source {
                    t = t.union(&Taint { via: Some(*g), ..rs.as_source() });
                }
                for &(pname, clean) in &gf.param_to_return {
                    if let Some(b) = bound_get(bound, pname) {
                        if b.tainted() {
                            t = t.union(&b.sanitize(clean));
                        }
                    }
                }
            }
            if res.ctor.is_some() || !res.precise {
                t = t.union(&all_args);
            }
            return Ok(t);
        }
        let san = class.builtin_san;
        if san == Some(San::Full) {
            return Ok(Taint::empty());
        }
        if class.full_result {
            return Ok(Taint::empty());
        }
        if class.sql_builder {
            return Ok(all_args.union(&recv).sanitize(bit(SQL)));
        }
        if let Some(San::Partial(cats)) = san {
            return Ok(all_args.sanitize(cats));
        }
        if class.clean_result {
            return Ok(Taint::empty());
        }
        Ok(all_args.union(&recv))
    }
}

/// What a call's callee texts make it (`CallClass`: flow's checks, in the
/// order `Analyzer::call` asks them): `raw` its dotted text, `canon` with an
/// import alias at its head replaced, `precise` its resolution, `attr`
/// whether it calls an attribute.
pub fn classify(cfg: &Config, raw: &[u32], canon: &[u32], precise: bool, attr: bool) -> CallClass {
    let source = cfg.is_source(raw) || cfg.is_source(canon) || pystr::eq(raw, "input") || pystr::ends_with(raw, ".get_json");
    let mut sink = cfg.config_sink(&[raw, canon]);
    if sink.is_none() && !precise {
        sink = builtin_sink(canon).or_else(|| builtin_sink(raw));
    }
    let mut dot_raw = vec![0x2E];
    dot_raw.extend_from_slice(raw);
    // (an attribute's name is the last part of its dotted text)
    let attr_is_builder = attr && is_in(last_part(raw), SQL_BUILDER_METHODS);
    CallClass {
        source,
        sink,
        config_san: cfg.config_sanitizer(&[raw, canon]),
        builtin_san: cfg.builtin_sanitizer(&[canon, raw]),
        full_result: is_in(canon, FULL_RESULT) || is_in(raw, FULL_RESULT) || cfg.orm.search(&dot_raw).is_some(),
        sql_builder: is_in(canon, SQL_BUILDER_FUNCS) || is_in(raw, SQL_BUILDER_FUNCS) || attr_is_builder,
        clean_result: in_words(last_part(raw), CLEAN_RESULT),
    }
}

impl<'p> Analyzer<'p> {
    // ---------- commit ----------

    /// Merges this reading into the function's summary (monotone: sinks and
    /// returned params only grow, clean sets only shrink): (summary changed,
    /// class attributes changed, globals changed).
    pub fn commit(&mut self) -> (bool, bool, bool) {
        let f = self.f;
        let (mut changed, mut cls_changed, mut glob_changed) = (false, false, false);
        let pnames = self.p.fns[f as usize].pnames.clone();
        let sink_adds = std::mem::take(&mut self.sink_adds);
        {
            let func = &mut self.p.fns[f as usize];
            for (p, cat, loc) in sink_adds {
                let pname = pnames[p as usize];
                let pos = match func.param_to_sink.iter().position(|(k, _)| *k == pname) {
                    Some(i) => i,
                    None => {
                        func.param_to_sink.push((pname, Vec::new()));
                        func.param_to_sink.len() - 1
                    }
                };
                let d = &mut func.param_to_sink[pos].1;
                if !d.iter().any(|(c, _)| *c == cat) {
                    d.push((cat, loc));
                    changed = true;
                }
            }
            for &(p, clean) in &self.ret_params {
                let pname = pnames[p as usize];
                match func.param_to_return.iter_mut().find(|(k, _)| *k == pname) {
                    Some(e) => {
                        let new = e.1 & clean;
                        if new != e.1 {
                            e.1 = new;
                            changed = true;
                        }
                    }
                    None => {
                        func.param_to_return.push((pname, clean));
                        changed = true;
                    }
                }
            }
            if let Some(rs) = &self.ret_source {
                match &func.ret_source {
                    None => {
                        func.ret_source = Some(rs.as_source());
                        changed = true;
                    }
                    Some(old) => {
                        // (the supply-chain model: the kinds it holds, and what it is, only grow)
                        let sc = crate::jsflow::sc_union(&old.sc, &rs.sc);
                        let marks = old.marks | rs.marks;
                        if old.clean & rs.clean != old.clean || sc != old.sc || marks != old.marks {
                            func.ret_source = Some(Taint { clean: old.clean & rs.clean, sc, marks, ..old.as_source() });
                            changed = true;
                        }
                    }
                }
            }
        }
        if let Some(c) = self.p.fns[f as usize].cls {
            let writes = std::mem::take(&mut self.attr_writes);
            let cls = &mut self.p.classes[c as usize];
            for (attr, t) in writes {
                let old = cls.attr_taint.get(&attr).cloned();
                let new = match &old {
                    None => t.as_source(),
                    Some(o) => Taint {
                        clean: o.clean & t.clean,
                        sc: crate::jsflow::sc_union(&o.sc, &t.sc),
                        marks: o.marks | t.marks,
                        ..o.as_source()
                    },
                };
                if old.as_ref().map(|o| o.clean != new.clean || o.sc != new.sc || o.marks != new.marks).unwrap_or(true) {
                    cls.attr_taint.insert(attr, new);
                    cls_changed = true;
                }
            }
        }
        if self.supply && (self.sc_commit() || self.sc_dirty) {
            glob_changed = true;
        }
        if self.p.fns[f as usize].pseudo {
            let m = self.m;
            let entries: Vec<(Key, Taint)> = self.env.iter().map(|(k, v)| (*k, v.clone())).collect();
            let globals = &mut self.p.mods[m as usize].globals;
            for (k, t) in entries {
                if k >> 32 != 0 || !(t.source || t.marks != 0) {
                    continue;
                }
                let name = k as NameId;
                let old = globals.get(&name).cloned();
                let new = match &old {
                    None => t.as_source(),
                    Some(o) => Taint {
                        clean: o.clean & t.clean,
                        sc: crate::jsflow::sc_union(&o.sc, &t.sc),
                        marks: o.marks | t.marks,
                        ..o.as_source()
                    },
                };
                let update = match &old {
                    None => true,
                    Some(o) => o.clean != new.clean || o.sc != new.sc || o.marks != new.marks,
                };
                if update {
                    globals.insert(name, new);
                    glob_changed = true;
                }
            }
        }
        (changed, cls_changed, glob_changed)
    }
}

/// flow._py_builtin_sink: the sink category of a callee's text.
pub fn builtin_sink(callee: &[u32]) -> Option<u8> {
    let last = last_part(callee);
    let eq = |s: &str| pystr::eq(callee, s);
    let leq = |s: &str| pystr::eq(last, s);
    if leq("execute") || leq("executemany") || leq("executescript") || leq("RawSQL") {
        return Some(SQL);
    }
    if leq("raw") || leq("extra") {
        let mut dotted = vec![0x2E];
        dotted.extend_from_slice(callee);
        if pystr::contains(&dotted, ".objects.") {
            return Some(SQL);
        }
    }
    if eq("os.system") || eq("os.popen") || eq("asyncio.create_subprocess_shell") {
        return Some(CMD);
    }
    if pystr::starts_with(callee, "subprocess.") && (leq("run") || leq("call") || leq("check_output") || leq("check_call") || leq("Popen")) {
        return Some(CMD);
    }
    if eq("eval") || eq("exec") || eq("builtins.eval") || eq("builtins.exec") {
        return Some(CODE);
    }
    if leq("render_template_string")
        || eq("jinja2.Template")
        || eq("mako.template.Template")
        || eq("django.template.Template")
        || (leq("from_string") && (pystr::contains(&pystr::lower(callee), "env") || pystr::starts_with(callee, "jinja2.")))
    {
        return Some(TEMPLATE);
    }
    if eq("open")
        || eq("builtins.open")
        || eq("codecs.open")
        || eq("io.open")
        || eq("os.open")
        || leq("send_file")
        || leq("send_from_directory")
        || leq("FileResponse")
        || (pystr::starts_with(callee, "shutil.")
            && (leq("copy") || leq("copy2") || leq("copyfile") || leq("copytree") || leq("move") || leq("rmtree")))
        || eq("os.remove")
        || eq("os.unlink")
        || eq("os.rmdir")
        || eq("os.removedirs")
        || eq("os.rename")
        || eq("os.replace")
        || eq("os.listdir")
        || eq("os.scandir")
    {
        return Some(PATH);
    }
    if leq("urlopen")
        || (pystr::starts_with(callee, "requests.")
            && (leq("get") || leq("post") || leq("put") || leq("delete") || leq("head") || leq("request")))
        || (pystr::starts_with(callee, "httpx.")
            && (leq("get") || leq("post") || leq("put") || leq("patch") || leq("delete") || leq("head") || leq("request") || leq("stream")))
    {
        return Some(SSRF);
    }
    if leq("redirect") || leq("HttpResponseRedirect") || leq("HttpResponsePermanentRedirect") || leq("RedirectResponse") {
        return Some(REDIRECT);
    }
    if leq("make_response")
        || leq("Response")
        || leq("HttpResponse")
        || leq("HTMLResponse")
        || leq("Markup")
        || leq("mark_safe")
        || leq("SafeString")
    {
        return Some(XSS);
    }
    None
}
