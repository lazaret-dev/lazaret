//! (Q-4) The intra-file taint pass follows a call into the helper it names: a function or method defined in the
//! file, or in another file of the project, that returns untrusted data of its own (it reads the request, the command
//! line…) gets a summary — the categories what it returns is clean for — and a call of it carries that data too
//! (`param = x.get_parameter('id')` with `x = Wrapper(request)` and `get_parameter` returning
//! `self.request.args.get(…)` is tainted).
//!
//! Following only adds. A followed call's text is read as before (what its arguments and receiver carry), and a
//! placeholder name tainted with what the helper returns is put among its arguments (one Yi syllable the text does
//! not hold, so the finding can say "untrusted data that 'x.m()' returns", and what neutralizes the call — `int(…)`,
//! a sanitizer around it — neutralizes it too); nothing a call's text carries is ever taken away, however the helper
//! is written or reached. A helper that returns no untrusted data of its own gets no summary: its
//! calls are read as text, as before.
//!
//! A summary is the pass's own reading of the helper's body (taint.rs `run`, its `walk`): what its `return`s carry,
//! and the categories all of them are clean for. A helper is read when it may return a source: its body names one,
//! an import whose summary reads one, or such a helper (`_HELPER_DEPTH` deep), and it is called in the file (a
//! module's: asked for by a file that imports it). A call is matched only to what it names: a module-level function
//! of the file or one it imports from a project module (`f()`, `mod.f()`, `pkg.mod.f()`), a method through `self` in
//! its class, through a name assigned an instance of the class in the same function (`x = C(…)`, `x = mod.C(…)`; the
//! last such assignment), on an instance made in place (`C(…).m()`) or on the class (`C.m()`). A helper the file
//! defines twice, a name more than `_HELPER_SAME_NAME` defs have, a property, a nested def, and an import two of the
//! project's files could be the module of add nothing.
//!
//! The work is bounded and linear in the file: a chain of helpers is followed `_HELPER_DEPTH` deep, recursion is read
//! as text at the call that recurses, the bodies read for summaries are at most `_HELPER_LINES_BASE` +
//! `_HELPER_LINES_PER_LINE` lines per line of the file (`_HELPER_PROJECT_LINES` for a project's modules,
//! `taint_helpers`, its imports followed `_HELPER_HOPS` modules deep), and at most `_HELPER_CALLS` calls of one
//! statement are followed (innermost first). A bound reached only leaves a call as its text.

use super::*;
use std::cell::Cell;
use std::collections::BTreeMap;

// ---------------------------------------------------------------- summaries

/// What a helper's return value carries of untrusted data of its own: the categories it is clean for.
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct Summary {
    pub source: Clean,
}

fn cats_of(v: &Value) -> Option<Clean> {
    let mut out: Clean = v.as_arr()?.iter().map(|s| s.as_str().map(|s| s.to_vec())).collect::<Option<_>>()?;
    out.sort();
    out.dedup();
    Some(out)
}

impl Summary {
    /// `[category, …]`: those the untrusted data it returns is clean for.
    pub fn to_value(&self) -> Value {
        Value::Arr(self.source.iter().map(|s| Value::Str(s.clone())).collect())
    }

    pub fn from_value(v: &Value) -> Option<Summary> {
        cats_of(v).map(|source| Summary { source })
    }
}

// ---------------------------------------------------------------- the file's definitions

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum Kind {
    Function,
    Method,
    Static,
    ClassMethod,
    /// a property, a nested def: not followed
    Other,
}

pub(crate) struct Def {
    pub name: PyStr,
    pub line: usize,
    /// the first line after its body
    pub end: usize,
    pub class: Option<usize>,
    pub kind: Kind,
    /// its first parameter (a method's instance, a classmethod's class)
    pub first: Option<PyStr>,
    /// the body on the def's own line, after its colon (`def f(x): return x`)
    pub inline: Option<PyStr>,
}

pub(crate) struct ClassDef {
    pub methods: Vec<(PyStr, usize)>,
    index: HashMap<PyStr, usize>,
}

/// A file's functions and classes, as the pass reads its lines (the structure lines, not those a statement or a
/// literal continues).
#[derive(Default)]
pub(crate) struct Defs {
    pub defs: Vec<Def>,
    pub classes: Vec<ClassDef>,
    /// module-level functions and classes by name (one defined twice: neither)
    pub functions: HashMap<PyStr, usize>,
    pub class_names: HashMap<PyStr, usize>,
    /// each line's innermost def
    owner: Vec<u32>,
    /// the names more than `_HELPER_SAME_NAME` defs of the file have: not followed (read as text)
    pub crowded: HashSet<PyStr>,
}

const NO_DEF: u32 = u32::MAX;

fn kind_of(decorators: &[PyStr]) -> Option<Kind> {
    let mut kind = Kind::Method;
    for d in decorators {
        let last = match d.iter().rposition(|&c| c == '.' as u32) {
            Some(k) => &d[k + 1..],
            None => d.as_slice(),
        };
        if pystr::eq(d, "staticmethod") {
            kind = Kind::Static;
        } else if pystr::eq(d, "classmethod") {
            kind = Kind::ClassMethod;
        } else if pystr::eq(d, "property") || pystr::eq(last, "setter") || pystr::eq(last, "getter")
            || pystr::eq(last, "deleter") || pystr::eq(d, "overload") || pystr::eq(d, "typing.overload")
        {
            return None;
        }
    }
    Some(kind)
}

/// A def's first parameter, and the body after its colon when it is on the def's own line (`def f(a, *b): …`).
fn def_head(p: &Pack, stmt: &[u32]) -> (Option<PyStr>, Option<PyStr>) {
    let Some(m) = p.re("_DEF_HEAD_RE").match_(stmt) else { return (None, None) };
    let close = call_close(stmt, m.end());
    if close >= stmt.len() {
        return (None, None);
    }
    let first = frameworks::top_split(&stmt[m.end()..close], ',' as u32).first()
        .and_then(|part| p.re("_PARAM_RE").match_(pystr::strip(part)).map(|pm| pm.group(1).unwrap_or(&[]).to_vec()))
        .filter(|n| !n.is_empty());
    // the colon after the parameters (and a return annotation), outside brackets and strings
    let rest = &stmt[close + 1..];
    let colon = frameworks::top_split(rest, ':' as u32);
    let inline = if colon.len() >= 2 {
        let body = pystr::strip(&rest[colon[0].len() + 1..]);
        (!body.is_empty()).then(|| body.to_vec())
    } else {
        None
    };
    (first, inline)
}

impl Defs {
    /// The definitions of a Python file.
    pub fn of(ctx: &FileCtx) -> Defs {
        let p = ctx.p;
        let mut out = Defs { owner: vec![NO_DEF; ctx.len()], ..Defs::default() };
        if !pystr::contains(&ctx.content, "def") {
            return out;
        }
        let inside = literal_continuations(ctx);
        let join_max = p.usize("TAINT_JOIN_MAX_LINES");
        let (def_re, class_re, deco_re) = (p.re("_HELPER_DEF_RE"), p.re("_HELPER_CLASS_RE"), p.re("_HELPER_DECORATOR_RE"));
        // the open blocks: (indent, Some(def) or None for a class, the class's index)
        let mut stack: Vec<(usize, Option<usize>, Option<usize>)> = Vec::new();
        let mut decorators: Vec<PyStr> = Vec::new();
        let (mut open_depth, mut continued) = (0i64, 0usize);
        let mut fn_count: HashMap<PyStr, usize> = HashMap::new();
        let mut cls_count: HashMap<PyStr, usize> = HashMap::new();
        let mut def_count: HashMap<PyStr, usize> = HashMap::new();
        for i in 0..ctx.len() {
            if ctx.cmask[i] || inside.contains(&i) {
                continue;
            }
            let line = ctx.mcode(i);
            if line.iter().all(|&c| pystr::is_space(c)) {
                continue;
            }
            let depth = delta(&ctx.names_code(i));
            if open_depth > 0 && continued < join_max {
                open_depth = (open_depth + depth).max(0);
                continued += 1;
                continue;
            }
            open_depth = depth.max(0);
            continued = 0;
            let indent = indent_of(ctx.line(i));
            while stack.last().is_some_and(|s| indent <= s.0) {
                let (_, d, _) = stack.pop().expect("there");
                if let Some(d) = d {
                    out.defs[d].end = i;
                }
            }
            if let Some(m) = deco_re.match_(line) {
                decorators.push(m.group(1).unwrap_or(&[]).to_vec());
                continue;
            }
            let decos = std::mem::take(&mut decorators);
            if let Some(m) = class_re.match_(line) {
                let name = m.group(1).unwrap_or(&[]).to_vec();
                let nested = !stack.is_empty();
                let c = out.classes.len();
                out.classes.push(ClassDef { methods: Vec::new(), index: HashMap::new() });
                if !nested {
                    *cls_count.entry(name.clone()).or_default() += 1;
                    out.class_names.insert(name, c);
                }
                stack.push((indent, None, Some(c)));
                continue;
            }
            let Some(m) = def_re.match_(line) else { continue };
            let name = m.group(1).unwrap_or(&[]).to_vec();
            let stmt = if depth > 0 { statement_at(ctx, i, line) } else { line.to_vec() };
            let (first, inline) = def_head(p, &stmt);
            let (class, kind) = match stack.last().map(|s| (s.1, s.2)) {
                None => (None, kind_of(&decos).map(|_| Kind::Function).unwrap_or(Kind::Other)),
                Some((None, Some(c))) => (Some(c), kind_of(&decos).unwrap_or(Kind::Other)),
                _ => (None, Kind::Other),
            };
            let d = out.defs.len();
            *def_count.entry(name.clone()).or_default() += 1;
            out.defs.push(Def { name: name.clone(), line: i, end: ctx.len(), class, kind, first, inline });
            match (class, kind) {
                (None, Kind::Function) => {
                    *fn_count.entry(name.clone()).or_default() += 1;
                    out.functions.insert(name, d);
                }
                (Some(c), k) => {
                    let cls = &mut out.classes[c];
                    match cls.index.get(&name) {
                        // defined twice (a setter, a conditional def): neither is followed
                        Some(&k0) => cls.methods[k0].1 = usize::MAX,
                        None => {
                            cls.index.insert(name.clone(), cls.methods.len());
                            cls.methods.push((name, if k != Kind::Other { d } else { usize::MAX }));
                        }
                    }
                }
                _ => {}
            }
            stack.push((indent, Some(d), None));
        }
        let k = p.usize("_HELPER_SAME_NAME");
        out.crowded = def_count.into_iter().filter(|(_, c)| *c > k).map(|(n, _)| n).collect();
        out.functions.retain(|n, _| fn_count.get(n) == Some(&1) && !cls_count.contains_key(n));
        out.class_names.retain(|n, _| cls_count.get(n) == Some(&1) && !fn_count.contains_key(n));
        for c in &mut out.classes {
            c.methods.retain(|(_, d)| *d != usize::MAX);
            c.index = c.methods.iter().enumerate().map(|(k, (n, _))| (n.clone(), k)).collect();
        }
        for (k, d) in out.defs.iter().enumerate() {
            for o in &mut out.owner[d.line..d.end.min(ctx.len())] {
                *o = k as u32;
            }
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.class_names.is_empty()
    }

    /// The innermost def line i is in.
    pub fn owner(&self, i: usize) -> Option<usize> {
        self.owner.get(i).filter(|&&o| o != NO_DEF).map(|&o| o as usize)
    }

    fn method(&self, c: usize, name: &[u32]) -> Option<usize> {
        self.classes[c].index.get(name).map(|&k| self.classes[c].methods[k].1)
    }
}

// ---------------------------------------------------------------- what a file imports from its project

/// A class of another module: the summaries of its methods that return untrusted data of their own.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ExtClass {
    pub methods: Vec<(PyStr, Summary)>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Entry {
    Fun(Summary),
    Class(ExtClass),
    /// a module imported whole: its functions and classes (`Fun`, `Class`)
    Module(Vec<(PyStr, Entry)>),
}

/// What a file imports from the rest of its project, by the names it uses (`taint_helpers`): `helpers.request`
/// for `import helpers.request`, `r` for `import helpers.request as r` or `from helpers import request as r`, `f`
/// for `from helpers.request import f`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Slice {
    names: Vec<(PyStr, Entry)>,
    by_name: HashMap<PyStr, usize>,
}

fn entry_value(e: &Entry) -> Value {
    match e {
        Entry::Fun(s) => Value::Arr(vec![Value::str("f"), s.to_value()]),
        Entry::Class(c) => Value::Arr(vec![
            Value::str("c"),
            Value::Arr(c.methods.iter().map(|(n, s)| Value::Arr(vec![Value::Str(n.clone()), s.to_value()])).collect()),
        ]),
        Entry::Module(m) => Value::Arr(vec![
            Value::str("m"),
            Value::Arr(m.iter().map(|(n, e)| Value::Arr(vec![Value::Str(n.clone()), entry_value(e)])).collect()),
        ]),
    }
}

fn entry_of(v: &Value, depth: usize) -> Option<Entry> {
    let f = v.as_arr()?;
    let tag = pystr::to_string(f.first()?.as_str()?);
    let body = f.get(1)?;
    match tag.as_str() {
        "f" => Some(Entry::Fun(Summary::from_value(body)?)),
        "c" => {
            let mut methods = Vec::new();
            for item in body.as_arr()? {
                let pair = item.as_arr()?;
                methods.push((pair.first()?.as_str()?.to_vec(), Summary::from_value(pair.get(1)?)?));
            }
            Some(Entry::Class(ExtClass { methods }))
        }
        "m" if depth == 0 => {
            let mut members = Vec::new();
            for item in body.as_arr()? {
                let pair = item.as_arr()?;
                let e = entry_of(pair.get(1)?, depth + 1)?;
                if matches!(e, Entry::Module(_)) {
                    return None;
                }
                members.push((pair.first()?.as_str()?.to_vec(), e));
            }
            Some(Entry::Module(members))
        }
        _ => None,
    }
}

impl Entry {
    /// Does what it names hold a helper (each entry's summary is one of untrusted data of its own)?
    pub(crate) fn reads_source(&self) -> bool {
        match self {
            Entry::Fun(_) => true,
            Entry::Class(c) => !c.methods.is_empty(),
            Entry::Module(m) => m.iter().any(|(_, e)| e.reads_source()),
        }
    }
}

impl Slice {
    fn push(&mut self, name: PyStr, e: Entry) {
        if self.by_name.contains_key(&name) {
            return;
        }
        self.by_name.insert(name.clone(), self.names.len());
        self.names.push((name, e));
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The names the file uses for what it imports.
    pub(crate) fn names(&self) -> impl Iterator<Item = &[u32]> {
        self.names.iter().map(|(n, _)| n.as_slice())
    }

    /// Does something the file imports return untrusted data of its own?
    pub(crate) fn reads_source(&self) -> bool {
        self.names.iter().any(|(_, e)| e.reads_source())
    }

    pub(crate) fn get(&self, name: &[u32]) -> Option<&Entry> {
        self.by_name.get(name).map(|&k| &self.names[k].1)
    }

    /// `[[name, entry], …]`; an entry is `["f", summary]`, `["c", [[method, summary], …]]` or `["m", [[name,
    /// entry], …]]` (a module's functions and classes); a summary is the categories the helper's untrusted data is
    /// clean for.
    pub fn to_value(&self) -> Value {
        Value::Arr(self.names.iter().map(|(n, e)| Value::Arr(vec![Value::Str(n.clone()), entry_value(e)])).collect())
    }

    /// The slice a call's `"helpers"` gives (none: an empty one); an error for one that is not of that form.
    pub fn from_args(args: &Value) -> Result<Slice, String> {
        let mut s = Slice::default();
        let v = match args.get("helpers") {
            None | Some(Value::Null) => return Ok(s),
            Some(v) => v,
        };
        for item in v.as_arr().ok_or("taint: helpers is not a list")? {
            let pair = item.as_arr().filter(|p| p.len() == 2).ok_or("taint: a helper is not [name, entry]")?;
            let name = pair[0].as_str().ok_or("taint: a helper's name")?.to_vec();
            let e = entry_of(&pair[1], 0).ok_or("taint: a helper's entry")?;
            s.push(name, e);
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------- calls in a text

fn is_ident(c: u32) -> bool {
    c == '_' as u32 || pystr::is_alnum(c)
}

/// `text` with the insides of its string literals blanked (quotes kept, offsets kept).
fn blank_strings(text: &[u32]) -> PyStr {
    let mut out = text.to_vec();
    let (mut i, n) = (0usize, text.len());
    while i < n {
        let q = text[i];
        if q != '"' as u32 && q != '\'' as u32 {
            i += 1;
            continue;
        }
        let triple = i + 2 < n && text[i + 1] == q && text[i + 2] == q;
        let mut j = if triple { i + 3 } else { i + 1 };
        let mut end = n;
        while j < n {
            if text[j] == '\\' as u32 {
                j += 2;
                continue;
            }
            if text[j] == q && (!triple || (j + 2 < n && text[j + 1] == q && text[j + 2] == q)) {
                end = j;
                break;
            }
            j += 1;
        }
        let inner = if triple { i + 3 } else { i + 1 };
        for c in &mut out[inner.min(n)..end.min(n)] {
            *c = ' ' as u32;
        }
        i = if end >= n { n } else if triple { end + 3 } else { end + 1 };
    }
    out
}

/// Each `(`'s matching `)` in `b` (string insides blanked): `close[k]` for the bracket at k (n: none).
fn closes(b: &[u32]) -> HashMap<usize, usize> {
    let mut out = HashMap::new();
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut quote: Option<u32> = None;
    for (k, &c) in b.iter().enumerate() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match char::from_u32(c) {
            Some('"' | '\'') => quote = Some(c),
            Some('(' | '[' | '{') => stack.push((k, c)),
            Some(')' | ']' | '}') => {
                if let Some((o, oc)) = stack.pop() {
                    if oc == '(' as u32 && c == ')' as u32 {
                        out.insert(o, k);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// A call the text holds: the callee's dotted names, the receiver call when it is `C(…).m(` (the receiver's
/// names), the call's span (`start`..`close` + 1) and its opening parenthesis.
struct Cand {
    segs: Vec<(usize, usize)>,
    recv: Option<Vec<(usize, usize)>>,
    start: usize,
    open: usize,
    close: usize,
}

const MAX_SEGS: usize = 16;

/// The dotted name ending at `end` (exclusive) in `b`: its segments, first to last, and where it starts; None when
/// what precedes it is not nameable (an attribute of a subscript, a call's result).
fn chain_before(b: &[u32], end: usize) -> Option<(Vec<(usize, usize)>, usize, Option<usize>)> {
    let back = |mut k: usize| {
        while k > 0 && (b[k - 1] == ' ' as u32 || b[k - 1] == '\t' as u32) {
            k -= 1;
        }
        k
    };
    let mut segs = Vec::new();
    let mut k = back(end);
    loop {
        let e = k;
        while k > 0 && is_ident(b[k - 1]) {
            k -= 1;
        }
        if k == e || (b[k] >= '0' as u32 && b[k] <= '9' as u32) {
            return None;
        }
        segs.push((k, e));
        if segs.len() > MAX_SEGS {
            return None;
        }
        let d = back(k);
        if d > 0 && b[d - 1] == '.' as u32 {
            let before = back(d - 1);
            if before > 0 && is_ident(b[before - 1]) {
                k = before;
                continue;
            }
            if before > 0 && b[before - 1] == ')' as u32 {
                segs.reverse();
                return Some((segs, k, Some(before - 1)));
            }
            return None;
        }
        segs.reverse();
        return Some((segs, k, None));
    }
}

/// The name just before position `o` (spaces between), when there is one.
fn name_before(b: &[u32], o: usize) -> &[u32] {
    let mut k = o;
    while k > 0 && (b[k - 1] == ' ' as u32 || b[k - 1] == '\t' as u32) {
        k -= 1;
    }
    let e = k;
    while k > 0 && is_ident(b[k - 1]) {
        k -= 1;
    }
    &b[k..e]
}

/// The calls of `b` (string insides blanked) whose callee's last name `wanted` takes.
fn candidates(p: &Pack, b: &[u32], wanted: &impl Fn(&[u32]) -> bool) -> Vec<Cand> {
    let at: Vec<usize> = (0..b.len()).filter(|&o| b[o] == '(' as u32 && wanted(name_before(b, o))).collect();
    if at.is_empty() {
        return Vec::new();
    }
    let close_of = closes(b);
    let opens: HashMap<usize, usize> = close_of.iter().map(|(&o, &c)| (c, o)).collect();
    let mut out = Vec::new();
    for o in at {
        let Some(&close) = close_of.get(&o) else { continue };
        let Some((segs, start, recv_close)) = chain_before(b, o) else { continue };
        if segs.iter().any(|&(a, e)| is_keyword(p, &b[a..e])) {
            continue;
        }
        let mut cand = Cand { segs, recv: None, start, open: o, close };
        if let Some(rc) = recv_close {
            if cand.segs.len() != 1 {
                continue;
            }
            let Some(&ro) = opens.get(&rc) else { continue };
            let Some((rsegs, rstart, None)) = chain_before(b, ro) else { continue };
            if rsegs.iter().any(|&(a, e)| is_keyword(p, &b[a..e])) {
                continue;
            }
            cand.recv = Some(rsegs);
            cand.start = rstart;
        }
        out.push(cand);
    }
    out
}

/// A class a name or a callee names: the file's own, or one of another module.
#[derive(Clone, Copy)]
pub(crate) enum ClassRef<'s> {
    Local(usize),
    Ext(&'s ExtClass),
}

/// A function or method a call names: the file's own (its summary is the pass's), or another module's.
#[derive(Clone, Copy)]
enum Fun<'s> {
    Local(usize),
    Ext(&'s Summary),
}

enum Named<'s> {
    Call(Fun<'s>),
    Class(ClassRef<'s>),
}

/// Where a text is read: its line, the function it is in (the pass's scope id), the names holding an instance of
/// a class there (and the function it was made in).
pub(crate) struct At<'a, 's> {
    pub line: usize,
    pub scope: Option<usize>,
    pub instances: &'a HashMap<PyStr, (ClassRef<'s>, Option<usize>)>,
}

/// A call of a helper that returns untrusted data of its own, in a text: the call's span, its opening parenthesis
/// (the placeholder goes after it, among what the call is given), its helper's summary, and the callee as written.
pub(crate) struct Followed<'s> {
    pub start: usize,
    pub open: usize,
    pub close: usize,
    pub summary: &'s Summary,
    pub callee: PyStr,
}

/// The names a file's calls resolve through: its definitions and what it imports from its project, and the last
/// names a call it follows can end with (its functions, classes and methods, what it imports and their members).
pub(crate) struct Resolver<'s> {
    pub defs: &'s Defs,
    pub imported: &'s Slice,
    names: HashSet<PyStr>,
    classes: bool,
    source: bool,
}

fn method_of<'s>(defs: &'s Defs, c: ClassRef<'s>, name: &[u32]) -> Option<Fun<'s>> {
    match c {
        ClassRef::Local(c) => defs.method(c, name).map(Fun::Local),
        ClassRef::Ext(e) => e.methods.iter().find(|(n, _)| n.as_slice() == name).map(|(_, s)| Fun::Ext(s)),
    }
}

fn entry_named<'s>(e: &'s Entry) -> Option<Named<'s>> {
    match e {
        Entry::Fun(s) => Some(Named::Call(Fun::Ext(s))),
        Entry::Class(c) => Some(Named::Class(ClassRef::Ext(c))),
        Entry::Module(_) => None,
    }
}

impl<'s> Resolver<'s> {
    pub fn new(defs: &'s Defs, imported: &'s Slice) -> Resolver<'s> {
        let mut names: HashSet<PyStr> = HashSet::new();
        names.extend(defs.functions.keys().cloned());
        names.extend(defs.class_names.keys().cloned());
        for c in &defs.classes {
            names.extend(c.methods.iter().map(|(n, _)| n.clone()));
        }
        fn add(names: &mut HashSet<PyStr>, e: &Entry) {
            match e {
                Entry::Fun(_) => {}
                Entry::Class(c) => names.extend(c.methods.iter().map(|(n, _)| n.clone())),
                Entry::Module(m) => {
                    for (n, e) in m {
                        names.insert(n.clone());
                        add(names, e);
                    }
                }
            }
        }
        for (n, e) in &imported.names {
            names.insert(n[n.iter().rposition(|&c| c == '.' as u32).map_or(0, |k| k + 1)..].to_vec());
            add(&mut names, e);
        }
        // (a name too many of the file's defs have is read as text: linking its calls would cost each def)
        names.retain(|n| !defs.crowded.contains(n));
        fn has_class(e: &Entry) -> bool {
            match e {
                Entry::Fun(_) => false,
                Entry::Class(_) => true,
                Entry::Module(m) => m.iter().any(|(_, e)| has_class(e)),
            }
        }
        let classes = defs.classes.iter().any(|c| !c.methods.is_empty()) || imported.names.iter().any(|(_, e)| has_class(e));
        let source = !imported.is_empty();
        Resolver { defs, imported, names, classes, source }
    }

    /// Does the file import a helper that returns untrusted data of its own?
    pub fn imported_source(&self) -> bool {
        self.source
    }

    fn wanted(&self) -> impl Fn(&[u32]) -> bool + '_ {
        |n: &[u32]| !n.is_empty() && self.names.contains(n)
    }

    pub fn is_empty(&self) -> bool {
        self.defs.is_empty() && self.imported.is_empty()
    }

    /// What the dotted name `segs` (in `b`) names at `at`.
    fn named(&self, b: &[u32], segs: &[(usize, usize)], at: &At<'_, 's>) -> Option<Named<'s>> {
        let seg = |k: usize| &b[segs[k].0..segs[k].1];
        let n = segs.len();
        if n == 1 {
            let name = seg(0);
            if let Some(&d) = self.defs.functions.get(name) {
                return Some(Named::Call(Fun::Local(d)));
            }
            if let Some(&c) = self.defs.class_names.get(name) {
                return Some(Named::Class(ClassRef::Local(c)));
            }
            return self.imported.get(name).and_then(entry_named);
        }
        let last = seg(n - 1);
        if n == 2 {
            let head = seg(0);
            // a name holding an instance, in the function it was made in
            if let Some((c, scope)) = at.instances.get(head) {
                if *scope == at.scope {
                    return method_of(self.defs, *c, last).map(Named::Call);
                }
                return None;
            }
            // self (or cls) in a method of the file's own class
            if let Some(d) = self.defs.owner(at.line) {
                let def = &self.defs.defs[d];
                if let (Some(c), Some(first)) = (def.class, &def.first) {
                    if matches!(def.kind, Kind::Method | Kind::ClassMethod) && first.as_slice() == head {
                        return method_of(self.defs, ClassRef::Local(c), last).map(Named::Call);
                    }
                }
            }
        }
        // a module imported whole: pkg.mod.f(), mod.C(), mod.C.m()
        for k in (1..n).rev() {
            let prefix: Vec<&[u32]> = (0..k).map(seg).collect();
            let Some(Entry::Module(members)) = self.imported.get(&pystr::join(&['.' as u32], &prefix)) else { continue };
            let member = |name: &[u32]| members.iter().find(|(m, _)| m.as_slice() == name).map(|(_, e)| e);
            return match n - k {
                1 => member(last).and_then(entry_named),
                2 => match member(seg(k)) {
                    Some(Entry::Class(c)) => method_of(self.defs, ClassRef::Ext(c), last).map(Named::Call),
                    _ => None,
                },
                _ => None,
            };
        }
        if n == 2 {
            let head = seg(0);
            let class = match self.defs.class_names.get(head) {
                Some(&c) => Some(ClassRef::Local(c)),
                None => match self.imported.get(head) {
                    Some(Entry::Class(c)) => Some(ClassRef::Ext(c)),
                    _ => None,
                },
            };
            return class.and_then(|c| method_of(self.defs, c, last)).map(Named::Call);
        }
        None
    }

    /// The class `text` (a whole assignment's value) makes an instance of, when it is one call of a class.
    pub fn instance_of(&self, p: &Pack, text: &[u32], at: &At<'_, 's>) -> Option<ClassRef<'s>> {
        let t = pystr::strip(text);
        if !self.classes || t.last() != Some(&(')' as u32)) {
            return None;
        }
        let b = blank_strings(t);
        let c = candidates(p, &b, &self.wanted()).into_iter().find(|c| c.start == 0 && c.close + 1 == b.len() && c.recv.is_none())?;
        match self.named(&b, &c.segs, at)? {
            Named::Class(c) => Some(c),
            Named::Call(..) => None,
        }
    }

    /// The calls of `text` the pass follows: those of a helper whose summary is known (`sums` for the file's own),
    /// innermost first.
    pub fn calls(&self, p: &Pack, text: &[u32], at: &At<'_, 's>, sums: &'s HashMap<usize, Summary>) -> Vec<Followed<'s>> {
        if self.is_empty() || !text.contains(&('(' as u32)) {
            return Vec::new();
        }
        let wanted = self.wanted();
        if !(0..text.len()).any(|o| text[o] == '(' as u32 && wanted(name_before(text, o))) {
            return Vec::new();
        }
        let b = blank_strings(text);
        let mut out = Vec::new();
        for c in candidates(p, &b, &wanted) {
            let fun = if let Some(rsegs) = &c.recv {
                let Some(Named::Class(cls)) = self.named(&b, rsegs, at) else { continue };
                let (a, e) = c.segs[0];
                let Some(f) = method_of(self.defs, cls, &b[a..e]) else { continue };
                f
            } else {
                match self.named(&b, &c.segs, at) {
                    Some(Named::Call(f)) => f,
                    _ => continue,
                }
            };
            let summary = match fun {
                Fun::Local(d) => sums.get(&d),
                Fun::Ext(s) => Some(s),
            };
            let Some(summary) = summary else { continue };
            let names: Vec<&[u32]> = c.segs.iter().map(|&(a, e)| &b[a..e]).collect();
            out.push(Followed { start: c.start, open: c.open, close: c.close, summary, callee: pystr::join(&['.' as u32], &names) });
        }
        out.sort_by_key(|f| (f.close, std::cmp::Reverse(f.start)));
        // (innermost first, at most _HELPER_CALLS of them: the calls around the last are read as text)
        out.truncate(p.usize("_HELPER_CALLS"));
        out
    }
}

/// The names followed calls' values are held under while the text they are in is read: one letter each, a Yi
/// syllable (U+A000 on), none the text holds and no tainted name.
pub(crate) struct Placeholders {
    next: u32,
    in_text: bool,
}

const PLACEHOLDER_END: u32 = 0xA48D;

impl Placeholders {
    pub fn new(text: &[u32]) -> Placeholders {
        Placeholders { next: 0xA000, in_text: text.iter().any(|&c| (0xA000..PLACEHOLDER_END).contains(&c)) }
    }

    /// The next name free in `text` that `taken` does not take (None: none left).
    pub fn take(&mut self, text: &[u32], taken: impl Fn(&[u32]) -> bool) -> Option<PyStr> {
        while self.next < PLACEHOLDER_END {
            let c = self.next;
            self.next += 1;
            if !(self.in_text && text.contains(&c)) && !taken(&[c]) {
                return Some(vec![c]);
            }
        }
        None
    }
}

/// Does `text` hold, as a name not after a `.`, one of `set`'s?
pub(crate) fn names_any(text: &[u32], set: &HashSet<PyStr>) -> bool {
    if set.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < text.len() {
        if is_ident(text[i]) {
            let k = text[i..].iter().take_while(|&&c| is_ident(c)).count();
            if (i == 0 || text[i - 1] != '.' as u32) && set.contains(&text[i..i + k]) {
                return true;
            }
            i += k;
            continue;
        }
        i += 1;
    }
    false
}

/// The names called in a line (`name(`), for the order the summaries are read in.
pub(crate) fn called_names(b: &[u32]) -> Vec<PyStr> {
    let mut out = Vec::new();
    let mut seen: HashSet<&[u32]> = HashSet::new();
    for (o, &c) in b.iter().enumerate() {
        if c != '(' as u32 {
            continue;
        }
        let mut k = o;
        while k > 0 && (b[k - 1] == ' ' as u32 || b[k - 1] == '\t' as u32) {
            k -= 1;
        }
        let e = k;
        while k > 0 && is_ident(b[k - 1]) {
            k -= 1;
        }
        if k < e && seen.insert(&b[k..e]) {
            out.push(b[k..e].to_vec());
        }
    }
    out
}

/// Each line's called names (`called_names`), but for the call a line is made of (an expression statement, whose
/// value nothing reads: `log(x)`, `self.save(x)`) when the call ends the line, and a def's own name on its line.
pub(crate) fn line_names(ctx: &FileCtx, defs: &Defs) -> Vec<Vec<PyStr>> {
    let known: HashSet<&[u32]> = defs.defs.iter().map(|d| d.name.as_slice()).collect();
    let def_re = ctx.p.re("_HELPER_DEF_RE");
    (0..ctx.len()).map(|i| {
        if ctx.cmask[i] || !ctx.line(i).contains(&('(' as u32)) {
            return Vec::new();
        }
        let b = blank_strings(ctx.mcode(i));
        let mut names = called_names(&b);
        if let Some(m) = def_re.match_(&b) {
            let own = m.group(1).unwrap_or(&[]);
            if let Some(k) = names.iter().position(|n| n.as_slice() == own) {
                names.remove(k);
            }
        }
        names.retain(|n| known.contains(n.as_slice()));
        if names.is_empty() {
            return names;
        }
        let t = pystr::strip(&b);
        let head = t.iter().take_while(|&&c| is_ident(c) || c == '.' as u32 || c == ' ' as u32).count();
        if head > 0 && t.get(head) == Some(&('(' as u32)) && t.last() == Some(&(')' as u32)) {
            let open = b.len() - pystr::lstrip(&b).len() + head;
            if closes(&b).get(&open) == Some(&(b.len() - (b.len() - pystr::rstrip(&b).len()) - 1)) {
                let callee = pystr::rstrip(&t[..head]);
                let last = &callee[callee.iter().rposition(|&c| c == '.' as u32).map_or(0, |k| k + 1)..];
                let first_call = names.first().map(|n| n.as_slice()) == Some(last);
                let again = names.iter().skip(1).any(|n| n.as_slice() == last);
                if first_call && !again && !is_keyword_name(last) {
                    names.remove(0);
                }
            }
        }
        names
    }).collect()
}

fn is_keyword_name(n: &[u32]) -> bool {
    ["return", "yield", "await", "assert", "del", "print", "raise", "not", "lambda", "if", "elif", "while", "with", "for", "in"]
        .iter().any(|k| pystr::eq(n, k))
}

/// What the pass is asked for a module's definitions (`taint_helpers`): the module-level functions and classes
/// another file names.
pub(crate) type Wanted = std::collections::BTreeSet<PyStr>;

/// The summaries a module gives the files that import it: its functions' and its classes' methods'.
#[derive(Default)]
pub(crate) struct Exports {
    pub functions: Vec<(PyStr, Summary)>,
    pub classes: Vec<(PyStr, ExtClass)>,
    by_name: HashMap<PyStr, (bool, usize)>,
}

impl Exports {
    /// Index the exports by name (once they are all in).
    pub fn index(&mut self) {
        self.by_name = self.functions.iter().enumerate().map(|(k, (n, _))| (n.clone(), (true, k)))
            .chain(self.classes.iter().enumerate().map(|(k, (n, _))| (n.clone(), (false, k))))
            .rev().collect();
    }

    /// What it exports under `name` (a function before a class of the name).
    fn entry(&self, name: &[u32]) -> Option<Entry> {
        let &(is_fn, k) = self.by_name.get(name)?;
        Some(if is_fn { Entry::Fun(self.functions[k].1.clone()) } else { Entry::Class(self.classes[k].1.clone()) })
    }
}

/// The work left for the summaries: lines of helpers' bodies that may still be read.
pub(crate) struct Lines {
    pub left: Cell<usize>,
}

impl Lines {
    pub fn take(&self, n: usize) -> bool {
        let left = self.left.get();
        if left < n {
            self.left.set(0);
            return false;
        }
        self.left.set(left - n);
        true
    }
}

// ---------------------------------------------------------------- a project's modules (`taint_helpers`)

fn basename(s: &[u32]) -> &[u32] {
    match s.iter().rposition(|&c| c == '/' as u32) {
        Some(k) => &s[k + 1..],
        None => s,
    }
}

fn dirname(s: &[u32]) -> PyStr {
    match s.iter().rposition(|&c| c == '/' as u32) {
        Some(k) => s[..k].to_vec(),
        None => Vec::new(),
    }
}

/// A module's key (its path without `.py`, a package's without `/__init__`) and directory, as the cross-file pass
/// keys them (pyflow's add_module).
fn module_key(path: &[u32]) -> (PyStr, PyStr) {
    let mut norm: PyStr = path.iter().map(|&c| if c == '\\' as u32 { '/' as u32 } else { c }).collect();
    while pystr::starts_with(&norm, "./") {
        norm.drain(..2);
    }
    let mut stem = if pystr::ends_with(&norm, ".py") {
        norm[..norm.len() - 3].to_vec()
    } else if pystr::ends_with(&norm, ".pyw") {
        norm[..norm.len() - 4].to_vec()
    } else {
        norm.clone()
    };
    if pystr::eq(basename(&stem), "__init__") {
        stem = dirname(&stem);
    }
    (stem, dirname(&norm))
}

/// The project's modules by key and by their keys' dotted tails.
struct Modules {
    keys: Vec<(PyStr, PyStr)>,
    by_key: HashMap<PyStr, usize>,
    by_dotted: HashMap<PyStr, Vec<usize>>,
}

impl Modules {
    fn new(paths: &[PyStr]) -> Modules {
        let mut m = Modules { keys: Vec::new(), by_key: HashMap::new(), by_dotted: HashMap::new() };
        for (k, path) in paths.iter().enumerate() {
            let (stem, dir) = module_key(path);
            m.by_key.entry(stem.clone()).or_insert(k);
            let parts: Vec<&[u32]> = pystr::split_char(&stem, '/' as u32).into_iter().filter(|p| !p.is_empty() && !pystr::eq(p, ".")).collect();
            for n in 1..=parts.len().min(8) {
                let key = pystr::join(&['.' as u32], &parts[parts.len() - n..]);
                m.by_dotted.entry(key).or_default().push(k);
            }
            m.keys.push((stem, dir));
        }
        m
    }

    /// The module `dotted` names from module `from` (`level`: the dots of a relative import), when one does: an
    /// absolute import two of the project's files' paths end with names none (what it imports adds nothing).
    fn resolve(&self, dotted: &[u32], from: usize, level: usize) -> Option<usize> {
        if level > 0 {
            let mut base = self.keys[from].1.clone();
            for _ in 0..level - 1 {
                base = dirname(&base);
            }
            let mut key = base;
            for part in pystr::split_char(dotted, '.' as u32).into_iter().filter(|p| !p.is_empty()) {
                if !key.is_empty() {
                    key.push('/' as u32);
                }
                key.extend_from_slice(part);
            }
            return self.by_key.get(&key).copied().filter(|&m| m != from);
        }
        match self.by_dotted.get(dotted)?.as_slice() {
            [m] => Some(*m).filter(|&m| m != from),
            _ => None,
        }
    }

}

/// What an import binds: a module whole, or a member of one (a function or a class).
#[derive(Clone)]
enum Bound {
    Module(usize),
    Member(usize, PyStr),
}

/// The imports of a file's text: (the name it binds, what it binds).
fn imports(p: &Pack, text: &[u32], me: usize, mods: &Modules) -> Vec<(PyStr, Bound)> {
    let lines: Vec<&[u32]> = pystr::split_char(text, '\n' as u32);
    let (imp, frm) = (p.re("_HELPER_IMPORT_RE"), p.re("_HELPER_FROM_RE"));
    let mut out: Vec<(PyStr, Bound)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        i += 1;
        let body = pystr::lstrip(line);
        if !(pystr::starts_with(body, "import") || pystr::starts_with(body, "from")) {
            continue;
        }
        let cut = |t: &[u32]| -> PyStr {
            let t = match t.iter().position(|&c| c == '#' as u32) {
                Some(k) => &t[..k],
                None => t,
            };
            t.iter().map(|&c| if c == '\r' as u32 { ' ' as u32 } else { c }).collect()
        };
        let mut stmt = cut(line);
        // a parenthesized or continued list of names
        let mut more = 0;
        while (delta(&stmt) > 0 || pystr::ends_with(pystr::rstrip(&stmt), "\\")) && i < lines.len() && more < 64 {
            if pystr::ends_with(pystr::rstrip(&stmt), "\\") {
                let n = pystr::rstrip(&stmt).len() - 1;
                stmt.truncate(n);
            }
            stmt.push(' ' as u32);
            stmt.extend(cut(lines[i]));
            i += 1;
            more += 1;
        }
        let names_of = |list: &[u32]| -> Vec<(PyStr, PyStr)> {
            let list: PyStr = list.iter().map(|&c| if c == '(' as u32 || c == ')' as u32 { ' ' as u32 } else { c }).collect();
            let mut out = Vec::new();
            for part in pystr::split_char(&list, ',' as u32) {
                let words: Vec<&[u32]> = pystr::split_ws(part);
                match words.as_slice() {
                    [name] => out.push((name.to_vec(), name.to_vec())),
                    [name, kw, alias] if pystr::eq(kw, "as") => out.push((name.to_vec(), alias.to_vec())),
                    _ => {}
                }
            }
            out
        };
        if let Some(m) = frm.match_(&stmt) {
            let level = m.group(1).map_or(0, |d| d.len());
            let base = m.group(2).unwrap_or(&[]).to_vec();
            for (name, alias) in names_of(m.group(3).unwrap_or(&[])) {
                if pystr::eq(&name, "*") || !pystr::is_identifier(&name) || !pystr::is_identifier(&alias) {
                    continue;
                }
                let mut sub = base.clone();
                if !sub.is_empty() {
                    sub.push('.' as u32);
                }
                sub.extend_from_slice(&name);
                if let Some(m) = mods.resolve(&sub, me, level) {
                    out.push((alias, Bound::Module(m)));
                } else if !base.is_empty() || level > 0 {
                    if let Some(m) = mods.resolve(&base, me, level) {
                        out.push((alias, Bound::Member(m, name)));
                    }
                }
            }
        } else if let Some(m) = imp.match_(&stmt) {
            for (name, alias) in names_of(m.group(1).unwrap_or(&[])) {
                let dotted_ok = pystr::split_char(&name, '.' as u32).iter().all(|s| pystr::is_identifier(s));
                if !dotted_ok || !pystr::split_char(&alias, '.' as u32).iter().all(|s| pystr::is_identifier(s)) {
                    continue;
                }
                if let Some(m) = mods.resolve(&name, me, 0) {
                    out.push((alias, Bound::Module(m)));
                }
            }
        }
    }
    out
}

/// The members a file names through a module it imports whole as `alias` (`alias.f(`, `alias.C`).
fn members_named(text: &[u32], alias: &[u32]) -> Vec<PyStr> {
    let mut out: Vec<PyStr> = Vec::new();
    let mut seen: HashSet<&[u32]> = HashSet::new();
    let mut at = 0;
    while let Some(k) = pystr::find(text, alias, at) {
        at = k + 1;
        if k > 0 && (is_ident(text[k - 1]) || text[k - 1] == '.' as u32) {
            continue;
        }
        let mut j = k + alias.len();
        while j < text.len() && pystr::is_space(text[j]) && text[j] != '\n' as u32 {
            j += 1;
        }
        if text.get(j) != Some(&('.' as u32)) {
            continue;
        }
        j += 1;
        while j < text.len() && (text[j] == ' ' as u32 || text[j] == '\t' as u32) {
            j += 1;
        }
        let s = j;
        while j < text.len() && is_ident(text[j]) {
            j += 1;
        }
        if s < j && seen.insert(&text[s..j]) {
            out.push(text[s..j].to_vec());
        }
    }
    out
}

/// Which of `names` a text calls or reads an attribute of (`f(`, `C.m`): the imports a helper's summary can matter
/// for.
fn used_heads(text: &[u32], names: &HashSet<&[u32]>) -> HashSet<PyStr> {
    let mut out = HashSet::new();
    if names.is_empty() {
        return out;
    }
    let mut i = 0;
    while i < text.len() {
        if is_ident(text[i]) {
            let k = text[i..].iter().take_while(|&&c| is_ident(c)).count();
            let mut j = i + k;
            while j < text.len() && (text[j] == ' ' as u32 || text[j] == '\t' as u32) {
                j += 1;
            }
            if text.get(j).is_some_and(|&c| c == '(' as u32 || c == '.' as u32) && (i == 0 || text[i - 1] != '.' as u32)
                && names.contains(&text[i..i + k]) {
                out.insert(text[i..i + k].to_vec());
            }
            i += k;
            continue;
        }
        i += 1;
    }
    out
}

/// (Q-4) For each of a project's Python files, the slice of what it imports from the others that the taint pass
/// follows calls into (None: nothing): `files` [(path, text)], the configured part of the model with them.
pub fn project_slices(p: &Pack, files: &[(PyStr, Option<PyStr>)], model: &Model) -> Vec<Option<Slice>> {
    let paths: Vec<PyStr> = files.iter().map(|(path, _)| path.clone()).collect();
    let mods = Modules::new(&paths);
    // the modules whose helpers may return untrusted data of their own: a source in their text (the pack's, the
    // configuration's), or an import of such a module (a helper of another module adds nothing else)
    let src = p.map_re("TAINT_SOURCES", "py");
    let max = p.usize("_TAINT_MAX_MATCH_TEXT");
    let mut may_taint: Vec<bool> = files.iter().map(|(_, t)| t.as_ref().is_some_and(|t| {
        src.search(t).is_some()
            || (!model.sources.is_empty()
                && pystr::split_char(t, '\n' as u32).iter().any(|l| model.sources.iter().any(|r| r.search(&l[..l.len().min(max)]).is_some())))
    })).collect();
    let bound: Vec<Vec<(PyStr, Bound)>> = files.iter().enumerate()
        .map(|(k, (_, t))| t.as_ref().map(|t| imports(p, t, k, &mods)).unwrap_or_default()).collect();
    // (and a module importing one, whose helpers may pass a source on: as many hops as the summaries follow)
    for _ in 0..p.usize("_HELPER_HOPS") {
        let mut changed = false;
        for k in 0..files.len() {
            if !may_taint[k] && bound[k].iter().any(|(_, b)| matches!(b, Bound::Module(m) | Bound::Member(m, _) if may_taint[*m])) {
                may_taint[k] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    // what each module is asked for, by the files that import it: the members they call or read an attribute of
    // (a name imported and not used so needs no summary), and what a module asked for a name it imports passes on
    let mut wanted: BTreeMap<usize, Wanted> = BTreeMap::new();
    let mut named: Vec<Vec<Import>> = Vec::new();
    for (k, b) in bound.iter().enumerate() {
        let text = files[k].1.as_deref().unwrap_or(&[]);
        let aliases: HashSet<&[u32]> = b.iter().filter(|(_, w)| matches!(w, Bound::Member(..))).map(|(a, _)| a.as_slice()).collect();
        let used = used_heads(text, &aliases);
        let mut mine = Vec::new();
        for (alias, what) in b {
            let (Bound::Module(m) | Bound::Member(m, _)) = what;
            if !may_taint[*m] {
                continue;
            }
            match what {
                Bound::Module(m) => {
                    let members = members_named(text, alias);
                    wanted.entry(*m).or_default().extend(members.iter().cloned());
                    mine.push((alias.clone(), what.clone(), members));
                }
                Bound::Member(m, name) => {
                    if used.contains(alias) {
                        wanted.entry(*m).or_default().insert(name.clone());
                    }
                    mine.push((alias.clone(), what.clone(), Vec::new()));
                }
            }
        }
        named.push(mine);
    }
    for _ in 0..p.usize("_HELPER_HOPS") {
        let mut more: Vec<(usize, PyStr)> = Vec::new();
        for (m, w) in &wanted {
            for (alias, what, _) in &named[*m] {
                if let Bound::Member(t, name) = what {
                    if w.contains(alias) && !wanted.get(t).is_some_and(|x| x.contains(name)) {
                        more.push((*t, name.clone()));
                    }
                }
            }
        }
        if more.is_empty() {
            break;
        }
        for (t, name) in more {
            wanted.entry(t).or_default().insert(name);
        }
    }
    let lines = Lines { left: Cell::new(p.usize("_HELPER_PROJECT_LINES")) };
    let hops = p.usize("_HELPER_HOPS");
    let mut exports: HashMap<usize, Exports> = HashMap::new();
    // the modules asked for, those they import first (a module on the way is read as text where it is named)
    let deps_of = |m: usize| -> Vec<usize> {
        let mut deps: Vec<usize> = Vec::new();
        for (_, b) in &bound[m] {
            let (Bound::Module(d) | Bound::Member(d, _)) = b;
            if wanted.contains_key(d) && !deps.contains(d) {
                deps.push(*d);
            }
        }
        deps
    };
    let mut seen: HashSet<usize> = HashSet::new();
    for &root in wanted.keys() {
        if !seen.insert(root) {
            continue;
        }
        let mut stack: Vec<(usize, Vec<usize>, usize)> = vec![(root, deps_of(root), 0)];
        while let Some((m, deps, next)) = stack.last_mut() {
            let m = *m;
            if *next < deps.len() {
                let d = deps[*next];
                *next += 1;
                if stack.len() <= hops && seen.insert(d) {
                    stack.push((d, deps_of(d), 0));
                }
                continue;
            }
            stack.pop();
            if let Some(text) = &files[m].1 {
                let slice = slice_of(&named[m], &exports, p.usize("_HELPER_NAMES_MAX"));
                let ctx = FileCtx::new(p, text, Lang::Py, false);
                let mut ex = super::exports(&ctx, model, &slice, &wanted[&m], &lines);
                ex.index();
                exports.insert(m, ex);
            }
        }
    }
    let max = p.usize("_HELPER_NAMES_MAX");
    named.iter().map(|n| {
        let s = slice_of(n, &exports, max);
        (!s.is_empty()).then_some(s)
    }).collect()
}

/// An import a file's slice is made from: the name it binds, what it binds, the members the file names through it
/// (a module imported whole).
type Import = (PyStr, Bound, Vec<PyStr>);

/// A file's slice from the modules' exports: what each of its imports names.
fn slice_of(named: &[Import], exports: &HashMap<usize, Exports>, max: usize) -> Slice {
    let mut s = Slice::default();
    let mut count = 0usize;
    for (alias, what, members) in named {
        if count >= max {
            break;
        }
        let e = match what {
            Bound::Module(m) => {
                let Some(ex) = exports.get(m) else { continue };
                let list: Vec<(PyStr, Entry)> = members.iter().filter_map(|n| ex.entry(n).map(|e| (n.clone(), e))).take(max - count).collect();
                if list.is_empty() {
                    continue;
                }
                count += list.len();
                Entry::Module(list)
            }
            Bound::Member(m, name) => {
                let Some(e) = exports.get(m).and_then(|ex| ex.entry(name)) else { continue };
                count += 1;
                e
            }
        };
        s.push(alias.clone(), e);
    }
    s
}
