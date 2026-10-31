//! Narrow proofs for SC-EVAL-DECODE exemptions (FP-PDFJS-DECODE, external review amendment).
//! A RegExp receiver needs both a binding proof and file-wide integrity: reflection, unresolved dynamic code,
//! unknown computed properties and writes to protected facilities keep the original warning. The literal
//! fast path shares this gate, with a conservative lexical guard when the tree is unavailable above 2 MB.
//! A round trip additionally needs an intact encoder, a direct child-process call with an untransformed
//! template, and the complete child argument parsed as one supported decode-and-run expression. Visible
//! source using unresolved dynamic execution is never exempted merely because a risk heuristic is quiet.

use super::eval::Eval;
use super::supply::{dialect, supply_tree, Dialect};
use super::*;

/// What a round trip encodes with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enc {
    /// `Buffer.from(src).toString('base64')`, `btoa(src)`
    Base64,
    /// `Buffer.from(src).toString('base64url')`
    Base64Url,
    /// `Buffer.from(src).toString('hex')`
    Hex,
    /// `encodeURIComponent(src)`
    Uri,
    /// `escape(src)`
    Escape,
}

/// A name in a template's hole that holds text the file encodes from text it writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundTrip {
    /// the offset of the name in the hole
    pub at: usize,
    pub enc: Enc,
    /// the text encoded, as the runtime reads it (a string's value, a template's text with its escapes read)
    pub script: PyStr,
    /// the line the text is written on (1-based)
    pub line: usize,
}

/// The tree's answers for one text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Marks {
    /// the offsets of the names of the calls `x.exec(…)` whose receiver is proven a RegExp, sorted
    pub regex_exec: Vec<usize>,
    /// The whole file leaves the shared RegExp method intact.
    pub literal_exec_safe: bool,
    /// the round trips, by offset
    pub round_trips: Vec<RoundTrip>,
}

impl Marks {
    /// Is the `exec` named at offset `at` a RegExp's?
    pub fn regex_exec_at(&self, at: usize) -> bool {
        self.regex_exec.binary_search(&at).is_ok()
    }

    /// The round trip whose name is at offset `at`.
    pub fn round_trip_at(&self, at: usize) -> Option<&RoundTrip> {
        self.round_trips.binary_search_by_key(&at, |r| r.at).ok().map(|k| &self.round_trips[k])
    }
}

thread_local! {
    /// The last text read and the answers (None: the tree could not read it).
    static LAST: std::cell::RefCell<Option<(Dialect, Vec<u32>, Option<Rc<Marks>>)>> = const { std::cell::RefCell::new(None) };
}

/// The marks of a JavaScript text, or None when the tree could not read it (the parser refuses it, or it is over
/// MAX_FILE): the line's reading stands then.
pub fn marks(text: &[u32]) -> Option<Rc<Marks>> {
    if text.len() > MAX_FILE {
        return None;
    }
    let dialect = dialect();
    if let Some(hit) = LAST.with(|l| l.borrow().as_ref().filter(|(d, t, _)| *d == dialect && t.as_slice() == text).map(|(_, _, m)| m.clone())) {
        return hit;
    }
    let owned = text.to_vec();
    let gate = crate::textgate::share(text);
    let got = crate::api::on_own_stack(move || {
        let _gate = gate.and_then(|g| crate::textgate::adopt(&owned, g));
        marks_here(&owned, dialect)
    })
    .map(Rc::new);
    LAST.with(|l| *l.borrow_mut() = Some((dialect, text.to_vec(), got.clone())));
    got
}

fn marks_here(text: &[u32], dialect: Dialect) -> Option<Marks> {
    let tree = supply_tree(text, dialect).ok()?;
    let mut prog = Program::new(Rc::new(Config::new(&[], &[], &[], &[])));
    prog.add_module(&u("script.js"), tree, 0);
    prog.resolve_module(0);
    let safe = integrity(&prog);
    let regex_exec = if safe { regex_exec_calls(&mut prog, false) } else { Vec::new() };
    let round_trips = if safe { round_trips_of(&prog) } else { Vec::new() };
    Some(Marks { regex_exec, round_trips, literal_exec_safe: safe })
}

/// The offsets of the names of the module's calls `x.exec(…)` whose receiver is proven a RegExp
/// (regexp_receiver_with, with `dynamic` for its eval/with), a member receiver never.
fn regex_exec_calls(prog: &mut Program, dynamic: bool) -> Vec<usize> {
    let mut todo: Vec<(FnId, NodeId, NodeId, ScopeId)> = Vec::new();
    {
        let a = Ast(&prog.mods[0].tree);
        for f in &prog.fns {
            if f.module != 0 {
                continue;
            }
            for &(call, scope) in &f.calls {
                if a.kind(call) != Kind::CallExpression {
                    continue;
                }
                let callee = a.unwrap(a.at(call, jt::A));
                if a.kind(callee) == Kind::MemberExpression && !a.computed(callee) && a.prop_name(callee).is_some_and(|n| eq(&n, "exec")) {
                    todo.push((f.fid, call, callee, scope));
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut findings: Vec<Out> = Vec::new();
    for (fid, _call, callee, scope) in todo {
        // (a const can be neither assigned nor shadowed where it is read by a direct eval or a with statement
        // outside the functions around the call: only theirs keep its proof from standing)
        let around = prog.scope_fns(fid);
        let near = around.iter().any(|&f| prog.fns[f as usize].eval_with);
        let mut ev = Eval::new(prog, fid, false, &mut findings);
        let obj = ev.a().unwrap(ev.a().at(callee, jt::A));
        // (a member: regexp_receiver_with's regexp_member takes a parameter's property, or an object literal's,
        // for a regex; neither is proven where a decoded value is handed to it)
        if ev.a().kind(ev.a().at(callee, jt::A)) == Kind::MemberExpression || ev.a().kind(obj) == Kind::MemberExpression {
            continue;
        }
        let a_const = ev.a().kind(obj) == Kind::Identifier
            && ev.bind(obj, scope).is_some_and(|b| ev.p.binds[b as usize].kind == BindKind::Const);
        if ev.regexp_receiver_with(callee, scope, dynamic && (near || !a_const)) {
            let prop = ev.a().at(callee, jt::B);
            out.push(ev.a().0.nodes[prop as usize].start as usize);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// The round trips of the module: each name in a template's hole bound to the encoding of text the file writes.
fn round_trips_of(prog: &Program) -> Vec<RoundTrip> {
    let md = &prog.mods[0];
    let a = Ast(&md.tree);
    let mut out = Vec::new();
    let parents = md.tree.parents();
    let mut source_read = 0usize;
    for id in 0..md.tree.nodes.len() as NodeId {
        if a.kind(id) != Kind::TemplateLiteral {
            continue;
        }
        // An escaped or transformed command, a stored command with unknown later uses, and a command with
        // more than one interpolation are not proofs of the program a child executes.
        if a.list(id, jt::B).len() != 1 || !direct_child_command(prog, id, &parents) {
            continue;
        }
        for &e in a.list(id, jt::B) {
            if e == NONE || a.kind(e) != Kind::Identifier {
                continue;
            }
            let Some(init) = single_init(prog, e) else { continue };
            if let Some((enc, script, line)) = encoded_text(prog, init) {
                source_read = source_read.saturating_add(script.len());
                if source_read > MAX_FILE || out.len() >= 1024 {
                    return Vec::new(); // no exemption when its proof budget is spent
                }
                if !exact_child(prog, id, enc) || !visible_program(&script) {
                    continue;
                }
                out.push(RoundTrip { at: a.0.nodes[e as usize].start as usize, enc, script, line });
            }
        }
    }
    out.sort_by_key(|r| r.at);
    out.dedup_by_key(|r| r.at);
    out
}

/// The value a name is bound to, when the binding is the module's and that value is all it is ever given: a const,
/// or a let or var with one declaration that initializes it and no other write (no assignment, no update, no
/// destructuring, no loop's).
fn single_init(prog: &Program, ident: NodeId) -> Option<NodeId> {
    let md = &prog.mods[0];
    let b = md.bind_at[ident as usize];
    if b == UNSET || b == GLOBAL {
        return None;
    }
    let bind = &prog.binds[b as usize];
    if bind.module != 0 {
        return None;
    }
    match (bind.kind, bind.writes.as_slice()) {
        (BindKind::Const | BindKind::Let | BindKind::Var, [Write::Init { node, path, .. }]) if path.is_empty() => Some(*node),
        _ => None,
    }
}

/// Is identifier `node` the global `name` (no binding of the file)?
fn global(prog: &Program, node: NodeId, name: &str) -> bool {
    let md = &prog.mods[0];
    Ast(&md.tree).is_ident_named(node, name) && md.bind_at[node as usize] == GLOBAL
}

/// `init` as the encoding of text the file writes: (the encoding, the text, its line).
fn encoded_text(prog: &Program, init: NodeId) -> Option<(Enc, PyStr, usize)> {
    let a = Ast(&prog.mods[0].tree);
    let n = a.unwrap(init);
    if a.kind(n) != Kind::CallExpression || a.flag(n, jt::OPTIONAL) {
        return None;
    }
    let callee = a.unwrap(a.at(n, jt::A));
    let args = a.list(n, jt::B);
    if args.len() != 1 && a.kind(callee) == Kind::Identifier {
        return None;
    }
    for (name, enc) in [("btoa", Enc::Base64), ("encodeURIComponent", Enc::Uri), ("escape", Enc::Escape)] {
        if global(prog, callee, name) {
            let (text, line) = written_text(prog, args[0], 0)?;
            return Some((enc, text, line));
        }
    }
    // Buffer.from(src[, 'utf8']).toString('base64' | 'base64url' | 'hex')
    if a.kind(callee) != Kind::MemberExpression || a.computed(callee) || a.flag(callee, jt::OPTIONAL) {
        return None;
    }
    if !a.prop_name(callee).is_some_and(|p| eq(&p, "toString")) || args.len() != 1 {
        return None;
    }
    let enc = match a.str_value(args[0]) {
        Some(v) if eq(v, "base64") => Enc::Base64,
        Some(v) if eq(v, "base64url") => Enc::Base64Url,
        Some(v) if eq(v, "hex") => Enc::Hex,
        _ => return None,
    };
    let inner = a.unwrap(a.at(callee, jt::A));
    if a.kind(inner) != Kind::CallExpression || a.flag(inner, jt::OPTIONAL) {
        return None;
    }
    let from = a.unwrap(a.at(inner, jt::A));
    if a.kind(from) != Kind::MemberExpression || a.computed(from) || a.flag(from, jt::OPTIONAL) {
        return None;
    }
    if !global(prog, a.at(from, jt::A), "Buffer") || !a.prop_name(from).is_some_and(|p| eq(&p, "from")) {
        return None;
    }
    let iargs = a.list(inner, jt::B);
    match iargs.len() {
        1 => {}
        2 if a.str_value(iargs[1]).is_some_and(|v| eq(v, "utf8") || eq(v, "utf-8")) => {}
        _ => return None,
    }
    let (text, line) = written_text(prog, iargs[0], 0)?;
    Some((enc, text, line))
}

/// Text the file writes: a string, a template with no holes, or a name bound once to one (one step). Its value
/// as the runtime reads it, and its line.
fn written_text(prog: &Program, node: NodeId, depth: u32) -> Option<(PyStr, usize)> {
    let a = Ast(&prog.mods[0].tree);
    let n = a.unwrap(node);
    match a.kind(n) {
        Kind::Literal => a.str_value(n).map(|v| (v.to_vec(), a.line(n) as usize)),
        Kind::TemplateLiteral if a.list(n, jt::B).is_empty() => {
            let quasis = a.list(n, jt::A);
            let raw = match quasis {
                [] => &[][..],
                [q] => a.s(*q, jt::A),
                _ => return None,
            };
            Some((cook_template(raw)?, a.line(n) as usize))
        }
        Kind::Identifier if depth == 0 => {
            let init = single_init(prog, n)?;
            written_text(prog, init, 1)
        }
        _ => None,
    }
}

/// A template's text as the runtime reads it (its escapes; a line continuation is nothing). None for an escape
/// the reading does not know (the text is then not read as code).
pub fn cook_template(raw: &[u32]) -> Option<PyStr> {
    let mut out = Vec::with_capacity(raw.len());
    let mut k = 0;
    let hex = |s: &[u32]| -> Option<u32> {
        let mut v: u32 = 0;
        for &c in s {
            v = v.checked_mul(16)? + char::from_u32(c)?.to_digit(16)?;
        }
        Some(v)
    };
    while k < raw.len() {
        let c = raw[k];
        if c == 0x0D {
            // (a template's CR LF and CR are LF)
            out.push(0x0A);
            k += if raw.get(k + 1) == Some(&0x0A) { 2 } else { 1 };
            continue;
        }
        if c != 0x5C {
            out.push(c);
            k += 1;
            continue;
        }
        let n = *raw.get(k + 1)?;
        k += 2;
        match char::from_u32(n)? {
            'n' => out.push(0x0A),
            't' => out.push(0x09),
            'r' => out.push(0x0D),
            'b' => out.push(0x08),
            'f' => out.push(0x0C),
            'v' => out.push(0x0B),
            '0' if !raw.get(k).is_some_and(|&d| (0x30..=0x39).contains(&d)) => out.push(0),
            '\n' => {}
            '\r' => {
                if raw.get(k) == Some(&0x0A) {
                    k += 1;
                }
            }
            '\u{2028}' | '\u{2029}' => {}
            'x' => {
                out.push(hex(raw.get(k..k + 2)?)?);
                k += 2;
            }
            'u' if raw.get(k) == Some(&0x7B) => {
                let end = k + raw[k..].iter().position(|&d| d == 0x7D)?;
                let v = hex(&raw[k + 1..end])?;
                if v > 0x10FFFF || end == k + 1 {
                    return None;
                }
                out.push(v);
                k = end + 1;
            }
            'u' => {
                out.push(hex(raw.get(k..k + 4)?)?);
                k += 4;
            }
            d if d.is_ascii_digit() => return None,
            _ => out.push(n),
        }
    }
    Some(out)
}

/// Conservative integrity gate for an exemption, not a claim that a clean heuristic proves safety.
/// Reads of reflection facilities invalidate aliases as well as direct uses. Unknown computed members are
/// deliberately refused: their key may select a prototype, a global constructor, or an encoder.
fn integrity(prog: &Program) -> bool {
    let md = &prog.mods[0];
    let a = Ast(&md.tree);
    let parents = md.tree.parents();
    let dangerous = |s: &[u32]| is_in(&["prototype", "__proto__", "getOwnPropertyDescriptor",
        "getOwnPropertyDescriptors", "defineProperty", "defineProperties", "setPrototypeOf", "assign",
        "runInThisContext", "runInContext", "runInNewContext", "compileFunction", "Script",
        "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"], s);
    let protected = |s: &[u32]| is_in(&["exec", "execSync", "RegExp", "Buffer", "from", "toString", "btoa",
        "encodeURIComponent", "escape", "Object", "Reflect", "eval", "Function", "require", "env", "NODE_OPTIONS", "PATH"], s);
    for id in 0..md.tree.nodes.len() as NodeId {
        let parent = parents[id as usize];
        match a.kind(id) {
            Kind::WithStatement | Kind::ImportExpression => return false,
            Kind::Identifier if is_in(&["eval", "Function", "AsyncFunction", "GeneratorFunction", "Reflect", "setTimeout", "setInterval"], a.name(id)) => return false,
            Kind::CallExpression if a.is_ident_named(a.at(id, jt::A), "require") => {
                if a.list(id, jt::B).first().is_none_or(|&n| !a.is_string(n)) { return false; }
            }
            Kind::Identifier if a.is_ident_named(id, "RegExp") && md.bind_at[id as usize] == GLOBAL => {
                if parent == NONE || !matches!(a.kind(parent), Kind::CallExpression | Kind::NewExpression)
                    || a.at(parent, jt::A) != id { return false; }
            }
            Kind::MemberExpression => {
                let Some(key) = a.prop_name(id) else { return false };
                if dangerous(&key) || is_in(&["eval", "Function", "Reflect"], &key) { return false; }
                if eq(&key, "constructor") && !known_non_regex(prog, a.at(id, jt::A), 0) { return false; }
                if eq(&key, "getPrototypeOf") {
                    if !global(prog, a.at(id, jt::A), "Object") { return false; }
                    let args = if parent != NONE && a.kind(parent) == Kind::CallExpression && a.at(parent, jt::A) == id {
                        a.list(parent, jt::B)
                    } else { &[] };
                    if args.len() != 1 || !known_non_regex(prog, args[0], 0) { return false; }
                }
            }
            Kind::AssignmentExpression | Kind::UpdateExpression | Kind::UnaryExpression => {
                if a.kind(id) == Kind::UnaryExpression && a.operator(id) != "delete" { continue; }
                let lhs = a.at(id, jt::A);
                if a.kind(lhs) == Kind::Identifier && protected(a.name(lhs)) { return false; }
                for m in a.pattern_members(lhs) {
                    let Some(key) = a.prop_name(m) else { return false };
                    if protected(&key) || dangerous(&key) || eq(&key, "constructor") || eq(&key, "getPrototypeOf") {
                        return false;
                    }
                }
            }
            Kind::Property | Kind::MethodDefinition | Kind::PropertyDefinition => {
                let Some(key) = a.key_name(id) else { return false };
                if dangerous(&key) || is_in(&["exec", "from", "toString", "getPrototypeOf", "constructor", "Reflect"], &key) { return false; }
            }
            _ => {}
        }
    }
    true
}

/// A small positive proof, used only for constructor/prototype reads. An identifier must have a single
/// initializer; only primitive literals and fresh containers count. Members, calls and parameters do not.
fn known_non_regex(prog: &Program, n: NodeId, depth: usize) -> bool {
    if depth > 8 { return false; }
    let a = Ast(&prog.mods[0].tree);
    match a.kind(n) {
        Kind::Literal => !matches!(a.op(n), jt::L_REGEX | jt::L_NULL),
        Kind::ArrayExpression | Kind::ObjectExpression => true,
        Kind::Identifier => single_init(prog, n).is_some_and(|v| known_non_regex(prog, v, depth + 1)),
        _ => false,
    }
}

/// No tree is available above MAX_FILE. Keep the existing text patch guard and additionally refuse reflection,
/// dynamic code, escaped names and indexing. This intentionally sacrifices large-bundle precision on uncertainty.
pub fn large_literal_safe(text: &[u32]) -> bool {
    use crate::lex::Kind as LK;
    for t in crate::lex::js::tokens(text, false).iter() {
        let s = &text[t.start as usize..t.end as usize];
        if t.kind == LK::Name && (s.contains(&(b'\\' as u32)) || is_in(&[
            "eval", "Function", "with", "constructor", "__proto__", "prototype", "Reflect", "require", "import",
            "runInThisContext", "runInContext", "runInNewContext", "compileFunction", "Script", "setTimeout", "setInterval",
            "getPrototypeOf", "getOwnPropertyDescriptor", "getOwnPropertyDescriptors", "defineProperty",
            "defineProperties", "setPrototypeOf", "assign", "__defineGetter__", "__defineSetter__",
            "__lookupGetter__", "__lookupSetter__"], s)) { return false; }
        if t.kind == LK::Punct && eq(s, "[") { return false; }
    }
    true
}

fn child_process_module(prog: &Program, node: NodeId) -> bool {
    let a = Ast(&prog.mods[0].tree);
    let n = if a.kind(node) == Kind::Identifier {
        match single_init(prog, node) { Some(n) => n, None => return false }
    } else { node };
    if a.kind(n) != Kind::CallExpression || !global(prog, a.at(n, jt::A), "require") { return false; }
    let args = a.list(n, jt::B);
    args.len() == 1 && a.str_value(args[0]).is_some_and(|s| is_in(&["child_process", "node:child_process"], s))
}

/// The command template is directly the first argument of the intact child-process exec/execSync binding.
/// A property value or a stored command can be transformed later, so it is deliberately not exempted.
fn direct_child_command(prog: &Program, template: NodeId, parents: &[NodeId]) -> bool {
    let md = &prog.mods[0];
    let a = Ast(&md.tree);
    let call = parents[template as usize];
    if call == NONE || a.kind(call) != Kind::CallExpression || a.flag(call, jt::OPTIONAL)
        || a.list(call, jt::B) != [template] { return false; }
    let callee = a.at(call, jt::A);
    if a.kind(callee) == Kind::MemberExpression {
        return a.prop_name(callee).is_some_and(|k| is_in(&["exec", "execSync"], &k))
            && child_process_module(prog, a.at(callee, jt::A));
    }
    if a.kind(callee) != Kind::Identifier { return false; }
    let b = md.bind_at[callee as usize];
    if b == GLOBAL || b == UNSET { return false; }
    match prog.binds[b as usize].writes.as_slice() {
        [Write::Init { node, path, .. }] if path.len() == 1 => {
            path[0].as_ref().is_some_and(|k| is_in(&["exec", "execSync"], k)) && child_process_module(prog, *node)
        }
        [Write::Import { spec, name, .. }] => is_in(&["child_process", "node:child_process"], spec)
            && is_in(&["exec", "execSync"], name),
        _ => false,
    }
}

/// Parse the entire child argument, with one fixed placeholder for the encoded bytes. No bindings, extra
/// statements, flags, shell operators or transformations are admitted. The whitelist is structural, not a search
/// for a decoder name inside arbitrary child source.
fn exact_child(prog: &Program, template: NodeId, enc: Enc) -> bool {
    const MARKER: &str = "LAZARET_ROUNDTRIP_BYTES";
    let a = Ast(&prog.mods[0].tree);
    let quasis = a.list(template, jt::A);
    if quasis.len() != 2 { return false; }
    let Some(mut cmd) = cook_template(a.s(quasis[0], jt::A)) else { return false };
    cmd.extend(u(MARKER));
    let Some(tail) = cook_template(a.s(quasis[1], jt::A)) else { return false };
    cmd.extend(tail);
    let command = crate::pystr::to_string(&cmd);
    let command = command.trim();
    let Some(after) = command.strip_prefix("node") else { return false };
    if !after.starts_with([' ', '\t']) { return false; }
    let after = after.trim_start_matches([' ', '\t']);
    let Some((flag, rest)) = after.split_once([' ', '\t']) else { return false };
    if !matches!(flag, "-e" | "--eval" | "-p") { return false; }
    let quoted = rest.trim_matches([' ', '\t']);
    let Some(q) = quoted.chars().next().filter(|c| *c == '\'' || *c == '"') else { return false };
    if quoted.len() < 2 || !quoted.ends_with(q) { return false; }
    let child = &quoted[1..quoted.len() - 1];
    if child.contains([q, '$', '`', '\\', '\n', '\r']) { return false; }
    let Ok(tree) = crate::jsparse::parse(&u(child), false, false) else { return false };
    let c = Ast(&tree);
    let body = c.list(tree.root, jt::A);
    if body.len() != 1 || c.kind(body[0]) != Kind::ExpressionStatement { return false; }
    let expr = c.at(body[0], jt::A);
    if c.kind(expr) != Kind::CallExpression || c.flag(expr, jt::OPTIONAL) { return false; }
    let callee = c.at(expr, jt::A);
    let args = c.list(expr, jt::B);
    let decoded = if c.is_ident_named(callee, "eval") && args.len() == 1 {
        args[0]
    } else if c.kind(callee) == Kind::MemberExpression && !c.computed(callee)
        && c.is_ident_named(c.at(callee, jt::A), "vm")
        && c.prop_name(callee).is_some_and(|k| eq(&k, "runInThisContext")) && args.len() == 1 {
        args[0]
    } else if args.is_empty() && matches!(c.kind(callee), Kind::CallExpression | Kind::NewExpression)
        && c.is_ident_named(c.at(callee, jt::A), "Function") && c.list(callee, jt::B).len() == 1 {
        c.list(callee, jt::B)[0]
    } else { return false };
    if c.kind(decoded) != Kind::CallExpression || c.flag(decoded, jt::OPTIONAL) { return false; }
    let d = c.at(decoded, jt::A);
    let da = c.list(decoded, jt::B);
    let marker = |n| c.str_value(n).is_some_and(|v| eq(v, MARKER));
    if da.len() == 1 && marker(da[0]) {
        if c.is_ident_named(d, "atob") { return enc == Enc::Base64; }
        if c.is_ident_named(d, "decodeURIComponent") { return enc == Enc::Uri; }
        if c.is_ident_named(d, "unescape") { return enc == Enc::Escape; }
    }
    if c.kind(d) != Kind::MemberExpression || c.computed(d)
        || !c.prop_name(d).is_some_and(|k| eq(&k, "toString"))
        || !(da.is_empty() || (da.len() == 1 && c.str_value(da[0]).is_some_and(|s| is_in(&["utf8", "utf-8"], s)))) {
        return false;
    }
    let from_call = c.at(d, jt::A);
    if c.kind(from_call) != Kind::CallExpression || c.flag(from_call, jt::OPTIONAL) { return false; }
    let from = c.at(from_call, jt::A);
    let fa = c.list(from_call, jt::B);
    if c.kind(from) != Kind::MemberExpression || c.computed(from)
        || !c.is_ident_named(c.at(from, jt::A), "Buffer") || !c.prop_name(from).is_some_and(|k| eq(&k, "from"))
        || fa.len() != 2 || !marker(fa[0]) { return false; }
    c.str_value(fa[1]).is_some_and(|v| match enc {
        Enc::Base64 | Enc::Base64Url => is_in(&["base64", "base64url"], v),
        Enc::Hex => eq(v, "hex"),
        _ => false,
    })
}

/// A clean install-script heuristic is insufficient when source still executes unknown code. Conservatively
/// retain BLOCKER for dynamic-code facilities, non-literal imports and non-literal child commands. Literal eval,
/// Function, vm and string timers are also left closed until their nested programs have a bounded proof.
fn visible_program(text: &[u32]) -> bool {
    let Ok(tree) = crate::jsparse::parse(text, false, false) else { return false };
    let a = Ast(&tree);
    let parents = tree.parents();
    for id in 0..tree.nodes.len() as NodeId {
        let parent = parents[id as usize];
        let direct_literal = || parent != NONE && a.kind(parent) == Kind::CallExpression
            && a.at(parent, jt::A) == id && a.list(parent, jt::B).first().is_some_and(|&n| a.is_string(n));
        match a.kind(id) {
            Kind::WithStatement => return false,
            Kind::Identifier if is_in(&["eval", "Function", "AsyncFunction", "GeneratorFunction", "Reflect", "Script",
                "runInThisContext", "runInNewContext", "runInContext", "compileFunction"], a.name(id)) => return false,
            Kind::Identifier if is_in(&["require", "exec", "execSync", "execFile", "execFileSync"], a.name(id)) => {
                // A property name is checked at its MemberExpression. A binding or an alias has unknown effects.
                if parent == NONE || a.kind(parent) != Kind::MemberExpression {
                    if !direct_literal() { return false; }
                }
            }
            Kind::Identifier if is_in(&["spawn", "spawnSync", "fork", "setTimeout", "setInterval"], a.name(id)) => return false,
            Kind::MemberExpression => {
                let Some(k) = a.prop_name(id) else { return false };
                if is_in(&["eval", "Function", "constructor", "__proto__", "getPrototypeOf", "Reflect", "Script",
                    "runInThisContext", "runInNewContext", "runInContext", "compileFunction",
                    "spawn", "spawnSync", "fork", "setTimeout", "setInterval"], &k) { return false; }
                if is_in(&["require", "exec", "execSync", "execFile", "execFileSync"], &k) && !direct_literal() { return false; }
            }
            Kind::ImportExpression if !a.is_string(a.at(id, jt::A)) => return false,
            Kind::CallExpression | Kind::NewExpression => {
                let callee = a.at(id, jt::A);
                let args = a.list(id, jt::B);
                let key = if a.kind(callee) == Kind::Identifier { Some(a.name(callee).to_vec()) }
                    else if a.kind(callee) == Kind::MemberExpression { a.prop_name(callee) } else { None };
                if a.kind(callee) == Kind::MemberExpression {
                    if a.is_ident_named(a.at(callee, jt::A), "vm") || key.is_none()
                        || key.as_ref().is_some_and(|k| is_in(&["runInThisContext", "runInNewContext", "runInContext", "compileFunction"], k)) {
                        return false;
                    }
                }
                if let Some(k) = key {
                    if is_in(&["setTimeout", "setInterval"], &k) {
                        if args.first().is_none_or(|&n| !a.is_function(n)) { return false; }
                    }
                    if is_in(&["require", "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"], &k)
                        && args.first().is_none_or(|&n| !a.is_string(n)) { return false; }
                }
            }
            _ => {}
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn at(src: &str, needle: &str, nth: usize) -> usize {
        let t = cps(src);
        let n = cps(needle);
        let mut found = 0;
        for k in 0..t.len() {
            if t[k..].starts_with(&n) {
                if found == nth {
                    return k;
                }
                found += 1;
            }
        }
        panic!("{} not in {}", needle, src);
    }

    fn proven(src: &str, nth: usize) -> bool {
        let m = marks_here(&cps(src), Dialect::Js).expect("parsed");
        m.regex_exec_at(at(src, "exec(", nth))
    }

    #[test]
    fn a_regexs_own_exec() {
        // pdf.js's getPdfFilenameFromUrl, minified (3.11.174), and with its eval("require") elsewhere
        let pdfjs = "function g(t,e=\"document.pdf\"){const i=/[^/?#=]+\\.pdf\\b(?!.*\\.pdf\\b)/i,s=/^(?:[^?#]*)$/.exec(t);\
                     let a=i.exec(s[1])||i.exec(s[2]);if(a){a=a[0];if(a.includes(\"%\"))try{a=i.exec(decodeURIComponent(a))[0]}catch{}}return a||e}";
        assert!(proven(pdfjs, 3));
        assert!(!proven(&format!("{}function w(){{const r=eval(\"require\");return r}}", pdfjs), 3));
        assert!(!proven(&format!("{}var w=eval(\"module.require\");", pdfjs), 3));
        assert!(proven("const s=x();/a(b)/.exec(atob(s));", 0));
        assert!(proven("function f(s){var re=new RegExp('^a');return re.exec(atob(s))}", 0));
        // the construction itself, inline
        assert!(proven("function f(s){return new RegExp('^a').exec(decodeURIComponent(s))}", 0));
        assert!(proven("function f(s){return RegExp('^a','i').exec(atob(s))}", 0));
        // (the same name elsewhere is another binding)
        assert!(proven("function f(s){const i=/x/;return i.exec(atob(s))}function h(i){return i}h(1);", 0));
        // any direct eval invalidates the file-wide integrity proof
        assert!(!proven("function f(s){const i=/x/;return i.exec(atob(s))}function g(c){return eval(c)}", 0));
        assert!(!proven("const i=/x/;function f(s){return i.exec(atob(s))}function g(c){return eval(c)}", 0));
    }

    #[test]
    fn not_a_regexs_exec() {
        let not = |src: &str| assert!(!proven(src, 0), "{}", src);
        // a name given something else, a parameter, a member, a call's result
        not("let r=/x/;r=require('child_process');r.exec(atob('aWQ='));");
        not("function f(r){return r.exec(atob('aWQ='))}f(require('child_process'));");
        not("const re=/x/;function g(re){return re.exec(atob('aWQ='))}g(require('child_process'));");
        not("const o={re:require('child_process')};o.re.exec(atob('aWQ='));");
        not("const n=require('child_process');n.exec(atob('aWQ='));");
        not("const re=/x/;re.exec=require('child_process').exec;re.exec(atob('aWQ='));");
        not("const re=/x/;use(re);re.exec(atob('aWQ='));");
        // RegExp.prototype touched, RegExp rebound, a with statement, a direct eval of code
        not("RegExp.prototype.exec=function(s){return require('child_process').execSync(s)};const re=/x/;re.exec(atob('aWQ='));");
        not("const RegExp=function(){return require('child_process')};const re=new RegExp('x');re.exec(atob('aWQ='));");
        not("const re=/x/;with(o){re.exec(atob('aWQ='))}");
        not("const re=/x/;eval(s);re.exec(atob('aWQ='));");
        not("const re=/x/;eval('re=require(\"child_process\")');re.exec(atob('aWQ='));");
        not("const re=/x/;re?.exec(atob('aWQ='));");
        // a member, even one the taint pass takes for a regex: an object literal's property, one assigned, one
        // defined, a parameter's
        not("const patterns={file:/[^/]+$/};function f(u){return patterns.file.exec(decodeURIComponent(u))}");
        not("const o={};o.re=/x/;o.re.exec(atob('aWQ='));");
        not("const o={};Object.defineProperty(o,'re',{get:()=>/x/});o.re.exec(atob('aWQ='));");
        not("function f(p,u){return p.file.exec(decodeURIComponent(u))}");
        not("const patterns={file:/x/};(patterns.file).exec(atob('aWQ='));");
        // ... in a function around the call, or a let or var anywhere
        not("function f(s){const i=/x/;eval(s);return i.exec(atob(s))}");
        not("const i=/x/;function f(s){eval(s);return i.exec(atob(s))}");
        not("function f(s){let i=/x/;return i.exec(atob(s))}function g(c){return eval(c)}");
    }

    fn trips(src: &str) -> Vec<(Enc, String, usize)> {
        let m = marks_here(&cps(src), Dialect::Js).expect("parsed");
        m.round_trips.iter().map(|r| (r.enc, r.script.iter().map(|&c| char::from_u32(c).unwrap()).collect(), r.line)).collect()
    }

    #[test]
    fn round_trips() {
        let cmd = "require('child_process').execSync(`node -e \"eval(Buffer.from('${encodedScript}','base64').toString('utf8'))\"`);\n";
        let src = format!("const scriptSource = `console.log(1);\nprocess.exitCode = 0;\n`;\nconst encodedScript = Buffer.from(scriptSource).toString('base64');\n{}", cmd);
        assert_eq!(trips(&src), [(Enc::Base64, "console.log(1);\nprocess.exitCode = 0;\n".to_string(), 1)]);
        let inline = format!("const encodedScript = Buffer.from('console.log(1)', 'utf8').toString('base64');\n{}", cmd);
        assert_eq!(trips(&inline), [(Enc::Base64, "console.log(1)".to_string(), 1)]);
        // in a function, with the template's escapes read
        let f = format!("async function main() {{\n  const s = `console.log('a\\`b');\\n`;\n  const encodedScript = btoa(s);\n  {}}}\n", cmd);
        assert_eq!(trips(&f), [(Enc::Base64, "console.log('a`b');\n".to_string(), 2)]);
        assert_eq!(trips(&format!("const encodedScript = Buffer.from('x').toString('hex');\n{}", cmd.replace("base64", "hex")))[0].0, Enc::Hex);
        assert_eq!(trips(&format!("const encodedScript = encodeURIComponent('x');\n{}", cmd.replace("Buffer.from('${encodedScript}','base64').toString('utf8')", "decodeURIComponent('${encodedScript}')")))[0].0, Enc::Uri);
        assert_eq!(trips(&format!("const encodedScript = escape('x');\n{}", cmd.replace("Buffer.from('${encodedScript}','base64').toString('utf8')", "unescape('${encodedScript}')")))[0].0, Enc::Escape);
    }

    #[test]
    fn not_round_trips() {
        let cmd = "require('child_process').execSync(`node -e \"eval(Buffer.from('${encodedScript}','base64').toString('utf8'))\"`);\n";
        let none = |pre: &str| assert_eq!(trips(&format!("{}{}", pre, cmd)), [], "{}", pre);
        none("const encodedScript = require('fs').readFileSync('p.b64', 'utf8');\n");
        none("const encodedScript = process.env.CHILD_SCRIPT;\n");
        none("const encodedScript = process.argv[2];\n");
        none("let encodedScript = Buffer.from(`x`).toString('base64');\nencodedScript = process.env.X;\n");
        none("var encodedScript = Buffer.from(`x`).toString('base64');\nvar encodedScript = process.env.X;\n");
        none("const s = `console.log(${process.env.X})`;\nconst encodedScript = Buffer.from(s).toString('base64');\n");
        none("let s = 'x';\ns = process.env.X;\nconst encodedScript = Buffer.from(s).toString('base64');\n");
        none("const encodedScript = Buffer.from(f()).toString('base64');\n");
        none("const encodedScript = Buffer.from('x', 'base64').toString('base64');\n");
        none("const encodedScript = Buffer.from('x').toString('utf8');\n");
        none("const Buffer = require('./b');\nconst encodedScript = Buffer.from('x').toString('base64');\n");
        none("const btoa = (s) => s;\nconst encodedScript = btoa(process.env.X);\n");
        none("const encodedScript = btoa(process.env.X);\n");
        none("");
        none("function run(encodedScript) {\n  return encodedScript;\n}\n");
        // a parameter of the same name in the template's function
        assert_eq!(
            trips(&format!(
                "const encodedScript = btoa('x');\nfunction f(encodedScript) {{\n  {}}}\n",
                cmd
            )),
            []
        );
        // a direct eval or a with statement anywhere: none
        none("const encodedScript = btoa('x');\neval(code);\n");
        none("const encodedScript = btoa('x');\nwith (o) { y(); }\n");
    }

    #[test]
    fn templates_cooked() {
        let c = |s: &str| cook_template(&cps(s)).map(|v| v.iter().map(|&c| char::from_u32(c).unwrap()).collect::<String>());
        assert_eq!(c("a\\nb\\tc\\\\d\\`e\\${f}"), Some("a\nb\tc\\d`e${f}".to_string()));
        assert_eq!(c("\\x41\\u0042\\u{43}"), Some("ABC".to_string()));
        assert_eq!(c("a\\\nb"), Some("ab".to_string()));
        assert_eq!(c("\\1"), None);
        assert_eq!(c("\\u{110000}"), None);
    }
    fn review_cases(boundary: bool) {
        let data = crate::json::parse_str(include_str!("../../tests/data/decode-review.json")).unwrap();
        let p = crate::pack::current();
        for row in data.as_arr().unwrap() {
            if row.get("size").is_some() != boundary { continue; }
            let id = row.get("id").unwrap().as_string().unwrap();
            let mut source = row.get("source").unwrap().as_string().unwrap();
            for (k, v) in [("<eval>", "eval"), ("<exec>", "exec"), ("<atob>", "atob"), ("<Function>", "Function"),
                ("<from>", "Buffer.from"), ("<duc>", "decodeURIComponent"), ("<cp>", "child_process")] {
                source = source.replace(k, v);
            }
            if let Some(size) = row.get("size").and_then(|x| x.as_i64()) {
                source = format!("{}\n/*{}*/", source, " ".repeat(size as usize - source.len() - 5));
            }
            let want: Vec<String> = row.get("expected").unwrap().as_arr().unwrap().iter().map(|v| v.as_string().unwrap()).collect();
            for dep in [false, true] {
                let opts = crate::scanfile::Options { dep, redact: true, neumaier: true };
                let mut got: Vec<String> = crate::scanfile::scan_file(&p, &cps(&source), Some("js"), false, &opts)
                    .iter().filter_map(|v| { let a=v.as_arr()?; (a[0].as_string()? == "SC-EVAL-DECODE").then(|| a[3].as_string().unwrap()) }).collect();
                got.sort();
                assert_eq!(got, want, "{id}, dep={dep}");
            }
        }
    }
    #[test]
    fn external_review_cases() { review_cases(false); }
    #[test]
    fn external_review_boundaries() { review_cases(true); }

}
