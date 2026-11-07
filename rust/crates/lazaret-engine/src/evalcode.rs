//! EVAL-LITERAL (0.1.9): the code a JavaScript or Python text hands an eval call as a string.
//!
//! `eval("…")`, `Function("…")` and `new Function("a", "…")` (its last argument: the ones before it name its
//! parameters), and a global object's eval or Function by a name the text computes (`globalThis["ev" + "al"]("…")`;
//! `window[k]("…")`, whose name is not known, any of its arguments), run the string they are handed as code; in
//! Python `eval("…")`, `exec("…")` and `compile("…", …)`, and `getattr(builtins, "exec")("…")`. The import-time and
//! install-script tests read a text's code, and a string is not code to them: a send written inside one was quiet.
//! [`codes`] gives the value of each such string, which the tests read as a text of their own
//! (`signs::eval_literal_reasons`). Found and first fixed by the external review agent (card 609dd639, Oct 21–22),
//! whose fix this ports.
//!
//! The calls are found on the text's tokens (lex), so a call in a comment, a string or a regular expression is none,
//! and a comment between a call's name and its `(` changes nothing. The name may be a global object's member
//! (`window.eval`, `globalThis.Function`, `builtins.exec`), parenthesized (`(0, eval)("…")`), called optionally
//! (`eval?.("…")`) or through `call` (`eval.call(null, "…")`), and written with JavaScript's escapes (`\u0065val`) or
//! in a form Python's NFKC reads as the name (`ｅｘｅｃ`). An argument is a string where it is one the runtime makes
//! of literals alone: a string literal, a template with no holes, several joined by `+` (in Python adjacent ones,
//! `'a' 'b'`, too), each read as its runtime reads it (lex/value.rs: escaped quotes, `\x41`, `\u0041`, `\u{41}`, line
//! continuations; Python's raw, bytes and triple-quoted strings, `\N{…}`). Not read: a template with holes, a
//! string joined with anything else (`"a" + x`), a name or a call that holds the string (`eval(code)`,
//! `eval(atob("…"))`: the decoded view and the received-code flows read those), `Function.apply`,
//! `Reflect.apply(eval, …)`, `[].constructor.constructor("…")` and Node's `vm.runInThisContext("…")`.

use crate::lex::{self, value, Kind, Token};
use crate::pack::Pack;
use crate::pystr::PyStr;
use std::borrow::Cow;
use std::collections::HashSet;

const fn c(ch: char) -> u32 {
    ch as u32
}

fn eq(a: &[u32], b: &str) -> bool {
    a.len() == b.len() && a.iter().zip(b.bytes()).all(|(&x, y)| x == y as u32)
}

/// Which of a call's arguments it runs as code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Runs {
    /// the first after `skip` (eval; Python's exec and compile; `eval.call(this, code)` skips one)
    First(usize),
    /// the last, past `skip` (Function: the arguments before it name its parameters)
    Last(usize),
    /// each (a global object's member by a name the text computes: eval or Function, or neither)
    Each,
}

/// What calling the name `name` runs, in Python (`py`) or JavaScript.
fn runner(name: &[u32], py: bool) -> Option<Runs> {
    if eq(name, "eval") || (py && (eq(name, "exec") || eq(name, "compile"))) {
        return Some(Runs::First(0));
    }
    if !py && eq(name, "Function") {
        return Some(Runs::Last(0));
    }
    None
}

/// A text's tokens, read in its language; comments are stepped over.
struct Code<'t> {
    text: &'t [u32],
    toks: &'t [Token],
    py: bool,
    /// each bracket token's closing one ([`pairs`])
    pair: Vec<u32>,
}

/// No closing bracket: the text ends first.
const NONE: u32 = u32::MAX;

/// For each bracket token of `toks`, the index of the one that closes it (`(`, `[` and `{` alike, as a walk that
/// counts them reads it), else [`NONE`]; found once for the whole text, so that a call's arguments are read to its end
/// stepping over the brackets in them (F-4, the gates of Oct 27: a walk of each call to its end read `eval(` nested
/// 100,000 deep once for each call, until the budget was spent, where the tree's "nesting too deep" answered at once).
fn pairs(text: &[u32], toks: &[Token]) -> Vec<u32> {
    let mut pair = vec![NONE; toks.len()];
    let mut open: Vec<u32> = Vec::new();
    for (k, t) in toks.iter().enumerate() {
        if t.kind != Kind::Punct {
            continue;
        }
        match &text[t.start as usize..t.end as usize] {
            [o] if matches!(*o, 0x28 | 0x5B | 0x7B) => open.push(k as u32),
            [o] if matches!(*o, 0x29 | 0x5D | 0x7D) => {
                if let Some(o) = open.pop() {
                    pair[o as usize] = k as u32;
                }
            }
            _ => {}
        }
    }
    pair
}

impl<'t> Code<'t> {
    fn s(&self, i: usize) -> &'t [u32] {
        let t = self.toks[i];
        &self.text[t.start as usize..t.end as usize]
    }

    /// The code token after `i`.
    fn next(&self, i: usize) -> Option<usize> {
        (i + 1..self.toks.len()).find(|&k| self.toks[k].kind != Kind::Comment)
    }

    /// The code token before `i`.
    fn prev(&self, i: usize) -> Option<usize> {
        (0..i).rev().find(|&k| self.toks[k].kind != Kind::Comment)
    }

    fn punct(&self, i: usize, p: &str) -> bool {
        self.toks[i].kind == Kind::Punct && eq(self.s(i), p)
    }

    fn word(&self, i: usize, w: &str) -> bool {
        self.toks[i].kind == Kind::Name && eq(&self.ident(i), w)
    }

    /// A member access: `.`, or JavaScript's `?.`.
    fn dot(&self, i: usize) -> bool {
        self.punct(i, ".") || (!self.py && self.punct(i, "?."))
    }

    /// A name's identifier: JavaScript's escapes read (`\u0065val` is `eval`), Python's NFKC (as Python reads names).
    fn ident(&self, i: usize) -> Cow<'t, [u32]> {
        let s = self.s(i);
        if self.py {
            if s.iter().any(|&ch| ch >= 0x80) {
                return Cow::Owned(crate::normalize::nfkc(s));
            }
        } else if s.contains(&c('\\')) {
            let mut out = Vec::with_capacity(s.len());
            crate::jsparse::scan::unescape_ident(s, &mut out);
            return Cow::Owned(out);
        }
        Cow::Borrowed(s)
    }

    /// Is token `i` a name of a global object (`_GLOBAL_EVAL_RECEIVERS`: `window`, `globalThis`, `builtins` …) that
    /// is no member of another?
    fn receiver(&self, i: usize, receivers: &[PyStr]) -> bool {
        self.toks[i].kind == Kind::Name
            && receivers.iter().any(|r| *r == *self.ident(i))
            && !self.prev(i).is_some_and(|k| self.dot(k))
    }

    /// The token that closes the bracket at `open`; None when the text ends first.
    fn close(&self, open: usize) -> Option<usize> {
        let k = self.pair[open];
        (k != NONE).then_some(k as usize)
    }

    /// The `(` of a call whose callee ends at token `i`: the next token's, after an optional call's `?.` (and with
    /// `paren`, after the `)` that closes a parenthesized callee, `(0, eval)(…)`).
    fn open(&self, i: usize, paren: bool) -> Option<usize> {
        let mut j = self.next(i)?;
        if paren && self.punct(j, ")") {
            j = self.next(j)?;
        }
        if !self.py && self.punct(j, "?.") {
            j = self.next(j)?;
        }
        self.punct(j, "(").then_some(j)
    }

    /// The call whose callee begins at name token `i`, when it runs a string it is handed: (its offset, the index of
    /// its `(`, which arguments it runs). Not a member of an object other than a global one, nor a declaration
    /// (`function eval(`, `def exec(`).
    fn call(&self, i: usize, receivers: &[PyStr]) -> Option<(usize, usize, Runs)> {
        let name = self.ident(i);
        let run = runner(&name, self.py);
        let global = run.is_none() && receivers.iter().any(|r| *r == *name);
        if run.is_none() && !global && !(self.py && eq(&name, "getattr")) {
            return None;
        }
        let prev = self.prev(i);
        let member = prev.is_some_and(|k| self.dot(k));
        if member {
            let r = self.prev(prev?)?;
            if !self.receiver(r, receivers) {
                return None;
            }
        } else if prev.is_some_and(|k| self.word(k, "function") || self.word(k, "def") || self.word(k, "class")) {
            return None;
        }
        let at = self.toks[i].start as usize;
        if let Some(runs) = run {
            let j = self.next(i)?;
            // eval.call(this, code), Function.call(this, …, body)
            if self.dot(j) && self.next(j).is_some_and(|k| self.word(k, "call")) {
                let open = self.open(self.next(j)?, false)?;
                let runs = match runs {
                    Runs::First(_) => Runs::First(1),
                    _ => Runs::Last(1),
                };
                return Some((at, open, runs));
            }
            return Some((at, self.open(i, true)?, runs));
        }
        if member {
            return None;
        }
        // a global object's member by a name: globalThis["ev" + "al"](code), window[k](code), __builtins__["exec"](…)
        if global {
            let b = self.next(i)?;
            if !self.punct(b, "[") {
                return None;
            }
            let e = self.close(b)?;
            let open = self.open(e, true)?;
            let runs = match self.constant(b + 1, e) {
                Some(key) => runner(&key, self.py)?,
                None => Runs::Each,
            };
            return Some((at, open, runs));
        }
        // Python: getattr(builtins, "exec")(code); getattr(builtins, name)(code), any of them
        let o = self.open(i, false)?;
        let close = self.close(o)?;
        let args = self.args(o)?;
        let [(oa, ob), (ka, kb)] = args.as_slice() else { return None };
        let object: Vec<usize> = (*oa..*ob).filter(|&k| self.toks[k].kind != Kind::Comment).collect();
        let runs = match self.constant(*ka, *kb) {
            Some(key) => runner(&key, true)?,
            None if matches!(object.as_slice(), [k] if self.receiver(*k, receivers)) => Runs::Each,
            None => return None,
        };
        Some((at, self.open(close, false)?, runs))
    }

    /// The arguments of the call whose `(` is token `open`: each as the range of its tokens; None when the text ends
    /// before the call does. A bracket in an argument is stepped over to its end (`close`), so a token is read for the
    /// call whose arguments hold it directly, not for each call it is nested in: a text of calls nested in each other's
    /// arguments is read once (each token read charged to the call's budget, a step).
    fn args(&self, open: usize) -> Option<Vec<(usize, usize)>> {
        let mut out = Vec::new();
        let mut from = open + 1;
        let mut k = open;
        loop {
            k = self.next(k)?;
            if !crate::budget::spend(1) {
                return None;
            }
            if self.toks[k].kind != Kind::Punct {
                continue;
            }
            match self.s(k) {
                [o] if matches!(*o, 0x28 | 0x5B | 0x7B) => k = self.close(k)?,
                [o] if matches!(*o, 0x29 | 0x5D | 0x7D) => {
                    if self.next(from - 1).is_some_and(|f| f < k) {
                        out.push((from, k));
                    }
                    return Some(out);
                }
                [o] if *o == c(',') => {
                    out.push((from, k));
                    from = k + 1;
                }
                _ => {}
            }
        }
    }

    /// The value of the code tokens in `a..b` when they are one string the runtime makes of literals alone (string
    /// literals and templates with no holes, `+` between them; in Python adjacent ones too), else None.
    fn constant(&self, a: usize, b: usize) -> Option<PyStr> {
        let mut out: PyStr = Vec::new();
        let mut bytes: Option<bool> = None;
        // (a literal is wanted next: at the start, and after a `+`)
        let mut want = true;
        for k in a..b {
            match self.toks[k].kind {
                Kind::Comment => {}
                Kind::Punct if !want && self.punct(k, "+") => want = true,
                Kind::Str | Kind::Template if want || self.py => {
                    let v = self.literal(k)?;
                    if *bytes.get_or_insert(v.bytes) != v.bytes {
                        return None;
                    }
                    out.extend_from_slice(&v.chars);
                    want = false;
                }
                _ => return None,
            }
        }
        (bytes.is_some() && !want).then_some(out)
    }

    /// A literal token's value: a JavaScript string or template with no holes, a Python string or bytes literal
    /// (an f-string is none).
    fn literal(&self, k: usize) -> Option<value::Value> {
        let lit = self.s(k);
        if self.py {
            return if self.toks[k].kind == Kind::Str { value::py(lit) } else { None };
        }
        value::js(lit).map(|chars| value::Value { chars, bytes: false })
    }
}

/// The strings `text` (in `lang`, "js" or "py") hands a call that runs them as code, as the runtime reads them: (the
/// offset of the call, the string), in order, each string once (an empty one is none).
pub fn codes(p: &Pack, text: &[u32], lang: &str) -> Vec<(usize, PyStr)> {
    let py = lang == "py";
    // (the names, and an escape that may write one; a Python name NFKC reads as one)
    if p.re("_EVAL_CALL_RE").search(text).is_none() && !(py && text.iter().any(|&ch| ch >= 0x80)) {
        return Vec::new();
    }
    let toks = if py { lex::py::tokens(text) } else { lex::js::tokens(text, false) };
    let code = Code { text, toks: toks.as_slice(), py, pair: pairs(text, toks.as_slice()) };
    let receivers = p.strs("_GLOBAL_EVAL_RECEIVERS");
    let mut seen: HashSet<PyStr> = HashSet::new();
    let mut out = Vec::new();
    for i in 0..toks.len() {
        if toks[i].kind != Kind::Name {
            continue;
        }
        // (the first character of each name a call may begin with, before a name is read: e, F, c, g, w, s, t, p, f, b,
        // _; an escape; a character NFKC may read as one)
        let first = text[toks[i].start as usize];
        if !(matches!(char::from_u32(first), Some('e' | 'F' | 'c' | 'g' | 'w' | 's' | 't' | 'p' | 'f' | 'b' | '_' | '\\')) || first >= 0x80) {
            continue;
        }
        let Some((at, open, runs)) = code.call(i, &receivers) else { continue };
        let Some(args) = code.args(open) else { continue };
        let picked: &[(usize, usize)] = match runs {
            Runs::First(k) => args.get(k..k + 1).unwrap_or(&[]),
            Runs::Last(k) if args.len() > k => &args[args.len() - 1..],
            Runs::Last(_) => &[],
            Runs::Each => &args,
        };
        for &(a, b) in picked {
            if let Some(v) = code.constant(a, b) {
                if !v.is_empty() && seen.insert(v.clone()) {
                    out.push((at, v));
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "evalcode_tests.rs"]
mod route_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    fn found(text: &str, lang: &str) -> Vec<(usize, String)> {
        let t = cps(text);
        codes(&crate::pack::current(), &t, lang)
            .into_iter()
            .map(|(at, v)| (crate::pystr::count_char(&t, c('\n'), 0, at) + 1, crate::pystr::to_string(&v)))
            .collect()
    }

    fn strings(text: &str, lang: &str) -> Vec<String> {
        found(text, lang).into_iter().map(|(_, v)| v).collect()
    }

    #[test]
    fn the_calls_that_run_a_string() {
        assert_eq!(found("x();\neval(\"a + 1\");\n", "js"), vec![(2, "a + 1".to_string())]);
        assert_eq!(strings("new Function('a', 'b', 'return a + b');\n", "js"), vec!["return a + b"]);
        assert_eq!(strings("Function(\"return this\")();\n", "js"), vec!["return this"]);
        assert_eq!(strings("globalThis[\"ev\" + \"al\"](\"x = 1\");\n", "js"), vec!["x = 1"]);
        assert_eq!(strings("window['Func' + 'tion']('a', 'return a')(1);\n", "js"), vec!["return a"]);
        assert_eq!(strings("self[`eval`]('y = 2');\n", "js"), vec!["y = 2"]);
        // a name the text computes: any of the arguments
        assert_eq!(strings("global[k]('one', 'two');\n", "js"), vec!["one", "two"]);
        // a member of a global object; parenthesized; optional; through call; escaped
        assert_eq!(strings("window.eval('a');\n(0, eval)('b');\n(eval)('c');\neval?.('d');\n", "js"), vec!["a", "b", "c", "d"]);
        assert_eq!(strings("eval.call(null, 'e');\nFunction.call(null, 'p', 'f');\n", "js"), vec!["e", "f"]);
        assert_eq!(strings("\\u0065val('g');\nev\\u{61}l('h');\n", "js"), vec!["g", "h"]);
        assert_eq!(strings("eval /* x */ (\n  'i' // y\n);\n", "js"), vec!["i"]);
    }

    #[test]
    fn the_string_as_its_runtime_reads_it() {
        assert_eq!(strings("eval('it\\'s \"q\"');\n", "js"), vec!["it's \"q\""]);
        assert_eq!(strings("eval(\"\\x66\\u0065tch(\\u{61})\");\n", "js"), vec!["fetch(a)"]);
        assert_eq!(strings("eval(`a\nb`);\n", "js"), vec!["a\nb"]);
        assert_eq!(strings("eval('a' + \"b\" + `c`);\n", "js"), vec!["abc"]);
        assert_eq!(strings("eval('a\\\nb');\n", "js"), vec!["ab"]);
        // Python: exec, eval and compile; adjacent and joined literals, triple-quoted, raw, bytes, \N{…}
        assert_eq!(strings("exec('a = 1')\neval(\"b\")\ncompile('c', '<s>', 'exec')\n", "py"), vec!["a = 1", "b", "c"]);
        assert_eq!(strings("exec('a' \"b\"\n     'c' + '''d''')\n", "py"), vec!["abcd"]);
        assert_eq!(strings("exec(r'\\x41')\nexec(b'\\x42')\nexec('\\N{LATIN SMALL LETTER E}')\n", "py"), vec!["\\x41", "B", "e"]);
        assert_eq!(strings("import builtins\nbuiltins.exec('x')\ngetattr(builtins, 'exec')('y')\n__builtins__['eval']('z')\n", "py"), vec!["x", "y", "z"]);
        assert_eq!(strings("\u{ff45}\u{ff58}\u{ff45}\u{ff43}('w')\n", "py"), vec!["w"]);
    }

    #[test]
    fn what_is_not_a_string_run() {
        // a name, a call, a template with holes, a string joined with a name
        assert!(strings("eval(code);\neval(atob('eA=='));\neval(`a${b}c`);\neval('a' + b);\neval(('a'));\n", "js").is_empty());
        // in a comment, a string, a regular expression; a declaration; another object's member; another name
        assert!(strings("// eval('a')\nconst s = \"eval('b')\";\nconst r = /eval('c')/;\nfunction eval(x) {}\n", "js").is_empty());
        assert!(strings("redis.eval('d');\nmath.eval('e');\nwindow.foo.eval('f');\nevaluate('g');\nmyeval('h');\n", "js").is_empty());
        assert!(strings("window['alert']('i');\nwindow.x('j');\nre.compile('k');\nexec('l');\n", "js").is_empty());
        assert!(strings("re.compile('a')\ngetattr(obj, name)('b')\ndef exec(x): pass\nexec(f'c{d}')\n", "py").is_empty());
        // Function's parameters are not its body
        assert!(strings("new Function('a', 'b', body);\n", "js").is_empty());
        // each string once; an empty one is none
        assert_eq!(strings("eval('x');\neval('x');\neval('');\n", "js"), vec!["x"]);
    }

    #[test]
    fn calls_nested_in_each_others_arguments_are_read_once() {
        // (F-4) a call's arguments are read stepping over the brackets in them, each token a step: 100,000 calls one
        // in another's are some 300,000 tokens read, where a walk of each call to its end read 10,000,000,000
        let p = crate::pack::current();
        let t = cps(&format!("{}x{}", "eval(".repeat(100_000), ")".repeat(100_000)));
        assert_eq!(crate::budget::call_with(1_000_000, || codes(&p, &t, "js")), Ok(vec![]));
        let t = cps(&format!("{}k{}('a');\n", "window[".repeat(100_000), "]".repeat(100_000)));
        assert_eq!(crate::budget::call_with(1_000_000, || codes(&p, &t, "js")), Ok(vec![(0, cps("a"))]));
        // and what a call is handed is read as before, the brackets in its arguments and around it whatever they are
        let deep = format!("{}eval('a', f(b, [c, {{d: 'e'}}]), 'g'){}", "f(".repeat(500), ")".repeat(500));
        assert_eq!(strings(&deep, "js"), vec!["a"]);
        assert_eq!(strings("new Function('p', g(h(1), [2]), 'body');\nglobal[f(k)[0]]('x', (y), 'z');\n", "js"), vec!["body", "x", "z"]);
        assert_eq!(strings("eval(f(')'), 'a');\neval([1, 2)\n", "js"), Vec::<String>::new());
        crate::budget::reset(crate::budget::DEFAULT_STEPS);
    }

    #[test]
    fn a_text_that_ends_inside_the_call() {
        for text in ["eval(", "eval(\"", "eval('a'", "eval('a',", "x = eval", "new Function('a', ", "globalThis[", "window['eval'](", "eval(\n"] {
            assert!(strings(text, "js").is_empty(), "{text:?}");
        }
        for text in ["exec(", "exec('a'", "getattr(builtins, 'exec')(", "getattr("] {
            assert!(strings(text, "py").is_empty(), "{text:?}");
        }
    }
}
