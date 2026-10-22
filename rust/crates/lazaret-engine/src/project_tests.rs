//! Project mode after the rules (Q-1), through the call both packages make (`scan_file` with `dep: false`): each
//! pass finds what it is for, a sanitizer or a scope ends a flow, a reviewer's marker drops a finding, the cap
//! holds, and a taint configuration is read, or refused when it is not one. The recorded sets
//! (python/tests/architecture/test_snapshot_project.py) hold the rest, finding by finding.

use crate::api::{call, CallError};
use crate::json::{parse_str, Value};

fn cps(s: &str) -> Vec<u32> {
    s.chars().map(|c| c as u32).collect()
}

fn answer(name: &str, args: &str, text: &str) -> Result<Value, CallError> {
    call(name, &parse_str(args).unwrap(), &cps(text))
}

/// (rule, line) of each finding of a project scan of `text`.
fn found(args: &str, text: &str) -> Vec<(String, i64)> {
    let v = answer("scan_file", args, text).unwrap();
    v.as_arr()
        .unwrap()
        .iter()
        .map(|i| {
            let a = i.as_arr().unwrap();
            (a[0].as_string().unwrap(), a[8].as_i64().unwrap())
        })
        .collect()
}

fn are(want: &[(&str, i64)]) -> Vec<(String, i64)> {
    want.iter().map(|(r, l)| (r.to_string(), *l)).collect()
}

const PY: &str = r#"{"lang": "py", "dep": false}"#;
const JS: &str = r#"{"lang": "js", "dep": false, "jsx": true}"#;
const SQL: &str = r#"{"lang": "sql", "dep": false}"#;
const FLOW: &str = "from flask import request\nimport os\n\ndef run():\n    cmd = request.args.get(\"c\")\n    os.system(cmd)\n";

#[test]
fn a_request_value_that_reaches_a_shell() {
    assert_eq!(found(PY, FLOW), are(&[("S-OSCMD-PY", 6), ("T-CMD", 6)]));
    // the message names the value and where it was tainted
    let v = answer("taint_scan", r#"{"lang": "py"}"#, FLOW).unwrap();
    let issues = v.as_arr().unwrap();
    assert_eq!(issues.len(), 1);
    let msg = issues[0].as_arr().unwrap()[4].as_string().unwrap();
    assert!(msg.contains("'cmd' (tainted at line 5)"), "{msg}");
}

#[test]
fn a_sanitizer_or_the_end_of_a_scope_ends_the_flow() {
    let quoted = FLOW.replace("os.system(cmd)", "os.system(shlex.quote(cmd))");
    assert_eq!(found(PY, &quoted), are(&[("S-OSCMD-PY", 6)]));
    let scoped = "import os\nfrom flask import request\n\ndef a():\n    v = request.args[\"x\"]\n\ndef b(v):\n    os.system(v)\n";
    assert_eq!(found(PY, scoped), are(&[("S-OSCMD-PY", 8)]));
}

#[test]
fn javascript_flows_and_their_markers() {
    let js = "app.get(\"/a\", (req, res) => {\n  const q = req.query.q;\n  res.send(\"<p>\" + q);\n});\n";
    assert_eq!(found(JS, js), are(&[("T-XSS", 3)]));
    let marked = js.replace("  res.send", "  // lazaret-ignore: T-XSS\n  res.send");
    assert_eq!(found(JS, &marked), are(&[]));
}

#[test]
fn a_marker_on_the_line_drops_its_findings() {
    assert_eq!(found(PY, &FLOW.replace("os.system(cmd)", "os.system(cmd)  # nosec")), are(&[]));
}

#[test]
fn sql_built_from_strings_and_statements_without_where() {
    let py = "def f(cur, uid):\n    cur.execute(\"SELECT * FROM t WHERE id=\" + uid)\n";
    assert_eq!(found(PY, py), are(&[("S-SQL-PY", 2)]));
    let sql = "DELETE FROM users;\nUPDATE users SET a = 1;\nDELETE FROM t WHERE id = 1;\n";
    assert_eq!(found(SQL, sql), are(&[("SQL-DELETE-NOWHERE", 1), ("SQL-UPDATE-NOWHERE", 2)]));
}

#[test]
fn function_metrics() {
    let py = "def f(a):\n    if a:\n        return 1\n    for x in a:\n        if x and a:\n            pass\n    return 2\n\nclass C:\n    def m(self):\n        return 0\n";
    let v = answer("functions", r#"{"lang": "py"}"#, py).unwrap();
    assert_eq!(crate::json::write(&v), r#"[["f",1,8,5],["m",10,3,1]]"#);
    let js = "function f(a) {\n  return a ? 2 : 3;\n}\nconst g = async (b) => {\n  return b || 1;\n};\n";
    let v = answer("functions", r#"{"lang": "js"}"#, js).unwrap();
    assert_eq!(crate::json::write(&v), r#"[["f",1,3,2],["g",4,3,2]]"#);
    let long = format!("def big(a):\n{}    return a\n", "    x = a\n".repeat(90));
    assert_eq!(found(PY, &long), are(&[("Q-FN-LONG", 1)]));
    let busy: String = (0..12).map(|i| format!("    if a == {i}:\n        return {i}\n")).collect();
    assert_eq!(found(PY, &format!("def busy(a):\n{busy}    return 0\n")), are(&[("Q-FN-CX", 1)]));
}

#[test]
fn findings_past_the_cap_are_one_note() {
    let text: String = (0..230).map(|i| format!("# TODO item {i}\nx{i} = 1\n")).collect();
    let v = answer("scan_file", PY, &text).unwrap();
    let issues = v.as_arr().unwrap();
    assert_eq!(issues.len(), 201);
    let last = issues[200].as_arr().unwrap();
    assert_eq!(last[0].as_string().unwrap(), "Q-CAPPED");
    assert_eq!(last[4].as_string().unwrap(), "30 more Q-TODO findings omitted");
}

#[test]
fn a_taint_configuration_is_read() {
    let text = "x = get_param(\"a\")\nrun_query(x)\nshell(escape_sql(x))\nrun_query(escape_sql(x))\ny = clean_it(x)\nrun_query(y)\n";
    assert_eq!(found(PY, text), are(&[]));
    let conf = r#"{"lang": "py", "dep": false, "taint": {"sources": ["get_param\\("],
        "sinks": [["run_query\\(", "SQL injection"], ["\\bshell\\(", "command injection"]],
        "full": ["clean_it"], "partial": [["escape_sql", ["SQL injection"]]]}}"#;
    // the partial sanitizer is one for SQL alone; the full one, for every category
    assert_eq!(found(conf, text), are(&[("T-SQL", 2), ("T-CMD", 3)]));
    // null is no configuration
    assert_eq!(found(r#"{"lang": "py", "dep": false, "taint": null}"#, text), are(&[]));
}

#[test]
fn a_configuration_that_is_not_one_is_refused() {
    for (taint, why) in [
        (r#"{"sources": ["("]}"#, "does not compile"),
        (r#"{"sinks": [["run_query\\("]]}"#, "category is not a string"),
        (r#"{"sinks": [["run_query\\(", "a category no one knows"]]}"#, "unknown category"),
        (r#"{"partial": [["f", ["SQL injection", "bogus"]]]}"#, "unknown category"),
        (r#"{"sinks": ["run_query"]}"#, "not [pattern, category]"),
    ] {
        for call_name in ["scan_file", "taint_scan"] {
            let args = format!(r#"{{"lang": "py", "dep": false, "taint": {taint}}}"#);
            match answer(call_name, &args, "x = 1\n") {
                Err(CallError::BadArgs(m)) => assert!(m.starts_with(call_name) && m.contains(why), "{m}"),
                other => panic!("{call_name} {taint}: {other:?}"),
            }
        }
    }
}
