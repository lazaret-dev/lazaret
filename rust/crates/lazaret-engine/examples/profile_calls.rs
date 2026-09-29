//! Time each engine call over a JSON list of texts (a development aid):
//!     cargo run --release --example profile_calls -- cases.json
use lazaret_engine::{api, json};
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("a JSON file of texts");
    let text = std::fs::read_to_string(path).expect("readable");
    let cases = json::parse_str(&text).expect("JSON");
    let cases: Vec<Vec<u32>> = cases.as_arr().unwrap().iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect();
    let empty = json::Value::Obj(Vec::new());
    let py = json::parse_str(r#"{"lang":"py"}"#).unwrap();
    let js = json::parse_str(r#"{"lang":"js"}"#).unwrap();
    let calls: Vec<(&str, &json::Value)> = vec![
        ("shlex_split", &empty), ("hook_tokens", &empty), ("follow_hook", &empty), ("install_script_risk", &empty),
        ("import_time_risk", &empty), ("import_time_risk", &py), ("import_time_risk", &js), ("node_e_codes", &empty),
        ("shebang_lang", &empty), ("self_publish_at", &empty), ("runs_dll", &empty), ("join_string_pieces", &empty),
        ("decoded_view", &empty), ("spawned_scripts", &empty), ("received_code_kind", &empty),
        ("powershell_risk", &empty), ("stager_at", &empty), ("reverse_shell_at", &empty), ("runs_own_source_at", &empty),
        ("persistence_reasons", &empty), ("downloads_and_runs", &empty), ("decodes_and_runs", &empty),
    ];
    let small: Vec<&Vec<u32>> = cases.iter().filter(|c| c.len() < 5000).collect();
    let _ = api::call("version", &empty, &[]);
    for (name, args) in calls {
        let t = Instant::now();
        for c in &small {
            let _ = api::call(name, args, c);
        }
        println!("{:24} {:8.1} ms over {} small cases", format!("{}{}", name, if std::ptr::eq(args, &py) {" py"} else if std::ptr::eq(args, &js) {" js"} else {""}), t.elapsed().as_secs_f64() * 1000.0, small.len());
    }
}
