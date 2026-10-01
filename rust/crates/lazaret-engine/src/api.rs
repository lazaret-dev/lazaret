//! The engine's calls, by name: what the bindings expose.
//!
//! A call is a name, its arguments (a JSON object) and, for the functions
//! that read one, the text (a Python str, passed apart from the arguments so
//! that a large file is not escaped into JSON). It answers with a JSON value,
//! or an error: an unknown call or bad arguments (a bug in the binding), or
//! the work budget spent (the binding then answers with the Python reference
//! engine: see crate::budget).

use crate::json::Value;
use crate::pack::Pack;
use crate::pyre::{self, Regex};
use crate::pystr::{u, PyStr};
use crate::{hooks, lexer, received, signs};

#[derive(Debug)]
pub enum CallError {
    Unknown(String),
    BadArgs(String),
    Exhausted,
}

fn arg_str(args: &Value, name: &str) -> Result<Vec<u32>, CallError> {
    args.get(name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_vec())
        .ok_or_else(|| CallError::BadArgs(format!("missing string argument {}", name)))
}

fn opt_str(args: &Value, name: &str) -> Option<Vec<u32>> {
    args.get(name).and_then(|v| v.as_str()).map(|s| s.to_vec())
}

fn opt_int(args: &Value, name: &str) -> Option<i64> {
    args.get(name).and_then(|v| v.as_i64())
}

/// Every call's name, for `lazaret --engine rust --version` and the tests.
pub const CALLS: &[&str] = &[
    "version", "batch", "pack.install", "pack.reset", "pack.info", "pyre.probe", "pyre.escape",
    // Phase 1: following install hooks, the install-script and import-time tests
    "shlex_split", "hook_tokens", "follow_hook", "node_candidates", "node_e_codes", "shebang_lang",
    "install_script_risk", "import_time_risk", "import_time_severity", "decoded_view", "spawned_scripts",
    "self_publish_at", "runs_dll", "join_string_pieces", "received_code_kind", "runs_received_code",
    "downloads_and_runs", "decodes_and_runs", "powershell_risk", "stager_at", "reverse_shell_at",
    "sends_host_info", "runs_own_source_at", "reads_own_source", "persistence_reasons",
    "dumps_workflow_secrets", "pipes_download_to_shell", "runs_substituted_download", "offscreen_code",
    "lex_comment_spans", "logical_text", "hooks_view", "signs_view",
    // 0.1.8: the exfiltration shapes, programs started at login or boot
    "chat_secret_at", "credential_sweep_at", "env_copy_serialized_at", "dns_beacon_at", "miner_at",
    "raw_ip_connect", "capture_service", "exfil_signs", "service_reasons",
    // 0.1.8: the dead drop
    "dead_drop_at",
    // Phase 2: scan_file, and what it reads
    "normalize", "scan_file", "file_context",
];

fn dead_drop(v: Option<(usize, PyStr)>) -> Value {
    match v {
        Some((at, host)) => Value::Arr(vec![Value::Int(at as i64), Value::Str(host)]),
        None => Value::Null,
    }
}

fn at_reason(v: Option<(usize, PyStr)>) -> Value {
    match v {
        Some((at, reason)) => Value::Arr(vec![Value::Int(at as i64), Value::Str(reason)]),
        None => Value::Null,
    }
}

fn sweep(v: Option<(usize, Vec<PyStr>)>) -> Value {
    match v {
        Some((at, names)) => Value::Arr(vec![Value::Int(at as i64), strs(&names)]),
        None => Value::Null,
    }
}

fn exfil(p: &Pack, text: &[u32]) -> Value {
    let host = p.re("_HOST_INFO_RE").search(text).map(|m| m.start());
    Value::Arr(signs::exfil_signs(p, text, host).into_iter().map(|s| at_reason(Some(s))).collect())
}

/// Run one call.
pub fn call(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    if name == "batch" {
        return batch(args);
    }
    let out = crate::budget::call(|| dispatch(name, args, text));
    match out {
        Ok(r) => r,
        Err(_) => Err(CallError::Exhausted),
    }
}

/// batch: {"calls": [[name, args, text], …], "threads": n} ->
/// [{"ok": value} | {"error": …, "exhausted": bool}]: many calls in one
/// crossing of the boundary, each with its own budget, answered in the
/// order asked. With `threads` above 1 the calls run on that many threads
/// (a thread takes the next call when it is done with one, so a long file
/// does not hold the others back); the answers are the same, only sooner.
/// A call that panics answers an error; the others are unaffected.
fn batch(args: &Value) -> Result<Value, CallError> {
    let calls = args.get("calls").and_then(|c| c.as_arr()).ok_or_else(|| CallError::BadArgs("calls".into()))?;
    let threads = args.get("threads").and_then(|t| t.as_i64()).unwrap_or(1).clamp(1, MAX_THREADS as i64) as usize;
    let threads = if cfg!(target_arch = "wasm32") { 1 } else { threads.min(calls.len()).max(1) };
    if threads > 1 {
        // what changes the engine for every call is not run alongside others
        for item in calls {
            let name = item.as_arr().and_then(|p| p.first()).and_then(|v| v.as_string()).unwrap_or_default();
            if name == "batch" || name.starts_with("pack.") {
                return Err(CallError::BadArgs(format!("{} in a batch on threads", name)));
            }
        }
    }
    if threads == 1 {
        return Ok(Value::Arr(calls.iter().map(batch_item).collect()));
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut out: Vec<Value> = vec![Value::Null; calls.len()];
    let done: Vec<Vec<(usize, Value)>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut mine = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= calls.len() {
                            break;
                        }
                        mine.push((i, batch_item(&calls[i])));
                    }
                    mine
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap_or_default()).collect()
    });
    for (i, v) in done.into_iter().flatten() {
        out[i] = v;
    }
    // (a worker that failed outright leaves Null: answered as an error)
    for v in out.iter_mut() {
        if matches!(v, Value::Null) {
            *v = Value::obj(vec![("error", Value::str("the call did not finish"))]);
        }
    }
    Ok(Value::Arr(out))
}

/// Threads a batch may ask for.
pub const MAX_THREADS: usize = 256;

fn batch_item(item: &Value) -> Value {
    let parts = item.as_arr().unwrap_or(&[]);
    let name = parts.first().and_then(|v| v.as_string()).unwrap_or_default();
    let empty = Value::Obj(Vec::new());
    let a = parts.get(1).unwrap_or(&empty);
    let text = parts.get(2).and_then(|v| v.as_str()).unwrap_or(&[]);
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call(&name, a, text)));
    match r {
        Ok(Ok(v)) => Value::obj(vec![("ok", v)]),
        Ok(Err(CallError::Exhausted)) => {
            Value::obj(vec![("error", Value::str("exhausted")), ("exhausted", Value::Bool(true))])
        }
        Ok(Err(CallError::Unknown(n))) => Value::obj(vec![("error", Value::str(&format!("unknown call {}", n)))]),
        Ok(Err(CallError::BadArgs(m))) => Value::obj(vec![("error", Value::str(&m))]),
        Err(_) => Value::obj(vec![("error", Value::str("panic")), ("panic", Value::Bool(true))]),
    }
}

fn strs(v: &[PyStr]) -> Value {
    Value::Arr(v.iter().map(|s| Value::Str(s.clone())).collect())
}

fn opt_s(v: Option<PyStr>) -> Value {
    v.map(Value::Str).unwrap_or(Value::Null)
}

fn arg_strs(args: &Value, name: &str) -> Vec<PyStr> {
    args.get(name).and_then(|v| v.as_arr()).unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect()
}

fn spans_value(sp: &[(usize, usize)]) -> Value {
    Value::Arr(sp.iter().map(|&(a, b)| Value::Arr(vec![Value::Int(a as i64), Value::Int(b as i64)])).collect())
}

fn dispatch(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    let pk = crate::pack::current();
    let p: &Pack = &pk;
    let lang_arg = opt_str(args, "lang").map(|l| crate::pystr::to_string(&l));
    let lang = lang_arg.as_deref();
    Ok(match name {
        "version" => Value::obj(vec![
            ("engine", Value::str("rust")),
            ("version", Value::str(crate::VERSION)),
            ("rule_set", p.rule_set.as_deref().map(Value::str).unwrap_or(Value::Null)),
            ("calls", Value::Arr(CALLS.iter().map(|c| Value::str(c)).collect())),
        ]),
        "pack.install" => {
            crate::pack::install(&crate::pystr::to_string(text)).map_err(CallError::BadArgs)?;
            Value::Bool(true)
        }
        "pack.reset" => {
            crate::pack::reset();
            Value::Bool(true)
        }
        "pack.info" => Value::obj(vec![
            ("rule_set", p.rule_set.as_deref().map(Value::str).unwrap_or(Value::Null)),
            ("values", Value::Int(p.names().len() as i64)),
        ]),
        "pyre.escape" => Value::Str(pyre::escape(text)),
        "scan_file" => {
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let opts = crate::scanfile::Options { dep: flag("dep", false), redact: flag("redact", true), neumaier: flag("neumaier", false) };
            if !opts.dep {
                return Err(CallError::BadArgs("project mode is not in the native engine yet".into()));
            }
            Value::Arr(crate::scanfile::scan_file(p, text, lang, flag("jsx", true), &opts))
        }
        "file_context" => {
            // the parity tests' view of a file's context: per line
            // [comment line?, comment spans, match text, match text without comments, names]
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            let ctx = crate::filectx::FileCtx::new(p, text, crate::filectx::Lang::from(lang), jsx);
            Value::Arr(
                (0..ctx.len())
                    .map(|i| {
                        Value::Arr(vec![
                            Value::Bool(ctx.cmask[i]),
                            spans_value(&ctx.cspans[i]),
                            Value::Str(ctx.mline(i).to_vec()),
                            Value::Str(ctx.mcode(i).to_vec()),
                            Value::Str(ctx.names_code(i)),
                        ])
                    })
                    .collect(),
            )
        }
        "normalize" => {
            let form = opt_str(args, "form").map(|f| crate::pystr::to_string(&f)).unwrap_or_default();
            Value::Str(match form.as_str() {
                "NFC" => crate::normalize::nfc(text),
                "NFD" => crate::normalize::nfd(text),
                "NFKC" => crate::normalize::nfkc(text),
                "NFKD" => crate::normalize::nfkd(text),
                _ => return Err(CallError::BadArgs(format!("unknown normalization form {:?}", form))),
            })
        }
        "pyre.probe" => probe(args, text)?,
        "shlex_split" => match hooks::shlex_split(text) {
            Some(t) => strs(&t),
            None => Value::Null,
        },
        "hook_tokens" => strs(&hooks::hook_tokens(p, text)),
        "follow_hook" => {
            let (targets, complete) = hooks::follow_hook(p, text);
            Value::Arr(vec![strs(&targets), Value::Bool(complete)])
        }
        "node_candidates" => strs(&hooks::node_candidates(text)),
        "node_e_codes" => strs(&hooks::node_e_codes(p, text)),
        "shebang_lang" => hooks::shebang_lang(p, text).map(Value::str).unwrap_or(Value::Null),
        "install_script_risk" => strs(&signs::install_script_risk(p, text)),
        "import_time_risk" => {
            let (reasons, line) = signs::import_time_risk(p, text, lang);
            Value::Arr(vec![strs(&reasons), line.map(|l| Value::Int(l as i64)).unwrap_or(Value::Null)])
        }
        "import_time_severity" => Value::str(signs::import_time_severity(p, &arg_strs(args, "reasons"))),
        "decoded_view" => Value::Str(signs::decoded_view(p, text)),
        "spawned_scripts" => Value::Arr(
            signs::spawned_scripts(p, text)
                .into_iter()
                .map(|(b, path)| Value::Arr(vec![Value::str(b), Value::Str(path)]))
                .collect(),
        ),
        "self_publish_at" => Value::Int(signs::self_publish_at(p, text) as i64),
        "runs_dll" => opt_s(signs::runs_dll(p, text)),
        "join_string_pieces" => Value::Str(signs::join_string_pieces(p, text)),
        "received_code_kind" => {
            match received::received_code_kind(p, text, &arg_strs(args, "extra_always"), &arg_strs(args, "extra_runners")) {
                Some((line, cat)) => Value::Arr(vec![Value::Int(line as i64), Value::str(cat)]),
                None => Value::Null,
            }
        }
        "runs_received_code" => match received::received_code_kind(p, text, &[], &[]) {
            Some((line, _)) => Value::Int(line as i64),
            None => Value::Null,
        },
        "downloads_and_runs" | "decodes_and_runs" => {
            let r = if name == "downloads_and_runs" {
                received::downloads_and_runs(p, text)
            } else {
                received::decodes_and_runs(p, text)
            };
            match r {
                Some((line, interp)) => Value::Arr(vec![Value::Int(line as i64), opt_s(interp)]),
                None => Value::Null,
            }
        }
        "powershell_risk" => strs(&signs::powershell_risk(p, text)),
        "stager_at" => Value::Int(signs::stager_at(p, text) as i64),
        "reverse_shell_at" => Value::Int(signs::reverse_shell_at(p, text) as i64),
        "sends_host_info" => Value::Bool(signs::sends_host_info(p, text)),
        "runs_own_source_at" => Value::Int(signs::runs_own_source_at(p, text) as i64),
        "reads_own_source" => Value::Bool(signs::reads_own_source(p, text)),
        "persistence_reasons" => strs(&signs::persistence_reasons(p, text)),
        "chat_secret_at" => at_reason(signs::chat_secret_at(p, text)),
        "credential_sweep_at" => sweep(signs::credential_sweep_at(p, text)),
        "env_copy_serialized_at" => Value::Int(signs::env_copy_serialized_at(p, text) as i64),
        "dns_beacon_at" => {
            let host = !matches!(args.get("host"), Some(Value::Bool(false)));
            Value::Int(signs::dns_beacon_at(p, text, host) as i64)
        }
        "dead_drop_at" => dead_drop(signs::dead_drop_at(p, text)),
        "miner_at" => Value::Int(signs::miner_at(p, text) as i64),
        "raw_ip_connect" => opt_s(signs::raw_ip_connect(p, text)),
        "capture_service" => opt_s(signs::capture_service(p, text).map(|m| m.group0().to_vec())),
        "exfil_signs" => exfil(p, text),
        "service_reasons" => strs(&signs::service_reasons(p, text)),
        "dumps_workflow_secrets" => Value::Bool(signs::dumps_workflow_secrets(p, text)),
        "pipes_download_to_shell" => Value::Bool(signs::pipes_download_to_shell(p, text)),
        "runs_substituted_download" => Value::Bool(signs::runs_substituted_download(p, text)),
        "offscreen_code" => match signs::offscreen_code(p, text, lang.unwrap_or("js")) {
            Some((col, blanks, hidden, runs)) => Value::Arr(vec![
                Value::Int(col as i64),
                Value::Int(blanks as i64),
                Value::Str(hidden),
                Value::Bool(runs),
            ]),
            None => Value::Null,
        },
        "lex_comment_spans" => {
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            let want_strings = matches!(args.get("strings"), Some(Value::Bool(true)));
            let want_literals = matches!(args.get("literals"), Some(Value::Bool(true)));
            let mut s = Vec::new();
            let mut l = Vec::new();
            let comments = lexer::lex_comment_spans(
                p,
                text,
                lang,
                if want_strings { Some(&mut s) } else { None },
                jsx,
                if want_literals { Some(&mut l) } else { None },
            );
            Value::obj(vec![("comments", spans_value(&comments)), ("strings", spans_value(&s)), ("literals", spans_value(&l))])
        }
        "hooks_view" => {
            // the parity tests' view of one case: core_view's fields, in order
            let itr = |lang: Option<&str>| {
                let (reasons, line) = signs::import_time_risk(p, text, lang);
                Value::Arr(vec![strs(&reasons), line.map(|l| Value::Int(l as i64)).unwrap_or(Value::Null)])
            };
            let (targets, complete) = hooks::follow_hook(p, text);
            Value::Arr(vec![
                match hooks::shlex_split(text) {
                    Some(t) => strs(&t),
                    None => Value::Null,
                },
                strs(&hooks::hook_tokens(p, text)),
                Value::Arr(vec![strs(&targets), Value::Bool(complete)]),
                strs(&signs::install_script_risk(p, text)),
                itr(None),
                strs(&hooks::node_candidates(text)),
                strs(&hooks::node_e_codes(p, text)),
                hooks::shebang_lang(p, text).map(Value::str).unwrap_or(Value::Null),
                itr(Some("py")),
                itr(Some("js")),
                Value::Int(signs::self_publish_at(p, text) as i64),
                opt_s(signs::runs_dll(p, text)),
                Value::Str(signs::join_string_pieces(p, text)),
                Value::Str(signs::decoded_view(p, text)),
                Value::Arr(
                    signs::spawned_scripts(p, text)
                        .into_iter()
                        .map(|(b, path)| Value::Arr(vec![Value::str(b), Value::Str(path)]))
                        .collect(),
                ),
            ])
        }
        "signs_view" => {
            // the parity tests' view of one case: signs_view's fields, in order
            let pair = |r: Option<(usize, Option<PyStr>)>| match r {
                Some((line, interp)) => Value::Arr(vec![Value::Int(line as i64), opt_s(interp)]),
                None => Value::Null,
            };
            let off = |lang: &str| match signs::offscreen_code(p, text, lang) {
                Some((col, blanks, hidden, runs)) => {
                    Value::Arr(vec![Value::Int(col as i64), Value::Int(blanks as i64), Value::Str(hidden), Value::Bool(runs)])
                }
                None => Value::Null,
            };
            Value::Arr(vec![
                match received::received_code_kind(p, text, &[], &[]) {
                    Some((line, cat)) => Value::Arr(vec![Value::Int(line as i64), Value::str(cat)]),
                    None => Value::Null,
                },
                pair(received::downloads_and_runs(p, text)),
                pair(received::decodes_and_runs(p, text)),
                strs(&signs::powershell_risk(p, text)),
                Value::Int(signs::stager_at(p, text) as i64),
                Value::Int(signs::reverse_shell_at(p, text) as i64),
                Value::Bool(signs::sends_host_info(p, text)),
                Value::Int(signs::runs_own_source_at(p, text) as i64),
                Value::Bool(signs::reads_own_source(p, text)),
                strs(&signs::persistence_reasons(p, text)),
                Value::Bool(signs::dumps_workflow_secrets(p, text)),
                Value::Bool(signs::pipes_download_to_shell(p, text)),
                Value::Bool(signs::runs_substituted_download(p, text)),
                off("js"),
                off("py"),
                at_reason(signs::chat_secret_at(p, text)),
                sweep(signs::credential_sweep_at(p, text)),
                Value::Int(signs::env_copy_serialized_at(p, text) as i64),
                Value::Int(signs::dns_beacon_at(p, text, true) as i64),
                Value::Int(signs::miner_at(p, text) as i64),
                opt_s(signs::raw_ip_connect(p, text)),
                opt_s(signs::capture_service(p, text).map(|m| m.group0().to_vec())),
                exfil(p, text),
                strs(&signs::service_reasons(p, text)),
                // 0.1.8: the DNS beacon without a read of the identity, the dead drop
                Value::Int(signs::dns_beacon_at(p, text, false) as i64),
                dead_drop(signs::dead_drop_at(p, text)),
            ])
        }
        "logical_text" => {
            let (alt, firsts) = received::logical(p, text, &arg_strs(args, "runners"));
            Value::Arr(vec![
                Value::Str(alt),
                firsts
                    .map(|f| Value::Arr(f.into_iter().map(|x| Value::Int(x as i64)).collect()))
                    .unwrap_or(Value::Null),
            ])
        }
        _ => return Err(CallError::Unknown(name.to_string())),
    })
}

fn match_value(m: &pyre::Match) -> Value {
    let mut groups = Vec::new();
    for g in 1..=m.regex().groups {
        groups.push(Value::Int(m.start_of(g) as i64));
        groups.push(Value::Int(m.end_of(g) as i64));
    }
    Value::Arr(vec![
        Value::Int(m.start() as i64),
        Value::Int(m.end() as i64),
        Value::Int(m.lastindex as i64),
        Value::Arr(groups),
    ])
}

fn opt_match(m: Option<pyre::Match>) -> Value {
    m.map(|m| match_value(&m)).unwrap_or(Value::Null)
}

/// pyre.probe: every entry point of a pattern on each text of `texts` (or
/// on the text), for the differential tests against Python's `re`:
/// search / match / fullmatch at pos..endpos, finditer, findall, sub with a
/// function and with a template, split.
fn probe(args: &Value, text: &[u32]) -> Result<Value, CallError> {
    let pattern = arg_str(args, "pattern")?;
    let flags = opt_str(args, "flags").map(|f| pyre::flags_from_letters(&crate::pystr::to_string(&f))).unwrap_or(0);
    let rx = match Regex::new(&pattern, flags) {
        Ok(rx) => rx,
        Err(e) => return Ok(Value::obj(vec![("error", Value::str(&e.0))])),
    };
    let texts: Vec<Vec<u32>> = match args.get("texts").and_then(|t| t.as_arr()) {
        Some(items) => items.iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect(),
        None => vec![text.to_vec()],
    };
    let pos = opt_int(args, "pos").unwrap_or(0) as isize;
    let template = opt_str(args, "template");
    let mut out = Vec::new();
    for t in &texts {
        let endpos = opt_int(args, "endpos").map(|e| e as isize).unwrap_or(t.len() as isize);
        let mut r = vec![
            ("search", opt_match(rx.search_at(t, pos, endpos))),
            ("match", opt_match(rx.match_at(t, pos, endpos))),
            ("fullmatch", opt_match(rx.fullmatch_at(t, pos, endpos))),
            ("finditer", Value::Arr(rx.finditer_at(t, pos, endpos).take(10_000).map(|m| match_value(&m)).collect())),
            (
                "sub",
                Value::Str(rx.sub_fn(t, 0, |m| {
                    let mut v = u("<");
                    v.extend_from_slice(m.group0());
                    v.push(b'>' as u32);
                    v
                })),
            ),
            (
                "split",
                Value::Arr(
                    rx.split(t, 0)
                        .into_iter()
                        .map(|p| p.map(|s| Value::Str(s.to_vec())).unwrap_or(Value::Null))
                        .collect(),
                ),
            ),
        ];
        if let Some(tpl) = &template {
            r.push(("template", Value::Str(rx.sub(t, tpl, 0))));
        }
        out.push(Value::obj(r));
    }
    Ok(Value::obj(vec![("groups", Value::Int(rx.groups as i64)), ("results", Value::Arr(out))]))
}
