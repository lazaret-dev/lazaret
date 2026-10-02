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
    "local_data_sent_at", "runs_own_source_at", "reads_own_source", "persistence_reasons",
    "dumps_workflow_secrets", "pipes_download_to_shell", "runs_substituted_download", "offscreen_code",
    "lex_comment_spans", "logical_text", "hooks_view", "signs_view",
    // 0.1.8: the exfiltration shapes, programs started at login or boot
    "secret_endpoint_at", "credential_sweep_at", "exec_command_reasons", "dns_beacon_at", "miner_at",
    "raw_ip_connect", "capture_service", "exfil_signs", "service_reasons", "wallet_swap_at", "string_array_line",
    // 0.1.8: a shell text read as a program, and the command lines a script hands a shell
    "sh_reasons", "shell_text", "code_text", "sh_literal_value", "sh_parse",
    // 0.1.8: the dead drop
    "dead_drop_at",
    // Phase 2: scan_file, and what it reads
    "normalize", "scan_file", "file_context",
    // 0.1.8: what the npm package asks (it runs this engine as WebAssembly)
    "pack.values", "agent_hijack", "agent_hijack_in_command", "hook_command_risk", "hook_is_suspicious",
    "import_code", "scan_rules", "hook_command_view", "hex_view", "lookalike_view",
    // 0.1.8: the cross-file follower, each package on its own budget
    "cross_file",
    // the JavaScript parser (jsparse.py's trees)
    "js_parse", "js_parse_file",
    // the Python parser (Python 3.13's ast trees)
    "py_parse",
    // linre, the linear-time regex engine (not yet what the engine's patterns run on)
    "linre.probe", "linre.check",
];

fn dead_drop(v: Option<(usize, PyStr)>) -> Value {
    match v {
        Some((at, host)) => Value::Arr(vec![Value::Int(at as i64), Value::Str(host)]),
        None => Value::Null,
    }
}

fn agent_hijack(v: Option<(PyStr, PyStr, usize)>) -> Value {
    match v {
        Some((agent, flag, line)) => Value::Arr(vec![Value::Str(agent), Value::Str(flag), Value::Int(line as i64)]),
        None => Value::Null,
    }
}

fn agent_in_command(v: Option<(PyStr, PyStr)>) -> Value {
    match v {
        Some((agent, flag)) => Value::Arr(vec![Value::Str(agent), Value::Str(flag)]),
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

fn flow(v: Option<(usize, &'static str, PyStr, bool)>) -> Value {
    match v {
        Some((at, kind, what, in_address)) => {
            Value::Arr(vec![Value::Int(at as i64), Value::str(kind), Value::Str(what), Value::Bool(in_address)])
        }
        None => Value::Null,
    }
}

fn sh_reasons(p: &Pack, text: &[u32]) -> Value {
    let mut walk = crate::shell::HookWalk::new();
    strs(&crate::shell::sh_reasons(p, text, 0, false, &mut walk))
}

fn exfil(p: &Pack, text: &[u32]) -> Value {
    let host = p.re("_HOST_INFO_RE").search(text).map(|m| m.start());
    Value::Arr(signs::exfil_signs(p, text, host).into_iter().map(|s| at_reason(Some(s))).collect())
}

/// The calls whose text gets a text gate (textgate.rs).
const GATED: &[&str] = &[
    "import_time_risk", "install_script_risk", "spawned_scripts", "decoded_view", "string_array_line", "received_code_kind",
    "runs_received_code", "downloads_and_runs", "decodes_and_runs", "local_data_sent_at", "exfil_signs",
    "secret_endpoint_at", "credential_sweep_at", "persistence_reasons", "service_reasons", "exec_command_reasons",
    "dead_drop_at", "signs_view", "hooks_view", "follow_hook", "hook_command_risk", "hook_command_view",
];

/// Run one call. `budget` in the arguments: the steps of the regex matcher
/// it may take (crate::budget; the default otherwise).
pub fn call(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    if name == "batch" {
        return batch(args);
    }
    let steps = match args.get("budget").and_then(|b| b.as_i64()) {
        Some(b) if b > 0 => b as u64,
        _ => crate::budget::DEFAULT_STEPS,
    };
    // (the text's pairs, read once: its searches ask them, textgate.rs; for
    // the calls that run many searches over the whole text: reading the
    // pairs costs a pass over it)
    let _gate = if GATED.contains(&name) { crate::textgate::open(text) } else { None };
    let out = crate::budget::call_with(steps, || dispatch(name, args, text));
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
        "pack.values" => {
            // core's values by name, as the pack holds them (null for a name it lacks)
            let names = arg_strs(args, "names");
            Value::Obj(
                names
                    .iter()
                    .map(|n| (n.clone(), p.raw(&crate::pystr::to_string(n)).cloned().unwrap_or(Value::Null)))
                    .collect(),
            )
        }
        "pyre.escape" => Value::Str(pyre::escape(text)),
        "cross_file" => cross_file(p, args, text)?,
        "js_parse" | "js_parse_file" => {
            // jsparse.parse(text, ts, jsx) / jsparse.parse_file(path, text): the
            // tree as JSON, or {"error": {"line": n, "reason": …}}; "spans": each
            // node's start and end (code points) too
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let (ts, jsx) = if name == "js_parse_file" {
                crate::jsparse::dialect(&arg_str(args, "path")?)
            } else {
                (flag("ts", false), flag("jsx", true))
            };
            Value::Raw(crate::jsparse::to_json(text, ts, jsx, flag("spans", false)))
        }
        "py_parse" => {
            // ast.parse(text) as Python 3.13 builds it, as JSON (pyparse/out.rs),
            // or {"error": {"line": n, "reason": …}}; "spans": each node's start
            // and end (code points) too
            let spans = matches!(args.get("spans"), Some(Value::Bool(true)));
            Value::Raw(crate::pyparse::to_json(text, spans))
        }
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
        "scan_rules" => {
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            Value::Arr(crate::scanfile::scan_rules(p, text, lang, flag("jsx", true), flag("redact", true), flag("neumaier", false)))
        }
        "hex_view" => {
            // the parity tests' view of a line's escapes: the name they hide and its column, the text they hide
            let name = crate::scanfile::hex_hidden_name(p, text)
                .map(|(n, col)| Value::Arr(vec![Value::Str(n), Value::Int(col as i64)]))
                .unwrap_or(Value::Null);
            Value::Arr(vec![name, opt_s(crate::scanfile::hex_hidden_text(p, text))])
        }
        "lookalike_view" => {
            let words = arg_strs(args, "words");
            match crate::scanfile::lookalike_view(p, text, crate::filectx::Lang::from(lang), &words) {
                Some((name, skeleton, sev, other, detail, col)) => Value::Arr(vec![
                    Value::Str(name),
                    Value::Str(skeleton),
                    Value::str(sev),
                    Value::Bool(other),
                    Value::Str(detail),
                    Value::Int(col as i64),
                ]),
                None => Value::Null,
            }
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
        "linre.probe" => linre_probe(args, text)?,
        "linre.check" => linre_check(p, args),
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
        "install_script_risk" => {
            let shell = !matches!(args.get("shell"), Some(Value::Bool(false)));
            let command = matches!(args.get("command"), Some(Value::Bool(true)));
            strs(&signs::install_script_risk_with(p, text, shell, command))
        }
        "import_time_risk" => {
            let (reasons, line) = signs::import_time_risk(p, text, lang);
            Value::Arr(vec![strs(&reasons), line.map(|l| Value::Int(l as i64)).unwrap_or(Value::Null)])
        }
        "import_time_severity" => Value::str(signs::import_time_severity(p, &arg_strs(args, "reasons"))),
        "decoded_view" => Value::Str(signs::decoded_view(p, text)),
        "string_array_line" => signs::string_array_line(p, text).map(|n| Value::Int(n as i64)).unwrap_or(Value::Null),
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
        "local_data_sent_at" => flow(crate::flow::local_data_sent_at(p, text)),
        "runs_own_source_at" => Value::Int(signs::runs_own_source_at(p, text) as i64),
        "reads_own_source" => Value::Bool(signs::reads_own_source(p, text)),
        "persistence_reasons" => strs(&signs::persistence_reasons(p, text)),
        "secret_endpoint_at" => at_reason(crate::flow::secret_endpoint_at(p, text)),
        "credential_sweep_at" => sweep(signs::credential_sweep_at(p, text)),
        "exec_command_reasons" => strs(&crate::shell::exec_command_reasons(p, text)),
        "sh_reasons" => sh_reasons(p, text),
        "sh_parse" => {
            // the simple commands of a shell text: [words, substitutions, redirections, piped in,
            // piped out, what follows, [the program's word or null, the program, negated]]
            Value::Arr(
                crate::shell::sh_parse(p, text)
                    .iter()
                    .map(|c| {
                        let (at, program, negated) = crate::shell::sh_program(p, c);
                        Value::Arr(vec![
                            strs(&c.words),
                            Value::Arr(c.subs.iter().map(|s| strs(s)).collect()),
                            Value::Arr(c.redirs.iter().map(|(a, b)| strs(&[a.clone(), b.clone()])).collect()),
                            Value::Bool(c.pipe_in),
                            Value::Bool(c.pipe_out),
                            Value::str(c.after),
                            Value::Arr(vec![
                                at.map(|i| Value::Int(i as i64)).unwrap_or(Value::Null),
                                Value::Str(program),
                                Value::Bool(negated),
                            ]),
                        ])
                    })
                    .collect(),
            )
        }
        "shell_text" => Value::Bool(crate::shell::shell_text(p, text)),
        "code_text" => Value::Bool(crate::shell::code_text(p, text)),
        "sh_literal_value" => {
            let at = opt_int(args, "at").unwrap_or(0).max(0) as usize;
            opt_s(crate::shell::sh_literal_value(p, text, at))
        }
        "dns_beacon_at" => {
            let host = !matches!(args.get("host"), Some(Value::Bool(false)));
            Value::Int(signs::dns_beacon_at(p, text, host) as i64)
        }
        "dead_drop_at" => dead_drop(signs::dead_drop_at(p, text)),
        "agent_hijack" => agent_hijack(signs::agent_hijack(p, text)),
        "agent_hijack_in_command" => agent_in_command(signs::agent_hijack_in_command(p, text)),
        "hook_command_risk" => {
            let kept = matches!(args.get("output_kept"), Some(Value::Bool(true)));
            strs(&crate::shell::hook_command_risk(p, text, kept))
        }
        "hook_is_suspicious" => Value::Bool(hooks::hook_is_suspicious(p, text)),
        "hook_command_view" => {
            // the parity tests' view of a hook command: its reasons (output
            // thrown away, then kept), its simple commands, its inline code
            let commands = crate::shell::sh_parse(p, text)
                .into_iter()
                .map(|c| {
                    Value::Arr(vec![
                        strs(&c.words),
                        Value::Arr(c.subs.iter().map(|s| strs(s)).collect()),
                        Value::Arr(c.redirs.iter().map(|(a, b)| strs(&[a.clone(), b.clone()])).collect()),
                        Value::Bool(c.pipe_in),
                        Value::Bool(c.pipe_out),
                        Value::str(c.after),
                    ])
                })
                .collect();
            let mut walk = crate::shell::HookWalk::new();
            Value::Arr(vec![
                strs(&crate::shell::hook_command_risk(p, text, false)),
                strs(&crate::shell::hook_command_risk(p, text, true)),
                Value::Arr(commands),
                strs(&crate::shell::hook_inline_code(p, text, &mut walk, 0)),
            ])
        }
        "import_code" => match lang {
            Some(l @ ("py" | "js")) => Value::Str(signs::import_code(p, text, l)),
            _ => return Err(CallError::BadArgs("import_code needs lang 'py' or 'js'".into())),
        },
        "miner_at" => Value::Int(signs::miner_at(p, text) as i64),
        "wallet_swap_at" => at_reason(signs::wallet_swap_at(p, text)),
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
                flow(crate::flow::local_data_sent_at(p, text)),
                Value::Int(signs::runs_own_source_at(p, text) as i64),
                Value::Bool(signs::reads_own_source(p, text)),
                strs(&signs::persistence_reasons(p, text)),
                Value::Bool(signs::dumps_workflow_secrets(p, text)),
                Value::Bool(signs::pipes_download_to_shell(p, text)),
                Value::Bool(signs::runs_substituted_download(p, text)),
                off("js"),
                off("py"),
                at_reason(crate::flow::secret_endpoint_at(p, text)),
                sweep(signs::credential_sweep_at(p, text)),
                strs(&crate::shell::exec_command_reasons(p, text)),
                Value::Int(signs::dns_beacon_at(p, text, true) as i64),
                Value::Int(signs::miner_at(p, text) as i64),
                opt_s(signs::raw_ip_connect(p, text)),
                opt_s(signs::capture_service(p, text).map(|m| m.group0().to_vec())),
                exfil(p, text),
                strs(&signs::service_reasons(p, text)),
                // 0.1.8: the DNS beacon without a read of the identity, the dead drop
                Value::Int(signs::dns_beacon_at(p, text, false) as i64),
                dead_drop(signs::dead_drop_at(p, text)),
                // 0.1.8: the text read as a shell program
                sh_reasons(p, text),
                Value::Bool(crate::shell::shell_text(p, text)),
                Value::Bool(crate::shell::code_text(p, text)),
                // 0.1.8: what the npm package asks besides
                agent_hijack(signs::agent_hijack(p, text)),
                agent_in_command(signs::agent_hijack_in_command(p, text)),
                Value::Bool(hooks::hook_is_suspicious(p, text)),
                Value::Str(signs::import_code(p, text, "js")),
                Value::Str(signs::import_code(p, text, "py")),
                // the detection round: wallet addresses swapped; code built around a string array
                at_reason(signs::wallet_swap_at(p, text)),
                signs::string_array_line(p, text).map(|n| Value::Int(n as i64)).unwrap_or(Value::Null),
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

/// cross_file: {"files": [[path, lang, length], …], "skip": […], "who": …,
/// "whos": [one per file] | null, "one_package", "sep", "redact", "neumaier",
/// "threads"} and the files' texts one after another (each `length` code
/// points) -> core._cross_file_received_issues per package
/// (crossfile::answer). Each package gets the call's budget.
fn cross_file(p: &Pack, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::crossfile::{self, File, Options};
    let bad = |m: &str| CallError::BadArgs(format!("cross_file: {}", m));
    let items = args.get("files").and_then(|f| f.as_arr()).ok_or_else(|| bad("files"))?;
    let who = opt_str(args, "who").unwrap_or_else(|| u("Dependency code"));
    let whos = args.get("whos").and_then(|w| w.as_arr());
    let groups = args.get("groups").and_then(|g| g.as_arr());
    let mut files = Vec::with_capacity(items.len());
    let mut at = 0usize;
    for (k, item) in items.iter().enumerate() {
        let parts = item.as_arr().ok_or_else(|| bad("a file is not [path, lang, length]"))?;
        let path = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a file's path"))?.to_vec();
        let lang = parts.get(1).and_then(|v| v.as_str()).ok_or_else(|| bad("a file's lang"))?.to_vec();
        let len = parts.get(2).and_then(|v| v.as_i64()).filter(|&n| n >= 0).ok_or_else(|| bad("a file's length"))? as usize;
        if at + len > text.len() {
            return Err(bad("the files' lengths run past the text"));
        }
        let who = whos.and_then(|w| w.get(k)).and_then(|v| v.as_str()).map(|s| s.to_vec()).unwrap_or_else(|| who.clone());
        let group = groups.and_then(|g| g.get(k)).and_then(|v| v.as_str()).map(|s| s.to_vec());
        files.push(File { path, lang, text: &text[at..at + len], who, group });
        at += len;
    }
    if at != text.len() {
        return Err(bad("the files' lengths do not add up to the text"));
    }
    let flag = |k: &str, d: bool| match args.get(k) {
        Some(Value::Bool(b)) => *b,
        _ => d,
    };
    let opts = Options {
        one_package: flag("one_package", false),
        sep: opt_str(args, "sep").unwrap_or_else(|| u("/")),
        redact: flag("redact", true),
        neumaier: flag("neumaier", false),
        threads: opt_int(args, "threads").unwrap_or(1).clamp(1, MAX_THREADS as i64) as usize,
        steps: match opt_int(args, "budget") {
            Some(b) if b > 0 => b as u64,
            _ => crate::budget::DEFAULT_STEPS,
        },
    };
    let skip: std::collections::HashSet<PyStr> = arg_strs(args, "skip").into_iter().collect();
    Ok(crossfile::answer(crossfile::cross_file(p, &files, &skip, &opts)))
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
    let gated = matches!(args.get("gate"), Some(Value::Bool(true)));
    let mut out = Vec::new();
    for t in &texts {
        // ("gate": each text's searches ask a text gate, textgate.rs)
        let _gate = if gated { crate::textgate::open(t) } else { None };
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

fn linre_match_value(m: &crate::linre::Match) -> Value {
    let mut groups = Vec::new();
    for g in 1..=m.regex().groups() {
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

fn linre_opt(m: Option<crate::linre::Match>) -> Value {
    m.map(|m| linre_match_value(&m)).unwrap_or(Value::Null)
}

/// linre.probe: pyre.probe's answers from linre (search / match / fullmatch
/// at pos..endpos, finditer, sub with a function, split), for the
/// differential tests against Python's `re`; {"error": …, "refused": bool}
/// for a pattern linre does not compile.
fn linre_probe(args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::linre::{self, Regex as Linre};
    let pattern = arg_str(args, "pattern")?;
    let flags = opt_str(args, "flags").map(|f| linre::flags_from_letters(&crate::pystr::to_string(&f))).unwrap_or(0);
    let rx = match Linre::new(&pattern, flags) {
        Ok(rx) => rx,
        Err(e) => return Ok(Value::obj(vec![("error", Value::str(&e.msg)), ("refused", Value::Bool(e.refused))])),
    };
    let texts: Vec<Vec<u32>> = match args.get("texts").and_then(|t| t.as_arr()) {
        Some(items) => items.iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect(),
        None => vec![text.to_vec()],
    };
    let pos = opt_int(args, "pos").unwrap_or(0) as isize;
    let gated = matches!(args.get("gate"), Some(Value::Bool(true)));
    let mut out = Vec::new();
    for t in &texts {
        let _gate = if gated { crate::textgate::open(t) } else { None };
        let endpos = opt_int(args, "endpos").map(|e| e as isize).unwrap_or(t.len() as isize);
        let r = vec![
            ("search", linre_opt(rx.search_at(t, pos, endpos))),
            ("match", linre_opt(rx.match_at(t, pos, endpos))),
            ("fullmatch", linre_opt(rx.fullmatch_at(t, pos, endpos))),
            ("finditer", Value::Arr(rx.finditer_at(t, pos, endpos).take(10_000).map(|m| linre_match_value(&m)).collect())),
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
                Value::Arr(rx.split(t, 0).into_iter().map(|p| p.map(|s| Value::Str(s.to_vec())).unwrap_or(Value::Null)).collect()),
            ),
        ];
        out.push(Value::obj(r));
    }
    Ok(Value::obj(vec![("groups", Value::Int(rx.groups() as i64)), ("results", Value::Arr(out))]))
}

/// One pattern of the pack by the name the parity tests give it: a value's
/// name, then `[i]` into a list and `['key']` into a map
/// (`TAINT_SINKS['js'][3][1]`). Answers its {"re", "flags"} value.
fn pack_pattern<'v>(p: &'v Pack, name: &str) -> Option<&'v Value> {
    let base_end = name.find('[').unwrap_or(name.len());
    let mut v = p.raw(&name[..base_end])?;
    let mut rest = &name[base_end..];
    while !rest.is_empty() {
        let close = if rest.starts_with("['") || rest.starts_with("[\"") {
            let q = &rest[1..2];
            let inner_end = rest[2..].find(q)? + 2;
            let key = &rest[2..inner_end];
            v = v.get("map")?.get(key)?;
            inner_end + 1
        } else {
            let end = rest.find(']')?;
            let i: usize = rest.get(1..end)?.parse().ok()?;
            v = v.get("list")?.as_arr()?.get(i)?;
            end
        };
        if rest.as_bytes().get(close) != Some(&b']') {
            return None;
        }
        rest = &rest[close + 1..];
    }
    Some(v)
}

/// Every pattern of the pack, named as the parity tests name them (values in
/// name order, lists by index, maps in their order).
pub fn pack_pattern_names(p: &Pack) -> Vec<String> {
    fn walk(name: String, v: &Value, out: &mut Vec<String>) {
        if v.get("re").is_some() {
            out.push(name);
        } else if let Some(items) = v.get("list").and_then(|l| l.as_arr()) {
            for (i, x) in items.iter().enumerate() {
                walk(format!("{}[{}]", name, i), x, out);
            }
        } else if let Some(m) = v.get("map").and_then(|m| m.as_obj()) {
            for (k, x) in m {
                let key = crate::pystr::to_string(k);
                let q = if key.contains('\'') && !key.contains('"') { '"' } else { '\'' };
                walk(format!("{}[{}{}{}]", name, q, key, q), x, out);
            }
        }
    }
    let mut out = Vec::new();
    for n in p.names() {
        if let Some(v) = p.raw(n) {
            walk(n.to_string(), v, &mut out);
        }
    }
    out
}

/// linre.check: {"names": [pack names]} (all of the pack's patterns when
/// absent) -> [{"name", "accepted", "reason"?, "error"?, "insts"?}]: what
/// linre makes of each pattern, and why it refuses one.
fn linre_check(p: &Pack, args: &Value) -> Value {
    let names: Vec<String> = match args.get("names").and_then(|n| n.as_arr()) {
        Some(items) => items.iter().filter_map(|v| v.as_string()).collect(),
        None => pack_pattern_names(p),
    };
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let mut r = vec![("name", Value::str(&name))];
        match pack_pattern(p, &name) {
            None => {
                r.push(("accepted", Value::Bool(false)));
                r.push(("reason", Value::str("no such pattern in the pack")));
            }
            Some(v) => {
                let src = v.get("re").and_then(|s| s.as_str()).map(|s| s.to_vec()).unwrap_or_default();
                let flags = v.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
                r.push(("flags", Value::str(&flags)));
                match crate::linre::Regex::new(&src, crate::linre::flags_from_letters(&flags)) {
                    Ok(rx) => {
                        let info = rx.info();
                        let opt = |s: Option<String>| s.map(|s| Value::str(&s)).unwrap_or(Value::Null);
                        r.push(("accepted", Value::Bool(true)));
                        r.push(("insts", Value::Int(info.insts as i64)));
                        r.push(("lookarounds", Value::Int(info.lookarounds as i64)));
                        r.push(("need", opt(info.need)));
                        r.push(("lead", opt(info.lead)));
                        r.push(("first", Value::Bool(info.first)));
                        r.push(("simple", Value::Bool(info.simple)));
                    }
                    Err(e) => {
                        r.push(("accepted", Value::Bool(false)));
                        r.push(("reason", Value::str(&e.msg)));
                        if !e.refused {
                            r.push(("error", Value::Bool(true)));
                        }
                    }
                }
            }
        }
        out.push(Value::obj(r));
    }
    Value::Arr(out)
}
