//! The engine's calls, by name: what the bindings expose.
//!
//! A call is a name, its arguments (a JSON object) and, for the functions
//! that read one, the text (a Python str, passed apart from the arguments so
//! that a large file is not escaped into JSON). It answers with a JSON value,
//! or an error: an unknown call or bad arguments (a bug in the binding), or
//! the work budget spent (the call has no answer, and the bindings make the
//! file SC-TRUNCATED: see crate::budget).

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
    "shlex_split", "hook_tokens", "follow_hook", "node_candidates", "node_e_codes", "shebang_lang", "script_lang",
    // a hook that runs files of the package alone (NEW-HOOK-FP)
    "hook_runs_only_files",
    "install_script_risk", "install_script_severity", "import_time_risk", "import_time_severity", "decoded_view", "spawned_scripts",
    "self_publish_at", "runs_dll", "join_string_pieces", "received_code_kind", "runs_received_code",
    "downloads_and_runs", "decodes_and_runs", "powershell_risk", "stager_at", "reverse_shell_at",
    "local_data_sent_at", "runs_own_source_at", "reads_own_source", "persistence_reasons",
    // a .pth file's import lines (SC-PTH-EXEC)
    "pth_line_risk",
    // phase 3 step 3: the data flow and received code on the JavaScript and Python trees (the
    // supply-chain models; {"lang": "py"} asks Python's)
    "local_data_sent_tree", "received_code_tree", "decoded_runs_tree", "dropped_run_tree",
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
    // 0.1.9 (FP-B64-PROTOBUF): a scan's SC-B64 findings that are protobuf descriptors used as generated code uses them
    "b64_descriptors",
    // 0.1.8: what the npm package asks (it runs this engine as WebAssembly)
    "pack.values", "agent_hijack", "agent_hijack_in_command", "hook_command_risk", "hook_is_suspicious",
    "import_code", "scan_rules", "hook_command_view", "hex_view", "lookalike_view",
    // 0.1.8: the cross-file follower, each package on its own budget
    "cross_file",
    // 0.1.9 (R-1): a crate's code read for what it does when it is built, starts or is used
    "rs_crate",
    // 0.1.9 (G-1): a Go module's code read for what its init code and the rest do
    "go_package",
    // 0.1.9 (Part C): what a vendored crate's Cargo.toml and a vendor/modules.txt say (vendor.rs), for --deps
    "cargo_layout", "go_vendored_modules", "go_imports",
    // 0.1.9 (BR-7 step 1): CI files read for what they run — GitHub Actions workflows and GitLab CI files
    "ci_kind", "ci_outline", "ci_workflow", "ci_gitlab", "ci_rule", "ci_issues", "ci_uses", "ci_parse_uses", "ci_check",
    "ci_logical_lines",
    // 0.1.9 (BR-7 step 2): editor and AI-agent settings that run commands (autorun.rs; SC-AUTORUN)
    "autorun_kind", "autorun_owner", "autorun_jsonc", "autorun_entries", "autorun_local_command", "autorun_issues",
    "agentdoc_kind", "agentdoc_issues",
    // 0.1.9 (BR-7 step 3): a config or data file's scan (config.rs: S-TOKEN, S-SECRET, SC-AUTORUN, the CI checks)
    "scan_config", "config_check",
    // 0.1.9 (BR-7 step 3 b): manifests (manifest/: package.json's install hooks and dependencies, binding.gyp's
    // actions and expansions; json.loads and ast.literal_eval as Python reads them)
    "scan_manifest", "scan_gyp", "manifest_data", "manifest_check",
    // 0.1.9 (BR-7 step 3 c): the one redactor, for the findings the packages build (redact.rs)
    "issue_make", "redact_text", "redact_issues", "redact_file", "clip_line", "pem_lines",
    // BR-7 step 3 d: binaries, bytecode and .pth files (a file's bytes as latin-1 text; one too large to read whole in
    // chunks, pth_stream, its lines site.py runs checked by pth_kept)
    "binary_check", "binary_classify", "binary_disguised", "pyc_issues", "pth_issues",
    // 0.1.9 (FP-MODEL-FILES): a model file's pickles read for what they would run (pickle/), and the globals of the
    // package's own modules the scan's model files import
    "model_sniff", "model_file", "model_own", "pth_stream", "pth_kept",
    // 0.1.9 (FP-OPAQUE-MEDIA): a sound, video, image or font file walked by its structure to its end (media/), whole or
    // as its stream passes
    "media_walk", "media_stream",
    // BR-7 step 3 e: --deps' decisions (deps.rs; the packages answer what the calls ask of the tree)
    "deps_hooks", "deps_script", "deps_targets", "deps_files", "dep_file_issues", "declared_names",
    "agent_issue",
    // the JavaScript parser (jsparse.py's trees)
    "js_parse", "js_parse_file",
    // the Python parser (Python 3.13's ast trees)
    "py_parse",
    // linre, the linear-time regex engine the patterns run on
    "linre.probe", "linre.check", "linre.refused",
    // the lexers (lex/): a text read once into its language's tokens
    "lex.tokens", "lex.structure",
    // phase 3: project mode's cross-file JavaScript taint (jsflow/)
    "js_flow",
    // phase 3: project mode's cross-file Python taint (pyflow/)
    "py_flow",
    // 0.1.9 (FE-1): texts handed over once and named by id after (texts.rs)
    "texts.put", "texts.drop", "texts.info",
    // 0.1.9 (Q-1): project mode's passes one at a time (scan_file with dep false runs them all)
    "taint_scan", "functions",
    // 0.1.9 (Q-4): what each of a project's Python files imports from the others that the taint pass follows
    "taint_helpers",
    // 0.1.9 (Q-1 step 4): a project file's line metrics: comment lines, lines of code, the duplication windows
    "file_metrics",
    // 0.1.9 (V-1 stage 2): live secret verification's table and logic (secrets.rs); each package makes the call
    "secrets.providers", "secrets.identify", "secrets.request", "secrets.judge", "secrets.find",
    // 0.1.9 (D-13): what a JavaScript module loads when it runs (jsloads.rs)
    "js_loads",
    // 0.1.9 (JS-PARSE-STRICT): the parser's refusal of a text the supply-chain model reads on its tree
    "js_refusal",
    // 0.1.9 (BR-7 step 4 a): a scan's result, graded again, and a project's metrics (result.rs)
    "result", "regrade", "project_metrics",
    // 0.1.9 (BR-7 step 4 b): a source file's bytes decoded as its interpreter reads them, and bytes in a codec
    // Python has (decode/)
    "decode_source", "encoding_issues", "decode",
    // 0.1.9 (BR-7 step 4 c): the reports' forms, each a frame and its findings in batches, and the terminal's
    // sanitizers (report.rs)
    "term", "issue_excerpt", "report_json", "report_items", "sarif_rules", "sarif_frame", "sarif_items", "html_frame",
    "html_items", "text_frame", "text_order", "text_items",
    // 0.1.9 (BR-7 step 4 d): baselines (baseline.rs): findings' fingerprints, the signature, a baseline applied
    "baseline_fingerprints", "baseline_sign", "baseline_apply",
    // 0.1.9 (BR-7 step 4 e): a project scan's collection (collect.rs): a folder's entries, a file, a __pycache__, the
    // coverage notes of what the packages' I/O finds
    "collect_dir", "collect_file", "collect_pycache", "collect_issue", "collect_check",
    // and the registry's test code (collect.rs): which members are tests, fixtures or code a package does not run
    // when it is used, and which findings in them are listed only
    "test_paths", "demote_tests",
    // 0.1.9 (BR-7 step 4 f): the commit-time gate (gate.rs): its lines and exit, what it does with each file the
    // commit holds, why one could not be read
    "gate_report", "gate_source", "gate_why",
];

fn arr_arg<'a>(args: &'a Value, name: &str) -> &'a [Value] {
    args.get(name).and_then(|v| v.as_arr()).unwrap_or(&[])
}

fn count_arg(args: &Value, name: &str) -> Result<usize, CallError> {
    match args.get(name) {
        Some(Value::Int(n)) if *n >= 0 => Ok(*n as usize),
        _ => Err(CallError::BadArgs(format!("{name}: a count"))),
    }
}

/// A folder's entries as the packages list them: [[name, what, extra…]]: "file" and its size, "dir" with its
/// identity (or null) and whether the walk has seen it, "link" and its target, "special" and its kind, "error" and
/// why it could not be read.
fn entries_arg(args: &Value) -> Result<Vec<(PyStr, crate::collect::Entry)>, CallError> {
    use crate::collect::Entry;
    arr_arg(args, "entries").iter().enumerate().map(|(k, e)| {
        let bad = || CallError::BadArgs(format!("entries[{k}] is not [name, what, …]"));
        let a = e.as_arr().ok_or_else(bad)?;
        let name = a.first().and_then(|v| v.as_str()).ok_or_else(bad)?.to_vec();
        let what = a.get(1).and_then(|v| v.as_str()).map(crate::pystr::to_string).ok_or_else(bad)?;
        let text = |j: usize| a.get(j).and_then(|v| v.as_str()).map(|s| s.to_vec()).unwrap_or_default();
        let entry = match what.as_str() {
            "file" => Entry::File(a.get(2).and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64),
            "dir" => Entry::Dir(a.get(2).and_then(|v| v.as_str()).map(|s| s.to_vec()), matches!(a.get(3), Some(Value::Bool(true)))),
            "link" => Entry::Link(text(2)),
            "special" => Entry::Special(text(2)),
            "error" => Entry::Error(text(2)),
            _ => return Err(bad()),
        };
        Ok((name, entry))
    }).collect()
}

/// A read's answer: the bytes as latin-1 text (true: the call's text, so that a large file is not escaped into
/// JSON), or {"error": why}; None: not read.
fn read_arg(v: Option<&Value>, text: &[u32]) -> Result<crate::collect::Read, CallError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(true)) => crate::binary::bytes_of(text)
            .map(|b| Some(Ok(b)))
            .ok_or_else(|| CallError::BadArgs("a read's bytes come as latin-1 text".into())),
        Some(Value::Str(t)) => crate::binary::bytes_of(t)
            .map(|b| Some(Ok(b)))
            .ok_or_else(|| CallError::BadArgs("a read's bytes come as latin-1 text".into())),
        Some(o @ Value::Obj(_)) => Ok(Some(Err(o.get("error").and_then(|e| e.as_str()).map(|s| s.to_vec()).unwrap_or_default()))),
        _ => Err(CallError::BadArgs("a read is latin-1 text or {error}".into())),
    }
}

/// [[offset, length]] as (offset, length) pairs.
pub fn layout_arg(layout: &[Value]) -> Result<Vec<(u64, u64)>, CallError> {
    layout.iter().map(|x| {
        let a = x.as_arr().filter(|a| a.len() == 2);
        let n = |k: usize| a.and_then(|a| a[k].as_i64()).filter(|&v| v >= 0).map(|v| v as u64);
        match (n(0), n(1)) {
            (Some(o), Some(l)) => Ok((o, l)),
            _ => Err(CallError::BadArgs("a piece is [offset, length]".into())),
        }
    }).collect()
}

/// The pieces of a file a layout says `data` holds, one after another.
fn pieces_of<'d>(layout: &[(u64, u64)], data: &'d [u8]) -> Result<Vec<(u64, &'d [u8])>, CallError> {
    let mut at = 0u64;
    let mut out = Vec::with_capacity(layout.len());
    for &(off, len) in layout {
        let end = at.checked_add(len).filter(|&e| e <= data.len() as u64)
            .ok_or_else(|| CallError::BadArgs("the pieces' lengths run past the bytes given".into()))?;
        out.push((off, &data[at as usize..end as usize]));
        at = end;
    }
    Ok(out)
}

/// pth_stream's state from its last answer (null: the file's start).
fn pth_state_arg(v: Option<&Value>) -> Result<crate::binary::PthStream, CallError> {
    let Some(v @ Value::Obj(_)) = v else { return Ok(crate::binary::PthStream::default()) };
    let b = |k: &str| matches!(v.get(k), Some(Value::Bool(true)));
    let carry = match v.get("carry") {
        Some(Value::Str(t)) => crate::binary::bytes_of(t).ok_or_else(|| CallError::BadArgs("a carry is latin-1 text".into()))?,
        _ => Vec::new(),
    };
    Ok(crate::binary::PthStream { line: v.get("line").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u64, cr: b("cr"),
                                  carry, whole: b("whole"), keeping: b("keeping"), skipping: b("skipping"),
                                  kept: v.get("kept").and_then(|x| x.as_i64()).unwrap_or(0).max(0) as u64, full: b("full") })
}

/// A media walk's answer as JSON: {"is": kind}, {"not": kind, "why"}, {"unknown": true}.
pub fn walked_value(w: &crate::media::Walked) -> Value {
    use crate::media::Walked;
    match w {
        Walked::Is(k) => Value::obj(vec![("is", Value::str(k))]),
        Walked::Not(k, why) => Value::obj(vec![("not", Value::str(k)), ("why", Value::str(why))]),
        Walked::Unknown => Value::obj(vec![("unknown", Value::Bool(true))]),
    }
}

/// walked_value's JSON back.
pub fn walked_arg(v: &Value) -> Result<crate::media::Walked, CallError> {
    use crate::media::Walked;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(crate::pystr::to_string);
    if let Some(k) = s("is") {
        return Ok(Walked::Is(k));
    }
    if let Some(k) = s("not") {
        return Ok(Walked::Not(k, s("why").unwrap_or_default()));
    }
    if matches!(v.get("unknown"), Some(Value::Bool(true))) {
        return Ok(Walked::Unknown);
    }
    Err(CallError::BadArgs("a walk is {is}, {not, why} or {unknown}".into()))
}

/// A media walk's state as JSON, for the host to give back with the next chunk (every number below 2^53).
fn media_state_value(w: &crate::media::Walker) -> Value {
    let n = |v: u64| Value::Int(if v == u64::MAX { -1 } else { v as i64 });
    Value::obj(vec![
        ("fmt", Value::Int(w.fmt as i64)),
        ("phase", Value::Int(w.phase as i64)),
        ("at", n(w.at)),
        ("fed", n(w.fed)),
        ("carry", Value::Str(w.carry.iter().map(|&b| b as u32).collect())),
        ("n", Value::Arr(w.n.iter().map(|&v| n(v)).collect())),
        ("x", Value::Arr(w.x.iter().map(|&v| n(v)).collect())),
        ("crc", Value::Int(w.crc as i64)),
        ("claims", Value::Arr(w.claims.iter().map(|&(a, b)| Value::Arr(vec![n(a), n(b)])).collect())),
        ("free", n(w.free)),
        ("freeWhat", Value::str(&w.free_what)),
        ("kind", Value::str(&w.kind)),
        ("why", Value::str(&w.why)),
        ("end", match &w.end {
            None => Value::Null,
            Some(Ok(())) => Value::obj(vec![("ok", Value::Bool(true))]),
            Some(Err(why)) => Value::obj(vec![("fail", Value::str(why))]),
        }),
    ])
}

/// media_state_value's JSON back (null: a walk's start).
fn media_state_arg(v: Option<&Value>) -> Result<crate::media::Walker, CallError> {
    let Some(v @ Value::Obj(_)) = v else { return Ok(crate::media::Walker::new()) };
    let bad = || CallError::BadArgs("a media walk's state is media_stream's last answer's".into());
    let n = |x: Option<&Value>| -> Result<u64, CallError> {
        match x.and_then(|x| x.as_i64()) {
            Some(-1) => Ok(u64::MAX),
            Some(i) if i >= 0 => Ok(i as u64),
            _ => Err(bad()),
        }
    };
    let text = |k: &str| v.get(k).and_then(|x| x.as_str()).map(crate::pystr::to_string).unwrap_or_default();
    let mut w = crate::media::Walker::new();
    w.fmt = u8::try_from(n(v.get("fmt"))?).map_err(|_| bad())?;
    w.phase = u8::try_from(n(v.get("phase"))?).map_err(|_| bad())?;
    w.at = n(v.get("at"))?;
    w.fed = n(v.get("fed"))?;
    w.carry = match v.get("carry") {
        Some(Value::Str(t)) => crate::binary::bytes_of(t).ok_or_else(bad)?,
        _ => return Err(bad()),
    };
    let ns = v.get("n").and_then(|x| x.as_arr()).filter(|a| a.len() == 8).ok_or_else(bad)?;
    for (k, x) in ns.iter().enumerate() {
        w.n[k] = n(Some(x))?;
    }
    let xs = v.get("x").and_then(|x| x.as_arr()).filter(|a| a.len() == 4).ok_or_else(bad)?;
    for (k, x) in xs.iter().enumerate() {
        w.x[k] = n(Some(x))?;
    }
    w.free = n(v.get("free"))?;
    w.free_what = text("freeWhat");
    w.crc = u32::try_from(n(v.get("crc"))?).map_err(|_| bad())?;
    for c in v.get("claims").and_then(|x| x.as_arr()).ok_or_else(bad)? {
        let a = c.as_arr().filter(|a| a.len() == 2).ok_or_else(bad)?;
        w.claims.push((n(a.first())?, n(a.get(1))?));
    }
    w.kind = text("kind");
    w.why = text("why");
    w.end = match v.get("end") {
        None | Some(Value::Null) => None,
        Some(e) if matches!(e.get("ok"), Some(Value::Bool(true))) => Some(Ok(())),
        Some(e) => Some(Err(e.get("fail").and_then(|x| x.as_str()).map(crate::pystr::to_string).ok_or_else(bad)?)),
    };
    Ok(w)
}

/// [[line, latin-1 text]] as (line, bytes).
pub fn pth_lines_arg(v: Option<&Value>) -> Result<Vec<(u64, Vec<u8>)>, CallError> {
    v.and_then(|x| x.as_arr()).unwrap_or(&[]).iter().map(|x| {
        let a = x.as_arr().filter(|a| a.len() == 2);
        let n = a.and_then(|a| a[0].as_i64()).filter(|&n| n > 0);
        let t = a.and_then(|a| a[1].as_str()).and_then(crate::binary::bytes_of);
        match (n, t) {
            (Some(n), Some(t)) => Ok((n as u64, t)),
            _ => Err(CallError::BadArgs("a line is [line, latin-1 text]".into())),
        }
    }).collect()
}

fn pth_lines_value(lines: &[(u64, Vec<u8>)]) -> Value {
    Value::Arr(lines.iter().map(|(n, b)| Value::Arr(vec![Value::Int(*n as i64), Value::Str(b.iter().map(|&c| c as u32).collect())])).collect())
}

/// [[offset, length]] of the ranges a reading needs.
pub fn ranges_value(ranges: &[(u64, u64)]) -> Value {
    Value::Arr(ranges.iter().map(|&(o, l)| Value::Arr(vec![Value::Int(o as i64), Value::Int(l as i64)])).collect())
}

/// The collection's calls (collect.rs).
fn collect_call(p: &Pack, name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::collect;
    let flag = |k: &str| matches!(args.get(k), Some(Value::Bool(true)));
    let sep = if flag("windows") { u("\\") } else { u("/") };
    let answers = args.get("answers");
    Ok(match name {
        "collect_dir" => {
            // {dir, dep, entries, excludes, includeDeps, windows, answers: {lists: [[index, [[child, is a folder]] or
            // null]], cargo: [[index, [folders with a regular .cargo-checksum.json]]]}} -> {"do", "seen"} or {"need"}
            let mut a = collect::DirAnswers::default();
            let pairs = |key: &str| -> Vec<(usize, Value)> {
                answers.and_then(|x| x.get(key)).and_then(|x| x.as_arr()).unwrap_or(&[]).iter().filter_map(|it| {
                    let pair = it.as_arr()?;
                    Some((pair.first()?.as_i64()?.max(0) as usize, pair.get(1).cloned().unwrap_or(Value::Null)))
                }).collect()
            };
            for (k, v) in pairs("lists") {
                let list = v.as_arr().map(|items| {
                    items.iter().filter_map(|it| {
                        let pair = it.as_arr()?;
                        Some((pair.first()?.as_str()?.to_vec(), matches!(pair.get(1), Some(Value::Bool(true)))))
                    }).collect()
                });
                a.lists.push((k, list));
            }
            for (k, v) in pairs("cargo") {
                let found = v.as_arr().unwrap_or(&[]).iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect();
                a.cargo.push((k, found));
            }
            let d = collect::DirIn {
                dir: opt_str(args, "dir").unwrap_or_default(),
                dep: collect::Dep::of(args.get("dep")),
                entries: entries_arg(args)?,
                excludes: arr_arg(args, "excludes").iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect(),
                include_deps: flag("includeDeps"),
                sep,
                answers: &a,
            };
            collect::dir(p, &d)
        }
        "collect_file" => {
            // {rel, name, size, dep, cap, configCap, windows, neumaier, redact, ranges (the host reads a file by
            // range), answers: {head, data, sample, ranges, rounds}} -> {"need": {read, limit}} (or {read: "ranges",
            // ranges: [[offset, length]]}: a zip model file's, read by range) or {"issues": [[path, issue]], "file",
            // "manifest", "config", "pth", "model"}. The ranges' answer is [[offset, length]] of every range read so
            // far, their bytes the call's text one after another, and `rounds` how many times they were asked for; a
            // .pth file too large to read whole ({read: "pth"}) is read in chunks through pth_stream, its answer
            // {lines: [[line, latin-1 text]], cuts: [why]} or {error}; one walked as its stream passes ({read:
            // "media"}: FP-OPAQUE-MEDIA) through media_stream, its answer the walk's end or {error}; a file beside
            // it ({read: "sibling", name, limit}: a Gradle wrapper's gradle-wrapper.properties, FP-GRADLE-WRAPPER;
            // `limit` is one byte more than the engine reads, so that a longer file is told), its answer `sibling`:
            // its first `limit` bytes as latin-1 text, false when there is no such regular file, or {error} (one
            // there and not read: a symbolic link, which Java follows and the scan does not, can't be verified).
            let ranges = match answers.and_then(|x| x.get("ranges")) {
                None | Some(Value::Null) => None,
                Some(Value::Arr(layout)) => {
                    let layout = layout_arg(layout)?;
                    let data = crate::binary::bytes_of(text)
                        .ok_or_else(|| CallError::BadArgs("a read's bytes come as latin-1 text".into()))?;
                    pieces_of(&layout, &data)?;
                    Some(Ok((layout, data)))
                }
                Some(o @ Value::Obj(_)) => Some(Err(o.get("error").and_then(|e| e.as_str()).map(|s| s.to_vec()).unwrap_or_default())),
                _ => return Err(CallError::BadArgs("the ranges read are [[offset, length]] or {error}".into())),
            };
            let pth_lines = match answers.and_then(|x| x.get("pth")) {
                None | Some(Value::Null) => None,
                Some(o @ Value::Obj(_)) => match o.get("error") {
                    Some(e) => Some(Err(e.as_str().map(|s| s.to_vec()).unwrap_or_default())),
                    None => Some(Ok((pth_lines_arg(o.get("lines"))?,
                                     o.get("cuts").and_then(|c| c.as_arr()).unwrap_or(&[]).iter()
                                         .filter_map(|c| c.as_str().map(crate::pystr::to_string)).collect()))),
                },
                _ => return Err(CallError::BadArgs("a .pth file read in chunks is {lines, cuts} or {error}".into())),
            };
            let media = match answers.and_then(|x| x.get("media")) {
                None | Some(Value::Null) => None,
                Some(o) => match o.get("error") {
                    Some(e) => Some(Err(e.as_str().map(|s| s.to_vec()).unwrap_or_default())),
                    None => Some(Ok(walked_arg(o)?)),
                },
            };
            let sibling = match answers.and_then(|x| x.get("sibling")) {
                None | Some(Value::Null) => None,
                Some(Value::Bool(false)) => Some(Ok(None)),
                Some(Value::Str(t)) => Some(Ok(Some(crate::binary::bytes_of(t)
                    .ok_or_else(|| CallError::BadArgs("a read's bytes come as latin-1 text".into()))?))),
                Some(o @ Value::Obj(_)) => Some(Err(o.get("error").and_then(|e| e.as_str()).map(|s| s.to_vec()).unwrap_or_default())),
                _ => return Err(CallError::BadArgs("a file beside it is latin-1 text, false or {error}".into())),
            };
            let f = collect::FileIn {
                sibling,
                media,
                pth_lines,
                ranged: flag("ranges"),
                ranges,
                rounds: answers.and_then(|x| x.get("rounds")).and_then(|v| v.as_i64()).unwrap_or(0).max(0) as u64,
                rel: arg_str(args, "rel")?,
                name: arg_str(args, "name")?,
                size: opt_int(args, "size").unwrap_or(0).max(0) as u64,
                dep: collect::Dep::of(args.get("dep")),
                cap: opt_int(args, "cap").map(|c| c.max(0) as u64).unwrap_or(p.usize("SOURCE_SIZE_CAP") as u64),
                config_cap: opt_int(args, "configCap").map(|c| c.max(0) as u64).unwrap_or(p.usize("CONFIG_SCAN_CAP") as u64),
                windows: flag("windows"),
                neumaier: flag("neumaier"),
                redact: !matches!(args.get("redact"), Some(Value::Bool(false))),
                head: read_arg(answers.and_then(|x| x.get("head")), text)?,
                data: read_arg(answers.and_then(|x| x.get("data")), text)?,
                sample: match read_arg(answers.and_then(|x| x.get("sample")), text)? {
                    None => None,
                    Some(Ok(b)) => Some(b),
                    Some(Err(_)) => Some(Vec::new()), // (not read: the SC-TRUNCATED stands alone)
                },
            };
            collect::file(p, &f)
        }
        "collect_pycache" => {
            // {dir, entries, parent: [the folder's names], windows, answers: {headers: {name: 16 bytes or {error}}}}
            // -> {"issues"} or {"need": [names]}
            let entries = entries_arg(args)?;
            let parent: Vec<PyStr> = arr_arg(args, "parent").iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect();
            let mut headers = Vec::new();
            for (k, v) in answers.and_then(|x| x.get("headers")).and_then(|x| x.as_obj()).unwrap_or(&[]) {
                if let Some(r) = read_arg(Some(v), text)? {
                    headers.push((k.clone(), r));
                }
            }
            collect::pycache(p, &opt_str(args, "dir").unwrap_or_default(), &sep, &entries, &parent, &headers)
        }
        _ => {
            // {kind: unreadable | symlink | skipped_tree, path, reason | target | files and bytes} -> the issue
            let path = arg_str(args, "path")?;
            match crate::pystr::to_string(&arg_str(args, "kind")?).as_str() {
                "unreadable" => collect::unreadable_issue(p, &path, &opt_str(args, "reason").unwrap_or_default()),
                "symlink" => collect::symlink_issue(p, &path, &opt_str(args, "target").unwrap_or_default()),
                "skipped_tree" => collect::skipped_tree_issue(p, &path, opt_int(args, "files").unwrap_or(0), opt_int(args, "bytes").unwrap_or(0)),
                other => return Err(CallError::BadArgs(format!("collect_issue: no kind {other:?}"))),
            }
        }
    })
}

/// The reports' calls (report.rs): a frame's {head, tail}, a batch of findings' {text}.
fn report_call(p: &Pack, name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::report as rep;
    let pair = |h: String, t: String| Value::obj(vec![("head", Value::str(&h)), ("tail", Value::str(&t))]);
    let wpair = |h: PyStr, t: PyStr| Value::obj(vec![("head", Value::Str(h)), ("tail", Value::Str(t))]);
    let doc = || args.get("doc").cloned().ok_or_else(|| CallError::BadArgs(format!("{name}: doc")));
    let order = args.get("perFileOrder").and_then(|v| v.as_arr());
    let windows = flag(args, "windows", false);
    Ok(match name {
        // {mode: "text" | "line" | "excerpt", width}: the text as sanitize_term, sanitize_term_line or
        // safe_excerpt (width characters, 100 by default) makes it
        "term" => {
            let mode = opt_str(args, "mode").map(|m| crate::pystr::to_string(&m)).unwrap_or_default();
            let out = match mode.as_str() {
                "text" => rep::sanitize_term(text),
                "line" => rep::sanitize_term_line(text),
                "excerpt" => rep::safe_excerpt(text, opt_int(args, "width").unwrap_or(100)),
                _ => return Err(CallError::BadArgs("term: mode is text, line or excerpt".into())),
            };
            Value::obj(vec![("text", Value::Str(out))])
        }
        // {issue, width, redact, shown}: a finding's flagged line for the terminal (core.issue_excerpt): `shown` the
        // line as read (--show-secrets), else its snippet's, "[redacted]" for a secret rule's when redacting
        "issue_excerpt" => {
            let issue = args.get("issue").cloned().unwrap_or(Value::Null);
            let out = rep::issue_excerpt(p, &issue, opt_int(args, "width").unwrap_or(100), args.get("shown"), flag(args, "redact", true));
            Value::obj(vec![("text", Value::Str(out))])
        }
        // {doc, prefix: [[key, value]], perFileOrder, count}: the JSON report's frame, the findings left out
        "report_json" => {
            let count = match args.get("count") {
                Some(Value::Int(n)) if *n >= 0 => Some(*n as usize),
                _ => None,
            };
            let (h, t) = rep::json_frame(doc()?, arr_arg(args, "prefix"), order, count);
            pair(h, t)
        }
        // {items, level, first}: items of a frame's array, at its level
        "report_items" => {
            let level = count_arg(args, "level")?;
            Value::obj(vec![("text", Value::str(&rep::items_text(arr_arg(args, "items"), level, flag(args, "first", false))))])
        }
        // {issues, known: [rule ids]}: the SARIF rules of the findings' rules not known yet
        "sarif_rules" => {
            let known: Vec<PyStr> = arr_arg(args, "known").iter().map(rep::py_str).collect();
            Value::obj(vec![("rules", Value::Arr(rep::sarif_rules(arr_arg(args, "issues"), &known)))])
        }
        // {rules, root, windows, version, source, marker, count}: the SARIF log's frame
        "sarif_frame" => {
            let root = arg_str(args, "root")?;
            let (h, t) = rep::sarif_frame(
                arr_arg(args, "rules").to_vec(),
                &root,
                windows,
                args.get("version").cloned().unwrap_or(Value::Null),
                args.get("source"),
                args.get("marker"),
                count_arg(args, "count")?,
            );
            pair(h, t)
        }
        // {issues, rules: [rule ids, in their index order], windows, first}: SARIF results
        "sarif_items" => {
            let rules: Vec<PyStr> = arr_arg(args, "rules").iter().map(rep::py_str).collect();
            Value::obj(vec![("text", Value::str(&rep::sarif_items(arr_arg(args, "issues"), &rules, windows, flag(args, "first", false))))])
        }
        // {doc, count, windows, marker, perFileOrder}: the HTML report's frame
        "html_frame" => {
            let (h, t) = rep::html_frame(&doc()?, count_arg(args, "count")?, windows, args.get("marker"), order);
            wpair(h, t)
        }
        // {issues, first}: the HTML report's items
        "html_items" => Value::obj(vec![("text", Value::Str(rep::html_items(arr_arg(args, "issues"), flag(args, "first", false))))]),
        // {doc, count, quiet, color}: the terminal summary's frame
        "text_frame" => {
            let (h, t) = rep::text_frame(&doc()?, count_arg(args, "count")?, flag(args, "quiet", false), flag(args, "color", false));
            wpair(h, t)
        }
        // {rows: [[file, sev, line]]}: the order the terminal summary lists the findings in
        "text_order" => Value::obj(vec![(
            "order",
            Value::Arr(rep::text_order(arr_arg(args, "rows")).into_iter().map(|k| Value::Int(k as i64)).collect()),
        )]),
        // {issues, file, color, width, redact, shown}: findings, in that order, as the terminal summary lists them
        _ => {
            let file = opt_str(args, "file");
            let (out, last) = rep::text_items(
                p,
                arr_arg(args, "issues"),
                file,
                flag(args, "color", false),
                opt_int(args, "width").unwrap_or(100),
                flag(args, "redact", true),
                arr_arg(args, "shown"),
            );
            Value::obj(vec![("text", Value::Str(out)), ("file", last.map_or(Value::Null, Value::Str))])
        }
    })
}

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
/// it may take (crate::budget; the default otherwise). `text_id` in the
/// arguments: the call's text is that one of the store's (texts.rs), read
/// here, and the call is given no other.
pub fn call(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    if name == "batch" {
        return batch(args);
    }
    if let Some(id) = args.get("text_id") {
        let id = text_id(id)?;
        if !text.is_empty() {
            return Err(CallError::BadArgs(format!("{name}: a text and a text_id")));
        }
        let shared = crate::texts::decoded_shared(id).ok_or_else(|| CallError::BadArgs(format!("{name}: no text {id} in the store")))?;
        return with_call_text(&shared, || call_text(name, args, &shared));
    }
    call_text(name, args, text)
}

thread_local! {
    /// The text of the call in progress, as a shared copy (call_owned, a stored text's call): call_text_shared
    static CALL_TEXT: std::cell::RefCell<Option<std::sync::Arc<[u32]>>> = const { std::cell::RefCell::new(None) };
}

/// `f` with `text` as the call's shared text (the one before restored after).
fn with_call_text<R>(text: &std::sync::Arc<[u32]>, f: impl FnOnce() -> R) -> R {
    let before = CALL_TEXT.with(|c| c.borrow_mut().replace(text.clone()));
    let out = f();
    CALL_TEXT.with(|c| *c.borrow_mut() = before);
    out
}

/// The call's shared copy of `text`, when `text` is it (the same characters where they are): what a reading that
/// keeps the text holds instead of a copy of its own (the supply-chain tree's, BIG-BUNDLE-TAIL).
pub fn call_text_shared(text: &[u32]) -> Option<std::sync::Arc<[u32]>> {
    CALL_TEXT.with(|c| c.borrow().as_ref().filter(|t| t.as_ptr() == text.as_ptr() && t.len() == text.len()).cloned())
}

/// A text_id's value: the id `texts.put` answered.
fn text_id(v: &Value) -> Result<u64, CallError> {
    v.as_i64().filter(|&n| n > 0).map(|n| n as u64).ok_or_else(|| CallError::BadArgs("text_id is not an id".into()))
}

fn call_text(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
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

/// `call`, given the text to keep: a module's or a crate's reading (go_package, rs_crate) holds every file of it
/// at once, so it takes the text as it is rather than a copy of each file (a copy doubled what 200 MB of Go held:
/// aws-sdk-go's 207 million characters were 1.7 GB of text in the engine before a tree was built). The other
/// calls borrow it.
pub fn call_owned(name: &str, args: &Value, text: Vec<u32>) -> Result<Value, CallError> {
    if name != "go_package" && name != "rs_crate" {
        return call_shared(name, args, std::sync::Arc::from(text));
    }
    let steps = match args.get("budget").and_then(|b| b.as_i64()) {
        Some(b) if b > 0 => b as u64,
        _ => crate::budget::DEFAULT_STEPS,
    };
    let mut text = Some(text);
    let out = crate::budget::call_with(steps, || {
        let text = text.take().unwrap_or_default();
        if name == "go_package" {
            go_package(args, text)
        } else {
            rs_crate(args, text)
        }
    });
    match out {
        Ok(r) => r,
        Err(_) => Err(CallError::Exhausted),
    }
}

/// call_owned, given the text as one shared buffer (the WebAssembly build's, decode_wtf8_shared): the call's text is
/// the one copy the supply-chain tree reads and keeps (call_text_shared, BIG-BUNDLE-TAIL, John's decision of Oct 21),
/// not copied again while its model lives: at 16,000,000 characters a copy is 64 MB.
pub fn call_shared(name: &str, args: &Value, text: std::sync::Arc<[u32]>) -> Result<Value, CallError> {
    if name == "go_package" || name == "rs_crate" {
        return call_owned(name, args, text.to_vec());
    }
    with_call_text(&text, || call(name, args, &text))
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
            if name == "batch" || name.starts_with("pack.") || name.starts_with("texts.") {
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

/// The stack of the thread a call that recurses on nested input runs on
/// natively (the parsers, the JavaScript taint pass): the deepest input each
/// reads takes a bounded stack — under 512 KiB natively (release;
/// docs/RUST_ENGINE.md) — which the host's thread may not have (a worker
/// thread's default is 512 KiB on macOS, 128 KiB on musl). In WebAssembly
/// they run on the module's own stack, 8 MiB (rust/.cargo/config.toml).
/// (A debug build's frames are several times larger.)
pub const OWN_STACK: usize = if cfg!(debug_assertions) { 64 << 20 } else { 8 << 20 };

/// `f` on a thread with an OWN_STACK stack: natively, the calling thread's
/// own such thread, made at its first call and kept for the next (the
/// engine's caches, compiled patterns among them, are per thread; a thread
/// made per call would compile them again each time), ending when the
/// calling thread does; inline if no thread can be made, and in
/// WebAssembly.
pub(crate) fn on_own_stack<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(f: F) -> T {
    #[cfg(not(target_arch = "wasm32"))]
    {
        own_stack::run(f)
    }
    #[cfg(target_arch = "wasm32")]
    f()
}

#[cfg(not(target_arch = "wasm32"))]
mod own_stack {
    use std::cell::RefCell;
    use std::sync::mpsc::{channel, sync_channel, SendError, Sender};

    type Job = Box<dyn FnOnce() + Send>;

    thread_local! {
        static WORKER: RefCell<Option<Sender<Job>>> = const { RefCell::new(None) };
    }

    fn spawn() -> Option<Sender<Job>> {
        let (tx, rx) = channel::<Job>();
        std::thread::Builder::new()
            .name("lazaret-own-stack".into())
            .stack_size(super::OWN_STACK)
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job();
                }
            })
            .ok()?;
        Some(tx)
    }

    pub fn run<T: Send + 'static, F: FnOnce() -> T + Send + 'static>(f: F) -> T {
        // (the call's budget goes with the job and comes back with its answer: what the job spends is the call's, as
        // it is when the job runs here, and in WebAssembly)
        let (back, answer) = sync_channel::<(T, crate::budget::State)>(1);
        let budget = crate::budget::state();
        let job: Job = Box::new(move || {
            crate::budget::carry(budget);
            let out = f();
            let _ = back.send((out, crate::budget::state()));
        });
        // to this thread's worker (made again if it is gone); kept here if none can be made
        let kept = WORKER.with(|w| {
            let mut w = w.borrow_mut();
            let mut job = Some(job);
            for _ in 0..2 {
                if w.is_none() {
                    *w = spawn();
                }
                let tx = match w.as_ref() {
                    Some(tx) => tx,
                    None => break,
                };
                match tx.send(job.take().expect("not sent yet")) {
                    Ok(()) => return None,
                    Err(SendError(j)) => {
                        job = Some(j);
                        *w = None;
                    }
                }
            }
            job
        });
        if let Some(job) = kept {
            job();
        }
        let (out, left) = answer.recv().expect("the call's own thread ended before answering");
        crate::budget::carry(left);
        out
    }
}

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
            // (BIG-BUNDLE-TAIL: the limit a reading met, when one made the call answer so)
            let why = crate::budget::last_cut().unwrap_or_else(|| "exhausted".to_string());
            Value::obj(vec![("error", Value::str(&why)), ("exhausted", Value::Bool(true))])
        }
        Ok(Err(CallError::Unknown(n))) => Value::obj(vec![("error", Value::str(&format!("unknown call {}", n)))]),
        Ok(Err(CallError::BadArgs(m))) => Value::obj(vec![("error", Value::str(&m))]),
        Err(_) => Value::obj(vec![("error", Value::str("panic")), ("panic", Value::Bool(true))]),
    }
}

/// texts.put's lengths (code points, one per text).
pub fn put_lengths(args: &Value) -> Result<Vec<usize>, CallError> {
    let bad = || CallError::BadArgs("texts.put: lengths".into());
    args.get("lengths").and_then(|l| l.as_arr()).ok_or_else(bad)?
        .iter().map(|n| n.as_i64().filter(|&n| n >= 0).map(|n| n as usize).ok_or_else(bad)).collect()
}

/// texts.put's answer, {"ids": [id, …]}, or the reason it kept nothing (a store that would pass its bound: the caller
/// sends those texts with its calls instead).
pub fn texts_put_answer(r: Result<Vec<u64>, crate::texts::PutError>) -> Result<Value, CallError> {
    match r {
        Ok(ids) => Ok(Value::obj(vec![("ids", Value::Arr(ids.into_iter().map(|id| Value::Int(id as i64)).collect()))])),
        Err(e) => Err(CallError::BadArgs(e.message())),
    }
}

fn flag(args: &Value, name: &str, default: bool) -> bool {
    match args.get(name) {
        Some(Value::Bool(b)) => *b,
        _ => default,
    }
}

fn deps_opts(args: &Value) -> crate::deps::Opts {
    crate::deps::Opts { redact: flag(args, "redact", true), neumaier: flag(args, "neumaier", false) }
}

/// ['/'-separated path, a dependency's] pairs, or the strings of a list of strings.
fn path_flags(args: &Value, name: &str) -> Vec<(PyStr, bool)> {
    args.get(name)
        .and_then(|v| v.as_arr())
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| {
            let a = x.as_arr()?;
            Some((a.first()?.as_str()?.to_vec(), matches!(a.get(1), Some(Value::Bool(true)))))
        })
        .collect()
}

/// `deps_hooks`: {project, hooks: [[manifest, line, sev, cmd]…], manifests: [[path, dep]…] (a dependency's hooks: for
/// npm's implicit node-gyp hooks), known, redact, neumaier} -> {"need": {…}} (deps::Need), or {"hooks": [[sev, msg]
/// or null…], "out": [["issue", file, issue] or ["read", rel]…], "run": [rel…]}.
fn deps_hooks(p: &Pack, args: &Value) -> Result<Value, CallError> {
    let mut hooks = Vec::new();
    for h in args.get("hooks").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let a = h.as_arr().ok_or_else(|| CallError::BadArgs("deps_hooks: a hook".into()))?;
        let s = |k: usize| a.get(k).and_then(|v| v.as_str()).map(|x| x.to_vec());
        let (Some(file), Some(sev), Some(cmd)) = (s(0), s(2), s(3)) else {
            return Err(CallError::BadArgs("deps_hooks: a hook's manifest, severity and command".into()));
        };
        let line = a.get(1).and_then(|v| v.as_i64()).unwrap_or(1).max(0) as usize;
        hooks.push(crate::deps::Hook { file, line, sev, cmd, msg: None, weak_named: false });
    }
    let known = crate::deps::Known::from_value(args.get("known"));
    let manifests = path_flags(args, "manifests");
    Ok(match crate::deps::follow_hooks(p, &known, flag(args, "project", false), &hooks, &manifests, &deps_opts(args)) {
        Err(need) => Value::obj(vec![("need", need.to_value())]),
        Ok(done) => Value::obj(vec![
            (
                "hooks",
                Value::Arr(
                    done.hooks
                        .into_iter()
                        .map(|h| h.map(|(sev, msg)| Value::Arr(vec![Value::Str(sev), Value::Str(msg)])).unwrap_or(Value::Null))
                        .collect(),
                ),
            ),
            ("out", Value::Arr(done.out.iter().map(|o| o.to_value()).collect())),
            ("run", strs(&done.run)),
        ]),
    })
}

/// `deps_files`: {files: [[path, lang]…] (a --deps scan's dependency JavaScript and Python files, in order), run:
/// [rel…], known} -> {"need": {…}}, or {"assets": [path…], "todo": [[path, [declared, own] or null]…], "groups":
/// [[path, group]…]}.
fn deps_files(p: &Pack, args: &Value) -> Result<Value, CallError> {
    let files: Vec<(PyStr, PyStr)> = args
        .get("files")
        .and_then(|v| v.as_arr())
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| {
            let a = x.as_arr()?;
            Some((a.first()?.as_str()?.to_vec(), a.get(1)?.as_str()?.to_vec()))
        })
        .collect();
    let run: std::collections::HashSet<PyStr> = arg_strs(args, "run").into_iter().collect();
    let known = crate::deps::Known::from_value(args.get("known"));
    Ok(match crate::deps::plan_files(p, &known, &files, &run) {
        Err(need) => Value::obj(vec![("need", need.to_value())]),
        Ok(plan) => Value::obj(vec![
            ("assets", strs(&plan.assets)),
            (
                "todo",
                Value::Arr(plan.todo.iter().map(|(f, n)| Value::Arr(vec![Value::Str(f.clone()), crate::deps::names_value(n)])).collect()),
            ),
            (
                "groups",
                Value::Arr(plan.groups.iter().map(|(f, g)| Value::Arr(vec![Value::Str(f.clone()), Value::Str(g.clone())])).collect()),
            ),
        ]),
    })
}

fn strs(v: &[PyStr]) -> Value {
    Value::Arr(v.iter().map(|s| Value::Str(s.clone())).collect())
}

/// `b64_descriptors` (FP-B64-PROTOBUF, protodesc::usage): {files: [[path, text]…] (every JavaScript-family file the
/// scan read whole), holders: [[path, text or null]…] (the files of kinds that hold script it does not read),
/// manifests: [[path, text]…] (every package.json), configs: [[path, text or null]…] (the files that say where modules
/// are: tsconfig*.json, jsconfig*.json, `_B64_RESOLVER_CONFIGS`),
/// findings: [[path, line]…] (the SC-B64 findings to decide), unread: [path…] (the SC-TRUNCATED, Q-UNREADABLE and
/// Q-SYMLINK findings' files), stopped, package (a package's scan, not a checkout's)} -> {"findings": [[path, line,
/// null (dropped) or why it stays]…]}, in the order given. Paths '/'-separated.
fn b64_descriptors(p: &Pack, args: &Value) -> Result<Value, CallError> {
    let pairs = |k: &str| -> Result<Vec<(String, Option<PyStr>)>, CallError> {
        let mut out = Vec::new();
        for r in args.get(k).and_then(|v| v.as_arr()).unwrap_or(&[]) {
            let a = r.as_arr().ok_or_else(|| CallError::BadArgs(format!("b64_descriptors: {k}")))?;
            let path = a.first().and_then(|v| v.as_str()).ok_or_else(|| CallError::BadArgs(format!("b64_descriptors: {k}'s path")))?;
            out.push((crate::pystr::to_string(path).replace('\\', "/"), a.get(1).and_then(|v| v.as_str()).map(|t| t.to_vec())));
        }
        Ok(out)
    };
    let texts = |k: &str| -> Result<Vec<(String, PyStr)>, CallError> {
        pairs(k)?.into_iter().map(|(p, t)| t.map(|t| (p, t)).ok_or_else(|| CallError::BadArgs(format!("b64_descriptors: {k}'s text")))).collect()
    };
    let mut findings = Vec::new();
    for r in args.get("findings").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let a = r.as_arr().ok_or_else(|| CallError::BadArgs("b64_descriptors: a finding".into()))?;
        let path = a.first().and_then(|v| v.as_str()).ok_or_else(|| CallError::BadArgs("b64_descriptors: a finding's path".into()))?;
        let line = a.get(1).and_then(|v| v.as_i64()).ok_or_else(|| CallError::BadArgs("b64_descriptors: a finding's line".into()))?;
        findings.push((crate::pystr::to_string(path).replace('\\', "/"), usize::try_from(line).unwrap_or(0)));
    }
    let flag = |k: &str| matches!(args.get(k), Some(Value::Bool(true)));
    let input = crate::protodesc::usage::Input {
        files: texts("files")?,
        holders: pairs("holders")?,
        manifests: texts("manifests")?,
        configs: pairs("configs")?,
        findings,
        unread: arg_strs(args, "unread").iter().map(|x| crate::pystr::to_string(x).replace('\\', "/")).collect(),
        stopped: flag("stopped"),
        package: flag("package"),
    };
    let out = crate::protodesc::usage::decide(p, &input);
    Ok(Value::obj(vec![(
        "findings",
        Value::Arr(
            out.into_iter()
                .map(|(path, line, why)| {
                    Value::Arr(vec![Value::str(&path), Value::Int(line as i64), why.map(|w| Value::str(&w)).unwrap_or(Value::Null)])
                })
                .collect(),
        ),
    )]))
}

fn opt_s(v: Option<PyStr>) -> Value {
    v.map(Value::Str).unwrap_or(Value::Null)
}

fn arg_strs(args: &Value, name: &str) -> Vec<PyStr> {
    args.get(name).and_then(|v| v.as_arr()).unwrap_or(&[]).iter().filter_map(|v| v.as_str().map(|s| s.to_vec())).collect()
}

/// A file's line metrics as the packages read them: {"ncloc", "comments", "measured", "windows"}, the windows'
/// keys as one string of 16 hexadecimal digits each.
fn metrics_value(m: &crate::metrics::FileMetrics) -> Value {
    use std::fmt::Write;
    let mut windows = String::with_capacity(16 * m.windows.len());
    for h in &m.windows {
        let _ = write!(windows, "{h:016x}");
    }
    Value::obj(vec![
        ("ncloc", Value::Int(m.ncloc as i64)),
        ("comments", Value::Int(m.comments as i64)),
        ("measured", Value::Int(m.measured as i64)),
        ("windows", Value::str(&windows)),
    ])
}

fn spans_value(sp: &[(usize, usize)]) -> Value {
    Value::Arr(sp.iter().map(|&(a, b)| Value::Arr(vec![Value::Int(a as i64), Value::Int(b as i64)])).collect())
}

fn dispatch(name: &str, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    let pk = crate::pack::current();
    let p: &Pack = &pk;
    let lang_arg = opt_str(args, "lang").map(|l| crate::pystr::to_string(&l));
    let lang = lang_arg.as_deref();
    // `dialect` (TS-STRIP): "ts" or "tsx", the text is a TypeScript file's (.ts, .mts, .cts; .tsx), and the
    // supply-chain tree of any call that reads one (import_time_risk, install_script_risk, js_refusal, the *_tree
    // calls, scan_file's decoded-payload flow, dep_file_issues) reads it in that dialect alone; "js" or none, as
    // JavaScript first, then as TypeScript
    let _dialect = match opt_str(args, "dialect") {
        Some(d) => Some(crate::jsflow::supply::read_as(
            crate::jsflow::supply::Dialect::of_name(&crate::pystr::to_string(&d))
                .ok_or_else(|| CallError::BadArgs(format!("{name}: dialect is \"js\", \"ts\" or \"tsx\"")))?,
        )),
        None => None,
    };
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
        "texts.put" => {
            // {"lengths": [code points, …]} and the texts one after another as the text. The library's entry point
            // keeps the request's bytes as they came (lazaret-ffi); this is the call for a caller that holds code
            // points (a batch's)
            let lengths = put_lengths(args)?;
            texts_put_answer(crate::texts::put(&lengths, &crate::texts::encode_wtf8(text)))?
        }
        "texts.drop" => {
            let ids = args.get("ids").and_then(|l| l.as_arr()).ok_or_else(|| CallError::BadArgs("texts.drop: ids".into()))?;
            let ids = ids.iter().map(text_id).collect::<Result<Vec<_>, _>>()?;
            Value::obj(vec![("dropped", Value::Int(crate::texts::release(&ids) as i64))])
        }
        "texts.info" => {
            let (n, bytes) = crate::texts::held();
            Value::obj(vec![("texts", Value::Int(n as i64)), ("bytes", Value::Int(bytes as i64)),
                            ("max_bytes", Value::Int(crate::texts::MAX_BYTES as i64))])
        }
        "cross_file" => cross_file(p, args, text)?,
        "rs_crate" => rs_crate(args, text.to_vec())?,
        "go_package" => go_package(args, text.to_vec())?,
        "ci_kind" => crate::ci::kind_of(text).map(Value::str).unwrap_or(Value::Null),
        "ci_outline" => {
            let items = matches!(args.get("items"), Some(Value::Bool(true)));
            let seq_blocks = matches!(args.get("seq_blocks"), Some(Value::Bool(true)));
            Value::Arr(crate::ci::outline::outline(text, items, seq_blocks).iter().map(|r| r.to_value(items)).collect())
        }
        "ci_workflow" => Value::obj(vec![
            ("findings", Value::Arr(crate::ci::workflow_findings(p, text).iter().map(crate::ci::found_value).collect())),
            ("hardening", Value::Arr(crate::ci::workflow::hardening(p, text).iter().map(crate::ci::found_value).collect())),
        ]),
        "ci_gitlab" => Value::obj(vec![(
            "hardening",
            Value::Arr(crate::ci::gitlab::hardening(p, text).iter().map(crate::ci::found_value).collect()),
        )]),
        "ci_rule" => {
            let ci = crate::pystr::to_string(&arg_str(args, "ci")?);
            let kind = crate::pystr::to_string(&arg_str(args, "kind")?);
            let detail = args.get("detail").cloned().unwrap_or(Value::Null);
            crate::ci::rule(p, &ci, &kind, &detail).map(|r| crate::ci::rule_value(&r)).unwrap_or(Value::Null)
        }
        "ci_issues" => {
            let path = arg_str(args, "path")?;
            Value::Arr(
                crate::ci::issues(p, &path, text)
                    .iter()
                    .map(|(line, r)| Value::Arr(vec![Value::Int(*line as i64), crate::ci::rule_value(r)]))
                    .collect(),
            )
        }
        "ci_uses" => Value::Arr(
            crate::ci::workflow::uses(text)
                .into_iter()
                .map(|(line, v)| Value::Arr(vec![Value::Int(line as i64), Value::Str(v)]))
                .collect(),
        ),
        "ci_parse_uses" => match crate::ci::workflow::parse_uses(text) {
            Some((kind, name, r, pinned)) => {
                Value::Arr(vec![Value::str(kind), Value::Str(name), Value::Str(r), Value::Bool(pinned)])
            }
            None => Value::Null,
        },
        "ci_check" => {
            // one of the readers' line checks, for the packages' tests and the Actions check
            let check = crate::pystr::to_string(&arg_str(args, "check")?);
            match check.as_str() {
                "pipe_to_shell" => opt_s(crate::ci::workflow::pipe_to_shell(p, text)),
                "install" => opt_s(crate::ci::workflow::install_command(p, text)),
                "publish" => opt_s(crate::ci::workflow::publish_command(p, text)),
                "mr_text" => match crate::ci::gitlab::mr_text(p, text) {
                    Some((var, how)) => Value::Arr(vec![Value::Str(var), Value::str(how)]),
                    None => Value::Null,
                },
                "flow_items" => Value::Arr(crate::ci::gitlab::flow_items(text).iter().map(|i| i.to_value()).collect()),
                "parse_image" => {
                    let (name, tag, digest) = crate::ci::gitlab::parse_image(text);
                    Value::Arr(vec![Value::Str(name), Value::Str(tag), Value::Str(digest)])
                }
                _ => return Err(CallError::BadArgs(format!("ci_check: unknown check {}", check))),
            }
        }
        "ci_logical_lines" => {
            let bad = || CallError::BadArgs("ci_logical_lines: lines".into());
            let mut lines: Vec<(usize, PyStr)> = Vec::new();
            for item in args.get("lines").and_then(|l| l.as_arr()).ok_or_else(bad)? {
                let pair = item.as_arr().ok_or_else(bad)?;
                let n = pair.first().and_then(|v| v.as_i64()).ok_or_else(bad)?;
                let t = pair.get(1).and_then(|v| v.as_str()).ok_or_else(bad)?;
                lines.push((n.max(0) as usize, t.to_vec()));
            }
            Value::Arr(
                crate::ci::workflow::logical_lines(&lines)
                    .into_iter()
                    .map(|(n, t)| Value::Arr(vec![Value::Int(n as i64), Value::Str(t)]))
                    .collect(),
            )
        }
        "autorun_kind" => match crate::autorun::config_kind(text) {
            Some((kind, tool)) => Value::Arr(vec![Value::str(kind), Value::str(tool)]),
            None => Value::Null,
        },
        "autorun_owner" => Value::Str(crate::autorun::owner_dir(text)),
        "autorun_jsonc" => match crate::autorun::parse_jsonc(text) {
            Ok(v) => Value::obj(vec![("ok", v.to_value())]),
            Err((line, reason)) => {
                Value::obj(vec![("error", Value::Arr(vec![Value::Int(line as i64), Value::Str(reason)]))])
            }
        },
        "autorun_entries" => {
            let kind = crate::pystr::to_string(&arg_str(args, "kind")?);
            let tool = crate::pystr::to_string(&arg_str(args, "tool")?);
            let (entries, error) = crate::autorun::entries(&kind, &tool, text);
            Value::obj(vec![
                ("entries", Value::Arr(entries.iter().map(|e| e.to_value()).collect())),
                (
                    "error",
                    error
                        .map(|(line, reason)| Value::Arr(vec![Value::Int(line as i64), Value::Str(reason)]))
                        .unwrap_or(Value::Null),
                ),
            ])
        }
        "autorun_local_command" => Value::Str(crate::autorun::local_command(p, text)),
        "scan_config" => {
            // {path, follow, files: {rel: text or null}, redact, neumaier} -> {"issues": [scan_file's issues…]}, or
            // {"need": [rel…]}: the files of the tree a settings file's commands run, still to be read
            let path = arg_str(args, "path")?;
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let mut files: std::collections::BTreeMap<PyStr, Option<PyStr>> = std::collections::BTreeMap::new();
            if let Some(Value::Obj(items)) = args.get("files") {
                for (k, v) in items {
                    files.insert(k.clone(), v.as_str().map(|x| x.to_vec()));
                }
            }
            let mut tree = crate::autorun::Tree { follow: flag("follow", true), files: &files, need: Vec::new() };
            // (dep absent: a file under a dependency folder is a dependency's, as scan_manifest's registry)
            let dep = flag("dep", crate::collect::is_dependency_manifest(p, &path));
            let opts = crate::config::Options { redact: flag("redact", true), neumaier: flag("neumaier", false), dep };
            match crate::config::scan(p, &path, text, &opts, &mut tree) {
                Ok(issues) => Value::obj(vec![("issues", Value::Arr(issues))]),
                Err(need) => Value::obj(vec![("need", Value::Arr(need.into_iter().map(Value::Str).collect()))]),
            }
        }
        "scan_manifest" => {
            // {path, registry, hooks: [script…] or null, redact, windows} -> {"issues": [scan_file's issues…, a hook's
            // {"cmd"}]}. `windows`: the path is a Windows walk's (os.sep), "\\" separating its folders too (a
            // package's root manifest; WIN-DEP-PATHS); absent, a backslash is a file name's, as on POSIX
            let path = arg_str(args, "path")?;
            // (registry null: a manifest under a dependency folder is a dependency's, collect.rs)
            let registry = match args.get("registry") {
                Some(Value::Bool(b)) => *b,
                _ => crate::collect::is_dependency_manifest(p, &path),
            };
            let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
            let hooks: Option<Vec<PyStr>> = match args.get("hooks") {
                Some(Value::Arr(_)) => Some(arg_strs(args, "hooks")),
                _ => None,
            };
            let windows = flag(args, "windows", false);
            let issues = crate::manifest::scan_manifest(p, &path, text, registry, hooks.as_deref(), redact, windows);
            Value::obj(vec![("issues", Value::Arr(issues))])
        }
        "scan_gyp" => {
            // {path, redact} -> {"issues": [scan_file's issues…, a hook's {"cmd"}]}
            let path = arg_str(args, "path")?;
            let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
            Value::obj(vec![("issues", Value::Arr(crate::manifest::gyp::scan_gyp(p, &path, text, redact)))])
        }
        "manifest_data" => {
            // {path, redact} -> {"data": a package.json's data (manifest::data_value) or null, "issues": why not}: what
            // the npm package's --deps reading reads (core.load_manifest)
            let path = opt_str(args, "path").unwrap_or_default();
            let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
            let (data, early) = crate::manifest::load(p, &path, text, false, None);
            let none = crate::findings::Snippets::new(p, Vec::new(), redact, false).plain();
            Value::obj(vec![
                ("data", data.as_ref().map_or(Value::Null, crate::manifest::data_value)),
                ("issues", Value::Arr(early.iter().map(|f| none.issue(f)).collect())),
            ])
        }
        "binary_check" | "binary_classify" | "binary_disguised" | "pyc_issues" => {
            // the bytes of a file as latin-1 text (a character per byte); `windows`: "\\" separates a path's
            // folders too (os.path on Windows)
            use crate::binary;
            let data = binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            let flag = |k: &str| matches!(args.get(k), Some(Value::Bool(true)));
            let path = opt_str(args, "path").unwrap_or_default();
            let or_null = |v: Option<Value>| v.unwrap_or(Value::Null);
            match name {
                // {check: looks | mpeg_ts | program} -> core.looks_binary, core._mpeg_ts, the registry's
                // _native_program
                "binary_check" => match crate::pystr::to_string(&arg_str(args, "check")?).as_str() {
                    "looks" => Value::Bool(binary::looks_binary(p, &data)),
                    "mpeg_ts" => Value::Bool(binary::mpeg_ts(&data)),
                    "program" => Value::Bool(binary::native_program(p, &data)),
                    other => return Err(CallError::BadArgs(format!("binary_check: no check {other:?}"))),
                },
                // {path, size, context, windows, neumaier, whole, walked, more, props} -> core.classify_binary's
                // issue, or null. FP-OPAQUE-MEDIA: `whole`, the text is the whole file (its first 8,192 bytes the
                // sample); `walked`, a walk of it as its stream passed (media_stream's end); `more`, the caller can
                // give either, and is asked: {"need": "whole"}. FP-GRADLE-WRAPPER: a Gradle wrapper jar asks
                // {"need": "wrapper"} (with `more`, or `whole`), answered with `props`, its gradle-wrapper.properties
                // as latin-1 text (its first GRADLE_PROPERTIES_MAX_BYTES and one more), null when there are none, or
                // {error} when it is there and was not read, and `whole` when the text is the whole jar
                "binary_classify" => {
                    let context = opt_str(args, "context").map(|c| crate::pystr::to_string(&c)).unwrap_or_default();
                    let size = opt_int(args, "size").unwrap_or(data.len() as i64).max(0) as u64;
                    let walked = match args.get("walked") {
                        None | Some(Value::Null) => None,
                        Some(v) => Some(walked_arg(v)?),
                    };
                    let sample = &data[..data.len().min(8192)];
                    // (props: latin-1 text, null when there are none, or {error}: there, and not read)
                    let props = match args.get("props") {
                        None => None,
                        Some(Value::Str(t)) => Some(Ok(Some(binary::bytes_of(t).ok_or_else(|| {
                            CallError::BadArgs("the properties come as latin-1 text".into())
                        })?))),
                        Some(o @ Value::Obj(_)) => Some(Err(o.get("error").and_then(|e| e.as_str()).map(|s| s.to_vec())
                            .unwrap_or_default())),
                        Some(_) => Some(Ok(None)),
                    };
                    let more = if let Some(props) = props.as_ref().filter(|_| crate::gradle::wrapper_path(&path, flag("windows"))) {
                        let props = match props {
                            Ok(Some(b)) => crate::gradle::Sibling::Bytes(b),
                            Ok(None) => crate::gradle::Sibling::None,
                            Err(e) => crate::gradle::Sibling::Error(e),
                        };
                        binary::More::Wrapper { jar: flag("whole").then_some(&data[..]), props }
                    } else if flag("whole") {
                        binary::More::Whole(&data)
                    } else if let Some(w) = &walked {
                        binary::More::Walked(w)
                    } else if flag("more") {
                        binary::More::Ask
                    } else {
                        binary::More::No
                    };
                    match binary::classify_more(p, &path, sample, size, &context, flag("windows"), flag("neumaier"), more) {
                        binary::Classified::Issue(v) => v,
                        // (a keystore that is an opaque blob too: both findings)
                        binary::Classified::Issues(v) => Value::Arr(v),
                        binary::Classified::Quiet => Value::Null,
                        binary::Classified::Need => Value::obj(vec![("need", Value::str("whole"))]),
                        binary::Classified::Wrapper => Value::obj(vec![("need", Value::str("wrapper"))]),
                    }
                }
                // {path, windows} -> core.disguised_binary's issue, or null
                "binary_disguised" => or_null(binary::disguised(p, &path, &data, flag("windows"))),
                // {path, has_source} -> core.pyc_issues
                _ => Value::Arr(binary::pyc_issues(p, &path, &data, flag("has_source"))),
            }
        }
        "model_sniff" => {
            // {path, windows} + a file's first bytes (HEADER_SAMPLE_BYTES of them) as latin-1 text -> whether it may be a
            // model file (pickle::sniff): one to read whole with model_file
            let data = crate::binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            let path = opt_str(args, "path").unwrap_or_default();
            Value::Bool(crate::pickle::sniff(p, &path, &data, flag(args, "windows", false)))
        }
        "model_file" => {
            // {path, size, limit, windows} + a file's bytes as latin-1 text (all of them, or its first ones when the
            // file is larger, `size`, than the scan reads, `limit`) -> null (not a model file) or {"kind", "issues",
            // "imports": [[module, name, how]], "opaque"}. With {pieces: [[offset, length]], last}, the text is those
            // pieces of the file one after another (its first bytes among them): a zip model file read by range
            // (pickle::read_ranges) -> null, the report, or {"need": [[offset, length]]} (the ranges to read before
            // asking again; none with `last`, which makes what is still needed SC-TRUNCATED)
            let data = crate::binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            let path = opt_str(args, "path").unwrap_or_default();
            let size = opt_int(args, "size").unwrap_or(data.len() as i64).max(0) as u64;
            let limit = opt_int(args, "limit").map(|l| l.max(0) as u64);
            let windows = flag(args, "windows", false);
            if let Some(layout) = args.get("pieces").and_then(|v| v.as_arr()) {
                let layout = layout_arg(layout)?;
                let src = crate::pickle::zip::Bytes::pieces(size, pieces_of(&layout, &data)?, crate::pickle::range_cap(p));
                match crate::pickle::read_ranges(p, &path, &src, windows, flag(args, "last", false)) {
                    crate::pickle::Ranged::Not => Value::Null,
                    crate::pickle::Ranged::Report(r) => crate::pickle::report_value(&r),
                    crate::pickle::Ranged::Need(n) => Value::obj(vec![("need", ranges_value(&n))]),
                }
            } else {
                match crate::pickle::read_file(p, &path, &data, size, limit, windows) {
                    None => Value::Null,
                    Some(r) => crate::pickle::report_value(&r),
                }
            }
        }
        "model_own" => {
            // {models: [[path, dep, [[module, name, how]], [[module, name, issue]]]], files: [[path, dep]]} ->
            // [[path, issue]]: the model files' globals of the scanned package's own modules (INFO), and the calls
            // with text they hold (MAJOR: pickle::own_imports). A third item of a file, a text, is not read.
            let models: Vec<crate::pickle::ModelIn> = arr_arg(args, "models").iter().filter_map(|m| {
                let a = m.as_arr()?;
                Some((a.first()?.as_str()?.to_vec(), matches!(a.get(1), Some(Value::Bool(true))),
                      crate::pickle::imports_of(a.get(2)), crate::pickle::calls_of(a.get(3))))
            }).collect();
            let files: Vec<(PyStr, bool, Option<Vec<u32>>)> = arr_arg(args, "files").iter().filter_map(|f| {
                let a = f.as_arr()?;
                Some((a.first()?.as_str()?.to_vec(), matches!(a.get(1), Some(Value::Bool(true))),
                      a.get(2).and_then(|t| t.as_str()).map(|t| t.to_vec())))
            }).collect();
            Value::Arr(crate::pickle::own_imports(p, &models, &files).into_iter()
                .map(|(path, issue)| Value::Arr(vec![Value::Str(path), issue])).collect())
        }
        "media_walk" => {
            // a whole file as latin-1 text -> what it is, walked by its structure to its end (media::walk):
            // {"is": kind}, {"not": kind, "why"} or {"unknown": true}
            let data = crate::binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            walked_value(&crate::media::walk(&data))
        }
        "media_stream" => {
            // {state: null or the last answer's, offset, eof} + the next chunk of a file, from `offset` (where the last
            // one ended, or the answer's `next` when the host passes over the bytes the walk skips), as latin-1 text
            // -> {"state", "next": the offset of the next byte the walk reads, "end": null while it runs, else
            // media_walk's answer}
            let data = crate::binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            let mut w = media_state_arg(args.get("state"))?;
            let offset = opt_int(args, "offset").unwrap_or(0).max(0) as u64;
            crate::media::feed(&mut w, offset, &data, flag(args, "eof", false));
            Value::obj(vec![
                ("next", Value::Int(w.at.min(crate::media::MAX_OFFSET) as i64)),
                ("end", w.walked().as_ref().map_or(Value::Null, walked_value)),
                ("state", media_state_value(&w)),
            ])
        }
        "pth_stream" => {
            // {state: null or the last answer's, end} + the next chunk of a .pth file too large to read whole, as
            // latin-1 text -> {"state", "lines": [[line, its bytes from its import start as latin-1 text]], "cuts"}:
            // the lines site.py runs (binary::pth_stream; FP-MODEL-FILES)
            let data = crate::binary::bytes_of(text)
                .ok_or_else(|| CallError::BadArgs("the bytes come as latin-1 text: a character past U+00FF".into()))?;
            let st = pth_state_arg(args.get("state"))?;
            let (st, got) = crate::binary::pth_stream(p, &st, &data, flag(args, "end", false));
            Value::obj(vec![
                ("state", Value::obj(vec![
                    ("line", Value::Int(st.line as i64)),
                    ("cr", Value::Bool(st.cr)),
                    ("carry", Value::Str(st.carry.iter().map(|&b| b as u32).collect())),
                    ("whole", Value::Bool(st.whole)),
                    ("keeping", Value::Bool(st.keeping)),
                    ("skipping", Value::Bool(st.skipping)),
                    ("kept", Value::Int(st.kept as i64)),
                    ("full", Value::Bool(st.full)),
                ])),
                ("lines", pth_lines_value(&got.lines)),
                ("cuts", Value::Arr(got.cuts.iter().map(|c| Value::str(c)).collect())),
            ])
        }
        "pth_kept" => {
            // {lines: [[line, latin-1 text]], redact, neumaier} -> core.pth_issues' issues for the lines pth_stream
            // kept, at their lines
            let lines = pth_lines_arg(args.get("lines"))?;
            let f = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            Value::Arr(crate::binary::pth_kept_issues(p, &lines, f("redact", true), f("neumaier", false)))
        }
        "pth_issues" => {
            // {redact, neumaier} + a .pth file's text -> core.pth_issues' issues
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            Value::Arr(crate::binary::pth_issues(p, text, flag("redact", true), flag("neumaier", false)))
        }
        "deps_hooks" => deps_hooks(p, args)?,
        "deps_script" => {
            // {rel, project, own, redact, neumaier} + the text of a file a hook runs -> what it does (deps::script_facts);
            // `own`: the name of the package whose hook runs it, when known (D-9c)
            let o = deps_opts(args);
            let release = opt_str(args, "own");
            crate::deps::script_facts(p, &arg_str(args, "rel")?, text, flag(args, "project", false), release.as_deref(), &o)
        }
        "deps_targets" => crate::deps::file_targets(p, text),
        "deps_files" => deps_files(p, args)?,
        "b64_descriptors" => b64_descriptors(p, args)?,
        "dep_file_issues" => {
            // {lang, declared, own, redact, neumaier} + a dependency's file -> [SC-IMPORT-RISK or null, SC-AGENT-HIJACK
            // or null]; `declared` and `own`: its package's names and its own name (D-12b, D-9c), when known
            let declared = args.get("declared").filter(|d| !matches!(d, Value::Null)).map(|_| arg_strs(args, "declared"));
            let release = opt_str(args, "own");
            // `unread` (BIG-BUNDLE-TAIL, the review of Oct 20): where a reading of the text met a limit before its end,
            // or the supply-chain tree did not read it whole (budget::cut), a third element, its words, and the call
            // answers with what it found, where without it such a call answers as one that ran out (a file read whole:
            // the two elements, as before)
            let unread = flag(args, "unread", false);
            crate::deps::dep_file_issues(p, text, lang, declared.as_deref(), release.as_deref(), &deps_opts(args), unread)
        }
        "agent_issue" => {
            // {agent, flag, line, context, redact, neumaier} + the file's text -> its SC-AGENT-HIJACK issue
            let line = opt_int(args, "line").unwrap_or(1).max(0) as usize;
            let (agent, flag_) = (arg_str(args, "agent")?, arg_str(args, "flag")?);
            crate::deps::agent_issue_of(p, text, &agent, &flag_, line, flag(args, "context", false), &deps_opts(args))
        }
        "declared_names" => crate::deps::declared_names(p, &crate::pystr::to_string(&arg_str(args, "kind")?), text),
        "issue_make" => {
            // {items: [[rule {id, name, type, sev, msg, why, fix, ref}, line, col or null]…], redact, context, neumaier}
            // + the file's lines joined by "\n" -> {"issues": [mk_issue's…]}; `context`: the file's entropy literals
            // redacted too (core's _Redactor over these lines)
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let items = args.get("items").and_then(|v| v.as_arr()).unwrap_or(&[]);
            let issues = crate::redact::make_issues(p, text, items, flag("redact", true), flag("context", false), flag("neumaier", false));
            Value::obj(vec![("issues", Value::Arr(issues))])
        }
        "redact_text" => {
            // {mode, context, neumaier}: core._redact_text (mode "text", the default: the PEM blocks, the line patterns;
            // with `context`, a file's lines joined by "\n", its entropy literals too), _redact_context_line ("line":
            // the line patterns alone) or _SecretLiterals(context).redact ("literals": the literals alone)
            let neumaier = matches!(args.get("neumaier"), Some(Value::Bool(true)));
            let lits = opt_str(args, "context").map(|c| crate::redact::literals(p, &c, neumaier));
            let mode = opt_str(args, "mode").map(|m| crate::pystr::to_string(&m)).unwrap_or_default();
            Value::Str(match mode.as_str() {
                "line" => crate::findings::redact_context_line(p, text),
                "literals" => match &lits {
                    Some(l) => l.redact(p, text),
                    None => text.to_vec(),
                },
                _ => crate::redact::redact_text(p, text, lits.as_ref()),
            })
        }
        "pem_lines" => {
            // the lines (of a text split at "\n") inside a PEM private key's block: core._pem_block_lines
            let lines = crate::pystr::split_char(text, '\n' as u32);
            let mut found: Vec<usize> = crate::findings::pem_block_lines(p, &lines).into_iter().collect();
            found.sort_unstable();
            Value::Arr(found.into_iter().map(|k| Value::Int(k as i64)).collect())
        }
        "redact_issues" => {
            // {issues: [[rule, line, snipStart or null, snippet or null, msg or null, cmd or null]…], redact} ->
            // {"issues": [[snippet, msg, cmd]…]}: core.redact_result's sweep
            let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
            let issues = args.get("issues").and_then(|v| v.as_arr()).unwrap_or(&[]);
            Value::obj(vec![("issues", Value::Arr(crate::redact::redact_issues(p, issues, redact)))])
        }
        "redact_file" => {
            // {issues: [[lines or null, msg or null, cmd or null]…], neumaier} + the file's scan lines joined by "\n" ->
            // {"issues": [[shown, msg, cmd]…]}: core.redact_file_issues for one file (`lines`: the indices of the file's
            // lines a snippet still shows raw; `shown`: each as the scan's snippets show it)
            let neumaier = matches!(args.get("neumaier"), Some(Value::Bool(true)));
            let issues = args.get("issues").and_then(|v| v.as_arr()).unwrap_or(&[]);
            Value::obj(vec![("issues", Value::Arr(crate::redact::redact_file(p, text, issues, neumaier)))])
        }
        "clip_line" => {
            // {col or null} -> core.clip_snippet_line
            let col = args.get("col").and_then(|v| v.as_i64()).filter(|&c| c >= 0).map(|c| c as usize);
            Value::Str(crate::findings::clip_snippet_line(p, text, col))
        }
        "manifest_check" => {
            // one of the manifest readers' parts, for the packages' tests: json (json.loads: {"ok": repr, "type"} or
            // {"error": "line L column C"} or {"depth": true}), literal (ast.literal_eval of the stripped text: {"ok",
            // "type"} or {"error": the exception's name} or {"depth": true}), key_lines {section} ({key: line}),
            // dep_url_risk ([reason…]), gyp_command {pymod} (an expansion's command as it runs), is_root
            use crate::manifest::{self, gyp, pyjson, pylit, pyval};
            let check = crate::pystr::to_string(&arg_str(args, "check")?);
            let shown = |v: &pyval::PyVal| {
                Value::obj(vec![("ok", Value::Str(pyval::repr(v))), ("type", Value::Str(u(v.type_name())))])
            };
            match check.as_str() {
                "literal" => match pylit::literal_eval(crate::pystr::strip(text), None, 0) {
                    Ok(v) => shown(&v),
                    Err(pylit::Fail::Depth) => Value::obj(vec![("depth", Value::Bool(true))]),
                    Err(pylit::Fail::Error(name)) => Value::obj(vec![("error", Value::Str(u(name)))]),
                },
                "json" if pyjson::depth_exceeds(text, p.usize("MAX_MANIFEST_DEPTH")) => Value::obj(vec![("depth", Value::Bool(true))]),
                "json" => match pyjson::loads(text, None) {
                    Ok(v) => shown(&v),
                    Err(pyjson::Error::Depth) => Value::obj(vec![("depth", Value::Bool(true))]),
                    Err(e @ pyjson::Error::IntDigits(_)) => Value::obj(vec![("error", Value::Str(u(&pyjson::message(text, e))))]),
                    Err(pyjson::Error::At(at, _)) => Value::obj(vec![("error", Value::Str(u(&pyjson::error_where(text, at))))]),
                },
                "key_lines" => {
                    let section = opt_str(args, "section").unwrap_or_else(|| u("scripts"));
                    let mut found: Vec<(PyStr, usize)> = manifest::key_lines(text, &crate::pystr::to_string(&section)).into_iter().collect();
                    found.sort();
                    Value::Obj(found.into_iter().map(|(k, l)| (k, Value::Int(l as i64))).collect())
                }
                "dep_url_risk" => Value::Arr(manifest::dependency_url_risk(p, text).into_iter().map(Value::Str).collect()),
                "gyp_command" => Value::Str(gyp::hook_command_of(p, text, matches!(args.get("pymod"), Some(Value::Bool(true))))),
                "is_root" => Value::Bool(manifest::is_root(text)),
                _ => return Err(CallError::BadArgs(format!("manifest_check: unknown check {}", check))),
            }
        }
        "config_check" => {
            // one of the config reader's checks, for the packages' tests: secret_col {netrc, skip}, redact_values
            // {netrc}, comment_spans, key_follows {end, following}, documentation_token, secret_key, secret_value
            let check = crate::pystr::to_string(&arg_str(args, "check")?);
            let netrc = matches!(args.get("netrc"), Some(Value::Bool(true)));
            match check.as_str() {
                "secret_col" => {
                    let skip: Vec<usize> = args
                        .get("skip")
                        .and_then(|v| v.as_arr())
                        .map(|a| a.iter().filter_map(|x| x.as_i64()).map(|x| x.max(0) as usize).collect())
                        .unwrap_or_default();
                    match crate::config::secret_col(p, text, netrc, &skip) {
                        Some(col) => Value::Int(col as i64),
                        None => Value::Null,
                    }
                }
                "redact_values" => Value::Str(crate::config::redact_values(p, text, netrc)),
                "comment_spans" => Value::Arr(
                    crate::config::comment_spans(text)
                        .into_iter()
                        .map(|(a, b)| Value::Arr(vec![Value::Int(a as i64), Value::Int(b as i64)]))
                        .collect(),
                ),
                "key_follows" => {
                    let end = args.get("end").and_then(|v| v.as_i64()).unwrap_or(0).max(0) as usize;
                    let following = arg_strs(args, "following");
                    let refs: Vec<&[u32]> = following.iter().map(|x| x.as_slice()).collect();
                    Value::Bool(crate::config::key_follows(p, text, end.min(text.len()), &refs))
                }
                "documentation_token" => Value::Bool(crate::config::documentation_token(p, text)),
                "secret_key" => Value::Bool(crate::config::secret_key(p, text)),
                "secret_value" => Value::Bool(crate::config::secret_value(p, text)),
                _ => return Err(CallError::BadArgs(format!("config_check: unknown check {}", check))),
            }
        }
        "agentdoc_kind" => crate::agentdoc::is_agent_doc(text).map(Value::str).unwrap_or(Value::Null),
        "agentdoc_issues" => {
            // RA-3: an agent skill/instruction file — {path, follow, files, dep} -> {"issues":[[line,rule]…]} or
            // {"need":[rel…]} (the scripts of the skill's folder it has yet to be given), like autorun_issues. dep: a
            // dependency's file (CRITICAL / MAJOR), else the project's own (INFO); absent, a file under a dependency
            // folder is a dependency's
            let path = arg_str(args, "path")?;
            let follow = !matches!(args.get("follow"), Some(Value::Bool(false)));
            let dep = match args.get("dep") {
                Some(Value::Bool(b)) => *b,
                _ => crate::collect::is_dependency_manifest(p, &path),
            };
            let mut files: std::collections::BTreeMap<PyStr, Option<PyStr>> = std::collections::BTreeMap::new();
            if let Some(Value::Obj(items)) = args.get("files") {
                for (k, v) in items {
                    files.insert(k.clone(), v.as_str().map(|x| x.to_vec()));
                }
            }
            let mut tree = crate::autorun::Tree { follow, files: &files, need: Vec::new() };
            match crate::agentdoc::issues(p, &path, text, &mut tree, dep) {
                Ok(found) => Value::obj(vec![(
                    "issues",
                    Value::Arr(
                        found
                            .iter()
                            .map(|(line, r)| Value::Arr(vec![Value::Int(*line as i64), crate::ci::rule_value(r)]))
                            .collect(),
                    ),
                )]),
                Err(need) => Value::obj(vec![("need", Value::Arr(need.into_iter().map(Value::Str).collect()))]),
            }
        }
        "autorun_issues" => {
            // {path, follow, files: {rel: text or null}} -> {"issues": [[line, rule]…]}, or {"need": [rel…]}: the
            // files of the tree it has yet to be given (the package reads them and asks again)
            let path = arg_str(args, "path")?;
            let follow = !matches!(args.get("follow"), Some(Value::Bool(false)));
            let mut files: std::collections::BTreeMap<PyStr, Option<PyStr>> = std::collections::BTreeMap::new();
            if let Some(Value::Obj(items)) = args.get("files") {
                for (k, v) in items {
                    files.insert(k.clone(), v.as_str().map(|x| x.to_vec()));
                }
            }
            let mut tree = crate::autorun::Tree { follow, files: &files, need: Vec::new() };
            match crate::autorun::issues(p, &path, text, &mut tree) {
                Ok(found) => Value::obj(vec![(
                    "issues",
                    Value::Arr(
                        found
                            .iter()
                            .map(|(line, r)| Value::Arr(vec![Value::Int(*line as i64), crate::ci::rule_value(r)]))
                            .collect(),
                    ),
                )]),
                Err(need) => Value::obj(vec![("need", Value::Arr(need.into_iter().map(Value::Str).collect()))]),
            }
        }
        "cargo_layout" => {
            let l = crate::vendor::cargo_layout(text);
            Value::obj(vec![
                ("build", match l.build {
                    Some(crate::vendor::Build::Path(p)) => Value::Str(p),
                    Some(crate::vendor::Build::Off) => Value::Bool(false),
                    None => Value::Null,
                }),
                ("lib", l.lib_path.map(Value::Str).unwrap_or(Value::Null)),
                ("proc_macro", l.proc_macro.map(Value::Bool).unwrap_or(Value::Null)),
            ])
        }
        // {"files": [[path, length], …]} (the files' texts, concatenated) -> [the import paths of a file's build, or
        // null for one the parser refuses, …] (F-06: the vendored folders a --deps scan's Go files import)
        "go_imports" => {
            let files = package_files(args, text.len()).map_err(|m| CallError::BadArgs(format!("go_imports: {m}")))?;
            let text = std::sync::Arc::new(text.to_vec());
            let got = on_own_stack(move || {
                files.iter().map(|(_, a, b)| crate::goread::file_imports(&text[*a..*b])).collect::<Vec<_>>()
            });
            Value::Arr(got.into_iter().map(|f| f.map_or(Value::Null, |v| strs(&v))).collect())
        }
        // {"packages": true}: the packages it lists (F-06), not its modules
        "go_vendored_modules" if matches!(args.get("packages"), Some(Value::Bool(true))) => strs(&crate::vendor::vendored_packages(text)),
        "go_vendored_modules" => strs(&crate::vendor::vendored_modules(text)),
        "js_flow" => js_flow(args, text)?,
        "py_flow" => py_flow(args, text)?,
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
            let (spans, text) = (flag("spans", false), text.to_vec());
            Value::Raw(on_own_stack(move || crate::jsparse::to_json(&text, ts, jsx, spans)))
        }
        "js_loads" => {
            // [[specifier, line, how, package]] of what a JavaScript module loads when it runs (D-13; the npm package
            // the specifier names, or null), or null when it does not parse; "path": its file name, for the dialect
            let path = match args.get("path") {
                Some(_) => arg_str(args, "path")?,
                None => u("module.js"),
            };
            let text = text.to_vec();
            match on_own_stack(move || crate::jsloads::js_loads(&text, &path)) {
                Some(found) => Value::Arr(
                    found
                        .into_iter()
                        .map(|(spec, line, how)| {
                            let package = crate::jsloads::npm_package(&spec).map(Value::Str).unwrap_or(Value::Null);
                            Value::Arr(vec![Value::Str(spec), Value::Int(line as i64), Value::str(how), package])
                        })
                        .collect(),
                ),
                None => Value::Null,
            }
        }
        "js_refusal" => {
            // [line, reason] of the parser's refusal of a JavaScript text the supply-chain model would read on its tree
            // (TypeScript's reading refusing it too), or null: the parse alone (JS-PARSE-STRICT, the registry's
            // report of an install script whose tree its test could not read)
            match crate::jsflow::supply::parse_refusal(text) {
                Some((line, reason)) => Value::Arr(vec![Value::Int(line as i64), Value::Str(reason)]),
                None => Value::Null,
            }
        }
        "py_parse" => {
            // ast.parse(text) as Python 3.13 builds it, as JSON (pyparse/out.rs),
            // or {"error": {"line": n, "reason": …}}; "spans": each node's start
            // and end (code points) too
            let spans = matches!(args.get("spans"), Some(Value::Bool(true)));
            let text = text.to_vec();
            Value::Raw(on_own_stack(move || crate::pyparse::to_json(&text, spans)))
        }
        "scan_file" => {
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let opts = crate::scanfile::Options { dep: flag("dep", false), redact: flag("redact", true), neumaier: flag("neumaier", false) };
            if !opts.dep {
                // project mode (Q-1): the rules, the passes after them, the suppression markers and the cap
                let model = crate::taint::Model::from_args(p, args).map_err(|m| CallError::BadArgs(format!("scan_file: {m}")))?;
                if flag("metrics", false) {
                    // and the file's line metrics (Q-1 step 4): {"issues": […], "metrics": file_metrics' answer}
                    let (issues, m) = crate::scanfile::scan_project_metrics(p, text, lang, flag("jsx", true), &opts, &model, true);
                    return Ok(Value::obj(vec![("issues", Value::Arr(issues)), ("metrics", metrics_value(&m.expect("asked for")))]));
                }
                return Ok(Value::Arr(crate::scanfile::scan_project(p, text, lang, flag("jsx", true), &opts, &model)));
            }
            Value::Arr(crate::scanfile::scan_file(p, text, lang, flag("jsx", true), &opts))
        }
        "taint_scan" => {
            // project mode's intra-file taint alone (core.taint_scan): its T-* findings, before markers and the cap
            let flag = |k: &str, d: bool| match args.get(k) {
                Some(Value::Bool(b)) => *b,
                _ => d,
            };
            let model = crate::taint::Model::from_args(p, args).map_err(|m| CallError::BadArgs(format!("taint_scan: {m}")))?;
            let ctx = crate::filectx::FileCtx::new(p, text, crate::filectx::Lang::from(lang), flag("jsx", true));
            let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
            let snippets = crate::findings::Snippets::new(p, lines, flag("redact", true), flag("neumaier", false));
            let mut found = Vec::new();
            crate::taint::scan(&ctx, &model, &mut found);
            Value::Arr(found.iter().map(|f| snippets.issue(f)).collect())
        }
        "taint_helpers" => {
            // (Q-4) {"files": [[path, length], …] (a project's own Python files, their texts concatenated as the
            // text), "taint": the configured part of the model} -> for each file, what it imports from the others
            // that the intra-file taint pass follows calls into: its scan_file's "helpers", or null
            let files = flow_files(args, text, "taint_helpers")?;
            let model = crate::taint::Model::from_args(p, args).map_err(|m| CallError::BadArgs(format!("taint_helpers: {m}")))?;
            let slices = crate::taint::follow::project_slices(p, &files, &model);
            Value::Arr(slices.into_iter().map(|s| s.map_or(Value::Null, |s| s.to_value())).collect())
        }
        "secrets.providers" => {
            // the table's providers: where each credential would go, for a report's notice before any call
            let t = crate::secrets::table(p).as_ref().map_err(|m| CallError::BadArgs(format!("secrets.providers: {m}")))?;
            Value::Arr(t.iter().map(|q| Value::obj(vec![
                ("id", Value::str(&q.id)), ("label", Value::str(&q.label)), ("host", Value::str(&q.host)),
                ("path", Value::str(&q.path)), ("parts", Value::Arr(q.part_names().into_iter().map(Value::str).collect())),
            ])).collect())
        }
        "secrets.identify" => {
            // the providers whose one-part pattern matches all of the text
            let t = crate::secrets::table(p).as_ref().map_err(|m| CallError::BadArgs(format!("secrets.identify: {m}")))?;
            Value::Arr(crate::secrets::identify(t, text).iter().map(|id| Value::str(id)).collect())
        }
        "secrets.find" => {
            // {"lines": [n, …]} and those lines of one file, joined by "\n", as the text -> the credentials the providers
            // name in them: [{"provider", "parts": {name: text}, "lines": [n, …]}] (`lazaret scan --verify-secrets`)
            let bad = |m: &str| CallError::BadArgs(format!("secrets.find: {m}"));
            let t = crate::secrets::table(p).as_ref().map_err(|m| bad(m))?;
            let numbers: Vec<i64> = match args.get("lines").and_then(|l| l.as_arr()) {
                Some(list) => list.iter().map(|n| n.as_i64()).collect::<Option<_>>().ok_or_else(|| bad("a line is not a number"))?,
                None => return Err(bad("no lines")),
            };
            let texts: Vec<&[u32]> = text.split(|&c| c == '\n' as u32).collect();
            if texts.len() != numbers.len() {
                return Err(bad("the text is not one line for each number"));
            }
            let lines: Vec<(i64, Vec<u32>)> = numbers.into_iter().zip(texts).map(|(n, t)| (n, t.to_vec())).collect();
            Value::Arr(crate::secrets::find(t, &lines).into_iter().map(|f| Value::obj(vec![
                ("provider", Value::str(&f.provider)),
                ("parts", Value::Obj(f.parts.into_iter().map(|(name, v)| (u(&name), Value::Str(v))).collect())),
                ("lines", Value::Arr(f.lines.into_iter().map(Value::Int).collect())),
            ])).collect())
        }
        "secrets.request" => {
            // {"provider": id (the pack's) | "entry": {…} (one of the caller's), "parts": {name: text}, "time":
            // "YYYYMMDDTHHMMSSZ"} -> the request, or {"refused": why} when the parts are not the provider's format
            let bad = |m: String| CallError::BadArgs(format!("secrets.request: {m}"));
            let owned;
            let q = match (args.get("entry"), args.get("provider")) {
                (Some(entry), _) => {
                    owned = crate::secrets::provider_of(entry).map_err(bad)?;
                    &owned
                }
                (None, Some(Value::Str(id))) => crate::secrets::by_id(p, &crate::pystr::to_string(id)).map_err(bad)?,
                _ => return Err(bad("no provider".into())),
            };
            let time = args.get("time").and_then(|t| t.as_string()).filter(|t| crate::secrets::is_amz_date(t))
                .ok_or_else(|| bad("time is not YYYYMMDDTHHMMSSZ".into()))?;
            let given = args.get("parts").and_then(|v| v.as_obj()).ok_or_else(|| bad("parts is not a mapping".into()))?;
            // (a part that is not text is not this provider's format: nothing is sent)
            let parts: Option<Vec<(String, Vec<u32>)>> =
                given.iter().map(|(k, v)| v.as_str().map(|s| (crate::pystr::to_string(k), s.to_vec()))).collect();
            match parts.ok_or(crate::secrets::NOT_THIS_FORMAT).and_then(|parts| crate::secrets::request(q, &parts, &time)) {
                Ok(r) => Value::obj(vec![
                    ("method", Value::str(&r.method)), ("host", Value::str(&r.host)), ("path", Value::str(&r.path)),
                    ("headers", Value::Arr(r.headers.iter().map(|(n, v)| Value::Arr(vec![Value::str(n), Value::str(v)])).collect())),
                    ("secret_headers", Value::Arr(r.secret_headers.iter().map(|n| Value::str(n)).collect())),
                    ("body", r.body.as_deref().map_or(Value::Null, Value::str)),
                ]),
                Err(why) => Value::obj(vec![("refused", Value::str(why))]),
            }
        }
        "secrets.judge" => {
            // {"provider": id | "answers": [rules], "status": n, "truncated": bool, "secrets": [the credential's parts]}
            // and the answer's body as the text, one code point a byte -> [outcome, why, who]
            let bad = |m: String| CallError::BadArgs(format!("secrets.judge: {m}"));
            let owned;
            let rules: &[crate::secrets::Rule] = match (args.get("answers"), args.get("provider")) {
                (Some(Value::Arr(answers)), _) => {
                    owned = crate::secrets::rules_of(answers).map_err(bad)?;
                    &owned
                }
                (None, Some(Value::Str(id))) => crate::secrets::by_id(p, &crate::pystr::to_string(id)).map_err(bad)?.rules(),
                _ => return Err(bad("no provider".into())),
            };
            let status = args.get("status").and_then(|s| s.as_i64()).ok_or_else(|| bad("status is not a number".into()))?;
            let truncated = matches!(args.get("truncated"), Some(Value::Bool(true)));
            let secrets: Vec<Vec<u32>> = args.get("secrets").and_then(|s| s.as_arr()).unwrap_or(&[])
                .iter().filter_map(|s| s.as_str().map(|s| s.to_vec())).collect();
            if text.len() > crate::secrets::MAX_ANSWER_BYTES || text.iter().any(|&c| c > 0xFF) {
                return Err(bad(format!("the body is at most {} bytes, one code point each", crate::secrets::MAX_ANSWER_BYTES)));
            }
            let body: Vec<u8> = text.iter().map(|&c| c as u8).collect();
            let (outcome, why, who) = crate::secrets::judge(rules, status, &body, truncated, &secrets);
            Value::Arr(vec![Value::str(outcome.as_str()), Value::Str(why), who.map_or(Value::Null, Value::Str)])
        }
        "result" => {
            let bad = |m: String| CallError::BadArgs(format!("result: {m}"));
            // a scan's result from its findings and files (result.rs; core.build_result's, npm's buildResult's)
            let issues = crate::result::findings_arg(args.get("issues")).map_err(bad)?;
            let files = crate::result::files_arg(args.get("files")).map_err(bad)?;
            crate::result::result(p, &issues, &files).map_err(bad)?
        }
        "regrade" => {
            let bad = |m: String| CallError::BadArgs(format!("regrade: {m}"));
            // a result graded again after its findings changed (result.rs; core.regrade's, npm's regrade's)
            let issues = crate::result::findings_arg(args.get("issues")).map_err(bad)?;
            let conditions = crate::result::conditions_arg(args.get("conditions")).map_err(bad)?;
            crate::result::regrade(p, &issues, &conditions).map_err(bad)?
        }
        "collect_dir" | "collect_file" | "collect_pycache" | "collect_issue" => collect_call(p, name, args, text)?,
        "collect_check" => match crate::pystr::to_string(&arg_str(args, "check")?).as_str() {
            // {check: config_name, name} -> configsecrets.is_config_file; {check: own_report} + a text ->
            // configsecrets.own_report
            "config_name" => Value::Bool(crate::collect::is_config_file(p, &arg_str(args, "name")?)),
            "own_report" => Value::Bool(crate::collect::own_report(text)),
            other => return Err(CallError::BadArgs(format!("collect_check: no check {other:?}"))),
        },
        "gate_report" => {
            // {checked, issues: [[issue, --show-secrets' line or null]], conditions: [[label, ok]], quiet, color,
            // windows, width, redact} -> {"lines", "exit"}
            let flag = |k: &str| matches!(args.get(k), Some(Value::Bool(true)));
            let issues: Vec<(Value, Option<Value>)> = arr_arg(args, "issues").iter().map(|it| match it.as_arr() {
                Some(a) if a.len() == 2 => (a[0].clone(), match &a[1] { Value::Null => None, v => Some(v.clone()) }),
                _ => (it.clone(), None),
            }).collect();
            let conditions = crate::result::conditions_arg(args.get("conditions")).map_err(|m| CallError::BadArgs(format!("gate_report: {m}")))?;
            let r = crate::gate::Report {
                checked: opt_int(args, "checked").unwrap_or(0).max(0) as usize,
                issues: &issues,
                conditions: &conditions,
                quiet: flag("quiet"),
                color: flag("color"),
                windows: flag("windows"),
                width: opt_int(args, "width").unwrap_or(100),
                redact: !matches!(args.get("redact"), Some(Value::Bool(false))),
            };
            let (lines, exit) = crate::gate::report(p, &r);
            Value::obj(vec![("lines", Value::Arr(lines.into_iter().map(Value::Str).collect())), ("exit", Value::Int(exit))])
        }
        "gate_source" => {
            // {modes: [an index entry's mode, or null]} -> ["blob" | "skip" | "disk"]
            Value::Arr(arr_arg(args, "modes").iter().map(|m| Value::str(crate::gate::source(m.as_str()))).collect())
        }
        "gate_why" => {
            // {kind, detail} -> why a file the commit holds could not be read for the scan
            let kind = crate::pystr::to_string(&arg_str(args, "kind")?);
            crate::gate::why(&kind, &opt_str(args, "detail").unwrap_or_default())
                .map(Value::Str)
                .ok_or_else(|| CallError::BadArgs(format!("gate_why: no kind {kind:?}")))?
        }
        "test_paths" => {
            // {paths} -> {"test": [is a test path], "unused": [is code the package does not run when it is used]}
            let paths: Vec<PyStr> = arr_arg(args, "paths").iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect();
            Value::obj(vec![
                ("test", Value::Arr(paths.iter().map(|r| Value::Bool(crate::collect::is_test_path(p, r))).collect())),
                ("unused", Value::Arr(paths.iter().map(|r| Value::Bool(crate::collect::not_used_code(p, r))).collect())),
            ])
        }
        "demote_tests" => {
            // {issues: [[rule, sev, file, msg]], reachable: [paths]} -> [the demoted message, or null]
            let mut issues = Vec::new();
            for (k, it) in arr_arg(args, "issues").iter().enumerate() {
                let a = it.as_arr().filter(|a| a.len() == 4).ok_or_else(|| CallError::BadArgs(format!("demote_tests: issue {k}")))?;
                let t = |j: usize| a[j].as_str().map(|s| s.to_vec()).unwrap_or_default();
                issues.push([t(0), t(1), t(2), t(3)]);
            }
            let reachable: Vec<PyStr> = arr_arg(args, "reachable").iter().filter_map(|x| x.as_str().map(|s| s.to_vec())).collect();
            Value::Arr(crate::collect::demoted(p, &issues, &reachable).into_iter().map(|m| m.map_or(Value::Null, Value::Str)).collect())
        }
        "baseline_fingerprints" => {
            // {issues: [a finding, …]} -> {"fingerprints": [rule|path|line, or null where Python's fingerprint raises]}
            let fps: Vec<Value> = arr_arg(args, "issues").iter()
                .map(|i| crate::baseline::fingerprint(&crate::baseline::pyval_of(i)).map(Value::Str).unwrap_or(Value::Null))
                .collect();
            Value::obj(vec![("fingerprints", Value::Arr(fps))])
        }
        "baseline_sign" => {
            // {fingerprints: [str, …], key} -> {"value": the hex HMAC}
            let key = arg_str(args, "key")?;
            let fps: Vec<PyStr> = arr_arg(args, "fingerprints").iter().filter_map(|f| f.as_str().map(|s| s.to_vec())).collect();
            Value::obj(vec![("value", Value::str(&crate::baseline::sign(&fps, &key)))])
        }
        "baseline_apply" => {
            // the baseline's bytes as the text (latin-1, a character a byte), or {error}: why they could not be read;
            // {path, ours, inside, key, fingerprints, issues (finding rows), conditions} -> {"warnings", and "new",
            // "newIssues", "untrusted", "accepted", "acceptedIssues", "pass", "conditions" as they apply}
            let bad = |m: String| CallError::BadArgs(format!("baseline_apply: {m}"));
            let data = match opt_str(args, "error") {
                Some(why) => Err(why),
                None => {
                    if text.iter().any(|&c| c > 0xFF) {
                        return Err(bad("the bytes come as latin-1 text: a character past U+00FF".into()));
                    }
                    Ok(text.iter().map(|&c| c as u8).collect())
                }
            };
            let a = crate::baseline::ApplyIn {
                path: arg_str(args, "path")?,
                ours: matches!(args.get("ours"), Some(Value::Bool(true))),
                inside: matches!(args.get("inside"), Some(Value::Bool(true))),
                key: opt_str(args, "key").filter(|k| !k.is_empty()),
                data,
                fingerprints: arr_arg(args, "fingerprints").iter().map(|f| f.as_str().map(|s| s.to_vec())).collect(),
                rows: crate::result::findings_arg(args.get("issues")).map_err(bad)?,
                conditions: crate::result::conditions_arg(args.get("conditions")).map_err(bad)?,
            };
            if a.rows.len() != a.fingerprints.len() {
                return Err(bad("a fingerprint each finding".into()));
            }
            crate::baseline::apply(p, &a)
        }
        "decode_source" => {
            // the file's bytes as the text (one code point a byte); {lang, issues, redact} -> {"text", "info", for
            // "go" "goText" where the Go toolchain reads the bytes otherwise (decode::go_text: the Go reader's text),
            // and with `issues` its encoding findings (decode/mod.rs)}
            if text.iter().any(|&c| c > 0xFF) {
                return Err(CallError::BadArgs("decode_source: the bytes are one code point each, up to 0xFF".into()));
            }
            let bytes: Vec<u8> = text.iter().map(|&c| c as u8).collect();
            let (decoded, info) = crate::decode::decode_source(&bytes, lang);
            let mut items = vec![("text", Value::Str(decoded.clone())), ("info", crate::decode::info_value(&info))];
            if lang == Some("go") {
                if let Some(go) = crate::decode::go_text(&bytes) {
                    items.push(("goText", Value::Str(go)));
                }
            }
            if matches!(args.get("issues"), Some(Value::Bool(true))) {
                let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
                let mut issues = crate::decode::encoding_issues(p, &decoded, &info, redact);
                // `name`: read as decode_member reads an archive member or a project's file, which is also
                // SC-TRUNCATED when it does not decode to anything text-like
                if let Some(Value::Str(name)) = args.get("name") {
                    let windows = matches!(args.get("windows"), Some(Value::Bool(true)));
                    issues.extend(crate::decode::not_text_issue(p, &decoded, name, windows, &bytes));
                }
                items.push(("issues", Value::Arr(issues)));
            }
            Value::obj(items)
        }
        "encoding_issues" => {
            // a decoded file's encoding findings, from its text and decode_source's info {info, redact}
            let info = crate::decode::info_arg(args.get("info")).map_err(|m| CallError::BadArgs(format!("encoding_issues: {m}")))?;
            let redact = !matches!(args.get("redact"), Some(Value::Bool(false)));
            Value::Arr(crate::decode::encoding_issues(p, text, &info, redact))
        }
        "term" | "issue_excerpt" | "report_json" | "report_items" | "sarif_rules" | "sarif_frame" | "sarif_items"
        | "html_frame" | "html_items" | "text_frame" | "text_order" | "text_items" => report_call(p, name, args, text)?,
        "decode" => {
            // the bytes (one code point a byte) in `codec` (any spelling Python's codecs.lookup takes) as
            // bytes.decode(codec, "replace") gives them -> {"codec": its name, "text"}; an escape codec strict
            // ("text" null where Python raises, or for \N{name}); a codec Python lacks or the engine does not
            // decode: {"codec": null or its name, "text": null}
            if text.iter().any(|&c| c > 0xFF) {
                return Err(CallError::BadArgs("decode: the bytes are one code point each, up to 0xFF".into()));
            }
            let Some(Value::Str(name)) = args.get("codec") else {
                return Err(CallError::BadArgs("decode: codec is the codec's name".into()));
            };
            let bytes: Vec<u8> = text.iter().map(|&c| c as u8).collect();
            let codec = crate::decode::codec_of(&crate::pystr::to_string(name));
            let decoded = codec.and_then(|c| crate::decode::decode(c, &bytes));
            Value::obj(vec![
                ("codec", codec.map_or(Value::Null, Value::str)),
                ("text", decoded.map_or(Value::Null, Value::Str)),
            ])
        }
        "project_metrics" => {
            let bad = |m: String| CallError::BadArgs(format!("project_metrics: {m}"));
            // a project's metrics from its files' line metrics (result.rs; core.compute_metrics', npm's computeMetrics')
            crate::result::metrics(&crate::result::files_arg(args.get("files")).map_err(bad)?)
        }
        "file_metrics" => {
            // core.compute_metrics' part for one file (metrics.rs)
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            metrics_value(&crate::metrics::file_metrics(p, text, lang, jsx))
        }
        "functions" => {
            // core.extract_functions: [[name, line, length, complexity], …] of a Python or JavaScript file
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            let ctx = crate::filectx::FileCtx::new(p, text, crate::filectx::Lang::from(lang), jsx);
            Value::Arr(crate::project::functions(p, &ctx).into_iter().map(|f| Value::Arr(vec![
                Value::Str(f.name), Value::Int(f.line as i64), Value::Int(f.len as i64), Value::Int(f.cx as i64),
            ])).collect())
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
            let out = match form.as_str() {
                "NFC" => crate::normalize::nfc(text),
                "NFD" => crate::normalize::nfd(text),
                "NFKC" => crate::normalize::nfkc(text),
                "NFKD" => crate::normalize::nfkd(text),
                _ => return Err(CallError::BadArgs(format!("unknown normalization form {:?}", form))),
            };
            // "fold": true, then case-folded (str.casefold): a name as file systems that ignore case and
            // normalization compare it, on this engine's Unicode 13.0 whatever the caller's (BR-2)
            let fold = matches!(args.get("fold"), Some(Value::Bool(true)));
            Value::Str(if fold { crate::unicode::casefold(&out) } else { out })
        }
        "lex.tokens" => {
            // the tokens of one reading (lex/): [kind, start, end] each, in
            // code points; lang "js" (with JSX unless "jsx": false), "py",
            // "go" or "rs"
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            let toks = match lang {
                Some("js") => crate::lex::js::tokens(text, jsx).to_vec(),
                Some("py") => crate::lex::py::tokens(text).to_vec(),
                Some("go") => crate::lex::go::tokens(text),
                Some("rs") => crate::lex::rs::tokens(text),
                _ => return Err(CallError::BadArgs("lex.tokens needs lang 'js', 'py', 'go' or 'rs'".into())),
            };
            Value::Arr(
                toks.iter()
                    .map(|t| Value::Arr(vec![Value::str(t.kind.name()), Value::Int(t.start as i64), Value::Int(t.end as i64)]))
                    .collect(),
            )
        }
        "lex.structure" => {
            // what the detectors ask of a text (lex::Structure): for a file
            // that may hold JSX, what its two readings agree on
            let jsx = !matches!(args.get("jsx"), Some(Value::Bool(false)));
            match crate::lex::structure(text, lang.unwrap_or(""), jsx) {
                Some(st) => Value::obj(vec![
                    ("comments", spans_value(&st.comments)),
                    ("strings", spans_value(&st.strings)),
                    ("literals", spans_value(&st.literals)),
                ]),
                None => return Err(CallError::BadArgs("lex.structure needs lang 'js', 'py', 'go' or 'rs'".into())),
            }
        }
        "pyre.probe" => probe(args, text)?,
        "linre.probe" => linre_probe(args, text)?,
        "linre.check" => linre_check(p, args),
        // the patterns the engine built that linre refused (each failed its
        // call closed), since the last call: none, the tests hold
        "linre.refused" => Value::Arr(crate::rxutil::take_refused().iter().map(|s| Value::str(s)).collect()),
        "shlex_split" => match hooks::shlex_split(text) {
            Some(t) => strs(&t),
            None => Value::Null,
        },
        "hook_tokens" => strs(&hooks::hook_tokens(p, text)),
        "follow_hook" => {
            let (targets, complete) = hooks::follow_hook(p, text);
            Value::Arr(vec![strs(&targets), Value::Bool(complete)])
        }
        "hook_runs_only_files" => Value::Bool(hooks::hook_runs_only_files(p, text)),
        "node_candidates" => strs(&hooks::node_candidates(text)),
        "node_e_codes" => strs(&hooks::node_e_codes(p, text)),
        "shebang_lang" => hooks::shebang_lang(p, text).map(Value::str).unwrap_or(Value::Null),
        // the language the tests read a script in, by its path and its text (deps::script_lang)
        "script_lang" => crate::deps::script_lang(p, &arg_str(args, "path")?, text).map(Value::str).unwrap_or(Value::Null),
        "install_script_risk" => {
            let shell = !matches!(args.get("shell"), Some(Value::Bool(false)));
            let command = matches!(args.get("command"), Some(Value::Bool(true)));
            // `own`: the release's name, when the caller knows it (its own package's code is not another's, D-9)
            let _own = if args.get("own").is_some() { Some(signs::own_release(&arg_str(args, "own")?)) } else { None };
            let reasons = strs(&signs::install_script_risk_with(p, text, shell, command, lang));
            // `unread` (BIG-BUNDLE-TAIL): [reasons, the limit a reading met or the tree's not reading the text whole, or
            // null], as import_time_risk's fourth element
            if matches!(args.get("unread"), Some(Value::Bool(true))) {
                Value::Arr(vec![reasons, crate::budget::take_cut().map(|c| Value::Str(u(&c))).unwrap_or(Value::Null)])
            } else {
                reasons
            }
        }
        "import_time_risk" => {
            // `declared`: the release's own name and the packages its manifest names (D-12), when the caller knows them
            let declared = args.get("declared").map(|_| arg_strs(args, "declared"));
            // `own`: the release's name (D-9), as for install_script_risk
            let _own = if args.get("own").is_some() { Some(signs::own_release(&arg_str(args, "own")?)) } else { None };
            // `refused`: a third element, the parser's refusal of a JavaScript text whose tree the test then could
            // not read ([line, reason], or null: JS-PARSE-STRICT, said in a registry scan's report); asked first, it
            // reads the text once for the test (facts' cache)
            let refused = matches!(args.get("refused"), Some(Value::Bool(true)));
            // `unread` (BIG-BUNDLE-TAIL): a fourth element, the limit a reading of the text met before its end (the
            // text follower's: budget::cut), or null; the call answers then with what it found, where without it a
            // call whose reading met a limit answers as one that ran out
            let unread = matches!(args.get("unread"), Some(Value::Bool(true)));
            let why = if refused && lang == Some("js") { crate::jsflow::supply::refusal(text) } else { None };
            let (reasons, line) = signs::import_time_risk_with(p, text, lang, declared.as_deref());
            let mut out = vec![strs(&reasons), line.map(|l| Value::Int(l as i64)).unwrap_or(Value::Null)];
            if refused || unread {
                out.push(why.map(|(l, r)| Value::Arr(vec![Value::Int(l as i64), Value::Str(r)])).unwrap_or(Value::Null));
            }
            if unread {
                out.push(crate::budget::take_cut().map(|c| Value::Str(u(&c))).unwrap_or(Value::Null));
            }
            Value::Arr(out)
        }
        "import_time_severity" => Value::str(signs::import_time_severity(p, &arg_strs(args, "reasons"))),
        "install_script_severity" => {
            signs::install_script_severity(p, &arg_strs(args, "reasons")).map(Value::str).unwrap_or(Value::Null)
        }
        "decoded_view" => Value::Str(signs::decoded_view(p, text, lang)),
        "string_array_line" => signs::string_array_line(p, text, lang).map(|n| Value::Int(n as i64)).unwrap_or(Value::Null),
        "spawned_scripts" => Value::Arr(
            signs::spawned_scripts(p, text, lang)
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
        "local_data_sent_tree" => match if lang == Some("py") {
            crate::pyflow::supply::local_data_sent(text)
        } else {
            crate::jsflow::supply::local_data_sent(text)
        } {
            crate::jsflow::supply::Answer::Found(at, kind, what, in_address) => flow(Some((at, kind, what, in_address))),
            crate::jsflow::supply::Answer::Nothing => Value::Null,
            crate::jsflow::supply::Answer::Unread => Value::str("unread"),
        },
        "received_code_tree" => match if lang == Some("py") {
            crate::pyflow::supply::received_code(text)
        } else {
            crate::jsflow::supply::received_code(text)
        } {
            Some(Some((line, cat))) => Value::Arr(vec![Value::Int(line as i64), Value::str(cat)]),
            Some(None) => Value::Null,
            None => Value::str("unread"),
        },
        // code the text decodes and runs: [[the run's offset, the decoding's], …]
        "decoded_runs_tree" => match if lang == Some("py") {
            crate::pyflow::supply::decoded_runs(text)
        } else {
            crate::jsflow::supply::decoded_runs(text)
        } {
            Some(runs) => Value::Arr(runs.iter().map(|&(a, f)| Value::Arr(vec![Value::Int(a as i64), Value::Int(f as i64)])).collect()),
            None => Value::str("unread"),
        },
        // a file the text writes, then runs: [line, what it held, the carved file, the interpreter]
        "dropped_run_tree" => match if lang == Some("py") {
            crate::pyflow::supply::dropped_run(text)
        } else {
            crate::jsflow::supply::dropped_run(text)
        } {
            Some(Some(d)) => {
                let held: Vec<Value> = [(crate::jsflow::supply::K_DECODED, "decoded"), (crate::jsflow::supply::K_CARVED, "carved"), (crate::jsflow::supply::K_RECEIVED, "received")]
                    .iter()
                    .filter(|(b, _)| d.kinds & b != 0)
                    .map(|(_, n)| Value::str(n))
                    .collect();
                Value::Arr(vec![
                    Value::Int(d.line as i64),
                    Value::Arr(held),
                    Value::Str(d.what.clone()),
                    match d.interp {
                        Some(i) => Value::Str(i),
                        None => Value::Null,
                    },
                ])
            }
            Some(None) => Value::Null,
            None => Value::str("unread"),
        },
        "runs_own_source_at" => Value::Int(signs::runs_own_source_at(p, text, lang) as i64),
        "reads_own_source" => Value::Bool(signs::reads_own_source(p, text)),
        "persistence_reasons" => strs(&signs::persistence_reasons(p, text)),
        "pth_line_risk" => strs(&signs::pth_line_risk(p, text)),
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
                strs(&crate::shell::hook_inline_code(p, text, &mut walk, 0).into_iter().map(|(_, code)| code).collect::<Vec<_>>()),
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
                strs(&signs::install_script_risk(p, text, None)),
                itr(None),
                strs(&hooks::node_candidates(text)),
                strs(&hooks::node_e_codes(p, text)),
                hooks::shebang_lang(p, text).map(Value::str).unwrap_or(Value::Null),
                itr(Some("py")),
                itr(Some("js")),
                Value::Int(signs::self_publish_at(p, text) as i64),
                opt_s(signs::runs_dll(p, text)),
                Value::Str(signs::join_string_pieces(p, text)),
                Value::Str(signs::decoded_view(p, text, None)),
                Value::Arr(
                    signs::spawned_scripts(p, text, None)
                        .into_iter()
                        .map(|(b, path)| Value::Arr(vec![Value::str(b), Value::Str(path)]))
                        .collect(),
                ),
                // phase 2: the decoded view of JavaScript and of Python (their
                // literals read with the lexers)
                Value::Str(signs::decoded_view(p, text, Some("js"))),
                Value::Str(signs::decoded_view(p, text, Some("py"))),
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
                Value::Int(signs::runs_own_source_at(p, text, None) as i64),
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
                signs::string_array_line(p, text, None).map(|n| Value::Int(n as i64)).unwrap_or(Value::Null),
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
/// points), or "text_ids": [one per file] (the store's texts, texts.rs: each
/// `length` code points, and no text) -> core._cross_file_received_issues per
/// package (crossfile::answer). Each package gets the call's budget.
fn cross_file(p: &Pack, args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::crossfile::{self, File, Options};
    let bad = |m: &str| CallError::BadArgs(format!("cross_file: {}", m));
    let items = args.get("files").and_then(|f| f.as_arr()).ok_or_else(|| bad("files"))?;
    let who = opt_str(args, "who").unwrap_or_else(|| u("Dependency code"));
    let whos = args.get("whos").and_then(|w| w.as_arr());
    let groups = args.get("groups").and_then(|g| g.as_arr());
    // the files' texts: the store's, by id, or the text's, one after another
    let stored: Option<Vec<Vec<u32>>> = match args.get("text_ids") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let ids = v.as_arr().filter(|ids| ids.len() == items.len()).ok_or_else(|| bad("text_ids: one per file"))?;
            if !text.is_empty() {
                return Err(bad("a text and text_ids"));
            }
            let mut out = Vec::with_capacity(ids.len());
            for id in ids {
                let id = text_id(id)?;
                out.push(crate::texts::decoded(id).ok_or_else(|| bad(&format!("no text {id} in the store")))?);
            }
            Some(out)
        }
    };
    let mut files = Vec::with_capacity(items.len());
    let mut at = 0usize;
    for (k, item) in items.iter().enumerate() {
        let parts = item.as_arr().ok_or_else(|| bad("a file is not [path, lang, length]"))?;
        let path = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a file's path"))?.to_vec();
        let lang = parts.get(1).and_then(|v| v.as_str()).ok_or_else(|| bad("a file's lang"))?.to_vec();
        let len = parts.get(2).and_then(|v| v.as_i64()).filter(|&n| n >= 0).ok_or_else(|| bad("a file's length"))? as usize;
        let body: &[u32] = match &stored {
            Some(texts) => {
                if texts[k].len() != len {
                    return Err(bad("a stored text's length is not its file's"));
                }
                &texts[k]
            }
            None => {
                if at + len > text.len() {
                    return Err(bad("the files' lengths run past the text"));
                }
                at += len;
                &text[at - len..at]
            }
        };
        let who = whos.and_then(|w| w.get(k)).and_then(|v| v.as_str()).map(|s| s.to_vec()).unwrap_or_else(|| who.clone());
        let group = groups.and_then(|g| g.get(k)).and_then(|v| v.as_str()).map(|s| s.to_vec());
        files.push(File { path, lang, text: body, who, group });
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

/// rs_crate: {"files": [[path, length], …] (their contents, concatenated, are
/// the text; the .rs files of one crate), "build" (the build script's path, or
/// null), "proc_macro" (bool), "lib" (the library root's path, or null),
/// "use_file_chars", "use_chars" (SC-USE-RISK's bounds, optional)} ->
/// {"build": finding|null, "macros": finding|null, "start": [finding, …],
/// "uses": [finding, …], "read": [file index, …], "useRead": {files, chars,
/// ofFiles, ofChars}}. A finding is {"file": index, "reasons": [str, …],
/// "line": n}. Each crate gets the call's budget (crate::rsread::read_crate).
/// The files of a package's call: [[path, length], …], their contents the text, concatenated -> (path, where its
/// contents start, where they end), or the reason the arguments are refused.
fn package_files(args: &Value, text_len: usize) -> Result<Vec<(PyStr, usize, usize)>, &'static str> {
    let items = args.get("files").and_then(|f| f.as_arr()).ok_or("files")?;
    let mut files = Vec::with_capacity(items.len());
    let mut at = 0usize;
    for item in items {
        let parts = item.as_arr().ok_or("a file is not [path, length]")?;
        let path = parts.first().and_then(|v| v.as_str()).ok_or("a file's path")?.to_vec();
        let len = parts.get(1).and_then(|v| v.as_i64()).filter(|&n| n >= 0).ok_or("a file's length")? as usize;
        if at + len > text_len {
            return Err("the files' lengths run past the text");
        }
        files.push((path, at, at + len));
        at += len;
    }
    if at != text_len {
        return Err("the files' lengths do not add up to the text");
    }
    Ok(files)
}

fn rs_crate(args: &Value, text: Vec<u32>) -> Result<Value, CallError> {
    use crate::rsread::{read_crate, Found, Options};
    let bad = |m: &str| CallError::BadArgs(format!("rs_crate: {}", m));
    let files = package_files(args, text.len()).map_err(bad)?;
    let flag = |k: &str, d: bool| match args.get(k) {
        Some(Value::Bool(b)) => *b,
        _ => d,
    };
    let mut opts = Options { build: opt_str(args, "build"), proc_macro: flag("proc_macro", false), lib: opt_str(args, "lib"), ..Options::default() };
    if let Some(n) = opt_int(args, "use_file_chars").filter(|&n| n >= 0) {
        opts.use_file_chars = n as usize;
    }
    if let Some(n) = opt_int(args, "use_chars").filter(|&n| n >= 0) {
        opts.use_chars = n as usize;
    }
    let spans: Vec<(usize, usize)> = files.iter().map(|(_, a, b)| (*a, *b)).collect();
    let text = std::sync::Arc::new(text);
    let shared = text.clone();
    let answer = on_own_stack(move || {
        let pack = crate::pack::current();
        let refs: Vec<(PyStr, &[u32])> = files.iter().map(|(p, a, b)| (p.clone(), &shared[*a..*b])).collect();
        read_crate(&pack, &refs, &opts)
    });
    let finding = |f: &Found| {
        Value::obj(vec![
            ("file", Value::Int(f.file as i64)),
            ("reasons", strs(&f.reasons)),
            ("line", Value::Int(f.line as i64)),
        ])
    };
    let findings = |fs: &[Found]| Value::Arr(fs.iter().map(finding).collect());
    Ok(with_reader_issues(args, &spans, &text, Value::obj(vec![
        ("build", answer.build.as_ref().map(finding).unwrap_or(Value::Null)),
        ("macros", answer.macros.as_ref().map(finding).unwrap_or(Value::Null)),
        ("start", findings(&answer.start)),
        ("uses", findings(&answer.uses)),
        ("read", Value::Arr(answer.read.iter().map(|&k| Value::Int(k as i64)).collect())),
        (
            "useRead",
            Value::obj(vec![
                ("files", Value::Int(answer.use_read.files as i64)),
                ("chars", Value::Int(answer.use_read.chars as i64)),
                ("ofFiles", Value::Int(answer.use_read.of_files as i64)),
                ("ofChars", Value::Int(answer.use_read.of_chars as i64)),
            ]),
        ),
    ])))
}

/// A reader's answer with its findings (readers.rs), when the call says whose code it is: {"what": "module",
/// "crate" or "sdist", "names": [the files' names as the findings show them], "redact", "neumaier"} -> "issues":
/// [[file index, issue]…]. `spans`: each file's place in `text`.
fn with_reader_issues(args: &Value, spans: &[(usize, usize)], text: &[u32], answer: Value) -> Value {
    let Some(what) = opt_str(args, "what").map(|w| crate::pystr::to_string(&w)) else { return answer };
    let names = arg_strs(args, "names");
    let texts: Vec<&[u32]> = spans.iter().map(|&(a, b)| &text[a..b]).collect();
    let reading = crate::readers::Reading {
        what: &what,
        names: &names,
        texts: &texts,
        redact: flag(args, "redact", true),
        neumaier: flag(args, "neumaier", false),
    };
    let found = crate::readers::issues(&crate::pack::current(), &answer, &reading);
    match answer {
        Value::Obj(mut items) => {
            items.push((crate::pystr::u("issues"), crate::readers::issues_value(found)));
            Value::Obj(items)
        }
        other => other,
    }
}

/// go_package: {"files": [[path, length], …] (their contents, concatenated, are
/// the text; a module's .go files, as the Go toolchain reads them, and its
/// cgo packages' .c and .h files), "module" (go.mod's module path,
/// optional), "use_file_chars", "use_chars" (SC-USE-RISK's bounds,
/// optional), "listed" (true: the packages a vendor tree's modules.txt
/// lists, every one built), "testdata" ([folder, …]: the module's testdata/
/// folders with .go files, given or not; an import of a testdata/ package
/// that names none of them is another module's, a nested one's included)}
/// -> {"start": [finding, …] (the import-time test
/// of what init code reaches), "uses": [finding, …], "read": [file index,
/// …], "unparsed": [file index, …] (.go files the parser refuses),
/// "refused": [[file, line, why], …] (those of them a build compiles, where
/// the parser stopped), "wanted": [import path, …] (the module's testdata/
/// packages an import names of which no file was given), "testdataImports":
/// [[file, line, import path], …] (another module's testdata/ packages
/// imported), "generate": [[file, line, text], …], "linkname": [[file, line,
/// text], …], "useRead": {files, chars, ofFiles, ofChars}}. A finding is
/// {"file": index, "reasons": [str, …], "line": n}. Each module gets the
/// call's budget (crate::goread::read_module).
fn go_package(args: &Value, text: Vec<u32>) -> Result<Value, CallError> {
    use crate::goread::{read_module, Found, Options};
    let bad = |m: &str| CallError::BadArgs(format!("go_package: {}", m));
    let files = package_files(args, text.len()).map_err(bad)?;
    let listed = matches!(args.get("listed"), Some(Value::Bool(true)));
    let testdata_dirs = match args.get("testdata") {
        None | Some(Value::Null) => None,
        Some(Value::Arr(a)) => Some(a.iter().map(|d| d.as_str().map(|t| t.to_vec()).ok_or_else(|| bad("testdata is a list of folders"))).collect::<Result<Vec<_>, _>>()?),
        Some(_) => return Err(bad("testdata is a list of folders")),
    };
    let mut opts = Options { module: opt_str(args, "module"), listed, testdata_dirs, ..Options::default() };
    if let Some(n) = opt_int(args, "use_file_chars").filter(|&n| n >= 0) {
        opts.use_file_chars = n as usize;
    }
    if let Some(n) = opt_int(args, "use_chars").filter(|&n| n >= 0) {
        opts.use_chars = n as usize;
    }
    let spans: Vec<(usize, usize)> = files.iter().map(|(_, a, b)| (*a, *b)).collect();
    let text = std::sync::Arc::new(text);
    let shared = text.clone();
    let answer = on_own_stack(move || {
        let pack = crate::pack::current();
        let refs: Vec<(PyStr, &[u32])> = files.iter().map(|(p, a, b)| (p.clone(), &shared[*a..*b])).collect();
        read_module(&pack, &refs, &opts)
    });
    let finding = |f: &Found| {
        Value::obj(vec![
            ("file", Value::Int(f.file as i64)),
            ("reasons", strs(&f.reasons)),
            ("line", Value::Int(f.line as i64)),
        ])
    };
    let findings = |fs: &[Found]| Value::Arr(fs.iter().map(finding).collect());
    let directives = |ds: &[(usize, usize, PyStr)]| {
        Value::Arr(ds.iter().map(|(f, l, t)| Value::Arr(vec![Value::Int(*f as i64), Value::Int(*l as i64), Value::Str(t.clone())])).collect())
    };
    let ints = |v: &[usize]| Value::Arr(v.iter().map(|&k| Value::Int(k as i64)).collect());
    Ok(with_reader_issues(args, &spans, &text, Value::obj(vec![
        ("start", findings(&answer.start)),
        ("uses", findings(&answer.uses)),
        ("read", ints(&answer.read)),
        ("unparsed", ints(&answer.unparsed)),
        ("refused", directives(&answer.refused)),
        ("wanted", strs(&answer.wanted)),
        ("testdataImports", directives(&answer.testdata_imports)),
        ("generate", directives(&answer.generate)),
        ("linkname", directives(&answer.linkname)),
        (
            "useRead",
            Value::obj(vec![
                ("files", Value::Int(answer.use_read.files as i64)),
                ("chars", Value::Int(answer.use_read.chars as i64)),
                ("ofFiles", Value::Int(answer.use_read.of_files as i64)),
                ("ofChars", Value::Int(answer.use_read.of_chars as i64)),
            ]),
        ),
    ])))
}

/// js_flow: {"files": [[path, length], …] (their contents, concatenated,
/// are the text; a length of null: a file whose content is not text),
/// "sources": [pattern, …], "sinks": [[pattern, category], …], "full":
/// [name, …], "partial": [[name, [category, …]], …] (the configured part
/// of the model, as taintspec validated it), "run_limit": [base, per node]
/// (optional: a lower limit for one function's reading)} -> the pass's
/// output in order: ["skipped_size", path, n, the limit], ["issue",
/// category, path, line, source, sink, via, the index of the path's file],
/// ["note", rule, name, path, line, msg, why, fix].
fn js_flow(args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::jsflow::{self, Config, Out};
    let bad = |m: &str| CallError::BadArgs(format!("js_flow: {}", m));
    let items = args.get("files").and_then(|f| f.as_arr()).ok_or_else(|| bad("files"))?;
    let mut files: Vec<(PyStr, Option<PyStr>)> = Vec::with_capacity(items.len());
    let mut at = 0usize;
    for item in items {
        let parts = item.as_arr().ok_or_else(|| bad("a file is not [path, length]"))?;
        let path = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a file's path"))?.to_vec();
        if matches!(parts.get(1), Some(Value::Null)) {
            files.push((path, None));
            continue;
        }
        let len = parts.get(1).and_then(|v| v.as_i64()).filter(|&n| n >= 0).ok_or_else(|| bad("a file's length"))? as usize;
        if at + len > text.len() {
            return Err(bad("the files' lengths run past the text"));
        }
        files.push((path, Some(text[at..at + len].to_vec())));
        at += len;
    }
    if at != text.len() {
        return Err(bad("the files' lengths do not add up to the text"));
    }
    let cat = |v: &Value| -> Result<u8, CallError> {
        let s = v.as_str().ok_or_else(|| bad("a category"))?;
        let name: String = s.iter().map(|&c| char::from_u32(c).unwrap_or('\u{FFFD}')).collect();
        jsflow::cat_of(&name).ok_or_else(|| bad("an unknown category"))
    };
    let sources = arg_strs(args, "sources");
    let mut sinks = Vec::new();
    for item in args.get("sinks").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let parts = item.as_arr().ok_or_else(|| bad("a sink is not [pattern, category]"))?;
        let pat = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a sink's pattern"))?.to_vec();
        sinks.push((pat, cat(parts.get(1).unwrap_or(&Value::Null))?));
    }
    let full = arg_strs(args, "full");
    let mut partial = Vec::new();
    for item in args.get("partial").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let parts = item.as_arr().ok_or_else(|| bad("a partial sanitizer is not [name, [category, …]]"))?;
        let name = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a sanitizer's name"))?.to_vec();
        let mut bits = 0u8;
        for c in parts.get(1).and_then(|v| v.as_arr()).unwrap_or(&[]) {
            bits |= jsflow::bit(cat(c)?);
        }
        partial.push((name, bits));
    }
    let mut run_limit = (jsflow::RUN_BASE, jsflow::RUN_PER_NODE);
    if let Some(limit) = args.get("run_limit") {
        let parts = limit.as_arr().filter(|p| p.len() == 2).ok_or_else(|| bad("run_limit is not [base, per node]"))?;
        let n = |v: &Value| v.as_i64().filter(|&n| n >= 0).map(|n| n as u64).ok_or_else(|| bad("a run_limit part"));
        run_limit = (n(&parts[0])?, n(&parts[1])?);
    }
    // (the model is built on the pass's own thread: its patterns are not Send)
    let out = on_own_stack(move || {
        jsflow::analyze(&files, Config::new(&sources, &sinks, &full, &partial).with_run_limit(run_limit.0, run_limit.1))
    });
    Ok(Value::Arr(
        out.into_iter()
            .map(|o| match o {
                Out::SkippedSize { path, n } => Value::Arr(vec![
                    Value::str("skipped_size"),
                    Value::Str(path),
                    Value::Int(n as i64),
                    Value::Int(jsflow::MAX_FILE as i64),
                ]),
                Out::Issue { cat, path, file, line, source, sink, via } => Value::Arr(vec![
                    Value::str("issue"),
                    Value::str(jsflow::CATS[cat as usize]),
                    Value::Str(path),
                    Value::Int(line as i64),
                    Value::Str(source),
                    Value::Str(sink),
                    Value::Str(via),
                    Value::Int(file as i64),
                ]),
                Out::Note { rule, name, path, line, msg, why, fix } => Value::Arr(vec![
                    Value::str("note"),
                    Value::str(rule),
                    Value::str(name),
                    Value::Str(path),
                    Value::Int(line as i64),
                    Value::Str(msg),
                    Value::str(why),
                    Value::str(fix),
                ]),
                // (the supply-chain model's; project mode never gives one)
                Out::Delete { .. } | Out::Send { .. } | Out::Received { .. } | Out::Decoded { .. } | Out::Dropped { .. } | Out::Own { .. } | Out::Rewrote { .. } => Value::Null,
            })
            .collect(),
    ))
}

/// The files of a flow call: [[path, length], …] (their contents,
/// concatenated, are the text; a length of null: content that is not text).
fn flow_files(args: &Value, text: &[u32], call: &str) -> Result<Vec<(PyStr, Option<PyStr>)>, CallError> {
    let bad = |m: &str| CallError::BadArgs(format!("{}: {}", call, m));
    let items = args.get("files").and_then(|f| f.as_arr()).ok_or_else(|| bad("files"))?;
    let mut files: Vec<(PyStr, Option<PyStr>)> = Vec::with_capacity(items.len());
    let mut at = 0usize;
    for item in items {
        let parts = item.as_arr().ok_or_else(|| bad("a file is not [path, length]"))?;
        let path = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a file's path"))?.to_vec();
        if matches!(parts.get(1), Some(Value::Null)) {
            files.push((path, None));
            continue;
        }
        let len = parts.get(1).and_then(|v| v.as_i64()).filter(|&n| n >= 0).ok_or_else(|| bad("a file's length"))? as usize;
        if at + len > text.len() {
            return Err(bad("the files' lengths run past the text"));
        }
        files.push((path, Some(text[at..at + len].to_vec())));
        at += len;
    }
    if at != text.len() {
        return Err(bad("the files' lengths do not add up to the text"));
    }
    Ok(files)
}

/// The configured part of a flow call's model: (sources, sinks, full,
/// partial) as taintspec validated them.
#[allow(clippy::type_complexity)]
fn flow_model(args: &Value, call: &str) -> Result<(Vec<PyStr>, Vec<(PyStr, u8)>, Vec<PyStr>, Vec<(PyStr, u8)>), CallError> {
    let bad = |m: &str| CallError::BadArgs(format!("{}: {}", call, m));
    let cat = |v: &Value| -> Result<u8, CallError> {
        let s = v.as_str().ok_or_else(|| bad("a category"))?;
        let name: String = s.iter().map(|&c| char::from_u32(c).unwrap_or('\u{FFFD}')).collect();
        crate::jsflow::cat_of(&name).ok_or_else(|| bad("an unknown category"))
    };
    let sources = arg_strs(args, "sources");
    let mut sinks = Vec::new();
    for item in args.get("sinks").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let parts = item.as_arr().ok_or_else(|| bad("a sink is not [pattern, category]"))?;
        let pat = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a sink's pattern"))?.to_vec();
        sinks.push((pat, cat(parts.get(1).unwrap_or(&Value::Null))?));
    }
    let full = arg_strs(args, "full");
    let mut partial = Vec::new();
    for item in args.get("partial").and_then(|v| v.as_arr()).unwrap_or(&[]) {
        let parts = item.as_arr().ok_or_else(|| bad("a partial sanitizer is not [name, [category, …]]"))?;
        let name = parts.first().and_then(|v| v.as_str()).ok_or_else(|| bad("a sanitizer's name"))?.to_vec();
        let mut bits = 0u8;
        for c in parts.get(1).and_then(|v| v.as_arr()).unwrap_or(&[]) {
            bits |= crate::jsflow::bit(cat(c)?);
        }
        partial.push((name, bits));
    }
    Ok((sources, sinks, full, partial))
}

/// A flow call's output: ["issue", category, path, line, source, sink,
/// via, the index of the path's file], ["note", rule, name, path, line,
/// msg, why, fix] (and js_flow's ["skipped_size", path, n, the limit]).
fn flow_out(out: Vec<crate::jsflow::Out>, max_file: usize) -> Value {
    use crate::jsflow::Out;
    Value::Arr(
        out.into_iter()
            .map(|o| match o {
                Out::SkippedSize { path, n } => Value::Arr(vec![
                    Value::str("skipped_size"),
                    Value::Str(path),
                    Value::Int(n as i64),
                    Value::Int(max_file as i64),
                ]),
                Out::Issue { cat, path, file, line, source, sink, via } => Value::Arr(vec![
                    Value::str("issue"),
                    Value::str(crate::jsflow::CATS[cat as usize]),
                    Value::Str(path),
                    Value::Int(line as i64),
                    Value::Str(source),
                    Value::Str(sink),
                    Value::Str(via),
                    Value::Int(file as i64),
                ]),
                Out::Note { rule, name, path, line, msg, why, fix } => Value::Arr(vec![
                    Value::str("note"),
                    Value::str(rule),
                    Value::str(name),
                    Value::Str(path),
                    Value::Int(line as i64),
                    Value::Str(msg),
                    Value::str(why),
                    Value::str(fix),
                ]),
                // (the supply-chain model's; project mode never gives one)
                Out::Delete { .. } | Out::Send { .. } | Out::Received { .. } | Out::Decoded { .. } | Out::Dropped { .. } | Out::Own { .. } | Out::Rewrote { .. } => Value::Null,
            })
            .collect(),
    )
}

/// py_flow: {"files": [[path, length], …] (their contents, concatenated,
/// are the text; a length of null: a file whose content is not text),
/// "sources", "sinks", "full", "partial" (the configured part of the model,
/// as taintspec validated it), and lower limits, each at most the default:
/// "max_iters", "max_files", "max_bytes", "work_limit" and "run_limit"
/// ([base, per node])} -> the pass's output in order: ["issue", category,
/// path, line, source, sink, via, the index of the path's file], ["note",
/// rule, name, path, line, msg, why, fix].
fn py_flow(args: &Value, text: &[u32]) -> Result<Value, CallError> {
    use crate::pyflow::{self, Config};
    let bad = |m: &str| CallError::BadArgs(format!("py_flow: {}", m));
    let files = flow_files(args, text, "py_flow")?;
    let (sources, sinks, full, partial) = flow_model(args, "py_flow")?;
    let count = |k: &str| -> Result<Option<u64>, CallError> {
        match args.get(k) {
            None => Ok(None),
            Some(v) => v.as_i64().filter(|&n| n >= 0).map(|n| Some(n as u64)).ok_or_else(|| bad(k)),
        }
    };
    let pair = |k: &str| -> Result<Option<(u64, u64)>, CallError> {
        match args.get(k) {
            None => Ok(None),
            Some(v) => {
                let parts = v.as_arr().filter(|p| p.len() == 2).ok_or_else(|| bad(k))?;
                let n = |v: &Value| v.as_i64().filter(|&n| n >= 0).map(|n| n as u64).ok_or_else(|| bad(k));
                Ok(Some((n(&parts[0])?, n(&parts[1])?)))
            }
        }
    };
    let max_iters = count("max_iters")?.map(|n| n.min(u32::MAX as u64) as u32);
    let max_files = count("max_files")?.map(|n| n as usize);
    let max_bytes = count("max_bytes")?.map(|n| n as usize);
    let (work, run) = (pair("work_limit")?, pair("run_limit")?);
    // (the model is built on the pass's own thread: its patterns are not Send)
    let out = on_own_stack(move || {
        let cfg = Config::new(&sources, &sinks, &full, &partial).with_limits(max_iters, max_files, max_bytes, work, run);
        pyflow::analyze(&files, cfg)
    });
    Ok(flow_out(out, 0))
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
/// function and with a template, split, as the engine's code calls them
/// (pyre, on linre). A pattern Python rejects is `{"error"}`; one linre does
/// not run, `{"error", "refused": true}`. (`"backtracking": true` asked for
/// sre's matcher alone until P-16 retired it: an error now.)
fn probe(args: &Value, text: &[u32]) -> Result<Value, CallError> {
    let pattern = arg_str(args, "pattern")?;
    let flags = opt_str(args, "flags").map(|f| pyre::flags_from_letters(&crate::pystr::to_string(&f))).unwrap_or(0);
    if matches!(args.get("backtracking"), Some(Value::Bool(true))) {
        return Err(CallError::BadArgs("pyre.probe: there is no backtracking matcher (P-16: every pattern runs on linre)".into()));
    }
    let rx = match Regex::new(&pattern, flags) {
        Ok(rx) => rx,
        Err(e) => {
            let refused = e.0.starts_with("linre does not run it");
            return Ok(Value::obj(vec![("error", Value::str(&e.0)), ("refused", Value::Bool(refused))]));
        }
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
    let base_end = [name.find('['), name.find(".items[")].into_iter().flatten().min().unwrap_or(name.len());
    let mut v = p.raw(&name[..base_end])?;
    let mut rest = &name[base_end..];
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix(".items[") {
            // a table of (key, pattern) items, by index
            let end = r.find(']')?;
            let i: usize = r.get(..end)?.parse().ok()?;
            v = v.get("items")?.as_arr()?.get(i)?.as_arr()?.get(1)?;
            rest = &r[end + 1..];
            continue;
        }
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
        } else if let Some(items) = v.get("items").and_then(|l| l.as_arr()) {
            for (i, kv) in items.iter().enumerate() {
                if let Some(x) = kv.as_arr().and_then(|kv| kv.get(1)) {
                    walk(format!("{}.items[{}]", name, i), x, out);
                }
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
