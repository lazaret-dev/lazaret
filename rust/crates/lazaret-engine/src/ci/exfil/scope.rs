//! Positive clearance of bulk secrets. Unknown senders/paths never count as proof of safety.
//! Sources are finding line numbers, so a send cannot promote an unrelated job's held value.
use super::*;

pub(super) fn expression_sources(
    p: &Pack,
    e: &[u32],
    line: usize,
    env: &AllEnv,
    outputs: &AllEnv,
) -> Origins {
    let mut out = Origins::new();
    if p.re("_WF_SECRETS_RE").search(e).is_some() {
        out.insert(line);
    }
    for m in p.re("_WFX_ENV_NAME_RE").finditer(e) {
        out.extend(env.get(first_group(&m)).into_iter().flatten().copied());
        out.extend(env.get(&u("*")).into_iter().flatten().copied());
    }
    for m in p.re("_WF_SCOPE_OUTPUT_RE").finditer(e) {
        let prefix = pystr::concat(&[
            m.group(1).unwrap_or(&[]),
            &u("."),
            m.group(2).unwrap_or(&[]),
            &u(".outputs."),
        ]);
        let key = pystr::concat(&[&prefix, m.group(3).unwrap_or(&[])]);
        out.extend(outputs.get(&key).into_iter().flatten().copied());
        out.extend(
            outputs
                .get(&pystr::concat(&[&prefix, &u("*")]))
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    // Dynamic indexing cannot identify the name. Keep the available taint rather than dropping it.
    if pystr::contains(e, "[") {
        if pystr::contains(e, "env[") || pystr::contains(e, "env [") {
            out.extend(env.values().flatten().copied());
        }
        if pystr::contains(e, "steps") || pystr::contains(e, "needs") {
            out.extend(outputs.values().flatten().copied());
        }
    }
    out
}

pub(super) fn record_sources(p: &Pack, r: &Rec, env: &AllEnv, outputs: &AllEnv) -> Origins {
    let first = r
        .lines()
        .iter()
        .find(|(_, t)| p.re("_WF_SECRETS_RE").search(t).is_some())
        .map(|(n, _)| *n)
        .unwrap_or(r.line);
    let mut out = Origins::new();
    for (_, t) in r.lines() {
        for e in outline::expressions(&t) {
            out.extend(expression_sources(p, e, first, env, outputs));
        }
    }
    out
}

pub(super) fn signal(ctx: &mut Ctx, got: &Content, kind: &'static str, how: &str) {
    if got.sources.is_empty() {
        return;
    }
    ctx.found.push((
        kind,
        ctx.line,
        Value::obj(vec![
            ("job", Value::Str(ctx.job.clone())),
            ("how", Value::str(how)),
            (
                "sources",
                Value::Arr(got.sources.iter().map(|n| Value::Int(*n as i64)).collect()),
            ),
        ]),
    ));
}

fn from_sources(sources: Origins) -> Content {
    Content {
        all: !sources.is_empty(),
        sources,
        ..Content::default()
    }
}

pub(super) fn reachable(ctx: &Ctx) -> Content {
    let mut out = ctx.everything();
    for file in ctx.files.values() {
        out.join(file);
    }
    out.join(&ctx.uncertain);
    out
}

/// Flow maps used for env/with/outputs. Expressions, quotes and nested lists are kept intact.
fn flow_fields(value: &[u32]) -> Vec<(PyStr, PyStr)> {
    let s = pystr::strip_chars(value, " \t");
    if s.first() != Some(&c('{')) || s.last() != Some(&c('}')) {
        return Vec::new();
    }
    let s = &s[1..s.len() - 1];
    let mut result = Vec::new();
    let (mut start, mut quote, mut depth, mut i) = (0, 0, 0usize, 0);
    while i <= s.len() {
        if i == s.len() || (quote == 0 && depth == 0 && s[i] == c(',')) {
            let part = &s[start..i];
            if let Some(k) = find(part, c(':'), 0) {
                result.push((
                    pystr::strip_chars(&part[..k], " \t'\"").to_vec(),
                    pystr::strip_chars(&part[k + 1..], " \t'\"").to_vec(),
                ));
            }
            start = i + 1;
        } else if quote != 0 {
            if s[i] == c('\\') {
                i += 1;
            } else if s[i] == quote {
                quote = 0;
            }
        } else if any_of(s[i], "'\"") {
            quote = s[i];
        } else if any_of(s[i], "{[") {
            depth += 1;
        } else if any_of(s[i], "}]") {
            depth = depth.saturating_sub(1);
        }
        i += 1;
    }
    result
}

pub(crate) fn records(text: &[u32]) -> Vec<Rec> {
    let mut out = Vec::new();
    for r in outline::outline(text, true, false) {
        let fields = if r.key_is("env") || r.key_is("with") || r.key_is("outputs") {
            flow_fields(&r.value)
        } else {
            Vec::new()
        };
        out.push(r.clone());
        for (key, value) in fields {
            let mut path = r.path.clone();
            path.push(r.key.clone().unwrap());
            out.push(Rec {
                path,
                key: Some(key),
                value,
                block: Vec::new(),
                item: false,
                line: r.line,
            });
        }
    }
    out
}

pub(super) fn flow_upload_paths(recs: &[&Rec]) -> Vec<PyStr> {
    recs.iter()
        .filter(|r| r.key_is("with") && r.path.len() == 4)
        .flat_map(|r| flow_fields(&r.value))
        .filter(|(k, _)| pystr::eq(k, "path"))
        .map(|(_, v)| v)
        .collect()
}

/// Workspace-relative paths keep their namespace; absolute paths never alias relative ones.
/// Unknown variables and home expansion are deliberately unresolved. Exclusions are ignored.
pub(super) fn normal_path(path: &[u32]) -> Option<PyStr> {
    let mut s = pystr::strip_chars(path, " \t\r\n'\"").to_vec();
    s = pystr::replace_char(&s, c('\\'), c('/'));
    let mut replaced = Vec::new();
    let mut i = 0;
    for (a, b) in outline::expression_spans(&s) {
        replaced.extend_from_slice(&s[i..a]);
        let compact: PyStr = s[a + 3..b - 2]
            .iter()
            .copied()
            .filter(|ch| !any_of(*ch, " \t"))
            .collect();
        if is(&compact, &["github.workspace", "runner.workspace"]) {
            replaced.extend(u("@WORKSPACE@"));
        } else {
            return None;
        }
        i = b;
    }
    replaced.extend_from_slice(&s[i..]);
    s = replaced;
    for prefix in ["$GITHUB_WORKSPACE", "${GITHUB_WORKSPACE}", "@WORKSPACE@"] {
        if pystr::starts_with(&s, prefix) {
            let n = prefix.chars().count();
            if s.len() == n || s.get(n) == Some(&c('/')) {
                s = pystr::lstrip_chars(&s[n..], "/").to_vec();
            }
        }
    }
    if s.iter().any(|ch| *ch == MARK || any_of(*ch, "$`~")) {
        return None;
    }
    let absolute = s.first() == Some(&c('/'));
    let mut parts: Vec<&[u32]> = Vec::new();
    for part in pystr::split_char(&s, c('/')) {
        if part.is_empty() || pystr::eq(part, ".") {
            continue;
        }
        if pystr::eq(part, "..") {
            if parts.pop().is_none() && !absolute {
                return None;
            }
        } else {
            parts.push(part);
        }
    }
    let mut result = if absolute { u("/") } else { Vec::new() };
    result.extend(pystr::join(&u("/"), &parts));
    Some(result)
}

fn covers(path: &[u32], file: &[u32]) -> Option<bool> {
    if pystr::starts_with(pystr::strip_chars(path, " \t"), "!") {
        return Some(false);
    }
    let path = normal_path(path)?;
    let file = normal_path(file)?;
    let glob = path.iter().position(|ch| any_of(*ch, "*?["));
    let lit = &path[..glob.unwrap_or(path.len())];
    if (path.first() == Some(&c('/'))) != (file.first() == Some(&c('/'))) {
        return Some(false);
    }
    Some(if glob.is_some() {
        file.starts_with(lit)
    } else {
        lit.is_empty()
            || file == lit
            || (file.starts_with(lit) && file.get(lit.len()) == Some(&c('/')))
    })
}

pub(super) fn runner_file(path: &[u32]) -> Option<&'static str> {
    let clean = pystr::strip_chars(path, " \t'\"");
    if is(clean, &["$GITHUB_ENV", "${GITHUB_ENV}", "$env:GITHUB_ENV"]) {
        Some("env")
    } else if is(
        clean,
        &["$GITHUB_OUTPUT", "${GITHUB_OUTPUT}", "$env:GITHUB_OUTPUT"],
    ) {
        Some("output")
    } else {
        None
    }
}

pub(super) fn handoff(target: &[u32], args: &[PyStr], out: &Content, ctx: &mut Ctx) {
    let Some(kind) = runner_file(&ctx.restore(target)) else {
        return;
    };
    let name = args
        .iter()
        .find_map(|a| {
            let (name, eq, _) = partition(a, c('='));
            (eq && !name.is_empty()
                && (is_letter(name[0]) || name[0] == c('_'))
                && name
                    .iter()
                    .all(|ch| is_letter(*ch) || is_digit(*ch) || *ch == c('_')))
            .then(|| name.to_vec())
        })
        .unwrap_or_else(|| u("*"));
    let map = if kind == "env" {
        &mut ctx.next_env
    } else {
        &mut ctx.next_outputs
    };
    // Unknown names affect all later references; they cannot clear a previous value.
    if pystr::eq(&name, "*") {
        if out.all {
            map.entry(name)
                .or_default()
                .extend(out.sources.iter().copied());
        }
    } else {
        map.insert(name, out.sources.clone());
    }
}

fn inline(name: &[u32], args: &[PyStr]) -> bool {
    if is(name, &["eval"]) {
        return true;
    }
    if pystr::starts_with(name, "python3.") || is(
        name,
        &[
            "python",
            "python3",
            "python3.13",
            "node",
            "nodejs",
            "ruby",
            "perl",
            "php",
            "bun",
            "deno",
            "pwsh",
            "powershell",
            "bash",
            "sh",
            "zsh",
        ],
    ) {
        return args.iter().any(|a| {
            is(&lower(a), &["-c", "-e", "-r", "-command", "--eval", "eval"])
                || pystr::starts_with(a, "--eval=")
                || pystr::eq(a, "-lc")
                || (["-c", "-e", "-r"].iter().any(|flag| pystr::starts_with(a, flag) && a.len() > 2))
        });
    }
    false
}

/// The send parser must understand every option capable of introducing request data.
fn unmodeled_send(name: &[u32], args: &[PyStr], p: &Pack) -> bool {
    if is(name, &["curl", "wget"]) {
        let curl = pystr::eq(name, "curl");
        let short = p.text(if curl {
            "_WFX_CURL_SHORT_VALUE"
        } else {
            "_WFX_WGET_SHORT_VALUE"
        });
        let long = p.strs(if curl {
            "_WFX_CURL_LONG_VALUE"
        } else {
            "_WFX_WGET_LONG_VALUE"
        });
        return options(args, &short, long).iter().any(|(opt, _)| {
            let Some(opt) = opt else {
                return false;
            };
            if curl {
                !is(
                    opt,
                    &[
                        "url",
                        "url-query",
                        "d",
                        "data",
                        "data-ascii",
                        "data-binary",
                        "data-raw",
                        "data-urlencode",
                        "json",
                        "H",
                        "header",
                        "F",
                        "form",
                        "form-string",
                        "T",
                        "upload-file",
                        "u",
                        "user",
                        "oauth2-bearer",
                        "s",
                        "S",
                        "f",
                        "L",
                        "I",
                        "i",
                        "v",
                        "k",
                        "q",
                        "G",
                        "X",
                        "request",
                        "o",
                        "O",
                        "output",
                        "output-dir",
                        "silent",
                        "show-error",
                        "fail",
                        "fail-with-body",
                        "location",
                        "head",
                        "include",
                        "verbose",
                        "insecure",
                        "max-time",
                        "m",
                        "connect-timeout",
                        "retry",
                        "retry-delay",
                        "retry-max-time",
                        "compressed",
                        "no-progress-meter",
                    ],
                )
            } else {
                !is(
                    opt,
                    &[
                        "header",
                        "post-file",
                        "body-file",
                        "post-data",
                        "body-data",
                        "O",
                        "output-document",
                        "q",
                        "quiet",
                        "nv",
                        "v",
                        "S",
                        "server-response",
                        "spider",
                        "method",
                        "timeout",
                        "tries",
                        "t",
                        "T",
                        "no-check-certificate",
                    ],
                )
            }
        });
    }
    // Hashtable headers and abbreviated parameters aren't modeled by the PowerShell reader.
    if is(
        name,
        &["invoke-webrequest", "iwr", "invoke-restmethod", "irm"],
    ) {
        return args.iter().any(|a| {
            pystr::starts_with(a, "-")
                && !is(
                    &lower(a),
                    &[
                        "-uri",
                        "-url",
                        "-body",
                        "-form",
                        "-infile",
                        "-method",
                        "-outfile",
                        "-usebasicparsing",
                        "-verbose",
                    ],
                )
        });
    }
    false
}

pub(super) fn command_scope(
    name: &[u32],
    args: &[PyStr],
    seg: &[u32],
    own: &Content,
    ctx: &mut Ctx,
) {
    let mut available = reachable(ctx);
    available.join(own);
    let sending_cli = is(
        name,
        &[
            "gh", "gsutil", "rclone", "scp", "sftp", "ssh", "socat", "telnet", "ftp",
        ],
    ) || (is(name, &["aws", "az", "gcloud"])
        && args.iter().any(|a| is(a, &["s3", "storage"])))
        || (pystr::eq(name, "rsync") && args.iter().any(|a| a.contains(&c(':'))))
        || (pystr::eq(name, "openssl") && args.iter().any(|a| pystr::eq(a, "s_client")))
        || (pystr::eq(name, "git") && args.iter().any(|a| pystr::eq(a, "push")));
    let modeled = has(ctx.p.strs("_WFX_SENDERS"), name);
    let script = (is(
        name,
        &[
            "python", "python3", "node", "nodejs", "ruby", "perl", "npm", "pnpm", "yarn", "make",
            "pytest", "cargo",
        ],
    ) && !inline(name, args))
        || [".sh", ".py", ".js", ".mjs"]
            .iter()
            .any(|ext| pystr::ends_with(name, ext));
    let harmless = is(
        name,
        &[
            "echo",
            "printf",
            "cat",
            "type",
            "get-content",
            "gc",
            "jq",
            "base64",
            "xxd",
            "gzip",
            "head",
            "tail",
            "true",
            "false",
            "test",
            "[",
            "env",
            "printenv",
            "tee",
            "export",
            "mkdir",
            "touch",
            "pwd",
            "ls",
        ],
    );
    let network = ctx.p.re("_WF_NETWORK_RE").search(seg).is_some();
    let config = modeled && unmodeled_send(name, args, ctx.p);
    if inline(name, args) || sending_cli || config || (network && !modeled && !harmless && !script)
    {
        signal(
            ctx,
            &available,
            "secrets-uncleared",
            "cannot clear an opaque or unsupported sender",
        );
    }
    if modeled && ctx.uncertain.all {
        let uncertain = ctx.uncertain.clone();
        signal(
            ctx,
            &uncertain,
            "secrets-uncleared",
            "cannot clear an unmodeled data or file hand-off",
        );
    }
    if modeled
        && args
            .iter()
            .any(|a| pystr::starts_with(a, "@$") || pystr::starts_with(a, "@\u{1}"))
    {
        signal(
            ctx,
            &available,
            "secrets-uncleared",
            "cannot resolve a sent file path",
        );
    }
    // File transformations and control-flow are not proofs of an unrelated upload.
    if is(
        name,
        &[
            "cp", "mv", "zip", "tar", "openssl", "cd", "pushd", "if", "for", "while", "case",
            "function",
        ],
    ) || inline(name, args)
        || pystr::contains(name, "()")
        || (!modeled && !harmless && !script)
    {
        ctx.uncertain.join(&available);
    }
    if is(name, &["cd", "pushd"]) {
        ctx.cwd_unknown = true;
    }
}

/// Jobs in needs order, independent of YAML declaration order. Cycles retain textual order and cannot
/// erase taint; invalid dependency graphs are not executed by GitHub in any event.
fn ordered_steps<'a>(p: &Pack, records: &'a [Rec]) -> Vec<(PyStr, Vec<Vec<&'a Rec>>)> {
    let mut groups: BTreeMap<PyStr, Vec<Vec<&Rec>>> = BTreeMap::new();
    let mut order = Vec::new();
    for (job, recs) in workflow::steps(records) {
        if !groups.contains_key(&job) {
            order.push(job.clone());
        }
        groups.entry(job).or_default().push(recs);
    }
    let mut deps: BTreeMap<PyStr, BTreeSet<PyStr>> = BTreeMap::new();
    for r in records {
        if r.path.len() >= 2
            && pystr::eq(&r.path[0], "jobs")
            && ((r.path.len() == 2 && r.key_is("needs"))
                || (r.path.len() == 3 && r.path_ends("needs")))
        {
            for word in p.re("_WF_EVENT_WORD_RE").findall(&r.text()) {
                if groups.contains_key(word) {
                    deps.entry(r.path[1].clone())
                        .or_default()
                        .insert(word.to_vec());
                }
            }
        }
    }
    let mut followers: BTreeMap<PyStr, Vec<PyStr>> = BTreeMap::new();
    for (job, need) in &deps {
        for parent in need {
            followers
                .entry(parent.clone())
                .or_default()
                .push(job.clone());
        }
    }
    let mut ready: std::collections::VecDeque<PyStr> = order
        .iter()
        .filter(|j| deps.get(*j).is_none_or(|s| s.is_empty()))
        .cloned()
        .collect();
    let mut result = Vec::new();
    while let Some(job) = ready.pop_front() {
        if let Some(steps) = groups.remove(&job) {
            result.push((job.clone(), steps));
        }
        for child in followers.get(&job).into_iter().flatten() {
            if let Some(set) = deps.get_mut(child) {
                set.remove(&job);
                if set.is_empty() {
                    ready.push_back(child.clone());
                }
            }
        }
    }
    for job in order {
        if let Some(steps) = groups.remove(&job) {
            result.push((job, steps));
        }
    }
    result
}

pub(super) fn read(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = records(text);
    let mut workflow_env = Env::new();
    let mut workflow_values = Values::new();
    let mut workflow_all = AllEnv::new();
    let mut source_lines = BTreeMap::new();
    for r in &records {
        let hits: Vec<usize> = r
            .lines()
            .iter()
            .filter(|(_, t)| p.re("_WF_SECRETS_RE").search(t).is_some())
            .map(|(n, _)| *n)
            .collect();
        if let Some(first) = hits.first() {
            for line in &hits {
                source_lines.insert(*line, *first);
            }
        }
        if r.key.is_some() && r.path_is(&["env"]) {
            env_entry(
                p,
                r,
                &mut workflow_env,
                &mut workflow_values,
                &mut workflow_all,
                Some(&Env::new()),
            );
        }
    }
    let source_lines = std::rc::Rc::new(source_lines);
    let workflow_cwd = records.iter().any(|r| {
        r.path.first().is_some_and(|x| pystr::eq(x, "defaults"))
            && r.key_is("working-directory")
    });
    let mut job_records: BTreeMap<PyStr, Vec<&Rec>> = BTreeMap::new();
    for r in &records {
        if r.path.len() >= 2 && pystr::eq(&r.path[0], "jobs") {
            job_records.entry(r.path[1].clone()).or_default().push(r);
        }
    }
    let mut found = Vec::new();
    let mut job_outputs = AllEnv::new();
    for (job, steps) in ordered_steps(p, &records) {
        let mut job_env = workflow_env.clone();
        let mut job_values = workflow_values.clone();
        let mut job_all = workflow_all.clone();
        let mut output_defs = Vec::new();
        let mut job_cwd = workflow_cwd;
        for &r in job_records.get(&job).into_iter().flatten() {
            if r.path.len() == 3 && r.path_ends("env") && r.key.is_some() {
                let sources = record_sources(p, r, &job_all, &job_outputs);
                env_entry(
                    p,
                    r,
                    &mut job_env,
                    &mut job_values,
                    &mut job_all,
                    Some(&workflow_env),
                );
                let key = r.key.clone().unwrap();
                if sources.is_empty() {
                    job_all.remove(&key);
                } else {
                    job_all.insert(key, sources);
                }
            }
            if r.path.len() == 3 && r.path_ends("outputs") && r.key.is_some() {
                output_defs.push(r);
            }
            if r.path.len() <= 4 && r.key_is("working-directory") {
                job_cwd = true;
            }
        }
        let mut files = BTreeMap::new();
        let mut uncertain = Content::default();
        let mut persistent = AllEnv::new();
        let mut outputs = job_outputs.clone();
        for recs in steps {
            let mut env = job_env.clone();
            let mut values = job_values.clone();
            let mut env_all = job_all.clone();
            for (key, sources) in &persistent {
                if sources.is_empty() {
                    env_all.remove(key);
                } else {
                    env_all.insert(key.clone(), sources.clone());
                }
            }
            for r in &recs {
                if r.key.is_some() && r.path.len() == 5 && pystr::eq(&r.path[4], "env") {
                    let sources = record_sources(p, r, &env_all, &outputs);
                    env_entry(p, r, &mut env, &mut values, &mut env_all, None);
                    let key = r.key.clone().unwrap();
                    if sources.is_empty() {
                        env_all.remove(&key);
                    } else {
                        env_all.insert(key, sources);
                    }
                }
            }
            let id = recs
                .iter()
                .find(|r| r.key_is("id") && r.path.len() == 4)
                .map(|r| r.value.clone());
            let mut ctx = Ctx {
                p,
                exprs: Vec::new(),
                env,
                values,
                local: Vec::new(),
                local_at: BTreeMap::new(),
                files,
                job: job.clone(),
                line: recs.first().map(|r| r.line).unwrap_or(0),
                found: Vec::new(),
                depth_max: p.usize("_WFX_DEPTH"),
                env_all,
                outputs: outputs.clone(),
                next_env: AllEnv::new(),
                next_outputs: AllEnv::new(),
                uncertain,
                cwd_unknown: job_cwd || recs.iter().any(|r| r.key_is("working-directory")),
                source_lines: source_lines.clone(),
            };
            if let Some((paths, line)) = artifact_upload(&recs) {
                ctx.line = line;
                let mut sent = Content::default();
                let mut unresolved = false;
                for path in &paths {
                    if normal_path(path).is_none() {
                        unresolved = true;
                    }
                    for (file, value) in &ctx.files {
                        match covers(path, file) {
                            Some(true) => sent.join(value),
                            None => unresolved = true,
                            _ => {}
                        }
                    }
                }
                if sent.all {
                    signal(&mut ctx, &sent, "secrets-sent", "an artifact upload");
                }
                if unresolved || ctx.uncertain.all {
                    let available = if unresolved {
                        reachable(&ctx)
                    } else {
                        ctx.uncertain.clone()
                    };
                    signal(
                        &mut ctx,
                        &available,
                        "secrets-uncleared",
                        "cannot resolve an artifact path or file hand-off",
                    );
                }
            }
            // github-script's script input is executable code, unlike ordinary action inputs.
            if recs.iter().any(|r| {
                r.key_is("uses") && pystr::starts_with(&lower(&r.value), "actions/github-script@")
            }) {
                for r in &recs {
                    if r.key_is("script") && r.path_ends("with") {
                        let mut available = reachable(&ctx);
                        available.join(&from_sources(record_sources(
                            p,
                            r,
                            &ctx.env_all,
                            &ctx.outputs,
                        )));
                        ctx.line = r.line;
                        signal(
                            &mut ctx,
                            &available,
                            "secrets-uncleared",
                            "cannot clear executable github-script input",
                        );
                    }
                }
            }
            let lines = workflow::logical_lines(&workflow::step_run_lines(&recs));
            let mut k = 0;
            while k < lines.len() {
                let (line, t) = &lines[k];
                k += 1;
                ctx.line = *line;
                if t.len() > p.usize("_WFX_LINE_MAX") {
                    let mut got = reachable(&ctx);
                    for e in outline::expressions(t) {
                        got.join(&from_sources(expression_sources(
                            p,
                            e,
                            *line,
                            &ctx.env_all,
                            &ctx.outputs,
                        )));
                    }
                    ctx.uncertain.join(&got);
                    signal(
                        &mut ctx,
                        &got,
                        "secrets-uncleared",
                        "analysis limit prevents clearance",
                    );
                    continue;
                }
                let origin = ctx.source_lines.get(line).copied().unwrap_or(*line);
                let mark = marked(t, &mut ctx.exprs, origin);
                let mut heredocs = Vec::new();
                for m in p.re("_WFX_HEREDOC_RE").finditer(&mark) {
                    let delimiter = first_group(&m);
                    let mut body = Vec::new();
                    while k < lines.len() && pystr::strip_chars(&lines[k].1, " \t") != delimiter {
                        let origin = ctx
                            .source_lines
                            .get(&lines[k].0)
                            .copied()
                            .unwrap_or(lines[k].0);
                        body.push(marked(&lines[k].1, &mut ctx.exprs, origin));
                        k += 1;
                    }
                    k += 1;
                    let mut got = Content::default();
                    for b in &body {
                        got.join(&content(b, &mut ctx, 0));
                    }
                    heredocs.push(got);
                }
                eval(&mark, &mut ctx, 0, Some(&mut heredocs));
            }
            persistent.extend(ctx.next_env);
            if let Some(id) = id {
                for (name, sources) in ctx.next_outputs {
                    outputs.insert(
                        pystr::concat(&[&u("steps."), &id, &u(".outputs."), &name]),
                        sources,
                    );
                }
            }
            found.extend(ctx.found);
            files = ctx.files;
            uncertain = ctx.uncertain;
        }
        for r in output_defs {
            let sources = record_sources(p, r, &job_all, &outputs);
            job_outputs.insert(
                pystr::concat(&[&u("needs."), &job, &u(".outputs."), r.key.as_ref().unwrap()]),
                sources,
            );
        }
    }
    found
}
