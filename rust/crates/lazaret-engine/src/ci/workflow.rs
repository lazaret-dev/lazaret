//! GitHub Actions workflows (scanner/ghworkflow.py and its npm twin until BR-7 moved them here, 0.1.9).
//!
//! The worms' shapes: a workflow that hands every repository secret (`${{ toJSON(secrets) }}`) to a job's
//! environment or a script (SC-WORKFLOW-SECRETS; the Shai-Hulud waves), and one that puts text anyone can write
//! (an issue's, a discussion's, a pull request's) into a command on a self-hosted runner (SC-WORKFLOW-BACKDOOR).
//! The hardening checks: what a pipeline should do (actions pinned to a commit, no pull_request_target job running a
//! pull request's code, no build cache in a release, read-only tokens, no OIDC token where dependencies install, no
//! script fetched and run unread). The patterns, lists and rule texts are the pack's (`_WF_*`).

use super::outline::{self, Rec};
use crate::findings::{self, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};

const fn c(ch: char) -> u32 {
    ch as u32
}

const HEX: &str = "0123456789abcdefABCDEF";

/// A finding of a reader: (kind, line, detail).
pub type Found = (&'static str, usize, Value);

fn s(v: &[u32]) -> Value {
    Value::Str(v.to_vec())
}

fn is_hex(v: &[u32], n: usize) -> bool {
    v.len() == n && v.iter().all(|&ch| HEX.chars().any(|h| h as u32 == ch))
}

fn is_digit(ch: u32) -> bool {
    (c('0')..=c('9')).contains(&ch)
}

/// Is `path` ('/' or '\\' separators) a workflow: .github/workflows/*.yml|yaml?
pub fn is_workflow(path: &[u32]) -> bool {
    let p = pystr::replace_char(path, c('\\'), c('/'));
    let parts = pystr::split_char(&p, c('/'));
    let n = parts.len();
    n >= 3
        && pystr::eq(&pystr::lower(parts[n - 3]), ".github")
        && pystr::eq(&pystr::lower(parts[n - 2]), "workflows")
        && {
            let name = pystr::lower(parts[n - 1]);
            pystr::ends_with(&name, ".yml") || pystr::ends_with(&name, ".yaml")
        }
}

fn is_run(r: &Rec) -> bool {
    r.key_is("run") || (r.key.is_none() && r.path_ends("run"))
}

/// The names of the events that start the workflow (its `on:`).
fn events(p: &Pack, records: &[Rec]) -> Vec<PyStr> {
    let word = p.re("_WF_EVENT_WORD_RE");
    let mut names: Vec<PyStr> = Vec::new();
    for r in records {
        if r.path.is_empty() && (r.key_is("on") || r.key_is("true")) {
            names.extend(word.findall(&r.value).into_iter().map(|x| x.to_vec()));
        } else if r.path_is(&["on"]) && r.key.is_some() {
            names.push(r.key.clone().unwrap_or_default());
        } else if r.path_is(&["on", "-"]) && r.key.is_none() {
            names.extend(word.findall(&r.value).into_iter().map(|x| x.to_vec()));
        }
    }
    names
}

fn has_event(events: &[PyStr], name: &str) -> bool {
    events.iter().any(|e| pystr::eq(e, name))
}

/// The worms' shapes in a workflow's text: kind 'secrets' {where, how} (how null when nothing sends them out),
/// 'backdoor' {job, expr, event, act}; and, where `extra` gives them, the findings that sit between the two
/// (RA-1's sends, read by the caller).
pub fn findings(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = outline::outline(text, false, false);
    let mut out: Vec<Found> = Vec::new();
    // every secret handed to a job's environment or a script
    let mut sends: Option<&'static str> = None;
    let network = p.re("_WF_NETWORK_RE");
    for r in &records {
        if r.key_is("uses") && pystr::starts_with(&r.value, "actions/upload-artifact") {
            sends = sends.or(Some("an artifact upload"));
        } else if is_run(r) && network.search(&r.text()).is_some() {
            sends = sends.or(Some("a network command"));
        }
    }
    let secrets = p.re("_WF_SECRETS_RE");
    for r in &records {
        if r.path_has("with") {
            continue;
        }
        let where_ = if r.path_ends("env") && r.key.is_some() {
            "a job's environment"
        } else if is_run(r) {
            "a script"
        } else {
            continue;
        };
        for (line, t) in r.lines() {
            if secrets.search(&t).is_some() {
                out.push((
                    "secrets",
                    line,
                    Value::obj(vec![("where", Value::str(where_)), ("how", sends.map(Value::str).unwrap_or(Value::Null))]),
                ));
                break;
            }
        }
    }
    out
}

/// The backdoor: event text in a command on a self-hosted runner, when an event anyone can start starts it.
pub fn backdoor(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = outline::outline(text, false, false);
    let evs = events(p, &records);
    let names = p.strs("_WF_OUTSIDER_EVENTS");
    let acts = p.strs("_WF_OUTSIDER_ACTS");
    let outsider = names.iter().zip(acts).find(|(e, _)| evs.iter().any(|x| x == *e));
    let (event, act) = match outsider {
        Some(x) => x,
        None => return Vec::new(),
    };
    let mut hosted: Vec<PyStr> = Vec::new();
    for r in &records {
        let path = &r.path;
        if path.len() >= 2
            && pystr::eq(&path[0], "jobs")
            && ((path.len() == 2 && r.key_is("runs-on")) || path.get(2).is_some_and(|x| pystr::eq(x, "runs-on")))
            && pystr::contains(&pystr::lower(&r.text()), "self-hosted")
            && !hosted.contains(&path[1])
        {
            hosted.push(path[1].clone());
        }
    }
    let untrusted = p.re("_WF_UNTRUSTED_RE");
    let mut out: Vec<Found> = Vec::new();
    for r in &records {
        let path = &r.path;
        if path.len() < 4
            || !pystr::eq(&path[0], "jobs")
            || !hosted.contains(&path[1])
            || !pystr::eq(&path[2], "steps")
            || !pystr::eq(&path[3], "-")
        {
            continue;
        }
        if !(r.key_is("run") && path.len() == 4) && !(r.key.is_none() && path.len() == 5 && pystr::eq(&path[4], "run")) {
            continue;
        }
        for (line, t) in r.lines() {
            let hit = outline::expressions(&t).into_iter().find_map(|e| untrusted.search(e).map(|m| m.group0().to_vec()));
            if let Some(expr) = hit {
                out.push((
                    "backdoor",
                    line,
                    Value::obj(vec![
                        ("job", s(&path[1])),
                        ("expr", Value::Str(expr)),
                        ("event", s(event)),
                        ("act", s(act)),
                    ]),
                ));
                break;
            }
        }
    }
    out
}

// ---------------------------------------------------------------- hardening

/// (kind, name, ref, pinned) of a `uses:` value: kind "action", "docker" or "workflow" (a reusable one); ref "" for
/// none; None for a local path (`./…`).
pub fn parse_uses(value: &[u32]) -> Option<(&'static str, PyStr, PyStr, bool)> {
    let v = pystr::strip_chars(value, " \t");
    if v.is_empty() || pystr::eq(v, ".") || pystr::starts_with(v, "./") || pystr::starts_with(v, "../") {
        return None;
    }
    if pystr::starts_with(v, "docker://") {
        let rest = &v[9..];
        return Some(match pystr::find_char(rest, c('@'), 0) {
            Some(k) => {
                let digest = &rest[k + 1..];
                let pinned = pystr::starts_with(digest, "sha256:") && is_hex(&digest[7..], 64);
                ("docker", rest[..k].to_vec(), digest.to_vec(), pinned)
            }
            None => ("docker", rest.to_vec(), Vec::new(), false),
        });
    }
    let (name, ref_, at) = match pystr::find_char(v, c('@'), 0) {
        Some(k) => (&v[..k], &v[k + 1..], true),
        None => (v, &v[v.len()..], false),
    };
    let kind = if pystr::contains(name, "/.github/workflows/") { "workflow" } else { "action" };
    Some((kind, name.to_vec(), if at { ref_.to_vec() } else { Vec::new() }, at && is_hex(ref_, 40)))
}

/// [(line, value)] of every `uses:` of a workflow: a step's, and a job's (a reusable workflow).
pub fn uses(text: &[u32]) -> Vec<(usize, PyStr)> {
    outline::outline(text, false, false)
        .into_iter()
        .filter(|r| r.key_is("uses") && (is_step_path(&r.path) || is_job_path(&r.path)))
        .map(|r| (r.line, r.value))
        .collect()
}

fn is_step_path(p: &[PyStr]) -> bool {
    p.len() == 4 && pystr::eq(&p[0], "jobs") && pystr::eq(&p[2], "steps") && pystr::eq(&p[3], "-")
}

fn is_job_path(p: &[PyStr]) -> bool {
    p.len() == 2 && pystr::eq(&p[0], "jobs")
}

/// Does ref read as a version tag (`v4`, `1.2.3`)?
fn tag_like(r: &[u32]) -> bool {
    !r.is_empty() && (is_digit(r[0]) || (r[0] == c('v') && r.len() > 1 && is_digit(r[1])))
}

fn in_actions(name: &[u32], names: &[PyStr]) -> bool {
    names.iter().any(|a| name == a.as_slice() || (name.len() > a.len() && name.starts_with(a) && name[a.len()] == c('/')))
}

/// [(job, its records)]: the steps of every job, in order (records from outline(text, items)).
fn steps(records: &[Rec]) -> Vec<(PyStr, Vec<&Rec>)> {
    let mut out: Vec<(PyStr, Vec<&Rec>)> = Vec::new();
    for r in records {
        let p = &r.path;
        if p.len() >= 4 && pystr::eq(&p[0], "jobs") && pystr::eq(&p[2], "steps") && pystr::eq(&p[3], "-") {
            if (p.len() == 4 && r.item) || out.last().map_or(true, |(j, _)| *j != p[1]) {
                out.push((p[1].clone(), Vec::new()));
            }
            if let Some(last) = out.last_mut() {
                last.1.push(r);
            }
        }
    }
    out
}

/// (value, line) of a step's `uses:`.
fn step_uses(recs: &[&Rec]) -> Option<(PyStr, usize)> {
    recs.iter().find(|r| r.key_is("uses") && r.path.len() == 4).map(|r| (r.value.clone(), r.line))
}

/// input -> (value, line) of a step's `with:` (the first of each).
fn step_with(recs: &[&Rec]) -> Vec<(PyStr, PyStr, usize)> {
    let mut out: Vec<(PyStr, PyStr, usize)> = Vec::new();
    for r in recs {
        if r.path.len() == 5 && pystr::eq(&r.path[4], "with") {
            if let Some(k) = &r.key {
                if !out.iter().any(|(x, _, _)| x == k) {
                    out.push((k.clone(), r.value.clone(), r.line));
                }
            }
        }
    }
    out
}

fn with_get<'a>(withs: &'a [(PyStr, PyStr, usize)], key: &str) -> Option<(&'a [u32], usize)> {
    withs.iter().find(|(k, _, _)| pystr::eq(k, key)).map(|(_, v, l)| (v.as_slice(), *l))
}

/// [(line, text)] of a step's script.
fn step_run_lines(recs: &[&Rec]) -> Vec<(usize, PyStr)> {
    let mut out = Vec::new();
    for r in recs {
        let p = &r.path;
        if (r.key_is("run") && p.len() == 4) || (r.key.is_none() && p.len() == 5 && pystr::eq(&p[4], "run")) {
            out.extend(r.lines());
        }
    }
    out
}

/// What a `permissions:` grants: present, [(scope, line)] granted write, the line of an id-token grant.
#[derive(Clone, Default)]
struct Grants {
    present: bool,
    scopes: Vec<(PyStr, usize)>,
    token: Option<usize>,
}

/// owner (None: the workflow; Some(job)) -> its grants, for the workflow and each job that states some.
fn permissions(p: &Pack, records: &[Rec]) -> Vec<(Option<PyStr>, Grants)> {
    let mut table: Vec<(Option<PyStr>, Grants)> = Vec::new();
    fn entry<'a>(table: &'a mut Vec<(Option<PyStr>, Grants)>, owner: Option<PyStr>) -> &'a mut Grants {
        let k = match table.iter().position(|(o, _)| *o == owner) {
            Some(k) => k,
            None => {
                table.push((owner, Grants::default()));
                table.len() - 1
            }
        };
        &mut table[k].1
    }
    let write = p.re("_WF_WRITE_SCOPE_RE");
    for r in records {
        let path = &r.path;
        if r.key_is("permissions") && (path.is_empty() || is_job_path(path)) {
            let owner = if path.is_empty() { None } else { Some(path[1].clone()) };
            let e = entry(&mut table, owner);
            e.present = true;
            if pystr::eq(&r.value, "write-all") {
                e.scopes.push((u("all"), r.line));
                e.token = e.token.or(Some(r.line));
            } else if pystr::starts_with(&r.value, "{") {
                for m in write.finditer(&r.value) {
                    let scope = m.group(1).unwrap_or(&[]).to_vec();
                    if pystr::eq(&scope, "id-token") {
                        e.token = e.token.or(Some(r.line));
                    }
                    e.scopes.push((scope, r.line));
                }
            }
        } else if let Some(key) = &r.key {
            if pystr::eq(&r.value, "write")
                && r.path_ends("permissions")
                && (path.len() == 1 || (path.len() == 3 && pystr::eq(&path[0], "jobs")))
            {
                let owner = if path.len() == 1 { None } else { Some(path[1].clone()) };
                let e = entry(&mut table, owner);
                e.scopes.push((key.clone(), r.line));
                if pystr::eq(key, "id-token") {
                    e.token = e.token.or(Some(r.line));
                }
            }
        }
    }
    table
}

fn grants(table: &[(Option<PyStr>, Grants)], owner: Option<&[u32]>) -> Grants {
    table.iter().find(|(o, _)| o.as_deref() == owner).map(|(_, g)| g.clone()).unwrap_or_default()
}

/// Why this workflow is a release (it publishes something), or None.
fn release_why(p: &Pack, table: &[(Option<PyStr>, Grants)], steps: &[(PyStr, Vec<&Rec>)], events: &[PyStr]) -> Option<PyStr> {
    if has_event(events, "release") {
        return Some(u("it runs when a release is published"));
    }
    if table.iter().any(|(_, g)| g.token.is_some()) {
        return Some(u("it asks for an OIDC token"));
    }
    let publish = p.strs("_WF_PUBLISH_ACTIONS");
    for (_job, recs) in steps {
        if let Some((value, _)) = step_uses(recs) {
            if let Some((_, name, _, _)) = parse_uses(&value) {
                if in_actions(&pystr::lower(&name), publish) {
                    return Some(pystr::concat(&[&u("it uses "), &name]));
                }
            }
        }
        for (_line, t) in step_run_lines(recs) {
            if let Some(found) = publish_command(p, &t) {
                return Some(pystr::concat(&[&u("it runs `"), &found, &u("`")]));
            }
        }
    }
    None
}

/// (line, what, explicit) for a step that restores a cache, or None.
fn cache_of(p: &Pack, recs: &[&Rec]) -> Option<(usize, PyStr, bool)> {
    let (value, use_line) = step_uses(recs)?;
    let (_, aname, _, _) = parse_uses(&value)?;
    let name = pystr::lower(&aname);
    if in_actions(&name, p.strs("_WF_CACHE_ACTIONS")) {
        return Some((use_line, aname, true));
    }
    let withs = step_with(recs);
    let actions = p.strs("_WF_SETUP_CACHE_ACTIONS");
    let keys = p.strs("_WF_SETUP_CACHE_KEYS");
    let on = p.strs("_WF_SETUP_CACHE_ON");
    for (action, key) in actions.iter().zip(keys) {
        if name != *action {
            continue;
        }
        let (v, line) = with_get(&withs, &pystr::to_string(key)).unwrap_or((&[], use_line));
        if !v.is_empty() && !pystr::eq(v, "false") {
            return Some((line, pystr::concat(&[&aname, &u(" with "), key, &u(": "), v]), true));
        }
        if v.is_empty() && pystr::eq(action, "actions/setup-node") {
            if !with_get(&withs, "package-manager-cache").is_some_and(|(x, _)| pystr::eq(x, "false")) {
                return Some((use_line, pystr::concat(&[&aname, &u(" (it may cache unless package-manager-cache: false)")]), false));
            }
        } else if v.is_empty() && on.contains(action) {
            return Some((use_line, pystr::concat(&[&aname, &u(" (it caches unless "), key, &u(": false)")]), false));
        }
        return None;
    }
    None
}

/// The dependency install in a script line (`npm ci`, `pip install`), or None; a line that passes
/// `--ignore-scripts` is not counted.
pub fn install_command(p: &Pack, text: &[u32]) -> Option<PyStr> {
    let m = p.re("_WF_INSTALL_RE").search(text)?;
    if pystr::contains(text, "--ignore-scripts") {
        return None;
    }
    m.group(1).map(|g| g.to_vec())
}

/// The command in a script line that publishes a release (`npm publish`, `twine upload`), or None.
pub fn publish_command(p: &Pack, text: &[u32]) -> Option<PyStr> {
    p.re("_WF_PUBLISH_RE").search(text).and_then(|m| m.group(1).map(|g| g.to_vec()))
}

/// A script line that fetches a script and runs it unread: `curl … | sh`, `bash <(curl …)`, `sh -c "$(curl …)"`,
/// `eval "$(wget …)"`, `iwr … | iex`, as `curl … | sh`; or None.
pub fn pipe_to_shell(p: &Pack, text: &[u32]) -> Option<PyStr> {
    let head = p.re("_WF_SCRIPT_HEAD_RE");
    let fetch = p.re("_WF_FETCH_RE");
    let stdin_only = p.re("_WF_STDIN_ONLY_RE");
    let shells = p.strs("_WF_SHELLS");
    for pipeline in p.re("_WF_PIPELINE_RE").split(text, 0).into_iter().flatten() {
        let mut fetched: Option<PyStr> = None;
        let joined = pystr::replace(pipeline, &u("|&"), &u("|"));
        for seg in pystr::split_char(&joined, c('|')) {
            if let Some(f) = &fetched {
                if let Some(m) = head.match_(seg) {
                    let interp = m.group(1).unwrap_or(&[]);
                    let low = pystr::lower(interp);
                    if shells.iter().any(|sh| low.starts_with(sh)) || stdin_only.match_at(seg, m.end() as isize, seg.len() as isize).is_some() {
                        return Some(pystr::concat(&[f, &u(" … | "), interp]));
                    }
                }
            }
            if let Some(m) = fetch.search(seg) {
                if fetched.is_none() {
                    fetched = Some(m.group(1).unwrap_or(&[]).to_vec());
                }
            }
        }
    }
    p.re("_WF_FETCHED_ARG_RE").search(text).map(|m| m.group0().to_vec())
}

/// [(line, text)] with a script's continued lines (`… \`) joined to the line they continue, at its first line.
pub fn logical_lines(lines: &[(usize, PyStr)]) -> Vec<(usize, PyStr)> {
    let mut out: Vec<(usize, PyStr)> = Vec::new();
    let mut first = 0usize;
    let mut parts: Option<Vec<&[u32]>> = None;
    for (n, t) in lines {
        let ps = parts.get_or_insert_with(|| {
            first = *n;
            Vec::new()
        });
        let continued = t.last() == Some(&c('\\'));
        ps.push(if continued { &t[..t.len() - 1] } else { &t[..] });
        if !continued {
            out.push((first, pystr::join(&[c(' ')], ps)));
            parts = None;
        }
    }
    if let Some(ps) = parts {
        out.push((first, pystr::join(&[c(' ')], &ps)));
    }
    out
}

/// The hardening checks of a workflow's text, by line: 'unpinned' {uses, kind, ref, first, tag}; 'pr-checkout'
/// {job, via, expr}; 'cache' {job, what, explicit, why}; 'perms' {scopes}; 'perms-missing' {jobs}; 'oidc-install'
/// {job, from, command}; 'pipe-to-shell' {job, command}.
pub fn hardening(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = outline::outline(text, true, false);
    let evs = events(p, &records);
    let steps = steps(&records);
    let jobs: Vec<PyStr> = records.iter().filter(|r| r.path_is(&["jobs"]) && r.key.is_some()).filter_map(|r| r.key.clone()).collect();
    let mut out: Vec<Found> = Vec::new();
    // write permissions for every job; or none stated, and jobs that state none
    let table = permissions(p, &records);
    let top = grants(&table, None);
    if let Some((_, line)) = top.scopes.first() {
        out.push(("perms", *line, Value::obj(vec![("scopes", Value::Arr(top.scopes.iter().map(|(sc, _)| s(sc)).collect()))])));
    } else if !top.present {
        let bare: Vec<&PyStr> = jobs.iter().filter(|j| !grants(&table, Some(j)).present).collect();
        if !bare.is_empty() {
            let where_ = records.iter().find(|r| r.path.is_empty() && r.key_is("jobs")).map(|r| r.line).unwrap_or(1);
            out.push(("perms-missing", where_, Value::obj(vec![("jobs", Value::Arr(bare.iter().map(|j| s(j)).collect()))])));
        }
    }
    // actions, reusable workflows and images that are not pinned
    let first_party = p.strs("_WF_FIRST_PARTY");
    for r in &records {
        if !r.key_is("uses") || !(is_step_path(&r.path) || is_job_path(&r.path)) {
            continue;
        }
        if let Some((kind, name, tag, pinned)) = parse_uses(&r.value) {
            if !pinned {
                let low = pystr::lower(&name);
                out.push((
                    "unpinned",
                    r.line,
                    Value::obj(vec![
                        ("uses", s(&r.value)),
                        ("kind", Value::str(kind)),
                        ("ref", Value::Str(tag.clone())),
                        ("first", Value::Bool(kind == "action" && first_party.iter().any(|f| low.starts_with(f)))),
                        ("tag", Value::Bool(tag_like(&tag))),
                    ]),
                ));
            }
        }
    }
    // a pull_request_target job that checks out the pull request
    if has_event(&evs, "pull_request_target") {
        let head = p.re("_WF_PR_HEAD_RE");
        for (job, recs) in &steps {
            let mut hit: Option<(usize, PyStr, PyStr)> = None;
            if let Some((value, _)) = step_uses(recs) {
                if let Some((_, name, _, _)) = parse_uses(&value) {
                    if pystr::eq(&pystr::lower(&name), "actions/checkout") {
                        let withs = step_with(recs);
                        for key in ["ref", "repository"] {
                            let (v, line) = with_get(&withs, key).unwrap_or((&[], 0));
                            if let Some(m) = head.search(v) {
                                hit = Some((line, pystr::concat(&[&u("with "), &u(key)]), m.group0().to_vec()));
                                break;
                            }
                        }
                    }
                }
            }
            if hit.is_none() {
                for (line, t) in step_run_lines(recs) {
                    let mut m = p.re("_WF_GH_PR_CHECKOUT_RE").search(&t).map(|m| m.group0().to_vec());
                    if m.is_none() && p.re("_WF_PR_CHECKOUT_CMD_RE").search(&t).is_some() {
                        m = head.search(&t).map(|m| m.group0().to_vec());
                    }
                    if let Some(expr) = m {
                        hit = Some((line, u("a command"), expr));
                        break;
                    }
                }
            }
            if let Some((line, via, expr)) = hit {
                out.push(("pr-checkout", line, Value::obj(vec![("job", s(job)), ("via", Value::Str(via)), ("expr", Value::Str(expr))])));
            }
        }
    }
    // a cache in a release
    if let Some(why) = release_why(p, &table, &steps, &evs) {
        for (job, recs) in &steps {
            if let Some((line, what, explicit)) = cache_of(p, recs) {
                out.push((
                    "cache",
                    line,
                    Value::obj(vec![("job", s(job)), ("what", Value::Str(what)), ("explicit", Value::Bool(explicit)), ("why", s(&why))]),
                ));
            }
        }
    }
    // a job with an OIDC token that installs dependencies
    for job in &jobs {
        let jg = grants(&table, Some(job));
        let (grant, source) = if jg.present { (jg.token, "job") } else { (top.token, "workflow") };
        if grant.is_none() {
            continue;
        }
        let mut hit: Option<(usize, PyStr)> = None;
        'job: for (j, recs) in &steps {
            if j != job {
                continue;
            }
            for (line, t) in step_run_lines(recs) {
                if let Some(found) = install_command(p, &t) {
                    hit = Some((line, found));
                    break 'job;
                }
            }
        }
        if let Some((line, cmd)) = hit {
            out.push(("oidc-install", line, Value::obj(vec![("job", s(job)), ("from", Value::str(source)), ("command", Value::Str(cmd))])));
        }
    }
    // a script fetched and run without being read
    for (job, recs) in &steps {
        for (line, t) in logical_lines(&step_run_lines(recs)) {
            if let Some(found) = pipe_to_shell(p, &t) {
                out.push(("pipe-to-shell", line, Value::obj(vec![("job", s(job)), ("command", Value::Str(found))])));
                break;
            }
        }
    }
    out.sort_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0)));
    out
}

// ---------------------------------------------------------------- the rules

fn d_str(d: &Value, key: &str) -> PyStr {
    d.get(key).and_then(|v| v.as_str()).map(|x| x.to_vec()).unwrap_or_default()
}

fn d_bool(d: &Value, key: &str) -> bool {
    matches!(d.get(key), Some(Value::Bool(true)))
}

fn d_strs(d: &Value, key: &str) -> Vec<PyStr> {
    d.get(key).and_then(|v| v.as_arr()).map(|a| a.iter().filter_map(|x| x.as_str().map(|y| y.to_vec())).collect()).unwrap_or_default()
}

fn fill(p: &Pack, name: &str, args: &[(&str, Arg)]) -> RuleText {
    let mut rule = RuleText::of(p, name);
    rule.msg = findings::format(&rule.msg, args);
    rule
}

/// The rule of one of the workflow reader's findings (core.workflow_issues', ghworkflow.hardening_rule's), or None
/// for a kind this reader does not have.
pub fn rule(p: &Pack, kind: &str, d: &Value) -> Option<RuleText> {
    let st = |k: &str| Arg::S(d_str(d, k));
    Some(match kind {
        "secrets" => match d.get("how").and_then(|v| v.as_str()) {
            Some(how) => fill(p, "_WF_SECRETS_SENT_RULE", &[("where", st("where")), ("how", Arg::S(how.to_vec()))]),
            None => fill(p, "_WF_SECRETS_HELD_RULE", &[("where", st("where"))]),
        },
        "backdoor" => fill(p, "_WF_BACKDOOR_RULE", &[("job", st("job")), ("expr", st("expr")), ("event", st("event")), ("act", st("act"))]),
        "unpinned" => {
            let k = d_str(d, "kind");
            let what = if pystr::eq(&k, "docker") {
                "the image "
            } else if pystr::eq(&k, "workflow") {
                "the reusable workflow "
            } else {
                ""
            };
            let pin = if pystr::eq(&k, "docker") { "a digest" } else { "a full commit SHA" };
            let mut rule = fill(p, "_WF_UNPINNED_RULE", &[("what", Arg::S(u(what))), ("uses", st("uses")), ("pin", Arg::S(u(pin)))]);
            let small = pystr::eq(&k, "action") && d_bool(d, "first") && d_bool(d, "tag");
            rule.sev = u(if small { "MINOR" } else { "MAJOR" });
            rule
        }
        "pr-checkout" => fill(p, "_WF_PR_CHECKOUT_RULE", &[("job", st("job")), ("via", st("via")), ("expr", st("expr"))]),
        "cache" => {
            let mut rule = fill(p, "_WF_CACHE_RULE", &[("job", st("job")), ("what", st("what")), ("why", st("why"))]);
            rule.sev = u(if d_bool(d, "explicit") { "MAJOR" } else { "MINOR" });
            rule
        }
        "perms" => {
            let scopes: Vec<PyStr> =
                d_strs(d, "scopes").into_iter().map(|x| if pystr::eq(&x, "all") { u("write-all") } else { x }).collect();
            let refs: Vec<&[u32]> = scopes.iter().map(|x| x.as_slice()).collect();
            fill(p, "_WF_PERMS_RULE", &[("scopes", Arg::S(pystr::join(&u(", "), &refs)))])
        }
        "perms-missing" => {
            let jobs = d_strs(d, "jobs");
            let quoted: Vec<PyStr> = jobs.iter().take(3).map(|j| pystr::concat(&[&u("\""), j, &u("\"")])).collect();
            let refs: Vec<&[u32]> = quoted.iter().map(|x| x.as_slice()).collect();
            let mut names = pystr::join(&u(", "), &refs);
            if jobs.len() > 3 {
                names.extend(u(&format!(" and {} more", jobs.len() - 3)));
            }
            let who = if jobs.len() == 1 {
                pystr::concat(&[&u("the job "), &names, &u(" has")])
            } else {
                pystr::concat(&[&u("the jobs "), &names, &u(" have")])
            };
            fill(p, "_WF_PERMS_MISSING_RULE", &[("who", Arg::S(who))])
        }
        "pipe-to-shell" => fill(p, "_WF_PIPE_SHELL_RULE", &[("job", st("job")), ("command", st("command"))]),
        "oidc-install" => {
            let source = if pystr::eq(&d_str(d, "from"), "job") { "its own permissions" } else { "the workflow permissions" };
            fill(p, "_WF_OIDC_INSTALL_RULE", &[("job", st("job")), ("source", Arg::S(u(source))), ("command", st("command"))])
        }
        _ => return None,
    })
}
