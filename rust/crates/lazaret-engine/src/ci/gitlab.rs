//! GitLab CI files (scanner/gitlabci.py and its npm twin until BR-7 moved them here; 0.1.9, S-3): the places a
//! pipeline can be turned. An `include:` of a URL, of another project's file at a branch, a tag or no ref, or of a
//! component not at a commit; an image or a service without a digest; a script that fetches a script and runs it
//! unread; a script that hands text anyone can write (a merge request's title, a commit message, a branch name) to
//! `eval`, `sh -c` or the place of a command; a job holding a publishing credential that installs dependencies.
//! Read on the outline of the YAML (outline.rs): anchors, `extends:`, `!reference` and multi-line flow collections
//! are the plain text they are, and a job's scripts are the ones written under it. Offline: a component's own
//! repository and a project's ref are not looked up. The patterns, lists and rule texts are the pack's (`_GL_*`).

use super::outline::{self, Rec};
use super::workflow::{self, Found};
use crate::findings::{self, Arg, RuleText};
use crate::json::Value;
use crate::pack::Pack;
use crate::pystr::{self, u, PyStr};

const fn c(ch: char) -> u32 {
    ch as u32
}

const HEX: &str = "0123456789abcdefABCDEF";

fn s(v: &[u32]) -> Value {
    Value::Str(v.to_vec())
}

fn is_hex(v: &[u32], n: usize) -> bool {
    v.len() == n && v.iter().all(|&ch| HEX.chars().any(|h| h as u32 == ch))
}

fn is_digit(ch: u32) -> bool {
    (c('0')..=c('9')).contains(&ch)
}

/// Is `path` a GitLab CI file: `.gitlab-ci.yml`, a `*.gitlab-ci.yml`, or a .yml/.yaml under a `.gitlab` directory
/// (the usual place of included files)?
pub fn is_gitlab_ci(path: &[u32]) -> bool {
    let p = pystr::replace_char(path, c('\\'), c('/'));
    let parts = pystr::split_char(&p, c('/'));
    let name = pystr::lower(parts[parts.len() - 1]);
    if pystr::ends_with(&name, ".gitlab-ci.yml")
        || pystr::ends_with(&name, ".gitlab-ci.yaml")
        || pystr::eq(&name, ".gitlab-ci.yml")
        || pystr::eq(&name, ".gitlab-ci.yaml")
    {
        return true;
    }
    (pystr::ends_with(&name, ".yml") || pystr::ends_with(&name, ".yaml"))
        && parts[..parts.len() - 1].iter().any(|x| pystr::eq(&pystr::lower(x), ".gitlab"))
}

fn is_url(v: &[u32]) -> bool {
    let low8 = pystr::lower(pystr::upto(v, 8));
    let low7 = pystr::lower(pystr::upto(v, 7));
    pystr::eq(&low8, "https://") || pystr::eq(&low7, "http://")
}

/// Does ref read as a version tag (1.2, v1.2)?
fn tag_like(r: &[u32]) -> bool {
    !r.is_empty() && (is_digit(r[0]) || (r[0] == c('v') && r.len() > 1 && is_digit(r[1])))
}

fn unquote(v: &[u32]) -> PyStr {
    let t = pystr::strip_chars(v, " \t");
    if t.len() >= 2 && (t[0] == c('"') || t[0] == c('\'')) && t[t.len() - 1] == t[0] {
        return t[1..t.len() - 1].to_vec();
    }
    t.to_vec()
}

/// v split at `sep` outside quotes and brackets, at most `maxsplit` times (None: no limit).
fn split_top(v: &[u32], sep: u32, maxsplit: Option<usize>) -> Vec<&[u32]> {
    let mut out: Vec<&[u32]> = Vec::new();
    let (mut depth, mut quote, mut start) = (0usize, 0u32, 0usize);
    for (i, &ch) in v.iter().enumerate() {
        if quote != 0 {
            if ch == quote {
                quote = 0;
            }
        } else if ch == c('"') || ch == c('\'') {
            quote = ch;
        } else if ch == c('[') || ch == c('{') {
            depth += 1;
        } else if ch == c(']') || ch == c('}') {
            depth = depth.saturating_sub(1);
        } else if ch == sep && depth == 0 && maxsplit.map_or(true, |m| out.len() != m) {
            out.push(&v[start..i]);
            start = i + 1;
        }
    }
    out.push(&v[start..]);
    out
}

/// An item of a flow collection: a string, or a map's fields (the first of each key).
#[derive(Clone, Debug)]
pub enum Item {
    Str(PyStr),
    Map(Vec<(PyStr, PyStr)>),
}

impl Item {
    fn field(&self, key: &str) -> Option<&[u32]> {
        match self {
            Item::Map(m) => m.iter().find(|(k, _)| pystr::eq(k, key)).map(|(_, v)| v.as_slice()),
            Item::Str(_) => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Item::Str(x) => s(x),
            Item::Map(m) => Value::Obj(m.iter().map(|(k, v)| (k.clone(), s(v))).collect()),
        }
    }
}

fn flow_item(v: &[u32]) -> Item {
    let t = pystr::strip_chars(v, " \t");
    if t.first() != Some(&c('{')) {
        return Item::Str(unquote(t));
    }
    let body = if t.last() == Some(&c('}')) && t.len() >= 2 { &t[1..t.len() - 1] } else { &t[1..] };
    let mut out: Vec<(PyStr, PyStr)> = Vec::new();
    for pair in split_top(body, c(','), None) {
        let kv = split_top(pair, c(':'), Some(1));
        if kv.len() == 2 {
            let k = unquote(kv[0]);
            if !out.iter().any(|(x, _)| *x == k) {
                out.push((k, unquote(kv[1])));
            }
        }
    }
    Item::Map(out)
}

/// The items of a flow collection written on one line: `[a, {k: v}]` gives "a" and the map's fields; `{k: v}` the
/// fields; a scalar itself.
pub fn flow_items(text: &[u32]) -> Vec<Item> {
    let t = pystr::strip_chars(text, " \t");
    if t.first() == Some(&c('[')) {
        let body = if t.last() == Some(&c(']')) && t.len() >= 2 { &t[1..t.len() - 1] } else { &t[1..] };
        return split_top(body, c(','), None)
            .into_iter()
            .filter(|x| !pystr::strip_chars(x, " \t").is_empty())
            .map(flow_item)
            .collect();
    }
    if t.first() == Some(&c('{')) {
        return vec![flow_item(t)];
    }
    if t.is_empty() {
        Vec::new()
    } else {
        vec![Item::Str(unquote(t))]
    }
}

/// (name, tag, digest) of an image reference: `registry:5000/app:1.2@sha256:…` gives ("registry:5000/app", "1.2",
/// "sha256:…").
pub fn parse_image(value: &[u32]) -> (PyStr, PyStr, PyStr) {
    let v = pystr::strip_chars(value, " \t");
    let (name, digest) = match pystr::find_char(v, c('@'), 0) {
        Some(k) => (&v[..k], &v[k + 1..]),
        None => (v, &v[v.len()..]),
    };
    let cut = name.iter().rposition(|&ch| ch == c(':'));
    let slash = name.iter().rposition(|&ch| ch == c('/'));
    match cut {
        Some(k) if slash.map_or(true, |sl| k > sl) => (name[..k].to_vec(), name[k + 1..].to_vec(), digest.to_vec()),
        _ => (name.to_vec(), Vec::new(), digest.to_vec()),
    }
}

/// (variable, how) for a script line that hands text anyone can write to code: "eval", "a `sh -c` string" or "the
/// place of a command"; or None. A variable inside single quotes, or an argument of an ordinary command, is data.
pub fn mr_text(p: &Pack, text: &[u32]) -> Option<(PyStr, &'static str)> {
    let mr = p.re("_GL_MR_VAR_RE");
    mr.search(text)?;
    if let Some(m) = p.re("_GL_COMMAND_VAR_RE").search(text) {
        return Some((m.group(1).unwrap_or(&[]).to_vec(), "the place of a command"));
    }
    let arg = p.re("_GL_ARG_RE");
    for (name, how, limit) in [("_GL_EVAL_RE", "eval", None), ("_GL_SHELL_C_RE", "a `sh -c` string", Some(1usize))] {
        let pattern = p.re(name);
        let mut pos = 0usize;
        while let Some(m) = pattern.search_at(text, pos as isize, text.len() as isize) {
            pos = m.end();
            let mut taken = 0usize;
            while limit.map_or(true, |l| taken < l) {
                let a = match arg.match_at(text, pos as isize, text.len() as isize) {
                    Some(a) => a,
                    None => break,
                };
                pos = a.end();
                taken += 1;
                let word = a.group(1).unwrap_or(&[]);
                if word.first() != Some(&c('\'')) {
                    if let Some(f) = mr.search(word) {
                        return Some((f.group0().to_vec(), how));
                    }
                }
            }
        }
    }
    None
}

/// [(line, text)] of one record's own text: its value and its block scalar; a flow list's strings.
fn rec_lines(r: &Rec) -> Vec<(usize, PyStr)> {
    if r.value.first() == Some(&c('[')) {
        let mut out: Vec<(usize, PyStr)> =
            flow_items(&r.value).into_iter().filter_map(|x| if let Item::Str(t) = x { Some((r.line, t)) } else { None }).collect();
        out.extend(r.block.iter().cloned());
        return out;
    }
    r.lines()
}

/// rec_lines for a sequence item: a script line with `: ` in it reads as a key, so the line is put back together.
fn item_lines(r: &Rec) -> Vec<(usize, PyStr)> {
    let key = match &r.key {
        None => return rec_lines(r),
        Some(k) => k,
    };
    let head = if r.value.is_empty() {
        pystr::concat(&[key, &u(":")])
    } else {
        pystr::concat(&[key, &u(": "), &r.value])
    };
    let mut out = vec![(r.line, head)];
    out.extend(r.block.iter().cloned());
    out
}

#[derive(Default)]
struct Job {
    /// the commands of before_script, script, after_script
    scripts: [Vec<(usize, PyStr)>; 3],
    /// the lines of a list under a hidden key (`.setup: &setup`), which jobs pull in with an alias
    loose: Vec<(usize, PyStr)>,
    /// (line, image, "image" or "service")
    images: Vec<(usize, PyStr, &'static str)>,
    id_tokens: Option<usize>,
    secrets: Option<usize>,
}

fn script_index(p: &Pack, name: &[u32]) -> Option<usize> {
    p.strs("_GL_SCRIPT_KEYS").iter().position(|k| k.as_slice() == name)
}

/// owner -> job, in the order owners first appear: every job, `default` (the settings of the whole file, and the
/// top-level keys that are the same).
fn jobs(p: &Pack, records: &[Rec]) -> Vec<(PyStr, Job)> {
    let globals = p.strs("_GL_GLOBAL_KEYS");
    let not_jobs = p.strs("_GL_NOT_JOBS");
    let mut jobs: Vec<(PyStr, Job)> = Vec::new();
    for r in records {
        let path = &r.path;
        let (owner, rest): (PyStr, &[PyStr]) = if path.is_empty() {
            match &r.key {
                Some(k) if globals.contains(k) => (u("default"), &path[..]),
                _ => continue,
            }
        } else if globals.contains(&path[0]) {
            (u("default"), &path[..])
        } else if not_jobs.contains(&path[0]) {
            continue;
        } else {
            (path[0].clone(), &path[1..])
        };
        let k = match jobs.iter().position(|(o, _)| *o == owner) {
            Some(k) => k,
            None => {
                jobs.push((owner.clone(), Job::default()));
                jobs.len() - 1
            }
        };
        let job = &mut jobs[k].1;
        if rest.is_empty() {
            let value = &r.value;
            let key = r.key.clone().unwrap_or_default();
            if let Some(si) = r.key.as_ref().and_then(|k| script_index(p, k)) {
                job.scripts[si].extend(rec_lines(r));
            } else if pystr::eq(&key, "image") && !value.is_empty() {
                let items = if value.first() == Some(&c('{')) { flow_items(value) } else { vec![Item::Str(value.clone())] };
                for item in items {
                    let name = match &item {
                        Item::Str(x) => x.clone(),
                        Item::Map(_) => item.field("name").unwrap_or(&[]).to_vec(),
                    };
                    if !name.is_empty() {
                        job.images.push((r.line, name, "image"));
                    }
                }
            } else if pystr::eq(&key, "services") && value.first() == Some(&c('[')) {
                for item in flow_items(value) {
                    let name = match &item {
                        Item::Str(x) => x.clone(),
                        Item::Map(_) => item.field("name").unwrap_or(&[]).to_vec(),
                    };
                    if !name.is_empty() {
                        job.images.push((r.line, name, "service"));
                    }
                }
            } else if pystr::eq(&key, "id_tokens") && r.key.is_some() && job.id_tokens.is_none() {
                job.id_tokens = Some(r.line);
            } else if pystr::eq(&key, "secrets") && r.key.is_some() && job.secrets.is_none() {
                job.secrets = Some(r.line);
            }
        } else if let Some(si) = script_index(p, &rest[0]).filter(|_| rest.len() >= 2 && rest[1..].iter().all(|x| pystr::eq(x, "-"))) {
            job.scripts[si].extend(item_lines(r));
        } else if rest.len() == 1 && pystr::eq(&rest[0], "image") && r.key_is("name") && !r.value.is_empty() {
            job.images.push((r.line, r.value.clone(), "image"));
        } else if rest.len() == 2
            && pystr::eq(&rest[0], "services")
            && pystr::eq(&rest[1], "-")
            && (r.key.is_none() || r.key_is("name"))
            && !r.value.is_empty()
        {
            job.images.push((r.line, r.value.clone(), "service"));
        } else if owner.first() == Some(&c('.')) && r.key.is_none() && !rest.is_empty() && rest.iter().all(|x| pystr::eq(x, "-")) {
            job.loose.extend(rec_lines(r));
        }
    }
    jobs
}

/// [(line, item)] for what `include:` names: a string (`- 'https://…'`) or the item's fields (`remote`, `project`,
/// `ref`, `component` …).
fn includes(records: &[Rec]) -> Vec<(usize, Item)> {
    let mut items: Vec<(usize, Item)> = Vec::new();
    // the index of the item being filled: a sequence item's map, the single map of `include:` + keys
    let mut cur: Option<usize> = None;
    let mut single: Option<usize> = None;
    for r in records {
        let path = &r.path;
        if path.is_empty() {
            if r.key_is("include") {
                cur = None;
                single = None;
                if r.value.first().is_some_and(|&ch| ch == c('[') || ch == c('{')) {
                    items.extend(flow_items(&r.value).into_iter().map(|it| (r.line, it)));
                } else if !r.value.is_empty() {
                    items.push((r.line, Item::Str(unquote(&r.value))));
                }
            }
            continue;
        }
        if !pystr::eq(&path[0], "include") {
            continue;
        }
        if r.path_is(&["include"]) && r.key.is_some() {
            let k = match single {
                Some(k) => k,
                None => {
                    items.push((r.line, Item::Map(Vec::new())));
                    single = Some(items.len() - 1);
                    items.len() - 1
                }
            };
            if let (Item::Map(m), Some(key)) = (&mut items[k].1, &r.key) {
                if !m.iter().any(|(x, _)| x == key) {
                    m.push((key.clone(), r.value.clone()));
                }
            }
        } else if r.path_is(&["include", "-"]) {
            if r.item {
                match &r.key {
                    None => {
                        items.push((r.line, Item::Str(r.value.clone())));
                        cur = None;
                    }
                    Some(key) => {
                        items.push((r.line, Item::Map(vec![(key.clone(), r.value.clone())])));
                        cur = Some(items.len() - 1);
                    }
                }
            } else if let (Some(k), Some(key)) = (cur, &r.key) {
                if let Item::Map(m) = &mut items[k].1 {
                    if !m.iter().any(|(x, _)| x == key) {
                        m.push((key.clone(), r.value.clone()));
                    }
                }
            }
        }
    }
    items
}

/// The commands a job runs, in order: its before_script (the file's default one when it has none), its script, its
/// after_script (the same).
fn effective(jobs: &[(PyStr, Job)], k: usize) -> Vec<(usize, PyStr)> {
    let job = &jobs[k].1;
    let base = jobs.iter().find(|(o, _)| pystr::eq(o, "default")).map(|(_, j)| j);
    let pick = |i: usize| -> Vec<(usize, PyStr)> {
        let own = &job.scripts[i];
        match base {
            Some(b) if own.is_empty() => b.scripts[i].clone(),
            _ => own.clone(),
        }
    };
    let mut out = pick(0);
    out.extend(job.scripts[1].iter().cloned());
    out.extend(pick(2));
    out
}

/// The checks of a GitLab CI file's text, by line: 'include-remote' {url, http}; 'include-project' {project, ref,
/// tag}; 'include-component' {component, ref, exact}; 'image' {job, image, where, tag, official}; 'pipe-to-shell'
/// {job, command}; 'mr-text' {job, variable, how}; 'token-install' {job, grant, command}.
pub fn hardening(p: &Pack, text: &[u32]) -> Vec<Found> {
    let records = outline::outline(text, true, true);
    let jobs = jobs(p, &records);
    let mut out: Vec<Found> = Vec::new();
    for (line, item) in includes(&records) {
        let fields: Vec<(PyStr, PyStr)> = match &item {
            Item::Map(m) => m.clone(),
            Item::Str(x) if is_url(x) => vec![(u("remote"), x.clone())],
            Item::Str(_) => Vec::new(),
        };
        let get = |k: &str| fields.iter().find(|(x, _)| pystr::eq(x, k)).map(|(_, v)| v.as_slice());
        let remote = get("remote").unwrap_or(&[]);
        if !remote.is_empty() {
            let http = pystr::eq(&pystr::lower(pystr::upto(remote, 7)), "http://");
            out.push(("include-remote", line, Value::obj(vec![("url", s(remote)), ("http", Value::Bool(http))])));
        } else if let Some(project) = get("project") {
            let r = get("ref").unwrap_or(&[]);
            if !is_hex(r, 40) && !pystr::eq(r, "$CI_COMMIT_SHA") && !pystr::eq(r, "${CI_COMMIT_SHA}") {
                out.push((
                    "include-project",
                    line,
                    Value::obj(vec![("project", s(project)), ("ref", s(r)), ("tag", Value::Bool(tag_like(r)))]),
                ));
            }
        } else if let Some(component) = get("component") {
            let (name, r) = match pystr::find_char(component, c('@'), 0) {
                Some(k) => (&component[..k], &component[k + 1..]),
                None => (component, &component[component.len()..]),
            };
            if !is_hex(r, 40) {
                let exact = p.re("_GL_EXACT_RE").search(r).is_some();
                out.push((
                    "include-component",
                    line,
                    Value::obj(vec![("component", s(name)), ("ref", s(r)), ("exact", Value::Bool(exact))]),
                ));
            }
        }
    }
    for (owner, job) in &jobs {
        for (line, value, where_) in &job.images {
            if pystr::starts_with(value, "$CI_REGISTRY_IMAGE") || pystr::starts_with(value, "${CI_REGISTRY_IMAGE") {
                continue; // an image the project built
            }
            let (name, tag, digest) = parse_image(value);
            if pystr::starts_with(&digest, "sha256:") && is_hex(&digest[7..], 64) {
                continue;
            }
            out.push((
                "image",
                *line,
                Value::obj(vec![
                    ("job", s(owner)),
                    ("image", s(value)),
                    ("where", Value::str(where_)),
                    ("tag", Value::Str(tag)),
                    ("official", Value::Bool(!name.contains(&c('/')))),
                ]),
            ));
        }
    }
    for (owner, job) in &jobs {
        let sections: [&Vec<(usize, PyStr)>; 4] = [&job.scripts[0], &job.scripts[1], &job.scripts[2], &job.loose];
        for kind in ["pipe-to-shell", "mr-text"] {
            let mut hit: Option<(usize, Value)> = None;
            'sections: for section in sections {
                for (line, t) in workflow::logical_lines(section) {
                    let found = if kind == "pipe-to-shell" {
                        workflow::pipe_to_shell(p, &t).map(|cmd| Value::obj(vec![("job", s(owner)), ("command", Value::Str(cmd))]))
                    } else {
                        mr_text(p, &t).map(|(var, how)| {
                            Value::obj(vec![("job", s(owner)), ("variable", Value::Str(var)), ("how", Value::str(how))])
                        })
                    };
                    if let Some(d) = found {
                        hit = Some((line, d));
                        break 'sections;
                    }
                }
            }
            if let Some((line, d)) = hit {
                out.push((kind, line, d));
            }
        }
    }
    let base = jobs.iter().find(|(o, _)| pystr::eq(o, "default")).map(|(_, j)| j);
    let token = p.re("_GL_TOKEN_VAR_RE");
    for (k, (owner, job)) in jobs.iter().enumerate() {
        if pystr::eq(owner, "default") {
            continue;
        }
        let lines = effective(&jobs, k);
        let grant: Option<PyStr> = if job.id_tokens.is_some() {
            Some(u("its id_tokens"))
        } else if base.is_some_and(|b| b.id_tokens.is_some()) {
            Some(u("the default id_tokens"))
        } else if job.secrets.is_some() {
            Some(u("its secrets"))
        } else {
            lines.iter().find_map(|(_, t)| token.search(t).map(|m| m.group0().to_vec()))
        };
        let grant = match grant {
            Some(g) => g,
            None => continue,
        };
        for (line, t) in &lines {
            if let Some(cmd) = workflow::install_command(p, t) {
                out.push((
                    "token-install",
                    *line,
                    Value::obj(vec![("job", s(owner)), ("grant", Value::Str(grant.clone())), ("command", Value::Str(cmd))]),
                ));
                break;
            }
        }
    }
    out.sort_by(|a, b| (a.1, a.0).cmp(&(b.1, b.0)));
    out
}

fn d_str(d: &Value, key: &str) -> PyStr {
    d.get(key).and_then(|v| v.as_str()).map(|x| x.to_vec()).unwrap_or_default()
}

fn d_bool(d: &Value, key: &str) -> bool {
    matches!(d.get(key), Some(Value::Bool(true)))
}

fn fill(p: &Pack, name: &str, args: &[(&str, Arg)]) -> RuleText {
    let mut rule = RuleText::of(p, name);
    rule.msg = findings::format(&rule.msg, args);
    rule
}

/// The rule of one of hardening()'s findings (gitlabci.hardening_rule's), or None for a kind it does not have.
pub fn rule(p: &Pack, kind: &str, d: &Value) -> Option<RuleText> {
    let st = |k: &str| Arg::S(d_str(d, k));
    Some(match kind {
        "include-remote" => {
            let http = d_bool(d, "http");
            let how = if http { ", over plain HTTP, so that anyone on the path can change it, and" } else { ", and" };
            let mut rule = fill(p, "_GL_INCLUDE_REMOTE_RULE", &[("url", st("url")), ("how", Arg::S(u(how)))]);
            rule.sev = u(if http { "CRITICAL" } else { "MAJOR" });
            rule
        }
        "include-project" => {
            let r = d_str(d, "ref");
            let at = if r.is_empty() { u("no ref (its default branch)") } else { pystr::concat(&[&u("the ref \""), &r, &u("\"")]) };
            let mut rule = fill(p, "_GL_INCLUDE_PROJECT_RULE", &[("project", st("project")), ("at", Arg::S(at))]);
            rule.sev = u(if d_bool(d, "tag") { "MINOR" } else { "MAJOR" });
            rule
        }
        "include-component" => {
            let r = d_str(d, "ref");
            let at = if r.is_empty() || pystr::eq(&r, "~latest") {
                u("its latest version")
            } else {
                pystr::concat(&[&u("the version \""), &r, &u("\"")])
            };
            let mut rule = fill(p, "_GL_INCLUDE_COMPONENT_RULE", &[("component", st("component")), ("at", Arg::S(at))]);
            rule.sev = u(if d_bool(d, "exact") { "MINOR" } else { "MAJOR" });
            rule
        }
        "image" => {
            let tag = d_str(d, "tag");
            let small = d_bool(d, "official") && !tag.is_empty() && !pystr::eq(&tag, "latest");
            let job = d_str(d, "job");
            let who = if pystr::eq(&job, "default") {
                u("The file's default settings use")
            } else {
                let act = if pystr::eq(&d_str(d, "where"), "service") { "starts the service" } else { "runs" };
                pystr::concat(&[&u("The job \""), &job, &u("\" "), &u(act)])
            };
            let mut rule = fill(p, "_GL_IMAGE_RULE", &[("who", Arg::S(who)), ("image", st("image"))]);
            rule.sev = u(if small { "MINOR" } else { "MAJOR" });
            rule
        }
        "pipe-to-shell" => fill(p, "_GL_PIPE_SHELL_RULE", &[("job", st("job")), ("command", st("command"))]),
        "mr-text" => fill(p, "_GL_MR_TEXT_RULE", &[("job", st("job")), ("variable", st("variable")), ("how", st("how"))]),
        "token-install" => fill(p, "_GL_TOKEN_INSTALL_RULE", &[("job", st("job")), ("grant", st("grant")), ("command", st("command"))]),
        _ => return None,
    })
}
