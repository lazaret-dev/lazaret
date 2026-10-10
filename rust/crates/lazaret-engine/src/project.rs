//! Project mode after the rules (0.1.9, Q-1): what core's `_project_passes` runs once `scan_rules` has read a file
//! of the user's own project, then the suppression markers and the cap.
//!
//! In core's order, each adding to the file's findings: the SQL statements without WHERE (a `.sql` file:
//! `scan_sql_nowhere`), the intra-file taint (Python and JavaScript: `taint.rs`), the SQL built from strings into
//! `execute()` (Python: `sql_sink_analyzer`), the function metrics (Q-FN-LONG, Q-FN-CX: `extract_functions`). Then
//! a finding a reviewer's marker suppresses (`# nosec`, `// lazaret-ignore: T-CMD`, … in a real comment on its line,
//! or on a comment line of its own just above) is dropped, never a supply-chain or cross-file one (SC-, X-), and the
//! rest are deduplicated and capped per rule (`findings::cap`). The same findings, in the same order, as core's
//! `scan_file(…, dep=False)`; the npm package and the Python package both ask the engine for them.
//!
//! Core bounded a file's passes by 30 seconds of wall clock, so a slow machine could cut a file a fast one read
//! whole; here they spend the call's work budget like everything else the engine does, and a file that spends it
//! has no answer (the caller makes it SC-TRUNCATED, as in dependency mode).

use crate::filectx::{FileCtx, Lang};
use crate::findings::{self, Arg, Finding, RuleText};
use crate::pack::Pack;
use crate::pystr::{self, PyStr};
use crate::taint;

/// Project mode's passes after the rules, in core's order (`_project_passes`), adding to `found`.
pub fn passes(ctx: &FileCtx, found: &mut Vec<Finding>, model: &taint::Model) {
    let p = ctx.p;
    if ctx.lang == Lang::Sql {
        sql_nowhere(p, ctx, found);
    }
    taint::scan(ctx, model, found);
    if ctx.lang == Lang::Py {
        sql_sinks(p, ctx, found);
    }
    let len_limit = p.usize("FN_LEN_LIMIT");
    let cx_limit = p.usize("FN_CX_LIMIT");
    for f in functions(p, ctx) {
        if f.len > len_limit {
            let mut rule = RuleText::of(p, "_FN_LONG_RULE");
            rule.msg = findings::format(&rule.msg, &[("name", Arg::S(f.name.clone())), ("len", Arg::I(f.len as i64)),
                                                     ("limit", Arg::I(len_limit as i64))]);
            found.push(Finding::new(rule, f.line, None));
        }
        if f.cx > cx_limit {
            let mut rule = RuleText::of(p, "_FN_CX_RULE");
            rule.msg = findings::format(&rule.msg, &[("name", Arg::S(f.name.clone())), ("cx", Arg::I(f.cx as i64)),
                                                     ("limit", Arg::I(cx_limit as i64))]);
            found.push(Finding::new(rule, f.line, None));
        }
    }
}

// ---------------------------------------------------------------- function metrics

/// One function of a file (core.extract_functions): its name, its 1-based line, its length in lines and its
/// cyclomatic complexity (one plus its branches).
pub struct Function {
    pub name: PyStr,
    pub line: usize,
    pub len: usize,
    pub cx: usize,
}

/// core.extract_functions: the functions of a Python or JavaScript file (none in another language).
pub fn functions(p: &Pack, ctx: &FileCtx) -> Vec<Function> {
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.line(i)).collect();
    match ctx.lang {
        Lang::Py => py_functions(p, &lines),
        Lang::Js => js_functions(p, ctx, &lines),
        _ => Vec::new(),
    }
}

/// The running count of a pattern's matches over the lines: `out[k]` is the count in lines before k.
fn prefix_counts(rx: &crate::pyre::Regex, lines: &[&[u32]]) -> Vec<usize> {
    let mut out = Vec::with_capacity(lines.len() + 1);
    out.push(0);
    for l in lines {
        let n = rx.finditer(l).count();
        out.push(out.last().copied().unwrap_or(0) + n);
    }
    out
}

/// A Python def ends at the first later line that is not blank, not a comment and indented no deeper than it: one
/// pass with a stack of the open defs (core: a forward scan per def was quadratic).
fn py_functions(p: &Pack, lines: &[&[u32]]) -> Vec<Function> {
    let cx_re = p.re("_FN_PY_CX_RE");
    let def_re = p.re("_FN_PY_DEF_RE");
    let cx = prefix_counts(cx_re, lines);
    let mut found: Vec<(usize, PyStr)> = Vec::new();
    let mut spans: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
    let mut stack: Vec<(usize, usize)> = Vec::new(); // (indent, line), indents increasing
    for (k, l) in lines.iter().enumerate() {
        let m = def_re.match_(l);
        let t = pystr::strip(l);
        if !t.is_empty() && t[0] != '#' as u32 {
            let ind = match &m {
                Some(m) => m.group(1).map_or(0, |g| g.len()),
                None => l.len() - pystr::lstrip(l).len(),
            };
            while let Some(&(top, line)) = stack.last() {
                if top < ind {
                    break;
                }
                stack.pop();
                spans.insert(line, k);
            }
        }
        if let Some(m) = m {
            found.push((k, m.group(2).unwrap_or(&[]).to_vec()));
            stack.push((m.group(1).map_or(0, |g| g.len()), k));
        }
    }
    for (_, k) in stack {
        spans.insert(k, lines.len());
    }
    found
        .into_iter()
        .map(|(i, name)| {
            let end = spans[&i];
            Function { name, line: i + 1, len: end - i, cx: 1 + cx[end] - cx[i] }
        })
        .collect()
}

/// A JavaScript function: the first header of each line claims the first `{` at or after its line's start (two
/// headers on nested lines share one, as their scans in core's first form both counted it), and its body runs to
/// the `}` that balances it, within the old 800-line window; one walk of the braces with a stack (core's G4 fix).
fn js_functions(p: &Pack, ctx: &FileCtx, lines: &[&[u32]]) -> Vec<Function> {
    let cx_re = p.re("_FN_JS_CX_RE");
    let fn_re = p.re("_FN_JS_HEADER_RE");
    let scan_limit = p.usize("FN_HEADER_SCAN_LIMIT");
    let window = p.usize("_FN_JS_WINDOW_LINES");
    let content = &ctx.content;
    let nlines = lines.len();
    // line -> its start in the content, and a sentinel past the end
    let mut starts: Vec<usize> = ctx.starts.clone();
    starts.push(content.len() + 1);
    let mut headers: Vec<(usize, PyStr)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(m) = fn_re.search_at(line, 0, scan_limit as isize) {
            let name = m.group(1).or_else(|| m.group(2)).or_else(|| m.group(3)).map(|g| g.to_vec())
                .unwrap_or_else(|| pystr::u("(anonymous)"));
            headers.push((i, name));
        }
    }
    let cx = prefix_counts(cx_re, lines);
    let opens: Vec<usize> = content.iter().enumerate().filter(|(_, &c)| c == '{' as u32).map(|(k, _)| k).collect();
    let mut matched: Vec<Option<(usize, usize)>> = vec![None; headers.len()];
    let mut stack: Vec<(usize, Vec<usize>)> = Vec::new();
    let mut waiting: Vec<usize> = Vec::new();
    let mut hi = 0;
    for (bpos, &c) in content.iter().enumerate() {
        if c != '{' as u32 && c != '}' as u32 {
            continue;
        }
        while hi < headers.len() && starts[headers[hi].0] <= bpos {
            waiting.push(hi); // the header's line has begun: it claims the next '{' it sees
            hi += 1;
        }
        if c == '{' as u32 {
            stack.push((bpos, std::mem::take(&mut waiting)));
        } else if let Some((open_pos, owners)) = stack.pop() {
            for h in owners {
                matched[h] = Some((open_pos, bpos));
            }
        }
    }
    let mut out = Vec::new();
    for (h, (i, name)) in headers.into_iter().enumerate() {
        let window_end_off = starts[nlines.min(i + window)];
        let k = opens.partition_point(|&o| o < starts[i]);
        if k == opens.len() || opens[k] >= window_end_off {
            continue; // no '{' in the window: the old scan never started
        }
        let end = match matched[h] {
            Some((_, close)) if close < window_end_off => starts.partition_point(|&s| s <= close) - 1,
            // opened but not closed within the window: the old scan ran to the window's end
            _ => nlines.min(i + window) - 1,
        };
        out.push(Function { name, line: i + 1, len: end - i + 1, cx: 1 + cx[end + 1] - cx[i] });
    }
    out
}

// ---------------------------------------------------------------- SQL

/// core.scan_sql_nowhere: SQL-DELETE-NOWHERE and SQL-UPDATE-NOWHERE in one linear pass. A match starts at a DELETE
/// or UPDATE head and runs to the next ';', unless a WHERE comes first (then the heads after it are still tried);
/// matches do not overlap (every head before a reported statement's ';' is spent by it); a head with no ';' after it
/// never matched.
fn sql_nowhere(p: &Pack, ctx: &FileCtx, found: &mut Vec<Finding>) {
    let content = &ctx.content;
    let mut offsets: Option<(Vec<usize>, Vec<usize>, Vec<usize>)> = None; // ';', WHERE and '\n', made once
    for (rule, rx) in nowhere_rules(p) {
        let mut skip_to: isize = -1;
        for m in rx.finditer(content) {
            if (m.start() as isize) < skip_to {
                continue;
            }
            let (semis, wheres, nl) = offsets.get_or_insert_with(|| {
                let at = |c: char| content.iter().enumerate().filter(|(_, &x)| x == c as u32).map(|(k, _)| k).collect();
                (at(';'), p.re("_SQL_WHERE_RE").finditer(content).map(|w| w.start()).collect(), at('\n'))
            });
            let k = semis.partition_point(|&x| x < m.end());
            if k == semis.len() {
                continue; // no ';' ahead: the old pattern could never match
            }
            let semi = semis[k];
            let w = wheres.partition_point(|&x| x < m.end());
            if w < wheres.len() && wheres[w] < semi {
                skip_to = m.end() as isize; // a WHERE before the ';': the old match aborted there
                continue;
            }
            let line = nl.partition_point(|&x| x < m.start()) + 1;
            found.push(Finding::new(rule.clone(), line, None));
            skip_to = semi as isize; // non-overlapping: the heads before the ';' are spent
        }
    }
}

/// The *-NOWHERE rules (core._SQL_NOWHERE_RULES, in its order): their texts and statement-head patterns.
fn nowhere_rules(p: &Pack) -> &[(RuleText, crate::pyre::Regex)] {
    p.derived("_SQL_NOWHERE_RULES", |v| {
        v.get("map")
            .and_then(|m| m.as_obj())
            .unwrap_or(&[])
            .iter()
            .map(|(_, r)| {
                let re = r.get("map").and_then(|m| m.get("re")).expect("a *-NOWHERE rule's pattern");
                let src = re.get("re").and_then(|t| t.as_str()).unwrap_or(&[]);
                let flags = re.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
                let rx = crate::pyre::Regex::new(src, crate::pyre::flags_from_letters(&flags)).expect("a *-NOWHERE pattern");
                (RuleText::from_value(r), rx)
            })
            .collect::<Vec<_>>()
    })
}

/// How an execute() argument (or an assigned expression) builds a string (core._sql_build_method).
#[derive(Clone, Copy, PartialEq)]
enum Build {
    Format,
    Percent,
    Concat,
    Static,
}

fn sql_build_method(p: &Pack, arg: &[u32]) -> Option<Build> {
    let lead = pystr::lstrip(arg);
    if p.re("_SQL_FORMAT_RE").is_match(arg) || pystr::starts_with(lead, "f\"") || pystr::starts_with(lead, "f'") {
        return Some(Build::Format);
    }
    if p.re("_SQL_PERCENT_RE").is_match(arg) {
        return Some(Build::Percent);
    }
    if p.res("_SQL_CONCAT_RES").iter().any(|r| r.is_match(arg)) {
        return Some(Build::Concat);
    }
    None
}

/// core._sql_template_map: name -> how its value is built, from the file's simple assignments.
fn sql_template_map(p: &Pack, lines: &[&[u32]]) -> std::collections::HashMap<PyStr, Build> {
    let assign = p.re("SQL_ASSIGN_RE");
    let lit_re = p.re("SQL_LIT_RE");
    let mut tmap = std::collections::HashMap::new();
    for ln in lines {
        let Some(mm) = assign.match_(ln) else { continue };
        let var = mm.group(1).unwrap_or(&[]).to_vec();
        let op = mm.group(2).unwrap_or(&[]);
        let rhs = pystr::rstrip(mm.group(3).unwrap_or(&[]));
        if pystr::eq(op, "+=") {
            tmap.entry(var).or_insert(Build::Concat);
            continue;
        }
        if let Some(b) = sql_build_method(p, rhs) {
            tmap.insert(var, b);
            continue;
        }
        if let Some(lit) = lit_re.match_(pystr::strip(rhs)) {
            let t = lit.group(1).unwrap_or(&[]);
            let b = if t.contains(&('%' as u32)) {
                Build::Percent
            } else if t.contains(&('{' as u32)) {
                Build::Format
            } else {
                Build::Static
            };
            tmap.insert(var, b);
        }
    }
    tmap
}

/// core._split_top_level: an argument string cut at its top-level commas (brackets and quotes respected).
fn split_top_level(s: &[u32]) -> Vec<&[u32]> {
    let mut parts = Vec::new();
    let (mut depth, mut start) = (0i64, 0usize);
    let mut quote: Option<u32> = None;
    for (i, &ch) in s.iter().enumerate() {
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        match char::from_u32(ch).unwrap_or('\0') {
            '"' | '\'' => quote = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// core._paren_close_map: {index of '(' : index of its ')'} for one line, quotes tracked from the line's start.
fn paren_close_map(p: &Pack, line: &[u32]) -> std::collections::HashMap<usize, usize> {
    let mut close = std::collections::HashMap::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut quote: Option<u32> = None;
    for m in p.re("_PAREN_TOKEN_RE").finditer(line) {
        let (ch, j) = (line[m.start()], m.start());
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
        } else if ch == '"' as u32 || ch == '\'' as u32 {
            quote = Some(ch);
        } else if ch == '(' as u32 {
            stack.push(j);
        } else if let Some(o) = stack.pop() {
            close.insert(o, j);
        }
    }
    close
}

/// core.sql_sink_analyzer: S-SQL-PY for an execute() whose SQL is built from strings (by %, .format() or an
/// f-string, or concatenation, in the call or in an earlier assignment of the name it is given); a parameterized
/// call is not one, and a line the line rule flagged already is not read again.
fn sql_sinks(p: &Pack, ctx: &FileCtx, found: &mut Vec<Finding>) {
    let lines: Vec<&[u32]> = (0..ctx.len()).map(|i| ctx.mline(i)).collect();
    let tmap = sql_template_map(p, &lines);
    let flagged: std::collections::HashSet<usize> =
        found.iter().filter(|f| pystr::eq(&f.rule.id, "S-SQL-PY")).map(|f| f.line).collect();
    let call_re = p.re("SQL_CALL_RE");
    let ident_re = p.re("SQL_IDENT_RE");
    let per_line = p.usize("SQL_CALLS_PER_LINE");
    let arg_max = p.usize("SQL_ARG_MAX");
    for (i, line) in lines.iter().enumerate() {
        if flagged.contains(&(i + 1)) || !pystr::contains(line, ".execute") {
            continue;
        }
        let mut close: Option<std::collections::HashMap<usize, usize>> = None;
        for (n_call, m) in call_re.finditer(line).enumerate() {
            if n_call >= per_line {
                break;
            }
            let close = close.get_or_insert_with(|| paren_close_map(p, line));
            let Some(&j) = close.get(&(m.end() - 1)) else { continue };
            let arg = &line[m.end()..j];
            let arg = &arg[..arg.len().min(arg_max)];
            let parts = split_top_level(arg);
            let first = parts.first().map(|x| pystr::strip(x)).unwrap_or(&[]);
            let second = parts.get(1).map(|x| pystr::strip(x)).unwrap_or(&[]);
            if first.is_empty() {
                continue;
            }
            // a parameterized call: a tuple, list or dict of parameters after the first argument
            if parts.len() >= 2 && !second.is_empty() && matches!(char::from_u32(second[0]), Some('(' | '[' | '{')) {
                continue;
            }
            let mut build = sql_build_method(p, first);
            if build.is_none() && ident_re.fullmatch(first).is_some() {
                build = tmap.get(first).copied();
                if matches!(build, None | Some(Build::Static)) {
                    continue;
                }
            }
            let Some(build) = build else { continue };
            let how = match build {
                Build::Percent => p.map_text("_SQL_HOW", "percent"),
                Build::Format => p.map_text("_SQL_HOW", "format"),
                Build::Concat => p.map_text("_SQL_HOW", "concat"),
                Build::Static => p.text("_SQL_HOW_OTHER"),
            };
            let mut rule = RuleText::of(p, "_SQL_SINK_RULE");
            rule.msg = findings::format(&rule.msg, &[("how", Arg::S(how))]);
            found.push(Finding::new(rule, i + 1, None));
        }
    }
}

// ---------------------------------------------------------------- suppression markers

/// What a suppression marker names: every rule (a blanket marker), or these rule IDs (upper case).
enum Marker {
    Every,
    Rules(Vec<PyStr>),
}

/// core._find_marker: the first marker on `line` (ASCII) whose introducer is inside one of the line's comment
/// spans, and what it names.
fn marker(p: &Pack, line: &[u32], spans: &[(usize, usize)]) -> Option<Marker> {
    if spans.is_empty() {
        return None;
    }
    let mut k = 0;
    for m in p.re("SUPPRESS_RE").finditer(line) {
        let at = m.start();
        while k < spans.len() && spans[k].1 <= at {
            k += 1;
        }
        if k == spans.len() {
            return None;
        }
        if spans[k].0 <= at && pystr::is_ascii(m.group0()) {
            return Some(match m.group(1) {
                None => Marker::Every,
                Some(ids) if ids.is_empty() => Marker::Every,
                Some(ids) => Marker::Rules(
                    pystr::split_char(ids, ',' as u32).into_iter().map(|s| ascii_upper(pystr::strip(s))).collect(),
                ),
            });
        }
    }
    None
}

fn ascii_upper(s: &[u32]) -> PyStr {
    s.iter().map(|&c| if ('a' as u32..='z' as u32).contains(&c) { c - 32 } else { c }).collect()
}

/// core._FileCtx.suppressed (project mode): a marker on the finding's line, or on a comment line of its own just
/// above, that names its rule or every rule; never a rule of UNSUPPRESSIBLE_PREFIXES.
fn suppressed(p: &Pack, ctx: &FileCtx, f: &Finding, markers: &mut Vec<Option<Option<Marker>>>) -> bool {
    if p.strs("UNSUPPRESSIBLE_PREFIXES").iter().any(|pre| f.rule.id.starts_with(pre)) {
        return false;
    }
    let rule = ascii_upper(&f.rule.id);
    let ln = f.line as isize - 1;
    for k in [ln, ln - 1] {
        if k < 0 || k as usize >= ctx.len() {
            continue;
        }
        let k = k as usize;
        if k as isize != ln && !ctx.cmask[k] {
            continue; // the line above counts only when it is a comment line of its own
        }
        let m = markers[k].get_or_insert_with(|| marker(p, ctx.line(k), &ctx.cspans[k]));
        match m {
            None => continue,
            Some(Marker::Every) => return true,
            Some(Marker::Rules(ids)) => {
                if ids.contains(&rule) {
                    return true;
                }
            }
        }
    }
    false
}

/// The findings no marker suppresses, in their order.
pub fn unsuppressed(ctx: &FileCtx, found: Vec<Finding>) -> Vec<Finding> {
    let mut markers: Vec<Option<Option<Marker>>> = (0..ctx.len()).map(|_| None).collect();
    found.into_iter().filter(|f| !suppressed(ctx.p, ctx, f, &mut markers)).collect()
}

#[cfg(test)]
#[path = "project_tests.rs"]
mod tests;
