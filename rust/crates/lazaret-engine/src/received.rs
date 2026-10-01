//! Code that runs what it receives over the network: a port of
//! lazaret.scanner.core's received-code detector (`_received_code_kind` and
//! the `_Dl*` readers, section "Code that runs what it receives over the
//! network") and of "Download to a file, then run the file" (
//! `_downloads_and_runs`, `_decodes_and_runs`), function for function. The
//! patterns, name sets and limits are the rule pack's (received_spec.json,
//! through core). Offsets are code-point indices.

use crate::pack::Pack;
use crate::pyre::{Match, Regex};
use crate::pystr::{self, u, PyStr};
use crate::rxutil;
use crate::unicode;
use std::collections::{HashMap, HashSet};

const fn c(ch: char) -> u32 {
    ch as u32
}

fn has(text: &[u32], needle: &str) -> bool {
    pystr::contains(text, needle)
}

fn any_in(text: &[u32], needles: &pystr::Needles) -> bool {
    needles.any_in(text)
}

fn in_set(set: &[PyStr], s: &[u32]) -> bool {
    set.iter().any(|x| x.as_slice() == s)
}

/// The limits, read once per call.
struct Lim {
    long_row: usize,
    window: usize,
    arg_span: usize,
    lookback: usize,
    named_searches: usize,
    phases: usize,
    alias_max: usize,
    join_rows: usize,
    join_chars: usize,
    logical_max: usize,
}

impl Lim {
    fn of(p: &Pack) -> Lim {
        Lim {
            long_row: p.usize("_DL_LONG_ROW"),
            window: p.usize("_DL_WINDOW"),
            arg_span: p.usize("_DL_ARG_SPAN"),
            lookback: p.usize("_DL_LOOKBACK"),
            named_searches: p.usize("_DL_NAMED_SEARCHES"),
            phases: p.usize("_DL_PHASES"),
            alias_max: p.usize("_DL_ALIAS_MAX"),
            join_rows: p.usize("_DL_JOIN_ROWS"),
            join_chars: p.usize("_DL_JOIN_CHARS"),
            logical_max: p.usize("_DL_LOGICAL_MAX_CHARS"),
        }
    }
}

/// core._dl_finditer: the exact pattern's matches in row[pos:endpos], found
/// through the candidate (which must end by endpos).
pub struct DlIter<'s> {
    exact: &'s Regex,
    cand: &'s Regex,
    row: &'s [u32],
    pos: usize,
    end: usize,
    done: bool,
}

impl<'s> Iterator for DlIter<'s> {
    type Item = Match<'s>;
    fn next(&mut self) -> Option<Match<'s>> {
        if self.done {
            return None;
        }
        loop {
            let m = match self.cand.search_at(self.row, self.pos as isize, self.end as isize) {
                None => {
                    self.done = true;
                    return None;
                }
                Some(m) => m,
            };
            match self.exact.match_at(self.row, m.start() as isize, self.row.len() as isize) {
                None => {
                    self.pos = m.start() + 1;
                    continue;
                }
                Some(e) => {
                    self.pos = if e.end() > e.start() { e.end() } else { e.start() + 1 };
                    return Some(e);
                }
            }
        }
    }
}

pub(crate) fn dl_finditer<'s>(pair: (&'s Regex, &'s Regex), row: &'s [u32], pos: usize, end: Option<usize>) -> DlIter<'s> {
    DlIter { exact: pair.0, cand: pair.1, row, pos, end: end.unwrap_or(row.len()), done: false }
}

fn dl_any(offsets: &[usize], lo: usize, hi: usize) -> bool {
    let i = offsets.partition_point(|&x| x < lo);
    i < offsets.len() && offsets[i] < hi
}

fn dl_within(starts: &[usize], ends: &[usize], lo: usize, hi: usize) -> bool {
    let i = starts.partition_point(|&x| x < lo);
    i < starts.len() && ends[i] <= hi
}

// ---------------- the second reading ----------------

fn blank_literal(m: &Match) -> PyStr {
    let s = m.group0();
    if s.len() >= 2 {
        let mut out = vec![s[0]];
        out.extend(std::iter::repeat(c(' ')).take(s.len() - 2));
        out.push(s[s.len() - 1]);
        out
    } else {
        s.to_vec()
    }
}

fn join_code(p: &Pack, row: &[u32]) -> PyStr {
    let masked = if row.iter().any(|&x| x == c('\'') || x == c('"') || x == c('`')) {
        p.re("_DL_STR_RE").sub_fn(row, 0, blank_literal)
    } else {
        row.to_vec()
    };
    let m = if masked.contains(&c('#')) || has(&masked, "//") {
        p.re("_DL_JOIN_COMMENT_RE").search(&masked).map(|m| m.start())
    } else {
        None
    };
    match m {
        None => masked,
        Some(at) => masked[..at].to_vec(),
    }
}

fn join_plain(p: &Pack, code: &[u32]) -> bool {
    let end = pystr::rstrip(code);
    p.re("_DL_JOIN_BLOCK_RE").search(code).is_none()
        && pystr::count_char(code, c('{'), 0, code.len()) == pystr::count_char(code, c('}'), 0, code.len())
        && !(end.last() == Some(&c(':')) || end.last() == Some(&c('{')))
}

fn bracket_delta(code: &[u32]) -> isize {
    let mut d = 0isize;
    for &x in code {
        match x {
            0x28 | 0x5B => d += 1,
            0x29 | 0x5D => d -= 1,
            _ => {}
        }
    }
    d
}

/// core._dl_join_rows: (joined, firsts), firsts None when nothing was joined.
fn join_rows(p: &Pack, lim: &Lim, text: &[u32]) -> (PyStr, Option<Vec<usize>>) {
    let rows: Vec<&[u32]> = pystr::split_char(text, c('\n'));
    let n = rows.len();
    if n < 2 {
        return (text.to_vec(), None);
    }
    let mut codes: HashMap<usize, PyStr> = HashMap::new();
    let mut code = |j: usize| -> PyStr { codes.entry(j).or_insert_with(|| join_code(p, rows[j])).clone() };
    let mut join = vec![0u8; n];
    let mut k = 0usize;
    while k < n - 1 {
        let row = rows[k];
        if !row.iter().any(|&x| x == c('(') || x == c('[') || x == c('\\')) {
            k += 1;
            continue;
        }
        let cd = code(k);
        if pystr::rstrip(&cd).last() == Some(&c('\\')) && rows[k].len() + 1 + rows[k + 1].len() <= lim.join_chars {
            join[k] = 1;
            k += 1;
            continue;
        }
        let mut depth = bracket_delta(&cd);
        if depth > 0 && rows[k].len() <= lim.join_chars && join_plain(p, &cd) {
            let mut j = k + 1;
            let mut total = rows[k].len();
            let mut done = false;
            while j < n && j - k < lim.join_rows {
                let cj = code(j);
                total += 1 + rows[j].len();
                if total > lim.join_chars || !join_plain(p, &cj) {
                    break;
                }
                depth += bracket_delta(&cj);
                if depth <= 0 {
                    done = true;
                    break;
                }
                j += 1;
            }
            if done {
                for t in k..j {
                    join[t] = 1;
                }
                k = j;
                continue;
            }
        }
        k += 1;
    }
    let chain = p.re("_DL_JOIN_CHAIN_RE");
    for j in 1..n {
        if join[j - 1] != 0 || chain.match_(rows[j]).is_none() || pystr::strip(&code(j - 1)).is_empty() {
            continue;
        }
        let mut first = j - 1;
        let mut total = rows[j - 1].len() + 1 + rows[j].len();
        while first > 0 && join[first - 1] != 0 && j - first < lim.join_rows {
            first -= 1;
            total += rows[first].len() + 1;
        }
        if (first == 0 || join[first - 1] == 0) && j - first < lim.join_rows && total <= lim.join_chars {
            join[j - 1] = 2;
        }
    }
    if join.iter().all(|&x| x == 0) {
        return (text.to_vec(), None);
    }
    let mut out: PyStr = rows[0].to_vec();
    let mut pad = 0usize;
    let mut firsts = vec![0usize];
    for k in 1..n {
        let how = join[k - 1];
        if how == 2 {
            let row = rows[k];
            let body = pystr::lstrip_chars(row, " \t");
            pad += 1 + row.len() - body.len();
            out.extend_from_slice(body);
        } else if how != 0 {
            out.push(c(' '));
            out.extend_from_slice(rows[k]);
        } else {
            out.extend(std::iter::repeat(c(' ')).take(pad));
            out.push(c('\n'));
            pad = 0;
            out.extend_from_slice(rows[k]);
            firsts.push(k);
        }
    }
    out.extend(std::iter::repeat(c(' ')).take(pad));
    (out, Some(firsts))
}

fn ljust(mut s: PyStr, width: usize) -> PyStr {
    while s.len() < width {
        s.push(c(' '));
    }
    s
}

fn env_canonical(p: &Pack, text: PyStr) -> PyStr {
    let mut text = text;
    if has(&text, "environ") || has(&text, "getenv") {
        text = p.re("_DL_ENV_PY_RE").sub_fn(&text, 0, |m| {
            let name = rxutil::or_groups(m, &["a", "b", "c"]).unwrap_or(&[]);
            ljust(pystr::concat(&[&u("environ."), name]), m.group0().len())
        });
    }
    if has(&text, "process") && has(&text, "env") {
        text = p.re("_DL_ENV_JS_RE").sub_fn(&text, 0, |m| {
            ljust(pystr::concat(&[&u("process.env."), m.name("a").unwrap_or(&[])]), m.group0().len())
        });
    }
    text
}

fn comma_calls(p: &Pack, text: PyStr) -> PyStr {
    if !has(&text, "(0") {
        return text;
    }
    let space = p.re("_DL_SPACE_RE_ANY");
    p.re("_DL_COMMA_CALL_RE")
        .sub_fn(&text, 0, |m| ljust(space.sub(m.name("c").unwrap_or(&[]), &[], 0), m.group0().len()))
}

fn members(p: &Pack, text: PyStr) -> PyStr {
    let mut text = text;
    let space = p.re("_DL_SPACE_RE_ANY");
    if has(&text, "getattr") {
        text = p.re("_DL_GETATTR_RE").sub_fn(&text, 0, |m| {
            let o = space.sub(m.name("o").unwrap_or(&[]), &[], 0);
            let name = rxutil::or_groups(m, &["a", "b"]).unwrap_or(&[]);
            ljust(pystr::concat(&[&o, &u("."), name]), m.group0().len())
        });
    }
    if has(&text, "['") || has(&text, "[\"") {
        text = p.re("_DL_MEMBER_RE").sub_fn(&text, 0, |m| {
            let name = rxutil::or_groups(m, &["a", "b"]).unwrap_or(&[]);
            ljust(pystr::concat(&[&u("."), name]), m.group0().len())
        });
    }
    text
}

fn callbacks(p: &Pack, text: PyStr, runners: &[PyStr]) -> PyStr {
    if !text.contains(&c(')')) {
        return text;
    }
    let mut text = text;
    if any_in(&text, p.needles("_DL_CALLBACK_NEEDLES")) {
        let space = p.re("_DL_SPACE_RE_ANY");
        text = p.re("_DL_CALLBACK_RE").sub_fn(&text, 0, |m| {
            pystr::concat(&[&u("(_v)=>"), &space.sub(m.name("r").unwrap_or(&[]), &[], 0), &u("(_v)")])
        });
    }
    let mut names: Vec<&PyStr> = runners.iter().filter(|n| pystr::find(&text, n, 0).is_some()).collect();
    if !names.is_empty() {
        names.sort();
        let esc: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = esc.iter().map(|x| x.as_slice()).collect();
        let src = pystr::concat(&[&p.text("_DL_RUNNER_ARG_HEAD"), &pystr::join(&[c('|')], &parts), &p.text("_DL_RUNNER_ARG_TAIL")]);
        let rx = rxutil::dynamic(src, 0);
        text = rx.sub_fn(&text, 0, |m| pystr::concat(&[&u("(_v)=>"), m.name("r").unwrap_or(&[]), &u("(_v)")]));
    }
    text
}

/// core._dl_logical: (alt, firsts)
pub fn logical(p: &Pack, text: &[u32], runners: &[PyStr]) -> (PyStr, Option<Vec<usize>>) {
    let lim = Lim::of(p);
    let (joined, firsts) = join_rows(p, &lim, text);
    let t = env_canonical(p, joined);
    let t = members(p, t);
    let t = callbacks(p, t, runners);
    (comma_calls(p, t), firsts)
}

// ---------------- names ----------------

fn split_dots<'a>(p: &'a Pack, chain: &'a [u32]) -> Vec<&'a [u32]> {
    p.re("_DL_DOT_RE").split(chain, 0).into_iter().map(|x| x.unwrap_or(&[])).collect()
}

fn lhs_names(p: &Pack, lhs: &[u32]) -> Vec<PyStr> {
    let lhs = pystr::strip(lhs);
    let not_names = p.strs("_DL_NOT_NAMES");
    if lhs.is_empty() || lhs[0] == c('{') || lhs[0] == c('[') {
        return p.re("_DL_NAME_RE").findall(lhs).into_iter().filter(|n| !in_set(not_names, n)).map(|n| n.to_vec()).collect();
    }
    let dot = p.re("_DL_DOT_RE");
    let mut out = Vec::new();
    for part in lhs.split(|&x| x == c(',')) {
        let part = dot.sub(pystr::strip(part), &[c('.')], 0);
        if !part.is_empty() && !in_set(not_names, &part) {
            out.push(part);
        }
    }
    out
}

fn defined_here(p: &Pack, row: &[u32], i: usize) -> bool {
    let mut j = i;
    while j > 0 && unicode::is_space(row[j - 1]) {
        j -= 1;
    }
    if j == i {
        return false;
    }
    for word in p.strs("_DL_DEFINING") {
        if j < word.len() {
            continue;
        }
        let s = j - word.len();
        if row[s..].starts_with(word) && (s == 0 || !(row[s - 1] == c('_') || unicode::is_alnum(row[s - 1]))) {
            return true;
        }
    }
    false
}

struct Taint {
    always: HashSet<PyStr>,
    at: HashMap<PyStr, usize>,
    heads: HashSet<PyStr>,
    window: usize,
}

fn head_of(name: &[u32]) -> PyStr {
    match name.iter().position(|&x| x == c('.')) {
        Some(k) => name[..k].to_vec(),
        None => name.to_vec(),
    }
}

impl Taint {
    fn new(always: Vec<PyStr>, window: usize) -> Taint {
        let heads = always.iter().map(|n| head_of(n)).collect();
        Taint { always: always.into_iter().collect(), at: HashMap::new(), heads, window }
    }
    fn name_live(&self, name: &[u32], row: usize) -> bool {
        if self.always.contains(name) {
            return true;
        }
        match self.at.get(name) {
            Some(&t) => row as isize - t as isize <= self.window as isize,
            None => false,
        }
    }
    fn live(&self, p: &Pack, chain: &[u32], row: usize) -> bool {
        let mut acc: Option<PyStr> = None;
        for part in split_dots(p, chain) {
            let next = match acc {
                None => part.to_vec(),
                Some(a) => pystr::concat(&[&a, &[c('.')], part]),
            };
            if self.name_live(&next, row) {
                return true;
            }
            acc = Some(next);
        }
        false
    }
}

/// core._dl_carried
fn carried(p: &Pack, lim: &Lim, row: &[u32], i: usize, taint: Option<&Taint>, k: usize) -> bool {
    let lead = p.re("_DL_LEAD_RE");
    let callee = p.re("_DL_CALLEE_RE");
    let source = p.pair("_DL_SOURCE").0;
    let n = row.len();
    let mut i = lead.match_at(row, i as isize, n as isize).map(|m| m.end()).unwrap_or(i.min(n));
    let limit = n.min(i + lim.arg_span);
    for step in 0..4 {
        if step > 0 {
            i = lead.match_at(row, i as isize, limit as isize).map(|m| m.end()).unwrap_or(i);
        }
        let m = match callee.match_at(row, i as isize, limit as isize) {
            None => return false,
            Some(m) => m,
        };
        if source.search_at(row, i as isize, m.end() as isize).is_some()
            || taint.map(|t| t.live(p, m.name("chain").unwrap_or(&[]), k)).unwrap_or(false)
        {
            return true;
        }
        if m.name("call").is_none() {
            return false;
        }
        i = m.end();
    }
    false
}

// ---------------- a row read as code ----------------

struct Code {
    lo: usize,
    hi: usize,
    lit_s: Vec<usize>,
    lit_e: Vec<usize>,
    code: PyStr,
    close: Option<HashMap<usize, usize>>,
    opener: HashMap<usize, usize>,
    commas: HashMap<usize, Vec<usize>>,
    open_paren: HashMap<usize, Option<usize>>,
    es: HashMap<usize, Option<usize>>,
    inner: HashMap<usize, usize>,
    by: Option<HashMap<PyStr, Vec<usize>>>,
    live: Vec<usize>,
    holes: Option<(Vec<usize>, Vec<usize>)>,
}

impl Code {
    fn new(p: &Pack, row: &[u32], lo: usize, hi: usize) -> Code {
        let mut code: PyStr = Vec::with_capacity(hi.saturating_sub(lo));
        let mut lit_s = Vec::new();
        let mut lit_e = Vec::new();
        let mut at = lo;
        for m in p.re("_DL_STR_RE").finditer_at(row, lo as isize, hi as isize) {
            let (s, e) = m.span();
            code.extend_from_slice(pystr::sub(row, at, s + 1));
            code.extend(std::iter::repeat(c(' ')).take(e - s - 2));
            at = e - 1;
            lit_s.push(s);
            lit_e.push(e);
        }
        code.extend_from_slice(pystr::sub(row, at, hi));
        Code {
            lo,
            hi,
            lit_s,
            lit_e,
            code,
            close: None,
            opener: HashMap::new(),
            commas: HashMap::new(),
            open_paren: HashMap::new(),
            es: HashMap::new(),
            inner: HashMap::new(),
            by: None,
            live: Vec::new(),
            holes: None,
        }
    }

    fn literal_at(&self, pos: usize) -> Option<usize> {
        let i = self.lit_s.partition_point(|&s| s <= pos);
        if i == 0 {
            return None;
        }
        let i = i - 1;
        if self.lit_s[i] < pos && pos + 1 < self.lit_e[i] {
            Some(i)
        } else {
            None
        }
    }

    fn brackets(&mut self, p: &Pack, queries: &[usize]) {
        if self.close.is_some() {
            return;
        }
        let mut close = HashMap::new();
        let mut stack: Vec<usize> = Vec::new();
        let mut parens: Vec<usize> = Vec::new();
        let mut qi = 0usize;
        let lo = self.lo;
        for m in p.re("_DL_BRACKET_RE").finditer(&self.code) {
            let q = m.start() + lo;
            let ch = m.group0()[0];
            while qi < queries.len() && queries[qi] <= q {
                self.open_paren.insert(queries[qi], parens.last().copied());
                qi += 1;
            }
            if ch == c(',') {
                if let Some(&top) = stack.last() {
                    self.commas.entry(top).or_default().push(q);
                }
            } else if ch == c('(') || ch == c('[') || ch == c('{') {
                stack.push(q);
                if ch == c('(') {
                    parens.push(q);
                }
            } else if let Some(o) = stack.pop() {
                if parens.last() == Some(&o) {
                    parens.pop();
                }
                close.insert(o, q);
                self.opener.insert(q, o);
            }
        }
        for &pq in &queries[qi..] {
            self.open_paren.insert(pq, parens.last().copied());
        }
        self.close = Some(close);
    }

    fn expr_start(&mut self, callee_chars: &[PyStr], j: usize) -> Option<usize> {
        let lo = self.lo;
        let n = self.code.len();
        let mut path = Vec::new();
        let mut q = j;
        let res: Option<usize>;
        loop {
            if let Some(&r) = self.es.get(&q) {
                res = r;
                break;
            }
            path.push(q);
            let r = q - lo;
            if r == 0 {
                res = Some(q);
                break;
            }
            let ch = self.code[r - 1];
            if callee_chars.iter().any(|x| x.len() == 1 && x[0] == ch) {
                q -= 1;
            } else if ch == c(')') || ch == c(']') {
                match self.opener.get(&(q - 1)) {
                    None => {
                        res = None;
                        break;
                    }
                    Some(&o) => q = o,
                }
            } else if (ch == c(' ') || ch == c('\t'))
                && ((r < n && self.code[r] == c('.')) || (r >= 2 && self.code[r - 2] == c('.')))
            {
                q -= 1;
            } else {
                res = Some(q);
                break;
            }
        }
        for pp in path {
            self.es.insert(pp, res);
        }
        res
    }
}

/// core._dl_in_code: is offset pos code where `code` reads it — outside its
/// string literals, or in a template literal's or an f-string's interpolation?
/// A program written in a string literal is text until something runs it.
fn in_code(p: &Pack, row: &[u32], code: &Code, pos: usize) -> bool {
    let i = match code.literal_at(pos) {
        None => return true,
        Some(i) => i,
    };
    let (s, e) = (code.lit_s[i], code.lit_e[i]);
    let holes = if row[s] == c('`') {
        p.re("_DL_TEMPLATE_HOLE_RE")
    } else {
        let prefix_chars = p.strs("_DL_PREFIX_CHARS");
        let mut pre = pystr::sub(row, code.lo.max(s.saturating_sub(2)), s);
        while !pre.is_empty() && !prefix_chars.iter().any(|x| x.len() == 1 && x[0] == pre[0]) {
            pre = &pre[1..];
        }
        if !pre.contains(&c('f')) && !pre.contains(&c('F')) {
            return false;
        }
        p.re("_DL_FSTRING_HOLE_RE")
    };
    holes.finditer_at(row, s as isize, e as isize).any(|m| m.start() < pos && pos < m.end())
}

/// core._dl_chain_index
fn chain_index(p: &Pack, code: &[u32], lo: usize) -> HashMap<PyStr, Vec<usize>> {
    let mut by: HashMap<PyStr, Vec<usize>> = HashMap::new();
    for m in p.re("_DL_CHAIN_RE").finditer(code) {
        let ch = m.group0();
        let s = m.start() + lo;
        if !ch.contains(&c('.')) {
            by.entry(ch.to_vec()).or_default().push(s);
            continue;
        }
        let mut acc: Option<PyStr> = None;
        for part in split_dots(p, ch) {
            let next = match acc {
                None => part.to_vec(),
                Some(a) => pystr::concat(&[&a, &[c('.')], part]),
            };
            by.entry(next.clone()).or_default().push(s);
            acc = Some(next);
        }
    }
    by
}

/// The codes of one row: an arena (a literal's contents read as code are codes too).
struct Codes<'r> {
    row: &'r [u32],
    all: Vec<Code>,
}

impl<'r> Codes<'r> {
    fn add(&mut self, p: &Pack, lo: usize, hi: usize) -> usize {
        self.all.push(Code::new(p, self.row, lo, hi));
        self.all.len() - 1
    }

    fn segment_at(&mut self, p: &Pack, id: usize, pos: usize) -> usize {
        let mut id = id;
        loop {
            let i = match self.all[id].literal_at(pos) {
                None => return id,
                Some(i) => i,
            };
            let next = match self.all[id].inner.get(&i) {
                Some(&n) => n,
                None => {
                    let (lo, hi) = (self.all[id].lit_s[i] + 1, self.all[id].lit_e[i] - 1);
                    let n = self.add(p, lo, hi);
                    self.all[id].inner.insert(i, n);
                    n
                }
            };
            id = next;
        }
    }

    fn index(&mut self, p: &Pack, id: usize, taint: &Taint, k: usize) {
        let by = chain_index(p, &self.all[id].code, self.all[id].lo);
        let mut live: Vec<usize> =
            by.iter().filter(|(name, _)| taint.name_live(name, k)).flat_map(|(_, offs)| offs.iter().copied()).collect();
        live.sort_unstable();
        self.all[id].live = live;
        self.all[id].by = Some(by);
    }

    fn bound(&mut self, id: usize, name: &[u32]) {
        let code = &mut self.all[id];
        if let Some(by) = &code.by {
            if let Some(offs) = by.get(name) {
                for &s in offs {
                    let at = code.live.partition_point(|&x| x <= s);
                    code.live.insert(at, s);
                }
            }
        }
    }

    fn live_holes(&mut self, p: &Pack, id: usize, taint: &Taint, k: usize) -> (Vec<usize>, Vec<usize>) {
        if let Some(h) = &self.all[id].holes {
            return h.clone();
        }
        let row = self.row;
        let prefix_chars = p.strs("_DL_PREFIX_CHARS");
        let template = p.re("_DL_TEMPLATE_HOLE_RE");
        let fstring = p.re("_DL_FSTRING_HOLE_RE");
        let chain = p.re("_DL_CHAIN_RE");
        let (lo, lit_s, lit_e) = {
            let code = &self.all[id];
            (code.lo, code.lit_s.clone(), code.lit_e.clone())
        };
        let mut starts = Vec::new();
        let mut ends = Vec::new();
        for (&s, &e) in lit_s.iter().zip(lit_e.iter()) {
            let holes: Vec<&[u32]> = if row[s] == c('`') {
                template.findall_at(row, s as isize, e as isize)
            } else {
                let mut pre = pystr::sub(row, lo.max(s.saturating_sub(2)), s);
                while !pre.is_empty() && !prefix_chars.iter().any(|x| x.len() == 1 && x[0] == pre[0]) {
                    pre = &pre[1..];
                }
                if !pre.contains(&c('f')) && !pre.contains(&c('F')) {
                    continue;
                }
                fstring.findall_at(row, s as isize, e as isize)
            };
            if holes.is_empty() {
                continue;
            }
            let joined = pystr::join(&[c(' ')], &holes);
            if chain.finditer(&joined).any(|m| taint.live(p, m.group0(), k)) {
                starts.push(s);
                ends.push(e);
            }
        }
        self.all[id].holes = Some((starts.clone(), ends.clone()));
        (starts, ends)
    }
}

// ---------------- the reader ----------------

struct Named<'t> {
    text: &'t [u32],
    rows: &'t [&'t [u32]],
    starts: &'t [usize],
    searches: usize,
    index: Option<HashMap<PyStr, Vec<usize>>>,
}

impl<'t> Named<'t> {
    fn find(&mut self, p: &Pack, lim: &Lim, name: &[u32]) -> Vec<usize> {
        let head = head_of(name);
        if p.re("_DL_WORD_RUN_RE").fullmatch(&head).is_none() {
            return Vec::new();
        }
        if self.index.is_none() && self.searches < lim.named_searches {
            self.searches += 1;
            let esc = crate::pyre::escape(&head);
            let src = pystr::concat(&[&esc, &p.text("_DL_NAMED_MID"), &esc, &p.text("_DL_NAMED_TAIL")]);
            let rx = rxutil::dynamic(src, 0);
            let mut out = Vec::new();
            let mut m = rx.search(self.text);
            while let Some(mm) = m {
                let k = self.starts.partition_point(|&s| s <= mm.start()) - 1;
                out.push(k);
                if k + 1 >= self.starts.len() {
                    break;
                }
                m = rx.search_at(self.text, self.starts[k + 1] as isize, self.text.len() as isize);
            }
            return out;
        }
        if self.index.is_none() {
            let word = p.re("_DL_WORD_RUN_RE");
            let mut index: HashMap<PyStr, Vec<usize>> = HashMap::new();
            for (k, row) in self.rows.iter().enumerate() {
                let mut seen: HashSet<&[u32]> = HashSet::new();
                for w in word.findall(row) {
                    if seen.insert(w) {
                        index.entry(w.to_vec()).or_default().push(k);
                    }
                }
            }
            self.index = Some(index);
        }
        self.index.as_ref().and_then(|ix| ix.get(&head).cloned()).unwrap_or_default()
    }
}

fn import_names(p: &Pack, lim: &Lim, rows: &[&[u32]], cand: &HashSet<usize>) -> Vec<PyStr> {
    let mut out: Vec<PyStr> = Vec::new();
    let add = |x: PyStr, out: &mut Vec<PyStr>| {
        if !out.contains(&x) {
            out.push(x);
        }
    };
    let net = p.strs("_DL_PY_NET_MODULES");
    let mut ks: Vec<usize> = cand.iter().copied().collect();
    ks.sort_unstable();
    for k in ks {
        let row = rows[k];
        if !has(row, "import") || row.len() > lim.long_row {
            continue;
        }
        for m in p.re("_DL_IMPORT_RE").finditer(row) {
            if let Some(py) = m.name("py") {
                for item in py.split(|&x| x == c(',')) {
                    let parts = pystr::split_ws(item);
                    if !parts.is_empty() && in_set(net, parts[0]) {
                        let name = if parts.len() == 3 && pystr::eq(parts[1], "as") { parts[2] } else { parts[0] };
                        add(name.to_vec(), &mut out);
                    }
                }
                continue;
            }
            let items = m.name("pyfrom").or_else(|| m.name("esn"));
            match items {
                None => add(m.name("es").unwrap_or(&[]).to_vec(), &mut out),
                Some(items) => {
                    for item in items.split(|&x| x == c(',')) {
                        let parts = pystr::split_ws(item);
                        if !parts.is_empty() {
                            let name = if parts.len() == 3 && pystr::eq(parts[1], "as") { parts[2] } else { parts[0] };
                            add(name.to_vec(), &mut out);
                        }
                    }
                }
            }
        }
    }
    out
}

fn header(p: &Pack, lim: &Lim, row: &[u32]) -> Option<PyStr> {
    if row.len() > lim.long_row {
        return Some(Vec::new());
    }
    let h = p.re("_DL_FN_HEADER_RE").search(row)?;
    Some(rxutil::or_groups(&h, &["py", "js", "var"]).unwrap_or(&[]).to_vec())
}

fn row_above(lim: &Lim, rows: &[&[u32]], k: usize) -> Option<usize> {
    let stop = k as isize - lim.window as isize - 1;
    let mut j = k as isize - 1;
    while j > stop.max(-1) {
        let r = rows[j as usize];
        if !pystr::strip(r).is_empty() {
            return if r.len() <= lim.long_row { Some(j as usize) } else { None };
        }
        j -= 1;
    }
    None
}

#[derive(Clone)]
enum FactKind {
    Bind,
    Return,
    With,
    For,
    Param(Vec<PyStr>),
}

struct Fact {
    kind: FactKind,
    lo: usize,
    hi: usize,
    // the bind match's groups
    ann: Option<PyStr>,
    lhs: Option<PyStr>,
    with: Option<PyStr>,
    for_: Option<PyStr>,
    continued: bool,
    seg: usize,
}

/// One row (or a minified row's stretch) as the reader reads it.
struct Row<'r> {
    k: usize,
    row: &'r [u32],
    hi: usize,
    codes: Codes<'r>,
    top: Option<usize>,
    phases: Vec<usize>,
    src_s: Vec<usize>,
    src_e: Vec<usize>,
    dirty: bool,
    indexed: Vec<usize>,
}

impl<'r> Row<'r> {
    fn new(p: &Pack, k: usize, row: &'r [u32], lo: usize, hi: usize, sources: Vec<(usize, usize)>, top: bool) -> Row<'r> {
        let mut codes = Codes { row, all: Vec::new() };
        let (top_id, phases) = if top {
            let id = codes.add(p, lo, hi);
            (Some(id), vec![id])
        } else {
            (None, Vec::new())
        };
        Row {
            k,
            row,
            hi,
            codes,
            top: top_id,
            phases,
            src_s: sources.iter().map(|&(s, _)| s).collect(),
            src_e: sources.iter().map(|&(_, e)| e).collect(),
            dirty: false,
            indexed: Vec::new(),
        }
    }

    fn live(&mut self, p: &Pack, seg: usize, taint: &Taint) -> Vec<usize> {
        if self.codes.all[seg].by.is_none() {
            self.codes.index(p, seg, taint, self.k);
            self.indexed.push(seg);
        }
        self.codes.all[seg].live.clone()
    }

    fn live_any(&mut self, p: &Pack, seg: usize, taint: &Taint, lo: usize, hi: usize) -> bool {
        if self.codes.all[seg].by.is_none() {
            self.codes.index(p, seg, taint, self.k);
            self.indexed.push(seg);
        }
        dl_any(&self.codes.all[seg].live, lo, hi)
    }

    fn bound(&mut self, name: &[u32]) {
        for i in 0..self.indexed.len() {
            let id = self.indexed[i];
            self.codes.bound(id, name);
        }
    }

    /// _DlRow.received_in: is a source read inside [lo, hi), in seg's code (in_code)?
    fn received_in(&self, p: &Pack, seg: usize, lo: usize, hi: usize) -> bool {
        let mut i = self.src_s.partition_point(|&x| x < lo);
        while i < self.src_s.len() && self.src_e[i] <= hi {
            if in_code(p, self.row, &self.codes.all[seg], self.src_s[i]) {
                return true;
            }
            i += 1;
        }
        false
    }

    fn phase_at(&mut self, p: &Pack, lim: &Lim, o: usize) -> Option<usize> {
        for &ph in &self.phases {
            let code = &self.codes.all[ph];
            if code.lo <= o && o < code.hi && code.literal_at(o).is_none() {
                return Some(ph);
            }
        }
        if self.phases.len() - (self.top.is_some() as usize) >= lim.phases {
            return None;
        }
        let ph = self.codes.add(p, o, self.hi);
        self.phases.push(ph);
        Some(ph)
    }

    /// _DlRow.runs
    fn runs(&mut self, rd: &mut ReaderState, p: &Pack, lim: &Lim, r: &Match, taint: Option<&Taint>, alias: bool) -> bool {
        let row = self.row;
        let k = self.k;
        if defined_here(p, row, r.start()) {
            return false;
        }
        if !alias && p.re("_DL_SHELL_CALL_RE").fullmatch(r.group0()).is_some() && !rd.shell_within(p, lim, k, row, r.end()) {
            return false;
        }
        let o = r.end() - 1;
        if o >= self.hi {
            return false;
        }
        let ph = match self.phase_at(p, lim, o) {
            None => return false,
            Some(ph) => ph,
        };
        self.codes.all[ph].brackets(p, &[]);
        let ph_hi = self.codes.all[ph].hi;
        let end = ph_hi.min(o + 1 + lim.arg_span);
        let close = self.codes.all[ph].close.as_ref().and_then(|cl| cl.get(&o).copied()).filter(|&cc| cc < end);
        if let Some(cl) = close {
            let after = pystr::lstrip(pystr::sub(row, cl + 1, cl + 3));
            if after.first() == Some(&c('{')) {
                return false;
            }
        }
        let mut starts = vec![o + 1];
        let mut ends = Vec::new();
        if let Some(cs) = self.codes.all[ph].commas.get(&o) {
            for &x in cs {
                if x >= end {
                    break;
                }
                ends.push(x);
                starts.push(x + 1);
            }
        }
        ends.push(close.unwrap_or(end));
        let (live, holes): (Vec<usize>, (Vec<usize>, Vec<usize>)) = match taint {
            Some(t) if self.dirty => {
                let l = self.live(p, ph, t);
                let h = self.codes.live_holes(p, ph, t, k);
                (l, h)
            }
            _ => (Vec::new(), (Vec::new(), Vec::new())),
        };
        let lead = p.re("_DL_LEAD_RE");
        let last = starts.len() - 1;
        for (i, (&s, &e0)) in starts.iter().zip(ends.iter()).enumerate() {
            let mut e = e0;
            if close.is_none() && i == last {
                let le = lead.match_at(row, s as isize, row.len() as isize).map(|m| m.end()).unwrap_or(s);
                e = self.hi.min(le + lim.arg_span);
            }
            if (dl_any(&self.src_s, s, e) || dl_any(&live, s, e)) && carried(p, lim, row, s, taint, k) {
                return true;
            }
        }
        let (s, e) = (starts[0], ends[0]);
        if p.re("_DL_EMBED_RE").match_at(row, s as isize, e as isize).is_none() {
            return false;
        }
        self.received_in(p, ph, s, e) || dl_any(&live, s, e) || dl_within(&holes.0, &holes.1, s, e)
    }
}

/// What the reader keeps between rows (besides the taint).
struct ReaderState {
    until: isize,
    headers: HashMap<usize, Option<PyStr>>,
    shell_row: isize,
    shell: Vec<usize>,
}

impl ReaderState {
    fn shell_within(&mut self, p: &Pack, lim: &Lim, k: usize, row: &[u32], i: usize) -> bool {
        if self.shell_row != k as isize {
            self.shell_row = k as isize;
            self.shell = p.re("_DL_SHELL_ARG_RE").finditer(row).map(|m| m.start()).collect();
        }
        dl_any(&self.shell, i, i + lim.arg_span + 1)
    }

    fn function_above(&mut self, p: &Pack, lim: &Lim, rows: &[&[u32]], k: usize) -> Option<PyStr> {
        let stop = (k as isize - lim.window as isize - 1).max(-1);
        let mut j = k as isize;
        while j > stop {
            let ju = j as usize;
            let h = match self.headers.get(&ju) {
                Some(h) => h.clone(),
                None => {
                    let h = header(p, lim, rows[ju]);
                    self.headers.insert(ju, h.clone());
                    h
                }
            };
            if h.is_some() {
                return h;
            }
            j -= 1;
        }
        None
    }
}

struct Reader<'t, 'p> {
    p: &'p Pack,
    lim: Lim,
    rows: Vec<&'t [u32]>,
    taint: Taint,
    sources: HashSet<usize>,
    runners: (&'p Regex, &'p Regex),
    named: Named<'t>,
    seeds: Vec<u8>,
    sinks: Vec<(&'static str, (&'p Regex, &'p Regex))>,
    aliases: HashMap<PyStr, Option<Vec<usize>>>,
    alias_call: Option<std::rc::Rc<Regex>>,
    st: ReaderState,
}

fn alias_near(def_rows: &Option<Vec<usize>>, lim: &Lim, k: usize) -> bool {
    match def_rows {
        None => true,
        Some(rows) => {
            let i = rows.partition_point(|&r| r <= k);
            i > 0 && k - rows[i - 1] <= lim.window
        }
    }
}

impl<'t, 'p> Reader<'t, 'p> {
    fn short_row(&mut self, k: usize, row: &'t [u32]) -> Option<&'static str> {
        let p = self.p;
        let head_re = p.re("_DL_HEAD_RE");
        let heads_hit = |r: &[u32], heads: &HashSet<PyStr>| -> bool {
            !heads.is_empty() && head_re.findall(r).iter().any(|h| heads.contains(*h))
        };
        let found = heads_hit(row, &self.taint.heads);
        let hot = self.sources.contains(&k);
        let above = if pystr::lstrip(row).first() == Some(&c('.')) { row_above(&self.lim, &self.rows, k) } else { None };
        let above_ok = match above {
            None => false,
            Some(a) => self.sources.contains(&a) || heads_hit(self.rows[a], &self.taint.heads),
        };
        if !(hot || found || above_ok) {
            return None;
        }
        let srcs: Vec<(usize, usize)> =
            if hot { dl_finditer(p.pair("_DL_SOURCE"), row, 0, None).map(|m| m.span()).collect() } else { Vec::new() };
        let mut rd = Row::new(p, k, row, 0, row.len(), srcs, true);
        rd.dirty = found;
        let top = rd.top.unwrap_or(0);
        let mut facts: Vec<Fact> = Vec::new();
        let mut semi: isize = -1;
        if row.contains(&c('=')) || has(row, "as") || has(row, "for") || has(row, "return") {
            for m in p.re("_DL_BIND_RE").finditer(row) {
                let seg = rd.codes.segment_at(p, top, m.start());
                let ann = m.name("ann").map(|x| x.to_vec());
                let lhs = m.name("lhs").map(|x| x.to_vec());
                let ret = m.name("ret").is_some();
                let with = m.name("with").map(|x| x.to_vec());
                let for_ = m.name("for").map(|x| x.to_vec());
                let (kind, lo, hi);
                if ann.is_some() || lhs.as_ref().map(|l| !l.is_empty()).unwrap_or(false) || ret {
                    let lo0 = m.end();
                    if semi < lo0 as isize {
                        semi = pystr::find_char(row, c(';'), lo0).map(|x| x as isize).unwrap_or(row.len() as isize);
                    }
                    kind = if ret { FactKind::Return } else { FactKind::Bind };
                    lo = lo0;
                    hi = semi as usize;
                } else if with.as_ref().map(|w| !w.is_empty()).unwrap_or(false) {
                    kind = FactKind::With;
                    lo = 0;
                    hi = m.start();
                } else {
                    kind = FactKind::For;
                    lo = m.end();
                    hi = row.len();
                }
                facts.push(Fact { kind, lo, hi, ann, lhs, with, for_, continued: false, seg });
            }
        }
        let mut params: Vec<(usize, Vec<PyStr>, usize)> = Vec::new();
        let mut queries: Vec<(usize, Vec<usize>)> = Vec::new();
        if has(row, "=>") || has(row, "function") || has(row, "lambda") {
            let not_names = p.strs("_DL_NOT_NAMES");
            let default_re = p.re("_DL_DEFAULT_RE");
            let name_re = p.re("_DL_NAME_RE");
            for m in p.re("_DL_PARAMS_RE").finditer(row) {
                let ps = rxutil::or_groups(&m, &["fp", "ap", "one", "lp"]).unwrap_or(&[]);
                let stripped = default_re.sub(ps, &[], 0);
                let names: Vec<PyStr> =
                    name_re.findall(&stripped).into_iter().filter(|n| !in_set(not_names, n)).map(|n| n.to_vec()).collect();
                if !names.is_empty() {
                    let seg = rd.codes.segment_at(p, top, m.start());
                    params.push((m.start(), names, seg));
                    match queries.iter_mut().find(|(s, _)| *s == seg) {
                        Some((_, offs)) => offs.push(m.start()),
                        None => queries.push((seg, vec![m.start()])),
                    }
                }
            }
        }
        for (seg, offsets) in &queries {
            rd.codes.all[*seg].brackets(p, offsets);
        }
        let first = row.len() - pystr::lstrip(row).len();
        let callee_chars = p.strs("_DL_CALLEE_CHARS");
        for (pp, names, seg) in params {
            let j = match rd.codes.all[seg].open_paren.get(&pp).copied().flatten() {
                None => continue,
                Some(j) => j,
            };
            let start = match rd.codes.all[seg].expr_start(callee_chars, j) {
                None => continue,
                Some(s) => s,
            };
            let continued = seg == top && start <= first && first < j && row[first] == c('.');
            facts.push(Fact {
                kind: FactKind::Param(names),
                lo: start,
                hi: j,
                ann: None,
                lhs: None,
                with: None,
                for_: None,
                continued,
                seg,
            });
        }
        let mut above_by: Option<HashMap<PyStr, Vec<usize>>> = None;
        let mut above_live = false;
        if let Some(a) = above {
            if facts.iter().any(|f| f.continued) {
                if self.sources.contains(&a) {
                    above_live = true;
                } else {
                    // (core reuses the chains of the row it read last when that is the
                    // row above: the same index of the same code)
                    let a_row = self.rows[a];
                    let by = chain_index(p, &Code::new(p, a_row, 0, a_row.len()).code, 0);
                    above_live = by.keys().any(|n| self.taint.name_live(n, k));
                    above_by = Some(by);
                }
            }
        }
        let mut added: Vec<PyStr> = Vec::new();
        let mut pending: Vec<Fact> = facts;
        for _ in 0..3 {
            let mut grew = false;
            let mut rest: Vec<Fact> = Vec::new();
            for f in pending {
                let hit = rd.received_in(p, f.seg, f.lo, f.hi)
                    || (f.continued && above_live)
                    || (rd.dirty && rd.live_any(p, f.seg, &self.taint, f.lo, f.hi));
                if !hit {
                    rest.push(f);
                    continue;
                }
                let (names, always) = self.names_of(&f, row, k);
                for name in names {
                    if always {
                        if self.taint.always.contains(&name) {
                            continue;
                        }
                        self.taint.always.insert(name.clone());
                        added.push(name.clone());
                    } else if self.taint.at.get(&name) != Some(&k) {
                        self.taint.at.insert(name.clone(), k);
                        self.st.until = self.st.until.max((k + self.lim.window) as isize);
                    } else {
                        continue;
                    }
                    grew = true;
                    rd.dirty = true;
                    self.taint.heads.insert(head_of(&name));
                    rd.bound(&name);
                    if let Some(by) = &above_by {
                        if by.contains_key(&name) {
                            above_live = true;
                        }
                    }
                }
            }
            pending = rest;
            if !grew {
                break;
            }
        }
        for name in &added {
            for r in self.named.find(p, &self.lim, name) {
                if r > k {
                    self.seeds[r] = 1;
                }
            }
        }
        // its runners, with what it binds
        let taint = &self.taint;
        for r in dl_finditer(self.runners, row, 0, None) {
            if rd.runs(&mut self.st, p, &self.lim, &r, Some(taint), false) {
                return Some("run");
            }
        }
        for r in dl_finditer(p.pair("_DL_INTERP"), row, 0, None) {
            if carried(p, &self.lim, row, r.end(), Some(taint), k) {
                return Some("run");
            }
        }
        let from_import = !self.sinks.is_empty() && p.re("_DL_FROM_IMPORT_RE").match_(row).is_some();
        let bare_import = p.re("_DL_BARE_IMPORT_RE");
        for &(cat, sink) in &self.sinks {
            for r in dl_finditer(sink, row, 0, None) {
                if from_import && bare_import.fullmatch(r.group0()).is_some() {
                    continue;
                }
                if rd.runs(&mut self.st, p, &self.lim, &r, Some(taint), false) {
                    return Some(cat);
                }
            }
        }
        if let Some(ac) = self.alias_call.clone() {
            for r in ac.finditer(row) {
                let name = r.group(1).unwrap_or(&[]);
                let near = self.aliases.get(name).map(|d| alias_near(d, &self.lim, k)).unwrap_or(false);
                if near && rd.runs(&mut self.st, p, &self.lim, &r, Some(taint), true) {
                    return Some("run");
                }
            }
        }
        None
    }

    /// _DlReader._names: (names, always)
    fn names_of(&mut self, f: &Fact, row: &[u32], k: usize) -> (Vec<PyStr>, bool) {
        let p = self.p;
        let not_names = p.strs("_DL_NOT_NAMES");
        match &f.kind {
            FactKind::Param(names) => (names.clone(), false),
            FactKind::Bind => {
                let names: Vec<PyStr> = match &f.ann {
                    Some(a) => vec![a.clone()],
                    None => lhs_names(p, f.lhs.as_deref().unwrap_or(&[])),
                };
                let names: Vec<PyStr> = names.into_iter().filter(|n| !in_set(not_names, n)).collect();
                if names.len() == 1 && !names[0].contains(&c('.')) {
                    if p.re("_DL_MODULE_VALUE_RE").match_at(row, f.lo as isize, f.hi as isize).is_some() {
                        return (names, true);
                    }
                    if names[0].len() >= 3 && p.re("_DL_FUNCTION_VALUE_RE").match_at(row, f.lo as isize, f.hi as isize).is_some()
                    {
                        return (names, true);
                    }
                }
                (names, false)
            }
            FactKind::With => (vec![f.with.clone().unwrap_or_default()], false),
            FactKind::For => (lhs_names(p, f.for_.as_deref().unwrap_or(&[])), false),
            FactKind::Return => {
                let rows = self.rows.clone();
                let fname = self.st.function_above(p, &self.lim, &rows, k);
                match fname {
                    Some(fnm) if fnm.len() >= 3 => (vec![fnm], true),
                    _ => (Vec::new(), true),
                }
            }
        }
    }

    fn long_row(&mut self, k: usize, row: &'t [u32]) -> Option<&'static str> {
        let p = self.p;
        let lim = &self.lim;
        let mut stretches: Vec<(usize, usize)> = Vec::new();
        for nm in p.re("_DL_NEEDLE_RE").finditer(row) {
            let lo = nm.start().saturating_sub(lim.lookback);
            match stretches.last_mut() {
                Some(last) if lo <= last.1 => last.1 = nm.start(),
                _ => stretches.push((lo, nm.start())),
            }
        }
        let mut families: Vec<(&'static str, (&Regex, &Regex))> = vec![("run", self.runners)];
        families.extend(self.sinks.iter().copied());
        let from_import = !self.sinks.is_empty() && p.re("_DL_FROM_IMPORT_RE").match_(row).is_some();
        let bare_import = p.re("_DL_BARE_IMPORT_RE");
        let lim = Lim::of(p);
        for (lo, hi) in stretches {
            let end = row.len().min(hi + 3 * lim.arg_span);
            let mut rd: Option<Row> = None;
            let search_end = end.min(hi + lim.arg_span);
            for &(cat, family) in &families {
                for r in dl_finditer(family, row, lo, Some(search_end)) {
                    if r.start() >= hi {
                        break;
                    }
                    if from_import && cat == "import" && bare_import.fullmatch(r.group0()).is_some() {
                        continue;
                    }
                    if rd.is_none() {
                        let srcs: Vec<(usize, usize)> =
                            dl_finditer(p.pair("_DL_SOURCE"), row, lo, Some(end)).map(|m| m.span()).collect();
                        rd = Some(Row::new(p, k, row, lo, end, srcs, false));
                    }
                    if let Some(rdr) = rd.as_mut() {
                        if rdr.runs(&mut self.st, p, &lim, &r, None, false) {
                            return Some(cat);
                        }
                    }
                }
            }
            for r in dl_finditer(p.pair("_DL_INTERP"), row, lo, Some(search_end)) {
                if r.start() >= hi {
                    break;
                }
                if carried(p, &lim, row, r.end(), None, k) {
                    return Some("run");
                }
            }
        }
        None
    }
}

fn runner_aliases(p: &Pack, lim: &Lim, rows: &[&[u32]]) -> Vec<(PyStr, Vec<usize>)> {
    let needles = p.needles("_DL_ALIAS_NEEDLES");
    let not_names = p.strs("_DL_NOT_NAMES");
    let rx = p.re("_DL_ALIAS_RE");
    let mut defs: Vec<(PyStr, Vec<usize>)> = Vec::new();
    for (k, row) in rows.iter().enumerate() {
        if !row.contains(&c('=')) || row.len() > lim.long_row || !any_in(row, needles) {
            continue;
        }
        for m in rx.finditer(row) {
            let name = m.name("alias").unwrap_or(&[]);
            if in_set(not_names, name) {
                continue;
            }
            match defs.iter_mut().find(|(n, _)| n.as_slice() == name) {
                Some((_, rs)) => rs.push(k),
                None => {
                    if defs.len() >= lim.alias_max {
                        continue;
                    }
                    defs.push((name.to_vec(), vec![k]));
                }
            }
        }
    }
    defs
}

/// core._received_code_kind: (1-based line, category) or None.
pub fn received_code_kind(p: &Pack, text: &[u32], extra_always: &[PyStr], extra_runners: &[PyStr]) -> Option<(usize, &'static str)> {
    if extra_runners.is_empty()
        && !(any_in(text, p.needles("_DL_RUN_NEEDLES"))
            || any_in(text, p.needles("_DL_DESERIAL_NEEDLES"))
            || any_in(text, p.needles("_DL_IMPORT_NEEDLES")))
    {
        return None;
    }
    if extra_always.is_empty() && !any_in(text, p.needles("_DL_NEEDLES")) {
        return None;
    }
    let res = dl_kind(p, text, extra_always, extra_runners);
    let lim = Lim::of(p);
    if res.is_some() || text.len() > lim.logical_max {
        return res;
    }
    let (alt, firsts) = logical(p, text, extra_runners);
    if alt == text {
        return None;
    }
    let (line, cat) = dl_kind(p, &alt, extra_always, extra_runners)?;
    Some((
        match firsts {
            None => line,
            Some(f) => f.get(line - 1).copied().unwrap_or(0) + 1,
        },
        cat,
    ))
}

fn dl_kind(p: &Pack, text: &[u32], extra_always: &[PyStr], extra_runners: &[PyStr]) -> Option<(usize, &'static str)> {
    let lim = Lim::of(p);
    let rows: Vec<&[u32]> = pystr::split_char(text, c('\n'));
    let mut starts = Vec::with_capacity(rows.len());
    let mut at = 0usize;
    for r in &rows {
        starts.push(at);
        at += r.len() + 1;
    }
    let needle = p.re("_DL_NEEDLE_RE");
    let mut near: HashSet<usize> = HashSet::new();
    let mut m = needle.search(text);
    while let Some(mm) = m {
        let k = starts.partition_point(|&s| s <= mm.start()) - 1;
        near.insert(k);
        m = if k + 1 < starts.len() { needle.search_at(text, starts[k + 1] as isize, text.len() as isize) } else { None };
    }
    let mut always: Vec<PyStr> = if has(text, "import") { import_names(p, &lim, &rows, &near) } else { Vec::new() };
    always.extend(extra_always.iter().cloned());
    let taint = Taint::new(always, lim.window);
    let source = p.pair("_DL_SOURCE");
    let sources: HashSet<usize> = near
        .iter()
        .copied()
        .filter(|&k| rows[k].len() > lim.long_row || dl_finditer(source, rows[k], 0, None).next().is_some())
        .collect();
    if taint.always.is_empty() && sources.is_empty() {
        return None;
    }
    let mut named = Named { text, rows: &rows, starts: &starts, searches: 0, index: None };
    let mut seeds = vec![0u8; rows.len()];
    for &r in &sources {
        seeds[r] = 1;
    }
    let mut always_names: Vec<PyStr> = taint.always.iter().cloned().collect();
    always_names.sort();
    for name in &always_names {
        for r in named.find(p, &lim, name) {
            seeds[r] = 1;
        }
    }
    let mut aliases: HashMap<PyStr, Option<Vec<usize>>> = HashMap::new();
    if any_in(text, p.needles("_DL_ALIAS_NEEDLES")) {
        for (n, rs) in runner_aliases(p, &lim, &rows) {
            aliases.insert(n, Some(rs));
        }
    }
    for name in extra_runners {
        aliases.insert(name.clone(), None);
    }
    let mut alias_call = None;
    if !aliases.is_empty() {
        let mut names: Vec<&PyStr> = aliases.keys().collect();
        names.sort();
        let esc: Vec<PyStr> = names.iter().map(|n| crate::pyre::escape(n)).collect();
        let parts: Vec<&[u32]> = esc.iter().map(|x| x.as_slice()).collect();
        let src = pystr::concat(&[&p.text("_DL_ALIAS_CALL_HEAD"), &pystr::join(&[c('|')], &parts), &p.text("_DL_ALIAS_CALL_TAIL")]);
        alias_call = Some(rxutil::dynamic(src, 0));
        let names: Vec<PyStr> = names.into_iter().cloned().collect();
        for name in &names {
            for r in named.find(p, &lim, name) {
                seeds[r] = 1;
            }
        }
    }
    let shell_on = has(text, "shell") && p.re("_DL_SHELL_TRUE_RE").search(text).is_some();
    let runners = if shell_on { p.pair("_DL_RUNNER_SHELL") } else { p.pair("_DL_RUNNER") };
    let mut sinks = Vec::new();
    if any_in(text, p.needles("_DL_DESERIAL_NEEDLES")) {
        sinks.push(("deserialize", p.pair("_DL_DESERIAL")));
    }
    if any_in(text, p.needles("_DL_IMPORT_NEEDLES")) {
        sinks.push(("import", p.pair("_DL_IMPORT_SINK")));
    }
    let long_row = lim.long_row;
    let window = lim.window;
    let mut reader = Reader {
        p,
        lim,
        rows: rows.clone(),
        taint,
        sources,
        runners,
        named,
        seeds,
        sinks,
        aliases,
        alias_call,
        st: ReaderState { until: -1, headers: HashMap::new(), shell_row: -1, shell: Vec::new() },
    };
    let n = rows.len();
    let find_seed = |seeds: &[u8], from: usize| seeds[from.min(seeds.len())..].iter().position(|&x| x == 1).map(|i| i + from);
    let mut k = find_seed(&reader.seeds, 0).unwrap_or(n);
    while k < n {
        let row = rows[k];
        if row.len() > long_row {
            if let Some(cat) = reader.long_row(k, row) {
                return Some((k + 1, cat));
            }
        } else {
            if reader.seeds[k] != 0 {
                reader.st.until = reader.st.until.max((k + window) as isize);
            }
            if let Some(cat) = reader.short_row(k, row) {
                return Some((k + 1, cat));
            }
        }
        let mut nk = k + 1;
        if nk as isize > reader.st.until {
            nk = find_seed(&reader.seeds, nk).unwrap_or(n);
        }
        k = nk;
    }
    None
}

// ---------------- download to a file, then run the file ----------------

fn norm_path(tok: &[u32]) -> PyStr {
    let mut t: &[u32] = tok;
    if t.is_empty() || t[0] == c('"') || t[0] == c('\'') {
        t = if t.len() >= 2 { &t[1..t.len() - 1] } else { &[] };
        while pystr::starts_with(t, "./") {
            t = &t[2..];
        }
    }
    t.to_vec()
}

fn region_names_path(p: &Pack, region: &[u32], path: &[u32]) -> bool {
    if p.re("_DL_NAME_RE").finditer(region).any(|m| m.group0() == path) {
        return true;
    }
    p.re("_DL_STR_RE").finditer(region).any(|m| {
        let lit = m.group0();
        norm_path(lit) == path || command_runs(p, pystr::slice(lit, 1, -1), path)
    })
}

/// core._dl_command_runs: does the command line `line` (a string literal's
/// text) run the file `path` — as a command's program, or as what a program
/// that runs its argument is given (_DL_RUNNERS)?
fn command_runs(p: &Pack, line: &[u32], path: &[u32]) -> bool {
    let runners = p.strs("_DL_RUNNERS");
    let mut first = true;
    let mut runner = false;
    for m in p.re("_DL_CMD_TOKEN_RE").finditer(line) {
        let tok = m.group0();
        if tok.len() == 1 && matches!(tok[0], 0x7C | 0x26 | 0x3B | 0x0A) {
            first = true;
            runner = false;
            continue;
        }
        let mut word: &[u32] = pystr::strip_chars(tok, "\"'");
        if first {
            if word.contains(&c('=')) {
                continue; // an assignment before the command
            }
            first = false;
            let key: PyStr = if pystr::is_ascii(word) { pystr::lower(word) } else { word.to_vec() };
            runner = runners.iter().any(|r| *r == key);
        } else if !runner {
            continue;
        }
        while pystr::starts_with(word, "./") {
            word = &word[2..];
        }
        if word == path {
            return true;
        }
    }
    false
}

fn run_interp(p: &Pack, row: &[u32]) -> Option<PyStr> {
    if let Some(m) = p.re("_SCRIPT_INTERP_RE").search(row) {
        return Some(m.name("name").unwrap_or(&[]).to_vec());
    }
    let m = p.re("_SCRIPT_LOAD_RE").search(row)?;
    Some(if m.name("fork").is_some() { u("node") } else { u("Python") })
}

fn pathrun_after(p: &Pack, lim: &Lim, rows: &[&[u32]], k: usize, path: &[u32]) -> Option<usize> {
    let end = rows.len().min(k + lim.window + 1);
    let needles = p.needles("_DL_PATHRUN_NEEDLES");
    let sink = p.re("_DL_PATHRUN_SINK_RE");
    for j in k..end {
        let row = rows[j];
        if row.len() > lim.long_row || !any_in(row, needles) {
            continue;
        }
        for sm in sink.finditer(row) {
            if region_names_path(p, pystr::sub(row, sm.end(), sm.end() + lim.arg_span), path) {
                return Some(j);
            }
        }
    }
    None
}

fn written_and_run(p: &Pack, lim: &Lim, rows: &[&[u32]], is_src: &dyn Fn(&[u32]) -> bool, downloads: bool) -> Option<usize> {
    let mut known: HashMap<usize, bool> = HashMap::new();
    let n = rows.len();
    let needles = p.needles("_DL_FILE_WRITE_NEEDLES");
    let write = p.re("_DL_FILE_WRITE_RE");
    for (k, row) in rows.iter().enumerate() {
        if row.len() > lim.long_row || !any_in(row, needles) {
            continue;
        }
        let mut near_src: Option<bool> = None;
        for wm in write.finditer(row) {
            if wm.name("p4").is_none() && wm.name("p5").is_none() {
                if near_src.is_none() {
                    let lo = k.saturating_sub(lim.window);
                    let hi = n.min(k + lim.window + 1);
                    let mut any = false;
                    for j in lo..hi {
                        let got = *known.entry(j).or_insert_with(|| rows[j].len() <= lim.long_row && is_src(rows[j]));
                        if got {
                            any = true;
                            break;
                        }
                    }
                    near_src = Some(any);
                }
                if near_src == Some(false) {
                    continue;
                }
            } else if !downloads {
                continue;
            }
            let path = norm_path(wm.first_group().unwrap_or(&[]));
            if path.is_empty() {
                continue;
            }
            if let Some(hit) = pathrun_after(p, lim, rows, k, &path) {
                return Some(hit);
            }
        }
    }
    None
}

/// core._downloads_and_runs: (line, interpreter)
pub fn downloads_and_runs(p: &Pack, text: &[u32]) -> Option<(usize, Option<PyStr>)> {
    if !any_in(text, p.needles("_DL_NEEDLES"))
        || !any_in(text, p.needles("_DL_FILE_WRITE_NEEDLES"))
        || !any_in(text, p.needles("_DL_PATHRUN_NEEDLES"))
    {
        return None;
    }
    let lim = Lim::of(p);
    let rows: Vec<&[u32]> = pystr::split_char(text, c('\n'));
    let source = p.pair("_DL_SOURCE");
    let is_src = |row: &[u32]| dl_finditer(source, row, 0, None).next().is_some();
    let hit = written_and_run(p, &lim, &rows, &is_src, true)?;
    Some((hit + 1, run_interp(p, rows[hit])))
}

/// core._decodes_and_runs: (line, interpreter)
pub fn decodes_and_runs(p: &Pack, text: &[u32]) -> Option<(usize, Option<PyStr>)> {
    if !any_in(text, p.needles("_DL_FILE_WRITE_NEEDLES"))
        || !any_in(text, p.needles("_DL_PATHRUN_NEEDLES"))
        || p.re("_DECODE_CALL_RE").search(text).is_none()
    {
        return None;
    }
    let lim = Lim::of(p);
    let rows: Vec<&[u32]> = pystr::split_char(text, c('\n'));
    let decode = p.re("_DECODE_CALL_RE");
    let is_src = |row: &[u32]| decode.search(row).is_some();
    let hit = written_and_run(p, &lim, &rows, &is_src, false)?;
    Some((hit + 1, run_interp(p, rows[hit])))
}
