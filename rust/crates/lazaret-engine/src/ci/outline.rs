//! The outline of a YAML file that the CI checks read (scanner/ghworkflow.py's `_outline` until BR-7 moved it here):
//! each `key: value` line with the keys above it (a sequence item counts as "-"), block scalars (`run: |`), the
//! values of flow collections, quoted scalars and comments. It is not a YAML parser: anchors, tags, multi-line flow
//! collections and complex keys are read as the plain text they are. Lazaret has no YAML library (it depends on
//! nothing), and a workflow's or a pipeline's checks need no more than this.

use crate::json::Value;
use crate::pystr::{self, PyStr};

const fn c(ch: char) -> u32 {
    ch as u32
}

/// One line of the outline.
#[derive(Clone, Debug)]
pub struct Rec {
    /// its line number (from 1)
    pub line: usize,
    /// the keys above it ("-" for a sequence item)
    pub path: Vec<PyStr>,
    /// the line's key (None for a scalar line: a sequence item's value, a continuation)
    pub key: Option<PyStr>,
    /// the value's text (a quoted one's content, escapes kept; a plain one up to its comment)
    pub value: PyStr,
    /// a block scalar's lines (line, text without indentation)
    pub block: Vec<(usize, PyStr)>,
    /// the first record of a sequence item (the line began with '- ', or a lone '-' stood on the one before)
    pub item: bool,
}

impl Rec {
    /// path == [names…]
    pub fn path_is(&self, names: &[&str]) -> bool {
        self.path.len() == names.len() && self.path.iter().zip(names).all(|(a, b)| pystr::eq(a, b))
    }

    /// The last name of the path is `name`.
    pub fn path_ends(&self, name: &str) -> bool {
        self.path.last().is_some_and(|x| pystr::eq(x, name))
    }

    pub fn path_has(&self, name: &str) -> bool {
        self.path.iter().any(|x| pystr::eq(x, name))
    }

    pub fn key_is(&self, name: &str) -> bool {
        self.key.as_deref().is_some_and(|k| pystr::eq(k, name))
    }

    /// Its value, with its block scalar, one line per line (ghworkflow._text).
    pub fn text(&self) -> PyStr {
        let mut parts: Vec<&[u32]> = Vec::new();
        if !self.value.is_empty() {
            parts.push(&self.value);
        }
        parts.extend(self.block.iter().map(|(_, t)| t.as_slice()));
        pystr::join(&[c('\n')], &parts)
    }

    /// (line, text) of its value and of its block scalar's lines (ghworkflow._lines).
    pub fn lines(&self) -> Vec<(usize, PyStr)> {
        let mut out = Vec::new();
        if !self.value.is_empty() {
            out.push((self.line, self.value.clone()));
        }
        out.extend(self.block.iter().cloned());
        out
    }

    /// The record as the `ci_outline` call answers it; `items` adds the "item" field.
    pub fn to_value(&self, items: bool) -> Value {
        let mut fields = vec![
            ("line", Value::Int(self.line as i64)),
            ("path", Value::Arr(self.path.iter().map(|x| Value::Str(x.clone())).collect())),
            ("key", self.key.clone().map(Value::Str).unwrap_or(Value::Null)),
            ("value", Value::Str(self.value.clone())),
            (
                "block",
                Value::Arr(
                    self.block.iter().map(|(n, t)| Value::Arr(vec![Value::Int(*n as i64), Value::Str(t.clone())])).collect(),
                ),
            ),
        ];
        if items {
            fields.push(("item", Value::Bool(self.item)));
        }
        Value::obj(fields)
    }
}

fn indent(line: &[u32]) -> usize {
    line.iter().take_while(|&&ch| ch == c(' ')).count()
}

fn rstrip_st(s: &[u32]) -> &[u32] {
    pystr::rstrip_chars(s, " \t")
}

fn lstrip_st(s: &[u32]) -> &[u32] {
    pystr::lstrip_chars(s, " \t")
}

/// The end (exclusive) of the quoted scalar that opens s, or None when it does not close on this line.
fn quoted_end(s: &[u32]) -> Option<usize> {
    let q = s[0];
    let mut j = 1;
    while j < s.len() {
        let ch = s[j];
        if q == c('"') && ch == c('\\') {
            j += 2;
            continue;
        }
        if ch == q {
            if q == c('\'') && pystr::starts_with_at(s, j, "''") {
                j += 2;
                continue;
            }
            return Some(j + 1);
        }
        j += 1;
    }
    None
}

/// Where a comment starts in s (a '#' after a space or a tab), or len(s).
fn comment_at(s: &[u32]) -> usize {
    let mut best = s.len();
    for sep in [" #", "\t#"] {
        if let Some(k) = pystr::find_str(s, sep, 0) {
            best = best.min(k);
        }
    }
    best
}

/// (text, quoted) of a scalar written at the start of s.
fn scalar(s: &[u32]) -> (PyStr, bool) {
    if s.first().is_some_and(|&ch| ch == c('"') || ch == c('\'')) {
        return match quoted_end(s) {
            Some(end) => (s[1..end - 1].to_vec(), true),
            None => (s[1..].to_vec(), true),
        };
    }
    (rstrip_st(&s[..comment_at(s)]).to_vec(), false)
}

/// (key, value text) of a line's body: the key None when the line is not `key: value`.
fn split(body: &[u32]) -> (Option<PyStr>, PyStr) {
    if body.first().is_some_and(|&ch| ch == c('"') || ch == c('\'')) {
        let end = match quoted_end(body) {
            Some(e) => e,
            None => return (None, body.to_vec()),
        };
        let rest = lstrip_st(&body[end..]);
        if rest.first() == Some(&c(':')) && (rest.len() == 1 || rest[1] == c(' ') || rest[1] == c('\t')) {
            return (Some(body[1..end - 1].to_vec()), lstrip_st(&rest[1..]).to_vec());
        }
        return (None, body.to_vec());
    }
    if body.first().is_some_and(|&ch| ch == c('[') || ch == c('{') || ch == c('#') || ch == c('?')) {
        return (None, body.to_vec());
    }
    let cut = comment_at(body);
    let k = pystr::find_in(body, &[c(':'), c(' ')], 0, cut);
    let kt = pystr::find_in(body, &[c(':'), c('\t')], 0, cut);
    let k = match (k, kt) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, None) => a,
        (None, b) => b,
    };
    match k {
        Some(k) => (Some(pystr::rstrip(&body[..k]).to_vec()), lstrip_st(&body[k + 2..]).to_vec()),
        None => {
            let head = pystr::rstrip(&body[..cut]);
            if head.last() == Some(&c(':')) {
                (Some(pystr::rstrip(&head[..head.len() - 1]).to_vec()), Vec::new())
            } else {
                (None, body.to_vec())
            }
        }
    }
}

/// Does a value open a block scalar (`|`, `>-`, `|2`: ghworkflow._BLOCK_RE)?
fn is_block(value: &[u32]) -> bool {
    !value.is_empty()
        && (value[0] == c('|') || value[0] == c('>'))
        && value.len() <= 4
        && value[1..].iter().all(|&ch| ch == c('-') || ch == c('+') || (c('0')..=c('9')).contains(&ch))
}

/// The outline of a text: with `items`, each record says whether it begins a sequence item; with `seq_blocks`, a
/// block scalar that is a sequence item (`- |`, the way GitLab scripts are written) is one.
pub fn outline(text: &[u32], items: bool, seq_blocks: bool) -> Vec<Rec> {
    let mut records: Vec<Rec> = Vec::new();
    let mut stack: Vec<(usize, PyStr)> = Vec::new();
    // the block scalar being read: (its key's indentation, the record's index)
    let mut block: Option<(usize, usize)> = None;
    let mut fresh = false;
    for (n0, raw) in pystr::split_char(text, c('\n')).into_iter().enumerate() {
        let n = n0 + 1;
        let raw = if raw.last() == Some(&c('\r')) { &raw[..raw.len() - 1] } else { raw };
        if let Some((bind, idx)) = block {
            if pystr::strip_chars(raw, " \t").is_empty() {
                continue;
            }
            if indent(raw) > bind {
                let t = pystr::strip_chars(raw, " \t").to_vec();
                records[idx].block.push((n, t));
                continue;
            }
            block = None;
        }
        let mut ind = indent(raw);
        let mut body: &[u32] = rstrip_st(&raw[ind..]);
        if body.is_empty() || body[0] == c('#') {
            continue;
        }
        if ind == 0 && (pystr::eq(body, "---") || pystr::eq(body, "...") || pystr::starts_with(body, "--- ")) {
            stack.clear();
            fresh = false;
            continue;
        }
        while pystr::eq(body, "-") || pystr::starts_with(body, "- ") || pystr::starts_with(body, "-\t") {
            // an item closes what is deeper and the item before it; a key at its own indentation is the
            // sequence's (`steps:` / `- run: x`)
            while let Some((sind, sname)) = stack.last() {
                if *sind > ind || (*sind == ind && pystr::eq(sname, "-")) {
                    stack.pop();
                } else {
                    break;
                }
            }
            stack.push((ind, vec![c('-')]));
            fresh = true;
            let rest = &body[1..];
            let rest_l = lstrip_st(rest);
            let gap = rest.len() - rest_l.len();
            ind = ind + 1 + gap;
            body = rest_l;
        }
        if body.is_empty() || body[0] == c('#') {
            continue;
        }
        let (key, rest) = split(body);
        while stack.last().is_some_and(|(sind, _)| *sind >= ind) {
            stack.pop();
        }
        let path: Vec<PyStr> = stack.iter().map(|(_, name)| name.clone()).collect();
        let (value, quoted) = scalar(&rest);
        let rec_item = fresh;
        fresh = false;
        let idx = records.len();
        records.push(Rec { line: n, path, key: key.clone(), value, block: Vec::new(), item: items && rec_item });
        if let Some(k) = key {
            stack.push((ind, k));
            if !quoted && is_block(&records[idx].value) {
                records[idx].value.clear();
                block = Some((ind, idx));
            }
        } else if seq_blocks
            && !quoted
            && is_block(&records[idx].value)
            && stack.last().is_some_and(|(_, name)| pystr::eq(name, "-"))
        {
            records[idx].value.clear();
            block = Some((stack.last().map(|(i, _)| *i).unwrap_or(0), idx));
        }
    }
    records
}

/// Code points between `${{` and `}}` an expression may have (ghworkflow.EXPR_MAX)
pub const EXPR_MAX: usize = 500;

/// (start, end) of each `${{ … }}` of a line: the first `}}` after a `${{`, when it closes within EXPR_MAX code
/// points (what re.finditer(r"\$\{\{(.{0,500}?)\}\}", t) finds), read in one pass.
pub fn expression_spans(t: &[u32]) -> Vec<(usize, usize)> {
    let open = [c('$'), c('{'), c('{')];
    let close_s = [c('}'), c('}')];
    let mut out = Vec::new();
    let mut i = pystr::find(t, &open, 0);
    let mut close: Option<usize> = None;
    while let Some(at) = i {
        if close.map_or(true, |cl| cl < at + 3) {
            close = pystr::find(t, &close_s, at + 3);
            if close.is_none() {
                break;
            }
        }
        let cl = close.unwrap_or(0);
        if cl - (at + 3) <= EXPR_MAX {
            out.push((at, cl + 2));
            i = pystr::find(t, &open, cl + 2);
        } else {
            i = pystr::find(t, &open, at + 1);
        }
    }
    out
}

/// The text of each `${{ … }}` in a line (ghworkflow._expressions).
pub fn expressions(t: &[u32]) -> Vec<&[u32]> {
    expression_spans(t).into_iter().map(|(a, b)| &t[a + 3..b - 2]).collect()
}
