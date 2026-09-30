//! One source file as core's `scan_file` reads it (`_FileCtx`): its lines,
//! pinned to Unicode 13.0 and split as the language ends lines; the comment
//! layout (which lines are comments, the comment spans of each line, each
//! line without its comment text); the text each line is matched in (NFKC
//! for a Python line with non-ASCII characters, JavaScript's identifier
//! escapes decoded); and a line as names are read in it (literals blanked).
//! Offsets are code points, lines are counted from 0.

use crate::lexer;
use crate::normalize;
use crate::pack::Pack;
use crate::pyre::Regex;
use crate::pystr;
use crate::unicode;
use std::cell::OnceCell;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Py,
    Js,
    Sql,
    Other,
}

impl Lang {
    pub fn from(name: Option<&str>) -> Lang {
        match name {
            Some("py") => Lang::Py,
            Some("js") => Lang::Js,
            Some("sql") => Lang::Sql,
            _ => Lang::Other,
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Lang::Py => Some("py"),
            Lang::Js => Some("js"),
            Lang::Sql => Some("sql"),
            Lang::Other => None,
        }
    }
}

/// _unicode13.pin: every code point Unicode 13.0 leaves unassigned becomes
/// U+FFFD (one for one: offsets do not move).
pub fn pin(text: &mut [u32]) {
    for c in text.iter_mut() {
        if *c >= 0x378 && !unicode::assigned(*c) {
            *c = 0xFFFD;
        }
    }
}

/// normalize_newlines, and for JavaScript U+2028 / U+2029 (line terminators
/// there) as newlines too: the text source_lines splits at "\n".
pub fn source_text(text: &[u32], lang: Lang) -> Vec<u32> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        let c = text[i];
        if c == '\r' as u32 {
            out.push('\n' as u32);
            if i + 1 < text.len() && text[i + 1] == '\n' as u32 {
                i += 1;
            }
        } else if lang == Lang::Js && (c == 0x2028 || c == 0x2029) {
            out.push('\n' as u32);
        } else {
            out.push(c);
        }
        i += 1;
    }
    out
}

/// `line` without the text of `spans` (sorted, disjoint, relative to it).
pub fn cut_spans(line: &[u32], spans: &[(usize, usize)]) -> Vec<u32> {
    let mut out = Vec::with_capacity(line.len());
    let mut p = 0;
    for &(a, b) in spans {
        out.extend_from_slice(&line[p..a]);
        p = b;
    }
    out.extend_from_slice(&line[p..]);
    out
}

fn is_blank(s: &[u32]) -> bool {
    s.iter().all(|&c| unicode::is_space(c))
}

fn replace_feff(mut s: Vec<u32>) -> Vec<u32> {
    for c in s.iter_mut() {
        if *c == 0xFEFF {
            *c = ' ' as u32;
        }
    }
    s
}

/// core._py_match_text
pub fn py_match_text(text: &[u32]) -> Vec<u32> {
    if pystr::is_ascii(text) {
        text.to_vec()
    } else {
        normalize::nfkc(text)
    }
}

pub struct FileCtx<'p> {
    pub p: &'p Pack,
    pub lang: Lang,
    pub jsx: bool,
    /// The text, pinned, its lines joined with "\n".
    pub content: Vec<u32>,
    /// Where each line starts and ends in `content`.
    pub starts: Vec<usize>,
    ends: Vec<usize>,
    /// Comment lines: something other than whitespace, all of it in comments.
    pub cmask: Vec<bool>,
    /// Each line's comment spans, relative to it (sorted; empty for most lines).
    pub cspans: Vec<Vec<(usize, usize)>>,
    /// Each line without its comment text, where it has some.
    code: Vec<Option<Vec<u32>>>,
    /// '…' / "…" literal spans (JavaScript), absolute.
    strings: Vec<(usize, usize)>,
    /// Every literal's span (JavaScript, Python), absolute; None elsewhere.
    literals: Option<Vec<(usize, usize)>>,
    /// Each line's match text, where it is not the line itself.
    mlines: Vec<Option<Vec<u32>>>,
    mcode: Vec<OnceCell<Vec<u32>>>,
}

impl<'p> FileCtx<'p> {
    /// The context of `text` as scan_file reads it (pinned here).
    pub fn new(p: &'p Pack, text: &[u32], lang: Lang, jsx: bool) -> FileCtx<'p> {
        let mut content = source_text(text, lang);
        if !pystr::is_ascii(&content) {
            pin(&mut content);
        }
        let mut starts = vec![0usize];
        let mut ends = Vec::new();
        for (i, &c) in content.iter().enumerate() {
            if c == '\n' as u32 {
                ends.push(i);
                starts.push(i + 1);
            }
        }
        ends.push(content.len());
        let n = starts.len();
        let mut strings = Vec::new();
        let mut literals = Vec::new();
        let want_literals = matches!(lang, Lang::Js | Lang::Py);
        let spans = lexer::lex_comment_spans(
            p,
            &content,
            lang.name(),
            if lang == Lang::Js { Some(&mut strings) } else { None },
            jsx,
            if want_literals { Some(&mut literals) } else { None },
        );
        // _comment_layout
        let mut cspans: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
        for &(s, e) in &spans {
            let mut i = starts.partition_point(|&x| x <= s) - 1;
            while i < n {
                let (ls, le) = (starts[i], ends[i]);
                let a = s.max(ls) - ls;
                let b = e.min(le).saturating_sub(ls);
                if b > a {
                    cspans[i].push((a, b));
                }
                if e <= le + 1 {
                    break;
                }
                i += 1;
            }
        }
        let mut cmask = vec![false; n];
        let mut code: Vec<Option<Vec<u32>>> = vec![None; n];
        for i in 0..n {
            if cspans[i].is_empty() {
                continue;
            }
            let line = &content[starts[i]..ends[i]];
            let c = cut_spans(line, &cspans[i]);
            cmask[i] = is_blank(&c) && !is_blank(line);
            code[i] = Some(c);
        }
        let mut ctx = FileCtx {
            p,
            lang,
            jsx,
            content,
            starts,
            ends,
            cmask,
            cspans,
            code,
            strings,
            literals: if want_literals { Some(literals) } else { None },
            mlines: Vec::new(),
            mcode: (0..n).map(|_| OnceCell::new()).collect(),
        };
        ctx.mlines = (0..n)
            .map(|i| {
                let line = ctx.line(i);
                match lang {
                    Lang::Py => {
                        if pystr::is_ascii(line) {
                            None
                        } else {
                            Some(normalize::nfkc(line))
                        }
                    }
                    Lang::Js => {
                        if !line.contains(&0xFEFF) && !pystr::contains(line, "\\u") {
                            return None;
                        }
                        let t = ctx.js_text(i, false, None);
                        if t.as_slice() == line {
                            None
                        } else {
                            Some(t)
                        }
                    }
                    _ => None,
                }
            })
            .collect();
        ctx
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    /// Where line i ends in `content`.
    pub fn end_of(&self, i: usize) -> usize {
        self.ends[i]
    }

    /// Line i.
    pub fn line(&self, i: usize) -> &[u32] {
        &self.content[self.starts[i]..self.ends[i]]
    }

    /// Line i without its comment text.
    pub fn code(&self, i: usize) -> &[u32] {
        match &self.code[i] {
            Some(c) => c,
            None => self.line(i),
        }
    }

    /// The text line i is matched in.
    pub fn mline(&self, i: usize) -> &[u32] {
        match &self.mlines[i] {
            Some(m) => m,
            None => self.line(i),
        }
    }

    /// Is line i's match text other than the line (NFKC, decoded escapes)?
    pub fn mline_differs(&self, i: usize) -> bool {
        self.mlines[i].is_some()
    }

    /// Is line i's match text without comments other than a part of the
    /// file's text (its match text differs, or comment text was cut out)?
    pub fn mcode_differs(&self, i: usize) -> bool {
        self.mlines[i].is_some() || !self.cspans[i].is_empty()
    }

    /// The match text of line i with its comment text removed (_FileCtx.mcode).
    pub fn mcode(&self, i: usize) -> &[u32] {
        if self.cspans[i].is_empty() {
            return self.mline(i);
        }
        self.mcode[i].get_or_init(|| match self.lang {
            Lang::Py => py_match_text(self.code(i)),
            Lang::Js => self.js_text(i, true, None),
            _ => self.code(i).to_vec(),
        })
    }

    /// Line i as names are read in it (_FileCtx.names_code): its match text
    /// without comments, every literal blanked.
    pub fn names_code(&self, i: usize) -> Vec<u32> {
        let literals = match &self.literals {
            None => return self.mcode(i).to_vec(),
            Some(l) => l,
        };
        let line = self.line(i);
        let base = self.starts[i];
        let end = base + line.len();
        let mut k = literals.partition_point(|&(_, e)| e <= base); // the first literal ending after base
        let mut parts: Vec<u32> = Vec::new();
        let mut p = 0;
        let mut any = false;
        while k < literals.len() && literals[k].0 < end {
            let a = literals[k].0.max(base) - base;
            let b = literals[k].1.min(end) - base;
            parts.extend_from_slice(&line[p..a]);
            parts.extend(std::iter::repeat(' ' as u32).take(b - a));
            p = b;
            k += 1;
            any = true;
        }
        if !any {
            return self.mcode(i).to_vec();
        }
        parts.extend_from_slice(&line[p..]);
        match self.lang {
            Lang::Js => self.js_text(i, true, Some(&parts)),
            _ => py_match_text(&cut_spans(&parts, &self.cspans[i])),
        }
    }

    /// _FileCtx._js_text: line i's match text (its identifier escapes
    /// decoded outside '…' "…" literals, U+FEFF read as a space);
    /// `blanked`: line i with some of its text blanked, to read instead.
    fn js_text(&self, i: usize, drop_comments: bool, blanked: Option<&[u32]>) -> Vec<u32> {
        let line: &[u32] = blanked.unwrap_or_else(|| self.line(i));
        if !pystr::contains(line, "\\u") {
            let plain = if drop_comments {
                match blanked {
                    None => self.code(i).to_vec(),
                    Some(b) => cut_spans(b, &self.cspans[i]),
                }
            } else {
                line.to_vec()
            };
            return replace_feff(plain);
        }
        let base = self.starts[i];
        let cuts: &[(usize, usize)] = if drop_comments { &self.cspans[i] } else { &[] };
        // (start, end, replacement: None to remove)
        let mut edits: Vec<(usize, usize, Option<u32>)> = cuts.iter().map(|&(a, b)| (a, b, None)).collect();
        let rx: &Regex = self.p.re("_JS_UESC_RE");
        let mut c = 0;
        for m in rx.finditer_at(line, 0, line.len() as isize) {
            let at = m.start();
            while c < cuts.len() && cuts[c].1 <= at {
                c += 1;
            }
            if c < cuts.len() && cuts[c].0 <= at {
                continue;
            }
            let k = self.strings.partition_point(|&(a, _)| a <= base + at);
            if k > 0 && self.strings[k - 1].1 > base + at {
                continue; // inside a '…' or "…" literal
            }
            let digits = if m.start_of(1) >= 0 { m.group(1) } else { m.group(2) };
            if let Some(ch) = js_ident_char(self.p, digits.unwrap_or(&[])) {
                edits.push((m.start(), m.end(), Some(ch)));
            }
        }
        let out = if edits.is_empty() {
            if drop_comments {
                match blanked {
                    None => self.code(i).to_vec(),
                    Some(b) => cut_spans(b, &self.cspans[i]),
                }
            } else {
                line.to_vec()
            }
        } else {
            // (sorted as core sorts its (start, end, text) tuples: removals, with
            // the empty text, before a replacement at the same place)
            edits.sort_by(|x, y| (x.0, x.1, x.2.is_some(), x.2).cmp(&(y.0, y.1, y.2.is_some(), y.2)));
            let mut out = Vec::with_capacity(line.len());
            let mut p = 0;
            for (a, b, rep) in edits {
                if a < p {
                    continue;
                }
                out.extend_from_slice(&line[p..a]);
                if let Some(ch) = rep {
                    out.push(ch);
                }
                p = b;
            }
            out.extend_from_slice(&line[p..]);
            out
        };
        replace_feff(out)
    }
}

/// core._js_ident_char: the identifier character a JS \u escape denotes
/// (its hex digits), else None.
pub fn js_ident_char(p: &Pack, digits: &[u32]) -> Option<u32> {
    let mut cp: u64 = 0;
    for &d in digits {
        let v = char::from_u32(d)?.to_digit(16)? as u64;
        cp = cp * 16 + v;
    }
    if cp > 0x10FFFF {
        return None;
    }
    let cp = cp as u32;
    if cp == '$' as u32 || p.strs("_LATER_ID_CONTINUE").iter().any(|s| s.len() == 1 && s[0] == cp) {
        return Some(cp);
    }
    if unicode::assigned(cp) && unicode::props(cp) & unicode::ID_CONTINUE != 0 {
        Some(cp)
    } else {
        None
    }
}
