//! Python `str` operations on code-point slices.
//!
//! Text is `[u32]`: a Python str's code points, lone surrogates included, so
//! every index here is a Python index. Slicing clamps as Python's does
//! (`slice`), and nothing here panics on any index.

use crate::unicode;

pub type PyStr = Vec<u32>;

/// The code points of a Rust string.
#[inline]
pub fn u(s: &str) -> PyStr {
    s.chars().map(|c| c as u32).collect()
}

/// A Rust string of code points (a lone surrogate becomes U+FFFD).
pub fn to_string(s: &[u32]) -> String {
    s.iter().map(|&c| char::from_u32(c).unwrap_or('\u{FFFD}')).collect()
}

/// s[a:b] with Python's clamping (negative indices count from the end).
pub fn slice(s: &[u32], a: isize, b: isize) -> &[u32] {
    let n = s.len() as isize;
    let fix = |i: isize| -> usize {
        let i = if i < 0 { (i + n).max(0) } else { i };
        i.min(n) as usize
    };
    let (a, b) = (fix(a), fix(b));
    if a >= b {
        &[]
    } else {
        &s[a..b]
    }
}

/// s[a:] (a clamped).
#[inline]
pub fn from(s: &[u32], a: usize) -> &[u32] {
    if a >= s.len() {
        &[]
    } else {
        &s[a..]
    }
}

/// s[:b] (b clamped).
#[inline]
pub fn upto(s: &[u32], b: usize) -> &[u32] {
    &s[..b.min(s.len())]
}

/// s[a:b] for a <= b (both clamped).
#[inline]
pub fn sub(s: &[u32], a: usize, b: usize) -> &[u32] {
    let b = b.min(s.len());
    if a >= b {
        &[]
    } else {
        &s[a..b]
    }
}

#[inline]
fn needle_eq(h: &[u32], i: usize, needle: &[u8]) -> bool {
    h.len() >= i + needle.len() && h[i..i + needle.len()].iter().zip(needle).all(|(&a, &b)| a == b as u32)
}

/// Does `h` hold the ASCII (or any) string `needle`? (`needle in h`)
pub fn contains(h: &[u32], needle: &str) -> bool {
    find_str(h, needle, 0).is_some()
}

/// Does `h` hold any of `needles`?
pub fn contains_any(h: &[u32], needles: &[&str]) -> bool {
    needles.iter().any(|n| contains(h, n))
}

/// A text shorter than this is searched character by character.
const SHORT: usize = 64;

/// h.find(needle, start) for a Rust string needle.
pub fn find_str(h: &[u32], needle: &str, start: usize) -> Option<usize> {
    if needle.is_ascii() {
        let nb = needle.as_bytes();
        if nb.is_empty() {
            return if start <= h.len() { Some(start) } else { None };
        }
        let last_start = h.len().checked_sub(nb.len())?;
        if h.len() < start + SHORT {
            // (a short text: each place its first character is)
            let first = nb[0] as u32;
            let mut i = start;
            while i <= last_start {
                match h[i..=last_start].iter().position(|&c| c == first) {
                    None => return None,
                    Some(k) => i += k,
                }
                if needle_eq(h, i, nb) {
                    return Some(i);
                }
                i += 1;
            }
            return None;
        }
        if gated_out_str(h, start, h.len(), needle) {
            return None;
        }
        // (each place the needle's rarest character is, in order: pyre/scan.rs)
        let at = crate::pyre::scan::rarest(nb);
        let c = nb[at] as u32;
        let stop = last_start + at + 1;
        let mut p = start + at;
        while p < stop {
            let q = crate::pyre::scan::find1(h, p, stop, c)?;
            if needle_eq(h, q - at, nb) {
                return Some(q - at);
            }
            p = q + 1;
        }
        None
    } else {
        find(h, &u(needle), start)
    }
}

/// Does the open gate of the text h is part of say the ASCII string
/// `needle` is not in h[start..end] (textgate.rs)?
#[inline]
fn gated_out_str(h: &[u32], start: usize, end: usize, needle: &str) -> bool {
    needle.len() >= 2
        && end >= start + crate::textgate::MIN_RANGE
        && crate::textgate::ask(h, |p| !p.may_hold_str(needle)).unwrap_or(false)
}

/// h.find(n, start)
pub fn find(h: &[u32], n: &[u32], start: usize) -> Option<usize> {
    find_in(h, n, start, h.len())
}

/// h.find(n, start, end)
pub fn find_in(h: &[u32], n: &[u32], start: usize, end: usize) -> Option<usize> {
    let end = end.min(h.len());
    if start > end {
        return None;
    }
    if n.is_empty() {
        return Some(start);
    }
    if n.len() > end - start {
        return None;
    }
    if end >= start + crate::textgate::MIN_RANGE && n.len() >= 2 && crate::textgate::ask(h, |p| !p.may_hold(n)).unwrap_or(false) {
        return None; // (the text lacks one of its pairs: textgate.rs)
    }
    // (each place the needle's rarest character is, in order: pyre/scan.rs)
    let lit = crate::pyre::scan::Literal::new(n);
    lit.find(h, n, start, end)
}

/// h.find(c, start)
pub fn find_char(h: &[u32], c: u32, start: usize) -> Option<usize> {
    if start >= h.len() {
        return None;
    }
    h[start..].iter().position(|&x| x == c).map(|k| k + start)
}

/// h.rfind(c, start, end)
pub fn rfind_char(h: &[u32], c: u32, start: usize, end: usize) -> Option<usize> {
    let end = end.min(h.len());
    if start >= end {
        return None;
    }
    h[start..end].iter().rposition(|&x| x == c).map(|k| k + start)
}

/// h.rfind(n, start, end)
pub fn rfind_in(h: &[u32], n: &[u32], start: usize, end: usize) -> Option<usize> {
    let end = end.min(h.len());
    if start > end || n.len() > end - start {
        return None;
    }
    let mut i = end - n.len();
    loop {
        if h[i..i + n.len()] == *n {
            return Some(i);
        }
        if i == start {
            return None;
        }
        i -= 1;
    }
}

/// h.startswith(needle, i)
pub fn starts_with_at(h: &[u32], i: usize, needle: &str) -> bool {
    if needle.is_ascii() {
        needle_eq(h, i, needle.as_bytes())
    } else {
        let n = u(needle);
        h.len() >= i + n.len() && h[i..i + n.len()] == n[..]
    }
}

pub fn starts_with(h: &[u32], needle: &str) -> bool {
    starts_with_at(h, 0, needle)
}

pub fn ends_with(h: &[u32], needle: &str) -> bool {
    let b = needle.as_bytes();
    if b.is_ascii() {
        return h.len() >= b.len() && needle_eq(h, h.len() - b.len(), b);
    }
    let n = u(needle);
    h.len() >= n.len() && h[h.len() - n.len()..] == n[..]
}

/// h == needle
pub fn eq(h: &[u32], needle: &str) -> bool {
    let b = needle.as_bytes();
    if h.len() == b.len() && b.is_ascii() {
        return needle_eq(h, 0, b);
    }
    !b.is_ascii() && h.iter().copied().eq(needle.chars().map(|c| c as u32))
}

/// h.count(c, start, end)
pub fn count_char(h: &[u32], c: u32, start: usize, end: usize) -> usize {
    sub(h, start, end).iter().filter(|&&x| x == c).count()
}

/// h.split(sep) for one separator character.
pub fn split_char(h: &[u32], sep: u32) -> Vec<&[u32]> {
    h.split(|&c| c == sep).collect()
}

/// h.split(sep) for a separator string.
pub fn split_str<'a>(h: &'a [u32], sep: &[u32]) -> Vec<&'a [u32]> {
    let mut out = Vec::new();
    if sep.is_empty() {
        out.push(h);
        return out;
    }
    let mut at = 0;
    while let Some(i) = find(h, sep, at) {
        out.push(&h[at..i]);
        at = i + sep.len();
    }
    out.push(&h[at..]);
    out
}

/// h.split() with no argument: runs of whitespace separate, none kept.
pub fn split_ws(h: &[u32]) -> Vec<&[u32]> {
    h.split(|&c| unicode::is_space(c)).filter(|p| !p.is_empty()).collect()
}

/// str.strip() / lstrip() / rstrip() (whitespace as str.isspace()).
pub fn strip(h: &[u32]) -> &[u32] {
    rstrip(lstrip(h))
}
pub fn lstrip(h: &[u32]) -> &[u32] {
    let a = h.iter().position(|&c| !unicode::is_space(c)).unwrap_or(h.len());
    &h[a..]
}
pub fn rstrip(h: &[u32]) -> &[u32] {
    let b = h.iter().rposition(|&c| !unicode::is_space(c)).map(|i| i + 1).unwrap_or(0);
    &h[..b]
}

/// str.strip(chars) / lstrip(chars) / rstrip(chars)
pub fn strip_chars<'a>(h: &'a [u32], chars: &str) -> &'a [u32] {
    rstrip_chars(lstrip_chars(h, chars), chars)
}
pub fn lstrip_chars<'a>(h: &'a [u32], chars: &str) -> &'a [u32] {
    let set = u(chars);
    let a = h.iter().position(|c| !set.contains(c)).unwrap_or(h.len());
    &h[a..]
}
pub fn rstrip_chars<'a>(h: &'a [u32], chars: &str) -> &'a [u32] {
    let set = u(chars);
    let b = h.iter().rposition(|c| !set.contains(c)).map(|i| i + 1).unwrap_or(0);
    &h[..b]
}

/// h.replace(a, b)
pub fn replace(h: &[u32], a: &[u32], b: &[u32]) -> PyStr {
    if a.is_empty() {
        // Python inserts b between every character (and at both ends)
        let mut out = Vec::with_capacity(h.len() * (b.len() + 1) + b.len());
        out.extend_from_slice(b);
        for &c in h {
            out.push(c);
            out.extend_from_slice(b);
        }
        return out;
    }
    let mut out = Vec::with_capacity(h.len());
    let mut at = 0;
    while let Some(i) = find(h, a, at) {
        out.extend_from_slice(&h[at..i]);
        out.extend_from_slice(b);
        at = i + a.len();
    }
    out.extend_from_slice(&h[at..]);
    out
}

/// h.replace(a, b) for one character each.
pub fn replace_char(h: &[u32], a: u32, b: u32) -> PyStr {
    h.iter().map(|&c| if c == a { b } else { c }).collect()
}

/// str.lower()
pub fn lower(h: &[u32]) -> PyStr {
    unicode::lower(h)
}

/// str.isidentifier() (Unicode 13.0).
pub fn is_identifier(s: &[u32]) -> bool {
    match s.split_first() {
        None => false,
        Some((&first, rest)) => {
            (unicode::props(first) & unicode::ID_START != 0)
                && rest.iter().all(|&c| unicode::props(c) & unicode::ID_CONTINUE != 0)
        }
    }
}

/// str.isascii()
pub fn is_ascii(s: &[u32]) -> bool {
    s.iter().all(|&c| c < 128)
}

/// ch.isalnum() for one code point.
#[inline]
pub fn is_alnum(c: u32) -> bool {
    unicode::is_alnum(c)
}

/// ch.isspace() for one code point.
#[inline]
pub fn is_space(c: u32) -> bool {
    unicode::is_space(c)
}

/// int(s) for a run of decimal digits (any script's, as Python reads them);
/// None if one is not a digit or the value does not fit.
pub fn int_of_digits(s: &[u32]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &ch in s {
        let d = unicode::decimal_value(ch)? as u64;
        v = v.checked_mul(10)?.checked_add(d)?;
    }
    Some(v)
}

/// Concatenate pieces.
pub fn concat(parts: &[&[u32]]) -> PyStr {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// sep.join(parts)
pub fn join(sep: &[u32], parts: &[&[u32]]) -> PyStr {
    let mut out = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(p);
    }
    out
}

/// Python's posixpath.normpath (for a str path).
pub fn normpath(path: &[u32]) -> PyStr {
    let slash = b'/' as u32;
    if path.is_empty() {
        return vec![b'.' as u32];
    }
    let initial = if path.first() == Some(&slash) {
        // POSIX allows one or two initial slashes, but treats three or more as one
        if path.len() >= 2 && path[1] == slash && !(path.len() >= 3 && path[2] == slash) {
            2
        } else {
            1
        }
    } else {
        0
    };
    let mut comps: Vec<&[u32]> = Vec::new();
    for comp in path.split(|&c| c == slash) {
        if comp.is_empty() || comp == [b'.' as u32] {
            continue;
        }
        if comp != [b'.' as u32, b'.' as u32]
            || (initial == 0 && comps.is_empty())
            || comps.last().map(|c| *c == [b'.' as u32, b'.' as u32]).unwrap_or(false)
        {
            comps.push(comp);
        } else if !comps.is_empty() {
            comps.pop();
        }
    }
    let mut out: PyStr = vec![slash; initial];
    out.extend(join(&[slash], &comps));
    if out.is_empty() {
        vec![b'.' as u32]
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(x: &str) -> PyStr {
        u(x)
    }

    #[test]
    fn slicing_and_search() {
        let h = s("hello world");
        assert_eq!(slice(&h, -5, 100), &s("world")[..]);
        assert_eq!(find_str(&h, "o", 5), Some(7));
        assert_eq!(rfind_char(&h, 'o' as u32, 0, 11), Some(7));
        assert_eq!(rfind_char(&h, 'o' as u32, 0, 5), Some(4));
        assert!(contains(&h, "lo w") && !contains(&h, "low"));
        assert_eq!(split_str(&s("a::b::"), &s("::")).len(), 3);
        assert_eq!(strip(&s("\u{85} x \x1c")), &s("x")[..]);
    }

    #[test]
    fn equal_and_ends_with_any_needle() {
        assert!(eq(&s("os.system"), "os.system") && !eq(&s("os.systems"), "os.system") && !eq(&s("os.syste"), "os.system"));
        assert!(eq(&s(""), "") && !eq(&s("x"), ""));
        assert!(eq(&s("caf\u{e9}"), "caf\u{e9}") && !eq(&s("cafe"), "caf\u{e9}") && !eq(&s("caf\u{e9}x"), "caf\u{e9}"));
        assert!(!eq(&s("abcde"), "caf\u{e9}"));      // as long as the needle's UTF-8 bytes
        assert!(ends_with(&s("a.execute"), "execute") && !ends_with(&s("ute"), "execute") && ends_with(&s("x"), ""));
        assert!(ends_with(&s("na\u{ef}ve"), "\u{ef}ve") && !ends_with(&s("naive"), "\u{ef}ve"));
    }

    #[test]
    fn normpath_matches_posixpath() {
        for (a, b) in [("", "."), ("a/../..", ".."), ("/a/../..", "/"), ("//a", "//a"), ("///a/./b/", "/a/b"),
                       ("a/b/../c", "a/c"), ("../x", "../x"), ("./", ".")] {
            assert_eq!(to_string(&normpath(&s(a))), b, "{}", a);
        }
    }
}

/// A list of strings to look for all at once: `any(n in h for n in list)`
/// in one pass over `h` instead of one per string.
pub struct Needles {
    list: Vec<Vec<u32>>,

    /// for each ASCII character, the strings that start with it
    by_first: Vec<Vec<u32>>,
    /// the strings that start past ASCII
    other: Vec<u32>,
    has_empty: bool,
}

impl Needles {
    pub fn new(list: &[Vec<u32>]) -> Needles {
        let mut by_first = vec![Vec::new(); 128];
        let mut other = Vec::new();
        let mut has_empty = false;
        for (k, n) in list.iter().enumerate() {
            match n.first() {
                None => has_empty = true,
                Some(&c) if c < 128 => by_first[c as usize].push(k as u32),
                Some(_) => other.push(k as u32),
            }
        }
        Needles { list: list.to_vec(), by_first, other, has_empty }
    }

    /// Does `h` hold one of the strings?
    pub fn any_in(&self, h: &[u32]) -> bool {
        if self.has_empty {
            return true;
        }
        if h.len() >= crate::textgate::MIN_RANGE
            && crate::textgate::ask(h, |p| self.list.iter().all(|n| !p.may_hold(n))).unwrap_or(false)
        {
            return false; // (each string has a pair the text lacks: textgate.rs)
        }
        for (i, &c) in h.iter().enumerate() {
            let cands = if c < 128 { &self.by_first[c as usize] } else { &self.other };
            for &k in cands {
                let n = &self.list[k as usize];
                if h[i..].starts_with(n) {
                    return true;
                }
            }
        }
        false
    }
}
