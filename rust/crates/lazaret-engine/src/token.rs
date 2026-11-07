//! core's `_TokenPattern`: the provider token formats (S-TOKEN, and the
//! first pattern of secret redaction), matched in linear time.
//!
//! The pattern is "|".join(alternatives), the last one the JWT alternative
//! `eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}`, which backtracks
//! quadratically on a run of "eyJeyJ…". The other alternatives run as one
//! regex; the JWT one is found by examining each [A-Za-z0-9_-] run once: a
//! match starts at the first "eyJ" of a run that is followed by ".eyJ" and
//! ten more run characters, at least 13 characters before the run's end
//! (core's `_jwt_search`). The matches are core's: leftmost-first over both
//! parts, the same spans.

use crate::json::Value;
use crate::pyre::{self, Regex};

pub struct TokenPattern {
    others: Regex,
}

/// A character of a JWT's runs: [A-Za-z0-9_-].
fn jwt_char(c: u32) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A) || c == '_' as u32 || c == '-' as u32
}

fn run_end(s: &[u32], mut i: usize) -> usize {
    while i < s.len() && jwt_char(s[i]) {
        i += 1;
    }
    i
}

fn starts_with_at(s: &[u32], i: usize, lit: &[u8]) -> bool {
    i + lit.len() <= s.len() && lit.iter().enumerate().all(|(k, &b)| s[i + k] == b as u32)
}

/// (start, end) of the leftmost JWT match beginning in s[start..end_of_run],
/// where `end_of_run` ends that run; else None (core's `_jwt_in_run`).
fn jwt_in_run(s: &[u32], start: usize, end_of_run: usize) -> Option<(usize, usize)> {
    if end_of_run < start + 13 || !starts_with_at(s, end_of_run, b".eyJ") {
        return None;
    }
    let tail = run_end(s, end_of_run + 4);
    if tail - (end_of_run + 4) < 10 {
        return None;
    }
    // the first "eyJ" in s[start .. end_of_run - 10] (Python's find with an end)
    let stop = end_of_run - 10;
    let mut p = start;
    while p + 3 <= stop {
        if starts_with_at(s, p, b"eyJ") {
            return Some((p, tail));
        }
        p += 1;
    }
    None
}

/// (start, end) of the leftmost JWT-alternative match at or after `pos`.
pub fn jwt_search(s: &[u32], mut pos: usize) -> Option<(usize, usize)> {
    let n = s.len();
    if pos > 0 && pos < n && jwt_char(s[pos - 1]) && jwt_char(s[pos]) {
        let end = run_end(s, pos); // pos is inside a run: its rest counts
        if let Some(hit) = jwt_in_run(s, pos, end) {
            return Some(hit);
        }
        pos = end;
    }
    // each run starting at or after pos (core finds the candidates with
    // _JWT_CANDIDATE_RE; a run is one only when jwt_in_run can match in it)
    let mut i = pos;
    while i < n {
        if !jwt_char(s[i]) || (i > 0 && jwt_char(s[i - 1])) {
            i += 1;
            continue;
        }
        let end = run_end(s, i);
        if let Some(hit) = jwt_in_run(s, i, end) {
            return Some(hit);
        }
        i = end.max(i + 1);
    }
    None
}

impl TokenPattern {
    /// From the pack's form of a `_TokenPattern` ({"re", "flags", "token": [alternatives]}).
    pub fn from_value(v: &Value) -> Result<TokenPattern, String> {
        let alts: Vec<Vec<u32>> = v
            .get("token")
            .and_then(|t| t.as_arr())
            .ok_or("not a token pattern")?
            .iter()
            .filter_map(|a| a.as_str().map(|s| s.to_vec()))
            .collect();
        if alts.len() < 2 {
            return Err("a token pattern has the JWT alternative and others".into());
        }
        let mut src = Vec::new();
        for (k, a) in alts[..alts.len() - 1].iter().enumerate() {
            if k > 0 {
                src.push('|' as u32);
            }
            src.extend_from_slice(a);
        }
        let flags = v.get("flags").and_then(|f| f.as_string()).unwrap_or_default();
        let others = Regex::new(&src, pyre::flags_from_letters(&flags)).map_err(|e| e.0)?;
        Ok(TokenPattern { others })
    }

    /// The regex of the alternatives but the JWT one.
    pub fn others(&self) -> &Regex {
        &self.others
    }

    /// The pattern "eyJ", whose need is the text a JWT match starts with.
    pub fn jwt_start() -> &'static Regex {
        static EYJ: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        EYJ.get_or_init(|| Regex::compile("eyJ", 0).expect("eyJ compiles"))
    }

    /// The matches at or after `pos`, leftmost-first, one at a time (core's `_spans`, lazily): each part's
    /// search is kept until the matches pass it, so reading them all is one pass over the text.
    pub fn iter<'a>(&'a self, s: &'a [u32], pos: usize) -> Tokens<'a> {
        Tokens { t: self, s, pos, other: None, jwt: None, fresh_other: false, fresh_jwt: false, done: false }
    }

    /// Every match at or after `pos`, leftmost-first, as core's `_spans`.
    pub fn spans(&self, s: &[u32], pos: usize) -> Vec<(usize, usize)> {
        self.iter(s, pos).collect()
    }

    /// The first match at or after `pos`.
    pub fn search(&self, s: &[u32], pos: usize) -> Option<(usize, usize)> {
        self.iter(s, pos).next()
    }

    /// re.sub with a literal replacement.
    pub fn sub(&self, repl: &[u32], s: &[u32]) -> Vec<u32> {
        let spans = self.spans(s, 0);
        if spans.is_empty() {
            return s.to_vec();
        }
        let mut out = Vec::with_capacity(s.len());
        let mut pos = 0;
        for (a, b) in spans {
            out.extend_from_slice(&s[pos..a]);
            out.extend_from_slice(repl);
            pos = b;
        }
        out.extend_from_slice(&s[pos..]);
        out
    }
}

/// TokenPattern::iter's matches.
pub struct Tokens<'a> {
    t: &'a TokenPattern,
    s: &'a [u32],
    pos: usize,
    other: Option<(usize, usize)>,
    jwt: Option<(usize, usize)>,
    fresh_other: bool,
    fresh_jwt: bool,
    done: bool,
}

impl Iterator for Tokens<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.done {
            return None;
        }
        let (s, pos) = (self.s, self.pos);
        if !self.fresh_other || matches!(self.other, Some((a, _)) if a < pos) {
            self.other = self.t.others.search_at(s, pos as isize, s.len() as isize).map(|m| (m.start(), m.end()));
            self.fresh_other = true;
        }
        if !self.fresh_jwt || matches!(self.jwt, Some((a, _)) if a < pos) {
            self.jwt = jwt_search(s, pos);
            self.fresh_jwt = true;
        }
        let best = match (self.other, self.jwt) {
            (None, None) => {
                self.done = true;
                return None;
            }
            (Some(o), None) => o,
            (None, Some(j)) => j,
            (Some(o), Some(j)) => {
                if o.0 < j.0 {
                    o
                } else {
                    j
                }
            }
        };
        self.pos = best.1; // (matches are never empty)
        // one more round could still find nothing: every part needs a character
        self.done = self.pos >= s.len();
        Some(best)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystr::u;

    fn pattern() -> TokenPattern {
        let p = crate::pack::current();
        TokenPattern::from_value(p.raw("_TOKEN_PATTERN").unwrap()).unwrap()
    }

    #[test]
    fn a_jwt_and_the_other_formats() {
        let t = pattern();
        // fake credentials in pieces: a whole one would trip secret scanners
        let jwt = u(concat!("x = 'eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig'"));
        assert_eq!(t.search(&jwt, 0), Some((5, 53)));
        let aws = u(concat!("key AKIA", "ABCDEFGHIJKLMNOP end"));
        assert_eq!(t.search(&aws, 0), Some((4, 24)));
        assert_eq!(t.search(&u("nothing here"), 0), None);
    }

    #[test]
    fn a_run_of_eyj_is_linear() {
        let t = pattern();
        let mut s = u("//");
        for _ in 0..60_000 {
            s.extend(u("eyJ"));
        }
        assert_eq!(t.search(&s, 0), None);
        s.extend(u(".eyJabcdefghijk"));
        assert_eq!(t.search(&s, 0), Some((2, s.len())));
    }

    #[test]
    fn the_matches_one_at_a_time_in_one_walk() {
        let t = pattern();
        // fake credentials in pieces, as above
        let s = u(concat!("a AKIA", "ABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY----- x eyJhbGciOiJIUzI1NiJ9.",
                          "eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig end"));
        let texts: Vec<String> = t.iter(&s, 0).map(|(a, b)| crate::pystr::to_string(&s[a..b])).collect();
        assert_eq!(texts, [concat!("AKIA", "ABCDEFGHIJKLMNOP"), "-----BEGIN PRIVATE KEY-----",
                           concat!("eyJhbGciOiJIUzI1NiJ9.", "eyJzdWIiOiIxMjM0NTY3ODkwIn0")]);
        assert_eq!(t.iter(&s, 0).collect::<Vec<_>>(), t.spans(&s, 0));
        assert_eq!(t.iter(&s, 3).next(), t.search(&s, 3));
        // 60,000 headers: each match is read on from the one before (S-TOKEN-PEM's walk past headers without their
        // keys), not by searching the rest of the line again (over 45 seconds)
        let mut many = Vec::new();
        for _ in 0..60_000 {
            many.extend(u("\"-----BEGIN PRIVATE KEY-----\")x("));
        }
        let start = std::time::Instant::now();
        assert_eq!(t.iter(&many, 0).count(), 60_000);
        assert!(start.elapsed().as_secs() < 10, "{:?}", start.elapsed());
    }
}
