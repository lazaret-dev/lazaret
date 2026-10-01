//! Rule patterns that `re` (and so pyre) runs in more than linear time on
//! some lines, matched by hand in linear time.
//!
//! Each matcher finds exactly where core's pattern first matches a line (the
//! leftmost start; the end is then the pattern's own match there, one
//! anchored match), and is used only while the pack holds that pattern's
//! text and flags (scanfile::Matcher compares them once per pack): a change
//! of the pattern in core makes the engine slower, never wrong, until the
//! hand code follows. The npm package's JavaScript engine had these as
//! linear-time twins (js/src/scanner/linear.js, through 0.1.8); the
//! differential tests hold them to core (test_rust_parity_project, and the
//! adversarial lines in scanfile_corpus.py).

use crate::pyre::{self, Regex};
use crate::unicode;

/// core's SQL-DYNAMIC pattern (re.I): SQL built by concatenation and run.
pub const SQL_DYNAMIC_TEXT: &str = concat!(
    r#"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+"#,
    r#"|EXECUTE\s+IMMEDIATE\b(?:(?!EXECUTE\s+IMMEDIATE\b)[^;])*\|\|"#,
    r#"|sp_executesql\b(?:(?!sp_executesql\b)[^;])*\+"#,
    r#"|EXEC\s*\(\s*['\"][^']*['\"]\s*\+"#,
    r#"|SET\s+@\w+\s*=(?:(?!SET\s+@)[^;'\"])*['\"](?:(?!SET\s+@)[^;])*(?:\+|\|\|)"#
);
pub const SQL_DYNAMIC_FLAGS: &str = "i";

const fn c(ch: char) -> u32 {
    ch as u32
}

fn rx(src: &str) -> Regex {
    Regex::new(&crate::pystr::u(src), pyre::flags_from_letters("i")).expect("a helper pattern")
}

/// Every start where `re` matches, overlapping ones too, with each match's end.
fn heads(re: &Regex, s: &[u32]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos <= s.len() {
        match re.search_at(s, pos as isize, s.len() as isize) {
            Some(m) => {
                out.push((m.start(), m.end()));
                pos = m.start() + 1;
            }
            None => break,
        }
    }
    out
}

/// The first element of the sorted `a` at or after `x`.
fn at_or_after(a: &[usize], x: usize) -> Option<usize> {
    a.get(a.partition_point(|&v| v < x)).copied()
}

fn where_(s: &[u32], f: impl Fn(usize) -> bool) -> Vec<usize> {
    (0..s.len()).filter(|&i| f(i)).collect()
}

/// SQL-DYNAMIC, alternative by alternative: the first one's head is the
/// whole pattern; a tempered alternative (`(?:(?!HEAD)[^;])*`) ends before
/// the next ';' and the next head of its own kind; the unbounded one
/// (`['\"][^']*['\"]\s*\+`) is read with prefix counts.
pub struct SqlDynamic {
    any: Regex,
    a1: Regex,
    a2: Regex,
    a3: Regex,
    a4: Regex,
    a5: Regex,
    set_at: Regex,
}

impl Default for SqlDynamic {
    fn default() -> Self {
        SqlDynamic::new()
    }
}

impl SqlDynamic {
    pub fn new() -> SqlDynamic {
        SqlDynamic {
            any: rx("exec|sp_executesql|set"),
            a1: rx(r"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+"),
            a2: rx(r"EXECUTE\s+IMMEDIATE\b"),
            a3: rx(r"sp_executesql\b"),
            a4: rx(r#"EXEC\s*\(\s*['"]"#),
            a5: rx(r"SET\s+@\w+\s*="),
            set_at: rx(r"SET\s+@"),
        }
    }

    /// The start of the pattern's first match in `s`.
    pub fn find(&self, s: &[u32]) -> Option<usize> {
        self.any.search(s)?;
        let n = s.len();
        let mut best: Option<usize> = None;
        let mut take = |i: usize| {
            if best.map_or(true, |b| i < b) {
                best = Some(i);
            }
        };
        if let Some(m) = self.a1.search(s) {
            take(m.start());
        }
        let semis = where_(s, |i| s[i] == c(';'));
        let semi_after = |i: usize| at_or_after(&semis, i).unwrap_or(n);
        let pipes = where_(s, |i| s[i] == c('|') && i + 1 < n && s[i + 1] == c('|'));
        let pluses = where_(s, |i| s[i] == c('+'));
        let next_head = |starts: &[usize], e: usize| at_or_after(starts, e).unwrap_or(usize::MAX);
        // EXECUTE IMMEDIATE …||, sp_executesql …+: the first || or + before the next ';' and the next head
        for (re, ends) in [(&self.a2, &pipes), (&self.a3, &pluses)] {
            let hs = heads(re, s);
            let starts: Vec<usize> = hs.iter().map(|h| h.0).collect();
            for &(h, e) in &hs {
                if let Some(p) = at_or_after(ends, e) {
                    if p < semi_after(e) && p < next_head(&starts, e) {
                        take(h);
                        break;
                    }
                }
            }
        }
        // EXEC ( '…' + : a quote then \s*\+ before the first single quote after the opening one
        let a4 = heads(&self.a4, s);
        if !a4.is_empty() {
            let mut plus_from = vec![false; n + 1]; // s[i:] matches \s*\+
            for i in (0..n).rev() {
                plus_from[i] = s[i] == c('+') || (unicode::is_space(s[i]) && plus_from[i + 1]);
            }
            let mut good_dq = vec![0u32; n + 1]; // `"` followed by \s*\+, counted before each index
            for i in 0..n {
                good_dq[i + 1] = good_dq[i] + u32::from(s[i] == c('"') && plus_from[i + 1]);
            }
            let sq = where_(s, |i| s[i] == c('\''));
            for &(h, e) in &a4 {
                let q0 = e - 1; // the opening quote
                let nsq = at_or_after(&sq, q0 + 1).unwrap_or(n);
                if good_dq[nsq] > good_dq[q0 + 1] || (nsq < n && plus_from[nsq + 1]) {
                    take(h);
                    break;
                }
            }
        }
        // SET @v = …'…+: the first quote before the next ';' and the next SET @, then + or || before both
        let a5 = heads(&self.a5, s);
        if !a5.is_empty() {
            let quotes = where_(s, |i| s[i] == c('\'') || s[i] == c('"'));
            let sets: Vec<usize> = self.set_at.finditer(s).map(|m| m.start()).collect();
            let set_after = |i: usize| at_or_after(&sets, i).unwrap_or(usize::MAX);
            for &(h, e) in &a5 {
                let semi = semi_after(e);
                let q = match at_or_after(&quotes, e) {
                    Some(q) if q < semi && set_after(e) >= q => q,
                    _ => continue,
                };
                let limit = semi.min(set_after(q + 1));
                let plus = at_or_after(&pluses, q + 1).map_or(false, |p| p < limit);
                let pipe = at_or_after(&pipes, q + 1).map_or(false, |p| p < limit);
                if plus || pipe {
                    take(h);
                    break;
                }
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystr::u;

    #[test]
    fn sql_dynamic_agrees_with_the_pattern() {
        let re = Regex::new(&u(SQL_DYNAMIC_TEXT), pyre::flags_from_letters(SQL_DYNAMIC_FLAGS)).unwrap();
        let hand = SqlDynamic::new();
        let pieces = [
            "EXEC", "EXECUTE", "exec", "ſet", "SET", " ", "\t", "(", ")", "@", "x", "+", "|", "||", ";", "'", "\"",
            "IMMEDIATE", " IMMEDIATE ", "sp_executesql", "@v", " = ", "\u{2028}", "\u{a0}",
        ];
        let mut seed: u64 = 20261001;
        let mut next = |n: usize| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((seed >> 33) as usize) % n
        };
        let mut found = 0;
        for _ in 0..60000 {
            let k = 1 + next(14);
            let text: String = (0..k).map(|_| pieces[next(pieces.len())]).collect();
            let s = u(&text);
            let want = re.search(&s).map(|m| m.start());
            assert_eq!(hand.find(&s), want, "{:?}", text);
            found += usize::from(want.is_some());
        }
        assert!(found > 1500, "{} matches", found);
    }

    #[test]
    fn sql_dynamic_is_linear() {
        let hand = SqlDynamic::new();
        let s = u(&"EXEC(\"".repeat(200_000));
        let t = std::time::Instant::now();
        assert_eq!(hand.find(&s), None);
        assert!(t.elapsed().as_secs_f64() < 2.0);
    }
}
