//! What the parser reads of Unicode 15.1 (Python 3.13's version): which
//! characters an identifier may hold, NFKC (identifiers are normalized), and
//! the character names of `\N{...}` escapes. The data is `unidata.rs`
//! (scripts/make_pyparse_tables.py); NFKC reads the engine's Unicode 13.0
//! tables (crate::normalize) for every character Unicode 13.0 assigns —
//! the answer is the same in 15.1, by Unicode's normalization stability
//! policy — and `unidata.rs` for the characters assigned since.

use super::unidata as t;

fn in_runs(runs: &[(u32, u32)], c: u32) -> bool {
    let i = runs.partition_point(|&(a, _)| a <= c);
    i > 0 && c <= runs[i - 1].1
}

/// May `c` start an identifier (`_` and the letters; str.isidentifier())?
pub fn id_start(c: u32) -> bool {
    if c < 0x80 {
        return c == 0x5F || (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c);
    }
    in_runs(t::ID_START, c)
}

/// May `c` go on with an identifier?
pub fn id_continue(c: u32) -> bool {
    if c < 0x80 {
        return c == 0x5F || (0x30..=0x39).contains(&c) || (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c);
    }
    in_runs(t::ID_CONTINUE, c)
}

// ---- NFKC ----

fn new_char(c: u32) -> bool {
    c >= 0x80 && !crate::unicode::assigned(c)
}

fn ccc(c: u32) -> u8 {
    if new_char(c) {
        match t::NEW_CCC.binary_search_by_key(&c, |&(x, _)| x) {
            Ok(i) => t::NEW_CCC[i].1,
            Err(_) => 0,
        }
    } else {
        crate::normalize::ccc(c)
    }
}

fn decomposition(c: u32) -> Option<(bool, &'static [u32])> {
    if new_char(c) {
        match t::NEW_DECOMP.binary_search_by_key(&c, |&(x, _, _)| x) {
            Ok(i) => Some((t::NEW_DECOMP[i].1, t::NEW_DECOMP[i].2)),
            Err(_) => None,
        }
    } else {
        crate::normalize::decomposition(c)
    }
}

fn compose_pair(a: u32, b: u32) -> Option<u32> {
    if let Some(c) = crate::normalize::compose_pair(a, b) {
        return Some(c);
    }
    match t::NEW_COMPOSE.binary_search_by_key(&(a, b), |&(x, y, _)| (x, y)) {
        Ok(i) => Some(t::NEW_COMPOSE[i].2),
        Err(_) => None,
    }
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const N_COUNT: u32 = V_COUNT * T_COUNT;
const S_COUNT: u32 = 19 * N_COUNT;

/// The full compatibility decomposition of `c`, appended to `out`
/// (iteratively: a mapping's characters are decomposed in turn).
fn decompose_into(c: u32, out: &mut Vec<u32>) {
    let mut stack = vec![c];
    while let Some(c) = stack.pop() {
        if (S_BASE..S_BASE + S_COUNT).contains(&c) {
            let s = c - S_BASE;
            out.push(L_BASE + s / N_COUNT);
            out.push(V_BASE + (s % N_COUNT) / T_COUNT);
            if s % T_COUNT != 0 {
                out.push(T_BASE + s % T_COUNT);
            }
            continue;
        }
        match decomposition(c) {
            Some((_, parts)) if c >= 0xA0 => {
                for &p in parts.iter().rev() {
                    stack.push(p);
                }
            }
            _ => out.push(c),
        }
    }
}

/// unicodedata.normalize("NFKC", s) as Python 3.13 gives it (Unicode 15.1).
pub fn nfkc(s: &[u32]) -> Vec<u32> {
    if s.iter().all(|&c| c < 0x80) {
        return s.to_vec();
    }
    // decompose, then put each run of non-starters in canonical order
    let mut d: Vec<u32> = Vec::with_capacity(s.len() + 8);
    for &c in s {
        decompose_into(c, &mut d);
    }
    let mut i = 0;
    while i < d.len() {
        if ccc(d[i]) == 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < d.len() && ccc(d[i]) != 0 {
            i += 1;
        }
        if i - start > 1 {
            d[start..i].sort_by_key(|&c| ccc(c)); // (stable)
        }
    }
    // canonical composition
    let mut out: Vec<u32> = Vec::with_capacity(d.len());
    let mut starter: Option<usize> = None;
    let mut last: Option<u8> = None;
    for c in d {
        let k = ccc(c);
        if let Some(at) = starter {
            let blocked = match last {
                None => false,
                Some(b) => b == 0 || b >= k,
            };
            if !blocked {
                let a = out[at];
                let composite = if (L_BASE..L_BASE + 19).contains(&a) && (V_BASE..V_BASE + V_COUNT).contains(&c) {
                    Some(S_BASE + ((a - L_BASE) * V_COUNT + (c - V_BASE)) * T_COUNT)
                } else if (S_BASE..S_BASE + S_COUNT).contains(&a)
                    && (a - S_BASE) % T_COUNT == 0
                    && c > T_BASE
                    && c < T_BASE + T_COUNT
                {
                    Some(a + (c - T_BASE))
                } else {
                    compose_pair(a, c)
                };
                if let Some(p) = composite {
                    out[at] = p;
                    continue;
                }
            }
        }
        if k == 0 {
            starter = Some(out.len());
            last = None;
        } else {
            last = Some(k);
        }
        out.push(c);
    }
    out
}

// ---- character names ----

/// The name of entry `at` of `NAMES` (a byte offset) written over `buf`,
/// which holds the entry before it; the offset of the entry after it.
fn decode_entry(at: usize, buf: &mut Vec<u8>) -> usize {
    let data = t::NAMES;
    let keep = data.get(at).copied().unwrap_or(0) as usize;
    buf.truncate(keep);
    let mut i = at + 1;
    while let Some(&b) = data.get(i) {
        match b {
            0 => return i + 1,
            0x80..=0xFF => {
                buf.extend_from_slice(t::NAME_WORDS.get((b - 0x80) as usize).map(|w| w.as_bytes()).unwrap_or(b""));
                i += 1;
            }
            0x01..=0x1F => {
                let next = data.get(i + 1).copied().unwrap_or(0) as usize;
                let w = 128 + (b as usize - 1) * 256 + next;
                buf.extend_from_slice(t::NAME_WORDS.get(w).map(|w| w.as_bytes()).unwrap_or(b""));
                i += 2;
            }
            _ => {
                buf.push(b);
                i += 1;
            }
        }
    }
    i
}

fn code_of(entry: usize) -> u32 {
    let c = t::NAME_CODES;
    match c.get(3 * entry..3 * entry + 3) {
        Some(b) => b[0] as u32 | (b[1] as u32) << 8 | (b[2] as u32) << 16,
        None => 0,
    }
}

/// The code point a name made by rule names: a Hangul syllable, or a prefix
/// and the code point in hexadecimal.
fn by_rule(name: &[u8]) -> Option<u32> {
    if let Some(rest) = name.strip_prefix(b"HANGUL SYLLABLE ") {
        let longest = |table: &[&str], s: &[u8]| -> Option<usize> {
            let mut best: Option<usize> = None;
            for (i, j) in table.iter().enumerate() {
                if s.starts_with(j.as_bytes()) && best.map_or(true, |b| j.len() > table[b].len()) {
                    best = Some(i);
                }
            }
            best
        };
        let l = longest(t::JAMO_L, rest)?;
        let rest = &rest[t::JAMO_L[l].len()..];
        let v = longest(t::JAMO_V, rest)?;
        let rest = &rest[t::JAMO_V[v].len()..];
        let tt = t::JAMO_T.iter().position(|j| j.as_bytes() == rest)?;
        return Some(S_BASE + (l as u32 * V_COUNT + v as u32) * T_COUNT + tt as u32);
    }
    for &(prefix, runs) in t::RULE_NAMES {
        if let Some(hex) = name.strip_prefix(prefix.as_bytes()) {
            if hex.len() < 4 || hex.len() > 5 {
                return None;
            }
            let mut v: u32 = 0;
            for &h in hex {
                let d = match h {
                    b'0'..=b'9' => h - b'0',
                    b'A'..=b'F' => h - b'A' + 10,
                    _ => return None,
                };
                v = v * 16 + d as u32;
            }
            // the code point's own spelling only (no leading zero past four digits)
            if hex.len() == 5 && hex[0] == b'0' {
                return None;
            }
            return if in_runs(runs, v) { Some(v) } else { None };
        }
    }
    None
}

/// The code point of a character name, as unicodedata.lookup() reads it in
/// a `\N{...}` escape (any case; aliases too; not named sequences), else
/// None.
pub fn lookup_name(name: &[u32]) -> Option<u32> {
    if name.is_empty() || name.len() > 128 {
        return None;
    }
    let mut q: Vec<u8> = Vec::with_capacity(name.len());
    for &c in name {
        if c >= 0x80 {
            return None;
        }
        let b = c as u8;
        q.push(b.to_ascii_uppercase());
    }
    if let Some(c) = by_rule(&q) {
        return Some(c);
    }
    // the last block whose first entry is not after q
    let blocks = t::NAME_BLOCKS;
    let mut buf: Vec<u8> = Vec::with_capacity(96);
    let (mut lo, mut hi) = (0usize, blocks.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        buf.clear();
        decode_entry(blocks[mid] as usize, &mut buf);
        if buf.as_slice() <= q.as_slice() {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let block = lo - 1;
    let mut at = blocks[block] as usize;
    let total = t::NAME_CODES.len() / 3;
    buf.clear();
    for k in 0..t::NAME_BLOCK {
        let entry = block * t::NAME_BLOCK + k;
        if entry >= total {
            break;
        }
        at = decode_entry(at, &mut buf);
        if buf == q {
            return Some(code_of(entry));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn names() {
        assert_eq!(lookup_name(&cps("LATIN SMALL LETTER A")), Some(0x61));
        assert_eq!(lookup_name(&cps("latin small letter a")), Some(0x61));
        assert_eq!(lookup_name(&cps("BOM")), Some(0xFEFF));
        assert_eq!(lookup_name(&cps("byte order mark")), Some(0xFEFF));
        assert_eq!(lookup_name(&cps("EM DASH")), Some(0x2014));
        assert_eq!(lookup_name(&cps("DEGREE SIGN")), Some(0xB0));
        assert_eq!(lookup_name(&cps("SNOWMAN")), Some(0x2603));
        assert_eq!(lookup_name(&cps("VS17")), Some(0xE0100));
        assert_eq!(lookup_name(&cps("NULL")), Some(0));
        assert_eq!(lookup_name(&cps("LATIN SMALL LETTER  A")), None);
        assert_eq!(lookup_name(&cps("LATIN CAPITAL LETTER A WITH MACRON AND GRAVE")), None);
        assert_eq!(lookup_name(&cps("")), None);
        assert_eq!(lookup_name(&cps("A")), None);
        assert_eq!(lookup_name(&cps("ZZZZ")), None);
        assert_eq!(lookup_name(&cps("HANGUL SYLLABLE GA")), Some(0xAC00));
        assert_eq!(lookup_name(&cps("hangul syllable gagS")), Some(0xAC03));
        assert_eq!(lookup_name(&cps("HANGUL SYLLABLE A")), Some(0xC544));
        assert_eq!(lookup_name(&cps("HANGUL SYLLABLE ")), None);
        assert_eq!(lookup_name(&cps("CJK UNIFIED IDEOGRAPH-4E00")), Some(0x4E00));
        assert_eq!(lookup_name(&cps("cjk unified ideograph-4e00")), Some(0x4E00));
        assert_eq!(lookup_name(&cps("CJK UNIFIED IDEOGRAPH-04E00")), None);
        assert_eq!(lookup_name(&cps("CJK UNIFIED IDEOGRAPH-2EE5D")), Some(0x2EE5D));
        assert_eq!(lookup_name(&cps("CJK UNIFIED IDEOGRAPH-2EE5E")), None);
        assert_eq!(lookup_name(&cps("TANGUT IDEOGRAPH-17000")), Some(0x17000));
        assert_eq!(lookup_name(&cps("CJK COMPATIBILITY IDEOGRAPH-F900")), Some(0xF900));
        assert_eq!(lookup_name(&cps("LATIN SMALL LETTER \u{e9}")), None);
    }

    #[test]
    fn identifiers() {
        assert!(id_start('_' as u32) && id_start('a' as u32) && !id_start('1' as u32));
        assert!(id_start(0xE9) && id_continue(0xB7) && !id_start(0xB7) && !id_start(0x20AC));
        assert_eq!(nfkc(&cps("\u{FB01}x")), cps("fix"));
        assert_eq!(nfkc(&cps("\u{2115}")), cps("N"));
        assert_eq!(nfkc(&cps("e\u{301}")), cps("\u{e9}"));
        assert_eq!(nfkc(&cps("\u{FF49}\u{FF46}")), cps("if"));
        // a character added after Unicode 13.0: MODIFIER LETTER SMALL AE (14.0) is <super> U+00E6
        assert_eq!(nfkc(&[0x10783]), vec![0xE6]);
    }
}
