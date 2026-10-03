//! Finding characters fast: the scans a search runs before it matches (a
//! literal prefix, the strings a match must hold or start with: literal.rs).
//! A scan looks for the character of a string that is rarest in source text
//! (a static guess: the choice changes only how fast, never what is found),
//! sixteen characters at a time, and checks the string only where it finds
//! one.

/// How common an ASCII character is in source code (a guess; higher is more
/// common). Characters outside ASCII are never anchors.
fn freq(c: u32) -> u32 {
    match c {
        0x20 => 100,
        0x65 => 60,                                                         // e
        0x74 => 50,                                                         // t
        0x61 | 0x69 | 0x6E | 0x6F | 0x72 | 0x73 => 45,                      // a i n o r s
        0x6C => 35,                                                         // l
        0x63 => 30,                                                         // c
        0x0A | 0x28 | 0x29 | 0x2E | 0x64 | 0x75 => 25,                      // \n ( ) . d u
        0x2C | 0x3D | 0x68 | 0x6D | 0x70 => 20,                             // , = h m p
        0x66 => 18,                                                         // f
        0x27 | 0x3B | 0x5F | 0x67 => 15,                                    // ' ; _ g
        0x62 | 0x79 => 12,                                                  // b y
        0x09 | 0x22 | 0x3A | 0x76 | 0x77 => 10,                             // \t " : v w
        0x2F | 0x7B | 0x7D => 8,                                            // / { }
        0x2D | 0x30 | 0x5B | 0x5D | 0x6B => 6,                              // - 0 [ ] k
        0x2A | 0x31 | 0x3E | 0x78 => 5,                                     // * 1 > x
        0x41 | 0x43 | 0x44 | 0x45 | 0x49 | 0x4C | 0x4E | 0x4F | 0x50 | 0x52 | 0x53 | 0x54 => 5,
        0x2B => 4,                                                          // +
        0x0D | 0x21 | 0x24 | 0x3C | 0x6A | 0x32..=0x39 => 3,                // \r ! $ < j 2-9
        0x42 | 0x46 | 0x47 | 0x48 | 0x4B | 0x4D | 0x55 | 0x56 | 0x57 | 0x59 => 3,
        0x23 | 0x26 | 0x3F | 0x5C | 0x60 | 0x7C | 0x71 | 0x7A => 2,         // # & ? \ ` | q z
        _ => 1,
    }
}

/// The cost of scanning for any of the ASCII characters in `mask`.
pub fn mask_cost(mask: u128) -> u32 {
    let mut cost = 0;
    let mut m = mask;
    while m != 0 {
        cost += freq(m.trailing_zeros());
        m &= m - 1;
    }
    cost
}

const W: usize = 16;

/// What a scan looks for: one to three characters, or any of a set of ASCII
/// characters.
#[derive(Clone, Debug)]
pub enum Chars {
    One(u32),
    Two(u32, u32),
    Three(u32, u32, u32),
    Mask(Box<[bool; 128]>),
}

impl Chars {
    /// For the ASCII characters of `mask` (not empty).
    pub fn of_mask(mask: u128) -> Chars {
        let mut list = Vec::new();
        let mut m = mask;
        while m != 0 {
            list.push(m.trailing_zeros());
            m &= m - 1;
        }
        match list[..] {
            [a] => Chars::One(a),
            [a, b] => Chars::Two(a, b),
            [a, b, c] => Chars::Three(a, b, c),
            _ => {
                let mut t = Box::new([false; 128]);
                for c in list {
                    t[c as usize] = true;
                }
                Chars::Mask(t)
            }
        }
    }

    #[cfg(test)]
    fn has(&self, c: u32) -> bool {
        match self {
            Chars::One(a) => c == *a,
            Chars::Two(a, b) => c == *a || c == *b,
            Chars::Three(a, b, d) => c == *a || c == *b || c == *d,
            Chars::Mask(t) => c < 128 && t[c as usize],
        }
    }

    /// The first i in [from, to) where s[i] is one of the characters.
    #[inline]
    pub fn find(&self, s: &[u32], from: usize, to: usize) -> Option<usize> {
        let to = to.min(s.len());
        if from >= to {
            return None;
        }
        match self {
            Chars::One(a) => find_by(s, from, to, |c| c == *a),
            Chars::Two(a, b) => find_by(s, from, to, |c| (c == *a) | (c == *b)),
            Chars::Three(a, b, d) => find_by(s, from, to, |c| (c == *a) | (c == *b) | (c == *d)),
            Chars::Mask(t) => find_by(s, from, to, |c| (c < 128) & t[(c & 127) as usize]),
        }
    }
}

#[inline(always)]
fn find_by(s: &[u32], from: usize, to: usize, hit: impl Fn(u32) -> bool) -> Option<usize> {
    let mut i = from;
    while i + W <= to {
        let chunk: &[u32; W] = s[i..i + W].try_into().expect("a chunk of W");
        let mut any = false;
        for &c in chunk {
            any |= hit(c);
        }
        if any {
            return chunk.iter().position(|&c| hit(c)).map(|k| i + k);
        }
        i += W;
    }
    s[i..to].iter().position(|&c| hit(c)).map(|k| i + k)
}

/// The first i in [from, to) where s[i] == c.
#[inline]
pub fn find1(s: &[u32], from: usize, to: usize, c: u32) -> Option<usize> {
    let to = to.min(s.len());
    if from >= to {
        return None;
    }
    find_by(s, from, to, |x| x == c)
}

/// The position of the rarest character of an ASCII string (for a scan).
pub fn rarest(lit: &[u8]) -> usize {
    let mut best = (u32::MAX, 0usize);
    for (k, &c) in lit.iter().enumerate() {
        let f = freq(c as u32);
        if f < best.0 {
            best = (f, k);
        }
    }
    best.1
}

/// A literal string's fastest scan: the position of its rarest character.
#[derive(Clone, Debug)]
pub struct Literal {
    at: usize,
    c: u32,
}

impl Literal {
    pub fn new(lit: &[u32]) -> Literal {
        let mut best = (u32::MAX, 0usize);
        for (k, &c) in lit.iter().enumerate() {
            let f = if c < 128 { freq(c) } else { 0 };
            if f < best.0 {
                best = (f, k);
            }
        }
        Literal { at: best.1, c: lit.get(best.1).copied().unwrap_or(0) }
    }

    /// The first i in [from, to - lit.len()] where `lit` occurs in s (whole
    /// before `to`).
    pub fn find(&self, s: &[u32], lit: &[u32], from: usize, to: usize) -> Option<usize> {
        let to = to.min(s.len());
        if lit.is_empty() {
            return if from <= to { Some(from) } else { None };
        }
        if to < lit.len() || from > to - lit.len() {
            return None;
        }
        let stop = to - lit.len() + self.at + 1; // (exclusive bound of the anchor's position)
        let mut p = from + self.at;
        while p < stop {
            let q = find_by(s, p, stop, |c| c == self.c)?;
            let i = q - self.at;
            if s[i..i + lit.len()] == *lit {
                return Some(i);
            }
            p = q + 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(s: &str) -> Vec<u32> {
        s.chars().map(|c| c as u32).collect()
    }

    #[test]
    fn finds_what_a_plain_scan_finds() {
        let text = cps(&format!("{}export xx exp export{}", "a".repeat(37), "é".repeat(20)));
        for (from, to) in [(0, text.len()), (38, text.len()), (0, 40), (41, 60), (70, 72)] {
            for chars in [Chars::of_mask(1 << b'x'), Chars::of_mask((1 << b'x') | (1 << b'p')),
                          Chars::of_mask((1 << b'x') | (1 << b'p') | (1 << b'q')),
                          Chars::of_mask((1 << b'x') | (1 << b'p') | (1 << b'q') | (1 << b'z'))] {
                let want = (from..to.min(text.len())).find(|&i| chars.has(text[i]));
                assert_eq!(chars.find(&text, from, to), want, "{:?} {}..{}", chars, from, to);
            }
            for lit in ["export", "xx", "exp", "é", "aex", "export xx exp export"] {
                let lit = cps(lit);
                let want = (from..=to.min(text.len()).saturating_sub(lit.len()))
                    .find(|&i| i + lit.len() <= to && text[i..i + lit.len()] == lit[..]);
                assert_eq!(Literal::new(&lit).find(&text, &lit, from, to), want, "{:?} {}..{}", lit, from, to);
            }
        }
    }
}
