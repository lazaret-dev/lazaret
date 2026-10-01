//! Text a match must hold: an optimization sre does not have.
//!
//! Most of the scanner's patterns look for words (`pastebin.com`, `ngrok`,
//! `gethostname(`) most texts do not hold. From the compiled program this
//! reads a set of literal strings, one of which lies inside every match —
//! the longest runs of single-character operations that every match must
//! pass through, in sequence — and a search of a text holding none of them
//! stops before matching at all. It changes no answer: a text without any
//! of the strings has no match.
//!
//! A run is built only from operations that consume one character and
//! accept few: LITERAL and its IGNORE forms, and a set of at most a few
//! literals (how re compiles `i` or `s` under IGNORECASE: [i ı], [s ſ]).
//! Zero-width operations (group marks, \b, lookarounds) do not break a run,
//! as they consume nothing. What lies inside a lookaround is not used: it
//! can lie outside the match (a lookbehind, before `pos`).

use super::constants::*;
use crate::unicode;

const MAX_DEPTH: usize = 32;
/// A set operation with more literals than this ends a run.
const MAX_CLASS: usize = 4;
/// A requirement of more strings than this is not used.
const MAX_STRINGS: usize = 64;
/// Nor one whose shortest string is shorter than this.
const MIN_LEN: usize = 2;

/// How a text character is compared with an operation's characters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fold {
    None,
    Ascii,   // LITERAL_IGNORE, IN_IGNORE: the ASCII lower case
    Unicode, // LITERAL_UNI_IGNORE, IN_UNI_IGNORE: sre's lower()
}

/// One position of a string: the characters it accepts, after folding.
#[derive(Clone, Debug)]
struct Unit {
    fold: Fold,
    chars: Vec<u32>,
    /// which ASCII characters it accepts
    ascii: u128,
}

impl Unit {
    fn new(fold: Fold, chars: Vec<u32>) -> Unit {
        let mut u = Unit { fold, chars, ascii: 0 };
        for c in 0..128u32 {
            if u.accepts_slow(c) {
                u.ascii |= 1u128 << c;
            }
        }
        u
    }

    fn accepts_slow(&self, c: u32) -> bool {
        let c = match self.fold {
            Fold::None => c,
            Fold::Ascii => {
                if (0x41..=0x5A).contains(&c) {
                    c + 32
                } else {
                    c
                }
            }
            Fold::Unicode => unicode::sre_lower(c),
        };
        self.chars.contains(&c)
    }

    #[inline]
    fn accepts(&self, c: u32) -> bool {
        if c < 128 {
            self.ascii & (1u128 << c) != 0
        } else {
            self.accepts_slow(c)
        }
    }
}

type Str = Vec<Unit>;

/// One of these strings occurs inside every match.
pub struct Need {
    strings: Vec<Str>,
    /// for each string, the ASCII mask of each position (None: it may take
    /// a character outside ASCII), for a text gate (textgate.rs)
    masks: Vec<Vec<Option<u128>>>,
    shortest: usize,
    /// for each ASCII character, the strings that can start with it
    by_first: Vec<Vec<u16>>,
    /// the ASCII characters a string can start with
    first_ascii: u128,
    /// can a string start with a character outside ASCII?
    first_other: bool,
    /// for each ASCII character, the ASCII characters that can follow it at
    /// the start of a string (all of them after the first of a string of
    /// one character, or of one whose second position can take a character
    /// outside ASCII): most positions are passed on these two characters
    second: Vec<u128>,
}

/// The ASCII-only masks of a unit (None: it can take a character outside
/// ASCII).
fn ascii_only(u: &Unit) -> Option<u128> {
    if u.fold == Fold::Unicode || u.chars.iter().any(|&c| c >= 128) {
        None
    } else {
        Some(u.ascii)
    }
}

fn masks_of(strings: &[Str]) -> Vec<Vec<Option<u128>>> {
    strings.iter().map(|st| st.iter().map(ascii_only).collect()).collect()
}

impl Need {
    fn build(strings: Vec<Str>) -> Option<Need> {
        let shortest = strings.iter().map(|s| s.len()).min()?;
        let mut by_first = vec![Vec::new(); 128];
        for (k, st) in strings.iter().enumerate() {
            for (c, list) in by_first.iter_mut().enumerate() {
                if st[0].accepts(c as u32) {
                    list.push(k as u16);
                }
            }
        }
        let first_ascii = by_first.iter().enumerate().fold(0u128, |m, (c, l)| if l.is_empty() { m } else { m | (1u128 << c) });
        // outside ASCII a unit accepts its own characters, and under Unicode
        // folding whatever sre's lower() maps onto them (K, the Kelvin sign, onto k)
        let first_other = strings.iter().any(|st| st[0].fold == Fold::Unicode || st[0].chars.iter().any(|&c| c >= 128));
        let masks = masks_of(&strings);
        let mut second = vec![0u128; 128];
        for st in &strings {
            let follow = match st.get(1) {
                Some(u) => ascii_only(u).unwrap_or(u128::MAX),
                None => u128::MAX,
            };
            for (c, slot) in second.iter_mut().enumerate() {
                if st[0].accepts(c as u32) {
                    *slot |= follow;
                }
            }
        }
        Some(Need { strings, masks, shortest, by_first, first_ascii, first_other, second })
    }

    /// Does the open gate of the text `s` is part of say none of the strings
    /// occurs in it (each has a pair of characters the text lacks)?
    #[inline]
    fn gated_out(&self, s: &[u32], start: usize, end: usize) -> bool {
        end >= start + crate::textgate::MIN_RANGE
            && crate::textgate::ask(s, |p| self.masks.iter().all(|m| !p.may_hold_masks(m))).unwrap_or(false)
    }

    /// The strings, for a person (`|` between them, `[..]` for a position
    /// that takes several characters, `~` before a folded one).
    pub fn describe(&self) -> String {
        let unit = |u: &Unit| {
            let f = if u.fold == Fold::None { "" } else { "~" };
            if u.chars.len() == 1 {
                format!("{}{}", f, char::from_u32(u.chars[0]).unwrap_or('?'))
            } else {
                format!("{}[{}]", f, u.chars.iter().map(|&c| char::from_u32(c).unwrap_or('?')).collect::<String>())
            }
        };
        self.strings.iter().map(|s| s.iter().map(unit).collect::<String>()).collect::<Vec<_>>().join(" | ")
    }

    #[inline]
    fn at(st: &Str, s: &[u32], i: usize, end: usize) -> bool {
        if i + st.len() > end {
            return false;
        }
        let text = &s[i..i + st.len()];
        for k in 0..st.len() {
            if !st[k].accepts(text[k]) {
                return false;
            }
        }
        true
    }

    /// May a string start at s[i] (= c, ASCII), going by the character after
    /// it? (No character after it within `end`, or one outside ASCII: maybe.)
    #[inline]
    fn second_ok(&self, c: u32, s: &[u32], i: usize, end: usize) -> bool {
        match s.get(i + 1) {
            Some(&d) if i + 1 < end && d < 128 => self.second[c as usize] & (1u128 << d) != 0,
            _ => true,
        }
    }

    /// Are these the same strings as `other`'s?
    pub fn same_strings(&self, other: &Need) -> bool {
        self.describe() == other.describe()
    }

    /// The ASCII characters a string can start with.
    pub fn first_ascii(&self) -> u128 {
        self.first_ascii
    }

    /// Can a string start with a character outside ASCII?
    pub fn first_other(&self) -> bool {
        self.first_other
    }

    /// Does one of the strings start at s[i] and end by `end`?
    #[inline]
    pub fn starts_at(&self, s: &[u32], i: usize, end: usize) -> bool {
        let c = s[i];
        if c < 128 {
            self.first_ascii & (1u128 << c) != 0
                && self.second_ok(c, s, i, end)
                && self.by_first[c as usize].iter().any(|&k| Self::at(&self.strings[k as usize], s, i, end))
        } else {
            self.first_other && self.strings.iter().any(|st| Self::at(st, s, i, end))
        }
    }

    /// The first i >= start where one of the strings starts and ends by
    /// `end`, if any.
    pub fn next_start(&self, s: &[u32], start: usize, end: usize) -> Option<usize> {
        if end < start || end - start < self.shortest || self.gated_out(s, start, end) {
            return None;
        }
        let last = end - self.shortest;
        let mut i = start;
        while i <= last {
            let c = s[i];
            if c < 128 {
                if self.first_ascii & (1u128 << c) != 0
                    && self.second_ok(c, s, i, end)
                    && self.by_first[c as usize].iter().any(|&k| Self::at(&self.strings[k as usize], s, i, end))
                {
                    return Some(i);
                }
            } else if self.first_other && self.strings.iter().any(|st| Self::at(st, s, i, end)) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Does one of the strings occur in s[start..end]?
    pub fn occurs(&self, s: &[u32], start: usize, end: usize) -> bool {
        if end < start || end - start < self.shortest || self.gated_out(s, start, end) {
            return false;
        }
        let last = end - self.shortest;
        let window = &s[start..=last];
        let mut off = 0;
        while off < window.len() {
            let c = window[off];
            if c < 128 {
                if self.first_ascii & (1u128 << c) != 0 && self.second_ok(c, s, start + off, end) {
                    for &k in &self.by_first[c as usize] {
                        if Self::at(&self.strings[k as usize], s, start + off, end) {
                            return true;
                        }
                    }
                }
            } else if self.first_other && self.strings.iter().any(|st| Self::at(st, s, start + off, end)) {
                return true;
            }
            off += 1;
        }
        false
    }
}

/// The requirement of a compiled program, when it has one worth using.
pub fn need(code: &[u32]) -> Option<Need> {
    let pc = if code.first() == Some(&INFO) { 1 + *code.get(1)? as usize } else { 0 };
    let strings = seq(code, pc, 0)?;
    let shortest = strings.iter().map(|s| s.len()).min()?;
    if shortest < MIN_LEN || strings.len() > MAX_STRINGS {
        return None;
    }
    Need::build(strings)
}

/// Strings one of which every match starts with (a lead), when the program
/// says so and they are worth a scan: a search then tries only where one
/// of them starts. Read past zero-width operations (group marks, \b, ^,
/// lookarounds: a match starts where they are tested), through the
/// alternatives of a BRANCH (each must lead with a string) and the JUMP
/// that ends one; a run is as in `walk`.
pub fn lead(code: &[u32]) -> Option<Need> {
    let pc = if code.first() == Some(&INFO) { 1 + *code.get(1)? as usize } else { 0 };
    let strings = leads(code, pc, 0)?;
    // (a string of one character is worth it only beside longer ones, and
    // only when it is punctuation, rarer than letters: `` ` `` or `$(` among
    // names)
    let one = |st: &Str| st.len() == 1 && (st[0].fold != Fold::None || st[0].chars.iter().any(|&c| c >= 128 || ascii_word(c)));
    if strings.iter().any(one) || strings.iter().all(|st| st.len() < MIN_LEN) || strings.len() > MAX_STRINGS {
        return None;
    }
    Need::build(strings)
}

fn ascii_word(c: u32) -> bool {
    matches!(c, 0x30..=0x39 | 0x41..=0x5A | 0x61..=0x7A | 0x5F)
}

/// The strings every match of the sequence at code[pc] starts with.
fn leads(code: &[u32], mut pc: usize, depth: usize) -> Option<Vec<Str>> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut run: Str = Vec::new();
    loop {
        let op = *code.get(pc)?;
        match op {
            MARK | AT => pc += 2,
            ASSERT | ASSERT_NOT => pc += 1 + *code.get(pc + 1)? as usize,
            // (the end of an alternative: on after the BRANCH; what follows
            // still starts the match while the run is empty)
            JUMP if run.is_empty() => pc += 1 + *code.get(pc + 1)? as usize,
            LITERAL | LITERAL_IGNORE | LITERAL_UNI_IGNORE => {
                let fold = match op {
                    LITERAL => Fold::None,
                    LITERAL_IGNORE => Fold::Ascii,
                    _ => Fold::Unicode,
                };
                run.push(Unit::new(fold, vec![*code.get(pc + 1)?]));
                pc += 2;
            }
            IN | IN_IGNORE | IN_UNI_IGNORE => {
                let fold = match op {
                    IN => Fold::None,
                    IN_IGNORE => Fold::Ascii,
                    _ => Fold::Unicode,
                };
                match small_set(code, pc) {
                    Some(chars) => run.push(Unit::new(fold, chars)),
                    None => break,
                }
                pc += 1 + *code.get(pc + 1)? as usize;
            }
            BRANCH => {
                // each alternative's leads after the run before them (re's
                // parser takes a prefix all alternatives share out of them:
                // `nc|ncat|netcat` is n(?:c|cat|etcat)); an alternative
                // without a lead leaves the run alone
                let mut q = pc + 1;
                let mut out: Vec<Str> = Vec::new();
                loop {
                    let skip = *code.get(q)? as usize;
                    if skip == 0 {
                        break;
                    }
                    match leads(code, q + 1, depth + 1) {
                        Some(list) => {
                            for st in list {
                                let mut joined = run.clone();
                                joined.extend(st);
                                out.push(joined);
                            }
                        }
                        None => {
                            out.clear();
                            break;
                        }
                    }
                    q += skip;
                }
                return if !out.is_empty() {
                    Some(out)
                } else if run.is_empty() {
                    None
                } else {
                    Some(vec![run])
                };
            }
            _ => break,
        }
    }
    if run.is_empty() {
        None
    } else {
        Some(vec![run])
    }
}

/// Better: a longer shortest string, then fewer strings.
fn better(a: &[Str], b: &[Str]) -> bool {
    let short = |x: &[Str]| x.iter().map(|s| s.len()).min().unwrap_or(0);
    (short(a), std::cmp::Reverse(a.len())) > (short(b), std::cmp::Reverse(b.len()))
}

/// The literals of a set operation (at code[pc]), when it holds only a few.
fn small_set(code: &[u32], pc: usize) -> Option<Vec<u32>> {
    let end = pc + 1 + *code.get(pc + 1)? as usize;
    let mut q = pc + 2;
    let mut out = Vec::new();
    while q < end {
        match *code.get(q)? {
            LITERAL => {
                out.push(*code.get(q + 1)?);
                q += 2;
            }
            FAILURE => break,
            _ => return None, // NEGATE, RANGE, CHARSET, CATEGORY, …
        }
    }
    if out.is_empty() || out.len() > MAX_CLASS {
        return None;
    }
    Some(out)
}

/// What a sequence says: the best requirement of it, and the run it starts
/// with (what every match of it begins with; empty where that is not a
/// literal).
struct Seq {
    best: Option<Vec<Str>>,
    lead: Str,
}

/// The best requirement of the sequence at code[pc] (up to the end of its
/// alternative, repeat body or program): strings one of which every match
/// of the sequence holds.
fn seq(code: &[u32], pc: usize, depth: usize) -> Option<Vec<Str>> {
    walk(code, pc, depth)?.best
}

fn walk(code: &[u32], mut pc: usize, depth: usize) -> Option<Seq> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut best: Option<Vec<Str>> = None;
    let mut run: Str = Vec::new();
    let mut lead: Option<Str> = None;
    let consider = |cand: Option<Vec<Str>>, best: &mut Option<Vec<Str>>| {
        if let Some(c) = cand {
            if !c.is_empty() && c.iter().all(|s| !s.is_empty()) && best.as_ref().map_or(true, |b| better(&c, b)) {
                *best = Some(c);
            }
        }
    };
    macro_rules! flush {
        () => {{
            if lead.is_none() {
                lead = Some(run.clone());
            }
            if !run.is_empty() {
                consider(Some(vec![std::mem::take(&mut run)]), &mut best);
            }
        }};
    }
    loop {
        let Some(&op) = code.get(pc) else { break };
        match op {
            MARK | AT => pc += 2,
            ASSERT | ASSERT_NOT => pc += 1 + *code.get(pc + 1)? as usize,
            LITERAL | LITERAL_IGNORE | LITERAL_UNI_IGNORE => {
                let fold = match op {
                    LITERAL => Fold::None,
                    LITERAL_IGNORE => Fold::Ascii,
                    _ => Fold::Unicode,
                };
                run.push(Unit::new(fold, vec![*code.get(pc + 1)?]));
                pc += 2;
            }
            IN | IN_IGNORE | IN_UNI_IGNORE => {
                let fold = match op {
                    IN => Fold::None,
                    IN_IGNORE => Fold::Ascii,
                    _ => Fold::Unicode,
                };
                match small_set(code, pc) {
                    Some(chars) => run.push(Unit::new(fold, chars)),
                    None => flush!(),
                }
                pc += 1 + *code.get(pc + 1)? as usize;
            }
            ANY | ANY_ALL => {
                flush!();
                pc += 1;
            }
            NOT_LITERAL | NOT_LITERAL_IGNORE | NOT_LITERAL_UNI_IGNORE | CATEGORY | GROUPREF | GROUPREF_IGNORE
            | GROUPREF_UNI_IGNORE => {
                flush!();
                pc += 2;
            }
            BRANCH => {
                // the run just before, joined to each alternative's own lead
                // (re's parser takes a prefix all alternatives share out of
                // them: `nc|ncat|netcat` is n(?:c|cat|etcat))
                let before = run.clone();
                flush!();
                let mut q = pc + 1;
                let mut all: Option<Vec<Str>> = Some(Vec::new());
                let mut joined: Vec<Str> = Vec::new();
                let mut joined_ok = true;
                loop {
                    let skip = *code.get(q)? as usize;
                    if skip == 0 {
                        break;
                    }
                    let alt = walk(code, q + 1, depth + 1);
                    match &alt {
                        Some(a) => {
                            let mut j = before.clone();
                            j.extend(a.lead.iter().cloned());
                            joined.push(j);
                        }
                        None => joined_ok = false, // (an alternative not read: no joined strings)
                    }
                    all = match (all, alt.and_then(|a| a.best)) {
                        (Some(mut a), Some(b)) if !b.is_empty() => {
                            a.extend(b);
                            Some(a)
                        }
                        _ => None, // an alternative that holds nothing required
                    };
                    q += skip;
                }
                consider(all, &mut best);
                if !before.is_empty() && joined_ok {
                    consider(Some(joined), &mut best);
                }
                pc = q + 1;
            }
            REPEAT | POSSESSIVE_REPEAT => {
                flush!();
                let skip = *code.get(pc + 1)? as usize;
                if *code.get(pc + 2)? >= 1 {
                    consider(seq(code, pc + 4, depth + 1), &mut best);
                }
                pc += 1 + skip + 1; // past the UNTIL (or the possessive repeat's SUCCESS)
            }
            REPEAT_ONE | MIN_REPEAT_ONE | POSSESSIVE_REPEAT_ONE => {
                flush!();
                pc += 1 + *code.get(pc + 1)? as usize;
            }
            ATOMIC_GROUP => {
                flush!();
                consider(seq(code, pc + 2, depth + 1), &mut best);
                pc += 1 + *code.get(pc + 1)? as usize;
            }
            // the end of this sequence (SUCCESS, JUMP, the UNTILs, FAILURE),
            // or what is not read here (GROUPREF_EXISTS): what came before
            // is still required
            _ => break,
        }
    }
    flush!();
    Some(Seq { best, lead: lead.unwrap_or_default() })
}

#[cfg(test)]
mod tests {
    use crate::pyre::Regex;

    fn need(src: &str) -> Option<String> {
        Regex::compile(src, 0).expect("compiles").need_text()
    }

    #[test]
    fn what_a_search_needs() {
        assert_eq!(need(r"\bcurl\b"), Some("curl".into()));
        assert_eq!(need(r"\b(?:nc|ncat|netcat)\s"), Some("nc | ncat | netcat".into()));
        assert_eq!(need(r"(?i)ngrok"), Some("~n~g~r~o~k".into()));
        assert_eq!(need(r"(?i)kiss"), Some("~k~[iı]~[sſ]~[sſ]".into()));
        assert_eq!(need(r"\w+\.npmrc\b"), Some(".npmrc".into()));
        assert_eq!(need(r"(?:ab)+cde"), Some("cde".into())); // the longer of two required strings
        assert_eq!(need(r"(?:abc)+de"), Some("abc".into()));
        assert_eq!(need(r"x(?:abc|de)y"), Some("xabc | xde".into()));
    }

    fn lead(src: &str) -> Option<String> {
        Regex::compile(src, 0).expect("compiles").lead_text()
    }

    #[test]
    fn what_a_match_starts_with() {
        assert_eq!(lead(r"\b(?:nc|ncat|netcat)\s"), Some("nc | ncat | netcat".into()));
        assert_eq!(lead(r"(?<![\w$.])eval\("), Some("eval(".into()));
        assert_eq!(lead(r"(?i)ngrok"), Some("~n~g~r~o~k".into()));
        assert_eq!(lead(r"(?:\$\(|`)\s*id\b"), Some("$( | `".into())); // (punctuation alone may lead)
        assert_eq!(lead(r"socket\.(?:gethostname|getfqdn)"), Some("socket.gethostname | socket.getfqdn".into()));
        assert_eq!(lead(r"x(?:ab|\w)y"), None); // ("x" alone: one letter is not worth it)
    }

    #[test]
    fn no_lead_where_a_match_need_not_start_with_one() {
        assert_eq!(lead(r"a?bc"), None);
        assert_eq!(lead(r"(?:abc|\w+)d"), None);
        assert_eq!(lead(r"\s*foo"), None);
        assert_eq!(lead(r"(?:ab)+c"), None);
        assert_eq!(lead(r"[a-z]bc"), None);
        assert_eq!(lead(r"x|yz"), None); // (a lone letter)
    }

    #[test]
    fn nothing_where_a_match_need_not_hold_it() {
        assert_eq!(need(r"a|bc"), None); // one character is too little to be worth a scan
        assert_eq!(need(r"(?:abc)?d"), None);
        assert_eq!(need(r"(?:abc|\w)d"), None);
        assert_eq!(need(r"(?=abc)\w"), None); // a lookaround's text is not used
        assert_eq!(need(r"(?<=abc)d"), None);
        assert_eq!(need(r"[a-z]+"), None);
    }
}
