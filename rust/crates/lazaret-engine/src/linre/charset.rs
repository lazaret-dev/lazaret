//! Sets of code points, and what each of the pattern's characters matches.
//!
//! Every character-consuming item of a pattern (a literal, `.`, a class, an
//! escape like `\w`) is turned once, at compile time, into the exact set of
//! text characters it accepts, folding included: the matchers then never fold
//! case or ask a Unicode table, they test set membership. A set is a sorted
//! list of disjoint, non-adjacent inclusive ranges over all `u32` values
//! (a text is code points, lone surrogates included; values past U+10FFFF
//! cannot occur in a Python str, and no category holds them).
//!
//! How `re` folds case under IGNORECASE is not "compare lowercase forms": it
//! depends on how its compiler emits the item (a literal, a literal with
//! extra equivalences, a class that holds a cased character or not, an
//! astral range inside a class), and those paths do not all agree with one
//! folding rule. `literal_set`, `class_set` and `fold_class` reproduce each
//! path, as Python 3.13 on (and pyre) take them, so the sets are exactly
//! what `re` matches; the parity tests hold them to it.

use crate::generated::unicode13 as t;
use crate::unicode;
use std::sync::OnceLock;

/// The largest value a text character can have.
pub const MAX: u32 = u32::MAX;

/// A set of code points: sorted, disjoint, non-adjacent inclusive ranges.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct CharSet {
    ranges: Vec<(u32, u32)>,
}

impl CharSet {
    pub fn empty() -> CharSet {
        CharSet { ranges: Vec::new() }
    }

    pub fn all() -> CharSet {
        CharSet { ranges: vec![(0, MAX)] }
    }

    pub fn one(c: u32) -> CharSet {
        CharSet { ranges: vec![(c, c)] }
    }

    pub fn range(a: u32, b: u32) -> CharSet {
        if a > b {
            CharSet::empty()
        } else {
            CharSet { ranges: vec![(a, b)] }
        }
    }

    /// From any ranges (unsorted, overlapping): the canonical set.
    pub fn from_ranges(mut v: Vec<(u32, u32)>) -> CharSet {
        v.retain(|&(a, b)| a <= b);
        v.sort_unstable();
        let mut out: Vec<(u32, u32)> = Vec::with_capacity(v.len());
        for (a, b) in v {
            if let Some(last) = out.last_mut() {
                if a <= last.1.saturating_add(1) {
                    if b > last.1 {
                        last.1 = b;
                    }
                    continue;
                }
            }
            out.push((a, b));
        }
        CharSet { ranges: out }
    }

    /// From single characters (any order, repeats allowed).
    pub fn from_chars(mut v: Vec<u32>) -> CharSet {
        v.sort_unstable();
        v.dedup();
        CharSet::from_ranges(v.into_iter().map(|c| (c, c)).collect())
    }

    pub fn ranges(&self) -> &[(u32, u32)] {
        &self.ranges
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn is_all(&self) -> bool {
        self.ranges.len() == 1 && self.ranges[0] == (0, MAX)
    }

    /// How many code points (saturating).
    pub fn count(&self) -> u64 {
        self.ranges.iter().map(|&(a, b)| (b - a) as u64 + 1).sum()
    }

    /// The one character of a one-character set.
    pub fn single(&self) -> Option<u32> {
        match self.ranges[..] {
            [(a, b)] if a == b => Some(a),
            _ => None,
        }
    }

    /// The characters of a set of at most `n` of them.
    pub fn chars_upto(&self, n: usize) -> Option<Vec<u32>> {
        if self.count() > n as u64 {
            return None;
        }
        Some(self.ranges.iter().flat_map(|&(a, b)| a..=b).collect())
    }

    #[inline]
    pub fn contains(&self, c: u32) -> bool {
        // (most sets are a few ranges: a scan beats a search)
        if self.ranges.len() <= 8 {
            for &(a, b) in &self.ranges {
                if c < a {
                    return false;
                }
                if c <= b {
                    return true;
                }
            }
            return false;
        }
        let i = self.ranges.partition_point(|&(a, _)| a <= c);
        i > 0 && c <= self.ranges[i - 1].1
    }

    pub fn union(&self, other: &CharSet) -> CharSet {
        let mut v = self.ranges.clone();
        v.extend_from_slice(&other.ranges);
        CharSet::from_ranges(v)
    }

    pub fn complement(&self) -> CharSet {
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        let mut next = 0u32;
        let mut open = true;
        for &(a, b) in &self.ranges {
            if a > next {
                out.push((next, a - 1));
            }
            if b == MAX {
                open = false;
                break;
            }
            next = b + 1;
        }
        if open {
            out.push((next, MAX));
        }
        CharSet { ranges: out }
    }

    pub fn intersect(&self, other: &CharSet) -> CharSet {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        while i < self.ranges.len() && j < other.ranges.len() {
            let (a1, b1) = self.ranges[i];
            let (a2, b2) = other.ranges[j];
            let lo = a1.max(a2);
            let hi = b1.min(b2);
            if lo <= hi {
                out.push((lo, hi));
            }
            if b1 < b2 {
                i += 1;
            } else {
                j += 1;
            }
        }
        CharSet { ranges: out }
    }

    pub fn minus(&self, other: &CharSet) -> CharSet {
        self.intersect(&other.complement())
    }

    pub fn intersects(&self, other: &CharSet) -> bool {
        !self.intersect(other).is_empty()
    }

    /// The ASCII members, as a bit mask.
    pub fn ascii_mask(&self) -> u128 {
        let mut m = 0u128;
        for &(a, b) in &self.ranges {
            if a >= 128 {
                break;
            }
            for c in a..=b.min(127) {
                m |= 1u128 << c;
            }
        }
        m
    }

    /// Does the set hold a character outside ASCII?
    pub fn has_non_ascii(&self) -> bool {
        self.ranges.last().is_some_and(|&(_, b)| b >= 128)
    }
}

/// The character classes of `\d \s \w`, as Python reads them for a str
/// pattern (Unicode) or under ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    Digit,
    NotDigit,
    Space,
    NotSpace,
    Word,
    NotWord,
}

impl Category {
    pub fn set(self, ascii: bool) -> CharSet {
        let base = match self {
            Category::Digit | Category::NotDigit => {
                if ascii {
                    CharSet::range(0x30, 0x39)
                } else {
                    tables().digit.clone()
                }
            }
            Category::Space | Category::NotSpace => {
                if ascii {
                    // C's isspace in ASCII: \t \n \v \f \r and space
                    CharSet::from_ranges(vec![(0x09, 0x0D), (0x20, 0x20)])
                } else {
                    tables().space.clone()
                }
            }
            Category::Word | Category::NotWord => {
                if ascii {
                    ascii_word()
                } else {
                    tables().word.clone()
                }
            }
        };
        match self {
            Category::NotDigit | Category::NotSpace | Category::NotWord => base.complement(),
            _ => base,
        }
    }
}

fn ascii_word() -> CharSet {
    CharSet::from_ranges(vec![(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)])
}

/// Python's `\w` for a str pattern (isalnum() or "_"), and under ASCII.
pub fn word_set(ascii: bool) -> CharSet {
    if ascii {
        ascii_word()
    } else {
        tables().word.clone()
    }
}

struct Tables {
    word: CharSet,
    digit: CharSet,
    space: CharSet,
    /// characters whose sre lowercase is another character
    lower_dom: CharSet,
    /// characters whose sre uppercase is another character
    upper_dom: CharSet,
    /// characters that are cased (lowercase or uppercase differ)
    cased: CharSet,
}

fn tables() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(|| {
        let mut word = Vec::new();
        let mut digit = Vec::new();
        let mut space = Vec::new();
        for c in 0..128u32 {
            if unicode::is_word(c) {
                word.push((c, c));
            }
            if unicode::is_decimal(c) {
                digit.push((c, c));
            }
            if unicode::is_space(c) {
                space.push((c, c));
            }
        }
        // past ASCII the predicates read only the property bits, constant
        // over each run of the table
        let runs = t::PROPS;
        for (k, &(start, bits)) in runs.iter().enumerate() {
            let end = runs.get(k + 1).map_or(0x10FFFF, |&(n, _)| n - 1);
            let (a, b) = (start.max(128), end.min(0x10FFFF));
            if a > b {
                continue;
            }
            if bits & unicode::ALNUM != 0 {
                word.push((a, b));
            }
            if bits & unicode::DECIMAL != 0 {
                digit.push((a, b));
            }
            if bits & unicode::SPACE != 0 {
                space.push((a, b));
            }
        }
        let lower_dom = CharSet::from_chars(t::LOWER.iter().map(|&(c, _)| c).collect());
        let upper_dom = CharSet::from_chars(t::UPPER.iter().map(|&(c, _)| c).collect());
        let cased = lower_dom.union(&upper_dom);
        Tables {
            word: CharSet::from_ranges(word),
            digit: CharSet::from_ranges(digit),
            space: CharSet::from_ranges(space),
            lower_dom,
            upper_dom,
            cased,
        }
    })
}

/// How a pattern compares case: as written, Unicode folding (a str
/// pattern's IGNORECASE) or ASCII folding (IGNORECASE with ASCII).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fold {
    None,
    Unicode,
    Ascii,
}

fn lower_of(c: u32, fold: Fold) -> u32 {
    match fold {
        Fold::Ascii => {
            if (0x41..=0x5A).contains(&c) {
                c + 32
            } else {
                c
            }
        }
        _ => unicode::sre_lower(c),
    }
}

fn is_cased(c: u32, fold: Fold) -> bool {
    match fold {
        Fold::Ascii => (0x41..=0x5A).contains(&c) || (0x61..=0x7A).contains(&c),
        _ => unicode::sre_iscased(c),
    }
}

fn fixes_of(lo: u32, fold: Fold) -> &'static [u32] {
    match fold {
        Fold::Unicode => unicode::case_fixes(lo).unwrap_or(&[]),
        _ => &[],
    }
}

/// The text characters t whose folded form (lower(t)) lies in `q`: what an
/// item that folds the text character before testing it accepts.
fn by_lower(q: &CharSet, fold: Fold) -> CharSet {
    let dom = match fold {
        Fold::Ascii => CharSet::range(0x41, 0x5A),
        _ => tables().lower_dom.clone(),
    };
    // (outside the domain a character is its own lowercase)
    let mut out = q.minus(&dom).ranges;
    for &(a, b) in dom.ranges() {
        for c in a..=b {
            if q.contains(lower_of(c, fold)) {
                out.push((c, c));
            }
        }
    }
    CharSet::from_ranges(out)
}

/// What one literal character of the pattern matches (`negated`: the class
/// `[^c]`), under `fold`.
pub fn literal_set(c: u32, negated: bool, fold: Fold) -> CharSet {
    let set = if fold == Fold::None || !is_cased(c, fold) {
        CharSet::one(c)
    } else {
        // the text character's lowercase is c's, or one of re's extra
        // equivalences of it (ſ for s)
        let lo = lower_of(c, fold);
        let mut q = vec![lo];
        q.extend_from_slice(fixes_of(lo, fold));
        by_lower(&CharSet::from_chars(q), fold)
    };
    if negated {
        set.complement()
    } else {
        set
    }
}

/// An item of a class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClassItem {
    Lit(u32),
    Range(u32, u32),
    Cat(Category),
}

/// What a class matches: its items, negated or not, under `fold`, with
/// `ascii` categories (the ASCII flag).
pub fn class_set(items: &[ClassItem], negated: bool, fold: Fold, ascii: bool) -> CharSet {
    let set = if fold == Fold::None {
        let mut v = Vec::new();
        let mut cats = CharSet::empty();
        for it in items {
            match *it {
                ClassItem::Lit(c) => v.push((c, c)),
                ClassItem::Range(a, b) => v.push((a, b)),
                ClassItem::Cat(k) => cats = cats.union(&k.set(ascii)),
            }
        }
        CharSet::from_ranges(v).union(&cats)
    } else {
        fold_class(items, fold, ascii)
    };
    if negated {
        set.complement()
    } else {
        set
    }
}

/// A class under IGNORECASE, as re compiles it (3.13 on, as pyre does): the
/// set its items stand for is built from their lowercase forms (and re's
/// extra equivalences), the text character is lowercased before it is
/// tested against that set — unless no item is cased, in which case the
/// class is compared as written. A range reaching past the Basic
/// Multilingual Plane is tested, past it, on the lowercase and on the
/// uppercase of that lowercase (under ASCII folding: on the character as it
/// is). (Python 3.10–3.12 differ for an uppercase astral letter written in a
/// class: they test it as written against the text's lowercase, so `[𐐀a]`
/// matches neither 𐐀 nor 𐐨; and for an astral range under ASCII folding.)
fn fold_class(items: &[ClassItem], fold: Fold, ascii: bool) -> CharSet {
    const BMP: u32 = 0x10000;
    let mut hascased = false;
    // what the folded text character is tested against
    let mut lowered: Vec<(u32, u32)> = Vec::new();
    let mut as_written: Vec<(u32, u32)> = Vec::new();
    let mut cats = CharSet::empty();
    let mut astral_ranges: Vec<(u32, u32)> = Vec::new();
    let dom = match fold {
        Fold::Ascii => CharSet::range(0x41, 0x5A),
        _ => tables().lower_dom.clone(),
    };
    for it in items {
        match *it {
            ClassItem::Lit(c) => {
                let lo = lower_of(c, fold);
                lowered.push((lo, lo));
                if is_cased(c, fold) {
                    hascased = true;
                }
            }
            ClassItem::Range(a, b) => {
                // the Basic Multilingual Plane's part, character by
                // character (each one's lowercase; a lowercase never leaves
                // the plane)
                let bmp_end = b.min(BMP - 1);
                if a <= bmp_end {
                    let part = CharSet::range(a, bmp_end);
                    lowered.extend_from_slice(part.minus(&dom).ranges());
                    for &(x, y) in part.intersect(&dom).ranges() {
                        for c in x..=y {
                            let lo = lower_of(c, fold);
                            lowered.push((lo, lo));
                        }
                    }
                }
                if b >= BMP {
                    match fold {
                        Fold::Ascii => as_written.push((a, b)),
                        _ => astral_ranges.push((a, b)),
                    }
                    hascased = true;
                } else if !hascased {
                    let cased = match fold {
                        Fold::Ascii => CharSet::from_ranges(vec![(0x41, 0x5A), (0x61, 0x7A)]),
                        _ => tables().cased.clone(),
                    };
                    hascased = CharSet::range(a, b).intersects(&cased);
                }
            }
            ClassItem::Cat(k) => cats = cats.union(&k.set(ascii)),
        }
    }
    if !hascased {
        // compared as written
        return class_set(items, false, Fold::None, ascii);
    }
    // re's extra equivalences of each lowercase
    let mut low = CharSet::from_ranges(lowered);
    if fold == Fold::Unicode {
        let mut extra = Vec::new();
        for &(k, others) in t::CASE_FIXES {
            if low.contains(k) {
                extra.extend(others.iter().map(|&c| (c, c)));
            }
        }
        low = low.union(&CharSet::from_ranges(extra));
    }
    let mut q = low.union(&CharSet::from_ranges(as_written)).union(&cats);
    for &(a, b) in &astral_ranges {
        // the lowercase in [a, b], or its uppercase in [a, b]
        let mut v = vec![(a, b)];
        let ud = tables().upper_dom.clone();
        for &(x, y) in ud.ranges() {
            for c in x..=y {
                let up = unicode::sre_upper(c);
                if a <= up && up <= b {
                    v.push((c, c));
                }
            }
        }
        q = q.union(&CharSet::from_ranges(v));
    }
    by_lower(&q, fold)
}

/// Any character, or any but "\n".
pub fn any_set(dotall: bool) -> CharSet {
    if dotall {
        CharSet::all()
    } else {
        CharSet::one(0x0A).complement()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_algebra() {
        let a = CharSet::from_ranges(vec![(5, 9), (1, 3), (4, 4), (20, 30)]);
        assert_eq!(a.ranges(), &[(1, 9), (20, 30)]);
        assert_eq!(a.complement().complement(), a);
        assert!(a.contains(9) && !a.contains(10) && a.contains(25));
        assert_eq!(a.intersect(&CharSet::range(8, 22)).ranges(), &[(8, 9), (20, 22)]);
        assert_eq!(CharSet::all().complement(), CharSet::empty());
        assert_eq!(CharSet::range(0, 5).complement().ranges(), &[(6, MAX)]);
        assert_eq!(CharSet::one(MAX).complement().ranges(), &[(0, MAX - 1)]);
    }

    #[test]
    fn categories() {
        let w = Category::Word.set(false);
        assert!(w.contains('_' as u32) && w.contains(0xE9) && !w.contains('-' as u32) && !w.contains(0x110000));
        let s = Category::Space.set(false);
        assert!(s.contains(0x1C) && s.contains(0x85) && s.contains(0x3000) && !s.contains(0xFEFF));
        assert!(!Category::Space.set(true).contains(0x1C));
        assert!(Category::NotDigit.set(false).contains(0x110000));
    }

    #[test]
    fn folding_as_re_does_it() {
        let k = literal_set('k' as u32, false, Fold::Unicode);
        assert_eq!(k, CharSet::from_chars(vec!['k' as u32, 'K' as u32, 0x212A]));
        let s = literal_set('s' as u32, false, Fold::Unicode);
        assert_eq!(s, CharSet::from_chars(vec!['s' as u32, 'S' as u32, 0x17F]));
        // an astral letter folds, on its own and in a class (Python 3.13 on)
        assert_eq!(literal_set(0x10400, false, Fold::Unicode), CharSet::from_chars(vec![0x10400, 0x10428]));
        let cls = class_set(&[ClassItem::Lit(0x10400), ClassItem::Lit('a' as u32)], false, Fold::Unicode, false);
        assert!(cls.contains(0x10400) && cls.contains(0x10428) && cls.contains('A' as u32));
        // an astral range under ASCII folding is compared as written
        let cls = class_set(&[ClassItem::Range(0x10400, 0x10401), ClassItem::Lit('a' as u32)], false, Fold::Ascii, true);
        assert!(cls.contains(0x10400) && !cls.contains(0x10428) && cls.contains('A' as u32));
        // a class of no cased character is compared as written
        assert_eq!(class_set(&[ClassItem::Range(0x30, 0x39)], false, Fold::Unicode, false), CharSet::range(0x30, 0x39));
        let neg = class_set(&[ClassItem::Lit('a' as u32), ClassItem::Lit('b' as u32)], true, Fold::Unicode, false);
        assert!(!neg.contains('A' as u32) && neg.contains('c' as u32));
        let ascii = literal_set('k' as u32, false, Fold::Ascii);
        assert_eq!(ascii, CharSet::from_chars(vec!['k' as u32, 'K' as u32]));
    }
}
