//! The key under which a file system may take two member names for one path.

use crate::fold_table::{COMBINING, FOLD, IGNORABLE};
use std::cmp::Ordering;

fn in_ranges(table: &[(u32, u32)], c: u32) -> bool {
    table.binary_search_by(|&(lo, hi)| {
        if hi < c { Ordering::Less } else if lo > c { Ordering::Greater } else { Ordering::Equal }
    }).is_ok()
}

const S_BASE: u32 = 0xAC00;
const L_BASE: u32 = 0x1100;
const V_BASE: u32 = 0x1161;
const T_BASE: u32 = 0x11A7;
const V_COUNT: u32 = 21;
const T_COUNT: u32 = 28;
const S_COUNT: u32 = 11_172;

struct Key {
    out: String,
    marks: Vec<char>,
}

impl Key {
    fn push(&mut self, c: char) {
        if in_ranges(COMBINING, c as u32) {
            self.marks.push(c);
        } else {
            self.flush();
            self.out.push(c);
        }
    }

    // Canonically equivalent sequences hold the same marks after each base: sorted, they compare equal.
    fn flush(&mut self) {
        self.marks.sort_unstable();
        self.out.extend(self.marks.drain(..));
    }

    fn segment(&mut self, segment: &str) {
        for c in segment.chars() {
            let cp = c as u32;
            if in_ranges(IGNORABLE, cp) { continue; }
            if (S_BASE..S_BASE + S_COUNT).contains(&cp) {
                let s = cp - S_BASE;
                for jamo in [L_BASE + s / (V_COUNT * T_COUNT), V_BASE + (s % (V_COUNT * T_COUNT)) / T_COUNT, T_BASE + s % T_COUNT] {
                    if jamo != T_BASE { self.push(char::from_u32(jamo).unwrap_or(c)); }
                }
                continue;
            }
            match FOLD.binary_search_by_key(&cp, |&(k, _)| k) {
                Ok(i) => FOLD[i].1.chars().for_each(|f| self.push(f)),
                Err(_) => c.to_lowercase().for_each(|f| self.push(f)),
            }
        }
        self.flush();
    }
}

/// The key two member names share when some file system may store them as one path: `\` and `/` both
/// separate segments (Windows), `.` and empty segments are dropped, and each segment is case-folded
/// (NTFS, APFS, HFS+, ext4 casefold, FAT), brought to one Unicode normalization (APFS, HFS+, ext4 casefold)
/// and stripped of default-ignorable code points (HFS+). Two names with one key may end up as one file.
///
/// It over-approximates on purpose (no single file system does all of this): it is for flagging names
/// that may collide, never for proving that they do not.
pub fn path_key(name: &str) -> String {
    let mut key = Key { out: String::with_capacity(name.len()), marks: Vec::new() };
    let mut first = true;
    for segment in name.split(['/', '\\']) {
        if segment.is_empty() || segment == "." { continue; }
        if !first { key.out.push('/'); }
        first = false;
        key.segment(segment);
    }
    key.out
}

#[cfg(test)]
mod tests {
    use super::path_key;

    #[test]
    fn names_a_file_system_may_merge_share_a_key() {
        for (a, b) in [
            ("Makefile", "makefile"),
            ("caf\u{e9}.txt", "cafe\u{301}.txt"),           // NFC and NFD
            ("\u{d55c}.txt", "\u{1112}\u{1161}\u{11ab}.txt"), // Hangul syllable and jamo
            ("\u{304c}.txt", "\u{304b}\u{3099}.txt"),          // kana with a voiced mark
            ("x\u{3a3}.txt", "x\u{3c3}.txt"),                  // Σ and σ
            ("x\u{3c2}.txt", "x\u{3c3}.txt"),                  // final sigma
            ("\u{17f}.txt", "s.txt"),                          // long s
            ("\u{212a}.txt", "k.txt"),                         // Kelvin sign
            ("\u{131}nit.py", "init.py"),                      // dotless i (NTFS)
            ("stra\u{df}e", "STRASSE"),
            ("setup\u{200d}.py", "setup.py"),                  // zero-width joiner (HFS+)
            ("a\\b.txt", "a/b.txt"),
            ("a//./b", "a/b"),
            ("a\u{323}\u{301}", "a\u{301}\u{323}"),            // marks in either order
        ] {
            assert_eq!(path_key(a), path_key(b), "{a:?} {b:?}");
        }
    }

    #[test]
    fn distinct_names_keep_distinct_keys() {
        for (a, b) in [("caf\u{e9}.txt", "cafe.txt"), ("\u{65e5}\u{672c}.txt", "\u{4e2d}\u{56fd}.txt"),
                       ("a.txt", "b.txt"), ("\u{130}nit", "init"), ("a/b", "ab")] {
            assert_ne!(path_key(a), path_key(b), "{a:?} {b:?}");
        }
    }

    #[test]
    fn the_table_is_sorted() {
        assert!(crate::fold_table::FOLD.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(crate::fold_table::COMBINING.windows(2).all(|w| w[0].1 < w[1].0));
        assert!(crate::fold_table::IGNORABLE.windows(2).all(|w| w[0].1 < w[1].0));
        assert!(!crate::fold_table::UNICODE_VERSION.is_empty());
    }
}
