//! A compiled program and what is read from it once, at compile time, to
//! make matching cheaper without changing any answer:
//!
//! * for each set operation (IN, IN_IGNORE, IN_UNI_IGNORE), whether each
//!   ASCII character is a member — one bit test instead of walking the set;
//! * for each single-character repeat (REPEAT_ONE, MIN_REPEAT_ONE), the
//!   characters its tail can start with (first.rs), so backtracking skips a
//!   position where the tail cannot match at once, as sre already does when
//!   the tail starts with a literal;
//! * for each alternative of a BRANCH, the characters it can start with, so
//!   an alternative that cannot match here is not tried, as sre already does
//!   when the alternative starts with a literal or a set;
//! * for the whole program, the characters a match can start with and the
//!   one-character lookbehinds and position tests made before the first of
//!   them, and sre's own first-character set as a bit table;
//! * the strings one of which every match holds (literal.rs), and those
//!   one of which every match starts with: a search then tries only where
//!   one of them starts.

use super::constants::*;
use super::first::{self, FirstSet, StartSet};
use super::literal::{self, Need};
use super::matcher;

pub struct Prog {
    pub code: Vec<u32>,
    in_ascii: Vec<u128>,
    in_known: Vec<bool>,
    /// code position (a single-character repeat, or the skip word of a
    /// BRANCH alternative) -> index into `sets`, u32::MAX for none
    set_at: Vec<u32>,
    sets: Vec<FirstSet>,
    /// where a search's match can start (first.rs: the characters, and the
    /// zero-width tests made before the first of them)
    pub first: Option<StartSet>,
    /// sre's INFO charset (a search's first-character scan), for ASCII
    info_ascii: u128,
    /// strings one of which every match holds (literal.rs)
    pub need: Option<Need>,
    /// strings one of which every match starts with (literal.rs)
    pub lead: Option<Need>,
    /// is `need` worth checking before a search? (not when it is `lead`'s
    /// own strings, which the search scans for anyway)
    pub check_need: bool,
    /// (development: characters the need and lead scans read; `stats`)
    #[cfg(feature = "stats")]
    pub scanned: [std::sync::atomic::AtomicU64; 4],
}

/// Every operation's position in code[start..end] (sre's `dis` walk).
fn visit(code: &[u32], start: usize, end: usize, out: &mut Vec<usize>, depth: usize) -> Option<()> {
    if depth > 200 {
        return None;
    }
    let mut i = start;
    while i < end {
        let op = *code.get(i)?;
        out.push(i);
        i += 1;
        match op {
            FAILURE | SUCCESS | ANY | ANY_ALL | MAX_UNTIL | MIN_UNTIL | NEGATE => {}
            LITERAL | NOT_LITERAL | LITERAL_IGNORE | NOT_LITERAL_IGNORE | LITERAL_UNI_IGNORE | NOT_LITERAL_UNI_IGNORE
            | LITERAL_LOC_IGNORE | NOT_LITERAL_LOC_IGNORE | AT | CATEGORY | MARK | GROUPREF | GROUPREF_IGNORE
            | GROUPREF_UNI_IGNORE | GROUPREF_LOC_IGNORE | JUMP => i += 1,
            IN | IN_IGNORE | IN_UNI_IGNORE | IN_LOC_IGNORE | INFO => i += *code.get(i)? as usize,
            BRANCH => {
                let mut skip = *code.get(i)? as usize;
                while skip != 0 {
                    visit(code, i + 1, i + skip, out, depth + 1)?;
                    i += skip;
                    skip = *code.get(i)? as usize;
                }
                i += 1;
            }
            REPEAT | REPEAT_ONE | MIN_REPEAT_ONE | POSSESSIVE_REPEAT | POSSESSIVE_REPEAT_ONE => {
                let skip = *code.get(i)? as usize;
                visit(code, i + 3, i + skip, out, depth + 1)?;
                i += skip;
            }
            GROUPREF_EXISTS => i += 2,
            ASSERT | ASSERT_NOT => {
                let skip = *code.get(i)? as usize;
                visit(code, i + 2, i + skip, out, depth + 1)?;
                i += skip;
            }
            ATOMIC_GROUP => {
                let skip = *code.get(i)? as usize;
                visit(code, i + 1, i + skip, out, depth + 1)?;
                i += skip;
            }
            _ => return None,
        }
    }
    Some(())
}

impl Prog {
    pub fn new(code: Vec<u32>) -> Prog {
        let n = code.len();
        let mut prog = Prog {
            in_ascii: vec![0; n],
            in_known: vec![false; n],
            set_at: vec![u32::MAX; n],
            sets: Vec::new(),
            first: first::start_set(&code),
            info_ascii: 0,
            need: literal::need(&code),
            lead: literal::lead(&code),
            check_need: true,
            #[cfg(feature = "stats")]
            scanned: Default::default(),
            code,
        };
        if prog.code.first() == Some(&INFO) && prog.code.get(2).is_some_and(|f| f & INFO_CHARSET != 0 && f & INFO_PREFIX == 0) {
            for c in 0..128u32 {
                if matcher::charset(&prog.code, 5, c) {
                    prog.info_ascii |= 1u128 << c;
                }
            }
        }
        let prefix = prog.code.first() == Some(&INFO) && prog.code.get(2).is_some_and(|f| f & INFO_PREFIX != 0);
        if let (Some(need), Some(lead)) = (&prog.need, &prog.lead) {
            prog.check_need = prefix || !need.same_strings(lead);
        }
        let mut ops = Vec::new();
        if visit(&prog.code, 0, n, &mut ops, 0).is_none() {
            return prog; // (never for a program the compiler wrote; then simply no tables)
        }
        for pc in ops {
            match prog.code[pc] {
                IN | IN_IGNORE | IN_UNI_IGNORE => {
                    let mut bits = 0u128;
                    for c in 0..128u32 {
                        if matcher::unit_accepts(&prog.code, pc, c) {
                            bits |= 1u128 << c;
                        }
                    }
                    prog.in_ascii[pc] = bits;
                    prog.in_known[pc] = true;
                }
                REPEAT_ONE | MIN_REPEAT_ONE => {
                    let tail = pc + 1 + prog.code[pc + 1] as usize;
                    prog.keep_set(pc, tail);
                }
                BRANCH => {
                    let mut q = pc + 1;
                    while let Some(&skip) = prog.code.get(q) {
                        if skip == 0 {
                            break;
                        }
                        prog.keep_set(q, q + 1);
                        q += skip as usize;
                    }
                }
                _ => {}
            }
        }
        prog
    }

    /// Is `ch` in the INFO charset (at code[5])?
    #[inline]
    pub fn info_accepts(&self, ch: u32) -> bool {
        if ch < 128 {
            self.info_ascii & (1u128 << ch) != 0
        } else {
            matcher::charset(&self.code, 5, ch)
        }
    }

    fn keep_set(&mut self, key: usize, at: usize) {
        if let Some(fs) = first::first_set_at(&self.code, at) {
            self.set_at[key] = self.sets.len() as u32;
            self.sets.push(fs);
        }
    }

    /// Is `ch` a member of the set operation at `pc` (IN, IN_IGNORE, IN_UNI_IGNORE)?
    #[inline]
    pub fn in_accepts(&self, pc: usize, ch: u32) -> bool {
        if ch < 128 && self.in_known[pc] {
            self.in_ascii[pc] & (1u128 << ch) != 0
        } else {
            matcher::unit_accepts(&self.code, pc, ch)
        }
    }

    /// Can what follows `key` start with `ch` (None: at the end)? `key` is a
    /// single-character repeat (then: its tail) or the skip word of a BRANCH
    /// alternative (then: that alternative). True where there is no filter.
    #[inline]
    pub fn can_start(&self, key: usize, ch: Option<u32>) -> bool {
        let t = self.set_at[key];
        if t == u32::MAX {
            return true;
        }
        match ch {
            None => false, // it must consume a character, and there is none
            Some(ch) => self.sets[t as usize].accepts(&self.code, ch),
        }
    }
}
