//! Where a match can start: an optimization sre does not have.
//!
//! SRE(search) tries a pattern that begins with no literal prefix and no
//! first-character set it knows (`\b(?:curl|wget)\s…`, `(?<![\w$.])eval\(`,
//! most of the scanner's) at every position of the text. Here the compiled
//! program is read for the operations that can consume a match's first
//! character — past zero-width ones (\b, ^, lookarounds, group marks),
//! through alternatives and optional repeats — and a position whose
//! character none of them accepts is skipped. It changes no answer: a match
//! of a pattern that cannot match the empty string consumes its start
//! position's character with one of those operations, so no match starts at
//! a skipped position. A lookahead at the start says as much: its first
//! consuming operation must take the character where the match starts. Where the program does not say (a backreference, a
//! path that reaches the end without consuming), there is no filter.

use super::constants::*;
use super::matcher;

const MAX_DEPTH: usize = 32;

pub struct FirstSet {
    ops: Vec<usize>,
    ascii: [bool; 128],
}

impl FirstSet {
    #[inline]
    pub fn accepts(&self, code: &[u32], ch: u32) -> bool {
        if ch < 128 {
            self.ascii[ch as usize]
        } else {
            self.ops.iter().any(|&pc| matcher::unit_accepts(code, pc, ch))
        }
    }
}

fn union(a: Option<Vec<usize>>, b: Option<Vec<usize>>) -> Option<Vec<usize>> {
    let mut a = a?;
    a.extend(b?);
    Some(a)
}

/// The one-character operations a match starting at code[pc] can consume
/// first, or None when they cannot be told.
fn first(code: &[u32], mut pc: usize, depth: usize) -> Option<Vec<usize>> {
    if depth > MAX_DEPTH {
        return None;
    }
    loop {
        let op = *code.get(pc)?;
        match op {
            MARK | AT => pc += 2,
            // the end of an alternative: on after the BRANCH
            JUMP => pc += 1 + *code.get(pc + 1)? as usize,
            ASSERT if *code.get(pc + 2)? == 0 => {
                // a lookahead at the start: a match here needs its first
                // character to be one the lookahead can take
                match first(code, pc + 3, depth + 1) {
                    Some(ops) if !ops.is_empty() => return Some(ops),
                    _ => pc += 1 + *code.get(pc + 1)? as usize,
                }
            }
            ASSERT | ASSERT_NOT => pc += 1 + *code.get(pc + 1)? as usize,
            LITERAL | NOT_LITERAL | LITERAL_IGNORE | NOT_LITERAL_IGNORE | LITERAL_UNI_IGNORE | NOT_LITERAL_UNI_IGNORE
            | ANY | ANY_ALL | IN | IN_IGNORE | IN_UNI_IGNORE | CATEGORY => return Some(vec![pc]),
            BRANCH => {
                let mut q = pc + 1;
                let mut out = Vec::new();
                loop {
                    let skip = *code.get(q)? as usize;
                    if skip == 0 {
                        return Some(out);
                    }
                    out.extend(first(code, q + 1, depth + 1)?);
                    q += skip;
                }
            }
            REPEAT_ONE | MIN_REPEAT_ONE | POSSESSIVE_REPEAT_ONE => {
                let skip = *code.get(pc + 1)? as usize;
                let min = *code.get(pc + 2)?;
                let item = vec![pc + 4];
                if min >= 1 {
                    return Some(item);
                }
                return union(Some(item), first(code, pc + 1 + skip, depth + 1));
            }
            REPEAT | POSSESSIVE_REPEAT => {
                let skip = *code.get(pc + 1)? as usize;
                let min = *code.get(pc + 2)?;
                let body = first(code, pc + 4, depth + 1);
                if min >= 1 {
                    return body;
                }
                // the tail, after the UNTIL (or the possessive repeat's SUCCESS)
                return union(body, first(code, pc + 1 + skip + 1, depth + 1));
            }
            ATOMIC_GROUP => return first(code, pc + 2, depth + 1),
            _ => return None, // SUCCESS, FAILURE, UNTILs, GROUPREF*, …
        }
    }
}

/// The first-character filter of a compiled program, when it has one worth
/// using (sre's own INFO prefix or charset scan comes first).
pub fn first_set(code: &[u32]) -> Option<FirstSet> {
    if code.first() != Some(&INFO) {
        return None;
    }
    // (a pattern that can match the empty string gets no filter from
    // first(), which then meets SUCCESS, unless a lookahead needs a character)
    if code[2] & (INFO_PREFIX | INFO_CHARSET) != 0 {
        return None;
    }
    let pc = 1 + code[1] as usize;
    if code.get(pc) == Some(&AT) && matches!(code.get(pc + 1), Some(&AT_BEGINNING) | Some(&AT_BEGINNING_STRING)) {
        return None;
    }
    first_set_at(code, pc)
}

/// The characters a match of the program at code[pc] must start with, when
/// it must consume one (None: no filter, or one that would take everything).
pub fn first_set_at(code: &[u32], pc: usize) -> Option<FirstSet> {
    let ops = first(code, pc, 0)?;
    if ops.is_empty() || ops.iter().any(|&o| matches!(code[o], ANY | ANY_ALL)) {
        return None;
    }
    let mut ascii = [false; 128];
    for (c, slot) in ascii.iter_mut().enumerate() {
        *slot = ops.iter().any(|&pc| matcher::unit_accepts(code, pc, c as u32));
    }
    if ascii.iter().all(|&x| x) {
        return None;
    }
    Some(FirstSet { ops, ascii })
}
