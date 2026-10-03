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
//!
//! For a search (StartSet), the zero-width tests a path makes before its
//! first character are kept with it and made too: a one-character
//! lookbehind (`(?<![\w$.])` before a name, `(?<![^\n])` at a line's start)
//! and the position tests of `\b`, `^` and the like. Most of the scanner's
//! patterns start a name after a character that cannot be part of one, so
//! the matcher is entered at the first letter of a name, not at every
//! letter. Each test is the matcher's own, made at the same position before
//! anything is consumed, so a position where every path fails one is a
//! position where the matcher would fail: no answer changes.

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

// ---------------- where a search's match can start ----------------

/// Most tests a path keeps (more are not made: a filter that takes more
/// positions than it could is still exact).
const MAX_TESTS: usize = 3;

/// A zero-width test a path makes where the match starts, before it
/// consumes a character.
#[derive(Clone, Copy, Debug)]
enum Test {
    /// a lookbehind of one character: the character before the start must
    /// (`neg`: must not) be one the operation at `op` takes; `ascii`: which
    /// ASCII characters it takes
    Before { op: usize, neg: bool, ascii: u128 },
    /// a position test (`\b`, `\B`, `^`, `$` …), SRE(at)'s own
    At(u32),
}

impl Test {
    #[inline]
    fn holds(&self, code: &[u32], s: &[u32], p: usize, end: usize) -> bool {
        match *self {
            Test::Before { op, neg, ascii } => {
                if p == 0 {
                    // (sre: a lookbehind cannot look before the string; a
                    // negative one then holds, a positive one fails)
                    return neg;
                }
                let c = s[p - 1];
                let takes = if c < 128 { ascii & (1u128 << c) != 0 } else { matcher::unit_accepts(code, op, c) };
                takes != neg
            }
            Test::At(at) => matcher::at_pos(s, end, p, at),
        }
    }
}

/// One way a match can start: the tests it makes, then the operation that
/// consumes its first character.
#[derive(Clone, Debug)]
struct Start {
    tests: Vec<Test>,
    op: usize,
}

impl Start {
    #[inline]
    fn holds(&self, code: &[u32], s: &[u32], p: usize, end: usize) -> bool {
        self.tests.iter().all(|t| t.holds(code, s, p, end))
    }
}

/// Where a search's match can start: a position whose character no start
/// takes, or whose tests all of those that take it fail, is not tried.
pub struct StartSet {
    starts: Vec<Start>,
    /// ASCII characters a start without tests takes (tried at once)
    free: u128,
    /// for each ASCII character, the starts with tests that take it
    by_ascii: Vec<Vec<u16>>,
}

impl StartSet {
    /// For a person: how many starts, and the tests of each.
    pub fn describe(&self) -> String {
        let free = (0..128u32).filter(|c| self.free & (1u128 << c) != 0).count();
        let tests: Vec<String> = self
            .starts
            .iter()
            .filter(|s| !s.tests.is_empty())
            .map(|s| {
                s.tests
                    .iter()
                    .map(|t| match t {
                        Test::Before { neg, .. } => if *neg { "(?<!.)".to_string() } else { "(?<=.)".to_string() },
                        Test::At(a) => format!("at{}", a),
                    })
                    .collect::<Vec<_>>()
                    .join("+")
            })
            .collect();
        format!("{} starts, {} ASCII characters untested; tested: {}", self.starts.len(), free, tests.join(" "))
    }

    /// Can a match start at s[p] (p < end; `end`: the search's end)?
    #[inline]
    pub fn may_start(&self, code: &[u32], s: &[u32], p: usize, end: usize) -> bool {
        let ch = s[p];
        if ch < 128 {
            self.free & (1u128 << ch) != 0
                || self.by_ascii[ch as usize].iter().any(|&k| self.starts[k as usize].holds(code, s, p, end))
        } else {
            self.starts.iter().any(|st| matcher::unit_accepts(code, st.op, ch) && st.holds(code, s, p, end))
        }
    }
}

/// The test of a one-character lookbehind at code[pc] (ASSERT or
/// ASSERT_NOT, back 1, a body of one operation unit() knows and SUCCESS).
fn before_test(code: &[u32], pc: usize) -> Option<Test> {
    let neg = code[pc] == ASSERT_NOT;
    if *code.get(pc + 2)? != 1 {
        return None;
    }
    let body = pc + 3;
    let len = match *code.get(body)? {
        LITERAL | NOT_LITERAL | LITERAL_IGNORE | NOT_LITERAL_IGNORE | LITERAL_UNI_IGNORE | NOT_LITERAL_UNI_IGNORE
        | CATEGORY => 2,
        ANY | ANY_ALL => 1,
        IN | IN_IGNORE | IN_UNI_IGNORE => 1 + *code.get(body + 1)? as usize,
        _ => return None,
    };
    if *code.get(body + len)? != SUCCESS || !matcher::unit_known(code, body) {
        return None;
    }
    let mut ascii = 0u128;
    for c in 0..128u32 {
        if matcher::unit_accepts(code, body, c) {
            ascii |= 1u128 << c;
        }
    }
    Some(Test::Before { op: body, neg, ascii })
}

fn with(tests: &[Test], t: Test) -> Vec<Test> {
    let mut v = tests.to_vec();
    if v.len() < MAX_TESTS {
        v.push(t);
    }
    v
}

fn union_starts(a: Option<Vec<Start>>, b: Option<Vec<Start>>) -> Option<Vec<Start>> {
    let mut a = a?;
    a.extend(b?);
    Some(a)
}

/// first(), keeping the tests each path makes on the way (all of them at
/// the position the match starts, as nothing is consumed before them).
fn starts(code: &[u32], mut pc: usize, depth: usize, tests: &[Test]) -> Option<Vec<Start>> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut tests = tests.to_vec();
    loop {
        let op = *code.get(pc)?;
        match op {
            MARK => pc += 2,
            AT => {
                tests = with(&tests, Test::At(*code.get(pc + 1)?));
                pc += 2;
            }
            JUMP => pc += 1 + *code.get(pc + 1)? as usize,
            ASSERT if *code.get(pc + 2)? == 0 => {
                // a lookahead at the start: its first character is the match's
                match starts(code, pc + 3, depth + 1, &tests) {
                    Some(ops) if !ops.is_empty() => return Some(ops),
                    _ => pc += 1 + *code.get(pc + 1)? as usize,
                }
            }
            ASSERT | ASSERT_NOT => {
                if let Some(t) = before_test(code, pc) {
                    tests = with(&tests, t);
                }
                pc += 1 + *code.get(pc + 1)? as usize;
            }
            LITERAL | NOT_LITERAL | LITERAL_IGNORE | NOT_LITERAL_IGNORE | LITERAL_UNI_IGNORE | NOT_LITERAL_UNI_IGNORE
            | ANY | ANY_ALL | IN | IN_IGNORE | IN_UNI_IGNORE | CATEGORY => return Some(vec![Start { tests, op: pc }]),
            BRANCH => {
                let mut q = pc + 1;
                let mut out = Vec::new();
                loop {
                    let skip = *code.get(q)? as usize;
                    if skip == 0 {
                        return Some(out);
                    }
                    out.extend(starts(code, q + 1, depth + 1, &tests)?);
                    q += skip;
                }
            }
            REPEAT_ONE | MIN_REPEAT_ONE | POSSESSIVE_REPEAT_ONE => {
                let skip = *code.get(pc + 1)? as usize;
                let min = *code.get(pc + 2)?;
                let item = vec![Start { tests: tests.clone(), op: pc + 4 }];
                if min >= 1 {
                    return Some(item);
                }
                return union_starts(Some(item), starts(code, pc + 1 + skip, depth + 1, &tests));
            }
            REPEAT | POSSESSIVE_REPEAT => {
                let skip = *code.get(pc + 1)? as usize;
                let min = *code.get(pc + 2)?;
                let body = starts(code, pc + 4, depth + 1, &tests);
                if min >= 1 {
                    return body;
                }
                return union_starts(body, starts(code, pc + 1 + skip + 1, depth + 1, &tests));
            }
            ATOMIC_GROUP => return starts(code, pc + 2, depth + 1, &tests),
            _ => return None,
        }
    }
}

/// Where a search's match can start, when that can be told and filters
/// something (sre's own INFO prefix or charset scan comes first).
pub fn start_set(code: &[u32]) -> Option<StartSet> {
    if code.first() != Some(&INFO) {
        return None;
    }
    if code[2] & (INFO_PREFIX | INFO_CHARSET) != 0 {
        return None;
    }
    let pc = 1 + code[1] as usize;
    if code.get(pc) == Some(&AT) && matches!(code.get(pc + 1), Some(&AT_BEGINNING) | Some(&AT_BEGINNING_STRING)) {
        return None;
    }
    let starts = starts(code, pc, 0, &[])?;
    if starts.is_empty() || starts.len() > u16::MAX as usize {
        return None;
    }
    let mut free = 0u128;
    let mut by_ascii: Vec<Vec<u16>> = vec![Vec::new(); 128];
    for (k, st) in starts.iter().enumerate() {
        for c in 0..128u32 {
            if matcher::unit_accepts(code, st.op, c) {
                if st.tests.is_empty() {
                    free |= 1u128 << c;
                } else {
                    by_ascii[c as usize].push(k as u16);
                }
            }
        }
    }
    for (c, list) in by_ascii.iter_mut().enumerate() {
        if free & (1u128 << c) != 0 {
            list.clear(); // (taken at once)
        }
    }
    if free == u128::MAX {
        return None; // (every ASCII character, untested: no filter)
    }
    Some(StartSet { starts, free, by_ascii })
}
