// SPDX-License-Identifier: Apache-2.0 AND Python-2.0.1
//
// A Rust translation of CPython's Modules/_sre/sre_lib.h,
// changed as rust/NOTICE summarizes, and distributed under CPython's
// license (rust/LICENSE-PYTHON) as well as Lazaret's. The original's
// notices:
//
//   Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved.
//   See the sre.c file for information on usage and redistribution.
//
//   (Modules/_sre/sre.c:)
//   This version of the SRE library can be redistributed under CNRI's
//   Python 1.6 license.  For any other use, please contact Secret Labs
//   AB (info@pythonware.com).
//
//   Copyright (c) 2001 Python Software Foundation; All Rights Reserved

//! sre's matching engine (Modules/_sre/sre_lib.h, CPython 3.11-3.14),
//! ported operation for operation: SRE(match) with its context stack on the
//! heap (the recursion of a backtracking step is a pushed context, so no
//! pattern and no input can overflow the call stack), SRE(count),
//! SRE(charset), SRE(at) and SRE(search) with its literal-prefix and
//! first-character scans. Positions are code-point indices into the string.
//!
//! Each dispatched operation spends one step of the call's budget
//! (crate::budget); once it is gone every match fails at once and the call
//! reports it (Python's `re` has no bound, so neither answer is used then).

use super::constants::*;
use super::prog::Prog;
use crate::budget;
use crate::unicode;

/// Stands for C's NULL pointer where a position is compared with one.
const NULL: usize = usize::MAX;
const STEP_BATCH: u64 = 4096;

pub struct Rep {
    count: isize,
    pattern: usize,
    prev: Option<usize>,
    last_ptr: usize,
}

pub struct State<'s> {
    pub s: &'s [u32],
    pub start: usize,
    pub end: usize,
    pub ptr: usize,
    pub pos: usize,
    pub endpos: usize,
    pub mark: Vec<usize>,
    pub lastmark: isize,
    pub lastindex: isize,
    repeat: Option<usize>,
    reps: Vec<Rep>,
    free_reps: Vec<usize>,
    data: Vec<usize>,
    pub match_all: bool,
    pub must_advance: bool,
    steps: u64,
    pub aborted: bool,
    /// the context stack, kept between calls (SRE(match) runs once per start
    /// position of a search: it must not allocate each time)
    pool: Vec<Ctx>,
}

/// A matcher's buffers, kept by the thread between searches: most searches
/// are of short texts, where growing them each time would cost more than
/// the matching.
#[derive(Default)]
struct Buffers {
    mark: Vec<usize>,
    reps: Vec<Rep>,
    free_reps: Vec<usize>,
    data: Vec<usize>,
    pool: Vec<Ctx>,
}

/// Buffers above this many entries go back to the allocator, not the pool.
const KEEP_BUFFER: usize = 1 << 14;
/// States alive at once on a thread whose buffers are kept (a finditer
/// open while another search runs needs two).
const KEEP_STATES: usize = 8;

thread_local! {
    static SPARE: std::cell::RefCell<Vec<Buffers>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl<'s> State<'s> {
    /// state_init: `pos` and `endpos` clamped to the string.
    pub fn new(s: &'s [u32], groups: usize, pos: isize, endpos: isize) -> Self {
        let length = s.len() as isize;
        let start = pos.clamp(0, length) as usize;
        let end = endpos.clamp(0, length) as usize;
        let mut b = SPARE.with(|p| p.try_borrow_mut().ok().and_then(|mut p| p.pop())).unwrap_or_default();
        b.mark.clear();
        b.mark.resize(groups * 2, NULL);
        b.reps.clear();
        b.free_reps.clear();
        b.data.clear();
        b.pool.clear();
        State {
            s,
            start,
            end,
            ptr: start,
            pos: start,
            endpos: end,
            mark: b.mark,
            lastmark: -1,
            lastindex: -1,
            repeat: None,
            reps: b.reps,
            free_reps: b.free_reps,
            data: b.data,
            match_all: false,
            must_advance: false,
            steps: 0,
            aborted: false,
            pool: b.pool,
        }
    }

    /// state_reset.
    pub fn reset(&mut self) {
        self.lastmark = -1;
        self.lastindex = -1;
        self.repeat = None;
        self.data.clear();
    }

    fn alloc_rep(&mut self, rep: Rep) -> usize {
        match self.free_reps.pop() {
            Some(i) => {
                self.reps[i] = rep;
                i
            }
            None => {
                self.reps.push(rep);
                self.reps.len() - 1
            }
        }
    }

    fn free_rep(&mut self, i: usize) {
        self.free_reps.push(i);
    }

    #[inline]
    fn tick(&mut self) -> bool {
        self.steps += 1;
        if self.steps >= STEP_BATCH {
            self.steps = 0;
            if !budget::spend(STEP_BATCH) {
                self.aborted = true;
                return false;
            }
        }
        !self.aborted
    }

    fn mark_push(&mut self, lastmark: isize) {
        if lastmark >= 0 {
            let n = (lastmark + 1) as usize;
            self.data.extend_from_slice(&self.mark[..n]);
        }
    }
    fn mark_pop(&mut self, lastmark: isize) {
        if lastmark >= 0 {
            let n = (lastmark + 1) as usize;
            let at = self.data.len() - n;
            self.mark[..n].copy_from_slice(&self.data[at..]);
            self.data.truncate(at);
        }
    }
    fn mark_pop_keep(&mut self, lastmark: isize) {
        if lastmark >= 0 {
            let n = (lastmark + 1) as usize;
            let at = self.data.len() - n;
            self.mark[..n].copy_from_slice(&self.data[at..]);
        }
    }
    fn mark_pop_discard(&mut self, lastmark: isize) {
        if lastmark >= 0 {
            let n = (lastmark + 1) as usize;
            let at = self.data.len() - n;
            self.data.truncate(at);
        }
    }
}

impl Drop for State<'_> {
    fn drop(&mut self) {
        let b = Buffers {
            mark: std::mem::take(&mut self.mark),
            reps: std::mem::take(&mut self.reps),
            free_reps: std::mem::take(&mut self.free_reps),
            data: std::mem::take(&mut self.data),
            pool: std::mem::take(&mut self.pool),
        };
        if b.pool.capacity().max(b.data.capacity()).max(b.reps.capacity()) > KEEP_BUFFER {
            return;
        }
        SPARE.with(|p| {
            if let Ok(mut p) = p.try_borrow_mut() {
                if p.len() < KEEP_STATES {
                    p.push(b);
                }
            }
        });
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Jump {
    None,
    MaxUntil1,
    MaxUntil2,
    MaxUntil3,
    MinUntil1,
    MinUntil2,
    MinUntil3,
    Repeat,
    RepeatOne1,
    RepeatOne2,
    MinRepeatOne,
    Branch,
    Assert,
    AssertNot,
    PossRepeat1,
    PossRepeat2,
    AtomicGroup,
}

struct Ctx {
    count: isize,
    chr: u32,
    rep: usize,
    lastmark: isize,
    lastindex: isize,
    pattern: usize,
    ptr: usize,
    toplevel: bool,
    jump: Jump,
}

impl Ctx {
    fn new(pattern: usize, toplevel: bool, jump: Jump) -> Self {
        Ctx { count: 0, chr: 0, rep: 0, lastmark: -1, lastindex: -1, pattern, ptr: 0, toplevel, jump }
    }
}

#[inline]
fn lower_ascii(c: u32) -> u32 {
    if (0x41..=0x5A).contains(&c) {
        c + 32
    } else {
        c
    }
}

fn is_ascii_word(c: u32) -> bool {
    c <= 0x7A && ((c as u8).is_ascii_alphanumeric() || c == 0x5F)
}

fn category(cat: u32, c: u32) -> bool {
    match cat {
        CATEGORY_DIGIT => (0x30..=0x39).contains(&c),
        CATEGORY_NOT_DIGIT => !(0x30..=0x39).contains(&c),
        CATEGORY_SPACE => matches!(c, 0x09..=0x0D | 0x20),
        CATEGORY_NOT_SPACE => !matches!(c, 0x09..=0x0D | 0x20),
        CATEGORY_WORD => is_ascii_word(c),
        CATEGORY_NOT_WORD => !is_ascii_word(c),
        CATEGORY_LINEBREAK => c == 0x0A,
        CATEGORY_NOT_LINEBREAK => c != 0x0A,
        // (LOCALE never reaches a str pattern)
        CATEGORY_LOC_WORD => is_ascii_word(c),
        CATEGORY_LOC_NOT_WORD => !is_ascii_word(c),
        CATEGORY_UNI_DIGIT => unicode::is_decimal(c),
        CATEGORY_UNI_NOT_DIGIT => !unicode::is_decimal(c),
        CATEGORY_UNI_SPACE => unicode::is_space(c),
        CATEGORY_UNI_NOT_SPACE => !unicode::is_space(c),
        CATEGORY_UNI_WORD => unicode::is_word(c),
        CATEGORY_UNI_NOT_WORD => !unicode::is_word(c),
        CATEGORY_UNI_LINEBREAK => unicode::is_linebreak(c),
        CATEGORY_UNI_NOT_LINEBREAK => !unicode::is_linebreak(c),
        _ => false,
    }
}

/// SRE(charset): is `ch` a member of the set at code[pc..]?
pub fn charset(code: &[u32], mut pc: usize, ch: u32) -> bool {
    let mut ok = true;
    loop {
        let op = match code.get(pc) {
            Some(&op) => op,
            None => return false,
        };
        pc += 1;
        match op {
            FAILURE => return !ok,
            LITERAL => {
                if ch == code[pc] {
                    return ok;
                }
                pc += 1;
            }
            CATEGORY => {
                if category(code[pc], ch) {
                    return ok;
                }
                pc += 1;
            }
            CHARSET => {
                if ch < 256 && code[pc + (ch as usize) / 32] & (1u32 << (ch & 31)) != 0 {
                    return ok;
                }
                pc += 8;
            }
            RANGE => {
                if code[pc] <= ch && ch <= code[pc + 1] {
                    return ok;
                }
                pc += 2;
            }
            RANGE_UNI_IGNORE => {
                if code[pc] <= ch && ch <= code[pc + 1] {
                    return ok;
                }
                let uch = unicode::sre_upper(ch);
                if code[pc] <= uch && uch <= code[pc + 1] {
                    return ok;
                }
                pc += 2;
            }
            NEGATE => ok = !ok,
            BIGCHARSET => {
                let count = code[pc] as usize;
                pc += 1;
                if ch < 0x10000 {
                    let block = code[pc + (ch >> 8) as usize] as usize;
                    let bit = block * 256 + (ch & 255) as usize;
                    if code[pc + 256 + bit / 32] & (1u32 << (bit & 31)) != 0 {
                        return ok;
                    }
                }
                pc += 256 + count * 8;
            }
            _ => return false,
        }
    }
}

/// SRE(at).
fn at(st: &State, ptr: usize, at: u32) -> bool {
    at_pos(st.s, st.end, ptr, at)
}

/// SRE(at) at `ptr` of `s` searched up to `end` (the state's end).
pub fn at_pos(s: &[u32], end: usize, ptr: usize, at: u32) -> bool {
    match at {
        AT_BEGINNING | AT_BEGINNING_STRING => ptr == 0,
        AT_BEGINNING_LINE => ptr == 0 || s[ptr - 1] == 0x0A,
        AT_END => (end.wrapping_sub(ptr) == 1 && s[ptr] == 0x0A) || ptr == end,
        AT_END_LINE => ptr == end || s.get(ptr) == Some(&0x0A),
        AT_END_STRING => ptr == end,
        AT_BOUNDARY | AT_NON_BOUNDARY | AT_LOC_BOUNDARY | AT_LOC_NON_BOUNDARY => {
            if end == 0 {
                return false;
            }
            let thatp = ptr > 0 && is_ascii_word(s[ptr - 1]);
            let thisp = ptr < end && is_ascii_word(s[ptr]);
            if at == AT_BOUNDARY || at == AT_LOC_BOUNDARY {
                thisp != thatp
            } else {
                thisp == thatp
            }
        }
        AT_UNI_BOUNDARY | AT_UNI_NON_BOUNDARY => {
            if end == 0 {
                return false;
            }
            let thatp = ptr > 0 && unicode::is_word(s[ptr - 1]);
            let thisp = ptr < end && unicode::is_word(s[ptr]);
            if at == AT_UNI_BOUNDARY {
                thisp != thatp
            } else {
                thisp == thatp
            }
        }
        _ => false,
    }
}

/// One character against a one-character operation (REPEAT_ONE's item).
fn unit(code: &[u32], pc: usize, ch: u32) -> Option<bool> {
    Some(match code[pc] {
        LITERAL => ch == code[pc + 1],
        NOT_LITERAL => ch != code[pc + 1],
        LITERAL_IGNORE => lower_ascii(ch) == code[pc + 1],
        NOT_LITERAL_IGNORE => lower_ascii(ch) != code[pc + 1],
        LITERAL_UNI_IGNORE => unicode::sre_lower(ch) == code[pc + 1],
        NOT_LITERAL_UNI_IGNORE => unicode::sre_lower(ch) != code[pc + 1],
        ANY => ch != 0x0A,
        ANY_ALL => true,
        IN => charset(code, pc + 2, ch),
        IN_IGNORE => charset(code, pc + 2, lower_ascii(ch)),
        IN_UNI_IGNORE => charset(code, pc + 2, unicode::sre_lower(ch)),
        CATEGORY => category(code[pc + 1], ch),
        _ => return None,
    })
}

/// Does the one-character operation at code[pc] accept `ch`?
pub fn unit_accepts(code: &[u32], pc: usize, ch: u32) -> bool {
    unit(code, pc, ch).unwrap_or(true)
}

/// Is code[pc] a one-character operation unit() answers for exactly?
pub fn unit_known(code: &[u32], pc: usize) -> bool {
    unit(code, pc, 0).is_some()
}

/// SRE(count): how many times the one-character item at code[pc] matches
/// from state.ptr, at most `maxcount`.
fn count(st: &mut State, prog: &Prog, pc: usize, maxcount: u32) -> Result<isize, ()> {
    let code = &prog.code[..];
    let start = st.ptr;
    let mut end = st.end;
    if maxcount != MAXREPEAT && (maxcount as usize) < end.saturating_sub(start) {
        end = start + maxcount as usize;
    }
    let s = st.s;
    let mut ptr = start;
    match code[pc] {
        ANY_ALL => ptr = end.max(start),
        LITERAL => {
            let c = code[pc + 1];
            while ptr < end && s[ptr] == c {
                ptr += 1;
            }
        }
        IN | IN_IGNORE | IN_UNI_IGNORE => {
            while ptr < end && prog.in_accepts(pc, s[ptr]) {
                ptr += 1;
            }
        }
        _ => {
            if unit(code, pc, 0).is_none() {
                // any other item: SRE(match) on it, one character at a time
                while st.ptr < end {
                    let i = sre_match(st, prog, pc, false)?;
                    if !i {
                        break;
                    }
                }
                return Ok((st.ptr - start) as isize);
            }
            while ptr < end && unit(code, pc, s[ptr]) == Some(true) {
                ptr += 1;
            }
        }
    }
    // (a long run is a step per character: count it)
    let n = ptr - start;
    if n as u64 >= STEP_BATCH && !budget::spend(n as u64 / 16) {
        st.aborted = true;
        return Err(());
    }
    Ok(n as isize)
}

enum Phase {
    Entrance,
    Dispatch,
    Return(bool),
    Resume(Jump, bool),
    BranchNext,
    RepeatOne1Loop,
    RepeatOne2Loop,
    MinRepeatOneLoop,
    MaxUntilTail,
    PossRepeatMin,
    PossRepeatMore,
    PossRepeatDone,
}

/// SRE(match): does the pattern at code[pc0..] match at state.ptr?
/// Err(()) when the call's budget is gone or the program is malformed.
pub fn sre_match(st: &mut State, prog: &Prog, pc0: usize, toplevel: bool) -> Result<bool, ()> {
    let mut stack = std::mem::take(&mut st.pool);
    stack.clear();
    stack.push(Ctx::new(pc0, toplevel, Jump::None));
    let r = match_with(st, &mut stack, prog, pc0);
    st.pool = stack;
    r
}

fn match_with(st: &mut State, stack: &mut Vec<Ctx>, prog: &Prog, pc0: usize) -> Result<bool, ()> {
    let code = &prog.code[..];
    let end = st.end;
    let s = st.s;
    let mut pattern = pc0;
    let mut ptr = st.ptr;
    let mut phase = Phase::Entrance;

    'main: loop {
        macro_rules! ctx {
            () => {
                stack.last_mut().ok_or(())?
            };
        }
        macro_rules! do_jump {
            ($jump:expr, $next:expr, $toplevel:expr) => {{
                let next = $next;
                let tl = $toplevel;
                {
                    let c = ctx!();
                    c.pattern = pattern;
                    c.ptr = ptr;
                }
                stack.push(Ctx::new(next, tl, $jump));
                pattern = next;
                phase = Phase::Entrance;
                continue 'main;
            }};
        }
        macro_rules! fail {
            () => {{
                phase = Phase::Return(false);
                continue 'main;
            }};
        }
        macro_rules! succeed {
            () => {{
                phase = Phase::Return(true);
                continue 'main;
            }};
        }
        macro_rules! lastmark_save {
            () => {{
                let (lm, li) = (st.lastmark, st.lastindex);
                let c = ctx!();
                c.lastmark = lm;
                c.lastindex = li;
            }};
        }
        macro_rules! lastmark_restore {
            () => {{
                let c = ctx!();
                st.lastmark = c.lastmark;
                st.lastindex = c.lastindex;
            }};
        }

        match phase {
            Phase::Entrance => {
                ptr = st.ptr;
                if code[pattern] == INFO {
                    let min = code[pattern + 3] as usize;
                    if min != 0 && end.wrapping_sub(ptr) < min {
                        fail!();
                    }
                    pattern += code[pattern + 1] as usize + 1;
                }
                phase = Phase::Dispatch;
            }
            Phase::Dispatch => loop {
                // (one op after another, without leaving this loop, until
                // one fails, succeeds, calls or needs another phase)
                if !st.tick() {
                    return Err(());
                }
                let op = code[pattern];
                pattern += 1;
                match op {
                    MARK => {
                        let i = code[pattern] as isize;
                        if i & 1 != 0 {
                            st.lastindex = i / 2 + 1;
                        }
                        if i > st.lastmark {
                            let mut j = st.lastmark + 1;
                            while j < i {
                                st.mark[j as usize] = NULL;
                                j += 1;
                            }
                            st.lastmark = i;
                        }
                        st.mark[i as usize] = ptr;
                        pattern += 1;
                    }
                    LITERAL => {
                        if ptr >= end || s[ptr] != code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    NOT_LITERAL => {
                        if ptr >= end || s[ptr] == code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    SUCCESS => {
                        let c = ctx!();
                        if c.toplevel && ((st.match_all && ptr != st.end) || (st.must_advance && ptr == st.start)) {
                            fail!();
                        }
                        st.ptr = ptr;
                        succeed!();
                    }
                    AT => {
                        if !at(st, ptr, code[pattern]) {
                            fail!();
                        }
                        pattern += 1;
                    }
                    CATEGORY => {
                        if ptr >= end || !category(code[pattern], s[ptr]) {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    ANY => {
                        if ptr >= end || s[ptr] == 0x0A {
                            fail!();
                        }
                        ptr += 1;
                    }
                    ANY_ALL => {
                        if ptr >= end {
                            fail!();
                        }
                        ptr += 1;
                    }
                    IN => {
                        if ptr >= end || !prog.in_accepts(pattern - 1, s[ptr]) {
                            fail!();
                        }
                        pattern += code[pattern] as usize;
                        ptr += 1;
                    }
                    LITERAL_IGNORE => {
                        if ptr >= end || lower_ascii(s[ptr]) != code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    LITERAL_UNI_IGNORE => {
                        if ptr >= end || unicode::sre_lower(s[ptr]) != code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    NOT_LITERAL_IGNORE => {
                        if ptr >= end || lower_ascii(s[ptr]) == code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    NOT_LITERAL_UNI_IGNORE => {
                        if ptr >= end || unicode::sre_lower(s[ptr]) == code[pattern] {
                            fail!();
                        }
                        pattern += 1;
                        ptr += 1;
                    }
                    IN_IGNORE => {
                        if ptr >= end || !prog.in_accepts(pattern - 1, s[ptr]) {
                            fail!();
                        }
                        pattern += code[pattern] as usize;
                        ptr += 1;
                    }
                    IN_UNI_IGNORE => {
                        if ptr >= end || !prog.in_accepts(pattern - 1, s[ptr]) {
                            fail!();
                        }
                        pattern += code[pattern] as usize;
                        ptr += 1;
                    }
                    JUMP | INFO => {
                        pattern += code[pattern] as usize;
                    }
                    BRANCH => {
                        lastmark_save!();
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_push(lm);
                        }
                        phase = Phase::BranchNext;
                        continue 'main;
                    }
                    REPEAT_ONE => {
                        // <REPEAT_ONE> <skip> <1=min> <2=max> item <SUCCESS> tail
                        let min = code[pattern + 1] as usize;
                        if min as isize > end as isize - ptr as isize {
                            fail!();
                        }
                        st.ptr = ptr;
                        let n = count(st, prog, pattern + 3, code[pattern + 2])?;
                        ctx!().count = n;
                        ptr += n as usize;
                        if (n as usize) < min {
                            fail!();
                        }
                        let tail = pattern + code[pattern] as usize;
                        let tl = ctx!().toplevel;
                        if code[tail] == SUCCESS && ptr == st.end && !(tl && st.must_advance && ptr == st.start) {
                            st.ptr = ptr;
                            succeed!();
                        }
                        lastmark_save!();
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_push(lm);
                        }
                        if code[tail] == LITERAL {
                            ctx!().chr = code[tail + 1];
                            phase = Phase::RepeatOne1Loop;
                            continue 'main;
                        } else {
                            phase = Phase::RepeatOne2Loop;
                            continue 'main;
                        }
                    }
                    MIN_REPEAT_ONE => {
                        let min = code[pattern + 1] as usize;
                        if min as isize > end as isize - ptr as isize {
                            fail!();
                        }
                        st.ptr = ptr;
                        if min == 0 {
                            ctx!().count = 0;
                        } else {
                            let n = count(st, prog, pattern + 3, code[pattern + 1])?;
                            if (n as usize) < min {
                                fail!();
                            }
                            ctx!().count = n;
                            ptr += n as usize;
                        }
                        let tail = pattern + code[pattern] as usize;
                        let tl = ctx!().toplevel;
                        if code[tail] == SUCCESS
                            && !(tl && ((st.match_all && ptr != st.end) || (st.must_advance && ptr == st.start)))
                        {
                            st.ptr = ptr;
                            succeed!();
                        }
                        lastmark_save!();
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_push(lm);
                        }
                        phase = Phase::MinRepeatOneLoop;
                        continue 'main;
                    }
                    POSSESSIVE_REPEAT_ONE => {
                        let min = code[pattern + 1] as usize;
                        if ptr + min > end {
                            fail!();
                        }
                        st.ptr = ptr;
                        let n = count(st, prog, pattern + 3, code[pattern + 2])?;
                        ctx!().count = n;
                        ptr += n as usize;
                        if (n as usize) < min {
                            fail!();
                        }
                        pattern += code[pattern] as usize;
                        let tl = ctx!().toplevel;
                        if code[pattern] == SUCCESS && ptr == st.end && !(tl && st.must_advance && ptr == st.start) {
                            st.ptr = ptr;
                            succeed!();
                        }
                    }
                    REPEAT => {
                        let prev = st.repeat;
                        let rep = st.alloc_rep(Rep { count: -1, pattern, prev, last_ptr: NULL });
                        ctx!().rep = rep;
                        st.repeat = Some(rep);
                        st.ptr = ptr;
                        do_jump!(Jump::Repeat, pattern + code[pattern] as usize, ctx!().toplevel);
                    }
                    MAX_UNTIL => {
                        let rep = st.repeat.ok_or(())?;
                        ctx!().rep = rep;
                        st.ptr = ptr;
                        let cnt = st.reps[rep].count + 1;
                        ctx!().count = cnt;
                        let rp = st.reps[rep].pattern;
                        if cnt < code[rp + 1] as isize {
                            st.reps[rep].count = cnt;
                            do_jump!(Jump::MaxUntil1, rp + 3, ctx!().toplevel);
                        }
                        let max = code[rp + 2];
                        if ((cnt as u64) < max as u64 || max == MAXREPEAT) && st.ptr != st.reps[rep].last_ptr {
                            st.reps[rep].count = cnt;
                            lastmark_save!();
                            let lm = ctx!().lastmark;
                            st.mark_push(lm);
                            let lp = st.reps[rep].last_ptr;
                            st.data.push(lp);
                            st.reps[rep].last_ptr = st.ptr;
                            do_jump!(Jump::MaxUntil2, rp + 3, ctx!().toplevel);
                        }
                        phase = Phase::MaxUntilTail;
                        continue 'main;
                    }
                    MIN_UNTIL => {
                        let rep = st.repeat.ok_or(())?;
                        ctx!().rep = rep;
                        st.ptr = ptr;
                        let cnt = st.reps[rep].count + 1;
                        ctx!().count = cnt;
                        let rp = st.reps[rep].pattern;
                        if cnt < code[rp + 1] as isize {
                            st.reps[rep].count = cnt;
                            do_jump!(Jump::MinUntil1, rp + 3, ctx!().toplevel);
                        }
                        // see if the tail matches
                        st.repeat = st.reps[rep].prev;
                        lastmark_save!();
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_push(lm);
                        }
                        do_jump!(Jump::MinUntil2, pattern, ctx!().toplevel);
                    }
                    POSSESSIVE_REPEAT => {
                        st.ptr = ptr;
                        let prev = st.repeat;
                        let rep = st.alloc_rep(Rep { count: -1, pattern: NULL, prev, last_ptr: NULL });
                        ctx!().rep = rep;
                        st.repeat = Some(rep);
                        ctx!().count = 0;
                        phase = Phase::PossRepeatMin;
                        continue 'main;
                    }
                    ATOMIC_GROUP => {
                        st.ptr = ptr;
                        do_jump!(Jump::AtomicGroup, pattern + 1, false);
                    }
                    GROUPREF | GROUPREF_IGNORE | GROUPREF_UNI_IGNORE | GROUPREF_LOC_IGNORE => {
                        let groupref = code[pattern] as isize * 2;
                        if groupref >= st.lastmark {
                            fail!();
                        }
                        let p0 = st.mark[groupref as usize];
                        let e = st.mark[groupref as usize + 1];
                        if p0 == NULL || e == NULL || e < p0 {
                            fail!();
                        }
                        let mut p = p0;
                        let mut ok = true;
                        while p < e {
                            if ptr >= end {
                                ok = false;
                                break;
                            }
                            let (a, b) = (s[ptr], s[p]);
                            let same = match op {
                                GROUPREF => a == b,
                                GROUPREF_UNI_IGNORE => unicode::sre_lower(a) == unicode::sre_lower(b),
                                _ => lower_ascii(a) == lower_ascii(b),
                            };
                            if !same {
                                ok = false;
                                break;
                            }
                            p += 1;
                            ptr += 1;
                        }
                        if !ok {
                            fail!();
                        }
                        pattern += 1;
                    }
                    GROUPREF_EXISTS => {
                        let groupref = code[pattern] as isize * 2;
                        if groupref >= st.lastmark {
                            pattern += code[pattern + 1] as usize;
                            continue;
                        }
                        let p0 = st.mark[groupref as usize];
                        let e = st.mark[groupref as usize + 1];
                        if p0 == NULL || e == NULL || e < p0 {
                            pattern += code[pattern + 1] as usize;
                            continue;
                        }
                        pattern += 2;
                    }
                    ASSERT => {
                        let back = code[pattern + 1] as usize;
                        if ptr < back {
                            fail!();
                        }
                        st.ptr = ptr - back;
                        do_jump!(Jump::Assert, pattern + 2, false);
                    }
                    ASSERT_NOT => {
                        let back = code[pattern + 1] as usize;
                        if ptr >= back {
                            st.ptr = ptr - back;
                            lastmark_save!();
                            if st.repeat.is_some() {
                                let lm = ctx!().lastmark;
                                st.mark_push(lm);
                            }
                            do_jump!(Jump::AssertNot, pattern + 2, false);
                        }
                        pattern += code[pattern] as usize;
                    }
                    FAILURE => fail!(),
                    _ => return Err(()),
                }
            },
            Phase::Return(ret) => {
                let done = stack.pop().ok_or(())?;
                if stack.is_empty() {
                    return Ok(ret);
                }
                let c = ctx!();
                pattern = c.pattern;
                ptr = c.ptr;
                phase = Phase::Resume(done.jump, ret);
            }
            Phase::Resume(jump, ret) => match jump {
                Jump::None => return Err(()),
                Jump::Branch => {
                    if ret {
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_pop_discard(lm);
                        }
                        succeed!();
                    }
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_keep(lm);
                    }
                    lastmark_restore!();
                    pattern += code[pattern] as usize;
                    phase = Phase::BranchNext;
                }
                Jump::RepeatOne1 => {
                    if ret {
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_pop_discard(lm);
                        }
                        succeed!();
                    }
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_keep(lm);
                    }
                    lastmark_restore!();
                    ptr = ptr.wrapping_sub(1);
                    ctx!().count -= 1;
                    phase = Phase::RepeatOne1Loop;
                }
                Jump::RepeatOne2 => {
                    if ret {
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_pop_discard(lm);
                        }
                        succeed!();
                    }
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_keep(lm);
                    }
                    lastmark_restore!();
                    ptr = ptr.wrapping_sub(1);
                    ctx!().count -= 1;
                    phase = Phase::RepeatOne2Loop;
                }
                Jump::MinRepeatOne => {
                    if ret {
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_pop_discard(lm);
                        }
                        succeed!();
                    }
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_keep(lm);
                    }
                    lastmark_restore!();
                    st.ptr = ptr;
                    let n = count(st, prog, pattern + 3, 1)?;
                    if n == 0 {
                        if st.repeat.is_some() {
                            let lm = ctx!().lastmark;
                            st.mark_pop_discard(lm);
                        }
                        fail!();
                    }
                    ptr += 1;
                    ctx!().count += 1;
                    phase = Phase::MinRepeatOneLoop;
                }
                Jump::Repeat => {
                    let rep = ctx!().rep;
                    st.repeat = st.reps[rep].prev;
                    st.free_rep(rep);
                    phase = Phase::Return(ret);
                }
                Jump::MaxUntil1 => {
                    if ret {
                        succeed!();
                    }
                    let (rep, cnt) = {
                        let c = ctx!();
                        (c.rep, c.count)
                    };
                    st.reps[rep].count = cnt - 1;
                    st.ptr = ptr;
                    fail!();
                }
                Jump::MaxUntil2 => {
                    let rep = ctx!().rep;
                    st.reps[rep].last_ptr = st.data.pop().ok_or(())?;
                    let lm = ctx!().lastmark;
                    if ret {
                        st.mark_pop_discard(lm);
                        succeed!();
                    }
                    st.mark_pop(lm);
                    lastmark_restore!();
                    let cnt = ctx!().count;
                    st.reps[rep].count = cnt - 1;
                    st.ptr = ptr;
                    phase = Phase::MaxUntilTail;
                }
                Jump::MaxUntil3 => {
                    let rep = ctx!().rep;
                    st.repeat = Some(rep);
                    if ret {
                        succeed!();
                    }
                    st.ptr = ptr;
                    fail!();
                }
                Jump::MinUntil1 => {
                    if ret {
                        succeed!();
                    }
                    let (rep, cnt) = {
                        let c = ctx!();
                        (c.rep, c.count)
                    };
                    st.reps[rep].count = cnt - 1;
                    st.ptr = ptr;
                    fail!();
                }
                Jump::MinUntil2 => {
                    let repeat_of_tail = st.repeat;
                    let (rep, lm, cnt) = {
                        let c = ctx!();
                        (c.rep, c.lastmark, c.count)
                    };
                    st.repeat = Some(rep);
                    if ret {
                        if repeat_of_tail.is_some() {
                            st.mark_pop_discard(lm);
                        }
                        succeed!();
                    }
                    if repeat_of_tail.is_some() {
                        st.mark_pop(lm);
                    }
                    lastmark_restore!();
                    st.ptr = ptr;
                    let rp = st.reps[rep].pattern;
                    let max = code[rp + 2];
                    if ((cnt as u64) >= max as u64 && max != MAXREPEAT) || st.ptr == st.reps[rep].last_ptr {
                        fail!();
                    }
                    st.reps[rep].count = cnt;
                    let lp = st.reps[rep].last_ptr;
                    st.data.push(lp);
                    st.reps[rep].last_ptr = st.ptr;
                    do_jump!(Jump::MinUntil3, rp + 3, ctx!().toplevel);
                }
                Jump::MinUntil3 => {
                    let (rep, cnt) = {
                        let c = ctx!();
                        (c.rep, c.count)
                    };
                    st.reps[rep].last_ptr = st.data.pop().ok_or(())?;
                    if ret {
                        succeed!();
                    }
                    st.reps[rep].count = cnt - 1;
                    st.ptr = ptr;
                    fail!();
                }
                Jump::Assert => {
                    if !ret {
                        fail!();
                    }
                    pattern += code[pattern] as usize;
                    phase = Phase::Dispatch;
                }
                Jump::AssertNot => {
                    let lm = ctx!().lastmark;
                    if ret {
                        if st.repeat.is_some() {
                            st.mark_pop_discard(lm);
                        }
                        fail!();
                    }
                    if st.repeat.is_some() {
                        st.mark_pop(lm);
                    }
                    lastmark_restore!();
                    pattern += code[pattern] as usize;
                    phase = Phase::Dispatch;
                }
                Jump::AtomicGroup => {
                    if !ret {
                        st.ptr = ptr;
                        fail!();
                    }
                    pattern += code[pattern] as usize;
                    ptr = st.ptr;
                    phase = Phase::Dispatch;
                }
                Jump::PossRepeat1 => {
                    if ret {
                        ctx!().count += 1;
                        phase = Phase::PossRepeatMin;
                    } else {
                        st.ptr = ptr;
                        let rep = ctx!().rep;
                        st.repeat = st.reps[rep].prev;
                        st.free_rep(rep);
                        fail!();
                    }
                }
                Jump::PossRepeat2 => {
                    let lm = ctx!().lastmark;
                    if ret {
                        st.mark_pop_discard(lm);
                        ctx!().count += 1;
                        phase = Phase::PossRepeatMore;
                    } else {
                        st.mark_pop(lm);
                        lastmark_restore!();
                        st.ptr = ptr;
                        phase = Phase::PossRepeatDone;
                    }
                }
            },
            Phase::BranchNext => {
                // <BRANCH> <0=skip> code <JUMP> ... <NULL>
                loop {
                    let skip = code[pattern];
                    if skip == 0 {
                        break;
                    }
                    let first = code[pattern + 1];
                    if first == LITERAL && (ptr >= end || s[ptr] != code[pattern + 2]) {
                        pattern += skip as usize;
                        continue;
                    }
                    if first == IN && (ptr >= end || !prog.in_accepts(pattern + 1, s[ptr])) {
                        pattern += skip as usize;
                        continue;
                    }
                    if !prog.can_start(pattern, if ptr < end { Some(s[ptr]) } else { None }) {
                        pattern += skip as usize;
                        continue;
                    }
                    break;
                }
                if code[pattern] == 0 {
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_discard(lm);
                    }
                    fail!();
                }
                st.ptr = ptr;
                do_jump!(Jump::Branch, pattern + 1, ctx!().toplevel);
            }
            Phase::RepeatOne1Loop => {
                let min = code[pattern + 1] as isize;
                let chr = ctx!().chr;
                loop {
                    let c = ctx!();
                    if c.count >= min && (ptr >= end || s[ptr] != chr) {
                        ptr = ptr.wrapping_sub(1);
                        c.count -= 1;
                    } else {
                        break;
                    }
                }
                if ctx!().count < min {
                    if st.repeat.is_some() {
                        let lm = ctx!().lastmark;
                        st.mark_pop_discard(lm);
                    }
                    fail!();
                }
                st.ptr = ptr;
                do_jump!(Jump::RepeatOne1, pattern + code[pattern] as usize, ctx!().toplevel);
            }
            Phase::RepeatOne2Loop => {
                let min = code[pattern + 1] as isize;
                // (a position where the tail cannot start is passed over, as the
                // literal-tail loop above does: prog.rs)
                loop {
                    let c = ctx!();
                    if c.count >= min && !prog.can_start(pattern - 1, if ptr < end { Some(s[ptr]) } else { None }) {
                        ptr = ptr.wrapping_sub(1);
                        c.count -= 1;
                    } else {
                        break;
                    }
                }
                if ctx!().count >= min {
                    st.ptr = ptr;
                    do_jump!(Jump::RepeatOne2, pattern + code[pattern] as usize, ctx!().toplevel);
                }
                if st.repeat.is_some() {
                    let lm = ctx!().lastmark;
                    st.mark_pop_discard(lm);
                }
                fail!();
            }
            Phase::MinRepeatOneLoop => {
                let max = code[pattern + 2];
                if max == MAXREPEAT || ctx!().count <= max as isize {
                    if !prog.can_start(pattern - 1, if ptr < end { Some(s[ptr]) } else { None }) {
                        // the tail cannot start here: one more item, as after a failed tail
                        st.ptr = ptr;
                        let n = count(st, prog, pattern + 3, 1)?;
                        if n == 0 {
                            if st.repeat.is_some() {
                                let lm = ctx!().lastmark;
                                st.mark_pop_discard(lm);
                            }
                            fail!();
                        }
                        ptr += 1;
                        ctx!().count += 1;
                        continue;
                    }
                    st.ptr = ptr;
                    do_jump!(Jump::MinRepeatOne, pattern + code[pattern] as usize, ctx!().toplevel);
                }
                if st.repeat.is_some() {
                    let lm = ctx!().lastmark;
                    st.mark_pop_discard(lm);
                }
                fail!();
            }
            Phase::MaxUntilTail => {
                // cannot match more repeated items here: make sure the tail matches
                let rep = ctx!().rep;
                st.repeat = st.reps[rep].prev;
                do_jump!(Jump::MaxUntil3, pattern, ctx!().toplevel);
            }
            Phase::PossRepeatMin => {
                let min = code[pattern + 1] as isize;
                if ctx!().count < min {
                    do_jump!(Jump::PossRepeat1, pattern + 3, false);
                }
                ptr = NULL;
                phase = Phase::PossRepeatMore;
            }
            Phase::PossRepeatMore => {
                let max = code[pattern + 2];
                let cnt = ctx!().count;
                if ((cnt as u64) < max as u64 || max == MAXREPEAT) && st.ptr != ptr {
                    lastmark_save!();
                    let lm = ctx!().lastmark;
                    st.mark_push(lm);
                    ptr = st.ptr;
                    do_jump!(Jump::PossRepeat2, pattern + 3, false);
                }
                phase = Phase::PossRepeatDone;
            }
            Phase::PossRepeatDone => {
                let rep = ctx!().rep;
                st.repeat = st.reps[rep].prev;
                st.free_rep(rep);
                pattern += code[pattern] as usize + 1;
                ptr = st.ptr;
                phase = Phase::Dispatch;
            }
        }
    }
}

/// SRE(search): the first match at or after state.start.
pub fn sre_search(st: &mut State, prog: &Prog) -> Result<bool, ()> {
    let code = &prog.code[..];
    let first = prog.first.as_ref();
    let s = st.s;
    let mut ptr = st.start;
    let mut end = st.end;
    if ptr > end {
        return Ok(false);
    }
    if let Some(need) = prog.need.as_ref().filter(|_| prog.check_need) {
        // (a text holding none of the strings every match holds)
        #[cfg(feature = "stats")]
        let t0 = std::time::Instant::now();
        let found = need.occurs(s, ptr, end);
        #[cfg(feature = "stats")]
        {
            use std::sync::atomic::Ordering::Relaxed;
            prog.scanned[0].fetch_add(1, Relaxed);
            prog.scanned[1].fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
        }
        if !found {
            return Ok(false);
        }
    }
    let mut pc = 0usize;
    let mut flags = 0u32;
    let mut prefix_len = 0usize;
    let mut prefix_skip = 0usize;
    let mut prefix = 0usize;
    let mut overlap = 0usize;
    let mut has_charset = false;
    if code[0] == INFO {
        flags = code[2];
        let min = code[3] as usize;
        if min != 0 && end - ptr < min {
            return Ok(false);
        }
        if min > 1 {
            end -= min - 1;
            if end <= ptr {
                end = ptr;
            }
        }
        if flags & INFO_PREFIX != 0 {
            prefix_len = code[5] as usize;
            prefix_skip = code[6] as usize;
            prefix = 7;
            overlap = prefix + prefix_len - 1;
        } else if flags & INFO_CHARSET != 0 {
            has_charset = true; // (at code[5]: prog.info_accepts)
        }
        pc = 1 + code[1] as usize;
    }

    if prefix_len == 1 {
        let c = code[prefix];
        let end = st.end;
        st.must_advance = false;
        while ptr < end {
            // (a scan for the first character: one step per character)
            match s[ptr..end].iter().position(|&x| x == c) {
                None => return Ok(false),
                Some(i) => ptr += i,
            }
            if !budget::spend(1) {
                st.aborted = true;
                return Err(());
            }
            st.start = ptr;
            st.ptr = ptr + prefix_skip;
            if flags & INFO_LITERAL != 0 {
                return Ok(true);
            }
            if sre_match(st, prog, pc + 2 * prefix_skip, false)? {
                return Ok(true);
            }
            ptr += 1;
            st.lastmark = -1;
            st.lastindex = -1;
        }
        return Ok(false);
    }

    if prefix_len > 1 {
        let end = st.end;
        if prefix_len > end - ptr {
            return Ok(false);
        }
        if let Some((lit, scan)) = prog.prefix.as_ref().filter(|(lit, _)| lit.len() == prefix_len) {
            // each place the prefix occurs, in order (overlapping ones too):
            // the places sre's own scan of it tries
            let mut from = ptr;
            loop {
                let at = match scan.find(s, lit, from, end) {
                    None => return Ok(false),
                    Some(at) => at,
                };
                // found a potential match
                if !budget::spend(1) {
                    st.aborted = true;
                    return Err(());
                }
                st.must_advance = false;
                st.start = at;
                st.ptr = at + prefix_skip;
                if flags & INFO_LITERAL != 0 {
                    return Ok(true);
                }
                if sre_match(st, prog, pc + 2 * prefix_skip, false)? {
                    return Ok(true);
                }
                st.lastmark = -1;
                st.lastindex = -1;
                from = at + 1;
            }
        }
        while ptr < end {
            let c = code[prefix];
            loop {
                let x = s[ptr];
                ptr += 1;
                if x == c {
                    break;
                }
                if ptr >= end {
                    return Ok(false);
                }
            }
            if ptr >= end {
                return Ok(false);
            }
            let mut i = 1usize;
            st.must_advance = false;
            loop {
                if s[ptr] == code[prefix + i] {
                    i += 1;
                    if i != prefix_len {
                        ptr += 1;
                        if ptr >= end {
                            return Ok(false);
                        }
                        continue;
                    }
                    // found a potential match
                    if !budget::spend(1) {
                        st.aborted = true;
                        return Err(());
                    }
                    st.start = ptr - (prefix_len - 1);
                    st.ptr = ptr - (prefix_len - prefix_skip - 1);
                    if flags & INFO_LITERAL != 0 {
                        return Ok(true);
                    }
                    if sre_match(st, prog, pc + 2 * prefix_skip, false)? {
                        return Ok(true);
                    }
                    ptr += 1;
                    if ptr >= end {
                        return Ok(false);
                    }
                    st.lastmark = -1;
                    st.lastindex = -1;
                }
                i = code[overlap + i] as usize;
                if i == 0 {
                    break;
                }
            }
        }
        return Ok(false);
    }

    if let Some(lead) = &prog.lead {
        // (every match starts with one of the lead strings: only where one
        // starts is a match tried, the way sre tries its charset positions)
        let end = st.end;
        st.must_advance = false;
        loop {
            #[cfg(feature = "stats")]
            let t0 = std::time::Instant::now();
            let next = lead.next_start(s, ptr, end);
            #[cfg(feature = "stats")]
            {
                use std::sync::atomic::Ordering::Relaxed;
                prog.scanned[2].fetch_add(1, Relaxed);
                prog.scanned[3].fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
            }
            match next {
                None => return Ok(false),
                Some(q) => ptr = q,
            }
            st.start = ptr;
            st.ptr = ptr;
            if sre_match(st, prog, pc, false)? {
                return Ok(true);
            }
            ptr += 1;
            st.lastmark = -1;
            st.lastindex = -1;
        }
    }

    if has_charset {
        let end = st.end;
        st.must_advance = false;
        loop {
            while ptr < end && !prog.info_accepts(s[ptr]) {
                // (sre's own first-character scan)
                ptr += 1;
            }
            if ptr >= end {
                return Ok(false);
            }
            st.start = ptr;
            st.ptr = ptr;
            if sre_match(st, prog, pc, false)? {
                return Ok(true);
            }
            ptr += 1;
            st.lastmark = -1;
            st.lastindex = -1;
        }
    }

    // A pattern that starts with ^ under MULTILINE matches only where a line
    // starts (at 0 or after "\n"): no other start is tried (each would fail
    // at its first operation).
    let line_starts = code[pc] == AT && code[pc + 1] == AT_BEGINNING_LINE;
    let line_start = |p: usize| p == 0 || s[p - 1] == 0x0A;
    if let Some(fs) = first {
        // (no match starts where the first character is not one it can take)
        let real_end = st.end;
        let mut p = ptr;
        let mut toplevel = true;
        while p <= end {
            if line_starts && p < real_end && !line_start(p) {
                // (no match starts before the next line does: on to it)
                match super::scan::find1(s, p, real_end, 0x0A) {
                    None => break,
                    Some(nl) => {
                        toplevel = false;
                        st.must_advance = false;
                        p = nl + 1;
                        continue;
                    }
                }
            }
            if p < real_end && (!line_starts || line_start(p)) && fs.may_start(code, s, p, real_end) {
                st.lastmark = -1;
                st.lastindex = -1;
                st.start = p;
                st.ptr = p;
                if sre_match(st, prog, pc, toplevel)? {
                    st.must_advance = false;
                    return Ok(true);
                }
            } else if p >= real_end {
                break;
            }
            toplevel = false;
            st.must_advance = false;
            p += 1;
        }
        return Ok(false);
    }
    st.start = ptr;
    st.ptr = ptr;
    let mut status = sre_match(st, prog, pc, true)?;
    st.must_advance = false;
    if !status && code[pc] == AT && (code[pc + 1] == AT_BEGINNING || code[pc + 1] == AT_BEGINNING_STRING) {
        st.start = end;
        st.ptr = end;
        return Ok(false);
    }
    while !status && ptr < end {
        ptr += 1;
        if line_starts && !line_start(ptr) {
            // (on to where the next line starts: s[ptr - 1] is not "\n")
            ptr = match super::scan::find1(s, ptr, end, 0x0A) {
                Some(nl) => nl,
                None => end,
            };
            continue;
        }
        st.lastmark = -1;
        st.lastindex = -1;
        st.start = ptr;
        st.ptr = ptr;
        status = sre_match(st, prog, pc, false)?;
    }
    Ok(status)
}
