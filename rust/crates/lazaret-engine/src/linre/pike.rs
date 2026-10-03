//! The Pike VM: every state of the program at once, one character at a
//! time, each thread with its capture slots.
//!
//! Threads are kept in priority order, the order sre's backtracking would
//! try them in; a thread that reaches a state already taken this step is
//! dropped (the earlier one has the same future and a higher priority).
//! When a thread matches, the threads after it are dropped and the ones
//! before it go on: the last match recorded is the leftmost-first one, the
//! one sre answers, with the captures of that path (the last iteration's
//! inside a repeat, nothing for a group the path did not pass through).
//!
//! Work: the text's length times the program's size, captures copied per
//! thread. Used wherever the DFAs give up, for a match whose start lies
//! past the window's end, and for the groups of a match too long for the
//! backtracker's visited bits (on its span only).

use super::looks::{self, Oracle, SparseSet};
use super::nfa::{Inst, Prog, Programs};

struct Threads {
    set: SparseSet,
    /// slots of each thread, by program counter
    slots: Vec<isize>,
}

impl Threads {
    fn new() -> Threads {
        Threads { set: SparseSet::new(0), slots: Vec::new() }
    }

    fn reset(&mut self, n: usize, nslots: usize) {
        self.set.resize(n);
        if self.slots.len() < n * nslots {
            self.slots.resize(n * nslots, -1);
        }
    }
}

enum Job {
    Explore(u32),
    Restore(u32, isize),
}

pub struct PikeCache {
    clist: Threads,
    nlist: Threads,
    stack: Vec<Job>,
    scratch: Vec<isize>,
    pub oracle: Oracle,
    memo: Vec<u8>,
    memo_touched: Vec<u32>,
}

impl PikeCache {
    pub fn new() -> PikeCache {
        PikeCache {
            clist: Threads::new(),
            nlist: Threads::new(),
            stack: Vec::new(),
            scratch: Vec::new(),
            oracle: Oracle::new(),
            memo: Vec::new(),
            memo_touched: Vec::new(),
        }
    }
}

impl Default for PikeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// What a search accepts.
#[derive(Clone, Copy, Debug)]
pub struct Want {
    /// only from `start` (match, fullmatch) or from any position on (search)
    pub anchored: bool,
    /// no empty match at `start` (finditer after an empty match)
    pub must_advance: bool,
    /// only a match ending here
    pub end_at: Option<usize>,
}

/// The leftmost-first match of `prog` in text[start..end] (`start` may lie
/// past `end`: a match that starts outside the window): its slots
/// (`pr.slots` of them: the groups' starts and ends, the last group closed,
/// the match's start) and its end.
pub fn search(pr: &Programs, prog: &Prog, text: &[u32], start: usize, end: usize, want: Want, cache: &mut PikeCache) -> Option<(Vec<isize>, usize)> {
    let n = prog.insts.len();
    let nslots = pr.slots;
    cache.clist.reset(n, nslots);
    cache.nlist.reset(n, nslots);
    cache.scratch.clear();
    cache.scratch.resize(nslots, -1);
    if cache.memo.len() < pr.looks.len() {
        cache.memo.resize(pr.looks.len(), 0);
    }
    let entry = if want.anchored { prog.start } else { prog.start_unanchored };
    let mut matched: Option<(Vec<isize>, usize)> = None;
    let mut p = start;
    {
        let PikeCache { clist, stack, scratch, oracle, memo, memo_touched, .. } = cache;
        add(pr, prog, clist, stack, scratch, nslots, entry, text, p, end, oracle, memo, memo_touched);
    }
    loop {
        clear_memo(&mut cache.memo, &mut cache.memo_touched);
        let len = cache.clist.set.len();
        for i in 0..len {
            let pc = cache.clist.set.get(i);
            match prog.insts[pc as usize] {
                Inst::Char { set, next } if p < end && text.get(p).is_some_and(|&c| pr.sets[set as usize].contains(c)) => {
                    let base = pc as usize * nslots;
                    let PikeCache { clist, nlist, stack, scratch, oracle, memo, memo_touched } = cache;
                    scratch.copy_from_slice(&clist.slots[base..base + nslots]);
                    add(pr, prog, nlist, stack, scratch, nslots, next, text, p + 1, end, oracle, memo, memo_touched);
                }
                Inst::Match => {
                    let ok = (!want.must_advance || p != start) && want.end_at.map_or(true, |e| e == p);
                    if ok {
                        let base = pc as usize * nslots;
                        matched = Some((cache.clist.slots[base..base + nslots].to_vec(), p));
                        // (the threads after this one have lower priority)
                        break;
                    }
                }
                _ => {}
            }
        }
        if p >= end || cache.nlist.set.is_empty() {
            break;
        }
        if let Some(e) = want.end_at {
            if matched.is_some() || p >= e {
                break;
            }
        }
        std::mem::swap(&mut cache.clist, &mut cache.nlist);
        cache.nlist.set.clear();
        p += 1;
    }
    clear_memo(&mut cache.memo, &mut cache.memo_touched);
    matched
}

fn clear_memo(memo: &mut [u8], touched: &mut Vec<u32>) {
    for &l in touched.iter() {
        memo[l as usize] = 0;
    }
    touched.clear();
}

/// Add the thread at `from` (slots in `scratch`) and what it reaches
/// without consuming, in priority order.
#[allow(clippy::too_many_arguments)]
fn add(
    pr: &Programs,
    prog: &Prog,
    list: &mut Threads,
    stack: &mut Vec<Job>,
    scratch: &mut [isize],
    nslots: usize,
    from: u32,
    text: &[u32],
    pos: usize,
    end: usize,
    oracle: &mut Oracle,
    memo: &mut [u8],
    touched: &mut Vec<u32>,
) {
    let last_slot = (nslots - 2) as u32;
    stack.push(Job::Explore(from));
    while let Some(job) = stack.pop() {
        let pc = match job {
            Job::Restore(slot, old) => {
                scratch[slot as usize] = old;
                continue;
            }
            Job::Explore(pc) => pc,
        };
        if !list.set.insert(pc) {
            continue;
        }
        match prog.insts[pc as usize] {
            Inst::Split { x, y } => {
                stack.push(Job::Explore(y));
                stack.push(Job::Explore(x));
            }
            Inst::Jmp { next } => stack.push(Job::Explore(next)),
            Inst::Guard { next } => {
                if pos <= end {
                    stack.push(Job::Explore(next));
                }
            }
            Inst::Save { slot, next } => {
                stack.push(Job::Restore(slot, scratch[slot as usize]));
                if slot % 2 == 1 && slot < last_slot {
                    // (the end of a group: it is the last one closed)
                    stack.push(Job::Restore(last_slot, scratch[last_slot as usize]));
                    scratch[last_slot as usize] = (slot / 2 + 1) as isize;
                }
                scratch[slot as usize] = pos as isize;
                stack.push(Job::Explore(next));
            }
            Inst::Look { look, next } => {
                let m = memo[look as usize];
                let ok = if m != 0 {
                    m == 2
                } else {
                    let v = looks::holds(pr, look, text, pos, end, oracle);
                    memo[look as usize] = if v { 2 } else { 1 };
                    touched.push(look);
                    v
                };
                if ok {
                    stack.push(Job::Explore(next));
                }
            }
            Inst::Run { .. } => {}
            Inst::Char { .. } | Inst::Match => {
                let base = pc as usize * nslots;
                list.slots[base..base + nslots].copy_from_slice(scratch);
            }
        }
    }
}
