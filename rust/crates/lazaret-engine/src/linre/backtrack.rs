//! Depth-first search of the program in priority order — sre's own order —
//! that never visits a (state, position) twice.
//!
//! sre's answer from a start is the first path, in the order its
//! backtracking tries paths, that reaches the match. This search tries
//! paths in that order; a (state, position) it has left once without
//! success fails again whatever path leads to it (its future does not
//! depend on the groups), so it is visited once: the work is at most the
//! program's size times the characters read. Two uses:
//!
//! - `groups`: the groups of a match whose span the DFAs found (the first
//!   path from s that matches at e);
//! - `anchored`: a whole match from one start, as `match` asks and as a
//!   search tries at each place a match may start, within a budget of
//!   steps (the caller goes on with the DFA when it runs out, so a search
//!   stays linear).
//!
//! Visited bits are kept a row per position (as many bits as the program
//! has states), up to `MAX_BITS`.

use super::looks::{self, Oracle};
use super::nfa::{Inst, Prog, Programs};

/// Visited bits a search may use (2 MB; only the rows a search reaches are
/// cleared after it).
pub const MAX_BITS: usize = 1 << 24;

enum Frame {
    Explore(u32, usize),
    Restore(u32, isize),
    /// the exit of a run of one set, at hi, then hi - 1, … down to lo
    Exits(u32, usize, usize),
    /// the exit of a lazy run of a set at `at`, then (if text[at] is in
    /// the set) at + 1, … up to `last`
    Lazy { next: u32, set: u32, at: usize, last: usize },
}

/// Is `pc` a split of a greedy run of `set` leaving to `exit` (its first
/// branch consumes a character of the set)?
#[inline]
fn run_split(prog: &Prog, pc: u32, set: u32, exit: u32) -> bool {
    match prog.insts[pc as usize] {
        Inst::Split { x, y } if y == exit => matches!(prog.insts[x as usize], Inst::Char { set: s, .. } if s == set),
        _ => false,
    }
}

#[derive(Default)]
pub struct Backtracker {
    visited: Vec<u64>,
    /// words of the rows in use (cleared before the next search)
    used: usize,
    stack: Vec<Frame>,
    slots: Vec<isize>,
}

impl Backtracker {
    pub fn new() -> Backtracker {
        Backtracker::default()
    }
}

/// Can a span of `len` characters be searched within the limit?
pub fn fits(prog: &Prog, len: usize) -> bool {
    let row = prog.insts.len().div_ceil(64);
    len < (MAX_BITS / 64 / row).max(1)
}

/// Why an anchored search stopped without an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfSteps;

/// The search proper: from `s`, the first path in priority order whose
/// match is accepted (`end_at`: only a match at that position; `no_empty`:
/// not an empty one at s). Steps: at most `budget` (states visited and
/// characters a run reads).
#[allow(clippy::too_many_arguments)]
fn dfs(
    pr: &Programs,
    prog: &Prog,
    text: &[u32],
    s: usize,
    end: usize,
    end_at: Option<usize>,
    no_empty: bool,
    budget: usize,
    bt: &mut Backtracker,
    oracle: &mut Oracle,
    spent: &mut usize,
) -> Result<Option<(Vec<isize>, usize)>, OutOfSteps> {
    let n = prog.insts.len();
    let row = n.div_ceil(64);
    // (the rows of the last search are cleared, not the whole table)
    for w in &mut bt.visited[..bt.used] {
        *w = 0;
    }
    bt.used = 0;
    let max_rows = (MAX_BITS / 64 / row).max(1);
    bt.slots.clear();
    bt.slots.resize(pr.slots, -1);
    let last_slot = (pr.slots - 2) as u32;
    let limit = end_at.unwrap_or(end).min(end);
    let mut steps = 0usize;
    bt.stack.clear();
    bt.stack.push(Frame::Explore(prog.start, s));
    // characters a run reads count as steps too
    macro_rules! charge {
        ($k:expr) => {{
            steps += $k;
            *spent += $k;
            if steps > budget {
                return Err(OutOfSteps);
            }
        }};
    }
    // mark (pc, pos) visited; false if it was
    macro_rules! visit {
        ($pc:expr, $pos:expr) => {{
            let r = $pos - s;
            if r >= max_rows {
                return Err(OutOfSteps);
            }
            let need = (r + 1) * row;
            if need > bt.used {
                if bt.visited.len() < need {
                    bt.visited.resize(need, 0);
                }
                bt.used = need;
            }
            let (w, b) = (r * row + $pc as usize / 64, 1u64 << ($pc % 64));
            if bt.visited[w] & b != 0 {
                false
            } else {
                bt.visited[w] |= b;
                charge!(1);
                true
            }
        }};
    }
    while let Some(f) = bt.stack.pop() {
        let (mut pc, mut pos) = match f {
            Frame::Restore(slot, old) => {
                bt.slots[slot as usize] = old;
                continue;
            }
            Frame::Explore(pc, pos) => (pc, pos),
            Frame::Exits(exit, lo, hi) => {
                if hi > lo {
                    bt.stack.push(Frame::Exits(exit, lo, hi - 1));
                }
                (exit, hi)
            }
            Frame::Lazy { next, set, at, last: stop } => {
                charge!(1);
                if at < stop && at < limit && pr.sets[set as usize].contains(text[at]) {
                    bt.stack.push(Frame::Lazy { next, set, at: at + 1, last: stop });
                }
                (next, at)
            }
        };
        // follow one path as far as it goes, leaving the alternatives on the stack
        loop {
            if !visit!(pc, pos) {
                break;
            }
            match prog.insts[pc as usize] {
                Inst::Char { set, next } => {
                    if pos < limit && pr.sets[set as usize].contains(text[pos]) {
                        pc = next;
                        pos += 1;
                    } else {
                        break;
                    }
                }
                Inst::Split { x, y } => {
                    let run = match prog.insts[x as usize] {
                        Inst::Char { set, next } if next == pc || run_split(prog, next, set, y) => Some(set),
                        _ => None,
                    };
                    let set = match run {
                        None => {
                            bt.stack.push(Frame::Explore(y, pos));
                            pc = x;
                            continue;
                        }
                        Some(set) => set,
                    };
                    // A greedy run of one set (a loop, or a counted repeat's
                    // chain): consume as far as it goes, then leave its exits
                    // to try from the furthest back, as the plain search would.
                    let lo = pos;
                    let mut sp = pc;
                    let mut q = pos;
                    let mut cont: Option<(u32, usize)> = None;
                    while let Inst::Split { x: cpc, .. } = prog.insts[sp as usize] {
                        let cnext = match prog.insts[cpc as usize] {
                            Inst::Char { next, .. } => next,
                            _ => break,
                        };
                        if !visit!(cpc, q) {
                            break;
                        }
                        if !(q < limit && pr.sets[set as usize].contains(text[q])) {
                            break;
                        }
                        if cnext == sp || run_split(prog, cnext, set, y) {
                            if !visit!(cnext, q + 1) {
                                break;
                            }
                            sp = cnext;
                            q += 1;
                        } else {
                            // (the chain's last character: on after it)
                            cont = Some((cnext, q + 1));
                            break;
                        }
                    }
                    bt.stack.push(Frame::Exits(y, lo, q));
                    match cont {
                        Some((c, p)) => {
                            pc = c;
                            pos = p;
                        }
                        None => break,
                    }
                }
                Inst::Run { set, min, max, greedy, next } => {
                    // a repeat of one set: as the expanded program would be
                    // searched, its continuation tried after the most
                    // characters first (greedy) or the fewest (lazy)
                    let st = &pr.sets[set as usize];
                    let cap = if max == u32::MAX { limit } else { limit.min(pos.saturating_add(max as usize)) };
                    let need = pos + min as usize;
                    if need > cap {
                        break;
                    }
                    if greedy {
                        let mut q = pos;
                        while q < cap && st.contains(text[q]) {
                            q += 1;
                        }
                        charge!((q - pos) / 4);
                        if q < need {
                            break;
                        }
                        bt.stack.push(Frame::Exits(next, need, q));
                        break;
                    }
                    let mut q = pos;
                    while q < need && st.contains(text[q]) {
                        q += 1;
                    }
                    charge!((q - pos) / 4);
                    if q < need {
                        break;
                    }
                    bt.stack.push(Frame::Lazy { next, set, at: need, last: cap });
                    break;
                }
                Inst::Jmp { next } => pc = next,
                Inst::Guard { next } => {
                    if pos <= end {
                        pc = next;
                    } else {
                        break;
                    }
                }
                Inst::Save { slot, next } => {
                    bt.stack.push(Frame::Restore(slot, bt.slots[slot as usize]));
                    if slot % 2 == 1 && slot < last_slot {
                        bt.stack.push(Frame::Restore(last_slot, bt.slots[last_slot as usize]));
                        bt.slots[last_slot as usize] = (slot / 2 + 1) as isize;
                    }
                    bt.slots[slot as usize] = pos as isize;
                    pc = next;
                }
                Inst::Look { look, next } => {
                    if looks::holds(pr, look, text, pos, end, oracle) {
                        pc = next;
                    } else {
                        break;
                    }
                }
                Inst::Match => {
                    let ok = match end_at {
                        Some(e) => pos == e,
                        None => !(no_empty && pos == s),
                    };
                    if ok {
                        return Ok(Some((bt.slots.clone(), pos)));
                    }
                    break;
                }
            }
        }
    }
    Ok(None)
}

/// The slots of the first path (in sre's order) of `prog` from `s` that
/// matches at `e`, within a window ending at `end`.
#[allow(clippy::too_many_arguments)]
pub fn groups(pr: &Programs, prog: &Prog, text: &[u32], s: usize, e: usize, end: usize, bt: &mut Backtracker, oracle: &mut Oracle) -> Option<Vec<isize>> {
    let mut spent = 0;
    match dfs(pr, prog, text, s, end, Some(e), false, usize::MAX, bt, oracle, &mut spent) {
        Ok(Some((slots, _))) => Some(slots),
        _ => None,
    }
}

/// sre's match from `s` (its slots and end), within `budget` steps (the
/// steps taken are added to `spent`).
#[allow(clippy::too_many_arguments)]
pub fn anchored(
    pr: &Programs,
    prog: &Prog,
    text: &[u32],
    s: usize,
    end: usize,
    no_empty: bool,
    budget: usize,
    bt: &mut Backtracker,
    oracle: &mut Oracle,
    spent: &mut usize,
) -> Result<Option<(Vec<isize>, usize)>, OutOfSteps> {
    dfs(pr, prog, text, s, end, None, no_empty, budget, bt, oracle, spent)
}
