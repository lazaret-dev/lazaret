//! A bound on the work one engine call may do.
//!
//! The regex engines count their work against the budget of the call in
//! progress (a thread's own): pyre each backtracking step and a sixteenth of
//! each character a scan reads, linre a sixteenth of the characters its
//! automata read (neither charges the scans for a pattern's strings, nor a
//! search the text gate answers). Python's `re` has no such bound. On every
//! input the corpora hold the budget is never reached; if a hostile input
//! reaches it, the call stops and reports `Exhausted` instead of answering,
//! and both packages make the file SC-TRUNCATED (it was not fully read, so
//! it fails the gate).

use std::cell::Cell;

/// Steps of the regex matcher one call may take by default: several seconds
/// of work, far above what any input of the corpora needs.
pub const DEFAULT_STEPS: u64 = 4_000_000_000;

thread_local! {
    static LEFT: Cell<u64> = const { Cell::new(DEFAULT_STEPS) };
    static SPENT: Cell<bool> = const { Cell::new(false) };
}

/// The call ran out of budget: its answer is not to be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhausted;

/// Start a call with `steps` to spend.
pub fn reset(steps: u64) {
    LEFT.with(|l| l.set(steps));
    SPENT.with(|s| s.set(false));
}

/// Spend `n` steps; false once the budget is gone (and from then on).
#[inline]
pub fn spend(n: u64) -> bool {
    LEFT.with(|l| {
        let left = l.get();
        if left >= n {
            l.set(left - n);
            true
        } else {
            l.set(0);
            SPENT.with(|s| s.set(true));
            false
        }
    })
}

/// Has the call in progress run out?
pub fn exhausted() -> bool {
    SPENT.with(|s| s.get())
}

/// Run `f` as one engine call with the default budget.
pub fn call<T>(f: impl FnOnce() -> T) -> Result<T, Exhausted> {
    call_with(DEFAULT_STEPS, f)
}

/// Run `f` as one engine call with `steps` to spend.
pub fn call_with<T>(steps: u64, f: impl FnOnce() -> T) -> Result<T, Exhausted> {
    reset(steps);
    let out = f();
    if exhausted() {
        Err(Exhausted)
    } else {
        Ok(out)
    }
}

/// Run `f` with `steps` of its own, as if it were a call of its own (a step of a larger call that the packages used
/// to make as a call: --deps' checks of a script, deps.rs), then give the call in progress back its own budget as it
/// was: Err when `f` ran out (the call in progress has not).
pub fn isolated<T>(steps: u64, f: impl FnOnce() -> T) -> Result<T, Exhausted> {
    let (left, spent) = (LEFT.with(|l| l.get()), SPENT.with(|s| s.get()));
    reset(steps);
    let out = f();
    let gone = exhausted();
    LEFT.with(|l| l.set(left));
    SPENT.with(|s| s.set(spent));
    if gone {
        Err(Exhausted)
    } else {
        Ok(out)
    }
}

/// The call in progress is to answer as one that ran out (a step of it that ran out of its own budget: isolated).
pub fn exhaust() {
    LEFT.with(|l| l.set(0));
    SPENT.with(|s| s.set(true));
}
