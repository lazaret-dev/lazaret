//! A bound on the work one engine call may do.
//!
//! The regex engines count their work against the budget of the call in
//! progress (a thread's own, which a step of the call run on the call's own
//! stack takes there and brings back: `api::on_own_stack`, `state`,
//! `carry`): pyre each backtracking step and a sixteenth of
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

/// The budget of the call in progress on this thread: what is left, and whether it ran out.
pub fn state() -> (u64, bool) {
    (LEFT.with(|l| l.get()), SPENT.with(|s| s.get()))
}

/// Make `state` the budget of the call in progress on this thread: a step of the call run on another thread starts
/// with the call's (`state` there) and gives back what it left.
pub fn carry(state: (u64, bool)) {
    LEFT.with(|l| l.set(state.0));
    SPENT.with(|s| s.set(state.1));
}

/// Run `f` with `steps` of its own, as if it were a call of its own (a step of a larger call that the packages used
/// to make as a call: --deps' checks of a script, deps.rs), then give the call in progress back its own budget as it
/// was: Err when `f` ran out (the call in progress has not).
pub fn isolated<T>(steps: u64, f: impl FnOnce() -> T) -> Result<T, Exhausted> {
    let kept = state();
    reset(steps);
    let out = f();
    let gone = exhausted();
    carry(kept);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A search the DFA answers by reading a million characters: a sixteenth of them spent.
    fn search() -> bool {
        let text = vec![u32::from(b'a'); 1_000_000];
        let runs = crate::linre::Regex::compile(r"a+[^a]", 0).unwrap();
        runs.search(&text).is_none()
    }

    #[test]
    fn a_step_on_the_calls_own_stack_spends_the_calls_budget() {
        // (the models' thread, api::on_own_stack, kept the budget it was made with, which every call it ran spent
        // down: in a long-lived process its searches would run out unseen, and the call never knew)
        let here = call_with(DEFAULT_STEPS, || (search(), state())).unwrap();
        let there = call_with(DEFAULT_STEPS, || (crate::api::on_own_stack(search), state())).unwrap();
        assert_eq!(there, here);
        let cost = DEFAULT_STEPS - here.1 .0;
        assert!(cost >= 1_000_000 / 16 && !here.1 .1);
        // a call that runs out there runs out, and the next has its own budget there
        assert_eq!(call_with(cost - 1, || crate::api::on_own_stack(search)), Err(Exhausted));
        assert_eq!(call_with(cost, || crate::api::on_own_stack(search)), Ok(true));
        reset(DEFAULT_STEPS);
    }
}
