//! What the readers of a language's code share (0.1.9): Rust's (`rsread`) and Go's (`goread`).
//!
//! Each reader evaluates its language's code from the moments the code runs (a build script, a procedural
//! macro, a start-up function, Go's `init` and package initializers, and the rest when it is used) and
//! records what it does as [`events::Ev`]s, on [`val::Val`]s: the text the code builds, the data it carries
//! and the handles it opens. [`facts`] turns a reading's events into what the install-script and
//! import-time tests ask ([`crate::signs::ModelFacts`]), so the reasons and the severities are the ones
//! Python's and JavaScript's code gets.

pub mod events;
pub mod facts;
pub mod val;

use crate::pystr::PyStr;

/// What the use-time test read: (files, characters) read, of how many.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UseRead {
    pub files: usize,
    pub chars: usize,
    pub of_files: usize,
    pub of_chars: usize,
}

/// One finding: the file, its reasons, the 1-based line of the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    pub file: usize,
    pub reasons: Vec<PyStr>,
    pub line: usize,
}
