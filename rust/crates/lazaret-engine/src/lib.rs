//! Lazaret's scanning engine: the bytes of a file in, findings out.
//!
//! A second implementation of `lazaret.scanner` (the Python reference
//! engine), held to it by differential tests: for every input it answers
//! exactly what the reference answers (docs/RUST_ENGINE.md). It reads only
//! the text it is handed: no files, no network, no processes, no `unsafe`,
//! no dependencies.
#![forbid(unsafe_code)]

pub mod api;
pub mod budget;
pub mod crossfile;
pub mod filectx;
pub mod findings;
pub mod flow;
pub mod generated;
pub mod hooks;
pub mod json;
pub mod jsparse;
pub mod lexer;
pub mod linear;
pub mod normalize;
pub mod pack;
pub mod pyparse;
pub mod pyre;
pub mod pystr;
pub mod received;
pub mod rxutil;
pub mod scanfile;
pub mod shell;
pub mod signs;
pub mod strarr;
pub mod textgate;
pub mod token;
pub mod unicode;

/// The engine's version (the workspace's).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
