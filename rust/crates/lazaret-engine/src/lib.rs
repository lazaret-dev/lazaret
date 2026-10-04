//! Lazaret's scanning engine: the bytes of a file in, findings out.
//!
//! Lazaret's only engine since the Rust-first refactor (it was ported from
//! `lazaret.scanner`'s Python engine and held to it by differential tests
//! until then): the Python package calls it through ctypes and the npm
//! package as WebAssembly, and it is held to its own recorded outputs
//! (docs/RUST_ENGINE.md). It reads only the text it is handed: no files, no
//! network, no processes, no `unsafe`, no dependencies.
#![forbid(unsafe_code)]

pub mod api;
pub mod budget;
pub mod crossfile;
pub mod filectx;
pub mod findings;
pub mod flow;
pub mod generated;
pub mod goparse;
pub mod hooks;
pub mod json;
pub mod jsflow;
pub mod jsparse;
pub mod lex;
pub mod lexer;
pub mod linear;
pub mod linre;
pub mod normalize;
pub mod pack;
pub mod pyflow;
pub mod pyparse;
pub mod pyre;
pub mod pystr;
pub mod quickhash;
pub mod received;
pub mod rsparse;
pub mod rsread;
pub mod rxutil;
pub mod scan;
pub mod scanfile;
pub mod shell;
pub mod signs;
pub mod strarr;
pub mod textgate;
pub mod token;
pub mod unicode;

/// The engine's version (the workspace's).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
