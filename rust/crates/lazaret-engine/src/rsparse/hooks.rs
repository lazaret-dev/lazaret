//! Code in a Rust file that runs without being called (0.1.9, R-2's first detector; nothing registers it yet).
//!
//! A crate's code runs at a moment its author chose and its user did not: when Cargo builds it (a build script), when
//! the compiler of whoever uses it expands a macro (a procedural macro), and when a binary that links it starts (a
//! constructor, an entry in a section the loader runs). [`hooks`] lists these from the items of [`parse`](super::parse):
//! what kind, which item, and the span of the code that runs, so that a rule can look for what the code does (a process
//! started, a connection opened, a file written) in that span and nowhere else.
//!
//! It reads names, attributes and the shapes of items, not what the code does: `#[ctor] fn f() {}` is a hook whatever
//! `f` holds, and the rule decides whether that matters. A macro that expands to a constructor (`inventory::submit!`,
//! `lazy_static!`) is not seen: macros are not read as code here.

use super::tree::*;

/// What kind of code runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HookKind {
    /// `#[proc_macro]`, `#[proc_macro_derive(X)]` or `#[proc_macro_attribute]` on a function: it runs inside the
    /// compiler of whoever builds a crate that uses the macro.
    ProcMacro,
    /// `#[ctor]` or `#[dtor]` (the `ctor` and `dtor` crates, in any path ending in them): the function runs before
    /// `main`, or at exit, in every binary that links the crate.
    LoadFn,
    /// `#[link_section = "…"]` naming a section the loader or the runtime runs (`.init_array`, `.ctors`,
    /// `.preinit_array`, `.fini_array`, `.dtors`, `__DATA,__mod_init_func`, `.CRT$XCU`…) on a function or a static.
    LoadSection,
    /// The crate does not start at `main`: `#![no_main]`, `#[start]`, or a `#[no_mangle] extern "C" fn main`.
    OwnEntry,
    /// `fn main` of a build script (`build.rs`: the caller says that the file is one): Cargo runs it, with the
    /// builder's rights, before it builds anything else of the crate.
    BuildMain,
}

impl HookKind {
    pub fn name(self) -> &'static str {
        match self {
            HookKind::ProcMacro => "proc-macro",
            HookKind::LoadFn => "load-fn",
            HookKind::LoadSection => "load-section",
            HookKind::OwnEntry => "own-entry",
            HookKind::BuildMain => "build-main",
        }
    }
}

/// One thing that runs by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hook {
    pub kind: HookKind,
    /// The item (an index into [`Tree::items`]), or [`NONE`] for a crate attribute (`#![no_main]`).
    pub item: u32,
    /// The span of the code that runs, in code points: the item's (a function's body is in it).
    pub start: u32,
    pub end: u32,
    /// The attribute that makes it a hook, as written (`ctor::ctor`, `link_section = ".init_array"`), or the function's name for `BuildMain`.
    pub why: String,
}

/// Sections the loader or the C runtime runs code from at load or exit.
fn runs_at_load(section: &str) -> bool {
    let s = section.to_ascii_lowercase();
    s.contains(".init_array")
        || s.contains(".ctors")
        || s.contains(".preinit_array")
        || s.contains(".fini_array")
        || s.contains(".dtors")
        || s.contains("mod_init_func")
        || s.contains("mod_term_func")
        || s.contains(".crt$xc")
        || s.contains(".crt$xt")
        || s == ".init"
        || s == ".fini"
}

/// The hooks of a parsed file, in the order of the items. `build_script`: the file is a build script (a function `main`
/// at its top level is run by Cargo).
pub fn hooks(tree: &Tree, src: &[u32], build_script: bool) -> Vec<Hook> {
    let mut out = Vec::new();
    let (first, count) = tree.crate_attrs;
    for a in &tree.attrs[first as usize..(first + count) as usize] {
        if tree.attr_path(src, a) == "no_main" {
            let start = tree.toks[a.tok_start as usize].start;
            let end = tree.toks[a.tok_end as usize - 1].end;
            out.push(Hook { kind: HookKind::OwnEntry, item: NONE, start, end, why: "no_main".to_string() });
        }
    }
    for (n, it) in tree.items.iter().enumerate() {
        let mut fn_main_no_mangle = false;
        for a in tree.attrs_of(n) {
            let path = tree.attr_path(src, a);
            let last = path.rsplit("::").next().unwrap_or("");
            let hook = |kind: HookKind, why: String| Hook { kind, item: n as u32, start: it.start, end: it.end, why };
            if it.kind == Kind::Fn {
                if matches!(path.as_str(), "proc_macro" | "proc_macro_derive" | "proc_macro_attribute") {
                    out.push(hook(HookKind::ProcMacro, path.clone()));
                } else if last == "ctor" || last == "dtor" {
                    out.push(hook(HookKind::LoadFn, path.clone()));
                } else if path == "start" {
                    out.push(hook(HookKind::OwnEntry, path.clone()));
                } else if path == "no_mangle" {
                    fn_main_no_mangle = true;
                }
            }
            if matches!(it.kind, Kind::Fn | Kind::Static) && path == "link_section" {
                if let Some(v) = tree.attr_value(src, a).and_then(|t| tree.str_value(src, t)) {
                    if runs_at_load(&v) {
                        out.push(hook(HookKind::LoadSection, format!("link_section = \"{}\"", v)));
                    }
                }
            }
        }
        if it.kind == Kind::Fn && tree.name(src, n) == "main" {
            if fn_main_no_mangle && it.flags & EXTERN != 0 {
                out.push(Hook { kind: HookKind::OwnEntry, item: n as u32, start: it.start, end: it.end, why: "no_mangle extern fn main".to_string() });
            }
            if build_script && it.parent == NONE && it.flags & LOCAL == 0 {
                out.push(Hook { kind: HookKind::BuildMain, item: n as u32, start: it.start, end: it.end, why: "main".to_string() });
            }
        }
    }
    out
}
