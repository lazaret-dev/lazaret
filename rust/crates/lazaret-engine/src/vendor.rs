//! A vendored dependency's manifest, read for what the readers need (0.1.9, Part C).
//!
//! A `--deps` scan reads a Rust project's `cargo vendor` tree and a Go project's `vendor/` as the registry reads a
//! `.crate` and a module zip: the Rust reader on each crate, the Go reader on each module. Both CLIs do it (the Python
//! package's core.py, the npm package's deps.js), and what they need to know of a manifest is read here, once, so the
//! two answer alike:
//!
//! - [`cargo_layout`]: what a crate's `Cargo.toml` says of its build script (`package.build`: a path, or `false`) and
//!   its library (`lib.path`, `lib.proc-macro`, and `lib.crate-type`: a `"proc-macro"` among its crate types makes
//!   the library a procedural macro whatever `proc-macro` says, as cargo builds it), read as TOML reads them: tables and arrays of tables, dotted and
//!   quoted keys, inline tables, the four kinds of strings, arrays over several lines and comments. Only those keys are
//!   kept; a line this reader cannot read is left, and the next one read. Cargo refuses a manifest that is not TOML, so
//!   a crate with one is never built; what is read of it here does not matter.
//! - [`vendored_modules`]: the module paths a `vendor/modules.txt` says are vendored (a `# path version` line followed
//!   by its annotations and packages; a `# ` line with nothing after it is a replacement `go mod vendor` records but
//!   does not use), longest first, so that a file is given to the module whose path is the longest prefix of its own.
//!
//! Every loop advances or stops, values nest at most [`MAX_DEPTH`] deep, and nothing here panics on any input.

use crate::pystr::PyStr;

/// How deep arrays and inline tables nest before the rest of the value is skipped.
pub const MAX_DEPTH: usize = 32;
/// The lines of a `modules.txt` read, at most.
pub const MAX_MODULE_LINES: usize = 200_000;
/// The strings an array keeps (`lib.crate-type`'s), at most; the rest are read and dropped.
pub const MAX_ARRAY_STRINGS: usize = 16;

/// What `package.build` says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Build {
    /// A path (cargo's default, `build.rs`, when it is not set).
    Path(PyStr),
    /// `build = false`: cargo runs no build script.
    Off,
}

/// What a crate's `Cargo.toml` says of the files that run: `None` where it says nothing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub build: Option<Build>,
    pub lib_path: Option<PyStr>,
    pub proc_macro: Option<bool>,
}

#[derive(Clone, Debug, PartialEq)]
enum Val {
    Str(PyStr),
    Bool(bool),
    Table(Vec<(Vec<PyStr>, Val)>),
    /// An array's strings (the first MAX_ARRAY_STRINGS; its other values are not kept).
    Strs(Vec<PyStr>),
    Other,
}

struct Toml<'a> {
    s: &'a [u32],
    i: usize,
    /// Values nested deeper than MAX_DEPTH: the document is not read on (cargo refuses one so deep).
    stop: bool,
}

fn is_bare(c: u32) -> bool {
    matches!(char::from_u32(c), Some('A'..='Z' | 'a'..='z' | '0'..='9' | '_' | '-'))
}

impl<'a> Toml<'a> {
    fn peek(&self, k: usize) -> Option<u32> {
        self.s.get(self.i + k).copied()
    }

    fn is(&self, k: usize, c: char) -> bool {
        self.peek(k) == Some(c as u32)
    }

    fn at(&self, lit: &str) -> bool {
        lit.chars().enumerate().all(|(k, c)| self.is(k, c))
    }

    /// Spaces and tabs.
    fn ws(&mut self) {
        while self.is(0, ' ') || self.is(0, '\t') {
            self.i += 1;
        }
    }

    /// Spaces, tabs, line ends and comments.
    fn ws_lines(&mut self) {
        loop {
            match self.peek(0).and_then(char::from_u32) {
                Some(' ' | '\t' | '\r' | '\n') => self.i += 1,
                Some('#') => self.rest_of_line(),
                _ => return,
            }
        }
    }

    /// To the start of the next line.
    fn rest_of_line(&mut self) {
        while let Some(c) = self.peek(0) {
            self.i += 1;
            if c == '\n' as u32 {
                return;
            }
        }
    }

    /// A dotted key: bare keys and one-line basic or literal strings, `.` between them.
    fn key(&mut self) -> Option<Vec<PyStr>> {
        let mut parts = Vec::new();
        loop {
            self.ws();
            let part = if self.is(0, '"') && !self.at("\"\"\"") {
                self.i += 1;
                self.basic(false)?
            } else if self.is(0, '\'') && !self.at("'''") {
                self.i += 1;
                self.literal(false)?
            } else {
                let start = self.i;
                while self.peek(0).map_or(false, is_bare) {
                    self.i += 1;
                }
                if self.i == start {
                    return None;
                }
                self.s[start..self.i].to_vec()
            };
            parts.push(part);
            self.ws();
            if self.is(0, '.') {
                self.i += 1;
                continue;
            }
            return Some(parts);
        }
    }

    /// A basic string's text after its opening quote(s): escapes decoded, to its closing quote(s); None when it does
    /// not close (on its line, for a one-line string).
    fn basic(&mut self, multi: bool) -> Option<PyStr> {
        let mut out = Vec::new();
        if multi && self.is(0, '\n') {
            self.i += 1;
        } else if multi && self.at("\r\n") {
            self.i += 2;
        }
        loop {
            let c = self.peek(0)?;
            if c == '"' as u32 {
                if !multi {
                    self.i += 1;
                    return Some(out);
                }
                if self.at("\"\"\"") {
                    self.i += 3;
                    let mut extra = 0;
                    while extra < 2 && self.is(0, '"') {
                        out.push('"' as u32);
                        self.i += 1;
                        extra += 1;
                    }
                    return Some(out);
                }
                out.push(c);
                self.i += 1;
            } else if c == '\\' as u32 {
                self.i += 1;
                let e = self.peek(0)?;
                self.i += 1;
                match char::from_u32(e) {
                    Some('b') => out.push(8),
                    Some('t') => out.push(9),
                    Some('n') => out.push(10),
                    Some('f') => out.push(12),
                    Some('r') => out.push(13),
                    Some('"') => out.push('"' as u32),
                    Some('\\') => out.push('\\' as u32),
                    Some(h @ ('u' | 'U')) => {
                        let n = if h == 'u' { 4 } else { 8 };
                        let digits: Option<u32> = (0..n).try_fold(0u32, |acc, k| {
                            char::from_u32(self.peek(k)?).and_then(|d| d.to_digit(16)).map(|d| acc.wrapping_mul(16) | d)
                        });
                        match digits {
                            Some(v) => {
                                self.i += n;
                                out.push(v);
                            }
                            None => out.push(e),
                        }
                    }
                    Some(' ' | '\t' | '\r' | '\n') if multi => {
                        // a line-ending backslash: the line end and the whitespace after it go
                        self.i -= 1;
                        while matches!(self.peek(0).and_then(char::from_u32), Some(' ' | '\t' | '\r' | '\n')) {
                            self.i += 1;
                        }
                    }
                    _ => out.push(e),
                }
            } else if c == '\n' as u32 && !multi {
                return None;
            } else {
                out.push(c);
                self.i += 1;
            }
        }
    }

    /// A literal string's text after its opening quote(s), to its closing quote(s).
    fn literal(&mut self, multi: bool) -> Option<PyStr> {
        let mut out = Vec::new();
        if multi && self.is(0, '\n') {
            self.i += 1;
        } else if multi && self.at("\r\n") {
            self.i += 2;
        }
        loop {
            let c = self.peek(0)?;
            if c == '\'' as u32 {
                if !multi {
                    self.i += 1;
                    return Some(out);
                }
                if self.at("'''") {
                    self.i += 3;
                    let mut extra = 0;
                    while extra < 2 && self.is(0, '\'') {
                        out.push('\'' as u32);
                        self.i += 1;
                        extra += 1;
                    }
                    return Some(out);
                }
                out.push(c);
                self.i += 1;
            } else if c == '\n' as u32 && !multi {
                return None;
            } else {
                out.push(c);
                self.i += 1;
            }
        }
    }

    /// A value: a string, a boolean, an inline table's keys and values, or something else (a number, a date, an
    /// array: read past). `depth`: how deep it nests.
    fn value(&mut self, depth: usize) -> Val {
        if self.at("\"\"\"") {
            self.i += 3;
            return self.basic(true).map_or(Val::Other, Val::Str);
        }
        if self.at("'''") {
            self.i += 3;
            return self.literal(true).map_or(Val::Other, Val::Str);
        }
        match self.peek(0).and_then(char::from_u32) {
            Some('"') => {
                self.i += 1;
                self.basic(false).map_or(Val::Other, Val::Str)
            }
            Some('\'') => {
                self.i += 1;
                self.literal(false).map_or(Val::Other, Val::Str)
            }
            Some('[') => {
                self.i += 1;
                if depth >= MAX_DEPTH {
                    self.stop = true;
                    self.i = self.s.len();
                    return Val::Other;
                }
                let mut strs = Vec::new();
                loop {
                    self.ws_lines();
                    if self.is(0, ']') {
                        self.i += 1;
                        break;
                    }
                    let before = self.i;
                    if let Val::Str(item) = self.value(depth + 1) {
                        if strs.len() < MAX_ARRAY_STRINGS {
                            strs.push(item);
                        }
                    }
                    self.ws_lines();
                    if self.is(0, ',') {
                        self.i += 1;
                    } else if self.is(0, ']') {
                        self.i += 1;
                        break;
                    } else if self.i == before || self.peek(0).is_none() {
                        break;
                    }
                }
                Val::Strs(strs)
            }
            Some('{') => {
                self.i += 1;
                if depth >= MAX_DEPTH {
                    self.stop = true;
                    self.i = self.s.len();
                    return Val::Other;
                }
                let mut items = Vec::new();
                loop {
                    self.ws_lines();
                    if self.is(0, '}') {
                        self.i += 1;
                        break;
                    }
                    let Some(k) = self.key() else { break };
                    self.ws();
                    if !self.is(0, '=') {
                        break;
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value(depth + 1);
                    items.push((k, v));
                    self.ws_lines();
                    if self.is(0, ',') {
                        self.i += 1;
                    } else if self.is(0, '}') {
                        self.i += 1;
                        break;
                    } else {
                        break;
                    }
                }
                Val::Table(items)
            }
            _ => {
                let start = self.i;
                while let Some(c) = self.peek(0).and_then(char::from_u32) {
                    if matches!(c, ' ' | '\t' | '\r' | '\n' | ',' | ']' | '}' | '#') {
                        break;
                    }
                    self.i += 1;
                }
                let word = &self.s[start..self.i];
                if word == crate::pystr::u("true").as_slice() {
                    Val::Bool(true)
                } else if word == crate::pystr::u("false").as_slice() {
                    Val::Bool(false)
                } else {
                    Val::Other
                }
            }
        }
    }
}

fn keyed(parts: &[PyStr]) -> Vec<String> {
    parts.iter().map(|p| crate::pystr::to_string(p)).collect()
}

fn record(layout: &mut Layout, key: &[String], v: &Val) {
    let key: Vec<&str> = key.iter().map(|s| s.as_str()).collect();
    let key: Vec<&str> = match key.first() {
        Some(&"project") => std::iter::once("package").chain(key[1..].iter().copied()).collect(),
        _ => key,
    };
    if let Val::Table(items) = v {
        if matches!(key.as_slice(), ["package"] | ["lib"]) {
            for (k, vv) in items {
                let mut full: Vec<String> = key.iter().map(|s| s.to_string()).collect();
                full.extend(keyed(k));
                record(layout, &full, vv);
            }
        }
        return;
    }
    match (key.as_slice(), v) {
        (["package", "build"], Val::Str(p)) if layout.build.is_none() => layout.build = Some(Build::Path(p.clone())),
        (["package", "build"], Val::Bool(false)) if layout.build.is_none() => layout.build = Some(Build::Off),
        (["lib", "path"], Val::Str(p)) if layout.lib_path.is_none() => layout.lib_path = Some(p.clone()),
        (["lib", "proc-macro" | "proc_macro"], Val::Bool(b)) if layout.proc_macro.is_none() => layout.proc_macro = Some(*b),
        // (cargo builds a library whose crate types hold "proc-macro" as a procedural macro, `proc-macro = false` or not)
        (["lib", "crate-type" | "crate_type"], Val::Strs(types)) if types.iter().any(|t| t == &crate::pystr::u("proc-macro")) => {
            layout.proc_macro = Some(true)
        }
        _ => {}
    }
}

/// What a crate's `Cargo.toml` (`src`) says of its build script and its library (see the module's comment).
pub fn cargo_layout(src: &[u32]) -> Layout {
    let mut t = Toml { s: src, i: 0, stop: false };
    let mut layout = Layout::default();
    // the table the keys are in: None in an array of tables or after a header that could not be read
    let mut table: Option<Vec<String>> = Some(Vec::new());
    loop {
        t.ws_lines();
        let Some(c) = t.peek(0) else { break };
        let line_start = t.i;
        if c == '[' as u32 {
            let array = t.is(1, '[');
            t.i += if array { 2 } else { 1 };
            let k = t.key();
            t.ws();
            let closed = if array { t.at("]]") } else { t.is(0, ']') };
            table = match (k, closed, array) {
                (Some(k), true, false) => Some(keyed(&k)),
                _ => None,
            };
            t.rest_of_line();
            continue;
        }
        let Some(k) = t.key() else {
            t.rest_of_line();
            continue;
        };
        t.ws();
        if !t.is(0, '=') {
            t.rest_of_line();
            continue;
        }
        t.i += 1;
        t.ws();
        let v = t.value(0);
        if t.stop {
            break;
        }
        if let Some(tb) = &table {
            let mut full = tb.clone();
            full.extend(keyed(&k));
            record(&mut layout, &full, &v);
        }
        t.ws();
        if !t.is(0, '\n') && !t.is(0, '\r') && t.peek(0).is_some() {
            t.rest_of_line(); // (a comment, or what could not be read)
        }
        if t.i == line_start {
            t.i += 1;
        }
    }
    layout
}

/// The module paths a `vendor/modules.txt` (`src`) says are vendored, longest first (see the module's comment).
pub fn vendored_modules(src: &[u32]) -> Vec<PyStr> {
    let text = crate::pystr::to_string(src);
    let mut found: Vec<String> = Vec::new();
    let mut current: Option<String> = None;
    for line in text.split('\n').take(MAX_MODULE_LINES) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("# ") {
            current = rest.split_whitespace().next().map(str::to_string);
        } else if !line.trim().is_empty() {
            if let Some(m) = current.take() {
                found.push(m); // (an annotation or a package of the module's: it is vendored)
            }
        }
    }
    found.sort_by(|a, b| b.chars().count().cmp(&a.chars().count()).then_with(|| a.cmp(b)));
    found.dedup();
    found.iter().map(|m| crate::pystr::u(m)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystr::u;

    fn layout(text: &str) -> (Option<Build>, Option<String>, Option<bool>) {
        let l = cargo_layout(&u(text));
        (l.build, l.lib_path.map(|p| crate::pystr::to_string(&p)), l.proc_macro)
    }

    fn path(p: &str) -> Option<Build> {
        Some(Build::Path(u(p)))
    }

    #[test]
    fn a_manifest_as_cargo_publish_writes_it() {
        let text = "# THIS FILE IS AUTOMATICALLY GENERATED BY CARGO\n\n[package]\nedition = \"2018\"\nname = \"serde\"\n\
                    version = \"1.0.0\"\nbuild = \"build.rs\"\nautobins = false\n\n[lib]\nname = \"serde_derive\"\n\
                    path = \"src/lib.rs\"\nproc-macro = true\n\n[dependencies.proc-macro2]\nversion = \"1.0\"\n";
        assert_eq!(layout(text), (path("build.rs"), Some("src/lib.rs".into()), Some(true)));
    }

    #[test]
    fn a_library_whose_crate_types_hold_proc_macro_is_one() {
        // cargo builds it as a procedural macro and runs it inside the compiler of every user
        for text in [
            "[lib]\ncrate-type = [\"proc-macro\"]\n",
            "[lib]\ncrate_type = ['proc-macro']\n",
            "lib = { path = \"src/m.rs\", crate-type = [\n  \"proc-macro\", # the macro\n] }\n",
            "[lib]\nproc-macro = false\ncrate-type = [\"proc-macro\"]\n",
            "[lib]\ncrate-type = [\"proc-macro\"]\nproc-macro = false\n",
        ] {
            assert_eq!(layout(text).2, Some(true), "{text}");
        }
        assert_eq!(layout("[lib]\ncrate-type = [\"rlib\", \"cdylib\"]\n").2, None);
        assert_eq!(layout("[package]\ncrate-type = [\"proc-macro\"]\n").2, None);           // (only [lib]'s)
        assert_eq!(layout("[lib]\nproc-macro = false\n").2, Some(false));
        // an array's other values, and arrays nested in it, are read past
        assert_eq!(layout("[lib]\ncrate-type = [1, [\"x\"], { a = 1 }, \"proc-macro\"]\npath = \"l.rs\"\n"),
                   (None, Some("l.rs".into()), Some(true)));
    }

    #[test]
    fn nothing_said_and_build_false() {
        assert_eq!(layout("[package]\nname = \"x\"\n"), (None, None, None));
        assert_eq!(layout(""), (None, None, None));
        assert_eq!(layout("[package]\nbuild = false # none\n"), (Some(Build::Off), None, None));
        assert_eq!(layout("[project]\nbuild = 'tools/gen.rs'\n"), (path("tools/gen.rs"), None, None));
    }

    #[test]
    fn the_ways_toml_writes_a_key() {
        assert_eq!(layout("package.build = \"b.rs\"\nlib.path = \"l.rs\"\nlib.\"proc-macro\" = true\n"),
                   (path("b.rs"), Some("l.rs".into()), Some(true)));
        assert_eq!(layout("[ \"package\" ]\n\"build\" = \"b.rs\"\n[lib]\nproc_macro = true\n"),
                   (path("b.rs"), None, Some(true)));
        assert_eq!(layout("lib = { path = \"l.rs\", proc-macro = true }\npackage = { build = \"b.rs\" }\n"),
                   (path("b.rs"), Some("l.rs".into()), Some(true)));
        assert_eq!(layout("[package]\nbuild = \"a\\\\b.rs\"\n[lib]\npath = \"\\u0073rc/x.rs\"\n"),
                   (path("a\\b.rs"), Some("src/x.rs".into()), None));
        assert_eq!(layout("[package]\r\nbuild = \"b.rs\"\r\n"), (path("b.rs"), None, None));
    }

    #[test]
    fn keys_of_other_tables_are_not_these() {
        let text = "[package]\nname = \"x\"\n\n[[bin]]\nname = \"b\"\npath = \"src/evil.rs\"\n\n\
                    [target.'cfg(unix)'.dependencies]\nbuild = \"no.rs\"\n[dependencies.lib]\npath = \"../lib\"\n\
                    [dev-dependencies]\nlib = { path = \"../lib\" }\n";
        assert_eq!(layout(text), (None, None, None));
    }

    #[test]
    fn what_a_string_or_an_array_holds_is_not_read_as_lines() {
        // a description that holds what would be a table and keys, and an array over several lines with a nested one
        let text = "[package]\ndescription = \"\"\"\n[package]\nbuild = false\n[lib]\nproc-macro = true\n\"\"\"\n\
                    keywords = [\n  \"a\", # [lib]\n  [1, [2, 3]],\n  '''\n[lib]\n''',\n]\nbuild = \"evil.rs\"\n";
        assert_eq!(layout(text), (path("evil.rs"), None, None));
        let text = "[package]\nreadme = '''\nbuild = \"x.rs\"\n'''\nbuild = \"b.rs\"\n";
        assert_eq!(layout(text), (path("b.rs"), None, None));
        let text = "[package]\ndescription = \"a # b\"\nbuild = \"b.rs\" # [lib]\n";
        assert_eq!(layout(text), (path("b.rs"), None, None));
    }

    #[test]
    fn the_first_says_it() {
        assert_eq!(layout("[package]\nbuild = \"a.rs\"\nbuild = \"b.rs\"\n"), (path("a.rs"), None, None));
    }

    #[test]
    fn what_cannot_be_read_is_left_and_the_rest_read() {
        assert_eq!(layout("[package\nbuild = \"x.rs\"\n[package]\nbuild = \"b.rs\"\n"), (path("b.rs"), None, None));
        assert_eq!(layout("[package]\nbuild = \"unclosed\nbuild = \"b.rs\"\n"), (path("b.rs"), None, None));
        assert_eq!(layout("[package]\n= 1\n???\nbuild = \"b.rs\"\n"), (path("b.rs"), None, None));
        assert_eq!(layout("[package]\nbuild = \"\"\"never closed\n"), (None, None, None));
        // nested deeper than cargo reads: what came before is kept, nothing after is read
        let deep = format!("[package]\nbuild = \"b.rs\"\nx = {}{}\n[lib]\npath = \"l.rs\"\n", "[".repeat(5000), "]".repeat(5000));
        assert_eq!(layout(&deep), (path("b.rs"), None, None));
        let tables = format!("[package]\nbuild = \"b.rs\"\nx = {}\n", "{a = ".repeat(3000));
        assert_eq!(layout(&tables), (path("b.rs"), None, None));
        let _ = layout(&"\"".repeat(10000));
        let _ = layout(&"[".repeat(10000));
        let _ = layout("\\u");
    }

    #[test]
    fn the_modules_a_modules_txt_vendors() {
        let text = "# a.example/x v1.2.3\n## explicit; go 1.21\na.example/x\n# a.example/x/v2 v2.0.0\n## explicit\n\
                    a.example/x/v2\n# b.example/y v1.0.0 => ./y\n# c.example/z v1.0.0\n## explicit\n# d.example/w v1.0.0 => \
                    e.example/w v1.0.1\n## explicit\nd.example/w/pkg\n# unused.example/r => ./r\n";
        let got: Vec<String> = vendored_modules(&u(text)).iter().map(|m| crate::pystr::to_string(m)).collect();
        assert_eq!(got, vec!["a.example/x/v2", "a.example/x", "c.example/z", "d.example/w"]);
        assert!(vendored_modules(&u("")).is_empty());
        assert!(vendored_modules(&u("# \n\n# a.example/x v1\n")).is_empty());
    }
}
