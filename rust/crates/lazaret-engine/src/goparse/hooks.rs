//! Code in a Go file that runs without being called (0.1.9, G-2's first detector; nothing registers it yet).
//!
//! Go has no install script, but a package's code still runs at moments its author chose and its user did not: when a
//! program that imports the package starts (every `init` function, and the initializer of every package-level variable),
//! when the builder compiles it (the C of a cgo preamble, with the flags its `#cgo` lines give), and when a tool the
//! author named is run (`go generate`, which the user runs only if they choose to). [`hooks`] lists these from the tree
//! of [`parse`](super::parse) and the comments of the text: what kind, and the span of the code that runs, so that a rule
//! can look for what that code does (a process started, a connection opened, a file written) in that span and nowhere
//! else.
//!
//! It reads names and the shapes of declarations, not what the code does: `func init() {}` is a hook whatever it holds,
//! and the rule decides whether that matters. A variable's initializer is a hook when it calls something other than a
//! conversion or a built-in (`var x = f()`, not `var x = int64(1)` or `var m = make(map[string]int)`); what a call does
//! is for the rule to read in the span. A call inside a function literal is not run by the declaration (the literal is
//! only a value) unless the literal is itself called, and that call is seen.
//!
//! `//go:linkname` ties a name to one in another package, the runtime's included, past what the language lets a package
//! reach; it runs nothing, but a package that uses it is doing something its readers should see. `//go:generate` runs
//! only when someone runs `go generate`, which neither `go build` nor `go get` does; it is listed so that a rule can read
//! the command, and its [`HookKind`] says that it is not run by a build.

use super::scan::Tok;
use super::tree::*;

/// What kind of code runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum HookKind {
    /// `func init()`: it runs when the package is loaded, in every program that imports it.
    InitFn,
    /// A package-level `var` whose initializer calls something that is not a conversion or a built-in: the call runs
    /// when the package is loaded.
    VarInit,
    /// `import "C"`: the comment before it (the preamble) is C that the builder's compiler compiles when `go build`
    /// runs, with the flags its `#cgo` lines give; a constructor in it runs when the program starts.
    Cgo,
    /// `//go:linkname local remote`: a name bound to one in another package.
    Linkname,
    /// `//go:generate command`: run by `go generate` only, never by a build or an install.
    Generate,
}

impl HookKind {
    pub fn name(self) -> &'static str {
        match self {
            HookKind::InitFn => "init-fn",
            HookKind::VarInit => "var-init",
            HookKind::Cgo => "cgo",
            HookKind::Linkname => "linkname",
            HookKind::Generate => "generate",
        }
    }

    /// Does it run when a program that imports the package starts or is built (not only when someone runs a tool)?
    pub fn runs_without_a_command(self) -> bool {
        !matches!(self, HookKind::Generate)
    }
}

/// One thing that runs by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hook {
    pub kind: HookKind,
    /// The declaration (a node of the tree), or [`NONE`] for a comment.
    pub node: u32,
    /// The span of the code that runs, in code points: a function's whole declaration; the values of a variable's
    /// initializer; the cgo preamble and the import; a directive's comment.
    pub start: u32,
    pub end: u32,
    /// What makes it a hook: the first call's callee as written (`regexp.MustCompile`), `init`, the directive's
    /// arguments, `import "C"` (or `import "C" with #cgo lines`). At most [`MAX_WHY`] code points.
    pub why: String,
}

/// The longest `why`.
pub const MAX_WHY: usize = 160;

/// The names Go predeclares: a call of one is a conversion or a built-in, which runs nothing of the package's.
const PREDECLARED: &[&str] = &[
    "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16", "int32", "int64", "rune",
    "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any", "append", "cap", "clear", "close", "complex",
    "copy", "delete", "imag", "len", "make", "max", "min", "new", "panic", "print", "println", "real", "recover",
];

fn text(src: &[u32], start: u32, end: u32) -> String {
    src[(start as usize).min(src.len())..(end as usize).min(src.len())].iter().filter_map(|&c| char::from_u32(c)).collect()
}

fn same(src: &[u32], start: u32, end: u32, word: &str) -> bool {
    let len = (end - start) as usize;
    len == word.chars().count()
        && src[start as usize..end as usize].iter().zip(word.chars()).all(|(&a, b)| a == b as u32)
}

fn short(s: String) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > MAX_WHY {
        s.chars().take(MAX_WHY).collect()
    } else {
        s
    }
}

/// The first call in `expr` that runs something: not a conversion (a type before the parenthesis) and not a built-in,
/// and not inside a function literal. Its callee's span.
fn first_call(tree: &Tree, src: &[u32], expr: NodeId) -> Option<(u32, u32)> {
    let mut stack = vec![expr];
    let mut kids: Vec<u32> = Vec::new();
    let mut found: Option<(u32, u32)> = None;
    while let Some(id) = stack.pop() {
        let n = tree.node(id);
        if n.kind == Kind::FuncLit {
            continue; // a value, not a run: its body runs when it is called, and a call of it is a CallExpr above
        }
        if n.kind == Kind::CallExpr {
            let fun = tree.node(n.f[0]);
            let mut inner = fun;
            while inner.kind == Kind::ParenExpr && inner.f[0] != NONE {
                inner = tree.node(inner.f[0]);
            }
            let conversion = match inner.kind {
                Kind::ArrayType | Kind::MapType | Kind::ChanType | Kind::FuncType | Kind::StructType | Kind::InterfaceType => true,
                // `(*T)(p)`: a conversion to a pointer type (a call of a dereferenced function is rare enough to miss)
                Kind::StarExpr => fun.kind == Kind::ParenExpr,
                Kind::Ident => PREDECLARED.iter().any(|w| same(src, inner.start, inner.end, w)),
                _ => false,
            };
            if !conversion {
                // the earliest call in the text is the one to name
                if found.map_or(true, |(s, _)| fun.start < s) {
                    found = Some((fun.start, fun.end));
                }
            }
        }
        kids.clear();
        tree.each_child(id, &mut |x| kids.push(x));
        stack.extend(kids.iter().rev());
    }
    found
}

/// Is the text between `from` and `to` only white space with at most one line break (so a comment ending at `from` leads
/// what starts at `to`)?
fn leads(src: &[u32], from: usize, to: usize) -> bool {
    let mut lines = 0;
    for &c in &src[from.min(src.len())..to.min(src.len())] {
        match c {
            0x0A => lines += 1,
            0x20 | 0x09 | 0x0D => {}
            _ => return false,
        }
    }
    lines <= 1
}

/// The comment group that leads the declaration or spec starting at `start` (comments with no blank line between them,
/// the last one ending on the line before, or on the line of, `start`): its first comment's start, or `start`.
fn lead_start(src: &[u32], comments: &[(usize, usize)], start: usize) -> usize {
    let mut at = start;
    // the comments that end at or before `start` (the list is in order, so a search finds where they end)
    let mut i = comments.partition_point(|&(_, ce)| ce <= start);
    while i > 0 {
        i -= 1;
        let (cs, ce) = comments[i];
        if leads(src, ce, at) {
            at = cs;
        } else {
            break;
        }
    }
    at
}

/// The hooks of a parsed file, in the order of the text. `comments` are the spans of the comments of `src` (the `comments`
/// of `lex::structure(src, "go", false)`), in order.
pub fn hooks(tree: &Tree, src: &[u32], comments: &[(usize, usize)]) -> Vec<Hook> {
    let mut out: Vec<Hook> = Vec::new();
    if tree.root == NONE {
        return out;
    }
    for &decl in tree.items(tree.node(tree.root).f[1]) {
        let d = tree.node(decl);
        match d.kind {
            Kind::FuncDecl => {
                let name = d.f[1];
                if d.f[0] == NONE && name != NONE {
                    let nm = tree.node(name);
                    if same(src, nm.start, nm.end, "init") {
                        out.push(Hook { kind: HookKind::InitFn, node: decl, start: d.start, end: d.end, why: "init".to_string() });
                    }
                }
            }
            Kind::GenDecl if d.op == Tok::Var as u8 => {
                for &spec in tree.items(d.f[0]) {
                    let s = tree.node(spec);
                    let values = tree.items(s.f[2]);
                    let call = values.iter().find_map(|&v| first_call(tree, src, v));
                    if let (Some((cs, ce)), Some(&first), Some(&last)) = (call, values.first(), values.last()) {
                        out.push(Hook {
                            kind: HookKind::VarInit,
                            node: spec,
                            start: tree.node(first).start,
                            end: tree.node(last).end,
                            why: short(text(src, cs, ce)),
                        });
                    }
                }
            }
            Kind::GenDecl if d.op == Tok::Import as u8 => {
                for &spec in tree.items(d.f[0]) {
                    let s = tree.node(spec);
                    if s.f[1] == NONE {
                        continue;
                    }
                    let path = tree.node(s.f[1]);
                    let lit = text(src, path.start, path.end);
                    if lit != "\"C\"" && lit != "`C`" {
                        continue;
                    }
                    // the preamble is the comment that leads the declaration (`import "C"`), or the spec in a group
                    let node_start = if d.flags & PAREN == 0 { d.start } else { s.start } as usize;
                    let from = lead_start(src, comments, node_start);
                    let preamble = text(src, from as u32, node_start as u32);
                    let with_cgo = preamble.lines().any(|l| l.trim_start_matches(|c: char| c == '/' || c == '*' || c.is_whitespace()).starts_with("#cgo"));
                    out.push(Hook {
                        kind: HookKind::Cgo,
                        node: spec,
                        start: from as u32,
                        end: s.end,
                        why: if with_cgo { "import \"C\" with #cgo lines".to_string() } else { "import \"C\"".to_string() },
                    });
                }
            }
            _ => {}
        }
    }
    // directives: line comments written `//go:name args` (no space after the slashes)
    for &(cs, ce) in comments {
        if !(ce >= cs + 5 && same(src, cs as u32, cs as u32 + 5, "//go:")) {
            continue;
        }
        let line = text(src, cs as u32, ce as u32);
        let Some(rest) = line.strip_prefix("//go:") else { continue };
        let (name, args) = match rest.split_once(|c: char| c == ' ' || c == '\t') {
            Some((n, a)) => (n, a.trim()),
            None => (rest.trim_end(), ""),
        };
        let kind = match name {
            "linkname" => HookKind::Linkname,
            "generate" => HookKind::Generate,
            _ => continue,
        };
        out.push(Hook { kind, node: NONE, start: cs as u32, end: ce as u32, why: short(args.to_string()) });
    }
    out.sort_by_key(|h| (h.start, h.end));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::goparse::parse;
    use crate::lex;

    fn run(s: &str) -> (Vec<u32>, Vec<Hook>) {
        let src: Vec<u32> = s.chars().map(|c| c as u32).collect();
        let tree = parse(&src).expect("the file parses");
        let comments = lex::structure(&src, "go", false).expect("go is a language").comments;
        let h = hooks(&tree, &src, &comments);
        (src, h)
    }

    fn of(s: &str) -> Vec<(String, String)> {
        run(s).1.iter().map(|h| (h.kind.name().to_string(), h.why.clone())).collect()
    }

    fn span(s: &str, h: &Hook) -> String {
        s.chars().skip(h.start as usize).take((h.end - h.start) as usize).collect()
    }

    fn pair(a: &str, b: &str) -> (String, String) {
        (a.to_string(), b.to_string())
    }

    #[test]
    fn init_functions_are_hooks_and_methods_and_other_names_are_not() {
        let s = "package p\nfunc init() { run() }\nfunc init() {}\nfunc (t T) init() {}\nfunc initx() {}\nfunc Init() {}\nfunc f() { init2() }\n";
        assert_eq!(of(s), vec![pair("init-fn", "init"), pair("init-fn", "init")]);
        let (_, h) = run(s);
        assert_eq!(span(s, &h[0]), "func init() { run() }");
    }

    #[test]
    fn a_variable_initialized_by_a_call_is_a_hook() {
        let s = "package p\nvar a = f()\nvar b, c = 1, g.H(2)\nvar (\n\td = regexp.MustCompile(`x`)\n\te = 5\n)\nvar _ = pkg.Register(x)\n";
        assert_eq!(of(s), vec![pair("var-init", "f"), pair("var-init", "g.H"), pair("var-init", "regexp.MustCompile"), pair("var-init", "pkg.Register")]);
        let (_, h) = run(s);
        assert_eq!(span(s, &h[1]), "1, g.H(2)");
        assert_eq!(span(s, &h[2]), "regexp.MustCompile(`x`)");
    }

    #[test]
    fn conversions_and_built_ins_run_nothing_of_the_packages() {
        let s = "package p\nvar a = int64(1)\nvar b = []byte(\"x\")\nvar c = make(map[string]int)\nvar d = len(\"abc\")\nvar e = map[string]int{}\nvar f = new(T)\nvar g = (func())(nil)\nvar h = string(rune(65))\n";
        assert_eq!(of(s), vec![]);
        assert_eq!(of("package p\nvar a = []byte(f())\n"), vec![pair("var-init", "f")]);
        assert_eq!(of("package p\nvar a = T(1)\n"), vec![pair("var-init", "T")]);
    }

    #[test]
    fn a_call_in_a_function_literal_is_not_run_by_the_declaration_unless_the_literal_is_called() {
        assert_eq!(of("package p\nvar a = func() { run() }\nvar b = map[string]func(){\"x\": func() { run() }}\n"), vec![]);
        assert_eq!(of("package p\nvar a = func() int { return run() }()\n"), vec![pair("var-init", "func() int { return run() }")]);
        assert_eq!(of("package p\nvar a = []int{f(), 1}\n"), vec![pair("var-init", "f")]);
    }

    #[test]
    fn declarations_inside_functions_and_constants_are_not_hooks() {
        assert_eq!(of("package p\nfunc f() {\n\tvar a = g()\n\t_ = a\n}\nconst c = 1\nvar x int\nvar y = 3 + 4\n"), vec![]);
    }

    #[test]
    fn a_cgo_import_is_a_hook_with_its_preamble() {
        let s = "package p\n\n// #cgo LDFLAGS: -lm\n// #include <math.h>\nimport \"C\"\n\nfunc f() {}\n";
        assert_eq!(of(s), vec![pair("cgo", "import \"C\" with #cgo lines")]);
        let (_, h) = run(s);
        assert_eq!(span(s, &h[0]), "// #cgo LDFLAGS: -lm\n// #include <math.h>\nimport \"C\"");
        let s = "package p\n\n/*\n#include <stdio.h>\nstatic void f(void) { puts(\"x\"); }\n*/\nimport \"C\"\n";
        assert_eq!(of(s), vec![pair("cgo", "import \"C\"")]);
        let (_, h) = run(s);
        assert!(span(s, &h[0]).starts_with("/*\n#include"));
        assert!(span(s, &h[0]).ends_with("import \"C\""));
    }

    #[test]
    fn the_preamble_is_only_the_comment_that_leads_the_import() {
        let s = "package p\n\n// not the preamble\n\nimport \"C\"\n";
        let (_, h) = run(s);
        assert_eq!(span(s, &h[0]), "import \"C\"");
        let s = "package p\n\nimport (\n\t\"fmt\"\n\n\t// #include <x.h>\n\t\"C\"\n)\n";
        assert_eq!(of(s), vec![pair("cgo", "import \"C\"")]);
        let (_, h) = run(s);
        assert_eq!(span(s, &h[0]), "// #include <x.h>\n\t\"C\"");
        assert_eq!(of("package p\nimport \"fmt\"\nimport c \"cgo\"\nimport \"Cx\"\n"), vec![]);
        assert_eq!(of("package p\nimport `C`\n"), vec![pair("cgo", "import \"C\"")]);
    }

    #[test]
    fn linkname_and_generate_directives_are_hooks_and_other_comments_are_not() {
        let s = "package p\n//go:linkname local runtime.nanotime\n//go:generate go run gen.go -out x\n// go:generate not a directive\n//go:noinline\n//go:embed x\nvar s = \"//go:linkname a b\"\n/* //go:generate no */\n";
        assert_eq!(of(s), vec![pair("linkname", "local runtime.nanotime"), pair("generate", "go run gen.go -out x")]);
        let (_, h) = run(s);
        assert_eq!(span(s, &h[0]), "//go:linkname local runtime.nanotime");
        assert_eq!(h[0].node, NONE);
        assert!(HookKind::Linkname.runs_without_a_command());
        assert!(!HookKind::Generate.runs_without_a_command());
    }

    #[test]
    fn hooks_come_in_the_order_of_the_text_and_a_long_why_is_cut() {
        let long = "x".repeat(400);
        let s = format!("package p\nvar a = {}()\n//go:generate {}\nfunc init() {{}}\n", long, long);
        let got = of(&s);
        assert_eq!(got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), vec!["var-init", "generate", "init-fn"]);
        assert_eq!(got[0].1.chars().count(), MAX_WHY);
        assert_eq!(got[1].1.chars().count(), MAX_WHY);
    }

    #[test]
    fn nothing_in_nothing_out() {
        assert_eq!(of("package p\n"), vec![]);
        let tree = Tree::new();
        assert_eq!(hooks(&tree, &[], &[]), vec![]);
    }

    #[test]
    fn a_deeply_nested_initializer_is_read_without_recursion() {
        let mut s = String::from("package p\nvar a = ");
        for _ in 0..100 {
            s.push_str("[]int{");
        }
        s.push_str("f()");
        for _ in 0..100 {
            s.push('}');
        }
        s.push('\n');
        assert_eq!(of(&s), vec![pair("var-init", "f")]);
    }
}
