//! What a JavaScript module loads when it runs (D-13), read on the engine's tree: the specifier of each `require()`
//! given a literal (a string, or a template without substitutions) outside any function, class body and `try`
//! statement, of each import and export-from declaration (and TypeScript's `import x = require('m')`), and of each
//! `import()` given a literal outside any function. A `require()` in a function runs when the function is called,
//! and one in a `try` is an optional dependency the module does without; a class's static block and static fields
//! run when the class is defined, its methods and other fields when they are called or an instance is made. The registry compares the packages the specifiers name with the release's package.json
//! (repo._dev_only_loads): dotenv-express 17.4.3 requires `environment-gate`, which its package.json names only in
//! devDependencies.

use crate::jsflow::{Ast, NODE_BUILTINS};
use crate::jsparse::tree::{self as jt, Kind, NodeId, NONE};
use crate::pystr::{self, u, PyStr};

/// How a module loads a specifier: `require()` (and `import x = require()`), an import or export-from declaration,
/// `import()`.
pub const REQUIRE: &str = "require";
pub const IMPORT: &str = "import";
pub const DYNAMIC: &str = "import()";

/// [(specifier, 1-based line, how)] in the module's order, or None when the text does not parse (in the dialect of
/// `path`'s extension, then as TypeScript, which hosts hand as JavaScript).
pub fn js_loads(text: &[u32], path: &[u32]) -> Option<Vec<(PyStr, u32, &'static str)>> {
    let (mut ts, _jsx) = crate::jsparse::dialect(path);
    let tree = match crate::jsparse::parse_file(path, text) {
        Ok(t) => t,
        Err(_) if !ts => {
            ts = true;
            crate::jsparse::parse_file(&u("module.ts"), text).ok()?
        }
        Err(_) => return None,
    };
    let a = Ast(&tree);
    let mut out = Vec::new();
    // (a node, and whether it runs when the module does)
    let mut stack: Vec<(NodeId, bool)> = vec![(tree.root, true)];
    while let Some((id, live)) = stack.pop() {
        if id == NONE {
            continue;
        }
        let kind = a.kind(id);
        let found = match kind {
            Kind::CallExpression if live && a.is_ident_named(a.at(id, jt::A), "require") => {
                a.list(id, jt::B).first().and_then(|&arg| literal(&a, arg)).map(|s| (s, REQUIRE))
            }
            // (in TypeScript the parser keeps no names of `import type … from`: such an import loads nothing)
            Kind::ImportDeclaration if !(ts && a.list(id, jt::A).is_empty()) => {
                literal(&a, a.at(id, jt::B)).map(|s| (s, IMPORT))
            }
            Kind::ExportNamedDeclaration if !(ts && a.list(id, jt::B).is_empty()) => {
                a.opt(id, jt::C).and_then(|src| literal(&a, src)).map(|s| (s, IMPORT))
            }
            Kind::ExportAllDeclaration => literal(&a, a.at(id, jt::B)).map(|s| (s, IMPORT)),
            Kind::TSImportEquals if live => a.opt(id, jt::B).and_then(|m| literal(&a, m)).map(|s| (s, REQUIRE)),
            Kind::ImportExpression if live => literal(&a, a.at(id, jt::A)).map(|s| (s, DYNAMIC)),
            _ => None,
        };
        if let Some((spec, how)) = found {
            out.push((spec, a.line(id), how));
        }
        let inner = live && !a.is_function(id) && !matches!(kind, Kind::TryStatement | Kind::ClassBody);
        for &k in a.kids(id).iter().rev() {
            let at_definition = a.kind(k) == Kind::StaticBlock || (a.kind(k) == Kind::PropertyDefinition && a.flag(k, jt::STATIC));
            let runs = if kind == Kind::ClassBody && at_definition { live } else { inner };
            stack.push((k, runs));
        }
    }
    Some(out)
}

/// The npm package a module specifier names (`@s/n/sub`: `@s/n`; `n/sub`: `n`), or None: a relative or absolute
/// path, a `#` import, a URL or another scheme's (`node:`, `bun:`, `data:`), one of Node's built-in modules.
pub fn npm_package(spec: &[u32]) -> Option<PyStr> {
    let first = *spec.first()?;
    if first == c('.') || first == c('/') || first == c('#') || first == c('\\') || spec.contains(&c(':')) {
        return None;
    }
    let parts = pystr::split_char(spec, c('/'));
    if first == c('@') {
        return match parts.as_slice() {
            [scope, name, ..] if scope.len() > 1 && !name.is_empty() => Some(pystr::join(&u("/"), &[*scope, *name])),
            _ => None,
        };
    }
    let name = parts[0];
    if name.is_empty() || NODE_BUILTINS.iter().any(|b| pystr::eq(name, b)) {
        return None;
    }
    Some(name.to_vec())
}

const fn c(ch: char) -> u32 {
    ch as u32
}

/// A literal module specifier: a string, or a template without substitutions (as written).
fn literal(a: &Ast, id: NodeId) -> Option<PyStr> {
    if id == NONE {
        return None;
    }
    if let Some(s) = a.str_value(id) {
        return Some(s.to_vec());
    }
    if a.kind(id) == Kind::TemplateLiteral && a.list(id, jt::B).is_empty() {
        if let [q] = a.list(id, jt::A) {
            return Some(a.s(*q, jt::A).to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pystr;

    fn loads(text: &str, path: &str) -> Vec<(String, u32, &'static str)> {
        let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
        js_loads(&cps, &u(path)).expect("parses").into_iter().map(|(s, l, h)| (pystr::to_string(&s), l, h)).collect()
    }

    fn specs(text: &str) -> Vec<String> {
        loads(text, "index.js").into_iter().map(|(s, _, _)| s).collect()
    }

    #[test]
    fn what_a_module_loads_when_it_runs() {
        // dotenv-express 17.4.3's shape: a require at the module's top, the package called later
        let dx = "const fs = require('fs')\nconst gate = require('environment-gate')\nfunction config () {\n  \
                  gate.gate()\n}\nmodule.exports = { config }\n";
        assert_eq!(loads(dx, "lib/main.js"), vec![("fs".into(), 1, REQUIRE), ("environment-gate".into(), 2, REQUIRE)]);
        // declarations; a template without substitutions; a condition, which runs at load
        assert_eq!(specs("import a from 'a';\nimport 'b';\nexport * from 'c';\nexport { d } from 'd';\n\
                          const e = require(`e`);\nif (process.env.X) { require('f'); }\nimport('g');\n"),
                   vec!["a", "b", "c", "d", "e", "f", "g"]);
        // what does not run when the module does: a function's, a method's, an optional dependency's
        assert_eq!(specs("function f() { return require('a'); }\nconst g = () => require('b');\n\
                          class C { m() { require('c'); } y = require('y'); static z = () => require('z'); }\n\
                          try { require('d'); } catch (e) { require('e'); }\nconst h = async () => import('h');\n"),
                   Vec::<String>::new());
        // a class's static block and static fields run when the class is defined
        assert_eq!(specs("class C { static { require('s'); } static x = require('x'); }\n"), vec!["s", "x"]);
        // not literals: what the code builds
        assert_eq!(specs("const n = 'x';\nrequire(n);\nrequire('a' + n);\nrequire(`${n}`);\nimport(n);\n"),
                   Vec::<String>::new());
        // TypeScript: `import x = require()`; an import of types alone loads nothing
        assert_eq!(loads("import x = require('m');\nimport type { T } from 't';\nimport { u } from 'u';\n\
                          export type { V } from 'v';\nexport { type W } from 'w';\n", "a.ts"),
                   vec![("m".into(), 1, REQUIRE), ("u".into(), 3, IMPORT)]);
        // what does not parse
        assert!(js_loads(&u("const = ;"), &u("x.js")).is_none());
    }

    #[test]
    fn the_package_a_specifier_names() {
        let pkg = |s: &str| npm_package(&u(s)).map(|p| pystr::to_string(&p));
        assert_eq!(pkg("environment-gate"), Some("environment-gate".into()));
        assert_eq!(pkg("lodash/fp/map"), Some("lodash".into()));
        assert_eq!(pkg("@scope/name/sub"), Some("@scope/name".into()));
        for none in ["./x", "../x", "/abs", "#internal", "node:fs", "bun:ffi", "https://h.invalid/x.js", "fs",
                     "fs/promises", "child_process", "@scope", "@/x", ""] {
            assert_eq!(pkg(none), None, "{}", none);
        }
    }
}
