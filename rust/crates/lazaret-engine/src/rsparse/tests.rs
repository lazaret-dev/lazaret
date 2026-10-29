use super::*;

fn p(s: &str) -> (Vec<u32>, Tree) {
    let src: Vec<u32> = s.chars().map(|c| c as u32).collect();
    let t = parse(&src);
    (src, t)
}

/// `Kind name` of every item, in order.
fn items(s: &str) -> Vec<String> {
    let (src, t) = p(s);
    (0..t.items.len())
        .map(|i| {
            let n = t.name(&src, i);
            if n.is_empty() {
                t.items[i].kind.name().to_string()
            } else {
                format!("{} {}", t.items[i].kind.name(), n)
            }
        })
        .collect()
}

fn text_of(s: &str, from: u32, to: u32) -> String {
    s.chars().skip(from as usize).take((to - from) as usize).collect()
}

/// The source text of every item, in order.
fn spans(s: &str) -> Vec<String> {
    let (_, t) = p(s);
    t.items.iter().map(|it| text_of(s, it.start, it.end)).collect()
}

fn problems(s: &str) -> u32 {
    p(s).1.problems
}

fn attr_names(s: &str, i: usize) -> Vec<String> {
    let (src, t) = p(s);
    t.attrs_of(i).iter().map(|a| t.attr_path(&src, a)).collect()
}

fn leaves(s: &str) -> Vec<String> {
    let (src, t) = p(s);
    t.leaves
        .iter()
        .map(|l| {
            let mut x = t.leaf_path(&src, l);
            if l.alias != NONE {
                x.push_str(&format!(" as {}", t.ident(&src, l.alias)));
            }
            x
        })
        .collect()
}

#[test]
fn each_kind_of_item_is_found_with_its_name() {
    let src = "use a::b;\nextern crate c;\nmod d;\nmod e { }\nstruct F;\nstruct G(u8);\nstruct H { x: u8 }\nenum I { A, B }\nunion J { a: u8 }\n\
               trait K { }\ntrait L = M;\nimpl N { }\nimpl O for N { }\nfn p() { }\nstatic Q: u8 = 1;\nconst R: u8 = 2;\ntype S = u8;\n\
               macro_rules! t { () => {} }\nu!{ }\nv!();\nextern \"C\" { fn w(); }\n";
    assert_eq!(
        items(src),
        vec![
            "Use", "ExternCrate c", "Mod d", "Mod e", "Struct F", "Struct G", "Struct H", "Enum I", "Union J", "Trait K", "TraitAlias L", "Impl", "Impl",
            "Fn p", "Static Q", "Const R", "TyAlias S", "MacroDef t", "MacCall u", "MacCall v", "ForeignMod", "Fn w"
        ]
    );
}

#[test]
fn an_item_spans_from_its_visibility_to_its_semicolon_or_closing_brace() {
    let src = "pub struct A;\n#[derive(X)]\npub(crate) struct B { x: u8 }\nunsafe impl Send for B {}\nconst fn f() -> u8 { 1 }\nm!{ a }\nn!(b);\nmacro_rules! o ( () => () );\nuse a::{b, c};\n";
    assert_eq!(
        spans(src),
        vec![
            "pub struct A;",
            "pub(crate) struct B { x: u8 }",
            "unsafe impl Send for B {}",
            "const fn f() -> u8 { 1 }",
            "m!{ a }",
            "n!(b);",
            "macro_rules! o ( () => () );",
            "use a::{b, c};"
        ]
    );
}

#[test]
fn visibility_and_qualifiers() {
    let (_, t) = p("pub fn a() {}\npub(crate) fn b() {}\npub(in x::y) fn c() {}\npub(self) fn d() {}\npub(super) fn e() {}\nfn f() {}\n");
    let vis: Vec<Vis> = t.items.iter().map(|i| i.vis).collect();
    assert_eq!(vis, vec![Vis::Pub, Vis::Restricted, Vis::Restricted, Vis::Restricted, Vis::Restricted, Vis::Inherited]);
    let (src, t) = p("const unsafe fn a() {}\nasync fn b() {}\nunsafe extern \"C\" fn c() {}\nextern fn d() {}\nunsafe trait E {}\nauto trait F {}\nunsafe impl G for H {}\nimpl !I for J {}\nstatic mut K: u8 = 0;\ndefault fn l() {}\n");
    let f: Vec<u16> = t.items.iter().map(|i| i.flags).collect();
    assert_eq!(f[0], CONST | UNSAFE);
    assert_eq!(f[1], ASYNC);
    assert_eq!(f[2], UNSAFE | EXTERN);
    assert_eq!(t.text(&src, t.items[2].abi), "\"C\"");
    assert_eq!(f[3], EXTERN);
    assert_eq!(t.items[3].abi, NONE);
    assert_eq!(f[4], UNSAFE);
    assert_eq!(f[5], AUTO);
    assert_eq!(f[6], UNSAFE);
    assert_eq!(f[7], NEGATIVE);
    assert_eq!(f[8], MUT);
    assert_eq!(f[9], DEFAULT);
    assert_eq!(t.items[2].kind, Kind::Fn);
}

#[test]
fn keywords_of_some_editions_are_names() {
    assert_eq!(items("mod gen { fn try() {} fn dyn() {} struct await; }"), vec!["Mod gen", "Fn try", "Fn dyn", "Struct await"]);
    assert_eq!(items("fn f() { try!(x); fn g() {} }"), vec!["Fn f", "Fn g"]);
}

#[test]
fn a_negative_implementation_has_a_trait_and_a_for() {
    let (_, t) = p("impl !Send for T {}\nimpl ! {}\nimpl<T> !Sync for U<T> {}\n");
    assert_eq!(t.items.iter().map(|i| i.flags & NEGATIVE != 0).collect::<Vec<_>>(), vec![true, false, true]);
}

#[test]
fn an_unsafe_attribute_has_the_path_inside() {
    let (src, t) = p("#[unsafe(no_mangle)] pub extern \"C\" fn f() {}\n#[unsafe(export_name = \"x\")] fn g() {}\n#[unsafe(a::b(c))] fn h() {}\n#[unsafe] fn i() {}\n#[unsafe (x)] fn j() {}\n");
    let names: Vec<String> = (0..5).map(|i| t.attr_path(&src, &t.attrs_of(i)[0])).collect();
    assert_eq!(names, vec!["no_mangle", "export_name", "a::b", "unsafe", "x"]);
    assert_eq!((0..5).map(|i| t.attr_is_unsafe(&src, &t.attrs_of(i)[0])).collect::<Vec<_>>(), vec![true, true, true, false, true]);
    let (o, c) = t.attr_args(&src, &t.attrs_of(2)[0]).unwrap();
    assert_eq!((t.text(&src, o), t.text(&src, c)), ("(".to_string(), ")".to_string()));
    assert!(t.attr_args(&src, &t.attrs_of(0)[0]).is_none());
}

#[test]
fn a_foreign_block_and_its_items() {
    let (src, t) = p("unsafe extern \"C\" { pub safe fn a(); static B: u8; type C; }\nextern { fn d(); }\n");
    assert_eq!(t.items[0].kind, Kind::ForeignMod);
    assert_eq!(t.items[0].flags, UNSAFE | EXTERN);
    assert_eq!(t.text(&src, t.items[0].abi), "\"C\"");
    assert_eq!(t.items[1].flags, SAFE);
    assert_eq!(items("extern { fn d(); }"), vec!["ForeignMod", "Fn d"]);
    assert_eq!(items("unsafe extern \"C\" { pub safe fn a(); static B: u8; type C; }"), vec!["ForeignMod", "Fn a", "Static B", "TyAlias C"]);
}

#[test]
fn attributes_are_on_the_item_they_come_before() {
    let src = "#![no_std]\n/// docs\n#[derive(Debug)]\n#[cfg(feature = \"x\")]\n#[a::b(c, d = \"e\")]\nstruct S;\n#[no_mangle] pub extern \"C\" fn f() {}\nstruct T;\n";
    assert_eq!(attr_names(src, 0), vec!["derive", "cfg", "a::b"]);
    assert_eq!(attr_names(src, 1), vec!["no_mangle"]);
    assert_eq!(attr_names(src, 2), Vec::<String>::new());
    let (src2, t) = p(src);
    assert_eq!(t.crate_attrs.1, 1);
    assert_eq!(t.attr_path(&src2, &t.attrs[t.crate_attrs.0 as usize]), "no_std");
    // the span of the item does not include its attributes
    assert_eq!(spans(src)[0], "struct S;");
}

#[test]
fn inner_attributes_belong_to_the_braces_they_are_in() {
    let (src, t) = p("mod m { #![allow(x)] #![deny(y)] fn f() { #![inline] } }\n");
    assert_eq!(t.inner_attrs_of(0).len(), 2);
    assert_eq!(t.attr_path(&src, &t.inner_attrs_of(0)[1]), "deny");
    assert_eq!(t.inner_attrs_of(1).len(), 1);
    assert_eq!(t.attr_path(&src, &t.inner_attrs_of(1)[0]), "inline");
    assert_eq!(t.crate_attrs.1, 0);
}

#[test]
fn attribute_arguments() {
    let (src, t) = p("#[cfg_attr(a, derive(B))] struct S;\n#[doc = \"x\"] struct T;\n#[x] struct U;\n");
    let a = &t.attrs_of(0)[0];
    let (o, c) = t.attr_args(&src, a).unwrap();
    assert_eq!(t.text(&src, o), "(");
    assert_eq!(t.text(&src, c), ")");
    assert!(t.attr_args(&src, &t.attrs_of(1)[0]).is_none());
    assert!(t.attr_args(&src, &t.attrs_of(2)[0]).is_none());
    assert_eq!(t.attr_path(&src, &t.attrs_of(1)[0]), "doc");
}

#[test]
fn items_in_bodies_are_found_and_marked_local() {
    let src = "fn main() {\n    fn inner() {}\n    struct Local;\n    let x = 1;\n    static S: u8 = 0;\n    const C: u8 = 1;\n    use std::io;\n    impl Local {}\n}\n";
    assert_eq!(items(src), vec!["Fn main", "Fn inner", "Struct Local", "Static S", "Const C", "Use", "Impl"]);
    let (_, t) = p(src);
    assert_eq!(t.items[0].flags & LOCAL, 0);
    for i in 1..7 {
        assert_ne!(t.items[i].flags & LOCAL, 0, "{}", i);
        assert_eq!(t.items[i].parent, 0);
    }
}

#[test]
fn items_in_nested_blocks_closures_and_initializers() {
    assert_eq!(items("fn f() { if a { fn g() {} } else { fn h() {} } }"), vec!["Fn f", "Fn g", "Fn h"]);
    assert_eq!(items("fn f() { let c = || { fn g() {} }; foo(|| { struct S; }); }"), vec!["Fn f", "Fn g", "Struct S"]);
    assert_eq!(items("fn f() { unsafe { fn g() {} } async { fn h() {} } }"), vec!["Fn f", "Fn g", "Fn h"]);
    assert_eq!(items("const X: () = { fn g() {} };\nstatic Y: u8 = { struct S; 0 };"), vec!["Const X", "Fn g", "Static Y", "Struct S"]);
    assert_eq!(items("fn f() { match x { A => { fn g() {} } _ => {} } }"), vec!["Fn f", "Fn g"]);
    assert_eq!(items("impl T { const C: u8 = { fn g() {} 0 }; fn m() { fn n() {} } }"), vec!["Impl", "Const C", "Fn g", "Fn m", "Fn n"]);
    assert_eq!(items("fn f() { { { fn deep() {} } } }"), vec!["Fn f", "Fn deep"]);
}

#[test]
fn a_statement_item_after_a_block_or_a_semicolon() {
    assert_eq!(items("fn f() { if a {} fn g() {} match b { _ => {} } struct S; let x = S {}; enum E {} }"), vec!["Fn f", "Fn g", "Struct S", "Enum E"]);
}

#[test]
fn what_is_not_an_item_in_a_block_is_not_one() {
    // blocks, closures and types that start with the words of items
    assert_eq!(items("fn f() { unsafe { x() } let a = async { 1 }; const { 1 }; let g: fn(u8) -> u8 = h; let t: impl Trait; static || {}; }"), vec!["Fn f"]);
    assert_eq!(items("fn f() { let x = S { union: 1, auto: 2, default: 3 }; let union = 1; let auto = default; }"), vec!["Fn f"]);
}

#[test]
fn a_macros_tokens_are_not_read_as_code() {
    assert_eq!(items("m! { fn f() {} struct S; }"), vec!["MacCall m"]);
    assert_eq!(items("fn g() { println!(\"{}\", { fn x() {} 1 }); vec![fn_like(|| { fn y() {} })]; m!{ fn z() {} } }"), vec!["Fn g"]);
    assert_eq!(items("macro_rules! m { () => { fn f() {} struct S; } }"), vec!["MacroDef m"]);
    assert_eq!(items("a::b::c!{ fn f() {} }"), vec!["MacCall c"]);
    assert_eq!(items("::a::b!(x);"), vec!["MacCall b"]);
    // a statement macro, then an item
    assert_eq!(items("fn f() { m!{ x } fn g() {} n!(y); fn h() {} }"), vec!["Fn f", "Fn g", "Fn h"]);
    // `!` that is not a macro's
    assert_eq!(items("fn f() { if !(a) { fn g() {} } while !{ true } { fn h() {} } return !(x); }"), vec!["Fn f", "Fn g", "Fn h"]);
}

#[test]
fn angle_brackets_are_told_from_braces() {
    assert_eq!(spans("fn f<const N: usize = { 3 }>() {}"), vec!["fn f<const N: usize = { 3 }>() {}"]);
    assert_eq!(spans("struct S<const N: usize = { 3 }>;"), vec!["struct S<const N: usize = { 3 }>;"]);
    assert_eq!(items("impl<T> Tr<{ N }> for X<T> where T: Fn() -> u8 { fn m() {} }"), vec!["Impl", "Fn m"]);
    assert_eq!(items("fn f() -> Foo<{ N }> { fn g() {} }"), vec!["Fn f", "Fn g"]);
    assert_eq!(items("fn f<F: Fn() -> Vec<u8>>(x: F) -> impl Fn(u8) -> u8 where F: Send { fn g() {} }"), vec!["Fn f", "Fn g"]);
    assert_eq!(spans("trait T<const N: usize = { 3 }> { fn f(); }"), vec!["trait T<const N: usize = { 3 }> { fn f(); }", "fn f();"]);
    assert_eq!(items("struct S<T>(T) where T: Copy;\nstruct U<T> where T: Copy { x: T }"), vec!["Struct S", "Struct U"]);
    assert_eq!(items("fn f() where for<'a> &'a u8: Copy, [u8; { 3 }]: Sized {}"), vec!["Fn f"]);
}

#[test]
fn the_for_of_an_implementation() {
    let (src, t) = p("impl<T: for<'a> Fn(&'a u8)> Tr for X<T> {}\nimpl X {}\nimpl<T> Tr<for<'a> fn(&'a u8)> for Y<T> where T: Copy {}\n");
    assert_eq!(t.text(&src, t.items[0].extra), "for");
    assert!(t.items[0].extra > 10);
    assert_eq!(t.items[1].extra, NONE);
    assert_eq!(t.items[2].kind, Kind::Impl);
    assert_ne!(t.items[2].extra, NONE);
}

#[test]
fn statics_and_consts() {
    let (src, t) = p("static A: &dyn Iterator<Item = u8> = &x;\nconst _: () = ();\nconst B: u8 = if c { 1 } else { 2 };\nstatic mut C: [u8; 3] = [0; 3];\nconst D: u8;\n");
    assert_eq!(items("static A: &dyn Iterator<Item = u8> = &x;\nconst _: () = ();"), vec!["Static A", "Const _"]);
    assert_eq!(t.text(&src, t.items[0].extra), "=");
    // the `=` of the `Item = u8` is not the item's
    assert_eq!(t.toks[t.items[0].extra as usize].start, "static A: &dyn Iterator<Item = u8> ".chars().count() as u32);
    assert_eq!(t.items[4].extra, NONE);
    assert_eq!(t.items[3].flags, MUT);
}

#[test]
fn use_trees() {
    assert_eq!(leaves("use a::b::c;"), vec!["a::b::c"]);
    assert_eq!(leaves("use a::{b, c::d, e::{f, g as h}};"), vec!["a::b", "a::c::d", "a::e::f", "a::e::g as h"]);
    assert_eq!(leaves("use ::a::*; use b::{self, c::*};"), vec!["a::*", "b::self", "b::c::*"]);
    assert_eq!(leaves("use a as _; use {b, c};"), vec!["a as _", "b", "c"]);
    assert_eq!(leaves("use crate::a; use self::b; use super::super::c;"), vec!["crate::a", "self::b", "super::super::c"]);
    assert_eq!(leaves("use a::{};"), Vec::<String>::new());
    assert_eq!(leaves("pub use r#type::r#fn;"), vec!["type::fn"]);
    let (_, t) = p("use a::{b, c}; fn f() { use x::y; }");
    assert_eq!(t.leaves.iter().map(|l| l.item).collect::<Vec<_>>(), vec![0, 0, 2]);
}

#[test]
fn the_leaves_of_use_items_are_bounded() {
    let make = |prefix: usize, leaves: usize| {
        let mut s = String::from("use ");
        for _ in 0..prefix {
            s.push_str("a::");
        }
        s.push('{');
        for _ in 0..leaves {
            s.push_str("b,");
        }
        s.push_str("};");
        s
    };
    let (_, t) = p(&make(1000, 3000));
    assert_eq!(t.leaves.len(), 3000);
    assert_eq!(t.problems, 0);
    // 3000 * 3000 segments is more than the budget: the leaves stop, and the file says so
    let (_, t) = p(&make(3000, 3000));
    assert!(t.leaves.len() < 3000);
    assert!(t.segs.len() <= MAX_USE_SEGS + 3001);
    assert!(t.problems > 0);
}

#[test]
fn names_that_are_contextual_keywords() {
    assert_eq!(
        items("fn default() {}\nfn union() {}\nfn auto() {}\nfn safe() {}\nfn macro_rules() {}\nstruct union;\nstruct auto;\nconst safe: u8 = 1;"),
        vec!["Fn default", "Fn union", "Fn auto", "Fn safe", "Fn macro_rules", "Struct union", "Struct auto", "Const safe"]
    );
    assert_eq!(items("union U { a: u8 }\nunion<T> X;"), vec!["Union U"]);
    assert_eq!(items("fn r#type() {}\nstruct r#struct;"), vec!["Fn type", "Struct struct"]);
    assert_eq!(items("default fn f() {}"), vec!["Fn f"]);
}

#[test]
fn traits_and_impls_hold_their_items() {
    assert_eq!(
        items("trait T { fn a(&self); fn b() { fn c() {} } const D: u8 = 1; type E: Copy; m!(); }"),
        vec!["Trait T", "Fn a", "Fn b", "Fn c", "Const D", "TyAlias E", "MacCall m"]
    );
    assert_eq!(items("impl T for S { fn a(&self) {} const D: u8 = 1; type E = u8; }"), vec!["Impl", "Fn a", "Const D", "TyAlias E"]);
    let (_, t) = p("trait T { fn a(); }\nimpl S { fn b() {} }\nmod m { fn c() {} }\n");
    assert_eq!(t.items[1].parent, 0);
    assert_eq!(t.items[3].parent, 2);
    assert_eq!(t.items[5].parent, 4);
    assert_eq!(t.ancestors(1), vec![0]);
}

#[test]
fn nested_modules() {
    let src = "mod a { mod b { pub fn c() {} } fn d() {} }\nmod e;\n";
    assert_eq!(items(src), vec!["Mod a", "Mod b", "Fn c", "Fn d", "Mod e"]);
    let (_, t) = p(src);
    assert_eq!(t.ancestors(2), vec![1, 0]);
    assert_eq!((t.items[0].parent, t.items[1].parent, t.items[3].parent, t.items[4].parent), (NONE, 0, 0, NONE));
    assert_ne!(t.items[0].body_open, NONE);
    assert_eq!(t.items[4].body_open, NONE);
}

#[test]
fn a_shebang_comments_and_doc_comments_are_not_tokens() {
    assert_eq!(items("#!/usr/bin/env run\n// c\n/* /* nested */ fn no() {} */\n/// doc\nfn a() {}\n/** doc */ fn b() {}\n"), vec!["Fn a", "Fn b"]);
}

#[test]
fn strings_and_chars_hide_their_delimiters() {
    assert_eq!(items("fn f() { let a = \"}\"; let b = '}'; let c = r#\"}\"#; let d = b'}'; fn g() {} }"), vec!["Fn f", "Fn g"]);
    assert_eq!(items("fn f<'a>(x: &'a u8) -> &'a u8 { 'outer: loop { fn g() {} break 'outer; } x }"), vec!["Fn f", "Fn g"]);
}

#[test]
fn a_text_that_is_not_rust_is_read_as_far_as_it_goes() {
    let (_, t) = p("fn f() { fn g() {");
    assert_eq!(t.items.len(), 2);
    assert_ne!(t.items[0].flags & CUT, 0);
    assert!(t.problems > 0);
    assert_eq!(items("fn a( {\nfn b() {}"), vec!["Fn a"]);
    assert_eq!(items("struct S;\n}\nfn f() {}\n"), vec!["Struct S", "Fn f"]);
    assert!(problems("}\n") > 0);
    assert_eq!(problems("fn f() {}\n"), 0);
    for s in ["fn f( {", "struct S {", "}}}", "((((", "use a::{b", "impl", "fn", "pub", "pub(", "#[", "#![x", "macro_rules! m {", "static", "const X", "extern", "extern \"C\"", "union", "unsafe", "r#", "'", "\"unclosed"] {
        let (_, t) = p(s);
        assert!(t.problems > 0 || t.items.is_empty(), "{:?}", s);
    }
}

#[test]
fn a_mismatched_closer_does_not_take_what_follows_with_it() {
    // the `(` is never closed and the `]` closes nothing: the braces are still pairs, so `h` is read as an item
    // of the module and not as a part of `f`
    let (_, t) = p("fn f() { ( ] fn g() {} }\nfn h() {}");
    assert_eq!(t.items.iter().map(|i| i.kind.name()).collect::<Vec<_>>(), vec!["Fn", "Fn"]);
    assert!(t.problems > 0);
    assert_eq!(t.items[1].parent, NONE);
}

#[test]
fn offsets_are_code_points() {
    let s = "// \u{fc}\u{20ac}\u{1d518}\nfn a() {}\n/* \u{1d518}\u{1d518} */ fn b() {}";
    let (_, t) = p(s);
    assert_eq!(text_of(s, t.items[0].start, t.items[0].end), "fn a() {}");
    assert_eq!(text_of(s, t.items[1].start, t.items[1].end), "fn b() {}");
}

#[test]
fn deep_nesting_costs_no_stack() {
    let n = 200_000;
    let mut s = String::new();
    for _ in 0..n {
        s.push_str("fn f() { ");
    }
    for _ in 0..n {
        s.push_str("} ");
    }
    let (_, t) = p(&s);
    assert_eq!(t.items.len(), n);
    assert_eq!(t.problems, 0);
    let mut s = String::new();
    for _ in 0..n {
        s.push_str("mod m { ");
    }
    for _ in 0..n {
        s.push_str("} ");
    }
    assert_eq!(p(&s).1.items.len(), n);
    let mut s = String::from("fn f() { ");
    for _ in 0..n {
        s.push_str("( ");
    }
    s.push_str("|| { fn g() {} }");
    for _ in 0..n {
        s.push_str(") ");
    }
    s.push('}');
    assert_eq!(p(&s).1.items.len(), 2);
    let mut s = String::from("fn f() { ");
    for _ in 0..n {
        s.push_str("{ ");
    }
    s.push_str("fn g() {}");
    for _ in 0..n {
        s.push_str("} ");
    }
    s.push('}');
    assert_eq!(p(&s).1.items.len(), 2);
    let mut s = String::from("const X: u8 = ");
    for _ in 0..n {
        s.push_str("[ ");
    }
    for _ in 0..n {
        s.push_str("] ");
    }
    s.push(';');
    assert_eq!(p(&s).1.items.len(), 1);
}

#[test]
fn every_item_is_inside_its_parent_and_in_order() {
    let src = "mod a { fn b() { struct C; fn d() { static E: u8 = 0; } } impl F { fn g() {} } }\nfn h() { mod i { fn j() {} } }\n";
    let (_, t) = p(src);
    for (n, it) in t.items.iter().enumerate() {
        assert!(it.start < it.end);
        assert!(it.tok_start < it.tok_end);
        if it.parent != NONE {
            let par = &t.items[it.parent as usize];
            assert!((it.parent as usize) < n);
            assert!(par.start <= it.start && it.end <= par.end, "{} in {}", n, it.parent);
        }
        if n > 0 {
            assert!(t.items[n - 1].start <= it.start);
        }
    }
}

/// A small generator for the property test below: a linear congruential generator, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 33) as u32
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.next() as usize % xs.len()]
    }
}

const WORDS: &[&str] = &[
    "fn", "struct", "enum", "union", "trait", "impl", "mod", "use", "type", "static", "const", "extern", "crate", "pub", "unsafe", "async", "default", "auto", "safe",
    "macro_rules", "where", "for", "as", "mut", "self", "Self", "super", "in", "a", "b", "c", "r#x", "_", "(", ")", "[", "]", "{", "}", "<", ">", "->", "=>", "::", ":", ";", ",",
    "=", "!", "#", "'a", "'", "\"s\"", "\"", "r#\"x\"#", "1", "1.5", "/*", "*/", "//", "\n", "*", "&", "|", "?", "\u{e9}", "\u{1d518}",
];

#[test]
fn any_token_soup_reads_without_a_panic_and_with_consistent_spans() {
    let mut rng = Rng(7);
    for round in 0..3000 {
        let n = 1 + rng.next() as usize % 60;
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(rng.pick(WORDS));
            if rng.next() % 3 != 0 {
                s.push(' ');
            }
        }
        let (src, t) = p(&s);
        let total = src.len() as u32;
        for (i, it) in t.items.iter().enumerate() {
            assert!(it.start < it.end && it.end <= total, "round {} item {} in {:?}", round, i, s);
            assert!(it.tok_start < it.tok_end && (it.tok_end as usize) <= t.toks.len());
            assert!(it.parent == NONE || (it.parent as usize) < i);
            if it.body_open != NONE {
                assert!(it.body_open >= it.tok_start && it.body_open < it.tok_end);
            }
            if it.name != NONE {
                assert!((it.name as usize) < t.toks.len());
            }
        }
        for a in &t.attrs {
            assert!(a.tok_start < a.tok_end && (a.tok_end as usize) <= t.toks.len());
        }
        for l in &t.leaves {
            assert!(((l.segs.0 + l.segs.1) as usize) <= t.segs.len());
        }
        let mut out = String::new();
        out::write_items(&t, &src, &mut out);
    }
}

#[test]
fn a_clean_program_has_no_problems() {
    let src = "use std::io;\n#[derive(Debug)]\npub struct S { a: u8 }\nimpl S { pub fn new() -> S { S { a: 0 } } }\nfn main() { let s = S::new(); println!(\"{:?}\", s); }\n";
    let (_, t) = p(src);
    assert_eq!(t.problems, 0);
    assert_eq!(items(src), vec!["Use", "Struct S", "Impl", "Fn new", "Fn main"]);
}

// ---- items in the groups of a head and of a field list ----

/// `Kind name (parent)` of every item, in order.
fn with_parents(s: &str) -> Vec<String> {
    let (src, t) = p(s);
    (0..t.items.len())
        .map(|i| {
            let it = &t.items[i];
            let parent = if it.parent == NONE { "-".to_string() } else { it.parent.to_string() };
            format!("{} {} ({})", it.kind.name(), t.name(&src, i), parent).replace("  ", " ")
        })
        .collect()
}

#[test]
fn a_const_block_in_a_generic_argument_or_a_where_clause_holds_items() {
    assert_eq!(with_parents("impl Tr for Foo where (): P<Self, { struct S; fn f() {} 1 }> { fn g() {} }"), vec!["Impl (-)", "Struct S (0)", "Fn f (0)", "Fn g (0)"]);
    assert_eq!(with_parents("struct S<const N: usize = { fn d() {} 1 }>;"), vec!["Struct S (-)", "Fn d (0)"]);
    assert_eq!(with_parents("fn f<const N: usize>() -> Foo<{ fn r() {} N }> where Bar<{ fn w() {} N }>: Tr {}"), vec!["Fn f (-)", "Fn r (0)", "Fn w (0)"]);
}

#[test]
fn an_array_length_in_a_type_holds_items_wherever_the_type_is() {
    assert_eq!(with_parents("fn g(x: [u8; { struct T; 1 }]) -> [u8; { fn r() {} 1 }] {}"), vec!["Fn g (-)", "Struct T (0)", "Fn r (0)"]);
    assert_eq!(with_parents("struct S { a: [u8; { fn f() {} 1 }], b: u8 }"), vec!["Struct S (-)", "Fn f (0)"]);
    assert_eq!(with_parents("struct S([u8; { fn f() {} 1 }]);"), vec!["Struct S (-)", "Fn f (0)"]);
    assert_eq!(with_parents("union U { a: [u8; { fn f() {} 1 }] }"), vec!["Union U (-)", "Fn f (0)"]);
    assert_eq!(with_parents("const C: [u8; { fn h() {} 1 }] = [0];"), vec!["Const C (-)", "Fn h (0)"]);
    assert_eq!(with_parents("static mut X: [u8; { fn h() {} 1 }] = [0];"), vec!["Static X (-)", "Fn h (0)"]);
    assert_eq!(with_parents("type T = [u8; { fn h() {} 1 }];"), vec!["TyAlias T (-)", "Fn h (0)"]);
    assert_eq!(with_parents("trait Tr { fn m(x: [u8; { fn h() {} 1 }]); }"), vec!["Trait Tr (-)", "Fn m (0)", "Fn h (1)"]);
    assert_eq!(with_parents("impl S { fn m(x: [u8; { fn h() {} 1 }]) {} }"), vec!["Impl (-)", "Fn m (0)", "Fn h (1)"]);
    assert_eq!(with_parents("extern \"C\" { fn e(x: [u8; { fn h() {} 1 }]); }"), vec!["ForeignMod (-)", "Fn e (0)", "Fn h (1)"]);
}

#[test]
fn an_enum_discriminant_and_a_variants_fields_hold_items() {
    assert_eq!(with_parents("enum E { A = { fn f() {} 1 }, B { x: [u8; { fn g() {} 1 }] }, C([u8; { fn h() {} 1 }]) }"), vec!["Enum E (-)", "Fn f (0)", "Fn g (0)", "Fn h (0)"]);
}

#[test]
fn the_items_of_a_head_come_before_those_of_the_body_and_after_the_item() {
    let s = "fn g(x: [u8; { fn a() {} 1 }]) { fn b() {} }\nfn after() {}";
    assert_eq!(with_parents(s), vec!["Fn g (-)", "Fn a (0)", "Fn b (0)", "Fn after (-)"]);
    let (_, t) = p(s);
    let starts: Vec<u32> = t.items.iter().map(|i| i.start).collect();
    let mut sorted = starts.clone();
    sorted.sort();
    assert_eq!(starts, sorted);
    assert_eq!(t.problems, 0);
    let s = "const C: [u8; { fn h() {} 1 }] = [{ fn i() {} 1 }];";
    assert_eq!(with_parents(s), vec!["Const C (-)", "Fn h (0)", "Fn i (0)"]);
}

#[test]
fn a_head_with_no_item_in_it_costs_nothing_and_changes_nothing() {
    let s = "pub fn f<'a, T: Tr>(a: fn(u8) -> u8, b: &'a [T; 4], c: impl Fn(u8)) -> Vec<[u8; N]> where T: Clone {}\nstruct S { a: u8, b: Vec<u8>, #[serde(rename = \"c\")] c: u8 }\nenum E { A, B(u8), C { x: u8 }, D = 4 }\nimpl<T> Tr for S<T> where T: Tr {}\n";
    let (_, t) = p(s);
    assert_eq!(t.problems, 0);
    assert_eq!(items(s), vec!["Fn f", "Struct S", "Enum E", "Impl"]);
}

#[test]
fn a_field_named_like_a_keyword_that_starts_an_item_is_not_one() {
    let s = "struct S { r#fn: u8, r#struct: u8, union: u8, auto: u8, default: u8, safe: u8 }\nenum E { Fn { r#const: u8 }, Union { union: u8 } }\n";
    assert_eq!(items(s), vec!["Struct S", "Enum E"]);
}

#[test]
fn an_abi_that_holds_a_space_or_a_control_character_is_one_word_of_the_dump() {
    for (text, word) in [
        ("extern \"C\" {}", "\"C\""),
        ("extern \"a b\" {}", "\"a%20b\""),
        ("extern \"a%b\" {}", "\"a%25b\""),
        ("extern \"x\u{7f}\" {}", "\"x%7F\""),
        ("extern \"\u{e9}\" {}", "\"\u{e9}\""),
        ("extern \"x\\\n  y\" {}", "\"x\\%0A%20%20y\""),
        ("extern \"a\u{2028}b\" {}", "\"a%E2%80%A8b\""),
        ("extern r#\"a\\b\"# {}", "r#\"a\\b\"#"),
    ] {
        let (src, t) = p(text);
        let mut out = String::new();
        super::out::write_items(&t, &src, &mut out);
        let line = out.lines().next().unwrap();
        let fields: Vec<&str> = line.split(' ').collect();
        assert_eq!(fields.len(), 12, "{line}");
        assert_eq!(fields[9], word, "{text:?}");
        assert_eq!(out.lines().filter(|l| l.starts_with("item ")).count(), 1, "{text:?}");
    }
}

// ---- the hooks ----

fn hooks_of(s: &str, build_script: bool) -> Vec<(String, String)> {
    let (src, t) = p(s);
    hooks(&t, &src, build_script).iter().map(|h| (h.kind.name().to_string(), h.why.clone())).collect()
}

#[test]
fn procedural_macros_are_hooks() {
    let got = hooks_of("#[proc_macro]\npub fn a(i: TokenStream) -> TokenStream { i }\n#[proc_macro_derive(B, attributes(c))] pub fn b(i: TokenStream) -> TokenStream { i }\n#[proc_macro_attribute] pub fn d(a: TokenStream, i: TokenStream) -> TokenStream { i }\n#[derive(X)] struct S;\n", false);
    assert_eq!(got, vec![("proc-macro".to_string(), "proc_macro".to_string()), ("proc-macro".to_string(), "proc_macro_derive".to_string()), ("proc-macro".to_string(), "proc_macro_attribute".to_string())]);
}

#[test]
fn constructors_and_destructors_are_hooks_in_any_path() {
    let got = hooks_of("#[ctor] fn a() {}\n#[ctor::ctor] fn b() {}\n#[dtor::dtor] fn c() {}\n#[crate::deps::ctor(unsafe)] fn d() {}\n#[constructor] fn e() {}\n#[ctor] struct S;\n", false);
    assert_eq!(got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), vec!["load-fn", "load-fn", "load-fn", "load-fn"]);
    assert_eq!(got[3].1, "crate::deps::ctor");
}

#[test]
fn a_link_section_the_loader_runs_is_a_hook() {
    let got = hooks_of("#[link_section = \".init_array\"] #[used] static A: extern \"C\" fn() = f;\n#[unsafe(link_section = \".ctors\")] static B: u8 = 0;\n#[link_section = \"__DATA,__mod_init_func\"] static C: u8 = 0;\n#[link_section = \".CRT$XCU\"] static D: u8 = 0;\n#[link_section = \".rodata.x\"] static E: u8 = 0;\n#[link_section = r#\".init_array\"#] static F: u8 = 0;\n#[link_section = \".text.hot\"] fn g() {}\n", false);
    assert_eq!(got.iter().map(|g| g.1.as_str()).collect::<Vec<_>>(), vec!["link_section = \".init_array\"", "link_section = \".ctors\"", "link_section = \"__DATA,__mod_init_func\"", "link_section = \".CRT$XCU\"", "link_section = \".init_array\""]);
}

#[test]
fn a_crate_with_its_own_entry() {
    assert_eq!(hooks_of("#![no_main]\n#[no_mangle] pub extern \"C\" fn main(a: i32) -> i32 { 0 }\n", false), vec![("own-entry".to_string(), "no_main".to_string()), ("own-entry".to_string(), "no_mangle extern fn main".to_string())]);
    assert_eq!(hooks_of("#[start] fn s(a: isize) -> isize { 0 }", false), vec![("own-entry".to_string(), "start".to_string())]);
    assert_eq!(hooks_of("#[no_mangle] pub fn main() {}", false), vec![]);
}

#[test]
fn a_constructor_hidden_in_a_head_is_still_a_hook() {
    let got = hooks_of("struct S<const N: usize = { #[ctor] fn f() {} 1 }>;\nfn g(x: [u8; { #[ctor::ctor] fn h() {} 1 }]) {}\nenum E { A = { #[dtor] fn i() {} 1 } }\n", false);
    assert_eq!(got.iter().map(|g| g.0.as_str()).collect::<Vec<_>>(), vec!["load-fn", "load-fn", "load-fn"]);
}

#[test]
fn a_build_scripts_main_is_a_hook_only_in_a_build_script() {
    assert_eq!(hooks_of("fn helper() {}\nfn main() { fn main() {} }\nmod m { pub fn main() {} }\n", true), vec![("build-main".to_string(), "main".to_string())]);
    assert_eq!(hooks_of("fn main() {}", false), vec![]);
}

#[test]
fn spans_of_hooks_are_the_items() {
    let s = "#[ctor] fn a() { run(); }\nfn b() {}\n";
    let (src, t) = p(s);
    let h = hooks(&t, &src, false);
    assert_eq!(h.len(), 1);
    assert_eq!(text_of(s, h[0].start, h[0].end), "fn a() { run(); }");
    assert_eq!(h[0].item, 0);
    let s = "#![no_main]";
    let (src, t) = p(s);
    let h = hooks(&t, &src, false);
    assert_eq!((h[0].item, text_of(s, h[0].start, h[0].end)), (NONE, "#![no_main]".to_string()));
}
