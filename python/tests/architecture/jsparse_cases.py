"""Inputs for the tests of the engine's JavaScript parser (the `js_parse`
call: rust/crates/lazaret-engine/src/jsparse/): test_snapshot_js_parse.py,
which holds its trees to the ones recorded, test_jsparse_native.py (its
options and bounds), test_wasm_parity_jsparse.py (the WebAssembly build
against the native library) and test_lex.py.

The parser is a port of jsparse.py, the Python package's reader from 0.1.7,
and was held to it node for node until phase 3 of the Rust-first refactor
retired jsparse.py and its npm twin; these are the inputs it was held to:
curated snippets for every construct the cross-file pass reads and the
errors (READER_SNIPPETS), and for what those do not reach (SNIPPETS: the
speculation budgets at their edges, jsparse.py's own bugs, which the engine
reproduces, surrogates, numbers, strings' escapes, regular expressions,
templates, ASI, comments, JSX, TypeScript and Flow); every construct that
nests (NESTINGS); seeded soups of tokens and of TypeScript, JSX and Flow
pieces; seeded mutations of real files.

An answer is kept as JSON text (`native_json`): a tree may be as deep as its
input is long, deeper than json.loads reads.

Inert text only: nothing here is executed.
"""
import glob
import os
import random
import re

from lazaret.scanner import _native
from tests import _support

LS, PS = chr(0x2028), chr(0x2029)


def dialect(path):
    """(TypeScript, JSX) for a file name, as `js_parse_file` picks them:
    .ts, .mts and .cts are TypeScript, .tsx TypeScript with JSX, anything
    else JavaScript with JSX (and Flow's annotations)."""
    lower = path.lower()
    if lower.endswith((".ts", ".mts", ".cts")):
        return True, False
    if lower.endswith(".tsx"):
        return True, True
    return False, True


def native_raw(name, args, text):
    """(status, the answer's JSON text) of one call of the native library."""
    return _native.call_raw(name, args, text)


def native_json(src, ts, jsx, spans=False):
    """The engine's js_parse answer (the status too, when it is not 0)."""
    args = {"ts": ts, "jsx": jsx}
    if spans:
        args["spans"] = True
    status, answer = native_raw("js_parse", args, src)
    return answer if status == 0 else f"status {status}: {answer}"


SPAN_RE = re.compile(r',"start":(\d+),"end":(\d+)')
LINE_SPAN_RE = re.compile(r'"line":(\d+),"start":(\d+),"end":(\d+)')
LINE_END_RE = re.compile(r"\r\n|[\n\r  ]")

# (path, source): the path picks the dialect (dialect())
SNIPPETS = [
    # jsparse.py's bugs, which the native parser has too: a parenthesized
    # list that starts with a rest element raises KeyError: 'line'; a long
    # chain of Flow's `?T` or a long JSX member name runs out of Python's
    # recursion limit ("nesting too deep", line 1)
    ("k.js", "x = (...a, b);"), ("k.js", "(...a, b, c)"), ("k.js", "f((...a, b))"),
    ("k.js", "(...a, b) => 0"), ("k.js", "async (...a, b)"),
    ("q.js", "let x: " + "? " * 1000 + "T;"), ("q.js", "let x: " + "? " * 30000 + "T;"),
    ("q.ts", "f<" + "? " * 3000 + "T>(x);"),
    ("m.jsx", "<" + ".".join(["a"] * 1000) + "></" + ".".join(["a"] * 1000) + ">"),
    ("m.jsx", "<" + ".".join(["a"] * 30000) + "></" + ".".join(["a"] * 30000) + ">"),
    ("m.jsx", "<" + ".".join(["a"] * 30000) + "></a>"), ("m.jsx", "<a></" + ".".join(["a"] * 30000) + ">"),
    ("m.jsx", "<" + ".".join(["a"] * 30000) + " />"),
    # the speculation budgets at their edges: a generic arrow function's
    # read ahead (4096 tokens), function_type_ahead's (256), the file's
    ("b.ts", "x = <T,>(" + "a," * 2040 + ") => 0;"), ("b.ts", "x = <T,>(" + "a," * 2044 + ") => 0;"),
    ("b.ts", "x = <T,>(" + "a," * 2050 + ") => 0;"), ("b.ts", "x = async <T,>(" + "a," * 2043 + ") => 0;"),
    ("b.ts", "f<" + "A," * 2040 + "B>(x);"), ("b.ts", "f<" + "A," * 2050 + "B>(x);"),
    ("b.ts", "let x: ([" + "a," * 120 + "]) => T;"), ("b.ts", "let x: ([" + "a," * 130 + "]) => T;"),
    ("b.ts", "let x: ({" + "a," * 126 + "}) => T;"), ("b.ts", "let x: ({" + "a," * 127 + "}) => T;"),
    ("b.ts", "x = (a): " + "T | " * 2100 + "T => 0;"), ("b.ts", "x = (a): " + "T | " * 1900 + "T => 0;"),
    ("b.ts", "a < b > c;" * 3000), ("b.ts", "f<T>(x);" * 9000),
    ("b.tsx", "x = <T,>(a) => <div>{a}</div>;" * 500),
    # surrogates: lone and paired, raw and escaped, in names, strings, JSX, templates, regexes
    ("u.js", "a\ud800b = '\ud800' + '\ud83d\ude00' + '\\ud83d\\ude00' + '\\ud83d' + '\\ude00\\ud83d';"),
    ("u.js", "x\\ud835\\udd04 = 1; #p; class A { #\ud835\udd04 = 1; #\\u{1d504}; #\ud835\udd04x() {} }"),
    ("u.js", "'\\u{d83d}\\u{de00}' + '\\ud83d\\u{de00}' + `\ud800${'\udc00'}` + /\ud800/u"),
    ("u.jsx", "<a b='\ud800\udc00' c=\"\\ud800\">\ud83d\ude00{'\\uDE00'}</a>"),
    ("u.js", "\u00e9t\u00e9 = '\u00e9'; \u0391 = 1; \u4e2d\u6587 = 2; \U0001F600 = 3;"),
    ("u.js", "a\u00a0=\u3000b\ufeff;\u1680c\u2000d\u200a\u202f\u205fe"),
    ("u.js", "a\u0085b\u200bc\u200cd\u200de = 1"),
    # numbers
    ("n.js", "0x; 0xg; 0X1_F; 0o; 0o78; 0b; 0b102; 0_1; 1__2; 1e; 1e+; 1e-_; 1.e5; 1..e; .5.5; 5..3; 1_e1n;"),
    ("n.js", "x = 1n + 0xffn + 0o7n + 0b1n + 1.5n + 1e3n + 08n + .1n;"),
    ("n.js", "a.5; a?.5:b; a?.b; 1.toString(); 1 .x; 1.0.x; 0.x; 00.5;"),
    # strings and escapes
    ("s.js", "'\\0\\1\\12\\123\\1234\\400\\477\\777\\8\\9\\08\\09';"),
    ("s.js", "'\\x' + '\\x4' + '\\x41' + '\\u' + '\\u4' + '\\u41' + '\\u004' + '\\u0041' + '\\u{' + '\\u{}' + '\\u{41' + '\\u{41}';"),
    ("s.js", "'\\u{0000000000000041}' + '\\u{110000}' + '\\u{FFFFFFFFFFFFFFFFFFFF}' + '\\u{10FFFF}';"),
    ("s.js", "'a\\\r\nb' + 'a\\\rb' + 'a\\\nb' + 'a\\" + LS + "b' + 'a\\" + PS + "b' + 'a" + LS + "b';"),
    ("s.js", "'\\a\\c\\d\\e\\g\\q\\z\\'\\\"\\\\\\/' + \"\\b\\f\\n\\r\\t\\v\";"), ("s.js", "'a\r'"), ("s.js", "'a\\"),
    # regular expressions
    ("r.js", "a = /[/]/; b = /\\//g; c = /[\\]/]+/; d = /a/gimsuyd; e = /[[]/; f = /]/; g = /a/\u00e9;"),
    ("r.js", "x = /[\n]/"), ("r.js", "x = /a\\\n/"), ("r.js", "x = /a" + LS + "/"), ("r.js", "x = /[a"),
    ("r.js", "x = a / b / c; y = a /= b; z = (a) / /b/; w = [] / /c/g; if (/x/.test(y)) {} f(/=/, /==/);"),
    ("r.js", "x = y\n/re/g.exec(z); x = {} / 1; ({} / 1); typeof /a/; void /b/; a++ / 2; a-- /b/ 1"),
    # templates
    ("t.js", "`\\`` + `$` + `$${a}` + `${a}$` + `$\\{a}` + `\\${a}` + `a${b}${c}` + `${`${`${a}`}`}`"),
    ("t.js", "`a\\"), ("t.js", "`a${b"), ("t.js", "`a${b}"), ("t.js", "`a${b}c"), ("t.js", "`${}`"),
    ("t.js", "`\r\n${a}\r` + `" + LS + "`"), ("t.js", "a?.b`c`"), ("t.js", "a?.b\n`c`"), ("t.js", "new a`b`(c)"),
    # ASI and line terminators
    ("a.js", "a\r\nb\rc\nd" + LS + "e" + PS + "f\r\n\r\ng"), ("a.js", "x\n++\ny"), ("a.js", "x\n--y"),
    ("a.js", "let\nx = 1"), ("a.js", "let\n[a] = b"), ("a.js", "var\nx"), ("a.js", "return\nx"),
    ("a.js", "async\nfunction f() {}"), ("a.js", "async\n(x) => x"), ("a.js", "a\n?.b"), ("a.js", "throw\nx"),
    ("a.js", "do x; while (y) z"), ("a.js", "for (;;) break\nlabel"), ("a.js", "x: while (1) { continue\nx }"),
    ("a.js", "using\nx = 1"), ("a.js", "using x = 1, y = 2; await using z = w; for (using of of xs);"),
    ("a.js", "for (using x of y); for (await using x of y); for (let in x); for (let of of x);"),
    # comments
    ("c.js", "/**/a/**/;/*\n*/b//\n/*/ */c"), ("c.js", "a /*/ b"), ("c.js", "a //" + LS + "b"),
    ("c.js", "#!/x\r\na"), ("c.js", "#!"), ("c.js", "a #!b"), ("c.js", " #!/x\na"),
    # statements and declarations
    ("d.js", "if (a) function f() {} else class C {}"), ("d.js", "label: function f() {}"),
    ("d.js", "switch (x) { default: case 1: }"), ("d.js", "switch (x) { case 1 }"), ("d.js", "try {}"),
    ("d.js", "with (a) b"), ("d.js", "debugger"), ("d.js", "import.meta; import('x'); import('x', {a: 1},)"),
    ("d.js", "import x, { a, b as c, 'd e' as f, default as g } from 'm' with { type: 'json' };"),
    ("d.js", "import * as ns from 'm' assert { a: 'b' }; import {} from 'n'; import 'o';"),
    ("d.js", "export { a as 'b c', d as default } from 'm'; export * as 'x y' from 'n';"),
    ("d.js", "export default async function () {} export default async () => 1"),
    ("d.js", "export default (a, b); export default function* g() {}"), ("d.js", "export let x;"),
    ("d.js", "export x"), ("d.js", "export default"), ("d.js", "export { a b }"), ("d.js", "import { 'a' } from 'b'"),
    # expressions
    ("e.js", "a ?? b || c && d | e ^ f & g == h != i === j !== k < l > m <= n >= o << p >> q >>> r + s - t * u / v % w ** x ** y;"),
    ("e.js", "a >>= b; a >>>= b; a > b; a >> b; a >>> b; a >= b; a > >b"),
    ("e.js", "x = a in b; for (x = a in b;;); for (x of y); for (x in y); for ((x) of y); for ([x] of y);"),
    ("e.js", "({a, b} = c); [a, ...b] = c; ({a: [b], ...c} = d); [a = 1, [b] = [], {c} = {}] = e;"),
    ("e.js", "({a = 1}) => a; ({a = 1}); ({a = 1} = b); [{a = 1}] = b; ({a: {b = 1}} = c); f({a = 1})"),
    ("e.js", "(a, b) => {}; (a, b); (a, ...b) => 0; (a, ...b); ([a]) => 0; ({a}) => 0; ((a)) => 0; (a.b) => 0"),
    ("e.js", "a = b ? c : d; a = b ? (c) : d => e; a = b ? (c): d => e : f; a = (b) ? c : d;"),
    ("e.js", "async(); async(a, ...b); async (a) => b; async a => b; async\na => b; new async(); async.x"),
    ("e.js", "yield; function* g() { yield; yield a; yield* a; yield\na; x = yield; f(yield a, yield) }"),
    ("e.js", "await x; async function f() { await x; await (y); }; function g() { await (x) }; await\nx"),
    ("e.js", "a?.b.c?.[d]?.(e).f; (a?.b).c; a?.b(); new a.b?.c"), ("e.js", "a?.`x`"),
    ("e.js", "new.target; new.x; new X; new X(); new (X())(); new new X()(); new X.y[z]`t`()"),
    ("e.js", "x = { get a() {}, set a(v) {}, async b() {}, *c() {}, async *d() {}, get() {}, set: 1, async: 2, [e]: 3, 'f': 4, 5: 6, 7n: 8 }"),
    ("e.js", "x = { get\na() {} }; x = { async\na() {} }; x = { a, b, c }; x = { if: 1, class: 2 }; x = { #a: 1 }"),
    ("e.js", "++a; a++; ++a.b; ++a[b]; --(a); ++f(); a\n++; ++++a; !a++; typeof a++; delete a.b; void 0"),
    ("e.js", "class A { static async *[Symbol.iterator]() {} static #x; get #y() {} static { this.z = 1 } 'constructor'() {} constructor() {} }"),
    ("e.js", "class A { accessor x = 1; static accessor y; get = 1; set = 2; static = 3; async = 4 }"),
    ("e.js", "class A { a\nb\nc() {} d = 1\ne }"), ("e.js", "class A { x y }"), ("e.js", "class A { get x }"),
    ("e.js", "#x in obj; class A { #x; m() { return #x in this } }"), ("e.js", "a.#b"), ("e.js", "this.#x"),
    # JSX
    ("j.jsx", "<a.b.c d-e='f' g:h=\"i\" {...j} k={<l />} m=<n></n> o />"),
    ("j.jsx", "<>a&amp;b{/* c */}d{...e}</>;<a>{}</a>;<a>{' '}</a>;<a>></a>;<a>}</a>"),
    ("j.jsx", "<a:b></a:b>; <a></a:b>; <a.b></a.c>; <a></>; <></a>; <a/ >; <a b='c\nd' />; <a b=c />"),
    ("j.jsx", "<a\n  b\n  c={1}\n>\n  text\n  {x}\n</a>"), ("j.jsx", "<a>"), ("j.jsx", "<a b={1 2} />"),
    ("j.jsx", "x = a < b; y = <c />; z = a <b> c"), ("j.jsx", "<a>{x}</a>.b; <a />(1)"), ("j.jsx", "<a b='\\'' />"),
    ("j.jsx", "< a / >; < a >< / a >"), ("j.jsx", "<a /* c */ b /* d */ = /* e */ 'f' />"),
    ("j.jsx", "<a $b c_d />; <a-b></a-b>; <\u00e9 />; <\\u0061 />"),
    ("j.tsx", "<A<string>> </A>; <A<B<C>>/>; <T,>(x: T) => x; <T extends {}>(x: T) => x"),
    # TypeScript
    ("t.ts", "let a: string[] = [], b: Array<number> = [], c: [string, number?, ...boolean[]] = [] as const;"),
    ("t.ts", "let f: (a: string, b?: number, ...c: any[]) => void; let g: new (x: T) => U; let h: abstract new () => T;"),
    ("t.ts", "type A<T extends object = {}> = { readonly [K in keyof T]-?: T[K] } & { +readonly [K in string as `x${K}`]+?: never };"),
    ("t.ts", "type B = T extends (infer U)[] ? U : T extends Promise<infer V extends string> ? V : never;"),
    ("t.ts", "type C = typeof x; type D = typeof import('./x'); type E = import('./y').Z<T>; type F = keyof typeof a.b;"),
    ("t.ts", "type G = `a${B}c${D}`; type H = unique symbol; type I = -1 | 1n | 'x' | null | undefined | this;"),
    ("t.ts", "type J = { (a: T): U; new (b: T): V; m?(): void; readonly x: T; get y(): T; set y(v: T); [k: string]: any };"),
    ("t.ts", "function f(this: Foo, a?: T): a is string {} function g(x): asserts x {} function h(x): asserts x is T {}"),
    ("t.ts", "function f<const T, in U, out V, in out W>() {} class C<T = any> implements I<T>, J {}"),
    ("t.ts", "abstract class A { abstract m(): void; abstract x: T; protected abstract y?: T; private static readonly z = 1; }"),
    ("t.ts", "class B { constructor(public a: T, private readonly b?: U, protected override c = 1, @d e: F) { super() } }"),
    ("t.ts", "class C { declare x: T; m(): void; m(a?): void {} [key: string]: any; static [k: number]: T }"),
    ("t.ts", "enum E { A, B = 2, 'C' = 3, [D] = 4 } const enum F {} declare enum G { X } export enum H {}"),
    ("t.ts", "namespace A.B.C { export const x = 1 } module M {} declare module 'm' { export = x } declare global { var y: T }"),
    ("t.ts", "declare function f(): void; declare const x: T; declare class D { m(): void } declare namespace N {}"),
    ("t.ts", "import type { A } from 'a'; import type B from 'b'; import { type C, type D as E, F } from 'c';"),
    ("t.ts", "import type * as G from 'g'; import { type as } from 'h'; import { type as as as } from 'i'; import { type as as } from 'j';"),
    ("t.ts", "export type { A }; export type * from 'b'; export type * as C from 'c'; export { type D, E };"),
    ("t.ts", "import x = require('x'); import y = A.B.C; export import z = require('z'); import type w = require('w');"),
    ("t.ts", "export = x; export as namespace N; export default interface I {} export declare const y: T;"),
    ("t.ts", "x as any as T; x satisfies T; <T>x; x!; x!.y; x![0]; f!(); a < b > (c); f<T>; f<T>\n(x); f<T>`x`;"),
    ("t.ts", "f<T>(x)<U>(y); a?.<T>(b); new A<T>(); new A<T>; class X extends Y<T> {} @dec<T>() class Z {}"),
    ("t.ts", "let x = y as const; let z = <const>['a']; for (const k of x as T[]) {} if (a < b) c > d;"),
    ("t.ts", "function f(): void; function f(a) {} export function g(): void; export default function h(): T;"),
    ("t.ts", "interface I<T> extends J<T>, K { (x: T): U; new (): I<T>; readonly [index: number]: T; method<U>(u: U): T }"),
    ("t.ts", "let a: A.B.C<D>[]; let b: (A | B)[]; let c: A & B | C; let d: | A | B; let e: & A & B; let f: A[][]!;"),
    ("t.ts", "type X = [a: string, b?: number, ...c: T[]]; type Y = [first?: T]; type Z = [...T, ...U];"),
    ("t.ts", "x = (a: T): U => a; x = async (a: T): Promise<U> => a; x = (a?: T, b = 1): void => {};"),
    ("t.ts", "x = c ? (a) : b; x = c ? (a): T => b : d; x = c ? (a, b) : d;"),
    ("t.ts", "@a @b.c @d() @(e) @f.g<H>() class C { @h m(@i x) {} @j static p; @k get q() { return 1 } }"),
    ("t.ts", "let x: { a: string, b: number; c: boolean\n d: T }; let y: {}; let z: { a }"),
    ("t.ts", "type A = B extends C\n? D : E; type F = G\nextends H ? I : J; type K = (L extends M ? N : O)[]"),
    ("t.ts", "let v: void, n: never, u: unknown, o: object, s: symbol, b: bigint, a: any;"),
    ("t.ts", "type A = typeof a.#b; type B = A<typeof c>; let x: typeof y<T>;"),
    ("t.ts", "accessor; declare; abstract; type; namespace; module; global; interface; satisfies; as; keyof; infer;"),
    ("t.ts", "type = 1; namespace = 2; module.exports = 3; declare = 4; abstract = 5; interface = 6; global = 7;"),
    ("t.ts", "let x: A extends B ? C : D extends E ? F : G;"), ("t.ts", "let x: infer U;"),
    ("t.ts", "type X<T> = T extends [infer H extends string, ...infer R] ? H : never;"),
    ("t.mts", "export const x = await import('y'); export { x as default };"),
    ("t.cts", "import fs = require('fs'); module.exports = fs;"),
    # Flow in .js
    ("f.js", "type T = {a: ?string, b?: number}; function f(x: ?T, y?: string): void { return (x: any); }"),
    ("f.js", "opaque type A = B; declare var x: T; declare function f(): void; export type {A, B};"),
    ("f.js", "const f = (x: number): string => String(x); class C<T> { p: T; m(): T {} }"),
    ("f.js", "import type { A } from 'a'; import typeof B from 'b'; function g<T>(x: T): Array<T> {}"),
    ("f.js", "let x: ?(() => void); let y: ? ? T; let z: ??T; let w: (?T)[];"),
    # errors at every kind of token
    ("x.js", "a b"), ("x.js", "a 'b'"), ("x.js", "a `b`"), ("x.js", "a 1"), ("x.js", "a #b"), ("x.js", "a\\u0062 c"),
    ("x.js", "a \\"), ("x.js", "a \\x"), ("x.js", "a \x00"), ("x.js", "a \x7f"), ("x.js", "a \x1b"),
    ("x.js", "a " + "x" * 50), ("x.js", "a 'x\\'y'"), ("x.js", "let let"), ("x.js", "var if"), ("x.js", "x = {a: 1,,}"),
    ("x.js", "(a b)"), ("x.js", "f(a b)"), ("x.js", "[a b]"), ("x.js", "{a: 1 b: 2}"), ("x.js", "x = {a b}"),
    ("x.js", "class { }"), ("x.js", "function () {}"), ("x.js", "1 = 2"), ("x.js", "a + b = c"), ("x.js", "++1"),
    ("x.js", "(a, b) = c"), ("x.js", "[a + b] = c"), ("x.js", "({a: 1} = b)"), ("x.js", "({a() {}} = b)"),
    ("x.js", "({get a() {}} = b)"), ("x.js", "({...a, b} = c)"), ("x.js", "(a.b) => c"), ("x.js", "([a.b]) => c"),
    ("x.jsx", "<a></b>"), ("x.jsx", "<a>"), ("x.jsx", "<a b='c>"), ("x.jsx", "<a b=1 />"), ("x.jsx", "<a {b} />"),
    ("x.ts", "let x: ;"), ("x.ts", "type = ;"), ("x.ts", "enum {}"), ("x.ts", "f<>(x)"), ("x.ts", "x as"),
]

# every construct that nests: (name, path, source at depth k); the depth
# limit (MAX_DEPTH, 256: jsparse.py's) ends each, and the deepest that is
# read is the deepest stack the parser takes
NESTINGS = [
    ("parentheses", "n.js", lambda k: "(" * k + "x" + ")" * k),
    ("arrays", "n.js", lambda k: "[" * k + "x" + "]" * k),
    ("objects", "n.js", lambda k: "x = " + "{a: " * k + "1" + "}" * k),
    ("blocks", "n.js", lambda k: "{" * k + "}" * k),
    ("functions", "n.js", lambda k: "function f(){" * k + "}" * k),
    ("function expressions", "n.js", lambda k: "x = " + "function(){ return " * k + "1" + "}" * k),
    ("arrows", "n.js", lambda k: "x = " + "a => " * k + "a"),
    ("async arrows", "n.js", lambda k: "x = " + "async a => " * k + "a"),
    ("paren arrows", "n.js", lambda k: "x = " + "(a) => " * k + "a"),
    ("if", "n.js", lambda k: "if (x) " * k + "y;"),
    ("while", "n.js", lambda k: "while (x) " * k + "y;"),
    ("for", "n.js", lambda k: "for (;;) " * k + "y;"),
    ("for of", "n.js", lambda k: "for (a of b) " * k + "y;"),
    ("labels", "n.js", lambda k: "a: " * k + "x;"),
    ("try", "n.js", lambda k: "try { " * k + "} finally {}" * k),
    ("switch", "n.js", lambda k: "switch (x) { case 1: " * k + "}" * k),
    ("conditionals", "n.js", lambda k: "x = " + "a ? " * k + "b" + " : c" * k),
    ("assignments", "n.js", lambda k: "a = " * k + "b"),
    ("unary", "n.js", lambda k: "x = " + "!" * k + "y"),
    ("typeof", "n.js", lambda k: "x = " + "typeof " * k + "y"),
    ("await", "n.js", lambda k: "async function f() { x = " + "await " * k + "y }"),
    ("calls", "n.js", lambda k: "f(" * k + "x" + ")" * k),
    ("computed members", "n.js", lambda k: "a[" * k + "x" + "]" * k),
    ("optional calls", "n.js", lambda k: "a?.(" * k + "x" + ")" * k),
    ("spreads", "n.js", lambda k: "f(" + "...[" * k + "x" + "]" * k + ")"),
    ("templates", "n.js", lambda k: "`${" * k + "x" + "}`" * k),
    ("tagged templates", "n.js", lambda k: "f`${" * k + "x" + "}`" * k),
    ("new", "n.js", lambda k: "new " * k + "X"),
    ("classes", "n.js", lambda k: "class A { m() { " * k + "} }" * k),
    ("class expressions", "n.js", lambda k: "x = " + "class extends (" * k + "B" + ") {}" * k),
    ("array patterns", "n.js", lambda k: "let " + "[" * k + "a" + "]" * k + " = x;"),
    ("object patterns", "n.js", lambda k: "let " + "{a: " * k + "b" + "}" * k + " = x;"),
    ("parameter patterns", "n.js", lambda k: "function f(" + "{a: " * k + "b" + "}" * k + ") {}"),
    ("arrow parameters", "n.js", lambda k: "x = (" + "[" * k + "a" + "]" * k + ") => 0;"),
    ("assignment patterns", "n.js", lambda k: "(" + "[" * k + "a" + "]" * k + " = x);"),
    ("jsx elements", "n.jsx", lambda k: "<a>" * k + "</a>" * k),
    ("jsx fragments", "n.jsx", lambda k: "<>" * k + "</>" * k),
    ("jsx attributes", "n.jsx", lambda k: "x = " + "<a b=" * k + "<a />" + " />" * k),
    ("jsx containers", "n.jsx", lambda k: "<a>{" * k + "x" + "}</a>" * k),
    ("ts generics", "n.ts", lambda k: "let x: " + "A<" * k + "T" + ">" * k + ";"),
    ("ts object types", "n.ts", lambda k: "let x: " + "{a: " * k + "T" + "}" * k + ";"),
    ("ts tuple types", "n.ts", lambda k: "let x: " + "[" * k + "T" + "]" * k + ";"),
    ("ts function types", "n.ts", lambda k: "let x: " + "(a: " * k + "T" + ") => T" * k + ";"),
    ("ts parenthesized types", "n.ts", lambda k: "let x: " + "(" * k + "T" + ")" * k + ";"),
    ("ts keyof", "n.ts", lambda k: "let x: " + "keyof " * k + "T;"),
    ("ts indexed types", "n.ts", lambda k: "let x: " + "T[" * k + "K" + "]" * k + ";"),
    ("ts conditional types", "n.ts", lambda k: "type X = " + "A extends B ? " * k + "C" + " : D" * k + ";"),
    ("ts namespaces", "n.ts", lambda k: "namespace A { " * k + "}" * k),
    ("ts type arguments", "n.ts", lambda k: "f<" * k + "T" + ">" * k + "();"),
    ("ts generic arrows", "n.ts", lambda k: "x = " + "<T,>(a: T) => " * k + "a;"),
    ("tsx generic arrows", "n.tsx", lambda k: "x = " + "<T,>(a: T) => " * k + "<a />;"),
]


def nesting_cases(depths):
    """(name, path, source) for every construct at each depth of `depths`."""
    return [(name, path, make(k)) for name, path, make in NESTINGS for k in depths]


# ---- seeded random programs: soups of TypeScript, JSX and Flow pieces ----
PIECES = ["a", "b", "x1", "$", "_", "this", "super", "null", "true", "1", "0x1", ".5", "1n", "'s'", '"d"', "`t`",
          "`a${", "}`", "}", "${", "/re/g", "/", "/=", "(", ")", "[", "]", "{", "}", ";", ",", ".", "...", "?.",
          "?", ":", "=", "=>", "+", "-", "*", "**", "%", "<", ">", ">>", ">=", "<=", "!", "~", "&&", "||", "??",
          "&", "|", "^", "++", "--", "+=", "??=", "@", "#p", "\n", " ", " ", "\t", LS, "\r\n",
          "if", "else", "for", "of", "in", "while", "do", "return", "function", "class", "extends", "new", "let",
          "const", "var", "async", "await", "yield", "import", "export", "from", "as", "default", "static", "get",
          "set", "type", "interface", "enum", "namespace", "declare", "abstract", "readonly", "private", "public",
          "keyof", "typeof", "infer", "is", "asserts", "satisfies", "unique", "using", "accessor", "override",
          "<T>", "<T,>", ": T", ": string", "?:", "!", "!.", "<a>", "</a>", "<>", "</>", "<a/>", "{x}", "{...x}",
          "=<b/>", "//c\n", "/*c*/", "/*\n*/", "\\u0061", "é", "\ud800", "'\\u{1F600}'", "case", "switch", "try",
          "catch", "finally", "throw", "delete", "void", "with", "debugger", "require", "module", "global"]


def soup(seed, count, paths=("r.js", "r.ts", "r.tsx", "r.jsx")):
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        src = " ".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 80)))
        out.append((rnd.choice(paths), src))
    return out


def mutate(sources, seed, count, max_len=60_000):
    """Real files with a few spans dropped, doubled, swapped or cut short."""
    rnd = random.Random(seed)
    words = re.compile(r"[A-Za-z_$][\w$]*|\d+|\S")
    pool = [s for s in sources if 100 < len(s[1]) < max_len]
    out = []
    for _ in range(count):
        path, src = rnd.choice(pool)
        spans = [m.span() for m in words.finditer(src)]
        if not spans:
            continue
        for _ in range(rnd.randint(1, 4)):
            a, b = rnd.choice(spans)
            op = rnd.randrange(4)
            if op == 0:
                src = src[:a] + src[b:]
            elif op == 1:
                src = src[:a] + src[a:b] * 2 + src[b:]
            elif op == 2:
                c, d = rnd.choice(spans)
                if c > b:
                    src = src[:a] + src[c:d] + src[b:c] + src[a:b] + src[d:]
            else:
                src = src[:b]
            spans = [m.span() for m in words.finditer(src)]
            if not spans:
                break
        out.append((path, src))
    return out


# ---- the reader's snippets (they held jsparse.js, the npm package's twin, to jsparse.py) ----
READER_SNIPPETS = [
    # statements and declarations
    "var a = 1, b; let [c, , ...d] = e; const { f, g: { h = 2 } = {}, ...i } = j;",
    "if (a) b(); else if (c) d(); else { e(); }\nfor (let i = 0; i < n; i++) continue;\nfor (const k in o) break;",
    "for await (const x of y) {}\nwhile (a) do b(); while (c)\nlabel: for (;;) { break label; }",
    "switch (x) { case 1: case 2: y(); break; default: z(); }\ntry { a() } catch { b() } finally { c() }",
    "try { a() } catch ({ message }) { b(message) }\nthrow new Error('x');\ndebugger; with (o) { p(); }",
    "function* g(a = 1, { b }, [c], ...d) { yield a; yield* b; }\nasync function h() { await x; for await (y of z); }",
    "class A extends (B, C) { static #p = 1; #q() {} get [k]() {} set v(x) {} static async *m() {} static { init(); } }",
    "import d, * as ns from 'm'; import { a as b, default as c } from './n.js'; import './side';",
    "export * from './a'; export * as b from './b'; export { c as default, d }; export default class {}",
    "export const e = 1, f = () => 2; export async function g() {} export { h as 'string name' } from './h';",
    # expressions
    "a = b ? c : d ? e : f; g ??= h; i ||= j; k &&= l; m **= 2; n >>>= 1;",
    "x = a?.b?.[c]?.(d); y = new a.b.C(); z = new new D()(); w = new E; v = new.target; u = import.meta.url;",
    "f(...a, b, ...c); [1, , 3, ...d]; ({ a, b: c, [d]: e, f() {}, get g() { return 1 }, set g(v) {}, ...h, async *i() {} });",
    "(a, b) => a + b; async x => x; async (x) => { await x }; () => ({}); (a = 1, { b } = {}, [c] = []) => 0;",
    "typeof a + void b - delete c.d; !e; ~f; -g; +h; ++i; j--; a ** -b; (-a) ** b; a in b; a instanceof B;",
    "`a${b}c${`d${e}f`}g`; tag`h${i}`; String.raw`\\u{zz}`; x = a\n`t`;",
    "a = /[/]\\//g; b = c / d / e; if (x) /re/.test(y); f = (g) / 2; h = i++ / 2; j = [] / 1; k = {} / 2;",
    "x = 0x1F + 0o17 + 0b11 + 1_000 + .5e-3 + 010 + 08 + 10n + 0xFFn;",
    "s = 'a\\n\\x41\\u0042\\u{1F600}\\101\\\ncont\\q' + \"\\uD83D\\uDE00\" + '\\uD800' + '\\0';",
    "a\n++b\nc\n(d)\nreturn_\n/re/g;\nlet x = 1\nlet y = 2\nvar z = a\n[1, 2].map(f)",
    "function f() { return\nx }\nfunction g() { throw x\n}\nlet async = 1; async\nfunction h() {}",
    "a = b\n?.c; d = (e, f); g = h, i; j = k ? (l) : m => n;",
    "yield = 1; let of = 2; for (let of of xs); get = set = static = async = await = 3;",
    "a" + LS + "b" + PS + "c\r\nd\re\n" + "'x\\" + LS + "y';",
    "/* a\nb */ x; // c\n<!-- html comment\ny;",
    "#!/usr/bin/env node\nconsole.log(1);",
    # JSX
    "<a:b c=\"d\" {...e} f g={h} i='j' k=<l /> >t{m}<n.o.p />{/* c */}{...q}</a:b>",
    "<>x{y}</>; <A>{cond ? <B /> : <C x={1} />}</A>; <div dangerouslySetInnerHTML={{ __html: h }} />",
    "const C = () => <ul>{items.map((i) => <li key={i}>{i}</li>)}</ul>;",
    # TypeScript (.ts / .tsx)
    ("a.ts", "let x: number = <number>y; const z = w as unknown as T; v!.u; s satisfies T; f<T>(x); a < b > c;"),
    ("a.ts", "interface I<T> extends J { a?: string; [k: string]: T; m(): void }\ntype U = A | B & C;\n"
             "declare module 'm' { export function f(): void; }\ndeclare const d: number;\nexport type { I };"),
    ("a.ts", "enum E { A = 1, B, C = 'c' }\nconst enum F { X }\nnamespace N.M { export const x = 1; }\n"
             "import r = require('./r');\nimport q = N.M;\nexport = r;"),
    ("a.ts", "abstract class A<T> extends B<T> implements I, J { constructor(private x: T, public readonly y?: U) { super(); }\n"
             "abstract m(): void;\ndeclare z: number;\nf(a: string): void;\nf(a) {}\nprotected static g?(): void {}\n}"),
    ("a.ts", "@sealed @log() class K { @prop() p: string; @m m(@arg a: string) {} }\n"
             "function f<T extends K = K>(this: Window, a?: T, ...rest: T[]): asserts a is T {}"),
    ("a.ts", "const g = <T,>(v: T): T => v; const h = async <T>(x: T) => x; let u: (a: string) => void = null!;"),
    ("a.ts", "type C<T> = T extends (infer U extends string)[] ? U : T extends `a${infer V}` ? V : never;\n"
             "let t: [a: string, b?: number, ...c: boolean[]]; let m: { readonly [K in keyof T]?: T[K] };"),
    ("a.tsx", "const A = <T,>(p: P<T>) => <div<string>>{p.x}</div>; function f() { return <B<C> d={1} />; }"),
    ("a.tsx", "export default function Page({ a }: { a: string }): JSX.Element { return <p>{a as string}</p>; }"),
    ("a.mts", "export const x: number = 1;"), ("a.cts", "import fs = require('fs'); export = fs;"),
    # Flow in .js
    "// @flow\ntype T = {a: ?string};\nfunction g(x: ?T, y?: string): void { return (x: any); }\nconst re: RegExp = /x/;",
    # errors
    "a;\n'open", "a;\n`open ${x}", "/* open", "x = /open", "a b", "f(", "}", "let let = 1;", "x = {a: 1,,}",
    "(" * 300 + "x" + ")" * 300, "<a><b></a>", ("a.ts", "<a></a>"), "`${", "a.#b", "@", "0b12", "'\\u{110000}'",
]

def items_of(snippets):
    """(path, source) for snippets that are a source alone (a .js file) or a pair."""
    return [s if isinstance(s, tuple) else ("s.js", s) for s in snippets]


def own_sources():
    """The repository's own JavaScript: the npm package's sources and tests, the fixtures."""
    root = _support.REPO_ROOT
    paths = sorted(glob.glob(os.path.join(root, "js", "src", "**", "*.js"), recursive=True)
                   + glob.glob(os.path.join(root, "js", "test", "**", "*.js"), recursive=True)
                   + glob.glob(os.path.join(root, "js", "bin", "*.js"))
                   + glob.glob(os.path.join(root, "python", "tests", "fixtures", "**", "*.js"), recursive=True))
    out = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace", newline="") as f:
            out.append((os.path.relpath(p, root), f.read()))
    return out


# ---- seeded token soups ----
TOKENS = ["a", "b1", "$", "_", "if", "else", "for", "while", "return", "function", "=>", "class", "extends",
          "new", "this", "let", "const", "var", "async", "await", "yield", "import", "export", "from", "as",
          "(", ")", "[", "]", "{", "}", ";", ",", ".", "?.", "?", ":", "=", "+", "-", "*", "/", "%", "<", ">",
          "!", "&&", "||", "??", "...", "'s'", '"d"', "`t`", "`a${", "}`", "/re/g", "1", "0x1", "2n", "\n", " ",
          "<a>", "</a>", "<>", "</>", "{x}", "@d", "#p", "type", "interface", "enum", "namespace", "declare",
          ":", "string", "<T>", "as", "!", "satisfies", "readonly", "private", "abstract", LS, "\r"]


def token_soups(seed, count):
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        src = " ".join(rnd.choice(TOKENS) for _ in range(rnd.randint(1, 60)))
        out.append((rnd.choice(["s.js", "s.ts", "s.tsx", "s.jsx"]), src))
    return out


def mutations(sources, seed, count):
    """Real files with a few tokens dropped, doubled or swapped (by the regex of words and punctuation)."""
    rnd = random.Random(seed)
    words = re.compile(r"[A-Za-z_$][\w$]*|\d+|\S")
    out = []
    pool = [s for s in sources if 200 < len(s[1]) < 60_000]
    for k in range(count):
        path, src = rnd.choice(pool)
        spans = [m.span() for m in words.finditer(src)]
        if not spans:
            continue
        for _ in range(rnd.randint(1, 3)):
            a, b = rnd.choice(spans)
            op = rnd.randrange(3)
            if op == 0:
                src = src[:a] + src[b:]
            elif op == 1:
                src = src[:a] + src[a:b] * 2 + src[b:]
            else:
                c, d = rnd.choice(spans)
                if c > b:
                    src = src[:a] + src[c:d] + src[b:c] + src[a:b] + src[d:]
            spans = [m.span() for m in words.finditer(src)]
            if not spans:
                break
        out.append((path, src))
    return out
