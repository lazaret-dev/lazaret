"""Engine parity for the JavaScript reader: js/src/lib/jsparse.js against
lazaret.scanner.jsparse, node for node.

Both readers must build the same tree — every node, field and line — or
raise the same JsSyntaxError (line and reason) for:

* curated snippets: every construct the cross-file pass reads (statements,
  expressions, patterns, classes, modules, templates, regular expressions,
  ASI, JSX, TypeScript read and left out or kept, Flow annotations, escapes
  and surrogates, every line terminator) and the errors;
* the repository's own JavaScript (the npm engine's sources and tests, the
  fixtures) and seeded generated projects (tests/architecture/jsgen.py);
* seeded token soups and seeded mutations of real files (tokens dropped,
  duplicated or swapped), which reach error paths and speculative reads.

And both stay linear on the inputs that were not: a minified single line
(the npm reader once searched for line terminators to the end of the file
at every token) and TypeScript's `f<f<f<…` (each `<` a type-argument read
ahead; all of a file's reads ahead now share one allowance).

All content is inert: nothing is executed. Skipped where node is missing.
"""
import glob
import json
import os
import random
import subprocess
import time
import unittest

from lazaret.scanner import jsparse
from tests import _support
from tests.architecture import jsgen
from tests.architecture import test_js_parity as parity

PARSE_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "jsparse.js")

NPM_PARSE = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const p = await import(pathToFileURL(process.argv[1]).href);
const { items, timed } = JSON.parse(readFileSync(0, "utf8"));
const out = items.map(([path, src]) => {
  try { return { tree: p.parseFile(path, src) }; } catch (e) {
    if (!(e instanceof p.JsSyntaxError)) throw e;
    return { err: [e.line, e.reason] };
  }
});
const times = timed.map(([path, src]) => {
  const t = Date.now();
  try { p.parseFile(path, src); } catch (e) { if (!(e instanceof p.JsSyntaxError)) throw e; }
  return (Date.now() - t) / 1000;
});
process.stdout.write(JSON.stringify({ out, times }));
"""

LS, PS = chr(0x2028), chr(0x2029)
SNIPPETS = [
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
    out = []
    for s in snippets:
        out.append(s if isinstance(s, tuple) else ("s.js", s))
    return out


def own_sources():
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


TOKENS = ["a", "b1", "$", "_", "if", "else", "for", "while", "return", "function", "=>", "class", "extends",
          "new", "this", "let", "const", "var", "async", "await", "yield", "import", "export", "from", "as",
          "(", ")", "[", "]", "{", "}", ";", ",", ".", "?.", "?", ":", "=", "+", "-", "*", "/", "%", "<", ">",
          "!", "&&", "||", "??", "...", "'s'", '"d"', "`t`", "`a${", "}`", "/re/g", "1", "0x1", "2n", "\n", " ",
          "<a>", "</a>", "<>", "</>", "{x}", "@d", "#p", "type", "interface", "enum", "namespace", "declare",
          ":", "string", "<T>", "as", "!", "satisfies", "readonly", "private", "abstract", LS, "\r"]


def soups(seed, count):
    rnd = random.Random(seed)
    out = []
    for k in range(count):
        src = " ".join(rnd.choice(TOKENS) for _ in range(rnd.randint(1, 60)))
        out.append((rnd.choice(["s.js", "s.ts", "s.tsx", "s.jsx"]), src))
    return out


def mutations(sources, seed, count):
    """Real files with a few tokens dropped, doubled or swapped (by the regex of words and punctuation)."""
    import re
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


def python_side(items):
    out = []
    for path, src in items:
        try:
            out.append({"tree": json.loads(json.dumps(jsparse.parse_file(path, src)))})
        except jsparse.JsSyntaxError as e:
            out.append({"err": [e.line, e.reason]})
    return out


@unittest.skipUnless(parity.NODE, "node is not installed")
class ParseParityTests(unittest.TestCase):
    maxDiff = 4000

    def compare(self, items, timed=()):
        p = subprocess.run([parity.NODE, "--input-type=module", "-e", NPM_PARSE, PARSE_JS],
                           input=json.dumps({"items": items, "timed": list(timed)}), capture_output=True,
                           encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        got = json.loads(p.stdout)
        want = python_side(items)
        for (path, src), w, g in zip(items, want, got["out"]):
            if w != g:
                self.fail(f"{path}: {json.dumps(src)[:300]}\npy: {json.dumps(w)[:700]}\njs: {json.dumps(g)[:700]}")
        return want, got["times"]

    def test_snippets(self):
        want, _ = self.compare(items_of(SNIPPETS))
        self.assertGreater(sum("err" in w for w in want), 10)          # the error cases are errors
        self.assertGreater(sum("tree" in w for w in want), 35)

    def test_own_sources_and_generated_projects(self):
        items = own_sources() + [(f["path"], f["content"]) for files in jsgen.projects(20260928, 60) for f in files]
        want, _ = self.compare(items)
        self.assertEqual([p for (p, _), w in zip(items, want) if "err" in w], [])      # all of it reads

    def test_soups_and_mutations(self):
        items = soups(20260928, 1500) + mutations(own_sources(), 20260928, 300)
        want, _ = self.compare(items)
        self.assertGreater(sum("tree" in w for w in want), 100)
        self.assertGreater(sum("err" in w for w in want), 500)

    def test_linear_on_what_was_not(self):
        line = ("s.js", "var a=function(b,c){return b+c},d=[1,2,3].map(function(e){return e*2});" * 15000)
        gen = ("s.ts", "f<" * 40000)
        t = time.perf_counter()
        python_side([line, gen])
        py = time.perf_counter() - t
        _, times = self.compare([], timed=[line, gen])
        self.assertLess(py, 20)
        self.assertLess(max(times), 10, times)


if __name__ == "__main__":
    unittest.main()
