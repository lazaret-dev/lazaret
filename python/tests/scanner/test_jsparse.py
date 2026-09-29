"""The JavaScript reader the cross-file pass parses with (lazaret.scanner.
jsparse, 0.1.7): ESTree-shaped trees (acorn's and acorn-jsx's node types and
fields) for JavaScript, JSX and TypeScript, every node with the line it
starts on, and a JsSyntaxError — a line and a reason — for what it cannot
read, in linear time.

What these pin: node shapes, line numbering (LF, CR, CRLF, U+2028, U+2029),
literals (a string's cooked value with every escape, an escaped surrogate
pair as one character; numbers and bigints as their source text; a regex's
pattern and flags), templates, where `/` starts a regular expression,
automatic semicolon insertion, JSX, TypeScript read and left out (types,
interfaces, aliases, `declare`, abstract members, assertions) or kept as
nodes of their own (enums, namespaces, `import x = require()`, `export =`,
decorators), Flow's annotations in a .js file, the dialect a file name
picks, the errors, and hostile inputs (deep nesting, long speculative
reads, unterminated literals, minified single lines) staying fast.

The npm engine's twin (js/src/lib/jsparse.js) must build the same trees:
tests/architecture/test_js_parity_parse.py. Inert text only.
"""
import time
import unittest

from lazaret.scanner import jsparse


def body(src, ts=False, jsx=True):
    return jsparse.parse(src, ts, jsx)["body"]


def expr(src, ts=False, jsx=True):
    (st,) = body(src, ts, jsx)
    return st["expression"]


def error(src, ts=False, jsx=True):
    with self_raises() as ctx:
        jsparse.parse(src, ts, jsx)
    return ctx.exception


class self_raises:
    def __enter__(self):
        return self

    def __exit__(self, kind, exc, tb):
        if kind is None:
            raise AssertionError("no JsSyntaxError")
        if not issubclass(kind, jsparse.JsSyntaxError):
            return False
        self.exception = exc
        return True


class Shapes(unittest.TestCase):
    def test_a_small_program(self):
        tree = jsparse.parse("const { a, b: [c] = [] } = require('m');\nexport function f(x, ...y) {\n  return x?.y(z);\n}\n")
        self.assertEqual(tree["type"], "Program")
        decl, exp = tree["body"]
        self.assertEqual((decl["type"], decl["kind"], decl["line"]), ("VariableDeclaration", "const", 1))
        pat = decl["declarations"][0]["id"]
        self.assertEqual([p["type"] for p in pat["properties"]], ["Property", "Property"])
        self.assertEqual(pat["properties"][1]["value"]["type"], "AssignmentPattern")
        self.assertEqual(exp["type"], "ExportNamedDeclaration")
        fn = exp["declaration"]
        self.assertEqual((fn["type"], fn["id"]["name"], [p["type"] for p in fn["params"]]),
                         ("FunctionDeclaration", "f", ["Identifier", "RestElement"]))
        ret = fn["body"]["body"][0]
        self.assertEqual((ret["type"], ret["line"], ret["argument"]["type"]), ("ReturnStatement", 3, "ChainExpression"))
        call = ret["argument"]["expression"]
        self.assertEqual((call["type"], call["callee"]["optional"], call["optional"]), ("CallExpression", True, False))

    def test_classes_and_objects(self):
        (cls,) = body("class A extends B { static x = 1; #p; static { go(); } get g() { return 1; } m() {} }")
        members = cls["body"]["body"]
        self.assertEqual([m["type"] for m in members],
                         ["PropertyDefinition", "PropertyDefinition", "StaticBlock", "MethodDefinition", "MethodDefinition"])
        self.assertEqual((members[1]["key"]["type"], members[3]["kind"], members[4]["kind"]),
                         ("PrivateIdentifier", "get", "method"))
        obj = expr("({ a, b: c, [d]: e, f() {}, get g() { return 1 }, ...h })")
        self.assertEqual([(p["type"], p.get("kind"), p.get("shorthand"), p.get("computed"), p.get("method"))
                          for p in obj["properties"]],
                         [("Property", "init", True, False, False), ("Property", "init", False, False, False),
                          ("Property", "init", False, True, False), ("Property", "init", False, False, True),
                          ("Property", "get", False, False, False), ("SpreadElement", None, None, None, None)])

    def test_modules(self):
        imp, reexp, star, default = body("import d, { e as f, 'g h' as i } from './m';\nexport { a as b } from './n';\n"
                                         "export * as ns from './o';\nexport default function () {}\n")
        self.assertEqual([s["type"] for s in imp["specifiers"]],
                         ["ImportDefaultSpecifier", "ImportSpecifier", "ImportSpecifier"])
        self.assertEqual(imp["specifiers"][2]["imported"], {"type": "Literal", "line": 1, "kind": "string", "value": "g h"})
        self.assertEqual((reexp["source"]["value"], reexp["specifiers"][0]["exported"]["name"]), ("./n", "b"))
        self.assertEqual((star["type"], star["exported"]["name"]), ("ExportAllDeclaration", "ns"))
        self.assertEqual((default["declaration"]["type"], default["declaration"]["id"]), ("FunctionDeclaration", None))
        self.assertEqual(expr("import('./x', { with: { type: 'json' } })")["type"], "ImportExpression")


class Lines(unittest.TestCase):
    def test_every_line_terminator(self):
        for nl in ("\n", "\r", "\r\n", "\u2028", "\u2029"):
            with self.subTest(nl=repr(nl)):
                self.assertEqual([st["line"] for st in body(f"a;{nl}b;{nl}{nl}c;")], [1, 2, 4])

    def test_a_node_starts_where_its_first_token_does(self):
        e = expr("(a\n+\nb)\n* c")
        self.assertEqual((e["type"], e["line"], e["left"]["line"], e["left"]["right"]["line"]), ("BinaryExpression", 1, 1, 3))
        c = expr("(\nx)\n? y\n: z")
        self.assertEqual((c["line"], c["test"]["line"], c["consequent"]["line"]), (1, 2, 3))
        t = expr("`a\n${b}\nc`")
        self.assertEqual([q["line"] for q in t["quasis"]] + [t["expressions"][0]["line"]], [1, 2, 2])

    def test_a_comment_or_a_string_continues_a_line(self):
        self.assertEqual([st["line"] for st in body("/* a\nb */ x;\n'c\\\nd'; y;")], [2, 3, 4])


class Literals(unittest.TestCase):
    def test_a_strings_cooked_value(self):
        self.assertEqual(expr("'a\\n\\x41\\u0042\\u{1F600}\\101\\\ncont\\q'")["value"],
                         "a\nAB\U0001F600Acontq")
        self.assertEqual(expr("'\\uD83D\\uDE00'")["value"], "\U0001F600")          # an escaped pair: one character
        self.assertEqual(expr("'\\uD800'")["value"], "\ud800")
        self.assertEqual(expr('"\\0"')["value"], "\0")

    def test_numbers_and_bigints_keep_their_text(self):
        self.assertEqual([st["expression"]["value"] for st in body("0x1F; 0o17; 0b11; 1_000; .5e-3; 010;")],
                         ["0x1F", "0o17", "0b11", "1_000", ".5e-3", "010"])
        self.assertEqual((expr("10n")["kind"], expr("10n")["value"]), ("bigint", "10n"))
        self.assertEqual([(expr(s)["kind"], expr(s)["value"]) for s in ("true", "null")],
                         [("boolean", True), ("null", None)])

    def test_a_regex_or_a_division(self):
        right = expr("x = /a[/]b\\//gu")["right"]
        self.assertEqual((right["kind"], right["value"], right["flags"]), ("regex", "a[/]b\\/", "gu"))
        self.assertEqual(expr("a / b / c")["type"], "BinaryExpression")
        (st,) = body("if (x) /re/.test(s)")
        self.assertEqual(st["consequent"]["expression"]["callee"]["object"]["kind"], "regex")
        self.assertEqual(expr("a++ / 2")["type"], "BinaryExpression")
        self.assertEqual(expr("(a) / 2 / (b)")["operator"], "/")
        self.assertEqual(body("x\n/re/g.exec(y)")[0]["expression"]["type"], "BinaryExpression")   # no ASI: x / re / g…

    def test_templates(self):
        t = expr("`a${b}c${`d${e}`}`")
        self.assertEqual([(q["raw"], q["tail"]) for q in t["quasis"]], [("a", False), ("c", False), ("", True)])
        self.assertEqual(t["expressions"][1]["type"], "TemplateLiteral")
        tag = expr("sql`x ${y}`")
        self.assertEqual((tag["type"], tag["tag"]["name"]), ("TaggedTemplateExpression", "sql"))
        self.assertEqual(expr("`\\u{zz}`" if False else "`\\\\`")["quasis"][0]["raw"], "\\\\")


class Asi(unittest.TestCase):
    def test_restricted_productions_and_continuations(self):
        self.assertEqual([st["type"] for st in body("function f() { return\nx }")[0]["body"]["body"]],
                         ["ReturnStatement", "ExpressionStatement"])
        self.assertEqual([st["expression"]["type"] for st in body("a\n++b")], ["Identifier", "UpdateExpression"])
        self.assertEqual(expr("a\n(b)")["type"], "CallExpression")
        self.assertEqual([st["type"] for st in body("let x = 1\nlet y = 2")], ["VariableDeclaration"] * 2)
        self.assertEqual([st["type"] for st in body("x\n=> 1" if False else "x = 1\n[1].map(f)")], ["ExpressionStatement"])


class Jsx(unittest.TestCase):
    def test_elements(self):
        el = expr('<a:b c="d" {...e}>t{f}<g.h /></a:b>')
        self.assertEqual((el["type"], el["openingElement"]["name"]["type"]), ("JSXElement", "JSXNamespacedName"))
        self.assertEqual([a["type"] for a in el["openingElement"]["attributes"]], ["JSXAttribute", "JSXSpreadAttribute"])
        self.assertEqual([c["type"] for c in el["children"]], ["JSXText", "JSXExpressionContainer", "JSXElement"])
        self.assertEqual(el["children"][2]["openingElement"]["name"]["type"], "JSXMemberExpression")
        self.assertEqual(expr("<>x</>")["type"], "JSXFragment")

    def test_not_in_typescript(self):
        self.assertEqual(expr("<T>(x)", ts=True, jsx=False)["type"], "Identifier")      # an assertion, left out
        with self.assertRaises(jsparse.JsSyntaxError):
            jsparse.parse("<a></a>", ts=True, jsx=False)


class TypeScript(unittest.TestCase):
    def test_types_are_left_out(self):
        (decl,) = body("let x: number = <number>y;", ts=True, jsx=False)
        self.assertEqual(decl["declarations"][0]["init"], {"type": "Identifier", "line": 1, "name": "y"})
        self.assertEqual([st["expression"]["type"] for st in body("x!; y as any; z satisfies T;", ts=True, jsx=False)],
                         ["Identifier"] * 3)
        self.assertEqual([st["type"] for st in body("interface I { a: string }\ntype T = I | null;\n"
                                                     "declare module 'm' { }\ndeclare function f(): void;",
                                                     ts=True, jsx=False)], ["EmptyStatement"] * 4)
        call = expr("f<T>(x)", ts=True, jsx=False)
        self.assertEqual((call["type"], call["arguments"][0]["name"]), ("CallExpression", "x"))
        self.assertEqual(expr("a < b > c", ts=True, jsx=False)["operator"], ">")
        arrow = expr("<T,>(v: T): T => v", ts=True, jsx=False)
        self.assertEqual((arrow["type"], arrow["params"][0]["name"]), ("ArrowFunctionExpression", "v"))

    def test_classes(self):
        (cls,) = body("abstract class A<T> implements I { constructor(private x: T, public y?: U) {}\n"
                      "abstract m(): void;\ndeclare z: number;\nf(a: string): void;\nf(a) {}\n}", ts=True, jsx=False)
        members = cls["body"]["body"]
        self.assertEqual([(m["type"], m["key"]["name"]) for m in members],
                         [("MethodDefinition", "constructor"), ("MethodDefinition", "f")])
        self.assertEqual([p["name"] for p in members[0]["value"]["params"]], ["x", "y"])

    def test_nodes_of_their_own(self):
        enum, ns, imp, exp = body("enum E { A = 1, B }\nnamespace N.M { export const x = 1; }\n"
                                  "import r = require('./r');\nexport = r;", ts=True, jsx=False)
        self.assertEqual((enum["type"], [m["id"]["name"] for m in enum["members"]]), ("TSEnumDeclaration", ["A", "B"]))
        self.assertEqual((ns["type"], ns["body"]["type"]), ("TSModuleDeclaration", "BlockStatement"))
        self.assertEqual((imp["type"], imp["module"]["value"]), ("TSImportEquals", "./r"))
        self.assertEqual((exp["type"], exp["expression"]["name"]), ("TSExportAssignment", "r"))
        (cls,) = body("@sealed class K { @log m() {} }", ts=True, jsx=False)
        self.assertEqual((cls["decorators"][0]["name"], cls["body"]["body"][0]["decorators"][0]["name"]), ("sealed", "log"))

    def test_flow_annotations_in_javascript(self):
        (decl, fn) = body("const re: RegExp = /x/;\nfunction g(x: ?T, y?: string): void { return (x: any); }")
        self.assertEqual(decl["declarations"][0]["init"]["kind"], "regex")
        self.assertEqual(fn["body"]["body"][0]["argument"]["name"], "x")

    def test_dialect(self):
        self.assertEqual([jsparse.dialect(p) for p in ("a.ts", "b.MTS", "c.cts", "d.tsx", "e.js", "f.jsx", "g.mjs")],
                         [(True, False)] * 3 + [(True, True)] + [(False, True)] * 3)


class Errors(unittest.TestCase):
    def check(self, src, line, reason, ts=False):
        with self.assertRaises(jsparse.JsSyntaxError) as ctx:
            jsparse.parse(src, ts, not ts)
        self.assertEqual((ctx.exception.line, ctx.exception.reason, str(ctx.exception)),
                         (line, reason, f"line {line}: {reason}"))

    def test_what_it_cannot_read(self):
        self.check("a;\n'open", 2, "unterminated string")
        self.check("a;\n`open ${x}", 2, "unterminated template")
        self.check("/* open", 1, "unterminated comment")
        self.check("x = /open", 1, "unterminated regular expression")
        self.check("a b", 1, "unexpected token 'b'")
        self.check("f(", 1, "unexpected end of input")

    def test_nesting_is_bounded(self):
        ok = "(" * (jsparse.MAX_DEPTH // 4) + "x" + ")" * (jsparse.MAX_DEPTH // 4)       # two levels a parenthesis
        self.assertEqual(expr(ok)["type"], "Identifier")
        for src in ("(" * 5000 + "x" + ")" * 5000, "[" * 100000, "{" * 100000, "a = b = " * 100000 + "c",
                    "function f(){" * 5000, "<a>" * 5000, "if (x) " * 100000 + "y;"):
            with self.subTest(src=src[:20]):
                with self.assertRaises(jsparse.JsSyntaxError) as ctx:
                    jsparse.parse(src)
                self.assertEqual(ctx.exception.reason, "nesting too deep")


class Linear(unittest.TestCase):
    def fast(self, src, ts=False, limit=10.0):
        t = time.perf_counter()
        try:
            jsparse.parse(src, ts, not ts)
        except jsparse.JsSyntaxError:
            pass
        dt = time.perf_counter() - t
        self.assertLess(dt, limit, repr(src[:40]))

    def test_hostile_inputs(self):
        for src in ("'" * 300000, "`" * 300001, "/" * 300000, "/*" + "x" * 300000, "`${" * 20000,
                    "a" + "/b" * 200000, "x = " + "(a, " * 20000, "f<" * 20000, "<T>(" * 20000,
                    "(" * 250 + "a => " * 40000, "a ? " * 60000 + "b", "x" + ".y" * 300000, "f()" * 100000):
            with self.subTest(src=src[:20]):
                self.fast(src)
                self.fast(src, ts=True)

    def test_a_minified_single_line(self):
        # line terminators are looked for between two tokens only (the npm
        # twin searched to the end of the file: quadratic on one long line)
        line = "var a=function(b,c){return b+c},d=[1,2,3].map(function(e){return e*2});" * 15000
        self.fast(line, limit=10.0)


if __name__ == "__main__":
    unittest.main()
