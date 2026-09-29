// The JavaScript reader the cross-file pass parses with (src/lib/jsparse.js,
// 0.1.7): twin of tests/scanner/test_jsparse.py. ESTree-shaped trees with
// every node's line, a JsSyntaxError (a line and a reason) for what it cannot
// read, linear time. tests/architecture/test_js_parity_parse.py holds the two
// readers to the same trees node for node. Inert text only.

import { test } from "node:test";
import assert from "node:assert/strict";
import { JsSyntaxError, MAX_DEPTH, dialect, parse, parseFile } from "../../src/lib/jsparse.js";

const LS = String.fromCharCode(0x2028), PS = String.fromCharCode(0x2029);
const body = (src, ts = false, jsx = true) => parse(src, ts, jsx).body;
const expr = (src, ts = false, jsx = true) => body(src, ts, jsx)[0].expression;
const error = (src, ts = false) => {
  try { parse(src, ts, !ts); } catch (e) {
    assert.ok(e instanceof JsSyntaxError, String(e));
    return [e.line, e.reason, e.message];
  }
  assert.fail("no JsSyntaxError");
};

test("node shapes", () => {
  const [decl, exp] = body("const { a, b: [c] = [] } = require('m');\nexport function f(x, ...y) {\n  return x?.y(z);\n}\n");
  assert.deepEqual([decl.type, decl.kind, decl.line], ["VariableDeclaration", "const", 1]);
  assert.equal(decl.declarations[0].id.properties[1].value.type, "AssignmentPattern");
  const fn = exp.declaration;
  assert.deepEqual([fn.type, fn.id.name, fn.params.map((p) => p.type)], ["FunctionDeclaration", "f", ["Identifier", "RestElement"]]);
  const ret = fn.body.body[0];
  assert.deepEqual([ret.line, ret.argument.type, ret.argument.expression.callee.optional], [3, "ChainExpression", true]);
});

test("lines: LF, CR, CRLF, U+2028, U+2029", () => {
  for (const nl of ["\n", "\r", "\r\n", LS, PS]) {
    assert.deepEqual(body(`a;${nl}b;${nl}${nl}c;`).map((s) => s.line), [1, 2, 4], JSON.stringify(nl));
  }
  const e = expr("(a\n+\nb)\n* c");
  assert.deepEqual([e.line, e.left.line, e.left.right.line], [1, 1, 3]);
});

test("literals: cooked strings, number text, regex or division", () => {
  assert.equal(expr("'a\\n\\x41\\u0042\\u{1F600}\\101\\\ncont\\q'").value, "a\nAB\u{1F600}Acontq");
  assert.equal(expr("'\\uD83D\\uDE00'").value, "\u{1F600}");
  assert.deepEqual(body("0x1F; 0o17; 1_000; .5e-3;").map((s) => s.expression.value), ["0x1F", "0o17", "1_000", ".5e-3"]);
  assert.deepEqual([expr("10n").kind, expr("10n").value], ["bigint", "10n"]);
  const re = expr("x = /a[/]b\\//gu").right;
  assert.deepEqual([re.kind, re.value, re.flags], ["regex", "a[/]b\\/", "gu"]);
  assert.equal(expr("a / b / c").type, "BinaryExpression");
  assert.equal(body("if (x) /re/.test(s)")[0].consequent.expression.callee.object.kind, "regex");
});

test("JSX and TypeScript", () => {
  const el = expr('<a:b c="d" {...e}>t{f}<g.h /></a:b>');
  assert.deepEqual(el.children.map((c) => c.type), ["JSXText", "JSXExpressionContainer", "JSXElement"]);
  assert.equal(body("let x: number = <number>y;", true, false)[0].declarations[0].init.name, "y");
  assert.deepEqual(body("interface I { a: string }\ntype T = I | null;", true, false).map((s) => s.type),
    ["EmptyStatement", "EmptyStatement"]);
  const [en, ns, imp, ex] = body("enum E { A = 1, B }\nnamespace N { }\nimport r = require('./r');\nexport = r;", true, false);
  assert.deepEqual([en.type, ns.type, imp.type, ex.type], ["TSEnumDeclaration", "TSModuleDeclaration", "TSImportEquals",
    "TSExportAssignment"]);
  assert.deepEqual(["a.ts", "b.MTS", "d.tsx", "e.js"].map(dialect), [[true, false], [true, false], [true, true], [false, true]]);
  assert.equal(parseFile("x.js", "const re: RegExp = /x/;").body[0].declarations[0].init.kind, "regex");   // Flow
});

test("errors: a line and a reason", () => {
  assert.deepEqual(error("a;\n'open"), [2, "unterminated string", "line 2: unterminated string"]);
  assert.deepEqual(error("/* open"), [1, "unterminated comment", "line 1: unterminated comment"]);
  assert.deepEqual(error("a b"), [1, "unexpected token 'b'", "line 1: unexpected token 'b'"]);
  assert.equal(expr("(".repeat(MAX_DEPTH / 4) + "x" + ")".repeat(MAX_DEPTH / 4)).type, "Identifier");
  for (const src of ["(".repeat(5000) + "x" + ")".repeat(5000), "[".repeat(100000), "if (x) ".repeat(100000) + "y;"]) {
    assert.equal(error(src)[1], "nesting too deep");
  }
});

test("linear: a minified single line, TypeScript's f<f<f<, hostile literals", () => {
  const cases = [["s.js", "var a=function(b,c){return b+c},d=[1,2,3].map(function(e){return e*2});".repeat(15000)],
    ["s.ts", "f<".repeat(40000)], ["s.ts", "<T>(".repeat(20000)], ["s.js", "'".repeat(300000)], ["s.js", "`${".repeat(20000)],
    ["s.js", "a" + "/b".repeat(200000)], ["s.js", "x" + ".y".repeat(300000)]];
  for (const [path, src] of cases) {
    const t = Date.now();
    try { parseFile(path, src); } catch (e) { if (!(e instanceof JsSyntaxError)) throw e; }
    assert.ok(Date.now() - t < 10000, `${path} ${src.slice(0, 20)}: ${Date.now() - t} ms`);
  }
});
