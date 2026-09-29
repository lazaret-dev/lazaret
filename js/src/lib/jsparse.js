// A JavaScript reader for the cross-file flow engine (0.1.7): twin of
// python/src/lazaret/scanner/jsparse.py, node for node — the same tree, the
// same lines, the same errors (tests/architecture/test_js_parity_parse.py).
//
// ECMAScript 2025 with JSX and TypeScript, read into an ESTree-shaped tree
// (acorn's and acorn-jsx's node types and fields); TypeScript's types,
// interfaces, type aliases, overload signatures, abstract members and
// `declare` statements are read and left out; an enum, a namespace,
// `import x = require(...)` and `export =` get nodes of their own. Every node
// carries the line it starts on. A reader for analysis, not a validator: it
// raises JsSyntaxError (a line and a reason) for what it cannot read.
//
// Linear time: one token at a time; speculative reads consume at most
// SPECULATION_TOKENS tokens each, and all of a file's together at most
// SPECULATION_TOTAL plus 2 per code point of it; nesting deeper than
// MAX_DEPTH is a JsSyntaxError, well before the engine's stack runs out.

export const MAX_DEPTH = 256;
export const SPECULATION_TOKENS = 4096;
export const SPECULATION_TOTAL = 16 * SPECULATION_TOKENS;   // all of a file's reads ahead: this + 2 per code point

export class JsSyntaxError extends Error {
  constructor(line, reason) {
    super(`line ${line}: ${reason}`);
    this.line = line;
    this.reason = reason;
  }
}

class Backtrack extends Error {}

/** len(s) as Python counts it (code points). */
function cpCount(s) {
  let n = s.length;
  for (let i = 0; i + 1 < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { n--; i++; }
  }
  return n;
}

// ---- scanner ----
const WS_CHARS = "\\t\\x0b\\x0c \\xa0\\ufeff\\u1680\\u2000-\\u200a\\u202f\\u205f\\u3000";
const ID_OTHER = "\\u{80}-\\u{9f}\\u{a1}-\\u{167f}\\u{1681}-\\u{1fff}\\u{200b}-\\u{2027}\\u{202a}-\\u{202e}"
  + "\\u{2030}-\\u{205e}\\u{2060}-\\u{2fff}\\u{3001}-\\u{fefe}\\u{ff00}-\\u{10ffff}";
const ID_START = "A-Za-z_$" + ID_OTHER;
const ID_PART = "A-Za-z0-9_$" + ID_OTHER;
const ESC = String.raw`\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\})`;
const BLANKS_RE = new RegExp(`[${WS_CHARS}\\n\\r\\u2028\\u2029]*`, "y");
const LT_RE = /[\n\r\u2028\u2029]/g;
const LINE_RE = /\r\n|[\n\r\u2028\u2029]/g;
const REST_OF_LINE_RE = /[^\n\r\u2028\u2029]*/y;
const IDENT_RE = new RegExp(`(?:[${ID_START}]|${ESC})[${ID_PART}]*(?:${ESC}[${ID_PART}]*)*`, "uy");
const ESC_RE = new RegExp(ESC, "g");
const NUM_RE = /0[xX][0-9a-fA-F_]*n?|0[oO][0-7_]*n?|0[bB][01_]*n?|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?n?/y;
const STR_RE = {
  "'": /'[^'\\\n\r]*(?:\\(?:\r\n|[\s\S])[^'\\\n\r]*)*'/y,
  '"': /"[^"\\\n\r]*(?:\\(?:\r\n|[\s\S])[^"\\\n\r]*)*"/y,
};
const TMPL_RE = /[^`\\$]*(?:(?:\\[\s\S]|\$(?!\{))[^`\\$]*)*/y;
const REGEX_RE = new RegExp(String.raw`/[^/\\\[\n\r\u2028\u2029]*(?:(?:\\[^\n\r\u2028\u2029]`
  + String.raw`|\[[^\]\\\n\r\u2028\u2029]*(?:\\[^\n\r\u2028\u2029][^\]\\\n\r\u2028\u2029]*)*\])`
  + String.raw`[^/\\\[\n\r\u2028\u2029]*)*` + `/[${ID_PART}]*`, "uy");
// `>` is always one token: the parser reads `>=`, `>>`, `>>=`, … where an
// operator may stand (TypeScript's type arguments close with it)
const PUNCT_RE = /\.\.\.|===|!==|\*\*=|<<=|&&=|\|\|=|\?\?=|=>|==|!=|<=|&&|\|\||\?\?|\?\.(?![0-9])|\+\+|--|\+=|-=|\*=|\/=|%=|&=|\|=|\^=|\*\*|<<|[{}()[\];,<>+\-*/%&|^!~?:=.@#]/y;
const GT_RE = />>>=|>>=|>>>|>>|>=|>/y;
const JSX_NAME_RE = new RegExp(`[${ID_START}][${ID_PART}\\-]*`, "uy");
const JSX_TEXT_RE = /[^{<]+/y;
const JSX_STR_RE = { "'": /'[^']*'/y, '"': /"[^"]*"/y };
const SIMPLE_ESC = { n: "\n", r: "\r", t: "\t", b: "\b", f: "\f", v: "\x0b" };
const COOK_RE = /\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-7]{1,3})|(\r\n|[\s\S]))/g;
const LINE_ENDS = new Set(["\n", "\r", "\u2028", "\u2029", "\r\n"]);

function match(re, src, pos) {
  re.lastIndex = pos;
  return re.exec(src);
}

function cookOne(m, g1, g2, g3, g4, g5) {
  if (g1 !== undefined) {
    const cp = parseInt(g1, 16);
    return cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
  }
  if (g2 !== undefined) return String.fromCharCode(parseInt(g2, 16));
  if (g3 !== undefined) return String.fromCharCode(parseInt(g3, 16));
  if (g4 !== undefined) {
    if (parseInt(g4, 8) > 255) return String.fromCharCode(parseInt(g4.slice(0, 2), 8)) + g4.slice(2);
    return String.fromCharCode(parseInt(g4, 8));
  }
  if (LINE_ENDS.has(g5)) return "";               // a line continuation
  return Object.hasOwn(SIMPLE_ESC, g5) ? SIMPLE_ESC[g5] : g5;
}

function cook(raw) {
  if (!raw.includes("\\")) return raw;
  return raw.replace(COOK_RE, cookOne);
}

function unescapeIdentOne(m) {
  const h = m.slice(2);
  const cp = parseInt(h.startsWith("{") ? h.slice(1, -1) : h, 16);
  return cp <= 0x10ffff ? String.fromCodePoint(cp) : "\ufffd";
}

// ---- grammar ----
const BINARY_PREC = new Map(Object.entries({
  "??": 1, "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
  "==": 6, "!=": 6, "===": 6, "!==": 6,
  "<": 7, ">": 7, "<=": 7, ">=": 7, instanceof: 7, in: 7,
  "<<": 8, ">>": 8, ">>>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11,
}));
const LOGICAL = new Set(["||", "&&", "??"]);
const ASSIGN_OPS = new Set(["=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=",
  "&&=", "||=", "??="]);
const UNARY_WORDS = new Set(["typeof", "void", "delete"]);
// reserved words: never an identifier reference, a binding or a label
const RESERVED = new Set([
  "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
  "export", "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "return",
  "super", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with", "null", "true",
  "false", "enum"]);
const CLASS_MODIFIERS = new Set(["public", "private", "protected", "readonly", "abstract", "override", "declare",
  "static", "accessor", "async", "get", "set"]);
const PARAM_MODIFIERS = new Set(["public", "private", "protected", "readonly", "override"]);
const TS_DECL_WORDS = new Set(["interface", "type", "enum", "declare", "namespace", "module", "abstract", "global"]);
const EXPR_START_PUNCT = new Set(["(", "[", "{", "+", "-", "!", "~", "++", "--", "/", "/=", "<", "@", "#", "..."]);
const KEY_KINDS = new Set(["name", "str", "num", "bigint", "priv"]);

function n(type, line, fields) {
  return { type, line, ...fields };
}

function quote(text) {
  return "'" + text.replace(/\\/g, "\\\\").replace(/'/g, "\\'") + "'";
}

function jsxNameText(node) {
  if (node.type === "JSXIdentifier") return node.name;
  if (node.type === "JSXNamespacedName") return node.namespace.name + ":" + node.name.name;
  return jsxNameText(node.object) + "." + node.property.name;
}

/** Can a cover item be read as a parameter (toPattern with binding)? */
function paramOk(node) {
  const stack = [node];
  while (stack.length) {
    const nd = stack.pop();
    const t = nd.type;
    if (t === "Identifier") continue;
    if (t === "AssignmentExpression") {
      if (nd.operator !== "=") return false;
      stack.push(nd.left);
    } else if (t === "ObjectExpression") {
      for (const p of nd.properties) {
        if (p.type === "SpreadElement") stack.push(p.argument);
        else if (p.kind !== "init" || p.method) return false;
        else stack.push(p.value);
      }
    } else if (t === "ArrayExpression") {
      for (const el of nd.elements) {
        if (el !== null) stack.push(el.type === "SpreadElement" ? el.argument : el);
      }
    } else if (!["ObjectPattern", "ArrayPattern", "AssignmentPattern", "RestElement"].includes(t)) {
      return false;
    }
  }
  return true;
}

function reduce(operands, ops) {
  const right = operands.pop()[0];
  const [left, line] = operands.pop();
  const op = ops.pop()[0];
  operands.push([n(LOGICAL.has(op) ? "LogicalExpression" : "BinaryExpression", line, { operator: op, left, right }),
    line]);
}

function bisectLeft(a, x) {
  let lo = 0, hi = a.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (a[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

class Parser {
  constructor(src, ts, jsx) {
    this.src = src;
    this.n = src.length;
    this.ts = ts;
    this.jsx = jsx;
    this.lineEnds = [];
    for (const m of src.matchAll(LINE_RE)) this.lineEnds.push(m.index);
    this.depth = 0;
    this.inFunc = false;
    this.inAsync = false;
    this.inGen = false;
    this.noConditional = false;
    this.spec = 0;
    this.specBudget = 0;
    this.specLeft = 2 * cpCount(src) + SPECULATION_TOTAL;   // tokens every read ahead may still consume
    this.covers = [];
    this.peekAt = -1;
    this.peekVal = null;
    this.t = "eof";
    this.v = "";
    this.s = 0;
    this.e = 0;
    this.ln = 1;
    this.nl = false;
    this.esc = false;
    this.pt = null;
    this.pv = null;
    this.declaring = false;
    this.retOk = true;
    this.closerLine = 0;
    if (src.startsWith("#!")) this.e = match(REST_OF_LINE_RE, src, 2)[0].length + 2;
    this.next();
  }

  // ---- scanning ----
  lineAt(pos) {
    return bisectLeft(this.lineEnds, pos) + 1;
  }

  fail(reason = null, line = null) {
    if (reason === null) {
      if (this.t === "eof") reason = "unexpected end of input";
      else if (this.t === "str") reason = "unexpected string";
      else if (this.t === "tmpl") reason = "unexpected template";
      else {
        let text = this.src.slice(this.s, this.e);
        const cps = Array.from(text);
        if (cps.length > 20) text = cps.slice(0, 20).join("");
        reason = "unexpected token " + quote(text);
      }
    }
    throw new JsSyntaxError(line === null ? this.ln : line, reason);
  }

  /** A line terminator in src[a:b]? (A bounded scan: a regex search from a would run to the end.) */
  ltBetween(a, b) {
    const src = this.src;
    for (let i = a; i < b; i++) {
      const c = src.charCodeAt(i);
      if (c === 10 || c === 13 || c === 0x2028 || c === 0x2029) return true;
    }
    return false;
  }

  skip(pos) {
    const src = this.src;
    let b = pos;
    for (;;) {
      b = match(BLANKS_RE, src, b)[0].length + b;
      if (src.startsWith("//", b)) {
        LT_RE.lastIndex = b;
        const m = LT_RE.exec(src);
        b = m === null ? this.n : m.index;
      } else if (src.startsWith("/*", b)) {
        const end = src.indexOf("*/", b + 2);
        if (end < 0) throw new JsSyntaxError(this.lineAt(b), "unterminated comment");
        b = end + 2;
      } else {
        break;
      }
    }
    this.nl = b > pos && this.ltBetween(pos, b);
    this.s = b;
    this.ln = this.lineAt(b);
    this.esc = false;
    return b;
  }

  next() {
    if (this.spec) {
      this.specBudget -= 1;
      this.specLeft -= 1;
      if (this.specBudget < 0 || this.specLeft < 0) throw new Backtrack();
    }
    this.pt = this.t;
    this.pv = this.v;
    const src = this.src;
    const b = this.skip(this.e);
    if (b >= this.n) {
      this.t = "eof"; this.v = ""; this.e = b;
      return;
    }
    const c = src[b];
    const o = c.charCodeAt(0);
    if ((o < 128 && ((o >= 65 && o <= 90) || (o >= 97 && o <= 122) || c === "_" || c === "$")) || c === "\\"
        || o >= 128) {
      const m = match(IDENT_RE, src, b);
      if (m !== null) {
        let text = m[0];
        this.e = b + text.length;
        if (text.includes("\\")) {
          this.esc = true;
          text = text.replace(ESC_RE, unescapeIdentOne);
        }
        this.t = "name"; this.v = text;
        return;
      }
      if (c === "\\") this.fail("unexpected character '\\'");
      this.fail("unexpected character " + quote(String.fromCodePoint(src.codePointAt(b))));
    }
    const c1 = src[b + 1];
    if ((c >= "0" && c <= "9") || (c === "." && c1 !== undefined && c1 >= "0" && c1 <= "9")) {
      const text = match(NUM_RE, src, b)[0];
      this.e = b + text.length;
      this.t = text.endsWith("n") ? "bigint" : "num"; this.v = text;
      return;
    }
    if (c === "'" || c === '"') {
      const m = match(STR_RE[c], src, b);
      if (m === null) this.fail("unterminated string");
      this.e = b + m[0].length;
      this.t = "str"; this.v = cook(src.slice(b + 1, this.e - 1));
      return;
    }
    if (c === "`") {
      this.readTemplate(b + 1);
      return;
    }
    if (c === "#") {
      const m = match(IDENT_RE, src, b + 1);
      if (m !== null) {
        this.e = b + 1 + m[0].length;
        this.t = "priv"; this.v = m[0].replace(ESC_RE, unescapeIdentOne);
        return;
      }
    }
    const m = match(PUNCT_RE, src, b);
    if (m === null) this.fail("unexpected character " + quote(String.fromCodePoint(src.codePointAt(b))));
    this.e = b + m[0].length;
    this.t = "p"; this.v = m[0];
  }

  readTemplate(pos) {
    const end = pos + match(TMPL_RE, this.src, pos)[0].length;
    if (this.src.startsWith("`", end)) {
      this.t = "tmpl"; this.v = [this.src.slice(pos, end), true]; this.e = end + 1;
    } else if (this.src.startsWith("${", end)) {
      this.t = "tmpl"; this.v = [this.src.slice(pos, end), false]; this.e = end + 2;
    } else {
      this.fail("unterminated template");
    }
  }

  rescanRegex() {
    const m = match(REGEX_RE, this.src, this.s);
    if (m === null) this.fail("unterminated regular expression");
    const text = m[0];
    const close = text.lastIndexOf("/");
    this.e = this.s + text.length;
    this.t = "regex"; this.v = [text.slice(1, close), text.slice(close + 1)];
  }

  rescanTemplateContinuation() {
    if (!(this.t === "p" && this.v === "}")) this.fail();
    this.readTemplate(this.s + 1);
  }

  gtOp() {
    return match(GT_RE, this.src, this.s)[0];
  }

  takeGt() {
    const op = this.gtOp();
    this.e = this.s + op.length;
    this.v = op;
  }

  peek() {
    if (this.peekAt === this.e && this.peekVal !== null) return this.peekVal;
    const st = this.save();
    this.spec += 1;
    this.specBudget += 1;
    let out, ok = true;
    try {
      this.next();
      out = [this.t, this.v, this.nl];
    } catch (e) {
      if (!(e instanceof JsSyntaxError || e instanceof Backtrack)) throw e;
      out = ["eof", "", false];
      ok = false;
    } finally {
      this.spec -= 1;
      this.restore(st);
    }
    if (ok) {
      this.peekAt = this.e;
      this.peekVal = out;
    }
    return out;
  }

  save() {
    return [this.t, this.v, this.s, this.e, this.ln, this.nl, this.esc, this.depth, this.covers.length,
      this.inFunc, this.inAsync, this.inGen, this.noConditional, this.pt, this.pv, this.retOk, this.specBudget];
  }

  restore(st) {
    let ncov;
    [this.t, this.v, this.s, this.e, this.ln, this.nl, this.esc, this.depth, ncov,
      this.inFunc, this.inAsync, this.inGen, this.noConditional, this.pt, this.pv, this.retOk, this.specBudget] = st;
    this.covers.length = ncov;
  }

  speculate(fn) {
    const st = this.save();
    const outer = this.spec > 0;
    if (!outer) this.specBudget = SPECULATION_TOKENS;
    this.spec += 1;
    let out;
    try {
      out = fn();
    } catch (e) {
      if (!(e instanceof JsSyntaxError || e instanceof Backtrack)) throw e;
      this.spec -= 1;
      const spent = this.specBudget;
      this.restore(st);
      if (outer) this.specBudget = spent;
      return null;
    }
    this.spec -= 1;
    if (!outer) this.specBudget = st[st.length - 1];
    return out;
  }

  look(fn, tokens) {
    const st = this.save();
    this.spec += 1;
    this.specBudget += tokens;
    try {
      return fn();
    } catch (e) {
      if (!(e instanceof JsSyntaxError || e instanceof Backtrack)) throw e;
      return false;
    } finally {
      this.spec -= 1;
      this.restore(st);
    }
  }

  // ---- token tests ----
  isP(v) { return this.t === "p" && this.v === v; }

  isN(v) { return this.t === "name" && this.v === v && !this.esc; }

  eatP(v) {
    if (this.t === "p" && this.v === v) {
      this.next();
      return true;
    }
    return false;
  }

  eatN(v) {
    if (this.t === "name" && this.v === v && !this.esc) {
      this.next();
      return true;
    }
    return false;
  }

  expectP(v) {
    if (!(this.t === "p" && this.v === v)) this.fail();
    this.next();
  }

  expectN(v) {
    if (!(this.t === "name" && this.v === v && !this.esc)) this.fail();
    this.next();
  }

  semicolon() {
    if (this.t === "p" && this.v === ";") this.next();
    else if (!(this.t === "eof" || (this.t === "p" && this.v === "}") || this.nl)) this.fail();
  }

  enter() {
    this.depth += 1;
    if (this.depth > MAX_DEPTH) throw new JsSyntaxError(this.ln, "nesting too deep");
  }

  ident(reservedOk = false) {
    if (this.t !== "name" || (!reservedOk && !this.esc && RESERVED.has(this.v))) this.fail();
    const node = n("Identifier", this.ln, { name: this.v });
    this.next();
    return node;
  }

  functionContext(isAsync, gen) {
    const saved = [this.inFunc, this.inAsync, this.inGen];
    this.inFunc = true; this.inAsync = isAsync; this.inGen = gen;
    return saved;
  }

  restoreContext(saved) {
    [this.inFunc, this.inAsync, this.inGen] = saved;
  }

  // ---- program and statements ----
  parseProgram() {
    const body = [];
    while (this.t !== "eof") {
      const stmt = this.parseStatement();
      if (stmt !== null) body.push(stmt);
    }
    for (const prop of this.covers) {
      if (Object.hasOwn(prop, "_cover")) throw new JsSyntaxError(prop.line, "invalid shorthand property initializer");
    }
    return n("Program", 1, { body });
  }

  parseStatement() {
    this.enter();
    const stmt = this.parseStatementInner();
    this.depth -= 1;
    return stmt;
  }

  subStatement() {
    const line = this.ln;
    const stmt = this.parseStatement();
    return stmt === null ? n("EmptyStatement", line, {}) : stmt;
  }

  parseStatementInner() {
    const { t, v } = this;
    const line = this.ln;
    if (t === "p") {
      if (v === "{") return this.parseBlock();
      if (v === ";") {
        this.next();
        return n("EmptyStatement", line, {});
      }
      if (v === "@") {
        const decorators = this.parseDecorators();
        if (this.isN("export")) return this.parseExport(decorators);
        return this.parseClass(true, decorators);
      }
    } else if (t === "name" && !this.esc) {
      const [pk, pv, pnl] = this.peek();
      if (v === "var" || v === "const") {
        if (v === "const" && pk === "name" && pv === "enum") {
          this.next();
          return this.parseEnum(line);
        }
        const node = this.parseVar(v);
        this.semicolon();
        return node;
      }
      if (v === "let" && (pk === "name" || (pk === "p" && (pv === "[" || pv === "{")))) {
        const node = this.parseVar("let");
        this.semicolon();
        return node;
      }
      if (v === "using" && pk === "name" && !pnl && !["in", "of", "instanceof"].includes(pv)) {
        const node = this.parseVar("using");
        this.semicolon();
        return node;
      }
      if (v === "await" && pk === "name" && pv === "using" && !pnl && this.look(() => this.awaitUsingAhead(), 3)) {
        this.next();
        const node = this.parseVar("await using");
        this.semicolon();
        return node;
      }
      if (v === "function") return this.parseFunction(true, false, line);
      if (v === "async" && pk === "name" && pv === "function" && !pnl) {
        this.next();
        return this.parseFunction(true, true, line);
      }
      if (v === "class") return this.parseClass(true, []);
      if (v === "if") return this.parseIf();
      if (v === "for") return this.parseFor();
      if (v === "while") {
        this.next();
        const test = this.parseParenExpr();
        const body = this.subStatement();
        return n("WhileStatement", line, { test, body });
      }
      if (v === "do") {
        this.next();
        const body = this.subStatement();
        this.expectN("while");
        const test = this.parseParenExpr();
        this.eatP(";");
        return n("DoWhileStatement", line, { body, test });
      }
      if (v === "return") {
        this.next();
        let argument = null;
        if (!(this.t === "eof" || this.nl || (this.t === "p" && (this.v === ";" || this.v === "}")))) {
          argument = this.parseExpression();
        }
        this.semicolon();
        return n("ReturnStatement", line, { argument });
      }
      if (v === "break" || v === "continue") {
        this.next();
        let label = null;
        if (this.t === "name" && !this.nl) label = this.ident(true);
        this.semicolon();
        return n(v === "break" ? "BreakStatement" : "ContinueStatement", line, { label });
      }
      if (v === "throw") {
        this.next();
        if (this.nl) this.fail("illegal newline after throw");
        const argument = this.parseExpression();
        this.semicolon();
        return n("ThrowStatement", line, { argument });
      }
      if (v === "try") return this.parseTry();
      if (v === "switch") return this.parseSwitch();
      if (v === "with") {
        this.next();
        const object = this.parseParenExpr();
        const body = this.subStatement();
        return n("WithStatement", line, { object, body });
      }
      if (v === "debugger") {
        this.next();
        this.semicolon();
        return n("DebuggerStatement", line, {});
      }
      if (v === "import" && !(pk === "p" && (pv === "(" || pv === "."))) return this.parseImport();
      if (v === "export") return this.parseExport([]);
      if (TS_DECL_WORDS.has(v)) {
        const node = this.parseTsDeclaration(pk, pv, pnl);
        if (node !== false) return node;
      }
      if (pk === "p" && pv === ":" && !RESERVED.has(v)) {
        const label = this.ident();
        this.next();
        const body = this.subStatement();
        return n("LabeledStatement", line, { label, body });
      }
    }
    const expression = this.parseExpression();
    this.semicolon();
    return n("ExpressionStatement", line, { expression });
  }

  awaitUsingAhead() {
    this.next();
    this.next();
    return this.t === "name" && !this.nl && !["in", "of", "instanceof"].includes(this.v);
  }

  parseBlock() {
    const line = this.ln;
    this.expectP("{");
    const body = [];
    while (!(this.t === "p" && this.v === "}")) {
      if (this.t === "eof") this.fail();
      const stmt = this.parseStatement();
      if (stmt !== null) body.push(stmt);
    }
    this.next();
    return n("BlockStatement", line, { body });
  }

  parseParenExpr() {
    this.expectP("(");
    const expr = this.parseExpression();
    this.expectP(")");
    return expr;
  }

  parseIf() {
    const chain = [];
    let alt = null;
    for (;;) {
      const line = this.ln;
      this.next();
      const test = this.parseParenExpr();
      const cons = this.subStatement();
      chain.push([line, test, cons]);
      if (!this.isN("else")) break;
      this.next();
      if (!this.isN("if")) {
        alt = this.subStatement();
        break;
      }
    }
    for (let i = chain.length - 1; i >= 0; i--) {
      const [line, test, consequent] = chain[i];
      alt = n("IfStatement", line, { test, consequent, alternate: alt });
    }
    return alt;
  }

  parseTry() {
    const line = this.ln;
    this.next();
    const block = this.parseBlock();
    let handler = null, finalizer = null;
    if (this.isN("catch")) {
      const cline = this.ln;
      this.next();
      let param = null;
      if (this.eatP("(")) {
        param = this.parseBindingTarget();
        if (this.eatP(":")) this.parseType();
        this.expectP(")");
      }
      const body = this.parseBlock();
      handler = n("CatchClause", cline, { param, body });
    }
    if (this.eatN("finally")) finalizer = this.parseBlock();
    if (handler === null && finalizer === null) this.fail("missing catch or finally");
    return n("TryStatement", line, { block, handler, finalizer });
  }

  parseSwitch() {
    const line = this.ln;
    this.next();
    const discriminant = this.parseParenExpr();
    this.expectP("{");
    const cases = [];
    while (!this.eatP("}")) {
      const cline = this.ln;
      let test;
      if (this.eatN("case")) test = this.parseExpression();
      else if (this.eatN("default")) test = null;
      else this.fail();
      this.expectP(":");
      const consequent = [];
      while (!(this.isP("}") || this.isN("case") || this.isN("default"))) {
        if (this.t === "eof") this.fail();
        const stmt = this.parseStatement();
        if (stmt !== null) consequent.push(stmt);
      }
      cases.push(n("SwitchCase", cline, { test, consequent }));
    }
    return n("SwitchStatement", line, { discriminant, cases });
  }

  parseFor() {
    const line = this.ln;
    this.next();
    const isAwait = this.eatN("await");
    this.expectP("(");
    let init = null;
    if (!this.isP(";")) {
      let kind = null;
      if (this.t === "name" && !this.esc) {
        const [pk, pv, pnl] = this.peek();
        if (this.v === "var" || this.v === "const") kind = this.v;
        else if (this.v === "let" && (pk === "name" || (pk === "p" && (pv === "[" || pv === "{")))) kind = "let";
        else if (this.v === "using" && pk === "name" && pv !== "of" && pv !== "in" && !pnl) kind = "using";
        else if (this.v === "await" && pk === "name" && pv === "using" && this.look(() => this.awaitUsingAhead(), 3)) {
          this.next();
          kind = "await using";
        }
      }
      if (kind !== null) init = this.parseVar(kind, true);
      else init = this.parseExpression(true);
      if (this.isN("of") || this.isN("in")) {
        const of = this.v === "of";
        this.next();
        if (init.type !== "VariableDeclaration") init = this.toPattern(init, false);
        const right = of ? this.parseMaybeAssign() : this.parseExpression();
        this.expectP(")");
        const body = this.subStatement();
        if (of) return n("ForOfStatement", line, { left: init, right, body, await: isAwait });
        return n("ForInStatement", line, { left: init, right, body });
      }
    }
    this.expectP(";");
    const test = this.isP(";") ? null : this.parseExpression();
    this.expectP(";");
    const update = this.isP(")") ? null : this.parseExpression();
    this.expectP(")");
    const body = this.subStatement();
    return n("ForStatement", line, { init, test, update, body });
  }

  parseVar(kind, noIn = false) {
    const line = this.ln;
    this.next();
    const declarations = [];
    for (;;) {
      const dline = this.ln;
      const id = this.parseBindingTarget();
      if (this.ts && this.isP("!")) this.next();
      if (this.eatP(":")) this.parseType();
      let init = null;
      if (this.eatP("=")) init = this.parseMaybeAssign(noIn);
      declarations.push(n("VariableDeclarator", dline, { id, init }));
      if (!this.eatP(",")) break;
    }
    return n("VariableDeclaration", line, { kind, declarations });
  }

  // ---- functions ----
  parseFunction(isDecl, isAsync, line) {
    this.next();
    const gen = this.eatP("*");
    let id = null;
    if (this.t === "name" && !this.isP("(")) id = this.ident(this.v === "yield" || this.v === "await");
    if (this.isP("<")) this.parseTypeParams();
    const saved = this.functionContext(isAsync, gen);
    let params, body;
    try {
      params = this.parseParams();
      if (this.isP(":")) this.parseReturnType();
      if (!this.isP("{")) {
        if (isDecl && (this.ts || this.declaring) && (this.isP(";") || this.nl || this.isP("}") || this.t === "eof")) {
          this.eatP(";");
          return null;
        }
        this.fail();
      }
      body = this.parseBlock();
    } finally {
      this.restoreContext(saved);
    }
    return n(isDecl ? "FunctionDeclaration" : "FunctionExpression", line,
      { id, params, body, generator: gen, async: isAsync });
  }

  parseParams() {
    this.expectP("(");
    const params = [];
    while (!this.isP(")")) {
      const param = this.parseParam();
      if (param !== null) params.push(param);
      if (!this.isP(")")) this.expectP(",");
    }
    this.next();
    return params;
  }

  parseParam() {
    const line = this.ln;
    const decorators = this.isP("@") ? this.parseDecorators() : [];
    while (this.t === "name" && PARAM_MODIFIERS.has(this.v) && !this.esc) {
      const [pk, pv] = this.peek();
      if (pk === "name" || (pk === "p" && (pv === "[" || pv === "{"))) this.next();
      else break;
    }
    if (this.isP("...")) {
      this.next();
      const node = n("RestElement", line, { argument: this.parseBindingTarget() });
      this.eatP("?");
      if (this.eatP(":")) this.parseType();
      if (this.eatP("=")) this.parseMaybeAssign();
      return node;
    }
    if (this.isN("this")) {
      const [pk, pv] = this.peek();
      if (pk === "p" && (pv === ":" || pv === "," || pv === ")")) {
        this.next();
        if (this.eatP(":")) this.parseType();
        return null;
      }
    }
    const tline = this.ln;
    let target = this.parseBindingTarget();
    this.eatP("?");
    if (this.eatP(":")) this.parseType();
    if (this.eatP("=")) target = n("AssignmentPattern", tline, { left: target, right: this.parseMaybeAssign() });
    if (decorators.length) target.decorators = decorators;
    return target;
  }

  parseBindingTarget() {
    const line = this.ln;
    if (this.isP("[")) {
      this.enter();
      this.next();
      const elements = [];
      while (!this.isP("]")) {
        if (this.isP(",")) {
          this.next();
          elements.push(null);
          continue;
        }
        const eline = this.ln;
        if (this.eatP("...")) {
          elements.push(n("RestElement", eline, { argument: this.parseBindingTarget() }));
        } else {
          let el = this.parseBindingTarget();
          if (this.eatP("=")) el = n("AssignmentPattern", eline, { left: el, right: this.parseMaybeAssign() });
          elements.push(el);
        }
        if (!this.isP("]")) this.expectP(",");
      }
      this.next();
      this.depth -= 1;
      return n("ArrayPattern", line, { elements });
    }
    if (this.isP("{")) {
      this.enter();
      this.next();
      const properties = [];
      while (!this.isP("}")) {
        const pline = this.ln;
        if (this.eatP("...")) {
          properties.push(n("RestElement", pline, { argument: this.parseBindingTarget() }));
        } else {
          let computed = false, key;
          if (this.eatP("[")) {
            key = this.parseMaybeAssign();
            this.expectP("]");
            computed = true;
          } else {
            key = this.parsePropertyName();
          }
          let value, shorthand, vline;
          if (this.eatP(":")) {
            vline = this.ln;
            value = this.parseBindingTarget();
            shorthand = false;
          } else {
            if (key.type !== "Identifier" || computed) this.fail();
            vline = key.line;
            value = n("Identifier", vline, { name: key.name });
            shorthand = true;
          }
          if (this.eatP("=")) value = n("AssignmentPattern", vline, { left: value, right: this.parseMaybeAssign() });
          properties.push(n("Property", pline, { key, value, kind: "init", method: false, shorthand, computed }));
        }
        if (!this.isP("}")) this.expectP(",");
      }
      this.next();
      this.depth -= 1;
      return n("ObjectPattern", line, { properties });
    }
    if (this.t === "name") return this.ident();
    this.fail();
  }

  parsePropertyName() {
    const { t, v } = this;
    const line = this.ln;
    let node;
    if (t === "name") node = n("Identifier", line, { name: v });
    else if (t === "str") node = n("Literal", line, { kind: "string", value: v });
    else if (t === "num" || t === "bigint") node = n("Literal", line, { kind: t === "num" ? "number" : "bigint", value: v });
    else if (t === "priv") node = n("PrivateIdentifier", line, { name: v });
    else this.fail();
    this.next();
    return node;
  }

  // ---- classes ----
  parseDecorators() {
    const out = [];
    while (this.isP("@")) {
      this.next();
      this.enter();
      const line = this.ln;
      let expr;
      if (this.isP("(")) {
        expr = this.parseParenExpr();
      } else {
        expr = this.ident(true);
        while (this.eatP(".")) {
          const property = this.t === "priv" ? this.parsePropertyName() : this.ident(true);
          expr = n("MemberExpression", line, { object: expr, property, computed: false, optional: false });
        }
        if (this.ts && this.isP("<")) this.speculate(() => this.parseTypeArgs());
        if (this.isP("(")) {
          const args = this.parseArguments();
          expr = n("CallExpression", line, { callee: expr, arguments: args, optional: false });
        }
      }
      out.push(expr);
      this.depth -= 1;
    }
    return out;
  }

  parseClass(isDecl, decorators) {
    const line = this.ln;
    this.eatN("abstract");
    this.expectN("class");
    let id = null;
    if (this.t === "name" && !(this.isN("extends") || this.isN("implements"))) id = this.ident();
    if (this.isP("<")) this.parseTypeParams();
    let superClass = null;
    if (this.eatN("extends")) {
      superClass = this.parseExprSubscripts();
      if (this.isP("<")) this.parseTypeArgs();
    }
    if (this.eatN("implements")) {
      this.parseType();
      while (this.eatP(",")) this.parseType();
    }
    const body = this.parseClassBody();
    const node = n(isDecl ? "ClassDeclaration" : "ClassExpression", line, { id, superClass, body });
    if (decorators.length) node.decorators = decorators;
    return node;
  }

  parseClassBody() {
    const line = this.ln;
    this.expectP("{");
    const members = [];
    while (!this.isP("}")) {
      if (this.eatP(";")) continue;
      if (this.t === "eof") this.fail();
      this.enter();
      const member = this.parseClassMember();
      this.depth -= 1;
      if (member !== null) members.push(member);
    }
    this.next();
    return n("ClassBody", line, { body: members });
  }

  isModifier() {
    const [pk, pv, pnl] = this.peek();
    if (this.v === "async" && pnl) return false;
    return KEY_KINDS.has(pk) || (pk === "p" && (pv === "[" || pv === "*"));
  }

  parseClassMember() {
    const line = this.ln;
    const decorators = this.isP("@") ? this.parseDecorators() : [];
    let isStatic = false, isAsync = false, gen = false, declare = false, abstract = false;
    let kind = "method";
    while (this.t === "name" && !this.esc && CLASS_MODIFIERS.has(this.v)) {
      const word = this.v;
      if (word === "static") {
        const [pk, pv] = this.peek();
        if (pk === "p" && pv === "{") {
          this.next();
          const saved = this.functionContext(false, false);
          let block;
          try {
            block = this.parseBlock();
          } finally {
            this.restoreContext(saved);
          }
          return n("StaticBlock", line, { body: block.body });
        }
      }
      if (!this.isModifier()) break;
      this.next();
      if (word === "static") isStatic = true;
      else if (word === "async") isAsync = true;
      else if (word === "get" || word === "set") kind = word;
      else if (word === "declare") declare = true;
      else if (word === "abstract") abstract = true;
    }
    if (this.eatP("*")) gen = true;
    if (this.ts && this.isP("[") && this.indexSignatureAhead()) {
      this.parseIndexSignature();
      this.memberEnd();
      return null;
    }
    let computed = false, key;
    if (this.isP("[")) {
      this.next();
      key = this.parseMaybeAssign();
      this.expectP("]");
      computed = true;
    } else {
      key = this.parsePropertyName();
    }
    if (this.isP("?") || (this.ts && this.isP("!"))) this.next();
    if (this.isP("<")) this.parseTypeParams();
    if (this.isP("(")) {
      const isCtor = !isStatic && !computed && kind === "method"
        && ((key.type === "Identifier" && key.name === "constructor") || (key.type === "Literal" && key.value === "constructor"));
      const fn = this.parseMethod(isAsync, gen);
      if (fn === null || abstract || declare) return null;
      const node = n("MethodDefinition", line,
        { key, value: fn, kind: isCtor ? "constructor" : kind, static: isStatic, computed });
      if (decorators.length) node.decorators = decorators;
      return node;
    }
    if (kind !== "method" || gen) this.fail();
    if (this.eatP(":")) this.parseType();
    let value = null;
    if (this.eatP("=")) {
      const saved = this.functionContext(false, false);
      try {
        value = this.parseMaybeAssign();
      } finally {
        this.restoreContext(saved);
      }
    }
    this.memberEnd();
    if (declare || abstract) return null;
    const node = n("PropertyDefinition", line, { key, value, static: isStatic, computed });
    if (decorators.length) node.decorators = decorators;
    return node;
  }

  memberEnd() {
    if (this.eatP(";") || this.eatP(",")) return;
    if (!(this.isP("}") || this.nl || this.t === "eof")) this.fail();
  }

  parseMethod(isAsync, gen) {
    const line = this.ln;
    const saved = this.functionContext(isAsync, gen);
    let params, body;
    try {
      params = this.parseParams();
      if (this.isP(":")) this.parseReturnType();
      if (!this.isP("{")) {
        if (this.isP(";") || this.isP(",") || this.isP("}") || this.nl || this.t === "eof") {
          this.eatP(";");
          return null;
        }
        this.fail();
      }
      body = this.parseBlock();
    } finally {
      this.restoreContext(saved);
    }
    return n("FunctionExpression", line, { id: null, params, body, generator: gen, async: isAsync });
  }

  indexSignatureAhead() {
    return this.look(() => {
      this.next();
      if (this.t !== "name") return false;
      this.next();
      return this.t === "p" && (this.v === ":" || this.v === ",");
    }, 3);
  }

  parseIndexSignature() {
    this.expectP("[");
    while (!this.isP("]")) {
      this.ident(true);
      if (this.eatP(":")) this.parseType();
      if (!this.isP("]")) this.expectP(",");
    }
    this.next();
    this.eatP("?");
    if (this.eatP(":")) this.parseType();
  }

  // ---- modules ----
  parseModuleSource() {
    if (this.t !== "str") this.fail();
    const node = n("Literal", this.ln, { kind: "string", value: this.v });
    this.next();
    if ((this.isN("with") || this.isN("assert")) && !this.nl) {
      this.next();
      this.parseObjectLike();
    }
    return node;
  }

  parseImport() {
    const line = this.ln;
    this.next();
    let typeOnly = false;
    if (this.isN("type") || this.isN("typeof")) {
      const [pk, pv] = this.peek();
      if ((pk === "name" && pv !== "from") || (pk === "p" && (pv === "{" || pv === "*"))) {
        this.next();
        typeOnly = true;
      }
    }
    if (this.t === "str") {
      const source = this.parseModuleSource();
      this.semicolon();
      return n("ImportDeclaration", line, { specifiers: [], source });
    }
    const specs = [];
    if (this.t === "name") {
      const local = this.ident();
      if (this.isP("=")) {
        this.next();
        return this.parseImportEquals(line, local, typeOnly);
      }
      specs.push(n("ImportDefaultSpecifier", local.line, { local }));
      if (!this.eatP(",")) {
        this.expectN("from");
        const source = this.parseModuleSource();
        this.semicolon();
        return n("ImportDeclaration", line, { specifiers: typeOnly ? [] : specs, source });
      }
    }
    if (this.isP("*")) {
      const sline = this.ln;
      this.next();
      this.expectN("as");
      specs.push(n("ImportNamespaceSpecifier", sline, { local: this.ident() }));
    } else if (this.isP("{")) {
      this.next();
      while (!this.isP("}")) {
        const sline = this.ln;
        const skip = this.typeModifierHere();
        let imported;
        if (this.t === "str") {
          imported = n("Literal", this.ln, { kind: "string", value: this.v });
          this.next();
        } else {
          imported = this.ident(true);
        }
        let local;
        if (this.eatN("as")) local = this.ident();
        else if (imported.type === "Identifier") local = n("Identifier", imported.line, { name: imported.name });
        else this.fail();
        if (!skip) specs.push(n("ImportSpecifier", sline, { imported, local }));
        if (!this.isP("}")) this.expectP(",");
      }
      this.next();
    } else {
      this.fail();
    }
    this.expectN("from");
    const source = this.parseModuleSource();
    this.semicolon();
    return n("ImportDeclaration", line, { specifiers: typeOnly ? [] : specs, source });
  }

  typeModifierHere() {
    if (!this.isN("type")) return false;
    const [pk, pv] = this.peek();
    if (pk === "str") {
      this.next();
      return true;
    }
    if (pk !== "name") return false;
    if (pv !== "as") {
      this.next();
      return true;
    }
    const ahead = () => {
      this.next();
      this.next();
      if (this.t === "name" && this.v === "as") return true;
      return this.t === "p" && (this.v === "," || this.v === "}");
    };
    if (this.look(ahead, 3)) {
      this.next();
      return true;
    }
    return false;
  }

  parseImportEquals(line, local, typeOnly) {
    if (this.isN("require")) {
      const [pk, pv] = this.peek();
      if (pk === "p" && pv === "(") {
        this.next();
        this.next();
        if (this.t !== "str") this.fail();
        const src = n("Literal", this.ln, { kind: "string", value: this.v });
        this.next();
        this.expectP(")");
        this.semicolon();
        if (typeOnly) return n("EmptyStatement", line, {});
        return n("TSImportEquals", line, { id: local, module: src, entity: null });
      }
    }
    let entity = this.ident(true);
    while (this.eatP(".")) {
      const property = this.ident(true);
      entity = n("MemberExpression", entity.line, { object: entity, property, computed: false, optional: false });
    }
    this.semicolon();
    if (typeOnly) return n("EmptyStatement", line, {});
    return n("TSImportEquals", line, { id: local, module: null, entity });
  }

  exportName() {
    if (this.t === "str") {
      const node = n("Literal", this.ln, { kind: "string", value: this.v });
      this.next();
      return node;
    }
    return this.ident(true);
  }

  parseExport(decorators) {
    const line = this.ln;
    this.next();
    if (this.isP("@")) decorators = decorators.concat(this.parseDecorators());
    if (this.isP("=")) {
      this.next();
      const expression = this.parseExpression();
      this.semicolon();
      return n("TSExportAssignment", line, { expression });
    }
    if (this.isN("as")) {
      this.next();
      this.expectN("namespace");
      this.ident(true);
      this.semicolon();
      return n("EmptyStatement", line, {});
    }
    if (this.isN("import") && this.peek()[0] === "name") {
      this.next();
      const local = this.ident();
      this.expectP("=");
      const node = this.parseImportEquals(line, local, false);
      if (node.type === "TSImportEquals") node.exported = true;
      return node;
    }
    if (this.isN("default")) {
      this.next();
      const [pk, pv, pnl] = this.peek();
      let decl;
      if (this.isN("function")) {
        decl = this.parseFunction(true, false, this.ln);
      } else if (this.isN("async") && pk === "name" && pv === "function" && !pnl) {
        const aline = this.ln;
        this.next();
        decl = this.parseFunction(true, true, aline);
      } else if (this.isN("class") || (this.isN("abstract") && pk === "name" && pv === "class")) {
        decl = this.parseClass(true, decorators);
      } else if (this.isP("@")) {
        decl = this.parseClass(true, decorators.concat(this.parseDecorators()));
      } else if (this.isN("interface") && pk === "name" && !pnl) {
        this.parseTsDeclaration(pk, pv, pnl);
        return n("EmptyStatement", line, {});
      } else {
        decl = this.parseMaybeAssign();
        this.semicolon();
      }
      if (decl === null) return n("EmptyStatement", line, {});
      return n("ExportDefaultDeclaration", line, { declaration: decl });
    }
    if (this.isP("*")) {
      this.next();
      let exported = null;
      if (this.eatN("as")) exported = this.exportName();
      this.expectN("from");
      const source = this.parseModuleSource();
      this.semicolon();
      return n("ExportAllDeclaration", line, { exported, source });
    }
    let typeOnly = false;
    if (this.isN("type")) {
      const [pk, pv] = this.peek();
      if (pk === "p" && (pv === "{" || pv === "*")) {
        this.next();
        typeOnly = true;
        if (this.isP("*")) {
          this.next();
          if (this.eatN("as")) this.exportName();
          this.expectN("from");
          this.parseModuleSource();
          this.semicolon();
          return n("EmptyStatement", line, {});
        }
      }
    }
    if (this.isP("{")) {
      this.next();
      const specs = [];
      while (!this.isP("}")) {
        const sline = this.ln;
        const skip = this.typeModifierHere();
        const local = this.exportName();
        const exported = this.eatN("as") ? this.exportName() : { ...local };
        if (!skip) specs.push(n("ExportSpecifier", sline, { local, exported }));
        if (!this.isP("}")) this.expectP(",");
      }
      this.next();
      const source = this.eatN("from") ? this.parseModuleSource() : null;
      this.semicolon();
      if (typeOnly) return n("EmptyStatement", line, {});
      return n("ExportNamedDeclaration", line, { declaration: null, specifiers: specs, source });
    }
    if (this.isP("@")) decorators = decorators.concat(this.parseDecorators());
    const [pk, pv] = this.peek();
    let decl;
    if (this.isN("class") || (this.isN("abstract") && pk === "name" && pv === "class")) decl = this.parseClass(true, decorators);
    else decl = this.parseStatement();
    if (decl === null || decl.type === "EmptyStatement") return n("EmptyStatement", line, {});
    if (!["VariableDeclaration", "FunctionDeclaration", "ClassDeclaration", "TSEnumDeclaration",
      "TSModuleDeclaration"].includes(decl.type)) this.fail("unexpected export", line);
    return n("ExportNamedDeclaration", line, { declaration: decl, specifiers: [], source: null });
  }

  // ---- TypeScript declarations ----
  parseTsDeclaration(pk, pv, pnl) {
    const line = this.ln;
    const v = this.v;
    if (v === "abstract") {
      if (pk === "name" && pv === "class" && !pnl) return this.parseClass(true, []);
      return false;
    }
    if (!this.ts && v !== "type" && v !== "interface" && v !== "declare") return false;
    if (v === "interface") {
      if (pk !== "name" || pnl) return false;
      this.next();
      this.ident(true);
      if (this.isP("<")) this.parseTypeParams();
      if (this.eatN("extends")) {
        this.parseType();
        while (this.eatP(",")) this.parseType();
      }
      this.parseObjectType();
      return n("EmptyStatement", line, {});
    }
    if (v === "type") {
      if (pk !== "name" || pnl) return false;
      this.next();
      this.ident(true);
      if (this.isP("<")) this.parseTypeParams();
      this.expectP("=");
      this.parseType();
      this.semicolon();
      return n("EmptyStatement", line, {});
    }
    if (v === "enum") {
      if (pk !== "name") return false;
      return this.parseEnum(line);
    }
    if (v === "declare") {
      if (pk !== "name" || pnl) return false;
      this.next();
      const saved = this.declaring;
      this.declaring = true;
      try {
        this.parseStatement();
      } finally {
        this.declaring = saved;
      }
      return n("EmptyStatement", line, {});
    }
    if (v === "namespace" || v === "module") {
      if (pnl || !(pk === "name" || (v === "module" && pk === "str"))) return false;
      this.next();
      if (this.t === "str") {
        this.next();
        if (this.isP("{")) this.parseBlock();
        else this.semicolon();
        return n("EmptyStatement", line, {});
      }
      const id = this.ident(true);
      while (this.eatP(".")) this.ident(true);
      if (!this.isP("{")) {
        this.semicolon();
        return n("EmptyStatement", line, {});
      }
      const body = this.parseBlock();
      return n("TSModuleDeclaration", line, { id, body });
    }
    if (v === "global") {
      if (pk === "p" && pv === "{") {
        this.next();
        this.parseBlock();
        return n("EmptyStatement", line, {});
      }
      return false;
    }
    return false;
  }

  parseEnum(line) {
    this.expectN("enum");
    const id = this.ident(true);
    this.expectP("{");
    const members = [];
    while (!this.isP("}")) {
      const mline = this.ln;
      let key;
      if (this.eatP("[")) {
        key = this.parseMaybeAssign();
        this.expectP("]");
      } else {
        key = this.parsePropertyName();
      }
      const initializer = this.eatP("=") ? this.parseMaybeAssign() : null;
      members.push(n("TSEnumMember", mline, { id: key, initializer }));
      if (!this.isP("}")) this.expectP(",");
    }
    this.next();
    return n("TSEnumDeclaration", line, { id, members });
  }

  // ---- TypeScript types (read and left out) ----
  parseType() {
    this.enter();
    if (this.functionTypeAhead()) {
      this.parseFunctionType();
    } else {
      this.parseUnionType();
      if (this.isN("extends") && !this.nl && !this.noConditional) {
        this.next();
        const saved = this.noConditional;
        this.noConditional = true;
        this.parseType();
        this.noConditional = false;
        this.expectP("?");
        this.parseType();
        this.expectP(":");
        this.parseType();
        this.noConditional = saved;
      }
    }
    this.depth -= 1;
  }

  parseReturnType() {
    this.expectP(":");
    const outer = this.noConditional;
    this.noConditional = false;
    this.parseTypeOrPredicate();
    this.noConditional = outer;
  }

  parseTypeOrPredicate() {
    if (this.t === "name") {
      const [pk, pv, pnl] = this.peek();
      if (this.isN("asserts") && pk === "name" && !pnl) {
        this.next();
        this.next();
        if (this.eatN("is")) this.parseType();
        return;
      }
      if (pk === "name" && pv === "is" && !pnl) {
        this.next();
        this.next();
        this.parseType();
        return;
      }
    }
    this.parseType();
  }

  functionTypeAhead() {
    if (this.isP("<")) return true;
    if (this.isN("new")) return true;
    if (this.isN("abstract")) {
      const [pk, pv] = this.peek();
      return pk === "name" && pv === "new";
    }
    if (!this.isP("(")) return false;
    return this.look(() => {
      this.next();
      if (this.t === "p" && (this.v === ")" || this.v === "...")) return true;
      if (this.skipParamStart()) {
        if (this.t === "p" && [":", ",", "?", "="].includes(this.v)) return true;
        if (this.isP(")")) {
          this.next();
          return this.isP("=>");
        }
      }
      return false;
    }, 256);
  }

  skipParamStart() {
    if (this.t === "name") {
      this.next();
      return true;
    }
    if (this.t === "p" && (this.v === "[" || this.v === "{")) {
      let depth = 0;
      while (this.t !== "eof") {
        if (this.t === "p" && (this.v === "[" || this.v === "{" || this.v === "(")) depth += 1;
        else if (this.t === "p" && (this.v === "]" || this.v === "}" || this.v === ")")) {
          depth -= 1;
          if (depth === 0) {
            this.next();
            return true;
          }
        }
        this.next();
      }
    }
    return false;
  }

  parseFunctionType() {
    this.eatN("abstract");
    this.eatN("new");
    if (this.isP("<")) this.parseTypeParams();
    const saved = this.functionContext(false, false);
    try {
      this.parseParams();
    } finally {
      this.restoreContext(saved);
    }
    this.expectP("=>");
    const outer = this.noConditional;
    this.noConditional = false;
    this.parseTypeOrPredicate();
    this.noConditional = outer;
  }

  parseUnionType() {
    this.eatP("|");
    this.parseIntersectionType();
    while (this.eatP("|")) this.parseIntersectionType();
  }

  parseIntersectionType() {
    this.eatP("&");
    this.parseTypeOperator();
    while (this.eatP("&")) this.parseTypeOperator();
  }

  parseTypeOperator() {
    this.enter();
    if (this.t === "name" && !this.esc && (this.v === "keyof" || this.v === "unique" || this.v === "readonly")) {
      const [pk, pv] = this.peek();
      if (["name", "str", "num", "tmpl"].includes(pk) || (pk === "p" && ["(", "[", "{", "-"].includes(pv))) {
        this.next();
        this.parseTypeOperator();
        this.depth -= 1;
        return;
      }
    }
    if (this.isN("infer")) {
      this.next();
      this.ident(true);
      if (this.isN("extends")) {
        const outer = this.noConditional;
        const st = this.save();
        this.next();
        this.noConditional = true;
        let keep;
        try {
          this.parseType();
          keep = outer || !this.isP("?");
        } catch (e) {
          if (!(e instanceof JsSyntaxError)) throw e;
          keep = false;
        }
        this.noConditional = outer;
        if (!keep) {
          const spent = this.specBudget;
          this.restore(st);
          if (this.spec) this.specBudget = spent;
        }
      }
      this.depth -= 1;
      return;
    }
    const outer = this.noConditional;
    this.noConditional = false;
    if (this.functionTypeAhead()) {
      this.parseFunctionType();
    } else {
      this.parsePrimaryType();
      while (!this.nl) {
        if (this.isP("[")) {
          this.next();
          if (!this.isP("]")) this.parseType();
          this.expectP("]");
        } else if (this.isP("!")) {
          this.next();
        } else {
          break;
        }
      }
    }
    this.noConditional = outer;
    this.depth -= 1;
  }

  parseEntityName() {
    this.ident(true);
    while (this.isP(".")) {
      this.next();
      if (this.t === "priv") this.next();
      else this.ident(true);
    }
  }

  parsePrimaryType() {
    const { t, v } = this;
    if (t === "name") {
      if (!this.esc) {
        if (v === "typeof") {
          this.next();
          if (this.isN("import")) this.parseImportType();
          else this.parseEntityName();
          if (this.isP("<") && !this.nl) this.parseTypeArgs();
          return;
        }
        if (v === "import") {
          this.parseImportType();
          return;
        }
      }
      this.parseEntityName();
      if (this.isP("<") && !this.nl) this.parseTypeArgs();
      return;
    }
    if (t === "str" || t === "num" || t === "bigint") {
      this.next();
      return;
    }
    if (t === "tmpl") {
      while (!this.v[1]) {
        this.next();
        this.parseType();
        this.rescanTemplateContinuation();
      }
      this.next();
      return;
    }
    if (t === "p") {
      if (v === "-") {
        this.next();
        if (this.t !== "num" && this.t !== "bigint") this.fail();
        this.next();
        return;
      }
      if (v === "{") {
        if (this.mappedTypeAhead()) this.parseMappedType();
        else this.parseObjectType();
        return;
      }
      if (v === "[") {
        this.parseTupleType();
        return;
      }
      if (v === "(") {
        this.next();
        this.parseType();
        this.expectP(")");
        return;
      }
      if (v === "*") {
        this.next();
        return;
      }
      if (v === "?") {
        this.next();
        this.parsePrimaryType();
        return;
      }
    }
    this.fail();
  }

  parseImportType() {
    this.expectN("import");
    this.expectP("(");
    if (this.t !== "str") this.fail();
    this.next();
    if (this.eatP(",") && !this.isP(")")) {
      this.parseObjectLike();
      this.eatP(",");
    }
    this.expectP(")");
    while (this.eatP(".")) this.ident(true);
    if (this.isP("<") && !this.nl) this.parseTypeArgs();
  }

  parseTupleType() {
    this.expectP("[");
    while (!this.isP("]")) {
      this.eatP("...");
      let labeled = false;
      if (this.t === "name") {
        const [pk, pv] = this.peek();
        labeled = pk === "p" && (pv === ":" || (pv === "?" && this.look(() => this.labeledOptionalAhead(), 3)));
      }
      if (labeled) {
        this.next();
        this.eatP("?");
        this.expectP(":");
      }
      this.parseType();
      this.eatP("?");
      if (!this.isP("]")) this.expectP(",");
    }
    this.next();
  }

  labeledOptionalAhead() {
    this.next();
    this.next();
    return this.isP(":");
  }

  mappedTypeAhead() {
    return this.look(() => {
      this.next();
      if (this.isP("+") || this.isP("-")) {
        this.next();
        return this.isN("readonly");
      }
      if (this.isN("readonly")) this.next();
      if (!this.isP("[")) return false;
      this.next();
      if (this.t !== "name") return false;
      this.next();
      return this.isN("in");
    }, 6);
  }

  parseMappedType() {
    this.expectP("{");
    if (this.isP("+") || this.isP("-")) this.next();
    this.eatN("readonly");
    this.expectP("[");
    this.ident(true);
    this.expectN("in");
    this.parseType();
    if (this.eatN("as")) this.parseType();
    this.expectP("]");
    if (this.isP("+") || this.isP("-")) {
      this.next();
      this.expectP("?");
    } else {
      this.eatP("?");
    }
    if (this.eatP(":")) this.parseType();
    if (!this.eatP(";")) this.eatP(",");
    this.expectP("}");
  }

  parseObjectType() {
    this.expectP("{");
    while (!this.isP("}")) {
      if (this.t === "eof") this.fail();
      this.enter();
      this.parseTypeMember();
      this.depth -= 1;
      if (!(this.eatP(";") || this.eatP(","))) {
        if (!(this.isP("}") || this.nl)) this.fail();
      }
    }
    this.next();
  }

  parseSignatureRest() {
    if (this.isP("<")) this.parseTypeParams();
    const saved = this.functionContext(false, false);
    try {
      this.parseParams();
    } finally {
      this.restoreContext(saved);
    }
    if (this.isP(":")) this.parseReturnType();
  }

  parseTypeMember() {
    if (this.isP("(") || this.isP("<")) {
      this.parseSignatureRest();
      return;
    }
    if (this.isN("new")) {
      const [pk, pv] = this.peek();
      if (pk === "p" && (pv === "(" || pv === "<")) {
        this.next();
        this.parseSignatureRest();
        return;
      }
    }
    while (this.t === "name" && (this.v === "readonly" || this.v === "get" || this.v === "set") && !this.esc) {
      const [pk, pv] = this.peek();
      if (pk === "name" || pk === "str" || pk === "num" || (pk === "p" && pv === "[")) this.next();
      else break;
    }
    if (this.isP("[")) {
      if (this.indexSignatureAhead()) {
        this.parseIndexSignature();
        return;
      }
      this.next();
      this.parseMaybeAssign();
      this.expectP("]");
    } else {
      this.parsePropertyName();
    }
    this.eatP("?");
    if (this.isP("(") || this.isP("<")) {
      this.parseSignatureRest();
      return;
    }
    if (this.eatP(":")) this.parseType();
  }

  parseTypeParams() {
    this.expectP("<");
    while (!this.isP(">")) {
      while (this.t === "name" && (this.v === "in" || this.v === "out" || this.v === "const") && this.peek()[0] === "name") {
        this.next();
      }
      this.ident(true);
      if (this.eatN("extends")) this.parseType();
      if (this.eatP("=")) this.parseType();
      if (!this.isP(">")) this.expectP(",");
    }
    this.next();
  }

  parseTypeArgs() {
    this.expectP("<");
    while (!this.isP(">")) {
      this.parseType();
      if (!this.isP(">")) this.expectP(",");
    }
    this.next();
    return true;
  }

  // ---- expressions ----
  parseExpression(noIn = false) {
    const line = this.ln;
    const expr = this.parseMaybeAssign(noIn);
    if (this.isP(",")) {
      const expressions = [expr];
      while (this.eatP(",")) expressions.push(this.parseMaybeAssign(noIn));
      return n("SequenceExpression", line, { expressions });
    }
    return expr;
  }

  parseMaybeAssign(noIn = false, retOk = true) {
    this.enter();
    const saved = this.retOk;
    this.retOk = retOk;
    const expr = this.parseMaybeAssignInner(noIn);
    this.retOk = saved;
    this.depth -= 1;
    return expr;
  }

  parseMaybeAssignInner(noIn) {
    const { t, v } = this;
    const line = this.ln;
    if (t === "name" && !this.esc) {
      if (v === "yield" && this.inGen) {
        this.next();
        let delegate = false, argument = null;
        if (!this.nl) {
          delegate = this.eatP("*");
          if (delegate || this.startsExpression()) argument = this.parseMaybeAssign(noIn);
        }
        return n("YieldExpression", line, { argument, delegate });
      }
      const [pk, pv, pnl] = this.peek();
      if (pk === "p" && pv === "=>" && !pnl && !RESERVED.has(v)) return this.parseArrowRest([this.ident()], false, line);
      if (v === "async" && !pnl) {
        if (pk === "name" && !RESERVED.has(pv)) {
          const st = this.save();
          this.next();
          const param = this.ident();
          if (this.isP("=>") && !this.nl) return this.parseArrowRest([param], true, line);
          this.restore(st);
        } else if (this.ts && pk === "p" && pv === "<") {
          const node = this.speculate(() => this.parseGenericArrow(true, line));
          if (node !== null) return node;
        }
      }
    } else if (t === "p" && v === "<" && this.ts) {
      const node = this.speculate(() => this.parseGenericArrow(false, line));
      if (node !== null) return node;
    }
    const left = this.parseMaybeConditional(noIn);
    if (this.t === "p") {
      let op = this.v;
      if (op === ">") {
        op = this.gtOp();
        if (op === ">>=" || op === ">>>=") this.takeGt();
      }
      if (ASSIGN_OPS.has(op)) {
        const target = op === "=" ? this.toPattern(left, false) : this.simpleTarget(left);
        this.next();
        const right = this.parseMaybeAssign(noIn);
        return n("AssignmentExpression", line, { operator: op, left: target, right });
      }
    }
    return left;
  }

  simpleTarget(node) {
    if (node.type === "Identifier" || node.type === "MemberExpression") return node;
    this.fail("invalid assignment target", node.line);
  }

  startsExpression() {
    const t = this.t;
    if (["name", "num", "bigint", "str", "tmpl", "priv", "regex"].includes(t)) return true;
    return t === "p" && EXPR_START_PUNCT.has(this.v);
  }

  parseGenericArrow(isAsync, line) {
    if (isAsync) this.next();
    this.parseTypeParams();
    if (!this.isP("(")) throw new Backtrack();
    const saved = this.functionContext(isAsync, false);
    let params;
    try {
      params = this.parseParams();
    } finally {
      this.restoreContext(saved);
    }
    if (this.isP(":")) this.parseReturnType();
    if (!this.isP("=>") || this.nl) throw new Backtrack();
    return this.parseArrowRest(params, isAsync, line);
  }

  parseArrowRest(params, isAsync, line) {
    if (this.nl || !this.isP("=>")) this.fail();
    this.next();
    const saved = this.functionContext(isAsync, false);
    let body, expression;
    try {
      if (this.isP("{")) {
        body = this.parseBlock();
        expression = false;
      } else {
        body = this.parseMaybeAssign();
        expression = true;
      }
    } finally {
      this.restoreContext(saved);
    }
    return n("ArrowFunctionExpression", line, { id: null, params, body, expression, generator: false, async: isAsync });
  }

  parseMaybeConditional(noIn) {
    const line = this.ln;
    const expr = this.parseExprOps(noIn);
    if (this.isP("?")) {
      this.next();
      const consequent = this.parseMaybeAssign(false, false);
      this.expectP(":");
      const alternate = this.parseMaybeAssign(noIn);
      return n("ConditionalExpression", line, { test: expr, consequent, alternate });
    }
    return expr;
  }

  binaryOp(noIn) {
    const { t, v } = this;
    if (t === "p") {
      if (v === ">") {
        const op = this.gtOp();
        if (op === ">>=" || op === ">>>=") return [null, 0];
        return [op, BINARY_PREC.get(op)];
      }
      const prec = BINARY_PREC.get(v);
      if (prec !== undefined) return [v, prec];
      return [null, 0];
    }
    if (t === "name" && !this.esc) {
      if (v === "instanceof" || (v === "in" && !noIn)) return [v, 7];
      if ((v === "as" || v === "satisfies") && this.ts && !this.nl) return [v, 7];
    }
    return [null, 0];
  }

  parseExprOps(noIn) {
    const line = this.ln;
    const left = this.parseMaybeUnary();
    if (left.type === "ArrowFunctionExpression" && !(this.pt === "p" && this.pv === ")")) return left;
    let [op, prec] = this.binaryOp(noIn);
    if (op === null) return left;
    const operands = [[left, line]];
    const ops = [];
    while (op !== null) {
      if (op === "as" || op === "satisfies") {
        while (ops.length && ops[ops.length - 1][1] >= prec) reduce(operands, ops);
        this.next();
        if (this.isN("const")) this.next();
        else this.parseType();
        [op, prec] = this.binaryOp(noIn);
        continue;
      }
      while (ops.length && (ops[ops.length - 1][1] > prec || (ops[ops.length - 1][1] === prec && op !== "**"))) {
        reduce(operands, ops);
      }
      if (this.v === ">") this.takeGt();
      ops.push([op, prec]);
      this.next();
      const oline = this.ln;
      operands.push([this.parseMaybeUnary(), oline]);
      [op, prec] = this.binaryOp(noIn);
    }
    while (ops.length) reduce(operands, ops);
    return operands[0][0];
  }

  parseMaybeUnary() {
    const prefix = [];
    const line = this.ln;
    for (;;) {
      const { t, v } = this;
      if (t === "p" && ["!", "~", "+", "-", "++", "--"].includes(v)) {
        prefix.push([v === "++" || v === "--" ? "UpdateExpression" : "UnaryExpression", v, this.ln]);
        this.next();
      } else if (t === "name" && !this.esc && UNARY_WORDS.has(v)) {
        prefix.push(["UnaryExpression", v, this.ln]);
        this.next();
      } else if (t === "name" && !this.esc && v === "await" && this.awaitHere()) {
        prefix.push(["AwaitExpression", v, this.ln]);
        this.next();
      } else if (t === "p" && v === "<" && this.ts && !this.jsx) {
        this.next();
        this.parseType();
        this.expectP(">");
      } else {
        break;
      }
      if (prefix.length > MAX_DEPTH) this.fail("nesting too deep");
    }
    const oline = prefix.length ? this.ln : line;
    let expr = this.parseExprSubscripts();
    if (this.t === "p" && (this.v === "++" || this.v === "--") && !this.nl) {
      expr = n("UpdateExpression", oline, { operator: this.v, prefix: false, argument: this.simpleTarget(expr) });
      this.next();
    }
    for (let i = prefix.length - 1; i >= 0; i--) {
      const [type, op, pline] = prefix[i];
      if (type === "AwaitExpression") expr = n("AwaitExpression", pline, { argument: expr });
      else if (type === "UpdateExpression") expr = n("UpdateExpression", pline, { operator: op, prefix: true, argument: this.simpleTarget(expr) });
      else expr = n("UnaryExpression", pline, { operator: op, prefix: true, argument: expr });
    }
    return expr;
  }

  awaitHere() {
    if (this.inAsync) return true;
    if (this.inFunc) return false;
    const [pk, pv, pnl] = this.peek();
    if (pnl) return false;
    if (["name", "num", "bigint", "str", "tmpl", "priv"].includes(pk)) {
      return !["in", "of", "instanceof", "as", "satisfies"].includes(pv);
    }
    return pk === "p" && ["(", "[", "{", "!", "~", "+", "-", "++", "--", "/", "/="].includes(pv);
  }

  parseExprSubscripts() {
    const line = this.ln;
    const expr = this.parseExprAtom();
    if (expr.type === "ArrowFunctionExpression" && !(this.pt === "p" && this.pv === ")")) return expr;
    return this.parseSubscripts(expr, line);
  }

  parseSubscripts(expr, line) {
    let chained = false;
    for (;;) {
      const { t, v } = this;
      if (t === "p") {
        if (v === ".") {
          this.next();
          const property = this.t === "priv" ? this.parsePropertyName() : this.ident(true);
          expr = n("MemberExpression", line, { object: expr, property, computed: false, optional: false });
          continue;
        }
        if (v === "?.") {
          chained = true;
          this.next();
          if (this.isP("(")) {
            expr = n("CallExpression", line, { callee: expr, arguments: this.parseArguments(), optional: true });
          } else if (this.isP("[")) {
            this.next();
            const property = this.parseExpression();
            this.expectP("]");
            expr = n("MemberExpression", line, { object: expr, property, computed: true, optional: true });
          } else if (this.isP("<") && this.ts) {
            this.parseTypeArgs();
            expr = n("CallExpression", line, { callee: expr, arguments: this.parseArguments(), optional: true });
          } else {
            const property = this.t === "priv" ? this.parsePropertyName() : this.ident(true);
            expr = n("MemberExpression", line, { object: expr, property, computed: false, optional: true });
          }
          continue;
        }
        if (v === "[") {
          this.next();
          const property = this.parseExpression();
          this.expectP("]");
          expr = n("MemberExpression", line, { object: expr, property, computed: true, optional: false });
          continue;
        }
        if (v === "(") {
          expr = n("CallExpression", line, { callee: expr, arguments: this.parseArguments(), optional: false });
          continue;
        }
        if (v === "!" && this.ts && !this.nl) {
          this.next();
          continue;
        }
        if (v === "<" && this.ts && !this.nl) {
          if (this.speculate(() => this.parseTypeArgsInExpression()) !== null) {
            if (this.isP("(")) {
              expr = n("CallExpression", line, { callee: expr, arguments: this.parseArguments(), optional: false });
            }
            continue;
          }
        }
        break;
      }
      if (t === "tmpl") {
        if (chained) this.fail("tagged template in an optional chain");
        expr = n("TaggedTemplateExpression", line, { tag: expr, quasi: this.parseTemplate() });
        continue;
      }
      break;
    }
    if (chained) expr = n("ChainExpression", line, { expression: expr });
    return expr;
  }

  parseTypeArgsInExpression() {
    this.parseTypeArgs();
    const { t, v } = this;
    if (t === "tmpl" || (t === "p" && v === "(")) return true;
    if (t === "p" && ["<", ">", "+", "-"].includes(v)) throw new Backtrack();
    if (this.nl || this.binaryOp(false)[0] !== null || !this.startsExpression()) return true;
    throw new Backtrack();
  }

  parseArguments() {
    this.expectP("(");
    const args = [];
    while (!this.isP(")")) {
      if (this.isP("...")) {
        const line = this.ln;
        this.next();
        args.push(n("SpreadElement", line, { argument: this.parseMaybeAssign() }));
      } else {
        args.push(this.parseMaybeAssign());
      }
      if (!this.isP(")")) this.expectP(",");
    }
    this.next();
    return args;
  }

  parseTemplate() {
    const line = this.ln;
    const quasis = [];
    const expressions = [];
    for (;;) {
      const [raw, tail] = this.v;
      quasis.push(n("TemplateElement", this.ln, { raw, tail }));
      this.next();
      if (tail) break;
      expressions.push(this.parseExpression());
      this.rescanTemplateContinuation();
    }
    return n("TemplateLiteral", line, { quasis, expressions });
  }

  parseExprAtom() {
    this.enter();
    const expr = this.parseExprAtomInner();
    this.depth -= 1;
    return expr;
  }

  parseExprAtomInner() {
    const { t, v } = this;
    const line = this.ln;
    if (t === "name") {
      if (!this.esc) {
        if (v === "function") return this.parseFunction(false, false, line);
        if (v === "async") {
          const [pk, pv, pnl] = this.peek();
          if (pk === "name" && pv === "function" && !pnl) {
            this.next();
            return this.parseFunction(false, true, line);
          }
          if (pk === "p" && pv === "(" && !pnl) return this.parseAsyncCallOrArrow(line);
        }
        if (v === "class" || (v === "abstract" && this.peek()[1] === "class")) return this.parseClass(false, []);
        if (v === "new") return this.parseNew();
        if (v === "this") {
          this.next();
          return n("ThisExpression", line, {});
        }
        if (v === "super") {
          this.next();
          return n("Super", line, {});
        }
        if (v === "null") {
          this.next();
          return n("Literal", line, { kind: "null", value: null });
        }
        if (v === "true" || v === "false") {
          this.next();
          return n("Literal", line, { kind: "boolean", value: v === "true" });
        }
        if (v === "import") {
          this.next();
          if (this.eatP(".")) {
            return n("MetaProperty", line, { meta: n("Identifier", line, { name: "import" }), property: this.ident(true) });
          }
          this.expectP("(");
          const source = this.parseMaybeAssign();
          let options = null;
          if (this.eatP(",") && !this.isP(")")) {
            options = this.parseMaybeAssign();
            this.eatP(",");
          }
          this.expectP(")");
          return n("ImportExpression", line, { source, options });
        }
        if (RESERVED.has(v)) this.fail();
      }
      return this.ident(true);
    }
    if (t === "num" || t === "bigint") {
      this.next();
      return n("Literal", line, { kind: t === "num" ? "number" : "bigint", value: v });
    }
    if (t === "str") {
      this.next();
      return n("Literal", line, { kind: "string", value: v });
    }
    if (t === "tmpl") return this.parseTemplate();
    if (t === "priv") {
      this.next();
      return n("PrivateIdentifier", line, { name: v });
    }
    if (t === "p") {
      if (v === "(") return this.parseParenOrArrow();
      if (v === "[") return this.parseArrayLiteral();
      if (v === "{") return this.parseObjectLike();
      if (v === "/" || v === "/=") {
        this.rescanRegex();
        const [pattern, flags] = this.v;
        this.next();
        return n("Literal", line, { kind: "regex", value: pattern, flags });
      }
      if (v === "<" && this.jsx) {
        this.enter();
        this.jsxTagNext();
        const node = this.parseJsxElement(line, "expr");
        this.depth -= 1;
        return node;
      }
      if (v === "@") return this.parseClass(false, this.parseDecorators());
    }
    this.fail();
  }

  parseNew() {
    const line = this.ln;
    this.next();
    if (this.eatP(".")) {
      return n("MetaProperty", line, { meta: n("Identifier", line, { name: "new" }), property: this.ident(true) });
    }
    this.enter();
    const cline = this.ln;
    let callee = this.isN("new") ? this.parseNew() : this.parseExprAtom();
    for (;;) {
      if (this.isP(".")) {
        this.next();
        const property = this.t === "priv" ? this.parsePropertyName() : this.ident(true);
        callee = n("MemberExpression", cline, { object: callee, property, computed: false, optional: false });
      } else if (this.isP("[")) {
        this.next();
        const property = this.parseExpression();
        this.expectP("]");
        callee = n("MemberExpression", cline, { object: callee, property, computed: true, optional: false });
      } else if (this.t === "tmpl") {
        callee = n("TaggedTemplateExpression", cline, { tag: callee, quasi: this.parseTemplate() });
      } else if (this.ts && this.isP("!") && !this.nl) {
        this.next();
      } else {
        break;
      }
    }
    if (this.ts && this.isP("<")) this.speculate(() => this.parseTypeArgs());
    const args = this.isP("(") ? this.parseArguments() : [];
    this.depth -= 1;
    return n("NewExpression", line, { callee, arguments: args });
  }

  parseAsyncCallOrArrow(line) {
    const callee = this.ident(true);
    const items = this.parseParenItems();
    if (this.isP("=>") && !this.nl) return this.parseArrowRest(this.itemsToParams(items), true, line);
    if (this.isP(":") && !this.nl && this.arrowReturnTypeAhead(items)) {
      return this.parseArrowRest(this.itemsToParams(items), true, line);
    }
    if (items.typed) this.fail();
    const args = [];
    for (const item of items.list) {
      let node = item.node;
      if (item.rest) node = n("SpreadElement", node.line, { argument: node.argument });
      args.push(node);
    }
    return this.parseSubscripts(n("CallExpression", line, { callee, arguments: args, optional: false }), line);
  }

  parseParenOrArrow() {
    const line = this.ln;
    const items = this.parseParenItems();
    if (this.isP("=>") && !this.nl) return this.parseArrowRest(this.itemsToParams(items), false, line);
    if (this.isP(":") && !this.nl && this.arrowReturnTypeAhead(items)) {
      return this.parseArrowRest(this.itemsToParams(items), false, line);
    }
    if (items.trailing || !items.list.length || items.list[items.list.length - 1].rest) this.fail();
    if (items.typed && !(items.list.length === 1 && items.cast)) this.fail();
    const exprs = items.list.map((item) => item.node);
    if (exprs.length === 1) return exprs[0];
    return n("SequenceExpression", items.line, { expressions: exprs });
  }

  arrowReturnTypeAhead(items) {
    if (!this.retOk || !items.list.every((item) => item.rest || paramOk(item.node))) return false;
    return this.speculate(() => {
      this.parseReturnType();
      if (!this.isP("=>") || this.nl) throw new Backtrack();
      return true;
    }) !== null;
  }

  parseParenItems() {
    this.expectP("(");
    const out = { list: [], typed: false, trailing: false, cast: false, line: 0 };
    while (!this.isP(")")) {
      const line = this.ln;
      if (this.isP("...")) {
        this.next();
        const target = this.t !== "name" || [")", ",", ":", "?", "="].includes(this.peek()[1])
          ? this.parseBindingTarget() : this.parseMaybeAssign();
        this.eatP("?");
        if (this.eatP(":")) {
          this.parseType();
          out.typed = true;
        }
        if (this.eatP("=")) {
          this.parseMaybeAssign();
          out.typed = true;
        }
        out.list.push({ rest: true, node: n("RestElement", line, { argument: target }) });
        if (!this.isP(")")) this.expectP(",");
        continue;
      }
      if (this.isP("@")) {
        this.parseDecorators();
        out.typed = true;
      }
      while (this.t === "name" && PARAM_MODIFIERS.has(this.v) && !this.esc && this.peek()[0] === "name") {
        this.next();
        out.typed = true;
      }
      if (this.isN("this")) {
        const [pk, pv] = this.peek();
        if (pk === "p" && pv === ":") {
          this.next();
          this.next();
          this.parseType();
          out.typed = true;
          if (!this.isP(")")) this.expectP(",");
          continue;
        }
      }
      if (!out.list.length) out.line = this.ln;
      let typed = false, node;
      if (this.t === "name" && this.peek()[1] === "?" && this.look(() => this.optionalParamAhead(), 2)) {
        node = this.ident();
        this.next();
        typed = true;
      } else {
        node = this.parseMaybeAssign();
      }
      if (this.eatP(":")) {
        this.parseType();
        if (!typed) out.cast = true;
        typed = true;
      }
      if (typed) {
        out.typed = true;
        if (this.eatP("=")) {
          node = n("AssignmentExpression", node.line, { operator: "=", left: node, right: this.parseMaybeAssign() });
        }
      }
      out.list.push({ rest: false, node });
      if (!this.isP(")")) {
        this.expectP(",");
        if (this.isP(")")) out.trailing = true;
      }
    }
    this.next();
    return out;
  }

  optionalParamAhead() {
    this.next();
    if (!this.isP("?")) return false;
    this.next();
    return this.t === "p" && [":", ",", ")", "="].includes(this.v);
  }

  itemsToParams(items) {
    return items.list.map((item) => (item.rest ? item.node : this.toPattern(item.node, true)));
  }

  toPattern(node, binding) {
    const t = node.type;
    if (t === "Identifier" || ["ObjectPattern", "ArrayPattern", "AssignmentPattern", "RestElement"].includes(t)) return node;
    if (t === "MemberExpression" && !binding) return node;
    if (t === "ObjectExpression") {
      const properties = [];
      for (const p of node.properties) {
        if (p.type === "SpreadElement") {
          properties.push(n("RestElement", p.line, { argument: this.toPattern(p.argument, binding) }));
          continue;
        }
        if (p.kind !== "init" || p.method) this.fail("invalid destructuring target", p.line);
        let value = this.toPattern(p.value, binding);
        if (Object.hasOwn(p, "_cover")) {
          value = n("AssignmentPattern", p.line, { left: value, right: p._cover });
          delete p._cover;
        }
        properties.push(n("Property", p.line, { key: p.key, value, kind: "init", method: false, shorthand: p.shorthand,
          computed: p.computed }));
      }
      return n("ObjectPattern", node.line, { properties });
    }
    if (t === "ArrayExpression") {
      const elements = [];
      for (const el of node.elements) {
        if (el === null) elements.push(null);
        else if (el.type === "SpreadElement") elements.push(n("RestElement", el.line, { argument: this.toPattern(el.argument, binding) }));
        else elements.push(this.toPattern(el, binding));
      }
      return n("ArrayPattern", node.line, { elements });
    }
    if (t === "AssignmentExpression" && node.operator === "=") {
      return n("AssignmentPattern", node.line, { left: this.toPattern(node.left, binding), right: node.right });
    }
    this.fail("invalid destructuring target", node.line);
  }

  parseArrayLiteral() {
    const line = this.ln;
    this.next();
    const elements = [];
    while (!this.isP("]")) {
      if (this.isP(",")) {
        this.next();
        elements.push(null);
        continue;
      }
      if (this.isP("...")) {
        const sline = this.ln;
        this.next();
        elements.push(n("SpreadElement", sline, { argument: this.parseMaybeAssign() }));
      } else {
        elements.push(this.parseMaybeAssign());
      }
      if (!this.isP("]")) this.expectP(",");
    }
    this.next();
    return n("ArrayExpression", line, { elements });
  }

  parseObjectLike() {
    const line = this.ln;
    this.expectP("{");
    const properties = [];
    while (!this.isP("}")) {
      this.enter();
      properties.push(this.parseObjectMember());
      this.depth -= 1;
      if (!this.isP("}")) this.expectP(",");
    }
    this.next();
    return n("ObjectExpression", line, { properties });
  }

  parseObjectMember() {
    const line = this.ln;
    if (this.isP("...")) {
      this.next();
      return n("SpreadElement", line, { argument: this.parseMaybeAssign() });
    }
    let isAsync = false;
    let kind = "init";
    if (this.t === "name" && !this.esc && (this.v === "async" || this.v === "get" || this.v === "set")) {
      const [pk, pv, pnl] = this.peek();
      if ((KEY_KINDS.has(pk) || (pk === "p" && (pv === "[" || pv === "*"))) && !(this.v === "async" && pnl)) {
        if (this.v === "async") isAsync = true;
        else kind = this.v;
        this.next();
      }
    }
    const gen = this.eatP("*");
    let computed = false, key;
    if (this.isP("[")) {
      this.next();
      key = this.parseMaybeAssign();
      this.expectP("]");
      computed = true;
    } else {
      key = this.parsePropertyName();
    }
    if (this.isP("(") || this.isP("<")) {
      if (this.isP("<")) this.parseTypeParams();
      const fn = this.parseMethod(isAsync, gen);
      if (fn === null) this.fail();
      return n("Property", line, { key, value: fn, kind, method: kind === "init", shorthand: false, computed });
    }
    if (isAsync || gen || kind !== "init") this.fail();
    if (this.eatP(":")) {
      return n("Property", line, { key, value: this.parseMaybeAssign(), kind: "init", method: false, shorthand: false, computed });
    }
    if (computed || key.type !== "Identifier") this.fail();
    const node = n("Property", line, { key, value: n("Identifier", key.line, { name: key.name }), kind: "init",
      method: false, shorthand: true, computed: false });
    if (this.isP("=")) {
      this.next();
      node._cover = this.parseMaybeAssign();
      this.covers.push(node);
    }
    return node;
  }

  // ---- JSX ----
  jsxTagNext() {
    const src = this.src;
    const b = this.skip(this.e);
    if (b >= this.n) {
      this.t = "eof"; this.v = ""; this.e = b;
      return;
    }
    const c = src[b];
    if (c === "'" || c === '"') {
      const m = match(JSX_STR_RE[c], src, b);
      if (m === null) this.fail("unterminated string");
      this.t = "str"; this.v = m[0].slice(1, -1); this.e = b + m[0].length;
      return;
    }
    const m = match(JSX_NAME_RE, src, b);
    if (m !== null) {
      this.t = "name"; this.v = m[0]; this.e = b + m[0].length;
      return;
    }
    if ("<>/{}=.:".includes(c)) {
      this.t = "p"; this.v = c; this.e = b + 1;
      return;
    }
    this.fail("unexpected character " + quote(String.fromCodePoint(src.codePointAt(b))));
  }

  jsxTextNext() {
    const pos = this.e;
    this.s = pos;
    this.ln = this.lineAt(pos);
    this.nl = false;
    this.esc = false;
    if (pos >= this.n) {
      this.t = "eof"; this.v = ""; this.e = pos;
      return;
    }
    const c = this.src[pos];
    if (c === "{" || c === "<") {
      this.t = "p"; this.v = c; this.e = pos + 1;
      return;
    }
    const m = match(JSX_TEXT_RE, this.src, pos);
    this.t = "jsxtext"; this.v = m[0]; this.e = pos + m[0].length;
  }

  parseJsxName() {
    const line = this.ln;
    if (this.t !== "name") this.fail();
    let name = n("JSXIdentifier", line, { name: this.v });
    this.jsxTagNext();
    if (this.isP(":")) {
      this.jsxTagNext();
      if (this.t !== "name") this.fail();
      const local = n("JSXIdentifier", this.ln, { name: this.v });
      this.jsxTagNext();
      return n("JSXNamespacedName", line, { namespace: name, name: local });
    }
    while (this.isP(".")) {
      this.jsxTagNext();
      if (this.t !== "name") this.fail();
      const property = n("JSXIdentifier", this.ln, { name: this.v });
      this.jsxTagNext();
      name = n("JSXMemberExpression", line, { object: name, property });
    }
    return name;
  }

  jsxEnd(where) {
    if (where === "expr") this.next();
    else if (where === "attr") this.jsxTagNext();
  }

  parseJsxElement(line, where) {
    if (this.isP(">")) {
      const children = this.parseJsxChildren();
      this.jsxTagNext();
      if (!this.isP(">")) this.fail();
      this.jsxEnd(where);
      return n("JSXFragment", line, { children });
    }
    const name = this.parseJsxName();
    if (this.ts && this.isP("<")) {
      this.next();
      let depth = 1;
      for (;;) {
        if (this.t === "eof") this.fail();
        if (this.isP("<")) depth += 1;
        else if (this.isP(">")) {
          depth -= 1;
          if (depth === 0) break;
        }
        this.next();
      }
      this.jsxTagNext();
    }
    const attrs = [];
    while (!(this.isP(">") || this.isP("/"))) {
      const aline = this.ln;
      if (this.isP("{")) {
        this.next();
        this.expectP("...");
        const argument = this.parseMaybeAssign();
        if (!this.isP("}")) this.fail();
        this.jsxTagNext();
        attrs.push(n("JSXSpreadAttribute", aline, { argument }));
        continue;
      }
      if (this.t !== "name") this.fail();
      let aname = n("JSXIdentifier", aline, { name: this.v });
      this.jsxTagNext();
      if (this.isP(":")) {
        this.jsxTagNext();
        if (this.t !== "name") this.fail();
        aname = n("JSXNamespacedName", aline, { namespace: aname, name: n("JSXIdentifier", this.ln, { name: this.v }) });
        this.jsxTagNext();
      }
      let value = null;
      if (this.isP("=")) {
        this.jsxTagNext();
        const vline = this.ln;
        if (this.t === "str") {
          value = n("Literal", vline, { kind: "string", value: this.v });
          this.jsxTagNext();
        } else if (this.isP("{")) {
          this.next();
          const expression = this.parseMaybeAssign();
          if (!this.isP("}")) this.fail();
          value = n("JSXExpressionContainer", vline, { expression });
          this.jsxTagNext();
        } else if (this.isP("<")) {
          this.enter();
          this.jsxTagNext();
          value = this.parseJsxElement(vline, "attr");
          this.depth -= 1;
        } else {
          this.fail();
        }
      }
      attrs.push(n("JSXAttribute", aline, { name: aname, value }));
    }
    if (this.isP("/")) {
      this.jsxTagNext();
      if (!this.isP(">")) this.fail();
      const opening = n("JSXOpeningElement", line, { name, attributes: attrs, selfClosing: true });
      this.jsxEnd(where);
      return n("JSXElement", line, { openingElement: opening, closingElement: null, children: [] });
    }
    const opening = n("JSXOpeningElement", line, { name, attributes: attrs, selfClosing: false });
    const children = this.parseJsxChildren();
    const cline = this.closerLine;
    this.jsxTagNext();
    if (this.isP(">")) this.fail("unexpected closing fragment");
    const cname = this.parseJsxName();
    if (!this.isP(">")) this.fail();
    if (jsxNameText(cname) !== jsxNameText(name)) this.fail("mismatched closing tag");
    const closing = n("JSXClosingElement", cline, { name: cname });
    this.jsxEnd(where);
    return n("JSXElement", line, { openingElement: opening, closingElement: closing, children });
  }

  parseJsxChildren() {
    const children = [];
    for (;;) {
      this.jsxTextNext();
      if (this.t === "eof") this.fail("unterminated JSX contents");
      if (this.t === "jsxtext") {
        children.push(n("JSXText", this.ln, { value: this.v }));
        continue;
      }
      if (this.v === "{") {
        const cline = this.ln;
        this.next();
        if (this.isP("}")) {
          children.push(n("JSXExpressionContainer", cline, { expression: n("JSXEmptyExpression", cline, {}) }));
        } else if (this.isP("...")) {
          this.next();
          const expression = this.parseExpression();
          if (!this.isP("}")) this.fail();
          children.push(n("JSXSpreadChild", cline, { expression }));
        } else {
          const expression = this.parseExpression();
          if (!this.isP("}")) this.fail();
          children.push(n("JSXExpressionContainer", cline, { expression }));
        }
        continue;
      }
      const ltLine = this.ln;
      this.jsxTagNext();
      if (this.isP("/")) {
        this.closerLine = ltLine;
        return children;
      }
      this.enter();
      children.push(this.parseJsxElement(ltLine, "child"));
      this.depth -= 1;
    }
  }
}

/** [TypeScript, JSX] for a file name. */
export function dialect(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".mts") || lower.endsWith(".cts")) return [true, false];
  if (lower.endsWith(".tsx")) return [true, true];
  return [false, true];
}

/** The Program node of `src`; JsSyntaxError when it cannot be read. */
export function parse(src, ts = false, jsx = true) {
  try {
    return new Parser(src, ts, jsx).parseProgram();
  } catch (e) {
    if (e instanceof RangeError) throw new JsSyntaxError(1, "nesting too deep");
    throw e;
  }
}

/** parse() in the dialect of the file name. */
export function parseFile(path, src) {
  const [ts, jsx] = dialect(path);
  return parse(src, ts, jsx);
}
