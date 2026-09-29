"""A JavaScript reader for the cross-file flow engine (0.1.7).

ECMAScript 2025 with JSX and TypeScript — the syntax of .js .mjs .cjs .jsx
.ts .tsx .mts .cts files — read into an ESTree-shaped tree: the node types
and fields acorn uses for JavaScript and acorn-jsx for JSX. TypeScript's
types are read and left out, and so are interfaces, type aliases, overload
signatures, abstract members and `declare` statements; an enum, a namespace,
`import x = require(...)` and `export =` get nodes of their own
(TSEnumDeclaration, TSModuleDeclaration, TSImportEquals, TSExportAssignment).
Decorators are kept (a `decorators` list, when there are any). Flow's type
annotations in a .js file are read the way TypeScript's are.

Every node carries the line it starts on (`line`; line terminators are LF,
CR, CRLF, U+2028 and U+2029, as in the language). A Literal has a `kind`
(string, number, bigint, boolean, null, regex) and a `value`: a string's
cooked value, a number's or a bigint's source text, a regex's pattern (its
flags in `flags`), a boolean, or None. A TemplateElement has its `raw` text.

It is a reader for analysis, not a validator: early errors are not checked,
and a program it cannot read raises JsSyntaxError (a line and a reason).
Identifiers are ASCII letters, digits, `$`, `_`, escapes and every character
past ASCII but whitespace, whatever the Unicode version.

Linear time: the parser asks the scanner for one token at a time and tells
it where a regular expression or a template's continuation may start;
speculative reads (an arrow function's return type, TypeScript's type
arguments in an expression, a generic arrow function) consume at most
SPECULATION_TOKENS tokens each, and all of a file's together at most
SPECULATION_TOTAL plus 2 per code point of it (past that a read ahead
fails, as one that does not fit does). Nesting deeper than MAX_DEPTH is a
JsSyntaxError rather than a RecursionError (parse() raises Python's
recursion limit to fit it); chains that are not nesting — `else if`, binary operators, member
and call chains — are read in loops.

Twin: js/src/lib/jsparse.js, node for node (tests/architecture/
test_js_parity_parse.py).
"""
import re
import sys
from bisect import bisect_left

MAX_DEPTH = 256                  # nested statements, expressions and types
SPECULATION_TOKENS = 4096        # tokens one speculative read may consume
SPECULATION_TOTAL = 16 * SPECULATION_TOKENS   # ... and all of a file's: this + 2 per code point of it
_RECURSION = 40 * MAX_DEPTH + 3000   # frames parse() makes room for


class JsSyntaxError(Exception):
    """A program the reader cannot read: `line` and `reason`."""

    def __init__(self, line, reason):
        super().__init__(f"line {line}: {reason}")
        self.line = line
        self.reason = reason


class _Backtrack(Exception):
    """A speculative read that did not fit."""


# ---------------------------------------------------------------- scanner --
_WS_CHARS = "\t\x0b\x0c \xa0\ufeff\u1680\u2000-\u200a\u202f\u205f\u3000"
_ID_OTHER = ("\u0080-\u009f\u00a1-\u167f\u1681-\u1fff\u200b-\u2027\u202a-\u202e\u2030-\u205e"
             "\u2060-\u2fff\u3001-\ufefe\uff00-\U0010ffff")
_ID_START = "A-Za-z_$" + _ID_OTHER
_ID_PART = "A-Za-z0-9_$" + _ID_OTHER
_ESC = r"\\u(?:[0-9a-fA-F]{4}|\{[0-9a-fA-F]+\})"
_BLANKS_RE = re.compile(r"[" + _WS_CHARS + r"\n\r\u2028\u2029]*")
_LT_RE = re.compile(r"[\n\r\u2028\u2029]")
_LINE_RE = re.compile(r"\r\n|[\n\r\u2028\u2029]")
_REST_OF_LINE_RE = re.compile(r"[^\n\r\u2028\u2029]*")
_IDENT_RE = re.compile(r"(?:[" + _ID_START + r"]|" + _ESC + r")[" + _ID_PART + r"]*(?:" + _ESC + r"[" + _ID_PART
                       + r"]*)*")
_ESC_RE = re.compile(_ESC)
_NUM_RE = re.compile(r"0[xX][0-9a-fA-F_]*n?|0[oO][0-7_]*n?|0[bB][01_]*n?"
                     r"|(?:[0-9][0-9_]*(?:\.[0-9_]*)?|\.[0-9][0-9_]*)(?:[eE][+-]?[0-9_]+)?n?")
_STR_RE = {"'": re.compile(r"'[^'\\\n\r]*(?:\\(?:\r\n|[\s\S])[^'\\\n\r]*)*'"),
           '"': re.compile(r'"[^"\\\n\r]*(?:\\(?:\r\n|[\s\S])[^"\\\n\r]*)*"')}
_TMPL_RE = re.compile(r"[^`\\$]*(?:(?:\\[\s\S]|\$(?!\{))[^`\\$]*)*")
_REGEX_RE = re.compile(r"/[^/\\\[\n\r\u2028\u2029]*(?:(?:\\[^\n\r\u2028\u2029]"
                       r"|\[[^\]\\\n\r\u2028\u2029]*(?:\\[^\n\r\u2028\u2029][^\]\\\n\r\u2028\u2029]*)*\])"
                       r"[^/\\\[\n\r\u2028\u2029]*)*/[" + _ID_PART + r"]*")
# `>` is always one token: the parser reads `>=`, `>>`, `>>=`, … where an
# operator may stand (TypeScript's type arguments close with it)
_PUNCT_RE = re.compile(r"\.\.\.|===|!==|\*\*=|<<=|&&=|\|\|=|\?\?=|=>|==|!=|<=|&&|\|\||\?\?|\?\.(?![0-9])"
                       r"|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|\*\*|<<|[{}()\[\];,<>+\-*/%&|^!~?:=.@#]")
_GT_RE = re.compile(r">>>=|>>=|>>>|>>|>=|>")
_JSX_NAME_RE = re.compile(r"[" + _ID_START + r"][" + _ID_PART + r"\-]*")
_JSX_TEXT_RE = re.compile(r"[^{<]+")
_JSX_STR_RE = {"'": re.compile(r"'[^']*'"), '"': re.compile(r'"[^"]*"')}
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\x0b"}
_COOK_RE = re.compile(r"\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|([0-7]{1,3})"
                      r"|(\r\n|[\s\S]))")
_LINE_ENDS = ("\n", "\r", "\u2028", "\u2029", "\r\n")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _cook_one(m):
    if m.group(1) is not None:
        cp = int(m.group(1), 16)
        return chr(cp) if cp <= 0x10FFFF else "\ufffd"
    if m.group(2) is not None:
        return chr(int(m.group(2), 16))
    if m.group(3) is not None:
        return chr(int(m.group(3), 16))
    if m.group(4) is not None:
        digits = m.group(4)
        if int(digits, 8) > 255:               # \400 is \40, then "0"
            return chr(int(digits[:2], 8)) + digits[2:]
        return chr(int(digits, 8))
    c = m.group(5)
    if c in _LINE_ENDS:
        return ""                              # a line continuation
    return _SIMPLE_ESC.get(c, c)


def _utf16(text):
    """text as a JavaScript string holds it: an escaped surrogate pair
    (`\\ud835\\udd04`) is one character."""
    if _SURROGATE_RE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _cook(raw):
    """The value of a string literal's body (escapes read)."""
    if "\\" not in raw:
        return raw
    return _utf16(_COOK_RE.sub(_cook_one, raw))


def _unescape_ident_one(m):
    h = m.group()[2:]
    cp = int(h[1:-1] if h.startswith("{") else h, 16)
    return chr(cp) if cp <= 0x10FFFF else "\ufffd"


# --------------------------------------------------------------- grammar ---
_BINARY_PREC = {
    "??": 1, "||": 1, "&&": 2, "|": 3, "^": 4, "&": 5,
    "==": 6, "!=": 6, "===": 6, "!==": 6,
    "<": 7, ">": 7, "<=": 7, ">=": 7, "instanceof": 7, "in": 7,
    "<<": 8, ">>": 8, ">>>": 8, "+": 9, "-": 9, "*": 10, "/": 10, "%": 10, "**": 11,
}
_LOGICAL = frozenset(("||", "&&", "??"))
_ASSIGN_OPS = frozenset(("=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=",
                         "&&=", "||=", "??="))
_UNARY_WORDS = frozenset(("typeof", "void", "delete"))
# reserved words: never an identifier reference, a binding or a label
_RESERVED = frozenset((
    "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else",
    "export", "extends", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "return",
    "super", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with", "null", "true",
    "false", "enum"))
_CLASS_MODIFIERS = frozenset(("public", "private", "protected", "readonly", "abstract", "override", "declare",
                              "static", "accessor", "async", "get", "set"))
_PARAM_MODIFIERS = frozenset(("public", "private", "protected", "readonly", "override"))
_TS_DECL_WORDS = frozenset(("interface", "type", "enum", "declare", "namespace", "module", "abstract", "global"))
_EXPR_START_PUNCT = frozenset(("(", "[", "{", "+", "-", "!", "~", "++", "--", "/", "/=", "<", "@", "#", "..."))
_KEY_KINDS = frozenset(("name", "str", "num", "bigint", "priv"))


def _n(type_, line, **fields):
    node = {"type": type_, "line": line}
    node.update(fields)
    return node


class _Parser:
    def __init__(self, src, ts, jsx):
        self.src = src
        self.n = len(src)
        self.ts = ts
        self.jsx = jsx
        self.line_ends = [m.start() for m in _LINE_RE.finditer(src)]
        self.depth = 0
        self.in_func = False
        self.in_async = False
        self.in_gen = False
        self.no_conditional = False      # in a conditional type's `extends` clause
        self.spec = 0                    # speculative reads under way
        self.spec_budget = 0
        self.spec_left = 2 * len(src) + SPECULATION_TOTAL   # tokens every read ahead may still consume
        self.covers = []                 # shorthand initializers (`{ a = 1 }`) read so far
        self.peek_at = -1
        self.peek_val = None
        # the current token: kind, value, start, end, line, a newline before it
        self.t = "eof"
        self.v = ""
        self.s = 0
        self.e = 0
        self.ln = 1
        self.nl = False
        self.esc = False                 # a name written with escapes
        self.pt = self.pv = None         # the previous token's kind and value
        self.declaring = False           # in a `declare` statement: signatures without bodies
        self.ret_ok = True               # an arrow function may have a return type here
        if src.startswith("#!"):
            self.e = _REST_OF_LINE_RE.match(src, 2).end()
        self.next()

    # ---- scanning ----
    def line_at(self, pos):
        return bisect_left(self.line_ends, pos) + 1

    def fail(self, reason=None, line=None):
        if reason is None:
            if self.t == "eof":
                reason = "unexpected end of input"
            elif self.t == "str":
                reason = "unexpected string"
            elif self.t == "tmpl":
                reason = "unexpected template"
            else:
                text = self.src[self.s:self.e]
                if len(text) > 20:
                    text = text[:20]
                reason = "unexpected token " + _quote(text)
        raise JsSyntaxError(self.ln if line is None else line, reason)

    def skip(self, pos):
        """Skip blanks and comments from pos: the token start."""
        src = self.src
        b = pos
        while True:
            b = _BLANKS_RE.match(src, b).end()
            if src.startswith("//", b):
                m = _LT_RE.search(src, b)
                b = self.n if m is None else m.start()
            elif src.startswith("/*", b):
                end = src.find("*/", b + 2)
                if end < 0:
                    raise JsSyntaxError(self.line_at(b), "unterminated comment")
                b = end + 2
            else:
                break
        self.nl = b > pos and _LT_RE.search(src, pos, b) is not None
        self.s = b
        self.ln = self.line_at(b)
        self.esc = False
        return b

    def next(self):
        if self.spec:
            self.spec_budget -= 1
            self.spec_left -= 1
            if self.spec_budget < 0 or self.spec_left < 0:
                raise _Backtrack()
        self.pt, self.pv = self.t, self.v
        src = self.src
        b = self.skip(self.e)
        if b >= self.n:
            self.t, self.v, self.e = "eof", "", b
            return
        c = src[b]
        o = ord(c)
        if (o < 128 and (c.isalpha() or c == "_" or c == "$")) or c == "\\" or o >= 128:
            m = _IDENT_RE.match(src, b)
            if m is not None:
                text = m.group()
                self.e = m.end()
                if "\\" in text:
                    self.esc = True
                    text = _utf16(_ESC_RE.sub(_unescape_ident_one, text))
                self.t, self.v = "name", text
                return
            if c == "\\":
                self.fail("unexpected character '\\'")
            self.fail("unexpected character " + _quote(c))
        if "0" <= c <= "9" or (c == "." and "0" <= src[b + 1:b + 2] <= "9"):
            m = _NUM_RE.match(src, b)
            self.e = m.end()
            text = m.group()
            self.t, self.v = ("bigint" if text.endswith("n") else "num"), text
            return
        if c == "'" or c == '"':
            m = _STR_RE[c].match(src, b)
            if m is None:
                self.fail("unterminated string")
            self.e = m.end()
            self.t, self.v = "str", _cook(src[b + 1:m.end() - 1])
            return
        if c == "`":
            self.read_template(b + 1)
            return
        if c == "#":
            m = _IDENT_RE.match(src, b + 1)
            if m is not None:
                self.e = m.end()
                self.t, self.v = "priv", _utf16(_ESC_RE.sub(_unescape_ident_one, m.group()))
                return
        m = _PUNCT_RE.match(src, b)
        if m is None:
            self.fail("unexpected character " + _quote(c))
        self.e = m.end()
        self.t, self.v = "p", m.group()

    def read_template(self, pos):
        """A template chunk from pos (after ` or }): kind 'tmpl', value
        (raw text, tail)."""
        end = _TMPL_RE.match(self.src, pos).end()
        if self.src.startswith("`", end):
            self.t, self.v, self.e = "tmpl", (self.src[pos:end], True), end + 1
        elif self.src.startswith("${", end):
            self.t, self.v, self.e = "tmpl", (self.src[pos:end], False), end + 2
        else:
            self.fail("unterminated template")

    def rescan_regex(self):
        m = _REGEX_RE.match(self.src, self.s)
        if m is None:
            self.fail("unterminated regular expression")
        text = m.group()
        close = text.rindex("/")
        self.e = m.end()
        self.t, self.v = "regex", (text[1:close], text[close + 1:])

    def rescan_template_continuation(self):
        """At the `}` that closes a template substitution."""
        if not (self.t == "p" and self.v == "}"):
            self.fail()
        self.read_template(self.s + 1)

    def gt_op(self):
        """The operator a `>` token starts (`>`, `>=`, `>>`, `>>=`, …)."""
        return _GT_RE.match(self.src, self.s).group()

    def take_gt(self):
        op = self.gt_op()
        self.e = self.s + len(op)
        self.v = op

    def peek(self):
        """(kind, value, newline before) of the token after this one."""
        if self.peek_at == self.e and self.peek_val is not None:
            return self.peek_val
        st = self.save()
        self.spec += 1
        self.spec_budget += 1
        ok = True
        try:
            self.next()
            out = (self.t, self.v, self.nl)
        except (JsSyntaxError, _Backtrack):
            out = ("eof", "", False)
            ok = False
        finally:
            self.spec -= 1
            self.restore(st)
        if ok:
            self.peek_at, self.peek_val = self.e, out
        return out

    def save(self):
        return (self.t, self.v, self.s, self.e, self.ln, self.nl, self.esc, self.depth, len(self.covers),
                self.in_func, self.in_async, self.in_gen, self.no_conditional, self.pt, self.pv, self.ret_ok,
                self.spec_budget)

    def restore(self, st):
        (self.t, self.v, self.s, self.e, self.ln, self.nl, self.esc, self.depth, ncov,
         self.in_func, self.in_async, self.in_gen, self.no_conditional, self.pt, self.pv, self.ret_ok,
         self.spec_budget) = st
        del self.covers[ncov:]

    def speculate(self, fn):
        """fn()'s value, read ahead; None, with the state as before, when
        it does not fit. A read inside another keeps using that one's
        budget: what a failed read consumed stays consumed."""
        st = self.save()
        outer = self.spec > 0
        if not outer:
            self.spec_budget = SPECULATION_TOKENS
        self.spec += 1
        try:
            out = fn()
        except (JsSyntaxError, _Backtrack):
            self.spec -= 1
            spent = self.spec_budget
            self.restore(st)
            if outer:
                self.spec_budget = spent
            return None
        self.spec -= 1
        if not outer:
            self.spec_budget = st[-1]
        return out

    def look(self, fn, tokens):
        """fn() on a read ahead of at most `tokens` tokens; the state is
        always restored. False when the read fails."""
        st = self.save()
        self.spec += 1
        self.spec_budget += tokens
        try:
            return fn()
        except (JsSyntaxError, _Backtrack):
            return False
        finally:
            self.spec -= 1
            self.restore(st)

    # ---- token tests ----
    def is_p(self, v):
        return self.t == "p" and self.v == v

    def is_n(self, v):
        return self.t == "name" and self.v == v and not self.esc

    def eat_p(self, v):
        if self.t == "p" and self.v == v:
            self.next()
            return True
        return False

    def eat_n(self, v):
        if self.t == "name" and self.v == v and not self.esc:
            self.next()
            return True
        return False

    def expect_p(self, v):
        if not (self.t == "p" and self.v == v):
            self.fail()
        self.next()

    def expect_n(self, v):
        if not (self.t == "name" and self.v == v and not self.esc):
            self.fail()
        self.next()

    def semicolon(self):
        if self.t == "p" and self.v == ";":
            self.next()
        elif not (self.t == "eof" or (self.t == "p" and self.v == "}") or self.nl):
            self.fail()

    def enter(self):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise JsSyntaxError(self.ln, "nesting too deep")

    def ident(self, reserved_ok=False):
        if self.t != "name" or (not reserved_ok and not self.esc and self.v in _RESERVED):
            self.fail()
        node = _n("Identifier", self.ln, name=self.v)
        self.next()
        return node

    def function_context(self, is_async, gen):
        saved = (self.in_func, self.in_async, self.in_gen)
        self.in_func, self.in_async, self.in_gen = True, is_async, gen
        return saved

    def restore_context(self, saved):
        self.in_func, self.in_async, self.in_gen = saved

    # ---- program and statements ----
    def parse_program(self):
        body = []
        while self.t != "eof":
            stmt = self.parse_statement()
            if stmt is not None:
                body.append(stmt)
        for prop in self.covers:
            if "_cover" in prop:
                raise JsSyntaxError(prop["line"], "invalid shorthand property initializer")
        return _n("Program", 1, body=body)

    def parse_statement(self):
        self.enter()
        stmt = self.parse_statement_inner()
        self.depth -= 1
        return stmt

    def sub_statement(self):
        """A statement that is part of another (a body): never None."""
        line = self.ln
        stmt = self.parse_statement()
        return _n("EmptyStatement", line) if stmt is None else stmt

    def parse_statement_inner(self):
        t, v, line = self.t, self.v, self.ln
        if t == "p":
            if v == "{":
                return self.parse_block()
            if v == ";":
                self.next()
                return _n("EmptyStatement", line)
            if v == "@":
                decorators = self.parse_decorators()
                if self.is_n("export"):
                    return self.parse_export(decorators)
                return self.parse_class(True, decorators)
        elif t == "name" and not self.esc:
            pk, pv, pnl = self.peek()
            if v == "var" or v == "const":
                if v == "const" and pk == "name" and pv == "enum":
                    self.next()
                    return self.parse_enum(line)
                node = self.parse_var(v)
                self.semicolon()
                return node
            if v == "let" and (pk == "name" or (pk == "p" and pv in ("[", "{"))):
                node = self.parse_var("let")
                self.semicolon()
                return node
            if v == "using" and pk == "name" and not pnl and pv not in ("in", "of", "instanceof"):
                node = self.parse_var("using")
                self.semicolon()
                return node
            if v == "await" and pk == "name" and pv == "using" and not pnl and self.look(self.await_using_ahead, 3):
                self.next()
                node = self.parse_var("await using")
                self.semicolon()
                return node
            if v == "function":
                return self.parse_function(True, False, line)
            if v == "async" and pk == "name" and pv == "function" and not pnl:
                self.next()
                return self.parse_function(True, True, line)
            if v == "class":
                return self.parse_class(True, [])
            if v == "if":
                return self.parse_if()
            if v == "for":
                return self.parse_for()
            if v == "while":
                self.next()
                test = self.parse_paren_expr()
                body = self.sub_statement()
                return _n("WhileStatement", line, test=test, body=body)
            if v == "do":
                self.next()
                body = self.sub_statement()
                self.expect_n("while")
                test = self.parse_paren_expr()
                self.eat_p(";")
                return _n("DoWhileStatement", line, body=body, test=test)
            if v == "return":
                self.next()
                arg = None
                if not (self.t == "eof" or self.nl or (self.t == "p" and self.v in (";", "}"))):
                    arg = self.parse_expression()
                self.semicolon()
                return _n("ReturnStatement", line, argument=arg)
            if v == "break" or v == "continue":
                self.next()
                label = None
                if self.t == "name" and not self.nl:
                    label = self.ident(True)
                self.semicolon()
                return _n("BreakStatement" if v == "break" else "ContinueStatement", line, label=label)
            if v == "throw":
                self.next()
                if self.nl:
                    self.fail("illegal newline after throw")
                arg = self.parse_expression()
                self.semicolon()
                return _n("ThrowStatement", line, argument=arg)
            if v == "try":
                return self.parse_try()
            if v == "switch":
                return self.parse_switch()
            if v == "with":
                self.next()
                obj = self.parse_paren_expr()
                body = self.sub_statement()
                return _n("WithStatement", line, object=obj, body=body)
            if v == "debugger":
                self.next()
                self.semicolon()
                return _n("DebuggerStatement", line)
            if v == "import" and not (pk == "p" and pv in ("(", ".")):
                return self.parse_import()
            if v == "export":
                return self.parse_export([])
            if v in _TS_DECL_WORDS:
                node = self.parse_ts_declaration(pk, pv, pnl)
                if node is not False:
                    return node
            if pk == "p" and pv == ":" and v not in _RESERVED:
                label = self.ident()
                self.next()
                body = self.sub_statement()
                return _n("LabeledStatement", line, label=label, body=body)
        expr = self.parse_expression()
        self.semicolon()
        return _n("ExpressionStatement", line, expression=expr)

    def await_using_ahead(self):
        """At `await using`: a name follows on the line (a declaration)."""
        self.next()
        self.next()
        return self.t == "name" and not self.nl and self.v not in ("in", "of", "instanceof")

    def parse_block(self):
        line = self.ln
        self.expect_p("{")
        body = []
        while not (self.t == "p" and self.v == "}"):
            if self.t == "eof":
                self.fail()
            stmt = self.parse_statement()
            if stmt is not None:
                body.append(stmt)
        self.next()
        return _n("BlockStatement", line, body=body)

    def parse_paren_expr(self):
        self.expect_p("(")
        expr = self.parse_expression()
        self.expect_p(")")
        return expr

    def parse_if(self):
        """if / else if / … / else, the chain read in a loop."""
        chain = []
        alt = None
        while True:
            line = self.ln
            self.next()                         # if
            test = self.parse_paren_expr()
            cons = self.sub_statement()
            chain.append((line, test, cons))
            if not self.is_n("else"):
                break
            self.next()
            if not self.is_n("if"):
                alt = self.sub_statement()
                break
        for line, test, cons in reversed(chain):
            alt = _n("IfStatement", line, test=test, consequent=cons, alternate=alt)
        return alt

    def parse_try(self):
        line = self.ln
        self.next()
        block = self.parse_block()
        handler = finalizer = None
        if self.is_n("catch"):
            cline = self.ln
            self.next()
            param = None
            if self.eat_p("("):
                param = self.parse_binding_target()
                if self.eat_p(":"):
                    self.parse_type()
                self.expect_p(")")
            body = self.parse_block()
            handler = _n("CatchClause", cline, param=param, body=body)
        if self.eat_n("finally"):
            finalizer = self.parse_block()
        if handler is None and finalizer is None:
            self.fail("missing catch or finally")
        return _n("TryStatement", line, block=block, handler=handler, finalizer=finalizer)

    def parse_switch(self):
        line = self.ln
        self.next()
        disc = self.parse_paren_expr()
        self.expect_p("{")
        cases = []
        while not self.eat_p("}"):
            cline = self.ln
            if self.eat_n("case"):
                test = self.parse_expression()
            elif self.eat_n("default"):
                test = None
            else:
                self.fail()
            self.expect_p(":")
            cons = []
            while not (self.is_p("}") or self.is_n("case") or self.is_n("default")):
                if self.t == "eof":
                    self.fail()
                stmt = self.parse_statement()
                if stmt is not None:
                    cons.append(stmt)
            cases.append(_n("SwitchCase", cline, test=test, consequent=cons))
        return _n("SwitchStatement", line, discriminant=disc, cases=cases)

    def parse_for(self):
        line = self.ln
        self.next()
        is_await = self.eat_n("await")
        self.expect_p("(")
        init = None
        if not self.is_p(";"):
            kind = None
            if self.t == "name" and not self.esc:
                pk, pv, pnl = self.peek()
                if self.v in ("var", "const"):
                    kind = self.v
                elif self.v == "let" and (pk == "name" or (pk == "p" and pv in ("[", "{"))):
                    kind = "let"
                elif self.v == "using" and pk == "name" and pv not in ("of", "in") and not pnl:
                    kind = "using"
                elif self.v == "await" and pk == "name" and pv == "using" and self.look(self.await_using_ahead, 3):
                    self.next()
                    kind = "await using"
            if kind is not None:
                init = self.parse_var(kind, no_in=True)
            else:
                init = self.parse_expression(no_in=True)
            if self.is_n("of") or self.is_n("in"):
                of = self.v == "of"
                self.next()
                if init["type"] != "VariableDeclaration":
                    init = self.to_pattern(init, False)
                right = self.parse_maybe_assign() if of else self.parse_expression()
                self.expect_p(")")
                body = self.sub_statement()
                if of:
                    return _n("ForOfStatement", line, left=init, right=right, body=body, **{"await": is_await})
                return _n("ForInStatement", line, left=init, right=right, body=body)
        self.expect_p(";")
        test = None if self.is_p(";") else self.parse_expression()
        self.expect_p(";")
        update = None if self.is_p(")") else self.parse_expression()
        self.expect_p(")")
        body = self.sub_statement()
        return _n("ForStatement", line, init=init, test=test, update=update, body=body)

    def parse_var(self, kind, no_in=False):
        line = self.ln
        self.next()
        decls = []
        while True:
            dline = self.ln
            target = self.parse_binding_target()
            if self.ts and self.is_p("!"):
                self.next()
            if self.eat_p(":"):
                self.parse_type()
            init = None
            if self.eat_p("="):
                init = self.parse_maybe_assign(no_in)
            decls.append(_n("VariableDeclarator", dline, id=target, init=init))
            if not self.eat_p(","):
                break
        return _n("VariableDeclaration", line, kind=kind, declarations=decls)

    # ---- functions ----
    def parse_function(self, is_decl, is_async, line):
        """`function …` (the current token): a declaration or an
        expression; None for a TypeScript signature without a body."""
        self.next()
        gen = self.eat_p("*")
        fid = None
        if self.t == "name" and not self.is_p("("):
            fid = self.ident(self.v in ("yield", "await"))
        if self.is_p("<"):
            self.parse_type_params()
        saved = self.function_context(is_async, gen)
        try:
            params = self.parse_params()
            if self.is_p(":"):
                self.parse_return_type()
            if not self.is_p("{"):
                if is_decl and (self.ts or self.declaring) and (self.is_p(";") or self.nl or self.is_p("}")
                                                                or self.t == "eof"):
                    self.eat_p(";")
                    return None
                self.fail()
            body = self.parse_block()
        finally:
            self.restore_context(saved)
        return _n("FunctionDeclaration" if is_decl else "FunctionExpression", line, id=fid, params=params,
                  body=body, generator=gen, **{"async": is_async})

    def parse_params(self):
        """A parameter list `( … )` (TypeScript's `this` parameter left out)."""
        self.expect_p("(")
        params = []
        while not self.is_p(")"):
            param = self.parse_param()
            if param is not None:
                params.append(param)
            if not self.is_p(")"):
                self.expect_p(",")
        self.next()
        return params

    def parse_param(self):
        line = self.ln
        decorators = self.parse_decorators() if self.is_p("@") else []
        while self.t == "name" and self.v in _PARAM_MODIFIERS and not self.esc:
            pk, pv, _ = self.peek()
            if pk == "name" or (pk == "p" and pv in ("[", "{")):
                self.next()
            else:
                break
        if self.is_p("..."):
            self.next()
            node = _n("RestElement", line, argument=self.parse_binding_target())
            self.eat_p("?")
            if self.eat_p(":"):
                self.parse_type()
            if self.eat_p("="):
                self.parse_maybe_assign()
            return node
        if self.is_n("this"):
            pk, pv, _ = self.peek()
            if pk == "p" and pv in (":", ",", ")"):
                self.next()
                if self.eat_p(":"):
                    self.parse_type()
                return None
        tline = self.ln
        target = self.parse_binding_target()
        self.eat_p("?")
        if self.eat_p(":"):
            self.parse_type()
        if self.eat_p("="):
            target = _n("AssignmentPattern", tline, left=target, right=self.parse_maybe_assign())
        if decorators:
            target["decorators"] = decorators
        return target

    def parse_binding_target(self):
        """An identifier, or an array or object pattern."""
        line = self.ln
        if self.is_p("["):
            self.enter()
            self.next()
            elements = []
            while not self.is_p("]"):
                if self.is_p(","):
                    self.next()
                    elements.append(None)
                    continue
                eline = self.ln
                if self.eat_p("..."):
                    elements.append(_n("RestElement", eline, argument=self.parse_binding_target()))
                else:
                    el = self.parse_binding_target()
                    if self.eat_p("="):
                        el = _n("AssignmentPattern", eline, left=el, right=self.parse_maybe_assign())
                    elements.append(el)
                if not self.is_p("]"):
                    self.expect_p(",")
            self.next()
            self.depth -= 1
            return _n("ArrayPattern", line, elements=elements)
        if self.is_p("{"):
            self.enter()
            self.next()
            props = []
            while not self.is_p("}"):
                pline = self.ln
                if self.eat_p("..."):
                    props.append(_n("RestElement", pline, argument=self.parse_binding_target()))
                else:
                    computed = False
                    if self.eat_p("["):
                        key = self.parse_maybe_assign()
                        self.expect_p("]")
                        computed = True
                    else:
                        key = self.parse_property_name()
                    if self.eat_p(":"):
                        vline = self.ln
                        value = self.parse_binding_target()
                        shorthand = False
                    else:
                        if key["type"] != "Identifier" or computed:
                            self.fail()
                        vline = key["line"]
                        value = _n("Identifier", vline, name=key["name"])
                        shorthand = True
                    if self.eat_p("="):
                        value = _n("AssignmentPattern", vline, left=value, right=self.parse_maybe_assign())
                    props.append(_n("Property", pline, key=key, value=value, kind="init", method=False,
                                    shorthand=shorthand, computed=computed))
                if not self.is_p("}"):
                    self.expect_p(",")
            self.next()
            self.depth -= 1
            return _n("ObjectPattern", line, properties=props)
        if self.t == "name":
            return self.ident()
        self.fail()

    def parse_property_name(self):
        """A property key: any word, a string, a number, a private name."""
        line, t, v = self.ln, self.t, self.v
        if t == "name":
            node = _n("Identifier", line, name=v)
        elif t == "str":
            node = _n("Literal", line, kind="string", value=v)
        elif t == "num" or t == "bigint":
            node = _n("Literal", line, kind="number" if t == "num" else "bigint", value=v)
        elif t == "priv":
            node = _n("PrivateIdentifier", line, name=v)
        else:
            self.fail()
        self.next()
        return node

    # ---- classes ----
    def parse_decorators(self):
        out = []
        while self.is_p("@"):
            self.next()
            self.enter()
            line = self.ln
            if self.is_p("("):
                expr = self.parse_paren_expr()
            else:
                expr = self.ident(True)
                while self.eat_p("."):
                    prop = self.parse_property_name() if self.t == "priv" else self.ident(True)
                    expr = _n("MemberExpression", line, object=expr, property=prop, computed=False, optional=False)
                if self.ts and self.is_p("<"):
                    self.speculate(self.parse_type_args)
                if self.is_p("("):
                    args = self.parse_arguments()
                    expr = _n("CallExpression", line, callee=expr, arguments=args, optional=False)
            out.append(expr)
            self.depth -= 1
        return out

    def parse_class(self, is_decl, decorators):
        line = self.ln
        self.eat_n("abstract")
        self.expect_n("class")
        cid = None
        if self.t == "name" and not (self.is_n("extends") or self.is_n("implements")):
            cid = self.ident()
        if self.is_p("<"):
            self.parse_type_params()
        sup = None
        if self.eat_n("extends"):
            sup = self.parse_expr_subscripts()
            if self.is_p("<"):
                self.parse_type_args()
        if self.eat_n("implements"):
            self.parse_type()
            while self.eat_p(","):
                self.parse_type()
        body = self.parse_class_body()
        node = _n("ClassDeclaration" if is_decl else "ClassExpression", line, id=cid, superClass=sup, body=body)
        if decorators:
            node["decorators"] = decorators
        return node

    def parse_class_body(self):
        line = self.ln
        self.expect_p("{")
        members = []
        while not self.is_p("}"):
            if self.eat_p(";"):
                continue
            if self.t == "eof":
                self.fail()
            self.enter()
            member = self.parse_class_member()
            self.depth -= 1
            if member is not None:
                members.append(member)
        self.next()
        return _n("ClassBody", line, body=members)

    def is_modifier(self):
        """Is the current word a modifier, a member's name following it?"""
        pk, pv, pnl = self.peek()
        if self.v == "async" and pnl:
            return False
        return pk in _KEY_KINDS or (pk == "p" and pv in ("[", "*"))

    def parse_class_member(self):
        line = self.ln
        decorators = self.parse_decorators() if self.is_p("@") else []
        is_static = is_async = gen = declare = abstract = False
        kind = "method"
        while self.t == "name" and not self.esc and self.v in _CLASS_MODIFIERS:
            word = self.v
            if word == "static":
                pk, pv, _ = self.peek()
                if pk == "p" and pv == "{":
                    self.next()
                    saved = self.function_context(False, False)
                    try:
                        block = self.parse_block()
                    finally:
                        self.restore_context(saved)
                    return _n("StaticBlock", line, body=block["body"])
            if not self.is_modifier():
                break
            self.next()
            if word == "static":
                is_static = True
            elif word == "async":
                is_async = True
            elif word == "get" or word == "set":
                kind = word
            elif word == "declare":
                declare = True
            elif word == "abstract":
                abstract = True
        if self.eat_p("*"):
            gen = True
        if self.ts and self.is_p("[") and self.index_signature_ahead():
            self.parse_index_signature()
            self.member_end()
            return None
        computed = False
        if self.is_p("["):
            self.next()
            key = self.parse_maybe_assign()
            self.expect_p("]")
            computed = True
        else:
            key = self.parse_property_name()
        if self.is_p("?") or (self.ts and self.is_p("!")):
            self.next()
        if self.is_p("<"):
            self.parse_type_params()
        if self.is_p("("):
            is_ctor = (not is_static and not computed and kind == "method"
                       and ((key["type"] == "Identifier" and key["name"] == "constructor")
                            or (key["type"] == "Literal" and key["value"] == "constructor")))
            fn = self.parse_method(is_async, gen)
            if fn is None or abstract or declare:
                return None
            node = _n("MethodDefinition", line, key=key, value=fn, kind="constructor" if is_ctor else kind,
                      static=is_static, computed=computed)
            if decorators:
                node["decorators"] = decorators
            return node
        if kind != "method" or gen:
            self.fail()
        if self.eat_p(":"):
            self.parse_type()
        value = None
        if self.eat_p("="):
            saved = self.function_context(False, False)
            try:
                value = self.parse_maybe_assign()
            finally:
                self.restore_context(saved)
        self.member_end()
        if declare or abstract:
            return None
        node = _n("PropertyDefinition", line, key=key, value=value, static=is_static, computed=computed)
        if decorators:
            node["decorators"] = decorators
        return node

    def member_end(self):
        if self.eat_p(";") or self.eat_p(","):
            return
        if not (self.is_p("}") or self.nl or self.t == "eof"):
            self.fail()

    def parse_method(self, is_async, gen):
        """A method's `(params) { body }` as a FunctionExpression (its line:
        the `(`'s); None for a signature without a body."""
        line = self.ln
        saved = self.function_context(is_async, gen)
        try:
            params = self.parse_params()
            if self.is_p(":"):
                self.parse_return_type()
            if not self.is_p("{"):
                if self.is_p(";") or self.is_p(",") or self.is_p("}") or self.nl or self.t == "eof":
                    self.eat_p(";")
                    return None
                self.fail()
            body = self.parse_block()
        finally:
            self.restore_context(saved)
        return _n("FunctionExpression", line, id=None, params=params, body=body, generator=gen,
                  **{"async": is_async})

    def index_signature_ahead(self):
        """`[name:` or `[name,` (a TypeScript index signature)."""
        def ahead():
            self.next()
            if self.t != "name":
                return False
            self.next()
            return self.t == "p" and self.v in (":", ",")
        return self.look(ahead, 3)

    def parse_index_signature(self):
        self.expect_p("[")
        while not self.is_p("]"):
            self.ident(True)
            if self.eat_p(":"):
                self.parse_type()
            if not self.is_p("]"):
                self.expect_p(",")
        self.next()
        self.eat_p("?")
        if self.eat_p(":"):
            self.parse_type()

    # ---- modules ----
    def parse_module_source(self):
        if self.t != "str":
            self.fail()
        node = _n("Literal", self.ln, kind="string", value=self.v)
        self.next()
        if (self.is_n("with") or self.is_n("assert")) and not self.nl:
            self.next()
            self.parse_object_like()             # import attributes, left out
        return node

    def parse_import(self):
        line = self.ln
        self.next()
        type_only = False
        if self.is_n("type") or self.is_n("typeof"):
            pk, pv, _ = self.peek()
            if (pk == "name" and pv != "from") or (pk == "p" and pv in ("{", "*")):
                self.next()
                type_only = True
        if self.t == "str":
            source = self.parse_module_source()
            self.semicolon()
            return _n("ImportDeclaration", line, specifiers=[], source=source)
        specs = []
        if self.t == "name":
            local = self.ident()
            if self.is_p("="):
                self.next()
                return self.parse_import_equals(line, local, type_only)
            specs.append(_n("ImportDefaultSpecifier", local["line"], local=local))
            if not self.eat_p(","):
                self.expect_n("from")
                source = self.parse_module_source()
                self.semicolon()
                return _n("ImportDeclaration", line, specifiers=[] if type_only else specs, source=source)
        if self.is_p("*"):
            sline = self.ln
            self.next()
            self.expect_n("as")
            specs.append(_n("ImportNamespaceSpecifier", sline, local=self.ident()))
        elif self.is_p("{"):
            self.next()
            while not self.is_p("}"):
                sline = self.ln
                skip = self.type_modifier_here()
                if self.t == "str":
                    imported = _n("Literal", self.ln, kind="string", value=self.v)
                    self.next()
                else:
                    imported = self.ident(True)
                if self.eat_n("as"):
                    local = self.ident()
                elif imported["type"] == "Identifier":
                    local = _n("Identifier", imported["line"], name=imported["name"])
                else:
                    self.fail()
                if not skip:
                    specs.append(_n("ImportSpecifier", sline, imported=imported, local=local))
                if not self.is_p("}"):
                    self.expect_p(",")
            self.next()
        else:
            self.fail()
        self.expect_n("from")
        source = self.parse_module_source()
        self.semicolon()
        return _n("ImportDeclaration", line, specifiers=[] if type_only else specs, source=source)

    def type_modifier_here(self):
        """In `{ … }` of an import or export: a `type` modifier before a
        name (consumed; True), not a name `type` itself."""
        if not self.is_n("type"):
            return False
        pk, pv, _ = self.peek()
        if pk == "str":
            self.next()
            return True
        if pk != "name":
            return False
        if pv != "as":
            self.next()
            return True

        # `type as …`: `type as x` renames `type`; `type as as x` and
        # `type as,` / `type as }` import `as` as a type
        def ahead():
            self.next()                         # as
            self.next()
            if self.t == "name" and self.v == "as":
                return True
            return self.t == "p" and self.v in (",", "}")
        if self.look(ahead, 3):
            self.next()
            return True
        return False

    def parse_import_equals(self, line, local, type_only):
        """`import x = require('m')` / `import x = A.B` (after the `=`)."""
        if self.is_n("require"):
            pk, pv, _ = self.peek()
            if pk == "p" and pv == "(":
                self.next()
                self.next()
                if self.t != "str":
                    self.fail()
                src = _n("Literal", self.ln, kind="string", value=self.v)
                self.next()
                self.expect_p(")")
                self.semicolon()
                if type_only:
                    return _n("EmptyStatement", line)
                return _n("TSImportEquals", line, id=local, module=src, entity=None)
        entity = self.ident(True)
        while self.eat_p("."):
            prop = self.ident(True)
            entity = _n("MemberExpression", entity["line"], object=entity, property=prop, computed=False,
                        optional=False)
        self.semicolon()
        if type_only:
            return _n("EmptyStatement", line)
        return _n("TSImportEquals", line, id=local, module=None, entity=entity)

    def export_name(self):
        if self.t == "str":
            node = _n("Literal", self.ln, kind="string", value=self.v)
            self.next()
            return node
        return self.ident(True)

    def parse_export(self, decorators):
        line = self.ln
        self.next()
        if self.is_p("@"):
            decorators = decorators + self.parse_decorators()
        if self.is_p("="):
            self.next()
            expr = self.parse_expression()
            self.semicolon()
            return _n("TSExportAssignment", line, expression=expr)
        if self.is_n("as"):
            self.next()
            self.expect_n("namespace")
            self.ident(True)
            self.semicolon()
            return _n("EmptyStatement", line)
        if self.is_n("import") and self.peek()[0] == "name":
            self.next()
            local = self.ident()
            self.expect_p("=")
            node = self.parse_import_equals(line, local, False)
            if node["type"] == "TSImportEquals":
                node["exported"] = True
            return node
        if self.is_n("default"):
            self.next()
            pk, pv, pnl = self.peek()
            if self.is_n("function"):
                decl = self.parse_function(True, False, self.ln)
            elif self.is_n("async") and pk == "name" and pv == "function" and not pnl:
                aline = self.ln
                self.next()
                decl = self.parse_function(True, True, aline)
            elif self.is_n("class") or (self.is_n("abstract") and pk == "name" and pv == "class"):
                decl = self.parse_class(True, decorators)
            elif self.is_p("@"):
                decl = self.parse_class(True, decorators + self.parse_decorators())
            elif self.is_n("interface") and pk == "name" and not pnl:
                self.parse_ts_declaration(pk, pv, pnl)
                return _n("EmptyStatement", line)
            else:
                decl = self.parse_maybe_assign()
                self.semicolon()
            if decl is None:
                return _n("EmptyStatement", line)
            return _n("ExportDefaultDeclaration", line, declaration=decl)
        if self.is_p("*"):
            self.next()
            exported = None
            if self.eat_n("as"):
                exported = self.export_name()
            self.expect_n("from")
            source = self.parse_module_source()
            self.semicolon()
            return _n("ExportAllDeclaration", line, exported=exported, source=source)
        type_only = False
        if self.is_n("type"):
            pk, pv, _ = self.peek()
            if pk == "p" and pv in ("{", "*"):
                self.next()
                type_only = True
                if self.is_p("*"):
                    self.next()
                    if self.eat_n("as"):
                        self.export_name()
                    self.expect_n("from")
                    self.parse_module_source()
                    self.semicolon()
                    return _n("EmptyStatement", line)
        if self.is_p("{"):
            self.next()
            specs = []
            while not self.is_p("}"):
                sline = self.ln
                skip = self.type_modifier_here()
                local = self.export_name()
                exported = self.export_name() if self.eat_n("as") else dict(local)
                if not skip:
                    specs.append(_n("ExportSpecifier", sline, local=local, exported=exported))
                if not self.is_p("}"):
                    self.expect_p(",")
            self.next()
            source = self.parse_module_source() if self.eat_n("from") else None
            self.semicolon()
            if type_only:
                return _n("EmptyStatement", line)
            return _n("ExportNamedDeclaration", line, declaration=None, specifiers=specs, source=source)
        if self.is_p("@"):
            decorators = decorators + self.parse_decorators()
        pk, pv, _ = self.peek()
        if self.is_n("class") or (self.is_n("abstract") and pk == "name" and pv == "class"):
            decl = self.parse_class(True, decorators)
        else:
            decl = self.parse_statement()
        if decl is None or decl["type"] == "EmptyStatement":
            return _n("EmptyStatement", line)
        if decl["type"] not in ("VariableDeclaration", "FunctionDeclaration", "ClassDeclaration",
                                "TSEnumDeclaration", "TSModuleDeclaration"):
            self.fail("unexpected export", line)
        return _n("ExportNamedDeclaration", line, declaration=decl, specifiers=[], source=None)

    # ---- TypeScript declarations ----
    def parse_ts_declaration(self, pk, pv, pnl):
        """interface / type / enum / declare / namespace / module / global /
        abstract class at a statement's start; False where the word is an
        identifier instead."""
        line, v = self.ln, self.v
        if v == "abstract":
            if pk == "name" and pv == "class" and not pnl:
                return self.parse_class(True, [])
            return False
        if not self.ts and v not in ("type", "interface", "declare"):
            return False
        if v == "interface":
            if pk != "name" or pnl:
                return False
            self.next()
            self.ident(True)
            if self.is_p("<"):
                self.parse_type_params()
            if self.eat_n("extends"):
                self.parse_type()
                while self.eat_p(","):
                    self.parse_type()
            self.parse_object_type()
            return _n("EmptyStatement", line)
        if v == "type":
            if pk != "name" or pnl:
                return False
            self.next()
            self.ident(True)
            if self.is_p("<"):
                self.parse_type_params()
            self.expect_p("=")
            self.parse_type()
            self.semicolon()
            return _n("EmptyStatement", line)
        if v == "enum":
            if pk != "name":
                return False
            return self.parse_enum(line)
        if v == "declare":
            if pk not in ("name",) or pnl:
                return False
            self.next()
            saved = self.declaring
            self.declaring = True
            try:
                self.parse_statement()           # read and left out
            finally:
                self.declaring = saved
            return _n("EmptyStatement", line)
        if v == "namespace" or v == "module":
            if pnl or not (pk == "name" or (v == "module" and pk == "str")):
                return False
            self.next()
            if self.t == "str":
                self.next()
                if self.is_p("{"):
                    self.parse_block()
                else:
                    self.semicolon()
                return _n("EmptyStatement", line)
            name = self.ident(True)
            while self.eat_p("."):
                self.ident(True)
            if not self.is_p("{"):
                self.semicolon()
                return _n("EmptyStatement", line)
            body = self.parse_block()
            return _n("TSModuleDeclaration", line, id=name, body=body)
        if v == "global":
            if pk == "p" and pv == "{":
                self.next()
                self.parse_block()
                return _n("EmptyStatement", line)
            return False
        return False

    def parse_enum(self, line):
        self.expect_n("enum")
        eid = self.ident(True)
        self.expect_p("{")
        members = []
        while not self.is_p("}"):
            mline = self.ln
            if self.eat_p("["):
                key = self.parse_maybe_assign()
                self.expect_p("]")
            else:
                key = self.parse_property_name()
            init = self.parse_maybe_assign() if self.eat_p("=") else None
            members.append(_n("TSEnumMember", mline, id=key, initializer=init))
            if not self.is_p("}"):
                self.expect_p(",")
        self.next()
        return _n("TSEnumDeclaration", line, id=eid, members=members)

    # ---- TypeScript types (read and left out) ----
    def parse_type(self):
        self.enter()
        if self.function_type_ahead():
            self.parse_function_type()
        else:
            self.parse_union_type()
            if self.is_n("extends") and not self.nl and not self.no_conditional:
                self.next()
                saved = self.no_conditional
                self.no_conditional = True
                self.parse_type()
                self.no_conditional = False
                self.expect_p("?")
                self.parse_type()
                self.expect_p(":")
                self.parse_type()
                self.no_conditional = saved
        self.depth -= 1

    def parse_return_type(self):
        """`: T` after a parameter list; type predicates too."""
        self.expect_p(":")
        outer = self.no_conditional
        self.no_conditional = False
        self.parse_type_or_predicate()
        self.no_conditional = outer

    def parse_type_or_predicate(self):
        if self.t == "name":
            pk, pv, pnl = self.peek()
            if self.is_n("asserts") and pk == "name" and not pnl:
                self.next()
                self.next()
                if self.eat_n("is"):
                    self.parse_type()
                return
            if pk == "name" and pv == "is" and not pnl:
                self.next()
                self.next()
                self.parse_type()
                return
        self.parse_type()

    def function_type_ahead(self):
        if self.is_p("<"):
            return True
        if self.is_n("new"):
            return True
        if self.is_n("abstract"):
            pk, pv, _ = self.peek()
            return pk == "name" and pv == "new"
        if not self.is_p("("):
            return False

        def ahead():
            self.next()
            if self.t == "p" and self.v in (")", "..."):
                return True
            if self.skip_param_start():
                if self.t == "p" and self.v in (":", ",", "?", "="):
                    return True
                if self.is_p(")"):
                    self.next()
                    return self.is_p("=>")
            return False
        return self.look(ahead, 256)

    def skip_param_start(self):
        """At the start of a parameter in a type: a name or a pattern
        (skipped); True when one was there."""
        if self.t == "name":
            self.next()
            return True
        if self.t == "p" and self.v in ("[", "{"):
            depth = 0
            while self.t != "eof":
                if self.t == "p" and self.v in ("[", "{", "("):
                    depth += 1
                elif self.t == "p" and self.v in ("]", "}", ")"):
                    depth -= 1
                    if depth == 0:
                        self.next()
                        return True
                self.next()
        return False

    def parse_function_type(self):
        self.eat_n("abstract")
        self.eat_n("new")
        if self.is_p("<"):
            self.parse_type_params()
        saved = self.function_context(False, False)
        try:
            self.parse_params()
        finally:
            self.restore_context(saved)
        self.expect_p("=>")
        outer = self.no_conditional
        self.no_conditional = False
        self.parse_type_or_predicate()
        self.no_conditional = outer

    def parse_union_type(self):
        self.eat_p("|")
        self.parse_intersection_type()
        while self.eat_p("|"):
            self.parse_intersection_type()

    def parse_intersection_type(self):
        self.eat_p("&")
        self.parse_type_operator()
        while self.eat_p("&"):
            self.parse_type_operator()

    def parse_type_operator(self):
        self.enter()
        if self.t == "name" and not self.esc and self.v in ("keyof", "unique", "readonly"):
            pk, pv, _ = self.peek()
            if pk in ("name", "str", "num", "tmpl") or (pk == "p" and pv in ("(", "[", "{", "-")):
                self.next()
                self.parse_type_operator()
                self.depth -= 1
                return
        if self.is_n("infer"):
            self.next()
            self.ident(True)
            if self.is_n("extends"):
                # a constraint, unless `infer U extends X ? …` starts a
                # conditional type where one may stand
                outer = self.no_conditional
                st = self.save()
                self.next()
                self.no_conditional = True
                try:
                    self.parse_type()
                    keep = outer or not self.is_p("?")
                except JsSyntaxError:
                    keep = False
                self.no_conditional = outer
                if not keep:
                    spent = self.spec_budget
                    self.restore(st)
                    if self.spec:
                        self.spec_budget = spent
            self.depth -= 1
            return
        outer = self.no_conditional
        self.no_conditional = False
        if self.function_type_ahead():
            self.parse_function_type()
        else:
            self.parse_primary_type()
            while not self.nl:
                if self.is_p("["):
                    self.next()
                    if not self.is_p("]"):
                        self.parse_type()
                    self.expect_p("]")
                elif self.is_p("!"):
                    self.next()
                else:
                    break
        self.no_conditional = outer
        self.depth -= 1

    def parse_entity_name(self):
        """A name, dotted (`A.B.C`)."""
        self.ident(True)
        while self.is_p("."):
            self.next()
            if self.t == "priv":
                self.next()
            else:
                self.ident(True)

    def parse_primary_type(self):
        t, v = self.t, self.v
        if t == "name":
            if not self.esc:
                if v == "typeof":
                    self.next()
                    if self.is_n("import"):
                        self.parse_import_type()
                    else:
                        self.parse_entity_name()
                    if self.is_p("<") and not self.nl:
                        self.parse_type_args()
                    return
                if v == "import":
                    self.parse_import_type()
                    return
            self.parse_entity_name()
            if self.is_p("<") and not self.nl:
                self.parse_type_args()
            return
        if t in ("str", "num", "bigint"):
            self.next()
            return
        if t == "tmpl":
            while not self.v[1]:
                self.next()
                self.parse_type()
                self.rescan_template_continuation()
            self.next()
            return
        if t == "p":
            if v == "-":
                self.next()
                if self.t not in ("num", "bigint"):
                    self.fail()
                self.next()
                return
            if v == "{":
                if self.mapped_type_ahead():
                    self.parse_mapped_type()
                else:
                    self.parse_object_type()
                return
            if v == "[":
                self.parse_tuple_type()
                return
            if v == "(":
                self.next()
                self.parse_type()
                self.expect_p(")")
                return
            if v == "*":
                self.next()
                return
            if v == "?":
                self.next()                      # Flow's ?T
                self.parse_primary_type()
                return
        self.fail()

    def parse_import_type(self):
        self.expect_n("import")
        self.expect_p("(")
        if self.t != "str":
            self.fail()
        self.next()
        if self.eat_p(",") and not self.is_p(")"):
            self.parse_object_like()
            self.eat_p(",")
        self.expect_p(")")
        while self.eat_p("."):
            self.ident(True)
        if self.is_p("<") and not self.nl:
            self.parse_type_args()

    def parse_tuple_type(self):
        self.expect_p("[")
        while not self.is_p("]"):
            self.eat_p("...")
            if self.t == "name":
                pk, pv, _ = self.peek()
                labeled = pk == "p" and (pv == ":" or (pv == "?" and self.look(self.labeled_optional_ahead, 3)))
            else:
                labeled = False
            if labeled:
                self.next()
                self.eat_p("?")
                self.expect_p(":")
            self.parse_type()
            self.eat_p("?")
            if not self.is_p("]"):
                self.expect_p(",")
        self.next()

    def labeled_optional_ahead(self):
        self.next()
        self.next()
        return self.is_p(":")

    def mapped_type_ahead(self):
        def ahead():
            self.next()
            if self.is_p("+") or self.is_p("-"):
                self.next()
                return self.is_n("readonly")
            if self.is_n("readonly"):
                self.next()
            if not self.is_p("["):
                return False
            self.next()
            if self.t != "name":
                return False
            self.next()
            return self.is_n("in")
        return self.look(ahead, 6)

    def parse_mapped_type(self):
        self.expect_p("{")
        if self.is_p("+") or self.is_p("-"):
            self.next()
        self.eat_n("readonly")
        self.expect_p("[")
        self.ident(True)
        self.expect_n("in")
        self.parse_type()
        if self.eat_n("as"):
            self.parse_type()
        self.expect_p("]")
        if self.is_p("+") or self.is_p("-"):
            self.next()
            self.expect_p("?")
        else:
            self.eat_p("?")
        if self.eat_p(":"):
            self.parse_type()
        if not self.eat_p(";"):
            self.eat_p(",")
        self.expect_p("}")

    def parse_object_type(self):
        self.expect_p("{")
        while not self.is_p("}"):
            if self.t == "eof":
                self.fail()
            self.enter()
            self.parse_type_member()
            self.depth -= 1
            if not (self.eat_p(";") or self.eat_p(",")):
                if not (self.is_p("}") or self.nl):
                    self.fail()
        self.next()

    def parse_signature_rest(self):
        """`<T>(params): R` of a call, construct or method signature."""
        if self.is_p("<"):
            self.parse_type_params()
        saved = self.function_context(False, False)
        try:
            self.parse_params()
        finally:
            self.restore_context(saved)
        if self.is_p(":"):
            self.parse_return_type()

    def parse_type_member(self):
        if self.is_p("(") or self.is_p("<"):
            self.parse_signature_rest()
            return
        if self.is_n("new"):
            pk, pv, _ = self.peek()
            if pk == "p" and pv in ("(", "<"):
                self.next()
                self.parse_signature_rest()
                return
        while self.t == "name" and self.v in ("readonly", "get", "set") and not self.esc:
            pk, pv, _ = self.peek()
            if pk in ("name", "str", "num") or (pk == "p" and pv == "["):
                self.next()
            else:
                break
        if self.is_p("["):
            if self.index_signature_ahead():
                self.parse_index_signature()
                return
            self.next()
            self.parse_maybe_assign()
            self.expect_p("]")
        else:
            self.parse_property_name()
        self.eat_p("?")
        if self.is_p("(") or self.is_p("<"):
            self.parse_signature_rest()
            return
        if self.eat_p(":"):
            self.parse_type()

    def parse_type_params(self):
        self.expect_p("<")
        while not self.is_p(">"):
            while self.t == "name" and self.v in ("in", "out", "const") and self.peek()[0] == "name":
                self.next()
            self.ident(True)
            if self.eat_n("extends"):
                self.parse_type()
            if self.eat_p("="):
                self.parse_type()
            if not self.is_p(">"):
                self.expect_p(",")
        self.next()

    def parse_type_args(self):
        self.expect_p("<")
        while not self.is_p(">"):
            self.parse_type()
            if not self.is_p(">"):
                self.expect_p(",")
        self.next()
        return True

    # ---- expressions ----
    def parse_expression(self, no_in=False):
        line = self.ln
        expr = self.parse_maybe_assign(no_in)
        if self.is_p(","):
            exprs = [expr]
            while self.eat_p(","):
                exprs.append(self.parse_maybe_assign(no_in))
            return _n("SequenceExpression", line, expressions=exprs)
        return expr

    def parse_maybe_assign(self, no_in=False, ret_ok=True):
        """An assignment expression. ret_ok=False: `(x): T => …` is no arrow
        function with a return type here (a conditional's consequent, where
        `c ? (x) : y => z` reads as TypeScript reads it)."""
        self.enter()
        saved = self.ret_ok
        self.ret_ok = ret_ok
        expr = self.parse_maybe_assign_inner(no_in)
        self.ret_ok = saved
        self.depth -= 1
        return expr

    def parse_maybe_assign_inner(self, no_in):
        line, t, v = self.ln, self.t, self.v
        if t == "name" and not self.esc:
            if v == "yield" and self.in_gen:
                self.next()
                delegate = False
                arg = None
                if not self.nl:
                    delegate = self.eat_p("*")
                    if delegate or self.starts_expression():
                        arg = self.parse_maybe_assign(no_in)
                return _n("YieldExpression", line, argument=arg, delegate=delegate)
            pk, pv, pnl = self.peek()
            if pk == "p" and pv == "=>" and not pnl and v not in _RESERVED:
                return self.parse_arrow_rest([self.ident()], False, line)
            if v == "async" and not pnl:
                if pk == "name" and pv not in _RESERVED:
                    st = self.save()
                    self.next()
                    param = self.ident()
                    if self.is_p("=>") and not self.nl:
                        return self.parse_arrow_rest([param], True, line)
                    self.restore(st)
                elif self.ts and pk == "p" and pv == "<":
                    node = self.speculate(lambda: self.parse_generic_arrow(True, line))
                    if node is not None:
                        return node
        elif t == "p" and v == "<" and self.ts:
            node = self.speculate(lambda: self.parse_generic_arrow(False, line))
            if node is not None:
                return node
        left = self.parse_maybe_conditional(no_in)
        if self.t == "p":
            op = self.v
            if op == ">":
                op = self.gt_op()
                if op in (">>=", ">>>="):
                    self.take_gt()
            if op in _ASSIGN_OPS:
                target = self.to_pattern(left, False) if op == "=" else self.simple_target(left)
                self.next()
                right = self.parse_maybe_assign(no_in)
                return _n("AssignmentExpression", line, operator=op, left=target, right=right)
        return left

    def simple_target(self, node):
        if node["type"] in ("Identifier", "MemberExpression"):
            return node
        self.fail("invalid assignment target", node["line"])

    def starts_expression(self):
        t = self.t
        if t in ("name", "num", "bigint", "str", "tmpl", "priv", "regex"):
            return True
        return t == "p" and self.v in _EXPR_START_PUNCT

    def parse_generic_arrow(self, is_async, line):
        if is_async:
            self.next()
        self.parse_type_params()
        if not self.is_p("("):
            raise _Backtrack()
        saved = self.function_context(is_async, False)
        try:
            params = self.parse_params()
        finally:
            self.restore_context(saved)
        if self.is_p(":"):
            self.parse_return_type()
        if not self.is_p("=>") or self.nl:
            raise _Backtrack()
        return self.parse_arrow_rest(params, is_async, line)

    def parse_arrow_rest(self, params, is_async, line):
        """`=> body` (the current token)."""
        if self.nl or not self.is_p("=>"):
            self.fail()
        self.next()
        saved = self.function_context(is_async, False)
        try:
            if self.is_p("{"):
                body = self.parse_block()
                expression = False
            else:
                body = self.parse_maybe_assign()
                expression = True
        finally:
            self.restore_context(saved)
        return _n("ArrowFunctionExpression", line, id=None, params=params, body=body, expression=expression,
                  generator=False, **{"async": is_async})

    def parse_maybe_conditional(self, no_in):
        line = self.ln
        expr = self.parse_expr_ops(no_in)
        if self.is_p("?"):
            self.next()
            cons = self.parse_maybe_assign(False, False)
            self.expect_p(":")
            alt = self.parse_maybe_assign(no_in)
            return _n("ConditionalExpression", line, test=expr, consequent=cons, alternate=alt)
        return expr

    def binary_op(self, no_in):
        """(operator, precedence) of the current token as a binary
        operator, else (None, 0)."""
        t, v = self.t, self.v
        if t == "p":
            if v == ">":
                op = self.gt_op()
                if op == ">>=" or op == ">>>=":
                    return None, 0
                return op, _BINARY_PREC[op]
            prec = _BINARY_PREC.get(v)
            if prec is not None:
                return v, prec
            return None, 0
        if t == "name" and not self.esc:
            if v == "instanceof" or (v == "in" and not no_in):
                return v, 7
            if (v == "as" or v == "satisfies") and self.ts and not self.nl:
                return v, 7
        return None, 0

    def parse_expr_ops(self, no_in):
        """Binary operators by precedence: operands and operators on stacks,
        no recursion per operand."""
        line = self.ln
        left = self.parse_maybe_unary()
        if left["type"] == "ArrowFunctionExpression" and not (self.pt == "p" and self.pv == ")"):
            return left
        op, prec = self.binary_op(no_in)
        if op is None:
            return left
        operands = [(left, line)]              # (node, the line its first token is on)
        ops = []
        while op is not None:
            if op == "as" or op == "satisfies":
                while ops and ops[-1][1] >= prec:
                    _reduce(operands, ops)
                self.next()
                if self.is_n("const"):
                    self.next()
                else:
                    self.parse_type()
                op, prec = self.binary_op(no_in)
                continue
            while ops and (ops[-1][1] > prec or (ops[-1][1] == prec and op != "**")):
                _reduce(operands, ops)
            if self.v == ">":
                self.take_gt()
            ops.append((op, prec))
            self.next()
            oline = self.ln
            operands.append((self.parse_maybe_unary(), oline))
            op, prec = self.binary_op(no_in)
        while ops:
            _reduce(operands, ops)
        return operands[0][0]

    def parse_maybe_unary(self):
        prefix = []                        # (node type, operator, line), applied inside out
        line = self.ln
        while True:
            t, v = self.t, self.v
            if t == "p" and v in ("!", "~", "+", "-", "++", "--"):
                prefix.append(("UpdateExpression" if v in ("++", "--") else "UnaryExpression", v, self.ln))
                self.next()
            elif t == "name" and not self.esc and v in _UNARY_WORDS:
                prefix.append(("UnaryExpression", v, self.ln))
                self.next()
            elif t == "name" and not self.esc and v == "await" and self.await_here():
                prefix.append(("AwaitExpression", v, self.ln))
                self.next()
            elif t == "p" and v == "<" and self.ts and not self.jsx:
                self.next()                     # <T>expr: a type assertion
                self.parse_type()
                self.expect_p(">")
            else:
                break
            if len(prefix) > MAX_DEPTH:
                self.fail("nesting too deep")
        oline = self.ln if prefix else line
        expr = self.parse_expr_subscripts()
        if self.t == "p" and (self.v == "++" or self.v == "--") and not self.nl:
            expr = _n("UpdateExpression", oline, operator=self.v, prefix=False,
                      argument=self.simple_target(expr))
            self.next()
        for type_, op, pline in reversed(prefix):
            if type_ == "AwaitExpression":
                expr = _n("AwaitExpression", pline, argument=expr)
            elif type_ == "UpdateExpression":
                expr = _n("UpdateExpression", pline, operator=op, prefix=True, argument=self.simple_target(expr))
            else:
                expr = _n("UnaryExpression", pline, operator=op, prefix=True, argument=expr)
        return expr

    def await_here(self):
        """`await` as an operator: in an async function, or outside any
        function (a module's top level) when an operand follows on its line."""
        if self.in_async:
            return True
        if self.in_func:
            return False
        pk, pv, pnl = self.peek()
        if pnl:
            return False
        if pk in ("name", "num", "bigint", "str", "tmpl", "priv"):
            return pv not in ("in", "of", "instanceof", "as", "satisfies")
        return pk == "p" and pv in ("(", "[", "{", "!", "~", "+", "-", "++", "--", "/", "/=")

    def parse_expr_subscripts(self):
        line = self.ln
        expr = self.parse_expr_atom()
        if expr["type"] == "ArrowFunctionExpression" and not (self.pt == "p" and self.pv == ")"):
            return expr                          # `(a) => b` ends here: no call or member follows it
        return self.parse_subscripts(expr, line)

    def parse_subscripts(self, expr, line):
        chained = False
        while True:
            t, v = self.t, self.v
            if t == "p":
                if v == ".":
                    self.next()
                    prop = self.parse_property_name() if self.t == "priv" else self.ident(True)
                    expr = _n("MemberExpression", line, object=expr, property=prop, computed=False, optional=False)
                    continue
                if v == "?.":
                    chained = True
                    self.next()
                    if self.is_p("("):
                        expr = _n("CallExpression", line, callee=expr, arguments=self.parse_arguments(),
                                  optional=True)
                    elif self.is_p("["):
                        self.next()
                        prop = self.parse_expression()
                        self.expect_p("]")
                        expr = _n("MemberExpression", line, object=expr, property=prop, computed=True, optional=True)
                    elif self.is_p("<") and self.ts:
                        self.parse_type_args()
                        expr = _n("CallExpression", line, callee=expr, arguments=self.parse_arguments(),
                                  optional=True)
                    else:
                        prop = self.parse_property_name() if self.t == "priv" else self.ident(True)
                        expr = _n("MemberExpression", line, object=expr, property=prop, computed=False, optional=True)
                    continue
                if v == "[":
                    self.next()
                    prop = self.parse_expression()
                    self.expect_p("]")
                    expr = _n("MemberExpression", line, object=expr, property=prop, computed=True, optional=False)
                    continue
                if v == "(":
                    expr = _n("CallExpression", line, callee=expr, arguments=self.parse_arguments(), optional=False)
                    continue
                if v == "!" and self.ts and not self.nl:
                    self.next()                 # a non-null assertion
                    continue
                if v == "<" and self.ts and not self.nl:
                    if self.speculate(self.parse_type_args_in_expression) is not None:
                        if self.is_p("("):
                            expr = _n("CallExpression", line, callee=expr, arguments=self.parse_arguments(),
                                      optional=False)
                        continue
                break
            if t == "tmpl":
                if chained:
                    self.fail("tagged template in an optional chain")
                expr = _n("TaggedTemplateExpression", line, tag=expr, quasi=self.parse_template())
                continue
            break
        if chained:
            expr = _n("ChainExpression", line, expression=expr)
        return expr

    def parse_type_args_in_expression(self):
        """`<T>` after an expression, when TypeScript's rule lets type
        arguments stand there (else a _Backtrack: `a < b > c`)."""
        self.parse_type_args()
        t, v = self.t, self.v
        if t == "tmpl" or (t == "p" and v == "("):
            return True
        if t == "p" and v in ("<", ">", "+", "-"):
            raise _Backtrack()
        if self.nl or self.binary_op(False)[0] is not None or not self.starts_expression():
            return True
        raise _Backtrack()

    def parse_arguments(self):
        self.expect_p("(")
        args = []
        while not self.is_p(")"):
            if self.is_p("..."):
                line = self.ln
                self.next()
                args.append(_n("SpreadElement", line, argument=self.parse_maybe_assign()))
            else:
                args.append(self.parse_maybe_assign())
            if not self.is_p(")"):
                self.expect_p(",")
        self.next()
        return args

    def parse_template(self):
        line = self.ln
        quasis = []
        exprs = []
        while True:
            raw, tail = self.v
            quasis.append(_n("TemplateElement", self.ln, raw=raw, tail=tail))
            self.next()
            if tail:
                break
            exprs.append(self.parse_expression())
            self.rescan_template_continuation()
        return _n("TemplateLiteral", line, quasis=quasis, expressions=exprs)

    def parse_expr_atom(self):
        self.enter()
        expr = self.parse_expr_atom_inner()
        self.depth -= 1
        return expr

    def parse_expr_atom_inner(self):
        t, v, line = self.t, self.v, self.ln
        if t == "name":
            if not self.esc:
                if v == "function":
                    return self.parse_function(False, False, line)
                if v == "async":
                    pk, pv, pnl = self.peek()
                    if pk == "name" and pv == "function" and not pnl:
                        self.next()
                        return self.parse_function(False, True, line)
                    if pk == "p" and pv == "(" and not pnl:
                        return self.parse_async_call_or_arrow(line)
                if v == "class" or (v == "abstract" and self.peek()[1] == "class"):
                    return self.parse_class(False, [])
                if v == "new":
                    return self.parse_new()
                if v == "this":
                    self.next()
                    return _n("ThisExpression", line)
                if v == "super":
                    self.next()
                    return _n("Super", line)
                if v == "null":
                    self.next()
                    return _n("Literal", line, kind="null", value=None)
                if v == "true" or v == "false":
                    self.next()
                    return _n("Literal", line, kind="boolean", value=v == "true")
                if v == "import":
                    self.next()
                    if self.eat_p("."):
                        return _n("MetaProperty", line, meta=_n("Identifier", line, name="import"),
                                  property=self.ident(True))
                    self.expect_p("(")
                    source = self.parse_maybe_assign()
                    options = None
                    if self.eat_p(",") and not self.is_p(")"):
                        options = self.parse_maybe_assign()
                        self.eat_p(",")
                    self.expect_p(")")
                    return _n("ImportExpression", line, source=source, options=options)
                if v in _RESERVED:
                    self.fail()
            return self.ident(True)
        if t == "num" or t == "bigint":
            self.next()
            return _n("Literal", line, kind="number" if t == "num" else "bigint", value=v)
        if t == "str":
            self.next()
            return _n("Literal", line, kind="string", value=v)
        if t == "tmpl":
            return self.parse_template()
        if t == "priv":
            self.next()                         # `#x in obj`
            return _n("PrivateIdentifier", line, name=v)
        if t == "p":
            if v == "(":
                return self.parse_paren_or_arrow()
            if v == "[":
                return self.parse_array_literal()
            if v == "{":
                return self.parse_object_like()
            if v == "/" or v == "/=":
                self.rescan_regex()
                pattern, flags = self.v
                self.next()
                return _n("Literal", line, kind="regex", value=pattern, flags=flags)
            if v == "<" and self.jsx:
                self.enter()
                self.jsx_tag_next()
                node = self.parse_jsx_element(line, "expr")
                self.depth -= 1
                return node
            if v == "@":
                return self.parse_class(False, self.parse_decorators())
        self.fail()

    def parse_new(self):
        line = self.ln
        self.next()
        if self.eat_p("."):
            return _n("MetaProperty", line, meta=_n("Identifier", line, name="new"), property=self.ident(True))
        self.enter()
        cline = self.ln
        callee = self.parse_new() if self.is_n("new") else self.parse_expr_atom()
        while True:
            if self.is_p("."):
                self.next()
                prop = self.parse_property_name() if self.t == "priv" else self.ident(True)
                callee = _n("MemberExpression", cline, object=callee, property=prop, computed=False, optional=False)
            elif self.is_p("["):
                self.next()
                prop = self.parse_expression()
                self.expect_p("]")
                callee = _n("MemberExpression", cline, object=callee, property=prop, computed=True, optional=False)
            elif self.t == "tmpl":
                callee = _n("TaggedTemplateExpression", cline, tag=callee, quasi=self.parse_template())
            elif self.ts and self.is_p("!") and not self.nl:
                self.next()
            else:
                break
        if self.ts and self.is_p("<"):
            self.speculate(self.parse_type_args)
        args = self.parse_arguments() if self.is_p("(") else []
        self.depth -= 1
        return _n("NewExpression", line, callee=callee, arguments=args)

    def parse_async_call_or_arrow(self, line):
        """`async (…)`: an async arrow function's parameters, or a call of
        a function named async."""
        callee = self.ident(True)
        items = self.parse_paren_items()
        if self.is_p("=>") and not self.nl:
            return self.parse_arrow_rest(self.items_to_params(items), True, line)
        if self.is_p(":") and not self.nl and self.arrow_return_type_ahead(items):
            return self.parse_arrow_rest(self.items_to_params(items), True, line)
        if items["typed"]:
            self.fail()
        args = []
        for item in items["list"]:
            node = item["node"]
            if item["rest"]:
                node = _n("SpreadElement", node["line"], argument=node["argument"])
            args.append(node)
        return self.parse_subscripts(_n("CallExpression", line, callee=callee, arguments=args, optional=False),
                                     line)

    def parse_paren_or_arrow(self):
        line = self.ln
        items = self.parse_paren_items()
        if self.is_p("=>") and not self.nl:
            return self.parse_arrow_rest(self.items_to_params(items), False, line)
        if self.is_p(":") and not self.nl and self.arrow_return_type_ahead(items):
            return self.parse_arrow_rest(self.items_to_params(items), False, line)
        if items["trailing"] or not items["list"] or items["list"][-1]["rest"]:
            self.fail()
        if items["typed"] and not (len(items["list"]) == 1 and items["cast"]):
            self.fail()
        exprs = [item["node"] for item in items["list"]]
        if len(exprs) == 1:
            return exprs[0]
        return _n("SequenceExpression", items["line"], expressions=exprs)

    def arrow_return_type_ahead(self, items):
        """At `:` after `( … )`: the items are parameters, and a return type
        and `=>` follow (read ahead; `c ? (a) : b` is a conditional)."""
        if not self.ret_ok or not all(item["rest"] or _param_ok(item["node"]) for item in items["list"]):
            return False

        def attempt():
            self.parse_return_type()
            if not self.is_p("=>") or self.nl:
                raise _Backtrack()
            return True
        return self.speculate(attempt) is not None

    def parse_paren_items(self):
        """The contents of `( … )` read as expressions that may turn out to
        be arrow parameters: {list: [{rest, node}], typed, trailing}."""
        self.expect_p("(")
        out = {"list": [], "typed": False, "trailing": False, "cast": False}
        while not self.is_p(")"):
            line = self.ln
            if self.is_p("..."):
                self.next()
                target = self.parse_binding_target() if self.t != "name" or self.peek()[1] in (")", ",", ":", "?", "=") \
                    else self.parse_maybe_assign()
                self.eat_p("?")
                if self.eat_p(":"):
                    self.parse_type()
                    out["typed"] = True
                if self.eat_p("="):
                    self.parse_maybe_assign()
                    out["typed"] = True
                out["list"].append({"rest": True, "node": _n("RestElement", line, argument=target)})
                if not self.is_p(")"):
                    self.expect_p(",")
                continue
            if self.is_p("@"):
                self.parse_decorators()
                out["typed"] = True
            while self.t == "name" and self.v in _PARAM_MODIFIERS and not self.esc and self.peek()[0] == "name":
                self.next()
                out["typed"] = True
            if self.is_n("this"):
                pk, pv, _ = self.peek()
                if pk == "p" and pv == ":":
                    self.next()
                    self.next()
                    self.parse_type()
                    out["typed"] = True
                    if not self.is_p(")"):
                        self.expect_p(",")
                    continue
            if not out["list"]:
                out["line"] = self.ln
            typed = False
            if self.t == "name" and self.peek()[1] == "?" and self.look(self.optional_param_ahead, 2):
                node = self.ident()
                self.next()                      # ?
                typed = True
            else:
                node = self.parse_maybe_assign()
            if self.eat_p(":"):
                self.parse_type()
                if not typed:
                    out["cast"] = True           # (x: T): Flow's type cast, or a parameter
                typed = True
            if typed:
                out["typed"] = True
                if self.eat_p("="):
                    node = _n("AssignmentExpression", node["line"], operator="=", left=node,
                              right=self.parse_maybe_assign())
            out["list"].append({"rest": False, "node": node})
            if not self.is_p(")"):
                self.expect_p(",")
                if self.is_p(")"):
                    out["trailing"] = True
        self.next()
        return out

    def optional_param_ahead(self):
        """At `name ?`: `name?:`, `name?,`, `name?)` or `name?=` (an optional
        parameter, not a conditional expression)."""
        self.next()
        if not self.is_p("?"):
            return False
        self.next()
        return self.t == "p" and self.v in (":", ",", ")", "=")

    def items_to_params(self, items):
        return [item["node"] if item["rest"] else self.to_pattern(item["node"], True) for item in items["list"]]

    def to_pattern(self, node, binding):
        """An expression read again as an assignment target, or (binding)
        as a parameter."""
        t = node["type"]
        if t == "Identifier" or t in ("ObjectPattern", "ArrayPattern", "AssignmentPattern", "RestElement"):
            return node
        if t == "MemberExpression" and not binding:
            return node
        if t == "ObjectExpression":
            props = []
            for p in node["properties"]:
                if p["type"] == "SpreadElement":
                    props.append(_n("RestElement", p["line"], argument=self.to_pattern(p["argument"], binding)))
                    continue
                if p["kind"] != "init" or p["method"]:
                    self.fail("invalid destructuring target", p["line"])
                value = self.to_pattern(p["value"], binding)
                if "_cover" in p:
                    value = _n("AssignmentPattern", p["line"], left=value, right=p.pop("_cover"))
                props.append(_n("Property", p["line"], key=p["key"], value=value, kind="init", method=False,
                                shorthand=p["shorthand"], computed=p["computed"]))
            return _n("ObjectPattern", node["line"], properties=props)
        if t == "ArrayExpression":
            elements = []
            for el in node["elements"]:
                if el is None:
                    elements.append(None)
                elif el["type"] == "SpreadElement":
                    elements.append(_n("RestElement", el["line"], argument=self.to_pattern(el["argument"], binding)))
                else:
                    elements.append(self.to_pattern(el, binding))
            return _n("ArrayPattern", node["line"], elements=elements)
        if t == "AssignmentExpression" and node["operator"] == "=":
            return _n("AssignmentPattern", node["line"], left=self.to_pattern(node["left"], binding),
                      right=node["right"])
        self.fail("invalid destructuring target", node["line"])

    def parse_array_literal(self):
        line = self.ln
        self.next()
        elements = []
        while not self.is_p("]"):
            if self.is_p(","):
                self.next()
                elements.append(None)
                continue
            if self.is_p("..."):
                sline = self.ln
                self.next()
                elements.append(_n("SpreadElement", sline, argument=self.parse_maybe_assign()))
            else:
                elements.append(self.parse_maybe_assign())
            if not self.is_p("]"):
                self.expect_p(",")
        self.next()
        return _n("ArrayExpression", line, elements=elements)

    def parse_object_like(self):
        """An object literal (a pattern later, maybe: a shorthand with an
        initializer, `{ a = 1 }`, is kept for to_pattern)."""
        line = self.ln
        self.expect_p("{")
        props = []
        while not self.is_p("}"):
            self.enter()
            props.append(self.parse_object_member())
            self.depth -= 1
            if not self.is_p("}"):
                self.expect_p(",")
        self.next()
        return _n("ObjectExpression", line, properties=props)

    def parse_object_member(self):
        line = self.ln
        if self.is_p("..."):
            self.next()
            return _n("SpreadElement", line, argument=self.parse_maybe_assign())
        is_async = gen = False
        kind = "init"
        if self.t == "name" and not self.esc and self.v in ("async", "get", "set"):
            pk, pv, pnl = self.peek()
            if (pk in _KEY_KINDS or (pk == "p" and pv in ("[", "*"))) and not (self.v == "async" and pnl):
                if self.v == "async":
                    is_async = True
                else:
                    kind = self.v
                self.next()
        gen = self.eat_p("*")
        computed = False
        if self.is_p("["):
            self.next()
            key = self.parse_maybe_assign()
            self.expect_p("]")
            computed = True
        else:
            key = self.parse_property_name()
        if self.is_p("(") or self.is_p("<"):
            if self.is_p("<"):
                self.parse_type_params()
            fn = self.parse_method(is_async, gen)
            if fn is None:
                self.fail()
            return _n("Property", line, key=key, value=fn, kind=kind, method=kind == "init", shorthand=False,
                      computed=computed)
        if is_async or gen or kind != "init":
            self.fail()
        if self.eat_p(":"):
            return _n("Property", line, key=key, value=self.parse_maybe_assign(), kind="init", method=False,
                      shorthand=False, computed=computed)
        if computed or key["type"] != "Identifier":
            self.fail()
        node = _n("Property", line, key=key, value=_n("Identifier", key["line"], name=key["name"]), kind="init",
                  method=False, shorthand=True, computed=False)
        if self.is_p("="):
            self.next()                         # only valid in a pattern
            node["_cover"] = self.parse_maybe_assign()
            self.covers.append(node)
        return node

    # ---- JSX ----
    def jsx_tag_next(self):
        """The next token inside a JSX tag: names may hold '-', strings have
        no escapes."""
        src = self.src
        b = self.skip(self.e)
        if b >= self.n:
            self.t, self.v, self.e = "eof", "", b
            return
        c = src[b]
        if c == "'" or c == '"':
            m = _JSX_STR_RE[c].match(src, b)
            if m is None:
                self.fail("unterminated string")
            self.t, self.v, self.e = "str", src[b + 1:m.end() - 1], m.end()
            return
        m = _JSX_NAME_RE.match(src, b)
        if m is not None:
            self.t, self.v, self.e = "name", m.group(), m.end()
            return
        if c in "<>/{}=.:":
            self.t, self.v, self.e = "p", c, b + 1
            return
        self.fail("unexpected character " + _quote(c))

    def jsx_text_next(self):
        """The next child of a JSX element: text up to `{` or `<`, or one of
        them."""
        pos = self.e
        self.s = pos
        self.ln = self.line_at(pos)
        self.nl = False
        self.esc = False
        if pos >= self.n:
            self.t, self.v, self.e = "eof", "", pos
            return
        c = self.src[pos]
        if c == "{" or c == "<":
            self.t, self.v, self.e = "p", c, pos + 1
            return
        m = _JSX_TEXT_RE.match(self.src, pos)
        self.t, self.v, self.e = "jsxtext", m.group(), m.end()

    def parse_jsx_name(self):
        line = self.ln
        if self.t != "name":
            self.fail()
        name = _n("JSXIdentifier", line, name=self.v)
        self.jsx_tag_next()
        if self.is_p(":"):
            self.jsx_tag_next()
            if self.t != "name":
                self.fail()
            local = _n("JSXIdentifier", self.ln, name=self.v)
            self.jsx_tag_next()
            return _n("JSXNamespacedName", line, namespace=name, name=local)
        while self.is_p("."):
            self.jsx_tag_next()
            if self.t != "name":
                self.fail()
            prop = _n("JSXIdentifier", self.ln, name=self.v)
            self.jsx_tag_next()
            name = _n("JSXMemberExpression", line, object=name, property=prop)
        return name

    def jsx_end(self, where):
        """After an element's final `>`: the next token for where it was
        read (a regular token after an expression, a tag token after an
        attribute value, nothing for a child: its parent reads on)."""
        if where == "expr":
            self.next()
        elif where == "attr":
            self.jsx_tag_next()

    def parse_jsx_element(self, line, where):
        """An element or a fragment; the current token is the first one
        after its `<`, read in a tag."""
        if self.is_p(">"):
            children = self.parse_jsx_children()
            self.jsx_tag_next()
            if not self.is_p(">"):
                self.fail()
            self.jsx_end(where)
            return _n("JSXFragment", line, children=children)
        name = self.parse_jsx_name()
        if self.ts and self.is_p("<"):
            # a component's type arguments, read with the regular scanner
            self.next()
            depth = 1
            while True:
                if self.t == "eof":
                    self.fail()
                if self.is_p("<"):
                    depth += 1
                elif self.is_p(">"):
                    depth -= 1
                    if depth == 0:
                        break
                self.next()
            self.jsx_tag_next()
        attrs = []
        while not (self.is_p(">") or self.is_p("/")):
            aline = self.ln
            if self.is_p("{"):
                self.next()
                self.expect_p("...")
                arg = self.parse_maybe_assign()
                if not self.is_p("}"):
                    self.fail()
                self.jsx_tag_next()
                attrs.append(_n("JSXSpreadAttribute", aline, argument=arg))
                continue
            if self.t != "name":
                self.fail()
            aname = _n("JSXIdentifier", aline, name=self.v)
            self.jsx_tag_next()
            if self.is_p(":"):
                self.jsx_tag_next()
                if self.t != "name":
                    self.fail()
                aname = _n("JSXNamespacedName", aline, namespace=aname, name=_n("JSXIdentifier", self.ln, name=self.v))
                self.jsx_tag_next()
            value = None
            if self.is_p("="):
                self.jsx_tag_next()
                vline = self.ln
                if self.t == "str":
                    value = _n("Literal", vline, kind="string", value=self.v)
                    self.jsx_tag_next()
                elif self.is_p("{"):
                    self.next()
                    expr = self.parse_maybe_assign()
                    if not self.is_p("}"):
                        self.fail()
                    value = _n("JSXExpressionContainer", vline, expression=expr)
                    self.jsx_tag_next()
                elif self.is_p("<"):
                    self.enter()
                    self.jsx_tag_next()
                    value = self.parse_jsx_element(vline, "attr")
                    self.depth -= 1
                else:
                    self.fail()
            attrs.append(_n("JSXAttribute", aline, name=aname, value=value))
        if self.is_p("/"):
            self.jsx_tag_next()
            if not self.is_p(">"):
                self.fail()
            opening = _n("JSXOpeningElement", line, name=name, attributes=attrs, selfClosing=True)
            self.jsx_end(where)
            return _n("JSXElement", line, openingElement=opening, closingElement=None, children=[])
        opening = _n("JSXOpeningElement", line, name=name, attributes=attrs, selfClosing=False)
        children = self.parse_jsx_children()
        cline = self.closer_line
        self.jsx_tag_next()
        if self.is_p(">"):
            self.fail("unexpected closing fragment")
        cname = self.parse_jsx_name()
        if not self.is_p(">"):
            self.fail()
        if _jsx_name_text(cname) != _jsx_name_text(name):
            self.fail("mismatched closing tag")
        closing = _n("JSXClosingElement", cline, name=cname)
        self.jsx_end(where)
        return _n("JSXElement", line, openingElement=opening, closingElement=closing, children=children)

    def parse_jsx_children(self):
        """Children up to the `</` that closes them: the current token is
        the `>` of the opening tag; on return it is the `/` after the
        closer's `<` (self.closer_line: the `<`'s line)."""
        children = []
        while True:
            self.jsx_text_next()
            if self.t == "eof":
                self.fail("unterminated JSX contents")
            if self.t == "jsxtext":
                children.append(_n("JSXText", self.ln, value=self.v))
                continue
            if self.v == "{":
                cline = self.ln
                self.next()
                if self.is_p("}"):
                    children.append(_n("JSXExpressionContainer", cline, expression=_n("JSXEmptyExpression", cline)))
                elif self.is_p("..."):
                    self.next()
                    expr = self.parse_expression()
                    if not self.is_p("}"):
                        self.fail()
                    children.append(_n("JSXSpreadChild", cline, expression=expr))
                else:
                    expr = self.parse_expression()
                    if not self.is_p("}"):
                        self.fail()
                    children.append(_n("JSXExpressionContainer", cline, expression=expr))
                continue
            lt_line = self.ln                     # `<`
            self.jsx_tag_next()
            if self.is_p("/"):
                self.closer_line = lt_line
                return children
            self.enter()
            children.append(self.parse_jsx_element(lt_line, "child"))
            self.depth -= 1


def _param_ok(node):
    """Can a cover item be read as a parameter (to_pattern with binding)?"""
    stack = [node]
    while stack:
        n = stack.pop()
        t = n["type"]
        if t == "Identifier":
            continue
        if t == "AssignmentExpression":
            if n["operator"] != "=":
                return False
            stack.append(n["left"])
        elif t == "ObjectExpression":
            for p in n["properties"]:
                if p["type"] == "SpreadElement":
                    stack.append(p["argument"])
                elif p["kind"] != "init" or p["method"]:
                    return False
                else:
                    stack.append(p["value"])
        elif t == "ArrayExpression":
            for el in n["elements"]:
                if el is not None:
                    stack.append(el["argument"] if el["type"] == "SpreadElement" else el)
        elif t not in ("ObjectPattern", "ArrayPattern", "AssignmentPattern", "RestElement"):
            return False
    return True


def _reduce(operands, ops):
    right = operands.pop()[0]
    left, line = operands.pop()
    op = ops.pop()[0]
    operands.append((_n("LogicalExpression" if op in _LOGICAL else "BinaryExpression", line,
                        operator=op, left=left, right=right), line))


def _quote(text):
    """'text', the way both engines print it."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _jsx_name_text(node):
    t = node["type"]
    if t == "JSXIdentifier":
        return node["name"]
    if t == "JSXNamespacedName":
        return node["namespace"]["name"] + ":" + node["name"]["name"]
    return _jsx_name_text(node["object"]) + "." + node["property"]["name"]


def dialect(path):
    """(TypeScript, JSX) for a file name."""
    lower = path.lower()
    if lower.endswith((".ts", ".mts", ".cts")):
        return True, False
    if lower.endswith(".tsx"):
        return True, True
    return False, True


def parse(src, ts=False, jsx=True):
    """The Program node of `src`; JsSyntaxError when it cannot be read."""
    limit = sys.getrecursionlimit()
    if limit < _RECURSION:
        sys.setrecursionlimit(_RECURSION)
    try:
        return _Parser(src, ts, jsx).parse_program()
    except RecursionError:
        raise JsSyntaxError(1, "nesting too deep") from None
    finally:
        if limit < _RECURSION:
            sys.setrecursionlimit(limit)


def parse_file(path, src):
    """parse() in the dialect of the file name."""
    ts, jsx = dialect(path)
    return parse(src, ts, jsx)
