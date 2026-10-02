"""Inputs for the native Python parser's tests (test_pyparse_native*.py,
test_wasm_parity_pyparse.py): curated snippets of every construct and of the
errors, every construct that nests, seeded generated programs, token soups
and mutations of real files.

Inert text only: nothing here is executed.
"""
import os
import random

from tests import _support

# ---- curated snippets: every construct, and errors ----

STATEMENTS = [
    "", "\n", "   ", "# only a comment", "\n\n# c\n\n", "x", "x\n", "x = 1", "x = y = z = 1", "x: int", "x: int = 1",
    "(x): int = 1", "x.y: int", "x[0]: int = 1", "((x)): int", "x: 'str' = yield", "x += 1", "x -= 1", "x *= 1",
    "x @= 1", "x /= 1", "x %= 1", "x &= 1", "x |= 1", "x ^= 1", "x <<= 1", "x >>= 1", "x **= 1", "x //= 1",
    "(x) += 1", "x.y += 1", "x[1:2] += f()", "x += yield", "x = yield", "x = yield from y", "x = *a, *b",
    "a, b = c", "a, = b", "(a, b) = c", "[a, b] = c", "[a, *b] = c", "*a, b = c", "() = x", "[] = x",
    "a.b, c[d], *e = f", "a = b, c = d", "x = (yield)", "*a = 1", "[*a, *b] = x", "(*a,) = x", "x = *a",
    "pass", "break", "continue", "return", "return 1", "return 1, 2", "return *a, b", "return *a",
    "raise", "raise E", "raise E from e", "global a", "global a, b", "nonlocal a, b", "del a", "del a, b",
    "del a,", "del (a, b)", "del [a, b], c.d, e[f]", "del (a), [b]", "del ()", "del []", "assert x",
    "assert x, 'msg'", "import a", "import a.b.c", "import a as b, c.d as e", "import a . b",
    "from a import b", "from a import b as c, d", "from a import (b, c,)", "from . import a", "from .. import a",
    "from ... import a", "from .... import a", "from .a.b import *", "from a import *", "from . a import b",
    "x; y", "x; y;", "a = 1; b = 2", "type X = int", "type X[T] = list[T]", "type X[T: int, *Ts, **P] = T",
    "type X[T = int] = T", "type X[*Ts = *tuple[int]] = Ts", "type X[**P = [int]] = P", "type = 1",
    "type(x)", "type.x = 1", "type X[T,] = T", "print(x)", "print >>f, x", "exec(x)", "__debug__ = 1",
    "if x: pass", "if x:\n    pass\n", "if x:\n  a\nelif y:\n  b\nelif z:\n  c\nelse:\n  d\n", "if x: pass;",
    "if x: a; b;", "while x: pass", "while x:\n  pass\nelse:\n  pass\n", "for x in y: pass",
    "for x, y in z: pass", "for x, in y: pass", "for (x, y) in z: pass", "for [x, *y] in z: pass",
    "for x.y in z: pass", "for x[0] in z: pass", "for *x in y: pass", "for x in *a, b: pass",
    "for x in y:\n  pass\nelse:\n  pass\n", "async def f():\n  async for x in y: pass\n  async with a as b: pass\n",
    "with a: pass", "with a as b: pass", "with a as (b, c): pass", "with a as b.c, d as e[0]: pass",
    "with (a): pass", "with (a, b): pass", "with (a, b) as c: pass", "with (a as b): pass",
    "with (a as b, c as d,): pass", "with (a, b), c: pass", "with (yield): pass", "with (a for a in b): pass",
    "with (a := b): pass", "with (*a, b): pass", "with (): pass", "with (a) as b: pass", "with a as *b: pass",
    "with (a), (b): pass", "with (lambda: 1): pass", "with (a, b) as (c, d): pass", "with (a).b: pass",
    "try:\n  pass\nexcept:\n  pass\n", "try:\n  pass\nexcept E:\n  pass\n", "try:\n  pass\nexcept E as e:\n  pass\n",
    "try:\n  pass\nexcept (A, B) as e:\n  pass\nelse:\n  pass\nfinally:\n  pass\n",
    "try:\n  pass\nfinally:\n  pass\n", "try:\n  pass\nexcept* E:\n  pass\n",
    "try:\n  pass\nexcept* (A, B) as e:\n  pass\nexcept* C:\n  pass\nelse:\n  pass\nfinally:\n  pass\n",
    "def f(): pass", "def f(a, b): pass", "def f(a, b=1): pass", "def f(*a, **b): pass", "def f(a, /, b): pass",
    "def f(a, /): pass", "def f(a=1, /, b=2): pass", "def f(*, a): pass", "def f(*, a=1, b): pass",
    "def f(a: int, *b: str, c: float = 1.0, **d: bool) -> None: pass", "def f(*args: *Ts): pass",
    "def f(a,): pass", "def f(*a,): pass", "def f(**a,): pass", "def f[T](x: T) -> T: pass",
    "def f[T: (int, str), *Ts, **P](): pass", "def f[T = int, *Ts = *tuple[int], **P = [int]](): pass",
    "async def f(): await x", "async def f():\n  return [x async for x in y]\n",
    "@d\ndef f(): pass", "@d1\n@d2.e(f)\n@(lambda f: f)\n@x[0]\n@a if b else c\n@(yield)\ndef f(): pass",
    "@d\nasync def f(): pass", "@d\nclass A: pass", "class A: pass", "class A(): pass", "class A(B): pass",
    "class A(B, C, metaclass=M, **kw): pass", "class A(*bases): pass", "class A[T]: pass",
    "class A[T](B[T]): pass", "class A:\n  x = 1\n  def f(self): pass\n",
    "match x:\n  case 1: pass\n", "match x:\n  case 1:\n    pass\n  case _:\n    pass\n",
    "match x, y:\n  case a, b: pass\n", "match x,:\n  case a,: pass\n", "match *x, y:\n  case _: pass\n",
    "match (x):\n  case _: pass\n", "match x := y:\n  case _: pass\n", "match -x:\n  case _: pass\n",
    "match = 1", "match.x = 1", "match[x] = 1", "match(x)", "match * x", "match - x", "match x", "match: int = 1",
    "match (x)[0]: int = 3", "case = 1", "_ = 1", "match match:\n  case case: pass\n",
    "def f():\n  x = 1\n  return x\n", "def f():\n\n  # c\n\n  x\n", "class A:\n  pass\n\n\nclass B:\n  pass\n",
    "if x:\n    if y:\n        pass\n    else:\n        pass\n", "x = 1 \\\n  + 2", "x = (1 +\n2)", "x = [1,\n2,\n]",
    "x = {\n'a': 1,\n}", "if x:\n  pass\n  # c\n", "def f():\n  '''doc'''\n", "x = 1\r\ny = 2\r\n",
    "x = 1\ry = 2\r", "if x:\r\n  pass\r\n", "if x:\n\tpass\n", "if x:\n\tif y:\n\t\tpass\n",
    "if x:\n        pass\n", "if x:\n  \x0c  pass\n", "\x0cx = 1", "x = 1 # comment\n", "x = 1\n# end",
    "if x:\n    \\\npass", "if x:\n\\\n    pass",
]

EXPRESSIONS = [
    "1", "1.5", "1e10", "1E-5", "1.", ".5", "1_000", "0x_ff", "0o17", "0b101", "0", "00", "0_0", "0.0", "0e0",
    "09.5", "09j", "1j", "1.5J", "1e5j", "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "10**100",
    "1" * 300, "0x" + "f" * 5000, "0b" + "1" * 20000, "0o" + "7" * 6000, "1e400", "1e-400", "5e-324",
    "123456789012345678901234567890.123456789e-30", "1_0.0_1e1_0", "True", "False", "None", "...",
    "'a'", '"a"', "'''a'''", '"""a"""', "'a' 'b'", "'a' \"b\" '''c'''", "u'a'", "U'a'", "u'a' 'b'", "'a' u'b'",
    "r'\\n'", "R'\\n'", "b'a'", "B'a'", "br'\\n'", "rb'\\n'", "Rb'x'", "bR'x'", "b'a' b'b'", "'\\n\\t\\r\\a\\b\\f\\v'",
    "'\\x41\\101\\0\\777'", "'\\u00e9\\U0001F600'", "'\\N{BULLET}'", "'\\N{bullet}'", "'\\N{LATIN SMALL LETTER E WITH ACUTE}'",
    "'\\d\\w\\s'", "'\\\\'", "'\\''", '"\\""', "'a\\\nb'", "'''a\nb'''", "'''a\r\nb'''", "b'\\x80\\xff'",
    "'\\ud800'", "'\\udfff\\ud800'", "'\\ud83d\\ude00'", "'\\N{BOM}'", "'\\N{HANGUL SYLLABLE GAG}'",
    "'\\N{CJK UNIFIED IDEOGRAPH-4E00}'", "'\\N{TANGUT IDEOGRAPH-17000}'", "'é'", "'😀'", "'\\U00010000'",
    "b'\\N{BOM}'", "b'\\u1234'", "x", "_", "__x__", "é", "ﬁ", "ℕ", "x·y", "ｉｆ", "Ω", "_1", "a1",
    "a.b", "a.b.c", "a[1]", "a[1:2]", "a[1:2:3]", "a[:]", "a[::]", "a[::2]", "a[1:]", "a[:2]", "a[1,]",
    "a[1, 2]", "a[1:2, 3]", "a[*b]", "a[*b, c]", "a[b, *c]", "a[x := 1]", "a[(x := 1):2]", "a[...]",
    "a()", "a(b)", "a(b, c)", "a(*b)", "a(**b)", "a(b=1)", "a(b, *c, d=1, **e)", "a(*b, c)", "a(b=1, *c)",
    "a(**b, c=1)", "a(x for x in y)", "a((x for x in y))", "a(b)(c)", "a.b(c).d[e]", "a(b,)", "a(x := 1)",
    "a(b, x := 1)", "a(*b or c)", "a(**b or c)", "-x", "+x", "~x", "not x", "--x", "-+~x", "not not x",
    "x + y", "x - y", "x * y", "x / y", "x // y", "x % y", "x @ y", "x ** y", "x << y", "x >> y", "x & y",
    "x | y", "x ^ y", "x + y * z", "(x + y) * z", "x ** y ** z", "-x ** y", "x ** -y", "x ** -y ** z",
    "2 ** -2 ** -2", "a | b ^ c & d << e + f * g ** h", "x < y", "x < y < z", "x == y != z",
    "x in y", "x not in y", "x is y", "x is not y", "x < y <= z > w >= v", "x and y", "x or y",
    "x and y or z", "x or y and z", "not x and y", "x if y else z", "x if y else z if w else v",
    "(x if y else z) if w else v", "lambda: x", "lambda x: x", "lambda x, y=1, *z, w, **v: x",
    "lambda *, x: x", "lambda x, /: x", "lambda x, /, y: x", "lambda: (yield)", "lambda: lambda: x",
    "lambda x=lambda: 1: x", "x := 1", "(x := 1)", "(x := y := 1)", "[x := 1, y]", "{x := 1}",
    "await x", "await x.y", "await x ** 2", "-await x", "(yield)", "(yield x)", "(yield from x)",
    "(yield x, y)", "()", "(x)", "(x,)", "(x, y)", "(x, y,)", "((x))", "(*x, y)", "(x, *y)", "[]", "[x]",
    "[x, y,]", "[*x]", "[*x, *y]", "{}", "{x}", "{x, y}", "{*x}", "{x: y}", "{x: y, z: w}", "{**x}",
    "{**x, y: z}", "{x: y, **z}", "{**x, **y}", "[x for x in y]", "[x for x in y if z]",
    "[x for x in y if z if w]", "[x for x in y for z in w]", "[x async for x in y]", "{x for x in y}",
    "{x: y for x, y in z}", "(x for x in y)", "[(x, y) for x, y in z]", "[x for x, in y]",
    "[x for (x, y) in z]", "[x for x in (y := z)]", "[x := 1 for y in z]", "[x for x in y if (z := w)]",
    "f'a'", "f''", "f'{x}'", "f'{x!r}'", "f'{x!s}'", "f'{x!a}'", "f'{x:>10}'", "f'{x:{y}}'", "f'{x:{y}.{z}}'",
    "f'{x=}'", "f'{x = }'", "f'{x=!s}'", "f'{x=:10}'", "f'{x=!r:10}'", "f'{{}}'", "f'{{x}}'", "f'a{{'",
    "f'}}b'", "f'{x}{y}'", "f'a{x}b{y}c'", "f'{x}' 'a'", "'a' f'{x}'", "u'a' f'{x}'", "f'{x}' u'a'",
    "f'{\"a\"}'", "f\"{'a'}\"", "f'{'a'}'", "f'{f'{x}'}'", "f'''{x\n}'''", "f'{x\n}'", "f'''{\nx\n=\n}'''",
    "f'''{x # c\n}'''", "f'''{x # c\n=}'''", "f'{x:{{}}}'", "f'{x:a{{y}}b}'", "f'\\{x}'", "rf'\\{x}'",
    "f'\\N{BULLET}{x}'", "rf'\\N{x}'", "f'\\n{x}\\t'", "rf'\\n{x}'", "f'{x:\\n}'", "f'{x!r:}'", "f'{x:}'",
    "f'{*a}'", "f'{*a,}'", "f'{a, b}'", "f'{yield}'", "f'{yield x}'", "f'{await x}'", "f'{(x:=1)}'",
    "f'{x:=1}'", "f'{(lambda: 1)}'", "f'{x if y else z}'", "f'{ {1: 2} }'", "f'{a[1:2]}'", "f'{a!=b}'",
    "f'{a==b}'", "f'{a>=b}'", "f'{x!r:{y!s:}}'", "f'{x:{y:{z}}}'", "f'a\\\nb{c}'", "f'{x\\\n}'",
    "f'{x}' f'{y}' 'z'", "'' f''", "f'' ''", "f'{x}' ''", "'' f'{x}'", "f'{x}' u'' 'a'", "f'{x}' '' u'a'",
    "F'{x}'", "Rf'{x}'", "fR'{x}'", "FR'{x}'", "rF'{x}'", "f'{x}' 'y' f'{z!r}'", "f'{x:%Y-%m-%d %H:%M}'",
    "f'{x:{y}=}'", "f'{x:a:b}'", "f'{x:!}'", "f'{ x = !r:>5 }'", "f'{\"\\n\".join(a)}'",
    "f'{a}' f'''{b\n}''' f\"{c}\"", "(f'{a}'\n f'{b}')", "f'''\na{b}\nc'''", "f'{a!ｒ}'", "f'{a!ｓ:>3}'",
    "1if x else y", "[0x1for x in y]", "1_000if x else 2", "x = 1.5not in y", "0or 1", "1.5", "x = y\nz = 1or 2",
]

ERRORS = [
    "(", ")", "[", "]", "{", "}", "(]", "[)", "x = (1, 2", "def", "def f", "def f(", "def f():", "class",
    "if", "if x", "if x:", "if x:\npass", "x = ", "= 1", "1 = x", "x + 1 = 2", "f() = 1", "None = 1",
    "True = 1", "x.y() = 1", "(x, y) += 1", "[x] += 1", "*x += 1", "x, y: int", "[x]: int", "*x: int",
    "lambda: x = 1", "x if y else z = 1", "(x := 1) = 2", "x := 1", "def f(x=1, y): pass",
    "def f(*): pass", "def f(*, **k): pass", "def f(**k, a): pass", "def f(a, /, /): pass", "def f(/, a): pass",
    "def f(*a, *b): pass", "def f(*, a, /): pass", "lambda x=1, y: 1", "lambda *: 1", "f(a=1, b)",
    "f(**a, *b)", "f(**a, b)", "f(x for x in y, z)", "f(z, x for x in y)", "f(x for x in y,)", "f(a.b=1)",
    "f(a=1=2)", "a[x for x in y]", "class A(x for x in y): pass", "print 'x'", "exec 'x'", "print x",
    "`x`", "x <> y", "0777", "0b2", "0o8", "0x", "1__0", "1_", "1e", "1e+", "1.e+", "1_.5", "1._5",
    "1.__class__", "1L", "0xfL", "ur'x'", "bu'x'", "'abc", "'''abc", "'a\nb'", "b'é'", "'\\x4'",
    "'\\N{NOSUCHNAME}'", "'\\N'", "'\\N{'", "'\\N{}'", "'\\U00110000'", "'\\u12'", "'\\U1234'",
    "'a' b'b'", "b'a' 'b'", "f'{x}' b'y'", "f'{'", "f'}'", "f'{}'", "f'{ }'", "f'{x!}'", "f'{x!z}'",
    "f'{x! r}'", "f'{x!R}'", "f'{x!r=}'", "f'{x=y}'", "f'{lambda x: 1}'", "f'{a for a in b}'",
    "f'{x:{y:{z:{w}}}}'", "f'a\nb'", "f'{x:\n}'", "f'{#}'", "f'\\N{BULLET'", "f'{x}}'", "f'{{x}'",
    "f'{x)}'", "f'{\\'a\\'}'", "x\0", "\ufeffx = 1", "x\u00a0= 1", "€ = 1", "x = ²", "·x = 1", "$",
    "a ? b", "a ! b", "x = 1\x01", "\\", "x = 1 \\", "x = 1 \\\n", "x \\ y", "  x", "if x:\n pass\n  y",
    "if x:\n  pass\n y", "if x:\n\tpass\n        pass", "if x:\n        pass\n\tpass",
    "if x:\n    \tpass\n\tpass", "if x:\n  \x0cpass", "\\\n    x", "x\n  # c\n y", "else: pass", "elif x: pass",
    "except: pass", "finally: pass", "try: pass", "try:\n  pass\nelse:\n  pass\n",
    "try:\n  pass\nexcept:\n  pass\nexcept* E:\n  pass\n", "try:\n  pass\nexcept*:\n  pass\n",
    "except Exception, e: pass", "try:\n  pass\nexcept A, B:\n  pass\n", "with a as f(): pass",
    "with (a as b) as c: pass", "for x in y if z: pass", "for f() in y: pass", "for x + 1 in y: pass",
    "for (x in y) in z: pass", "for -x in y: pass", "for await x in y: pass", "del *a", "del f()",
    "del a + b", "del (a, *b)", "del a,,", "del", "from a import b,", "from a import (b,,)", "from a import ()",
    "import (a)", "import a,", "from import a", "from . import", "import a.b as c.d", "global", "global a,",
    "nonlocal", "assert", "raise from x", "return x y", "x y", "x = 1 2", "x;;", ";", "x = 1;;",
    "match x:\n  pass\n", "match x:\ncase 1: pass", "match *x:\n  case 1: pass\n", "match yield:\n  case 1: pass\n",
    "match x:\n  case *a: pass\n", "match x:\n  case (*a): pass\n", "match x:\n  case a as _: pass\n",
    "match x:\n  case -a: pass\n", "match x:\n  case 1 + 2: pass\n", "match x:\n  case 1j + 2j: pass\n",
    "match x:\n  case a.b(c=1, d): pass\n", "match x:\n  case {a: 1}: pass\n", "match x:\n  case {**_}: pass\n",
    "match x:\n  case {**a, 'b': 1}: pass\n", "match x:\n  case a=1: pass\n", "match x:\n  case f(): pass\n  pass\n",
    "type X = ", "type X[] = 1", "type X[*Ts: int] = 1", "type X[T] = *a", "def f[](): pass", "class A[]: pass",
    "async x", "async = 1", "await = 1", "def f(a, (b, c)): pass", "lambda (a): 1", "(*a)", "[*a for a in b]",
    "{*a for a in b}", "{**a for a in b}", "(*a for a in b)", "{a: *b}", "{*a: b}", "{a := 1: 2}",
    "{a: b := 1}", "a[1:x := 2]", "a[*b:c]", "@d\nx = 1", "@d\n", "@\ndef f(): pass", "def f() -> : pass",
    "class A(:): pass", "x = yield = y", "x = (yield) = y", "del (yield)", "for x in yield: pass",
    "(yield) = 1", "[x for x in y if a else b]", "[x for x in lambda: y]", "a if b", "a if b else",
    "lambda x: yield", "x = **a", "f(**)", "f(*)", "a.1", "a.if", "1 if x else", "not",
    "x not y", "x is not not y", "x < < y", "def f(a, b=1, /, c): pass", "if x:\n  pass\n else:\n  pass\n",
    "while x:\n  pass\nelse x:\n  pass\n", "x = [1, 2", "x = 'unterminated", "x = '''unterminated\n",
    "f'a{b'", "f'''{a\n", "a = b c", "if = 1", "class = 1", "def = 1", "x.class", "import if",
]

MATCH = [
    "match x:\n  case 1: pass\n", "match x:\n  case -1: pass\n", "match x:\n  case 1.5: pass\n",
    "match x:\n  case 1j: pass\n", "match x:\n  case -1j: pass\n", "match x:\n  case 1 + 2j: pass\n",
    "match x:\n  case -1 - 2j: pass\n", "match x:\n  case 'a': pass\n", "match x:\n  case 'a' 'b': pass\n",
    "match x:\n  case b'a': pass\n", "match x:\n  case f'{a}': pass\n", "match x:\n  case None: pass\n",
    "match x:\n  case True: pass\n", "match x:\n  case False: pass\n", "match x:\n  case a: pass\n",
    "match x:\n  case _: pass\n", "match x:\n  case a.b: pass\n", "match x:\n  case a.b.c: pass\n",
    "match x:\n  case (a): pass\n", "match x:\n  case (a, b): pass\n", "match x:\n  case (a,): pass\n",
    "match x:\n  case (): pass\n", "match x:\n  case []: pass\n", "match x:\n  case [a, b]: pass\n",
    "match x:\n  case [a, *b]: pass\n", "match x:\n  case [*_, a]: pass\n", "match x:\n  case a, *b: pass\n",
    "match x:\n  case *a, b: pass\n", "match x:\n  case a, b,: pass\n", "match x:\n  case {}: pass\n",
    "match x:\n  case {'a': 1}: pass\n", "match x:\n  case {'a': 1, **rest}: pass\n",
    "match x:\n  case {**rest}: pass\n", "match x:\n  case {1: a, -1: b, 1+2j: c, None: d, True: e}: pass\n",
    "match x:\n  case {a.b: 1}: pass\n", "match x:\n  case {'a': 1,}: pass\n", "match x:\n  case {**r,}: pass\n",
    "match x:\n  case A(): pass\n", "match x:\n  case A(a): pass\n", "match x:\n  case A(a, b): pass\n",
    "match x:\n  case A(a=1): pass\n", "match x:\n  case A(a, b=1, c=2): pass\n", "match x:\n  case A.B(a,): pass\n",
    "match x:\n  case a | b: pass\n", "match x:\n  case 1 | 2 | 3: pass\n", "match x:\n  case (1 | 2) as a: pass\n",
    "match x:\n  case 1 as a: pass\n", "match x:\n  case [1, 2] as a: pass\n", "match x:\n  case a if b: pass\n",
    "match x:\n  case a if (b := c): pass\n", "match x:\n  case [a, [b, (c, d)]]: pass\n",
    "match x:\n  case A(B(C(a))): pass\n", "match x:\n  case _.x: pass\n", "match x:\n  case _(): pass\n",
    "match x:\n  case ＿: pass\n", "match x:\n  case {**_}: pass\n", "match x:\n  case [*_]: pass\n",
    "match x:\n  case (*_,): pass\n", "match x:\n  case case: pass\n", "match x:\n  case match: pass\n",
    "match x:\n  case a.b(): pass\n", "match x:\n  case -0: pass\n", "match x:\n  case 0x10: pass\n",
    "match x:\n  case 1 if a else b: pass\n", "match x:\n  case [1, 2, *rest] if rest: pass\n  case _: pass\n",
    "match x:\n    case 1:\n        pass\n    case 2:\n        pass\n",
]


# errors whose line is the point: which error Python reports when there are
# several, and where (its parser takes tokens one at a time; its error pass)
ERROR_LINES = [
    # the parser stops before a token the tokenizer refuses: its error stands …
    "a b\n  c\n d\n", "a b\nf(\n  \\ x\n", "a b\nx = (\n", "a b\n\tif x:\n", "x = 1\n  y = 2\nz = (\n",
    "if x:\n    y\n  z\n", "  a b\nc\n",
    # … unless the rest of the text holds an error the tokenizer raises itself
    "a b\nc = 'unterminated\n", "a b\n'''abc\n", "a b\n1__0\n", "a b\n0b2\n", "a b\n0o8\n", "a b\n1.e+\n",
    "a b\n)\n", "a b\n(]\n", "a b\n\u20ac\n", "a b\n\x01\n", "a b\nx\u00b2\n", "a b\n" + "(" * 201 + "\n",
    "x = '\\N{NOSUCH}'\ny = 'unterminated", "a b\n0777\n",
    # (not inside an f-string; nor a string's escapes, which the parser reads)
    "a b\nf'{x!}'\n", "a b\nf'{'\n", "a b\nf'a\nb'\n", "f'{\n  not.->from\nnotmatch&\n\t", "a b\n'\\N{NOSUCH}'\n",
    # brackets left open on a line before the error's
    "x = (1,\n2 3\n", "(\na b\n", "(a b\n", "f(a,\n b c,\n", "[\n1\n2\n3\n", "def f(\n  a b\n", "x(\n1 2\n",
    # stray characters are tokens the parser refuses
    "a b\n$\n", "a b\n?\n", "a b\n`\n", "x = 1\n$\n",
    # the end of the text is on its last line
    "@d\n", "@d", "@d\n\n\n", "if x:\n", "if x:\n\n\n", "if x:\n  pass\nelse:\n\n# c\n", "x = 1\ny = 2 +\n\n\n",
    "class A:\npass\n", "def f():\n  x\n@d\n",
    # where the error pass reports: a missing comma, `print`, `if` without `else` …
    "f(a\n b)", "f(a,\n b\n c)", "[1\n 2]", "(a\n b)", "{a\n b}", "{a\n b: 1}", "{1: a\n b}", "f(a\n not b)",
    "f(a\n 1 +)", "f(a\n {})", "f(a\n f'x')", "f(a\n lambda: 1)", "x[a\n b]", "x[1:a\n b]", "f(a=1\n b)",
    "f(print\n x)", "f(x\n 'y')", "f(match\n x)", "x = (1 if 2\n 3)", "f(lambda: a\n b)", "f(a if b else c\n d)",
    "f(*a\n b)", "f(x for x in y\n z)", "[\n\t*a\n\tTrue{", "if (a\n b):\n pass",
    # … a target that is none, a mistaken `=` or `:=`
    "f() += 1 +", "f() += \\\n 1 +", "f() += \\\n (1 \n 2)", "(a, b) += \\\n 1", "(a, b): \\\n int",
    "(a, b): \\\n 1 +", "f() = \\\n 1 +", "x = f() = \\\n 1 +", "[a, b] += \\\n 1 if", "a + b += \\\n (1,\n 2",
    "x = ('a'\n 'b' = 1)", "if x\n = 1:\n pass", "f(a.b\n = 1)", "if (a.b\n := 1):\n pass",
    # … strings and f-strings
    "b'b''''a\nb'''class.yimport+x", "x = ('a'\n b'b')", "f'{True\r\n:=}import ^", "f'{a!rx\n)}'",
    "(~f'{\n  {\n\f;:Truetrydef(%", "f'{x:abc'\ny = (", "1.5=f'{\nas<\n\tyintryclassb'b'and1not_...asyncand \n",
    "raisef'{x}'Nonetypey-passtype<yieldglobal<<f'{\r\n==", "globalyorb'b'f'{(yNone#c\n [)**kclass)",
    # … a dict's key after its first item, not followed by `:`: at the key,
    # whatever follows it (the first item's are checked as elsewhere)
    "x = {'a': 1,\n 'b' c}", "{1: 1, 2\n 3: 4}", "{1: 1,\n 2 if 3}", "x = {'a': 1,\n c if d: 2}", "{**a,\n 2 3}",
    "x = {'a': 1,\n (c\n ) d: 2}", "x = {'a': 1,\n 'b'\n}", "x = {'a':\n}", "x = {'a': 1, 'b':\n}", "{2\n 3: 1}",
    "x = {\n'a': 1,\n'b' c\\'d': 2,\n}", "x = {'a': 1,\n 'b' c\\'d': 2}",
    # … the expression after another (Python's `expression_without_invalid`):
    # its failing trailers dropped, but an error in brackets it starts with is
    # the error
    "f(a) {\n b\n c}", "x = (u\n f(\n b c))", "[u g(\n b c)]", "[u -g(\n b c)]", "[u not g(\n b c)]",
    "x = (u\n {\n b c})", "[f(a) g[\n b c]]", "a.b {\nx y\n}", "x = 1\nf(a) {{\n let lo = 0, hi = 1;\n}}",
    # … an f-string field that reads in part: after its first atom
    "f\"{p.stderr[-200#0:]}\"\nx = 1\n", "f'{a.b[1 # c\n}'\nx = 1\n",
    # … a block that is missing ("expected an indented block") is Python's
    # own error: an error its tokenizer raises further on takes its place
    # (not the generic "unexpected unindent")
    "class A:\n    def f(self):\nx = 1\nz = 'unterminated", "if a:\n    try:\n        pass\nw = 1\nw = 'u",
    "if a:\n    match x:\n        case 1:\nw = 1\nw = 'u", "class A:\n    def f(self):\nx = 1\nz = 1abc",
    "class A:\n    @d\nx = 1\nz = 'unterminated", "class A:\n    def f(self):\nx = 1\nz = (",
    # Python's errors without a line: a NUL, what it cannot encode
    "x = 1\ny\0", "x = 1\ny = '\ud800'",
]


def items():
    """Every curated snippet."""
    return STATEMENTS + EXPRESSIONS + ERRORS + MATCH + ERROR_LINES


# ---- the constructs that nest ----

def nest(head, opener, middle, closer, tail=""):
    return lambda k: head + opener * k + middle + closer * k + tail


def blocks(head, k, body):
    return "".join(" " * i + head for i in range(k)) + " " * k + body


# (name, the source nested k deep, the deepest Python 3.13 reads): the
# engine reads exactly as deep — the tokenizer's limits (200 brackets, 99
# indentation levels, 149 f-strings), its parser's stack (6000 rule calls:
# `not`, `-`, `lambda`, `**`, `elif` …), the tree's depth (9,997 nodes: what
# ast converts)
NESTINGS = [
    ("parentheses", nest("", "(", "x", ")"), 200),
    ("lists", nest("", "[", "x", "]"), 200),
    ("sets", nest("", "{", "x", "}"), 200),
    ("dicts", nest("", "{1: ", "x", "}"), 200),
    ("tuples", nest("", "(x, ", "x", ")"), 199),
    ("calls", nest("", "f(", "x", ")"), 200),
    ("subscripts", nest("", "a[", "x", "]"), 200),
    ("not", nest("", "not ", "x", ""), 5969),
    ("minus", nest("", "-", "x", ""), 5969),
    ("invert", nest("", "~", "x", ""), 5969),
    ("lambda", nest("", "lambda: ", "x", ""), 2984),
    ("conditional", nest("", "a if b else ", "c", ""), 5969),
    ("power", nest("", "a ** ", "a", ""), 2984),
    ("await", nest("", "await (", "x", ")"), 200),
    ("f-strings", nest("", "f'{", "x", "}'"), 149),
    ("nested f-strings in a format specifier", lambda k: "f'{x:{" + "f'{" * k + "1" + "}'" * k + "}}'", 148),
    ("if", lambda k: blocks("if x:\n", k, "pass\n"), 99),
    ("elif", lambda k: "if a: pass\n" + "elif b: pass\n" * k, 5965),
    ("def", lambda k: blocks("def f():\n", k, "pass\n"), 99),
    ("blocks and parentheses", lambda k: blocks("if x:\n", 98, "(" * k + "x" + ")" * k + "\n"), 193),
    ("patterns", lambda k: "match x:\n case " + "[" * k + "a" + "]" * k + ": pass\n", 200),
    ("class patterns", lambda k: "match x:\n case " + "A(" * k + "a" + ")" * k + ": pass\n", 200),
    ("keyword patterns", lambda k: "match x:\n case " + "A(a=" * k + "1" + ")" * k + ": pass\n", 200),
    ("mapping patterns", lambda k: "match x:\n case " + "{1: " * k + "a" + "}" * k + ": pass\n", 200),
    ("or patterns", lambda k: "match x:\n case " + "(1 | " * k + "2" + ")" * k + ": pass\n", 200),
    ("lambda defaults", nest("", "lambda a=", "1", ": 0"), 746),
    ("calls of lambdas", nest("", "f(lambda: ", "x", ")"), 200),
    ("dict values", nest("", "{1: ", "x", "}"), 200),
    ("slices", nest("", "a[1:", "x", "]"), 200),
    ("generator arguments", lambda k: "f(" * k + "x for x in y" + ")" * k, 200),
    ("keyword arguments", nest("", "f(a=", "x", ")"), 200),
    ("star targets", lambda k: "for " + "[*" * k + "a" + "]" * k + " in x: pass", 200),
    ("assignment targets", lambda k: "(" * k + "a, b" + ")" * k + " = x", 200),
    ("with items", lambda k: "with (" + "(" * k + "a" + ")" * k + " as b): pass", 199),
    ("type parameters", lambda k: "def f[T: " + "list[" * k + "int" + "]" * k + "](): pass", 199),
    ("decorators", lambda k: "@" + "f(" * k + "x" + ")" * k + "\ndef g(): pass\n", 200),
    ("annotations", lambda k: "def f(a: " + "list[" * k + "int" + "]" * k + "): pass", 199),
    ("chained +", lambda k: "a" + " + a" * k, 9994),
    ("attributes", lambda k: "a" + ".b" * k, 9994),
    ("call chains", lambda k: "a" + "()" * k, 9994),
    ("subscript chains", lambda k: "a" + "[0]" * k, 9994),
]

# (name, source, the deepest the engine reads, the deepest Python reads):
# where the engine's estimate of Python's parser stack is stricter than
# Python (never more lenient)
STRICTER = [
    ("lambda default bodies", nest("", "lambda a=lambda: ", "1", ": 0"), 542, 596),
    ("blocks and lambdas", lambda k: blocks("def f():\n", 98, "lambda a=" * k + "1" + ": 0" * k + "\n"), 648, 660),
    ("f-string parentheses", lambda k: "f'{" * 100 + "(" * k + "x" + ")" * k + "}'" * 100, 95, 96),
    ("comprehensions", nest("", "[x for x in ", "y", "]"), 199, 200),
]

# (before, after): contexts for a chain of `not`s, each one more rule call
# deep in Python's parser: the engine reads no longer a chain there than
# Python, and not much shorter. Among them, where Python's depth depends on
# the way it first reads a construct: an f-string read first as a possible
# assignment target (at a statement's start, an assignment value's) or not;
# a line Python reads as a match statement first; type parameters' bounds;
# assignment expressions; a slice's step.
INNERMOST = [
    ("", ""), ("x = ", ""), ("print(", ")"), ("(", ")"), ("((", "))"), ("[", "]"), ("x = (", ")"),
    ("f'{", "}'"), ("x = f'{", "}'"), ("'a' f'{", "}'"), ("(f'{", "}')"), ("((f'{", "}'))"), ("[f'{", "}']"),
    ("print(f'{", "}')"), ("x = (f'{", "}')"), ("x += f'{", "}'"), ("x: int = f'{", "}'"),
    ("if (f'{", "}'): pass"), ("print(f'{x:{", "}}')"), ("a, f'{", "}'"), ("f'{a}' + f'{", "}'"),
    ("print(" + "(f'{" * 3, "}')" * 3 + ")"), ("def f():\n return f'{", "}'"), ("@f'{", "}'\ndef f(): pass"),
    ("match(", ")"), ("match[", "]"), ("match((", "))"), ("match(a)(", ")"), ("match - (", ")"),
    ("match(f'{", "}')"), ("x = match(", ")"), ("type(", ")"), ("match a, ", ":\n case 1: pass"),
    ("type X[T: ", "] = int"), ("type X[T: (", ")] = int"), ("type X[*T = ", "] = int"),
    ("def f[T = ", "](): pass"), ("class A[T: ", "]: pass"),
    ("(y := ", ")"), ("(y := (y := (y := ", ")))"), ("a[y := ", "]"), ("if y := ", ": pass"),
    ("type X[T: {a: a[::{1: a and ", "}] for a in b}] = int"), ("(y := (y := f(", " for a in b)))"),
    ("try:\n    pass\nexcept* a[::", "]:\n    pass"), ("(a, b, c, a[::", "])"), ("with (a, b, a[::a[", "]]): pass"),
]

# ---- seeded random programs ----

NAMES = ["a", "b", "x", "y", "self", "match", "case", "type", "_", "print", "é", "ﬁ"]


class Gen:
    """Random programs from the grammar (valid by construction, mostly)."""

    def __init__(self, rng):
        self.r = rng

    def name(self):
        return self.r.choice(NAMES)

    def atom(self, d):
        r = self.r
        k = r.randrange(16)
        if d > 2 or k < 4:
            return r.choice([self.name(), self.name(), str(r.randrange(1000)), repr(r.random()), "None", "True",
                             "...", "1j", "0x1F", "'s'", "b'b'", "f'{x}'", "'\\n'", "u'u'"])
        if k == 4:
            return "(" + self.expr(d + 1) + ")"
        if k == 5:
            return "[" + ", ".join(self.expr(d + 1) for _ in range(r.randrange(4))) + "]"
        if k == 6:
            return "{" + ", ".join(f"{self.expr(d + 1)}: {self.expr(d + 1)}" for _ in range(r.randrange(3))) + "}"
        if k == 7:
            return "(" + ", ".join(self.expr(d + 1) for _ in range(r.randrange(1, 4))) + ",)"
        if k == 8:
            # (a comprehension's iterable and conditions are disjunctions)
            return f"[{self.expr(d + 1)} for {self.name()} in ({self.expr(d + 1)})" + \
                (f" if ({self.expr(d + 1)})" if r.random() < 0.5 else "") + "]"
        if k == 9:
            return f"f'{{ {self.expr(d + 1)} }}x{{{self.name()}!r:>{r.randrange(9)}}}'"
        if k == 10:
            a = self.atom(d + 1)
            return f"({a}).{self.name()}" if a.isdigit() else f"{a}.{self.name()}"
        if k == 11:
            return f"{self.atom(d + 1)}({self.args(d + 1)})"
        if k == 12:
            return f"{self.atom(d + 1)}[{self.expr(d + 1)}:{self.expr(d + 1)}]"
        if k == 13:
            return f"(lambda {self.name()}: {self.expr(d + 1)})"
        if k == 14:
            return "{" + ", ".join(self.expr(d + 1) for _ in range(r.randrange(1, 4))) + "}"
        return f"({self.expr(d + 1)} if ({self.expr(d + 1)}) else {self.expr(d + 1)})"

    def args(self, d):
        r = self.r
        parts = [self.expr(d) for _ in range(r.randrange(3))]
        if r.random() < 0.3:
            parts.append("*" + self.atom(d))
        if r.random() < 0.3:
            parts.append(f"{self.name()}={self.expr(d)}")
        if r.random() < 0.2:
            parts.append("**" + self.atom(d))
        return ", ".join(parts)

    def expr(self, d=0):
        r = self.r
        k = r.randrange(10)
        if d > 2 or k < 5:
            return self.atom(d)
        if k == 5:
            return f"{self.atom(d)} {r.choice(['+', '-', '*', '/', '//', '%', '**', '<<', '>>', '&', '|', '^', '@'])} " \
                   f"{self.atom(d)}"
        if k == 6:
            return f"{self.atom(d)} {r.choice(['<', '>', '==', '!=', 'in', 'not in', 'is', 'is not'])} {self.atom(d)}"
        if k == 7:
            return f"{self.atom(d)} {r.choice(['and', 'or'])} {self.atom(d)}"
        if k == 8:
            return f"{r.choice(['not ', '-', '+', '~'])}{self.atom(d)}"
        return f"{self.atom(d)} if {self.atom(d)} else {self.atom(d)}"

    def target(self):
        r = self.r
        k = r.randrange(5)
        if k == 0:
            return f"{self.name()}, {self.name()}"
        if k == 1:
            return f"{self.name()}.{self.name()}"
        if k == 2:
            return f"{self.name()}[{self.expr(3)}]"
        if k == 3:
            return f"[{self.name()}, *{self.name()}]"
        return self.name()

    def simple(self):
        r = self.r
        k = r.randrange(14)
        if k < 4:
            return f"{self.target()} = {self.expr()}"
        if k == 4:
            return f"{self.name()} {r.choice(['+=', '-=', '*=', '|=', '**=', '//='])} {self.expr()}"
        if k == 5:
            return f"{self.name()}: {self.expr(3)} = {self.expr()}"
        if k == 6:
            return "return " + self.expr()
        if k == 7:
            return r.choice(["pass", "break", "continue", "global a", "nonlocal b", "del a, b[0]", "raise E from e"])
        if k == 8:
            return r.choice(["import os", "import a.b as c", "from . import x", "from .m import (a, b as c)"])
        if k == 9:
            return "assert " + self.expr() + ", 'm'"
        if k == 10:
            return "yield " + self.expr()
        return self.expr()

    def block(self, ind, d):
        r = self.r
        out = []
        for _ in range(r.randrange(1, 4)):
            out.append(self.stmt(ind, d + 1))
        return "".join(out)

    def stmt(self, ind, d=0):
        r = self.r
        pad = " " * ind
        k = r.randrange(12)
        if d > 3 or k < 5:
            line = "; ".join(self.simple() for _ in range(r.randrange(1, 3)))
            return pad + line + "\n"
        n = ind + r.choice([1, 2, 4])
        if k == 5:
            s = f"{pad}if {self.expr()}:\n{self.block(n, d)}"
            if r.random() < 0.5:
                s += f"{pad}elif {self.expr()}:\n{self.block(n, d)}"
            if r.random() < 0.5:
                s += f"{pad}else:\n{self.block(n, d)}"
            return s
        if k == 6:
            return f"{pad}for {self.target()} in {self.expr()}:\n{self.block(n, d)}"
        if k == 7:
            return f"{pad}while {self.expr()}:\n{self.block(n, d)}"
        if k == 8:
            deco = f"{pad}@{self.name()}\n" if r.random() < 0.3 else ""
            return f"{deco}{pad}{r.choice(['', 'async '])}def {self.name()}({self.name()}, *, {self.name()}=1):\n" \
                   f"{self.block(n, d)}"
        if k == 9:
            return f"{pad}class {self.name()}({self.name()}):\n{self.block(n, d)}"
        if k == 10:
            return f"{pad}try:\n{self.block(n, d)}{pad}except {self.name()} as e:\n{self.block(n, d)}" \
                   f"{pad}finally:\n{self.block(n, d)}"
        return f"{pad}with {self.expr()} as {self.name()}, {self.expr()}:\n{self.block(n, d)}"

    def program(self):
        return "".join(self.stmt(0) for _ in range(self.r.randrange(1, 8)))


def programs(seed, n):
    rng = random.Random(seed)
    g = Gen(rng)
    return [g.program() for _ in range(n)]


# ---- token soups and mutations ----

PIECES = [
    "x", "y", "1", "1.5", "'s'", '"t"', "f'{x}'", "b'b'", "(", ")", "[", "]", "{", "}", ":", ",", ";", ".", "=",
    "==", "+", "-", "*", "**", "/", "//", "%", "@", "<", ">", "<=", "!=", "->", ":=", "~", "^", "&", "|", "<<",
    "if", "else", "elif", "for", "in", "while", "def", "class", "return", "lambda", "not", "and", "or", "is",
    "with", "as", "try", "except", "finally", "import", "from", "yield", "await", "async", "pass", "None",
    "True", "match", "case", "type", "_", "global", "del", "raise", "assert", "\n", "\n    ", "\n  ", "\n\t",
    " ", " ", " ", "#c\n", "\\\n", "'''a\nb'''", "f'{", "}'", "!r", "*a", "**k", "...", "\r\n", "\x0c",
]


def soups(seed, n):
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        k = rng.randrange(1, 40)
        s = "".join(rng.choice(PIECES) for _ in range(k))
        if rng.random() < 0.05:
            s += chr(rng.choice([0xE9, 0x2603, 0x10000, 0xD800, 0, 0x85, 0x2028, 0xFEFF, 0x1F600]))
        out.append(s)
    return out


def mutations(sources, seed, n):
    """Real files with a few characters deleted, doubled or swapped."""
    rng = random.Random(seed)
    out = []
    sources = [s for s in sources if s]
    if not sources:
        return out
    for _ in range(n):
        s = rng.choice(sources)
        if len(s) > 3000:
            a = rng.randrange(len(s) - 3000)
            s = s[a:a + 3000]
        chars = list(s)
        for _ in range(rng.randrange(1, 4)):
            if not chars:
                break
            i = rng.randrange(len(chars))
            op = rng.randrange(4)
            if op == 0:
                del chars[i]
            elif op == 1:
                chars.insert(i, chars[i])
            elif op == 2:
                j = rng.randrange(len(chars))
                chars[i], chars[j] = chars[j], chars[i]
            else:
                chars.insert(i, rng.choice(["(", ")", ":", "\n", " ", "'", "\"", "\\", "#", ",", "=", "\t"]))
        out.append("".join(chars))
    return out


def own_sources():
    """The repository's Python sources and tests (as text: UTF-8, as Python reads them)."""
    out = []
    for base in (os.path.join(_support.REPO_ROOT, "python"), os.path.join(_support.REPO_ROOT, "scripts")):
        for root, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d != "__pycache__")
            for fn in sorted(files):
                if fn.endswith(".py"):
                    with open(os.path.join(root, fn), "rb") as f:
                        data = f.read()
                    out.append(data.decode("utf-8", "surrogateescape"))
    return out
