"""The oracle of the native Python parser's tests: Python 3.13's `ast.parse`,
run in a `python3.13` subprocess (the suite runs on Python 3.10 to 3.14),
its trees written as JSON text the way the engine's `py_parse` writes them
(rust/crates/lazaret-engine/src/pyparse/out.rs): `_type`, the fields in
`_fields` order, the positions; a Constant's value tagged by its type (ints
in decimal up to 16384 bits, floats as float.hex()). Written without
recursion: a tree may be as deep as its input is long.

Nothing here parses with the running Python's own `ast` (it may not be 3.13),
and nothing is executed: the sources are only parsed.
"""
import ctypes
import functools
import json
import os
import shutil
import struct
import subprocess
import sys

from lazaret.scanner import _native

# the dumper, run by python3.13: a JSON list of sources on stdin, a JSON list
# of answers out
DUMPER = r'''
import ast, json, sys, warnings
sys.set_int_max_str_digits(0)
warnings.simplefilter("ignore")


def const(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is Ellipsis:
        return '{"Ellipsis":true}'
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, bytes):
        return '{"bytes":"%s"}' % v.hex()
    if isinstance(v, int):
        return '{"int":%s}' % json.dumps(str(v) if v.bit_length() <= 16384 else hex(v))
    if isinstance(v, float):
        return '{"float":"%s"}' % v.hex()
    if isinstance(v, complex):
        return '{"complex":["%s","%s"]}' % (v.real.hex(), v.imag.hex())
    raise TypeError(type(v).__name__)


def dump(tree):
    out = []
    stack = [(0, tree)]
    while stack:
        kind, x = stack.pop()
        if kind == 1:
            out.append(x)
        elif kind == 2:
            out.append(const(x))
        elif x is None:
            out.append("null")
        elif isinstance(x, ast.AST):
            name = type(x).__name__
            tasks = [(1, '{"_type":"%s"' % name)]
            for f in x._fields:
                v = getattr(x, f, None)
                tasks.append((1, ',"%s":' % f))
                if f == "value" and name in ("Constant", "MatchSingleton"):
                    tasks.append((2, v))
                elif isinstance(v, list):
                    tasks.append((1, "["))
                    for i, item in enumerate(v):
                        if i:
                            tasks.append((1, ","))
                        tasks.append((0, item))
                    tasks.append((1, "]"))
                elif v is None or isinstance(v, ast.AST):
                    tasks.append((0, v))
                elif isinstance(v, int):
                    tasks.append((1, str(v)))
                elif isinstance(v, str):
                    tasks.append((1, json.dumps(v)))
                else:
                    raise TypeError(type(v).__name__)
            for a in x._attributes:
                v = getattr(x, a, None)
                tasks.append((1, ',"%s":%s' % (a, "null" if v is None else v)))
            tasks.append((1, "}"))
            stack.extend(reversed(tasks))
        elif isinstance(x, str):
            out.append(json.dumps(x))
        else:
            raise TypeError(type(x).__name__)
    return "".join(out)


def answer(src):
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError) as e:
        line = getattr(e, "lineno", None) or 0
        return '{"error":{"line":%d,"reason":%s}}' % (line, json.dumps("%s: %s" % (type(e).__name__, e)))
    try:
        return dump(tree)
    except RecursionError as e:
        return '{"error":{"line":0,"reason":%s}}' % json.dumps("RecursionError: %s" % e)


def main():
    sources = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    out = [answer(s) for s in sources]
    sys.stdout.buffer.write(json.dumps(out).encode("ascii"))


main()
'''


def python313():
    """The Python 3.13 to compare with: LAZARET_PYTHON313, the running Python
    if it is 3.13, else python3.13 on the PATH (None if there is none)."""
    env = os.environ.get("LAZARET_PYTHON313")
    if env:
        return env if os.path.isfile(env) else None
    if sys.version_info[:2] == (3, 13):
        return sys.executable
    return shutil.which("python3.13")


PYTHON313 = python313()
SKIP = "Python 3.13 is not installed (python3.13 on the PATH, or LAZARET_PYTHON313): its ast is the oracle"

# CPython's C recursion limit bounds the trees its ast converts: 10000 on
# Linux and macOS, where ast.parse reads a tree 9,997 nodes deep, but 3000 on
# Windows, where it refuses one deeper than 2,997 nodes (a RecursionError),
# and so does its compiler. On every platform, the engine reads what Python
# reads on Linux and macOS, so a scan's answer doesn't depend on where it
# runs. Against an oracle with a lower limit, the comparisons that a tree's
# depth decides are skipped.
SHALLOW = ("this Python's ast refuses trees that Python reads on Linux and macOS (its C recursion limit is lower, "
           "as on Windows): the engine reads them, and is compared with Python on those platforms")


@functools.lru_cache(maxsize=None)
def deep_trees():
    """Does the oracle's ast convert trees as deep as on Linux and macOS (a
    chain of 9,994 `+`s: NESTINGS' "chained +" at its deepest)?"""
    return not is_error(oracle(["a" + " + a" * 9994])[0])


def too_deep(answer):
    """Is the answer the RecursionError of an oracle whose ast converts
    shallower trees than on Linux and macOS (see deep_trees)?"""
    return (is_error(answer) and json.loads(answer)["error"]["reason"].startswith("RecursionError")
            and not deep_trees())


def oracle(sources, timeout=40):
    """ast.parse's answer for each source, as JSON text (or {"error": …})."""
    if not sources:
        return []
    data = json.dumps(list(sources)).encode("utf-8", "surrogatepass")
    p = subprocess.run([PYTHON313, "-c", DUMPER], input=data, capture_output=True, timeout=timeout)
    if p.returncode:
        raise AssertionError(f"the oracle exited {p.returncode}: {p.stderr[-2000:]!r}")
    return json.loads(p.stdout.decode("ascii"))


# the deepest chain ast.parse reads in each context: a JSON list of
# [before, unit, middle, after, most] on stdin, the largest k (at most `most`)
# with before + unit * k + middle + after read, or -1, out
DEEPEST = r'''
import ast, json, sys, warnings
warnings.simplefilter("ignore")


def reads(src):
    try:
        ast.parse(src)
        return True
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False


out = []
for before, unit, middle, after, most in json.loads(sys.stdin.read()):
    lo, hi = -1, most + 1
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if reads(before + unit * mid + middle + after):
            lo = mid
        else:
            hi = mid
    out.append(lo)
print(json.dumps(out))
'''


def deepest(contexts, unit="not ", middle="x", most=6000, timeout=40):
    """For each (before, after), the most `unit`s ast.parse reads between
    them (before `middle`), or -1."""
    jobs = [[before, unit, middle, after, most] for before, after in contexts]
    p = subprocess.run([PYTHON313, "-c", DEEPEST], input=json.dumps(jobs).encode("utf-8"), capture_output=True,
                       timeout=timeout)
    if p.returncode:
        raise AssertionError(f"the oracle exited {p.returncode}: {p.stderr[-2000:]!r}")
    return json.loads(p.stdout.decode("ascii"))


def native_raw(name, args, text):
    """(status, the answer's JSON text) of one call of the native library."""
    lib = _native._load()
    if lib is None:
        raise _native.NativeError(_native.load_error())
    n = name.encode("ascii")
    a = json.dumps(args, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    req = struct.pack("<I", len(n)) + n + struct.pack("<I", len(a)) + a + text.encode("utf-8", "surrogatepass")
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = lib.lazaret_engine_call(req, len(req), ctypes.byref(out), ctypes.byref(out_len))
    try:
        answer = ctypes.string_at(out.value, out_len.value).decode("ascii") if out.value else ""
    finally:
        if out.value:
            lib.lazaret_engine_free(out.value, out_len.value)
    return status, answer


def native(src, spans=False):
    """The engine's py_parse answer (the status too, when it is not 0)."""
    status, answer = native_raw("py_parse", {"spans": True} if spans else {}, src)
    return answer if status == 0 else f"status {status}: {answer}"


def is_error(answer):
    return answer.startswith('{"error"')


def error_line(answer):
    return json.loads(answer)["error"]["line"]


def same(want, got):
    """Do the answers agree: the same tree, or both errors?"""
    return want == got or (is_error(want) and is_error(got))


def differences(sources, limit=5, answers=None):
    """[(source, where the answers part, the oracle's, the engine's)] for the
    sources whose answers differ (a tree against an error, or two trees)."""
    want = answers if answers is not None else oracle(sources)
    found = []
    for src, w in zip(sources, want):
        g = native(src)
        if not same(w, g):
            i = next((k for k, (x, y) in enumerate(zip(w, g)) if x != y), min(len(w), len(g)))
            found.append((json.dumps(src)[:300], i, w[max(0, i - 150):i + 150], g[max(0, i - 150):i + 150]))
            if len(found) >= limit:
                break
    return found
