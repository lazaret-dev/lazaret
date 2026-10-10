"""The native (Rust) engine, through ctypes: the loader and one call.

The engine is a shared library (rust/crates/lazaret-ffi) with a C ABI, so it
needs no compiled Python extension and no third-party binding: stdlib ctypes
loads it, one binary per platform serves every Python version. A wheel ships
it as lazaret/_native/<name> (an editable install puts it in
src/lazaret/_native/); LAZARET_NATIVE_LIB names another copy (a development
build). Since the Rust-first refactor it is the package's only engine: where
there is none, `available()` is False and the scanning commands stop
(engine.require).

A call sends a name, its arguments (JSON) and a text (the str's code points
as UTF-8, surrogates passed through), and gets JSON back. When the engine
cannot answer (its work budget spent on a hostile input, an internal error)
the call raises; the scans make the file SC-TRUNCATED (see `engine.py`).
"""
import ctypes
import json
import os
import struct
import sys
import threading

from lazaret.scanner import timings

STATUS_OK, STATUS_ERROR, STATUS_EXHAUSTED, STATUS_PANIC = 0, 1, 2, 3

#: every call is a timings.span("engine", its name) while a capture is open
#: (0.1.9, P-4: `--timings`); a batch is named for its first call (batch:scan_file)
TIMED = True

_LIB_NAMES = {"win32": "lazaret_native.dll", "darwin": "liblazaret_native.dylib"}


class NativeError(RuntimeError):
    """The native engine could not answer."""


class NativeExhausted(NativeError):
    """The call spent its work budget (a hostile input): it has no answer."""


def library_name():
    return _LIB_NAMES.get(sys.platform, "liblazaret_native.so")


def library_path():
    """The native library to load, or None."""
    env = os.environ.get("LAZARET_NATIVE_LIB")
    if env:
        return env if os.path.isfile(env) else None
    here = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_native", library_name())
    return here if os.path.isfile(here) else None


_lock = threading.Lock()
_lib = None
_load_error = None


def _load():
    global _lib, _load_error
    with _lock:
        if _lib is not None or _load_error is not None:
            return _lib
        path = library_path()
        if path is None:
            _load_error = "no native engine library"
            return None
        try:
            lib = ctypes.CDLL(path)
            lib.lazaret_engine_call.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                                ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)]
            lib.lazaret_engine_call.restype = ctypes.c_int
            lib.lazaret_engine_free.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.lazaret_engine_free.restype = None
            lib.lazaret_engine_version.argtypes = []
            lib.lazaret_engine_version.restype = ctypes.c_char_p
        except (OSError, AttributeError) as e:
            _load_error = f"cannot load {path}: {e}"
            return None
        _lib = lib
        return lib


def available():
    """Is the native engine here?"""
    return _load() is not None


def load_error():
    _load()
    return _load_error


def version():
    """The native engine's version, or None."""
    lib = _load()
    return None if lib is None else lib.lazaret_engine_version().decode("ascii")


def span_name(name, args):
    """A call's name in timings: a batch is named for its first call."""
    if name == "batch" and isinstance(args, dict) and isinstance(args.get("calls"), list) and args["calls"]:
        first = args["calls"][0]
        if isinstance(first, (list, tuple)) and first and isinstance(first[0], str):
            return "batch:" + first[0]
    return name


def call_raw(name, args=None, text=""):
    """Run one call of the native engine: (its status, its answer as JSON
    text), the answer not parsed (a parsed tree may be deeper than
    json.loads reads)."""
    lib = _load()
    if lib is None:
        raise NativeError(_load_error)
    with timings.span("engine", span_name(name, args)):
        return _call_lib(lib, name, args, text)


def _call_lib(lib, name, args, text):
    n = name.encode("ascii")
    a = b"" if args is None else json.dumps(args, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    req = struct.pack("<I", len(n)) + n + struct.pack("<I", len(a)) + a + text.encode("utf-8", "surrogatepass")
    out = ctypes.c_void_p()
    out_len = ctypes.c_size_t()
    status = lib.lazaret_engine_call(req, len(req), ctypes.byref(out), ctypes.byref(out_len))
    try:
        answer = ctypes.string_at(out.value, out_len.value).decode("ascii") if out.value else "null"
    finally:
        if out.value:
            lib.lazaret_engine_free(out.value, out_len.value)
    return status, answer


def call(name, args=None, text=""):
    """Run one call of the native engine and return its JSON answer."""
    status, answer = call_raw(name, args, text)
    if status == STATUS_OK:
        return json.loads(answer)
    message = json.loads(answer).get("error", "") if answer.startswith("{") else answer
    if status == STATUS_EXHAUSTED:
        raise NativeExhausted(message)
    raise NativeError(f"{name}: {message}")
