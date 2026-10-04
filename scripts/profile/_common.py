"""What the scripts in this folder share (0.1.9, P-10): where the checkout is, the native engine built
beside it, a recording cache for registry answers, and a wrapper that puts each engine call in a
`timings` span.

The scripts import `lazaret` from this checkout, not from an installed copy, so a profile is of the
code in the tree. Standard library only."""

import contextlib
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, "python", "src")


def configure_stdio():
    """Redirected output is UTF-8, and never raises on a character the stream cannot encode
    (STRUCTURE.md, "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def use_source_tree():
    """Make `import lazaret` this checkout's, and point LAZARET_NATIVE_LIB at the engine built in
    rust/target/release when the caller has not named one. -> the library path or None."""
    if SRC not in sys.path:
        sys.path.insert(0, SRC)
    if not os.environ.get("LAZARET_NATIVE_LIB"):
        from lazaret.scanner import _native
        built = os.path.join(ROOT, "rust", "target", "release", _native.library_name())
        if os.path.isfile(built):
            os.environ["LAZARET_NATIVE_LIB"] = built
    return os.environ.get("LAZARET_NATIVE_LIB")


@contextlib.contextmanager
def engine_spans(native, timings):
    """Every call of the native engine is a `timings.span("engine", name)` while this is open (a batch is
    named for its first call, `batch:scan_file`). Restores the engine's own function after. The package's own
    loader opens these spans itself since P-4 (`_native.TIMED`), and is left as it is."""
    if getattr(native, "TIMED", False):
        yield
        return
    real = native.call_raw

    def call_raw(name, args=None, text=""):
        label = name
        if name == "batch" and isinstance(args, dict) and args.get("calls"):
            label = "batch:" + str(args["calls"][0][0])
        with timings.span("engine", label):
            return real(name, args, text)

    native.call_raw = call_raw
    try:
        yield
    finally:
        native.call_raw = real


def cache_key(url, data=None):
    return hashlib.sha256(repr((url, data)).encode("utf-8")).hexdigest()


@contextlib.contextmanager
def recorded_network(repo, directory, *, record, replay):
    """`repo._fetch` answers from `directory` when `replay` is set and it has the answer; otherwise it asks the
    network and, with `record`, keeps what it got. Cold run: record, no replay. Warm run: replay, so there is no
    network time in the numbers."""
    real = repo._fetch
    os.makedirs(directory, exist_ok=True)

    def fetch(url, *args, **kwargs):
        path = os.path.join(directory, cache_key(url, kwargs.get("data")))
        if replay and os.path.exists(path):
            with open(path, "rb") as fh:
                return fh.read()
        data = real(url, *args, **kwargs)
        if record:
            with open(path, "wb") as fh:
                fh.write(data)
        return data

    repo._fetch = fetch
    try:
        yield
    finally:
        repo._fetch = real


def split_spec(spec):
    """'npm:next@16.3.8' -> ('npm', 'next', '16.3.8'); a scope keeps its '@' (npm:@babel/core@7.0.0); the
    version is None when absent. ValueError for anything else."""
    eco, _, rest = spec.partition(":")
    scoped = rest.startswith("@")
    name, _, version = (rest[1:] if scoped else rest).partition("@")
    if eco not in ("npm", "pypi") or not name:
        raise ValueError(f"not a package spec (npm:name[@version] or pypi:name[@version]): {spec!r}")
    return eco, "@" + name if scoped else name, version or None
