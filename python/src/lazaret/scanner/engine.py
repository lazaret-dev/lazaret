"""Which engine answers the supply-chain tests: the native one (Rust,
crates/lazaret-engine through _native.py) or the Python reference engine
(lazaret.scanner.core).

The two give the same answers — the differential tests in
tests/architecture/test_rust_parity_*.py hold the native engine to core on
every case — so the choice changes the time a scan takes, never its
findings. The native engine answers where it is installed (a wheel ships it
as lazaret/_native/<library>; LAZARET_NATIVE_LIB names a development build);
`--engine python` or LAZARET_ENGINE=python keeps the Python engine, and
`--engine rust` fails when the native one is missing rather than scan
slowly without saying so. Wherever the native engine can't answer a call —
its work budget spent on a hostile file, an internal error — core answers
that call, so a scan never loses a finding to the native engine.

Files are sent in batches (BATCH files per crossing of the boundary), which
the native engine reads on threads (THREADS, at most the machine's cores);
the answers come back in the order asked, so reports are the same whatever
the thread count.
"""
import os

from lazaret.scanner import _native, core

ENGINES = ("rust", "python")
ENV = "LAZARET_ENGINE"
BATCH = 64                    # files per batch: small enough that a scan's deadline stays responsive
THREADS = min(8, os.cpu_count() or 1)

_choice = None                # set by choose(): 'rust', 'python', or None (automatic)


class EngineError(ValueError):
    """An engine asked for that is unknown or not installed."""


def choose(name=None):
    """Use `name` ('rust', 'python'; None: LAZARET_ENGINE, else the native
    engine where it is installed). Raises EngineError for an unknown engine,
    or 'rust' where the native library is missing."""
    global _choice
    name = (name or os.environ.get(ENV) or "").strip().lower() or None
    if name is not None and name not in ENGINES:
        raise EngineError(f"unknown engine {name!r} (choose rust or python)")
    if name == "rust" and not _native.available():
        raise EngineError(f"the native engine is not installed ({_native.load_error()})")
    _choice = name


def name():
    """The engine in use: 'rust' or 'python'."""
    if _choice == "python":
        return "python"
    if _choice == "rust":
        return "rust"
    env = (os.environ.get(ENV) or "").strip().lower()
    if env == "python":
        return "python"
    return "rust" if _native.available() else "python"


def describe():
    """'rust 0.1.8' or 'python' (what --version and reports say)."""
    if name() == "rust":
        return f"rust {_native.version()}"
    return "python"


def _batch(call, items, fallback):
    """[args, text] items -> answers, in order: the native engine's batch,
    core (`fallback(i)`) for each item it could not answer."""
    out = []
    for start in range(0, len(items), BATCH):
        chunk = items[start:start + BATCH]
        try:
            answers = _native.call("batch", {"calls": [[call, args, text] for args, text in chunk], "threads": THREADS})
        except _native.NativeError:
            answers = [None] * len(chunk)
        for k, answer in enumerate(answers):
            if isinstance(answer, dict) and "ok" in answer:
                out.append(answer["ok"])
            else:
                out.append(fallback(start + k))
    return out


def import_time_risks(items):
    """[(text, lang)] -> [(reasons, line)]: core.import_time_risk for each."""
    if not items:
        return []
    if name() != "rust":
        return [core.import_time_risk(text, lang) for text, lang in items]
    answers = _batch("import_time_risk", [({"lang": lang} if lang else {}, text) for text, lang in items],
                     lambda i: list(core.import_time_risk(*items[i])))
    return [(reasons, line) for reasons, line in answers]


def import_time_risk(text, lang=None):
    """core.import_time_risk, by the engine in use."""
    return import_time_risks([(text, lang)])[0]


def install_script_risks(texts):
    """[text] -> [reasons]: core.install_script_risk for each."""
    if not texts:
        return []
    if name() != "rust":
        return [core.install_script_risk(text) for text in texts]
    return _batch("install_script_risk", [({}, text) for text in texts], lambda i: core.install_script_risk(texts[i]))


def install_script_risk(text):
    """core.install_script_risk, by the engine in use."""
    return install_script_risks([text])[0]
