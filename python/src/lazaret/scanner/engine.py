"""Which engine answers the supply-chain tests and the dependency-mode
scan of a file: the native one (Rust, crates/lazaret-engine through
_native.py) or the Python reference engine (lazaret.scanner.core).

The two give the same answers — the differential tests in
tests/architecture/test_rust_parity_*.py hold the native engine to core on
every case — so the choice changes the time a scan takes, never its
findings. scan_file in dependency mode (registry, guard and --deps scans:
the supply-chain and credential rules) is the native engine's whole; in
project mode core scans the file. The native engine answers where it is
installed (a wheel ships it as lazaret/_native/<library>;
LAZARET_NATIVE_LIB names a development build); `--engine python` or
LAZARET_ENGINE=python keeps the Python engine, and `--engine rust` fails
when the native one is missing rather than scan slowly without saying so.
Wherever the native engine can't answer a call — its work budget spent on a
hostile file, an internal error — core answers that call, so a scan never
loses a finding to the native engine.

Files are sent in batches (BATCH files per crossing of the boundary), which
the native engine reads on threads (THREADS, at most the machine's cores);
the answers come back in the order asked, so reports are the same whatever
the thread count.
"""
import os
import sys

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


def spawned_scripts(text):
    """core.spawned_scripts, by the engine in use: [(base, path)] for the
    package scripts `text` starts. The native engine reads the decoded view
    too (an 11.7 MB obfuscated payload: 3 s there, 20 s in Python)."""
    if name() != "rust":
        return core.spawned_scripts(text)
    answer = _batch("spawned_scripts", [({}, text)], lambda i: core.spawned_scripts(text))[0]
    return [tuple(x) for x in answer]


_ISSUE_KEYS = ("rule", "name", "type", "sev", "msg", "why", "fix", "ref")


def _issues(path, answer):
    """The native engine's issues as core's dicts (mk_issue's keys, in its order)."""
    out = []
    for a in answer:
        issue = dict(zip(_ISSUE_KEYS, a[:8]))
        issue.update(file=path, line=a[8], snippet=a[9], snipStart=a[10])
        if len(a) > 11:                           # a Q-CAPPED note: what it stands for
            issue.update(omitted=a[11], omittedType=a[12])
        out.append(issue)
    return out


def scan_files(items):
    """[(path, content, lang, dep)] -> [issues]: core.scan_file for each, in
    order. The native engine answers the files in dependency mode, and the
    first part of the others (scan_rules: the pattern rules, the families,
    the whole-text rules), after which core runs the passes that follow
    (taint, SQL, function length and complexity), the suppression markers
    and the cap; core scans whatever the native engine could not answer."""
    if not items:
        return []
    if name() != "rust":
        return [core.scan_file(path, content, lang, dep=dep) for path, content, lang, dep in items]
    native = [k for k, (_p, content, lang, _d) in enumerate(items)
              if lang in ("py", "js", "sql") and isinstance(content, str)]
    out = [None] * len(items)
    if native:
        base = {"redact": bool(core.REDACT_SECRETS), "neumaier": _NEUMAIER}
        calls = [("scan_file" if items[k][3] else "scan_rules",
                  dict(base, lang=items[k][2], jsx=core.jsx_reading(items[k][0]), dep=bool(items[k][3])), items[k][1])
                 for k in native]
        answers = _batch_calls(calls)
        for k, (call, _a, _t), answer in zip(native, calls, answers):
            if answer is None:
                continue
            path, content, lang, _dep = items[k]
            if call == "scan_file":
                out[k] = _issues(path, answer)
            else:
                out[k] = core.scan_file_after_rules(path, content, lang, _issues(path, answer))
    for k, (path, content, lang, dep) in enumerate(items):
        if out[k] is None:
            out[k] = core.scan_file(path, content, lang, dep=dep)
    return out


def _batch_calls(calls):
    """[(call, args, text)] -> answers in order, None where the native engine
    could not answer (the caller then asks core)."""
    out = []
    for start in range(0, len(calls), BATCH):
        chunk = calls[start:start + BATCH]
        try:
            answers = _native.call("batch", {"calls": [list(c) for c in chunk], "threads": THREADS})
        except _native.NativeError:
            answers = [None] * len(chunk)
        out.extend(a["ok"] if isinstance(a, dict) and "ok" in a else None for a in answers)
    return out


def scan_file(path, content, lang, dep=False):
    """core.scan_file, by the engine in use."""
    return scan_files([(path, content, lang, dep)])[0]


def cross_file_issues(files, skip_paths=(), who="Dependency code", one_package=False):
    """core._cross_file_received_issues, by the engine in use. The native
    engine reads the packages in one call (on THREADS threads), each with
    its own work budget; a package it could not read (the budget spent, an
    internal error) is read by core, so the findings and their order are
    core's."""
    if name() != "rust":
        return core._cross_file_received_issues(files, skip_paths, who, one_package)
    todo = [f for f in files if f.get("dep") and f["lang"] in ("py", "js")]
    if len(todo) < 2:
        return []
    args = {"files": [[f["path"], f["lang"], len(f["content"])] for f in todo],
            "skip": sorted(set(skip_paths)), "one_package": bool(one_package), "sep": os.sep,
            "redact": bool(core.REDACT_SECRETS), "neumaier": _NEUMAIER, "threads": THREADS}
    if callable(who):
        args["whos"] = [who(f["path"]) for f in todo]
    else:
        args["who"] = who
    try:
        answer = _native.call("cross_file", args, "".join(f["content"] for f in todo))
    except _native.NativeError:
        return core._cross_file_received_issues(files, skip_paths, who, one_package)
    out, groups = [], None
    for package in answer:
        if "failed" in package:
            if groups is None:
                groups = core._xf_groups(files, one_package)
            members = groups.get((package["lang"], package["root"]), [])
            out.extend(core._xf_group_issues(package["lang"], members, set(skip_paths), who))
            continue
        for k, issue in package["issues"]:
            out.extend(_issues(todo[k]["path"], [issue]))
    return out


# sum() adds floats with Neumaier's compensation since Python 3.12, and
# S-ENTROPY's Shannon entropy is such a sum: the native engine adds as this
# Python does.
_NEUMAIER = sys.version_info >= (3, 12)
