"""Lazaret's scanning engine: the native (Rust) engine, through _native.py.

Since the Rust-first refactor the Rust engine (rust/crates/lazaret-engine)
is the only engine: the Python package hands it each file's text and gets
its answers back, and the work around it — walking a project, reading
archives, the registry, the guard, the reports — stays Python. The engine
is held to its own recorded outputs (tests/architecture/test_snapshot_*.py),
no longer to a Python twin.

A wheel ships the engine as lazaret/_native/<library> (LAZARET_NATIVE_LIB
names a development build). Where it is missing, require() raises
EngineError and the command-line tools stop with exit code 2: there is no
engine to fall back on.

A call the engine cannot finish — its work budget spent on a hostile input
(a pattern that backtracks without end on the text), an internal error —
has no answer. The batch functions give None for such an item, the single
calls raise _native.NativeError, and scan_file gives the file SC-TRUNCATED
(EXHAUSTED, or "its scan failed" on an internal error): it was not fully
read, so it fails the gate. The npm package, which runs the same engine as
WebAssembly, does the same.

Files are sent in batches (BATCH per crossing of the boundary), which the
engine reads on threads (THREADS, at most the machine's cores); the answers
come back in the order asked, so reports are the same whatever the thread
count.
"""
import os

from lazaret.scanner import _native

BATCH = 64                    # files per batch: small enough that a scan's deadline stays responsive
THREADS = min(8, os.cpu_count() or 1)
# the work each file's call may do, in steps of the engine's regex matcher (None: the engine's
# default, about 4e9; the npm package's setWorkBudget)
WORK_BUDGET = None
# why a file the engine could not finish is SC-TRUNCATED (the npm package's words)
EXHAUSTED = "reading it spent the engine's work budget (a pattern that backtracks without end on this text)"


class EngineError(RuntimeError):
    """The native engine is not installed."""


# a call the engine could not answer raises these (NativeExhausted: its work budget spent)
NativeError, NativeExhausted = _native.NativeError, _native.NativeExhausted


def available():
    """Is the engine here?"""
    return _native.available()


def require():
    """Raise EngineError unless the engine is here."""
    if not _native.available():
        raise EngineError(
            f"the native engine is not installed ({_native.load_error()}): install the platform wheel for this "
            "machine, or build it (cd rust && cargo build --release) and point LAZARET_NATIVE_LIB at the library")


def name():
    """The engine in use (always 'rust')."""
    return "rust"


def describe():
    """'rust 0.1.8' (what --version says)."""
    return f"rust {_native.version()}" if _native.available() else "rust (not installed)"


def pack_value(name):
    """A value of the engine's rule pack (rust/crates/lazaret-engine/rules/
    lazaret-rules.json): a text, a number, a list for a set or a list, a
    dict for a map, a pattern's text for a pattern. KeyError when the pack
    has no such value."""
    raw = _native.call("pack.values", {"names": [name]}).get(name)
    if raw is None:
        raise KeyError(name)
    return _pack_entry(raw)


def pack_pattern(name):
    """A pattern of the engine's rule pack, compiled with Python's re (the
    pack's patterns are written in its syntax): for tests and tools."""
    import re
    raw = _native.call("pack.values", {"names": [name]}).get(name)
    if raw is None or "re" not in raw:
        raise KeyError(name)
    flags = 0
    for letter in raw.get("flags", ""):
        flags |= {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}.get(letter, 0)
    return re.compile(raw["re"], flags)


def _pack_entry(entry):
    if not isinstance(entry, dict):
        return entry
    if "map" in entry:
        return {k: _pack_entry(v) for k, v in entry["map"].items()}
    for kind in ("set", "list", "items"):
        if kind in entry:
            return [_pack_entry(v) for v in entry[kind]]
    if "re" in entry:
        return entry["re"]
    return entry.get("value")


def _budget(args):
    """`args` with WORK_BUDGET, when one is set."""
    return args if WORK_BUDGET is None else dict(args, budget=int(WORK_BUDGET))


def _answer(item):
    """A batch's answer to one call: its value, or the _native.NativeError it
    stands for (NativeExhausted: the call spent its work budget)."""
    if isinstance(item, dict) and "ok" in item:
        return item["ok"]
    if isinstance(item, dict) and item.get("exhausted"):
        return _native.NativeExhausted(str(item.get("error")))
    return _native.NativeError(str(item.get("error") if isinstance(item, dict) else item))


def unanswered(value):
    """Is `value` (an item of a batch function's answer) a call the engine
    could not answer?"""
    return isinstance(value, _native.NativeError)


def error_issue(path, exc):
    """SC-TRUNCATED for a file whose reading could not finish: EXHAUSTED when
    the engine spent its work budget, core.scan_error_issue ("its scan
    failed") for any other error."""
    from lazaret.scanner import core
    if isinstance(exc, _native.NativeExhausted):
        return core.truncated_issue(path, EXHAUSTED)
    return core.scan_error_issue(path, exc)


def _batch(call, items):
    """[(args, text)] -> the engine's answers in order (an item it could not
    answer: the _native.NativeError it stands for)."""
    out = []
    for start in range(0, len(items), BATCH):
        chunk = items[start:start + BATCH]
        answers = _native.call("batch", {"calls": [[call, _budget(args), text] for args, text in chunk],
                                         "threads": THREADS})
        out.extend(_answer(a) for a in answers)
    return out


def import_time_risks(items):
    """[(text, lang)] -> the import-time test of each, (reasons, line), in
    order; an item the engine could not answer is the _native.NativeError it
    stands for (see unanswered, error_issue)."""
    if not items:
        return []
    answers = _batch("import_time_risk", [({"lang": lang} if lang else {}, text) for text, lang in items])
    return [a if unanswered(a) else (a[0], a[1]) for a in answers]


def import_time_risk(text, lang=None):
    """(reasons, line) of the import-time test (raises _native.NativeError
    when the engine could not answer)."""
    answer = _native.call("import_time_risk", {"lang": lang} if lang else {}, text)
    return answer[0], answer[1]


def install_script_risks(items):
    """[(text, lang)] -> the install-script test's reasons for each, in order
    (an item the engine could not answer: the _native.NativeError it stands
    for)."""
    if not items:
        return []
    return _batch("install_script_risk", [({"lang": lang} if lang else {}, text) for text, lang in items])


def install_script_risk(text, shell=True, command=False, lang=None):
    """The install-script test's reasons (raises _native.NativeError when the
    engine could not answer). `lang`: the script's language when known
    ("js", "py"): its strings are read as its runtime reads them."""
    args = {}
    if not shell:
        args["shell"] = False
    if command:
        args["command"] = True
    if lang:
        args["lang"] = lang
    return _native.call("install_script_risk", args, text)


def _package_call(name, files, args):
    """One reading of a whole package (go_package, rs_crate): `files`, [(path, text)], cross the boundary as one text
    with each file's length, and the answer's file indexes are theirs (raises _native.NativeError when the engine
    could not answer)."""
    args = dict(_budget(args), files=[[path, len(text)] for path, text in files])
    return _native.call(name, args, "".join(text for _path, text in files))


def go_package(files, module=None, use_file_chars=None, use_chars=None):
    """The Go reader (G-1, docs/RUST_ENGINE.md section 22) on a module's files: [(path below the module's root, text)]
    of its .go files and its cgo packages' .c and .h files; `module` is its go.mod's module path. -> {"start": [{"file",
    "reasons", "line"}, …] (what init code reaches: the import-time test), "uses": […] (the rest: every reason, of
    which SC-USE-RISK counts the strong ones), "read", "unparsed", "generate", "linkname", "useRead"}."""
    args = {}
    if module:
        args["module"] = module
    if use_file_chars is not None:
        args["use_file_chars"] = int(use_file_chars)
    if use_chars is not None:
        args["use_chars"] = int(use_chars)
    return _package_call("go_package", files, args)


def rs_crate(files, build=None, proc_macro=False, lib=None, use_file_chars=None, use_chars=None):
    """The Rust reader (R-1, docs/RUST_ENGINE.md section 21) on a crate's .rs files: [(path below the crate's root,
    text)]; `build` is its build script's path, `proc_macro` whether its library is a procedural macro, `lib` its
    library's root. -> {"build": finding or None (the install-script test), "macros": finding or None, "start":
    [finding, …] (#[ctor], load sections: the import-time test), "uses": […] (the rest), "read", "useRead"}."""
    args = {"proc_macro": bool(proc_macro)}
    if build:
        args["build"] = build
    if lib:
        args["lib"] = lib
    if use_file_chars is not None:
        args["use_file_chars"] = int(use_file_chars)
    if use_chars is not None:
        args["use_chars"] = int(use_chars)
    return _package_call("rs_crate", files, args)


def cargo_layout(text):
    """What a crate's Cargo.toml says of the files that run, as the engine reads TOML (vendor.rs): {"build": a path,
    False (`build = false`) or None (not said), "lib": `lib.path` or None, "proc_macro": `lib.proc-macro` or None}.
    A --deps scan's reading of a vendored crate (core.cargo_layout); the npm package asks the same."""
    return _native.call("cargo_layout", {}, text)


def go_vendored_modules(text):
    """The module paths a vendor/modules.txt says are vendored (a `# path version` line followed by its annotations
    and packages), longest first (vendor.rs)."""
    return _native.call("go_vendored_modules", {}, text)


def spawned_scripts(text, lang=None):
    """[(base, path)] of the package scripts `text` (in `lang`, when known)
    starts (raises _native.NativeError when the engine could not answer)."""
    return [tuple(x) for x in _native.call("spawned_scripts", {"lang": lang} if lang else {}, text)]


def script_lang(path):
    """The language a script runs in, for the tests that read its strings:
    "py" for a .py file, None for a shell script (.sh), "js" for the rest
    (what node runs: a hook's target, a script it starts)."""
    if path.endswith(".py"):
        return "py"
    if path.endswith(".sh"):
        return None
    return "js"


_ISSUE_KEYS = ("rule", "name", "type", "sev", "msg", "why", "fix", "ref")


def _issues(path, answer):
    """The engine's issues as the scanner's dicts (mk_issue's keys, in its order)."""
    out = []
    for a in answer:
        issue = dict(zip(_ISSUE_KEYS, a[:8]))
        issue.update(file=path, line=a[8], snippet=a[9], snipStart=a[10])
        if len(a) > 11:                           # a Q-CAPPED note: what it stands for
            issue.update(omitted=a[11], omittedType=a[12])
        out.append(issue)
    return out


def scan_calls(items):
    """[(path, content, lang, dep)] -> the engine call that scans each, as
    (name, args), or None for a file it does not read. Its answer is a
    function of the name, the args and the text: the engine reads no path
    (the path's part is `jsx`, from its extension), which is what lets the
    registry ask once for a file that is in several archives (P-2a,
    registry/contentcache.py)."""
    from lazaret.scanner import core
    base = _budget({"redact": bool(core.REDACT_SECRETS), "neumaier": False})
    return [("scan_file" if dep else "scan_rules", dict(base, lang=lang, jsx=core.jsx_reading(path), dep=bool(dep)))
            if lang in ("py", "js", "sql", "go", "rs") and isinstance(content, str) else None
            for path, content, lang, dep in items]


def call_answers(calls):
    """[(name, args, text)] -> the engine's answers, in order, a batch at a
    time on THREADS threads (an answer it could not give: the NativeError it
    stands for, unanswered)."""
    out = []
    for start in range(0, len(calls), BATCH):
        chunk = calls[start:start + BATCH]
        answers = _native.call("batch", {"calls": [list(c) for c in chunk], "threads": THREADS})
        out.extend(_answer(a) for a in answers)
    return out


def scan_issues(path, content, lang, name, answer):
    """One file's issues from the engine's answer to its scan_calls call: in
    dependency mode the engine's (scan_file); in project mode its rules part
    (scan_rules), after which core runs the passes that follow."""
    from lazaret.scanner import core
    rules = [error_issue(path, answer)] if unanswered(answer) else _issues(path, answer)
    return rules if name == "scan_file" else core.scan_file_after_rules(path, content, lang, rules)


def scan_files(items):
    """[(path, content, lang, dep)] -> [issues] for each, in order. In
    dependency mode the engine reads the whole file; in project mode it reads
    the rules part (scan_rules: the pattern rules, the families, the
    whole-text rules), after which core runs the passes that follow (taint,
    SQL, function length and complexity), the suppression markers and the
    cap. A file the engine could not answer is SC-TRUNCATED: EXHAUSTED when
    it spent its work budget, "its scan failed" on an internal error."""
    if not items:
        return []
    calls = scan_calls(items)
    todo = [k for k, call in enumerate(calls) if call is not None]
    answers = call_answers([(calls[k][0], calls[k][1], items[k][1]) for k in todo])
    out = [[] for _ in items]
    for k, answer in zip(todo, answers):
        path, content, lang, _dep = items[k]
        out[k] = scan_issues(path, content, lang, calls[k][0], answer)
    return out


def scan_file(path, content, lang, dep=False):
    """The scan of one file (see scan_files)."""
    return scan_files([(path, content, lang, dep)])[0]


def cross_file_issues(files, skip_paths=(), who="Dependency code", one_package=False, site_groups=None):
    """The cross-file follower's findings: the engine reads the packages in
    one call (on THREADS threads), each with its own work budget. A package
    it could not finish is skipped, and a call it refuses altogether (an
    internal error) gives no findings, as in the npm package."""
    return cross_file_answer(files, skip_paths, who, one_package, site_groups)[0]


def cross_file_args(files, skip_paths=(), who="Dependency code", one_package=False, site_groups=None):
    """The cross-file call's files (the ones it reads, in order) and its
    arguments other than their text: what its answer is a function of, with
    the text (P-2a: registry/contentcache.cross_file_key)."""
    from lazaret.scanner import core
    todo = [f for f in files if f.get("dep") and f["lang"] in ("py", "js")]
    args = _budget({"files": [[f["path"], f["lang"], len(f["content"])] for f in todo],
                    "skip": sorted(set(skip_paths)), "one_package": bool(one_package), "sep": os.sep,
                    "redact": bool(core.REDACT_SECRETS), "neumaier": False, "threads": THREADS})
    if site_groups:
        args["groups"] = [site_groups.get(f["path"].replace(os.sep, "/")) for f in todo]
    if callable(who):
        args["whos"] = [who(f["path"]) for f in todo]
    else:
        args["who"] = who
    return todo, args


def cross_file_answer(files, skip_paths=(), who="Dependency code", one_package=False, site_groups=None):
    """(the cross-file follower's findings, whether the engine finished every
    package): a package it could not finish (its work budget spent) is
    skipped, and a call it refuses (an internal error) gives no findings, so
    an answer that is not complete must not be kept as clean (P-2a)."""
    todo, args = cross_file_args(files, skip_paths, who, one_package, site_groups)
    if len(todo) < 2:
        return [], True
    try:
        answer = _native.call("cross_file", args, "".join(f["content"] for f in todo))
    except _native.NativeError:
        return [], False
    out, complete = [], True
    for package in answer:
        complete = complete and "failed" not in package
        for k, issue in package.get("issues", ()):
            out.extend(_issues(todo[k]["path"], [issue]))
    return out, complete


def _flow_args(files, sources, sinks, full, partial):
    """A flow call's files, and the model's configured part (js_flow)."""
    texts = [f["content"] if isinstance(f.get("content"), str) else None for f in files]
    args = {"files": [[f["path"], None if t is None else len(t)] for f, t in zip(files, texts)]}
    if sources:
        args["sources"] = [g.pattern for g in sources]
    if sinks:
        args["sinks"] = [[g.pattern, cat] for g, cat in sinks]
    if full:
        args["full"] = sorted(full)
    if partial:
        args["partial"] = [[name, sorted(cats)] for name, cats in sorted(partial.items())]
    return args, "".join(t for t in texts if t is not None)


def _pair(limit):
    return [int(limit[0]), int(limit[1])]


def js_flow(files, sources=(), sinks=(), full=(), partial=None, run_limit=None):
    """The cross-file JavaScript taint pass (rust/crates/lazaret-engine/src/
    jsflow/) over `files` ({"path", "content"}: a project's own JavaScript
    and TypeScript; a content that is not a str is noted as not text), with
    the model's configured part as taintspec validated it: `sources`
    (guarded patterns), `sinks` ((guarded pattern, category)), `full`
    (sanitizers' call names) and `partial` (call name -> categories);
    `run_limit` (base, steps per node) lowers the limit of one function's
    reading. The pass's outputs, in order: ["skipped_size", path, n,
    limit], ["issue", category, path, line, source, sink, chain, the index
    of the path's file in `files`], ["note", rule, name, path, line, msg,
    why, fix]. Raises _native.NativeError when the engine cannot answer."""
    args, text = _flow_args(files, sources, sinks, full, partial)
    if run_limit is not None:
        args["run_limit"] = _pair(run_limit)
    return _native.call("js_flow", args, text)


def py_flow(files, sources=(), sinks=(), full=(), partial=None, max_iters=None, max_files=None, max_bytes=None,
            work_limit=None, run_limit=None):
    """The cross-file Python taint pass (rust/crates/lazaret-engine/src/
    pyflow/) over `files` ({"path", "content"}: a project's own Python; a
    content that is not a str is noted as not text), with the model's
    configured part as for js_flow (`full`: the configured full sanitizers,
    the built-in ones being the pass's own). Each limit lowers the pass's
    own, never raises it: `max_iters` (readings of one function in the
    fixpoint), `max_files` and `max_bytes` (the files and characters read),
    `work_limit` (base, steps per node: the fixpoint's budget) and
    `run_limit` (base, steps per node: one reading's). The pass's outputs,
    in order: ["issue", category, path, line, source, sink, chain, the
    index of the path's file in `files`], ["note", rule, name, path, line,
    msg, why, fix]. Raises _native.NativeError when the engine cannot
    answer."""
    args, text = _flow_args(files, sources, sinks, full, partial)
    for key, n in (("max_iters", max_iters), ("max_files", max_files), ("max_bytes", max_bytes)):
        if n is not None:
            args[key] = max(0, int(n))
    if work_limit is not None:
        args["work_limit"] = _pair(work_limit)
    if run_limit is not None:
        args["run_limit"] = _pair(run_limit)
    return _native.call("py_flow", args, text)
