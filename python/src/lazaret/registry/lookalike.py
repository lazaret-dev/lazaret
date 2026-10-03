"""Names like a popular package's (SC-TYPOSQUAT, 0.1.8).

A typosquat takes the name of a popular package with one character added,
dropped or changed, or two swapped, and waits for a typo in an install
command or a dependency list: requesxs and requestn for requests,
python-dateuti, tiketoken, sklearns, nhmpy for numpy (11 of the benchmark's
malicious PyPI releases); or it keeps the letters and changes the
separators (pythondateutil). A registry scan compares a release's own name
and the dependencies it declares (package.json dependencies and
optionalDependencies; a wheel's or an sdist's Requires-Dist, optional
extras left out) with the most-downloaded packages of its registry: the
TARGETS of popular_names.json, 5,000 of npm's and of PyPI's.

Most names one character from a popular one are real packages: mysql and
mysql2, delegate and delegates, fastai and fastapi, echarts and recharts.
So a name the lists know — one of npm's 17,000-odd most-downloaded or
most-depended-on packages, or one of PyPI's 15,000 most-downloaded — is
never one (popular_names.json keeps, as KNOWN, those of them one change
from a target; the others can't match). Neither is a target of fewer than
MIN_TARGET characters (os, fs, vm, ws have hundreds of real neighbours), nor
one in the package's own npm scope (its owner names those). A finding is
MAJOR, a weak indicator: a new package with such a name is worth a look,
and its code is judged by the other tests.

npm names are also compared with Node's built-in modules that have a
separator in their name (NODE_BUILTINS): a dependency on child-process
installs a stranger's package, since require('child_process') loads the
built-in (crypto-hash-sdk, in the benchmark, declares it and uses neither).
Built-ins named without one (events, buffer) are popular npm packages too,
browser polyfills, so they are not compared.

The lists and their licences: scripts/update-popular-names.py, and the
"source" fields of popular_names.json.
"""
import json
import os
import re

import lazaret.scanner.core as lazaret

MIN_TARGET = 5
MAX_NAME = 214                       # npm's longest name; a longer one is not compared
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-._"
_SEP_RE = re.compile(r"[-_.]")
_PEP503_RE = re.compile(r"[-_.]+")
_ECO_TEXT = {"npm": "npm packages", "pypi": "PyPI projects"}
_DATA = {}
#: Node's built-in modules named with a separator (string_decoder is a
#: popular npm package too, so it is a target already).
NODE_BUILTINS = ("child_process", "worker_threads", "perf_hooks", "async_hooks", "trace_events",
                 "diagnostics_channel")
_BUILTIN_BARE = {_SEP_RE.sub("", b): b for b in NODE_BUILTINS}


def normalize(eco, name):
    """The name as the registry compares it: npm's lower-cased, PyPI's
    PEP 503-normalized."""
    name = name.strip()
    return _PEP503_RE.sub("-", name).lower() if eco == "pypi" else name.lower()


def _load():
    if not _DATA:
        with open(os.path.join(os.path.dirname(__file__), "popular_names.json"), encoding="utf-8") as f:
            raw = json.load(f)
        for eco in ("npm", "pypi"):
            _DATA[eco] = tables(raw[eco]["targets"], raw[eco]["known"])
    return _DATA


def tables(targets, known):
    """(rank of each target, the known names, targets by their letters
    without separators) for lookalike()."""
    rank = {}
    for i, t in enumerate(targets):
        rank.setdefault(t, i)
    bare = {}
    for t in targets:
        if len(t) >= MIN_TARGET:
            bare.setdefault(_SEP_RE.sub("", t), t)
    return rank, frozenset(known), bare


def variants(n):
    """The names one character from n: one dropped, changed or added, or two
    neighbours swapped (over _ALPHABET)."""
    out = set()
    for i in range(len(n)):
        out.add(n[:i] + n[i + 1:])
        for c in _ALPHABET:
            if c != n[i]:
                out.add(n[:i] + c + n[i + 1:])
        if i + 1 < len(n) and n[i] != n[i + 1]:
            out.add(n[:i] + n[i + 1] + n[i] + n[i + 2:])
    for i in range(len(n) + 1):
        for c in _ALPHABET:
            out.add(n[:i] + c + n[i:])
    out.discard(n)
    return out


def popular(eco, name):
    """True for one of the registry's most-downloaded names (the targets)."""
    return isinstance(name, str) and normalize(eco, name) in _load()[eco][0]


def builtin_lookalike(name):
    """(the built-in module, how it was changed) when an npm name looks
    like one of NODE_BUILTINS (its separators changed, or one change), else
    None."""
    n = normalize("npm", name) if isinstance(name, str) else ""
    if not n or len(n) > MAX_NAME or n in NODE_BUILTINS:
        return None
    b = _BUILTIN_BARE.get(_SEP_RE.sub("", n))
    if b is not None:
        return b, "its separators changed"
    if any(abs(len(n) - len(b)) <= 1 for b in NODE_BUILTINS):
        near = variants(n)
        for b in NODE_BUILTINS:
            if b in near:
                return b, _how(n, b)
    return None


def _how(n, t):
    if len(n) > len(t):
        return "a character added"
    if len(n) < len(t):
        return "a character dropped"
    diff = [i for i in range(len(n)) if n[i] != t[i]]
    if len(diff) == 2 and diff[1] == diff[0] + 1:
        return "two characters swapped"
    return "a character changed"


def lookalike(eco, name, data=None):
    """(the popular name, how it was changed) when `name` looks like a
    popular package's of its registry (see above), else None."""
    rank, known, bare = data or _load()[eco]
    n = normalize(eco, name) if isinstance(name, str) else ""
    if not n or len(n) > MAX_NAME or n in rank or n in known:
        return None
    scope = n.split("/", 1)[0] + "/" if eco == "npm" and n.startswith("@") and "/" in n else None

    def fits(t):
        return len(t) >= MIN_TARGET and not (scope and t.startswith(scope))

    t = bare.get(_SEP_RE.sub("", n))
    if t is not None and t != n and fits(t):
        return t, "its separators changed"
    hits = [t for t in variants(n) if t in rank and fits(t)]
    if not hits:
        return None
    t = min(hits, key=rank.__getitem__)
    return t, _how(n, t)


def _line_of(text, needles):
    """The 1-based line of the first of `needles` found in text, else 1."""
    for needle in needles:
        at = text.find(needle) if text and needle else -1
        if at >= 0:
            return text.count("\n", 0, at) + 1
    return 1


_WHY = ("A typosquat takes the name of a popular package with one character added, dropped or changed, or two "
        "swapped, and waits for a typo in an install command or a dependency list: requesxs and requestn for "
        "requests, python-dateuti for python-dateutil, nhmpy for numpy. Most names one character from a popular "
        "one belong to real packages the lists know; this one is not among them.")


_BUILTIN_WHY = ("A package named like a module built into Node is never what code that requires the module "
                "loads: require('child_process') gets the built-in. A dependency on child-process installs a "
                "stranger's package, and runs its install scripts, for nothing the code uses; squatters publish "
                "such names for whoever adds one by mistake.")


def _found(eco, name):
    """(target, how, built-in?) for a look-alike name, else None."""
    found = lookalike(eco, name)
    if found is not None:
        return found + (False,)
    found = builtin_lookalike(name) if eco == "npm" else None
    return found + (True,) if found is not None else None


def issues(eco, name, deps, rel, text=""):
    """SC-TYPOSQUAT findings (MAJOR) for a release named `name` that declares
    `deps` in `rel` (its text, for the lines)."""
    out, lines = [], (text or "").split("\n")
    count = f"{len(_load()[eco][0]):,}"
    what = _ECO_TEXT[eco]

    def whose(target, how, builtin):
        if builtin:
            return f'one change from "{target}" ({how}), a module built into Node.'
        return f'one change from "{target}" ({how}), one of the {count} most-downloaded {what}.'

    found = _found(eco, name) if name else None
    if found is not None:
        target, how, builtin = found
        line = _line_of(text, [f'"name": {json.dumps(name)}', f'"name":{json.dumps(name)}', f"Name: {name}"])
        out.append(lazaret.mk_issue(
            {"id": "SC-TYPOSQUAT", "name": "A name like a popular package's", "type": "HOTSPOT", "sev": "MAJOR",
             "msg": f'The package is named "{name}", ' + whose(target, how, builtin),
             "why": _BUILTIN_WHY if builtin else _WHY,
             "fix": f'Make sure "{name}" is the package you meant, not "{target}"; read what it runs before '
                    "installing it.",
             "ref": "CWE-506 · Supply chain"}, rel, line, lines))
    for dep in sorted(deps):
        found = _found(eco, dep)
        if found is None:
            continue
        target, how, builtin = found
        line = _line_of(text, [json.dumps(dep) + ":", f"Requires-Dist: {dep}"])
        out.append(lazaret.mk_issue(
            {"id": "SC-TYPOSQUAT", "name": "A name like a popular package's", "type": "HOTSPOT", "sev": "MAJOR",
             "msg": f'Depends on "{dep}", ' + whose(target, how, builtin),
             "why": _BUILTIN_WHY if builtin else _WHY,
             "fix": f'Check that "{dep}" is the dependency meant, not "{target}", and read it before installing.',
             "ref": "CWE-506 · Supply chain"}, rel, line, lines))
    return out
