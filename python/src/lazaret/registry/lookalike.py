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

Go module paths (0.1.9, N-3) are compared part by part, since anyone can
create an owner on GitHub but only its owner can add a repository to it: a
path is one of a well-known module's when its owner is one change from that
module's, differs from it only in its separators, or gains a word like "-go"
(GO_AFFIXES), with the repository the same (github.com/shopsprint/
decimal and github.com/boltdb-go/bolt, both published to squat on
github.com/shopspring/decimal and github.com/boltdb/bolt); when its host is
one change from the module's, with the rest the same (githab.com/spf13/
cobra); or, for gopkg.in, when its name is (gopkg.in/yanl.v3 is
github.com/go-yanl/yanl). The well-known modules are the TARGETS of
popular_names.json's "go": the Go modules awesome-go lists and those Debian
packages, compared lower-cased and without a major version (/v2). An owner
or host of one of them is never a look-alike (it is no stranger's), nor is a
dependency in the module's own owner, nor a change to an owner of fewer than
MIN_GO_OWNER characters unless the repository has MIN_GO_REPO (rs/zerolog,
aws/aws-sdk-go). A module of another owner with the same repository name is
not one: most are forks.

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
#: Go module hosts where anyone can create an owner (a user, an organization,
#: a group), so that a path is host/owner/repository; gopkg.in/NAME.vN is
#: github.com/go-NAME/NAME and gopkg.in/OWNER/NAME.vN github.com/OWNER/NAME.
GO_FORGES = frozenset({"github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com", "git.sr.ht",
                       "gitea.com", "framagit.org", "salsa.debian.org", "launchpad.net", "gopkg.in"})
#: Words an owner may gain, with or without a separator: boltdb-go for
#: boltdb. (Not lose: an author who moved a module to an organization so
#: named left the old path, github.com/xdg/scram for github.com/xdg-go/scram,
#: in the go.mod of the modules that required it, Shopify/sarama's among them.)
GO_AFFIXES = ("go", "golang", "dev", "lib", "libs", "pkg", "io", "hq", "official", "org", "team", "labs", "oss",
              "inc", "sdk")
MIN_GO_OWNER = 4
MIN_GO_REPO = 5
MIN_GO_HOST = 5
MAX_GO_PATH = 512
_GO_MAJOR_RE = re.compile(r"/v(?:[2-9]|[1-9][0-9]+)$")
_GOPKG_MAJOR_RE = re.compile(r"\.v(?:0|[1-9][0-9]*)(?:-unstable)?$")
_GO_PATH_RE = re.compile(r"[a-z0-9.~_+-]+(?:/[a-z0-9.~_+-]+)*")
#: Node's built-in modules named with a separator (string_decoder is a
#: popular npm package too, so it is a target already).
NODE_BUILTINS = ("child_process", "worker_threads", "perf_hooks", "async_hooks", "trace_events",
                 "diagnostics_channel")
_BUILTIN_BARE = {_SEP_RE.sub("", b): b for b in NODE_BUILTINS}


def normalize(eco, name):
    """The name as the registry compares it: npm's lower-cased, PyPI's
    PEP 503-normalized, a Go module path as go_path() writes it ("" for
    one it does not compare)."""
    if eco == "go":
        return go_path(name) or ""
    name = name.strip()
    return _PEP503_RE.sub("-", name).lower() if eco == "pypi" else name.lower()


def _load():
    if not _DATA:
        with open(os.path.join(os.path.dirname(__file__), "popular_names.json"), encoding="utf-8") as f:
            raw = json.load(f)
        for eco in ("npm", "pypi"):
            _DATA[eco] = tables(raw[eco]["targets"], raw[eco]["known"])
        _DATA["go"] = go_tables(raw["go"]["targets"])
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
    """True for one of the registry's most-downloaded names (the targets;
    for Go, the well-known modules)."""
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
    popular package's of its registry (see above), else None. For Go,
    go_lookalike's answer."""
    if eco == "go":
        return go_lookalike(name, data)
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


# ---- Go module paths (0.1.9, N-3)
def go_path(path):
    """A Go module path as the look-alike check compares it — lower-cased,
    without its major version (/v2; gopkg.in keeps its .vN, which is part
    of the name) — or None for one it does not compare (not a string,
    longer than MAX_GO_PATH, a character no module path has, no dot in its
    host)."""
    if not isinstance(path, str):
        return None
    p = path.strip().lower()
    if not p or len(p) > MAX_GO_PATH or not _GO_PATH_RE.fullmatch(p) or "." not in p.split("/", 1)[0]:
        return None
    return p if p.startswith("gopkg.in/") else _GO_MAJOR_RE.sub("", p)


def _go_key(p):
    """A go_path() without gopkg.in's .vN."""
    return _GOPKG_MAJOR_RE.sub("", p) if p.startswith("gopkg.in/") else p


def _go_major(p):
    """gopkg.in's .vN of a go_path(), else ""."""
    m = _GOPKG_MAJOR_RE.search(p) if p.startswith("gopkg.in/") else None
    return m.group(0) if m else ""


def _go_split(p):
    """A go_path() -> (host, owner, repository, what follows the host). A
    forge's path (GO_FORGES) has an owner and a repository (a gopkg.in
    name is its owner, with no repository); another host's has no owner
    (None): its domain's owner owns every path below it."""
    host, _, tail = p.partition("/")
    if host not in GO_FORGES:
        return host, None, "", tail
    parts = _go_key(p).split("/")
    return host, parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "", tail


def go_tables(targets):
    """(rank of each target, the targets by host and repository, the
    targets by what follows their host, their owners, their hosts) for
    go_lookalike(); `targets` are go_path()s."""
    rank, by_repo, by_tail, owners, hosts = {}, {}, {}, set(), set()
    for t in targets:
        if t in rank:
            continue
        rank[t] = len(rank)
        host, owner, repo, tail = _go_split(t)
        hosts.add(host)
        if owner is not None:
            owners.add((host, owner))
            by_repo.setdefault((host, repo), []).append((owner, t))
        by_tail.setdefault(tail, []).append((host, t))
    return rank, by_repo, by_tail, frozenset(owners), frozenset(hosts)


def _one_change(mine, theirs):
    """How `mine` is one change from `theirs` (_how's words), else None."""
    if mine == theirs or abs(len(mine) - len(theirs)) > 1:
        return None
    if len(mine) == len(theirs):
        diff = [i for i in range(len(mine)) if mine[i] != theirs[i]]
        if len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and mine[diff[0]] == theirs[diff[1]]
                              and mine[diff[1]] == theirs[diff[0]]):
            return _how(mine, theirs)
        return None
    longer, shorter = (mine, theirs) if len(mine) > len(theirs) else (theirs, mine)
    i = 0
    while i < len(shorter) and longer[i] == shorter[i]:
        i += 1
    return _how(mine, theirs) if longer[i + 1:] == shorter[i:] else None


def _go_change(mine, theirs, affixes=True):
    """How `mine`, a part of a path (an owner, a gopkg.in name, a host),
    looks like `theirs`: a clause ('is one change from "x" (a character
    added)'), else None."""
    if mine == theirs:
        return None
    if _SEP_RE.sub("", mine) == _SEP_RE.sub("", theirs):
        return f'differs from "{theirs}" only in its separators'
    how = _one_change(mine, theirs)
    if how:
        return f'is one change from "{theirs}" ({how})'
    for word in GO_AFFIXES if affixes else ():
        for sep in ("-", "_", ".", ""):
            for piece, after in ((sep + word, True), (word + sep, False)):
                if mine == (theirs + piece if after else piece + theirs):
                    return f'is "{theirs}" with "{piece}" added'
    return None


def go_lookalike(path, data=None, own=None):
    """(the well-known module, the part of `path` that looks like its
    ("owner", "name" for a gopkg.in name, "host"), that part of `path`, the
    module's, and how: _go_change's clause) when `path` looks like a
    well-known module's (see above), else None. `own` is the (host, owner)
    of the module that requires `path`: its own modules are not compared."""
    rank, by_repo, by_tail, owners, hosts = data or _load()["go"]
    p = go_path(path)
    if p is None or p in rank:
        return None
    host, owner, repo, tail = _go_split(p)
    hits = []
    if owner and (host, owner) not in owners and (host, owner) != own:
        part = "name" if host == "gopkg.in" and not repo else "owner"
        for theirs, t in by_repo.get((host, repo), ()):
            if len(theirs) < MIN_GO_OWNER and not (len(theirs) >= 2 and len(repo) >= MIN_GO_REPO):
                continue
            how = _go_change(owner, theirs)
            if how:
                hits.append((t, part, owner, theirs, how))
    if host not in hosts:
        for theirs, t in by_tail.get(tail, ()):
            how = _go_change(host, theirs, affixes=False) if len(theirs) >= MIN_GO_HOST else None
            if how:
                hits.append((t, "host", host, theirs, how))
    if not hits:
        return None
    major = _go_major(p)
    return min(hits, key=lambda h: (_go_major(h[0]) != major, rank[h[0]]))


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


_GO_WHY = ("A typosquat publishes a Go module under a path like a well-known module's and waits for a typo in an "
           "import or a go.mod: github.com/shopsprint/decimal for github.com/shopspring/decimal, github.com/"
           "boltdb-go/bolt for github.com/boltdb/bolt. Anyone can create an owner on GitHub, so an owner one "
           "character from a well-known one, or with a word like -go added, costs nothing to take. The owners "
           "and hosts of the well-known modules are never flagged; this one is not among them.")


def _go_issues(name, deps, rel, text, lines):
    """issues() for a Go module whose go.mod (`rel`, `text`) names it `name`
    and requires `deps`."""
    out, count = [], f"{len(_load()['go'][0]):,}"
    mine = go_path(name) if name else None
    own = _go_split(mine)[:2] if mine else None

    def whose(target, part, my_part, how):
        return (f'its {part} "{my_part}" {how}, the {part} of "{target}", one of the {count} Go modules awesome-go '
                "lists or Debian packages.")

    found = go_lookalike(name) if mine else None
    if found is not None:
        target, part, my_part, _theirs, how = found
        line = _line_of(text, [f"module {name}", f'module "{name}"'])
        out.append(lazaret.mk_issue(
            {"id": "SC-TYPOSQUAT", "name": "A name like a popular package's", "type": "HOTSPOT", "sev": "MAJOR",
             "msg": f'The module is "{name}": ' + whose(target, part, my_part, how),
             "why": _GO_WHY,
             "fix": f'Make sure "{name}" is the module you meant, not "{target}"; read what its code does before '
                    "building it.",
             "ref": "CWE-506 · Supply chain"}, rel, line, lines))
    for dep in sorted(deps):
        found = go_lookalike(dep, own=own)
        if found is None:
            continue
        target, part, my_part, _theirs, how = found
        line = _line_of(text, [dep + " ", dep + "\t", f'"{dep}"'])
        out.append(lazaret.mk_issue(
            {"id": "SC-TYPOSQUAT", "name": "A name like a popular package's", "type": "HOTSPOT", "sev": "MAJOR",
             "msg": f'Requires "{dep}": ' + whose(target, part, my_part, how),
             "why": _GO_WHY,
             "fix": f'Check that "{dep}" is the module meant, not "{target}", and read it before building.',
             "ref": "CWE-506 · Supply chain"}, rel, line, lines))
    return out


def issues(eco, name, deps, rel, text=""):
    """SC-TYPOSQUAT findings (MAJOR) for a release named `name` that declares
    `deps` in `rel` (its text, for the lines). For Go, `name` is the module
    path of a go.mod and `deps` the paths it requires."""
    out, lines = [], (text or "").split("\n")
    if eco == "go":
        return _go_issues(name, deps, rel, text, lines)
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
