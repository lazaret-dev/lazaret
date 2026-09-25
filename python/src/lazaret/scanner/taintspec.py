"""Taint-config validation shared by both taint engines.

A taint config (``--taint-config PATH``, or the scanned repository's own
``.lazaret-taint.json`` with ``--trust-repo-config``) extends the built-in
model with custom sources, sinks and sanitizers. It is consumed by the
intra-file engine (core.apply_taint_config) and the interprocedural engine
(flow.configure); both go through validate() here, so they accept exactly
the same rules and report rejections with identical texts.

Every field is type-checked: a wrong type is a rejected rule with a warning
(never a traceback, never a string iterated character by character). User
regular expressions are guarded, because a config can come from the scanned
repository:
  * at most MAX_PATTERN_LEN characters;
  * a conservative static check rejects patterns that can backtrack
    catastrophically: a repeated group containing another repeat or an
    alternation (``(a+)+``, ``(a|a)+``, ``(.*)*``), backreferences, more than
    two unbounded repeats, or two unbounded repeats over overlapping
    characters (``.*.*x``, ``\\w+\\w+x``);
  * every match runs against at most MAX_MATCH_TEXT characters of each
    candidate text (GuardedPattern).
Sanitizer names are exact call names (``module.func`` / ``func``), escaped
before they are compiled, so they carry no regex risk; but a config loaded
from the scanned repository may not declare sanitizers at all (allow_sanitizers
=False): a repository must not be able to declare its own code safe.

Standard library only; imports nothing else from Lazaret.
"""
from __future__ import annotations

import re

try:                                    # Python 3.11+
    import re._parser as _sre_parse
except ImportError:                     # Python 3.10
    import sre_parse as _sre_parse

#: The sink categories a config may use (both engines' category tables).
CATEGORIES = (
    "SQL injection", "command injection", "code injection",
    "template injection", "path traversal", "server-side request forgery",
    "open redirect", "cross-site scripting",
)
VALID_CATEGORIES = tuple(sorted(CATEGORIES))
_CATS_TXT = ", ".join(VALID_CATEGORIES)

MAX_PATTERN_LEN = 500       # characters per user regex
MAX_MATCH_TEXT = 2000       # characters of each candidate a user regex sees
MAX_RULES = 500             # entries per list (sources, sinks, full, partial)
MAX_NAME_LEN = 200          # characters per sanitizer name
_BIG_REPEAT = 32            # {n,m} with m above this counts as unbounded

_SECTIONS = ("python", "javascript")
_SECTION_KEYS = ("sources", "sinks", "sanitizers")
_SANITIZER_KEYS = ("full", "partial")
_NAME_RE = re.compile(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\Z")


# ---------------------------------------------------------------------------
# Guarded user regexes
# ---------------------------------------------------------------------------
def _clip(text):
    text = text if isinstance(text, str) else str(text)
    return text if len(text) <= MAX_MATCH_TEXT else text[:MAX_MATCH_TEXT]


class _ShiftedMatch:
    """A match found in one line, reported in whole-text coordinates."""
    __slots__ = ("_m", "_off")

    def __init__(self, m, off):
        self._m, self._off = m, off

    def start(self, *g):
        return self._m.start(*g) + self._off

    def end(self, *g):
        return self._m.end(*g) + self._off

    def span(self, *g):
        return self.start(*g), self.end(*g)

    def group(self, *g):
        return self._m.group(*g)


class GuardedPattern:
    """A user regex that passed check_pattern(). Duck-types the subset of
    re.Pattern the engines use; every match sees at most MAX_MATCH_TEXT
    characters of its candidate (finditer: of each line)."""
    __slots__ = ("pattern", "_re")

    def __init__(self, pattern, compiled):
        self.pattern = pattern
        self._re = compiled

    def search(self, text, *_):
        return self._re.search(_clip(text))

    def match(self, text, *_):
        return self._re.match(_clip(text))

    def finditer(self, text):
        pos = 0
        for line in str(text).split("\n"):
            for m in self._re.finditer(_clip(line)):
                yield _ShiftedMatch(m, pos)
            pos += len(line) + 1

    def __repr__(self):
        return f"GuardedPattern({self.pattern!r})"


class PatternUnion:
    """A built-in compiled regex extended with guarded user patterns — the
    replacement for the old ``re.compile(builtin + "|" + user)``, which let a
    user alternative backtrack over entire (multi-megabyte) lines. .pattern
    still reads like the joined alternation."""
    __slots__ = ("base", "extras")

    def __init__(self, base, extras=()):
        self.base = base
        self.extras = tuple(extras)

    @property
    def pattern(self):
        return self.base.pattern + "".join("|" + e.pattern for e in self.extras)

    def with_extras(self, more):
        return PatternUnion(self.base, self.extras + tuple(more))

    def search(self, text, *_):
        m = self.base.search(text)
        if m is not None:
            return m
        for e in self.extras:
            m = e.search(text)
            if m is not None:
                return m
        return None

    def match(self, text, *_):
        m = self.base.match(text)
        if m is not None:
            return m
        for e in self.extras:
            m = e.match(text)
            if m is not None:
                return m
        return None

    def finditer(self, text):
        yield from self.base.finditer(text)
        for e in self.extras:
            yield from e.finditer(text)

    def __repr__(self):
        return f"PatternUnion({self.pattern!r})"


def extend_pattern(current, extras):
    """*current* (a compiled regex or PatternUnion) plus guarded *extras*."""
    if not extras:
        return current
    if isinstance(current, PatternUnion):
        return current.with_extras(extras)
    return PatternUnion(current, extras)


# ---- static backtracking check ----
class _Unsafe(Exception):
    pass


def _op(name):
    return getattr(_sre_parse, name, None)


_REPEATS = {o for o in (_op("MAX_REPEAT"), _op("MIN_REPEAT"),
                        _op("POSSESSIVE_REPEAT")) if o is not None}
_MAXREPEAT = _sre_parse.MAXREPEAT
_ASCII = frozenset(range(128))
# ASCII members and a tag for the non-ASCII members of the categories we
# model ('W': Unicode word chars incl. digits, 'S': Unicode whitespace,
# '*': some other non-ASCII char — conservatively overlaps any non-ASCII).
_CAT_CHARS = {
    "CATEGORY_DIGIT": (frozenset(range(48, 58)), "W"),
    "CATEGORY_WORD": (frozenset(list(range(48, 58)) + list(range(65, 91))
                                + list(range(97, 123)) + [95]), "W"),
    "CATEGORY_SPACE": (frozenset((9, 10, 11, 12, 13, 28, 29, 30, 31, 32)), "S"),
}


def _charclass(items):
    """(ascii codepoint set, non-ASCII tags) for a repeat body, or None for
    "anything" (conservative)."""
    if len(items) != 1:
        return None
    op, av = items[0]
    if op is _op("LITERAL"):
        return (frozenset([av]), frozenset()) if av < 128 else (frozenset(), frozenset("*"))
    if op is _op("IN"):
        chars, wide = set(), set()
        for iop, iav in av:
            if iop is _op("NEGATE"):
                return None
            if iop is _op("LITERAL"):
                if iav < 128:
                    chars.add(iav)
                else:
                    wide.add("*")
            elif iop is _op("RANGE"):
                lo, hi = iav
                chars.update(range(lo, min(hi, 127) + 1))
                if hi >= 128:
                    wide.add("*")
            elif iop is _op("CATEGORY"):
                known = _CAT_CHARS.get(str(iav))
                if known is None:
                    return None              # NOT_DIGIT, NOT_WORD, … ≈ anything
                chars.update(known[0])
                wide.add(known[1])
            else:
                return None
        return frozenset(chars), frozenset(wide)
    return None                                # ANY, NOT_LITERAL, groups, …


def _overlap(a, b):
    if a is None or b is None:
        return True
    if a[0] & b[0]:
        return True
    wa, wb = a[1], b[1]
    return bool(wa & wb) or ("*" in wa and bool(wb)) or ("*" in wb and bool(wa))


def _has_branch(items):
    for op, av in items:
        if op is _op("BRANCH") or op is _op("GROUPREF_EXISTS"):
            return True
        for sub in _children(op, av):
            if _has_branch(sub):
                return True
    return False


def _children(op, av):
    if op in _REPEATS:
        return [av[2]]
    if op is _op("SUBPATTERN"):
        return [av[-1]]
    if op is _op("BRANCH"):
        return list(av[1])
    if op in (_op("ASSERT"), _op("ASSERT_NOT")):
        return [av[1]]
    if op is _op("ATOMIC_GROUP"):
        return [av]
    return []


def _walk(items, in_repeat, unbounded):
    for op, av in items:
        if op in (_op("GROUPREF"), _op("GROUPREF_EXISTS")):
            raise _Unsafe("backreferences are not allowed")
        if op in _REPEATS:
            _lo, hi, sub = av
            repeats = hi > 1
            if repeats and in_repeat:
                raise _Unsafe("nested quantifier (a repeat inside a repeated "
                              "group, e.g. (a+)+) can backtrack exponentially")
            if repeats and _has_branch(sub):
                raise _Unsafe("repeated alternation (e.g. (a|aa)+) can "
                              "backtrack exponentially")
            if hi == _MAXREPEAT or hi > _BIG_REPEAT:
                unbounded.append(_charclass(list(sub)))
            _walk(sub, in_repeat or repeats, unbounded)
            continue
        for sub in _children(op, av):
            _walk(sub, in_repeat, unbounded)


def check_pattern(pattern):
    """(GuardedPattern, None) for an acceptable user regex, else
    (None, reason). reason starting with 'invalid:' means it did not
    compile at all."""
    try:
        compiled = re.compile(pattern)
    except (re.error, OverflowError, RecursionError, ValueError) as exc:
        return None, f"invalid:{exc}"
    try:
        unbounded = []
        _walk(list(_sre_parse.parse(pattern)), False, unbounded)
        if len(unbounded) > 2:
            raise _Unsafe(f"{len(unbounded)} unbounded repeats (limit 2) can "
                          f"backtrack polynomially")
        if len(unbounded) == 2 and _overlap(unbounded[0], unbounded[1]):
            raise _Unsafe("two unbounded repeats over overlapping characters "
                          "(e.g. .*.* or \\w+\\w+) can backtrack polynomially "
                          "— drop a leading/trailing .*: patterns are "
                          "searched, not anchored")
    except _Unsafe as exc:
        return None, str(exc)
    except Exception:                     # parser internals changed: refuse
        return None, "could not be analyzed for backtracking safety"
    return GuardedPattern(pattern, compiled), None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
class LangSpec:
    """Validated rules for one language section."""

    def __init__(self):
        self.sources = []        # [GuardedPattern]
        self.sinks = []          # [(GuardedPattern, category)]
        self.full = []           # [call name]
        self.partial = {}        # call name -> set(categories)

    def empty(self):
        return not (self.sources or self.sinks or self.full or self.partial)


class TaintSpec:
    """Result of validate(): per-language rules plus messages.

    warnings — rejected rules (invalid config); count toward the CLI's
               exit-4 strictness.
    notes    — policy messages (sanitizers ignored in a repository config);
               printed, never fatal.
    """

    def __init__(self):
        self.python = LangSpec()
        self.javascript = LangSpec()
        self.warnings = []
        self.notes = []
        self.ignored_sanitizers = 0

    def lang(self, key):
        return self.python if key == "python" else self.javascript

    def counts(self):
        s = self.python, self.javascript
        return {"sources": sum(len(x.sources) for x in s),
                "sinks": sum(len(x.sinks) for x in s),
                "sanitizers": sum(len(x.full) + len(x.partial) for x in s)}


def _tn(v):
    return "null" if v is None else type(v).__name__


def _short(v, n=80):
    r = repr(v)
    return r if len(r) <= n else r[:n] + "…"


def _cap(lst, what, warn):
    if len(lst) > MAX_RULES:
        warn(f"{what} has {len(lst)} entries (limit {MAX_RULES}) — the rest "
             f"are skipped")
        return lst[:MAX_RULES]
    return lst


def _pattern(pat, where, warn):
    """GuardedPattern for a user regex or None (with a warning)."""
    if len(pat) > MAX_PATTERN_LEN:
        warn(f"{where} is {len(pat)} characters (limit {MAX_PATTERN_LEN}) "
             f"— rule skipped")
        return None
    gp, reason = check_pattern(pat)
    if gp is None:
        if reason.startswith("invalid:"):
            warn(f"{where} {_short(pat)} is not a valid regex "
                 f"({reason[len('invalid:'):]}) — rule skipped")
        else:
            warn(f"{where} {_short(pat)} is rejected: {reason} — rule skipped")
    return gp


def _valid_name(name):
    return (isinstance(name, str) and 0 < len(name) <= MAX_NAME_LEN
            and _NAME_RE.match(name) is not None)


def validate(cfg, allow_sanitizers=True):
    """Validate a parsed taint config; returns a TaintSpec.

    allow_sanitizers=False (a config loaded from the scanned repository):
    'sanitizers' sections are ignored with a note instead of applied.
    """
    spec = TaintSpec()
    warn = spec.warnings.append
    if not isinstance(cfg, dict):
        warn(f"top level is {_tn(cfg)}, not an object — nothing applied")
        return spec
    for key in cfg:
        if key not in _SECTIONS and not str(key).startswith("_"):
            warn(f"unknown top-level section {_short(key)} — expected "
                 f"'python' or 'javascript'; rule skipped")
    for lang_key in _SECTIONS:
        if lang_key not in cfg:
            continue
        section = cfg[lang_key]
        if section is None:
            section = {}
        if not isinstance(section, dict):
            warn(f"section '{lang_key}' is {_tn(section)}, not an object — "
                 f"section ignored")
            continue
        _validate_section(spec, lang_key, section, allow_sanitizers)
    return spec


def _validate_section(spec, lang_key, section, allow_sanitizers):
    warn = spec.warnings.append
    out = spec.lang(lang_key)
    for key in section:
        if key not in _SECTION_KEYS and not str(key).startswith("_"):
            warn(f"{lang_key}: unknown key {_short(key)} — expected 'sources', "
                 f"'sinks' or 'sanitizers'; ignored")

    # ---- sources: list of regex strings ----
    if "sources" in section:
        sources = section["sources"]
        if not isinstance(sources, list):
            warn(f"{lang_key}.sources is {_tn(sources)}, not a list — "
                 f"section ignored")
            sources = []
        for idx, pat in enumerate(_cap(sources, f"{lang_key}.sources", warn), 1):
            if not isinstance(pat, str):
                warn(f"{lang_key}.sources entry #{idx} is {_tn(pat)}, not a "
                     f"string — rule skipped")
                continue
            if not pat:
                warn(f"{lang_key}.sources entry #{idx} is empty — rule skipped")
                continue
            gp = _pattern(pat, f"{lang_key}.sources pattern", warn)
            if gp is not None:
                out.sources.append(gp)

    # ---- sinks: list of {pattern, category} ----
    if "sinks" in section:
        sinks = section["sinks"]
        if not isinstance(sinks, list):
            warn(f"{lang_key}.sinks is {_tn(sinks)}, not a list — "
                 f"section ignored")
            sinks = []
        for idx, sk in enumerate(_cap(sinks, f"{lang_key}.sinks", warn), 1):
            if not isinstance(sk, dict):
                warn(f"{lang_key} sink #{idx} is not an object — rule skipped")
                continue
            cat, pattern = sk.get("category"), sk.get("pattern")
            for k in sk:
                if k not in ("category", "pattern") and not str(k).startswith("_"):
                    warn(f"{lang_key} sink #{idx}: unknown key {_short(k)} — "
                         f"ignored")
            if not cat:
                warn(f"{lang_key} sink #{idx} (pattern {_short(pattern)}) has "
                     f"no 'category' — rule skipped; valid categories: "
                     f"{_CATS_TXT}")
                continue
            if not isinstance(cat, str) or cat not in CATEGORIES:
                warn(f"{lang_key} sink #{idx} (pattern {_short(pattern)}) has "
                     f"unknown category {_short(cat)} — rule skipped; valid "
                     f"categories: {_CATS_TXT}")
                continue
            if pattern is not None and not isinstance(pattern, str):
                warn(f"{lang_key} sink #{idx} (category {cat!r}) pattern is "
                     f"{_tn(pattern)}, not a string — rule skipped")
                continue
            if not pattern:
                warn(f"{lang_key} sink #{idx} (category {cat!r}) has an empty "
                     f"'pattern' — rule skipped")
                continue
            gp = _pattern(pattern, f"{lang_key} sink #{idx} (category {cat!r}) "
                                   f"pattern", warn)
            if gp is not None:
                out.sinks.append((gp, cat))

    # ---- sanitizers: {full: [name], partial: {name: [category]}} ----
    if "sanitizers" not in section:
        return
    san = section["sanitizers"]
    if not allow_sanitizers:
        if san:
            spec.ignored_sanitizers += (
                sum(len(v) for v in san.values() if isinstance(v, (list, dict)))
                if isinstance(san, dict) else 1)
            spec.notes.append(
                f"{lang_key}.sanitizers ignored: a scanned repository's own "
                f".lazaret-taint.json may add sources and sinks but not "
                f"sanitizers (it must not be able to declare its own code "
                f"safe) — pass the file with --taint-config to trust it")
        return
    if san is None:
        return
    if not isinstance(san, dict):
        warn(f"{lang_key}.sanitizers is {_tn(san)}, not an object — "
             f"section ignored")
        return
    for key in san:
        if key not in _SANITIZER_KEYS and not str(key).startswith("_"):
            warn(f"{lang_key}.sanitizers: unknown key {_short(key)} — expected "
                 f"'full' or 'partial'; ignored")
    full = san.get("full", [])
    if full is None:
        full = []
    if not isinstance(full, list):
        warn(f"{lang_key}.sanitizers.full is {_tn(full)}, not a list — "
             f"section ignored")
        full = []
    for name in _cap(full, f"{lang_key}.sanitizers.full", warn):
        if not _valid_name(name):
            warn(f"{lang_key}.sanitizers.full entry {_short(name)} is not a "
                 f"valid sanitizer name (expected a call name like "
                 f"'module.func') — rule skipped")
            continue
        out.full.append(name)
    partial = san.get("partial", {})
    if partial is None:
        partial = {}
    if not isinstance(partial, dict):
        warn(f"{lang_key}.sanitizers.partial is {_tn(partial)}, not an object "
             f"— section ignored")
        partial = {}
    items = list(partial.items())
    if len(items) > MAX_RULES:
        warn(f"{lang_key}.sanitizers.partial has {len(items)} entries (limit "
             f"{MAX_RULES}) — the rest are skipped")
        items = items[:MAX_RULES]
    for name, cats in items:
        if not _valid_name(name):
            warn(f"{lang_key} sanitizer {_short(name)} could not be compiled: "
                 f"not a valid call name (expected e.g. 'module.func') — rule "
                 f"skipped")
            continue
        if not isinstance(cats, list):
            warn(f"{lang_key} sanitizer {name!r} has {_tn(cats)} categories, "
                 f"not a list — rule skipped")
            continue
        good = set()
        for c in cats:
            if not isinstance(c, str) or c not in CATEGORIES:
                warn(f"{lang_key} sanitizer {name!r} lists unknown category "
                     f"{_short(c)} — category ignored; valid categories: "
                     f"{_CATS_TXT}")
                continue
            good.add(c)
        if good:
            out.partial.setdefault(name, set()).update(good)
