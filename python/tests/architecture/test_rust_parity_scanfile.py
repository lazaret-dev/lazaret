"""Engine parity for scan_file in dependency mode (registry, guard and
--deps scans): the native engine (crates/lazaret-engine: scanfile.rs,
findings.rs, filectx.rs) against core.scan_file(dep=True), finding for
finding — rule, texts, line, snippet (clipped, secrets redacted) — family
by family, on the scan_file corpus (scanfile_corpus.py) and on real files:
this repository's sources and fixtures, and a sample of Python's standard
library. Also what the families read: each line's comment layout, match
text and names (core._FileCtx), and Unicode normalization.

A difference names its family (the rule), the file and the first finding
that differs. The native engine runs in a thread while core reads the
files. Skipped where the native library is not built.
"""
import json
import os
import random
import sys
import threading
import unicodedata
import unittest

from lazaret.scanner import _native, _unicode13, core
from tests import _support
from tests.architecture.scanfile_corpus import corpus

KEYS = ("rule", "name", "type", "sev", "msg", "why", "fix", "ref")
CHUNK = 256
FAMILIES = ("S-SECRET", "S-TOKEN", "SC-EVAL-DECODE", "SC-PACKER", "SC-EVAL-DECODER", "SC-MARSHAL", "SC-HEXSTR",
            "SC-HOMOGLYPH", "SC-HIDDEN-UNICODE", "SC-CHARCODE", "SC-B64", "SC-OFFSCREEN-CODE", "S-ENTROPY",
            "SC-OBF-IDENT", "SC-SELF-PUBLISH")
# each variant a family can take, reached by the corpus: (rule, severity, a piece of the message)
VARIANTS = (("SC-HEXSTR", "CRITICAL", "hide readable text"), ("SC-HEXSTR", "MAJOR", "hide readable text"),
            ("SC-HEXSTR", "CRITICAL", "hide a name"), ("SC-HOMOGLYPH", "CRITICAL", "another name in this file"),
            ("SC-HOMOGLYPH", "CRITICAL", "reads as"), ("SC-HOMOGLYPH", "MAJOR", "reads as"),
            ("SC-HOMOGLYPH", "CRITICAL", "invisible"), ("SC-HIDDEN-UNICODE", "CRITICAL", "runs code"),
            ("SC-HIDDEN-UNICODE", "MAJOR", "tag characters"), ("SC-HIDDEN-UNICODE", "MAJOR", "variation selectors"),
            ("SC-OFFSCREEN-CODE", "CRITICAL", "blanks"), ("SC-OFFSCREEN-CODE", "MAJOR", "blanks"),
            ("SC-EVAL-DECODE", "BLOCKER", "assigned at line"), ("SC-EVAL-DECODE", "BLOCKER", "in the same call"))
MAX_REAL = 300_000                     # characters of a real file read


def lang_of(path):
    return core.EXTS.get(os.path.splitext(path)[1].lower())


def call_args(path):
    return {"lang": lang_of(path), "dep": True, "jsx": core.jsx_reading(path), "neumaier": sys.version_info >= (3, 12)}


def jsonable(v):
    """A value as JSON carries it (both sides are compared so)."""
    return json.loads(json.dumps(v))


def as_issues(path, answer):
    """The native engine's answer as core's issue dicts."""
    out = []
    for a in answer:
        issue = dict(zip(KEYS, a[:8]))
        issue.update(file=path, line=a[8], snippet=a[9], snipStart=a[10])
        if len(a) > 11:
            issue.update(omitted=a[11], omittedType=a[12])
        out.append(issue)
    return out


def context_view(path, text):
    """core's context of a file, per line: [comment line, comment spans,
    match text, match text without comments, names]."""
    lang = lang_of(path)
    lines = core.source_lines(_unicode13.pin(text), lang)
    ctx = core._FileCtx(lines, lang, "\n".join(lines), None, core.jsx_reading(path))
    return [[ctx.cmask[i], [list(s) for s in ctx.cspans.get(i, [])], ctx.mlines[i], ctx.mcode(i), ctx.names_code(i)]
            for i in range(len(lines))]


def real_files():
    """(path, text): this repository's Python and JavaScript sources and
    fixtures, and every 12th module of the standard library."""
    out = []
    roots = [os.path.join(_support.PY_ROOT, "src"), os.path.join(_support.REPO_ROOT, "js", "src"),
             os.path.join(_support.PY_ROOT, "tests", "fixtures")]
    stdlib = []
    for root, _dirs, files in os.walk(os.path.dirname(os.__file__)):
        if "site-packages" in root or "dist-packages" in root:
            continue
        stdlib += [os.path.join(root, f) for f in files if f.endswith(".py")]
    paths = []
    for base in roots:
        for root, _dirs, files in os.walk(base):
            paths += [os.path.join(root, f) for f in sorted(files) if lang_of(f)]
    paths += sorted(stdlib)[::12]
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if len(text) <= MAX_REAL:
            out.append((os.path.relpath(p, _support.REPO_ROOT) if p.startswith(_support.REPO_ROOT) else p, text))
    return out


def native_answers(call, cases, box):
    answers = []
    try:
        for i in range(0, len(cases), CHUNK):
            chunk = cases[i:i + CHUNK]
            batch = [[call, call_args(path), text] for path, text in chunk]
            answers += _native.call("batch", {"calls": batch, "threads": 2})
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)
    box["answers"] = answers


def run_both(call, cases, core_side):
    box = {}
    worker = threading.Thread(target=native_answers, args=(call, cases, box))
    worker.start()
    want = [core_side(path, text) for path, text in cases]
    worker.join()
    return want, box


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustScanFileParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus() + real_files()
        cls.want, box = run_both("scan_file", cls.cases, lambda path, text: jsonable(
            core.scan_file(path, text, lang_of(path), dep=True)))
        cls.error = box.get("error")
        cls.got = [jsonable(as_issues(path, a["ok"])) if "ok" in a else a
                   for (path, _text), a in zip(cls.cases, box.get("answers", []))]

    def test_every_file_is_answered(self):
        self.assertIsNone(self.error)
        self.assertEqual(len(self.got), len(self.cases))
        unanswered = [(path, g) for (path, _t), g in zip(self.cases, self.got) if not isinstance(g, list)]
        self.assertEqual(unanswered[:5], [])

    def test_each_family_agrees(self):
        families = sorted({i["rule"] for issues in self.want for i in issues}
                          | {i["rule"] for issues in self.got if isinstance(issues, list) for i in issues})
        for family in families:
            with self.subTest(family=family):
                found = []
                for (path, text), want, got in zip(self.cases, self.want, self.got):
                    if not isinstance(got, list):
                        continue
                    w = [i for i in want if i["rule"] == family]
                    g = [i for i in got if i["rule"] == family]
                    if w != g:
                        k = next((k for k, (a, b) in enumerate(zip(w, g)) if a != b), min(len(w), len(g)))
                        found.append((path, text[:300], w[k:k + 1], g[k:k + 1]))
                        if len(found) >= 3:
                            break
                self.assertEqual(found, [])

    def test_the_findings_come_in_cores_order(self):
        for (path, _t), want, got in zip(self.cases, self.want, self.got):
            if isinstance(got, list) and got != want:
                self.fail(f"{path}: {[i['rule'] for i in want]} != {[i['rule'] for i in got]}")

    def test_every_family_is_reached(self):
        """The corpus makes core find each family, in each of its variants."""
        found = [i for issues in self.want for i in issues]
        for family in FAMILIES:
            with self.subTest(family=family):
                self.assertTrue(any(i["rule"] == family for i in found), family)
        for rule, sev, piece in VARIANTS:
            with self.subTest(rule=rule, sev=sev, msg=piece):
                self.assertTrue(any(i["rule"] == rule and i["sev"] == sev and piece in i["msg"] for i in found))
        # and redaction: a secret on a flagged line and in the lines around one
        self.assertTrue(any("[redacted" in line for i in found for line in i["snippet"]))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustFileContextParityTests(unittest.TestCase):
    """What each family reads: the comment layout, match text and names."""
    maxDiff = None

    def test_every_line_reads_the_same(self):
        cases = corpus(seed=7, scale=1)[::2] + real_files()[::3]
        want, box = run_both("file_context", cases, lambda path, text: jsonable(context_view(path, text)))
        self.assertIsNone(box.get("error"))
        got = box.get("answers", [])
        self.assertEqual(len(got), len(cases))
        found = []
        fields = ("comment line", "comment spans", "match text", "match text without comments", "names")
        for (path, text), w, g in zip(cases, want, got):
            if "ok" not in g:
                found.append((path, g))
                continue
            g = jsonable(g["ok"])
            if len(w) != len(g):
                found.append((path, "lines", len(w), len(g)))
                continue
            for n, (a, b) in enumerate(zip(w, g)):
                for field, x, y in zip(fields, a, b):
                    if x != y:
                        found.append((path, n + 1, field, x, y))
            if len(found) >= 10:
                break
        self.assertEqual(found, [])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustNormalizationParityTests(unittest.TestCase):
    """NFC, NFD, NFKC and NFKD of text pinned to Unicode 13.0: every
    assigned code point alone, and random strings of the characters
    composition turns on (combining marks, the pairs' first and second
    characters, Hangul jamo and syllables, compatibility characters)."""

    @classmethod
    def setUpClass(cls):
        cls.cps = [c for c in range(0x110000) if _unicode13.assigned(c) and not 0xD800 <= c <= 0xDFFF]

    def compare(self, form, texts):
        bad = []
        for i in range(0, len(texts), 4000):
            chunk = texts[i:i + 4000]
            answers = _native.call("batch", {"calls": [["normalize", {"form": form}, t] for t in chunk], "threads": 2})
            for t, a in zip(chunk, answers):
                if a.get("ok") != unicodedata.normalize(form, t):
                    bad.append((form, [f"U+{ord(c):04X}" for c in t]))
                    if len(bad) >= 10:
                        return bad
        return bad

    def test_each_code_point(self):
        singles = [chr(c) for c in self.cps]
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            with self.subTest(form=form):
                self.assertEqual(self.compare(form, singles), [])

    def test_sequences(self):
        rnd = random.Random(15)
        marks = [c for c in self.cps if unicodedata.combining(chr(c))]
        decomposable = [c for c in self.cps if unicodedata.decomposition(chr(c))
                        and not 0xAC00 <= c <= 0xD7A3]
        pairs = [d.split() for d in map(unicodedata.decomposition, map(chr, decomposable))
                 if d and not d.startswith("<") and len(d.split()) == 2]
        firsts = sorted({int(a, 16) for a, _ in pairs})
        seconds = sorted({int(b, 16) for _, b in pairs})
        jamo = list(range(0x1100, 0x1113)) + list(range(0x1161, 0x1176)) + list(range(0x11A7, 0x11C3))
        syllables = [0xAC00, 0xAC01, 0xAC1C, 0xB098, 0xB099, 0xD7A3]
        pools = [marks, decomposable, firsts, seconds, jamo, syllables, [0x61, 0x41, 0x3A3, 0x300, 0x301, 0x323, 0x345]]
        texts = ["".join(chr(rnd.choice(rnd.choice(pools))) for _ in range(rnd.randint(1, 8))) for _ in range(20000)]
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            with self.subTest(form=form):
                self.assertEqual(self.compare(form, texts), [])


if __name__ == "__main__":
    unittest.main()
