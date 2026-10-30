"""Baselines are the engine's (BR-7 step 4 (d), 0.1.9).

core applied a baseline (apply_baseline) with the reports module's fingerprint, sign_fingerprints and verify_signature,
and the npm package with its twin (baseline.js, over pyjson.js: its json.loads). The engine does it for both
(rust/crates/lazaret-engine/src/baseline.rs: the baseline_fingerprints, baseline_sign and baseline_apply calls), as
core did; each package keeps whether the file is one of its reports, where it is, its bytes, the key and the printing.

Held here to core's code as it was (below: what this replaced, word for word but its docstrings, with the key and
the standard error as arguments), on generated baselines: entries of every type json.loads makes in every field,
texts with JSON errors, a byte-order mark, CRLF and CR line ends, bytes that are not UTF-8, ints past Python's 4,300
digits, nesting past 500 levels, signatures right, wrong, of another key, of another algorithm or none, keys with
bytes the environment could not decode, baselines inside and outside the scanned tree; and the npm package's
applyBaseline to the Python package's, line for line and mark for mark. Two answers differ on purpose: where core
raised an error the CLI did not catch (OverflowError: an int too large for a float, in a float's arithmetic; TypeError:
a signature whose value is not ASCII), the engine skips the entry, or the signature does not verify. And N-15: a
signed baseline accepts the findings it holds that no marker can accept (SC-*, X-*), which core's code did not do
(its tests below). All content is inert.
"""
import contextlib
import copy
import hashlib
import hmac
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import _native, core
from lazaret.scanner import reports as lazaret_report
from lazaret.scanner.core import json_loads_bounded, sanitize_term_line
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

if not _native.available():
    raise unittest.SkipTest(f"baselines are the native engine's ({_native.load_error()})")

KEY_ENV = "LAZARET_BASELINE_KEY"

# ---------------------------------------------------------------- core's code as it was (921e794)

_SIGNATURE_DOMAIN = b"lazaret-baseline-v1\n"
#: what core's callers caught of fingerprint(); OverflowError added where the engine's answer is to skip the entry
CORE_ERRORS = (KeyError, TypeError, AttributeError)
SKIPPED = CORE_ERRORS + (OverflowError,)


def ref_fingerprint(issue):
    idx = issue["line"] - issue["snipStart"]
    snippet = issue.get("snippet") or []
    line_text = snippet[idx].strip() if 0 <= idx < len(snippet) else ""
    path = str(issue["file"]).replace("\\", "/")
    return f"{issue['rule']}|{path}|{line_text}"


def ref_fingerprints(issues, errors=SKIPPED):
    out = []
    for i in issues if isinstance(issues, list) else ():
        try:
            fp = ref_fingerprint(i)
        except errors:
            continue
        out.append(fp)
    return out


def ref_sign(fingerprints, key):
    canon = json.dumps(sorted(set(fingerprints)), ensure_ascii=True,
                       separators=(",", ":"))
    return hmac.new(key, _SIGNATURE_DOMAIN + canon.encode("ascii"),
                    hashlib.sha256).hexdigest()


def ref_verify(doc, key):
    if not isinstance(doc, dict):
        return False, "not a JSON object"
    sig = doc.get("baselineSignature")
    if not isinstance(sig, dict) or not isinstance(sig.get("value"), str):
        return False, "it carries no baseline signature"
    if sig.get("alg") != "HMAC-SHA256":
        return False, "unsupported signature algorithm"
    expected = ref_sign(ref_fingerprints(doc.get("issues")), key)
    if not hmac.compare_digest(expected, sig["value"]):
        return False, ("its signature does not verify with "
                       f"${KEY_ENV} (forged, edited, or signed "
                       "with another key)")
    return True, ""


def _ref_untrusted(res, baseline_path, reason, err):
    print(f"warning: baseline {sanitize_term_line(baseline_path)} {reason} — "
          f"treating it as untrusted: all current findings are counted "
          f"as new", file=err)
    for i in res["issues"]:
        i["new"] = True
    res["newIssues"] = len(res["issues"])
    res["baselineUntrusted"] = True


def ref_apply(res, baseline_path, scan_root, key, err):
    """core.apply_baseline; `key`: what reports.baseline_key() gave (bytes or None)."""
    if not lazaret_report.is_our_report(baseline_path, "json"):
        _ref_untrusted(
            res, baseline_path,
            "is not a report produced by this engine (no matching engine "
            "marker, or wrong shape)", err)
        return
    if (key is None and scan_root is not None
            and lazaret_report.path_is_inside(baseline_path, scan_root)):
        _ref_untrusted(
            res, baseline_path,
            f"is inside the scanned tree and ${KEY_ENV} "
            f"is not set (the scanned repository could have planted it) — "
            f"keep baselines outside the scanned tree (e.g. in $RUNNER_TEMP) "
            f"or set {KEY_ENV} so reports are signed", err)
        return
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            prev = json_loads_bounded(fh.read())
    except (OSError, ValueError, MemoryError) as exc:
        print(f"warning: could not read baseline {sanitize_term_line(baseline_path)}: "
              f"{sanitize_term_line(exc)}", file=err)
        return
    if not isinstance(prev, dict):
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: top level is "
              f"{type(prev).__name__}, not an object — expected "
              f'{{"issues": [...]}}; baseline ignored', file=err)
        return
    issues = prev.get("issues", [])
    if not isinstance(issues, list):
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: 'issues' is "
              f"{type(issues).__name__}, not a list — baseline ignored",
              file=err)
        return
    if key is not None:
        ok, why = ref_verify(prev, key)
        if not ok:
            _ref_untrusted(res, baseline_path, f"is not trusted: {why}", err)
            return
    known, skipped = set(), 0
    for i in issues:
        try:
            known.add(ref_fingerprint(i))
        except SKIPPED:
            skipped += 1
    if skipped:
        print(f"warning: baseline {sanitize_term_line(baseline_path)}: {skipped} malformed "
              f"issue entrie(s) skipped (expected objects with "
              f"rule/file/line)", file=err)
    new_count = 0
    for i in res["issues"]:
        i["new"] = ref_fingerprint(i) not in known
        new_count += i["new"]
    res["newIssues"] = new_count


# ---------------------------------------------------------------- generated cases

#: (a lone high surrogate is left out of the texts a package sends: two lone ones, high then low, are one character
#: once they go through JSON, as in test_report_engine)
CHARS = ["a", "Z", "0", " ", "  ", "\t", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x1b", "\x7f", "\x85", "\xa0",
         "\u1680", "\u2028", "\u2029", "\u3000", "\ufeff", "\u200b", "é", "\U0001F600", "\\", "/", '"', "'", "|",
         "\udc80", "\udfff", "{", "[", ",", ":", "eval(x)", "app\\views", "😀"]
RULES = ["S-EVAL-PY", "Q-TODO", "S-SECRET", "T-CMD", "Q-LONG"]
CONDITIONS = ["No blocker issues", "No critical vulnerabilities", "Duplication < 10%", "Maintainability ≥ C",
              "No supply-chain indicators", "No cross-file taint flows"]
KEYS = ["k", "test-key-é", "\udcff\udc80raw", "x" * 100, "another key", ""]


def text(rng, n=6, high=False):
    s = "".join(rng.choice(CHARS) for _ in range(rng.randrange(n)))
    if high and rng.random() < 0.1:
        s += "\ud83d"
    return s


def number(rng, big=True, special=True):
    pick = rng.random()
    if pick < 0.55:
        return rng.randrange(-2, 7)
    if pick < 0.65:
        return rng.choice([True, False])
    if pick < 0.8:
        return rng.choice([1.0, 2.5, -0.0, 0.0, 3.0, 1e300, -1.5] + ([float("nan"), float("inf"), float("-inf")]
                                                                       if special else []))
    if pick < 0.9 and big:
        return rng.choice([10 ** 30 + rng.randrange(3), -(10 ** 25), 10 ** 400 + 1, 10 ** 400])
    return rng.choice(["3", None, [], {}, [1], {"a": 1}])


def value(rng, depth=0, big=True, special=True, high=True):
    pick = rng.random()
    if pick < 0.3 or depth > 2:
        return text(rng, high=high)
    if pick < 0.6:
        return number(rng, big, special)
    if pick < 0.8:
        return [value(rng, depth + 1, big, special, high) for _ in range(rng.randrange(3))]
    return {text(rng, 3, high): value(rng, depth + 1, big, special, high) for _ in range(rng.randrange(3))}


def entry(rng, big=True, special=True, high=True):
    """A baseline's entry: mostly an object of rule, file, line, snipStart and snippet, of any types."""
    if rng.random() < 0.08:
        return value(rng, 1, big, special, high)
    e = {}
    fields = ["rule", "file", "line", "snipStart", "snippet", "msg"]
    rng.shuffle(fields)
    for f in fields:
        if rng.random() < 0.12:
            continue
        if f in ("line", "snipStart"):
            e[f] = number(rng, big, special) if rng.random() < 0.5 else rng.randrange(0, 5)
        elif f == "snippet":
            pick = rng.random()
            e[f] = ([text(rng, high=high) for _ in range(rng.randrange(5))] if pick < 0.75
                    else value(rng, 1, big, special, high))
        elif f == "rule":
            e[f] = rng.choice(RULES) if rng.random() < 0.8 else value(rng, 1, big, special, high)
        else:
            e[f] = text(rng, high=high) if rng.random() < 0.85 else value(rng, 1, big, special, high)
    return e


def finding(rng, rules=RULES):
    n = rng.randrange(1, 6)
    snippet = [text(rng) for _ in range(rng.randrange(1, 5))]
    start = max(1, n - rng.randrange(len(snippet)))
    return {"rule": rng.choice(rules), "type": rng.choice(["VULN", "HOTSPOT", "BUG", "SMELL"]),
            "sev": rng.choice(["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]),
            "file": rng.choice(["a.py", "src\\b.js", "src/b.js", "é/c.py", "d e.py"]), "line": n,
            "snipStart": start, "snippet": snippet, "msg": text(rng)}


def result(rng, rules=RULES):
    issues = [finding(rng, rules) for _ in range(rng.randrange(6))]
    conds = [{"label": label, "ok": rng.random() < 0.6} for label in CONDITIONS]
    return {"issues": issues, "conditions": conds, "pass": all(c["ok"] for c in conds)}


def like(rng, issue):
    """A baseline entry made of a finding: the same, or with its path's separators or its line's blanks changed."""
    e = copy.deepcopy(issue)
    pick = rng.random()
    if pick < 0.2:
        e["file"] = e["file"].replace("/", "\\")
    elif pick < 0.35:
        k = e["line"] - e["snipStart"]
        if 0 <= k < len(e["snippet"]):
            e["snippet"][k] = " \t" + e["snippet"][k] + "\u3000"
    elif pick < 0.45:
        e["line"] += 1
    return e


def key_bytes(key):
    return key.encode("utf-8", "surrogateescape") if key else None


def signature(rng, issues, key):
    pick = rng.random()
    if pick < 0.55:
        return {"alg": "HMAC-SHA256", "value": ref_sign(ref_fingerprints(issues), key_bytes(key) or b"")}
    if pick < 0.65:
        return {"alg": "HMAC-SHA256", "value": ref_sign(ref_fingerprints(issues), b"another")}
    if pick < 0.72:
        return {"alg": "HMAC-SHA256", "value": "%064x" % rng.getrandbits(256)}
    if pick < 0.78:
        return {"alg": "HMAC-SHA1", "value": "00"}
    if pick < 0.84:
        good = ref_sign(ref_fingerprints(issues), key_bytes(key) or b"")
        return {"value": good.upper()}
    return rng.choice([None, "sig", {"alg": "HMAC-SHA256", "value": 5}, {"alg": "HMAC-SHA256"}, []])


def baseline_bytes(rng, res, key):
    """A baseline's bytes: mostly a report of this engine (its marker first) holding entries made of the scan's findings
    and others, written as json.dumps writes it, then perhaps changed."""
    entries = [like(rng, i) for i in res["issues"] if rng.random() < 0.6]
    entries += [entry(rng) for _ in range(rng.randrange(4))]
    rng.shuffle(entries)
    doc = {"generatedBy": "lazaret-cli-1"}
    if key is not None and rng.random() < 0.9:
        doc["baselineSignature"] = signature(rng, entries, key)
    doc["project"] = text(rng)
    pick = rng.random()
    doc["issues"] = entries if pick < 0.9 else rng.choice(["nope", 5, {"a": 1}, None, 2.5])
    if rng.random() < 0.05:
        del doc["issues"]
    out = json.dumps(doc, indent=rng.choice([None, None, 1, 2]), ensure_ascii=rng.random() < 0.8)
    data = out.encode("utf-8", "surrogatepass")
    head = len(b'{"generatedBy": "lazaret-cli-1",') + 4
    pick = rng.random()
    if pick < 0.08:
        data = data.replace(b"\n", b"\r\n")
    elif pick < 0.12:
        data = data.replace(b"\n", b"\r")
    elif pick < 0.16:
        data = b"\xef\xbb\xbf" + data
    elif pick < 0.24:
        cut = rng.randrange(head, len(data) + 1)
        data = data[:cut] + rng.choice([b"", b"x", b",", b"]", b"\xff", b"\xc3", b"\xe2\x82", b"\x01", b"\\q"]) + data[cut:]
    elif pick < 0.28:
        data = data[:rng.randrange(head, len(data) + 1)]
    elif pick < 0.32:
        data = data.replace(b'"project":', b'"n": ' + b"9" * rng.choice([1001, 4300, 4301, 5000]) + b', "project":', 1)
    elif pick < 0.36:
        data = data.replace(b'"project":', b'"deep": ' + b"[" * 499 + b"]" * 499 + b', "project":', 1)
    elif pick < 0.39:
        data = data.replace(b'"project":', b'"deep": ' + b"[" * 501 + b"]" * 501 + b', "project":', 1)
    elif pick < 0.41:
        data = data.replace(b'"project":', b'"n": 1e400, "nan": NaN, "project":', 1)
    elif pick < 0.44:
        data = data + rng.choice([b" x", b"}", b"\n\n[]", b"\r\n\t "])
    return data


@contextlib.contextmanager
def keyed(key):
    env = {k: v for k, v in os.environ.items() if k != KEY_ENV}
    if key is not None:
        env[KEY_ENV] = key
    with mock.patch.dict(os.environ, env, clear=True):
        yield


def run_engine(res, path, root, key):
    err = io.StringIO()
    with keyed(key), contextlib.redirect_stderr(err):
        core.apply_baseline(res, path, scan_root=root)
    return err.getvalue()


def run_ref(res, path, root, key):
    err = io.StringIO()
    ref_apply(res, path, root, key_bytes(key), err)
    return err.getvalue()


class Scenarios:
    """Baselines written to a folder: (path, root, key, res) each, the scan's result as it was before."""

    def __init__(self, seed, n, rules=RULES):
        self.dir = tempfile.mkdtemp(prefix="lazaret-baseline-")
        rng = random.Random(seed)
        tree = os.path.join(self.dir, "tree")
        out = os.path.join(self.dir, "out")
        os.makedirs(tree)
        os.makedirs(out)
        os.makedirs(os.path.join(out, "a-folder"))
        self.cases = []
        for k in range(n):
            res = result(rng, rules)
            key = rng.choice(KEYS + [None, None, None])
            where = tree if rng.random() < 0.3 else out
            path = os.path.join(where, f"base-{k}.json")
            pick = rng.random()
            if pick < 0.05:
                data = json.dumps({"issues": []}).encode()          # not ours: no marker
            elif pick < 0.07:
                data = None                                         # nothing there
            elif pick < 0.08:
                path = os.path.join(out, "a-folder")
                data = None
            else:
                data = baseline_bytes(rng, res, key or None)
            if data is not None:
                with open(path, "wb") as f:
                    f.write(data)
            root = None if rng.random() < 0.15 else tree
            self.cases.append((path, root, key, res))

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


#: the reasons 3.10 to 3.12 word otherwise than 3.13, whose words the engine gives: an int past 4,300 digits
#: ("Exceeds the limit (4300)" on 3.10, "(4300 digits)" since), and a string a bad \\u escape ends ("Invalid
#: \\uXXXX escape" where 3.13 says "Unterminated string"; CI's python-unit, Oct 29)
WORDED_OTHERWISE = (": Exceeds the limit (4300", ": Invalid \\uXXXX escape", ": Unterminated string starting at")


def reason_cut(text, path):
    """`text` with a "could not read baseline" line whose reason is one WORDED_OTHERWISE cut after its path: on those
    Pythons, that the baseline is refused is compared there, and every other line and reason word for word."""
    head = f"warning: could not read baseline {path}"
    return "\n".join(head if line.startswith(head) and any(w in line for w in WORDED_OTHERWISE) else line
                     for line in text.split("\n"))


class ApplyTests(unittest.TestCase):
    def test_the_engines_baseline_is_cores(self):
        cases = Scenarios(4, 500)
        try:
            for k, (path, root, key, res) in enumerate(cases.cases):
                with self.subTest(k, key=key, path=os.path.basename(path)):
                    mine, theirs = copy.deepcopy(res), copy.deepcopy(res)
                    got, want = run_engine(mine, path, root, key), run_ref(theirs, path, root, key)
                    if sys.version_info < (3, 13):
                        got, want = reason_cut(got, path), reason_cut(want, path)
                    self.assertEqual(got, want)
                    self.assertEqual(mine, theirs)
        finally:
            cases.close()

    def test_every_path_is_taken(self):
        """The generated cases reach each of core's answers (so the comparison above means something)."""
        cases = Scenarios(4, 500)
        seen = set()
        try:
            for path, root, key, res in cases.cases:
                said = run_ref(copy.deepcopy(res), path, root, key)
                for what in ("not a report produced", "is inside the scanned tree", "could not read baseline",
                             "Expecting", "Extra data", "Unexpected UTF-8 BOM", "codec can't decode", "Exceeds the limit",
                             "nested deeper than", "'issues' is", "carries no baseline signature",
                             "unsupported signature algorithm", "does not verify", "malformed issue entrie"):
                    if what in said:
                        seen.add(what)
                if not said:
                    seen.add("applied")
        finally:
            cases.close()
        self.assertEqual(len(seen), 15, sorted(seen))

    def test_core_raised_where_the_engine_skips(self):
        """An int too large for a float, in a float's arithmetic: core's OverflowError went past apply_baseline;
        the entry is skipped (its warning says so). A signature that is not ASCII: core's TypeError; it does not
        verify."""
        with self.assertRaises(OverflowError):
            ref_fingerprint({"rule": "R", "file": "f", "line": 10 ** 400, "snipStart": 0.5})
        self.assertEqual(lazaret_report.fingerprints([{"rule": "R", "file": "f", "line": 1.5, "snipStart": 0,
                                                        "snippet": ["a", "b"]}]), [None])
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, "b.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"generatedBy": "lazaret-cli-1", "issues": [{"rule": "R", "file": "f", "line": 1' + "0" * 400
                        + ', "snipStart": 0.5}, {"rule": "R", "file": "a.py", "line": 1, "snipStart": 1, "snippet": ["x"]}]}')
            res = {"issues": [{"rule": "R", "type": "BUG", "sev": "MINOR", "file": "a.py", "line": 1, "snipStart": 1,
                               "snippet": ["x"]}], "conditions": [], "pass": True}
            said = run_engine(res, path, None, None)
            self.assertIn(": 1 malformed issue entrie(s) skipped", said)
            self.assertEqual((res["issues"][0]["new"], res["newIssues"]), (False, 0))
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"generatedBy": "lazaret-cli-1", "baselineSignature": {"alg": "HMAC-SHA256", "value": "é"}, '
                        '"issues": []}')
            with self.assertRaises(TypeError):
                run_ref(copy.deepcopy(res), path, None, "k")
            said = run_engine(res, path, None, "k")
            self.assertIn("its signature does not verify", said)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class FingerprintTests(unittest.TestCase):
    def test_a_findings_fingerprint_is_cores(self):
        """Values a package sends (no NaN, no int past 64 bits: what JSON carries to the engine as they are)."""
        rng = random.Random(9)
        entries = [entry(rng, big=False, special=False, high=False) for _ in range(4000)]
        got = lazaret_report.fingerprints(entries)
        for k, (e, fp) in enumerate(zip(entries, got)):
            try:
                want = ref_fingerprint(e)
            except SKIPPED:
                want = None
            with self.subTest(k, entry=e):
                self.assertEqual(fp, want)

    def test_portable_across_path_separators(self):
        issue = {"rule": "S-EVAL-PY", "line": 3, "snipStart": 1, "snippet": ["import os", "", "eval(data)", ""]}
        a = core.fingerprint(dict(issue, file="app\\views\\admin.py"))
        self.assertEqual(a, core.fingerprint(dict(issue, file="app/views/admin.py")))
        self.assertEqual(a, "S-EVAL-PY|app/views/admin.py|eval(data)")
        self.assertNotEqual(core.fingerprint(dict(issue, file="app/a.py")), core.fingerprint(dict(issue, file="app/b.py")))
        with self.assertRaises(TypeError):
            core.fingerprint("nonsense")

    def test_the_signature_is_cores(self):
        rng = random.Random(3)
        for k in range(300):
            fps = [text(rng, 8) for _ in range(rng.randrange(6))]
            fps += fps[:rng.randrange(3)]
            # (an environment's string: a surrogate only as surrogateescape makes one of a byte, U+DC80 to U+DCFF)
            key = "".join(c for c in text(rng, 5) if not ("\ud800" <= c <= "\udfff") or "\udc80" <= c <= "\udcff")
            key = rng.choice(KEYS[:-1] + [key or "k"])
            with self.subTest(k):
                self.assertEqual(lazaret_report.sign_fingerprints(fps, key), ref_sign(fps, key_bytes(key)))


# ---------------------------------------------------------------- N-15: a signed baseline accepts SC-* and X-*

def scan_like(rule, sev, typ="VULN", file="package.json", line=1, text="x"):
    return {"rule": rule, "type": typ, "sev": sev, "file": file, "line": line, "snipStart": line, "snippet": [text],
            "msg": "m", "why": "w", "fix": "f", "ref": "r"}


class AcceptTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lazaret-accept-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def graded(self, issues):
        files = [{"path": i["file"], "content": "x\n", "lang": "py", "dep": False} for i in issues]
        return core.build_result(self.dir, files, issues)

    def write(self, res, key):
        path = os.path.join(self.dir, "base.json")
        with keyed(key):
            text = lazaret_report.json_renderer(res)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_a_signed_baseline_accepts_what_no_marker_can(self):
        hook = scan_like("SC-INSTALL-HOOK", "MAJOR", "HOTSPOT", text='"postinstall": "node x.js"')
        flow = scan_like("X-TAINT-JS", "CRITICAL", "VULN", file="a.js", text="exec(q)")
        vuln = scan_like("S-EVAL-PY", "CRITICAL", "VULN", file="b.py", text="eval(x)")
        base = self.graded([copy.deepcopy(hook), copy.deepcopy(flow)])
        path = self.write(base, "k")
        res = self.graded([copy.deepcopy(hook), copy.deepcopy(flow), copy.deepcopy(vuln)])
        self.assertFalse(res["pass"])
        said = run_engine(res, path, self.dir, "k")
        self.assertEqual(said, "")
        accepted = {i["rule"]: i.get("accepted", False) for i in res["issues"]}
        self.assertEqual(accepted, {"SC-INSTALL-HOOK": True, "X-TAINT-JS": True, "S-EVAL-PY": False})
        self.assertEqual((res["acceptedIssues"], res["newIssues"]), (2, 1))
        ok = {c["label"]: c["ok"] for c in res["conditions"]}
        self.assertTrue(ok["No supply-chain indicators"])
        self.assertTrue(ok["No cross-file taint flows"])
        self.assertFalse(ok["No critical vulnerabilities"])   # S-EVAL-PY is new, and a marker could accept it
        self.assertFalse(res["pass"])
        self.assertEqual((res["supplyChain"], res["crossFile"], res["counts"]["VULN"]), (1, 1, 2))   # still counted
        # without the new finding, the gate passes
        res = self.graded([copy.deepcopy(hook), copy.deepcopy(flow)])
        run_engine(res, path, self.dir, "k")
        self.assertTrue(res["pass"])

    def test_without_a_key_or_with_another_nothing_is_accepted(self):
        hook = scan_like("SC-INSTALL-HOOK", "MAJOR", "HOTSPOT")
        path = self.write(self.graded([copy.deepcopy(hook)]), "k")
        out = os.path.join(self.dir, "out")
        os.makedirs(out)
        moved = shutil.copy(path, out)
        res = self.graded([copy.deepcopy(hook)])
        self.assertEqual(run_engine(res, moved, self.dir + "/none", None), "")    # trusted (outside), unsigned use
        self.assertEqual((res["newIssues"], "acceptedIssues" in res, res["pass"]), (0, False, False))
        res = self.graded([copy.deepcopy(hook)])
        self.assertIn("does not verify", run_engine(res, path, self.dir, "other"))
        self.assertEqual((res["newIssues"], "acceptedIssues" in res, res["pass"]), (1, False, False))

    def test_a_new_finding_of_the_same_rule_is_not_accepted(self):
        hook = scan_like("SC-INSTALL-HOOK", "MAJOR", "HOTSPOT", text='"postinstall": "node x.js"')
        other = scan_like("SC-INSTALL-HOOK", "MAJOR", "HOTSPOT", text='"preinstall": "node y.js"')
        path = self.write(self.graded([copy.deepcopy(hook)]), "k")
        res = self.graded([copy.deepcopy(hook), copy.deepcopy(other)])
        run_engine(res, path, self.dir, "k")
        self.assertEqual(res["acceptedIssues"], 1)
        self.assertFalse(res["pass"])
        self.assertFalse({c["label"]: c["ok"] for c in res["conditions"]}["No supply-chain indicators"])

    def test_the_reports_show_what_was_accepted(self):
        hook = scan_like("SC-INSTALL-HOOK", "MAJOR", "HOTSPOT")
        path = self.write(self.graded([copy.deepcopy(hook)]), "k")
        res = self.graded([copy.deepcopy(hook)])
        res["project"] = self.dir
        run_engine(res, path, self.dir, "k")
        self.assertTrue(res["pass"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.print_report(res, quiet=True)
        self.assertIn("  Accepted by the signed baseline: 1 (supply-chain and cross-file findings the gate does not "
                      "count)\n", out.getvalue())
        self.assertIn("Quality gate:  PASSED", out.getvalue())
        html = "".join(core.html_chunks(res))
        self.assertIn('<span class="itype">Accepted</span>', html)
        self.assertIn('<p class="accepted">Accepted by the signed baseline: 1', html)
        sarif = core.sarif_report(res, self.dir)
        self.assertEqual(sarif["runs"][0]["results"][0]["suppressions"], [
            {"kind": "external", "status": "accepted",
             "justification": "Accepted: held by a baseline whose signature verifies with LAZARET_BASELINE_KEY"}])
        doc = json.loads(lazaret_report.json_renderer(res))
        self.assertEqual((doc["acceptedIssues"], doc["issues"][0]["accepted"]), (1, True))


    def test_the_gate_passes_on_an_accepted_finding_with_ci(self):
        root = os.path.join(self.dir, "app")
        os.makedirs(root)
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as f:
            f.write('{"name": "app", "scripts": {"postinstall": "node setup.js"}}\n')
        with open(os.path.join(root, "setup.js"), "w", encoding="utf-8") as f:
            f.write("module.exports = { ready: true };\n")
        base = os.path.join(self.dir, "base.json")
        keyed_env = dict(os.environ, **{KEY_ENV: "k"})

        def cli(*args, env=keyed_env):
            return subprocess.run([sys.executable, _support.CLI, root, "--no-html", "-q", *args], capture_output=True,
                                  encoding="utf-8", errors="replace", timeout=120, env=env)
        first = cli("--json", base, "--ci")
        self.assertEqual(first.returncode, 1, first.stdout + first.stderr)       # the install hook fails the gate
        again = cli("--no-json", "--baseline", base, "--ci")
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn("Accepted by the signed baseline: 1 ", again.stdout)
        plain = cli("--no-json", "--baseline", base, "--ci", env={k: v for k, v in keyed_env.items() if k != KEY_ENV})
        self.assertEqual(plain.returncode, 1, plain.stdout + plain.stderr)      # no key: nothing accepted


NODE_APPLY = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const b = await import(pathToFileURL(process.argv[1]).href);
const cases = JSON.parse(readFileSync(0).toString("utf8"));
process.stdout.write(JSON.stringify(cases.map(([path, root, key, res]) => {
  const warnings = [];
  b.applyBaseline(res, path, { root, warn: (l) => warnings.push(l), env: key === null ? {} : { LAZARET_BASELINE_KEY: key } });
  return [warnings, res];
})));
"""


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class NpmTests(unittest.TestCase):
    def test_the_npm_packages_baseline_is_the_python_packages(self):
        cases = Scenarios(5, 200, rules=RULES + ["SC-INSTALL-HOOK", "X-TAINT-JS"])
        try:
            p = subprocess.run([NPM_READY, "--input-type=module", "-e", NODE_APPLY,
                                os.path.join(_support.REPO_ROOT, "js", "src", "baseline.js")],
                               input=json.dumps(cases.cases), capture_output=True, encoding="utf-8",
                               errors="surrogatepass", timeout=120)
            self.assertEqual(p.returncode, 0, p.stderr[-2000:])
            got = json.loads(p.stdout)
            self.assertEqual(len(got), len(cases.cases))
            for k, ((path, root, key, res), (warnings, npm_res)) in enumerate(zip(cases.cases, got)):
                with self.subTest(k):
                    mine = copy.deepcopy(res)
                    said = run_engine(mine, path, root, key)
                    self.assertEqual("".join(w + "\n" for w in warnings), said)
                    self.assertEqual(npm_res, json.loads(json.dumps(mine)))
        finally:
            cases.close()


if __name__ == "__main__":
    unittest.main()
