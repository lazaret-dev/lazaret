"""A scan's result is the engine's (BR-7 step 4 (a), 0.1.9).

core.build_result, regrade and compute_metrics and the npm package's buildResult, regrade and computeMetrics each
graded a scan in their own language, held equal by the parity tests: the findings' order, the counts, the three
ratings, the gate's six conditions, the supply-chain indicators, the cross-file flows, the findings by file, and the
duplication across a project's files. The engine does it once (rust/crates/lazaret-engine/src/result.rs: the
`result`, `regrade` and `project_metrics` calls); each package keeps the project's path, the time and asking the
engine for each file's line metrics.

Held here to core's code as it was (REFERENCE_*, below: what this replaced, word for word), on generated sets
(every type, severity and kind of rule; files whose names sort differently by code point and by UTF-16 unit; Q-CAPPED
notes; files of every language, with their metrics, without them, and without a text) and on the findings of the
fixtures' files; and the WebAssembly build to the native library on the same calls.
"""
import copy
import os
import random
import unittest

from lazaret.scanner import _native, _unicode13, core, engine
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

if not _native.available():
    raise unittest.SkipTest(f"the result is the native engine's ({_native.load_error()})")

# ---------------------------------------------------------------- core's code as it was (f8bc410)

DUP_LANGS = frozenset({"py", "js", "sql"})
COVERAGE_RULES = frozenset({"Q-SKIPPED-TREE", "Q-SYMLINK", "Q-UNREADABLE", "Q-SKIPPED-CONFIG",
                            "Q-FLOW-SKIPPED", "Q-FLOW-INCOMPLETE", "Q-FLOW-RECURSION", "Q-TAINT-CONFIG"})
HARDENING_RULES = frozenset({
    "SC-WORKFLOW-UNPINNED", "SC-WORKFLOW-PR-CHECKOUT", "SC-WORKFLOW-CACHE", "SC-WORKFLOW-PERMISSIONS",
    "SC-WORKFLOW-OIDC-INSTALL", "SC-WORKFLOW-PIPE-SHELL",
    "SC-GITLAB-INCLUDE", "SC-GITLAB-IMAGE", "SC-GITLAB-PIPE-SHELL", "SC-GITLAB-MR-TEXT", "SC-GITLAB-TOKEN-INSTALL",
    "SC-AGENT-CONFIG"})                                   # (RA-2: what an agent's settings let it do, a setting)
SEV_ORDER = {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2, "MINOR": 3, "INFO": 4}
TYPE_LABEL = {"VULN": "Vulnerability", "HOTSPOT": "Security Hotspot", "BUG": "Bug", "SMELL": "Code Smell"}


def REFERENCE_compute_metrics(all_files):
    files = [f for f in all_files if not f.get("dep")]
    answers = [f.get("lineMetrics") for f in files]
    todo = [k for k, got in enumerate(answers) if got is None]
    for k, got in zip(todo, engine.file_metrics([(files[k].get("path"), files[k].get("content"), files[k].get("lang"))
                                                  for k in todo])):
        answers[k] = got
    ncloc = comments = measured = left_out = 0
    starts = {}
    for f, got in zip(files, answers):
        dup_lang = f.get("lang") is None or f["lang"] in DUP_LANGS
        if got is None:
            lines = [l for l in _unicode13.pin(str(f.get("content") or "")).split("\n") if l.strip()]
            ncloc += len(lines)
            if dup_lang:
                measured += len(lines)
            else:
                left_out += len(lines)
            continue
        f_ncloc, f_comments, f_measured, windows = got
        ncloc += f_ncloc
        if not dup_lang:
            left_out += f_ncloc
        comments += f_comments
        for k in range(0, len(windows), 16):
            starts.setdefault(windows[k:k + 16], []).append(measured + k // 16)
        measured += f_measured
    dup = set()
    for at in starts.values():
        if len(at) > 1:
            for a in at:
                dup.update(range(a, a + 6))
    dup_pct = round(100 * len(dup) / measured, 1) if measured else 0.0
    return {"files": len(files), "depFiles": len(all_files) - len(files),
            "ncloc": ncloc, "comments": comments, "dupPct": dup_pct, "dupLeftOut": left_out}


def worst_sev_rating(issues, types):
    sevs = {i["sev"] for i in issues if i["type"] in types}
    for sev, rating in (("BLOCKER", "E"), ("CRITICAL", "D"), ("MAJOR", "C"), ("MINOR", "B")):
        if sev in sevs:
            return rating
    return "A"


def _rated_smells(issue):
    if issue.get("rule") == "Q-CAPPED" and isinstance(issue.get("omitted"), int):
        return issue["omitted"] if issue.get("omittedType") == "SMELL" else 0
    return 1


def maintainability_rating(issues, ncloc):
    smells = sum(_rated_smells(i) for i in issues
                 if i["type"] == "SMELL" and i.get("rule") not in COVERAGE_RULES)
    per100 = 100 * smells / ncloc if ncloc else 0
    for limit, rating in ((5, "A"), (10, "B"), (20, "C"), (40, "D")):
        if per100 <= limit:
            return rating
    return "E"


def _severity_grades(issues):
    counts = {t: sum(1 for i in issues if i["type"] == t) for t in TYPE_LABEL}
    ratings = {"security": worst_sev_rating(issues, ("VULN",)),
               "reliability": worst_sev_rating(issues, ("BUG",))}
    conds = [
        {"label": "No blocker issues",
         "ok": not any(i["sev"] == "BLOCKER" for i in issues)},
        {"label": "No critical vulnerabilities",
         "ok": not any(i["type"] == "VULN" and i["sev"] in ("CRITICAL", "BLOCKER") for i in issues)},
    ]
    return counts, ratings, conds


def REFERENCE_regrade(res):
    issues = res["issues"]
    issues.sort(key=lambda i: (SEV_ORDER[i["sev"]], i["file"], i["line"]))
    counts, ratings, conds = _severity_grades(issues)
    res["counts"] = counts
    res["ratings"].update(ratings)
    now = {c["label"]: c["ok"] for c in conds}
    for cond in res["conditions"]:
        if cond["label"] in now:
            cond["ok"] = now[cond["label"]]
    res["pass"] = all(c["ok"] for c in res["conditions"])
    return res


def REFERENCE_build_result(files, issues):
    issues.sort(key=lambda i: (SEV_ORDER[i["sev"]], i["file"], i["line"]))
    metrics = REFERENCE_compute_metrics(files)
    counts, ratings, conds = _severity_grades(issues)
    ratings["maintainability"] = maintainability_rating(issues, metrics["ncloc"])
    conds += [
        {"label": "Duplication < 10%", "ok": metrics["dupPct"] < 10},
        {"label": "Maintainability ≥ C", "ok": ratings["maintainability"] in "ABC"},
    ]
    per_file = {}
    for i in issues:
        per_file[i["file"]] = per_file.get(i["file"], 0) + 1
    supply = sum(1 for i in issues if i["rule"].startswith("SC-") and i["sev"] != "INFO"
                 and (i["rule"] not in HARDENING_RULES or i["sev"] == "CRITICAL"))
    conds.append({"label": "No supply-chain indicators", "ok": supply == 0})
    cross_file = sum(1 for i in issues if i["rule"].startswith("X-"))
    conds.append({"label": "No cross-file taint flows", "ok": cross_file == 0})
    return {"pass": all(c["ok"] for c in conds), "conditions": conds,
            "metrics": metrics, "counts": counts, "ratings": ratings,
            "supplyChain": supply, "crossFile": cross_file,
            "perFile": per_file, "issues": issues}


# ---------------------------------------------------------------- the sets

RULES = ["SC-INSTALL-HOOK", "SC-WORKFLOW-UNPINNED", "SC-GITLAB-IMAGE", "SC-WORKFLOW-EXFIL", "X-TAINT-PY", "X-CMD",
         "S-EVAL-PY", "S-SECRET", "Q-CAPPED", "Q-SYMLINK", "Q-FLOW-SKIPPED", "Q-LONGLINE", "Q-TODO", "B-EQEQ", "T-CMD"]
#: names that sort otherwise by UTF-16 unit than by code point (U+FFFF before U+10000 here), and the odd ones
FILES = ["a.py", "b.py", "a/b.py", "A.py", "￿.py", "\U00010000.py", "é.js", "__proto__", "constructor", "", "x y",
         "lib/\U0001F600.py", "z" * 40]
LINES = ["x = 1", "y = compute(x)", "# a comment", "", "   ", "return y", "if x: pass", "print(x)", " ",
         "s = 'café'", "// js comment", "const a = 1;", "SELECT 1;", "\u2028", "x = 1  # tail"]


def issue(rng, k):
    i = {"rule": rng.choice(RULES), "type": rng.choice(list(TYPE_LABEL)), "sev": rng.choice(list(SEV_ORDER)),
         "file": rng.choice(FILES), "line": rng.choice([0, 1, 2, 3, 10, 99, 100000, rng.randrange(1, 500)]),
         "msg": f"finding {k}", "snippet": ["a", "b"], "snipStart": 1}
    if i["rule"] == "Q-CAPPED" and rng.random() < 0.8:
        i["omitted"] = rng.choice([0, 1, 7, 1800])
        i["omittedType"] = rng.choice(["SMELL", "BUG", "VULN"])
    return i


def project_file(rng, k):
    lang = rng.choice(["py", "js", "sql", "go", "rs", None, "toml"])
    block = [rng.choice(LINES) for _ in range(rng.choice([0, 3, 8, 30]))]
    content = "\n".join(block * rng.choice([1, 1, 2, 3])) + rng.choice(["", "\n"])
    f = {"path": f"f{k}.{lang or 'txt'}", "lang": lang, "content": content, "dep": rng.random() < 0.2}
    r = rng.random()
    if r < 0.3:
        f["lineMetrics"] = engine.file_metrics([(f["path"], content, lang)])[0]
    elif r < 0.35:
        f["content"] = None                             # no text: no line of it counts
    return f


def generated(seed, n):
    rng = random.Random(seed)
    for k in range(n):
        files = [project_file(rng, j) for j in range(rng.choice([0, 1, 2, 5, 12]))]
        issues = [issue(rng, j) for j in range(rng.choice([0, 1, 3, 20, 200]))]
        yield files, issues


def fixture_sets():
    """Each fixture folder's source files with the findings core.scan_file gives them."""
    out = []
    for name in sorted(os.listdir(_support.FIXTURES)):
        root = os.path.join(_support.FIXTURES, name)
        if not os.path.isdir(root):
            continue
        files, issues = [], []
        for dirpath, dirs, names in os.walk(root):
            dirs.sort()
            for n in sorted(names):
                lang = core.EXTS.get(os.path.splitext(n)[1].lower())
                if lang is None:
                    continue
                path = os.path.join(dirpath, n)
                with open(path, encoding="utf-8", errors="replace", newline="") as f:
                    text = f.read()
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                files.append({"path": rel, "lang": lang, "content": text})
                issues += core.scan_file(rel, text, lang)
        if files:
            out.append((name, files, issues))
    return out


def without_place(res):
    return {k: v for k, v in res.items() if k not in ("project", "scannedAt")}


class ResultTests(unittest.TestCase):
    def check(self, files, issues, label):
        mine, ref = copy.deepcopy(issues), copy.deepcopy(issues)
        got = core.build_result(".", copy.deepcopy(files), mine)
        want = REFERENCE_build_result(copy.deepcopy(files), ref)
        self.assertEqual(without_place(got), want, label)
        self.assertEqual([type(got["metrics"]["dupPct"]), list(got)], [float, ["project", "scannedAt"] + list(want)], label)
        self.assertIs(got["issues"], mine, label)       # put in order where it is
        # graded again after its findings changed
        rng = random.Random(len(issues))
        for i in got["issues"]:
            if rng.random() < 0.3:
                i["sev"], i["type"] = rng.choice(list(SEV_ORDER)), rng.choice(list(TYPE_LABEL))
        want_again = REFERENCE_regrade(copy.deepcopy(got))
        self.assertEqual(core.regrade(got), want_again, label)

    def test_generated_sets(self):
        for k, (files, issues) in enumerate(generated(20261015, 300)):
            with self.subTest(set=k):
                self.check(files, issues, f"set {k}")

    def test_the_fixtures(self):
        sets = fixture_sets()
        self.assertGreater(len(sets), 10)
        for name, files, issues in sets:
            with self.subTest(fixtures=name):
                self.check(files, issues, name)

    def test_the_metrics_alone(self):
        for k, (files, _issues) in enumerate(generated(7, 200)):
            with self.subTest(set=k):
                self.assertEqual(core.compute_metrics(copy.deepcopy(files)), REFERENCE_compute_metrics(copy.deepcopy(files)))

    def test_ties_round_as_python_rounds(self):
        # six lines in two files, with 0 to 90 other lines: 100%, 63.2%, 26.1%, 22.2%, 12.5% and 11.8%, rounded as
        # Python's round rounds (its ties at the tenth: result.rs' round1_is_pythons_round)
        block = "\n".join(f"v{j} = {j}" for j in range(6))
        for extra in (0, 7, 34, 42, 84, 90):
            other = "\n".join(f"w{j} = {j}" for j in range(extra))
            files = [{"path": "a.py", "lang": "py", "content": block + "\n" + other},
                     {"path": "b.py", "lang": "py", "content": block}]
            with self.subTest(extra=extra):
                self.assertEqual(core.compute_metrics(files), REFERENCE_compute_metrics(files))

    def test_the_hardening_rules_are_the_packs(self):
        self.assertEqual(core.HARDENING_RULES, HARDENING_RULES)

    def test_bad_arguments_are_refused(self):
        for args in ({"issues": [["S-X", "VULN", "NOPE", "a", 1, None, None]], "files": []},
                     {"issues": [["S-X", "VULN", "MAJOR", "a", "1", None, None]], "files": []},
                     {"issues": [["S-X"]], "files": []}, {"issues": {}, "files": []},
                     {"issues": [], "files": [[False, "py", [1, 2, 3, "abc"]]]},
                     {"issues": [], "files": [[False, "py", 7]]}):
            with self.subTest(args=args):
                with self.assertRaises(_native.NativeError):
                    _native.call("result", args)


def engine_calls():
    out = []
    for files, issues in generated(99, 60):
        rows = core._finding_rows(issues)
        mf = core._metrics_files(files)
        out.append(("result", {"issues": rows, "files": mf}, ""))
        out.append(("project_metrics", {"files": mf}, ""))
        out.append(("regrade", {"issues": rows, "conditions": [["No blocker issues", True], ["x", False],
                                                                ["No critical vulnerabilities", False]]}, ""))
    return out


#: each call's answer, as node reads it (the digests of test_wasm_parity write a float as Python does: 100.0, where
#: JSON.stringify writes 100, and these answers hold dupPct)
NODE_ANSWERS = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const n = await import(pathToFileURL(process.argv[1]).href);
const calls = JSON.parse(readFileSync(0).toString("utf8"));
process.stdout.write(JSON.stringify(calls.map(([name, args, text]) => {
  try { return { ok: n.call(name, args, text) }; } catch (e) { return { error: `${e.name}: ${e.message}` }; }
})));
"""


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class WasmParityTests(unittest.TestCase):
    def test_the_calls(self):
        import json
        import subprocess
        from tests.architecture.test_wasm_parity import NATIVE_JS
        calls = engine_calls()
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", NODE_ANSWERS, NATIVE_JS], input=json.dumps(calls),
                           capture_output=True, encoding="utf-8", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        wasm = json.loads(p.stdout)
        self.assertEqual(len(wasm), len(calls))
        for k, (call, got) in enumerate(zip(calls, wasm)):
            with self.subTest(call=k, name=call[0]):
                self.assertEqual(got, {"ok": _native.call(*call)})


if __name__ == "__main__":
    unittest.main()
