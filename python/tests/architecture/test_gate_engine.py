"""The commit-time gate's decisions are the engine's (BR-7 step 4 (f), 0.1.9).

hook.py decided which findings the gate prints (shown), which of a result's conditions it gates on (GATE), the lines
it prints and its exit (report), what it does with each path the commit holds by its index entry (gather) and why a
file could not be read for the scan (its texts), and the npm package's hook.js the same, word for word. The engine
does it for both (rust/crates/lazaret-engine/src/gate.rs: the gate_report, gate_source and gate_why calls); each
package keeps git, the copy of what the commit holds, the project scan of it and the printing.

Held here to hook.py's code as it was (below: what this replaced, word for word but its docstrings, with the system's
separator and whether the output is a terminal as arguments) on generated results: findings of every rule family,
severity and type, in files whose names hold backslashes, control characters, line separators and text past the
Basic Multilingual Plane, with snippets or none, the line as --show-secrets read it or none, every set of conditions,
quiet or not, on a terminal or not, on Windows or not. All content is inert.
"""
import contextlib
import io
import os
import random
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import _native, core, hook

if not _native.available():
    raise unittest.SkipTest(f"the gate is the native engine's ({_native.load_error()})")

# ---------------------------------------------------------------- hook.py as it was (4 (e))

GATE = ("No blocker issues", "No critical vulnerabilities", "No supply-chain indicators",
        "No cross-file taint flows")
COLLISION_WHY = ("its name is another file's on this system (they differ only in case, in their Unicode form or by a "
                 "backslash), so it could not be copied for the scan")
UNPRINTED_WHY = "git could not print it from the index"


def ref_shown(issue):
    rule, sev = issue["rule"], issue["sev"]
    if rule.startswith("SC-"):
        return sev != "INFO"
    if rule.startswith("X-"):
        return True
    return issue["type"] == "VULN" and core.SEV_ORDER[sev] <= core.SEV_ORDER["MAJOR"]


def ref_git_form(path, sep):
    return path if sep == "/" else path.replace(sep, "/")


def ref_report(checked, issues, failed_conditions, quiet, raw_lines, sep):
    c, line = core.c, core.sanitize_term_line
    if not quiet or issues:
        print(f"lazaret hook: {len(checked)} file{'s' if len(checked) != 1 else ''} checked")
    cur = None
    for i in sorted(issues, key=lambda i: (ref_git_form(i["file"], sep), core.SEV_ORDER[i["sev"]], i["line"])):
        if ref_git_form(i["file"], sep) != cur:
            cur = ref_git_form(i["file"], sep)
            print(f"  {c('4', line(cur))}")
        sev = f"{i['sev']:<8}"
        prefix = f"    L{i['line']:<5} {sev} [{i['rule']}] "
        print(f"    L{i['line']:<5} {c(core.SEV_COLOR[i['sev']], sev)} [{i['rule']}] {line(i['msg'])}")
        ex = core.issue_excerpt(i, shown=raw_lines)
        if ex and not quiet:
            print(" " * len(prefix) + c("2", "» " + ex))
    if failed_conditions:
        print(f"  Commit gate: {c('41;97', ' FAILED ')}")
        for label in failed_conditions:
            print(f"    {c('31', '✗')} {line(label)}")
    elif not quiet:
        print(f"  Commit gate: {c('42;30', ' PASSED ')}")


def ref_run_tail(checked, res, quiet, raw_lines, sep):
    """run()'s last lines: what it printed and returned once it had the result."""
    issues = [i for i in res["issues"] if ref_shown(i)]
    failed_conditions = [cond["label"] for cond in res["conditions"]
                         if cond["label"] in GATE and not cond["ok"]]
    ref_report(checked, issues, failed_conditions, quiet, raw_lines, sep)
    return core.EXIT_GATE if failed_conditions else core.EXIT_OK


def ref_source(mode):
    """gather's choice for a path, by its index entry's mode (None: the index does not hold it)."""
    if mode in ("100644", "100755"):
        return "blob"
    if mode is not None:
        return "skip"
    return "disk"

# ---------------------------------------------------------------- generated results

RULES = ("SC-INSTALL-HOOK", "SC-TRUNCATED", "X-CMD", "X-SQL", "S-TOKEN", "S-SECRET", "SQL-CRED", "S-ENTROPY",
         "P-EVAL", "P-EXEC", "J-EVAL", "Q-LONG", "Q-UNREADABLE", "D-DUP")
SEVS = tuple(core.SEV_ORDER)
TYPES = ("VULN", "BUG", "SMELL", "HOTSPOT")
PIECES = ("a", "b", "src", "Z", "\xe9", "\\", "/", " ", "\t", "\n", "\x1b[31m", "\u2028", "\u2029", "\u202e", "\x7f",
          "\U0001f600", "\ud800", "x.py", "\xdf", "\u0130", "\u0301", "..", "~")


def _text(rng, n):
    return "".join(rng.choice(PIECES) for _ in range(rng.randrange(n)))


def _issue(rng, files):
    line = rng.choice((0, 1, 2, 3, 9, 10, 99, 12345, 123456, -1))
    issue = {"rule": rng.choice(RULES), "sev": rng.choice(SEVS), "type": rng.choice(TYPES),
             "file": rng.choice(files), "line": line, "msg": _text(rng, 6) or "m"}
    if rng.random() < 0.8:
        start = line - rng.randrange(0, 3)
        issue["snipStart"] = start
        issue["snippet"] = [_text(rng, 8) for _ in range(rng.randrange(0, 5))]
    return issue


def generated(seed):
    rng = random.Random(seed)
    files = [_text(rng, 5) or "f.py" for _ in range(rng.randrange(1, 5))]
    issues = [_issue(rng, files) for _ in range(rng.randrange(0, 9))]
    labels = list(GATE) + ["No new code duplication", "Maintainability rating A or B"]
    rng.shuffle(labels)
    conditions = [{"label": label, "ok": rng.random() < 0.6} for label in labels[:rng.randrange(0, len(labels) + 1)]]
    raw = None
    if rng.random() < 0.4:
        raw = {(i["file"], i["line"]): _text(rng, 8) for i in issues if rng.random() < 0.6}
    checked = [f"c{k}" for k in range(rng.choice((0, 1, 1, 2, 7)))]
    return checked, {"issues": issues, "conditions": conditions}, raw, rng.random() < 0.3, rng.random() < 0.3, \
        rng.choice(("/", "\\"))


def _printed(fn, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = fn(*args)
    return out.getvalue(), code


class GateReportTests(unittest.TestCase):
    def test_the_report_and_exit_are_hook_pys(self):
        for seed in range(1500):
            checked, res, raw, quiet, color, sep = generated(seed)
            with self.subTest(seed=seed), mock.patch.object(core, "_stdout_is_tty", return_value=color):
                want = _printed(ref_run_tail, checked, res, quiet, raw, sep)
                with mock.patch.object(hook.os, "sep", sep):
                    got = _printed(hook.report, checked, res, quiet, raw)
                self.assertEqual(got, want)

    def test_the_excerpt_width_and_redaction_are_cores(self):
        res = {"issues": [{"rule": "S-TOKEN", "sev": "BLOCKER", "type": "VULN", "file": "a.py", "line": 1,
                           "msg": "m", "snippet": ["t = " + "x" * 30], "snipStart": 1},
                          {"rule": "P-EVAL", "sev": "MAJOR", "type": "VULN", "file": "a.py", "line": 2,
                           "msg": "m", "snippet": ["eval(" + "y" * 30 + ")"], "snipStart": 2}],
               "conditions": [{"label": "No blocker issues", "ok": False}]}
        for width in (5, 20, 100):
            for redact in (True, False):
                with self.subTest(width=width, redact=redact), mock.patch.object(core, "EXCERPT_WIDTH", width), \
                        mock.patch.object(core, "REDACT_SECRETS", redact), \
                        mock.patch.object(core, "_stdout_is_tty", return_value=False):
                    self.assertEqual(_printed(hook.report, ["a.py"], res, False, None),
                                     _printed(ref_run_tail, ["a.py"], res, False, None, os.sep))

    def test_the_conditions_are_build_results(self):
        # the labels the gate keeps are ones build_result gives (a renamed condition would pass every commit)
        with tempfile.TemporaryDirectory() as tmp:
            labels = {c["label"] for c in core.build_result(tmp, [], [])["conditions"]}
        self.assertLessEqual(set(GATE), labels)
        for label in labels:
            res = {"issues": [], "conditions": [{"label": label, "ok": False}]}
            with mock.patch.object(core, "_stdout_is_tty", return_value=False):
                self.assertEqual(_printed(hook.report, ["a"], res, True, None)[1],
                                 core.EXIT_GATE if label in GATE else core.EXIT_OK, label)


class GateSourceTests(unittest.TestCase):
    def test_what_the_gate_does_with_each_path(self):
        modes = ["100644", "100755", "120000", "160000", "100664", "040000", "", None]
        self.assertEqual(_native.call("gate_source", {"modes": modes}), [ref_source(m) for m in modes])

    def test_the_reasons_are_hook_pys(self):
        self.assertEqual(hook.why("collision"), COLLISION_WHY)
        self.assertEqual(hook.why("unprinted"), UNPRINTED_WHY)
        self.assertEqual(hook.why("stopped"), "it could not be copied for the scan (git stopped mid-file)")
        self.assertEqual(hook.why("not_regular"), "it is not a regular file")
        self.assertEqual(hook.why("git_missing"), "git could not be run (it is not on PATH)")
        for detail in ("Permission denied", "OSError", "\xe9\\\u2028", ""):
            self.assertEqual(hook.why("unreadable", detail), f"it could not be read ({detail})")
            self.assertEqual(hook.why("git_failed", detail), f"git could not be run ({detail})")
            self.assertEqual(hook.why("not_copied", detail), f"it could not be copied for the scan ({detail})")
        self.assertEqual(hook._not_copied(OSError(13, "Permission denied")),
                         "it could not be copied for the scan (Permission denied)")
        self.assertEqual(hook._not_copied(ValueError("not a path inside the project: ../x")),
                         "it could not be copied for the scan (not a path inside the project: ../x)")


if __name__ == "__main__":
    unittest.main()
