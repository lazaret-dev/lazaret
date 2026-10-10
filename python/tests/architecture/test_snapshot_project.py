"""Project mode's scan of a file, held to its recorded outputs (_snapshots.py; Q-1, 0.1.9): the engine's scan_file
with dep=False, which runs the rules part (scan_rules), then the SQL statements without WHERE, the intra-file taint,
the SQL built from strings into execute(), the function metrics, the suppression markers and the cap. On the project
corpus (project_corpus.py: every pass's shapes and their combinations), the scan_file corpus (its Go and Rust part
too) and the repository's fixtures; with a taint configuration as the CLI applies one (configured sources, sinks and
sanitizers); and the function list a file's metrics come from (functions).

Recorded from core's answers when the passes moved into the engine: they were the same, file by file, on these sets,
on Python's standard library, on this repository's own sources (its Rust too) and on every file the scanner's tests
scan. A change in them is a change in what a project scan finds."""

import os
import random
import unittest

from lazaret.scanner import _native, core
from tests.architecture import _snapshots, project_corpus, scanfile_corpus
from tests.architecture.test_snapshot_scanfile import fixtures

# what only the passes after the rules find, each of which the corpus must reach
PASSES = ("T-CMD", "T-CODE", "T-PATH", "T-REDIR", "T-SQL", "T-SSRF", "T-SSTI", "T-XSS", "S-SQL-PY",
          "SQL-DELETE-NOWHERE", "SQL-UPDATE-NOWHERE", "Q-FN-LONG", "Q-FN-CX", "Q-CAPPED")
# a taint configuration's part of the model, as engine.py hands it over (taintspec validated it)
CONFIGURED = {
    "py": {"sources": [r"get_param\(", r"os\.environ\.get\("],
           "sinks": [[r"run_query\(", "SQL injection"], [r"\bshell\(", "command injection"],
                     [r"fetch_url\(", "server-side request forgery"], [r"render_html\(", "cross-site scripting"]],
           "full": ["clean_it", "util.normalize"],
           "partial": [["escape_sql", ["SQL injection"]], ["safe_url", ["open redirect", "server-side request forgery"]],
                       ["quote_cmd", ["command injection"]]]},
    "js": {"sources": [r"readInput\(", r"ctx\.request\.body"],
           "sinks": [[r"runSql\(", "SQL injection"], [r"\.execRaw\(", "command injection"]],
           "full": ["toSafe"], "partial": [["escapeIt", ["SQL injection", "cross-site scripting"]]]},
}
CONFIGURED_LINES = {
    "py": ["x = get_param('a')", "run_query(x)", "shell(x)", "fetch_url(x)", "render_html(x)", "y = clean_it(x)",
           "run_query(escape_sql(x))", "shell(quote_cmd(x))", "fetch_url(safe_url(x))", "z = util.normalize(x)",
           "run_query(z)", "e = os.environ.get('E')", "shell(e)", "redirect(safe_url(x))", "w = escape_sql(x)",
           "run_query(w)", "os.system(w)"],
    "js": ["const a = readInput();", "runSql(a);", "child.execRaw(a);", "const b = toSafe(a);", "runSql(b);",
           "res.send(escapeIt(a));", "runSql(escapeIt(a));", "const c = ctx.request.body.c;", "exec(c);", "runSql(c);"],
}


def lang_of(path):
    return core.EXTS.get(os.path.splitext(path)[1].lower())


def call_args(path, taint=None):
    a = {"lang": lang_of(path), "dep": False, "jsx": core.jsx_reading(path), "redact": True, "neumaier": True}
    if taint:
        a["taint"] = taint
    return a


def files():
    return [(p, t) for p, t in project_corpus.corpus() + scanfile_corpus.corpus()[::4]
            + scanfile_corpus.go_rs_corpus()[::4] + fixtures() if lang_of(p)]


def configured_files():
    rnd = random.Random(5)
    out = []
    for path, text in project_corpus.corpus(seed=31):
        lang = lang_of(path)
        if lang in CONFIGURED_LINES:
            text += "\n".join(rnd.choice(CONFIGURED_LINES[lang]) for _ in range(rnd.randint(2, 10))) + "\n"
        out.append((path, text))
    return out


def snapshot_sets():
    return {"scan_project": lambda: [("scan_file", call_args(p), t) for p, t in files()],
            "scan_project_configured": lambda: [("scan_file", call_args(p, CONFIGURED.get(lang_of(p))), t)
                                                for p, t in configured_files()],
            "functions": lambda: [("functions", {"lang": lang_of(p), "jsx": core.jsx_reading(p)}, t)
                                  for p, t in project_corpus.corpus() if lang_of(p) in ("py", "js")]}


def rules(answers):
    return {a[0] for r in answers if "ok" in r for a in r["ok"]}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ProjectScanSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["scan_project"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "scan_project", answers)
        found = rules(answers)
        for rule in PASSES:
            with self.subTest(rule=rule):
                self.assertIn(rule, found)

    def test_with_a_taint_configuration(self):
        answers = _snapshots.run(snapshot_sets()["scan_project_configured"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "scan_project_configured", answers)
        bare = _snapshots.run([(c, {k: v for k, v in a.items() if k != "taint"}, t)
                               for c, a, t in snapshot_sets()["scan_project_configured"]()[:300]])
        def count(ans, rule):
            return sum(1 for r in ans if "ok" in r for a in r["ok"] if a[0] == rule)
        for rule in ("T-SQL", "T-CMD"):
            with self.subTest(rule=rule):           # (the configuration's sources and sinks are read)
                self.assertGreater(count(answers[:300], rule), count(bare, rule))

    def test_the_function_lists_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["functions"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "functions", answers)
        self.assertGreater(sum(len(r["ok"]) for r in answers), 1000)


if __name__ == "__main__":
    unittest.main()
