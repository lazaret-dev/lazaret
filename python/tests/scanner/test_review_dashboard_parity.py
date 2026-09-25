"""Dashboard <-> CLI parity: the same input gives the same (rule, line) findings.

The dashboard (lazaret/web/lazaret.html) carries its own copy of the scanning
engine, and it drifted from the CLI unnoticed (per-file budget, no size
limit). This runs the page's scanFile() in node:vm (_dashboard_vm.py) and the
CLI engine's scan_file() on the same files and compares the multisets of
(rule, line). Project-level CLI checks the page doesn't do (manifests,
binaries, directory walking) are out of scope.

INTEGRATOR: the review-fix branches change the CLI engine (FIX-SPEC items 1
comments, 2 suppression, 4/15 encodings, 5 unicode, 7 caps, 12 taint idioms,
14 time backstop) without touching the page. PARITY_FIXTURES are inputs none
of those changes affect, so this test stays green while the engines are
fixed separately. PENDING_FIXTURES and PENDING_CASES exercise the changed
behavior; they run only with LAZARET_DASHBOARD_PARITY_ALL=1. After porting
the engine changes into lazaret.html, move them into the checked lists (and
delete the environment switch) so the two engines can't drift again.
"""

import collections
import os
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

LANGS = {".py": "py", ".js": "js", ".sql": "sql"}

# Inputs whose findings no pending engine change affects: no suppression
# markers, no block comments, no non-ASCII text, no encoding cookies, no
# annotated assignments or destructuring, fewer than 200 findings per rule.
PARITY_FIXTURES = [
    "testproj/app.py",
    "testproj/secrets.py",
    "testproj/utils/clean.py",
    "testproj/utils/web.js",
    "detection_gaps/vuln_sql.py",
    "detection_gaps/sql/vuln.py",
    "detection_gaps/migrations/0001.py",
    "sqlproj/schema.sql",
    "sqlproj/clean.sql",
    "sqlclean/clean.sql",
    "flowproj/app/views.py",
    "flowproj/app/db.py",
    "cleanflow/svc/api.py",
    "cleanflow/svc/store.py",
    "cleanflow/svc/util.js",
    "cleanproj/clean.py",
    "cfgproj/app.py",
    "cfgproj2/app.py",
]
# The page's own "Load sample" inputs.
PARITY_SAMPLES = [("SAMPLE_PY", "sample.py", "py"), ("SAMPLE_JS", "sample.js", "js"),
                  ("SAMPLE_SQL", "sample.sql", "sql")]

# Agree today, but exercise behavior the fix branches change in the CLI only.
PENDING_FIXTURES = [
    "testproj/tainted.py",               # suppression markers (item 2)
    "supdir/sup.sql",                    # SQL -- suppression (item 2)
    "test.js", "test2.js", "testsan.js", "testsql.js",   # block comments (item 1), non-ASCII (item 5)
    "detection_gaps/encoding_readme.py", # encoding (items 4, 15)
    "detection_gaps/safe_sql.py", "detection_gaps/safe/safe.py",
    "detection_gaps/dist-file.py", "detection_gaps/dist/bundle.py",
    "detection_gaps/skips/dist-file.py", "detection_gaps/skips/dist/bundle.py",
    "detection_gaps/skips/migrations/0001.py", "detection_gaps/skips/.hidden/x.py",
]
# Synthetic inputs for behavior the dashboard already implements and the CLI
# gets on the core-scan / core-cli branches.
PENDING_CASES = [
    ("capped.js", "js", "".join(f"var a{n} = 1;\n" for n in range(250))),         # Q-CAPPED (item 7)
    ("blockcomment.js", "js", "/*\n eval(x)\n*/\n/**/eval(y)\n"),                  # item 1
    ("suppressed.py", "py", "import os\nos.system(cmd)  # nosec - reviewed\n"),    # item 2
    ("bidi.js", "js", 'const s = "‮";\n'),                                     # item 5 (S-BIDI)
]
RUN_PENDING = bool(os.environ.get("LAZARET_DASHBOARD_PARITY_ALL"))


def read_fixture(rel):
    with open(os.path.join(_support.FIXTURES, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


def findings(issues):
    return collections.Counter((i["rule"], i["line"]) for i in issues)


@dash.requires_node
class DashboardParityTests(unittest.TestCase):
    def compare(self, cases):
        """cases: [(name, lang, content)]; one page instance for all of them."""
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": lang, "content": c}}
                         for n, lang, c in cases])
        for (name, lang, content), page_issues in zip(cases, page):
            with self.subTest(file=name):
                cli, dashboard = findings(core.scan_file(name, content, lang)), findings(page_issues)
                self.assertEqual(
                    (sorted((cli - dashboard).elements()), sorted((dashboard - cli).elements())), ([], []),
                    f"{name}: (only in the CLI, only in the dashboard)")

    def test_fixtures(self):
        self.compare([(rel, LANGS[os.path.splitext(rel)[1]], read_fixture(rel)) for rel in PARITY_FIXTURES])

    def test_dashboard_samples(self):
        sources = dash.run([{"op": "eval", "expr": const} for const, _, _ in PARITY_SAMPLES])
        self.compare([(name, lang, src) for (_, name, lang), src in zip(PARITY_SAMPLES, sources)])

    def test_the_comparison_can_fail(self):
        """Control: a page that drops a rule is caught."""
        with open(dash.HTML, encoding="utf-8", newline="") as f:
            html = f.read()
        broken = html.replace('{id:"S-PICKLE"', '{id:"S-PICKLE-OFF"', 1)
        self.assertNotEqual(broken, html)
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "lazaret.html")
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(broken)
            (page,) = dash.run([{"op": "scanFile", "file": {"name": "sample.py", "lang": "py",
                                                            "content": "import pickle\npickle.loads(d)\n"}}],
                               html=path)
        self.assertNotEqual(findings(page), findings(core.scan_file("sample.py", "import pickle\npickle.loads(d)\n", "py")))

    @unittest.skipUnless(RUN_PENDING, "set LAZARET_DASHBOARD_PARITY_ALL=1 once the page is aligned (see docstring)")
    def test_pending_fixtures_and_cases(self):
        self.compare([(rel, LANGS[os.path.splitext(rel)[1]], read_fixture(rel)) for rel in PENDING_FIXTURES]
                     + PENDING_CASES)

    def test_every_fixture_is_classified(self):
        on_disk = []
        for root, dirs, files in os.walk(_support.FIXTURES):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if os.path.splitext(name)[1] in LANGS:
                    on_disk.append(os.path.relpath(os.path.join(root, name), _support.FIXTURES).replace(os.sep, "/"))
        self.assertEqual(sorted(set(on_disk) - set(PARITY_FIXTURES) - set(PENDING_FIXTURES)), [],
                         "new fixture: add it to PARITY_FIXTURES or PENDING_FIXTURES")


if __name__ == "__main__":
    unittest.main()
