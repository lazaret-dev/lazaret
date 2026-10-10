"""`lazaret [scan] github:owner/repo[@ref]` (0.1.9, S-1): `lazaret.registry.sourcescan`
and the dispatch in `lazaret._cli`.

What the command line means (which argument is the source, which is the value of
an option), where the reports go, what a checkout that was not read whole does to
the exit status, and that the directory the commit was read into is gone
afterwards. Archives are built in memory and the network is the same fake as
`test_sources`: nothing is fetched. Most tests put a recorder in place of
`core.main`, so they check the arguments the scan is given; the end-to-end ones
run the real scan on a two-file repository."""

import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from lazaret import _cli
from lazaret.registry import sources, sourcescan
from lazaret.scanner import core, engine
from tests.registry.test_sources import SHA, TOKEN, Net, gh_answers

SPEC = "github:o/r@v1"
NAME = "lazaret-github-o-r-0123456-report"


class Dir(unittest.TestCase):
    """A working directory of its own, and the way back."""

    def setUp(self):
        self.cwd = os.getcwd()
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="lazaret-ss-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.cwd)       # before the folder goes: Windows cannot remove the current one


class Recorder:
    """In place of `core.main`: keeps the arguments, the source block and what
    was on disk at the time."""

    def __init__(self, result=0, exc=None):
        self.result, self.exc, self.calls, self.sources = result, exc, [], []

    def __call__(self, argv=None, source=None):
        root = next((a for a in argv if os.path.isdir(a) and os.path.basename(a).startswith(("github-", "gitlab-"))), None)
        listing = sorted(os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/")
                         for d, _, fs in os.walk(root) for f in fs) if root else None
        self.calls.append((list(argv), root, listing))
        self.sources.append(source)
        if self.exc:
            raise self.exc
        return self.result

    @property
    def argv(self):
        return self.calls[-1][0]


def run(argv, answers=None, env=None, core_main=None, **kw):
    """sourcescan.main with the fake network -> (exit code, stdout, stderr, net)."""
    net = Net(gh_answers() if answers is None else answers)
    out, err = io.StringIO(), io.StringIO()
    patch = mock.patch.object(core, "main", core_main) if core_main is not None else mock.patch.object(core, "configure_stdio")
    with patch, redirect_stdout(out), redirect_stderr(err):
        code = sourcescan.main(argv, env={} if env is None else env, http=net, **kw)
    return code, out.getvalue(), err.getvalue(), net


class Find(unittest.TestCase):
    def test_a_source_and_where_it_stands(self):
        p = sourcescan.find([SPEC])
        self.assertEqual((p.spec, p.argv, p.slot, p.accept), (sources.Source("github", "o/r", "v1"), [None], 0, False))
        p = sourcescan.find(["--ci", "scan", "gitlab:g/sub/p", "--deps"])
        self.assertEqual((p.spec.kind, p.spec.path, p.argv, p.slot), ("gitlab", "g/sub/p", ["--ci", None, "--deps"], 1))
        self.assertTrue(p.opts["--ci"] and p.opts["--deps"])

    def test_scan_is_a_word_only_before_a_source(self):
        self.assertIsNone(sourcescan.find(["scan"]))
        self.assertIsNone(sourcescan.find(["scan", "somedir"]))
        self.assertEqual(sourcescan.find(["scan", SPEC]).argv, [None])
        self.assertEqual(sourcescan.find([SPEC, "--ci"]).argv, [None, "--ci"])
        with self.assertRaises(sourcescan.UsageError):
            sourcescan.find([SPEC, "scan"])

    def test_options_values_are_not_the_source(self):
        for argv in (["--exclude", SPEC, "dir"], ["--baseline", "github:o/r", "dir"], ["--json=github:o/r", "dir"],
                     ["--out", "gitlab:g/p", "dir"], ["--no-html", "--sarif", "gitlab:g/p", "d"]):
            with self.subTest(argv):
                self.assertIsNone(sourcescan.find(argv))

    def test_options_are_read_as_argparse_reads_them(self):
        p = sourcescan.find(["--out=elsewhere", SPEC, "--json", "x.json", "--c", "--no-h"])
        self.assertEqual(p.opts, {"--out-dir": "elsewhere", "--json": "x.json", "--ci": True, "--no-html": True})
        self.assertEqual(sourcescan.find([SPEC, "--out-dir", "a", "--out-dir", "b"]).opts["--out-dir"], "b")
        self.assertEqual(sourcescan.find(["-q", SPEC]).opts, {"--quiet": True})
        # unknown and ambiguous options are core's to refuse
        self.assertEqual(sourcescan.find([SPEC, "--no", "--nonsense"]).opts, {})

    def test_a_value_may_hold_an_equals_sign_and_may_be_missing(self):
        self.assertEqual(sourcescan.find([SPEC, "--baseline=a=b.json"]).opts, {"--baseline": "a=b.json"})
        self.assertEqual(sourcescan.find([SPEC, "--json"]).opts, {"--json": None})        # core says what is missing
        self.assertEqual(sourcescan.find([SPEC, "--json="]).opts, {"--json": ""})

    def test_help_and_version_are_never_a_fetch(self):
        for argv in (["-h", SPEC], [SPEC, "--help"], ["--vers", SPEC], [SPEC, "--he"]):
            with self.subTest(argv):
                self.assertIsNone(sourcescan.find(argv))

    def test_what_is_refused(self):
        for argv in ([SPEC, "github:o/other"], [SPEC, "dir"], ["dir", SPEC], ["scan", SPEC, "dir"], ["github:o", ],
                     ["github:o/r@a..b"],
                     ["gitlab:g"], ["--ci", "github:", "--deps"]):
            with self.subTest(argv):
                with self.assertRaises(sourcescan.UsageError):
                    sourcescan.find(argv)

    def test_a_double_dash_makes_the_rest_positional(self):
        self.assertEqual(sourcescan.find(["--ci", "--", SPEC]).argv, ["--ci", "--", None])
        with self.assertRaises(sourcescan.UsageError):
            sourcescan.find(["--", SPEC, "--ci"])           # `--ci` is then a second thing to scan

    def test_accept_incomplete_is_ours_and_not_core_s(self):
        p = sourcescan.find([SPEC, "--accept-incomplete", "--ci"])
        self.assertEqual((p.accept, p.argv), (True, [None, "--ci"]))

    @unittest.skipIf(os.name == "nt", "a colon is not allowed in a Windows file name")
    def test_a_folder_of_that_name_is_a_folder(self):
        with tempfile.TemporaryDirectory() as d:
            here = os.getcwd()
            os.chdir(d)
            try:
                os.makedirs("github:o/r")
                self.assertIsNone(sourcescan.find(["github:o/r"]))
                self.assertFalse(_cli.is_source(["github:o/r"]))
                self.assertTrue(_cli.is_source(["GITHUB:o/other"]))
            finally:
                os.chdir(here)


class OptionTable(unittest.TestCase):
    def test_it_is_core_s_own(self):
        """The options listed in `sourcescan` are the ones `core.main`'s parser has, with and
        without a value: a new option there that is not here would be mistaken for the thing
        to scan, or its value would."""
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            core.main(["--help"])
        text = out.getvalue()
        found = re.findall(r"^  (?:-\w, )?(--[a-z][a-z-]*)(?: ([A-Z_]+))?", text, re.M)
        with_value = {o for o, meta in found if meta}
        without = {o for o, meta in found if not meta}
        self.assertEqual(with_value, set(sourcescan.VALUE_OPTIONS))
        self.assertEqual(without, set(sourcescan.FLAG_OPTIONS))
        self.assertEqual(set(sourcescan.SHORT_OPTIONS.values()), {"--quiet", "--help"})


class Destination(unittest.TestCase):
    def plan(self, *opts):
        return sourcescan.find([SPEC, *opts])

    def test_reports_are_named_for_the_commit_and_go_to_the_current_directory(self):
        front = sourcescan.report_defaults(self.plan(), SHA, "/work")
        self.assertEqual(front, ["--out-dir", "/work", "--json", NAME + ".json", "--html", NAME + ".html"])

    def test_the_users_choices_come_after_ours_and_win(self):
        p = self.plan("--json", "mine.json", "--out-dir", "elsewhere")
        self.assertEqual(sourcescan.report_defaults(p, SHA, "/work"), ["--html", NAME + ".html"])
        self.assertEqual(sourcescan.report_defaults(self.plan("--no-json", "--no-html"), SHA, "/work"), [])
        self.assertEqual(sourcescan.report_defaults(self.plan("--no-html"), SHA, "/work"),
                         ["--out-dir", "/work", "--json", NAME + ".json"])

    def test_a_gitlab_subgroup_path_is_one_name(self):
        p = sourcescan.find(["gitlab:group/sub/pro.ject@main"])
        self.assertIn("lazaret-gitlab-group-sub-pro.ject-0123456-report.json", sourcescan.report_defaults(p, SHA, "/w"))

    def test_the_out_dir_matters_only_when_a_report_lands_there(self):
        absolute = os.path.abspath("x.json")
        self.assertTrue(sourcescan.needs_out_dir(self.plan().opts))
        self.assertFalse(sourcescan.needs_out_dir(self.plan("--json", absolute, "--html", absolute + ".html").opts))
        self.assertFalse(sourcescan.needs_out_dir(self.plan("--json", absolute, "--no-html").opts))
        self.assertTrue(sourcescan.needs_out_dir(self.plan("--json", absolute, "--no-html", "--sarif", "s.sarif").opts))
        self.assertFalse(sourcescan.needs_out_dir(self.plan("--no-json", "--no-html").opts))
        self.assertEqual(sourcescan.report_defaults(self.plan("--json", absolute, "--html", absolute + ".h"), SHA, "/w"), [])


class Arguments(Dir):
    def test_the_scan_gets_the_checkout_in_the_place_of_the_source(self):
        rec = Recorder()
        code, out, err, net = run(["--ci", "scan", SPEC, "--deps", "--exclude", "vendor"], core_main=rec)
        self.assertEqual(code, 0)
        argv, root, listing = rec.calls[0]
        self.assertEqual(argv[:6], ["--out-dir", self.tmp, "--json", NAME + ".json", "--html", NAME + ".html"])
        self.assertEqual(argv[6:], ["--ci", root, "--deps", "--exclude", "vendor"])
        self.assertEqual(os.path.basename(root), "github-o-r")
        self.assertEqual(listing, ["README.md", "src/main.py"])          # the commit, read
        self.assertFalse(os.path.exists(root))                          # and gone
        self.assertFalse(os.path.exists(os.path.dirname(root)))

    def test_verify_secrets_goes_to_the_scan_of_the_checkout(self):
        # (decision 4: any target is verified when asked, a repository that is not the user's too)
        self.assertEqual(sourcescan.find([SPEC, "--verify-secrets"]).opts, {"--verify-secrets": True})
        rec = Recorder()
        code, out, err, net = run([SPEC, "--verify-secrets"], core_main=rec)
        self.assertEqual(code, 0)
        argv, root, listing = rec.calls[0]
        self.assertEqual(argv[6:], [root, "--verify-secrets"])

    def test_the_commit_that_was_read_is_named(self):
        code, out, err, net = run([SPEC], core_main=Recorder())
        self.assertIn(f"Source: github:o/r@{SHA} (the ref v1)", out)
        self.assertIn("2 files", out)
        self.assertIn("Fetching github:o/r@v1", err)
        code, out, err, net = run([f"github:o/r@{SHA}"], answers=gh_answers(), core_main=Recorder())
        self.assertIn(f"Source: github:o/r@{SHA}\n", out)                # a commit given is not "the ref"

    def test_nothing_is_fetched_when_the_report_could_not_be_saved(self):
        rec = Recorder()
        code, out, err, net = run([SPEC, "--out-dir", os.path.join(self.tmp, "missing")], core_main=rec)
        self.assertEqual(code, 3)
        self.assertIn("does not exist", err)
        self.assertEqual((net.seen, rec.calls), ([], []))

    def test_an_out_dir_that_no_report_uses_is_not_asked_about(self):
        rec = Recorder()
        absolute = os.path.join(self.tmp, "r.json")
        code, out, err, net = run([SPEC, "--json", absolute, "--no-html", "--out-dir", "missing"], core_main=rec)
        self.assertEqual((code, len(rec.calls)), (0, 1))                  # (core still checks a --out-dir it is given)

    def test_core_s_exit_status_is_passed_on(self):
        for exc, expected in ((SystemExit(1), 1), (SystemExit(4), 4), (SystemExit(None), 0), (SystemExit("x"), 1)):
            with self.subTest(exc.code):
                code, out, err, net = run([SPEC], core_main=Recorder(exc=exc))
                self.assertEqual(code, expected)

    def test_the_directory_goes_when_the_scan_fails(self):
        rec = Recorder(exc=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):
            run([SPEC], core_main=rec)
        self.assertFalse(os.path.exists(rec.calls[0][1]))

    def test_a_folder_to_scan_goes_to_core_untouched(self):
        rec = Recorder()
        code, out, err, net = run(["somedir", "--ci", "--accept-incomplete"], core_main=rec)
        self.assertEqual((code, rec.argv, net.seen), (0, ["somedir", "--ci"], []))

    def test_a_usage_error_is_exit_2_and_fetches_nothing(self):
        for argv in ([SPEC, "dir"], ["github:o/r/extra"], ["github:o/r@-rf"]):
            with self.subTest(argv):
                code, out, err, net = run(argv, core_main=Recorder())
                self.assertEqual((code, net.seen), (2, []))
                self.assertTrue(err.startswith("error: "))

    def test_a_source_that_cannot_be_fetched_is_exit_2_with_the_reason(self):
        rec = Recorder()
        code, out, err, net = run([SPEC], answers={}, core_main=rec)
        self.assertEqual((code, rec.calls), (2, []))
        self.assertIn("error:", err)
        self.assertEqual(os.listdir(self.tmp), [])                        # no report, no stray directory

    def test_the_token_is_used_and_not_shown(self):
        code, out, err, net = run([SPEC], env={"GITHUB_TOKEN": TOKEN}, core_main=Recorder())
        self.assertEqual(code, 0)
        self.assertTrue(any(h.get("Authorization") for _, h in net.seen))
        self.assertNotIn(TOKEN, out + err)

    def test_the_environment_and_the_command_line_are_the_defaults(self):
        net = Net(gh_answers())
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": TOKEN}), mock.patch.object(sys, "argv", ["lazaret", SPEC]), \
                mock.patch.object(core, "main", Recorder()), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(sourcescan.main(http=net), 0)
        self.assertTrue(any(h.get("Authorization") for _, h in net.seen))

    def test_a_long_path_gives_a_short_name(self):
        self.assertEqual(len(sourcescan._slug("a/" * 100)), 80)
        self.assertEqual(sourcescan._slug("../.."), "source")
        self.assertEqual(sourcescan._slug("g/sub/p.x"), "g-sub-p.x")

    def test_a_bug_while_fetching_is_an_internal_error_not_a_scan_result(self):
        err = io.StringIO()
        with mock.patch.object(sources, "checkout", side_effect=RuntimeError("boom")), \
                mock.patch.object(core, "main", Recorder()), redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            sourcescan.main([SPEC], env={})
        self.assertEqual(cm.exception.code, core.EXIT_INTERNAL)
        self.assertIn("error: internal: RuntimeError", err.getvalue())


class Incomplete(Dir):
    """A commit with a path its archive leaves out (`export-ignore`): not read whole."""

    ANSWERS = staticmethod(lambda: gh_answers(files={"a.py": b"x = 1\n"}, tree=["a.py", "tests/b.py", "tests/c.py"]))

    def test_with_ci_the_exit_status_is_1_even_when_the_gate_passes(self):
        code, out, err, net = run([SPEC, "--ci"], answers=self.ANSWERS(), core_main=Recorder(0))
        self.assertEqual(code, 1)
        self.assertIn("was not read whole", err)
        self.assertIn("export-ignore", err)
        self.assertIn("tests/b.py", err)
        self.assertIn("--accept-incomplete", err)

    def test_accepting_it_leaves_the_exit_status_to_the_gate(self):
        code, out, err, net = run([SPEC, "--ci", "--accept-incomplete"], answers=self.ANSWERS(), core_main=Recorder(0))
        self.assertEqual(code, 0)
        self.assertIn("was not read whole", err)                         # still said
        code, *_ = run([SPEC, "--ci", "--accept-incomplete"], answers=self.ANSWERS(), core_main=Recorder(exc=SystemExit(1)))
        self.assertEqual(code, 1)                                         # and the gate still fails it

    def test_without_ci_it_is_said_and_the_exit_status_is_the_scan_s(self):
        code, out, err, net = run([SPEC], answers=self.ANSWERS(), core_main=Recorder(0))
        self.assertEqual(code, 0)
        self.assertIn("was not read whole", err)
        self.assertIn("without --ci the exit status is unchanged", err)

    def test_a_gate_that_failed_stays_what_it_was(self):
        code, *_ = run([SPEC, "--ci"], answers=self.ANSWERS(), core_main=Recorder(exc=SystemExit(1)))
        self.assertEqual(code, 1)
        code, *_ = run([SPEC, "--ci"], answers=self.ANSWERS(), core_main=Recorder(exc=SystemExit(4)))
        self.assertEqual(code, 4)                                         # another failure is not turned into a gate's

    def test_a_complete_commit_says_nothing_of_the_kind(self):
        code, out, err, net = run([SPEC, "--ci"], core_main=Recorder(0))
        self.assertEqual(code, 0)
        self.assertNotIn("not read whole", err)

    def test_the_paths_are_cut_off_and_cleaned(self):
        tree = ["a.py"] + [f"gone/{i}.py" for i in range(20)] + ["x\x1b[2Jy.py"]
        code, out, err, net = run([SPEC, "--ci"], answers=gh_answers(files={"a.py": b"x = 1\n"}, tree=tree),
                                  core_main=Recorder(0))
        self.assertEqual(code, 1)
        self.assertNotIn("\x1b", err)
        self.assertIn("and 16 more", err)                                 # the checkout counts them, this shows five

    def test_a_file_that_could_not_be_written_counts_a_large_one_does_not(self):
        ck = mock.Mock(incomplete=[], skipped=[("big.bin", "larger than 50 MB, not read"),
                                               ("x/y", "could not be written (NotADirectoryError)")])
        self.assertEqual(sourcescan.not_covered(ck), [("skipped", "x/y: could not be written (NotADirectoryError)")])
        ck = mock.Mock(incomplete=[("tree", "not listed whole")], skipped=[])
        self.assertEqual(sourcescan.not_covered(ck), [("tree", "not listed whole")])


class SourceBlock(Dir):
    """N-5: the scan is told what it is a scan of (`source_block`), and its
    result says so (`core.set_source`)."""

    def test_the_scan_is_given_the_source(self):
        rec = Recorder()
        code, out, err, net = run([SPEC], core_main=rec)
        self.assertEqual(rec.sources, [{
            "spec": f"github:o/r@{SHA}", "kind": "github", "repository": "o/r", "ref": "v1", "commit": SHA,
            "uri": "https://github.com/o/r", "files": 2, "bytes": 14, "complete": True, "incomplete": [],
            "skipped": [], "notes": [], "anomalies": []}])
        rec = Recorder()
        run(["github:o/r"], core_main=rec)
        self.assertEqual((rec.sources[0]["ref"], rec.sources[0]["spec"]), (None, f"github:o/r@{SHA}"))

    def test_what_was_not_read_is_in_it(self):
        rec = Recorder()
        run([SPEC], answers=Incomplete.ANSWERS(), core_main=rec)
        (block,) = rec.sources
        self.assertFalse(block["complete"])
        ((reason, detail),) = block["incomplete"]
        self.assertEqual(reason, "export-ignore")
        self.assertTrue(detail.startswith("2 path(s) are in the commit but not in its archive"), detail)
        self.assertEqual(block["files"], 1)

    def test_a_gitlab_repository_is_on_its_instance_and_no_token_is_kept(self):
        from tests.registry.test_sources_missing import gitlab
        env = {"LAZARET_GITLAB_URL": "https://git.example.org", "GITLAB_TOKEN": TOKEN}
        rec = Recorder()
        code, out, err, net = run(["gitlab:grp/proj@main"], answers=gitlab(), env=env, core_main=rec)
        self.assertEqual(code, 0, err)
        (block,) = rec.sources
        self.assertEqual((block["uri"], block["repository"], block["kind"], block["complete"]),
                         ("https://git.example.org/grp/proj", "grp/proj", "gitlab", True))
        self.assertNotIn(TOKEN, json.dumps(block))
        self.assertNotIn(self.tmp, json.dumps(block))                   # nor the temporary directory

    def test_the_result_names_the_source_and_keeps_an_earlier_reason(self):
        res = {"project": "/tmp/lazaret-src-x/github-o-r", "issues": []}
        core.set_source(res, {"spec": f"github:o/r@{SHA}", "complete": True, "incomplete": []})
        self.assertEqual(res["project"], f"github:o/r@{SHA}")
        self.assertEqual(res["source"]["spec"], f"github:o/r@{SHA}")
        self.assertNotIn("incomplete", res)
        res = {"project": "x", "incomplete": True, "incompleteReason": "stopped early"}
        core.set_source(res, {"spec": "github:o/r@abc", "complete": False,
                              "incomplete": [["tree", "t"], ["export-ignore", "e"], ["skipped", "s"], ["more", "m"]]})
        self.assertTrue(res["incomplete"])
        self.assertEqual(res["incompleteReason"], "stopped early; the checkout of github:o/r@abc was not read whole "
                                                  "(tree: t; export-ignore: e; skipped: s)")


def fake_checkout(**fields):
    """In place of `sources.checkout`: a directory and a Checkout carrying what a test says."""
    def make(spec, dest=None, **kw):
        os.makedirs(dest, exist_ok=True)
        ck = sources.Checkout(spec, SHA, dest, None)
        for name, value in fields.items():
            setattr(ck, name, value)
        return ck
    return make


class WhatIsShown(Dir):
    def run_with(self, argv, **fields):
        err, out = io.StringIO(), io.StringIO()
        with mock.patch.object(sources, "checkout", fake_checkout(**fields)), mock.patch.object(core, "main", Recorder()), \
                redirect_stderr(err), redirect_stdout(out):
            code = sourcescan.main(argv, env={})
        return code, out.getvalue(), err.getvalue()

    def test_what_the_checkout_found_is_said_a_few_lines_at_a_time(self):
        code, out, err = self.run_with(
            [SPEC], notes=[f"note {i}" for i in range(10)], anomalies=[("case", "a/B", "differs from a/b\x1b[2J")],
            skipped=[("big.bin", "larger than 50 MB, not read"), ("x/y", "could not be written (OSError)")])
        lines = err.splitlines()
        self.assertEqual([l for l in lines if l.startswith("warning: note:")],
                         [f"warning: note: note {i}" for i in range(8)] + ["warning: note: and 2 more"])
        archive = [l for l in lines if l.startswith("warning: archive:")]
        self.assertEqual(len(archive), 1)
        self.assertTrue(archive[0].startswith("warning: archive: case a/B: differs from a/b"))
        self.assertNotIn("\x1b", err)
        self.assertEqual([l for l in lines if l.startswith("warning: skipped:")],
                         ["warning: skipped: big.bin: larger than 50 MB, not read"])        # the other is a gap, below
        self.assertIn("x/y: could not be written (OSError)", err)

    def test_as_many_notes_as_are_shown_leave_nothing_out(self):
        code, out, err = self.run_with([SPEC], notes=[f"note {i}" for i in range(8)])
        self.assertEqual(err.count("warning: note:"), 8)
        self.assertNotIn(" more", err)

    def test_the_gaps_are_cut_off_and_counted(self):
        code, out, err = self.run_with([SPEC, "--ci"], incomplete=[(f"r{i}", f"d{i}") for i in range(12)])
        self.assertEqual(code, 1)
        gap_lines = [l for l in err.splitlines() if re.match(r"  r\d+: d\d+$", l)]
        self.assertEqual(gap_lines, [f"  r{i}: d{i}" for i in range(8)])
        self.assertIn("\n  and 4 more\n", err)
        code, out, err = self.run_with([SPEC, "--ci"], incomplete=[(f"r{i}", f"d{i}") for i in range(8)])
        self.assertNotIn(" more", err)                                    # exactly as many as are shown: nothing left out

    def test_accepting_says_so(self):
        code, out, err = self.run_with([SPEC, "--ci", "--accept-incomplete"], incomplete=[("tree", "t")])
        self.assertEqual(code, 0)
        self.assertIn("--accept-incomplete: the exit status is the gate's alone", err)
        self.assertNotIn("--ci: exit 1", err)


class EndToEnd(Dir):
    """The real scan, on a two-file repository the fake network serves."""

    FILES = {"app.py": b"import os\nos.system(input())\n", "README.md": b"# r\n"}

    @unittest.skipUnless(engine.available(), "the scan needs the native engine")
    def test_the_reports_name_the_commit_and_hold_the_findings(self):
        out, err = io.StringIO(), io.StringIO()
        net = Net(gh_answers(files=self.FILES))
        with redirect_stdout(out), redirect_stderr(err):
            code = sourcescan.main([SPEC, "--ci", "-q"], env={}, http=net)
        self.assertEqual(code, 1, out.getvalue() + err.getvalue())         # the command injection fails the gate
        self.assertEqual(sorted(os.listdir(self.tmp)), [NAME + ".html", NAME + ".json"])
        self.assertIn(f"Source: github:o/r@{SHA}", out.getvalue())
        with open(os.path.join(self.tmp, NAME + ".json"), encoding="utf-8") as f:
            report = json.load(f)
        self.assertTrue(any(i["file"].endswith("app.py") for i in report["issues"]), report["issues"])
        self.assertEqual(report["project"], f"github:o/r@{SHA}")          # not the directory it was read into
        self.assertEqual((report["source"]["commit"], report["source"]["uri"], report["source"]["complete"]),
                         (SHA, "https://github.com/o/r", True))
        self.assertNotIn("incomplete", report)
        self.assertIn(f"Lazaret scan — github:o/r@{SHA}", out.getvalue())

    @unittest.skipUnless(engine.available(), "the scan needs the native engine")
    def test_an_incomplete_checkout_s_report_says_so_and_the_sarif_names_the_repository(self):
        net = Net(gh_answers(files=self.FILES, tree=list(self.FILES) + ["tests/t.py"]))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = sourcescan.main([SPEC, "-q", "--sarif", "r.sarif"], env={}, http=net)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())         # without --ci: said, exit unchanged
        with open(NAME + ".json", encoding="utf-8") as f:
            report = json.load(f)
        self.assertTrue(report["incomplete"])
        self.assertTrue(report["incompleteReason"].startswith(
            f"the checkout of github:o/r@{SHA} was not read whole (export-ignore: 1 path(s) are in the commit"),
            report["incompleteReason"])
        self.assertFalse(report["source"]["complete"])
        with open("r.sarif", encoding="utf-8") as f:
            run_ = json.load(f)["runs"][0]
        self.assertEqual(run_["versionControlProvenance"], [{"repositoryUri": "https://github.com/o/r",
                                                             "revisionId": SHA,
                                                             "mappedTo": {"uriBaseId": "%SRCROOT%"}}])
        self.assertTrue(run_["results"])
        self.assertTrue(all(r["locations"][0]["physicalLocation"]["artifactLocation"].get("uriBaseId") == "%SRCROOT%"
                            for r in run_["results"]), run_["results"][:1])

    def test_cli_dispatch_runs_the_same_thing(self):
        seen = []
        with mock.patch.object(sourcescan, "main", lambda argv: seen.append(argv) or 0):
            self.assertEqual(_cli.main(["scan", SPEC, "--ci"]), 0)
            self.assertEqual(_cli.main(["--ci", "gitlab:g/p@main"]), 0)
        self.assertEqual(seen, [["scan", SPEC, "--ci"], ["--ci", "gitlab:g/p@main"]])
        with mock.patch.object(sourcescan, "main", lambda argv: self.fail("not a source")), \
                mock.patch.object(core, "main", lambda argv: 7):
            self.assertEqual(_cli.main(["somedir", "--ci"]), 7)
            self.assertFalse(_cli.is_source(["guard", "npm", "install", "x"]))
            self.assertFalse(_cli.is_source([]))
            self.assertTrue(_cli.is_source(["--exclude", "x", "gitlab:g/p"]))   # a first look; `find` decides


if __name__ == "__main__":
    unittest.main()
