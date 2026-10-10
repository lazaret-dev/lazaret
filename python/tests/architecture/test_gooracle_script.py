"""scripts/gooracle (0.1.9, G-1): the program that asks Go's own code the questions `registry/ecosystems/golang.py` answers.

The tests never run Go. They check the Python half of the script: the zips it builds are zips (Python reads what it writes), the
cases are the same on every run, the comparison reports a difference when there is one and nothing when there is none (a fake
oracle that answers from this repository's module, and one that lies), the golden file is refused when the two disagree, and
`main.go` is a program of Go's own packages that opens no connection."""

import collections
import io
import json
import os
import random
import re
import subprocess
import tempfile
import unittest
import zipfile
from unittest import mock

from lazaret.registry.ecosystems import base, golang
from lazaret.scanner import gomod
from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "gooracle")
gooracle = _support.load_script(os.path.join(SCRIPT, "gooracle.py"), "gooracle_script")
ROOT = gooracle.ROOT


def text_of(hexed):
    return bytes.fromhex(hexed).decode("utf-8", "surrogatepass")


class SelfOracle:
    """Answers every question from this repository's own module, so the comparison has nothing to find; with `lie` set it
    answers the checks of module paths the wrong way round."""

    def __init__(self, lie=False):
        self.lie = lie
        self.asked = collections.Counter()

    def run(self, requests):
        return [self.answer(r) for r in requests]

    def answer(self, r):
        op = r["op"]
        self.asked[op] += 1
        if op in ("checkpath", "escapepath", "split"):
            path = text_of(r["hex"])
            why = golang.check_module_path(path)
            if op == "checkpath":
                return {"ok": (why is None) != self.lie, "err": why or ""}
            if op == "escapepath":
                return {"ok": why is None, "out": golang.escape(path) if why is None else "", "err": why or ""}
            prefix, major, ok = golang.split_path_version(path)
            return {"prefix": prefix, "major": major, "ok": ok}
        if op == "canonver":
            return {"canonical": golang.canonical_version(r["v"]), "pseudo": golang.is_pseudo_version(r["v"])}
        if op == "semver":
            return {"valid": golang.VERSION_RE.fullmatch(r["v"]) is not None, "canonical": ""}
        if op == "checkmajor":
            return {"ok": golang.check_path_major(r["v"], r["path"]), "err": ""}
        if op == "checkzip":
            with zipfile.ZipFile(r["file"]) as zf:
                name = zf.infolist()[0].orig_filename.encode("cp437").decode("utf-8", "surrogatepass")      # (the raw bytes, as text)
            _, problem = golang.Go().member_path("gomod", name, ROOT)
            return {"err": problem or "", "valid": 0, "omitted": 0, "invalid": 0}
        if op == "parsemodlax":
            try:
                got = golang.parse_gomod(text_of(r["hex"]))
            except ValueError as problem:
                return {"ok": False, "err": str(problem)}
            return {"ok": True, "err": "", "module": got["module"], "require": [list(x) for x in got["require"]]}
        if op == "parsemod":                                  # (what the project reads of its own go.mod; Go refuses an unknown verb)
            text = text_of(r["hex"])
            got = gomod.parse(text)
            return {"ok": True, "err": "", "module": got["module"], "go": got["go"], "require": [list(x) for x in got["require"]],
                    "replace": [list(x) for x in got["replace"]]}
        if op == "hashzip":
            with open(r["file"], "rb") as fh:
                blob = fh.read()
            try:
                return {"ok": True, "h1": golang.zip_h1(blob), "err": ""}
            except base.DigestError as problem:
                return {"ok": False, "h1": "", "err": str(problem)}
        raise AssertionError("an op the fake does not know: " + op)


class ZipTests(unittest.TestCase):
    def test_what_build_zip_writes_python_reads(self):
        entries = [(b"a.go", b"package a\n", 0, 8), (b"d/b.go", b"", 0, 0), (ROOT.encode() + b"go.mod", b"module x\n", 0x08, 8),
                   (b"\xc3\xa9.go", b"x" * 1000, 0x800, 8), (b"d/", b"", 0, 0)]
        blob = gooracle.build_zip(entries, b"a comment")
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            self.assertIsNone(zf.testzip())
            self.assertEqual(zf.comment, b"a comment")
            self.assertEqual([i.filename for i in zf.infolist()], ["a.go", "d/b.go", ROOT + "go.mod", "é.go", "d/"])
            self.assertEqual([zf.read(i) for i in zf.infolist()], [e[1] for e in entries])
            self.assertEqual([i.compress_type for i in zf.infolist()][:2], [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED])

    def test_an_empty_zip_is_only_an_end_record(self):
        blob = gooracle.build_zip([])
        self.assertEqual(len(blob), 22)
        self.assertEqual(zipfile.ZipFile(io.BytesIO(blob)).namelist(), [])

    def test_a_case_becomes_the_same_zip_every_time(self):
        case = {"label": "x", "entries": [[b"a.go".hex(), b"x".hex(), 0, 8], [b"b".hex(), b"".hex(), 0x800, 0]], "comment": "63"}
        self.assertEqual(gooracle.zip_of(case), gooracle.zip_of(case))
        self.assertEqual(zipfile.ZipFile(io.BytesIO(gooracle.zip_of(case))).comment, b"c")

    def test_a_zip_is_strict_when_a_module_could_be_one(self):
        def case(entries, comment=""):
            return {"label": "t", "entries": [[n.hex(), b"".hex(), f, 8] for n, f in entries], "comment": comment}
        self.assertTrue(gooracle.zip_is_strict(case([(b"a", 0), (b"b", 0x800)])))
        self.assertTrue(gooracle.zip_is_strict(case([(b"a", 0)], "63")))
        self.assertFalse(gooracle.zip_is_strict(case([(b"a", 0)], "504b0506" + "00" * 18)), "a comment that is an end record")
        self.assertFalse(gooracle.zip_is_strict(case([(b"a", 0), (b"a", 0)])), "a repeated name")
        self.assertFalse(gooracle.zip_is_strict(case([(b"a\nb", 0)])), "a newline in a name")
        self.assertFalse(gooracle.zip_is_strict(case([(b"\xff", 0x800)])), "UTF-8 flagged and not UTF-8")
        self.assertTrue(gooracle.zip_is_strict(case([(b"\xff", 0)])), "not flagged, so any bytes")


class CaseTests(unittest.TestCase):
    def test_the_cases_are_the_same_on_every_run(self):
        for make in (gooracle.path_cases, gooracle.version_cases, gooracle.member_cases, gooracle.gomod_cases, gooracle.zip_cases):
            with self.subTest(make=make.__name__):
                self.assertEqual(make(random.Random(5), 200), make(random.Random(5), 200))
                self.assertNotEqual(make(random.Random(5), 200), make(random.Random(6), 200))

    def test_the_cases_are_of_both_kinds_and_bounded(self):
        rnd = random.Random(1)
        paths = gooracle.path_cases(rnd, 3000)
        good = [p for p in paths if golang.check_module_path(p) is None]
        self.assertGreater(len(good), 100)
        self.assertGreater(len(paths) - len(good), 100)
        self.assertEqual(len(paths), len(set(paths)))
        versions = gooracle.version_cases(rnd, 3000)
        self.assertGreater(len([v for v in versions if golang.VERSION_RE.fullmatch(v)]), 20)
        self.assertGreater(len([v for v in versions if not golang.VERSION_RE.fullmatch(v)]), 50)
        for text in paths + versions + gooracle.member_cases(rnd, 500) + gooracle.gomod_cases(rnd, 500):
            self.assertLess(len(text), 5000)
        for case in gooracle.zip_cases(rnd, 200):
            self.assertLessEqual(len(case["entries"]), 6)

    def test_a_path_that_is_not_text_goes_through_hex(self):
        for text in ("a", "é", "a\ud800b", "\udcff", "a/b", ""):
            with self.subTest(text=text):
                self.assertEqual(text_of(gooracle.hexof(text)), text)


class OracleTests(unittest.TestCase):
    def fake_run(self, stdout="", returncode=0, stderr=""):
        return mock.patch.object(gooracle.subprocess, "run", return_value=subprocess.CompletedProcess([], returncode, stdout, stderr))

    def test_no_requests_start_nothing(self):
        with mock.patch.object(gooracle.subprocess, "run", side_effect=AssertionError("started")):
            self.assertEqual(gooracle.Oracle("/x").run([]), [])

    def test_one_json_line_in_and_one_out(self):
        with self.fake_run('{"ok": true}\n{"ok": false}\n') as run:
            self.assertEqual(gooracle.Oracle("/x").run([{"op": "a"}, {"op": "b"}]), [{"ok": True}, {"ok": False}])
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/x"])
        self.assertEqual(kwargs["input"], '{"op": "a"}\n{"op": "b"}\n')
        self.assertEqual(kwargs["encoding"], "utf-8")

    def test_an_oracle_that_fails_or_answers_short_stops_everything(self):
        with self.fake_run("", 2, "boom"):
            with self.assertRaises(SystemExit) as caught:
                gooracle.Oracle("/x").run([{"op": "a"}])
            self.assertIn("boom", str(caught.exception))
        with self.fake_run('{"ok": true}\n'):
            with self.assertRaises(SystemExit) as caught:
                gooracle.Oracle("/x").run([{"op": "a"}, {"op": "b"}])
            self.assertIn("1 of 2", str(caught.exception))

    def test_build_needs_go(self):
        with mock.patch.object(gooracle.shutil, "which", return_value=None):
            with self.assertRaises(SystemExit) as caught:
                gooracle.build("/nowhere")
        self.assertIn("go is not installed", str(caught.exception))


class CompareTests(unittest.TestCase):
    def test_nothing_differs_when_the_answers_are_this_module_s_own(self):
        oracle = SelfOracle()
        data = gooracle.gather(oracle, 1)
        count, bad = gooracle.compare(data)
        self.assertEqual(bad, [])
        for kind in ("paths", "versions", "zip members", "go.mod files", "zips", "path majors"):
            self.assertGreater(count[kind], 0, kind)
        for op in ("checkpath", "escapepath", "split", "canonver", "semver", "checkmajor", "checkzip", "parsemodlax", "hashzip"):
            self.assertGreater(oracle.asked[op], 0, op)

    def test_a_difference_is_reported_and_diff_exits_with_one(self):
        count, bad = gooracle.compare(gooracle.gather(SelfOracle(lie=True), 1))
        self.assertTrue(bad)
        self.assertTrue(all(line.split(" ")[0] == "path" for line in bad), bad[:3])
        with mock.patch("builtins.print") as printed:
            self.assertEqual(gooracle.diff(SelfOracle(lie=True), 1), 1)
            self.assertIn("MISMATCH", " ".join(str(c.args[0]) for c in printed.call_args_list if c.args))
        with mock.patch("builtins.print"):
            self.assertEqual(gooracle.diff(SelfOracle(), 1), 0)

    def test_golden_files_are_not_written_while_the_two_differ(self):
        with tempfile.TemporaryDirectory(prefix="gooracle-test-") as out:
            with self.assertRaises(SystemExit) as caught:
                gooracle.golden(SelfOracle(lie=True), os.path.join(out, "clone"), out)
            self.assertIn("differ", str(caught.exception))
            self.assertEqual(os.listdir(out), [])


class SmallToolsTests(unittest.TestCase):
    def test_pick_keeps_a_few_of_each_group_in_a_fixed_order(self):
        rows = [(i % 3, i) for i in range(30)]
        a = gooracle.pick(rows, lambda r: r[0], 4, random.Random(1))
        b = gooracle.pick(rows, lambda r: r[0], 4, random.Random(1))
        self.assertEqual(a, b)
        self.assertEqual(collections.Counter(r[0] for r in a), {0: 4, 1: 4, 2: 4})
        self.assertEqual(gooracle.pick(rows[:2], lambda r: r[0], 4, random.Random(1)), rows[:2])

    def test_a_reason_is_the_error_without_what_was_quoted(self):
        self.assertEqual(gooracle.reason('malformed module path "a b": invalid char \' \''), "invalid char Q")
        self.assertEqual(gooracle.reason("plain"), "plain")
        self.assertLessEqual(len(gooracle.reason("x" * 500)), 60)

    def test_the_published_hashes_are_h1_hashes_of_modules_at_tags(self):
        self.assertEqual(len(gooracle.PUBLISHED), 3)
        for module, version, url, h1_zip, h1_mod in gooracle.PUBLISHED:
            self.assertIsNone(golang.check_module_path(module))
            self.assertRegex(version, golang.VERSION_RE)
            self.assertTrue(url.startswith("https://github.com/"))
            self.assertRegex(h1_zip, r"^h1:[A-Za-z0-9+/]{43}=$")
            self.assertRegex(h1_mod, r"^h1:[A-Za-z0-9+/]{43}=$")
        self.assertTrue(set(gooracle.KEEP_ZIPS) <= {row[0] for row in gooracle.PUBLISHED})

    def test_the_command_line_has_three_commands(self):
        with mock.patch("sys.stderr", new=io.StringIO()):                # (argparse says its usage there)
            with self.assertRaises(SystemExit):
                gooracle.main([])
            with self.assertRaises(SystemExit):
                gooracle.main(["diff"])
        with mock.patch.object(gooracle, "build") as build:
            self.assertEqual(gooracle.main(["build", "--out", "/somewhere"]), 0)
        build.assert_called_once_with("/somewhere")


class GoSourceTests(unittest.TestCase):
    """`main.go` is read, not run: it must stay a program that asks Go's own packages and opens no connection."""

    def setUp(self):
        with open(os.path.join(SCRIPT, "main.go"), encoding="utf-8") as fh:
            self.source = fh.read()

    def imports(self):
        block = re.search(r"import \((.*?)\n\)", self.source, re.S).group(1)
        return re.findall(r'"([^"]+)"', block)

    def test_it_imports_the_standard_library_and_golang_org_x_mod_only(self):
        found = self.imports()
        self.assertTrue(found)
        for path in found:
            first = path.split("/")[0]
            self.assertTrue("." not in first or path.startswith("golang.org/x/mod/"), path)
        for needed in ("golang.org/x/mod/module", "golang.org/x/mod/semver", "golang.org/x/mod/modfile", "golang.org/x/mod/zip",
                       "golang.org/x/mod/sumdb/dirhash"):
            self.assertIn(needed, found)

    def test_it_opens_no_connection_and_runs_no_program(self):
        for word in ("os/exec", "net.Dial", "net.Listen", "http.Get", "http.Post", "http.Client", "http.ListenAndServe", "syscall", "unsafe", "os.Remove",
                     "os.Setenv", "ioutil.WriteFile"):
            self.assertNotIn(word, self.source, word)

    def test_every_op_the_script_asks_is_one_it_answers(self):
        with open(os.path.join(SCRIPT, "gooracle.py"), encoding="utf-8") as fh:
            asked = set(re.findall(r'"op": "([a-z]+)"', fh.read()))
        answered = set(re.findall(r'case "([a-z]+)"', self.source))
        self.assertTrue(asked)
        self.assertEqual(asked - answered, set())

    def test_the_fake_in_these_tests_answers_the_same_ops(self):
        answered = set(re.findall(r'case "([a-z]+)"', self.source)) - {"vcszip", "hashfile", "sumdbserve"}
        with open(__file__, encoding="utf-8") as fh:
            ours = set(re.findall(r'op == "([a-z]+)"', fh.read())) | {"checkpath", "escapepath", "split"}
        self.assertEqual(answered - ours, set())


if __name__ == "__main__":
    unittest.main()
