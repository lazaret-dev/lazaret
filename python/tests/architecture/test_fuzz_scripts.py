"""scripts/fuzz (0.1.9, X-1): the mutation fuzzer for the readers of untrusted input.

Three layers are tested. The mutator: the same seed gives the same bytes, nothing outgrows its limit, every change does
what it says and copes with an empty input. The driver, with fake targets: a clean target runs clean, an exception, a
broken promise, a warning and a slow run are each a finding, de-duplicated, made smaller and written out; the same seed
runs the same inputs; the exit status, `--replay` and the known-findings list behave. And the targets, against the real
readers: their seeds run clean, a short run of fixed seed finds nothing new, each known finding still reproduces (the
test that says the reader was fixed), and every promise a target checks is shown to be live by a reader that breaks it.

The workflow that runs the long fuzz is checked for the rules of ci.yml when the file is there."""

import ast
import contextlib
import importlib
import io
import json
import os
import random
import re
import sys
import tempfile
import time
import unittest
import warnings
import xml.etree.ElementTree as StdET
from unittest import mock

from tests import _support

FUZZ = os.path.join(_support.REPO_ROOT, "scripts", "fuzz")
WORKFLOW = os.path.join(_support.REPO_ROOT, ".github", "workflows", "fuzz.yml")
if FUZZ not in sys.path:
    sys.path.insert(0, FUZZ)

fuzz_mutate = importlib.import_module("fuzz_mutate")
fuzz_targets = importlib.import_module("fuzz_targets")
driver = _support.load_script(os.path.join(FUZZ, "fuzz.py"), "fuzz_driver")

EXPECTED_TARGETS = ["archive-tgz", "archive-tbz2", "archive-txz", "archive-zip", "xml", "xml-minidom",
                    "sca-package-lock-json", "sca-yarn-lock", "sca-pnpm-lock-yaml", "sca-bun-lock", "sca-poetry-lock",
                    "sca-uv-lock", "sca-pylock-toml", "sca-pipfile-lock", "sca-requirements-txt", "sca-pyproject-toml",
                    "sca-setup-py", "sca-bundle-index", "sca-bundle-doc"]


def fake(run, seeds=(b"abc",), name="fake", **options):
    return fuzz_targets.Target(name, "a fake", lambda: list(seeds), lambda: (run, lambda: None), **options)


def run_main(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = driver.main(list(argv))
    return status, out.getvalue(), err.getvalue()


# ----------------------------------------------------------------------------------------------- mutator

class MutatorTests(unittest.TestCase):
    def mutator(self, seed=1, **kw):
        return fuzz_mutate.Mutator(random.Random(seed), **kw)

    def test_the_same_seed_gives_the_same_bytes_and_another_gives_others(self):
        corpus = [b"alpha 123 beta", b"[1, 2, 3]"]

        def stream(seed):
            m = self.mutator(seed, dictionary=(b"<!DOCTYPE",))
            return [m.mutate(corpus[i % 2], corpus) for i in range(200)]
        self.assertEqual(stream(5), stream(5))
        self.assertNotEqual(stream(5), stream(6))

    def test_rng_for_is_a_function_of_the_seed_and_the_name(self):
        draw = lambda seed, name: fuzz_mutate.rng_for(seed, name).random()      # noqa: E731
        self.assertEqual(draw("0", "a"), draw("0", "a"))
        self.assertNotEqual(draw("0", "a"), draw("0", "b"))
        self.assertNotEqual(draw("0", "a"), draw("1", "a"))

    def test_nothing_outgrows_its_limit_and_the_input_is_not_changed(self):
        for limit in (1, 16, 300):
            m = self.mutator(limit, max_len=limit, dictionary=(b"x" * 40,))
            base = b"seed 12345 " * 20
            for _ in range(500):
                self.assertLessEqual(len(m.mutate(base, [base])), limit)
        self.assertEqual(base, b"seed 12345 " * 20)

    def test_every_change_copes_with_an_empty_input(self):
        m = self.mutator(3, dictionary=(b"tok",))
        for op in m.ops:
            for corpus in ([], [b""], [b"abc"]):
                with self.subTest(op=op.__name__, corpus=corpus):
                    buf = bytearray()
                    op(buf, corpus)
                    self.assertIsInstance(buf, bytearray)
        self.assertIsInstance(m.mutate(b""), bytes)

    def test_the_changes_do_what_they_say(self):
        m = self.mutator(4, dictionary=(b"<TOK>",))
        base = b"value 1234 end of the seed input"

        def apply(op, corpus=(), times=40):
            outs = []
            for _ in range(times):
                buf = bytearray(base)
                op(buf, list(corpus))
                outs.append(bytes(buf))
            return outs
        bits = [sum(bin(a ^ b).count("1") for a, b in zip(base, o)) for o in apply(m.flip_bit)]
        self.assertEqual(set(bits), {1})
        self.assertTrue(all(len(o) == len(base) for o in apply(m.flip_bit)))
        self.assertTrue(all(len(o) == len(base) for o in apply(m.set_byte)))
        self.assertTrue(all(len(o) > len(base) for o in apply(m.insert_bytes)))
        self.assertTrue(all(len(o) < len(base) for o in apply(m.delete_span)))
        self.assertTrue(all(len(o) > len(base) for o in apply(m.duplicate_span)))
        self.assertTrue(any(len(o) > 2 * len(base) for o in apply(m.repeat_span)))
        self.assertTrue(all(len(o) < len(base) for o in apply(m.truncate)))
        self.assertTrue(all(b"<TOK>" in o for o in apply(m.insert_token)))
        self.assertTrue(all(sorted(o) == sorted(base) for o in apply(m.swap_spans)))
        self.assertTrue(all(o != base for o in apply(m.nest)))
        spliced = apply(m.splice, [b"ZZZZZZZZZZ"])
        self.assertTrue(any(b"Z" in o for o in spliced))

    def test_numbers_become_boundary_values_as_text_and_as_binary_fields(self):
        m = self.mutator(8)
        seen = set()
        for _ in range(300):
            buf = bytearray(b"size 1234 end")
            m.rewrite_number(buf, [])
            seen.add(bytes(buf))
        texts = {s.split(b" ")[1] for s in seen}
        wanted = {str(v).encode() for v in fuzz_mutate.INTERESTING}
        self.assertTrue(texts & wanted)
        self.assertTrue(all(s.startswith(b"size ") and s.endswith(b" end") for s in seen))
        binary = set()
        for _ in range(300):
            buf = bytearray(b"no digits in this one")
            m.rewrite_number(buf, [])                        # no digits: a binary field instead
            binary.add(bytes(buf))
        self.assertTrue(len(binary) > 10)
        buf = bytearray(b"\x00" * 16)
        for _ in range(50):
            m.write_int(buf, [])
        self.assertNotEqual(bytes(buf), b"\x00" * 16)

    def test_the_stack_is_one_to_six_changes(self):
        m = self.mutator(9)
        calls = []
        m.ops = (lambda buf, corpus: calls.append(1),)
        counts = set()
        for _ in range(300):
            calls.clear()
            m.mutate(b"x")
            counts.add(len(calls))
        self.assertEqual(counts, {1, 2, 3, 4, fuzz_mutate.MAX_STACK})


# ------------------------------------------------------------------------------------------------ driver

class DriverTests(unittest.TestCase):
    def test_a_clean_target_runs_its_seeds_and_then_the_iterations(self):
        seen = []
        report = driver.fuzz_target(fake(seen.append, seeds=(b"one", b"two")), iterations=25)
        self.assertEqual((report["runs"], report["findings"], len(seen)), (27, [], 27))
        self.assertEqual(seen[:2], [b"one", b"two"])

    def test_the_same_seed_runs_the_same_inputs_and_another_runs_others(self):
        def inputs(seed):
            seen = []
            driver.fuzz_target(fake(seen.append, dictionary=(b"tok",)), seed=seed, iterations=60)
            return seen
        self.assertEqual(inputs("a"), inputs("a"))
        self.assertNotEqual(inputs("a"), inputs("b"))

    def test_the_default_number_of_iterations(self):
        report = driver.fuzz_target(fake(lambda data: None))
        self.assertEqual(report["runs"], driver.DEFAULT_ITERATIONS + 1)

    def test_an_exception_is_a_finding_with_its_signature_and_a_smaller_input(self):
        def run(data):
            if b"X" in data:
                raise KeyError("boom")
        report = driver.fuzz_target(fake(run, seeds=(b"padding X padding",)), iterations=5)
        (finding,) = report["findings"]
        self.assertEqual((finding.kind, finding.data), ("exception", b"X"))
        self.assertRegex(finding.signature, r"^KeyError@test_fuzz_scripts\.py:\d+$")
        self.assertIn("KeyError: 'boom'", finding.text)
        self.assertEqual((finding.target, finding.iteration, finding.seed), ("fake", 1, 0))

    def test_findings_are_kept_as_found_when_not_to_be_shrunk(self):
        def run(data):
            if b"X" in data:
                raise KeyError
        report = driver.fuzz_target(fake(run, seeds=(b"padding X padding",)), iterations=0, minimize=False)
        self.assertEqual(report["findings"][0].data, b"padding X padding")

    def test_a_system_exit_is_a_finding_too(self):
        def run(data):
            raise SystemExit(3)
        report = driver.fuzz_target(fake(run), iterations=0)
        self.assertRegex(report["findings"][0].signature, r"^SystemExit@")

    def test_a_broken_promise_is_a_finding_named_for_its_rule(self):
        def run(data):
            fuzz_targets.check(b"Q" not in data, "rule-q", "a Q was kept")
        report = driver.fuzz_target(fake(run, seeds=(b"xxQxx",)), iterations=0)
        (finding,) = report["findings"]
        self.assertEqual((finding.kind, finding.signature, finding.data), ("invariant", "invariant:rule-q", b"Q"))
        self.assertEqual(finding.text, "rule-q: a Q was kept")

    def test_the_same_failure_is_one_finding_and_different_ones_are_each_a_finding(self):
        def run(data):
            if b"A" in data:
                raise ValueError
            if b"B" in data:
                raise ValueError
            if b"C" in data:
                fuzz_targets.check(False, "rule-c")
        report = driver.fuzz_target(fake(run, seeds=(b"A", b"AA", b"B", b"C", b"CC")), iterations=0)
        self.assertEqual(sorted(f.signature.split("@")[0] for f in report["findings"]),
                         ["ValueError", "ValueError", "invariant:rule-c"])
        self.assertEqual(len({f.signature for f in report["findings"]}), 3)

    def test_a_run_over_the_limit_is_a_slow_finding_and_the_slowest_is_kept(self):
        def run(data):
            time.sleep(0.03 * data.count(b"S"))
        report = driver.fuzz_target(fake(run, seeds=(b"S", b"SS", b"abc")), iterations=0, time_limit=0.01, minimize=False)
        (finding,) = report["findings"]
        self.assertEqual((finding.kind, finding.signature, finding.data), ("slow", "slow", b"SS"))
        self.assertGreater(finding.seconds, 0.05)
        self.assertGreater(report["slowest"], 0.05)

    def test_a_slow_finding_is_shrunk_while_it_stays_slow(self):
        def run(data):
            time.sleep(0.03 * data.count(b"S"))
        report = driver.fuzz_target(fake(run, seeds=(b"xxSxx",)), iterations=0, time_limit=0.01)
        self.assertEqual(report["findings"][0].data, b"S")

    def test_the_time_limit_is_the_targets_unless_given(self):
        run = lambda data: time.sleep(0.03)             # noqa: E731
        self.assertEqual(driver.fuzz_target(fake(run, time_limit=5), iterations=0)["findings"], [])
        self.assertEqual(driver.fuzz_target(fake(run, time_limit=0.01), iterations=0)["findings"][0].kind, "slow")
        self.assertEqual(driver.fuzz_target(fake(run, time_limit=5), iterations=0, time_limit=0.01)["findings"][0].kind, "slow")

    def test_a_warning_is_a_finding_and_a_deprecation_is_not(self):
        def run(data):
            warnings.warn("noisy" if data != b"quiet" else "old", SyntaxWarning if data != b"quiet" else DeprecationWarning)
        report = driver.fuzz_target(fake(run, seeds=(b"quiet", b"loud")), iterations=0)
        (finding,) = report["findings"]
        self.assertEqual(finding.kind, "warning")
        self.assertTrue(finding.data and finding.data != b"quiet")
        self.assertRegex(finding.signature, r"^warning:SyntaxWarning@test_fuzz_scripts\.py:\d+$")
        self.assertIn("noisy", finding.text)

    def test_the_warnings_a_target_raises_do_not_reach_the_caller_or_change_its_filters(self):
        before = list(warnings.filters)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            driver.fuzz_target(fake(lambda data: warnings.warn("x", RuntimeWarning)), iterations=0)
        self.assertEqual(caught, [])
        self.assertEqual(warnings.filters, before)

    def test_inputs_that_ran_slower_than_usual_join_the_corpus(self):
        def run(data):
            if b"S" in data:
                time.sleep(0.02)
        report = driver.fuzz_target(fake(run, dictionary=(b"S",)), iterations=300, time_limit=5)
        self.assertGreater(report["corpus"], 1)
        self.assertLessEqual(report["corpus"], driver.MAX_CORPUS)

    def test_a_run_by_seconds_stops_when_they_are_over(self):
        started = time.monotonic()
        report = driver.fuzz_target(fake(lambda data: time.sleep(0.002)), seconds=0.25)
        self.assertGreater(report["runs"], 5)
        self.assertLess(time.monotonic() - started, 3)

    def test_a_target_is_started_once_and_closed_even_when_the_run_raises(self):
        events = []

        def run(data):
            raise RuntimeError("x")

        def start():
            events.append("start")
            return run, lambda: events.append("close")
        target = fuzz_targets.Target("fake", "a fake", lambda: [b"a"], start)
        driver.fuzz_target(target, iterations=3)
        self.assertEqual(events, ["start", "close"])

    def test_the_hard_limit_is_armed_for_each_run_and_cancelled_after_it(self):
        armed, cancelled = [], []
        with mock.patch.object(driver.faulthandler, "dump_traceback_later", lambda s, exit=False: armed.append((s, exit))), \
                mock.patch.object(driver.faulthandler, "cancel_dump_traceback_later", lambda: cancelled.append(1)):
            report = driver.fuzz_target(fake(lambda data: None), iterations=4, hard_limit=7)
        self.assertEqual((armed, len(cancelled)), ([(7, True)] * 5, 5))
        self.assertEqual(report["runs"], 5)
        armed.clear()
        with mock.patch.object(driver.faulthandler, "dump_traceback_later", lambda *a, **k: armed.append(1)):
            driver.fuzz_target(fake(lambda data: None), iterations=2)
        self.assertEqual(armed, [])

    def test_the_input_is_written_before_it_runs_so_a_hang_leaves_it_behind(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "pending.bin")
            seen_on_disk = []

            def run(data):
                with open(path, "rb") as fh:
                    seen_on_disk.append((fh.read(), data))
            driver.fuzz_target(fake(run), iterations=10, pending=path)
            self.assertTrue(all(a == b for a, b in seen_on_disk))
            self.assertEqual(len(seen_on_disk), 11)

    def test_shrink_deletes_what_is_not_needed_and_keeps_what_is(self):
        def run(data):
            if b"AB" in data and b"CD" in data:
                raise KeyError
        sig = driver.execute(run, b"..AB....CD..", 1)[0][1]
        small = driver.shrink(run, b"xxxxAByyyyyyyyyyCDzzzz" * 3, ("exception", sig), 1)
        self.assertIn(b"AB", small)
        self.assertIn(b"CD", small)
        self.assertLessEqual(len(small), 4 + 2)
        self.assertEqual(driver.shrink(run, b"xxABxxCDxx", ("exception", sig), 1, tries=0), b"xxABxxCDxx")

    def test_execute_says_what_happened(self):
        self.assertIsNone(driver.execute(lambda d: None, b"", 1)[0])
        outcome, seconds = driver.execute(lambda d: 1 / 0, b"", 1)
        self.assertEqual(outcome[:2][0], "exception")
        self.assertGreaterEqual(seconds, 0)

    def test_signature_of_names_the_deepest_frame_of_this_checkout(self):
        try:
            from lazaret.scanner import sca
            sca._yarn_spec_name(None)
        except AttributeError as exc:
            self.assertEqual(driver.signature_of(exc), f"AttributeError@sca.py:{exc.__traceback__.tb_next.tb_lineno}")

    def test_a_finding_is_written_with_its_input_and_how_to_replay_it(self):
        def run(data):
            raise OSError("disk")
        report = driver.fuzz_target(fake(run, seeds=(b"\x00\xffinput",)), iterations=0, minimize=False)
        (finding,) = report["findings"]
        with tempfile.TemporaryDirectory() as folder:
            path = driver.write_finding(finding, os.path.join(folder, "nested"), "python3 scripts/fuzz/fuzz.py")
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), b"\x00\xffinput")
            self.assertRegex(os.path.basename(path), r"^fake-exception-[0-9a-f]{10}\.bin$")
            with open(path[:-4] + ".txt", encoding="utf-8") as fh:
                text = fh.read()
            self.assertEqual(finding.path, path)
        for part in ("target:     fake", "kind:       exception", "OSError: disk", finding.digest,
                     f"--replay {os.path.basename(path)} fake", "first bytes:"):
            self.assertIn(part, text)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(fuzz_targets.TARGETS, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def register(self, run, **kw):
        target = fake(run, **kw)
        fuzz_targets.TARGETS[target.name] = target
        return target

    def test_list_names_every_target(self):
        status, out, _ = run_main("--list")
        self.assertEqual(status, 0)
        for name in EXPECTED_TARGETS:
            self.assertRegex(out, rf"(?m)^{re.escape(name)}\s+\S")

    def test_a_clean_run_exits_zero_and_prints_the_table_and_the_seed(self):
        self.register(lambda data: None)
        status, out, err = run_main("fake", "--iterations", "10", "--seed", "77")
        self.assertEqual(status, 0)
        self.assertRegex(out, r"(?m)^fake\s+11\s")
        self.assertIn("seed 77", err)

    def test_a_random_seed_is_printed_so_the_run_can_be_repeated(self):
        self.register(lambda data: None)
        status, _, err = run_main("fake", "--iterations", "1", "--seed", "random")
        self.assertRegex(err, r"seed \d+")

    def test_a_finding_exits_one_and_is_written_and_summarised(self):
        self.register(lambda data: 1 / 0, seeds=(b"a",))
        with tempfile.TemporaryDirectory() as folder:
            status, out, err = run_main("fake", "--iterations", "3", "--findings", folder,
                                        "--json", os.path.join(folder, "r.json"))
            self.assertEqual(status, 1)
            self.assertEqual(sorted(n.split(".")[-1] for n in os.listdir(folder)), ["bin", "json", "txt"])
            with open(os.path.join(folder, "r.json"), encoding="utf-8") as fh:
                report = json.load(fh)
        self.assertEqual(report["seed"], "0")
        (target,) = report["targets"]
        self.assertEqual((target["target"], target["runs"], target["findings"][0]["kind"]), ("fake", 4, "exception"))
        self.assertIn("exception: ZeroDivisionError@", out)
        self.assertIn("exception ZeroDivisionError@", err)

    def test_what_was_told_is_checked(self):
        self.register(lambda data: None)
        for argv in (("nonesuch",), ("fake", "--iterations", "3", "--seconds", "1"), ("--replay", "x"),
                     ("--replay", "x", "fake", "xml")):
            with self.subTest(argv):
                status, _, err = run_main(*argv)
                self.assertEqual(status, 2)
                self.assertTrue(err)

    def test_replay_runs_one_saved_input_against_one_target(self):
        self.register(lambda data: 1 / 0 if data == b"bad" else None)
        with tempfile.TemporaryDirectory() as folder:
            bad, good = os.path.join(folder, "bad.bin"), os.path.join(folder, "good.bin")
            for path, data in ((bad, b"bad"), (good, b"fine")):
                with open(path, "wb") as fh:
                    fh.write(data)
            status, out, _ = run_main("--replay", bad, "fake")
            self.assertEqual((status, "ZeroDivisionError@" in out), (1, True))
            status, out, _ = run_main("--replay", good, "fake")
            self.assertEqual((status, out.startswith("no finding")), (0, True))

    def test_a_known_finding_is_listed_as_known_and_does_not_fail_the_run(self):
        self.register(lambda data: 1 / 0 if data == b"X" else None, seeds=(b"X",))
        known = {("fake", "ZeroDivisionError@test_fuzz_scripts.py"): ("F-9", b"X")}
        with mock.patch.object(fuzz_targets, "KNOWN", known):
            status, out, _ = run_main("fake", "--iterations", "2")
        self.assertEqual(status, 0)
        self.assertIn("[known: F-9]", out)
        status, out, _ = run_main("fake", "--iterations", "2")
        self.assertEqual(status, 1)
        self.assertNotIn("known", out)

    def test_a_finding_is_known_by_its_target_and_its_signature_without_the_line(self):
        known = {("fake", "ValueError@a.py"): ("F-1", b""), ("fake", "invariant:rule-x"): ("F-2", None),
                 ("fake", "warning:UserWarning@a.py"): ("F-3", None)}
        with mock.patch.object(fuzz_targets, "KNOWN", known):
            self.assertEqual(fuzz_targets.known("fake", "ValueError@a.py:12"), "F-1")
            self.assertEqual(fuzz_targets.known("fake", "ValueError@a.py:7"), "F-1")
            self.assertEqual(fuzz_targets.known("fake", "invariant:rule-x"), "F-2")
            self.assertEqual(fuzz_targets.known("fake", "warning:UserWarning@a.py:3"), "F-3")
            self.assertIsNone(fuzz_targets.known("other", "ValueError@a.py:12"))
            self.assertIsNone(fuzz_targets.known("fake", "ValueError@b.py:12"))
            self.assertIsNone(fuzz_targets.known("fake", "invariant:rule-y"))
            self.assertIsNone(fuzz_targets.known("fake", "ValueError@a.py"[:-3]))
            self.assertIsNone(fuzz_targets.known("fake", "slow"))
            finding = driver.Finding("fake", "invariant", "invariant:rule-x", b"", "", 0, 1, 0)
            self.assertEqual(driver.is_known(finding), "F-2")


# ------------------------------------------------------------------------------------------------ targets

def run_of(name):
    return fuzz_targets.TARGETS[name].start()


class TargetTests(unittest.TestCase):
    def test_the_targets(self):
        self.assertEqual(list(fuzz_targets.TARGETS), EXPECTED_TARGETS)
        for name, target in fuzz_targets.TARGETS.items():
            with self.subTest(name):
                seeds = target.seeds()
                self.assertTrue(seeds and all(isinstance(s, bytes) for s in seeds))
                self.assertLessEqual(max(len(s) for s in seeds), target.max_len)
                self.assertGreater(target.time_limit, 0)
                self.assertTrue(target.summary and target.dictionary)

    def test_every_seed_runs_clean(self):
        for name, target in fuzz_targets.TARGETS.items():
            run, close = target.start()
            try:
                for index, seed in enumerate(target.seeds()):
                    with self.subTest(target=name, seed=index):
                        outcome, _ = driver.execute(run, seed, target.time_limit)
                        self.assertIsNone(outcome)
            finally:
                close()

    def test_a_short_run_of_fixed_seed_finds_nothing_new(self):
        started = time.monotonic()
        for name, target in fuzz_targets.TARGETS.items():
            heavy = name.startswith("archive")
            report = driver.fuzz_target(target, seed="x1", iterations=40 if heavy else 150, minimize=False)
            with self.subTest(target=name):
                unknown = [(f.kind, f.signature, f.data[:80]) for f in report["findings"] if not driver.is_known(f)]
                self.assertEqual(unknown, [])
        self.assertLess(time.monotonic() - started, 40)

    def test_the_known_findings_still_reproduce(self):
        for (name, signature), (ident, data) in fuzz_targets.KNOWN.items():
            if data is None:                     # what it shows depends on the Python version: not replayed
                continue
            run, close = run_of(name)
            try:
                with self.subTest(finding=ident, target=name):
                    outcome, _ = driver.execute(run, data, 5)
                    self.assertIsNotNone(outcome, f"{ident} no longer reproduces on {name}: it was fixed, so remove "
                                                  "its entry from KNOWN (and say so in docs/0.1.9-findings.md)")
                    self.assertEqual((outcome[0], outcome[1].rsplit(":", 1)[0]), ("exception", signature))
            finally:
                close()

    def test_the_known_findings_are_in_the_findings_document_when_it_is_there(self):
        path = os.path.join(_support.REPO_ROOT, "docs", "0.1.9-findings.md")
        if not os.path.exists(path):
            self.skipTest("docs/0.1.9-findings.md is not in this tree")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for ident in {i for i, _ in fuzz_targets.KNOWN.values()}:
            self.assertIn(ident, text)


class VersionBoundFindings(unittest.TestCase):
    """Findings that show on some Pythons only, so `KNOWN` does not replay them (its data is None)."""

    # a zip of two stored entries, "a.py" and one with no name at all (the standard library of 3.10 cannot write it)
    NAMELESS = bytes.fromhex(
        "504b03041400000000009124435d3b89f68b060000000600000004000000612e707978203d20310a504b0304140000000000"
        "9124435d5d09876b06000000060000000000000079203d20320a504b010214031400000000009124435d3b89f68b06000000"
        "06000000040000000000000000000000800100000000612e7079504b010214031400000000009124435d5d09876b06000000"
        "06000000000000000000000000000000800128000000504b05060000000002000200600000004c0000000000")

    def names(self):
        from lazaret.registry import repo
        anomalies = []
        return [m[0] for m in repo.iter_archive(self.NAMELESS, "zip", "wheel", anomalies=anomalies)]

    @unittest.skipUnless(sys.version_info < (3, 11), "from 3.11 ZipInfo.is_dir() asks endswith('/')")
    def test_f6_a_zip_entry_with_no_name_raises_index_error_before_python_3_11(self):
        with self.assertRaises(IndexError):
            self.names()                    # when this stops raising, the reader was fixed: drop F-6 from KNOWN

    @unittest.skipIf(sys.version_info < (3, 11), "before 3.11 this is F-6")
    def test_f6_the_same_zip_is_read_on_newer_pythons(self):
        self.assertEqual(self.names(), ["a.py"])

    def test_the_fixture_is_the_zip_it_says_it_is(self):
        import zipfile
        self.assertEqual(zipfile.ZipFile(io.BytesIO(self.NAMELESS)).namelist(), ["a.py", ""])

    # F-7: a wheel of LZMA entries (method 14) whose raw-LZMA header declares a dictionary of about 4 GiB (bytes 0x00 0x83 0xff 0xfb
    # 0xff: 5d 00 83 ff fb after the version and the length of the properties), 625 bytes, found by the fuzzer on 3.10
    HUGE_DICTIONARY = bytes.fromhex(
        "504b03043f0002000e00000021009475037b250000001200000018000000706b672d312e302e646973742d696e666f2f5245434f"
        "5244090405005d0083fffbff381ac9159c036e5225bf332e18d6b3d29cceedffc6387ffef1d800504b03043f0002000e00000021"
        "00361afa6e1e0000000b0000000b000000706b672f6c696e6b2e7079090405005d00008000002fe1a0dc6b102649c5a768cab6c4"
        "ffffd1908000504b01023f033f0002000e00000021002fa30108220000000e0000000f0000000000000000000000a48100000000"
        "706b672f5f5f696e69745f5f2e7079504b01023f033f0002000e0000002100000000001300000000000000090000000000000000"
        "000000ed414f000000706b672f646174612f504b01023f033f0002000e000000210065b7196629000000160000000b0000000000"
        "000000000000a48189000000706b672f636f72652e7079504b01023f033f00020d0e0000002100a4bdfeb82b000000170000001a"
        "0000000000000000000000a481db000000706b672d312e302e646973742d696e666f2f4d45544144415441504b01023f033f0002"
        "000e00000021008c483b262700000013000000170000000000000000000000a4813e010000706b672d312e302e646973742d696e"
        "666f2f574845454c504b01023f033f0002000e00000021009475037b2500000012000000180000000000000000000000a4819a01"
        "0000706b672d312e302e646973742d696e666f2f5245434f5244504b01023f033f0002000e0000002100361afa6e1e0000000b00"
        "00000b0000000000000000000000ffa1f5010000706b672f6c696e6b2e7079504b05060000000007000700b90100003c02000000"
        "00"
    )
    CAPPED = (
        "import resource, sys\n"
        "resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))        # as in a container or a CI job with a memory cap\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from lazaret.registry import repo\n"
        "try:\n"
        "    list(repo.iter_archive(bytes.fromhex(sys.argv[2]), 'zip', 'wheel', anomalies=[]))\n"
        "except MemoryError:\n"
        "    print('MemoryError')\n"
        "else:\n"
        "    print('read')\n")

    def under_a_cap(self):
        import subprocess
        run = subprocess.run([sys.executable, "-c", self.CAPPED, _support.SRC, self.HUGE_DICTIONARY.hex()],
                             capture_output=True, encoding="utf-8", errors="replace", timeout=30)
        return run.stdout.strip(), run.stderr

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_AS is enforced on Linux")
    def test_f7_a_huge_lzma_dictionary_is_a_memory_error_where_memory_is_capped(self):
        answer, err = self.under_a_cap()
        self.assertEqual(answer, "MemoryError", err)   # when this reads, the reader was fixed: drop F-7 from KNOWN

    def test_f7_the_fixture_is_a_wheel_of_lzma_entries(self):
        import zipfile
        infos = zipfile.ZipFile(io.BytesIO(self.HUGE_DICTIONARY)).infolist()
        self.assertEqual({i.compress_type for i in infos if not i.is_dir()}, {zipfile.ZIP_LZMA})
        self.assertIn(bytes.fromhex("090405005d0083fffbff"), self.HUGE_DICTIONARY)     # the 4 GiB header


class PromisesAreLive(unittest.TestCase):
    """A check that cannot fail checks nothing: each promise a target makes is broken here by a reader that does."""

    def archive(self, members, **patches):
        from lazaret.registry import repo
        calls = []

        def iter_archive(data, container, artifact=None, *, budget=None, anomalies=None):
            calls.append(1)
            items = members(len(calls)) if callable(members) else members
            for item in items:
                if isinstance(item, tuple) and item and item[0] == "anomaly":
                    anomalies.append(item[1])
                else:
                    yield item
        run, close = fuzz_targets.TARGETS["archive-tgz"].start()
        self.addCleanup(close)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(repo, "iter_archive", iter_archive))
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(repo if hasattr(repo, name) else fuzz_targets, name, value))
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(b"x")
        return raised.exception.rule

    def member(self, *a, **k):
        from lazaret.registry import repo
        return repo.Member(*a, **k)

    def test_the_archive_promises(self):
        M = self.member
        cases = [
            ("archive-member-shape", [("a", 1, b"x", None)]),
            ("archive-path-type", [M(b"a", 1, b"x", None)]),
            ("archive-path-type", [M("", 1, b"x", None)]),
            ("archive-size-type", [M("a", -1, b"", None)]),
            ("archive-size-type", [M("a", True, b"x", None)]),
            ("archive-bytes-type", [M("a", 1, "x", None)]),
            ("archive-reason", [M("a", 0, b"", "bogus")]),
            ("archive-detail-type", [M("a", 0, b"", "corrupt", 7)]),
            ("archive-real-size", [M("a", 5, b"abc", None)]),
            ("archive-member-path", [M("../x", 1, b"x", None)]),
            ("archive-member-path", [M("/x", 1, b"x", None)]),
            ("archive-member-path", [M("a\\b", 1, b"x", None)]),
            ("archive-member-path", [M(".", 1, b"x", None)]),
            ("archive-sample-limit", [M("a", 9000, b"x" * 9000, "member")]),
            ("archive-after-stop", [M("a", 0, b"", "total"), M("b", 1, b"x", None)]),
            ("archive-after-stop", [M("a", 0, b"", "time"), M("b", 0, b"", "corrupt")]),
            ("archive-after-stop", [M("a", 0, b"", "files"), M("b", 0, b"", "member")]),
            ("archive-anomaly-shape", [("anomaly", ("dup", "a"))]),
            ("archive-anomaly-shape", [("anomaly", ("dup", "a", 5))]),
        ]
        for rule, members in cases:
            with self.subTest(rule=rule, members=repr(members)[:60]):
                self.assertEqual(self.archive(members), rule)

    def test_the_archive_limits(self):
        M = self.member
        self.assertEqual(self.archive([M("a", 11, b"x" * 11, None)], MAX_MEMBER=10), "archive-member-limit")
        self.assertEqual(self.archive([M("a", 11, b"x" * 11, None)], BUDGET_TOTAL=10), "archive-budget")
        self.assertEqual(self.archive([M("a", 1, b"x", None), M("b", 1, b"x", None)], MAX_FILES=1), "archive-file-limit")

    def test_an_archive_read_twice_gives_the_same_members(self):
        M = self.member
        self.assertEqual(self.archive(lambda n: [M("a", n, b"x" * n, None)]), "archive-deterministic")
        self.assertEqual(self.archive(lambda n: [M("a", 1, b"x", None)] if n % 2 else [M("a", 1, b"x", None), ("anomaly", ("dup", "a", 5))]),
                         "archive-anomaly-shape")

    def sca(self, answer, warnings_to_make=()):
        from lazaret.scanner import sca

        def scan_all(root, extra_site_packages=None, warn=None):
            for kind, n in warnings_to_make:
                warn(kind, n)
            return answer
        run, close = fuzz_targets.TARGETS["sca-yarn-lock"].start()
        self.addCleanup(close)
        with mock.patch.object(sca, "scan_all", scan_all), self.assertRaises(fuzz_targets.Violation) as raised:
            run(b"x")
        return raised.exception.rule

    def test_the_inventory_promises(self):
        from lazaret.scanner import sca
        inv = lambda *entries: sca.Inventory(entries)       # noqa: E731
        good = ("npm", "lodash", "1", "yarn.lock")
        self.assertEqual(self.sca([good]), "sca-result-type")
        self.assertEqual(self.sca(inv(good, good, good)), "sca-entry-count")                  # 3 entries from 1 byte
        self.assertEqual(self.sca(inv(["npm", "a", "1", "w"])), "sca-entry-shape")
        self.assertEqual(self.sca(inv(("npm", "a", 1, "w"))), "sca-entry-shape")
        self.assertEqual(self.sca(inv(("npm", "a", "1"))), "sca-entry-shape")
        self.assertEqual(self.sca(inv(("gem", "a", "1", "w"))), "sca-entry-values")
        self.assertEqual(self.sca(inv(("npm", "", "1", "w"))), "sca-entry-values")
        self.assertEqual(self.sca(inv(), [(1, 1)]), "sca-warning-shape")
        self.assertEqual(self.sca(inv(), [("kind", "n")]), "sca-warning-shape")

    def bundle(self, name, seed, *patches):
        run, close = fuzz_targets.TARGETS[name].start()
        self.addCleanup(close)
        with contextlib.ExitStack() as stack:
            for owner, attr, value in patches:
                stack.enter_context(mock.patch.object(owner, attr, value))
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(seed)
        return raised.exception.rule

    def test_the_index_promises(self):
        from lazaret.scanner import sca_index
        bundle = sca_index.IndexedBundle
        seed = fuzz_targets.index_seeds()[0]
        pkg = {"name": "x"}
        pair = ({"cve": "A", "packages": [pkg]}, pkg)
        calls = []

        def alternate(self, name, ecosystem=None):
            calls.append(1)
            return [pair] if len(calls) % 2 else []

        def damaged(self, name, ecosystem=None):
            raise sca_index.BundleDamaged("x")
        run = lambda *patches: self.bundle("sca-bundle-index", seed, *patches)       # noqa: E731
        self.assertEqual(run((bundle, "advisories_for", lambda self, n, e=None: [1])), "index-answer-shape")
        self.assertEqual(run((bundle, "advisories_for", lambda self, n, e=None: [({}, {})])), "index-answer-values")
        self.assertEqual(run((bundle, "advisories_for", lambda self, n, e=None: [({"cve": 5, "packages": []}, pkg)])),
                         "index-answer-values")
        self.assertEqual(run((bundle, "advisories_for", lambda self, n, e=None: [({"cve": "A", "packages": [dict(pkg)]}, pkg)])),
                         "index-answer-package")
        self.assertEqual(run((sca_index._Advisories, "__len__", lambda self: 10 ** 9)), "index-advisory-count")
        self.assertEqual(run((bundle, "advisories_for", damaged)), "index-checked-then-damaged")
        self.assertEqual(run((bundle, "advisories_for", alternate)), "index-deterministic")

    def test_the_index_target_runs_a_file_with_its_checksums_made_right_too(self):
        from lazaret.scanner import sca_index
        seed = fuzz_targets.index_seeds()[0]
        opened = []
        real = sca_index.IndexedBundle.open

        def spy(path):
            with open(path, "rb") as fh:
                opened.append(fh.read())
            return real(path)
        run, close = fuzz_targets.TARGETS["sca-bundle-index"].start()
        self.addCleanup(close)
        changed = bytearray(seed)
        changed[sca_index.HEADER.size + 3] ^= 0x20                       # a byte of the metadata
        with mock.patch.object(sca_index.IndexedBundle, "open", staticmethod(spy)):
            run(bytes(changed))
        self.assertEqual(opened[0], bytes(changed))
        self.assertEqual(opened[1], fuzz_targets.repair_index(bytes(changed)))
        self.assertNotEqual(opened[0], opened[1])

    def test_repairing_an_index_makes_its_checksums_right_and_nothing_else(self):
        from lazaret.scanner import sca_index
        seed = fuzz_targets.index_seeds()[0]
        self.assertEqual(fuzz_targets.repair_index(seed), seed)
        self.assertEqual(fuzz_targets.repair_index(seed[:50]), seed[:50])
        head = sca_index.HEADER.size
        meta_len = sca_index.HEADER.unpack_from(seed)[8]
        for at, what in ((head + 5, "metadata"), (head + meta_len + 3, "advisory table"), (len(seed) - 1, "records"),
                         (head - 1, "the header's own checksum")):
            changed = bytearray(seed)
            changed[at] ^= 0x01
            repaired = fuzz_targets.repair_index(bytes(changed))
            with self.subTest(what=what):
                try:
                    with tempfile.TemporaryDirectory() as folder:
                        path = os.path.join(folder, "b")
                        with open(path, "wb") as fh:
                            fh.write(repaired)
                        sca_index.IndexedBundle.open(path).close()
                except ValueError as error:
                    self.assertNotIn("checksum", str(error))             # whatever else it is, it is not that
        grown = seed + b"tail"
        self.assertEqual(sca_index.HEADER.unpack_from(fuzz_targets.repair_index(grown))[3], len(grown))

    def test_the_bundle_document_promises(self):
        from lazaret.scanner import sca, sca_index
        seed = fuzz_targets.BUNDLE_DOCS[0]
        run = lambda *patches: self.bundle("sca-bundle-doc", seed, *patches)         # noqa: E731
        real_dump = sca_index.dump_index

        def other_warnings(doc, fh):
            summary = real_dump(doc, fh)
            summary["warnings"] = ["a warning no bundle has"]
            return summary
        self.assertEqual(run((sca, "CveBundle", mock.Mock(side_effect=ValueError("no")))), "bundle-doc-refusal")
        self.assertEqual(run((sca_index, "dump_index", other_warnings)), "bundle-doc-warnings")
        self.assertEqual(run((sca_index._Advisories, "__len__", lambda self: 1 + self._bundle._n_adv)), "bundle-doc-count")
        self.assertEqual(run((sca_index.IndexedBundle, "verify", lambda self: {"advisories": -1})), "bundle-doc-verify")
        self.assertEqual(run((sca_index.IndexedBundle, "advisories_for", lambda self, n, e=None: [])), "bundle-doc-answers")

    def test_what_the_bundle_readers_refuse_is_not_a_finding(self):
        from lazaret.scanner import sca_index
        run, close = fuzz_targets.TARGETS["sca-bundle-index"].start()
        self.addCleanup(close)
        for data in (b"", b"LZSCAIDX", b"x" * 500, fuzz_targets.index_seeds()[0][:-1]):
            run(data)
        run, close = fuzz_targets.TARGETS["sca-bundle-doc"].start()
        self.addCleanup(close)
        for data in (b"", b"[", b"[]", b"{}", b'{"bundleVersion": 2}', b'{"bundleVersion": 1, "advisories": {}}',
                     b'{"bundleVersion": 1, "advisories": [{"cve": "A", "cvss": NaN}]}', b"\xff\xfe"):
            run(data)                                                     # refused by both, or by the index only for NaN

    def xml(self, root, name="xml", data=b"<a/>"):
        run, close = fuzz_targets.TARGETS[name].start()
        self.addCleanup(close)
        from lazaret.safexml import ElementTree as ET
        with mock.patch.object(ET, "fromstring", lambda *a, **k: root), self.assertRaises(fuzz_targets.Violation) as raised:
            run(data)
        return raised.exception.rule

    def test_the_xml_promises(self):
        element = StdET.Element
        self.assertEqual(self.xml(element(7)), "xml-tag-type")
        crowded = element("a")
        crowded.extend(element("b") for _ in range(10))
        self.assertEqual(self.xml(crowded), "xml-node-count")                                  # 11 elements from 4 bytes
        fat = element("a")
        fat.text = "x" * (100 * 4 + 2 * 8 * 1024 * 1024 + 1)
        self.assertEqual(self.xml(fat), "xml-amplification")
        tall = element("a")
        tall.attrib["k"] = "v" * (100 * 4 + 2 * 8 * 1024 * 1024)
        self.assertEqual(self.xml(tall), "xml-amplification")
        tail = element("a")
        tail.append(element("b"))
        tail[0].tail = "t" * (100 * 11 + 2 * 8 * 1024 * 1024 + 1)
        self.assertEqual(self.xml(tail, data=b"<a><b/></a>"), "xml-amplification")

    def test_what_the_xml_readers_refuse_is_not_a_finding(self):
        from xml.parsers import expat

        from lazaret.safexml import ElementTree as ET
        from lazaret.safexml import _common, minidom
        for error in (ET.ParseError("x"), _common.LimitExceeded("x"), expat.ExpatError("x")):
            for name, module, attr in (("xml", ET, "fromstring"), ("xml-minidom", minidom, "parseString")):
                run, close = fuzz_targets.TARGETS[name].start()
                self.addCleanup(close)
                with self.subTest(name=name, error=type(error).__name__), \
                        mock.patch.object(module, attr, mock.Mock(side_effect=error)):
                    run(b"<a/>")
        run, close = fuzz_targets.TARGETS["xml"].start()
        self.addCleanup(close)
        with mock.patch.object(ET, "fromstring", mock.Mock(side_effect=LookupError("unknown encoding"))), \
                self.assertRaises(LookupError):
            run(b"<a/>")


class SeedsAndOptions(unittest.TestCase):
    def test_the_option_an_input_is_run_with_is_a_function_of_its_bytes(self):
        options = ("a", "b", "c")
        self.assertEqual(fuzz_targets.pick(b"same", options), fuzz_targets.pick(b"same", options))
        self.assertEqual({fuzz_targets.pick(bytes([i]), options) for i in range(60)}, set(options))

    def test_the_archive_seeds_are_real_archives_and_the_odd_ones_are_odd(self):
        from lazaret.registry import repo
        by_reason = {}
        for seed in fuzz_targets.tgz_seeds():
            for item in repo.iter_archive(seed, "tgz", None, budget=repo.Budget(total=1 << 20)):
                by_reason.setdefault(item[3], []).append(item[0])
        self.assertTrue(by_reason[None])
        self.assertIn("corrupt", by_reason)                       # the one with trailing bytes
        paths = [p for p in by_reason[None]]
        self.assertTrue(any(p.endswith("package.json") for p in paths))
        zipped = [item for seed in fuzz_targets.zip_seeds() for item in repo.iter_archive(seed, "zip", "wheel")]
        self.assertTrue(any(i[0].endswith("METADATA") and i[3] is None for i in zipped))

    def test_the_xml_seeds_include_the_inputs_the_hardening_is_for(self):
        text = b"\n".join(fuzz_targets.XML_SEEDS)
        for part in (b"<!DOCTYPE", b"<!ENTITY", b"SYSTEM", b"<!ATTLIST", b"&c;", b"\xff\xfe<\x00?\x00"):
            self.assertIn(part, text)


# ------------------------------------------------------------------------------------------------ the files

class ScriptRules(unittest.TestCase):
    def test_every_script_is_standard_library_only(self):
        allowed = {"argparse", "bz2", "contextlib", "faulthandler", "gzip", "hashlib", "io", "json", "lzma", "os",
                   "platform", "random", "re", "shutil", "sys", "tarfile", "tempfile", "time", "traceback", "warnings",
                   "zipfile", "zlib", "xml", "fuzz_common", "fuzz_mutate", "fuzz_targets", "lazaret"}
        for name in sorted(os.listdir(FUZZ)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(FUZZ, name), encoding="utf-8") as fh:
                tree = ast.parse(fh.read())
            for node in ast.walk(tree):
                modules = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                for module in modules:
                    with self.subTest(script=name, module=module):
                        self.assertIn(module.split(".")[0], allowed)

    def test_the_command_line_makes_its_output_utf8_safe(self):
        with open(os.path.join(FUZZ, "fuzz.py"), encoding="utf-8") as fh:
            self.assertIn("configure_stdio()", fh.read())

    def test_the_readme_names_every_target_and_the_known_finding_ids(self):
        with open(os.path.join(FUZZ, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        for name in EXPECTED_TARGETS:
            self.assertIn(name, text)
        for ident in {i for i, _ in fuzz_targets.KNOWN.values()}:
            self.assertIn(ident, text)

    def test_the_modules_have_names_no_other_script_directory_uses(self):
        names = [n for n in os.listdir(FUZZ) if n.endswith(".py") and n != "fuzz.py"]
        self.assertTrue(all(n.startswith("fuzz_") for n in names), names)


@unittest.skipUnless(os.path.exists(WORKFLOW), ".github/workflows/fuzz.yml is added by the repository owner "
                     "(the tools that wrote the rest cannot write under .github/); remove this skip once it is in")
class WorkflowTests(unittest.TestCase):
    """The rules ci.yml states, for the file that runs the long fuzz."""

    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, encoding="utf-8") as fh:
            cls.text = fh.read()

    def test_every_action_is_pinned_to_a_commit(self):
        uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)(.*)$", self.text, flags=re.M)
        self.assertGreaterEqual(len(uses), 2)
        for ref, rest in uses:
            with self.subTest(ref):
                self.assertRegex(ref, r"^[\w./-]+@[0-9a-f]{40}$")
                self.assertRegex(rest, r"#\s*v\d")

    def test_it_runs_on_a_schedule_and_by_hand_and_reads_no_pull_request(self):
        on = self.text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("schedule:", on)
        self.assertIn("workflow_dispatch:", on)
        for trigger in ("pull_request", "push:", "workflow_call", "issue_comment", "workflow_run"):
            self.assertNotIn(trigger, on)

    def test_read_only_no_secrets_no_caches_a_timeout_and_one_run_at_a_time(self):
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        body = re.sub(r"(?m)#.*$", "", self.text)
        self.assertNotIn("secrets.", body)
        self.assertNotIn("actions/cache", body)
        self.assertNotRegex(body, r"(?m)^\s+cache(-dependency-path)?:")
        self.assertNotIn("id-token", body)
        self.assertRegex(body, r"timeout-minutes:\s*\d+")
        self.assertRegex(body, r"concurrency:\n  group: \S+\n  cancel-in-progress: false")
        self.assertIn("persist-credentials: false", body)

    def test_it_runs_the_fuzzer_with_a_hard_limit_and_keeps_what_it_finds(self):
        flat = re.sub(r"\s+", " ", self.text)
        self.assertIn("scripts/fuzz/fuzz.py", flat)
        self.assertIn("--hard-limit", flat)
        self.assertIn("--pending", flat)
        self.assertIn("--findings", flat)
        self.assertIn("actions/upload-artifact@", self.text)
        self.assertIn("if: always()", self.text)


if __name__ == "__main__":
    unittest.main()
