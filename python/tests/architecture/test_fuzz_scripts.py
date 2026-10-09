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
import zlib
from unittest import mock

from lazaret.scanner import _native
from tests import _support

FUZZ = os.path.join(_support.REPO_ROOT, "scripts", "fuzz")
WORKFLOW = os.path.join(_support.REPO_ROOT, ".github", "workflows", "fuzz.yml")
if FUZZ not in sys.path:
    sys.path.insert(0, FUZZ)

fuzz_mutate = importlib.import_module("fuzz_mutate")
fuzz_targets = importlib.import_module("fuzz_targets")
driver = _support.load_script(os.path.join(FUZZ, "fuzz.py"), "fuzz_driver")

EXPECTED_TARGETS = ["archive-tgz", "archive-tbz2", "archive-txz", "archive-zip", "archive-npm-diff", "xml", "xml-minidom",
                    "sca-package-lock-json", "sca-yarn-lock", "sca-pnpm-lock-yaml", "sca-bun-lock", "sca-poetry-lock",
                    "sca-uv-lock", "sca-pylock-toml", "sca-pipfile-lock", "sca-requirements-txt", "sca-pyproject-toml",
                    "sca-setup-py", "sca-go-mod", "sca-go-sum", "sca-vendor-modules-txt", "sca-cargo-lock", "sca-cargo-toml", "sca-bundle-index", "sca-bundle-doc", "crates-index", "crates-manifest", "go-zip", "go-mod", "go-sumdb",
                    "go-sumdb-check", "provenance-npm", "go-resolve", "ecosystem-names", "ecosystem-member-path", "action-code",
                    "verify-answers", "verify-credentials", "credential-path"]


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
            # (an input that runs slowly joins the corpus, which changes what follows it: on a loaded machine a pause
            # of a few milliseconds did, and the same seed ran other inputs; here no input is slow)
            with mock.patch.object(driver, "SLOW_FLOOR", 3600.0):
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

    def test_the_npm_diff_promises(self):
        # BR-4: with the reader's check against npm's reading taken out, the archive whose prefix field starts
        # with NUL is npm's index.js and nothing the reader read; with the model of npm's reading wrong, the model
        # and npm disagree. (npm's own node-tar decides: without node and it, nothing is compared.)
        from lazaret.registry import npmtar
        run, close = fuzz_targets.TARGETS["archive-npm-diff"].start()
        self.addCleanup(close)
        prefix_case = fuzz_targets.npm_diff_seeds()[0]
        run(prefix_case)                                   # the reader calls it corrupt: no finding
        if not fuzz_targets.shutil.which("node"):
            self.skipTest("no node here")
        with mock.patch.object(npmtar, "disagreements", lambda node, read: []):
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(prefix_case)
        if raised.exception.rule != "npm-unread":
            self.fail(raised.exception)
        plain = fuzz_targets.tar_entry(b"package/a.js", b"1;\n") + b"\0" * 1024
        with mock.patch.object(npmtar, "written_path", lambda path: "elsewhere.js"):
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(plain)
        self.assertEqual(raised.exception.rule, "npm-model")

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

    def sca_passes(self, answer):
        from lazaret.scanner import sca

        def scan_all(root, extra_site_packages=None, warn=None):
            return answer
        run, close = fuzz_targets.TARGETS["sca-yarn-lock"].start()
        self.addCleanup(close)
        with mock.patch.object(sca, "scan_all", scan_all):
            run(b"x")

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
        for eco in ("go", "crates"):
            self.sca_passes(inv((eco, "a.example/x", "", "w")))                                   # (a version is optional)
        self.assertEqual(self.sca(inv(("go", "stdlib", "v1.0.0", "go.mod"))), "sca-go-name")
        self.assertEqual(self.sca(inv(("go", "std/a.b", "v1.0.0", "go.mod"))), "sca-go-name")
        self.assertEqual(self.sca(inv(("go", "a.example/x", "1.0.0", "go.mod"))), "sca-go-version")
        self.assertEqual(self.sca(inv(("go", "a.example/x", "latest", "go.mod"))), "sca-go-version")
        self.sca_passes(inv(("go", "a.example/x", "v1.2.3+incompatible", "go.mod")))
        self.sca_passes(inv(("go", "a.example/x", "v1", "go.mod")))                               # (any SemVer the inventory could read)
        self.sca_passes(inv(("crates", "serde", "1.0.152", "Cargo.lock")))
        self.sca_passes(inv(("crates", "serde", "anything the lock said", "Cargo.lock")))
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


class RegistryModulePromisesAreLive(unittest.TestCase):
    """The same for the targets of the registry modules (crates.io and Go): each promise is broken by a reader that breaks it."""

    def promise(self, target, data, *patches):
        run, close = fuzz_targets.TARGETS[target].start()
        self.addCleanup(close)
        with contextlib.ExitStack() as stack:
            for owner, attr, value in patches:
                stack.enter_context(mock.patch.object(owner, attr, value))
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(data)
        return raised.exception.rule

    @staticmethod
    def padded(seed, wanted, pad=b"\n"):
        """`seed` with enough `pad` after it for `wanted(crc32)` to hold: the targets choose what to ask by the bytes."""
        data = seed
        while not wanted(zlib.crc32(data)):
            data += pad
        return data

    @staticmethod
    def altered(res, version=None, art=None, info=None):
        from lazaret.registry.ecosystems import base
        return base.Resolution(res[0] if version is None else version, [dict(res.artifacts[0], **(art or {}))], res.skipped,
                               dict(res.info, **(info or {})))

    @staticmethod
    def every_other(first, second):
        """A function that gives `first` the first time and `second` the next, and so on."""
        calls = []

        def answer(*args, **kw):
            calls.append(1)
            return first(*args, **kw) if len(calls) % 2 else second(*args, **kw)
        return answer

    def test_the_crates_index_promises(self):
        from lazaret.registry.ecosystems import base, crates
        eco = crates.Crates()
        real = crates.Crates.resolve
        latest = self.padded(fuzz_targets.CRATES_INDEX_SEEDS[1], lambda c: c % 5 == 0)
        asked = self.padded(fuzz_targets.CRATES_INDEX_SEEDS[1], lambda c: c % 5 == 1)

        def resolve_once(data):
            fetch, _ = fuzz_targets.served(eco, lambda url: data)
            return real(eco, "fnv", None, fetch)
        res = resolve_once(latest)
        art = res.artifacts[0]
        entry = art["entry"]

        def tweak(change):
            return lambda self, name, version, fetch: change(real(self, name, version, fetch))

        def fixed(value):
            return lambda self, name, version, fetch: value

        def failing(self, name, version, fetch):
            raise base.FetchError("x" * 700)

        def asking_twice(self, name, version, fetch):
            fetch.bytes("https://index.crates.io/3/f/fnv")
            return real(self, name, version, fetch)
        run = lambda data, *patches: self.promise("crates-index", data, *patches)        # noqa: E731
        R = lambda attr, value: (crates.Crates, attr, value)                              # noqa: E731
        self.assertEqual(run(latest, R("resolve", failing)), "crates-index-message")
        self.assertEqual(run(latest, R("resolve", fixed(res))), "crates-index-requests")
        self.assertEqual(run(latest, R("resolve", asking_twice)), "crates-index-requests")
        self.assertEqual(run(latest, R("resolve", tweak(tuple))), "crates-index-shape")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, art={"url": "http://evil.example/x.crate"})))), "crates-index-url")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, art={"container": "zip"})))), "crates-index-artifact")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, version="1.0")))), "crates-index-version")
        self.assertEqual(run(asked, R("resolve", tweak(lambda r: self.altered(r, version="1.0.8")))), "crates-index-asked-for")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, art={"entry": dict(entry, cksum="A" * 64)})))), "crates-index-cksum")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, art={"entry": dict(entry, yanked="no")})))), "crates-index-yanked")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, info={"yanked": True})))), "crates-index-yanked")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, art={"entry": dict(entry, yanked=True)}, info={"yanked": True})))),
                         "crates-index-latest-yanked")
        self.assertEqual(run(latest, R("resolve", tweak(lambda r: self.altered(r, info={"name": "other"})))), "crates-index-name")
        self.assertEqual(run(latest, R("archive_root", lambda self, r, a: "wrong/")), "crates-index-root")
        self.assertEqual(run(latest, R("dependencies", lambda self, r, fetch: ("b", "a"))), "crates-index-dependencies")
        self.assertEqual(run(latest, R("dependencies", lambda self, r, fetch: ["a"])), "crates-index-dependencies")
        self.assertEqual(run(latest, R("dependencies", lambda self, r, fetch: fetch.bytes("https://index.crates.io/3/f/fnv") and ())),
                         "crates-index-dependencies-asked")
        self.assertEqual(run(latest, R("verify", lambda self, data, entry, name, version: ("sha256", "0" * 64))), "crates-index-verify")
        self.assertEqual(run(latest, R("resolve", self.every_other(real, tweak(lambda r: self.altered(r, info={"links": "x"}))))),
                         "crates-index-deterministic")

    def test_the_crates_manifest_promises(self):
        from lazaret.registry.ecosystems import base, crates
        seed = fuzz_targets.CARGO_SEEDS[1]
        run_real, declared_real = crates.Crates.run_targets, crates.Crates.declared
        run = lambda *patches: self.promise("crates-manifest", seed, *patches)           # noqa: E731
        R = lambda attr, value: (crates.Crates, attr, value)                              # noqa: E731
        members = fuzz_targets.CARGO_MEMBERS
        self.assertEqual(run(R("run_targets", lambda self, k, m, mem: ())), "crates-manifest-run-type")
        self.assertEqual(run(R("run_targets", lambda self, k, m, mem: base.RunTargets(entries={"zzz.rs"}))), "crates-manifest-run-members")
        self.assertEqual(run(R("run_targets", lambda self, k, m, mem: base.RunTargets(startup={members[1]}))), "crates-manifest-startup")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: ("demo", ()))), "crates-manifest-declared-type")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: base.Declared("-bad", ()))), "crates-manifest-name")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: base.Declared(None, ("b", "a")))), "crates-manifest-dependencies")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: base.Declared(None, ("a b",)))), "crates-manifest-dependencies")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: base.Declared(None, ("a",), {"a": "1" * (crates.MAX_SPEC + 1)}))),
                         "crates-manifest-specs")
        self.assertEqual(run(R("declared", lambda self, k, m, mem: base.Declared(None, ("a",), {"a": "1"}, {"a": "a b"}))),
                         "crates-manifest-aliases")
        self.assertEqual(run(R("declared", self.every_other(declared_real, lambda self, k, m, mem: base.Declared("other", ())))),
                         "crates-manifest-deterministic")
        self.assertEqual(run(R("run_targets", self.every_other(run_real, lambda self, k, m, mem: base.RunTargets(entries={members[1]})))),
                         "crates-manifest-deterministic")

    def test_the_go_zip_promises(self):
        from lazaret.registry.ecosystems import base, golang
        seeds = fuzz_targets.go_zip_seeds()
        module, odd = seeds[0], seeds[2]
        real = golang.zip_h1
        other = "h1:" + "B" * 43 + "="
        run = lambda data, *patches: self.promise("go-zip", data, *patches)               # noqa: E731

        def failing(data):
            raise base.DigestError("x" * 700)
        self.assertEqual(run(module, (golang, "zip_h1", failing)), "go-zip-message")
        self.assertEqual(run(module, (golang, "zip_h1", lambda data: "h1:short")), "go-zip-format")
        self.assertEqual(run(module, (golang, "zip_h1", lambda data: None)), "go-zip-format")
        self.assertEqual(run(module, (golang, "zip_h1", self.every_other(real, lambda data: other))), "go-zip-deterministic")
        self.assertEqual(run(odd, (golang, "zip_h1", lambda data: other)), "go-zip-names")             # (a hash for a zip with two members of one name)
        self.assertEqual(run(module, (golang.Go, "verify", lambda self, data, entry, name, version: ("h1", "wrong"))), "go-zip-verify")
        self.assertEqual(run(module, (golang.Go, "verify", lambda self, data, entry, name, version: ("h1", entry["h1"][3:]))),
                         "go-zip-wrong-hash-accepted")

    def test_the_go_mod_promises(self):
        from lazaret.registry.ecosystems import base, golang
        seed = fuzz_targets.GOMOD_SEEDS[0]
        real = golang.parse_gomod
        run = lambda *patches: self.promise("go-mod", seed, *patches)                     # noqa: E731
        P = lambda value: (golang, "parse_gomod", lambda text: value)                     # noqa: E731
        G = lambda attr, value: (golang.Go, attr, value)                                  # noqa: E731
        ok = {"module": "example.com/m", "go": "1.22", "require": []}
        self.assertEqual(run(P([])), "go-mod-shape")
        self.assertEqual(run(P({"module": None})), "go-mod-shape")
        self.assertEqual(run(P(dict(ok, module=5))), "go-mod-module")
        self.assertEqual(run(P(dict(ok, go=5))), "go-mod-go")
        self.assertEqual(run(P(dict(ok, require=[("a.example/x", "v1.0.0", False)] * 1000))), "go-mod-count")
        self.assertEqual(run(P(dict(ok, require=[("a.example/x",)]))), "go-mod-requirement-shape")
        self.assertEqual(run(P(dict(ok, require=[("a.example/x", "v1.0.0", "no")]))), "go-mod-requirement-shape")
        self.assertEqual(run(P(dict(ok, require=[("a.example/x", "v1", False)]))), "go-mod-requirement-version")
        self.assertEqual(run(P(dict(ok, require=[("a.example/x", "", False)]))), "go-mod-requirement-version")
        self.assertEqual(run((golang, "parse_gomod", self.every_other(real, lambda text: dict(ok)))), "go-mod-deterministic")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared("-x", ()))), "go-mod-declared-name")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared(None, ("b.example/y", "a.example/x")))), "go-mod-declared-dependencies")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared(None, ("zz.example/q",)))), "go-mod-declared-from-requirements")
        names = ("a.example/x", "b.example/y", "c.example/z")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared(None, names, {n: "v9.9.9" for n in names}))), "go-mod-declared-specs")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared(None, names, {"a.example/x": "v1.0.0", "b.example/y": "v1.2.3"}))),
                         "go-mod-declared-specs")
        self.assertEqual(run(G("declared", lambda self, k, m, mem: base.Declared(
            None, names, {"a.example/x": "v1.0.0", "b.example/y": "v1.2.3", "c.example/z": "v0.1.0"}, {"a.example/x": "x"}))), "go-mod-declared-specs")

    def test_the_go_sumdb_promises(self):
        from lazaret.registry.ecosystems import base, golang
        seed = fuzz_targets.SUMDB_SEEDS[0]
        real = golang.parse_lookup
        good = real(seed.decode("utf-8"), fuzz_targets.SUMDB_NAME, fuzz_targets.SUMDB_VERSION)
        run = lambda *patches: self.promise("go-sumdb", seed, *patches)                   # noqa: E731
        P = lambda value: (golang, "parse_lookup", lambda text, name, version: value)     # noqa: E731
        elsewhere = "h1:" + "Z" * 43 + "="

        def failing(text, name, version):
            raise base.FetchError("x" * 700)
        self.assertEqual(run((golang, "parse_lookup", failing)), "go-sumdb-message")
        self.assertEqual(run(P({})), "go-sumdb-shape")
        self.assertEqual(run(P(dict(good, id=8))), "go-sumdb-id")
        self.assertEqual(run(P(dict(good, id=True))), "go-sumdb-id")
        self.assertEqual(run(P(dict(good, h1="bad"))), "go-sumdb-h1")
        self.assertEqual(run(P(dict(good, gomod_h1="bad"))), "go-sumdb-gomod-h1")
        self.assertEqual(run(P(dict(good, h1=elsewhere))), "go-sumdb-h1-from-the-record")
        self.assertEqual(run(P(dict(good, gomod_h1=elsewhere))), "go-sumdb-gomod-from-the-record")
        self.assertEqual(run((golang, "parse_lookup", self.every_other(real, lambda text, name, version: dict(good, h1=elsewhere)))),
                         "go-sumdb-deterministic")

    @unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
    def test_the_go_sumdb_check_promises(self):
        from lazaret.registry.ecosystems import base, golang
        seeds = fuzz_targets.check_seeds()
        real, changed = seeds[0], seeds[1]
        run = lambda data, *patches: self.promise("go-sumdb-check", data, *patches)      # noqa: E731
        V = lambda value: (golang, "verify_lookup", value)                                 # noqa: E731

        def failing(*args):
            raise base.FetchError("x" * 700)
        self.assertEqual(run(real, V(failing)), "go-sumdb-check-message")
        self.assertEqual(run(real, V(lambda *args: None)), "go-sumdb-check-checked")
        self.assertEqual(run(changed, V(lambda *args: True)), "go-sumdb-check-only-what-was-signed")
        elsewhere = lambda tile, fetch: fetch.bytes("https://sum.golang.org/lookup/x.example/m@v1.0.0")    # noqa: E731
        self.assertEqual(run(real, (golang, "_fetch_tile", elsewhere)), "go-sumdb-check-requests")
        def refused(*args):
            raise base.FetchError("go: refused")
        self.assertEqual(run(real, V(self.every_other(golang.verify_lookup, refused))), "go-sumdb-check-deterministic")

    @unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
    def test_the_provenance_promises(self):
        from lazaret.registry import provenance
        real = fuzz_targets.provenance_seeds()[0]
        run = lambda data, *patches: self.promise("provenance-npm", data, *patches)        # noqa: E731
        V = lambda value: (provenance, "verify", value)                                     # noqa: E731

        def unchecked(*args):
            raise provenance.Unchecked("x" * 300)
        self.assertEqual(run(real, V(unchecked)), "provenance-message")
        self.assertEqual(run(real, V(lambda *args: [{"outcome": "maybe", "predicateType": "p"}])), "provenance-shape")
        self.assertEqual(run(real, V(lambda *args: [{"outcome": "verified", "predicateType": "p",
                                                     "signer": {"kind": "certificate", "repository": "https://github.com/evil/x"}}])),
                         "provenance-only-who-signed")
        self.assertEqual(run(real, V(lambda *args: [{"outcome": "verified", "predicateType": "p",
                                                     "signer": {"kind": "key", "id": "SHA256:other"}}])),
                         "provenance-only-who-signed")
        calls = []

        def every_other(*args):
            calls.append(1)
            return [] if len(calls) % 2 else [{"outcome": "unchecked", "predicateType": "p", "reason": "r"}]
        self.assertEqual(run(real, V(every_other)), "provenance-deterministic")

    def test_the_action_code_promises(self):
        from lazaret.registry import repo
        real = fuzz_targets.ACTION_SEEDS[0]
        run = lambda data, *patches: self.promise("action-code", data, *patches)            # noqa: E731
        scan = repo.scan_action

        def changed(**fields):
            def answer(*args, **kw):
                res = scan(*args, **kw)
                for key, value in fields.items():
                    if key in ("runs", "missing", "bases"):
                        res["action"] = dict(res["action"] or {"runs": {}, "missing": [], "bases": []}, **{key: value})
                    else:
                        res[key] = value
                return res
            return (repo, "scan_action", answer)
        self.assertEqual(run(real, changed(verdict="FINE")), "action-code-shape")
        self.assertEqual(run(real, changed(runs={"runs.main": "elsewhere.js"})), "action-code-runs-the-archives-files")
        self.assertEqual(run(real, changed(bases=[("Dockerfile", 1, "alpine:3", True)])), "action-code-bases")
        self.assertEqual(run(real, changed(issues=[{"rule": "SC-X", "sev": "SEVERE", "msg": "m", "file": "f", "line": 1}])),
                         "action-code-issues")
        self.assertEqual(run(real, (repo, "scan_action", self.every_other(scan, lambda *a, **k: dict(
            scan(*a, **k), issues=[{"rule": "SC-X", "sev": "MAJOR", "msg": "m", "file": "f", "line": 1}])))),
            "action-code-deterministic")

    @mock.patch("lazaret.registry.ecosystems.golang.verify_lookup", new=lambda name, version, lookup, record, fetch: None)
    def test_the_go_resolve_promises(self):
        from lazaret.registry.ecosystems import base, golang
        eco = golang.Go()
        real = golang.Go.resolve
        seed = fuzz_targets.INFO_SEEDS[0]
        latest = self.padded(seed, lambda c: c % 4 == 0 and (c >> 8) % 5 == 0, b" ")
        asked = self.padded(seed, lambda c: c % 4 == 0 and (c >> 8) % 5 == 1, b" ")

        def sumdb_for(url):
            module, _, version = url.rsplit("/lookup/", 1)[1].partition("@")
            return fuzz_targets.sumdb_text(module, version).encode("utf-8")
        fetch, _ = fuzz_targets.served(eco, lambda url: sumdb_for(url) if "/lookup/" in url else latest)
        res = real(eco, "example.com/m", None, fetch)
        entry = res.artifacts[0]["entry"]

        def tweak(change):
            return lambda self, name, version, fetch: change(real(self, name, version, fetch))

        def failing(self, name, version, fetch):
            raise base.FetchError("x" * 700)
        run = lambda data, *patches: self.promise("go-resolve", data, *patches)           # noqa: E731
        R = lambda value: (golang.Go, "resolve", value)                                   # noqa: E731
        self.assertEqual(run(latest, R(failing)), "go-resolve-message")
        self.assertEqual(run(latest, R(lambda self, name, version, fetch: res)), "go-resolve-requests")
        self.assertEqual(run(latest, R(tweak(tuple))), "go-resolve-shape")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, version="1.0")))), "go-resolve-version")
        self.assertEqual(run(asked, R(tweak(lambda r: self.altered(r, version="v9.9.9")))), "go-resolve-asked-for")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, art={"url": "http://proxy.golang.org/x.zip"})))), "go-resolve-url")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, art={"container": "tgz"})))), "go-resolve-artifact")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, art={"entry": dict(entry, h1="bad")})))), "go-resolve-h1")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, info={"root": "wrong/"})))), "go-resolve-root")
        self.assertEqual(run(latest, R(tweak(lambda r: self.altered(r, info={"time": "x" * 100})))), "go-resolve-time")
        self.assertEqual(run(latest, R(self.every_other(real, tweak(lambda r: self.altered(r, info={"time": None}))))), "go-resolve-deterministic")

    def test_the_names_promises(self):
        from lazaret.registry.ecosystems import base, golang
        Go = golang.Go
        run = lambda seed, *patches: self.promise("ecosystem-names", seed, *patches)       # noqa: E731
        G = lambda attr, value: (Go, attr, value)                                          # noqa: E731
        name, refused = b"github.com/pkg/errors\nv0.9.1", b"x/y\n1"

        def failing(self, value):
            raise base.SpecError("x" * 700)
        self.assertEqual(run(name, G("check_name", failing)), "names-message")
        self.assertEqual(run(refused, G("identity", lambda self, value: value)), "names-refusal-consistent")
        self.assertEqual(run(name, G("check_name", lambda self, value: value + "x")), "names-idempotent")
        self.assertEqual(run(name, G("identity", lambda self, value: value + "x")), "names-identity-idempotent")
        self.assertEqual(run(name, G("segment", lambda self, value: "a b")), "names-segment")
        self.assertEqual(run(name, G("segment", lambda self, value: "../x")), "names-segment")
        self.assertEqual(run(name, G("segment", lambda self, value: "a?b=1")), "names-segment")
        self.assertEqual(run(name, G("check_version", lambda self, value: None if value is None else value + "x")), "names-version-idempotent")
        self.assertEqual(run(name, G("segment", lambda self, value: "a b" if value.startswith("v") else value)), "names-version-segment")
        self.assertEqual(run(name, G("parse_spec", lambda self, value: ("x", "y"))), "names-spec")
        self.assertEqual(run(name, G("check_version", lambda self, value: failing(self, value))), "names-message")

    def test_the_member_path_promises(self):
        from lazaret.registry.ecosystems import crates, golang
        run = lambda seed, *patches: self.promise("ecosystem-member-path", seed, *patches)    # noqa: E731
        G = lambda attr, value: (golang.Go, attr, value)                                      # noqa: E731
        C = lambda attr, value: (crates.Crates, attr, value)                                  # noqa: E731
        seed = fuzz_targets.MEMBER_SEEDS[1]
        M = lambda result: G("member_path", lambda self, kind, name, root=None: result)       # noqa: E731
        self.assertEqual(run(seed, M((5, None))), "member-rel-type")
        self.assertEqual(run(seed, M((None, 5))), "member-problem-type")
        self.assertEqual(run(seed, M(("a", "problem"))), "member-rel-and-problem")
        self.assertEqual(run(seed, M((None, "x" * 700))), "member-problem-message")
        for bad in ("", ".", "/abs", "../x", "a/../b", "a\\b", "a//b"):
            self.assertEqual(run(seed, M((bad, None))), "member-rel-path", bad)
        self.assertEqual(run(seed, C("member_path", lambda self, kind, name, root=None: ("a/.cargo-ok", None))), "member-crates-marker")
        self.assertEqual(run(seed, M(("sub/go.mod", None))), "member-go-mod-only-at-the-root")
        self.assertEqual(run(seed, M(("sub/GO.MOD", None))), "member-go-mod-only-at-the-root")
        self.assertEqual(run(b"other/x\nexample.com/m@v1.0.0/", M(("x", None))), "member-under-the-root")
        real = golang.Go.member_path
        self.assertEqual(run(seed, G("member_path", self.every_other(real, lambda self, kind, name, root=None: ("x", None)))),
                         "member-deterministic")


class VerificationPromisesAreLive(unittest.TestCase):
    """The same for the two targets of live secret verification (V-1): each promise is broken by a reader that breaks it."""

    def promise(self, target, data, *patches):
        run, close = fuzz_targets.TARGETS[target].start()
        self.addCleanup(close)
        with contextlib.ExitStack() as stack:
            for owner, attr, value in patches:
                stack.enter_context(mock.patch.object(owner, attr, value))
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(data)
        return raised.exception.rule

    def test_the_answer_promises(self):
        from lazaret.scanner import secretverify as sv
        run = lambda seed, interpret: self.promise("verify-answers", seed, (sv, "interpret", interpret))       # noqa: E731
        github_401 = fuzz_targets.verify_answer(0, 401, b"")
        github_500 = fuzz_targets.verify_answer(0, 500, b"")
        slack_cut = fuzz_targets.verify_answer(1, 200, b'{"ok": true}', truncated=True)
        self.assertEqual(run(github_401, lambda p, r, s=(): ("maybe", "x", None)), "verify-outcome")
        for detail in ("", "a\nb", "x" * 201, 5, None):
            self.assertEqual(run(github_401, lambda p, r, s=(), d=detail: ("unknown", d, None)), "verify-detail")
        for who in ("", "a\x1b[0m", "x" * (sv.MAX_WHO + 1), 5):
            self.assertEqual(run(github_401, lambda p, r, s=(), w=who: ("unknown", "x", w)), "verify-who")
        self.assertEqual(run(github_401, lambda p, r, s=(): ("unknown", "secret " + s[0], None)), "verify-leak")
        self.assertEqual(run(github_401, lambda p, r, s=(): ("unknown", "x", "who " + s[0])), "verify-leak")
        self.assertEqual(run(github_500, lambda p, r, s=(): ("rejected", "x", None)), "verify-outcome-needs-a-rule")
        self.assertEqual(run(github_500, lambda p, r, s=(): ("live", "x", None)), "verify-outcome-needs-a-rule")
        self.assertEqual(run(slack_cut, lambda p, r, s=(): ("live", "x", None)), "verify-truncated-needs-no-body")
        real = sv.interpret
        calls = []

        def alternating(provider, response, secrets=()):
            calls.append(1)
            return real(provider, response, secrets) if len(calls) % 2 else ("unknown", "other", None)
        self.assertEqual(run(github_401, alternating), "verify-deterministic")

    def test_the_verifier_has_to_agree_with_the_reader(self):
        from lazaret.scanner import secretverify as sv
        original = sv.Verifier.verify
        seed = fuzz_targets.verify_answer(0, 401, b"")
        wrong = lambda self, pid, credential: sv.Result(pid, "live", "x", None, 401)                          # noqa: E731
        self.assertEqual(self.promise("verify-answers", seed, (sv.Verifier, "verify", wrong)), "verify-verifier-agrees")
        leaking = lambda self, pid, credential: original(self, pid, credential)._replace(detail="ghp_" + "a1B2" * 9)   # noqa: E731
        self.assertEqual(self.promise("verify-answers", seed, (sv.Verifier, "verify", leaking)), "verify-leak")

    def test_the_credential_promises(self):
        from lazaret.scanner import secretverify as sv
        from lazaret.scanner import secretverify_http as http
        good = fuzz_targets.VERIFY_CREDENTIAL_SEEDS[0]
        short = b"github\nghp_short"
        aws = fuzz_targets.VERIFY_CREDENTIAL_SEEDS[10]
        run = lambda seed, *patches: self.promise("verify-credentials", seed, *patches)                       # noqa: E731
        original_verify, original_build = sv.Verifier.verify, sv.build_request

        def lax(provider, parts, now):                    # (the format not held: the engine asked with patterns that take any text)
            return original_build(dict(provider, parts={name: "[\\s\\S]+" for name in provider["parts"]}), parts, now)

        def refusing(provider, parts, now):
            raise ValueError(sv.NOT_THIS_FORMAT)
        self.assertEqual(run(short, (sv, "build_request", lax)), "verify-sent-a-credential-that-is-not-the-providers")
        for seed in (good, aws):
            self.assertEqual(run(seed, (sv.Verifier, "_parts", staticmethod(lambda credential: None))), "verify-wrongly-refused")
            self.assertEqual(run(seed, (sv, "build_request", refusing)), "verify-wrongly-refused")
        invented = lambda self, pid, credential: sv.Result(pid, "live", "x", None, 200)                       # noqa: E731
        self.assertEqual(run(short, (sv.Verifier, "verify", invented)), "verify-refused-is-unknown")

        def twice(self, pid, credential):
            original_verify(self, pid, credential)
            self._cache.clear()
            return original_verify(self, pid, credential)
        self.assertEqual(run(good, (sv.Verifier, "verify", twice)), "verify-one-call")

        def built(change):
            def build(provider, parts, now):
                request = original_build(provider, parts, now)
                return change(request, parts)
            return (sv, "build_request", build)
        self.assertEqual(run(good, built(lambda r, p: r._replace(headers=dict(r.headers, X="a\r\nX-Evil: 1")))), "verify-header-injection")
        self.assertEqual(run(good, built(lambda r, p: r._replace(host="Evil Host"))), "verify-request-sendable")
        self.assertEqual(run(good, built(lambda r, p: r._replace(host="evil.example.com"))), "verify-host")
        self.assertEqual(run(good, built(lambda r, p: r._replace(path="/user/" + p["secret"]))), "verify-secret-in-url")
        self.assertEqual(run(good, built(lambda r, p: r._replace(path=r.path + "?t=" + p["secret"]))), "verify-secret-in-url")
        self.assertEqual(run(good, (sv, "interpret", lambda p, r, s=(): ("bogus", "x", None))), "verify-answer-passed-through")
        self.assertEqual(run(good, (sv, "interpret", lambda p, r, s=(): ("rejected", s[0], None))), "verify-leak")


class CredentialPathPromisesAreLive(unittest.TestCase):
    """The same for the credential of a URL's path (decision 14, the credentials review): each promise is broken by a
    reader that breaks it."""

    def promise(self, data, *patches):
        run, close = fuzz_targets.TARGETS["credential-path"].start()
        self.addCleanup(close)
        with contextlib.ExitStack() as stack:
            for owner, attr, value in patches:
                stack.enter_context(mock.patch.object(owner, attr, value))
            with self.assertRaises(fuzz_targets.Violation) as raised:
                run(data)
        return raised.exception.rule

    def test_the_promises(self):
        from lazaret.registry import pmsettings as pm
        real_normal, real_header = pm.normal_path, pm.Credentials.header
        N = lambda value: (pm, "normal_path", value)                                       # noqa: E731
        self.assertEqual(self.promise(b"/a/b", N(lambda p: "a\\b")), "normal-path-shape")
        self.assertEqual(self.promise(b"/a/b", N(lambda p: "/a/../b")), "normal-path-dots")
        self.assertEqual(self.promise(b"/a/b", N(lambda p: "/x" + real_normal(p))), "normal-path-idempotent")
        self.assertEqual(self.promise(b"/team/x", (pm.Credentials, "header", lambda self, url: None)), "credential-choice")
        self.assertEqual(self.promise(b"/team/../x", (pm.Credentials, "header", lambda self, url: "Bearer T/team/")),
                         "credential-choice")
        calls = []

        def alternating(self, url):
            calls.append(1)
            return real_header(self, url) if len(calls) % 2 else None
        self.assertEqual(self.promise(b"/team/x", (pm.Credentials, "header", alternating)), "credential-deterministic")

    def test_the_seeds_keep_the_promises(self):
        run, close = fuzz_targets.TARGETS["credential-path"].start()
        self.addCleanup(close)
        for seed in fuzz_targets.CREDENTIAL_PATH_SEEDS:
            run(seed)


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
                   "platform", "random", "re", "shutil", "subprocess", "sys", "tarfile", "tempfile", "time",
                   "traceback", "warnings",
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
