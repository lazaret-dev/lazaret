"""`lazaret.scanner.timings` (0.1.9, P-4): where a run's time goes.

A clock the test moves makes every number exact: spans nest and give their own seconds only,
threads and worker reports add up as documented, `other` is what the owner thread did outside
a span, a name built from input cannot grow a phase without end, and nothing is recorded (or
paid for beyond one read) when no capture is open."""

import json
import threading
import unittest

from lazaret.scanner import timings
from lazaret.scanner.timings import Timings


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now += seconds


class Basics(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.t = Timings(self.clock)

    def test_a_span_gives_its_seconds_and_a_call(self):
        with self.t.span("network", "fetch"):
            self.clock.tick(2.5)
        row = self.t.report()["phases"]["network"]
        self.assertEqual((row["seconds"], row["calls"]), (2.5, 1))
        self.assertEqual(row["by"], {"fetch": {"seconds": 2.5, "calls": 1}})

    def test_calls_and_seconds_add_up(self):
        for _ in range(3):
            with self.t.span("engine", "scan_file"):
                self.clock.tick(0.5)
        with self.t.span("engine", "agent_hijack"):
            self.clock.tick(1)
        row = self.t.report()["phases"]["engine"]
        self.assertEqual((row["seconds"], row["calls"]), (2.5, 4))
        self.assertEqual(row["by"]["scan_file"], {"seconds": 1.5, "calls": 3})

    def test_a_span_without_a_name_has_no_names(self):
        with self.t.span("archive"):
            self.clock.tick(1)
        self.assertEqual(self.t.report()["phases"]["archive"]["by"], {})

    def test_nested_spans_are_exclusive(self):
        with self.t.span("scan", "artifact"):
            self.clock.tick(1)
            with self.t.span("engine", "scan_file"):
                self.clock.tick(4)
                with self.t.span("archive"):
                    self.clock.tick(0.5)
            self.clock.tick(2)
        phases = self.t.report()["phases"]
        self.assertEqual(phases["scan"]["seconds"], 3)          # 1 + 2, not 7.5
        self.assertEqual(phases["engine"]["seconds"], 4)        # not 4.5
        self.assertEqual(phases["archive"]["seconds"], 0.5)
        self.assertEqual(sum(p["seconds"] for p in phases.values()), 7.5)

    def test_the_same_phase_nested_is_not_counted_twice(self):
        with self.t.span("network", "outer"):
            self.clock.tick(1)
            with self.t.span("network", "inner"):
                self.clock.tick(2)
        row = self.t.report()["phases"]["network"]
        self.assertEqual(row["seconds"], 3)
        self.assertEqual((row["by"]["outer"]["seconds"], row["by"]["inner"]["seconds"]), (1, 2))

    def test_an_exception_still_closes_the_span(self):
        with self.assertRaises(ValueError):
            with self.t.span("network"):
                self.clock.tick(1)
                raise ValueError
        self.assertEqual(self.t.report()["phases"]["network"]["seconds"], 1)
        with self.t.span("engine"):                             # and the stack is clean
            self.clock.tick(1)
        self.assertEqual(self.t.report()["other"], 0)

    def test_add_takes_seconds_measured_elsewhere(self):
        self.t.add("network", 0.25, "connect", calls=5)
        self.t.add("network", -3, "connect")                    # never negative
        row = self.t.report()["phases"]["network"]
        self.assertEqual((row["seconds"], row["calls"]), (0.25, 6))

    def test_seconds_added_are_not_the_owners(self):
        with self.t.run():
            self.clock.tick(5)
            self.t.add("network", 2, "connect")
        self.assertEqual(self.t.report()["other"], 5)

    def test_spans_closed_out_of_order_do_not_break_the_stack(self):
        a, b = self.t.span("x"), self.t.span("y")
        a.__enter__()
        b.__enter__()
        self.clock.tick(1)
        a.__exit__(None, None, None)                            # the outer one first
        b.__exit__(None, None, None)
        self.assertEqual(self.t._stack(), [])                   # nothing is left on the stack
        with self.t.span("z"):
            self.clock.tick(1)
        self.assertEqual(self.t.report()["phases"]["z"]["seconds"], 1)


class Wall(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.t = Timings(self.clock)

    def test_other_is_the_wall_less_the_spans(self):
        with self.t.run():
            self.clock.tick(1)                                  # python, in no span
            with self.t.span("network"):
                self.clock.tick(3)
            self.clock.tick(2)
            with self.t.span("engine"):
                self.clock.tick(4)
        report = self.t.report()
        self.assertEqual((report["wall"], report["other"]), (10, 3))

    def test_a_run_still_open_counts_to_now(self):
        self.t.start()
        self.clock.tick(5)
        self.assertEqual(self.t.report()["wall"], 5)
        self.clock.tick(1)
        self.t.stop()
        self.t.stop()                                           # twice is once
        self.assertEqual(self.t.report()["wall"], 6)

    def test_starting_twice_keeps_the_first_start(self):
        self.t.start()
        self.clock.tick(2)
        self.t.start()
        self.clock.tick(3)
        self.t.stop()
        self.assertEqual(self.t.report()["wall"], 5)

    def test_runs_add_up(self):
        for _ in range(2):
            with self.t.run():
                self.clock.tick(2)
            self.clock.tick(10)                                 # between runs: not counted
        self.assertEqual(self.t.report()["wall"], 4)

    def test_other_is_never_negative(self):
        with self.t.span("network"):
            self.clock.tick(1)
        self.assertEqual(self.t.report()["other"], 0)           # no wall was taken


class Threads(unittest.TestCase):
    def test_each_thread_nests_on_its_own_and_phases_add_up(self):
        clock = Clock()
        t = Timings(clock)
        with t.run():
            def work():
                with t.span("engine", "scan_file"):
                    clock.tick(2)
            for _ in range(3):                                  # one after another: exact, and each its own thread
                th = threading.Thread(target=work)
                th.start()
                th.join()
            with t.span("network"):
                clock.tick(1)
        report = t.report()
        self.assertEqual(report["phases"]["engine"]["seconds"], 6)
        self.assertEqual(report["wall"], 7)
        # the engine ran on other threads, so it is not subtracted from what the owner left over
        self.assertEqual(report["other"], 6)

    def test_what_another_thread_did_meanwhile_stays_in_the_waiting_span(self):
        clock = Clock()
        t = Timings(clock)

        def work():
            with t.span("engine"):
                clock.tick(3)
        with t.span("scan"):                                    # the owner waits for the worker
            clock.tick(1)
            th = threading.Thread(target=work)
            th.start()
            th.join()
            clock.tick(1)
        phases = t.report()["phases"]
        self.assertEqual((phases["scan"]["seconds"], phases["engine"]["seconds"]), (5, 3))

    def test_many_threads_at_once_lose_nothing(self):
        t = Timings()                                           # the real clock: only the counts are checked
        barrier = threading.Barrier(8)

        def work():
            barrier.wait()
            for _ in range(500):
                with t.span("engine", "call"):
                    pass
        threads = [threading.Thread(target=work) for _ in range(8)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        row = t.report()["phases"]["engine"]
        self.assertEqual((row["calls"], row["by"]["call"]["calls"]), (4000, 4000))


class Merge(unittest.TestCase):
    def test_a_workers_report_is_added_not_its_wall(self):
        clock = Clock()
        worker = Timings(clock)
        with worker.run():
            with worker.span("engine", "scan_file"):
                clock.tick(2)
            with worker.span("archive"):
                clock.tick(1)
            clock.tick(1)
        report = worker.report()
        parent = Timings(clock)
        with parent.run():
            parent.merge(report)
            parent.merge(report)
            clock.tick(5)
        out = parent.report()
        self.assertEqual(out["wall"], 5)
        self.assertEqual(out["phases"]["engine"], {"seconds": 4, "calls": 2, "by": {"scan_file": {"seconds": 4, "calls": 2}}})
        self.assertEqual(out["phases"]["archive"]["seconds"], 2)
        self.assertEqual(out["other"], 5)                       # the worker's seconds are not the owner's

    def test_a_report_through_json_merges_the_same(self):
        clock = Clock()
        worker = Timings(clock)
        with worker.span("network", "fetch"):
            clock.tick(1.25)
        parent = Timings(clock)
        parent.merge(json.loads(json.dumps(worker.report())))
        self.assertEqual(parent.report()["phases"], worker.report()["phases"])

    def test_seconds_of_a_phase_beyond_its_names_are_kept(self):
        parent = Timings(Clock())
        parent.merge({"phases": {"engine": {"seconds": 5, "calls": 10, "by": {"a": {"seconds": 2, "calls": 4}}}}})
        row = parent.report()["phases"]["engine"]
        self.assertEqual((row["seconds"], row["calls"], row["by"]), (5, 10, {"a": {"seconds": 2, "calls": 4}}))

    def test_seconds_beyond_the_names_are_kept_even_with_no_calls_beyond_them(self):
        parent = Timings(Clock())
        parent.merge({"phases": {"engine": {"seconds": 5, "calls": 1, "by": {"a": {"seconds": 2, "calls": 1}}}}})
        row = parent.report()["phases"]["engine"]
        self.assertEqual((row["seconds"], row["calls"]), (5, 1))

    def test_nothing_or_nonsense_merges_as_nothing(self):
        parent = Timings(Clock())
        parent.merge(None)
        parent.merge({})
        parent.merge({"phases": {"x": {"seconds": -4, "calls": -1}}})
        self.assertEqual(parent.report()["phases"], {})


class Bounded(unittest.TestCase):
    def test_names_built_from_input_stop_at_a_cap(self):
        t = Timings(Clock())
        for i in range(timings.MAX_NAMES + 40):
            t.add("network", 1, f"host-{i}")
        row = t.report()["phases"]["network"]
        self.assertEqual(len(row["by"]), timings.MAX_NAMES + 1)
        self.assertEqual(row["by"][timings.OTHER_NAMES], {"seconds": 40, "calls": 40})
        self.assertEqual((row["seconds"], row["calls"]), (timings.MAX_NAMES + 40, timings.MAX_NAMES + 40))
        t.add("network", 1, "host-0")                           # a name already there keeps its own row
        self.assertEqual(t.report()["phases"]["network"]["by"]["host-0"]["calls"], 2)


class Capture(unittest.TestCase):
    def test_without_a_capture_nothing_is_recorded_and_one_object_is_returned(self):
        self.assertIsNone(timings.current())
        a, b = timings.span("network"), timings.span("engine", "x")
        self.assertIs(a, b)
        with timings.span("network"):
            pass
        timings.add("network", 1)                               # nothing to add to: no error

    def test_an_error_goes_through_a_span_that_records_nothing(self):
        with self.assertRaises(ValueError):
            with timings.span("network"):
                raise ValueError
        with timings.capture():
            with self.assertRaises(ValueError):
                with timings.span("network"):
                    raise ValueError

    def test_add_counts_one_call_unless_told(self):
        with timings.capture() as t:
            timings.add("network", 1)
            timings.add("network", 1, "x", calls=4)
        self.assertEqual(t.report()["phases"]["network"]["calls"], 5)

    def test_a_capture_is_what_span_and_add_record_into(self):
        clock = Clock()
        t = Timings(clock)
        with timings.capture(t) as got:
            self.assertIs(got, t)
            self.assertIs(timings.current(), t)
            with timings.span("network", "fetch"):
                clock.tick(2)
            timings.add("network", 1, "connect")
        self.assertIsNone(timings.current())
        self.assertEqual(t.report()["phases"]["network"]["seconds"], 3)

    def test_a_capture_without_an_argument_makes_one(self):
        with timings.capture() as t:
            with timings.span("x"):
                pass
        self.assertEqual(t.report()["phases"]["x"]["calls"], 1)

    def test_captures_nest_and_the_outer_one_comes_back(self):
        with timings.capture() as outer:
            with timings.capture() as inner:
                with timings.span("x"):
                    pass
            self.assertIs(timings.current(), outer)
            with timings.span("y"):
                pass
        self.assertEqual(list(inner.report()["phases"]), ["x"])
        self.assertEqual(list(outer.report()["phases"]), ["y"])

    def test_the_capture_is_closed_on_an_exception(self):
        with self.assertRaises(KeyError):
            with timings.capture():
                raise KeyError
        self.assertIsNone(timings.current())

    def test_spans_from_other_threads_reach_the_capture(self):
        def work():
            with timings.span("engine", "scan_file"):
                pass
        with timings.capture() as t:
            th = threading.Thread(target=work)
            th.start()
            th.join()
        self.assertEqual(t.report()["phases"]["engine"]["calls"], 1)


class Render(unittest.TestCase):
    def report(self):
        clock = Clock()
        t = Timings(clock)
        with t.run():
            with t.span("network", "fetch"):
                clock.tick(5)
            with t.span("engine", "scan_file"):
                clock.tick(3)
            with t.span("engine", "import_time_risk"):
                clock.tick(1)
            clock.tick(1)
        return t.report()

    def test_the_table(self):
        lines = timings.render(self.report())
        self.assertEqual(lines[0], "timings (seconds; wall 10.00)")
        self.assertEqual(lines[1].split(), ["network", "5.00", "50%", "1", "call"])
        self.assertEqual(lines[2].split(), ["fetch", "5.00", "1"])
        self.assertEqual(lines[3].split(), ["engine", "4.00", "40%", "2", "calls"])
        self.assertEqual(lines[4].split(), ["scan_file", "3.00", "1"])         # the busiest name first
        self.assertEqual(lines[5].split(), ["import_time_risk", "1.00", "1"])
        self.assertEqual(lines[-1].split()[:3], ["other", "1.00", "10%"])

    def test_phases_are_sorted_by_seconds_then_name(self):
        report = {"wall": 10, "other": 0, "phases": {
            "b": {"seconds": 1, "calls": 1, "by": {}}, "a": {"seconds": 1, "calls": 1, "by": {}},
            "c": {"seconds": 5, "calls": 1, "by": {}}}}
        self.assertEqual([l.split()[0] for l in timings.render(report)[1:4]], ["c", "a", "b"])

    def test_names_beyond_the_top_are_summed(self):
        by = {f"n{i}": {"seconds": 12 - i, "calls": 1} for i in range(12)}
        report = {"wall": 100, "other": 0, "phases": {"engine": {"seconds": 99, "calls": 12, "by": by}}}
        lines = timings.render(report, top=3)
        self.assertEqual([l.split()[0] for l in lines[2:5]], ["n0", "n1", "n2"])
        self.assertEqual(lines[5].split(), ["…", "9", "more", "45.00", "9"])

    def test_eight_names_are_shown_by_default_and_the_rest_summed(self):
        names = lambda n: {f"n{i}": {"seconds": 1, "calls": 1} for i in range(n)}
        for n, shown_more in ((8, False), (9, True), (10, True)):
            report = {"wall": 100, "other": 0, "phases": {"x": {"seconds": n, "calls": n, "by": names(n)}}}
            lines = timings.render(report)
            self.assertEqual(any("more" in l for l in lines), shown_more, n)
            self.assertEqual(sum(1 for l in lines if l.startswith("    ")) - (1 if shown_more else 0), 8)

    def test_a_long_name_is_cut_and_a_share_is_rounded(self):
        report = {"wall": 3, "other": 0, "phases": {"x": {"seconds": 1, "calls": 1,
                                                          "by": {"y" * 40: {"seconds": 1, "calls": 1}}}}}
        lines = timings.render(report)
        self.assertIn("33%", lines[1])
        self.assertEqual(lines[2].split()[0], "y" * 28)

    def test_parallel_work_is_said_to_add_up_to_more_than_the_wall(self):
        report = {"wall": 4, "other": 0, "phases": {"engine": {"seconds": 12, "calls": 1, "by": {}}}}
        self.assertIn("add up to more than", timings.render(report)[0])
        self.assertNotIn("add up to more than", timings.render(self.report())[0])

    def test_no_wall_means_no_shares(self):
        report = {"wall": 0, "other": 0, "phases": {"x": {"seconds": 1, "calls": 2, "by": {}}}}
        self.assertEqual(timings.render(report)[1].split(), ["x", "1.00", "2", "calls"])
        self.assertEqual(timings.render(timings.empty_report())[0], "timings (seconds; wall 0.00)")

    def test_the_report_is_json(self):
        self.assertEqual(json.loads(json.dumps(self.report())), self.report())


if __name__ == "__main__":
    unittest.main()
