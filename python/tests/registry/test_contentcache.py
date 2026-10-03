"""The memo for the engine's answers (lazaret.registry.contentcache, 0.1.9, P-2a). What the design asks of it
(`specs/lazaret-content-cache-design-2026-10-03.md`):

* **A hit equals a miss.** The same answer comes back whether the memo had it or computed it, and the memo that is
  always off (`NULL`) gives the answers the memo gives, for the same computations: that is the gate "identical issues
  with the memo on and off".
* **Single flight.** Any number of threads that ask for one key at once cause one computation.
* **Nothing unfinished is kept.** An error is raised to everyone who waited and is not stored; an `Uncacheable`
  answer is given to its caller and kept by nobody, and nobody else is handed it.
* **A batch costs one call for what nobody has**, and comes back in the order it was asked in; a batch that is all
  hits makes no call; two batches that overlap do not wait for each other.
* **Bounded**, and the longest unused go first.
* **The keys** change with anything the answer depends on and with nothing else."""

import concurrent.futures
import random
import threading
import time
import unittest
from unittest import mock

from lazaret.registry import contentcache as cc

TIMEOUT = 30


def key(name="a", text="x = 1", **kw):
    return cc.file_key("scan", kw.pop("rel", name + ".py"), text, kw.pop("lang", "python"), kw.pop("flags", ()), **kw)


class Counter:
    """A compute function that counts its calls and can be held at a gate."""

    def __init__(self, answer=None, gate=None):
        self.calls, self.answer, self.gate, self.started = 0, answer, gate, threading.Event()
        self._lock = threading.Lock()

    def __call__(self, *args):
        with self._lock:
            self.calls += 1
        self.started.set()
        if self.gate is not None:
            self.gate.wait(TIMEOUT)
        return self.answer() if callable(self.answer) else self.answer


class KeyTests(unittest.TestCase):
    def test_a_key_is_the_same_for_the_same_question(self):
        self.assertEqual(key(), key())
        self.assertEqual(hash(key()), hash(key()))
        self.assertEqual(key(flags={"full": False, "x": 1}), key(flags={"x": 1, "full": False}))
        self.assertEqual(key(flags=("b", "a")), key(flags=("a", "b")))
        for nothing in (None, (), [], {}):
            self.assertEqual(key(flags=nothing), key())                        # (no flags, however it is said)
        self.assertNotEqual(key(flags=("a",)), key(flags=("b",)))
        self.assertNotEqual(key(flags=("a",)), key())
        self.assertNotEqual(key(flags={"full": True}), key(flags={"full": False}))
        self.assertNotEqual(key(flags={"full": True}), key(flags={"deep": True}))

    def test_the_parts_of_a_key(self):
        self.assertEqual(key("a", "x", flags={"full": False}, pack="p", engine="e"),
                         ("scan", "a.py", cc.file_key("scan", "a", "x", "python")[2], "python", (("full", "False"),),
                          "p", "e"))
        self.assertEqual(key()[4], ())
        self.assertEqual(key(flags=("b", "a"))[4], ("'a'", "'b'"))

    def test_a_key_changes_with_everything_the_answer_depends_on(self):
        base = key()
        for change in ({"text": "x = 2"}, {"rel": "other.py"}, {"lang": "javascript"}, {"flags": {"full": True}},
                       {"pack": "rules-2"}, {"engine": "2.18.0"}):
            with self.subTest(change):
                self.assertNotEqual(base, key(**change))
        self.assertNotEqual(base, cc.file_key("import-risk", "a.py", "x = 1", "python"))

    def test_a_pass_that_does_not_read_the_path_gives_one_key_for_one_file_under_two_paths(self):
        self.assertEqual(cc.file_key("import-risk", None, "x", "python"), cc.file_key("import-risk", None, "x", "python"))
        self.assertNotEqual(key(rel="a.py"), key(rel="b.py"))

    def test_text_is_hashed_whatever_it_holds(self):
        self.assertNotEqual(key(text="a\ud800b"), key(text="a\udc00b"))      # (lone surrogates are different content)
        self.assertEqual(key(text="é"), key(text="é"))
        self.assertEqual(cc.file_key("scan", "a", b"abc", "x")[2], cc.file_key("scan", "a", "abc", "x")[2])
        self.assertEqual(len(key()[2]), 64)

    def test_only_the_cached_kinds_have_keys(self):
        for kind in cc.KINDS:
            self.assertEqual(cc.file_key(kind, None, "x", None)[0], kind)
        with self.assertRaises(ValueError):
            cc.file_key("verdict", None, "x", None)

    def test_a_cross_file_key_is_of_the_files_and_not_of_their_order(self):
        files = [("a.py", "import b"), ("b.py", "x = 1"), ("c/d.py", "y")]
        k = cc.cross_file_key(files, {"one_package": True})
        self.assertEqual(k[0], "cross-file")
        self.assertEqual(k, cc.cross_file_key(list(reversed(files)), {"one_package": True}))
        self.assertNotEqual(k, cc.cross_file_key(files, {"one_package": False}))
        self.assertNotEqual(k, cc.cross_file_key(files[:2]))
        self.assertNotEqual(k, cc.cross_file_key([("a.py", "import b"), ("b.py", "x = 2"), ("c/d.py", "y")],
                                                 {"one_package": True}))
        self.assertNotEqual(k, cc.cross_file_key([("z.py", "import b")] + files[1:], {"one_package": True}))
        self.assertNotEqual(cc.cross_file_key([("ab", "c")]), cc.cross_file_key([("a", "bc")]))   # (path and content do not run together)
        self.assertNotEqual(k, cc.cross_file_key(files, {"one_package": True}, pack="p"))


class OneKeyTests(unittest.TestCase):
    def test_the_first_ask_computes_and_the_second_does_not(self):
        memo, work = cc.Memo(), Counter([{"rule": "R1"}])
        k = key()
        self.assertEqual(memo.get_or_compute(k, work), [{"rule": "R1"}])
        self.assertEqual(memo.get_or_compute(k, work), [{"rule": "R1"}])
        self.assertEqual(work.calls, 1)
        self.assertEqual(len(memo), 1)

    def test_a_hit_equals_a_miss_and_other_keys_are_other_questions(self):
        memo = cc.Memo()
        a, b = key("a", "x = 1"), key("b", "y = 2")
        self.assertEqual(memo.get_or_compute(a, lambda: ["A"]), ["A"])
        self.assertEqual(memo.get_or_compute(b, lambda: ["B"]), ["B"])
        self.assertEqual(memo.get_or_compute(a, lambda: ["not asked"]), ["A"])
        self.assertEqual(memo.get_or_compute(b, lambda: ["not asked"]), ["B"])

    def test_what_a_caller_does_to_an_answer_changes_nothing_for_the_next(self):
        memo = cc.Memo()
        k = key()
        mine = memo.get_or_compute(k, lambda: [{"rule": "R1", "lines": [1, 2]}])
        mine[0]["lines"].append(99)
        mine.append("junk")
        again = memo.get_or_compute(k, lambda: None)
        self.assertEqual(again, [{"rule": "R1", "lines": [1, 2]}])
        again[0]["rule"] = "changed"
        self.assertEqual(memo.get_or_compute(k, lambda: None), [{"rule": "R1", "lines": [1, 2]}])

    def test_a_caller_that_promises_not_to_change_answers_gets_the_stored_object(self):
        memo = cc.Memo(copy_answers=False)
        k = key()
        first = memo.get_or_compute(k, lambda: ["A"])
        self.assertIs(memo.get_or_compute(k, lambda: None), first)

    def test_an_error_is_raised_and_not_stored_and_the_next_caller_tries_again(self):
        memo = cc.Memo()
        k = key()
        with self.assertRaisesRegex(RuntimeError, "boom"):
            memo.get_or_compute(k, Counter(answer=lambda: (_ for _ in ()).throw(RuntimeError("boom"))))
        self.assertEqual(len(memo), 0)
        self.assertEqual(memo.get_or_compute(k, lambda: ["fine"]), ["fine"])
        self.assertEqual(memo.stats()["kinds"]["scan"]["errors"], 1)

    def test_an_answer_not_for_keeping_is_given_and_not_kept(self):
        memo = cc.Memo()
        k = key()
        calls = []

        def partial():
            calls.append(1)
            return cc.Uncacheable(["cut short"])
        self.assertEqual(memo.get_or_compute(k, partial), ["cut short"])
        self.assertEqual(len(memo), 0)
        self.assertEqual(memo.get_or_compute(k, partial), ["cut short"])
        self.assertEqual(len(calls), 2)                                       # (asked again: nothing was kept)
        self.assertEqual(memo.get_or_compute(k, lambda: ["whole"]), ["whole"])
        self.assertEqual(memo.get_or_compute(k, partial), ["whole"])          # (and once it is whole, it is kept)
        self.assertEqual(memo.stats()["kinds"]["scan"]["dropped"], 2)

    def test_a_falsy_answer_is_an_answer(self):
        memo = cc.Memo()
        for n, answer in enumerate((None, [], {}, 0, "")):
            with self.subTest(answer=answer):
                k = key(text="t%d" % n)
                work = Counter(answer)
                self.assertEqual(memo.get_or_compute(k, work), answer)
                self.assertEqual(memo.get_or_compute(k, work), answer)
                self.assertEqual(work.calls, 1)

    def test_the_stats_say_how_many_answers_were_served_by_kind(self):
        memo = cc.Memo()
        memo.get_or_compute(key("a"), lambda: 1)
        memo.get_or_compute(key("a"), lambda: 1)
        memo.get_or_compute(key("a"), lambda: 1)
        memo.get_or_compute(cc.file_key("import-risk", None, "x", "python"), lambda: 2)
        stats = memo.stats()
        self.assertEqual(stats["kinds"]["scan"], {"hits": 2, "misses": 1, "shared": 0, "stored": 1, "dropped": 0,
                                                  "evicted": 0, "errors": 0})
        self.assertEqual(stats["kinds"]["import-risk"]["misses"], 1)
        self.assertEqual((stats["entries"], stats["max_bytes"]), (2, cc.DEFAULT_MAX_BYTES))
        self.assertGreater(stats["bytes"], 0)

    def test_clear_forgets_everything(self):
        memo = cc.Memo()
        memo.get_or_compute(key(), lambda: [1])
        memo.clear()
        self.assertEqual((len(memo), memo.stats()["bytes"]), (0, 0))
        self.assertEqual(memo.get_or_compute(key(), lambda: [2]), [2])


class SingleFlightTests(unittest.TestCase):
    def ask_together(self, memo, k, work, n=6, **kw):
        """`n` threads ask for `k` while `work` is held at its gate -> their answers."""
        pool = concurrent.futures.ThreadPoolExecutor(n)
        self.addCleanup(pool.shutdown, True)
        futures = [pool.submit(memo.get_or_compute, k, work, **kw)]
        self.assertTrue(work.started.wait(TIMEOUT))
        futures += [pool.submit(memo.get_or_compute, k, work, **kw) for _ in range(n - 1)]
        deadline = time.time() + TIMEOUT
        while time.time() < deadline and memo.stats()["kinds"].get("scan", {}).get("misses", 0) + len(memo._flights) == 0:
            time.sleep(0.005)
        time.sleep(0.15)                                                      # (the others are at the flight by now)
        work.gate.set()
        return [f.result(TIMEOUT) for f in futures]

    def test_threads_that_ask_at_once_cause_one_computation(self):
        memo, work = cc.Memo(), Counter(["answer"], gate=threading.Event())
        answers = self.ask_together(memo, key(), work)
        self.assertEqual(work.calls, 1)
        self.assertEqual(answers, [["answer"]] * 6)
        stats = memo.stats()["kinds"]["scan"]
        self.assertEqual((stats["misses"], stats["shared"] + stats["hits"]), (1, 5))

    def test_threads_that_ask_at_once_share_one_computation_even_when_nothing_can_be_kept(self):
        for memo in (cc.Memo(max_bytes=0), cc.Memo(max_bytes=1000)):
            work = Counter(["x" * 5000], gate=threading.Event())
            answers = self.ask_together(memo, key(), work)
            self.assertEqual(work.calls, 1)
            self.assertEqual(answers, [["x" * 5000]] * 6)
            self.assertEqual(len(memo), 0)
            self.assertEqual(memo.stats()["kinds"]["scan"]["shared"], 5)

    def test_the_answers_the_threads_get_are_theirs(self):
        memo, work = cc.Memo(), Counter([{"n": 1}], gate=threading.Event())
        answers = self.ask_together(memo, key(), work)
        self.assertEqual(len({id(a) for a in answers}), len(answers))
        answers[0][0]["n"] = 99
        self.assertEqual(answers[1], [{"n": 1}])

    def test_an_error_goes_to_every_thread_that_waited_for_it(self):
        memo = cc.Memo()
        gate = threading.Event()

        def fail():
            raise ValueError("engine said no")
        work = Counter(answer=fail, gate=gate)
        pool = concurrent.futures.ThreadPoolExecutor(4)
        self.addCleanup(pool.shutdown, True)
        futures = [pool.submit(memo.get_or_compute, key(), work)]
        self.assertTrue(work.started.wait(TIMEOUT))
        futures += [pool.submit(memo.get_or_compute, key(), work) for _ in range(3)]
        time.sleep(0.15)
        gate.set()
        for f in futures:
            with self.assertRaisesRegex(ValueError, "engine said no"):
                f.result(TIMEOUT)
        self.assertEqual(work.calls, 1)
        self.assertEqual(len(memo._flights), 0)

    def test_an_answer_not_for_keeping_is_not_handed_to_the_threads_that_waited(self):
        memo = cc.Memo()
        gate = threading.Event()
        order = []

        def slow_partial():
            order.append("first")
            gate.wait(TIMEOUT)
            return cc.Uncacheable(["cut by the first thread's budget"])

        def own():
            order.append("second")
            return ["worked out in full"]
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        first = pool.submit(memo.get_or_compute, key(), slow_partial)
        while not order:
            time.sleep(0.005)
        second = pool.submit(memo.get_or_compute, key(), own)
        time.sleep(0.15)
        gate.set()
        self.assertEqual(first.result(TIMEOUT), ["cut by the first thread's budget"])
        self.assertEqual(second.result(TIMEOUT), ["worked out in full"])
        self.assertEqual(memo.get_or_compute(key(), lambda: None), ["worked out in full"])

    def test_a_thread_that_is_interrupted_does_not_leave_the_others_waiting(self):
        memo = cc.Memo()
        gate = threading.Event()
        started = threading.Event()

        def interrupted():
            started.set()
            gate.wait(TIMEOUT)
            raise KeyboardInterrupt

        def run():
            try:
                memo.get_or_compute(key(), interrupted)
            except KeyboardInterrupt:
                pass
        leader = threading.Thread(target=run)
        leader.start()
        self.assertTrue(started.wait(TIMEOUT))
        pool = concurrent.futures.ThreadPoolExecutor(1)
        self.addCleanup(pool.shutdown, True)
        follower = pool.submit(memo.get_or_compute, key(), lambda: ["done by the follower"])
        time.sleep(0.15)
        gate.set()
        leader.join(TIMEOUT)
        self.assertEqual(follower.result(TIMEOUT), ["done by the follower"])

    def test_a_thread_does_not_wait_longer_than_it_is_willing_to(self):
        memo = cc.Memo()
        gate = threading.Event()
        slow = Counter(["slow"], gate=gate)
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, key(), slow)
        self.assertTrue(slow.started.wait(TIMEOUT))
        started = time.time()
        self.assertEqual(memo.get_or_compute(key(), lambda: ["mine"], wait=0.05), ["mine"])
        self.assertLess(time.time() - started, TIMEOUT / 2)
        gate.set()
        self.assertEqual(leader.result(TIMEOUT), ["slow"])

    def test_different_keys_are_computed_at_the_same_time(self):
        memo = cc.Memo()
        inside = threading.Barrier(2, timeout=TIMEOUT)

        def work(name):
            def run():
                inside.wait()                                                 # (both must be here at once)
                return [name]
            return run
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        a = pool.submit(memo.get_or_compute, key("a", "1"), work("a"))
        b = pool.submit(memo.get_or_compute, key("b", "2"), work("b"))
        self.assertEqual((a.result(TIMEOUT), b.result(TIMEOUT)), (["a"], ["b"]))


class BatchTests(unittest.TestCase):
    def keys(self, *names):
        return [key(n, "text of " + n) for n in names]

    def engine(self):
        calls = []

        def batch(missing):
            calls.append(list(missing))
            return [["answer for " + k[2][:6]] for k in missing]
        batch.calls = calls
        return batch

    def test_a_batch_of_misses_is_one_call_in_the_order_asked(self):
        memo, batch = cc.Memo(), self.engine()
        keys = self.keys("a", "b", "c")
        answers = memo.get_or_compute_many(keys, batch)
        self.assertEqual(answers, [["answer for " + k[2][:6]] for k in keys])
        self.assertEqual(batch.calls, [keys])

    def test_a_batch_of_hits_makes_no_call(self):
        memo, batch = cc.Memo(), self.engine()
        keys = self.keys("a", "b")
        first = memo.get_or_compute_many(keys, batch)
        self.assertEqual(memo.get_or_compute_many(keys, batch), first)
        self.assertEqual(len(batch.calls), 1)

    def test_a_mixed_batch_sends_the_misses_and_returns_everything_in_the_asked_order(self):
        memo, batch = cc.Memo(), self.engine()
        keys = self.keys("a", "b", "c", "d", "e")
        memo.get_or_compute_many([keys[1], keys[3]], batch)
        answers = memo.get_or_compute_many(keys, batch)
        self.assertEqual(batch.calls[1], [keys[0], keys[2], keys[4]])
        self.assertEqual(answers, [["answer for " + k[2][:6]] for k in keys])

    def test_a_key_twice_in_a_batch_is_asked_once_and_answered_twice_with_separate_objects(self):
        memo, batch = cc.Memo(), self.engine()
        a, b = self.keys("a", "b")
        answers = memo.get_or_compute_many([a, b, a], batch)
        self.assertEqual(batch.calls, [[a, b]])
        self.assertEqual(answers[0], answers[2])
        self.assertIsNot(answers[0], answers[2])

    def test_an_empty_batch_is_no_call(self):
        memo, batch = cc.Memo(), self.engine()
        self.assertEqual(memo.get_or_compute_many([], batch), [])
        self.assertEqual(batch.calls, [])

    def test_answers_not_for_keeping_come_back_and_are_not_kept(self):
        memo = cc.Memo()
        a, b = self.keys("a", "b")
        answers = memo.get_or_compute_many([a, b], lambda ks: [["whole"], cc.Uncacheable(["cut"])])
        self.assertEqual(answers, [["whole"], ["cut"]])
        self.assertEqual(len(memo), 1)
        self.assertEqual(memo.get_or_compute(b, lambda: ["again"]), ["again"])

    def test_a_batch_that_fails_raises_and_leaves_nothing_in_flight(self):
        memo = cc.Memo()
        keys = self.keys("a", "b")

        def fail(missing):
            raise OSError("engine down")
        with self.assertRaisesRegex(OSError, "engine down"):
            memo.get_or_compute_many(keys, fail)
        self.assertEqual((len(memo), len(memo._flights)), (0, 0))
        self.assertEqual(memo.get_or_compute(keys[0], lambda: ["fine"]), ["fine"])      # (nobody waits for it)

    def test_the_wrong_number_of_answers_is_an_error_and_not_a_shifted_answer(self):
        memo = cc.Memo()
        keys = self.keys("a", "b", "c")
        for answers in ([["only one"]], [["x"]] * 4, "abc", None):
            with self.subTest(answers=answers), self.assertRaises(ValueError):
                memo.get_or_compute_many(keys, lambda missing, answers=answers: answers)
            self.assertEqual((len(memo), len(memo._flights)), (0, 0))

    def test_an_answer_that_cannot_be_published_does_not_leave_the_rest_waiting(self):
        memo = cc.Memo()
        a, b = self.keys("a", "b")
        real = memo._publish
        seen = []

        def publish(k, kind, flight, result):
            seen.append(k)
            if len(seen) == 1:
                raise RuntimeError("cannot publish")
            return real(k, kind, flight, result)
        memo._publish = publish
        with self.assertRaisesRegex(RuntimeError, "cannot publish"):
            memo.get_or_compute_many([a, b], lambda ks: [["A"], ["B"]])
        self.assertEqual(len(memo._flights), 0)
        memo._publish = real
        self.assertEqual(memo.get_or_compute(b, lambda: ["B again"]), ["B again"])

    def test_a_batch_waits_for_what_another_thread_is_working_on_and_asks_for_the_rest(self):
        memo = cc.Memo()
        a, b = self.keys("a", "b")
        gate = threading.Event()
        slow = Counter(["slow a"], gate=gate)
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, a, slow)
        self.assertTrue(slow.started.wait(TIMEOUT))
        asked = []
        batch = pool.submit(memo.get_or_compute_many, [a, b], lambda ks: asked.append(list(ks)) or [["B"] for _ in ks])
        time.sleep(0.2)
        self.assertEqual(asked, [[b]])                                         # (b is computed while a is awaited)
        gate.set()
        self.assertEqual(batch.result(TIMEOUT), [["slow a"], ["B"]])
        self.assertEqual(leader.result(TIMEOUT), ["slow a"])

    def test_a_batch_whose_waited_for_answer_is_not_for_keeping_asks_for_it_itself(self):
        memo = cc.Memo()
        a, b = self.keys("a", "b")
        gate = threading.Event()
        started = threading.Event()

        def partial():
            started.set()
            gate.wait(TIMEOUT)
            return cc.Uncacheable(["cut"])
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, a, partial)
        self.assertTrue(started.wait(TIMEOUT))
        asked = []
        batch = pool.submit(memo.get_or_compute_many, [a, b], lambda ks: asked.append(list(ks)) or [["mine"] for _ in ks])
        time.sleep(0.2)
        gate.set()
        self.assertEqual(batch.result(TIMEOUT), [["mine"], ["mine"]])
        self.assertEqual(asked, [[b], [a]])
        self.assertEqual(leader.result(TIMEOUT), ["cut"])

    def test_a_batch_that_runs_out_of_patience_computes_the_key_itself(self):
        memo = cc.Memo()
        a, b = self.keys("a", "b")
        gate = threading.Event()
        slow = Counter(["slow"], gate=gate)
        pool = concurrent.futures.ThreadPoolExecutor(1)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, a, slow)
        self.assertTrue(slow.started.wait(TIMEOUT))
        answers = memo.get_or_compute_many([a, b], lambda ks: [["mine"] for _ in ks], wait=0.05)
        self.assertEqual(answers, [["mine"], ["mine"]])
        gate.set()
        leader.result(TIMEOUT)

    def test_overlapping_batches_do_not_wait_for_each_other(self):
        """Many threads, each asking for a random set of keys from a small pool, in random order, through batches
        and single asks: all finish, each gets the answer for its key, and the engine was asked at most once for
        a key that stayed in the memo."""
        memo = cc.Memo()
        names = ["k%d" % i for i in range(12)]
        keys = {n: key(n, "text of " + n) for n in names}
        asked = []
        lock = threading.Lock()

        def engine(missing):
            time.sleep(0.002)
            with lock:
                asked.extend(missing)
            return [["answer " + k[1]] for k in missing]

        def worker(seed):
            rnd = random.Random(seed)
            for _ in range(25):
                picked = rnd.sample(names, rnd.randint(1, 6))
                if rnd.random() < 0.3:
                    one = picked[0]
                    got = [memo.get_or_compute(keys[one], lambda one=one: engine([keys[one]])[0])]
                    picked = [one]
                else:
                    got = memo.get_or_compute_many([keys[n] for n in picked], engine)
                assert got == [["answer " + n + ".py"] for n in picked], (picked, got)
        pool = concurrent.futures.ThreadPoolExecutor(8)
        self.addCleanup(pool.shutdown, True)
        for f in [pool.submit(worker, s) for s in range(8)]:
            f.result(TIMEOUT * 2)
        self.assertEqual(sorted(set(asked)), sorted(set(asked)))
        self.assertEqual(len(asked), len(set(asked)))                          # (each asked once: it was kept)
        self.assertEqual(len(memo._flights), 0)


class BoundTests(unittest.TestCase):
    """The bound is in bytes, and an answer over 1/8 of it is not kept, so a memo holds at least eight."""

    def room_for_eight(self, text):
        return 8 * cc.estimate([text]) + 10

    def test_the_memo_holds_what_it_is_told_to_and_drops_the_longest_unused_first(self):
        text = "x" * 500
        memo = cc.Memo(max_bytes=self.room_for_eight(text))
        keys = [key("n%d" % i, "t%d" % i) for i in range(12)]
        for k in keys:
            memo.get_or_compute(k, lambda: [text])
        self.assertEqual(len(memo), 8)
        self.assertLessEqual(memo.stats()["bytes"], memo.max_bytes)
        self.assertEqual(memo.stats()["kinds"]["scan"]["evicted"], 4)
        other = ["y" * 500]                                                    # (the same size: what a recomputed answer takes)
        self.assertEqual([memo.get_or_compute(k, lambda: other) for k in keys[:4]], [other] * 4)
        self.assertEqual(len(memo), 8)                                         # (those four came back, four others went)
        self.assertEqual(memo.get_or_compute(keys[-1], lambda: other), [text])

    def test_an_answer_that_was_used_again_outlives_one_that_was_not(self):
        text = "x" * 500
        memo = cc.Memo(max_bytes=self.room_for_eight(text))
        keys = [key(n, n) for n in "abcdefghi"]
        for k in keys[:8]:
            memo.get_or_compute(k, lambda: [text])
        memo.get_or_compute(keys[0], lambda: None)                             # (a is used again)
        memo.get_or_compute(keys[8], lambda: [text])                           # (b goes, not a)
        self.assertEqual(memo.get_or_compute(keys[0], lambda: ["gone"]), [text])
        self.assertEqual(memo.get_or_compute(keys[1], lambda: ["gone"]), ["gone"])

    def test_an_answer_that_is_too_big_is_given_and_not_kept(self):
        memo = cc.Memo(max_bytes=10_000)
        big = ["x" * 5000]
        self.assertEqual(memo.get_or_compute(key(), lambda: big), big)
        self.assertEqual(len(memo), 0)
        self.assertEqual(memo.stats()["kinds"]["scan"]["dropped"], 1)

    def test_a_memo_with_no_room_still_shares_a_flight_and_keeps_nothing(self):
        memo = cc.Memo(max_bytes=0)
        work = Counter(["a"])
        self.assertEqual(memo.get_or_compute(key(), work), ["a"])
        self.assertEqual(memo.get_or_compute(key(), work), ["a"])
        self.assertEqual((work.calls, len(memo)), (2, 0))

    def test_the_bound_is_what_the_design_says(self):
        self.assertEqual((cc.DEFAULT_MAX_BYTES, cc.Memo().max_bytes, cc.MAX_ENTRY_SHARE), (64 << 20, 64 << 20, 8))

    def test_an_answer_too_big_to_count_is_counted_as_a_big_one(self):
        n = 1_100_000
        counted = cc.estimate(list(range(n)))
        self.assertEqual(counted, 56 + 8 * n + 32 * 999_999 + 4096)            # (the list, a million less one numbers, a margin)
        self.assertEqual((cc.estimate(None), cc.estimate("x"), cc.estimate(b"xy"), cc.estimate([])), (32, 50, 35, 56))

    def test_the_estimate_counts_what_an_answer_holds(self):
        self.assertGreater(cc.estimate("x" * 1000), cc.estimate("x"))
        self.assertGreater(cc.estimate([{"a": ["x" * 100] * 10}]), cc.estimate([{"a": ["x" * 100]}]))
        self.assertGreater(cc.estimate(b"x" * 1000), 1000)
        self.assertGreater(cc.estimate(None), 0)
        self.assertGreater(cc.estimate(set(range(50))), cc.estimate(set()))
        deep = []
        for _ in range(5000):
            deep = [deep]
        self.assertGreater(cc.estimate(deep), 5000)                            # (and it does not recurse)

    def test_an_answer_that_cannot_be_copied_is_given_and_not_kept(self):
        memo = cc.Memo()

        class Awkward:
            def __deepcopy__(self, memo_):
                raise TypeError("no copy")
        answer = [Awkward()]
        self.assertIs(memo.get_or_compute(key(), lambda: answer), answer)
        self.assertEqual(len(memo), 0)
        self.assertEqual(len(memo._flights), 0)


class CountingEvent(threading.Event):
    """An event that counts the waits made on it."""
    waits = 0

    def wait(self, timeout=None):
        self.waits += 1
        return super().wait(timeout)


def counts(memo, kind="scan"):
    return memo.stats()["kinds"].get(kind, {})


class BookkeepingTests(unittest.TestCase):
    """The counts and the table of flights say what happened, down to the last one."""

    def test_a_memo_keeps_exactly_what_its_bound_allows(self):
        size = cc.estimate(["x" * 100])
        memo = cc.Memo(max_bytes=8 * size)
        keys = [key("n%d" % i, "t%d" % i) for i in range(9)]
        for k in keys[:8]:
            memo.get_or_compute(k, lambda: ["x" * 100])
        self.assertEqual((len(memo), memo.stats()["bytes"], counts(memo)["evicted"]), (8, 8 * size, 0))
        memo.get_or_compute(keys[8], lambda: ["x" * 100])
        self.assertEqual((len(memo), counts(memo)["evicted"]), (8, 1))
        self.assertEqual(memo.get_or_compute(keys[1], lambda: ["again"]), ["x" * 100])      # (the first one went)
        self.assertEqual(memo.get_or_compute(keys[0], lambda: ["again"]), ["again"])

    def test_an_answer_is_kept_at_exactly_an_eighth_of_the_bound_and_not_a_byte_more(self):
        size = cc.estimate(["x" * 100])
        fits, short = cc.Memo(max_bytes=8 * size), cc.Memo(max_bytes=8 * size - 1)
        fits.get_or_compute(key(), lambda: ["x" * 100])
        short.get_or_compute(key(), lambda: ["x" * 100])
        self.assertEqual((len(fits), counts(fits)["stored"], counts(fits)["dropped"]), (1, 1, 0))
        self.assertEqual((len(short), counts(short)["stored"], counts(short)["dropped"]), (0, 0, 1))

    def test_a_key_twice_in_a_batch_is_one_miss_and_is_not_waited_for(self):
        memo = cc.Memo()
        k = key()
        out = memo.get_or_compute_many([k, k, k], lambda ks: [["v"] for _ in ks])
        self.assertEqual(out, [["v"]] * 3)
        self.assertEqual({n: counts(memo)[n] for n in ("misses", "hits", "shared", "stored")},
                         {"misses": 1, "hits": 0, "shared": 0, "stored": 1})

    def test_a_key_the_memo_has_twice_in_a_batch_is_one_hit(self):
        memo = cc.Memo()
        k = key()
        memo.get_or_compute(k, lambda: ["v"])
        memo.get_or_compute_many([k, k], lambda ks: self.fail("asked"))
        self.assertEqual((counts(memo)["hits"], counts(memo)["shared"], counts(memo)["misses"]), (1, 0, 1))

    def test_what_a_batch_waited_for_is_counted_as_shared_and_not_as_a_hit(self):
        memo = cc.Memo()
        a = key("a", "a")
        gate = threading.Event()
        slow = Counter(["slow"], gate=gate)
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, a, slow)
        self.assertTrue(slow.started.wait(TIMEOUT))
        batch = pool.submit(memo.get_or_compute_many, [a], lambda ks: self.fail("asked"))
        time.sleep(0.2)
        gate.set()
        self.assertEqual(batch.result(TIMEOUT), [["slow"]])
        leader.result(TIMEOUT)
        self.assertEqual((counts(memo)["shared"], counts(memo)["hits"], counts(memo)["misses"]), (1, 0, 1))

    def test_a_batch_that_runs_out_of_patience_waits_once_and_keeps_nothing(self):
        memo = cc.Memo()
        a = key("a", "a")
        flight = cc._Flight()
        flight.done = CountingEvent()
        memo._flights[a] = flight
        self.assertEqual(memo.get_or_compute_many([a], lambda ks: [["mine"] for _ in ks], wait=0.01), [["mine"]])
        self.assertEqual(flight.done.waits, 1)
        self.assertEqual((len(memo), counts(memo)["misses"], counts(memo)["stored"]), (0, 1, 0))
        self.assertIs(memo._flights[a], flight)                                # (it is the other thread's to finish)

    def test_a_single_ask_that_runs_out_of_patience_waits_once_and_keeps_nothing(self):
        memo = cc.Memo()
        a = key("a", "a")
        flight = cc._Flight()
        flight.done = CountingEvent()
        memo._flights[a] = flight
        self.assertEqual(memo.get_or_compute(a, lambda: ["mine"], wait=0.01), ["mine"])
        self.assertEqual(flight.done.waits, 1)
        self.assertEqual((len(memo), counts(memo)["misses"], counts(memo)["stored"]), (0, 1, 0))

    def test_a_batch_whose_waited_for_answer_was_not_for_keeping_leads_the_asking_again(self):
        memo = cc.Memo()
        a, b = key("a", "a"), key("b", "b")
        gate, started = threading.Event(), threading.Event()

        def partial():
            started.set()
            gate.wait(TIMEOUT)
            return cc.Uncacheable(["cut"])
        pool = concurrent.futures.ThreadPoolExecutor(2)
        self.addCleanup(pool.shutdown, True)
        leader = pool.submit(memo.get_or_compute, a, partial)
        self.assertTrue(started.wait(TIMEOUT))
        batch = pool.submit(memo.get_or_compute_many, [a, b], lambda ks: [["mine"] for _ in ks])
        time.sleep(0.2)
        gate.set()
        self.assertEqual(batch.result(TIMEOUT), [["mine"], ["mine"]])
        leader.result(TIMEOUT)
        self.assertEqual(len(memo), 2)                                         # (its own asking was a full one: kept)
        self.assertEqual((counts(memo)["stored"], counts(memo)["dropped"]), (2, 1))
        self.assertEqual(memo._flights, {})

    def test_a_flight_that_is_not_the_current_one_is_left_alone_by_its_abandonment(self):
        memo = cc.Memo()
        k = key()
        old, new = cc._Flight(), cc._Flight()
        memo._flights[k] = new
        memo._abandon([(k, old)], ValueError("old"))
        self.assertIs(memo._flights[k], new)
        self.assertFalse(new.done.is_set())
        self.assertTrue(old.done.is_set())
        self.assertIsInstance(old.error, ValueError)
        self.assertEqual(counts(memo)["errors"], 1)

    def test_abandoning_a_flight_that_is_not_in_the_table_is_not_an_error(self):
        memo = cc.Memo()
        flight = cc._Flight()
        memo._abandon([(key(), flight)], None)
        self.assertTrue(flight.done.is_set())
        self.assertIsNone(flight.error)
        self.assertEqual(counts(memo).get("errors", 0), 0)                     # (nobody was told of an error)
        self.assertEqual(memo._flights, {})

    def test_abandoning_a_flight_that_has_finished_changes_nothing_about_it(self):
        memo = cc.Memo()
        k = key()
        flight = cc._Flight()
        flight.answer, flight.share = ["done"], True
        flight.done.set()
        memo._flights[k] = flight
        memo._abandon([(k, flight)], ValueError("late"))
        self.assertIsNone(flight.error)
        self.assertEqual((flight.answer, flight.share), (["done"], True))
        self.assertEqual(counts(memo).get("errors", 0), 0)
        self.assertNotIn(k, memo._flights)

    def test_publishing_leaves_a_newer_flight_for_the_same_key_in_the_table(self):
        memo = cc.Memo()
        k = key()
        mine, other = cc._Flight(), cc._Flight()
        memo._flights[k] = other
        memo._publish(k, "scan", mine, ["v"])
        self.assertIs(memo._flights[k], other)
        self.assertTrue(mine.done.is_set() and mine.share)
        self.assertEqual(memo.get_or_compute(k, lambda: self.fail("asked")), ["v"])

    def test_publishing_a_flight_that_is_not_in_the_table_is_not_an_error(self):
        memo = cc.Memo()
        k = key()
        mine = cc._Flight()
        memo._publish(k, "scan", mine, ["v"])
        self.assertTrue(mine.done.is_set())
        self.assertEqual((len(memo), memo._flights), (1, {}))

    def test_a_failure_after_one_answer_was_published_releases_the_flights_that_are_left(self):
        memo = cc.Memo()
        a, b = key("a", "a"), key("b", "b")
        with mock.patch.object(cc.Memo, "_evict", side_effect=RuntimeError("evict")):
            with self.assertRaisesRegex(RuntimeError, "^evict$"):                  # (and not a KeyError from the cleanup)
                memo.get_or_compute_many([a, b], lambda ks: [["A"], ["B"]])
        self.assertEqual(memo._flights, {})
        self.assertEqual(memo.get_or_compute(b, lambda: ["B again"]), ["B again"])


class NullMemoTests(unittest.TestCase):
    def test_it_computes_every_time_and_keeps_nothing(self):
        work = Counter(["a"])
        for _ in range(3):
            self.assertEqual(cc.NULL.get_or_compute(key(), work), ["a"])
        self.assertEqual(work.calls, 3)
        self.assertEqual((len(cc.NULL), cc.NULL.enabled, cc.Memo().enabled), (0, False, True))
        self.assertEqual(cc.NULL.stats()["entries"], 0)
        cc.NULL.clear()

    def test_it_unwraps_what_is_not_for_keeping(self):
        self.assertEqual(cc.NULL.get_or_compute(key(), lambda: cc.Uncacheable([1])), [1])
        self.assertEqual(cc.NULL.get_or_compute_many([key("a"), key("b")], lambda ks: [cc.Uncacheable(1), 2]), [1, 2])

    def test_a_batch_is_one_call_of_all_the_keys_and_an_empty_one_is_none(self):
        asked = []
        keys = [key("a"), key("b"), key("a")]
        self.assertEqual(cc.NULL.get_or_compute_many(keys, lambda ks: asked.append(list(ks)) or list(range(len(ks)))),
                         [0, 1, 2])
        self.assertEqual(asked, [keys])
        self.assertEqual(cc.NULL.get_or_compute_many([], lambda ks: asked.append(1)), [])
        self.assertEqual(len(asked), 1)
        with self.assertRaises(ValueError):
            cc.NULL.get_or_compute_many(keys, lambda ks: [1])
        with self.assertRaises(ValueError):
            cc.NULL.get_or_compute_many(keys, lambda ks: None)

    def test_the_memo_on_and_the_memo_off_give_the_same_answers_for_the_same_work(self):
        """The gate, in small: a stand-in engine whose answer is a function of the key; run a random stream of single
        asks and batches through the memo and through `NULL`; every answer is the same, in the same order."""
        def engine(k):
            return [{"file": k[1], "sha": k[2][:8], "n": int(k[2][:4], 16) % 7}]
        rnd = random.Random(5)
        names = ["f%d" % i for i in range(15)]
        stream = [[rnd.choice(names) for _ in range(rnd.randint(1, 8))] for _ in range(200)]
        results = {}
        for label, memo in (("on", cc.Memo()), ("off", cc.NULL)):
            out = []
            for picked in stream:
                keys = [key(n, "text of " + n) for n in picked]
                if len(keys) == 1:
                    out.append([memo.get_or_compute(keys[0], lambda k=keys[0]: engine(k))])
                else:
                    out.append(memo.get_or_compute_many(keys, lambda missing: [engine(k) for k in missing]))
            results[label] = out
        self.assertEqual(results["on"], results["off"])


if __name__ == "__main__":
    unittest.main()
