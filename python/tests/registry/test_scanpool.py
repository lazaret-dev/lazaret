"""The guard's scan workers (0.1.9, P-7): `lazaret.registry.scanpool.WorkerPool`.

Real worker processes (`spawn`, as in the guard) run the functions of `_scanpool_support`, which do what the first bytes of
the archive say: answer with what they were given, end the process, compute or sleep for ever, ask for memory. What is
checked: the archive goes to the worker as a file that is hashed again there and removed after, not as a pickle; the
worker's address-space limit, CPU limit and engine threads; a lost worker is a retry alone and then `Died`, never a scan
in the caller's process; a hung scan ends its workers; a pool that cannot start is `Unavailable`; `close` leaves nothing
behind."""

import concurrent.futures
import json
import multiprocessing
import os
import pickle
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from lazaret.registry import scanpool
from lazaret.scanner import timings
from tests import _support
from tests.registry import _scanpool_support as support

try:
    import resource
except ImportError:
    resource = None

LINUX_LIMITS = resource is not None and sys.platform.startswith("linux")
MB = 1024 * 1024


def pool(fn=support.echo, jobs=1, **kw):
    p = scanpool.WorkerPool(jobs, fn, **kw)
    return p


class Case(unittest.TestCase):
    def pool(self, *args, **kw):
        p = pool(*args, **kw)
        self.addCleanup(p.close)
        return p


class HelperTests(unittest.TestCase):
    def test_the_cores_are_shared_out_between_one_and_eight(self):
        self.assertEqual([scanpool.threads_for(j, 8) for j in (1, 2, 3, 4, 8, 9, 100)], [8, 4, 2, 2, 1, 1, 1])
        self.assertEqual([scanpool.threads_for(1, c) for c in (1, 2, 8, 9, 64)], [1, 2, 8, 8, 8])
        self.assertEqual(scanpool.threads_for(0, 4), 4)                      # (no jobs is one job)

    def test_the_cores_come_from_the_affinity_when_there_is_one(self):
        self.assertGreaterEqual(scanpool.cores(), 1)
        if hasattr(os, "sched_getaffinity"):
            self.assertEqual(scanpool.cores(), len(os.sched_getaffinity(0)))
        for error in (OSError, AttributeError):                                # (no affinity: the machine's cores)
            with mock.patch.object(os, "sched_getaffinity", side_effect=error, create=True), \
                    mock.patch.object(os, "cpu_count", return_value=6):
                self.assertEqual(scanpool.cores(), 6)
        with mock.patch.object(os, "sched_getaffinity", side_effect=OSError, create=True), \
                mock.patch.object(os, "cpu_count", return_value=None):
            self.assertEqual(scanpool.cores(), 1)
        self.assertEqual(scanpool.threads_for(2), scanpool.threads_for(2, scanpool.cores()))


def python(code):
    """What `code` prints, run in a Python of its own (so that a limit set there is its own)."""
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(p for p in sys.path if p)}
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, encoding="utf-8", errors="replace",
                          timeout=60, check=True)
    return done.stdout.strip()


@unittest.skipUnless(LINUX_LIMITS, "the limits are Linux's")
class LimitsOfAnotherProcessTests(unittest.TestCase):
    """The worker's limits against the ones it was started with: never above a hard limit, never raising a lower one."""

    def test_the_cpu_limit_stays_under_a_hard_limit(self):
        got = python("import resource\nfrom lazaret.registry import scanpool\n"
                     "resource.setrlimit(resource.RLIMIT_CPU, (500, 1000))\nscanpool._cpu_limit(5000)\n"
                     "print(*resource.getrlimit(resource.RLIMIT_CPU))")
        self.assertEqual(got, "1000 1000")

    def test_the_cpu_limit_is_the_cpu_used_so_far_plus_the_budget(self):
        got = python("import resource\nfrom lazaret.registry import scanpool\nscanpool._cpu_limit(300)\n"
                     "print(resource.getrlimit(resource.RLIMIT_CPU)[0])")
        self.assertTrue(300 <= int(got) <= 330, got)

    def test_a_cpu_limit_that_cannot_be_set_is_not_an_error(self):
        self.assertEqual(python("from lazaret.registry import scanpool\nimport resource\n"
                                "resource.setrlimit(resource.RLIMIT_CPU, (10, 10))\n"
                                "scanpool._cpu_limit(5000)\nprint('ok', resource.getrlimit(resource.RLIMIT_CPU)[0])"),
                         "ok 10")

    def test_the_memory_limit_never_raises_a_lower_one(self):
        got = python("import resource\nfrom lazaret.registry import scanpool\nGIB = 1 << 30\n"
                     "resource.setrlimit(resource.RLIMIT_AS, (3 * GIB, resource.RLIM_INFINITY))\n"
                     "scanpool._init(6144 * 1024 * 1024)\nprint(resource.getrlimit(resource.RLIMIT_AS)[0] // GIB)")
        self.assertEqual(got, "3")
        got = python("import resource\nfrom lazaret.registry import scanpool\nGIB = 1 << 30\n"
                     "scanpool._init(2 * GIB)\nprint(resource.getrlimit(resource.RLIMIT_AS)[0] // GIB)")
        self.assertEqual(got, "2")


class DefaultTests(unittest.TestCase):
    def test_the_defaults(self):
        self.assertEqual((scanpool.DEFAULT_MEMORY_MB, scanpool.MAX_BREAKS, scanpool.MAX_ENGINE_THREADS), (6144, 20, 8))
        self.assertEqual(scanpool._ping(), os.getpid())
        p = scanpool.WorkerPool(0, support.echo)
        self.assertEqual((p.jobs, p.memory_bytes, p.threads, p.wall, p.cpu), (1, 6144 * MB, None, None, None))
        self.assertEqual(scanpool.WorkerPool(2, support.echo, memory_mb=0).memory_bytes, 0)


class HandOffTests(Case):
    def test_an_archive_is_a_private_file_named_for_its_content(self):
        p = self.pool()
        path, digest = p.stage(b"archive bytes")
        import hashlib
        self.assertEqual(digest, hashlib.sha256(b"archive bytes").hexdigest())
        self.assertTrue(os.path.basename(path).startswith(digest + "-"))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"archive bytes")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        again, same = p.stage(b"archive bytes")
        self.assertEqual((same, os.path.dirname(again)), (digest, os.path.dirname(path)))
        self.assertNotEqual(again, path)                                    # the same content twice is two files

    def test_the_worker_gets_the_archive_and_the_file_is_gone_after(self):
        p = self.pool()
        got = p.run(b"ok" + b"x" * 1000, "tgz", "npm", 7, False)
        self.assertEqual((got["length"], got["head"], got["container"], got["kind"], got["timeout"], got["timed"]),
                         (1002, "okxxxxxx", "tgz", "npm", 7, False))
        self.assertNotEqual(got["pid"], os.getpid())                        # (a process of its own)
        self.assertEqual(os.listdir(p._dir), [])
        self.assertTrue(p.run(b"ok", "zip", "pypi", 7, True)["timed"])

    def test_the_file_is_gone_after_an_error_too(self):
        p = self.pool(support.behave)
        with self.assertRaisesRegex(ValueError, "boom"):
            p.run(b"raise", "tgz", "npm", 7)
        self.assertEqual(os.listdir(p._dir), [])

    def test_an_archive_does_not_travel_as_a_pickle(self):
        sizes = []

        class Spy(concurrent.futures.ProcessPoolExecutor):
            def submit(self, fn, *args, **kwargs):
                sizes.append(len(pickle.dumps((fn, args))))
                return super().submit(fn, *args, **kwargs)

        p = self.pool()
        with mock.patch.object(scanpool.concurrent.futures, "ProcessPoolExecutor", Spy):
            got = p.run(b"ok" + bytes(5 * MB), "tgz", "npm", 7)
        self.assertEqual(got["length"], 5 * MB + 2)
        self.assertEqual(len(sizes), 2)                                      # (the trivial first job, then the archive)
        self.assertLess(max(sizes), 2000)

    def test_bytes_that_are_not_the_ones_staged_are_not_scanned(self):
        class Swapping(scanpool.WorkerPool):
            def stage(self, data):
                path, digest = super().stage(data)
                with open(path, "wb") as f:                                  # another process wrote to it in between
                    f.write(b"other bytes")
                return path, digest

        p = Swapping(1, support.echo)
        self.addCleanup(p.close)
        with self.assertRaisesRegex(scanpool.ArchiveChanged, "changed on its way"):
            p.run(b"ok", "tgz", "npm", 7)
        self.assertEqual(os.listdir(p._dir), [])

    def test_the_hand_off_and_the_wait_are_spans(self):
        p = self.pool()
        with timings.capture() as t:
            p.run(b"ok", "tgz", "npm", 7)
        by = t.report()["phases"]["scan"]["by"]
        self.assertEqual({k: v["calls"] for k, v in by.items()}, {"hand off": 1, "queue": 1, "wait for worker": 1})

    def test_close_ends_a_worker_that_is_busy_and_the_archive_waiting_on_it_is_unavailable(self):
        p = pool(support.behave)
        outcome = []

        def go():
            try:
                outcome.append(p.run(b"sleep:60", "tgz", "npm", 7))
            except Exception as exc:                                         # noqa: BLE001
                outcome.append(exc)

        t = threading.Thread(target=go)
        t.start()
        while p._running < 1 or p._pool is None:
            t.join(0.01)
        t.join(1.0)                                                          # (the worker has the archive by now)
        procs = list((getattr(p._pool, "_processes", None) or {}).values())
        self.assertTrue(procs and all(proc.is_alive() for proc in procs))
        p.close()
        t.join(30)
        self.assertFalse(t.is_alive())
        self.assertIsInstance(outcome[0], scanpool.Unavailable)
        for proc in procs:
            proc.join(10)
        self.assertFalse(any(proc.is_alive() for proc in procs))

    def test_close_waits_for_the_workers_and_the_thread_it_ended(self):
        # N-22: the interpreter waits at its exit for a pool's workers and its manager thread, and under load a test
        # process outlived its time box waiting for them; close ends them and waits (CLOSE_WAIT at most)
        p = pool(support.behave, jobs=2)
        p.run(b"ok", "tgz", "npm", 7)
        procs = list((getattr(p._pool, "_processes", None) or {}).values())
        pids, thread = [proc.pid for proc in procs], p._pool._executor_manager_thread
        self.assertTrue(pids and thread is not None and thread.is_alive())
        p.close()
        self.assertFalse(thread.is_alive())
        self.assertTrue({c.pid for c in multiprocessing.active_children()}.isdisjoint(pids))

    def test_a_pool_that_never_ran_closes_without_a_word(self):
        p = pool()
        p.close()
        self.assertIsNone(p._dir)

    def test_close_removes_the_directory_and_the_pool_is_closed(self):
        p = pool()
        p.run(b"ok", "tgz", "npm", 7)
        folder = p._dir
        self.assertTrue(os.path.isdir(folder))
        p.close()
        self.assertFalse(os.path.exists(folder))
        with self.assertRaises(scanpool.Unavailable):
            p.run(b"ok", "tgz", "npm", 7)
        p.close()                                                            # twice is harmless


class LimitTests(Case):
    def test_the_engine_threads_are_the_cores_shared_out_among_the_archives_running(self):
        p = self.pool(support.behave, jobs=2)
        first = []
        t = threading.Thread(target=lambda: first.append(p.run(b"sleep:2", "tgz", "npm", 7)))
        t.start()
        while p._running < 1:
            t.join(0.01)
        second = p.run(b"ok", "tgz", "npm", 7)
        t.join()
        self.assertEqual((first[0]["threads"], second["threads"]), (scanpool.threads_for(1), scanpool.threads_for(2)))

    def test_the_wall_limit_is_for_the_scan_and_not_for_the_wait_for_a_worker(self):
        p = self.pool(support.behave, jobs=1, wall=3.0)
        answers = []
        threads = [threading.Thread(target=lambda: answers.append(p.run(b"sleep:1.2", "tgz", "npm", 7)))
                   for _ in range(4)]                                       # (4 x 1.2 s on one worker: 4.8 s in all)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual([a["kind"] for a in answers], ["npm"] * 4)
        self.assertEqual(p.breaks, 0)

    def test_no_more_archives_run_at_once_than_there_are_workers(self):
        p = self.pool(support.behave, jobs=2)
        seen = []
        real = p._wait

        def wait(pool, args, wall):
            seen.append(p._running)
            return real(pool, args, wall)

        with mock.patch.object(p, "_wait", wait):
            threads = [threading.Thread(target=p.run, args=(b"sleep:0.4", "tgz", "npm", 7)) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(len(seen), 5)
        self.assertLessEqual(max(seen), 2)

    def test_a_number_of_threads_can_be_fixed(self):
        p = self.pool(jobs=2, threads=3)
        self.assertEqual(p.run(b"ok", "tgz", "npm", 7)["threads"], 3)

    @unittest.skipUnless(LINUX_LIMITS, "the address-space limit is Linux's")
    def test_a_worker_runs_under_an_address_space_limit(self):
        _, hard = resource.getrlimit(resource.RLIMIT_AS)
        soft = resource.getrlimit(resource.RLIMIT_AS)[0]
        want = 2048 * MB if soft == resource.RLIM_INFINITY else min(soft, 2048 * MB)
        self.assertEqual(self.pool(memory_mb=2048).run(b"ok", "tgz", "npm", 7)["as"], want)
        self.assertEqual(self.pool(memory_mb=0).run(b"ok", "tgz", "npm", 7)["as"], soft)    # none asked for: as it was

    @unittest.skipUnless(LINUX_LIMITS, "the address-space limit is Linux's")
    def test_a_scan_that_asks_for_more_than_the_limit_gets_a_memory_error(self):
        p = self.pool(support.behave, memory_mb=1024)
        self.assertEqual(p.run(b"alloc:64", "tgz", "npm", 7), {"allocated": 64 * MB})
        with self.assertRaises(MemoryError):
            p.run(b"alloc:1600", "tgz", "npm", 7)
        self.assertEqual(p.breaks, 0)                                         # (an error in the worker, not a lost worker)
        self.assertEqual(p.run(b"alloc:64", "tgz", "npm", 7), {"allocated": 64 * MB})

    @unittest.skipIf(resource is None, "no CPU limit here")
    def test_each_archive_gets_its_own_cpu_limit(self):
        p = self.pool(cpu=100)
        for _ in range(2):
            got = p.run(b"ok", "tgz", "npm", 7)
            self.assertTrue(100 <= got["cpu"] <= 160, got["cpu"])             # (the CPU used so far, plus 100)
        scale = self.pool(jobs=1, threads=2)
        self.assertTrue(2 * (2 * 7 + 30) <= scale.run(b"ok", "tgz", "npm", 7)["cpu"] <= 2 * (2 * 7 + 30) + 60)

    @unittest.skipIf(resource is None, "no CPU limit here")
    def test_no_cpu_limit_when_none_is_asked_for(self):
        got = self.pool(cpu=0).run(b"ok", "tgz", "npm", 7)
        self.assertEqual(got["cpu"], resource.getrlimit(resource.RLIMIT_CPU)[0])

    @unittest.skipIf(resource is None, "no CPU limit here")
    def test_a_scan_that_ignores_its_deadline_is_ended_by_the_cpu_limit(self):
        p = self.pool(support.behave, cpu=1, wall=60)
        with self.assertRaisesRegex(scanpool.Died, "lost on this archive, also when it ran alone"):
            p.run(b"spin", "tgz", "npm", 7)
        self.assertEqual(p.run(b"ok", "tgz", "npm", 7)["kind"], "npm")       # the pool goes on

    def test_a_scan_that_does_not_answer_ends_its_workers(self):
        p = self.pool(support.behave, wall=1.5)
        with self.assertRaisesRegex(scanpool.Hung, "did not finish"):
            p.run(b"hang", "tgz", "npm", 7)
        self.assertEqual(p.run(b"ok", "tgz", "npm", 7)["kind"], "npm")
        self.assertEqual(p.breaks, 0)                                         # (a hung scan is not a lost worker)


class LostWorkerTests(Case):
    def test_an_archive_that_ends_its_worker_is_died_and_the_pool_goes_on(self):
        p = self.pool(support.behave)
        with self.assertRaisesRegex(scanpool.Died, "lost on this archive, also when it ran alone"):
            p.run(b"crash", "tgz", "npm", 7)
        self.assertEqual(p.breaks, 2)                                         # (in the shared pool, and alone)
        self.assertEqual(p.run(b"ok", "tgz", "npm", 7)["kind"], "npm")
        self.assertEqual(os.listdir(p._dir), [])

    def test_a_worker_lost_once_is_not_the_archives_fault(self):
        marker = os.path.join(tempfile.mkdtemp(), "marker")
        self.addCleanup(lambda: os.path.exists(marker) and os.unlink(marker))
        p = self.pool(support.behave)
        got = p.run(b"crash-once:" + marker.encode(), "tgz", "npm", 7)
        self.assertEqual(got["kind"], "npm")
        self.assertEqual(p.breaks, 1)

    def test_the_archives_in_flight_with_the_one_that_died_are_scanned(self):
        p = self.pool(support.behave, jobs=2)
        answers = {}

        def go(name, data):
            try:
                answers[name] = p.run(data, "tgz", "npm", 7)
            except Exception as exc:                                         # noqa: BLE001
                answers[name] = exc

        threads = [threading.Thread(target=go, args=(n, d)) for n, d in
                   (("bad", b"crash"), ("a", b"sleep:0.5"), ("b", b"sleep:0.5"), ("c", b"ok"))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertIsInstance(answers["bad"], scanpool.Died)
        self.assertEqual([answers[n]["kind"] for n in "abc"], ["npm"] * 3)
        self.assertGreaterEqual(p.breaks, 2)

    def test_after_too_many_lost_workers_no_more_are_started_and_it_is_never_unavailable(self):
        p = self.pool(support.behave)
        with mock.patch.object(scanpool, "MAX_BREAKS", 2):
            with self.assertRaises(scanpool.Died):
                p.run(b"crash", "tgz", "npm", 7)
            self.assertEqual(p.breaks, 2)
            with self.assertRaisesRegex(scanpool.Died, "2 scan workers have been lost"):
                p.run(b"ok", "tgz", "npm", 7)                                # (not Unavailable: that is a scan here)

    def test_a_retry_is_not_made_once_too_many_workers_have_been_lost(self):
        marker = os.path.join(tempfile.mkdtemp(), "marker")
        self.addCleanup(lambda: os.path.exists(marker) and os.unlink(marker))
        p = self.pool(support.behave)
        with mock.patch.object(scanpool, "MAX_BREAKS", 1):
            with self.assertRaisesRegex(scanpool.Died, "workers keep being lost"):
                p.run(b"crash-once:" + marker.encode(), "tgz", "npm", 7)       # (it would have passed alone)
        self.assertEqual(p.breaks, 1)

    def test_a_pool_closed_while_an_archive_waits_for_its_retry_is_unavailable(self):
        p = self.pool(support.behave, jobs=2)
        real = p._make

        def make(workers):
            pool = real(workers)
            if workers == 1:
                p.close()
            return pool

        with mock.patch.object(p, "_make", make), self.assertRaisesRegex(scanpool.Unavailable, "closed"):
            p.run(b"crash", "tgz", "npm", 7)
        self.assertEqual(p._live, [])

    def test_a_retry_that_cannot_start_a_worker_is_died_not_unavailable(self):
        p = self.pool(support.behave, jobs=2)
        real = p._make
        calls = []

        def make(workers):
            calls.append(workers)
            if workers == 1:
                raise scanpool.Unavailable("no more processes")
            return real(workers)

        with mock.patch.object(p, "_make", make):
            with self.assertRaisesRegex(scanpool.Died, "no worker could be started to run it alone"):
                p.run(b"crash", "tgz", "npm", 7)
        self.assertEqual(calls, [2, 1])                                       # (the shared pool, then one for the retry)

    def test_an_error_of_the_scan_itself_is_passed_on(self):
        p = self.pool(support.behave)
        with self.assertRaisesRegex(ValueError, "boom"):
            p.run(b"raise", "tgz", "npm", 7)
        self.assertEqual(p.breaks, 0)


class FakePool:
    """What `_retire` and `_alone_run` see of a `ProcessPoolExecutor`: processes, `shutdown` and `submit`."""

    def __init__(self, processes=2):
        self._processes = {n: mock.Mock() for n in range(processes)}
        self.shutdown = mock.Mock()
        self.submit = mock.Mock()

    def terminated(self):
        return [proc.terminate.called for proc in self._processes.values()]


class BookkeepingTests(Case):
    """What the pool does to its own records, without a process to start: who is retired, killed, counted, tracked."""

    def test_a_pool_is_retired_with_its_processes_ended_only_when_asked(self):
        p = pool()
        quiet, killed = FakePool(), FakePool()
        p._retire(quiet)
        p._retire(killed, kill=True)
        self.assertEqual((quiet.terminated(), killed.terminated()), ([False, False], [True, True]))
        for fake in (quiet, killed):                                          # (and no waiting for what is left)
            fake.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_retiring_a_pool_survives_what_a_dying_one_does(self):
        p = pool()
        fake = FakePool()
        fake._processes[0].terminate.side_effect = OSError("gone")
        fake._processes[1].terminate.side_effect = AttributeError("no such")
        fake.shutdown.side_effect = RuntimeError("already")
        p._retire(fake, kill=True)
        self.assertEqual(fake.terminated(), [True, True])
        bare = mock.Mock(spec=["shutdown"])                                    # (an executor that has no processes to speak of)
        p._retire(bare, kill=True)
        bare.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_an_old_pool_that_is_retired_late_leaves_the_current_one_alone(self):
        p = pool()
        old, current = FakePool(), FakePool()
        p._pool, p._live = current, [current, old]
        p._retire(old)
        self.assertIs(p._pool, current)
        self.assertEqual(p._live, [current])
        p._retire(current)
        self.assertIsNone(p._pool)
        self.assertEqual(p._live, [])

    def test_a_lost_worker_is_counted_once_by_the_first_thread_that_sees_it(self):
        p = pool()
        current, other = FakePool(), FakePool()
        p._pool, p._live = current, [current]
        p._lost(other)                                                         # (a pool that was retired already)
        self.assertEqual(p.breaks, 0)
        p._lost(current)
        p._lost(current)                                                       # (the second thread to see it)
        self.assertEqual(p.breaks, 1)
        self.assertIsNone(p._pool)

    def test_a_pool_that_exists_is_handed_out_without_waiting_for_the_one_that_makes_pools(self):
        p = self.pool(support.behave)
        p.run(b"ok", "tgz", "npm", 7)
        got = []
        with p._start:                                                         # (another thread is starting a pool)
            t = threading.Thread(target=lambda: got.append(p._shared()))
            t.start()
            t.join(10)
            self.assertFalse(t.is_alive())
        self.assertIs(got[0], p._pool)

    def test_a_closed_pool_hands_out_nothing(self):
        p = self.pool(support.behave)
        p.run(b"ok", "tgz", "npm", 7)
        p.close()
        with self.assertRaisesRegex(scanpool.Unavailable, "closed"):
            p._shared()

    def test_a_thread_that_waited_for_the_pool_to_be_made_takes_the_one_that_was_made(self):
        p = pool(support.behave)
        fake = FakePool()
        got, errors = [], []

        def ask():
            try:
                got.append(p._shared())
            except BaseException as exc:                                       # (a thread's error would be lost)
                errors.append(exc)
        with mock.patch.object(p, "_make", side_effect=AssertionError("made another pool")):
            with p._start:                                                     # (another thread is making one)
                t = threading.Thread(target=ask)
                t.start()
                t.join(0.3)
                self.assertTrue(t.is_alive())                                  # (waiting for it)
                with p._lock:
                    p._pool = fake                                             # (and it is made)
            t.join(10)
        self.assertEqual((errors, got), ([], [fake]))

    def test_no_timings_unless_asked_for(self):
        p = self.pool(support.behave)
        self.assertIs(p.run(b"ok", "tgz", "npm", 7)["timed"], False)
        self.assertIs(p.run(b"ok", "tgz", "npm", 7, True)["timed"], True)
        self.assertIs(p.run(b"ok", "tgz", "npm", 7, timed=True)["timed"], True)

    def test_the_limits_an_archive_gets_unless_the_pool_was_given_others(self):
        for kw, wall, cpu in (({"threads": 1}, 74, 44), ({"threads": 3}, 74, 132),
                              ({"threads": 1, "wall": 5, "cpu": 9}, 5, 9), ({"threads": 1, "wall": 0.5}, 0.5, 44)):
            p = self.pool(support.behave, **kw)
            seen = []
            real = p._wait

            def wait(pool_, args, wall_, real=real, seen=seen):
                seen.append((wall_, args[7], args[8]))
                return real(pool_, args, wall_)
            with self.subTest(kw=kw), mock.patch.object(p, "_wait", wait):
                p.run(b"ok", "tgz", "npm", 7)
                self.assertEqual(seen, [(wall, cpu, kw["threads"])])

    @unittest.skipIf(resource is None, "no CPU limit here")
    def test_the_cpu_limit_is_the_user_and_the_system_time_so_far_plus_the_budget(self):
        used = mock.Mock(ru_utime=10.0, ru_stime=5.0)
        infinite = resource.RLIM_INFINITY
        with mock.patch.object(resource, "getrusage", return_value=used), \
                mock.patch.object(resource, "getrlimit", return_value=(infinite, infinite)), \
                mock.patch.object(resource, "setrlimit") as setrlimit:
            scanpool._cpu_limit(300)
        setrlimit.assert_called_once_with(resource.RLIMIT_CPU, (315, infinite))

    @unittest.skipIf(resource is None, "no CPU limit here")
    def test_the_cpu_limit_never_raises_the_hard_limit_asks_for_nothing_and_survives_a_refusal(self):
        used = mock.Mock(ru_utime=10.0, ru_stime=5.0)
        with mock.patch.object(resource, "getrusage", return_value=used), \
                mock.patch.object(resource, "getrlimit", return_value=(resource.RLIM_INFINITY, 100)), \
                mock.patch.object(resource, "setrlimit") as setrlimit:
            scanpool._cpu_limit(300)                                           # (the hard limit is 100 s)
        setrlimit.assert_called_once_with(resource.RLIMIT_CPU, (100, 100))
        for seconds in (0, None):
            with self.subTest(seconds=seconds), mock.patch.object(resource, "setrlimit") as setrlimit:
                scanpool._cpu_limit(seconds)
                setrlimit.assert_not_called()
        with mock.patch.object(scanpool, "resource", None):
            scanpool._cpu_limit(300)                                           # (no `resource` module: nothing to set)
        for error in (ValueError, OSError):
            with self.subTest(error=error), mock.patch.object(resource, "setrlimit", side_effect=error):
                scanpool._cpu_limit(300)                                       # (the kernel said no: the scan goes on)

    def test_a_pool_closed_before_the_retry_ends_the_pool_it_made_for_it(self):
        p = pool(support.behave)
        fake = FakePool()
        p._closed = True
        with mock.patch.object(p, "_make", return_value=fake), self.assertRaisesRegex(scanpool.Unavailable, "closed"):
            p._alone_run((), 5)
        self.assertEqual(fake.terminated(), [True, True])
        self.assertEqual(p._live, [])

    def test_the_pool_made_for_a_retry_is_closed_with_the_pool_and_forgotten_after(self):
        p = pool(support.behave)
        fake = FakePool()
        seen = []
        with mock.patch.object(p, "_make", return_value=fake), \
                mock.patch.object(p, "_wait", side_effect=lambda pool_, args, wall: seen.append(list(p._live)) or "answer"):
            self.assertEqual(p._alone_run((), 5), "answer")
        self.assertEqual(seen, [[fake]])
        self.assertEqual(p._live, [])
        fake.shutdown.assert_called_once_with(wait=False, cancel_futures=True)

    def test_closing_is_quiet_when_the_staging_folder_is_already_gone(self):
        p = self.pool(support.behave)
        p.run(b"ok", "tgz", "npm", 7)
        folder = p._dir
        shutil.rmtree(folder)
        p.close()                                                             # (someone cleaned the temp folder)
        self.assertFalse(os.path.exists(folder))
        p.close()

    def test_workers_that_cannot_run_a_trivial_job_are_ended_and_forgotten(self):
        p = pool(support.behave)
        fake = FakePool()
        future = mock.Mock()
        future.result.side_effect = concurrent.futures.process.BrokenProcessPool("died")
        fake.submit.return_value = future
        with mock.patch.object(p, "_make", return_value=fake), self.assertRaisesRegex(
                scanpool.Unavailable, r"a worker could not start \(BrokenProcessPool\)"):
            p._shared()
        self.assertEqual(fake.terminated(), [True, True])                     # (not left running)
        self.assertEqual((p._live, p._pool), ([], None))
        with mock.patch.object(p, "_make", side_effect=AssertionError("asked twice")), self.assertRaises(
                scanpool.Unavailable):
            p._shared()                                                       # (and it is not tried again)

    def test_the_count_of_archives_running_is_one_while_one_runs_and_zero_when_none_do(self):
        p = self.pool(support.behave, jobs=2)
        seen = []
        real = p._wait

        def wait(pool_, args, wall):
            seen.append((p._running, args[8]))
            return real(pool_, args, wall)
        with mock.patch.object(p, "_wait", wait):
            for _ in range(3):
                p.run(b"ok", "tgz", "npm", 7)
        self.assertEqual([running for running, _threads in seen], [1, 1, 1])
        self.assertEqual(p._running, 0)
        with mock.patch.object(p, "_wait", side_effect=scanpool.Hung("x")), self.assertRaises(scanpool.Hung):
            p.run(b"ok", "tgz", "npm", 7)
        self.assertEqual(p._running, 0)

    def test_an_archive_that_cannot_be_written_leaves_no_file_behind(self):
        p = self.pool(support.behave)
        opened = []
        real_open = os.open

        def record(*args, **kw):
            opened.append(real_open(*args, **kw))
            return opened[-1]
        writer = mock.MagicMock()
        writer.__enter__.return_value.write.side_effect = OSError("disk full")
        with mock.patch.object(scanpool.os, "open", record), mock.patch.object(scanpool.os, "fdopen", return_value=writer):
            with self.assertRaisesRegex(OSError, "disk full"):
                p.stage(b"archive")
        for fd in opened:
            os.close(fd)
        self.assertEqual(os.listdir(p._dir), [])


class StartTests(Case):
    def test_a_pool_that_cannot_be_made_is_unavailable_and_that_is_remembered(self):
        made = []

        def refuse(*args, **kwargs):
            made.append(1)
            raise OSError("no processes")

        p = self.pool()
        with mock.patch.object(scanpool.concurrent.futures, "ProcessPoolExecutor", refuse):
            for _ in range(2):
                with self.assertRaisesRegex(scanpool.Unavailable, "OSError: no processes"):
                    p.run(b"ok", "tgz", "npm", 7)
        self.assertEqual(len(made), 1)
        self.assertEqual(os.listdir(p._dir), [])

    def test_a_worker_that_cannot_start_is_unavailable_and_every_thread_hears_it(self):
        p = self.pool()
        results = []

        def go():
            try:
                p.run(b"ok", "tgz", "npm", 7)
                results.append("ran")
            except scanpool.Unavailable as exc:
                results.append(str(exc))

        with mock.patch.object(scanpool, "_ping", support.exit_now):
            threads = [threading.Thread(target=go) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
        self.assertEqual(len(results), 4)
        self.assertTrue(all(r.startswith("a worker could not start (BrokenProcessPool)") for r in results), results)
        self.assertEqual(p.breaks, 0)
        self.assertEqual(p._live, [])

    def test_once_a_pool_has_worked_a_lost_worker_is_not_a_failure_to_start(self):
        p = self.pool(support.behave)
        p.run(b"ok", "tgz", "npm", 7)
        with mock.patch.object(scanpool, "_ping", support.exit_now):          # (not asked again)
            with self.assertRaises(scanpool.Died):
                p.run(b"crash", "tgz", "npm", 7)
            self.assertEqual(p.run(b"ok", "tgz", "npm", 7)["kind"], "npm")

    def test_one_pool_serves_every_archive_and_pools_do_not_pile_up(self):
        p = self.pool(jobs=2)
        for _ in range(3):
            p.run(b"ok", "tgz", "npm", 7)
        self.assertEqual(len(p._live), 1)
        bad = self.pool(support.behave)
        with self.assertRaises(scanpool.Died):
            bad.run(b"crash", "tgz", "npm", 7)
        self.assertEqual(bad._live, [])                                       # (the broken one and the one for the retry are done)


FLAGS_DRIVER = """\
import json, multiprocessing, multiprocessing.spawn, multiprocessing.util, subprocess, sys
sys.path[:0] = [{py_root!r}, {src!r}]
from lazaret.registry import scanpool
from tests.registry import _scanpool_support as support


def child(queue):
    queue.put(sys.flags.isolated)


def unrelated():
    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(target=child, args=(queue,))
    proc.start()
    try:
        return queue.get(timeout=60)
    finally:
        proc.join(60)


def stdlib():
    return multiprocessing.util._args_from_interpreter_flags is subprocess._args_from_interpreter_flags


def worker(pool):
    return pool.run(b"ok", "tgz", "npm", 7)["isolated"]


if __name__ == "__main__":
    out = {{"before": unrelated(), "stdlib before": stdlib()}}
    one, two = scanpool.WorkerPool(1, support.flags, isolated=True), scanpool.WorkerPool(1, support.flags, isolated=True)
    out["worker"], out["second worker"] = worker(one), worker(two)
    cmd = multiprocessing.spawn.get_command_line(pipe_handle=0)
    out["command line"] = cmd.count("-I") == 1 and cmd.index("-I") < cmd.index("-c")
    out["unrelated while open"] = unrelated()
    one.close()
    out["stdlib with one still open"] = stdlib()
    two.close()
    out["stdlib after"], out["after"] = stdlib(), unrelated()
    plain = scanpool.WorkerPool(1, support.flags)
    out["library pool worker"], out["stdlib with a library pool"] = worker(plain), stdlib()
    plain.close()

    def theirs():
        return ["-B"]

    multiprocessing.util._args_from_interpreter_flags = theirs
    third = scanpool.WorkerPool(1, support.flags, isolated=True)
    try:
        worker(third)
        out["over another library's"] = "ran"
    except scanpool.Unavailable:
        out["over another library's"] = "Unavailable"
    third.close()
    out["theirs kept"] = multiprocessing.util._args_from_interpreter_flags is theirs
    print(json.dumps(out))
"""


OWNERSHIP_DRIVER = """\
import concurrent.futures, functools, json, multiprocessing.util, subprocess, sys, threading
from unittest import mock
sys.path[:0] = [{py_root!r}, {src!r}]
from lazaret.registry import scanpool
from tests.registry import _scanpool_support as support

STDLIB = subprocess._args_from_interpreter_flags
REPLACED = getattr(scanpool, "FlagsReplaced", scanpool.Unavailable)     # (so that an older pool fails on what it does)


def worker(pool):
    try:
        return pool.run(b"ok", "tgz", "npm", 7)["isolated"]
    except REPLACED:
        return "FlagsReplaced"
    except scanpool.Unavailable as exc:
        return "Unavailable: " + str(exc)


def theirs():
    return ["-B"]


def in_place():
    return multiprocessing.util._args_from_interpreter_flags


if __name__ == "__main__":
    out = {{}}
    # another library replaces the function while an isolated pool is open
    one = scanpool.WorkerPool(1, support.flags, isolated=True)
    two = scanpool.WorkerPool(1, support.flags, isolated=True)
    out["first"] = worker(one)
    multiprocessing.util._args_from_interpreter_flags = theirs
    out["second pool after the replacement"] = worker(two)
    out["first pool after the replacement"] = worker(one)
    try:
        one._make(1)
        out["first pool's new executor"] = "made"
    except REPLACED:
        out["first pool's new executor"] = "FlagsReplaced"
    two.close(), one.close()
    out["theirs kept"], out["holders"] = in_place() is theirs, scanpool._flags_holders
    multiprocessing.util._args_from_interpreter_flags = STDLIB
    # a wrapper of the stand-in (functools.wraps copies its attributes) is another library's
    three = scanpool.WorkerPool(1, support.flags, isolated=True)
    out["third"] = worker(three)
    ours = in_place()

    @functools.wraps(ours)
    def wrapped():
        return ours()

    multiprocessing.util._args_from_interpreter_flags = wrapped
    three.close()
    out["wrapper kept"] = in_place() is wrapped
    multiprocessing.util._args_from_interpreter_flags = STDLIB
    # close() while the shared executor is being made: the flags are held until that is over, and the executor
    # is ended, never published or given a job
    entered, resume, submitted = threading.Event(), threading.Event(), []
    real = concurrent.futures.ProcessPoolExecutor

    def counted(executor):
        submit = executor.submit

        def recorded(*args, **kwargs):
            submitted.append(args[0].__name__)          # (a submission is where a worker is started)
            return submit(*args, **kwargs)

        executor.submit = recorded
        return executor

    def paused(*args, **kwargs):
        entered.set()
        resume.wait(30)
        return counted(real(*args, **kwargs))

    def start(pool, errors):
        try:
            pool._shared()
        except scanpool.Unavailable as exc:
            errors.append(str(exc))

    four, errors = scanpool.WorkerPool(1, support.flags, isolated=True), []
    with mock.patch.object(concurrent.futures, "ProcessPoolExecutor", paused):
        thread = threading.Thread(target=start, args=(four, errors))
        thread.start()
        entered.wait(30)
        four.close()
        out["held while it is made"] = scanpool._flags_holders == 1 and in_place() is not STDLIB
        resume.set()
        thread.join(30)
    out["making"] = {{"errors": errors, "live": len(four._live), "submitted": submitted,
                     "holders": scanpool._flags_holders, "stdlib back": in_place() is STDLIB}}
    # close() after the executor is published, before its first job: no job is submitted
    five, errors, submitted = scanpool.WorkerPool(1, support.flags, isolated=True), [], []
    if not hasattr(five, "_publish"):
        out["published"] = "no _publish"                    # (an older pool: the step is not there to pause)
    else:
        entered, resume = threading.Event(), threading.Event()
        publish = five._publish

        def paused_publish(pool):
            publish(counted(pool))
            entered.set()
            resume.wait(30)

        five._publish = paused_publish
        thread = threading.Thread(target=start, args=(five, errors))
        thread.start()
        entered.wait(30)
        five.close()
        resume.set()
        thread.join(30)
        out["published"] = {{"errors": errors, "live": len(five._live), "submitted": submitted,
                            "holders": scanpool._flags_holders, "stdlib back": in_place() is STDLIB}}
        # replaced after it is published, before its first job: no job, and the executor is ended
        six, errors, submitted = scanpool.WorkerPool(1, support.flags, isolated=True), [], []
        entered, resume = threading.Event(), threading.Event()
        publish = six._publish

        def paused_publish(pool):
            publish(counted(pool))
            entered.set()
            resume.wait(30)

        six._publish = paused_publish
        thread = threading.Thread(target=start, args=(six, errors))
        thread.start()
        entered.wait(30)
        multiprocessing.util._args_from_interpreter_flags = theirs
        resume.set()
        thread.join(30)
        out["replaced after it is published"] = {{"errors": [e.split(":")[0] for e in errors], "live": len(six._live),
                                                 "submitted": submitted}}
        six.close()
        multiprocessing.util._args_from_interpreter_flags = STDLIB
    print(json.dumps(out))
"""


LIFECYCLE_DRIVER = """\
import concurrent.futures, json, multiprocessing.resource_tracker, multiprocessing.util, os, subprocess, sys, tempfile
import threading, time
from unittest import mock
sys.path[:0] = [{py_root!r}, {src!r}]
from lazaret.registry import scanpool
from tests.registry import _scanpool_support as support

STDLIB = subprocess._args_from_interpreter_flags


def in_place():
    return multiprocessing.util._args_from_interpreter_flags


def worker(pool, data=b"ok"):
    try:
        return pool.run(data, "tgz", "npm", 7)["isolated"]
    except scanpool.Unavailable as exc:
        return type(exc).__name__
    except scanpool.Died:
        return "Died"


def theirs():
    return STDLIB()


def tracker_flags():
    \"\"\"The resource tracker's flags (before its -c), or None where there is no tracker.\"\"\"
    pid = getattr(multiprocessing.resource_tracker._resource_tracker, "_pid", None)
    if os.name != "posix" or pid is None:
        return None
    try:
        with open(f"/proc/{{pid}}/cmdline", "rb") as f:
            argv = [os.fsdecode(a) for a in f.read().split(b"\\0") if a]
    except OSError:
        argv = subprocess.run(["ps", "-o", "args=", "-p", str(pid)], capture_output=True, encoding="utf-8",
                              errors="replace").stdout.split()
    return argv[1:argv.index("-c")] if "-c" in argv else argv[1:]


if __name__ == "__main__":
    out = {{}}
    # the resource tracker starts with the pool's first executor: with -I too
    one = scanpool.WorkerPool(1, support.flags_or_crash, isolated=True)
    out["first"] = worker(one)
    out["tracker has -I"] = None if tracker_flags() is None else "-I" in tracker_flags()
    # a second isolated pool refused at its acquisition holds nothing
    multiprocessing.util._args_from_interpreter_flags = theirs
    two = scanpool.WorkerPool(1, support.flags, isolated=True)
    out["second pool"] = [worker(two), scanpool._flags_holders, two._holds_flags]
    two.close()
    multiprocessing.util._args_from_interpreter_flags = scanpool._flags_installed
    # a replacement while an archive is lost and run alone: FlagsReplaced (the guard scans in its own process),
    # not Died (which blocks the package)
    lost = one._lost

    def replaced_when_lost(pool):
        multiprocessing.util._args_from_interpreter_flags = theirs
        lost(pool)

    one._lost = replaced_when_lost
    out["lost, then replaced"] = worker(one, b"crash")
    one._lost = lost
    multiprocessing.util._args_from_interpreter_flags = scanpool._flags_installed
    # one pool closed twice lets go once: another open pool keeps its hold
    three = scanpool.WorkerPool(1, support.flags, isolated=True)
    out["third"] = worker(three)
    one.close(), one.close()
    out["one closed twice"] = [scanpool._flags_holders, in_place() is scanpool._flags_installed, worker(three)]
    three.close()
    out["stdlib back"] = in_place() is STDLIB
    # the executor's construction raising: whatever it raises, the making is over and close lets go
    real = concurrent.futures.ProcessPoolExecutor
    out["construction raising"] = {{}}
    for exc_type in (OSError, RuntimeError, KeyboardInterrupt):
        def failing(*args, **kwargs):
            raise exc_type("made to fail")

        four = scanpool.WorkerPool(1, support.flags, isolated=True)
        concurrent.futures.ProcessPoolExecutor = failing
        try:
            four.run(b"ok", "tgz", "npm", 7)
            raised = "nothing"
        except BaseException as exc:
            raised = type(exc).__name__
        concurrent.futures.ProcessPoolExecutor = real
        four.close()
        out["construction raising"][exc_type.__name__] = [raised, four._starting, scanpool._flags_holders,
                                                          in_place() is STDLIB]
    # close() while the first job runs: "the pool is closed", not a worker that could not start
    mark = os.path.join(tempfile.mkdtemp(prefix="lazaret-ping-"), "running")
    os.environ["LAZARET_TEST_PING_MARK"] = mark
    five, errors = scanpool.WorkerPool(1, support.flags, isolated=True), []
    with mock.patch.object(scanpool, "_ping", support.ping_slowly):
        def start():
            try:
                five._shared()
            except scanpool.Unavailable as exc:
                errors.append(str(exc))

        thread = threading.Thread(target=start)
        thread.start()
        for _ in range(600):
            if os.path.exists(mark):
                break
            time.sleep(0.05)
        five.close()
        thread.join(30)
    out["close during the first job"] = [errors, scanpool._flags_holders, in_place() is STDLIB]
    # close() while an archive is run alone after its worker was lost: "the pool is closed" (the caller scans in
    # its own process), not Died pinned on that archive
    alone, result = scanpool.WorkerPool(1, support.crash_once_then_wait, isolated=True), []
    lost_once = os.path.join(tempfile.mkdtemp(prefix="lazaret-alone-"), "seen")

    def run_alone():
        try:
            alone.run(lost_once.encode(), "tgz", "npm", 7)
            result.append("ran")
        except scanpool.Unavailable as exc:
            result.append("Unavailable: " + str(exc))
        except scanpool.Died as exc:
            result.append("Died: " + str(exc))

    thread = threading.Thread(target=run_alone)
    thread.start()
    for _ in range(600):
        if os.path.exists(lost_once + ".running"):
            break
        time.sleep(0.05)
    alone.close()
    thread.join(30)
    out["close while run alone"] = [result, alone.breaks, scanpool._flags_holders]
    # another library saving the function and putting it back around the last close: the stand-in it puts back
    # passes the flags through, and the next isolated pool takes it for the function it wraps
    six = scanpool.WorkerPool(1, support.flags, isolated=True)
    worker(six)
    patcher = mock.patch.object(multiprocessing.util, "_args_from_interpreter_flags", theirs)
    patcher.start()
    six.close()
    patcher.stop()
    library = scanpool.WorkerPool(1, support.flags)
    seven = scanpool.WorkerPool(1, support.flags, isolated=True)
    out["stand-in put back"] = [scanpool._flags_holders, in_place() is not STDLIB, worker(library), worker(seven)]
    library.close(), seven.close()
    out["stdlib back at the end"] = in_place() is STDLIB
    print(json.dumps(out))
"""


class StandInLookupTests(unittest.TestCase):
    """Only a stand-in this module made, known by identity, is taken for the function it wraps; any other callable
    in place is another library's, and an isolated pool refuses it."""

    def setUp(self):
        self.assertEqual(scanpool._flags_holders, 0)
        self.addCleanup(setattr, multiprocessing.util, "_args_from_interpreter_flags",
                        multiprocessing.util._args_from_interpreter_flags)

    def test_a_callable_that_compares_equal_to_a_stand_in_is_not_taken(self):
        self.assertTrue(scanpool._isolate_flags())
        stale = multiprocessing.util._args_from_interpreter_flags              # (kept alive: still in the weak map)
        scanpool._release_flags()

        class Theirs:
            def __call__(self):
                return subprocess._args_from_interpreter_flags()

            def __hash__(self):
                return hash(stale)

            def __eq__(self, other):
                return True

        theirs = Theirs()
        multiprocessing.util._args_from_interpreter_flags = theirs
        self.assertFalse(scanpool._isolate_flags())
        self.assertIs(multiprocessing.util._args_from_interpreter_flags, theirs)
        self.assertEqual(scanpool._flags_holders, 0)

    def test_a_callable_that_takes_no_weak_reference_is_not_taken(self):
        class Theirs:
            __slots__ = ()                                       # (no __weakref__: a weak map can't hold it)

            def __call__(self):
                return ["-B"]

        theirs = Theirs()
        multiprocessing.util._args_from_interpreter_flags = theirs
        self.assertFalse(scanpool._isolate_flags())
        self.assertIs(multiprocessing.util._args_from_interpreter_flags, theirs)
        self.assertEqual(scanpool._flags_holders, 0)


class ClosedPoolTests(Case):
    """A closed pool makes nothing more: no executor (and so no resource tracker), no staging folder."""

    def test_a_closed_pool_makes_no_executor(self):
        p = self.pool()
        p.close()
        made = []
        with mock.patch.object(concurrent.futures, "ProcessPoolExecutor", lambda *a, **k: made.append(a)):
            with self.assertRaises(scanpool.Unavailable):
                p._make(1)
        self.assertEqual((made, p._starting), ([], 0))

    def test_a_closed_pool_stages_nothing(self):
        p = self.pool()
        p.close()
        with self.assertRaises(scanpool.Unavailable):
            p.run(b"ok", "tgz", "npm", 7)
        self.assertIsNone(p._dir)

    def test_a_close_while_an_archive_is_staged_is_reported_as_closed(self):
        p = self.pool()
        staging = p._staging

        def then_closed():
            folder = staging()
            p.close()                                                          # (which takes the folder away)
            return folder

        with mock.patch.object(p, "_staging", then_closed):
            with self.assertRaises(scanpool.Unavailable) as caught:
                p.stage(b"ok")
        self.assertEqual(str(caught.exception), "the pool is closed")
        other = self.pool()                                                    # (open: a folder gone is left as it is)
        shutil.rmtree(other._staging())
        with self.assertRaises(FileNotFoundError):
            other.stage(b"ok")


class HeldExecutor:
    """An executor whose jobs wait until it is shut down, when `ended` ends each one not done yet (cancelled, as a
    `ProcessPoolExecutor` cancels the jobs no worker has taken). `answer(fn, future)` may answer a job at once."""

    def __init__(self, answer=lambda fn, future: None, ended=lambda future: future.cancel()):
        self.answer, self.ended = answer, ended
        self.futures, self.held, self.shutdowns = [], threading.Event(), 0
        self._processes = {}

    def submit(self, fn, *args):
        future = concurrent.futures.Future()
        self.answer(fn, future)
        self.futures.append(future)
        if not future.done():
            self.held.set()
        return future

    def shutdown(self, wait=True, cancel_futures=False):
        self.shutdowns += 1
        for future in self.futures:
            if not future.done():
                self.ended(future)


def ping_answered(fn, future):
    if fn is scanpool._ping:
        future.set_result(True)


class CloseMidwayTests(Case):
    """close() while a thread is in the middle of the pool: that thread learns the pool is closed (Unavailable,
    which a scan answers by scanning in its own process), not a worker's loss or a job's cancellation."""

    def held(self, executor, call):
        """-> what `call` raised in another thread, closing the pool once the executor holds a job."""
        p, raised = self.pool(), []

        def go():
            try:
                call(p)
            except BaseException as exc:
                raised.append((type(exc).__name__, str(exc)))

        with mock.patch.object(concurrent.futures, "ProcessPoolExecutor", lambda *a, **k: executor):
            thread = threading.Thread(target=go)
            thread.start()
            self.assertTrue(executor.held.wait(10))
            p.close()
            thread.join(10)
        return raised, p

    def test_a_close_during_the_first_job_is_reported_as_closed(self):
        raised, p = self.held(HeldExecutor(), lambda p: p._shared())
        self.assertEqual(raised, [("Unavailable", "the pool is closed")])
        self.assertEqual(p._unavailable, "")                                  # (not a reason workers cannot be had)

    def test_a_close_during_a_scan_is_reported_as_closed(self):
        for ended in (lambda future: future.cancel(),                          # (its job had not been taken)
                      lambda future: future.set_exception(FileNotFoundError("gone"))):   # (its staged file went)
            raised, p = self.held(HeldExecutor(ping_answered, ended), lambda p: p.run(b"ok", "tgz", "npm", 7))
            self.assertEqual(raised, [("Unavailable", "the pool is closed")])
            self.assertEqual(p.breaks, 0)

    def test_a_job_cancelled_or_a_file_missing_while_the_pool_is_open_is_left_as_it_is(self):
        for answer, error in ((lambda fn, future: future.cancel(), "CancelledError"),
                              (lambda fn, future: future.set_exception(FileNotFoundError("gone")),
                               "FileNotFoundError")):
            p = self.pool()
            executor = HeldExecutor(lambda fn, future, answer=answer: (ping_answered if fn is scanpool._ping
                                                                       else answer)(fn, future))
            with mock.patch.object(concurrent.futures, "ProcessPoolExecutor", lambda *a, **k: executor):
                with self.assertRaises(Exception) as caught:
                    p.run(b"ok", "tgz", "npm", 7)
            self.assertEqual(type(caught.exception).__name__, error)

    def test_a_close_just_after_the_first_job_hands_out_no_pool(self):
        p = self.pool()

        def close_first(fn, future):
            p.close()
            future.set_result(True)

        executor = HeldExecutor(close_first)
        with mock.patch.object(concurrent.futures, "ProcessPoolExecutor", lambda *a, **k: executor):
            with self.assertRaises(scanpool.Unavailable) as caught:
                p._shared()
        self.assertEqual(str(caught.exception), "the pool is closed")
        self.assertIsNone(p._pool)
        self.assertGreaterEqual(executor.shutdowns, 1)


class WorkingFolderTests(unittest.TestCase):
    """F-01: a worker and the resource tracker start as `python -c '…'` in the guard's working directory, the
    project it is run in, which `-c` puts first on sys.path. A pool made with isolated=True (the guard's command
    line) starts them with -I while it is open; a library's own pool changes nothing. Each test runs a process of
    its own, so that this one's multiprocessing is never touched."""

    def driver(self, text, cwd=None):
        tmp = tempfile.mkdtemp(prefix="lazaret-pool-cwd-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        folder = os.path.join(tmp, "driver")
        os.makedirs(folder)
        with open(os.path.join(folder, "run_pool.py"), "w", encoding="utf-8") as f:
            f.write(text)
        # the guard's process as its console script runs it: a script (its own folder first on sys.path, not the
        # working directory), not isolated itself
        done = subprocess.run([sys.executable, os.path.join(folder, "run_pool.py")], cwd=cwd or tmp,
                              capture_output=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(done.stdout.strip().splitlines()[-1]), done

    def test_the_flags_are_isolated_while_an_isolated_pool_is_open_and_put_back(self):
        out, _done = self.driver(FLAGS_DRIVER.format(py_root=_support.PY_ROOT, src=_support.SRC))
        self.assertEqual(out, {
            "before": 0, "stdlib before": True,
            "worker": 1, "second worker": 1, "command line": True,
            "unrelated while open": 1,                 # (the scope: this process's children while the pool is open)
            "stdlib with one still open": False,
            "stdlib after": True, "after": 0,
            "library pool worker": 0, "stdlib with a library pool": True,
            "over another library's": "Unavailable", "theirs kept": True})

    def test_a_replacement_while_a_pool_is_open_and_a_close_while_one_starts(self):
        """Another library's function in place of the stand-in, put there while an isolated pool is open (or a
        wrapper of the stand-in): no new pool, executor or job of an isolated pool starts, and the last close
        leaves that function. A close while the executor is being made, or before its first job: the flags are
        held until the making is over, and the executor is ended without a worker. Deterministic (events)."""
        out, _done = self.driver(OWNERSHIP_DRIVER.format(py_root=_support.PY_ROOT, src=_support.SRC))
        self.maxDiff = None
        self.assertEqual(out, {
            "first": 1, "second pool after the replacement": "FlagsReplaced",
            "first pool after the replacement": "FlagsReplaced", "first pool's new executor": "FlagsReplaced",
            "theirs kept": True, "holders": 0,
            "third": 1, "wrapper kept": True,
            "held while it is made": True,
            "making": {"errors": ["the pool is closed"], "live": 0, "submitted": [], "holders": 0, "stdlib back": True},
            "published": {"errors": ["the pool is closed"], "live": 0, "submitted": [], "holders": 0,
                          "stdlib back": True},
            "replaced after it is published": {"errors": ["multiprocessing's flags for a child were replaced while "
                                                          "the pool was open"], "live": 0, "submitted": []}})

    def test_the_lifecycle_of_the_flags(self):
        """The resource tracker starts with -I too. A second isolated pool refused at its acquisition holds
        nothing; a replacement while an archive is run alone is FlagsReplaced, not Died; a pool closed twice lets
        go once; whatever the executor's construction raises, close lets go; a close while the first job runs, or
        while an archive is run alone, is "the pool is closed"; a stand-in another library puts back after the
        last close passes the flags through, and the next isolated pool takes it for the function it wraps."""
        out, _done = self.driver(LIFECYCLE_DRIVER.format(py_root=_support.PY_ROOT, src=_support.SRC))
        self.maxDiff = None
        self.assertEqual(out, {
            "first": 1, "tracker has -I": True if os.name == "posix" else None,
            "second pool": ["FlagsReplaced", 1, False],
            "lost, then replaced": "FlagsReplaced",
            "third": 1, "one closed twice": [1, True, 1], "stdlib back": True,
            "construction raising": {"OSError": ["Unavailable", 0, 0, True],
                                     "RuntimeError": ["RuntimeError", 0, 0, True],
                                     "KeyboardInterrupt": ["KeyboardInterrupt", 0, 0, True]},
            "close during the first job": [["the pool is closed"], 0, True],
            "close while run alone": [["Unavailable: the pool is closed"], 1, 0],
            "stand-in put back": [0, True, 0, 1], "stdlib back at the end": True})

    def test_a_process_run_with_dash_i_gets_it_once(self):
        """The stand-in puts -I first only when the flags lack it: a process run with -I passes it on once."""
        code = (f"import multiprocessing.util, sys\nsys.path[:0] = [{_support.PY_ROOT!r}, {_support.SRC!r}]\n"
                "from lazaret.registry import scanpool\nscanpool._isolate_flags()\n"
                "print(multiprocessing.util._args_from_interpreter_flags().count('-I'))\n")
        done = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, encoding="utf-8",
                              errors="replace", timeout=60)
        self.assertEqual(done.stdout.strip(), "1", done.stderr)

    def test_a_pool_run_in_a_project_imports_nothing_of_it(self):
        tmp = tempfile.mkdtemp(prefix="lazaret-pool-project-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        project, markers = os.path.join(tmp, "project"), os.path.join(tmp, "markers")
        os.makedirs(markers)
        for name in ("multiprocessing", "concurrent", "lazaret", "tests"):
            os.makedirs(os.path.join(project, name))
            with open(os.path.join(project, name, "__init__.py"), "w", encoding="utf-8") as f:
                f.write(f"import os\nopen(os.path.join({markers!r}, {name!r} + '-' + str(os.getpid())), 'w', "
                        f"encoding='utf-8').close()\n")
        out, done = self.driver(
            f"import json, sys\nsys.path[:0] = [{_support.PY_ROOT!r}, {_support.SRC!r}]\n"
            "from lazaret.registry import scanpool\nfrom tests.registry import _scanpool_support as support\n"
            "if __name__ == '__main__':\n"
            "    pool = scanpool.WorkerPool(1, support.behave, isolated=True)\n"
            "    try:\n        print(json.dumps(pool.run(b'ok', 'tgz', 'npm', 7)))\n"
            "    finally:\n        pool.close()\n", cwd=project)
        self.assertEqual(sorted(os.listdir(markers)), [], done.stderr)
        self.assertEqual((out["head"], out["length"], out["kind"]), ("ok", 2, "npm"))


if __name__ == "__main__":
    unittest.main()
