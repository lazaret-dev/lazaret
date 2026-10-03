"""The guard's scan workers (0.1.9, P-7): `lazaret.registry.scanpool.WorkerPool`.

Real worker processes (`spawn`, as in the guard) run the functions of `_scanpool_support`, which do what the first bytes of
the archive say: answer with what they were given, end the process, compute or sleep for ever, ask for memory. What is
checked: the archive goes to the worker as a file that is hashed again there and removed after, not as a pickle; the
worker's address-space limit, CPU limit and engine threads; a lost worker is a retry alone and then `Died`, never a scan
in the caller's process; a hung scan ends its workers; a pool that cannot start is `Unavailable`; `close` leaves nothing
behind."""

import concurrent.futures
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


if __name__ == "__main__":
    unittest.main()
