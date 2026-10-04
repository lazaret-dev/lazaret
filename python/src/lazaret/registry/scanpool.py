"""Worker processes for the guard's scans: limited, replaceable, and given files, not pickles (0.1.9, P-7).

`guard.Scanner` used to scan in its own process when `--jobs` was 1 (the process that downloads, holds
every archive and talks to the package manager grew to 1.55 GB on a large install) and, when a worker
died, went on scanning in that same process. Here the scan always runs in a worker (`--no-isolate`
brings the old way back), and the worker is the one that can be hurt:

- **A file, not a pickle.** The parent writes the archive's bytes to a file in a directory of its own
  (mode 0700, a name made of the content's sha256 and a sequence number, mode 0600) and sends the
  worker the path. A pickled archive was copied three times (pickle, pipe, unpickle) and queued in the
  parent's memory ahead of the worker. The worker reads the file and **hashes it again**: bytes that
  are not the ones the parent staged make the scan fail (`ArchiveChanged`), so a process that could
  swap the file in between gets an error, not a clean verdict. The file is removed as soon as the
  answer is in, and the directory when the pool closes. The name carries the content's digest so that
  a seen-set shared by the workers (P-2a's guard half) can key on it.
- **Limits that follow the work.** Each worker sets, once, an address-space limit (`RLIMIT_AS`, where
  the platform keeps one: Linux; it is ignored elsewhere). For each archive the parent says how many
  engine threads it may use: the cores shared out among the archives running at that moment (all of
  them for one big archive alone, half each for two), so `--jobs` times engine threads stays within
  the cores when the workers are busy. The worker then sets a CPU-time limit above the scan's own
  deadline (`RLIMIT_CPU`, CPU seconds of all its threads), a backstop for a scan that ignores its
  deadline: the signal ends the worker.
- **A worker that dies is not the guard's problem.** When a worker is lost (the memory limit, the CPU
  limit, a crash of the engine) every archive in flight in that pool is run once more, one at a time,
  in a pool of its own; one that kills its worker again raises `Died` and the guard cannot clear that
  package (it is blocked as "could not be checked", as any scan that fails). The others get their
  answers. A scan that does not answer within the wall limit gets the pool's processes terminated
  and raises `Hung`. After `MAX_BREAKS` lost workers the pool stops starting new ones.
- **A pool that cannot start is told apart from one that loses a worker.** The first pool is tried
  with a trivial job; if that fails (no `spawn`, a limit too small to import Python, a frozen
  program) `Unavailable` is raised and the caller scans in its own process, saying so.

What it does not do: no limit on a worker's resident memory on platforms without `RLIMIT_AS`, and
nothing against a worker that reads the whole disk; the worker is a process of the same user.
"""

import concurrent.futures
import concurrent.futures.process
import hashlib
import itertools
import multiprocessing
import os
import shutil
import tempfile
import threading

try:
    import resource
except ImportError:                                      # Windows
    resource = None

from lazaret.scanner import timings

__all__ = ["WorkerPool", "Unavailable", "Died", "Hung", "ArchiveChanged", "cores", "threads_for",
           "DEFAULT_MEMORY_MB", "MAX_BREAKS", "MAX_ENGINE_THREADS"]

#: Address space a worker may use, in MB (Linux). A 40 MB archive peaks near 1.4 GB; the archive
#: reader's own cap is 500 MB of decompressed bytes.
DEFAULT_MEMORY_MB = 6144
#: Lost workers after which no new pool is started.
MAX_BREAKS = 20
#: The engine's own cap on its threads (`scanner.engine.THREADS` is `min(8, cores)`).
MAX_ENGINE_THREADS = 8


class Unavailable(Exception):
    """Worker processes cannot be started here: the caller scans in its own process."""


class Died(Exception):
    """A worker was lost on this archive, and again when the archive was run alone."""


class Hung(Exception):
    """The scan did not answer within the wall limit; the workers were terminated."""


class ArchiveChanged(Exception):
    """The file the worker read is not the one the parent staged."""


def cores():
    """The cores this process may use (the affinity mask where there is one)."""
    try:
        return len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        return os.cpu_count() or 1


def threads_for(jobs, total=None):
    """The engine threads for each of `jobs` workers: the cores shared out, 1 to 8."""
    return max(1, min(MAX_ENGINE_THREADS, (total or cores()) // max(1, jobs)))


# ---------------------------------------------------------------- in the worker
def _init(memory_bytes):
    """Once per worker: the address-space limit."""
    if resource is not None and memory_bytes:
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_AS)
            want = memory_bytes if soft == resource.RLIM_INFINITY else min(soft, memory_bytes)
            resource.setrlimit(resource.RLIMIT_AS, (want, hard))
        except (ValueError, OSError):
            pass                                          # a platform that keeps no such limit


def _threads(n):
    """The engine's threads for the next archive (a module global it reads at each call)."""
    try:
        from lazaret.scanner import engine
    except ImportError:
        return
    engine.THREADS = n


def _cpu_limit(seconds):
    """Before an archive: end this process after `seconds` more CPU seconds (all threads)."""
    if resource is None or not seconds:
        return
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_CPU)
        used = resource.getrusage(resource.RUSAGE_SELF)
        soft = int(used.ru_utime + used.ru_stime) + int(seconds)
        if hard != resource.RLIM_INFINITY:
            soft = min(soft, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
    except (ValueError, OSError):
        pass


def _ping():
    return os.getpid()


def _task(fn, path, digest, container, kind, timeout, timed, cpu_seconds, threads):
    """One archive in a worker: read the staged file, check it is the bytes that were staged, set the engine's
    threads and the CPU limit, and run `fn(data, container, kind, timeout, timed)`."""
    with open(path, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ArchiveChanged("the archive changed on its way to the worker")
    _threads(threads)
    _cpu_limit(cpu_seconds)
    return fn(data, container, kind, timeout, timed)


# ---------------------------------------------------------------- in the parent
class WorkerPool:
    """Runs `fn(data, container, kind, timeout, timed)` for one archive at a time in each of `jobs`
    worker processes. `fn` must be importable by the worker (a module-level function). Any number of
    threads may call `run`."""

    def __init__(self, jobs, fn, memory_mb=DEFAULT_MEMORY_MB, threads=None, wall=None, cpu=None):
        self.jobs = max(1, jobs)
        self.wall, self.cpu = wall, cpu                  # seconds to wait for an answer, CPU seconds for an archive:
                                                         # None is 2 x the scan timeout + 60, and (2 x timeout + 30) per thread
        self.fn = fn
        self.memory_bytes = max(0, int(memory_mb)) * 1024 * 1024
        self.threads = threads                           # None: the cores shared out among the archives running now
        self._running = 0
        self._slots = threading.Semaphore(self.jobs)
        self.breaks = 0                                  # workers lost so far
        self._pool = None
        self._dir = None
        self._seq = itertools.count()
        self._lock = threading.Lock()
        self._alone = threading.Lock()                   # one retry at a time
        self._live = []                                  # the pools in use, to end them all on close
        self._start = threading.Lock()                   # one thread makes the shared pool
        self._proved = False                             # the shared pool has run a trivial job
        self._unavailable = ""                           # why workers cannot be had, once known
        self._closed = False

    # ---- pools
    def _make(self, workers):
        try:
            return concurrent.futures.ProcessPoolExecutor(
                max_workers=workers, mp_context=multiprocessing.get_context("spawn"),
                initializer=_init, initargs=(self.memory_bytes,))
        except (OSError, ValueError, ImportError, NotImplementedError) as exc:
            raise Unavailable(f"{type(exc).__name__}: {exc}") from None

    def _shared(self):
        """The pool the archives go to: made, and proved with a trivial job the first time, by one thread while
        the others wait for the answer (so that they all learn the same thing: a pool, or `Unavailable`)."""
        with self._lock:
            if self._pool is not None and not self._closed:
                return self._pool
        with self._start:
            with self._lock:
                if self._closed:
                    raise Unavailable("the pool is closed")
                if self._pool is not None:
                    return self._pool
                if self._unavailable:
                    raise Unavailable(self._unavailable)
                if self.breaks >= MAX_BREAKS:                    # (never a reason to scan in the caller's own process)
                    raise Died(f"{self.breaks} scan workers have been lost; no more are started")
            try:
                pool = self._make(self.jobs)
            except Unavailable as exc:
                self._unavailable = str(exc)
                raise
            with self._lock:
                self._live.append(pool)                  # (so that close() ends it)
            if not self._proved:
                try:
                    pool.submit(_ping).result(timeout=120)
                except (concurrent.futures.process.BrokenProcessPool, concurrent.futures.TimeoutError, OSError,
                        RuntimeError) as exc:
                    self._retire(pool, kill=True)
                    self._unavailable = f"a worker could not start ({type(exc).__name__})"
                    raise Unavailable(self._unavailable) from None
                self._proved = True
            with self._lock:
                self._pool = pool                        # only a pool that has run a job is handed out
            return pool

    def _retire(self, pool, kill=False):
        """Forget `pool` (it is broken or done) and, with `kill`, stop its processes."""
        with self._lock:
            if self._pool is pool:
                self._pool = None
            if pool in self._live:
                self._live.remove(pool)
        if kill:
            procs = getattr(pool, "_processes", None) or {}
            for proc in list(procs.values()):
                try:
                    proc.terminate()
                except (OSError, AttributeError):
                    pass
        try:
            pool.shutdown(wait=False, cancel_futures=True)
        except (OSError, RuntimeError):
            pass

    # ---- files
    def _staging(self):
        with self._lock:
            if self._dir is None:
                self._dir = tempfile.mkdtemp(prefix="lazaret-guard-")      # mode 0700
            return self._dir

    def stage(self, data):
        """Write `data` where a worker can read it -> (path, sha256 hex)."""
        digest = hashlib.sha256(data).hexdigest()
        path = os.path.join(self._staging(), f"{digest}-{next(self._seq)}.bin")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        except BaseException:
            _remove(path)
            raise
        return path, digest

    # ---- running
    def run(self, data, container, kind, timeout, timed=False):
        """-> what `fn` returned for this archive. `Unavailable` (nothing was run), `Died`, `Hung`,
        `ArchiveChanged`, or whatever `fn` raised."""
        with timings.span("scan", "hand off"):
            path, digest = self.stage(data)
        try:
            with timings.span("scan", "queue"):
                self._slots.acquire()                    # a task is sent only when a worker is free, so the wall limit
            try:                                         # below is for the scan and not for the time spent waiting its turn
                with self._lock:
                    self._running += 1
                    share = self.threads or threads_for(min(self.jobs, self._running))
                try:
                    wall = self.wall if self.wall is not None else 2 * timeout + 60
                    cpu = self.cpu if self.cpu is not None else int((2 * timeout + 30) * share)
                    args = (self.fn, path, digest, container, kind, timeout, timed, cpu, share)
                    pool = self._shared()
                    try:
                        return self._wait(pool, args, wall)
                    except concurrent.futures.process.BrokenProcessPool:
                        self._lost(pool)
                    with self._alone:                    # the archives in flight with it are run one at a time
                        return self._alone_run(args, wall)
                finally:
                    with self._lock:
                        self._running -= 1
            finally:
                self._slots.release()
        finally:
            _remove(path)

    def _wait(self, pool, args, wall):
        try:
            future = pool.submit(_task, *args)
        except concurrent.futures.process.BrokenProcessPool:
            raise
        except RuntimeError:                             # shut down by the thread that found it broken
            raise concurrent.futures.process.BrokenProcessPool("the pool was shut down") from None
        try:
            with timings.span("scan", "wait for worker"):
                return future.result(timeout=wall)
        except concurrent.futures.TimeoutError:
            self._retire(pool, kill=True)
            raise Hung("the scan did not finish") from None

    def _lost(self, pool):
        """A worker of the shared `pool` was lost: counted once, by the first thread that sees it."""
        with self._lock:
            if self._pool is pool:
                self.breaks += 1
        self._retire(pool)

    def _alone_run(self, args, wall):
        if self.breaks >= MAX_BREAKS:
            raise Died("workers keep being lost")
        try:
            pool = self._make(1)
        except Unavailable as exc:
            raise Died(f"no worker could be started to run it alone ({exc})") from None
        with self._lock:
            if self._closed:
                closed = True
            else:
                closed = False
                self._live.append(pool)
        if closed:
            self._retire(pool, kill=True)
            raise Unavailable("the pool is closed")
        try:
            return self._wait(pool, args, wall)
        except concurrent.futures.process.BrokenProcessPool:
            with self._lock:
                self.breaks += 1
            raise Died("the scan worker was lost on this archive, also when it ran alone "
                       "(its memory or CPU limit, or a crash)") from None
        finally:
            self._retire(pool)

    # ---- the end
    def close(self):
        with self._lock:
            self._closed = True
            pools, self._live, self._pool = self._live, [], None
            folder, self._dir = self._dir, None
        for pool in pools:
            self._retire(pool, kill=True)
        if folder:
            shutil.rmtree(folder, ignore_errors=True)


def _remove(path):
    try:
        os.unlink(path)
    except OSError:
        pass
