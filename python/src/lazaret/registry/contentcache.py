"""A memo for the engine's answers about content (0.1.9, P-2a): ask the engine once for bytes that appear in
several archives of a release, and share the answer with every thread that asks while it is being worked out.

Design: `specs/lazaret-content-cache-design-2026-10-03.md`. This module is step 1 of it: in memory, for one run, no
stored state and so no trust question. It is not called by `repo.py` yet (the call sites are the 0.1.8 agent's:
`scan_pending`, `_import_time_risks`, `_cross_file_code`); it is written first, with the properties the gate asks
for, so that the call sites are three small edits.

    memo = Memo()
    answer = memo.get_or_compute(file_key("scan", rel, text, lang, flags), lambda: engine.scan_files(...))
    answers = memo.get_or_compute_many(keys, lambda missing: engine.batch(missing))   # one call for the misses

What is cached is **the engine's raw answer for one input, never a verdict**: the verdict is decided from the issues
of the whole artifact afterwards, so a cached answer changes the time and nothing else (the gate is identical issues
with the memo on and off: `NULL` is the memo that is always off, with the same interface).

The rules:

* **Single flight.** Two threads that want one key do the work once; the second waits for the first's answer. A call
  that raises raises for every thread that waited for it, and is not stored; the next caller tries again.
* **Nothing unfinished is stored.** A `compute` that ran out of time or budget returns `Uncacheable(answer)`: the
  caller gets the answer, the memo keeps nothing, and a thread that was waiting for it works the question out for
  itself (it may have a different budget: it does not take another thread's cut-short answer).
  What the caller must return as `Uncacheable`: a call the engine did not answer (`engine.unanswered`: the work
  budget spent, an internal error, a `NativeError`), and a cross-file answer in which any package is marked
  `failed` (it would be cached as clean). Anything asked after the artifact's deadline is not asked at all.
* **What the key says about the path.** The engine's first pass reads no path, in dependency mode or in `--full`'s
  project mode: key it with `rel=None` and the flags that matter (`lang`, `jsx`, `dep`, `redact`, `neumaier`, a
  taint configuration), so one `.js` file under two paths is one call. A pass that reads the path keeps the path in
  the key or is not cached at all. The cross-file question is keyed on the files in the order given, not as a set
  (the engine's limits make the order count).
* **A hit is a copy.** The answer is copied on the way in and on the way out, so a caller that changes what it was
  given changes nothing for the next one (`copy=False` for a caller that promises not to).
* **Bounded by bytes.** The answers are small; the least recently used go first, and an answer larger than a
  fraction of the whole is not kept.
* **No hold and wait.** A batch computes the keys it claimed before it waits for any key another thread claimed, so
  two batches that overlap cannot wait for each other.
* **A waiter's patience is its own.** `wait` seconds, then it computes for itself, so a thread with a deadline is not
  held past it by another thread's slow call.

Standard library only; nothing here imports the rest of Lazaret."""

import collections
import copy
import hashlib
import threading

__all__ = ["KINDS", "file_key", "cross_file_key", "Digests", "Uncacheable", "Memo", "NULL", "NullMemo"]

KINDS = ("scan", "import-risk", "spawned", "cross-file")           # the engine calls whose answers are cached
DEFAULT_MAX_BYTES = 64 << 20                                      # of answers (an estimate of their size)
MAX_ENTRY_SHARE = 8                                               # an answer over 1/8 of the bound is not kept
_NO_ANSWER = object()


# ---------------------------------------------------------------- keys
def _digest(text):
    if isinstance(text, str):
        text = text.encode("utf-8", "surrogatepass")               # (a lone surrogate is content too)
    return hashlib.sha256(text).hexdigest()


class Digests:
    """The SHA-256 of each distinct text, worked out once (0.1.9, FE-1): a registry scan keys four steps' answers on
    one file's text (the rules, the import-time test, the scripts it starts, the cross-file follower), and each key
    used to hash the text again. Pass one as `digest=` to file_key and cross_file_key; clear() it with the scan."""

    def __init__(self):
        self._of = {}

    def __call__(self, text):
        d = self._of.get(text)
        if d is None:
            d = self._of[text] = _digest(text)
        return d

    def clear(self):
        self._of.clear()


def _flags(flags):
    """The pass arguments as a tuple that is the same whichever way they were given."""
    if not flags:
        return ()
    if isinstance(flags, dict):
        return tuple(sorted((str(k), repr(v)) for k, v in flags.items()))
    return tuple(sorted(repr(f) for f in flags))


def file_key(kind, rel, text, lang, flags=(), pack="", engine="", digest=_digest):
    """`(kind, rel, sha256(text), lang, flags, pack, engine)`. `rel` is the member's path when the pass reads it
    (manifests, the extension's language) and None when it does not (the first pass for a language that reads
    only the text), so that one file under two paths is one question. `pack` is the rule pack's hash and `engine`
    the engine's version: a new rule never reads an old answer. `digest`: the scan's Digests (the same hash, kept)."""
    if kind not in KINDS:
        raise ValueError(f"not a kind of answer that is cached: {kind!r}")
    return (kind, rel, digest(text), lang, _flags(flags), pack, engine)


def cross_file_key(files, flags=(), pack="", engine="", digest=_digest):
    """The key of a cross-file question. `files` is `[(path, lang, content)]` **in the order the engine is given
    them** (the registry passes `sorted(self.sources)`): the answer is not a function of the set, because where the
    engine has a limit (the symbols kept, the bodies tested for running a parameter, the first import that names a
    seed) the order decides what is read. So the key is of the list: put two files the other way round, change a
    path or a language, or change one byte of one file, and it is another question. `flags` carry the call's other
    arguments (`one_package`, `skip`, `who`, `groups`, `redact`, `neumaier`, `os.sep`, the work budget): anything
    the answer depends on that is not in `files`. `digest`: the scan's Digests (the same hashes, kept)."""
    parts = []
    for item in files:
        if not isinstance(item, (tuple, list)) or len(item) != 3:
            raise ValueError("a file of a cross-file question is (path, language, content)")
        path, lang, content = item
        parts.append(repr((path, lang, digest(content))))
    return ("cross-file", None, _digest("\n".join(parts)), None, _flags(flags), pack, engine)


# ---------------------------------------------------------------- what a compute returns
class Uncacheable:
    """Return this from a `compute` whose answer must not be kept: the caller is given `answer`, the memo stores
    nothing, and a thread that waited for it asks for itself."""
    __slots__ = ("answer",)

    def __init__(self, answer):
        self.answer = answer


def _unwrap(answer):
    return answer.answer if isinstance(answer, Uncacheable) else answer


def estimate(value):
    """About how many bytes an answer takes (the text it holds and a little for each part): good enough to bound
    a memo of answers that are lists, dicts and strings."""
    total, stack, seen = 0, [value], 0
    while stack and seen < 1_000_000:
        item = stack.pop()
        seen += 1
        if isinstance(item, str):
            total += 49 + len(item)
        elif isinstance(item, (bytes, bytearray)):
            total += 33 + len(item)
        elif isinstance(item, dict):
            total += 64 + 16 * len(item)
            for k, v in item.items():
                stack.append(k)
                stack.append(v)
        elif isinstance(item, (list, tuple, set, frozenset)):
            total += 56 + 8 * len(item)
            stack.extend(item)
        else:
            total += 32
    return total + (4096 if stack else 0)                          # (an answer too big to count is a big one)


class _Flight:
    """One computation in progress: threads that want its key wait on `done`. `share` says whether what it found
    may be handed to them (not for an `Uncacheable` answer, nor when it raised or was abandoned)."""
    __slots__ = ("done", "answer", "error", "share")

    def __init__(self):
        self.done = threading.Event()
        self.answer, self.error, self.share = None, None, False


class _Counts:
    __slots__ = ("hits", "misses", "shared", "stored", "dropped", "evicted", "errors")

    def __init__(self):
        self.hits = self.misses = self.shared = self.stored = self.dropped = self.evicted = self.errors = 0

    def asdict(self):
        return {name: getattr(self, name) for name in self.__slots__}


# ---------------------------------------------------------------- the memo
class Memo:
    """Answers by key, with single flight and a byte bound. Thread-safe."""

    enabled = True

    def __init__(self, max_bytes=DEFAULT_MAX_BYTES, copy_answers=True):
        self.max_bytes = max(0, int(max_bytes))
        self.copy = copy_answers
        self._lock = threading.Lock()
        self._answers = collections.OrderedDict()                  # key -> (answer, size), oldest first
        self._flights = {}
        self._bytes = 0
        self._counts = collections.defaultdict(_Counts)            # by the key's kind

    def _out(self, answer):
        return copy.deepcopy(answer) if self.copy else answer

    # ---- one key
    def get_or_compute(self, key, compute, wait=None):
        """The answer for `key`: the stored one, or what `compute()` returns (called once for any number of threads
        that ask at once). `compute` may return `Uncacheable(answer)`. `wait` is how long to wait for another
        thread's computation of the key before computing it here (None: as long as it takes)."""
        kind = key[0]
        while True:
            state, item = self._look(key, kind)
            if state == "hit":
                return self._out(item)
            if state == "lead":
                return self._lead(key, kind, item, compute)
            outcome = self._follow(kind, item, wait)
            if outcome is not _NO_ANSWER:
                return outcome
            if not item.done.is_set():                             # (patience ran out: work it out here, unclaimed)
                with self._lock:
                    self._counts[kind].misses += 1
                return _unwrap(compute())
            # the flight ended with nothing to share (an answer not for keeping, or abandoned): ask again

    def _look(self, key, kind):
        """-> ("hit", the stored answer), ("lead", a new flight: this thread computes it) or ("follow", the flight
        another thread is computing)."""
        with self._lock:
            held = self._answers.get(key)
            if held is not None:
                self._answers.move_to_end(key)
                self._counts[kind].hits += 1
                return "hit", held[0]
            flight = self._flights.get(key)
            if flight is None:
                self._flights[key] = flight = _Flight()
                self._counts[kind].misses += 1
                return "lead", flight
            return "follow", flight

    def _lead(self, key, kind, flight, compute):
        try:
            result = compute()
        except BaseException as exc:
            self._abandon([(key, flight)], exc if isinstance(exc, Exception) else None)
            raise
        self._publish(key, kind, flight, result)
        return _unwrap(result)

    def _abandon(self, claimed, error=None):
        """Release the threads waiting on `claimed`: with `error` they raise it, without they ask again."""
        with self._lock:
            for key, flight in claimed:
                if self._flights.get(key) is flight:
                    del self._flights[key]
                if not flight.done.is_set():
                    flight.error = error
                    if error is not None:
                        self._counts[key[0]].errors += 1
        for _key, flight in claimed:
            flight.done.set()

    def _publish(self, key, kind, flight, result):
        keep = not isinstance(result, Uncacheable)
        stored, size = result, 0
        if keep:
            try:
                stored = copy.deepcopy(result) if self.copy else result
                size = estimate(result)
            except Exception:                                      # (an answer that cannot be copied is not kept)
                keep, stored = False, result
        try:
            with self._lock:
                if self._flights.get(key) is flight:
                    del self._flights[key]
                counts = self._counts[kind]
                if keep and size * MAX_ENTRY_SHARE <= self.max_bytes:                  # (a memo of 0 bytes keeps nothing: size is over 0)
                    self._answers[key] = (stored, size)                                # (a new key goes last: it is the newest)
                    self._bytes += size
                    counts.stored += 1
                    self._evict()
                else:
                    counts.dropped += 1
                flight.answer, flight.share = stored, keep
        finally:
            flight.done.set()

    def _evict(self):
        while self._bytes > self.max_bytes and self._answers:
            old_key, (_answer, old_size) = self._answers.popitem(last=False)
            self._bytes -= old_size
            self._counts[old_key[0]].evicted += 1

    def _follow(self, kind, flight, wait):
        """Wait for another thread's computation -> its answer, or `_NO_ANSWER` when it is not to be shared (not for
        keeping, abandoned) or we ran out of patience. Raises what it raised."""
        flight.done.wait(wait)
        if not flight.done.is_set():
            return _NO_ANSWER
        if flight.error is not None:
            raise flight.error
        if not flight.share:
            return _NO_ANSWER
        with self._lock:
            self._counts[kind].shared += 1
        return self._out(flight.answer)

    # ---- many keys, one engine call for the ones nobody has
    def get_or_compute_many(self, keys, compute_many, wait=None):
        """-> the answers for `keys`, in order. The keys the memo has, and the keys other threads are working on, are
        not asked about again; the rest go to ONE call, `compute_many(missing_keys)`, which returns a list of
        answers in the same order (each may be `Uncacheable`). A key twice in `keys` is asked once."""
        keys = list(keys)
        results, seen = {}, set()
        claimed, waiting = [], []                                  # (key, flight): ours to compute, theirs to wait for
        held = {}
        with self._lock:
            for key in keys:
                if key in seen:
                    continue
                seen.add(key)
                stored = self._answers.get(key)
                if stored is not None:
                    self._answers.move_to_end(key)
                    self._counts[key[0]].hits += 1
                    held[key] = stored[0]
                    continue
                flight = self._flights.get(key)
                if flight is None:
                    self._flights[key] = flight = _Flight()
                    self._counts[key[0]].misses += 1
                    claimed.append((key, flight))
                else:
                    waiting.append((key, flight))
        for key, answer in held.items():
            results[key] = self._out(answer)
        if claimed:
            self._lead_many(claimed, compute_many, results)
        for key, flight in waiting:                                # (only after our own are published: no deadlock)
            outcome = self._follow(key[0], flight, wait)
            if outcome is _NO_ANSWER:
                if flight.done.is_set():                           # (nothing to share: ask again)
                    outcome = self.get_or_compute(key, lambda key=key: _single(compute_many, key), wait)
                else:                                              # (patience ran out)
                    with self._lock:
                        self._counts[key[0]].misses += 1
                    outcome = _unwrap(_single(compute_many, key))
            results[key] = outcome
        out, emitted = [], set()
        for key in keys:
            answer = results[key]
            out.append(self._out(answer) if key in emitted else answer)    # (no two places share one object)
            emitted.add(key)
        return out

    def _lead_many(self, claimed, compute_many, results):
        keys = [key for key, _flight in claimed]
        try:
            answers = compute_many(keys)
            if not isinstance(answers, (list, tuple)) or len(answers) != len(keys):
                raise ValueError(f"asked for {len(keys)} answers and got "
                                 f"{len(answers) if hasattr(answers, '__len__') else 'no list'}")
        except BaseException as exc:
            self._abandon(claimed, exc if isinstance(exc, Exception) else None)
            raise
        for n, ((key, flight), result) in enumerate(zip(claimed, answers)):
            try:
                self._publish(key, key[0], flight, result)
            except BaseException:
                self._abandon(claimed[n:], None)                   # (nobody is left waiting on what was not published)
                raise
            results[key] = _unwrap(result)

    # ---- reporting
    def stats(self):
        """{kinds: {kind: {hits, misses, shared, stored, dropped, evicted, errors}}, entries, bytes, max_bytes}: for
        the report line that says how many answers the memo served."""
        with self._lock:
            by_kind = {kind: counts.asdict() for kind, counts in sorted(self._counts.items())}
            return {"kinds": by_kind, "entries": len(self._answers), "bytes": self._bytes,
                    "max_bytes": self.max_bytes}

    def __len__(self):
        with self._lock:
            return len(self._answers)

    def clear(self):
        with self._lock:
            self._answers.clear()
            self._bytes = 0


def _single(compute_many, key):
    return compute_many([key])[0]


class NullMemo:
    """The memo that is always off, with the interface of `Memo`: every key is computed, nothing is kept. What a
    call site uses for `--no-cache`, for the guard, and for the run that checks the memo changes no answer."""

    enabled = False

    def get_or_compute(self, key, compute, wait=None):
        return _unwrap(compute())

    def get_or_compute_many(self, keys, compute_many, wait=None):
        keys = list(keys)
        if not keys:
            return []
        answers = compute_many(keys)
        if not isinstance(answers, (list, tuple)) or len(answers) != len(keys):
            raise ValueError(f"asked for {len(keys)} answers and got "
                             f"{len(answers) if hasattr(answers, '__len__') else 'no list'}")
        return [_unwrap(a) for a in answers]

    def stats(self):
        return {"kinds": {}, "entries": 0, "bytes": 0, "max_bytes": 0}

    def __len__(self):
        return 0

    def clear(self):
        pass


NULL = NullMemo()
