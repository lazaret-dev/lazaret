"""Where a run's time goes (0.1.9, P-4): seconds by phase, and by call inside a phase.

The profile of Oct 3 needed a harness of its own to learn that a guarded install
spends its time in the package manager, the network, the archive reader and the
engine, in that order of surprise. This is the part of that harness a user can
run: wrap a piece of work in `span("network")` and the run reports how many
seconds went there, how many calls, and what is left over (`other`: the Python
that was not wrapped).

    t = timings.Timings()
    with timings.capture(t):                    # installs it; `span` finds it
        with t.run():                           # the wall clock
            ...                                 # code that calls timings.span(...)
    print("\\n".join(timings.render(t.report())))

    with timings.span("engine", "scan_file"):   # in the code being measured:
        ...                                     # a no-op unless a capture is open

- **Exclusive time.** Spans nest; a span's seconds are its own, without those of
  the spans inside it. `span("scan")` around a call that itself opens
  `span("engine", "scan_file")` reports the engine's seconds under `engine` and
  only the rest under `scan`, so a call site added later, inside, moves seconds
  to where they belong without the outer one changing.
- **Threads.** Each thread keeps its own stack. A phase's seconds are summed over
  threads, so with parallel work they can exceed the wall; `other` is the wall
  minus what the thread that made the `Timings` spent in spans (the others' time
  overlaps it, and is not "left over").
- **Processes.** A worker makes its own `Timings`, returns `report()` with its
  result, and the parent calls `merge(report)`. The merged seconds are CPU-like
  (summed), like another thread's.
- **Cost.** Nothing is recorded, and a span costs one global read and a shared
  no-op object, unless a capture is open. An open one costs two clock reads and
  a lock per span.
- **Bounded.** A phase keeps at most `MAX_NAMES` call names; later ones are
  counted under `(other names)`, so a name built from input cannot grow it
  without end.

Nothing here reads a file, a path or a package name: the names are the code's.
The report is plain numbers and names, and is meant for stderr and `--json`."""

import contextlib
import threading
import time

__all__ = ["Timings", "span", "add", "capture", "current", "render", "MAX_NAMES", "OTHER_NAMES", "empty_report"]

MAX_NAMES = 64
OTHER_NAMES = "(other names)"


class _Off:
    """The span that does nothing: one shared object, for when no capture is open."""
    __slots__ = ()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


_OFF = _Off()


class _Span:
    __slots__ = ("owner", "phase", "name", "start", "inner")

    def __init__(self, owner, phase, name):
        self.owner, self.phase, self.name, self.start, self.inner = owner, phase, name, 0.0, 0.0

    def __enter__(self):
        stack = self.owner._stack()
        stack.append(self)
        self.start = self.owner._clock()
        return self

    def __exit__(self, *exc):
        owner = self.owner
        elapsed = owner._clock() - self.start
        stack = owner._stack()
        if self in stack:                                 # (closed out of order, it takes those above it along)
            del stack[stack.index(self):]
        mine = max(0.0, elapsed - self.inner)
        if stack:
            stack[-1].inner += elapsed
        owner._record(self.phase, self.name, mine, 1, in_owner_thread=threading.get_ident() == owner._thread)
        return False


class Timings:
    """Seconds and calls by phase and name. `clock` is `time.perf_counter` unless a
    test gives another (a function that returns seconds as a float)."""

    def __init__(self, clock=time.perf_counter):
        self._clock = clock
        self._lock = threading.Lock()
        self._local = threading.local()
        self._thread = threading.get_ident()            # the thread `other` is counted for
        self._phases = {}                               # phase -> [seconds, calls, {name: [seconds, calls]}]
        self._owner_seconds = 0.0                       # what the owning thread spent in spans
        self._wall = 0.0
        self._started = None

    # ---- the wall clock
    def start(self):
        if self._started is None:
            self._started = self._clock()

    def stop(self):
        if self._started is not None:
            self._wall += max(0.0, self._clock() - self._started)
            self._started = None

    @contextlib.contextmanager
    def run(self):
        self.start()
        try:
            yield self
        finally:
            self.stop()

    # ---- spans
    def _stack(self):
        stack = getattr(self._local, "stack", None)
        if stack is None:
            stack = self._local.stack = []
        return stack

    def span(self, phase, name=None):
        return _Span(self, phase, name)

    def add(self, phase, seconds, name=None, calls=1):
        """Seconds measured elsewhere (a callback, a number from another tool)."""
        self._record(phase, name, max(0.0, float(seconds)), int(calls), in_owner_thread=False)

    def _record(self, phase, name, seconds, calls, in_owner_thread):
        with self._lock:
            entry = self._phases.get(phase)
            if entry is None:
                entry = self._phases[phase] = [0.0, 0, {}]
            entry[0] += seconds
            entry[1] += calls
            if in_owner_thread:
                self._owner_seconds += seconds
            if name is not None:
                names = entry[2]
                if name not in names and len(names) >= MAX_NAMES:
                    name = OTHER_NAMES
                row = names.setdefault(name, [0.0, 0])
                row[0] += seconds
                row[1] += calls

    # ---- reports
    def report(self):
        """-> {"wall": seconds, "other": seconds, "phases": {phase: {"seconds", "calls", "by": {name: {"seconds",
        "calls"}}}}} of plain numbers. A run still open counts up to now."""
        with self._lock:
            wall = self._wall + (max(0.0, self._clock() - self._started) if self._started is not None else 0.0)
            phases = {}
            for phase, (seconds, calls, names) in self._phases.items():
                phases[phase] = {"seconds": seconds, "calls": calls,
                                 "by": {n: {"seconds": s, "calls": c} for n, (s, c) in names.items()}}
            other = max(0.0, wall - self._owner_seconds)
        return {"wall": wall, "other": other, "phases": phases}

    def merge(self, report):
        """Add another run's `report()` (a worker's). Its wall time is not added (the parent's own
        covers it); its seconds are summed into the phases like another thread's."""
        for phase, row in (report or {}).get("phases", {}).items():
            by = row.get("by") or {}
            named_seconds = named_calls = 0
            for name, sub in by.items():
                self._record(phase, name, max(0.0, float(sub.get("seconds", 0.0))), int(sub.get("calls", 0)), False)
                named_seconds += max(0.0, float(sub.get("seconds", 0.0)))
                named_calls += int(sub.get("calls", 0))
            rest_seconds = max(0.0, float(row.get("seconds", 0.0)) - named_seconds)
            rest_calls = max(0, int(row.get("calls", 0)) - named_calls)
            if rest_seconds or rest_calls:
                self._record(phase, None, rest_seconds, rest_calls, False)


def empty_report():
    return {"wall": 0.0, "other": 0.0, "phases": {}}


# ---- the capture that `span` finds
_current = None
_current_lock = threading.Lock()


def current():
    return _current


@contextlib.contextmanager
def capture(t=None):
    """Make `t` (a new Timings when None) the one `span` and `add` record into, for the block;
    the one that was there comes back after. -> t."""
    global _current
    t = Timings() if t is None else t
    with _current_lock:
        before, _current = _current, t
    try:
        yield t
    finally:
        with _current_lock:
            _current = before


def span(phase, name=None):
    """`with timings.span("network", "fetch"):` records into the open capture, or does nothing."""
    t = _current
    return _OFF if t is None else t.span(phase, name)


def add(phase, seconds, name=None, calls=1):
    t = _current
    if t is not None:
        t.add(phase, seconds, name, calls)


# ---- text
def _count(n):
    return f"{n:,}"


def render(report, top=8):
    """-> the report as lines of text for stderr: each phase with its seconds, share of the wall and
    calls, its busiest names indented under it, then what was left over."""
    wall = report.get("wall") or 0.0
    phases = report.get("phases") or {}
    lines = [f"timings (seconds; wall {wall:.2f}" + ("; the phases of parallel work add up to more than that)"
             if sum(p["seconds"] for p in phases.values()) > wall * 1.05 + 0.01 else ")")]

    def share(seconds):
        return f"{100 * seconds / wall:3.0f}%" if wall > 0 else "    "

    rows = sorted(phases.items(), key=lambda kv: (-kv[1]["seconds"], kv[0]))
    for phase, row in rows:
        lines.append(f"  {phase:<12} {row['seconds']:8.2f} {share(row['seconds'])}  {_count(row['calls'])} call"
                     + ("" if row["calls"] == 1 else "s"))
        named = sorted(row.get("by", {}).items(), key=lambda kv: (-kv[1]["seconds"], kv[0]))
        for name, sub in named[:top]:
            lines.append(f"    {name[:28]:<28} {sub['seconds']:6.2f}  {_count(sub['calls'])}")
        if len(named) > top:
            rest = named[top:]
            lines.append(f"    {'… ' + str(len(rest)) + ' more':<28} {sum(s['seconds'] for _, s in rest):6.2f}  "
                         f"{_count(sum(s['calls'] for _, s in rest))}")
    lines.append(f"  {'other':<12} {report.get('other', 0.0):8.2f} {share(report.get('other', 0.0))}  "
                 f"(Python outside the phases above)")
    return lines
