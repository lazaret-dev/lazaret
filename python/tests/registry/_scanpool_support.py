"""Functions the scan workers of `test_scanpool` run. A worker is a process of its own (`spawn`), so what it
runs must be importable by name: nothing here is a test. Each takes what `guard._scan_one` takes
(`data, container, kind, timeout, timed`) and does what the first bytes of `data` say."""

import os
import time


def _limits():
    try:
        import resource
    except ImportError:
        return None, None
    return resource.getrlimit(resource.RLIMIT_AS)[0], resource.getrlimit(resource.RLIMIT_CPU)[0]


def echo(data, container, kind, timeout, timed):
    """What the worker was given and the limits it runs under."""
    from lazaret.scanner import engine
    as_limit, cpu_limit = _limits()
    return {"pid": os.getpid(), "length": len(data), "head": bytes(data[:8]).decode("latin-1"), "container": container,
            "kind": kind, "timeout": timeout, "timed": timed, "threads": engine.THREADS, "as": as_limit,
            "cpu": cpu_limit}


def behave(data, container, kind, timeout, timed):
    """`ok`, `crash` (the process ends at once), `crash-once:PATH` (ends the first time, when PATH is not there yet),
    `spin` (computes for ever), `hang` (sleeps for ever), `alloc:MB`, `raise`, `sleep:SECONDS`."""
    head = bytes(data).split(b":", 1)
    word, rest = head[0], head[1] if len(head) > 1 else b""
    if word == b"crash":
        os._exit(5)
    if word == b"crash-once":
        marker = rest.decode()
        if not os.path.exists(marker):
            with open(marker, "w", encoding="utf-8") as f:
                f.write("seen")
            os._exit(9)
    elif word == b"spin":
        n = 0
        while True:
            n += 1
    elif word == b"hang":
        time.sleep(3600)
    elif word == b"alloc":
        block = bytearray(int(rest) * 1024 * 1024)
        return {"allocated": len(block)}
    elif word == b"raise":
        raise ValueError("boom")
    elif word == b"sleep":
        time.sleep(float(rest))
    return echo(data, container, kind, timeout, timed)


def exit_now():
    """A stand-in for the pool's trivial first job that ends the worker."""
    os._exit(3)
