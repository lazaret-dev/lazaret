#!/usr/bin/env python3
"""How many connections a guarded install makes, and what they cost (0.1.9, P-10; P-15's evidence).

    python3 scripts/profile/guard_connections.py [--keepalive] pip install --target DIR requests

Runs `lazaret guard` with the rest of the command line, and prints on stderr, as one JSON line, the exit code,
the wall seconds, the HTTPS connections the guard opened (and the seconds spent connecting, summed over its
threads), the requests it made, and the hosts. Compare a run with and without `--keepalive` on a direct network
(`lazaret guard --timings` gives the same split by phase). Needs pip or npm, and the native engine."""

import http.client
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def main(argv=None):
    _common.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0 if argv else 2
    _common.use_source_tree()
    from lazaret.registry import guard
    stats = {"connects": 0, "seconds": 0.0, "hosts": {}, "requests": 0}
    lock = threading.Lock()
    real_connect, real_request = http.client.HTTPSConnection.connect, http.client.HTTPConnection.request

    def connect(self):
        started = time.perf_counter()
        try:
            return real_connect(self)
        finally:
            with lock:
                stats["connects"] += 1
                stats["seconds"] += time.perf_counter() - started
                stats["hosts"][self.host] = stats["hosts"].get(self.host, 0) + 1

    def request(self, *a, **k):
        with lock:
            stats["requests"] += 1
        return real_request(self, *a, **k)

    http.client.HTTPSConnection.connect, http.client.HTTPConnection.request = connect, request
    started = time.perf_counter()
    try:
        code = guard.main(argv)
    finally:
        http.client.HTTPSConnection.connect, http.client.HTTPConnection.request = real_connect, real_request
    print(json.dumps({"exit": code, "wall": round(time.perf_counter() - started, 2), "https_connects": stats["connects"],
                      "connect_seconds_summed": round(stats["seconds"], 2), "requests": stats["requests"],
                      "hosts": stats["hosts"]}), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
