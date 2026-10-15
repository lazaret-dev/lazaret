"""How the popular-set scripts (popular.py, packaged.py) fetch: over Lazaret's native client where the engine library
is installed (lazaret-net on pratique, as the registry fetches since NET-1: connections kept alive and reused, TLS 1.3
or 1.2, the caller's host rule on the URL and on every redirect, https only), else over urllib with the script's own
redirect rule, as these scripts did before; and, with --jobs, several requests at once (the native client runs
outside the interpreter's lock, so the threads' downloads overlap).

An `Opener` is called as urllib's urlopen is, `opener(request, timeout=...)`, and gives back a response to read and
to close, so a test's stand-in for urlopen stands in for it too. Two marks on a request, read only by the native
path: `download` (bytes as published, which a digest is checked against: never asked for compressed) and
`max_bytes` (the body's budget; the caller still checks its own limit). An HTTP status other than 200 is an
HTTPError and a request that got no answer a URLError, both OSErrors, as urllib raises them.
"""
import concurrent.futures
import os
import sys
import urllib.error

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "python", "src")
#: a request's budget when it names none
BUDGET = 1 << 30
#: requests at once when --jobs is not given
JOBS = 8


def native():
    """lazaret.scanner.nativenet from this tree, or None when it can't be imported."""
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)
    try:
        from lazaret.scanner import nativenet
    except ImportError:
        return None
    return nativenet


class Opener:
    """urlopen's interface on the native client, `hosts` its rule for the URL and every redirect; `fallback` (urllib's
    opener) sends what the native client is not there for or does not send (nativenet.UsePython)."""

    def __init__(self, hosts, fallback):
        self.hosts, self.fallback = tuple(sorted(hosts)), fallback

    def __call__(self, req, timeout=None):
        net = native()
        if net is None or not net.chosen(req.full_url):
            return self.fallback(req, timeout=timeout)
        try:
            stream = net.open_stream(req.full_url, hosts=self.hosts, headers=req.header_items(),
                                     max_bytes=getattr(req, "max_bytes", BUDGET), timeout=timeout or 90,
                                     compressed=False if getattr(req, "download", False) else None)
        except net.UsePython:
            return self.fallback(req, timeout=timeout)
        except net.NetError as exc:
            raise urllib.error.URLError(f"{exc} ({exc.kind})") from None
        if stream.status != 200:
            stream.close()
            raise urllib.error.HTTPError(req.full_url, stream.status, f"HTTP {stream.status}", None, None)
        return Response(stream, net.NetError)


class Response:
    """A native response read as urllib's is: `read(n)` gives n bytes unless the body ends first."""

    def __init__(self, stream, net_error):
        self._stream, self._net_error = stream, net_error

    def read(self, n=-1):
        out = bytearray()
        while n is None or n < 0 or len(out) < n:
            want = 1 << 20 if n is None or n < 0 else min(1 << 20, n - len(out))
            try:
                chunk = self._stream.read(want)
            except self._net_error as exc:
                raise urllib.error.URLError(f"{exc} ({exc.kind})") from None
            if not chunk:
                break
            out += chunk
        return bytes(out)

    def close(self):
        self._stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def each(items, work, jobs, progress=None):
    """`work(item)` for every item, `jobs` at a time in threads -> the results, in the items' order. `progress(n)` is
    told how many have finished after each one (from the calling thread)."""
    items = list(items)
    if jobs <= 1:
        out = []
        for n, item in enumerate(items, 1):
            out.append(work(item))
            if progress is not None:
                progress(n)
        return out
    results = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(work, item): i for i, item in enumerate(items)}
        for n, future in enumerate(concurrent.futures.as_completed(futures), 1):
            results[futures[future]] = future.result()
            if progress is not None:
                progress(n)
    return results
