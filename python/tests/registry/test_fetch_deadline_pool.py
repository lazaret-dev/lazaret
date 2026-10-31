"""A cut read through the pool is the deadline's give-up, not a network fault (F-07; the Windows CI of
Oct 31, run 313 — `RedirectTests.test_slow_hops_count_against_the_deadline`, '/hop0', the pool,
`fetch_to_file`).

On Windows a socket's timeout, cut to the time left (`_Deadline.wait`/`arm`), fires before the deadline's
watchdog thread (a timer resolution of some 15 ms) and a hair before the deadline's `stop`, so `socket.timeout`
escaped `guard.Fetcher._open_kept`'s handlers, which called `deadline.check()` bare: not `_fired`, not
`_ran_out`, the clock short of `stop` — and the download that had simply run out of time was reported as
"network error ...: timed out". The give-up is intentional (the `_Deadline` docstring: whatever a call
returns or raises once the time is up, `check` raises the deadline's FetchError); what was wrong was its
classification. `check(exc, cut)` — `_Timed._call`'s rule, the one PR #21 applied to urllib's path in
`sources.py` — is what decides.

The pool path is driven with a stub pool (the classification is what is tested, not the wire): `request`
answers or is cut short, and the deadline's clock is far from its stop, so only `check`'s rule can tell the
two apart. A timeout of a call that was NOT cut — the plain per-read timeout, plenty of time left — stays
a network error: that is the boundary, and it is asserted too, for a blanket conversion would hide a real
network fault behind the deadline's words.

Run as the suite runs it: `python -m pytest tests/registry/test_fetch_deadline_pool.py -q` (or
`python -m unittest tests.registry.test_fetch_deadline_pool`) from `python/`.
"""

import socket
import unittest
import urllib.request

from lazaret.registry import guard, repo

SECONDS = 0.2          # the deadline: the test takes milliseconds, so the clock never reaches its stop
READ = 5.0             # the per-read timeout, over the deadline: `wait` cuts it to the time left
SHORT = 0.05           # under the deadline: `wait` hands it on whole, nothing is cut
URL = "http://127.0.0.1:1/hop0"


class _Sock:
    """The socket `deadline.arm` cuts (a stand-in for the one `watch` holds)."""

    def __init__(self):
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout


class _Reply:
    """A redirect's answer (302, a Location) whose body's `drain` times out."""

    status = 302
    headers = {"Location": "/hop1"}

    def drain(self):
        raise socket.timeout("timed out")

    def close(self):
        pass


class _Pool:
    """The pool as the deadline sees it: one request, answered with `reply` or cut short with `raise_`; the
    timeout it was handed remembered in `got` (the cut, or the plain timeout, is what `got` shows)."""

    def __init__(self, reply=None, raise_=None):
        self.reply, self.raise_, self.got = reply, raise_, []

    def request(self, url, headers, timeout, via, deadline=None, **held):
        self.got.append(timeout)
        if self.raise_ is not None:
            raise self.raise_
        return self.reply


class CutReadTests(unittest.TestCase):
    def _kept(self, pool, deadline):
        """`_open_kept` of a fetcher whose pool is `pool`, within `deadline` (hops: none, as `fetch` calls it)."""
        fetcher = guard.Fetcher({"127.0.0.1"}, keepalive=True)
        fetcher.pool = pool
        return fetcher._open_kept(urllib.request.Request(URL), URL, READ, deadline)

    def test_a_cut_head_read_is_the_deadline_s_give_up(self):
        # the pool's request (a kept connection's status line) with its timeout cut to the time left
        # (READ over SECONDS: `wait` cuts), raising the timeout the cut made — on Windows, before the watchdog
        deadline = guard._Deadline(SECONDS, URL)
        pool = _Pool(raise_=socket.timeout("timed out"))
        with self.assertRaises(repo.FetchError) as caught:
            self._kept(pool, deadline)
        self.assertIn(f"the download took over {SECONDS} s: {URL}", str(caught.exception))
        self.assertNotIn("network error", str(caught.exception))
        self.assertTrue(deadline.expired())          # (the give-up is recorded, not just reported)

    def test_a_cut_drain_of_a_redirect_s_body_is_the_deadline_s_give_up(self):
        # the redirect's body, its read `arm`ed to the time left (a live socket the arm can cut), cut short
        # the same way: the watchdog never fires, the clock short of its stop, only the cut can say it
        deadline = guard._Deadline(SECONDS, URL)
        sock = socket.socket()                             # (what `watch`/`using` would hold of the connection:
        deadline._sock = sock                              # arm needs a live descriptor to set the cut)
        pool = _Pool(reply=_Reply())
        try:
            with self.assertRaises(repo.FetchError) as caught:
                self._kept(pool, deadline)
        finally:
            sock.close()
        self.assertIn(f"the download took over {SECONDS} s: {URL}", str(caught.exception))
        self.assertNotIn("network error", str(caught.exception))

    def test_a_timeout_of_a_call_that_was_not_cut_is_a_network_error(self):
        # the plain per-read timeout (SHORT under SECONDS: `wait` hands it on whole) with the time left far
        # from its end: a real network fault, and it stays one — the boundary of the rule above
        deadline = guard._Deadline(SECONDS, URL)
        pool = _Pool(raise_=socket.timeout("timed out"))
        with self.assertRaises(repo.FetchError) as caught:
            fetcher = guard.Fetcher({"127.0.0.1"}, keepalive=True)
            fetcher.pool = pool
            fetcher._open_kept(urllib.request.Request(URL), URL, SHORT, deadline)
        self.assertIn(f"network error fetching {URL}", str(caught.exception))
        self.assertFalse(deadline.expired())         # (the deadline was never up: not its give-up)


class _Opener:
    """urllib's opener as the deadline sees it: its `open` cut short with `raise_`."""

    def __init__(self, raise_):
        self.raise_ = raise_

    def open(self, req, timeout=None):
        raise self.raise_


class OpenHeadTests(unittest.TestCase):
    """The same rule on urllib's transport (`guard.py:887-902` of the note): the connection's socket, its
    timeout cut to the time left by `netaddr.open_socket`, times out in `open` — TLS, the handshake or the
    status line — and the cut's timeout must reach `check` there too, on both handlers that can carry it:
    `URLError` (urllib wraps a socket error as its `reason`) and the bare `OSError` the note's parity path
    showed. The pool's head read above is the same seam on the other transport."""

    def _open(self, exc, timeout):
        deadline = guard._Deadline(SECONDS, URL)
        fetcher = guard.Fetcher({"127.0.0.1"})
        fetcher._opener = lambda clean: _Opener(exc)     # (the native transport is not taken on this URL)
        return fetcher._open(urllib.request.Request(URL), URL, timeout, 1024, deadline), deadline

    def test_a_cut_open_s_url_error_is_the_deadline_s_give_up(self):
        with self.assertRaises(repo.FetchError) as caught:
            self._open(urllib.error.URLError(socket.timeout("timed out")), READ)
        self.assertIn(f"the download took over {SECONDS} s: {URL}", str(caught.exception))
        self.assertNotIn("network error", str(caught.exception))

    def test_a_cut_open_s_own_error_is_the_deadline_s_give_up(self):
        with self.assertRaises(repo.FetchError) as caught:
            self._open(socket.timeout("timed out"), READ)
        self.assertIn(f"the download took over {SECONDS} s: {URL}", str(caught.exception))
        self.assertNotIn("network error", str(caught.exception))

    def test_a_timeout_of_an_open_that_was_not_cut_is_a_network_error(self):
        with self.assertRaises(repo.FetchError) as caught:
            self._open(socket.timeout("timed out"), SHORT)
        self.assertIn(f"network error fetching {URL}", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
