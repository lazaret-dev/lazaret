"""A GitHub or GitLab repository at a commit, fetched as a project to scan
(0.1.9; docs/0.1.9-progress.md, specs/lazaret-sources-and-languages-plan).

    github:owner/repo[@ref]            gitlab:group[/subgroup...]/project[@ref]

`ref` is a branch, a tag or a commit; none means the default branch. The
ref is resolved to a commit SHA, that commit's archive is fetched and
read as a project, and the SHA is what the report names: a branch moving
while the scan runs cannot change what was read.

The rules are the registry module's (`repo.py`), applied to these hosts:

- HTTPS only, to fixed hosts: `api.github.com` and `codeload.github.com`;
  for GitLab, the one host of `LAZARET_GITLAB_URL` (default gitlab.com) and
  never a host taken from a spec, a redirect, or what was scanned. A
  redirect to any other host, or off HTTPS, is refused, and at most
  `repo.MAX_REDIRECTS` are followed.
- A token (`GITHUB_TOKEN`, `GITLAB_TOKEN`; read-only) goes only to the API
  host, is dropped from a redirect to another host, is checked for
  characters that could split a header, and appears in no message,
  report or exception.
- Byte budgets: the archive is read by `repo.iter_archive`, which charges
  every decompressed byte, caps a file, the file count and the time, and
  resolves links inside the archive instead of creating them.
- Nothing is run: no `git`, no archive hooks. Files are written under a
  fresh directory, by canonical relative path, never through a link.

One POST (GH-SCAN-GQL, 0.1.9: GitHub's GraphQL API, `Client.post`): to the
API host alone, over HTTPS, the token with it as with a GET, no redirect
followed, a byte budget on the answer, and a deadline for the whole of it
(the connection, TLS, the request, the headers and the body: the native
transport's total timeout, or on urllib's F-07's `guard._Deadline`). The
GETs keep their timeout for each read, as before.

What an archive cannot show: `git archive` leaves out any path marked
`export-ignore` in `.gitattributes`, so a payload can sit in the commit and
out of its tarball. The commit's tree is listed (one call on GitHub, pages
on GitLab), and every path in it that the archive lacks is fetched on its
own (N-5, 0.1.9: a public GitHub repository's from
`raw.githubusercontent.com`, by the commit; with a token, and on GitLab,
through the API), checked against the blob the tree names, and written
with the rest: most repositories that keep their tests and workflows out
of their tarball are read whole. What could not be fetched within the
budget (`MAX_MISSING_FILES` requests, `MISSING_FILES_SECONDS`, the
registry's download budget) is reported, and the checkout is incomplete:
fail closed, as everywhere in Lazaret.
"""

import contextlib
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import namedtuple

from lazaret.registry import pmsettings as _pm
from lazaret.registry import repo as _repo
from lazaret.scanner import core as _core
from lazaret.scanner import nativenet as _net

__all__ = ["SourceError", "Source", "Checkout", "parse_source", "checkout", "scanned_checkout",
           "archive_commit", "gitlab_base"]

GITHUB_API = "api.github.com"
GITHUB_ARCHIVE = "codeload.github.com"
GITHUB_RAW = "raw.githubusercontent.com"     # a public repository's files by commit (N-5)
GITLAB_DEFAULT = "https://gitlab.com"
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_TREE_BYTES = 16 * 1024 * 1024         # one tree listing's JSON
GITLAB_TREE_PAGES = 100                   # of 100 entries: a larger tree is not listed whole
#: N-5: the paths the archive left out are fetched one at a time, at most this
#: many (each a request; GitHub's API allows 60 an hour without a token, which
#: is why a public repository's files come from raw.githubusercontent.com)
MAX_MISSING_FILES = 300
#: ... and within this many seconds (the registry's scan budget, LAZARET_SCAN_TIMEOUT)
MISSING_FILES_SECONDS = _repo.SCAN_TIMEOUT
#: GH-SCAN-GQL: a POST's answer at most (GitHub's GraphQL API: 100 repositories' fields are some 25 KB) and the
#: seconds it has in all, from before its connection to its body's last byte
POST_BYTES = 1024 * 1024
POST_SECONDS = 60.0

Source = namedtuple("Source", "kind path ref")


class SourceError(ValueError):
    """A source was refused or could not be fetched. `status` is the HTTP
    status when the server answered with an error, and `limits` that
    answer's rate-limit headers (Retry-After, X-RateLimit-*, lower-cased)."""
    status = None
    limits = None


# ---------------------------------------------------------------- specs
_GH_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_GH_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_GL_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$")
_REF_BAD_RE = re.compile(r"[\x00-\x20\x7f~^:?*\[\\]|\.\.|@\{|//")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{8,512}$")


def _check_ref(ref):
    """git's own rules for a ref name (check-ref-format), so nothing odd
    reaches a URL."""
    if (not ref or len(ref) > 255 or ref[0] in "-/." or ref[-1] in "/." or ref == "@"
            or _REF_BAD_RE.search(ref)
            or any(c.startswith(".") or c.endswith(".lock") for c in ref.split("/"))):
        raise SourceError(f"invalid ref {ref!r}")
    return ref


def parse_source(spec):
    """'github:owner/repo@ref' -> Source('github', 'owner/repo', 'ref'); ref
    may be None. Raises SourceError for anything else, with nothing echoed
    beyond the text the user typed."""
    if not isinstance(spec, str) or ":" not in spec:
        raise SourceError(f"a source is github:owner/repo[@ref] or gitlab:group/project[@ref], not {spec!r}")
    kind, rest = spec.split(":", 1)
    kind = kind.strip().lower()
    if kind not in ("github", "gitlab"):
        raise SourceError(f"unknown source {kind!r} (use github or gitlab)")
    path, at, ref = rest.strip().partition("@")
    ref = _check_ref(ref) if at else None
    parts = path.split("/")
    if kind == "github":
        if len(parts) != 2 or not _GH_OWNER_RE.fullmatch(parts[0]) or not _GH_REPO_RE.fullmatch(parts[1]) \
                or parts[1] in (".", "..") or parts[1].lower().endswith(".git"):
            raise SourceError(f"github: expected owner/repo, got {path!r}")
    else:
        if not 2 <= len(parts) <= 21 or any(not _GL_SEGMENT_RE.fullmatch(p) or p in (".", "..")
                                            or p.endswith((".git", ".atom")) for p in parts):
            raise SourceError(f"gitlab: expected group/project (subgroups allowed), got {path!r}")
    return Source(kind, path, ref)


def spec_text(src, commit=None):
    return f"{src.kind}:{src.path}@{commit or src.ref or 'HEAD'}"


def gitlab_base(env=None):
    """The GitLab instance: LAZARET_GITLAB_URL from the user's own
    environment, https only, a host (and port, and path prefix) and nothing
    else. Never taken from a spec or from scanned content."""
    env = os.environ if env is None else env
    url = (env.get("LAZARET_GITLAB_URL") or GITLAB_DEFAULT).strip()
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        raise SourceError("LAZARET_GITLAB_URL is not a URL") from None
    if (parts.scheme != "https" or not host or parts.username or parts.password
            or parts.query or parts.fragment or not re.fullmatch(r"[A-Za-z0-9.-]+", host)):
        raise SourceError("LAZARET_GITLAB_URL must be https://host[:port][/prefix], nothing more")
    prefix = parts.path.rstrip("/")
    if "//" in prefix or (prefix and _pm.normal_path(prefix) != prefix):     # ("..", "%2e%2e", a backslash)
        raise SourceError("LAZARET_GITLAB_URL has an unusable path")
    return f"https://{host}{':%d' % port if port else ''}{prefix}"


def _token(kind, env):
    name = "GITHUB_TOKEN" if kind == "github" else "GITLAB_TOKEN"
    tok = (env.get(name) or "").strip()
    if not tok:
        return None
    if not _TOKEN_RE.fullmatch(tok):
        raise SourceError(f"{name} is not usable as a token (letters, digits and _-.~+/= only; "
                          f"8 to 512 characters); it is never printed")
    return tok


# ---------------------------------------------------------------- the network
class _Hop(urllib.request.HTTPRedirectHandler):
    """A redirect stays on https and on the allowed hosts, a token never
    follows it to another host, or out of the token's path on its own host
    (urllib would send the header on), and the number of hops is capped."""

    max_redirections = _repo.MAX_REDIRECTS

    def __init__(self, hosts, auth_host, auth_path="/"):
        self.hosts, self.auth_host, self.auth_path = frozenset(hosts), auth_host, auth_path

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        newurl = _pm.normal_url(newurl)
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.netloc.lower() not in self.hosts:
            raise urllib.error.URLError(f"redirect blocked: {parts.scheme}://{parts.netloc}")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and not _covers(parts, self.auth_host, self.auth_path):
            for table in (new.headers, new.unredirected_hdrs):
                for key in [k for k in table if k.lower() in ("authorization", "private-token")]:
                    del table[key]
        return new


def _covers(parts, auth_host, auth_path):
    """Is the URL of these parts one the token goes with: its host, and a path under the token's however a server
    reads it (pmsettings.covers, as lazaret-net's `granted` reads a hop)?"""
    return parts.netloc.lower() == auth_host and _pm.covers(auth_path, parts.path)


def _shown(url):
    """A URL without its query or credentials (a redirect to codeload carries a
    short-lived token in its query)."""
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.hostname or ''}{p.path}"


def _explain(status, headers, url, what, has_token, kind):
    var = "GITHUB_TOKEN" if kind == "github" else "GITLAB_TOKEN"
    if status == 404:
        hint = "" if has_token else f" (a private {'repository' if kind == 'github' else 'project'} needs {var})"
        return f"{what}: not found{hint}"
    if status == 401:
        return f"{what}: the token was refused (HTTP 401)"
    limited = status == 429 or "retry-after" in headers or headers.get("x-ratelimit-remaining") == "0"
    if status in (403, 429) and limited:
        when = ""
        reset, retry = headers.get("x-ratelimit-reset", ""), headers.get("retry-after", "")
        if reset.isascii() and reset.isdigit() and len(reset) <= 12:
            try:
                when = " until " + time.strftime("%H:%M UTC", time.gmtime(int(reset)))
            except (OverflowError, OSError, ValueError):     # (a time no clock holds: none said)
                when = ""
        elif retry.isascii() and retry.isdigit() and len(retry) <= 12:
            when = f" for {retry} seconds"
        more = "" if has_token else f"; setting {var} (read-only) raises the limit"
        return f"{what}: rate limit reached, wait{when}{more}"
    return f"{what}: HTTP {status} from {_shown(url)}"


_TOKEN_HEADERS = ("authorization", "private-token")


def _refused(status, pairs, url, what, has_token, kind):
    """The SourceError of an answer with an error status: `_explain`'s words, the status, and the answer's rate-limit
    headers (`limits`), which tell GitHub's hourly limit from a secondary one (GH-SCAN-GQL)."""
    headers = {str(k).lower(): str(v) for k, v in pairs}
    err = SourceError(_explain(status, headers, url, what, has_token, kind))
    err.status = status
    err.limits = {k: v[:40] for k, v in headers.items() if k == "retry-after" or k.startswith("x-ratelimit-")}
    return err


def _keep_headers(into, pairs):
    """An answer's headers, lower-cased, into the dict `into` (None: nowhere)."""
    if into is not None:
        into.update({str(k).lower(): str(v) for k, v in pairs})


def _http(url, headers, max_bytes, hosts, auth_host, what="fetch", has_token=False, kind="github", auth_path="/",
          reply_headers=None, method="GET", data=None, seconds=None):
    """The real fetch: a byte-budgeted read, through the native transport (NET-1, scanner/nativenet.py: `hosts` the
    rule for the URL and every redirect), with the token as a credential of `auth_host` and the paths under
    `auth_path` (decision 14: the native client gives it to those hops and to no other, DESIGN.md §5j; a GitLab
    under a path prefix has the prefix); through urllib and `_Hop`, which takes a token off a redirect anywhere
    else, where the native transport is not to be used. `reply_headers`, a dict, gets the answer's headers,
    lower-cased, an error's too (GH-NEW-REPOS reads GitHub's rate limit from them). `method` "POST" sends `data`
    (`_post`: no redirect followed, `seconds` in all); the seam takes a POST as it takes a GET."""
    if method != "GET":
        if method != "POST":
            raise SourceError(f"{what}: the method {method!r} is not one sent")
        return _post(url, headers, data, max_bytes, hosts, auth_host, what=what, has_token=has_token, kind=kind,
                     auth_path=auth_path, reply_headers=reply_headers, seconds=seconds or POST_SECONDS)
    if _net.chosen(url):
        plain = [(k, v) for k, v in headers.items() if k.lower() not in _TOKEN_HEADERS]
        key = _net.host_key(f"https://{auth_host}/")
        credentials = [_net.Credential(key, auth_path, k, v) for k, v in headers.items()
                       if k.lower() in _TOKEN_HEADERS]
        try:
            reply = _net.request(url, hosts=sorted(hosts), headers=plain, credentials=credentials, max_bytes=max_bytes,
                                 timeout=_repo.DOWNLOAD_TIMEOUT, max_redirects=_repo.MAX_REDIRECTS)
        except _net.UsePython:
            pass                                 # (urllib below: a proxy it does not take, a credential it cannot send)
        except _net.NetError as exc:
            if exc.kind == "too-large":
                raise SourceError(f"{what}: response exceeds the {max_bytes // (1024 * 1024)}MB budget") from None
            if exc.kind == "refused":
                raise SourceError(f"{what}: redirect blocked ({exc})") from None
            if exc.kind in ("timeout", "network"):
                raise SourceError(f"{what}: network error ({exc.kind})") from None
            raise SourceError(f"{what}: {exc}") from None
        else:
            _keep_headers(reply_headers, reply.headers)
            if 200 <= reply.status < 300:
                return reply.body
            raise _refused(reply.status, reply.headers, url, what, has_token, kind)
    opener = urllib.request.build_opener(_Hop(hosts, auth_host, auth_path), _net.HTTPSHandler())
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=_repo.DOWNLOAD_TIMEOUT) as r:
            _keep_headers(reply_headers, r.headers.items())
            buf = bytearray()
            while True:
                chunk = r.read(_repo.FETCH_CHUNK)
                if not chunk:
                    return bytes(buf)
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise SourceError(f"{what}: response exceeds the {max_bytes // (1024 * 1024)}MB budget")
    except urllib.error.HTTPError as exc:
        _keep_headers(reply_headers, exc.headers.items())
        raise _refused(exc.code, exc.headers.items(), url, what, has_token, kind) from None
    except urllib.error.URLError as exc:
        raise SourceError(f"{what}: {exc.reason}") from None
    except OSError as exc:                       # includes socket timeouts
        raise SourceError(f"{what}: network error ({type(exc).__name__})") from None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A POST follows no redirect: urllib makes the 3xx an HTTPError, the answer's status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _post(url, headers, data, max_bytes, hosts, auth_host, what="post", has_token=False, kind="github", auth_path="/",
          reply_headers=None, seconds=POST_SECONDS):
    """A POST of `data` (GH-SCAN-GQL: a query of GitHub's GraphQL API) by `_http`'s rules, `hosts` the URL's, the
    token a credential of `auth_host` on the native transport (decision 14) and on urllib's a header of this request
    alone, the answer's headers into `reply_headers`, the body within `max_bytes`; and two more: no redirect is
    followed (the answer is the API's own, an error otherwise), and `seconds` is the time it has in all, from before
    the connection to the body's last byte. The native transport takes it as its total timeout; on urllib's it is
    F-07's deadline (guard._Deadline: each connection made within it, a watchdog that ends a pending TLS handshake,
    header read or body read when it is up, each read of the body cut to the time left, and an end the watchdog made
    never taken for the body's end). -> the body; SourceError otherwise (`status` an HTTP error's)."""
    timeout = min(_repo.METADATA_TIMEOUT, seconds)
    if _net.chosen(url):
        plain = [(k, v) for k, v in headers.items() if k.lower() not in _TOKEN_HEADERS]
        key = _net.host_key(f"https://{auth_host}/")
        credentials = [_net.Credential(key, auth_path, k, v) for k, v in headers.items()
                       if k.lower() in _TOKEN_HEADERS]
        try:
            reply = _net.request(url, hosts=sorted(hosts), method="POST", headers=plain, data=data,
                                 credentials=credentials, max_bytes=max_bytes, timeout=timeout, max_redirects=0,
                                 total_timeout=seconds)
        except _net.UsePython:
            pass                                 # (urllib below)
        except _net.NetError as exc:
            if exc.kind == "too-large":
                raise SourceError(f"{what}: response exceeds the {max_bytes // 1024} KB budget") from None
            if exc.kind == "refused":
                raise SourceError(f"{what}: redirect blocked ({exc})") from None
            if "redirect" in str(exc):
                raise SourceError(f"{what}: answered with a redirect, which a POST does not follow") from None
            if exc.kind in ("timeout", "network"):
                raise SourceError(f"{what}: network error ({exc.kind}; {seconds:g} s in all)") from None
            raise SourceError(f"{what}: {exc}") from None
        else:
            _keep_headers(reply_headers, reply.headers)
            if 200 <= reply.status < 300:
                return reply.body
            raise _refused(reply.status, reply.headers, url, what, has_token, kind)
    from lazaret.registry import guard as _guard          # (F-07's deadline; the guard imports nothing of this module)
    deadline = _guard._Deadline(seconds, _shown(url))
    try:
        return _post_urllib(url, headers, data, max_bytes, what, has_token, kind, reply_headers, deadline, timeout,
                            _guard)
    except _repo.FetchError:                     # (the deadline's: whatever a call returned or raised once it was up)
        raise SourceError(f"{what}: no answer within {seconds:g} s") from None
    finally:
        deadline.close()


def _post_opener(guard):
    """urllib's opener for a POST: no redirect followed, and the guard's handlers, whose connections are made and
    watched within a request's deadline (F-07); its HTTPS one is nativenet's, TLS_FLOOR and all (the TLS floor's
    check reads this list: tests/scanner/test_tls_floor.py)."""
    handlers = [_NoRedirect(), guard._HTTPHandler(), guard._HTTPSHandler()]
    return urllib.request.build_opener(*handlers)


def _post_urllib(url, headers, data, max_bytes, what, has_token, kind, reply_headers, deadline, timeout, guard):
    """`_post` on urllib's transport, within `deadline` (guard._Deadline; its FetchError once the time is up)."""
    opener = _post_opener(guard)
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    req.lazaret_deadline = deadline
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        deadline.check()
        _keep_headers(reply_headers, exc.headers.items())
        raise _refused(exc.code, exc.headers.items(), url, what, has_token, kind) from None
    except urllib.error.URLError as exc:
        deadline.check(exc.reason, isinstance(exc.reason, TimeoutError))  # (a timeout of a call cut to the time left)
        raise SourceError(f"{what}: {exc.reason}") from None
    except (OSError, http.client.HTTPException) as exc:
        deadline.check(exc, isinstance(exc, TimeoutError))  # (a timeout of a call cut to the time left)
        raise SourceError(f"{what}: network error ({type(exc).__name__})") from None
    too_big = f"{what}: response exceeds the {max_bytes // 1024} KB budget"
    with guard._Timed(resp, deadline, timeout) as r:
        _keep_headers(reply_headers, r.headers.items())
        length = r.headers.get("Content-Length")
        if length and length.isdigit() and int(length) > max_bytes:
            raise SourceError(too_big)
        buf = bytearray()
        while True:
            try:
                chunk = r.read1(_repo.FETCH_CHUNK)
            except (OSError, http.client.HTTPException) as exc:
                deadline.check()
                raise SourceError(f"{what}: network error ({type(exc).__name__})") from None
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) > max_bytes:
                raise SourceError(too_big)
        deadline.check()                         # (an end the watchdog made is not the body's end)
        if length and length.isdigit() and len(buf) != int(length):
            raise SourceError(f"{what}: the answer ended after {len(buf)} of its {length} bytes")
        return bytes(buf)


def _json(raw, what):
    try:
        return _repo._deep_safe_loads(raw, what)
    except _repo.FetchError as exc:
        raise SourceError(str(exc)) from None


class Client:
    """One host's API: resolving a ref, fetching an archive, listing a tree.
    `http(url, headers, max_bytes, hosts, auth_host, ...)` is the network
    seam: tests give it fixed answers."""

    def __init__(self, kind, base=None, token=None, http=None):
        self.kind, self.token = kind, token
        self._http = http or _http
        if kind == "github":
            self.base = None
            self.hosts = {GITHUB_API, GITHUB_ARCHIVE, GITHUB_RAW}
            self.auth_host, self.auth_path = GITHUB_API, "/"
        else:
            self.base = base or gitlab_base({})
            parts = urllib.parse.urlsplit(self.base)
            self.auth_host = parts.netloc.lower()
            self.auth_path = parts.path.rstrip("/") + "/"           # (a GitLab under a path prefix: the token's)
            self.hosts = {self.auth_host}
        self.calls = []                          # the URLs asked for, for the report and the tests

    def get(self, url, what, accept=None, max_bytes=None, reply_headers=None):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.netloc.lower() not in self.hosts:
            raise SourceError(f"{what}: host not allowed ({parts.netloc!r})")
        headers = {"User-Agent": _repo.USER_AGENT}
        if accept:
            headers["Accept"] = accept
        if self.kind == "github":
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        if self.token and _covers(parts, self.auth_host, self.auth_path):
            if self.kind == "github":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                headers["PRIVATE-TOKEN"] = self.token
        self.calls.append(_shown(url))
        more = {} if reply_headers is None else {"reply_headers": reply_headers}   # (a seam need not take it)
        return self._http(url, headers, max_bytes or _repo.MAX_FEED_BYTES, self.hosts, self.auth_host,
                          what=what, has_token=bool(self.token), kind=self.kind, auth_path=self.auth_path, **more)

    def post(self, url, what, data, max_bytes=POST_BYTES, reply_headers=None, seconds=POST_SECONDS):
        """POST `data` (JSON) to the API host itself, the token with it (GH-SCAN-GQL: `POST
        https://api.github.com/graphql`, GitHub's GraphQL API): https and that host alone (not the archive's or the
        raw files'), no redirect followed, `seconds` in all (`_post`). The seam `http` gets it as a GET, with
        method="POST", data= and seconds=."""
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" or parts.netloc.lower() != self.auth_host \
                or not _covers(parts, self.auth_host, self.auth_path):
            raise SourceError(f"{what}: host not allowed ({parts.netloc!r})")
        headers = {"User-Agent": _repo.USER_AGENT, "Accept": "application/json", "Content-Type": "application/json"}
        if self.token:
            if self.kind == "github":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                headers["PRIVATE-TOKEN"] = self.token
        self.calls.append(_shown(url))
        more = {} if reply_headers is None else {"reply_headers": reply_headers}
        return self._http(url, headers, max_bytes, {self.auth_host}, self.auth_host, what=what,
                          has_token=bool(self.token), kind=self.kind, auth_path=self.auth_path, method="POST",
                          data=bytes(data), seconds=seconds, **more)

    # -- GitHub
    def _gh(self, src):
        owner, repo = src.path.split("/")
        return f"https://{GITHUB_API}/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"

    # -- GitLab
    def _gl(self, src):
        return f"{self.base}/api/v4/projects/{urllib.parse.quote(src.path, safe='')}"

    def resolve(self, src):
        """The commit SHA of `src.ref` (the default branch when None)."""
        ref = src.ref
        if ref and SHA_RE.fullmatch(ref):
            return ref
        what = f"resolving {spec_text(src)}"
        if self.kind == "github":
            raw = self.get(f"{self._gh(src)}/commits/{urllib.parse.quote(ref or 'HEAD', safe='/')}", what,
                           accept="application/vnd.github.sha")
            sha = raw.decode("ascii", "replace").strip()
        else:
            if ref is None:
                project = _json(self.get(self._gl(src), what, accept="application/json"), what)
                ref = project.get("default_branch") if isinstance(project, dict) else None
                if not isinstance(ref, str) or not ref:
                    raise SourceError(f"{what}: the project has no default branch (an empty repository?)")
                _check_ref(ref)
            doc = _json(self.get(f"{self._gl(src)}/repository/commits/{urllib.parse.quote(ref, safe='')}", what,
                                 accept="application/json"), what)
            sha = doc.get("id") if isinstance(doc, dict) else None
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
            raise SourceError(f"{what}: the answer is not a commit SHA")
        return sha

    def archive(self, src, sha):
        """The commit's .tar.gz, within the registry's per-archive budget."""
        what = f"fetching {spec_text(src, sha)}"
        if self.kind == "github":
            owner, repo = (urllib.parse.quote(p) for p in src.path.split("/"))
            # (a token opens private repositories: only the API serves those, and
            # redirects to codeload with a short-lived URL of its own)
            url = (f"{self._gh(src)}/tarball/{sha}" if self.token
                   else f"https://{GITHUB_ARCHIVE}/{owner}/{repo}/tar.gz/{sha}")
        else:
            url = f"{self._gl(src)}/repository/archive.tar.gz?sha={sha}"
        return self.get(url, what, max_bytes=_repo.MAX_DOWNLOAD_BYTES)

    def file(self, src, sha, path):
        """One file of the commit, by its path in the tree (N-5: a path the
        archive left out), within the registry's per-file limit."""
        what = f"fetching {path} from {spec_text(src, sha)}"
        if self.kind == "github" and not self.token:
            owner, repo = (urllib.parse.quote(p) for p in src.path.split("/"))
            url, accept = f"https://{GITHUB_RAW}/{owner}/{repo}/{sha}/{urllib.parse.quote(path)}", None
        elif self.kind == "github":
            url, accept = f"{self._gh(src)}/contents/{urllib.parse.quote(path)}?ref={sha}", "application/vnd.github.raw"
        else:
            url, accept = f"{self._gl(src)}/repository/files/{urllib.parse.quote(path, safe='')}/raw?ref={sha}", None
        return self.get(url, what, accept=accept, max_bytes=_repo.MAX_MEMBER)

    def tree(self, src, sha):
        """The files of the commit's tree: ({path: its blob's id, or None},
        complete, notes). `complete` is False when the host would not list it
        whole."""
        what = f"listing the tree of {spec_text(src, sha)}"
        paths, notes = {}, []
        if self.kind == "github":
            doc = _json(self.get(f"{self._gh(src)}/git/trees/{sha}?recursive=1", what,
                                 accept="application/vnd.github+json", max_bytes=MAX_TREE_BYTES), what)
            entries = doc.get("tree") if isinstance(doc, dict) else None
            if not isinstance(entries, list):
                raise SourceError(f"{what}: unexpected answer")
            complete = not doc.get("truncated")
            if not complete:
                notes.append("GitHub listed only part of the tree (more than 100,000 entries or 7 MB)")
        else:
            entries, complete = [], True
            for page in range(1, GITLAB_TREE_PAGES + 1):
                chunk = _json(self.get(f"{self._gl(src)}/repository/tree?ref={sha}&recursive=true"
                                       f"&per_page=100&page={page}", what, accept="application/json",
                                       max_bytes=MAX_TREE_BYTES), what)
                if not isinstance(chunk, list):
                    raise SourceError(f"{what}: unexpected answer")
                entries.extend(chunk)
                if len(chunk) < 100:
                    break
            else:
                complete = False
                notes.append(f"the tree has more than {GITLAB_TREE_PAGES * 100} entries; not all were listed")
        submodules = 0
        for e in entries:
            if not isinstance(e, dict) or not isinstance(e.get("path"), str):
                continue
            kind = e.get("type")
            if kind == "commit":
                submodules += 1
            elif kind == "blob" and str(e.get("mode", "")) != "120000":     # (a link is made a file by its target)
                blob = e.get("sha") if self.kind == "github" else e.get("id")
                paths[e["path"]] = blob if isinstance(blob, str) and SHA_RE.fullmatch(blob) else None
        if submodules:
            notes.append(f"{submodules} submodule(s) are not part of the archive and were not read")
        return paths, complete, notes


# ---------------------------------------------------------------- the archive
def archive_commit(data):
    """The commit a `git archive` tarball says it holds: the comment in its
    pax global header (both GitHub's and GitLab's carry it), or None."""
    try:
        head = zlib.decompressobj(31).decompress(bytes(data[:8192]), 4096)
    except zlib.error:
        return None
    if len(head) < 512 or head[156:157] != b"g":
        return None
    try:
        size = int(head[124:135].split(b"\0")[0].strip() or b"0", 8)
    except ValueError:
        return None
    m = re.search(rb"(?:^|\n)\d+ comment=([0-9a-f]{40}|[0-9a-f]{64})\n", head[512:512 + size])
    return m.group(1).decode() if m else None


class Checkout:
    """A commit read into a directory: `root`, what it is and what could not
    be read. Nothing in it is a secret (the token is never kept)."""

    def __init__(self, source, commit, root, tmp):
        self.source, self.commit, self.root, self._tmp = source, commit, root, tmp
        self.files = 0
        self.bytes = 0
        self.skipped = []         # (path, why): a file not written (too large, in the way of another)
        self.incomplete = []      # (reason, detail): the commit was not read whole
        self.notes = []           # things worth saying that do not make it incomplete
        self.anomalies = []       # (kind, path, detail): what the archive did oddly
        self.twins = []           # the twin trees beside the root (_Writer): each scanned as its own project
        self.overlaid = {}        # twin tree -> the paths of the commit's other files it was given (_Writer.overlay)
        self.calls = []

    @property
    def spec(self):
        return spec_text(self.source, self.commit)

    @property
    def complete(self):
        return not self.incomplete

    def summary(self):
        return {"source": self.spec, "commit": self.commit, "root": self.root, "twins": list(self.twins),
                "files": self.files, "bytes": self.bytes, "complete": self.complete,
                "incomplete": list(self.incomplete),
                "skipped": [list(s) for s in self.skipped], "notes": list(self.notes),
                "anomalies": [list(a) for a in self.anomalies]}

    def cleanup(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None
        for twin in self.twins:
            shutil.rmtree(twin, ignore_errors=True)
        self.twins, self.overlaid = [], {}

    def __repr__(self):
        return f"<Checkout {self.spec} {self.files} files>"


def not_covered(ck):
    """What the commit holds that a scan of its checkout does not read: the
    checkout's own `incomplete`, and every file that could not be written. A
    file left out only for its size is not here: a scan of a folder does not
    read one either. `lazaret scan github:…` (sourcescan) and the registry's
    repository scans (ghdiscover) both count these."""
    gaps, seen = list(ck.incomplete), set()
    for rel, why in ck.skipped:
        gap = ("skipped", f"{rel}: {why}")
        if not why.startswith("larger than") and gap not in seen:
            seen.add(gap)
            gaps.append(gap)
    return gaps


#: the twin trees a checkout may make beside its root (MAX_TWIN_TREES): a path the disk holds as one name with another
#: path of the commit goes to the first of them where it can be written; one more such path is not written
MAX_TWIN_TREES = 16

#: the files the twin trees may be given of the commit's others, all trees together (_Writer.overlay): the files
#: written times the twin trees; past it no tree is given any, and the scans read each twin tree's own files alone
MAX_OVERLAY_FILES = 50_000

#: a name Windows does not keep as given (`_windows_refuses`): a device's (CON, NUL, COM1, …, with any extension), an
#: alternate data stream's (`name:stream`), one that ends in a dot or a space (the disk drops them)
WINDOWS = os.name == "nt"
_WINDOWS_DEVICES = re.compile(r"(?i)(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|(COM|LPT)[0-9\u00b9\u00b2\u00b3])")


def _windows_refuses(part):
    """Why Windows would not keep the path component `part` as it is, or None."""
    if ":" in part:
        return "a data stream's name"
    if part.endswith((".", " ")):
        return "a name ending in a dot or a space"
    if _WINDOWS_DEVICES.fullmatch(part.split(".", 1)[0].rstrip(" ")):
        return "a device's name"
    return None


class _Writer:
    """Writes the files of a checkout by their real paths, never through a link
    and never over a file written before (MAC-TESTS).

    Every path is written under its own name in the checkout's root wherever
    the disk lets it: each folder is made by this writer (`mkdir`, which fails
    where anything is), each file is created where nothing is (O_EXCL). So on
    a disk that tells names apart every path of the commit is in the root as
    the commit has it. macOS's and Windows' disks take names that differ only
    in case or Unicode form for one: there the second of `App.py` and `app.py`
    (or a folder `lib/` beside a `Lib/` or a file `A`) is refused, and the path
    is written whole, under its real name, in a twin tree beside the root
    (`<root>.lazaret-twin-N`, the first of them where the disk takes it).
    A twin tree holds the commit's paths as the root does, so the scan reads
    each of its files at the commit's path, with the rules that go by path
    (a workflow, a package.json, an agent's settings) as for the root's own
    (`twins`: the scans read the root and each twin tree, each as its own
    project, and report every finding at its path in the commit). Once all
    is written, each twin tree is given every other file of the commit that
    it can hold (`overlay`: a hard link, or a copy), so that what a rule
    reads across files (a hook's script, a helper a tainted call goes into)
    is there too; two paths that are one name on the disk still cannot be in
    one tree, so a checkout with twin trees is not read whole (`apart`, a
    gap in `incomplete`). The checkout's anomalies say which paths were kept
    apart (`case`), one line each. A path that is refused in every twin tree
    (more than MAX_TWIN_TREES names that are one), that the disk cannot hold
    at all (a name too long, or one it refuses) or that Windows would not
    keep as given (`_windows_refuses`), is not written: `skipped`, which
    makes the checkout not read whole (`not_covered`). An archive entry whose
    path was written before (the same path, twice) is written over its own
    file: the later one wins, as an extractor writes it. `written`: the paths
    written; `held`: the paths the archive held, written or not (no path of
    these is fetched again); `kept`: the tree each written path is in (0 for
    the root)."""

    def __init__(self, dest, ck):
        self.root, self.ck = os.path.abspath(dest), ck
        self.trees = [self.root]           # the root, then the twin trees made so far
        self.made = [{""}]                 # each tree's folders made by this writer (the commit's paths)
        self.refused = [{}]                # each tree's folders the disk refused -> why (one name with another there)
        self.entries = [{}]                # each tree: folder -> {name: (the commit's path, a folder?)} made in it
        self.folds = {}                    # a name -> its fold (repo.case_fold), asked only to name a twin
        self.written, self.held, self.kept = set(), set(), {}
        self.noted = set()

    def _fold(self, name):
        if name not in self.folds:
            self.folds[name] = _repo.case_fold(name)
        return self.folds[name]

    def _why(self, k, folder, name, is_folder):
        """Why the disk refused `name` in tree k's `folder` (a folder of the path being written when `is_folder`),
        naming the commit's path it is one name with there: one of the same name (a file and a folder of one name,
        which git does not make), one by the archive reader's fold, or a path written before (a name the disk folds
        as the reader does not)."""
        here = self.entries[k].get(folder, {})
        what = f"its folder {folder + '/' if folder else ''}{name}/" if is_folder else None
        if name in here:
            path, other_is_folder = here[name]
            other = f"the archive's {'folder' if other_is_folder else 'file'} {path}{'/' if other_is_folder else ''}"
            return f"{what} has the name of {other}" if what else f"{other} has its name"
        key = self._fold(name)
        twin = next((f"{path}{'/' if other_is_folder else ''}" for other, (path, other_is_folder) in here.items()
                     if self._fold(other) == key), "a path written before")
        return f"{what} is one name on this disk with {twin}" if what else f"one name on this disk with {twin}"

    def _tree(self, k):
        """Tree k, made when first needed -> its root."""
        while len(self.trees) <= k:
            n = len(self.trees)
            while True:
                path = f"{self.root}.lazaret-twin-{n}"
                try:
                    os.mkdir(path, 0o700)
                    break
                except FileExistsError:
                    n += 1
            self.trees.append(path)
            self.made.append({""})
            self.refused.append({})
            self.entries.append({})
            self.ck.twins.append(path)
        return self.trees[k]

    def _note(self, rel, whys):
        """Say that the commit's `rel` was kept apart in a twin tree: why each tree before it refused it."""
        if rel in self.noted:
            return
        self.noted.add(rel)
        detail = whys[0] + "".join(f"; in twin tree {j}, {why}" for j, why in enumerate(whys[1:], 1))
        anomalies = self.ck.anomalies
        # (the archive's reader names the pair too, as it reads it, and what an installer does with it, EG-4: one
        # line, the reader's, and that this checkout kept both)
        same = next((i for i, a in enumerate(anomalies) if a[0] == "case" and a[1] == rel), None)
        if same is None:
            anomalies.append(("case", rel, f"{detail}: kept apart and read at its own path"))
        else:
            anomalies[same] = ("case", rel, f"{anomalies[same][2]}; this checkout kept it apart and read it at its "
                                            f"own path")

    def _folders(self, k, parts):
        """Make the folders of the commit's path `parts` in tree k -> None, or why the disk refused one of them."""
        root, made, refused, entries = self.trees[k], self.made[k], self.refused[k], self.entries[k]
        for i in range(1, len(parts)):
            folder = "/".join(parts[:i])
            if folder in made:
                continue
            if folder in refused:
                return refused[folder]
            parent = "/".join(parts[:i - 1])
            try:
                os.mkdir(os.path.join(root, *parts[:i]))
            except (FileExistsError, NotADirectoryError):
                refused[folder] = self._why(k, parent, parts[i - 1], is_folder=True)
                return refused[folder]
            made.add(folder)
            entries.setdefault(parent, {})[parts[i - 1]] = (folder, True)
        return None

    def _place(self, k, parts):
        """Make the commit's path `parts` in tree k: its folders, then the file, open for writing -> (the file, None),
        or (None, why) where the disk refuses a name there (one name with another: the path goes to the next tree).
        Raises OSError when the disk cannot hold the path at all."""
        self._tree(k)
        why = self._folders(k, parts)
        if why is not None:
            return None, why
        folder, name = "/".join(parts[:-1]), parts[-1]
        path = os.path.join(self.trees[k], *parts)
        try:
            out = open(path, "xb")
        except (FileExistsError, IsADirectoryError):
            return None, self._why(k, folder, name, is_folder=False)
        except PermissionError:
            # (Windows: a file where its disk has a folder of that name, `A` beside `a/`, is "access denied" there,
            # not EEXIST: it was not written at all, where a twin tree keeps it)
            if not os.path.isdir(path):
                raise
            return None, self._why(k, folder, name, is_folder=False)
        self.entries[k].setdefault(folder, {})[name] = ("/".join(parts), False)
        return out, None

    def write(self, rel, raw):
        ck = self.ck
        self.held.add(rel)
        parts = rel.split("/")
        if any(p in ("", ".", "..") for p in parts):
            ck.skipped.append((rel, "outside the checkout"))
            return
        refuses = next((why for why in map(_windows_refuses, parts) if why), None) if WINDOWS else None
        if refuses:
            ck.skipped.append((rel, f"could not be written ({refuses}, which Windows does not keep as given)"))
            return
        try:
            if rel in self.kept:
                out = open(os.path.join(self.trees[self.kept[rel]], *parts), "wb")    # (the file written for it before)
                k = self.kept[rel]
            else:
                out, whys = None, []
                for k in range(MAX_TWIN_TREES + 1):
                    out, why = self._place(k, parts)
                    if out is not None:
                        break
                    whys.append(why)
                if out is None:
                    ck.skipped.append((rel, f"could not be written (one name on this disk with paths in "
                                            f"{MAX_TWIN_TREES + 1} trees)"))
                    return
                if whys:
                    self._note(rel, whys)
            with out:
                out.write(raw)
        except (OSError, ValueError) as exc:
            ck.skipped.append((rel, f"could not be written ({type(exc).__name__})"))
            return
        self.kept[rel] = k
        self.written.add(rel)
        ck.files += 1
        ck.bytes += len(raw)

    def apart(self):
        """The paths written in a twin tree, sorted."""
        return sorted(rel for rel, k in self.kept.items() if k)

    def overlay(self):
        """Give each twin tree every other file of the commit that it can hold: the root's, then each other twin
        tree's, each a hard link to the file written (a copy where the disk makes none), made only where nothing is
        (O_EXCL, mkdir: a name that is one with the tree's own is left out), never through a link. Kept in
        `ck.overlaid` ({twin tree: the paths given it}), which the scans leave out of what each tree holds of its
        own. -> how many were given, or None when MAX_OVERLAY_FILES is less than the files times the twin trees."""
        twins = len(self.trees) - 1
        if not twins:
            return 0
        if len(self.kept) * twins > MAX_OVERLAY_FILES:
            return None
        order = sorted(self.kept.items(), key=lambda item: item[1])        # (the root's first; stable)
        given = 0
        for k in range(1, twins + 1):
            got = self.ck.overlaid.setdefault(self.trees[k], set())
            for rel, j in order:
                parts = rel.split("/")
                if j != k and self._folders(k, parts) is None and self._link(
                        os.path.join(self.trees[j], *parts), os.path.join(self.trees[k], *parts)):
                    got.add(rel)
                    given += 1
        return given

    @staticmethod
    def _link(src, dst):
        """`dst` made as `src` (a file this writer wrote): a hard link, or a copy -> made (False: a name there)."""
        try:
            os.link(src, dst, follow_symlinks=False)
            return True
        except FileExistsError:
            return False
        except (OSError, NotImplementedError):              # (no hard links on this disk, or across these folders)
            pass
        try:
            fd = os.open(src, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
            with os.fdopen(fd, "rb") as inp, open(dst, "xb") as out:
                shutil.copyfileobj(inp, out)
            return True
        except OSError:
            return False


def _write_members(members, writer):
    """Writes the files of `iter_archive`'s members (`_Writer`). -> the set
    of relative paths the archive held (written, or not for a reason the
    tree's fetch cannot change: its size, the disk)."""
    ck = writer.ck
    for m in members:
        rel, size, raw, reason = m
        if reason == "member":
            writer.held.add(rel)
            ck.skipped.append((rel, f"larger than {_repo.MAX_MEMBER // 1_000_000} MB, not read"))
            continue
        if reason:
            ck.incomplete.append((reason, m.detail or f"reading stopped at {rel}"))
            continue
        writer.write(rel, raw)
    return writer.held


def _blob_id(raw, size_of_id):
    """Git's id of a blob holding `raw` (SHA-1, or SHA-256 for a 64-digit id)."""
    head = b"blob %d\0" % len(raw)
    return (hashlib.sha256 if size_of_id == 64 else hashlib.sha1)(head + raw).hexdigest()


def _fetch_missing(client, src, sha, missing, writer, deadline):
    """N-5: each path of the tree the archive left out, fetched on its own and
    written with the rest, when it is the blob the tree names. `missing`:
    [(canonical path, the tree's path, its blob's id or None)], sorted; no
    request is made after `deadline` (time.monotonic()).
    -> (the canonical paths still missing, why the rest were not fetched)."""
    ck, left, why, spent = writer.ck, [], None, 0
    for k, (rel, path, blob) in enumerate(missing):
        if why is None and k >= MAX_MISSING_FILES:
            why = f"at most {MAX_MISSING_FILES} are fetched one by one"
        if why is None and time.monotonic() >= deadline:
            why = f"the time budget ({MISSING_FILES_SECONDS:g} s) is spent"
        if why is not None:
            left.append(rel)
            continue
        try:
            raw = client.file(src, sha, path)
        except SourceError as exc:
            text = str(exc)
            if "exceeds" in text:
                ck.skipped.append((rel, f"larger than {_repo.MAX_MEMBER // 1_000_000} MB, not read"))
                continue
            left.append(rel)
            if getattr(exc, "status", None) in (403, 429) or "rate limit" in text:
                why = text                        # (asking on would only be refused again)
            continue
        if blob is not None and _blob_id(raw, len(blob)) != blob:
            left.append(rel)
            ck.anomalies.append(("blob", rel, "fetched on its own, it is not the blob the commit's tree names"))
            continue
        spent += len(raw)
        if spent > _repo.MAX_DOWNLOAD_BYTES:
            left.append(rel)
            why = f"the download budget ({_repo.MAX_DOWNLOAD_BYTES // (1024 * 1024)} MB) is spent"
            continue
        writer.write(rel, raw)
    return left, why


def checkout(spec, dest=None, *, env=None, http=None, check_tree=True):
    """Fetch `spec` at its commit into `dest` (a new temporary directory when
    None; the caller removes it: `Checkout.cleanup()`). Raises SourceError
    when the commit cannot be resolved or fetched, or the archive is for
    another commit; what could not be read whole is `.incomplete`."""
    env = os.environ if env is None else env
    src = spec if isinstance(spec, Source) else parse_source(spec)
    client = Client(src.kind, base=gitlab_base(env) if src.kind == "gitlab" else None,
                    token=_token(src.kind, env), http=http)
    commit = client.resolve(src)
    data = client.archive(src, commit)
    claimed = archive_commit(data)
    if claimed is not None and claimed != commit:
        raise SourceError(f"the archive for {spec_text(src, commit)} says it is for commit {claimed}")
    tmp = None
    if dest is None:
        tmp = dest = tempfile.mkdtemp(prefix="lazaret-src-")
    else:
        os.makedirs(dest, exist_ok=True)
    ck = Checkout(src, commit, os.path.abspath(dest), tmp)
    try:
        if claimed is None:
            ck.notes.append("the archive names no commit, so it was not checked against the one resolved")
        budget = _repo.Budget(deadline=time.monotonic() + _repo.SCAN_TIMEOUT)
        members = _repo.iter_archive(data, "tgz", "sdist", budget=budget, anomalies=ck.anomalies)
        writer = _Writer(ck.root, ck)
        held = set(_write_members(members, writer))
        if check_tree:
            paths, complete, notes = client.tree(src, commit)
            ck.notes.extend(notes)
            if not complete:
                ck.incomplete.append(("tree", "the tree was not listed whole, so paths left out of the archive "
                                              "(`export-ignore`) cannot be ruled out"))
            norm = {}
            for p, blob in paths.items():
                rel = _repo.canonical_member_path("x/" + p, "sdist")[0]
                if rel:
                    norm.setdefault(rel, (p, blob))
            missing = sorted((rel, p, blob) for rel, (p, blob) in norm.items() if rel not in held)
            if missing:
                left, why = _fetch_missing(client, src, commit, missing, writer,
                                           deadline=time.monotonic() + MISSING_FILES_SECONDS)
                fetched = len(missing) - len(left)
                if fetched:
                    ck.notes.append(f"{fetched} path(s) the archive left out (`export-ignore` in .gitattributes) "
                                    f"were fetched one by one")
                if left:
                    shown = ", ".join(left[:5]) + (f" and {len(left) - 5} more" if len(left) > 5 else "")
                    ck.incomplete.append(("export-ignore", f"{len(left)} path(s) are in the commit but not in its "
                                                           f"archive (`export-ignore` in .gitattributes), and were not "
                                                           f"fetched on their own"
                                                           + (f" ({why})" if why else "") + f": {shown}"))
        apart = writer.apart()
        if apart:
            # (MAC-TESTS: each twin tree is given the commit's other files, and still two paths that are one name on
            # this disk are never in one tree, so what a rule reads across them is not seen: not read whole)
            if writer.overlay() is None:
                ck.notes.append(f"the twin trees were not given the commit's other files ({len(writer.kept)} files "
                                f"in {len(ck.twins)} twin trees is more than {MAX_OVERLAY_FILES}): each is read alone")
            shown = ", ".join(apart[:5]) + (f" and {len(apart) - 5} more" if len(apart) > 5 else "")
            ck.incomplete.append(("case", f"{len(apart)} path(s) were kept apart from the commit's other files on "
                                          f"this disk, each one name there with another path (names that differ only "
                                          f"in case or Unicode form), so rules across files may not have seen them "
                                          f"together: {shown}"))
    except BaseException:
        ck.cleanup()
        raise
    ck.calls = list(client.calls)
    return ck


@contextlib.contextmanager
def scanned_checkout(spec, **kw):
    """`with scanned_checkout("github:o/r@v1") as ck:` scans `ck.root` and
    each of `ck.twins` (core.scan_twins); the directories are removed on the
    way out."""
    ck = checkout(spec, **kw)
    try:
        yield ck
    finally:
        ck.cleanup()


def main(argv=None):
    """python -m lazaret.registry.sources SPEC [--no-tree] [--keep]: resolves,
    fetches and reads a source, and prints what it found (JSON). The CLI's
    `scan github:…` uses the same calls."""
    _core.configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)
    keep, tree = "--keep" in argv, "--no-tree" not in argv
    specs = [a for a in argv if not a.startswith("--")]
    if len(specs) != 1:
        print("usage: python -m lazaret.registry.sources github:owner/repo[@ref] [--no-tree] [--keep]", file=sys.stderr)
        return 2
    try:
        ck = checkout(specs[0], check_tree=tree)
    except SourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        print(json.dumps(ck.summary(), indent=2))
    finally:
        if not keep:
            ck.cleanup()
    return 0 if ck.complete else 3


if __name__ == "__main__":
    sys.exit(main())
