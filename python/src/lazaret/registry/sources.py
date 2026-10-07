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
import json
import os
import re
import shutil
import sys
import tempfile
import time
import unicodedata
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

Source = namedtuple("Source", "kind path ref")


class SourceError(ValueError):
    """A source was refused or could not be fetched. `status` is the HTTP
    status when the server answered with an error."""
    status = None


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
        reset = headers.get("x-ratelimit-reset", "")
        if reset.isdigit():
            when = " until " + time.strftime("%H:%M UTC", time.gmtime(int(reset)))
        elif headers.get("retry-after", "").isdigit():
            when = f" for {headers['retry-after']} seconds"
        more = "" if has_token else f"; setting {var} (read-only) raises the limit"
        return f"{what}: rate limit reached, wait{when}{more}"
    return f"{what}: HTTP {status} from {_shown(url)}"


_TOKEN_HEADERS = ("authorization", "private-token")


def _http(url, headers, max_bytes, hosts, auth_host, what="fetch", has_token=False, kind="github", auth_path="/"):
    """The real fetch: a byte-budgeted read, through the native transport (NET-1, scanner/nativenet.py: `hosts` the
    rule for the URL and every redirect), with the token as a credential of `auth_host` and the paths under
    `auth_path` (decision 14: the native client gives it to those hops and to no other, DESIGN.md §5j; a GitLab
    under a path prefix has the prefix); through urllib and `_Hop`, which takes a token off a redirect anywhere
    else, where the native transport is not to be used."""
    if _net.chosen(url):
        plain = [(k, v) for k, v in headers.items() if k.lower() not in _TOKEN_HEADERS]
        key = _net.host_key(f"https://{auth_host}/")
        credentials = [_net.Credential(key, auth_path, k, v) for k, v in headers.items()
                       if k.lower() in _TOKEN_HEADERS]
        try:
            reply = _net.request(url, hosts=sorted(hosts), headers=plain, credentials=credentials, max_bytes=max_bytes,
                                 timeout=_repo.DOWNLOAD_TIMEOUT, max_redirects=_repo.MAX_REDIRECTS)
        except _net.UsePython:
            pass                                 # (urllib below: a server without TLS 1.3, a proxy over TLS)
        except _net.NetError as exc:
            if exc.kind == "too-large":
                raise SourceError(f"{what}: response exceeds the {max_bytes // (1024 * 1024)}MB budget") from None
            if exc.kind == "refused":
                raise SourceError(f"{what}: redirect blocked ({exc})") from None
            if exc.kind in ("timeout", "network"):
                raise SourceError(f"{what}: network error ({exc.kind})") from None
            raise SourceError(f"{what}: {exc}") from None
        else:
            if 200 <= reply.status < 300:
                return reply.body
            err = SourceError(_explain(reply.status, {k.lower(): v for k, v in reply.headers}, url, what, has_token,
                                       kind))
            err.status = reply.status
            raise err
    opener = urllib.request.build_opener(_Hop(hosts, auth_host, auth_path))
    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=_repo.DOWNLOAD_TIMEOUT) as r:
            buf = bytearray()
            while True:
                chunk = r.read(_repo.FETCH_CHUNK)
                if not chunk:
                    return bytes(buf)
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise SourceError(f"{what}: response exceeds the {max_bytes // (1024 * 1024)}MB budget")
    except urllib.error.HTTPError as exc:
        err = SourceError(_explain(exc.code, {k.lower(): v for k, v in exc.headers.items()},
                                   url, what, has_token, kind))
        err.status = exc.code
        raise err from None
    except urllib.error.URLError as exc:
        raise SourceError(f"{what}: {exc.reason}") from None
    except OSError as exc:                       # includes socket timeouts
        raise SourceError(f"{what}: network error ({type(exc).__name__})") from None


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

    def get(self, url, what, accept=None, max_bytes=None):
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
        return self._http(url, headers, max_bytes or _repo.MAX_FEED_BYTES, self.hosts, self.auth_host,
                          what=what, has_token=bool(self.token), kind=self.kind, auth_path=self.auth_path)

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
        self.calls = []

    @property
    def spec(self):
        return spec_text(self.source, self.commit)

    @property
    def complete(self):
        return not self.incomplete

    def summary(self):
        return {"source": self.spec, "commit": self.commit, "root": self.root, "files": self.files,
                "bytes": self.bytes, "complete": self.complete, "incomplete": list(self.incomplete),
                "skipped": [list(s) for s in self.skipped], "notes": list(self.notes),
                "anomalies": [list(a) for a in self.anomalies]}

    def cleanup(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def __repr__(self):
        return f"<Checkout {self.spec} {self.files} files>"


class _Writer:
    """Writes files under a checkout's root: by their canonical relative
    path, never through a link, a path's case-fold collision kept apart
    instead of overwritten. `written`: the relative paths written (as the
    archive or the tree named them)."""

    def __init__(self, dest, ck):
        self.root, self.ck = os.path.realpath(dest), ck
        self.taken, self.written = {}, set()

    def write(self, rel, raw):
        ck = self.ck
        key = unicodedata.normalize("NFC", rel).casefold()
        out = rel
        if key in self.taken and self.taken[key] != rel:
            n = 1
            while f"{rel}.lazaret-dup{n}" in self.written:
                n += 1
            out = f"{rel}.lazaret-dup{n}"
            detail = f"differs from {self.taken[key]} only in case or form; kept as {out}"
            # (the archive's reader names the pair too, as it reads it: one line, with where it was kept, EG-4)
            same = next((i for i, a in enumerate(ck.anomalies) if a[0] == "case" and a[1] == rel), None)
            if same is None:
                ck.anomalies.append(("case", rel, detail))
            else:
                ck.anomalies[same] = ("case", rel, detail)
        self.taken.setdefault(key, rel)
        target = os.path.join(self.root, *out.split("/"))
        if os.path.commonpath([self.root, os.path.realpath(os.path.dirname(target))]) != self.root:
            ck.skipped.append((rel, "outside the checkout"))
            return
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(raw)
        except (OSError, ValueError) as exc:
            ck.skipped.append((rel, f"could not be written ({type(exc).__name__})"))
            return
        self.written.add(rel)
        ck.files += 1
        ck.bytes += len(raw)


def _write_members(members, writer):
    """Writes the files of `iter_archive`'s members (`_Writer`). -> the set
    of relative paths written."""
    ck = writer.ck
    for m in members:
        rel, size, raw, reason = m
        if reason == "member":
            ck.skipped.append((rel, f"larger than {_repo.MAX_MEMBER // 1_000_000} MB, not read"))
            continue
        if reason:
            ck.incomplete.append((reason, m.detail or f"reading stopped at {rel}"))
            continue
        writer.write(rel, raw)
    return writer.written


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
        written = set(_write_members(members, writer))
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
            missing = sorted((rel, p, blob) for rel, (p, blob) in norm.items() if rel not in written)
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
    except BaseException:
        ck.cleanup()
        raise
    ck.calls = list(client.calls)
    return ck


@contextlib.contextmanager
def scanned_checkout(spec, **kw):
    """`with scanned_checkout("github:o/r@v1") as ck:` scans `ck.root`; the
    directory is removed on the way out."""
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
