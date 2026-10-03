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
on GitLab) and every path in it that the archive lacks is reported, and the
checkout is incomplete: fail closed, as everywhere in Lazaret.
"""

import contextlib
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

from lazaret.registry import repo as _repo
from lazaret.scanner import core as _core

__all__ = ["SourceError", "Source", "Checkout", "parse_source", "checkout", "scanned_checkout",
           "archive_commit", "gitlab_base"]

GITHUB_API = "api.github.com"
GITHUB_ARCHIVE = "codeload.github.com"
GITLAB_DEFAULT = "https://gitlab.com"
SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MAX_TREE_BYTES = 16 * 1024 * 1024         # one tree listing's JSON
GITLAB_TREE_PAGES = 100                   # of 100 entries: a larger tree is not listed whole

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
    if "//" in prefix or ".." in prefix.split("/"):
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
    follows it to another host (urllib would send the header on), and the
    number of hops is capped."""

    max_redirections = _repo.MAX_REDIRECTS

    def __init__(self, hosts, auth_host):
        self.hosts, self.auth_host = frozenset(hosts), auth_host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.scheme != "https" or parts.netloc.lower() not in self.hosts:
            raise urllib.error.URLError(f"redirect blocked: {parts.scheme}://{parts.netloc}")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and parts.netloc.lower() != self.auth_host:
            for table in (new.headers, new.unredirected_hdrs):
                for key in [k for k in table if k.lower() in ("authorization", "private-token")]:
                    del table[key]
        return new


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


def _http(url, headers, max_bytes, hosts, auth_host, what="fetch", has_token=False, kind="github"):
    """The real fetch: a byte-budgeted read through `_Hop`."""
    opener = urllib.request.build_opener(_Hop(hosts, auth_host))
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
            self.hosts = {GITHUB_API, GITHUB_ARCHIVE}
            self.auth_host = GITHUB_API
        else:
            self.base = base or gitlab_base({})
            self.auth_host = urllib.parse.urlsplit(self.base).netloc.lower()
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
        if self.token and parts.netloc.lower() == self.auth_host:
            if self.kind == "github":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                headers["PRIVATE-TOKEN"] = self.token
        self.calls.append(_shown(url))
        return self._http(url, headers, max_bytes or _repo.MAX_FEED_BYTES, self.hosts, self.auth_host,
                          what=what, has_token=bool(self.token), kind=self.kind)

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

    def tree(self, src, sha):
        """The files of the commit's tree: (paths, complete, notes). `complete`
        is False when the host would not list it whole."""
        what = f"listing the tree of {spec_text(src, sha)}"
        paths, notes = set(), []
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
                paths.add(e["path"])
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


def _write_members(members, dest, ck):
    """Writes the files of `iter_archive`'s members under `dest`: by their
    canonical relative path, never through a link, a path's case-fold
    collision kept apart instead of overwritten. -> the set of relative
    paths written (as the archive named them)."""
    root = os.path.realpath(dest)
    taken, written = {}, set()
    for m in members:
        rel, size, raw, reason = m
        if reason == "member":
            ck.skipped.append((rel, f"larger than {_repo.MAX_MEMBER // 1_000_000} MB, not read"))
            continue
        if reason:
            ck.incomplete.append((reason, m.detail or f"reading stopped at {rel}"))
            continue
        key = unicodedata.normalize("NFC", rel).casefold()
        out = rel
        if key in taken and taken[key] != rel:
            n = 1
            while f"{rel}.lazaret-dup{n}" in written:
                n += 1
            out = f"{rel}.lazaret-dup{n}"
            ck.anomalies.append(("case", rel, f"differs from {taken[key]} only in case or form; kept as {out}"))
        taken.setdefault(key, rel)
        target = os.path.join(root, *out.split("/"))
        if os.path.commonpath([root, os.path.realpath(os.path.dirname(target))]) != root:
            ck.skipped.append((rel, "outside the checkout"))
            continue
        try:
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(raw)
        except (OSError, ValueError) as exc:
            ck.skipped.append((rel, f"could not be written ({type(exc).__name__})"))
            continue
        written.add(rel)
        ck.files += 1
        ck.bytes += len(raw)
    return written


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
        written = _write_members(members, ck.root, ck)
        if check_tree:
            paths, complete, notes = client.tree(src, commit)
            ck.notes.extend(notes)
            if not complete:
                ck.incomplete.append(("tree", "the tree was not listed whole, so paths left out of the archive "
                                              "(`export-ignore`) cannot be ruled out"))
            norm = {_repo.canonical_member_path("x/" + p, "sdist")[0] for p in paths}
            missing = sorted(p for p in norm if p and p not in written)
            if missing:
                shown = ", ".join(missing[:5]) + (f" and {len(missing) - 5} more" if len(missing) > 5 else "")
                ck.incomplete.append(("export-ignore", f"{len(missing)} path(s) are in the commit but not in "
                                                       f"its archive (`export-ignore` in .gitattributes): {shown}"))
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
