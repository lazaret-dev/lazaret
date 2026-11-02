"""A small in-memory GitHub for the tests of lazaret.registry.actions: repositories
with a commit graph, branches, tags (lightweight and annotated), commits that exist
only in a fork, and files; and the endpoints the auditor asks about, answered from
it, as the `http` seam of `sources.Client` (url, headers, max_bytes, hosts,
auth_host, **kw) -> bytes. Nothing is fetched.

An annotated tag's object (`Repo.tag_object`) is answered by git/tags/{sha} with
its name, and taken for the commit it tags where GitHub takes it so (John's run of
Oct 18 on vercel/next.js's pin `actions/github-script@d746ffe…`, the object of
v9.0.0): the contents API, and the archive, whose pax header names the commit. The
compare API does not take it so (none of the 9 compares of that run held it, though
the default branch holds its commit): it answers 404 there, as for a commit it does
not have, and the commits endpoint 422."""

import hashlib
import io
import json
import re
import tarfile
import urllib.parse

from lazaret.registry.sources import SourceError

API = "https://api.github.com"


def fail(status, what):
    exc = SourceError(f"{what}: HTTP {status}")
    exc.status = status
    return exc


class Repo:
    def __init__(self, full_name, default="main"):
        self.full_name, self.default = full_name, default
        self.parents = {}                   # the repository's own commits: sha -> [parent shas]
        self.fork = {}                      # commits of a fork in the network: sha -> [parent shas]
        self.branches, self.tags = {}, {}   # name -> sha; tag -> sha or ("tag", object sha, commit sha)
        self.objects = {}                   # the network's tag objects: sha -> (name, its object's type, its sha)
        self.files = {}                     # (sha, path) -> bytes
        self.archived = False
        self._n = 0

    def commit(self, *parents, branch=None, fork=False, files=None):
        self._n += 1
        sha = hashlib.sha1(f"{self.full_name}/{self._n}".encode()).hexdigest()
        (self.fork if fork else self.parents)[sha] = list(parents)
        if branch:
            self.branches[branch] = sha
        for path, data in (files or {}).items():
            self.files[(sha, path)] = data if isinstance(data, bytes) else data.encode()
        return sha

    def tag_object(self, name, target, kind="commit"):
        """An annotated tag's object (`git tag -a`; no ref names it until `tag` does) -> its sha. `target` is a
        commit, or with kind 'tag' another tag object (or another kind, which GitHub Actions cannot run)."""
        self._n += 1
        sha = hashlib.sha1(f"tagobj/{self.full_name}/{self._n}".encode()).hexdigest()
        self.objects[sha] = (name, kind, target)
        return sha

    def tag(self, name, sha, annotated=False):
        """The tag `name` at the commit `sha` (annotated: through a tag object of its own), or at the tag object
        `sha` when it is one."""
        if sha in self.objects:
            self.tags[name] = ("tag", sha, self.peel(sha))
        elif annotated:
            self.tags[name] = ("tag", self.tag_object(name, sha), sha)
        else:
            self.tags[name] = sha

    def peel(self, sha):
        """The commit a tag object tags, through tag objects; None for a sha that is not a tag object."""
        if sha not in self.objects:
            return None
        for _ in range(10):
            if sha not in self.objects:
                return sha
            sha = self.objects[sha][2]
        return None

    def tag_commit(self, name):
        t = self.tags[name]
        return t[2] if isinstance(t, tuple) else t

    def graph(self):
        return {**self.parents, **self.fork}

    def ancestors(self, sha):
        graph, seen, todo = self.graph(), set(), [sha]
        while todo:
            c = todo.pop()
            if c in seen or c not in graph:
                continue
            seen.add(c)
            todo.extend(graph[c])
        return seen

    def has(self, sha):
        return sha in self.graph()

    def status(self, base, head):
        """GitHub's compare status of `head` against `base`."""
        a_base, a_head = self.ancestors(base), self.ancestors(head)
        if base == head:
            return "identical"
        if base in a_head:
            return "ahead"
        if head in a_base:
            return "behind"
        return "diverged" if a_base & a_head else None


def archive(full_name, sha, files):
    """A commit's archive as GitHub serves it (`git archive`): one top directory, the commit in a pax global
    header. `files`: {path: bytes or str}."""
    buf = io.BytesIO()
    top = f"{full_name.replace('/', '-')}-{sha[:7]}"
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, pax_headers={"comment": sha}) as tf:
        d = tarfile.TarInfo(top)
        d.type, d.mode = tarfile.DIRTYPE, 0o775
        tf.addfile(d)
        for path, data in sorted(files.items()):
            data = data if isinstance(data, bytes) else data.encode()
            ti = tarfile.TarInfo(f"{top}/{path}")
            ti.size, ti.mode, ti.mtime = len(data), 0o664, 0
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


class FakeGitHub:
    """The network seam. `calls` is every URL asked for; `limit` makes API
    call number limit + 1 answer with the rate limit. A commit's archive is served
    from codeload.github.com (and through the API, with a token) from the
    files the commit holds."""

    def __init__(self, *repos, limit=None):
        self.repos = {r.full_name.lower(): r for r in repos}
        self.calls, self.headers, self.limit = [], [], limit
        self.broken = {}                    # a part of a path -> the HTTP status every call to it answers with

    def __call__(self, url, headers, max_bytes, hosts, auth_host, **kw):
        what = kw.get("what", url)
        self.calls.append(url)
        self.headers.append((url, dict(headers)))
        if self.limit is not None and url.startswith(API) and sum(c.startswith(API) for c in self.calls) > self.limit:
            exc = SourceError(f"{what}: rate limit reached, wait until 12:00 UTC")
            exc.status = 403
            raise exc
        p = urllib.parse.urlsplit(url)
        assert p.scheme == "https" and p.netloc in ("api.github.com", "codeload.github.com"), url
        path = urllib.parse.unquote(p.path)
        for part, status in self.broken.items():
            if part in path:
                raise fail(status, what)
        if p.netloc == "codeload.github.com":
            m = re.match(r"^/([^/]+)/([^/]+)/tar\.gz/([0-9a-f]{40})$", path)
            repo = self.repos.get(f"{m.group(1)}/{m.group(2)}".lower()) if m else None
            if repo is None:
                raise fail(404, what)
            return self.archive_of(repo, m.group(3), what)
        m = re.match(r"^/repos/([^/]+)/([^/]+)(/.*)?$", path)
        if not m:
            raise fail(404, what)
        repo = self.repos.get(f"{m.group(1)}/{m.group(2)}".lower())
        rest = m.group(3) or ""
        if repo is None:
            raise fail(404, what)
        return self.answer(repo, rest, urllib.parse.parse_qs(p.query), what)

    @staticmethod
    def js(doc):
        return json.dumps(doc).encode()

    def archive_of(self, repo, sha, what):
        sha = repo.peel(sha) or sha             # a tag object's archive is its commit's, and says so
        if not repo.has(sha):
            raise fail(404, what)
        return archive(repo.full_name, sha, {path: data for (s, path), data in repo.files.items() if s == sha})

    def answer(self, repo, rest, query, what):
        m = re.match(r"^/tarball/([0-9a-f]{40})$", rest)
        if m:
            return self.archive_of(repo, m.group(1), what)
        if rest == "":
            return self.js({"full_name": repo.full_name, "default_branch": repo.default, "archived": repo.archived})
        if rest == "/tags":
            # the tags by name, a page at a time (GitHub's default 30 a page, 100 at most); an annotated tag at the
            # commit it tags, as GitHub lists it
            per = min(int(query.get("per_page", ["30"])[0]), 100)
            page = int(query.get("page", ["1"])[0])
            names = sorted(repo.tags)[(page - 1) * per:page * per]
            return self.js([{"name": n, "commit": {"sha": repo.tag_commit(n)}} for n in names])
        if rest == "/branches":
            return self.js([{"name": n, "commit": {"sha": s}} for n, s in sorted(repo.branches.items())][:100])
        m = re.match(r"^/git/ref/(tags|heads)/(.+)$", rest)
        if m:
            name = m.group(2)
            if m.group(1) == "tags" and name in repo.tags:
                t = repo.tags[name]
                obj = {"type": "tag", "sha": t[1]} if isinstance(t, tuple) else {"type": "commit", "sha": t}
                return self.js({"ref": f"refs/tags/{name}", "object": obj})
            if m.group(1) == "heads" and name in repo.branches:
                return self.js({"ref": f"refs/heads/{name}", "object": {"type": "commit", "sha": repo.branches[name]}})
            raise fail(404, what)
        m = re.match(r"^/git/tags/([0-9a-f]{40})$", rest)
        if m:
            if m.group(1) not in repo.objects:
                raise fail(404, what)                        # a commit, or nothing: not a tag object
            name, kind, target = repo.objects[m.group(1)]
            return self.js({"sha": m.group(1), "tag": name, "object": {"type": kind, "sha": target}})
        m = re.match(r"^/commits/([0-9a-f]{40})$", rest)
        if m:
            if not repo.has(m.group(1)):
                raise fail(422, what)
            return self.js({"sha": m.group(1), "parents": [{"sha": x} for x in repo.graph()[m.group(1)]]})
        m = re.match(r"^/compare/(.+)\.\.\.([0-9a-f]{40})$", rest)
        if m:
            base, head = m.group(1), m.group(2)
            if base not in repo.branches or not repo.has(head):
                raise fail(404, what)
            status = repo.status(repo.branches[base], head)
            if status is None:
                raise fail(404, what)                        # "No common ancestor"
            return self.js({"status": status, "ahead_by": 0, "behind_by": 0, "files": [], "commits": []})
        m = re.match(r"^/contents/(.+)$", rest)
        if m:
            ref = query.get("ref", [""])[0]
            data = repo.files.get((repo.peel(ref) or ref, m.group(1)))
            if data is None:
                raise fail(404, what)
            return data
        raise fail(404, what)


def action_yml(using="node20", **runs):
    """An action.yml: `runs:` with `using` and the given keys (a list is a list of step `uses:`)."""
    lines = ["name: an action", "runs:", f"  using: '{using}'"]
    for key, value in runs.items():
        key = key.replace("_", "-")
        if key == "steps":
            lines.append("  steps:")
            for u in value:
                lines.append(f"    - uses: {u}")
        else:
            lines.append(f"  {key}: {value}")
    return "\n".join(lines) + "\n"
