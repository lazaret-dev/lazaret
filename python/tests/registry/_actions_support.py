"""A small in-memory GitHub for the tests of lazaret.registry.actions: repositories
with a commit graph, branches, tags (lightweight and annotated), commits that exist
only in a fork, and files; and the endpoints the auditor asks about, answered from
it, as the `http` seam of `sources.Client` (url, headers, max_bytes, hosts,
auth_host, **kw) -> bytes. Nothing is fetched."""

import hashlib
import json
import re
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

    def tag(self, name, sha, annotated=False):
        if annotated:
            self._n += 1
            self.tags[name] = ("tag", hashlib.sha1(f"tagobj/{self.full_name}/{self._n}".encode()).hexdigest(), sha)
        else:
            self.tags[name] = sha

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


class FakeGitHub:
    """The network seam. `calls` is every URL asked for; `limit` makes call
    number limit + 1 answer with the rate limit."""

    def __init__(self, *repos, limit=None):
        self.repos = {r.full_name.lower(): r for r in repos}
        self.calls, self.headers, self.limit = [], [], limit
        self.broken = {}                    # a part of a path -> the HTTP status every call to it answers with

    def __call__(self, url, headers, max_bytes, hosts, auth_host, **kw):
        what = kw.get("what", url)
        self.calls.append(url)
        self.headers.append((url, dict(headers)))
        if self.limit is not None and len(self.calls) > self.limit:
            exc = SourceError(f"{what}: rate limit reached, wait until 12:00 UTC")
            exc.status = 403
            raise exc
        p = urllib.parse.urlsplit(url)
        assert p.scheme == "https" and p.netloc == "api.github.com", url
        path = urllib.parse.unquote(p.path)
        for part, status in self.broken.items():
            if part in path:
                raise fail(status, what)
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

    def answer(self, repo, rest, query, what):
        if rest == "":
            return self.js({"full_name": repo.full_name, "default_branch": repo.default, "archived": repo.archived})
        if rest == "/tags":
            return self.js([{"name": n, "commit": {"sha": repo.tag_commit(n)}} for n in sorted(repo.tags)][:100])
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
            for t in repo.tags.values():
                if isinstance(t, tuple) and t[1] == m.group(1):
                    return self.js({"sha": t[1], "object": {"type": "commit", "sha": t[2]}})
            raise fail(404, what)
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
            data = repo.files.get((ref, m.group(1)))
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
