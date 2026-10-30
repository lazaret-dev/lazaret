"""GitHub and GitLab as sources (0.1.9): `lazaret.registry.sources`.

A repository at a commit: the spec's grammar, the hosts and credentials the
fetch may use, the commit the archive says it holds, what the archive leaves
out (`export-ignore`), and what is written where. Archives are built in
memory from inert text and the network seam is a fake: nothing is fetched.
"""

import builtins
import contextlib
import email.message
import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

from lazaret.registry import repo, sources
from lazaret.registry.sources import SourceError
from tests._folding_disk import apfs_fold, folding_disk, tells_names_apart

SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
TOKEN = "ghp_NotARealTokenJustTestText1234567890"

#: what the archive's reader says of a path that is one name with another where case and form are ignored (EG-4), and
#: what a checkout adds when the disk it writes on is such a disk (MAC-TESTS)
READER = ("it differs from {!r} only by case or normalization: macOS and Windows write the later entry over the "
          "earlier, under the earlier's name")
KEPT = "; this checkout kept it apart and read it at its own path"
#: the gap a checkout with twin trees has: such paths are never in one tree with their twins (sources.checkout)
APART = ("{} path(s) were kept apart from the commit's other files on this disk, each one name there with another path "
         "(names that differ only in case or Unicode form), so rules across files may not have seen them together: {}")


def make_archive(sha, files, prefix="o-r-0123456", links=None, comment=True, extra_names=()):
    """A `git archive`-shaped .tar.gz: a pax global header whose comment is the
    commit, a top directory, files, symbolic links."""
    buf = io.BytesIO()
    kw = {"pax_headers": {"comment": sha}} if comment else {}
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT, **kw) as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(f"{prefix}/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for name, target in (links or {}).items():
            ti = tarfile.TarInfo(f"{prefix}/{name}")
            ti.type, ti.linkname = tarfile.SYMTYPE, target
            tf.addfile(ti)
        for name in extra_names:
            ti = tarfile.TarInfo(name)
            ti.size = 1
            tf.addfile(ti, io.BytesIO(b"x"))
    return buf.getvalue()


class Net:
    """The network seam: fixed answers by URL; every request is kept."""

    def __init__(self, answers):
        self.answers, self.seen = dict(answers), []

    def __call__(self, url, headers, max_bytes, hosts, auth_host, **kw):
        self.seen.append((url, dict(headers)))
        ans = self.answers.get(url)
        if ans is None:
            raise SourceError(f"no answer for {url}")
        if isinstance(ans, Exception):
            raise ans
        return ans if isinstance(ans, bytes) else json.dumps(ans).encode()

    def urls(self):
        return [u for u, _ in self.seen]


def gh_answers(sha=SHA, files=None, tree=None, truncated=False, comment=True, **archive_kw):
    files = {"README.md": b"# hi\n", "src/main.py": b"print(1)\n"} if files is None else files
    tree = list(files) if tree is None else tree
    base = "https://api.github.com/repos/o/r"
    return {
        f"{base}/commits/HEAD": sha.encode(),
        f"{base}/commits/v1": sha.encode(),
        "https://codeload.github.com/o/r/tar.gz/" + sha: make_archive(sha, files, comment=comment, **archive_kw),
        f"{base}/tarball/{sha}": make_archive(sha, files, comment=comment, **archive_kw),
        f"{base}/git/trees/{sha}?recursive=1": {
            "sha": sha, "truncated": truncated,
            "tree": [{"path": p, "type": "blob", "mode": "100644"} for p in tree]},
    }


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class ParseSource(unittest.TestCase):
    def test_what_is_accepted(self):
        p = sources.parse_source
        self.assertEqual(p("github:owner/repo"), ("github", "owner/repo", None))
        self.assertEqual(p("GitHub:a-b/c.d_e@v1.2.3"), ("github", "a-b/c.d_e", "v1.2.3"))
        self.assertEqual(p("github:o/r@feature/x"), ("github", "o/r", "feature/x"))
        self.assertEqual(p("gitlab:group/project"), ("gitlab", "group/project", None))
        self.assertEqual(p("gitlab:g/sub/sub2/project@main"), ("gitlab", "g/sub/sub2/project", "main"))
        self.assertEqual(p(f"github:o/r@{SHA}").ref, SHA)

    def test_what_is_refused(self):
        for bad in ["", "o/r", "npm:left-pad", "bitbucket:o/r", "github:o", "github:o/r/extra", "github:/r",
                    "github:o/", "github:../r", "github:o/..", "github:o/r.git", "github:-o/r", "github:o_o/r",
                    "github:o/r@", "github:o/r@-rf", "github:o/r@a..b", "github:o/r@a b", "github:o/r@a:b",
                    "github:o/r@a\\b", "github:o/r@x?y", "github:o/r@a@{1}", "github:o/r@.hidden",
                    "github:o/r@x.lock", "github:o/r@a//b", "github:o/r@a/", "github:o/r@a\nb",
                    "gitlab:g", "gitlab:g/../p", "gitlab:g//p", "gitlab:g/p.git", "gitlab:g/p@..",
                    "gitlab:" + "/".join("a" * 3 for _ in range(30)), "github:o/r%2f..", None, 7]:
            with self.assertRaises(SourceError, msg=repr(bad)):
                sources.parse_source(bad)

    def test_gitlab_instance_comes_from_the_environment_only(self):
        self.assertEqual(sources.gitlab_base({}), "https://gitlab.com")
        self.assertEqual(sources.gitlab_base({"LAZARET_GITLAB_URL": "https://git.example.org:8443/gl/"}),
                         "https://git.example.org:8443/gl")
        for bad in ["http://git.example.org", "https://u:p@git.example.org", "https://git.example.org?x=1",
                    "https://git.example.org#f", "ftp://x", "git.example.org", "https://", "https://a b",
                    "https://git.example.org/../x", "https://git.example.org//x", "https://exa_mple.org"]:
            with self.assertRaises(SourceError, msg=bad):
                sources.gitlab_base({"LAZARET_GITLAB_URL": bad})

    def test_a_token_that_could_split_a_header_is_refused_and_not_printed(self):
        self.assertIsNone(sources._token("github", {}))
        self.assertEqual(sources._token("github", {"GITHUB_TOKEN": f" {TOKEN} "}), TOKEN)
        for bad in ["short", "a b c d e f g h", TOKEN + "\r\nX-Evil: 1", "tok\x00en123456", "x" * 600]:
            with self.assertRaises(SourceError) as cm:
                sources._token("gitlab", {"GITLAB_TOKEN": bad})
            self.assertNotIn(bad.strip()[:12], str(cm.exception).replace("GITLAB_TOKEN", ""))


class Hosts(unittest.TestCase):
    def test_only_the_allowed_hosts_over_https(self):
        net = Net({})
        c = sources.Client("github", http=net)
        for url in ["https://evil.example/x", "http://api.github.com/x", "https://api.github.com.evil.example/x",
                    "https://user@api.github.com@evil.example/x", "https://gitlab.com/x", "file:///etc/passwd"]:
            with self.assertRaises(SourceError, msg=url):
                c.get(url, "t")
        self.assertEqual(net.seen, [])                      # none reached the network
        g = sources.Client("gitlab", base="https://git.example.org:8443/gl", http=net)
        with self.assertRaises(SourceError):
            g.get("https://git.example.org/gl/api/v4/x", "t")      # another port is another host
        with self.assertRaises(SourceError):
            g.get("https://api.github.com/x", "t")

    def test_the_token_goes_only_to_the_api_host(self):
        net = Net({"https://api.github.com/a": b"x", "https://codeload.github.com/b": b"x",
                   "https://gl.example.org/api/v4/c": b"x"})
        c = sources.Client("github", token=TOKEN, http=net)
        c.get("https://api.github.com/a", "t")
        c.get("https://codeload.github.com/b", "t")
        self.assertEqual(net.seen[0][1]["Authorization"], f"Bearer {TOKEN}")
        self.assertNotIn("Authorization", net.seen[1][1])
        g = sources.Client("gitlab", base="https://gl.example.org", token=TOKEN, http=net)
        g.get("https://gl.example.org/api/v4/c", "t")
        self.assertEqual(net.seen[2][1]["PRIVATE-TOKEN"], TOKEN)
        self.assertNotIn(TOKEN, " ".join(c.calls + g.calls))

    def _redirect(self, hosts, auth_host, url, new, token=True, auth_path="/"):
        hop = sources._Hop(hosts, auth_host, auth_path)
        req = urllib.request.Request(url, headers={"Authorization": "Bearer t", "PRIVATE-TOKEN": "t", "Accept": "x"})
        return hop.redirect_request(req, io.BytesIO(), 302, "Found", email.message.Message(), new)

    def test_a_redirect_stays_on_the_hosts_and_leaves_the_token_behind(self):
        hosts = {"api.github.com", "codeload.github.com"}
        for bad in ["https://evil.example/x", "http://codeload.github.com/x", "ftp://codeload.github.com/x",
                    "https://codeload.github.com@evil.example/x", "https://u:p@codeload.github.com/x",
                    "file:///etc/passwd"]:
            with self.assertRaises(urllib.error.URLError, msg=bad):
                self._redirect(hosts, "api.github.com", "https://api.github.com/a", bad)
        moved = self._redirect(hosts, "api.github.com", "https://api.github.com/a",
                               "https://codeload.github.com/o/r/legacy.tar.gz/x?token=abc")
        self.assertEqual(sorted(k.lower() for k in moved.headers), ["accept"])
        same = self._redirect(hosts, "api.github.com", "https://api.github.com/a", "https://api.github.com/b")
        self.assertIn("authorization", [k.lower() for k in same.headers])

    def test_a_gitlab_tokens_path_is_its_prefix(self):
        # (the credentials review of decision 14: with LAZARET_GITLAB_URL=https://host/gitlab, a redirect to another
        # app on that host got the token)
        net = Net({})
        g = sources.Client("gitlab", base="https://gl.example.org/gitlab", token=TOKEN, http=net)
        self.assertEqual((g.auth_host, g.auth_path), ("gl.example.org", "/gitlab/"))
        with self.assertRaises(SourceError):
            g.get("https://gl.example.org/gitlab/api/v4/x", "t")
        self.assertEqual(net.seen[0][1]["PRIVATE-TOKEN"], TOKEN)
        with self.assertRaises(SourceError):
            g.get("https://gl.example.org/other/x", "t")
        self.assertNotIn("PRIVATE-TOKEN", net.seen[1][1])
        hosts = {"gl.example.org"}
        for new, kept in [("https://gl.example.org/gitlab/api/v4/y", True), ("https://gl.example.org/other/y", False),
                          ("https://gl.example.org/gitlab/../other/y", False), ("https://gl.example.org/gitlab2/y", False),
                          ("https://gl.example.org/gitlab/%2e%2e/other/y", False),
                          ("https://gl.example.org/x/../gitlab/y", True)]:          # (urllib has joined a Location by now)
            with self.subTest(new):
                moved = self._redirect(hosts, "gl.example.org", "https://gl.example.org/gitlab/api/v4/x", new,
                                       auth_path="/gitlab/")
                self.assertEqual("private-token" in [k.lower() for k in moved.headers], kept)
        self.assertEqual(sources.Client("gitlab", base="https://gl.example.org", token=TOKEN, http=net).auth_path, "/")

    def test_hops_are_capped(self):
        self.assertEqual(sources._Hop.max_redirections, repo.MAX_REDIRECTS)

    def test_on_the_native_transport_the_token_is_a_credential_of_the_api_host(self):
        # (decision 14: pratique's hop hook gives it to the API host's hops alone; never a header of the request)
        asked = []

        def request(url, **kw):
            asked.append(kw)
            return sources._net.Reply(200, "HTTP/2", [], url, b"{}")

        with mock.patch.object(sources._net, "chosen", lambda url: True), \
                mock.patch.object(sources._net, "request", request):
            sources._http("https://gl.example.org:8443/api/v4/x", {"User-Agent": "u", "PRIVATE-TOKEN": "glpat-x"},
                          100, {"gl.example.org:8443"}, "gl.example.org:8443", kind="gitlab")
            sources._http("https://api.github.com/a", {"Authorization": "Bearer t", "Accept": "x"}, 100,
                          {"api.github.com", "codeload.github.com"}, "api.github.com")
            sources._http("https://codeload.github.com/b", {"Accept": "x"}, 100, {"codeload.github.com"}, "api.github.com")
            sources._http("https://gl.example.org/gitlab/api/v4/x", {"PRIVATE-TOKEN": "glpat-x"}, 100, {"gl.example.org"},
                          "gl.example.org", kind="gitlab", auth_path="/gitlab/")
        self.assertEqual(asked[3]["credentials"], [sources._net.Credential("gl.example.org", "/gitlab/", "PRIVATE-TOKEN",
                                                                           "glpat-x")])
        self.assertEqual(asked[0]["headers"], [("User-Agent", "u")])
        self.assertEqual(asked[0]["credentials"], [sources._net.Credential("gl.example.org:8443", "/", "PRIVATE-TOKEN",
                                                                           "glpat-x")])
        self.assertEqual(asked[1]["headers"], [("Accept", "x")])
        self.assertEqual(asked[1]["credentials"], [sources._net.Credential("api.github.com", "/", "Authorization",
                                                                           "Bearer t")])
        self.assertEqual(asked[2]["credentials"], [])


class Errors(unittest.TestCase):
    def test_messages_name_the_problem_not_the_token(self):
        e = sources._explain
        self.assertIn("not found", e(404, {}, "https://api.github.com/x", "w", False, "github"))
        self.assertIn("GITHUB_TOKEN", e(404, {}, "https://api.github.com/x", "w", False, "github"))
        self.assertNotIn("GITHUB_TOKEN", e(404, {}, "https://api.github.com/x", "w", True, "github"))
        self.assertIn("GITLAB_TOKEN", e(404, {}, "https://gitlab.com/x", "w", False, "gitlab"))
        self.assertIn("refused", e(401, {}, "u", "w", True, "github"))
        limited = e(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791000000"}, "u", "w", False, "github")
        self.assertIn("rate limit", limited)
        self.assertIn("GITHUB_TOKEN", limited)
        self.assertIn("UTC", limited)
        self.assertIn("rate limit", e(429, {"retry-after": "30"}, "u", "w", True, "gitlab"))
        self.assertIn("30 seconds", e(429, {"retry-after": "30"}, "u", "w", True, "gitlab"))
        self.assertIn("HTTP 403", e(403, {}, "https://api.github.com/x?token=SECRET", "w", False, "github"))
        self.assertNotIn("SECRET", e(500, {}, "https://codeload.github.com/x?token=SECRET", "w", False, "github"))


class Resolve(unittest.TestCase):
    def test_github_ref_to_commit(self):
        net = Net(gh_answers())
        c = sources.Client("github", http=net)
        self.assertEqual(c.resolve(sources.parse_source("github:o/r@v1")), SHA)
        self.assertEqual(c.resolve(sources.parse_source("github:o/r")), SHA)         # the default branch: HEAD
        self.assertEqual(net.urls(), ["https://api.github.com/repos/o/r/commits/v1",
                                      "https://api.github.com/repos/o/r/commits/HEAD"])
        self.assertEqual(net.seen[0][1]["Accept"], "application/vnd.github.sha")
        self.assertEqual(net.seen[0][1]["User-Agent"], repo.USER_AGENT)

    def test_a_pinned_commit_asks_nothing(self):
        net = Net({})
        self.assertEqual(sources.Client("github", http=net).resolve(sources.parse_source(f"github:o/r@{SHA}")), SHA)
        self.assertEqual(net.seen, [])

    def test_an_answer_that_is_not_a_sha_is_refused(self):
        for answer in [b"main", b"<html>", b"0123", SHA.upper().encode(), (SHA + "0").encode(), b""]:
            net = Net({"https://api.github.com/repos/o/r/commits/HEAD": answer})
            with self.assertRaises(SourceError, msg=answer):
                sources.Client("github", http=net).resolve(sources.parse_source("github:o/r"))

    def test_gitlab_default_branch_then_commit(self):
        base = "https://gitlab.com/api/v4/projects/grp%2Fsub%2Fproj"
        net = Net({base: {"default_branch": "trunk"}, f"{base}/repository/commits/trunk": {"id": SHA},
                   f"{base}/repository/commits/feature%2Fx": {"id": SHA2}})
        c = sources.Client("gitlab", http=net)
        self.assertEqual(c.resolve(sources.parse_source("gitlab:grp/sub/proj")), SHA)
        self.assertEqual(c.resolve(sources.parse_source("gitlab:grp/sub/proj@feature/x")), SHA2)
        self.assertEqual(len(net.seen), 3)

    def test_gitlab_answers_that_are_not_commits(self):
        base = "https://gitlab.com/api/v4/projects/g%2Fp"
        for answers in [{base: {"default_branch": None}}, {base: {"default_branch": "../x"}},
                        {base: {"default_branch": "m"}, f"{base}/repository/commits/m": {"id": "xyz"}},
                        {base: {"default_branch": "m"}, f"{base}/repository/commits/m": [SHA]},
                        {base: [1, 2]}]:
            with self.assertRaises(SourceError, msg=answers):
                sources.Client("gitlab", http=Net(answers)).resolve(sources.parse_source("gitlab:g/p"))

    def test_json_nested_too_deeply_is_a_refusal_not_a_crash(self):
        base = "https://gitlab.com/api/v4/projects/g%2Fp"
        with self.assertRaises(SourceError):
            sources.Client("gitlab", http=Net({base: b"[" * 100_000})).resolve(sources.parse_source("gitlab:g/p"))


class ArchiveCommit(unittest.TestCase):
    def test_the_commit_in_the_global_header(self):
        self.assertEqual(sources.archive_commit(make_archive(SHA, {"a": b"x"})), SHA)
        sha256 = "ab" * 32
        self.assertEqual(sources.archive_commit(make_archive(sha256, {"a": b"x"})), sha256)

    def test_none_when_there_is_none(self):
        self.assertIsNone(sources.archive_commit(make_archive(SHA, {"a": b"x"}, comment=False)))
        self.assertIsNone(sources.archive_commit(b"not gzip"))
        self.assertIsNone(sources.archive_commit(b""))
        self.assertIsNone(sources.archive_commit(make_archive(SHA, {"a": b"x"})[:12]))


class CheckoutGitHub(Tmp):
    def run_checkout(self, answers=None, spec="github:o/r@v1", env=None, **kw):
        net = Net(gh_answers() if answers is None else answers)
        ck = sources.checkout(spec, dest=os.path.join(self.tmp, "out"), env=env or {}, http=net, **kw)
        return ck, net

    def test_a_repository_at_a_commit(self):
        files = {"README.md": b"# hi\n", "src/main.py": b"print(1)\n", ".github/workflows/ci.yml": b"on: push\n",
                 "docs/guide.md": b"g\n"}
        ck, net = self.run_checkout(gh_answers(files=files, links={"docs/link.md": "guide.md"}))
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertEqual(ck.commit, SHA)
        self.assertEqual(ck.spec, f"github:o/r@{SHA}")
        got = sorted(os.path.relpath(os.path.join(d, f), ck.root).replace(os.sep, "/")
                     for d, _, fs in os.walk(ck.root) for f in fs)
        # the archive's top directory is gone; the link is its target's content, not a link
        self.assertEqual(got, sorted(list(files) + ["docs/link.md"]))
        self.assertFalse(os.path.islink(os.path.join(ck.root, "docs", "link.md")))
        with open(os.path.join(ck.root, "docs", "link.md"), "rb") as f:
            self.assertEqual(f.read(), b"g\n")
        self.assertEqual(ck.files, 5)
        # what was asked of the network: the commit, its archive on codeload, its tree
        self.assertEqual(net.urls(), ["https://api.github.com/repos/o/r/commits/v1",
                                      f"https://codeload.github.com/o/r/tar.gz/{SHA}",
                                      f"https://api.github.com/repos/o/r/git/trees/{SHA}?recursive=1"])
        self.assertEqual(ck.calls, [u.split("?")[0] for u in net.urls()])      # (a report shows no query)

    def test_a_token_uses_the_api_archive_and_is_in_no_output(self):
        ck, net = self.run_checkout(env={"GITHUB_TOKEN": TOKEN})
        self.assertIn(f"https://api.github.com/repos/o/r/tarball/{SHA}", net.urls())
        self.assertNotIn("codeload", " ".join(net.urls()))
        self.assertNotIn(TOKEN, json.dumps(ck.summary()) + repr(ck) + " ".join(ck.calls))
        for url, headers in net.seen:
            self.assertEqual(headers.get("Authorization"), f"Bearer {TOKEN}")

    def test_an_archive_for_another_commit_is_refused_and_nothing_is_left(self):
        answers = gh_answers()
        answers["https://codeload.github.com/o/r/tar.gz/" + SHA] = make_archive(SHA2, {"a": b"x"})
        made = []
        real = tempfile.mkdtemp

        def mk(*a, **k):
            made.append(real(*a, **k))
            return made[-1]
        with mock.patch("lazaret.registry.sources.tempfile.mkdtemp", mk):
            with self.assertRaises(SourceError) as cm:
                sources.checkout("github:o/r@v1", env={}, http=Net(answers))
        self.assertIn(SHA2, str(cm.exception))
        self.assertEqual(made, [])                          # refused before anything was written

    def test_a_failure_while_reading_removes_the_directory(self):
        made = []
        real = tempfile.mkdtemp

        def mk(*a, **k):
            made.append(real(*a, **k))
            return made[-1]
        answers = gh_answers()
        del answers[f"https://api.github.com/repos/o/r/git/trees/{SHA}?recursive=1"]       # the tree call fails
        with mock.patch("lazaret.registry.sources.tempfile.mkdtemp", mk):
            with self.assertRaises(SourceError):
                sources.checkout("github:o/r@v1", env={}, http=Net(answers))
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))

    def test_the_context_manager_cleans_up(self):
        with sources.scanned_checkout("github:o/r@v1", env={}, http=Net(gh_answers())) as ck:
            root = ck.root
            self.assertTrue(os.path.isdir(root))
        self.assertFalse(os.path.exists(root))

    def test_an_archive_that_names_no_commit_is_read_with_a_note(self):
        ck, _ = self.run_checkout(gh_answers(comment=False))
        self.assertTrue(ck.complete)
        self.assertTrue(any("names no commit" in n for n in ck.notes))

    def test_export_ignore_is_incomplete_and_says_which(self):
        files = {"README.md": b"a\n", "src/main.py": b"b\n"}
        tree = list(files) + ["payload/evil.js", "payload/more.js", ".gitattributes"]
        ck, _ = self.run_checkout(gh_answers(files=files, tree=tree))
        self.assertFalse(ck.complete)
        reason, detail = ck.incomplete[0]
        self.assertEqual(reason, "export-ignore")
        for name in ("payload/evil.js", "payload/more.js", ".gitattributes"):
            self.assertIn(name, detail)
        self.assertIn("3 path(s)", detail)

    def test_many_missing_paths_are_counted_not_listed(self):
        tree = ["README.md"] + [f"x/{i}.js" for i in range(12)]
        ck, _ = self.run_checkout(gh_answers(files={"README.md": b"a"}, tree=tree))
        self.assertIn("12 path(s)", ck.incomplete[0][1])
        self.assertIn("and 7 more", ck.incomplete[0][1])

    def test_a_tree_listed_in_part_is_incomplete(self):
        ck, _ = self.run_checkout(gh_answers(truncated=True))
        self.assertEqual([r for r, _ in ck.incomplete], ["tree"])
        self.assertTrue(any("only part" in n for n in ck.notes))

    def test_links_and_submodules_do_not_count_as_missing(self):
        files = {"a.txt": b"a"}
        answers = gh_answers(files=files, links={"l.txt": "a.txt"})
        tree = answers[f"https://api.github.com/repos/o/r/git/trees/{SHA}?recursive=1"]
        tree["tree"] += [{"path": "l.txt", "type": "blob", "mode": "120000"},
                         {"path": "vendor/sub", "type": "commit", "mode": "160000"},
                         {"path": "dir", "type": "tree", "mode": "040000"}]
        ck, _ = self.run_checkout(answers)
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertTrue(any("1 submodule" in n for n in ck.notes))

    def test_the_tree_check_can_be_left_out(self):
        answers = gh_answers()
        del answers[f"https://api.github.com/repos/o/r/git/trees/{SHA}?recursive=1"]
        ck, net = self.run_checkout(answers, check_tree=False)
        self.assertTrue(ck.complete)
        self.assertEqual(len(net.seen), 2)

    def test_a_member_that_would_leave_the_checkout_is_not_written(self):
        files = {"ok.txt": b"ok"}
        answers = gh_answers(files=files, tree=["ok.txt"], extra_names=["o-r-0123456/../../escape.txt",
                                                                       "/etc/cron.d/x", "o-r-0123456/a/../../b"])
        ck, _ = self.run_checkout(answers)
        # nothing outside the checkout; an absolute path is taken as the extractor takes it
        # (its first component stripped, the rest inside), the `..` ones are refused
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape.txt")))
        under = sorted(os.path.relpath(os.path.join(d, f), ck.root).replace(os.sep, "/")
                       for d, _, fs in os.walk(ck.root) for f in fs)
        self.assertEqual(under, ["cron.d/x", "ok.txt"])
        self.assertEqual(len([a for a in ck.anomalies if a[0] == "path"]), 2)

    def kept(self, files, fold=None, check_tree=True, **kw):
        """The checkout of an archive holding `files` (its tree names them too), on this machine's disk, or on one that
        folds names as `fold` does -> (the checkout, [{path: bytes} of its own in its root, then in each of its twin
        trees]): what a twin tree was given of the commit's other files is not its own (`ck.overlaid`). The network
        seam is `self.net`."""
        disk = tempfile.mkdtemp(dir=self.tmp)            # (the twin trees are made beside the root: they fold too)
        self.net = Net(gh_answers(files=files, **kw))
        with folding_disk(disk, fold) if fold else contextlib.nullcontext():
            ck = sources.checkout("github:o/r@v1", dest=os.path.join(disk, "out"), env={}, http=self.net,
                                  check_tree=check_tree)
        self.assertEqual(ck.twins, [f"{ck.root}.lazaret-twin-{n}" for n in range(1, len(ck.twins) + 1)])
        self.assertLessEqual(set(ck.overlaid), set(ck.twins))
        trees = []
        for top in [ck.root] + ck.twins:
            got = {}
            for d, _, names in os.walk(top):
                for name in names:
                    rel = os.path.relpath(os.path.join(d, name), top).replace(os.sep, "/")
                    if rel not in ck.overlaid.get(top, ()):
                        with open(os.path.join(d, name), "rb") as f:
                            got[rel] = f.read()
            trees.append(got)
        return ck, trees

    def on_both_disks(self, files, want=None, in_root=True, **kw):
        """`kept` on this machine's disk and on one that ignores case and Unicode form as macOS's and Windows' do. On
        each, every file of the commit is in one tree only, at its path in the commit, with its bytes (`want`: the
        files as written, when not `files`); on a disk that tells the names apart, all of them are in the root, as
        the commit has them, and it is read whole (`in_root`) -> (this disk's (the checkout, its trees), the
        other's)."""
        both = []
        for fold in (None, apfs_fold):
            ck, trees = self.kept(files, fold=fold, **kw)
            merged = {}
            for tree in trees:
                self.assertFalse(set(tree) & set(merged), trees)
                merged.update(tree)
            self.assertEqual(merged, files if want is None else want)
            both.append((ck, trees))
        if in_root and tells_names_apart(self.tmp):
            self.assertEqual((both[0][0].twins, sources.not_covered(both[0][0])), ([], []))
        return both

    def cases(self, ck):
        return [a[1:] for a in ck.anomalies if a[0] == "case"]

    def test_paths_that_differ_only_in_case_are_all_kept_at_their_paths(self):
        # (MAC-TESTS: the twins were written as setup.py.lazaret-dup1 and SETUP.PY.lazaret-dup1, which no rule reads
        # as a setup.py, and on a disk that ignores case those are one name: the third was written over the second,
        # unread, while the anomalies said both were kept)
        files = {"Setup.py": b"one", "setup.py": b"two", "SETUP.PY": b"three"}
        (here, _), (ck, trees) = self.on_both_disks(files)
        self.assertEqual(trees, [{"Setup.py": b"one"}, {"setup.py": b"two"}, {"SETUP.PY": b"three"}])
        self.assertEqual(self.cases(ck), [("setup.py", READER.format("Setup.py") + KEPT),
                                          ("SETUP.PY", READER.format("Setup.py") + KEPT)])
        if tells_names_apart(self.tmp):                # (the reader's own: what an installer on a Mac does)
            self.assertEqual(self.cases(here), [("setup.py", READER.format("Setup.py")),
                                                ("SETUP.PY", READER.format("Setup.py"))])
        # two of them are never in one tree there, so what a rule reads across files may not have seen them together
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(2, "SETUP.PY, setup.py"))])

    def test_names_that_differ_only_in_unicode_form_are_both_kept(self):
        composed, decomposed = "café.js", "café.js"
        _, (ck, trees) = self.on_both_disks({composed: b"composed", decomposed: b"decomposed"})
        self.assertEqual(trees, [{composed: b"composed"}, {decomposed: b"decomposed"}])
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(1, decomposed))])

    def test_a_file_and_a_folder_that_differ_only_in_case_are_both_kept(self):
        # (on a disk that ignores case the folder could not be made: a `.github/` beside a `.GITHUB` file was not read)
        _, (ck, trees) = self.on_both_disks({"A": b"file", "a/b.js": b"under"})
        self.assertEqual(trees, [{"A": b"file"}, {"a/b.js": b"under"}])
        self.assertEqual(self.cases(ck), [("a/b.js", "its folder a/ is one name on this disk with A: kept apart and "
                                                     "read at its own path")])
        _, (ck, trees) = self.on_both_disks({"a/b.js": b"under", "A": b"file"})
        self.assertEqual(trees, [{"a/b.js": b"under"}, {"A": b"file"}])
        self.assertEqual(self.cases(ck), [("A", "one name on this disk with a/: kept apart and read at its own path")])
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(1, "A"))])

    def test_a_file_whose_name_is_a_folders_on_a_disk_that_denies_it_is_kept_apart(self):
        # (Windows' disk answers a file `A` where a folder `a/` is with "access denied", not EEXIST: such a file was
        # not written at all; it is kept apart in a twin tree, as on a Mac)
        def denying(file, mode="r", *args, **kwargs):
            if "x" in mode and os.path.isdir(file):
                raise PermissionError(13, "Access is denied", file)
            return builtins.open(file, mode, *args, **kwargs)
        with mock.patch.object(sources, "open", denying, create=True):
            ck, trees = self.kept({"a/b.js": b"under", "A": b"file"}, fold=apfs_fold)
        self.assertEqual(trees, [{"a/b.js": b"under"}, {"A": b"file"}])
        self.assertEqual(self.cases(ck), [("A", "one name on this disk with a/: kept apart and read at its own path")])
        self.assertEqual(ck.skipped, [])

    def test_folders_that_differ_only_in_case_are_not_one_folder(self):
        # (a disk that ignores case had lib/b.js written into Lib/, and what was found in it reported at Lib/b.js: no
        # path of the commit)
        _, (ck, trees) = self.on_both_disks({"Lib/a.js": b"1", "lib/b.js": b"2", "lib/A.js": b"3"})
        self.assertEqual(trees, [{"Lib/a.js": b"1"}, {"lib/b.js": b"2", "lib/A.js": b"3"}])
        self.assertEqual(self.cases(ck), [
            ("lib/b.js", "its folder lib/ is one name on this disk with Lib/: kept apart and read at its own path"),
            ("lib/A.js", READER.format("Lib/a.js") + KEPT)])
        _, (ck, trees) = self.on_both_disks({"Lib/x/a.js": b"1", "lib/x/b.js": b"2", "lib/X/c.js": b"3"})
        self.assertEqual(trees, [{"Lib/x/a.js": b"1"}, {"lib/x/b.js": b"2"}, {"lib/X/c.js": b"3"}])
        self.assertEqual(self.cases(ck), [   # (each path kept apart, with why each tree before it refused it)
            ("lib/x/b.js", "its folder lib/ is one name on this disk with Lib/: kept apart and read at its own path"),
            ("lib/X/c.js", "its folder lib/ is one name on this disk with Lib/; in twin tree 1, its folder lib/X/ is "
                           "one name on this disk with lib/x/: kept apart and read at its own path")])
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(2, "lib/X/c.js, lib/x/b.js"))])

    def test_a_name_the_disk_takes_for_another_is_kept_apart_too(self):
        # the disk decides, not the reader's fold: a disk that takes two names for one where the fold does not refuses
        # the second's file (O_EXCL), folder (mkdir) or hard link all the same, and it is kept apart
        def fold(name):
            return apfs_fold(name).replace("_", "-")
        ck, trees = self.kept({"a-b.js": b"1", "a_b.js": b"2", "x-y/c.js": b"3", "x_y/d.js": b"4"}, fold=fold)
        self.assertEqual(trees, [{"a-b.js": b"1", "x-y/c.js": b"3"}, {"a_b.js": b"2", "x_y/d.js": b"4"}])
        self.assertEqual(ck.overlaid, {ck.twins[0]: set()})                 # (each of the root's is one with its own)
        self.assertEqual(self.cases(ck), [
            ("a_b.js", "one name on this disk with a path written before: kept apart and read at its own path"),
            ("x_y/d.js", "its folder x_y/ is one name on this disk with a path written before: kept apart and read "
                         "at its own path")])
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(2, "a_b.js, x_y/d.js"))])

    def test_each_twin_tree_is_given_the_commit_s_other_files(self):
        # (MAC-TESTS: what a rule reads across files, a hook's script or the helper a tainted call goes into, was not
        # beside a twin read alone; the scans read each tree's own files and findings once: core.scan_twins)
        files = {"App.py": b"1", "app.py": b"2", "lib/h.py": b"3", "README.md": b"4", "Lib/x.py": b"5",
                 "src/m.py": b"6"}
        ck, trees = self.kept(files, fold=apfs_fold)
        self.assertEqual(trees, [{"App.py": b"1", "lib/h.py": b"3", "README.md": b"4", "src/m.py": b"6"},
                                 {"app.py": b"2", "Lib/x.py": b"5"}])
        twin = ck.twins[0]
        # every other file it can hold (not App.py, one name with its own app.py; not lib/h.py, whose folder is one
        # with its own Lib/), each the root's file itself: a hard link
        self.assertEqual(ck.overlaid, {twin: {"README.md", "src/m.py"}})
        self.assertTrue(os.path.samefile(os.path.join(twin, "src", "m.py"), os.path.join(ck.root, "src", "m.py")))
        with mock.patch.object(os, "link", side_effect=OSError("no hard links here")):
            ck, _ = self.kept(files, fold=apfs_fold)                        # (a copy where the disk makes none)
        twin = ck.twins[0]
        self.assertEqual(ck.overlaid, {twin: {"README.md", "src/m.py"}})
        self.assertFalse(os.path.samefile(os.path.join(twin, "src", "m.py"), os.path.join(ck.root, "src", "m.py")))
        with open(os.path.join(twin, "src", "m.py"), "rb") as f:
            self.assertEqual(f.read(), b"6")
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(2, "Lib/x.py, app.py"))])
        ck.cleanup()
        self.assertEqual((ck.twins, ck.overlaid), ([], {}))

    def test_past_the_overlay_s_limit_each_twin_tree_is_read_alone(self):
        with mock.patch.object(sources, "MAX_OVERLAY_FILES", 4):            # (5 files, 1 twin tree)
            ck, trees = self.kept({"App.py": b"1", "app.py": b"2", "a.js": b"3", "b.js": b"4", "c.js": b"5"},
                                  fold=apfs_fold)
        self.assertEqual(ck.overlaid, {})
        self.assertEqual(sorted(os.listdir(ck.twins[0])), ["app.py"])
        self.assertIn("the twin trees were not given the commit's other files (5 files in 1 twin trees is more than "
                      "4): each is read alone", ck.notes)
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(1, "app.py"))])

    def test_a_path_that_cannot_be_kept_is_not_read_and_said_and_not_fetched_again(self):
        with mock.patch.object(sources, "MAX_TWIN_TREES", 1):
            ck, trees = self.kept({"a.js": b"1", "A.js": b"2", "A.JS": b"3"}, fold=apfs_fold)
        self.assertEqual(trees, [{"a.js": b"1"}, {"A.js": b"2"}])
        why = "could not be written (one name on this disk with paths in 2 trees)"
        self.assertEqual(ck.skipped, [("A.JS", why)])
        self.assertEqual(sources.not_covered(ck), [("case", APART.format(1, "A.js")), ("skipped", f"A.JS: {why}")])
        # (a path not written was fetched again by its blob, failed again, and was said to be left out of the
        # archive: export-ignore)
        self.assertEqual([reason for reason, _ in ck.incomplete], ["case"])
        self.assertEqual(len(self.net.seen), 3)                 # the commit, its archive, its tree

    def test_names_windows_does_not_keep_as_given_are_not_written(self):
        # (a device's name is the device, `a:b` writes a stream of `a`, a trailing dot or space is dropped: on Windows
        # none is the file the commit has, so none is written, and the checkout is not read whole)
        files = {"ok.js": b"1", "CON": b"2", "aux.txt": b"3", "lib/nul/x.js": b"4", "Com1.js": b"5", "a:b": b"6",
                 "dot.": b"7", "lpt¹": b"8"}
        with mock.patch.object(sources, "WINDOWS", True):
            ck, trees = self.kept(files, check_tree=False)
        self.assertEqual(trees, [{"ok.js": b"1"}])
        self.assertEqual(dict(ck.skipped), {
            "CON": "could not be written (a device's name, which Windows does not keep as given)",
            "aux.txt": "could not be written (a device's name, which Windows does not keep as given)",
            "lib/nul/x.js": "could not be written (a device's name, which Windows does not keep as given)",
            "Com1.js": "could not be written (a device's name, which Windows does not keep as given)",
            "a:b": "could not be written (a data stream's name, which Windows does not keep as given)",
            "dot.": "could not be written (a name ending in a dot or a space, which Windows does not keep as given)",
            "lpt¹": "could not be written (a device's name, which Windows does not keep as given)"})
        self.assertEqual(len(sources.not_covered(ck)), 7)
        like = {"CONTRIBUTING.md": b"1", "console.js": b"2"}
        with mock.patch.object(sources, "WINDOWS", True):
            ck, trees = self.kept(like, check_tree=False)
        self.assertEqual((trees, ck.skipped), ([like], []))                 # (names like a device's: kept on Windows)
        ck, trees = self.kept({**like, "nul.d/x": b"3"}, check_tree=False)
        if sources.WINDOWS:                                                  # (nul.d is NUL's name with an extension)
            self.assertEqual((trees, dict(ck.skipped)), ([like], {
                "nul.d/x": "could not be written (a device's name, which Windows does not keep as given)"}))
        else:
            self.assertEqual(len(trees[0]), 3)                               # (elsewhere, a device's name too: kept)

    def test_an_entry_again_is_written_over_its_own_file(self):
        # (an archive's later entry of a path wins, as an extractor writes it, in the tree it went to; the reader
        # names the pair: "dup")
        _, (ck, trees) = self.on_both_disks({"a.js": b"first", "A.js": b"second"}, extra_names=["o-r-0123456/A.js"],
                                            want={"a.js": b"first", "A.js": b"x"})
        self.assertEqual(trees, [{"a.js": b"first"}, {"A.js": b"x"}])
        self.assertIn(("dup", "A.js"), [a[:2] for a in ck.anomalies])

    def test_a_file_in_the_way_of_a_folder_is_kept_apart_on_every_disk(self):
        # (not something git makes: an archive that has a file `a` and a file `a/b.txt`)
        (here, here_trees), (ck, trees) = self.on_both_disks({"a": b"file", "a/b.txt": b"under"}, tree=["a"],
                                                                in_root=False)
        self.assertEqual(here_trees, trees)
        self.assertEqual(trees, [{"a": b"file"}, {"a/b.txt": b"under"}])
        self.assertEqual(self.cases(ck), [("a/b.txt", "its folder a/ has the name of the archive's file a: kept "
                                                      "apart and read at its own path")])
        self.assertEqual(self.cases(here), self.cases(ck))
        self.assertEqual((ck.skipped, sources.not_covered(ck)), ([], [("case", APART.format(1, "a/b.txt"))]))

    def test_twin_trees_take_a_free_name_and_go_with_the_checkout(self):
        disk = tempfile.mkdtemp(dir=self.tmp)
        os.mkdir(os.path.join(disk, "out.lazaret-twin-1"))          # (a name taken beside the root: left alone)
        files = {"a.js": b"1", "A.js": b"2"}
        with folding_disk(disk):
            ck = sources.checkout("github:o/r@v1", dest=os.path.join(disk, "out"), env={},
                                  http=Net(gh_answers(files=files)))
        self.assertEqual(ck.twins, [os.path.join(disk, "out.lazaret-twin-2")])
        if os.name == "posix":                                      # (the commit's files, for this user alone)
            self.assertEqual(stat.S_IMODE(os.stat(ck.twins[0]).st_mode), 0o700)
        ck.cleanup()
        self.assertEqual(sorted(os.listdir(disk)), ["out", "out.lazaret-twin-1"])     # (the root was the caller's)
        with mock.patch.object(tempfile, "tempdir", disk), folding_disk(disk):
            ck = sources.checkout("github:o/r@v1", env={}, http=Net(gh_answers(files=files)))
        self.assertEqual(len(ck.twins), 1)
        ck.cleanup()
        self.assertEqual(sorted(os.listdir(disk)), ["out", "out.lazaret-twin-1"])

    def test_a_file_too_large_to_read_is_skipped_and_named(self):
        with mock.patch.object(repo, "MAX_MEMBER", 100):
            ck, _ = self.run_checkout(gh_answers(files={"big.bin": b"x" * 500, "small.txt": b"s"}))
        self.assertEqual([p for p, _ in ck.skipped], ["big.bin"])
        self.assertEqual(os.listdir(ck.root), ["small.txt"])
        self.assertTrue(any(r for r, _ in ck.incomplete) or ck.skipped)

    def test_a_decompression_bomb_stops_and_is_incomplete(self):
        bomb = make_archive(SHA, {"zeros": b"\0" * 5_000_000})
        answers = gh_answers()
        answers["https://codeload.github.com/o/r/tar.gz/" + SHA] = bomb
        with mock.patch.object(repo, "MAX_ARCHIVE_TOTAL", 1_000_000):
            ck, _ = self.run_checkout(answers, check_tree=False)
        self.assertEqual([r for r, _ in ck.incomplete], ["total"])

    def test_not_an_archive_is_incomplete_not_a_crash(self):
        answers = gh_answers()
        answers["https://codeload.github.com/o/r/tar.gz/" + SHA] = b"<html>rate limited</html>"
        ck, _ = self.run_checkout(answers, check_tree=False)
        self.assertEqual(ck.files, 0)
        self.assertEqual([r for r, _ in ck.incomplete], ["corrupt"])

    def test_http_errors_reach_the_caller_as_source_errors(self):
        err = SourceError("resolving github:o/r@HEAD: not found (a private repository needs GITHUB_TOKEN)")
        err.status = 404
        with self.assertRaises(SourceError) as cm:
            sources.checkout("github:o/r", env={}, http=Net({"https://api.github.com/repos/o/r/commits/HEAD": err}))
        self.assertEqual(cm.exception.status, 404)


class CheckoutGitLab(Tmp):
    def answers(self, tree_pages=1, **kw):
        base = "https://git.example.org/api/v4/projects/grp%2Fsub%2Fproj"
        files = kw.get("files", {"app.py": b"x = 1\n", ".gitlab-ci.yml": b"script: [ls]\n"})
        tree = kw.get("tree", list(files))
        out = {base: {"default_branch": "main"}, f"{base}/repository/commits/main": {"id": SHA},
               f"{base}/repository/archive.tar.gz?sha={SHA}": make_archive(SHA, files, prefix="proj-" + SHA)}
        for page in range(1, tree_pages + 1):
            chunk = tree[(page - 1) * 100: page * 100]
            out[f"{base}/repository/tree?ref={SHA}&recursive=true&per_page=100&page={page}"] = [
                {"path": p, "type": "blob", "mode": "100644", "name": p.split("/")[-1]} for p in chunk]
        return out

    def run_checkout(self, answers, **kw):
        net = Net(answers)
        env = {"LAZARET_GITLAB_URL": "https://git.example.org", "GITLAB_TOKEN": TOKEN}
        ck = sources.checkout("gitlab:grp/sub/proj", dest=os.path.join(self.tmp, "out"), env=env, http=net, **kw)
        return ck, net

    def test_a_project_on_a_self_managed_instance(self):
        ck, net = self.run_checkout(self.answers())
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertEqual(sorted(os.listdir(ck.root)), [".gitlab-ci.yml", "app.py"])
        self.assertTrue(all(u.startswith("https://git.example.org/api/v4/") for u in net.urls()))
        for _, headers in net.seen:
            self.assertEqual(headers["PRIVATE-TOKEN"], TOKEN)
            self.assertNotIn("Authorization", headers)
        self.assertNotIn(TOKEN, json.dumps(ck.summary()))

    def test_the_tree_is_read_a_page_at_a_time(self):
        tree = [f"f{i}.py" for i in range(250)]
        files = {p: b"x" for p in tree}
        ck, net = self.run_checkout(self.answers(tree_pages=3, files=files, tree=tree))
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertEqual(sum("repository/tree" in u for u in net.urls()), 3)

    def test_a_tree_too_large_to_list_is_incomplete(self):
        tree = [f"f{i}.py" for i in range(100 * 3)]
        answers = self.answers(tree_pages=3, files={p: b"x" for p in tree}, tree=tree)
        with mock.patch.object(sources, "GITLAB_TREE_PAGES", 3):
            ck, _ = self.run_checkout(answers)
        self.assertEqual([r for r, _ in ck.incomplete], ["tree"])

    def test_export_ignore_on_gitlab(self):
        files = {"app.py": b"x"}
        ck, _ = self.run_checkout(self.answers(files=files, tree=["app.py", "hidden/payload.sh"]))
        self.assertEqual(ck.incomplete[0][0], "export-ignore")
        self.assertIn("hidden/payload.sh", ck.incomplete[0][1])

    def test_the_instance_is_never_taken_from_a_spec(self):
        for spec in ["gitlab:evil.example/grp/proj", "gitlab://evil.example/grp/proj", "gitlab:https://evil.example/a/b"]:
            net = Net({})
            try:
                sources.checkout(spec, env={}, http=net)
            except SourceError:
                pass
            # (a host-looking first segment is a group name, asked of the configured instance)
            hosts = {urllib.parse.urlsplit(u).hostname for u in net.urls()}
            self.assertLessEqual(hosts, {"gitlab.com"}, spec)


class Main(Tmp):
    def test_the_module_prints_what_it_found(self):
        out = io.StringIO()
        net = Net(gh_answers())
        with mock.patch.object(sources, "_http", net), mock.patch("sys.stdout", out):
            self.assertEqual(sources.main(["github:o/r@v1"]), 0)
        doc = json.loads(out.getvalue())
        self.assertEqual((doc["commit"], doc["files"], doc["complete"]), (SHA, 2, True))
        self.assertFalse(os.path.exists(doc["root"]))        # removed unless --keep

    def test_exit_codes(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.assertEqual(sources.main([]), 2)
            self.assertEqual(sources.main(["nope"]), 1)
        incomplete = gh_answers(files={"a": b"x"}, tree=["a", "b"])
        with mock.patch.object(sources, "_http", Net(incomplete)), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(sources.main(["github:o/r@v1"]), 3)


if __name__ == "__main__":
    unittest.main()
