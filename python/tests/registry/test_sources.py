"""GitHub and GitLab as sources (0.1.9): `lazaret.registry.sources`.

A repository at a commit: the spec's grammar, the hosts and credentials the
fetch may use, the commit the archive says it holds, what the archive leaves
out (`export-ignore`), and what is written where. Archives are built in
memory from inert text and the network seam is a fake: nothing is fetched.
"""

import email.message
import io
import json
import os
import shutil
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

from lazaret.registry import repo, sources
from lazaret.registry.sources import SourceError

SHA = "0123456789abcdef0123456789abcdef01234567"
SHA2 = "fedcba9876543210fedcba9876543210fedcba98"
TOKEN = "ghp_NotARealTokenJustTestText1234567890"


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

    def _redirect(self, hosts, auth_host, url, new, token=True):
        hop = sources._Hop(hosts, auth_host)
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

    def test_hops_are_capped(self):
        self.assertEqual(sources._Hop.max_redirections, repo.MAX_REDIRECTS)


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

    def test_paths_that_differ_only_in_case_are_both_kept(self):
        files = {"Setup.py": b"one", "setup.py": b"two", "SETUP.PY": b"three"}
        ck, _ = self.run_checkout(gh_answers(files=files))
        names = sorted(os.listdir(ck.root))
        self.assertEqual(len(names), 3)
        self.assertEqual(sum(".lazaret-dup" in n for n in names), 2)
        self.assertEqual(len([a for a in ck.anomalies if a[0] == "case"]), 2)
        self.assertTrue(ck.complete, ck.incomplete)
        contents = []
        for n in names:
            with open(os.path.join(ck.root, n), "rb") as f:
                contents.append(f.read())
        contents.sort()
        self.assertEqual(contents, [b"one", b"three", b"two"])

    def test_a_file_in_the_way_of_a_directory_is_skipped_not_fatal(self):
        files = {"a": b"file", "a/b.txt": b"under"}
        ck, _ = self.run_checkout(gh_answers(files=files, tree=["a"]))
        self.assertEqual(len(ck.skipped), 1)
        self.assertIn("could not be written", ck.skipped[0][1])

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
