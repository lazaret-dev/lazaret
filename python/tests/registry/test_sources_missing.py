"""N-5: the paths a commit's archive left out are fetched one by one.

`git archive` leaves out every path marked `export-ignore` in
`.gitattributes`, and many repositories keep their tests, their docs and
`.github/` out of their tarball that way, so S-1 found most `github:` scans
incomplete (and `--ci` failed them). `sources.checkout` now fetches each
such path on its own: a public GitHub repository's from
raw.githubusercontent.com, by the commit (outside the API's 60 requests an
hour), with a token through the API's contents call, on GitLab through the
repository files call. A file is written only when it is the blob the tree
names; what could not be fetched within the budget is still reported, and
the checkout is incomplete. The network is a fake; nothing is fetched.
`test_sourcescan.SourceBlock` has what the report then says.
"""
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import repo, sources
from lazaret.registry.sources import SourceError
from tests.registry.test_sources import SHA, TOKEN, Net, make_archive

BASE = "https://api.github.com/repos/o/r"
GL = "https://git.example.org/api/v4/projects/grp%2Fproj"
INSIDE = {"README.md": b"# hi\n", "src/main.py": b"print(1)\n"}
LEFT_OUT = {"tests/test_a.py": b"assert True\n", ".github/workflows/ci.yml": b"on: push\n",
            "docs/space name.md": b"doc\n"}


def blob(raw):
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def github(inside=INSIDE, left_out=LEFT_OUT, token=False, bad=()):
    """A repository whose archive holds `inside`, whose tree also lists
    `left_out`, and whose left-out files are served where checkout asks
    (the raw host, or the API with a token); paths in `bad` are served
    with other bytes than the tree's blob."""
    files = dict(inside, **left_out)
    out = {f"{BASE}/commits/v1": SHA.encode(),
           f"https://codeload.github.com/o/r/tar.gz/{SHA}": make_archive(SHA, inside),
           f"{BASE}/tarball/{SHA}": make_archive(SHA, inside),
           f"{BASE}/git/trees/{SHA}?recursive=1": {
               "sha": SHA, "truncated": False,
               "tree": [{"path": p, "type": "blob", "mode": "100644", "sha": blob(raw)} for p, raw in files.items()]}}
    for p, raw in left_out.items():
        url = (f"{BASE}/contents/{urllib.parse.quote(p)}?ref={SHA}" if token
               else f"https://raw.githubusercontent.com/o/r/{SHA}/{urllib.parse.quote(p)}")
        out[url] = raw + b"changed" if p in bad else raw
    return out


def gitlab(inside=INSIDE, left_out=LEFT_OUT):
    files = dict(inside, **left_out)
    out = {f"{GL}/repository/commits/main": {"id": SHA},
           f"{GL}/repository/archive.tar.gz?sha={SHA}": make_archive(SHA, inside, prefix="proj-" + SHA),
           f"{GL}/repository/tree?ref={SHA}&recursive=true&per_page=100&page=1": [
               {"path": p, "type": "blob", "mode": "100644", "id": blob(raw)} for p, raw in files.items()]}
    for p, raw in left_out.items():
        out[f"{GL}/repository/files/{urllib.parse.quote(p, safe='')}/raw?ref={SHA}"] = raw
    return out


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-test-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def checkout(self, answers, spec="github:o/r@v1", env=None):
        net = Net(answers)
        ck = sources.checkout(spec, dest=os.path.join(self.tmp, "out"), env=env or {}, http=net)
        return ck, net

    def files(self, ck):
        out = {}
        for d, _, fs in os.walk(ck.root):
            for f in fs:
                with open(os.path.join(d, f), "rb") as fh:
                    out[os.path.relpath(os.path.join(d, f), ck.root).replace(os.sep, "/")] = fh.read()
        return out


class GitHubTests(Tmp):
    def test_a_public_repositorys_left_out_paths_come_from_the_raw_host(self):
        ck, net = self.checkout(github())
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertEqual(self.files(ck), dict(INSIDE, **LEFT_OUT))
        self.assertIn("3 path(s) the archive left out (`export-ignore` in .gitattributes) were fetched one by one",
                      ck.notes)
        raw = [(u, h) for u, h in net.seen if u.startswith("https://raw.githubusercontent.com/")]
        self.assertEqual(sorted(u for u, _ in raw), sorted(
            f"https://raw.githubusercontent.com/o/r/{SHA}/{urllib.parse.quote(p)}" for p in LEFT_OUT))
        self.assertTrue(all("Authorization" not in h for _, h in raw))
        self.assertEqual(ck.files, 5)

    def test_with_a_token_through_the_api(self):
        ck, net = self.checkout(github(token=True), env={"GITHUB_TOKEN": TOKEN})
        self.assertTrue(ck.complete, ck.incomplete)
        api = [(u, h) for u, h in net.seen if "/contents/" in u]
        self.assertEqual(len(api), 3)
        for _, h in api:
            self.assertEqual((h["Accept"], h["Authorization"]), ("application/vnd.github.raw", f"Bearer {TOKEN}"))
        self.assertNotIn("raw.githubusercontent.com", " ".join(net.urls()))
        self.assertNotIn(TOKEN, json.dumps(ck.summary()))

    def test_a_file_that_is_not_the_trees_blob_is_not_written(self):
        ck, _ = self.checkout(github(bad=("tests/test_a.py",)))
        self.assertFalse(ck.complete)
        (reason, detail), = ck.incomplete
        self.assertEqual(reason, "export-ignore")
        self.assertIn("1 path(s) are in the commit but not in its archive", detail)
        self.assertIn("tests/test_a.py", detail)
        self.assertNotIn("tests/test_a.py", self.files(ck))
        self.assertIn(("blob", "tests/test_a.py", "fetched on its own, it is not the blob the commit's tree names"),
                      ck.anomalies)

    def test_a_rate_limit_stops_the_asking(self):
        answers = github()
        err = SourceError("fetching x: rate limit reached, wait until 12:00 UTC")
        err.status = 403
        for p in LEFT_OUT:
            answers[f"https://raw.githubusercontent.com/o/r/{SHA}/{urllib.parse.quote(p)}"] = err
        ck, net = self.checkout(answers)
        self.assertEqual(sum(u.startswith("https://raw.githubusercontent.com/") for u in net.urls()), 1)
        (reason, detail), = ck.incomplete
        self.assertIn("3 path(s)", detail)
        self.assertIn("rate limit reached", detail)

    def test_at_most_so_many_are_fetched(self):
        left_out = {f"t/{i}.py": b"x = %d\n" % i for i in range(5)}
        with mock.patch.object(sources, "MAX_MISSING_FILES", 2):
            ck, net = self.checkout(github(left_out=left_out))
        self.assertEqual(sum(u.startswith("https://raw.githubusercontent.com/") for u in net.urls()), 2)
        (reason, detail), = ck.incomplete
        self.assertIn("3 path(s)", detail)
        self.assertIn("at most 2 are fetched one by one", detail)
        self.assertIn("2 path(s) the archive left out (`export-ignore` in .gitattributes) were fetched one by one",
                      ck.notes)

    def test_so_is_the_time_budget(self):
        with mock.patch.object(sources, "MISSING_FILES_SECONDS", 0):
            ck, net = self.checkout(github())
        self.assertFalse(any(u.startswith("https://raw.githubusercontent.com/") for u in net.urls()))
        (reason, detail), = ck.incomplete
        self.assertIn("3 path(s)", detail)
        self.assertIn("the time budget (0 s) is spent", detail)

    def test_a_file_too_large_is_skipped_as_in_the_archive(self):
        answers = github()
        answers[f"https://raw.githubusercontent.com/o/r/{SHA}/tests/test_a.py"] = SourceError(
            "fetching tests/test_a.py: response exceeds the 15MB budget")
        ck, _ = self.checkout(answers)
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertIn(("tests/test_a.py", f"larger than {repo.MAX_MEMBER // 1_000_000} MB, not read"), ck.skipped)

    def test_a_path_that_would_leave_the_checkout_is_not_written(self):
        ck, net = self.checkout(github(left_out={"../escape.py": b"x\n"}))
        self.assertFalse(any("escape" in p for p in self.files(ck)))
        self.assertNotIn(os.path.join(self.tmp, "escape.py"), [os.path.join(self.tmp, f) for f in os.listdir(self.tmp)])


class GitLabTests(Tmp):
    def test_the_repository_files_call(self):
        env = {"LAZARET_GITLAB_URL": "https://git.example.org", "GITLAB_TOKEN": TOKEN}
        ck, net = self.checkout(gitlab(), spec="gitlab:grp/proj@main", env=env)
        self.assertTrue(ck.complete, ck.incomplete)
        self.assertEqual(self.files(ck), dict(INSIDE, **LEFT_OUT))
        self.assertEqual(sum("/repository/files/" in u for u in net.urls()), 3)
        self.assertIn(f"{GL}/repository/files/docs%2Fspace%20name.md/raw?ref={SHA}", net.urls())


if __name__ == "__main__":
    unittest.main()
