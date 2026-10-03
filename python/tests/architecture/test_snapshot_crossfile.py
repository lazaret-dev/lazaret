"""The engine's cross-file follower (`cross_file`, crossfile.rs: what the
Python package's --deps checks and registry scans, and the npm package's
--deps checks, run), held to its recorded outputs (_snapshots.py) on the
follower's corpus (crossfile_corpus.py): its own test cases and a seeded
stream of generated packages, each package alone; the stream's packages
side by side in one call; a registry scan's reading (one distribution, the
file named in the message); a distribution's RECORD read as one package;
and skipped files with Windows separators.
"""
import collections
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots
from tests.architecture.crossfile_corpus import curated, generated
from tests.scanner import test_cross_file_follower as T


def call(files, skip=(), who="Dependency code", one_package=False, groups=None, sep="/"):
    """The engine's cross_file call for `files` (as engine.cross_file_issues makes it)."""
    todo = [f for f in files if f.get("dep") and f["lang"] in ("py", "js")]
    args = {"files": [[f["path"], f["lang"], len(f["content"])] for f in todo], "skip": sorted(set(skip)),
            "one_package": one_package, "sep": sep, "redact": True, "neumaier": True, "threads": 2}
    if groups:
        args["groups"] = [groups.get(f["path"]) for f in todo]
    if callable(who):
        args["whos"] = [who(f["path"]) for f in todo]
    else:
        args["who"] = who
    return ("cross_file", args, "".join(f["content"] for f in todo))


def stream():
    return generated(20260928, 700)


def side_by_side():
    """The stream's packages side by side (each under its own directory, a
    Python one under its own top-level name)."""
    files = []
    for k, case in enumerate(stream()):
        for f in case:
            path = f["path"].replace("site-packages/pkg/", f"site-packages/pkg{k}/")
            files.append(dict(f, path=f"case{k}/" + path))
    return files


def one_distribution():
    cases = [T.py({"a.py": T.PY_NET, "b.py": "from a import pull\nexec(pull())\n"})] + generated(7, 60)
    out = []
    for files in cases:
        back = {f["path"]: "rel/" + f["path"].rsplit("/", 1)[-1] for f in files}
        out.append(call(files, who=back.__getitem__, one_package=True))
    return out


def distributions():
    cases = [T.py({"a.py": T.PY_NET, "b.py": "from a import pull\nexec(pull())\n"})] + generated(11, 80)[::2]
    out = []
    for k, files in enumerate(cases):
        groups = {f["path"]: "site-packages/x-1.dist-info" if k == 0 else
                  "venv/lib/python3.12/site-packages/d" + str(len(f["path"]) % 2) + ".dist-info" for f in files}
        out.append(call(files, groups=groups))
    return out


def separators():
    files = T.py({"pkg/_net.py": T.PY_NET, "pkg/run.py": "from ._net import pull\nexec(pull())\n",
                  "pkg/other.py": "from ._net import pull\neval(pull())\n"})
    win = [dict(f, path=f["path"].replace("/", "\\")) for f in files]
    skip = [files[0]["path"].rsplit("/", 2)[0] + "/pkg/run.py"]
    return [call(files), call(files, skip), call(win, skip, sep="\\")]


def snapshot_sets():
    return {"crossfile": lambda: [call(files) for _label, files in curated()] + [call(files) for files in stream()],
            "crossfile_side_by_side": lambda: [call(side_by_side())],
            "crossfile_one_package": one_distribution,
            "crossfile_distributions": distributions,
            "crossfile_separators": separators}


def issues(answer):
    """The issues of a cross_file answer, every package's."""
    return [issue for package in answer.get("ok", []) for _k, issue in package.get("issues", [])]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class CrossFileSnapshotTests(unittest.TestCase):
    def check(self, name):
        answers = _snapshots.run(snapshot_sets()[name](), threads=1)
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return answers

    def test_each_package(self):
        answers = self.check("crossfile")
        # the stream reaches every path: each count is well above zero for this seed
        n = len(curated())
        counts = collections.Counter()
        for files, answer in zip(stream(), answers[n:]):
            lang = files[0]["lang"]
            found = issues(answer)
            if found and any("emit(" in f["content"] for f in files):
                counts["js emitter"] += 1
            for i in found:
                kind = "runner" if "the function that runs it" in i[4] else "received"
                counts[f"{lang} {kind}"] += 1
                counts[i[4].split(";")[0].split(" ", 2)[2]] += 1
        self.assertGreaterEqual(counts["py received"], 40, counts)
        self.assertGreaterEqual(counts["js received"], 40, counts)
        self.assertGreaterEqual(counts["py runner"], 5, counts)
        self.assertGreaterEqual(counts["js runner"], 5, counts)
        self.assertGreaterEqual(counts["js emitter"], 5, counts)
        for cat in ("runs code it receives over the network", "deserializes data it receives over the network",
                    "loads a module named by data it receives over the network"):
            self.assertGreaterEqual(counts[cat], 5, counts)

    def test_every_package_in_one_call(self):
        answers = self.check("crossfile_side_by_side")
        self.assertGreater(len(issues(answers[0])), 100)

    def test_one_distribution(self):
        answers = self.check("crossfile_one_package")
        self.assertTrue(issues(answers[0]))

    def test_a_distributions_modules(self):
        answers = self.check("crossfile_distributions")
        self.assertGreater(sum(1 for a in answers if issues(a)), 5)

    def test_skipped_files_and_windows_separators(self):
        answers = self.check("crossfile_separators")
        self.assertEqual([len(issues(a)) for a in answers], [2, 1, 1])


if __name__ == "__main__":
    unittest.main()
