"""engine.cross_file_issues: which engine follows values across a package's
files, and that the findings are core._cross_file_received_issues' whichever
engine finds them.

- With the Python engine, core follows them.
- With the native engine, its `cross_file` reads every package in one call
  (the dependency files of the scan, each package on its own budget, on
  engine.THREADS threads); a package it reports as failed (its budget spent,
  an internal error) is read by core, in its place; a call the engine refuses
  altogether is answered by core.
- What a registry scan passes (one package, each file named in the message by
  a function) reaches the engine as one name per file.

The cases that run the native library skip where it is not built; the
fallbacks are checked with the library mocked, everywhere. Inert text: hosts
are .invalid, nothing is executed.
"""
import unittest
from unittest import mock

from lazaret.scanner import _native, core, engine
from tests.scanner import test_cross_file_follower as T


def py_pkg(prefix):
    return [dict(f, path=prefix + f["path"]) for f in
            T.py({"pkg/_net.py": T.PY_NET, "pkg/__init__.py": "from ._net import pull\nexec(pull())\n"})]


def js_pkg(prefix):
    return [dict(f, path=prefix + f["path"]) for f in
            T.js({"net.js": T.JS_NET + "module.exports = { pull };\n",
                  "run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n"})]


FILES = py_pkg("a/") + js_pkg("b/") + js_pkg("c/") + [
    {"path": "app/main.py", "lang": "py", "dep": False, "content": "exec(input())\n"}]


def view(issues):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues]


class PythonEngineTests(unittest.TestCase):
    def test_core_follows_them(self):
        engine.choose("python")
        try:
            with mock.patch.object(_native, "call") as call:
                got = engine.cross_file_issues(FILES)
        finally:
            engine.choose(None)
        call.assert_not_called()
        self.assertEqual(view(got), view(core._cross_file_received_issues(FILES)))
        self.assertEqual(len(got), 3)


class FallbackTests(unittest.TestCase):
    """The native engine mocked: what core answers in its place."""

    def setUp(self):
        patcher = mock.patch.object(engine, "name", return_value="rust")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_refused_call_is_answered_by_core(self):
        with mock.patch.object(_native, "call", side_effect=_native.NativeError("no")):
            got = engine.cross_file_issues(FILES)
        self.assertEqual(view(got), view(core._cross_file_received_issues(FILES)))

    def test_a_failed_package_is_read_by_core_in_its_place(self):
        want = core._cross_file_received_issues(FILES)
        answer = [{"lang": "py", "root": "pkg", "failed": "exhausted"},
                  {"lang": "js", "root": "b/node_modules/pkg", "failed": "panic"},
                  {"lang": "js", "root": "c/node_modules/pkg", "issues": [[5, ["SC-IMPORT-RISK", "n", "HOTSPOT", "CRITICAL",
                                                                                "m", "w", "f", "r", 2, ["x"], 1]]]}]
        with mock.patch.object(_native, "call", return_value=answer) as call:
            got = engine.cross_file_issues(FILES)
        name, args, text = call.call_args[0]
        self.assertEqual(name, "cross_file")
        self.assertEqual([f[0] for f in args["files"]], [f["path"] for f in FILES[:6]])    # dependency files only
        self.assertEqual(text, "".join(f["content"] for f in FILES[:6]))
        self.assertEqual([f[2] for f in args["files"]], [len(f["content"]) for f in FILES[:6]])
        self.assertEqual(view(got[:2]), view(want[:2]))
        self.assertEqual(got[2]["file"], FILES[5]["path"])
        self.assertEqual((got[2]["rule"], got[2]["line"], got[2]["snipStart"]), ("SC-IMPORT-RISK", 2, 1))

    def test_a_registry_scan_names_each_file(self):
        names = {f["path"]: "rel/" + f["path"].rsplit("/", 1)[-1] for f in FILES}
        with mock.patch.object(_native, "call", return_value=[]) as call:
            engine.cross_file_issues(FILES, who=names.__getitem__, one_package=True)
        args = call.call_args[0][1]
        self.assertTrue(args["one_package"])
        self.assertNotIn("who", args)
        self.assertEqual(args["whos"], [names[f["path"]] for f in FILES[:6]])

    def test_fewer_than_two_files_ask_nothing(self):
        with mock.patch.object(_native, "call") as call:
            self.assertEqual(engine.cross_file_issues(FILES[:1] + FILES[-1:]), [])
        call.assert_not_called()


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativeEngineTests(unittest.TestCase):
    def test_the_native_engine_finds_cores_findings(self):
        engine.choose("rust")
        try:
            got = engine.cross_file_issues(FILES)
        finally:
            engine.choose(None)
        self.assertEqual(got, core._cross_file_received_issues(FILES))
        self.assertEqual(len(got), 3)

    def test_redaction_follows_core(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"           # a fake key, built so no scanner takes it for a real one
        files = T.py({"pkg/_net.py": T.PY_NET, "pkg/__init__.py": f"K = '{key}'\nfrom ._net import pull\nexec(pull())\n"})
        engine.choose("rust")
        try:
            for redact in (True, False):
                with self.subTest(redact=redact), mock.patch.object(core, "REDACT_SECRETS", redact):
                    got = engine.cross_file_issues(files)
                    self.assertEqual(got, core._cross_file_received_issues(files))
                    self.assertEqual(key in "".join(got[0]["snippet"]), not redact)
        finally:
            engine.choose(None)


if __name__ == "__main__":
    unittest.main()
