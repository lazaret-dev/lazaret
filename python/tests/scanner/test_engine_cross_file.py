"""engine.cross_file_issues: the native engine's cross-file follower, which
reads every package in one call (the dependency files of the scan, each
package on its own work budget, on engine.THREADS threads).

- A package the engine reports as failed (its budget spent, an internal
  error) is skipped, and a call it refuses altogether gives no findings, as
  in the npm package.
- What a registry scan passes (one package, each file named in the message by
  a function) reaches the engine as one name per file.

The call's shape is checked with the library mocked; the findings, with the
library (skipped where it is not built). Inert text: hosts are .invalid,
nothing is executed.
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

# (rule, file, line, severity) of each finding on FILES: one per package, at the file that runs what
# the other file received
FOUND = [("SC-IMPORT-RISK", "a/site-packages/pkg/__init__.py", 2, "CRITICAL"),
         ("SC-IMPORT-RISK", "b/node_modules/pkg/run.js", 2, "CRITICAL"),
         ("SC-IMPORT-RISK", "c/node_modules/pkg/run.js", 2, "CRITICAL")]


def view(issues):
    return [(i["rule"], i["file"], i["line"], i["sev"]) for i in issues]


class CallTests(unittest.TestCase):
    """The native library mocked: what is asked, and what an answer becomes."""

    def test_a_refused_call_gives_no_findings(self):
        with mock.patch.object(_native, "call", side_effect=_native.NativeError("no")):
            self.assertEqual(engine.cross_file_issues(FILES), [])

    def test_a_failed_package_is_skipped(self):
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
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["file"], FILES[5]["path"])
        self.assertEqual((got[0]["rule"], got[0]["line"], got[0]["snippet"], got[0]["snipStart"]),
                         ("SC-IMPORT-RISK", 2, ["x"], 1))

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
    def test_the_engine_follows_each_package(self):
        got = engine.cross_file_issues(FILES)
        self.assertEqual(view(got), FOUND)
        self.assertEqual(got, core._cross_file_received_issues(FILES))

    def test_a_file_already_flagged_is_skipped(self):
        got = engine.cross_file_issues(FILES, skip_paths={"b/node_modules/pkg/run.js"})
        self.assertEqual(view(got), [FOUND[0], FOUND[2]])

    def test_redaction_follows_core(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"           # a fake key, built so no scanner takes it for a real one
        files = T.py({"pkg/_net.py": T.PY_NET, "pkg/__init__.py": f"K = '{key}'\nfrom ._net import pull\nexec(pull())\n"})
        for redact in (True, False):
            with self.subTest(redact=redact), mock.patch.object(core, "REDACT_SECRETS", redact):
                got = engine.cross_file_issues(files)
                self.assertEqual(len(got), 1)
                self.assertEqual(key in "".join(got[0]["snippet"]), not redact)


if __name__ == "__main__":
    unittest.main()
