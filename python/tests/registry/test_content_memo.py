"""P-2a's call sites: a registry scan asks the engine once for content that several of a release's files hold
(repo._ArtifactScan through registry/contentcache.Memo, one per scan_package run), and a hit gives exactly what
the engine would. The four questions it keeps: a file's first pass (`scan`), the import-time test
(`import-risk`), the scripts a script starts (`spawned`) and the cross-file follower (`cross-file`). An answer
the engine could not give, and a cross-file answer with a package it could not finish, are not kept."""
import io
import json
import os
import tarfile
import time
import unittest
import zipfile
from unittest import mock

from lazaret.registry import contentcache, repo
from lazaret.scanner import _native

PACKAGE = {
    "package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "index.js",
                                "scripts": {"postinstall": "node install.js"}}),
    "install.js": "const cp = require('child_process');\ncp.spawn('node', [__dirname + '/helper.js']);\n",
    "helper.js": "console.log('ready');\n",
    "index.js": "module.exports = require('./lib/a');\n",
    "lib/a.js": "module.exports = function add(a, b) { return a + b; };\n",
    "lib/b.js": "module.exports = function add(a, b) { return a + b; };\n",     # (a's content: one question)
    "lib/c.js": "const d = require('./d');\nmodule.exports = () => d.run();\n",
    "lib/d.js": "exports.run = () => 42;\n",
}


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in sorted(files.items()):
            zf.writestr(name, text)
    return buf.getvalue()


def scan(data, memo, container="tgz", kind="npm"):
    budget = repo.Budget(deadline=time.monotonic() + 60, deadline_detail="the test's budget")
    return repo._scan_artifact(data, container, kind, False, budget, memo)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class CallSiteTests(unittest.TestCase):
    def counting(self):
        """Patches that count the engine's calls the memo stands in front of -> {name: mock}."""
        names = ("call_answers", "import_time_risks", "cross_file_answer", "spawned_scripts", "spawned_scripts_many")
        mocks = {}
        for name in names:
            patch = mock.patch.object(repo._engine, name, wraps=getattr(repo._engine, name))
            mocks[name] = patch.start()
            self.addCleanup(patch.stop)
        return mocks

    def test_a_hit_gives_what_the_engine_gives(self):
        data = tgz(PACKAGE)
        off = scan(data, contentcache.NULL)
        memo = contentcache.Memo()
        self.assertEqual(scan(data, memo), off)
        calls = self.counting()
        self.assertEqual(scan(data, memo), off)                 # every answer a hit
        for name, m in calls.items():
            self.assertEqual(m.call_count, 0, name)
        kinds = memo.stats()["kinds"]
        self.assertEqual(set(kinds), set(contentcache.KINDS))
        for kind in contentcache.KINDS:
            self.assertGreater(kinds[kind]["hits"], 0, kind)
        self.assertEqual(off["verdict"], "WARN")                 # (an install hook: the package is scanned in full)

    def test_one_file_under_two_paths_is_asked_once(self):
        calls = self.counting()
        scan(tgz(PACKAGE), contentcache.Memo())
        asked = [(name, text) for (batch,), _kw in calls["call_answers"].call_args_list for name, _args, text in batch]
        self.assertEqual([text for _name, text in asked].count(PACKAGE["lib/a.js"]), 1)
        self.assertEqual(len(asked), len(set(asked)))           # each question once for one content

    def test_an_answer_the_engine_could_not_give_is_not_kept(self):
        real = repo._engine.call_answers

        def exhausted(calls, texts=None):
            return [_native.NativeExhausted("the work budget was spent") if "d.run" in text else answer
                    for (_n, _a, text), answer in zip(calls, real(calls, texts=texts))]
        memo = contentcache.Memo()
        with mock.patch.object(repo._engine, "call_answers", exhausted):
            res = scan(tgz(PACKAGE), memo)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("lib/c.js", [i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"])
        self.assertGreaterEqual(memo.stats()["kinds"]["scan"]["dropped"], 1)
        calls = self.counting()
        again = scan(tgz(PACKAGE), memo)                          # asked again, and answered this time
        asked = [text for (batch,), _kw in calls["call_answers"].call_args_list for _name, _args, text in batch]
        self.assertEqual(asked, [PACKAGE["lib/c.js"]])
        self.assertEqual(again, scan(tgz(PACKAGE), contentcache.NULL))

    def test_a_cross_file_answer_with_a_package_cut_short_is_not_kept(self):
        memo = contentcache.Memo()
        with mock.patch.object(repo._engine, "cross_file_answer", return_value=([], False)) as cut:
            scan(tgz(PACKAGE), memo)
            scan(tgz(PACKAGE), memo)
        self.assertEqual(cut.call_count, 2)
        stats = memo.stats()["kinds"]["cross-file"]
        self.assertEqual((stats["stored"], stats["dropped"]), (0, 2))

    def test_a_release_shares_one_memo(self):
        files = {"x/__init__.py": "from .core import run\n", "x/core.py": "def run():\n    return 1\n",
                 "x/util.py": "def helper(a):\n    return a\n", "x/more.py": "from .util import helper\n"}
        data = wheel(files)
        arts = [{"url": f"https://files.pythonhosted.org/x-1.0-{t}.whl", "container": "zip",
                 "artifact": "wheel", "entry": {}, "filename": f"x-1.0-{t}.whl"} for t in ("a", "b")]
        seen = []
        real = repo._scan_artifact

        def recording(*args):
            seen.append(args[5])
            return real(*args)

        def run(env):
            with mock.patch.dict(os.environ, env), mock.patch.object(repo, "http_bytes", return_value=data), \
                    mock.patch.object(repo, "verify_digest", return_value=None), \
                    mock.patch.object(repo, "_scan_artifact", recording):
                res = repo.scan_package("pypi", "x", "1.0", resolved=repo.Resolution("1.0", arts))
            res.pop("scannedAt", None)
            return res
        on = run({repo.MEMO_DISABLED_ENV: "0"})
        self.assertIsInstance(seen[0], contentcache.Memo)
        self.assertIs(seen[0], seen[1])                          # both wheels, one memo
        self.assertGreater(seen[0].stats()["kinds"]["scan"]["hits"], 0)
        seen.clear()
        off = run({repo.MEMO_DISABLED_ENV: "1"})
        self.assertIs(seen[0], contentcache.NULL)
        for result in (on, off):
            for key in ("scanSeconds", "elapsed", "durationSeconds"):
                result.pop(key, None)
        self.assertEqual(json.dumps(on, sort_keys=True, default=str), json.dumps(off, sort_keys=True, default=str))


class SwitchTests(unittest.TestCase):
    def test_lazaret_no_cache_turns_it_off(self):
        with mock.patch.dict(os.environ, {repo.MEMO_DISABLED_ENV: "1"}):
            self.assertIs(repo.new_memo(), contentcache.NULL)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(repo.MEMO_DISABLED_ENV, None)
            self.assertIsInstance(repo.new_memo(), contentcache.Memo)

    def test_a_single_archive_and_the_guard_use_none(self):
        st = repo._ArtifactScan("npm", False)
        self.assertIs(st.memo, contentcache.NULL)


if __name__ == "__main__":
    unittest.main()
