"""A project's line metrics are the engine's (Q-1 step 4, 0.1.9).

core.compute_metrics lexed each file again in a second engine call and walked
its lines in Python: the comment lines, the lines of code, and the windows of
six lines of code compared across the project's files (the duplication); the
npm package did the same with its own lexer. Each file's part is now the
engine's (rust/crates/lazaret-engine/src/metrics.rs): from a project scan's
own reading of the file (scan_file with "metrics", a file's `lineMetrics`),
or from `file_metrics` for a file without one; each window is a 64-bit key of
its six lines stripped and joined, as core keyed it, and the keys are compared
here, across the files.

The engine's metrics are held to core's as they were (REFERENCE, below: the
code this replaced, on core's comment layout), on files built from every kind
of comment, string, blank line, line ending and repeat, on files of this
repository, and through a project scan; the npm package's merge to core's.
"""
import json
import os
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import _native, _unicode13, core, engine
from tests import _support
from tests.architecture.test_js_parity import NPM_READY

if not _native.available():
    raise unittest.SkipTest(f"the metrics are the native engine's ({_native.load_error()})")


def REFERENCE(all_files):
    """core.compute_metrics before Q-1 step 4."""
    files = [f for f in all_files if not f.get("dep")]
    ncloc = comments = measured = 0
    win_map = {}
    for f in files:
        code = []
        dup_lang = f.get("lang") is None or f["lang"] in core.DUP_LANGS
        flines = _unicode13.pin(f["content"]).split("\n")
        cmask = core.comment_mask(flines, f["lang"], core.jsx_reading(f["path"]))
        for i, l in enumerate(flines):
            t = l.strip()
            if not t:
                continue
            if cmask[i]:
                comments += 1
                continue
            ncloc += 1
            if dup_lang:
                measured += 1
                code.append((t, i, f["path"]))
        for i in range(len(code) - 5):
            key = "".join(c[0] for c in code[i:i + 6])
            win_map.setdefault(key, []).append(code[i:i + 6])
    dup = set()
    for occ in win_map.values():
        if len(occ) > 1:
            for win in occ:
                for _, i, p in win:
                    dup.add((p, i))
    dup_pct = round(100 * len(dup) / measured, 1) if measured else 0.0
    return {"files": len(files), "depFiles": len(all_files) - len(files),
            "ncloc": ncloc, "comments": comments, "dupPct": dup_pct}


PIECES = {
    "py": ["x = 1", "# c", '"""doc', 'doc"""', "'''a'''", "  ", "　", "y = 'a # b'", " z = 2", "\r",
           "\U0010d4a0"[:1], "s = '''", "'''", "f'{x}#'"],
    "js": ["let a = 1;", "// c", "/* a", "b */", "`t ${x}`", "  ", " ", "'/* no */'", "x = /re\\/x/;", "\r",
           "<div>{/* j */}</div>", " y();"],
    "sql": ["SELECT 1;", "-- c", "/* a", "b */", "'it''s'", "  ", "\r"],
    "go": ["package a", "// c", "/* a", "b */", "x := `raw`", "  "],
    "rs": ["fn a() {}", "// c", "/* a /* nested */", "*/", 'let s = r#"x"#;', "  "],
    None: ["a", "# b", "// c", "  ", "\u0085"],
}
EXT = {"py": ["py"], "js": ["js", "ts", "jsx", "mjs"], "sql": ["sql"], "go": ["go"], "rs": ["rs"], None: ["txt"]}


def made_up(seed=11, sets=60):
    """Sets of files of one language each, built line by line from PIECES, half of them repeated whole."""
    rnd = random.Random(seed)
    out = []
    for lang, pieces in PIECES.items():
        for _ in range(sets):
            files = []
            for j in range(rnd.randint(1, 4)):
                body = "\n".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 40)))
                if rnd.random() < 0.5:
                    body = body + "\n" + body
                files.append({"path": f"f{j}.{rnd.choice(EXT[lang])}", "content": body, "lang": lang})
            out.append(files)
    return out


class EngineMetricsTests(unittest.TestCase):
    maxDiff = None

    def test_the_same_as_cores_on_made_up_files(self):
        for files in made_up():
            with self.subTest(files=[f["content"][:40] for f in files]):
                self.assertEqual(core.compute_metrics(files), REFERENCE(files))

    def test_the_same_as_cores_on_this_repositorys_files(self):
        for tree in ("python/src/lazaret/scanner", "js/src", "python/tests/fixtures"):
            files = core._collect(os.path.join(_support.REPO_ROOT, tree), ())["files"]
            with self.subTest(tree=tree):
                self.assertGreater(len(files), 3)
                self.assertEqual(core.compute_metrics(files), REFERENCE(files))

    def test_a_dependencys_file_is_not_counted_and_a_windows_lines_are_counted_once(self):
        six = "a = 1\nb = 2\nc = 3\nd = 4\ne = 5\nf = 6\ng = 7\n"
        files = [{"path": "a.py", "content": six, "lang": "py"}, {"path": "b.py", "content": six + six, "lang": "py"},
                 {"path": "node_modules/x/c.js", "content": "x();\n", "lang": "js", "dep": True}]
        got = core.compute_metrics(files)
        self.assertEqual(got, REFERENCE(files))
        self.assertEqual((got["files"], got["depFiles"], got["ncloc"], got["dupPct"]), (2, 1, 21, 100.0))

    def test_a_project_scan_reads_them_from_its_own_reading_of_each_file(self):
        root = tempfile.mkdtemp(prefix="lz-metrics-")
        self.addCleanup(shutil.rmtree, root, True)
        rnd = random.Random(3)
        for n, files in enumerate(rnd.sample(made_up(seed=4, sets=12), 20)):
            for f in files:
                if f["lang"] is None:
                    continue
                path = os.path.join(root, f"s{n}", f["path"])
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(f["content"])
        asked = []
        real = engine.file_metrics

        def file_metrics(items):
            asked.extend(items)
            return real(items)
        with mock.patch.object(engine, "file_metrics", file_metrics):
            res = core.scan_project(root)
        self.assertEqual(asked, [])                                   # every file's from its scan: none read again
        res["metrics"].pop("configFiles")
        self.assertEqual(res["metrics"], REFERENCE(core._collect(root, ())["files"]))

    def test_a_file_without_its_scans_metrics_is_read_for_them(self):
        files = [{"path": "a.py", "content": "# n\nx = 1\n", "lang": "py"},
                 {"path": "b.py", "content": "# n\nx = 1\n", "lang": "py", "lineMetrics": (1, 1, 1, "")}]
        self.assertEqual(core.compute_metrics(files), REFERENCE(files))
        # (a file the engine gives no answer at all for: test_review_cli, every line of it is code)


@unittest.skipUnless(NPM_READY, "the npm package's engine is not built")
class NpmMetricsTests(unittest.TestCase):
    """The npm package's computeMetrics, on the engine's file_metrics (the WebAssembly build), merges as core's."""

    SCRIPT = r"""
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { computeMetrics } = await import(pathToFileURL(process.argv[1]).href);
const sets = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(sets.map((files) => computeMetrics(files))));
"""

    def test_the_same_as_cores(self):
        sets = made_up(seed=12, sets=25)
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", self.SCRIPT,
                            os.path.join(_support.REPO_ROOT, "js", "src", "scanner", "metrics.js")],
                           input=json.dumps(sets), capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        got = json.loads(p.stdout)
        for files, js in zip(sets, got):
            with self.subTest(files=[f["content"][:40] for f in files]):
                self.assertEqual(js, core.compute_metrics(files))


if __name__ == "__main__":
    unittest.main()
