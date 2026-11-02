"""D-17 (0.1.9): a function in another file of the package that runs a fixed program, given the data as its arguments.

lerna 10.0.1 was SUSPICIOUS: dist/chunk-EB6RZPL6.js calls `gitCheckout(dirtyManifests, gitOpts, this.execOpts)`, and
gitCheckout (dist/chunk-WC2B4V4E.js) runs `exec("git", ["checkout", "--"].concat(files), execOpts)`, its wrapper of
execa: git, given the files as its arguments. The cross-file follower read each function's body with its strings
blanked, so the program's name was not there, and the received-code test took the call for one that runs what it is
given. It now reads the body's code, and a call of exec's whose first argument is a literal, plain command line
naming a program that runs nothing it is given runs none of the data after it.

Still found: the data as the program, an interpreter given it as code, and a program that runs the command its
arguments name (`timeout`, `xargs`, `npx` …) given the data.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

MAIN = ("import { gitCheckout } from './a.js';\nimport https from 'https';\n"
        "https.get('https://x.invalid/m', (res) => { let d = ''; res.on('data', (c) => d += c);\n"
        "  res.on('end', async () => { const files = JSON.parse(d); await gitCheckout(files, {}, {}); }); });\n")
HELPER = ("import { execa } from 'execa';\nfunction exec(command, args, opts) { return execa(command, args, opts); }\n"
          "export function gitCheckout(stagedFiles, gitOpts, execOpts) {\n"
          "  const files = gitOpts.granularPathspec ? stagedFiles : \".\";\n  RUN\n}\n")


def scan(run):
    res = scan_npm({"package.json": manifest(main="b.mjs", type="module"), "b.mjs": MAIN,
                    "a.js": HELPER.replace("RUN", run)})
    return res, [(i["file"], i["line"], i["msg"]) for i in issues(res, "SC-IMPORT-RISK")]


class NotFoundTests(unittest.TestCase):
    def test_lernas_shape(self):
        for run in ('return exec("git", ["checkout", "--"].concat(files), execOpts);',
                    'return exec(\n    "git",\n    ["checkout", "--"].concat(files),\n    execOpts\n  );',
                    "return execSync('git status --porcelain', files);"):
            with self.subTest(run):
                res, found = scan(run)
                self.assertEqual(found, [])
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])


class FoundTests(unittest.TestCase):
    def test_the_data_as_the_program_or_an_interpreters_code(self):
        for run in ("return exec(stagedFiles, [], execOpts);", 'return exec("node", ["-e", stagedFiles], execOpts);',
                    'return exec("timeout", ["5"].concat(files), execOpts);'):
            with self.subTest(run):
                res, found = scan(run)
                ((file, line, msg),) = found
                self.assertEqual((file, line), ("b.mjs", 4))
                self.assertIn("runs code it receives over the network; the function that runs it is in another file",
                              msg)
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
