"""SC-EVAL-DECODE's sinks, the text's against the tree's (0.1.8).

Where the engine reads a JavaScript file on its tree, the tree's answer
stands: a decoded value run by a call the tree doesn't count as a runner
loses its finding, though the text reading (`_DECODE_SINK_RE`) counts it.
The droppers work found two such sinks by chance (`await import(
'child_process')`, any object's `execSync`). This test reads the text's sink
names from the rule pack and runs each one, through every way the code can
reach it, on a decoded value: a sink added to the pattern without a probe
here fails, and so does one the tree stops counting.

Python's text reading has no shell among its sinks, so a decoded value run
by a shell (`os.system(b64decode(s).decode())`) had no candidate and was no
finding, while JavaScript's `execSync(atob(s))` was BLOCKER. A Python text
with a decoder the text knows and a shell is read on its tree now (0.1.8):
every shell, after every decoder, is held here, and what is not a run is
not a finding.

The probes are inert: the payloads decode to `console.log(1)` and `whoami`.
"""
import json
import os
import re
import unittest

from lazaret.scanner import core
from tests import _support

PACK = os.path.join(_support.REPO_ROOT, "rust", "crates", "lazaret-engine", "rules", "lazaret-rules.json")
DECODED = 'const d = Buffer.from("Y29uc29sZS5sb2coMSk=", "base64").toString();\n'

# where each of the pattern's sink names comes from, and how code reaches it
WAYS = {
    "global": ("{f}(d);\n", "globalThis.{f}(d);\n"),
    "child_process": ("const cp = require('child_process');\ncp.{f}(d);\n",
                      "require('child_process').{f}(d);\n",
                      "const {{ {f} }} = require('child_process');\n{f}(d);\n",
                      "const cp = require('node:child_process');\ncp.{f}(d);\n",
                      "(async () => {{ const cp = await import('child_process'); cp.{f}(d); }})();\n"),
    "vm": ("const vm = require('vm');\nvm.{f}(d, {{}});\n", "require('vm').{f}(d, {{}});\n"),
}
SINKS = {"eval": "global", "Function": "global", "exec": "child_process", "execSync": "child_process",
         "execFile": "child_process", "execFileSync": "child_process", "spawn": "child_process",
         "spawnSync": "child_process", "runInThisContext": "vm", "runInNewContext": "vm", "runInContext": "vm"}


def text_sinks():
    """The sink names `_DECODE_SINK_RE` alternates, `(?:A|B)?` expanded."""
    with open(PACK, encoding="utf-8") as f:
        pattern = json.load(f)["values"]["_DECODE_SINK_RE"]["re"]
    group = re.search(r"\(\?<!\[\\w\$\]\)\(([^()]*(?:\(\?:[^()]*\)\??[^()]*)*)\)\\s\*\\\($", pattern)
    if group is None:
        raise AssertionError(f"_DECODE_SINK_RE changed shape: {pattern}")
    names, depth, part = [], 0, ""
    for ch in group.group(1):                       # split on | at the top level
        depth += ch == "("
        depth -= ch == ")"
        if ch == "|" and depth == 0:
            names.append(part)
            part = ""
        else:
            part += ch
    names.append(part)
    out = set()
    for name in names:
        m = re.fullmatch(r"(\w*)\(\?:([\w|]+)\)\?(\w*)", name)
        if m:
            out.add(m.group(1) + m.group(3))
            out.update(m.group(1) + alt + m.group(3) for alt in m.group(2).split("|"))
        else:
            out.add(name)
    return out


def decode_findings(body):
    return {(i["rule"], i["sev"]) for i in core.scan_file("x.js", DECODED + body, "js", dep=True)
            if i["rule"] == "SC-EVAL-DECODE"}


class DecodeSinkTests(unittest.TestCase):
    def test_every_text_sink_has_a_probe(self):
        self.assertEqual(text_sinks(), set(SINKS), "a sink of _DECODE_SINK_RE has no probe here (SINKS, WAYS)")

    def test_the_tree_counts_every_sink(self):
        for name, origin in sorted(SINKS.items()):
            for way in WAYS[origin]:
                body = way.format(f=name)
                with self.subTest(sink=name, code=body):
                    self.assertEqual(decode_findings(body), {("SC-EVAL-DECODE", "BLOCKER")})

    def test_the_constructor_and_any_objects_execSync(self):
        for body in ("new Function(d)();\n", "shell.execSync(d);\n", "Function(d)();\n"):
            with self.subTest(code=body):
                self.assertEqual(decode_findings(body), {("SC-EVAL-DECODE", "BLOCKER")})


PY_DECODED = "import base64, codecs, os, subprocess, zlib\nd = {decode}\n"
PY_DECODERS = ("base64.b64decode('d2hvYW1p').decode()", "bytes.fromhex('77686f616d69').decode()",
               "zlib.decompress(b'x').decode()", "codecs.decode('6a686e6e7a76', 'hex').decode()")
PY_SHELLS = ("os.system(d)", "os.popen(d)", "subprocess.run(d, shell=True)", "subprocess.Popen(d, shell=True)",
             "subprocess.call(d, shell=True)", "subprocess.check_output(d, shell=True)", "subprocess.getoutput(d)",
             "__import__('os').system(d)")


def py_findings(text):
    return {(i["rule"], i["sev"]) for i in core.scan_file("setup.py", text, "py", dep=True)
            if i["rule"] == "SC-EVAL-DECODE"}


class PythonShellTests(unittest.TestCase):
    def test_a_decoded_value_run_by_a_shell(self):
        for decode in PY_DECODERS:
            for run in PY_SHELLS:
                text = PY_DECODED.format(decode=decode) + run + "\n"
                with self.subTest(decode=decode, run=run):
                    self.assertEqual(py_findings(text), {("SC-EVAL-DECODE", "BLOCKER")})

    def test_in_the_same_call(self):
        self.assertEqual(py_findings("import base64, os\nos.system(base64.b64decode('d2hvYW1p').decode())\n"),
                         {("SC-EVAL-DECODE", "BLOCKER")})

    def test_what_is_not_a_decoded_value_run(self):
        decoded = PY_DECODED.format(decode=PY_DECODERS[0])
        for text in (decoded + "subprocess.run(['echo', d])\n",                 # an argument, not the command
                     decoded + "print(d)\nsubprocess.run(['ls'])\n",            # never reaches the shell
                     "import os\nx = 'ls'\nos.system(x)\n",                     # nothing decoded
                     '"""os.system(base64.b64decode(s))"""\nimport subprocess\nsubprocess.run(["ls"])\n'):
            with self.subTest(text=text):
                self.assertEqual(py_findings(text), set())

    def test_an_sdist_that_runs_one_at_install(self):
        from tests.registry._review_support import scan_sdist
        res = scan_sdist({"setup.py": "import base64, os\nfrom setuptools import setup\n"
                                      "os.system(base64.b64decode('d2hvYW1p').decode())\nsetup(name='x')\n"})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
