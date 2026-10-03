"""SC-EVAL-DECODE's sinks, the text's against the tree's (0.1.8).

Where the engine reads a JavaScript file on its tree, the tree's answer
stands: a decoded value run by a call the tree doesn't count as a runner
loses its finding, though the text reading (`_DECODE_SINK_RE`) counts it.
The droppers work found two such sinks by chance (`await import(
'child_process')`, any object's `execSync`). This test reads the text's sink
names from the rule pack and runs each one, through every way the code can
reach it, on a decoded value: a sink added to the pattern without a probe
here fails, and so does one the tree stops counting.

The probes are inert: the payload decodes to `console.log(1)`.
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


if __name__ == "__main__":
    unittest.main()
