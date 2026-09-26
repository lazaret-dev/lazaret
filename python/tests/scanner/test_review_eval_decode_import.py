"""Final review: SC-EVAL-DECODE missed decoders reached through an inline import.

`exec(__import__("base64").b64decode("…"))` and
`eval(__import__('codecs').decode(…))` were not flagged: the decoder prefix
`(?:[\\w$]+\\s*\\.\\s*)*` allowed only dotted names, not a call such as
`__import__("x").`. The prefix grammar (all three engines) now also allows
`__import__("mod").` and `importlib.import_module("mod").` segments, and a
module-qualified decoder (codecs.decode, zlib.decompress, marshal.loads) may
name its module that way. Every segment ends at a '.', so matching stays
linear. Dependency mode's decode-to-variable flow recognizes the same
decoders. Checked in the Python engine and (project mode) the dashboard;
js/test/review-eval-decode-import.test.js covers the npm engine. All content
is inert: nothing is decoded or executed.
"""
import json
import time
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

FLAGGED = [
    'exec(__import__("base64").b64decode("cHJpbnQoMSk="))',
    "eval(__import__('codecs').decode(s, 'rot13'))",
    'exec(importlib.import_module("zlib").decompress(b))',
    "exec(importlib.import_module( 'base64' ).b64decode(x))",
    "exec(__import__('marshal').loads(b))",
    "exec(__import__('binascii').unhexlify(h))",
    'exec( __import__("base64") . b64decode ( p ) )',
    'eval(__import__("zlib").decompress(__import__("base64").b64decode(z)))',
    "exec(base64.b64decode(x))",
]
NOT_FLAGGED = [
    'exec(__import__("os").system("x"))',
    "eval(__import__('json').loads(s))",
    "exec(importlib.import_module('codecs').lookup(n))",
    "decoded = __import__('base64').b64decode(p)",
]

# Dependency mode, across statements: (source, sink line, assigned-at line)
DEP_FLOWS = [
    ('p = __import__("base64").b64decode(s)\nq = 1\nexec(p)\n', 3, 1),
    ("d = __import__('codecs').decode(s, 'rot13'); eval(d)\n", 1, 1),
    ("z = importlib.import_module('zlib').decompress(b)\nrun = z\nexec(run)\n", 3, 1),
]


def at(issues, rule="SC-EVAL-DECODE"):
    return [(i["line"], i["msg"]) for i in issues if i["rule"] == rule]


class PythonEngineTests(unittest.TestCase):
    def test_inline_import_decoders_are_flagged(self):
        for src in FLAGGED:
            with self.subTest(src=src):
                self.assertEqual([ln for ln, _ in at(core.scan_file("m.py", src + "\n", "py"))], [1])

    def test_multi_line_statement(self):
        src = 'x = 1\nexec(\n    __import__("base64").b64decode(p))\n'
        self.assertEqual([ln for ln, _ in at(core.scan_file("m.py", src, "py"))], [2])

    def test_other_calls_are_not_decoders(self):
        for src in NOT_FLAGGED:
            with self.subTest(src=src):
                self.assertEqual(at(core.scan_file("m.py", src + "\n", "py")), [])

    def test_dependency_mode_follows_the_decoded_value(self):
        for src, line, assigned in DEP_FLOWS:
            with self.subTest(src=src):
                self.assertEqual(at(core.scan_file("dep.py", src, "py", dep=True)), [
                    (line, f"Decoded payload (assigned at line {assigned}) reaches a code-execution sink.")])

    def test_linear_time(self):
        for src in ("exec(" + "__import__('x')." * 50_000, "exec(__import__('" * 50_000,
                    "exec(importlib.import_module('q')." * 30_000, "x = " + "__import__('codecs')" * 50_000):
            started = time.monotonic()
            core.scan_file("m.py", src + "\n", "py")
            core.scan_file("dep.py", src + "\n", "py", dep=True)
            self.assertLess(time.monotonic() - started, 8.0, src[:40])


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_same_findings_as_the_cli(self):
        cases = [(f"f{n}.py", src + "\n") for n, src in enumerate(FLAGGED + NOT_FLAGGED)]
        cases.append(("multi.py", 'x = 1\nexec(\n    __import__("base64").b64decode(p))\n'))
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": "py", "content": c}} for n, c in cases])
        for (name, content), got in zip(cases, page):
            with self.subTest(file=name):
                key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
                self.assertEqual(sorted(map(key, got)), sorted(map(key, core.scan_file(name, content, "py"))))
        self.assertEqual(sum(bool(at(got)) for got in page), len(FLAGGED) + 1)


if __name__ == "__main__":
    unittest.main()
