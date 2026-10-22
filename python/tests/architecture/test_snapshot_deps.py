"""--deps' decisions, held to their recorded outputs (_snapshots.py): the engine's calls of
rust/crates/lazaret-engine/src/deps.rs (`deps_hooks`, `deps_files`, `deps_script`, `deps_targets`,
`dep_file_issues`) as --deps scans make them, every round of every call with what the tree had answered by then.

Until BR-7's step 3 e (0.1.9) both packages made these decisions themselves (core's dependency_checks,
project_hook_checks and their helpers; js/src/deps.js): the follow of a dependency's install hooks and of a
project's own, npm's implicit node-gyp hook, a web app's static assets, each installed package's names, the
site-packages groups, the import-time and agent findings. The engine took them over; the packages read the tree
for it. The step's gate held the scans these calls come from to the Python the engine replaced, issue for issue
(140 trees like these, with --deps and without: no difference), and these hashes were recorded from the engine
then.

The calls are made here, by --deps scans of trees put together from the dependency tests' own fixtures
(test_review_dependency_checks, test_review_project_hooks, test_deps_package_names, test_cross_file_follower,
test_review_agent_hijack): each fixture tree whole, then trees of one to three of them merged, some files left
out, some packages moved under a scope or into another package's node_modules, with an exclusion and without.

All content is inert text: hosts are .invalid, every credential is made up and built in pieces
(test_fixture_credentials), and nothing is executed or contacted.
"""
import json
import os
import random
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import _native, core
from tests.architecture import _snapshots

CALLS = ("deps_hooks", "deps_files", "deps_script", "deps_targets", "dep_file_issues")
TREES = 40


def fixtures():
    from tests.scanner import test_review_dependency_checks as dc
    from tests.scanner import test_review_project_hooks as ph
    from tests.scanner import test_deps_package_names as dn
    from tests.scanner import test_cross_file_follower as cf
    from tests.scanner import test_review_agent_hijack as ah
    pkg = dn.pkg
    names = {"package.json": pkg("app"),
             "node_modules/hash-sdk/package.json": pkg("hash-sdk"), "node_modules/hash-sdk/index.js": dn.CHS,
             "node_modules/@s/hash-sdk/package.json": pkg("@s/hash-sdk", dependencies={"prettier-sdk": "^1"}),
             "node_modules/@s/hash-sdk/index.js": dn.CHS,
             "node_modules/gen-pkg/package.json": pkg("gen-pkg", scripts={"postinstall": "node gen.js"}),
             "node_modules/gen-pkg/gen.js": dn.GEN.replace("PKG", "other-pkg"),
             "node_modules/gen-own/package.json": pkg("gen-own", scripts={"postinstall": "node gen.js"}),
             "node_modules/gen-own/gen.js": dn.GEN.replace("PKG", "gen-own"),
             "node_modules/gen-own/lib/index.js": dn.GEN.replace("PKG", "gen-own")}
    site = "venv/lib/python3.12/site-packages/"
    py = {site + "evil/__init__.py": dn.PIP,
          site + "evil-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n\nA description.\n",
          site + "evil-1.0.dist-info/RECORD": "evil/__init__.py,sha256=x,1\nevil-1.0.dist-info/METADATA,,\n",
          site + "ok/__init__.py": dn.PIP,
          site + "ok-1.0.dist-info/METADATA": "Name: ok\nRequires-Dist: evil-pkg>=1; extra == 'x'\n\n",
          site + "ok-1.0.dist-info/RECORD": "ok/__init__.py,,\n",
          site + "a.py": cf.PY_NET, site + "b.py": "from a import pull\nexec(pull())\n",
          site + "c.py": "from a import pull\neval(pull())\n",
          site + "x-1.0.dist-info/RECORD": "a.py,sha256=1,2\nb.py,,\nx-1.0.dist-info/RECORD,,\n../../../bin/x,,\n",
          site + "x-1.0.dist-info/METADATA": "Name: x\nRequires-Dist: requests\n",
          site + "ns1-1.dist-info/RECORD": "ns/one/__init__.py,,\n", site + "ns/one/__init__.py": cf.PY_NET}
    agent = {"node_modules/ag/package.json": pkg("ag", scripts={"postinstall": "node t.js"}),
             "node_modules/ag/t.js": ah.TELEMETRY,
             "node_modules/ah/package.json": pkg("ah", scripts={"install": "q --trust-all-tools -p harvest"}),
             "node_modules/ai/package.json": pkg("ai"), "node_modules/ai/index.js": ah.TELEMETRY,
             "node_modules/aj/package.json": pkg("aj", scripts={"preinstall": "node a.js"}),
             "node_modules/aj/a.js": ph.START, "node_modules/aj/lib/setup.js": ph.EXFIL + ph.OBF,
             "node_modules/aj/setup.js": ph.OBF}
    gyp = {"node_modules/gy/package.json": pkg("gy"), "node_modules/gy/binding.gyp": "{'targets': []}\n",
           "node_modules/gz/package.json": pkg("gz", gypfile=False), "node_modules/gz/binding.gyp": "{'targets': []}\n",
           "node_modules/gw/package.json": pkg("gw", scripts={"install": "node-gyp rebuild"}),
           "node_modules/gw/binding.gyp": "{'targets': []}\n",
           "node_modules/@s/gv/package.json": pkg("@s/gv", scripts={"preinstall": "  "}),
           "node_modules/@s/gv/binding.gyp": "{'targets': []}\n"}
    return [dc.TREE, dc.WEB_TREE, ph.TREE, names, py, agent, gyp]


def move(tree, rnd):
    """A package moved under a scope, or into another's node_modules."""
    tops = sorted({"/".join(k.split("/")[:2]) for k in tree if k.startswith("node_modules/") and k.count("/") >= 2
                   and not k.split("/")[1].startswith("@")})
    if not tops:
        return tree
    top = rnd.choice(tops)
    name = top.split("/")[1]
    to = rnd.choice([f"node_modules/@sc/{name}", f"node_modules/host/node_modules/{name}", f"lib/node_modules/{name}"])
    return {(to + k[len(top):] if k == top or k.startswith(top + "/") else k): v for k, v in tree.items()}


def trees(seed=20261016):
    pool = fixtures()
    rnd = random.Random(seed)
    out = [dict(f) for f in pool]
    while len(out) < TREES:
        tree = {}
        for f in rnd.sample(pool, rnd.randint(1, 3)):
            tree.update(f)
        tree = {rel: data for rel, data in tree.items() if rnd.random() > 0.12}
        for _ in range(rnd.randint(0, 2)):
            tree = move(tree, rnd)
        out.append(tree)
    return out


_MADE = {}


def deps_calls():
    """The deps.rs calls --deps scans of the trees make, in order (each recorded as it was made)."""
    if "calls" in _MADE:
        return _MADE["calls"]
    made = []
    real = _native.call

    def record(name, args=None, text=""):
        if name in CALLS:
            made.append((name, json.loads(json.dumps(args)), text))
        elif name == "batch":
            made.extend((c[0], json.loads(json.dumps(c[1])), c[2]) for c in args["calls"]
                        if c[0] in CALLS and len(c) > 2)
        return real(name, args, text) if args is not None else real(name)

    base = tempfile.mkdtemp(prefix="lz-snap-deps-")
    try:
        with mock.patch.object(_native, "call", record):
            for k, tree in enumerate(trees()):
                root = os.path.join(base, f"t{k}")
                for rel, data in tree.items():
                    path = os.path.join(root, *rel.split("/"))
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "wb") as fh:
                        fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
                try:
                    core.scan_project(root, exclude=("excluded",) if k % 2 else (), include_deps=True)
                except core.ScanTargetError:
                    pass
    finally:
        shutil.rmtree(base, ignore_errors=True)
    _MADE["calls"] = made
    return made


def snapshot_sets():
    return {"deps_follow": lambda: [c for c in deps_calls() if c[0] in ("deps_hooks", "deps_script")],
            "deps_files": lambda: [c for c in deps_calls() if c[0] in ("deps_files", "deps_targets", "dep_file_issues")]}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class DepsSnapshotTests(unittest.TestCase):
    def answers(self, name):
        calls = snapshot_sets()[name]()
        answers = _snapshots.run(calls)
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return calls, [a["ok"] for a in answers]

    def test_the_follow(self):
        calls, got = self.answers("deps_follow")
        done = [a for (c, _a, _t), a in zip(calls, got) if c == "deps_hooks" and "need" not in a]
        self.assertGreater(len(done), 45)
        self.assertGreater(sum(1 for a in done for h in a["hooks"] if h and h[0] == "CRITICAL"), 150)
        self.assertGreater(sum(1 for a in done for o in a["out"] if o[0] == "read"), 70)
        self.assertGreater(sum(1 for a in done for o in a["out"] if o[0] == "issue"), 45)
        facts = [a for (c, _a, _t), a in zip(calls, got) if c == "deps_script" and a]
        self.assertGreater(sum(1 for a in facts if a["risk"]), 140)
        self.assertGreater(sum(1 for a in facts if a.get("spawned")), 15)

    def test_the_files(self):
        calls, got = self.answers("deps_files")
        done = [a for (c, _a, _t), a in zip(calls, got) if c == "deps_files" and "need" not in a]
        self.assertGreater(len(done), 30)
        self.assertGreater(sum(len(a["assets"]) for a in done), 30)
        self.assertGreater(sum(1 for a in done for _p, n in a["todo"] if n), 120)
        self.assertGreater(sum(len(a["groups"]) for a in done), 12)
        found = [a for (c, _a, _t), a in zip(calls, got) if c == "dep_file_issues"]
        self.assertGreater(sum(1 for a in found if a[0]), 90)
        self.assertGreater(sum(1 for a in found if a[1]), 7)


if __name__ == "__main__":
    unittest.main()
