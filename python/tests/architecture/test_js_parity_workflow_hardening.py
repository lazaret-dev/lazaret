"""Engine parity for the workflow hardening checks (0.1.9, S-2): the npm engine's
js/src/lib/ghworkflow.js `hardening` and `hardeningRule` against
lazaret.scanner.ghworkflow.hardening and hardening_rule.

Compared case by case in one node process, on curated workflows and on seeded
random ones built from the forms each part takes: `uses:` pinned and not (a
full SHA, a tag, a branch, an image with and without a digest, a reusable
workflow, a local path), permissions as a block, a flow mapping, `write-all`,
`read-all` and none, pull_request_target and release events, checkouts with a
`ref:` or a `repository:` from the pull request and the same as git commands,
cache actions and the setup actions' cache inputs, installs with and without
--ignore-scripts, publish commands. The rule each finding becomes is compared
too (the id, severity, message, reason and fix), and the pattern text and the
lists the twin keeps are checked to be the Python module's own.

All content is inert text: hosts are .invalid, and nothing is executed.
Skipped where node is missing.
"""
import json
import random
import re
import subprocess
import unittest

from lazaret.scanner import ghworkflow
from tests.architecture import test_js_parity as parity
from tests.architecture.test_js_parity_persistence import LIB

NODE = parity.NODE
NPM = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const g = await import(pathToFileURL(process.argv[1] + "/ghworkflow.js").href);
const texts = JSON.parse(readFileSync(0, "utf8"));
const out = {
  twins: g.HARDENING_TWINS,
  cases: texts.map((t) => { const found = g.hardening(t); return [found, found.map(([k, , d]) => g.hardeningRule(k, d))]; }),
};
process.stdout.write(JSON.stringify(out));
"""

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32

CURATED = [
    # an unpinned workflow with write permissions for every job
    "on: push\npermissions:\n  contents: write\n  id-token: write\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n      - uses: some/thing@main\n      - run: npm ci\n",
    # pinned, read only: nothing to say
    f"on: push\npermissions: read-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{SHA} # v4\n",
    # a pull_request_target job that checks out the pull request, with and by command
    "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          git fetch origin pull/1/head\n"
    "          git checkout ${{ github.head_ref }}\n",
    # a release that restores caches
    "on:\n  release:\n    types: [published]\npermissions:\n  contents: read\njobs:\n  p:\n    runs-on: ubuntu-latest\n"
    "    steps:\n      - uses: actions/cache@v4\n        with:\n          path: ~/.npm\n"
    "      - uses: actions/setup-node@v4\n        with:\n          cache: npm\n      - uses: actions/setup-go@v5\n"
    "      - uses: actions/setup-node@v4\n      - uses: actions/setup-python@v5\n        with:\n          cache: false\n",
    # an OIDC token, and installs, in the workflow's permissions and in a job's own
    "on: push\npermissions:\n  id-token: write\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"
    "  b:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: npm ci\n"
    "  c:\n    runs-on: ubuntu-latest\n    permissions: {id-token: write, contents: read}\n    steps:\n"
    "      - run: npm ci --ignore-scripts\n      - run: pip install x\n",
    # no permissions at all
    "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n  b:\n    runs-on: ubuntu-latest\n"
    "    permissions: {}\n    steps:\n      - run: echo hi\n",
    # images, reusable workflows, local paths
    f"on: push\npermissions: {{}}\njobs:\n  a:\n    uses: org/repo/.github/workflows/w.yml@v1\n  b:\n    uses: ./.github/workflows/x.yml\n"
    f"  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: docker://alpine:3\n      - uses: docker://alpine@{DIGEST}\n"
    f"      - uses: ./local\n      - uses: org/repo/sub@{SHA}\n      - uses: org/repo@{SHA[:39]}\n",
    "", "on: push\n", "jobs:\n", "jobs:\n  a:\n", "- uses: x@v1\n", "permissions: write-all\n",
]


def uses():
    return ["actions/checkout@v4", "actions/checkout@" + SHA, "actions/cache@v4", "actions/cache/restore@" + SHA,
            "actions/setup-node@v4", "actions/setup-python@v5", "actions/setup-go@v5", "actions/setup-java@v4",
            "actions/setup-dotnet@v4", "ruby/setup-ruby@v1", "astral-sh/setup-uv@v5", "Swatinem/rust-cache@v2",
            "github/codeql-action/init@v3", "some/thing@main", "some/thing@" + SHA, "some/thing", "some/thing@",
            "docker://alpine:3", "docker://alpine@" + DIGEST, "docker://alpine@sha256:xyz", "./local", ".", "../x",
            "pypa/gh-action-pypi-publish@release/v1", "softprops/action-gh-release@v2", "org/repo/.github/workflows/w.yml@v1",
            "org/repo@1.2.3", "org/repo@v", "org/repo@V4", "  spaced/action@v1  "]


def withs(rnd):
    c = rnd.choice
    pick = [c(["ref: ${{ github.event.pull_request.head.sha }}", "ref: ${{ github.head_ref }}", "ref: main",
               "ref: refs/pull/${{ github.event.number }}/merge", "ref: ''"]),
            c(["repository: ${{ github.event.pull_request.head.repo.full_name }}", "repository: me/x"]),
            c(["cache: npm", "cache: false", "cache: ''", "enable-cache: false", "enable-cache: true", "bundler-cache: true",
               "package-manager-cache: false", "package-manager-cache: true", "path: ~/.cache"]),
            c(["token: ${{ secrets.T }}", "persist-credentials: false", "node-version: 20"])]
    return rnd.sample(pick, rnd.randint(0, 3))


RUNS = ["npm ci", "npm install", "npm i --ignore-scripts", "pnpm install --frozen-lockfile", "yarn", "yarn install", "yarn;",
        "pip install -r r.txt", "python3 -m pip install x", "uv sync", "poetry install", "cargo build --release", "go build ./...",
        "go mod download", "npm publish", "twine upload dist/*", "gh release create v1", "docker push x", "cargo publish",
        "git checkout ${{ github.event.pull_request.head.sha }}", "git fetch origin refs/pull/1/head", "gh pr checkout 1",
        "gh pr checkout ${{ github.event.number }}", "git fetch origin pull/${{ github.event.number }}/head", "git fetch origin pull/7/merge",
        "echo ${{ github.head_ref }}", "echo hi", "make test", "npm run build && npm ci", "(npm ci)", "yarnpkg", "npm ci;",
        "CI=true npm ci", "A=1 B=x/y npm ci", "sudo pip install x", "if true; then npm ci; fi", "x=$(npm ci)", "a | yarn",
        "echo npm ci", "git commit -m 'npm ci'", "echo do not npm install", "FOO=\"a b\" npm ci", "time cargo build",
        "echo && npm publish", "echo npm publish", "exec twine upload dist/*"]


def permissions(rnd, pad):
    c = rnd.choice
    return c([
        pad + "permissions: read-all", pad + "permissions: write-all", pad + "permissions: {}",
        pad + "permissions: {contents: write}", pad + "permissions: {id-token: write, contents: read}",
        pad + "permissions:\n" + pad + "  contents: read",
        pad + "permissions:\n" + pad + "  contents: write\n" + pad + "  id-token: write",
        pad + "permissions:\n" + pad + "  id-token: write\n" + pad + "  packages: read",
        pad + "permissions:\n" + pad + "  pull-requests: write"])


def workflow(rnd):
    c = rnd.choice
    on = c(["on: push", "on: pull_request_target", "on: [push, pull_request_target]", "on:\n  release:\n    types: [published]",
            "on:\n  pull_request_target:\n    types: [opened]", "on: workflow_dispatch", "on: pull_request",
            "\"on\":\n  - release", "on: {release: {types: [created]}}"])
    lines = [c(["name: w", "# a workflow", ""]), on]
    if rnd.random() < 0.6:
        lines.append(permissions(rnd, ""))
    lines.append("jobs:")
    for j in range(rnd.randint(1, 3)):
        if rnd.random() < 0.2:
            lines.append(f"  j{j}:\n    uses: {c(uses())}")
            continue
        lines.append(f"  j{j}:")
        lines.append("    runs-on: ubuntu-latest")
        if rnd.random() < 0.4:
            lines.append(permissions(rnd, "    "))
        lines.append("    steps:")
        for _ in range(rnd.randint(1, 5)):
            k = rnd.randrange(5)
            if k in (0, 1):
                lines.append("      - uses: " + c(uses()))
                w = withs(rnd)
                if w:
                    lines.append("        with:\n" + "\n".join("          " + x for x in w))
            elif k == 2:
                lines.append("      - run: " + c(RUNS))
            elif k == 3:
                lines.append("      - name: s\n        run: " + c(["|", ">-"]) + "\n          " + c(RUNS) + "\n          " + c(RUNS))
            else:
                lines.append("      - name: n\n        uses: " + c(uses()) + "\n        with:\n          " + c(withs(rnd) or ["a: b"]))
    return "\n".join(lines) + "\n"


def corpus(seed=20261003, count=1500):
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(count):
        text = workflow(rnd)
        if rnd.random() < 0.2:                   # cut: malformed files
            k = rnd.randrange(len(text) + 1)
            text = text[:k] + rnd.choice(["", "\n  - ", ": ", "{", "'", "\t"]) + text[k + rnd.randrange(4):]
        cases.append(text)
    return [json.loads(json.dumps(c)) for c in cases]


def core(text):
    found = ghworkflow.hardening(text)
    return [[list(f) for f in found], [ghworkflow.hardening_rule(k, d) for k, _line, d in found]]


@unittest.skipUnless(NODE, "node is not installed")
class HardeningParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.texts = corpus()
        p = subprocess.run([NODE, "--input-type=module", "-e", NPM, LIB], input=json.dumps(cls.texts),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        if p.returncode:
            raise AssertionError(f"node exited {p.returncode}: {p.stderr[-2000:]}")
        cls.npm = json.loads(p.stdout)

    def test_findings_and_rules(self):
        bad = []
        for text, got in zip(self.texts, self.npm["cases"]):
            want = json.loads(json.dumps(core(text)))
            if want != got:
                bad.append((text[:400], want, got))
        self.assertEqual(bad[:3], [])
        kinds = [f[0] for found, _rules in self.npm["cases"] for f in found]
        for kind in ("unpinned", "pr-checkout", "cache", "perms", "perms-missing", "oidc-install"):
            self.assertGreater(kinds.count(kind), 60, kind)

    def test_the_lists_and_patterns_are_cores(self):
        twins = self.npm["twins"]
        for name, src in twins["patterns"].items():
            rx = getattr(ghworkflow, name)
            self.assertEqual(src, rx.pattern, name)
            self.assertFalse(rx.flags & re.I, name)         # the twin's patterns carry no flags
        for name, value in twins["lists"].items():
            self.assertEqual(value, json.loads(json.dumps(getattr(ghworkflow, name))), name)


if __name__ == "__main__":
    unittest.main()
