"""Engine parity for the GitLab CI checks (0.1.9, S-3): the npm engine's js/src/lib/gitlabci.js
`hardening` and `hardeningRule` against lazaret.scanner.gitlabci.hardening and hardening_rule.

Compared case by case in one node process, on curated pipelines and on seeded random ones built from
the forms each part takes: includes as a block list, a single map, a string, a flow list and a flow
map (local files, remote URLs over https and http, a project's file at a branch, a tag, a commit, no
ref or a variable, components at a version, a latest version, a commit and a branch); images as a
string, a map and a flow map, services as strings, maps and flows, with and without a digest;
scripts as lists, block scalars, strings and flow lists, in `before_script`, `script` and
`after_script`, in jobs, in `default:`, at the top of the file and in lists under hidden keys;
`id_tokens:`, `secrets:` and registry token variables; commands that install, fetch and run, and
ones that put a merge request's text in `eval` and `sh -c`. The rule each finding becomes is
compared too, and so are the helpers on their own (mr_text, parse_image, flow_items, the outline
with block scalars in lists, is_gitlab_ci); the pattern text the twin keeps is checked to be the
Python module's own.

All content is inert text: hosts are .invalid, and nothing is executed. Skipped where node is
missing.
"""
import json
import random
import re
import subprocess
import unittest

from lazaret.scanner import ghworkflow, gitlabci
from tests.architecture import test_js_parity as parity
from tests.architecture.test_js_parity_persistence import LIB
from tests.architecture.test_js_parity_workflow_hardening import PIPES, RUNS
from tests.scanner.test_gitlabci import ADVERSARIAL

NODE = parity.NODE
NPM = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const g = await import(pathToFileURL(process.argv[1] + "/gitlabci.js").href);
const w = await import(pathToFileURL(process.argv[1] + "/ghworkflow.js").href);
const a = JSON.parse(readFileSync(0, "utf8"));
const plain = (x) => (x instanceof Map ? Object.fromEntries(x) : x);
const out = {
  twins: g.GITLAB_TWINS,
  cases: a.texts.map((t) => { const found = g.hardening(t); return [found, found.map(([k, , d]) => g.hardeningRule(k, d))]; }),
  records: a.texts.map((t) => w.yamlRecords(t, true, true)),
  mr: a.lines.map((l) => g.mrText(l)),
  images: a.images.map((v) => g.parseImage(v)),
  flows: a.flows.map((v) => g.flowItems(v).map(plain)),
  paths: a.paths.map((p) => g.isGitlabCi(p)),
};
process.stdout.write(JSON.stringify(out));
"""
TIMING = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const g = await import(pathToFileURL(process.argv[1] + "/gitlabci.js").href);
const texts = JSON.parse(readFileSync(0, "utf8"));
const times = texts.map((t) => { const start = performance.now(); g.hardening(t); return performance.now() - start; });
process.stdout.write(JSON.stringify(times));
"""

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "ab" * 32

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


SCRIPT_KEYS = gitlabci.SCRIPT_KEYS


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


CURATED = [
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


def corpus(seed=20261004, count=1200):
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(count):
        text = pipeline(rnd)
        if rnd.random() < 0.2:                   # cut: malformed files
            k = rnd.randrange(len(text) + 1)
            text = text[:k] + rnd.choice(["", "\n  - ", ": ", "{", "'", "\t", "\"", "["]) + text[k + rnd.randrange(4):]
        if rnd.random() < 0.15:                  # Windows line ends
            text = text.replace("\n", "\r\n")
        cases.append(text)
    return [json.loads(json.dumps(c)) for c in cases]


def core(text):
    found = gitlabci.hardening(text)
    return [[list(f) for f in found], [gitlabci.hardening_rule(k, d) for k, _line, d in found]]


@unittest.skipUnless(NODE, "node is not installed")
class GitlabParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.texts = corpus()
        cls.lines = sorted(set(COMMANDS + PIPES))
        cls.images = IMAGES + ["", "a@", "@b", ":", "a:b:c", "a/b:c/d", "host:1/x", "host:1/x:2@sha256:ab", "x:"]
        cls.flows = FLOWS
        args = {"texts": cls.texts, "lines": cls.lines, "images": cls.images, "flows": cls.flows, "paths": PATHS}
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
        for kind in ("include-remote", "include-project", "include-component", "image", "pipe-to-shell", "mr-text", "token-install"):
            self.assertGreater(kinds.count(kind), 80, kind)

    def test_the_outline_with_block_scalars_in_lists(self):
        for text, got in zip(self.texts, self.npm["records"]):
            self.assertEqual(json.loads(json.dumps(ghworkflow.records(text, True, True))), got, text[:300])

    def test_mr_text(self):
        want = [gitlabci.mr_text(t) for t in self.lines]
        self.assertEqual(json.loads(json.dumps(want)), self.npm["mr"])
        self.assertGreater(sum(w is not None for w in want), 12)
        self.assertGreater(sum(w is None for w in want), 12)

    def test_parse_image(self):
        self.assertEqual(json.loads(json.dumps([gitlabci.parse_image(v) for v in self.images])), self.npm["images"])

    def test_flow_items(self):
        self.assertEqual([gitlabci.flow_items(v) for v in self.flows], self.npm["flows"])

    def test_is_gitlab_ci(self):
        self.assertEqual([gitlabci.is_gitlab_ci(p) for p in PATHS], self.npm["paths"])

    def test_the_patterns_are_cores(self):
        twins = self.npm["twins"]
        for name, src in twins["patterns"].items():
            rx = getattr(gitlabci, name)
            self.assertEqual(src, rx.pattern, name)
            self.assertFalse(rx.flags & (re.I | re.M | re.S | re.X), name)
        for name, value in twins["lists"].items():
            self.assertEqual(value, json.loads(json.dumps(getattr(gitlabci, name))), name)

    def test_hostile_files_are_read_in_linear_time(self):
        texts = list(ADVERSARIAL())
        p = subprocess.run([NODE, "--input-type=module", "-e", TIMING, LIB], input=json.dumps(texts),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr[-1000:])
        slow = [(texts[i][:24], round(t)) for i, t in enumerate(json.loads(p.stdout)) if t > 3000]
        self.assertEqual(slow, [])


if __name__ == "__main__":
    unittest.main()
