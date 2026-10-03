"""GitHub workflow hardening checks (0.1.9, S-2, offline half): what
ghworkflow.hardening() reports for a workflow's text, and the rule each finding
becomes (hardening_rule). The npm twin is compared in
tests/architecture/test_js_parity_workflow_hardening.py.

Each check has the shapes it must report, the lookalikes it must not, and where
it matters the line it reports. All content is inert text.
"""
import time
import unittest

from lazaret.scanner import ghworkflow

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "cd" * 32


def wf(on="push", perms="permissions: {}", jobs=""):
    """A workflow: `jobs` is the text under `jobs:` (job bodies at two spaces)."""
    return f"on: {on}\n{perms}\njobs:\n{jobs}" if perms else f"on: {on}\njobs:\n{jobs}"


def job(name="a", steps=(), extra=""):
    """A job with `steps` (each the text after `- `, continuation lines at 8 spaces)."""
    body = f"  {name}:\n    runs-on: ubuntu-latest\n{extra}    steps:\n"
    return body + "".join(f"      - {s}\n" for s in steps)


def kinds(text):
    return [f[0] for f in ghworkflow.hardening(text)]


class UnpinnedTests(unittest.TestCase):
    def found(self, uses):
        return [f for f in ghworkflow.hardening(wf(jobs=job(steps=[f"uses: {uses}"]))) if f[0] == "unpinned"]

    def test_what_is_not_a_full_commit_sha(self):
        for uses in ("some/thing@main", "some/thing@v1", "some/thing@" + SHA[:39], "some/thing@" + SHA + "0",
                     "some/thing@" + "g" * 40, "some/thing", "some/thing@", "some/thing/sub@v2"):
            self.assertEqual(len(self.found(uses)), 1, uses)

    def test_what_is_pinned(self):
        for uses in ("some/thing@" + SHA, "some/thing/sub@" + SHA.upper(), f"docker://alpine@{DIGEST}",
                     "./local-action", "./", "../shared/action", "."):
            self.assertEqual(self.found(uses), [], uses)

    def test_the_detail(self):
        self.assertEqual(self.found("actions/checkout@v4")[0][2], {
            "uses": "actions/checkout@v4", "kind": "action", "ref": "v4", "first": True, "tag": True})
        self.assertEqual(self.found("Some/Thing@main")[0][2]["first"], False)
        self.assertEqual(self.found("GitHub/codeql-action/init@v3")[0][2]["first"], True)      # names are not case-sensitive
        self.assertEqual(self.found("docker://alpine:3")[0][2]["kind"], "docker")
        self.assertEqual(self.found("docker://alpine@sha256:abc")[0][2]["kind"], "docker")      # a digest that is not one
        self.assertEqual(self.found("org/repo/.github/workflows/w.yml@v1")[0][2]["kind"], "workflow")

    def test_a_reusable_workflow_called_by_a_job(self):
        text = wf(jobs="  call:\n    uses: org/repo/.github/workflows/w.yml@main\n  pinned:\n"
                       f"    uses: org/repo/.github/workflows/w.yml@{SHA}\n")
        self.assertEqual([(f[1], f[2]["kind"]) for f in ghworkflow.hardening(text) if f[0] == "unpinned"],
                         [(5, "workflow")])

    def test_the_line_is_the_uses_line(self):
        text = wf(jobs=job(steps=["name: a\n        uses: x/y@v1", "run: echo"]))
        self.assertEqual([f[1] for f in ghworkflow.hardening(text) if f[0] == "unpinned"], [8])

    def test_severity(self):
        rule = lambda uses: ghworkflow.hardening_rule("unpinned", self.found(uses)[0][2])
        self.assertEqual(rule("actions/checkout@v4")["sev"], "MINOR")        # GitHub's own, a version tag
        self.assertEqual(rule("actions/checkout@main")["sev"], "MAJOR")      # GitHub's own, a branch
        self.assertEqual(rule("other/thing@v4")["sev"], "MAJOR")
        self.assertEqual(rule("docker://alpine:3")["sev"], "MAJOR")
        self.assertIn("the image docker://alpine:3", rule("docker://alpine:3")["msg"])
        self.assertIn("a digest", rule("docker://alpine:3")["msg"])
        self.assertIn("the reusable workflow", rule("o/r/.github/workflows/w.yml@v1")["msg"])


class PrCheckoutTests(unittest.TestCase):
    def found(self, step, on="pull_request_target"):
        return [f for f in ghworkflow.hardening(wf(on=on, jobs=job(steps=[step]))) if f[0] == "pr-checkout"]

    def test_checkout_of_the_pull_requests_code(self):
        for with_ in ("ref: ${{ github.event.pull_request.head.sha }}", "ref: ${{ github.head_ref }}",
                      "ref: refs/pull/${{ github.event.number }}/merge", "ref: ${{ github.event.pull_request.head.ref }}",
                      "repository: ${{ github.event.pull_request.head.repo.full_name }}"):
            step = f"uses: actions/checkout@{SHA}\n        with:\n          {with_}"
            self.assertEqual(len(self.found(step)), 1, with_)

    def test_the_detail_and_the_line(self):
        step = f"uses: actions/checkout@{SHA}\n        with:\n          fetch-depth: 0\n          ref: ${{{{ github.head_ref }}}}"
        self.assertEqual(self.found(step), [("pr-checkout", 10, {"job": "a", "via": "with ref", "expr": "github.head_ref"})])

    def test_a_command_that_fetches_it(self):
        for run in ("git checkout ${{ github.event.pull_request.head.sha }}", "git fetch origin refs/pull/1/head",
                    "git fetch origin pull/${{ github.event.pull_request.number }}/head:pr", "git fetch origin pull/7/merge",
                    "gh pr checkout ${{ github.event.pull_request.number }}", "gh pr checkout 12",
                    "git switch ${{ github.head_ref }}"):
            self.assertEqual(len(self.found(f"run: {run}")), 1, run)
        self.assertEqual(self.found("run: git checkout ${{ github.head_ref }}")[0][2]["via"], "a command")
        self.assertEqual(self.found("run: gh pr checkout 12")[0][2]["expr"], "gh pr checkout")
        self.assertEqual(self.found("run: |\n          git checkout main\n          git merge ${{ github.head_ref }}")[0][1], 9)

    def test_not_the_pull_request(self):
        self.assertEqual(self.found(f"uses: actions/checkout@{SHA}"), [])
        self.assertEqual(self.found(f"uses: actions/checkout@{SHA}\n        with:\n          ref: main"), [])
        self.assertEqual(self.found("run: git checkout main"), [])
        self.assertEqual(self.found("run: echo ${{ github.head_ref }}"), [])    # only a command that fetches the code
        self.assertEqual(self.found("run: git fetch origin main"), [])
        self.assertEqual(self.found("run: gh pr view 12"), [])

    def test_only_on_pull_request_target(self):
        step = f"uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.event.pull_request.head.sha }}}}"
        self.assertEqual(self.found(step, on="pull_request"), [])
        self.assertEqual(len(self.found(step, on="[push, pull_request_target]")), 1)

    def test_each_step_is_reported_at_its_line(self):
        text = wf(on="pull_request_target", jobs=job(steps=[
            f"uses: actions/checkout@{SHA}\n        with:\n          ref: ${{{{ github.head_ref }}}}",
            "run: git checkout ${{ github.head_ref }}"]))
        self.assertEqual([(f[1], f[2]["via"]) for f in ghworkflow.hardening(text) if f[0] == "pr-checkout"],
                         [(9, "with ref"), (10, "a command")])

    def test_the_rule_is_critical(self):
        hit = self.found("run: git pull origin refs/pull/1/head")[0][2]
        self.assertEqual(ghworkflow.hardening_rule("pr-checkout", hit)["sev"], "CRITICAL")


class CacheTests(unittest.TestCase):
    def found(self, step, on="push", perms="permissions: {}"):
        return [f for f in ghworkflow.hardening(wf(on=on, perms=perms, jobs=job(steps=[step]))) if f[0] == "cache"]

    def test_a_cache_in_a_release(self):
        hits = self.found("uses: actions/cache@v4\n        with:\n          path: x", on="release")
        self.assertEqual(hits, [("cache", 7, {"job": "a", "what": "actions/cache", "explicit": True,
                                              "why": "it runs when a release is published"})])

    def test_the_cache_actions(self):
        for uses in ("actions/cache", "actions/cache/restore", "Swatinem/rust-cache"):
            self.assertEqual(len(self.found(f"uses: {uses}@v1", on="release")), 1, uses)
        self.assertEqual(self.found("uses: actions/cache-something@v1", on="release"), [])

    def test_a_setup_action_that_caches(self):
        self.assertEqual(self.found("uses: actions/setup-node@v4\n        with:\n          cache: npm", on="release")[0][2]["what"],
                         "actions/setup-node with cache: npm")
        self.assertEqual(self.found("uses: ruby/setup-ruby@v1\n        with:\n          bundler-cache: true", on="release")[0][2]["explicit"],
                         True)
        # on unless it is turned off
        self.assertEqual(self.found("uses: actions/setup-go@v5", on="release")[0][2]["explicit"], False)
        self.assertEqual(self.found("uses: astral-sh/setup-uv@v5", on="release")[0][2]["explicit"], False)
        self.assertEqual(self.found("uses: actions/setup-go@v5\n        with:\n          cache: false", on="release"), [])
        self.assertEqual(self.found("uses: astral-sh/setup-uv@v5\n        with:\n          enable-cache: false", on="release"), [])
        # setup-node may cache by itself
        self.assertEqual(self.found("uses: actions/setup-node@v4", on="release")[0][2]["explicit"], False)
        self.assertEqual(self.found("uses: actions/setup-node@v4\n        with:\n          package-manager-cache: false",
                                    on="release"), [])
        # off unless asked for
        self.assertEqual(self.found("uses: actions/setup-python@v5", on="release"), [])
        self.assertEqual(self.found("uses: actions/setup-python@v5\n        with:\n          cache: ''", on="release"), [])

    def test_what_makes_a_workflow_a_release(self):
        cache = "uses: actions/cache@v4"
        self.assertEqual(self.found(cache), [])                                           # a plain build
        self.assertEqual(self.found(cache, on="pull_request"), [])
        self.assertEqual(self.found(cache, perms="permissions:\n  id-token: write")[0][2]["why"], "it asks for an OIDC token")
        self.assertEqual(self.found(cache, perms="permissions: {id-token: write}")[0][2]["why"], "it asks for an OIDC token")
        self.assertEqual(self.found(cache, perms="permissions:\n  contents: write"), [])          # write alone is not a release
        for step, why in (("run: npm publish --provenance", "it runs `npm publish`"),
                          ("run: twine upload dist/*", "it runs `twine upload`"),
                          (f"uses: pypa/gh-action-pypi-publish@{SHA}", "it uses pypa/gh-action-pypi-publish")):
            text = wf(jobs=job(steps=[cache, step]))
            self.assertEqual([f[2]["why"] for f in ghworkflow.hardening(text) if f[0] == "cache"], [why], step)

    def test_an_oidc_grant_in_a_job_makes_a_release(self):
        text = wf(jobs=job(steps=["uses: actions/cache@v4"], extra="    permissions:\n      id-token: write\n"))
        self.assertEqual(len([f for f in ghworkflow.hardening(text) if f[0] == "cache"]), 1)

    def test_severity(self):
        hits = self.found("uses: actions/setup-go@v5", on="release")
        self.assertEqual(ghworkflow.hardening_rule("cache", hits[0][2])["sev"], "MINOR")
        hits = self.found("uses: actions/cache@v4", on="release")
        self.assertEqual(ghworkflow.hardening_rule("cache", hits[0][2])["sev"], "MAJOR")


class PermissionTests(unittest.TestCase):
    def found(self, text):
        return [f for f in ghworkflow.hardening(text) if f[0] in ("perms", "perms-missing")]

    def test_write_for_every_job(self):
        self.assertEqual(self.found(wf(perms="permissions:\n  contents: write\n  pull-requests: write", jobs=job())),
                         [("perms", 3, {"scopes": ["contents", "pull-requests"]})])
        self.assertEqual(self.found(wf(perms="permissions: write-all", jobs=job())), [("perms", 2, {"scopes": ["all"]})])
        self.assertEqual(self.found(wf(perms="permissions: {contents: write, id-token: write, packages: read}", jobs=job())),
                         [("perms", 2, {"scopes": ["contents", "id-token"]})])

    def test_read_only_and_empty_are_fine(self):
        for perms in ("permissions: read-all", "permissions: {}", "permissions:\n  contents: read",
                      "permissions: {contents: read}", "permissions:\n  contents: none"):
            self.assertEqual(self.found(wf(perms=perms, jobs=job())), [], perms)

    def test_a_job_with_its_own_write_is_the_right_shape(self):
        text = wf(jobs=job("build") + job("release", extra="    permissions:\n      contents: write\n"))
        self.assertEqual(self.found(text), [])

    def test_no_permissions_at_the_top(self):
        text = wf(perms="", jobs=job("a") + job("b", extra="    permissions: read-all\n") + job("c"))
        self.assertEqual(self.found(text), [("perms-missing", 2, {"jobs": ["a", "c"]})])
        self.assertEqual(self.found(wf(perms="", jobs=job("a", extra="    permissions: {}\n"))), [])
        self.assertEqual(self.found("on: push\n"), [])                       # no jobs, nothing to say
        self.assertEqual(self.found("name: x\n"), [])

    def test_the_rules(self):
        d = {"scopes": ["all", "contents"]}
        self.assertIn("(write-all, contents)", ghworkflow.hardening_rule("perms", d)["msg"])
        many = ghworkflow.hardening_rule("perms-missing", {"jobs": ["a", "b", "c", "d", "e"]})["msg"]
        self.assertIn('"a", "b", "c" and 2 more', many)
        self.assertIn('the job "a" has none', ghworkflow.hardening_rule("perms-missing", {"jobs": ["a"]})["msg"])
        self.assertEqual(ghworkflow.hardening_rule("perms", d)["id"],
                         ghworkflow.hardening_rule("perms-missing", {"jobs": ["a"]})["id"])


class OidcInstallTests(unittest.TestCase):
    def found(self, text):
        return [f for f in ghworkflow.hardening(text) if f[0] == "oidc-install"]

    def test_the_workflows_token_and_an_install(self):
        text = wf(perms="permissions:\n  id-token: write", jobs=job(steps=["run: npm ci", "run: npm publish"]))
        self.assertEqual(self.found(text), [("oidc-install", 8, {"job": "a", "from": "workflow", "command": "npm ci"})])

    def test_a_jobs_own_permissions_replace_the_workflows(self):
        text = wf(perms="permissions:\n  id-token: write", jobs=job("a", steps=["run: npm ci"],
                                                                     extra="    permissions:\n      contents: read\n"))
        self.assertEqual(self.found(text), [])
        text = wf(perms="permissions: read-all", jobs=job("a", steps=["run: pip install x"],
                                                           extra="    permissions: {id-token: write}\n"))
        self.assertEqual(self.found(text), [("oidc-install", 8, {"job": "a", "from": "job", "command": "pip install"})])

    def test_every_installer(self):
        for cmd, name in (("npm install", "npm install"), ("npm i left-pad", "npm i"), ("pnpm add x", "pnpm add"),
                          ("yarn", "yarn"), ("yarn install --immutable", "yarn install"), ("bun install", "bun install"),
                          ("pip3 install -r r.txt", "pip3 install"), ("python -m pip install x", "python -m pip install"),
                          ("uv sync", "uv sync"), ("poetry install", "poetry install"), ("bundle install", "bundle install"),
                          ("cargo build --release", "cargo build"), ("go mod download", "go mod download"),
                          ("echo a && npm ci", "npm ci"), ("(npm ci)", "npm ci"), ("make; npm ci;", "npm ci"),
                          ("CI=true npm ci", "npm ci"), ("A=1 B=x/y npm ci", "npm ci"), ("sudo pip install x", "pip install"),
                          ("if true; then npm ci; fi", "npm ci"), ("x=$(npm ci)", "npm ci"), ("a | yarn", "yarn")):
            text = wf(perms="permissions:\n  id-token: write", jobs=job(steps=[f"run: {cmd}"]))
            self.assertEqual([f[2]["command"] for f in self.found(text)], [name], cmd)

    def test_not_an_install(self):
        for cmd in ("npm ci --ignore-scripts", "npm test", "npm run build", "echo npm ci", "yarnpkg", "pip list",
                    "cargo test", "go test ./...", "npm publish", "my-npm install", "git commit -m 'npm ci'",
                    "echo do not npm install", "FOO=\"a b\" echo x"):
            text = wf(perms="permissions:\n  id-token: write", jobs=job(steps=[f"run: {cmd}"]))
            self.assertEqual(self.found(text), [], cmd)

    def test_without_the_token_nothing(self):
        self.assertEqual(self.found(wf(perms="permissions:\n  contents: write", jobs=job(steps=["run: npm ci"]))), [])
        self.assertEqual(self.found(wf(perms="permissions:\n  id-token: read", jobs=job(steps=["run: npm ci"]))), [])

    def test_another_job_installs(self):
        text = wf(perms="permissions: {}", jobs=job("build", steps=["run: npm ci"])
                  + job("publish", steps=["run: npm publish"], extra="    permissions:\n      id-token: write\n"))
        self.assertEqual(self.found(text), [])

    def test_a_multi_line_script_reports_the_line(self):
        text = wf(perms="permissions:\n  id-token: write",
                  jobs=job(steps=["name: b\n        run: |\n          echo a\n          npm ci\n          echo b"]))
        self.assertEqual(self.found(text)[0][1], 11)


class QuietTests(unittest.TestCase):
    def test_a_workflow_that_does_everything_right(self):
        text = (f"on:\n  pull_request:\n  push:\n    branches: [main]\npermissions:\n  contents: read\njobs:\n  test:\n"
                f"    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{SHA} # v4.1.1\n"
                f"        with:\n          persist-credentials: false\n      - run: npm ci --ignore-scripts\n      - run: npm test\n"
                f"  release:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write\n"
                f"    steps:\n      - uses: actions/download-artifact@{SHA}\n      - run: npm publish dist.tgz\n")
        self.assertEqual(ghworkflow.hardening(text), [])

    def test_not_yaml_and_cut_files(self):
        for text in ("", "\n\n", "{}", "[", "jobs:", "jobs:\n  a:", "steps:\n  - uses", "jobs:\n  a:\n    steps:\n      -\n",
                     "\t\tjobs:\n", "\ufeffon: push\n"):
            ghworkflow.hardening(text)                                   # no exception

    def test_the_findings_are_by_line(self):
        text = wf(perms="permissions: write-all", jobs=job(steps=["uses: a/b@v1", "run: npm ci", "uses: c/d@main"]))
        lines = [f[1] for f in ghworkflow.hardening(text)]
        self.assertEqual(lines, sorted(lines))

    def test_the_worm_findings_do_not_include_these(self):
        # findings() keeps its two kinds: the hardening kinds come only from hardening()
        text = wf(on="issues", perms="permissions: write-all", jobs=job(steps=["uses: a/b@v1", "run: npm ci"],
                                                                         extra="    env:\n      D: ${{ toJSON(secrets) }}\n"))
        self.assertEqual({f[0] for f in ghworkflow.findings(text)}, {"secrets"})
        self.assertEqual({"perms", "unpinned", "oidc-install"}, {f[0] for f in ghworkflow.hardening(text)})   # write-all grants the token


class RuleTests(unittest.TestCase):
    CASES = {
        "unpinned": {"uses": "a/b@v1", "kind": "action", "ref": "v1", "first": False, "tag": True},
        "pr-checkout": {"job": "a", "via": "with ref", "expr": "github.head_ref"},
        "cache": {"job": "a", "what": "actions/cache", "explicit": True, "why": "it runs when a release is published"},
        "perms": {"scopes": ["contents"]},
        "perms-missing": {"jobs": ["a"]},
        "oidc-install": {"job": "a", "from": "job", "command": "npm ci"},
    }

    def test_each_rule_has_what_mk_issue_takes(self):
        ids = set()
        for kind, detail in self.CASES.items():
            rule = ghworkflow.hardening_rule(kind, detail)
            self.assertEqual(sorted(rule), ["fix", "id", "msg", "name", "ref", "sev", "type", "why"], kind)
            self.assertTrue(rule["id"].startswith("SC-WORKFLOW-"), kind)
            self.assertEqual(rule["type"], "HOTSPOT")
            self.assertIn(rule["sev"], ("MINOR", "MAJOR", "CRITICAL"))
            self.assertTrue(all(isinstance(rule[k], str) and rule[k] for k in ("msg", "why", "fix", "name", "ref")), kind)
            ids.add(rule["id"])
        self.assertEqual(ids, {"SC-WORKFLOW-UNPINNED", "SC-WORKFLOW-PR-CHECKOUT", "SC-WORKFLOW-CACHE",
                               "SC-WORKFLOW-PERMISSIONS", "SC-WORKFLOW-OIDC-INSTALL"})

    def test_the_messages_name_what_was_found(self):
        self.assertIn("a/b@v1", ghworkflow.hardening_rule("unpinned", self.CASES["unpinned"])["msg"])
        self.assertIn("github.head_ref", ghworkflow.hardening_rule("pr-checkout", self.CASES["pr-checkout"])["msg"])
        self.assertIn("actions/cache", ghworkflow.hardening_rule("cache", self.CASES["cache"])["msg"])
        self.assertIn("`npm ci`", ghworkflow.hardening_rule("oidc-install", self.CASES["oidc-install"])["msg"])
        self.assertIn("its own permissions", ghworkflow.hardening_rule("oidc-install", self.CASES["oidc-install"])["msg"])
        self.assertIn("the workflow permissions", ghworkflow.hardening_rule(
            "oidc-install", dict(self.CASES["oidc-install"], **{"from": "workflow"}))["msg"])


class LinearTimeTests(unittest.TestCase):
    """A workflow is attacker-controlled text: the checks must take time in proportion to its size."""

    def timed(self, text):
        start = time.perf_counter()
        ghworkflow.hardening(text)
        return time.perf_counter() - start

    def test_many_jobs(self):
        def many(n):
            return ("on: push\npermissions:\n  id-token: write\njobs:\n" + "".join(
                f"  j{i}:\n    runs-on: x\n    permissions:\n      contents: read\n    steps:\n"
                f"      - uses: a/b@v1\n      - run: npm ci --ignore-scripts\n" for i in range(n)))
        self.assertLess(self.timed(many(8000)), 3.0)

    def test_many_steps_and_long_lines(self):
        steps = "".join(f"      - uses: a/b{i}@v1\n        with:\n          cache: npm\n      - run: npm ci; npm ci\n"
                         for i in range(8000))
        self.assertLess(self.timed("on: release\npermissions: {}\njobs:\n  a:\n    runs-on: x\n    steps:\n" + steps), 3.0)
        for run in ("git " + " " * 200_000 + "x", "npm " * 50_000, "yarn" + " " * 200_000, ";" * 200_000 + "pip",
                    "${{ github.head_ref " * 20_000, "git checkout " * 20_000, ";a=b" * 50_000, "a=b " * 50_000 + "x",
                    ";" + "a=b;" * 50_000 + "npm", "then " * 50_000, "pull/" * 50_000, "gh pr " * 50_000):
            text = f"on: pull_request_target\npermissions:\n  id-token: write\njobs:\n  a:\n    steps:\n      - run: {run}\n"
            self.assertLess(self.timed(text), 3.0, run[:20])


if __name__ == "__main__":
    unittest.main()
