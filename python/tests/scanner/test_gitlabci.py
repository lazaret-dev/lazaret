"""GitLab CI checks (0.1.9, S-3): what gitlabci.hardening() reports for a `.gitlab-ci.yml`'s text, and
the rule each finding becomes (hardening_rule). The npm twin is compared in
tests/architecture/test_js_parity_gitlabci.py.

Each check has the shapes it must report, the lookalikes it must not, and where it matters the line it
reports. All content is inert text: hosts are .invalid.
"""
import time
import unittest

from lazaret.scanner import gitlabci

SHA = "0123456789abcdef0123456789abcdef01234567"
DIGEST = "sha256:" + "cd" * 32


def found(text, *kinds):
    return [f for f in gitlabci.hardening(text) if not kinds or f[0] in kinds]


def kinds(text):
    return [f[0] for f in gitlabci.hardening(text)]


def include(*items):
    return "include:\n" + "".join(f"  - {i}\n" for i in items)


def job(script, name="build", extra=""):
    return f"{name}:\n{extra}  script:\n" + "".join(f"    - {s}\n" for s in script)


class IncludeTests(unittest.TestCase):
    def test_a_remote_file(self):
        f = found(include("remote: 'https://x.invalid/ci.yml'"))
        self.assertEqual([(x[0], x[1], x[2]) for x in f], [("include-remote", 2, {"url": "https://x.invalid/ci.yml", "http": False})])
        self.assertEqual(found(include("remote: http://x.invalid/ci.yml"))[0][2]["http"], True)
        self.assertEqual(found(include("HTTP://X.INVALID/c.yml"))[0][2]["http"], True)           # a bare URL is a remote file

    def test_every_form_of_include(self):
        url = "https://x.invalid/ci.yml"
        for text in (f"include: '{url}'\n", f"include:\n  remote: {url}\n", f"include: {{remote: '{url}'}}\n",
                     f"include: [{{remote: '{url}'}}, local.yml]\n", include(f"remote: \"{url}\"", "local: /a.yml"),
                     f"include:\n  - local: /a.yml\n  - {url}\n"):
            self.assertEqual([x[0] for x in found(text)], ["include-remote"], text)

    def test_local_files_and_templates_are_not(self):
        for text in (include("local: '/ci/a.yml'", "template: Security/SAST.gitlab-ci.yml"), "include: local.yml\n",
                     "include: ci/other.yml\n", "include:\n  - /ci/a.yml\n", "include: []\n", "include:\n"):
            self.assertEqual(found(text), [], text)

    def test_a_project_at_a_branch_a_tag_or_nothing(self):
        def f(ref):
            body = f"project: g/p\n    ref: {ref}\n    file: /a.yml" if ref is not None else "project: g/p\n    file: /a.yml"
            return found(include(body))
        self.assertEqual(f("main")[0][2], {"project": "g/p", "ref": "main", "tag": False})
        self.assertEqual(f("v1.2")[0][2], {"project": "g/p", "ref": "v1.2", "tag": True})
        self.assertEqual(f(None)[0][2], {"project": "g/p", "ref": "", "tag": False})
        self.assertEqual(f(SHA[:39])[0][0], "include-project")                                  # not a full SHA
        self.assertEqual(f(SHA + "0")[0][0], "include-project")
        self.assertEqual(f("$CI_COMMIT_REF_NAME")[0][0], "include-project")                    # a branch's name is not a pin

    def test_a_project_at_a_commit_is_pinned(self):
        for ref in (SHA, SHA.upper(), "$CI_COMMIT_SHA", "${CI_COMMIT_SHA}"):
            self.assertEqual(found(include(f"project: g/p\n    ref: {ref}\n    file: /a.yml")), [], ref)

    def test_the_ref_may_come_before_the_project(self):
        text = include("ref: main\n    project: g/p")
        self.assertEqual(found(text)[0][2]["project"], "g/p")

    def test_a_components_version(self):
        def f(version):
            return found(include(f"component: gitlab.com/g/p/c@{version}"))
        self.assertEqual(f("1.2.3")[0][2], {"component": "gitlab.com/g/p/c", "ref": "1.2.3", "exact": True})
        self.assertEqual(f("v2.0.1-rc.1")[0][2]["exact"], True)
        for version in ("~latest", "main", "1", "1.2", "1.2.3.4", "", "1.2.x"):
            self.assertEqual(f(version)[0][2]["exact"], False, version)
        self.assertEqual(f(SHA), [])
        self.assertEqual(found(include("component: gitlab.com/g/p/c"))[0][2]["ref"], "")

    def test_the_single_map_form_is_one_item(self):
        text = "include:\n  project: g/p\n  ref: main\n  file: /a.yml\n"
        self.assertEqual([(f[0], f[1], f[2]) for f in found(text)], [("include-project", 2, {"project": "g/p", "ref": "main", "tag": False})])
        self.assertEqual(found(f"include:\n  project: g/p\n  ref: {SHA}\n  file: /a.yml\n"), [])
        self.assertEqual(found("include:\n  project: g/p\n  ref: main\n  ref: other\n")[0][2]["ref"], "main")     # the first key counts

    def test_an_item_keeps_its_first_key(self):
        text = "include:\n  - project: g/p\n    ref: main\n    ref: v1\n"
        self.assertEqual(found(text)[0][2]["ref"], "main")

    def test_two_include_keys_are_both_read(self):
        text = "include:\n  remote: https://a.invalid/x.yml\ninclude:\n  remote: https://b.invalid/y.yml\n"
        self.assertEqual([f[2]["url"] for f in found(text)], ["https://a.invalid/x.yml", "https://b.invalid/y.yml"])
        text = "include:\n  - remote: https://a.invalid/x.yml\ninclude:\n  - remote: https://b.invalid/y.yml\n"
        self.assertEqual(len(found(text)), 2)

    def test_the_line_is_the_items(self):
        text = include("local: a.yml", "project: g/p\n    ref: main\n    file: x.yml", "component: g/p/c@main")
        self.assertEqual([(f[0], f[1]) for f in found(text)], [("include-project", 3), ("include-component", 6)])

    def test_flow_style_items(self):
        text = f"include: [{{project: g/p, ref: main, file: x}}, {{component: gitlab.com/g/p/c@1.0.0}}, {{project: g/q, ref: '{SHA}'}}]\n"
        self.assertEqual([(f[0], f[2].get("project") or f[2].get("component")) for f in found(text)],
                         [("include-component", "gitlab.com/g/p/c"), ("include-project", "g/p")])       # one line: by kind

    def test_severity(self):
        sev = lambda d, k: gitlabci.hardening_rule(k, d)["sev"]
        self.assertEqual(sev({"url": "u", "http": False}, "include-remote"), "MAJOR")
        self.assertEqual(sev({"url": "u", "http": True}, "include-remote"), "CRITICAL")
        self.assertEqual(sev({"project": "p", "ref": "v1", "tag": True}, "include-project"), "MINOR")
        self.assertEqual(sev({"project": "p", "ref": "main", "tag": False}, "include-project"), "MAJOR")
        self.assertEqual(sev({"component": "c", "ref": "1.2.3", "exact": True}, "include-component"), "MINOR")
        self.assertEqual(sev({"component": "c", "ref": "~latest", "exact": False}, "include-component"), "MAJOR")


class ImageTests(unittest.TestCase):
    def test_what_is_not_pinned(self):
        for image in ("python:3.12", "python:latest", "python", "node:20-alpine", "ghcr.io/x/y:v1",
                      "registry.example.invalid:5000/team/app", "python:3.12@sha256:xyz", f"python:3.12@{DIGEST[:-1]}"):
            f = found(f"image: {image}\n", "image")
            self.assertEqual(len(f), 1, image)

    def test_what_is_pinned(self):
        for image in (f"python:3.12@{DIGEST}", f"python@{DIGEST}", f"registry.example.invalid:5000/x@{DIGEST}",
                      "$CI_REGISTRY_IMAGE:latest", "${CI_REGISTRY_IMAGE}/app:$CI_COMMIT_SHA"):
            self.assertEqual(found(f"image: {image}\n", "image"), [], image)

    def test_the_forms(self):
        for text in ("build:\n  image: python:3.12\n", "build:\n  image:\n    name: python:3.12\n    entrypoint: ['']\n",
                     "build:\n  image: {name: python:3.12, entrypoint: ['']}\n", "default:\n  image: python:3.12\n",
                     "image:\n  name: python:3.12\n"):
            self.assertEqual([f[0] for f in found(text)], ["image"], text)

    def test_services(self):
        text = "build:\n  services:\n    - postgres:16\n    - name: redis:7\n      alias: cache\n  script: [x]\n"
        self.assertEqual([(f[1], f[2]["image"], f[2]["where"]) for f in found(text)],
                         [(3, "postgres:16", "service"), (4, "redis:7", "service")])
        self.assertEqual([f[2]["image"] for f in found("build:\n  services: [postgres:16, {name: redis:7}]\n")],
                         ["postgres:16", "redis:7"])

    def test_the_detail(self):
        d = found("build:\n  image: node:20\n")[0][2]
        self.assertEqual(d, {"job": "build", "image": "node:20", "where": "image", "tag": "20", "official": True})
        self.assertEqual(found("build:\n  image: me/app\n")[0][2], {
            "job": "build", "image": "me/app", "where": "image", "tag": "", "official": False})

    def test_severity(self):
        def sev(image):
            f = found(f"image: {image}\n", "image")[0]
            return gitlabci.hardening_rule(f[0], f[2])["sev"]
        self.assertEqual(sev("python:3.12"), "MINOR")                        # an official image at a version
        self.assertEqual(sev("python:latest"), "MAJOR")
        self.assertEqual(sev("python"), "MAJOR")
        self.assertEqual(sev("me/app:1.0"), "MAJOR")

    def test_a_variable_in_a_key_named_image_is_not_an_image(self):
        self.assertEqual(found("variables:\n  image: python:3\nbuild:\n  variables:\n    image: python:3\n  script: [x]\n"), [])

    def test_not_images(self):
        self.assertEqual(found("build:\n  script:\n    - docker run python:3.12\n"), [])
        self.assertEqual(found("build:\n  image:\n"), [])


class PipeToShellTests(unittest.TestCase):
    def test_in_every_section_and_form(self):
        line = "curl -fsSL https://x.invalid/i.sh | sh"
        for text in (job([line]), f"build:\n  before_script:\n    - {line}\n", f"build:\n  after_script:\n    - {line}\n",
                     f"build:\n  script: {line}\n", f"build:\n  script: [\"{line}\"]\n", f"build:\n  script:\n    - |\n      echo a\n      {line}\n",
                     f"default:\n  before_script:\n    - {line}\n", f"before_script:\n  - {line}\n", f".setup: &setup\n  - {line}\n"):
            self.assertEqual([f[0] for f in found(text)], ["pipe-to-shell"], text)

    def test_the_line_and_the_job(self):
        text = job(["echo a", "wget -qO- https://x.invalid | sudo bash"], name="deploy")
        self.assertEqual([(f[1], f[2]["job"], f[2]["command"]) for f in found(text)], [(4, "deploy", "wget … | bash")])

    def test_a_job_is_reported_once(self):
        self.assertEqual(len(found(job(["curl a.invalid | sh", "curl b.invalid | sh"]))), 1)

    def test_one_per_job(self):
        text = job(["curl a.invalid | sh"], "a") + job(["curl b.invalid | sh"], "b")
        self.assertEqual([f[2]["job"] for f in found(text)], ["a", "b"])

    def test_what_is_read_first(self):
        self.assertEqual(found(job(["curl -o i.sh https://x.invalid", "sha256sum -c i.sum", "sh i.sh", "curl x.invalid | jq ."])), [])

    def test_a_continued_line_in_a_block(self):
        text = "build:\n  script:\n    - |\n      curl -fsSL https://x.invalid \\\n        | sh\n"
        self.assertEqual([(f[0], f[1]) for f in found(text)], [("pipe-to-shell", 4)])

    def test_a_line_with_a_colon_and_a_space_is_still_read(self):
        # `- echo "a: b"` is not valid YAML to GitLab (it is a mapping), and still a script line here
        self.assertEqual([f[0] for f in found(job(["echo \"a: b\"; curl x.invalid | sh"]))], ["pipe-to-shell"])

    def test_not_in_other_keys(self):
        self.assertEqual(found("build:\n  stage: curl x.invalid | sh\n  variables:\n    CMD: curl x.invalid | sh\n  script: [x]\n"), [])

    def test_the_rule(self):
        rule = gitlabci.hardening_rule("pipe-to-shell", {"job": "a", "command": "curl … | sh"})
        self.assertEqual((rule["id"], rule["sev"]), ("SC-GITLAB-PIPE-SHELL", "MAJOR"))
        self.assertIn("\"a\"", rule["msg"])


class WhereKeysCountTests(unittest.TestCase):
    """Which keys are a job's, and which are not."""
    TOKENS = "  id_tokens:\n    T:\n      aud: https://x.invalid\n"

    def test_a_list_under_a_name_that_is_not_hidden_is_not_a_script(self):
        self.assertEqual(found("unrelated:\n  - curl x.invalid | sh\n"), [])
        self.assertEqual([f[2]["job"] for f in found(".setup: &setup\n  - curl x.invalid | sh\n")], [".setup"])

    def test_top_level_id_tokens_and_secrets_are_not_the_defaults(self):
        for key in ("id_tokens:\n  T:\n    aud: x\n", "secrets:\n  K:\n    vault: a/b@c\n"):
            self.assertEqual(found(key + job(["npm ci"], "a")), [], key)

    def test_the_default_is_not_a_job(self):
        # it holds an OIDC token and installs, and no job inherits either: nothing runs
        self.assertEqual(found("default:\n" + self.TOKENS + "  before_script:\n    - npm ci\n"), [])
        # a job that inherits both is the one reported, at the default's line
        text = "default:\n" + self.TOKENS + "  before_script:\n    - npm ci\n" + job(["echo"], "a")
        self.assertEqual([(f[2]["job"], f[1]) for f in found(text)], [("a", 6)])


class MrTextTests(unittest.TestCase):
    def test_what_reads_the_text_as_code(self):
        for line in ('eval "$CI_COMMIT_TITLE"', "eval $CI_COMMIT_TITLE", 'eval "echo ${CI_COMMIT_MESSAGE}"', 'eval a "b" $CI_COMMIT_TITLE',
                     'bash -c "deploy.sh $CI_COMMIT_BRANCH"', 'sh -c "$CI_MERGE_REQUEST_TITLE"', 'sudo bash -ec "x ${CI_MERGE_REQUEST_DESCRIPTION}"',
                     'dash -lc "$CI_COMMIT_DESCRIPTION"', '/bin/sh -c "$CI_COMMIT_REF_NAME"', "$CI_COMMIT_TITLE", "FOO=1 $CI_COMMIT_MESSAGE arg",
                     'zsh -c "$CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME"', "if eval $CI_COMMIT_TITLE; then :; fi",
                     "(eval $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME)", 'eval "$CI_COMMIT_TAG_MESSAGE"', 'eval "$CI_MERGE_REQUEST_LABELS"'):
            self.assertIsNotNone(gitlabci.mr_text(line), line)

    def test_what_keeps_it_as_data(self):
        for line in ('echo "$CI_COMMIT_TITLE"', "git checkout $CI_COMMIT_BRANCH", "eval '$CI_COMMIT_TITLE'", "bash -c 'echo $CI_COMMIT_BRANCH'",
                     "x=$CI_COMMIT_TITLE", "eval", "bash -c eval", 'bash -c "echo ok" && echo "$CI_COMMIT_TITLE"', "$CI_COMMIT_TITLE_X",
                     "$CI_COMMIT_BRANCH_NAME", "$CI_MERGE_REQUEST_ID", 'eval "$CI_COMMIT_SHA"', "$CI_PIPELINE_ID", "", "bash script.sh $CI_COMMIT_TITLE",
                     "eval 'a' '$CI_COMMIT_TITLE'", "bash -c '$CI_COMMIT_TITLE' x", "echo $CI_COMMIT_TITLE | tee f",
                     'sh -c "a" "$CI_COMMIT_TITLE"', "sh -c 'a' $CI_COMMIT_TITLE"):          # after the script, the arguments are data
            self.assertIsNone(gitlabci.mr_text(line), line)

    def test_the_answer(self):
        self.assertEqual(gitlabci.mr_text('eval "$CI_COMMIT_TITLE"'), ("$CI_COMMIT_TITLE", "eval"))
        self.assertEqual(gitlabci.mr_text('bash -c "x ${CI_COMMIT_BRANCH}"'), ("${CI_COMMIT_BRANCH}", "a `sh -c` string"))
        self.assertEqual(gitlabci.mr_text("$CI_COMMIT_TITLE now"), ("$CI_COMMIT_TITLE", "the place of a command"))

    def test_an_escaped_quote_does_not_end_the_string(self):
        self.assertIsNotNone(gitlabci.mr_text('bash -c "a \\" $CI_COMMIT_TITLE"'))

    def test_in_a_job(self):
        text = job(["echo start", 'bash -c "deploy $CI_COMMIT_BRANCH"'], "deploy")
        f = found(text)
        self.assertEqual([(x[0], x[1], x[2]) for x in f],
                         [("mr-text", 4, {"job": "deploy", "variable": "$CI_COMMIT_BRANCH", "how": "a `sh -c` string"})])

    def test_the_rule(self):
        rule = gitlabci.hardening_rule("mr-text", {"job": "a", "variable": "$CI_COMMIT_TITLE", "how": "eval"})
        self.assertEqual((rule["id"], rule["sev"]), ("SC-GITLAB-MR-TEXT", "MAJOR"))
        self.assertIn("$CI_COMMIT_TITLE", rule["msg"])
        self.assertIn("eval", rule["msg"])


class TokenInstallTests(unittest.TestCase):
    TOKENS = "  id_tokens:\n    T:\n      aud: https://x.invalid\n"

    def test_a_jobs_id_tokens_and_an_install(self):
        text = job(["npm ci", "npm publish"], "publish", self.TOKENS)
        self.assertEqual([(f[0], f[1], f[2]) for f in found(text)],
                         [("token-install", 6, {"job": "publish", "grant": "its id_tokens", "command": "npm ci"})])

    def test_the_default_id_tokens(self):
        text = "default:\n" + self.TOKENS + job(["pip install x"], "a") + job(["echo"], "b")
        self.assertEqual([(f[2]["job"], f[2]["grant"]) for f in found(text)], [("a", "the default id_tokens")])

    def test_a_job_that_has_its_own_before_script(self):
        # the default's before_script is the job's unless it has one of its own
        text = "default:\n  before_script:\n    - npm ci\n" + job(["echo"], "a", self.TOKENS) + job(["echo"], "b", "  before_script:\n    - echo\n" + self.TOKENS)
        self.assertEqual([(f[2]["job"], f[1]) for f in found(text)], [("a", 3)])

    def test_secrets_and_registry_tokens(self):
        text = job(["npm ci"], "a", "  secrets:\n    K:\n      vault: a/b@c\n")
        self.assertEqual(found(text)[0][2]["grant"], "its secrets")
        for var in ("$NPM_TOKEN", "${NODE_AUTH_TOKEN}", "$PYPI_API_TOKEN", "$TWINE_PASSWORD", "$CARGO_REGISTRY_TOKEN", "$CI_JOB_JWT_V2"):
            f = found(job(["npm ci", f"echo {var}"]), "token-install")
            self.assertEqual([x[2]["grant"] for x in f], [var], var)

    def test_not_a_credential(self):
        for var in ("$PYPI_TOKENS", "$MY_NPM_TOKEN", "$CI_JOB_TOKEN", "$HOME"):
            self.assertEqual(found(job(["npm ci", f"echo {var}"]), "token-install"), [], var)

    def test_without_an_install_or_with_scripts_off(self):
        self.assertEqual(found(job(["npm publish"], "p", self.TOKENS)), [])
        self.assertEqual(found(job(["npm ci --ignore-scripts", "npm publish"], "p", self.TOKENS)), [])
        self.assertEqual(found(job(["npm ci"], "p")), [])

    def test_a_hidden_job_counts(self):
        self.assertEqual(found(job(["npm ci"], ".tpl", self.TOKENS))[0][2]["job"], ".tpl")

    def test_the_rule(self):
        rule = gitlabci.hardening_rule("token-install", {"job": "a", "grant": "its id_tokens", "command": "npm ci"})
        self.assertEqual((rule["id"], rule["sev"]), ("SC-GITLAB-TOKEN-INSTALL", "MAJOR"))
        self.assertIn("`npm ci`", rule["msg"])


class HelperTests(unittest.TestCase):
    def test_parse_image(self):
        self.assertEqual(gitlabci.parse_image("python:3.12"), ("python", "3.12", ""))
        self.assertEqual(gitlabci.parse_image("registry:5000/app"), ("registry:5000/app", "", ""))
        self.assertEqual(gitlabci.parse_image("registry:5000/app:1.2@sha256:ab"), ("registry:5000/app", "1.2", "sha256:ab"))
        self.assertEqual(gitlabci.parse_image(" x@y "), ("x", "", "y"))
        self.assertEqual(gitlabci.parse_image(""), ("", "", ""))

    def test_flow_items(self):
        self.assertEqual(gitlabci.flow_items("[a, 'b, c', {k: v, 'q': \"w\"}]"), ["a", "b, c", {"k": "v", "q": "w"}])
        self.assertEqual(gitlabci.flow_items("{remote: https://x.invalid/a.yml}"), [{"remote": "https://x.invalid/a.yml"}])
        self.assertEqual(gitlabci.flow_items("[a"), ["a"])
        self.assertEqual(gitlabci.flow_items("[]"), [])
        self.assertEqual(gitlabci.flow_items(""), [])
        self.assertEqual(gitlabci.flow_items("plain"), ["plain"])
        self.assertEqual(gitlabci.flow_items("[{a: b}, [c, d]]"), [{"a": "b"}, "[c, d]"])
        self.assertEqual(gitlabci.flow_items("{k: v, k: w}"), [{"k": "v"}])                  # the first one
        self.assertEqual(gitlabci.flow_items("[a]], b, c]"), ["a]]", "b", "c"])              # a stray closer is not a depth below zero
        self.assertEqual(gitlabci.flow_items('["abc]'), ['"abc'])                            # a quote that does not close stays
        self.assertEqual(gitlabci.flow_items('["]'), ['"'])
        self.assertEqual(gitlabci.flow_items("['a', \"b\"]"), ["a", "b"])

    def test_is_gitlab_ci(self):
        for p in (".gitlab-ci.yml", "a/.gitlab-ci.yaml", "x.gitlab-ci.yml", ".gitlab/ci/build.yml", "a\\.gitlab\\b.yaml", ".GITLAB/x.YML"):
            self.assertTrue(gitlabci.is_gitlab_ci(p), p)
        for p in ("ci.yml", ".github/workflows/x.yml", ".gitlab/issue_templates/Bug.md", ".gitlab-ci.yml.bak", "gitlab-ci.yml", ""):
            self.assertFalse(gitlabci.is_gitlab_ci(p), p)


class QuietTests(unittest.TestCase):
    def test_a_pipeline_that_does_everything_right(self):
        text = (f"include:\n  - project: g/p\n    ref: {SHA}\n    file: /a.yml\n  - component: gitlab.com/g/p/c@{SHA}\n"
                f"  - local: /ci/b.yml\nimage: python:3.12@{DIGEST}\nbuild:\n  services:\n    - name: postgres:16@{DIGEST}\n"
                "  script:\n    - pip install --require-hashes -r r.txt\n    - echo \"$CI_COMMIT_TITLE\"\n    - git checkout \"$CI_COMMIT_BRANCH\"\n"
                f"publish:\n  image: python:3.12@{DIGEST}\n  id_tokens:\n    T:\n      aud: x\n  script:\n    - twine upload dist/*\n")
        self.assertEqual(found(text), [])

    def test_not_yaml_and_cut_files(self):
        for text in ("", "\n\n", "{}", "[", "include:", "include: [", "job:\n  script:", "job:\n  script:\n    -\n", "\t\tjob:\n", "\ufeffimage: x\n",
                     "image:", "services:", "default:", "job:\n  image: {", "job:\n  services: [", "include:\n  -\n  - :\n"):
            gitlabci.hardening(text)                                       # no exception

    def test_the_findings_are_by_line(self):
        text = (include("remote: https://x.invalid/a.yml") + "image: python:3\n" + job(["curl x.invalid | sh", "npm ci"], "a", "  image: node:20\n"))
        lines = [f[1] for f in gitlabci.hardening(text)]
        self.assertEqual(lines, sorted(lines))
        self.assertGreater(len(lines), 3)

    def test_windows_line_ends_read_the_same(self):
        text = (include("remote: https://x.invalid/a.yml", f"project: g/p\n    ref: {SHA}\n    file: x") + "image: python:3\n"
                + job(["curl x.invalid | sh", 'eval "$CI_COMMIT_TITLE"'], "a", "  image: node:20\n"))
        self.assertEqual(gitlabci.hardening(text.replace("\n", "\r\n")), gitlabci.hardening(text))

    def test_the_findings_are_not_the_github_workflow_kinds(self):
        for f in gitlabci.hardening(include("remote: https://x.invalid/a.yml") + job(["curl x.invalid | sh"])):
            self.assertTrue(gitlabci.hardening_rule(f[0], f[2])["id"].startswith("SC-GITLAB-"))


class RuleTests(unittest.TestCase):
    CASES = {
        "include-remote": {"url": "https://x.invalid/a.yml", "http": False},
        "include-project": {"project": "g/p", "ref": "main", "tag": False},
        "include-component": {"component": "gitlab.com/g/p/c", "ref": "~latest", "exact": False},
        "image": {"job": "a", "image": "node:20", "where": "image", "tag": "20", "official": True},
        "pipe-to-shell": {"job": "a", "command": "curl … | sh"},
        "mr-text": {"job": "a", "variable": "$CI_COMMIT_TITLE", "how": "eval"},
        "token-install": {"job": "a", "grant": "its id_tokens", "command": "npm ci"},
    }

    def test_each_rule_has_what_mk_issue_takes(self):
        ids = set()
        for kind, detail in self.CASES.items():
            rule = gitlabci.hardening_rule(kind, detail)
            self.assertEqual(sorted(rule), ["fix", "id", "msg", "name", "ref", "sev", "type", "why"], kind)
            self.assertTrue(rule["id"].startswith("SC-GITLAB-"), kind)
            self.assertEqual(rule["type"], "HOTSPOT")
            self.assertIn(rule["sev"], ("MINOR", "MAJOR", "CRITICAL"))
            self.assertTrue(all(isinstance(rule[k], str) and rule[k] for k in ("msg", "why", "fix", "name", "ref")), kind)
            ids.add(rule["id"])
        self.assertEqual(ids, {"SC-GITLAB-INCLUDE", "SC-GITLAB-IMAGE", "SC-GITLAB-PIPE-SHELL", "SC-GITLAB-MR-TEXT", "SC-GITLAB-TOKEN-INSTALL"})

    def test_the_messages_name_what_was_found(self):
        msg = lambda kind, **kw: gitlabci.hardening_rule(kind, dict(self.CASES[kind], **kw))["msg"]
        self.assertIn("https://x.invalid/a.yml", msg("include-remote"))
        self.assertIn("plain HTTP", msg("include-remote", http=True))
        self.assertIn("no ref", msg("include-project", ref=""))
        self.assertIn("\"main\"", msg("include-project"))
        self.assertIn("latest", msg("include-component"))
        self.assertIn("\"1.2.3\"", msg("include-component", ref="1.2.3"))
        self.assertIn("starts the service", msg("image", where="service"))
        self.assertIn("default settings", msg("image", job="default"))
        self.assertIn("node:20", msg("image"))


def ADVERSARIAL():
    """Files built to make a pattern backtrack or a loop go slow: each must be read in time proportional to its size."""
    n = 50_000
    yield "include:\n" + "  - remote: https://x.invalid/a.yml\n" * n
    yield "include:\n" + "  - project: g/p\n    ref: main\n" * n
    yield "include: [" + "{remote: x}, " * n + "]\n"
    yield "include: [" * n
    yield "include: {" + "a: {" * n
    yield "image: " + "a" * 400_000 + "\n"
    yield "image: " + "a:" * 200_000 + "\n"
    yield "image: " + "a/" * 200_000 + "@" * 1000 + "\n"
    yield "services: [" + "{name: a}, " * n + "]\n"
    yield "build:\n  services:\n" + "    - name: a\n      alias: b\n" * n
    yield "build:\n  script:\n" + "    - curl x | sh\n" * n
    yield "build:\n  script:\n" + "    - npm ci\n" * n + "  id_tokens:\n    T:\n      aud: x\n"
    yield "".join(f"j{i}:\n  script:\n    - curl x.invalid | sh\n    - eval $CI_COMMIT_TITLE\n" for i in range(n // 5))
    yield "".join(f"j{i}:\n  id_tokens:\n    T: x\n  script:\n    - npm ci\n" for i in range(n // 5))
    yield "default:\n  before_script:\n    - npm ci\n" + "".join(f"j{i}:\n  id_tokens:\n    T: x\n  script:\n    - echo\n" for i in range(n // 5))
    yield "build:\n  script:\n    - |\n" + "      curl x \\\n" * n + "      | sh\n"
    yield "build:\n  script:\n    - " + "eval " * n + "$CI_COMMIT_TITLE\n"
    yield "build:\n  script:\n    - " + "eval \"a\" " * (n // 2) + "\n"
    yield "build:\n  script:\n    - " + 'bash -c "' * n + "\n"
    yield "build:\n  script:\n    - " + "bash -c bash -c " * (n // 2) + "$CI_COMMIT_TITLE\n"
    yield "build:\n  script:\n    - " + "bash -c \"\\\"" * (n // 2) + "\n"
    yield "build:\n  script:\n    - " + "$CI_COMMIT_TITLE " * n + "\n"
    yield "build:\n  script:\n    - " + ";$CI_COMMIT_TITLE" * n + "\n"
    yield "build:\n  script:\n    - " + "A=1 " * n + "$CI_COMMIT_TITLE\n"
    yield "build:\n  script:\n    - " + "x " + "echo $PYPI_" * (n // 2) + "\n"
    yield "build:\n  script:\n    - " + "$PYPI_" + "A_" * n + "\n"
    yield "build:\n  script:\n    - " + "sh -a " * n + "-c \"$CI_COMMIT_TITLE\n"
    yield "build:\n  script: [" + "\"a\", " * n + "]\n"
    yield "a:\n" * n
    yield "- " * n + "x\n"
    yield "".join(f"  - project: p{i}\n    ref: v{i}\n" for i in range(n // 2)).join(["include:\n", ""])
    yield "build:\n  script:\n    - echo \"a: b\"\n" * n


class LinearTimeTests(unittest.TestCase):
    """A pipeline is attacker-controlled text: the checks must take time in proportion to its size."""

    def test_hostile_files(self):
        for text in ADVERSARIAL():
            start = time.perf_counter()
            gitlabci.hardening(text)
            self.assertLess(time.perf_counter() - start, 3.0, text[:40])


if __name__ == "__main__":
    unittest.main()
