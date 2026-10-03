"""Audit P0: credentials in config and data files.

Lazaret read only Python, JavaScript and SQL, so a credential in a .env,
JSON, YAML, TOML, INI, .properties, shell script, PEM key, Dockerfile,
.npmrc / .pypirc or Terraform variables file was never seen: 19% recall on
the audit's labeled corpus, 83% in the files Lazaret already read. Those files
are now read as text and checked by S-TOKEN and a config form of S-SECRET only
(lazaret.scanner.configsecrets, core.scan_config_file); they count in no code
metric and are listed as metrics["configFiles"].

The value filters come from a false-positive sweep of 11,490 config files in
17 public repositories (translations, Kubernetes secret names, template
references, environment-variable names, documentation samples) and of 476 in
the benign package corpus (no findings). Fixtures are inert: hosts are .invalid
or TEST-NET, every credential is made up, nothing is contacted.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from lazaret.scanner import configsecrets as C
from lazaret.scanner import core
from tests import _support

PY = sys.executable
TOKEN = "ghp_" + "a1B2" * 9                  # GitHub classic PAT shape, made up
# GitHub fine-grained PAT shape (22 and 59 characters around an underscore),
# made up and built in pieces so the source holds no token-shaped literal
PAT = "github" + "_pat_" + "11ABCDEFG0" + "a1b2c3d4e5f6" + "_" + ("Zz9" * 20)[:59]
PASS = "Zq8!vN3pL0wX7r"                       # a made-up credential


# S-SECRET's config form: lines it reports, and lines it must not (the
# second list is the false-positive sweep's classes). Also run through both
# engines by tests/architecture/test_js_parity_config.py.
REPORTED = (
    f"DB_PASSWORD={PASS}", f'  "password": "{PASS}",', f"password = '{PASS}'",
    f"export API_TOKEN=\"{PASS}\"", f"ENV SLACK_BOT_TOKEN={PASS}", f"db_pass: {PASS}",
    f"GITHUB_PAT={PASS}", f"clientSecret: {PASS}", f"aws_secret_access_key = {PASS}",
    f"AccountKey={PASS}", f"STRIPE_RESTRICTED_KEY={PASS}", f"APP_KEY={PASS}",
    f"//registry.invalid/:_authToken={PASS}", f"_auth={PASS}", f"  - --password={PASS}",
    "api_key: d41d8cd98f00b204e9800998ecf8427e", "password: cGFzc3dvcmQxMjM=",
    f"url: postgres://app:{PASS}@db.prod.invalid:5432/app",
    # split so the fake webhook is not one literal in the source (GitHub push protection)
    "hook: https://hooks.slack.com/services/" "T0AAAAAAA/B0BBBBBBB/" "Zq8vN3pL0wX7rT2mK9sB4hF6",
    "hook: https://discord.com/api/webhooks/123456789012/Zq8vN3pL0wX7rT2mK9sB4hF6jD1",
    f"{{\"user\": \"bob\", \"password\": \"{PASS}\"}}")
QUIET = (
    "DB_PASSWORD=changeme", "DB_PASSWORD=change_this", "OPENAI_API_KEY=${OPENAI_API_KEY}",
    "API_KEY=$API_KEY", "password: {{ .Values.password }}", "token: <your-token>",
    "password: '%(db_password)s'", "GITHUB_TOKEN=your-github-token-here",
    "API_KEY=xxxxxxxxxxxxxxxxxxxx", "password: ********", "secret_key = ...",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "password: postgres", "password: supersecret1", "PASSWORD: P@ssw0rd!",
    "PASSWORD_MIN_LENGTH=12", "PASSWORD_FIELD=password", "PASSWORD_RESET_URL=/account/reset",
    "TOKEN_EXPIRY=3600", "max_tokens: 4096", "token_type: bearer", "tokenizer: gpt2-large",
    "STRIPE_PUBLISHABLE_KEY=pk_live_Zq8vN3pL0wX7rT2mK9sB",   # key named publishable
    "secret: root-ca5", "secretName: default/basic-auth", "auth: mdi:lock",
    "password: Contrase\u00f1a actual", "password: Palavra-passe", "token: Lykilor\u00f0",
    "forgot_password: Forgot your password?", "access_token: ACCESS_TOKEN",
    "access_key: A1B2C3D4E5F6G7H8I9J0", "auth: data_shipper:0987654321abcDEF",
    "auth: WPAPSKWPA2PSK", "nextPageToken: Zq8vN3pL0wX7rT2m", "csrf_token: Zq8vN3pL0wX7rT2m",
    "spring.datasource.password=${DB_PASSWORD:Zq8vN3pL0wX7r}", "auth: elastic:${ELASTIC_PASSWORD}",
    "password: /run/secrets/db-password", "private_key_file: ./keys/id_rsa",
    "token_url: https://oauth2.invalid/token", "password: fake-password-1",
    "accountkey: base64encodedaccountkey", "token: MyString123",
    "url: postgres://postgres:postgres@localhost:5432/app",
    "url: postgres://app:Zq8vN3pL0wX7r@localhost:5432/app",
    "url: postgres://app:${DB_PASSWORD}@db.prod.invalid/app",
    "DB_PASSWORD=hunter2", "password:", 'password: ""', "password: |")


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-cfg-")
    for rel, body in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(body if isinstance(body, bytes) else body.encode("utf-8"))
    return root


def found(path, text):
    return sorted((i["rule"], i["line"]) for i in core.scan_config_file(path, text))


class Names(unittest.TestCase):
    def test_config_files(self):
        for name in (".env", ".env.local", ".env.production", "prod.env", ".envrc", "config.json",
                     "tsconfig.JSON", "app.yaml", "ci.yml", "pyproject.toml", "setup.cfg", "tox.ini",
                     "nginx.conf", "application.properties", "deploy.sh", "run.bash", "z.zsh",
                     "server.pem", "server.key", "prod.tfvars", ".npmrc", ".pypirc", ".netrc",
                     ".git-credentials", "Dockerfile", "Dockerfile.prod", "api.dockerfile",
                     "Containerfile", "id_rsa", "id_ed25519", "settings.jsonc"):
            with self.subTest(name=name):
                self.assertTrue(C.is_config_file(name))

    def test_not_config_files(self):
        for name in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "pylock.toml",
                     "pylock.dev.toml", "packages.lock.json", "yarn.lock", "poetry.lock", "uv.lock",
                     "app.py", "index.js", "README.md", "notes.txt", "data.csv", "env", "dockerfiles",
                     "id_rsa.pub", "cert.crt", "page.html", "report.sarif"):
            with self.subTest(name=name):
                self.assertFalse(C.is_config_file(name))


class Comments(unittest.TestCase):
    def spans(self, line):
        return [line[a:b] for a, b in C.comment_spans(line)]

    def test_forms(self):
        cases = {
            "# a comment": ["# a comment"], "   # indented": ["# indented"],
            "KEY=value # trailing": ["# trailing"], "KEY=value#not": [],
            "url: https://x.invalid/a#frag": [], '"a": "b # c"': [], "k: 'x # y' # z": ["# z"],
            "; ini comment": ["; ini comment"], "a = 1 ; not one": [],
            "// jsonc": ["// jsonc"], "//": ["//"], "//registry.invalid/:_authToken=x": [],
            '"url": "https://x.invalid"': [], 'k: "a \\" # b" # c': ["# c"],
            "": [], "plain": [],
        }
        for line, want in cases.items():
            with self.subTest(line=line):
                self.assertEqual(self.spans(line), want)

    def test_absolute_spans_over_lines(self):
        content = "a=1\n# two\nb=2 # three\n"
        self.assertEqual([content[a:b] for a, b in C.comment_spans(content)], ["# two", "# three"])


class SecretValues(unittest.TestCase):
    def test_reported(self):
        for line in REPORTED:
            with self.subTest(line=line):
                self.assertIsNotNone(C.secret_col(line))

    def test_not_reported(self):
        for line in QUIET:
            with self.subTest(line=line):
                self.assertIsNone(C.secret_col(line))

    def test_linear_time(self):
        # each pattern is tried once per run start and every repetition is
        # bounded, so none of these can make a match rescan the line
        for line in ("a" * 2_000_000, "a=" * 1_000_000, 'k="' * 700_000, "k='" * 700_000,
                     "x://" * 500_000, "password:" + " " * 2_000_000 + "x",
                     "a:b@" * 500_000, "_" * 2_000_000 + "=", ("-" * 127 + "=") * 15_000):
            with self.subTest(line=line[:12]):
                t0 = time.perf_counter()
                C.secret_col(line)
                C.redact_values(line)
                C.comment_spans(line)
                dt = time.perf_counter() - t0
                self.assertLess(dt, 10.0, f"took {dt:.1f}s")


class ScanConfigFile(unittest.TestCase):
    def test_tokens_on_every_line_secrets_outside_comments(self):
        text = (f"# GITHUB_TOKEN={TOKEN}\n# DB_PASSWORD={PASS}\n"
                f"DB_PASSWORD={PASS}\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nKEY=AKIA2345ABCD6789WXYZ\n")
        self.assertEqual(found(".env", text), [("S-SECRET", 3), ("S-TOKEN", 1), ("S-TOKEN", 5)])

    def test_fine_grained_github_tokens(self):
        # the CI/CD review's gap: a fine-grained token got only S-ENTROPY
        self.assertEqual(found(".env", f"GH_PAT={PAT}\n"), [("S-TOKEN", 1)])
        got = core.scan_file("x.py", f'GH = "{PAT}"\n', "py")
        self.assertIn(("S-TOKEN", "BLOCKER"), {(i["rule"], i["sev"]) for i in got})
        self.assertTrue(all(PAT not in json.dumps(i) for i in got), "a snippet shows the token")
        # not the token's form: no S-TOKEN (the redaction list still reads it)
        for other in (PAT.replace("_", "x").replace("githubxpatx", "github_pat_"), PAT[:-1]):
            with self.subTest(other=other):
                self.assertNotIn("S-TOKEN", [r for r, _ in found(".env", f"GH_PAT={other}\n")])

    def test_documentation_tokens_are_not_reported(self):
        jwt_io = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + C.JWT_IO_PAYLOAD
                  + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        self.assertEqual(found("a.yaml", f"k: {jwt_io}\nid: AKIAIOSFODNN7EXAMPLE\n"), [])
        # a documentation sample first, a real-looking token after it: the second counts
        self.assertEqual(found("b.yaml", f"k: AKIAIOSFODNN7EXAMPLE {TOKEN}\n"), [("S-TOKEN", 1)])

    def test_private_keys_need_material(self):
        body = "MIIEpAIBAAKCAQEA3Bq7Zq8vN3pL0wX7rT2mK9sBZq8vN3pL0wX7rT2mK9sB"
        key = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
        template = key.replace(body, "privatekey" * 6)
        self.assertEqual(found("k.pem", key), [("S-TOKEN", 1)])
        self.assertEqual(found("t.pem", template), [])
        self.assertEqual(found("c.pem", "-----BEGIN CERTIFICATE-----\n" + body + "\n"), [])

    def test_suppression_markers(self):
        text = (f"A_TOKEN={PASS}  # nosec\n"
                f"B_TOKEN={TOKEN}  # lazaret-ignore: S-SECRET\n"
                f"# lazaret-ignore\nC_PASSWORD={PASS}\n"
                f"D_PASSWORD={PASS} LABEL=\"# nosec\"\n")      # a marker in a string is not one
        self.assertEqual(found(".env", text), [("S-SECRET", 5), ("S-TOKEN", 2)])

    def test_snippets_never_show_a_credential(self):
        text = (f"{{\n  \"user\": \"svc\",\n  \"password\": \"{PASS}\",\n  \"api_key\": \"d41d8cd98f00b204e9800998ecf8427e\",\n"
                f"  \"pw\": \"hunter2\",\n  \"db_pass\": \"x7!\",\n  \"token\": \"{TOKEN}\"\n}}\n")
        issues = core.scan_config_file("c.json", text)
        # line 7's token repeats itself (entropy under 2.5): S-TOKEN, not S-SECRET
        self.assertEqual(sorted((i["rule"], i["line"]) for i in issues),
                         [("S-SECRET", 3), ("S-SECRET", 4), ("S-TOKEN", 7)])
        shown = json.dumps(issues)
        for raw in (PASS, "d41d8cd98f00b204e9800998ecf8427e", TOKEN, "x7!"):
            self.assertNotIn(raw, shown)
        self.assertTrue(all(i["sev"] == "BLOCKER" and i["type"] == "VULN" for i in issues))


class ProjectScan(unittest.TestCase):
    def setUp(self):
        self.root = tree({
            ".env": f"DB_PASSWORD={PASS}\n",
            "deploy/app.yaml": f"db:\n  password: \"{PASS}\"\n",
            "Dockerfile": f"FROM scratch\nENV API_TOKEN={PASS}\n",
            "app.py": "x = 1\n",
            "package-lock.json": json.dumps({"packages": {"": {"token": TOKEN}}}),
            "lazaret-report.json": '{"generatedBy": "lazaret-cli-1", "password": "%s"}' % PASS,
            "server.key": b"\x30\x82\x04\xa4\x02\x01\x00" + b"\x00\xff" * 100,
            "node_modules/dep/.env": f"DB_PASSWORD={PASS}\n",
            "data/big.json": '{"password": "%s"}' % PASS + " " * 3000,
        })
        self.addCleanup(shutil.rmtree, self.root, True)

    def scan(self, **kw):
        with mock.patch.object(C, "CONFIG_SCAN_CAP", 2000):
            return core.scan_project(self.root, **kw)

    def test_what_is_read_and_counted(self):
        res = self.scan()
        got = sorted((i["rule"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"]
                     if i["rule"].startswith(("S-", "Q-SKIPPED-CONFIG")))
        self.assertEqual(got, [("Q-SKIPPED-CONFIG", "data/big.json", 1), ("S-SECRET", ".env", 1),
                               ("S-SECRET", "Dockerfile", 2), ("S-SECRET", "deploy/app.yaml", 2)])
        self.assertEqual(res["metrics"]["configFiles"], 3)
        self.assertEqual((res["metrics"]["files"], res["metrics"]["ncloc"]), (1, 1))   # not code
        note = next(i for i in res["issues"] if i["rule"] == "Q-SKIPPED-CONFIG")
        self.assertEqual(note["sev"], "INFO")
        self.assertIn("3,0", note["msg"])
        self.assertEqual(res["ratings"]["maintainability"], "A")      # a coverage note, not a smell

    def test_dependency_trees_are_not_read_with_deps(self):
        res = self.scan(include_deps=True)
        self.assertFalse([i for i in res["issues"] if "node_modules" in i["file"]
                          and i["rule"].startswith("S-")])

    def test_a_tree_of_config_files_only_is_scanned(self):
        root = tree({"values.yaml": f"password: \"{PASS}\"\n"})
        self.addCleanup(shutil.rmtree, root, True)
        res = core.scan_project(root)
        self.assertEqual([(i["rule"], i["line"]) for i in res["issues"]], [("S-SECRET", 1)])
        self.assertFalse(res["pass"])

    def test_reports_never_carry_the_credential(self):
        out = tempfile.mkdtemp(prefix="lz-cfg-out-")
        self.addCleanup(shutil.rmtree, out, True)
        p = subprocess.run([PY, _support.CLI, self.root, "--json", os.path.join(out, "r.json"),
                            "--html", os.path.join(out, "r.html"), "--sarif", os.path.join(out, "r.sarif")],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        self.assertIn("config files", p.stdout)
        for name in ("r.json", "r.html", "r.sarif"):
            with open(os.path.join(out, name), encoding="utf-8") as fh:
                self.assertNotIn(PASS, fh.read(), name)


class McpScanFiles(unittest.TestCase):
    def test_a_config_file_is_checked_for_credentials(self):
        from lazaret.mcp import server
        root = tree({".env": f"DB_PASSWORD={PASS}\n", "notes.txt": "hello\n"})
        self.addCleanup(shutil.rmtree, root, True)
        out = server.tool_scan_files({"paths": [os.path.join(root, ".env"), os.path.join(root, "notes.txt")]})
        env = out["files"][os.path.join(root, ".env")]
        self.assertEqual([(i["rule"], i["line"]) for i in env["issues"]], [("S-SECRET", 1)])
        self.assertNotIn(PASS, json.dumps(out))
        self.assertIn("Unsupported extension", out["files"][os.path.join(root, "notes.txt")]["error"])


if __name__ == "__main__":
    unittest.main()
