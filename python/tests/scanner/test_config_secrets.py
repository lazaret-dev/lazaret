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
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDEN\x47/bPxRfiCYEXAMPLEKEY",
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
                f"DB_PASSWORD={PASS}\nAWS_KEY=AKI\x41IOSFODNN7EXAMPLE\nKEY=AKI\x412345ABCD6789WXYZ\n")
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
        self.assertEqual(found("a.yaml", f"k: {jwt_io}\nid: AKI\x41IOSFODNN7EXAMPLE\n"), [])
        # a documentation sample first, a real-looking token after it: the second counts
        self.assertEqual(found("b.yaml", f"k: AKI\x41IOSFODNN7EXAMPLE {TOKEN}\n"), [("S-TOKEN", 1)])

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


class NetrcAndCratesTokens(unittest.TestCase):
    """0.1.9: a .netrc's password tokens (N-12: `machine HOST login USER password PASS`, blanks between the
    tokens, no key = value), and crates.io's API tokens (R-4: "cio" and 32 letters and digits; cargo keeps one in
    ~/.cargo/credentials.toml)."""

    def test_a_netrc_password(self):
        text = (f"machine api.example.invalid login alice password {PASS}\n"
                "machine ftp.example.invalid\n  login bob\n  password changeme\n"
                f"default login anon password \"{PASS}\"\n# password {PASS}\n")
        for name in (".netrc", "_netrc", "home/.NETRC"):
            with self.subTest(name):
                self.assertEqual(found(name, text), [("S-SECRET", 1), ("S-SECRET", 5)])
        # the keyword is a whole token: a login ending in "password" is not one
        self.assertEqual(found(".netrc", f"machine h.invalid login app_password password {PASS}\n"), [("S-SECRET", 1)])
        self.assertNotIn(PASS, json.dumps(core.scan_config_file(".netrc", f"login app_password password {PASS}\n")))
        # another config file's prose is not a .netrc's token
        self.assertEqual(found("notes.cfg", f"hint = the password {PASS} is not this\n"), [])
        # the snippet never shows the password, on its line or a line around it
        self.assertNotIn(PASS, json.dumps(core.scan_config_file(".netrc", text)))

    def test_an_anonymous_ftp_login_is_no_secret(self):
        """N-25: the password of an entry whose login is anonymous FTP's (`anonymous`, `ftp`, in any case) is by
        convention an e-mail address, wherever the login sits in the entry; any other entry's still counts."""
        text = ("machine ftp.host.invalid login anonymous password jdoe@mailhost.invalid\n"
                "default\n  password jdoe@mailhost.invalid\n  login FTP\n"
                f"machine api.host.invalid login alice password {PASS}\n"
                "macdef init\ncd /pub\n\n"
                f"machine other.invalid\n login ftpuser\n password {PASS}\n"
                "machine more.invalid login anonymous\n"
                f"machine last.invalid password {PASS}\n")
        self.assertEqual(found(".netrc", text), [("S-SECRET", 5), ("S-SECRET", 11), ("S-SECRET", 13)])
        # the same lines in another config file are prose, not tokens
        self.assertEqual(found("ftp.cfg", "login anonymous password jdoe@mailhost.invalid\n"), [])

    def test_a_crates_io_token(self):
        tok = "cio" + "Zq8vN3pL0wX7rT2mK9sB4hF6jD1aE5cG"
        self.assertEqual(len(tok), 35)
        self.assertEqual(found("credentials.toml", f'[registry]\ntoken = "{tok}"\n'), [("S-SECRET", 2), ("S-TOKEN", 2)])
        got = core.scan_file("src/lib.rs", f'pub const CRATES_IO: &str = "{tok}";\n', "rs")
        self.assertEqual([i["rule"] for i in got if i["rule"].startswith("S-")], ["S-TOKEN"])
        self.assertNotIn(tok, json.dumps(got))
        # in code too, a "cio" inside a longer run is chance
        for text in (f'const X: &str = "A{tok}";\n', f'const X: &str = "{tok}9";\n'):
            with self.subTest(text):
                self.assertNotIn("S-TOKEN", [i["rule"] for i in core.scan_file("src/x.rs", text, "rs")])
        # nor on another finding's context line
        got = core.scan_file("src/lib.rs", f'fn f() {{ let password = "hunter22hunter"; }}\nfn g() -> &\'static str {{ "{tok}" }}\n', "rs")
        self.assertEqual(sorted(i["rule"] for i in got if i["rule"].startswith("S-")), ["S-SECRET", "S-TOKEN"])
        self.assertNotIn(tok, json.dumps(got))
        # inside a longer run (base64, an identifier) it is chance, not a token
        for text in (f'x = "A{tok}"\n', f'x = "{tok}9"\n', f'x = "{tok[:-1]}"\n'):
            with self.subTest(text):
                self.assertNotIn("S-TOKEN", [r for r, _ in found("a.toml", text)])


# V-2: npm's access tokens, Anthropic's keys and tokens and OpenAI's keys, made up and built in pieces so the source
# holds no token-shaped literal (GitHub's push protection knows these formats)
NPM = "npm" + "_" + "a1B2" * 9
ANTHROPIC = "sk-ant-" + "api03-" + "Ab1_-" * 18 + "Ab1" + "AA"
ANTHROPIC_ADMIN = "sk-ant-" + "admin01-" + "x1Y2z" * 18 + "x1Y" + "AA"
ANTHROPIC_OAUTH = "sk-ant-" + "oat01-" + "Q7r_p" * 12
OPENAI = "sk-" + "a1B2C" * 4 + "T3Blbk" + "FJ" + "d3E4f" * 4
OPENAI_PROJECT = "sk-" + "proj-" + "Ab1_-" * 14 + "Ab1_" + "T3Blbk" + "FJ" + "Cd2-_" * 14 + "Cd2-"
OPENAI_ADMIN = "sk-" + "admin-" + "Zz9y8" * 11 + "Zz9" + "T3Blbk" + "FJ" + "Yy8x7" * 11 + "Yy8"
PROVIDER_KEYS = (NPM, ANTHROPIC, ANTHROPIC_ADMIN, ANTHROPIC_OAUTH, OPENAI, OPENAI_PROJECT, OPENAI_ADMIN)


class ProviderKeyFormats(unittest.TestCase):
    """V-2: S-TOKEN reads npm's access tokens ("npm_" and 36 letters and digits), Anthropic's keys and tokens
    ("sk-ant-", a kind such as api03, admin01 or oat01, and 40 to 200 more) and OpenAI's keys ("sk-", the kind's name
    if any, "T3BlbkFJ" in the middle), each a whole run of its characters. They got only S-ENTROPY, or S-SECRET by
    a variable's name, before."""

    def test_in_code_of_each_language(self):
        for tok in PROVIDER_KEYS:
            for path, text, lang in (("app.py", f'KEY = "{tok}"\n', "py"), ("app.js", f"const key = '{tok}';\n", "js"),
                                     ("main.go", f'var k = "{tok}"\n', "go"),
                                     ("src/lib.rs", f'const K: &str = "{tok}";\n', "rs")):
                with self.subTest(tok=tok[:12], lang=lang):
                    got = core.scan_file(path, text, lang)
                    self.assertIn("S-TOKEN", [i["rule"] for i in got])
                    self.assertNotIn(tok, json.dumps(got))

    def test_in_config_files(self):
        for tok in PROVIDER_KEYS:
            for path, text in ((".env", f"KEY={tok}\n"), ("ci.yml", f"env:\n  K: {tok}\n"),
                               (".npmrc", f"//registry.npmjs.org/:_authToken={tok}\n")):
                with self.subTest(tok=tok[:12], path=path):
                    self.assertIn("S-TOKEN", [r for r, _ in found(path, text)])
                    self.assertNotIn(tok, json.dumps(core.scan_config_file(path, text)))

    def test_each_is_the_whole_run(self):
        p = core._TOKEN_PATTERN
        for tok in PROVIDER_KEYS:
            for text in (tok, f'"{tok}"', f"Bearer {tok};", f"KEY={tok}\n"):
                with self.subTest(text=text[:20]):
                    self.assertEqual(p.search(text).group(0), tok)

    def test_what_is_not_one(self):
        not_ones = [
            "x" + NPM, NPM + "9", NPM[:-1], "npm" + "_" + "config_" + "a" * 36,   # a longer run, too short, a name
            "_" + ANTHROPIC, "sk-ant-" + "api03-" + "a" * 39,                       # glued, too short
            "sk-ant-" + "api03-" + "a" * 201, "sk-ant-" + "ap03-" + "a" * 50,     # too long, a kind too short
            "sk-ant-" + "abcdef03-" + "a" * 50, "sk-ant-" + "api003-" + "a" * 50,  # a kind too long, three digits
            "sk-ant-" + "api03-...", "sk-ant-" + "api03-xxxx",                      # documentation's samples
            "x" + OPENAI, "sk-" + "a" * 19 + "T3Blbk" + "FJ" + "a" * 20,           # glued, the first part short
            "sk-" + "a" * 20 + "T3Blbk" + "FJ" + "a" * 19, "sk-" + "a" * 91 + "T3Blbk" + "FJ" + "a" * 20,
            "sk-" + "a" * 20 + "T3Blbk" + "FJ" + "a" * 75, "sk-" + "a" * 48,       # the last part long; no marker
        ]
        for text in not_ones:
            with self.subTest(text=text[:24]):
                self.assertIsNone(core._TOKEN_PATTERN.search(text))
                self.assertNotIn("S-TOKEN", [r for r, _ in found(".env", f"K={text}\n")])

    def test_redacted_on_another_findings_line(self):
        for tok in PROVIDER_KEYS:
            with self.subTest(tok=tok[:12]):
                self.assertEqual(core._redact_context_line(f"x = '{tok}' # a"), "x = '[redacted]' # a")
                got = core.scan_file("app.py", f'password = "hunter22hunter"\nk = ["{tok}"]\n', "py")
                self.assertNotIn(tok, json.dumps(got))


class LinesReadTests(unittest.TestCase):
    """A config or data file's lines are read only where a test can report (0.1.9): the S-TOKEN test where the
    token pattern matches, found by one pass over the whole text, and S-SECRET's where a credential-named key meets a
    separator (configsecrets.SECRET_KV_HINT_RE, on the text lowered) or a URL is; a large data file's other lines
    are passed over. The findings are those of reading every line."""

    def test_every_credential_named_key_has_the_hint(self):
        import random
        rnd = random.Random(2)
        ends = ["password", "passwd", "passphrase", "secret", "token", "apikey", "api_key", "api-key", "accessKey",
                "client_secret", "SIGNING_KEY", "pass", "pwd", "pat", "auth", "db.pass", "x-auth"]
        heads = ["", "db_", "MY_", "app.", "a-", "Prod", "x"]
        for _ in range(2000):
            key = rnd.choice(heads) + "".join(c.upper() if rnd.random() < 0.3 else c for c in rnd.choice(ends))
            for form in ('{k}={v}', '"{k}": "{v}"', "{k}: {v}", "{k} = {v}", "'{k}'\t:\t{v}"):
                text = form.format(k=key, v="Zq8!vN3pL0wX7r")
                for m in C.KV_RE.finditer(text):
                    if C.secret_key(m.group(1)):
                        with self.subTest(text=text):
                            self.assertTrue(C.SECRET_KV_HINT_RE.search(text.lower()))

    def test_the_same_findings_as_reading_every_line(self):
        import random
        rnd = random.Random(9)
        pieces = list(REPORTED) + list(QUIET) + [TOKEN, PAT, f"key: {TOKEN}", "# " + TOKEN, "", "  ", "[x]",
                                                 "machine h.invalid login u password " + PASS, "eyJhbGciOiJIUzI1NiJ9.e"]
        every = lambda rx, text: set(range(text.count("\n") + 1))           # noqa: E731
        for k in range(300):
            text = "\n".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 25))) + "\n"
            name = rnd.choice([".env", "config.yml", "a.json", ".netrc", "x.ini", "Dockerfile"])
            with self.subTest(k=k):
                fast = core.scan_config_file(name, text)
                with mock.patch.object(core, "_match_lines", every):
                    self.assertEqual(fast, core.scan_config_file(name, text))


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
