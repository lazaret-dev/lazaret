"""Config and data files: which ones are checked for credentials, and how.

Lazaret reads Python, JavaScript and SQL as code. A credential is at least as
often in a config or data file — .env, JSON, YAML, TOML, INI, .properties, a
shell script, a PEM key, a Dockerfile, .npmrc / .pypirc, Terraform variables
— and those files were never opened (audit P0: 19% recall on a labeled
secrets corpus, 83% in the files Lazaret already read). They are now read as
text and checked by the two credential rules only, never as code, and they
count in no code metric (core.scan_config_file):

  S-TOKEN   the provider token formats and private-key blocks of the code
            rule, on every line, comment lines included; the AWS
            documentation key (AKIA…EXAMPLE) and jwt.io's sample token are
            not reported;
  S-SECRET  a key named like a credential — its last word is password,
            passwd, passphrase, secret, token, api_key, access_key,
            private_key or secret_key, or it ends in a pass / pwd / auth
            segment (DB_PASS, .npmrc's _auth) — whose value is a literal that
            looks like one (secret_value), outside comments; a password
            in a URL's userinfo (postgres://user:password@db.host/…); and in
            a .netrc (0.1.9, N-12), whose tokens are separated by blanks
            (`machine HOST login USER password PASS`), a password token's,
            unless the entry's login is anonymous FTP's (N-25).

This module holds the pure parts (names, matching, comments, redaction); the
npm engine has a twin (js/src/lib/configsecrets.js). Every pattern here runs
in linear time: a key is matched only from the start of a key-character run,
and every repetition is bounded or cannot backtrack.
"""
import math
import os
import re

#: Extensions of config and data files (os.path.splitext, lowercased).
CONFIG_EXTS = frozenset((
    ".env", ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".sh", ".bash", ".zsh", ".pem", ".key", ".tfvars",
))
#: Whole names (lowercased): credential dotfiles, container builds, SSH keys.
CONFIG_NAMES = frozenset((
    ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".dockercfg",
    "dockerfile", "containerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
))
#: A .netrc's names (curl's, git's, pip's and ftp's credentials; _netrc on Windows).
NETRC_NAMES = frozenset((".netrc", "_netrc"))
#: Lockfiles: generated, full of integrity hashes, never where a credential is kept.
CONFIG_SKIP_NAMES = frozenset((
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "packages.lock.json",
    "pylock.toml",
))
#: Config files larger than this are not read (a Q-SKIPPED-CONFIG note says
#: so): a data file that size is not where a credential is configured.
CONFIG_SCAN_CAP = 2_000_000
#: Lazaret's own JSON reports (lazaret-report.json, lazaret-sca.json, a
#: baseline) start with the provenance marker; they are not read.
_OWN_REPORT_RE = re.compile(r'\A\ufeff?\s*\{\s*"generatedBy"\s*:\s*"lazaret-')


def is_config_file(name):
    """True for a file (by its base name) that is read as config or data."""
    low = name.lower()
    if low in CONFIG_SKIP_NAMES or (low.startswith("pylock.") and low.endswith(".toml")):
        return False
    if (low in CONFIG_NAMES or low.startswith(".env.") or low.startswith("dockerfile.")
            or low.endswith(".dockerfile")):
        return True
    return os.path.splitext(low)[1] in CONFIG_EXTS


def own_report(text):
    """True for the text of one of Lazaret's own JSON reports."""
    return bool(_OWN_REPORT_RE.match(text))


# ---- comments ---------------------------------------------------------------
# The common ground of the formats read: a '#' or '// ' (a space, tab or the
# end of the line after it: .npmrc's `//registry.invalid/:_authToken=…` is a
# setting) at the start of a line or after a space or tab, or a ';' at the
# start of a line, begins a comment that runs to the end of the line —
# outside '…' and "…" quotes (a backslash escapes in "…"). JSON has none;
# JSONC, YAML, TOML, INI, .env, .properties, shell and Dockerfiles use these.
def _comment_start(line):
    if "#" not in line and "//" not in line and ";" not in line:
        return None
    quote = None
    blank = True                   # only spaces and tabs so far
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch == '"' or ch == "'":
            quote = ch
        elif (ch == "#" or (ch == "/" and line.startswith("//", i)
                            and line[i + 2:i + 3] in ("", " ", "\t"))) and (
                blank or line[i - 1] in " \t"):
            return i
        elif ch == ";" and blank:
            return i
        if ch != " " and ch != "\t":
            blank = False
        i += 1
    return None


def comment_spans(content):
    """Absolute (start, end) spans of the comments of a config file."""
    spans = []
    pos = 0
    for line in content.split("\n"):
        c = _comment_start(line)
        if c is not None:
            spans.append((pos + c, pos + len(line)))
        pos += len(line) + 1
    return spans


# ---- S-SECRET ----------------------------------------------------------------
# key = value in the forms the formats share: KEY=v, key: v, "key": "v",
# key = "v", export KEY="v", ENV KEY=v. The key starts where a run of key
# characters starts (so each run is tried once), the value is a quoted string
# or a run without spaces, quotes or separators.
KV_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])[\"']?([A-Za-z0-9_.\-]{1,128})[\"']?[ \t]*([:=])[ \t]*"
    r"(\"[^\"\n]*\"|'[^'\n]*'|[^\s\"',;#{}\[\]]+)")
#: A key named like a credential: by its last word, or its last segment.
SECRET_KEY_RE = re.compile(
    r"(?:password|passwd|passphrase|secret|token|(?:api|access|account|app|client|encryption|"
    r"master|private|restricted|secret|signing)[_\-]?key)$|(?:^|[_.\-])(?:pass|pwd|pat|auth)$", re.I)
#: Tokens that are not credentials: a page cursor, an anti-CSRF or idempotency token.
NOT_SECRET_KEY_RE = re.compile(
    r"(?:page|continuation|next|cursor|sync|csrf|xsrf|idempotency)[_\-]?token$", re.I)
#: Values that are documentation, templates or placeholders, not credentials:
#: the words, runs like 123456 / abcdef / A1B2C3, and P@ssw0rd spellings.
PLACEHOLDER_RE = re.compile(
    r"example|sample|dummy|placeholder|change[_\-.]?(?:me|this|it)|your[_\-.]|xxx|\*\*\*|\.\.\.|"
    r"redacted|replace|insert[_\-.]|enter[_\-.]|todo|fixme|fake|mock|encoded|secret|passw|p[a@4]ssw[o0]rd|string|"
    r"123456|654321|abcdef|a1b2c3|<|>|\$\{|\{\{|\}\}|%\(|\$\(",
    re.I)
#: A name or words, not a credential: words (lowercase after their first
#: letter) joined by - . _ / or : (a Kubernetes secret's name "root-ca", a
#: reference "default/basic-auth", an icon "mdi:lock", a translation
#: "Palavra-passe"), or an environment variable's name standing in for its
#: value ("ACCESS_TOKEN").
_NAME_RE = re.compile(r"[A-Za-z][a-z]*[0-9]{0,2}(?:[\-._/:][A-Za-z][a-z]*[0-9]{0,2})+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_URL_START_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://")
_WS_RE = re.compile(r"\s")
_LETTER_RE = re.compile(r"[A-Za-z]")
_NOT_LETTER_RE = re.compile(r"[^A-Za-z]")
# a reference, a template, a YAML anchor / alias / tag / block, a path
_REFERENCE_FIRST = frozenset("$%<{@!(*&~/.\\#[|>")


def unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def secret_value(value):
    """True for a (quoted or bare) value that looks like a credential: at
    least 8 ASCII characters, no whitespace, letters and something else, not
    a reference ($VAR, ${…}, {{…}}, %(…)s, @Vault(…)), a YAML anchor or tag,
    a path, a URL, a name (_NAME_RE) or a placeholder (changeme,
    your-token-here, xxxx, …EXAMPLE…, or anything containing "secret" or
    "passw"). A translation ("Contraseña") is not ASCII."""
    v = unquote(value)
    if len(v) < 8 or not v.isascii() or _WS_RE.search(v) or v[0] in _REFERENCE_FIRST:
        return False
    if _URL_START_RE.match(v) or PLACEHOLDER_RE.search(v) or _NAME_RE.fullmatch(v):
        return False
    return bool(_LETTER_RE.search(v) and _NOT_LETTER_RE.search(v)) and entropy(v) >= 2.5


def entropy(v):
    """Shannon entropy of `v` in bits per character: under 2.5 a value
    repeats itself ("WPAPSKWPA2PSK", "aaaa1111") rather than looks random."""
    counts = {}
    for ch in v:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(v)
    h = 0.0
    for c in counts.values():
        h -= c / n * math.log2(c / n)
    return h


def secret_key(key):
    """True for a key named like a credential (SECRET_KEY_RE, not NOT_SECRET_KEY_RE)."""
    return bool(SECRET_KEY_RE.search(key)) and not NOT_SECRET_KEY_RE.search(key)


# scheme://user:password@host — each part bounded, the scheme from a run start
URL_CRED_RE = re.compile(
    r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,31}://([^\s/:@'\"]{1,256}):"
    r"([^\s/@'\"]{1,512})@([^\s/:?#'\"]{1,256})")
LOCAL_HOSTS = frozenset(("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"))
#: Webhook URLs that carry their own secret (Slack, Discord).
WEBHOOK_RE = re.compile(
    r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,32}"
    r"|https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{5,20}/[A-Za-z0-9_\-]{20,100}")


#: A .netrc's password token and its value: a run without blanks, or "…" quoted.
NETRC_PASSWORD_RE = re.compile(r'(?<![^ \t])password[ \t]+("[^"\n]*"|[^\s"]+)')
#: A .netrc's tokens: a run without blanks, or "…" quoted.
_NETRC_TOKEN_RE = re.compile(r'"[^"\n]*"|[^\s"]+')
#: The logins of anonymous FTP, whose password is by convention an e-mail address, not a secret (N-25).
NETRC_ANONYMOUS = frozenset(("anonymous", "ftp"))


def netrc_anonymous(code_lines):
    """{line index: {column}} of the password values of a .netrc's entries
    whose login is anonymous FTP's (`anonymous`, `ftp`, in any case), which
    S-SECRET does not report (N-25). An entry runs from `machine NAME` or
    `default` to the next one, over as many lines as it takes, its login
    before or after its password; a `macdef`'s lines, up to an empty one, are
    not tokens. `code_lines`: the file's lines, comments removed."""
    skip, login, passwords = {}, None, []
    pending, in_macro = None, False

    def close():
        if login is not None and unquote(login).lower() in NETRC_ANONYMOUS:
            for i, col in passwords:
                skip.setdefault(i, set()).add(col)
    for i, line in enumerate(code_lines):
        if in_macro:
            in_macro = bool(line.strip())
            continue
        for m in _NETRC_TOKEN_RE.finditer(line):
            token = m.group(0)
            if pending is not None:
                if pending == "login":
                    login = token
                elif pending == "password":
                    passwords.append((i, m.start()))
                elif pending == "macdef":
                    in_macro = True                 # (its body is the lines that follow, to an empty one)
                pending = None
                if in_macro:
                    break
                continue
            if token in ("machine", "default"):
                close()
                login, passwords = None, []
                pending = "machine" if token == "machine" else None
            elif token in ("login", "password", "account", "macdef"):
                pending = token
    close()
    return skip


def secret_col(code, netrc=False, skip=()):
    """Column of the first credential S-SECRET reports on a config line (its
    comment text removed), else None. `netrc`: the line is a .netrc's;
    `skip`: the columns of its password values that are not secrets
    (netrc_anonymous)."""
    if netrc:
        for m in NETRC_PASSWORD_RE.finditer(code):
            if m.start(1) not in skip and secret_value(m.group(1)):
                return m.start(1)
    for m in KV_RE.finditer(code):
        value = m.group(3)
        if value[0] not in "\"'":
            after = code[m.end(3):]
            if after[:1] in ("{", "}"):
                continue                # part of a template: ${VAR:default}, pre${VAR}
            if m.group(2) == ":" and after.strip():
                continue                # a YAML phrase: `key: some words` is all value
        if secret_key(m.group(1)) and secret_value(value):
            return m.start(1)
    if "://" in code:
        for m in URL_CRED_RE.finditer(code):
            user, password, host = m.group(1), m.group(2), m.group(3)
            if password != user and host.lower() not in LOCAL_HOSTS and secret_value(password):
                return m.start(2)
        m = WEBHOOK_RE.search(code)
        if m:
            return m.start()
    return None


def redact_values(line, netrc=False):
    """`line` with the value of every credential-named key replaced by
    [redacted] — whatever the value looks like, unless it is a reference or
    a template ($VAR, {{…}}, <…>, %…): a snippet's context lines are shown
    only as far as they cannot carry a credential. `netrc`: a .netrc's line,
    whose password tokens' values are redacted too."""
    if netrc:
        line = NETRC_PASSWORD_RE.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + "[redacted]", line)
    out, pos = [], 0
    for m in KV_RE.finditer(line):
        value = unquote(m.group(3))
        if not secret_key(m.group(1)) or not value or value[0] in "${<%":
            continue
        out.append(line[pos:m.start(3)])
        out.append("[redacted]")
        pos = m.end(3)
    if not out:
        return line
    out.append(line[pos:])
    return "".join(out)


# ---- S-TOKEN in config files ---------------------------------------------------
#: jwt.io's sample token (HS256; sub 1234567890, name John Doe): its payload.
JWT_IO_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"


_PEM_BODY_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_MIXED_RE = (re.compile(r"[A-Z]"), re.compile(r"[a-z]"), re.compile(r"[0-9]"))


def key_material(text):
    """True when `text` holds a line of private-key material: a base64 run of
    40 or more characters that mixes upper case, lower case and digits (a
    template's "privatekeyprivatekey…" does not)."""
    m = _PEM_BODY_RE.search(text)
    return bool(m and all(r.search(m.group()) for r in _MIXED_RE))


def documentation_token(text):
    """True for a token-rule match that is a documentation sample, not a
    credential: AWS's example access key ids (AKIA…EXAMPLE) and the jwt.io
    sample token."""
    if text.startswith("AKIA"):
        return text.endswith("EXAMPLE")
    if text.startswith("eyJ"):
        return text.partition(".")[2] == JWT_IO_PAYLOAD
    return False
