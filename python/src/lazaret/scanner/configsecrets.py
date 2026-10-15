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

The reading is the native engine's since 0.1.9 (BR-7 step 3: rust/crates/
lazaret-engine/src/config.rs, the `scan_config` call; the patterns are the
rule pack's `_CFG_*`), as it is for the npm package; until then this module
and js/src/lib/configsecrets.js were twins. This module keeps which files are
read (is_config_file, own_report: the collection's) and the names the tests
call, over the engine.
"""
import os
import re

from . import _native, engine

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


# ---- the engine's reading, for the tests ----------------------------------------
# The pack's values, read when first asked (importing never needs the engine): KV_RE (key = value in the forms the
# formats share), SECRET_KV_HINT_RE (where a pair S-SECRET can report on may be, in the text lowered), JWT_IO_PAYLOAD
# (jwt.io's sample token's payload), NETRC_NAMES (a .netrc's names).
_LAZY = {"KV_RE": lambda: engine.pack_pattern("_CFG_KV_RE"),
         "SECRET_KV_HINT_RE": lambda: engine.pack_pattern("_CFG_SECRET_KV_HINT_RE"),
         "JWT_IO_PAYLOAD": lambda: engine.pack_value("_CFG_JWT_IO_PAYLOAD"),
         "NETRC_NAMES": lambda: frozenset(engine.pack_value("_CFG_NETRC_NAMES"))}


def __getattr__(name):
    if name in _LAZY:
        value = _LAZY[name]()
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _check(check, text, **args):
    return _native.call("config_check", dict(args, check=check), text)


def comment_spans(content):
    """Absolute (start, end) spans of the comments of a config file."""
    return [tuple(s) for s in _check("comment_spans", content)]


def secret_key(key):
    """True for a key named like a credential (and not a cursor's or an anti-CSRF token's)."""
    return _check("secret_key", key)


def secret_value(value):
    """True for a (quoted or bare) value that looks like a credential."""
    return _check("secret_value", value)


def secret_col(code, netrc=False, skip=()):
    """Column of the first credential S-SECRET reports on a config line (its
    comment text removed), else None. `netrc`: the line is a .netrc's;
    `skip`: the columns of its password values that are not secrets."""
    return _check("secret_col", code, netrc=bool(netrc), skip=sorted(skip))


def redact_values(line, netrc=False):
    """`line` with the value of every credential-named key replaced by
    [redacted], unless it is a reference or a template. `netrc`: a .netrc's
    line, whose password tokens' values are redacted too."""
    return _check("redact_values", line, netrc=bool(netrc))


def key_follows(line, end, following):
    """True when a private-key header's key comes right after it (S-TOKEN-PEM),
    on its line (the header ending at `end`) or at the start of the first of
    the `following` lines that holds anything."""
    return _check("key_follows", line, end=end, following=list(following))


def documentation_token(text):
    """True for a token-rule match that is a documentation sample (AKIA…EXAMPLE,
    jwt.io's sample token)."""
    return _check("documentation_token", text)
