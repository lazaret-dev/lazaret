"""The package managers' own settings, as lazaret guard reads them (0.1.8):
where each tool fetches a package from, and the credentials its settings
give for that place — so a private registry or index is checked like a
public one, and its credentials go only where the tool itself sends them.

npm, pnpm, yarn and Bun: the default and scoped registries, and the
credentials of npm's `//host/path/:_authToken` keys (`_auth`, `username` and
`_password`), each read the way the tool reads them — npm from `npm config
list --json` and its .npmrc files (npm leaves credentials out of the
listing), pnpm from `pnpm config list --json`, yarn 1 from `yarn config list
--json`, yarn 2+ from `yarn config get … --json --no-redacted`, Bun from
bunfig.toml and .npmrc. pip: its index-url and extra-index-url (`pip config
list`, PIP_INDEX_URL, PIP_EXTRA_INDEX_URL). uv: its indexes (UV_INDEX,
UV_DEFAULT_INDEX, uv.toml, pyproject.toml's [tool.uv]). Python indexes take
their credentials from the index URL, uv's UV_INDEX_<NAME>_USERNAME and
_PASSWORD, and .netrc.

A credential belongs to a host and a path: npm's rule for its keys (a
request gets the credentials of the longest path of its URL that has some;
`//host/` covers the whole host), a Python index's for its whole host (pip's
and uv's). The guard sends them over https, or plain http to this machine;
never on a redirect to another host (Fetcher); never in its output, cache or
--json (a URL is shown without its user:password@)."""
import ast
import base64
import concurrent.futures
import ipaddress
import json
import netrc
import os
import re
import subprocess
import urllib.parse

from lazaret.scanner import sca

NPM_REGISTRY = "https://registry.npmjs.org/"
YARN_REGISTRY = "https://registry.yarnpkg.com/"
PYPI_SIMPLE = "https://pypi.org/simple/"
#: Seconds a package manager may take to print its settings
SETTINGS_TIMEOUT = 60
#: Bytes of a settings file read
MAX_SETTINGS_FILE = 1024 * 1024


def is_loopback(host):
    host = (host or "").strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _origin(url):
    """(scheme, hostname, 'host[:port]' without the scheme's default port,
    path) of an http(s) URL, or None."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not host:
        return None
    shown = f"[{host}]" if ":" in host else host
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        shown = f"{shown}:{port}"
    return parts.scheme, host, shown, parts.path or "/"


#: the spellings of a "." and a ".." segment (WHATWG's URL standard, case aside)
_DOT_SEGMENTS = frozenset({".", "%2e"})
_DOTDOT_SEGMENTS = frozenset({"..", ".%2e", "%2e.", "%2e%2e"})


def normal_path(path):
    """A URL's path as npm, uv and browsers send it (the WHATWG URL parser's reading): its "." and ".." segments
    resolved, "%2e" spellings included, and a backslash read as the slash it is to them; an empty segment stays
    ("/a//b" is not "/a/b"). The guard sends a URL's path so (Fetcher.request); which credential goes with it is
    `covers`' question."""
    path = (path or "/").replace("\\", "/")
    segments = path.split("/")[1:] if path.startswith("/") else path.split("/")
    out = []
    for i, seg in enumerate(segments):
        last = i == len(segments) - 1
        kind = seg.lower()
        if kind in _DOTDOT_SEGMENTS:
            if out:
                out.pop()
            if last:
                out.append("")
        elif kind in _DOT_SEGMENTS:
            if last:
                out.append("")
        else:
            out.append(seg)
    return "/" + "/".join(out)


#: an encoded "/" or "\\" and an encoded "."
_ENCODED_SLASH_RE = re.compile(r"%2[fF]|%5[cC]")
_ENCODED_DOT_RE = re.compile(r"%2[eE]")


def server_path(path):
    """A URL's path as a server that decodes it before it routes it may read it (nginx's location matching decodes
    "%XX", merges slashes and resolves "." and ".."; Tomcat drops a segment's ";parameters"): a backslash and an
    encoded "/" or "\\" a slash, an encoded "." a dot, ";…" dropped from each segment, a run of "/" one, and the dot
    segments resolved. A credential's path is read so too, for `covers` to compare them."""
    path = _ENCODED_DOT_RE.sub(".", _ENCODED_SLASH_RE.sub("/", (path or "/").replace("\\", "/")))
    segments = path.split("/")[1:] if path.startswith("/") else path.split("/")
    last = len(segments) - 1
    out = []
    for i, seg in enumerate(segments):
        seg = seg.split(";", 1)[0]
        if seg == "..":
            if out:
                out.pop()
            if i == last:
                out.append("")
        elif seg == ".":
            if i == last:
                out.append("")
        elif seg or i == last:
            out.append(seg)
    return "/" + "/".join(out)


def _directory(path):
    return path[:path.rfind("/") + 1]


def _readings(path):
    """The directories of a path as it is sent, as `normal_path` reads it, and as `server_path` does."""
    raw = path or "/"
    return _directory(raw), _directory(normal_path(raw)), _directory(server_path(raw))


def _covered(prefix, readings):
    raw, whatwg, server = readings
    return raw.startswith(prefix) and whatwg.startswith(prefix) and server.startswith(server_path(prefix))


def covers(prefix, path):
    """Does the credential path `prefix` (one that ends in "/") cover a request of this URL path, read as it is
    sent, as npm and uv resolve it (`normal_path`) and as a server that decodes it may route it (`server_path`)?
    lazaret-net's `granted` asks the same of every hop: tiny_https sends a redirect's path as its Location gives it,
    and "/team/../x" is under /team/ to a server that reads it as it is and /x to one that resolves it, as
    "/team/..%2fx" is to nginx."""
    return _covered(prefix, _readings(path))


def same_origin(a, b):
    """Are two http(s) URLs of one scheme, host and port?"""
    oa, ob = _origin(a), _origin(b)
    return oa is not None and ob is not None and (oa[0], oa[2]) == (ob[0], ob[2])


def normal_url(url):
    """url with its path as `normal_path` reads it (an http(s) URL; anything else as it is)."""
    if not isinstance(url, str):
        return url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url
    if parts.scheme not in ("http", "https") or not parts.path:
        return url
    path = normal_path(parts.path)
    return url if path == parts.path else urllib.parse.urlunsplit(parts._replace(path=path))


def split_userinfo(url):
    """(the URL without user:password@, (user, password) or None)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return url, None
    if "@" not in parts.netloc:
        return url, None
    userinfo, _, hostport = parts.netloc.rpartition("@")
    user, sep, password = userinfo.partition(":")
    clean = urllib.parse.urlunsplit((parts.scheme, hostport, parts.path, parts.query, parts.fragment))
    creds = (urllib.parse.unquote(user), urllib.parse.unquote(password)) if (user or sep) else None
    return clean, creds


def shown(url):
    """A URL as the guard prints it: without user:password@."""
    return split_userinfo(url)[0] if isinstance(url, str) else url


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")


class Credentials:
    """Authorization headers by host and path (see above). The first header
    added for a host and path wins: callers add the highest-precedence
    setting first."""

    def __init__(self):
        self.hosts = {}                 # 'host[:port]' -> {path prefix ending in '/': header}

    def __bool__(self):
        return bool(self.hosts)

    def add(self, where, header, whole_host=False):
        """where: a URL, or an npm key's '//host[:port]/path'. A path that
        does not end in '/' covers what is under it (npm reads
        '//host/npm' as '//host/npm/')."""
        if not isinstance(where, str) or not header:
            return
        if where.startswith("//"):
            where = "https:" + where
        o = _origin(where)
        if o is None:
            return
        path = "/" if whole_host else (o[3] if o[3].endswith("/") else o[3] + "/")
        self.hosts.setdefault(o[2], {}).setdefault(path, header)

    def token(self, where, token, whole_host=False):
        if token:
            self.add(where, "Bearer " + token, whole_host)

    def login(self, where, user, password, whole_host=False):
        if user or password:
            self.add(where, basic(user or "", password or ""), whole_host)

    def update(self, other):
        """Add another's credentials (this one's win where both have some)."""
        for host, paths in other.hosts.items():
            for path, header in paths.items():
                self.hosts.setdefault(host, {}).setdefault(path, header)

    def _lookup(self, url, crossed=False):
        """(_origin(url), the header of the longest credential path that `covers` url's path): npm's choice, the
        longest key its walk up the path finds, made over the host's few keys (a long path costs one reading).
        `crossed`: the request is a redirect from another origin, which gets a credential of the whole host only."""
        o = _origin(url)
        if o is None:
            return None, None
        prefixes = self.hosts.get(o[2])
        if not prefixes:
            return o, None
        readings = _readings(o[3])
        best = None
        for prefix in prefixes:
            if (not crossed or prefix == "/") and (best is None or len(prefix) > len(best)) \
                    and _covered(prefix, readings):
                best = prefix
        return o, None if best is None else prefixes[best]

    def header(self, url, from_url=None):
        """The Authorization header for a request of url, or None: none is
        set for it, or it would go over plain http to another machine.
        from_url: the URL of the hop before, for a redirect; from another
        origin, only a credential of the whole host goes (npm sends none on a
        redirect to another host, and pip a .netrc's login for it), as
        lazaret-net's `granted` gives."""
        crossed = from_url is not None and not same_origin(from_url, url)
        o, header = self._lookup(url, crossed)
        if header is None or (o[0] == "http" and not is_loopback(o[1])):
            return None
        return header

    def withheld(self, url):
        """Does url have credentials that are not sent (plain http)?"""
        o, header = self._lookup(url)
        return header is not None and o[0] == "http" and not is_loopback(o[1])

    def has_host(self, url):
        o = _origin(url)
        return o is not None and o[2] in self.hosts


# ---------------- Settings files ----------------
def read_file(path):
    """A settings file's text (at most MAX_SETTINGS_FILE bytes), or None."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_SETTINGS_FILE + 1)
    except OSError:
        return None
    if len(raw) > MAX_SETTINGS_FILE:
        return None
    return raw.decode("utf-8", errors="replace")


# npm's ${NAME} (and ${NAME?}, empty when unset) in a setting — a port of
# @npmcli/config's env-replace: an odd number of backslashes before the $
# escapes it, and each pair of backslashes stands for one.
_ENV_EXPR_RE = re.compile(r"(?<!\\)(\\*)\$\{([^${}?]+)(\?)?\}")


def env_replace(text, env):
    def sub(m):
        esc, name, optional = m.group(1), m.group(2), m.group(3)
        if len(esc) % 2:
            return m.group(0)[(len(esc) + 1) // 2:]
        value = env.get(name)
        if value is None:
            value = "" if optional else "${" + name + "}"
        return esc[len(esc) // 2:] + value
    return _ENV_EXPR_RE.sub(sub, text) if "${" in text else text


def parse_npmrc(text, env):
    """{key: value} of an .npmrc (ini): `key = value` lines, `;` and `#`
    comments, quoted values unquoted, ${NAME} replaced in keys and values;
    a later line wins. Sections are skipped (npm keeps no settings there)."""
    out, section = {}, None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        key, sep, value = line.partition("=")
        if not sep or section:
            continue
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except ValueError:
                value = value[1:-1]
        elif len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1]
        if isinstance(value, str) and key:
            out[env_replace(key, env)] = env_replace(value, env)
    return out


def npm_env_settings(env, prefixes=("npm_config_",)):
    """Settings given in the environment (npm_config_registry,
    npm_config_//host/:_authToken …): keys other than npm's `//` ones are
    lowercased, `_` read as `-` (not a leading one); empty values skipped."""
    out = {}
    for k, v in env.items():
        low = k.lower()
        prefix = next((p for p in prefixes if low.startswith(p)), None)
        if prefix is None or not v:
            continue
        key = k[len(prefix):]
        if not key.startswith("//"):
            key = key[:1] + key[1:].replace("_", "-")
            key = key.lower()
        out[key] = v
    return out


def _home(env):
    return env.get("HOME") or env.get("USERPROFILE") or os.path.expanduser("~")


def npmrc_paths(env, dirs, listed=None):
    """The .npmrc files npm-style tools read, highest precedence first: the
    project's (`dirs`: the folders the tool reads one in), the user's
    (userconfig), the global one (globalconfig)."""
    listed = listed or {}
    paths = [os.path.join(d, ".npmrc") for d in dict.fromkeys(dirs) if d]
    lowered = {k.lower(): v for k, v in env.items()}
    user = listed.get("userconfig") or lowered.get("npm_config_userconfig") or os.path.join(_home(env), ".npmrc")
    paths.append(user)
    glob = listed.get("globalconfig") or lowered.get("npm_config_globalconfig")
    if glob:
        paths.append(glob)
    return list(dict.fromkeys(p for p in paths if isinstance(p, str)))


def npmrc_settings(paths, env):
    """The settings of .npmrc files (highest precedence first) merged."""
    out = {}
    for path in reversed(paths):
        text = read_file(path)
        if text is not None:
            out.update(parse_npmrc(text, env))
    return out


def run_json(argv, env, cwd, lines=False):
    """A tool's JSON output ({} or [] when it gives none); lines=True: one
    document per line."""
    try:
        out = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                             errors="replace", timeout=SETTINGS_TIMEOUT).stdout
    except (OSError, subprocess.SubprocessError):
        return [] if lines else {}
    if lines:
        docs = []
        for line in out.splitlines():
            try:
                docs.append(json.loads(line))
            except ValueError:
                continue
        return docs
    try:
        return json.loads(out)
    except ValueError:
        return {}


# ---------------- npm-style settings -> registries and credentials ----------------
def registry_url(value):
    """A registry URL as a base ending in '/', or None."""
    if not isinstance(value, str) or not value.startswith(("https://", "http://")):
        return None
    return value if value.endswith("/") else value + "/"


def npm_credentials(settings, default_registry):
    """Credentials of npm's keys in `settings` (npm-style, merged): per
    `//host/path`, a token, else `_auth`, else `username` and `_password`
    (base64, as npm keeps it); the unscoped legacy `_authToken`, `_auth`,
    `username` and `_password` belong to the default registry."""
    darts = {}
    for key, value in settings.items():
        if isinstance(key, str) and key.startswith("//") and isinstance(value, str) and value:
            dart, sep, field = key.rpartition(":")
            if sep and dart:
                darts.setdefault(dart, {})[field] = value
    if default_registry and "//" in default_registry:
        own = darts.setdefault("//" + default_registry.split("//", 1)[1], {})
        for field in ("_authToken", "_auth", "username", "_password"):
            value = settings.get(field)
            if isinstance(value, str) and value:
                own.setdefault(field, value)
    creds = Credentials()
    for dart, fields in darts.items():
        if fields.get("_authToken"):
            creds.token(dart, fields["_authToken"])
        elif fields.get("_auth"):
            creds.add(dart, "Basic " + fields["_auth"])
        elif fields.get("username") and fields.get("_password"):
            try:
                password = base64.b64decode(fields["_password"]).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            creds.login(dart, fields["username"], password)
    return creds


class NpmSettings:
    """What an npm-style tool fetches a package from: the default registry,
    the scoped ones (@scope:registry), and the credentials for them —
    `creds` first (a tool's own, like bunfig's), then a registry URL's
    user:password@, then npm's keys."""

    def __init__(self, settings, default=NPM_REGISTRY, creds=None, replace_npmjs=None):
        self.creds = Credentials()
        if creds:
            self.creds.update(creds)
        base = registry_url(settings.get("registry"))
        base, inline = split_userinfo(base) if base else (None, None)
        self.default = base or default
        if inline:
            self.creds.login(self.default, *inline)
        self.scoped = {}
        for k, v in settings.items():
            url = registry_url(v)
            if url and isinstance(k, str) and k.startswith("@") and k.endswith(":registry"):
                url, inline = split_userinfo(url)
                self.scoped[k[:-len(":registry")]] = url
                if inline:
                    self.creds.login(url, *inline)
        self.creds.update(npm_credentials(settings, self.default))
        if replace_npmjs is None:
            replace_npmjs = settings.get("replace-registry-host") != "never"
        self.replace_npmjs = replace_npmjs


def npm_tool_settings(tool, exe, env, cwd, root):
    """npm and pnpm: `<tool> config list --json` over the .npmrc files and
    the environment (npm lists no credentials; pnpm lists them)."""
    listed = run_json([exe, "config", "list", "--json"], env, cwd)
    listed = listed if isinstance(listed, dict) else {}
    dirs = [cwd, root] if tool == "pnpm" else [root]
    settings = npmrc_settings(npmrc_paths(env, dirs, listed), env)
    if tool == "pnpm":
        xdg = env.get("XDG_CONFIG_HOME") or os.path.join(_home(env), ".config")
        for k, v in npmrc_settings([os.path.join(xdg, "pnpm", "rc")], env).items():
            settings.setdefault(k, v)
    settings.update(npm_env_settings(env, ("npm_config_", "pnpm_config_") if tool == "pnpm" else ("npm_config_",)))
    settings.update({k: v for k, v in listed.items() if isinstance(k, str)})
    return settings


def yarn_classic_settings(exe, env, cwd):
    """yarn 1: `yarn config list --json` gives yarn's settings and npm's;
    npm's registry settings win (yarn 1 asks the npm ones first), yarn's
    default registry is registry.yarnpkg.com."""
    docs = [d.get("data") for d in run_json([exe, "config", "list", "--json"], env, cwd, lines=True)
            if isinstance(d, dict) and d.get("type") == "inspect" and isinstance(d.get("data"), dict)]
    yarn_cfg, npm_cfg = (docs + [{}, {}])[:2]
    settings = npmrc_settings(npmrc_paths(env, [cwd]), env)
    settings.update(npm_env_settings(env, ("npm_config_", "yarn_")))
    for k, v in yarn_cfg.items():
        if isinstance(k, str) and (k == "registry" or k.endswith(":registry") or k.startswith("//")):
            settings[k] = v
    settings.update({k: v for k, v in npm_cfg.items() if isinstance(k, str)})
    return settings


_BERRY_KEYS = ("npmRegistryServer", "npmScopes", "npmRegistries", "npmAuthToken", "npmAuthIdent")


def _berry_ident(ident):
    return "Basic " + (base64.b64encode(ident.encode("utf-8")).decode("ascii") if ":" in ident else ident)


def berry_settings(exe, env, cwd, get=None):
    """yarn 2+: (npm-style settings with the registries, Credentials) from
    `yarn config get <key> --json --no-redacted` (the keys are read at
    once). Credentials: a registry's own (npmRegistries), a scope's
    (npmScopes), then the top-level npmAuthToken / npmAuthIdent for the
    default registry."""
    if get is None:
        def get(key):
            return run_json([exe, "config", "get", key, "--json", "--no-redacted"], env, cwd)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_BERRY_KEYS)) as pool:
        values = dict(zip(_BERRY_KEYS, pool.map(get, _BERRY_KEYS)))
    default = registry_url(values.get("npmRegistryServer")) or YARN_REGISTRY
    settings = {"registry": default}
    creds = Credentials()
    registries = values.get("npmRegistries") if isinstance(values.get("npmRegistries"), dict) else {}
    for where, conf in registries.items():
        if isinstance(where, str) and isinstance(conf, dict):
            url = where if where.startswith(("http://", "https://")) else "https:" + where \
                if where.startswith("//") else "https://" + where
            if isinstance(conf.get("npmAuthToken"), str):
                creds.token(url, conf["npmAuthToken"])
            elif isinstance(conf.get("npmAuthIdent"), str):
                creds.add(url, _berry_ident(conf["npmAuthIdent"]))
    scopes = values.get("npmScopes") if isinstance(values.get("npmScopes"), dict) else {}
    for scope, conf in scopes.items():
        if not isinstance(scope, str) or not isinstance(conf, dict):
            continue
        url = registry_url(conf.get("npmRegistryServer")) or default
        settings[f"@{scope.lstrip('@')}:registry"] = url
        if isinstance(conf.get("npmAuthToken"), str):
            creds.token(url, conf["npmAuthToken"])
        elif isinstance(conf.get("npmAuthIdent"), str):
            creds.add(url, _berry_ident(conf["npmAuthIdent"]))
    if isinstance(values.get("npmAuthToken"), str):
        creds.token(default, values["npmAuthToken"])
    elif isinstance(values.get("npmAuthIdent"), str):
        creds.add(default, _berry_ident(values["npmAuthIdent"]))
    return settings, creds


_BUN_ENV_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _bun_expand(value, env):
    if not isinstance(value, str):
        return None
    return _BUN_ENV_RE.sub(lambda m: env.get(m.group(1) or m.group(2), ""), value)


def _bun_registry(value, env, creds):
    """A bunfig registry (a URL, possibly with user:password@, or a table of
    url, token, username, password) -> its URL; its credentials into creds."""
    if isinstance(value, str):
        url, inline = split_userinfo(_bun_expand(value, env))
        url = registry_url(url)
        if url and inline:
            creds.login(url, *inline)
        return url
    if isinstance(value, dict):
        url, inline = split_userinfo(_bun_expand(value.get("url"), env) or "")
        url = registry_url(url)
        if url:
            token = _bun_expand(value.get("token"), env)
            user, password = _bun_expand(value.get("username"), env), _bun_expand(value.get("password"), env)
            if token:
                creds.token(url, token)
            elif user or password:
                creds.login(url, user, password)
            elif inline:
                creds.login(url, *inline)
        return url
    return None


def bun_settings(env, cwd):
    """Bun: (npm-style settings with the registries, Credentials) from the
    project's and the user's .npmrc, under bunfig.toml ([install] registry
    and [install.scopes]; the project's over the user's), under
    BUN_CONFIG_REGISTRY / NPM_CONFIG_REGISTRY."""
    settings = npmrc_settings(npmrc_paths(env, [cwd]), env)
    creds, seen = Credentials(), set()
    xdg = env.get("XDG_CONFIG_HOME")
    bunfigs = [os.path.join(cwd, "bunfig.toml")] + ([os.path.join(xdg, ".bunfig.toml")] if xdg else []) \
        + [os.path.join(_home(env), ".bunfig.toml")]
    for path in dict.fromkeys(bunfigs):            # highest precedence first
        text = read_file(path)
        if text is None:
            continue
        try:
            doc = sca.load_toml(text)
        except ValueError:
            continue
        install = doc.get("install") if isinstance(doc.get("install"), dict) else {}
        scopes = install.get("scopes") if isinstance(install.get("scopes"), dict) else {}
        for key, value in [("registry", install.get("registry"))] + \
                [(f"@{str(k).lstrip('@')}:registry", v) for k, v in scopes.items()]:
            if value is None or key in seen:
                continue
            seen.add(key)
            url = _bun_registry(value, env, creds)
            if url:
                settings[key] = url
    lowered = {k.lower(): v for k, v in env.items()}
    env_registry = env.get("BUN_CONFIG_REGISTRY") or lowered.get("npm_config_registry")
    if registry_url(env_registry):
        settings["registry"] = env_registry
    return settings, creds


# ---------------- Python indexes ----------------
class Index:
    """A Python package index: its simple URL (ending in '/'), its name (uv),
    and whether it is the default (the last one uv asks)."""

    def __init__(self, url, name=None, default=False):
        self.url = url if url.endswith("/") else url + "/"
        self.name = name
        self.default = default

    def __repr__(self):
        return f"Index({shown(self.url)!r}, name={self.name!r}, default={self.default})"


def _netrc_login(host, env):
    path = env.get("NETRC") or os.path.join(_home(env), ".netrc")
    if not os.path.isfile(path):
        return None
    try:
        found = netrc.netrc(path).authenticators(host)
    except (OSError, netrc.NetrcParseError):
        return None
    if not found:
        return None
    login, _account, password = found
    return login or "", password or ""


def index_credentials(indexes, env, hosts=()):
    """Credentials for Python indexes (whole hosts, pip's and uv's rule):
    the URL's user:password@ (then taken out of the URL), uv's
    UV_INDEX_<NAME>_USERNAME / _PASSWORD for a named index, else .netrc for
    the host; also .netrc for the other `hosts` a lockfile names."""
    creds = Credentials()
    for index in indexes:
        clean, inline = split_userinfo(index.url)
        index.url = clean
        if index.name:
            var = "UV_INDEX_" + re.sub(r"[^A-Za-z0-9]", "_", index.name).upper()
            user, password = env.get(var + "_USERNAME"), env.get(var + "_PASSWORD")
            if user or password:
                creds.login(clean, user, password, whole_host=True)
        if inline:
            creds.login(clean, *inline, whole_host=True)
    for url in [i.url for i in indexes] + list(hosts):
        o = _origin(url)
        if o is not None and not creds.has_host(url):
            login = _netrc_login(o[1], env)
            if login:
                creds.login(url, *login, whole_host=True)
    return creds


def pip_indexes(exe, env, cwd):
    """[Index] pip reads, the default first (pip merges them all): index-url
    and extra-index-url from PIP_INDEX_URL / PIP_EXTRA_INDEX_URL, else its
    configuration files (`pip config list`: the install section over the
    global one); PyPI by default."""
    cfg = {}
    try:
        out = subprocess.run([exe, "config", "list"], env=env, cwd=cwd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=SETTINGS_TIMEOUT).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    for line in out.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        try:
            value = ast.literal_eval(value.strip())
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, str):
            cfg[key.strip()] = value

    def setting(name, var):
        return env.get(var) or cfg.get(f"install.{name}") or cfg.get(f"global.{name}") or ""
    default = setting("index-url", "PIP_INDEX_URL").strip() or PYPI_SIMPLE
    extras = setting("extra-index-url", "PIP_EXTRA_INDEX_URL").split()
    return [Index(default, default=True)] + [Index(u) for u in extras if u != default]


def _uv_config_docs(env, cwd, pip):
    """uv's settings tables, highest precedence first: the project's (the
    nearest uv.toml, or pyproject.toml with a [tool.uv] table, from cwd up;
    UV_CONFIG_FILE names one instead), the user's, the system's. None of
    them under UV_NO_CONFIG. With pip=True, a table's [pip] section too
    (uv pip's own settings, over the table's)."""
    if env.get("UV_NO_CONFIG"):
        return []
    found = []
    explicit = env.get("UV_CONFIG_FILE")
    if explicit:
        found.append(("uv.toml", explicit))
    else:
        d = os.path.abspath(cwd)
        while True:
            if os.path.isfile(os.path.join(d, "uv.toml")):
                found.append(("uv.toml", os.path.join(d, "uv.toml")))
                break
            text = read_file(os.path.join(d, "pyproject.toml"))
            if text is not None and "[tool.uv" in text:
                found.append(("pyproject.toml", os.path.join(d, "pyproject.toml")))
                break
            parent = os.path.dirname(d)
            if parent == d:
                break
            d = parent
    xdg = env.get("XDG_CONFIG_HOME") or os.path.join(_home(env), ".config")
    found.append(("uv.toml", os.path.join(xdg, "uv", "uv.toml")))
    for base in (env.get("XDG_CONFIG_DIRS") or "/etc/xdg").split(os.pathsep) + ["/etc"]:
        found.append(("uv.toml", os.path.join(base, "uv", "uv.toml")))
    docs = []
    for kind, path in found:
        text = read_file(path)
        if text is None:
            continue
        try:
            doc = sca.load_toml(text)
        except ValueError:
            continue
        if kind == "pyproject.toml":
            doc = doc.get("tool", {}).get("uv", {}) if isinstance(doc.get("tool"), dict) else {}
        if not isinstance(doc, dict):
            continue
        if pip and isinstance(doc.get("pip"), dict):
            doc = dict(doc, **doc["pip"])
        docs.append(doc)
    return docs


def _uv_index_value(value):
    """UV_INDEX's `name=url` or `url` -> Index."""
    name, sep, url = value.partition("=")
    if sep and re.fullmatch(r"[A-Za-z0-9_.-]+", name) and "://" in url:
        return Index(url, name=name)
    return Index(value)


def uv_indexes(env, cwd, pip=False):
    """[Index] uv reads, in the order it asks them (its first-index rule):
    UV_INDEX (and UV_EXTRA_INDEX_URL), the settings files' `index` tables
    (not the explicit ones, and not the one marked default) and
    extra-index-url, then the default index: UV_DEFAULT_INDEX (UV_INDEX_URL),
    else the settings' default `index` or index-url, else PyPI."""
    docs = _uv_config_docs(env, cwd, pip)
    extras, default = [], None
    for value in (env.get("UV_INDEX") or "").split():
        extras.append(_uv_index_value(value))
    for value in (env.get("UV_EXTRA_INDEX_URL") or "").split():
        extras.append(Index(value))
    default_env = env.get("UV_DEFAULT_INDEX") or env.get("UV_INDEX_URL")
    if default_env:
        default = Index(default_env, default=True)
    for doc in docs:
        for entry in doc.get("index", []) if isinstance(doc.get("index"), list) else []:
            if not isinstance(entry, dict) or not isinstance(entry.get("url"), str) or entry.get("explicit"):
                continue
            name = entry.get("name") if isinstance(entry.get("name"), str) else None
            if entry.get("default"):
                if default is None:
                    default = Index(entry["url"], name=name, default=True)
            else:
                extras.append(Index(entry["url"], name=name))
        for url in doc.get("extra-index-url", []) if isinstance(doc.get("extra-index-url"), list) else []:
            if isinstance(url, str):
                extras.append(Index(url))
        if default is None and isinstance(doc.get("index-url"), str):
            default = Index(doc["index-url"], default=True)
    seen, out = set(), []
    for index in extras + [default or Index(PYPI_SIMPLE, default=True)]:
        key = split_userinfo(index.url)[0]
        if key not in seen:
            seen.add(key)
            out.append(index)
    return out


def uv_index_strategy(env, cwd, pip=False):
    """uv's index-strategy (UV_INDEX_STRATEGY, else its settings files):
    first-index by default."""
    if env.get("UV_INDEX_STRATEGY"):
        return env["UV_INDEX_STRATEGY"]
    for doc in _uv_config_docs(env, cwd, pip):
        if isinstance(doc.get("index-strategy"), str):
            return doc["index-strategy"]
    return "first-index"
