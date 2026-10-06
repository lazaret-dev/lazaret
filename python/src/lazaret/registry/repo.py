#!/usr/bin/env python3
"""Lazaret registry scanner — audit npm / PyPI packages, Go modules and crates for supply-chain compromise.

Fetches package archives from registry.npmjs.org / pypi.org (and Go modules
from proxy.golang.org, crates from static.crates.io), scans them in memory
(never extracted to disk — immune to tar-slip), and tracks scan state in a
database so you can do full or incremental sweeps.

Usage:
    lazaret-registry add npm:express pypi:requests      # track packages
    lazaret-registry scan npm:left-pad                  # scan latest version
    lazaret-registry scan npm:left-pad@1.3.0            # scan specific version
    lazaret-registry scan pypi:six --full               # full ruleset, not just supply-chain
    lazaret-registry scan go:github.com/pkg/errors@v0.9.1   # a Go module version
    lazaret-registry scan crates:serde                  # the latest crate release
    lazaret-registry scan-all                           # scan latest of every tracked package
    lazaret-registry list                               # tracked packages + last verdicts
    lazaret-registry report npm:left-pad@1.3.0          # stored findings for a scan

State backends (--db or LAZARET_DB env):
    default            SQLite file lazaret-registry.db (no dependencies);
                       also `sqlite:PATH` / `sqlite:///PATH`
    postgres://…       PostgreSQL via the internal wire-protocol client
                       (lazaret.pg — pure stdlib, SCRAM-SHA-256 + TLS; nothing
                       to pip-install). A libpq keyword string
                       ("host=db user=… dbname=lazaret") works too.
                       Point the DSN at a dedicated database on your server, e.g.
                       postgres://user:pass@host:5432/lazaret — see registry/schema.sql
                       for one-time setup. Don't reuse an existing application DB.

Package specs: npm:<name>[@version]  |  pypi:<name>[@version or ==version]
               go:<module path>[@version]  |  crates:<name>[@version]
Scoped npm packages work: npm:@scope/pkg@1.0.0
A Go module is the zip the module proxy serves, checked against the h1: hash
the Go checksum database publishes; a crate is the .crate crates.io serves,
checked against its index's SHA-256. Neither has `discover` yet.
PyPI releases are judged on every file pip may install: the sdist and each
distinct wheel (up to --max-artifacts files and --max-download-bytes in
total); the verdict is the worst of them.
"""
import argparse
import base64
import bisect
import bz2
import contextlib
import datetime
import functools
import hashlib
import importlib
import io
import json
import lzma
import os
import posixpath
import re
import struct
import sys
import tarfile
import time
import zipfile
import zlib
import urllib.error
import urllib.parse
import urllib.request
import warnings

from lazaret.scanner import core as lazaret  # noqa: E402

from lazaret import safexml as _safexml                 # noqa: E402
from lazaret.registry import contentcache as _cache     # noqa: E402
from lazaret.registry import lookalike as _lookalike    # noqa: E402
from lazaret.registry import unused_deps as _unused     # noqa: E402
from lazaret.registry.ecosystems import base as _base   # noqa: E402
from lazaret.scanner import engine as _engine           # noqa: E402
from lazaret.scanner import gomod as _gomod             # noqa: E402
from lazaret.scanner import timings                     # noqa: E402
from lazaret.safexml import ElementTree as _safe_ET     # noqa: E402


def _env_number(var, default, kind=int):
    try:
        value = kind(os.environ.get(var, default))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


USER_AGENT = "Lazaret-registry-scanner/1.0"
# Bytes of one text file scanned as source; a larger file is SC-TRUNCATED and
# the verdict INCOMPLETE. Single-file bundles (a CLI's dist/index.js) often
# pass 1 MB, the old limit (npm:pullfrog 0.1.84 ships two of 7.8 and 8.0 MB),
# and the scan stays linear: both of those scan in about 5 s each.
# Env LAZARET_MAX_SOURCE_BYTES / --max-source-bytes.
MAX_MEMBER = _env_number("LAZARET_MAX_SOURCE_BYTES", 16_000_000)
MAX_FILES = 20_000         # files per package (numpy's sdist alone has >4,000)
SAMPLE = 8192              # header/entropy sample read from oversized files
# Stored scans from another engine version are scanned again (has_scan).
# 2.31: a Go module's and a crate's code is read (Part C: the Go and Rust
#      readers, G-1 and R-1, in registry and guard scans), so a module or a
#      crate is OK, WARN or SUSPICIOUS for what its code does; it was
#      INCOMPLETE whatever it held (SC-UNREAD-CODE, N-1)
# 2.30: a download piped into a shell named by its path (`| /bin/bash`,
#      `| /usr/bin/env sh`) is one: the pipe test read only a bare shell's name,
#      so the 2025 Go typosquats' `wget -O - … | /bin/bash &` was not one
# 2.29: the Go/Rust review's archive fix (RM-1): a tar member of a type that
#      cargo or pip unpacks as a file (a device, a FIFO, a type tar does not
#      know) is read as one, and is SC-ARCHIVE-TYPE; it was left out unread,
#      so a crate's build.rs could hide in one and the crate scan OK
# 2.28: every pattern runs on linre, the linear-time engine (P-16): the
#      decoder body SC-EVAL-DECODER reads and the arguments of open() a
#      shell-profile write reads are no longer cut at 2,000 and 300 items;
#      the other rewritten patterns answer as before
# 2.27: Go and Rust source files read by project scans (S-4): their
#      comments and literals as their lexers read them, and S-SECRET,
#      S-TOKEN, S-BIDI and Q-TODO on them (a package's are not read yet); a
#      Go module or a crate whose code is not read is INCOMPLETE, never OK
#      (SC-UNREAD-CODE, N-1)
# 2.26: the in-sample misses examined (D-1, B-4): a command that downloads
#      or runs code written to a shell's startup file is persistence (any
#      command, to one named only in strings the script decodes: alinet),
#      the request client's calls requests (and what they are given
#      received), a parameter whose default is the script's own address
#      that address when the caller gives none, a member or require() named
#      by a constant read by that name
# 2.25: popular packages' false positives (B-1): a library's request for an
#      address it is given or works out is not the script's own download, a
#      server's address and options not data it receives, a selection of
#      the environment's variables (a loop's test, read with what the names
#      it reads are given) not the whole environment, os.environ by a
#      constant key one variable, a list's reversal no decoder, a Node
#      module's objects not the script's classes (createHash(…).update),
#      createRequire's require a require, one instance of a class made in
#      several places not every other's members, a .pth line judged by what
#      its code does (the network or another program CRITICAL; an exec of a
#      plain literal by the literal's code), a __doc__= keyword no read of
#      the file's own docstring, and the cross-file follower's environment
#      variables from another file only
# 2.24: Python's decoded value run by a shell (os.system, os.popen,
#      subprocess with shell=True) is SC-EVAL-DECODE, as JavaScript's was
# 2.23: the zip reader on the fuzzers' findings: entries that overlap are
#      SC-ARCHIVE-OVERLAP, an entry with no name SC-ARCHIVE-PATH, an LZMA
#      dictionary over 64 MiB is refused (the member is corrupt)
# 2.22: an npm release's dependencies no file names (SC-UNUSED-DEPENDENCY,
#      INFO; a brand-new one is SC-NEW-DEPENDENCY, CRITICAL), and a name
#      like one of Node's built-in modules (child-process) is SC-TYPOSQUAT
# 2.21: a program under a source file's name (an executable's bytes in a
#      .py or .js member) is SC-BINARY, CRITICAL, in a wheel too
# 2.20: S-TOKEN reads GitHub's fine-grained tokens (github_pat_…), which
#      got only S-ENTROPY
# 2.19: 0.1.8's droppers: code a script decodes and runs read on the trees
#      (an XOR, characters' codes, a reversal; a program it decodes, run),
#      code in a literal not code for the text reading, and a file a script
#      writes, then runs: a program carved out of another file it ships, or
#      code it decodes or downloads (a batch file cmd runs, a script); a
#      keyword's look-alike name is MAJOR, not CRITICAL
# 2.18: the Rust-first refactor's phase 3: local data sent and code received
#      read on Python's tree too (a closure's variables, a thread's
#      arguments, a request object given its data, a callee under another
#      name; code in strings and comments is not code)
# 2.17: the Rust-first refactor's phase 3: local data sent and code received
#      read on JavaScript's tree (a send reported by the strongest data it
#      carries; a library's request for its caller not the script's
#      download), and at import time what no client sends (the whole
#      environment, a credential store) and what local commands print sent
#      anywhere, and local data sent to a raw socket's public address
# 2.16: the Rust-first refactor's lexers: comments and literals read as
#      JavaScript and Python read them (a template's `${…}` and an f-string's
#      fields code, every line terminator, a first-line #!), the engine's
#      patterns on a linear-time matcher
# 2.15: 0.1.8's detection round: local data followed through parameters,
#      returns, methods, callbacks, constructors, threads and HTTP clients,
#      command runners and browser profiles read as sources, wallet addresses
#      swapped for the script's own, literals written in escapes and a proxy
#      name each function reuses read in the decoded view, code built around a
#      string array a sign of its own, the cross-file follower through
#      relays, 16 hops, getattr names a file builds and a distribution's
#      modules, runners named through the builtins, and PyPI owners for
#      SC-NEW-DEPENDENCY
# 2.14: 0.1.8's behaviour pass: an install hook's command read as a program,
#      local data followed to where it is sent (service lists only label
#      where it goes; any webhook whose secret is in the code), string arrays,
#      proxy objects and character-code decoders read in the decoded view,
#      programs started by any runtime followed, a program's shortcuts
#      rewritten, SC-EVAL-DECODER for any decoder, `_0x` names and the packer
#      MAJOR, the Bun loader rule retired, and a program in a string literal
#      no longer received code
# 2.13: 0.1.8's DNS names built from values (in code and in shell commands),
#      the host name sent to an address fetched at run time (a dead drop),
#      the host name read through require('os') or a destructured import,
#      and the cross-file follower through event emitters
# 2.12: 0.1.8's programs set to start at login or boot (systemd, launchd,
#      cron, Run keys, scheduled tasks, the Startup folder, XDG autostart),
#      code read back asynchronously or by a path's name from a licence or
#      data file shipped with it, a home-made XOR decoder's strings read, and
#      names like a popular package's (SC-TYPOSQUAT)
# 2.11: 0.1.8's exfiltration shapes (a chat bot or webhook whose secret is in
#      the code, credential files sent to an IP address, a sweep of
#      credential folders, the host name hidden in base64 or sent in a DNS
#      name, the public IP address sent to a capture service, a copy of the
#      environment serialized), reverse shells as argument lists, miners, a
#      raw socket and browser shortcuts at install time, curl or wget
#      downloading to a file that is then run
# 2.10: 0.1.8's names and code in strings a file decodes as it runs, eval of
#      an inline decoder (SC-EVAL-DECODER), a script downloaded or decoded,
#      written and run with an interpreter, scripts a script starts with node
#      or python followed, the received-code detector's second reading, and
#      the cross-file follower on a release (several hops, classes, object
#      literals, callbacks, caches, environment variables, another file's
#      runner)
# 2.9: 0.1.8's code that renames its package and publishes it
#      (SC-SELF-PUBLISH), code hidden off-screen (SC-OFFSCREEN-CODE), install
#      scripts that publish, collect npm tokens or run a DLL, the strong
#      shapes in code a package runs when used (SC-USE-RISK), and a release's
#      brand-new dependencies (SC-NEW-DEPENDENCY)
# 2.8: 0.1.7's install-script and import-time tests (PowerShell, stagers,
#      reverse shells, host beacons, CRITICAL import-time shapes, code run
#      from a file's own prose), more import-time reach (an sdist's modules
#      and their imports), persistence targets (writing an agent's or
#      editor's auto-run settings, a workflow, an extension, a runner; a
#      workflow that dumps every secret) and the Bun loader of the 2025-26
#      worms
# 2.7: a dependency that launches your AI coding agent in an autonomous mode
#      (SC-AGENT-HIJACK, the s1ngularity / Nx attack), a run of invisible
#      characters carrying a payload (SC-HIDDEN-UNICODE, GlassWorm)
# 2.6: install hooks followed through wrapper options, fd numbers, env -C/-S
#      (and within limits), #! scripts run by bun/deno/ts-node/tsx and a
#      Python script's coding cookie, .mts/.cts sources and .jsc bytecode,
#      decode-then-run through an indirect eval, names hidden in a few escapes,
#      look-alike names (SC-HOMOGLYPH), a download piped into a shell (full profile)
# 2.5: what runs (exports patterns, required files, start-up and import-time
#      code), escape codecs, zip links, the time budget
# 2.4: every PyPI artifact, decode/cookie handling, archive structure checks,
#      entry points and hook targets, Python install scripts
# 2.3: verdict tiers, decoded hex, install-script inspection; 2.2:
#      verdict-integrity; 2.1: binary-artifact awareness
ENGINE_VERSION = "2.32.0"

# ---------------- The content memo (P-2a, registry/contentcache.py) ----------------
# One per scan_package run: the engine answers once for content several of a
# release's files hold (a wheel per platform, an sdist with the same modules),
# and a hit gives exactly what the engine would (its raw answer, rebuilt for
# the member's own path). LAZARET_NO_CACHE=1 turns it off. The guard and a
# single archive's scan (_scan_artifact) use none unless given one.
MEMO_DISABLED_ENV = "LAZARET_NO_CACHE"


def new_memo():
    """A memo for one run: contentcache.Memo, or NULL with LAZARET_NO_CACHE=1."""
    return _cache.NULL if os.environ.get(MEMO_DISABLED_ENV) == "1" else _cache.Memo()

# ---------------- Trust-chain limits (F9/G14/F10) ----------------
# Only these hosts may ever be fetched, over https only, and redirects to any
# other scheme/host are refused. Everything else fails closed.
REGISTRY_HOSTS = {"registry.npmjs.org", "replicate.npmjs.com",
                  "pypi.org", "files.pythonhosted.org"}
MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024     # one artifact archive (F9a)
MAX_FEED_BYTES = 5 * 1024 * 1024           # registry metadata / RSS / _changes feed
FEED_MAX_BYTES = MAX_FEED_BYTES            # XML parser cap: never above the fetch cap
# Every byte the decompressor produces counts, including member data that is
# skipped rather than read (F9b): a 2 MB gzip that inflates to 2 GiB stops here.
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024
MAX_REDIRECTS = 3                          # no redirect loops / long hop chains
FETCH_CHUNK = 64 * 1024
METADATA_TIMEOUT = 30                      # seconds for registry metadata / feeds
DOWNLOAD_TIMEOUT = 60                      # seconds for artifact archives
# Wall-clock budget for reading and scanning ONE artifact archive; past it the
# scan stops and the verdict is INCOMPLETE. Env LAZARET_SCAN_TIMEOUT / --scan-timeout.
SCAN_TIMEOUT = _env_number("LAZARET_SCAN_TIMEOUT", 120.0, float)
# PyPI: artifacts scanned per release (sdist + distinct wheels). More than
# this makes the verdict INCOMPLETE. Env LAZARET_MAX_ARTIFACTS / --max-artifacts.
# Popular binary packages publish 60-90 files per release (numpy, grpcio,
# pillow); 50 made every one of them permanently INCOMPLETE.
MAX_ARTIFACTS = _env_number("LAZARET_MAX_ARTIFACTS", 200)
# Total bytes downloaded for ONE package (all its release files together);
# checked BEFORE each download against the sizes PyPI's metadata declares, so
# a release that cannot fit is not fetched at all. Files that don't fit are
# not scanned and the verdict is INCOMPLETE. Env LAZARET_MAX_DOWNLOAD_BYTES /
# --max-download-bytes. (MAX_DOWNLOAD_BYTES above is the per-file limit.)
MAX_PACKAGE_DOWNLOAD_BYTES = _env_number("LAZARET_MAX_DOWNLOAD_BYTES", 2 * 1024 ** 3)
# Non-source text members kept in memory until package.json says whether
# they are entry points (main/bin/exports) or hook targets.
DEFERRED_TEXT_BUDGET = 64 * 1024 * 1024
# Package names come from user input AND from registry feeds, and end up in URLs
# and the watchlist — validate before either.
NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,100}$")          # versions
NAME_MAX = 214                                           # npm's limit; PyPI has none
_NPM_NAME_PART_RE = re.compile(r"^[a-zA-Z0-9~-][a-zA-Z0-9._~-]*$")
_PYPI_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")   # PEP 508


# The errors are the registry modules' (registry/ecosystems/base.py; X-2's
# first step): one class each, so what a Go or crates.io module raises is what
# this file and its callers catch. SpecError: invalid ecosystem / package name
# / version. FetchError: a fetch refused (scheme, host) or over its budget, with
# `status` the HTTP status when the server answered with an error. DigestError:
# a download failed its registry-published integrity check; fail closed, the
# scan stops and nothing is persisted for that package.
SpecError = _base.SpecError
FetchError = _base.FetchError
DigestError = _base.DigestError


class FeedError(ValueError):
    """A registry change feed was rejected as unsafe (DTD / entity declaration)."""


class StoreConfigError(RuntimeError):
    """--db / LAZARET_DB is not a usable SQLite path or Postgres DSN."""


class ScanCancelled(Exception):
    """The caller asked a running scan to stop (MCP notifications/cancelled)."""


# ---------------- Package spec parsing ----------------
#: The ecosystems whose names, versions, resolving and digest live in a
#: registry module (registry/ecosystems; Part C wires them in, X-2's part):
#: `go:<module path>[@version]` and `crates:<name>[@version]`. npm and PyPI
#: keep their code in this file until X-2 moves it.
MODULE_ECOSYSTEMS = ("go", "crates")
ECOSYSTEMS = ("npm", "pypi") + MODULE_ECOSYSTEMS


def registry_module(eco):
    """The registry module of `eco` (golang.ECOSYSTEM, crates.ECOSYSTEM), or
    None for npm, PyPI and anything else. Imported when first asked for: a
    sweep of npm and PyPI packages never loads them."""
    if eco == "go":
        from lazaret.registry.ecosystems import golang
        return golang.ECOSYSTEM
    if eco == "crates":
        from lazaret.registry.ecosystems import crates
        return crates.ECOSYSTEM
    return None


def _check_npm_name(name):
    """npm's naming rules (validate-npm-package-name), restricted to URL-safe
    ASCII: an optional @scope/, at most 214 characters, no leading '.' or
    '_', nothing that could escape the registry API path."""
    if len(name) > NAME_MAX:
        raise SpecError(f"npm: package name longer than {NAME_MAX} characters")
    if name.startswith("@"):
        scope, sep, pkg = name[1:].partition("/")
        if not sep or not scope or not pkg or "/" in pkg:
            raise SpecError(f"npm: scoped name must be @scope/pkg, got {name!r}")
        parts = (scope, pkg)
    else:
        parts = (name,)
    for part in parts:
        if part in (".", "..") or not _NPM_NAME_PART_RE.fullmatch(part):
            raise SpecError(f"npm: invalid package name {name!r}")
    if name.lower() in ("node_modules", "favicon.ico"):
        raise SpecError(f"npm: reserved package name {name!r}")
    return name


def _check_name(eco, name):
    """Reject names that could escape the registry API path or poison the DB (F10).

    Names arrive from the CLI, the watchlist *and* registry discovery feeds, and
    end up interpolated into URLs and persisted — so traversal segments, path
    separators and control characters must never be accepted.
    """
    module = registry_module(eco)
    if module is not None:
        return module.check_name(name)
    if not isinstance(name, str) or not name:
        raise SpecError(f"{eco}: empty package name")
    if eco == "npm":
        return _check_npm_name(name)
    if len(name) > NAME_MAX or not _PYPI_NAME_RE.fullmatch(name):
        raise SpecError(f"{eco}: invalid package name {name!r}")
    return name


def valid_name(eco, name):
    try:
        _check_name(eco, name)
        return True
    except SpecError:
        return False


def _check_version(eco, version):
    """Same guarantee for pinned versions; None (== latest) passes through."""
    module = registry_module(eco)
    if module is not None:
        return module.check_version(version)
    if version is None:
        return None
    if not isinstance(version, str) or not version.strip():
        raise SpecError(f"{eco}: invalid version {version!r}")
    version = version.strip()
    if version in (".", "..") or not NAME_RE.fullmatch(version):
        raise SpecError(f"{eco}: invalid version {version!r}")
    return version


def parse_spec(spec):
    """'npm:@scope/pkg@1.2.3' -> ('npm', '@scope/pkg', '1.2.3'); version may be None.
    'go:github.com/pkg/errors@v0.9.1' and 'crates:serde@1.0.0' are read by
    their registry module (a Go version is v1.2.3; a crate's has no v)."""
    if not isinstance(spec, str) or ":" not in spec:
        raise SpecError(f"Spec must be npm:<name>, pypi:<name>, go:<module> or crates:<name> — got {spec!r}")
    eco, rest = spec.split(":", 1)
    eco = eco.strip().lower()
    if eco not in ECOSYSTEMS:
        raise SpecError(f"Unknown ecosystem {eco!r} (use npm, pypi, go or crates)")
    module = registry_module(eco)
    if module is not None:
        name, ver = module.parse_spec(rest)
        return eco, name, ver
    rest = rest.strip().replace("==", "@")
    if rest.startswith("@"):                      # scoped npm package
        if eco != "npm":
            raise SpecError(f"{eco}: invalid package name {rest!r}")
        at = rest.find("@", 1)
        name, ver = (rest[:at], rest[at + 1:]) if at != -1 else (rest, None)
    elif "@" in rest:
        name, ver = rest.split("@", 1)
    else:
        name, ver = rest, None
    return eco, _check_name(eco, name), _check_version(eco, ver)


def _validated_url(url):
    """F10: registry fetches must be https to a known registry host.

    urlopen() honors ANY scheme by default — file:// would read local disk
    (local file disclosure), ftp://, data://… likewise. Validate before we
    ever hand a URL to the opener."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        raise FetchError(f"unparseable registry URL {url!r}") from exc
    if parts.scheme != "https":
        raise FetchError(
            f"non-https registry URL blocked ({parts.scheme or 'no scheme'}): {url}")
    if parts.netloc.lower() not in REGISTRY_HOSTS:
        raise FetchError(f"registry host not allowlisted: {parts.netloc!r}")
    return url


class _RegistryOpener(urllib.request.HTTPRedirectHandler):
    """G15: urllib follows redirects to ANY host/scheme by default — a
    Location: header must not turn a registry fetch into an arbitrary
    network read. Keep redirects on https + allowlisted registry hosts,
    and cap the hop count."""

    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _validated_url(newurl)
        except FetchError as exc:
            raise urllib.error.URLError(f"redirect blocked: {exc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_RegistryOpener)


def _fetch(url, max_bytes=MAX_DOWNLOAD_BYTES, timeout=DOWNLOAD_TIMEOUT, accept=None,
           data=None, content_type=None):
    """Validated, byte-budgeted fetch (F10 + F9a). Reads in bounded chunks so
    a hostile server cannot OOM the scanner with an unbounded stream (a 300MB
    response previously pinned ~714MB RSS via bare r.read()). With `data`
    (bytes) the request is a POST of that body (PyPI's XML-RPC API). Its
    seconds are the network's in `--timings`."""
    with timings.span("network", "fetch"):
        return _fetch_bytes(url, max_bytes, timeout, accept, data, content_type)


def _fetch_bytes(url, max_bytes, timeout, accept, data, content_type, opener=None, validate=None):
    """`opener` and `validate` default to this file's (_OPENER, _validated_url);
    a registry module's fetch passes its own (module_transport)."""
    (validate or _validated_url)(url)
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with (opener or _OPENER).open(req, timeout=timeout) as r:
            buf = bytearray()
            while True:
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    raise FetchError(
                        f"response exceeds {max_bytes // (1024 * 1024)}MB budget: {url}")
            return bytes(buf)
    except urllib.error.HTTPError as exc:
        err = FetchError(f"HTTP {exc.code} fetching {url}")
        err.status = exc.code
        raise err from exc
    except urllib.error.URLError as exc:
        raise FetchError(f"URL error fetching {url}: {exc.reason}") from exc
    except OSError as exc:                     # includes socket timeouts
        raise FetchError(f"network error fetching {url}: {exc}") from exc


class _ModuleRedirects(urllib.request.HTTPRedirectHandler):
    """_RegistryOpener for a registry module's fetches: every redirect is
    checked by the module's own rule (`base.Fetch.check_url`: https, one of
    the module's hosts, no credentials), at most MAX_REDIRECTS hops."""

    max_redirections = MAX_REDIRECTS

    def __init__(self, check):
        super().__init__()
        self._check = check

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            self._check(newurl)
        except FetchError as exc:
            raise urllib.error.URLError(f"redirect blocked: {exc}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _module_opener(check):
    return urllib.request.build_opener(_ModuleRedirects(check))


def module_transport(url, max_bytes=MAX_DOWNLOAD_BYTES, accept=None, timeout=DOWNLOAD_TIMEOUT,
                     check_redirect=None):
    """The transport a registry module's `base.Fetch` is given (X-2): _fetch's
    bounded, timed read, with the module's URL rule (`check_redirect`, which
    `Fetch` passes) for the URL and for every redirect. The network seam for
    go: and crates: (tests patch it with recorded responses)."""
    if check_redirect is None:
        raise FetchError("a registry module's fetch needs the module's URL rule")
    with timings.span("network", "fetch"):
        return _fetch_bytes(url, max_bytes, timeout, accept, None, None,
                            opener=_module_opener(check_redirect), validate=check_redirect)


def module_fetch(module):
    """A `base.Fetch` for a registry module, over module_transport."""
    return _base.Fetch(module, module_transport)


def http_json(url, accept=None):
    extra = {"accept": accept} if accept else {}
    raw = _fetch(url, max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT, **extra)
    return _deep_safe_loads(raw, f"registry response from {url}")


def _deep_safe_loads(raw, what):
    """json.loads for registry-published JSON with a deep-nesting guard
    (card 1149e3e5, the primitive proven by card 48033f94's scan_manifest PoC:
    ~60KB of '[' parses a 60k-deep document and blows CPython's recursion
    limit). Applies wherever scanned-repo/registry content is consumed:
    registry metadata (resolve_npm/resolve_pypi), discovery feeds, and
    scan-all loops. A hostile response must neither kill the sweep
    (uncaught RecursionError — exit 1, every later package lost) nor silently
    vanish; we raise a FetchError naming the reason so callers treat it like
    any other network failure: warn-and-skip in the non-critical paths,
    'error scanning <spec>' + continuing in cmd_scan (nothing persisted under
    a wrong verdict, remaining work still reported)."""
    try:
        return lazaret.json_loads_bounded(raw)
    except lazaret.JsonTooDeep as exc:
        raise FetchError(
            f"JSON {what} is too deeply nested to parse ({exc}) — treated as "
            f"a fetch failure, not a crash") from exc
    except (UnicodeDecodeError, ValueError) as exc:     # JSONDecodeError, int digits
        raise FetchError(f"invalid JSON {what}: {exc}") from exc


def http_bytes(url):
    """Budget-limited artifact/attachment fetch (F9a): keeps reading until EOF
    but aborts as soon as the byte budget is exceeded."""
    return _fetch(url)


# ---------------- Registry metadata ----------------
# (version, url, container_format, artifact_kind, meta_entry) — the primary
# artifact, unpackable as before — plus .artifacts: every artifact to scan, as
# dicts {url, container, artifact, entry, filename}, and .skipped: files of
# the release that are not scanned, as dicts {filename, packagetype,
# installable, size, reason}; `installable` means pip may install the file
# anyway (scan_package counts it as not scanned). .info: PyPI's release
# metadata; a Go module's path and root, a crate's spelling and yanked flag.
# The registry modules' class (base.py), as the errors are.
Resolution = _base.Resolution


def resolve_npm(name, version):
    """-> (version, url, container_format, artifact_kind, meta_entry).
    meta_entry is the version metadata (dist.integrity digest lives there),
    consumed by scan_package for artifact verification (G15)."""
    _check_name("npm", name)
    version = _check_version("npm", version)
    # Ask for one version's manifest (/<name>/latest or /<name>/<version>), not
    # the full packument: that lists every version ever published and runs to
    # tens of MB for packages like typescript. A scoped name keeps its '@' and
    # encodes the '/' (registry.npmjs.org/@babel%2Fcore/latest).
    url = ("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@") + "/"
           + (_quote_seg(version) if version else "latest"))
    v = http_json(url)
    if not isinstance(v, dict) or not isinstance(v.get("dist"), dict) \
            or not isinstance(v["dist"].get("tarball"), str):
        raise ValueError(f"npm:{name}@{version or 'latest'} not found")
    if version is not None and v.get("version") != version:
        raise ValueError(f"npm:{name}@{version} not found")
    found = v.get("version") if isinstance(v.get("version"), str) else version
    return found or version, v["dist"]["tarball"], "tgz", "npm", v


def pypi_container(filename):
    """Archive format of a PyPI file, from its name (pip decides the same
    way: pip 24's ZIP/TAR/BZ2/XZ_EXTENSIONS); None for formats pip does not
    install."""
    f = (filename or "").lower()
    if f.endswith((".whl", ".zip")):
        return "zip"
    if f.endswith((".tar.gz", ".tgz")):
        return "tgz"
    if f.endswith((".tar.bz2", ".tbz", ".tbz2")):
        return "tbz2"
    if f.endswith((".tar.xz", ".txz")):
        return "txz"
    if f.endswith((".tlz", ".tar.lz", ".tar.lzma")):
        # pip opens these with tarfile's "r:xz" too, i.e. lzma's FORMAT_AUTO:
        # an .xz stream or a legacy .lzma one (and lzip, where liblzma can)
        return "tlz"
    if f.endswith(".tar"):
        return "tar"
    return None


def resolve_pypi(name, version):
    """-> Resolution: (version, url, container_format, artifact_kind,
    meta_entry) of the primary file, and .artifacts = EVERY file pip may
    install for that release: the sdist and each distinct wheel (pip picks a
    compatible wheel when one exists, so scanning only the sdist judged a
    file that is usually never installed). Duplicate files (same sha256) are
    scanned once. URL path segments are quoted (F10); each entry carries its
    digests.sha256 for G15 verification."""
    _check_name("pypi", name)
    version = _check_version("pypi", version)
    url = (f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(version)}/json" if version
           else f"https://pypi.org/pypi/{_quote_seg(name)}/json")
    try:
        meta = http_json(url)
    except FetchError as exc:
        # The unversioned document lists every release's files (9 MB for
        # grpcio). Find the latest stable version from the release feed
        # instead, then fetch just that version's document.
        if version is not None or "budget" not in str(exc):
            raise
        version = pypi_latest_from_feed(name)
        meta = http_json(f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(version)}/json")
    info = meta.get("info") if isinstance(meta, dict) else None
    if not isinstance(info, dict) or not isinstance(info.get("version"), str):
        raise ValueError(f"pypi:{name}@{version or 'latest'} not found")
    version = info["version"]
    urls = meta.get("urls") if isinstance(meta.get("urls"), list) else []
    artifacts, skipped, seen = [], [], set()
    for entry in urls:
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            continue
        filename = entry.get("filename") if isinstance(entry.get("filename"), str) \
            else entry["url"].rsplit("/", 1)[-1]
        kind = entry.get("packagetype")
        container = pypi_container(filename)
        if kind not in ("sdist", "bdist_wheel") or container is None:
            # pip goes by the file NAME, not PyPI's packagetype: an archive
            # it can unpack (a bdist_dumb .tar.gz) is a candidate it may
            # install, so leaving it unscanned makes the scan INCOMPLETE;
            # an egg or a Windows installer is never installed by pip
            installable = container is not None
            skipped.append({"filename": filename, "packagetype": kind,
                            "installable": installable, "size": declared_size(entry),
                            "reason": (f"{kind or 'unknown package type'}: an archive pip may "
                                       f"install, not scanned" if installable else
                                       f"{kind or 'unknown package type'}: not a format pip "
                                       f"installs")})
            continue
        digest = expected_digest(entry)
        key = digest or entry["url"]
        if key in seen:
            continue
        seen.add(key)
        artifacts.append({"url": entry["url"], "container": container,
                          "artifact": "sdist" if kind == "sdist" else "wheel",
                          "entry": entry, "filename": filename})
    if not artifacts:
        raise ValueError(f"pypi:{name}@{version} has no downloadable archive")
    artifacts.sort(key=lambda a: (a["artifact"] != "sdist", a["filename"]))
    return Resolution(version, artifacts, skipped, info=info)


_PEP440_FINAL_RE = re.compile(r"^(\d+(?:\.\d+)*)(?:\.post(\d+))?$")


def _final_release_key(v):
    """Sort key for a final (non-pre/dev) PEP 440 version, or None otherwise."""
    m = _PEP440_FINAL_RE.match(v.strip())
    if not m:
        return None
    release = tuple(int(x) for x in m.group(1).split("."))
    return release + (0,) * (10 - len(release)), int(m.group(2) or 0)


def pypi_latest_from_feed(name):
    """Latest final release of a PyPI project, from its release RSS feed
    (parsed with lazaret.safexml). The feed is ordered by upload time, and a
    backport can be uploaded after a newer release, so pick the highest
    version, not the first item."""
    raw = _fetch(f"https://pypi.org/rss/project/{_quote_seg(name)}/releases.xml",
                 max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT)
    try:
        root = _safe_ET.fromstring(raw, forbid_dtd=True, max_bytes=FEED_MAX_BYTES)
    except (_safexml.SafeXMLError, _safe_ET.ParseError) as exc:
        raise FeedError(f"pypi:{name}: unreadable release feed: {exc}") from None
    titles = [(item.findtext("title") or "").strip() for item in root.iter("item")]
    finals = [(key, t) for t in titles if (key := _final_release_key(t)) is not None]
    if finals:
        return max(finals)[1]
    if titles:
        return titles[0]
    raise ValueError(f"pypi:{name} has no releases")


def resolve(eco, name, version):
    """Registry metadata for one package version (network seam: tests patch
    resolve_npm / resolve_pypi, and module_transport for go and crates)."""
    module = registry_module(eco)
    if module is not None:
        return module.resolve(name, version, module_fetch(module))
    return (resolve_npm if eco == "npm" else resolve_pypi)(name, version)


# ---------------- Artifact integrity (G15) ----------------
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _quote_seg(value):
    """Percent-encode one URL path segment (package name / version)."""
    return urllib.parse.quote(str(value), safe="")


def expected_digest(meta_entry):
    """Digest published by the registry for one artifact, from its metadata
    entry. npm: dist.integrity ("sha512-<base64>"); PyPI: digests.sha256 (hex).
    -> (alg, hexdigest) or None when the registry published no digest."""
    if not isinstance(meta_entry, dict):
        return None
    dist = meta_entry.get("dist") or {}
    if isinstance(dist, dict):
        integrity = dist.get("integrity")
        if isinstance(integrity, str) and "-" in integrity:
            alg, b64 = integrity.split("-", 1)
            if alg in ("sha256", "sha512"):
                try:
                    digest = base64.b64decode(b64, validate=True)
                except (ValueError, TypeError):
                    return None
                if digest and len(digest) == hashlib.new(alg).digest_size:
                    return alg, digest.hex()
    digests = meta_entry.get("digests") or {}
    if isinstance(digests, dict):
        sha = digests.get("sha256")
        if isinstance(sha, str) and _HEX64_RE.fullmatch(sha.strip().lower()):
            return "sha256", sha.strip().lower()
    return None


def verify_digest(data, meta_entry, eco, name, version):
    """Fail closed (SC-DIGEST-MISMATCH) when the downloaded artifact does not
    match the registry-published digest (G15). Any CDN/mirror compromise or
    host-hopping redirect then yields an error instead of an unverified blob
    whose verdict is persisted under the real name/version. Returns (alg,
    hexdigest) for the result dict, or None if no digest was published."""
    expected = expected_digest(meta_entry)
    if expected is None:
        return None
    alg, want = expected
    got = hashlib.new(alg, data).hexdigest()
    if got != want:
        raise DigestError(
            f"{eco}:{name}@{version} SC-DIGEST-MISMATCH: registry metadata says "
            f"{alg}={want[:16]}… but the downloaded artifact hashes to {got[:16]}… — "
            f"refusing to scan an unverified artifact (possible CDN/mirror "
            f"compromise or man-in-the-middle)")
    return alg, want


def _module_digest(module, data, meta_entry, eco, name, version):
    """verify_digest for a registry module's download: the module's check (a Go
    module's h1: from the checksum database, a crate's SHA-256 from the index),
    which fails closed in verify_digest's words. A module that resolves always
    has a digest to check (resolve fails without one); None only when the
    release names none, as verify_digest's."""
    try:
        return module.verify(data, meta_entry, name, version)
    except DigestError as exc:
        raise DigestError(
            f"{eco}:{name}@{version} SC-DIGEST-MISMATCH: {exc} — refusing to scan an "
            f"unverified artifact (possible CDN/mirror compromise or man-in-the-middle)") from None


# ---------------- In-memory archive reading ----------------
class ArchiveLimit(Exception):
    """Internal: reading stopped (reason 'total' | 'time' | 'corrupt')."""

    def __init__(self, reason, detail=""):
        super().__init__(detail or reason)
        self.reason, self.detail = reason, detail


class Budget:
    """Decompression and time budget for reading and scanning one archive.
    Every decompressed byte is charged — including member data tarfile skips
    over rather than returns — and the deadline / cancellation hook is
    checked between chunks and members while reading, and between files and
    phases while scanning. `deadline_detail` says which deadline it is (the
    per-archive --scan-timeout or the caller's, whichever comes first), for
    the SC-TRUNCATED message when it passes."""

    def __init__(self, total=None, deadline=None, cancel=None, deadline_detail=None):
        self.limit = MAX_ARCHIVE_TOTAL if total is None else total
        self.used = 0
        self.deadline = deadline
        self.cancel = cancel
        self.deadline_detail = deadline_detail

    def time_detail(self, where):
        """SC-TRUNCATED detail for this budget's deadline, stopped at `where`."""
        if self.deadline_detail:
            return f"{self.deadline_detail} (stopped at {where})"
        return _TRUNC_DETAILS["time"](where, 0)

    def charge(self, n):
        self.used += n
        if self.used > self.limit:
            raise ArchiveLimit("total")

    def check(self):
        if self.cancel is not None and self.cancel():
            raise ScanCancelled("scan cancelled")
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise ArchiveLimit("time")


_GZIP_MAGIC, _BZ2_MAGIC, _XZ_MAGIC = b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00"
_CODEC_MAGIC = {"gz": _GZIP_MAGIC, "bz2": _BZ2_MAGIC, "xz": _XZ_MAGIC}
_INPUT_CHUNK = 64 * 1024
_OUTPUT_CHUNK = 1024 * 1024


class _Inflater:
    """Read-only, forward-only file object over one compressed tar stream.

    Decompresses in bounded chunks with the container's REAL codec (gzip for
    npm and .tar.gz, bzip2/xz only for .tar.bz2/.tar.xz files, lzma's
    auto-detection for .tlz/.tar.lz/.tar.lzma as pip does), charges every
    produced byte to the budget, follows concatenated streams (gzip allows
    several members; node-tar reads them all), and keeps the last bytes it
    produced for the end-of-archive check. Data after the last stream that
    is not zero padding, or a stream cut short, raises ArchiveLimit('corrupt')."""

    def __init__(self, data, codec, budget):
        self.data, self.pos, self.codec, self.budget = memoryview(data), 0, codec, budget
        self.dec = self._decompressor() if codec != "tar" else None
        self.buf, self.tail = bytearray(), bytearray()
        self.produced, self.eof = 0, False

    def _decompressor(self):
        if self.codec == "gz":
            return zlib.decompressobj(31)
        if self.codec == "bz2":
            return bz2.BZ2Decompressor()
        if self.codec == "lzma":                  # .tlz / .tar.lz / .tar.lzma, as pip reads them
            return lzma.LZMADecompressor(format=lzma.FORMAT_AUTO)
        return lzma.LZMADecompressor(format=lzma.FORMAT_XZ)

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = _OUTPUT_CHUNK
        while len(self.buf) < n and not self.eof:
            self.budget.check()
            self._fill(n - len(self.buf))
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def _emit(self, out):
        if out:
            self.budget.charge(len(out))
            self.produced += len(out)
            self.buf += out
            self.tail += out[-1024:]
            del self.tail[:-1024]

    def _next_input(self):
        chunk = self.data[self.pos:self.pos + _INPUT_CHUNK]
        self.pos += len(chunk)
        return bytes(chunk)

    def _fill(self, want):
        want = min(max(want, _INPUT_CHUNK), _OUTPUT_CHUNK)
        if self.dec is None:                                   # plain tar
            chunk = self.data[self.pos:self.pos + want]
            self.pos += len(chunk)
            if not chunk:
                self.eof = True
            self._emit(bytes(chunk))
            return
        try:
            if self.codec == "gz":
                inp = self.dec.unconsumed_tail or self._next_input()
                if not inp and not self.dec.eof:
                    raise ArchiveLimit("corrupt", "compressed stream is truncated")
                out = self.dec.decompress(inp, want)
            else:
                inp = self._next_input() if self.dec.needs_input else b""
                if not inp and self.dec.needs_input and not self.dec.eof:
                    raise ArchiveLimit("corrupt", "compressed stream is truncated")
                out = self.dec.decompress(inp, want)
        except (zlib.error, OSError, lzma.LZMAError, EOFError, ValueError) as exc:
            raise ArchiveLimit("corrupt", f"decompression failed ({type(exc).__name__})") from None
        self._emit(out)
        if self.dec.eof:
            rest = bytes(self.dec.unused_data) + bytes(self.data[self.pos:])
            self.data, self.pos = memoryview(rest), 0
            if not rest or not rest.strip(b"\x00"):
                self.eof = True
            elif self.codec == "lzma" or rest.startswith(_CODEC_MAGIC[self.codec]):
                # concatenated stream (FORMAT_AUTO has no single magic: the
                # decoder decides, and data it can't read is corrupt)
                self.dec = self._decompressor()
            else:
                raise ArchiveLimit("corrupt", "data after the end of the compressed stream")


class _TarReader(tarfile.TarFile):
    """Records the blocks tarfile skips with ignore_zeros=True: zero blocks
    (end-of-archive markers) and invalid headers (a bad checksum). Python's
    tarfile used to STOP at either, while npm's node-tar skips a bad header
    and reads on — so what npm installed was never scanned."""

    def _dbg(self, level, msg):
        if level == 2 and isinstance(msg, str) and msg.startswith("0x") and ": " in msg:
            offset, _, what = msg.partition(": ")
            try:
                offset = int(offset, 16)
            except ValueError:
                offset = -1
            key = "_lazaret_zero_blocks" if what == "end of file header" else "_lazaret_bad_blocks"
            self.__dict__.setdefault(key, []).append(offset)
        super()._dbg(level, msg)


class _PipTarInfo(tarfile.TarInfo):
    """An sdist's member as pip reads it. pip unpacks with Python's tarfile,
    which extracts a member of a type no tool writes (`9`, `A`…) as a regular
    file, while the scan's loop took only regular files: a setup.py of such a
    type was run by pip and never read. Here it is a regular file, and the
    type the archive gave is kept in `odd_type` (None for a regular file). A
    device or a FIFO is not one pip extracts (it fails on it)."""

    odd_type = None

    def _odd(self):
        return self.type not in tarfile.SUPPORTED_TYPES

    def _proc_builtin(self, tarfile_):
        if self._odd():
            self.odd_type = self.type
            self.type = tarfile.REGTYPE
        return super()._proc_builtin(tarfile_)


class _CargoTarInfo(_PipTarInfo):
    """A .crate's member as cargo reads it. Cargo unpacks with Rust's `tar`
    crate, which reads every entry's data by its size and writes any entry
    that is not a directory, a link or one of the format's own headers as a
    regular file: a character or block device and a FIFO too (Python's
    tarfile reads the data of those as the next headers)."""

    def _odd(self):
        return self.type in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE) or super()._odd()


class Member(tuple):
    """(relative_path, real_size, raw_bytes, reason) with a .detail text for
    reasons that need one ('corrupt')."""

    def __new__(cls, rel, size, raw, reason, detail=""):
        self = super().__new__(cls, (rel, size, raw, reason))
        self.detail = detail
        return self


_DRIVE_ROOT_RE = re.compile(r"^(?:[A-Za-z]:)?/+")


def canonical_member_path(name, artifact=None):
    """Where an extractor puts an archive member, relative to the package
    root. -> (rel or None, problem or None).

    npm: exactly pacote's node-tar strip:1 — drop the FIRST path component
    whatever it is ('./decoy/setup.js' -> 'decoy/setup.js', never
    'setup.js'), strip absolute roots, refuse '..'; a member that ends up as
    the package root itself (a top-level file) is not extracted.
    wheel: paths are install paths, nothing stripped.
    sdist (and the legacy default): '.' / empty segments dropped, then the
    top directory. Backslashes count as separators (npm on Windows)."""
    p = str(name).replace("\\", "/")
    if artifact == "npm":
        rest = "/".join(p.split("/")[1:])
    elif artifact == "wheel":
        rest = p
    else:
        parts = [x for x in p.split("/") if x not in ("", ".")]
        rest = "/".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else "")
    while True:
        stripped = _DRIVE_ROOT_RE.sub("", rest)
        if stripped == rest:
            break
        rest = stripped
    if ".." in rest.split("/"):
        return None, "path contains '..'"
    norm = posixpath.normpath(rest) if rest else ""
    if norm in ("", "."):
        return None, None
    return norm, None


def strip_root(path):
    """Legacy helper: canonical_member_path() without artifact semantics."""
    rel, _problem = canonical_member_path(path)
    return rel if rel is not None else str(path).replace("\\", "/")


def _tar_codec(data, container, artifact):
    """The only codec a container may use -> 'gz' | 'bz2' | 'xz' | 'lzma' | 'tar'.
    Raises ArchiveLimit('corrupt') on a mismatch: a bzip2 or xz stream served
    as an npm .tgz is rejected, not decompressed (pip opens .tar.gz with
    r:gz; npm auto-detects gzip and otherwise reads plain tar). 'lzma' (the
    .tlz family) is lzma's FORMAT_AUTO, which is what pip's r:xz reads."""
    head = bytes(data[:6])
    is_tar = len(data) >= 262 and bytes(data[257:262]) == b"ustar"
    want = {"tgz": "gz", "tbz2": "bz2", "txz": "xz", "tar": "tar", "tlz": "lzma"}.get(container, "gz")
    if want == "gz" and head.startswith(_GZIP_MAGIC):
        return "gz"
    if want == "gz" and artifact in (None, "npm") and (is_tar or not head.startswith(
            (_BZ2_MAGIC, _XZ_MAGIC, b"PK", b"(\xb5/\xfd"))):
        return "tar"                   # node-tar reads uncompressed tarballs too
    if want in ("bz2", "xz") and head.startswith(_CODEC_MAGIC[want]):
        return want
    if want == "lzma" and not head.startswith((_GZIP_MAGIC, _BZ2_MAGIC, b"PK", b"(\xb5/\xfd")):
        return "lzma"                  # xz or legacy lzma: the decoder tells them apart
    if want == "tar":
        return "tar"
    found = next((k for k, magic in _CODEC_MAGIC.items() if head.startswith(magic)), "unknown")
    raise ArchiveLimit("corrupt", f"{container} artifact is {found}-compressed; "
                                  f"only {'xz/lzma' if want == 'lzma' else want} is accepted "
                                  f"for this format")


def _note_member(seen, rel, anomalies):
    if rel in seen:
        if seen[rel] == 1:
            anomalies.append(("dup", rel, "two archive entries extract to this path; "
                                          "the later one wins"))
        seen[rel] += 1
    else:
        seen[rel] = 1


def iter_archive(data, container, artifact=None, *, budget=None, anomalies=None):
    """Yield Member(relative_path, real_size, raw_bytes, reason) for every file
    an installer would extract from the archive.

    Verdict-integrity fix (audit C2/G16): sizes are REAL decompressed byte
    counts, never the archive-declared file_size/tar m.size — a hostile
    archive used to declare >MAX_MEMBER and skip scanning entirely with zero
    signal. Reading is bounded at MAX_MEMBER+1 per member, and every
    decompressed byte (skipped member data included) is charged to the
    budget, so neither a lying header nor a decompression bomb can exhaust
    memory or time.

    Paths are canonicalized like the installer does it (canonical_member_path).
    In-archive links in sdists and wheels are resolved and their target's
    content is yielded under the link's name (pip extracts them); npm drops
    links (pacote), so they are skipped there. Structural problems that do
    not stop the scan — duplicate paths, links out of the archive, '..'
    entries — are appended to `anomalies` as (kind, path, detail).

    reason is None for a fully-read member, or:
      "member"  — more than MAX_MEMBER bytes; only the first SAMPLE bytes are
                  returned, so the caller can classify but not scan it.
      "files"   — more than MAX_FILES entries; iteration stops.
      "total"   — the decompression budget is spent; iteration stops.
      "time"    — the scan deadline passed; iteration stops.
      "corrupt" — the archive is damaged or ambiguous (bad header block,
                  entries after an end-of-archive block, trailing data, a
                  truncated or wrongly compressed stream); .detail says what."""
    budget = budget if budget is not None else Budget()
    anomalies = anomalies if anomalies is not None else []
    if container == "zip":
        members = _iter_zip(data, artifact, budget, anomalies)
    else:
        members = _iter_tar(data, container, artifact, budget, anomalies)
    yield from _timed_members(members)


def _timed_members(members):
    """`members`, the seconds spent reading each (not the caller's, between
    them) in the archive phase of `--timings`; closed when the caller stops."""
    try:
        while True:
            with timings.span("archive", "iter_archive"):
                try:
                    member = next(members)
                except StopIteration:
                    return
            yield member
    finally:
        members.close()


def _iter_tar(data, container, artifact, budget, anomalies):
    last = "(archive)"
    try:
        codec = _tar_codec(data, container, artifact)
        reader = _Inflater(data, codec, budget)
        # (npm's node-tar writes regular files only, and skips the rest)
        kinds = {"crate": {"tarinfo": _CargoTarInfo}, "npm": {}}.get(artifact, {"tarinfo": _PipTarInfo})
        tf = _TarReader.open(fileobj=reader, mode="r|", ignore_zeros=True, **kinds)
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
        return
    except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt", f"not a readable tar archive ({type(exc).__name__})")
        return
    seen, links, offsets, count = {}, [], [], 0
    try:
        for m in tf:
            budget.check()
            offsets.append(m.offset)
            if m.isdir():
                continue
            rel, problem = canonical_member_path(m.name, artifact)
            if m.issym() or m.islnk():
                if artifact != "npm":                  # pacote drops links
                    links.append((m.name, m.linkname, m.issym(), rel, problem))
                continue
            if not m.isfile():
                continue
            if problem:
                anomalies.append(("path", m.name, problem))
                continue
            if rel is None:
                continue                               # the extractor drops it
            if getattr(m, "odd_type", None) is not None:
                anomalies.append(("type", rel, f"a tar entry of type {m.odd_type.decode('latin-1')!r}, which "
                                               f"{'cargo' if artifact == 'crate' else 'pip'} writes as a regular file "
                                               f"and other tar readers skip"))
            count += 1
            if count > MAX_FILES:
                yield Member(rel, 0, b"", "files")
                return
            _note_member(seen, rel, anomalies)
            last = rel
            f = tf.extractfile(m)
            raw = f.read(MAX_MEMBER + 1) if f is not None else b""
            if len(raw) > MAX_MEMBER:
                yield Member(rel, SAMPLE, raw[:SAMPLE], "member")
                continue
            yield Member(rel, len(raw), raw, None)
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
        return
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt",
                     f"archive could not be read past {last} ({type(exc).__name__})")
        return
    bad = tf.__dict__.get("_lazaret_bad_blocks", [])
    zeros = tf.__dict__.get("_lazaret_zero_blocks", [])
    if bad:
        yield Member("(archive)", 0, b"", "corrupt",
                     f"{len(bad)} invalid tar header block(s) skipped (first at byte "
                     f"{bad[0]:#x}); tar readers disagree about what follows")
    if zeros and offsets and max(offsets) > min(zeros):
        yield Member("(archive)", 0, b"", "corrupt",
                     "entries follow an end-of-archive block; pip stops reading there "
                     "while npm reads on")
    leftover = reader.produced - tf.offset
    if 0 < leftover <= len(reader.tail) and reader.tail[-leftover:].strip(b"\x00"):
        yield Member("(archive)", 0, b"", "corrupt", "data after the last tar entry")
    if links:
        yield from _resolve_tar_links(data, codec, artifact, links, seen, budget, anomalies, count)


def _link_target(member_name, linkname, symbolic):
    """Archive path a link points to, or None when it leaves the archive."""
    linkname = str(linkname).replace("\\", "/")
    if linkname.startswith("/") or _DRIVE_ROOT_RE.match(linkname):
        return None
    base = posixpath.dirname(str(member_name).replace("\\", "/")) if symbolic else ""
    target = posixpath.normpath(posixpath.join(base, linkname))
    if target == ".." or target.startswith("../"):
        return None
    return target


def _link_plan(links, artifact, anomalies):
    """{target rel: [link rel, ...]} with link chains followed (8 hops)."""
    by_rel = {}
    for name, linkname, symbolic, rel, problem in links:
        if problem or rel is None:
            if problem:
                anomalies.append(("path", name, problem))
            continue
        target = _link_target(name, linkname, symbolic)
        if target is None:
            anomalies.append(("link", rel, f"link to {linkname!r} points outside the archive"))
            continue
        # tar link targets are archive paths: canonicalize them like members
        trel, tproblem = canonical_member_path(target, artifact)
        if tproblem or trel is None:
            anomalies.append(("link", rel, f"link to {linkname!r} points outside the archive"))
            continue
        by_rel[rel] = trel
    plan = {}
    for rel, trel in by_rel.items():
        hops = 0
        while trel in by_rel and hops < 8:
            trel, hops = by_rel[trel], hops + 1
        plan.setdefault(trel, []).append(rel)
    return plan


def _resolve_tar_links(data, codec, artifact, links, seen, budget, anomalies, count):
    plan = _link_plan(links, artifact, anomalies)
    if not plan:
        return
    last = "(archive)"
    try:
        reader = _Inflater(data, codec, budget)
        tf = tarfile.open(fileobj=reader, mode="r|", ignore_zeros=True)
        for m in tf:
            budget.check()
            if not m.isfile():
                continue
            rel, _problem = canonical_member_path(m.name, artifact)
            if rel not in plan:
                continue
            f = tf.extractfile(m)
            raw = f.read(MAX_MEMBER + 1) if f is not None else b""
            for link_rel in plan.pop(rel):
                count += 1
                if count > MAX_FILES:
                    yield Member(link_rel, 0, b"", "files")
                    return
                _note_member(seen, link_rel, anomalies)
                last = link_rel
                if len(raw) > MAX_MEMBER:
                    yield Member(link_rel, SAMPLE, raw[:SAMPLE], "member")
                else:
                    yield Member(link_rel, len(raw), raw, None)
            if not plan:
                return
    except ArchiveLimit as lim:
        yield Member(last, 0, b"", lim.reason, lim.detail)
    except (tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError) as exc:
        yield Member(last, 0, b"", "corrupt", f"links could not be resolved ({type(exc).__name__})")


def _zip_is_symlink(info):
    return (info.external_attr >> 16) & 0o170000 == 0o120000


_ZIP_EOCD_SIG, _ZIP64_LOC_SIG, _ZIP64_EOCD_SIG = b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"
_ZIP_CD_SIG = b"PK\x01\x02"
_ZIP_EOCD = struct.Struct("<4s4H2LH")            # 22 bytes
_ZIP64_LOC = struct.Struct("<4sLQL")             # 20 bytes
_ZIP64_EOCD = struct.Struct("<4sQ2H2L4Q")        # 56 bytes
# Largest central directory read (bytes). zipfile reads it whole and builds
# one ZipInfo per record before any file cap can apply; MAX_FILES records
# with long names fit easily in this.
MAX_ZIP_CENTRAL_DIR = 64 * 1024 * 1024


def _zip_preflight(data, max_files=None):
    """Refuse a zip whose central directory is too big to parse, BEFORE
    zipfile.ZipFile() reads it -> None (fine) or the reason. `max_files`:
    the most entries (MAX_FILES; a Go module zip's limit is Go's).

    zipfile parses the whole central directory — ~340 MB and 4 s for a
    million records — before MAX_FILES can apply. Read the End Of Central
    Directory record (and the ZIP64 one) the same way zipfile finds it,
    and refuse when the declared entry count exceeds MAX_FILES, the
    declared directory size is implausible, or the directory region holds
    more than MAX_FILES record signatures (a count field can lie; zipfile
    parses records until the declared SIZE is consumed). Anything this
    reader can't make sense of is left to zipfile, which reports it."""
    max_files = MAX_FILES if max_files is None else max_files
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    n = len(data)
    if n >= _ZIP_EOCD.size and data[n - 22:n - 18] == _ZIP_EOCD_SIG and data[n - 2:] == b"\0\0":
        pos = n - 22
    else:                                       # an archive comment follows the EOCD
        pos = data.rfind(_ZIP_EOCD_SIG, max(0, n - 65535 - _ZIP_EOCD.size))
        if pos < 0 or pos + _ZIP_EOCD.size > n:
            return None
    (_sig, _disk, _cd_disk, count_disk, count, cd_size, _cd_offset,
     _comment) = _ZIP_EOCD.unpack_from(data, pos)
    counts, sizes, records = [], [], [pos]
    loc = pos - _ZIP64_LOC.size
    if loc >= 0 and data[loc:loc + 4] == _ZIP64_LOC_SIG:
        _sig, _disk, reloff, _disks = _ZIP64_LOC.unpack_from(data, loc)
        # zipfile reads the record at the offset the locator names or,
        # depending on the version, right before the locator: check both
        for rec in {reloff, loc - _ZIP64_EOCD.size}:
            if 0 <= rec <= n - _ZIP64_EOCD.size and data[rec:rec + 4] == _ZIP64_EOCD_SIG:
                fields = _ZIP64_EOCD.unpack_from(data, rec)
                counts += [fields[6], fields[7]]
                sizes.append(fields[8])
                records.append(rec)
    if not sizes:          # no ZIP64 record: the classic fields are the real ones
        counts, sizes = [count_disk, count], [cd_size]
    declared = max(counts)
    if declared > max_files:
        return (f"zip central directory declares {declared:,} entries — more than the "
                f"{max_files:,}-file limit; the archive was not opened")
    size = max(sizes)
    if size > MAX_ZIP_CENTRAL_DIR:
        return (f"zip central directory declares {size:,} bytes — more than the "
                f"{MAX_ZIP_CENTRAL_DIR:,}-byte limit; the archive was not opened")
    # the records zipfile will parse lie in the `size` bytes before the
    # (ZIP64) end record; count their signatures without copying
    start = max(0, min(records) - size)
    found = data.count(_ZIP_CD_SIG, start, pos)
    if found > max_files:
        return (f"zip central directory holds more than {max_files:,} entries "
                f"({found:,} records, {declared:,} declared); the archive was not opened")
    return None


# What reading one zip member can raise (bad CRC, broken deflate/bz2/lzma
# stream, an encrypted or unsupported entry, a bad local header; an LZMA
# dictionary the host can't allocate: fuzz finding F-7).
_ZIP_READ_ERRORS = (zipfile.BadZipFile, OSError, EOFError, ValueError, zlib.error,
                    lzma.LZMAError, NotImplementedError, RuntimeError, MemoryError)
#: The largest LZMA dictionary a zip entry may declare (xz -9 and 7-Zip's
#: ultra level use 64 MiB). zipfile allocates it before a byte is decoded:
#: a 625-byte wheel declaring 4 GiB ended the scan with MemoryError on a host
#: whose memory is capped (F-7). Wheels are stored or deflated (PEP 427).
MAX_LZMA_DICT = 64 << 20
_ZIP_LOCAL = struct.Struct("<4s22xHH")       # signature ... name length, extra length


def _lzma_dict_size(data, info):
    """The dictionary size an LZMA zip entry declares (zipfile's format: a
    version, the properties' size, then lc/lp/pb and the dictionary, after
    the local header), or None when the entry isn't one or can't say."""
    if info.compress_type != zipfile.ZIP_LZMA:
        return None
    at = info.header_offset
    if at < 0 or at + _ZIP_LOCAL.size > len(data):
        return None
    sig, n_name, n_extra = _ZIP_LOCAL.unpack_from(data, at)
    start = at + _ZIP_LOCAL.size + n_name + n_extra
    head = data[start:start + 9]
    if sig != b"PK\x03\x04" or len(head) < 9 or int.from_bytes(head[2:4], "little") != 5:
        return None
    return int.from_bytes(head[5:9], "little")


def _zip_overlaps(data, infos):
    """The names of zip entries whose bytes begin inside an earlier entry's
    (by local header offset): the shape of a zip bomb. zipfile 3.12.3+ warns
    of some and raises for others; this says the same on every version (F-2)."""
    spans = []
    for info in infos:
        at = info.header_offset
        if at < 0 or at + _ZIP_LOCAL.size > len(data):
            continue
        sig, n_name, n_extra = _ZIP_LOCAL.unpack_from(data, at)
        if sig == b"PK\x03\x04":
            spans.append((at, at + _ZIP_LOCAL.size + n_name + n_extra + info.compress_size, info.filename))
    out, reach = [], -1
    for at, end, name in sorted(spans):
        if at < reach:
            out.append(name)
        reach = max(reach, end)
    return out


def _iter_zip(data, artifact, budget, anomalies):
    refused = _zip_preflight(data)
    if refused:
        yield Member("(archive)", 0, b"", "files", refused)
        return
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, EOFError, ValueError,
            NotImplementedError, RuntimeError) as exc:
        yield Member("(archive)", 0, b"", "corrupt", f"not a readable zip archive ({type(exc).__name__})")
        return
    seen, count, last = {}, 0, "(archive)"

    def read(info, rel, limit):
        dictionary = _lzma_dict_size(data, info)
        if dictionary is not None and dictionary > MAX_LZMA_DICT:
            raise ValueError(f"an LZMA dictionary of {dictionary:,} bytes, over the {MAX_LZMA_DICT:,}-byte limit")
        # zipfile 3.12.3+ warns of entries that overlap: _zip_overlaps names
        # them, so the warning is no line on stderr or, under -W error, an
        # exception out of the reader (F-2)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with zf.open(info) as fh:
                raw = fh.read(limit)
        budget.charge(len(raw))
        return raw

    for name in _zip_overlaps(data, infos):
        anomalies.append(("overlap", name, "its bytes overlap another entry's"))
    with zf:
        try:
            for info in infos:
                budget.check()
                if not info.filename:
                    # no extractor can place it, and Python 3.10's is_dir()
                    # raised IndexError on it (F-6); 3.11+ dropped it silently
                    anomalies.append(("noname", "(archive)", "an entry with no name, which was not read"))
                    continue
                if info.is_dir():
                    continue
                rel, problem = canonical_member_path(info.filename, artifact)
                if problem:
                    anomalies.append(("path", info.filename, problem))
                    continue
                if rel is None:
                    continue
                count += 1
                if count > MAX_FILES:
                    yield Member(rel, 0, b"", "files")
                    return
                if _zip_is_symlink(info):
                    # pip ignores a zip entry's symlink mode bits: it installs
                    # the stored bytes as a regular file (wheels and zip sdists
                    # alike), so those bytes are what is scanned. Lazaret used to
                    # read them as a link target and skip the entry when no
                    # member had that name: code pip installs went unscanned.
                    anomalies.append(("ziplink", rel, "pip installs its stored bytes as a regular "
                                                      "file, which is what was scanned; unzip "
                                                      "would create a symlink instead"))
                _note_member(seen, rel, anomalies)
                last = rel
                try:
                    raw = read(info, rel, MAX_MEMBER + 1)     # bounded, real bytes
                except _ZIP_READ_ERRORS as exc:
                    why = str(exc) if str(exc).startswith("an LZMA dictionary") else type(exc).__name__
                    yield Member(rel, 0, b"", "corrupt", f"member {rel} could not be read ({why})")
                    continue
                if len(raw) > MAX_MEMBER:
                    yield Member(rel, SAMPLE, raw[:SAMPLE], "member")
                    continue
                yield Member(rel, len(raw), raw, None)
        except ArchiveLimit as lim:
            yield Member(last, 0, b"", lim.reason, lim.detail)


# Detail text for each truncation reason (verdict integrity, audit C2/G16).
_TRUNC_DETAILS = {
    "member": lambda rel, size: (
        f"{rel} is larger than the {MAX_MEMBER:,}-byte source-scan limit, so it was "
        f"not scanned (raise the limit with --max-source-bytes)"),
    "files": lambda rel, size: (
        f"archive holds more than {MAX_FILES:,} file entries — entry order is "
        f"attacker-controlled (stopped at {rel})"),
    "total": lambda rel, size: (
        f"cumulative decompressed archive size exceeds {MAX_ARCHIVE_TOTAL:,} "
        f"bytes (stopped at {rel})"),
    "time": lambda rel, size: (
        f"scan time budget of {SCAN_TIMEOUT:g} s exceeded (stopped at {rel})"),
}
# Hard cap on SC-TRUNCATED findings per package so a hostile archive with
# thousands of oversize members cannot flood the report; the `truncated`
# count in the result always reflects the true number.
TRUNCATED_FINDING_CAP = 20


# ---------------- Verdicts ----------------
# The registry verdict answers one question: does this package look malicious?
#   SUSPICIOUS  a strong supply-chain indicator (CRITICAL/BLOCKER SC-* finding):
#               decode-then-execute, packed code, an install script that ships
#               data off the machine, hidden code in hex escapes, ...
#   INCOMPLETE  part of the package could not be scanned, so it cannot be
#               cleared; nothing strong was found in the part that was.
#   WARN        weaker indicators or capabilities worth a look: install hooks,
#               shipped binaries, opaque blobs.
#   OK          none of the above.
# Secrets and code-quality findings are reported but never decide the verdict:
# a test key inside someone else's package is not a threat to you.
STRONG_SEVERITIES = ("BLOCKER", "CRITICAL")
VERDICT_RANK = {"OK": 0, "WARN": 1, "INCOMPLETE": 2, "SUSPICIOUS": 3}
# Rules that mean "not fully scanned": they make a scan INCOMPLETE instead
# of counting as indicators.
TRUNCATION_RULES = ("SC-TRUNCATED", "SC-MANIFEST-UNPARSEABLE", "SC-UNREAD-CODE")
# N-1 (0.1.9): code in a language the engine has no detectors for, by the
# artifact that ships it: such an artifact is never OK, one SC-UNREAD-CODE
# finding says what was not read, and the verdict is INCOMPLETE. A Go
# module's .go files and a crate's .rs files were such code until the Go and
# Rust readers (G-1, R-1) were wired in (Part C): they are read now
# (PACKAGE_CODE), so none is left here; the finding stays for code a reader
# could not hold (_package_code).
UNREAD_CODE = {}
UNREAD_CODE_RULE = "SC-UNREAD-CODE"
# The code a module or a crate is read for, by artifact: (its language, the
# extensions of its source, the extensions of the other files its reader
# reads). A Go module's .go files are read with its cgo packages' C (.c, .h);
# a crate's .rs files. Each source file gets the file rules too (dependency
# mode, as a package's JavaScript and Python do).
PACKAGE_CODE = {"gomod": ("go", (".go",), (".c", ".h")), "crate": ("rs", (".rs",), ())}
# The most a reader takes of one module or crate, in characters: the reader
# holds all of it at once (the text, each file's tree), so a larger one is
# not read and the scan is INCOMPLETE (aws-sdk-go v1, Go's largest module in
# common use, is 207 million characters of Go and peaks at 2.4 GB read).
PACKAGE_CODE_CHARS = lazaret.PACKAGE_CODE_CHARS        # (300,000,000; --deps reads with core's)
# Directory names that hold tests / fixtures (exact names, case-insensitive).
# Weaker findings in them are listed as INFO unless the file is reachable from
# an entry point (main/bin/exports, an install hook, setup.py).
TEST_DIR_NAMES = {"test", "tests", "testing", "__tests__", "spec", "specs", "fixtures",
                  "__fixtures__", "testdata", "test_data", "test-data", "test-fixtures",
                  "unittests", "test cases"}
_TEST_FILE_RE = re.compile(r"(?:^test_.*\.py|.*_test\.(?:py|go)|.*\.(?:test|spec)\.[cm]?[jt]sx?)$", re.I)


def is_test_path(rel):
    parts = rel.replace("\\", "/").split("/")
    return (any(_is_test_dir(part.lower()) for part in parts[:-1])
            or bool(_TEST_FILE_RE.match(parts[-1])))


def _is_test_dir(name):
    # exact names only: testkit/, testutils/, attestation/ are code, not tests
    return name in TEST_DIR_NAMES


# The strong shapes anywhere in a package (SC-USE-RISK, 0.1.8). The
# import-time test reads what runs at install and import; a payload in a
# module the package only runs when it is used — a logger's constructor, a
# middleware, a script a CLI spawns — was never read by it (about 20 of the
# 0.1.7 benchmark's 50 decode-or-download-then-run misses, and 11 stealers).
# Every other JavaScript or Python file the package ships now gets the same
# test, and counts only for the shapes no library needs (import_time_severity
# CRITICAL); the weaker ones stay unread there, so the benign rate is the
# import-time test's. Files that never run in Node or Python when the package
# is used are left out: tests and fixtures (is_test_path), examples, docs,
# demos and benchmarks, and a web app's static assets (a Next.js export's
# _next/static chunks: one minified line held an exec call and a `curl … | sh`
# string, the only popular package of 429 the test flagged anywhere).
USE_RISK_SKIP_DIRS = {"example", "examples", "doc", "docs", "demo", "demos", "sample", "samples", "benchmark",
                      "benchmarks", "bench", "__mocks__", "_next", "static", "public"}
# The test costs time on every file it reads, so it reads none once the
# package is SUSPICIOUS anyway (the Shai-Hulud 2.0 releases' 10 MB
# bun_environment.js took 10 s each, and changed no verdict), no file of more
# than USE_RISK_MAX_CHARS characters, and at most USE_RISK_CHARS characters
# per archive, smallest files first. The bound is work, not time, so every
# machine reads the same files (P-14). It was 3 s per archive, which read
# less on a slower machine, and the report didn't say. 24 million characters
# read what 3 s read on two cores, at the same cost: all of a litellm wheel's
# 20 million, 32% of next 16.3.8's 74 million (3 s: 26%). Reading all of
# next's made its scan 32 s instead of 14 s. What it did not read is not "not
# scanned" — the rules of the file scan read every file — so the verdict is
# not INCOMPLETE; the artifact's "useTime" says how much it read.
USE_RISK_MAX_CHARS = lazaret.USE_RISK_MAX_CHARS        # (8,000,000)
USE_RISK_CHARS = lazaret.USE_RISK_CHARS                # (24,000,000)
# The native engine reads a batch of files at a time; the archive's deadline
# (Budget) is checked between batches, which hold at most
# USE_RISK_BATCH_CHARS characters (or one file) in this step.
USE_RISK_BATCH_CHARS = 1_000_000


def _not_used_code(rel):
    """Is `rel` a file the package does not run when it is used (see above)?"""
    parts = rel.replace("\\", "/").split("/")
    return is_test_path(rel) or any(part.lower() in USE_RISK_SKIP_DIRS for part in parts[:-1])


def _demote_test_findings(issues, reachable=frozenset()):
    """Weaker supply-chain findings inside test code become inventory (INFO):
    test fixtures legitimately contain binaries, blobs and escaped bytes, and
    tests are neither imported nor run when the package is installed. Strong
    findings are never demoted: hiding a payload in tests/ doesn't make it safe.
    Nor is anything reachable from an entry point: a main that points into
    test/ makes that code the package."""
    for issue in issues:
        if (issue["rule"].startswith("SC-") and issue["rule"] not in TRUNCATION_RULES
                and issue["sev"] not in STRONG_SEVERITIES + ("INFO",)
                and issue["file"] not in reachable
                and is_test_path(issue["file"])):
            issue["sev"] = "INFO"
            issue["msg"] = issue["msg"].rstrip() + " (in test code: listed, not counted)"


def decide_verdict(issues, truncated):
    """-> (verdict, reason, strong_count, weak_count)."""
    # a truncation finding always counts, even one that reached `issues`
    # without going through _ArtifactScan.truncate (verdict integrity)
    unread = sorted({i["name"].removesuffix(" code not read") for i in issues if i["rule"] == UNREAD_CODE_RULE})
    truncated = max(truncated, len({i.get("file") for i in issues
                                    if i["rule"] in TRUNCATION_RULES and i["rule"] != UNREAD_CODE_RULE}))
    indicators = [i for i in issues if i["rule"].startswith("SC-")
                  and i["rule"] not in TRUNCATION_RULES and i["sev"] != "INFO"]
    strong = sum(1 for i in indicators if i["sev"] in STRONG_SEVERITIES)
    weak = len(indicators) - strong
    plural = lambda n, word: f"{n} {word}{'' if n == 1 else 's'}"
    if strong:
        return "SUSPICIOUS", plural(strong, "strong supply-chain indicator"), strong, weak
    if truncated or unread:
        parts = ([f"{plural(truncated, 'part')} not fully scanned"] if truncated else []) + (
            [f"its {' and '.join(unread)} code not read (Lazaret has no {' or '.join(unread)} detectors yet)"]
            if unread else [])
        return ("INCOMPLETE", f"scan incomplete: {', and '.join(parts)}, so the package can't be cleared",
                strong, weak)
    if weak:
        return "WARN", plural(weak, "weaker supply-chain indicator") + " to review", strong, weak
    return "OK", "no supply-chain indicators", strong, weak


# The install-script and import-time tests live in the scanner, which runs
# them on the dependencies of a --deps project scan too; the registry uses the
# same functions.
_NETWORK_RE = lazaret._NETWORK_RE
_EXFIL_SERVICES = lazaret._EXFIL_SERVICES
_EXFIL_SERVICE_RE = lazaret._EXFIL_SERVICE_RE
_PIPE_SCAN_RE = lazaret._PIPE_SCAN_RE
_pipes_download_to_shell = lazaret._pipes_download_to_shell
install_script_risk = lazaret.install_script_risk
_EXEC_CALL_RE = lazaret._EXEC_CALL_RE
import_time_risk = lazaret.import_time_risk
_node_candidates = lazaret.node_candidates


def _rel_join(base, target):
    target = str(target).replace("\\", "/")
    if target.startswith("/"):
        target = target.lstrip("/")
    joined = posixpath.normpath(posixpath.join(base or ".", target))
    return "" if joined in (".", "") else joined


# Entry points declared in package.json: what `require(pkg)`, `import pkg`
# and the installed command run, as (target, exported) pairs: `exported` for
# the targets of "exports", which may be assets a bundler loads. A target
# under a subpath-pattern key ("./*": "./lib/*.js") keeps its "*": it stands
# for any subpath, and _ArtifactScan expands it against the archive (these
# used to be skipped, so "./*": "./lib/*.dat" exported unscanned code).
def _package_entry_targets(data):
    targets = []
    main = data.get("main")
    # no main: require(pkg) loads index.js
    targets.append((main if isinstance(main, str) and main.strip() else "index.js", False))
    bins = data.get("bin")
    if isinstance(bins, str):
        targets.append((bins, False))
    elif isinstance(bins, dict):
        targets += [(v, False) for v in bins.values() if isinstance(v, str)]
    stack, nodes = [(data.get("exports"), False)], 0
    while stack and nodes < 10_000:
        node, pattern = stack.pop()
        nodes += 1
        if isinstance(node, str):
            # a "*" outside a pattern key is taken literally by Node: skipped as before
            if node.startswith("./") and (pattern or "*" not in node):
                targets.append((node, True))
        elif isinstance(node, dict):
            stack.extend((v, pattern or (isinstance(k, str) and "*" in k)) for k, v in node.items())
        elif isinstance(node, list):
            stack.extend((v, pattern) for v in node)
    return targets


def _pattern_regex(pattern):
    """Regex for the members an exports pattern target resolves to: Node puts
    the matched subpath (non-empty; it may contain '/') in place of every
    '*' of the target."""
    head, *tails = pattern.split("*")
    return re.compile(re.escape(head) + "(.+)" + re.escape(tails[0])
                      + "".join(r"\1" + re.escape(t) for t in tails[1:]))


_JS_LOCAL_DEP_RE = re.compile(
    r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s+|^\s*import\s+|\bexport\s+[^'"\n;]*?\bfrom\s+)"""
    r"""(['"])(\.{1,2}/[^'"\n]+)\1""", re.M)
_MANIFEST_NAMES = ("package.json", "binding.gyp", "pyproject.toml")
# A script's language by its #! line: the scanner's (project and --deps scans
# read such scripts as source too).
_SHEBANG_RE = lazaret._SHEBANG_RE
_shebang_lang = lazaret.shebang_lang


# SC-PTH-EXEC lives in the scanner (project and --deps scans check .pth files
# too); the registry uses the same function, so the two can't drift.
_PTH_EXEC_RE = lazaret._PTH_EXEC_RE
pth_issues = lazaret.pth_issues

# A wheel's top level (and its .data/purelib|platlib) is installed into
# site-packages, where site.py imports sitecustomize — and usercustomize,
# when the user site is enabled — at EVERY interpreter start, like a .pth
# file's import lines.
_STARTUP_MODULE_RE = re.compile(
    r"^(?:[^/]+\.data/(?:purelib|platlib)/)?(sitecustomize|usercustomize)(?:\.py|/__init__\.py)$")
# What `import <name>` runs from a wheel: a top-level package's __init__.py or
# a top-level module (a single-module distribution)
_WHEEL_TOP_MODULE_RE = re.compile(
    r"^(?:[^/]+\.data/(?:purelib|platlib)/)?(?![^/]*\.(?:dist-info|data)/)[^/]+(?:/__init__)?\.py$")
# What `import <name>` runs from an installed sdist: a top-level package's
# __init__.py or a top-level module, at the sdist's root or in src/ — not the
# build and test tooling that ships next to them
_SDIST_TOP_MODULE_RE = re.compile(
    r"^(?:src/)?(?!(?:tests?|testing|docs?|examples?|benchmarks?|scripts?|tools|ci|build)/)[^/]+(?:/__init__)?\.py$")
_SDIST_NOT_MODULES = frozenset((
    "setup.py", "conftest.py", "noxfile.py", "fabfile.py", "manage.py", "runtests.py", "versioneer.py",
    "pavement.py", "ez_setup.py", "distribute_setup.py", "bootstrap.py", "tasks.py"))
# the directory prefix the modules of a root live under (a wheel's
# .data/purelib/, an sdist's src/), for absolute imports
_PY_BASE_RE = re.compile(r"^((?:[^/]+\.data/(?:purelib|platlib)|src)/)")
_PY_REACH_MAX = 300
# `import a.b`, `from a.b import c, d`, `from .x import (a, b)`, `from . import a`
_PY_IMPORT_STMT_RE = re.compile(
    r"^[ \t]*(?:from[ \t]+(?P<dots>\.*)(?P<mod>[A-Za-z_][\w.]*)?[ \t]+import[ \t]+(?P<names>\([^)]{0,2000}\)|[^\n#;]{0,2000})"
    r"|import[ \t]+(?P<imod>[A-Za-z_][\w.]*))", re.M)


def _import_names(names):
    """The plain names of an import list (`a, b as c`, `(a,\n b)`); not *."""
    if not names:
        return []
    out = []
    for part in names.strip().strip("()").split(","):
        name = part.strip().split(" as ")[0].strip()
        if name.isidentifier():
            out.append(name)
    return out[:50]


def startup_module_issue(rel, text):
    """SC-SITECUSTOMIZE for a start-up module a wheel installs: MAJOR (a
    capability to review, like SC-PTH-EXEC), CRITICAL when the code looks
    hostile by the install-script test (install_script_risk)."""
    module = _STARTUP_MODULE_RE.match(rel).group(1)
    reasons = _engine.install_script_risk(text, lang="py")
    msg = f"{rel} is installed as {module} in site-packages, which Python imports at every start"
    msg += f", and it {'; and '.join(reasons)}." if reasons else "."
    return lazaret.mk_issue(
        {"id": "SC-SITECUSTOMIZE", "name": "Start-up module", "type": "HOTSPOT",
         "sev": "CRITICAL" if reasons else "MAJOR", "msg": msg,
         "why": ("site.py imports sitecustomize (and usercustomize, when the user site is "
                 "enabled) whenever the interpreter starts, whether or not the package is "
                 "imported — the persistence and execution vector of a .pth file, with no "
                 "install hook."),
         "fix": "Find out why the package ships a start-up module; remove it if unexplained.",
         "ref": "CWE-506 · Supply chain"}, rel, 1, lazaret.normalize_newlines(text).split("\n"))


def _archive_issue(kind, path, detail):
    rules = {
        "dup": ("SC-ARCHIVE-DUP", "Duplicate archive path",
                "Two entries in the archive extract to the same path, so what a reviewer "
                "(or a scanner reading the first) sees is not what gets installed."),
        "link": ("SC-ARCHIVE-LINK", "Archive link leaves the package",
                 "A symlink or hardlink pointing outside the extraction directory can make "
                 "the installer read or overwrite files elsewhere on the machine."),
        "ziplink": ("SC-ARCHIVE-LINK", "Zip entry marked as a symlink",
                    "pip ignores the mark and installs the entry's bytes as a regular file, "
                    "while unzip creates a symlink: the same archive installs differently, and "
                    "no packaging tool produces one."),
        "path": ("SC-ARCHIVE-PATH", "Unsafe archive path",
                 "An entry with '..' in its path tries to escape the extraction directory; "
                 "installers refuse it, and no legitimate package tool produces one."),
        "noname": ("SC-ARCHIVE-PATH", "Unnamed archive entry",
                   "No extractor can place an entry with no name: installers fail on it or skip it, so "
                   "its bytes are neither installed nor reviewed, and no packaging tool produces one."),
        "overlap": ("SC-ARCHIVE-OVERLAP", "Overlapping archive entries",
                    "Two entries of the zip archive share their bytes: the shape of a zip bomb (one "
                    "compressed stream counted many times), and no packaging tool produces one."),
        "type": ("SC-ARCHIVE-TYPE", "Archive entry of an unusual type",
                 "pip writes a tar entry of a type no tool writes as a regular file, and cargo any entry but "
                 "a directory or a link (a device, a FIFO too), where other tar readers skip it: what is "
                 "installed or built is not what a reviewer listing the archive sees, and no packaging tool "
                 "writes one. The entry was read and scanned as the file the installer writes."),
    }
    rid, name, why = rules[kind]
    return {"rule": rid, "name": name, "type": "HOTSPOT", "sev": "MAJOR",
            "msg": f"{name}: {path} — {detail}.", "why": why,
            "fix": "Inspect the archive listing (tar -tvf / unzip -l) before installing.",
            "ref": "CWE-506 · Supply chain", "file": str(path), "line": 1,
            "snippet": [], "snipStart": 1}


# Files that are not run as script text wherever package.json names them:
# data (JSON) and native code (.node, .wasm). An oversized one is not "code
# that runs at install/import time". Anything else named as main / bin or run
# by an install hook counts as code even with an odd extension: require() and
# `node <file>` run a file with an unknown extension (x.cjs.txt, core.dat,
# setup.css) as JavaScript.
_DATA_OR_NATIVE_EXTS = frozenset((".json", ".node", ".wasm"))
# Assets a package exports for bundlers (stylesheets, source maps, fonts,
# images): not code when they are "exports" targets. Only there: 0.1.1 also
# skipped them as main / bin / hook targets, so `postinstall: node setup.css`
# ran a script that was never scanned.
_EXPORTED_ASSET_EXTS = frozenset((
    ".css", ".scss", ".sass", ".less", ".styl", ".map",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot"))


def _not_run_as_script(rel, exported=False):
    ext = os.path.splitext(rel)[1].lower()
    return ext in _DATA_OR_NATIVE_EXTS or (exported and ext in _EXPORTED_ASSET_EXTS)


class _OutOfTime(Exception):
    """Internal: the archive's deadline passed while scanning (recorded)."""


def _unread_code(artifact, rel):
    """Is `rel`, a member of an `artifact`, code in a language nothing reads
    (UNREAD_CODE), and not test code its build leaves out?"""
    lang = UNREAD_CODE.get(artifact)
    return lang is not None and rel.lower().endswith(lang[1]) and not is_test_path(rel)


def _never_built(artifact, rel):
    """Is `rel`, a source file of a Go module or a crate, one no build of a
    dependent compiles, as the readers say (core.never_built: a Go
    *_test.go file, a file named with "_" or "." first, one under testdata/
    or vendor/; a crate's tests/, benches/ and examples/)? Neither the reader
    nor the file rules read it: the toolchain never runs it in a dependent
    (rivo/uniseg's line-break tests hold escaped URLs)."""
    if artifact == "gomod":
        return lazaret.never_built("go", _go_root_file(rel))
    if artifact == "crate":
        return lazaret.never_built("crate", rel)
    return False


def _go_root_file(rel):
    """The path of a Go module's member below its "<path>@<version>" root
    directory (the member paths start below the module path's host; a
    module whose path is a host alone has its root stripped)."""
    parts = rel.split("/")
    root = next((k for k, p in enumerate(parts) if "@" in p), -1)
    return "/".join(parts[root + 1:])


def _unread_code_issue(artifact, rels):
    """The SC-UNREAD-CODE finding for an artifact whose code in `rels`
    (sorted) nothing reads (N-1)."""
    lang, _ext = UNREAD_CODE[artifact]
    shown = ", ".join(rels[:3]) + (", …" if len(rels) > 3 else "")
    return {"rule": UNREAD_CODE_RULE, "name": f"{lang} code not read", "type": "HOTSPOT", "sev": "MAJOR",
            "msg": (f"{len(rels)} {lang} file{'' if len(rels) == 1 else 's'} not read ({shown}): Lazaret has no "
                    f"{lang} detectors yet, so what that code does when the package is built or used was not "
                    "checked, and the package can't be cleared."),
            "why": (f"A package's {lang} code runs on the machine that builds or uses it. The package's checksum, age "
                    "and archive were checked, and its other files were read; what its code does was not, so a clean "
                    "verdict would say more than the scan knows."),
            "fix": f"Review the package's {lang} code.",
            "ref": "CWE-506 · Supply chain", "file": rels[0], "line": 1, "snippet": [], "snipStart": 1}


class _ArtifactScan:
    """Scan state for one archive: classify members as they stream by, then
    resolve what package.json / setup.py say runs (entry points, install
    hooks, build backends) once every member is known."""

    def __init__(self, artifact, full, budget=None, memo=None):
        self.artifact, self.full = artifact, full
        self.budget = budget       # the archive's Budget (its deadline names itself)
        self.memo = _cache.NULL if memo is None else memo     # the engine's answers by content (P-2a)
        self.issues, self.files_scanned, self.binaries = [], 0, 0
        self.truncated, self.truncated_emitted = 0, 0
        self.truncated_at = {}     # rel -> its SC-TRUNCATED issue (None past the cap)
        self.timed_out = False     # the deadline passed (recorded once)
        self.sources = {}          # rel -> (text, lang) scanned as source
        self.pending = []          # source files queued for scan_pending (a batch)
        self.first_pass = True     # members as they stream by; finish() is the second pass
        self.deferred = {}         # rel -> raw bytes (text, not scanned yet)
        self.deferred_bytes = 0
        self.dropped = set()       # text members not kept (budget)
        self.shell = {}            # rel -> text of shell scripts
        self.binary = set()        # classified as binary
        self.oversize = set()
        self.members = set()
        self.manifests = {}        # rel -> text (package.json, binding.gyp, pyproject.toml)
        self.entries = set()       # rels that run when installed / imported
        self.install_scripts = set()   # hook targets, setup.py & co (install_script_risk)
        self.startup = set()       # a wheel's sitecustomize / usercustomize
        self.unread = False        # a member the archive's limits left unread
        self.unused_dependencies = []  # npm: registry names no file uses (_unused_dependencies)
        self.use_time = None       # what SC-USE-RISK's step read (_use_time_code), None: not run
        self.unread_code = []      # N-1: members whose code nothing reads yet (UNREAD_CODE)
        self.code_text = {}        # rel -> raw: what a reader reads besides the scanned sources (a Go
        self.code_bytes = 0        # module's cgo C; an sdist's .rs and Cargo.toml files, N-17), kept
        self.code_dropped = set()  # within PACKAGE_CODE_CHARS bytes (code_dropped: not kept)

    # ---- bookkeeping ----
    def truncate(self, rel, detail):
        """One SC-TRUNCATED finding, and one "part not fully scanned", per
        file: another reason for the same file (it also runs at install time,
        and package.json can name it as main, bin and exports) is added to
        that finding's message instead of repeating it."""
        self.scan_pending()                   # (the files queued before come first)
        if rel in self.truncated_at:
            issue = self.truncated_at[rel]
            if issue is not None and detail not in issue["msg"]:
                issue["msg"] = f"{issue['msg'][:-1]}; {detail}."
            return
        self.truncated += 1
        issue = None
        if self.truncated_emitted < TRUNCATED_FINDING_CAP:
            issue = lazaret.truncated_issue(rel, detail)
            self.issues.append(issue)
            self.truncated_emitted += 1
        self.truncated_at[rel] = issue

    def limit_detail(self, reason, rel, size=0):
        """SC-TRUNCATED detail for an archive limit ('files', 'total',
        'time', ...) reached at `rel`; 'time' names the deadline that
        passed, which may be the caller's rather than --scan-timeout."""
        if reason == "time" and self.budget is not None:
            return self.budget.time_detail(rel)
        return _TRUNC_DETAILS.get(
            reason, lambda r, s: f"archive not fully read ({reason})")(rel, size)

    def out_of_time(self, where):
        """True once the archive's deadline has passed; the first time, one
        SC-TRUNCATED finding says where the scan stopped. Checked between
        files and phases of both passes: the per-archive limit used to be
        checked only between archive members, so a slow member or the whole
        second pass (entry points, hook targets, cross-file analysis) ran on
        past it. Cancellation raises ScanCancelled."""
        if self.timed_out:
            return True
        if self.budget is None:
            return False
        try:
            self.budget.check()
        except ArchiveLimit as lim:
            self.timed_out = True
            self.truncate("(archive)", lim.detail or self.limit_detail(lim.reason, where))
            return True
        return False

    def _deadline(self, where):
        """Stop scanning (_OutOfTime) once the deadline has passed."""
        if self.out_of_time(where):
            raise _OutOfTime(where)

    def add_decode_issues(self, extra, keep_encoding=True):
        for i in extra:
            if i["rule"] == "SC-TRUNCATED":
                self.truncate(i["file"], i["msg"].removeprefix("File not fully scanned: ").rstrip("."))
            elif keep_encoding or i["rule"] != "Q-ENCODING":
                self.issues.append(i)

    def classify(self, rel, raw, size):
        bi = lazaret.classify_binary(rel, raw, size, self.artifact)
        if bi:
            self.binaries += 1
            self.issues.append(bi)

    def scan_source(self, rel, text, lang):
        self._deadline(rel)                  # not one more file past the deadline
        self.sources[rel] = (text, lang)
        self.pending.append((rel, text, lang))
        # The engine reads a batch of the first pass's files on threads
        # (engine.py); a --full scan (project mode: core's passes follow the
        # engine's rules) and the second pass, whose steps read what they
        # scan, go one at a time.
        batch = _engine.BATCH if self.first_pass and not self.full else 1
        if len(self.pending) >= batch:
            self.scan_pending()

    def scan_pending(self):
        """Scan the source files queued by scan_source, in order. Their
        findings are the same whenever they are made; a truncation, and the
        second pass (finish), scan the queue first."""
        pending, self.pending = self.pending, []
        if not pending:
            return
        found = self._scan_files([(rel, text, lang, not self.full) for rel, text, lang in pending])
        for (rel, _text, _lang), issues in zip(pending, found):
            self.files_scanned += 1
            for i in issues:
                if i["rule"] in TRUNCATION_RULES:
                    # part of the file was not scanned (the engine's work budget
                    # spent, an internal error, the time budget of core's passes),
                    # so the release can't be cleared (it used to be listed while
                    # the verdict stayed OK)
                    self.truncate(rel, i["msg"].removeprefix("File not fully scanned: ").rstrip("."))
                else:
                    self.issues.append(i)

    # ---- the engine, through the memo (P-2a) ----
    def _key(self, kind, text, lang, flags):
        return _cache.file_key(kind, None, text, lang, flags, pack=ENGINE_VERSION, engine=_engine.describe())

    def _scan_files(self, items):
        """engine.scan_files, asking the engine once for each distinct call
        (its name, its arguments and the text: it reads no path) and building
        each file's issues for its own path. A call the engine could not
        answer is not kept."""
        calls = _engine.scan_calls(items)
        todo = [k for k, call in enumerate(calls) if call is not None]
        keys = [self._key("scan", items[k][1], items[k][2], dict(calls[k][1], call=calls[k][0])) for k in todo]
        asked = dict(zip(keys, [(calls[k][0], calls[k][1], items[k][1]) for k in todo]))

        def compute(missing):
            return [_cache.Uncacheable(a) if _engine.unanswered(a) else a
                    for a in _engine.call_answers([asked[key] for key in missing])]
        answers = self.memo.get_or_compute_many(keys, compute)
        out = [[] for _ in items]
        for k, answer in zip(todo, answers):
            rel, text, lang, _dep = items[k]
            out[k] = _engine.scan_issues(rel, text, lang, calls[k][0], answer)
        return out

    def _import_risks(self, items):
        """engine.import_time_risks for [(text, lang)], once for each distinct
        file (an answer the engine could not give is not kept)."""
        flags = {"budget": _engine.WORK_BUDGET}
        keys = [self._key("import-risk", text, lang, flags) for text, lang in items]
        asked = dict(zip(keys, items))

        def compute(missing):
            return [_cache.Uncacheable(a) if _engine.unanswered(a) else a
                    for a in _engine.import_time_risks([asked[key] for key in missing])]
        return self.memo.get_or_compute_many(keys, compute)

    def _spawned_scripts(self, text, lang):
        """engine.spawned_scripts, once for each distinct script (a call the
        engine could not answer raises, and is not kept)."""
        return self.memo.get_or_compute(self._key("spawned", text, lang, ()),
                                        lambda: _engine.spawned_scripts(text, lang))

    # ---- pass 1: members ----
    def member(self, m):
        rel, size, raw, reason = m
        if reason in ("files", "total", "time", "corrupt"):
            self.unread = True
            self.truncate(rel, getattr(m, "detail", "") or self.limit_detail(reason, rel, size))
            self.timed_out = self.timed_out or reason == "time"
            return
        self.members.add(rel)
        if self.artifact in UNREAD_CODE and _unread_code(self.artifact, rel):
            self.unread_code.append(rel)
        base = os.path.basename(rel)
        ext = os.path.splitext(base)[1].lower()
        code = PACKAGE_CODE.get(self.artifact)
        wants_text = (base in _MANIFEST_NAMES or lazaret.dep_source_lang(ext) is not None
                      or ext in (".pth", ".gyp", ".gypi")
                      # a file a reader reads: a Go module's .go and cgo C, a crate's .rs (an
                      # sdist's .rs is known to be a crate's only at the end: _sdist_crates)
                      or (code is not None and ext in code[1] + code[2] and not _never_built(self.artifact, rel)))
        if reason == "member":
            self.oversize.add(rel)
            if wants_text and not (ext in lazaret.MPEG_TS_EXTS and lazaret._mpeg_ts(raw[:512])):
                # Verdict integrity (audit C2/G16): a cut-short scan is a
                # signal, not a clean verdict — whatever the first bytes look like.
                self.truncate(rel, _TRUNC_DETAILS["member"](rel, size))
            # still classifiable by magic/entropy from the decompressed prefix
            disguised = lazaret.disguised_binary(rel, raw) if lazaret.dep_source_lang(ext) else None
            if disguised:
                self.binaries += 1
                self.issues.append(disguised)
            else:
                self.classify(rel, raw, size)
            return
        if base == "package.json":
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra, keep_encoding=False)
            self.manifests[rel] = text
            self._deadline(rel)
            try:
                found = lazaret.scan_manifest(rel, text, registry=True)
            except _engine.NativeError as exc:
                self._unanswered(rel, exc)
                return
            for i in found:
                if i["rule"] == "SC-MANIFEST-UNPARSEABLE":
                    self.truncated += 1
                self.issues.append(i)
            return
        if base in ("binding.gyp",) or ext in (".gyp", ".gypi"):
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra, keep_encoding=False)
            self.manifests[rel] = text
            self._deadline(rel)
            try:
                found = lazaret.scan_gyp(rel, text)
            except _engine.NativeError as exc:
                self._unanswered(rel, exc)
                return
            for i in found:
                if i["rule"] == "SC-MANIFEST-UNPARSEABLE":
                    self.truncated += 1
                self.issues.append(i)
            return
        if base == "pyproject.toml":
            self.manifests[rel] = raw.decode("utf-8", "replace")
            return
        if ((self.artifact == "sdist" and (ext == ".rs" or base == "Cargo.toml"))
                or (code is not None and ext in code[2] and not _never_built(self.artifact, rel))) \
                and not lazaret.looks_binary(raw[:2048]):
            # read by a package reader at the end (_package_code, _sdist_crates), whatever text came
            # before: a Go module's cgo C, and the files of a Rust crate inside an sdist (N-17), which
            # cargo builds when pip builds the sdist; which crate a file is in is known once every
            # Cargo.toml is
            self._keep_code(rel, raw)
            return
        if ext == ".pth":
            text = raw.decode("utf-8-sig", "replace")
            try:
                self.issues.extend(pth_issues(rel, text))
            except _engine.NativeError as exc:
                self._unanswered(rel, exc)
            self.scan_source(rel, text, "py")
            return
        lang = lazaret.dep_source_lang(ext)
        if lang is None and code is not None and ext in code[1] and not _never_built(self.artifact, rel):
            lang = code[0]                       # a Go module's .go, a crate's .rs (Part C)
        if lang is not None:
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra)
            disguised = lazaret.disguised_binary(rel, raw)
            if disguised:
                # a program under a source file's name: a disguise, CRITICAL (0.1.8)
                self.binaries += 1
                self.issues.append(disguised)
            elif any(i["rule"] == "SC-TRUNCATED" for i in extra):
                self.classify(rel, raw, size)   # an ELF named index.js is still an ELF
            self.scan_source(rel, text, lang)
            return
        if lazaret.looks_binary(raw[:2048]):
            self.binary.add(rel)
            self.classify(rel, raw, size)
            return
        # Text without a source extension: a script by its #! line, or kept
        # until package.json says whether it runs (main -> lib/core.dat).
        if raw.startswith(b"#!"):
            text = raw.decode("utf-8", "replace")
            kind = _shebang_lang(text)
            if kind in ("js", "py"):
                # decoded as its interpreter reads it: a Python script keeps
                # its coding cookie (a UTF-7 one hid code in comments)
                text, extra = lazaret.decode_member(rel, raw, lang=kind)
                self.add_decode_issues(extra)
                self.scan_source(rel, text, kind)
                return
            if kind == "sh":
                self.shell[rel] = text
                return
        if self.deferred_bytes + len(raw) <= DEFERRED_TEXT_BUDGET or (
                # a module's go.mod (Go's limit is 16 MiB) is read for its names whatever came before it
                self.artifact == "gomod" and len(raw) <= _gomod.MAX_GOMOD and _go_root_file(rel) == "go.mod"):
            self.deferred[rel] = raw
            self.deferred_bytes += len(raw)
        else:
            self.dropped.add(rel)

    def _keep_code(self, rel, raw):
        """Keep a file a package reader reads (code_text), within PACKAGE_CODE_CHARS bytes in all: the
        reader holds a package at once, and one larger is not read anyway (code_dropped)."""
        if self.code_bytes + len(raw) <= PACKAGE_CODE_CHARS:
            self.code_text[rel] = raw
            self.code_bytes += len(raw)
        else:
            self.code_dropped.add(rel)

    # ---- pass 2: what runs ----
    def _find(self, candidates):
        return next((c for c in candidates if c in self.members), None)

    def _resolve(self, path):
        """The member Node loads for a path it is asked to run or require:
        the file itself or with an extension, else — for a directory — the
        file its own package.json's "main" names, else its index file
        (LOAD_AS_FILE, then LOAD_AS_DIRECTORY). The "main" step was missing:
        `main: "lib"` with lib/package.json naming core.dat ran core.dat,
        and it was neither scanned nor counted."""
        candidates = _node_candidates(path)
        found = self._find(candidates[:6])                 # the file, .js, .json, ...
        if found:
            return found
        manifest_rel = _rel_join(path.rstrip("/"), "package.json")
        text = self.manifests.get(manifest_rel)
        if text is not None:
            data, _problems = lazaret.load_manifest(manifest_rel, text)
            main = data.get("main") if isinstance(data, dict) else None
            if isinstance(main, str) and main.strip():
                found = self._find(_node_candidates(_rel_join(path.rstrip("/"), main)))
                if found:
                    return found
        return self._find(candidates[6:])                  # index.js, ...

    def _text_of(self, rel, as_lang="js", exported=False, imported=False):
        """Text of a member that is run as code, scanning it as `as_lang`
        first when it has not been scanned (non-source extension). None when
        it cannot be read as text — that is counted as INCOMPLETE.
        `exported`: named only by "exports", where assets are not code.
        `imported`: required or imported by code that runs. Text is code
        whatever its extension (require() runs lib/core.dat as JavaScript),
        but a stylesheet, image or font that is not text is a bundler asset
        (React Native's require('./icon.png')), not code that can't be read."""
        if rel in self.sources:
            return self.sources[rel][0]
        if rel in self.shell:
            return self.shell[rel]
        if _not_run_as_script(rel, exported):
            return None          # data or native code; an exported asset
        if rel in self.deferred:
            raw = self.deferred.pop(rel)
            if as_lang == "sh" or _shebang_lang(raw[:256].decode("utf-8", "replace")) == "sh":
                text = raw.decode("utf-8", "replace")
                self.shell[rel] = text
                return text
            text, extra = lazaret.decode_member(rel, raw)
            self.add_decode_issues(extra)
            self.scan_source(rel, text, as_lang)
            return text
        if rel in self.manifests:
            # binding.gyp, a .gyp/.gypi or pyproject.toml was only read as a
            # manifest; named as a main, bin or hook target, node runs it as
            # JavaScript (it used to come back as None, scanned by nothing)
            text = self.manifests[rel]
            if as_lang == "sh":
                self.shell[rel] = text
            else:
                self.scan_source(rel, text, as_lang)
            return text
        if imported and _not_run_as_script(rel, exported=True):
            return None          # an image, font or stylesheet a bundler loads
        if rel in self.dropped:
            self.truncate(rel, f"{rel} runs at install/import time but was not kept for "
                               f"scanning (text budget exhausted)")
        elif rel in self.oversize:
            self.truncate(rel, "it runs at install/import time" if rel in self.truncated_at
                          else f"{rel} runs at install/import time but is larger than the "
                               f"{MAX_MEMBER:,}-byte source-scan limit")
        elif rel in self.binary:
            self.truncate(rel, f"{rel} runs at install/import time but is not text, so it "
                               f"could not be scanned")
        elif rel in self.members:
            # every member lands in one of the sets above; should one ever
            # not, it runs unscanned: never a silent None
            self.truncate(rel, f"{rel} runs at install/import time but was not scanned")
        return None

    def _entry_points(self, manifest_rel, data):
        base = posixpath.dirname(manifest_rel)
        patterns = set()
        for target, exported in _package_entry_targets(data):
            if exported and "*" in target:
                patterns.add(_rel_join(base, target))
                continue
            rel = self._resolve(_rel_join(base, target))
            if rel:
                self.entries.add(rel)
                self._text_of(rel, "js", exported)
        if patterns:
            self._exported_patterns(patterns)

    def _exported_patterns(self, patterns):
        """Every member an exports pattern target can resolve to is exported
        code (the exported-asset exemption applies): "./*": "./lib/*.dat"
        exports lib/**/*.dat, which `require('pkg/x')` runs."""
        members = sorted(self.members)
        for pattern in sorted(patterns):
            self._deadline("the exports patterns")
            head = pattern.split("*", 1)[0]
            rx = _pattern_regex(pattern)
            for rel in members[bisect.bisect_left(members, head):]:
                if not rel.startswith(head):
                    break
                if rx.fullmatch(rel):
                    self.entries.add(rel)
                    self._text_of(rel, "js", exported=True)

    def _implicit_gyp_hook(self, manifest_rel, data):
        """npm runs `node-gyp rebuild` for a root binding.gyp when the package
        defines no install/preinstall script (and gypfile isn't false)."""
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        if "binding.gyp" not in self.members or data.get("gypfile") is False:
            return
        if any(isinstance(scripts.get(h), str) and scripts[h].strip() for h in ("install", "preinstall")):
            return
        self.issues.append(lazaret._sc_install_hook_issue(
            "binding.gyp", 1, [], "install (implicit)", "node-gyp rebuild", False))

    def _entry_point_manifests(self):
        """The root package.json's entry points and its implicit node-gyp hook."""
        for rel, text in list(self.manifests.items()):
            if os.path.basename(rel) != "package.json":
                continue
            data, _problems = lazaret.load_manifest(rel, text)
            if data is None:
                continue
            if rel == "package.json":
                self._entry_points(rel, data)
                self._implicit_gyp_hook(rel, data)

    def _follow_hooks(self):
        """Follow each install hook to the scripts it runs; escalate the hook
        when one looks hostile (see install_script_risk)."""
        for issue in list(self.issues):
            if issue["rule"] != "SC-INSTALL-HOOK" or not issue.get("cmd"):
                continue
            base = posixpath.dirname(issue["file"])
            direct = lazaret.agent_hijack_in_command(issue["cmd"])    # the hook runs the agent itself
            if direct is not None:
                mtext = lazaret.normalize_newlines(self.manifests.get(issue["file"], ""))
                self.issues.append(lazaret._agent_hijack_issue(
                    issue["file"], issue["line"], mtext.split("\n"), direct[0], direct[1]))
            persist = lazaret.persistence_reasons(issue["cmd"])   # the command itself plants something
            if persist and issue["sev"] not in STRONG_SEVERITIES:
                issue["sev"] = "CRITICAL"
                issue["msg"] = f"Install hook command {'; and '.join(persist)}."
            targets, complete = lazaret.follow_hook(issue["cmd"])
            if not complete:            # a limit stopped the walk (core.HOOK_MAX_CHARS)
                self.truncate(issue["file"], "its install hook is more than Lazaret follows "
                              f"({lazaret.HOOK_MAX_COMMANDS:,} commands, {lazaret.HOOK_MAX_TARGETS} "
                              f"scripts, {lazaret.HOOK_MAX_CHARS:,} characters, "
                              f"{lazaret.HOOK_MAX_PATH:,}-character paths)")
            for target in targets:
                rel = self._resolve(_rel_join(base, target))
                if rel is None:
                    continue
                self.entries.add(rel)
                self.install_scripts.add(rel)
                lang = "sh" if rel.endswith(".sh") else "js"
                text = self._text_of(rel, lang)
                reasons = _engine.install_script_risk(text, lang=_engine.script_lang(rel)) if text else []
                if reasons and issue["sev"] not in STRONG_SEVERITIES:
                    issue["sev"] = "CRITICAL"
                    issue["msg"] = f"Install hook runs {target}, which {'; and '.join(reasons)}."
                # the scripts it starts with node or python (0.1.8, core.spawned_scripts)
                for started, more in self._started_scripts(rel, text, base, self.install_scripts):
                    more = _engine.install_script_risk(more, lang=_engine.script_lang(started)) if more else []
                    if more and issue["sev"] not in STRONG_SEVERITIES:
                        issue["sev"] = "CRITICAL"
                        issue["msg"] = (f"Install hook runs {target}, which starts {started}, which "
                                        f"{'; and '.join(more)}.")

    def _started_scripts(self, rel, text, cwd, into):
        """[(rel, text)] for the package scripts `rel` starts with node or
        python, and the ones those start (core.spawned_scripts), at most
        _SPAWN_MAX_DEPTH starts deep and _SPAWN_MAX_FILES files; each is added
        to the entries and to `into` (the install scripts, or import-time
        files). `cwd`: the directory the package runs in, for a path written
        as a plain literal — None at import time, when that is the user's
        directory, not the package's, and such a path is not followed."""
        out, seen, queue = [], {rel}, [(rel, text, 0)]
        while queue and len(seen) <= lazaret._SPAWN_MAX_FILES:
            cur, cur_text, depth = queue.pop(0)
            if not cur_text or depth >= lazaret._SPAWN_MAX_DEPTH:
                continue
            for where, path in self._spawned_scripts(lazaret.normalize_newlines(cur_text), _engine.script_lang(cur)):
                if where != "dir" and cwd is None:
                    continue
                start = posixpath.dirname(cur) if where == "dir" else cwd
                nxt = self._resolve(_rel_join(start, path))
                if nxt is None or nxt in seen or len(seen) > lazaret._SPAWN_MAX_FILES:
                    continue
                seen.add(nxt)
                self.entries.add(nxt)
                into.add(nxt)
                lang = "py" if nxt.endswith(".py") else ("sh" if nxt.endswith(".sh") else "js")
                ntext = self._text_of(nxt, lang)
                out.append((nxt, ntext))
                queue.append((nxt, ntext, depth + 1))
        return out

    def _python_install_scripts(self):
        """Python code pip runs to build/install an sdist: setup.py and an
        in-tree PEP 517 backend (build-system.backend-path)."""
        scripts = []
        if "setup.py" in self.sources:
            scripts.append("setup.py")
        backend, paths = _pep517_backend(self.manifests.get("pyproject.toml", ""))
        if backend and paths:
            mod = backend.split(":", 1)[0].replace(".", "/")
            for p in paths:
                root = _rel_join("", p)
                rel = self._find([_rel_join(root, mod + ".py"), _rel_join(root, mod + "/__init__.py")])
                if rel:
                    scripts.append(rel)
        # modules they import from the sdist itself run at install time too —
        # in the sdist's root or its src/ directory, or relative to the
        # importing module (`from .main import x`)
        queue, seen = list(scripts), set(scripts)
        while queue and len(seen) < 200:
            current = queue.pop()
            text, lang = self.sources.get(current, ("", None))
            if lang != "py":
                continue
            found = []
            for m in _PY_LOCAL_IMPORT_RE.finditer(text):
                mod = (m.group(1) or m.group(2)).replace(".", "/")
                found.append(self._find([mod + ".py", mod + "/__init__.py",
                                         "src/" + mod + ".py", "src/" + mod + "/__init__.py"]))
            for m in _PY_RELATIVE_IMPORT_RE.finditer(text):
                base = posixpath.dirname(current)
                for _ in range(len(m.group(1)) - 1):
                    base = posixpath.dirname(base)
                mod = _rel_join(base, m.group(2).replace(".", "/"))
                found.append(self._find([mod + ".py", mod + "/__init__.py"]))
            for rel in found:
                if rel and rel not in seen:
                    seen.add(rel)
                    scripts.append(rel)
                    queue.append(rel)
        for rel in list(scripts):                  # and the scripts they start with python or node (0.1.8)
            for started, _text in self._started_scripts(rel, self.sources.get(rel, ("", "py"))[0], "",
                                                        self.install_scripts):
                if started not in scripts:
                    scripts.append(started)
        for rel in scripts:
            self.entries.add(rel)
            self.install_scripts.add(rel)
            text = self.sources.get(rel, ("", "py"))[0]
            reasons = _engine.install_script_risk(text, lang=_engine.script_lang(rel))
            # a download written to a file and run: CRITICAL in the code pip
            # runs to install an sdist (a prebuilt-binary installer's shape
            # keeps it MAJOR-only in npm hooks and import-time code)
            if (lazaret._downloads_and_runs_file(lazaret.normalize_newlines(text)) is not None
                    and not any(r.startswith("downloads a script and runs it with") for r in reasons)):
                reasons.append("downloads a file and then runs it")
            if reasons:
                lines = lazaret.normalize_newlines(text).split("\n")
                self.issues.append(lazaret.mk_issue(
                    {"id": "SC-INSTALL-HOOK", "name": "Install hook", "type": "HOTSPOT",
                     "sev": "CRITICAL",
                     "msg": f"{rel} runs when pip builds or installs this sdist, and it "
                            f"{'; and '.join(reasons)}.",
                     "why": ("pip executes an sdist's setup.py (or its in-tree build "
                             "backend) with the user's privileges before anything is "
                             "reviewed — the Python twin of an npm install hook."),
                     "fix": "Do not install this sdist; report it to the index.",
                     "ref": "CWE-506 · Supply chain"}, rel, 1, lines))

    def _startup_modules(self):
        """A wheel's sitecustomize / usercustomize (SC-SITECUSTOMIZE): run at
        every interpreter start like a .pth file, but they used to be only
        ordinary modules to the scan."""
        for rel in sorted(self.sources):
            text, lang = self.sources[rel]
            if lang == "py" and _STARTUP_MODULE_RE.match(rel):
                self.entries.add(rel)
                self.startup.add(rel)
                self.issues.append(startup_module_issue(rel, text))

    def _python_reach(self, roots):
        """The Python modules of the archive that `roots` import, roots
        included: absolute imports of a package the archive holds (at its
        root, in src/, or in a wheel's .data directory), relative imports,
        and `from pkg import name` where name is a submodule. At most
        _PY_REACH_MAX modules."""
        py = {rel for rel, (_t, lang) in self.sources.items() if lang == "py"}
        bases = sorted({m.group(1) for m in map(_PY_BASE_RE.match, roots) if m} | {""})

        def module(dotted, base=None):
            path = dotted.replace(".", "/")
            for prefix in ([base] if base is not None else bases):
                for cand in (_rel_join(prefix, path + ".py"), _rel_join(prefix, path + "/__init__.py")):
                    if cand in py:
                        return cand
            return None

        out, queue = list(dict.fromkeys(r for r in roots if r in py)), []
        queue.extend(out)
        seen = set(out)
        while queue and len(seen) < _PY_REACH_MAX:
            current = queue.pop()
            text = self.sources[current][0]
            found = []
            for m in _PY_IMPORT_STMT_RE.finditer(text):
                dots, mod, names = m.group("dots"), m.group("mod") or m.group("imod"), m.group("names")
                if dots:                                  # from .x import a / from . import a
                    base = posixpath.dirname(current)
                    for _ in range(len(dots) - 1):
                        base = posixpath.dirname(base)
                    target = module(mod, base) if mod else None
                    found.append(target)
                    pkg = _rel_join(base, mod.replace(".", "/")) if mod else base
                    found.extend(module(n, pkg) for n in _import_names(names))
                elif mod:                                 # import a.b / from a.b import c
                    parts = mod.split(".")
                    found.extend(module(".".join(parts[:k])) for k in range(1, len(parts) + 1))
                    if names is not None:
                        found.extend(module(mod + "." + n) for n in _import_names(names))
            for rel in found:
                if rel and rel not in seen:
                    seen.add(rel)
                    out.append(rel)
                    queue.append(rel)
        return out

    def _import_time_code(self, reachable):
        """SC-IMPORT-RISK: the weaker install-script test (import_time_risk)
        on code that runs when the package is loaded — for npm what the entry
        points reach; for a wheel its top-level packages and modules and the
        modules they import; for an sdist the same, found at its root or in
        src/ (it used to get no import-time test at all, and a wheel's
        x/__init__.py was read without the modules it imports). It used to
        run on install-time scripts only, so an import-time stealer in
        index.js or x/__init__.py said OK. MAJOR, or CRITICAL for the
        reasons import_time_severity names. Install scripts and start-up
        modules have their own, stronger test."""
        if self.artifact == "wheel":
            files = self._python_reach(sorted(rel for rel in self.sources if _WHEEL_TOP_MODULE_RE.match(rel)))
        elif self.artifact == "sdist":
            files = self._python_reach(sorted(rel for rel in self.sources if _SDIST_TOP_MODULE_RE.match(rel)
                                              and posixpath.basename(rel) not in _SDIST_NOT_MODULES))
        else:
            files = reachable
        # and the package scripts that code starts with node or python (0.1.8)
        started = set()
        for rel in sorted(files):
            text, lang = self.sources.get(rel, (None, None))
            if text and lang in ("js", "py") and rel not in self.install_scripts:
                self._started_scripts(rel, text, None, started)
        files = set(files) | {rel for rel in started if rel not in self.install_scripts}
        todo = []
        for rel in sorted(files):
            if rel in self.install_scripts or rel in self.startup:
                continue
            text, lang = self.sources.get(rel, (None, None))
            if text and lang in ("js", "py"):
                todo.append((rel, text, lang))
        for rel, text, lang, risk in self._import_time_risks(todo):
            if _engine.unanswered(risk):
                self._unanswered(rel, risk)
                continue
            reasons, line = risk
            if not reasons:
                continue
            self.issues.append(lazaret.mk_issue(
                {"id": "SC-IMPORT-RISK", "name": "Risky import-time code", "type": "HOTSPOT",
                 "sev": lazaret.import_time_severity(reasons),
                 "msg": f"{rel} runs when the package is loaded, and it {'; and '.join(reasons)}.",
                 "why": ("Code the package's entry points reach (in a wheel or an sdist, its "
                         "top-level modules and what they import) runs whenever the package is "
                         "imported or its command runs. Collecting credentials or the whole "
                         "environment next to a network call is the shape of an import-time "
                         "stealer; SDKs read the few variables they need. MAJOR where the file "
                         "may have a reason; CRITICAL for code no library needs — code fetched "
                         "and run, a reverse shell, hidden PowerShell, a beacon to a "
                         "data-capture service."),
                 "fix": "Read the file: what does it collect, and where does it send it?",
                 "ref": "CWE-506 · Supply chain"}, rel, line, text.split("\n")))
        self._use_time_code(set(files))
        self._cross_file_code()

    def _import_time_risks(self, todo, short_batches=False):
        """(rel, text, lang, import_time_risk's answer) for [(rel, text, lang)]
        (the text with its newlines normalized), in order, a batch at a time
        (engine.py: the engine reads a batch on threads; an answer it could
        not give is the NativeError it stands for, engine.unanswered); the
        deadline is checked before each batch. With `short_batches`, a batch
        holds at most USE_RISK_BATCH_CHARS characters, or one file."""
        size = _engine.BATCH
        start = 0
        while start < len(todo):
            end, chars = start + 1, len(todo[start][1] or "")
            while end < len(todo) and end - start < size:
                more = len(todo[end][1] or "")
                if short_batches and chars + more > USE_RISK_BATCH_CHARS:
                    break
                chars += more
                end += 1
            chunk = [(rel, lazaret.normalize_newlines(text), lang) for rel, text, lang in todo[start:end]]
            start = end
            self._deadline(chunk[0][0])
            for (rel, text, lang), risk in zip(chunk, self._import_risks([(t, lg) for _r, t, lg in chunk])):
                yield rel, text, lang, risk

    def _unanswered(self, rel, exc):
        """A file the engine could not read for a test (engine.unanswered):
        SC-TRUNCATED, once per file (truncate), in engine.error_issue's words."""
        self.truncate(rel, _engine.error_issue(rel, exc)["msg"].removeprefix("File not fully scanned: ").rstrip("."))

    def _phase(self, where, step, *args):
        """Run one step of finish() once the deadline check passes. A call the
        engine could not answer in it (its work budget spent on a hostile
        input, an internal error) makes the release INCOMPLETE (SC-TRUNCATED
        for the release, naming the step) and gives None; the next step runs."""
        self._deadline(where)
        try:
            return step(*args)
        except _engine.NativeError as exc:
            why = (_engine.EXHAUSTED if isinstance(exc, _engine.NativeExhausted)
                   else f"an internal error of the engine ({type(exc).__name__})")
            self.truncate("(release)", f"the engine could not finish {where}: {why}")
            return None

    def _suspicious(self):
        """Has a strong supply-chain finding made the package SUSPICIOUS already?"""
        return any(i["rule"].startswith("SC-") and i["rule"] not in TRUNCATION_RULES and i["sev"] in STRONG_SEVERITIES
                   for i in self.issues)

    def _use_time_code(self, loaded):
        """SC-USE-RISK (CRITICAL): the strong import-time shapes in the other
        JavaScript and Python files of the package — code it runs when it is
        used (see USE_RISK_SKIP_DIRS), smallest files first, within
        USE_RISK_CHARS characters. self.use_time says how much of it was
        read: files and characters, of how many."""
        if self._suspicious():
            return
        # smallest first, within USE_RISK_CHARS: as many files as fit (droppers are small), and the
        # same ones on every machine. Every candidate counts toward the share: a file over
        # USE_RISK_MAX_CHARS, or past the bound, is one not read.
        todo, files, chars, room = [], 0, 0, USE_RISK_CHARS
        for rel in sorted(self.sources, key=lambda r: (len(self.sources[r][0] or ""), r)):
            if rel in loaded or rel in self.install_scripts or rel in self.startup or _not_used_code(rel):
                continue
            text, lang = self.sources[rel]
            if not text or lang not in ("js", "py"):
                continue
            files += 1
            chars += len(text)
            if len(text) <= min(room, USE_RISK_MAX_CHARS):
                todo.append((rel, text, lang))
                room -= len(text)
            else:
                room = -1                   # sizes only grow from here: read nothing after a file left out
        self.use_time = {"files": 0, "ofFiles": files, "chars": 0, "ofChars": chars, "boundChars": USE_RISK_CHARS}
        for rel, text, lang, risk in self._import_time_risks(todo, short_batches=True):
            if _engine.unanswered(risk):
                self._unanswered(rel, risk)     # SC-TRUNCATED: not read
                continue
            self.use_time["files"] += 1
            self.use_time["chars"] += len(self.sources[rel][0])
            reasons, line = risk
            strong = [r for r in reasons if r.startswith(lazaret._STRONG_IMPORT_REASONS)]
            if not strong:
                continue
            self.issues.append(lazaret.mk_issue(
                {"id": "SC-USE-RISK", "name": "Hostile code the package runs when used", "type": "HOTSPOT",
                 "sev": "CRITICAL",
                 "msg": f"{rel} {'; and '.join(strong)}. Nothing loads it at install or import: it runs when "
                        f"the package's code calls it.",
                 "why": ("A payload need not run on install or import to reach you: a logger's constructor, a "
                         "middleware or a script the package spawns runs it the first time your code uses the "
                         "package. These are the shapes no library needs: code fetched and run, a reverse shell, "
                         "hidden PowerShell, credentials sent to an exfiltration service, a beacon to a "
                         "data-capture service."),
                 "fix": "Don't use the package; report it to the registry.",
                 "ref": "CWE-506 · Supply chain"}, rel, line, text.split("\n")))

    def _cross_file_code(self):
        """SC-IMPORT-RISK (CRITICAL) for a package file that runs a value
        another file of the package received over the network
        (core._cross_file_received_issues, 0.1.8, by the engine in use:
        engine.cross_file_issues): the dropper split across
        files — _net.py fetches, __init__.py runs what it returns — that
        neither file shows alone. The --deps checks ran it on installed
        dependencies only; a registry or guard scan reads the release before
        it is installed. The files are SC-USE-RISK's (not once the package is
        SUSPICIOUS, not those it does not run when used, none over
        USE_RISK_MAX_CHARS), read as one package: npm files as the package's
        own, a wheel's or an sdist's modules under their import names (a
        .data/purelib/ or src/ prefix dropped)."""
        if self._suspicious():
            return
        files, back = [], {}
        for rel in sorted(self.sources):
            text, lang = self.sources[rel]
            if not text or lang not in ("js", "py") or len(text) > USE_RISK_MAX_CHARS or _not_used_code(rel):
                continue
            if lang == "js":
                path = "node_modules/package/" + rel
            else:
                base = _PY_BASE_RE.match(rel)
                path = "site-packages/" + (rel[base.end():] if base else rel)
            if path in back:
                continue                            # src/x.py and x.py: the first wins
            back[path] = rel
            files.append({"path": path, "lang": lang, "dep": True, "content": lazaret.normalize_newlines(text)})
        if len(files) < 2:
            return
        self._deadline("the cross-file follower")
        todo, args = _engine.cross_file_args(files, who=lambda path: back[path], one_package=True)
        key = _cache.cross_file_key([(f["path"], f["lang"], f["content"]) for f in todo],
                                    {k: v for k, v in args.items() if k not in ("files", "threads")},
                                    pack=ENGINE_VERSION, engine=_engine.describe())

        def compute():
            issues, complete = _engine.cross_file_answer(files, who=lambda path: back[path], one_package=True)
            return issues if complete else _cache.Uncacheable(issues)    # (a package cut short is not clean)
        for issue in self.memo.get_or_compute(key, compute):
            issue["file"] = back[issue["file"]]
            self.issues.append(issue)

    def _agent_hijack(self):
        """SC-AGENT-HIJACK (CRITICAL): a package file that launches an AI
        coding agent in an autonomous mode (core.agent_hijack). A package is a
        dependency, so every source file is dependency code."""
        for rel in sorted(self.sources):
            text, lang = self.sources.get(rel, (None, None))
            if not text or lang not in ("js", "py"):
                continue
            self._deadline(rel)
            issue = lazaret.dependency_agent_issue(rel, lazaret.normalize_newlines(text))
            if issue is not None:
                self.issues.append(issue)

    def _go_mods(self):
        """[(rel, text, gomod.parse's answer)] of the go.mod in a Go module's root
        directory ("<path>@<version>/"; the member paths have lost the host, so
        its module line names the module). Go refuses a zip with another root;
        this reads each."""
        out = []
        for rel in sorted(r for r in self.deferred if _go_root_file(r) == "go.mod"):
            text = self.deferred[rel].decode("utf-8", "replace")
            out.append((rel, text, _gomod.parse(text)))
        return out

    def _package_code(self):
        """Part C (0.1.9): a Go module's or a crate's code read for what it
        does, by the engine's readers (G-1: engine.go_package; R-1:
        engine.rs_crate), with the tests a package's JavaScript and Python
        get for the same moment and the same reasons and severities:
        - Go: the code a package's init functions, package-level variables'
          initializers and cgo constructors reach runs when any program that
          imports the package starts: the import-time test (SC-IMPORT-RISK);
        - Rust: a build script, and a procedural-macro crate's code, run on
          the machine that builds a dependent: the install-script test
          (SC-INSTALL-HOOK, CRITICAL); #[ctor] and load sections run before
          a program's main: the import-time test;
        - the rest runs when the module's or the crate's code is called: its
          strong reasons are SC-USE-RISK (CRITICAL), as for _use_time_code,
          within the same bounds (useTime says how much was read).
        A module's //go:generate commands are listed (SC-GO-GENERATE, INFO):
        they run only when someone runs go generate. Code larger than
        PACKAGE_CODE_CHARS is not read (SC-TRUNCATED: INCOMPLETE), and so is
        a module whose cgo C was not all kept."""
        code = PACKAGE_CODE.get(self.artifact)
        if code is None:
            return
        lang, _exts, others = code
        rels = sorted(rel for rel, (text, lg) in self.sources.items() if lg == lang and text is not None)
        if not rels:
            return
        what = "module" if self.artifact == "gomod" else "crate"
        texts = {rel: self.sources[rel][0] for rel in rels}
        for rel in sorted(self.code_text):
            if os.path.splitext(rel)[1].lower() in others:
                texts[rel] = self.code_text[rel].decode("utf-8", "replace")
        order = sorted(texts)
        place = _go_root_file if self.artifact == "gomod" else (lambda r: r)
        files = [(place(rel), texts[rel]) for rel in order]
        size = sum(len(t) for _p, t in files)
        if size > PACKAGE_CODE_CHARS or self.code_dropped:
            amount = f"{size:,} characters" if not self.code_dropped else "its C files not all kept"
            self.truncate(rels[0], f"the {what}'s code ({amount}) is more than the reader takes at once "
                                   f"({PACKAGE_CODE_CHARS:,}), so it was not read")
            return
        self._deadline(rels[0])
        if self.artifact == "gomod":
            mods = self._go_mods()
            module = mods[0][2]["module"] if mods else None
            answer = _engine.go_package(files, module=module, use_file_chars=USE_RISK_MAX_CHARS,
                                        use_chars=USE_RISK_CHARS)
        else:
            from lazaret.registry.ecosystems import crates as _crates
            manifest = self.deferred.get("Cargo.toml", b"").decode("utf-8", "replace")
            script, lib, proc_macro = _crates.ECOSYSTEM.layout({"Cargo.toml": manifest}, self.members)
            answer = _engine.rs_crate(files, build=script, proc_macro=proc_macro, lib=lib,
                                      use_file_chars=USE_RISK_MAX_CHARS, use_chars=USE_RISK_CHARS)
        self._reader_findings(answer, order, texts, what)

    def _sdist_crates(self):
        """N-17 (Part C): the Rust crates inside an sdist. A maturin or
        setuptools-rust project ships its crate (or a workspace of them), and
        pip has cargo build it when it installs the sdist; each is read as a
        crate's code is (_package_code): every .rs file with the file rules,
        each crate with the Rust reader. A crate is a directory with a
        Cargo.toml, a .rs file is in the nearest one above it, and one in
        none is not built by cargo, nor are a crate's tests/, benches/ and
        examples/: those are not read. A build script and a procedural macro
        run when pip builds the sdist (SC-INSTALL-HOOK, CRITICAL, as
        setup.py's code); #[ctor] and load sections when the extension module
        is loaded (SC-IMPORT-RISK); the strong reasons of the rest are
        SC-USE-RISK, the crates sharing one USE_RISK_CHARS. A crate's file
        that was not kept (over the member limit, or past PACKAGE_CODE_CHARS
        in all) makes the sdist INCOMPLETE."""
        manifests = {posixpath.dirname(rel): raw for rel, raw in self.code_text.items()
                     if posixpath.basename(rel) == "Cargo.toml"}
        unkept = {posixpath.dirname(rel) for rel in self.code_dropped if posixpath.basename(rel) == "Cargo.toml"}

        def crate_of(rel):
            folder = posixpath.dirname(rel)
            while True:
                if folder in manifests or folder in unkept:
                    return folder
                if not folder:
                    return None
                folder = posixpath.dirname(folder)

        def inside(root, rel):
            return rel[len(root) + 1:] if root else rel

        crates = {}
        for rel in sorted(set(self.code_text) | self.code_dropped | {r for r in self.oversize if r.endswith(".rs")}):
            if not rel.endswith(".rs"):
                continue
            root = crate_of(rel)
            if root is None or _never_built("crate", inside(root, rel)):
                continue                                  # not a file cargo builds
            if rel in self.oversize:
                self.truncate(rel, f"{rel} is the code of a Rust crate this sdist builds, and it is larger than the "
                                   f"{MAX_MEMBER:,}-byte source-scan limit")
            elif rel in self.code_dropped or root in unkept:
                self.truncate(rel, f"{rel} is the code of a Rust crate this sdist builds, and the sdist's Rust is more "
                                   f"than the {PACKAGE_CODE_CHARS:,} characters a reader takes")
            else:
                crates.setdefault(root, []).append(rel)
        if not crates:
            return
        # the file rules, a batch at a time (as the first pass reads sources)
        for root in sorted(crates):
            for rel in crates[root]:
                self._deadline(rel)
                text, extra = lazaret.decode_member(rel, self.code_text[rel])
                self.add_decode_issues(extra)
                self.sources[rel] = (text, "rs")
                self.pending.append((rel, text, "rs"))
                if len(self.pending) >= _engine.BATCH:
                    self.scan_pending()
        self.scan_pending()
        if self._suspicious():
            room = 0                                       # (no use-time reading once SUSPICIOUS, as _use_time_code)
        else:
            room = USE_RISK_CHARS
        from lazaret.registry.ecosystems import crates as _crates
        for root in sorted(crates):
            order = crates[root]
            texts = {rel: self.sources[rel][0] for rel in order}
            files = [(inside(root, rel), texts[rel]) for rel in order]
            manifest = manifests[root].decode("utf-8", "replace")
            script, lib, proc_macro = _crates.ECOSYSTEM.layout({"Cargo.toml": manifest}, [p for p, _t in files])
            self._deadline(order[0])
            answer = _engine.rs_crate(files, build=script, proc_macro=proc_macro, lib=lib,
                                      use_file_chars=USE_RISK_MAX_CHARS, use_chars=max(0, room))
            room -= int((answer.get("useRead") or {}).get("chars", 0))
            self._reader_findings(answer, order, texts, "sdist")

    def _reader_findings(self, answer, order, texts, what):
        """The findings of a package reader's answer (go_package, rs_crate)
        for the files `order` (archive paths, in the order the reader was
        given them; `texts` their text): core.package_reader_issues, with
        `what` "module", "crate" or "sdist" (a crate inside an sdist, N-17)
        for the words; what its use-time step read goes to useTime."""
        issues, read = lazaret.package_reader_issues(answer, order, texts, what)
        self.issues.extend(issues)
        mine = dict(read, boundChars=USE_RISK_CHARS)
        if self.use_time is None:
            self.use_time = mine
        else:
            for key in ("files", "ofFiles", "chars", "ofChars"):
                self.use_time[key] = self.use_time.get(key, 0) + mine[key]

    def _lookalike_names(self):
        """SC-TYPOSQUAT (MAJOR, 0.1.8): the release's own name, or a
        dependency it declares, one change from a popular package's
        (registry/lookalike.py). npm: package.json's name, dependencies and
        optionalDependencies; PyPI: the Name and Requires-Dist (optional
        extras left out) of a wheel's METADATA or an sdist's PKG-INFO; Go
        (0.1.9, N-3): the module line of the module's go.mod and the paths
        it requires."""
        if self.artifact == "gomod":
            for rel, text, parsed in self._go_mods():
                deps = {p for p, _v, _i in parsed["require"]} | {p for p, _i in parsed["unversioned"]}
                self.issues.extend(_lookalike.issues("go", parsed["module"], deps, rel, text))
            return
        if self.artifact == "wheel":
            rel = next((r for r in sorted(self.deferred) if r.count("/") == 1
                        and r.endswith(".dist-info/METADATA")), None)
        elif self.artifact == "sdist":
            rel = "PKG-INFO" if "PKG-INFO" in self.deferred else None
        else:
            text = self.manifests.get("package.json")
            data, _problems = lazaret.load_manifest("package.json", text) if text else (None, None)
            if isinstance(data, dict):
                name = data.get("name")
                self.issues.extend(_lookalike.issues("npm", name if isinstance(name, str) else None,
                                                     npm_dependency_names(data), "package.json", text))
            return
        if rel is None:
            return
        text = self.deferred[rel].decode("utf-8", "replace")
        name, requires = None, []
        for line in text.split("\n"):           # the headers, up to the first empty line
            if not line.strip():
                break
            if line.startswith("Name:") and name is None:
                name = line[5:].strip()
            elif line.startswith("Requires-Dist:"):
                requires.append(line[14:].strip())
        self.issues.extend(_lookalike.issues("pypi", name, pypi_dependency_names(requires), rel, text))

    def _unused_dependencies(self):
        """SC-UNUSED-DEPENDENCY (INFO, 0.1.8): the runtime dependencies of an
        npm release that no file of it names (registry/unused_deps.py), but
        not one of npm's most-downloaded packages (a tslib its build
        inlined) nor one of the package's own scope. Only when every text
        member was read whole: one past the archive's limits, over the size
        limit or the text budget, or not reached in time could name it.
        Kept for scan_package, which makes a brand-new one CRITICAL."""
        if self.artifact != "npm" or self.unread or self.dropped or self.oversize or self.timed_out:
            return
        text = self.manifests.get("package.json")
        data, _problems = lazaret.load_manifest("package.json", text) if text else (None, None)
        if not isinstance(data, dict):
            return
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        scope = name.split("/", 1)[0] + "/" if name.startswith("@") and "/" in name else None
        texts = ([t for t, _lang in self.sources.values() if t]
                 + [t for r, t in self.manifests.items() if r != "package.json" and t]
                 + [t for t in self.shell.values() if t] + list(self.deferred.values()))
        found = [(dep, spec) for dep, spec in _unused.npm_unused(data, texts)
                 if not (scope and dep.startswith(scope))
                 and not _lookalike.popular("npm", _unused.npm_registry_name(dep, spec))]
        if found:
            self.unused_dependencies = [_unused.npm_registry_name(dep, spec) for dep, spec in found]
            self.issues.append(_unused_dependency_issue([dep for dep, _spec in found], text))

    def _reachable(self):
        """Entry files plus local files they require/import (JS), transitively.
        A file reached this way runs when the package is loaded: one not
        scanned yet (index.js requiring ./lib/core.dat) is scanned now as
        JavaScript, or counted as not scanned. They used to be found and
        left alone, so a payload one require() away from main was OK."""
        # `seen` holds archive members only (at most MAX_FILES) and the deadline
        # is checked per file; the old cap of 10,000 files skipped the walk
        # altogether once exports patterns made that many files entry points
        seen, queue = set(self.entries), list(self.entries)
        while queue:
            rel = queue.pop()
            self._deadline(rel)
            text, lang = self.sources.get(rel, (None, None))
            if not text or lang != "js":
                continue
            base = posixpath.dirname(rel)
            for _q, target in _JS_LOCAL_DEP_RE.findall(text):
                dep = self._resolve(_rel_join(base, target))
                if dep and dep not in seen:
                    seen.add(dep)
                    self._text_of(dep, "js", imported=True)
                    queue.append(dep)
        return seen

    def finish(self, anomalies):
        self.scan_pending()
        self.first_pass = False
        for kind, path, detail in anomalies:
            self.issues.append(_archive_issue(kind, path, detail))
        reachable = None
        # The deadline is checked between these phases and before each file
        # they scan: past it, the rest is not scanned and the archive is
        # INCOMPLETE (this pass used to run to the end whatever the time).
        try:
            self._phase("the entry points", self._entry_point_manifests)
            self._phase("the install hooks", self._follow_hooks)
            if self.artifact == "sdist":
                self._phase("the install scripts", self._python_install_scripts)
            if self.artifact == "wheel":
                self._phase("the start-up modules", self._startup_modules)
            reachable = self._phase("the files the entry points load", self._reachable)
            self._phase("the import-time code", self._import_time_code,
                        reachable if reachable is not None else set(self.entries))
            if self.artifact in PACKAGE_CODE:
                self._phase(f"the {'module' if self.artifact == 'gomod' else 'crate'}'s code", self._package_code)
            if self.artifact == "sdist" and (self.code_text or self.code_dropped):
                self._phase("the Rust crates' code", self._sdist_crates)
            self._phase("the agent-hijack check", self._agent_hijack)
            self._phase("the package's names", self._lookalike_names)
            self._phase("the dependencies nothing uses", self._unused_dependencies)
            # interprocedural / cross-file taint (full profile only — needs whole source)
            if self.full and getattr(lazaret, "lazaret_flow", None) is not None:
                self._deadline("the cross-file analysis")
                records = [{"path": r, "content": t, "lang": lang}
                           for r, (t, lang) in self.sources.items()]
                try:
                    self.issues.extend(lazaret.lazaret_flow.analyze(records))
                except Exception as exc:                            # noqa: BLE001
                    print(f"warning: interprocedural taint analysis skipped "
                          f"({type(exc).__name__})", file=sys.stderr)
        except _OutOfTime:
            pass                              # recorded: the archive is INCOMPLETE
        if self.unread_code:
            self.issues.append(_unread_code_issue(self.artifact, sorted(self.unread_code)))
        _demote_test_findings(self.issues, reachable if reachable is not None else self.entries)
        # F9b: the decompressed sources are no longer needed
        self.sources, self.deferred, self.shell, self.code_text = {}, {}, {}, {}


_PY_LOCAL_IMPORT_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][\w.]*))", re.M)
# `from .main import x` / `from ..util import y`: a module of the importing
# file's own package (or one above it)
_PY_RELATIVE_IMPORT_RE = re.compile(r"^\s*from\s+(\.+)([A-Za-z_][\w.]*)\s+import\b", re.M)
_PEP517_SECTION_RE = re.compile(r"^\s*\[build-system\]\s*$(.*?)(?=^\s*\[|\Z)", re.M | re.S)


def _pep517_backend(pyproject):
    """(build-backend, backend-path list) from pyproject.toml text; tomllib
    where available (3.11+), a narrow regex reader on 3.10."""
    if not pyproject:
        return None, []
    try:
        # stdlib from Python 3.11; loaded by name so the 3.10 stdlib guard
        # (tests/architecture) does not see an import it cannot resolve
        tomllib = importlib.import_module("tomllib")
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            section = tomllib.loads(pyproject).get("build-system") or {}
        except (ValueError, RecursionError):       # TOMLDecodeError is a ValueError
            section = None
        if isinstance(section, dict):
            backend = section.get("build-backend")
            paths = section.get("backend-path")
            return (backend if isinstance(backend, str) else None,
                    [p for p in paths if isinstance(p, str)] if isinstance(paths, list) else [])
    m = _PEP517_SECTION_RE.search(pyproject)
    if not m:
        return None, []
    body = m.group(1)
    backend = re.search(r"""^\s*build-backend\s*=\s*["']([^"']+)["']""", body, re.M)
    paths = re.search(r"""^\s*backend-path\s*=\s*\[([^\]]*)\]""", body, re.M | re.S)
    return (backend.group(1) if backend else None,
            re.findall(r"""["']([^"']+)["']""", paths.group(1)) if paths else [])


def _scan_artifact(data, container, artifact, full, budget, memo=None):
    """Scan one archive -> per-artifact result fields (issues, counts, verdict).
    `memo`: the engine's answers by content, shared with the release's other
    files (contentcache.Memo; none by default)."""
    st = _ArtifactScan(artifact, full, budget, memo)
    anomalies = []
    try:
        for m in iter_archive(data, container, artifact, budget=budget, anomalies=anomalies):
            st.member(m)
            if st.out_of_time("(archive)"):          # between members
                break
    except _OutOfTime:
        pass                             # inside a member: recorded where it stopped
    except ArchiveLimit as lim:          # (defensive: iter_archive yields its limits)
        st.truncate("(archive)", lim.detail or st.limit_detail(lim.reason, "(archive)"))
    st.finish(anomalies)
    issues = st.issues
    verdict, reason, strong, weak = decide_verdict(issues, st.truncated)
    return {"issues": issues, "filesScanned": st.files_scanned, "binaryArtifacts": st.binaries,
            "truncated": st.truncated, "verdict": verdict, "verdictReason": reason,
            "strongIndicators": strong, "weakIndicators": weak,
            "unusedDependencies": st.unused_dependencies, "useTime": st.use_time}


def _fmt_bytes(n):
    """1536 -> '1.5 KiB' (binary units, one decimal)."""
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"  # pragma: no cover


def declared_size(meta_entry):
    """Byte size a registry declares for one artifact (PyPI's `size`), or
    None when it declares none. Used to refuse a download BEFORE it starts."""
    size = meta_entry.get("size") if isinstance(meta_entry, dict) else None
    if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
        return size
    return None


def _skipped_summary(skipped, byte_budget, limit):
    """SC-TRUNCATED issues + a short verdict-reason phrase for release files
    that were not scanned. skipped: [(filename, kind, size)] with kind
    'artifacts' | 'budget' | 'filesize' | 'time' | 'packagetype'."""
    issues, labels = [], []
    groups = {}
    for filename, kind, size in skipped:
        groups.setdefault(kind, []).append((filename, size))

    def names(items):
        shown = ", ".join(str(f) for f, _ in items[:3])
        return shown + (f", … (+{len(items) - 3})" if len(items) > 3 else "")

    if "artifacts" in groups:
        items = groups["artifacts"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} more release file(s) not scanned (limit {limit} "
                         f"artifacts per release; raise --max-artifacts)"))
        labels.append(f"more than {limit} files (--max-artifacts)")
    if "packagetype" in groups:
        items = groups["packagetype"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not scanned: PyPI lists them as neither an "
                         f"sdist nor a wheel, but pip may install an archive named like this "
                         f"({names(items)})"))
        labels.append("archives of another package type")
    if "filesize" in groups:
        items = groups["filesize"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: each is larger than "
                         f"the {_fmt_bytes(MAX_DOWNLOAD_BYTES)} per-file download limit "
                         f"({names(items)})"))
        labels.append(f"over the {_fmt_bytes(MAX_DOWNLOAD_BYTES)} per-file limit")
    if "budget" in groups:
        items = groups["budget"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: they would take the "
                         f"package past its {_fmt_bytes(byte_budget)} download budget "
                         f"({names(items)}; raise --max-download-bytes / "
                         f"LAZARET_MAX_DOWNLOAD_BYTES)"))
        labels.append(f"over the {_fmt_bytes(byte_budget)} download budget (--max-download-bytes)")
    if "time" in groups:                   # only the caller's deadline stops downloads
        items = groups["time"]
        issues.append(lazaret.truncated_issue(
            "(release)", f"{len(items)} release file(s) not downloaded: the caller's time "
                         f"budget for this package ran out ({names(items)})"))
        labels.append("the caller's time budget ran out")
    return issues, "; ".join(labels)


def _always_redacted(fn):
    """What `fn` returns is stored in the state DB (and read back by
    `report` and the MCP tools), so it is always redacted: neither the
    registry CLI's --no-redact-secrets nor the MCP server's LAZARET_NO_REDACT
    may put a raw credential line in the DB (review P2). The whole scan runs
    under core.forced_redaction(), because redaction happens as each finding
    is created, from the whole file."""
    @functools.wraps(fn)
    def run(*args, **kwargs):
        with lazaret.forced_redaction():
            return fn(*args, **kwargs)
    return run


# ---------------- A release that adds a new dependency (SC-NEW-DEPENDENCY, 0.1.8) ----------------
# The @mastra compromise (June 2026) changed no code: each hijacked release
# gained a dependency on easy-day-js, published by another account 19 hours
# before, which carried the payload (17 of the 0.1.7 benchmark's misses; the
# releases themselves read OK). A release rarely depends on a package that
# did not exist a week earlier, from someone who does not maintain it. So a
# registry scan compares a release's dependencies with those of the release
# published before it (npm: the packument's versions and times; PyPI: the
# project's release files and each release's requires_dist; a prerelease is
# compared with any version, a release with releases only) and looks up at
# most NEW_DEP_LOOKUPS added ones: CRITICAL for one first published less than
# NEW_DEP_CRITICAL before the release, MAJOR for one under NEW_DEP_RECENT.
# Not counted: a dependency of the package's own npm scope, or one an npm
# maintainer of the package also maintains; (the detection round) on PyPI
# one an owner or maintainer of the project also owns or maintains, or its
# organization owns (the JSON API's "ownership"); an optional extra's
# requirement (PyPI); a git, file or URL dependency. Best effort: a document over the
# metadata budget (an established package's) or a registry that does not
# answer is not a finding, and a release with no dependencies costs no
# request. LAZARET_NO_DEPENDENCY_HISTORY=1 turns it off (an offline scan).
NEW_DEP_CRITICAL = datetime.timedelta(days=7)
NEW_DEP_RECENT = datetime.timedelta(days=30)
NEW_DEP_LOOKUPS = 5
_NPM_NOT_REGISTRY = ("file:", "link:", "workspace:", "portal:", "git:", "git+", "github:", "gitlab:", "bitbucket:",
                     "http:", "https:")
_PY_REQ_NAME_RE = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _iso_time(value):
    """An aware datetime from registry time text ('2026-06-17T02:06:22.156Z'), else None."""
    if not isinstance(value, str):
        return None
    try:
        return _to_utc(datetime.datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
    except ValueError:
        return None


def _npm_scope(name):
    return name.split("/", 1)[0] if name.startswith("@") and "/" in name else None


def npm_dependency_names(manifest):
    """The registry packages a package.json depends on (dependencies and
    optionalDependencies; an `npm:` alias as the package it names)."""
    out = set()
    for field in ("dependencies", "optionalDependencies"):
        deps = manifest.get(field) if isinstance(manifest, dict) else None
        if not isinstance(deps, dict):
            continue
        for key, spec in deps.items():
            if not isinstance(key, str) or not key:
                continue
            spec = spec.strip() if isinstance(spec, str) else ""
            if spec.startswith("npm:"):
                target = spec[4:]
                at = target.rfind("@")
                key = target[:at] if at > 0 else target
            elif spec.startswith(_NPM_NOT_REGISTRY) or ("/" in spec and not spec.startswith("@")):
                continue                       # a file, link, git or URL dependency; user/repo is GitHub
            if key:
                out.add(key)
    return out


def pypi_dependency_names(requires_dist):
    """The PEP 503 names a release requires, leaving out optional extras'."""
    out = set()
    for req in requires_dist if isinstance(requires_dist, list) else ():
        if not isinstance(req, str) or re.search(r"\bextra\s*==", req):
            continue
        m = _PY_REQ_NAME_RE.match(req)
        if m:
            out.add(_pep503(m.group(1)))
    return out


def _previous_release(times, version, candidates, prerelease):
    """(time of `version`, the candidate published last before it) from
    {version: time text}; a prerelease candidate only when `version` is one.
    (None, None) when the time of `version` is unknown."""
    when = _iso_time(times.get(version))
    if when is None:
        return None, None
    best = None
    for v in candidates:
        if v == version or (prerelease(v) and not prerelease(version)):
            continue
        t = _iso_time(times.get(v))
        if t is not None and t < when and (best is None or t > best[1]):
            best = (v, t)
    return when, best[0] if best else None


def _age_text(age):
    hours = age.total_seconds() / 3600
    if hours < 48:
        n = max(1, int(hours))
        return f"{n} hour{'s' if n != 1 else ''}"
    n = int(hours // 24)
    return f"{n} day{'s' if n != 1 else ''}"


_UNUSED_WHY = ("A dependency is installed with the package, and its install scripts run, whether the package's "
               "code uses it or not. The @mastra compromise (June 2026) changed no code: each hijacked release gained "
               "a dependency on easy-day-js, which no file of it named and which carried the payload. Packages also "
               "keep dependencies their build inlined or that they no longer use, so on its own this is context; a "
               "scan that sees the dependency is brand-new makes it SC-NEW-DEPENDENCY, CRITICAL.")


def _unused_dependency_issue(names, text):
    """SC-UNUSED-DEPENDENCY (INFO) for an npm release's dependencies that no
    file names, at the first one's line of package.json."""
    lines = (text or "").split("\n")
    line = _lookalike._line_of(text, [json.dumps(names[0]) + ":"])
    if len(names) == 1:
        msg = (f'Depends on "{names[0]}", which no file of the package names: installing the package installs it, '
               "and runs its install scripts, for nothing the package does.")
    else:
        shown = ", ".join(f'"{n}"' for n in names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        msg = (f"Depends on {len(names)} packages no file of the package names ({shown}): installing the package "
               "installs them, and runs their install scripts, for nothing the package does.")
    return lazaret.mk_issue(
        {"id": "SC-UNUSED-DEPENDENCY", "name": "A dependency nothing uses", "type": "HOTSPOT", "sev": "INFO",
         "msg": msg, "why": _UNUSED_WHY,
         "fix": "Find out why the package declares it, and read it before installing the package.",
         "ref": "CWE-506 · Supply chain"}, "package.json", line, lines)


def _new_dependency_issue(eco, dep, age, previous, owners, unused=False):
    """SC-NEW-DEPENDENCY: CRITICAL under NEW_DEP_CRITICAL, or when no file of
    the release uses it (`unused`, npm), else MAJOR."""
    sev = "CRITICAL" if age < NEW_DEP_CRITICAL or unused else "MAJOR"
    by = f" by {', '.join(owners[:3])}" if owners else ""
    had = f"which {previous} did not have" + (" and no file of this release names" if unused else "")
    return lazaret.mk_issue(
        {"id": "SC-NEW-DEPENDENCY", "name": "A release adds a brand-new dependency", "type": "HOTSPOT", "sev": sev,
         "msg": (f'Adds a dependency on "{dep}", {had}: a package first published '
                 f"{_age_text(age)} before this release{by}"
                 + (", who does not maintain this one." if eco == "npm" or owners else ".")),
         "why": ("The @mastra compromise (June 2026) changed no code: each hijacked release gained a dependency on "
                 "easy-day-js, published by another account 19 hours before, which carried the payload. A release "
                 "rarely depends on a package that did not exist a week earlier."),
         "fix": f'Read "{dep}" before installing this release; pin the previous one ({previous}) until you have.',
         "ref": "CWE-506 · Supply chain"},
        "package.json" if eco == "npm" else "(release)", 1, [])


def npm_new_dependencies(name, version, manifest, fetch=None):
    """-> (previous version, [(dependency, age, its maintainers)]) for the
    dependencies an npm release adds that are recent (see above)."""
    fetch = fetch or http_json
    mine = npm_dependency_names(manifest)
    if not mine:
        return None, []
    doc = fetch("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
    times = doc.get("time") if isinstance(doc, dict) else None
    versions = doc.get("versions") if isinstance(doc, dict) else None
    if not isinstance(times, dict) or not isinstance(versions, dict):
        return None, []
    when, previous = _previous_release(times, version, versions, lambda v: "-" in v)
    if previous is None:
        return None, []
    added = sorted(mine - npm_dependency_names(versions.get(previous)))
    owners = {m.get("name") for m in doc.get("maintainers") or () if isinstance(m, dict)}
    scope, found = _npm_scope(name), []
    for dep in added:
        if len(found) >= NEW_DEP_LOOKUPS:
            break
        if scope is not None and _npm_scope(dep) == scope:
            continue
        try:
            ddoc = fetch("https://registry.npmjs.org/" + urllib.parse.quote(dep, safe="@"))
        except FetchError:
            continue                     # over the budget: an established package; or unreachable
        created = _iso_time((ddoc.get("time") or {}).get("created") if isinstance(ddoc, dict) else None)
        if created is None:
            continue
        age = max(when - created, datetime.timedelta(0))
        if age >= NEW_DEP_RECENT:
            continue
        theirs = sorted({m.get("name") for m in ddoc.get("maintainers") or ()
                         if isinstance(m, dict) and isinstance(m.get("name"), str)})
        if owners & set(theirs):
            continue
        found.append((dep, age, theirs))
    return previous, found


def _pypi_first_upload(files):
    times = [_iso_time(f.get("upload_time_iso_8601")) for f in files or () if isinstance(f, dict)]
    times = [t for t in times if t is not None]
    return min(times) if times else None


def _pypi_ownership(doc):
    """({owner and maintainer usernames}, organization or None) of a PyPI
    JSON document's "ownership"; empty where it has none."""
    own = doc.get("ownership") if isinstance(doc, dict) else None
    if not isinstance(own, dict):
        return set(), None
    users = {r.get("user") for r in own.get("roles") or () if isinstance(r, dict) and isinstance(r.get("user"), str)}
    org = own.get("organization")
    return users, org if isinstance(org, str) and org else None


def pypi_new_dependencies(name, version, info, fetch=None):
    """-> (previous version, [(dependency, age, its owners and maintainers)])
    for the requirements a PyPI release adds that are recent (see above)."""
    fetch = fetch or http_json
    mine = pypi_dependency_names((info or {}).get("requires_dist"))
    if not mine:
        return None, []
    doc = fetch(f"https://pypi.org/pypi/{_quote_seg(name)}/json")
    releases = doc.get("releases") if isinstance(doc, dict) else None
    if not isinstance(releases, dict):
        return None, []
    times = {}
    for v, files in releases.items():
        first = _pypi_first_upload(files)
        if first is not None:
            times[v] = first.isoformat()
    when, previous = _previous_release(times, version, releases, lambda v: not _PEP440_FINAL_RE.match(v))
    if previous is None:
        return None, []
    prev = fetch(f"https://pypi.org/pypi/{_quote_seg(name)}/{_quote_seg(previous)}/json")
    prev_info = prev.get("info") if isinstance(prev, dict) else None
    added = sorted(mine - pypi_dependency_names((prev_info or {}).get("requires_dist")))
    users, org = _pypi_ownership(doc)
    found = []
    for dep in added:
        if len(found) >= NEW_DEP_LOOKUPS:
            break
        try:
            ddoc = fetch(f"https://pypi.org/pypi/{_quote_seg(dep)}/json")
        except FetchError:
            continue
        rels = ddoc.get("releases") if isinstance(ddoc, dict) else None
        firsts = [t for t in (_pypi_first_upload(fs) for fs in (rels or {}).values()) if t is not None]
        if not firsts:
            continue
        age = max(when - min(firsts), datetime.timedelta(0))
        if age >= NEW_DEP_RECENT:
            continue
        theirs, their_org = _pypi_ownership(ddoc)
        if users & theirs or (org is not None and their_org == org):
            continue                     # the project's own account or organization
        found.append((dep, age, sorted(theirs)))
    return previous, found


def new_dependency_issues(eco, name, version, resolved, unused=()):
    """SC-NEW-DEPENDENCY findings for one release (best effort: [] when the
    registry can't say). unused: the registry names of the dependencies no
    file of the release names (the artifact scan's unusedDependencies)."""
    if os.environ.get("LAZARET_NO_DEPENDENCY_HISTORY") or eco not in ("npm", "pypi"):
        return []                        # (a crate's: N-3's second part, from the sparse index)
    try:
        if eco == "npm":
            previous, found = npm_new_dependencies(name, version, resolved[4])
        else:
            previous, found = pypi_new_dependencies(name, version, getattr(resolved, "info", None))
    except (FetchError, ValueError):
        return []
    unused = set(unused)
    return [_new_dependency_issue(eco, dep, age, previous, owners, dep in unused) for dep, age, owners in found]


@_always_redacted
def scan_package(eco, name, version=None, full=False, *, resolved=None, deadline=None,
                 cancel=None, max_artifacts=None, max_download_bytes=None):
    """Fetch and scan one package version. Returns a result dict.

    Every archive member is classified as source or binary. Source files (by
    extension, by #! line, or because package.json runs them) are run through
    the normal ruleset; binary/compiled artifacts through classify_binary,
    which flags smuggled executables, nested archives, and opaque
    high-entropy blobs — with severity that depends on whether they belong
    (sdist/npm vs wheel).

    PyPI: every file of the release pip may install is scanned (sdist and
    each distinct wheel, at most max_artifacts files and max_download_bytes
    bytes in total); the verdict is the worst one, and result["artifacts"]
    keeps the per-file detail. A file that does not fit — past the artifact
    limit, over the per-file download limit or the package's download budget
    by its DECLARED size (checked before downloading), or reached after the
    deadline — is not downloaded; it is listed in result["skippedArtifacts"],
    an SC-TRUNCATED finding names it, and the verdict is INCOMPLETE at best.
    Files PyPI lists as neither sdist nor wheel are listed there too: as not
    scanned (INCOMPLETE) when pip may install them anyway (an archive, by
    its name), as "not-installable" otherwise (eggs, installers).

    resolved: a resolve_npm/resolve_pypi result already fetched (scan-all
    checks the version before downloading). deadline: absolute
    time.monotonic() bound for the whole package (MCP budget); each archive
    also gets SCAN_TIMEOUT. cancel: callable; True stops the scan with
    ScanCancelled."""
    started = time.monotonic()
    module = registry_module(eco)       # go and crates: their module downloads and checks
    if resolved is None:
        resolved = resolve(eco, name, version)
    version, url, container, artifact, meta_entry = resolved
    refs = getattr(resolved, "artifacts", None) or [
        {"url": url, "container": container, "artifact": artifact, "entry": meta_entry,
         "filename": url.rsplit("/", 1)[-1] if isinstance(url, str) else None}]
    limit = max_artifacts or MAX_ARTIFACTS
    byte_budget = max_download_bytes or MAX_PACKAGE_DOWNLOAD_BYTES
    over, refs = refs[limit:], refs[:limit]
    skipped = [(r.get("filename"), "artifacts", declared_size(r.get("entry"))) for r in over]
    # release files resolve_pypi did not select: one pip may install (an
    # archive by its name) was not scanned, so the release can't be cleared;
    # the rest (eggs, installers) are only listed. They used to be dropped
    # without a word: a lone .tar.lzma sdist left the release "OK".
    not_installed = []
    for s in getattr(resolved, "skipped", None) or ():
        if not isinstance(s, dict):
            continue
        size = declared_size(s)
        installable = s.get("installable")
        if installable is None:
            installable = pypi_container(s.get("filename")) is not None
        if installable:
            skipped.append((s.get("filename"), "packagetype", size))
        else:
            not_installed.append((s.get("filename"), "not-installable", size))
    per, all_issues, truncated, unused = [], [], 0, set()
    multi = len(refs) > 1
    downloaded = 0
    memo = new_memo()                      # (the release's files share the engine's answers: P-2a)
    for ref in refs:
        size = declared_size(ref.get("entry"))
        if cancel is not None and cancel():
            raise ScanCancelled("scan cancelled")
        if deadline is not None and time.monotonic() > deadline:
            skipped.append((ref.get("filename"), "time", size))
            continue
        if size is not None and size > MAX_DOWNLOAD_BYTES:
            skipped.append((ref.get("filename"), "filesize", size))
            continue
        if downloaded >= byte_budget or (size is not None and downloaded + size > byte_budget):
            skipped.append((ref.get("filename"), "budget", size))
            continue
        if module is None:
            data = http_bytes(ref["url"])
        else:
            data = module_fetch(module).bytes(ref["url"], MAX_DOWNLOAD_BYTES)
        downloaded += max(len(data), size or 0)
        # G15: verify the artifact against the registry-published digest BEFORE
        # scanning anything — a mismatch raises and nothing is persisted under
        # this name/version.
        digest = (verify_digest(data, ref["entry"], eco, name, version) if module is None
                  else _module_digest(module, data, ref["entry"], eco, name, version))
        stop = time.monotonic() + SCAN_TIMEOUT
        if deadline is not None and deadline < stop:
            # the caller's deadline comes first: say so, not "120 s exceeded"
            budget = Budget(deadline=deadline, cancel=cancel, deadline_detail=(
                f"the caller's time budget of {max(0.0, deadline - started):.1f} s for "
                f"this package ran out"))
        else:
            budget = Budget(deadline=stop, cancel=cancel, deadline_detail=(
                f"scan time budget of {SCAN_TIMEOUT:g} s per archive (--scan-timeout) exceeded"))
        r = _scan_artifact(data, ref["container"], ref["artifact"], full, budget, memo)
        prefix = f"{ref['filename']}/" if multi and ref.get("filename") else ""
        for issue in r["issues"]:
            if prefix:
                issue["file"] = prefix + issue["file"]
                issue["artifact"] = ref["filename"]
            all_issues.append(issue)
        truncated += r["truncated"]
        unused.update(r.get("unusedDependencies") or ())
        per.append({"filename": ref.get("filename"), "kind": ref["artifact"], "url": ref["url"],
                    "archiveBytes": len(data), "digest": digest,
                    **{k: r[k] for k in ("verdict", "verdictReason", "filesScanned",
                                         "binaryArtifacts", "truncated",
                                         "strongIndicators", "weakIndicators", "useTime")}})
    all_issues.extend(new_dependency_issues(eco, name, version, resolved, unused))
    skip_issues, skip_label = _skipped_summary(skipped, byte_budget, limit)
    # one part per release file left out; skip_issues holds one finding per
    # REASON, and used to be counted instead ("1 part" for 3 skipped files)
    truncated += len(skipped)
    all_issues.extend(skip_issues)
    all_issues.sort(key=lambda i: (lazaret.SEV_ORDER[i["sev"]], i["file"], i["line"]))
    sev_counts = {s: 0 for s in lazaret.SEV_ORDER}
    for i in all_issues:
        sev_counts[i["sev"]] += 1
    # Only supply-chain indicators decide the verdict (see "Verdicts" above).
    # Verdict integrity: a truncated scan can never be cleared, because the
    # unscanned members are attacker-chosen: it is INCOMPLETE at best.
    verdict, reason, strong, weak = decide_verdict(all_issues, truncated)
    if multi and per:
        worst = max(per, key=lambda p: VERDICT_RANK.get(p["verdict"], 0))
        if VERDICT_RANK.get(worst["verdict"], 0) == VERDICT_RANK.get(verdict, 0) \
                and verdict != "OK":
            reason += f" (worst: {worst['filename']}; {len(per)} release files scanned)"
        else:
            reason += f" ({len(per)} release files scanned)"
    if skipped:
        reason += (f"; {len(skipped)} of {len(per) + len(skipped)} release files not "
                   f"scanned: {skip_label}")
    # L1 (artifact hygiene): redaction is default-on, so the issues this
    # result carries — including the ones persisted as the Store blob via
    # save_scan — already have placeholder/scrubbed snippets from mk_issue.
    # This defensive sweep exists so the registry path cannot regress.
    all_issues = lazaret.redact_result({"issues": list(all_issues)})["issues"]
    kinds = [p["kind"] for p in per]
    artifact_label = kinds[0] if len(kinds) == 1 else (
        "+".join(filter(None, ["sdist" if "sdist" in kinds else "",
                               f"{kinds.count('wheel')} wheel{'s' if kinds.count('wheel') != 1 else ''}"
                               if "wheel" in kinds else ""])))
    return {"ecosystem": eco, "name": name, "version": version, "artifact": artifact_label,
            "archiveBytes": sum(p["archiveBytes"] for p in per),
            "filesScanned": sum(p["filesScanned"] for p in per),
            "binaryArtifacts": sum(p["binaryArtifacts"] for p in per),
            "profile": "full" if full else "supply-chain",
            "sevCounts": sev_counts, "supplyChain": strong + weak, "strongIndicators": strong,
            "weakIndicators": weak, "truncated": truncated,
            "verdict": verdict, "verdictReason": reason, "issues": all_issues,
            "digest": per[0]["digest"] if per else None, "artifacts": per,
            "skippedArtifacts": [{"filename": f, "reason": kind, "declaredBytes": size}
                                 for f, kind, size in skipped + not_installed],
            "useTime": use_time_total([p["useTime"] for p in per]),
            "scannedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}


def use_time_total(parts):
    """The release's use-time share (_ArtifactScan.use_time): the sums over
    the release files the step read, with the bound per file it read them
    with, or None when it ran on none of them (each was SUSPICIOUS before
    it)."""
    parts = [p for p in parts if p]
    if not parts:
        return None
    total = {k: sum(p[k] for p in parts) for k in ("files", "ofFiles", "chars", "ofChars")}
    total["boundChars"] = max(p.get("boundChars", USE_RISK_CHARS) for p in parts)
    return total


def use_time_line(use_time):
    """One line for a report when the use-time step left code unread (None
    otherwise): how much it read, of how much, and why the rest is not."""
    if not use_time or use_time["chars"] >= use_time["ofChars"]:
        return None
    percent = use_time["chars"] * 100 // use_time["ofChars"]          # rounded down: 99%, never 100%
    return (f"SC-USE-RISK read {use_time['files']:,} of the {use_time['ofFiles']:,} files that run only "
            f"when the package is used, {percent}% of their characters (smallest first, none over "
            f"{USE_RISK_MAX_CHARS:,} characters, {use_time.get('boundChars', USE_RISK_CHARS):,} in all per "
            f"release file)")


# ---------------- State store (SQLite / Postgres) ----------------
_PG_KEYWORD_RE = re.compile(
    r"^\s*(?:host|hostaddr|port|dbname|database|user|password|passfile|sslmode|sslrootcert|"
    r"sslcert|sslkey|connect_timeout|application_name|channel_binding|require_auth|options|"
    r"service|target_session_attrs)\s*=", re.I)
_PG_SCHEME_RE = re.compile(r"^\s*(postgres(?:ql)?)://", re.I)


def classify_dsn(dsn):
    """--db / LAZARET_DB -> ('pg', dsn) or ('sqlite', path).

    postgres:// and postgresql:// in any letter case, and libpq keyword
    strings ("host=db user=app dbname=lazaret"), select Postgres; `sqlite:`
    / `sqlite:///` prefixes and plain paths select SQLite. A plain path
    containing '=' is refused: it is almost certainly a mistyped connection
    string, and SQLite would create a FILE named after it — password
    included. Error messages never echo the value."""
    if not isinstance(dsn, str) or not dsn.strip():
        raise StoreConfigError("empty database location (--db / LAZARET_DB)")
    m = _PG_SCHEME_RE.match(dsn)
    if m:
        return "pg", m.group(1).lower() + dsn[m.end(1):].lstrip()
    if _PG_KEYWORD_RE.match(dsn):
        return "pg", dsn.strip()
    if dsn.lower().startswith("sqlite:"):
        path = dsn[len("sqlite:"):]
        if path.startswith("///"):
            path = path[3:]
        elif path.startswith("//"):
            path = path[2:]
        if not path:
            raise StoreConfigError("sqlite: needs a path (sqlite:PATH or sqlite:///PATH)")
        return "sqlite", path
    if "=" in dsn:
        raise StoreConfigError(
            "database location contains '=' but is not a recognized Postgres connection "
            "string; refusing to create a SQLite file with that name (use postgres://…, "
            "a libpq 'host=… dbname=…' string, or sqlite:PATH)")
    if "://" in dsn:
        raise StoreConfigError("unsupported database URL scheme (use postgres:// or sqlite:)")
    return "sqlite", dsn


def _db_text(value):
    """Text a Postgres TEXT/JSONB value can hold: no NUL, no lone surrogate
    (a hook command with \\u0000, an archive member name that is not UTF-8)."""
    if not isinstance(value, str):
        return value
    if "\x00" in value:
        value = value.replace("\x00", "\\x00")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        value = value.encode("utf-8", "backslashreplace").decode("utf-8")
    return value


def _db_clean(obj, depth=0):
    """_db_text over a JSON-shaped structure (bounded depth)."""
    if isinstance(obj, str):
        return _db_text(obj)
    if depth > 64:
        return None
    if isinstance(obj, dict):
        return {_db_text(str(k)): _db_clean(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_db_clean(v, depth + 1) for v in obj]
    return obj


def db_json(obj):
    """JSON text for the issues/artifacts columns. Non-ASCII stays literal
    UTF-8 (a \\uXXXX escape above U+007F is refused by a JSONB column in a
    non-UTF8 database), NUL and lone surrogates are made storable first."""
    return json.dumps(_db_clean(obj), ensure_ascii=False)


# Insecure escape hatches for a Postgres state DB that still authenticates
# with MD5 or a cleartext password. lazaret.pg refuses both over TLS whose
# certificate is not verified (sslmode=prefer/require, the default is
# prefer): a man-in-the-middle terminating TLS could relay the MD5 response
# or read the password. Its opt-outs are keyword arguments of pg.connect(),
# not libpq parameters — the DSN parser rejects them as unknown — so a
# LAZARET_DB DSN cannot carry them. Set one of these variables to "1" to
# opt in; prefer sslmode=verify-full or a SCRAM-SHA-256 role instead.
PG_INSECURE_AUTH_ENV = {
    "LAZARET_PG_ALLOW_MD5_OVER_UNVERIFIED_TLS": "allow_md5_over_unverified_tls",
    "LAZARET_PG_ALLOW_CLEARTEXT_PASSWORD": "allow_cleartext_password",
}


def pg_insecure_auth_options(environ=None):
    """pg.connect() keyword arguments enabled by PG_INSECURE_AUTH_ENV
    (exactly "1" enables one; anything else leaves lazaret.pg's refusal)."""
    env = os.environ if environ is None else environ
    return {kw: True for var, kw in PG_INSECURE_AUTH_ENV.items() if env.get(var) == "1"}


def _cursor_table(t=""):
    """DDL of the discovery cursors (the same for SQLite and Postgres): where
    `discover --resume` continues for each registry. seq is PyPI's changelog
    serial or npm's replication sequence number, as text; seq_time (the time
    of that change, when known) and updated_at are ISO 8601 UTC."""
    return (f"CREATE TABLE IF NOT EXISTS {t}discovery_cursors ("
            f"ecosystem TEXT PRIMARY KEY, seq TEXT NOT NULL, seq_time TEXT, "
            f"updated_at TEXT NOT NULL)")


class Store:
    def __init__(self, dsn):
        kind, target = classify_dsn(dsn)
        self.pg = kind == "pg"
        schema_errors = ()        # errors of the backend that mean "--db is not usable"
        if self.pg:
            from lazaret import pg as lazaret_pg
            # audit H2 (=F3/F4): Store is LIBRARY code — the MCP server
            # constructs it inside tool dispatch (scan_package /
            # registry_status / discover_packages), where sys.exit()
            # bypasses every `except Exception` and kills the whole
            # server with no error reply. RuntimeError propagates to the
            # tool boundary normally; the CLI boundary (main) converts
            # it back to the identical sys.exit() message and exit code.
            # (License note: the backend is the internal stdlib-only
            # lazaret_pg client — no external driver, nothing to pip-install.)
            try:
                self.conn = lazaret_pg.connect(   # DSN should target a dedicated lazaret DB
                    target, timeout=30, application_name="lazaret",
                    **pg_insecure_auth_options())
            except (lazaret_pg.Error, OSError) as exc:
                raise RuntimeError(f"Postgres backend unreachable: {exc}") from exc
            self._pg_errors = lazaret_pg
            self.ph, self.t = "$1", ""
        else:
            import sqlite3
            # G20 (artifact hygiene): registry state is shared by concurrent
            # writers (a `scan-all` sweep while the MCP server answers
            # tool calls against the same LAZARET_DB). Plain connect()
            # gave us the 5s default lock timeout and no WAL, so writers
            # crashed with "database is locked" mid-sweep. 30s busy timeout
            # + WAL (readers never block writers) is the standard remedy.
            try:
                self.conn = sqlite3.connect(target, timeout=30)
            except sqlite3.Error as exc:
                raise StoreConfigError(f"cannot open SQLite database: {exc}") from exc
            self._configure_sqlite()
            self.ph, self.t = "?", ""
            # connect() opens any file lazily: a --db that is not a SQLite
            # database ("file is not a database") first fails here, and used
            # to escape as a sqlite3.DatabaseError traceback
            schema_errors = (sqlite3.Error,)
        try:
            self._init_schema()
        except schema_errors as exc:
            self.close()
            raise StoreConfigError(f"cannot use the SQLite database: {exc} "
                                   f"(check --db / LAZARET_DB)") from exc
        except BaseException:
            self.close()
            raise

    def close(self):
        """Close the database connection (idempotent). Every caller closes
        what it opens: a long-running MCP server must not keep a handle per
        tool call, and Windows can't delete a database file that is still
        open (STRUCTURE.md, "Cross-platform rules", rule 3)."""
        conn = getattr(self, "conn", None)
        if conn is not None and not getattr(self, "_closed", False):
            self._closed = True
            try:
                conn.close()
            except Exception:                                  # noqa: BLE001
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def _phs(self, n):
        """n positional placeholders for the ACTIVE backend, in order.

        sqlite wants `?` for every parameter; the Postgres wire protocol
        requires each parameter to have its OWN $k number ($1, $2, ...).
        SQL shared by both branches must interpolate this list, never a
        single repeated self.ph (which would send every value as $1)."""
        if self.pg:
            return [f"${i}" for i in range(1, n + 1)]
        return ["?"] * n

    def _configure_sqlite(self):
        """Best-effort pragmas for shared use; failures (exotic filesystems,
        immutable VFS, …) must not make the store unusable."""
        import sqlite3
        for pragma in ("PRAGMA journal_mode=WAL",
                       "PRAGMA synchronous=NORMAL",
                       "PRAGMA busy_timeout=30000"):
            try:
                self.conn.execute(pragma)
            except sqlite3.Error:
                pass

    def _init_schema(self):
        """Create the tables, and migrate older ones in place (idempotent):
        scans.artifacts holds the per-file detail of multi-artifact scans;
        discovery_cursors is created in databases made before it."""
        if self.pg:
            # Postgres DDL (SERIAL / JSONB): execute_script runs the whole
            # script as ONE implicit transaction via the simple protocol.
            self.conn.execute_script(f"""CREATE TABLE IF NOT EXISTS {self.t}packages (
                id SERIAL PRIMARY KEY, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
                added_at TEXT NOT NULL, UNIQUE (ecosystem, name));
                CREATE TABLE IF NOT EXISTS {self.t}scans (
                id SERIAL PRIMARY KEY, package_id INTEGER NOT NULL REFERENCES {self.t}packages(id),
                version TEXT NOT NULL, profile TEXT NOT NULL, scanned_at TEXT NOT NULL,
                engine_version TEXT NOT NULL, files_scanned INTEGER, archive_bytes INTEGER,
                blockers INTEGER, criticals INTEGER, majors INTEGER,
                supply_chain INTEGER, issue_count INTEGER, verdict TEXT,
                issues JSONB, artifacts JSONB,
                UNIQUE (package_id, version, profile, engine_version));
                ALTER TABLE {self.t}scans ADD COLUMN IF NOT EXISTS artifacts JSONB;
                CREATE INDEX IF NOT EXISTS idx_scans_package
                ON {self.t}scans(package_id, scanned_at DESC);
                {_cursor_table(self.t)}""")
            return
        cur = self.conn.cursor()
        serial, jsontype = "INTEGER PRIMARY KEY AUTOINCREMENT", "TEXT"
        cur.execute(f"""CREATE TABLE IF NOT EXISTS {self.t}packages (
            id {serial}, ecosystem TEXT NOT NULL, name TEXT NOT NULL,
            added_at TEXT NOT NULL, UNIQUE (ecosystem, name))""")
        cur.execute(f"""CREATE TABLE IF NOT EXISTS {self.t}scans (
            id {serial}, package_id INTEGER NOT NULL REFERENCES {self.t}packages(id),
            version TEXT NOT NULL, profile TEXT NOT NULL, scanned_at TEXT NOT NULL,
            engine_version TEXT NOT NULL, files_scanned INTEGER, archive_bytes INTEGER,
            blockers INTEGER, criticals INTEGER, majors INTEGER,
            supply_chain INTEGER, issue_count INTEGER, verdict TEXT,
            issues {jsontype}, artifacts {jsontype},
            UNIQUE (package_id, version, profile, engine_version))""")
        columns = {row[1] for row in cur.execute(f"PRAGMA table_info({self.t}scans)")}
        if "artifacts" not in columns:
            cur.execute(f"ALTER TABLE {self.t}scans ADD COLUMN artifacts {jsontype}")
        # G20: WAL already set at connect; index for the status() lateral join
        cur.execute(f"CREATE INDEX IF NOT EXISTS idx_scans_package "
                    f"ON {self.t}scans(package_id, scanned_at DESC)")
        cur.execute(_cursor_table(self.t))
        self.conn.commit()

    def _pg_call(self, run):
        """Run one self-contained Postgres operation, run() -> result, and
        survive a dropped session. The MCP server and scan-all keep a Store
        open for a long time; an admin shutdown or pg_terminate_backend
        (57P01), idle_session_timeout (57P05) or a network blip ends the
        session, and every later call used to fail with "connection is
        closed" until the process restarted.

        A connection already found closed (lost during an earlier call) is
        reopened first. An OperationalError from run() is followed by ONE
        conn.reconnect() and ONE retry; a second failure, or a failed
        reconnect (server still down), propagates. Never inside a
        transaction: when the caller has a transaction open, run() is not
        retried (a lone retried statement would silently drop the ones
        before it), and reconnect() itself refuses inside a transaction()
        block. run() may be a whole transaction() block of Store's own
        (save_scan): it is retried only as a whole, after the block has
        been left and rolled back. Every Store write is an idempotent
        upsert, so a retry after a lost COMMIT acknowledgement is safe
        (add_package's `created` flag may then read False)."""
        conn = self.conn
        if conn.closed:
            conn.reconnect()
        elif conn.in_transaction:
            return run()                  # the caller's transaction: never retried
        try:
            return run()
        except self._pg_errors.OperationalError:
            conn.reconnect()
            return run()

    def _one(self, sql, args=()):
        if self.pg:
            # wire client: fetchrow(sql, *args) with $n placeholders already
            # written into the SQL by the caller
            return self._pg_call(lambda: self.conn.fetchrow(sql, *args))
        cur = self.conn.cursor()
        cur.execute(sql, args)
        return cur.fetchone()

    def add_package(self, eco, name):
        """Idempotent package upsert, race-free (audit G20).

        The old SELECT-then-INSERT raced between a CLI `scan-all` sweep and
        the MCP server both adding the same (eco, name): one process hit the
        UNIQUE(ecosystem, name) constraint and the sweep died mid-run. The
        SQLite branch uses INSERT OR IGNORE followed by a SELECT inside one
        transaction (last-writer-wins; `added_at` keeps the first timestamp
        because the ignored row stays); the Postgres branch upserts with
        RETURNING so both writers converge on the same id.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        if self.pg:
            # race-free upsert: ON CONFLICT DO UPDATE converges both concurrent
            # writers on the same id; (xmax = 0) reports whether THIS call
            # created the row (False when it already existed, exactly like the
            # old DO NOTHING + SELECT fallback).
            row = self._pg_call(lambda: self.conn.fetchrow(
                f"INSERT INTO {self.t}packages (ecosystem,name,added_at) "
                f"VALUES ($1,$2,$3) "
                f"ON CONFLICT (ecosystem,name) DO UPDATE "
                f"SET added_at={self.t}packages.added_at "
                f"RETURNING id, (xmax = 0) AS created",
                eco, _db_text(name), now))
            return row[0], row[1]
        cur = self.conn.cursor()
        # SQLite: single write that is a no-op if the row exists (keeps the
        # original added_at), then read the id — committed atomically.
        created = False
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cur.execute(f"INSERT OR IGNORE INTO {self.t}packages "
                        f"(ecosystem,name,added_at) VALUES (?,?,?)",
                        (eco, name, now))
            created = cur.rowcount == 1
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        row = self._one(f"SELECT id FROM {self.t}packages "
                        f"WHERE ecosystem={self.ph} AND name={self.ph}",
                        (eco, name))
        return (row[0], created) if row else (None, created)

    def packages(self):
        sql = (f"SELECT id, ecosystem, name FROM {self.t}packages "
               f"ORDER BY ecosystem, name")
        if self.pg:
            # wire client: fetch() rows are tuple-subclass Rows — positional
            # unpacking (id, eco, name) works unchanged
            return self._pg_call(lambda: self.conn.fetch(sql))
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def has_scan(self, pid, version, profile, engine_version=ENGINE_VERSION):
        """Verdict-integrity fix (audit C2/G16): the cache match is keyed on the
        ENGINE_VERSION that produced the stored scan. A package last scanned
        by an older engine no longer reports OK forever: with UNIQUE
        (package_id, version, profile) and no --rescan, a stale-clean verdict
        used to shadow every future re-scan."""
        p1, p2, p3, p4 = self._phs(4)
        return self._one(
            f"SELECT id FROM {self.t}scans WHERE package_id={p1} AND version={p2} "
            f"AND profile={p3} AND engine_version={p4}",
            (pid, _db_text(version), profile, engine_version)) is not None

    def stored_verdict(self, pid, version, profile, engine_version=ENGINE_VERSION):
        """Verdict of the stored scan has_scan() matches, or None. A sweep
        that skips an already-scanned version reports this one, so a known
        SUSPICIOUS / INCOMPLETE package still fails --ci."""
        p1, p2, p3, p4 = self._phs(4)
        row = self._one(
            f"SELECT verdict FROM {self.t}scans WHERE package_id={p1} AND version={p2} "
            f"AND profile={p3} AND engine_version={p4}",
            (pid, _db_text(version), profile, engine_version))
        return row[0] if row else None

    def save_scan(self, pid, res):
        """Persist one scan result as a SINGLE atomic statement (audit G20).

        The old implementation ran DELETE then INSERT as two separate
        autocommitted statements: a crash between them (kill, disk full,
        exception) left the version with NO row, which has_scan then
        reported as never-scanned — a completed scan silently vanishing
        from the record. Now one INSERT … ON CONFLICT DO UPDATE keyed on
        the same UNIQUE (package_id, version, profile, engine_version) the
        schema already declares, inside one transaction: there is no window
        in which the version has no row.

        Text is made storable first (_db_clean): Postgres rejects NUL and
        lone surrogates in TEXT/JSONB, and an issue that quotes a hostile
        hook command or a non-UTF-8 member name must not cost the verdict.
        """
        sc = res["sevCounts"]
        conflict_key = ("ON CONFLICT (package_id, version, profile, engine_version) "
                        "DO UPDATE SET "
                        "scanned_at=excluded.scanned_at, "
                        "engine_version=excluded.engine_version, "
                        "files_scanned=excluded.files_scanned, "
                        "archive_bytes=excluded.archive_bytes, "
                        "blockers=excluded.blockers, criticals=excluded.criticals, "
                        "majors=excluded.majors, supply_chain=excluded.supply_chain, "
                        "issue_count=excluded.issue_count, verdict=excluded.verdict, "
                        "issues=excluded.issues, artifacts=excluded.artifacts")
        values = (pid, _db_text(res["version"]), res["profile"], res["scannedAt"], ENGINE_VERSION,
                  res["filesScanned"], res["archiveBytes"], sc["BLOCKER"], sc["CRITICAL"],
                  sc["MAJOR"], res["supplyChain"], len(res["issues"]), _db_text(res["verdict"]),
                  db_json(res["issues"]), db_json(res.get("artifacts") or []))
        columns = ("INSERT INTO {t}scans (package_id,version,profile,scanned_at,"
                   "engine_version,files_scanned,archive_bytes,blockers,criticals,majors,"
                   "supply_chain,issue_count,verdict,issues,artifacts) ").format(t=self.t)
        if self.pg:
            # The wire client's transaction() gives the single-atomic-statement
            # guarantee (commit on success, rollback on exception). ::jsonb
            # casts the dumps'd text into the JSONB columns (sqlite stores TEXT).
            # _pg_call retries the WHOLE block once after a dropped session
            # (the upsert is idempotent), never a statement inside it.
            def upsert():
                with self.conn.transaction():
                    self.conn.execute(
                        columns + "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,"
                                  f"$14::jsonb,$15::jsonb) {conflict_key}",
                        *values)
            self._pg_call(upsert)
            return
        cur = self.conn.cursor()
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            cur.execute(columns + f"VALUES ({','.join([self.ph] * 15)}) {conflict_key}", values)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def discovery_cursor(self, eco):
        """Where `discover --resume` continues for one registry, as stored:
        (seq, seq_time, updated_at) text, seq_time possibly None; None when
        no cursor was stored yet."""
        row = self._one(f"SELECT seq, seq_time, updated_at FROM {self.t}discovery_cursors "
                        f"WHERE ecosystem={self._phs(1)[0]}", (eco,))
        return tuple(row) if row else None

    def save_discovery_cursor(self, eco, seq, seq_time=None):
        """Store a registry's discovery cursor: seq (PyPI changelog serial,
        npm replication sequence number) and the time of that change when
        known (a datetime, stored as ISO 8601 UTC text). One idempotent
        upsert, like every Store write, so _pg_call may retry it."""
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        if seq_time is not None:
            seq_time = seq_time.astimezone(datetime.timezone.utc).isoformat(timespec="seconds")
        sql = (f"INSERT INTO {self.t}discovery_cursors (ecosystem,seq,seq_time,updated_at) "
               f"VALUES ({','.join(self._phs(4))}) ON CONFLICT (ecosystem) DO UPDATE SET "
               f"seq=excluded.seq, seq_time=excluded.seq_time, updated_at=excluded.updated_at")
        values = (eco, str(seq), seq_time, now)
        if self.pg:
            self._pg_call(lambda: self.conn.execute(sql, *values))
            return
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            self.conn.execute(sql, values)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def status(self):
        sql = (f"""
            SELECT p.ecosystem, p.name, s.version, s.profile, s.scanned_at,
                   s.verdict, s.issue_count, s.supply_chain
            FROM {self.t}packages p
            LEFT JOIN {self.t}scans s ON s.id = (
              SELECT id FROM {self.t}scans WHERE package_id = p.id
              ORDER BY scanned_at DESC, id DESC LIMIT 1)
            ORDER BY p.ecosystem, p.name""")
        if self.pg:
            return self._pg_call(lambda: self.conn.fetch(sql))
        cur = self.conn.cursor()
        cur.execute(sql)
        return cur.fetchall()

    def report(self, eco, name, version=None):
        p1, p2 = self._phs(2)
        q = (f"SELECT s.version, s.profile, s.scanned_at, s.verdict, s.issues, s.artifacts "
             f"FROM {self.t}scans s JOIN {self.t}packages p ON p.id = s.package_id "
             f"WHERE p.ecosystem={p1} AND p.name={p2}")
        args = [eco, name]
        if version:
            p3 = self._phs(3)[2]
            q += f" AND s.version={p3}"
            args.append(version)
        q += " ORDER BY s.scanned_at DESC LIMIT 1"
        row = self._one(q, args)
        if not row:
            return None
        if isinstance(row[4], list):          # JSONB backend already parsed it
            issues = row[4]
        else:
            # Card 1149e3e5: a scan result — user-supplied repo content at
            # write time — round-trips through json.loads here. Nothing stops
            # a hostile entry from being nested 60k deep: ~60KB of '[' will
            # RecursionError, killing 'report' and MCP registry_status with a
            # traceback. Guard it: parse failure (any cause) degrades to a
            # named issue instead of crashing the query; verdict + metrics
            # (rows the JSON blob doesn't feed) stay intact.
            try:
                issues = lazaret.json_loads_bounded(row[4])
            except (ValueError, TypeError) as exc:      # incl. JsonTooDeep
                what = f"stored scan issues for {eco}:{name}@{row[0]}"
                # audit H1: `what` interpolates the stored name/version — a
                # registry-supplied value that never passed NAME_RE on the
                # stored-blob path. Neutralize its control bytes before it
                # reaches a terminal.
                print(f"warning: {lazaret.sanitize_term(what)}: could not parse "
                      f"({exc.__class__.__name__})", file=sys.stderr)
                issues = [lazaret.mk_issue(
                    {"id": "SC-STORED-DEPTH", "type": "HOTSPOT",
                     "sev": "CRITICAL",
                     "name": "Hostile nesting depth in stored scan result",
                     "msg": (f"Stored scan result could not be parsed "
                             f"({exc.__class__.__name__})"
                             + (f" — nested deeper than {lazaret.MAX_MANIFEST_DEPTH} levels."
                                if isinstance(exc, lazaret.JsonTooDeep) else ".")),
                     "why": ("A stored issues blob this shape cannot come from "
                             "a normal scan: a 60k-deep document is exactly "
                             "the primitive that crashes or blinds scanners "
                             "(card 48033f94). The record's verdict and "
                             "counts stand; only the issue list is unreadable."),
                     "fix": ("Inspect this DB row directly; re-scan the package "
                             "with --rescan to rebuild a sane stored result."),
                     "ref": "CWE-506 · Supply chain"},
                    row[0] or "<stored>", 1, [])]
        artifacts = row[5] if len(row) > 5 else None
        if isinstance(artifacts, str):
            try:
                artifacts = lazaret.json_loads_bounded(artifacts)
            except ValueError:                  # incl. JsonTooDeep
                artifacts = None
        return {"version": row[0], "profile": row[1], "scannedAt": row[2],
                "verdict": row[3], "issues": issues,
                "artifacts": artifacts if isinstance(artifacts, list) else []}


# ---------------- CLI ----------------
def c(code, s):
    return f"\033[{code}m{s}\033[0m" if sys.stdout.isatty() else str(s)

VERDICT_COLOR = {"OK": "42;30", "WARN": "43;30", "INCOMPLETE": "44;97", "SUSPICIOUS": "41;97"}

def print_scan(res, top=15):
    # audit H1: the verdict badge is wrapped in its own SGR sequence by c(),
    # so the sanitized value must be the ARGUMENT of c() — sanitizing the
    # result would strip Lazaret's own color codes and leave the span open.
    v = c(VERDICT_COLOR.get(res["verdict"], "7"), f" {lazaret.sanitize_term(res['verdict'])} ")
    sc = res["sevCounts"]
    # audit H1: ecosystem/name/version come from registry metadata; `version`
    # in particular is re-read from the feed (after _check_version), so it is
    # never NAME_RE-gated. Neutralize before printing.
    print(f"\n{lazaret.sanitize_term(res['ecosystem'])}:"
          f"{lazaret.sanitize_term(res['name'])}@"
          f"{lazaret.sanitize_term(res['version'])}  {v}")
    if res.get("verdictReason"):
        print(f"  {lazaret.sanitize_term(res['verdictReason'])}")
    print(f"  {res['filesScanned']} source files · {res.get('binaryArtifacts', 0)} binary "
          f"artifacts · {res['archiveBytes']//1024} KB {res.get('artifact','')} "
          f"· profile: {res['profile']}")
    arts = res.get("artifacts") or []
    use_time = use_time_line(res.get("useTime") or use_time_total([a.get("useTime") for a in arts]))
    if use_time:
        print(f"  {use_time}")
    if len(arts) > 1:
        for a in arts:
            print(f"    {lazaret.sanitize_term(a.get('verdict'))!s:<10} "
                  f"{lazaret.sanitize_term(a.get('filename'))}")
    print(f"  blockers {sc['BLOCKER']} · criticals {sc['CRITICAL']} · majors {sc['MAJOR']} "
          f"· supply-chain indicators {res['supplyChain']}")
    for i in res["issues"][:top]:
        prefix = f"    {i['sev']:<8} [{i['rule']}] "
        # audit H1: i['file'] is an archive member name (hostile tarball) and
        # i['msg'] embeds scanned content (install-hook cmd, X-FLOW paths).
        print(f"{prefix}{lazaret.sanitize_term(i['file'])}:{i['line']} — "
              f"{lazaret.sanitize_term(i['msg'])}")
        ex = lazaret.issue_excerpt(i)
        if ex:
            print(" " * len(prefix) + c('2', '» ' + ex))   # aligned under the file path
    if len(res["issues"]) > top:
        print(f"    … {len(res['issues']) - top} more (see 'report')")


# ---------------- Discovery: recently published/updated packages ----------------
def parse_since(s):
    """'7d' / '2w' / '24h' / an ISO date -> a timezone-aware UTC cutoff datetime."""
    s = (s or "").strip().lower()
    now = _now()
    m = re.fullmatch(r"(\d+)\s*([hdw])", s)
    if m:
        hours = int(m.group(1)) * {"h": 1, "d": 24, "w": 168}[m.group(2)]
        try:
            return now - datetime.timedelta(hours=hours)
        except OverflowError:
            raise ValueError(f"bad --since {s!r}; use e.g. 7d, 2w, 24h, or 2026-06-25") from None
    try:
        d = datetime.datetime.fromisoformat(s)
        # always UTC: the window is printed as "… UTC"
        return d.astimezone(datetime.timezone.utc) if d.tzinfo \
            else d.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        # audit H2 (=F3): this module is LIBRARY code — parse_since is called
        # from the MCP server's tool dispatch (tool_discover_packages), where
        # a raised SystemExit bypasses every `except Exception` and kills the
        # whole server with no error reply (PoC: one discover_packages call
        # with since:"garbage!!" → exit 1, subsequent ping never answered).
        # ValueError propagates normally; the CLI boundary (main → cmd_discover)
        # converts it back to the exact same sys.exit() message and exit code.
        raise ValueError(f"bad --since {s!r}; use e.g. 7d, 2w, 24h, or 2026-06-25")


def _to_utc(dt):
    """G13: force a datetime to UTC-aware so comparisons against aware cutoffs
    never raise naive-vs-aware TypeErrors, and stored timestamps compare
    correctly across DST/timezones."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _now():
    """The current UTC time (a seam for tests)."""
    return datetime.datetime.now(datetime.timezone.utc)


def _fmt_span(start, end):
    """'17:28–17:47 UTC', with dates when the two ends fall on different days."""
    start = start.astimezone(datetime.timezone.utc)
    end = max(end.astimezone(datetime.timezone.utc), start)
    if start.date() == end.date():
        return f"{start:%H:%M}–{end:%H:%M} UTC"
    return f"{start:%Y-%m-%d %H:%M} – {end:%Y-%m-%d %H:%M} UTC"


def _partly(notes, eco, text):
    """Record a coverage gap: notes[eco] becomes (or is extended as)
    "partly checked: <text>". A registry noted in `notes` was not fully
    checked; the CLI warns about it and --ci fails the run."""
    if notes is None:
        return
    prev = notes.get(eco)
    notes[eco] = f"{prev}; {text}" if prev else f"partly checked: {text}"


def _parse_xml(raw):
    """G14: parse a registry feed defensively with lazaret.safexml. Any
    DOCTYPE is rejected (forbid_dtd), which also rules out every entity
    declaration, so external-entity resolution and entity-expansion bombs are
    impossible on feed-derived XML that feeds the watchlist. Nesting depth and
    size are bounded too. Returns the parsed root or raises FeedError."""
    try:
        return _safe_ET.fromstring(raw, forbid_dtd=True, max_bytes=FEED_MAX_BYTES)
    except _safexml.SafeXMLError as exc:
        raise FeedError(f"feed rejected by the XML hardening layer: {exc}") from None
    except (_safe_ET.ParseError, ValueError, RecursionError) as exc:
        raise FeedError(f"feed is not well-formed XML ({type(exc).__name__})") from None


def _feed_token_ok(value):
    """A token lifted from an RSS title (name or version) must survive the same
    name validation as CLI specs before it can enter the watchlist and drive a
    download (G14 + F10)."""
    return value is not None and NAME_RE.fullmatch(value) is not None


def discover_pypi(cutoff, limit, notes=None):
    """Recently created + updated PyPI projects via the RSS feeds, newest
    first. The feeds hold only the latest 100 releases (updates.xml, about 20
    minutes of PyPI) and the latest 40 new projects (packages.xml, about an
    hour), so for any longer window notes["pypi"] says which part was covered
    ("partly checked: covered 17:28–17:47 UTC only; …"). A feed that can't be
    read is a warning and noted too, and so are releases left out by `limit`."""
    import email.utils
    now = _now()
    found, failed, reach = {}, [], {}
    for feed in ("https://pypi.org/rss/packages.xml", "https://pypi.org/rss/updates.xml"):
        try:
            # metadata budget (5 MB) and timeout, not the 200 MB artifact budget
            raw = _fetch(feed, max_bytes=MAX_FEED_BYTES, timeout=METADATA_TIMEOUT)
        except Exception as exc:                                   # noqa: BLE001
            # audit H1: FetchError/_fetch messages can embed text derived from
            # the network response; `feed` is a constant URL.
            print(f"warning: PyPI feed {feed} failed: "
                  f"{lazaret.sanitize_term(exc)}", file=sys.stderr)
            failed.append(feed.rsplit("/", 1)[-1])
            continue
        try:
            root = _parse_xml(raw)
        except Exception as exc:                                   # noqa: BLE001
            # audit H1: an XML ParseError echoes bytes from the hostile feed.
            print(f"warning: PyPI feed {feed} rejected "
                  f"({lazaret.sanitize_term(exc)}).", file=sys.stderr)
            failed.append(feed.rsplit("/", 1)[-1])
            continue
        items, oldest = 0, None        # how far back this feed reaches
        for item in root.findall(".//item"):
            title = (item.findtext("title") or "").strip()
            pub = item.findtext("pubDate")
            if not title or not pub:
                continue
            try:
                when = email.utils.parsedate_to_datetime(pub)
            except (TypeError, ValueError, IndexError, OverflowError):
                continue
            when = _to_utc(when)
            items += 1
            if oldest is None or when < oldest:
                oldest = when
            if when < cutoff:
                continue
            parts = title.split()
            name = parts[0]
            # updates.xml titles are "<name> <version>"; packages.xml (new
            # projects) titles are "<name> added to PyPI", whose second word
            # used to become the version: `discover --scan` then asked for
            # pypi:<name>@added and failed for every new project
            version = parts[1] if feed.endswith("/updates.xml") and len(parts) == 2 else None
            # G14/F10: feed-derived names drive downloads — validate them
            # against the same rules as CLI specs.
            if not valid_name("pypi", name):
                continue
            if version is not None and not _feed_token_ok(version):
                version = None
            prev = found.get(name)
            if prev is None or when > prev[3] or (when == prev[3] and version and not prev[2]):
                found[name] = ("pypi", name, version, when)
        reach[feed.rsplit("/", 1)[-1]] = (items, oldest)
    out = sorted(found.values(), key=lambda x: x[3], reverse=True)
    if notes is not None:
        if len(failed) == 2:
            notes["pypi"] = "not checked: both RSS feeds failed"
        else:
            for name in failed:
                _partly(notes, "pypi", f"the {name} feed failed")
            _note_pypi_reach(notes, cutoff, now, reach)
            if limit and len(out) > limit:
                _partly(notes, "pypi", f"{len(out) - limit} more not listed (limit {limit})")
    return out[:limit] if limit else out


def _note_pypi_reach(notes, cutoff, now, reach):
    """A feed covers the window only if it reaches back past the cutoff:
    PyPI's feeds are the latest N items, and anything older fell off.
    updates.xml lists every release (a new project's first one too), so its
    reach is PyPI's; packages.xml may reach further back for new projects."""
    def covers(feed):
        return feed[1] is not None and feed[1] < cutoff

    def span(feed):
        return _fmt_span(feed[1], now) if feed[1] is not None else None

    updates, projects = reach.get("updates.xml"), reach.get("packages.xml")
    if updates is not None and not covers(updates):
        text = (f"covered {span(updates)} only; its RSS feeds hold the latest "
                f"{updates[0]} updates" if updates[0] else "the updates.xml feed was empty")
        if projects is not None and covers(projects):
            text += " (new projects: the whole window)"
        elif projects is not None and projects[1] is not None \
                and (updates[1] is None or projects[1] < updates[1]):
            text += f" (new projects: {span(projects)})"
        _partly(notes, "pypi", text)
    elif updates is None and projects is not None and not covers(projects):
        _partly(notes, "pypi", f"new projects covered {span(projects)} only; packages.xml "
                               f"holds the latest {projects[0]}" if projects[0]
                else "the packages.xml feed was empty")


# PyPI's XML-RPC API: its mirroring methods (changelog_last_serial,
# changelog_since_serial) are supported, and rate-limited: discovery makes
# one call per run. changelog_since_serial answers with at most 50,000
# journal rows (warehouse's limit), about 15 MB of XML: more than the 5 MB
# feed cap, so these answers have their own (safexml's XML-RPC default).
PYPI_XMLRPC_URL = "https://pypi.org/pypi"
PYPI_XMLRPC_MAX_BYTES = 32 * 1024 * 1024
PYPI_CHANGELOG_MAX = 50_000
_SERIAL_MAX = 2 ** 63 - 1


def _uint(value):
    """A non-negative int from a decoded answer (never a bool)."""
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _SERIAL_MAX


def _pypi_xmlrpc(method, *params):
    """Call one method of PyPI's XML-RPC API -> its return value. The request
    goes through _fetch (https to pypi.org only, byte and time limits) and
    the answer is parsed by lazaret.safexml's XML-RPC parser (no DTD or
    entities, bounded depth and size). Raises FetchError when PyPI can't be
    reached or the answer is too large, FeedError for a fault or an answer
    that isn't a well-formed XML-RPC response."""
    import xmlrpc.client
    from lazaret.safexml import xmlrpc as safe_xmlrpc
    body = xmlrpc.client.dumps(params, method, encoding="utf-8").encode("utf-8")
    raw = _fetch(PYPI_XMLRPC_URL, max_bytes=PYPI_XMLRPC_MAX_BYTES, timeout=METADATA_TIMEOUT,
                 data=body, content_type="text/xml")
    try:
        result, called = safe_xmlrpc.loads(raw, max_bytes=PYPI_XMLRPC_MAX_BYTES)
    except xmlrpc.client.Fault as exc:
        raise FeedError(f"PyPI's XML-RPC {method} failed: fault {exc.faultCode!s:.20}: "
                        f"{exc.faultString!s:.200}") from None
    except Exception as exc:                                       # noqa: BLE001
        # hostile or broken XML: refused by safexml, malformed, or values the
        # unmarshaller can't decode. The text may echo the answer: not kept.
        raise FeedError(f"PyPI's XML-RPC {method} answer was rejected "
                        f"({type(exc).__name__})") from None
    if called is not None or not isinstance(result, tuple) or len(result) != 1:
        raise FeedError(f"PyPI's XML-RPC {method} answer is not a method response")
    return result[0]


def _pypi_last_serial():
    """PyPI's newest changelog serial (changelog_last_serial)."""
    serial = _pypi_xmlrpc("changelog_last_serial")
    if not _uint(serial):
        raise FeedError("PyPI's changelog_last_serial answer is not a serial number")
    return serial


def _pypi_changelog(serial):
    """PyPI's changelog after `serial` (changelog_since_serial: rows of
    (name, version, timestamp, action, serial), oldest first). Returns a dict:
      events: [(serial, name, version or None, datetime)] of the rows that
              are releases ("new release") or new projects ("create"), in
              serial order, each (project, version) once; other actions
              (file uploads, removals, roles) are ignored. A version that
              isn't a safe token becomes None (scanned at the latest
              version), as in the RSS feeds, and a new project whose first
              release is in the answer is listed by that release.
      rows:   rows in the answer (PyPI sends at most PYPI_CHANGELOG_MAX)
      last:   (serial, datetime) of the newest row, or None
      unread: rows that could not be read (wrong shape or types)
      stale:  rows before `serial` (PyPI never sends them; they are ignored)
      names:  release rows whose project name is not a valid PyPI name
    A row at `serial` itself is ignored too. Raises like _pypi_xmlrpc, and
    FeedError when the answer is not a list."""
    answer = _pypi_xmlrpc("changelog_since_serial", serial)
    if not isinstance(answer, list):
        raise FeedError("PyPI's changelog answer has an unexpected shape")
    events, last, unread, stale, names = [], None, 0, 0, 0
    for row in answer:
        if not isinstance(row, (list, tuple)) or len(row) != 5:
            unread += 1
            continue
        name, version, stamp, action, row_serial = row
        if not (_uint(row_serial) and _uint(stamp) and isinstance(action, str)):
            unread += 1
            continue
        try:
            when = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
        except (OverflowError, OSError, ValueError):
            unread += 1
            continue
        if row_serial <= serial:
            if row_serial < serial:
                stale += 1
            continue
        if last is None or row_serial > last[0]:
            last = (row_serial, when)
        if action not in ("new release", "create"):
            continue
        if not isinstance(name, str) or not valid_name("pypi", name):
            names += 1                          # G14: names drive downloads
            continue
        if action == "create" or not isinstance(version, str) or not _feed_token_ok(version):
            version = None
        events.append((row_serial, name, version, when))
    events.sort(key=lambda e: e[0])
    released = {_pep503(name) for _s, name, version, _w in events if version is not None}
    distinct, seen = [], set()
    for event in events:
        key = (_pep503(event[1]), event[2])
        if key not in seen and not (event[2] is None and key[0] in released):
            seen.add(key)
            distinct.append(event)
    return {"events": distinct, "rows": len(answer), "last": last, "unread": unread,
            "stale": stale, "names": names}


def _pep503(name):
    """PyPI's normalized project name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


# npm's replication API (changed 2025: new endpoints from 2025-03-18, the old
# ones retired 2025-05-29) accepts only doc_ids, descending, last-event-id,
# limit (max 10000) and since on _changes. include_docs is gone: a row is a
# sequence number, a package name and a revision, with no time and no
# metadata, so each package's publish time and latest version come from the
# registry itself (the abbreviated "corgi" document: name, dist-tags,
# versions, modified).
NPM_CHANGES_URL = "https://replicate.npmjs.com/registry/_changes"
NPM_CHANGES_MAX = 10000
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"
NPM_LOOKUP_WORKERS = 8
# Feed rows are newest first. After this many packages in a row modified
# before the window, the rest of the feed is older too: stop looking up.
NPM_OLDER_STOP = 5
# `discover --resume` reads the feed forward from the stored sequence
# number, NPM_CHANGES_MAX rows a page, at most this many pages per run; the
# rest waits for the next run.
NPM_RESUME_PAGES = 20


def _npm_feed_names(want):
    """-> (package names, newest first, each once; count of names npm would
    reject; number of feed rows read; the highest sequence number read, or
    None). Raises FetchError / FeedError when the feed can't be read."""
    data = http_json(f"{NPM_CHANGES_URL}?descending=true&limit={want}")
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        raise FeedError("npm changes feed has an unexpected shape")
    names, seen, rejected, head = [], set(), 0, None
    for row in results:
        if isinstance(row, dict) and _uint(row.get("seq")) and (head is None or row["seq"] > head):
            head = row["seq"]
        if not isinstance(row, dict) or row.get("deleted") is True:
            continue                                  # unpublished: nothing to scan
        name = row.get("id")
        if not isinstance(name, str) or not name or name.startswith("_") or name in seen:
            continue                                  # design documents, repeats
        seen.add(name)
        if not valid_name("npm", name):
            rejected += 1                             # G14: feed names drive downloads
            continue
        names.append(name)
    return names, rejected, len(results), head


def _npm_changes_since(seq, pages=None, want=0):
    """npm's replication feed after sequence number `seq`, read forward
    (since=, limit=NPM_CHANGES_MAX: the only parameters it takes besides
    doc_ids, descending and last-event-id) a page at a time, until a page
    comes back short (caught up), `pages` pages (NPM_RESUME_PAGES) were
    read, or `want` (if set) packages are in hand. Returns a dict:
      changes:   [(seq, name)] of the packages that changed, oldest first,
                 each name once at its newest seq; unpublished (deleted)
                 and design documents are passed over
      last:      the highest seq read (where to continue), or None
      caught_up: a page came back short: nothing more to read yet
      pages, rows: pages and rows read
      rejected:  names npm would reject (G14: names drive downloads)
      error:     the feed problem that ended the walk after the first
                 page (what was read before it stands), or None
    A page with rows but none after the position is a problem, not "caught
    up": only an empty page, or one with just the row at the position, is.
    Raises FetchError / FeedError when the first page can't be read or has
    that problem."""
    pages = NPM_RESUME_PAGES if pages is None else pages
    newest, rejected, rows, done = {}, 0, 0, 0
    since, last, caught_up, error = seq, None, False, None
    while done < pages:
        try:
            data = http_json(f"{NPM_CHANGES_URL}?since={since}&limit={NPM_CHANGES_MAX}")
            results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(results, list):
                raise FeedError("npm changes feed has an unexpected shape")
        except (FetchError, FeedError) as exc:
            if not done:
                raise
            error = exc
            break
        done += 1
        rows += len(results)
        page_last, echoed = since, False
        for row in results:
            row_seq = row.get("seq") if isinstance(row, dict) else None
            if not _uint(row_seq) or row_seq <= since:
                echoed = echoed or (_uint(row_seq) and row_seq == since)
                continue
            page_last = max(page_last, row_seq)
            name = row.get("id")
            if row.get("deleted") is True or not isinstance(name, str) or not name \
                    or name.startswith("_"):
                continue                               # unpublished; design documents
            if not valid_name("npm", name):
                rejected += 1
                continue
            newest[name] = max(newest.get(name, 0), row_seq)
        if page_last == since and (len(results) >= NPM_CHANGES_MAX or (results and not echoed)):
            # rows, and none after `since`: not "nothing new" (and a full page
            # would come back the same). An empty page, or one repeating only
            # the row at `since`, is caught up.
            error = FeedError("npm changes feed returned a page with nothing after "
                              f"sequence number {since}")
            if done == 1:
                raise error
        elif len(results) < NPM_CHANGES_MAX:
            caught_up = True
        if page_last > since:
            since = last = page_last
        if caught_up or error or (want and len(newest) >= want):
            break
    changes = sorted((row_seq, name) for name, row_seq in newest.items())
    return {"changes": changes, "last": last, "caught_up": caught_up, "pages": done,
            "rows": rows, "rejected": rejected, "error": error}


def _npm_lookups(names):
    """Yield (name, (modified, latest version) or None if the lookup failed)
    for each name in order, looked up NPM_LOOKUP_WORKERS at a time, a batch
    at a time, so a caller that stops early leaves the rest unfetched.
    Close the generator when stopping early."""
    import concurrent.futures
    batch = NPM_LOOKUP_WORKERS * 2
    with concurrent.futures.ThreadPoolExecutor(NPM_LOOKUP_WORKERS) as pool:
        for i in range(0, len(names), batch):
            chunk = names[i:i + batch]
            futures = [pool.submit(_npm_recent, n) for n in chunk]
            for name, fut in zip(chunk, futures):
                try:
                    result = fut.result()
                except Exception:                                  # noqa: BLE001
                    result = None
                yield name, result


def _npm_recent(name):
    """-> (datetime modified, latest version or None) for one package, from its
    abbreviated registry document. Raises on any failure."""
    doc = http_json("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"),
                    accept=NPM_ABBREVIATED)
    if not isinstance(doc, dict) or not isinstance(doc.get("modified"), str):
        raise FeedError("no modified time")
    # G13: always UTC-aware, so the cutoff comparison never mixes naive/aware
    when = _to_utc(datetime.datetime.fromisoformat(doc["modified"].replace("Z", "+00:00")))
    tags = doc.get("dist-tags") if isinstance(doc.get("dist-tags"), dict) else {}
    version = tags.get("latest") if isinstance(tags.get("latest"), str) else None
    if version is not None and not _feed_token_ok(version):
        version = None
    return when, version


def _npm_feed_problem(exc):
    if getattr(exc, "status", None):
        return (f"npm rejected the changes-feed request (HTTP {exc.status}"
                + ("; its replication API may have changed" if exc.status in (400, 404, 410) else "")
                + ")")
    if isinstance(exc, FeedError):
        return str(exc)
    return f"could not reach replicate.npmjs.com ({exc})"


def discover_npm(cutoff, limit, notes=None, head=None):
    """Recently published or updated npm packages: the newest names from npm's
    replication _changes feed, each checked against the window with one small
    registry lookup (8 at a time), newest first, until `limit` are found or the
    feed falls behind the window. `head`, a dict, gets head["seq"]: the feed's
    newest sequence number, where a following `discover --resume` continues.

    Best-effort per package, fail-visible per ecosystem: when the feed itself
    can't be read, npm is skipped with a warning and notes["npm"] says so (the
    CLI's --ci then fails the run: a hunting job must not pass while checking
    nothing). The walk reads at most 3 x `limit` feed rows (300 with no limit):
    when it stops before reaching the start of the window, because of `limit`
    or because those rows ran out, notes["npm"] says which part was covered.
    A package whose registry lookup fails is still listed, because
    the feed says it just changed: its time is the nearest older time the walk
    saw (or the window start), and it is counted in a warning."""
    want = min((limit or 100) * 3, NPM_CHANGES_MAX)
    now = _now()
    try:
        names, rejected, rows_read, newest_seq = _npm_feed_names(want)
        if head is not None and newest_seq is not None:
            head["seq"] = newest_seq
    except (FetchError, FeedError) as exc:
        # audit H1: the exception text can echo bytes of the network response.
        problem = lazaret.sanitize_term(_npm_feed_problem(exc))
        print(f"warning: {problem}; npm was not checked.", file=sys.stderr)
        if notes is not None:
            notes["npm"] = f"not checked: {problem}"
        return []
    if rejected:
        print(f"warning: skipped {rejected} npm feed name(s) that are not valid package names.",
              file=sys.stderr)
    rows, older_run, unknown = [], 0, 0          # rows: [name, when or None, version]
    passed_window = False                        # the walk went past the start of the window
    processed, last_known = 0, None              # names looked up; the last time seen
    lookups = _npm_lookups(names)
    try:
        for name, result in lookups:
            processed += 1
            if result is None:
                rows.append([name, None, None])
                unknown += 1
                continue
            when, version = result
            last_known = when
            if when < cutoff:
                older_run += 1
                if older_run >= NPM_OLDER_STOP:
                    passed_window = True
                    break
                continue
            older_run = 0
            rows.append([name, when, version])
            if limit and len(rows) >= limit:
                break
    finally:
        lookups.close()
    # The whole window was seen when the walk went past its start, or looked
    # up every name of a feed shorter than asked for (nothing older exists).
    # Otherwise it reaches back only to the last time it saw.
    exhausted = processed == len(names)
    if exhausted and last_known is not None and last_known < cutoff:
        passed_window = True
    if not passed_window and not (exhausted and rows_read < want):
        if last_known is None:
            _partly(notes, "npm", f"none of the {len(names)} packages in the newest {rows_read} "
                                  f"changes of its replication feed could be looked up" if names
                    else f"the newest {rows_read} changes of its replication feed named no "
                         f"package to look up")
        elif not exhausted:
            _partly(notes, "npm", f"covered {_fmt_span(last_known, now)} only: stopped at "
                                  f"the limit of {limit} packages")
        else:
            _partly(notes, "npm", f"covered {_fmt_span(last_known, now)} only; read the newest "
                                  f"{rows_read} changes of its replication feed")
    # a failed lookup sits between known times in feed order: give it the
    # nearest older known time (a lower bound), or the window start
    floor = cutoff
    for row in reversed(rows):
        if row[1] is None:
            row[1] = floor
        else:
            floor = row[1]
    if unknown:
        print(f"warning: could not read the registry entry of {unknown} npm package(s); "
              f"they are listed with a time estimated from the feed order.", file=sys.stderr)
    res = [("npm", name, version, when) for name, when, version in rows]
    res.sort(key=lambda x: x[3], reverse=True)
    return res[:limit] if limit else res


def _fill_times(rows, start, now):
    """rows [name, when or None, version] in feed order, oldest first: a
    failed lookup gets the nearest earlier known time (a lower bound), else
    `start`, else the first known time, else `now`."""
    known = start
    for row in rows:
        if row[1] is None:
            row[1] = known
        else:
            known = row[1]
    first = next((row[1] for row in rows if row[1] is not None), now)
    for row in rows:
        if row[1] is None:
            row[1] = first


def discover_pypi_since(cursor, limit, notes=None):
    """Every PyPI release and new project after a stored changelog position,
    with one changelog_since_serial call. `cursor` is (serial, time of that
    change or None). -> (found, oldest first; the new cursor, or None to
    keep the stored one; what was covered, one line).

    PyPI answers with at most PYPI_CHANGELOG_MAX rows. A full answer, or
    `limit` cutting the list, makes notes["pypi"] "partly checked", and the
    new cursor is where this run stopped, so the next run continues there. A
    changelog that can't be read is "not checked" and the cursor stays."""
    serial, since_time = cursor
    try:
        log = _pypi_changelog(serial)
        if log["last"] is None and (log["unread"] or log["stale"]):
            # rows, but none readable after the position: not "nothing new"
            raise FeedError(f"PyPI's changelog answer had no readable row after serial {serial}")
    except (FetchError, FeedError) as exc:
        # audit H1: a fault's text comes from the network
        problem = lazaret.sanitize_term(f"could not read PyPI's changelog ({exc})")
        print(f"warning: {problem}; PyPI was not checked.", file=sys.stderr)
        if notes is not None:
            notes["pypi"] = f"not checked: {problem}"
        return [], None, None
    if log["names"]:
        print(f"warning: skipped {log['names']} PyPI changelog row(s) whose project name is "
              f"not valid.", file=sys.stderr)
    if log["unread"]:
        _partly(notes, "pypi", f"{log['unread']} changelog row(s) could not be read")
    events = log["events"]
    if limit and len(events) > limit:
        rest, events = len(events) - limit, events[:limit]
        new = (events[-1][0], events[-1][3])
        _partly(notes, "pypi", f"stopped at --limit {limit}; {rest} more release(s) are left "
                               f"for the next --resume run")
    elif log["last"] is not None:
        new = log["last"]
        if log["rows"] >= PYPI_CHANGELOG_MAX:
            _partly(notes, "pypi", f"covered changes up to {new[1]:%Y-%m-%d %H:%M} UTC only: PyPI's "
                                   f"changelog answers with at most {PYPI_CHANGELOG_MAX:,} changes "
                                   f"per call; the next --resume run continues from serial {new[0]}")
    else:
        new = (serial, since_time)                         # nothing after it yet
    if new[0] == serial:
        covered = f"no changes after changelog serial {serial}"
    else:
        span = (_fmt_span(since_time, new[1]) if since_time is not None
                else f"up to {new[1]:%Y-%m-%d %H:%M} UTC")
        covered = f"changelog serial {serial} → {new[0]}, {span}"
    return [("pypi", name, version, when) for _s, name, version, when in events], new, covered


def discover_npm_since(cursor, limit, notes=None):
    """Every npm package changed after a stored replication-feed position:
    the feed read forward (_npm_changes_since, at most NPM_RESUME_PAGES
    pages), then each package's latest version and time from its registry
    entry, as discover_npm does (a failed lookup is still listed). `cursor`
    is (seq, time or None). -> (found, oldest first; the new cursor, or None
    to keep the stored one; what was covered, one line).

    A spent page budget, a feed that failed after its first page, or
    `limit` cutting the list makes notes["npm"] "partly checked", and the
    new cursor is where this run stopped, so the next run continues there.
    A feed that can't be read is "not checked" and the cursor stays."""
    seq, since_time = cursor
    now = _now()
    try:
        # with a limit, no more pages than it takes: the next run reads on
        # from where this one stops
        walk = _npm_changes_since(seq, want=limit)
    except (FetchError, FeedError) as exc:
        # audit H1: the exception text can echo bytes of the network response.
        problem = lazaret.sanitize_term(_npm_feed_problem(exc))
        print(f"warning: {problem}; npm was not checked.", file=sys.stderr)
        if notes is not None:
            notes["npm"] = f"not checked: {problem}"
        return [], None, None
    if walk["rejected"]:
        print(f"warning: skipped {walk['rejected']} npm feed name(s) that are not valid package "
              f"names.", file=sys.stderr)
    changes = walk["changes"]
    last = walk["last"] if walk["last"] is not None else seq
    if limit and (len(changes) > limit or (len(changes) == limit and not walk["caught_up"])):
        rest, changes = len(changes) - limit, changes[:limit]
        new = (changes[-1][0], None)
        more = (f"{rest} more changed package(s) are" if walk["caught_up"]
                else "more changes are")                # it stopped reading at the limit
        _partly(notes, "npm", f"stopped at --limit {limit}; {more} left for the next --resume run")
    else:
        new = (last, now if walk["caught_up"] else None)
        if walk["error"] is not None:
            problem = lazaret.sanitize_term(_npm_feed_problem(walk["error"]))
            _partly(notes, "npm", f"its replication feed failed after {walk['pages']} page(s) "
                                  f"({problem}); the next --resume run continues from change {last}")
        elif not walk["caught_up"]:
            _partly(notes, "npm", f"read {walk['pages']} pages ({walk['rows']:,} changes) of its "
                                  f"replication feed, the most one run reads; the next --resume "
                                  f"run continues from change {last}")
    rows = []                                    # [name, when or None, version], oldest first
    lookups = _npm_lookups([name for _s, name in changes])
    try:
        for name, result in lookups:
            rows.append([name, *(result if result is not None else (None, None))])
    finally:
        lookups.close()
    unknown = sum(1 for row in rows if row[1] is None)
    if unknown:
        print(f"warning: could not read the registry entry of {unknown} npm package(s); "
              f"they are listed with a time estimated from the feed order.", file=sys.stderr)
    _fill_times(rows, since_time, now)
    covered = (f"no changes after replication-feed position {seq}" if last == seq else
               f"replication feed {seq} → {new[0]}, {walk['rows']:,} changes in "
               f"{walk['pages']} page(s)")
    return [("npm", name, version, when) for name, when, version in rows], new, covered


def _stored_cursor(eco, stored):
    """A Store.discovery_cursor() row -> (seq, datetime or None), or None
    when there is none or it isn't a sequence number (a warning: the run
    starts over from the time window)."""
    if stored is None:
        return None
    seq, seq_time = stored[0], stored[1]
    if not isinstance(seq, str) or not re.fullmatch(r"[0-9]{1,19}", seq) or not _uint(int(seq)):
        print(f"warning: the stored {eco} discovery cursor is not a sequence number; this "
              f"run starts over from the --since window.", file=sys.stderr)
        return None
    when = None
    if isinstance(seq_time, str):
        try:
            when = _to_utc(datetime.datetime.fromisoformat(seq_time))
        except ValueError:
            pass
    return int(seq), when


def _discover_first_run(eco, cutoff, limit, notes):
    """The first `discover --resume` of a registry: the --since window, as
    without --resume, and the feed's current position for the next run.
    -> (found, (seq, time) or None when the position could not be read)."""
    now = _now()
    if eco == "pypi":
        try:
            head = _pypi_last_serial()        # before the feeds: nothing in between is missed
        except (FetchError, FeedError) as exc:
            print(f"warning: could not read PyPI's changelog position "
                  f"({lazaret.sanitize_term(exc)}); the next --resume run checks a --since "
                  f"window again.", file=sys.stderr)
            head = None
        found = discover_pypi(cutoff, limit, notes)
        return found, ((head, now) if head is not None else None)
    position = {}
    found = discover_npm(cutoff, limit, notes, head=position)
    return found, ((position["seq"], now) if "seq" in position else None)


def _discover_resumed(store, ecos, cutoff, limit, notes):
    """discover --resume: each registry continues from its stored cursor
    or, the first time, checks the --since window and records where its feed
    is now. -> (discovered, {eco: new cursor}, {eco: what was covered})."""
    discovered, cursors, covered = [], {}, {}
    for eco in ("pypi", "npm"):
        if eco not in ecos:
            continue
        try:
            cursor = _stored_cursor(eco, store.discovery_cursor(eco))
        except Exception as exc:                                    # noqa: BLE001
            problem = lazaret.sanitize_term(f"could not read its discovery cursor "
                                            f"({type(exc).__name__}: {exc})")
            print(f"warning: {eco}: {problem}; {eco} was not checked.", file=sys.stderr)
            notes[eco] = f"not checked: {problem}"
            covered[eco] = "not checked (see the warning at the end)"
            continue
        if cursor is None:
            found, new = _discover_first_run(eco, cutoff, limit, notes)
            text = f"first --resume run: the window since {cutoff:%Y-%m-%d %H:%M} UTC"
            if new is not None:
                text += (f"; the next run continues from "
                         f"{'changelog serial' if eco == 'pypi' else 'change'} {new[0]}")
        else:
            since = discover_pypi_since if eco == "pypi" else discover_npm_since
            found, new, text = since(cursor, limit, notes)
        discovered += found
        if new is not None:
            cursors[eco] = new
        covered[eco] = ("not checked (see the warning at the end)"
                        if notes.get(eco, "").startswith("not checked") else text)
    return discovered, cursors, covered


def _discover_window(ecos, cutoff, limit, notes):
    """discover without --resume: what the feeds hold from the --since
    window, newest first, --limit across both registries."""
    discovered = []
    if "pypi" in ecos:
        # all the feeds hold: --limit applies below, across both registries
        discovered += discover_pypi(cutoff, 0, notes)
    if "npm" in ecos:
        discovered += discover_npm(cutoff, limit, notes)
    discovered.sort(key=lambda x: x[3], reverse=True)
    if limit and len(discovered) > limit:
        # what --limit leaves out was not checked either: it is neither listed
        # nor scanned, so it is a gap like any other
        unlisted = {}
        for eco, _name, _ver, _when in discovered[limit:]:
            unlisted[eco] = unlisted.get(eco, 0) + 1
        for eco, count in unlisted.items():
            _partly(notes, eco, f"{count} more not listed (--limit {limit})")
        discovered = discovered[:limit]
    return discovered


def _save_cursors(store, cursors):
    """Store the new discovery cursors; False if one could not be (warned:
    the next --resume run repeats that part, nothing is skipped)."""
    saved = True
    for eco, (seq, when) in cursors.items():
        try:
            store.save_discovery_cursor(eco, seq, when)
        except Exception as exc:                                    # noqa: BLE001
            print(f"warning: could not store the {eco} discovery cursor ({type(exc).__name__}: "
                  f"{lazaret.sanitize_term(exc)}); the next --resume run repeats this part.",
                  file=sys.stderr)
            saved = False
    return saved


def cmd_discover(store, args):
    """discover: list (and with --add / --scan, track and scan) the packages
    published or changed in the --since window, or with --resume since the
    last --resume run. Returns True when --ci should fail the run: a registry
    not (fully) checked, a SUSPICIOUS / INCOMPLETE scan, or a cursor that
    could not be stored."""
    cutoff = parse_since(args.since)
    ecos = args.ecosystem or ["pypi", "npm"]
    resume = bool(getattr(args, "resume", False))
    # --resume lists everything since the last run unless --limit says otherwise
    limit = args.limit if args.limit is not None else (0 if resume else 50)
    notes = {}
    if resume:
        discovered, cursors, covered = _discover_resumed(store, ecos, cutoff, limit, notes)
        discovered.sort(key=lambda x: x[3], reverse=True)
        print("Resuming discovery:")
        for eco, text in covered.items():
            print(f"  {eco}: {text}")
    else:
        discovered, cursors = _discover_window(ecos, cutoff, limit, notes), {}
    bad = False
    whole = [e for e in ecos if e not in notes]           # every change in the range checked
    if not discovered:
        partly = [e for e in ecos if notes.get(e, "").startswith("partly checked")]
        if whole:
            print(f"No new packages in {', '.join(whole)}." if resume else
                  f"No packages published/updated since {cutoff:%Y-%m-%d %H:%M} UTC in "
                  f"{', '.join(whole)}.")
        if partly:
            print(f"Nothing found in the part {'' if resume else 'of the window '}that was "
                  f"checked in {', '.join(partly)} (see the warning below).")
        if not whole and not partly:
            print("Nothing was checked.")
    else:
        heading = f"Discovered {len(discovered)} package(s)"
        if not resume:
            heading += f" since {cutoff:%Y-%m-%d %H:%M} UTC"
        if len(whole) < len(ecos):
            heading += (", but not everything was checked" if resume else
                        ", but not all of that window was checked")
            heading += " (see the warnings at the end)"
        print(f"\n{heading}:")
        for eco, name, ver, when in discovered:
            # audit H1: discovery-feed name/version are raw feed text. Sanitize
            # before the width-free print (the strftime timestamp is engine-controlled).
            print(f"  {when.astimezone(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M')}  "
                  f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}"
                  f"{('@' + lazaret.sanitize_term(ver)) if ver else ''}")
        errors = getattr(args, "_errors", None)
        if args.add or args.scan:
            for eco, name, _ver, _when in discovered:
                if not valid_name(eco, name):
                    continue
                try:
                    store.add_package(eco, name)
                except Exception as exc:                            # noqa: BLE001
                    # one package the DB refuses must not end the run (cmd_scan
                    # below reports it again when --scan is set)
                    spec = f"{eco}:{name}"
                    print(f"error adding {lazaret.sanitize_term(spec)} to the watchlist: "
                          f"{type(exc).__name__}: {lazaret.sanitize_term(exc)}", file=sys.stderr)
                    if errors is not None and not args.scan:
                        errors.append(spec)
        if args.scan:
            specs = [f"{eco}:{name}" + (f"@{ver}" if ver else "")
                     for eco, name, ver, _ in discovered]
            print(f"\nScanning {len(specs)} discovered package(s)…")
            bad = cmd_scan(store, specs, args.full, args.rescan, errors=errors)
    # only now, after listing, tracking and scanning: a run that dies on the
    # way leaves the old cursor, and the next run sees those packages again
    saved = _save_cursors(store, cursors)
    gaps = _report_discovery_gaps(ecos, notes)
    if gaps and not resume and any(n.startswith("partly checked") for n in notes.values()):
        print("hint: `discover --resume` continues where the previous --resume run stopped, "
              "so a scheduled run sees every release (README: Discovering new packages).",
              file=sys.stderr)
    return gaps or bad or not saved


def _report_discovery_gaps(ecos, notes):
    """At the end of discover: one stderr line per registry that was not
    (fully) checked; True if any. The CLI's --ci fails such a run, like an
    INCOMPLETE scan: a scheduled hunt must not pass while checking nothing."""
    for eco in ecos:
        if eco in notes:
            print(f"warning: discovery incomplete: {eco} {notes[eco]}.", file=sys.stderr)
    return any(eco in notes for eco in ecos)


BAD_VERDICTS = ("SUSPICIOUS", "INCOMPLETE")


def cmd_scan(store, specs, full, rescan, errors=None):
    """Scan each spec; returns True when any result is SUSPICIOUS/INCOMPLETE
    — including the STORED verdict of a version skipped as already scanned —
    or any spec failed. One package's failure (bad name in the watchlist,
    network, digest mismatch, a store error) never stops the sweep.
    `errors`, when given, collects every spec that failed to scan or to be
    stored (the CLI exits 1 for them at the end of the sweep)."""
    exit_bad = False
    profile = "full" if full else "supply-chain"
    for spec in specs:
        try:
            eco, name, ver = parse_spec(spec)
            pid, _ = store.add_package(eco, name)
            resolved = None
            if not rescan:
                if ver is None:
                    # scan-all specs carry no version: ask the registry which
                    # version is current BEFORE downloading, so an already
                    # scanned version is skipped instead of re-scanned.
                    resolved = resolve(eco, name, None)
                    ver = resolved[0]
                if ver and store.has_scan(pid, ver, profile):
                    # A skipped version keeps its stored verdict: a sweep
                    # without --rescan must not turn a known SUSPICIOUS or
                    # INCOMPLETE package into a passing --ci run.
                    stored = store.stored_verdict(pid, ver, profile)
                    # audit H1: name/version echo registry- or feed-derived text.
                    print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                          f"{lazaret.sanitize_term(ver)} already scanned ({profile}"
                          f"{', ' + lazaret.sanitize_term(stored) if stored else ''}); "
                          f"use --rescan to redo")
                    exit_bad |= stored in BAD_VERDICTS
                    continue
            res = scan_package(eco, name, ver, full, resolved=resolved)
        except Exception as exc:
            # audit H1: {spec} is echoed verbatim and {exc} embeds registry
            # response text (FetchError URL/reason, JSON parse position) —
            # both are network-controlled on the failure path.
            print(f"error scanning {lazaret.sanitize_term(spec)}: "
                  f"{lazaret.sanitize_term(exc)}", file=sys.stderr)
            exit_bad = True
            if errors is not None:
                errors.append(spec)
            continue
        try:
            if not rescan and store.has_scan(pid, res["version"], profile):
                # audit H1: res['version'] is re-read from registry metadata.
                print(f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                      f"{lazaret.sanitize_term(res['version'])} already scanned "
                      f"({profile}); skipping store")
            else:
                store.save_scan(pid, res)
        except Exception as exc:
            # The verdict is printed below all the same; the failure to record
            # it is an error of its own and fails the run at the end.
            print(f"error storing the scan of {lazaret.sanitize_term(spec)}: "
                  f"{type(exc).__name__}: {lazaret.sanitize_term(exc)}", file=sys.stderr)
            exit_bad = True
            if errors is not None:
                errors.append(spec)
        print_scan(res)
        exit_bad |= res["verdict"] in BAD_VERDICTS  # a partial scan never passes
    return exit_bad


def _finish_sweep(errors, bad, ci):
    """CLI exit for scan / scan-all / discover: every package was attempted;
    any that failed to scan or store makes the run exit 1 (with or without
    --ci), after a one-line summary on stderr. --ci also fails on
    SUSPICIOUS / INCOMPLETE."""
    if errors:
        shown = ", ".join(lazaret.sanitize_term(s) for s in errors[:20])
        more = f", … (+{len(errors) - 20} more)" if len(errors) > 20 else ""
        print(f"error: {len(errors)} package(s) failed to scan or store: {shown}{more}",
              file=sys.stderr)
    if errors or (ci and bad):
        sys.exit(1)


def main():
    global SCAN_TIMEOUT, MAX_ARTIFACTS, MAX_PACKAGE_DOWNLOAD_BYTES, MAX_MEMBER
    lazaret.configure_stdio()
    ap = argparse.ArgumentParser(prog="lazaret-registry",
                                 description="Lazaret registry scanner: npm, PyPI, Go modules and crates")
    ap.add_argument("--version", action="version",
                    version=f"lazaret-registry {lazaret.VERSION} (engine: {_engine.describe()})")
    ap.add_argument("command", choices=["add", "scan", "scan-all", "list", "report", "discover"])
    ap.add_argument("specs", nargs="*", help="npm:<name>[@ver], pypi:<name>[@ver], go:<module>[@vX.Y.Z] "
                                             "or crates:<name>[@ver]")
    ap.add_argument("--db", default=os.environ.get("LAZARET_DB", "lazaret-registry.db"),
                    help="SQLite path (or sqlite:PATH), postgres:// URL or libpq "
                         "'host=… dbname=…' string (env LAZARET_DB)")
    ap.add_argument("--full", action="store_true",
                    help="Run the full ruleset, not just supply-chain/secret rules")
    ap.add_argument("--rescan", action="store_true", help="Re-scan already-scanned versions")
    ap.add_argument("--ci", action="store_true",
                    help="Exit 1 if any package is SUSPICIOUS or INCOMPLETE")
    ap.add_argument("--no-redact-secrets", action="store_true",
                    help="No effect, kept so existing scripts keep working: registry "
                         "results are always redacted, on screen and in the state DB "
                         "(the scanned archive has the original lines)")
    ap.add_argument("--excerpt-width", type=int, metavar="N",
                    help="Chars of the matched line to show under each finding (default 100)")
    ap.add_argument("--scan-timeout", type=float, metavar="SECONDS",
                    help=f"Time budget per archive (default {SCAN_TIMEOUT:g}, env "
                         f"LAZARET_SCAN_TIMEOUT); past it the verdict is INCOMPLETE")
    ap.add_argument("--max-artifacts", type=int, metavar="N",
                    help=f"PyPI files scanned per release (default {MAX_ARTIFACTS}, env "
                         f"LAZARET_MAX_ARTIFACTS); more makes the verdict INCOMPLETE")
    ap.add_argument("--max-source-bytes", type=int, metavar="BYTES",
                    help=f"Largest text file scanned as source (default {MAX_MEMBER:,}, env "
                         f"LAZARET_MAX_SOURCE_BYTES); a larger one is not fully scanned and "
                         f"the verdict is INCOMPLETE. Re-scan a stored version with --rescan")
    ap.add_argument("--max-download-bytes", type=int, metavar="BYTES",
                    help=f"Total bytes downloaded per package, all release files together "
                         f"(default {MAX_PACKAGE_DOWNLOAD_BYTES} = "
                         f"{_fmt_bytes(MAX_PACKAGE_DOWNLOAD_BYTES)}, env "
                         f"LAZARET_MAX_DOWNLOAD_BYTES); checked against the registry's "
                         f"declared sizes before downloading — files that don't fit "
                         f"are not scanned and the verdict is INCOMPLETE")
    # discover options
    ap.add_argument("--since", default="7d",
                    help="discover: time window — 7d, 2w, 24h, or an ISO date (default 7d); "
                         "with --resume, the window of a registry's first run")
    ap.add_argument("--resume", action="store_true",
                    help="discover: continue each registry's change feed where the last "
                         "--resume run stopped (a cursor per registry, stored in --db), so a "
                         "scheduled run sees every release in between")
    ap.add_argument("--limit", type=int, default=None,
                    help="discover: max packages to return (default 50, 0 for no limit); "
                         "with --resume, per registry and no limit by default, and the rest "
                         "is left for the next run")
    ap.add_argument("--ecosystem", action="append", choices=["pypi", "npm"],
                    help="discover: restrict to pypi and/or npm (default both)")
    ap.add_argument("--scan", action="store_true",
                    help="discover: scan the discovered packages (and track them)")
    ap.add_argument("--add", action="store_true",
                    help="discover: add discovered packages to the watchlist")
    ap.add_argument("--timings", action="store_true",
                    help="say on stderr where the time went: the network, reading archives, "
                         "the engine (by call), the rest")
    args = ap.parse_args()
    try:
        _engine.require()
    except _engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    if args.no_redact_secrets:
        # review P2: a raw credential line must never reach the state DB,
        # which other tools (the MCP server, a shared Postgres) read back
        print("note: --no-redact-secrets has no effect: registry results are always "
              "redacted, on screen and in the state DB", file=sys.stderr)
    if args.excerpt_width:
        lazaret.EXCERPT_WIDTH = args.excerpt_width
    if args.scan_timeout and args.scan_timeout > 0:
        SCAN_TIMEOUT = args.scan_timeout
    if args.max_artifacts and args.max_artifacts > 0:
        MAX_ARTIFACTS = args.max_artifacts
    if args.max_download_bytes and args.max_download_bytes > 0:
        MAX_PACKAGE_DOWNLOAD_BYTES = args.max_download_bytes
    if args.max_source_bytes and args.max_source_bytes > 0:
        MAX_MEMBER = args.max_source_bytes
    try:
        store = Store(args.db)
    except RuntimeError as exc:
        # CLI boundary: Store.__init__ raises RuntimeError when the Postgres
        # backend is unreachable or --db is unusable (library code must not
        # sys.exit — the MCP server dispatches it); here the CLI keeps the
        # exact legacy behavior.
        sys.exit(str(exc))
    kept = timings.Timings() if args.timings else None
    timed = contextlib.ExitStack()
    if kept is not None:
        timed.enter_context(timings.capture(kept))
        timed.enter_context(kept.run())
    try:
        errors = []
        args._errors = errors

        if args.command == "add":
            for spec in args.specs:
                try:
                    eco, name, _ = parse_spec(spec)
                except SpecError as exc:
                    sys.exit(f"error: {lazaret.sanitize_term(exc)}")
                _, created = store.add_package(eco, name)
                # audit H1: operator CLI arg; sanitize is a no-op for clean names.
                print(f"{'added' if created else 'already tracked'}: "
                      f"{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}")

        elif args.command == "scan":
            if not args.specs:
                sys.exit("scan needs at least one package spec")
            bad = cmd_scan(store, args.specs, args.full, args.rescan, errors=errors)
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "scan-all":
            specs = [f"{eco}:{name}" for _, eco, name in store.packages()]
            if not specs:
                sys.exit("no tracked packages — use 'add' first")
            print(f"Scanning latest versions of {len(specs)} tracked package(s)…")
            bad = cmd_scan(store, specs, args.full, args.rescan, errors=errors)
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "discover":
            try:
                bad = cmd_discover(store, args)
            except ValueError as exc:
                # CLI boundary: parse_since raises ValueError for a bad --since
                # (library code must not raise SystemExit — the MCP server
                # dispatches discover_packages); the CLI keeps the exact legacy
                # behavior: message on stderr, exit 1.
                sys.exit(str(exc))
            _finish_sweep(errors, bad, args.ci)

        elif args.command == "list":
            rows = store.status()
            if not rows:
                print("no tracked packages")
                return
            print(f"\n{'package':<40} {'last scan':<22} {'version':<12} {'verdict':<11} issues")
            for eco, name, ver, profile, at, verdict, n, supply in rows:
                # audit H1: eco/name/ver come from the stored DB blob (registry
                # data). Sanitize BEFORE the <40/<12 width padding so the column
                # alignment is computed on the string that is actually printed
                # ('·' is one char, so widths stay correct).
                pkg = lazaret.sanitize_term(f"{eco}:{name}")
                if ver is None:
                    print(f"{pkg:<40} {'— never scanned':<22}")
                else:
                    # sanitize the ARGUMENT of c(), never its result.
                    vc = c(VERDICT_COLOR.get(verdict, "0"), lazaret.sanitize_term(verdict))
                    extra = f" ({supply} supply-chain)" if supply else ""
                    print(f"{pkg:<40} {at:<22} "
                          f"{lazaret.sanitize_term(ver):<12} {vc:<11} {n}{extra}")

        elif args.command == "report":
            if not args.specs:
                sys.exit("report needs a package spec")
            try:
                eco, name, ver = parse_spec(args.specs[0])
            except SpecError as exc:
                sys.exit(f"error: {lazaret.sanitize_term(exc)}")
            rep = store.report(eco, name, ver)
            if not rep:
                # audit H1: args.specs[0] is echoed before any validation applies
                # to it on this path (parse_spec accepts a scoped name; a hostile
                # discovery-fed spec reaches here verbatim).
                sys.exit(f"no stored scan for {lazaret.sanitize_term(args.specs[0])}")
            # audit H1: rep[] fields are read back from the stored DB blob, which
            # was built from registry metadata + package content.
            print(f"\n{lazaret.sanitize_term(eco)}:{lazaret.sanitize_term(name)}@"
                  f"{lazaret.sanitize_term(rep['version'])} — "
                  f"{lazaret.sanitize_term(rep['verdict'])} "
                  f"(profile {rep['profile']}, scanned {rep['scannedAt']})")
            for a in rep.get("artifacts") or []:
                if isinstance(a, dict) and len(rep["artifacts"]) > 1:
                    print(f"  {lazaret.sanitize_term(a.get('verdict'))!s:<10} "
                          f"{lazaret.sanitize_term(a.get('filename'))}")
            for i in rep["issues"]:
                prefix = f"  {i['sev']:<8} [{i['rule']}] "
                # audit H1: stored archive member names + rule messages that embed
                # package content (SC-INSTALL-HOOK cmd, SCA advisory titles).
                print(f"{prefix}{lazaret.sanitize_term(i['file'])}:{i['line']} — "
                      f"{lazaret.sanitize_term(i['msg'])}")
                ex = lazaret.issue_excerpt(i)
                if ex:
                    print(" " * len(prefix) + c('2', '» ' + ex))
            if not rep["issues"]:
                print("  no findings")

    finally:
        store.close()
        timed.close()
        if kept is not None:
            for line in timings.render(kept.report()):
                print(line, file=sys.stderr)


if __name__ == "__main__":
    main()
