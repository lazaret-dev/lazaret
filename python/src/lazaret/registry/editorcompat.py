"""Which version of a VS Code extension an editor installs (0.1.9, E-1's fifth part): the rules `lazaret guard code
--install-extension` chooses by, so that it checks the version the editor would install, and installs that one.

They are VS Code's (MIT; its extension management and its extension validator), written again here:

    the target platform  the editor's: its system and the architecture its own build runs on (`process.arch`), Alpine
                 when /etc/os-release says ID=alpine: `win32-x64`, `win32-arm64`, `linux-x64`, `linux-arm64`,
                 `linux-armhf`, `alpine-x64`, `alpine-arm64`, `darwin-x64`, `darwin-arm64`; `unknown` for any other.
                 A version's file fits it when it is for that platform, or universal (a gallery entry that names no
                 platform is universal too); a file for an unknown platform never fits.
    the engine   `engines.vscode`: `*`, or `[^|>=]MAJOR.MINOR.PATCH[-…]` with `x` for any number. A caret frees the
                 minor and the patch (the patch only, for 0.x); `>=` is a minimum. The range must name the major (and,
                 for 0.x, the minor); a pre-release part `-YYYYMMDD[HH[MM]]` is a date the editor's build must not be
                 older than. An editor 1.x takes any 0.x range that is not an exact version.
    the version  with no version asked for, the newest version (by version number, the editor's platform's file
                 first among a version's files) whose file fits the platform and whose engine takes the editor's
                 version: a release, or, with --pre-release, a release or a pre-release. An exact version is that
                 version or nothing.

An editor whose VS Code version is not known (a fork that reports its own) is not checked against the engine: the
newest fitting file is taken, and the editor itself refuses one it cannot run (it checks the engine of every file it
installs). Nothing here reaches the network."""

import datetime
import re

__all__ = ["TARGET_PLATFORMS", "target_platform", "platform_fits", "engine_ok", "parse_engine", "version_key",
           "choose", "Candidate"]

TARGET_PLATFORMS = frozenset(("win32-x64", "win32-arm64", "linux-x64", "linux-arm64", "linux-armhf", "alpine-x64",
                              "alpine-arm64", "darwin-x64", "darwin-arm64"))
#: A file for every platform: `universal`, and `undefined` (a Marketplace entry that names no platform).
ANY_PLATFORM = frozenset(("universal", "undefined"))

_ENGINE_RE = re.compile(r"^(\^|>=)?(\d+|x)\.(\d+|x)\.(\d+|x)(-.*)?$")
_NOT_BEFORE_RE = re.compile(r"^-(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?$")
_SEMVER_RE = re.compile(r"^(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
#: node's process.arch for the machine names Python reports (the editor's build is the machine's, as a rule)
_ARCH = {"x86_64": "x64", "amd64": "x64", "x64": "x64", "aarch64": "arm64", "arm64": "arm64", "armv7l": "arm",
         "armv8l": "arm", "armv6l": "arm", "arm": "arm"}


def target_platform(system, arch, os_release=None):
    """The editor's target platform for `system` (sys.platform's value), `arch` (node's process.arch, as the editor's
    `--version` prints it, or a machine name) and `os_release` (the text of /etc/os-release, on Linux)."""
    arch = _ARCH.get((arch or "").lower(), (arch or "").lower())
    if system.startswith("win") or system == "cygwin":
        return {"x64": "win32-x64", "arm64": "win32-arm64"}.get(arch, "unknown")
    if system == "darwin":
        return {"x64": "darwin-x64", "arm64": "darwin-arm64"}.get(arch, "unknown")
    if system.startswith("linux"):
        match = re.search(r"^ID=([^\x1b\r\n]*)", os_release or "", re.M)
        if match and match.group(1) == "alpine":
            return {"x64": "alpine-x64", "arm64": "alpine-arm64"}.get(arch, "unknown")
        return {"x64": "linux-x64", "arm64": "linux-arm64", "arm": "linux-armhf"}.get(arch, "unknown")
    return "unknown"


def platform_fits(file_platform, target):
    """Does a file for `file_platform` install on an editor whose target platform is `target`?"""
    if file_platform in ANY_PLATFORM:
        return True
    return file_platform in TARGET_PLATFORMS and file_platform == target


class _Range:
    """One parsed `engines.vscode` value (or an editor's version): the numbers, which of them must be equal, a minimum,
    and the date the editor must not be older than (milliseconds since 1970, 0 for none)."""
    __slots__ = ("nums", "fixed", "minimum", "not_before")

    def __init__(self, nums, fixed, minimum, not_before):
        self.nums, self.fixed, self.minimum, self.not_before = nums, fixed, minimum, not_before


def parse_engine(text):
    """A range (or a version) -> _Range, or None when it is not one the editor reads."""
    if not isinstance(text, str):
        return None
    text = text.strip()
    if text == "*":
        return _Range((0, 0, 0), (False, False, False), False, 0)
    m = _ENGINE_RE.match(text)
    if not m:
        return None
    caret, minimum = m.group(1) == "^", m.group(1) == ">="
    parts = (m.group(2), m.group(3), m.group(4))
    nums = tuple(0 if p == "x" else int(p) for p in parts)
    fixed = [p != "x" for p in parts]
    if caret:
        if nums[0] == 0:
            fixed[2] = False
        else:
            fixed[1] = fixed[2] = False
    not_before = 0
    dated = _NOT_BEFORE_RE.match(m.group(5) or "")
    if dated:
        y, mo, d, h, mi = (int(g) if g else 0 for g in dated.groups())
        try:
            when = datetime.datetime(y, mo, d, h, mi, tzinfo=datetime.timezone.utc)
            not_before = int(when.timestamp() * 1000)
        except ValueError:
            not_before = 0
    return _Range(nums, tuple(fixed), minimum, not_before)


def _within(have, product_ms, want):
    """Is the editor's version `have` (a _Range of its version) within `want`?"""
    major, minor, patch = have.nums
    w_major, w_minor, w_patch = want.nums
    if want.minimum:
        if (major, minor) != (w_major, w_minor):
            return (major, minor) > (w_major, w_minor)
        if product_ms and product_ms < want.not_before:
            return False
        return patch >= w_patch
    fixed = list(want.fixed)
    # an editor 1.x takes a 0.x range, unless the range is an exact version
    if major == 1 and w_major == 0 and not all(fixed):
        w_major, w_minor, w_patch, fixed = 1, 0, 0, [True, False, False]
    for mine, wanted, must_equal in ((major, w_major, fixed[0]), (minor, w_minor, fixed[1]), (patch, w_patch, fixed[2])):
        if mine < wanted:
            return False
        if mine > wanted:
            return not must_equal
    return not (product_ms and product_ms < want.not_before)


def engine_ok(engine, product_version, product_date=None):
    """Would an editor at VS Code version `product_version` (built on `product_date`, ISO text or None) take an
    extension whose `engines.vscode` is `engine`? An engine that is not one, or that does not name the major (and the
    minor, for 0.x), is refused, as the editor refuses it."""
    if engine == "*":
        return True
    want = parse_engine(engine)
    have = parse_engine(product_version)
    if want is None or have is None or have.minimum:
        return False
    if not want.fixed[0] or (want.nums[0] == 0 and not want.fixed[1]):
        return False                    # (the range must name the major, and for 0.x the minor too)
    product_ms = 0
    if isinstance(product_date, str) and product_date:
        try:
            when = datetime.datetime.fromisoformat(product_date.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=datetime.timezone.utc)
            product_ms = int(when.timestamp() * 1000)
        except ValueError:
            product_ms = 0
    return _within(have, product_ms, want)


def version_key(version):
    """A sort key for an extension version (SemVer: a release above its own pre-releases, numeric identifiers below
    the others); a version that is not SemVer sorts below every one that is."""
    m = _SEMVER_RE.match(version or "")
    if not m:
        return (0, (), 0, ())
    nums = tuple(int(g) for g in m.groups()[:3])
    pre = m.group(4)
    if pre is None:
        return (1, nums, 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (1, nums, 0, ids)


class Candidate:
    """One file of one version, as a registry lists it: the version, the platform the file is for (`universal`, or
    `undefined` for a gallery entry that names none), its `engines.vscode` (None when the registry does not say), a
    pre-release?, when it was published (an aware datetime or None), and the registry's own entry (for its module)."""
    __slots__ = ("version", "platform", "engine", "pre", "when", "entry")

    def __init__(self, version, platform, engine=None, pre=False, when=None, entry=None):
        self.version, self.platform, self.engine, self.pre, self.when, self.entry = (
            version, platform, engine, pre, when, entry)

    def __repr__(self):
        return f"Candidate({self.version!r}, {self.platform!r}, pre={self.pre})"


def choose(candidates, target, product_version=None, product_date=None, version=None, pre_release=False):
    """The file the editor installs among `candidates` (Candidate), or None: `version` that exact version, else the
    newest release (with `pre_release`, the newest version) whose file fits `target` and whose engine takes
    `product_version` (not checked when it is None, nor for a file whose engine the registry does not give). As the
    editor walks them: newest version first and, among a version's files, the one for `target` first; for an exact
    version, the first of its files that does not fit ends the walk."""
    def order(c):
        return (version_key(c.version), c.platform == target)
    for c in sorted(candidates, key=order, reverse=True):
        if version is not None and c.version != version:
            continue
        if version is None and not pre_release and c.pre:
            continue
        fits = platform_fits(c.platform, target) and (
            product_version is None or c.engine is None or engine_ok(c.engine, product_version, product_date))
        if fits:
            return c
        if version is not None:
            return None
    return None
