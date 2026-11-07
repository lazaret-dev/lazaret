"""SC-VERSION-INFLATION (RA-7, 0.1.9): a release whose version number is inflated the way a dependency-confusion
squat inflates it, or one published in a burst of releases.

Dependency confusion (Alex Birsan, 2021) shadows a victim's private package with a public one of the same name at a
high version, so a misconfigured resolver prefers the public one. Lazaret, reading a public-registry release in
isolation, cannot see the private package — so it reads the public tell: an anomalous version on the package's own
history (Xygeni reported npm packages published at 19999.x and 99.x through September 2026), and an unusual
publishing rate.

Two shapes, each MAJOR (a weaker indicator, like SC-NEW-DEPENDENCY's recent one), judged on the package's history as
the registry gives it — [(version, its publish time or None)] in the registry's order, a version without a time (a
crate's index line from before crates.io recorded `pubtime`) published before every version with one:

  * an inflated version — a non-zero PyPI epoch (`1!0.0.1` outranks every version without one), or a major of
    INFLATED_MAJOR (99) or more that is not a calendar version (`calendar_like`: a year from CALENDAR_FIRST_YEAR
    (1990) to the year after the version was published, as YYYY, YYYYMM or YYYYMMDD, so 2024.x and 20240101 are left
    alone and 2099.x, 999912.x and 99991231.x are not) — that is *new to the package*, judged on the versions
    published at or before this release only, so the verdict does not change when later versions appear: the origin
    of this release's inflated line is the latest inflated version published at or before it that is new to the
    package — the package's first published version, or a jump: its major at least JUMP (50) above the highest major
    published before it, or an epoch above every epoch before it — and the release is flagged when it has one. A
    squat's 99.0.0 and its 99.0.1 are both flagged; a package that climbs 97 -> 98 -> 99 (chromedriver follows
    Chrome's numbers) is not, and one that climbs past 99 and later jumps (130 -> 9999) is flagged from the jump;
  * a flood — more than FLOOD_COUNT (20) releases published within a FLOOD_WINDOW (24 hours) that contains this
    release's publish time; pre-releases (a SemVer `-…`, a PEP 440 a/b/rc/dev) are not counted, as a resolver's range
    does not pick them, nor a version without a time.

This module is the pure heuristic (no fetch, no finding object); `repo.version_inflation_issues` reads the registry
history (`prior.version_times`) and builds the finding. Judging an inflated major against the package's own versions,
rather than an absolute floor alone, is the "internal version" check: a jump within the package's own sequence.
"""
import bisect
import datetime
import re

INFLATED_MAJOR = 99                                   # a major this high (not calendar-like, new to the package)
JUMP = 50                                             # an origin this many majors above the highest before it
CALENDAR_FIRST_YEAR = 1990                            # the first year a calendar version names
FLOOD_COUNT = 20                                      # more than this many releases (John, Oct 18: 5 made 13% of a
                                                      # day's new releases WARN, mostly CI publishing) ...
FLOOD_WINDOW = datetime.timedelta(hours=24)           # ... within a window this long that holds this release's time
RULE = "SC-VERSION-INFLATION"

_VERSION_RE = re.compile(r"\s*v?(?:(\d{1,9})!)?(\d{1,9})")    # [epoch!]major of a SemVer or PEP 440 version
#: a PEP 440 pre-release or development release (its spellings: a, alpha, b, beta, c, rc, pre, preview, dev)
_PEP440_PRE_RE = re.compile(r"(?:\d|[._-])(?:a|alpha|b|beta|c|rc|pre|preview|dev)(?:\d|[._-]|$)", re.IGNORECASE)
_FIRST = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)


def rank(version):
    """(epoch, major) of a SemVer or PEP 440 version ('1!2.0' -> (1, 2), 'v99.0.0' -> (0, 99)), or None."""
    m = _VERSION_RE.match(version or "")
    return (int(m.group(1) or 0), int(m.group(2))) if m else None


def major(version):
    """The leading integer major of a version string ('v99.0.0' -> 99, '2024.1' -> 2024, '1!2.0' -> 2), or None."""
    r = rank(version)
    return r[1] if r else None


def _latest_year(when):
    """The last year a calendar version published at `when` (None: now) can name: the year after."""
    return (when or datetime.datetime.now(datetime.timezone.utc)).year + 1


def calendar_like(m, latest_year=None):
    """Is a major a calendar version — a year, a year-month (YYYYMM) or a date (YYYYMMDD) of a year from
    CALENDAR_FIRST_YEAR to `latest_year` (the year after the version was published; None: the year after this one)?
    Those are normal CalVer schemes (2024.x, 20240101), not inflation; 2099.x, 999912.x and 99991231.x are not."""
    if m is None:
        return False
    latest = latest_year if latest_year is not None else _latest_year(None)
    s = str(m)
    for width, fmt in ((4, "%Y"), (6, "%Y%m"), (8, "%Y%m%d")):
        if len(s) == width:
            try:
                year = datetime.datetime.strptime(s, fmt).year
            except ValueError:
                return False
            return CALENDAR_FIRST_YEAR <= year <= latest
    return False


def inflated(version, when=None):
    """Is a version inflated — a non-zero epoch, or a major of at least INFLATED_MAJOR that is not a calendar version
    for a version published at `when` (None: now)?"""
    r = rank(version)
    if r is None:
        return False
    epoch, m = r
    return epoch > 0 or (m >= INFLATED_MAJOR and not calendar_like(m, _latest_year(when)))


def prerelease(eco, version):
    """Is a version a pre-release a resolver's range does not pick: a SemVer `-…` (npm, crates; not in its `+` build
    metadata), a PEP 440 a/b/rc/dev (PyPI; not in its `+` local part)?"""
    core = (version or "").split("+", 1)[0]
    if eco == "pypi":
        return bool(_PEP440_PRE_RE.search(core))
    return "-" in core


def timeline(history):
    """[(version, time or None)] in the order the versions were published: those without a time first, in the
    registry's order (a crate's index lists its lines as they were published, and one without `pubtime` predates
    it), then by time (the registry's order between two of the same time)."""
    order = sorted(enumerate(history), key=lambda iv: (iv[1][1] is not None, iv[1][1] or _FIRST, iv[0]))
    return [vw for _i, vw in order]


def _describe(version, when):
    epoch, m = rank(version)
    if epoch:
        return f"an epoch of {epoch}, which outranks every version without one"
    return f"a major of {m}, which is not a calendar version"


def version_reason(version, history):
    """A reason string when `version` is an inflated version new to the package, else None. `history`: [(version,
    publish time or None)], the package's versions as the registry lists them, `version` among them; only those
    published at or before it are read (`timeline`)."""
    line = timeline(history)
    at = next((k for k, (v, _t) in enumerate(line) if v == version), None)
    if at is None or not inflated(version, line[at][1]):
        return None
    # the origin of this release's inflated line: the latest inflated version, at or before this release, that is new
    # to the package — the first published version, or a jump over every version published before it — so a line
    # that climbed past 99 and later jumps (130 -> 9999) is caught at the jump, and what continues a jump is flagged
    origin = new = None
    hi = None                                             # ((epoch, major), index, version) of the highest so far
    for k in range(at + 1):
        v, t = line[k]
        r = rank(v) or (0, 0)
        if inflated(v, t):
            if hi is None:
                origin, new = v, "the package's first published version"
            elif r[0] > hi[0][0]:
                origin, new = v, f"an epoch above that of every version published before it (the highest, {hi[2]})"
            elif r[0] == hi[0][0] and r[1] >= hi[0][1] + JUMP:
                origin, new = v, (f"a jump of {r[1] - hi[0][1]} majors from {hi[2]}, the highest version published "
                                  "before it")
        if hi is None or (r, k) > hi[:2]:
            hi = (r, k, v)                                # (of the highest, the one published last)
    if origin is None:
        return None                              # (a climb, as chromedriver follows Chrome's numbers: not new)
    this = f"its version {version} is inflated — {_describe(version, line[at][1])} —"
    how = f"is {new}" if origin == version else f"continues the inflated line {origin} began, {new}"
    return (f"{this} and {how}. A public package published at an outsized version is how dependency confusion "
            "outranks a private package of the same name")


def flood_reason(eco, version, history):
    """A reason string when more than FLOOD_COUNT releases were published within a FLOOD_WINDOW that contains the
    publish time of `version`, else None. `history` as `version_reason`'s; pre-releases (`prerelease`) and versions
    without a time are not counted (nor is `version`, when it is a pre-release)."""
    when = next((t for v, t in history if v == version), None)
    if when is None:
        return None
    times = sorted(t for v, t in history if t is not None and not prerelease(eco, v))
    lo = bisect.bisect_left(times, when - FLOOD_WINDOW)
    starts = times[lo:bisect.bisect_right(times, when)] + [when]      # (each window that holds `when`, at its best)
    best = max(bisect.bisect_right(times, s + FLOOD_WINDOW) - bisect.bisect_left(times, s) for s in starts)
    if best <= FLOOD_COUNT:
        return None
    return (f"{best} of its releases (pre-releases not counted) were published within 24 hours, a span that includes "
            "this release — a burst of versions, as a name-squatting flood publishes")
