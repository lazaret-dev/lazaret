"""GH Archive's hourly files of GitHub's public events, read for GitHub discovery (GH-SCAN-ALL, 0.1.9; the plan's
phase 2 of GH-NEW-REPOS): which new repositories got code, and which repositories were made public, without a
request to GitHub for each one.

    https://data.gharchive.org/YYYY-MM-DD-H.json.gz      (UTC; the hour unpadded: 2026-10-17-3)

GH Archive (gharchive.org) records GitHub's public timeline, the Events API's events, and publishes each UTC hour as
one gzipped file of JSON lines, some 70 MB, a while after the hour ends; until then the file is not there (404).
What discovery reads of an event (anything else is passed over):

- `PushEvent`, and `CreateEvent` of a branch or a tag: the repository (`repo.id`, `repo.name`) has code.
- `CreateEvent` of a repository (`payload.ref_type` "repository"): a new repository, with its description.
- `PublicEvent`: a repository made public. One created private keeps its old ID, so GitHub's list of new
  repositories (`/repositories`) never shows it.

GitHub trimmed the events' payloads in 2025 (a push's commits, for one); what is read here is the repository and
the event's type, which every event keeps. GH Archive can miss an event, so a repository a filter keeps is still
checked as before (ghdiscover.check); this only makes it ready sooner.

Bounds, since the file is someone else's: the compressed file (ARCHIVE_BYTES), the text it unpacks to (TEXT_BYTES),
a line (LINE_BYTES: a longer one is passed over, counted), and an event's fields (an ID a positive integer, a name
owner/repo by GitHub's rules, a description cut to ghdiscover.MAX_TEXT). The file goes only to data.gharchive.org,
over HTTPS, with no credential; nothing in it is fetched or run.
"""
import datetime
import gzip
import io
import json

from lazaret.registry import repo as _repo
from lazaret.registry import sources

__all__ = ["HOST", "Hour", "hour_name", "parse_hour", "url", "fetch", "read", "ArchiveError"]

UTC = datetime.timezone.utc
HOST = "data.gharchive.org"
ARCHIVE_BYTES = 768 * 1024 * 1024       # one hour's file, compressed (some 70 MB in 2026)
TEXT_BYTES = 8 * 1024 * 1024 * 1024     # what it unpacks to
LINE_BYTES = 1024 * 1024                # one event
MAX_TEXT = 1000                         # characters of a name or description kept
_WANTED = (b"PushEvent", b"CreateEvent", b"PublicEvent")


class ArchiveError(Exception):
    """An hour's file could not be read (the network, a budget, a file that is not gzip)."""


class Hour:
    """What one hour's events tell discovery: `pushed`, `created` and `public` map a repository's ID to what the
    events say of it ((name, time), (name, description, time), (name, time)), `pushed` only for the repositories
    `keep` keeps; `pushed_ids` every repository pushed to; `events` the lines read, `skipped` the lines passed over
    (too long, not JSON, not an event)."""

    def __init__(self):
        self.pushed, self.created, self.public = {}, {}, {}
        self.pushed_ids = set()
        self.events = self.skipped = 0


def hour_name(t):
    """The file name's hour: 2026-10-17-3 (UTC)."""
    t = t.astimezone(UTC)
    return f"{t:%Y-%m-%d}-{t.hour}"


def parse_hour(name):
    """2026-10-17-3 -> that hour (UTC), else ValueError."""
    day, _, hour = str(name).rpartition("-")
    if not hour.isdigit() or not 0 <= int(hour) <= 23:
        raise ValueError(f"not an hour of GH Archive: {name!r}")
    d = datetime.datetime.strptime(day, "%Y-%m-%d")
    return datetime.datetime(d.year, d.month, d.day, int(hour), tzinfo=UTC)


def url(t):
    return f"https://{HOST}/{hour_name(t)}.json.gz"


def fetch(t, http=None):
    """The hour's file (bytes, compressed), or None when GH Archive has not published it yet (404). `http` is the
    network seam (sources._http's signature); ArchiveError for anything else that fails."""
    http = http or sources._http
    what = f"reading GH Archive's hour {hour_name(t)}"
    try:
        return http(url(t), {"User-Agent": _repo.USER_AGENT}, ARCHIVE_BYTES, {HOST}, HOST, what=what,
                    has_token=False, kind="github")
    except sources.SourceError as exc:
        if getattr(exc, "status", None) == 404:
            return None
        raise ArchiveError(str(exc)) from None


def read(body, keep=None):
    """An hour's file -> Hour. `keep(repo_id)`, when given, says which repositories' pushes are kept (the others
    are only counted): a busy hour has some hundred thousand pushes, and discovery wants the new repositories'."""
    hour = Hour()
    total = 0
    # (a server that unpacked the file on the way, as a store transcoding gzip does, sends the lines themselves)
    opened = gzip.GzipFile(fileobj=io.BytesIO(body)) if body[:2] == b"\x1f\x8b" else io.BytesIO(body)
    try:
        with opened as f:
            while True:
                line = f.readline(LINE_BYTES + 1)
                if not line:
                    break
                total += len(line)
                if total > TEXT_BYTES:
                    raise ArchiveError(f"the hour's events unpack to more than {TEXT_BYTES // 2**30} GiB")
                if len(line) > LINE_BYTES and not line.endswith(b"\n"):
                    hour.skipped += 1
                    total += _skip_line(f)
                    continue
                hour.events += 1
                if any(w in line for w in _WANTED):
                    _event(hour, line, keep)
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise ArchiveError(f"the hour's file is not one GH Archive writes: {exc}") from None
    return hour


def _skip_line(f):
    """Read past the rest of a line too long to keep: -> the bytes read."""
    n = 0
    while True:
        part = f.readline(LINE_BYTES)
        n += len(part)
        if not part or part.endswith(b"\n"):
            return n


def _event(hour, line, keep):
    try:
        ev = json.loads(line)
    except ValueError:
        hour.skipped += 1
        return
    if not isinstance(ev, dict) or not isinstance(ev.get("repo"), dict):
        hour.skipped += 1
        return
    kind, rid, name = ev.get("type"), ev["repo"].get("id"), ev["repo"].get("name")
    if not (isinstance(rid, int) and not isinstance(rid, bool) and rid > 0 and _repository(name)):
        hour.skipped += 1
        return
    at = ev.get("created_at") if isinstance(ev.get("created_at"), str) else None
    at = _when(at)
    payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else {}
    if kind == "CreateEvent" and payload.get("ref_type") == "repository":
        desc = payload.get("description") if isinstance(payload.get("description"), str) else None
        hour.created.setdefault(rid, (name, desc[:MAX_TEXT] if desc else None, at))
    elif kind == "PushEvent" or (kind == "CreateEvent" and payload.get("ref_type") in ("branch", "tag")):
        hour.pushed_ids.add(rid)
        if keep is None or keep(rid):
            hour.pushed.setdefault(rid, (name, at))
    elif kind == "PublicEvent":
        hour.public.setdefault(rid, (name, at))


def _when(text):
    """An event's time as ISO 8601 UTC text, or None for one that is not a time."""
    if not text:
        return None
    try:
        t = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=UTC)
    return t.astimezone(UTC).isoformat(timespec="seconds")


def _repository(name):
    """Is `name` owner/repo by GitHub's rules (what goes into a URL later)?"""
    if not isinstance(name, str) or len(name) > 200 or "@" in name:
        return False
    try:
        sources.parse_source(f"github:{name}")
    except sources.SourceError:
        return False
    return True
