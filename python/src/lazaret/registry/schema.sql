-- Lazaret registry-scanner state — PostgreSQL setup
--
-- Creates a NEW dedicated database on your existing server (do not merge
-- into an existing application database such as edgar).
--
-- One-time, as a superuser or CREATEDB role:
--   psql -h <host> -U <admin> -c "CREATE DATABASE lazaret;"
--   psql -h <host> -U <admin> -c "CREATE ROLE lazaret_app LOGIN PASSWORD '<strong-password>';"
--   psql -h <host> -U <admin> -d lazaret -f schema.sql
--
-- Then point the scanner at it:
--   export LAZARET_DB="postgres://lazaret_app:<password>@<host>:5432/lazaret"
--   lazaret-registry scan-all
--
-- Note: lazaret-registry also runs this DDL automatically on first connect
-- (CREATE TABLE IF NOT EXISTS, and ADD COLUMN IF NOT EXISTS for columns
-- added since), so this file is optional if the app role may create tables.
-- Re-running it on an existing database is safe: it only adds what is missing.

CREATE TABLE IF NOT EXISTS packages (
    id         SERIAL PRIMARY KEY,
    ecosystem  TEXT NOT NULL,            -- 'npm' | 'pypi'
    name       TEXT NOT NULL,
    added_at   TEXT NOT NULL,
    UNIQUE (ecosystem, name)
);

CREATE TABLE IF NOT EXISTS scans (
    id             SERIAL PRIMARY KEY,
    package_id     INTEGER NOT NULL REFERENCES packages(id),
    version        TEXT NOT NULL,
    profile        TEXT NOT NULL,        -- 'supply-chain' | 'full'
    scanned_at     TEXT NOT NULL,
    engine_version TEXT NOT NULL,
    files_scanned  INTEGER,
    archive_bytes  INTEGER,
    blockers       INTEGER,
    criticals      INTEGER,
    majors         INTEGER,
    supply_chain   INTEGER,
    issue_count    INTEGER,
    verdict        TEXT,                 -- 'OK' | 'WARN' | 'INCOMPLETE' | 'SUSPICIOUS'
    issues         JSONB,
    -- per-file detail: a PyPI release is judged on the sdist AND every
    -- distinct wheel; [{filename, kind, verdict, verdictReason, ...}]
    artifacts      JSONB,
    -- Verdict-integrity fix (audit C2/G16): keyed on the engine version so a
    -- stale-clean verdict from an older engine cannot shadow future re-scans
    -- (the app-side Store.has_scan matches on engine_version too).
    UNIQUE (package_id, version, profile, engine_version)
);

-- databases created before the artifacts column existed
ALTER TABLE scans ADD COLUMN IF NOT EXISTS artifacts JSONB;

CREATE INDEX IF NOT EXISTS idx_scans_package ON scans(package_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);

-- `discover --resume`: where each registry's change feed was read up to, so
-- the next run continues there and sees every release in between
CREATE TABLE IF NOT EXISTS discovery_cursors (
    ecosystem  TEXT PRIMARY KEY,         -- 'npm' | 'pypi' | 'crates' | 'github'
    seq        TEXT NOT NULL,            -- PyPI changelog serial / npm replication seq / crates.io's newest update read
                                         -- (microseconds since 1970) / GitHub's last repository ID
    seq_time   TEXT,                     -- when that change was made, if known (ISO 8601 UTC)
    updated_at TEXT NOT NULL             -- when a --resume run last stored it
);

-- `discover --ecosystem github --resume` (GH-NEW-REPOS): the new public
-- repositories a filter kept, each waiting for content, scanned, reported (a
-- campaign repository, never downloaded) or dropped
CREATE TABLE IF NOT EXISTS github_candidates (
    repo_id        BIGINT PRIMARY KEY,   -- GitHub's repository ID
    full_name      TEXT NOT NULL,        -- owner/repo
    description    TEXT,
    fork           INTEGER NOT NULL,     -- 1 for a fork
    filters        TEXT NOT NULL,        -- JSON list: what matched
    listed_at      TEXT NOT NULL,        -- ISO 8601 UTC
    state          TEXT NOT NULL,        -- 'waiting' | 'ready' | 'scanned' | 'reported' | 'dropped'
                                         -- (--github-scan-all: 'queued' | 'pending' | 'excluded')
    next_check     TEXT,                 -- when its content is checked next (waiting)
    checks         INTEGER NOT NULL,
    size           INTEGER,              -- GitHub's size, KB
    pushed_at      TEXT,
    default_branch TEXT,
    commit_sha     TEXT,                 -- the commit scanned
    verdict        TEXT,
    last_error     TEXT,                 -- why it was dropped, or what failed last
    updated_at     TEXT NOT NULL,
    late_at        TEXT                  -- GH-SCAN-GQL: when a re-ask 6 hours or more after the listing found its
                                         -- code (a late find, which has a share of the scans); NULL for the others
);
ALTER TABLE github_candidates ADD COLUMN IF NOT EXISTS late_at TEXT;

-- `python -m lazaret.registry.actions --db` (RA-4): the commit each version tag
-- of an action pointed to when the action scan first saw it, so a tag that
-- moves is reported (SC-ACTION-TAG-MOVED), and whether a release commit only
-- its tag holds was given SC-ACTION-TAG-ONLY before (FP-IMPOSTOR-TAG)
CREATE TABLE IF NOT EXISTS action_tags (
    repo       TEXT NOT NULL,            -- owner/repo, lower-cased
    tag        TEXT NOT NULL,            -- an exact version tag (v4.1.0)
    sha        TEXT NOT NULL,            -- the commit it pointed to when first seen (or when its move was accepted)
    first_seen TEXT NOT NULL,            -- ISO 8601 UTC
    last_seen  TEXT NOT NULL,
    moved_to   TEXT,                     -- the commit it was seen at since, until the move is accepted
    moved_at   TEXT,
    tag_only   TEXT,                     -- when SC-ACTION-TAG-ONLY was first given of the tag (FP-IMPOSTOR-TAG)
    tag_only_sha TEXT,                   -- at which commit (another than sha: a move an older version accepted)
    moved_from TEXT,                     -- the commit it was at before a move to sha was accepted
    moved_from_at TEXT,
    PRIMARY KEY (repo, tag)
);

-- databases created before FP-IMPOSTOR-TAG's columns existed
ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS tag_only TEXT;
ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS tag_only_sha TEXT;
ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS moved_from TEXT;
ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS moved_from_at TEXT;

-- `discover --ecosystem github --resume --github-scan-all` (GH-SCAN-GQL): the
-- new repositories the listing gave scan-all that nothing kept, waiting for
-- code, asked of GitHub's GraphQL API by their node IDs; one that got code
-- moves to github_candidates (queued), one gone or still without code after
-- the last check is deleted
CREATE TABLE IF NOT EXISTS github_listed (
    repo_id     BIGINT PRIMARY KEY,      -- GitHub's repository ID
    node_id     TEXT NOT NULL,           -- its GraphQL node ID (the listing's node_id)
    full_name   TEXT NOT NULL,           -- owner/repo, as listed
    description TEXT,
    fork        INTEGER NOT NULL,        -- 1 for a fork
    listed_at   TEXT NOT NULL,           -- ISO 8601 UTC
    state       TEXT NOT NULL,           -- 'unasked' | 'empty' | 'fork' (a fork with no push of its own)
    next_check  TEXT NOT NULL,           -- when it is asked next (1, 6, 24 and 72 hours after listed_at)
    checks      INTEGER NOT NULL,        -- the answers "no code yet" so far
    fails       INTEGER NOT NULL DEFAULT 0, -- the asks in a row GitHub could not answer about it (each puts
                                            -- it off longer)
    last_error  TEXT,                    -- why the last ask got no answer
    updated_at  TEXT NOT NULL
);
ALTER TABLE github_listed ADD COLUMN IF NOT EXISTS fails INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_github_listed_listed ON github_listed(listed_at, repo_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON packages, scans, discovery_cursors, github_candidates TO lazaret_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON action_tags TO lazaret_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON github_listed TO lazaret_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lazaret_app;
