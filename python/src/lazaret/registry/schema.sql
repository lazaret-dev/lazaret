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
    ecosystem  TEXT PRIMARY KEY,         -- 'npm' | 'pypi'
    seq        TEXT NOT NULL,            -- PyPI changelog serial / npm replication seq
    seq_time   TEXT,                     -- when that change was made, if known (ISO 8601 UTC)
    updated_at TEXT NOT NULL             -- when a --resume run last stored it
);

GRANT SELECT, INSERT, UPDATE, DELETE ON packages, scans, discovery_cursors TO lazaret_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lazaret_app;
