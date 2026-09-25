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
--   python3 lazaret_repo.py scan-all
--
-- Note: lazaret_repo.py also runs this DDL automatically on first connect
-- (CREATE TABLE IF NOT EXISTS), so this file is optional if the app role may
-- create tables.

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
    verdict        TEXT,                 -- 'OK' | 'WARN' | 'SUSPICIOUS'
    issues         JSONB,
    -- Verdict-integrity fix (audit C2/G16): keyed on the engine version so a
    -- stale-clean verdict from an older engine cannot shadow future re-scans
    -- (the app-side Store.has_scan matches on engine_version too).
    UNIQUE (package_id, version, profile, engine_version)
);

CREATE INDEX IF NOT EXISTS idx_scans_package ON scans(package_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);

GRANT SELECT, INSERT, UPDATE, DELETE ON packages, scans TO lazaret_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lazaret_app;
