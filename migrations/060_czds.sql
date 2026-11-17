-- CZDS module (cybercheck/czds.py, job "czds", dashboard page /czds). Additive only.
--
-- Only per-zone counters live here. The zone data itself (licensed under the CZDS Terms & Conditions) never
-- enters Postgres: the sorted name lists stay in data_dir/czds/<tld>/ (current + previous only), and only the
-- scored hits reach `domains` through store_hit(source = 'czds').

-- One row per TLD that is configured (CZDS_TLDS) or approved for this CZDS account.
-- status: pending | not_approved | approved | not_configured | revoked          (where the zone stands)
--         downloading | downloaded | processing                                 (in progress)
--         ok | baseline | rebaseline | unchanged                                (last file processed / skipped)
--         invalid | retrying | error | terms | no_access | low_disk             (last attempt failed)
CREATE TABLE IF NOT EXISTS czds_zones (
    tld             text        PRIMARY KEY,          -- ASCII (punycode for IDN TLDs), no dots
    configured      boolean     NOT NULL DEFAULT false,
    approved        boolean     NOT NULL DEFAULT false, -- listed in /czds/downloads/links
    approved_at     timestamptz,                      -- first seen approved (or approved again after a revocation)
    download_url    text,                             -- as returned by the links endpoint (spec v1.0.9)
    last_head       timestamptz,                      -- at most one HEAD ...
    last_download   timestamptz,                      -- ... and one GET per zone per 24 h (CZDS T&C s1.8)
    last_processed  timestamptz,
    next_due        timestamptz,
    retry_at        timestamptz,
    total_names     bigint,                           -- registrable names directly under the TLD in the last file
    new_names       bigint,                           -- names not in the previous list (NULL for a baseline)
    removed_names   bigint,
    hits            int,                              -- new names that scored and were stored
    new_hits        int,                              -- ... of which were not already in `domains`
    soa_serial      bigint,
    file_bytes      bigint,
    last_modified   text,                             -- Last-Modified of the file processed
    status          text        NOT NULL DEFAULT 'pending',
    error           text,
    fail_count      int         NOT NULL DEFAULT 0,
    duration_s      real,
    state           jsonb       NOT NULL DEFAULT '{}',  -- private job state (HEAD/download metadata, retry counters)
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- One row per processed or failed file, kept 120 days (the job deletes older rows).
CREATE TABLE IF NOT EXISTS czds_runs (
    id              bigserial   PRIMARY KEY,
    tld             text        NOT NULL,
    at              timestamptz NOT NULL DEFAULT now(),
    status          text        NOT NULL,
    soa_serial      bigint,
    file_bytes      bigint,
    total_names     bigint,
    new_names       bigint,
    removed_names   bigint,
    hits            int,
    new_hits        int,
    duration_s      real,
    error           text
);
CREATE INDEX IF NOT EXISTS czds_runs_at_idx  ON czds_runs (at);
CREATE INDEX IF NOT EXISTS czds_runs_tld_idx ON czds_runs (tld, at DESC);

-- Recent CZDS hits on the dashboard
CREATE INDEX IF NOT EXISTS domains_czds_first_seen_idx ON domains (first_seen DESC) WHERE source = 'czds';
