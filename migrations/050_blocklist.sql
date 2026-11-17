-- Blocklist module (cybercheck/blocklist.py). Additive only.
--
-- blocklisted / blocklist_expires_at already exist in 001_init.sql. This adds the manual exclusion
-- flag (set from the /blocklist dashboard page) and when the current (or last) listing started.
-- After an entry expires, blocklisted is false and blocklist_expires_at keeps the (past) expiry time,
-- so the domain is not listed again unless it is seen live again or a reviewer re-confirms it.

ALTER TABLE domains ADD COLUMN IF NOT EXISTS blocklist_excluded    boolean NOT NULL DEFAULT false;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS blocklist_excluded_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS blocklist_excluded_by text;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS blocklist_listed_at   timestamptz;

CREATE INDEX IF NOT EXISTS domains_blocklisted_idx ON domains (blocklist_listed_at) WHERE blocklisted;
