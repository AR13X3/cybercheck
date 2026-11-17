-- fetch module: sandboxed page fetcher worker side (cybercheck/jobs/fetch.py, cybercheck/jobs/retention.py).
-- Additive only. The pages table itself is in 001_init.sql; the fetch job writes those columns and the
-- domains columns live_state / first_live_at / last_live_at / page_score (per docs/ARCHITECTURE.md).

-- Private per-domain state of the fetch job, written only by cybercheck/jobs/fetch.py:
--   n            number of completed fetch rounds
--   fail_since   ISO timestamp of the first failed fetch in the current run of failures
--   fail_count   consecutive failed fetches since fail_since
--   shots        {profile: {"sha": <screenshot sha256>, "path": <relative screenshot_path>}}  (last written snapshot)
--   htmls        {profile: {"sha": <html sha256>, "path": <relative html_path>}}               (last written html)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS fetch_state jsonb NOT NULL DEFAULT '{}';

-- When the fetch job should next fetch this domain. NULL means "as soon as it is otherwise eligible"
-- (a domain that has never been fetched) or "stop" after the fetch job clears it past the watch window.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS next_fetch_at timestamptz;

-- Due scan of the fetch job: resolving review/high (or high-score) domains that are not taken down.
CREATE INDEX IF NOT EXISTS domains_fetch_due_idx ON domains (next_fetch_at)
    WHERE takedown_at IS NULL AND dns_state = 'resolves';

-- Retention scan (cybercheck/jobs/retention.py): snapshots whose files are due for deletion.
CREATE INDEX IF NOT EXISTS pages_retain_idx ON pages (retain_until)
    WHERE retain_until IS NOT NULL AND NOT is_evidence;
