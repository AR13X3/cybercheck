-- enrich module (DNS / RDAP / ASN, re-check schedule, takedown detection).
-- Additive only.

-- Private per-domain state of the enrich job, written only by cybercheck/enrich.py:
--   dns          last definitive DNS state (resolves | nxdomain | no_answer), ignoring lookup errors
--   dns_err      consecutive DNS lookup errors
--   resolved_at  first time CyberCheck saw the domain resolve (ISO timestamp)
--   rdap_at      last RDAP lookup that got an answer (or found the TLD has no RDAP)
--   rdap_fail / rdap_fail_at   consecutive RDAP errors, for back-off
--   ip           primary IP the asn / hosting columns describe
--   pending      takedown signals seen on the latest checks, {"nxdomain": {"since": ts, "n": 1}, ...}
ALTER TABLE domains ADD COLUMN IF NOT EXISTS enrich_state jsonb NOT NULL DEFAULT '{}';

-- Picking due checks: confirmed / reported domains are not 'open', so domains_next_check_idx misses them.
CREATE INDEX IF NOT EXISTS domains_enrich_due_idx ON domains (next_check_at)
    WHERE takedown_at IS NULL AND next_check_at IS NOT NULL;
