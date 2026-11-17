-- AI module: page verdicts, combined confidence bookkeeping, domain triage, call accounting.
-- Additive only.

-- Page verdicts (judge job). ai_judged_at is set once a page has been processed (judged, reused
-- from an identical snapshot, skipped, or given up on); ai_result holds the verdict or the reason.
ALTER TABLE pages ADD COLUMN IF NOT EXISTS ai_judged_at timestamptz;
ALTER TABLE pages ADD COLUMN IF NOT EXISTS ai_result jsonb;
CREATE INDEX IF NOT EXISTS pages_ai_pending_idx ON pages (fetched_at DESC)
    WHERE ai_judged_at IS NULL AND error IS NULL;

-- Combined confidence (final_score itself is in 001_init.sql)
ALTER TABLE domains ADD COLUMN IF NOT EXISTS final_reasons jsonb;     -- [{points, why}] adding up to final_score
ALTER TABLE domains ADD COLUMN IF NOT EXISTS final_score_at timestamptz;
ALTER TABLE domains ADD COLUMN IF NOT EXISTS final_basis text;        -- inputs of the last computation (recompute when they change)

-- Text-only triage of domains that have no page yet
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ai_triage jsonb;         -- {assessment, likely_target, reason, ai_call_id}
ALTER TABLE domains ADD COLUMN IF NOT EXISTS ai_triaged_at timestamptz;

-- Call accounting for the spending cap
ALTER TABLE ai_calls ADD COLUMN IF NOT EXISTS status text;            -- pending | ok | refusal | invalid | api_error | error | abandoned
ALTER TABLE ai_calls ADD COLUMN IF NOT EXISTS estimated_cost_usd numeric(12,6);
ALTER TABLE ai_calls ADD COLUMN IF NOT EXISTS duration_ms int;
ALTER TABLE ai_calls ADD COLUMN IF NOT EXISTS fallback_model text;    -- set when a server-side refusal fallback served the call
CREATE INDEX IF NOT EXISTS ai_calls_domain_idx ON ai_calls (domain_id, at);
CREATE INDEX IF NOT EXISTS ai_calls_pending_idx ON ai_calls (at) WHERE status = 'pending';
