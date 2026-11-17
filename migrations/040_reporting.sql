-- Reporting module (cybercheck/reporting/, job "report", dashboard page /reports). Additive only.
--
-- reports (001_init.sql) holds one row per domain and channel (UNIQUE (domain_id, channel)).
-- Statuses used by this module:
--   pending_review  email draft or manual web-form checklist item waiting for a reviewer
--   approved        queued for sending by the worker (automated channel, or an email a reviewer approved)
--   sending         claimed by the worker; a send is in flight
--   sent            sent (API / SMTP) or marked as sent / done by a reviewer
--   failed          gave up after retries, or a permanent error
--   rejected        a reviewer rejected or cancelled it (never revived automatically)
--   skipped         not sent because the domain no longer qualified (closed, taken down, rules changed)

ALTER TABLE reports ADD COLUMN IF NOT EXISTS kind            text;          -- api | email | manual
ALTER TABLE reports ADD COLUMN IF NOT EXISTS attempts        int  NOT NULL DEFAULT 0;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS next_attempt_at timestamptz;   -- queued items wait until then
ALTER TABLE reports ADD COLUMN IF NOT EXISTS last_attempt_at timestamptz;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS updated_at      timestamptz NOT NULL DEFAULT now();
ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_by     text;          -- dashboard user who approved / rejected / marked it
ALTER TABLE reports ADD COLUMN IF NOT EXISTS reviewed_at     timestamptz;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS sent_via        text;          -- api | smtp | manual
ALTER TABLE reports ADD COLUMN IF NOT EXISTS sent_by         text;          -- 'worker' or the reviewer who marked it sent
ALTER TABLE reports ADD COLUMN IF NOT EXISTS checked_at      timestamptz;   -- last status poll of the channel (Netcraft)

CREATE INDEX IF NOT EXISTS reports_queue_idx   ON reports (next_attempt_at) WHERE status = 'approved';
CREATE INDEX IF NOT EXISTS reports_sent_at_idx ON reports (sent_at DESC) WHERE status = 'sent';
CREATE INDEX IF NOT EXISTS reports_domain_idx  ON reports (domain_id);

-- Every outgoing request to a reporting channel (API call or SMTP delivery). The global hourly rate
-- limit (REPORT_RATE_PER_HOUR) and the per-channel minimum interval are counted from this table, so
-- failed attempts count too. Rows older than 180 days are deleted by the report job.
CREATE TABLE IF NOT EXISTS report_attempts (
    id           bigserial PRIMARY KEY,
    report_id    bigint      NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    channel      text        NOT NULL,
    via          text        NOT NULL,             -- api | smtp
    at           timestamptz NOT NULL DEFAULT now(),
    ok           boolean,                          -- null while in flight
    http_status  int,
    error        text,
    response     jsonb
);
CREATE INDEX IF NOT EXISTS report_attempts_at_idx      ON report_attempts (at);
CREATE INDEX IF NOT EXISTS report_attempts_channel_idx ON report_attempts (channel, at);

-- Candidate scans of the report job
CREATE INDEX IF NOT EXISTS domains_confirmed_changed_idx ON domains (status_changed_at) WHERE status = 'confirmed';
CREATE INDEX IF NOT EXISTS domains_auto_report_idx ON domains (final_score)
    WHERE status = 'open' AND ai_verdict = 'phishing' AND takedown_at IS NULL;
