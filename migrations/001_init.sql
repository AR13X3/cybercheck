-- CyberCheck core schema. Modules add their own numbered migrations (see docs/ARCHITECTURE.md).

CREATE TABLE IF NOT EXISTS domains (
    id                    bigserial PRIMARY KEY,
    registered_domain     text        NOT NULL UNIQUE,   -- eTLD+1 per the Public Suffix List (private section included)
    unicode_domain        text,                          -- decoded form when punycode is involved
    tld                   text        NOT NULL,          -- public suffix, e.g. 'top', 'com.au'
    brand_id              text,                          -- watchlist brand id of the best match
    score                 int         NOT NULL,          -- domain-name score 0-100 (max seen)
    tier                  text        NOT NULL,          -- watch | review | high (from score)
    reasons               jsonb       NOT NULL DEFAULT '[]',
    hostnames             text[]      NOT NULL DEFAULT '{}',  -- up to 50 hostnames seen under this domain
    sightings             int         NOT NULL DEFAULT 1,
    source                text        NOT NULL DEFAULT 'ct',  -- ct | czds | bot | manual
    first_seen            timestamptz NOT NULL DEFAULT now(),
    last_seen             timestamptz NOT NULL DEFAULT now(),
    issuer                text,
    ct_log                text,

    -- human review / lifecycle
    status                text        NOT NULL DEFAULT 'open',  -- open | confirmed | false_positive | benign
    status_changed_at     timestamptz,
    status_by             text,
    notes                 text,

    -- enrichment (worker: DNS / RDAP / ASN)
    dns_state             text        NOT NULL DEFAULT 'unknown', -- unknown | resolves | nxdomain | no_answer | error
    ips                   text[]      NOT NULL DEFAULT '{}',
    asn                   int,
    as_name               text,
    ip_country            text,
    registrar             text,
    registrar_iana_id     int,
    registrar_abuse_email text,
    hosting_abuse_email   text,
    rdap_status           text[]      NOT NULL DEFAULT '{}',
    registered_at         timestamptz,
    enriched_at           timestamptz,

    -- page checks (fetcher) and AI
    live_state            text        NOT NULL DEFAULT 'unknown', -- unknown | live | down | no_dns | blocked
    first_live_at         timestamptz,
    last_live_at          timestamptz,
    page_score            int,          -- 0-100 from page features
    ai_verdict            text,         -- phishing | suspicious | benign | parked | error | null
    ai_confidence         real,
    ai_brand              text,
    final_score           int,          -- combined confidence 0-100 (domain + page + AI)

    -- reporting / takedown
    reported_at           timestamptz,
    takedown_at           timestamptz,
    takedown_signal       text,         -- nxdomain | rdap_hold | http_gone | content_removed

    -- re-check schedule (watch suspicious domains for ~14 days)
    next_check_at         timestamptz   DEFAULT now(),
    check_count           int           NOT NULL DEFAULT 0,
    watch_until           timestamptz,

    -- blocklist
    blocklisted           boolean       NOT NULL DEFAULT false,
    blocklist_expires_at  timestamptz
);

CREATE INDEX IF NOT EXISTS domains_first_seen_idx ON domains (first_seen DESC);
CREATE INDEX IF NOT EXISTS domains_tier_idx       ON domains (tier, status);
CREATE INDEX IF NOT EXISTS domains_next_check_idx ON domains (next_check_at) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS domains_brand_idx      ON domains (brand_id);

-- Timeline of everything that happened to a domain (first seen, went live, AI verdict, reported, taken down, labelled...)
CREATE TABLE IF NOT EXISTS domain_events (
    id         bigserial PRIMARY KEY,
    domain_id  bigint      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    kind       text        NOT NULL,
    detail     jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS domain_events_domain_idx ON domain_events (domain_id, at);
CREATE INDEX IF NOT EXISTS domain_events_kind_idx   ON domain_events (kind, at);

-- Raw results of each re-check (dns | rdap | asn | http | page)
CREATE TABLE IF NOT EXISTS checks (
    id         bigserial PRIMARY KEY,
    domain_id  bigint      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    at         timestamptz NOT NULL DEFAULT now(),
    kind       text        NOT NULL,
    ok         boolean,
    result     jsonb       NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS checks_domain_idx ON checks (domain_id, at);

-- Page snapshots from the sandboxed fetcher
CREATE TABLE IF NOT EXISTS pages (
    id                  bigserial PRIMARY KEY,
    domain_id           bigint      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    fetched_at          timestamptz NOT NULL DEFAULT now(),
    url                 text        NOT NULL,
    final_url           text,
    http_status         int,
    title               text,
    egress_ip           text,
    user_agent_profile  text,          -- desktop | mobile
    has_password_field  boolean,
    has_otp_field       boolean,
    has_card_field      boolean,
    form_actions        text[]      NOT NULL DEFAULT '{}',
    external_form_post  boolean,
    brand_mentions      text[]      NOT NULL DEFAULT '{}',
    text_excerpt        text,
    features            jsonb       NOT NULL DEFAULT '{}',
    html_sha256         text,
    html_path           text,
    screenshot_path     text,
    screenshot_sha256   text,
    error               text,
    is_evidence         boolean     NOT NULL DEFAULT false,  -- kept past retention (confirmed phishing)
    retain_until        timestamptz
);
CREATE INDEX IF NOT EXISTS pages_domain_idx ON pages (domain_id, fetched_at);

-- Every AI call, for the spending cap and audit
CREATE TABLE IF NOT EXISTS ai_calls (
    id                  bigserial PRIMARY KEY,
    at                  timestamptz NOT NULL DEFAULT now(),
    purpose             text        NOT NULL,   -- page_judge | domain_triage | report_draft | bot | watchlist
    domain_id           bigint      REFERENCES domains(id) ON DELETE SET NULL,
    page_id             bigint      REFERENCES pages(id) ON DELETE SET NULL,
    model               text        NOT NULL,
    input_tokens        int         NOT NULL DEFAULT 0,
    output_tokens       int         NOT NULL DEFAULT 0,
    cache_read_tokens   int         NOT NULL DEFAULT 0,
    cache_write_tokens  int         NOT NULL DEFAULT 0,
    cost_usd            numeric(12,6) NOT NULL DEFAULT 0,
    stop_reason         text,
    result              jsonb,
    error               text
);
CREATE INDEX IF NOT EXISTS ai_calls_at_idx ON ai_calls (at);

-- Outgoing reports (automatic or drafted for human approval)
CREATE TABLE IF NOT EXISTS reports (
    id           bigserial PRIMARY KEY,
    domain_id    bigint      NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    channel      text        NOT NULL,     -- netcraft | registrar_abuse | hosting_abuse | brand:<id> | scamwatch | ...
    status       text        NOT NULL,     -- draft | pending_review | approved | sent | failed | rejected | skipped
    auto         boolean     NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz,
    payload      jsonb       NOT NULL DEFAULT '{}',
    response     jsonb,
    error        text,
    external_id  text,
    UNIQUE (domain_id, channel)
);
CREATE INDEX IF NOT EXISTS reports_status_idx ON reports (status, created_at);

-- Per-minute stream counters for the dashboard
CREATE TABLE IF NOT EXISTS ingest_stats (
    minute     timestamptz NOT NULL,
    source     text        NOT NULL DEFAULT 'ct',
    certs      int         NOT NULL DEFAULT 0,
    hostnames  int         NOT NULL DEFAULT 0,
    scored     int         NOT NULL DEFAULT 0,
    hits       int         NOT NULL DEFAULT 0,
    PRIMARY KEY (minute, source)
);

-- Small key/value store for module state (czds cursors, last blocklist build, ...)
CREATE TABLE IF NOT EXISTS kv (
    key        text PRIMARY KEY,
    value      jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
