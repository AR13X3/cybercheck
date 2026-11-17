-- Telegram forwarding bot (cybercheck/bot.py, dashboard page /bot).
-- No message text is ever stored: only chat records with counters, and the domains found per message.

-- One row per Telegram chat that has talked to the bot.
CREATE TABLE IF NOT EXISTS bot_chats (
    chat_id            bigint      PRIMARY KEY,
    chat_type          text,                              -- private | group | supergroup
    title              text,                              -- group title, or the user's first name in a private chat
    username           text,
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('pending', 'allowed', 'blocked')),
    status_changed_at  timestamptz,
    status_by          text,                              -- dashboard user who allowed/blocked it
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    -- counters for one UTC day (reset by the bot when counter_day changes)
    counter_day        date,
    day_messages       int         NOT NULL DEFAULT 0,    -- checks today (BOT_DAILY_LIMIT_PER_CHAT)
    day_ai             int         NOT NULL DEFAULT 0,    -- AI explanations today (BOT_AI_DAILY_LIMIT_PER_CHAT)
    limit_notified     boolean     NOT NULL DEFAULT false,
    -- lifetime counters
    total_messages     int         NOT NULL DEFAULT 0,
    total_domains      int         NOT NULL DEFAULT 0,
    total_ai           int         NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS bot_chats_status_idx ON bot_chats (status, last_seen);

-- One row per checked message: when, which chat, and the domains found with the bot's verdicts.
-- Kept for 30 days (the bot deletes older rows).
CREATE TABLE IF NOT EXISTS bot_messages (
    id           bigserial   PRIMARY KEY,
    chat_id      bigint      NOT NULL REFERENCES bot_chats(chat_id) ON DELETE CASCADE,
    at           timestamptz NOT NULL DEFAULT now(),
    domains      text[]      NOT NULL DEFAULT '{}',   -- hostnames found (normalised, ASCII/punycode)
    registered   text[]      NOT NULL DEFAULT '{}',   -- registrable domain of each hostname (same order)
    verdicts     text[]      NOT NULL DEFAULT '{}',   -- confirmed | suspicious | official | shortener | not_flagged (same order)
    new_domains  int         NOT NULL DEFAULT 0,      -- how many were newly added to domains (source 'bot')
    ai_used      boolean     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS bot_messages_at_idx   ON bot_messages (at);
CREATE INDEX IF NOT EXISTS bot_messages_chat_idx ON bot_messages (chat_id, at);
