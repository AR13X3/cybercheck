"""Writing scored hits into the domains table (shared by CT ingest, CZDS, the bot and manual adds)."""
from __future__ import annotations

import re
from datetime import timedelta

from .config import settings
from .db import add_event, jsonb
from .scoring import Hit

UPSERT = """
INSERT INTO domains (registered_domain, unicode_domain, tld, brand_id, score, tier, reasons, hostnames,
                     source, issuer, ct_log, next_check_at, watch_until)
VALUES (%(registered_domain)s, %(unicode_domain)s, %(tld)s, %(brand_id)s, %(score)s, %(tier)s, %(reasons)s,
        ARRAY[%(hostname)s], %(source)s, %(issuer)s, %(ct_log)s, now(), now() + %(watch)s)
ON CONFLICT (registered_domain) DO UPDATE SET
    last_seen = now(),
    sightings = domains.sightings + 1,
    -- a CT certificate makes a CZDS-found domain public CT data (released from the CZDS blocklist hold).
    -- Bot-found rows stay 'bot': their score may come from a made-up forwarded hostname (GREATEST below),
    -- so a later CT sighting must not make that score count for other hostnames (cybercheck/bot.py).
    source = CASE WHEN EXCLUDED.source = 'ct' AND domains.source = 'czds' THEN 'ct'
                  ELSE domains.source END,
    hostnames = CASE WHEN %(hostname)s = ANY(domains.hostnames) OR cardinality(domains.hostnames) >= 50
                     THEN domains.hostnames ELSE domains.hostnames || %(hostname)s END,
    reasons   = CASE WHEN EXCLUDED.score > domains.score THEN EXCLUDED.reasons ELSE domains.reasons END,
    brand_id  = CASE WHEN EXCLUDED.score > domains.score THEN EXCLUDED.brand_id ELSE domains.brand_id END,
    tier      = CASE WHEN EXCLUDED.score > domains.score THEN EXCLUDED.tier ELSE domains.tier END,
    score     = GREATEST(domains.score, EXCLUDED.score),
    -- new certificate on a domain we watch: re-check soon and extend the watch window
    next_check_at = LEAST(COALESCE(domains.next_check_at, now()), now() + interval '10 minutes'),
    watch_until   = GREATEST(domains.watch_until, now() + %(watch)s),
    -- a new certificate after a takedown means the domain is back: start tracking it again
    takedown_at     = NULL,
    takedown_signal = NULL
RETURNING id, (xmax = 0) AS inserted, score,
          (SELECT takedown_at FROM domains d2 WHERE d2.id = domains.id) AS old_takedown_at
"""


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def cert_text(value, limit: int = 200) -> str | None:
    """issuer / ct_log come from certificates and CT log metadata (untrusted). Postgres text and jsonb cannot
    hold NUL, so one in an issuer name would make the hit unstorable: drop control characters, cap the length,
    and ignore anything that is not a string."""
    if not isinstance(value, str):
        return None
    return " ".join(_CTRL.sub(" ", value).split())[:limit] or None


_SURROGATES = re.compile("[\ud800-\udfff]")


def pg_unicode(value):
    """A crafted xn-- label can punycode-decode to a lone UTF-16 surrogate, which then sits in hit.unicode_domain
    and in a "mixed scripts" reason. It is not valid Unicode: psycopg cannot encode it for a text column and
    Postgres jsonb rejects its escape, so the hit would be unstorable. Replace each with U+FFFD (also inside
    lists and dicts); any other value is returned unchanged."""
    if isinstance(value, str):
        return _SURROGATES.sub("\ufffd", value)
    if isinstance(value, list):
        return [pg_unicode(v) for v in value]
    if isinstance(value, dict):
        return {pg_unicode(k): pg_unicode(v) for k, v in value.items()}
    return value


async def store_hit(conn, hit: Hit, source: str = "ct", issuer: str | None = None, ct_log: str | None = None) -> tuple[int, bool]:
    issuer, ct_log = cert_text(issuer), cert_text(ct_log)
    row = await (await conn.execute(UPSERT, {
        "registered_domain": hit.registered_domain, "unicode_domain": pg_unicode(hit.unicode_domain), "tld": hit.tld,
        "brand_id": hit.brand_id, "score": hit.score, "tier": hit.tier, "reasons": jsonb(pg_unicode(hit.reasons)),
        "hostname": hit.hostname, "source": source, "issuer": issuer, "ct_log": ct_log,
        "watch": timedelta(days=settings().watch_days),
    })).fetchone()
    if not row["inserted"] and row.get("old_takedown_at") is not None:
        await add_event(conn, row["id"], "reappeared", {"hostname": hit.hostname, "taken_down_at": str(row["old_takedown_at"])})
    if row["inserted"]:
        await add_event(conn, row["id"], "first_seen", {
            "source": source, "hostname": hit.hostname, "score": hit.score, "tier": hit.tier,
            "brand": hit.brand_id, "issuer": issuer, "ct_log": ct_log})
    return row["id"], row["inserted"]
