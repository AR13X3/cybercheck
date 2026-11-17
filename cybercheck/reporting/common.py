"""Small helpers shared by the reporting module (no database or network access here)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

UTC = timezone.utc

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})"
                      r"(?:\.[A-Za-z0-9-]{1,63})+$")
# Unpaired surrogates (json.loads turns a lone "\ud83d" escape into one) cannot be encoded as UTF-8: Postgres
# text refuses them, and so do jsonb strings. Any surrogate in a Python str is unpaired.
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩\ud800-\udfff]")
_LINE_CTRL = re.compile(r"[\x00-\x1f\x7f  ​-‏‪-‮⁦-⁩\ud800-\udfff]+")


def utcnow() -> datetime:
    return datetime.now(UTC)


def aware(ts):
    if isinstance(ts, datetime) and ts.tzinfo is None:
        return ts.replace(tzinfo=UTC)
    return ts


def fmt_ts(ts) -> str | None:
    """'2026-11-15 03:04 UTC' (None stays None)."""
    ts = aware(ts)
    if not isinstance(ts, datetime):
        return None
    return ts.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def fmt_date(ts) -> str | None:
    ts = aware(ts)
    if not isinstance(ts, datetime):
        return None
    return ts.astimezone(UTC).strftime("%Y-%m-%d")


def valid_email(value) -> bool:
    return isinstance(value, str) and len(value) <= 254 and bool(EMAIL_RE.match(value))


def clean_line(value, limit: int = 200) -> str:
    """One line of plain text: no control, bidi or line-break characters (safe for mail headers)."""
    if value is None:
        return ""
    return " ".join(_LINE_CTRL.sub(" ", str(value)).split())[:limit]


def clean_text(value, limit: int = 20000) -> str:
    """Multi-line plain text: control and bidi characters removed, CRLF normalised, length capped."""
    if value is None:
        return ""
    s = str(value).replace("\r\n", "\n").replace("\r", "\n")
    return _CTRL.sub("", s)[:limit]


_NOT_PG = re.compile(r"[\x00\ud800-\udfff]")


def pg_text(value: str) -> str:
    """A string Postgres can store: text and jsonb cannot hold NUL (jsonb: "unsupported Unicode escape
    sequence"), and an unpaired surrogate cannot be encoded as UTF-8 at all."""
    return _NOT_PG.sub(lambda m: "" if m.group() == "\x00" else "\ufffd", value)


def _pg_json(value):
    if isinstance(value, str):
        return pg_text(value)
    if isinstance(value, list):
        return [_pg_json(v) for v in value]
    if isinstance(value, dict):
        return {pg_text(k): _pg_json(v) for k, v in value.items()}
    return value


def json_safe(value):
    """Round-trip through JSON so datetimes and other objects become plain strings, and strip what jsonb
    cannot hold (NUL, unpaired surrogates). Everything the module writes to a jsonb column goes through here,
    including channel responses (Netcraft JSON, SMTP errors) that a fake database would accept as they are."""
    return _pg_json(json.loads(json.dumps(value, default=str)))


@dataclass
class SendResult:
    """Outcome of one delivery attempt to a channel."""
    ok: bool
    permanent: bool = False             # do not retry (bad request, refused recipient, ...)
    retry_after: float | None = None    # seconds the channel asked us to wait (HTTP 429 Retry-After)
    http_status: int | None = None
    external_id: str | None = None      # submission id at the channel (Netcraft uuid, SMTP Message-ID)
    response: dict = field(default_factory=dict)
    error: str | None = None
    sent: dict = field(default_factory=dict)   # what was sent, for the audit trail (no binary data)
