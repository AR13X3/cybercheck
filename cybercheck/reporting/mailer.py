"""Optional SMTP delivery of email reports a reviewer approved.

Off unless SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD and SMTP_FROM are all set. Port 465 uses
implicit TLS (SMTP_SSL); any other port must offer STARTTLS, otherwise nothing is sent. Certificates
are verified with the system CA store. smtplib is blocking, so it runs in a thread.

Only reviewer-approved drafts reach this module: nothing here decides to send by itself.
"""
from __future__ import annotations

import asyncio
import os
import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from .common import SendResult, clean_line, clean_text, valid_email

TIMEOUT_S = 30
MAX_BODY = 20000
MAX_ATTACHMENT = 3_000_000


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    sender: str = ""


def smtp_from_env(env=None) -> tuple[SmtpConfig | None, str]:
    """(config, '') when SMTP is fully configured, else (None, why it is off)."""
    env = os.environ if env is None else env
    names = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM")
    vals = {n: (env.get(n) or "").strip() for n in names}
    missing = [n for n in names if not vals[n]]
    if missing:
        return None, "SMTP is off: " + ", ".join(missing) + (" is" if len(missing) == 1 else " are") + " not set"
    try:
        port = int(vals["SMTP_PORT"])
    except ValueError:
        return None, "SMTP is off: SMTP_PORT is not a number"
    if not 0 < port < 65536:
        return None, "SMTP is off: SMTP_PORT is out of range"
    if not valid_email(vals["SMTP_FROM"]):
        return None, "SMTP is off: SMTP_FROM is not a valid email address"
    if any(c in vals["SMTP_HOST"] for c in " /\\@"):
        return None, "SMTP is off: SMTP_HOST is not a host name"
    return SmtpConfig(vals["SMTP_HOST"], port, vals["SMTP_USER"], vals["SMTP_PASSWORD"], vals["SMTP_FROM"]), ""


def build_message(cfg: SmtpConfig, to: str, subject: str, body: str, reply_to: str | None = None,
                  attachment: tuple[str, bytes] | None = None) -> EmailMessage:
    if not valid_email(to):
        raise ValueError("invalid recipient address")
    msg = EmailMessage()
    msg["From"] = cfg.sender
    msg["To"] = to
    if reply_to and valid_email(reply_to) and reply_to.lower() != cfg.sender.lower():
        msg["Reply-To"] = reply_to
    msg["Subject"] = clean_line(subject, 200) or "Phishing report"
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=cfg.sender.rsplit("@", 1)[1])
    msg.set_content(clean_text(body, MAX_BODY), subtype="plain", charset="utf-8")
    if attachment and attachment[1] and len(attachment[1]) <= MAX_ATTACHMENT:
        name = clean_line(attachment[0], 80).replace("/", "_") or "screenshot.jpg"
        msg.add_attachment(attachment[1], maintype="image", subtype="jpeg", filename=name)
    return msg


def _send_sync(cfg: SmtpConfig, msg: EmailMessage) -> None:
    ctx = ssl.create_default_context()
    if cfg.port == 465:
        with smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=TIMEOUT_S, context=ctx) as s:
            s.ehlo()
            s.login(cfg.user, cfg.password)
            s.send_message(msg)
        return
    with smtplib.SMTP(cfg.host, cfg.port, timeout=TIMEOUT_S) as s:
        s.ehlo()
        if not s.has_extn("starttls"):
            raise _NoTls("the SMTP server does not offer STARTTLS; not sending in clear text")
        s.starttls(context=ctx)
        s.ehlo()
        s.login(cfg.user, cfg.password)
        s.send_message(msg)


class _NoTls(Exception):
    pass


def classify_error(e: Exception) -> SendResult:
    """Permanent errors (refused recipient, auth failure, no TLS, 5xx) are not retried."""
    name = type(e).__name__
    if isinstance(e, _NoTls):
        return SendResult(ok=False, permanent=True, error=str(e))
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        return SendResult(ok=False, permanent=True, error="recipient refused by the SMTP server")
    if isinstance(e, smtplib.SMTPAuthenticationError):
        return SendResult(ok=False, permanent=True, error="SMTP login failed (check SMTP_USER / SMTP_PASSWORD)")
    if isinstance(e, smtplib.SMTPResponseException):
        code = int(getattr(e, "smtp_code", 0) or 0)
        text = clean_line(getattr(e, "smtp_error", b"").decode("utf-8", "replace")
                          if isinstance(getattr(e, "smtp_error", None), bytes) else getattr(e, "smtp_error", ""), 200)
        return SendResult(ok=False, permanent=500 <= code < 600, http_status=None,
                          error=f"SMTP {code}: {text}".strip())
    if isinstance(e, ssl.SSLCertVerificationError):
        return SendResult(ok=False, permanent=True, error="SMTP server certificate could not be verified")
    if isinstance(e, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout,
                      TimeoutError, ConnectionError, OSError, smtplib.SMTPException)):
        return SendResult(ok=False, error=f"{name}: {clean_line(e, 200)}")
    return SendResult(ok=False, error=f"{name}: {clean_line(e, 200)}")


async def send(cfg: SmtpConfig, to: str, subject: str, body: str, reply_to: str | None = None,
               attachment: tuple[str, bytes] | None = None) -> SendResult:
    try:
        msg = build_message(cfg, to, subject, body, reply_to, attachment)
    except ValueError as e:
        return SendResult(ok=False, permanent=True, error=str(e))
    sent = {"to": to, "from": cfg.sender, "subject": msg["Subject"], "message_id": msg["Message-ID"],
            "attachment": bool(attachment and attachment[1])}
    try:
        await asyncio.to_thread(_send_sync, cfg, msg)
    except Exception as e:  # noqa: BLE001 - every SMTP failure becomes a recorded attempt
        r = classify_error(e)
        r.sent = sent
        return r
    return SendResult(ok=True, external_id=msg["Message-ID"], response={"smtp": "accepted"}, sent=sent)
