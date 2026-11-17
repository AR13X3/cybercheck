"""Reporting settings.

From cybercheck.config.settings() (core): REPORTING_MODE, AUTO_REPORT_MIN_FINAL_SCORE, REPORT_RATE_PER_HOUR,
REPORTER_EMAIL, NETCRAFT_API_KEY (unused: Netcraft's report API v3 takes no key), CYBERCHECK_DATA_DIR.

Read here (module settings, documented in docs/REPORTING.md):
  REPORTER_NAME                  name in report signatures (default "CyberCheck")
  REPORT_CHANNEL_MIN_INTERVAL_S  minimum seconds between two sends on the same channel (60)
  REPORT_LOOKBACK_DAYS           confirmed domains are planned for reporting this long after confirmation (30)
  REPORT_MAX_ATTEMPTS            delivery attempts before a report is marked failed (5)
  REPORT_AI_DRAFTS               use the AI to write email drafts (true; template when AI is unavailable)
  REPORT_AI_DRAFTS_PER_RUN       AI drafts per job run (3)
  REPORT_MANUAL_CHANNELS         manual web-form checklist channels to create (see channels.MANUAL)
  NETCRAFT_ENABLED               false turns the Netcraft API channel off (true)
  NETCRAFT_TEST                  true sends to Netcraft's development endpoint /api/v3/test (false)
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM   optional SMTP for approved email drafts
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .common import valid_email
from .mailer import SmtpConfig, smtp_from_env

log = logging.getLogger("cybercheck.reporting")

MODES = ("off", "review", "auto")
# Automatic sends (REPORTING_MODE=auto) never happen below this combined score, whatever
# AUTO_REPORT_MIN_FINAL_SCORE says: a typo like 9 instead of 90 must not start mass reporting. 90 because
# cybercheck/confidence.py caps final_score at NO_EVIDENCE_CAP (89) unless the domain's own page asks for
# credentials and the AI says phishing (contract with the AI module; hard-coded, not imported, on purpose).
HARD_MIN_AUTO_SCORE = 90
SANDBOX_MAX_AGE_DAYS = 30
SANDBOX_FILE = "sandbox_verified.json"


def _env(name: str, env=None) -> str:
    return ((os.environ if env is None else env).get(name) or "").strip()


def _int(name: str, default: int, lo: int, hi: int, env=None) -> int:
    v = _env(name, env)
    try:
        n = int(v) if v else default
    except ValueError:
        log.warning("ignoring bad %s=%r", name, v)
        n = default
    return max(lo, min(hi, n))


def _bool(name: str, default: bool, env=None) -> bool:
    v = _env(name, env).lower()
    return default if not v else v in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class ReportConfig:
    mode: str = "review"
    mode_warning: str = ""
    min_final_score: int = 90                 # effective threshold for automatic reports
    configured_min_final_score: int = 90
    rate_per_hour: int = 10
    channel_min_interval_s: int = 60
    reporter_email: str = ""                  # valid address or ""
    reporter_email_warning: str = ""
    reporter_name: str = "CyberCheck"
    netcraft_enabled: bool = True
    netcraft_test: bool = False
    netcraft_api_key_set: bool = False
    smtp: SmtpConfig | None = None
    smtp_reason: str = "SMTP is off"
    lookback_days: int = 30
    max_attempts: int = 5
    ai_drafts: bool = True
    ai_drafts_per_run: int = 3
    manual_channels: frozenset = field(default_factory=frozenset)
    data_dir: Path = Path("data")

    @property
    def sandbox_file(self) -> Path:
        return self.data_dir / SANDBOX_FILE

    @property
    def netcraft_ready(self) -> bool:
        return self.netcraft_enabled and bool(self.reporter_email)

    def netcraft_reason(self) -> str:
        if not self.netcraft_enabled:
            return "turned off with NETCRAFT_ENABLED=false"
        if not self.reporter_email:
            return ("needs a reporter identity: set REPORTER_EMAIL (Netcraft requires the email address its "
                    "analysis result is sent to; use a role mailbox on a domain you own)")
        return ""


def load_config(s=None, env=None) -> ReportConfig:
    """s: a cybercheck.config.Settings (default settings()); env: mapping for module settings (default os.environ)."""
    if s is None:
        from ..config import settings
        s = settings()
    from .channels import MANUAL, default_manual_channels
    mode = (s.reporting_mode or "review").strip().lower()
    mode_warning = ""
    if mode not in MODES:
        mode_warning = f"REPORTING_MODE={s.reporting_mode!r} is not off, review or auto; using review"
        mode = "review"
    configured = int(s.auto_report_min_final_score)
    reporter = (s.reporter_email or "").strip()
    reporter_warning = ""
    if reporter and not valid_email(reporter):
        reporter_warning = "REPORTER_EMAIL is not a valid email address; channels that need it stay off"
        reporter = ""
    manual_raw = _env("REPORT_MANUAL_CHANNELS", env)
    if manual_raw:
        wanted = {c.strip() for c in manual_raw.split(",") if c.strip()}
        unknown = wanted - set(MANUAL) - {"brand_form"}
        if unknown:
            log.warning("REPORT_MANUAL_CHANNELS: unknown channels ignored: %s", ", ".join(sorted(unknown)))
        manual = frozenset(wanted - unknown)
    else:
        manual = default_manual_channels()
    smtp, smtp_reason = smtp_from_env(os.environ if env is None else env)
    return ReportConfig(
        mode=mode, mode_warning=mode_warning,
        # above 100 is kept as is: no score can reach it, so it switches automatic sends off
        min_final_score=max(HARD_MIN_AUTO_SCORE, configured),
        configured_min_final_score=configured,
        rate_per_hour=max(0, min(1000, int(s.report_rate_per_hour))),
        channel_min_interval_s=_int("REPORT_CHANNEL_MIN_INTERVAL_S", 60, 5, 86400, env),
        reporter_email=reporter, reporter_email_warning=reporter_warning,
        reporter_name=(_env("REPORTER_NAME", env) or "CyberCheck")[:80],
        netcraft_enabled=_bool("NETCRAFT_ENABLED", True, env),
        netcraft_test=_bool("NETCRAFT_TEST", False, env),
        netcraft_api_key_set=bool((s.netcraft_api_key or "").strip()),
        smtp=smtp, smtp_reason=smtp_reason or "",
        lookback_days=_int("REPORT_LOOKBACK_DAYS", 30, 1, 365, env),
        max_attempts=_int("REPORT_MAX_ATTEMPTS", 5, 1, 20, env),
        ai_drafts=_bool("REPORT_AI_DRAFTS", True, env),
        ai_drafts_per_run=_int("REPORT_AI_DRAFTS_PER_RUN", 3, 0, 50, env),
        manual_channels=manual,
        data_dir=Path(s.data_dir),
    )
