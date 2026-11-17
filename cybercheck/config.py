"""Settings from environment variables (.env is loaded by docker compose / the CLI)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _int(name: str, default: int) -> int:
    v = _env(name)
    return int(v) if v else default


def _float(name: str, default: float) -> float:
    v = _env(name)
    return float(v) if v else default


def _bool(name: str, default: bool) -> bool:
    v = _env(name).lower()
    return default if not v else v in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    database_url: str
    watchlist_path: str
    data_dir: Path
    certstream_url: str
    web_host: str
    web_port: int
    web_public_hostnames: list[str]   # names a reverse proxy (e.g. `tailscale serve`) shows the browser
    store_threshold: int
    review_threshold: int
    high_threshold: int
    watch_days: int
    dns_resolvers: list[str]
    # AI
    anthropic_api_key: str
    ai_model: str
    ai_daily_budget_usd: float
    ai_monthly_budget_usd: float
    ai_enabled: bool
    # fetcher
    fetcher_url: str
    fetcher_token: str
    fetch_min_score: int
    fetch_concurrency: int
    # retention
    screenshot_retention_days: int
    # reporting
    reporting_mode: str          # off | review | auto
    auto_report_min_final_score: int
    report_rate_per_hour: int
    reporter_email: str
    netcraft_api_key: str
    # blocklist
    blocklist_min_final_score: int
    blocklist_days: int
    # czds
    czds_username: str
    czds_password: str
    czds_tlds: list[str]
    # bot
    telegram_bot_token: str
    telegram_allowed_chats: list[int]
    bot_daily_limit_per_chat: int


@lru_cache(maxsize=1)
def settings() -> Settings:
    data_dir = Path(_env("CYBERCHECK_DATA_DIR", str(ROOT / "data")))
    return Settings(
        database_url=_env("DATABASE_URL"),
        watchlist_path=_env("WATCHLIST_PATH", str(ROOT / "config" / "watchlist.yaml")),
        data_dir=data_dir,
        certstream_url=_env("CERTSTREAM_URL", "ws://127.0.0.1:8431/"),
        web_host=_env("WEB_HOST", "127.0.0.1"),
        web_port=_int("WEB_PORT", 8430),
        web_public_hostnames=[h.strip().lower() for h in _env("WEB_PUBLIC_HOSTNAME").split(",") if h.strip()],
        store_threshold=_int("STORE_THRESHOLD", 40),
        review_threshold=_int("REVIEW_THRESHOLD", 60),
        high_threshold=_int("HIGH_THRESHOLD", 75),
        watch_days=_int("WATCH_DAYS", 14),
        # unfiltered resolvers only: filtering ones (9.9.9.9) hide the phishing domains we track
        dns_resolvers=[r for r in _env("DNS_RESOLVERS", "1.1.1.1,9.9.9.10").split(",") if r],
        anthropic_api_key=_env("ANTHROPIC_API_KEY"),
        ai_model=_env("AI_MODEL", "claude-opus-5-5"),
        ai_daily_budget_usd=_float("AI_DAILY_BUDGET_USD", 1.60),
        ai_monthly_budget_usd=_float("AI_MONTHLY_BUDGET_USD", 48.0),
        ai_enabled=_bool("AI_ENABLED", True),
        fetcher_url=_env("FETCHER_URL", "http://127.0.0.1:8432"),
        fetcher_token=_env("FETCHER_TOKEN"),
        fetch_min_score=_int("FETCH_MIN_SCORE", 60),
        fetch_concurrency=_int("FETCH_CONCURRENCY", 2),
        screenshot_retention_days=_int("SCREENSHOT_RETENTION_DAYS", 60),
        reporting_mode=_env("REPORTING_MODE", "review"),
        auto_report_min_final_score=_int("AUTO_REPORT_MIN_FINAL_SCORE", 90),
        report_rate_per_hour=_int("REPORT_RATE_PER_HOUR", 10),
        reporter_email=_env("REPORTER_EMAIL"),
        netcraft_api_key=_env("NETCRAFT_API_KEY"),
        # Never below 90: confidence.NO_EVIDENCE_CAP (89) is the most a domain can score without credential
        # fields on its own page plus an AI phishing verdict, so 90+ always means two signals agree. Hard-coded
        # here (contract with cybercheck/confidence.py), not imported, so a lower setting can never undercut it.
        blocklist_min_final_score=max(90, _int("BLOCKLIST_MIN_FINAL_SCORE", 90)),
        blocklist_days=_int("BLOCKLIST_DAYS", 90),
        czds_username=_env("CZDS_USERNAME"),
        czds_password=_env("CZDS_PASSWORD"),
        czds_tlds=[t.strip().lower() for t in _env("CZDS_TLDS").split(",") if t.strip()],
        telegram_bot_token=_env("TELEGRAM_BOT_TOKEN"),
        telegram_allowed_chats=[int(c) for c in _env("TELEGRAM_ALLOWED_CHATS").replace(" ", ",").split(",") if c.strip().lstrip("-").isdigit()],
        bot_daily_limit_per_chat=_int("BOT_DAILY_LIMIT_PER_CHAT", 20),
    )
