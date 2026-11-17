"""Reporting: get confirmed phishing domains blocked and taken down, without false positives.

Channels and the policy for each come from the fact-checked research (docs/research/au-reporting.*,
docs/research/intl-reporting.*). Overview and set-up: docs/REPORTING.md.

  channels.py  catalogue: automated (Netcraft API), email (registrar, host, brand mailbox), manual web forms
  evidence.py  page evidence, URLs on the reported domain only, sandbox verification file, report facts
  texts.py     neutral report wording (email drafts, form text, Netcraft reasons)
  netcraft.py  Netcraft Report API v3 client
  mailer.py    optional SMTP for reviewer-approved email drafts
  engine.py    planning, the rate-limited send queue, results (worker job "report")
  conf.py      settings
"""
from __future__ import annotations

from .conf import ReportConfig, load_config

__all__ = ["ReportConfig", "load_config"]
