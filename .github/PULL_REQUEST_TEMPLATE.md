## What and why

<!-- What does this change, and why? Link the issue if there is one ("Fixes #123"). -->

## Module(s)

<!-- core, enrich, fetch, ai, reporting, blocklist, czds, bot, ui, docs (see CONTRIBUTING.md). Call out any change to another module's or core files. -->

## Testing

- [ ] `python -m pytest -q` passes
- [ ] Integration tests pass (`scripts/it-postgres.sh start`, then `CYBERCHECK_IT_PG=... python -m pytest -q tests/integration`)
- [ ] New or changed behaviour has tests (a bug fix has a test that fails without it)
- [ ] Fetcher, VPN or firewall changes: `scripts/verify-sandbox.sh` passes on a real setup

## Checklist

- [ ] No secrets, private hostnames or IP addresses, real victim data or CZDS zone data in code, tests, docs or screenshots
- [ ] Watchlist change: every new official domain is verified on the brand's own site (source linked above), and `tests/test_scoring.py` has a regression test
- [ ] UI change: no inline `style`/`<style>`/`<script>`/`on*=`, no `|safe` or `Markup`, phishing URLs are not links, works without JavaScript
- [ ] No automated `.au` WHOIS/RDAP lookups, and no code outside `fetcher/` contacts flagged sites
- [ ] Reporting change: automatic sends only through channels that allow automated reports, and the score floors are unchanged
- [ ] New settings are documented and added to `.env.example`; migrations are additive and new

By submitting this pull request, I agree that my contribution is licensed under the AGPL-3.0 (see CONTRIBUTING.md).
