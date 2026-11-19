# Contributing to CyberCheck

Thanks for helping. CyberCheck finds phishing sites that impersonate Australian organisations and helps
get them taken down. Mistakes in it can get a legitimate website reported, or let a phishing page reach
the machine it runs on, so this guide has more rules than most. Please read it before your first pull
request.

By taking part you agree to follow the [code of conduct](CODE_OF_CONDUCT.md). Security problems go
through [SECURITY.md](SECURITY.md), never a public issue.

## Development setup

You need Python 3.13 (the version in the `Dockerfile`), Docker for the integration tests, and git.

```bash
git clone https://github.com/AR13X3/cybercheck.git
cd cybercheck
python3.13 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

`requirements.txt` is generated from `requirements.in` with `uv pip compile` and pins every package.
To add or upgrade a dependency, edit `requirements.in`, regenerate the lock file with the command at
the top of `requirements.txt`, and say why in the pull request. The fetcher has its own pinned
`fetcher/requirements.txt`.

You do not need a CT stream, an AI key or a VPN to work on most of the code: the tests mock the network.
To run the whole stack locally, follow the [README quick start](README.md#quick-start).

## Running the tests

Unit tests run without network or database:

```bash
.venv/bin/python -m pytest -q
```

Integration tests run against a throwaway Postgres in Docker (`127.0.0.1:55432`, data in tmpfs, gone when
stopped). Each test module gets its own freshly migrated database:

```bash
./scripts/it-postgres.sh start
CYBERCHECK_IT_PG=postgresql://postgres:cybercheck-it@127.0.0.1:55432/postgres \
  .venv/bin/python -m pytest -q tests/integration
./scripts/it-postgres.sh stop
```

`tests/integration/conftest.py` refuses any `CYBERCHECK_IT_PG` that is not on `127.0.0.1:55432`, so the
tests can never drop tables in a real database. Keep that guard.

CI (`.github/workflows/ci.yml`) runs both suites on every pull request. A pull request needs green CI
before it is merged.

## Developing on Windows

CyberCheck runs on Linux, and CI tests it on Linux. You can still write code and run most of the unit
tests on Windows 10 or 11. The commands below are for PowerShell.

**1. Install Python 3.13 and git** with `winget` (no administrator rights needed for Python):

```powershell
winget install --id Python.Python.3.13 -e --scope user
winget install --id Git.Git -e
```

Then **open a new terminal**. Until you do, `python` may open the Microsoft Store instead, because
Windows ships a placeholder `python` command. Check with `py -3.13 --version`.

If this is your first time using git on this computer, tell it who you are, or it will refuse to commit.
Your commits are public, so you can use the private `noreply` address from your GitHub email settings:

```powershell
git config --global user.name "Your Name"
git config --global user.email "12345678+username@users.noreply.github.com"
```

**2. Clone and create the virtual environment.** On Windows the venv's programs are in `.venv\Scripts\`,
not `.venv/bin/`:

```powershell
git clone https://github.com/AR13X3/cybercheck.git
cd cybercheck
py -3.13 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

You do not need to activate the venv: calling `.venv\Scripts\python` directly is enough, and it avoids
PowerShell's execution policy, which on many Windows installs blocks `.venv\Scripts\Activate.ps1`.

**3. Run the unit tests** in UTF-8 mode, because Windows otherwise reads text files in a legacy code page:

```powershell
$env:PYTHONUTF8 = "1"
.venv\Scripts\python -m pytest -q --ignore=tests/integration --continue-on-collection-errors
```

`--continue-on-collection-errors` is needed because, on native Windows, some test files currently cannot
even be loaded, and without it pytest stops before running anything. These unit tests fail for Windows
reasons, not because of your change:

- `cybercheck/czds.py` imports `fcntl`, which only exists on Linux and macOS, so the test files that
  import the dashboard or the CZDS code (`test_czds.py`, `test_web.py` and most `test_ui_*.py`) cannot
  load, and a few tests elsewhere that import them fail.
- On Windows, Python makes the socket pair inside every asyncio event loop by connecting to
  `127.0.0.1`. The "no network in tests" guards in `test_reporting.py` and `test_enrich.py` see that as
  a network connection and fail the test.
- Two tests in `test_blocklist.py` check Unix file permissions, which Windows does not have.

Run the tests for the module you change and compare with a run on unchanged `main`; anything that fails
only with your change is yours to fix. CI runs the whole suite on Linux for every pull request.

**4. For a full test run, and for the integration tests, use WSL 2.** Install it with `wsl --install`
(this needs administrator rights and a restart), then follow the Linux instructions above inside the
Ubuntu terminal. Clone the repository inside WSL (for example in `~/cybercheck`) rather than using the
Windows copy under `/mnt/c`: it is much faster, and the shell scripts keep their Linux line endings. The
integration tests also need Docker in WSL, either Docker Engine installed in Ubuntu or Docker Desktop
with WSL integration turned on.

**Line endings.** Git for Windows converts line endings to CRLF when it checks files out
(`core.autocrlf=true`) and back to LF when you commit, so your commits stay correct. Files in the Windows
checkout, such as the scripts in `scripts/`, have CRLF endings and will not run in Linux or in Docker
from there; use the WSL clone for that.

## Code style

There is no formatter or linter configuration yet; match the code around you:

- `from __future__ import annotations` and type hints on public functions.
- A module docstring that says what the module does and the rules it keeps, and comments that explain
  **why**, especially for security decisions and thresholds. Read a few modules (for example
  `cybercheck/jobs/retention.py` or `cybercheck/confidence.py`) to see the tone.
- Lines up to about 120 characters.
- Database access through `cybercheck/db.py` (psycopg 3, parameterised queries only; never build SQL
  from strings with values in them). Settings from environment variables; a module that needs a new
  setting reads `os.environ` itself, documents it, and adds it (commented, with its default) to
  `.env.example`.
- Plain, specific wording in the UI, docs and logs. British/Australian spelling in user-facing text is
  welcome but not required.
- Every bug fix comes with a test that fails without it. New features come with tests.
- Small, focused pull requests with a clear description are reviewed fastest.

## Module map

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) has the full contracts. In short, each part of the code has
an owner module, and changes to another module's files or to core files should be called out in the pull
request description:

| Module | Files | Tests |
|---|---|---|
| core | `cybercheck/config.py`, `db.py`, `scoring.py`, `normalize.py`, `store.py`, `ingest.py`, `worker.py`, `__main__.py`, `jobs/housekeeping.py`, `web/app.py`, `web/common.py`, `config/` | `test_scoring.py`, `test_ingest.py`, `test_web.py` |
| enrich | `cybercheck/enrich.py`, `jobs/enrich.py`, `migrations/010_*` | `test_enrich.py` |
| fetch | `fetcher/`, `cybercheck/fetch_client.py`, `pagefeatures.py`, `jobs/fetch.py`, `jobs/retention.py`, `scripts/verify-sandbox.sh`, `scripts/host-firewall.sh`, `migrations/020_*` | `test_fetch.py`, `test_pagefeatures.py` |
| ai | `cybercheck/ai/`, `confidence.py`, `jobs/judge.py`, `web/pages_ai.py`, `migrations/030_*` | `test_ai.py`, `test_confidence.py` |
| reporting | `cybercheck/reporting/`, `jobs/report.py`, `web/pages_reports.py`, `web/pages_takedown.py`, `migrations/040_*`, `docs/research/*reporting*` | `test_reporting.py` |
| blocklist | `cybercheck/blocklist.py`, `jobs/blocklist.py`, `web/pages_blocklist.py`, `scripts/publish-blocklist.sh`, `migrations/050_*` | `test_blocklist.py` |
| czds | `cybercheck/czds.py`, `jobs/czds.py`, `web/pages_czds.py`, `migrations/060_*` | `test_czds.py` |
| bot | `cybercheck/bot.py`, `web/pages_bot.py`, `migrations/070_*` | `test_bot.py` |
| ui | `cybercheck/web/templates/`, `web/static/`, `web/pages_live.py`, [docs/UI.md](docs/UI.md) | `test_ui_*.py` |

Integration tests for each module are in `tests/integration/test_it_<module>.py`.

Migrations are numbered by module (`010` enrich, `020` fetch, `030` ai, `040` reporting, `050` blocklist,
`060` czds, `070` bot, `080+` core) and are **additive only**: new tables, `ADD COLUMN IF NOT EXISTS`.
Never edit a migration that has been merged; add a new one.

## Rules that are not negotiable

These protect the people CyberCheck reports, the people who run it, and the data sources it depends on.
Pull requests that break them will not be merged.

### Only the fetcher contacts suspicious sites

No code outside `fetcher/` may open an HTTP or TCP connection to a flagged domain or its IP addresses.
DNS goes to public resolvers, RDAP to registries, IP lookups to Team Cymru's DNS service. Do not weaken
the fetcher's isolation (VPN-only egress, dropped capabilities, read-only root filesystem, seccomp
profile, Chromium sandbox, loopback-only ports). Every container port stays on `127.0.0.1`. If you change
anything in `fetcher/`, run `scripts/verify-sandbox.sh` on a real setup and say so in the pull request.

### No automated `.au` WHOIS or RDAP

auDA's WHOIS policy forbids automated lookups of `.au` domains. Never add code that queries `.au` WHOIS
or RDAP, directly or through a third-party service. `.au` registrar contacts stay a manual lookup.

### Reporting stays human-reviewed

Only channels that are explicitly built for automated reports may be sent without a person, and only
under the rules in [docs/REPORTING.md](docs/REPORTING.md). Do not lower the hard floors (the score cap
of 89 without page evidence in `confidence.py`, the minimum of 90 for automatic reports and the
blocklist), and do not let an AI verdict alone trigger a report.

**Proposing a new reporting channel:** open a feature request first, with links to the channel's own
official documentation showing:

- that it accepts reports from third parties (not only from victims or customers);
- whether it allows automated submissions. Channels without explicit permission for automation can only
  be added as drafts or web-form checklist items a reviewer files by hand;
- its rate limits, required fields, and what it does with the reporter's personal data.

Channel facts live in `docs/research/au-reporting.yaml` or `docs/research/intl-reporting.yaml`, with the
source page and the date it was checked, and `cybercheck/reporting/channels.py` must agree with them
(`tests/test_reporting.py` checks this).

### Watchlist changes

`config/watchlist.yaml` decides what gets flagged, and its `official_domains` decide what can never be
flagged or reported. Getting either wrong either misses phishing or reports a brand's own website.

- **Every domain added to `official_domains` must be verified on the brand's own website** (for example
  linked from its official homepage or listed on its official "how to spot a scam" page). A WHOIS record,
  a search result or the domain's own content is not enough. Put the source URL in the pull request
  description.
- **Add a regression test in `tests/test_scoring.py`** for every change: hostnames that must now be
  flagged (with the expected brand and minimum tier) in `test_flags`, hostnames that must not be in
  `test_not_flagged`, or a dedicated test like `test_hsbc_group_sites_abroad_are_allowlisted_but_not_argentina`,
  which checks both the newly allowed names and look-alikes that must still be flagged.
- When fixing a false positive, explain the hostname and why it is legitimate. Prefer the narrowest fix
  (an `exclude` substring or a verified official domain) over removing a keyword.
- Use defanged or made-up examples in tests and descriptions where you can.

After a watchlist change, `python -m cybercheck rescore` re-scores stored domains.

### UI rules

The dashboard shows attacker-controlled text (hostnames, page titles, URLs, AI output, certificate
issuers). [docs/UI.md](docs/UI.md) has the details; the hard rules are:

- The Content Security Policy allows no inline code: **no `style="..."`, no `<style>`, no inline
  `<script>` and no `on*=` attributes** in templates. Use classes, `data-*` attributes and files in
  `cybercheck/web/static/`.
- **Autoescape stays on. Never use `|safe` or `Markup`**, and never set `innerHTML` with data in
  JavaScript (use `CC.el(..., {text})` or `textContent`).
- **Never turn a reported or phishing URL into a link.** Links go only to dashboard paths and to the
  official report forms.
- No external assets: no CDNs, remote fonts or remote images.
- Every page and action works with JavaScript turned off. Every POST handler calls `same_origin(request)`.
- Meet the accessibility floor in docs/UI.md (contrast, focus rings, labels, usable at 360 px wide).

### Never commit secrets or real victim data

- `.env`, `vpn.env` and `data/` are gitignored. Keep it that way, and never paste their contents into an
  issue, pull request, log excerpt or test.
- No API keys, tokens, passwords, VPN keys or private hostnames and IP addresses of your own setup in
  code, docs, tests or screenshots. Use `example.com`, `example.org` and the documentation address ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- No real victim data: no phishing-kit submissions, credentials, personal details, or screenshots of
  real people's information. Test fixtures are made up.
- No CZDS zone data, ever (the CZDS terms forbid redistribution).
- If you commit a secret by accident, revoke it first, then tell the maintainers. Rewriting git history
  does not make it secret again.

## Reporting false positives and missed phishing

Use the "False positive or missed phishing" issue form. **Do not paste live phishing URLs unredacted**:
defang them (`hxxps://commbank-login[.]example`) so nobody clicks them by accident and they do not get
indexed. Report live phishing to Scamwatch or the impersonated brand as well; an issue here only improves
detection.

## Licence of contributions

CyberCheck is licensed under the [GNU Affero General Public License v3.0](LICENSE). By submitting a
contribution, you agree that it is licensed under the AGPL-3.0, and you confirm that you have the right
to submit it under that licence (it is your own work, or you have permission and it is compatible).
Do not copy code from sources with incompatible licences.
