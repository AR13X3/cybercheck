# Security policy

CyberCheck handles hostile web pages, sends reports that can get a website taken down, and holds API
keys and VPN credentials. Security problems in it matter, and we would much rather hear about them
privately first.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub:

1. Go to https://github.com/AR13X3/cybercheck/security/advisories/new
   (or the repository's **Security** tab, then **Report a vulnerability**).
2. Describe the problem, the affected files or versions (a commit hash is fine), and how to reproduce it.
   A minimal proof of concept helps. Say what an attacker would need (for example: control of a phishing
   page that CyberCheck fetches, or access to the dashboard's network).

What to expect:

- An acknowledgement within 7 days. This is a small volunteer project, so it may be faster or slower.
- An honest assessment, and a fix or mitigation plan for confirmed issues. We coordinate the disclosure
  date with you; the default is to publish an advisory once a fix is available, or after 90 days.
- Credit in the advisory if you want it.

There is no bug bounty.

## Supported versions

CyberCheck is alpha software with no releases yet. Only the latest commit on the default branch is
supported. Security fixes are not backported.

## Scope

In scope, with examples of what we want to hear about:

- **The dashboard** (`cybercheck/web/`): cross-site scripting (including through hostnames, page titles,
  URLs, AI output, certificate issuer strings or Telegram chat titles, which are all attacker-controlled),
  any way around the Content Security Policy, cross-site request forgery, DNS rebinding or `Host` header
  bypasses, path traversal in screenshot or file routes, SQL injection, and anything that turns a
  phishing URL into a clickable link.
- **The fetcher sandbox** (`fetcher/`, `scripts/verify-sandbox.sh`, `scripts/host-firewall.sh`): any way
  for a fetched page to reach the host, the local network, Postgres, the VPN control server or other
  containers; traffic that leaves outside the VPN tunnel (including DNS and IPv6); a Chromium sandbox or
  container escape made possible by our configuration (seccomp profile, capabilities, mounts); and the
  fetcher getting hold of app secrets.
- **Prompt injection into decisions or reports** (`cybercheck/ai/`, `cybercheck/reporting/`,
  `cybercheck/confidence.py`): page content or domain names that make the AI verdict, a report draft or
  the final score say something the evidence does not support, that get a legitimate site reported or
  blocklisted, that slip a recipient or URL into a report, or that bypass the rules for automatic
  reports.
- **Credential and secret handling**: secrets in logs, in the dashboard, in error messages, in reports,
  in the blocklist output or in container environments where they do not belong; secrets that a default
  configuration would commit to git; the AI budget cap being bypassed.
- **Reporting safety**: anything that makes CyberCheck send a report without the documented checks, send
  to an address controlled by the attacker, or exceed its rate limits.
- **Scripts and deployment files** (`scripts/`, `deploy/`, `docker-compose.yml`, `fetcher/compose.yaml`)
  that expose a port beyond loopback or weaken the isolation.

Out of scope:

- Vulnerabilities in third-party software (Chromium, gluetun, Playwright, Postgres, Python packages)
  unless our configuration makes them exploitable. Please report those upstream.
- A dashboard you exposed to the internet yourself. It has no login by design and must stay private
  (see [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md)).
- Detection gaps (a phishing site CyberCheck missed) and false positives. Those are ordinary issues: use
  the "False positive or missed phishing" issue form.
- Missing security headers or best-practice findings without a demonstrated impact.

## What not to do

- Do not test against anyone else's CyberCheck deployment. Run your own copy.
- Do not create, host or send real phishing pages, and do not use real victims' data. Test pages on
  domains you control (or `example.com` / local test servers) are enough to show a fetcher or prompt
  injection problem.
- Do not submit test reports to real reporting channels (Netcraft, registrars, brands, Scamwatch) to
  demonstrate an issue. Use `NETCRAFT_TEST=true` or a mocked channel.
- Do not run denial-of-service tests, or anything that degrades services for others, including the CT
  log operators, RDAP servers and the VPN provider.
- Do not include secrets, live phishing URLs or personal data in your report unless they are needed to
  understand the problem. If you must include a phishing URL, defang it (`hxxps://example[.]com`).
