"""Dashboard Host allowlist (DNS rebinding) and same_origin() (CSRF). Offline: fake database, no sockets."""
from __future__ import annotations

import re
import sys
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from cybercheck import config, db
from cybercheck.web import app as app_mod
from cybercheck.web import common
from cybercheck.web.common import same_origin

LOCAL = "http://127.0.0.1:8430"
LOCALHOST = "http://localhost:8430"
PUBLIC_NAME = "dashboard.example.ts.net"            # WEB_PUBLIC_HOSTNAME in every test here
TAILNET = f"https://{PUBLIC_NAME}:8430"             # what the browser is on; tailscale serve proxies to LOCAL

CHROME_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 "
             "Safari/537.36")


def chrome_form_post(origin: str, page: str = "/domain/5") -> dict:
    """Headers Chrome sends when a dashboard page at `origin` submits one of its own <form method="post">."""
    return {
        "cache-control": "max-age=0",
        "sec-ch-ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "origin": origin,
        "upgrade-insecure-requests": "1",
        "user-agent": CHROME_UA,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "navigate",
        "sec-fetch-user": "?1",
        "sec-fetch-dest": "document",
        "referer": origin + page,          # Referrer-Policy: same-origin keeps the full URL on same-origin requests
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-AU,en;q=0.9",
    }


# the same request minus the headers that say where it came from
CHROME_NAV = {k: v for k, v in chrome_form_post(LOCAL).items() if k not in ("origin", "referer", "sec-fetch-site")}

TAILSCALE = {"tailscale-user-login": "alex@example.org", "tailscale-user-name": "Alex",
             "x-forwarded-for": "100.101.102.103", "x-forwarded-proto": "https"}

# (name, TestClient base_url (sets the Host the app sees), extra headers, browser origin, expected reviewer)
SITES = [
    ("local", LOCAL, {}, LOCAL, "local"),
    ("localhost", LOCALHOST, {}, LOCALHOST, "local"),
    ("tailnet", "http://dashboard.example.ts.net:8430", TAILSCALE, TAILNET, "alex@example.org"),
    # tailscale serve normally keeps the browser's Host, but a proxy may drop the port
    ("tailnet-no-port", "http://dashboard.example.ts.net:8430", {**TAILSCALE, "host": "dashboard.example.ts.net"},
     TAILNET, "alex@example.org"),
]
SITE_IDS = [s[0] for s in SITES]


class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None

    async def fetchall(self):
        return self.rows


class FakeConn:
    def __init__(self, registered_domain="commbank-login.top"):
        self.sql: list[tuple[str, tuple]] = []
        self.registered_domain = registered_domain
        self.transactions = 0

    async def execute(self, sql, params=()):
        s = " ".join(sql.split())
        self.sql.append((s, params))
        if s.startswith("UPDATE domains SET status"):
            return Cur([{"id": params[-1]}])
        if s.startswith("SELECT registered_domain FROM domains"):
            return Cur([{"registered_domain": self.registered_domain}])
        return Cur([])

    @asynccontextmanager
    async def transaction(self):
        self.transactions += 1
        yield self


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def connection(self):
        yield self.conn


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("WEB_ALLOWED_HOSTS", raising=False)
    for k in ("WEB_HOST", "WEB_PORT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("WEB_PUBLIC_HOSTNAME", PUBLIC_NAME)
    config.settings.cache_clear()
    common.reset_status_cache()          # the status line cache is per process: no test sees another's
    yield
    common.reset_status_cache()
    config.settings.cache_clear()


@pytest.fixture
def conn(monkeypatch):
    c = FakeConn()

    async def pool():
        return FakePool(c)
    monkeypatch.setattr(db, "pool", pool)
    return c


def client(base_url: str) -> TestClient:
    return TestClient(app_mod.app, base_url=base_url)     # no `with`: no lifespan, so no real database


def writes(conn: FakeConn) -> list[str]:
    return [s for s, _ in conn.sql if s.startswith(("UPDATE", "INSERT", "DELETE"))]


# ---------------------------------------------------------------------------------------
# Host allowlist
# ---------------------------------------------------------------------------------------

def test_allowlist_parsing(monkeypatch):
    assert common.allowed_hosts() == {"127.0.0.1:8430", "localhost:8430", "dashboard.example.ts.net:8430",
                                      "dashboard.example.ts.net"}
    for ok in ("127.0.0.1:8430", "LOCALHOST:8430", "dashboard.example.ts.net", " dashboard.example.ts.net:8430 "):
        assert common.host_allowed(ok), ok
    for bad in (None, "", "testserver", "127.0.0.1", "127.0.0.1:8431", "rebind.attacker.example:8430",
                "dashboard.example.ts.net:8443", "dashboard.example.ts.net.evil.example:8430", "[::1]:8430"):
        assert not common.host_allowed(bad), bad
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", " Dash.Example:9000 , ,[::1]:8430")
    assert common.allowed_hosts() == {"dash.example:9000", "[::1]:8430"}
    assert common.host_allowed("dash.example:9000") and not common.host_allowed("127.0.0.1:8430")
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", "  ")
    assert common.host_allowed("127.0.0.1:8430")                  # empty means the default, not "nothing"


@pytest.fixture
def web_env(monkeypatch):
    """Set WEB_PORT / WEB_HOST for one test; settings() is cached, so clear it before and after."""
    def set_env(**env):
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        config.settings.cache_clear()
    yield set_env
    monkeypatch.undo()
    config.settings.cache_clear()


def test_default_allowlist_follows_web_port_and_host(web_env):
    """Changing WEB_PORT (or binding WEB_HOST to the tailnet IP) must not turn every request, healthz included,
    into a 400 unless WEB_ALLOWED_HOSTS is also edited."""
    web_env(WEB_PORT="9123", WEB_HOST="100.64.0.10")
    assert common.allowed_hosts() == {"127.0.0.1:9123", "localhost:9123", "dashboard.example.ts.net:9123",
                                      "dashboard.example.ts.net", "100.64.0.10:9123"}
    for base_url in ("http://127.0.0.1:9123", "http://100.64.0.10:9123", "http://dashboard.example.ts.net:9123"):
        assert client(base_url).get("/robots.txt").status_code == 200, base_url
    assert client(LOCAL).get("/robots.txt").status_code == 400            # the old port is not an address now
    assert common.origin_allowed("http://100.64.0.10:9123") and not common.origin_allowed(LOCAL)
    web_env(WEB_HOST="0.0.0.0")                                          # wildcard bind adds nothing
    assert common.allowed_hosts() == {"127.0.0.1:9123", "localhost:9123", "dashboard.example.ts.net:9123",
                                      "dashboard.example.ts.net"}
    web_env(WEB_HOST="::1")
    assert "[::1]:9123" in common.allowed_hosts()
    web_env(WEB_ALLOWED_HOSTS="dash.example:9000")                        # an explicit list replaces the default
    assert common.allowed_hosts() == {"dash.example:9000"}


def test_public_hostname_setting(web_env):
    """WEB_PUBLIC_HOSTNAME adds the proxy's name on WEB_PORT and port-less; unset, only loopback is allowed. An
    entry with its own port is taken as it is."""
    web_env(WEB_PUBLIC_HOSTNAME="")
    assert common.allowed_hosts() == {"127.0.0.1:8430", "localhost:8430"}
    assert not common.host_allowed(f"{PUBLIC_NAME}:8430") and not common.origin_allowed(TAILNET)
    web_env(WEB_PUBLIC_HOSTNAME=" Dash.Example.ORG , proxy.example:8443,[2001:db8::5]:8430")
    assert common.allowed_hosts() == {"127.0.0.1:8430", "localhost:8430", "dash.example.org:8430",
                                      "dash.example.org", "proxy.example:8443", "[2001:db8::5]:8430"}
    assert common.origin_allowed("https://proxy.example:8443") and not common.origin_allowed("https://proxy.example")


def test_origin_allowed_needs_an_explicit_port_entry():
    for ok in (LOCAL, LOCALHOST, TAILNET, "http://dashboard.example.ts.net:8430", LOCAL + "/domain/5?x=1",
               "HTTPS://DASHBOARD.example.ts.net:8430"):
        assert common.origin_allowed(ok), ok
    for bad in (None, "", "null", "https://dashboard.example.ts.net",      # port 443: a different app on this host
                "https://dashboard.example.ts.net:8443", "http://127.0.0.1:3001", "http://127.0.0.1",
                "http://rebind.attacker.example:8430", "https://evil.example", "file:///etc/passwd",
                "chrome-extension://abc", "http://user@127.0.0.1:8430", "http://127.0.0.1:99999", "127.0.0.1:8430",
                "http://[::1]:8430", "ftp://127.0.0.1:8430", "ws://127.0.0.1:8430",
                "chrome-extension://127.0.0.1:8430"):           # only http(s) origins are the dashboard's
        assert not common.origin_allowed(bad), bad


@pytest.mark.parametrize("base_url", [LOCAL, LOCALHOST, "http://dashboard.example.ts.net:8430"])
def test_allowed_hosts_are_served(base_url):
    r = client(base_url).get("/robots.txt")
    assert r.status_code == 200 and "Disallow: /" in r.text
    assert client(base_url).get("/robots.txt", headers={"host": "dashboard.example.ts.net"}).status_code == 200


@pytest.mark.parametrize("host", ["rebind.attacker.example:8430", "testserver", "127.0.0.1:8431", "127.0.0.1",
                                  "100.64.0.10:8430", "dashboard.example.ts.net:8443"])
def test_other_hosts_get_400_naming_the_host(host, conn):
    c = client(LOCAL)
    for method, path in (("GET", "/robots.txt"), ("GET", "/api/recent"), ("GET", "/bot"), ("GET", "/no-such-page"),
                         ("POST", "/domain/5/status")):
        r = c.request(method, path, headers={"host": host}, data={"status": "confirmed"} if method == "POST" else None)
        assert r.status_code == 400, (method, path)
        assert repr(host) in r.text and "WEB_ALLOWED_HOSTS" in r.text
        assert r.headers["content-type"].startswith("text/plain")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
    assert conn.sql == []


def test_rejected_host_is_not_reflected_raw():
    r = client(LOCAL).get("/robots.txt", headers={"host": "<script>alert(1)</script>"})
    assert r.status_code == 400 and r.headers["content-type"].startswith("text/plain")
    assert r.headers["x-content-type-options"] == "nosniff"


def test_env_override_is_enforced(monkeypatch):
    monkeypatch.setenv("WEB_ALLOWED_HOSTS", "dash.example:9000")
    assert client("http://dash.example:9000").get("/robots.txt").status_code == 200
    r = client(LOCAL).get("/robots.txt")
    assert r.status_code == 400 and "'127.0.0.1:8430'" in r.text


def test_websocket_with_other_host_is_refused():
    with pytest.raises(WebSocketDisconnect) as e:
        with client(LOCAL).websocket_connect("ws://rebind.attacker.example:8430/ws"):
            pass
    assert e.value.code == 1008
    with pytest.raises(WebSocketDisconnect) as e:                 # allowed host: just no such route
        with client(LOCAL).websocket_connect("ws://127.0.0.1:8430/ws"):
            pass
    assert e.value.code != 1008


def test_dns_rebinding_cannot_read_or_post(conn):
    """Finding: a page on rebind.attacker.example:8430 re-pointed at 127.0.0.1 is same-origin with the dashboard."""
    evil = "http://rebind.attacker.example:8430"
    c = client(evil)
    for path in ("/api/recent", "/bot", "/reports", "/"):
        assert c.get(path, headers={"sec-fetch-site": "same-origin"}).status_code == 400, path
    for path, data in (("/domain/5/status", {"status": "confirmed"}), ("/blocklist/5/exclude", {}),
                       ("/bot/chat/123456/status", {"status": "allowed"}), ("/reports/create/5", {})):
        r = c.post(path, data=data, headers=chrome_form_post(evil), follow_redirects=False)
        assert r.status_code == 400 and "rebind.attacker.example:8430" in r.text, path
    assert conn.sql == []


def test_same_origin_checks_the_host_without_the_middleware():
    """same_origin() is the per-POST gate; it must not depend on the app having the Host middleware."""
    bare = FastAPI()

    @bare.post("/x")
    async def x(request: Request):
        same_origin(request)
        return {"ok": True}

    evil = "http://rebind.attacker.example:8430"
    r = TestClient(bare, base_url=evil).post("/x", headers=chrome_form_post(evil))
    assert r.status_code == 400 and "rebind.attacker.example:8430" in r.json()["detail"]
    assert TestClient(bare, base_url=evil).post("/x").status_code == 400            # no-header path too
    assert TestClient(bare).post("/x").status_code == 400                           # TestClient's "testserver"
    assert TestClient(bare, base_url=LOCAL).post("/x", headers=chrome_form_post(LOCAL)).status_code == 200


# ---------------------------------------------------------------------------------------
# same_origin(): positive evidence required
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,base_url,extra,origin,who", SITES, ids=SITE_IDS)
def test_chrome_form_post_works_end_to_end(name, base_url, extra, origin, who, conn):
    r = client(base_url).post("/domain/5/status", data={"status": "confirmed", "note": "phish"},
                              headers={**chrome_form_post(origin), **extra}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/domain/5"
    upd = [p for s, p in conn.sql if s.startswith("UPDATE domains SET status")]
    assert upd and upd[0][:2] == ("confirmed", who) and upd[0][-1] == 5
    assert any(s.startswith("UPDATE pages SET is_evidence") for s, _ in conn.sql)


CSRF_REJECTED = {
    # Finding: no fetch metadata (Safari < 16.4, Firefox < 90) and a sandboxed iframe or no-referrer page
    "origin-null-no-fetch-metadata": {"origin": "null"},
    "origin-null-with-referer": {"origin": "null", "referer": LOCAL + "/domain/5"},
    "origin-null-same-origin": {"origin": "null", "sec-fetch-site": "same-origin"},
    "cross-site": {"sec-fetch-site": "cross-site", "origin": "https://evil.example"},
    "cross-site-no-origin": {"sec-fetch-site": "cross-site"},
    "cross-site-claims-our-origin": {"sec-fetch-site": "cross-site", "origin": LOCAL},
    # https://dashboard.example.ts.net (443) is another app on this machine: same site, not same origin
    "same-site-443": {"sec-fetch-site": "same-site", "origin": "https://dashboard.example.ts.net"},
    "same-site-no-origin": {"sec-fetch-site": "same-site"},        # the Sec-Fetch-Site rule on its own
    "same-site-our-referer": {"sec-fetch-site": "same-site", "referer": LOCAL + "/domain/5"},
    "empty-sec-fetch-site": {"sec-fetch-site": ""},
    "port-443-no-fetch-metadata": {"origin": "https://dashboard.example.ts.net"},
    "other-local-port": {"origin": "http://127.0.0.1:3001"},
    "foreign-origin": {"origin": "https://evil.example"},
    "foreign-origin-same-origin-claim": {"origin": "https://evil.example", "sec-fetch-site": "same-origin"},
    "foreign-referer-only": {"referer": "https://evil.example/x"},
    "sec-fetch-none-no-origin": {"sec-fetch-site": "none"},
    "unknown-sec-fetch-value": {"sec-fetch-site": "bogus", "origin": LOCAL},
}


@pytest.mark.parametrize("headers", list(CSRF_REJECTED.values()), ids=list(CSRF_REJECTED))
@pytest.mark.parametrize("base_url", [LOCAL, "http://dashboard.example.ts.net:8430"], ids=["local", "tailnet"])
def test_post_without_same_origin_evidence_is_refused(headers, base_url, conn):
    r = client(base_url).post("/domain/5/status", data={"status": "confirmed"}, headers=headers,
                              follow_redirects=False)
    assert r.status_code == 403, r.text
    assert "cross-site request blocked" in r.json()["detail"]
    assert writes(conn) == []


CSRF_ACCEPTED = {
    "no-browser-headers": {},                                      # curl / scripts on an allowlisted Host
    "origin-no-fetch-metadata": {"origin": LOCAL},                 # Safari < 16.4
    "referer-only": {"referer": LOCAL + "/domain/5"},              # Firefox < 70: no Origin on form posts
    "sec-fetch-none-with-origin": {"sec-fetch-site": "none", "origin": LOCAL},
    "same-origin-without-origin": {"sec-fetch-site": "same-origin"},
}


@pytest.mark.parametrize("headers", list(CSRF_ACCEPTED.values()), ids=list(CSRF_ACCEPTED))
def test_post_with_same_origin_evidence_is_accepted(headers, conn):
    r = client(LOCAL).post("/domain/5/status", data={"status": "benign"}, headers=headers, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert writes(conn)


def test_referrer_policy_lets_browsers_send_a_real_origin():
    r = client(LOCAL).get("/robots.txt")
    assert r.headers["referrer-policy"] == "same-origin"
    html = common.templates.env.get_template("base.html").render()
    assert '<meta name="referrer" content="same-origin">' in html and "no-referrer" not in html


# ---------------------------------------------------------------------------------------
# every POST route of the real app
# ---------------------------------------------------------------------------------------

def _post_routes():
    return [r for r in app_mod.app.routes if "POST" in (getattr(r, "methods", None) or ())]


def _form_for(route) -> dict:
    return {f.alias: "open" for f in route.dependant.body_params if f.field_info.is_required()}


@pytest.fixture
def spy(monkeypatch):
    """Replace same_origin in every dashboard module with: run the real check, then stop with 418.

    So a route reached 418 iff it called same_origin() and the real check let the request through; it never
    touches the database (which raises if a route skips same_origin)."""
    real = common.same_origin

    def checked(request):
        real(request)
        raise HTTPException(418, "passed same_origin")
    patched = []
    for name, mod in list(sys.modules.items()):
        if name.startswith("cybercheck.web") and getattr(mod, "same_origin", None) is real:
            monkeypatch.setattr(mod, "same_origin", checked)
            patched.append(name)

    async def no_db():
        raise AssertionError("a POST route reached the database without calling same_origin()")
    monkeypatch.setattr(db, "pool", no_db)
    return patched


def test_all_post_routes_are_known(spy):
    paths = {r.path for r in _post_routes()}
    assert {"/domain/{domain_id}/status", "/bot/chat/{chat_id}/status", "/blocklist/rebuild",
            "/blocklist/{domain_id}/exclude", "/blocklist/{domain_id}/include", "/reports/create/{domain_id}",
            "/reports/{report_id}/approve"} <= paths
    assert "cybercheck.web.app" in spy


@pytest.mark.parametrize("name,base_url,extra,origin,who", SITES, ids=SITE_IDS)
def test_every_post_route_accepts_chrome_from_the_dashboard(name, base_url, extra, origin, who, spy):
    c = client(base_url)
    for route in _post_routes():
        path = re.sub(r"\{[^}]+\}", "5", route.path)
        r = c.post(path, data=_form_for(route), headers={**chrome_form_post(origin), **extra}, follow_redirects=False)
        assert r.status_code == 418, (route.path, r.status_code, r.text)


@pytest.mark.parametrize("headers", [{"sec-fetch-site": "cross-site", "origin": "https://evil.example"},
                                     {"origin": "null"}, {"sec-fetch-site": "same-site",
                                                          "origin": "https://dashboard.example.ts.net"}],
                         ids=["cross-site", "origin-null", "same-site"])
def test_every_post_route_refuses_cross_site(headers, spy):
    c = client(LOCAL)
    for route in _post_routes():
        path = re.sub(r"\{[^}]+\}", "5", route.path)
        r = c.post(path, data=_form_for(route), headers={**CHROME_NAV, **headers}, follow_redirects=False)
        assert r.status_code == 403, (route.path, r.status_code, r.text)



def test_domain_page_previews_what_the_blocklist_would_list():
    """Before a reviewer confirms, the domain page says whether the whole domain or only the hostnames seen
    would be blocklisted (shared platforms, brand only in a subdomain)."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    base = {"status": "open", "registered_at": None, "first_seen": now}
    whole = app_mod._blocklist_preview(dict(base, registered_domain="commbank-login.top",
                                            hostnames=["commbank-login.top", "www.commbank-login.top"]))
    assert whole is not None and whole.wildcard
    shared = app_mod._blocklist_preview(dict(base, registered_domain="weebly.com",
                                             hostnames=["commbank-rewards.weebly.com"]))
    assert shared is not None and not shared.wildcard and shared.hosts == ("commbank-rewards.weebly.com",)
    sub_only = app_mod._blocklist_preview(dict(base, registered_domain="someplumber.com.au",
                                               hostnames=["netbank-login.someplumber.com.au"]))
    assert sub_only is not None and not sub_only.wildcard and "subdomain" in sub_only.why
    odd = app_mod._blocklist_preview({"registered_domain": None})      # never breaks the page
    assert odd is None or not odd.wildcard


def test_official_brand_domain_cannot_be_confirmed(conn):
    """Confirming the real bank's domain would make the bot, the stats and /takedown call it phishing."""
    conn.registered_domain = "commbank.com.au"
    r = client(LOCAL).post("/domain/5/status", data={"status": "confirmed"}, headers=chrome_form_post(LOCAL),
                           follow_redirects=False)
    assert r.status_code == 400 and "official brand domain" in r.json()["detail"]
    assert not any(s.startswith("UPDATE domains SET status") for s, _ in conn.sql)
    # other decisions on it are still allowed (e.g. marking a manual add benign)
    r = client(LOCAL).post("/domain/5/status", data={"status": "benign"}, headers=chrome_form_post(LOCAL),
                           follow_redirects=False)
    assert r.status_code == 303


def test_status_change_commits_with_its_event_and_requests_a_rebuild(conn):
    r = client(LOCAL).post("/domain/5/status", data={"status": "false_positive", "note": "real shop"},
                           headers=chrome_form_post(LOCAL), follow_redirects=False)
    assert r.status_code == 303 and conn.transactions == 1
    order = [s.split(" ")[0] + " " + s.split(" ")[2] if s.startswith("INSERT") else s[:22] for s, _ in conn.sql]
    upd = next(i for i, s in enumerate(conn.sql) if s[0].startswith("UPDATE domains SET status"))
    ev = next(i for i, s in enumerate(conn.sql) if s[0].startswith("INSERT INTO domain_events"))
    kv = next(i for i, s in enumerate(conn.sql) if s[0].startswith("INSERT INTO kv"))
    assert upd < ev < kv, order          # the rebuild request comes after the decision's commit


def test_domain_page_note_field_cannot_submit_a_decision_on_enter():
    """Implicit submission (Enter in the note field) uses the form's first submit button: it must be disabled."""
    from pathlib import Path
    src = (Path(app_mod.__file__).parent / "templates" / "domain.html").read_text(encoding="utf-8")
    form = src[src.index('action="/domain/{{ d.id }}/status"'):]
    first_button = form[form.index("<button"):form.index(">", form.index("<button")) + 1]
    assert "disabled" in first_button and 'name="status"' not in first_button
    assert form.index('name="note"') < form.index('name="status"')


def test_health_checks_for_uptime_kuma(tmp_path, monkeypatch):
    """Worker, fetcher and sandbox checks answer 200/503 and never need or reveal a token."""
    import json as _json
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace
    now = datetime.now(timezone.utc)

    class C:
        def __init__(self, last):
            self.last = last

        async def execute(self, sql, params=()):
            return Cur([{"last": self.last}])

    def use(conn):
        async def pool():
            return FakePool(conn)
        monkeypatch.setattr(db, "pool", pool)

    use(C(now - timedelta(seconds=30)))
    assert client(LOCAL).get("/healthz/worker").status_code == 200
    use(C(now - timedelta(hours=1)))
    assert client(LOCAL).get("/healthz/worker").status_code == 503
    use(C(None))
    assert client(LOCAL).get("/healthz/worker").status_code == 503

    monkeypatch.setattr(app_mod, "settings", lambda: SimpleNamespace(data_dir=tmp_path))
    assert client(LOCAL).get("/healthz/sandbox").status_code == 503                  # never verified
    f = tmp_path / "sandbox_verified.json"
    f.write_text(_json.dumps({"verified_at": (now - timedelta(days=2)).isoformat(), "tests_passed": 45}))
    r = client(LOCAL).get("/healthz/sandbox")
    assert r.status_code == 200 and r.json()["tests_passed"] == 45
    f.write_text(_json.dumps({"verified_at": (now - timedelta(days=12)).isoformat(), "tests_passed": 45}))
    assert client(LOCAL).get("/healthz/sandbox").status_code == 503
    f.write_text("not json")
    assert client(LOCAL).get("/healthz/sandbox").status_code == 503

    from cybercheck import fetch_client

    class FC:
        def __init__(self, *a, **k):
            self.configured = True

        async def __aenter__(self):
            return self

        async def __aexit__(self, *e):
            return None

        async def health(self):
            return FC.result
    monkeypatch.setattr(fetch_client, "FetchClient", FC)
    FC.result = {"ok": True, "vpn_running": True, "egress_country": "Australia", "egress_ip": "203.0.113.9"}
    r = client(LOCAL).get("/healthz/fetcher")
    assert r.status_code == 200 and "egress_ip" not in r.json() and "token" not in r.text.lower()
    FC.result = {"ok": False, "vpn_running": False, "http_status": 503}
    assert client(LOCAL).get("/healthz/fetcher").status_code == 503
    FC.result = None
    assert client(LOCAL).get("/healthz/fetcher").status_code == 503


# ---------------------------------------------------------------------------------------
# UI foundation: CSP, static files, status line
# ---------------------------------------------------------------------------------------

def test_csp_header_on_html_pages(conn):
    r = client(LOCAL).get("/review")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    assert csp == app_mod.CSP
    for directive in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:",
                      "connect-src 'self'", "object-src 'none'", "base-uri 'none'", "form-action 'self'",
                      "frame-ancestors 'none'"):
        assert directive in csp, directive
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    # the page links its own stylesheet and script, nothing external
    assert re.search(r'<link rel="stylesheet" href="/static/app\.css\?v=\w+">', r.text)
    assert re.search(r'<script src="/static/app\.js\?v=\w+" defer></script>', r.text)
    head = r.text.split("<main")[0]
    assert "http://" not in head and "https://" not in head
    assert client(LOCAL).get("/robots.txt").headers["content-security-policy"] == app_mod.CSP


def test_base_template_has_no_inline_script_style_or_handlers():
    """The CSP blocks them, so base.html and _ui.html must not depend on any."""
    from pathlib import Path
    tdir = Path(app_mod.__file__).parent / "templates"
    for name in ("base.html", "_ui.html"):
        src = re.sub(r"\{#.*?#\}", "", (tdir / name).read_text(encoding="utf-8"), flags=re.S)     # not comments
        assert "style=" not in src and "<style" not in src, name
        assert not re.search(r"<script(?![^>]*\bsrc=)", src), name
        assert not re.search(r"\son[a-z]+\s*=", src), name
        assert "|safe" not in src.replace(" ", "") and "Markup" not in src, name


def test_static_files_are_served_with_the_right_types():
    c = client(LOCAL)
    r = c.get("/static/app.css")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/css") and "--teal" in r.text
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["content-security-policy"] == app_mod.CSP
    r = c.get("/static/app.js")
    assert r.status_code == 200 and "javascript" in r.headers["content-type"] and "window.CC" in r.text
    assert c.get("/static/nope.css").status_code == 404
    assert c.get("/static/../app.py").status_code == 404
    assert c.get("/static/%2e%2e/app.py").status_code == 404
    # the Host allowlist covers static files too
    r = c.get("/static/app.css", headers={"host": "rebind.attacker.example:8430"})
    assert r.status_code == 400 and r.headers["content-type"].startswith("text/plain")
    # the asset() URLs base.html uses carry a content hash and resolve
    url = common.asset("app.css")
    assert re.fullmatch(r"/static/app\.css\?v=[0-9a-f]{10}", url) and c.get(url).status_code == 200


class FailingStatusConn(FakeConn):
    """A database where every page query works but the status line's query fails."""

    async def execute(self, sql, params=()):
        if "ingest:heartbeat" in sql and "ai_today" in sql:
            self.sql.append((" ".join(sql.split()), params))
            raise RuntimeError("relation does not exist")
        return await super().execute(sql, params)


def test_base_renders_when_the_status_query_fails(monkeypatch):
    c = FailingStatusConn()

    async def pool():
        return FakePool(c)
    monkeypatch.setattr(db, "pool", pool)
    r = client(LOCAL).get("/review")
    assert r.status_code == 200, r.text
    assert any("ai_today" in s for s, _ in c.sql)                    # it was tried
    bar = r.text[r.text.index('id="cc-status"'):r.text.index("</ul>")]
    assert bar.count('class="seg-value">unknown<') == 6 and "seg--muted" in bar
    assert 'aria-current="page"' in r.text and ">Review<" in r.text
    j = client(LOCAL).get("/api/status").json()
    assert j["ok"] is False and all(s["value"] == "unknown" for s in j["segments"])

    # the database is unreachable altogether: still an unknown status line, never an exception
    async def no_pool():
        raise OSError("connection refused")
    monkeypatch.setattr(db, "pool", no_pool)
    common.reset_status_cache()
    import asyncio
    data = asyncio.run(common.refresh_status())
    assert data["ok"] is False and "OSError" in data["reason"]
    html = common.templates.env.get_template("base.html").render()      # also without a request
    assert html.count('class="seg-value">unknown<') == 6


def test_status_query_is_cached_and_skipped_for_non_pages(conn):
    c = client(LOCAL)
    c.get("/review")
    c.get("/domains")
    assert sum("ai_today" in s for s, _ in conn.sql) == 1             # one query within the TTL
    common.reset_status_cache()
    for path in ("/static/app.css", "/robots.txt", "/healthz/sandbox", "/screenshot/1"):
        c.get(path)
    c.post("/domain/5/status", data={"status": "open"}, headers=chrome_form_post(LOCAL), follow_redirects=False)
    assert sum("ai_today" in s for s, _ in conn.sql) == 1


def test_build_status_states():
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    healthy = {"certs_5m": 2105, "heartbeat_at": now - timedelta(seconds=20), "open_review": 7, "open_high": 2,
               "worker_at": now - timedelta(seconds=40), "fetch_at": now - timedelta(seconds=10),
               "fetch_job": {"ok": True, "result": {"due": 0, "egress_country": "AU", "egress_ip": "203.0.113.9"}},
               "ai_today": 0.42, "db_now": now}
    s = common.build_status(healthy, 1.60, True)
    seg = {x["key"]: x for x in s["segments"]}
    assert s["ok"] and s["certs_per_min"] == 421 and s["stream"] == "live"
    assert seg["ct"]["value"] == "421/min" and seg["ct"]["tone"] == "teal"
    assert seg["queue"]["value"] == "7 open, 2 high" and seg["queue"]["tone"] == "red"
    assert seg["queue"]["href"] == "/review"
    assert seg["worker"]["value"] == "ok" and seg["fetcher"]["value"] == "ok" and seg["vpn"]["value"] == "AU"
    assert seg["ai"]["value"] == "$0.42 of $1.60" and seg["ai"]["tone"] == "violet" and s["ai_pct"] == 26
    assert "203.0.113.9" not in str(s)                                 # the egress IP is never shown
    for x in s["segments"]:                                            # colour is never the only signal
        assert x["value"] and x["glyph"] and x["title"]

    bad = dict(healthy, heartbeat_at=now - timedelta(minutes=9), open_review=3, open_high=0,
               worker_at=now - timedelta(hours=2),
               fetch_job={"ok": True, "result": {"skipped": "fetcher unavailable"}}, ai_today=1.70)
    s = common.build_status(bad, 1.60, True)
    seg = {x["key"]: x for x in s["segments"]}
    assert seg["ct"]["value"] == "stalled 9m" and seg["ct"]["tone"] == "red"
    assert seg["queue"]["value"] == "3 open" and seg["queue"]["tone"] == "amber"
    assert seg["worker"]["tone"] == "red" and seg["fetcher"]["value"] == "down" and seg["vpn"]["value"] == "unknown"
    assert s["ai"] == "over" and seg["ai"]["tone"] == "red"

    s = common.build_status(dict(healthy, fetch_job={"ok": True, "result": {"skipped": "fetcher not configured"}},
                                 open_review=0, open_high=0, heartbeat_at=None), 1.60, False)
    seg = {x["key"]: x for x in s["segments"]}
    assert seg["fetcher"]["value"] == "off" and seg["vpn"]["value"] == "off" and seg["ai"]["value"].startswith("off")
    assert seg["queue"]["value"] == "empty" and seg["ct"]["value"] == "no heartbeat"
    assert common.build_status(dict(healthy, fetch_at=now - timedelta(hours=1)), 1.6, True)["fetcher"] == "stale"
    assert common.build_status(dict(healthy, fetch_job={"ok": False, "error": "boom"}), 1.6, True)["fetcher"] == "error"
    assert common.build_status(None)["ok"] is False


def test_status_line_text_is_escaped(conn):
    import time
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    evil = {"certs_5m": 0, "heartbeat_at": now, "open_review": 0, "open_high": 0, "worker_at": now, "fetch_at": now,
            "fetch_job": {"ok": True, "result": {"egress_country": "<img src=x>"}}, "ai_today": 0, "db_now": now}
    common._status_cache.update(at=time.monotonic(), data=common.build_status(evil, 1.0, True))
    r = client(LOCAL).get("/review")
    assert "<img src=x>" not in r.text and "&lt;img src=x&gt;" in r.text


def test_nav_active_state():
    assert common.nav_active("/", "/") and not common.nav_active("/review", "/")
    assert common.nav_active("/domain/5", "/domains") and common.nav_active("/reports/7", "/reports")
    assert not common.nav_active("/reviewer", "/review") and not common.nav_active("", "/review")


def test_dot_matrix_cells():
    from datetime import datetime, timedelta, timezone
    end = datetime(2026, 11, 16, 14, 30, 45, tzinfo=timezone.utc)
    m0 = end.replace(second=0)
    certs = {m0: 400, m0 - timedelta(minutes=1): 100, m0 - timedelta(hours=30): 999}     # 30 h ago: outside
    flags = {m0 - timedelta(minutes=1): "review", m0: "high"}
    m = common.dot_matrix(certs, flags, end=end)
    assert len(m["rows"]) == 24 and all(len(r["cells"]) == 60 for r in m["rows"])
    assert m["rows"][0]["label"] == "15:00" and m["rows"][-1]["label"] == "14:00"
    last = m["rows"][-1]["cells"]
    assert last[30] == {"level": 4, "flag": "high", "title": "14:30 UTC: 400 certificates, high hit"}
    assert last[29]["level"] == 1 and last[29]["flag"] == "review"
    assert last[31]["level"] is None and last[59]["level"] is None                     # later this hour
    assert m["max"] == 400 and m["total"] == 500 and m["flagged"] == 2
    html = common.templates.env.from_string('{% import "_ui.html" as ui %}{{ ui.dot_matrix(m) }}').render(m=m)
    assert html.count("<i class=") == 24 * 60 + 6 and 'class="l4 f-high"' in html and 'class="x"' in html


def test_every_template_and_static_file_follows_the_csp():
    """Every template, not only the shared ones: nothing the CSP would block, nothing that skips autoescaping,
    and the static files load nothing from outside and build no HTML from strings."""
    from pathlib import Path
    web = Path(app_mod.__file__).parent
    for path in sorted((web / "templates").glob("*.html")):
        src = re.sub(r"\{#.*?#\}", "", path.read_text(encoding="utf-8"), flags=re.S)
        assert not re.search(r"\sstyle\s*=", src) and "<style" not in src, path.name
        assert not re.search(r"<script(?![^>]*\bsrc=\"\{\{ asset\()", src), path.name
        assert not re.search(r"<[^>]+\son[a-z]+\s*=", src), path.name
        assert not re.search(r"\|\s*safe\b", src) and "Markup" not in src and "autoescape" not in src, path.name
        assert not re.search(r"(?:src|href)=\"(?:https?:)?//", src), path.name
    from cybercheck.web import pages_live
    assert not re.search(r"\sstyle\s*=|<style|<script(?![^>]*\bsrc=)|\|\s*safe\b", pages_live.LIST_TEMPLATE)
    for path in sorted(p for p in (web / "static").rglob("*") if p.is_file()):
        if path.parent.name == "fonts":
            # the one bundled font and its licence; nothing else lives there
            assert path.suffix in (".ttf", ".woff2", ".txt"), path.name
            continue
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", text), path.name
        if path.suffix == ".css":
            # url() only for data: URIs, same-document #fragments (SVG gradients) and the bundled font
            assert "@import" not in text and not re.search(r"url\(\s*(?!['\"]?(?:data:|#|fonts/[\w.-]+['\")]))", text), path.name
        if path.suffix == ".js":
            code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
            code = re.sub(r"(?m)^\s*//.*$", "", code)
            assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function",
                                 code), path.name


def test_every_post_route_checks_the_origin():
    """A cross-site form post must never change anything: every POST handler calls same_origin(request) first."""
    import ast
    import inspect
    import textwrap
    from fastapi.routing import APIRoute
    posts = [r for r in app_mod.app.routes if isinstance(r, APIRoute) and "POST" in r.methods]
    assert len(posts) >= 11
    for route in posts:
        fn = ast.parse(textwrap.dedent(inspect.getsource(route.endpoint))).body[0]
        stmts = [x for x in fn.body if not (isinstance(x, ast.Expr) and isinstance(x.value, ast.Constant))]
        first = stmts[0]
        assert (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                and getattr(first.value.func, "id", "") == "same_origin"), route.path
