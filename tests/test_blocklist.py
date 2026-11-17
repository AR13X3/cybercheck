"""Blocklist module tests. Offline: the database is an in-memory fake, no network."""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cybercheck import blocklist as bl
from cybercheck.scoring import Watchlist

NOW = datetime(2026, 11, 15, 7, 30, tzinfo=timezone.utc)
DAY = timedelta(days=1)

WL = Watchlist({
    "brands": [
        {"id": "commbank", "name": "Commonwealth Bank", "keywords": ["commbank"],
         "official_domains": ["commbank.com.au", "netbank.com.au"]},
        {"id": "auspost", "name": "Australia Post", "keywords": ["auspost"], "official_domains": ["auspost.com.au"]},
    ],
    "extra_allowlist": ["allowed-partner.com"],
    "bait_words": {"strong": ["login", "verify", "netbank"], "weak": ["secure", "parcel"]},
    "au_context_tokens": ["au"],
})


def cfg(tmp_path: Path | None = None, **kw) -> bl.BuildConfig:
    base = dict(min_final_score=85, days=90, homepage="https://example.org/list", contact="abuse@example.org",
                license="not yet decided", out_dir=(tmp_path or Path("/nonexistent")) / "blocklist")
    base.update(kw)
    return bl.BuildConfig(**base)


def row(i: int, name: str, **kw) -> dict:
    r = {"id": i, "registered_domain": name, "brand_id": "commbank", "status": "open", "status_changed_at": None,
         "final_score": 90, "ai_verdict": "phishing", "ai_confidence": 0.9, "source": "ct",
         "first_seen": NOW - 2 * DAY, "registered_at": NOW - 3 * DAY, "hostnames": [f"www.{name}", name],
         "live_state": "unknown", "last_live_at": None, "dns_state": "resolves", "takedown_at": None,
         "blocklisted": False, "blocklist_expires_at": None, "blocklist_listed_at": None,
         "blocklist_excluded": False, "notes": "internal reviewer note: do not publish"}
    r.update(kw)
    return r


# ---- rules -------------------------------------------------------------------------------------
@pytest.mark.parametrize("name,ok", [
    ("commbank-login.top", True), ("xn--commbnk-0ug.top", True), ("a.b", True), ("x_y.example.com", True),
    ("", False), ("top", False), ("Commbank.top", False), ("evil.top\nserver=/x/1.2.3.4", False),
    ("evil.top\n", False), ('evil".top', False), ("-bad.top", False), ("bad-.top", False), ("*.evil.top", False),
    ("evil..top", False), ("évil.top", False), ("a" * 64 + ".top", False), (("a" * 60 + ".") * 5 + "top", False),
    (None, False),
])
def test_valid_name(name, ok):
    assert bl.valid_name(name) is ok


@pytest.mark.parametrize("overrides,reason", [
    ({}, None),
    ({"status": "confirmed", "final_score": None}, None),
    ({"status": "confirmed", "final_score": 10}, None),
    ({"final_score": 90}, None),
    ({"final_score": 89}, "combined score below 90"),     # cfg() asks for 85: the floor of 90 wins
    ({"final_score": 85}, "combined score below 90"),
    ({"final_score": None}, "combined score below 90"),
    ({"ai_verdict": None}, "no AI phishing verdict"),
    ({"ai_verdict": "suspicious", "final_score": 99}, "no AI phishing verdict"),
    ({"ai_confidence": 0.5}, "no AI phishing verdict"),
    ({"ai_confidence": float("nan")}, "no AI phishing verdict"),
    ({"status": "confirmed", "ai_verdict": None, "final_score": None}, None),
    ({"source": "czds"}, bl.CZDS_REASON),
    ({"source": "czds", "status": "confirmed"}, bl.CZDS_REASON),
    ({"status": "false_positive", "final_score": 99}, "marked false positive"),
    ({"status": "benign"}, "marked benign"),
    ({"status": "confirmed", "blocklist_excluded": True}, "excluded by a reviewer"),
    ({"status": "confirmed", "registered_domain": "commbank.com.au"}, "official domain on the watchlist"),
    ({"status": "confirmed", "registered_domain": "allowed-partner.com"}, "official domain on the watchlist"),
    ({"status": "confirmed", "registered_domain": "fake-ato.gov.au"}, "government domain"),
    ({"status": "confirmed", "registered_domain": "com.au"}, "public suffix"),
    ({"status": "confirmed", "registered_domain": "pages.dev"}, "public suffix"),
    ({"status": "confirmed", "registered_domain": "commbank-login.pages.dev"}, None),
    ({"status": "confirmed", "registered_domain": "bad name.top"}, "not a plain DNS name"),
])
def test_skip_reason(overrides, reason):
    assert bl.skip_reason(row(1, "commbank-login.top", **overrides), cfg(), WL) == reason


def test_is_live_ignores_taken_down_and_nxdomain():
    assert bl.is_live(row(1, "a.top", live_state="live", last_live_at=NOW - DAY))
    assert not bl.is_live(row(1, "a.top", live_state="live", last_live_at=NOW - DAY, dns_state="nxdomain"))
    assert not bl.is_live(row(1, "a.top", live_state="live", last_live_at=NOW - 2 * DAY, takedown_at=NOW - DAY))
    assert bl.is_live(row(1, "a.top", live_state="live", last_live_at=NOW, takedown_at=NOW - DAY))  # came back
    assert not bl.is_live(row(1, "a.top", live_state="down", last_live_at=NOW))


# ---- plan / expiry -----------------------------------------------------------------------------
def test_plan_new_listing_and_removals():
    rows = [
        row(1, "commbank-login.top"),                                                   # new, score
        row(2, "auspost-redelivery.top", brand_id="auspost", status="confirmed", final_score=None),
        row(3, "fp-now.top", status="false_positive", blocklisted=True,
            blocklist_listed_at=NOW - 5 * DAY, blocklist_expires_at=NOW + 85 * DAY),
        row(4, "excluded.top", status="confirmed", blocklist_excluded=True, blocklisted=True,
            blocklist_listed_at=NOW - DAY, blocklist_expires_at=NOW + 89 * DAY),
        row(5, "low.top", final_score=50),                                              # not listed, ignored
    ]
    p = bl.plan(rows, NOW, cfg(), WL)
    assert [e.name for e in p.entries] == ["auspost-redelivery.top", "commbank-login.top"]
    assert {e.id for e in p.added} == {1, 2}
    e1 = next(e for e in p.entries if e.id == 1)
    assert e1.listed_since == NOW and e1.expires == NOW + 90 * DAY and e1.via == "score"
    assert e1.reason == "automated detection, combined confidence 90/100"
    e2 = next(e for e in p.entries if e.id == 2)
    assert e2.brand == "Australia Post" and e2.reason == "confirmed phishing by a human reviewer"
    removed = {r["id"]: (why, keep) for r, why, keep in p.removed}
    assert removed == {3: ("marked false positive", None), 4: ("excluded by a reviewer", None)}


def test_plan_keeps_listed_since_and_extends_with_live():
    listed = NOW - 10 * DAY
    r = row(1, "commbank-login.top", blocklisted=True, blocklist_listed_at=listed,
            blocklist_expires_at=listed + 90 * DAY, last_live_at=NOW - 3 * DAY, live_state="down")
    p = bl.plan([r], NOW, cfg(), WL)
    (e,) = p.entries
    assert e.listed_since == listed
    assert e.expires == bl._day(NOW - 3 * DAY) + 90 * DAY   # day last seen live is later than listed
    assert p.updated == [e] and not p.added and not p.removed
    # unchanged expiry -> nothing to update
    r["blocklist_expires_at"] = e.expires
    assert bl.plan([r], NOW, cfg(), WL).updated == []


def test_expired_entry_dropped_unless_live():
    listed = NOW - 100 * DAY
    old = row(1, "commbank-old.top", status="confirmed", blocklisted=True, blocklist_listed_at=listed,
              blocklist_expires_at=listed + 90 * DAY, last_live_at=listed + DAY, live_state="down")
    p = bl.plan([old], NOW, cfg(), WL)
    assert not p.entries
    assert p.removed == [(old, "expired", bl._day(listed + DAY) + 90 * DAY)]   # expiry kept as a marker

    live = dict(old, live_state="live", last_live_at=NOW - 2 * DAY)   # seen live recently, still live
    p = bl.plan([live], NOW, cfg(), WL)
    assert [e.name for e in p.entries] == ["commbank-old.top"]
    assert p.entries[0].expires == datetime(2026, 11, 15, tzinfo=timezone.utc) + 90 * DAY

    # a 'live' flag nobody has re-checked for months must not keep the entry forever
    stale = dict(old, live_state="live", last_live_at=listed + DAY)
    p = bl.plan([stale], NOW, cfg(), WL)
    assert not p.entries
    assert p.removed == [(stale, "expired", bl._day(listed + DAY + bl.LIVE_FRESH_DAYS * DAY) + 90 * DAY)]
    # and once dropped it is not re-added on the next build
    dropped = dict(stale, blocklisted=False, blocklist_expires_at=p.removed[0][2])
    assert bl.plan([dropped], NOW + DAY, cfg(), WL).entries == []


def test_live_flag_without_last_live_time_is_not_live():
    assert not bl.is_live(row(1, "a.top", live_state="live", last_live_at=None))


def test_expiry_does_not_move_on_every_fetch():
    """last_live_at changes on each check; the expiry (and so the files and RPZ serial) only daily."""
    listed = NOW - 10 * DAY
    r = row(1, "commbank-login.top", blocklisted=True, blocklist_listed_at=listed, live_state="live",
            last_live_at=NOW.replace(hour=1))
    (e,) = bl.plan([r], NOW, cfg(), WL).entries
    r2 = dict(r, last_live_at=NOW.replace(hour=7), blocklist_expires_at=e.expires)
    (e2,) = bl.plan([r2], NOW.replace(hour=8), cfg(), WL).entries
    assert e2.expires == e.expires == datetime(2026, 11, 15, tzinfo=timezone.utc) + 90 * DAY
    assert bl.plan([r2], NOW.replace(hour=8), cfg(), WL).updated == []


def test_never_lists_parent_of_an_official_domain():
    """Blocking host.com in AdGuard/dnsmasq/RPZ also blocks an official secure.host.com."""
    wl = Watchlist({"brands": [{"id": "b", "name": "B", "keywords": ["bbbbbb"],
                                "official_domains": ["secure.shared-host.com", "brand.com.au"]}]})
    for name in ("shared-host.com", "secure.shared-host.com", "x.secure.shared-host.com", "brand.com.au"):
        assert bl.skip_reason(row(1, name, status="confirmed"), cfg(), wl) == "official domain on the watchlist"
    assert bl.skip_reason(row(1, "other-host.com", status="confirmed"), cfg(), wl) is None
    assert bl.skip_reason(row(1, "host.com", status="confirmed"), cfg(), wl) is None


def test_expired_entry_not_relisted_until_live_again_or_reconfirmed():
    expired_at = NOW - 5 * DAY
    base = row(1, "commbank-old.top", status="confirmed", status_changed_at=NOW - 120 * DAY, blocklisted=False,
               blocklist_listed_at=NOW - 95 * DAY, blocklist_expires_at=expired_at, last_live_at=NOW - 96 * DAY)
    assert bl.plan([base], NOW, cfg(), WL).entries == []
    seen_again = dict(base, last_live_at=NOW - DAY, live_state="down")
    p = bl.plan([seen_again], NOW, cfg(), WL)
    assert [e.id for e in p.added] == [1] and p.added[0].listed_since == NOW
    reconfirmed = dict(base, status_changed_at=NOW - DAY)
    assert [e.id for e in bl.plan([reconfirmed], NOW, cfg(), WL).added] == [1]
    # an open (automated) entry is not brought back by an unrelated status timestamp
    auto = dict(base, status="open", final_score=95, status_changed_at=NOW - DAY)
    assert bl.plan([auto], NOW, cfg(), WL).entries == []


def test_hostnames_only_under_the_domain():
    r = row(1, "commbank-login.top", hostnames=["www.commbank-login.top", "commbank-login.top", "evil.com",
                                                 "xcommbank-login.top", "bad\nname.commbank-login.top",
                                                 "secure.commbank-login.top"])
    (e,) = bl.plan([r], NOW, cfg(), WL).entries
    assert e.hostnames == ["secure.commbank-login.top", "www.commbank-login.top"]


# ---- rendering ---------------------------------------------------------------------------------
def _entries():
    return bl.plan([row(2, "zeta-commbank.top", hostnames=["login.zeta-commbank.top"]),
                    row(1, "alpha-commbank.top", status="confirmed", hostnames=[])], NOW, cfg(), WL).entries


def _body(text: str, mark: str) -> list[str]:
    return [line for line in text.splitlines() if line and not line.startswith(mark)]


def test_render_formats():
    files = bl.render(_entries(), cfg(), NOW, 2026111503)
    assert set(files) == set(bl.FILES)
    assert _body(files["hosts.txt"], "#") == ["0.0.0.0 alpha-commbank.top", "0.0.0.0 login.zeta-commbank.top",
                                              "0.0.0.0 zeta-commbank.top"]
    assert _body(files["adguard.txt"], "!") == ["||alpha-commbank.top^", "||zeta-commbank.top^"]
    assert _body(files["domains.txt"], "#") == ["alpha-commbank.top", "zeta-commbank.top"]
    assert _body(files["dnsmasq.conf"], "#") == [
        "address=/alpha-commbank.top/0.0.0.0", "address=/alpha-commbank.top/::",
        "address=/zeta-commbank.top/0.0.0.0", "address=/zeta-commbank.top/::"]
    assert _body(files["unbound.conf"], "#") == [
        "server:", '  local-zone: "alpha-commbank.top." always_nxdomain',
        '  local-zone: "zeta-commbank.top." always_nxdomain']
    assert _body(files["rpz.zone"], ";") == [
        "$TTL 300", "@ IN SOA localhost. hostmaster.localhost. ( 2026111503 3600 600 604800 300 )",
        "@ IN NS localhost.", "alpha-commbank.top CNAME .", "*.alpha-commbank.top CNAME .",
        "zeta-commbank.top CNAME .", "*.zeta-commbank.top CNAME ."]
    assert "$ORIGIN" not in files["rpz.zone"]


@pytest.mark.parametrize("name,mark", [(n, {"adguard.txt": "!", "rpz.zone": ";"}.get(n, "#"))
                                       for n in bl.FILES if n != "blocklist.json"])
def test_headers(name, mark):
    text = bl.render(_entries(), cfg(), NOW, 2026111501)[name]
    header = [line for line in text.splitlines() if line.startswith(mark)]
    assert header[0] == f"{mark} Title: CyberCheck Australian phishing blocklist"
    for expected in ("Updated: 2026-11-15 07:30:00 UTC", "Entries: 2", "Homepage: https://example.org/list",
                     "Contact: abuse@example.org", "License: not yet decided"):
        assert f"{mark} {expected}" in header
    assert text.endswith("\n") and "\r" not in text


def test_header_placeholders_empty_by_default(monkeypatch):
    for k in ("BLOCKLIST_HOMEPAGE", "BLOCKLIST_CONTACT", "BLOCKLIST_LICENSE"):
        monkeypatch.delenv(k, raising=False)
    c = bl.BuildConfig.from_env()
    assert (c.homepage, c.contact, c.license) == ("", "", "not yet decided")
    monkeypatch.setenv("BLOCKLIST_CONTACT", "a@b.example\nserver=/evil/1.2.3.4")
    assert "\n" not in bl.BuildConfig.from_env().contact
    text = bl.render([], c, NOW, 1)["domains.txt"]
    assert "# Homepage:\n" in text and "# Contact:\n" in text


def test_json_metadata_has_only_public_fields():
    meta = json.loads(bl.render(_entries(), cfg(), NOW, 1)["blocklist.json"])
    assert meta["title"] == bl.TITLE and meta["count"] == 2 and meta["updated"] == "2026-11-15T07:30:00Z"
    assert meta["license"] == "not yet decided" and meta["homepage"] == "https://example.org/list"
    assert [e["domain"] for e in meta["entries"]] == ["alpha-commbank.top", "zeta-commbank.top"]
    for e in meta["entries"]:
        assert set(e) == {"domain", "scope", "brand", "first_seen", "listed_since", "expires", "reason"}
    assert meta["entries"][0] == {"domain": "alpha-commbank.top", "scope": "domain", "brand": "Commonwealth Bank",
                                  "first_seen": "2026-11-13T07:30:00Z", "listed_since": "2026-11-15T07:30:00Z",
                                  "expires": "2027-02-13T07:30:00Z", "reason": "confirmed phishing by a human reviewer"}
    assert "internal" not in json.dumps(meta)


def test_rpz_zone_parses():
    import dns.rdatatype
    import dns.zone
    zone = dns.zone.from_text(bl.render(_entries(), cfg(), NOW, 2026111501)["rpz.zone"], origin="rpz.example.",
                              relativize=False)
    soa = zone.find_rdataset("rpz.example.", dns.rdatatype.SOA)[0]
    assert soa.serial == 2026111501
    cnames = sorted(str(n) for n, node in zone.nodes.items() if node.get_rdataset(1, dns.rdatatype.CNAME))
    assert cnames == ["*.alpha-commbank.top.rpz.example.", "*.zeta-commbank.top.rpz.example.",
                      "alpha-commbank.top.rpz.example.", "zeta-commbank.top.rpz.example."]
    assert all(str(r.target) == "." for n, node in zone.nodes.items()
               for r in (node.get_rdataset(1, dns.rdatatype.CNAME) or []))
    dns.zone.from_text(bl.render([], cfg(), NOW, 2026111501)["rpz.zone"], origin="rpz.example.")


def test_empty_list_is_still_valid():
    files = bl.render([], cfg(), NOW, 2026111501)
    assert _body(files["rpz.zone"], ";")[:3][1].startswith("@ IN SOA")
    assert _body(files["unbound.conf"], "#") == ["server:"]
    assert json.loads(files["blocklist.json"])["entries"] == []


def test_next_serial():
    assert bl.next_serial(None, NOW) == 2026111501
    assert bl.next_serial(2026111401, NOW) == 2026111501
    assert bl.next_serial(2026111501, NOW) == 2026111502
    assert bl.next_serial(2026111599, NOW) == 2026111600          # still increasing
    assert bl.next_serial(2026111600, NOW + DAY) == 2026111601
    assert bl.next_serial("garbage", NOW) == 2026111501


def test_digest_stable_and_sensitive():
    e = _entries()
    assert bl.digest(e, cfg()) == bl.digest(list(reversed(e)), cfg())
    assert bl.digest(e, cfg()) != bl.digest(e[:1], cfg())
    assert bl.digest(e, cfg()) != bl.digest(e, cfg(contact="other@example.org"))


# ---- atomic writes -----------------------------------------------------------------------------
def test_write_files_atomic(tmp_path, monkeypatch):
    d = tmp_path / "blocklist"
    bl.write_files(d, {"domains.txt": "old\n"})
    (d / ".domains.txt.crash.tmp").write_text("leftover")
    bl.write_files(d, {"domains.txt": "new\n", "hosts.txt": "h\n"})
    assert (d / "domains.txt").read_text() == "new\n"
    assert sorted(p.name for p in d.iterdir()) == ["domains.txt", "hosts.txt"]
    assert oct((d / "hosts.txt").stat().st_mode & 0o777) == "0o644"

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(bl.os, "replace", boom)
    with pytest.raises(OSError):
        bl.write_files(d, {"domains.txt": "broken\n"})
    assert (d / "domains.txt").read_text() == "new\n"           # old file intact
    assert sorted(p.name for p in d.iterdir()) == ["domains.txt", "hosts.txt"]  # temp cleaned up
    with pytest.raises(ValueError):
        bl.write_files(d, {"../evil.txt": "x"})


# ---- build against a fake database ---------------------------------------------------------------
class Cur:
    def __init__(self, rows):
        self.rows = rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None

    async def fetchall(self):
        return list(self.rows)


class FakeDB:
    """The handful of statements the blocklist runs, against in-memory rows."""

    def __init__(self, domains, now=NOW):
        self.domains = {d["id"]: d for d in domains}
        self.kv: dict[str, dict] = {}
        self.events: list[tuple[int, str, dict]] = []
        self.now = now
        self.locked = False
        self.sql: list[str] = []
        self.timed_events: list[tuple[int, str, dict, datetime]] = []   # (domain_id, kind, detail, at)

    @asynccontextmanager
    async def transaction(self):
        yield

    async def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.sql.append(s)
        if s.startswith("SELECT pg_try_advisory_xact_lock"):
            return Cur([{"locked": not self.locked, "now": self.now}])
        if s.startswith("SELECT value FROM kv WHERE key"):
            k = params[0]
            return Cur([{"value": self.kv[k]["value"]}] if k in self.kv else [])
        if s.startswith("INSERT INTO kv"):
            self.kv[params[0]] = {"value": params[1].obj, "updated_at": self.now}
            return Cur([])
        if s.startswith("DELETE FROM kv"):
            k, before = params
            if k in self.kv and self.kv[k]["updated_at"] <= before:
                del self.kv[k]
            return Cur([])
        if s.startswith("SELECT now() AS now, (SELECT value FROM kv"):
            st = self.kv.get(params[0])
            rq = self.kv.get(params[1])
            return Cur([{"now": self.now, "state": st["value"] if st else None,
                         "requested": rq["updated_at"] if rq else None}])
        if s.startswith("SELECT EXISTS (SELECT 1 FROM domain_events"):
            kinds, since = params
            return Cur([{"changed": any(k in kinds and at > since for _, k, _d, at in self.timed_events)}])
        if s.startswith("SELECT id, registered_domain"):
            return Cur([dict(d) for d in self.domains.values()])
        if s.startswith("UPDATE domains SET blocklisted = true"):
            listed_at, expires, i = params
            d = self.domains[i]
            if d["blocklist_excluded"] or d["status"] in ("false_positive", "benign"):
                return Cur([])
            d.update(blocklisted=True, blocklist_listed_at=listed_at, blocklist_expires_at=expires)
            return Cur([{"id": i}])
        if s.startswith("UPDATE domains SET blocklist_listed_at"):
            listed_at, expires, i = params
            self.domains[i].update(blocklist_listed_at=listed_at, blocklist_expires_at=expires)
            return Cur([])
        if s.startswith("UPDATE domains SET blocklisted = false"):
            expires, i = params
            self.domains[i].update(blocklisted=False, blocklist_expires_at=expires)
            return Cur([])
        if s.startswith("INSERT INTO domain_events"):
            i, kind, detail = params
            self.events.append((i, kind, detail.obj))
            return Cur([])
        raise AssertionError(f"unexpected SQL: {s}")


def run(coro):
    return asyncio.run(coro)


def test_build_lists_writes_and_is_idempotent(tmp_path):
    c = cfg(tmp_path)
    fake = FakeDB([row(1, "commbank-login.top"), row(2, "auspost-track.top", brand_id="auspost", status="confirmed"),
                   row(3, "commbank.com.au", status="confirmed"), row(4, "benign.top", status="benign", final_score=99)])
    res = run(bl.build(fake, cfg=c, watchlist=WL, trigger="test"))
    assert res["listed"] == 2 and res["added"] == 2 and res["removed"] == 0 and res["files_written"]
    assert res["serial"] == 2026111501
    assert [(i, k) for i, k, _ in fake.events] == [(1, "blocklisted"), (2, "blocklisted")]
    assert fake.domains[1]["blocklisted"] and fake.domains[1]["blocklist_expires_at"] == NOW + 90 * DAY
    assert not fake.domains[3]["blocklisted"] and not fake.domains[4]["blocklisted"]
    out = c.out_dir
    assert bl.files_present(out)
    assert _body((out / "domains.txt").read_text(), "#") == ["auspost-track.top", "commbank-login.top"]
    assert "commbank.com.au" not in (out / "rpz.zone").read_text()
    state = fake.kv[bl.KV_STATE]["value"]
    assert state["built_at"] == NOW.isoformat() and state["updated_at"] == NOW.isoformat()

    # same data again: nothing changes, files are not rewritten, serial stays
    mtime = (out / "rpz.zone").stat().st_mtime_ns
    fake.now = NOW + timedelta(minutes=10)
    res2 = run(bl.build(fake, cfg=c, watchlist=WL))
    assert res2["files_written"] is False and res2["serial"] == 2026111501 and res2["added"] == 0
    assert (out / "rpz.zone").stat().st_mtime_ns == mtime
    assert len(fake.events) == 2

    # reviewer marks one false positive: it drops out on the next build, serial goes up
    fake.domains[1]["status"] = "false_positive"
    fake.now = NOW + timedelta(minutes=20)
    res3 = run(bl.build(fake, cfg=c, watchlist=WL))
    assert res3["removed"] == 1 and res3["listed"] == 1 and res3["serial"] == 2026111502
    assert fake.events[-1] == (1, "unblocklisted", {"reason": "marked false positive", "trigger": "manual"})
    assert fake.domains[1]["blocklisted"] is False and fake.domains[1]["blocklist_expires_at"] is None
    assert "commbank-login.top" not in (out / "hosts.txt").read_text()

    # files deleted on disk: rewritten even though the list did not change
    (out / "hosts.txt").unlink()
    fake.now = NOW + timedelta(minutes=30)
    assert run(bl.build(fake, cfg=c, watchlist=WL))["files_written"] is True
    assert (out / "hosts.txt").is_file()


def test_build_skips_entry_when_guarded_update_fails(tmp_path):
    c = cfg(tmp_path)
    fake = FakeDB([row(1, "commbank-login.top")])
    real_execute = fake.execute

    async def racing_execute(sql, params=None):
        if sql.startswith("UPDATE domains SET blocklisted = true"):
            fake.domains[1]["blocklist_excluded"] = True   # excluded on the dashboard mid-build
        return await real_execute(sql, params)
    fake.execute = racing_execute
    res = run(bl.build(fake, cfg=c, watchlist=WL))
    assert res["listed"] == 0 and res["added"] == 0 and fake.events == []
    assert "commbank-login.top" not in (c.out_dir / "domains.txt").read_text()


def test_build_busy_lock_and_rebuild_flag(tmp_path):
    c = cfg(tmp_path)
    fake = FakeDB([row(1, "commbank-login.top")])
    fake.locked = True
    assert run(bl.build(fake, cfg=c, watchlist=WL)) is None
    assert not c.out_dir.exists()
    fake.locked = False
    run(bl.request_rebuild(fake, "test", "me"))
    assert bl.KV_REBUILD in fake.kv
    run(bl.build(fake, cfg=c, watchlist=WL))
    assert bl.KV_REBUILD not in fake.kv                        # request made before the build is cleared


def test_build_fails_closed_when_files_cannot_be_written(tmp_path, monkeypatch):
    c = cfg(tmp_path)
    fake = FakeDB([row(1, "commbank-login.top")])

    def boom(*a):
        raise OSError("read-only")
    monkeypatch.setattr(bl, "write_files", boom)
    with pytest.raises(OSError):
        run(bl.build(fake, cfg=c, watchlist=WL))
    assert bl.KV_STATE not in fake.kv                         # state not recorded: next run retries


def test_rebuild_reason(tmp_path):
    c = cfg(tmp_path)
    fake = FakeDB([row(1, "commbank-login.top")])
    assert run(bl.rebuild_reason(fake, c, 600)) == "first build"
    run(bl.build(fake, cfg=c, watchlist=WL))
    fake.now = NOW + timedelta(seconds=60)
    assert run(bl.rebuild_reason(fake, c, 600)) is None
    fake.timed_events = [(1, "ai_verdict", {}, NOW + timedelta(seconds=30))]
    assert run(bl.rebuild_reason(fake, c, 600)) is None
    fake.timed_events = [(1, "status", {}, NOW + timedelta(seconds=30))]
    assert run(bl.rebuild_reason(fake, c, 600)) == "review change"
    fake.timed_events = []
    (c.out_dir / "rpz.zone").unlink()
    assert run(bl.rebuild_reason(fake, c, 600)) == "files missing"
    run(bl.request_rebuild(fake, "x"))
    assert run(bl.rebuild_reason(fake, c, 600)) == "requested"
    fake.now = NOW + timedelta(seconds=601)
    del fake.kv[bl.KV_REBUILD]
    assert run(bl.rebuild_reason(fake, c, 600)) == "scheduled"


# ---- worker job --------------------------------------------------------------------------------
class FakePool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def connection(self):
        yield self.conn


def test_job(monkeypatch, tmp_path):
    from cybercheck.jobs import blocklist as job_mod
    from cybercheck.worker import Job, JobContext
    import logging

    assert isinstance(job_mod.JOB, Job) and job_mod.JOB.name == "blocklist"
    calls = []

    async def reason(conn, c, interval):
        return None if calls else "first build"

    async def fake_build(conn, *, cfg=None, watchlist=None, trigger="manual"):
        calls.append(trigger)
        return {"listed": 3, "added": 3, "removed": 0}

    monkeypatch.setattr(job_mod.blocklist, "rebuild_reason", reason)
    monkeypatch.setattr(job_mod.blocklist, "build", fake_build)
    monkeypatch.setattr(job_mod.blocklist, "out_dir", lambda: tmp_path)
    ctx = JobContext(settings=None, log=logging.getLogger("t"))

    async def pool():
        return FakePool(object())
    ctx.pool = pool
    assert run(job_mod.run_once(ctx)) == {"listed": 3, "added": 3, "removed": 0, "rebuilt": True}
    assert run(job_mod.run_once(ctx)) == {"listed": 3, "added": 3, "removed": 0, "rebuilt": False}
    assert calls == ["first build"]


# ---- dashboard ---------------------------------------------------------------------------------
class WebConn:
    def __init__(self, listed=None, excluded=None, update_ok=True):
        self.listed = listed or []
        self.excluded = excluded or []
        self.update_ok = update_ok
        self.sql: list[tuple[str, tuple]] = []

    async def execute(self, sql, params=()):
        s = " ".join(sql.split())
        self.sql.append((s, params))
        if "count(*) FILTER" in s:
            return Cur([{"listed": len(self.listed), "confirmed": 1, "automated": 0, "excluded": len(self.excluded),
                         "expiring": 0}])
        if s.startswith("SELECT id, registered_domain, unicode_domain, brand_id, status, final_score"):
            return Cur(self.listed)
        if s.startswith("SELECT id, registered_domain, unicode_domain, brand_id, status, blocklist_excluded_at"):
            return Cur(self.excluded)
        if "FROM domain_events e" in s:
            return Cur([{"at": NOW, "kind": "blocklisted", "detail": {"reason": "<b>r</b>"}, "id": 1,
                         "registered_domain": "commbank-login.top"}])
        if s.startswith("SELECT value FROM kv"):
            return Cur([{"value": {"built_at": NOW.isoformat(), "updated_at": NOW.isoformat(), "serial": 2026111501}}])
        if s.startswith("SELECT updated_at FROM kv"):
            return Cur([])
        if s.startswith("UPDATE domains SET blocklist_excluded"):
            return Cur([{"id": params[-1], "registered_domain": "x.top"}] if self.update_ok else [])
        return Cur([])


@pytest.fixture
def web(monkeypatch, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from cybercheck import db
    from cybercheck.web import pages_blocklist
    from cybercheck.web.common import templates

    conn = WebConn(listed=[{"id": 7, "registered_domain": "<script>alert(1)</script>.top", "unicode_domain": None,
                            "brand_id": "commbank", "status": "confirmed", "final_score": None, "live_state": "live",
                            "blocklist_listed_at": NOW, "blocklist_expires_at": NOW + 90 * DAY}])

    async def pool():
        return FakePool(conn)
    monkeypatch.setattr(db, "pool", pool)
    monkeypatch.setattr(bl, "out_dir", lambda: tmp_path)
    builds = []

    async def build_now(trigger, by=None):
        builds.append((trigger, by))
        return {"listed": 1}
    monkeypatch.setattr(bl, "build_now", build_now)
    app = FastAPI()
    nav: list = []
    pages_blocklist.register(app, templates, nav)
    assert nav == [("/blocklist", "Blocklist")]
    # the dashboard only answers on its own addresses (web.common.allowed_hosts): use one of them
    client = TestClient(app, base_url="http://127.0.0.1:8430")
    client.conn, client.builds, client.dir = conn, builds, tmp_path
    return client


def test_page_renders_and_escapes(web):
    r = web.get("/blocklist?msg=built")
    assert r.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.top" in r.text and "<script>alert(1)" not in r.text
    assert "&lt;b&gt;r&lt;/b&gt;" in r.text
    assert "Blocklist rebuilt." in r.text
    assert 'action="/blocklist/7/exclude"' in r.text and 'action="/blocklist/rebuild"' in r.text
    assert "not built yet" in r.text
    r = web.get("/blocklist?msg=<img src=x>")
    assert r.status_code == 200 and "<img src=x>" not in r.text


def test_file_download_allowlist(web):
    (web.dir / "hosts.txt").write_text("0.0.0.0 x.top\n")
    (web.dir / "secret.env").write_text("TOKEN=1")
    r = web.get("/blocklist/files/hosts.txt")
    assert r.status_code == 200 and r.text == "0.0.0.0 x.top\n"
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["content-security-policy"] == "default-src 'none'"
    assert web.get("/blocklist/files/rpz.zone").status_code == 404          # allowed but not built
    for bad in ("secret.env", "..%2Fsecret.env", "%2E%2E%2Fsecret.env", ".hosts.txt.tmp"):
        assert web.get(f"/blocklist/files/{bad}").status_code == 404


def test_posts_require_same_origin(web):
    for path in ("/blocklist/rebuild", "/blocklist/7/exclude", "/blocklist/7/include"):
        r = web.post(path, headers={"origin": "https://evil.example"}, follow_redirects=False)
        assert r.status_code == 403
        r = web.post(path, headers={"sec-fetch-site": "cross-site"}, follow_redirects=False)
        assert r.status_code == 403
    assert web.builds == []
    assert not any(s.startswith("UPDATE") for s, _ in web.conn.sql)


def test_exclude_records_reviewer_event_and_rebuilds(web):
    r = web.post("/blocklist/7/exclude", headers={"tailscale-user-login": "rev@example.org"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/blocklist?msg=excluded"
    upd = [(s, p) for s, p in web.conn.sql if s.startswith("UPDATE domains SET blocklist_excluded = true")]
    assert upd and upd[0][1] == ("rev@example.org", 7)
    ev = [p for s, p in web.conn.sql if s.startswith("INSERT INTO domain_events")]
    assert ev[0][0] == 7 and ev[0][1] == "blocklist_excluded" and ev[0][2].obj["by"] == "rev@example.org"
    assert any(s.startswith("INSERT INTO kv") and p[0] == bl.KV_REBUILD for s, p in web.conn.sql)
    assert web.builds == [("excluded by rev@example.org", "rev@example.org")]


def test_include_and_rebuild(web):
    r = web.post("/blocklist/7/include", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/blocklist?msg=included"
    assert any(s.startswith("UPDATE domains SET blocklist_excluded = false") for s, _ in web.conn.sql)
    r = web.post("/blocklist/rebuild", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/blocklist?msg=built"
    assert len(web.builds) == 2


def test_exclude_unknown_domain_404(web):
    web.conn.update_ok = False
    assert web.post("/blocklist/999/exclude", follow_redirects=False).status_code == 404
    assert web.builds == []


def test_build_now_reports_busy_and_errors(monkeypatch):
    from cybercheck import db
    fake = FakeDB([])

    async def pool():
        return FakePool(fake)
    monkeypatch.setattr(db, "pool", pool)

    async def busy(conn, **kw):
        return None
    monkeypatch.setattr(bl, "build", busy)
    assert run(bl.build_now("t", "me")) == {"busy": True}
    assert bl.KV_REBUILD in fake.kv

    async def broken(conn, **kw):
        raise RuntimeError("watchlist unreadable")
    monkeypatch.setattr(bl, "build", broken)
    del fake.kv[bl.KV_REBUILD]
    res = run(bl.build_now("t"))
    assert res["error"].startswith("RuntimeError") and bl.KV_REBUILD in fake.kv


def test_publish_script_guards():
    """Static checks only: the script is never run here."""
    script = (Path(__file__).resolve().parent.parent / "scripts" / "publish-blocklist.sh").read_text()
    assert 'BLOCKLIST_PUBLISH_CONFIRMED:-}" == "yes"' in script
    code = [line for line in script.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    guard = next(i for i, line in enumerate(code) if "BLOCKLIST_PUBLISH_CONFIRMED" in line)
    assert guard < next(i for i, line in enumerate(code) if "git" in line or "cp " in line)
    assert "--force" not in script and "push --tags" not in script and "--no-follow-tags" in script
    assert "git add -A" not in script and "git add ." not in script and "commit -a" not in script
    files_line = next(line for line in script.splitlines() if line.startswith("FILES=("))
    assert files_line == "FILES=(" + " ".join(bl.FILES) + ")"
    assert os.access(Path(__file__).resolve().parent.parent / "scripts" / "publish-blocklist.sh", os.X_OK)


# ---- regression: a brand only in a subdomain never blocks the whole registrable domain ----------
def _names(files: dict, name: str, mark: str) -> list[str]:
    return _body(files[name], mark)


def _assert_never_blocks(files: dict, registered: str) -> None:
    """No file blocks the registrable domain itself (and so every subdomain of it)."""
    assert f"||{registered}^" not in files["adguard.txt"]
    assert registered not in _names(files, "domains.txt", "#")
    assert f"address=/{registered}/" not in files["dnsmasq.conf"]
    assert f'"{registered}."' not in files["unbound.conf"]
    rpz = _names(files, "rpz.zone", ";")
    assert f"{registered} CNAME ." not in rpz and f"*.{registered} CNAME ." not in rpz
    assert f"0.0.0.0 {registered}" not in _names(files, "hosts.txt", "#")
    assert all(e["domain"] != registered for e in json.loads(files["blocklist.json"])["entries"])


def test_brand_in_subdomain_of_platform_lists_only_the_hostname():
    """commbank-netbank-login-au.weebly.com is stored under weebly.com (not in the PSL), score 100."""
    host = "commbank-netbank-login-au.weebly.com"
    r = row(1, "weebly.com", final_score=100, hostnames=[host], registered_at=None)
    assert bl.skip_reason(r, cfg(), WL) is None              # it does qualify ...
    sc = bl.scope(r, WL)
    assert not sc.wildcard and sc.hosts == (host,)            # ... but only by hostname
    (e,) = bl.plan([r], NOW, cfg(), WL).entries
    assert e.name == "weebly.com" and not e.wildcard and e.hostnames == [host] and e.names == [host]
    files = bl.render([e], cfg(), NOW, 2026111501)
    _assert_never_blocks(files, "weebly.com")
    assert _names(files, "hosts.txt", "#") == [f"0.0.0.0 {host}"]
    assert _names(files, "adguard.txt", "!") == [f"||{host}^"]
    assert _names(files, "domains.txt", "#") == [host]
    assert _names(files, "rpz.zone", ";")[3:] == [f"{host} CNAME .", f"*.{host} CNAME ."]
    (meta,) = json.loads(files["blocklist.json"])["entries"]
    assert meta["domain"] == host and meta["scope"] == "hostname" and meta["registered_domain"] == "weebly.com"
    import dns.zone
    dns.zone.from_text(files["rpz.zone"], origin="rpz.example.")


def test_kit_on_a_compromised_site_lists_only_the_kit_hostnames():
    """A cPanel AutoSSL certificate shows auspost-com-au-parcel.someplumber.com.au: the business keeps its
    website and its mail (the registrable domain, www and mail are never listed)."""
    kit = "auspost-com-au-parcel.someplumber.com.au"
    for status in ("open", "confirmed"):          # a reviewer's confirmation does not widen it either
        r = row(1, "someplumber.com.au", brand_id="auspost", status=status, final_score=100,
                hostnames=[kit, "www.someplumber.com.au", "mail.someplumber.com.au", "someplumber.com.au"])
        (e,) = bl.plan([r], NOW, cfg(), WL).entries
        assert not e.wildcard and e.hostnames == [kit] and "subdomain" in e.scope_note
        _assert_never_blocks(bl.render([e], cfg(), NOW, 1), "someplumber.com.au")


def test_shared_platform_is_never_wildcarded_even_when_its_name_scores(monkeypatch):
    monkeypatch.setattr(bl, "SHARED_PLATFORMS", bl.SHARED_PLATFORMS | {"commbank-sites.com"})
    r = row(1, "commbank-sites.com", hostnames=["login.commbank-sites.com", "commbank-sites.com"])
    assert bl.brand_in_name("commbank-sites.com", WL)
    sc = bl.scope(r, WL)
    assert not sc.wildcard and sc.hosts == ("login.commbank-sites.com",) and sc.why == "shared hosting platform"
    for name in ("weebly.com", "wordpress.com", "sharepoint.com", "wix.com", "godaddysites.com", "site123.me",
                 "zohosites.com", "hostingersite.com", "pages.dev", "workers.dev", "github.io", "vercel.app",
                 "netlify.app", "firebaseapp.com", "web.app", "blogspot.com", "wixsite.com"):
        assert name in bl.SHARED_PLATFORMS


def test_tenant_of_a_psl_platform_is_its_own_domain():
    """commbank-login.pages.dev is the registrable domain (PSL private section): the tenant is the attacker's."""
    r = row(1, "commbank-login.pages.dev", hostnames=["commbank-login.pages.dev", "x.commbank-login.pages.dev"])
    (e,) = bl.plan([r], NOW, cfg(), WL).entries
    assert e.wildcard and e.names == ["commbank-login.pages.dev"]
    # the brand only in a deeper label of somebody else's tenant: hostnames only
    r2 = row(2, "someone.pages.dev", hostnames=["commbank-login.someone.pages.dev"])
    (e2,) = bl.plan([r2], NOW, cfg(), WL).entries
    assert not e2.wildcard and e2.names == ["commbank-login.someone.pages.dev"]


def test_long_registered_domain_is_listed_by_hostname_only():
    """RDAP says the domain is years older than its first certificate sighting: an established site."""
    name = "commbank-plumbing.top"
    hosts = ["commbank-plumbing.top", "www.commbank-plumbing.top", "mail.commbank-plumbing.top",
             "netbank-login.commbank-plumbing.top"]
    old = row(1, name, hostnames=hosts, registered_at=NOW - 6 * 365 * DAY)
    (e,) = bl.plan([old], NOW, cfg(), WL).entries
    assert not e.wildcard and e.hostnames == ["netbank-login.commbank-plumbing.top"] and "registered" in e.scope_note
    _assert_never_blocks(bl.render([e], cfg(), NOW, 1), name)
    # registered just before the certificate, or no RDAP date (.au is never queried): the whole domain
    for registered_at in (NOW - 5 * DAY, None):
        (e,) = bl.plan([dict(old, registered_at=registered_at)], NOW, cfg(), WL).entries
        assert e.wildcard and e.names == [name]
    assert bl.registered_long_before_seen(dict(old, registered_at=NOW - 400 * DAY)) == 398
    assert bl.registered_long_before_seen(dict(old, registered_at=NOW - 300 * DAY)) is None


def test_hostname_only_domain_with_nothing_to_list_is_not_listed():
    listed = row(1, "someplumber.com.au", status="confirmed", hostnames=["www.someplumber.com.au"],
                 blocklisted=True, blocklist_listed_at=NOW - DAY, blocklist_expires_at=NOW + 89 * DAY)
    p = bl.plan([listed], NOW, cfg(), WL)
    assert p.entries == [] and len(p.removed) == 1
    _r, why, keep = p.removed[0]
    assert "no hostname of its own to list" in why and keep is None


def test_unscorable_name_means_hostnames_only():
    class Broken:
        brands: dict = {}

        def is_official(self, name):
            return False

        def score_hostname(self, name):
            raise RuntimeError("watchlist broken")
    assert bl.brand_in_name("commbank-login.top", Broken()) is False
    assert not bl.scope(row(1, "commbank-login.top"), Broken()).wildcard


def test_build_lists_platform_hostname_and_records_scope(tmp_path):
    c = cfg(tmp_path)
    host = "commbank-netbank-login-au.weebly.com"
    fake = FakeDB([row(1, "weebly.com", final_score=100, hostnames=[host]), row(2, "commbank-login.top")])
    res = run(bl.build(fake, cfg=c, watchlist=WL, trigger="test"))
    assert res["listed"] == 2 and res["hostnames_only"] == 1
    ev = {i: d for i, k, d in fake.events if k == "blocklisted"}
    assert ev[1]["scope"] == "hostnames" and ev[1]["hostnames"] == [host] and ev[2]["scope"] == "domain"
    files = {n: (c.out_dir / n).read_text() for n in bl.FILES}
    _assert_never_blocks(files, "weebly.com")
    assert _body(files["domains.txt"], "#") == ["commbank-login.top", host]
    assert bl.hostname_only_entries(c.out_dir) == {"weebly.com": [host]}
    assert bl.hostname_only_entries(tmp_path / "missing") == {}


# ---- regression: the score floor is 90, whatever BLOCKLIST_MIN_FINAL_SCORE says -------------------
def test_score_floor_is_90(monkeypatch):
    from cybercheck import config
    assert bl.BuildConfig(min_final_score=80).min_final_score == 90
    assert bl.BuildConfig(min_final_score=95).min_final_score == 95
    for value, expected in (("80", 90), ("85", 90), ("89", 90), ("90", 90), ("97", 97), ("", 90)):
        monkeypatch.setenv("BLOCKLIST_MIN_FINAL_SCORE", value)
        config.settings.cache_clear()
        try:
            assert config.settings().blocklist_min_final_score == expected
            assert bl.BuildConfig.from_env().min_final_score == expected
        finally:
            config.settings.cache_clear()
    # name-only: confidence.py caps the score at 89, which a lowered setting must not reach
    name_only = row(1, "westpac-login-verify-au.top", final_score=89, ai_verdict=None, ai_confidence=None)
    assert bl.skip_reason(name_only, bl.BuildConfig(min_final_score=80), WL) == "combined score below 90"


def test_build_selects_with_the_floor(tmp_path):
    fake = FakeDB([row(1, "commbank-login.top", final_score=89)])
    seen = []
    real = fake.execute

    async def spy(sql, params=None):
        if sql.lstrip().startswith("SELECT id, registered_domain"):
            seen.append(params)
        return await real(sql, params)
    fake.execute = spy
    res = run(bl.build(fake, cfg=cfg(tmp_path, min_final_score=80), watchlist=WL))
    assert seen == [{"min": 90}] and res["listed"] == 0


# ---- regression: CZDS-derived names wait for explicit licence terms ----------------------------
def test_czds_domains_are_held_back_until_terms_are_set(tmp_path, monkeypatch):
    rows = [row(1, "commbank-login.top", source="czds"),
            row(2, "commbank-verify.top", source="czds", status="confirmed", blocklisted=True,
                blocklist_listed_at=NOW - DAY, blocklist_expires_at=NOW + 89 * DAY),
            row(3, "auspost-parcel.top", brand_id="auspost")]
    p = bl.plan(rows, NOW, cfg(), WL)
    assert [e.id for e in p.entries] == [3] and p.held_czds == 2
    assert [(r["id"], why) for r, why, _ in p.removed] == [(2, bl.CZDS_REASON)]
    assert {e.id for e in bl.plan(rows, NOW, cfg(czds_ok=True), WL).entries} == {1, 2, 3}
    monkeypatch.delenv("BLOCKLIST_CZDS_TERMS_OK", raising=False)
    assert bl.BuildConfig.from_env().czds_ok is False
    monkeypatch.setenv("BLOCKLIST_CZDS_TERMS_OK", "true")      # only an explicit "yes" counts
    assert bl.BuildConfig.from_env().czds_ok is False
    monkeypatch.setenv("BLOCKLIST_CZDS_TERMS_OK", "yes")
    assert bl.BuildConfig.from_env().czds_ok is True
    fake = FakeDB([dict(r) for r in rows])
    res = run(bl.build(fake, cfg=cfg(tmp_path), watchlist=WL))
    assert res["held_czds"] == 2 and res["listed"] == 1
    assert "commbank-login.top" not in (tmp_path / "blocklist" / "domains.txt").read_text()


def test_publish_script_refuses_without_a_licence():
    script = (Path(__file__).resolve().parent.parent / "scripts" / "publish-blocklist.sh").read_text()
    code = [line for line in script.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    guard = next(i for i, line in enumerate(code) if 'grep -qiF "not yet decided"' in line)
    assert code[guard].lstrip().startswith("! grep") and "die" in code[guard + 1]
    assert guard < next(i for i, line in enumerate(code) if line.lstrip().startswith("cp "))
    assert "BLOCKLIST_CZDS_TERMS_OK" in script and "s1.1" in script


def test_page_marks_hostname_only_entries(web):
    (web.dir / "blocklist.json").write_text(json.dumps({"entries": [
        {"domain": "login.x.top", "scope": "hostname", "registered_domain": "<script>alert(1)</script>.top"}]}))
    t = web.get("/blocklist").text
    assert "hostnames only" in t and "login.x.top" in t and "<script>alert(1)" not in t


# ---- verifier regressions ---------------------------------------------------------------------------
def test_confirmed_aged_lookalike_is_still_blocked_whole():
    """A lookalike held for years (or bought aged) and confirmed by a reviewer: its own name impersonates
    the brand, so it is listed with every subdomain. Hostnames-only would drop the apex and www, leaving
    nothing to list, and a domain that was listed would be removed."""
    name = "commbank-netbank-login.top"
    hosts = [name, f"www.{name}"]
    aged = dict(registered_at=NOW - 3 * 365 * DAY, hostnames=hosts)
    (e,) = bl.plan([row(1, name, status="confirmed", **aged)], NOW, cfg(), WL).entries
    assert e.wildcard and e.names == [name] and e.hostnames == [f"www.{name}"]
    listed = row(1, name, status="confirmed", blocklisted=True, blocklist_listed_at=NOW - DAY,
                 blocklist_expires_at=NOW + 89 * DAY, **aged)
    p = bl.plan([listed], NOW, cfg(), WL)
    assert [x.id for x in p.entries] == [1] and p.entries[0].wildcard and p.removed == []
    # unreviewed: the age rule still holds it to its hostnames (none left here, so not listed automatically)
    p = bl.plan([row(1, name, **aged)], NOW, cfg(), WL)
    assert p.entries == []
    # a confirmed hacked site keeps the brand-in-subdomain rule whatever its age
    kit = "netbank-login.someplumber.com.au"
    (e,) = bl.plan([row(2, "someplumber.com.au", status="confirmed", hostnames=[kit, "someplumber.com.au"],
                        registered_at=NOW - 9 * 365 * DAY)], NOW, cfg(), WL).entries
    assert not e.wildcard and e.names == [kit]


def test_subdomain_context_never_widens_to_a_business_name():
    """bendigo-plumbing.com.au does not impersonate Bendigo Bank on its own (a place name needs bait or AU
    context). An attacker on that hacked site who picks au-login.bendigo-plumbing.com.au supplies the context
    from the subdomain; the business must still not be blocked as a whole."""
    wl = Watchlist({
        "brands": [{"id": "bendigo", "name": "Bendigo Bank", "keywords": ["bendigo"], "needs_context": True,
                    "official_domains": ["bendigobank.com.au"]}],
        "bait_words": {"strong": ["login", "verify"], "weak": ["secure"]},
        "au_context_tokens": ["au"],
    })
    host = "au-login.bendigo-plumbing.com.au"
    hit = wl.score_hostname(host)
    assert hit is not None and hit.registered_domain == "bendigo-plumbing.com.au"
    r = row(1, "bendigo-plumbing.com.au", brand_id="bendigo", status="confirmed",
            hostnames=[host, "bendigo-plumbing.com.au", "www.bendigo-plumbing.com.au"])
    assert not bl.brand_in_name("bendigo-plumbing.com.au", wl)
    (e,) = bl.plan([r], NOW, cfg(), wl).entries
    assert not e.wildcard and e.names == [host]
    _assert_never_blocks(bl.render([e], cfg(), NOW, 1), "bendigo-plumbing.com.au")
