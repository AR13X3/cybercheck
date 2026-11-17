"""Tests for the enrich module. Offline: fake resolver, httpx.MockTransport, fake database pool."""
from __future__ import annotations

import asyncio
import functools
import logging
import socket
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import dns.exception
import dns.name
import dns.resolver
import httpx
import pytest

from cybercheck import db, enrich
from cybercheck.enrich import (DnsResult, EnrichConfig, RdapClient, backoff_point, build_update_sql, decide,
                               evaluate_takedown, next_check, rdap_due)

UTC = timezone.utc
NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
CFG = EnrichConfig()


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any real TCP/UDP connection attempt fails the test."""
    def refuse(self, *a, **kw):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            raise AssertionError("test tried to open a network connection")
        return real_connect(self, *a, **kw)
    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError("test tried to open a network connection")))


def dom(**kw) -> dict:
    d = dict(id=1, registered_domain="commbank-login.top", tld="top", hostname="www.commbank-login.top",
             tier="high", status="open", status_changed_at=None, first_seen=NOW - timedelta(minutes=1),
             watch_until=NOW + timedelta(days=14), dns_state="unknown", ips=[], asn=None, rdap_status=[],
             live_state="unknown", first_live_at=None, last_live_at=None, ai_verdict=None, reported_at=None,
             takedown_at=None, enriched_at=None, enrich_state={})
    d.update(kw)
    return d


def nx(name="x.top", soa=True):
    """An NXDOMAIN like dnspython raises: the response carries the zone SOA unless soa=False (Quad9 block)."""
    import dns.message
    import dns.rcode
    import dns.rrset
    qname = dns.name.from_text(name)
    resp = dns.message.make_response(dns.message.make_query(qname, "A"))
    resp.set_rcode(dns.rcode.NXDOMAIN)
    if soa:
        resp.authority.append(dns.rrset.from_text(
            name.split(".", 1)[-1] + ".", 300, "IN", "SOA", "a.nic.top. hostmaster.nic.top. 1 7200 900 1209600 300"))
    return dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: resp})


def dnsr(state, reg_state=None, ips=()):
    return DnsResult(state=state, reg_state=reg_state or state, ips=list(ips), names={})


# ---------------------------------------------------------------- sample registry data

RDAP_DOMAIN = {
    "objectClassName": "domain", "ldhName": "COMMBANK-LOGIN.TOP",
    "status": ["client transfer prohibited", "server hold"],
    "events": [{"eventAction": "registration", "eventDate": "2026-11-14T03:04:05Z"},
               {"eventAction": "expiration", "eventDate": "2027-11-14T03:04:05Z"}],
    "entities": [
        {"objectClassName": "entity", "roles": ["registrant"],
         "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED"], ["email", {}, "text", "owner@example.net"]]]},
        {"objectClassName": "entity", "roles": ["registrar"], "handle": "999",
         "publicIds": [{"type": "IANA Registrar ID", "identifier": "1479"}],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "NameSilo, LLC"]]],
         "entities": [{"objectClassName": "entity", "roles": ["abuse"],
                       "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", ""],
                                                ["tel", {"type": "voice"}, "uri", "tel:+1.6024928798"],
                                                ["email", {}, "text", "Abuse@NameSilo.com"]]]}]},
    ],
}

RDAP_IP = {
    "objectClassName": "ip network", "handle": "NET-104-16-0-0-1", "name": "CLOUDFLARENET", "country": "US",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
                  "entities": [{"roles": ["abuse", "noc"],
                                "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                                         ["email", {}, "text", "mailto:abuse@cloudflare.com"]]]}]}],
}

BOOT_DNS = {"services": [[["top", "xyz"], ["https://rdap.nic.top/"]],
                         [["com", "net"], ["http://rdap.verisign.com/com/v1/", "https://rdap.verisign.com/com/v1/"]],
                         [["dev"], ["https://pubapi.registry.google/rdap/"]]]}
BOOT_V4 = {"services": [[["104.0.0.0/8", "8.0.0.0/8"], ["https://rdap.arin.net/registry/"]],
                        [["1.0.0.0/8", "103.0.0.0/8"], ["https://rdap.apnic.net/"]]]}
BOOT_V6 = {"services": [[["2400::/12"], ["https://rdap.apnic.net/"]]]}


def rdap_client(handler, **kw) -> RdapClient:
    c = RdapClient(min_interval=kw.pop("min_interval", 0.0), max_queue=kw.pop("max_queue", 20.0))
    c._apply_bootstrap("dns", BOOT_DNS, 1e12)
    c._apply_bootstrap("ipv4", BOOT_V4, 1e12)
    c._apply_bootstrap("ipv6", BOOT_V6, 1e12)
    c.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return c


# ---------------------------------------------------------------- parsing

def test_parse_domain_rdap():
    r = enrich.parse_domain_rdap(RDAP_DOMAIN)
    assert r["registrar"] == "NameSilo, LLC"
    assert r["iana_id"] == 1479
    assert r["abuse_email"] == "Abuse@namesilo.com"      # nested under the registrar, not the registrant's
    assert r["status"] == ["client transfer prohibited", "server hold"]
    assert r["registered_at"] == datetime(2026, 11, 14, 3, 4, 5, tzinfo=UTC)
    assert enrich.has_hold(r["status"])


def test_parse_domain_rdap_hostile_and_sparse():
    assert enrich.parse_domain_rdap({})["registrar"] is None
    junk = {"entities": "nope", "status": [1, None, "x" * 500], "events": [{"eventAction": "registration",
                                                                           "eventDate": "not a date"}]}
    r = enrich.parse_domain_rdap(junk)
    assert r["registrar"] is None and r["registered_at"] is None
    assert r["status"] == ["x" * 60]
    top_abuse = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg\x00 Inc"]]]},
                              {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "a@b.co"]]]}]}
    r = enrich.parse_domain_rdap(top_abuse)
    assert r["registrar"] == "Reg  Inc" and r["abuse_email"] == "a@b.co"


@pytest.mark.parametrize("value,expected", [
    ("abuse@example.com", "abuse@example.com"), ("mailto:Abuse@Example.COM", "Abuse@example.com"),
    ("<abuse@x.com.au>", "abuse@x.com.au"), ("not an email", None), ("a@b", None), ("a@b.c<script>", None),
    (None, None), ("x" * 300 + "@a.com", None),
])
def test_clean_email(value, expected):
    assert enrich.clean_email(value) == expected


@pytest.mark.parametrize("statuses,hold", [
    (["clientHold"], True), (["server hold"], True), (["CLIENT_HOLD"], True), (["client-hold"], True),
    (["client transfer prohibited", "active"], False), ([], False), (None, False), (["serverRenewProhibited"], False),
])
def test_has_hold(statuses, hold):
    assert enrich.has_hold(statuses) is hold


def test_parse_ip_rdap_nested_abuse():
    r = enrich.parse_ip_rdap(RDAP_IP)
    assert r["abuse_email"] == "abuse@cloudflare.com"
    assert r["network"] == "CLOUDFLARENET" and r["country"] == "US"


def test_bootstrap_lookup():
    c = RdapClient()
    c._apply_bootstrap("dns", BOOT_DNS, 0)
    c._apply_bootstrap("ipv4", BOOT_V4, 0)
    c._apply_bootstrap("ipv6", BOOT_V6, 0)
    assert c.base_for_domain("commbank-login.top") == "https://rdap.nic.top/"
    assert c.base_for_domain("x.com") == "https://rdap.verisign.com/com/v1/"   # https preferred
    assert c.base_for_domain("x.com.au") is None
    assert c.base_for_ip("104.16.1.1") == "https://rdap.arin.net/registry/"
    assert c.base_for_ip("103.1.2.3") == "https://rdap.apnic.net/"
    assert c.base_for_ip("2401:db00::1") == "https://rdap.apnic.net/"
    assert c.base_for_ip("9.9.9.9") is None
    assert {"rdap.nic.top", "rdap.verisign.com", "rdap.arin.net", "rdap.apnic.net"} <= c.allowed_hosts
    assert "http" not in {h.split(":")[0] for h in c.dns_map.values() if not h.startswith("https://")}


def test_cymru_names_and_parsing():
    assert enrich.cymru_origin_name("104.16.1.2") == "2.1.16.104.origin.asn.cymru.com"
    v6 = enrich.cymru_origin_name("2606:4700::1")
    assert v6.endswith(".origin6.asn.cymru.com") and v6.startswith("1.0.0.0.")
    o = enrich.parse_cymru_origin(["13335 | 104.16.0.0/13 | US | arin | 2014-03-28",
                                   "13335 209242 | 104.16.0.0/20 | US | arin | 2014-03-28", "garbage"])
    assert o == {"asn": 13335, "prefix": "104.16.0.0/20", "country": "US", "rir": "arin"}
    assert enrich.parse_cymru_origin(["x | y"]) is None
    assert enrich.parse_cymru_asname(["13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"]) \
        == "CLOUDFLARENET - Cloudflare, Inc., US"


def test_primary_ip_prefers_global_v4():
    assert enrich.primary_ip(["127.0.0.1", "2606:4700::1", "104.16.1.1"]) == "104.16.1.1"
    assert enrich.primary_ip(["10.0.0.1", "2606:4700::1"]) == "2606:4700::1"
    assert enrich.primary_ip(["0.0.0.0", "127.0.0.1"]) is None


# ---------------------------------------------------------------- schedule

def test_backoff_sequence_then_none_after_watch_window():
    fs = NOW
    d = dom(first_seen=fs, watch_until=fs + timedelta(days=14))
    t, seen = fs, []
    for _ in range(40):
        n = next_check(d, t, CFG)
        if n is None:
            break
        seen.append(n - fs)
        t = n
    m, h = timedelta(minutes=1), timedelta(hours=1)
    assert seen[:7] == [10 * m, 30 * m, h, 3 * h, 6 * h, 12 * h, 24 * h]
    assert seen[7:] == [timedelta(days=k) for k in range(2, 14)]
    assert next_check(d, fs + timedelta(days=13), CFG) is None


def test_backoff_when_behind_skips_missed_points():
    fs = NOW - timedelta(hours=5)
    assert backoff_point(fs, NOW) == fs + timedelta(hours=6)
    fs = NOW - timedelta(hours=26)
    assert backoff_point(fs, NOW) == fs + timedelta(days=2)
    assert backoff_point(NOW - timedelta(minutes=8), NOW) == NOW - timedelta(minutes=8) + timedelta(minutes=30)


def test_tracked_hourly_for_30_days_then_stop():
    confirmed_at = NOW - timedelta(days=5)
    d = dom(first_seen=NOW - timedelta(days=20), watch_until=NOW - timedelta(days=6), status="confirmed",
            status_changed_at=confirmed_at)
    assert next_check(d, NOW, CFG) == NOW + timedelta(hours=1)
    end = confirmed_at + timedelta(days=30)
    assert next_check(d, end - timedelta(minutes=20), CFG) == end
    assert next_check(d, end, CFG) is None
    # reported later than confirmed: the window runs from the report
    d2 = dict(d, reported_at=NOW - timedelta(days=1))
    assert next_check(d2, end + timedelta(days=1), CFG) == end + timedelta(days=1, hours=1)
    # AI phishing verdict alone also tracks (window from first_seen)
    d3 = dom(first_seen=NOW - timedelta(days=29, hours=23, minutes=30), watch_until=NOW - timedelta(days=15),
             ai_verdict="phishing")
    assert next_check(d3, NOW, CFG) == d3["first_seen"] + timedelta(days=30)
    # a false positive with an AI phishing verdict is not tracked
    assert not enrich.is_tracked(dict(d3, status="false_positive"))


def test_tracked_inside_window_takes_the_earlier_point():
    d = dom(first_seen=NOW - timedelta(minutes=12), status="confirmed", status_changed_at=NOW)
    assert next_check(d, NOW, CFG) == d["first_seen"] + timedelta(minutes=30)


def test_retry_soon_caps_the_next_check():
    d = dom(first_seen=NOW - timedelta(days=3))
    assert next_check(d, NOW, CFG, retry_soon=True) == NOW + timedelta(minutes=10)


def test_rdap_due():
    d = dom()
    assert rdap_due(d, {}, NOW, CFG)
    st = {"rdap_at": enrich.iso(NOW - timedelta(hours=3))}
    assert not rdap_due(d, st, NOW, CFG)
    assert rdap_due(d, {"rdap_at": enrich.iso(NOW - timedelta(hours=24))}, NOW, CFG)
    assert rdap_due(dom(status="confirmed"), st, NOW, CFG)            # hourly when confirmed
    assert rdap_due(dom(reported_at=NOW - timedelta(days=1)), st, NOW, CFG)
    failing = {"rdap_fail": 3, "rdap_fail_at": enrich.iso(NOW - timedelta(hours=2))}
    assert not rdap_due(d, failing, NOW, CFG)                         # back-off 4 h after 3 failures
    assert rdap_due(d, dict(failing, rdap_fail_at=enrich.iso(NOW - timedelta(hours=5))), NOW, CFG)


# ---------------------------------------------------------------- DNS

class FakeResolver:
    def __init__(self, answers):
        self.answers = answers
        self.queries = []

    async def resolve(self, qname, rdtype="A", search=None, **kw):
        name = str(qname).rstrip(".").lower()
        self.queries.append((name, rdtype))
        v = self.answers.get((name, rdtype), dns.resolver.NoAnswer())
        if isinstance(v, BaseException):
            raise v
        if rdtype == "TXT":
            return [SimpleNamespace(strings=(x.encode(),)) for x in v]
        return [SimpleNamespace(address=x) for x in v]


def run(coro):
    return asyncio.run(coro)


def test_dns_resolves_hostname_ips_first_and_dedupe():
    r = FakeResolver({("commbank-login.top", "A"): ["1.1.1.1", "2.2.2.2"],
                      ("www.commbank-login.top", "A"): ["2.2.2.2"],
                      ("www.commbank-login.top", "AAAA"): ["2606:4700::1"]})
    res = run(enrich.dns_check(r, "commbank-login.top", "www.commbank-login.top"))
    assert res.state == "resolves" and res.reg_state == "resolves"
    assert res.ips == ["2.2.2.2", "2606:4700::1", "1.1.1.1"]
    assert set(res.names) == {"commbank-login.top", "www.commbank-login.top"}


def test_dns_states():
    r = FakeResolver({("gone.top", "A"): nx("gone.top"), ("gone.top", "AAAA"): nx("gone.top")})
    assert run(enrich.dns_check(r, "gone.top", None)).state == "nxdomain"
    r = FakeResolver({})
    assert run(enrich.dns_check(r, "empty.top", None)).state == "no_answer"
    r = FakeResolver({("slow.top", "A"): dns.exception.Timeout(), ("slow.top", "AAAA"): dns.resolver.NoNameservers()})
    res = run(enrich.dns_check(r, "slow.top", None))
    assert res.state == "error" and "timeout" in res.names["slow.top"]["error"]
    # apex has no address but the phishing hostname does
    r = FakeResolver({("www.apex.top", "A"): ["5.6.7.8"]})
    res = run(enrich.dns_check(r, "apex.top", "www.apex.top"))
    assert res.state == "resolves" and res.reg_state == "no_answer" and res.ips == ["5.6.7.8"]
    # apex NXDOMAIN wins over a hostname error
    r = FakeResolver({("x.top", "A"): nx("x.top"), ("x.top", "AAAA"): nx("x.top"),
                      ("a.x.top", "A"): dns.exception.Timeout()})
    assert run(enrich.dns_check(r, "x.top", "a.x.top")).state == "nxdomain"


def test_dns_ignores_bad_or_foreign_hostname():
    r = FakeResolver({("ok.top", "A"): ["1.2.3.4"]})
    res = run(enrich.dns_check(r, "ok.top", "www.other.top"))
    assert list(res.names) == ["ok.top"]
    res = run(enrich.dns_check(r, "ok.top", "*.ok.top"))
    assert list(res.names) == ["ok.top"]
    res = run(enrich.dns_check(r, "bad name/../x", None))
    assert res.state == "error" and r.queries == [("ok.top", "A"), ("ok.top", "AAAA")] * 2


def test_make_resolver_uses_only_configured_resolvers(monkeypatch):
    monkeypatch.setattr(enrich, "settings", lambda: SimpleNamespace(dns_resolvers=["9.9.9.9", "bogus", "1.1.1.1"]))
    r = enrich.make_resolver(CFG)
    assert [str(n) for n in r.nameservers] == ["9.9.9.9", "1.1.1.1"]
    assert r.lifetime == 3.0
    monkeypatch.setattr(enrich, "settings", lambda: SimpleNamespace(dns_resolvers=["nope"]))
    with pytest.raises(RuntimeError):
        enrich.make_resolver(CFG)


# ---------------------------------------------------------------- decide / takedown

def test_first_enrichment_resolves():
    d = dom()
    rdap = {"state": "ok", **enrich.parse_domain_rdap(RDAP_DOMAIN)}
    ipinfo = {"ip": "104.16.1.1", "asn": 13335, "as_name": "CLOUDFLARENET", "country": "US",
              "abuse_email": "abuse@cloudflare.com", "cached": False}
    up = decide(d, dnsr("resolves", ips=["104.16.1.1"]), rdap, ipinfo, NOW, CFG)
    assert up.cols["dns_state"] == "resolves" and up.cols["ips"] == ["104.16.1.1"]
    assert up.cols["registrar"] == "NameSilo, LLC" and up.cols["registrar_iana_id"] == 1479
    assert up.cols["registrar_abuse_email"] == "Abuse@namesilo.com"
    assert up.cols["asn"] == 13335 and up.cols["hosting_abuse_email"] == "abuse@cloudflare.com"
    assert [e[0] for e in up.events] == ["dns_resolves"] and up.events[0][1]["first"] is True
    assert [c[0] for c in up.checks] == ["dns", "rdap", "asn"]
    assert up.state["resolved_at"] and up.state["rdap_at"] and up.state["dns"] == "resolves"
    assert up.next_check_at == d["first_seen"] + timedelta(minutes=10)
    assert up.takedown is None                    # server hold, but the domain is not tracked
    # second check, still resolving, cached IP info: no new event, no asn row
    d2 = dom(enrich_state=up.state, dns_state="resolves")
    up2 = decide(d2, dnsr("resolves", ips=["104.16.1.1"]), None, dict(ipinfo, cached=True), NOW, CFG)
    assert up2.events == [] and [c[0] for c in up2.checks] == ["dns"]


def test_dns_error_keeps_last_real_state_and_retries_soon():
    d = dom(dns_state="resolves", enrich_state={"dns": "resolves", "resolved_at": enrich.iso(NOW)},
            first_seen=NOW - timedelta(days=2))
    up = decide(d, dnsr("error"), None, None, NOW, CFG)
    assert "dns_state" not in up.cols and "ips" not in up.cols
    assert up.state["dns_err"] == 1 and up.next_check_at == NOW + timedelta(minutes=10)
    up = decide(dom(), dnsr("error"), {"state": "deferred"}, None, NOW, CFG)
    assert up.cols["dns_state"] == "error"


def test_nxdomain_event_when_it_stops_resolving():
    d = dom(dns_state="resolves", ips=["1.2.3.4"], enrich_state={"dns": "resolves", "resolved_at": enrich.iso(NOW)})
    up = decide(d, dnsr("nxdomain"), None, None, NOW, CFG)
    assert up.events == [("nxdomain", {"previous_ips": ["1.2.3.4"]})]
    assert up.cols["ips"] == [] and up.takedown is None


def tracked(**kw):
    base = dict(status="confirmed", status_changed_at=NOW - timedelta(hours=5), first_seen=NOW - timedelta(hours=10),
                first_live_at=NOW - timedelta(hours=9), reported_at=NOW - timedelta(hours=4), dns_state="resolves",
                enrich_state={"dns": "resolves", "resolved_at": enrich.iso(NOW - timedelta(hours=10)),
                              "rdap_at": enrich.iso(NOW - timedelta(minutes=30))})
    base.update(kw)
    return dom(**base)


def test_nxdomain_takedown_needs_two_consecutive_checks():
    d = tracked()
    first = NOW
    up1 = decide(d, dnsr("nxdomain"), None, None, first, CFG)
    assert up1.takedown is None and up1.state["pending"]["nxdomain"]["n"] == 1
    assert up1.next_check_at == first + timedelta(hours=1)
    # an inconclusive lookup in between neither confirms nor clears
    d2 = dict(d, dns_state="nxdomain", enrich_state=up1.state)
    up_err = decide(d2, dnsr("error"), None, None, first + timedelta(hours=1), CFG)
    assert up_err.takedown is None and up_err.state["pending"]["nxdomain"]["n"] == 1
    d3 = dict(d2, enrich_state=up_err.state)
    second = first + timedelta(hours=2)
    up2 = decide(d3, dnsr("nxdomain"), None, None, second, CFG)
    assert up2.takedown == ("nxdomain", first)
    assert up2.cols["takedown_at"] == first and up2.cols["takedown_signal"] == "nxdomain"
    assert up2.next_check_at is None and "pending" not in up2.state
    kind, detail = up2.events[-1]
    assert kind == "taken_down" and detail["signal"] == "nxdomain"
    assert detail["hours_from_first_seen"] == 10.0
    assert detail["hours_from_first_live"] == 9.0
    assert detail["hours_from_reported"] == 4.0


def test_blip_clears_pending():
    d = tracked()
    up1 = decide(d, dnsr("nxdomain"), None, None, NOW, CFG)
    d2 = dict(d, enrich_state=up1.state)
    up2 = decide(d2, dnsr("resolves", ips=["1.2.3.4"]), None, None, NOW + timedelta(hours=1), CFG)
    assert up2.takedown is None and "pending" not in up2.state
    assert [e[0] for e in up2.events] == ["dns_resolves"]   # came back


def test_rdap_hold_is_immediate():
    d = tracked()
    up = decide(d, dnsr("resolves", ips=["1.2.3.4"]), {"state": "ok", "status": ["clientHold"]}, None, NOW, CFG)
    assert up.takedown == ("rdap_hold", NOW)
    assert up.cols["rdap_status"] == ["clientHold"]
    # a hold stored by an earlier lookup counts from when it was seen
    seen = NOW - timedelta(minutes=30)
    d2 = tracked(rdap_status=["server hold"])
    up2 = decide(d2, dnsr("nxdomain"), None, None, NOW, CFG)
    assert up2.takedown == ("rdap_hold", seen)
    # ... but not while the domain resolves (the stored hold is contradicted / stale)
    assert decide(d2, dnsr("resolves", ips=["1.2.3.4"]), None, None, NOW, CFG).takedown is None
    # ... nor when that lookup predates the domain going up (hold lifted before it went live)
    early = tracked(rdap_status=["clientHold"], first_live_at=None,
                    enrich_state={"dns": "resolves", "resolved_at": enrich.iso(NOW - timedelta(hours=2)),
                                  "rdap_at": enrich.iso(NOW - timedelta(hours=3))})
    up3 = decide(early, dnsr("no_answer"), {"state": "deferred"}, None, NOW, CFG)
    assert up3.takedown is None


def test_http_gone_needs_first_live_and_two_checks():
    d = tracked(live_state="down")
    up1 = decide(d, dnsr("resolves", ips=["1.2.3.4"]), None, None, NOW, CFG)
    assert up1.takedown is None and up1.state["pending"]["http_gone"]["n"] == 1
    d2 = dict(d, enrich_state=up1.state)
    page_down = NOW - timedelta(minutes=40)
    up2 = decide(d2, dnsr("resolves", ips=["1.2.3.4"]), None, None, NOW + timedelta(hours=1), CFG,
                 page_down_at=page_down)
    assert up2.takedown == ("http_gone", page_down)   # the fetcher's first observation
    never_live = tracked(live_state="down", first_live_at=None)
    up3 = decide(dict(never_live, enrich_state=up1.state), dnsr("resolves"), None, None, NOW, CFG)
    assert up3.takedown is None and "http_gone" not in up3.state.get("pending", {})


def test_no_takedown_for_untracked_or_never_up():
    open_dom = dom(enrich_state={"dns": "resolves", "resolved_at": enrich.iso(NOW),
                                 "pending": {"nxdomain": {"since": enrich.iso(NOW), "n": 1}}})
    up = decide(open_dom, dnsr("nxdomain"), None, None, NOW, CFG)
    assert up.takedown is None and "pending" not in up.state
    never_up = dom(status="confirmed", status_changed_at=NOW)
    up = decide(never_up, dnsr("nxdomain"), {"state": "ok", "status": ["serverHold"]}, None, NOW, CFG)
    assert up.takedown is None


def test_evaluate_takedown_skips_already_taken_down():
    d = tracked(takedown_at=NOW)
    assert evaluate_takedown(d, d["enrich_state"], dnsr("nxdomain"), None, NOW) == ({}, None)


def test_rdap_failures_back_off_and_unsupported_is_quiet():
    d = dom()
    up = decide(d, dnsr("resolves"), {"state": "error", "http_status": 503}, None, NOW, CFG)
    assert up.state["rdap_fail"] == 1 and "rdap_at" not in up.state
    assert [c[0] for c in up.checks] == ["dns", "rdap"]
    up = decide(d, dnsr("resolves"), {"state": "unsupported", "tld": "au"}, None, NOW, CFG)
    assert up.state["rdap_at"] and [c[0] for c in up.checks] == ["dns", "rdap"]
    d2 = dom(enrich_state=up.state)
    up = decide(d2, dnsr("resolves"), {"state": "unsupported", "tld": "au"}, None, NOW, CFG)
    assert [c[0] for c in up.checks] == ["dns"]       # recorded once, not every day


def test_ip_change_resets_hosting_abuse():
    d = dom(enrich_state={"ip": "1.1.1.1"})
    up = decide(d, dnsr("resolves", ips=["2.2.2.2"]), None,
                {"ip": "2.2.2.2", "asn": 64500, "as_name": "X", "country": "AU", "abuse_email": None,
                 "partial": False, "cached": True}, NOW, CFG)
    assert up.cols["hosting_abuse_email"] is None and up.cols["asn"] == 64500 and up.state["ip"] == "2.2.2.2"
    assert [c[0] for c in up.checks] == ["dns", "asn"]


def test_build_update_sql_whitelist():
    sql, params = build_update_sql({"dns_state": "resolves", "ips": ["1.2.3.4"]})
    assert "ips = %s::text[]" in sql and sql.endswith("WHERE id = %s") and params == ["resolves", ["1.2.3.4"]]
    with pytest.raises(ValueError):
        build_update_sql({"status": "confirmed"})
    with pytest.raises(ValueError):
        build_update_sql({"live_state = 'x', status": 1})


# ---------------------------------------------------------------- RDAP client

def test_rdap_lookup_ok_and_not_found():
    calls = []

    def handler(req):
        calls.append(str(req.url))
        if req.url.path == "/domain/commbank-login.top":
            return httpx.Response(200, json=RDAP_DOMAIN)
        return httpx.Response(404, json={"errorCode": 404})

    async def go():
        c = rdap_client(handler)
        ok = await c.lookup_domain("commbank-login.top")
        nf = await c.lookup_domain("missing.top")
        un = await c.lookup_domain("anz-login.com.au")
        await c.client.aclose()
        return ok, nf, un
    ok, nf, un = run(go())
    assert ok["state"] == "ok" and ok["registrar"] == "NameSilo, LLC" and "data" not in ok
    assert nf["state"] == "not_found"
    assert un == {"state": "unsupported", "tld": "au"}
    assert calls == ["https://rdap.nic.top/domain/commbank-login.top", "https://rdap.nic.top/domain/missing.top"]


def test_rdap_platform_suffix_is_skipped():
    def handler(req):
        raise AssertionError("no request expected")

    async def go():
        c = rdap_client(handler)
        r = await c.lookup_domain("commbank-login.pages.dev")
        await c.client.aclose()
        return r
    assert run(go()) == {"state": "platform", "parent": "pages.dev"}


def test_rdap_wrong_answer_rejected():
    def handler(req):
        return httpx.Response(200, json={"objectClassName": "domain", "ldhName": "other.top"})

    async def go():
        c = rdap_client(handler)
        r = await c.lookup_domain("commbank-login.top")
        await c.client.aclose()
        return r
    assert run(go())["state"] == "error"


def test_rdap_429_backs_off_host():
    calls = []

    def handler(req):
        calls.append(req.url.host)
        return httpx.Response(429, headers={"Retry-After": "120"})

    async def go():
        c = rdap_client(handler)
        r1 = await c.lookup_domain("a.top")
        r2 = await c.lookup_domain("b.top")
        await c.client.aclose()
        return c, r1, r2
    c, r1, r2 = run(go())
    assert r1["state"] == "deferred" and r1["http_status"] == 429
    assert r2["state"] == "deferred" and calls == ["rdap.nic.top"]   # second one never sent
    assert c.backoff_s["rdap.nic.top"] == 120


def test_rdap_rate_limit_reservations():
    c = RdapClient(min_interval=1.0, max_queue=2.5)
    delays = [c.reserve("rdap.example") for _ in range(4)]
    assert delays[0] == 0 and 0.9 < delays[1] <= 1.0 and 1.9 < delays[2] <= 2.0 and delays[3] is None
    assert c.reserve("other.example") == 0


def test_redirects_only_to_known_rdap_hosts():
    def handler(req):
        if req.url.host == "rdap.arin.net" and req.url.path.endswith("/104.16.1.1"):
            return httpx.Response(302, headers={"Location": "https://rdap.apnic.net/ip/104.16.1.1"})
        if req.url.host == "rdap.apnic.net":
            return httpx.Response(200, json=RDAP_IP)
        if req.url.host == "rdap.arin.net":
            return httpx.Response(302, headers={"Location": "https://phish.example/ip/8.8.8.8"})
        raise AssertionError(f"unexpected request {req.url}")

    async def go():
        c = rdap_client(handler)
        a = await c.lookup_ip("104.16.1.1")
        b = await c.lookup_ip("8.8.8.8")
        await c.client.aclose()
        return a, b
    a, b = run(go())
    assert a["state"] == "ok" and a["abuse_email"] == "abuse@cloudflare.com"
    assert b["state"] == "error" and "refused" in b["error"]


def test_oversized_response_rejected(monkeypatch):
    monkeypatch.setattr(enrich, "RDAP_MAX_BYTES", 100)

    def handler(req):
        return httpx.Response(200, content=b"{" + b" " * 5000 + b"}")

    async def go():
        c = rdap_client(handler)
        r = await c.get_json("https://rdap.nic.top/domain/x.top", max_bytes=100)
        await c.client.aclose()
        return r
    assert run(go())["error"] == "response too large"


# ---------------------------------------------------------------- fake database + full run

class FakeCursor:
    def __init__(self, rows=None, rowcount=0):
        self.rows, self.rowcount = rows or [], rowcount

    async def fetchall(self):
        return self.rows

    async def fetchone(self):
        return self.rows[0] if self.rows else None


class _Ctx:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *exc):
        return False


class FakeConn:
    def __init__(self, due_rows):
        self.due_rows = due_rows
        self.calls = []
        self.kv = {}

    async def execute(self, sql, params=None):
        self.calls.append((sql, params))
        s = " ".join(sql.split())
        if s.startswith("SELECT id, registered_domain"):
            return FakeCursor(self.due_rows)
        if s.startswith("SELECT value FROM kv"):
            v = self.kv.get(params[0])
            return FakeCursor([{"value": v}] if v is not None else [])
        if s.startswith("SELECT value, updated_at FROM kv"):
            return FakeCursor([])
        if s.startswith("INSERT INTO kv"):
            self.kv[params[0]] = params[1].obj
        return FakeCursor([], rowcount=0)

    def transaction(self):
        return _Ctx(None)

    def sql(self, prefix):
        return [(s, p) for s, p in self.calls if " ".join(s.split()).startswith(prefix)]


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def connection(self):
        return _Ctx(self.conn)


def test_run_once_end_to_end(monkeypatch):
    row = dom(first_seen=NOW - timedelta(minutes=1))
    row["first_seen"] = enrich.utcnow() - timedelta(minutes=1)
    conn = FakeConn([row])

    async def fake_pool():
        return FakePool(conn)
    monkeypatch.setattr(db, "pool", fake_pool)

    resolver = FakeResolver({
        ("commbank-login.top", "A"): ["104.16.1.1"], ("www.commbank-login.top", "A"): ["104.16.1.1"],
        ("1.1.16.104.origin.asn.cymru.com", "TXT"): ["13335 | 104.16.0.0/13 | US | arin | 2014-03-28"],
        ("as13335.asn.cymru.com", "TXT"): ["13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"],
    })
    monkeypatch.setattr(enrich, "make_resolver", lambda cfg: resolver)

    requested = []

    def handler(req):
        requested.append(str(req.url))
        if req.url.host == "data.iana.org":
            return httpx.Response(200, json={"/rdap/dns.json": BOOT_DNS, "/rdap/ipv4.json": BOOT_V4,
                                             "/rdap/ipv6.json": BOOT_V6}[req.url.path])
        if req.url.host == "rdap.nic.top":
            return httpx.Response(200, json=RDAP_DOMAIN)
        if req.url.host == "rdap.arin.net":
            return httpx.Response(200, json=RDAP_IP)
        raise AssertionError(f"unexpected request {req.url}")
    monkeypatch.setattr(enrich.httpx, "AsyncClient",
                        functools.partial(httpx.AsyncClient, transport=httpx.MockTransport(handler)))

    ctx = SimpleNamespace(state={"rdap": RdapClient(min_interval=0.0)}, log=logging.getLogger("test"))
    result = run(enrich.run_once(ctx))
    assert result["due"] == 1 and result["checked"] == 1 and result["failed"] == 0 and result["rdap"] == 1
    assert requested[:3] == ["https://data.iana.org/rdap/dns.json", "https://data.iana.org/rdap/ipv4.json",
                             "https://data.iana.org/rdap/ipv6.json"]
    assert "https://rdap.nic.top/domain/commbank-login.top" in requested
    assert "https://rdap.arin.net/registry/ip/104.16.1.1" in requested
    assert set(conn.kv) >= {"enrich:rdap_bootstrap:dns", "enrich:rdap_bootstrap:ipv4", "enrich:ip:104.16.1.1"}

    kinds = [p[1] for _, p in conn.sql("INSERT INTO checks")]
    assert kinds == ["dns", "rdap", "asn"]
    (sql, params), = conn.sql("UPDATE domains SET dns_state")
    assert "%s::text[]" in sql and params[-1] == 1
    assert "NameSilo, LLC" in params and 13335 in params and "abuse@cloudflare.com" in params
    assert "CLOUDFLARENET - Cloudflare, Inc., US" in params
    assert [p[1] for _, p in conn.sql("INSERT INTO domain_events")] == ["dns_resolves"]
    # housekeeping ran once; the second run within 5 minutes skips it and reuses the bootstrap
    assert len(conn.sql("UPDATE domains SET next_check_at = NULL")) == 1
    requested.clear()
    conn.due_rows = []
    run(enrich.run_once(ctx))
    assert requested == [] and len(conn.sql("UPDATE domains SET next_check_at = NULL")) == 1


def test_run_once_survives_a_failing_domain(monkeypatch):
    conn = FakeConn([dom(id=7), dom(id=8, registered_domain="ok.top", hostname=None)])

    async def fake_pool():
        return FakePool(conn)
    monkeypatch.setattr(db, "pool", fake_pool)

    async def boom(env, d):
        if d["id"] == 7:
            raise RuntimeError("bad row")
        return enrich.Update()
    monkeypatch.setattr(enrich, "process_domain", boom)
    monkeypatch.setattr(enrich, "make_resolver", lambda cfg: FakeResolver({}))
    monkeypatch.setattr(RdapClient, "ensure_bootstrap", lambda self, kind: asyncio.sleep(0))
    ctx = SimpleNamespace(state={}, log=logging.getLogger("test"))
    result = run(enrich.run_once(ctx))
    assert result["checked"] == 1 and result["failed"] == 1
    (sql, params), = conn.sql("UPDATE domains SET next_check_at = now() + make_interval")
    assert params == (30, 7)


def test_sql_is_parameterised():
    assert "%s" in enrich.DUE_SQL and "%s" in enrich.REVIVE_SQL
    assert "'phishing'" in enrich.DUE_SQL and "ORDER BY CASE tier WHEN 'high'" in enrich.DUE_SQL


def test_job_registered():
    from cybercheck.jobs.enrich import JOB
    from cybercheck.worker import Job
    assert isinstance(JOB, Job) and JOB.name == "enrich" and JOB.interval == 30


# ---------------------------------------------------------------- dashboard page

def test_fmt_hours():
    from cybercheck.web.pages_takedown import fmt_hours
    assert fmt_hours(None) == "-" and fmt_hours(0.5) == "30 min" and fmt_hours(12.25) == "12.2 h"
    assert fmt_hours(72) == "3.0 d" and fmt_hours(-1) == "-"


def test_takedown_page(monkeypatch):
    from fastapi.testclient import TestClient

    from cybercheck.web import app as app_mod
    from cybercheck.web import pages_takedown as pt

    seen_sql = []
    agg = {"total": 3, "down": 2, "up": 1, "live_now": 1, "reported": 2, "med_first": 20.0, "p90_first": 70.0,
           "n_rep": 1, "med_rep": 5.5, "p90_rep": 5.5}

    async def fake_fetchone(sql, params=()):
        seen_sql.append(sql)
        return dict(agg)

    async def fake_fetchall(sql, params=()):
        seen_sql.append(sql)
        if "GROUP BY COALESCE" in sql:
            return [dict(agg, name="<script>alert(1)</script> Registrar", iana_id=1479)]
        if "GROUP BY asn" in sql:
            return [dict(agg, asn=13335, name="CLOUDFLARENET")]
        if "takedown_at IS NULL" in sql and "age_h" in sql:
            return [{"id": 5, "registered_domain": "commbank-login.top", "unicode_domain": None, "hostname": None,
                     "brand_id": "commbank", "registrar": "NameSilo", "asn": 13335, "as_name": "CF",
                     "dns_state": "resolves", "live_state": "live", "first_seen": NOW, "reported_at": None,
                     "last_live_at": NOW, "enriched_at": NOW, "age_h": 30.0, "reported_h": None}]
        if "ORDER BY takedown_at DESC" in sql:
            return [{"id": 6, "registered_domain": "anz-verify.top", "unicode_domain": None, "hostname": None,
                     "brand_id": "anz", "registrar": None, "asn": None, "as_name": None, "takedown_at": NOW,
                     "takedown_signal": "rdap_hold", "h_first": 12.0, "h_rep": None}]
        raise AssertionError(sql)

    monkeypatch.setattr(pt, "fetchall", fake_fetchall)
    monkeypatch.setattr(pt, "fetchone", fake_fetchone)
    assert ("/takedown", "Takedowns") in pt._templates.env.globals["nav"]
    # The dashboard's own address: the web app may reject other Host headers (DNS rebinding).
    client = TestClient(app_mod.app, base_url="http://127.0.0.1:8430")
    r = client.get("/takedown")
    assert r.status_code == 200
    body = r.text
    assert "Takedowns" in body and "only cover domains CyberCheck flagged" in body
    assert "<script>alert(1)</script>" not in body and "&lt;script&gt;" in body
    assert "commbank-login.top" in body and "anz-verify.top" in body and "registry hold" in body
    assert "2.9 d" in body and "30.0 h" in body and "12.0 h" in body and "IANA 1479" in body
    assert all("{where}" not in s and "percentile_cont" in s for s in seen_sql if "GROUP BY" in s)
    assert any("status = 'confirmed'" in s for s in seen_sql)

    seen_sql.clear()
    assert client.get("/takedown?scope=tracked").status_code == 200
    assert any("ai_verdict = 'phishing'" in s for s in seen_sql)
    seen_sql.clear()
    assert client.get("/takedown?scope=x' OR 1=1 --").status_code == 200
    assert all("1=1" not in s for s in seen_sql) and any("status = 'confirmed'" in s for s in seen_sql)


# ---------------------------------------------------------------- review fixes

def test_nxdomain_without_soa_is_inconclusive():
    """Quad9 answers NXDOMAIN (no SOA) for domains on its threat feed; that must not look like a takedown."""
    blocked = nx("phish.top", soa=False)
    r = FakeResolver({("phish.top", "A"): blocked, ("phish.top", "AAAA"): blocked})
    res = run(enrich.dns_check(r, "phish.top", None))
    assert res.state == "error" and res.reg_state == "error"
    assert "nxdomain_without_soa" in res.names["phish.top"]["error"]
    assert not enrich.nxdomain_verified(dns.resolver.NXDOMAIN())
    assert enrich.nxdomain_verified(nx("phish.top"))
    # two such answers in a row on a tracked domain: no takedown, last real DNS state kept
    d = tracked()
    up1 = decide(d, res, None, None, NOW, CFG)
    up2 = decide(dict(d, enrich_state=up1.state), res, None, None, NOW + timedelta(hours=1), CFG)
    assert up1.takedown is None and up2.takedown is None and "dns_state" not in up2.cols


def test_dns_check_lowercases_registered_domain():
    r = FakeResolver({("ok.top", "A"): ["1.2.3.4"]})
    res = run(enrich.dns_check(r, "OK.Top.", "WWW.ok.top"))
    assert res.state == "resolves" and set(res.names) == {"ok.top", "www.ok.top"}


def test_queued_rdap_requests_stop_after_a_429():
    calls = []

    def handler(req):
        calls.append(req.url.path)
        return httpx.Response(429)

    async def go():
        c = rdap_client(handler, min_interval=0.05)
        rs = await asyncio.gather(*(c.lookup_domain(f"d{i}.top") for i in range(5)))
        await c.client.aclose()
        return rs
    rs = run(go())
    assert all(r["state"] == "deferred" for r in rs)
    assert len(calls) == 1            # the four queued behind the 429 were not sent


def test_cymru_asn_out_of_int_range_ignored():
    o = enrich.parse_cymru_origin(["4294967294 | 10.0.0.0/8 | ZZ | other | 2020-01-01",
                                   "64500 | 10.0.0.0/16 | AU | apnic | 2020-01-01"])
    assert o["asn"] == 64500
    assert enrich.parse_cymru_origin(["4294967294 | 10.0.0.0/8 | ZZ | other | 2020-01-01"]) is None
    assert enrich.parse_cymru_origin(["0 | 10.0.0.0/8 | ZZ | other | 2020-01-01"]) is None


def test_registrar_handle_is_not_an_iana_id():
    data = {"entities": [{"roles": ["registrar"], "handle": "12",
                          "vcardArray": ["vcard", [["fn", {}, "text", "Some ccTLD Registrar"]]]}]}
    assert enrich.parse_domain_rdap(data)["iana_id"] is None


def test_ip_info_cymru_error_is_cached_briefly(monkeypatch):
    conn = FakeConn([])

    async def fake_pool():
        return FakePool(conn)
    monkeypatch.setattr(db, "pool", fake_pool)
    resolver = FakeResolver({("1.1.16.104.origin.asn.cymru.com", "TXT"): dns.exception.Timeout()})

    def handler(req):
        return httpx.Response(200, json=RDAP_IP)

    async def go():
        env = enrich.Env(cfg=CFG, resolver=resolver, rdap=rdap_client(handler), ip_cache=enrich.IpInfoCache(),
                         db_sem=asyncio.Semaphore(2))
        info = await enrich.ip_info(env, "104.16.1.1")
        await env.rdap.client.aclose()
        return info
    info = run(go())
    assert info["asn"] is None and info["abuse_email"] == "abuse@cloudflare.com"
    assert info["partial"] is True and enrich.ip_info_ttl(info) == enrich.IP_CACHE_PARTIAL_TTL_S


def test_nxdomain_event_after_no_answer():
    d = dom(dns_state="no_answer", enrich_state={"dns": "no_answer", "resolved_at": enrich.iso(NOW - timedelta(days=1))})
    up = decide(d, dnsr("nxdomain"), None, None, NOW, CFG)
    assert [e[0] for e in up.events] == ["nxdomain"]
    never = dom(dns_state="no_answer", enrich_state={"dns": "no_answer"})
    assert decide(never, dnsr("nxdomain"), None, None, NOW, CFG).events == []


def test_concurrent_writes_never_exceed_db_semaphore(monkeypatch):
    """The worker pool is shared (max 5); enrich must hold at most 2 connections for writes at once."""
    active, peak = 0, 0

    class CountingPool:
        def __init__(self, conn):
            self.conn = conn

        def connection(self):
            pool = self

            class C:
                async def __aenter__(self_inner):
                    nonlocal active, peak
                    active += 1
                    peak = max(peak, active)
                    await asyncio.sleep(0.01)
                    return pool.conn

                async def __aexit__(self_inner, *exc):
                    nonlocal active
                    active -= 1
                    return False
            return C()

    rows = [dom(id=i, registered_domain=f"d{i}.top", hostname=None,
                first_seen=enrich.utcnow() - timedelta(minutes=1)) for i in range(20)]
    conn = FakeConn(rows)

    async def fake_pool():
        return CountingPool(conn)
    monkeypatch.setattr(db, "pool", fake_pool)
    monkeypatch.setattr(enrich, "make_resolver", lambda cfg: FakeResolver({}))
    monkeypatch.setattr(RdapClient, "ensure_bootstrap", lambda self, kind: asyncio.sleep(0))
    ctx = SimpleNamespace(state={"housekeep_at": time.monotonic()}, log=logging.getLogger("test"))
    result = run(enrich.run_once(ctx))
    assert result["checked"] == 20 and result["failed"] == 0
    assert peak <= 2


# ---- one tracking window for enrich and fetch (security review) --------------------------------

def test_track_end_is_the_window_both_jobs_use():
    confirmed_at = NOW - timedelta(days=5)
    d = dom(first_seen=NOW - timedelta(days=20), status="confirmed", status_changed_at=confirmed_at,
            reported_at=NOW - timedelta(days=8))
    assert enrich.track_end(d, 30) == confirmed_at + timedelta(days=30)
    assert enrich.track_end(dom(first_seen=NOW - timedelta(days=2), ai_verdict="phishing"), 30) == \
        NOW - timedelta(days=2) + timedelta(days=30)
    # not tracked: no window at all
    assert enrich.track_end(dom(), 30) is None
    assert enrich.track_end(dom(ai_verdict="phishing", status="false_positive"), 30) is None
    # an open domain's old status_changed_at (e.g. un-confirmed) does not extend the window
    d2 = dom(first_seen=NOW - timedelta(days=40), ai_verdict="phishing", status_changed_at=NOW)
    assert enrich.track_end(d2, 30) == NOW - timedelta(days=10)
    # next_check follows track_end: hourly inside, nothing after (watch window over)
    d3 = dom(first_seen=NOW - timedelta(days=29), watch_until=NOW - timedelta(days=15), ai_verdict="phishing")
    assert next_check(d3, NOW, CFG) == NOW + timedelta(hours=1)
    assert next_check(d3, NOW + timedelta(days=2), CFG) is None


def test_track_anchor_without_first_seen_does_not_crash():
    assert enrich.track_anchor({"status": "open"}) is None
    assert enrich.track_end({"ai_verdict": "phishing"}, 30) is None
    assert enrich.track_anchor({"reported_at": NOW}) == NOW
