"""CZDS module tests. Offline: CZDS is an httpx.MockTransport, the database an in-memory fake, the clock is fake."""
from __future__ import annotations

import asyncio
import base64
import gzip
import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from cybercheck import czds, db
from cybercheck.scoring import Watchlist

UTC = timezone.utc
D1 = datetime(2026, 11, 16, tzinfo=UTC)          # midnight UTC, day 1
H = timedelta(hours=1)
DAY = timedelta(days=1)
LINKS = "https://czds-api.icann.org/czds/downloads/links"
TOP_URL = "https://czds-download-api.icann.org/czds/downloads/top.zone"

WL = Watchlist({
    "brands": [{"id": "commbank", "name": "Commonwealth Bank", "keywords": ["commbank"],
                "official_domains": ["commbank.com.au"]}],
    "bait_words": {"strong": ["login", "verify"], "weak": []},
})


def run(coro):
    return asyncio.run(coro)


def cfg(tmp_path: Path | None = None, **kw) -> czds.CzdsConfig:
    base = dict(username="u@example.org", password="pw", tlds=("top",),
                data_dir=(tmp_path or Path("/nonexistent")) / "czds")
    base.update(kw)
    return czds.CzdsConfig(**base)


def zone_text(tld: str, labels, serial: int, *, end_soa: bool = True, extra=(), soa_end_serial=None) -> str:
    soa = f"{tld}.\t3600\tin\tsoa\tns0.nic.{tld}.\thostmaster.nic.{tld}.\t{serial}\t1800\t900\t604800\t3600"
    lines = [soa, f"{tld}.\t172800\tin\tns\ta.nic.{tld}.", f"{tld}.\t172800\tin\tns\tb.nic.{tld}.",
             f"{tld}.\t3600\tin\tdnskey\t257 3 13 AAAA"]
    for label in sorted(labels):
        lines += [f"{label}.{tld}.\t3600\tin\tns\tns1.{label}.{tld}.",
                  f"{label}.{tld}.\t3600\tin\tns\tns2.example.net.",
                  f"{label}.{tld}.\t3600\tin\tds\t12345 13 2 ABCDEF",
                  f"{label}.{tld}.\t3600\tin\trrsig\tDS 13 2 3600 20261201000000 20261101000000 1 {tld}. AAAA",
                  f"ns1.{label}.{tld}.\t3600\tin\ta\t192.0.2.1"]          # glue: not a delegation
    lines += list(extra)
    if end_soa:
        lines.append(soa if soa_end_serial is None else soa.replace(f"\t{serial}\t", f"\t{soa_end_serial}\t"))
    return "\n".join(lines) + "\n"


def zone_gz(*a, **kw) -> bytes:
    return gzip.compress(zone_text(*a, **kw).encode())


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def scan(path: Path, tld: str = "top", **kw) -> tuple[list[bytes], czds.ZoneScan]:
    st = czds.ZoneScan(tld)
    return list(czds.scan_zone(path, tld, st, **kw)), st


def make_jwt(exp: datetime) -> str:
    def b64(obj) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'RS256'})}.{b64({'exp': int(exp.timestamp()), 'sub': 'x'})}.c2lnbmF0dXJlLXNpZ25hdHVyZQ"


# ---------------------------------------------------------------------------------------------------
# settings
# ---------------------------------------------------------------------------------------------------

def test_no_credentials_skips_without_database_or_network(monkeypatch, tmp_path):
    def no_http():
        raise AssertionError("no network without credentials")
    monkeypatch.setattr(czds, "make_http", no_http)

    class Ctx:
        settings = SimpleNamespace(czds_username="", czds_password="", czds_tlds=["top"], data_dir=tmp_path)
        state: dict = {}

        async def pool(self):
            raise AssertionError("no database without credentials")

    assert run(czds.run_once(Ctx())) == {"skipped": "no CZDS credentials"}
    Ctx.settings = SimpleNamespace(czds_username="u@example.org", czds_password="", czds_tlds=["top"], data_dir=tmp_path)
    assert run(czds.run_once(Ctx())) == {"skipped": "no CZDS credentials"}
    assert not (tmp_path / "czds").exists()


def test_normalise_tlds():
    good, bad = czds.normalise_tlds([" TOP ", ".xyz", "top", "bad_tld", "рф", "123", "", "a" * 64, "-x"])
    assert good == ("top", "xyz", "xn--p1ai")
    assert bad == ("bad_tld", "123", "a" * 64, "-x")


def test_load_config(monkeypatch, tmp_path):
    for k in ("CZDS_WINDOW_START", "CZDS_WINDOW_HOURS", "CZDS_SORT_BUFFER", "CZDS_STRICT_SOA"):
        monkeypatch.delenv(k, raising=False)
    s = SimpleNamespace(czds_username=" u@example.org ", czds_password="pw", czds_tlds=["top", "x y"], data_dir=tmp_path)
    c = czds.load_config(s)
    assert c.has_credentials and c.tlds == ("top",) and c.bad_tlds == ("x y",)
    assert c.data_dir == tmp_path / "czds" and c.window_label == "06:30-14:30 UTC" and c.sort_buffer == "128M"
    assert "pw" not in repr(c)
    monkeypatch.setenv("CZDS_WINDOW_START", "25:00")
    monkeypatch.setenv("CZDS_SORT_BUFFER", "1T; rm -rf /")
    monkeypatch.setenv("CZDS_WINDOW_HOURS", "99")
    c = czds.load_config(s)
    assert c.window_start_min == 6 * 60 + 30 and c.sort_buffer == "128M" and c.window_hours == 20.0
    monkeypatch.setenv("CZDS_WINDOW_START", "07:15")
    monkeypatch.setenv("CZDS_SORT_BUFFER", "200m")
    monkeypatch.setenv("CZDS_STRICT_SOA", "false")
    c = czds.load_config(s)
    assert c.window_start_min == 7 * 60 + 15 and c.sort_buffer == "200M" and not c.strict_soa


# ---------------------------------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------------------------------

def test_jwt_expiry():
    exp = datetime(2026, 11, 17, 6, 0, tzinfo=UTC)
    assert czds.jwt_expiry(make_jwt(exp)) == exp
    for bad in ("", "abc", "a.!!!.c", "a." + base64.urlsafe_b64encode(b'{"exp": "soon"}').decode() + ".c",
                "a." + base64.urlsafe_b64encode(b'{"exp": 1e300}').decode() + ".c"):
        assert czds.jwt_expiry(bad) is None


@pytest.mark.parametrize("url,tld", [
    (TOP_URL, "top"),
    ("https://czds-download-api.icann.org/czds/downloads/xn--p1ai.zone", "xn--p1ai"),
    ("https://CZDS-DOWNLOAD-API.icann.org/czds/downloads/TOP.zone", "top"),
    ("http://czds-download-api.icann.org/czds/downloads/top.zone", None),
    ("https://czds-download-api.icann.org:8443/czds/downloads/top.zone", None),
    ("https://evil-icann.org/czds/downloads/top.zone", None),
    ("https://icann.org.evil.example/czds/downloads/top.zone", None),
    ("https://czds-download-api.icann.org/czds/downloads/top.zone?x=1", None),
    ("https://czds-download-api.icann.org/czds/downloads/top.txt.gz", None),
    ("https://czds-download-api.icann.org/czds/downloads/to_p.zone", None),
    ("https://czds-download-api.icann.org/czds/downloads/.zone", None),
    (12, None), (None, None),
])
def test_zone_url_tld(url, tld):
    assert czds.zone_url_tld(url) == tld


def test_parse_links():
    links = czds.parse_links([TOP_URL, "https://evil.example/czds/downloads/xyz.zone", 5,
                              "https://czds-download-api.icann.org/czds/downloads/shop.zone"])
    assert links == {"top": TOP_URL, "shop": "https://czds-download-api.icann.org/czds/downloads/shop.zone"}
    with pytest.raises(czds.CzdsError):
        czds.parse_links({"links": []})


# ---------------------------------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------------------------------

def test_next_slot_keeps_downloads_inside_the_daily_window():
    c = cfg()
    assert czds.next_slot(D1 + 5 * H, c) == D1 + timedelta(hours=6, minutes=30)
    assert czds.next_slot(D1 + 7 * H, c) == D1 + 7 * H
    assert czds.next_slot(D1 + 15 * H, c) == D1 + DAY + timedelta(hours=6, minutes=30)
    late = czds.CzdsConfig(window_start_min=22 * 60, window_hours=6)    # window across midnight
    assert czds.next_slot(D1 + 2 * H, late) == D1 + 2 * H
    assert czds.next_slot(D1 + 5 * H, late) == D1 + 22 * H


def test_zone_due_enforces_24h_between_downloads():
    c = cfg()
    first = D1 + timedelta(hours=6, minutes=30)
    z = {"configured": True, "approved": True, "last_download": first}
    assert czds.zone_due(z, first + 2 * H, c) == first + czds.MIN_GAP
    assert czds.MIN_GAP > timedelta(hours=24)
    assert czds.zone_due({**z, "retry_at": first + 30 * H}, first + 2 * H, c) == first + 30 * H
    assert czds.zone_due({**z, "approved": False}, first, c) is None
    assert czds.zone_due({**z, "configured": False}, first, c) is None
    assert czds.zone_due(z, first + H, c, pending=True) == first + H     # file waiting: no network needed
    assert czds.zone_due({"configured": True, "approved": True}, D1 + 3 * H, c) == first
    assert not czds.head_allowed({"last_head": first}, first + 23 * H)
    assert czds.head_allowed({"last_head": first}, first + czds.MIN_GAP)


# ---------------------------------------------------------------------------------------------------
# zone parsing
# ---------------------------------------------------------------------------------------------------

def test_scan_zone_keeps_second_level_delegations_only(tmp_path):
    extra = [
        "sub.deleg.top.\t3600\tin\tns\tns1.example.net.",          # deeper delegation
        "_dmarc.top.\t3600\tin\tns\tns1.example.net.",              # not an LDH label
        "-bad.top.\t3600\tin\tns\tns1.example.net.",
        "2vb0nvp4o1djf8t2ln0jfrh7sfmhlqhb.top.\t300\tin\tnsec3\t1 0 0 - 2VB0NVP4 NS DS RRSIG",
        "ns.other.net.\t3600\tin\ta\t192.0.2.9",
        "xn--80ak6aa92e.top.\t3600\tin\tns\tns1.example.net.",
        "upper.top.\t3600\tin\tns\tns1.example.net.",
        "upper.top.\t3600\tin\tns\tns2.example.net.",
    ]
    path = write(tmp_path / "z.gz", zone_gz("top", ["commbank-login", "alpha"], 2026111601, extra=extra))
    labels, st = scan(path)
    assert labels == [b"alpha", b"commbank-login", b"xn--80ak6aa92e", b"upper"]
    assert st.serial == 2026111601 and st.strict and st.end_soa == "same"
    assert st.skipped == 4 and st.ns_records == 2 + 4 + 3 + 3       # apex, deeper, _dmarc, -bad


def test_scan_zone_lenient_layout(tmp_path):
    text = ("TOP. 3600 IN SOA ns0.nic.top. hostmaster.nic.top. 7 1800 900 604800 3600\n"
            "Mixed.TOP. IN 3600 NS ns1.example.net.\n"
            "other.top.   3600 NS   ns1.example.net.\n"
            "TOP. 3600 IN SOA ns0.nic.top. hostmaster.nic.top. 7 1800 900 604800 3600\n")
    labels, st = scan(write(tmp_path / "z.gz", gzip.compress(text.encode())))
    assert labels == [b"mixed", b"other"] and st.serial == 7 and not st.strict


@pytest.mark.parametrize("data,msg", [
    (b"<html>maintenance</html>", "not a gzip file"),
    (gzip.compress(b""), "empty"),
    (gzip.compress(b"; Transfer failed.\n"), "does not start with the zone's SOA"),
    (gzip.compress(zone_text("xyz", ["a"], 1).encode()), "SOA record is for another zone"),
    (zone_gz("top", ["a", "b"], 5)[:-30], "corrupt or truncated"),
    (zone_gz("top", ["a"], 5, soa_end_serial=6), "different SOA"),
    (zone_gz("top", ["a"], 5, end_soa=False), "does not end with the SOA"),
])
def test_scan_zone_rejects_bad_files(tmp_path, data, msg):
    path = write(tmp_path / "z.gz", data)
    with pytest.raises(czds.ZoneInvalid, match=msg):
        scan(path)


def test_scan_zone_serial_and_end_soa_rules(tmp_path):
    path = write(tmp_path / "z.gz", zone_gz("top", ["a"], 100))
    with pytest.raises(czds.ZoneUnchanged):
        scan(path, prev_serial=100)
    with pytest.raises(czds.ZoneInvalid) as e:
        scan(path, prev_serial=101)
    assert e.value.reason == "old_serial"
    assert scan(path, prev_serial=101, allow_older_serial=True)[0] == [b"a"]
    assert scan(path, prev_serial=4294967290)[0] == [b"a"]          # RFC 1982 wrap-around: 100 is newer
    nosoa = write(tmp_path / "n.gz", zone_gz("top", ["a"], 100, end_soa=False))
    with pytest.raises(czds.ZoneInvalid) as e:
        scan(nosoa)
    assert e.value.reason == "end_soa_missing"
    labels, st = scan(nosoa, allow_missing_end_soa=True)
    assert labels == [b"a"] and st.end_soa == "missing"
    assert scan(nosoa, strict_soa=False)[0] == [b"a"]
    mismatch = write(tmp_path / "m.gz", zone_gz("top", ["a"], 100, soa_end_serial=99))
    with pytest.raises(czds.ZoneInvalid):        # never tolerated: a different closing SOA
        scan(mismatch, allow_missing_end_soa=True)


# ---------------------------------------------------------------------------------------------------
# bounded-memory sort and the diff
# ---------------------------------------------------------------------------------------------------

NAMES = [b"b", b"a-b", b"a", b"ab", b"a", b"xn--80ak6aa92e", b"0a", b"z-", b"a0", b"zz", b"a", b"b", b"q", b"0a"]


def test_python_external_sort_spills_and_merges(monkeypatch, tmp_path):
    monkeypatch.setattr(czds, "CHUNK_NAMES", 3)
    monkeypatch.setattr(czds, "MERGE_FANIN", 2)          # several merge passes
    out = list(czds.sorted_unique(iter(NAMES), tmp_path, use_system=False))
    assert out == sorted(set(NAMES))
    assert list(tmp_path.iterdir()) == [] or all(p.name.startswith("chunk-") for p in tmp_path.iterdir())
    assert list(czds.sorted_unique(iter([]), tmp_path, use_system=False)) == []


def test_system_sort_matches_python_order(monkeypatch, tmp_path):
    monkeypatch.setattr(czds, "_sort_cmd_cache", {})
    if czds.system_sort_cmd(tmp_path) is None:
        pytest.skip("no usable sort(1) here")
    cmd = czds.system_sort_cmd(tmp_path)
    assert "-u" in cmd and all(";" not in c for c in cmd)
    assert list(czds.sorted_unique(iter(NAMES), tmp_path, "1M", use_system=True)) == sorted(set(NAMES))


def write_list(path: Path, names) -> Path:
    with gzip.open(path, "wb") as f:
        f.write(b"".join(n + b"\n" for n in names))
    return path


def test_merge_lists_new_and_removed(tmp_path):
    prev = write_list(tmp_path / "prev.gz", [b"a", b"c", b"e"])
    seen = []
    st = czds.merge_lists(iter([b"b", b"c", b"d", b"f"]), prev, tmp_path / "out.gz", seen.append)
    assert seen == [b"b", b"d", b"f"]
    assert (st.total, st.new, st.removed, st.prev_total, st.baseline) == (4, 3, 2, 3, False)
    assert list(czds.read_list(tmp_path / "out.gz")) == [b"b", b"c", b"d", b"f"]
    seen.clear()
    st = czds.merge_lists(iter([b"a", b"b"]), None, tmp_path / "base.gz", seen.append)
    assert seen == [] and st.baseline and st.total == 2 and st.new == 0


def test_merge_lists_treats_a_corrupt_previous_list_as_baseline(tmp_path):
    prev = write_list(tmp_path / "prev.gz", [b"c", b"a"])          # out of order
    seen = []
    st = czds.merge_lists(iter([b"b", b"d"]), prev, tmp_path / "out.gz", seen.append)
    assert st.baseline and st.new == 0 and "unreadable" in st.prev_error


# ---------------------------------------------------------------------------------------------------
# one zone file end to end (parse -> sort -> diff -> score)
# ---------------------------------------------------------------------------------------------------

def test_process_zone_baseline_then_new_names(tmp_path):
    c = cfg(tmp_path)
    zdir = czds.zone_dir(c, "top")
    raw = write(zdir / czds.RAW, zone_gz("top", ["commbank-login", "alpha", "beta"], 1))
    res = czds.process_zone(raw, zdir, "top", cfg=c, watchlist=WL, use_system_sort=False)
    assert res.baseline and res.new is None and res.hits == [] and res.total == 3   # first run: no "new" names
    czds.rotate_lists(zdir)
    raw = write(zdir / czds.RAW, zone_gz("top", ["commbank-login", "alpha", "commbank-verify", "gamma"], 2))
    res = czds.process_zone(raw, zdir, "top", cfg=c, watchlist=WL, prev_serial=1, use_system_sort=False)
    assert not res.baseline and (res.total, res.new, res.removed) == (4, 2, 1)
    assert [h.registered_domain for h in res.hits] == ["commbank-verify.top"]
    assert res.hits[0].tier in ("watch", "review", "high") and res.scored == 2
    czds.rotate_lists(zdir)
    assert sorted(p.name for p in zdir.iterdir()) == ["names.gz", "names.prev.gz", "zone.gz"]
    assert list(czds.read_list(zdir / czds.CUR_LIST)) == [b"alpha", b"commbank-login", b"commbank-verify", b"gamma"]
    assert list(czds.read_list(zdir / czds.PREV_LIST)) == [b"alpha", b"beta", b"commbank-login"]


def test_process_zone_count_check_and_recovery(tmp_path):
    c = cfg(tmp_path)
    zdir = czds.zone_dir(c, "top")
    names = [f"n{i:05d}" for i in range(2000)]
    raw = write(zdir / czds.RAW, zone_gz("top", names, 1))
    czds.process_zone(raw, zdir, "top", cfg=c, watchlist=WL, use_system_sort=False)
    czds.rotate_lists(zdir)
    half = write(zdir / czds.RAW, zone_gz("top", names[:1000], 2))
    with pytest.raises(czds.ZoneInvalid) as e:
        czds.process_zone(half, zdir, "top", cfg=c, watchlist=WL, prev_serial=1, use_system_sort=False)
    assert e.value.reason == "count" and e.value.total == 1000
    assert not (zdir / czds.NEW_LIST).exists() and not (zdir / czds.TMP_DIR).exists()
    # the next day's file has the same lower count: accepted (a real change, not a broken file)
    again = write(zdir / czds.RAW, zone_gz("top", names[:1010], 3))
    res = czds.process_zone(again, zdir, "top", cfg=c, watchlist=WL, prev_serial=1, rejected_total=1000,
                            use_system_sort=False)
    assert res.total == 1010 and "accepted" in res.note


def test_process_zone_rebaseline_and_hit_cap(tmp_path):
    c = cfg(tmp_path, max_new_names=2)
    zdir = czds.zone_dir(c, "top")
    czds.process_zone(write(zdir / czds.RAW, zone_gz("top", ["a"], 1)), zdir, "top", cfg=c, watchlist=WL,
                      use_system_sort=False)
    czds.rotate_lists(zdir)
    res = czds.process_zone(write(zdir / czds.RAW, zone_gz("top", ["a", "commbank-login", "b", "c"], 2)), zdir, "top",
                            cfg=c, watchlist=WL, prev_serial=1, use_system_sort=False)
    assert res.rebaseline and res.hits == [] and "baseline" in res.note
    (zdir / czds.NEW_LIST).unlink()
    c = cfg(tmp_path, max_hits=2)
    res = czds.process_zone(write(zdir / czds.RAW, zone_gz("top", ["a", "commbank", "commbank-login", "commbank-login-verify"], 3)),
                            zdir, "top", cfg=c, watchlist=WL, prev_serial=2, use_system_sort=False)
    assert len(res.hits) == 2 and res.hits_dropped == 1
    assert res.hits[0].score >= res.hits[1].score
    assert "commbank.top" not in [h.registered_domain for h in res.hits]       # lowest score dropped


def test_cleanup_unconfigured(tmp_path):
    c = cfg(tmp_path, tlds=("top",), keep_unconfigured_days=7)
    keep = czds.zone_dir(c, "top")
    write(keep / czds.CUR_LIST, b"x")
    old = czds.zone_dir(c, "xyz")
    write(old / czds.CUR_LIST, b"x")
    recent = czds.zone_dir(c, "shop")
    write(recent / czds.CUR_LIST, b"x")
    write(recent / czds.RAW, b"raw zone data")
    past = time.time() - 8 * 86400
    for p in (old / czds.CUR_LIST, old):
        os.utime(p, (past, past))
    removed = czds.cleanup_unconfigured(c)
    assert removed == ["xyz"] and not old.exists()
    assert (keep / czds.CUR_LIST).exists() and (recent / czds.CUR_LIST).exists()
    assert not (recent / czds.RAW).exists()          # raw downloads of unconfigured zones go at once


# ---------------------------------------------------------------------------------------------------
# CZDS API client
# ---------------------------------------------------------------------------------------------------

class Server:
    """Fake CZDS: account-api (login), czds-api (links) and czds-download-api (HEAD/GET)."""

    def __init__(self, clock):
        self.clock = clock
        self.requests: list[httpx.Request] = []
        self.links = [TOP_URL]
        self.zone = b""
        self.last_modified = "Mon, 16 Nov 2026 05:12:00 GMT"
        self.login_status = 200
        self.links_401 = 0
        self.redirect: str | None = None
        self.stream_error = False
        self.bad_length = False
        self.tokens: set[str] = set()

    def count(self, method: str, host: str) -> int:
        return sum(1 for r in self.requests if r.method == method and r.url.host == host)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["user-agent"] == czds.USER_AGENT
        host, path = request.url.host, request.url.path
        if host == "account-api.icann.org" and path == "/api/authenticate":
            assert request.method == "POST" and request.headers["content-type"] == "application/json"
            assert json.loads(request.content) == {"username": "u@example.org", "password": "pw"}
            if self.login_status != 200:
                return httpx.Response(self.login_status)
            token = make_jwt(self.clock() + 24 * H) + str(len(self.tokens))
            self.tokens.add(token)
            return httpx.Response(200, json={"accessToken": token})
        auth = request.headers.get("authorization", "")
        assert request.headers.get("accept-encoding") == "identity"
        if not auth.startswith("Bearer ") or auth[7:] not in self.tokens:
            return httpx.Response(401)
        if self.redirect and host == "czds-api.icann.org":
            target, self.redirect = self.redirect, None
            return httpx.Response(302, headers={"Location": target})
        if path == "/czds/downloads/links":
            if self.links_401:
                self.links_401 -= 1
                return httpx.Response(401)
            return httpx.Response(200, json=self.links)
        if host == "czds-download-api.icann.org" and path == "/czds/downloads/top.zone":
            if request.method == "HEAD":
                return httpx.Response(200, headers={"Content-Length": str(len(self.zone)),
                                                    "Last-Modified": self.last_modified,
                                                    "Content-Disposition": "attachment;filename=top.txt.gz"})
            if self.stream_error:
                return httpx.Response(200, headers={"Content-Length": str(len(self.zone))},
                                      stream=FailingStream(self.zone[:100]))
            if self.bad_length:
                return httpx.Response(200, headers={"Content-Length": str(len(self.zone) + 50)},
                                      stream=httpx.ByteStream(self.zone))
            # stream=, as on the network (content= would be pre-read, which aiter_raw() refuses)
            return httpx.Response(200, stream=httpx.ByteStream(self.zone),
                                  headers={"Content-Length": str(len(self.zone)), "Last-Modified": self.last_modified,
                                           "Content-Type": "text/dns"})
        return httpx.Response(403)


class FailingStream(httpx.AsyncByteStream):
    def __init__(self, first: bytes):
        self.first = first

    async def __aiter__(self):
        yield self.first
        raise httpx.ReadError("connection reset")


def make_api(server: Server, c=None, tokens=None):
    http = httpx.AsyncClient(transport=httpx.MockTransport(server.handler), headers={"User-Agent": czds.USER_AGENT})
    return czds.CzdsApi(c or cfg(), tokens or czds.TokenCache(), http), http


def test_api_logs_in_once_and_reuses_the_token():
    server = Server(lambda: datetime.now(UTC))

    async def go():
        api, http = make_api(server)
        async with http:
            assert await api.links() == {"top": TOP_URL}
            assert await api.links() == {"top": TOP_URL}
            server.zone = b"\x1f\x8b" + b"x" * 300
            head = await api.head(TOP_URL)
            assert head.status == 200 and head.length == 302 and head.last_modified == server.last_modified
        return api
    api = run(go())
    assert server.count("POST", "account-api.icann.org") == 1
    assert server.count("GET", "czds-api.icann.org") == 2
    exp = api.tokens.expires_at
    assert exp is not None and timedelta(hours=23) < exp - datetime.now(UTC) < timedelta(hours=24)


def test_api_logs_in_again_after_401():
    server = Server(lambda: datetime.now(UTC))
    server.links_401 = 1

    async def go():
        api, http = make_api(server)
        async with http:
            return await api.links()
    assert run(go()) == {"top": TOP_URL}
    assert server.count("POST", "account-api.icann.org") == 2


@pytest.mark.parametrize("status,text", [(401, "username or password"), (429, "rate limit")])
def test_login_failure_blocks_further_attempts(status, text):
    server = Server(lambda: datetime.now(UTC))
    server.login_status = status
    tokens = czds.TokenCache()

    async def go():
        api, http = make_api(server, tokens=tokens)
        async with http:
            for _ in range(3):
                with pytest.raises(czds.CzdsAuthError, match=text):
                    await api.links()
    run(go())
    assert server.count("POST", "account-api.icann.org") == 1        # blocked after the first refusal
    assert tokens.blocked_until is not None


def test_own_login_rate_limit_stays_under_icanns():
    server = Server(lambda: datetime.now(UTC))

    async def go():
        api, http = make_api(server)
        async with http:
            for _ in range(czds.LOGIN_MAX_PER_WINDOW):
                await api._login()
            with pytest.raises(czds.CzdsAuthError, match="too many"):
                await api._login()
    run(go())
    assert czds.LOGIN_MAX_PER_WINDOW < 8
    assert server.count("POST", "account-api.icann.org") == czds.LOGIN_MAX_PER_WINDOW


def test_login_rejects_an_unusable_token():
    async def go():
        def handler(request):
            return httpx.Response(200, json={"accessToken": "short"})
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        async with http:
            with pytest.raises(czds.CzdsAuthError, match="accessToken"):
                await czds.CzdsApi(cfg(), czds.TokenCache(), http).token()
    run(go())


def test_redirects_only_to_icann_hosts():
    server = Server(lambda: datetime.now(UTC))
    server.redirect = "https://evil.example/steal"

    async def go():
        api, http = make_api(server)
        async with http:
            with pytest.raises(czds.CzdsError, match="not an ICANN host"):
                await api.links()
            server.redirect = "https://czds-api.icann.org/czds/downloads/links"
            assert await api.links() == {"top": TOP_URL}
    run(go())
    assert not any(r.url.host == "evil.example" for r in server.requests)


def test_download_streams_to_disk_with_a_size_cap(tmp_path):
    server = Server(lambda: datetime.now(UTC))
    server.zone = zone_gz("top", ["a", "b"], 1)
    started = []

    async def on_start(at):
        started.append(at)

    async def go():
        api, http = make_api(server)
        async with http:
            dl = await api.download(TOP_URL, tmp_path / "z.part", max_bytes=1 << 20, on_start=on_start)
            assert dl.bytes == len(server.zone) == dl.content_length
            with pytest.raises(czds.ZoneInvalid, match="CZDS_MAX_ZONE_GB"):
                await api.download(TOP_URL, tmp_path / "y.part", max_bytes=100, on_start=on_start)
    run(go())
    assert (tmp_path / "z.part").read_bytes() == server.zone and len(started) == 2


# ---------------------------------------------------------------------------------------------------
# the job, end to end
# ---------------------------------------------------------------------------------------------------

class FakeConn:
    """Implements just the SQL the czds module sends."""

    def __init__(self):
        self.zones: dict[str, dict] = {}
        self.runs: list[dict] = []
        self.unexpected: list[str] = []

    async def execute(self, sql, params=()):
        rows = []
        if sql.startswith("SELECT * FROM czds_zones"):
            rows = [dict(z) for _, z in sorted(self.zones.items())]
        elif sql.startswith("INSERT INTO czds_zones"):
            cols = [c.strip() for c in re.match(r"INSERT INTO czds_zones \(([^)]*)\)", sql).group(1).split(",")]
            cols.remove("updated_at")
            vals = [getattr(v, "obj", v) for v in params]
            row = self.zones.setdefault(vals[0], {"tld": vals[0], "configured": False, "approved": False,
                                                  "status": "pending", "fail_count": 0, "state": {}})
            row.update(dict(zip(cols, vals)))
            row["updated_at"] = czds.utcnow()
        elif sql.startswith("INSERT INTO czds_runs"):
            cols = [c.strip() for c in re.match(r"INSERT INTO czds_runs \(([^)]*)\)", sql).group(1).split(",")]
            self.runs.append(dict(zip(cols, params)))
        elif sql.startswith("DELETE FROM czds_runs"):
            pass
        else:
            self.unexpected.append(sql)
        return SimpleNamespace(fetchall=_async(rows), fetchone=_async(rows[0] if rows else None))


def _async(value):
    async def f():
        return value
    return f


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def connection(self):
        conn = self.conn

        class _Ctx:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *a):
                return False
        return _Ctx()


class Job:
    """Drives czds.run_once with a fake clock, a fake CZDS server and a fake database."""

    def __init__(self, monkeypatch, tmp_path, tlds=("top", "xyz", "au")):
        self.now = D1 + 5 * H
        self.server = Server(lambda: self.now)
        self.server.links = [TOP_URL, "https://czds-download-api.icann.org/czds/downloads/shop.zone"]
        self.conn = FakeConn()
        self.stored: list[tuple[str, str]] = []
        self.events: list[tuple[int, str, dict]] = []
        self.slept: list[float] = []
        self.known = {"commbank-verify.top"}          # already in `domains` from CT
        settings = SimpleNamespace(czds_username="u@example.org", czds_password="pw", czds_tlds=list(tlds),
                                   data_dir=tmp_path)
        pool = FakePool(self.conn)

        class Ctx:
            state: dict = {}

            async def pool(self):
                return pool
        self.ctx = Ctx()
        self.ctx.settings = settings
        self.ctx.state = {}
        self.zdir = tmp_path / "czds" / "top"

        async def fake_sleep(seconds):
            self.slept.append(seconds)
            self.now += timedelta(seconds=seconds)

        async def fake_store_hit(conn, hit, source="ct", issuer=None, ct_log=None):
            self.stored.append((hit.registered_domain, source))
            return len(self.stored), hit.registered_domain not in self.known

        async def fake_add_event(conn, domain_id, kind, detail=None):
            self.events.append((domain_id, kind, detail))

        for k in ("CZDS_WINDOW_START", "CZDS_WINDOW_HOURS", "CZDS_STRICT_SOA", "CZDS_MAX_COUNT_CHANGE"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setattr(czds, "utcnow", lambda: self.now)
        monkeypatch.setattr(czds, "_sleep", fake_sleep)
        monkeypatch.setattr(czds, "default_watchlist", lambda: WL)
        monkeypatch.setattr(czds, "store_hit", fake_store_hit)
        monkeypatch.setattr(db, "add_event", fake_add_event)
        monkeypatch.setattr(czds, "_sort_cmd_cache", {"cmd": None})
        monkeypatch.setattr(czds, "LOGIN_MAX_PER_WINDOW", 8)     # many simulated days in a few real seconds
        monkeypatch.setattr(czds, "make_http", lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(self.server.handler), headers={"User-Agent": czds.USER_AGENT}))

    def run(self, at: datetime) -> dict:
        self.now = at
        out = run(czds.run_once(self.ctx))
        assert self.conn.unexpected == []
        return out

    def gets(self) -> int:
        return self.server.count("GET", "czds-download-api.icann.org")

    def heads(self) -> int:
        return self.server.count("HEAD", "czds-download-api.icann.org")

    def logins(self) -> int:
        return self.server.count("POST", "account-api.icann.org")


def test_job_end_to_end(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path)
    s = job.server
    s.zone = zone_gz("top", ["alpha", "commbank-login", "beta"], 2026111600)

    # 05:00 day 1: approvals recorded, nothing downloaded before the window opens (06:30)
    out = job.run(D1 + 5 * H)
    z = job.conn.zones
    assert z["top"]["approved"] and z["top"]["configured"] and z["top"]["status"] == "approved"
    assert z["xyz"]["status"] == "not_approved" and z["au"]["status"] == "not_approved"
    assert z["shop"]["approved"] and not z["shop"]["configured"] and z["shop"]["status"] == "not_configured"
    assert job.gets() == 0 and job.heads() == 0 and job.logins() == 1
    assert out["approved"] == 1 and out["next_due"] == (D1 + timedelta(hours=6, minutes=30)).isoformat()

    # 06:00: the zone is due within the hour, so the run waits for it, then stores the baseline
    out = job.run(D1 + 6 * H)
    assert job.slept == [1800.0] and job.gets() == 1 and job.heads() == 1 and job.logins() == 1   # cached token
    top = z["top"]
    assert top["status"] == "baseline" and top["total_names"] == 3 and top["new_names"] is None
    assert top["last_download"] == D1 + timedelta(hours=6, minutes=30) and top["soa_serial"] == 2026111600
    assert job.stored == []                               # first file: every name is old, nothing is "new"
    assert sorted(p.name for p in job.zdir.iterdir()) == ["names.gz"]      # raw download deleted
    assert out["processed"]["top"]["status"] == "baseline"

    # 07:00 and 23:00 day 1: never a second download within 24 h
    job.run(D1 + 7 * H)
    job.run(D1 + 23 * H)
    assert job.gets() == 1 and job.heads() == 1

    # 06:40 day 2: new file with two new names; one scores as a brand hit, one is already known from CT
    s.zone = zone_gz("top", ["alpha", "commbank-login", "commbank-verify", "commbank-signin-login", "gamma"],
                     2026111700)
    s.last_modified = "Tue, 17 Nov 2026 05:10:00 GMT"
    out = job.run(D1 + DAY + timedelta(hours=6, minutes=40))
    assert job.gets() == 2 and job.logins() == 2           # the day-old token expired
    top = z["top"]
    assert top["status"] == "ok" and (top["total_names"], top["new_names"], top["removed_names"]) == (5, 3, 1)
    assert sorted(job.stored) == [("commbank-signin-login.top", "czds"), ("commbank-verify.top", "czds")]
    assert top["hits"] == 2 and top["new_hits"] == 1
    assert [e[1] for e in job.events] == ["czds_new_delegation"]
    assert sorted(p.name for p in job.zdir.iterdir()) == ["names.gz", "names.prev.gz"]
    assert out["new_names"] == 3 and out["hits"] == 2
    assert [r["status"] for r in job.conn.runs] == ["baseline", "ok"]

    # day 3: ICANN still serves the same file (same Last-Modified and size): HEAD only, no GET
    job.run(D1 + 2 * DAY + timedelta(hours=6, minutes=50))
    assert job.heads() == 3 and job.gets() == 2 and z["top"]["status"] == "unchanged"
    assert z["top"]["retry_at"] > D1 + 3 * DAY

    # day 4: the approval disappears from the links list (like the .top revocation in January 2026)
    s.links = ["https://czds-download-api.icann.org/czds/downloads/shop.zone"]
    out = job.run(D1 + 3 * DAY + 7 * H)
    assert out["revoked"] == ["top"] and z["top"]["status"] == "revoked" and not z["top"]["approved"]
    assert job.gets() == 2 and z["top"]["next_due"] is None

    # removing the TLD from CZDS_TLDS: no longer configured, nothing due
    job.ctx.settings.czds_tlds = ["xyz"]
    job.run(D1 + 3 * DAY + 8 * H)
    assert not z["top"]["configured"] and z["xyz"]["configured"]


def test_job_never_retries_an_interrupted_download_the_same_day(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    job.server.zone = zone_gz("top", ["alpha", "beta"], 1)
    job.server.stream_error = True
    job.run(D1 + timedelta(hours=6, minutes=40))
    top = job.conn.zones["top"]
    assert job.gets() == 1 and top["status"] == "error" and "next try tomorrow" in top["error"]
    assert not any(job.zdir.iterdir())
    job.server.stream_error = False
    job.run(D1 + 9 * H)
    job.run(D1 + 13 * H)
    assert job.gets() == 1
    job.run(D1 + DAY + 7 * H)
    assert job.gets() == 2 and job.conn.zones["top"]["status"] == "baseline"


def test_job_cleans_up_after_a_worker_that_died_mid_download(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    started = D1 + timedelta(hours=6, minutes=30)
    job.conn.zones["top"] = {"tld": "top", "configured": True, "approved": True, "download_url": TOP_URL,
                             "status": "downloading", "last_download": started, "last_head": started,
                             "fail_count": 0, "state": {}}
    write(job.zdir / czds.PART, b"\x1f\x8b partial")
    job.run(D1 + 8 * H)
    top = job.conn.zones["top"]
    assert top["status"] == "error" and "interrupted" in top["error"]
    assert not (job.zdir / czds.PART).exists() and job.gets() == 0 and job.heads() == 0


def test_job_rejects_a_truncated_download(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    job.server.zone = zone_gz("top", ["alpha", "beta"], 1)
    job.server.bad_length = True
    job.run(D1 + 7 * H)
    top = job.conn.zones["top"]
    assert top["status"] == "invalid" and "truncated" in top["error"] and job.gets() == 1
    assert not any(job.zdir.iterdir())
    assert job.conn.runs[-1]["status"] == "invalid"


def test_job_tolerates_a_registry_without_a_closing_soa(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    names = ["alpha", "beta"]
    for day in range(4):
        job.server.zone = zone_gz("top", names + [f"new{day}"], 10 + day, end_soa=False)
        job.server.last_modified = f"day {day}"
        job.run(D1 + day * DAY + timedelta(hours=7, minutes=day * 6))
        status = job.conn.zones["top"]["status"]
        assert status == ("invalid" if day < czds.TOLERATE_AFTER else "baseline" if day == czds.TOLERATE_AFTER else "ok")
    assert "closing SOA" in (job.conn.zones["top"]["error"] or "")


def test_job_with_empty_tld_list_only_lists_approvals(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=())
    out = job.run(D1 + 7 * H)
    assert out == {"skipped": "CZDS_TLDS is empty", "approved": 2}
    assert job.gets() == 0 and job.heads() == 0


def test_job_login_failure_is_reported_not_retried_each_run(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    job.server.login_status = 401
    with pytest.raises(czds.CzdsAuthError):
        job.run(D1 + 7 * H)
    with pytest.raises(czds.CzdsAuthError):
        job.run(D1 + 8 * H)
    assert job.logins() == 1


def test_job_module_is_discovered():
    from cybercheck.jobs import czds as job_mod
    assert job_mod.JOB.name == "czds" and 1800 <= job_mod.JOB.interval <= 7200


# ---------------------------------------------------------------------------------------------------
# dashboard page
# ---------------------------------------------------------------------------------------------------

def _client(monkeypatch, *, has_credentials=True, migrated=True):
    import psycopg
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from cybercheck.web import pages_czds
    from cybercheck.web.common import templates

    now = datetime.now(UTC)
    zones = [
        {"tld": "top", "configured": True, "approved": True, "approved_at": now - 9 * DAY, "last_head": now - 2 * H,
         "last_download": now - 2 * H, "last_processed": now - H, "next_due": now + 22 * H, "retry_at": None,
         "total_names": 7320275, "new_names": 18234, "removed_names": 15012, "hits": 3, "new_hits": 2,
         "soa_serial": 1, "file_bytes": 1_250_000_000, "status": "ok", "error": "<script>alert(1)</script>",
         "fail_count": 0, "duration_s": 312.4, "updated_at": now},
        {"tld": "shop", "configured": False, "approved": True, "status": "not_configured", "error": None},
    ]

    async def fake_fetchall(sql, params=()):
        if "FROM czds_zones" in sql or "FROM czds_runs" in sql:
            if not migrated:
                raise psycopg.errors.UndefinedTable("relation does not exist")
            if "FROM czds_zones" in sql:
                return zones
            return [{"tld": "top", "at": now - H, "status": "ok", "total_names": 7320275, "new_names": 18234,
                     "removed_names": 15012, "hits": 3, "new_hits": 2, "file_bytes": 1_250_000_000,
                     "duration_s": 312.4, "error": None}]
        if "FROM domain_events" in sql:
            return [{"id": 42, "registered_domain": "commbank-verify.top", "unicode_domain": None, "hostnames": [],
                     "brand_id": "commbank", "score": 57, "tier": "watch", "status": "open", "first_seen": now,
                     "live_state": "unknown", "dns_state": "resolves", "ai_verdict": None, "final_score": None,
                     "source": "czds", "czds_at": now}]
        raise AssertionError(sql)

    async def fake_fetchone(sql, params=()):
        if "FROM kv" in sql:
            assert params == ("job:czds",)
            return {"value": {"ok": False, "error": "CzdsAuthError: <b>bad</b>", "last_run": now.isoformat()},
                    "updated_at": now}
        return {"stored_by_czds": 5, "new_24h": 1, "new_7d": 4, "known_7d": 2}

    c = czds.CzdsConfig(username="secret-user@example.org" if has_credentials else "",
                        password="hunter2" if has_credentials else "", tlds=("top", "au", "xyz"), bad_tlds=("x_y",))
    monkeypatch.setattr(pages_czds, "fetchall", fake_fetchall)
    monkeypatch.setattr(pages_czds, "fetchone", fake_fetchone)
    monkeypatch.setattr(czds, "load_config", lambda s=None: c)
    monkeypatch.setattr(czds, "disk_usage", lambda cfg: 3 * (1 << 30))
    app = FastAPI()
    nav = []
    pages_czds.register(app, templates, nav)
    assert nav == [("/czds", "CZDS")]
    return TestClient(app)


def test_czds_page_renders_and_escapes(monkeypatch):
    r = _client(monkeypatch).get("/czds")
    assert r.status_code == 200
    t = r.text
    assert "CZDS credentials configured" in t
    assert "secret-user" not in t and "hunter2" not in t                 # never shows the login
    assert "<script>alert(1)</script>" not in t and "&lt;script&gt;" in t
    assert "<b>bad</b>" not in t
    assert 'href="/domain/42"' in t and "commbank-verify.top" in t
    assert "7,320,275" in t and "1.2 GB" in t and "3.0 GB" in t
    assert ".au" not in t or "not in CZDS" in t
    assert "x_y" in t and "shop" in t                                    # invalid entry, approved-but-unused zone
    assert ".xyz" in t                                                   # configured, not recorded yet


def test_czds_page_without_credentials_or_tables(monkeypatch):
    r = _client(monkeypatch, has_credentials=False, migrated=False).get("/czds")
    assert r.status_code == 200
    assert "no CZDS credentials" in r.text and "060_czds.sql" in r.text


def test_page_is_registered_in_the_dashboard():
    from cybercheck.web.app import NAV, app
    assert any(getattr(r, "path", None) == "/czds" for r in app.routes)
    assert ("/czds", "CZDS") in NAV


def test_migration_defines_the_columns_the_module_writes():
    sql = (Path(__file__).resolve().parent.parent / "migrations" / "060_czds.sql").read_text()
    zones = re.search(r"CREATE TABLE IF NOT EXISTS czds_zones \((.*?)\n\);", sql, re.S).group(1)
    runs = re.search(r"CREATE TABLE IF NOT EXISTS czds_runs \((.*?)\n\);", sql, re.S).group(1)
    zone_cols = {m.group(1) for m in re.finditer(r"^\s+([a-z_]+)\s+[a-z]", zones, re.M)}
    run_cols = {m.group(1) for m in re.finditer(r"^\s+([a-z_]+)\s+[a-z]", runs, re.M)}
    assert czds.ZONE_COLUMNS | {"tld", "updated_at"} == zone_cols
    assert set(czds.RUN_COLUMNS) | {"id", "tld", "at"} == run_cols
    assert {"tld", "approved", "last_download", "last_processed", "total_names", "new_names", "hits", "status",
            "error"} <= zone_cols


# ---------------------------------------------------------------------------------------------------
# adversarial review: hostile files, disk limits, clean-up, and the 24 h rule under random faults
# ---------------------------------------------------------------------------------------------------

def test_scan_zone_refuses_a_line_without_newlines(monkeypatch, tmp_path):
    monkeypatch.setattr(czds, "MAX_LINE", 4096)
    soa = zone_text("top", [], 1).split("\n")[0]
    for body in (b"x" * 20000,                                        # first line already too long
                 (soa + "\n").encode() + b"a.top.\t3600\tin\tns\t" + b"x" * 20000):   # a later line
        with pytest.raises(czds.ZoneInvalid, match="longer than"):
            scan(write(tmp_path / "z.gz", gzip.compress(body)))
    # a long but terminated line (big RRSIG/TXT) is fine
    ok = zone_gz("top", ["a"], 1, extra=["a.top.\t3600\tin\ttxt\t" + "y" * 3000])
    assert scan(write(tmp_path / "ok.gz", ok))[0] == [b"a"]


def test_lenient_soa_serial_when_the_owner_contains_soa(tmp_path):
    text = ("SOA. 3600 IN SOA ns0.nic.soa. hostmaster.nic.soa. 42 1800 900 604800 3600\n"
            "x.soa. 3600 IN NS ns1.example.net.\n"
            "SOA. 3600 IN SOA ns0.nic.soa. hostmaster.nic.soa. 42 1800 900 604800 3600\n")
    labels, st = scan(write(tmp_path / "z.gz", gzip.compress(text.encode())), tld="soa")
    assert labels == [b"x"] and st.serial == 42 and not st.strict


def test_scan_zone_stops_when_the_disk_fills(monkeypatch, tmp_path):
    monkeypatch.setattr(czds, "SCAN_DISK_CHECK_LINES", 4)
    monkeypatch.setattr(czds.shutil, "disk_usage", lambda p: SimpleNamespace(free=10, total=100, used=90))
    with pytest.raises(czds.LowDisk):
        scan(write(tmp_path / "z.gz", zone_gz("top", ["a", "b", "c"], 1)))


def test_job_low_disk_while_processing_keeps_the_previous_list(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    job.server.zone = zone_gz("top", ["alpha", "beta"], 1)
    job.run(D1 + 7 * H)
    assert job.conn.zones["top"]["status"] == "baseline"
    job.server.zone = zone_gz("top", ["alpha", "beta", "commbank-login"], 2)
    job.server.last_modified = "day 2"

    def full(*a, **kw):
        raise czds.LowDisk("disk nearly full while processing the zone; stopped")
    real = czds.process_zone
    monkeypatch.setattr(czds, "process_zone", full)
    job.run(D1 + DAY + 7 * H)
    top = job.conn.zones["top"]
    assert top["status"] == "low_disk" and job.gets() == 2
    assert sorted(p.name for p in job.zdir.iterdir()) == ["names.gz"]      # raw deleted, list kept
    monkeypatch.setattr(czds, "process_zone", real)
    job.server.last_modified = "day 3"
    job.server.zone = zone_gz("top", ["alpha", "beta", "commbank-login"], 3)
    job.run(D1 + 2 * DAY + 7 * H)
    assert job.conn.zones["top"]["status"] == "ok" and job.stored == [("commbank-login.top", "czds")]


def test_empty_tld_list_still_deletes_old_lists(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=())
    old = tmp_path / "czds" / "top"
    write(old / czds.CUR_LIST, b"x")
    write(old / czds.RAW, b"raw")
    past = (D1 - 30 * DAY).timestamp()
    os.utime(old / czds.CUR_LIST, (past, past))
    os.utime(old, (past, past))
    out = job.run(D1 + 7 * H)
    assert out.get("deleted_lists") == ["top"] and not old.exists()


def test_no_credentials_still_deletes_lists_of_removed_tlds(monkeypatch, tmp_path):
    monkeypatch.setattr(czds, "make_http", lambda: (_ for _ in ()).throw(AssertionError("no network")))
    old = tmp_path / "czds" / "xyz"
    write(old / czds.RAW, b"raw zone data")
    write(old / czds.CUR_LIST, b"x")

    class Ctx:
        settings = SimpleNamespace(czds_username="", czds_password="", czds_tlds=["top"], data_dir=tmp_path)
        state: dict = {}

        async def pool(self):
            raise AssertionError("no database without credentials")

    assert run(czds.run_once(Ctx())) == {"skipped": "no CZDS credentials"}
    assert not (old / czds.RAW).exists() and (old / czds.CUR_LIST).exists()   # raw at once, list after 7 days


def _no_creds_ctx(tmp_path, tlds=("top",)):
    class Ctx:
        settings = SimpleNamespace(czds_username="", czds_password="", czds_tlds=list(tlds), data_dir=tmp_path)
        state: dict = {}

        async def pool(self):
            raise AssertionError("no database without credentials")
    return Ctx()


def _age(zdir: Path, days: float) -> None:
    past = time.time() - days * 86400
    for p in list(zdir.iterdir()) + [zdir]:
        os.utime(p, (past, past))


def test_no_credentials_deletes_lists_of_tlds_still_in_czds_tlds(monkeypatch, tmp_path):
    # credentials removed but CZDS_TLDS left set: CZDS is no longer in use, so every zone's data goes (T&C s1.4)
    monkeypatch.setattr(czds, "make_http", lambda: (_ for _ in ()).throw(AssertionError("no network")))
    old = tmp_path / "czds" / "top"
    for name in (czds.CUR_LIST, czds.PREV_LIST):
        write(old / name, b"x")
    _age(old, 30)
    recent = tmp_path / "czds" / "shop"
    for name in (czds.CUR_LIST, czds.PREV_LIST, czds.RAW, czds.PART):
        write(recent / name, b"x")
    write(recent / czds.TMP_DIR / "chunk", b"x")
    out = run(czds.run_once(_no_creds_ctx(tmp_path, tlds=("top", "shop"))))
    assert out == {"skipped": "no CZDS credentials", "deleted_lists": ["top"]}
    assert not old.exists()
    assert sorted(p.name for p in recent.iterdir()) == [czds.CUR_LIST, czds.PREV_LIST]   # raw and temp at once
    _age(recent, 8)
    assert run(czds.run_once(_no_creds_ctx(tmp_path, tlds=("top", "shop"))))["deleted_lists"] == ["shop"]
    assert not recent.exists()


def test_no_credentials_cleanup_leaves_a_run_of_another_process_alone(tmp_path):
    zdir = tmp_path / "czds" / "top"
    write(zdir / czds.PART, b"downloading")
    write(zdir / czds.CUR_LIST, b"x")
    _age(zdir, 30)
    held = czds._lock(cfg(tmp_path))          # another process (a separate open file) holds the lock
    try:
        assert run(czds.run_once(_no_creds_ctx(tmp_path))) == {"skipped": "no CZDS credentials"}
        assert (zdir / czds.PART).exists()
    finally:
        czds._unlock(held)
    assert run(czds.run_once(_no_creds_ctx(tmp_path)))["deleted_lists"] == ["top"] and not zdir.exists()


def test_cleanup_if_disabled_runs_only_when_the_job_is_off(monkeypatch, tmp_path):
    s = SimpleNamespace(czds_username="u@example.org", czds_password="pw", czds_tlds=["top"], data_dir=tmp_path)
    zdir = tmp_path / "czds" / "top"
    write(zdir / czds.CUR_LIST, b"x")
    write(zdir / czds.RAW, b"raw zone data")
    _age(zdir, 30)
    monkeypatch.delenv("JOB_CZDS_ENABLED", raising=False)
    assert czds.cleanup_if_disabled(s) == [] and (zdir / czds.RAW).exists()     # the job cleans up itself
    monkeypatch.setenv("JOB_CZDS_ENABLED", "true")
    assert czds.cleanup_if_disabled(s) == [] and (zdir / czds.RAW).exists()
    monkeypatch.setenv("JOB_CZDS_ENABLED", "false")
    assert czds.cleanup_if_disabled(s) == ["top"] and not zdir.exists()
    assert czds.cleanup_if_disabled(s) == []                                   # nothing left; never raises
    s.data_dir = tmp_path / "missing"
    assert czds.cleanup_if_disabled(s) == [] and not (tmp_path / "missing").exists()


def test_cleanup_if_disabled_keeps_recent_lists_but_deletes_raw_files(monkeypatch, tmp_path):
    s = SimpleNamespace(czds_username="", czds_password="", czds_tlds=["top"], data_dir=tmp_path)
    zdir = tmp_path / "czds" / "top"
    write(zdir / czds.CUR_LIST, b"x")
    write(zdir / czds.PART, b"partial")
    monkeypatch.setenv("JOB_CZDS_ENABLED", "off")
    assert czds.cleanup_if_disabled(s) == []
    assert (zdir / czds.CUR_LIST).exists() and not (zdir / czds.PART).exists()


def test_cleanup_if_disabled_never_raises(monkeypatch, tmp_path, caplog):
    # meant to run first thing in another job (housekeeping): a clean-up error must not fail that job
    def broken(s=None):
        raise RuntimeError("bad settings")
    monkeypatch.setattr(czds, "load_config", broken)
    monkeypatch.setenv("JOB_CZDS_ENABLED", "false")
    with caplog.at_level(logging.ERROR, logger="cybercheck.czds"):
        assert czds.cleanup_if_disabled(SimpleNamespace(data_dir=tmp_path)) == []
    assert "clean-up while the job is turned off failed" in caplog.text


def test_pending_file_of_a_revoked_zone_is_deleted(monkeypatch, tmp_path):
    job = Job(monkeypatch, tmp_path, tlds=("top",))
    job.server.links = []
    job.conn.zones["top"] = {"tld": "top", "configured": True, "approved": True, "download_url": TOP_URL,
                             "status": "downloaded", "last_download": D1 + 6 * H, "fail_count": 0, "state": {}}
    write(job.zdir / czds.RAW, zone_gz("top", ["a"], 1))
    job.run(D1 + 8 * H)
    top = job.conn.zones["top"]
    assert not (job.zdir / czds.RAW).exists() and top["status"] == "error" and "access ended" in top["error"]
    assert not top["approved"] and job.gets() == 0


def test_runs_cleanup_sql_casts_the_interval():
    import inspect
    assert "make_interval(days => %s::int)" in inspect.getsource(czds._run)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_never_more_than_one_get_and_one_head_per_24h_under_random_faults(monkeypatch, tmp_path, seed):
    import random
    rnd = random.Random(seed)
    job = Job(monkeypatch, tmp_path / str(seed), tlds=("top",))
    monkeypatch.setattr(czds, "LOGIN_WINDOW_S", 0.0)     # 12 simulated days of logins in a few real seconds
    s = job.server
    times: list[tuple[str, datetime]] = []
    base_handler = s.handler
    mode = {"fail": None}

    def handler(request):
        if request.url.host == "czds-download-api.icann.org" and request.method == "GET" and mode["fail"] == "500":
            s.requests.append(request)
            return httpx.Response(500)
        resp = base_handler(request)
        if request.url.host == "czds-download-api.icann.org" and resp.status_code == 200:
            times.append((request.method, job.now))      # HEAD, or a GET that serves the zone
        return resp
    monkeypatch.setattr(czds, "make_http", lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(handler), headers={"User-Agent": czds.USER_AGENT}))

    names = ["alpha", "beta", "gamma"]
    serial = 1
    s.zone = zone_gz("top", names, serial)
    statuses = set()
    for hour in range(24 * 12):
        t = D1 + hour * H + timedelta(minutes=rnd.randrange(0, 50))
        if t.hour == 3:          # ICANN publishes a new file each night
            serial += 1
            names.append(f"commbank-login{serial}" if rnd.random() < 0.3 else f"n{serial}")
            s.zone = zone_gz("top", names, serial, end_soa=rnd.random() > 0.15)
            s.last_modified = f"serial {serial}"
        mode["fail"] = rnd.choice([None, None, None, "500"])
        s.stream_error = rnd.random() < 0.1
        s.bad_length = rnd.random() < 0.1
        job.run(t)
        statuses.add(job.conn.zones["top"]["status"])
    for method in ("GET", "HEAD"):
        at = [w for m, w in times if m == method]
        assert len(at) >= 5, (method, at)
        assert all(b - a >= timedelta(hours=24) for a, b in zip(at, at[1:])), (method, at)
        assert all(w.hour * 60 + w.minute >= 6 * 60 + 30 and w.hour < 15 for w in at), at   # inside the window
    assert statuses & {"ok", "baseline"}
    assert not any(job.zdir.glob("zone.gz*")) and not (job.zdir / czds.TMP_DIR).exists()
    assert {p.name for p in job.zdir.iterdir()} <= {czds.CUR_LIST, czds.PREV_LIST}
