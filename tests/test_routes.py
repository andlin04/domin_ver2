"""Scan routes: Tor and Mullvad for posture scans and inventory jobs; Mullvad tunnel credentials."""
import json
import os
import random
import shutil
import subprocess
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import dns.message
import dns.rcode
import dns.resolver
import httpx
import pytest
from fastapi.testclient import TestClient
from test_fingerprint import PW, SCAN_XML, transport
from test_posture import run_queue, sign_in

from domin import admin, db, fingerprint, jobs, mullvad, posture, proxy, scanner, users
from domin.config import Settings
from domin.web import create_app

DOM = "routes.example"
ACCOUNT = "0000000000000000"                                   # made-up account number
KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="             # made-up WireGuard key (32 zero bytes)
RAW_RELAYS = [   # the shape of api.mullvad.net/www/relays/all/, made up
    {"hostname": "se-got-wg-001", "country_code": "se", "country_name": "Sweden", "city_code": "got",
     "city_name": "Gothenburg", "type": "wireguard", "active": True, "socks_name": "se-got-wg-socks5-001.relays.mullvad.net",
     "socks_port": 1080, "pubkey": "x", "ipv4_addr_in": "192.0.2.1"},
    {"hostname": "se-sto-wg-002", "country_code": "se", "country_name": "Sweden", "city_code": "sto",
     "city_name": "Stockholm", "type": "wireguard", "active": True, "socks_name": "se-sto-wg-socks5-002.relays.mullvad.net",
     "socks_port": 1080},
    {"hostname": "de-fra-wg-001", "country_code": "de", "country_name": "Germany", "city_code": "fra",
     "city_name": "Frankfurt", "type": "wireguard", "active": True, "socks_name": "de-fra-wg-socks5-001.relays.mullvad.net",
     "socks_port": 1080},
    {"hostname": "fi-hel-wg-001", "country_code": "fi", "country_name": "Finland", "city_code": "hel",
     "city_name": "Helsinki", "type": "wireguard", "active": False, "socks_name": "fi-hel-wg-socks5-001.relays.mullvad.net",
     "socks_port": 1080},
    {"hostname": "se-got-ovpn-001", "country_code": "se", "type": "openvpn", "active": True},
    {"hostname": "bad", "country_code": "se", "type": "wireguard", "socks_name": "evil.example.com", "socks_port": 1080},
]
RELAYS = mullvad.parse(RAW_RELAYS)
RECORDS = [{"host": "www.routes.example", "ip": "198.51.100.7", "country": "Sweden"},
           {"host": "nowhere.routes.example", "ip": "198.51.100.8", "country": ""},
           {"host": "lan.routes.example", "ip": "172.20.4.50", "country": ""}]


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1",),
                cve_db_path=str(tmp_path / "cve.json"))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "adm", "admin", PW)
        users.create(c, "ana", "analyst", PW)
        users.create(c, "vee", "viewer", PW)
        db.save_scan(c, DOM, db.now(), "scan", RECORDS)
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["198.51.100.0/24", "172.20.4.0/24"]})
        mullvad.store(c, RELAYS)
    return s


@pytest.fixture(autouse=True)
def doc_addresses_are_public(monkeypatch):
    """Documentation addresses (198.51.100.0/24) stand in for public targets here."""
    monkeypatch.setattr(proxy, "public_address", lambda ip: ip.startswith("198.51.100.") or
                        proxy.ipaddress.ip_address(ip).is_global)


def cfg(**kw) -> dict:
    """The single-route setting of earlier builds (stored under LEGACY_KEY: read through the migration)."""
    return {**proxy.LEGACY_DEFAULT, "route": "mullvad", "posture": True, **kw}


def rt(kind: str = "mullvad", **kw) -> dict:
    """A named route."""
    return {**proxy.ROUTE_DEFAULT, "id": "r1", "name": proxy.KINDS[kind], "kind": kind, **kw}


def no_fetch():
    def handle(req):
        raise AssertionError(f"no fetch expected: {req.url}")
    return httpx.Client(transport=httpx.MockTransport(handle))


# ---- relay list ----

def test_relay_list_keeps_wireguard_relays_with_socks():
    assert [r["hostname"] for r in RELAYS] == ["se-got-wg-001", "se-sto-wg-002", "de-fra-wg-001", "fi-hel-wg-001"]
    assert RELAYS[0] == {"hostname": "se-got-wg-001", "country_code": "se", "country_name": "Sweden",
                         "city_code": "got", "city_name": "Gothenburg",
                         "socks_name": "se-got-wg-socks5-001.relays.mullvad.net", "socks_port": 1080, "active": True}
    assert mullvad.parse({"not": "a list"}) == []
    assert mullvad.countries(RELAYS) == [("fi", "Finland", 0), ("de", "Germany", 1), ("se", "Sweden", 2)]
    assert ("se", "got", "Gothenburg") in mullvad.cities(RELAYS)


def test_relay_cache_is_refreshed_after_a_day(settings):
    fetched = []

    def handle(req):
        fetched.append(str(req.url))
        return httpx.Response(200, json=RAW_RELAYS[:1])
    later = datetime.now() + timedelta(hours=25)
    with db.connect(settings.db_path) as c, httpx.Client(transport=httpx.MockTransport(handle)) as client:
        assert len(mullvad.relays(c, client)) == 4 and not fetched   # fresh cache: no fetch
        assert mullvad.age(mullvad.load(c)[1]) < timedelta(minutes=1)
        assert len(mullvad.relays(c, client, now=later)) == 1 and fetched == [mullvad.RELAYS_URL]
        assert len(mullvad.load(c)[0]) == 1


def test_failed_refresh_keeps_a_stale_list_and_no_list_is_an_error(settings):
    def down(req):
        return httpx.Response(503)
    later = datetime.now() + timedelta(days=3)
    with db.connect(settings.db_path) as c, httpx.Client(transport=httpx.MockTransport(down)) as client:
        assert len(mullvad.relays(c, client, now=later)) == 4
        c.execute("DELETE FROM kv WHERE key = ?", (mullvad.RELAYS_KEY,))
        with pytest.raises(mullvad.MullvadError, match="cannot fetch"):
            mullvad.relays(c, client)


# ---- relay choice per mode ----

def test_follow_host_picks_a_relay_in_the_address_country(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        h = proxy.hop(c, rt(mullvad_mode="follow"), "198.51.100.7", "Sweden", client, random.Random(1))
        assert h["type"] == "socks5" and h["host"].startswith("se-") and h["port"] == 1080
        assert h["label"].endswith("(se, follow host)")
        # a country without an active relay: the fallback, else the scan fails
        h = proxy.hop(c, rt(mullvad_mode="follow", mullvad_fallback="de"), "198.51.100.7", "Finland",
                      client)
        assert h["label"] == ("Mullvad: mullvad de-fra-wg-socks5-001 (de, follow host: no active Mullvad relay in "
                              "fi, fallback)")
        with pytest.raises(proxy.ProxyError, match="no active Mullvad relay in fi, and no fallback country"):
            proxy.hop(c, rt(mullvad_mode="follow"), "198.51.100.7", "Finland", client)
        with pytest.raises(proxy.ProxyError, match="the address has no country"):
            proxy.hop(c, rt(mullvad_mode="follow"), "198.51.100.8", "", client)


def test_fixed_country_and_city(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        h = proxy.hop(c, rt(mullvad_mode="fixed", mullvad_country="se", mullvad_city="sto"),
                      "198.51.100.7", "Germany", client)
        assert h["host"] == "se-sto-wg-socks5-002.relays.mullvad.net" and h["label"].endswith("(se, fixed)")
        with pytest.raises(proxy.ProxyError, match="no active Mullvad relay in fi"):
            proxy.hop(c, rt(mullvad_mode="fixed", mullvad_country="fi"), "198.51.100.7", "", client)


def test_automatic_follows_then_falls_back_then_takes_any(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        assert proxy.hop(c, rt(), "198.51.100.7", "Germany", client)["label"].endswith("(de, automatic)")
        h = proxy.hop(c, rt(mullvad_fallback="se"), "198.51.100.8", "", client)
        assert h["label"].endswith("(se, automatic: the address has no country, fallback)")
        h = proxy.hop(c, rt(), "198.51.100.8", "", client, random.Random(3))
        assert "automatic: the address has no country, any relay" in h["label"]
        assert h["host"] != "fi-hel-wg-socks5-001.relays.mullvad.net"   # never an inactive relay


def test_random_country_draws_a_country_per_scan_among_active_relays(settings):
    seen = {mullvad.choose(rt(mullvad_mode="random"), RELAYS, "se", random.Random(seed))[0]["country_code"]
            for seed in range(40)}
    assert seen == {"se", "de"}   # fi has no active relay; the host's country does not decide
    relay, how = mullvad.choose(rt(mullvad_mode="random"), RELAYS, "", random.Random(1))
    assert how == "random country" and relay["active"]
    assert proxy.details(rt(mullvad_mode="random")) == "mullvad, random country"
    with pytest.raises(mullvad.MullvadError):
        mullvad.choose(rt(mullvad_mode="random"), [], "se")


def test_relay_pick_is_random_among_active_ones():
    picks = {mullvad.pick(RELAYS, "se", "", random.Random(seed))["hostname"] for seed in range(20)}
    assert picks == {"se-got-wg-001", "se-sto-wg-002"}
    assert mullvad.pick(RELAYS, "fi") is None


def test_private_targets_never_go_through_tor_or_mullvad(settings):
    with db.connect(settings.db_path) as c:
        for route, name in (("tor", "Tor"), ("mullvad", "Mullvad")):
            with pytest.raises(proxy.ProxyError, match=f"private address can't go through {name}"):
                proxy.hop(c, rt(route), "172.20.4.50")
        assert proxy.hop(c, rt("custom", host="192.0.2.10"), "172.20.4.50")["host"] == "192.0.2.10"
        assert proxy.hop(c, None, "172.20.4.50") is None   # direct


def test_country_code_from_dbip_or_the_record(settings):
    with db.connect(settings.db_path) as c:
        assert mullvad.country_code(c, "198.51.100.7", "Sweden") == "se"
        assert mullvad.country_code(c, "198.51.100.7", "DE") == "de"
        assert mullvad.country_code(c, "198.51.100.7", "Narnia") == ""


# ---- nmap under proxychains ----

class Done:
    stdout, stderr = SCAN_XML, ""


def nmap_conf(monkeypatch, hop) -> str:
    seen = {}

    def fake(args, **kw):
        seen["text"] = open(args[args.index("-f") + 1], encoding="utf-8").read()
        return Done()
    monkeypatch.setattr(fingerprint.shutil, "which", lambda name: "/usr/bin/proxychains4")
    monkeypatch.setattr(proxy, "handshake", lambda cfg: "ok")
    monkeypatch.setattr(fingerprint.subprocess, "run", fake)
    monkeypatch.setattr(proxy.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("10.124.0.5", 0))])
    fingerprint.run_nmap("198.51.100.7", "22", 10, via=hop)
    return seen["text"]


def test_proxychains_conf_for_tor_and_mullvad(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        tor = proxy.hop(c, rt("tor"), "198.51.100.7")
        mv = proxy.hop(c, rt(mullvad_mode="fixed", mullvad_country="de"), "198.51.100.7")
    assert proxy.route(tor) == "Tor: tor 127.0.0.1:9050"
    assert nmap_conf(monkeypatch, tor).endswith("[ProxyList]\nsocks5 127.0.0.1 9050\n")
    assert nmap_conf(monkeypatch, mv).endswith("[ProxyList]\nsocks5 10.124.0.5 1080\n")   # relay name resolved


def test_worker_records_the_mullvad_route_without_secrets(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(cfg(mullvad_mode="follow")))
        mullvad.save_tunnel(c, {**mullvad.TUNNEL_DEFAULT, "account": ACCOUNT, "private_key": KEY,
                                "address": "10.64.0.2/32"})
        n = posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
    assert run_queue(settings) == n == 3
    assert len(seen) == 1 and seen[0]["host"].startswith("se-")   # only the Swedish address was scanned
    with db.connect(settings.db_path) as c:
        rows = {r["ip"]: r for r in posture.current(c, DOM)}
    assert rows["198.51.100.7"]["status"] == "done"
    assert " via Mullvad: mullvad se-" in rows["198.51.100.7"]["params"]
    assert rows["198.51.100.7"]["params"].endswith("(se, follow host)")
    assert rows["198.51.100.8"]["error"] == "route: the address has no country, and no fallback country is set"
    assert rows["172.20.4.50"]["error"] == "route: private address can't go through Mullvad"
    assert all(r["params"].endswith(("(se, follow host)", "via Mullvad: mullvad, follow host")) for r in rows.values())
    for r in rows.values():
        assert ACCOUNT not in json.dumps(r) and KEY not in json.dumps(r)


# ---- inventory jobs ----

def doh_answer(req: httpx.Request, zone: dict) -> httpx.Response:
    q = dns.message.from_wire(req.content)
    r = dns.message.make_response(q)
    name, rtype = q.question[0].name.to_text().rstrip("."), dns.rdatatype.to_text(q.question[0].rdtype)
    if (name, rtype) in zone:
        r.answer.append(dns.rrset.from_text(name + ".", 60, "IN", rtype, *zone[(name, rtype)]))
    elif not any(n == name for n, _ in zone):
        r.set_rcode(dns.rcode.NXDOMAIN)
    return httpx.Response(200, content=r.to_wire(), headers={"content-type": "application/dns-message"})


def test_routed_inventory_job_uses_the_socks_client_and_doh(settings, monkeypatch):
    zone = {(DOM, "A"): ["198.51.100.7"], (f"www.{DOM}", "A"): ["198.51.100.7"]}
    seen = {"doh": 0, "urls": []}

    def handle(req):
        seen["urls"].append(req.url.host)
        if req.url.host == "dns.quad9.net":
            seen["doh"] += 1
            return doh_answer(req, zone)
        if req.url.host == "crt.sh":
            return httpx.Response(200, json=[{"name_value": f"www.{DOM}"}])
        return httpx.Response(404)

    def http_client(proxy=None):
        seen["proxy"] = proxy
        return httpx.Client(transport=httpx.MockTransport(handle))

    def never(*a, **k):
        raise AssertionError("routed: no direct DNS or amass")
    monkeypatch.setattr(scanner.tools, "http_client", http_client)
    monkeypatch.setattr(proxy, "handshake", lambda hop: "ok")
    monkeypatch.setattr(scanner, "from_amass", never)
    monkeypatch.setattr(scanner, "_resolver", never)
    progress = []
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(cfg(route="tor", posture=False, inventory=True)))
        records = scanner.run(c, DOM, settings, progress.append, client=no_fetch())
    assert str(seen["proxy"].url) == "socks5://127.0.0.1:9050"
    assert seen["doh"] > 0 and set(seen["urls"]) == {"dns.quad9.net", "crt.sh"}
    assert {r["host"] for r in records} == {DOM, f"www.{DOM}"}
    assert "route: Tor: tor 127.0.0.1:9050" in progress and "amass skipped (routed scan)" in progress


def test_mullvad_inventory_uses_the_fixed_or_fallback_country(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        assert proxy.hop(c, rt(mullvad_fallback="de"), client=client)["host"].startswith("de-")
        assert proxy.hop(c, rt(mullvad_mode="fixed", mullvad_country="se", mullvad_city="got"), client=client)["host"].startswith("se-got-")
        with pytest.raises(proxy.ProxyError, match="no fallback country"):
            proxy.hop(c, rt(mullvad_mode="follow"), client=client)


def test_internal_zone_inventory_stays_direct(settings, monkeypatch):
    class FakeRes:
        nameservers = ["172.20.0.252"]

        def resolve(self, name, rtype):
            raise dns.resolver.NXDOMAIN

    def never(*a, **k):
        raise AssertionError("an internal zone never takes the route")
    monkeypatch.setattr(proxy, "hop", never)
    monkeypatch.setattr(proxy, "handshake", never)
    s = replace(settings, internal_zones=("home.arpa",), internal_dns=("172.20.0.252",))
    with db.connect(s.db_path) as c, no_fetch() as client:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(cfg(route="tor", inventory=True)))
        assert scanner.run(c, "srv.home.arpa", s, client=client, resolver=FakeRes()) == [
            {"host": "srv.home.arpa", "ip": ""}]


def test_inventory_job_fails_closed_when_the_route_is_down(settings, monkeypatch):
    def never(*a, **k):
        raise AssertionError("must not go out direct")
    monkeypatch.setattr(scanner.tools, "http_client", never)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(cfg(route="tor", inventory=True)))
        jobs.enqueue(c, DOM)
        job = jobs.claim(c)
    jobs.run_job(settings, job)   # the conftest refuses every proxy connect
    with db.connect(settings.db_path) as c:
        row = jobs.get(c, job["id"])
    assert row["status"] == "failed"
    assert row["error"].startswith("route: cannot reach the proxy at 127.0.0.1:9050")


def test_doh_resolver_answers_and_raises_like_dnspython():
    zone = {("a.example.com", "A"): ["198.51.100.7"], ("a.example.com", "MX"): ["10 mx.example.com."]}
    with httpx.Client(transport=httpx.MockTransport(lambda req: doh_answer(req, zone))) as client:
        r = scanner.DohResolver("https://dns.quad9.net/dns-query", client)
        assert scanner.resolve("a.example.com", r) == ["198.51.100.7"]
        assert [a.exchange.to_text() for a in r.resolve("a.example.com", "MX")] == ["mx.example.com."]
        with pytest.raises(dns.resolver.NXDOMAIN):
            r.resolve("b.example.com", "A")
        with pytest.raises(dns.resolver.NoAnswer):
            r.resolve("a.example.com", "TXT")
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(502))) as client:
        assert scanner.resolve("a.example.com", scanner.DohResolver("https://dns.quad9.net/dns-query", client)) == []


def test_rdap_over_the_routed_client():
    body = {"name": "DOC-NET", "country": "SE", "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
            "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Doc Org"]]]}]}
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json=body))) as client:
        assert scanner.rdap_http("198.51.100.7", client) == {
            "asn": "", "prefix": "198.51.100.0/24", "netname": "DOC-NET", "descr": "Doc Org", "country": "Sweden"}


# ---- page and tunnel credentials ----

def app_client(settings):
    return TestClient(create_app(settings, http=httpx.Client(transport=transport())),
                      base_url="https://testserver", client=("127.0.0.1", 50000))


def route_form(**kw) -> dict:
    return {"name": "Mullvad", "kind": "mullvad", "mullvad_mode": "follow", "mullvad_fallback": "se", **kw}


def page_form(**kw) -> dict:
    """The shared settings form."""
    return {"posture": "r1", "inventory": "direct", "cve": "direct", "doh": proxy.DOH,
            "mullvad_address": "10.64.0.2/32", **kw}


def test_tunnel_credentials_are_validated_kept_and_cleared():
    old = {"account": ACCOUNT, "private_key": KEY, "address": "10.64.0.2/32", "entry": ""}
    for bad in ({"mullvad_account": "1234"}, {"mullvad_key": "not-a-key"}, {"mullvad_key": KEY[:-2] + "B="},
                {"mullvad_address": "10.64.0.2"}, {"mullvad_address": "fc00::1/128"}, {"mullvad_entry": "swe"}):
        with pytest.raises(ValueError):
            mullvad.check_tunnel({"mullvad_address": "10.64.0.2/32", **bad}, old)
    with pytest.raises(ValueError, match="needs its tunnel address"):
        mullvad.check_tunnel({"mullvad_key": KEY}, {})
    kept = mullvad.check_tunnel({"mullvad_address": "10.64.0.2/32"}, old)
    assert kept["account"] == ACCOUNT and kept["private_key"] == KEY
    both = "10.64.0.2/32,fc00:bbbb:bbbb:bb01::2/128"
    assert mullvad.check_tunnel({"mullvad_address": both}, {})["address"] == both
    cleared = mullvad.check_tunnel({"clear_mullvad_key": "on", "clear_mullvad_account": "on"}, old)
    assert cleared["account"] == "" and cleared["private_key"] == ""
    assert mullvad.check_tunnel({"mullvad_account": "0000 0000 0000 0000"}, {})["account"] == ACCOUNT
    assert mullvad.tunnel_public(old) == {"account_saved": True, "key_saved": True, "address": "10.64.0.2/32",
                                          "entry": ""}


def test_admin_saves_mullvad_route_and_tunnel_request_has_no_secrets(settings):
    flag = settings.db_path.parent / mullvad.REQUEST_FILE
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        page = h.get("/admin/security/scan-settings").text
        assert "not set up (save a Mullvad account number" in page and "4 relays" in page and "Sweden (se, 2)" in page
        for bad, msg in ((route_form(mullvad_fallback="xx"), "Fallback country"),
                         (route_form(mullvad_mode="fixed"), "Pick the Mullvad country")):
            r = h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **bad})
            assert r.status_code == 422 and msg in r.text
        assert h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **route_form()},
                      follow_redirects=False).status_code == 303
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **page_form(
            mullvad_account=ACCOUNT, mullvad_key=KEY, mullvad_address="10.64.0.2/32")}, follow_redirects=False)
        assert r.status_code == 303 and "tunnel-requested" in r.headers["location"]
        text = flag.read_text()
        assert text.startswith("requested ") and ACCOUNT not in text and KEY not in text
        page = h.get("/admin/security/scan-settings").text
        assert ("Posture scans (default): Mullvad: mullvad, follow host (fallback se) · Inventory jobs: direct · "
                "CVE look-ups: direct") in page
        assert ACCOUNT not in page and KEY not in page and page.count("saved; blank keeps it") == 2
        assert "✗ not up" in page and "Mullvad (unavailable: tunnel not up)" in page
        assert "A request is waiting for the host" in page
        flag.unlink()
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **page_form(mullvad_address="10.64.0.2/32")},
                   follow_redirects=False)
        assert "ok=saved" in r.headers["location"] and not flag.exists()   # unchanged: no new request
        (settings.db_path.parent / mullvad.STATUS_FILE).write_text(
            json.dumps({"at": "2026-11-08T10:00:00", "ok": True, "message": "tunnel up via se-got-wg-001"}))
        assert "Last apply 2026-11-08 10:00:00: done.</b> Tunnel up via se-got-wg-001." in h.get(
            "/admin/security/scan-settings").text
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **page_form(mullvad_account="12")})
        assert r.status_code == 422 and "16 digits" in r.text
        assert h.post("/admin/security/scan-settings/tunnel", data={"csrf": csrf},
                      follow_redirects=False).status_code == 303 and flag.exists()
        assert "Test route: Mullvad: Mullvad tunnel down" in h.post("/admin/security/scan-settings/test",
                                                                     data={"csrf": csrf, "route": "r1"}).text
    with db.connect(settings.db_path) as c:
        assert mullvad.get_tunnel(c)["private_key"] == KEY
        assert proxy.find(proxy.get(c), "r1")["mullvad_fallback"] == "se"


def test_relay_list_refresh_button(settings, monkeypatch):
    monkeypatch.setattr(mullvad, "fetch", lambda client: RELAYS[:2])
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/security/scan-settings/relays", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        assert len(mullvad.load(c)[0]) == 2


def test_admin_turns_tor_on_and_off_through_a_request_file(settings):
    d = settings.db_path.parent
    req = d / proxy.TOR_REQUEST
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        assert "Turn Tor" not in h.get("/admin/security/scan-settings").text   # no switch on this host yet
        (d / proxy.TOR_STATE).write_text("off\n")
        page = h.get("/admin/security/scan-settings").text
        assert "the Tor service is off" in page and "Turn Tor on" in page
        r = h.post("/admin/security/scan-settings/tor", data={"csrf": csrf, "tor": "on"}, follow_redirects=False)
        assert r.status_code == 303 and "tor-requested" in r.headers["location"] and req.read_text() == "on\n"
        assert "switching" in h.get("/admin/security/scan-settings").text
        req.unlink()
        (d / proxy.TOR_STATE).write_text("on\n")
        assert "Turn Tor off" in h.get("/admin/security/scan-settings").text
        assert h.post("/admin/security/scan-settings/tor", data={"csrf": csrf, "tor": "maybe"}).status_code == 422
        assert not req.exists()
        assert h.post("/admin/security/scan-settings/tor", data={"tor": "off"}).status_code in (403, 404)   # no CSRF
        assert not req.exists()


def test_install_leaves_tor_off_and_root_scripts_write_only_fresh_temp_files():
    deploy = Path(__file__).parent.parent / "deploy"
    install = (deploy / "install.sh").read_text()
    assert "TOR_START=off" in install and 'tor-switch.sh" "$TOR_START"' in install
    switch = (deploy / "tor-switch.sh").read_text()
    assert "mktemp" in switch and '[ ! -L "$1" ]' in switch
    for name in ("tor-switch.sh", "mullvad-tunnel.sh", "public-sync.sh"):   # $DATA belongs to the app user
        assert "STATUS.tmp" not in (deploy / name).read_text() and "mktemp" in (deploy / name).read_text()
    assert ".public-import.db" not in (deploy / "public-sync.sh").read_text()


def test_root_helper_units_are_sandboxed_and_a_failed_tor_switch_shows():
    deploy = Path(__file__).parent.parent / "deploy"
    for name in ("tor", "mullvad", "public-sync"):
        unit = (deploy / f"domin-{name}.service").read_text()
        for line in ("ProtectSystem=strict", "NoNewPrivileges=true", "PrivateTmp=true", "ProtectHome=true",
                     "ReadWritePaths=/var/lib/domin", "CapabilityBoundingSet=CAP_"):
            assert line in unit, (name, line)
        assert ("PrivateNetwork=true" in unit) == (name != "mullvad")   # only Mullvad talks to the internet
    assert "/etc/rc2.d" in (deploy / "domin-tor.service").read_text()   # tor's SysV links (update-rc.d)
    assert "disable -q --now tor 2>/dev/null || true" not in (deploy / "tor-switch.sh").read_text()


def test_only_admins_reach_the_route_endpoints(settings):
    with db.connect(settings.db_path) as c:
        proxy.save_route(c, route_form())
    for name in ("ana", "vee"):
        with app_client(settings) as h:
            csrf = sign_in(h, name)
            for path in ("", "/test", "/relays", "/tunnel", "/tor", "/routes", "/routes/r1/delete"):
                assert h.post(f"/admin/security/scan-settings{path}",
                              data={"csrf": csrf, "tor": "on", **page_form(), **route_form(id="r1", name="Changed")}
                              ).status_code == 404
    assert not (settings.db_path.parent / mullvad.REQUEST_FILE).exists()
    assert not (settings.db_path.parent / proxy.TOR_REQUEST).exists()
    with db.connect(settings.db_path) as c:
        assert [r["name"] for r in proxy.get(c)["routes"]] == ["Mullvad"]


# ---- migration from the single route ----

def test_settings_saved_before_routes_still_apply(settings):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps({"enabled": True, "type": "http", "host": "192.0.2.10",
                                                      "port": 3128, "username": "", "password": "", "cve": True}))
        got = proxy.get(c)
    assert [(r["id"], r["name"], r["kind"], r["type"]) for r in got["routes"]] == [("r1", "Custom proxy", "custom",
                                                                                     "http")]
    assert (got["posture"], got["inventory"], got["cve"]) == ("r1", "direct", "r1")
    assert proxy.state_line(got) == ("Posture scans (default): Custom proxy: http 192.0.2.10:3128 · Inventory jobs: "
                                     "direct · CVE look-ups: Custom proxy: http 192.0.2.10:3128")


@pytest.mark.parametrize("old, want", [
    ({}, ([], "direct", "direct", "direct")),
    ({"route": "direct", "host": "192.0.2.10", "posture": True}, (["Custom proxy"], "direct", "direct", "direct")),
    ({"route": "tor", "posture": True, "inventory": True, "cve": True}, (["Tor"], "r1", "r1", "r1")),
    ({"route": "tor", "posture": False, "inventory": True, "cve": True}, (["Tor"], "direct", "r1", "direct")),
    ({"route": "mullvad", "posture": True, "inventory": False, "mullvad_mode": "fixed", "mullvad_country": "de"},
     (["Mullvad"], "r1", "direct", "direct")),
])
def test_migration_keeps_the_single_route_and_its_tick_boxes(settings, old, want):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps({**old, "doh": "https://doh.example/dns-query"}) if old else
                     "{}")
        got = proxy.get(c)
    assert ([r["name"] for r in got["routes"]], got["posture"], got["inventory"], got["cve"]) == want
    assert got["doh"] == ("https://doh.example/dns-query" if old else proxy.DOH)


def test_migrated_route_keeps_working_and_the_old_setting_stays(settings, monkeypatch):
    """The old setting is never rewritten: a rollback finds it as it was. Tor for posture and inventory, Mullvad
    settings carried over, then a save through the new page."""
    old = cfg(route="tor", inventory=True, tor_port=9150, mullvad_mode="fixed", mullvad_country="de")
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(old))
        assert proxy.hop(c, proxy.pick(proxy.get(c), "", "inventory"))["port"] == 9150
        n = posture.enqueue(c, DOM, posture.targets(c, DOM, ip="198.51.100.7")[0], "22", "ana")
    assert run_queue(settings) == n == 1 and seen[0]["port"] == 9150
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **route_form(name="Second")})
    with db.connect(settings.db_path) as c:
        assert [r["name"] for r in proxy.get(c)["routes"]] == ["Tor", "Second"]
        assert proxy.get(c)["posture"] == "r1" and proxy.find(proxy.get(c), "r2")
        assert json.loads(admin.kv_get(c, proxy.LEGACY_KEY)) == old
        assert posture.profile(c, "default")["route"] == ""   # existing profiles: Default


# ---- routes per scan profile ----

def two_routes(c) -> None:
    """r1 Tor (the default route), r2 Mullvad fixed de; a profile 'viade' on r2 and one 'direct' on Direct."""
    proxy.save_route(c, {"name": "Tor", "kind": "tor", "tor_host": "127.0.0.1", "tor_port": "9050"})
    proxy.save_route(c, route_form(name="Germany", mullvad_mode="fixed", mullvad_country="de"))
    proxy.put(c, proxy.check_shared({"posture": "r1"}, proxy.get(c)))
    for name, route in (("viade", "r2"), ("plain", "direct")):
        p, err = posture.check_profile(name, "22", 2, 3, 60, route, {"r1", "r2"})
        posture.save_profile(c, p, "", "ana")


def test_profile_route_is_used_by_a_posture_scan_and_recorded(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    one = [{"ip": "198.51.100.7", "hosts": ["www.routes.example"], "country": "Sweden"}]
    with db.connect(settings.db_path) as c:
        two_routes(c)
        for name in ("viade", "default", "plain"):
            posture.enqueue(c, DOM, one, posture.profile(c, name), "ana")
            c.commit()
            assert run_queue(settings) == 1
    # one nmap run per port chunk: viade 1, default 4, plain 1
    assert seen[0]["host"].startswith("de-") and {v["host"] for v in seen[1:5]} == {"127.0.0.1"} and seen[5] is None
    with db.connect(settings.db_path) as c:
        rows = [dict(r) for r in c.execute("SELECT profile, route, params FROM posture_scans ORDER BY id")]
    assert [r["route"] for r in rows] == ["r2", "", "direct"]
    assert rows[0]["params"].endswith(" via Germany: mullvad de-fra-wg-socks5-001 (de, fixed)")
    assert rows[1]["params"].endswith(" via Tor: tor 127.0.0.1:9050")   # Default: the default route
    assert " via " not in rows[2]["params"]


def test_default_follows_the_default_route_and_a_deleted_route_fails_closed(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    one = [{"ip": "198.51.100.7", "hosts": ["www.routes.example"], "country": "Sweden"}]
    with db.connect(settings.db_path) as c:
        two_routes(c)
        cfg2 = proxy.get(c)
        assert proxy.pick(cfg2)["name"] == "Tor" and proxy.pick(cfg2, "r2")["name"] == "Germany"
        assert proxy.pick(cfg2, "direct") is None
        proxy.put(c, proxy.check_shared({"posture": "r2"}, cfg2))
        posture.enqueue(c, DOM, one, posture.profile(c, "default"), "ana")   # queued on Default
    assert run_queue(settings) == 1 and seen[-1]["host"].startswith("de-")   # the default as it is at run time
    runs = len(seen)
    with db.connect(settings.db_path) as c:
        c.execute("UPDATE posture_scans SET status = 'queued', route = 'r9', chunks_done = 0 WHERE id = 1")
    assert run_queue(settings) == 1 and len(seen) == runs   # a route that is gone: no scan
    with db.connect(settings.db_path) as c:
        row = c.execute("SELECT status, error, params FROM posture_scans WHERE id = 1").fetchone()
    assert row["status"] == "failed" and row["error"] == "route: the scan route no longer exists (Settings · Routes)"
    assert row["params"] == "via a deleted route"


def test_delete_is_refused_while_a_route_is_in_use(settings):
    with db.connect(settings.db_path) as c:
        two_routes(c)
        assert proxy.delete_route(c, "r2") == "Germany is in use (scan profile viade): pick another route there first."
        assert proxy.delete_route(c, "r1") == "Tor is in use (default route): pick another route there first."
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        page = h.get("/admin/security/scan-settings").text
        assert "profiles: viade" in page
        r = h.post("/admin/security/scan-settings/routes/r2/delete", data={"csrf": csrf})
        assert r.status_code == 409 and "Germany is in use (scan profile viade)" in r.text
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")   # admins pick routes in profiles; the list shows each profile's route
        assert h.post("/admin/security/profiles", data={"csrf": csrf, "name": "viade", "ports": "22", "intensity": "2",
                                                        "timing": "3", "timeout": "60", "route": "r9"}
                      ).status_code == 422
        assert h.post("/admin/security/profiles", data={"csrf": csrf, "name": "viade", "ports": "22", "intensity": "2",
                                                        "timing": "3", "timeout": "60", "route": ""},
                      follow_redirects=False).status_code == 303
        page = h.get("/admin/security/profiles").text
        assert '<td class="long">Default (Tor)</td>' in page and '<td class="long">Direct</td>' in page
        assert "route Default (Tor)" in h.get(f"/admin/security/scans?domain={DOM}").text
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        assert h.post("/admin/security/scan-settings/routes/r2/delete", data={"csrf": csrf},
                      follow_redirects=False).status_code == 303
    with db.connect(settings.db_path) as c:
        assert [r["id"] for r in proxy.get(c)["routes"]] == ["r1"]


def test_inventory_and_cve_routes(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        two_routes(c)
        cfg2 = proxy.check_shared({"posture": "r1", "inventory": "r2", "cve": "r1"}, proxy.get(c))
        assert proxy.hop(c, proxy.pick(cfg2, "", "inventory"), client=client)["host"].startswith("de-")
        assert proxy.label(cfg2, "", "inventory") == "Germany: mullvad, fixed de"
        tor = proxy.pick(cfg2)
        own = proxy.hop(c, tor, "198.51.100.7")
        assert proxy.cve_hop(c, cfg2, tor, own) == {**own, "cve": True}   # the scan's own hop
        other = proxy.cve_hop(c, cfg2, proxy.find(cfg2, "r2"), None, client)
        assert other["host"] == "127.0.0.1" and other["cve"]   # the CVE route on its own
        assert proxy.cve_hop(c, {**cfg2, "cve": "direct"}, tor, own) is None
        proxy.save_route(c, {"name": "Socks4", "kind": "custom", "type": "socks4", "host": "192.0.2.10",
                             "port": "1080"})
        for use in ("inventory", "cve"):
            with pytest.raises(ValueError, match="socks4"):
                proxy.check_shared({use: "r3"}, proxy.get(c))
        assert proxy.check_shared({"posture": "r3"}, proxy.get(c))["posture"] == "r3"


def test_tunnel_script_syntax():
    script = Path(__file__).parent.parent / "deploy" / "mullvad-tunnel.sh"
    text = script.read_text()
    assert "AllowedIPs = 10.64.0.0/10" in text and "/dev/tcp" not in text
    bash = shutil.which("bash")
    if not bash or os.name == "nt" and "System32" in bash:
        pytest.skip("no bash")
    assert subprocess.run([bash, "-n", str(script)], capture_output=True).returncode == 0


def test_tunnel_service_reads_the_proxy_environment():
    unit = (Path(__file__).parent.parent / "deploy" / "domin-mullvad.service").read_text()
    assert "EnvironmentFile=-/etc/domin.env" in unit
    script = (Path(__file__).parent.parent / "deploy" / "mullvad-tunnel.sh").read_text()
    assert "fail no-handshake" in script and "HTTPS_PROXY" not in script.split("set -Eeuo")[1]   # never printed


# ---- this host, kind choices, route status ----

def status_file(settings, **kw) -> None:
    (settings.db_path.parent / mullvad.STATUS_FILE).write_text(json.dumps(kw))


def answering(monkeypatch, *addrs: tuple[str, int]) -> None:
    """The SOCKS5 greeting succeeds at these addresses only (no socket is opened)."""
    def fake(cfg, timeout=proxy.TIMEOUT):
        if (cfg["host"], int(cfg["port"])) in addrs:
            return f"SOCKS5 at {cfg['host']}:{cfg['port']} OK (no authentication)"
        raise proxy.ProxyError(f"cannot reach the proxy at {cfg['host']}:{cfg['port']}: Connection refused")
    monkeypatch.setattr(proxy, "handshake", fake)


def test_status_messages_in_plain_words():
    old = mullvad.explain({"at": "2026-11-08T20:56:01", "ok": False,
                           "message": "key registration: the Mullvad API did not answer"})   # no code: an older file
    assert old["text"].startswith("Mullvad's API (api.mullvad.net) could not be reached from this host")
    assert "/etc/domin.env" in old["next"] and old["detail"] == ""
    hs = mullvad.explain({"at": "x", "ok": False, "code": "no-handshake", "message": "tunnel configured but ..."})
    assert "UDP 51820" in hs["text"] and "taken down" in hs["text"] and "outbound UDP 51820" in hs["next"]
    refused = mullvad.explain({"at": "x", "ok": False, "code": "refused", "message": "key registration refused: bad"})
    assert refused["detail"] == "key registration refused: bad" and "account number" in refused["next"]
    assert mullvad.explain({"at": "x", "ok": True, "code": "up", "message": "tunnel up via se-got-wg-001"})["text"] \
        == "Tunnel up via se-got-wg-001."
    assert mullvad.explain({"at": "x", "ok": False, "code": "new", "message": "odd"})["text"] == "odd"
    assert mullvad.explain({}) == {}
    t = {"up": True, "handshake": 0, "relay": "se-got-wg-001"}
    assert "no handshake" in mullvad.tunnel_summary({"tunnel": t}, False)["text"]
    assert mullvad.tunnel_summary({"tunnel": {**t, "handshake": 1}}, True) == {
        "ok": True, "text": "up via se-got-wg-001; Mullvad's SOCKS5 inside it (10.64.0.1:1080) answers"}
    assert mullvad.tunnel_summary({}, False)["text"].startswith("not set up")


def test_status_file_with_tunnel_facts(settings):
    status_file(settings, at="2026-11-08T21:00:00", ok=False, code="no-handshake", message="m",
                tunnel={"up": False, "handshake": "nope", "relay": "se-got-wg-001", "wg": True, "checked": "t"})
    got = mullvad.apply_status(settings.db_path.parent)
    assert got["code"] == "no-handshake" and got["tunnel"]["handshake"] == 0 and got["tunnel"]["wg"]
    assert got["pending"] is False


def test_host_check_states(settings, monkeypatch):
    monkeypatch.setattr(proxy.shutil, "which", lambda name: None)
    with db.connect(settings.db_path) as c:
        cap = proxy.host_check(c, settings.db_path.parent)
    assert not cap["proxychains"] and not cap["wg"] and not cap["tor"]["ok"] and not cap["tunnel"]["ok"]
    assert cap["tor"]["addr"] == "127.0.0.1:9050" and cap["relays"]["count"] == 4 and not cap["relays"]["stale"]
    proxy._probes.clear()
    monkeypatch.setattr(proxy.shutil, "which", lambda name: f"/usr/bin/{name}")
    answering(monkeypatch, ("127.0.0.1", 9050), mullvad.IN_TUNNEL)
    status_file(settings, at="t", ok=True, code="up", message="tunnel up via se-got-wg-001",
                tunnel={"up": True, "handshake": 1700000000, "relay": "se-got-wg-001", "wg": True})
    with db.connect(settings.db_path) as c:
        cap = proxy.host_check(c, settings.db_path.parent)
    assert cap["proxychains"] and cap["wg"] and cap["tor"]["ok"] and cap["tunnel"]["ok"]
    assert "se-got-wg-001" in cap["tunnel"]["text"]


def test_probes_are_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(proxy, "handshake", lambda cfg, timeout=0: calls.append(1) or "ok")
    assert proxy.probe("127.0.0.1", 9050) == proxy.probe("127.0.0.1", 9050) == (True, "ok") and len(calls) == 1
    proxy.probe("127.0.0.1", 9050, fresh=True)
    assert len(calls) == 2


def test_kind_choices_and_prefill():
    down = {"proxychains": True, "tor": {"ok": False, "addr": "127.0.0.1:9050"}, "tunnel": {"ok": False}}
    got = {k["value"]: k for k in proxy.kinds(down)}
    assert got["custom"]["ok"] and got["tor"]["ok"] and not got["mullvad"]["ok"]
    assert got["tor"]["label"] == "Tor (not reachable)" and got["tor"]["state"] == "bad"
    assert got["mullvad"]["label"] == "Mullvad (unavailable: tunnel not up)"
    assert {k["value"]: k["ok"] for k in proxy.kinds(down, "mullvad")}["mullvad"]   # an existing Mullvad route
    up = {**down, "tor": {"ok": True, "addr": "127.0.0.1:9050"}, "tunnel": {"ok": True}, "proxychains": False}
    got = {k["value"]: k for k in proxy.kinds(up)}
    assert got["mullvad"]["ok"] and got["mullvad"]["label"] == "Mullvad" and got["tor"]["state"] == "warn"


def test_route_form_kind_select_is_selectable(settings, monkeypatch):
    with app_client(settings) as h:
        sign_in(h, "adm")
        page = h.get("/admin/security/scan-settings").text
        select = page.split('name="kind" data-kind-select>')[1].split("</select>")[0]
        assert '<option value="custom" selected>Custom proxy</option>' in select
        assert '<option value="tor" >Tor (not reachable)</option>' in select   # selectable, with the reason
        assert '<option value="mullvad"  disabled>Mullvad (unavailable: tunnel not up)</option>' in select
        assert "<select name=\"kind\" data-kind-select disabled" not in page
        for kind in ("custom", "tor", "mullvad"):   # every kind's fields are in the page (the script only hides)
            assert f'<div data-kind="{kind}">' in page
        assert 'name="tor_host" value="127.0.0.1"' in page and 'name="tor_port" type="number" min="1" max="65535" ' \
            'value="9050"' in page
        assert '<option value="se" selected>Sweden (se)</option>' in page   # fallback prefilled
        assert '<option value="auto" selected>automatic</option>' in page
        assert 'name="enabled" checked' in page
        answering(monkeypatch, mullvad.IN_TUNNEL)
        status_file(settings, at="t", ok=True, code="up", message="tunnel up via se-got-wg-001",
                    tunnel={"up": True, "handshake": 1700000000, "relay": "se-got-wg-001", "wg": True})
        select = h.get("/admin/security/scan-settings").text.split("data-kind-select>")[1].split("</select>")[0]
        assert '<option value="mullvad" >Mullvad</option>' in select


def test_route_enabled_verified_and_fail_closed(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    with db.connect(settings.db_path) as c:
        two_routes(c)   # r1 Tor (the default), r2 Germany (profile viade)
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        page = h.get("/admin/security/scan-settings").text
        assert page.count('<span class="pill">not tested</span>') == 2 and page.count('name="on" value="1" data-autosubmit') == 2
        assert '<input type="radio" name="posture" value="r1" form="default-form"\n        checked>' in page
        r = h.post("/admin/security/scan-settings/test", data={"csrf": csrf, "route": "r1"})
        assert "Test route: Tor: cannot reach the proxy" in r.text and '<span class="pill bad">✗ ' in r.text
        assert "Tor is last test failed but in use (Default for posture, profile default)" in r.text
        answering(monkeypatch, ("127.0.0.1", 9050))
        r = h.post("/admin/security/scan-settings/test", data={"csrf": csrf, "route": "r1"})
        assert '<span class="pill ok" title="SOCKS5 at 127.0.0.1:9050 OK (no authentication)">✓ ' in r.text
        assert h.post("/admin/security/scan-settings/routes/r2/enabled", data={"csrf": csrf, "on": "0"},
                      follow_redirects=False).status_code == 303
        page = h.get("/admin/security/scan-settings").text
        assert '<span class="pill bad">off</span>' in page and 'aria-label="Enabled: Germany" >' in page
        assert "Germany is disabled but in use (profile viade): scans on it fail until it is enabled." in page
        assert "Germany (disabled)" in h.get("/admin/security/profiles").text
        assert h.post("/admin/security/scan-settings/default", data={"csrf": csrf, "posture": "r2"},
                      follow_redirects=False).status_code == 303
        assert h.post("/admin/security/scan-settings", data={"csrf": csrf, "inventory": "direct", "cve": "direct",
                                                             "doh": proxy.DOH}, follow_redirects=False
                      ).status_code == 303   # the shared form leaves the preferred route alone
    with db.connect(settings.db_path) as c:
        cfg2 = proxy.get(c)
        assert cfg2["posture"] == "r2" and proxy.tests(c)["r1"]["ok"]
        assert proxy.label(cfg2) == "Germany (disabled: scans fail)"
        posture.enqueue(c, DOM, [{"ip": "198.51.100.7", "hosts": ["www.routes.example"], "country": "Sweden"}],
                        posture.profile(c, "viade"), "ana")
    assert run_queue(settings) == 1 and seen == []   # disabled: no scan at all, never a direct one
    with db.connect(settings.db_path) as c:
        row = c.execute("SELECT status, error, params FROM posture_scans").fetchone()
        assert row["status"] == "failed" and row["error"] == ("route: the scan route Germany is disabled "
                                                              "(Settings · Routes)")
        assert row["params"] == "via Germany: mullvad, fixed de"
        proxy.save_route(c, {"id": "r1", "name": "Tor", "kind": "tor", "tor_host": "127.0.0.1", "tor_port": "9051"})
        assert "r1" not in proxy.tests(c)   # changed settings: not verified any more
        proxy.save_route(c, {"id": "r2", "name": "Germany", "kind": "mullvad", "mullvad_mode": "fixed",
                             "mullvad_country": "de"})
        assert not proxy.find(proxy.get(c), "r2")["enabled"]   # a save without the page's box keeps it off
        proxy.save_route(c, {"id": "r2", "name": "Germany", "kind": "mullvad", "mullvad_mode": "fixed",
                             "mullvad_country": "de", "enabled_shown": "1", "enabled": "on"})
        assert proxy.find(proxy.get(c), "r2")["enabled"]


def test_mullvad_relay_names_fall_back_to_the_in_tunnel_resolver(monkeypatch):
    from domin import proxy as px

    def no_dns(*a, **k):
        raise OSError("no public DNS")
    monkeypatch.setattr(px.socket, "getaddrinfo", no_dns)
    asked = []
    monkeypatch.setattr(px, "mullvad_dns", lambda host: asked.append(host) or ["10.124.0.99"])
    assert px.resolve("de-fra-wg-socks5-001.relays.mullvad.net") == "10.124.0.99"
    assert asked == ["de-fra-wg-socks5-001.relays.mullvad.net"]
    try:
        px.resolve("proxy.example.invalid")
        raise AssertionError("expected ProxyError")
    except px.ProxyError:
        pass
    assert len(asked) == 1   # other names never go to Mullvad's resolver


# ---- ready-made routes ----

def cap(tor: bool, tunnel: bool) -> dict:
    return {"tor": {"ok": tor}, "tunnel": {"ok": tunnel}}


def test_ready_made_routes_once_per_available_kind(settings):
    with db.connect(settings.db_path) as c:
        assert proxy.ready_made(c, cap(False, False)) == [] and proxy.get(c)["routes"] == []
        assert proxy.ready_made(c, cap(True, False)) == ["r1"]
        assert proxy.ready_made(c, cap(True, True)) == ["r2"]   # Tor exists already: Mullvad only
        assert proxy.ready_made(c, cap(True, True)) == []        # never duplicated
        routes = {r["kind"]: r for r in proxy.get(c)["routes"]}
        assert routes["tor"]["name"] == "Tor" and routes["tor"]["tor_port"] == 9050 and routes["tor"]["enabled"]
        m = routes["mullvad"]
        assert (m["name"], m["mullvad_mode"], m["mullvad_fallback"], m["enabled"]) == (
            "Mullvad (automatic)", "auto", "se", True)
        assert proxy.tests(c) == {} and proxy.get(c)["posture"] == proxy.DIRECT   # not verified, used by nothing
        assert proxy.delete_route(c, "r1") == ""
        assert proxy.ready_made(c, cap(True, True)) == []   # deleted by the admin: not created again
        assert proxy.get(c)["dismissed"] == ["tor"]


def test_ready_made_skips_a_kind_the_admin_made(settings):
    with db.connect(settings.db_path) as c:
        proxy.save_route(c, {"name": "Tor", "kind": "custom", "type": "socks5", "host": "192.0.2.10", "port": "1080"})
        proxy.save_route(c, route_form())
        assert proxy.ready_made(c, cap(True, True)) == ["r3"]   # a Tor route; the name Tor is taken
        assert proxy.find(proxy.get(c), "r3")["name"] == "Tor 2"


def test_routes_page_offers_ready_made_routes(settings, monkeypatch):
    with app_client(settings) as h:
        sign_in(h, "adm")
        page = h.get("/admin/security/scan-settings").text   # nothing answers: no routes
        assert 'id="no-routes"' in page and '<a href="#route-form">Add a route</a>' in page
        answering(monkeypatch, ("127.0.0.1", 9050), mullvad.IN_TUNNEL)
        status_file(settings, at="t", ok=True, code="up", message="tunnel up via se-got-wg-001",
                    tunnel={"up": True, "handshake": 1700000000, "relay": "se-got-wg-001", "wg": True})
        proxy._probes.clear()
        page = h.get("/admin/security/scan-settings").text
        assert 'id="no-routes"' not in page
        shared = page.split('id="shared"')[1]
        for use in ("posture", "inventory", "cve"):
            select = shared.split(f'<select name="{use}">')[1].split("</select>")[0]
            assert ">Direct</option>" in select
            assert '<option value="r1" >Tor — enabled, not tested</option>' in select
            assert '<option value="r2" >Mullvad (automatic) — enabled, not tested</option>' in select
        assert page.count('name="on" value="1" data-autosubmit') == 2   # an Enabled box per route
        assert page.count('aria-label="Enabled: ') == 2 and page.count(">Test</button>") == 2
        with db.connect(settings.db_path) as c:
            proxy.set_enabled(c, "r2", False)
            proxy.record_test(c, "r1", False, "refused")
        page = h.get("/admin/security/scan-settings").text
        assert "Mullvad (automatic) — disabled</option>" in page and "Tor — last test failed</option>" in page
        with db.connect(settings.db_path) as c:
            assert len(proxy.get(c)["routes"]) == 2   # not created twice


def test_install_sets_up_the_public_sync_only_with_its_flag():
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    assert "    --public-sync) PUBSYNC=1 ;;" in install and "  PUBSYNC=0" in install
    assert '[ "$PUBSYNC" != 1 ] || setenv DOMIN_PUBLIC_SYNC 1' in install   # kept for later runs
    assert "[ ! -f /etc/systemd/system/domin-public-sync.path ] || PUBSYNC=1" in install   # older installs keep it
    enable = [ln for ln in install.splitlines() if "enable" in ln and "domin-public-sync" in ln]
    assert enable == ['[ "$PUBSYNC" != 1 ] || systemctl enable -q --now domin-public-sync.path']
    unit = install.index('install -m 644 "$APP/app/deploy/domin-public-sync.path"')
    assert install.rindex('if [ "$PUBSYNC" = 1 ]; then', 0, unit) > install.rindex("\nfi\n", 0, unit)
    assert "/var/lib/domin-sync" not in install   # the inbox exists only where a copy is delivered


def test_the_tree_and_the_archive_hold_no_database():
    import io
    import tarfile
    root = Path(__file__).parent.parent
    try:
        files = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout
        tar = subprocess.run(["git", "archive", "--format=tar", "HEAD"], cwd=root, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    names = files.split() + tarfile.open(fileobj=io.BytesIO(tar.stdout)).getnames()
    assert not [n for n in names if n.endswith((".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm"))]
