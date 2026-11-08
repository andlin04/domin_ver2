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
    return {**proxy.DEFAULT, "route": "mullvad", "posture": True, **kw}


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
        h = proxy.hop(c, cfg(mullvad_mode="follow"), "posture", "198.51.100.7", "Sweden", client, random.Random(1))
        assert h["type"] == "socks5" and h["host"].startswith("se-") and h["port"] == 1080
        assert h["label"].endswith("(se, follow host)")
        # a country without an active relay: the fallback, else the scan fails
        h = proxy.hop(c, cfg(mullvad_mode="follow", mullvad_fallback="de"), "posture", "198.51.100.7", "Finland",
                      client)
        assert h["label"] == "mullvad de-fra-wg-socks5-001 (de, follow host: no active Mullvad relay in fi, fallback)"
        with pytest.raises(proxy.ProxyError, match="no active Mullvad relay in fi, and no fallback country"):
            proxy.hop(c, cfg(mullvad_mode="follow"), "posture", "198.51.100.7", "Finland", client)
        with pytest.raises(proxy.ProxyError, match="the address has no country"):
            proxy.hop(c, cfg(mullvad_mode="follow"), "posture", "198.51.100.8", "", client)


def test_fixed_country_and_city(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        h = proxy.hop(c, cfg(mullvad_mode="fixed", mullvad_country="se", mullvad_city="sto"), "posture",
                      "198.51.100.7", "Germany", client)
        assert h["host"] == "se-sto-wg-socks5-002.relays.mullvad.net" and h["label"].endswith("(se, fixed)")
        with pytest.raises(proxy.ProxyError, match="no active Mullvad relay in fi"):
            proxy.hop(c, cfg(mullvad_mode="fixed", mullvad_country="fi"), "posture", "198.51.100.7", "", client)


def test_automatic_follows_then_falls_back_then_takes_any(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        assert proxy.hop(c, cfg(), "posture", "198.51.100.7", "Germany", client)["label"].endswith("(de, automatic)")
        h = proxy.hop(c, cfg(mullvad_fallback="se"), "posture", "198.51.100.8", "", client)
        assert h["label"].endswith("(se, automatic: the address has no country, fallback)")
        h = proxy.hop(c, cfg(), "posture", "198.51.100.8", "", client, random.Random(3))
        assert "automatic: the address has no country, any relay" in h["label"]
        assert h["host"] != "fi-hel-wg-socks5-001.relays.mullvad.net"   # never an inactive relay


def test_relay_pick_is_random_among_active_ones():
    picks = {mullvad.pick(RELAYS, "se", "", random.Random(seed))["hostname"] for seed in range(20)}
    assert picks == {"se-got-wg-001", "se-sto-wg-002"}
    assert mullvad.pick(RELAYS, "fi") is None


def test_private_targets_never_go_through_tor_or_mullvad(settings):
    with db.connect(settings.db_path) as c:
        for route, name in (("tor", "Tor"), ("mullvad", "Mullvad")):
            with pytest.raises(proxy.ProxyError, match=f"private address can't go through {name}"):
                proxy.hop(c, cfg(route=route), "posture", "172.20.4.50")
        assert proxy.hop(c, cfg(route="custom", host="192.0.2.10"), "posture", "172.20.4.50")["host"] == "192.0.2.10"
        assert proxy.hop(c, cfg(route="tor", posture=False), "posture", "172.20.4.50") is None   # not ticked


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
        tor = proxy.hop(c, cfg(route="tor"), "posture", "198.51.100.7")
        mv = proxy.hop(c, cfg(mullvad_mode="fixed", mullvad_country="de"), "posture", "198.51.100.7")
    assert proxy.route(tor) == "tor 127.0.0.1:9050"
    assert nmap_conf(monkeypatch, tor).endswith("[ProxyList]\nsocks5 127.0.0.1 9050\n")
    assert nmap_conf(monkeypatch, mv).endswith("[ProxyList]\nsocks5 10.124.0.5 1080\n")   # relay name resolved


def test_worker_records_the_mullvad_route_without_secrets(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.KEY, json.dumps(cfg(mullvad_mode="follow")))
        mullvad.save_tunnel(c, {**mullvad.TUNNEL_DEFAULT, "account": ACCOUNT, "private_key": KEY,
                                "address": "10.64.0.2/32"})
        n = posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
    assert run_queue(settings) == n == 3
    assert len(seen) == 1 and seen[0]["host"].startswith("se-")   # only the Swedish address was scanned
    with db.connect(settings.db_path) as c:
        rows = {r["ip"]: r for r in posture.current(c, DOM)}
    assert rows["198.51.100.7"]["status"] == "done"
    assert " via mullvad se-" in rows["198.51.100.7"]["params"]
    assert rows["198.51.100.7"]["params"].endswith("(se, follow host)")
    assert rows["198.51.100.8"]["error"] == "route: the address has no country, and no fallback country is set"
    assert rows["172.20.4.50"]["error"] == "route: private address can't go through Mullvad"
    assert all(r["params"].endswith(("(se, follow host)", "via Mullvad, follow host")) for r in rows.values())
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
        admin.kv_set(c, proxy.KEY, json.dumps(cfg(route="tor", posture=False, inventory=True)))
        records = scanner.run(c, DOM, settings, progress.append, client=no_fetch())
    assert str(seen["proxy"].url) == "socks5://127.0.0.1:9050"
    assert seen["doh"] > 0 and set(seen["urls"]) == {"dns.quad9.net", "crt.sh"}
    assert {r["host"] for r in records} == {DOM, f"www.{DOM}"}
    assert "route: tor 127.0.0.1:9050" in progress and "amass skipped (routed scan)" in progress


def test_mullvad_inventory_uses_the_fixed_or_fallback_country(settings):
    with db.connect(settings.db_path) as c, no_fetch() as client:
        inv = {"posture": False, "inventory": True}
        assert proxy.hop(c, cfg(**inv, mullvad_fallback="de"), "inventory", client=client)["host"].startswith("de-")
        assert proxy.hop(c, cfg(**inv, mullvad_mode="fixed", mullvad_country="se", mullvad_city="got"),
                         "inventory", client=client)["host"].startswith("se-got-")
        with pytest.raises(proxy.ProxyError, match="no fallback country"):
            proxy.hop(c, cfg(**inv, mullvad_mode="follow"), "inventory", client=client)


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
        admin.kv_set(c, proxy.KEY, json.dumps(cfg(route="tor", inventory=True)))
        assert scanner.run(c, "srv.home.arpa", s, client=client, resolver=FakeRes()) == [
            {"host": "srv.home.arpa", "ip": ""}]


def test_inventory_job_fails_closed_when_the_route_is_down(settings, monkeypatch):
    def never(*a, **k):
        raise AssertionError("must not go out direct")
    monkeypatch.setattr(scanner.tools, "http_client", never)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.KEY, json.dumps(cfg(route="tor", inventory=True)))
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


def page_form(**kw) -> dict:
    return {"route": "mullvad", "posture": "on", "type": "socks5", "host": "", "port": "1080",
            "tor_host": "127.0.0.1", "tor_port": "9050", "mullvad_mode": "follow", "mullvad_fallback": "se",
            "doh": proxy.DOH, "mullvad_address": "10.64.0.2/32", **kw}


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
        assert "Tunnel state not checked" in page and "4 relays" in page and "Sweden (se, 2)" in page
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **page_form(
            mullvad_account=ACCOUNT, mullvad_key=KEY, mullvad_address="10.64.0.2/32")}, follow_redirects=False)
        assert r.status_code == 303 and "tunnel-requested" in r.headers["location"]
        text = flag.read_text()
        assert text.startswith("requested ") and ACCOUNT not in text and KEY not in text
        page = h.get("/admin/security/scan-settings").text
        assert "Posture scans: Mullvad, follow host (fallback se) · Inventory jobs: direct" in page
        assert ACCOUNT not in page and KEY not in page and page.count("saved; blank keeps it") == 2
        assert "Mullvad tunnel down" in page
        assert "a request is waiting for the host" in page
        flag.unlink()
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **page_form(mullvad_address="10.64.0.2/32")},
                   follow_redirects=False)
        assert "ok=saved" in r.headers["location"] and not flag.exists()   # unchanged: no new request
        (settings.db_path.parent / mullvad.STATUS_FILE).write_text(
            json.dumps({"at": "2026-11-08T10:00:00", "ok": True, "message": "tunnel up via se-got-wg-001"}))
        assert "2026-11-08T10:00:00: tunnel up via se-got-wg-001" in h.get("/admin/security/scan-settings").text
        for bad, msg in ((page_form(mullvad_fallback="xx"), "Fallback country"),
                         (page_form(mullvad_mode="fixed"), "Pick the Mullvad country"),
                         (page_form(mullvad_account="12"), "16 digits")):
            r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **bad})
            assert r.status_code == 422 and msg in r.text
        assert h.post("/admin/security/scan-settings/tunnel", data={"csrf": csrf},
                      follow_redirects=False).status_code == 303 and flag.exists()
        assert "Test route: Mullvad tunnel down" in h.post("/admin/security/scan-settings/test",
                                                            data={"csrf": csrf}).text
    with db.connect(settings.db_path) as c:
        assert mullvad.get_tunnel(c)["private_key"] == KEY
        assert proxy.get(c)["mullvad_fallback"] == "se"


def test_relay_list_refresh_button(settings, monkeypatch):
    monkeypatch.setattr(mullvad, "fetch", lambda client: RELAYS[:2])
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/security/scan-settings/relays", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        assert len(mullvad.load(c)[0]) == 2


def test_only_admins_reach_the_route_endpoints(settings):
    for name in ("ana", "vee"):
        with app_client(settings) as h:
            csrf = sign_in(h, name)
            for path in ("", "/test", "/relays", "/tunnel"):
                assert h.post(f"/admin/security/scan-settings{path}", data={"csrf": csrf, **page_form()}
                              ).status_code == 404
    assert not (settings.db_path.parent / mullvad.REQUEST_FILE).exists()


def test_settings_saved_before_routes_still_apply(settings):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.KEY, json.dumps({"enabled": True, "type": "http", "host": "192.0.2.10", "port": 3128,
                                               "username": "", "password": "", "cve": True}))
        got = proxy.get(c)
    assert got["route"] == "custom" and got["posture"] and not got["inventory"] and "enabled" not in got
    assert proxy.state_line(got) == "Posture scans: http 192.0.2.10:3128 · Inventory jobs: direct"


def test_tunnel_script_syntax():
    script = Path(__file__).parent.parent / "deploy" / "mullvad-tunnel.sh"
    text = script.read_text()
    assert "AllowedIPs = 10.64.0.0/10" in text and "/dev/tcp" not in text
    bash = shutil.which("bash")
    if not bash or os.name == "nt" and "System32" in bash:
        pytest.skip("no bash")
    assert subprocess.run([bash, "-n", str(script)], capture_output=True).returncode == 0
