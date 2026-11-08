import json
import os
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient
from test_fingerprint import PW, SCAN_XML, transport
from test_posture import DOM, RECORDS, run_queue, sign_in

from domin import admin, db, fingerprint, posture, proxy, users
from domin.config import Settings
from domin.web import create_app

SECRET = "harmless-pw-1"   # made-up test password
ON = {"enabled": True, "type": "socks5", "host": "192.0.2.10", "port": 1080, "username": "scanner",
      "password": SECRET, "cve": False}


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
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["172.20.4.0/24"]})
    return s


def app_client(settings):
    return TestClient(create_app(settings, http=httpx.Client(transport=transport())),
                      base_url="https://testserver", client=("127.0.0.1", 50000))


def form(**kw) -> dict:
    """The route form for a custom proxy."""
    return {"name": "Office", "kind": "custom", "type": "socks5", "host": "192.0.2.10", "port": "1080", **kw}


def shared(**kw) -> dict:
    return {"posture": "direct", "inventory": "direct", "cve": "direct", "doh": proxy.DOH, **kw}


# ---- settings ----

def test_check_route_validates_the_form():
    cfg = {**proxy.DEFAULT, "routes": []}
    for bad in (form(type="ftp"), form(host="socks5://192.0.2.10"), form(host="proxy host"), form(port="0"),
                form(port="70000"), form(port="x"), form(host=""), form(username="a b"),
                form(password=SECRET), form(kind="vpn"), form(name=""), form(name="Direct"), form(name="default"),
                form(name="x" * 41), form(name="<b>"), form(id="r9")):
        with pytest.raises(ValueError):
            proxy.check_route(bad, cfg)
    assert proxy.check_route(form(host="proxy.corp.example"), cfg)["host"] == "proxy.corp.example"
    r = proxy.check_route(form(type="http", name="  Office   proxy "), cfg)
    assert r["id"] == "r1" and r["name"] == "Office proxy" and r["kind"] == "custom"
    taken = {**cfg, "routes": [{**proxy.ROUTE_DEFAULT, **r}], "next": 2}
    with pytest.raises(ValueError, match="already"):
        proxy.check_route(form(name="office PROXY"), taken)
    assert proxy.check_route(form(name="Office proxy", id="r1", type="socks4"), taken)["type"] == "socks4"
    for use in ("inventory", "cve"):   # socks4 can't carry the HTTPS look-ups a route is used for
        with pytest.raises(ValueError, match="socks4"):
            proxy.check_route(form(name="Office proxy", id="r1", type="socks4"), {**taken, use: "r1"})
    tor = proxy.check_route({"name": "Tor", "kind": "tor", "host": "", "type": "nope"}, cfg)
    assert (tor["tor_host"], tor["tor_port"], tor["host"]) == ("127.0.0.1", 9050, "")   # only the kind's fields


def test_password_is_kept_replaced_or_cleared(settings):
    with db.connect(settings.db_path) as c:
        rid = proxy.save_route(c, form(username="scanner", password=SECRET))["id"]
        assert proxy.find(proxy.get(c), rid)["password"] == SECRET
        proxy.save_route(c, form(id=rid, username="scanner", password=""))   # blank keeps it
        assert proxy.find(proxy.get(c), rid)["password"] == SECRET
        proxy.save_route(c, form(id=rid, username="scanner", password="harmless-pw-2"))
        assert proxy.find(proxy.get(c), rid)["password"] == "harmless-pw-2"
        proxy.save_route(c, form(id=rid, username="scanner", clear_password="on"))
        assert proxy.find(proxy.get(c), rid)["password"] == ""
        assert all("password" not in r for r in proxy.public(proxy.get(c))["routes"])
        other = proxy.save_route(c, form(name="Second", username="scanner"))   # a new route: no saved one to keep
        assert other["id"] != rid and other["password"] == ""


def test_only_admins_see_and_change_routes(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        assert ">Routes</a>" in h.get("/admin/settings").text and ">Routes</a>" not in h.get("/admin/security").text
        r = h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **form(username="scanner",
                                                                                       password=SECRET)},
                   follow_redirects=False)
        assert r.status_code == 303 and "route-saved" in r.headers["location"]
        assert h.post("/admin/security/scan-settings", data={"csrf": csrf, **shared(posture="r1")},
                      follow_redirects=False).status_code == 303
        page = h.get("/admin/security/scan-settings").text
        assert "Posture scans (default): Office: socks5 192.0.2.10:1080 · Inventory jobs: direct" in page
        assert "Default for posture</span>" in page and SECRET not in page
        edit = h.get("/admin/security/scan-settings?edit=r1").text
        assert "Change route Office" in edit and "saved; blank keeps it" in edit and SECRET not in edit
        assert "Scans go through Office: socks5 192.0.2.10:1080" in h.get(f"/admin/security?domain={DOM}").text
        r = h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **form(id="r1", port="99999")})
        assert r.status_code == 422 and "Port" in r.text and "Change route" in r.text
        r = h.post("/admin/security/scan-settings", data={"csrf": csrf, **shared(posture="r7")})
        assert r.status_code == 422 and "pick one from the list" in r.text
        assert h.post("/admin/security/scan-settings/routes", data=form()).status_code == 403   # no CSRF token
    for name in ("ana", "vee"):
        with app_client(settings) as h:
            csrf = sign_in(h, name)
            assert ">Routes</a>" not in h.get("/admin/security/profiles").text
            assert h.get("/admin/security/scan-settings").status_code == 404
            for path in ("", "/routes", "/routes/r1/delete", "/test", "/default", "/routes/r1/enabled"):
                assert h.post(f"/admin/security/scan-settings{path}", data={"csrf": csrf, **form(id="r1", port="2")}
                              ).status_code == 404
    with db.connect(settings.db_path) as c:
        assert proxy.find(proxy.get(c), "r1")["port"] == 1080 and proxy.get(c)["posture"] == "r1"


def test_off_shows_no_route(settings):
    with app_client(settings) as h:
        sign_in(h, "ana")
        assert "Scans go through" not in h.get(f"/admin/security?domain={DOM}").text


# ---- nmap under proxychains ----

class Done:
    stdout, stderr = SCAN_XML, ""


def test_nmap_runs_under_proxychains_with_a_private_temp_config(monkeypatch):
    seen = {}

    def fake(args, **kw):
        path = args[args.index("-f") + 1]
        seen.update(args=args, path=path, text=open(path, encoding="utf-8").read(), mode=os.stat(path).st_mode)
        return Done()
    monkeypatch.setattr(fingerprint.shutil, "which", lambda name: "/usr/bin/proxychains4")
    monkeypatch.setattr(proxy, "handshake", lambda cfg: "ok")
    monkeypatch.setattr(fingerprint.subprocess, "run", fake)
    assert fingerprint.run_nmap("172.20.4.50", "22", 10, via=ON) == SCAN_XML
    args = seen["args"]
    assert args[:4] == ["/usr/bin/proxychains4", "-q", "-f", seen["path"]]
    assert args[4:7] == ["nmap", "-sT", "-sV"] and args[-1] == "172.20.4.50"
    assert SECRET not in " ".join(args)
    text = seen["text"]
    assert "strict_chain" in text and "proxy_dns" in text and "tcp_connect_time_out" in text
    assert text.endswith(f"[ProxyList]\nsocks5 192.0.2.10 1080 scanner {SECRET}\n")
    if os.name == "posix":
        assert seen["mode"] & 0o777 == 0o600
    assert not os.path.exists(seen["path"])


def test_proxy_host_name_is_resolved_once_to_an_address(monkeypatch):
    monkeypatch.setattr(proxy.socket, "getaddrinfo", lambda *a, **k: [(0, 0, 0, "", ("198.51.100.7", 0))])
    assert proxy.resolve("proxy.corp.example") == "198.51.100.7"
    assert proxy.conf({**ON, "username": ""}, "198.51.100.7").endswith("[ProxyList]\nsocks5 198.51.100.7 1080\n")

    def none(*a, **k):
        raise OSError("no such name")
    monkeypatch.setattr(proxy.socket, "getaddrinfo", none)
    with pytest.raises(proxy.ProxyError, match="does not resolve"):
        proxy.resolve("proxy.corp.example")


def test_missing_proxychains_fails_closed(tmp_path, monkeypatch):
    def never(*a, **k):
        raise AssertionError("must not scan directly")
    monkeypatch.setattr(fingerprint.shutil, "which", lambda name: None)
    monkeypatch.setattr(fingerprint.subprocess, "run", never)
    res = fingerprint.scan("172.20.4.50", cve_db=None, via=ON)
    assert res["error"] == "proxy enabled but proxychains4 is not installed" and not res["services"]
    assert res["params"].endswith(" via socks5 192.0.2.10:1080")


def test_unreachable_proxy_fails_closed(monkeypatch):
    def refused(cfg):
        raise proxy.ProxyError("cannot reach the proxy at 192.0.2.10:1080: refused")

    def never(*a, **k):
        raise AssertionError("must not scan directly")
    monkeypatch.setattr(fingerprint.shutil, "which", lambda name: "/usr/bin/proxychains4")
    monkeypatch.setattr(proxy, "handshake", refused)
    monkeypatch.setattr(fingerprint.subprocess, "run", never)
    with pytest.raises(fingerprint.NmapError, match="cannot reach the proxy"):
        fingerprint.run_nmap("172.20.4.50", "22", 10, via=ON)


def test_proxy_off_leaves_the_command_unchanged(tmp_path, monkeypatch):
    seen = {}

    def fake(args, **kw):
        seen["args"] = args
        return Done()
    monkeypatch.setattr(fingerprint.subprocess, "run", fake)
    from domin import cve
    res = fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "c.json"), ports="22",
                           via={**ON, "enabled": False})
    assert seen["args"] == fingerprint.nmap_args("172.20.4.50", "22", 120)
    assert "via" not in res["params"]


def test_worker_records_the_route_without_the_password(settings, monkeypatch):
    seen = []
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: seen.append(k.get("via")) or SCAN_XML)
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, proxy.LEGACY_KEY, json.dumps(ON))   # the single-route setting of earlier builds
        n = posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
    assert run_queue(settings) == n == 2
    assert all(v and v["host"] == "192.0.2.10" for v in seen)
    with db.connect(settings.db_path) as c:
        rows = posture.current(c, DOM)
    assert all(r["status"] == "done" and r["params"].endswith(" via Custom proxy: socks5 192.0.2.10:1080")
               for r in rows)
    assert all(SECRET not in r["params"] for r in rows)


# ---- test button: handshake ----

class FakeSock:
    def __init__(self, replies: bytes):
        self.replies, self.sent = replies, b""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def sendall(self, data):
        self.sent += data

    def recv(self, n):
        out, self.replies = self.replies[:n], self.replies[n:]
        return out


def fake_connect(monkeypatch, replies: bytes) -> dict:
    seen = {}

    def connect(addr, timeout):
        seen["addr"], seen["sock"] = addr, FakeSock(replies)
        return seen["sock"]
    monkeypatch.setattr(proxy.socket, "create_connection", connect)
    return seen


def test_socks5_handshake_with_user_and_password(monkeypatch):
    seen = fake_connect(monkeypatch, bytes([5, 2, 1, 0]))
    assert "accepted the user name and password" in proxy.handshake(ON)
    assert seen["addr"] == ("192.0.2.10", 1080)
    user, pw = b"scanner", SECRET.encode()
    assert seen["sock"].sent == bytes([5, 2, 0, 2, 1, len(user)]) + user + bytes([len(pw)]) + pw
    fake_connect(monkeypatch, bytes([5, 2, 1, 1]))
    with pytest.raises(proxy.ProxyError, match="refused the user name or password"):
        proxy.handshake(ON)
    fake_connect(monkeypatch, bytes([5, 0xFF]))
    with pytest.raises(proxy.ProxyError, match="none of the offered methods"):
        proxy.handshake({**ON, "username": "", "password": ""})
    fake_connect(monkeypatch, b"HTTP/1.1 400")
    with pytest.raises(proxy.ProxyError, match="not a SOCKS5 proxy"):
        proxy.handshake(ON)


def test_socks4_and_http_test_the_tcp_connect_only(monkeypatch):
    for kind in ("socks4", "http"):
        seen = fake_connect(monkeypatch, b"")
        assert "TCP connect to 192.0.2.10:3128 OK" == proxy.handshake({**ON, "type": kind, "port": 3128})
        assert seen["sock"].sent == b""

    def refused(addr, timeout):
        raise ConnectionRefusedError(111, "Connection refused")
    monkeypatch.setattr(proxy.socket, "create_connection", refused)
    with pytest.raises(proxy.ProxyError, match="cannot reach the proxy at 192.0.2.10:1080: Connection refused"):
        proxy.handshake(ON)


def test_test_button_shows_the_result(settings, monkeypatch):
    fake_connect(monkeypatch, bytes([5, 0]))
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        assert "Direct has nothing to test" in h.post("/admin/security/scan-settings/test",
                                                      data={"csrf": csrf, "route": "direct"}).text
        h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, **form()})
        h.post("/admin/security/scan-settings/routes", data={"csrf": csrf, "name": "Tor", "kind": "tor",
                                                            "tor_host": "127.0.0.1", "tor_port": "9050"})
        r = h.post("/admin/security/scan-settings/test", data={"csrf": csrf, "route": "r1"})
        assert r.status_code == 200 and "Test route: Office: SOCKS5 at 192.0.2.10:1080 OK" in r.text
        r = h.post("/admin/security/scan-settings/test", data={"csrf": csrf, "route": "r2"})
        assert "Test route: Tor: SOCKS5 at 127.0.0.1:9050 OK" in r.text


# ---- CVE look-ups ----

def test_cve_client_follows_the_checkbox(monkeypatch):
    default = object()
    made = []

    class Client:
        def __init__(self, proxy):
            self.proxy, self.closed = proxy, False
            made.append(self)

        def close(self):
            self.closed = True
    monkeypatch.setattr(proxy.tools, "http_client", lambda proxy=None: Client(proxy))
    with proxy.cve_client({**ON, "cve": False}, default) as c:
        assert c is default
    with proxy.cve_client({**ON, "enabled": False, "type": "http", "cve": True}, default) as c:
        assert c is default
    with proxy.cve_client({**ON, "type": "http", "port": 3128, "cve": True}, default) as c:
        assert c is made[0] and str(c.proxy.url) == "http://192.0.2.10:3128"
        assert c.proxy.auth == ("scanner", SECRET)
    assert made[0].closed
    with proxy.cve_client({**ON, "cve": True}, default) as c:   # socks5 carries look-ups too (httpx[socks])
        assert c is made[1] and str(c.proxy.url) == "socks5://192.0.2.10:1080"
    with proxy.cve_client({**ON, "type": "socks4", "cve": True}, default) as c:   # socks4 can't: local database only
        assert c is None
