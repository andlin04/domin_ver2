import re
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from domin import admin, db, totp, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"


@pytest.fixture
def settings(tmp_path):
    # admin_ips empty: the network gate is open, so the sign-in alone governs access
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    return s


def mkuser(settings, name, role, password=PW):
    with db.connect(settings.db_path) as c:
        uid = users.create(c, name, role, password)
    return uid


def client(settings, ip="203.0.113.9"):
    return TestClient(create_app(settings), base_url="https://testserver", client=(ip, 50000))


def login(h, name, password=PW):
    r = h.post(BASE + "/login", data={"name": name, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return r


def csrf_of(h, path=BASE + "/account"):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


# --- migration ---------------------------------------------------------------------------------------------------

def test_legacy_admin_password_becomes_a_user(settings):
    with db.connect(settings.db_path) as c:
        assert users.count(c) == 0
        admin.kv_set(c, "admin_password", admin.hash_password(PW))
    db.init(settings.db_path)   # migration runs on init
    with db.connect(settings.db_path) as c:
        u = users.by_name(c, "admin")
        assert u and u["role"] == "admin" and admin.kv_get(c, "admin_password") is None
        assert users.verify_password(c, "admin", PW)


# --- roles -------------------------------------------------------------------------------------------------------

def test_roles_gate_the_pages(settings):
    mkuser(settings, "boss", "admin")
    mkuser(settings, "ana", "analyst")
    mkuser(settings, "viewer", "viewer")
    expect = {
        "boss": {BASE: 200, BASE + "/users": 200, BASE + "/settings": 200, BASE + "/security": 200},
        "ana": {BASE: 303, BASE + "/users": 404, BASE + "/settings": 404, BASE + "/security": 200},
        "viewer": {BASE: 303, BASE + "/users": 404, BASE + "/settings": 404, BASE + "/security": 200},
    }
    for name, paths in expect.items():
        with client(settings) as h:
            login(h, name)
            for path, code in paths.items():
                assert h.get(path, follow_redirects=False).status_code == code, (name, path)


def test_last_admin_cannot_lose_access(settings):
    uid = mkuser(settings, "only", "admin")
    with client(settings) as h:
        login(h, "only")
        token = csrf_of(h, BASE + "/users")
        assert h.post(f"{BASE}/users/{uid}/disable", data={"csrf": token, "disabled": "on"}).status_code == 409
        assert h.post(f"{BASE}/users/{uid}/delete", data={"csrf": token}).status_code == 409
        assert h.post(f"{BASE}/users/{uid}/role", data={"csrf": token, "role": "power"}).status_code == 409


# --- user management ---------------------------------------------------------------------------------------------

def test_admin_adds_a_user_who_sets_a_password_from_the_link(settings):
    mkuser(settings, "boss", "admin")
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/users")
        r = h.post(BASE + "/users/add", data={"csrf": token, "name": "newbie", "role": "analyst"},
                   follow_redirects=False)
        assert "token" not in r.headers["location"]   # never in a URL: shown once on the next page from the session
        page = h.get(r.headers["location"]).text
        link = re.search(r"set-password\?token=([^&\"<]+)", page).group(1)
        assert "set-password?token=" not in h.get(BASE + "/users").text   # once only
    with client(settings) as h2:   # a fresh client (no session) opens the one-time link
        assert "newbie" in h2.get(BASE + "/set-password", params={"token": link}).text
        assert h2.post(BASE + "/set-password",
                       data={"token": link, "password": "another strong pw", "confirm": "another strong pw"},
                       follow_redirects=False).status_code == 303
        login(h2, "newbie", "another strong pw")   # the password now works
        # the link is one-time
        assert h2.post(BASE + "/set-password",
                       data={"token": link, "password": "x" * 12, "confirm": "x" * 12}).status_code == 404


def test_disable_and_delete(settings):
    mkuser(settings, "boss", "admin")
    victim = mkuser(settings, "temp", "viewer")
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/users")
        h.post(f"{BASE}/users/{victim}/disable", data={"csrf": token, "disabled": "on"})
    with client(settings) as h:   # disabled: cannot sign in
        assert h.post(BASE + "/login", data={"name": "temp", "password": PW}).status_code == 401
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/users")
        h.post(f"{BASE}/users/{victim}/delete", data={"csrf": token})
    with db.connect(settings.db_path) as c:
        assert users.by_name(c, "temp") is None


# --- two-factor --------------------------------------------------------------------------------------------------

def _enrol(settings, h, uid):
    """Start enrolment, confirm it with a real code, return the recovery codes."""
    token = csrf_of(h)
    h.post(BASE + "/account/2fa/start", data={"csrf": token})
    with db.connect(settings.db_path) as c:
        secret = users.enrol_pending(c, uid)["secret"]
    code = totp._code(secret, int(time.time() // totp.STEP))
    page = h.post(BASE + "/account/2fa/confirm", data={"csrf": token, "code": code})
    assert "Recovery codes" in page.text
    return secret, re.findall(r'class="mono">([0-9a-f-]+)</li>', page.text)


def test_two_factor_is_required_at_login_once_enrolled(settings):
    uid = mkuser(settings, "boss", "admin")
    with client(settings) as h:
        login(h, "boss")
        secret, recovery = _enrol(settings, h, uid)
    assert recovery
    with client(settings) as h:   # password alone no longer signs in
        r = h.post(BASE + "/login", data={"name": "boss", "password": PW}, follow_redirects=False)
        assert r.status_code == 200 and COOKIE not in r.cookies and "code" in r.text.lower()
        code = totp._code(secret, int(time.time() // totp.STEP))
        assert h.post(BASE + "/login/totp", data={"code": code}, follow_redirects=False).status_code == 303


def test_recovery_code_works_once(settings):
    uid = mkuser(settings, "boss", "admin")
    with client(settings) as h:
        login(h, "boss")
        _secret, recovery = _enrol(settings, h, uid)
    with client(settings) as h:
        h.post(BASE + "/login", data={"name": "boss", "password": PW})
        assert h.post(BASE + "/login/totp", data={"code": recovery[0]}, follow_redirects=False).status_code == 303
    with client(settings) as h:   # the same recovery code is now spent
        h.post(BASE + "/login", data={"name": "boss", "password": PW})
        assert h.post(BASE + "/login/totp", data={"code": recovery[0]}).status_code == 401


def test_required_role_cannot_turn_two_factor_off(settings):
    uid = mkuser(settings, "boss", "admin")
    with client(settings) as h:
        login(h, "boss")
        secret, _ = _enrol(settings, h, uid)
        with db.connect(settings.db_path) as c:
            users.save_scope(c, {**users.get_scope(c), "require_2fa": {"admin": True, "analyst": False, "viewer": False}})
        token = csrf_of(h)
        assert h.post(BASE + "/account/2fa/disable", data={"csrf": token}).status_code == 403


# --- scope settings ----------------------------------------------------------------------------------------------

def _inventory(c):
    db.save_scan(c, "example.se", "2025-03-01T00:00:00", "import",
                 [{"host": "a.example.se", "ip": "192.0.2.10", "country": "Sweden"},
                  {"host": "b.example.se", "ip": "198.51.100.5", "country": "Finland"}])


def test_settings_save_and_counts_per_engine(settings):
    mkuser(settings, "boss", "admin")
    with db.connect(settings.db_path) as c:
        _inventory(c)
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/settings")
        assert h.post(BASE + "/settings", data={"csrf": token, "ip_allow": "not-a-cidr"}).status_code == 422
        ok = h.post(BASE + "/settings", data={"csrf": token, "domains_allow": "example.se",
                                              "ip_allow": "192.0.2.0/24", "cd:Finland": "on",
                                              "require_2fa_admin": "on"}, follow_redirects=False)
        assert ok.status_code == 303
    with db.connect(settings.db_path) as c:
        scope = users.get_scope(c)
        assert scope["domains_allow"] == ["example.se"] and scope["ip_allow"] == ["192.0.2.0/24"]
        assert scope["countries_deny"] == ["Finland"] and scope["require_2fa"]["admin"] is True
        assert users.inventory_in_scope(c, scope) == {"total": 1, "in_scope": 1}
        posture = users.posture_in_scope(c, scope)
        assert posture["in_scope"] == 1 and posture["total"] == 2        # only the 192.0.2.10 host, and not Finland
        assert posture["countries_in_scope"] == 1 and posture["countries"] == 2


def test_geolocation_options_come_from_the_inventory(settings):
    mkuser(settings, "boss", "admin")
    with db.connect(settings.db_path) as c:
        _inventory(c)
        assert users.inventory_countries(c) == ["Finland", "Sweden"]
    with client(settings) as h:
        login(h, "boss")
        page = h.get(BASE + "/settings").text
        assert 'name="ca:Sweden"' in page and 'name="cd:Finland"' in page   # pick-list, not free text
        assert 'id="posture-exclude"' in page and 'name="ex_host_0"' in page   # Never scan rules, editable rows


def test_domain_scope_refuses_out_of_scope_domain_in_the_scanner(settings):
    with db.connect(settings.db_path) as c:
        users.save_scope(c, {**users.get_scope(c), "domains_allow": ["example.se"]})
    with client(settings) as h:
        assert h.post("/api/scan", json={"domain": "example.se"}).status_code == 200
        r = h.post("/api/scan", json={"domain": "other.com"})
        assert r.status_code == 403 and "scope" in r.json()["error"]


def test_posture_ip_and_geo_rules_do_not_gate_the_scanner(settings):
    # deny every address and country in the posture scope; the domain scanner must be unaffected
    with db.connect(settings.db_path) as c:
        users.save_scope(c, {**users.get_scope(c), "ip_deny": ["0.0.0.0/0"], "countries_deny": ["Sweden"]})
    with client(settings) as h:
        assert h.post("/api/scan", json={"domain": "example.se"}).status_code == 200


def test_refresh_skips_out_of_scope_domains(settings):
    from domin import jobs
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "in.se", "2000-01-01T00:00:00", "import", [{"host": "in.se"}])
        db.save_scan(c, "out.com", "2000-01-01T00:00:00", "import", [{"host": "out.com"}])
        users.save_scope(c, {**users.get_scope(c), "domains_allow": ["in.se"]})
        assert jobs.enqueue_due(c, days=1) == 1   # only the in-scope domain is queued for refresh
        queued = [r["domain"] for r in c.execute("SELECT domain FROM jobs WHERE status = 'queued'")]
        assert queued == ["in.se"]


def test_network_gate_blocks_when_admin_ips_set(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("192.0.2.0/24",))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
    with client(s, ip="203.0.113.9") as h:   # off the allowlist: the whole area looks absent
        assert h.get(BASE).status_code == 404
        assert h.post(BASE + "/login", data={"name": "boss", "password": PW}).status_code == 404
    with client(s, ip="192.0.2.50") as h:
        assert h.get(BASE).status_code == 200
