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
        "ana": {BASE: 200, BASE + "/users": 404, BASE + "/settings": 404, BASE + "/security": 200},
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
        assert h.post(f"{BASE}/users/{uid}/role", data={"csrf": token, "role": "viewer"}).status_code == 409


# --- user management ---------------------------------------------------------------------------------------------

def test_admin_adds_a_user_who_sets_a_password_from_the_link(settings):
    mkuser(settings, "boss", "admin")
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/users")
        r = h.post(BASE + "/users/add", data={"csrf": token, "name": "newbie", "role": "analyst"},
                   follow_redirects=False)
        link = re.search(r"set-password\?token=([^&\"]+)", r.headers["location"]).group(1)
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

def test_scope_saves_valid_lists_and_rejects_bad_ones(settings):
    mkuser(settings, "boss", "admin")
    with db.connect(settings.db_path) as c:   # a small inventory to count against
        db.save_scan(c, "example.se", "2025-03-01T00:00:00", "import",
                     [{"host": "a.example.se", "ip": "192.0.2.10"}, {"host": "b.example.se", "ip": "198.51.100.5"}])
    with client(settings) as h:
        login(h, "boss")
        token = csrf_of(h, BASE + "/settings")
        bad = h.post(BASE + "/settings", data={"csrf": token, "ip_allow": "not-a-cidr"})
        assert bad.status_code == 422
        ok = h.post(BASE + "/settings", data={"csrf": token, "ip_allow": "192.0.2.0/24",
                                              "countries_allow": "SE", "domains_deny": "example.org",
                                              "require_2fa_admin": "on"}, follow_redirects=False)
        assert ok.status_code == 303
    with db.connect(settings.db_path) as c:
        scope = users.get_scope(c)
        assert scope["ip_allow"] == ["192.0.2.0/24"] and scope["countries_allow"] == ["SE"]
        assert scope["require_2fa"]["admin"] is True
        counts = users.hosts_in_scope(c, scope)
        assert counts == {"total": 2, "in_scope": 1}   # only the host in 192.0.2.0/24


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
