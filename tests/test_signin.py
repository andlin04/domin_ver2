"""Settings, Sign-in required for (inventory, posture) and two-factor required per user (docs/delegation.md)."""
import re
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from domin import access, admin, db, totp, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
DOM = "alpha.example"
INVENTORY_PATHS = ("/", "/all", "/tools", f"/d/{DOM}")
API_PATHS = ("/api/domains", "/search.csv", "/data/drill.json")


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=(), internal_ips=("198.51.100.0/24",))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        access.set_grants(c, users.create(c, "pia", "power", PW), {DOM: "viewer"}, "test")
        db.save_scan(c, DOM, db.now(), "scan", [{"host": "www." + DOM, "ip": "192.0.2.10"}])
    return s


def client(settings, ip="203.0.113.9"):
    return TestClient(create_app(settings), base_url="https://testserver", client=(ip, 50000))


def login(h, name, **extra):
    r = h.post(BASE + "/login", data={"name": name, "password": PW, **extra}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return r


def csrf_of(h, path=BASE + "/account"):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


def require(settings, inventory, posture=True):
    with db.connect(settings.db_path) as c:
        users.set_signin_required(c, inventory, posture)


def uid(settings, name):
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)["id"]


# --- migration ---------------------------------------------------------------------------------------------------

def test_the_setting_is_migrated_from_the_old_switch(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "m.db")
    db.init(s.db_path)
    with db.connect(s.db_path) as c:   # a new database: inventory open, posture needs sign-in
        assert users.signin_required(c) == {"inventory": False, "posture": True}
        c.execute("DELETE FROM kv WHERE key = ?", (users.SIGNIN_KEY,))
        admin.set_no_login(c, 1)   # a lab database with sign-in turned off: the stand-in kept posture
    db.init(s.db_path)
    db.init(s.db_path)   # idempotent
    with db.connect(s.db_path) as c:
        assert users.signin_required(c) == {"inventory": False, "posture": False}
        assert users.migrate_signin(c) is False


def test_areas_of_the_paths():
    assert [access.area(p) for p in ("/", "/d/x.example", "/api/domains", "/adminx")] == ["inventory"] * 4
    assert [access.area(p) for p in (BASE + "/security", BASE + "/security/scans", BASE + "/security/kpis",
                                     BASE + "/schedules/3", BASE + "/tags", BASE + "/discovery/scan")] == ["posture"] * 6
    assert [access.area(p) for p in (BASE, BASE + "/users", BASE + "/settings", BASE + "/security/scan-settings",
                                     BASE + "/security/profiles", BASE + "/security/discovery-profiles/x/delete",
                                     BASE + "/account")] == ["admin"] * 7


# --- neither: as before ------------------------------------------------------------------------------------------

def test_neither_keeps_the_public_inventory_and_posture_behind_sign_in(settings):
    with client(settings) as h:
        for path in (*INVENTORY_PATHS, *API_PATHS):
            assert h.get(path).status_code == 200, path
        r = h.get(BASE + "/security", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == BASE
        assert "Sign in</a>" in h.get("/").text


# --- inventory required ------------------------------------------------------------------------------------------

def test_inventory_needs_sign_in_when_ticked(settings):
    require(settings, inventory=True)
    with client(settings) as h:
        for path in INVENTORY_PATHS:
            r = h.get(path, follow_redirects=False)
            assert r.status_code == 303, path
            assert parse_qs(urlsplit(r.headers["location"]).query)["next"] == [path]
        for path in API_PATHS:
            assert h.get(path).status_code == 401, path
        assert h.post("/api/scan", json={"domain": "beta.example"}).status_code == 401
        assert h.get("/healthz").status_code == 200 and h.get("/static/app.css").status_code == 200
        page = h.get(BASE + "?next=/d/alpha.example").text
        assert "Sign in to open that page." in page and 'name="next" value="/d/alpha.example"' in page
        r = login(h, "pia", next=f"/d/{DOM}")
        assert r.headers["location"] == f"/d/{DOM}"
        for path in (*INVENTORY_PATHS, *API_PATHS):
            assert h.get(path).status_code == 200, path
    with client(settings, ip="198.51.100.7") as h:   # a private API client keeps /api/
        assert h.get("/api/domains").status_code == 200
        assert h.get("/").status_code == 200 and "Sign in" in h.get("/").text   # the sign-in page


@pytest.mark.parametrize("target", ["https://elsewhere.example/", "//elsewhere.example/", "/\\elsewhere.example"])
def test_next_stays_on_this_site(settings, target):
    with client(settings) as h:
        r = login(h, "pia", next=target)
        assert r.headers["location"] == BASE


def test_admin_saves_the_setting_and_it_is_audited(settings):
    with client(settings) as h:
        login(h, "boss")
        csrf = csrf_of(h, BASE + "/settings")
        assert 'id="signin"' in h.get(BASE + "/settings").text
        r = h.post(BASE + "/settings/signin", data={"csrf": csrf, "inventory": "on"}, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:   # posture stays required without DOMIN_ALLOW_NO_LOGIN
        assert users.signin_required(c) == {"inventory": True, "posture": True}
        assert any(a["action"] == "sign-in" for a in access.audit_recent(c))
    with client(settings) as h:
        assert h.get("/", follow_redirects=False).status_code == 303
        login(h, "pia")
        assert h.post(BASE + "/settings/signin", data={"csrf": csrf_of(h)}).status_code == 404   # admins only


# --- the lab stand-in (sign-in off) ------------------------------------------------------------------------------

def test_lab_stand_in_counts_only_where_sign_in_is_not_required(settings):
    lab = replace(settings, allow_no_login=True)
    with db.connect(settings.db_path) as c:
        admin.set_no_login(c, uid(settings, "boss"))
    require(settings, inventory=False, posture=False)
    with client(lab) as h:   # as before: every visitor acts as boss
        assert h.get(BASE + "/security").status_code == 200 and h.get("/").status_code == 200
    require(settings, inventory=True, posture=True)
    with client(lab) as h:
        for path in ("/", BASE + "/security", BASE + "/security/scans"):
            r = h.get(path, follow_redirects=False)
            assert r.status_code == 303 and r.headers["location"].startswith(BASE + "?next="), path
        assert "Sign in to open that page." in h.get(BASE + "?next=/").text   # the sign-in form, not the dashboard
        assert h.get(BASE + "/settings").status_code == 200   # the admin area: the stand-in, as documented
        login(h, "pia")
        assert h.get("/").status_code == 200 and h.get(BASE + "/security").status_code == 200


# --- two-factor required per user --------------------------------------------------------------------------------

def test_admin_requires_two_factor_for_one_user(settings):
    pia = uid(settings, "pia")
    with client(settings) as h:
        login(h, "boss")
        page = h.get(f"{BASE}/users/{pia}").text
        assert "Require two-factor for this user" in page and f'href="{BASE}/account">My account</a>' in page
        assert "Reset two-factor" not in page   # nothing to reset yet
        csrf = csrf_of(h, f"{BASE}/users/{pia}")
        r = h.post(f"{BASE}/users/{pia}/require-2fa", data={"csrf": csrf, "required": "on", "from": "edit"},
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith(f"{BASE}/users/{pia}")
        assert "required</span>" in h.get(BASE + "/users").text
    with db.connect(settings.db_path) as c:
        assert users.get(c, pia)["totp_required"]
        assert any(a["action"] == "require-2fa" and a["target"] == "pia" for a in access.audit_recent(c))
    with client(settings) as h:   # sent to My account after sign-in, until enrolled
        assert login(h, "pia", next="/").headers["location"] == BASE + "/account"
        assert "Two-factor is required for your account" in h.get(BASE + "/account").text
        csrf = csrf_of(h)
        h.post(BASE + "/account/2fa/start", data={"csrf": csrf})
        with db.connect(settings.db_path) as c:
            secret = users.enrol_pending(c, pia)["secret"]
        code = totp._code(secret, int(time.time() // totp.STEP))
        assert "Recovery codes" in h.post(BASE + "/account/2fa/confirm", data={"csrf": csrf, "code": code}).text
        assert h.post(BASE + "/account/2fa/disable", data={"csrf": csrf}).status_code == 403
    with client(settings) as h:   # enrolled: the code step, then where the sign-in started
        r = h.post(BASE + "/login", data={"name": "pia", "password": PW, "next": f"/d/{DOM}"}, follow_redirects=False)
        assert r.status_code == 200 and COOKIE not in r.cookies
        code = totp._code(secret, int(time.time() // totp.STEP) + 1)   # a fresh step: the last one is spent
        r = h.post(BASE + "/login/totp", data={"code": code}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"/d/{DOM}"
    with client(settings) as h:   # the admin's reset button on the edit page
        login(h, "boss")
        assert "Reset two-factor" in h.get(f"{BASE}/users/{pia}").text
        csrf = csrf_of(h, f"{BASE}/users/{pia}")
        h.post(f"{BASE}/users/{pia}/reset-2fa", data={"csrf": csrf, "from": "edit"})
        h.post(f"{BASE}/users/{pia}/require-2fa", data={"csrf": csrf, "from": "edit"})   # unticked
    with db.connect(settings.db_path) as c:
        u = users.get(c, pia)
        assert not u["has_totp"] and not u["totp_required"]
    with client(settings) as h:
        assert login(h, "pia").headers["location"] == BASE


def test_two_factor_setup_shows_the_uri_as_a_qr_code(settings):
    import html

    import segno
    pia = uid(settings, "pia")
    with client(settings) as h:
        login(h, "pia")
        assert 'class="qr' not in h.get(BASE + "/account").text   # no enrolment pending: no QR
        h.post(BASE + "/account/2fa/start", data={"csrf": csrf_of(h)})
        r = h.get(BASE + "/account")
        assert r.headers["cache-control"] == "no-store"
        with db.connect(settings.db_path) as c:
            secret = users.enrol_pending(c, pia)["secret"]
        uri = totp.provisioning_uri(secret, "pia")
        assert html.escape(uri) in r.text
        svg = re.search(r'<div class="qr"[^>]*>(<svg.*?</svg>)</div>', r.text, re.S).group(1)
        assert svg == totp.qr_svg(uri)   # the same symbol segno makes for this URI
        assert segno.make(uri, error="m").svg_inline(scale=4, border=4, dark="#000", light="#fff",
                                                     svgclass="qr-code", lineclass=None) == svg
        assert "style" not in svg and "script" not in svg and 'fill="#fff"' in svg and 'stroke="#000"' in svg
