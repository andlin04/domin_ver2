"""Sign-in protection (domin.guard): one session per user, new place, impossible travel, exemptions, break-glass,
the session list and its sign-out buttons."""
import json
import re
import time
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from domin import access, admin, db, guard, totp, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
SE, SE2, US, NOWHERE = "203.0.113.9", "203.0.113.77", "198.51.100.20", "192.0.2.50"   # NOWHERE: not in the table


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=(), internal_ips=())
    db.init(s.db_path)
    geo = tmp_path / "geo.csv"
    geo.write_text("203.0.113.0,203.0.113.255,SE\n198.51.100.0,198.51.100.255,US\n", encoding="utf-8")
    with db.connect(s.db_path) as c:
        admin.import_geo(c, geo)
        users.create(c, "boss", "admin", PW)
        users.create(c, "ada", "admin", PW)   # a second admin: boss is not the last one
        users.create(c, "pia", "power", PW)
    return s


def client(settings, ip=SE, agent="Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/130.0"):
    return TestClient(create_app(settings), base_url="https://testserver", client=(ip, 50000),
                      headers={"user-agent": agent})


def post_login(h, name):
    return h.post(BASE + "/login", data={"name": name, "password": PW}, follow_redirects=False)


def login(h, name):
    r = post_login(h, name)
    assert r.status_code == 303 and COOKIE in r.cookies, r.text[:300]
    return r


def csrf_of(h, path=BASE + "/account"):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


def uid(settings, name):
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)["id"]


def seen(settings, name, ip, cc, days_ago):
    """A sign-in from ip/cc days_ago (the baseline history)."""
    at = (datetime.now() - timedelta(days=days_ago)).isoformat(timespec="seconds")
    with db.connect(settings.db_path) as c:
        guard.remember(c, uid(settings, name), ip, cc, at)


def configure(settings, **kw):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, guard.KEY, json.dumps({**guard.config(c), **kw}))


def audit(settings):
    with db.connect(settings.db_path) as c:
        return access.audit_recent(c, 200)


def signed_in(h):
    return h.get(BASE + "/account", follow_redirects=False).status_code == 200


# --- the math ------------------------------------------------------------------------------------------------------

def test_travel_speed_fast_triggers_slow_does_not():
    now = datetime.now()
    hour_ago = (now - timedelta(hours=1)).isoformat(timespec="seconds")
    month_ago = (now - timedelta(days=30)).isoformat(timespec="seconds")
    at = now.isoformat(timespec="seconds")
    assert guard.speed_kmh("SE", hour_ago, "US", at) > guard.TRAVEL_KMH   # thousands of km in an hour
    assert guard.speed_kmh("SE", month_ago, "US", at) < guard.TRAVEL_KMH   # the same trip in a month
    assert guard.speed_kmh("SE", hour_ago, "SE", at) is None   # same country: skipped
    assert guard.speed_kmh("", hour_ago, "US", at) is None and guard.speed_kmh("SE", hour_ago, "", at) is None
    assert guard.speed_kmh("SE", hour_ago, "ZZ", at) is None   # no centroid
    d = guard.distance_km(guard.centroids()["se"], guard.centroids()["us"])
    assert 6000 < d < 9000
    assert guard.centroids()["sg"] == (1.35, 103.8)   # small places from the dot list


def test_places_and_browsers():
    assert guard.net_of("203.0.113.9") == "203.0.113.0/24" and guard.net_of("2001:db8:1:2::5") == "2001:db8:1::/48"
    assert guard.place_of("se", "x") == "SE" and guard.place_of("", "203.0.113.0/24") == "net:203.0.113.0/24"
    assert guard.browser("Mozilla/5.0 (Windows NT 10.0) Gecko/20100101 Firefox/130.0") == "Firefox on Windows"
    assert guard.browser("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1") == "Safari on iPhone"


# --- one session per user ---------------------------------------------------------------------------------------

def test_a_new_sign_in_ends_the_previous_session(settings):
    a, b = client(settings), client(settings, SE2)
    login(a, "pia")
    login(b, "pia")
    assert not signed_in(a) and signed_in(b)
    configure(settings, one_session=False)
    login(a, "pia")
    assert signed_in(a) and signed_in(b)


# --- new place --------------------------------------------------------------------------------------------------

def test_first_sign_in_sets_the_baseline(settings):
    login(client(settings, US), "pia")   # no history: nothing to compare with
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT place FROM signin_history").fetchone()["place"] == "US"


def test_new_place_without_two_factor_waits_for_an_admin(settings):
    seen(settings, "pia", SE, "SE", 30)
    h = client(settings, US)
    r = post_login(h, "pia")
    assert r.status_code == 403 and "An admin must approve it" in r.text and COOKIE not in r.cookies
    assert post_login(h, "pia").status_code == 403   # a retry: still one waiting row
    with db.connect(settings.db_path) as c:
        rows = c.execute("SELECT * FROM signin_pending").fetchall()
    assert len(rows) == 1 and rows[0]["cc"] == "US" and rows[0]["status"] == "pending"
    assert any(a["action"] == "sign-in new-place: pending" and "address 198.51.100.20, country US, rule new-place"
               in a["detail"] for a in audit(settings))
    with client(settings) as boss:   # the admin approves from Users
        login(boss, "boss")
        page = boss.get(BASE + "/users").text
        assert "Sign-ins waiting for approval" in page and "new place: approve?" in page
        csrf = csrf_of(boss, BASE + "/users")
        assert boss.post(f"{BASE}/users/{uid(settings, 'boss')}/approve-place",
                         data={"csrf": csrf, "pid": rows[0]["id"]}).status_code == 404   # another user's row
        r = boss.post(f"{BASE}/users/{uid(settings, 'pia')}/approve-place", data={"csrf": csrf, "pid": rows[0]["id"]},
                      follow_redirects=False)
        assert r.status_code == 303
        assert "Sign-ins waiting for approval" not in boss.get(BASE + "/users").text
    login(h, "pia")   # approved: the place counts as seen
    assert any(a["action"] == "sign-in new-place: approved" and a["actor"] == "boss" for a in audit(settings))


def test_a_denied_place_stays_refused(settings):
    seen(settings, "pia", SE, "SE", 30)
    h = client(settings, US)
    post_login(h, "pia")
    with db.connect(settings.db_path) as c:
        pid = c.execute("SELECT id FROM signin_pending").fetchone()["id"]
        assert guard.decide(c, uid(settings, "pia"), pid, False, "boss")
    r = post_login(h, "pia")
    assert r.status_code == 403 and "denied by an admin" in r.text


def test_new_place_with_two_factor_steps_up(settings):
    pia = uid(settings, "pia")
    with db.connect(settings.db_path) as c:
        secret, _ = users.start_enrol(c, pia)
        assert users.confirm_enrol(c, pia, totp._code(secret, int(time.time() // totp.STEP)))
    seen(settings, "pia", SE, "SE", 30)
    h = client(settings, US)
    r = post_login(h, "pia")
    assert r.status_code == 200 and 'name="code"' in r.text and COOKIE not in r.cookies   # the code step
    r = h.post(BASE + "/login/totp", data={"code": totp._code(secret, int(time.time() // totp.STEP) + 1)},
               follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    assert any(a["action"] == "sign-in new-place: stepup" for a in audit(settings))


def test_unknown_country_falls_back_to_the_network(settings):
    seen(settings, "pia", NOWHERE, "", 5)
    login(client(settings, "192.0.2.99"), "pia")   # same /24, no country
    assert post_login(client(settings, "10.9.9.9"), "pia").status_code == 403   # another /24, no country


# --- impossible travel ------------------------------------------------------------------------------------------

def test_impossible_travel_ends_sessions_and_requires_renewal_and_two_factor(settings):
    home = client(settings, SE)
    login(home, "pia")
    r = post_login(client(settings, US), "pia")   # minutes later from the other side of the Atlantic
    assert r.status_code == 403 and "too far away" in r.text
    assert not signed_in(home)
    with db.connect(settings.db_path) as c:
        u = users.get(c, uid(settings, "pia"))
    assert u["must_renew"] and u["totp_required"]
    hit = next(a for a in audit(settings) if a["action"] == "sign-in travel: travel")
    assert "country US, rule travel" in hit["detail"] and "SE -> US" in hit["detail"]
    login(home, "pia")   # back home: straight to the renewal page
    assert home.get(BASE + "/account", follow_redirects=False).headers["location"].startswith(BASE + "/account/renew")


def test_slow_travel_is_no_travel_hit(settings):
    seen(settings, "boss", SE, "SE", 30)
    configure(settings, new_place=False)
    login(client(settings, US), "boss")
    assert not [a for a in audit(settings) if "travel" in a["action"]]


# --- exemptions and break-glass ---------------------------------------------------------------------------------

def test_trusted_ranges_and_admin_ips_are_exempt(settings):
    seen(settings, "pia", SE, "SE", 30)
    configure(settings, trusted=["198.51.100.0/24"])
    login(client(settings, US), "pia")
    assert any(a["action"] == "sign-in new-place: exempt" for a in audit(settings))
    configure(settings, trusted=[])
    seen(settings, "pia", SE, "SE", 0)   # the last sign-in again from SE: US now is new and too fast
    lab = replace(settings, admin_ips=("198.51.100.0/24",))
    login(client(lab, US), "pia")
    assert any(a["action"] == "sign-in travel: exempt" for a in audit(settings))


def test_the_last_admin_only_steps_up(settings):
    with db.connect(settings.db_path) as c:
        users.delete(c, users.by_name(c, "ada")["id"])
    seen(settings, "boss", SE, "SE", 0)
    h = client(settings, US)
    r = login(h, "boss")   # new place and impossible travel, but never blocked
    assert r.headers["location"] == BASE + "/account"   # no two-factor yet: enrol now
    with db.connect(settings.db_path) as c:
        u = users.get(c, uid(settings, "boss"))
    assert u["totp_required"] and not u["must_renew"]
    assert any(a["action"] == "sign-in travel: stepup" and "last admin" in a["detail"] for a in audit(settings))


# --- settings ---------------------------------------------------------------------------------------------------

def test_settings_validate_and_audit(settings):
    h = client(settings)
    login(h, "boss")
    csrf = csrf_of(h, BASE + "/settings")
    assert 'id="guard"' in h.get(BASE + "/settings").text
    ok = {"csrf": csrf, "one_session": "on", "new_place": "on", "travel": "on", "new_place_days": "90", "trusted": ""}
    assert h.post(BASE + "/settings/guard", data={**ok, "new_place_days": "0"}).status_code == 422
    assert h.post(BASE + "/settings/guard", data={**ok, "trusted": "not-a-net"}).status_code == 422
    r = h.post(BASE + "/settings/guard", data={**ok, "travel": "", "new_place_days": "30",
                                                "trusted": "10.0.0.0/8\n192.0.2.7"}, follow_redirects=False)
    assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        cfg = guard.config(c)
    assert cfg == {"one_session": True, "new_place": True, "new_place_days": 30, "travel": False,
                   "trusted": ["10.0.0.0/8", "192.0.2.7/32"]}
    assert any(a["action"] == "sign-in protection" for a in audit(settings))


# --- session list and sign-out ----------------------------------------------------------------------------------

def test_session_list_and_revoke(settings):
    configure(settings, one_session=False)
    a, b, c3 = client(settings), client(settings, SE2, agent="Mozilla/5.0 (iPhone) Safari/604.1"), client(settings)
    for h in (a, b, c3):
        login(h, "pia")
    page = a.get(BASE + "/account").text
    assert 'id="sessions"' in page and "3 signed in" in page and "203.0.113.77" in page and "SE" in page
    assert "Firefox on Windows" in page and "this browser" in page and "Sign out all others" in page
    with db.connect(settings.db_path) as c:
        rows = guard.sessions(c, uid(settings, "pia"))
    other = next(r for r in rows if r["ip"] == SE2)
    csrf = csrf_of(a)
    assert a.post(f"{BASE}/account/sessions/{other['sid']}/end", data={"csrf": "x"}).status_code == 403
    assert a.post(f"{BASE}/account/sessions/{other['sid']}/end", data={"csrf": csrf},
                  follow_redirects=False).status_code == 303
    assert not signed_in(b) and signed_in(a) and signed_in(c3)
    a.post(BASE + "/account/sessions/others", data={"csrf": csrf})
    assert signed_in(a) and not signed_in(c3)
    login(b, "pia")   # the admin ends one, then all, from Users
    with client(settings, US) as boss:
        configure(settings, new_place=False, travel=False)
        login(boss, "boss")
        pia = uid(settings, "pia")
        page = boss.get(f"{BASE}/users/{pia}").text
        assert "2 signed in" in page and "Sign out everywhere" in page
        csrf = csrf_of(boss, f"{BASE}/users/{pia}")
        with db.connect(settings.db_path) as c:
            sid = next(r["sid"] for r in guard.sessions(c, pia) if r["ip"] == SE2)
        boss.post(f"{BASE}/users/{pia}/end-session", data={"csrf": csrf, "sid": sid})
        assert not signed_in(b) and signed_in(a)
        boss.post(f"{BASE}/users/{pia}/end-sessions", data={"csrf": csrf})
        assert not signed_in(a)
    assert {"session ended (self)", "sessions ended (self)", "session ended (admin)", "sessions ended (admin)"} <= {
        x["action"] for x in audit(settings)}
