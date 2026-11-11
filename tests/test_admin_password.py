"""Admin-set passwords: create and reset with a typed or generated password, the grace sign-ins after one, the lock
to the renewal page when they are used up, and the removed set-password links."""
import io
import re
import time
from dataclasses import replace
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from domin import __main__ as cli
from domin import access, admin, db, totp, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
RENEW = BASE + "/account/renew"
BOSS_PW = "correct horse battery"
GIVEN = "Handover-Pw-7kQ2xZ"   # the admin-set password; never in a response body or URL
OWN = "my own new password 9"


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", BOSS_PW)
    return s


class Watched(TestClient):
    """A test client that fails when a secret shows up in any response body or redirect URL."""
    secrets = (GIVEN, OWN)

    def request(self, *a, **k):
        r = super().request(*a, **k)
        for s in self.secrets:
            assert s not in r.text, f"password in the body of {r.request.url}"
            assert s not in r.headers.get("location", ""), "password in a redirect"
            assert s not in str(r.url)
        return r


def client(settings):
    return Watched(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h, name, password, ok=True):
    r = h.post(BASE + "/login", data={"name": name, "password": password}, follow_redirects=False)
    assert (r.status_code == 303 and COOKIE in r.cookies) if ok else r.status_code == 401
    return r


def csrf_of(h, path):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


def now_code(secret):
    return totp._code(secret, int(time.time() // totp.STEP))


def user(settings, name):
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)


def audit_actions(settings):
    with db.connect(settings.db_path) as c:
        return [(a["action"], a["target"], a["detail"]) for a in access.audit_recent(c)]


def add(h, csrf, name="pia", pw=GIVEN, confirm=GIVEN, role="admin"):
    return h.post(BASE + "/users/add", data={"csrf": csrf, "name": name, "role": role, "password": pw,
                                             "confirm": confirm}, follow_redirects=False)


def boss(settings):
    h = client(settings)
    login(h, "boss", BOSS_PW)
    return h, csrf_of(h, BASE + "/users")


# --- create and reset ---------------------------------------------------------------------------------------------

def test_create_user_checks_the_two_fields_and_the_policy(settings):
    h, csrf = boss(settings)
    r = add(h, csrf, pw=GIVEN, confirm=GIVEN + "x")
    assert r.status_code == 422 and "The two passwords differ." in r.text and 'value="pia"' in r.text
    r = add(h, csrf, pw="short", confirm="short")
    assert r.status_code == 422 and f"at least {users.MIN_PASSWORD} characters" in r.text
    assert user(settings, "pia") is None
    r = add(h, csrf)
    assert r.status_code == 303 and r.headers["location"].endswith("ok=user-added")
    u = user(settings, "pia")
    assert u["pw_set_by_admin"] and u["pw_grace_left"] == users.GRACE_SIGNINS
    with db.connect(settings.db_path) as c:
        assert users.verify_password(c, "pia", GIVEN)   # the existing scrypt path
        assert admin.password_matches(u["password_hash"], GIVEN)[0] and GIVEN not in u["password_hash"]
    acts = audit_actions(settings)
    assert ("set password (admin)", "pia", "") in acts and not any(GIVEN in str(a) for a in acts)
    assert "preset password, 3 grace sign-ins left" in h.get(BASE + "/users").text


def test_forms_render_generate_and_the_script(settings):
    h, csrf = boss(settings)
    pia = user(settings, "boss")["id"]
    for path in (BASE + "/users", f"{BASE}/users/{pia}"):
        page = h.get(path).text
        assert "data-pw-generate" in page and "data-pw-toggle" in page and "data-pw-copy" in page
        assert re.search(r'<script src="/static/password\.js"></script>', page)
        assert 'name="password"' in page and 'name="confirm"' in page and "set-password?token" not in page and "Set-pw link" not in page
    assert h.get("/static/password.js").status_code == 200


def test_admin_reset_ends_sessions_and_restores_the_grace(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    pia = user(settings, "pia")["id"]
    p = client(settings)
    login(p, "pia", GIVEN)
    assert user(settings, "pia")["pw_grace_left"] == 2
    assert p.get(BASE + "/account").status_code == 200
    r = h.post(f"{BASE}/users/{pia}/set-password", data={"csrf": csrf, "password": "x" * 5, "confirm": "x" * 5})
    assert r.status_code == 422 and user(settings, "pia")["pw_grace_left"] == 2
    r = h.post(f"{BASE}/users/{pia}/set-password", data={"csrf": csrf, "password": GIVEN + "2",
                                                         "confirm": GIVEN + "2"}, follow_redirects=False)
    assert r.status_code == 303 and "ok=pw-set-admin" in r.headers["location"]
    assert p.get(BASE + "/account", follow_redirects=False).headers["location"] == BASE   # signed out
    assert user(settings, "pia")["pw_grace_left"] == users.GRACE_SIGNINS
    assert [a for a in audit_actions(settings) if a[0] == "set password (admin)"][0][1] == "pia"


def test_old_set_password_routes_are_gone(settings):
    h, csrf = boss(settings)
    anon = client(settings)
    assert anon.get(BASE + "/set-password", params={"token": "x"}).status_code == 404
    assert anon.post(BASE + "/set-password", data={"token": "x", "password": "y" * 12}).status_code == 404
    pia = user(settings, "boss")["id"]
    assert h.post(f"{BASE}/users/{pia}/reset-password", data={"csrf": csrf}).status_code == 404


def test_migration_drops_old_link_tokens(settings):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, "setpw:abc", '{"user_id": 1, "expires": "2099-01-01T00:00:00"}')
        admin.kv_set(c, "setpw-link:def", "{}")
    db.init(settings.db_path)
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM kv WHERE key LIKE 'setpw%'").fetchone()[0] == 0


# --- grace sign-ins and the lock ------------------------------------------------------------------------------------

def test_grace_signins_then_locked_until_renewed(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    p = client(settings)
    login(p, "pia", "wrong password", ok=False)   # a failed sign-in counts nothing
    assert user(settings, "pia")["pw_grace_left"] == 3
    for left in (2, 1, 0):
        r = login(p, "pia", GIVEN)
        assert r.headers["location"] == RENEW
        page = p.get(RENEW).text
        assert "Your password was set by an admin. Change it now?" in page
        assert f"Keep it ({left} of 3 left)" in page and 'name="current"' not in page and 'name="new"' in page
        assert "password.js" in page
        assert user(settings, "pia")["pw_grace_left"] == left
        assert p.get(BASE).status_code == 200   # Keep it: the dashboard, once; no prompt again this session
        assert user(settings, "pia")["pw_set_by_admin"]   # keeping clears nothing
    assert "preset password, 0 grace sign-ins left" in h.get(BASE + "/users").text
    r = login(p, "pia", GIVEN)   # the 4th: locked to the renewal step
    assert r.headers["location"] == RENEW and user(settings, "pia")["must_renew"]
    assert "must renew" in h.get(BASE + "/users").text
    page = p.get(RENEW).text
    assert "Set a new password" in page and "Keep it" not in page
    for path in (BASE, BASE + "/users", BASE + "/account", "/", "/search"):
        r = p.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == RENEW, path
    r = p.get("/api/domains")
    assert r.status_code == 403 and "Set a new password first" in r.json()["error"]
    token = csrf_of(p, RENEW)
    assert p.post(BASE + "/account/password", data={"csrf": token, "current": GIVEN, "new": OWN,
                                                    "confirm": OWN}).status_code == 403
    r = p.post(RENEW, data={"csrf": token, "new": GIVEN, "confirm": GIVEN})
    assert r.status_code == 422 and "other than the one the admin set" in r.text
    r = p.post(RENEW, data={"csrf": token, "new": OWN, "confirm": OWN}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies   # this browser stays signed in
    u = user(settings, "pia")
    assert not u["pw_set_by_admin"] and u["pw_grace_left"] == 0 and not u["must_renew"]
    assert p.get(BASE + "/users").status_code == 200 and p.get("/api/domains").status_code == 200
    assert login(p, "pia", OWN).headers["location"] == BASE   # no prompt any more
    assert ("password changed (self)", "pia", "") in audit_actions(settings)
    assert "preset password" not in h.get(BASE + "/users").text


def test_an_admin_reset_unlocks_with_three_new_grace_signins(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    pia = user(settings, "pia")["id"]
    with db.connect(settings.db_path) as c:
        c.execute("UPDATE users SET pw_grace_left = -1 WHERE id = ?", (pia,))
    h.post(f"{BASE}/users/{pia}/set-password", data={"csrf": csrf, "password": GIVEN, "confirm": GIVEN})
    u = user(settings, "pia")
    assert u["pw_grace_left"] == 3 and not u["must_renew"]


def test_change_from_the_prompt_clears_the_mark(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    p = client(settings)
    r = login(p, "pia", GIVEN)
    nxt = "/admin/users"
    r = p.post(BASE + "/login", data={"name": "pia", "password": GIVEN, "next": nxt}, follow_redirects=False)
    assert r.headers["location"] == RENEW + "?next=%2Fadmin%2Fusers"
    page = p.get(r.headers["location"]).text
    assert f'href="{nxt}">Keep it (1 of 3 left)' in page
    r = p.post(RENEW, data={"csrf": csrf_of(p, RENEW), "next": nxt, "new": OWN, "confirm": OWN},
               follow_redirects=False)
    assert r.headers["location"].startswith(nxt + "?ok=pw-changed")
    assert not user(settings, "pia")["pw_set_by_admin"]


def test_a_self_change_on_my_account_clears_the_mark(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    p = client(settings)
    login(p, "pia", GIVEN)
    assert "Your password was set by an admin" in p.get(BASE + "/account").text
    r = p.post(BASE + "/account/password", data={"csrf": csrf_of(p, BASE + "/account"), "current": GIVEN,
                                                  "new": OWN, "confirm": OWN}, follow_redirects=False)
    assert r.status_code == 303
    u = user(settings, "pia")
    assert not u["pw_set_by_admin"] and u["pw_grace_left"] == 0
    assert ("password changed (self)", "pia", "") in audit_actions(settings)


def test_later_than_right_after_sign_in_the_renewal_asks_the_current_password(settings):
    h, csrf = boss(settings)
    add(h, csrf)
    p = client(settings)
    login(p, "pia", GIVEN)
    old = (datetime.now() + timedelta(hours=admin.SESSION_HOURS, minutes=-30)).isoformat(timespec="seconds")
    with db.connect(settings.db_path) as c:
        c.execute("UPDATE admin_sessions SET expires = ? WHERE user_id = ?", (old, user(settings, "pia")["id"]))
    assert 'name="current"' in p.get(RENEW).text
    token = csrf_of(p, RENEW)
    assert p.post(RENEW, data={"csrf": token, "current": "wrong", "new": OWN, "confirm": OWN}).status_code == 401
    r = p.post(RENEW, data={"csrf": token, "current": GIVEN, "new": OWN, "confirm": OWN}, follow_redirects=False)
    assert r.status_code == 303 and not user(settings, "pia")["pw_set_by_admin"]


def test_two_factor_setup_comes_first_and_the_code_before_the_prompt(settings):
    h, csrf = boss(settings)
    add(h, csrf, name="tia")
    tia = user(settings, "tia")["id"]
    with db.connect(settings.db_path) as c:
        users.set_totp_required(c, tia, True)
    p = client(settings)
    assert login(p, "tia", GIVEN).headers["location"] == BASE + "/account"   # enrolment first, as before
    page = p.get(BASE + "/account").text
    assert "Two-factor is required" in page and "Your password was set by an admin" in page   # the offer there
    with db.connect(settings.db_path) as c:   # enrolled: the code step comes before the prompt
        users.start_enrol(c, tia)
        secret = users.enrol_pending(c, tia)["secret"]
        assert users.confirm_enrol(c, tia, now_code(secret))
    q = client(settings)
    r = q.post(BASE + "/login", data={"name": "tia", "password": GIVEN}, follow_redirects=False)
    assert r.status_code == 200 and COOKIE not in r.cookies   # the code form
    r = q.post(BASE + "/login/totp", data={"code": now_code(secret)}, follow_redirects=False)
    assert r.headers["location"] == RENEW


# --- CLI ------------------------------------------------------------------------------------------------------------

def test_cli_user_add_reads_the_password_from_stdin(settings, monkeypatch, capsys):
    monkeypatch.setenv("DOMIN_DB", str(settings.db_path))
    monkeypatch.setattr("sys.stdin", io.StringIO("short\n"))
    assert cli.main(["user-add", "cli1", "--password-stdin"]) == 2 and user(settings, "cli1") is None
    monkeypatch.setattr("sys.stdin", io.StringIO(GIVEN + "\n"))
    assert cli.main(["user-add", "cli1", "--password-stdin"]) == 0
    assert GIVEN not in capsys.readouterr().out
    u = user(settings, "cli1")
    assert u["pw_set_by_admin"] and u["pw_grace_left"] == 3
    monkeypatch.setattr("sys.stdin", io.StringIO(GIVEN + "\n"))
    assert cli.main(["user-add", "cli2", "--role", "admin", "--own", "--password-stdin"]) == 0
    assert not user(settings, "cli2")["pw_set_by_admin"]
    with db.connect(settings.db_path) as c:
        assert users.verify_password(c, "cli2", GIVEN)
