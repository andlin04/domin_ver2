"""Fixes from the security audit: the 2FA cookie path, non-global scan targets, re-authentication, set-password links
out of URLs, DOMIN_ALLOW_NO_LOGIN guard rails, the deploy scripts and hashed requirements."""
import re
import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domin import admin, db, fingerprint, netscope, posture, totp, users
from domin.config import Settings
from domin.web import COOKIE, PENDING, create_app

BASE = "/admin"
PW = "correct horse battery"
DOM = "alpha.example"
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def public(monkeypatch):
    """A public install (the suite's default is on-prem with test networks: conftest)."""
    monkeypatch.setenv("DOMIN_INSTALL_MODE", "")
    monkeypatch.delenv("DOMIN_SCAN_NETS", raising=False)


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
    return s


def client(settings, ip="203.0.113.9"):
    return TestClient(create_app(settings), base_url="https://testserver", client=(ip, 50000))


def login(h, name="boss"):
    r = h.post(BASE + "/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return r


def csrf_of(h, path=BASE + "/account"):
    return re.search(r'name="csrf" value="([^"]+)"', h.get(path).text).group(1)


def host_cookies(resp) -> list[str]:
    return [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie" and v.startswith("__Host-")]


def assert_host_prefix_rules(header: str):
    """What a browser requires of a __Host- cookie: Secure, Path=/ and no Domain attribute."""
    attrs = [a.strip().lower() for a in header.split(";")[1:]]
    assert "secure" in attrs and "path=/" in attrs and not any(a.startswith("domain=") for a in attrs), header


def enrol(settings, h, name="boss") -> str:
    csrf = csrf_of(h)
    h.post(BASE + "/account/2fa/start", data={"csrf": csrf})
    with db.connect(settings.db_path) as c:
        secret = users.enrol_pending(c, users.by_name(c, name)["id"])["secret"]
    code = totp._code(secret, int(time.time() // totp.STEP))
    assert "Recovery codes" in h.post(BASE + "/account/2fa/confirm", data={"csrf": csrf, "code": code}).text
    return secret


# --- M1: the second-factor cookie --------------------------------------------------------------------------------

def test_two_factor_sign_in_cookie_is_a_valid_host_cookie_and_the_flow_completes(settings):
    with client(settings) as h:
        login(h)
        secret = enrol(settings, h)
    with client(settings) as h:
        r = h.post(BASE + "/login", data={"name": "boss", "password": PW, "next": "/all"}, follow_redirects=False)
        assert r.status_code == 200 and COOKIE not in r.cookies and "code" in r.text
        pending = [c for c in host_cookies(r) if c.startswith(PENDING + "=")]
        assert len(pending) == 1
        assert_host_prefix_rules(pending[0])
        assert h.cookies.get(PENDING)   # the client sends it back on /admin/login/totp
        code = totp._code(secret, int(time.time() // totp.STEP) + 1)   # a fresh step: the last one is spent
        r = h.post(BASE + "/login/totp", data={"code": code}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/all"
        for header in host_cookies(r):   # the new session, and the pending cookie deleted on the same path
            assert_host_prefix_rules(header)
        assert any(c.startswith(PENDING + "=") and "max-age=0" in c.lower() for c in host_cookies(r))
        assert COOKIE in h.cookies and PENDING not in h.cookies
        assert h.get(BASE + "/account").status_code == 200


# --- M2: non-global targets --------------------------------------------------------------------------------------

NON_GLOBAL = ("127.0.0.1", "::1", "10.20.30.40", "169.254.169.254", "100.64.0.1", "::ffff:127.0.0.1", "0.0.0.0",
              "fe80::1", "fc00::1", "192.0.2.10")


@pytest.mark.parametrize("ip", NON_GLOBAL)
def test_public_install_refuses_non_global_addresses(ip):
    assert not netscope.target_ok(ip)


def test_global_addresses_pass_and_internal_mode_keeps_its_networks():
    assert netscope.target_ok("8.8.8.8") and netscope.target_ok("2a00:1450::1")
    nets = ("10.20.0.0/16",)
    assert netscope.target_ok("10.20.30.40", True, nets) and netscope.target_ok("8.8.8.8", True, nets)
    assert not netscope.target_ok("10.99.0.1", True, nets)                 # private, not a configured network
    assert not netscope.target_ok("127.0.0.1", True, ("127.0.0.0/8",))    # loopback never
    assert not netscope.target_ok("not an address", True, nets)


def test_mode_and_networks_come_from_the_environment_and_settings(settings, monkeypatch, public):
    with db.connect(settings.db_path) as c:
        admin.save_internal_dns(c, "", "", "172.20.4.0/24")
        assert not netscope.checker(c)("172.20.4.50")   # public: Settings networks do not count
        monkeypatch.setenv("DOMIN_INSTALL_MODE", "internal")
        monkeypatch.setenv("DOMIN_SCAN_NETS", "10.20.0.0/16")
        ok = netscope.checker(c)
        assert ok("172.20.4.50") and ok("10.20.1.1") and not ok("10.21.0.1") and not ok("127.0.0.1")


def test_fingerprint_of_loopback_and_private_addresses_is_refused_in_public_mode(tmp_path, public, monkeypatch):
    s = replace(Settings.from_env(), db_path=tmp_path / "p.db", admin_ips=())
    assert not s.internal_mode
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)

    def never(*a, **k):
        raise AssertionError("nmap must not run")
    monkeypatch.setattr(fingerprint, "scan", never)
    with client(s) as h:
        login(h)
        csrf = csrf_of(h)
        for target in ("127.0.0.1", "10.20.30.40", "169.254.169.254", "100.64.0.1"):
            r = h.post(BASE + "/security/scan", data={"csrf": csrf, "kind": "host", "target": target})
            assert r.status_code == 403 and "not a scannable address" in r.text, target
        # a name: every address it resolves to is checked, not just the first
        monkeypatch.setattr(fingerprint, "resolve", lambda t: (t, ["8.8.8.8", "::1"]))
        r = h.post(BASE + "/security/scan", data={"csrf": csrf, "kind": "host", "target": "mixed.example"})
        assert r.status_code == 403 and "::1" in r.text


def test_posture_targets_skip_non_global_addresses_in_public_mode(tmp_path, public):
    s = replace(Settings.from_env(), db_path=tmp_path / "p.db", admin_ips=())
    db.init(s.db_path)
    rows = [{"host": f"h{i}.{DOM}", "ip": ip} for i, ip in enumerate(NON_GLOBAL)]
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        db.save_scan(c, DOM, db.now(), "scan", rows)
        found, skipped = posture.targets(c, DOM)
        assert found == [] and skipped == len(NON_GLOBAL)
    with client(s) as h:   # the Security page's queue answers with the reason, nothing queued
        login(h)
        r = h.post(BASE + "/security/posture", data={"csrf": csrf_of(h), "domain": DOM},
                   headers={"accept": "application/json"})
        assert r.status_code == 422 and "No address of" in r.json()["error"]
    with db.connect(s.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 0


def test_internal_mode_still_scans_its_configured_networks(tmp_path, monkeypatch):
    monkeypatch.setenv("DOMIN_SCAN_NETS", "10.20.0.0/16")
    s = replace(Settings.from_env(), db_path=tmp_path / "i.db", admin_ips=())
    assert s.internal_mode
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        db.save_scan(c, DOM, db.now(), "scan", [{"host": "a." + DOM, "ip": "10.20.30.40"},
                                                {"host": "b." + DOM, "ip": "10.99.0.1"},
                                                {"host": "c." + DOM, "ip": "127.0.0.1"}])
        found, skipped = posture.targets(c, DOM)
        assert [f["ip"] for f in found] == ["10.20.30.40"] and skipped == 2


def test_worker_refuses_a_queued_non_global_address_in_public_mode(tmp_path, public, monkeypatch):
    s = replace(Settings.from_env(), db_path=tmp_path / "w.db")
    db.init(s.db_path)
    monkeypatch.setattr(fingerprint, "scan", lambda *a, **k: pytest.fail("nmap must not run"))
    with db.connect(s.db_path) as c:
        prof = posture.profile(c, posture.DEFAULT_PROFILE)
        posture.enqueue(c, DOM, [{"ip": "127.0.0.1", "hosts": ["lo." + DOM], "country": ""}], prof, "test")
        row = dict(c.execute("SELECT * FROM posture_scans").fetchone())
        posture.run(c, row, None, None)
        row = dict(c.execute("SELECT * FROM posture_scans").fetchone())
    assert row["status"] == "failed" and "not a scannable address" in row["error"]


# --- L3: re-authentication ---------------------------------------------------------------------------------------

def test_turning_two_factor_off_needs_the_password_or_a_code(settings):
    with client(settings) as h:
        login(h)
        secret = enrol(settings, h)
        csrf = csrf_of(h)
        r = h.post(BASE + "/account/2fa/disable", data={"csrf": csrf})
        assert r.status_code == 401
        r = h.post(BASE + "/account/2fa/disable", data={"csrf": csrf, "proof": "wrong password"})
        assert r.status_code == 401
        with db.connect(settings.db_path) as c:
            assert users.by_name(c, "boss")["has_totp"]
            assert c.execute("SELECT COUNT(*) FROM admin_fails").fetchone()[0] == 2   # counted as failed sign-ins
        code = totp._code(secret, int(time.time() // totp.STEP) + 1)
        r = h.post(BASE + "/account/2fa/disable", data={"csrf": csrf, "proof": code}, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        assert not users.by_name(c, "boss")["has_totp"]
    with client(settings) as h:   # the current password works too
        login(h)
        enrol(settings, h)
        r = h.post(BASE + "/account/2fa/disable", data={"csrf": csrf_of(h), "proof": PW}, follow_redirects=False)
        assert r.status_code == 303


def test_password_change_counts_wrong_current_passwords_and_locks_out(settings):
    with client(settings) as h:
        login(h)
        csrf = csrf_of(h)
        new = {"csrf": csrf, "new": "a new long password", "confirm": "a new long password"}
        for _ in range(admin.FAILS_PER_CLIENT):
            assert h.post(BASE + "/account/password", data={**new, "current": "wrong guess"}).status_code == 401
        r = h.post(BASE + "/account/password", data={**new, "current": PW})   # right, but locked out now
        assert r.status_code == 429 and "wait 15 minutes" in r.text
    with db.connect(settings.db_path) as c:
        assert users.verify_password(c, "boss", PW)   # unchanged


# --- L4: set-password links never in a URL -----------------------------------------------------------------------

def test_set_password_links_are_shown_once_from_the_session_not_the_url(settings):
    with client(settings) as h:
        login(h)
        csrf = csrf_of(h, BASE + "/users")
        r = h.post(BASE + "/users/add", data={"csrf": csrf, "name": "pia", "role": "power"}, follow_redirects=False)
        assert r.status_code == 303 and "token" not in r.headers["location"] and "link" not in r.headers["location"]
        page = h.get(r.headers["location"]).text   # the power user's edit page
        token = re.search(r"/set-password\?token=([A-Za-z0-9_-]+)", page).group(1)
        assert "set-password?token=" not in h.get(r.headers["location"]).text   # once
        assert h.get(BASE + "/users", params={"link": "/admin/set-password?token=planted"}).text.count("planted") == 0
        with db.connect(settings.db_path) as c:
            pia = users.by_name(c, "pia")["id"]
            assert users.setpw_user(c, token)["name"] == "pia"
        r = h.post(f"{BASE}/users/{pia}/reset-password", data={"csrf": csrf, "from": "edit"}, follow_redirects=False)
        assert r.status_code == 303 and "token" not in r.headers["location"]
        assert "set-password?token=" in h.get(r.headers["location"]).text
    with client(settings) as other:   # another admin session never sees it
        login(other)
        assert "set-password?token=" not in other.get(f"{BASE}/users/{pia}").text


# --- L7: DOMIN_ALLOW_NO_LOGIN ------------------------------------------------------------------------------------

def test_no_login_is_refused_without_a_private_admin_allowlist():
    base = replace(Settings.from_env(), allow_no_login=True, install_mode="public")
    assert base.no_login_refusal() == "DOMIN_ADMIN_IPS is empty"
    assert "non-private" in replace(base, admin_ips=("0.0.0.0/0",)).no_login_refusal()
    assert "non-private" in replace(base, admin_ips=("10.0.0.0/8", "8.8.8.0/24")).no_login_refusal()
    assert replace(base, admin_ips=("10.0.0.0/24",)).no_login_refusal() == ""
    assert replace(base, admin_ips=("8.8.8.0/24",), install_mode="internal").no_login_refusal() == ""
    assert replace(base, install_mode="internal").no_login_refusal() == "DOMIN_ADMIN_IPS is empty"
    assert replace(base, allow_no_login=False).no_login_refusal() == ""


def test_refused_no_login_keeps_sign_in_on_and_logs_it(settings, caplog):
    with db.connect(settings.db_path) as c:
        admin.set_no_login(c, users.by_name(c, "boss")["id"])   # a stand-in left in the database
    with client(replace(settings, allow_no_login=True)) as h:   # admin_ips empty: refused
        assert "DOMIN_ALLOW_NO_LOGIN refused" in caplog.text
        r = h.get(BASE + "/settings", follow_redirects=False)   # no stand-in: off to the sign-in page
        assert r.status_code == 303 and r.headers["location"] == BASE
        assert 'name="password"' in h.get(BASE).text


def test_the_stand_in_counts_only_for_the_admin_networks(settings, caplog):
    lab = replace(settings, allow_no_login=True, admin_ips=("10.0.0.0/24",), install_mode="public")
    with db.connect(settings.db_path) as c:
        admin.set_no_login(c, users.by_name(c, "boss")["id"])
        users.set_signin_required(c, False, False)
    with client(lab, ip="10.0.0.5") as h:
        assert "DOMIN_ALLOW_NO_LOGIN is active" in caplog.text
        assert "sign-in off" in h.get(BASE + "/security/scans").text
    with client(lab, ip="203.0.113.9") as h:   # outside: /admin is 404 and public pages show no admin
        assert h.get(BASE + "/settings").status_code == 404
        assert "My account" not in h.get("/").text


# --- L5, L6, L10: deploy scripts ---------------------------------------------------------------------------------

def test_requirements_are_pinned_with_hashes_and_installed_with_require_hashes():
    text = (ROOT / "deploy" / "requirements.txt").read_text(encoding="utf-8")
    pins = re.findall(r"^([A-Za-z0-9._-]+)==\S+ \\$", text, re.M)
    assert len(pins) >= 20
    for block in re.split(r"\n(?=[A-Za-z])", text.split("\n", 4)[-1]):
        if "==" in block:
            assert "--hash=sha256:" in block, block.splitlines()[0]
    for script in ("install.sh", "update.sh"):
        pip_lines = [x for x in (ROOT / "deploy" / script).read_text().splitlines() if "pip\" install" in x]
        assert pip_lines and all("--require-hashes" in x for x in pip_lines), script


def test_update_script_checks_entries_owns_the_code_and_never_evals_the_env_file():
    text = (ROOT / "deploy" / "update.sh").read_text()
    code = "\n".join(x for x in text.splitlines() if not x.lstrip().startswith("#"))
    assert "eval" not in code
    assert "tar -tvf" in code and "sha256sum -c" in code
    assert 'chown -R root:root "$APP"' in code and 'chmod -R go-w "$APP"' in code
    assert code.index("tar -tvf") < code.index("tar -x")   # checked before anything is extracted
    assert "__pycache__" in code


def test_the_cli_runs_as_the_app_user_without_writing_bytecode():
    for script in ("install.sh", "mullvad-tunnel.sh"):
        lines = [x for x in (ROOT / "deploy" / script).read_text().splitlines() if "runuser -u domin" in x]
        assert lines and all("PYTHONDONTWRITEBYTECODE=1" in x for x in lines), script
