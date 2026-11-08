import gzip
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from domin import admin, db, jobs, scanner, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
USER = "admin"
UA = {"user-agent": "Mozilla/5.0 (Windows NT 10.0) Firefox/130.0"}


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1", "192.0.2.0/24"))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, USER, "admin", PW)
    return s


def client(settings, ip="127.0.0.1"):
    # https: the __Host- session cookie is Secure and is only sent back over HTTPS
    return TestClient(create_app(settings), base_url="https://testserver", client=(ip, 50000))


def sign_in(h, name=USER, password=PW) -> str:
    r = h.post(BASE + "/login", data={"name": name, "password": password}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    page = h.get(BASE)
    assert page.status_code == 200 and "Tuning" in page.text and page.headers["cache-control"] == "no-store"
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def test_old_password_hash_is_upgraded_at_sign_in(settings):
    import hashlib
    salt = b"0123456789abcdef"
    old = "scrypt$" + salt.hex() + "$" + hashlib.scrypt(PW.encode(), salt=salt, n=2**14, r=8, p=1).hex()
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, "admin_password", old)
        assert not admin.check_password(c, "wrong password")
        assert admin.kv_get(c, "admin_password") == old
        assert admin.check_password(c, PW)
        assert admin.kv_get(c, "admin_password").startswith(f"scrypt${admin.SCRYPT_LOG_N}$")
        assert admin.check_password(c, PW)


def test_asset_links_are_relative(settings):
    # behind a proxy the app sees http and another Host: absolute links would be blocked as mixed content
    page = client(settings).get(BASE, headers=UA).text
    assert 'href="/static/app.css"' in page and 'src="/static/app.js"' in page and "http://" not in page


def test_admin_only_for_allowlisted_addresses(settings):
    with client(settings, ip="198.51.100.7") as h:   # not on the list: no link, and /admin* looks like it doesn't exist
        unknown = h.get("/no-such-page")
        for path in (BASE, BASE + "/", BASE + "/jobs/1/cancel"):
            r = h.get(path)
            assert (r.status_code, r.text) == (unknown.status_code, unknown.text) == (404, unknown.text)
        assert h.post(BASE + "/login", data={"password": PW}).status_code == 404
        assert 'href="/admin"' not in h.get("/").text
    with client(settings, ip="192.0.2.50") as h:
        assert 'href="/admin"' in h.get("/").text and h.get(BASE).status_code == 200


def test_admin_allowlist_cannot_be_spoofed_with_headers(settings):
    spoof = {"x-real-ip": "192.0.2.50", "x-forwarded-for": "192.0.2.50", "cf-connecting-ip": "192.0.2.50"}
    with client(settings, ip="198.51.100.7") as h:   # direct peer: forwarding headers are ignored
        assert h.get(BASE, headers=spoof).status_code == 404
    # through nginx (peer 127.0.0.1): only X-Real-IP counts, and nginx always sets it from $remote_addr
    with client(settings) as h:
        assert h.get(BASE, headers={**spoof, "x-real-ip": "198.51.100.7"}).status_code == 404
        assert h.get(BASE, headers={"x-real-ip": "192.0.2.50"}).status_code == 200


def test_login_logout_and_lockout(settings):
    with client(settings) as h:
        r = h.get(BASE)
        assert r.status_code == 200 and 'name="password"' in r.text and "Tuning" not in r.text
        for _ in range(admin.FAILS_PER_CLIENT):
            assert h.post(BASE + "/login", data={"password": "wrong"}).status_code == 401
        assert h.post(BASE + "/login", data={"password": PW}).status_code == 429   # locked, even with the right one
    with client(settings, ip="192.0.2.50") as h:   # another client is not locked out
        csrf = sign_in(h)
        h.post(BASE + "/logout", data={"csrf": csrf})
        assert "Tuning" not in h.get(BASE).text
    with db.connect(settings.db_path) as c:   # no addresses in the lockout table either
        assert all(r[0].startswith("h:") for r in c.execute("SELECT client FROM admin_fails"))


def test_forms_need_the_csrf_token(settings):
    with client(settings) as h:
        csrf = sign_in(h)
        form = {k: str(v) for k, v in {"scans_per_hour": 5, "scans_per_day": 50, "scans_per_day_total": 60, "queue_max": 9,
                                        "scan_timeout_hours": 3, "lookups_per_minute": 3,
                                        "max_hosts": 100, "refresh_days": 0, "analytics_days": 30}.items()}
        assert h.post(BASE + "/tune", data={**form, "csrf": "forged"}).status_code == 403
        assert h.post(BASE + "/tune", data={**form, "csrf": csrf, "max_hosts": "5"}).status_code == 422
        assert h.post(BASE + "/tune", data={**form, "csrf": csrf, "scans_paused": "on"}).status_code == 200
    with db.connect(settings.db_path) as c:
        live = admin.effective(settings, c)
    assert (live.scans_per_hour, live.max_hosts, live.scans_paused, live.once_per_day) == (5, 100, True, False)


def test_tuning_applies_to_the_scan_api(settings):
    with db.connect(settings.db_path) as c:
        admin.kv_set(c, "tuning", '{"scans_per_hour": 1, "once_per_day": false}')
    with client(settings) as h:
        assert h.post("/api/scan", json={"domain": "a.se"}).status_code == 200
        assert h.post("/api/scan", json={"domain": "b.se"}).status_code == 429
    with db.connect(settings.db_path) as c:   # the rate limit keeps a hash, not the address
        assert [r[0][:2] for r in c.execute("SELECT client FROM jobs")] == ["h:"]


def test_cancel_queued_and_kill_running(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        queued = jobs.enqueue(c, "queued.se")
        running = jobs.enqueue(c, "running.se")
        c.execute("UPDATE jobs SET status = 'running' WHERE id = ?", (running["id"],))

    def scan(conn, domain, s, progress, **kw):   # the admin kills the job mid-scan
        with db.connect(settings.db_path) as c2:
            assert jobs.cancel(c2, running["id"])
        progress("resolving")
        raise AssertionError("the worker should have stopped")
    monkeypatch.setattr(scanner, "run", scan)
    jobs.run_job(settings, running)
    with client(settings) as h:
        csrf = sign_in(h)
        assert "?ok=cancelled" in h.post(BASE + f"/jobs/{queued['id']}/cancel", data={"csrf": csrf},
                                          follow_redirects=False).headers["location"]
        h.post(BASE + f"/jobs/{running['id']}/retry", data={"csrf": csrf})
    with db.connect(settings.db_path) as c:
        st = {r["domain"]: r["status"] for r in c.execute("SELECT domain, status FROM jobs ORDER BY id")}
        assert st == {"queued.se": "cancelled", "running.se": "queued"}   # retried as a new job
        assert c.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0


def test_paused_worker_leaves_jobs_queued(settings):
    with db.connect(settings.db_path) as c:
        jobs.enqueue(c, "wait.se")
        admin.kv_set(c, "tuning", '{"scans_paused": true}')
    jobs.worker(settings, once=True)
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT status FROM jobs").fetchone()[0] == "queued"


def test_visits_are_counted_without_addresses(settings, tmp_path):
    csv = tmp_path / "geo.csv.gz"
    with gzip.open(csv, "wt") as f:
        f.write("198.51.100.0,198.51.100.255,SE\n2001:db8::,2001:db8::ffff:ffff:ffff:ffff,FI\n")
    with db.connect(settings.db_path) as c:
        assert admin.import_geo(c, csv) == 2
        assert admin.country(c, "198.51.100.7") == "SE" and admin.country(c, "203.0.113.1") == ""
        assert admin.country(c, "2001:db8::/64") == "FI"
        sid = db.save_scan(c, "example.se", "2025-03-01T00:00:00", "import", [{"host": "www.example.se", "ip": "192.0.2.1"}])
    with client(settings) as h:
        hdr = {**UA, "x-real-ip": "198.51.100.7", "referer": "https://news.example.org/post/1"}
        h.get("/", headers=hdr)
        h.get("/d/example.se", headers={**UA, "x-real-ip": "198.51.100.7"})
        h.get(f"/scans/{sid}.csv", headers={**UA, "x-real-ip": "198.51.100.7"})
        h.get("/static/app.css", headers=UA)
        h.get("/", headers={"user-agent": "Googlebot/2.1", "x-real-ip": "198.51.100.8"})
        csrf = sign_in(h)
        page = h.get(BASE).text
    assert csrf and "news.example.org" in page and "/d/example.se" in page
    with db.connect(settings.db_path) as c:
        rows = [dict(r) for r in c.execute("SELECT * FROM visits ORDER BY id")]
        rep = admin.report(c)
    assert [(r["kind"], r["domain"], r["bot"]) for r in rows] == [
        ("page", "", 0), ("page", "example.se", 0), ("download", "example.se", 0), ("page", "", 1)]
    assert len({r["visitor"] for r in rows if not r["bot"]}) == 1
    assert not any("198.51.100" in str(v) for r in rows for v in r.values())
    assert rows[0]["ref"] == "news.example.org" and rows[0]["country"] == "SE"
    assert rep["kpi"]["visitors"] == 1 and rep["kpi"]["downloads"] == 1 and rep["bots"] == 1
    assert [s["path"] for s in rep["sessions"][0]["steps"]] == ["/", "/d/example.se", f"/scans/{sid}.csv"]


def test_day_salt_rotates(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        a = admin.visitor(c, "192.0.2.1", "ua")
        monkeypatch.setattr(db, "now", lambda: "2099-01-02T00:00:00")
        b = admin.visitor(c, "192.0.2.1", "ua")
        assert a != b and len([r for r in c.execute("SELECT key FROM kv WHERE key LIKE 'day_salt:%'")]) == 1
