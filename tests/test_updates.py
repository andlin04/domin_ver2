"""Update check (domin.updates): GitHub's answer is faked; no test makes a network request."""
import json
import re
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from domin import __version__, access, admin, db, tools, updates, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"


def release(tag="v9.0.0", **kw) -> dict:
    return {"tag_name": tag, "html_url": f"https://github.com/andlin04/domin_ver2/releases/tag/{tag}",
            "published_at": "2026-11-17T08:00:00Z", "name": f"domin {tag}", "body": "Fixes and features.",
            "prerelease": False, "draft": False, **kw}


def fake(answer=None, status=200, exc=None, raw=None, calls=None):
    """An httpx client whose transport answers like GitHub (no public_only hook: it would resolve the name)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(request)
        if exc:
            raise exc
        if raw is not None:
            return httpx.Response(status, content=raw)
        return httpx.Response(status, json=answer if answer is not None else {"message": "Not Found"})
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture
def conn(tmp_path):
    db.init(tmp_path / "t.db")
    with db.connect(tmp_path / "t.db") as c:
        yield c


def state(conn, installed="2.0.0"):
    return updates.status(conn, True, installed=installed)


def test_version_is_the_package_version():
    assert updates.parse(__version__) == (2, 0, 0)


def test_no_release_published_is_running_latest(conn):
    calls = []
    updates.check(conn, fake(status=404, calls=calls))
    st = state(conn)
    assert st["state"] == "latest" and not st["error"] and st["checked_at"]
    req = calls[0]
    assert str(req.url) == updates.URL and req.headers["accept"] == "application/vnd.github+json"
    assert req.headers["user-agent"] == f"domin/{__version__}"


@pytest.mark.parametrize("tag,expected", [("v2.1.0", "available"), ("2.0.1", "available"), ("v3.0", "available"),
                                          ("v2.0.0", "latest"), ("2.0.0", "latest"), ("v1.9.9", "latest")])
def test_newer_equal_older_and_v_prefix(conn, tag, expected):
    updates.check(conn, fake(release(tag)))
    st = state(conn)
    assert st["state"] == expected
    if expected == "available":
        assert st["version"] == ".".join(map(str, updates.parse(tag))) and st["installed"] == "2.0.0"


@pytest.mark.parametrize("rel", [release("v9.0.0", prerelease=True), release("v9.0.0", draft=True),
                                 release("v9.0.0-rc1")])
def test_prerelease_is_ignored(conn, rel):
    updates.check(conn, fake(rel))
    assert state(conn)["state"] == "latest" and not state(conn)["error"]


@pytest.mark.parametrize("client", [fake(raw=b"{not json"), fake(raw=b"[1, 2]"),
                                    fake(exc=httpx.ReadTimeout("timed out")),
                                    fake(exc=httpx.ConnectError("refused")), fake(status=500, answer={}),
                                    fake(release("latest-and-greatest"))])
def test_failures_store_the_error_and_hide_the_banner(conn, client):
    updates.check(conn, fake(release("v9.0.0")))   # an earlier answer had a newer release
    assert state(conn)["state"] == "available"
    updates.check(conn, client)
    st = state(conn)
    assert st["state"] == "error" and st["error"]


def test_body_excerpt_and_name_are_capped(conn):
    updates.check(conn, fake(release("v9.0.0", body="x" * 5000, name="n" * 1000)))
    stored = json.loads(admin.kv_get(conn, updates.KEY))
    assert len(stored["body"]) == updates.EXCERPT and len(stored["name"]) == updates.NAME_MAX


def test_security_pill_from_name_or_body(conn):
    updates.check(conn, fake(release("v9.0.0", name="domin 9", body="Includes a SECURITY fix.")))
    assert state(conn)["security"]
    updates.check(conn, fake(release("v9.0.0", name="Security release", body="")))
    assert state(conn)["security"]
    updates.check(conn, fake(release("v9.0.0", name="domin 9", body="Faster scans.")))
    assert not state(conn)["security"]


def test_only_github_links(conn):
    updates.check(conn, fake(release("v9.0.0", html_url="https://evil.example/notes")))
    assert state(conn)["url"] == ""
    updates.check(conn, fake(release("v9.0.0", html_url="javascript:alert(1)")))
    assert state(conn)["url"] == ""
    updates.check(conn, fake(release("v9.0.0")))
    assert state(conn)["url"].startswith("https://github.com/")


def test_daily_run_off_makes_no_request(conn, monkeypatch):
    calls = []
    monkeypatch.setattr(tools, "http_client", lambda *a, **k: fake(status=404, calls=calls))
    assert updates.run(conn, default_on=False, now=1e9) is None   # env default off, no admin choice
    updates.set_enabled(conn, False)
    assert updates.run(conn, default_on=True, now=1e9) is None    # admin turned it off over env on
    assert calls == []
    updates.set_enabled(conn, True)
    assert updates.run(conn, default_on=False, now=1e9) is not None and len(calls) == 1
    assert updates.run(conn, default_on=True, now=1e9 + 3600) is None and len(calls) == 1   # once a day
    assert updates.run(conn, default_on=True, now=1e9 + 25 * 3600) is not None and len(calls) == 2


def test_env_sets_the_default(monkeypatch):
    monkeypatch.setenv("DOMIN_UPDATE_CHECK", "0")
    assert Settings.from_env().update_check is False
    monkeypatch.setenv("DOMIN_UPDATE_CHECK", "off")
    assert Settings.from_env().update_check is False
    monkeypatch.delenv("DOMIN_UPDATE_CHECK")
    assert Settings.from_env().update_check is True


# --- pages -------------------------------------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1",))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "admin", "admin", PW)
    return s


def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("127.0.0.1", 50000))


def sign_in(h, name="admin") -> str:
    r = h.post(BASE + "/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get(BASE + "/account").text).group(1)


def store(settings, rel):
    with db.connect(settings.db_path) as c:
        updates.check(c, fake(rel))


def test_banner_for_admins_escaped(settings):
    store(settings, release("v9.1.0", name="<script>alert(1)</script> security", body="<img src=x onerror=alert(1)>"))
    with client(settings) as h:
        sign_in(h)
        page = h.get(BASE + "/security").text
    banner = re.search(r"<p[^>]*data-update-banner.*?</p>", page, re.S).group(0)
    assert "domin v9.1.0 available (you run v2.0.0)" in banner
    assert '<span class="pill bad">security</span>' in banner
    assert 'href="https://github.com/andlin04/domin_ver2/releases/tag/v9.1.0"' in banner and "Release notes" in banner
    assert updates.UPGRADE[settings.install_mode] in banner
    assert "Major upgrade: read the upgrade notes first" in banner   # 9.x over 2.x
    assert "<script>alert(1)" not in page and "onerror=alert" not in page


def test_major_upgrade_line(conn):
    updates.check(conn, fake(release("v3.0.0")))
    assert state(conn)["major"]
    updates.check(conn, fake(release("v2.5.0")))
    assert state(conn)["state"] == "available" and not state(conn)["major"]
    updates.check(conn, fake(release("v2.0.0")))
    assert not state(conn)["major"]


def test_major_upgrade_in_banner_links_release_notes(settings):
    store(settings, release("v3.0.0"))
    with client(settings) as h:
        sign_in(h)
        banner = re.search(r"<p[^>]*data-update-banner.*?</p>", h.get(BASE).text, re.S).group(0)
    assert re.search(r'<a href="https://github.com/andlin04/domin_ver2/releases/tag/v3.0.0"[^>]*>'
                     r"Major upgrade: read the upgrade notes first</a>", banner)
    store(settings, release("v2.1.0"))
    with client(settings) as h:
        sign_in(h)
        banner = re.search(r"<p[^>]*data-update-banner.*?</p>", h.get(BASE).text, re.S).group(0)
    assert "Major upgrade" not in banner


def test_banner_without_link_for_non_github_url(settings):
    store(settings, release("v9.1.0", html_url="https://evil.example/x"))
    with client(settings) as h:
        sign_in(h)
        banner = re.search(r"<p[^>]*data-update-banner.*?</p>", h.get(BASE).text, re.S).group(0)
    assert "Release notes" not in banner and "evil.example" not in banner and "pill bad" not in banner


def test_no_banner_when_latest_or_failed(settings):
    store(settings, release("v2.0.0"))
    with client(settings) as h:
        sign_in(h)
        assert "data-update-banner" not in h.get(BASE).text
        with db.connect(settings.db_path) as c:
            updates.check(c, fake(raw=b"{bad"))
        assert "data-update-banner" not in h.get(BASE).text


def test_viewer_sees_no_banner_maintainer_does(settings):
    store(settings, release("v9.1.0"))
    with db.connect(settings.db_path) as c:
        uid = users.create(c, "vic", "power", PW)
        mid = users.create(c, "max", "power", PW)
        access.set_grants(c, uid, {"example.se": "viewer"}, "test")
        access.set_grants(c, mid, {"example.se": "admin"}, "test")
    with client(settings) as h:
        sign_in(h, "vic")
        assert "data-update-banner" not in h.get(BASE + "/account").text
    with client(settings) as h:
        sign_in(h, "max")
        assert "data-update-banner" in h.get(BASE + "/account").text


def test_settings_status_lines(settings):
    with client(settings) as h:
        sign_in(h)
        page = h.get(BASE + "/settings").text
        assert "not checked yet" in page and f"Version {__version__}" in page
        store(settings, release("v2.0.0"))
        assert "Running latest" in h.get(BASE + "/settings").text
        with db.connect(settings.db_path) as c:
            updates.check(c, fake(exc=httpx.ReadTimeout("<b>slow</b>")))
        page = h.get(BASE + "/settings").text
        assert "Could not check for updates" in page and "&lt;b&gt;slow&lt;/b&gt;" in page and "<b>slow" not in page


def test_toggle_and_check_now(settings, monkeypatch):
    calls = []
    monkeypatch.setattr(tools, "http_client", lambda *a, **k: fake(release("v9.2.0"), calls=calls))
    with client(settings) as h:
        csrf = sign_in(h)
        assert h.post(BASE + "/settings/update-check", data={"csrf": "forged"}).status_code == 403
        r = h.post(BASE + "/settings/update-check", data={"csrf": csrf}, follow_redirects=False)   # unticked = off
        assert r.status_code == 303
        with db.connect(settings.db_path) as c:
            assert not updates.enabled(c, settings.update_check)
            assert updates.run(c, settings.update_check) is None and calls == []   # daily job: no request
        assert h.post(BASE + "/settings/update-check/now", data={"csrf": "forged"}).status_code == 403
        r = h.post(BASE + "/settings/update-check/now", data={"csrf": csrf})   # works while automatic is off
        assert r.status_code == 200 and len(calls) == 1
        assert "domin v9.2.0 available (you run v2.0.0)" in r.text and "Update check done" in r.text
        h.post(BASE + "/settings/update-check", data={"csrf": csrf, "on": "1"})
        with db.connect(settings.db_path) as c:
            assert updates.enabled(c, settings.update_check)


def test_settings_actions_are_admin_only(settings, monkeypatch):
    calls = []
    monkeypatch.setattr(tools, "http_client", lambda *a, **k: fake(release("v9.2.0"), calls=calls))
    with db.connect(settings.db_path) as c:
        mid = users.create(c, "max", "power", PW)
        access.set_grants(c, mid, {"example.se": "admin"}, "test")
    with client(settings) as h:
        csrf = sign_in(h, "max")
        assert h.post(BASE + "/settings/update-check/now", data={"csrf": csrf}).status_code == 404
        assert h.post(BASE + "/settings/update-check", data={"csrf": csrf}).status_code == 404
    assert calls == []
