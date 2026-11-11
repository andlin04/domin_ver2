"""Delegation (docs/delegation.md): admins see everything, a power user only its granted domains, per domain as
viewer (read) or domain admin (read plus that domain's actions); out-of-scope objects answer 404 like unknown ones."""
import json
import re
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from domin import __main__ as cli
from domin import access, admin, db, jobs, posture, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
# alpha: viewer for pia; sub.alpha: covered by the alpha grant; xalpha: not (a suffix match needs the dot);
# beta: domain admin for pia; gamma: nobody but the admins
INVENTORY = {"alpha.example": "192.0.2.10", "sub.alpha.example": "192.0.2.11", "xalpha.example": "192.0.2.12",
             "beta.example": "198.51.100.20", "gamma.example": "203.0.113.30"}
SEEN = {"alpha.example", "sub.alpha.example", "beta.example"}
HIDDEN = {"xalpha.example", "gamma.example"}


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        pia = users.create(c, "pia", "power", PW)
        users.create(c, "nob", "power", PW)   # no grants
        access.set_grants(c, pia, {"alpha.example": "viewer", "beta.example": "admin"}, "test")
        for dom, ip in INVENTORY.items():
            db.save_scan(c, dom, db.now(), "scan", [{"host": "www." + dom, "ip": ip}])
            c.execute("INSERT INTO posture_scans (domain, ip, hosts, ports, status, created, finished, open_ports, "
                      "cves, high) VALUES (?, ?, ?, '22', 'done', ?, ?, 1, 2, 1)",
                      (dom, ip, "www." + dom, db.now(), db.now()))
    return s


def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h, name):
    r = h.post(BASE + "/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get(BASE + "/account").text).group(1)


def names_in(text):
    return {d for d in INVENTORY if re.search(r"(?<![\w.-])" + re.escape(d) + r"(?![\w-])", text)}


def scan_id(settings, dom):
    with db.connect(settings.db_path) as c:
        return db.history(c, dom)[-1]["id"]


def uid(settings, name):
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)["id"]


# --- the scope itself --------------------------------------------------------------------------------------------

def test_a_grant_covers_its_subdomains_and_the_highest_level_wins():
    s = access.Scope(grants=(("alpha.example", "viewer"), ("beta.example", "admin"), ("sub.beta.example", "viewer")))
    assert s.level("alpha.example") == "viewer" and s.level("www.sub.alpha.example") == "viewer"
    assert s.level("xalpha.example") == "" and s.level("example") == "" and not s.sees("")
    assert s.manages("sub.beta.example")   # the beta admin grant beats the narrower viewer grant
    assert s.sees("alpha.example") and not s.manages("alpha.example") and s.manages_any and not s.sees_all
    every = access.Scope(grants=(("*", "viewer"),))
    assert every.sees_all and every.sees("any.example") and not every.manages("any.example")
    assert access.NONE.sql("d.name") == ("0", []) and access.FULL.sql("d.name") == ("1", [])
    assert access.Scope(grants=(("a_b.example", "viewer"),)).sql("x")[1] == ["a_b.example", "%.a\\_b.example"]


def test_queries_filter_on_the_scope(settings):
    with db.connect(settings.db_path) as c:
        pia = access.for_user(c, users.by_name(c, "pia"))
        assert {d["name"] for d in db.domains_overview(c, scope=pia)} == SEEN
        assert db.totals(c, pia)["domains"] == 3 and db.totals(c, access.FULL)["domains"] == 5
        assert db.totals(c, access.NONE)["domains"] == 0
        rows, total = db.search(c, scope=pia)
        assert total == 3 and {r["domain"] for r in rows} == SEEN
        assert {r["domain"] for r in posture.current(c, scope=pia)} == SEEN
        assert posture.domains(c, pia) == sorted(SEEN) and posture.domains(c, access.NONE) == []
        assert set(posture.search_domains(c, "example", pia)) == SEEN


# --- public pages and API: lists, search, CSV, drill data, detail and 404 ----------------------------------------

def test_power_user_lists_only_its_domains_and_anonymous_sees_the_whole_inventory(settings):
    with client(settings) as h:   # anonymous: the public inventory
        assert names_in(h.get("/").text) == set(INVENTORY)
        assert {d["name"] for d in h.get("/api/domains").json()} == set(INVENTORY)
    for who, want in (("pia", SEEN), ("nob", set()), ("boss", set(INVENTORY))):
        with client(settings) as h:
            login(h, who)
            assert names_in(h.get("/").text) == want, who
            assert {d["name"] for d in h.get("/api/domains").json()} == want, who
            assert names_in(h.get("/all", params={"q": "www"}).text) == want, who
            assert names_in(h.get("/all", params={"scope": "all"}).text) == want, who
            csv = h.get("/search.csv", params={"q": "www"}).text
            assert {line.split(",")[0] for line in csv.splitlines()[1:]} == want, who
            drill = h.get("/data/drill.json", params={"scope": "latest"})
            assert names_in(drill.text) == want, who
            if who != "boss":
                assert drill.headers["cache-control"].startswith("private")


def test_out_of_scope_objects_answer_404_like_unknown_ones(settings):
    gamma, beta = scan_id(settings, "gamma.example"), scan_id(settings, "beta.example")
    with db.connect(settings.db_path) as c:
        job = jobs.enqueue(c, "gamma.example")["id"]
    with client(settings) as h:
        login(h, "pia")
        for path in ("/d/gamma.example", "/d/xalpha.example", "/api/domains/gamma.example/history",
                     f"/api/scans/{gamma}", f"/scans/{gamma}.csv", f"/api/jobs/{job}",
                     f"/d/gamma.example/compare?a={gamma}&b={gamma}", "/d/nosuch.example"):
            assert h.get(path).status_code == 404, path
        for path in ("/d/beta.example", "/d/sub.alpha.example", "/api/domains/beta.example/history",
                     f"/api/scans/{beta}", f"/scans/{beta}.csv"):
            assert h.get(path).status_code == 200, path
    with client(settings) as h:
        login(h, "nob")
        assert h.get("/d/alpha.example").status_code == 404
    with client(settings) as h:
        login(h, "boss")
        assert h.get("/d/gamma.example").status_code == 200 and h.get(f"/api/jobs/{job}").status_code == 200


def test_domain_page_offers_scans_only_where_the_user_is_domain_admin(settings):
    with client(settings) as h:
        login(h, "pia")
        assert "scan / renew" in h.get("/d/beta.example").text
        assert "scan / renew" not in h.get("/d/alpha.example").text


# --- the posture pages and their aggregates ----------------------------------------------------------------------

def test_posture_pages_and_counts_follow_the_grants(settings):
    with client(settings) as h:
        login(h, "pia")
        doms = h.get(BASE + "/security/analysis").text.split('id="posture-domains"')[1].split("</table>")[0]
        assert set(re.findall(r'<tr data-domain="([^"]+)"', doms)) == SEEN
        assert set(h.get(BASE + "/security/domain-search", params={"q": "example"}).json()["domains"]) == SEEN
        mine = h.get(BASE + "/security/kpis").text
        assert h.get(BASE + "/security/kpis", params={"domain": "gamma.example"}).text == mine   # ignored
        with db.connect(settings.db_path) as c:
            ids = [r[0] for r in c.execute("SELECT id FROM posture_scans ORDER BY domain")]
        st = h.get(BASE + "/security/posture/status", params={"ids": ",".join(map(str, ids))}).json()
        assert st["total"] == 3
        r = h.get(BASE + "/security", params={"domain": "gamma.example"})
        assert r.status_code == 200 and "gamma.example" not in r.text
    with client(settings) as h:
        login(h, "boss")
        assert h.get(BASE + "/security/kpis").text != mine
        st = h.get(BASE + "/security/posture/status", params={"ids": ",".join(map(str, ids))}).json()
        assert st["total"] == 5
    with client(settings) as h:
        login(h, "nob")
        st = h.get(BASE + "/security/posture/status", params={"ids": ",".join(map(str, ids))}).json()
        assert st["total"] == 0


def test_report_covers_only_granted_domains(settings):
    with client(settings) as h:
        csrf = login(h, "pia")
        r = h.post(BASE + "/security/report", data={"csrf": csrf, "domains": "gamma.example", "format": "md"})
        assert r.status_code == 422
        r = h.post(BASE + "/security/report", data={"csrf": csrf, "domains": "alpha.example,gamma.example",
                                                     "format": "md"})
        assert r.status_code == 200 and "alpha.example" in r.text and "gamma.example" not in r.text


# --- actions: domain admin only on its domains -------------------------------------------------------------------

def test_posture_scans_and_tags_need_domain_admin_on_that_domain(settings):
    with client(settings) as h:
        csrf = login(h, "pia")

        def scan(dom):
            return h.post(BASE + "/security/posture", data={"csrf": csrf, "domain": dom},
                          headers={"accept": "application/json"})

        assert scan("beta.example").status_code == 200 and scan("beta.example").json()["domain"] == "beta.example"
        assert scan("alpha.example").status_code == 403
        assert scan("sub.alpha.example").status_code == 403
        assert scan("gamma.example").status_code == 422 and scan("nosuch.example").status_code == 422

        def tag(dom):
            return h.post(BASE + "/tags", data={"csrf": csrf, "domain": dom, "host": "www." + dom, "tag": "lab"},
                          follow_redirects=False)

        assert tag("beta.example").status_code == 303
        assert tag("alpha.example").status_code == 403
        assert tag("gamma.example").status_code == 404
        r = h.post(BASE + "/security/scan", data={"csrf": csrf, "kind": "host", "target": "198.51.100.20"})
        assert r.status_code == 403   # an address: admins only
        r = h.post(BASE + "/security/scan", data={"csrf": csrf, "kind": "host", "target": "www.alpha.example"})
        assert r.status_code == 403   # viewer level
        for path in (BASE, BASE + "/users", BASE + "/settings"):
            assert h.get(path, follow_redirects=False).status_code in (303, 404), path
        assert h.post(BASE + "/tune", data={"csrf": csrf}, follow_redirects=False).status_code in (303, 404)
    with db.connect(settings.db_path) as c:
        queued = {r[0] for r in c.execute("SELECT domain FROM posture_scans WHERE status = 'queued'")}
    assert queued == {"beta.example"}
    with client(settings) as h:
        csrf = login(h, "nob")
        assert h.post(BASE + "/security/posture", data={"csrf": csrf, "domain": "beta.example"},
                      headers={"accept": "application/json"}).status_code == 422
        r = h.post(BASE + "/security/scan", data={"csrf": csrf, "kind": "cpe", "vendor": "x", "product": "y",
                                                   "version": "1"})
        assert r.status_code == 403


# --- users, grants and the audit trail ---------------------------------------------------------------------------

def test_admin_sets_grants_and_the_change_is_audited(settings):
    pia = uid(settings, "pia")
    with client(settings) as h:
        csrf = login(h, "boss")
        page = h.get(f"{BASE}/users/{pia}").text
        assert 'id="grants"' in page and "domain admin" in page
        r = h.post(f"{BASE}/users/{pia}/grants", data={"csrf": csrf, "g_domain_0": "alpha.example",
                   "g_level_0": "admin", "g_domain_1": "gamma.example", "g_level_1": "viewer"}, follow_redirects=False)
        assert r.status_code == 303
        with db.connect(settings.db_path) as c:
            assert {g["domain"]: g["level"] for g in access.grants(c, pia)} == {"alpha.example": "admin",
                                                                                "gamma.example": "viewer"}
        listing = h.get(BASE + "/users").text
        assert "beta.example=admin" in listing and "alpha.example=viewer-&gt;admin" in listing
        r = h.post(f"{BASE}/users/{pia}/grants", data={"csrf": csrf, "g_domain_0": "bad domain!",
                                                        "g_level_0": "viewer"})
        assert r.status_code == 422 and 'value="bad domain!" selected' in r.text
        r = h.post(BASE + "/users/add", data={"csrf": csrf, "name": "newp", "role": "power"}, follow_redirects=False)
        assert r.status_code == 303 and re.search(r"/admin/users/\d+\?", r.headers["location"])
    with client(settings) as h:   # the new grants apply at once
        login(h, "pia")
        assert h.get("/d/gamma.example").status_code == 200 and h.get("/d/beta.example").status_code == 404
        assert h.get(f"{BASE}/users/{pia}").status_code == 404   # not an admin


def test_several_admins_and_the_last_one_is_kept(settings):
    with db.connect(settings.db_path) as c:
        users.create(c, "boss2", "admin", PW)
    boss, boss2 = uid(settings, "boss"), uid(settings, "boss2")
    with client(settings) as h:
        csrf = login(h, "boss")
        assert h.post(f"{BASE}/users/{boss2}/role", data={"csrf": csrf, "role": "power"},
                      follow_redirects=False).status_code == 303
        for action, extra in (("role", {"role": "power"}), ("disable", {"disabled": "on"}), ("delete", {})):
            assert h.post(f"{BASE}/users/{boss}/{action}", data={"csrf": csrf, **extra}).status_code == 409, action
        assert "The last admin's role is locked" in h.get(f"{BASE}/users/{boss}").text
        assert h.post(f"{BASE}/users/{boss2}/role", data={"csrf": csrf, "role": "admin"},
                      follow_redirects=False).status_code == 303
        assert h.post(f"{BASE}/users/{boss}/disable", data={"csrf": csrf, "disabled": "on"},
                      follow_redirects=False).status_code == 303   # another admin exists now
    with db.connect(settings.db_path) as c:
        assert users.get(c, boss)["disabled"] and users.get(c, boss2)["role"] == "admin"


def test_cli_user_grant(settings, monkeypatch, capsys):
    monkeypatch.setenv("DOMIN_DB", str(settings.db_path))
    assert cli.main(["user-grant", "nob", "gamma.example", "admin"]) == 0
    assert cli.main(["user-grant", "nob", "beta.example", "viewer"]) == 0
    assert cli.main(["user-grant", "nob", "beta.example", "none"]) == 0
    assert cli.main(["user-grant", "nobody", "beta.example", "viewer"]) == 2
    assert cli.main(["user-role", "boss", "power"]) == 2   # the last admin
    with db.connect(settings.db_path) as c:
        assert {g["domain"]: g["level"] for g in access.grants(c, uid(settings, "nob"))} == {"gamma.example": "admin"}
        assert any(a["actor"] == "cli" and a["target"] == "nob" for a in access.audit_recent(c))


# --- migration from the old viewer / analyst roles ---------------------------------------------------------------

def test_old_roles_migrate_on_an_existing_database(settings):
    with db.connect(settings.db_path) as c:   # a database from before delegation: no grants or audit tables
        c.execute("DROP TABLE grants")
        c.execute("DROP TABLE audit")
        for name, role in (("vic", "viewer"), ("ann", "analyst")):
            c.execute("INSERT INTO users (name, password_hash, role, created) VALUES (?, ?, ?, ?)",
                      (name, admin.hash_password(PW), role, db.now()))
        admin.kv_set(c, "scope", json.dumps({"ip_allow": [], "require_2fa": {"admin": True, "analyst": True,
                                                                             "viewer": False}}))
    db.init(settings.db_path)
    db.init(settings.db_path)   # idempotent: a second run changes nothing
    with db.connect(settings.db_path) as c:
        assert users.migrate_roles(c) == 0
        vic, ann = users.by_name(c, "vic"), users.by_name(c, "ann")
        assert vic["role"] == ann["role"] == "power"
        assert access.grants(c, vic["id"])[0] | {"added": "", "added_by": ""} == {"domain": "*", "level": "viewer",
                                                                                 "added": "", "added_by": ""}
        assert [g["level"] for g in access.grants(c, ann["id"])] == ["admin"]
        assert users.get_scope(c)["require_2fa"] == {"power": True, "admin": True}
        audit = [a for a in access.audit_recent(c) if a["actor"] == "migration"]
        assert sorted(a["target"] for a in audit) == ["ann", "vic"]
        assert access.for_user(c, vic).sees_all and not access.for_user(c, vic).manages("x.example")
        assert access.for_user(c, ann).manages("x.example")
    with client(settings) as h:   # the migrated users keep their reach
        login(h, "vic")
        assert names_in(h.get("/").text) == set(INVENTORY)
