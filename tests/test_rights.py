"""Feature rights per power user (none / read / read-write per feature, docs/delegation.md) and Admin > Domain
viewers (a maintainer grants viewer on its own domains). Probes use invalid forms: an allowed write gets the
handler's own refusal (422), never a saved change or a queued scan."""
import json
import re
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domin import access, db, users
from domin.config import Settings
from domin.web import COOKIE, create_app

BASE = "/admin"
PW = "correct horse battery"
DOM, OTHER = "alpha.example", "beta.example"
NONE = {f: "none" for f in access.FEATURES}


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        access.set_grants(c, users.create(c, "dana", "power", PW), {DOM: "admin", OTHER: "viewer"}, "test")
        users.create(c, "pia", "power", PW)   # no grants
        users.set_disabled(c, users.create(c, "old", "power", PW), True)
        for dom in (DOM, OTHER):
            db.save_scan(c, dom, db.now(), "scan", [{"host": "www." + dom, "ip": "192.0.2.10"}])
    return s


def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h, name):
    r = h.post(BASE + "/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get(BASE + "/account").text).group(1)


def uid(settings, name):
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)["id"]


def set_rights(settings, name, **rights):
    with db.connect(settings.db_path) as c:
        access.set_rights(c, uid(settings, name), {**NONE, **rights})


# --- storage and migration ---------------------------------------------------------------------------------------

def test_existing_power_users_keep_what_they_could_do(tmp_path):
    path = tmp_path / "old.db"
    db.init(path)
    with db.connect(path) as c:
        users.create(c, "pia", "power", PW)
        c.execute("ALTER TABLE users DROP COLUMN rights")   # a database from before the rights
    db.init(path)
    db.init(path)   # idempotent
    with db.connect(path) as c:
        pia = users.by_name(c, "pia")
        assert access.rights_of(pia) == access.DEFAULT_RIGHTS
        assert json.loads(pia["rights"]) == access.DEFAULT_RIGHTS
    assert access.DEFAULT_RIGHTS == {"inventory": "read", "posture": "read", "scans": "write", "tags": "write",
                                     "profiles": "read", "discovery": "read"}


def test_rights_parse_and_admins_have_everything(settings):
    assert access.parse_rights({"r_scans": "write", "r_tags": "read"}) == {**NONE, "scans": "write", "tags": "read"}
    for bad in ({"r_posture": "write"}, {"r_scans": "all"}):   # posture is read only; unknown level
        with pytest.raises(ValueError):
            access.parse_rights(bad)
    assert access.rights_of({"rights": json.dumps({"posture": "write", "x": "write", "tags": "nope"})}) == {
        **NONE, "posture": "read"}
    assert access.FULL.can("users", "write") and not access.NONE.can("inventory")
    with db.connect(settings.db_path) as c:
        access.set_rights(c, uid(settings, "boss"), NONE)
        assert access.for_user(c, users.by_name(c, "boss")).can("operations", "write")


def test_routes_map_to_features():
    f = access.feature_of
    assert f("GET", "/d/x.example") == ("inventory", "read") and f("POST", "/api/scan") == ("inventory", "read")
    assert f("GET", BASE + "/security/analysis") == ("posture", "read")
    assert f("POST", BASE + "/security/report") == ("posture", "read")
    assert f("GET", BASE + "/security/scans") == ("scans", "read")
    assert f("POST", BASE + "/security/posture") == ("scans", "write")
    assert f("POST", BASE + "/schedules/3/run") == ("scans", "write")
    assert f("POST", BASE + "/tags") == ("tags", "write")
    assert f("POST", BASE + "/security/profiles/x/delete") == ("profiles", "write")
    assert f("GET", BASE + "/security/discovery-profiles") == ("discovery", "read")
    assert f("GET", BASE + "/users/2") == ("settings", "read") and f("POST", BASE + "/tune") == ("operations", "write")
    assert f("POST", BASE + "/domains/x.example/delete") == ("operations", "write")
    assert f("POST", BASE + "/domains/x.example/viewers") == ("inventory", "read")
    assert f("GET", BASE + "/viewers") == ("inventory", "read")
    for free in (BASE, BASE + "/account", BASE + "/login", BASE + "/security/posture/status", "/healthz"):
        assert f("GET", free) is None, free


# --- feature x level ---------------------------------------------------------------------------------------------

READS = {"inventory": "/all", "posture": BASE + "/security", "scans": BASE + "/security/scans",
         "profiles": BASE + "/security/profiles", "discovery": BASE + "/security/discovery-profiles"}
# an invalid form for each writable feature: allowed = the handler refuses the input (422)
WRITES = {"scans": (BASE + "/schedules", {"domain": DOM, "name": ""}),
          "tags": (BASE + "/tags", {"domain": DOM, "host": "www." + DOM, "tag": "Not A Tag!"}),
          "profiles": (BASE + "/security/profiles", {"name": "", "ports": ""}),
          "discovery": (BASE + "/security/discovery-profiles", {"name": "", "method": "nope"})}


@pytest.mark.parametrize("level", access.RIGHTS)
@pytest.mark.parametrize("feature", list(access.FEATURES))
def test_each_feature_at_each_level(settings, feature, level):
    if level == "write" and not access.FEATURES[feature][2]:
        pytest.skip("read-only feature")
    extra = {"inventory": "read"} if feature == "tags" else {}   # tags show on the domain page
    set_rights(settings, "dana", **{**extra, feature: level})
    with client(settings) as h:
        csrf = login(h, "dana")
        if feature in READS:
            assert h.get(READS[feature]).status_code == (404 if level == "none" else 200)
        if feature == "tags":
            assert ('<th data-sort="text">Tags</th>' in h.get(f"/d/{DOM}").text) == (level != "none")
        if feature in WRITES:
            path, form = WRITES[feature]
            r = h.post(path, data={"csrf": csrf, **form}, follow_redirects=False)
            assert r.status_code == {"none": 404, "read": 403, "write": 422}[level], r.text[:300]
            if level == "read":
                assert "may only read" in r.text


def test_admin_only_areas_stay_closed_to_power_users_with_every_right(settings):
    set_rights(settings, "dana", **{f: "write" if w else "read" for f, (_, _, w) in access.FEATURES.items()})
    with client(settings) as h:
        csrf = login(h, "dana")
        for path in (BASE + "/users", BASE + "/settings", BASE + "/security/scan-settings"):
            assert h.get(path).status_code == 404, path
        assert h.post(BASE + "/tune", data={"csrf": csrf}).status_code == 404
        assert h.post(f"{BASE}/domains/{DOM}/delete", data={"csrf": csrf}).status_code == 404
    set_rights(settings, "boss")   # admins: everything, whatever their stored rights
    with client(settings) as h:
        login(h, "boss")
        for path in (*READS.values(), BASE + "/users", BASE + "/settings"):
            assert h.get(path).status_code == 200, path


def test_navigation_hides_what_the_user_cannot_use(settings):
    set_rights(settings, "dana", scans="read")
    with client(settings) as h:
        login(h, "dana")
        assert h.get(BASE, follow_redirects=False).headers["location"] == BASE + "/security/scans"
        page = h.get(BASE + "/security/scans").text
        for gone in ('href="/all"', 'href="/tools"', 'class="jump"', ">Overview<", ">Analysis<", ">Settings</a>"):
            assert gone not in page, gone
        assert 'href="/admin/security/scans"' in page and "Scheduled rescans" in page
        assert 'action="/admin/schedules"' not in page   # read only: no add form
        assert h.get("/").status_code == 404   # the inventory, even while it is public
    set_rights(settings, "dana", inventory="read")
    with client(settings) as h:
        login(h, "dana")
        assert h.get(BASE, follow_redirects=False).headers["location"] == "/"
        page = h.get(f"/d/{DOM}").text
        assert 'id="posture"' not in page and "Scan with nmap" not in page and 'href="/all"' in page


def test_admin_saves_the_matrix_and_it_is_audited(settings):
    dana = uid(settings, "dana")
    with client(settings) as h:
        login(h, "boss")
        page = h.get(f"{BASE}/users/{dana}").text
        assert 'id="rights"' in page and 'name="r_scans" value="write"' in page
        assert 'name="r_posture" value="write"' not in page   # read only feature: no read-write radio
        csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
        r = h.post(f"{BASE}/users/{dana}/rights", data={"csrf": csrf, "r_inventory": "read", "r_scans": "read"},
                   follow_redirects=False)
        assert r.status_code == 303
        assert h.post(f"{BASE}/users/{dana}/rights", data={"csrf": csrf, "r_posture": "write"}).status_code == 422
    with db.connect(settings.db_path) as c:
        assert access.rights_of(users.get(c, dana)) == {**NONE, "inventory": "read", "scans": "read"}
        entry = next(a for a in access.audit_recent(c) if a["action"] == "rights")
        assert entry["target"] == "dana" and "scans write->read" in entry["detail"]
    with client(settings) as h:   # a power user can't save rights
        csrf = login(h, "dana")
        assert h.post(f"{BASE}/users/{dana}/rights", data={"csrf": csrf}).status_code == 404


# --- viewers granted by a maintainer ---------------------------------------------------------------------------

def grants_of(settings, name):
    with db.connect(settings.db_path) as c:
        return {g["domain"]: g["level"] for g in access.grants(c, uid(settings, name))}


def test_domain_page_has_no_viewers_box(settings):
    for name in ("boss", "dana"):   # admin, maintainer of DOM
        with client(settings) as h:
            login(h, name)
            page = h.get(f"/d/{DOM}").text
            assert 'id="viewers"' not in page and "Add viewer" not in page and "/viewers" not in page.split("<main")[1]


def test_domain_viewers_page(settings):
    with client(settings) as h:
        login(h, "dana")
        page = h.get(f"{BASE}/viewers").text
        assert 'href="/admin/viewers"' in page   # the Admin menu entry
        assert re.findall(r'<option value="([a-z.]+)"', page) == [DOM]   # only the domains she administers
        assert h.get(f"{BASE}/viewers", params={"domain": DOM}).status_code == 200
        assert h.get(f"{BASE}/viewers", params={"domain": OTHER}).status_code == 403   # viewer there
        assert h.get(f"{BASE}/viewers", params={"domain": "gamma.example"}).status_code == 404
    with client(settings) as h:
        login(h, "boss")   # admins: every domain
        assert re.findall(r'<option value="([a-z.]+)"', h.get(f"{BASE}/viewers").text) == [DOM, OTHER]
        assert h.get(f"{BASE}/viewers", params={"domain": OTHER}).status_code == 200
    with client(settings) as h:
        login(h, "pia")   # no maintainer grant: no page, no menu entry
        assert h.get(f"{BASE}/viewers").status_code == 404
        assert "/admin/viewers" not in h.get(BASE + "/account").text


def test_users_page_explains_roles_and_rights(settings):
    with client(settings) as h:
        login(h, "boss")
        page = h.get(BASE + "/users").text
        info = page.split('id="roles-info"')[1].split("</section>")[0]
        for term in ("Admin", "Power user", "Maintainer", "Viewer", "Feature rights", "Sign-in scope",
                     "2FA required"):
            assert f"<dt>{term}</dt>" in info, term
        assert 'href="/admin/viewers"' in page


OLD_NAME = re.compile(r"domain[\s-]+admin", re.I)   # the per-domain level is "maintainer" (AD Domain Admins clash)


def test_no_template_or_page_says_domain_admin(settings):
    root = Path(access.__file__).parent / "templates"
    assert [p.name for p in root.glob("*.html") if OLD_NAME.search(p.read_text(encoding="utf-8"))] == []
    dana, pages = uid(settings, "dana"), ["/", "/all", f"/d/{DOM}", "/tools", BASE, BASE + "/account",
                                          BASE + "/viewers", f"{BASE}/viewers?domain={DOM}", BASE + "/security",
                                          BASE + "/security/scans", BASE + "/security/lookup"]
    for name, extra in (("boss", [BASE + "/users", f"{BASE}/users/{dana}", BASE + "/settings"]), ("dana", [])):
        with client(settings) as h:
            csrf = login(h, name)
            for path in pages + extra:
                r = h.get(path)
                assert r.status_code in (200, 404) and not OLD_NAME.search(r.text), path
            if name == "dana":   # a refusal names the level too
                r = h.post(f"{BASE}/domains/{OTHER}/viewers", data={"csrf": csrf, "user": "1"})
                assert r.status_code == 403 and "maintainer rights" in r.text and not OLD_NAME.search(r.text)


def test_maintainer_grants_and_removes_a_viewer(settings):
    pia = uid(settings, "pia")
    with client(settings) as h:
        csrf = login(h, "dana")
        page = h.get(f"{BASE}/viewers", params={"domain": DOM}).text
        picks = re.findall(r'<option value="(\d+)">(\w+)</option>', page.split('id="add-viewer"')[1])
        assert {n for _, n in picks} == {"pia"}   # not the admin, not herself, not a disabled user
        r = h.post(f"{BASE}/domains/{DOM}/viewers", data={"csrf": csrf, "user": str(pia), "level": "admin"},
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == f"{BASE}/viewers?domain={DOM}&ok=viewer-added"
        assert grants_of(settings, "pia") == {DOM: "viewer"}   # a level in the form is ignored
        page = h.get(r.headers["location"]).text
        assert "Viewer added." in page and "<b>pia</b>" in page
    with client(settings) as h:
        login(h, "pia")
        assert h.get(f"/d/{DOM}").status_code == 200 and h.get(f"/d/{OTHER}").status_code == 404
        assert h.get(f"{BASE}/viewers").status_code == 404   # a viewer can't pass it on
    with client(settings) as h:
        csrf = login(h, "dana")
        r = h.post(f"{BASE}/domains/{DOM}/viewers/{pia}/delete", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
    assert grants_of(settings, "pia") == {}
    with db.connect(settings.db_path) as c:
        assert [(a["action"], a["actor"], a["target"], a["detail"]) for a in access.audit_recent(c)[:2]] == [
            ("revoke-viewer", "dana", "pia", DOM), ("grant-viewer", "dana", "pia", DOM)]


def test_maintainer_cannot_go_further(settings):
    ids = {n: uid(settings, n) for n in ("boss", "dana", "pia", "old")}
    with db.connect(settings.db_path) as c:
        access.set_grants(c, ids["pia"], {DOM: "admin"}, "test")
    with client(settings) as h:
        csrf = login(h, "dana")

        def add(dom, who, token=csrf):
            return h.post(f"{BASE}/domains/{dom}/viewers", data={"csrf": token, "user": str(who)}).status_code
        assert add(OTHER, ids["pia"]) == 403            # only viewer on beta
        assert add("gamma.example", ids["pia"]) == 404  # unknown domain
        assert add(DOM, ids["boss"]) == 404             # admins are untouched
        assert add(DOM, ids["dana"]) == 404             # not herself
        assert add(DOM, ids["old"]) == 404              # disabled
        assert add(DOM, 99999) == 404                   # no such user, no user made
        assert add(DOM, ids["pia"]) == 409              # maintainer there: never lowered
        assert add(DOM, ids["pia"], "wrong") == 403     # CSRF
        r = h.post(f"{BASE}/domains/{DOM}/viewers/{ids['pia']}/delete", data={"csrf": csrf})
        assert r.status_code == 409
    assert grants_of(settings, "pia") == {DOM: "admin"}
    with db.connect(settings.db_path) as c:
        assert not any(a["action"] == "grant-viewer" for a in access.audit_recent(c))
