"""Components: inventory and posture, installed together or one alone (install.sh --components, DOMIN_COMPONENTS),
each turned on or off in Settings > Components. Off: routes 404, nav hidden, the worker skips its jobs, schedules
wait, the data stays. At least one stays on; one not installed cannot be turned on."""
import json
import os
import re
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from test_posture import DOM, app_client, nmap, run_queue, settings, sign_in  # noqa: F401 (fixtures)

from domin import access, admin, components, csvimport, db, jobs, posture, schedules, users
from domin.config import Settings, parse_components

ROOT = Path(__file__).resolve().parents[1]
COMP = "/admin/settings/components"
INVENTORY_URLS = ("/all", "/search", "/tools", f"/d/{DOM}", "/data/drill.json", "/api/domains",
                  f"/api/domains/{DOM}", "/admin/viewers")
POSTURE_URLS = ("/admin/security", "/admin/security/scans", "/admin/security/analysis", "/admin/security/import",
                "/admin/security/profiles", "/admin/security/discovery-profiles", "/admin/security/lookup")
SHARED_URLS = ("/admin", "/admin/settings", "/admin/users", "/admin/account", "/admin/security/scan-settings", COMP)
SCHEDULE = {"name": "nightly", "enabled": "on", "discovery": "on", "discovery_profile": "default", "posture": "",
            "posture_profile": "default", "host_mode": "all", "tag": "", "freq": "daily", "at_time": "03:00",
            "weekday": "0", "monthday": "1", "every": "1"}


def turn(settings, **on):  # noqa: F811
    with db.connect(settings.db_path) as c:
        components.save(c, settings.components, {n: on.get(n, True) for n in components.COMPONENTS})


def post_components(h, csrf, **on):
    return h.post(COMP, data={"csrf": csrf, **{n: "on" for n, v in on.items() if v}}, follow_redirects=False)


def head_of(html: str) -> str:
    return html.split('<main class="wrap">', 1)[0]


def user_id(settings, name):  # noqa: F811
    with db.connect(settings.db_path) as c:
        return users.by_name(c, name)["id"]


# --- paths and settings ------------------------------------------------------------------------------------------

def test_paths_map_to_their_component():
    for p in ("/", "/all", "/search.csv", "/d/x.example", "/api/scan", "/api/domains/x.example", "/admin/viewers",
              "/admin/domains/x.example/viewers/3/delete"):
        assert components.of_path(p) == "inventory", p
    for p in ("/admin/security", "/admin/security/scans", "/admin/schedules/3", "/admin/discovery/scan",
              "/admin/security/import", "/admin/security/profiles"):
        assert components.of_path(p) == "posture", p
    # shared: sign-in, settings, Routes, tags, the CSV import, static files
    for p in ("/admin", "/admin/settings", "/admin/security/scan-settings", "/admin/tags",
              "/admin/settings/csv-import", "/static/app.css", "/healthz", "/allx", "/admin/securityx"):
        assert components.of_path(p) == "", p


def test_install_list_parsing():
    assert parse_components("") == ("inventory", "posture") == parse_components("bogus")
    assert parse_components("posture") == ("posture",)
    assert parse_components(" Posture , inventory") == ("inventory", "posture")
    assert components.install_command(("inventory",), "posture") == \
        "sudo bash deploy/install.sh --components inventory,posture"
    assert replace(Settings.from_env(), components=("posture",)).components == ("posture",)


def test_the_last_component_cannot_be_turned_off_and_a_missing_one_not_on(settings):  # noqa: F811
    with db.connect(settings.db_path) as c:
        with pytest.raises(ValueError, match="At least one"):
            components.save(c, settings.components, {"inventory": False, "posture": False})
        assert components.save(c, settings.components, {"inventory": True, "posture": False}) == ["posture off"]
        assert components.enabled(c, settings.components) == ("inventory",)
        with pytest.raises(ValueError, match="not installed"):
            components.save(c, ("inventory",), {"inventory": True, "posture": True})
        # the saved choice names only a component that is no longer installed: the installed one runs
        admin.kv_set(c, components.KEY, json.dumps({"inventory": False, "posture": True}))
        assert components.enabled(c, ("inventory",)) == ("inventory",)


def test_components_page_saves_and_refuses(settings):  # noqa: F811
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        page = h.get(COMP)
        assert page.status_code == 200 and page.text.count('type="checkbox"') == 2
        assert 'href="/admin/settings/components"' in h.get("/admin/settings").text
        none = post_components(h, csrf)
        assert none.status_code == 422 and "At least one" in none.text
        r = post_components(h, csrf, inventory=True)
        assert r.status_code == 303 and "ok=saved" in r.headers["location"]
        assert h.get("/admin/security").status_code == 404
        assert post_components(h, csrf, inventory=True, posture=True).status_code == 303
        assert h.get("/admin/security").status_code == 200
        assert post_components(h, "nope", inventory=True).status_code == 403
    with app_client(settings) as h:   # not an admin: no page, no change
        csrf = sign_in(h, "ana")
        assert h.get(COMP).status_code == 404
        assert post_components(h, csrf, inventory=True).status_code == 404
    with db.connect(settings.db_path) as c:
        assert components.enabled(c, settings.components) == ("inventory", "posture")
        assert [r["detail"] for r in access.audit_recent(c) if r["action"] == "components"] == \
            ["posture on", "posture off"]


def test_a_component_not_installed_is_greyed_out_and_cannot_be_enabled(settings):  # noqa: F811
    only = replace(settings, components=("posture",))
    with app_client(only) as h:
        csrf = sign_in(h, "adm")
        page = h.get(COMP).text
        assert re.search(r'name="inventory"[^>]*\sdisabled', page) and "not installed" in page
        assert "--components inventory,posture" in page
        r = h.post(COMP, data={"csrf": csrf, "inventory": "on", "posture": "on"})
        assert r.status_code == 422 and "not installed" in r.text
        assert h.get("/all").status_code == 404 and h.get("/api/domains").status_code == 404


# --- each component off ------------------------------------------------------------------------------------------

def test_inventory_off_404s_its_routes_and_hides_its_nav(settings):  # noqa: F811
    turn(settings, inventory=False)
    with app_client(settings) as h:
        for url in INVENTORY_URLS:
            assert h.get(url).status_code == 404, url
        r = h.get("/", follow_redirects=False)   # the front page goes to Posture
        assert r.status_code == 303 and r.headers["location"] == "/admin/security"
        assert h.post("/api/scan", json={"domain": DOM}).status_code == 404
        sign_in(h, "adm")
        for url in POSTURE_URLS + SHARED_URLS:
            assert h.get(url).status_code == 200, url
        page = h.get("/admin/security", params={"domain": DOM}).text
        head = head_of(page)
        assert 'href="/all"' not in head and 'href="/tools"' not in head and 'action="/d/"' not in head
        assert 'href="/admin/viewers"' not in head and 'class="brand" href="/admin/security"' in head
        assert "View DNS records" not in page and 'href="/d/' not in page
        assert 'href="/d/' not in h.get("/admin").text
        # the rights matrix and the sign-in settings: posture only
        edit = h.get(f"/admin/users/{user_id(settings, 'ana')}").text
        assert 'name="r_inventory"' not in edit and 'name="r_posture"' in edit
        st = h.get("/admin/settings").text
        assert 'name="inventory"' not in st and 'name="posture"' in st
        assert 'id="csv-import"' not in st   # the CSV import is in Posture > Import targets
        assert 'id="csv-import"' in h.get("/admin/security/import").text


def test_posture_off_404s_its_routes_and_hides_its_nav(settings):  # noqa: F811
    turn(settings, posture=False)
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        for url in POSTURE_URLS + ("/admin/security/kpis", "/admin/schedules"):
            assert h.get(url).status_code == 404, url
        assert h.post("/admin/discovery/scan", data={"csrf": csrf, "domain": DOM, "profile": "default"}
                      ).status_code == 404
        assert h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM}).status_code == 404
        for url in ("/", "/all", f"/d/{DOM}", "/admin/settings", "/admin/users", "/admin/security/scan-settings",
                    COMP):
            assert h.get(url).status_code == 200, url
        assert 'href="/admin/security' not in head_of(h.get("/").text)
        st = h.get("/admin/settings").text
        assert 'href="/admin/security/profiles"' not in st and 'href="/admin/security/lookup"' not in st
        assert 'name="posture"' not in st and 'name="inventory"' in st and 'id="csv-import"' in st
        edit = h.get(f"/admin/users/{user_id(settings, 'ana')}").text
        assert 'name="r_posture"' not in edit and 'name="r_scans"' not in edit and 'name="r_inventory"' in edit


def test_hidden_rights_and_signin_keep_their_values_on_save(settings):  # noqa: F811
    ana = user_id(settings, "ana")
    with db.connect(settings.db_path) as c:
        users.set_signin_required(c, True, True)
        before = access.rights_of(users.get(c, ana))
    turn(settings, posture=False)
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        assert h.post("/admin/settings/signin", data={"csrf": csrf}, follow_redirects=False).status_code == 303
        r = h.post(f"/admin/users/{ana}/rights", data={"csrf": csrf, "r_inventory": "none"}, follow_redirects=False)
        assert r.status_code == 303
    with db.connect(settings.db_path) as c:
        assert users.signin_required(c) == {"inventory": False, "posture": True}   # posture hidden: kept
        after = access.rights_of(users.get(c, ana))
    assert after["inventory"] == "none"
    assert {f: after[f] for f in components.FEATURES["posture"]} == \
        {f: before[f] for f in components.FEATURES["posture"]}


# --- the worker --------------------------------------------------------------------------------------------------

def queue(settings):  # noqa: F811
    """An inventory job (a visitor's), a discovery job and a schedule's job, in that order."""
    with db.connect(settings.db_path) as c:
        c.execute("INSERT INTO jobs (domain, status, created, client, discovery) VALUES "
                  "('a.example', 'queued', ?, 'visitor', ''), ('b.example', 'queued', ?, 'admin', 'default'), "
                  "('c.example', 'queued', ?, 'schedule', '')", (db.now(),) * 3)
        c.commit()


def claims(settings):  # noqa: F811
    got = []
    for refresh in (False, True):
        while job := jobs._next(settings, refresh)[1]:
            got.append(job["domain"])
    return got


def test_worker_skips_inventory_jobs_when_inventory_is_off(settings):  # noqa: F811
    queue(settings)
    with db.connect(settings.db_path) as c:   # a failed domain: housekeeping would retry it
        c.execute("INSERT INTO jobs (domain, status, created, finished, client, discovery) "
                  "VALUES ('f.example', 'failed', ?, ?, 'visitor', '')", (db.now(), db.now()))
        c.commit()
    turn(settings, inventory=False)
    assert claims(settings) == ["b.example", "c.example"]
    jobs.housekeeping(settings)
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT status FROM jobs WHERE domain = 'a.example'").fetchone()[0] == "queued"
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE client = 'refresh'").fetchone()[0] == 0   # no retry
    turn(settings)
    assert claims(settings)[0] == "a.example"


def test_worker_skips_posture_jobs_and_schedules_wait_when_posture_is_off(settings, nmap):  # noqa: F811
    queue(settings)
    with db.connect(settings.db_path) as c:
        found, _ = posture.targets(c, DOM)
        assert posture.enqueue(c, DOM, found, "22,80", "adm") == 2
        p, err = schedules.check(c, DOM, SCHEDULE)
        assert p, err
        sid = schedules.create(c, DOM, p, "adm")
        c.execute("UPDATE schedules SET next_ts = 1 WHERE id = ?", (sid,))
        c.commit()
    turn(settings, posture=False)
    assert claims(settings) == ["a.example"]
    assert run_queue(settings) == 0   # posture scans wait
    assert jobs.schedule_tick(settings) == []
    assert jobs.cve_refresh(settings, now=10 ** 10) is None
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT next_ts FROM schedules WHERE id = ?", (sid,)).fetchone()[0] == 1   # kept, waiting
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'").fetchone()[0] == 2
    turn(settings)
    assert run_queue(settings) == 2
    assert claims(settings) == ["b.example", "c.example"]


# --- posture-only ------------------------------------------------------------------------------------------------

def test_posture_only_discovery_and_csv_import_work_without_inventory_links(settings):  # noqa: F811
    only = replace(settings, components=("posture",))
    data = b"domain,host,ip\r\nexample.net,www.example.net,172.20.4.70\r\n"
    with app_client(only) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/discovery/scan", data={"csrf": csrf, "domain": DOM, "profile": "default"},
                   follow_redirects=False)
        assert r.status_code == 303 and "discovery-queued" in r.headers["location"]
        assert claims(only) == [DOM]   # the worker takes the discovery job with inventory not installed
        page = h.get("/admin/security/import").text
        assert 'name="from" value="posture"' in page and 'action="/admin/settings/csv-import"' in page
        assert 'href="/d/' not in page
        r = h.post("/admin/settings/csv-import", data={"csrf": csrf, "from": "posture"},
                   files={"file": ("t.csv", data, "text/csv")}, follow_redirects=False)
        assert r.status_code == 303 and "from=posture" in r.headers["location"]
        mapping = h.get(r.headers["location"]).text
        assert 'href="/admin/security/import"' in mapping and 'href="/d/' not in mapping
        sent = {"csrf": csrf, "t": re.search(r'name="t" value="([^"]+)"', mapping)[1], "header": "on",
                "from": "posture", "action": "import"}
        for field, opts in re.findall(r'<select name="(map_\w+)">(.*?)</select>', mapping, re.S):
            got = re.search(r'value="(\d+)" selected', opts)
            sent[field] = got[1] if got else ""
        r = h.post("/admin/settings/csv-import/map", data=sent, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/admin/security/import")
        assert csvimport.run_pending(only)["state"] == "done"
        with db.connect(only.db_path) as c:   # the imported rows are posture targets
            assert "example.net" in posture.domains(c)
            assert [t["ip"] for t in posture.targets(c, "example.net")[0]] == ["172.20.4.70"]
        for url in ("/admin/security", "/admin/security/scans", "/admin/security/analysis", "/admin",
                    "/admin/settings"):
            body = h.get(url, params={"domain": "example.net"}).text
            assert 'href="/d/' not in body and 'href="/all"' not in body and "View DNS records" not in body, url


# --- install.sh and update.sh ------------------------------------------------------------------------------------

def test_install_and_update_scripts_handle_components():
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    assert "--components) COMPONENTS=$2; shift ;;" in text
    assert "setenv DOMIN_COMPONENTS" in text and "envget DOMIN_COMPONENTS" in text
    assert "! has posture || apt-get install -y -q nmap wireguard-tools tor" in text
    for part in ("domin-tor", "domin-mullvad", "30-raw.conf", "posture removed:"):
        assert part in text
    update = (ROOT / "deploy" / "update.sh").read_text(encoding="utf-8")
    assert "DOMIN_COMPONENTS" in update and "eval" not in update


def components_block() -> str:
    """The --components block of install.sh, to run on its own."""
    text = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    start = text.index("# Components: --components")
    return text[start:text.index('[[ "$ZONES"', start)]


def find_bash() -> str | None:
    """A POSIX bash; on Windows Git's, not the WSL launcher in System32."""
    found = shutil.which("bash")
    if found and os.name == "nt" and "system32" in found.lower():
        git = shutil.which("git")
        cand = Path(git).resolve().parents[1] / "bin" / "bash.exe" if git else None
        found = str(cand) if cand and cand.exists() else None
    return found


BASH = find_bash()
PRELUDE = """set -euo pipefail
envget() { if [ -n "${SAVED:-}" ]; then echo "$SAVED"; fi; }
RAW=${RAW_IN:-}
COMPONENTS=$1
"""


@pytest.mark.skipif(not BASH, reason="needs bash")
@pytest.mark.parametrize("arg,saved,raw,out", [
    ("", "", "", "inventory,posture"),
    ("posture,inventory", "", "", "inventory,posture"),
    ("posture", "", "1", "posture"),
    ("", "inventory", "", "inventory"),
    ("inventory,,inventory", "", "", "inventory"),
    ("inventory", "", "1", "ERR --raw needs the posture component"),
    ("dns", "", "", "ERR bad --components: unknown 'dns' (inventory, posture)"),
    (",", "", "", "ERR bad --components: inventory, posture or inventory,posture"),
    ("inventory;id", "", "", "ERR bad --components: inventory, posture or inventory,posture"),
])
def test_install_components_flag_parsing(tmp_path, arg, saved, raw, out):
    script = tmp_path / "parse.sh"
    script.write_text(PRELUDE + components_block() + 'echo "$COMPONENTS"\n', encoding="utf-8", newline="\n")
    r = subprocess.run([BASH, str(script), arg], capture_output=True, text=True, timeout=30,
                       env={**os.environ, "SAVED": saved, "RAW_IN": raw})
    if out.startswith("ERR "):
        assert r.returncode == 2 and r.stdout.strip() == out[4:], (r.stdout, r.stderr)
    else:
        assert r.returncode == 0 and r.stdout.strip() == out, (r.stdout, r.stderr)


@pytest.mark.skipif(not BASH, reason="needs bash")
def test_scripts_parse():
    for name in ("install.sh", "update.sh"):
        assert subprocess.run([BASH, "-n", str(ROOT / "deploy" / name)], timeout=30).returncode == 0
