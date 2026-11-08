"""Settings > Public database: import a copy of the public database, keep this instance's own scans."""
import json
from dataclasses import replace

import pytest
from test_fingerprint import PW
from test_posture import app_client, sign_in

from domin import admin, db, jobs, publicsync, users
from domin.config import Settings

PUB = "public.sync.example"
OWN = "own.sync.example"


def rec(host: str, ip: str) -> dict:
    return {"host": host, "ip": ip, "country": ""}


@pytest.fixture
def pub_copy(tmp_path):
    path = tmp_path / "public.db"
    db.init(path)
    with db.connect(path) as c:
        for n in range(3):
            db.save_scan(c, PUB, f"2026-01-0{n + 1} 10:00:00", "scan", [rec(f"www.{PUB}", f"198.51.100.{n + 1}")])
        db.save_scan(c, "other.sync.example", "2026-01-04 10:00:00", "scan", [rec("a.other.sync.example", "")])
        c.execute("INSERT INTO ip_cache (ip, country, fetched) VALUES ('198.51.100.1', 'SE', '2026-01-01')")
        c.execute("INSERT INTO users (name, role, created) VALUES ('public-user', 'admin', '2026-01-01')")
        jobs.enqueue(c, "queued.sync.example", client="public")
    return path


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "lab" / "t.db", admin_ips=("127.0.0.1",),
                cve_db_path=str(tmp_path / "cve.json"))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "adm", "admin", PW)
        users.create(c, "ana", "analyst", PW)
        sid = db.save_scan(c, OWN, "2026-02-01 10:00:00", "scan", [rec(f"gw.{OWN}", "172.20.4.1")])
        c.execute("INSERT INTO jobs (domain, status, created, scan_id) VALUES (?, 'done', ?, ?)",
                  (OWN, "2026-02-01 10:00:00", sid))
    return s


def counts(c) -> dict:
    return {t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("domains", "scans", "records", "jobs")}


def test_import_replaces_the_inventory_and_keeps_own_scans(settings, pub_copy):
    for _ in range(2):   # a second sync must not duplicate the own scan or bring back the first copy's rows
        with db.connect(settings.db_path) as c:
            info = publicsync.import_public(c, pub_copy)
        assert info["scans"] == 4 and info["own"] == 1
    with db.connect(settings.db_path) as c:
        assert counts(c) == {"domains": 3, "scans": 5, "records": 5, "jobs": 1}
        own = c.execute("SELECT s.id, s.hosts FROM scans s JOIN domains d ON d.id = s.domain_id "
                        "WHERE d.name = ?", (OWN,)).fetchone()
        assert own["id"] == 5 and own["hosts"] == 1
        assert c.execute("SELECT scan_id FROM jobs").fetchone()[0] == 5
        assert c.execute("SELECT host FROM records WHERE scan_id = 5").fetchone()[0] == f"gw.{OWN}"
        assert c.execute("SELECT country FROM ip_cache").fetchone()[0] == "SE"
        # never copied: the public users and queued jobs
        assert [r[0] for r in c.execute("SELECT name FROM users ORDER BY name")] == ["adm", "ana"]
        assert not c.execute("SELECT 1 FROM jobs WHERE status = 'queued'").fetchone()
        new = db.save_scan(c, OWN, "2026-03-01 10:00:00", "scan", [rec(f"gw.{OWN}", "172.20.4.1")])
    with db.connect(settings.db_path) as c:   # scans made after a sync are own scans too
        assert publicsync.import_public(c, pub_copy)["own"] == 2
        assert new == 6 and counts(c)["scans"] == 6


def test_a_bad_copy_leaves_everything_as_it_was(settings, tmp_path):
    bad = tmp_path / "bad.db"
    with db.connect(bad) as c:
        c.execute("CREATE TABLE domains (id INTEGER PRIMARY KEY, name TEXT)")
    with db.connect(settings.db_path) as c:
        before = counts(c)
        with pytest.raises(ValueError):
            publicsync.import_public(c, bad)
        assert counts(c) == before and admin.kv_get(c, publicsync.FLOOR_KEY) is None


def test_sync_button_is_admin_only_and_drops_a_request(settings, pub_copy):
    state = settings.db_path.parent
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        page = h.get("/admin/settings").text
        assert "Public database" in page and "none received yet" in page and ">Sync</button>" in page
        r = h.post("/admin/settings/public-sync", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303 and "sync-requested" in r.headers["location"]
        assert (state / publicsync.REQUEST_FILE).read_text().startswith("requested ")
        assert "Sync running." in h.get("/admin/settings").text
    (state / publicsync.REQUEST_FILE).unlink()
    (state / publicsync.STATUS_FILE).write_text(json.dumps(
        {"at": "2026-11-08 22:00", "ok": True, "message": "Imported.", "copy": "2026-11-08 03:20"}))
    with db.connect(settings.db_path) as c:
        publicsync.import_public(c, pub_copy)
    with app_client(settings) as h:
        sign_in(h, "adm")
        page = h.get("/admin/settings").text
        assert "2026-11-08 03:20" in page and "4 public scans" in page and "1 own scans kept" in page
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        h.post("/admin/settings/public-sync", data={"csrf": csrf}, follow_redirects=False)
        assert not (state / publicsync.REQUEST_FILE).exists()
