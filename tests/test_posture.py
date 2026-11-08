import re
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient
from test_fingerprint import PW, SCAN_XML, transport

from domin import admin, cve, db, fingerprint, jobs, posture, users
from domin.config import Settings
from domin.web import COOKIE, create_app

DOM = "corp.example"
RECORDS = [{"host": "www.corp.example", "ip": "172.20.4.50"},
           {"host": "mail.corp.example", "ip": "172.20.4.50"},
           {"host": "nas.corp.example", "ip": "172.20.4.60"},
           {"host": "cdn.corp.example", "ip": "203.0.113.9"},
           {"host": "gone.corp.example", "ip": ""}]


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1",),
                cve_db_path=str(tmp_path / "cve.json"))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "ana", "analyst", PW)
        users.create(c, "vee", "viewer", PW)
        db.save_scan(c, DOM, db.now(), "scan", RECORDS)
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["172.20.4.0/24"]})
    return s


@pytest.fixture
def nmap(monkeypatch):
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: SCAN_XML)


def run_queue(settings) -> int:
    cve_db = cve.Database("own", settings.cve_db_file)
    n = 0
    with httpx.Client(transport=transport()) as client:
        while jobs._posture_next(settings, cve_db, client):
            n += 1
    return n


def test_targets_keep_in_scope_addresses_of_the_latest_scan(settings):
    with db.connect(settings.db_path) as c:
        found, skipped = posture.targets(c, DOM)
        assert [t["ip"] for t in found] == ["172.20.4.50", "172.20.4.60"] and skipped == 1   # 203.0.113.9 out
        assert found[0]["hosts"] == ["mail.corp.example", "www.corp.example"]
        one, _ = posture.targets(c, DOM, host="nas.corp.example")
        assert [t["ip"] for t in one] == ["172.20.4.60"]
        users.save_scope(c, {**users.get_scope(c), "ip_deny": ["172.20.4.60/32"]})
        assert [t["ip"] for t in posture.targets(c, DOM)[0]] == ["172.20.4.50"]


def test_enqueue_skips_addresses_already_pending(settings):
    with db.connect(settings.db_path) as c:
        found, _ = posture.targets(c, DOM)
        assert posture.enqueue(c, DOM, found, "22,80", "ana") == 2
        assert posture.enqueue(c, DOM, found, "22,80", "ana") == 0


def test_worker_runs_and_persists_with_params_and_raw_output(settings, nmap):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22,80,9999", "ana")
    assert run_queue(settings) == 2
    with db.connect(settings.db_path) as c:
        rows = posture.current(c, DOM)
        assert {r["status"] for r in rows} == {"done"} and len(rows) == 2
        r = rows[0]
        assert r["open_ports"] == 3 and r["cves"] == 1 and r["high"] == 1 and r["ports"] == "22,80,9999"
        assert r["requested_by"] == "ana" and "<nmaprun>" in r["raw"]
        assert r["services"][0]["findings"][0]["cve"] == "CVE-2024-9999"
        # renew: the finished result stays shown, flagged with the pending scan
        posture.enqueue(c, DOM, posture.targets(c, DOM, ip=r["ip"])[0], "22", "ana")
        again = {x["ip"]: x for x in posture.current(c, DOM)}[r["ip"]]
        assert again["status"] == "done" and again["pending"] == "queued"


def test_scope_change_after_queueing_fails_the_scan(settings, nmap):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["10.0.0.0/8"]})
    run_queue(settings)
    with db.connect(settings.db_path) as c:
        rows = posture.current(c, DOM)
        assert {r["status"] for r in rows} == {"failed"} and "outside the posture scope" in rows[0]["error"]


def test_paused_scans_leave_posture_queued(settings, nmap):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        admin.kv_set(c, "tuning", '{"scans_paused": true}')
    assert run_queue(settings) == 0


def test_restart_fails_running_posture(settings):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        assert posture.claim(c)
        assert posture.fail_running(c) == 1


def test_dropping_a_domain_drops_its_posture(settings):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        assert db.delete_domain(c, DOM)
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 0


def test_nmap_gets_minus_6_for_ipv6(monkeypatch):
    seen = {}

    class P:
        stdout, stderr = SCAN_XML, ""

    def fake(args, **kw):
        seen["args"] = args
        return P()
    monkeypatch.setattr(fingerprint.subprocess, "run", fake)
    fingerprint.run_nmap("2001:db8::5", "22", 10)
    assert seen["args"][1] == "-6"
    fingerprint.run_nmap("172.20.4.50", "22", 10)
    assert "-6" not in seen["args"]


# ---- web ----

def app_client(settings):
    return TestClient(create_app(settings, http=httpx.Client(transport=transport())),
                      base_url="https://testserver", client=("127.0.0.1", 50000))


def sign_in(h, name):
    assert h.post("/admin/login", data={"name": name, "password": PW}, follow_redirects=False).status_code == 303
    assert COOKIE in h.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get("/admin/account").text).group(1)


def test_analyst_queues_a_whole_domain_and_sees_the_result(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM}, follow_redirects=False)
        assert r.status_code == 303 and "posture-queued" in r.headers["location"]
        page = h.get(f"/admin/security?domain={DOM}").text
        assert "172.20.4.50" in page and "queued" in page and "203.0.113.9" not in page
        run_queue(settings)
        page = h.get(f"/admin/security?domain={DOM}").text
    assert "CVE-2024-9999" in page and "Renew" in page and "22/tcp" in page


def test_analyst_scans_one_host(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "host": "nas.corp.example"})
    with db.connect(settings.db_path) as c:
        assert [r["ip"] for r in posture.current(c, DOM)] == ["172.20.4.60"]


def test_viewer_cannot_start_posture(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM})
        assert r.status_code == 403 and "analyst role" in r.text
        assert "Scan / renew" not in h.get(f"/admin/security?domain={DOM}").text


def test_posture_refuses_unknown_domain_and_out_of_scope_host(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": "nope.example"})
        assert r.status_code == 422 and "finished inventory scan" in r.text
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "host": "cdn.corp.example"})
        assert r.status_code == 422 and "outside the posture scope" in r.text
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "ports": "22;id"})
        assert r.status_code == 422 and "Ports" in r.text


def test_posture_needs_csrf(settings):
    with app_client(settings) as h:
        sign_in(h, "ana")
        assert h.post("/admin/security/posture", data={"csrf": "x", "domain": DOM}).status_code == 403
