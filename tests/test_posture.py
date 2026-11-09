import json
import re
import time
from dataclasses import replace
from pathlib import Path

import httpx
import jinja2
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


def test_never_scan_rules_skip_matching_hosts(settings):
    recs = [{"host": "autodiscover.corp.example", "ip": "172.20.4.70", "asn": "8075", "netname": "MSFT"},
            {"host": "autodiscover.old.corp.example", "ip": "172.20.4.71", "asn": "18075", "descr": "Own hosting"},
            {"host": "www.corp.example", "ip": "172.20.4.72", "asn": "8075", "netname": "MSFT"},
            {"host": "sip.corp.example", "ip": "172.20.4.72", "asn": "8075", "netname": "MSFT"}]
    ms = "ms.corp.example"
    with db.connect(settings.db_path) as c:
        db.save_scan(c, ms, db.now(), "scan", recs)
        found, skipped = posture.targets(c, ms)   # defaults: Microsoft 365 names at Microsoft
        assert {t["ip"]: t["hosts"] for t in found} == {"172.20.4.71": ["autodiscover.old.corp.example"],
                                                         "172.20.4.72": ["www.corp.example"]} and skipped == 1
        scope = users.parse_scope(c, {"ex_host_0": "WWW.", "ex_owner_0": "", "ex_note_0": "test",
                                      "ex_host_1": "", "ex_owner_1": "", "ex_note_1": "blank row dropped"})
        assert scope["posture_exclude"] == [{"host": "www.", "owner": "", "note": "test"}]
        users.save_scope(c, {**users.get_scope(c), "posture_exclude": scope["posture_exclude"]})
        assert sorted(t["ip"] for t in posture.targets(c, ms)[0]) == ["172.20.4.70", "172.20.4.71", "172.20.4.72"]
        # the Posture domain search finds a domain by its records: ASN as "AS<n>", network name, description
        assert posture.search_domains(c, "AS8075") == [ms] and posture.search_domains(c, "own HOSTING") == [ms]
        assert posture.search_domains(c, "msft autodiscover.old") == [ms] and posture.search_domains(c, "") == []


def test_host_list_shows_last_scan_and_scan_now_queues_ticked_names(settings, nmap):
    with db.connect(settings.db_path) as c:
        before = {h["host"]: h for h in posture.host_list(c, DOM)}
    assert set(before) == {"www.corp.example", "mail.corp.example", "nas.corp.example", "cdn.corp.example"}
    assert all(h["last"] == "" for h in before.values()) and before["www.corp.example"]["ips"] == ["172.20.4.50"]
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        page = h.get(f"/admin/security?domain={DOM}").text
        assert 'id="posture-hosts"' in page and 'data-picked-open="#scan-picked"' in page and 'name="hosts"' in page
        assert page.count(">Never<") == 4
        assert page.count("· out of scope") == 1   # cdn: 203.0.113.9 is outside the IP allow range
        empty = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "hosts": "", "picked": "1"},
                       headers={"Accept": "application/json"})
        assert empty.status_code == 422 and "Tick at least one" in empty.json()["error"]
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "hosts": "nas.corp.example",
                                                     "picked": "1", "profile": "default"},
                   headers={"Accept": "application/json"})
        assert r.status_code == 200 and r.json()["queued"] == 1   # only the ticked name's address
    assert run_queue(settings) == 1
    with db.connect(settings.db_path) as c:
        after = {h["host"]: h for h in posture.host_list(c, DOM)}
    assert after["nas.corp.example"]["last"] and after["www.corp.example"]["last"] == ""
    with app_client(settings) as h:
        sign_in(h, "ana")
        page = h.get(f"/admin/security?domain={DOM}").text
    # one table: results sit on the host rows; the address details wait in the hidden pool for the dialog
    assert 'data-host-details="pa-172-20-4-60"' in page and 'id="pa-pool" hidden' in page
    assert "Findings by address <small>" not in page and 'class="host-toggle"' in page
    assert "data-resizable" in page and '<col style="width:17ch">' in page   # resizable; address column fits one IPv4
    with db.connect(settings.db_path) as c:
        rows = posture.report(posture.current(c, DOM))["rows"]
        merged = {m["host"]: m for m in posture.with_results(posture.host_list(c, DOM), rows)}
    nas = merged["nas.corp.example"]
    assert nas["results"] == 1 and nas["cves"] >= 1 and nas["worst"] and nas["rank"] < 5 and nas["open_ports"] == 3
    assert merged["www.corp.example"]["results"] == 0 and merged["www.corp.example"]["worst"] == ""


def test_enqueue_skips_addresses_already_pending(settings):
    with db.connect(settings.db_path) as c:
        found, _ = posture.targets(c, DOM)
        assert posture.enqueue(c, DOM, found, "22,80", "ana") == 2
        assert posture.enqueue(c, DOM, found, "22,80", "ana") == 0


def test_changes_compare_each_scan_with_the_previous_one(settings):
    def svc(port, product, version, cves=()):
        return {"port": port, "service": "x", "product": product, "version": version,
                "findings": [{"cve": c, "severity": "high", "score": 7.5, "summary": "", "fixed": [],
                              "references": []} for c in cves]}

    def done(at, ports, services, status="done"):
        c.execute("""INSERT INTO posture_scans (domain, ip, hosts, ports, status, created, finished, services)
                     VALUES (?, '172.20.4.50', 'web.home.arpa', ?, ?, ?, ?, ?)""",
                  (DOM, ports, status, at, at, json.dumps(services)))
    with db.connect(settings.db_path) as c:
        assert posture.changes(c, DOM)["compared"] == 0
        done("2026-11-01T10:00:00", "22,80,443", [svc(22, "OpenSSH", "9.2"), svc(80, "nginx", "1.24", ["CVE-1"])])
        done("2026-11-03T10:00:00", "1-1024", [], status="failed")   # a failed (timed-out) scan is not compared
        done("2026-11-05T10:00:00", "22,80,443,8080",
             [svc(80, "nginx", "1.26", ["CVE-2"]), svc(443, "nginx", "1.26"), svc(8080, "jetty", "9")])
        ch = posture.changes(c, DOM, now=posture.datetime(2026, 11, 8))
    kinds = {(x["kind"], x["detail"]) for x in ch["rows"]}
    assert ("opened", "443/tcp nginx 1.26") in kinds and ("closed", "22/tcp OpenSSH 9.2") in kinds
    assert ("version", "80/tcp nginx 1.24 → nginx 1.26") in kinds
    assert ("new-cve", "CVE-2") in kinds and ("gone-cve", "CVE-1") in kinds
    assert not any("8080" in d for _, d in kinds)   # the earlier scan did not cover 8080: not "opened"
    assert ch["kpi"] == {"opened": 1, "closed": 1, "version": 1, "new-cve": 1, "gone-cve": 1}
    assert ch["compared"] == 1 and ch["changed"] == 1
    assert posture.port_set("22,80,100-102") == {22, 80, 100, 101, 102}
    with app_client(settings) as h:
        sign_in(h, "ana")
        page = h.get(f"/admin/security?domain={DOM}").text
        assert "Changes" in page and "Port opened" in page and "nginx 1.24 → nginx 1.26" in page
        assert "−0<" not in page and "+0<" not in page   # a zero count has no sign


def test_posture_slots_above_the_setting_take_no_scans(settings, nmap):
    with db.connect(settings.db_path) as c:
        found, _ = posture.targets(c, DOM)
        posture.enqueue(c, DOM, found, "22,80", "ana")
    cve_db = cve.Database("own", settings.cve_db_file)
    with httpx.Client(transport=transport()) as client:
        assert not jobs._posture_next(settings, cve_db, client, slot=1)   # default: 1 at once
        with db.connect(settings.db_path) as c:
            admin.kv_set(c, "tuning", json.dumps({"posture_parallel": 2}))
        assert jobs._posture_next(settings, cve_db, client, slot=1)
        assert jobs._posture_next(settings, cve_db, client, slot=0)
    assert jobs.POSTURE_SLOTS == 4


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


def test_restart_requeues_running_posture_once(settings):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        first = posture.claim(c)
        assert posture.requeue_running(c) == 1
        again = posture.claim(c)   # back in the queue, same row
        assert again and again["id"] == first["id"] and again["note"] == posture.REQUEUED
        assert posture.requeue_running(c) == 0   # interrupted a second time: fails, no loop
        row = c.execute("SELECT status, error FROM posture_scans WHERE id = ?", (first["id"],)).fetchone()
        assert row["status"] == "failed" and row["error"] == "worker restarted twice"


def test_a_requeued_scan_that_made_progress_can_be_requeued_again(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "1-25", "ana")
        row = posture.claim(c)
        assert posture.requeue_running(c) == 1
        row = posture.claim(c)
        calls = []

        def fake(ip, ports, *a, **k):   # the worker dies in the second chunk
            calls.append(ports)
            if len(calls) == 2:
                raise KeyboardInterrupt
            return SCAN_XML
        monkeypatch.setattr(fingerprint, "run_nmap", fake)
        with pytest.raises(KeyboardInterrupt):
            posture.run(c, row, cve.Database("own", settings.cve_db_file), None)
        saved = c.execute("SELECT chunks, chunks_done, note FROM posture_scans WHERE id = ?", (row["id"],)).fetchone()
        assert (saved["chunks"], saved["chunks_done"], saved["note"]) == (3, 1, "")
        assert posture.requeue_running(c) == 1   # progress since the last requeue: back in the queue
        monkeypatch.setattr(fingerprint, "run_nmap", lambda ip, ports, *a, **k: calls.append(ports) or SCAN_XML)
        posture.run(c, posture.claim(c), cve.Database("own", settings.cve_db_file), None)
        assert calls == ["1-10", "11-20", "11-20", "21-25"]   # resumed at the chunk that was interrupted
        assert c.execute("SELECT status FROM posture_scans WHERE id = ?", (row["id"],)).fetchone()[0] == "done"


def test_refresh_fixes_fills_in_fixed_versions_without_changing_the_cves(settings, tmp_path):
    finding = {"cve": "CVE-2026-0002", "severity": "high", "score": 7.5, "fixed": None, "summary": "x",
               "url": "", "source": "NVD"}
    svc = {"port": 80, "proto": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.66",
           "cpes": ["cpe:/a:apache:http_server:2.4.66"], "matched": True, "findings": [finding]}
    cache = tmp_path / "cve.json"
    key = cve.target_key({"kind": "cpe", "part": "a", "vendor": "apache", "product": "http_server",
                          "version": "2.4.66"})
    newer = [{**finding, "fixed": "2.4.67"}, {**finding, "cve": "CVE-2026-0003", "fixed": "2.4.68"}]
    cache.write_text(json.dumps({key: {"fetched": int(time.time()), "format": cve.FORMAT, "findings": newer}}),
                     encoding="utf-8")
    with db.connect(settings.db_path) as c:
        c.execute("""INSERT INTO posture_scans (domain, ip, ports, status, created, services, cves)
                     VALUES (?, '192.0.2.10', '80', 'done', '2026-11-08T22:00:00', ?, 1)""", (DOM, json.dumps([svc])))
        assert posture.refresh_fixes(c, cve.Database("own", cache), None) == {"scans": 1, "findings": 1}
        stored = json.loads(c.execute("SELECT services FROM posture_scans").fetchone()[0])
    assert [f["cve"] for f in stored[0]["findings"]] == ["CVE-2026-0002"]   # no CVE added
    assert stored[0]["findings"][0]["fixed"] == "2.4.67"


def test_daily_cve_refresh_rematches_the_latest_scan_only(settings, nmap, monkeypatch):
    with db.connect(settings.db_path) as c:
        for _ in range(2):
            posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
            c.commit()
            assert run_queue(settings) >= 1
        ids = [r[0] for r in c.execute("SELECT id FROM posture_scans ORDER BY id")]
        empty = json.dumps([{**s, "findings": []} for s in json.loads(
            c.execute("SELECT services FROM posture_scans WHERE id = ?", (ids[0],)).fetchone()[0])])
        c.execute("UPDATE posture_scans SET services = ?, cves = 0", (empty,))   # as if scanned before the CVE
    monkeypatch.setattr(jobs.tools, "http_client", lambda *a, **k: httpx.Client(transport=transport()))
    res = jobs.cve_refresh(settings, now=1e9)
    again = jobs.cve_refresh(settings, now=1e9 + 3600)
    half = len(ids) // 2   # two runs over the same addresses
    assert res == {"scans": half, "changed": half} and again is None   # the latest per address; once a day
    with db.connect(settings.db_path) as c:
        cves = dict(c.execute("SELECT id, cves FROM posture_scans").fetchall())
    assert all(cves[i] == 0 for i in ids[:half]) and all(cves[i] > 0 for i in ids[half:])   # older: as of their day


def test_dropping_a_domain_drops_its_posture(settings):
    with db.connect(settings.db_path) as c:
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana")
        assert db.delete_domain(c, DOM)
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 0


def test_renamed_cpe_vendor_is_looked_up_under_both_names(tmp_path, monkeypatch):
    xml = SCAN_XML.replace("cpe:/a:apache:http_server:2.4.52", "cpe:/a:igor_sysoev:nginx:1.24.0")
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: xml)
    asked = []

    def handle(req: httpx.Request) -> httpx.Response:
        asked.append(req.url.params.get("virtualMatchString", ""))
        return httpx.Response(200, json={"vulnerabilities": []})
    with httpx.Client(transport=httpx.MockTransport(handle)) as c:
        fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "d.json"), client=c)
    assert any(":igor_sysoev:nginx:" in a for a in asked) and any(":f5:nginx:1.24.0" in a for a in asked)


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
        assert "172.20.4.50" in page and "queued" in page and 'id="pa-203-0-113-9"' not in page
        assert "out of scope" in page   # the host list still names it, marked
        run_queue(settings)
        page = h.get(f"/admin/security?domain={DOM}").text
    assert "CVE-2024-9999" in page and "Renew" in page and "22/tcp" in page
    # CVEs tab: one row per CVE with the addresses it hits; an address opens its host row
    assert 'data-tab="cves">CVEs <small>1</small>' in page and 'data-panel="cves" hidden' in page
    table = page.split('id="posture-cves"')[1].split("</table>")[0]
    assert "data-colfilters" in table and 'data-filter="#posture-cves"' in page
    assert '<td class="mono" title=' in table and "CVE-2024-9999" in table
    assert '<a href="#pa-172-20-4-50" data-open-details title="172.20.4.50">' in table
    assert 'id="pa-172-20-4-50"' in page and 'id="cve-findings"' not in page
    # domain search: any attribute, any case, every word must match; signed-in only
    assert 'data-domain-search="/admin/security/domain-search"' in page and 'class="field pick-filter">Filter' in page
    # the Filter box also narrows the host and CVE rows: each carries its lower-case text
    host_row = re.search(r'<tr data-text="([^"]*)">\s*<td class="tick"><input type="checkbox" data-pick value="www.lab', page)
    assert host_row and "openssh" in host_row.group(1) and "cve-2024-9999" in host_row.group(1)
    assert "22/tcp" in host_row.group(1) and "172.20.4.50" in host_row.group(1)
    assert re.search(r'<tr data-text="cve-2024-9999 [^"]*172\.20\.4\.50', page)
    with app_client(settings) as h:
        assert h.get("/admin/security/domain-search?q=lab").status_code == 401
        sign_in(h, "ana")
        for q in ("WWW.LAB", "172.20.4.50", "cve-2024-9999", "openssh", f"{DOM} cve-2024", "50%"):
            hit = h.get("/admin/security/domain-search", params={"q": q}).json()["domains"]
            assert hit == ([DOM] if q != "50%" else []), q
        assert h.get("/admin/security/domain-search", params={"q": "www no-such-word"}).json()["domains"] == []


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
        assert "data-scan-open" not in h.get(f"/admin/security?domain={DOM}").text


def test_posture_refuses_unknown_domain_and_out_of_scope_host(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": "nope.example"})
        assert r.status_code == 422 and "finished inventory scan" in r.text
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "host": "cdn.corp.example"})
        assert r.status_code == 422 and "outside the posture scope" in r.text
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "ports": "22;id"})
        assert r.status_code == 422 and "Ports" in r.text


JSON = {"Accept": "application/json"}
STATUS = "/admin/security/posture/status"


def test_json_post_returns_the_batch_and_status_follows_it(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM}, headers=JSON)
        assert r.status_code == 200
        batch = r.json()["batch"]
        assert len(batch) == 2 and r.json()["queued"] == 2
        ids = ",".join(map(str, batch))
        d = h.get(f"{STATUS}?ids={ids}").json()
        assert (d["total"], d["queued"], d["done"], d["finished"]) == (2, 2, 0, False)
        assert {i["ip"] for i in d["items"]} == {"172.20.4.50", "172.20.4.60"}
        # asking again while they wait: the same rows, nothing new queued
        again = h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM}, headers=JSON).json()
        assert sorted(again["batch"]) == sorted(batch) and again["queued"] == 0
        assert sorted(h.get(f"{STATUS}?pending=1&domain={DOM}").json()["ids"]) == sorted(batch)
        run_queue(settings)
        d = h.get(f"{STATUS}?ids={ids}").json()
        assert (d["total"], d["done"], d["queued"], d["running"], d["finished"]) == (2, 2, 0, 0, True)
        assert d["current"] == [] and d["elapsed"] >= 0
        item = d["items"][0]
        assert item["status"] == "done" and item["worst"] == "critical" and item["cves"] == 1 and item["host"]
        assert h.get(f"{STATUS}?pending=1&domain={DOM}").json()["total"] == 0
        r = h.post("/admin/security/posture", data={"csrf": csrf, "domain": "nope.example"}, headers=JSON)
        assert r.status_code == 422 and "finished inventory scan" in r.json()["error"]


def test_status_needs_sign_in_and_viewer_may_read(settings):
    with db.connect(settings.db_path) as c:
        batch: list[int] = []
        posture.enqueue(c, DOM, posture.targets(c, DOM)[0], "22", "ana", batch)
    ids = ",".join(map(str, batch))
    with app_client(settings) as h:
        assert h.get(f"{STATUS}?ids={ids}", follow_redirects=False).status_code == 401
        sign_in(h, "vee")
        assert h.get(f"{STATUS}?ids={ids}").json()["total"] == 2
        assert h.get(f"{STATUS}?ids=x,,9999").json()["total"] == 0


def test_posture_page_has_progress_dialog_and_no_auto_reload(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        page = h.get(f"/admin/security?domain={DOM}").text
        assert 'id="posture-progress"' in page and "data-posture-run" in page and "data-pp-reopen hidden" in page
        h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM})
        page = h.get(f"/admin/security?domain={DOM}").text
        assert "data-pp-reopen>" in page and "show progress" in page
        dom_page = h.get(f"/d/{DOM}").text
    for html in (page, dom_page):
        assert 'id="posture-progress"' in html
        assert "http-equiv" not in html.lower() and "reload the page to see progress" not in html


def test_posture_needs_csrf(settings):
    with app_client(settings) as h:
        sign_in(h, "ana")
        assert h.post("/admin/security/posture", data={"csrf": "x", "domain": DOM}).status_code == 403


# ---- scan profiles, saved parameters, raw output ----

def test_nmap_args_carry_profile_knobs():
    a = fingerprint.nmap_args("172.20.4.50", "22,80", 60, intensity=7, timing=2)
    assert a[a.index("--version-intensity") + 1] == "7" and "-T2" in a and "60s" in a


def test_default_profile_is_seeded_and_kept(settings):
    with db.connect(settings.db_path) as c:
        assert posture.profile(c, "default")["ports"] == fingerprint.DEFAULT_PORTS
        assert posture.delete_profile(c, "default") is False


def test_check_profile_rejects_bad_input():
    assert posture.check_profile("web", "80,443", 5, 3, 60)[0]
    assert not posture.check_profile("Bad Name", "80", 2, 3, 60)[0]
    assert not posture.check_profile("web", "80;id", 2, 3, 60)[0]
    assert not posture.check_profile("web", "80", 12, 3, 60)[0]
    assert not posture.check_profile("web", "80", 2, 5, 60)[0]


def test_analyst_makes_a_profile_and_scans_with_it(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/profiles", data={"csrf": csrf, "name": "web", "ports": "80,443",
                   "intensity": "5", "timing": "4", "timeout": "60", "note": "web only"}, follow_redirects=False)
        assert r.status_code == 303
        assert "web only" in h.get("/admin/security/profiles").text
        h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM, "profile": "web"})
        run_queue(settings)
        with db.connect(settings.db_path) as c:
            rows = posture.current(c, DOM)
        assert rows and all(p["profile"] == "web" and p["ports"] == "80,443" and p["intensity"] == 5 for p in rows)
        assert all("--version-intensity 5" in p["params"] and "-T4" in p["params"] for p in rows)
        page = h.get(f"/admin/security?domain={DOM}").text   # the domain page shows a summary only
        assert "Raw nmap output" in page and "profile <b>web</b>" in page
        r = h.post("/admin/security/profiles/web/delete", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303 and "web only" not in h.get("/admin/security/profiles").text


def test_viewer_cannot_change_profiles_and_anonymous_sees_no_posture(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        r = h.post("/admin/security/profiles", data={"csrf": csrf, "name": "x", "ports": "80", "intensity": "2",
                   "timing": "3", "timeout": "60"})
        assert r.status_code == 403
    with app_client(settings) as h:
        assert "Security posture" not in h.get(f"/d/{DOM}").text


# ---- host tags ----

def test_suggest_from_name_and_services():
    from domin import tags
    assert tags.suggest("cam-01.corp.example") == ["iot-device"]
    assert tags.suggest("www.example.org") == ["webserver"]
    assert tags.suggest("box.example.org", [{"port": 22, "service": "ssh"}, {"port": 443, "service": "https"},
                                            {"port": 1883, "service": "mqtt"}]) == ["iot-device", "webserver"]
    assert tags.suggest("box.example.org") == []
    assert tags.valid("iot-device") and not tags.valid("Bad Tag") and not tags.valid("x;y")


def test_analyst_tags_hosts_and_groups_by_tag(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        page = h.get(f"/d/{DOM}").text
        assert "+ storage" in page   # nas.corp.example: name rule suggestion
        r = h.post("/admin/tags", data={"csrf": csrf, "domain": DOM, "host": "nas.corp.example", "tag": "storage"},
                   follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith(f"/d/{DOM}")
        page = h.get(f"/d/{DOM}?tag=storage").text
        assert "Group by tag" in page and "nas.corp.example" in page and "cdn.corp.example" not in page
        h.post("/admin/tags", data={"csrf": csrf, "domain": DOM, "host": "nas.corp.example", "tag": "storage",
                                    "action": "remove"})
        assert "Group by tag" not in h.get(f"/d/{DOM}").text
        assert h.post("/admin/tags", data={"csrf": csrf, "domain": DOM, "host": "other.example", "tag": "x"}
                      ).status_code == 404
        assert h.post("/admin/tags", data={"csrf": csrf, "domain": DOM, "host": "nas.corp.example",
                                           "tag": "Bad Tag"}).status_code == 422
        assert h.post("/admin/tags", data={"csrf": "x", "domain": DOM, "host": "nas.corp.example",
                                           "tag": "y"}).status_code == 403


def test_viewer_sees_tags_but_cannot_change_them(settings):
    with db.connect(settings.db_path) as c:
        from domin import tags
        tags.add(c, "nas.corp.example", "storage", "ana")
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        page = h.get(f"/d/{DOM}").text
        assert "storage" in page and "Remove tag" not in page and "+ storage" not in page
        assert h.post("/admin/tags", data={"csrf": csrf, "domain": DOM, "host": "nas.corp.example",
                                           "tag": "y"}).status_code == 403
    with app_client(settings) as h:
        assert "Group by tag" not in h.get(f"/d/{DOM}").text and ">storage<" not in h.get(f"/d/{DOM}").text


def test_dropping_a_domain_drops_its_host_tags(settings):
    from domin import tags
    with db.connect(settings.db_path) as c:
        tags.add(c, "nas.corp.example", "storage", "ana")
        tags.add(c, "www.other.example", "webserver", "ana")
        assert db.delete_domain(c, DOM)
        assert tags.for_hosts(c, ["nas.corp.example", "www.other.example"]) == {"www.other.example": ["webserver"]}


# ---- posture report layout, look-up page, notice ----

def test_report_summarises_worst_first():
    rows = [{"ip": "172.20.4.60", "hosts": "nas.corp.example", "status": "done", "high": 0, "cves": 0,
             "open_ports": 1, "finished": "2000-01-01T00:00:00", "pending": None,
             "services": [{"port": 22, "service": "ssh", "findings": []}]},
            {"ip": "172.20.4.50", "hosts": "www.corp.example", "status": "done", "high": 1, "cves": 1,
             "open_ports": 1, "finished": "2999-01-01T00:00:00", "pending": None,
             "services": [{"port": 80, "service": "http", "product": "nginx", "version": "1.24.0",
                           "findings": [{"cve": "CVE-2024-9999", "severity": "high", "score": 7.5, "summary": "x",
                                         "url": "u", "fixed": "1.25"}]}]}]
    rep = posture.report(rows)
    assert [r["ip"] for r in rep["rows"]] == ["172.20.4.50", "172.20.4.60"]
    assert rep["kpi"]["high"] == 1 and rep["kpi"]["exposed"] == 1 and rep["kpi"]["stale"] == 1
    assert rep["vulns"][0]["targets"] == [("172.20.4.50", "www.corp.example", 80)]
    assert rep["vulns"][0]["products"] == ["nginx 1.24.0"]
    assert rep["charts"]["fix"] == [{"label": "high", "fix": 1, "nofix": 0}]
    assert rep["vulns"][0]["addresses"] == [("172.20.4.50", "www.corp.example")]
    assert [r["ip"] for r in posture.report(rows, host="nas.corp.example")["rows"]] == ["172.20.4.60"]


def report_rows():
    def f(cve_id, sev, score, fixed):
        return {"cve": cve_id, "severity": sev, "score": score, "summary": f"Made-up flaw {cve_id} in the parser.",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "fixed": fixed}
    return [{"ip": "172.20.4.60", "hosts": "nas.corp.example", "status": "done", "high": 0, "cves": 1,
             "open_ports": 1, "finished": "2999-01-01T00:00:00", "pending": None, "domain": DOM,
             "services": [{"port": 22, "proto": "tcp", "service": "ssh", "product": "fakessh", "version": "1.0",
                           "matched": True, "findings": [f("CVE-2099-0003", "medium", 5.0, None)]}]},
            {"ip": "172.20.4.50", "hosts": "www.corp.example", "status": "done", "high": 1, "cves": 2,
             "open_ports": 1, "finished": "2999-01-01T00:00:00", "pending": None, "domain": DOM,
             "services": [{"port": 443, "proto": "tcp", "service": "https", "product": "fakehttpd", "version": "2.0",
                           "matched": True, "findings": [f("CVE-2099-0001", "critical", 9.8, "2.1 / 3.0.1"),
                                                         f("GHSA-fake-0002", "low", 2.0, None)]}]}]


def test_report_rows_carry_their_cves_with_fix_counts():
    rep = posture.report(report_rows())
    www, nas = rep["rows"]
    assert www["ip"] == "172.20.4.50" and [v["cve"] for v in www["vulns"]] == ["CVE-2099-0001", "GHSA-fake-0002"]
    assert www["vulns"][0]["fixes"] == ["2.1", "3.0.1"] and www["vulns"][1]["fixes"] == []
    assert www["fixable"] == 1 and www["sev_n"] == {"critical": 1, "low": 1} and nas["fixable"] == 0
    assert www["vulns"][0]["where"] == [("fakehttpd 2.0", 443, "tcp")]
    assert www["vulns"][1]["links"][0] == ("OSV", "https://osv.dev/vulnerability/GHSA-fake-0002")
    assert rep["kpi"]["fixable"] == 1 and rep["kpi"]["cves"] == 3


def test_report_renders_collapsed_host_headlines_with_nested_cves():
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(Path(posture.__file__).parent / "templates"),
                             autoescape=True)
    html = env.get_template("_posture_report.html").render(rep=posture.report(report_rows()), can_run=True,
                                                           renew_base="/admin", csrf="t", show_domain=False)
    heads = re.findall(r'<details class="svc posture-detail"[^>]*>', html)
    assert len(heads) == 2 and not [d for d in re.findall(r"<details[^>]*>", html) if " open" in d]
    assert html.index('id="pa-172-20-4-50"') < html.index('id="pa-172-20-4-60"')  # worst host first
    assert "1 of 2 fixable" in html and "no fix published yet" in html
    assert re.search(r"Fix available</span><b>1 <i>of 3 CVEs", html)
    # trends first, then the charts of the current state, then the findings
    order = [html.index(x) for x in ('id="pc-trend"', 'id="pc-surface"', 'id="pc-fix"', 'id="pc-services"',
                                     "Findings by address <small>")]
    assert order == sorted(order) and "<script>" not in html
    assert 'id="pc-hosts"' not in html and 'id="pc-age"' not in html and 'id="posture-domains"' not in html
    assert re.search(r'<details class="cve-item">\s*<summary class="cve-head">\s*<b class="mono">CVE-2099-0001', html)
    assert "Made-up flaw CVE-2099-0001 in the parser." in html and "fix: 2 versions" in html
    assert "2.1, 3.0.1" in html and "no fix yet" in html
    assert "https://nvd.nist.gov/vuln/detail/CVE-2099-0001" in html and "Services &amp; scan details" in html
    assert html.index("CVE-2099-0001") < html.index("Services &amp; scan details")


def test_posture_page_puts_summary_and_vulnerabilities_first(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM})
        run_queue(settings)
        page = h.get(f"/admin/security?domain={DOM}").text
        order = [page.index(x) for x in ("data-scan-open", "Authorized use only", "Critical CVEs", 'id="pc-trend"',
                                         'id="posture-hosts"', 'id="posture-cves"')]   # host table = findings list
        assert order == sorted(order)
        assert 'id="posture-data"' in page and "CVE-2024-9999" in page
        assert "Vulnerabilities <small>" not in page and "Services &amp; scan details" in page
        assert not [d for d in re.findall(r'<details class="svc posture-detail"[^>]*>', page) if " open" in d]
        # viewing one host doesn't narrow the next scan: the form starts at the whole domain
        one = h.get(f"/admin/security?domain={DOM}&host=nas.corp.example").text
        form = one.split("data-scan-target>")[1].split("</select>")[0]
        assert "selected" not in form and "<b data-scan-what>the whole domain</b>" in one
        # the button just says Scan; the profile is picked in its confirm dialog, inside the same form
        run = one.split("data-posture-run>")[1].split("</form>")[0]
        assert '>Scan</button>' in run and 'name="profile"' in run.split('id="scan-confirm"')[1]
        # one host: its row only, opened on load
        rows = one.split('id="posture-hosts"')[1].split("</table>")[0]
        assert rows.count('<td class="tick">') == 1 and "data-auto-open" in rows and "nas.corp.example" in rows
        # all domains: one row per domain, no per-address lists
        every = h.get("/admin/security").text
        doms = every.split('id="posture-domains"')[1].split("</table>")[0]
        assert f'href="/admin/security?domain={DOM}">{DOM}</a>' in doms and doms.count("<tr") == 2   # head + 1
        assert f'<tr data-domain="{DOM}">' in doms
        assert 'id="posture-hosts"' not in every and 'class="svc posture-detail"' not in every
        # the domain page: a summary card, the details stay in Posture
        dom_page = h.get(f"/d/{DOM}").text
        assert dom_page.index("Security posture") < dom_page.index("Records <small>")
        assert 'id="pc-trend"' in dom_page and 'class="svc posture-detail"' not in dom_page
        assert 'id="posture-cves"' not in dom_page and "Open in Posture" in dom_page
        assert "CVE look-up" not in page and 'aria-label="Settings sections"' not in page   # moved under Settings
        look = h.get("/admin/security/lookup").text
        assert "Product (CPE)" in look and 'aria-label="Settings sections"' in look
        # an analyst's Settings opens Scan profiles; General and Routes stay admin-only
        assert '<a href="/admin/security/profiles" class="active" aria-current="page">Settings</a>' in look
        # Operations and Settings sit in the nav's Admin menu, which is marked active on their pages
        menu = look.split("data-nav-menu>")[1].split("</details>")[0]
        assert '<summary class="active">Admin</summary>' in menu and ">Operations</a>" in menu and ">Settings</a>" in menu
        assert '<summary >Admin</summary>' in page and page.index('href="/admin/security"') < page.index("data-nav-menu")
        assert ">General</a>" not in look and ">Routes</a>" not in look


def test_authorised_use_notice_can_be_dismissed_for_good(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        assert "Authorized use only" in h.get("/admin/security").text
        assert h.post("/admin/security/dismiss-notice", data={"csrf": "x"}).status_code == 403
        r = h.post("/admin/security/dismiss-notice", data={"csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
        assert "Authorized use only" not in h.get("/admin/security").text
    with app_client(settings) as h:   # a new session of the same user: still gone; another user still sees it
        sign_in(h, "vee")
        assert "Authorized use only" not in h.get("/admin/security").text
    with app_client(settings) as h:
        sign_in(h, "ana")
        assert "Authorized use only" in h.get("/admin/security").text


# ---- report charts: data shape, empty cases, trend ----

def test_report_chart_data_shape():
    ch = posture.report(report_rows())["charts"]
    assert ch["fix"] == [{"label": "critical", "fix": 1, "nofix": 0}, {"label": "medium", "fix": 0, "nofix": 1},
                         {"label": "low", "fix": 0, "nofix": 1}]
    assert ch["services"][0]["n"] == 1


def test_report_charts_are_empty_without_data():
    assert posture.report([])["charts"] == {"fix": [], "services": []}
    clean = [{"ip": "172.20.4.60", "hosts": "nas.corp.example", "status": "failed", "high": 0, "cves": 0,
              "open_ports": 0, "finished": "2999-01-01T00:00:00", "pending": None, "services": []}]
    assert posture.report(clean)["charts"] == {"fix": [], "services": []}


def test_domain_summary_is_one_row_per_domain_worst_first():
    other = {**report_rows()[0], "ip": "172.20.4.70", "domain": "b.corp.example", "finished": "2999-01-02T08:30:00"}
    rows = posture.report([*report_rows(), other])["rows"]
    a, b = posture.domain_summary(rows)
    assert (a["domain"], a["worst"], a["cves"], a["fixable"], a["addresses"], a["exposed"]) == (DOM, "critical", 3, 1, 2, 1)
    assert a["sev_n"] == {"critical": 1, "medium": 1, "low": 1} and a["last"] == "2999-01-01 00:00"
    assert (b["domain"], b["worst"], b["cves"], b["addresses"], b["last"]) == ("b.corp.example", "medium", 1, 1,
                                                                                "2999-01-02 08:30")


def add_done(c, ip, day, findings, hosts="www.corp.example"):
    services = [{"port": 443, "service": "https", "findings": [{"cve": cid, "severity": sev} for cid, sev in findings]}]
    c.execute("""INSERT INTO posture_scans (domain, ip, hosts, ports, status, created, finished, services)
                 VALUES (?, ?, ?, '443', 'done', ?, ?, ?)""", (DOM, ip, hosts, day, day, json.dumps(services)))


def test_trend_counts_severities_ports_and_addresses_per_scan_day(settings):
    with db.connect(settings.db_path) as c:
        add_done(c, "172.20.4.50", "2026-10-01T10:00:00", [("CVE-2099-0001", "critical"), ("CVE-2099-0002", "high")])
        assert posture.trend(c, DOM) == []                                    # one day: no trend yet
        add_done(c, "172.20.4.60", "2026-10-01T11:00:00", [("CVE-2099-0002", "high")], hosts="nas.corp.example")
        add_done(c, "172.20.4.50", "2026-10-05T10:00:00", [("CVE-2099-0002", "high")])   # critical patched
        c.execute("""INSERT INTO posture_scans (domain, ip, ports, status, created, finished)
                     VALUES (?, '172.20.4.60', '443', 'failed', '2026-10-06', '2026-10-06T00:00:00')""", (DOM,))
        day = {"medium": 0, "low": 0, "ports": 2, "addresses": 2}
        assert posture.trend(c, DOM) == [{"day": "2026-10-01", "critical": 1, "high": 1, **day},
                                         {"day": "2026-10-05", "critical": 0, "high": 1, **day}]
        assert posture.trend(c, "other.example") == []
        assert [t["critical"] for t in posture.trend(c, DOM, host="www.corp.example")] == [1, 0]
        assert posture.trend(c, DOM, host="nas.corp.example") == []          # its only scan day


def test_posture_page_carries_trend_data(settings):
    with db.connect(settings.db_path) as c:
        add_done(c, "172.20.4.50", "2026-10-01T10:00:00", [("CVE-2099-0001", "critical")])
        add_done(c, "172.20.4.50", "2026-10-02T10:00:00", [])
    with app_client(settings) as h:
        sign_in(h, "vee")
        for url in (f"/admin/security?domain={DOM}", f"/d/{DOM}"):
            raw = re.search(r'id="posture-data">(.*?)</script>', h.get(url).text).group(1)
            data = json.loads(raw)
            assert [t["critical"] for t in data["trend"]] == [1, 0]


def test_report_on_ticked_hosts_as_markdown_and_pdf(settings, nmap):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        h.post("/admin/security/posture", data={"csrf": csrf, "domain": DOM})
        run_queue(settings)
        page = h.get(f"/admin/security?domain={DOM}").text
        assert 'data-picked-open="#report-picked"' in page and 'action="/admin/security/report"' in page
        form = {"csrf": csrf, "domain": DOM, "hosts": "nas.corp.example,www.corp.example,other.example"}
        md = h.post("/admin/security/report", data={**form, "format": "md"})
        assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
        assert f'filename="posture-report-{DOM}-' in md.headers["content-disposition"]
        text = md.text
        for part in ("# Security posture report: corp.example", "## 1. Executive summary", "Overall risk:",
                     "## 2. Recommendations", "## 3. Top risks", "## 4. Hosts", "## 5. Technical findings",
                     "## 6. Scope and method", "CVE-2024-9999"):
            assert part in text, part
        assert "| nas.corp.example |" in text and "| www.corp.example |" in text
        assert "mail.corp.example |" not in text.split("## 4. Hosts")[1].split("## 5.")[0]   # not ticked
        pdf = h.post("/admin/security/report", data={**form, "format": "pdf"})
        assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
        assert pdf.content.startswith(b"%PDF") and len(pdf.content) > 2000
        assert h.post("/admin/security/report", data={**form, "hosts": ""}).status_code == 422
        assert h.post("/admin/security/report", data={**form, "hosts": "other.example"}).status_code == 422
    with app_client(settings) as h:   # viewers may export what they can see
        csrf = sign_in(h, "vee")
        page = h.get(f"/admin/security?domain={DOM}").text
        assert 'data-picked-open="#report-picked"' in page and 'data-picked-open="#scan-picked"' not in page
        assert h.post("/admin/security/report", data={**form, "csrf": csrf, "format": "md"}).status_code == 200


def test_report_on_ticked_domains(settings, nmap):
    other = "corp2.example"
    with db.connect(settings.db_path) as c:
        db.save_scan(c, other, db.now(), "scan", [{"host": "web.corp2.example", "ip": "172.20.4.80"}])
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        for d in (DOM, other):
            h.post("/admin/security/posture", data={"csrf": csrf, "domain": d})
        run_queue(settings)
        page = h.get("/admin/security").text
        assert 'data-picked-open="#report-domains"' in page and 'name="domains"' in page
        assert f'<input type="checkbox" data-pick value="{DOM}"' in page
        md = h.post("/admin/security/report", data={"csrf": csrf, "domains": f"{DOM},{other},nope.example",
                                                     "format": "md"})
        assert md.status_code == 200 and "# Security posture report: 2 domains" in md.text
        assert "## 4. Domains" in md.text and "## 5. Hosts" in md.text and "## 7. Scope and method" in md.text
        assert md.headers["content-type"] == "text/markdown; charset=utf-8" and "by ana · scans" in md.text
        assert f"| {DOM} |" in md.text and f"| {other} |" in md.text and "| web.corp2.example |" in md.text
        pdf = h.post("/admin/security/report", data={"csrf": csrf, "domains": f"{DOM},{other}", "format": "pdf"})
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        assert h.post("/admin/security/report", data={"csrf": csrf, "domains": "nope.example"}).status_code == 422
