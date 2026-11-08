import re
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
        page = h.get(f"/d/{DOM}").text
        assert "Security posture" in page and "Raw nmap output" in page and "profile <b>web</b>" in page
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
    assert {"label": "high", "n": 1} in rep["charts"]["sev"] and {"label": "none", "n": 1} in rep["charts"]["worst"]
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
    assert "1 of 2 fixable" in html and "no fix published yet" in html and "Fix available for 1 of 3" in html
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
        order = [page.index(x) for x in ("Scan / renew", "Critical CVEs", "CVEs by severity",
                                         "Findings by address <small>")]
        assert order == sorted(order)
        assert 'id="posture-data"' in page and "CVE-2024-9999" in page
        assert "Vulnerabilities <small>" not in page and "Services &amp; scan details" in page
        assert not [d for d in re.findall(r'<details class="svc posture-detail"[^>]*>', page) if " open" in d]
        dom_page = h.get(f"/d/{DOM}").text
        assert dom_page.index("Security posture") < dom_page.index("Records <small>")
        assert "CVE look-up" in page and "Product (CPE)" in h.get("/admin/security/lookup").text


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
