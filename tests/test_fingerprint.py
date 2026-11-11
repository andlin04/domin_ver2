import re
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from domin import cve, db, fingerprint, users
from domin.config import Settings
from domin.web import COOKIE, create_app

PW = "correct horse battery"

NVD_RESP = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-9999",
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8,
                                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
    "descriptions": [{"lang": "en", "value": "Remote code execution"}]}}]}

SCAN_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="172.20.4.50" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.2p1">
     <cpe>cpe:/a:openbsd:openssh:9.2p1</cpe></service></port>
   <port protocol="tcp" portid="80"><state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.52">
     <cpe>cpe:/a:apache:http_server:2.4.52</cpe></service></port>
   <port protocol="tcp" portid="81"><state state="closed"/></port>
   <port protocol="tcp" portid="9999"><state state="open"/>
    <service name="unknown"/></port>
  </ports>
 </host>
</nmaprun>"""


def transport():
    def handle(req: httpx.Request) -> httpx.Response:
        if "nvd.nist.gov" in req.url.host:
            return httpx.Response(200, json=NVD_RESP)
        if "osv.dev" in req.url.host:
            return httpx.Response(200, json={"vulns": []})
        return httpx.Response(404)
    return httpx.MockTransport(handle)


# ---- helpers ----

def test_valid_target_and_ports():
    assert fingerprint.valid_target("172.20.4.50") and fingerprint.valid_target("host.home.arpa")
    assert not fingerprint.valid_target("10.0.0.1; echo probe") and not fingerprint.valid_target("")
    assert not fingerprint.valid_target("a b") and not fingerprint.valid_target("http://x")
    assert fingerprint.valid_ports("22,80,443") and fingerprint.valid_ports("1-1024")
    assert not fingerprint.valid_ports("22,abc") and not fingerprint.valid_ports("")


def test_resolve_literal_ip():
    name, ips = fingerprint.resolve("172.20.4.50")
    assert name == "172.20.4.50" and ips == ["172.20.4.50"]


def test_parse_cpe_forms():
    assert fingerprint.parse_cpe("cpe:/a:apache:http_server:2.4.52") == {
        "kind": "cpe", "part": "a", "vendor": "apache", "product": "http_server", "version": "2.4.52"}
    assert fingerprint.parse_cpe("cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*") == {
        "kind": "cpe", "part": "o", "vendor": "linux", "product": "linux_kernel", "version": "6.1"}
    assert fingerprint.parse_cpe("cpe:/o:linux:linux_kernel") is None   # no version to match
    assert fingerprint.parse_cpe("not a cpe") is None


# ---- xml + scan ----

def test_parse_xml_keeps_only_open_ports():
    svcs = fingerprint.parse_xml(SCAN_XML)
    ports = [s["port"] for s in svcs]
    assert ports == [22, 80, 9999]   # 81 is closed; sorted
    assert svcs[0]["service"] == "ssh" and svcs[0]["cpes"] == ["cpe:/a:openbsd:openssh:9.2p1"]


def test_scan_matches_cpes_to_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: SCAN_XML)
    cve_db = cve.Database("own", tmp_path / "cve_db.json")
    with httpx.Client(transport=transport()) as c:
        res = fingerprint.scan("172.20.4.50", cve_db=cve_db, client=c, display="host.home.arpa")
    assert res["target"] == "host.home.arpa" and res["error"] == ""
    by_port = {s["port"]: s for s in res["services"]}
    assert by_port[22]["findings"][0]["cve"] == "CVE-2024-9999"   # openssh cpe -> NVD
    assert by_port[80]["matched"] and by_port[80]["findings"]      # apache cpe -> NVD
    assert by_port[9999]["matched"] is False and by_port[9999]["findings"] == []   # no cpe


def test_renamed_cpes_are_looked_up_under_both_names():
    t = fingerprint.parse_cpe("cpe:/a:matt_johnston:dropbear_ssh_server:2018.76")
    assert [(a["vendor"], a["product"]) for a in fingerprint.with_aliases(t)] == [
        ("matt_johnston", "dropbear_ssh_server"), ("dropbear_ssh_project", "dropbear_ssh")]


def test_ports_split_into_chunks_in_their_own_order():
    assert fingerprint.port_chunks("22,80,1-12,22") == ["22,80,1-8", "9-12"]
    assert fingerprint.port_chunks("443") == ["443"]
    assert len(fingerprint.port_chunks("1-1024")) == 103


def test_a_scan_resumes_after_its_last_finished_chunk(tmp_path, monkeypatch):
    ran = []

    def fake(ip, ports, *a, **k):
        ran.append(ports)
        return SCAN_XML if ports == "9-12" else "<nmaprun><host><ports/></host></nmaprun>"
    monkeypatch.setattr(fingerprint, "run_nmap", fake)
    seen = []
    earlier = [{"port": 21, "proto": "tcp", "service": "ftp", "product": "", "version": "", "cpes": []}]
    res = fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "d.json"), client=None,
                           ports="21,80,1-12", resume={"chunks_done": 1, "services": earlier, "raw": "<nmaprun/>"},
                           on_chunk=seen.append)
    assert ran == ["9-12"]   # the first chunk (21,80,1-8) was done before the restart
    assert [s["port"] for s in res["services"]] == [21, 22, 80, 9999]
    assert seen[-1]["chunks"] == 2 and seen[-1]["chunks_done"] == 2 and len(seen[-1]["services"]) == 4
    assert res["raw"].startswith("<nmaprun/>") and "(in 2 runs of up to 10 ports)" in res["params"]


def test_scan_reports_missing_nmap(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError
    monkeypatch.setattr(fingerprint, "run_nmap", boom)
    res = fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "d.json"), client=None)
    assert res["services"] == [] and "not installed" in res["error"]


def test_raw_drop_in_lets_nmap_see_interfaces():
    import pathlib
    text = (pathlib.Path(__file__).parents[1] / "deploy" / "worker-raw.conf").read_text(encoding="utf-8")
    assert "ProcSubset=all" in text and "AF_PACKET" in text and "AmbientCapabilities=CAP_NET_RAW" in text


def test_controls_card_rules_leave_the_scan_dialog_spacing_alone():
    import pathlib
    css = (pathlib.Path(__file__).parents[1] / "domin" / "static" / "app.css").read_text(encoding="utf-8")
    assert ".card.controls .field:not(dialog .field) { margin: 0; }" in css
    assert ".card.controls .field { margin: 0; }" not in css


def test_posture_chart_clicks_add_to_the_filter_and_the_map_is_on_inventory_pages():
    import pathlib
    js = (pathlib.Path(__file__).parents[1] / "domin" / "static" / "app.js").read_text(encoding="utf-8")
    assert js.count("...filterClick") == 2            # fix-by-severity and services bars
    assert "postureMap" not in js and "inventoryMap();" in js and 'getElementById("inv-map")' in js
    assert "--sev-" not in js.split("async function inventoryMap")[1].split("\nfunction ")[0]   # volume scale only
    assert "/all?f_country=" in js and 'data-filter="#records"' in js
    assert "singapore: [103.8, 1.35]" in js and '"türkiye": "turkey"' in js   # small places and spelling variants
    css = (pathlib.Path(__file__).parents[1] / "domin" / "static" / "app.css").read_text(encoding="utf-8")
    assert 'chips.className = "filter-chips"' in js and 'data-chip="all"' in js and ".filter-chips .chip" in css


def test_cut_short_nmap_output_reports_nmaps_error(monkeypatch):
    class Done:
        stdout = '<?xml version="1.0"?>\n<nmaprun scanner="nmap">\n<scaninfo type="syn"/>\n'
        stderr = "Starting Nmap\nexample failure line\n"
    monkeypatch.setattr(fingerprint.subprocess, "run", lambda *a, **k: Done)
    with pytest.raises(fingerprint.NmapError, match="nmap stopped early: example failure line"):
        fingerprint._run(["nmap"], 10)
    Done.stdout = ""
    with pytest.raises(fingerprint.NmapError, match="nmap produced no output: example failure line"):
        fingerprint._run(["nmap"], 10)


def test_a_host_timeout_is_an_incomplete_result_not_no_open_ports(tmp_path, monkeypatch):
    xml = SCAN_XML.replace("<host>", '<host timedout="true">', 1)
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: xml)
    res = fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "d.json"), client=None,
                           timeout=120)
    assert res["error"].startswith("Timed out") and "120 s" in res["error"] and res["note"] == ""
    assert [s["port"] for s in res["services"]] == [22, 80, 9999]   # what it found before the limit is kept
    empty = '<?xml version="1.0"?><nmaprun><host timedout="true"><address addr="172.20.4.50"/></host></nmaprun>'
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: empty)
    res = fingerprint.scan("172.20.4.50", cve_db=cve.Database("own", tmp_path / "d.json"), client=None)
    assert "No open TCP ports" not in res["note"] and res["error"]


# ---- web view ----

@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1",))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "adm", "admin", PW)
        users.create(c, "ana", "analyst", PW)
        users.create(c, "vee", "viewer", PW)
    return s


def app_client(settings):
    return TestClient(create_app(settings, http=httpx.Client(transport=transport())),
                      base_url="https://testserver", client=("127.0.0.1", 50000))


def sign_in(h, name):
    r = h.post("/admin/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    page = h.get("/admin/account")
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def test_admin_runs_host_fingerprint_and_a_power_user_may_not_on_an_address(settings, monkeypatch):
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: SCAN_XML)
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "172.20.4.50"})
    assert r.status_code == 200 and "22/tcp" in r.text and "CVE-2024-9999" in r.text
    with app_client(settings) as h:   # a maintainer of every domain: host names only, no addresses
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "172.20.4.50"})
    assert r.status_code == 403 and "addresses: admins only" in r.text


def test_host_out_of_scope_is_refused(settings):
    with db.connect(settings.db_path) as c:
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["10.0.0.0/8"]})
    with app_client(settings) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "172.20.4.50"})
    assert r.status_code == 403 and "outside the posture scope" in r.text


def test_bad_host_target_is_reported(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "bad target!"})
    assert r.status_code == 422 and "host name or IPv4" in r.text


def test_viewer_cannot_fingerprint(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "172.20.4.50"})
    assert r.status_code == 403 and "maintainer rights" in r.text


def test_no_answer_flags_potentially_blocked_addresses():
    filtered = '<extraports state="filtered" count="10">'
    refused = '<port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/>'
    reset = '<port protocol="tcp" portid="80"><state state="closed" reason="reset"/>'
    opened = '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
    assert fingerprint.no_answer(filtered, routed=False)              # direct: nothing replied
    assert fingerprint.no_answer(refused + refused, routed=True)     # relay: refused = no answer
    assert not fingerprint.no_answer(reset, routed=False)            # direct reset: a live host
    assert not fingerprint.no_answer(refused + opened, routed=True)
    assert not fingerprint.no_answer("", routed=True)                # no nmap output: unknown
    rows = [{"ip": "203.0.113.7", "hosts": "x.example", "status": "done", "services": [], "open_ports": 0, "cves": 0,
             "high": 0, "raw": refused, "params": "nmap ... via Mullvad: mullvad se-x (se, automatic)",
             "finished": "2026-11-09T00:00:00", "created": "2026-11-09T00:00:00", "note": "old note"}]
    from domin import posture
    rep = posture.report(rows)
    assert rep["kpi"]["blocked"] == 1 and rep["rows"][0]["note"] == fingerprint.BLOCKED_NOTE


def test_cves_are_grouped_per_service_worst_first():
    from domin import posture

    def f(cid, sev, score):
        return {"cve": cid, "severity": sev, "score": score, "summary": "", "fixed": []}
    services = [
        {"port": 22, "proto": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.2p1",
         "findings": [f("CVE-2024-0001", "medium", 5.0)]},
        {"port": 80, "proto": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.52",
         "findings": [f("CVE-2024-0002", "low", 2.0), f("CVE-2024-0003", "critical", 9.8)]},
        {"port": 8080, "proto": "tcp", "service": "http", "product": "Apache httpd", "version": "2.4.52",
         "findings": [f("CVE-2024-0003", "critical", 9.8)]}]
    rows = [{"ip": "172.20.4.50", "hosts": "host.home.arpa", "status": "done", "services": services,
             "open_ports": 3, "cves": 3, "high": 1, "raw": "", "params": "nmap", "note": "",
             "finished": "2026-11-09T00:00:00", "created": "2026-11-09T00:00:00"}]
    groups = posture.report(rows)["rows"][0]["by_service"]
    assert [(g["port"], g["worst"]) for g in groups] == [(80, "critical"), (8080, "critical"), (22, "medium")]
    assert [v["cve"] for v in groups[0]["vulns"]] == ["CVE-2024-0003", "CVE-2024-0002"]   # worst first
    assert groups[0]["sev_n"] == {"critical": 1, "low": 1} and groups[0]["product"] == "Apache httpd 2.4.52"
