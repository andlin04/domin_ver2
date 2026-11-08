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
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
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


def test_analyst_runs_host_fingerprint(settings, monkeypatch):
    monkeypatch.setattr(fingerprint, "run_nmap", lambda *a, **k: SCAN_XML)
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "host", "target": "172.20.4.50"})
    assert r.status_code == 200 and "22/tcp" in r.text and "CVE-2024-9999" in r.text


def test_host_out_of_scope_is_refused(settings):
    with db.connect(settings.db_path) as c:
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["10.0.0.0/8"]})
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
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
    assert r.status_code == 403 and "analyst role" in r.text
