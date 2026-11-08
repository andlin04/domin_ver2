import json
import re
import time
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from domin import cve, db, users
from domin.config import Settings
from domin.web import COOKIE, create_app

PW = "correct horse battery"
CRIT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

OSV_RESP = {"vulns": [{
    "id": "GHSA-abcd", "aliases": ["CVE-2024-0001"],
    "severity": [{"type": "CVSS_V3", "score": CRIT_VECTOR}],
    "affected": [{"package": {"ecosystem": "PyPI", "name": "foo"},
                  "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}],
    "summary": "A bad bug in foo"}]}

NVD_RESP = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-9999",
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
    "descriptions": [{"lang": "en", "value": "Remote code execution"}]}}]}


def transport(osv=OSV_RESP, nvd=NVD_RESP):
    def handle(req: httpx.Request) -> httpx.Response:
        if "osv.dev" in req.url.host:
            return httpx.Response(200, json=osv)
        if "nvd.nist.gov" in req.url.host:
            return httpx.Response(200, json=nvd)
        return httpx.Response(404)
    return httpx.MockTransport(handle)


def client_with(transport):
    return httpx.Client(transport=transport)


# ---- scoring ----

def test_cvss3_score_and_band():
    assert cve.cvss3_score(CRIT_VECTOR) == 9.8
    assert cve.band(9.8) == "critical" and cve.band(7.0) == "high"
    assert cve.band(4.0) == "medium" and cve.band(1.0) == "low" and cve.band(None) == "unknown"
    assert cve.cvss3_score("not a vector") is None


# ---- source queries ----

def test_osv_cves_parses_cve_severity_and_fix():
    with client_with(transport()) as c:
        found = cve.osv_cves(c, "PyPI", "foo", "1.0.0")
    assert len(found) == 1
    f = found[0]
    assert f["cve"] == "CVE-2024-0001" and f["severity"] == "critical" and f["score"] == 9.8
    assert f["fixed"] == "1.2.3" and f["source"] == "OSV"


def test_nvd_cves_parses_score_and_desc():
    with client_with(transport()) as c:
        found = cve.nvd_cves(c, "a", "proxmox", "virtual_environment", "8.1.4")
    assert len(found) == 1 and found[0]["cve"] == "CVE-2024-9999"
    assert found[0]["severity"] == "critical" and found[0]["source"] == "NVD"


def test_nvd_fixed_version_comes_from_the_products_vulnerable_range():
    rec = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "2.4.0", "versionEndExcluding": "2.4.67"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.9"},
        {"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "6.0"},
        {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
         "versionEndIncluding": "2.2.34"}]}]}]}
    assert cve.nvd_fixed(rec, "a", "apache", "http_server") == ["2.4.67"]
    assert cve.nvd_fixed({}, "a", "apache", "http_server") == []

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"vulnerabilities": [{"cve": {"id": "CVE-2026-0002", **rec,
                                                                     "descriptions": []}}]})
    with client_with(httpx.MockTransport(handler)) as c:
        found = cve.nvd_cves(c, "a", "apache", "http_server", "2.4.66")
    assert found[0]["fixed"] == "2.4.67"


# ---- local database + lookup ----

def test_entries_from_before_the_fixed_versions_format_are_refetched(tmp_path):
    path = tmp_path / "cve_db.json"
    key = cve.target_key({"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"})
    path.write_text(json.dumps({key: {"fetched": int(time.time()), "findings": []}}), encoding="utf-8")
    database = cve.Database("own", path)
    with client_with(transport()) as c:
        res = cve.lookup(database, {"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"}, c)
    assert res["cached"] is False and res["findings"]
    assert database.fresh(database.entry(key))

def test_own_mode_queries_then_serves_from_cache(tmp_path):
    database = cve.Database("own", tmp_path / "cve_db.json")
    target = {"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"}
    with client_with(transport()) as c:
        first = cve.lookup(database, target, c)
    assert first["cached"] is False and first["findings"][0]["cve"] == "CVE-2024-0001"
    assert database.size() == 1
    # a second look-up is served from the stored database, no client needed
    second = cve.lookup(database, target, client=None)
    assert second["cached"] is True and second["findings"][0]["cve"] == "CVE-2024-0001"


def test_own_mode_offline_with_no_cache_is_empty(tmp_path):
    database = cve.Database("own", tmp_path / "cve_db.json")
    target = {"kind": "cpe", "part": "a", "vendor": "x", "product": "y", "version": "1"}
    res = cve.lookup(database, target, client=None)
    assert res["findings"] == [] and "nothing cached" in res["note"]


def test_stale_entry_is_requeried(tmp_path):
    path = tmp_path / "cve_db.json"
    database = cve.Database("own", path, ttl_days=1)
    key = cve.target_key({"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"})
    path.write_text(json.dumps({key: {"fetched": int(time.time()) - 5 * 86400, "findings": []}}), encoding="utf-8")
    target = {"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"}
    with client_with(transport()) as c:
        res = cve.lookup(database, target, c)
    assert res["cached"] is False and res["findings"]  # refetched because the cached copy was 5 days old


def test_shared_mode_is_read_only(tmp_path):
    path = tmp_path / "shared.json"
    key = cve.target_key({"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"})
    path.write_text(json.dumps({key: {"fetched": int(time.time()), "findings": [{"cve": "CVE-X"}]}}), encoding="utf-8")
    database = cve.Database("shared", path)
    hit = cve.lookup(database, {"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1.0.0"})
    assert hit["findings"][0]["cve"] == "CVE-X" and hit["cached"] is True
    miss = cve.lookup(database, {"kind": "cpe", "part": "a", "vendor": "x", "product": "y", "version": "9"})
    assert miss["findings"] == [] and "shared" in miss["note"]
    # shared mode never writes, even when a client is offered
    with client_with(transport()) as c:
        cve.lookup(database, {"kind": "osv", "ecosystem": "PyPI", "name": "new", "version": "1"}, c)
    assert key in json.loads(path.read_text()) and "new" not in path.read_text()


# ---- target parsing ----

def test_parse_target_validates():
    assert cve.parse_target({"kind": "cpe", "vendor": "proxmox", "product": "pve", "version": "8"})["kind"] == "cpe"
    osv = cve.parse_target({"kind": "osv", "ecosystem": "PyPI", "name": "foo", "version": "1"})
    assert osv["ecosystem"] == "PyPI"
    for bad in ({"kind": "cpe", "vendor": "p", "product": "x"},                       # no version
                {"kind": "cpe", "vendor": "Bad Vendor!", "product": "x", "version": "1"},  # bad token
                {"kind": "osv", "ecosystem": "", "name": "", "version": "1"}):         # missing fields
        with pytest.raises(ValueError):
            cve.parse_target(bad)


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
    page = h.get("/admin/account")   # every role has the account page with a CSRF token
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def test_analyst_can_run_a_cve_lookup(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/scan",
                   data={"csrf": csrf, "kind": "cpe", "vendor": "proxmox", "product": "pve", "version": "8.1.4"})
    assert r.status_code == 200 and "CVE-2024-9999" in r.text and "critical" in r.text


def test_viewer_cannot_run_a_scan(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "vee")
        r = h.post("/admin/security/scan",
                   data={"csrf": csrf, "kind": "cpe", "vendor": "proxmox", "product": "pve", "version": "8.1.4"})
    assert r.status_code == 403 and "analyst role" in r.text and "CVE-2024-9999" not in r.text


def test_bad_input_is_reported(settings):
    with app_client(settings) as h:
        csrf = sign_in(h, "ana")
        r = h.post("/admin/security/scan", data={"csrf": csrf, "kind": "cpe", "vendor": "proxmox", "product": "pve"})
    assert r.status_code == 422 and "version" in r.text.lower()
