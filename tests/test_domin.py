from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from domin import db, importer, jobs, scanner, tools
from domin.config import Settings
from domin.validate import normalize_domain
from domin.web import create_app

HEAD = "Subdomain,IP,ASN,Inetnum,Netname,Descr,Country\n"


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", scans_per_hour=2)
    r = tmp_path / "reports"
    r.mkdir()
    (r / "example.se_250301_results.csv").write_text(
        HEAD + "www.example.se,192.0.2.1,64500,192.0.2.0/24,NET-A,Alpha,Sweden\nold.example.se,192.0.2.9,64500,,NET-A,,Sweden\n")
    (r / "example.se_250315_results.csv").write_text(
        HEAD + "www.example.se,198.51.100.7,64501,,NET-B,,Finland\nnew.example.se,192.0.2.2,64500,,NET-A,,Sweden\n")
    (r / "example.se_250316_results.csv").write_text(HEAD + "example.se,Lookup failed or turned up empty,,,,,\n")
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        st = importer.import_dir(c, r, log=lambda _: None)
        assert st["imported"] == 2 and st["skipped_empty"] == 1
        assert importer.import_dir(c, r, log=lambda _: None)["skipped_existing"] == 2
    return s


@pytest.mark.parametrize("raw,want", [("https://www.Example.SE/x", "example.se"), ("räksmörgås.se", "xn--rksmrgs-5wao1o.se"),
                                      ("example", None), ("-bad.se", None), ("example.se; echo probe", None),
                                      ("metadata.google.internal", None), ("router.home.arpa", None),
                                      ("app.localhost", None), ("x.invalid", None), ("a" * 3000 + ".se", None)])
def test_normalize(raw, want):
    assert normalize_domain(raw) == want


def test_wal_kept_between_connections(settings):
    with db.connect(settings.db_path) as c:
        c.execute("INSERT INTO domains (name, added) VALUES ('wal.example', '2026-10-30')")
    assert settings.db_path.with_name(settings.db_path.name + "-wal").exists()   # no checkpoint on each close


def test_diff():
    d = db.diff([{"host": "a", "ip": "1"}, {"host": "b", "ip": "2"}], [{"host": "b", "ip": "3"}, {"host": "c", "ip": ""}])
    assert d["hosts_added"] == ["c"] and d["hosts_removed"] == ["a"] and d["hosts_changed"] == ["b"]


def test_web(settings):
    with TestClient(create_app(settings)) as h:
        assert h.get("/").status_code == 200
        r = h.get("/d/example.se")
        assert r.status_code == 200 and "new.example.se" in r.text and "Changes since 2025-03-01" in r.text
        hist = h.get("/api/domains/example.se/history").json()
        assert [x["hosts"] for x in hist] == [2, 2]
        assert "old.example.se" in h.get(f"/d/example.se?scan={hist[0]['id']}").text
        assert h.get(f"/d/example.se/compare?a={hist[0]['id']}&b={hist[1]['id']}").status_code == 200
        assert h.get("/d/nothere.se").status_code == 404
        assert h.get("/tools").status_code == 200
        assert h.get(f"/scans/{hist[0]['id']}.csv").text.startswith("host,ip")
        assert h.post("/api/scan", json={"domain": "not a domain"}).status_code == 422


def test_scan_now_at_most_once_per_day_per_domain(settings):
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "today.se", db.now(), "scan", [{"host": "today.se", "ip": "192.0.2.5", "asn": "", "prefix": "",
                     "netname": "", "descr": "", "country": ""}])
    with TestClient(create_app(settings)) as h:
        r = h.post("/api/scan", json={"domain": "today.se"})
        assert r.status_code == 429 and "already scanned today" in r.json()["error"]
        assert h.post("/api/scan", json={"domain": "example.se"}).status_code == 200  # last scan 2025-03-15


def test_churn_chart_only_when_host_names_changed(settings):
    with db.connect(settings.db_path) as c:
        for day in ("2025-03-01", "2025-03-02"):
            db.save_scan(c, "stable.se", f"{day}T00:00:00", "import", [{"host": "www.stable.se", "ip": "192.0.2.5",
                         "asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}])
    with TestClient(create_app(settings)) as h:
        assert 'id="churn"' not in h.get("/d/stable.se").text
        assert 'id="churn"' in h.get("/d/example.se").text


ROW = {"host": "x.example.se", "ip": "192.0.2.5", "asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}


def fake_dns(addr):
    return lambda host, *a, **kw: [(2, 1, 6, "", (addr, 443))]


@pytest.mark.parametrize("url,addr", [("http://rdap.example/", "192.0.2.1"), ("https://rdap.example/", "127.0.0.1"),
                                      ("https://rdap.example/", "169.254.169.254"), ("https://rdap.example/", "10.0.0.1")])
def test_outbound_requests_refuse_internal_targets(monkeypatch, url, addr):
    monkeypatch.setattr(tools.socket, "getaddrinfo", fake_dns(addr))
    with pytest.raises(httpx.RequestError):
        tools.public_only(httpx.Request("GET", url))


def test_redirect_to_metadata_address_is_refused(monkeypatch):
    monkeypatch.setattr(tools.socket, "getaddrinfo", lambda host, *a, **kw: [
        (2, 1, 6, "", ("169.254.169.254" if host == "meta.invalid" else "45.0.0.1", 443))])
    redirect = httpx.MockTransport(lambda req: httpx.Response(302, headers={"location": "https://meta.invalid/latest"}))
    with tools.http_client() as c:
        c._transport = redirect
        with pytest.raises(httpx.RequestError, match="not a public address"):
            tools.get_json(c, "https://rdap.example/domain/example.se", timeout=5)


def test_response_size_is_capped(monkeypatch):
    monkeypatch.setattr(tools, "MAX_BODY", 10)
    with httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"[" + b"1," * 50 + b"1]"))) as c:
        with pytest.raises(httpx.RequestError, match="too large"):
            tools.get_json(c, "https://crt.example/", timeout=5)
        assert scanner.from_crtsh("example.se", c) == set()


def test_scan_api_hardening(settings):
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "formula.se", "2025-03-01T00:00:00", "import", [{**ROW, "host": "formula.se", "netname": "=1+2"}])
        sid = db.history(c, "formula.se")[0]["id"]
    with TestClient(create_app(replace(settings, queue_max=1))) as h:
        body = b'{"domain": "one.se"}'
        assert h.post("/api/scan", content=body, headers={"content-type": "text/plain"}).status_code == 422  # CSRF
        assert h.post("/api/scan", content=body).status_code in (415, 422)   # no content type (old FastAPI parsed it)
        assert h.get("/").text.count("one.se") == 0
        job = h.post("/api/scan", json={"domain": "one.se"}).json()
        assert "client" not in job and "client" not in h.get(f"/api/jobs/{job['id']}").json()
        assert h.post("/api/scan", json={"domain": "two.se"}).status_code == 503   # queue full
        assert h.get(f"/api/jobs/{2**70}").status_code == 422
        assert h.get(f"/d/example.se/compare?a=1&b={2**70}").status_code == 422
        assert "'=1+2" in h.get(f"/scans/{sid}.csv").text


def test_ipv6_clients_count_per_64(settings):
    with TestClient(create_app(settings), client=("127.0.0.1", 50000)) as h:
        for i, want in ((1, 200), (2, 200), (3, 429)):
            r = h.post("/api/scan", json={"domain": f"v{i}.se"}, headers={"x-real-ip": f"2001:db8::{i}"})
            assert r.status_code == want
        assert h.post("/api/scan", json={"domain": "v4.se"}, headers={"x-real-ip": "2001:db8:1::1"}).status_code == 200


def test_live_lookups_are_rate_limited(settings, monkeypatch):
    monkeypatch.setattr(tools, "email_security", lambda d: {"domain": d})
    with TestClient(create_app(replace(settings, lookups_per_minute=1))) as h:
        assert h.get("/api/email/example.se").status_code == 200
        assert h.get("/api/email/example.se").status_code == 429


def test_job_errors_and_client_addresses_are_not_kept(settings, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("detail from /srv/domin/internal/path")
    monkeypatch.setattr(scanner, "run", boom)
    with db.connect(settings.db_path) as c:
        job = jobs.enqueue(c, "fail.se", client="192.0.2.7")
        c.execute("UPDATE jobs SET created = '2025-01-01T00:00:00' WHERE id = ?", (job["id"],))
        assert jobs.forget_clients(c) == 1
        assert c.execute("SELECT client FROM jobs WHERE id = ?", (job["id"],)).fetchone()[0] == ""
    jobs.run_job(settings, job)
    with db.connect(settings.db_path) as c:
        assert jobs.get(c, job["id"])["error"] == "internal error (RuntimeError)"


def test_refresh_queue_is_separate_and_oldest_first(settings):
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "older.se", "2024-01-01T00:00:00", "import", [ROW])
        db.save_scan(c, "newer.se", "2024-06-01T00:00:00", "import", [ROW])
        assert jobs.enqueue_due(c, 7) == 3   # example.se from the fixture (2025-03) too
        assert [r[0] for r in c.execute("SELECT domain FROM jobs ORDER BY id")] == ["older.se", "newer.se", "example.se"]
        assert jobs.queued(c) == 0   # refreshes don't fill the visitors' queue
        user = jobs.enqueue(c, "user.se", client="h:a")
        assert jobs.get(c, user["id"])["ahead"] == 0   # not behind the refresh backlog
        taken = jobs.enqueue(c, "newer.se", client="h:b")   # a visitor takes over the queued refresh
        assert jobs.queued(c) == 2 and jobs.get(c, taken["id"])["ahead"] == 0   # keeps its earlier place
        assert [jobs.claim(c)["domain"], jobs.claim(c)["domain"]] == ["newer.se", "user.se"]
        assert jobs.claim(c, refresh=True)["domain"] == "older.se"


def test_scan_times_out(settings, monkeypatch):
    def slow(conn, domain, s, progress, **kw):
        progress("resolving")
        raise AssertionError("the scan should have timed out")
    monkeypatch.setattr(scanner, "run", slow)
    monkeypatch.setattr(jobs.time, "monotonic", iter([0.0, 4 * 3600.0]).__next__)
    with db.connect(settings.db_path) as c:
        job = jobs.claim(c) if jobs.enqueue(c, "slow.se", client="h:a") else None
    jobs.run_job(settings, job)
    with db.connect(settings.db_path) as c:
        assert jobs.get(c, job["id"])["error"] == "timed out after 3 h"


def test_scans_per_day_limit(settings):
    with TestClient(create_app(replace(settings, scans_per_hour=100, scans_per_day=1))) as h:
        assert h.post("/api/scan", json={"domain": "d1.se"}).status_code == 200
        r = h.post("/api/scan", json={"domain": "d2.se"})
        assert r.status_code == 429 and "per day" in r.text


def test_amass_output_old_and_new_formats():
    out = "a.ex.se\nB.EX.se.\nother.se\n\nc.ex.se (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"
    assert scanner.amass_hosts(out, "ex.se") == {"a.ex.se", "b.ex.se", "c.ex.se"}


def test_amass_runs_passive_then_active(monkeypatch):
    calls = []

    class Done:
        def __init__(self, args):
            calls.append(args)
            with open(args[args.index("-o") + 1], "w") as f:
                f.write("p.ex.se\n" if "-passive" in args else "p.ex.se\nq.ex.se\n")

    monkeypatch.setattr(scanner.shutil, "which", lambda exe: "/bin/amass")
    monkeypatch.setattr(scanner.subprocess, "run", lambda args, **kw: Done(args))
    assert scanner.from_amass("ex.se", "amass") == {"p.ex.se", "q.ex.se"}
    assert ["-passive" in c for c in calls] == [True, False] and scanner.RESOLVERS in calls[1]
    with open(scanner.RESOLVERS) as f:
        assert f.read().split()[0] == "1.1.1.1"
