from dataclasses import replace
from datetime import datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from domin import admin, db, importer, jobs, scanner, tools
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


def test_search_across_domains(settings):
    with db.connect(settings.db_path) as c:
        rows, total = db.search(c, "EXAMPLE")
        assert total == 2 and {r["host"] for r in rows} == {"www.example.se", "new.example.se"}   # latest scan only
        assert db.search(c, "old")[1] == 0
        rows, total = db.search(c, "old", history=True)
        assert total == 1 and rows[0]["first_seen"][:10] == rows[0]["last_seen"][:10] == "2025-03-01"
        assert db.search(c, history=True)[1] == 4   # every host and address pair ever seen
        assert db.search(c, "net-b", field="netname")[1] == 1 and db.search(c, "net-b", field="host")[1] == 0
        assert db.search(c, "%")[1] == 0 and db.search(c, "_")[1] == 0   # wildcards are plain text
        rows, total = db.search(c, "example", limit=1, offset=1)
        assert total == 2 and len(rows) == 1
        # column filters narrow each other and the search
        assert db.search(c, history=True, columns={"country": "swe"})[1] == 3
        assert db.search(c, history=True, columns={"country": "swe", "host": "www"})[1] == 1
        assert db.search(c, "new", history=True, columns={"country": "swe"})[1] == 1
        assert db.search(c, columns={"domain": "example.se", "ip": "198.51"})[1] == 1
        assert db.search(c, columns={"domain": "other"})[1] == 0
        assert db.search(c, columns={"nope": "x"})[1] == 2   # unknown columns are ignored
        # "!text" excludes; the EU column matches from the start ("eu" is not "Non-EU")
        assert db.search(c, history=True, columns={"country": "!swe"})[1] == 1
        assert db.search(c, history=True, columns={"host": "!www", "country": "swe"})[1] == 2
        assert db.search(c, history=True, columns={"eu": "eu"})[1] == 4   # Sweden and Finland
        assert db.search(c, history=True, columns={"eu": "!eu"})[1] == 0
        assert db.search(c, history=True, columns={"eu": "non"})[1] == 0
        rows = db.search(c, history=True)[0]
        assert [r["eu"] for r in rows] == [db.eu_status(r["country"]) for r in rows] and "EU" in {r["eu"] for r in rows}
        assert db.eu_status("Sweden") == "EU" and db.eu_status("Norway") == "Non-EU" and db.eu_status("") == ""
        # figures and charts of the all-domains view follow the same filters
        s = db.search_summary(c)
        assert (s["hosts"], s["ips"], s["domains"], s["asns"], s["countries"], s["eu_pct"]) == (2, 2, 1, 2, 2, 100.0)
        s = db.search_summary(c, history=True, columns={"country": "swe"})
        assert (s["hosts"], s["ips"]) == (3, 3) and s["country"] == [{"label": "Sweden", "ips": 3}]
        assert s["netname"] == [{"label": "NET-A", "ips": 3}]
        assert db.search_summary(c, "nothing-like-this")["eu_pct"] is None
        # the browser's dataset: the same rows as the search, column by column
        d = db.drill_columns(c)
        assert d["rows"] == 2 and "Sweden" in d["eu"]
        assert d["columns"]["domain"] == ["example.se"] * 2   # too few repeats for distinct values + indexes
        assert set(d["columns"]["host"]) == {"www.example.se", "new.example.se"}
        d = db.drill_columns(c, history=True)
        assert d["rows"] == 4 and {"first_seen", "seen", "eu"} <= set(d["columns"])
        assert list(d["columns"]).index("eu") == list(d["columns"]).index("country") - 1
        assert d["columns"]["domain"] == {"d": ["example.se"], "i": [0, 0, 0, 0]}
    with TestClient(create_app(settings)) as h:
        r = h.get("/data/drill.json", params={"scope": "latest", "v": "nope"})
        assert r.status_code == 200 and r.json()["rows"] == 2 and r.headers["cache-control"] == "no-cache"
        assert r.headers["content-encoding"] == "gzip"
        src = h.get("/all").text.split('data-drill="')[1].split('"')[0].replace("&amp;", "&")
        r = h.get(src)
        assert "immutable" in r.headers["cache-control"] and r.json()["rows"] == 2
        assert h.get("/data/drill.json", params={"scope": "all"}).json()["rows"] == 4
        assert "drill.js" in h.get("/").text and 'data-drill="/data/drill.json?scope=latest' in h.get("/").text
        r = h.get("/all", params={"q": "old", "scope": "all"})
        assert r.status_code == 200 and "old.example.se" in r.text and "First seen" in r.text
        assert '<a href="/all" class="active">Drilldown (All)</a>' in r.text and 'id="page-data"' in r.text
        assert "old.example.se" in h.get("/search", params={"q": "old", "scope": "all"}).text   # first address
        assert "old.example.se" not in h.get("/all", params={"q": "old"}).text
        r = h.get("/all", params={"q": "nothing-like-this"})
        assert "No matches." in r.text and 'name="f_host" form="search-form"' in r.text   # filters stay editable
        ov = h.get("/").text   # the overview's Drilldown (All) tab: filter form and first records
        assert 'data-tab="drill"' in ov and 'action="/all"' in ov and 'name="f_host" form="search-form"' in ov
        assert ov.count('<table id="results"') == 1 and 'data-scope="latest" hidden' in ov
        r = h.get("/all", params={"scope": "all"})   # unfiltered history: hourly figures, all 4 pairs
        assert "updated once an hour" in r.text and "4 host and address pairs" in r.text
        assert "updated once an hour" not in h.get("/all", params={"scope": "all", "f_host": "www"}).text
        r = h.get("/all", params={"scope": "all", "f_country": "Sweden", "f_host": "www"})
        assert r.text.count('<td class="host">') == 1 and 'value="Sweden"' in r.text and "Clear column filters" in r.text
        assert "f_country=Sweden" in r.text   # CSV and page links keep the filters
        assert "data-colfilters" not in h.get("/").text   # overview domain list: the Filter box only
        assert "applyFilters" in h.get("/static/app.js").text
        assert h.get("/search", params={"page": 0}).status_code == 422
        body = h.get("/search.csv", params={"q": "example", "field": "nope"}).text
        assert body.startswith("domain,host,ip") and len(body.strip().splitlines()) == 3


def test_tables_wrap_long_text_and_show_hidden_columns(settings):
    with TestClient(create_app(settings)) as h:
        page = h.get(f"/d/example.se?scan={h.get('/api/domains/example.se/history').json()[0]['id']}").text
        assert '<td class="host">www.example.se</td>' in page
        assert '<div class="lines2" title="Alpha">Alpha</div>' in page   # description wraps, 2 lines at most
        assert '<td class="host"><a href="/d/example.se">' in h.get("/").text
        css, js = h.get("/static/app.css").text, h.get("/static/app.js").text
        assert ".table-wrap td:first-child" in css and ".table-scroll.more-right::after" in css   # sticky column, fade
        assert "more-right" in js and "More columns" in js


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


def test_stuck_and_failed_jobs_are_retried_then_wait_a_day(settings):
    old = (datetime.now() - timedelta(hours=5)).isoformat(timespec="seconds")
    day_ago = (datetime.now() - timedelta(hours=25)).isoformat(timespec="seconds")
    with db.connect(settings.db_path) as c:
        add = "INSERT INTO jobs (domain, status, created, started, finished, client) VALUES (?, ?, ?, ?, ?, '')"
        c.execute(add, ("stuck.se", "running", old, old, None))
        c.execute(add, ("fresh.se", "running", db.now(), db.now(), None))     # still within the timeout
        c.execute(add, ("cancel.se", "cancelled", old, old, old))
        for _ in range(3):
            c.execute(add, ("flaky.se", "failed", old, old, old))            # 3 failures today: wait
            c.execute(add, ("yesterday.se", "failed", day_ago, day_ago, day_ago))
        c.execute(add, ("ok.se", "failed", old, old, old))
        c.execute(add, ("ok.se", "done", old, old, old))                     # newest job done: nothing to retry
        assert jobs.sweep_stuck(c, 3) == 1
        assert jobs.retry_failed(c) == 2   # stuck.se + yesterday.se
        queued = {r["domain"] for r in c.execute("SELECT domain FROM jobs WHERE status = 'queued'")}
        assert queued == {"stuck.se", "yesterday.se"}
        assert jobs.retry_failed(c) == 0   # queued now: not twice


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


def test_email_security_checks_common_dkim_selectors():
    import dns.resolver

    class Txt:
        def __init__(self, s):
            self.strings = [s.encode()]

    zone = {"ex.se": [Txt("v=spf1 -all")], "_dmarc.ex.se": [Txt("v=DMARC1; p=reject; rua=mailto:d@ex.se")],
            "selector1._domainkey.ex.se": [Txt("v=DKIM1; k=rsa; p=MIIB")]}

    class Fake:
        def resolve(self, name, rtype):
            if rtype == "TXT" and name in zone:
                return zone[name]
            raise dns.resolver.NXDOMAIN

    r = tools.email_security("ex.se", Fake())
    assert r["dkim"]["status"] == "ok" and r["dkim"]["record"] == "selector1"
    zone.pop("selector1._domainkey.ex.se")
    assert tools.email_security("ex.se", Fake())["dkim"]["status"] == "warn"


def test_eu_share_per_scan_and_per_day(settings):
    recs = [{"host": "a.eu.se", "ip": "192.0.2.1", "country": "Sweden"},
            {"host": "b.eu.se", "ip": "192.0.2.1", "country": "Sweden"},     # same address counts once
            {"host": "c.eu.se", "ip": "192.0.2.2", "country": "Czech Republic"},
            {"host": "d.eu.se", "ip": "192.0.2.3", "country": "United States"},
            {"host": "e.eu.se", "ip": "192.0.2.4", "country": ""},            # unknown country: left out
            {"host": "f.eu.se", "ip": ""}]
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "eu.se", "2025-05-01T10:00:00", "scan", recs)
        assert [(h["eu"], h["eu_known"], h["eu_pct"]) for h in db.history(c, "eu.se")] == [(2, 3, 66.7)]
        assert {r["day"]: r["pct"] for r in db.eu_per_day(c)}["2025-05-01"] == 66.7
        # a database from before the columns existed is filled in once at start
        c.execute("ALTER TABLE scans DROP COLUMN eu")
        c.execute("ALTER TABLE scans DROP COLUMN eu_known")
    db.init(settings.db_path)
    with db.connect(settings.db_path) as c:
        assert db.history(c, "eu.se")[0]["eu_pct"] == 66.7
        assert db.history(c, "example.se")[-1]["eu_pct"] == 100.0
    web = TestClient(create_app(settings))
    assert "66.7 %" in web.get("/d/eu.se").text and 'id="eu"' in web.get("/").text


def test_names_resolve_over_the_old_resolver_set():
    r = scanner._resolver()
    assert len(r.nameservers) == 8 and r.rotate and r.lifetime == 15


def test_country_is_address_location_when_the_table_is_loaded(settings, tmp_path):
    # public addresses (reserved ones are never looked up); the lookup is faked, nothing is sent
    rdap = {"asn": "64500", "prefix": "9.9.9.0/24", "netname": "NET-A", "descr": "", "country": "United States"}
    with db.connect(settings.db_path) as c:
        e = scanner.Enricher(c, lookup=lambda ip: dict(rdap))
        assert e.get("9.9.9.1")["country"] == "United States"   # no table: registry country
        geo = tmp_path / "geo.csv"
        geo.write_text("9.9.9.0,9.9.9.127,SE\n")
        admin.import_geo(c, geo)
        e = scanner.Enricher(c, lookup=lambda ip: dict(rdap))
        assert e.get("9.9.9.1")["country"] == "Sweden"
        assert e.get("9.9.9.200")["country"] == "United States"   # outside the table's ranges
        assert e.get("10.0.0.1")["netname"] == "Private/reserved"


def test_owner_lookup_does_not_hold_the_write_lock(settings):
    # the cache write stayed open through 25 slow lookups; other scans hit 'database is locked'
    rdap = {"asn": "64500", "prefix": "9.9.9.0/24", "netname": "NET-A", "descr": "", "country": "United States"}
    with db.connect(settings.db_path) as c:
        scanner.Enricher(c, lookup=lambda ip: dict(rdap)).get("9.9.9.1")
        assert not c.in_transaction
