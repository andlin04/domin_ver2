from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

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


def test_services_refuse_non_public_addresses():
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    deny = next(line for line in install.splitlines() if line.startswith("NON_PUBLIC="))
    for net in ("10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"):
        assert net in deny
    assert "IPAddressDeny=$NON_PUBLIC" in install
    worker = next(line for line in install.splitlines() if line.startswith("unit domin-worker"))
    assert "IPAddressAllow" not in worker   # only the web app, for nginx over loopback


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
        page = h.get(f"/d/example.se?scan={hist[0]['id']}").text
        assert "old.example.se" in page
        assert '<a href="/" class="active" aria-current="page">Inventory</a>' in page  # sub-page -> its section
        cmp = h.get(f"/d/example.se/compare?a={hist[0]['id']}&b={hist[1]['id']}")
        assert cmp.status_code == 200 and 'aria-current="page">Inventory</a>' in cmp.text
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
        assert '<a href="/all" class="active" aria-current="page">All records</a>' in r.text and 'id="page-data"' in r.text
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
        notes = []
        assert scanner.from_crtsh("example.se", c, notes, sleep=lambda s: None) == set()
        assert "certspotter failed" in notes[0]


def _cert_transport(crtsh_fails: int, spotter_pages: list):
    """crt.sh answers 502 `crtsh_fails` times, then a list; certspotter serves `spotter_pages` in order."""
    calls = {"crt": 0, "spot": 0}

    def handle(req):
        if req.url.host == "crt.sh":
            calls["crt"] += 1
            if calls["crt"] <= crtsh_fails:
                return httpx.Response(502)
            return httpx.Response(200, json=[{"name_value": "a.ex.se\n*.b.ex.se"}, {"name_value": "other.se"}])
        page = spotter_pages[calls["spot"]] if calls["spot"] < len(spotter_pages) else []
        calls["spot"] += 1
        return httpx.Response(200, json=page)
    return httpx.MockTransport(handle), calls


def test_crtsh_retries_then_succeeds():
    transport, calls = _cert_transport(2, [])
    waits, notes = [], []
    with httpx.Client(transport=transport) as c:
        assert scanner.from_crtsh("ex.se", c, notes, sleep=waits.append) == {"a.ex.se", "b.ex.se"}
    assert calls == {"crt": 3, "spot": 0} and waits == list(scanner.CRTSH_WAITS) and notes == []


def test_crtsh_down_falls_back_to_certspotter(monkeypatch):
    monkeypatch.setattr(scanner, "CERTSPOTTER_PAGES", 2)
    pages = [[{"id": "1", "dns_names": ["x.ex.se", "*.y.ex.se"]}], [{"id": "2", "dns_names": ["z.ex.se", "no.se"]}]]
    transport, calls = _cert_transport(9, pages)
    notes = []
    with httpx.Client(transport=transport) as c:
        assert scanner.from_crtsh("ex.se", c, notes, sleep=lambda s: None) == {"x.ex.se", "y.ex.se", "z.ex.se"}
    assert calls == {"crt": 3, "spot": 2}
    assert "certspotter used instead (3 names, first pages only" in notes[0]
    transport, _ = _cert_transport(9, pages[:1])   # an empty page ends the list: complete
    notes = []
    with httpx.Client(transport=transport) as c:
        scanner.from_crtsh("ex.se", c, notes, sleep=lambda s: None)
    assert notes == ["crt.sh failed 3 times; certspotter used instead (2 names)"]


def test_scan_notes_host_cap_and_missing_amass(monkeypatch, settings):
    names = {f"h{i}.ex.se" for i in range(5)}
    monkeypatch.setattr(scanner, "from_crtsh", lambda d, c, notes: set(names))
    monkeypatch.setattr(scanner, "from_dns", lambda d, r: set())
    monkeypatch.setattr(scanner, "wildcard_ips", lambda d, r: set())
    monkeypatch.setattr(scanner, "resolve", lambda h, r=None: [])
    checked = []
    monkeypatch.setattr(scanner, "ThreadPoolExecutor", lambda n: _Pool(checked))
    s = replace(settings, max_hosts=3, amass="/nonexistent/amass")
    notes = []
    with db.connect(settings.db_path) as c:
        scanner.run(c, "ex.se", s, client=httpx.Client(), resolver=object(), notes=notes)
    assert len(checked) == 3   # the cap holds; guesses get no room
    assert notes == ["amass is not installed: its names are missing",
                     "3 of 6 names found were not checked: over the limit of 3 names per scan"]


class _Pool:
    def __init__(self, seen):
        self.seen = seen

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def map(self, fn, items):
        items = list(items)
        self.seen.extend(items)
        return [fn(i) for i in items]


def test_done_scan_shows_its_notes(settings):
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "noted.se", "2025-03-01T00:00:00", "scan", [{**ROW, "host": "noted.se"}],
                     error="crt.sh failed 3 times; certspotter used instead (2 names)")
    with TestClient(create_app(settings)) as h:
        assert "This scan may be incomplete: crt.sh failed 3 times" in h.get("/d/noted.se").text


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


def test_visitor_scans_per_day_from_all_clients(settings):
    s = replace(settings, scans_per_hour=100, scans_per_day_total=2)
    for i, ip in enumerate(("198.51.100.1", "198.51.100.2", "198.51.100.3")):
        with TestClient(create_app(s), client=(ip, 50000)) as h:
            r = h.post("/api/scan", json={"domain": f"t{i}.se"})
            assert r.status_code == (200 if i < 2 else 503)
    assert "used up" in r.text
    with db.connect(settings.db_path) as c:   # refreshes and admin retries don't use the visitors' budget
        jobs.enqueue(c, "r1.se", client=jobs.REFRESH)
        jobs.enqueue(c, "a1.se", client="admin")
        assert jobs.visitor_scans(c) == 2


def test_heavy_searches_wait_for_a_slot(settings, monkeypatch):
    import threading

    from domin import web
    monkeypatch.setattr(web, "HEAVY_AT_ONCE", 1)
    release, started = threading.Event(), threading.Event()
    real = db.search

    def slow(*a, **kw):
        started.set()
        release.wait(10)
        return real(*a, **kw)

    monkeypatch.setattr(db, "search", slow)
    real_acquire = threading.BoundedSemaphore.acquire
    monkeypatch.setattr(threading.BoundedSemaphore, "acquire", lambda self, timeout=None: real_acquire(self, timeout=0.2))
    with TestClient(create_app(settings)) as h:
        first = threading.Thread(target=lambda: h.get("/search.csv?q=example"))
        first.start()
        assert started.wait(10)
        assert h.get("/all?q=example").status_code == 503   # the one slot is taken
        release.set()
        first.join(10)
        assert h.get("/all?q=example").status_code == 200


def test_security_headers(settings):
    with TestClient(create_app(settings)) as h:
        r = h.get("/")
    for k in ("content-security-policy", "permissions-policy", "cross-origin-opener-policy",
              "cross-origin-resource-policy", "x-frame-options", "x-content-type-options", "referrer-policy"):
        assert k in r.headers


def test_no_admin_page_without_admin_ips(monkeypatch):
    monkeypatch.delenv("DOMIN_ADMIN_IPS", raising=False)
    assert Settings.from_env().admin_ips == ()


def test_install_pins_dependencies_and_denies_own_addresses():
    root = Path(__file__).parent.parent
    install = (root / "deploy" / "install.sh").read_text()
    pins = [x for x in (root / "deploy" / "requirements.txt").read_text().splitlines() if x and not x.startswith("#")]
    assert pins and all("==" in x for x in pins)
    assert "deploy/requirements.txt" in install and "--upgrade pip" not in install
    assert "${DENY_MORE:+IPAddressDeny=$DENY_MORE}" in install   # never an empty IPAddressDeny= (it clears the list)
    assert "UMask=0077" in install.splitlines()
    assert "SystemCallFilter=~@privileged @resources" in install.splitlines()


def test_uninstall_removes_services_and_keeps_data():
    u = (Path(__file__).parent.parent / "deploy" / "uninstall.sh").read_text()
    assert "systemctl disable -q --now domin domin-worker" in u
    assert "rm -rf /opt/domin" in u                       # code and venv go
    assert "--purge" in u                                 # data only with --purge
    purge_block = u.split('if [ "$purge" = 1 ]', 1)[1]    # removing the data is inside the --purge branch only
    assert "rm -rf /var/lib/domin" in purge_block and "rm -rf /var/lib/domin" not in u.split('if [ "$purge"', 1)[0]


def test_install_starts_nginx_so_reinstall_after_uninstall_works():
    # a single-site uninstall.sh disables+stops nginx; a reinstall must start it again, not just `reload`
    # (a bare reload fails under set -e and aborts with the public site down). enable --now precedes reload.
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    assert "systemctl enable -q --now nginx" in install
    assert install.index("systemctl enable -q --now nginx") < install.index("systemctl reload nginx")


def test_internal_install_checks_itself_and_fits_both_nginx_versions():
    # found on clean Debian 13 / Ubuntu 24.04 VMs: the status check went through the exported proxy and got 403
    # from the source list; nginx 1.26 warns on "listen ... http2", 1.24 lacks "http2 on"
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    assert 'echo "allow 127.0.0.1;"' in install
    assert "curl -sk --noproxy '*'" in install and "nginx reloads its workers" in install
    assert "ge 1.25.1" in install and "listen 443 ssl$H2L default_server;" in install


def test_internal_ips_skip_scan_limits(settings):
    s = replace(settings, scans_per_hour=1, scans_per_day=1, queue_max=1, internal_ips=("192.0.2.0/24",))
    with TestClient(create_app(s), client=("192.0.2.9", 50000)) as h:
        for name in ("i1.se", "i2.se", "i3.se"):
            assert h.post("/api/scan", json={"domain": name}).status_code == 200
    with TestClient(create_app(s), client=("198.51.100.7", 50000)) as h:   # a visitor, even claiming an internal IP
        r = h.post("/api/scan", json={"domain": "v1.se"}, headers={"x-real-ip": "192.0.2.9"})
        assert r.status_code == 503   # the queue is full of the internal jobs
    with TestClient(create_app(s), client=("127.0.0.1", 50000)) as h:   # nginx passes the internal client's address
        assert h.post("/api/scan", json={"domain": "i4.se"}, headers={"x-real-ip": "192.0.2.9"}).status_code == 200


def test_amass_output_old_and_new_formats():
    out = "a.ex.se\nB.EX.se.\nother.se\n\nc.ex.se (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"
    assert scanner.amass_hosts(out, "ex.se") == {"a.ex.se", "b.ex.se", "c.ex.se"}


def test_amass_gets_no_app_environment(monkeypatch):
    seen = []
    monkeypatch.setenv("DOMIN_SECRET_KEY", "x")
    monkeypatch.setattr(scanner.shutil, "which", lambda exe: "/bin/amass")
    monkeypatch.setattr(scanner.subprocess, "run", lambda args, **kw: seen.append(kw["env"]))
    assert scanner.from_amass("ex.se", "amass") == set()
    assert len(seen) == 2 and all(set(env) == {"PATH", "HOME"} for env in seen)


def test_services_are_sandboxed_with_limits():
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    for line in ("CapabilityBoundingSet=", "SystemCallFilter=@system-service", "MemoryMax=$4", "TasksMax=$5"):
        assert line in install.splitlines()
    assert '" 2G 200 "' in install and '" 16G 2000' in install


def test_internal_install_hsts_only_when_ca_signed_and_firewall_follows_admin_sources():
    install = (Path(__file__).parent.parent / "deploy" / "install.sh").read_text()
    assert "selfsigned /etc/domin/tls.crt || HSTS='add_header Strict-Transport-Security" in install
    assert "ssl_session_tickets off;\n    $HSTS\n" in install
    fw = install[install.index('if [ "$FIREWALL" = 1 ]'):]
    assert 'if [ "$INTERNAL" = 1 ] && [ "$SOURCES" != any ]' in fw
    assert 'ufw allow from "$net" to any port 80,443 proto tcp' in fw
    assert 'setenv DOMIN_SSH_FROM "$SSH_FROM"; else SSH_FROM=$(envget DOMIN_SSH_FROM)' in fw   # kept for updates
    assert fw.index("ufw --force delete") < fw.index("ufw allow")   # old 22/80/443 rules go first


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
    internal = scanner._resolver(("172.20.0.252",))
    assert internal.nameservers == ["172.20.0.252"] and internal.lifetime == 15


def test_delete_domain_drops_its_scans_records_and_jobs(settings):
    with db.connect(settings.db_path) as c:
        sid = db.save_scan(c, "drop.se", "2025-06-01T00:00:00", "scan", [{"host": "a.drop.se", "ip": "192.0.2.5"}])
        jobs.enqueue(c, "drop.se", client="cli")
        assert db.domain(c, "drop.se") and c.execute("SELECT COUNT(*) FROM records WHERE scan_id = ?",
                                                      (sid,)).fetchone()[0] == 1
        assert db.delete_domain(c, "drop.se")
        assert db.domain(c, "drop.se") is None
        assert c.execute("SELECT COUNT(*) FROM records WHERE scan_id = ?", (sid,)).fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM scans WHERE source = 'scan'").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM jobs WHERE domain = 'drop.se'").fetchone()[0] == 0
        assert not db.delete_domain(c, "drop.se")   # already gone
        assert db.domain(c, "example.se")            # other domains are untouched


def test_internal_zone_names_validate_only_when_configured():
    from domin.validate import is_internal
    assert normalize_domain("srv.home.arpa") is None                       # arpa is private by default
    assert normalize_domain("srv.home.arpa", ("home.arpa",)) == "srv.home.arpa"
    assert normalize_domain("home.arpa", ("home.arpa",)) == "home.arpa"
    assert normalize_domain("evil.arpa", ("home.arpa",)) is None           # a different arpa zone stays blocked
    assert normalize_domain("corp.example", ("corp.example",)) == "corp.example"          # a public suffix is unaffected
    assert is_internal("a.home.arpa", ("home.arpa",)) and not is_internal("a.example.se", ("home.arpa",))


def test_internal_zones_and_dns_from_env(monkeypatch):
    monkeypatch.setenv("DOMIN_INTERNAL_ZONES", "home.arpa, CORP.example")
    monkeypatch.setenv("DOMIN_INTERNAL_DNS", "172.20.0.252")
    s = Settings.from_env()
    assert s.internal_zones == ("home.arpa", "corp.example") and s.internal_dns == ("172.20.0.252",)


def test_internal_scan_resolves_privately_without_external_egress(settings):
    import dns.resolver

    class R:
        def __init__(self, ip):
            self.ip = ip

        def to_text(self):
            return self.ip

    zone = {("srv.home.arpa", "A"): ["10.1.2.3"], ("www.srv.home.arpa", "A"): ["172.20.0.9"]}

    class FakeRes:   # only answers from the LAN zone; MX/NS and everything else is NXDOMAIN
        nameservers = ["172.20.0.252"]

        def resolve(self, name, rtype):
            recs = zone.get((name, rtype))
            if recs:
                return [R(x) for x in recs]
            raise dns.resolver.NXDOMAIN

    def no_egress(req):
        raise AssertionError(f"an internal scan must not reach {req.url}")

    s = replace(settings, internal_zones=("home.arpa",), internal_dns=("172.20.0.252",))
    with db.connect(s.db_path) as c, httpx.Client(transport=httpx.MockTransport(no_egress)) as client:
        records = scanner.run(c, "srv.home.arpa", s, client=client, resolver=FakeRes())
    by_host = {r["host"]: r for r in records}
    # private addresses the LAN lookup returns are kept and shown, labelled, not dropped
    assert by_host["srv.home.arpa"]["ip"] == "10.1.2.3"
    assert by_host["srv.home.arpa"]["netname"] == "Private/reserved"
    assert by_host["www.srv.home.arpa"]["ip"] == "172.20.0.9"   # a common-name guess resolved on the LAN


def test_internal_scan_keeps_lan_addresses_only(settings):
    """A LAN resolver forwards AAAA and unknown names upstream: public, link-local and loopback answers drop."""
    import dns.resolver

    class R:
        def __init__(self, ip):
            self.ip = ip

        def to_text(self):
            return self.ip

    zone = {("lan.example", "A"): ["172.20.0.1"],
            ("dns.lan.example", "A"): ["172.20.0.252"], ("dns.lan.example", "AAAA"): ["2620:fe::fe", "::1"],
            ("ftp.lan.example", "A"): ["172.20.0.1"], ("ftp.lan.example", "AAAA"): ["fe80::1"],
            ("gitlab.lan.example", "A"): ["9.9.9.9"], ("gitlab.lan.example", "AAAA"): ["2620:fe::9"]}

    class FakeRes:
        nameservers = ["172.20.0.252"]

        def resolve(self, name, rtype):
            recs = zone.get((name, rtype))
            if recs:
                return [R(x) for x in recs]
            raise dns.resolver.NXDOMAIN

    s = replace(settings, internal_zones=("lan.example",), internal_dns=("172.20.0.252",))
    with db.connect(s.db_path) as c, httpx.Client(transport=httpx.MockTransport(lambda r: 1 / 0)) as client:
        records = scanner.run(c, "lan.example", s, client=client, resolver=FakeRes())
    got = sorted((r["host"], r["ip"]) for r in records)
    assert got == [("dns.lan.example", "172.20.0.252"), ("ftp.lan.example", "172.20.0.1"),
                   ("lan.example", "172.20.0.1")]   # gitlab (public only) is gone


def test_internal_scan_finds_hosts_by_reverse_lookups_and_zone_transfer(settings, monkeypatch):
    import dns.resolver

    class R:
        def __init__(self, ip):
            self.ip = ip

        def to_text(self):
            return self.ip

    zone = {("lan.example", "A"): ["172.20.0.1"], ("pve.lan.example", "A"): ["172.20.0.102"],
            ("laptop.lan.example", "A"): ["172.20.1.14"], ("vault.lan.example", "A"): ["172.20.0.199"],
            ("102.0.20.172.in-addr.arpa.", "PTR"): ["pve."],                      # hosts-file entry: bare name
            ("14.1.20.172.in-addr.arpa.", "PTR"): ["laptop.lan.example."],       # DHCP name: qualified
            ("15.1.20.172.in-addr.arpa.", "PTR"): ["other.example.org."]}        # outside the domain: ignored
    asked = []

    class FakeRes:
        nameservers = ["172.20.0.252"]

        def resolve(self, name, rtype):
            asked.append(name)
            recs = zone.get((name, rtype))
            if recs:
                return [R(x) for x in recs]
            raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(scanner, "from_axfr", lambda domain, servers: {"vault.lan.example"})
    s = replace(settings, internal_zones=("lan.example",), internal_dns=("172.20.0.252",),
                internal_nets=("172.20.0.0/24", "172.20.1.0/28"))
    with db.connect(s.db_path) as c, httpx.Client(transport=httpx.MockTransport(lambda r: 1 / 0)) as client:
        records = scanner.run(c, "lan.example", s, client=client, resolver=FakeRes())
    hosts = {r["host"]: r["ip"] for r in records}
    assert hosts == {"lan.example": "172.20.0.1", "pve.lan.example": "172.20.0.102",
                     "laptop.lan.example": "172.20.1.14", "vault.lan.example": "172.20.0.199"}
    assert sum(n.endswith(".in-addr.arpa.") for n in asked) == 254 + 14   # every host address of both networks


def test_paced_resolver_keeps_under_the_query_rate():
    now, slept = [100.0], []

    class Inner:
        def resolve(self, name, rtype):
            return name

    def sleep(s):
        slept.append(round(s, 3))
        now[0] += s

    p = scanner.Paced(Inner(), 10, clock=lambda: now[0], sleep=sleep)
    assert [p.resolve(f"h{i}", "A") for i in range(4)] == ["h0", "h1", "h2", "h3"]
    assert slept == [0.1, 0.1, 0.1]   # the first query goes at once, then one every 1/qps seconds


def test_sweep_defaults_to_the_slash24_of_dns_servers_and_the_domain():
    got = scanner.sweep_addresses((), ["172.20.0.252", "172.20.4.7", "9.9.9.9", "fe80::1"], 8192)
    assert len(got) == 2 * 254 and got[0] == "172.20.0.1" and "172.20.4.254" in got
    assert scanner.sweep_addresses(("10.0.0.0/16",), [], 100)[-1] == "10.0.0.100"   # capped


def test_api_scan_accepts_an_internal_zone_only_when_configured(settings):
    with TestClient(create_app(replace(settings, internal_zones=("home.arpa",)))) as h:
        assert h.post("/api/scan", json={"domain": "srv.home.arpa"}).status_code == 200
    with TestClient(create_app(settings)) as h:   # not configured: the arpa suffix is refused
        assert h.post("/api/scan", json={"domain": "srv.home.arpa"}).status_code == 422


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
