import os
import re
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_fingerprint import PW

from domin import __main__ as cli
from domin import admin, csvimport, db, users
from domin.config import Settings
from domin.web import COOKIE, create_app

FIELDS = ("domain", *db.RECORD_FIELDS)
SCANS = {
    "example.com": ("2026-03-01T10:00:00", [
        {"host": "example.com", "ip": "192.0.2.10", "asn": "64500", "prefix": "192.0.2.0/24", "netname": "DOC-NET",
         "descr": "=1+1 test text", "country": "Sweden"},
        {"host": "www.example.com", "ip": "2001:db8::10", "asn": "64501", "prefix": "2001:db8::/32",
         "netname": "+plus", "descr": "-minus", "country": "Norway"},
        {"host": "old.example.com", "ip": "", "asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}]),
    "example.org": ("2026-03-02T11:00:00", [
        {"host": "mail.example.org", "ip": "198.51.100.7", "asn": "64502", "prefix": "198.51.100.0 - 198.51.100.255",
         "netname": "@at", "descr": "two\nlines", "country": "Germany"}]),
}


@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=("127.0.0.1",))
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "adm", "admin", PW)
        users.create(c, "ana", "analyst", PW)
    return s


def fill(s):
    with db.connect(s.db_path) as c:
        for dom, (when, recs) in SCANS.items():
            db.save_scan(c, dom, "2026-01-01T09:00:00", "scan", recs[:1])   # an older scan: history has 2 rows
            db.save_scan(c, dom, when, "scan", recs)


def client(s):
    return TestClient(create_app(s), base_url="https://testserver", client=("127.0.0.1", 50000))


def sign_in(h, name):
    assert h.post("/admin/login", data={"name": name, "password": PW}, follow_redirects=False).status_code == 303
    assert COOKIE in h.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get("/admin/account").text).group(1)


def export(s, scope="latest"):
    with client(s) as h:
        sign_in(h, "adm")
        r = h.get("/search.csv", params={"scope": scope})
    assert r.status_code == 200
    return r.content


def record_set(s):
    with db.connect(s.db_path) as c:
        rows, _ = db.search(c, limit=1000)
    return {tuple(r[f] for f in FIELDS) for r in rows}, {r["domain"]: r["last_seen"] for r in rows}


def scan_count(s):
    with db.connect(s.db_path) as c:
        return c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]


def run_import(s, path, **kw):
    with db.connect(s.db_path) as c:
        return csvimport.import_file(c, path, work_dir=s.db_path.parent, **kw)


@pytest.mark.parametrize("scope", ["latest", "all"])
def test_export_then_import_into_an_empty_database_gives_the_same_records(settings, tmp_path, scope):
    fill(settings)
    data = export(settings, scope)
    assert b"'=1+1 test text" in data and b"'+plus" in data and b"'-minus" in data and b"'@at" in data
    f = tmp_path / "export.csv"
    f.write_bytes(data)
    empty = replace(settings, db_path=tmp_path / "empty" / "e.db")
    empty.db_path.parent.mkdir()
    db.init(empty.db_path)
    stats = run_import(empty, f)
    assert (stats["bad"], stats["domains"], stats["imported"], stats["existing"]) == (0, 2, 2, 0)
    assert record_set(empty) == record_set(settings)   # same records, same "last seen" per domain
    with db.connect(empty.db_path) as c:
        assert {r["source"] for r in c.execute("SELECT source FROM scans")} == {"import"}
        assert c.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 2   # one imported scan per domain
        assert db.domain(c, "example.com") and db.history(c, "example.com")[0]["hosts"] == 3
    assert not list(empty.db_path.parent.glob("csv-import-*"))   # the staging database is gone


def test_unescape_strips_only_the_exporters_formula_escape():
    assert csvimport.unescape("'=SUM(A1)") == "=SUM(A1)" and csvimport.unescape("'-1") == "-1"
    assert csvimport.unescape("'quoted'") == "'quoted'" and csvimport.unescape("'") == "'"
    assert csvimport.unescape("plain") == "plain"


def write(tmp_path, text, name="in.csv"):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8", newline="")
    return p


HEADER = "domain,host,ip,asn,prefix,netname,descr,country,eu,last_seen\r\n"


def test_a_bad_header_stores_nothing(settings, tmp_path):
    # no data field; a repeated column; nothing at all; no domain or host column
    for text in ("domain,host\r\nexample.com,example.com\r\n", HEADER.replace("eu", "host"), "",
                 "ip,country\r\n192.0.2.1,Sweden\r\n"):
        with pytest.raises(ValueError):
            run_import(settings, write(tmp_path, text))
    assert scan_count(settings) == 0


def test_bad_rows_are_skipped_and_counted(settings, tmp_path):
    rows = ["example.com,www.example.com,192.0.2.1,64500,192.0.2.0/24,NET,text,Sweden,EU,2026-03-01T10:00:00",
            "not a domain,www.example.com,192.0.2.1,,,,,,,",
            "example.com,bad host!,192.0.2.1,,,,,,,",
            "example.com,a.example.com,999.1.1.1,,,,,,,",
            "example.com,a.example.com,192.0.2.2,AS64500,,,,,,",
            "example.com,a.example.com,192.0.2.2,,not-a-net,,,,,",
            "example.com,a.example.com,192.0.2.2,,,,,,maybe,",
            "example.com,a.example.com,192.0.2.2,,,,,,,yesterday",
            "example.com,a.example.com,192.0.2.2,,,,,,,2026-02-30",
            "example.com,a.example.com,192.0.2.2,,,,,",
            "example.com,b.example.com,,,,,,,,2026-03-01",
            "example.com,info@example.com,192.0.2.3,,NA,NA,,,,",   # mailbox names and NA come from real scans
            "example.com,bad local!@example.com,192.0.2.3,,,,,,,"]
    stats = run_import(settings, write(tmp_path, HEADER + "\r\n".join(rows) + "\r\n"))
    assert (stats["rows"], stats["bad"], stats["imported"], stats["records"]) == (13, 10, 1, 3)
    assert stats["errors"][:3] == ["line 3: domain", "line 4: host", "line 5: ip"] and len(stats["errors"]) == 10
    with db.connect(settings.db_path) as c:
        assert db.history(c, "example.com")[0]["started"] == "2026-03-01T10:00:00"   # the newest last_seen


def test_the_size_cap(settings, tmp_path, monkeypatch):
    monkeypatch.setattr(csvimport, "MAX_BYTES", 100)
    with pytest.raises(csvimport.TooLarge):
        run_import(settings, write(tmp_path, HEADER + "example.com,www.example.com,192.0.2.1,,,,,,,\r\n" * 3))
    with client(settings) as h:
        csrf = sign_in(h, "adm")
        r = h.post("/admin/settings/csv-import", data={"csrf": csrf},
                   files={"file": ("big.csv", b"x" * 500, "text/csv")}, follow_redirects=False)
        assert r.status_code == 413
    assert not list(tmp_path.glob("csv-import-*")) and scan_count(settings) == 0


def test_reimport_adds_nothing_and_keeps_existing_scans(settings, tmp_path):
    fill(settings)
    f = tmp_path / "e.csv"
    f.write_bytes(export(settings, "all"))
    with db.connect(settings.db_path) as c:   # a newer own scan of a domain the file also has
        own = db.save_scan(c, "example.com", "2026-04-01T08:00:00", "scan", [{"host": "new.example.com"}])
    before = scan_count(settings)
    same = run_import(settings, f)   # this instance's own export: its times are the existing scans' times
    assert (same["imported"], same["existing"]) == (0, 2) and scan_count(settings) == before
    with db.connect(settings.db_path) as c:
        assert [r["host"] for r in db.records(c, own)] == ["new.example.com"]
    empty = replace(settings, db_path=tmp_path / "empty" / "e.db")
    empty.db_path.parent.mkdir()
    db.init(empty.db_path)
    assert (run_import(empty, f)["imported"], scan_count(empty)) == (2, 2)
    again = run_import(empty, f)
    assert (again["imported"], again["existing"], scan_count(empty)) == (0, 2, 2)


def test_out_of_scope_domains_are_skipped(settings, tmp_path):
    with db.connect(settings.db_path) as c:
        users.save_scope(c, {**users.get_scope(c), "domains_deny": ["example.org"]})
    text = HEADER + "example.com,www.example.com,192.0.2.1,,,,,,,\r\nexample.org,example.org,192.0.2.2,,,,,,,\r\n"
    stats = run_import(settings, write(tmp_path, text))
    assert (stats["imported"], stats["out_of_scope"]) == (1, 1)
    with db.connect(settings.db_path) as c:
        assert db.domain(c, "example.org") is None
        audit = c.execute("SELECT actor, action, target, detail FROM audit WHERE action = 'csv-import'").fetchone()
    assert (audit["actor"], audit["target"]) == ("cli", "in.csv") and "out of scope 1" in audit["detail"]


def upload(h, csrf, data, name="e.csv"):
    """Upload through Settings; returns the mapping page and its form as the browser would send it."""
    r = h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": (name, data, "text/csv")},
               follow_redirects=False)
    assert r.status_code == 303 and "/admin/settings/csv-import/map?t=" in r.headers["location"], r.text
    page = h.get(r.headers["location"])
    assert page.status_code == 200
    html = page.text
    form = {"csrf": csrf, "t": re.search(r'name="t" value="([^"]+)"', html)[1]}
    if re.search(r'name="header" checked', html):
        form["header"] = "on"
    for field, opts in re.findall(r'<select name="(map_\w+)">(.*?)</select>', html, re.S):
        got = re.search(r'value="(\d+)" selected', opts)
        form[field] = got[1] if got else ""
    return html, form


def test_upload_queues_a_job_that_the_worker_runs(settings, tmp_path):
    fill(settings)
    data = export(settings)
    target = replace(settings, db_path=tmp_path / "web" / "w.db")
    target.db_path.parent.mkdir()
    db.init(target.db_path)
    with db.connect(target.db_path) as c:
        users.create(c, "adm", "admin", PW)
    with client(target) as h:
        csrf = sign_in(h, "adm")
        assert 'enctype="multipart/form-data"' in h.get("/admin/settings").text
        bad = h.post("/admin/settings/csv-import", data={"csrf": "nope"}, files={"file": ("e.csv", data)},
                     follow_redirects=False)
        assert bad.status_code == 403
        assert h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": ("e.csv", b"")},
                      follow_redirects=False).status_code == 422
        assert not list(target.db_path.parent.glob("csv-import-*"))
        page, form = upload(h, csrf, data)   # domin's own export: pre-mapped, only "Import" to press
        assert form == {"csrf": csrf, "t": form["t"], "header": "on", "map_domain": "0", "map_host": "1",
                        "map_ip": "2", "map_asn": "3", "map_prefix": "4", "map_netname": "5", "map_descr": "6",
                        "map_country": "7", "map_eu": "8", "map_last_seen": "9", "map_first_seen": ""}
        assert len(list(target.db_path.parent.glob("csv-import-*.csv"))) == 1
        r = h.post("/admin/settings/csv-import/map", data={**form, "action": "import"}, follow_redirects=False)
        assert r.status_code == 303 and "import-queued" in r.headers["location"]
        assert len(list(target.db_path.parent.glob("csv-import-*.csv"))) == 1
        assert h.get(f"/admin/settings/csv-import/map?t={form['t']}").status_code == 404   # used up
        assert "Import queued" in h.get("/admin/settings").text
        assert h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": ("e.csv", data)},
                      follow_redirects=False).status_code == 409   # one at a time
        assert "e.csv by adm" in h.get("/admin/settings").text
        st = csvimport.run_pending(target)
        assert st["state"] == "done" and (st["imported"], st["user"], st["file"]) == (2, "adm", "e.csv")
        assert csvimport.run_pending(target) is None
        page = h.get("/admin/settings").text
        assert "2 imported" in page and "e.csv by adm" in page
    assert not list(target.db_path.parent.glob("csv-import-*"))   # upload and staging files removed
    assert record_set(target)[0] == record_set(settings)[0]


class FakeUpload:
    def __init__(self, body, size):
        self.body, self.size = body, size
        self.headers = {"content-type": "multipart/form-data; boundary=XyZ"}

    async def stream(self):
        for i in range(0, len(self.body), self.size):
            yield self.body[i:i + self.size]


@pytest.mark.parametrize("size", [1, 7, 4096])
def test_receive_streams_the_file_part_whatever_the_chunking(tmp_path, size):
    import asyncio
    content = b"domain,host\r\n--Xy not a boundary\r\n\r\nend"
    body = (b'--XyZ\r\nContent-Disposition: form-data; name="csrf"\r\n\r\ntok\r\n'
            b'--XyZ\r\nContent-Disposition: form-data; name="file"; filename="C:\\dir\\a.csv"\r\n'
            b"Content-Type: text/csv\r\n\r\n" + content + b"\r\n--XyZ--\r\n")
    fields, path, name = asyncio.run(csvimport.receive(FakeUpload(body, size), tmp_path))
    assert fields == {"csrf": "tok"} and name == "a.csv" and path.read_bytes() == content
    other = tmp_path / "x"
    other.mkdir()
    with pytest.raises(ValueError):   # cut short: no file left behind
        asyncio.run(csvimport.receive(FakeUpload(body[:-30], size), other))
    with pytest.raises(csvimport.TooLarge):
        asyncio.run(csvimport.receive(FakeUpload(body, size), other, cap=10))
    assert not list(other.iterdir())


def test_only_admins_reach_the_upload(settings):
    with client(settings) as h:
        r = h.post("/admin/settings/csv-import", files={"file": ("e.csv", b"x")}, follow_redirects=False)
        assert r.status_code in (303, 401, 403, 404)
        csrf = sign_in(h, "ana")
        r = h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": ("e.csv", b"x")},
                   follow_redirects=False)
        assert r.status_code == 404
    with db.connect(settings.db_path) as c:
        assert not csvimport.status(c)
    assert not list(settings.db_path.parent.glob("csv-import-*"))


def test_a_queued_file_outside_the_data_directory_is_refused(settings, tmp_path):
    other = tmp_path / "elsewhere"
    other.mkdir()
    f = write(other, HEADER + "example.com,www.example.com,192.0.2.1,,,,,,,\r\n", "csv-import-x.csv")
    with db.connect(settings.db_path) as c:
        csvimport.queue(c, f, "x.csv", "adm")
    st = csvimport.run_pending(settings)
    assert st["state"] == "failed" and f.exists() and scan_count(settings) == 0


def test_cli_import_csv(settings, tmp_path, monkeypatch, capsys):
    fill(settings)
    f = tmp_path / "e.csv"
    f.write_bytes(export(settings))
    target = tmp_path / "cli" / "c.db"
    target.parent.mkdir()
    monkeypatch.setenv("DOMIN_DB", str(target))
    assert cli.main(["import-csv", str(f)]) == 0
    assert "imported 2 (4 records)" in capsys.readouterr().out
    assert cli.main(["import-csv", str(f)]) == 0
    assert "imported 0 (0 records), already there 2" in capsys.readouterr().out
    assert cli.main(["import-csv", str(write(tmp_path, "a,b\r\n1,2\r\n"))]) == 1
    assert "not a domin CSV export" in capsys.readouterr().err
    assert Path(f).exists()   # the CLI never removes the file it was given


# ---------------------------------------------------------------- any CSV: layout detection and column mapping

def stored(s, domain):
    with db.connect(s.db_path) as c:
        sid = db.history(c, domain)[-1]["id"]   # the newest scan
        return sorted((dict(r) for r in db.records(c, sid)), key=lambda r: r["host"])


def test_renamed_reordered_semicolon_columns_with_a_junk_column(settings, tmp_path):
    text = ("Notes;FQDN;Junk;Country;IP Address;Date\r\n"
            "edge box;www.example.com;zzz;Sweden;192.0.2.10;2026-03-01 10:00:00\r\n"
            "'=cmd;mail.example.com;zzz;Norway;2001:db8::1;2026-03-02T09:00:00Z\r\n")
    f = write(tmp_path, text)
    lay = csvimport.inspect(f)
    assert (lay["delimiter"], lay["encoding"], lay["header"]) == (";", "utf-8", True)
    m = csvimport.auto_map(lay["columns"])
    assert {t: i for t, i in m.items() if i is not None} == {"host": 1, "ip": 4, "descr": 0, "country": 3,
                                                             "last_seen": 5}
    stats = run_import(settings, f)
    assert (stats["rows"], stats["bad"], stats["imported"], stats["records"]) == (2, 0, 1, 2)
    recs = stored(settings, "example.com")   # the domain derived from the host names
    assert [(r["host"], r["ip"], r["country"], r["descr"]) for r in recs] == [
        ("mail.example.com", "2001:db8::1", "Norway", "=cmd"), ("www.example.com", "192.0.2.10", "Sweden", "edge box")]
    with db.connect(settings.db_path) as c:
        assert db.history(c, "example.com")[0]["started"] == "2026-03-02T09:00:00"
        audit = c.execute("SELECT detail FROM audit WHERE action = 'csv-import'").fetchone()["detail"]
    assert "semicolon" in audit and "host=FQDN" in audit and "ip=IP Address" in audit and "Junk" not in audit


def test_a_latin1_tab_separated_file(settings, tmp_path):
    p = tmp_path / "l1.csv"
    p.write_bytes("domain\thost\tdescr\tcountry\r\nexample.se\twww.example.se\tGöteborg kontor\tSverige\r\n"
                  .encode("latin-1"))
    lay = csvimport.inspect(p)
    assert (lay["delimiter"], lay["encoding"]) == ("\t", "latin-1")
    assert run_import(settings, p)["imported"] == 1
    assert stored(settings, "example.se")[0]["descr"] == "Göteborg kontor"


def test_only_mapped_fields_are_stored(settings, tmp_path):
    fill(settings)
    f = tmp_path / "e.csv"
    f.write_bytes(export(settings))
    empty = replace(settings, db_path=tmp_path / "empty" / "e.db")
    empty.db_path.parent.mkdir()
    db.init(empty.db_path)
    lay = csvimport.inspect(f)
    m = {**csvimport.auto_map(lay["columns"]), "descr": None, "country": None, "netname": None}
    assert run_import(empty, f, mapping=m, layout=lay)["imported"] == 2
    recs = stored(empty, "example.com")
    assert {r["host"] for r in recs} == {"example.com", "www.example.com", "old.example.com"}
    assert all(r["descr"] == r["country"] == r["netname"] == "" for r in recs)
    assert {r["asn"] for r in recs} == {"64500", "64501", ""}   # mapped ones are kept


def test_host_only_input_derives_the_domain(settings, tmp_path):
    with db.connect(settings.db_path) as c:
        db.save_scan(c, "sub.example.net", "2026-01-01T00:00:00", "scan", [{"host": "sub.example.net"}])
    assert csvimport.domain_of("a.b.example.co.uk") == "example.co.uk"
    assert csvimport.domain_of("x.sub.example.net", {"example.net", "sub.example.net"}) == "sub.example.net"
    assert csvimport.domain_of("info@mail.example.org") == "example.org"
    assert csvimport.domain_of("nas.corp.example", zones=("corp.example",)) == "corp.example"
    assert csvimport.domain_of("localhost") is None
    text = ("hostname,ip\r\nwww.example.co.uk,192.0.2.1\r\nx.sub.example.net,192.0.2.2\r\n"
            "localhost,192.0.2.3\r\n")
    stats = run_import(settings, write(tmp_path, text))
    assert (stats["bad"], stats["imported"], stats["errors"]) == (1, 2, ["line 4: domain"])
    assert stored(settings, "example.co.uk")[0]["host"] == "www.example.co.uk"
    assert [r["host"] for r in stored(settings, "sub.example.net")] == ["x.sub.example.net"]


def test_missing_required_fields_are_rejected(settings, tmp_path):
    f = write(tmp_path, "domain,host,ip\r\nexample.com,www.example.com,192.0.2.1\r\n")
    lay = csvimport.inspect(f)
    for m, why in (({"ip": 2}, "domain or a host"), ({"domain": 0, "host": 1}, "data column"),
                   ({"domain": 0, "host": 0, "ip": 2}, "only one field"), ({"domain": 0, "ip": 7}, "does not have")):
        assert why in csvimport.check_mapping(m, len(lay["columns"]))
        with pytest.raises(ValueError, match=why):
            run_import(settings, f, mapping=m, layout=lay)
    assert scan_count(settings) == 0


def test_a_headerless_file_with_a_mapping(settings, tmp_path):
    f = write(tmp_path, "www.example.com,192.0.2.1,Sweden\r\nexample.com,192.0.2.2,Sweden\r\n")
    lay = csvimport.inspect(f)
    assert not lay["header"] and lay["columns"] == ["www.example.com", "192.0.2.1", "Sweden"]
    stats = run_import(settings, f, mapping={"host": 0, "ip": 1, "country": 2}, layout=lay)
    assert (stats["rows"], stats["records"]) == (2, 2)


def test_mapping_dialog_import_cancel_and_validation(settings):
    text = b"FQDN;Address;Junk\r\nwww.example.com;192.0.2.1;x\r\n"
    data_dir = settings.db_path.parent
    with client(settings) as h:
        csrf = sign_in(h, "adm")
        html, form = upload(h, csrf, text)
        assert "semicolon separated" in html and "www.example.com" in html and "— don't import —" in html
        assert (form["map_host"], form["map_ip"], form["map_domain"]) == ("0", "1", "")
        files = list(data_dir.glob("csv-import-*.csv"))
        bad = h.post("/admin/settings/csv-import/map", data={**form, "map_ip": "", "action": "import"})
        assert bad.status_code == 422 and "Map at least one data column" in bad.text
        assert h.post("/admin/settings/csv-import/map", data={**form, "csrf": "x", "action": "import"}
                      ).status_code == 403
        assert len(files) == 1 and files[0].exists()   # a rejected mapping keeps the upload for another try
        r = h.post("/admin/settings/csv-import/map", data={**form, "action": "cancel"}, follow_redirects=False)
        assert r.status_code == 303 and "import-cancelled" in r.headers["location"]
        assert not list(data_dir.glob("csv-import-*"))
        _, form = upload(h, csrf, text)
        r = h.post("/admin/settings/csv-import/map", data={**form, "action": "import"}, follow_redirects=False)
        assert r.status_code == 303 and "import-queued" in r.headers["location"]
    st = csvimport.run_pending(settings)
    assert st["state"] == "done" and st["map"] == "host=FQDN, ip=Address" and st["records"] == 1
    assert [(r["host"], r["ip"]) for r in stored(settings, "example.com")] == [("www.example.com", "192.0.2.1")]
    with db.connect(settings.db_path) as c:
        detail = c.execute("SELECT detail FROM audit WHERE action = 'csv-import'").fetchone()["detail"]
    assert "map host=FQDN, ip=Address" in detail
    assert not list(data_dir.glob("csv-import-*"))


def test_upload_tokens_expire_and_belong_to_one_user(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        users.create(c, "adm2", "admin", PW)
    text = b"host,ip\r\nwww.example.com,192.0.2.1\r\n"
    data_dir = settings.db_path.parent
    with client(settings) as h, client(settings) as other:
        csrf = sign_in(h, "adm")
        csrf2 = sign_in(other, "adm2")
        _, form = upload(h, csrf, text)
        url = f"/admin/settings/csv-import/map?t={form['t']}"
        assert other.get(url).status_code == 404   # another admin: not theirs
        for action in ("import", "cancel"):
            assert other.post("/admin/settings/csv-import/map", data={**form, "csrf": csrf2, "action": action}
                              ).status_code == 404
        assert h.get(url).status_code == 200 and len(list(data_dir.glob("csv-import-*.csv"))) == 1
        assert h.get("/admin/settings/csv-import/map?t=" + "A" * 32).status_code == 404   # unknown
        later = csvimport.time.time() + csvimport.UPLOAD_TTL + 1
        monkeypatch.setattr(csvimport.time, "time", lambda: later)
        assert h.get(url).status_code == 404   # expired: the file is removed at once
        assert not list(data_dir.glob("csv-import-*"))
        assert h.post("/admin/settings/csv-import/map", data={**form, "action": "import"}).status_code == 404
    with db.connect(settings.db_path) as c:
        assert not csvimport.busy(c) and scan_count(settings) == 0


def test_the_worker_sweeps_expired_and_orphaned_uploads(settings):
    data_dir = settings.db_path.parent
    held, orphan, fresh = (data_dir / f"csv-import-{n}.csv" for n in ("held", "orphan", "fresh"))
    for p in (held, orphan, fresh):
        p.write_text("host,ip")
    old = csvimport.time.time() - csvimport.UPLOAD_TTL - 10
    os.utime(orphan, (old, old))
    with db.connect(settings.db_path) as c:
        token = csvimport.hold(c, held, "h.csv", 1, "", {"columns": []})
        c.execute("UPDATE kv SET value = json_set(value, '$.at', ?) WHERE key = ?",
                  (old, csvimport.UPLOAD_KEY + token))
        c.commit()
    assert csvimport.run_pending(settings) is None   # nothing queued; the sweep still ran
    assert not held.exists() and not orphan.exists() and fresh.exists()
    with db.connect(settings.db_path) as c:
        assert admin.kv_get(c, csvimport.UPLOAD_KEY + token) is None


def test_only_admins_reach_the_mapping(settings):
    with client(settings) as h:
        csrf = sign_in(h, "adm")
        _, form = upload(h, csrf, b"host,ip\r\nwww.example.com,192.0.2.1\r\n")
    with client(settings) as h:
        r = h.get(f"/admin/settings/csv-import/map?t={form['t']}", follow_redirects=False)
        assert r.status_code in (303, 401, 403, 404)
        csrf = sign_in(h, "ana")
        assert h.get(f"/admin/settings/csv-import/map?t={form['t']}").status_code == 404
        assert h.post("/admin/settings/csv-import/map", data={**form, "csrf": csrf, "action": "import"}
                      ).status_code == 404
    with db.connect(settings.db_path) as c:
        assert not csvimport.status(c)
    assert len(list(settings.db_path.parent.glob("csv-import-*.csv"))) == 1   # still the admin's


def test_cli_map_and_delimiter(settings, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DOMIN_DB", str(settings.db_path))
    f = write(tmp_path, "a|x;b;c\r\nwww.example.com;192.0.2.1;Sweden\r\n")
    assert cli.main(["import-csv", str(f)]) == 1
    err = capsys.readouterr().err
    assert "map a domain or a host column" in err and "--map field=column" in err
    assert cli.main(["import-csv", str(f), "--delimiter", ";", "--map", "host=1", "--map", "ip=b",
                     "--map", "country=C"]) == 0
    out = capsys.readouterr().out
    assert "semicolon separated" in out and "host=a|x, ip=b, country=c" in out and "imported 1 (1 records)" in out
    assert cli.main(["import-csv", str(f), "--map", "nope=1"]) == 1
    assert "unknown field" in capsys.readouterr().err
