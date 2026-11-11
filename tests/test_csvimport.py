import re
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_fingerprint import PW

from domin import __main__ as cli
from domin import csvimport, db, users
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
    for text in ("name,address\r\nexample.com,192.0.2.1\r\n", "domain,host\r\nexample.com,example.com\r\n",
                 HEADER.replace("eu", "extra"), HEADER.replace("eu", "host"), ""):
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
        r = h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": ("e.csv", data, "text/csv")},
                   follow_redirects=False)
        assert r.status_code == 303 and "import-queued" in r.headers["location"]
        assert len(list(target.db_path.parent.glob("csv-import-*.csv"))) == 1
        assert "Import queued" in h.get("/admin/settings").text
        assert h.post("/admin/settings/csv-import", data={"csrf": csrf}, files={"file": ("e.csv", data)},
                      follow_redirects=False).status_code == 409   # one at a time
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
