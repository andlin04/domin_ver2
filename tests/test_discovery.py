"""nmap discovery profiles and stage (docs/scheduled-scans.md): the argument allowlist, the targets per mode, the
profile page and "Scan with nmap". nmap never runs: the stage gets a fake runner."""
import re
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from domin import access, db, discovery, jobs, proxy, users
from domin.config import Settings
from domin.web import COOKIE, create_app

PW = "correct horse battery"
BAD = ("hello", "80;echo probe", "-1", "99999", "1-2-3")   # harmless invalid inputs only

BASE_FORM = {"name": "probe", "method": "syn", "probe_ports": "22,80,443", "port_mode": "none", "top_ports": "100",
             "ports": "", "timing": "3", "max_rate": "50", "max_retries": "1", "host_timeout": "120", "route": "",
             "note": ""}


def prof(**kw):
    p, err = discovery.check({**BASE_FORM, **kw}, routes={"tor"}, raw_ok=True)
    assert p, err
    return p


# --- argv from each option ---------------------------------------------------------------------------------------

def test_argv_for_each_method():
    want = {"default": None, "none": "-Pn", "syn": "-PS22,80,443", "ack": "-PA22,80,443", "udp": "-PU22,80,443",
            "echo": "-PE", "timestamp": "-PP"}
    for method, flag in want.items():
        form = {"method": method}
        if method == "none":
            form["port_mode"] = "top"   # -Pn alone is refused
        args = discovery.nmap_args(prof(**form), "/tmp/t.txt")
        assert args[0] == "nmap" and args[-4:] == ["-oX", "-", "-iL", "/tmp/t.txt"]
        if flag:
            assert flag in args, method
        else:
            assert not [a for a in args if re.fullmatch(r"-P[A-Z].*", a)], method


def test_argv_for_port_checks_timing_rate_retries_timeout_and_dns():
    a = discovery.nmap_args(prof(), "t")
    assert "-sn" in a and "-n" in a and "-T3" in a and a[a.index("--max-rate") + 1] == "50"
    assert a[a.index("--max-retries") + 1] == "1" and a[a.index("--host-timeout") + 1] == "120s"
    a = discovery.nmap_args(prof(port_mode="top", top_ports="20", timing="5", max_rate="0", max_retries="0",
                                 host_timeout="10"), "t")
    assert a[a.index("--top-ports") + 1] == "20" and "-sT" in a and "-sn" not in a and "-T5" in a
    assert "--max-rate" not in a and a[a.index("--max-retries") + 1] == "0" and "10s" in a
    a = discovery.nmap_args(prof(port_mode="list", ports="22,8000-8010", timing="0"), "t")
    assert a[a.index("-p") + 1] == "22,8000-8010" and "-T0" in a
    a = discovery.nmap_args(prof(rdns="on"), "t", dns_servers=("172.20.0.252",))
    assert "-R" in a and "-n" not in a and a[a.index("--dns-servers") + 1] == "172.20.0.252"


def test_argv_raw_routed_and_ipv6():
    p = prof(port_mode="top", rdns="on")
    raw = discovery.nmap_args(p, "t", raw=True)
    assert "-sS" in raw and "--privileged" in raw
    routed = discovery.nmap_args(p, "t", raw=True, routed=True)
    assert "-sT" in routed and "--privileged" not in routed and "-n" in routed and "-R" not in routed
    assert discovery.nmap_args(p, "t", ipv6=True)[1] == "-6"
    assert discovery.command_line(prof()) == ("nmap -PS22,80,443 -sn -n -T3 --max-retries 1 --host-timeout 120s "
                                              "--max-rate 50 -oX - -iL <targets>")


# --- rejection of invalid values ---------------------------------------------------------------------------------

def test_invalid_values_are_refused():
    for bad in BAD:
        for field in ("timing", "max_rate", "max_retries", "host_timeout", "top_ports"):
            p, err = discovery.check({**BASE_FORM, field: bad}, raw_ok=True)
            assert p is None and err, (field, bad)
        assert discovery.check({**BASE_FORM, "probe_ports": bad}, raw_ok=True)[0] is None, bad
        assert discovery.check({**BASE_FORM, "port_mode": "list", "ports": bad}, raw_ok=True)[0] is None, bad
        for field in ("method", "port_mode", "route"):
            assert discovery.check({**BASE_FORM, field: bad}, raw_ok=True)[0] is None, (field, bad)
    for bad in ("80;echo probe", "-1", ""):
        assert discovery.check({**BASE_FORM, "name": bad})[0] is None, bad
    assert discovery.port_count("1-2-3") is None and discovery.port_count("65535") == 1
    assert discovery.check({**BASE_FORM, "method": "none"})[0] is None   # -Pn without a port check
    for method in ("ack", "udp", "echo", "timestamp"):   # raw-only without raw sockets
        assert discovery.check({**BASE_FORM, "method": method}, raw_ok=False)[0] is None
        assert discovery.check({**BASE_FORM, "method": method}, raw_ok=True)[0]
    assert discovery.check({**BASE_FORM, "probe_ports": "1-101"})[0] is None   # over PROBE_MAX
    assert discovery.check({**BASE_FORM, "route": "r1"}, routes={"r1"})[0]


def test_accepted_profiles_put_no_free_text_on_the_command_line():
    p = prof(note="80;echo probe", port_mode="list", ports="22,443")
    for a in discovery.nmap_args(p, "t"):
        assert ";" not in a and " " not in a


# --- targets: public mode never sweeps beyond the domain's addresses ---------------------------------------------

@pytest.fixture
def conn(tmp_path):
    path = tmp_path / "t.db"
    db.init(path)
    with db.connect(path) as c:
        yield c


def fake_run(seen, xml="<nmaprun></nmaprun>"):
    def run(args, timeout, via=None):
        seen.append({"args": args, "targets": Path(args[-1]).read_text().split(), "via": via})
        return xml
    return run


XML = """<nmaprun><host><status state="up" reason="syn-ack"/><address addr="172.20.4.20" addrtype="ipv4"/>
<hostnames><hostname name="nas.home.arpa"/></hostnames><ports><port protocol="tcp" portid="22">
<state state="open"/></port></ports></host><host><status state="down" reason="no-response"/>
<address addr="172.20.4.21" addrtype="ipv4"/></host><host><status state="up" reason="user-set"/>
<address addr="172.20.4.22" addrtype="ipv4"/></host></nmaprun>"""


def test_public_mode_sweeps_only_this_scans_global_addresses(conn):
    s = replace(Settings.from_env(), internal_nets=("172.20.4.0/24",))
    records = [{"host": "www.example.org", "ip": "9.9.9.9"}, {"host": "mail.example.org", "ip": "9.9.9.9"},
               {"host": "v6.example.org", "ip": "2620:fe::fe"}, {"host": "lan.example.org", "ip": "172.20.4.20"},
               {"host": "doc.example.org", "ip": "192.0.2.1"}, {"host": "gone.example.org", "ip": ""}]
    seen, notes = [], []
    out = discovery.stage(conn, "default", records, False, s, notes, run=fake_run(seen), raw_capable=lambda: False)
    swept = [t for r in seen for t in r["targets"]]
    assert sorted(swept) == ["2620:fe::fe", "9.9.9.9"] and out["targets"] == ["9.9.9.9", "2620:fe::fe"]
    assert "-6" in seen[1]["args"] and "<1 addresses>" in out["params"]
    assert not Path(seen[0]["args"][-1]).exists()   # the targets file is removed
    users.save_scope(conn, {**users.get_scope(conn), "ip_deny": ["9.9.9.0/24"]})   # posture scope applies
    seen.clear()
    discovery.stage(conn, "default", records, False, s, notes, run=fake_run(seen), raw_capable=lambda: False)
    assert [t for r in seen for t in r["targets"]] == ["2620:fe::fe"]


def test_internal_mode_sweeps_the_internal_networks_and_adds_names_under_the_domain(conn):
    s = replace(Settings.from_env(), internal_nets=("172.20.4.16/29",), internal_dns=("172.20.0.252",))
    seen, notes = [], []
    p = prof(rdns="on")
    discovery.save(conn, {**p, "name": "lan"}, "t")
    out = discovery.stage(conn, "lan", [], True, s, notes, run=fake_run(seen, XML), raw_capable=lambda: False)
    assert seen[0]["targets"] == [f"172.20.4.{i}" for i in range(17, 23)] and seen[0]["via"] is None
    assert "--dns-servers" in seen[0]["args"]
    assert [f["ip"] for f in out["found"]] == ["172.20.4.20", "172.20.4.22"]
    assert out["found"][0]["ports"] == ["22/tcp"] and out["found"][0]["names"] == ["nas.home.arpa"]
    new = discovery.new_records(out["found"], [], "home.arpa")
    assert [(r["host"], r["ip"]) for r in new] == [("nas.home.arpa", "172.20.4.20")]
    assert discovery.new_records(out["found"], [], "other.example") == []


def test_stage_notes_instead_of_failing(conn):
    s = Settings.from_env()
    rec = [{"host": "www.example.org", "ip": "9.9.9.9"}]
    notes = []
    discovery.stage(conn, "missing", rec, False, s, notes, run=fake_run([]))
    discovery.stage(conn, "default", rec, True, replace(s, internal_nets=()), notes, run=fake_run([]))
    discovery.stage(conn, "default", [{"host": "x.example.org", "ip": "10.0.0.1"}], False, s, notes, run=fake_run([]))
    discovery.save(conn, {**prof(method="echo"), "name": "icmp"}, "t")
    discovery.stage(conn, "icmp", rec, False, s, notes, run=fake_run([]), raw_capable=lambda: False)
    assert [n.split(":")[0] for n in notes] == ["nmap discovery skipped"] * 4
    assert discovery.parse(XML, open_only=True)[0]["ip"] == "172.20.4.20"   # -Pn: only hosts with an open port


def test_a_proxy_route_carries_only_no_ping_with_a_port_check(conn, monkeypatch):
    monkeypatch.setattr(proxy, "pick", lambda cfg, rid, use: rid)
    monkeypatch.setattr(proxy, "hop", lambda c, rid: {"id": rid, "kind": "socks5", "host": "127.0.0.1",
                                                       "port": 9050} if rid else None)
    monkeypatch.setattr(proxy, "route", lambda via: via["id"])
    s = Settings.from_env()
    rec = [{"host": "www.example.org", "ip": "9.9.9.9"}]
    discovery.save(conn, {**prof(route="tor"), "name": "via"}, "t")
    seen, notes = [], []
    discovery.stage(conn, "via", rec, False, s, notes, run=fake_run(seen))
    assert not seen and "proxy" in notes[0]
    discovery.save(conn, {**prof(method="none", port_mode="list", ports="443", route="tor"), "name": "via"}, "t")
    discovery.stage(conn, "via", rec, False, s, notes, run=fake_run(seen))
    assert seen and "-sT" in seen[0]["args"] and "-n" in seen[0]["args"] and seen[0]["via"]["id"] == "tor"


def test_a_job_with_a_profile_saves_the_stage(tmp_path, monkeypatch):
    from domin import scanner
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db")
    db.init(s.db_path)
    calls = []

    def fake_scan(conn, domain, settings, progress, notes=None, nmap="", stage=None):
        calls.append(nmap)
        if nmap:
            stage.update({"params": "nmap -PS22 -sn <1 addresses>",
                          "found": [{"ip": "9.9.9.9", "names": [], "ports": [], "reason": "syn-ack"}]})
        return [{"host": "www." + domain, "ip": "9.9.9.9"}]
    monkeypatch.setattr(scanner, "run", fake_scan)
    with db.connect(s.db_path) as c:
        jobs.enqueue(c, "example.org", client="admin", discovery="default")
        job = jobs.claim(c)
    jobs.run_job(s, job)
    with db.connect(s.db_path) as c:
        scan = db.history(c, "example.org")[-1]
        assert calls == ["default"] and scan["discovery"] == "default" and "-PS22" in scan["discovery_params"]
        assert db.discovery_results(c, scan["id"])[0]["reason"] == "syn-ack"


# --- migration -----------------------------------------------------------------------------------------------------

def test_migration_adds_the_new_columns_and_tables_to_an_existing_db(tmp_path):
    path = tmp_path / "old.db"
    db.init(path)
    c = sqlite3.connect(path)   # back to the schema before this change
    for stmt in ("DROP TABLE schedules", "DROP TABLE discovery_results", "DROP TABLE discovery_profiles",
                 "DROP INDEX jobs_schedule", "DROP INDEX posture_schedule", "ALTER TABLE jobs DROP COLUMN discovery",
                 "ALTER TABLE jobs DROP COLUMN schedule_id", "ALTER TABLE scans DROP COLUMN discovery",
                 "ALTER TABLE scans DROP COLUMN discovery_params", "ALTER TABLE posture_scans DROP COLUMN schedule_id"):
        c.execute(stmt)
    c.execute("INSERT INTO jobs (domain, status, created, client) VALUES ('old.example', 'done', '2026-01-01', '')")
    c.commit()
    c.close()
    db.init(path)
    db.init(path)   # idempotent
    with db.connect(path) as c:
        cols = {t: {r[1] for r in c.execute(f"PRAGMA table_info({t})")} for t in ("jobs", "scans", "posture_scans")}
        assert {"discovery", "schedule_id"} <= cols["jobs"] and {"discovery", "discovery_params"} <= cols["scans"]
        assert "schedule_id" in cols["posture_scans"]
        assert c.execute("SELECT discovery, schedule_id FROM jobs").fetchone()[:] == ("", None)
        assert discovery.profile(c, "default")["method"] == "syn"
        assert c.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0


# --- web: profile page and "Scan with nmap" ------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        pia = users.create(c, "pia", "power", PW)
        access.set_grants(c, pia, {"alpha.example": "viewer", "beta.example": "admin"}, "test")
        for dom, ip in (("alpha.example", "9.9.9.9"), ("beta.example", "9.9.9.10"), ("gamma.example", "9.9.9.11")):
            db.save_scan(c, dom, db.now(), "scan", [{"host": "www." + dom, "ip": ip}])
    return s


def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h, name):
    r = h.post("/admin/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get("/admin/account").text).group(1)


def test_admin_saves_a_profile_and_sees_its_command_line(settings):
    with client(settings) as h:
        csrf = login(h, "boss")
        r = h.post("/admin/security/discovery-profiles", data={**BASE_FORM, "csrf": csrf}, follow_redirects=False)
        assert r.status_code == 303
        page = h.get("/admin/security/discovery-profiles").text
        assert "nmap -PS22,80,443 -sn -n -T3 --max-retries 1 --host-timeout 120s --max-rate 50" in page
        for bad in BAD:
            r = h.post("/admin/security/discovery-profiles", data={**BASE_FORM, "csrf": csrf, "timing": bad})
            assert r.status_code == 422
        assert h.post("/admin/security/discovery-profiles/default", data={"csrf": csrf, "name": "probe"}
                      ).status_code == 200
        assert 'selected>probe</option>' in h.get("/admin/security/discovery-profiles").text
        assert h.post("/admin/security/discovery-profiles/default/delete", data={"csrf": csrf}).status_code == 422
        assert h.post("/admin/security/discovery-profiles/probe/delete", data={"csrf": csrf}).status_code == 200
    with db.connect(settings.db_path) as c:
        assert discovery.profile(c, "probe") is None and discovery.get_default(c) == ""
        assert [r["action"] for r in access.audit_recent(c)][:3] == ["discovery-profile-delete",
                                                                     "discovery-profile-default",
                                                                     "discovery-profile-save"]


def test_power_users_read_profiles_but_cannot_change_them(settings):
    with client(settings) as h:
        csrf = login(h, "pia")
        assert "--max-retries" in h.get("/admin/security/discovery-profiles").text
        assert h.post("/admin/security/discovery-profiles", data={**BASE_FORM, "csrf": csrf}).status_code == 403
        assert h.post("/admin/security/discovery-profiles/default", data={"csrf": csrf, "name": "default"}
                      ).status_code == 403
        assert h.post("/admin/security/discovery-profiles/default/delete", data={"csrf": csrf}).status_code == 403
    with db.connect(settings.db_path) as c:
        assert discovery.profile(c, "probe") is None


def test_scan_with_nmap_queues_a_job_with_the_profile_for_domain_admins_only(settings):
    with client(settings) as h:
        csrf = login(h, "pia")
        assert 'action="/admin/discovery/scan"' in h.get("/d/beta.example").text
        assert 'action="/admin/discovery/scan"' not in h.get("/d/alpha.example").text   # viewer

        def post(dom, p="default"):
            return h.post("/admin/discovery/scan", data={"csrf": csrf, "domain": dom, "profile": p},
                          follow_redirects=False)
        assert post("alpha.example").status_code == 403
        assert post("gamma.example").status_code == 404 and post("nowhere.example").status_code == 404
        assert post("beta.example", "hello").status_code == 422
        r = post("beta.example")
        assert r.status_code == 303 and "ok=discovery-queued" in r.headers["location"]
        assert "ok=discovery-open" in post("beta.example").headers["location"]   # one open job per domain
    with db.connect(settings.db_path) as c:
        rows = [dict(r) for r in c.execute("SELECT domain, client, discovery FROM jobs")]
        assert rows == [{"domain": "beta.example", "client": "admin", "discovery": "default"}]
