"""Scheduled rescans (docs/scheduled-scans.md): next-run times incl. month ends and DST, the runner on a fake clock
(due, queueing with the chosen profiles and hosts, busy skip, missed runs, hosts gone), and the rights per level.
No real sleeps, no nmap: the runner only queues."""
import calendar
import json
import re
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta, tzinfo
from datetime import time as dtime

import pytest
from fastapi.testclient import TestClient

from domin import access, db, discovery, jobs, posture, schedules, users
from domin.config import Settings
from domin.web import COOKIE, create_app

PW = "correct horse battery"


class Stockholm(tzinfo):
    """Europe/Stockholm without tzdata: CET, CEST from the last Sunday of March 01:00 UTC to the last Sunday of
    October 01:00 UTC. PEP 495 folds: a gap time counts with the offset before the change, a repeated time is its
    first occurrence at fold 0."""
    H = timedelta(hours=1)

    @staticmethod
    def _last_sunday(year, month):
        d = date(year, month, calendar.monthrange(year, month)[1])
        return d - timedelta(days=(d.weekday() - 6) % 7)

    def _bounds(self, year):   # DST start and end, naive UTC
        return (datetime.combine(self._last_sunday(year, 3), dtime(1)),
                datetime.combine(self._last_sunday(year, 10), dtime(1)))

    def utcoffset(self, dt):
        start, end = self._bounds(dt.year)
        wall = dt.replace(tzinfo=None, fold=0)
        gap, rep = start + self.H, end + self.H   # 02:00 wall: the skipped and the repeated hour start
        if gap <= wall < gap + self.H:
            return 2 * self.H if dt.fold else self.H
        if rep <= wall < rep + self.H:
            return self.H if dt.fold else 2 * self.H
        return 2 * self.H if gap + self.H <= wall < rep else self.H

    def dst(self, dt):
        return self.utcoffset(dt) - self.H

    def tzname(self, dt):
        return "CEST" if self.dst(dt) else "CET"

    def fromutc(self, dt):
        u = dt.replace(tzinfo=None)
        start, end = self._bounds(u.year)
        summer = start <= u < end
        local = u + (2 * self.H if summer else self.H)
        return local.replace(tzinfo=self, fold=1 if end <= u < end + self.H else 0)


STO = Stockholm()


def ts(text, tz=STO):
    return schedules.to_ts(datetime.fromisoformat(text), tz)


def at(epoch, tz=STO):
    return schedules.stamp(epoch, tz)[:16]


def sched(**kw):
    return {"freq": "daily", "at_time": "03:00", "weekday": 0, "monthday": 1, "every": 1, "anchor": "", **kw}


# --- next run ------------------------------------------------------------------------------------------------------

def test_daily_weekly_and_strictly_after():
    s = sched()
    assert at(schedules.next_after(s, ts("2026-11-11T02:00"), STO)) == "2026-11-11T03:00"
    assert at(schedules.next_after(s, ts("2026-11-11T03:00"), STO)) == "2026-11-12T03:00"
    w = sched(freq="weekly", weekday=6, at_time="22:15")   # Sunday
    assert at(schedules.next_after(w, ts("2026-11-11T12:00"), STO)) == "2026-11-15T22:15"
    assert at(schedules.next_after(w, ts("2026-11-15T22:15"), STO)) == "2026-11-22T22:15"


def test_monthly_clamps_to_the_last_day_of_shorter_months():
    s = sched(freq="monthly", monthday=31)
    t = ts("2026-01-31T03:00")
    got = []
    for _ in range(4):
        t = schedules.next_after(s, t, STO)
        got.append(at(t))
    assert got == ["2026-02-28T03:00", "2026-03-31T03:00", "2026-04-30T03:00", "2026-05-31T03:00"]
    leap = sched(freq="monthly", monthday=30)
    assert at(schedules.next_after(leap, ts("2028-02-01T00:00"), STO)) == "2028-02-29T03:00"
    assert at(schedules.next_after(sched(freq="monthly", monthday=31), ts("2026-12-31T04:00"), STO)) == \
        "2027-01-31T03:00"


def test_dst_spring_gap_and_autumn_repeat():
    # 2026-03-29: 02:00 CET -> 03:00 CEST. A daily 02:30 runs at 03:30 that day (the offset before the change)
    s = sched(at_time="02:30")
    spring = schedules.next_after(s, ts("2026-03-29T00:00"), STO)
    assert datetime.fromtimestamp(spring, UTC).strftime("%H:%M") == "01:30" and at(spring) == \
        "2026-03-29T03:30"
    assert at(schedules.next_after(s, spring, STO)) == "2026-03-30T02:30"
    # a daily 03:00 keeps its wall time across the change (23 h apart)
    d = sched()
    a = schedules.next_after(d, ts("2026-03-28T00:00"), STO)
    b = schedules.next_after(d, a, STO)
    assert at(b) == "2026-03-29T03:00" and b - a == 23 * 3600
    # 2026-10-25: 03:00 CEST -> 02:00 CET. A daily 02:30 runs once, at its first occurrence
    autumn = schedules.next_after(s, ts("2026-10-25T00:00"), STO)
    assert datetime.fromtimestamp(autumn, UTC).strftime("%H:%M") == "00:30"
    assert at(schedules.next_after(s, autumn, STO)) == "2026-10-26T02:30"
    assert at(schedules.next_after(d, ts("2026-10-25T00:00"), STO)) == "2026-10-25T03:00"


def test_every_n_hours_and_days():
    h = sched(freq="hours", every=6, at_time="01:00", anchor="2026-11-11T01:00")
    assert at(schedules.next_after(h, ts("2026-11-11T00:00"), STO)) == "2026-11-11T01:00"
    assert at(schedules.next_after(h, ts("2026-11-11T08:00"), STO)) == "2026-11-11T13:00"
    assert at(schedules.next_after(h, ts("2026-11-14T13:00"), STO)) == "2026-11-14T19:00"
    across = sched(freq="hours", every=24, at_time="12:00", anchor="2026-03-28T12:00")   # real elapsed hours
    assert at(schedules.next_after(across, ts("2026-03-28T12:00"), STO)) == "2026-03-29T13:00"
    d = sched(freq="days", every=3, at_time="04:00", anchor="2026-11-01T04:00")
    assert at(schedules.next_after(d, ts("2026-11-01T04:00"), STO)) == "2026-11-04T04:00"
    assert at(schedules.next_after(d, ts("2026-11-05T00:00"), STO)) == "2026-11-07T04:00"
    assert at(schedules.next_after(d, ts("2026-10-20T00:00"), STO)) == "2026-11-01T04:00"


# --- form checks ---------------------------------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    s = replace(Settings.from_env(), db_path=tmp_path / "t.db", admin_ips=())
    db.init(s.db_path)
    with db.connect(s.db_path) as c:
        users.create(c, "boss", "admin", PW)
        pia = users.create(c, "pia", "power", PW)
        users.create(c, "nob", "power", PW)
        access.set_grants(c, pia, {"alpha.example": "viewer", "beta.example": "admin"}, "test")
        for dom, n in (("alpha.example", 1), ("beta.example", 2), ("gamma.example", 3)):
            db.save_scan(c, dom, db.now(), "scan", [{"host": f"www.{dom}", "ip": f"9.9.{n}.1"},
                                                    {"host": f"mail.{dom}", "ip": f"9.9.{n}.2"},
                                                    {"host": f"db.{dom}", "ip": f"9.9.{n}.3"}])
        users.save_scope(c, {**users.get_scope(c), "ip_allow": ["9.9.0.0/16"]})
    return s


FORM = {"name": "nightly", "enabled": "on", "discovery": "on", "discovery_profile": "default", "posture": "",
        "posture_profile": "default", "host_mode": "all", "tag": "", "freq": "daily", "at_time": "03:00",
        "weekday": "0", "monthday": "1", "every": "1"}


def test_form_check_refuses_invalid_values(settings):
    with db.connect(settings.db_path) as c:
        assert schedules.check(c, "beta.example", FORM)[0]
        for k, bad in (("freq", "hello"), ("at_time", "80;echo probe"), ("at_time", "24:00"),
                       ("at_time", "1-2-3"), ("discovery_profile", "hello"), ("host_mode", "hello")):
            assert schedules.check(c, "beta.example", {**FORM, k: bad})[0] is None, (k, bad)
        for k, freq in (("weekday", "weekly"), ("monthday", "monthly"), ("every", "hours"), ("every", "days")):
            for bad in ("hello", "-1", "99999", "1-2-3"):
                assert schedules.check(c, "beta.example", {**FORM, "freq": freq, k: bad})[0] is None, (k, bad)
        assert schedules.check(c, "beta.example", {**FORM, "discovery": ""})[0] is None   # nothing to run
        post = {**FORM, "posture": "on", "host_mode": "list"}
        assert schedules.check(c, "beta.example", post)[0] is None   # no host ticked
        assert schedules.check(c, "beta.example", {**post, "h:www.alpha.example": "on"})[0] is None   # not this domain
        p, _ = schedules.check(c, "beta.example", {**post, "h:www.beta.example": "on"})
        assert json.loads(p["hosts"]) == ["www.beta.example"]
        assert schedules.check(c, "beta.example", {**post, "posture_profile": "hello"})[0] is None
        assert schedules.check(c, "beta.example", {**FORM, "posture": "on", "host_mode": "tag", "tag": "80;echo probe"}
                               )[0] is None


# --- the runner on a fake clock ------------------------------------------------------------------------------------

def make(c, dom="beta.example", now="2026-11-11T02:00", **kw):
    p, err = schedules.check(c, dom, {**FORM, **kw})
    assert p, err
    return schedules.create(c, dom, p, "pia", now=ts(now), tz=STO)


def finish_jobs(c, status="done"):
    c.execute("UPDATE jobs SET status = ?, finished = ? WHERE status IN ('queued', 'running')", (status, db.now()))


def test_due_schedule_queues_one_job_with_its_profile_and_moves_next_run(settings):
    with db.connect(settings.db_path) as c:
        sid = make(c)
        s = schedules.get(c, sid)
        assert s["next_run"] == "2026-11-11T03:00:00"
        assert schedules.tick(c, ts("2026-11-11T02:59"), STO) == []
        assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert len(schedules.tick(c, ts("2026-11-11T03:00"), STO)) == 1
        job = dict(c.execute("SELECT * FROM jobs").fetchone())
        assert (job["domain"], job["client"], job["discovery"], job["schedule_id"]) == \
            ("beta.example", jobs.SCHEDULE, "default", sid)
        s = schedules.get(c, sid)
        assert s["next_run"] == "2026-11-12T03:00:00" and s["last_job"] == job["id"] and s["last_run"].startswith(
            "2026-11-11T03:00")
        assert schedules.tick(c, ts("2026-11-11T03:01"), STO) == []   # not due again
        assert jobs.queued(c) == 0   # the refresh queue, not the visitors'


def test_posture_only_with_chosen_hosts_queues_those_addresses_with_the_profile(settings):
    with db.connect(settings.db_path) as c:
        posture.save_profile(c, {"name": "quick", "ports": "22,443", "intensity": 0, "timing": 4, "timeout": 60,
                                 "route": ""}, "", "boss")
        sid = make(c, discovery="", posture="on", posture_profile="quick", host_mode="list",
                   **{"h:www.beta.example": "on", "h:db.beta.example": "on"})
        schedules.tick(c, ts("2026-11-11T03:00"), STO)
        rows = [dict(r) for r in c.execute("SELECT ip, hosts, ports, profile, schedule_id FROM posture_scans "
                                           "ORDER BY ip")]
        assert [(r["ip"], r["hosts"], r["ports"], r["profile"], r["schedule_id"]) for r in rows] == [
            ("9.9.2.1", "www.beta.example", "22,443", "quick", sid),
            ("9.9.2.3", "db.beta.example", "22,443", "quick", sid)]
        assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0
        assert "2 address(es) queued with profile quick" in schedules.get(c, sid)["last_result"]


def test_discovery_then_posture_waits_for_the_inventory_job(settings):
    with db.connect(settings.db_path) as c:
        sid = make(c, posture="on", host_mode="list", **{"h:mail.beta.example": "on"})
        schedules.tick(c, ts("2026-11-11T03:00"), STO)
        assert schedules.get(c, sid)["wait_job"] and c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 0
        schedules.tick(c, ts("2026-11-11T03:01"), STO)   # job still queued: posture waits
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 0
        finish_jobs(c)
        schedules.tick(c, ts("2026-11-11T03:02"), STO)
        assert [r[0] for r in c.execute("SELECT ip FROM posture_scans WHERE schedule_id = ?", (sid,))] == ["9.9.2.2"]
        s = schedules.get(c, sid)
        assert s["wait_job"] is None and "posture: 1 address(es) queued" in s["last_result"]
        # a failed inventory job: no posture
        c.execute("UPDATE posture_scans SET status = 'done'")
        schedules.tick(c, ts("2026-11-12T03:00"), STO)
        finish_jobs(c, "failed")
        schedules.tick(c, ts("2026-11-12T03:01"), STO)
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 1
        assert "posture not queued" in schedules.get(c, sid)["last_result"]


def test_a_run_whose_previous_one_is_open_is_skipped_and_logged(settings, caplog):
    with db.connect(settings.db_path) as c:
        sid = make(c)
        schedules.tick(c, ts("2026-11-11T03:00"), STO)
        c.execute("UPDATE jobs SET status = 'running'")
        with caplog.at_level("WARNING", logger="domin.schedules"):
            schedules.tick(c, ts("2026-11-12T03:00"), STO)
        assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        s = schedules.get(c, sid)
        assert s["last_result"].startswith("skipped") and s["next_run"] == "2026-11-13T03:00:00"
        assert "previous run still queued or running" in caplog.text
        assert schedules.run_now(c, sid, ts("2026-11-12T04:00"), STO) is None
        # posture scans of the schedule count as open too
        finish_jobs(c)
        c.execute("INSERT INTO posture_scans (domain, ip, ports, status, created, schedule_id) VALUES "
                  "('beta.example', '9.9.2.1', '22', 'running', ?, ?)", (db.now(), sid))
        schedules.tick(c, ts("2026-11-13T03:00"), STO)
        assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1


def test_missed_runs_run_once_without_catch_up(settings):
    with db.connect(settings.db_path) as c:
        sid = make(c)
        done = schedules.tick(c, ts("2026-11-15T10:00"), STO)   # four slots missed while down
        assert len(done) == 1 and c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 1
        assert schedules.get(c, sid)["next_run"] == "2026-11-16T03:00:00"
        finish_jobs(c)
        assert schedules.tick(c, ts("2026-11-15T10:01"), STO) == []


def test_chosen_hosts_gone_from_the_inventory_are_skipped_and_shown(settings):
    with db.connect(settings.db_path) as c:
        sid = make(c, discovery="", posture="on", host_mode="list",
                   **{"h:www.beta.example": "on", "h:db.beta.example": "on"})
        later = (datetime.now() + timedelta(minutes=1)).isoformat(timespec="seconds")
        db.save_scan(c, "beta.example", later, "scan", [{"host": "www.beta.example", "ip": "9.9.2.1"}])
        schedules.tick(c, ts("2026-11-11T03:00"), STO)
        assert [r[0] for r in c.execute("SELECT hosts FROM posture_scans")] == ["www.beta.example"]
        assert "skipped: db.beta.example" in schedules.get(c, sid)["last_result"]
        assert schedules.for_domain(c, "beta.example")[0]["missing"] == ["db.beta.example"]


def test_tag_mode_disabled_schedules_and_inventory_scope(settings):
    from domin import tags
    with db.connect(settings.db_path) as c:
        tags.add(c, "mail.beta.example", "mailer", "pia")
        sid = make(c, discovery="", posture="on", host_mode="tag", tag="mailer")
        off = make(c, name="off")
        schedules.set_enabled(c, off, False, "pia")
        schedules.tick(c, ts("2026-11-11T03:00"), STO)
        assert [r[0] for r in c.execute("SELECT hosts FROM posture_scans")] == ["mail.beta.example"]
        assert c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0] == 0   # the disabled one did not run
        users.save_scope(c, {**users.get_scope(c), "domains_deny": ["beta.example"]})
        c.execute("UPDATE posture_scans SET status = 'done'")
        schedules.tick(c, ts("2026-11-12T03:00"), STO)
        assert "outside the inventory scope" in schedules.get(c, sid)["last_result"]
        assert c.execute("SELECT COUNT(*) FROM posture_scans").fetchone()[0] == 1


def test_worker_tick_runs_on_its_own_connection(settings, monkeypatch):
    with db.connect(settings.db_path) as c:
        make(c)
    got = jobs.schedule_tick(settings, ts("2026-11-11T03:00", None) + 86400 * 2)
    assert len(got) == 1


# --- rights --------------------------------------------------------------------------------------------------------

def client(settings):
    return TestClient(create_app(settings), base_url="https://testserver", client=("203.0.113.9", 50000))


def login(h, name):
    r = h.post("/admin/login", data={"name": name, "password": PW}, follow_redirects=False)
    assert r.status_code == 303 and COOKIE in r.cookies
    return re.search(r'name="csrf" value="([^"]+)"', h.get("/admin/account").text).group(1)


def test_domain_admin_manages_schedules_on_its_domain(settings):
    with client(settings) as h:
        csrf = login(h, "pia")
        page = h.get("/d/beta.example").text
        assert 'id="schedules"' in page and "Add a schedule" in page and 'name="h:db.beta.example"' in page
        r = h.post("/admin/schedules", data={**FORM, "csrf": csrf, "domain": "beta.example"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/d/beta.example?ok=schedule-saved#schedules"
        assert "Schedule saved" in h.get(r.headers["location"]).text
        with db.connect(settings.db_path) as c:
            sid = c.execute("SELECT id FROM schedules").fetchone()[0]
        assert "nightly" in h.get("/d/beta.example").text
        assert h.get(f"/admin/schedules/{sid}").status_code == 200
        r = h.post(f"/admin/schedules/{sid}", data={**FORM, "csrf": csrf, "name": "weekly", "freq": "weekly"},
                   follow_redirects=False)
        assert r.status_code == 303
        assert h.post(f"/admin/schedules/{sid}", data={**FORM, "csrf": csrf, "at_time": "hello"}).status_code == 422
        assert h.post(f"/admin/schedules/{sid}/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303
        assert h.post(f"/admin/schedules/{sid}/run", data={"csrf": csrf}).status_code == 409   # still queued
        assert h.post(f"/admin/schedules/{sid}/enabled", data={"csrf": csrf, "on": "0"},
                      follow_redirects=False).status_code == 303
        assert h.post(f"/admin/schedules/{sid}/delete", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    with db.connect(settings.db_path) as c:
        assert c.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0
        assert [r["client"] for r in c.execute("SELECT client FROM jobs")] == [jobs.SCHEDULE]
        acts = [r["action"] for r in access.audit_recent(c) if r["action"].startswith("schedule")]
        assert acts == ["schedule-delete", "schedule-enabled", "schedule-run", "schedule-update", "schedule-create"]


def test_viewers_read_only_and_outside_answers_404(settings):
    with db.connect(settings.db_path) as c:
        a = make(c, dom="alpha.example")
        g = make(c, dom="gamma.example")
    with client(settings) as h:
        csrf = login(h, "pia")
        page = h.get("/d/alpha.example").text
        assert "nightly" in page and "Add a schedule" not in page and f"/admin/schedules/{a}/run" not in page
        view = h.get(f"/admin/schedules/{a}")
        assert view.status_code == 200 and 'class="schedule-form"' not in view.text
        assert h.post("/admin/schedules", data={**FORM, "csrf": csrf, "domain": "alpha.example"}).status_code == 403
        for action in ("", "/run", "/enabled", "/delete"):
            assert h.post(f"/admin/schedules/{a}{action}", data={**FORM, "csrf": csrf}).status_code == 403, action
            assert h.post(f"/admin/schedules/{g}{action}", data={**FORM, "csrf": csrf}).status_code == 404, action
        assert h.get(f"/admin/schedules/{g}").status_code == 404 and h.get("/admin/schedules/999").status_code == 404
        assert h.post("/admin/schedules", data={**FORM, "csrf": csrf, "domain": "gamma.example"}).status_code == 404
        r = h.get("/admin", follow_redirects=False)   # the Operations list is the admins'
        assert r.status_code == 303
    with client(settings) as h:
        csrf = login(h, "nob")
        assert h.get(f"/admin/schedules/{a}").status_code == 404
        assert h.post(f"/admin/schedules/{a}/run", data={"csrf": csrf}).status_code == 404
    with client(settings) as h:   # admins: everything, and the Operations list
        csrf = login(h, "boss")
        ops = h.get("/admin").text
        assert "Scheduled rescans" in ops and "gamma.example" in ops and "alpha.example" in ops
        assert h.post(f"/admin/schedules/{g}/run", data={"csrf": csrf, "from": "ops"},
                      follow_redirects=False).headers["location"].startswith("/admin")
    with db.connect(settings.db_path) as c:
        assert [r["domain"] for r in c.execute("SELECT domain FROM jobs")] == ["gamma.example"]


def test_profiles_in_use_by_a_schedule_cannot_be_deleted(settings):
    with db.connect(settings.db_path) as c:
        discovery.save(c, {**discovery.profile(c, "default"), "name": "lan"}, "boss")
        posture.save_profile(c, {"name": "quick", "ports": "22", "intensity": 0, "timing": 4, "timeout": 60,
                                 "route": ""}, "", "boss")
        make(c, discovery_profile="lan", posture="on", posture_profile="quick")
    with client(settings) as h:
        csrf = login(h, "boss")
        assert h.post("/admin/security/discovery-profiles/lan/delete", data={"csrf": csrf}).status_code == 409
        assert h.post("/admin/security/profiles/quick/delete", data={"csrf": csrf}).status_code == 409
    with db.connect(settings.db_path) as c:
        assert discovery.profile(c, "lan") and posture.profile(c, "quick")


def test_dropping_a_domain_drops_its_schedules(settings):
    with db.connect(settings.db_path) as c:
        make(c)
        db.delete_domain(c, "beta.example")
        assert c.execute("SELECT COUNT(*) FROM schedules").fetchone()[0] == 0
