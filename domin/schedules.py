"""Scheduled rescans of one domain (docs/scheduled-scans.md).

A schedule runs an inventory scan (optionally with an nmap discovery profile) and/or posture scans (a posture profile,
on all hosts, a chosen list or the hosts with a tag) at a recurrence in server local time. The worker's schedule
thread calls tick() every minute; it queues normal jobs through jobs.enqueue / posture.enqueue, so the queue limits,
scope rules and sandbox are those of any other scan. A missed run (downtime) runs once; a run whose previous one is
still open is skipped.

Times: next_ts (epoch) decides; next_run is the same moment as local wall time for the page. tz=None = the server's
local zone (tests pass a tzinfo)."""
from __future__ import annotations

import calendar
import json
import logging
import re
import sqlite3
import time
from datetime import date, datetime, timedelta, tzinfo
from datetime import time as dtime

from . import access, db, discovery, jobs, posture, tags, users

log = logging.getLogger("domin.schedules")

FREQS = {"daily": "Daily", "weekly": "Weekly", "monthly": "Monthly", "hours": "Every N hours",
         "days": "Every N days"}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
HOST_MODES = {"all": "All hosts at run time", "list": "Chosen hosts", "tag": "Hosts with a tag"}
EVERY_MAX = {"hours": 168, "days": 365}
HOSTS_MAX = 2000
OPEN = ("queued", "running")
_TIME = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,60}$")


# --- time ---------------------------------------------------------------------------------------------------------

def to_ts(local: datetime, tz: tzinfo | None = None) -> float:
    """Epoch of a local wall time. A time in the spring-forward gap counts with the offset before the change (02:30
    -> 03:30); a repeated autumn time is its first occurrence (fold 0)."""
    return (local.replace(tzinfo=tz) if tz else local).timestamp()


def from_ts(ts: float, tz: tzinfo | None = None) -> datetime:
    """Local wall time (naive) of an epoch."""
    return datetime.fromtimestamp(ts, tz).replace(tzinfo=None) if tz else datetime.fromtimestamp(ts)


def _at(s: dict) -> dtime:
    hh, mm = s["at_time"].split(":")
    return dtime(int(hh), int(mm))


def _day_matches(s: dict, d: date) -> bool:
    if s["freq"] == "weekly":
        return d.weekday() == int(s["weekday"])
    if s["freq"] == "monthly":   # day 29-31 in a shorter month: its last day
        return d.day == min(int(s["monthday"]), calendar.monthrange(d.year, d.month)[1])
    return True


def next_after(s: dict, after: float, tz: tzinfo | None = None) -> float:
    """The first slot of schedule s strictly after epoch `after`."""
    at = _at(s)
    if s["freq"] == "hours":   # real elapsed hours from the anchor
        base, step = to_ts(datetime.fromisoformat(s["anchor"]), tz), int(s["every"]) * 3600
        if base > after:
            return base
        return base + (int((after - base) // step) + 1) * step
    local = from_ts(after, tz)
    if s["freq"] == "days":   # every N calendar days at the same wall time
        d0, n = datetime.fromisoformat(s["anchor"]).date(), int(s["every"])
        k = max(0, (local.date() - d0).days // n)
        for i in range(k, k + 3):
            ts = to_ts(datetime.combine(d0 + timedelta(days=i * n), at), tz)
            if ts > after:
                return ts
    for i in range(0, 400):
        d = local.date() + timedelta(days=i)
        if _day_matches(s, d) and (ts := to_ts(datetime.combine(d, at), tz)) > after:
            return ts
    raise ValueError("no next run within 400 days")


def anchor_for(s: dict, now: float, tz: tzinfo | None = None) -> str:
    """The base slot of every N hours / days: today at the schedule's time."""
    return datetime.combine(from_ts(now, tz).date(), _at(s)).isoformat(timespec="minutes")


def stamp(ts: float, tz: tzinfo | None = None) -> str:
    return from_ts(ts, tz).isoformat(timespec="seconds")


def describe(s: dict) -> str:
    at = s["at_time"]
    return {"daily": f"Daily at {at}", "weekly": f"Weekly on {WEEKDAYS[int(s['weekday'])]} at {at}",
            "monthly": f"Monthly on day {s['monthday']} at {at}"
                       + (" (last day in shorter months)" if int(s["monthday"]) > 28 else ""),
            "hours": f"Every {s['every']} h from {at}", "days": f"Every {s['every']} days at {at}"}[s["freq"]]


# --- the form ------------------------------------------------------------------------------------------------------

def check(conn: sqlite3.Connection, domain: str, form: dict) -> tuple[dict | None, str]:
    """Validate a schedule form for a domain: (fields, "") or (None, error). Chosen hosts come as h:<name> keys and
    must be in the domain's latest inventory."""
    def get(k: str) -> str:
        return str(form.get(k) or "").strip()

    def num(k: str, lo: int, hi: int, label: str) -> int:
        v = get(k)
        if not re.fullmatch(r"[0-9]{1,4}", v) or not lo <= int(v) <= hi:
            raise ValueError(f"{label}: a whole number {lo}-{hi}.")
        return int(v)

    p: dict = {"name": get("name"), "enabled": 1 if get("enabled") in ("1", "on") else 0,
               "discovery": 1 if get("discovery") in ("1", "on") else 0, "discovery_profile": get("discovery_profile"),
               "posture": 1 if get("posture") in ("1", "on") else 0,
               "posture_profile": get("posture_profile") or posture.DEFAULT_PROFILE,
               "host_mode": get("host_mode") or "all", "tag": get("tag").lower(), "freq": get("freq"),
               "at_time": get("at_time")}
    if not _NAME.match(p["name"]):
        return None, "Name: 1-60 characters."
    if not (p["discovery"] or p["posture"]):
        return None, "Pick what to run: discovery, posture or both."
    if p["discovery"] and p["discovery_profile"] and not discovery.profile(conn, p["discovery_profile"]):
        return None, "Discovery profile: pick one from the list."
    if not p["discovery"]:
        p["discovery_profile"] = ""
    if p["posture"] and not posture.profile(conn, p["posture_profile"]):
        return None, "Posture profile: pick one from the list."
    if p["host_mode"] not in HOST_MODES:
        return None, "Posture hosts: pick all, chosen hosts or a tag."
    chosen = sorted({k[2:] for k, v in form.items() if k.startswith("h:") and v in ("1", "on")})
    p["hosts"], p["tag"] = "[]", p["tag"] if p["host_mode"] == "tag" else ""
    if p["posture"] and p["host_mode"] == "list":
        present = set(posture.hosts(conn, domain))
        if not chosen or len(chosen) > HOSTS_MAX:
            return None, f"Posture hosts: tick 1-{HOSTS_MAX} host names."
        if bad := [h for h in chosen if h not in present]:
            return None, f"Not in the latest inventory of {domain}: {', '.join(bad[:5])}."
        p["hosts"] = json.dumps(chosen)
    if p["posture"] and p["host_mode"] == "tag" and not tags.valid(p["tag"]):
        return None, "Tag: 1-30 lower-case letters, digits or -."
    if p["freq"] not in FREQS:
        return None, "Recurrence: pick one from the list."
    if not _TIME.match(p["at_time"]):
        return None, "Time: HH:MM, 00:00-23:59."
    try:
        p["weekday"] = num("weekday", 0, 6, "Weekday") if p["freq"] == "weekly" else 0
        p["monthday"] = num("monthday", 1, 31, "Day of month") if p["freq"] == "monthly" else 1
        p["every"] = num("every", 1, EVERY_MAX[p["freq"]], "Every N") if p["freq"] in EVERY_MAX else 1
    except ValueError as exc:
        return None, str(exc)
    return p, ""


COLS = ("name", "enabled", "discovery", "discovery_profile", "posture", "posture_profile", "host_mode", "hosts",
        "tag", "freq", "at_time", "weekday", "monthday", "every")


def _timing(p: dict, now: float, tz: tzinfo | None) -> dict:
    p = {**p, "anchor": anchor_for(p, now, tz)}
    nxt = next_after(p, now, tz)
    return {"anchor": p["anchor"], "next_ts": nxt, "next_run": stamp(nxt, tz)}


def create(conn: sqlite3.Connection, domain: str, p: dict, by: str, now: float | None = None,
           tz: tzinfo | None = None) -> int:
    now = time.time() if now is None else now
    t = _timing(p, now, tz)
    cols = [*COLS, "anchor", "next_ts", "next_run"]
    return conn.execute(f"INSERT INTO schedules (domain, {', '.join(cols)}, created, created_by, updated, updated_by) "
                        f"VALUES (?, {', '.join('?' * len(cols))}, ?, ?, ?, ?)",
                        [domain, *(p[c] for c in COLS), t["anchor"], t["next_ts"], t["next_run"], db.now(), by,
                         db.now(), by]).lastrowid


def update(conn: sqlite3.Connection, sid: int, p: dict, by: str, now: float | None = None,
           tz: tzinfo | None = None) -> None:
    """A change: next_run computed again from now."""
    now = time.time() if now is None else now
    t = _timing(p, now, tz)
    cols = [*COLS, "anchor", "next_ts", "next_run"]
    conn.execute(f"UPDATE schedules SET {', '.join(f'{c} = ?' for c in cols)}, updated = ?, updated_by = ? "
                 "WHERE id = ?", [*(p[c] for c in COLS), t["anchor"], t["next_ts"], t["next_run"], db.now(), by, sid])


def set_enabled(conn: sqlite3.Connection, sid: int, on: bool, by: str, now: float | None = None,
                tz: tzinfo | None = None) -> None:
    """Enable (next_run from now: no catch-up for the time it was off) or disable."""
    s = get(conn, sid)
    if on:
        now = time.time() if now is None else now
        t = _timing(s, now, tz) if s["freq"] not in ("hours", "days") else {
            "anchor": s["anchor"], "next_ts": (n := next_after(s, now, tz)), "next_run": stamp(n, tz)}
        conn.execute("UPDATE schedules SET enabled = 1, anchor = ?, next_ts = ?, next_run = ?, updated = ?, "
                     "updated_by = ? WHERE id = ?", (t["anchor"], t["next_ts"], t["next_run"], db.now(), by, sid))
    else:
        conn.execute("UPDATE schedules SET enabled = 0, updated = ?, updated_by = ? WHERE id = ?",
                     (db.now(), by, sid))


def delete(conn: sqlite3.Connection, sid: int) -> None:
    conn.execute("DELETE FROM schedules WHERE id = ?", (sid,))


def get(conn: sqlite3.Connection, sid: int) -> dict | None:
    row = conn.execute("SELECT * FROM schedules WHERE id = ?", (sid,)).fetchone()
    return dict(row) if row else None


def _view(conn: sqlite3.Connection, s: dict, present: set[str] | None = None) -> dict:
    """A schedule for a page: recurrence in words, chosen hosts and those no longer in the inventory, last job."""
    hosts = json.loads(s["hosts"] or "[]")
    if present is None:
        present = set(posture.hosts(conn, s["domain"]))
    job = jobs.get(conn, s["last_job"]) if s["last_job"] else None
    return {**s, "when": describe(s), "host_list": hosts,
            "missing": [h for h in hosts if h not in present] if s["posture"] and s["host_mode"] == "list" else [],
            "job": job, "busy": busy(conn, s)}


def for_domain(conn: sqlite3.Connection, domain: str) -> list[dict]:
    present = set(posture.hosts(conn, domain))
    return [_view(conn, dict(r), present) for r in conn.execute(
        "SELECT * FROM schedules WHERE domain = ? ORDER BY name, id", (domain,))]


def listing(conn: sqlite3.Connection, scope: access.Scope | None = None) -> list[dict]:
    """Every schedule (in the scope), next run first."""
    f, fa = db.in_scope(scope, "domain")
    return [_view(conn, dict(r)) for r in conn.execute(
        f"SELECT * FROM schedules WHERE {f} ORDER BY enabled DESC, next_ts, domain, name", fa)]


# --- running -------------------------------------------------------------------------------------------------------

def busy(conn: sqlite3.Connection, s: dict) -> bool:
    """Something of this schedule's last run is still queued or running."""
    if s.get("wait_job"):
        return True
    if s.get("last_job") and conn.execute("SELECT 1 FROM jobs WHERE id = ? AND status IN ('queued', 'running')",
                                          (s["last_job"],)).fetchone():
        return True
    return bool(conn.execute("SELECT 1 FROM jobs WHERE schedule_id = ? AND status IN ('queued', 'running') "
                             "UNION ALL SELECT 1 FROM posture_scans WHERE schedule_id = ? "
                             "AND status IN ('queued', 'running') LIMIT 1", (s["id"], s["id"])).fetchone())


def pick_hosts(conn: sqlite3.Connection, s: dict) -> tuple[set[str] | None, list[str]]:
    """(host names to scan, None = all; chosen names no longer in the latest inventory)."""
    if s["host_mode"] == "list":
        chosen = json.loads(s["hosts"] or "[]")
        present = set(posture.hosts(conn, s["domain"]))
        return {h for h in chosen if h in present}, [h for h in chosen if h not in present]
    if s["host_mode"] == "tag":
        return {e["host"] for e in posture.host_list(conn, s["domain"])
                if s["tag"] in (e.get("tags") or []) + (e.get("net_tags") or [])}, []
    return None, []


def posture_part(conn: sqlite3.Connection, s: dict) -> str:
    """Queue the posture scans of a schedule now; returns the result text."""
    prof = posture.profile(conn, s["posture_profile"])
    if not prof:
        return f"posture skipped: profile {s['posture_profile']} no longer exists"
    names, missing = pick_hosts(conn, s)
    gone = f"; hosts no longer in the domain, skipped: {', '.join(missing)}" if missing else ""
    if names is not None and not names:
        why = f" (no host with tag {s['tag']})" if s["host_mode"] == "tag" else ""
        return f"posture: no host to scan{why}{gone}"
    found, out = posture.targets(conn, s["domain"], names=names)
    n = posture.enqueue(conn, s["domain"], found, prof, f"schedule:{s['name']}"[:60], schedule_id=s["id"])
    text = f"posture: {n} address(es) queued with profile {prof['name']}"
    if len(found) > n:
        text += f", {len(found) - n} already queued or running"
    if out:
        text += f"; {out} outside the posture scope or on its Never scan list"
    return text + gone


def launch(conn: sqlite3.Connection, s: dict) -> dict:
    """Queue one run of s. Returns {result, last_job, wait_job}."""
    out = {"result": "", "last_job": None, "wait_job": None}
    if not users.domain_allowed(conn, s["domain"]):
        out["result"] = "skipped: the domain is outside the inventory scope (Settings)"
        return out
    if s["discovery"]:
        if s["discovery_profile"] and not discovery.profile(conn, s["discovery_profile"]):
            out["result"] = f"skipped: discovery profile {s['discovery_profile']} no longer exists"
            return out
        job = jobs.enqueue(conn, s["domain"], client=jobs.SCHEDULE, discovery=s["discovery_profile"],
                           schedule_id=s["id"])
        out["last_job"] = job["id"]
        ours = job.get("schedule_id") == s["id"] and job["status"] == "queued"
        out["result"] = (f"inventory job #{job['id']} queued"
                         + (f" (nmap discovery: {s['discovery_profile']})" if s["discovery_profile"] else "")
                         if ours else f"joined inventory job #{job['id']}, already open")
        if s["posture"]:
            out["wait_job"] = job["id"]
            out["result"] += "; posture follows when it is done"
        return out
    out["result"] = posture_part(conn, s)
    return out


def _record(conn: sqlite3.Connection, sid: int, run: dict, when: str) -> None:
    conn.execute("UPDATE schedules SET last_run = ?, last_job = COALESCE(?, last_job), wait_job = ?, last_result = ? "
                 "WHERE id = ?", (when, run["last_job"], run["wait_job"], run["result"][:1000], sid))


def run_now(conn: sqlite3.Connection, sid: int, now: float | None = None, tz: tzinfo | None = None) -> dict | None:
    """Queue a run at once; next_run unchanged. None when the previous run is still open."""
    s = get(conn, sid)
    if busy(conn, s):
        return None
    run = launch(conn, s)
    _record(conn, sid, run, stamp(time.time() if now is None else now, tz))
    log.info("schedule %d %s (%s): run now: %s", sid, s["name"], s["domain"], run["result"])
    return run


def tick(conn: sqlite3.Connection, now: float | None = None, tz: tzinfo | None = None) -> list[str]:
    """One pass of the runner: posture parts whose inventory job ended, then every due schedule. Returns what it
    did, one line per schedule."""
    now = time.time() if now is None else now
    done: list[str] = []
    for s in [dict(r) for r in conn.execute("SELECT * FROM schedules WHERE wait_job IS NOT NULL")]:
        job = conn.execute("SELECT status FROM jobs WHERE id = ?", (s["wait_job"],)).fetchone()
        if job and job["status"] in OPEN:
            continue
        if job and job["status"] == "done":
            text = posture_part(conn, s)
        else:
            text = f"posture not queued: inventory job #{s['wait_job']} {job['status'] if job else 'is gone'}"
        prev = (s["last_result"] or "").replace("; posture follows when it is done", "")
        conn.execute("UPDATE schedules SET wait_job = NULL, last_result = ? WHERE id = ?",
                     (f"{prev}; {text}"[:1000], s["id"]))
        conn.commit()
        done.append(f"schedule {s['id']}: {text}")
    for s in [dict(r) for r in conn.execute("SELECT * FROM schedules WHERE enabled = 1 AND next_ts IS NOT NULL AND "
                                            "next_ts <= ? ORDER BY next_ts, id", (now,))]:
        nxt = next_after(s, now, tz)   # missed slots (downtime) are not caught up
        conn.execute("UPDATE schedules SET next_ts = ?, next_run = ? WHERE id = ?", (nxt, stamp(nxt, tz), s["id"]))
        if busy(conn, s):
            text = f"skipped at {stamp(now, tz)[:16].replace('T', ' ')}: previous run still queued or running"
            conn.execute("UPDATE schedules SET last_result = ? WHERE id = ?", (text, s["id"]))
            log.warning("schedule %d %s (%s): %s", s["id"], s["name"], s["domain"], text)
        else:
            run = launch(conn, s)
            _record(conn, s["id"], run, stamp(now, tz))
            text = run["result"]
            log.info("schedule %d %s (%s): %s", s["id"], s["name"], s["domain"], text)
        conn.commit()
        done.append(f"schedule {s['id']}: {text}")
    return done
