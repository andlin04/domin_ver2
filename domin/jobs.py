"""Scan queue in SQLite. The web app enqueues; one worker process (python -m domin worker) runs jobs in order.

Two queues in one table: scheduled refreshes (client 'refresh') and visitors' jobs (everything else). The worker
runs user_workers threads on visitors' jobs and refresh_workers threads on refreshes, so a long refresh backlog
never delays a visitor (the old version's 3 + 2 threads)."""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta

from . import admin, db, scanner
from .config import Settings

log = logging.getLogger("domin.worker")


REFRESH = "refresh"


class Cancelled(Exception):
    """The admin cancelled the running job; the worker stops at its next progress step."""


class TimedOut(Exception):
    """The scan ran longer than scan_timeout_hours."""


def _queue(refresh: bool) -> str:
    return "client = 'refresh'" if refresh else "client != 'refresh'"


def _public(row: sqlite3.Row) -> dict:
    """A job as shown to anyone: without the requester's address."""
    job = dict(row)
    job.pop("client", None)
    return job


def enqueue(conn: sqlite3.Connection, domain: str, client: str = "") -> dict:
    """One open job per domain: asking again returns the job already queued or running. A visitor asking for a
    domain with a queued refresh takes that job over, so it moves to the visitors' queue."""
    row = conn.execute("SELECT * FROM jobs WHERE domain = ? AND status IN ('queued', 'running')", (domain,)).fetchone()
    if row and row["status"] == "queued" and row["client"] == REFRESH and client not in ("", REFRESH):
        conn.execute("UPDATE jobs SET client = ?, created = ? WHERE id = ?", (client, db.now(), row["id"]))
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (row["id"],)).fetchone()
    if row:
        return _public(row)
    jid = conn.execute("INSERT INTO jobs (domain, status, created, client) VALUES (?, 'queued', ?, ?)",
                       (domain, db.now(), client)).lastrowid
    return _public(conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone())


def queued(conn: sqlite3.Connection) -> int:
    """Visitors' queued jobs (the refresh backlog doesn't fill the queue)."""
    return conn.execute(f"SELECT COUNT(*) FROM jobs WHERE status = 'queued' AND {_queue(False)}").fetchone()[0]


def forget_clients(conn: sqlite3.Connection, hours: int = 24) -> int:
    """Privacy: requester addresses are kept only as long as the rate limit needs them."""
    since = (datetime.now() - timedelta(hours=hours)).isoformat(timespec="seconds")
    return conn.execute("UPDATE jobs SET client = '' WHERE client NOT IN ('', 'refresh') AND created < ?",
                        (since,)).rowcount


def cancel(conn: sqlite3.Connection, job_id: int) -> bool:
    return conn.execute("UPDATE jobs SET status = 'cancelled', finished = ?, error = 'cancelled by the admin' "
                        "WHERE id = ? AND status IN ('queued', 'running')", (db.now(), job_id)).rowcount == 1


def admin_list(conn: sqlite3.Connection, limit: int = 30) -> dict:
    open_ = [_public(r) for r in conn.execute("SELECT * FROM jobs WHERE status IN ('queued', 'running') ORDER BY id")]
    done = [_public(r) for r in conn.execute(
        "SELECT * FROM jobs WHERE status NOT IN ('queued', 'running') ORDER BY id DESC LIMIT ?", (limit,))]
    per_day = [dict(r) for r in conn.execute(
        """SELECT substr(created, 1, 10) AS day, COUNT(*) AS jobs, SUM(status = 'done') AS done,
                  SUM(status = 'failed') AS failed, SUM(status = 'cancelled') AS cancelled,
                  COUNT(DISTINCT NULLIF(client, '')) AS clients
           FROM jobs GROUP BY day ORDER BY day DESC LIMIT 14""")]
    return {"open": open_, "done": done, "per_day": per_day}


def get(conn: sqlite3.Connection, job_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        return None
    job = _public(row)
    if job["status"] == "queued":
        job["ahead"] = conn.execute(f"SELECT COUNT(*) FROM jobs WHERE status = 'queued' AND id < ? AND "
                                    f"{_queue(row['client'] == REFRESH)}", (job_id,)).fetchone()[0]
    return job


def recent(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    return [_public(r) for r in conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))]


def scans_by_client(conn: sqlite3.Connection, client: str, minutes: int = 60) -> int:
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    return conn.execute("SELECT COUNT(*) FROM jobs WHERE client = ? AND created >= ?", (client, since)).fetchone()[0]


def claim(conn: sqlite3.Connection, refresh: bool = False) -> dict | None:
    row = conn.execute(f"SELECT * FROM jobs WHERE status = 'queued' AND {_queue(refresh)} ORDER BY id LIMIT 1"
                       ).fetchone()
    if not row:
        return None
    n = conn.execute("UPDATE jobs SET status = 'running', started = ? WHERE id = ? AND status = 'queued'",
                     (db.now(), row["id"])).rowcount
    conn.commit()
    return dict(row) if n else None


def run_job(settings: Settings, job: dict) -> None:
    deadline = time.monotonic() + settings.scan_timeout_hours * 3600
    with db.connect(settings.db_path) as conn:
        def progress(text: str) -> None:
            n = conn.execute("UPDATE jobs SET progress = ? WHERE id = ? AND status = 'running'",
                             (text, job["id"])).rowcount
            conn.commit()
            if not n:
                raise Cancelled
            if time.monotonic() > deadline:
                raise TimedOut

        started = db.now()
        try:
            records = scanner.run(conn, job["domain"], settings, progress)
            progress("saving")
        except Cancelled:
            log.info("scan %s cancelled", job["domain"])
            return
        except TimedOut:
            log.warning("scan %s timed out", job["domain"])
            conn.execute("UPDATE jobs SET status = 'failed', finished = ?, error = ? WHERE id = ?",
                         (db.now(), f"timed out after {settings.scan_timeout_hours} h", job["id"]))
            return
        except Exception as exc:
            log.exception("scan %s failed", job["domain"])
            conn.rollback()   # drop this scan's half-done write, so marking the job failed can get the lock
            conn.execute("UPDATE jobs SET status = 'failed', finished = ?, error = ? WHERE id = ?",
                         (db.now(), f"internal error ({type(exc).__name__})", job["id"]))   # details: the log
            return
        sid = db.save_scan(conn, job["domain"], started, "scan", records, finished=db.now())
        conn.execute("UPDATE jobs SET status = 'done', finished = ?, scan_id = ?, progress = '' WHERE id = ?",
                     (db.now(), sid, job["id"]))
        log.info("scan %s done: %d records", job["domain"], len(records))


def enqueue_due(conn: sqlite3.Connection, days: int) -> int:
    """Scheduled refresh: queue every domain whose newest scan is older than `days` (0 = off), oldest first."""
    if days <= 0:
        return 0
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    due = [r["name"] for r in conn.execute(
        "SELECT d.name FROM domains d JOIN scans s ON s.domain_id = d.id GROUP BY d.id HAVING MAX(s.started) < ? "
        "ORDER BY MAX(s.started), d.name", (cutoff,))]
    for name in due:
        enqueue(conn, name, client=REFRESH)
    return len(due)


RETRIES_PER_DAY = 2


def sweep_stuck(conn: sqlite3.Connection, timeout_hours: int) -> int:
    """Jobs still 'running' half an hour past the scan timeout lost their thread (a database error while marking
    them failed): fail them, so retry_failed picks them up and they stop counting as open."""
    cutoff = (datetime.now() - timedelta(hours=timeout_hours, minutes=30)).isoformat(timespec="seconds")
    return conn.execute("UPDATE jobs SET status = 'failed', finished = ?, error = 'stuck: no result past the scan "
                        "timeout' WHERE status = 'running' AND started < ?", (db.now(), cutoff)).rowcount


def retry_failed(conn: sqlite3.Connection) -> int:
    """A domain whose newest job failed goes back on the refresh queue, at once while it failed at most
    RETRIES_PER_DAY times in 24 h, else once its failures are a day old (the next day). Cancelled jobs stay."""
    since = (datetime.now() - timedelta(hours=24)).isoformat(timespec="seconds")
    due = [r["domain"] for r in conn.execute(
        """SELECT l.domain FROM (SELECT domain, status, MAX(id) FROM jobs GROUP BY domain) l WHERE l.status = 'failed'
           AND (SELECT COUNT(*) FROM jobs f WHERE f.domain = l.domain AND f.status = 'failed' AND f.finished >= ?)
               <= ? ORDER BY l.domain""", (since, RETRIES_PER_DAY))]
    for name in due:
        enqueue(conn, name, client=REFRESH)
    return len(due)


def _next(settings: Settings, refresh: bool) -> tuple[Settings, dict | None]:
    with db.connect(settings.db_path) as conn:
        live = admin.effective(settings, conn)   # the admin page's tuning applies without a restart
        return live, None if live.scans_paused else claim(conn, refresh)


def _scan_loop(settings: Settings, refresh: bool, idle: float) -> None:
    while True:
        try:
            live, job = _next(settings, refresh)
            if job:
                run_job(live, job)
                continue
        except Exception:   # a database hiccup must not end the thread
            log.exception("worker thread error")
        time.sleep(idle)


def housekeeping(settings: Settings) -> None:
    with db.connect(settings.db_path) as conn:
        live = admin.effective(settings, conn)
        forget_clients(conn)
        admin.prune(conn, live.analytics_days)
        if n := sweep_stuck(conn, live.scan_timeout_hours):
            log.warning("%d stuck jobs failed", n)
        if n := retry_failed(conn):
            log.info("retry: %d failed domains queued", n)
        if n := enqueue_due(conn, live.refresh_days):
            log.info("refresh: %d domains queued", n)


def worker(settings: Settings, once: bool = False, idle: float = 3.0) -> None:
    """once: run housekeeping, then every queued job one at a time (visitors' first), and return."""
    db.init(settings.db_path)
    with db.connect(settings.db_path) as conn:  # a crash or restart leaves 'running' rows behind
        conn.execute("UPDATE jobs SET status = 'failed', error = 'worker restarted', finished = ? "
                     "WHERE status = 'running'", (db.now(),))
    housekeeping(settings)
    if once:
        for refresh in (False, True):
            while (got := _next(settings, refresh))[1]:
                run_job(*got)
        return
    for refresh, n in ((False, settings.user_workers), (True, settings.refresh_workers)):
        for i in range(n):
            threading.Thread(target=_scan_loop, args=(settings, refresh, idle), daemon=True,
                             name=f"{'refresh' if refresh else 'user'}-{i}").start()
    while True:
        time.sleep(3600)   # hourly: a failed job waits at most an hour for its retry
        try:
            housekeeping(settings)
        except Exception:
            log.exception("housekeeping failed")
