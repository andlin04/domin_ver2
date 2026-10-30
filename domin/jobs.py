"""Scan queue in SQLite. The web app enqueues; one worker process (python -m domin worker) runs jobs in order."""
from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timedelta

from . import admin, db, scanner
from .config import Settings

log = logging.getLogger("domin.worker")


class Cancelled(Exception):
    """The admin cancelled the running job; the worker stops at its next progress step."""


def _public(row: sqlite3.Row) -> dict:
    """A job as shown to anyone: without the requester's address."""
    job = dict(row)
    job.pop("client", None)
    return job


def enqueue(conn: sqlite3.Connection, domain: str, client: str = "") -> dict:
    """One open job per domain: asking again returns the job already queued or running."""
    row = conn.execute("SELECT * FROM jobs WHERE domain = ? AND status IN ('queued', 'running')", (domain,)).fetchone()
    if row:
        return _public(row)
    jid = conn.execute("INSERT INTO jobs (domain, status, created, client) VALUES (?, 'queued', ?, ?)",
                       (domain, db.now(), client)).lastrowid
    return _public(conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,)).fetchone())


def queued(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'").fetchone()[0]


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
        job["ahead"] = conn.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued', 'running') AND id < ?",
                                    (job_id,)).fetchone()[0]
    return job


def recent(conn: sqlite3.Connection, limit: int = 10) -> list[dict]:
    return [_public(r) for r in conn.execute("SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))]


def scans_by_client(conn: sqlite3.Connection, client: str, minutes: int = 60) -> int:
    since = (datetime.now() - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    return conn.execute("SELECT COUNT(*) FROM jobs WHERE client = ? AND created >= ?", (client, since)).fetchone()[0]


def claim(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT * FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
    if not row:
        return None
    n = conn.execute("UPDATE jobs SET status = 'running', started = ? WHERE id = ? AND status = 'queued'",
                     (db.now(), row["id"])).rowcount
    conn.commit()
    return dict(row) if n else None


def run_job(settings: Settings, job: dict) -> None:
    with db.connect(settings.db_path) as conn:
        def progress(text: str) -> None:
            n = conn.execute("UPDATE jobs SET progress = ? WHERE id = ? AND status = 'running'",
                             (text, job["id"])).rowcount
            conn.commit()
            if not n:
                raise Cancelled

        started = db.now()
        try:
            records = scanner.run(conn, job["domain"], settings, progress)
            progress("saving")
        except Cancelled:
            log.info("scan %s cancelled", job["domain"])
            return
        except Exception as exc:
            log.exception("scan %s failed", job["domain"])
            conn.execute("UPDATE jobs SET status = 'failed', finished = ?, error = ? WHERE id = ?",
                         (db.now(), f"internal error ({type(exc).__name__})", job["id"]))   # details: the log
            return
        sid = db.save_scan(conn, job["domain"], started, "scan", records, finished=db.now())
        conn.execute("UPDATE jobs SET status = 'done', finished = ?, scan_id = ?, progress = '' WHERE id = ?",
                     (db.now(), sid, job["id"]))
        log.info("scan %s done: %d records", job["domain"], len(records))


def enqueue_due(conn: sqlite3.Connection, days: int) -> int:
    """Scheduled refresh: queue every domain whose newest scan is older than `days` (0 = off)."""
    if days <= 0:
        return 0
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    due = [r["name"] for r in conn.execute(
        "SELECT d.name FROM domains d JOIN scans s ON s.domain_id = d.id GROUP BY d.id HAVING MAX(s.started) < ?",
        (cutoff,))]
    for name in due:
        enqueue(conn, name, client="refresh")
    return len(due)


def worker(settings: Settings, once: bool = False, idle: float = 3.0) -> None:
    db.init(settings.db_path)
    with db.connect(settings.db_path) as conn:  # a crash or restart leaves 'running' rows behind
        conn.execute("UPDATE jobs SET status = 'failed', error = 'worker restarted', finished = ? "
                     "WHERE status = 'running'", (db.now(),))
    last_refresh = 0.0
    while True:
        with db.connect(settings.db_path) as conn:
            live = admin.effective(settings, conn)   # the admin page's tuning applies without a restart
            if time.time() - last_refresh > 3600:
                last_refresh = time.time()
                forget_clients(conn)
                admin.prune(conn, live.analytics_days)
                if n := enqueue_due(conn, live.refresh_days):
                    log.info("refresh: %d domains queued", n)
            job = None if live.scans_paused else claim(conn)
        if job:
            run_job(live, job)
        elif once:
            return
        else:
            time.sleep(idle)
