"""Security posture (stage 2): fingerprint the in-scope addresses of an inventoried domain and match their
services against the CVE layer.

Stage 1 (the inventory scan) finds a domain's host names and addresses. A posture scan takes the addresses of the
domain's latest inventory scan, keeps those inside the posture scope (Settings: IP and country rules), and
fingerprints each one (:func:`fingerprint.scan`). An analyst starts it from the Security page, for the whole domain
or one host name; nothing starts it automatically.

Every scan is one row in posture_scans per address. The web app only queues rows; the worker's posture thread runs
them one at a time, so the web process never probes a target. The latest finished row per (domain, address) is the
current posture; older rows stay as history.
"""
from __future__ import annotations

import json
import logging
import sqlite3

import httpx

from . import cve, db, fingerprint, users

log = logging.getLogger("domin.posture")


def targets(conn: sqlite3.Connection, domain: str, host: str = "", ip: str = "") -> tuple[list[dict], int]:
    """Addresses of the domain's latest inventory scan inside the posture scope, as [{ip, hosts, country}], and how
    many addresses the scope left out. host or ip narrows the set to that host name or address."""
    scope = users.get_scope(conn)
    rows = conn.execute(f"""SELECT r.host, r.ip, r.country FROM records r JOIN ({db.LATEST}) s ON s.id = r.scan_id
                            JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != ''""", (domain,))
    by_ip: dict[str, dict] = {}
    for r in rows:
        if (host and r["host"] != host) or (ip and r["ip"] != ip):
            continue
        e = by_ip.setdefault(r["ip"], {"ip": r["ip"], "hosts": set(), "country": r["country"] or ""})
        e["hosts"].add(r["host"])
    keep = [{**e, "hosts": sorted(e["hosts"])} for e in by_ip.values()
            if users.posture_ok(scope, e["ip"], e["country"])]
    keep.sort(key=lambda e: e["ip"])
    return keep, len(by_ip) - len(keep)


def enqueue(conn: sqlite3.Connection, domain: str, found: list[dict], ports: str, requested_by: str) -> int:
    """Queue one posture scan per address; an address already queued or running for the domain is left alone.
    Returns how many were queued."""
    n = 0
    for t in found:
        if conn.execute("SELECT 1 FROM posture_scans WHERE domain = ? AND ip = ? AND status IN ('queued', 'running')",
                        (domain, t["ip"])).fetchone():
            continue
        conn.execute("INSERT INTO posture_scans (domain, ip, hosts, country, ports, status, requested_by, created) "
                     "VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)",
                     (domain, t["ip"], ",".join(t["hosts"]), t["country"], ports, requested_by, db.now()))
        n += 1
    return n


def claim(conn: sqlite3.Connection) -> dict | None:
    row = conn.execute("SELECT * FROM posture_scans WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
    if not row:
        return None
    n = conn.execute("UPDATE posture_scans SET status = 'running', started = ? WHERE id = ? AND status = 'queued'",
                     (db.now(), row["id"])).rowcount
    conn.commit()
    return dict(row) if n else None


def _finish(conn: sqlite3.Connection, sid: int, status: str, res: dict) -> None:
    services = res.get("services") or []
    findings = [f for s in services for f in s.get("findings") or []]
    conn.execute("""UPDATE posture_scans SET status = ?, finished = ?, services = ?, open_ports = ?, cves = ?,
                    high = ?, note = ?, error = ?, raw = ? WHERE id = ?""",
                 (status, db.now(), json.dumps(services), len(services), len({f["cve"] for f in findings}),
                  len({f["cve"] for f in findings if f["severity"] in ("critical", "high")}),
                  res.get("note") or "", res.get("error") or "", res.get("raw") or "", sid))


def run(conn: sqlite3.Connection, row: dict, cve_db: cve.Database, client: httpx.Client | None,
        api_key: str = "") -> None:
    """Run one claimed row. The scope is checked again: it may have changed while the row waited."""
    if not users.posture_ok(users.get_scope(conn), row["ip"], row["country"]):
        _finish(conn, row["id"], "failed", {"error": "outside the posture scope (Settings changed after queueing)"})
        return
    try:
        res = fingerprint.scan(row["ip"], cve_db=cve_db, client=client, api_key=api_key, ports=row["ports"],
                               display=row["hosts"].split(",")[0] or row["ip"])
    except Exception as exc:   # one bad host must not stop the queue
        log.exception("posture scan %s failed", row["ip"])
        res = {"error": f"internal error ({type(exc).__name__})"}
    _finish(conn, row["id"], "failed" if res.get("error") else "done", res)
    log.info("posture %s %s: %s", row["domain"], row["ip"], res.get("error") or "done")


def fail_running(conn: sqlite3.Connection) -> int:
    """Rows a crash or restart left running."""
    return conn.execute("UPDATE posture_scans SET status = 'failed', finished = ?, error = 'worker restarted' "
                        "WHERE status = 'running'", (db.now(),)).rowcount


def current(conn: sqlite3.Connection, domain: str = "", limit: int = 500) -> list[dict]:
    """The current posture per (domain, address): the latest finished scan, with `pending` set when a newer scan is
    queued or running. An address with nothing finished yet shows its pending row."""
    where, args = ("WHERE domain = ?", [domain]) if domain else ("", [])
    rows = conn.execute(f"""
        SELECT p.*, (SELECT q.status FROM posture_scans q WHERE q.domain = p.domain AND q.ip = p.ip
                     AND q.status IN ('queued', 'running') ORDER BY q.id DESC LIMIT 1) AS pending
        FROM posture_scans p JOIN (
            SELECT domain, ip, COALESCE(MAX(CASE WHEN status IN ('done', 'failed') THEN id END), MAX(id)) AS id
            FROM posture_scans {where} GROUP BY domain, ip) m ON m.id = p.id
        ORDER BY p.domain, p.high DESC, p.cves DESC, p.ip LIMIT ?""", (*args, limit)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["services"] = json.loads(d["services"] or "[]")
        if d["pending"] == d["status"]:   # the row shown is itself the pending one
            d["pending"] = None
        out.append(d)
    return out


def domains(conn: sqlite3.Connection) -> list[str]:
    """Domains with a finished inventory scan, for the target pick-list."""
    return [r[0] for r in conn.execute(f"SELECT d.name FROM domains d JOIN ({db.LATEST}) s ON s.domain_id = d.id "
                                       "ORDER BY d.name")]


def hosts(conn: sqlite3.Connection, domain: str) -> list[str]:
    """Host names with an address in the domain's latest inventory scan, for the host pick-list."""
    return [r[0] for r in conn.execute(f"""SELECT DISTINCT r.host FROM records r JOIN ({db.LATEST}) s
        ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id WHERE d.name = ? AND r.ip != '' ORDER BY r.host""",
        (domain,))]
