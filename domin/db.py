"""SQLite storage. One connection per call site (cheap); WAL lets the web app read while the worker writes."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    added TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    started TEXT NOT NULL,
    finished TEXT,
    source TEXT NOT NULL,              -- import | scan
    status TEXT NOT NULL,              -- done | failed
    hosts INTEGER NOT NULL DEFAULT 0,  -- distinct host names
    resolved INTEGER NOT NULL DEFAULT 0,  -- host names with an address
    ips INTEGER NOT NULL DEFAULT 0,
    asns INTEGER NOT NULL DEFAULT 0,
    countries INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS scans_domain ON scans(domain_id, started);
CREATE TABLE IF NOT EXISTS records (
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host TEXT NOT NULL,
    ip TEXT NOT NULL DEFAULT '',       -- '' = no address
    asn TEXT NOT NULL DEFAULT '',
    prefix TEXT NOT NULL DEFAULT '',
    netname TEXT NOT NULL DEFAULT '',
    descr TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS records_scan ON records(scan_id);
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,              -- queued | running | done | failed
    created TEXT NOT NULL,
    started TEXT,
    finished TEXT,
    scan_id INTEGER,
    client TEXT NOT NULL DEFAULT '',
    progress TEXT NOT NULL DEFAULT '',
    error TEXT
);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created);
CREATE TABLE IF NOT EXISTS ip_cache (
    ip TEXT PRIMARY KEY,
    asn TEXT, prefix TEXT, netname TEXT, descr TEXT, country TEXT,
    fetched TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- admin password, tuning, salts
CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS admin_fails (client TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    visitor TEXT NOT NULL,             -- daily-salted hash of address + user agent, never the address
    kind TEXT NOT NULL,                -- page | tool | download | scan | limited
    path TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    ref TEXT NOT NULL DEFAULT '',      -- referring site's host name, external only
    country TEXT NOT NULL DEFAULT '',
    bot INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS visits_at ON visits(at);
CREATE TABLE IF NOT EXISTS geo (start TEXT PRIMARY KEY, end TEXT NOT NULL, cc TEXT NOT NULL) WITHOUT ROWID;
"""

RECORD_FIELDS = ("host", "ip", "asn", "prefix", "netname", "descr", "country")


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


_keep: dict[str, sqlite3.Connection] = {}


@contextmanager
def connect(path: Path) -> Iterator[sqlite3.Connection]:
    if str(path) not in _keep:   # idle connection for the process: closing the last one checkpoints the WAL and
        keep = sqlite3.connect(path, check_same_thread=False)   # fsyncs (seconds per request on a slow-sync disk)
        keep.execute("PRAGMA journal_mode=WAL")
        keep.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()   # a read opens the WAL index (holds it)
        _keep[str(path)] = keep
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as conn:
        conn.executescript(SCHEMA)


def domain_id(conn: sqlite3.Connection, name: str, added: str | None = None) -> int:
    row = conn.execute("SELECT id FROM domains WHERE name = ?", (name,)).fetchone()
    if row:
        return row["id"]
    return conn.execute("INSERT INTO domains (name, added) VALUES (?, ?)", (name, added or now())).lastrowid


def save_scan(conn: sqlite3.Connection, domain: str, started: str, source: str, records: Iterable[dict],
              finished: str | None = None, status: str = "done", error: str | None = None) -> int:
    """Store one scan and its records; the summary counts are computed here so history charts stay cheap."""
    did = domain_id(conn, domain, added=started)
    rows = [tuple(str(r.get(f) or "") for f in RECORD_FIELDS) for r in records]
    hosts = {r[0] for r in rows}
    resolved = {r[0] for r in rows if r[1]}
    ips = {r[1] for r in rows if r[1]}
    asns = {r[2] for r in rows if r[2]}
    countries = {r[6] for r in rows if r[6]}
    sid = conn.execute(
        "INSERT INTO scans (domain_id, started, finished, source, status, hosts, resolved, ips, asns, countries, error)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (did, started, finished or started, source, status, len(hosts), len(resolved), len(ips), len(asns),
         len(countries), error)).lastrowid
    conn.executemany(f"INSERT INTO records (scan_id, {', '.join(RECORD_FIELDS)}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     [(sid, *r) for r in rows])
    return sid


# --- reads -------------------------------------------------------------------------------------------------------

LATEST = """
SELECT s.* FROM scans s
JOIN (SELECT domain_id, MAX(started) AS started FROM scans WHERE status = 'done' GROUP BY domain_id) m
  ON m.domain_id = s.domain_id AND m.started = s.started AND s.status = 'done'
"""


def domains_overview(conn: sqlite3.Connection, query: str = "") -> list[dict]:
    """Every domain with its latest scan's counts and its number of scans."""
    sql = f"""
    SELECT d.name, d.added, l.id AS scan_id, l.started AS last_scan, l.hosts, l.resolved, l.ips, l.asns,
           l.countries, (SELECT COUNT(*) FROM scans x WHERE x.domain_id = d.id AND x.status = 'done') AS scans
    FROM domains d LEFT JOIN ({LATEST}) l ON l.domain_id = d.id
    WHERE d.name LIKE ? ORDER BY d.name"""
    return [dict(r) for r in conn.execute(sql, (f"%{query}%",))]


def totals(conn: sqlite3.Connection) -> dict:
    row = conn.execute(f"""
        SELECT (SELECT COUNT(*) FROM domains) AS domains,
               (SELECT COUNT(*) FROM scans WHERE status = 'done') AS scans,
               (SELECT MIN(started) FROM scans) AS first_scan,
               (SELECT MAX(started) FROM scans) AS last_scan,
               COALESCE(SUM(l.hosts), 0) AS hosts, COALESCE(SUM(l.ips), 0) AS ips
        FROM ({LATEST}) l""").fetchone()
    return dict(row)


def top_latest(conn: sqlite3.Connection, field: str, limit: int = 12) -> list[dict]:
    """Across every domain's latest scan: distinct addresses per country / netname / ASN, and how many domains."""
    assert field in ("country", "netname", "asn")
    sql = f"""
    SELECT r.{field} AS label, COUNT(DISTINCT r.ip) AS ips, COUNT(DISTINCT l.domain_id) AS domains
    FROM records r JOIN ({LATEST}) l ON l.id = r.scan_id
    WHERE r.ip != '' AND r.{field} != ''
    GROUP BY r.{field} ORDER BY ips DESC LIMIT ?"""
    return [dict(r) for r in conn.execute(sql, (limit,))]


def scans_per_day(conn: sqlite3.Connection) -> list[dict]:
    sql = """SELECT substr(started, 1, 10) AS day, COUNT(*) AS scans, COUNT(DISTINCT domain_id) AS domains
             FROM scans WHERE status = 'done' GROUP BY day ORDER BY day"""
    return [dict(r) for r in conn.execute(sql)]


def domain(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM domains WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def history(conn: sqlite3.Connection, name: str) -> list[dict]:
    sql = """SELECT s.id, s.started, s.source, s.status, s.hosts, s.resolved, s.ips, s.asns, s.countries, s.error
             FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.name = ? ORDER BY s.started"""
    return [dict(r) for r in conn.execute(sql, (name,))]


def scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    row = conn.execute("SELECT s.*, d.name AS domain FROM scans s JOIN domains d ON d.id = s.domain_id"
                       " WHERE s.id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def records(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    sql = f"SELECT {', '.join(RECORD_FIELDS)} FROM records WHERE scan_id = ? ORDER BY host, ip"
    return [dict(r) for r in conn.execute(sql, (scan_id,))]


def breakdown(rows: list[dict], field: str, limit: int = 10) -> list[dict]:
    """Distinct addresses per value of field; the tail is folded into 'Other'."""
    groups: dict[str, set[str]] = {}
    for r in rows:
        if r["ip"]:
            groups.setdefault(r[field] or "Unknown", set()).add(r["ip"])
    ranked = sorted(((k, len(v)) for k, v in groups.items()), key=lambda kv: (-kv[1], kv[0]))
    out = [{"label": k, "ips": n} for k, n in ranked[:limit]]
    rest = sum(n for _, n in ranked[limit:])
    if rest:
        out.append({"label": "Other", "ips": rest})
    return out


def diff(old: list[dict], new: list[dict]) -> dict:
    """Host names and addresses that appeared or disappeared between two scans."""
    old_hosts, new_hosts = {r["host"] for r in old}, {r["host"] for r in new}
    old_ips, new_ips = {r["ip"] for r in old if r["ip"]}, {r["ip"] for r in new if r["ip"]}
    old_map: dict[str, set[str]] = {}
    new_map: dict[str, set[str]] = {}
    for rows, m in ((old, old_map), (new, new_map)):
        for r in rows:
            m.setdefault(r["host"], set()).update({r["ip"]} if r["ip"] else set())
    moved = sorted(h for h in old_hosts & new_hosts if old_map[h] != new_map[h])
    return {"hosts_added": sorted(new_hosts - old_hosts), "hosts_removed": sorted(old_hosts - new_hosts),
            "ips_added": sorted(new_ips - old_ips), "ips_removed": sorted(old_ips - new_ips),
            "hosts_changed": moved}
