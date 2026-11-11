"""SQLite storage. One connection per call site (cheap); WAL lets the web app read while the worker writes."""
from __future__ import annotations

import json
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
    error TEXT,
    eu INTEGER NOT NULL DEFAULT 0,        -- addresses in an EU country
    eu_known INTEGER NOT NULL DEFAULT 0,  -- addresses with a known country
    discovery TEXT NOT NULL DEFAULT '',   -- discovery profile of the nmap stage ('' = none ran)
    discovery_params TEXT NOT NULL DEFAULT ''   -- the nmap command line(s) of that stage
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
    error TEXT,
    discovery TEXT NOT NULL DEFAULT '',  -- discovery profile for the nmap stage ('' = DNS only)
    schedule_id INTEGER                  -- the schedule that queued it
);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status, created);
CREATE TABLE IF NOT EXISTS ip_cache (
    ip TEXT PRIMARY KEY,
    asn TEXT, prefix TEXT, netname TEXT, descr TEXT, country TEXT,
    fetched TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- tuning, salts, scope, pending steps
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL DEFAULT '',   -- scrypt$log_n$salt$hash; '' = no password yet (cannot sign in)
    pw_set_by_admin INTEGER NOT NULL DEFAULT 0,   -- 1: an admin set the password (users.count_signin)
    pw_grace_left INTEGER NOT NULL DEFAULT 0,     -- sign-ins it may still be kept; -1 = must renew now
    role TEXT NOT NULL DEFAULT 'power',        -- power (per-domain grants) | admin (old: viewer, analyst)
    totp_secret TEXT NOT NULL DEFAULT '',      -- '' = no second factor
    totp_required INTEGER NOT NULL DEFAULT 0,
    rights TEXT NOT NULL DEFAULT '',           -- json feature rights of a power user; '' = the defaults
    totp_last_step INTEGER NOT NULL DEFAULT -1,   -- last accepted TOTP step: a code works only once
    recovery TEXT NOT NULL DEFAULT '[]',       -- json: salted scrypt per unused recovery code (or old sha256)
    disabled INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS admin_sessions (token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires TEXT NOT NULL,
    user_id INTEGER);
CREATE TABLE IF NOT EXISTS admin_fails (client TEXT NOT NULL, at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS signin_history (   -- completed sign-ins per user (domin.guard), kept N days
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, at TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '',
    net TEXT NOT NULL DEFAULT '', cc TEXT NOT NULL DEFAULT '', place TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS signin_history_user ON signin_history(user_id, at);
CREATE TABLE IF NOT EXISTS signin_pending (   -- sign-ins from a new place waiting for an admin (domin.guard)
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, at TEXT NOT NULL, ip TEXT NOT NULL DEFAULT '',
    net TEXT NOT NULL DEFAULT '', cc TEXT NOT NULL DEFAULT '', place TEXT NOT NULL, agent TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | denied
    decided_by TEXT NOT NULL DEFAULT '', decided_at TEXT);
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
CREATE TABLE IF NOT EXISTS posture_scans (   -- stage 2: one fingerprint + CVE match per address (domin.posture)
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    ip TEXT NOT NULL,
    hosts TEXT NOT NULL DEFAULT '',       -- the inventory's host names at this address, comma separated
    country TEXT NOT NULL DEFAULT '',
    ports TEXT NOT NULL,                  -- the scan parameters: nmap port list
    status TEXT NOT NULL,                 -- queued | running | done | failed
    requested_by TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    started TEXT,
    finished TEXT,
    services TEXT NOT NULL DEFAULT '[]',  -- json: open ports with service, version, CPEs and CVE findings
    open_ports INTEGER NOT NULL DEFAULT 0,
    cves INTEGER NOT NULL DEFAULT 0,      -- distinct CVEs
    high INTEGER NOT NULL DEFAULT 0,      -- distinct critical + high CVEs
    note TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL DEFAULT '',         -- nmap XML as returned
    profile TEXT NOT NULL DEFAULT '',     -- scan profile the parameters came from
    intensity INTEGER NOT NULL DEFAULT 2,
    timing INTEGER NOT NULL DEFAULT 3,
    timeout INTEGER NOT NULL DEFAULT 120,
    params TEXT NOT NULL DEFAULT '',      -- the nmap command line that ran
    route TEXT NOT NULL DEFAULT '',       -- scan route id from the profile ('' = the default route, 'direct')
    chunks INTEGER NOT NULL DEFAULT 0,    -- port chunks in this scan (one nmap run each)
    chunks_done INTEGER NOT NULL DEFAULT 0,  -- chunks finished; services/raw hold their results (resume point)
    schedule_id INTEGER                     -- the schedule that queued it
);
CREATE TABLE IF NOT EXISTS posture_profiles (   -- named scan parameter sets, picked per posture scan
    name TEXT PRIMARY KEY,
    ports TEXT NOT NULL,
    intensity INTEGER NOT NULL DEFAULT 7,  -- nmap --version-intensity 0-9 (7: nmap's own default)
    timing INTEGER NOT NULL DEFAULT 3,     -- nmap -T1..-T4
    timeout INTEGER NOT NULL DEFAULT 900,  -- per-host seconds
    route TEXT NOT NULL DEFAULT '',        -- scan route id (proxy.py): '' = the default route, 'direct'
    note TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS posture_target ON posture_scans(domain, ip, id);
CREATE INDEX IF NOT EXISTS posture_status ON posture_scans(status, id);
CREATE TABLE IF NOT EXISTS host_tags (   -- analyst labels per discovered host name (domin.tags)
    host TEXT NOT NULL,
    tag TEXT NOT NULL,
    added TEXT NOT NULL,
    added_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (host, tag)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS host_tags_tag ON host_tags(tag, host);
CREATE TABLE IF NOT EXISTS grants (   -- delegation: a power user's domains (domin.access)
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,                 -- a domain name (covers the domains under it) or '*' = every domain
    level TEXT NOT NULL,                  -- viewer | admin (maintainer: that domain's actions too)
    added TEXT NOT NULL,
    added_by TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, domain)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS discovery_profiles (   -- nmap discovery stage parameters (domin.discovery)
    name TEXT PRIMARY KEY,
    method TEXT NOT NULL DEFAULT 'syn',      -- default | none | syn | ack | udp | echo | timestamp
    probe_ports TEXT NOT NULL DEFAULT '',    -- -PS/-PA/-PU port list
    port_mode TEXT NOT NULL DEFAULT 'none',  -- none (-sn) | top | list
    top_ports INTEGER NOT NULL DEFAULT 100,
    ports TEXT NOT NULL DEFAULT '',
    timing INTEGER NOT NULL DEFAULT 3,       -- -T0..-T5
    max_rate INTEGER NOT NULL DEFAULT 0,     -- 0 = unset
    max_retries INTEGER NOT NULL DEFAULT 1,
    host_timeout INTEGER NOT NULL DEFAULT 120,
    rdns INTEGER NOT NULL DEFAULT 0,         -- 1 = -R, 0 = -n
    route TEXT NOT NULL DEFAULT '',          -- '' = the inventory route, 'direct', or a route id
    note TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS discovery_results (   -- what the nmap discovery stage of a scan found
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    names TEXT NOT NULL DEFAULT '',    -- names nmap reported, comma separated
    ports TEXT NOT NULL DEFAULT '',    -- open ports, e.g. 22/tcp,443/tcp
    reason TEXT NOT NULL DEFAULT ''    -- why nmap counted it as up
);
CREATE INDEX IF NOT EXISTS discovery_results_scan ON discovery_results(scan_id);
CREATE TABLE IF NOT EXISTS schedules (   -- scheduled rescans of one domain (domin.schedules)
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    discovery INTEGER NOT NULL DEFAULT 0,          -- run an inventory scan
    discovery_profile TEXT NOT NULL DEFAULT '',    -- '' = DNS only
    posture INTEGER NOT NULL DEFAULT 0,            -- run posture scans
    posture_profile TEXT NOT NULL DEFAULT 'default',
    host_mode TEXT NOT NULL DEFAULT 'all',         -- all | list | tag
    hosts TEXT NOT NULL DEFAULT '[]',              -- json: chosen host names (list)
    tag TEXT NOT NULL DEFAULT '',                  -- host or network tag (tag)
    freq TEXT NOT NULL DEFAULT 'daily',            -- daily | weekly | monthly | hours | days
    at_time TEXT NOT NULL DEFAULT '03:00',         -- HH:MM server local time
    weekday INTEGER NOT NULL DEFAULT 0,            -- 0 = Monday
    monthday INTEGER NOT NULL DEFAULT 1,
    every INTEGER NOT NULL DEFAULT 1,              -- N for hours / days
    anchor TEXT NOT NULL DEFAULT '',               -- first slot (local), the base of every N hours / days
    next_ts REAL,                                  -- epoch of the next run (NULL = none)
    next_run TEXT NOT NULL DEFAULT '',             -- the same, local time, for display
    last_run TEXT NOT NULL DEFAULT '',
    last_job INTEGER,                              -- inventory job of the last run
    wait_job INTEGER,                              -- inventory job whose end queues the posture part
    last_result TEXT NOT NULL DEFAULT '',
    created TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    updated TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS schedules_domain ON schedules(domain);
CREATE TABLE IF NOT EXISTS audit (    -- who changed users, roles and grants
    id INTEGER PRIMARY KEY,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
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
        conn.execute("BEGIN IMMEDIATE")   # web and worker start together: one of them adds the columns
        if "eu" not in {r["name"] for r in conn.execute("PRAGMA table_info(scans)")}:
            conn.execute("ALTER TABLE scans ADD COLUMN eu INTEGER NOT NULL DEFAULT 0")
            conn.execute("ALTER TABLE scans ADD COLUMN eu_known INTEGER NOT NULL DEFAULT 0")
            conn.execute(f"""
                UPDATE scans SET eu = c.eu, eu_known = c.known FROM (
                    SELECT scan_id, SUM({_EU_SQL}) AS eu, COUNT(*) AS known FROM (
                        SELECT DISTINCT scan_id, ip, country FROM records WHERE ip != '' AND country != '')
                    GROUP BY scan_id) c
                WHERE scans.id = c.scan_id""", EU_NAMES)
        if "rights" not in {r["name"] for r in conn.execute("PRAGMA table_info(users)")}:
            from .access import DEFAULT_RIGHTS  # local import: access -> db
            conn.execute("ALTER TABLE users ADD COLUMN rights TEXT NOT NULL DEFAULT ''")
            conn.execute("UPDATE users SET rights = ?", (json.dumps(DEFAULT_RIGHTS, sort_keys=True),))
        have = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        for col in ("pw_set_by_admin", "pw_grace_left"):
            if col not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0")
        # the removed set-password links: their tokens (kv setpw:*) and the admin's once-shown copies (setpw-link:*)
        conn.execute("DELETE FROM kv WHERE key LIKE 'setpw:%' OR key LIKE 'setpw-link:%'")
        if "user_id" not in {r["name"] for r in conn.execute("PRAGMA table_info(admin_sessions)")}:
            conn.execute("ALTER TABLE admin_sessions ADD COLUMN user_id INTEGER")
        have = {r["name"] for r in conn.execute("PRAGMA table_info(admin_sessions)")}
        for col in ("created", "ip", "country", "agent"):   # the session list (My account, Users)
            if col not in have:
                conn.execute(f"ALTER TABLE admin_sessions ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        have = {r["name"] for r in conn.execute("PRAGMA table_info(posture_scans)")}
        for col, ddl in (("profile", "TEXT NOT NULL DEFAULT ''"), ("intensity", "INTEGER NOT NULL DEFAULT 2"),
                         ("timing", "INTEGER NOT NULL DEFAULT 3"), ("timeout", "INTEGER NOT NULL DEFAULT 120"),
                         ("params", "TEXT NOT NULL DEFAULT ''"), ("route", "TEXT NOT NULL DEFAULT ''"),
                         ("chunks", "INTEGER NOT NULL DEFAULT 0"), ("chunks_done", "INTEGER NOT NULL DEFAULT 0")):
            if col not in have:
                conn.execute(f"ALTER TABLE posture_scans ADD COLUMN {col} {ddl}")
        if "route" not in {r["name"] for r in conn.execute("PRAGMA table_info(posture_profiles)")}:
            conn.execute("ALTER TABLE posture_profiles ADD COLUMN route TEXT NOT NULL DEFAULT ''")
        for table, cols in (("jobs", (("discovery", "TEXT NOT NULL DEFAULT ''"), ("schedule_id", "INTEGER"))),
                            ("scans", (("discovery", "TEXT NOT NULL DEFAULT ''"),
                                       ("discovery_params", "TEXT NOT NULL DEFAULT ''"))),
                            ("posture_scans", (("schedule_id", "INTEGER"),))):
            have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in cols:
                if col not in have:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
        conn.execute("CREATE INDEX IF NOT EXISTS jobs_schedule ON jobs(schedule_id, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS posture_schedule ON posture_scans(schedule_id, status)")
        conn.execute("""INSERT OR IGNORE INTO discovery_profiles (name, method, probe_ports, port_mode, timing,
                        max_rate, max_retries, host_timeout, rdns, note, updated) VALUES ('default', 'syn',
                        '22,80,443', 'none', 3, 100, 1, 120, 0, 'TCP SYN ping on 22, 80, 443; no port check', ?)""",
                     (now(),))
        from .fingerprint import DEFAULT_PORTS  # local import: fingerprint -> cve
        # a fresh install's default profile: nmap's own version intensity (7) and 15 minutes per host; an existing
        # database keeps its profile as the admin left it
        conn.execute("INSERT OR IGNORE INTO posture_profiles (name, ports, intensity, timeout, note, updated) "
                     "VALUES ('default', ?, 7, 900, ?, ?)",
                     (DEFAULT_PORTS, "Common services, nmap's default version probes", now()))
        from . import users  # local import: users -> admin -> db
        users.migrate_legacy_admin(conn)
        users.migrate_roles(conn)
        users.migrate_signin(conn)
        users.migrate_totp_encryption(conn)   # plaintext two-factor values from before encryption; needs the key


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
    located = {(r[1], r[6]) for r in rows if r[1] and r[6]}
    eu = sum(1 for _, c in located if c in EU_NAMES)
    sid = conn.execute(
        "INSERT INTO scans (domain_id, started, finished, source, status, hosts, resolved, ips, asns, countries, error,"
        " eu, eu_known) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (did, started, finished or started, source, status, len(hosts), len(resolved), len(ips), len(asns),
         len(countries), error, eu, len(located))).lastrowid
    conn.executemany(f"INSERT INTO records (scan_id, {', '.join(RECORD_FIELDS)}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     [(sid, *r) for r in rows])
    return sid


def save_discovery(conn: sqlite3.Connection, scan_id: int, profile: str, params: str, found: list[dict]) -> None:
    """The nmap discovery stage of a scan (domin.discovery): its profile, command line and live addresses."""
    conn.execute("UPDATE scans SET discovery = ?, discovery_params = ? WHERE id = ?", (profile, params, scan_id))
    conn.executemany("INSERT INTO discovery_results (scan_id, ip, names, ports, reason) VALUES (?, ?, ?, ?, ?)",
                     [(scan_id, f["ip"], ",".join(f.get("names") or []), ",".join(f.get("ports") or []),
                       f.get("reason") or "") for f in found])


def discovery_results(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT ip, names, ports, reason FROM discovery_results WHERE scan_id = ? "
                                          "ORDER BY ip", (scan_id,))]


def delete_domain(conn: sqlite3.Connection, name: str) -> bool:
    """Admin action: drop a domain and all of its scans, records and jobs from the inventory. Returns False when
    the domain is unknown. User accounts, settings and scope are untouched."""
    row = conn.execute("SELECT id FROM domains WHERE name = ?", (name,)).fetchone()
    if not row:
        return False
    did = row["id"]
    conn.execute("DELETE FROM records WHERE scan_id IN (SELECT id FROM scans WHERE domain_id = ?)", (did,))
    conn.execute("DELETE FROM scans WHERE domain_id = ?", (did,))
    conn.execute("DELETE FROM jobs WHERE domain = ?", (name,))
    conn.execute("DELETE FROM posture_scans WHERE domain = ?", (name,))
    conn.execute("DELETE FROM schedules WHERE domain = ?", (name,))
    conn.execute("DELETE FROM discovery_results WHERE scan_id NOT IN (SELECT id FROM scans)")
    conn.execute("DELETE FROM host_tags WHERE host = ? OR host LIKE ?", (name, "%." + name))
    conn.execute("DELETE FROM domains WHERE id = ?", (did,))
    return True


# --- reads -------------------------------------------------------------------------------------------------------

LATEST = """
SELECT s.* FROM scans s
JOIN (SELECT domain_id, MAX(started) AS started FROM scans WHERE status = 'done' GROUP BY domain_id) m
  ON m.domain_id = s.domain_id AND m.started = s.started AND s.status = 'done'
"""


def in_scope(scope, column: str) -> tuple[str, list]:
    """The delegation filter (domin.access.Scope.sql) on a domain-name column; None = every domain."""
    return scope.sql(column) if scope is not None else ("1", [])


def domains_overview(conn: sqlite3.Connection, query: str = "", scope=None) -> list[dict]:
    """Every domain (in scope) with its latest scan's counts and its number of scans."""
    f, fa = in_scope(scope, "d.name")
    sql = f"""
    SELECT d.name, d.added, l.id AS scan_id, l.started AS last_scan, l.hosts, l.resolved, l.ips, l.asns,
           l.countries, (SELECT COUNT(*) FROM scans x WHERE x.domain_id = d.id AND x.status = 'done') AS scans
    FROM domains d LEFT JOIN ({LATEST}) l ON l.domain_id = d.id
    WHERE d.name LIKE ? AND {f} ORDER BY d.name"""
    return [dict(r) for r in conn.execute(sql, (f"%{query}%", *fa))]


def totals(conn: sqlite3.Connection, scope=None) -> dict:
    f, fa = in_scope(scope, "d.name")
    row = conn.execute(f"""
        SELECT (SELECT COUNT(*) FROM domains d WHERE {f}) AS domains,
               (SELECT COUNT(*) FROM scans s JOIN domains d ON d.id = s.domain_id
                WHERE s.status = 'done' AND {f}) AS scans,
               (SELECT MIN(s.started) FROM scans s JOIN domains d ON d.id = s.domain_id WHERE {f}) AS first_scan,
               (SELECT MAX(s.started) FROM scans s JOIN domains d ON d.id = s.domain_id WHERE {f}) AS last_scan,
               COALESCE(SUM(l.hosts), 0) AS hosts, COALESCE(SUM(l.ips), 0) AS ips
        FROM ({LATEST}) l JOIN domains d ON d.id = l.domain_id WHERE {f}""", fa * 5).fetchone()
    return dict(row)


def top_latest(conn: sqlite3.Connection, field: str, limit: int = 12, scope=None) -> list[dict]:
    """Across every domain's latest scan: distinct addresses per country / netname / ASN, and how many domains."""
    assert field in ("country", "netname", "asn")
    f, fa = in_scope(scope, "d.name")
    sql = f"""
    SELECT r.{field} AS label, COUNT(DISTINCT r.ip) AS ips, COUNT(DISTINCT l.domain_id) AS domains
    FROM records r JOIN ({LATEST}) l ON l.id = r.scan_id JOIN domains d ON d.id = l.domain_id
    WHERE r.ip != '' AND r.{field} != '' AND {f}
    GROUP BY r.{field} ORDER BY ips DESC LIMIT ?"""
    return [dict(r) for r in conn.execute(sql, (*fa, limit))]


def scans_per_day(conn: sqlite3.Connection, scope=None) -> list[dict]:
    f, fa = in_scope(scope, "d.name")
    sql = f"""SELECT substr(s.started, 1, 10) AS day, COUNT(*) AS scans, COUNT(DISTINCT s.domain_id) AS domains
              FROM scans s JOIN domains d ON d.id = s.domain_id WHERE s.status = 'done' AND {f}
              GROUP BY day ORDER BY day"""
    return [dict(r) for r in conn.execute(sql, fa)]


def domain(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM domains WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def history(conn: sqlite3.Connection, name: str) -> list[dict]:
    sql = """SELECT s.id, s.started, s.source, s.status, s.hosts, s.resolved, s.ips, s.asns, s.countries, s.error,
                    s.eu, s.eu_known, s.discovery, s.discovery_params
             FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.name = ? ORDER BY s.started"""
    return [{**dict(r), "eu_pct": eu_pct(r["eu"], r["eu_known"])} for r in conn.execute(sql, (name,))]


def scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    row = conn.execute("SELECT s.*, d.name AS domain FROM scans s JOIN domains d ON d.id = s.domain_id"
                       " WHERE s.id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def records(conn: sqlite3.Connection, scan_id: int) -> list[dict]:
    sql = f"SELECT {', '.join(RECORD_FIELDS)} FROM records WHERE scan_id = ? ORDER BY host, ip"
    return [dict(r) for r in conn.execute(sql, (scan_id,))]


SEARCH_FIELDS = ("host", "ip", "asn", "prefix", "netname", "descr", "country")


def like_escape(text: str) -> str:
    """text for a LIKE pattern with ESCAPE '\\': its wildcards and the escape character matched literally."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _like(text: str) -> str:
    return "%" + like_escape(text) + "%"


def _matching(q: str, field: str, history: bool, columns: dict[str, str] | None, scope=None) -> tuple[str, list]:
    """FROM ... WHERE ... for the records of a search: r = record, s = its scan, d = its domain. q matches field (any
    field when empty), each column in columns (domain or a SEARCH_FIELDS name -> text) must match its text too;
    the latest scan per domain, or with history every finished scan."""
    fields = (field,) if field in SEARCH_FIELDS else SEARCH_FIELDS
    where = "(" + " OR ".join(f"r.{f} LIKE ? ESCAPE '\\'" for f in fields) + ")" if q else "1"
    args = [_like(q)] * len(fields) if q else []
    for col, text in (columns or {}).items():
        negate = text.startswith("!")   # "!text": rows without it, as in the old version
        text = text[1:] if negate else text
        if not text or col not in (*SEARCH_FIELDS, "domain", "eu"):
            continue
        expr = {"domain": "d.name", "eu": EU_EXPR}.get(col, f"COALESCE(r.{col}, '')")
        where += f" AND {expr} {'NOT ' if negate else ''}LIKE ? ESCAPE '\\'"
        args.append(_like(text)[1:] if col == "eu" else _like(text))   # EU: from the start, so "eu" isn't "Non-EU"
    f, fa = in_scope(scope, "d.name")
    scans = "scans s" if history else f"({LATEST}) s"
    done = "s.status = 'done' AND " if history else ""
    return (f"FROM records r JOIN {scans} ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id"
            f" WHERE {done}{f} AND ({where})"), [*fa, *args]


def search(conn: sqlite3.Connection, q: str = "", field: str = "", history: bool = False,
           limit: int = 100, offset: int = 0, columns: dict[str, str] | None = None,
           scope=None) -> tuple[list[dict], int]:
    """A page of the records that match (see _matching); with history folded to one row per domain, host and
    address with first and last seen. Returns (page of rows, total matches)."""
    frm, args = _matching(q, field, history, columns, scope)
    cols = ", ".join(f"r.{f}" for f in RECORD_FIELDS) + f", {EU_EXPR} AS eu"
    if history:
        sql = f"""SELECT d.name AS domain, {cols}, MIN(s.started) AS first_seen, MAX(s.started) AS last_seen,
                         COUNT(*) AS seen, COUNT(*) OVER () AS total {frm}
                  GROUP BY s.domain_id, r.host, r.ip ORDER BY r.host, r.ip LIMIT ? OFFSET ?"""
    else:
        sql = f"""SELECT d.name AS domain, {cols}, s.started AS last_seen, COUNT(*) OVER () AS total {frm}
                  ORDER BY r.host, r.ip LIMIT ? OFFSET ?"""
    rows = [dict(r) for r in conn.execute(sql, (*args, limit, offset))]
    return rows, rows[0]["total"] if rows else 0


def search_summary(conn: sqlite3.Connection, q: str = "", field: str = "", history: bool = False,
                   columns: dict[str, str] | None = None, top: int = 10, scope=None) -> dict:
    """Counts and the top countries / networks / ASNs (distinct addresses) of the records that match."""
    frm, args = _matching(q, field, history, columns, scope)
    row = conn.execute(f"""SELECT COUNT(DISTINCT r.host) AS hosts, COUNT(DISTINCT NULLIF(r.ip, '')) AS ips,
        COUNT(DISTINCT s.domain_id) AS domains, COUNT(DISTINCT NULLIF(r.asn, '')) AS asns,
        COUNT(DISTINCT NULLIF(r.country, '')) AS countries {frm}""", args).fetchone()
    located = conn.execute(f"SELECT COUNT(*) AS known, SUM({_EU_SQL}) AS eu FROM (SELECT DISTINCT r.ip, r.country {frm}"
                           " AND r.ip != '' AND r.country != '')", [*EU_NAMES, *args]).fetchone()
    out = {**dict(row), "eu_pct": eu_pct(located["eu"] or 0, located["known"])}
    for f in ("country", "netname", "asn"):
        out[f] = [dict(r) for r in conn.execute(
            f"SELECT r.{f} AS label, COUNT(DISTINCT r.ip) AS ips {frm} AND r.ip != '' AND r.{f} != ''"
            f" GROUP BY r.{f} ORDER BY ips DESC LIMIT ?", (*args, top))]
    return out


def drill_columns(conn: sqlite3.Connection, history: bool = False, scope=None) -> dict:
    """Every record of the latest scans (history: one row per domain, host and address) column by column, for the
    Drilldown filtered in the browser. A column with many repeats is sent as its distinct values ("d") plus one
    index per row ("i"): about 1.7 MB gzip'd for 163k records."""
    frm, args = _matching("", "", history, None, scope)
    cols = ", ".join(f"r.{f}" for f in RECORD_FIELDS)
    keys = ["domain", *RECORD_FIELDS, "last_seen"]
    if history:
        keys += ["first_seen", "seen"]
        sql = (f"SELECT d.name, {cols}, substr(MAX(s.started), 1, 10), substr(MIN(s.started), 1, 10), COUNT(*)"
               f" {frm} GROUP BY s.domain_id, r.host, r.ip ORDER BY r.host, r.ip")
    else:
        sql = f"SELECT d.name, {cols}, substr(s.started, 1, 10) {frm} ORDER BY r.host, r.ip"
    columns: list[list] = [[] for _ in keys]
    for row in conn.execute(sql, args):
        for col, v in zip(columns, row, strict=True):
            col.append("" if v is None else v)
    i = keys.index("country")
    keys.insert(i, "eu")
    columns.insert(i, [eu_status(c) for c in columns[i]])
    out: dict = {}
    for k, vals in zip(keys, columns, strict=True):
        uniq = list(dict.fromkeys(vals))
        if len(uniq) < len(vals) / 2:
            index = {v: i for i, v in enumerate(uniq)}
            out[k] = {"d": uniq, "i": [index[v] for v in vals]}
        else:
            out[k] = vals
    return {"rows": len(columns[0]), "columns": out, "eu": EU_NAMES}


def country_map(rows: list[dict], hosts: int = 12) -> list[dict]:
    """For the world map: every country with distinct addresses, and up to `hosts` of its host names (`more` = the
    rest). Rows without an address or a country are left out."""
    groups: dict[str, tuple[set[str], set[str]]] = {}
    for r in rows:
        if r["ip"] and r["country"]:
            ips, names = groups.setdefault(r["country"], (set(), set()))
            ips.add(r["ip"])
            names.add(r["host"])
    return [{"label": k, "ips": len(ips), "hosts": sorted(names)[:hosts], "more": max(0, len(names) - hosts)}
            for k, (ips, names) in sorted(groups.items(), key=lambda kv: (-len(kv[1][0]), kv[0]))]


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


# EU member states: records store full names (pycountry), legacy imports the old version's names
EU_CODES = "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split()


def _eu_names() -> list[str]:
    import pycountry
    names = {pycountry.countries.get(alpha_2=c).name for c in EU_CODES}   # e.g. Czechia
    return sorted(names | {"Czech Republic", "Netherlands"} | set(EU_CODES))


EU_NAMES = _eu_names()
_EU_SQL = f"country IN ({','.join('?' * len(EU_NAMES))})"
_EU_SET = frozenset(EU_NAMES)
# the old version's "EU Status" column: EU / Non-EU, empty when the country is unknown
EU_EXPR = ("CASE WHEN COALESCE(r.country, '') = '' THEN '' WHEN r.country IN ("
           + ",".join("'" + n.replace("'", "''") + "'" for n in EU_NAMES) + ") THEN 'EU' ELSE 'Non-EU' END")


def eu_status(country: str | None) -> str:
    return "" if not country else "EU" if country in _EU_SET else "Non-EU"


def eu_pct(eu: int, known: int) -> float | None:
    return round(100 * eu / known, 1) if known else None


FOOTPRINT = ("hosts", "resolved", "ips")


def footprint_per_day(conn: sqlite3.Connection, since: str = "", scope=None) -> list[dict]:
    """The public footprint across all domains per day with a finished scan: each domain's latest finished scan as of
    that day (carried forward), summed: domains, host names, host names with an address, addresses. Days from since
    (YYYY-MM-DD) on; earlier scans still count as the state a domain was in."""
    latest: dict[int, tuple] = {}
    out: dict[str, dict] = {}
    f, fa = in_scope(scope, "d.name")
    for r in conn.execute(f"""SELECT s.domain_id, substr(s.started, 1, 10) AS day, s.hosts, s.resolved, s.ips
                              FROM scans s JOIN domains d ON d.id = s.domain_id
                              WHERE s.status = 'done' AND {f} ORDER BY s.started""", fa):
        latest[r["domain_id"]] = (r["hosts"] or 0, r["resolved"] or 0, r["ips"] or 0)
        if r["day"] >= since:
            out[r["day"]] = {"day": r["day"], "domains": len(latest),
                             **{k: sum(v[i] for v in latest.values()) for i, k in enumerate(FOOTPRINT)}}
    return list(out.values())


def eu_per_day(conn: sqlite3.Connection, scope=None) -> list[dict]:
    """Share of addresses in the EU across all scans per day, as the old version's EU changes report."""
    f, fa = in_scope(scope, "d.name")
    sql = f"""SELECT substr(s.started, 1, 10) AS day, SUM(s.eu) AS eu, SUM(s.eu_known) AS known
              FROM scans s JOIN domains d ON d.id = s.domain_id
              WHERE s.status = 'done' AND {f} GROUP BY day HAVING known > 0 ORDER BY day"""
    return [{"day": r["day"], "pct": eu_pct(r["eu"], r["known"])} for r in conn.execute(sql, fa)]


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
