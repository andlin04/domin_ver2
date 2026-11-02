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
    error TEXT,
    eu INTEGER NOT NULL DEFAULT 0,        -- addresses in an EU country
    eu_known INTEGER NOT NULL DEFAULT 0   -- addresses with a known country
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
    sql = """SELECT s.id, s.started, s.source, s.status, s.hosts, s.resolved, s.ips, s.asns, s.countries, s.error,
                    s.eu, s.eu_known
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


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _matching(q: str, field: str, history: bool, columns: dict[str, str] | None) -> tuple[str, list]:
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
    scans = "scans s" if history else f"({LATEST}) s"
    done = "s.status = 'done' AND " if history else ""
    return (f"FROM records r JOIN {scans} ON s.id = r.scan_id JOIN domains d ON d.id = s.domain_id"
            f" WHERE {done}({where})"), args


def search(conn: sqlite3.Connection, q: str = "", field: str = "", history: bool = False,
           limit: int = 100, offset: int = 0, columns: dict[str, str] | None = None) -> tuple[list[dict], int]:
    """A page of the records that match (see _matching); with history folded to one row per domain, host and
    address with first and last seen. Returns (page of rows, total matches)."""
    frm, args = _matching(q, field, history, columns)
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
                   columns: dict[str, str] | None = None, top: int = 10) -> dict:
    """Counts and the top countries / networks / ASNs (distinct addresses) of the records that match."""
    frm, args = _matching(q, field, history, columns)
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


def drill_columns(conn: sqlite3.Connection, history: bool = False) -> dict:
    """Every record of the latest scans (history: one row per domain, host and address) column by column, for the
    Drilldown filtered in the browser. A column with many repeats is sent as its distinct values ("d") plus one
    index per row ("i"): about 1.7 MB gzip'd for 163k records."""
    frm, args = _matching("", "", history, None)
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


def eu_per_day(conn: sqlite3.Connection) -> list[dict]:
    """Share of addresses in the EU across all scans per day, as the old version's EU changes report."""
    sql = """SELECT substr(started, 1, 10) AS day, SUM(eu) AS eu, SUM(eu_known) AS known FROM scans
             WHERE status = 'done' GROUP BY day HAVING known > 0 ORDER BY day"""
    return [{"day": r["day"], "pct": eu_pct(r["eu"], r["known"])} for r in conn.execute(sql)]


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
