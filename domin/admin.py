"""Admin side: login at /admin (allowlisted addresses), runtime tuning, job control, privacy-safe analytics.

Nothing here stores a full IP address: visitors are a daily-salted hash of address + user agent (the salt is
replaced every day, so yesterday's ids can't be linked to today's or turned back into an address), scan clients a
hash with a fixed salt (the per-hour limit needs the same id for an hour). Country comes from an optional DB-IP
lite table at request time; only the country code is kept."""
from __future__ import annotations

import csv
import gzip
import hashlib
import hmac
import ipaddress
import json
import secrets
import sqlite3
from dataclasses import fields, replace
from datetime import datetime, timedelta
from pathlib import Path

from . import db
from .config import Settings

SESSION_HOURS = 12
FAILS_PER_CLIENT, FAILS_TOTAL, FAIL_WINDOW_MIN = 5, 30, 15
PAGE_GAP_CAP = 30 * 60   # seconds: a longer gap counts as the visitor having left

# name -> (label, min, max); booleans have min/max None
TUNABLE = {
    "scans_paused": ("Pause the scan worker (queued jobs wait)", None, None),
    "once_per_day": ("Each domain at most once per day", None, None),
    "scan_limits_off": ("Disable scan limits — retry any domain freely (leave off where abuse is a concern)",
                        None, None),
    "scans_per_hour": ("Scans per hour per client", 0, 1000),
    "scans_per_day": ("Scans per day per client", 0, 100000),
    "scans_per_day_total": ("Visitor scans per day, all clients together", 0, 100000),
    "queue_max": ("Queued visitor scans before new ones are refused", 1, 10000),
    "scan_timeout_hours": ("A scan fails after N hours", 1, 48),
    "lookups_per_minute": ("RDAP / e-mail lookups per minute per client", 1, 1000),
    "max_hosts": ("Max host names per scan", 10, 50000),
    "refresh_days": ("Re-scan domains older than N days (0 = off)", 0, 3650),
    "analytics_days": ("Keep visit statistics N days", 1, 3650),
}


# --- key/value store ---------------------------------------------------------------------------------------------

def kv_get(conn: sqlite3.Connection, key: str) -> str | None:
    row = conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def kv_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                 (key, value))


def effective(settings: Settings, conn: sqlite3.Connection) -> Settings:
    """Environment values with the admin's overrides from the tuning form on top."""
    raw = kv_get(conn, "tuning")
    if not raw:
        return settings
    names = {f.name for f in fields(Settings)}
    return replace(settings, **{k: v for k, v in json.loads(raw).items() if k in TUNABLE and k in names})


def save_tuning(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    """Validate the tuning form; unticked checkboxes are absent from a form post, so booleans default to False."""
    out: dict = {}
    for name, (_, lo, hi) in TUNABLE.items():
        if lo is None:
            out[name] = form.get(name) == "on"
            continue
        try:
            value = int(form.get(name, ""))
        except ValueError:
            raise ValueError(f"{name}: not a whole number") from None
        if not lo <= value <= hi:
            raise ValueError(f"{name}: must be {lo}..{hi}")
        out[name] = value
    kv_set(conn, "tuning", json.dumps(out))
    return out


# --- password and sessions ---------------------------------------------------------------------------------------

SCRYPT_LOG_N = 15   # N = 2^15; hashes from older versions (2^14, no N field) are replaced at the next sign-in


def _scrypt(password: str, salt: bytes, log_n: int) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**log_n, r=8, p=1, maxmem=128 * 2**log_n * 8 * 2)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    return f"scrypt${SCRYPT_LOG_N}${salt.hex()}${_scrypt(password, salt, SCRYPT_LOG_N).hex()}"


def password_matches(stored: str, password: str) -> tuple[bool, bool]:
    """(ok, needs_rehash) for a stored scrypt$... hash; parses the 3-field (old N=2^14) and 4-field formats."""
    if not stored or not password:
        return False, False
    parts = stored.split("$")
    try:
        log_n, salt, want = (14, *parts[1:]) if len(parts) == 3 else (int(parts[1]), *parts[2:])
    except (ValueError, IndexError):
        return False, False
    ok = hmac.compare_digest(_scrypt(password, bytes.fromhex(salt), log_n).hex(), want)
    return ok, ok and log_n != SCRYPT_LOG_N


def check_password(conn: sqlite3.Connection, password: str) -> bool:
    """Legacy single-password check (kept for the admin-password CLI before the first user exists)."""
    stored = kv_get(conn, "admin_password")
    ok, rehash = password_matches(stored or "", password)
    if rehash:
        kv_set(conn, "admin_password", hash_password(password))   # sessions stay: same password
    return ok


def set_password(conn: sqlite3.Connection, password: str) -> None:
    kv_set(conn, "admin_password", hash_password(password))
    conn.execute("DELETE FROM admin_sessions")   # a new password signs every browser out


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def new_session(conn: sqlite3.Connection, user_id: int | None = None) -> str:
    """Returns the cookie token; only its hash is stored, next to the session's CSRF token and its user."""
    token = secrets.token_urlsafe(32)
    expires = (datetime.now() + timedelta(hours=SESSION_HOURS)).isoformat(timespec="seconds")
    conn.execute("INSERT INTO admin_sessions (token_hash, csrf, expires, user_id) VALUES (?, ?, ?, ?)",
                 (_token_hash(token), secrets.token_urlsafe(24), expires, user_id))
    return token


def session(conn: sqlite3.Connection, token: str | None) -> dict | None:
    if not token:
        return None
    row = conn.execute("SELECT * FROM admin_sessions WHERE token_hash = ? AND expires > ?",
                       (_token_hash(token), db.now())).fetchone()
    return dict(row) if row else None


def end_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (_token_hash(token),))


def end_user_sessions(conn: sqlite3.Connection, user_id: int) -> None:
    """Sign a user out everywhere (after a password, role or disable change)."""
    conn.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))


def login_blocked(conn: sqlite3.Connection, client: str) -> bool:
    since = (datetime.now() - timedelta(minutes=FAIL_WINDOW_MIN)).isoformat(timespec="seconds")
    mine = conn.execute("SELECT COUNT(*) FROM admin_fails WHERE client = ? AND at >= ?", (client, since)).fetchone()[0]
    total = conn.execute("SELECT COUNT(*) FROM admin_fails WHERE at >= ?", (since,)).fetchone()[0]
    return mine >= FAILS_PER_CLIENT or total >= FAILS_TOTAL


def login_failed(conn: sqlite3.Connection, client: str) -> None:
    conn.execute("INSERT INTO admin_fails (client, at) VALUES (?, ?)", (client, db.now()))


# --- visitor ids -------------------------------------------------------------------------------------------------

def _salt(conn: sqlite3.Connection, key: str) -> str:
    # INSERT OR IGNORE: when two web processes race, both read back the first one's salt
    conn.execute("INSERT OR IGNORE INTO kv (key, value) VALUES (?, ?)", (key, secrets.token_hex(16)))
    return kv_get(conn, key) or ""


def client_key(conn: sqlite3.Connection, ip: str) -> str:
    """Stable id for the scan rate limit and login lockout, in place of the address."""
    return "h:" + hashlib.sha256((_salt(conn, "client_salt") + ip).encode()).hexdigest()[:16]


def visitor(conn: sqlite3.Connection, ip: str, agent: str) -> str:
    key = f"day_salt:{db.now()[:10]}"
    if kv_get(conn, key) is None:
        conn.execute("DELETE FROM kv WHERE key LIKE 'day_salt:%'")   # yesterday's ids become unlinkable
    return hashlib.sha256((_salt(conn, key) + ip + "|" + agent).encode()).hexdigest()[:16]


BOT_WORDS = ("bot", "crawl", "spider", "slurp", "curl", "wget", "python-", "httpx", "go-http", "headless")


def is_bot(agent: str) -> bool:
    a = agent.lower()
    return not a or any(w in a for w in BOT_WORDS)


# --- country (optional DB-IP lite table) -------------------------------------------------------------------------

def _key(ip: str) -> str:
    """Addresses as fixed-width hex in one space (IPv4 mapped into IPv6) so text order = numeric order."""
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        a = ipaddress.IPv6Address(f"::ffff:{a}")
    return f"{int(a):032x}"


def import_geo(conn: sqlite3.Connection, path: Path) -> int:
    """Load a DB-IP 'IP to Country Lite' CSV (start,end,cc; .csv or .csv.gz), replacing the old table."""
    opener = gzip.open if path.suffix == ".gz" else open
    rows = []
    with opener(path, "rt", encoding="utf-8", newline="") as f:
        for r in csv.reader(f):
            if len(r) >= 3 and len(r[2]) == 2:
                try:
                    rows.append((_key(r[0]), _key(r[1]), r[2].upper()))
                except ValueError:
                    continue
    conn.execute("DELETE FROM geo")
    conn.executemany("INSERT INTO geo (start, end, cc) VALUES (?, ?, ?)", rows)
    return len(rows)


def country(conn: sqlite3.Connection, ip: str) -> str:
    try:
        k = _key(ip.split("/")[0])
    except ValueError:
        return ""
    row = conn.execute("SELECT end, cc FROM geo WHERE start <= ? ORDER BY start DESC LIMIT 1", (k,)).fetchone()
    return row["cc"] if row and row["end"] >= k else ""


# --- recording and reporting -------------------------------------------------------------------------------------

def record(conn: sqlite3.Connection, *, kind: str, path: str, domain: str, ip: str, agent: str, ref: str) -> None:
    conn.execute("INSERT INTO visits (at, visitor, kind, path, domain, ref, country, bot) VALUES (?,?,?,?,?,?,?,?)",
                 (db.now(), visitor(conn, ip, agent), kind, path[:300], domain[:253], ref[:253],
                  country(conn, ip), int(is_bot(agent))))


def prune(conn: sqlite3.Connection, days: int) -> None:
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    conn.execute("DELETE FROM visits WHERE at < ?", (cutoff,))
    conn.execute("DELETE FROM admin_sessions WHERE expires < ?", (db.now(),))
    since = (datetime.now() - timedelta(minutes=FAIL_WINDOW_MIN)).isoformat(timespec="seconds")
    conn.execute("DELETE FROM admin_fails WHERE at < ?", (since,))


def _top(conn: sqlite3.Connection, col: str, since: str, kinds: tuple[str, ...], limit: int = 15) -> list[dict]:
    assert col in ("path", "domain", "ref", "country")
    q = f"""SELECT {col} AS label, COUNT(*) AS hits, COUNT(DISTINCT visitor) AS visitors FROM visits
            WHERE at >= ? AND bot = 0 AND {col} != '' AND kind IN ({','.join('?' * len(kinds))})
            GROUP BY {col} ORDER BY hits DESC LIMIT ?"""
    return [dict(r) for r in conn.execute(q, (since, *kinds, limit))]


def sessions(conn: sqlite3.Connection, since: str) -> list[dict]:
    """Per visitor (one id per day): start, length, pages in order with the time spent on each."""
    by: dict[str, list] = {}
    for r in conn.execute("SELECT visitor, at, kind, path, country, ref FROM visits WHERE at >= ? AND bot = 0 "
                          "ORDER BY visitor, at", (since,)):
        by.setdefault(r["visitor"], []).append(r)
    out = []
    for vid, rows in by.items():
        times = [datetime.fromisoformat(r["at"]) for r in rows]
        steps = []
        for i, r in enumerate(rows):
            gap = (times[i + 1] - times[i]).total_seconds() if i + 1 < len(rows) else None
            steps.append({"kind": r["kind"], "path": r["path"],
                          "seconds": int(gap) if gap is not None and gap <= PAGE_GAP_CAP else None})
        out.append({"visitor": vid[:8], "start": rows[0]["at"], "seconds": sum(s["seconds"] or 0 for s in steps),
                    "hits": len(rows), "country": next((r["country"] for r in rows if r["country"]), ""),
                    "ref": next((r["ref"] for r in rows if r["ref"]), ""), "steps": steps})
    out.sort(key=lambda s: s["start"], reverse=True)
    return out


def report(conn: sqlite3.Connection, days: int = 7) -> dict:
    since = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    month = (datetime.now() - timedelta(days=30)).isoformat(timespec="seconds")
    per_day = [dict(r) for r in conn.execute(
        """SELECT substr(at, 1, 10) AS day, SUM(kind = 'page') AS views, COUNT(DISTINCT visitor) AS visitors,
                  SUM(kind = 'download') AS downloads, SUM(kind = 'scan') AS scans, SUM(kind = 'limited') AS limited,
                  SUM(kind = 'tool') AS tools
           FROM visits WHERE at >= ? AND bot = 0 GROUP BY day ORDER BY day""", (month,))]
    recent = [r for r in per_day if r["day"] >= since[:10]]
    sess = sessions(conn, since)
    lengths = sorted(s["seconds"] for s in sess)
    return {
        "days": days, "per_day": per_day,
        "bots": conn.execute("SELECT COUNT(*) FROM visits WHERE at >= ? AND bot = 1", (since,)).fetchone()[0],
        "geo": conn.execute("SELECT EXISTS (SELECT 1 FROM geo)").fetchone()[0] == 1,
        "kpi": {"visitors": len(sess), "views": sum(r["views"] or 0 for r in recent),
                "median_seconds": lengths[len(lengths) // 2] if lengths else 0,
                "downloads": sum(r["downloads"] or 0 for r in recent), "scans": sum(r["scans"] or 0 for r in recent),
                "limited": sum(r["limited"] or 0 for r in recent)},
        "pages": _top(conn, "path", since, ("page",)),
        "domains": _top(conn, "domain", since, ("page", "tool", "download", "scan")),
        "downloads": _top(conn, "domain", since, ("download",)),
        "tools": _top(conn, "path", since, ("tool",)),
        "refs": _top(conn, "ref", since, ("page",)),
        "countries": _top(conn, "country", since, ("page", "tool", "download", "scan")),
        "sessions": sess[:40],
    }
