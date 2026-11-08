"""Public database copy: replace this instance's inventory (domains, scans, records, address and country caches)
with a copy of the public server's database, and keep this instance's own inventory scans on top.

The copy arrives on the host by itself (deploy/public-sync.sh receive, fed by a backup host); Settings > Sync asks
the root path unit domin-public-sync.path to import it (deploy/public-sync.sh import), which runs `domin
import-public <file>`. Queued jobs, users, settings, posture scans, profiles and tags are never touched, and no
job is created: nothing starts scanning because of a sync."""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from . import admin, db

REQUEST_FILE = "public-sync.request"
STATUS_FILE = "public-sync.status"
FLOOR_KEY = "public_sync:max_scan"   # scans above this id are this instance's own (kept over a sync)
INFO_KEY = "public_sync:last"
TABLES = ("domains", "scans", "records", "ip_cache", "geo")


def request_sync(state_dir: Path) -> Path:
    """Ask the root path unit to import the newest public copy: a file with the request time only."""
    path = Path(state_dir) / REQUEST_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(f"requested {db.now()}\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


def status(state_dir: Path, conn: sqlite3.Connection) -> dict:
    """{pending, at, ok, message, received (the copy's time), imported, latest, scans, records, own} from the
    import script's status file and the last import's figures; empty values when it has not run."""
    out: dict = {"pending": (Path(state_dir) / REQUEST_FILE).exists()}
    try:
        got = json.loads((Path(state_dir) / STATUS_FILE).read_text(encoding="utf-8")[:4000])
        if isinstance(got, dict):
            out.update(at=str(got.get("at") or "")[:40], ok=bool(got.get("ok")),
                       message=str(got.get("message") or "")[:300], received=str(got.get("copy") or "")[:40])
    except (OSError, ValueError):
        pass
    try:
        info = json.loads(admin.kv_get(conn, INFO_KEY) or "{}")
    except ValueError:
        info = {}
    if isinstance(info, dict):
        out.update({k: info.get(k) for k in ("imported", "latest", "scans", "records", "own")})
    return out


def _columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    return [r[1] for r in conn.execute(f"PRAGMA {schema}.table_info({table})")]


def import_public(conn: sqlite3.Connection, path: Path) -> dict:
    """Replace the inventory tables with the copy at path in one transaction; own scans (id above the last
    import's highest public id) and their records are added back with new ids, their jobs follow them."""
    conn.execute("ATTACH DATABASE ? AS pub", (str(path),))
    try:
        missing = [t for t in ("domains", "scans", "records") if not _columns(conn, "pub", t)]
        if missing:
            raise ValueError(f"the copy has no {', '.join(missing)} table")
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("BEGIN IMMEDIATE")
        floor = int(admin.kv_get(conn, FLOOR_KEY) or 0)
        scan_cols = [c for c in _columns(conn, "main", "scans") if c not in ("id", "domain_id")]
        conn.execute("CREATE TEMP TABLE own_scans AS SELECT s.*, d.name AS dname, d.added AS dadded "
                     "FROM scans s JOIN domains d ON d.id = s.domain_id WHERE s.id > ?", (floor,))
        conn.execute("CREATE TEMP TABLE own_records AS SELECT * FROM records "
                     "WHERE scan_id IN (SELECT id FROM own_scans)")
        for t in TABLES:
            have = set(_columns(conn, "pub", t))
            if not have or (t in ("ip_cache", "geo")
                            and not conn.execute(f"SELECT 1 FROM pub.{t} LIMIT 1").fetchone()):
                continue   # an empty or missing cache in the copy keeps this instance's own
            conn.execute(f"DELETE FROM main.{t}")
            names = ", ".join(c for c in _columns(conn, "main", t) if c in have)
            conn.execute(f"INSERT INTO main.{t} ({names}) SELECT {names} FROM pub.{t}")
        top = conn.execute("SELECT COALESCE(MAX(id), 0) FROM scans").fetchone()[0]
        conn.execute("CREATE TEMP TABLE scan_map AS SELECT id AS old, ? + ROW_NUMBER() OVER (ORDER BY id) AS new "
                     "FROM own_scans", (top,))
        conn.execute("INSERT OR IGNORE INTO domains (name, added) SELECT dname, MIN(dadded) FROM own_scans "
                     "GROUP BY dname")
        names = ", ".join(scan_cols)
        own_names = ", ".join(f"o.{c}" for c in scan_cols)
        conn.execute(f"INSERT INTO scans (id, domain_id, {names}) SELECT m.new, d.id, {own_names} "
                     "FROM own_scans o JOIN scan_map m ON m.old = o.id JOIN domains d ON d.name = o.dname")
        rec_cols = [c for c in _columns(conn, "main", "records") if c != "scan_id"]
        names = ", ".join(rec_cols)
        own_names = ", ".join(f"r.{c}" for c in rec_cols)
        conn.execute(f"INSERT INTO records (scan_id, {names}) SELECT m.new, {own_names} "
                     "FROM own_records r JOIN scan_map m ON m.old = r.scan_id")
        conn.execute("UPDATE jobs SET scan_id = (SELECT new FROM scan_map WHERE old = jobs.scan_id) "
                     "WHERE scan_id IN (SELECT old FROM scan_map)")
        own = conn.execute("SELECT COUNT(*) FROM scan_map").fetchone()[0]
        info = {"imported": db.now(),
                "scans": conn.execute("SELECT COUNT(*) FROM scans WHERE id <= ?", (top,)).fetchone()[0],
                "records": conn.execute("SELECT COUNT(*) FROM records").fetchone()[0], "own": own,
                "latest": conn.execute("SELECT MAX(COALESCE(finished, started)) FROM scans WHERE id <= ?",
                                       (top,)).fetchone()[0] or ""}
        admin.kv_set(conn, FLOOR_KEY, str(top))
        admin.kv_set(conn, INFO_KEY, json.dumps(info))
        for t in ("own_scans", "own_records", "scan_map"):
            conn.execute(f"DROP TABLE temp.{t}")
        conn.execute("COMMIT")
        return info
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DETACH DATABASE pub")
