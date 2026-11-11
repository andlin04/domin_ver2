"""CSV import: the inventory's own CSV download (All records and search, /search.csv) loaded back as imported scans.

One imported scan per domain: its records are the file's rows for that domain, its time the newest last_seen of those
rows (the import time when the file has none). A domain that already has a scan at that time is skipped, so importing
the same file again adds nothing; existing scans are never changed or deleted. Domains outside the inventory scope
(Settings > Scope) are skipped and counted. Settings > CSV import streams the upload to a file in the data directory
and queues it; the worker runs it (run_pending). `python -m domin import-csv <file>` runs import_file directly."""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path

from . import access, admin, db, users
from .validate import normalize_domain

MAX_BYTES = 200 * 1024 * 1024   # upload and file size cap
REQUIRED = ("domain", *db.RECORD_FIELDS)
OPTIONAL = ("eu", "first_seen", "last_seen", "seen")
FORMULA = ("=", "+", "-", "@", "\t", "\r")   # what the exporter's csv_safe prefixes with '
SOURCE = "import"   # shown as "(imported)" on the domain page, like the old importer's scans
PENDING_KEY = "csv_import:pending"
STATUS_KEY = "csv_import:status"
PREFIX = "csv-import-"   # temp files in the data directory
TEXT_MAX = {"netname": 200, "descr": 1000, "country": 100}
ERRORS_KEPT = 10
_HOST_LABEL = re.compile(r"^(\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$")
_ASN = re.compile(r"^(\d{1,10}|NA)?$")
_WHEN = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RANGE_SPLIT = re.compile(r"\s*,\s*|\s+-\s+")


class TooLarge(Exception):
    """The upload or file is above MAX_BYTES."""


def unescape(value: str) -> str:
    """Undo the exporter's formula escape: a ' it put before = + - @ tab or CR."""
    return value[1:] if value[:1] == "'" and value[1:2] in FORMULA and len(value) > 1 else value


def check_header(header: list[str]) -> list[str]:
    """The column names, or ValueError when they are not the export's (domain + record fields, optional extras)."""
    names = [h.strip().lower() for h in header]
    if len(set(names)) != len(names):
        raise ValueError("the header repeats a column")
    missing = [n for n in REQUIRED if n not in names]
    unknown = [n for n in names if n not in REQUIRED and n not in OPTIONAL]
    if missing or unknown:
        raise ValueError("not a domin CSV export: " + "; ".join(
            x for x in (f"missing {', '.join(missing)}" if missing else "",
                        f"unknown {', '.join(u[:40] for u in unknown[:5])}" if unknown else "") if x))
    return names


def _host_ok(v: str) -> bool:
    return 0 < len(v) <= 253 and all(_HOST_LABEL.match(x) for x in v.split("."))


def _net_ok(v: str) -> bool:
    try:
        return all(ipaddress.ip_network(p, strict=False) for p in _RANGE_SPLIT.split(v))
    except ValueError:
        return False


def _when(v: str) -> str | None:
    """ISO time (a date gets T00:00:00); None when it is not one."""
    if not _WHEN.match(v):
        return None
    v = v if "T" in v else v + "T00:00:00"
    try:
        datetime.fromisoformat(v)
    except ValueError:
        return None
    return v


def clean_row(row: dict, zones: tuple[str, ...] = ()) -> tuple[dict | None, str]:
    """(record with domain and time, "") for a valid row, else (None, reason)."""
    v = {k: unescape(x).strip() for k, x in row.items()}
    if normalize_domain(v["domain"], zones) != v["domain"]:
        return None, "domain"
    host = v["host"].lower().rstrip(".")
    if not _host_ok(host):
        return None, "host"
    if v["ip"]:
        try:
            v["ip"] = str(ipaddress.ip_address(v["ip"]))
        except ValueError:
            return None, "ip"
    if not _ASN.match(v["asn"]):
        return None, "asn"
    if v["prefix"] and (len(v["prefix"]) > 200 or not _net_ok(v["prefix"])):
        return None, "prefix"
    for k, n in TEXT_MAX.items():
        if len(v[k]) > n or _CONTROL.search(v[k]):
            return None, k
    if v.get("eu", "") not in ("", "EU", "Non-EU"):
        return None, "eu"
    if not re.fullmatch(r"\d{0,10}", v.get("seen", "")):
        return None, "seen"
    times = {}
    for k in ("first_seen", "last_seen"):
        if v.get(k):
            times[k] = _when(v[k])
            if not times[k]:
                return None, k
    rec = {"domain": v["domain"], "host": host, **{f: v[f] for f in db.RECORD_FIELDS[1:]},
           "when": times.get("last_seen", "")}
    return rec, ""


def _stage(path: Path, stage: sqlite3.Connection, zones: tuple[str, ...], stats: dict, progress) -> None:
    """Read and check the file into the staging table r; counts go to stats."""
    if path.stat().st_size > MAX_BYTES:
        raise TooLarge(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    cols = ", ".join(("domain", *db.RECORD_FIELDS, "seen_at"))
    stage.execute(f"CREATE TABLE r ({cols})")
    batch: list[tuple] = []
    sql = f"INSERT INTO r ({cols}) VALUES ({', '.join('?' * (len(db.RECORD_FIELDS) + 2))})"
    try:
        with path.open(newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            names = check_header(next(reader, []))
            for row in reader:
                if not any(x.strip() for x in row):
                    continue
                stats["rows"] += 1
                if len(row) != len(names):
                    rec, why = None, "columns"
                else:
                    rec, why = clean_row(dict(zip(names, row, strict=True)), zones)
                if rec is None:
                    stats["bad"] += 1
                    if len(stats["errors"]) < ERRORS_KEPT:
                        stats["errors"].append(f"line {reader.line_num}: {why}")
                    continue
                batch.append((rec["domain"], *(rec[k] for k in db.RECORD_FIELDS), rec["when"]))
                if len(batch) >= 5000:
                    stage.executemany(sql, batch)
                    batch.clear()
                    progress(stats)
    except UnicodeDecodeError:
        raise ValueError("the file is not UTF-8 text") from None
    except csv.Error as e:
        raise ValueError(f"not a readable CSV file: {e}") from None
    stage.executemany(sql, batch)
    stage.execute("CREATE INDEX r_domain ON r(domain)")


def import_file(conn: sqlite3.Connection, path: Path, zones: tuple[str, ...] = (), actor: str = "cli",
                name: str = "", progress=lambda stats: None, work_dir: Path | None = None) -> dict:
    """Check every row, then store one imported scan per domain (see the module text). Returns the counts;
    ValueError (header, encoding, CSV syntax) or TooLarge before anything is stored."""
    path = Path(path)
    stats = {"rows": 0, "bad": 0, "domains": 0, "imported": 0, "existing": 0, "out_of_scope": 0, "records": 0,
             "errors": []}
    fd, stage_path = tempfile.mkstemp(prefix=PREFIX, suffix=".stage.db", dir=work_dir or path.parent)
    os.close(fd)
    stage = sqlite3.connect(stage_path)
    try:
        _stage(path, stage, zones, stats, progress)
        started = db.now()
        domains = stage.execute("SELECT domain, MAX(NULLIF(seen_at, '')) FROM r GROUP BY domain ORDER BY domain"
                                ).fetchall()
        stats["domains"] = len(domains)
        fields = ", ".join(db.RECORD_FIELDS)
        for n, (domain, when) in enumerate(domains, 1):
            when = when or started
            if not users.domain_allowed(conn, domain):
                stats["out_of_scope"] += 1
            elif conn.execute("SELECT 1 FROM scans s JOIN domains d ON d.id = s.domain_id "
                              "WHERE d.name = ? AND s.started = ?", (domain, when)).fetchone():
                stats["existing"] += 1
            else:
                recs = [dict(zip(db.RECORD_FIELDS, r, strict=True)) for r in stage.execute(
                    f"SELECT DISTINCT {fields} FROM r WHERE domain = ? ORDER BY host, ip", (domain,))]
                db.save_scan(conn, domain, when, SOURCE, recs)
                stats["imported"] += 1
                stats["records"] += len(recs)
            if n % 100 == 0:
                conn.commit()
                progress(stats)
        access.audit(conn, actor, "csv-import", (name or path.name)[:200], summary(stats))
        conn.commit()
        return stats
    finally:
        stage.close()
        Path(stage_path).unlink(missing_ok=True)


def summary(stats: dict) -> str:
    return (f"rows {stats['rows']}, bad {stats['bad']}, domains {stats['domains']}: imported {stats['imported']} "
            f"({stats['records']} records), already there {stats['existing']}, out of scope {stats['out_of_scope']}")


# ---------------------------------------------------------------- upload (Settings > CSV import)

def _disposition(head: str) -> tuple[str, str | None]:
    """(field name, file name or None) from a part's headers."""
    line = next((x for x in head.split("\r\n") if x.lower().startswith("content-disposition:")), "")
    name = re.search(r'\bname="([^"]*)"', line)
    fname = re.search(r'\bfilename="([^"]*)"', line)
    return (name[1] if name else ""), (fname[1] if fname else None)


async def receive(request, dest_dir: Path, cap: int | None = None) -> tuple[dict[str, str], Path | None, str]:
    """Stream a multipart/form-data body: small fields to memory (4 kB each), the one file part to a fresh temp file
    in dest_dir, never more than cap bytes. Returns (fields, file path or None, file name). TooLarge or ValueError;
    the temp file is removed on any failure."""
    cap = MAX_BYTES if cap is None else cap
    m = re.match(r'multipart/form-data;\s*boundary="?([^";]{1,70})"?\s*$', request.headers.get("content-type", ""),
                 re.I)
    if not m:
        raise ValueError("send the file from the form (multipart/form-data)")
    if int(request.headers.get("content-length") or 0) > cap + 65536:
        raise TooLarge()
    sep = b"\r\n--" + m[1].encode("latin-1")
    buf, state, fields, parts = b"\r\n", "start", {}, 0
    out, path, fname, size, name, value, is_file = None, None, "", 0, "", bytearray(), False
    try:
        async for chunk in request.stream():
            buf += chunk
            while state != "end":
                if state == "start":
                    i = buf.find(sep)
                    if i < 0:
                        buf = buf[-len(sep):]
                        break
                    buf, state = buf[i + len(sep):], "after"
                elif state == "after":
                    if len(buf) < 2:
                        break
                    if buf[:2] == b"--":
                        state = "end"
                        break
                    if buf[:2] != b"\r\n":
                        raise ValueError("malformed form data")
                    buf, state = buf[2:], "headers"
                elif state == "headers":
                    i = buf.find(b"\r\n\r\n")
                    if i < 0:
                        if len(buf) > 16384:
                            raise ValueError("malformed form data")
                        break
                    parts += 1
                    if parts > 5:
                        raise ValueError("too many form fields")
                    name, got = _disposition(buf[:i].decode("latin-1"))
                    buf, state, value = buf[i + 4:], "body", bytearray()
                    is_file = got is not None
                    if is_file:
                        if name != "file" or out:
                            raise ValueError("send one file, in the form's file field")
                        fd, p = tempfile.mkstemp(prefix=PREFIX, suffix=".csv", dir=dest_dir)
                        out, path, fname = os.fdopen(fd, "wb"), Path(p), got
                else:   # body: everything up to the next separator; keep a tail that may hold its start
                    i = buf.find(sep)
                    cut = i if i >= 0 else max(0, len(buf) - len(sep) + 1)
                    data, buf = buf[:cut], (buf[i + len(sep):] if i >= 0 else buf[cut:])
                    if is_file:
                        size += len(data)
                        if size > cap:
                            raise TooLarge()
                        out.write(data)
                    else:
                        value += data
                        if len(value) > 4096:
                            raise ValueError("form field too long")
                    if i < 0:
                        break
                    if not is_file:
                        fields[name] = value.decode("utf-8", "replace")
                    state = "after"
        if state != "end":
            raise ValueError("the upload was cut short")
    except BaseException:
        if out:
            out.close()
        if path:
            path.unlink(missing_ok=True)
        raise
    if out:
        out.close()
    fname = _CONTROL.sub("", fname.replace("\\", "/").rsplit("/", 1)[-1])[:200]
    return fields, path, fname


# ---------------------------------------------------------------- queue (one import at a time, run by the worker)

def status(conn: sqlite3.Connection) -> dict:
    try:
        got = json.loads(admin.kv_get(conn, STATUS_KEY) or "{}")
    except ValueError:
        got = {}
    return got if isinstance(got, dict) else {}


def _set_status(conn: sqlite3.Connection, st: dict) -> None:
    admin.kv_set(conn, STATUS_KEY, json.dumps(st))
    conn.commit()


def busy(conn: sqlite3.Connection) -> bool:
    return status(conn).get("state") in ("queued", "running")


def queue(conn: sqlite3.Connection, path: Path, name: str, user: str) -> None:
    job = {"path": str(path), "file": name, "user": user, "at": db.now()}
    admin.kv_set(conn, PENDING_KEY, json.dumps(job))
    _set_status(conn, {**job, "state": "queued"})


def _ours(path: Path, data_dir: Path) -> bool:
    """Only a temp file this module made in the data directory is read and removed."""
    return path.parent.resolve() == Path(data_dir).resolve() and path.name.startswith(PREFIX)


def recover(conn: sqlite3.Connection) -> None:
    """At worker start: an import left 'running' by a restart is marked failed (its file is gone or stale)."""
    st = status(conn)
    if st.get("state") == "running":
        _set_status(conn, {**st, "state": "failed", "error": "worker restarted; upload the file again"})


def run_pending(settings) -> dict | None:
    """Run the queued upload, if any (from the worker); the status in kv shows progress and the result."""
    data_dir = settings.db_path.parent
    with db.connect(settings.db_path) as conn:
        raw = admin.kv_get(conn, PENDING_KEY)
        if not raw:
            return None
        conn.execute("DELETE FROM kv WHERE key = ?", (PENDING_KEY,))
        conn.commit()
        try:
            job = json.loads(raw)
            path = Path(job["path"])
        except (ValueError, KeyError, TypeError):
            _set_status(conn, {"state": "failed", "error": "unreadable queue entry", "at": db.now()})
            return None
        st = {**job, "state": "running", "started": db.now()}
        _set_status(conn, st)
        try:
            if not _ours(path, data_dir):
                raise ValueError("the queued file is not an upload")
            zones = admin.effective(settings, conn).internal_zones
            stats = import_file(conn, path, zones, actor=job.get("user", ""), name=job.get("file", ""),
                                progress=lambda s: _set_status(conn, {**st, **s}), work_dir=data_dir)
            st = {**st, **stats, "state": "done", "finished": db.now()}
        except (ValueError, TooLarge, OSError, sqlite3.Error) as e:
            conn.rollback()
            st = {**st, "state": "failed", "finished": db.now(), "error": str(e)[:300] or type(e).__name__}
            access.audit(conn, job.get("user", ""), "csv-import", str(job.get("file", ""))[:200],
                         f"failed: {st['error']}")
        finally:
            if _ours(path, data_dir):
                path.unlink(missing_ok=True)
        _set_status(conn, st)
        return st
