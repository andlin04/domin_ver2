"""CSV import: any CSV with the inventory's data (domin's own CSV download, /search.csv, or another tool's) loaded as
imported scans.

The file's layout is detected first (inspect: delimiter, encoding, header, sample rows); a mapping then says which
column feeds which domin field (TARGETS; auto_map guesses it from the header names, domin's own export maps itself).
Only mapped fields are stored; a row needs a domain or a host (the domain is then derived from the host) and the file
at least one data field (DATA). One imported scan per domain: its records are the file's rows for that domain, its
time the newest last_seen of those rows (first_seen when last_seen is not mapped; the import time when the file has
none). A domain that already has a scan at that time is skipped, so importing the same file again adds nothing;
existing scans are never changed or deleted. Domains outside the inventory scope (Settings > Scope) are skipped and
counted. Settings > CSV import streams the upload to a file in the data directory, holds it for the mapping dialog
(hold: a random token bound to the user and session, UPLOAD_TTL at most) and queues it; the worker runs it
(run_pending). `python -m domin import-csv <file> [--map field=column]` runs import_file directly."""
from __future__ import annotations

import codecs
import csv
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
from datetime import datetime
from pathlib import Path

from . import access, admin, db, users
from .validate import normalize_domain

MAX_BYTES = 200 * 1024 * 1024   # upload and file size cap
TARGETS = ("domain", *db.RECORD_FIELDS, "last_seen", "first_seen", "eu")
DATA = ("ip", *db.RECORD_FIELDS[2:])   # at least one of these must be mapped
LABELS = {"domain": "Domain", "host": "Host name", "ip": "IP address", "asn": "ASN", "prefix": "Prefix",
          "netname": "Net name", "descr": "Description", "country": "Country", "last_seen": "Last seen",
          "first_seen": "First seen", "eu": "EU"}
HINTS = {"domain": "domain or host required", "host": "domain or host required; gives the domain",
         **dict.fromkeys(DATA, "data field"), "prefix": "data field; network, CIDR or range",
         "country": "data field; country name", "last_seen": "the scan time; ISO date",
         "first_seen": "the time when last seen is not mapped", "eu": "checked only; derived from the country"}
# header names that map to a field, beyond its own name (compared lower-case, spaces, dots and dashes as _)
ALIASES = {"domain": ("domain_name", "zone", "registrable_domain", "apex"),
           "host": ("hostname", "host_name", "fqdn", "name", "subdomain", "dns_name"),
           "ip": ("ip_address", "ipaddress", "address", "addr", "ip_addr", "ipv4", "ipv6"),
           "asn": ("as_number", "asnumber", "origin_as", "as"),
           "prefix": ("cidr", "network", "net", "ip_range", "range", "bgp_prefix"),
           "netname": ("net_name", "network_name", "as_name", "org", "organization", "organisation", "owner"),
           "descr": ("description", "desc", "comment", "notes"),
           "country": ("country_name", "geo", "location"),
           "last_seen": ("lastseen", "last_seen_at", "seen_at", "last", "date", "seen", "timestamp", "datetime",
                         "time", "updated", "scanned", "scan_date", "scan_time", "when"),
           "first_seen": ("firstseen", "first", "created", "discovered"),
           "eu": ()}
DELIMITERS = {",": "comma", ";": "semicolon", "\t": "tab"}
SAMPLE_ROWS = 10
MAX_COLUMNS = 200
FORMULA = ("=", "+", "-", "@", "\t", "\r")   # what the exporter's csv_safe prefixes with '
SOURCE = "import"   # shown as "(imported)" on the domain page, like the old importer's scans
PENDING_KEY = "csv_import:pending"
STATUS_KEY = "csv_import:status"
UPLOAD_KEY = "csv_import:upload:"   # + token: an upload waiting for its mapping
UPLOAD_TTL = 3600   # seconds an unmapped upload is kept
PREFIX = "csv-import-"   # temp files in the data directory
TEXT_MAX = {"netname": 200, "descr": 1000, "country": 100}
ERRORS_KEPT = 10
SECOND_LEVEL = {"ac", "co", "com", "edu", "gov", "net", "org", "ltd", "plc", "nhs", "sch", "mil", "nom"}
_HOST_LABEL = re.compile(r"^(\*|[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$")
_LOCAL = re.compile(r"^[a-z0-9._%+-]{1,64}$")
_ASN = re.compile(r"^(\d{1,10}|NA)?$")
_WHEN = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?)?(Z|[+-]\d{2}:?\d{2})?$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RANGE_SPLIT = re.compile(r"\s*,\s*|\s+-\s+")


class TooLarge(Exception):
    """The upload or file is above MAX_BYTES."""


def unescape(value: str) -> str:
    """Undo the exporter's formula escape: a ' it put before = + - @ tab or CR."""
    return value[1:] if value[:1] == "'" and value[1:2] in FORMULA and len(value) > 1 else value


# ---------------------------------------------------------------- layout and mapping

def norm(name: str) -> str:
    """A header name as compared with TARGETS and ALIASES."""
    return re.sub(r"[\s.\-]+", "_", name.strip().lstrip("﻿").lower()).strip("_")


def _encoding(path: Path) -> str:
    """utf-8-sig (byte order mark), utf-8 when the whole file decodes as UTF-8, else latin-1 (every byte is text)."""
    dec = codecs.getincrementaldecoder("utf-8")()
    with path.open("rb") as f:
        bom = f.read(3) == codecs.BOM_UTF8
        f.seek(0)
        try:
            while chunk := f.read(1 << 20):
                dec.decode(chunk)
            dec.decode(b"", final=True)
        except UnicodeDecodeError:
            return "latin-1"
    return "utf-8-sig" if bom else "utf-8"


def _delimiter(text: str) -> str:
    """csv.Sniffer's pick among comma, semicolon and tab; else the one the first line has most of (comma on a tie)."""
    try:
        return csv.Sniffer().sniff(text, delimiters="".join(DELIMITERS)).delimiter
    except csv.Error:
        first = text.splitlines()[0] if text else ""
        return max(DELIMITERS, key=first.count)


def inspect(path: Path, delimiter: str | None = None) -> dict:
    """The file's layout: encoding, delimiter, header (first row is one), columns (first row's cells), sample (the
    next SAMPLE_ROWS rows). TooLarge, or ValueError for an empty, unreadable or too wide file."""
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise TooLarge(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    enc = _encoding(path)
    with path.open(newline="", encoding=enc) as f:
        text = f.read(65536)
        delim = delimiter or _delimiter(text[:text.rfind("\n") + 1] or text)
        f.seek(0)
        try:
            rows = []
            for row in csv.reader(f, delimiter=delim):
                if any(x.strip() for x in row):
                    rows.append(row)
                if len(rows) > SAMPLE_ROWS:
                    break
        except csv.Error as e:
            raise ValueError(f"not a readable CSV file: {e}") from None
    if not rows:
        raise ValueError("the file is empty")
    columns = [_CONTROL.sub("", x).strip()[:100] for x in rows[0]]
    if len(columns) > MAX_COLUMNS:
        raise ValueError(f"more than {MAX_COLUMNS} columns")
    names = [norm(c) for c in columns]
    known = {*TARGETS, *(a for v in ALIASES.values() for a in v)}
    header = any(n in known for n in names)
    if not header:
        try:
            header = csv.Sniffer().has_header(text)
        except csv.Error:
            header = False
    dup = sorted({n for n in names if n and names.count(n) > 1})
    if header and dup:
        raise ValueError(f"the header repeats a column: {', '.join(dup[:5])}")
    sample = [[_CONTROL.sub("", x)[:200] for x in r[:MAX_COLUMNS]] for r in rows[1:]]
    return {"encoding": enc, "delimiter": delim, "header": header, "columns": columns, "sample": sample}


def auto_map(columns: list[str]) -> dict[str, int | None]:
    """Field -> column index from the header names: own names first, then ALIASES; a column feeds one field."""
    names = [norm(c) for c in columns]
    got: dict[str, int | None] = dict.fromkeys(TARGETS)
    for pass_names in ((lambda t: (t,)), (lambda t: ALIASES[t])):
        for t in TARGETS:
            for a in pass_names(t):
                if got[t] is None and a in names and names.index(a) not in got.values():
                    got[t] = names.index(a)
    return got


def check_mapping(mapping: dict[str, int | None], width: int) -> str:
    """'' when the mapping can be imported, else what is missing."""
    used = [i for i in mapping.values() if i is not None]
    if any(not 0 <= i < width for i in used) or any(t not in TARGETS for t in mapping):
        return "the mapping names a column the file does not have"
    if len(set(used)) != len(used):
        return "a column can feed only one field"
    if mapping.get("domain") is None and mapping.get("host") is None:
        return "map a domain or a host column (the domain is then derived from the host)"
    if all(mapping.get(t) is None for t in DATA):
        return "map at least one data column: " + ", ".join(LABELS[t] for t in DATA)
    return ""


def describe(mapping: dict[str, int | None], columns: list[str]) -> str:
    """The mapping as text for the audit log: field=column, ..."""
    return ", ".join(f"{t}={columns[i] if i < len(columns) and columns[i] else f'column {i + 1}'}"
                     for t, i in mapping.items() if i is not None)


def cli_map(layout: dict, pairs: list[str]) -> dict[str, int | None]:
    """--map field=column (header name or 1-based number; empty = don't import) over the auto-mapping."""
    mapping = auto_map(layout["columns"]) if layout["header"] else dict.fromkeys(TARGETS)
    names = [norm(c) for c in layout["columns"]]
    for pair in pairs:
        field, _, col = pair.partition("=")
        field = field.strip().lower()
        if field not in TARGETS:
            raise ValueError(f"--map {pair}: unknown field (one of {', '.join(TARGETS)})")
        col = col.strip()
        if not col:
            mapping[field] = None
        elif col.isdigit() and 1 <= int(col) <= len(names):
            mapping[field] = int(col) - 1
        elif norm(col) in names:
            mapping[field] = names.index(norm(col))
        else:
            raise ValueError(f"--map {pair}: no such column")
    return mapping


# ---------------------------------------------------------------- rows

def _host_ok(v: str) -> bool:
    """A host name; certificate logs also give mailbox names (local@host.example), kept as the scanner stored them."""
    local, at, v = v.rpartition("@")
    if at and not _LOCAL.match(local):
        return False
    return 0 < len(v) <= 253 and all(_HOST_LABEL.match(x) for x in v.split("."))


def _net_ok(v: str) -> bool:
    if v == "NA":   # RDAP/whois had no network for the address
        return True
    try:
        return all(ipaddress.ip_network(p, strict=False) for p in _RANGE_SPLIT.split(v))
    except ValueError:
        return False


def _when(v: str) -> str | None:
    """ISO time without a zone (a date gets T00:00:00); None when it is not one."""
    if not _WHEN.match(v):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00")).replace(tzinfo=None).isoformat(timespec="seconds")
    except ValueError:
        return None


def domain_of(host: str, known: frozenset[str] | set[str] = frozenset(), zones: tuple[str, ...] = ()) -> str | None:
    """The domain a host name belongs to: the longest inventory domain it is under, else its registrable part (the
    last two labels; three under a country's second level such as co.uk)."""
    labels = host.rpartition("@")[2].strip(".").split(".")
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in known:
            return ".".join(labels[i:])
    zone = next((z for z in zones if host.endswith("." + z) or host == z), "")
    if zone:
        return normalize_domain(zone, zones)
    n = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else 2
    return normalize_domain(".".join(labels[-n:]), zones) if len(labels) >= 2 else None


def clean_row(row: dict, zones: tuple[str, ...] = (), known: frozenset[str] | set[str] = frozenset()
              ) -> tuple[dict | None, str]:
    """(record with domain and time, "") for a valid row, else (None, reason). A field missing from row is empty."""
    v = {k: unescape(row.get(k) or "").strip() for k in TARGETS}
    host = v["host"].lower().rstrip(".")
    if host and not _host_ok(host):
        return None, "host"
    domain = v["domain"].lower()
    if domain:
        if normalize_domain(domain, zones) != domain:
            return None, "domain"
    elif not host or not (domain := domain_of(host, known, zones) or ""):
        return None, "domain"
    host = host or domain
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
    if v["eu"] not in ("", "EU", "Non-EU"):
        return None, "eu"
    times = {}
    for k in ("first_seen", "last_seen"):
        if v[k]:
            times[k] = _when(v[k])
            if not times[k]:
                return None, k
    rec = {"domain": domain, "host": host, **{f: v[f] for f in db.RECORD_FIELDS[1:]},
           "when": times.get("last_seen") or times.get("first_seen") or ""}
    return rec, ""


def _stage(path: Path, stage: sqlite3.Connection, layout: dict, mapping: dict[str, int | None],
           zones: tuple[str, ...], known: frozenset[str], stats: dict, progress) -> None:
    """Read and check the file into the staging table r; counts go to stats."""
    if path.stat().st_size > MAX_BYTES:
        raise TooLarge(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    cols = ", ".join(("domain", *db.RECORD_FIELDS, "seen_at"))
    stage.execute(f"CREATE TABLE r ({cols})")
    batch: list[tuple] = []
    sql = f"INSERT INTO r ({cols}) VALUES ({', '.join('?' * (len(db.RECORD_FIELDS) + 2))})"
    picks = [(t, i) for t, i in mapping.items() if i is not None]
    width = None
    try:
        with path.open(newline="", encoding=layout["encoding"]) as f:
            reader = csv.reader(f, delimiter=layout["delimiter"])
            for row in reader:
                if not any(x.strip() for x in row):
                    continue
                if width is None:   # the first row: its width is every row's; a header row is not data
                    width = len(row)
                    if layout["header"]:
                        continue
                stats["rows"] += 1
                if len(row) != width:
                    rec, why = None, "columns"
                else:
                    rec, why = clean_row({t: row[i] for t, i in picks}, zones, known)
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
        raise ValueError(f"the file is not {layout['encoding']} text") from None
    except csv.Error as e:
        raise ValueError(f"not a readable CSV file: {e}") from None
    stage.executemany(sql, batch)
    stage.execute("CREATE INDEX r_domain ON r(domain)")


def import_file(conn: sqlite3.Connection, path: Path, zones: tuple[str, ...] = (), actor: str = "cli",
                name: str = "", progress=lambda stats: None, work_dir: Path | None = None,
                mapping: dict[str, int | None] | None = None, layout: dict | None = None) -> dict:
    """Check every row, then store one imported scan per domain (see the module text). layout: inspect's (detected
    when not given); mapping: field -> column index (auto_map's when not given). Returns the counts; ValueError
    (mapping, encoding, CSV syntax) or TooLarge before anything is stored."""
    path = Path(path)
    layout = layout or inspect(path)
    if mapping is None:
        mapping = auto_map(layout["columns"]) if layout["header"] else dict.fromkeys(TARGETS)
    mapping = {t: mapping.get(t) for t in TARGETS}
    if err := check_mapping(mapping, len(layout["columns"])):
        raise ValueError(f"cannot import this file: {err}")
    stats = {"rows": 0, "bad": 0, "domains": 0, "imported": 0, "existing": 0, "out_of_scope": 0, "records": 0,
             "errors": []}
    known = frozenset(r[0] for r in conn.execute("SELECT name FROM domains"))
    fd, stage_path = tempfile.mkstemp(prefix=PREFIX, suffix=".stage.db", dir=work_dir or path.parent)
    os.close(fd)
    stage = sqlite3.connect(stage_path)
    try:
        _stage(path, stage, layout, mapping, zones, known, stats, progress)
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
        access.audit(conn, actor, "csv-import", (name or path.name)[:200],
                     f"{summary(stats)}; {DELIMITERS[layout['delimiter']]}, {layout['encoding']}, "
                     f"map {describe(mapping, layout['columns'])}")
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


def queue(conn: sqlite3.Connection, path: Path, name: str, user: str, mapping: dict[str, int | None] | None = None,
          layout: dict | None = None) -> None:
    """Queue the file for the worker; without mapping and layout it detects and auto-maps them when it runs."""
    job = {"path": str(path), "file": name, "user": user, "at": db.now()}
    if mapping is not None and layout:
        job.update(mapping=mapping, layout={k: v for k, v in layout.items() if k != "sample"},
                   map=describe(mapping, layout["columns"]))
    admin.kv_set(conn, PENDING_KEY, json.dumps(job))
    _set_status(conn, {**job, "state": "queued"})


# ---------------------------------------------------------------- uploads waiting for their mapping

def hold(conn: sqlite3.Connection, path: Path, name: str, user_id: int, session: str, layout: dict) -> str:
    """Keep an upload for the mapping dialog; the token returned is good for this user and session, UPLOAD_TTL."""
    token = secrets.token_urlsafe(24)
    admin.kv_set(conn, UPLOAD_KEY + token, json.dumps({"path": str(path), "file": name, "user_id": user_id,
                                                       "session": session, "at": time.time(), "layout": layout}))
    conn.commit()
    return token


def _expired(up: dict, now: float | None = None) -> bool:
    return not isinstance(up.get("at"), int | float) or (now or time.time()) - up["at"] > UPLOAD_TTL


def held(conn: sqlite3.Connection, token: str, user_id: int, session: str, data_dir: Path) -> dict | None:
    """The upload for token when it is this user's and session's and not expired (an expired one is removed)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,64}", token or ""):
        return None
    try:
        up = json.loads(admin.kv_get(conn, UPLOAD_KEY + token) or "null")
    except ValueError:
        up = None
    if not isinstance(up, dict):
        return None
    if _expired(up):
        drop(conn, token, data_dir)
        return None
    return up if up.get("user_id") == user_id and up.get("session") == session else None


def drop(conn: sqlite3.Connection, token: str, data_dir: Path, keep_file: bool = False) -> None:
    """Forget a held upload; its file goes too unless keep_file (it was queued)."""
    try:
        up = json.loads(admin.kv_get(conn, UPLOAD_KEY + token) or "{}")
    except ValueError:
        up = {}
    conn.execute("DELETE FROM kv WHERE key = ?", (UPLOAD_KEY + token,))
    conn.commit()
    path = Path(str(up.get("path", "")))
    if not keep_file and isinstance(up, dict) and _ours(path, data_dir):
        path.unlink(missing_ok=True)


def sweep(conn: sqlite3.Connection, data_dir: Path, now: float | None = None) -> int:
    """Remove expired held uploads, and upload files older than UPLOAD_TTL that nothing holds or queued (a crash or
    restart left them). Returns how many files went."""
    now = now or time.time()
    keep, gone = set(), 0
    for key, raw in conn.execute("SELECT key, value FROM kv WHERE key LIKE ?", (UPLOAD_KEY + "%",)).fetchall():
        try:
            up = json.loads(raw)
        except ValueError:
            up = {}
        if isinstance(up, dict) and not _expired(up, now):
            keep.add(str(up.get("path")))
        else:
            drop(conn, key[len(UPLOAD_KEY):], data_dir)
    for raw in (admin.kv_get(conn, PENDING_KEY), json.dumps(status(conn))):
        try:
            keep.add(str(json.loads(raw or "{}").get("path")))
        except (ValueError, AttributeError):
            pass
    for f in Path(data_dir).glob(PREFIX + "*.csv"):
        try:
            if str(f) not in keep and now - f.stat().st_mtime > UPLOAD_TTL:
                f.unlink()
                gone += 1
        except OSError:
            pass
    return gone


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
        sweep(conn, data_dir)
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
            layout = job.get("layout")
            if layout:   # the sample is not kept in the queue; the import needs only the layout
                layout = {**layout, "sample": []}
            stats = import_file(conn, path, zones, actor=job.get("user", ""), name=job.get("file", ""),
                                progress=lambda s: _set_status(conn, {**st, **s}), work_dir=data_dir,
                                mapping=job.get("mapping"), layout=layout)
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
