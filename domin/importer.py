"""Import the old domin's scan history: reports/<domain>_<YYMMDD>_results.csv, one file per domain and day."""
from __future__ import annotations

import csv
import re
import sqlite3
from pathlib import Path

from . import db
from .validate import normalize_domain

FILE = re.compile(r"^(?P<domain>.+)_(?P<date>\d{6})_results\.csv$")
FAILED = "Lookup failed or turned up empty"


def parse_file(path: Path) -> list[dict]:
    rows = []
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            host = (r.get("Subdomain") or "").strip().lower().rstrip(".")
            if not host:
                continue
            ip = (r.get("IP") or "").strip()
            if ip == FAILED:
                ip = ""
            rows.append({"host": host, "ip": ip, "asn": (r.get("ASN") or "").strip(),
                         "prefix": (r.get("Inetnum") or "").strip(), "netname": (r.get("Netname") or "").strip(),
                         "descr": (r.get("Descr") or "").strip(), "country": (r.get("Country") or "").strip()})
    return rows


def import_dir(conn: sqlite3.Connection, reports: Path, log=print) -> dict:
    """Idempotent: a (domain, date) already imported is skipped. Files with no resolved address are skipped too:
    the old cron wrote those whenever its discovery tool failed, and they would show as the domain going dark."""
    done = {(r["name"], r["started"][:10]) for r in conn.execute(
        "SELECT d.name, s.started FROM scans s JOIN domains d ON d.id = s.domain_id WHERE s.source = 'import'")}
    stats = {"files": 0, "imported": 0, "skipped_existing": 0, "skipped_empty": 0, "skipped_name": 0, "rows": 0}
    for path in sorted(reports.glob("*_results.csv")):
        m = FILE.match(path.name)
        if not m:
            continue
        stats["files"] += 1
        name = normalize_domain(m["domain"])
        if not name:
            stats["skipped_name"] += 1
            continue
        d = m["date"]
        day = f"20{d[:2]}-{d[2:4]}-{d[4:]}"
        if (name, day) in done:
            stats["skipped_existing"] += 1
            continue
        rows = parse_file(path)
        if not any(r["ip"] for r in rows):
            stats["skipped_empty"] += 1
            continue
        db.save_scan(conn, name, f"{day}T00:00:00", "import", rows)
        done.add((name, day))
        stats["imported"] += 1
        stats["rows"] += len(rows)
        if stats["imported"] % 250 == 0:
            conn.commit()
            log(f"  {stats['imported']} scans imported")
    return stats
