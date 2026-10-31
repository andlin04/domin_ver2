"""CLI: python -m domin {worker|import <reports dir>|scan <domain>|init|admin-password|geoip <csv>}."""
from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from . import admin, db, importer, jobs
from .config import Settings
from .validate import normalize_domain


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="domin")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the database")
    sub.add_parser("worker", help="run queued scans (and scheduled refreshes when DOMIN_REFRESH_DAYS > 0)")
    imp = sub.add_parser("import", help="import the old domin's reports/*_results.csv")
    imp.add_argument("reports", type=Path)
    sc = sub.add_parser("scan", help="queue a scan")
    sc.add_argument("domain")
    sub.add_parser("admin-password", help="set the admin page password (asked twice; or one line on stdin)")
    geo = sub.add_parser("geoip", help="load a DB-IP 'IP to Country Lite' CSV (.csv or .csv.gz) for visitor countries")
    geo.add_argument("file", type=Path)
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    settings = Settings.from_env()
    db.init(settings.db_path)
    if args.cmd == "worker":
        jobs.worker(settings)
    elif args.cmd == "import":
        with db.connect(settings.db_path) as conn:
            print(importer.import_dir(conn, args.reports))
    elif args.cmd == "scan":
        name = normalize_domain(args.domain)
        if not name:
            print(f"not a domain: {args.domain}", file=sys.stderr)
            return 2
        with db.connect(settings.db_path) as conn:
            print(jobs.enqueue(conn, name, client="cli"))
    elif args.cmd == "admin-password":
        if sys.stdin.isatty():
            pw = getpass.getpass("New admin password: ")
            if pw != getpass.getpass("Again: "):
                print("the passwords differ", file=sys.stderr)
                return 2
        else:
            pw = sys.stdin.readline().rstrip("\r\n")
        if len(pw) < 12:
            print("use at least 12 characters", file=sys.stderr)
            return 2
        with db.connect(settings.db_path) as conn:
            admin.set_password(conn, pw)
        print("admin password set; open sessions were signed out")
    elif args.cmd == "geoip":
        with db.connect(settings.db_path) as conn:
            print(f"{admin.import_geo(conn, args.file)} address ranges loaded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
