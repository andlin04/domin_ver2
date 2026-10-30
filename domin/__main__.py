"""CLI: python -m domin {worker|import <reports dir>|scan <domain>|init}."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import db, importer, jobs
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
