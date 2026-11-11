"""CLI: python -m domin {worker|import <dir>|scan <domain>|init|geoip <csv>|import-public <db>|refresh-fixes|
user-add|user-list|user-passwd|user-role|user-grant|user-2fa-reset|admin-password}."""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from . import access, admin, cve, db, importer, jobs, posture, publicsync, tools, users
from .config import Settings
from .validate import normalize_domain


def _read_password(confirm: bool = True) -> str | None:
    """A password from the tty (asked twice) or one line on stdin; None if it is too short or the two differ."""
    if sys.stdin.isatty():
        pw = getpass.getpass("New password: ")
        if confirm and pw != getpass.getpass("Again: "):
            print("the passwords differ", file=sys.stderr)
            return None
    else:
        pw = sys.stdin.readline().rstrip("\r\n")
    if len(pw) < 12:
        print("use at least 12 characters", file=sys.stderr)
        return None
    return pw


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="domin")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the database")
    sub.add_parser("worker", help="run queued scans (and scheduled refreshes when DOMIN_REFRESH_DAYS > 0)")
    imp = sub.add_parser("import", help="import the old domin's reports/*_results.csv")
    imp.add_argument("reports", type=Path)
    sc = sub.add_parser("scan", help="queue a scan")
    sc.add_argument("domain")
    geo = sub.add_parser("geoip", help="load a DB-IP 'IP to Country Lite' CSV (.csv or .csv.gz) for visitor countries")
    geo.add_argument("file", type=Path)
    pub = sub.add_parser("import-public", help="replace the inventory with a copy of the public database "
                                               "(own scans are kept; Settings > Sync runs this)")
    pub.add_argument("file", type=Path)
    sub.add_parser("refresh-fixes", help="update the fixed versions on stored posture findings")
    ua =sub.add_parser("user-add", help="create a user and print a one-time set-password link")
    ua.add_argument("name")
    ua.add_argument("--role", choices=users.ROLES, default="power")
    sub.add_parser("user-list", help="list users")
    up = sub.add_parser("user-passwd", help="set a user's password (asked twice, or one line on stdin)")
    up.add_argument("name")
    ur = sub.add_parser("user-role", help="change a user's role")
    ur.add_argument("name")
    ur.add_argument("role", choices=users.ROLES)
    ug = sub.add_parser("user-grant", help="give a power user a level on a domain (and the domains under it; "
                                           "* = every domain), or take it away with 'none'")
    ug.add_argument("name")
    ug.add_argument("domain")
    ug.add_argument("level", choices=(*access.LEVELS, "none"))
    u2 = sub.add_parser("user-2fa-reset", help="turn a user's two-factor off")
    u2.add_argument("name")
    sub.add_parser("admin-password", help="set the 'admin' user's password (kept for one release)")
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
        with db.connect(settings.db_path) as conn:
            settings = admin.effective(settings, conn)   # Settings page: internal zones and their DNS
        name = normalize_domain(args.domain, settings.internal_zones)
        if not name:
            print(f"not a domain: {args.domain}", file=sys.stderr)
            return 2
        with db.connect(settings.db_path) as conn:
            if not users.domain_allowed(conn, name):
                print(f"{name} is outside the configured inventory scope", file=sys.stderr)
                return 2
            print(jobs.enqueue(conn, name, client="cli"))
    elif args.cmd == "geoip":
        with db.connect(settings.db_path) as conn:
            print(f"{admin.import_geo(conn, args.file)} address ranges loaded")
    elif args.cmd == "import-public":
        with db.connect(settings.db_path) as conn:
            print(json.dumps(publicsync.import_public(conn, args.file)))
    elif args.cmd == "refresh-fixes":
        cve_db = cve.Database(settings.cve_db_mode, settings.cve_db_file, settings.cve_ttl_days)
        with db.connect(settings.db_path) as conn, tools.http_client() as client:
            print(json.dumps(posture.refresh_fixes(conn, cve_db, client, settings.nvd_api_key)))
    elif args.cmd == "user-add":
        with db.connect(settings.db_path) as conn:
            try:
                uid = users.create(conn, args.name, args.role)
            except ValueError as exc:
                print(exc, file=sys.stderr)
                return 2
            token = users.new_setpw_token(conn, uid)
        print(f"user {args.name} ({args.role}) created")
        print(f"set a password within 24 h at: /admin/set-password?token={token}")
    elif args.cmd == "user-list":
        with db.connect(settings.db_path) as conn:
            for u in users.listing(conn):
                flags = ",".join(f for f, on in (("2fa", u["has_totp"]), ("disabled", u["disabled"])) if on) or "-"
                grants = " ".join(f"{g['domain']}={g['level']}" for g in access.grants(conn, u["id"]))
                print(f"{u['name']}\t{u['role']}\t{flags}\t{u['last_login'] or 'never'}\t{grants or '-'}")
    elif args.cmd == "user-passwd":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, args.name)
            if not u:
                print(f"no such user: {args.name}", file=sys.stderr)
                return 2
            pw = _read_password()
            if pw is None:
                return 2
            users.set_password(conn, u["id"], pw)
        print(f"password set for {args.name}; open sessions were signed out")
    elif args.cmd == "user-role":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, args.name)
            if not u:
                print(f"no such user: {args.name}", file=sys.stderr)
                return 2
            if u["role"] == "admin" and args.role != "admin" and users.is_last_admin(conn, u["id"]):
                print("this is the last admin; make another user an admin first", file=sys.stderr)
                return 2
            users.set_role(conn, u["id"], args.role)
            access.audit(conn, "cli", "role", u["name"], f"{u['role']} -> {args.role}")
        print(f"{args.name} is now {args.role}")
    elif args.cmd == "user-grant":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, args.name)
            if not u:
                print(f"no such user: {args.name}", file=sys.stderr)
                return 2
            wanted = {g["domain"]: g["level"] for g in access.grants(conn, u["id"])}
            dom = args.domain.strip().lower().rstrip(".")
            if args.level == "none":
                wanted.pop(dom, None)
            else:
                wanted[dom] = args.level
            try:
                diff = access.set_grants(conn, u["id"], wanted, "cli")
            except ValueError as exc:
                print(exc, file=sys.stderr)
                return 2
            detail = "; ".join(f"{k} {', '.join(v)}" for k, v in diff.items() if v)
            if detail:
                access.audit(conn, "cli", "grants", u["name"], detail)
        note = " (admins see every domain anyway)" if u["role"] == "admin" else ""
        print(f"{args.name}: {dom} {args.level}{note}")
    elif args.cmd == "user-2fa-reset":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, args.name)
            if not u:
                print(f"no such user: {args.name}", file=sys.stderr)
                return 2
            users.disable_totp(conn, u["id"])
        print(f"two-factor turned off for {args.name}")
    elif args.cmd == "admin-password":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, "admin")
            if not u:
                print("no 'admin' user; create the first admin with: domin user-add <name> --role admin",
                      file=sys.stderr)
                return 2
            pw = _read_password()
            if pw is None:
                return 2
            users.set_password(conn, u["id"], pw)
        print("admin password set; open sessions were signed out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
