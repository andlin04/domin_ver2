"""CLI: python -m domin {worker|import <dir>|scan <domain>|init|geoip <csv>|import-csv <csv>|refresh-fixes|
refresh-exploits|user-add|user-list|user-passwd|user-role|user-grant|user-2fa-reset|admin-password|totp-rekey}."""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys
from pathlib import Path

from . import access, admin, components, csvimport, cve, db, exploits, importer, jobs, posture, secretbox, tools, users
from .config import Settings
from .validate import normalize_domain


def _read_password(from_stdin: bool = False) -> str | None:
    """A password from the tty (asked twice) or one line on stdin (--password-stdin, or no tty); None, with the
    reason on stderr, if it breaks the password policy (users.password_problem) or the two differ."""
    if sys.stdin.isatty() and not from_stdin:
        pw = getpass.getpass("New password: ")
        problem = users.password_problem(pw, getpass.getpass("Again: "))
    else:
        pw = sys.stdin.readline().rstrip("\r\n")
        problem = users.password_problem(pw)
    if problem:
        print(problem, file=sys.stderr)
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
    ic = sub.add_parser("import-csv", help="load a CSV (a domin export, or any file with a domain or host column) as "
                                           "imported scans, one per domain; existing scans are kept, re-imports add "
                                           "nothing")
    ic.add_argument("file", type=Path)
    ic.add_argument("--map", action="append", default=[], metavar="FIELD=COLUMN",
                    help="column for a field (header name or 1-based number; empty = don't import), over the "
                         "mapping guessed from the header names; fields: " + ", ".join(csvimport.TARGETS))
    ic.add_argument("--delimiter", choices=(",", ";", "tab"), help="instead of the detected one")
    sub.add_parser("refresh-fixes", help="update the fixed versions on stored posture findings")
    sub.add_parser("refresh-exploits", help="download the exploit data now (CISA KEV, Exploit-DB, Metasploit, "
                                            "EPSS, PoC-in-GitHub; also part of the daily CVE refresh)")
    ua = sub.add_parser("user-add", help="create a user with a password (asked twice, or one line on stdin); hand it "
                                         "over yourself: the user may keep it for a few sign-ins, then must renew it")
    ua.add_argument("name")
    ua.add_argument("--role", choices=users.ROLES, default="power")
    ua.add_argument("--password-stdin", action="store_true", help="read the password as one line from stdin")
    ua.add_argument("--own", action="store_true", help="the password is the user's own (you are that user): no "
                                                       "change offer, no renewal")
    sub.add_parser("user-list", help="list users")
    up = sub.add_parser("user-passwd", help="set a user's password as an admin (asked twice, or one line on stdin); "
                                            "the user may keep it for a few sign-ins, then must renew it")
    up.add_argument("name")
    up.add_argument("--password-stdin", action="store_true", help="read the password as one line from stdin")
    ur = sub.add_parser("user-role", help="change a user's role")
    ur.add_argument("name")
    ur.add_argument("role", choices=users.ROLES)
    ug = sub.add_parser("user-grant", help="give a power user a level on a domain (and the domains under it; "
                                           "* = every domain): viewer or maintainer, or take it away with 'none'")
    ug.add_argument("name")
    ug.add_argument("domain")
    ug.add_argument("level", choices=("viewer", "maintainer", "none", "admin"),
                    help="viewer, maintainer or none ('admin' = maintainer, the stored name)")
    u2 = sub.add_parser("user-2fa-reset", help="turn a user's two-factor off")
    u2.add_argument("name")
    sub.add_parser("admin-password", help="set the 'admin' user's password (kept for one release)")
    rk = sub.add_parser("totp-rekey", help="re-encrypt every stored two-factor secret with a new key (README: "
                                           "two-factor key); then move the new key file over DOMIN_TOTP_KEY")
    rk.add_argument("--new-key", type=Path, required=True,
                    help="file for the new key: written with a fresh key when missing or empty, else read")
    rk.add_argument("--old-key", type=Path, help="the key the values are encrypted with (default: DOMIN_TOTP_KEY)")
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
    elif args.cmd == "import-csv":
        with db.connect(settings.db_path) as conn:
            zones = admin.effective(settings, conn).internal_zones
            try:
                layout = csvimport.inspect(args.file, "\t" if args.delimiter == "tab" else args.delimiter)
                mapping = csvimport.cli_map(layout, args.map)
                if err := csvimport.check_mapping(mapping, len(layout["columns"])):
                    raise ValueError(f"not a domin CSV export, and the columns found are not enough: {err}; name "
                                     f"them with --map field=column (columns: {', '.join(layout['columns'][:20])})")
                print(f"import-csv: {csvimport.DELIMITERS[layout['delimiter']]} separated, {layout['encoding']}, "
                      f"map {csvimport.describe(mapping, layout['columns']) or '(nothing)'}")
                stats = csvimport.import_file(conn, args.file, zones, actor="cli", name=args.file.name,
                                              work_dir=settings.db_path.parent, mapping=mapping, layout=layout)
            except (ValueError, csvimport.TooLarge, OSError) as e:
                print(f"import-csv: {e}", file=sys.stderr)
                return 1
        print(csvimport.summary(stats))
        for line in stats["errors"]:
            print(f"  bad row: {line}")
    elif args.cmd == "refresh-fixes":
        cve_db = cve.Database(settings.cve_db_mode, settings.cve_db_file, settings.cve_ttl_days)
        with db.connect(settings.db_path) as conn, tools.http_client() as client:
            print(json.dumps(posture.refresh_fixes(conn, cve_db, client, settings.nvd_api_key)))
    elif args.cmd == "refresh-exploits":
        with db.connect(settings.db_path) as conn:
            if "posture" not in components.enabled(conn, settings.components):
                print("refresh-exploits: the posture component is off or not installed", file=sys.stderr)
                return 2
            if not exploits.enabled(conn):
                print("refresh-exploits: exploit data is off (Settings > CVE look-up)", file=sys.stderr)
                return 2
            with tools.http_client() as client:
                st = exploits.refresh(conn, client)
        print(json.dumps(st))
        return 1 if any(s.get("error") for s in st.values()) else 0
    elif args.cmd == "user-add":
        pw = _read_password(args.password_stdin)
        if pw is None:
            return 2
        with db.connect(settings.db_path) as conn:
            try:
                users.create(conn, args.name, args.role, pw, by_admin=not args.own)
            except ValueError as exc:
                print(exc, file=sys.stderr)
                return 2
            access.audit(conn, "cli", "user-add", args.name.strip(), f"role {args.role}")
            if not args.own:
                access.audit(conn, "cli", "set password (admin)", args.name.strip())
        print(f"user {args.name} ({args.role}) created" + ("" if args.own else "; hand the password over yourself"))
    elif args.cmd == "user-list":
        with db.connect(settings.db_path) as conn:
            for u in users.listing(conn):
                flags = ",".join(f for f, on in (("2fa", u["has_totp"]), ("disabled", u["disabled"])) if on) or "-"
                grants = " ".join(f"{g['domain']}={access.LEVEL_LABELS.get(g['level'], g['level'])}"
                                  for g in access.grants(conn, u["id"]))
                print(f"{u['name']}\t{u['role']}\t{flags}\t{u['last_login'] or 'never'}\t{grants or '-'}")
    elif args.cmd == "user-passwd":
        with db.connect(settings.db_path) as conn:
            u = users.by_name(conn, args.name)
            if not u:
                print(f"no such user: {args.name}", file=sys.stderr)
                return 2
            pw = _read_password(args.password_stdin)
            if pw is None:
                return 2
            users.set_password(conn, u["id"], pw, by_admin=True)
            access.audit(conn, "cli", "set password (admin)", u["name"])
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
            level = "admin" if args.level == "maintainer" else args.level   # stored name of maintainer
            if level == "none":
                wanted.pop(dom, None)
            else:
                wanted[dom] = level
            try:
                diff = access.set_grants(conn, u["id"], wanted, "cli")
            except ValueError as exc:
                print(exc, file=sys.stderr)
                return 2
            detail = "; ".join(f"{k} {', '.join(v)}" for k, v in diff.items() if v)
            if detail:
                access.audit(conn, "cli", "grants", u["name"], detail)
        note = " (admins see every domain anyway)" if u["role"] == "admin" else ""
        print(f"{args.name}: {dom} {access.LEVEL_LABELS.get(level, level)}{note}")
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
    elif args.cmd == "totp-rekey":
        try:
            old = secretbox.load(args.old_key)
            if not args.new_key.exists() or args.new_key.stat().st_size == 0:
                secretbox.write_key(args.new_key, secretbox.new_key())
            new = secretbox.load(args.new_key)
            with db.connect(settings.db_path) as conn:
                n = users.rekey_totp(conn, old, new)
        except (secretbox.KeyUnavailable, OSError) as e:
            print(f"totp-rekey: {e}; nothing changed", file=sys.stderr)
            return 1
        print(f"totp-rekey: {n} values re-encrypted with {args.new_key}; now move it over "
              f"{secretbox.key_path()} (root:domin 0640) and restart domin and domin-worker")
    return 0


if __name__ == "__main__":
    sys.exit(main())
