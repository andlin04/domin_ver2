"""User accounts, roles and second-factor state for the signed-in area.

Roles: power (a power user: only the domains of its grants, as viewer or maintainer per domain; domin.access) and
admin (every domain, users, grants and settings; several allowed, never fewer than one enabled). Passwords use the
same scrypt format as the old single admin password (admin.hash_password), so a migrated password keeps working
and is re-hashed at the next sign-in. Second factor: a TOTP secret plus one-time recovery codes (domin.totp); only
hashes of the recovery codes are stored, and the last accepted TOTP step is kept so a code works only once.
A password an admin sets (create or reset) is marked: the user may keep it for GRACE_SIGNINS sign-ins, then must
renew it (count_signin); a password the user sets clears the mark."""
from __future__ import annotations

import ipaddress
import json
import sqlite3

from . import admin, db, tags, totp

ROLES = ("power", "admin")
ROLE_LABELS = {"power": "power user", "admin": "admin"}
OLD_ROLES = {"viewer": "viewer", "analyst": "admin"}   # role before delegation -> grant level on every domain
MIN_PASSWORD = 12         # characters: the one password policy (web forms and CLI)
GRACE_SIGNINS = 3         # sign-ins an admin-set password may be kept before it must be renewed


def password_problem(password: str, confirm: str | None = None) -> str:
    """Why a new password is refused ('' = fine); confirm, when given, must match."""
    if confirm is not None and password != confirm:
        return "The two passwords differ."
    if len(password) < MIN_PASSWORD:
        return f"Use at least {MIN_PASSWORD} characters."
    return ""


def _row(r: sqlite3.Row | None) -> dict | None:
    if not r:
        return None
    d = dict(r)
    d["recovery"] = json.loads(d.get("recovery") or "[]")
    d["has_totp"] = bool(d["totp_secret"])
    d["disabled"] = bool(d["disabled"])
    d["totp_required"] = bool(d["totp_required"])
    d["pw_set_by_admin"] = bool(d["pw_set_by_admin"])
    d["must_renew"] = d["pw_set_by_admin"] and d["pw_grace_left"] < 0
    return d


def get(conn: sqlite3.Connection, user_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def by_name(conn: sqlite3.Connection, name: str) -> dict | None:
    return _row(conn.execute("SELECT * FROM users WHERE name = ? COLLATE NOCASE", (name.strip(),)).fetchone())


def listing(conn: sqlite3.Connection) -> list[dict]:
    return [_row(r) for r in conn.execute("SELECT * FROM users ORDER BY name COLLATE NOCASE")]


def count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create(conn: sqlite3.Connection, name: str, role: str, password: str = "", by_admin: bool = False) -> int:
    """A new user; by_admin marks its password as set by an admin (set_password). The old role names still work as
    shorthands, as the migration maps them: viewer = power user with a viewer grant on every domain, analyst = power
    user with a maintainer grant on every domain."""
    name = name.strip()
    if not name or len(name) > 64 or role not in (*ROLES, *OLD_ROLES):
        raise ValueError("name (1..64 chars) and a valid role are required")
    if by_name(conn, name):
        raise ValueError(f"a user named {name} already exists")
    pw = admin.hash_password(password) if password else ""
    from .access import DEFAULT_RIGHTS  # local import: access -> db
    marked = bool(password and by_admin)
    uid = conn.execute("INSERT INTO users (name, password_hash, role, created, rights, pw_set_by_admin, pw_grace_left)"
                       " VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (name, pw, "power" if role in OLD_ROLES else role, db.now(),
                        json.dumps(DEFAULT_RIGHTS, sort_keys=True), int(marked),
                        GRACE_SIGNINS if marked else 0)).lastrowid
    if role in OLD_ROLES:
        conn.execute("INSERT INTO grants (user_id, domain, level, added, added_by) VALUES (?, '*', ?, ?, '')",
                     (uid, OLD_ROLES[role], db.now()))
    return uid


def set_password(conn: sqlite3.Connection, user_id: int, password: str, by_admin: bool = False) -> None:
    """A new password; signs that user's browsers out. by_admin: an admin set it, so the user may keep it for
    GRACE_SIGNINS sign-ins and must then renew it; else the user set it, which clears that mark."""
    conn.execute("UPDATE users SET password_hash = ?, pw_set_by_admin = ?, pw_grace_left = ? WHERE id = ?",
                 (admin.hash_password(password), int(by_admin), GRACE_SIGNINS if by_admin else 0, user_id))
    admin.end_user_sessions(conn, user_id)


def count_signin(conn: sqlite3.Connection, user: dict) -> str:
    """At a successful sign-in (after the second factor): what an admin-set password asks for. '' = nothing;
    'offer' = one grace sign-in counted, the user may change or keep it; 'renew' = none left: pw_grace_left -1 locks
    every session of the user to the renewal page until the user sets a password."""
    if not user["pw_set_by_admin"]:
        return ""
    left = user["pw_grace_left"]
    if left > 0:
        conn.execute("UPDATE users SET pw_grace_left = ? WHERE id = ?", (left - 1, user["id"]))
        user["pw_grace_left"] = left - 1
        return "offer"
    conn.execute("UPDATE users SET pw_grace_left = -1 WHERE id = ?", (user["id"],))
    user["pw_grace_left"], user["must_renew"] = -1, True
    return "renew"


def pw_state(user: dict) -> str:
    """The Users list's note on an admin-set password ('' = the user's own)."""
    if not user["pw_set_by_admin"]:
        return ""
    if user["must_renew"]:
        return "must renew"
    n = user["pw_grace_left"]
    return f"preset password, {n} grace sign-in{'' if n == 1 else 's'} left"


def set_role(conn: sqlite3.Connection, user_id: int, role: str) -> None:
    if role not in ROLES:
        raise ValueError("unknown role")
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    admin.end_user_sessions(conn, user_id)


def set_disabled(conn: sqlite3.Connection, user_id: int, disabled: bool) -> None:
    conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
    if disabled:
        admin.end_user_sessions(conn, user_id)


def delete(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("DELETE FROM grants WHERE user_id = ?", (user_id,))
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    admin.end_user_sessions(conn, user_id)


def record_login(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (db.now(), user_id))


def admin_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0").fetchone()[0]


def is_last_admin(conn: sqlite3.Connection, user_id: int) -> bool:
    """True if this enabled admin is the only one left, so the UI keeps at least one way back in."""
    u = get(conn, user_id)
    return bool(u and u["role"] == "admin" and not u["disabled"] and admin_count(conn) <= 1)


def verify_password(conn: sqlite3.Connection, name: str, password: str) -> dict | None:
    """The user if the password is right and the account is enabled; re-hashes an old-format hash in passing."""
    u = by_name(conn, name)
    if not u or u["disabled"] or not u["password_hash"]:
        return None
    ok, rehash = admin.password_matches(u["password_hash"], password)
    if not ok:
        return None
    if rehash:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (admin.hash_password(password), u["id"]))
    return u


# --- second factor -----------------------------------------------------------------------------------------------

def start_enrol(conn: sqlite3.Connection, user_id: int) -> tuple[str, list[str]]:
    """A fresh secret and recovery codes to show the user; stored only once they confirm (confirm_enrol)."""
    secret = totp.new_secret()
    codes = totp.new_recovery_codes()
    admin.kv_set(conn, f"enrol:{user_id}", json.dumps({"secret": secret, "recovery": codes}))
    return secret, codes


def enrol_pending(conn: sqlite3.Connection, user_id: int) -> dict | None:
    raw = admin.kv_get(conn, f"enrol:{user_id}")
    return json.loads(raw) if raw else None


def confirm_enrol(conn: sqlite3.Connection, user_id: int, code: str) -> list[str] | None:
    """Turn 2FA on once the user proves one code from the app; returns the recovery codes, or None if the code is
    wrong. The codes were already shown at enrolment; this just stores their hashes."""
    pending = enrol_pending(conn, user_id)
    if not pending or totp.verify(pending["secret"], code) is None:
        return None
    hashes = [totp.hash_recovery(c) for c in pending["recovery"]]
    conn.execute("UPDATE users SET totp_secret = ?, recovery = ?, totp_last_step = -1 WHERE id = ?",
                 (pending["secret"], json.dumps(hashes), user_id))
    conn.execute("DELETE FROM kv WHERE key = ?", (f"enrol:{user_id}",))
    return pending["recovery"]


def disable_totp(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET totp_secret = '', recovery = '[]', totp_last_step = -1 WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM kv WHERE key = ?", (f"enrol:{user_id}",))


def verify_second_factor(conn: sqlite3.Connection, user_id: int, code: str) -> bool:
    """Accept a TOTP code (once per step) or an unused recovery code (consumed)."""
    u = get(conn, user_id)
    if not u or not u["has_totp"] or not code:
        return False
    step = totp.verify(u["totp_secret"], code, last_step=u["totp_last_step"])
    if step is not None:
        conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user_id))
        return True
    h = totp.hash_recovery(code)
    if h in u["recovery"]:
        left = [x for x in u["recovery"] if x != h]
        conn.execute("UPDATE users SET recovery = ? WHERE id = ?", (json.dumps(left), user_id))
        return True
    return False


def totp_required(conn: sqlite3.Connection, user: dict) -> bool:
    """True when this user must have a second factor: its role is ticked in Settings, or its own tick (Users, edit
    page)."""
    return bool(user["totp_required"]) or required_for(conn, user["role"])


def set_totp_required(conn: sqlite3.Connection, user_id: int, required: bool) -> None:
    conn.execute("UPDATE users SET totp_required = ? WHERE id = ?", (int(required), user_id))


def needs_totp_setup(conn: sqlite3.Connection, user: dict) -> bool:
    """True when policy (role or user) requires a second factor the user has not set up yet."""
    return totp_required(conn, user) and not user["has_totp"]


# --- where sign-in is required (Settings, Sign-in) ---------------------------------------------------------------
# inventory: the public pages (inventory, all records, domain pages, search, CSV, drill data, whois and e-mail
# tools); unticked they are open to every visitor that reaches the site. posture: the Posture pages always need a
# user; the setting decides whether the lab stand-in (sign-in turned off, DOMIN_ALLOW_NO_LOGIN) counts there. The
# admin area always needs a session or that stand-in.

SIGNIN_KEY = "auth:signin"
SIGNIN_AREAS = ("inventory", "posture")


def signin_required(conn: sqlite3.Connection) -> dict[str, bool]:
    raw = admin.kv_get(conn, SIGNIN_KEY)
    saved = json.loads(raw) if raw else {}
    return {"inventory": bool(saved.get("inventory", False)), "posture": bool(saved.get("posture", True))}


def set_signin_required(conn: sqlite3.Connection, inventory: bool, posture: bool) -> None:
    admin.kv_set(conn, SIGNIN_KEY, json.dumps({"inventory": bool(inventory), "posture": bool(posture)}))


def migrate_signin(conn: sqlite3.Connection) -> bool:
    """Once: the setting from the old switch, so nothing changes. Inventory was open; posture followed the sign-in-off
    switch (off = the stand-in counted there). Returns True when it wrote the setting."""
    if admin.kv_get(conn, SIGNIN_KEY) is not None:
        return False
    set_signin_required(conn, False, admin.no_login_session(conn) is None)
    return True


# --- migration from the single admin password --------------------------------------------------------------------

def migrate_legacy_admin(conn: sqlite3.Connection) -> None:
    """First run of the user model: turn the old kv 'admin_password' into an 'admin' user so the current login keeps
    working, then remove the kv entry. Runs only when there are no users yet."""
    if count(conn) > 0:
        return
    stored = admin.kv_get(conn, "admin_password")
    if not stored:
        return
    conn.execute("INSERT INTO users (name, password_hash, role, created) VALUES ('admin', ?, 'admin', ?)",
                 (stored, db.now()))
    conn.execute("DELETE FROM kv WHERE key = 'admin_password'")


def migrate_roles(conn: sqlite3.Connection) -> int:
    """Delegation (docs/delegation.md): a viewer becomes a power user with a viewer grant on every domain, an analyst
    one with a maintainer grant on every domain; the require-2FA setting of either old role carries over to power.
    Touches only rows still on an old role, so it runs once. Returns how many users changed."""
    old = conn.execute(f"SELECT id, name, role FROM users WHERE role IN ({','.join('?' * len(OLD_ROLES))})",
                       tuple(OLD_ROLES)).fetchall()
    for r in old:
        conn.execute("INSERT OR IGNORE INTO grants (user_id, domain, level, added, added_by) VALUES (?, '*', ?, ?, "
                     "'migration')", (r["id"], OLD_ROLES[r["role"]], db.now()))
        conn.execute("UPDATE users SET role = 'power' WHERE id = ?", (r["id"],))
        conn.execute("INSERT INTO audit (at, actor, action, target, detail) VALUES (?, 'migration', 'role', ?, ?)",
                     (db.now(), r["name"], f"{r['role']} -> power + * {OLD_ROLES[r['role']]}"))
    raw = admin.kv_get(conn, "scope")
    if raw:
        saved = json.loads(raw)
        req = saved.get("require_2fa") or {}
        if "power" not in req and any(k in req for k in OLD_ROLES):
            req = {"power": any(bool(req.get(k)) for k in OLD_ROLES), "admin": bool(req.get("admin"))}
            save_scope(conn, {**saved, "require_2fa": req})
    return len(old)


# --- scope and policy settings -----------------------------------------------------------------------------------
# Two independent guardrails, one per engine:
#  * Domain inventory scope (domains_allow / domains_deny) gates the original crt.sh/DNS/RDAP scanner. It is NEVER
#    limited by IP or geolocation.
#  * Security posture scope (ip_allow / ip_deny, countries_allow / countries_deny) belongs to the future posture /
#    vulnerability engine only (the Security tab is a placeholder this phase). It never affects the original scanner.
# require_2fa is a login policy, not a scan guardrail; it lives here for one shared settings store.

SCOPE_DEFAULT = {"domains_allow": [], "domains_deny": [],                 # domain inventory engine
                 "ip_allow": [], "ip_deny": [], "countries_allow": [], "countries_deny": [],   # posture engine
                 "scan_limits_off": False,                                # domain scanner: skip the visitor limits
                 "require_2fa": {r: False for r in ROLES}}
LIST_KEYS = ("domains_allow", "domains_deny", "ip_allow", "ip_deny", "countries_allow", "countries_deny")
# Posture exclusions: hosts never scanned. A rule is {"host": text, "owner": text, "note": text}: it matches when the
# host name contains `host` and the address's network owner (ASN, netname, description) contains `owner`; an empty
# field matches anything, case-insensitive. Defaults: Microsoft 365 service names that point at Microsoft (its hosts,
# not the domain owner's).
EXCLUDE_DEFAULT = [{"host": h, "owner": "as8075", "note": "Microsoft 365 (Microsoft's AS8075)"}
                   for h in ("autodiscover.", "enterpriseenrollment.", "enterpriseregistration.", "lyncdiscover.",
                             "msoid.", "sip.")]
EXCLUDE_MAX = 200


def get_scope(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, "scope")
    out = {**{k: [] for k in LIST_KEYS}, "require_2fa": dict(SCOPE_DEFAULT["require_2fa"]), "scan_limits_off": False}
    if raw:
        saved = json.loads(raw)
        for k in out:
            if k in saved:
                if k == "require_2fa":
                    out[k] = {**out[k], **saved[k]}
                elif k == "scan_limits_off":
                    out[k] = bool(saved[k])
                else:
                    out[k] = list(saved[k])
    out["posture_exclude"] = [dict(r) for r in (saved["posture_exclude"] if raw and "posture_exclude" in saved
                                                else EXCLUDE_DEFAULT)]
    out["net_tags"] = [dict(r) for r in (saved.get("net_tags") or [])] if raw else []
    out["raw_scans"] = bool(saved.get("raw_scans")) if raw else False
    return out


def net_tags(rules: list[dict], ips: list[str]) -> list[str]:
    """The tags of the network tag rules ({net: CIDR, tag, note}) whose network holds any of these addresses, sorted."""
    out = set()
    for ip in ips:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        out |= {r["tag"] for r in rules if a.version == ipaddress.ip_network(r["net"]).version
                and a in ipaddress.ip_network(r["net"])}
    return sorted(out)


def owner_text(record) -> str:
    """What a "network owner contains" rule is matched against: "AS<number> <netname> <description>"."""
    asn = str(record["asn"] or "")
    return f"{'AS' + asn if asn.isdigit() else asn} {record['netname'] or ''} {record['descr'] or ''}"


def excluded(rules: list[dict], host: str, owner: str) -> dict | None:
    """The first exclusion rule whose host and owner texts are contained in this host name and network owner."""
    host, owner = (host or "").lower(), (owner or "").lower()
    return next((r for r in rules if r["host"] in host and r["owner"] in owner), None)


def required_for(conn: sqlite3.Connection, role: str) -> bool:
    return bool(get_scope(conn)["require_2fa"].get(role))


def save_scope(conn: sqlite3.Connection, scope: dict) -> None:
    admin.kv_set(conn, "scope", json.dumps(scope))


def _lines(text: str) -> list[str]:
    return [x.strip() for x in (text or "").replace(",", "\n").splitlines() if x.strip()]


def parse_scope(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    """Build and validate a scope from the settings form. Domains and IP ranges come from a textarea each; the
    posture countries come from tick boxes (ca:<country> / cd:<country>) over the countries present in the
    inventory, so the choice uses the same country values as the records."""
    out: dict = {"require_2fa": {r: form.get(f"require_2fa_{r}") == "on" for r in ROLES},
                 "scan_limits_off": form.get("scan_limits_off") == "on"}
    out["domains_allow"] = [d.lower().lstrip(".") for d in _lines(form.get("domains_allow", ""))]
    out["domains_deny"] = [d.lower().lstrip(".") for d in _lines(form.get("domains_deny", ""))]
    for key, label in (("ip_allow", "allowed IP range"), ("ip_deny", "denied IP range")):
        nets = []
        for item in _lines(form.get(key, "")):
            try:
                nets.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                raise ValueError(f"{label}: {item} is not a valid CIDR or address") from None
        out[key] = nets
    rules = []
    for i in range(EXCLUDE_MAX):   # rows ex_host_N / ex_owner_N / ex_note_N; a row with both texts empty is dropped
        if f"ex_host_{i}" not in form:
            continue
        host, owner, note = ((form.get(f"ex_{k}_{i}") or "").strip()[:100] for k in ("host", "owner", "note"))
        if host or owner:
            rules.append({"host": host.lower(), "owner": owner.lower(), "note": note})
    out["posture_exclude"] = rules
    tagged = []
    for i in range(EXCLUDE_MAX):   # rows nt_net_N / nt_tag_N / nt_note_N; a row with an empty address is dropped
        if f"nt_net_{i}" not in form:
            continue
        net, tag, note = ((form.get(f"nt_{k}_{i}") or "").strip()[:100] for k in ("net", "tag", "note"))
        if not net:
            continue
        try:
            net = str(ipaddress.ip_network(net, strict=False))
        except ValueError:
            raise ValueError(f"network tag: {net} is not a valid CIDR or address") from None
        if not tags.valid(tag.lower()):
            raise ValueError(f"network tag for {net}: '{tag}' must be 1-30 of a-z, 0-9 and -")
        tagged.append({"net": net, "tag": tag.lower(), "note": note})
    out["net_tags"] = tagged
    out["raw_scans"] = form.get("raw_scans") == "on"
    inv = set(inventory_countries(conn))
    out["countries_allow"] = [c for c in inv if form.get(f"ca:{c}") == "on"]
    out["countries_deny"] = [c for c in inv if form.get(f"cd:{c}") == "on"]
    return out


# --- domain inventory engine guardrail ---------------------------------------------------------------------------

def _domain_ok(name: str, allow: list[str], deny: list[str]) -> bool:
    def matches(rules: list[str]) -> bool:
        return any(name == r or name.endswith("." + r) for r in rules)
    return (not allow or matches(allow)) and not matches(deny)


def domain_allowed(conn: sqlite3.Connection, name: str) -> bool:
    """True when the original scanner may scan/analyse this domain (inventory scope only; never IP or geo)."""
    scope = get_scope(conn)
    return _domain_ok((name or "").lower(), scope["domains_allow"], scope["domains_deny"])


def inventory_in_scope(conn: sqlite3.Connection, scope: dict) -> dict:
    """How many known domains the inventory scope keeps in scope."""
    domains = [r["name"] for r in conn.execute("SELECT name FROM domains")]
    n = sum(1 for d in domains if _domain_ok(d, scope["domains_allow"], scope["domains_deny"]))
    return {"total": len(domains), "in_scope": n}


# --- security posture engine guardrail (persisted now; the engine reads it in a later phase) ---------------------

def inventory_countries(conn: sqlite3.Connection) -> list[str]:
    """Distinct country values present in the latest scans' records, for the geolocation pick-list."""
    return [r[0] for r in conn.execute(
        f"SELECT DISTINCT r.country FROM records r JOIN ({db.LATEST}) s ON s.id = r.scan_id "
        "WHERE r.country != '' ORDER BY r.country")]


def _ip_ok(ips: list[str], allow: list[str], deny: list[str]) -> bool:
    import ipaddress
    allow_n = [ipaddress.ip_network(x) for x in allow]
    deny_n = [ipaddress.ip_network(x) for x in deny]

    def inn(addr, nets):
        try:
            a = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(a in n for n in nets)
    if not ips:
        return not allow_n   # a host with no address is in scope only when no allow-list narrows it
    return any((not allow_n or inn(ip, allow_n)) and not inn(ip, deny_n) for ip in ips)


def _country_ok(country: str, allow: list[str], deny: list[str]) -> bool:
    if not country:
        return not allow   # unknown country is in scope only when no allow-list narrows it
    return (not allow or country in allow) and country not in deny


def posture_ok(scope: dict, ip: str, country: str) -> bool:
    """True when the posture engine may probe this inventoried address: IP rules and geolocation rules."""
    return (_ip_ok([ip], scope["ip_allow"], scope["ip_deny"])
            and _country_ok(country, scope["countries_allow"], scope["countries_deny"]))


def posture_ip_ok(scope: dict, ip: str) -> bool:
    """The posture IP allow/deny rules only (an address without a country: internal networks)."""
    return _ip_ok([ip], scope["ip_allow"], scope["ip_deny"])


def posture_ip_in_scope(conn: sqlite3.Connection, ip: str) -> bool:
    """True when the posture / fingerprint engine may probe this address (IP allow/deny only)."""
    scope = get_scope(conn)
    return _ip_ok([ip], scope["ip_allow"], scope["ip_deny"])


def posture_in_scope(conn: sqlite3.Connection, scope: dict) -> dict:
    """How many inventoried host names (and distinct countries) the posture IP and geolocation rules keep in scope."""
    rows = conn.execute(f"""SELECT r.host AS host, r.ip AS ip, r.country AS country FROM records r
                            JOIN ({db.LATEST}) s ON s.id = r.scan_id""").fetchall()
    hosts: dict[str, dict] = {}
    for r in rows:
        h = hosts.setdefault(r["host"], {"ips": [], "country": ""})
        if r["ip"]:
            h["ips"].append(r["ip"])
        if r["country"]:
            h["country"] = r["country"]
    in_scope = sum(1 for h in hosts.values()
                   if _ip_ok(h["ips"], scope["ip_allow"], scope["ip_deny"])
                   and _country_ok(h["country"], scope["countries_allow"], scope["countries_deny"]))
    countries = inventory_countries(conn)
    cc_in = sum(1 for c in countries if _country_ok(c, scope["countries_allow"], scope["countries_deny"]))
    return {"total": len(hosts), "in_scope": in_scope, "countries": len(countries), "countries_in_scope": cc_in}
