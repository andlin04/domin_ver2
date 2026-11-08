"""User accounts, roles and second-factor state for the signed-in area.

Roles, least to most: viewer (reads the signed-in reports) < analyst (also runs scans) < admin (also manages users
and settings). Passwords use the same scrypt format as the old single admin password (admin.hash_password), so a
migrated password keeps working and is re-hashed at the next sign-in. Second factor: a TOTP secret plus one-time
recovery codes (domin.totp); only hashes of the recovery codes are stored, and the last accepted TOTP step is kept
so a code works only once."""
from __future__ import annotations

import json
import secrets
import sqlite3
from datetime import datetime, timedelta

from . import admin, db, totp

ROLES = ("viewer", "analyst", "admin")
SETPW_HOURS = 24          # a set-password link is valid this long


def can(role: str, need: str) -> bool:
    """True when role is at least as privileged as need."""
    return role in ROLES and need in ROLES and ROLES.index(role) >= ROLES.index(need)


def _row(r: sqlite3.Row | None) -> dict | None:
    if not r:
        return None
    d = dict(r)
    d["recovery"] = json.loads(d.get("recovery") or "[]")
    d["has_totp"] = bool(d["totp_secret"])
    d["disabled"] = bool(d["disabled"])
    d["totp_required"] = bool(d["totp_required"])
    return d


def get(conn: sqlite3.Connection, user_id: int) -> dict | None:
    return _row(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())


def by_name(conn: sqlite3.Connection, name: str) -> dict | None:
    return _row(conn.execute("SELECT * FROM users WHERE name = ? COLLATE NOCASE", (name.strip(),)).fetchone())


def listing(conn: sqlite3.Connection) -> list[dict]:
    return [_row(r) for r in conn.execute("SELECT * FROM users ORDER BY name COLLATE NOCASE")]


def count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create(conn: sqlite3.Connection, name: str, role: str, password: str = "") -> int:
    name = name.strip()
    if not name or len(name) > 64 or role not in ROLES:
        raise ValueError("name (1..64 chars) and a valid role are required")
    if by_name(conn, name):
        raise ValueError(f"a user named {name} already exists")
    pw = admin.hash_password(password) if password else ""
    return conn.execute("INSERT INTO users (name, password_hash, role, created) VALUES (?, ?, ?, ?)",
                        (name, pw, role, db.now())).lastrowid


def set_password(conn: sqlite3.Connection, user_id: int, password: str) -> None:
    conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (admin.hash_password(password), user_id))
    admin.end_user_sessions(conn, user_id)   # a new password signs that user's browsers out


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


def needs_totp_setup(conn: sqlite3.Connection, user: dict) -> bool:
    """True when policy requires a second factor the user has not set up yet."""
    return required_for(conn, user["role"]) and not user["has_totp"]


# --- one-time set-password tokens (for invites and admin resets) --------------------------------------------------

def new_setpw_token(conn: sqlite3.Connection, user_id: int) -> str:
    token = secrets.token_urlsafe(24)
    expires = (datetime.now() + timedelta(hours=SETPW_HOURS)).isoformat(timespec="seconds")
    admin.kv_set(conn, f"setpw:{admin._token_hash(token)}", json.dumps({"user_id": user_id, "expires": expires}))
    return token


def setpw_user(conn: sqlite3.Connection, token: str) -> dict | None:
    raw = admin.kv_get(conn, f"setpw:{admin._token_hash(token)}") if token else None
    if not raw:
        return None
    data = json.loads(raw)
    if data["expires"] < db.now():
        return None
    return get(conn, data["user_id"])


def use_setpw_token(conn: sqlite3.Connection, token: str, password: str) -> dict | None:
    u = setpw_user(conn, token)
    if not u:
        return None
    set_password(conn, u["id"], password)
    conn.execute("DELETE FROM kv WHERE key = ?", (f"setpw:{admin._token_hash(token)}",))
    return u


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
    return out


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
    import ipaddress
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
