"""Sign-in protection (Settings > General, Sign-in protection): soft rules checked after the password.

- One session per user: a new sign-in ends that user's other sessions.
- New place: the sign-in's country (DB-IP table; the /24, or /48 for IPv6, when the country is unknown) was not seen
  for this user in the last N days. A user with two-factor gives a code (the step-up; every TOTP sign-in asks one);
  a user without it is refused and the attempt waits for an admin (Users: approve or deny). A user's first sign-in
  sets the baseline.
- Impossible travel: the distance between the country centroids of the previous and this sign-in, divided by the
  time between them, is over TRAVEL_KMH. Same or unknown country: skipped. The sign-in is refused, every session
  of the user ends, and the user must renew the password and use two-factor.
- Exempt: DOMIN_ADMIN_IPS and the trusted ranges in Settings (a rule that would hit is recorded as "exempt").
- Break-glass: the last enabled admin only gets the two-factor step-up (without two-factor: it must enrol right after
  the sign-in), never a block. The CLI admin-password is untouched.
Every rule hit goes to the audit log with the user, address, country and rule."""
from __future__ import annotations

import ipaddress
import json
import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path

from . import access, admin, db, users

KEY = "signin_guard"
DEFAULTS = {"one_session": True, "new_place": True, "new_place_days": 90, "travel": True, "trusted": []}
DAYS_MIN, DAYS_MAX = 1, 3650
TRAVEL_KMH = 900
PENDING_KEEP_DAYS = 30
WORLD = Path(__file__).parent / "static" / "world.json"
# places too small for the 110m map data: [lon, lat] (the same list as app.js)
DOTS = {"sg": (103.8, 1.35), "hk": (114.17, 22.32), "mo": (113.55, 22.17), "mt": (14.45, 35.9),
        "bh": (50.55, 26.07), "ad": (1.52, 42.5), "li": (9.55, 47.16), "mc": (7.42, 43.74), "sm": (12.46, 43.94),
        "gg": (-2.58, 49.45), "je": (-2.13, 49.21), "im": (-4.5, 54.23), "gi": (-5.35, 36.14), "ms": (-62.19, 16.74),
        "bm": (-64.75, 32.3), "ky": (-81.25, 19.3), "mu": (57.55, -20.3), "sc": (55.45, -4.68), "mv": (73.5, 4.17),
        "bb": (-59.55, 13.17)}


# --- settings ----------------------------------------------------------------------------------------------------

def config(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, KEY)
    return {**DEFAULTS, **(json.loads(raw) if raw else {})}


def save_config(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    """Validate the Settings form (unticked boxes are absent); raises ValueError with the reason."""
    try:
        days = int(form.get("new_place_days", ""))
    except ValueError:
        raise ValueError("New place: the days must be a whole number.") from None
    if not DAYS_MIN <= days <= DAYS_MAX:
        raise ValueError(f"New place: the days must be {DAYS_MIN}..{DAYS_MAX}.")
    trusted = []
    for item in dict.fromkeys(x for x in re.split(r"[\s,]+", form.get("trusted", "")) if x):
        try:
            trusted.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            raise ValueError(f"Trusted ranges: not an address or network: {item}") from None
    cfg = {"one_session": form.get("one_session") == "on", "new_place": form.get("new_place") == "on",
           "new_place_days": days, "travel": form.get("travel") == "on", "trusted": trusted}
    admin.kv_set(conn, KEY, json.dumps(cfg))
    return cfg


def exempt(cfg: dict, ip: str, admin_nets) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in admin_nets) or any(a in ipaddress.ip_network(n) for n in cfg["trusted"])


# --- places, distances, browsers ---------------------------------------------------------------------------------

def net_of(ip: str) -> str:
    """The sign-in's network: /24 for IPv4, /48 for IPv6 ('' when not an address)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(ipaddress.ip_network(f"{a}/{24 if a.version == 4 else 48}", strict=False))


def place_of(cc: str, net: str) -> str:
    return cc.upper() if cc else f"net:{net}"


@lru_cache(maxsize=1)
def centroids() -> dict[str, tuple[float, float]]:
    """Country code -> (lat, lon): the centre of the box around each country's largest ring in world.json (the map's
    data, coordinates x10), as the map picks a country's box; overseas parts are left out."""
    out: dict[str, tuple[float, float]] = {cc: (lat, lon) for cc, (lon, lat) in DOTS.items()}
    for w in json.loads(WORLD.read_text(encoding="utf-8")):
        def area(r):
            return abs(sum(r[i] * r[i + 3] - r[i + 2] * r[i + 1] for i in range(0, len(r) - 2, 2)))
        big = max(w["r"], key=area)
        xs, ys = big[0::2], big[1::2]
        centre = ((min(ys) + max(ys)) / 20, (min(xs) + max(xs)) / 20)
        for k in w["k"]:
            if len(k) == 2:
                out.setdefault(k.lower(), centre)
    return out


def distance_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance between (lat, lon) points."""
    la1, lo1, la2, lo2 = map(math.radians, (*a, *b))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def speed_kmh(prev_cc: str, prev_at: str, cc: str, at: str) -> float | None:
    """Travel speed between two sign-ins' countries; None when either is unknown or both are the same."""
    if not prev_cc or not cc or prev_cc.upper() == cc.upper():
        return None
    a, b = centroids().get(prev_cc.lower()), centroids().get(cc.lower())
    if not a or not b:
        return None
    hours = max((datetime.fromisoformat(at) - datetime.fromisoformat(prev_at)).total_seconds() / 3600, 1 / 60)
    return distance_km(a, b) / hours


def browser(agent: str) -> str:
    """A short label for a user agent: "Firefox on Windows"."""
    a = agent or ""
    name = next((v for k, v in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"), ("Chrome/", "Chrome"),
                                ("Safari/", "Safari"), ("curl/", "curl")) if k in a), "")
    system = next((v for k, v in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                  ("Windows", "Windows"), ("Mac OS X", "macOS"), ("Linux", "Linux")) if k in a), "")
    return " on ".join(x for x in (name, system) if x) or a[:40] or "unknown"


# --- history ------------------------------------------------------------------------------------------------------

def remember(conn: sqlite3.Connection, user_id: int, ip: str, cc: str, at: str | None = None) -> None:
    """A completed (or approved) sign-in: the place counts as seen from now on."""
    net = net_of(ip)
    conn.execute("INSERT INTO signin_history (user_id, at, ip, net, cc, place) VALUES (?, ?, ?, ?, ?, ?)",
                 (user_id, at or db.now(), ip, net, cc.upper(), place_of(cc, net)))


def _since(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")


def prune(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM signin_history WHERE at < ?", (_since(config(conn)["new_place_days"] + 1),))
    conn.execute("DELETE FROM signin_pending WHERE at < ?", (_since(PENDING_KEEP_DAYS),))


# --- the check ----------------------------------------------------------------------------------------------------

@dataclass
class Decision:
    action: str          # allow | stepup | pending | denied | travel
    rule: str = ""       # new-place | travel | '' ; exempt hits keep their rule with action allow
    exempt: bool = False
    detail: str = ""


MESSAGES = {
    "pending": "This sign-in comes from a new place. An admin must approve it first (Users); then sign in again.",
    "denied": "A sign-in from this place was denied by an admin.",
    "travel": "This sign-in was refused: it comes from too far away for the time since your last one. Your sessions "
              "were ended; sign in from your usual place, then set a new password and use two-factor.",
}


def check(conn: sqlite3.Connection, user: dict, ip: str, cc: str, agent: str, is_exempt: bool) -> Decision:
    """After a correct password, before the second factor. Records the rule hits (audit) and applies the travel
    action; the caller refuses pending/denied/travel and goes on with allow/stepup."""
    cfg, now, net = config(conn), db.now(), net_of(ip)
    place = place_of(cc, net)
    prev = conn.execute("SELECT * FROM signin_history WHERE user_id = ? ORDER BY at DESC, id DESC LIMIT 1",
                        (user["id"],)).fetchone()
    rule, detail = "", ""
    if cfg["travel"] and prev and (v := speed_kmh(prev["cc"], prev["at"], cc, now)) and v > TRAVEL_KMH:
        rule, detail = "travel", f"{prev['cc']} -> {cc.upper()} at {v:.0f} km/h"
    elif cfg["new_place"] and prev and not conn.execute(
            "SELECT 1 FROM signin_history WHERE user_id = ? AND place = ? AND at >= ?",
            (user["id"], place, _since(cfg["new_place_days"]))).fetchone():
        rule, detail = "new-place", f"not seen in {cfg['new_place_days']} days"
    if not rule:
        return Decision("allow")
    if is_exempt:
        dec = Decision("allow", rule, True, detail)
    elif users.is_last_admin(conn, user["id"]):   # break-glass: a step-up only, never a block
        if not user["has_totp"]:
            users.set_totp_required(conn, user["id"], True)   # enrols right after the sign-in
        dec = Decision("stepup", rule, False, detail + "; last admin")
    elif rule == "travel":
        admin.end_user_sessions(conn, user["id"])
        conn.execute("UPDATE users SET pw_set_by_admin = 1, pw_grace_left = -1, totp_required = 1 WHERE id = ?",
                     (user["id"],))
        dec = Decision("travel", rule, False, detail)
    elif user["has_totp"]:
        dec = Decision("stepup", rule, False, detail)
    elif conn.execute("SELECT 1 FROM signin_pending WHERE user_id = ? AND place = ? AND status = 'denied' AND at >= ?",
                      (user["id"], place, _since(cfg["new_place_days"]))).fetchone():
        dec = Decision("denied", rule, False, detail)
    else:
        if not conn.execute("SELECT 1 FROM signin_pending WHERE user_id = ? AND place = ? AND status = 'pending'",
                            (user["id"], place)).fetchone():
            conn.execute("INSERT INTO signin_pending (user_id, at, ip, net, cc, place, agent, status) "
                         "VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')", (user["id"], now, ip, net, cc.upper(), place,
                                                                       agent[:300]))
        dec = Decision("pending", rule, False, detail)
    event(conn, user["name"], f"sign-in {rule}: {'exempt' if dec.exempt else dec.action}", user["name"], ip, cc,
          rule, dec.detail)
    return dec


def event(conn: sqlite3.Connection, actor: str, action: str, target: str, ip: str, cc: str, rule: str,
          detail: str = "") -> None:
    """One sign-in protection event in the audit log (Users, Changes)."""
    text = f"address {ip or '?'}, country {cc.upper() or '?'}, rule {rule}" + (f"; {detail}" if detail else "")
    access.audit(conn, actor, action, target, text)


# --- approvals (Users) --------------------------------------------------------------------------------------------

def pending(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("""SELECT p.*, u.name FROM signin_pending p JOIN users u ON u.id = p.user_id
                           WHERE p.status = 'pending' ORDER BY p.at DESC""")
    return [{**dict(r), "browser": browser(r["agent"])} for r in rows]


def decide(conn: sqlite3.Connection, user_id: int, pid: int, approve: bool, by: str) -> dict | None:
    """Approve (the place counts as seen: the user signs in again) or deny a waiting sign-in of this user."""
    row = conn.execute("SELECT p.*, u.name FROM signin_pending p JOIN users u ON u.id = p.user_id "
                       "WHERE p.id = ? AND p.user_id = ? AND p.status = 'pending'", (pid, user_id)).fetchone()
    if not row:
        return None
    conn.execute("UPDATE signin_pending SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?",
                 ("approved" if approve else "denied", by, db.now(), pid))
    if approve:
        remember(conn, row["user_id"], row["ip"], row["cc"])
    event(conn, by, f"sign-in new-place: {'approved' if approve else 'denied'}", row["name"], row["ip"], row["cc"],
          "new-place")
    return dict(row)


# --- sessions -----------------------------------------------------------------------------------------------------

def sessions(conn: sqlite3.Connection, user_id: int, current_hash: str = "") -> list[dict]:
    rows = conn.execute("SELECT rowid AS sid, * FROM admin_sessions WHERE user_id = ? AND expires > ? "
                        "ORDER BY created DESC", (user_id, db.now()))
    return [{"sid": r["sid"], "created": r["created"] or "", "ip": r["ip"] or "", "country": r["country"] or "",
             "browser": browser(r["agent"] or ""), "current": bool(current_hash) and r["token_hash"] == current_hash}
            for r in rows]


def end_session(conn: sqlite3.Connection, user_id: int, sid: int) -> bool:
    return conn.execute("DELETE FROM admin_sessions WHERE rowid = ? AND user_id = ?", (sid, user_id)).rowcount > 0


def end_others(conn: sqlite3.Connection, user_id: int, keep_hash: str) -> int:
    return conn.execute("DELETE FROM admin_sessions WHERE user_id = ? AND token_hash != ?",
                        (user_id, keep_hash)).rowcount
