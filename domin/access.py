"""Delegation: which domains a request may see and act on (docs/delegation.md).

Admins see everything. A power user sees only the domains of its grants: (domain, level) rows, level viewer (read)
or admin (read plus that domain's actions). A grant on example.com also covers every domain under it
(*.example.com); ALL covers every domain. Every query that lists, counts or charts domain data takes a Scope and adds
Scope.sql(column) to its WHERE clause, so one place decides what a user sees."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass

from . import db, syslog

LEVELS = ("viewer", "admin")   # per-domain grant levels, least to most
LEVEL_LABELS = {"viewer": "viewer", "admin": "maintainer"}
ALL = "*"                      # a grant on every domain

# Feature rights of a power user (admins: everything). A feature right decides whether a user may use a feature at
# all; the domain grants still decide on which domains. key: (label, what read allows, what read-write adds; "" = no
# write part, the feature is read only).
FEATURES = {
    "inventory": ("Inventory", "inventory pages, all records, domain pages, search, CSV, drill data, whois and e-mail "
                  "tools", ""),
    "posture": ("Posture & CVEs", "posture overview and analysis, CVEs, changes, reports, the CVE look-up page", ""),
    "scans": ("Scans & schedules", "Posture · Scans: scan activity and scheduled rescans",
              "posture scans and renew, Scan with nmap, look-ups and fingerprints, schedules (add, edit, run, enable, "
              "delete)"),
    "tags": ("Tags", "host tags on the domain and posture pages", "add and remove host tags"),
    "profiles": ("Scan profiles", "the profiles list", "add, change and delete profiles"),
    "discovery": ("Discovery profiles", "the profiles list", "add, change and delete profiles, the default"),
}
ADMIN_FEATURES = {"operations": ("Operations", "jobs, tuning, visits, dropping a domain"),
                  "settings": ("Settings", "general settings, Routes, sign-in"),
                  "users": ("Users", "users, roles, rights and grants")}   # admins only
RIGHTS = ("none", "read", "write")   # least to most
RIGHT_LABELS = {"none": "none", "read": "read", "write": "read-write"}
# What a power user could do before the rights existed (the migration and new power users)
DEFAULT_RIGHTS = {"inventory": "read", "posture": "read", "scans": "write", "tags": "write", "profiles": "read",
                  "discovery": "read"}


def rights_of(user: dict) -> dict[str, str]:
    """A user's feature rights from users.rights (JSON); '' = the defaults. Unknown keys and levels are dropped,
    a read-only feature never holds write."""
    raw = user.get("rights") or ""
    saved = json.loads(raw) if raw else dict(DEFAULT_RIGHTS)
    out = {}
    for f, (_, _, write) in FEATURES.items():
        lv = saved.get(f, "none")
        lv = lv if lv in RIGHTS else "none"
        out[f] = "read" if lv == "write" and not write else lv
    return out


def parse_rights(form: dict[str, str], keep: dict[str, str] | None = None) -> dict[str, str]:
    """The matrix of the user edit page: r_<feature> = none | read | write. keep: the rights of features the page
    did not show (a component turned off), stored unchanged."""
    out = {}
    for f, (label, _, write) in FEATURES.items():
        if keep and f in keep:
            out[f] = keep[f]
            continue
        lv = form.get(f"r_{f}") or "none"
        if lv not in RIGHTS or (lv == "write" and not write):
            raise ValueError(f"{label}: pick none, read{' or read-write' if write else ''}.")
        out[f] = lv
    return out


def set_rights(conn: sqlite3.Connection, user_id: int, wanted: dict[str, str]) -> list[str]:
    """Store a user's feature rights; returns the changes for the audit ("scans read->write")."""
    row = conn.execute("SELECT rights FROM users WHERE id = ?", (user_id,)).fetchone()
    have = rights_of({"rights": row["rights"] if row else ""})
    conn.execute("UPDATE users SET rights = ? WHERE id = ?", (json.dumps(wanted, sort_keys=True), user_id))
    return [f"{f} {have.get(f, 'none')}->{lv}" for f, lv in wanted.items() if have.get(f, "none") != lv]


def covers(grant: str, name: str) -> bool:
    """True when a grant on `grant` covers the domain or host name `name` (itself or a name under it)."""
    name = (name or "").lower().rstrip(".")
    return grant == ALL or name == grant or name.endswith("." + grant)


@dataclass(frozen=True)
class Scope:
    """What one request may see (hashable: it keys the page caches)."""
    everything: bool = False
    grants: tuple[tuple[str, str], ...] = ()   # (domain, level), sorted
    rights: tuple[tuple[str, str], ...] = ()   # (feature, none | read | write), sorted; ignored when everything
    off: frozenset[str] = frozenset()   # features of components turned off (domin.components): nobody has them

    def can(self, feature: str, level: str = "read") -> bool:
        """The feature right: may this user use the feature at this level (read / write) at all?"""
        if feature in self.off:
            return False
        if self.everything:
            return True
        return RIGHTS.index(dict(self.rights).get(feature, "none")) >= RIGHTS.index(level)

    def acts(self, feature: str, name: str) -> bool:
        """An action of a feature on one domain: read-write on the feature and maintainer of the domain."""
        return self.can(feature, "write") and self.manages(name)

    def level(self, name: str) -> str:
        """The highest level of the grants covering name: "admin", "viewer" or "" (none)."""
        if self.everything:
            return "admin"
        got = {lv for g, lv in self.grants if covers(g, name)}
        return next((lv for lv in reversed(LEVELS) if lv in got), "")

    def sees(self, name: str) -> bool:
        return bool(name) and self.level(name) != ""

    def manages(self, name: str) -> bool:
        return bool(name) and self.level(name) == "admin"

    @property
    def sees_all(self) -> bool:
        return self.everything or any(g == ALL for g, _ in self.grants)

    @property
    def manages_any(self) -> bool:
        return self.everything or any(lv == "admin" for _, lv in self.grants)

    def key(self) -> str:
        """Short text that changes with the grants (cache keys, browser cache URLs)."""
        return "all" if self.sees_all else hashlib.sha256(repr(self.grants).encode()).hexdigest()[:12]

    def sql(self, column: str) -> tuple[str, list]:
        """A WHERE fragment (and its arguments) that keeps rows whose domain `column` this scope sees."""
        if self.sees_all:
            return "1", []
        if not self.grants:
            return "0", []
        names = [g for g, _ in self.grants]
        parts = [f"{column} IN ({','.join('?' * len(names))})"]
        parts += [f"{column} LIKE ? ESCAPE '\\'"] * len(names)
        return "(" + " OR ".join(parts) + ")", [*names, *("%." + db.like_escape(n) for n in names)]

    def keep(self, names):
        """The names of an iterable this scope sees, in order."""
        return [n for n in names if self.sees(n)]


FULL = Scope(everything=True)
NONE = Scope()

ADMIN_BASE = "/admin"
_POSTURE = re.compile(r"/admin/(security(?!/(scan-settings|profiles|discovery-profiles)(/|$))(/.*)?"
                      r"|schedules(/.*)?|tags|discovery/scan)")


def area(path: str) -> str:
    """The sign-in area of a path (Settings, Sign-in): "inventory" (the public pages), "posture" or "admin"."""
    if path != ADMIN_BASE and not path.startswith(ADMIN_BASE + "/"):
        return "inventory"
    return "posture" if _POSTURE.fullmatch(path) else "admin"


# Which feature right a request needs: (path pattern, feature, level); level None = read for GET/HEAD, write for any
# other method. First match wins; no match = no feature right needed (sign-in, account, the admin start page).
# The web app checks this for every signed-in request before its handler runs (web.create_app, gate).
ROUTES = [(re.compile(p), f, lv) for p, f, lv in (
    (r"/admin/security/report", "posture", "read"),
    (r"/admin/security/posture/status", "", None),   # scan progress: grant-filtered, for posture and scans pages
    (r"/admin/security/scans", "scans", "read"),
    (r"/admin/security/(posture|scan)", "scans", "write"),
    (r"/admin/security/lookup", "posture", "read"),
    (r"/admin/security/profiles(/.*)?", "profiles", None),
    (r"/admin/security/discovery-profiles(/.*)?", "discovery", None),
    (r"/admin/security/scan-settings(/.*)?", "settings", None),
    (r"/admin/security(/analysis|/kpis|/domain-search)?", "posture", "read"),
    (r"/admin/(schedules(/.*)?|discovery/scan)", "scans", None),
    (r"/admin/tags", "tags", "write"),
    (r"/admin/(tune|jobs/.*|domains/[^/]+/delete)", "operations", "write"),
    (r"/admin/(settings|users)(/.*)?", "settings", None),
    (r"/admin/(viewers|domains/[^/]+/viewers(/.*)?)", "inventory", "read"),
    (r"/|/all|/search|/search\.csv|/tools|/d/.*|/data/drill\.json|/scans/[^/]+\.csv"
     r"|/api/(domains|scans|jobs|rdap|email|scan)(/.*)?", "inventory", "read"),
)]


def feature_of(method: str, path: str) -> tuple[str, str] | None:
    """(feature, level) a request needs, or None."""
    for pattern, feature, level in ROUTES:
        if pattern.fullmatch(path):
            return (feature, level or ("read" if method in ("GET", "HEAD") else "write")) if feature else None
    return None


def feature_label(feature: str) -> str:
    return (FEATURES.get(feature) or ADMIN_FEATURES.get(feature) or (feature,))[0]


def grants(conn: sqlite3.Connection, user_id: int) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT domain, level, added, added_by FROM grants WHERE user_id = ? ORDER BY domain != ?, domain",
        (user_id, ALL))]


def all_grants(conn: sqlite3.Connection) -> dict[int, list[dict]]:
    out: dict[int, list[dict]] = {}
    for r in conn.execute("SELECT user_id, domain, level FROM grants ORDER BY domain != ?, domain", (ALL,)):
        out.setdefault(r["user_id"], []).append({"domain": r["domain"], "level": r["level"]})
    return out


def for_user(conn: sqlite3.Connection, user: dict | None) -> Scope:
    """The scope of a signed-in user; admins see everything, a missing or disabled user nothing."""
    if not user or user.get("disabled"):
        return NONE
    if user["role"] == "admin":
        return FULL
    return Scope(grants=tuple(sorted((g["domain"], g["level"]) for g in grants(conn, user["id"]))),
                 rights=tuple(sorted(rights_of(user).items())))


def valid_domain(name: str) -> bool:
    """A grant's domain: ALL, or a lower-case name of labels (letters, digits, -, _), 1-253 characters."""
    if name == ALL:
        return True
    labels = name.split(".")
    return (0 < len(name) <= 253 and len(labels) >= 1
            and all(0 < len(x) <= 63 and all(ch.isalnum() or ch in "-_" for ch in x) and x.isascii()
                    for x in labels))


def set_grants(conn: sqlite3.Connection, user_id: int, wanted: dict[str, str], by: str) -> dict[str, list]:
    """Replace a user's grants with wanted ({domain: level}); returns {added, removed, changed} for the audit."""
    for d, lv in wanted.items():
        if not valid_domain(d) or lv not in LEVELS:
            raise ValueError(f"grant {d}: not a domain name or level")
    have = {g["domain"]: g["level"] for g in grants(conn, user_id)}
    lb = LEVEL_LABELS   # the audit shows the labels (maintainer), the table keeps the stored levels (admin)
    diff = {"added": sorted(f"{d}={lb[lv]}" for d, lv in wanted.items() if d not in have),
            "removed": sorted(f"{d}={lb.get(lv, lv)}" for d, lv in have.items() if d not in wanted),
            "changed": sorted(f"{d}={lb.get(have[d], have[d])}->{lb[lv]}" for d, lv in wanted.items()
                              if d in have and have[d] != lv)}
    now = db.now()
    for d in have.keys() - wanted.keys():
        conn.execute("DELETE FROM grants WHERE user_id = ? AND domain = ?", (user_id, d))
    for d, lv in wanted.items():
        if have.get(d) != lv:
            conn.execute("INSERT INTO grants (user_id, domain, level, added, added_by) VALUES (?, ?, ?, ?, ?) "
                         "ON CONFLICT(user_id, domain) DO UPDATE SET level = excluded.level, added = excluded.added, "
                         "added_by = excluded.added_by", (user_id, d, lv, now, by))
    return diff


def parse_grants(form: dict[str, str], rows: int = 200) -> dict[str, str]:
    """The grant rows of the user form: g_domain_N / g_level_N; an empty domain drops the row. A domain twice keeps
    the higher level."""
    out: dict[str, str] = {}
    for i in range(rows):
        d = (form.get(f"g_domain_{i}") or "").strip().lower().rstrip(".")
        if not d:
            continue
        lv = form.get(f"g_level_{i}") or "viewer"
        if not valid_domain(d) or lv not in LEVELS:
            raise ValueError(f"Grant row {i + 1}: pick a domain and a level.")
        if LEVELS.index(lv) >= LEVELS.index(out.get(d, "viewer")):
            out[d] = lv
    return out


# --- audit trail ---------------------------------------------------------------------------------------------------

# --- viewers granted by a maintainer (Admin > Domain viewers) ---------------------------------------------------
# A maintainer of a domain may give existing power users a viewer grant on exactly that domain, and take such a
# grant back. Never more: no users made, no maintainer grants, admins untouched, a higher grant never lowered.

def viewers_panel(conn: sqlite3.Connection, domain: str, actor: dict) -> dict:
    """The grants on exactly this domain (power users) and the enabled power users that could get a viewer grant."""
    rows = [dict(r) for r in conn.execute(
        "SELECT g.user_id, u.name, g.level, g.added_by FROM grants g JOIN users u ON u.id = g.user_id "
        "WHERE g.domain = ? AND u.role = 'power' ORDER BY u.name COLLATE NOCASE", (domain,))]
    have = {r["user_id"] for r in rows}
    pick = [dict(r) for r in conn.execute("SELECT id, name FROM users WHERE role = 'power' AND disabled = 0 "
                                          "ORDER BY name COLLATE NOCASE") if r["id"] not in have | {actor["id"]}]
    return {"rows": rows, "candidates": pick}


def _power_user(conn: sqlite3.Connection, user_id: int, actor: dict) -> dict:
    row = conn.execute("SELECT id, name, role, disabled FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or row["role"] != "power" or row["id"] == actor["id"]:
        raise LookupError("No such power user.")
    return dict(row)


def grant_viewer(conn: sqlite3.Connection, domain: str, user_id: int, actor: dict) -> bool:
    """A viewer grant on exactly `domain` for an existing, enabled power user. False = already there.
    ValueError: the user already holds maintainer there (never lowered here). LookupError: no such power user."""
    target = _power_user(conn, user_id, actor)
    if target["disabled"]:
        raise LookupError("No such power user.")
    row = conn.execute("SELECT level FROM grants WHERE user_id = ? AND domain = ?", (user_id, domain)).fetchone()
    if row:
        if row["level"] != "viewer":
            raise ValueError(f"{target['name']} is maintainer of {domain}; only an admin changes that.")
        return False
    conn.execute("INSERT INTO grants (user_id, domain, level, added, added_by) VALUES (?, ?, 'viewer', ?, ?)",
                 (user_id, domain, db.now(), actor["name"]))
    audit(conn, actor["name"], "grant-viewer", target["name"], domain)
    return True


def revoke_viewer(conn: sqlite3.Connection, domain: str, user_id: int, actor: dict) -> None:
    """Take back a viewer grant on exactly `domain`. ValueError: it is a maintainer grant. LookupError: none."""
    target = _power_user(conn, user_id, actor)
    row = conn.execute("SELECT level FROM grants WHERE user_id = ? AND domain = ?", (user_id, domain)).fetchone()
    if not row:
        raise LookupError(f"{target['name']} has no grant on {domain}.")
    if row["level"] != "viewer":
        raise ValueError(f"{target['name']} is maintainer of {domain}; only an admin changes that.")
    conn.execute("DELETE FROM grants WHERE user_id = ? AND domain = ?", (user_id, domain))
    audit(conn, actor["name"], "revoke-viewer", target["name"], domain)


def audit(conn: sqlite3.Connection, actor: str, action: str, target: str, detail: str = "",
          forward: bool = True) -> None:
    """One audit entry (Users, Changes); also forwarded to syslog when Settings > Logging has a server (forward=False:
    the caller sends its own, richer event)."""
    conn.execute("INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
                 (db.now(), actor, action, target, detail[:1000]))
    if forward:
        syslog.emit(conn, "notice", "audit", f"{actor}: {action} {target}".strip(), actor=actor, action=action,
                    target=target, detail=detail[:200])


def audit_recent(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]
