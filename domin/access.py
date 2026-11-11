"""Delegation: which domains a request may see and act on (docs/delegation.md).

Admins see everything. A power user sees only the domains of its grants: (domain, level) rows, level viewer (read)
or admin (read plus that domain's actions). A grant on example.com also covers every domain under it
(*.example.com); ALL covers every domain. Every query that lists, counts or charts domain data takes a Scope and adds
Scope.sql(column) to its WHERE clause, so one place decides what a user sees."""
from __future__ import annotations

import hashlib
import re
import sqlite3
from dataclasses import dataclass

from . import db

LEVELS = ("viewer", "admin")   # per-domain grant levels, least to most
LEVEL_LABELS = {"viewer": "viewer", "admin": "domain admin"}
ALL = "*"                      # a grant on every domain


def covers(grant: str, name: str) -> bool:
    """True when a grant on `grant` covers the domain or host name `name` (itself or a name under it)."""
    name = (name or "").lower().rstrip(".")
    return grant == ALL or name == grant or name.endswith("." + grant)


@dataclass(frozen=True)
class Scope:
    """What one request may see (hashable: it keys the page caches)."""
    everything: bool = False
    grants: tuple[tuple[str, str], ...] = ()   # (domain, level), sorted

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
    return Scope(grants=tuple(sorted((g["domain"], g["level"]) for g in grants(conn, user["id"]))))


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
    diff = {"added": sorted(f"{d}={lv}" for d, lv in wanted.items() if d not in have),
            "removed": sorted(f"{d}={lv}" for d, lv in have.items() if d not in wanted),
            "changed": sorted(f"{d}={have[d]}->{lv}" for d, lv in wanted.items() if d in have and have[d] != lv)}
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

def audit(conn: sqlite3.Connection, actor: str, action: str, target: str, detail: str = "") -> None:
    conn.execute("INSERT INTO audit (at, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)",
                 (db.now(), actor, action, target, detail[:1000]))


def audit_recent(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))]
