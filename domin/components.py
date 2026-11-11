"""Components: the DNS inventory and the security posture, installed together or one alone, each turned on or off.

Installed (install.sh --components, DOMIN_COMPONENTS; Settings.components) decides what the host has: posture brings
nmap, the worker's raw-socket drop-in and the Tor/Mullvad helper units. On (Settings > Components, kv KEY) decides
what runs: a component that is off answers 404 on its routes (pages and API), its nav entries and feature rights are
hidden, the worker skips its jobs and its schedules wait; its data stays. At least one installed component stays on.

Shared by both (never switched off): sign-in, account, users, settings, Operations, Routes, host tags and the CSV
import (Settings > CSV import with the inventory, Posture > Import targets with the posture)."""
from __future__ import annotations

import json
import re
import sqlite3

from . import admin
from .config import COMPONENTS

KEY = "components"   # kv: {"inventory": true, "posture": false}; a missing name = on
LABELS = {"inventory": "Inventory", "posture": "Posture"}
WHAT = {"inventory": "DNS inventory: inventory pages, all records, domain pages, search, CSV, drill data, whois and "
                     "e-mail tools, the public scan API and scheduled refreshes",
        "posture": "Security posture: posture and CVEs, scans and schedules, nmap discovery, scan and discovery "
                   "profiles, the CVE look-up, Import targets"}
FEATURES = {"inventory": ("inventory",), "posture": ("posture", "scans", "profiles", "discovery")}   # access.FEATURES
SIGNIN = {"inventory": "inventory", "posture": "posture"}   # users.SIGNIN_AREAS per component
_PATHS = {
    "inventory": re.compile(r"/|/all|/search|/search\.csv|/tools|/d/.*|/data/drill\.json|/scans/[^/]+\.csv"
                            r"|/api/(domains|scans|jobs|rdap|email|scan)(/.*)?"
                            r"|/admin/(viewers|domains/[^/]+/viewers(/.*)?)"),
    "posture": re.compile(r"/admin/(security(?!/scan-settings(/|$))(/.*)?|schedules(/.*)?|discovery/scan)"),
}


def of_path(path: str) -> str:
    """The component a path belongs to ('' = shared)."""
    return next((name for name, pattern in _PATHS.items() if pattern.fullmatch(path)), "")


def enabled(conn: sqlite3.Connection, installed: tuple[str, ...] = COMPONENTS) -> tuple[str, ...]:
    """The installed components that are on (Settings > Components); never none."""
    raw = admin.kv_get(conn, KEY)
    saved = json.loads(raw) if raw else {}
    on = tuple(c for c in installed if saved.get(c, True))
    return on or installed


def save(conn: sqlite3.Connection, installed: tuple[str, ...], wanted: dict[str, bool]) -> list[str]:
    """Store which components are on; returns the changes ("posture off"). ValueError: none left on, or one that is
    not installed asked on."""
    for c in COMPONENTS:
        if wanted.get(c) and c not in installed:
            raise ValueError(f"{LABELS[c]} is not installed on this host; install it first "
                             f"({install_command(installed, c)}).")
    on = [c for c in installed if wanted.get(c)]
    if not on:
        raise ValueError("At least one component must stay on.")
    have = enabled(conn, installed)
    admin.kv_set(conn, KEY, json.dumps({c: c in on for c in installed}, sort_keys=True))
    return [f"{c} {'on' if c in on else 'off'}" for c in installed if (c in on) != (c in have)]


def off_features(on: tuple[str, ...]) -> frozenset[str]:
    """The feature rights (access.FEATURES) of the components that are off or not installed."""
    return frozenset(f for c in COMPONENTS if c not in on for f in FEATURES[c])


def install_command(installed: tuple[str, ...], name: str) -> str:
    """The install.sh run that adds a component (the data is kept)."""
    return "sudo bash deploy/install.sh --components " + ",".join(c for c in COMPONENTS if c in installed or c == name)
