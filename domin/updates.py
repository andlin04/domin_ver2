"""Update check: is a newer domin release published on GitHub?

Once a day (the worker's hourly loop, like the CVE refresh), `python -m domin check-update`, or "Check for updates"
under Settings asks https://api.github.com/repos/andlin04/domin_ver2/releases/latest (unauthenticated, through the
app's HTTP client and its proxy). Nothing is downloaded or installed: the answer (tag, link, date, name, the first
500 characters of the notes) goes to kv `update_check:last`, and admins and maintainers see a one-line banner when
the tag is newer than this install's version. The release name and notes are someone else's text: pages escape them
and link only to https://github.com/.

Automatic check on or off: kv `update_check:on`, set under Settings; until an admin sets it, DOMIN_UPDATE_CHECK
(default on). Off: the daily check makes no request; "Check for updates" still works.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import time

import httpx

from . import __version__, admin, tools

log = logging.getLogger(__name__)

URL = "https://api.github.com/repos/andlin04/domin_ver2/releases/latest"
RELEASES = "https://github.com/"   # the only prefix a release link may have
KEY = "update_check:last"
ON_KEY = "update_check:on"
HOURS = 24
TIMEOUT = 10        # seconds for the whole request
EXCERPT = 500       # characters of the release notes kept
NAME_MAX = 200
ERROR_MAX = 300
UPGRADE = {"public": "git pull && sudo bash deploy/install.sh",
           "internal": "sudo bash deploy/install.sh (from the unpacked new package)"}

_TAG = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?(?:\+[0-9A-Za-z.-]+)?")


def parse(tag: str) -> tuple[int, int, int] | None:
    """'v2.1.0' or '2.1' -> (2, 1, 0); a pre-release ('2.1.0-rc1') or anything else -> None."""
    m = _TAG.fullmatch((tag or "").strip())
    return (int(m[1]), int(m[2]), int(m[3] or 0)) if m else None


def enabled(conn: sqlite3.Connection, default: bool) -> bool:
    got = admin.kv_get(conn, ON_KEY)
    return default if got is None else got == "1"


def set_enabled(conn: sqlite3.Connection, on: bool) -> None:
    admin.kv_set(conn, ON_KEY, "1" if on else "0")


def fetch(client: httpx.Client) -> dict:
    """The latest release as stored fields; {} when none is published (404, or only a pre-release or draft)."""
    got = tools.get_json(client, URL, TIMEOUT, headers={"Accept": "application/vnd.github+json",
                                                        "User-Agent": f"domin/{__version__}"})
    if got is None:
        return {}
    data = got[1]
    if not isinstance(data, dict):
        raise ValueError("unexpected answer (not a JSON object)")
    if data.get("prerelease") or data.get("draft"):
        return {}
    tag = str(data.get("tag_name") or "")
    if parse(tag) is None:
        if re.fullmatch(r"v?\d+(\.\d+){1,2}-.*", tag.strip()):   # a pre-release tag without the flag
            return {}
        raise ValueError(f"not a version tag: {tag[:40]!r}")
    return {"tag": tag.strip(), "html_url": str(data.get("html_url") or "")[:500],
            "published_at": str(data.get("published_at") or "")[:40],
            "name": str(data.get("name") or "")[:NAME_MAX], "body": str(data.get("body") or "")[:EXCERPT]}


def check(conn: sqlite3.Connection, client: httpx.Client, now: float | None = None) -> dict:
    """Ask GitHub once and store the answer (any failure: the error, no release)."""
    res = {"checked_at": time.time() if now is None else now, "error": ""}
    try:
        res.update(fetch(client))
    except Exception as exc:   # network, HTTP status, JSON, refused address: all mean "could not check"
        res["error"] = f"{type(exc).__name__}: {exc}"[:ERROR_MAX]
        log.warning("update check failed: %s", res["error"])
    admin.kv_set(conn, KEY, json.dumps(res))
    return res


def run(conn: sqlite3.Connection, default_on: bool, now: float | None = None) -> dict | None:
    """The daily check (worker): None without a request while it is off or the last check is under a day old."""
    now = time.time() if now is None else now
    if not enabled(conn, default_on):
        return None
    last = json.loads(admin.kv_get(conn, KEY) or "{}")
    if now - last.get("checked_at", 0) < HOURS * 3600:
        return None
    with tools.http_client() as client:
        return check(conn, client, now)


def status(conn: sqlite3.Connection, default_on: bool, install_mode: str = "public",
           installed: str = __version__) -> dict:
    """What the pages show. state: never | error | latest | available; major: the new release's MAJOR is higher."""
    last = json.loads(admin.kv_get(conn, KEY) or "{}")
    tag, mine = last.get("tag", ""), parse(installed)
    if not last.get("checked_at"):
        state = "never"
    elif last.get("error"):
        state = "error"
    elif (theirs := parse(tag)) and mine and theirs > mine:
        state = "available"
    else:
        state = "latest"
    major = state == "available" and parse(tag)[0] > mine[0]
    url = last.get("html_url", "")
    text = f"{last.get('name', '')}\n{last.get('body', '')}".lower()
    return {"on": enabled(conn, default_on), "state": state, "checked_at": last.get("checked_at", 0),
            "error": last.get("error", ""), "version": ".".join(map(str, parse(tag) or ())) if tag else "",
            "installed": installed, "name": last.get("name", ""), "published_at": last.get("published_at", ""),
            "url": url if url.startswith(RELEASES) else "", "security": "security" in text, "major": major,
            "command": UPGRADE.get(install_mode, UPGRADE["public"])}
