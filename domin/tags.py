"""Host tags: free labels per discovered host name, to group hosts (one host, any number of tags).

Analysts set tags by hand. :func:`suggest` proposes a classification from the host name's labels and, when a
posture scan has run, from the open services at the host's addresses; a suggestion becomes a tag only when an
analyst accepts it. Rules only, no model.
"""
from __future__ import annotations

import re
import sqlite3

from . import db

_TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,29}$")

# host-name label words -> tag
NAME_RULES = {
    "webserver": {"www", "web", "portal", "blog", "shop", "api", "cms", "intranet", "wiki"},
    "mailserver": {"mail", "smtp", "mx", "imap", "pop", "pop3", "webmail", "exchange", "autodiscover"},
    "dns": {"ns", "dns", "resolver"},
    "remote-access": {"vpn", "remote", "rdp", "citrix", "gateway", "bastion", "jump"},
    "iot-device": {"cam", "camera", "ipcam", "nvr", "dvr", "doorbell", "iot", "sensor", "thermostat", "plug", "bulb",
                   "hue", "esp", "tasmota", "shelly", "sonos", "chromecast", "tv"},
    "printer": {"printer", "print", "prn", "mfp", "scanner"},
    "storage": {"nas", "backup", "storage", "files", "nextcloud"},
    "database": {"db", "sql", "mysql", "postgres", "pg", "mongo", "redis", "elastic"},
    "non-production": {"dev", "test", "stage", "staging", "uat", "qa", "lab", "sandbox"},
}

# open TCP port -> tag; service names nmap reports -> tag
PORT_RULES = {
    "webserver": {80, 443, 8000, 8080, 8443},
    "mailserver": {25, 110, 143, 465, 587, 993, 995},
    "dns": {53},
    "remote-access": {3389, 5900},
    "database": {1433, 1521, 3306, 5432, 6379, 9200, 11211, 27017},
    "iot-device": {554, 1883, 8883, 5683, 1900},
    "printer": {515, 631, 9100},
    "file-share": {139, 445, 2049},
}
SERVICE_RULES = {"http": "webserver", "https": "webserver", "smtp": "mailserver", "domain": "dns",
                 "ms-wbt-server": "remote-access", "vnc": "remote-access", "rtsp": "iot-device", "mqtt": "iot-device",
                 "upnp": "iot-device", "ipp": "printer", "jetdirect": "printer", "microsoft-ds": "file-share",
                 "nfs": "file-share", "mysql": "database", "postgresql": "database", "redis": "database"}


def valid(tag: str) -> bool:
    return bool(_TAG.match(tag or ""))


def for_hosts(conn: sqlite3.Connection, hosts: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in range(0, len(hosts), 500):
        part = hosts[i:i + 500]
        q = ",".join("?" * len(part))
        for r in conn.execute(f"SELECT host, tag FROM host_tags WHERE host IN ({q}) ORDER BY tag", part):
            out.setdefault(r["host"], []).append(r["tag"])
    return out


def add(conn: sqlite3.Connection, host: str, tag: str, by: str) -> bool:
    return conn.execute("INSERT OR IGNORE INTO host_tags (host, tag, added, added_by) VALUES (?, ?, ?, ?)",
                        (host, tag, db.now(), by)).rowcount > 0


def remove(conn: sqlite3.Connection, host: str, tag: str) -> bool:
    return conn.execute("DELETE FROM host_tags WHERE host = ? AND tag = ?", (host, tag)).rowcount > 0


def suggest(host: str, services: list[dict] | None = None) -> list[str]:
    """Classification tags for a host name and its open services (posture scan), sorted."""
    first = host.lower().split(".")[0]
    words = set(re.split(r"[-_0-9]+", first)) | {first}
    out = {tag for tag, names in NAME_RULES.items() if words & names}
    for s in services or []:
        out |= {tag for tag, ports in PORT_RULES.items() if s.get("port") in ports}
        name = (s.get("service") or "").lower()
        if name in SERVICE_RULES or name.startswith("http"):
            out.add(SERVICE_RULES.get(name, "webserver"))
    return sorted(out)


def suggestions(rows: list[dict], posture_rows: list[dict], have: dict[str, list[str]]) -> dict[str, list[str]]:
    """Per host name of the records: suggested tags it does not carry yet. posture_rows give the open services per
    address (the latest posture scan); a host gets the services of every address it resolves to."""
    by_ip = {p["ip"]: p.get("services") or [] for p in posture_rows if p.get("status") == "done"}
    services: dict[str, list[dict]] = {}
    for r in rows:
        services.setdefault(r["host"], []).extend(by_ip.get(r["ip"], []))
    return {h: [t for t in suggest(h, svc) if t not in have.get(h, [])] for h, svc in services.items()}
