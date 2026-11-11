"""nmap discovery stage of an inventory scan, and its profiles (docs/scheduled-scans.md).

Optional, after the DNS stages: finds the live addresses and open ports among a fixed target set.
- public domain: the addresses this scan's DNS stages tied to its host names (global addresses, posture scope)
- internal domain: the hosts of Settings · Internal networks (posture IP scope)
A profile tunes how (probe method, port check, timing, rate, retries, timeout, reverse DNS, route), never what: it
holds no targets. Each value is checked against an allowlist; no free text reaches the command line.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import sqlite3
import tempfile
import xml.etree.ElementTree as ET

from . import admin, db, fingerprint, proxy, users
from .validate import is_under

log = logging.getLogger("domin.discovery")

DEFAULT_PROFILE = "default"
DEFAULT_KEY = "discovery:default"   # kv: the profile preselected for manual scans and new schedules ('' = none)
MAX_TARGETS = admin.SWEEP_MAX

# method -> (label, nmap flag, takes a probe port list, needs raw sockets)
METHODS = {
    "default": ("nmap's default probes", "", False, False),
    "none": ("No ping: treat all as up (-Pn)", "-Pn", False, False),
    "syn": ("TCP SYN ping (-PS)", "-PS", True, False),
    "ack": ("TCP ACK ping (-PA)", "-PA", True, True),
    "udp": ("UDP ping (-PU)", "-PU", True, True),
    "echo": ("ICMP echo (-PE)", "-PE", False, True),
    "timestamp": ("ICMP timestamp (-PP)", "-PP", False, True),
}
PORT_MODES = {"none": "None: host discovery only (-sn)", "top": "Top N ports (--top-ports)",
              "list": "Port list (-p)"}
FIELDS = ("name", "method", "probe_ports", "port_mode", "top_ports", "ports", "timing", "max_rate", "max_retries",
          "host_timeout", "rdns", "route", "note")
# name -> (low, high, label)
NUMBERS = {"top_ports": (1, 1000, "Top N ports"), "timing": (0, 5, "Timing"), "max_rate": (0, 10000, "Max rate"),
           "max_retries": (0, 10, "Max retries"), "host_timeout": (10, 3600, "Host timeout")}
PROBE_MAX, PORTS_MAX = 100, 1024   # ports in a probe list / a port-check list

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_ITEM = re.compile(r"^[0-9]{1,5}(-[0-9]{1,5})?$")


def port_count(text: str) -> int | None:
    """Ports in a list of N or N-M items (1-65535, N <= M, digits only); None when it is not such a list."""
    items = (text or "").split(",")
    if not text or len(items) > 200:
        return None
    n = 0
    for item in items:
        if not _ITEM.match(item):
            return None
        lo, _, hi = item.partition("-")
        lo_i, hi_i = int(lo), int(hi or lo)
        if not (1 <= lo_i <= hi_i <= 65535):
            return None
        n += hi_i - lo_i + 1
    return n


def check(form: dict, routes: set[str] = frozenset(), raw_ok: bool = False) -> tuple[dict | None, str]:
    """Validate a profile form: (profile, "") or (None, error). raw_ok: the worker may send raw packets and
    Settings · Raw network access is on (raw-only methods are refused otherwise)."""
    def get(k: str) -> str:
        return str(form.get(k) if form.get(k) is not None else "").strip()

    p: dict = {"name": get("name").lower(), "method": get("method"), "port_mode": get("port_mode") or "none",
               "route": get("route"), "note": get("note")[:200], "rdns": 1 if get("rdns") in ("1", "on") else 0}
    if not _NAME.match(p["name"]):
        return None, "Name: 1-40 lower-case letters, digits, - or _."
    if p["method"] not in METHODS:
        return None, "Host discovery: pick a method from the list."
    if p["port_mode"] not in PORT_MODES:
        return None, "Port check: pick one from the list."
    for k, (lo, hi, label) in NUMBERS.items():
        raw = get(k) or ("100" if k == "top_ports" else "")
        if not re.fullmatch(r"[0-9]{1,6}", raw) or not lo <= int(raw) <= hi:
            return None, f"{label}: a whole number {lo}-{hi}."
        p[k] = int(raw)
    takes_ports, needs_raw = METHODS[p["method"]][2], METHODS[p["method"]][3]
    p["probe_ports"] = get("probe_ports") if takes_ports else ""
    if takes_ports:
        n = port_count(p["probe_ports"])
        if n is None or n > PROBE_MAX:
            return None, f"Probe ports: digits, commas and N-M ranges (1-65535), at most {PROBE_MAX} ports."
    p["ports"] = get("ports") if p["port_mode"] == "list" else ""
    if p["port_mode"] == "list":
        n = port_count(p["ports"])
        if n is None or n > PORTS_MAX:
            return None, f"Port list: digits, commas and N-M ranges (1-65535), at most {PORTS_MAX} ports."
    if p["method"] == "none" and p["port_mode"] == "none":
        return None, "No ping (-Pn) needs a port check: alone it reports every target as up."
    if needs_raw and not raw_ok:
        return None, (f"{METHODS[p['method']][0]} needs raw sockets: turn on Settings · Raw network access on a worker "
                      "installed with --raw.")
    if p["route"] not in ("", proxy.DIRECT, *routes):
        return None, "Route: pick one from the list."
    return p, ""


def needs_raw(p: dict) -> bool:
    return METHODS.get(p.get("method", ""), ("", "", False, True))[3]


def nmap_args(p: dict, targets: str, raw: bool = False, dns_servers: tuple[str, ...] = (), routed: bool = False,
              ipv6: bool = False, nmap_bin: str = "nmap") -> list[str]:
    """The command line for profile p (already checked) on a targets file. raw: the worker may send raw packets
    (adds --privileged; a port check is -sS). routed: through a proxy (connect scan, no reverse DNS)."""
    label, flag, takes_ports, _ = METHODS[p["method"]]
    args = [nmap_bin]
    if ipv6:
        args.append("-6")
    if flag:
        args.append(flag + (p["probe_ports"] if takes_ports else ""))
    if p["port_mode"] == "none":
        args.append("-sn")
    else:
        args.append("-sS" if raw and not routed else "-sT")
        args += ["--top-ports", str(int(p["top_ports"]))] if p["port_mode"] == "top" else ["-p", p["ports"]]
    if p["rdns"] and not routed:
        args.append("-R")
        if dns_servers:
            args += ["--dns-servers", ",".join(dns_servers)]
    else:
        args.append("-n")
    args.append(f"-T{int(p['timing'])}")
    args += ["--max-retries", str(int(p["max_retries"])), "--host-timeout", f"{int(p['host_timeout'])}s"]
    if int(p["max_rate"]):
        args += ["--max-rate", str(int(p["max_rate"]))]
    if raw and not routed:
        args.append("--privileged")
    return [*args, "-oX", "-", "-iL", targets]


def command_line(p: dict, raw: bool = False) -> str:
    """For the profile page: the command line with <targets> for the targets file."""
    return " ".join(nmap_args(p, "<targets>", raw=raw))


def profiles(conn: sqlite3.Connection) -> list[dict]:
    return [dict(r) for r in conn.execute("SELECT * FROM discovery_profiles ORDER BY name != 'default', name")]


def profile(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM discovery_profiles WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def save(conn: sqlite3.Connection, p: dict, by: str) -> None:
    cols = list(FIELDS)
    conn.execute(f"""INSERT INTO discovery_profiles ({', '.join(cols)}, updated, updated_by)
                     VALUES ({', '.join('?' * len(cols))}, ?, ?) ON CONFLICT(name) DO UPDATE SET
                     {', '.join(f'{c} = excluded.{c}' for c in cols[1:])}, updated = excluded.updated,
                     updated_by = excluded.updated_by""", [*(p[c] for c in cols), db.now(), by])


def used_by(conn: sqlite3.Connection, name: str) -> list[str]:
    """Schedules ("domain: name") that use a discovery profile."""
    return [f"{r['domain']}: {r['name']}" for r in conn.execute(
        "SELECT domain, name FROM schedules WHERE discovery = 1 AND discovery_profile = ? ORDER BY domain, name",
        (name,))]


def delete(conn: sqlite3.Connection, name: str) -> str:
    """Remove a profile; returns why it can't ('' = removed)."""
    if name == DEFAULT_PROFILE:
        return "The default profile cannot be deleted."
    if uses := used_by(conn, name):
        return f"{name} is used by schedule(s) {', '.join(uses)}: pick another profile there first."
    if not conn.execute("DELETE FROM discovery_profiles WHERE name = ?", (name,)).rowcount:
        return "No such profile."
    if get_default(conn) == name:
        admin.kv_set(conn, DEFAULT_KEY, "")
    return ""


def get_default(conn: sqlite3.Connection) -> str:
    name = admin.kv_get(conn, DEFAULT_KEY) or ""
    return name if name and profile(conn, name) else ""


def set_default(conn: sqlite3.Connection, name: str) -> None:
    if name and not profile(conn, name):
        raise ValueError("Pick an existing discovery profile.")
    admin.kv_set(conn, DEFAULT_KEY, name)


# --- targets -------------------------------------------------------------------------------------------------------

def public_targets(records: list[dict], scope: dict) -> list[str]:
    """Public mode: the global addresses of this scan's records inside the posture scope; nothing else."""
    out: dict[str, None] = {}
    for r in records:
        ip = r.get("ip") or ""
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if a.is_global and users.posture_ok(scope, ip, r.get("country") or ""):
            out[ip] = None
    return list(out)


def internal_targets(nets: tuple[str, ...], scope: dict) -> list[str]:
    """Internal mode: the hosts of the configured internal networks inside the posture IP scope."""
    out: dict[str, None] = {}
    for n in nets:
        net = ipaddress.ip_network(n, strict=False)
        for a in (net.hosts() if net.num_addresses > 2 else net):
            if len(out) > MAX_TARGETS:
                break
            if users.posture_ip_ok(scope, str(a)):   # private addresses have no country: IP rules only
                out[str(a)] = None
    return list(out)


def parse(xml: str, open_only: bool) -> list[dict]:
    """Live hosts from nmap XML: [{ip, names, ports, reason}]. open_only (-Pn): only hosts with an open port."""
    found = []
    for host in ET.fromstring(xml).findall("host"):
        status = host.find("status")
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), "")
        if not addr or status is None or status.get("state") != "up":
            continue
        ports = [f"{p.get('portid')}/{p.get('protocol') or 'tcp'}" for p in host.findall("./ports/port")
                 if (s := p.find("state")) is not None and s.get("state") == "open"]
        if open_only and not ports:
            continue
        names = [h.get("name", "").lower().rstrip(".") for h in host.findall("./hostnames/hostname") if h.get("name")]
        found.append({"ip": addr, "names": list(dict.fromkeys(names)), "ports": ports,
                      "reason": status.get("reason") or ""})
    return found


# --- the stage -----------------------------------------------------------------------------------------------------

def stage(conn: sqlite3.Connection, name: str, records: list[dict], internal: bool, settings, notes: list[str],
          progress=lambda _: None, run=fingerprint.run_args, raw_capable=fingerprint.raw_capable,
          nmap_bin: str = "nmap") -> dict:
    """Run the nmap discovery stage with profile `name` for one scan. Returns {profile, params, found, targets}.
    Anything that stops it (no profile, no targets, raw needed, route) is a note, never a failed job."""
    out: dict = {"profile": name, "params": "", "found": [], "targets": []}
    p = profile(conn, name)
    if not p:
        notes.append(f"nmap discovery skipped: profile {name} no longer exists")
        return out
    scope = users.get_scope(conn)
    if internal:
        if not settings.internal_nets:
            notes.append("nmap discovery skipped: no internal networks configured (Settings · Internal networks)")
            return out
        targets = internal_targets(settings.internal_nets, scope)
    else:
        targets = public_targets(records, scope)
    if len(targets) > MAX_TARGETS:
        notes.append(f"nmap discovery: {len(targets) - MAX_TARGETS} addresses over the cap of {MAX_TARGETS} not swept")
        targets = targets[:MAX_TARGETS]
    out["targets"] = targets
    if not targets:
        notes.append("nmap discovery skipped: no address in scope to sweep")
        return out
    raw = bool(scope.get("raw_scans")) and raw_capable()
    if needs_raw(p) and not raw:
        notes.append(f"nmap discovery skipped: {METHODS[p['method']][0]} needs raw sockets (Settings · Raw network "
                     "access, worker installed with --raw)")
        return out
    via = None
    if not internal:   # internal scans never leave the LAN: always direct
        try:
            cfg = proxy.get(conn)
            via = proxy.hop(conn, proxy.pick(cfg, p.get("route") or "", "inventory"))
        except proxy.ProxyError as exc:   # fail closed: no direct run instead
            notes.append(f"nmap discovery skipped: route: {exc}")
            return out
        if via and (p["method"] != "none" or p["port_mode"] == "none"):
            notes.append(f"nmap discovery skipped: the route {proxy.route(via)} is a proxy, which carries only "
                         "No ping (-Pn) with a port check (connect scan)")
            return out
    dns = tuple(settings.internal_dns) if internal else ()
    timeout = int(settings.scan_timeout_hours) * 3600
    params, found = [], []
    for version in (4, 6):
        batch = [t for t in targets if ipaddress.ip_address(t).version == version]
        if not batch:
            continue
        fd, path = tempfile.mkstemp(prefix="domin-targets-", suffix=".txt")   # 0600 on POSIX
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write("\n".join(batch) + "\n")
            args = nmap_args(p, path, raw=raw, dns_servers=dns, routed=bool(via), ipv6=version == 6,
                             nmap_bin=nmap_bin)
            shown = " ".join(args[:-1] + [f"<{len(batch)} addresses>"]) + (f" via {proxy.route(via)}" if via else "")
            params.append(shown)
            log.info("discovery %s: %s", name, shown)
            progress(f"nmap discovery: {len(batch)} addresses")
            try:
                xml = run(args, timeout, via)
            except FileNotFoundError:
                notes.append("nmap discovery skipped: nmap is not installed")
                break
            except fingerprint.NmapError as exc:
                notes.append(f"nmap discovery failed: {exc}")
                continue
            found += parse(xml, open_only=p["method"] == "none")
        finally:
            os.unlink(path)
    out["params"], out["found"] = "; ".join(params), found
    return out


def new_records(found: list[dict], records: list[dict], domain: str) -> list[dict]:
    """Internal mode: live addresses whose reverse name is under the domain and not yet a record of this scan."""
    have = {(r["host"], r.get("ip") or "") for r in records}
    out = []
    for f in found:
        for n in f["names"]:
            n = n if "." in n else f"{n}.{domain}"   # a bare hosts-file name belongs to the zone
            if (is_under(n, domain) and re.fullmatch(r"[a-z0-9_.-]{1,253}", n) and not n.startswith(".")
                    and (n, f["ip"]) not in have):
                have.add((n, f["ip"]))
                out.append({"host": n, "ip": f["ip"], "asn": "", "prefix": "", "netname": "Private/reserved",
                            "descr": "", "country": ""})
    return out
