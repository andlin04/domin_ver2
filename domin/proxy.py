"""Scan routes: how posture scans and inventory jobs reach the internet (Settings · Routes).

Named routes, each a custom proxy (socks5 / socks4 / http), Tor (the local tor client's SOCKS5) or Mullvad (a
relay's SOCKS5 inside the host's Mullvad tunnel, chosen per target: mullvad.py). "Direct" is built in. Shared
settings pick the default route for posture scans, the route for inventory jobs and the route for CVE look-ups; a
scan profile picks "Default" (the default posture route), Direct or a named route.

Posture scans: nmap runs under proxychains4 with a per-run config file (:func:`conf`), so the connect scan and the
version probes both leave through the hop. nmap's own ``--proxies`` covers version detection and NSE only, so it is
not used. Inventory jobs: HTTP look-ups through httpx with the hop as proxy, DNS over DoH through the same client
(scanner.py). Internal zones always stay direct. Fail closed: a scan that cannot use its route fails with the
reason, never a direct scan. Tor and Mullvad never carry a private target.

A hop is one resolved proxy for one scan: {enabled, type, host, port, username, password, cve, label}. The settings
live as JSON in the kv table (KEY); a custom proxy's password is stored in plain text there (the database is
readable by the service user only) and never rendered back. The single-route settings of earlier builds
(LEGACY_KEY) are read once into one named route when KEY is missing, and never written or removed.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import shutil
import socket
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx

from . import admin, db, mullvad, tools

KEY = "scan_routes"
LEGACY_KEY = "scan_proxy"   # the single route before named routes: read for the migration only
TYPES = ("socks5", "socks4", "http")
KINDS = {"custom": "Custom proxy", "tor": "Tor", "mullvad": "Mullvad"}
DIRECT = "direct"
USES = {"posture": "default route", "inventory": "inventory jobs", "cve": "CVE look-ups"}
ROLES = {"posture": "Default for posture", "inventory": "Inventory", "cve": "CVE look-ups"}   # the Routes table
DOH = "https://dns.quad9.net/dns-query"
ROUTE_DEFAULT = {"id": "", "name": "", "kind": "custom", "enabled": True, "type": "socks5", "host": "", "port": 1080,
                 "username": "", "password": "", "tor_host": "127.0.0.1", "tor_port": 9050, "mullvad_mode": "auto",
                 "mullvad_country": "", "mullvad_city": "", "mullvad_fallback": ""}
TESTS_KEY = "scan_route_tests"   # {route id: {at, ok, message}}: the last Test per route; dropped when it changes
MULLVAD_FALLBACK = "se"   # prefilled for a new Mullvad route
DEFAULT = {"routes": [], "next": 1, "posture": DIRECT, "inventory": DIRECT, "cve": DIRECT, "doh": DOH}
LEGACY_DEFAULT = {"route": "direct", "posture": True, "inventory": False, "cve": False, "doh": DOH,
                  **{k: v for k, v in ROUTE_DEFAULT.items() if k not in ("id", "name", "kind")}}
TIMEOUT = 5.0   # seconds, handshake test and pre-flight check

_NAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                   r"[A-Za-z0-9])?)*$")
_ROUTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$")
_CRED = re.compile(r"^[!-~]{1,255}$")   # printable ASCII, no spaces: proxychains splits its line on whitespace
_DOH = re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,200})?$")
_CC = re.compile(r"^[a-z]{2}$")
_CITY = re.compile(r"^[a-z]{3}$")


class ProxyError(RuntimeError):
    """The route cannot be used (unresolvable, unreachable, refused the handshake, no relay, private target)."""


# ---- settings ----

def legacy(raw: dict) -> dict:
    """The single-route settings of earlier builds, with their defaults."""
    raw = dict(raw)
    if "route" not in raw and raw:   # saved before routes: on/off for the custom proxy, posture only
        raw["route"] = "custom" if raw.get("enabled") else "direct"
        raw["posture"] = True
    raw.pop("enabled", None)
    return {**LEGACY_DEFAULT, **raw}


def migrate(raw: dict) -> dict:
    """Named-route settings from the single-route ones: the route becomes one named route (named after its kind), its
    tick boxes the defaults. A custom proxy filled in but not in use is kept as a route nothing uses."""
    old = legacy(raw)
    cfg = {**DEFAULT, "routes": [], "doh": old["doh"]}
    kind = old["route"] if old["route"] in KINDS else "custom" if old["host"] else ""
    if not kind:
        return cfg
    r = {**ROUTE_DEFAULT, **{k: old[k] for k in ROUTE_DEFAULT if k in old}, "id": "r1", "name": KINDS[kind],
         "kind": kind}
    cfg.update(routes=[r], next=2)
    if old["route"] == kind:
        cfg["posture"] = r["id"] if old["posture"] else DIRECT
        cfg["inventory"] = r["id"] if old["inventory"] else DIRECT
        cfg["cve"] = r["id"] if old["posture"] and old["cve"] else DIRECT   # look-ups went with the posture hop
    return cfg


def get(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, KEY)
    if raw is None:
        return migrate(json.loads(admin.kv_get(conn, LEGACY_KEY) or "{}"))
    cfg = {**DEFAULT, **json.loads(raw)}
    cfg["routes"] = [{**ROUTE_DEFAULT, **r} for r in cfg["routes"]]
    return cfg


def put(conn: sqlite3.Connection, cfg: dict) -> None:
    admin.kv_set(conn, KEY, json.dumps(cfg))


def find(cfg: dict, rid: str) -> dict | None:
    return next((r for r in cfg["routes"] if r["id"] == rid), None)


def pick(cfg: dict, rid: str = "", use: str = "posture") -> dict | None:
    """The route a scan takes: rid '' = the shared choice for `use`, 'direct' or a route id. None = direct. A route
    that no longer exists is a ProxyError (fail closed)."""
    rid = rid or cfg[use]
    if rid == DIRECT:
        return None
    if r := find(cfg, rid):
        if not r.get("enabled", True):
            raise ProxyError(f"the scan route {r['name']} is disabled (Settings · Routes)")
        return r
    raise ProxyError("the scan route no longer exists (Settings · Routes)")


def warning(r: dict | None, test: dict | None = None) -> str:
    """Why a route should not be picked ('' = fine): disabled, or its last Test failed."""
    if not r:
        return ""
    if not r.get("enabled", True):
        return "disabled"
    if test and not test.get("ok"):
        return "last test failed"
    return ""


def names(cfg: dict, tests: dict | None = None) -> dict[str, str]:
    """Display names by route id, for pickers and lists ('' = Default); a disabled or failed route says so."""
    def name(r: dict | None) -> str:
        if not r:
            return "Direct"
        w = warning(r, (tests or {}).get(r["id"]))
        return f"{r['name']} ({w})" if w else r["name"]
    return {"": f"Default ({name(find(cfg, cfg['posture']))})", DIRECT: "Direct",
            **{r["id"]: name(r) for r in cfg["routes"]}}


def label(cfg: dict, rid: str = "", use: str = "posture") -> str:
    """How a scan on this route goes out ('' = direct), for a page."""
    try:
        return describe(pick(cfg, rid, use), use == "inventory")
    except ProxyError:
        r = find(cfg, rid or cfg[use])
        return f"{r['name']} (disabled: scans fail)" if r else "a deleted route (scans fail)"


def public(cfg: dict) -> dict:
    """The settings for a page: no password, only whether one is saved."""
    return {**cfg, "routes": [public_route(r) for r in cfg["routes"]]}


def public_route(r: dict) -> dict:
    return {**{k: v for k, v in r.items() if k != "password"}, "password_saved": bool(r.get("password"))}


def in_use(conn: sqlite3.Connection, cfg: dict, rid: str) -> list[str]:
    """What uses a route: the shared choices, then scan profiles by name."""
    got = [name for use, name in USES.items() if cfg[use] == rid]
    got += [f"scan profile {r[0]}" for r in conn.execute(
        "SELECT name FROM posture_profiles WHERE route = ? ORDER BY name", (rid,))]
    return got


def _host(value: str, label: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _NAME.match(value):
            raise ValueError(f"{label}: an IP address or a host name (no scheme, port or spaces).") from None
    return value


def _port(value: str | None, label: str) -> int:
    try:
        port = int((value or "").strip())
    except ValueError:
        port = 0
    if not 1 <= port <= 65535:
        raise ValueError(f"{label}: a whole number 1-65535.")
    return port


def _https_ok(r: dict | None) -> bool:
    return not (r and r["kind"] == "custom" and r["type"] == "socks4")


def check_route(form: dict[str, str], cfg: dict, countries: set[str] | None = None) -> dict:
    """Validate the route form (a new route when id is blank) into a route; raises ValueError with a message for the
    user. Only the chosen kind's fields are read. A blank password keeps the saved one, unless clear_password is
    ticked. countries: the Mullvad country codes of the cached relay list (None: not checked)."""
    rid = (form.get("id") or "").strip()
    old = find(cfg, rid) if rid else None
    if rid and not old:
        raise ValueError("That route no longer exists.")
    name = " ".join((form.get("name") or "").split())
    if not _ROUTE_NAME.match(name) or name.lower() in (DIRECT, "default"):
        raise ValueError("Name: 1-40 letters, digits, spaces or . _ ( ) -; not Direct or Default.")
    if any(r["name"].lower() == name.lower() and r["id"] != rid for r in cfg["routes"]):
        raise ValueError(f"There is a route named {name} already.")
    kind = (form.get("kind") or "").strip()
    if kind not in KINDS:
        raise ValueError("Kind: custom proxy, Tor or Mullvad.")
    # the page's form says whether the Enabled box was shown (an unticked box is not sent); else keep it as it was
    enabled = form.get("enabled") == "on" if "enabled_shown" in form else bool(old.get("enabled", True)) if old \
        else True
    r = {**ROUTE_DEFAULT, "id": rid or f"r{cfg['next']}", "name": name, "kind": kind, "enabled": enabled}
    if kind == "custom":
        typ = (form.get("type") or "").strip()
        host = (form.get("host") or "").strip()
        user = (form.get("username") or "").strip()
        pw = form.get("password") or ""
        if typ not in TYPES:
            raise ValueError(f"Type: one of {', '.join(TYPES)}.")
        if not host:
            raise ValueError("Give the proxy's host.")
        _host(host, "Host")
        port = _port(form.get("port"), "Port")
        if user and not _CRED.match(user):
            raise ValueError("User name: up to 255 printable characters, no spaces.")
        if pw and not _CRED.match(pw):
            raise ValueError("Password: up to 255 printable characters, no spaces.")
        if not pw and form.get("clear_password") != "on" and old:
            pw = old.get("password", "")
        if pw and not user:
            raise ValueError("A password needs a user name.")
        r.update(type=typ, host=host, port=port, username=user, password=pw)
        uses = [USES[u] for u in ("inventory", "cve") if cfg[u] == r["id"]]
        if typ == "socks4" and uses:
            raise ValueError(f"A socks4 proxy can't carry HTTPS look-ups ({' and '.join(uses)} use this route): use "
                             "socks5 or http.")
    elif kind == "tor":
        r.update(tor_host=_host((form.get("tor_host") or ROUTE_DEFAULT["tor_host"]).strip(), "Tor address"),
                 tor_port=_port(form.get("tor_port") or str(ROUTE_DEFAULT["tor_port"]), "Tor port"))
    else:
        mode = (form.get("mullvad_mode") or "auto").strip()
        country, city, fallback = ((form.get(k) or "").strip().lower()
                                   for k in ("mullvad_country", "mullvad_city", "mullvad_fallback"))
        if mode not in mullvad.MODES:
            raise ValueError("Mullvad mode: follow host, fixed or automatic.")
        for what, cc in (("Mullvad country", country), ("Fallback country", fallback)):
            if cc and (not _CC.match(cc) or (countries is not None and cc not in countries)):
                raise ValueError(f"{what}: a country from the Mullvad relay list.")
        if city and not _CITY.match(city):
            raise ValueError("Mullvad city: a city from the Mullvad relay list.")
        if mode == "fixed" and not country:
            raise ValueError("Pick the Mullvad country for the fixed mode.")
        r.update(mullvad_mode=mode, mullvad_country=country, mullvad_city=city if country else "",
                 mullvad_fallback=fallback)
    return r


def _countries(conn: sqlite3.Connection) -> set[str] | None:
    return {c for c, _, _ in mullvad.countries(mullvad.load(conn)[0])} or None


def save_route(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    """Add or change one route (raises ValueError)."""
    cfg = get(conn)
    r = check_route(form, cfg, _countries(conn))
    if old := find(cfg, r["id"]):
        cfg["routes"][cfg["routes"].index(old)] = r
        if {**old, "name": "", "enabled": True} != {**r, "name": "", "enabled": True}:
            forget_test(conn, r["id"])   # changed settings: the last Test no longer says anything
    else:
        cfg["routes"].append(r)
        cfg["next"] += 1
        forget_test(conn, r["id"])
    put(conn, cfg)
    return r


def set_enabled(conn: sqlite3.Connection, rid: str, on: bool) -> dict | None:
    """Turn a route on or off (off: scans on it fail closed); None when it no longer exists."""
    cfg = get(conn)
    if not (r := find(cfg, rid)):
        return None
    r["enabled"] = on
    put(conn, cfg)
    return r


# ---- last Test per route ----

def tests(conn: sqlite3.Connection) -> dict[str, dict]:
    return json.loads(admin.kv_get(conn, TESTS_KEY) or "{}")


def record_test(conn: sqlite3.Connection, rid: str, ok: bool, message: str) -> None:
    got = tests(conn)
    got[rid] = {"at": db.now(), "ok": ok, "message": message[:300]}
    admin.kv_set(conn, TESTS_KEY, json.dumps(got))


def forget_test(conn: sqlite3.Connection, rid: str) -> None:
    got = tests(conn)
    if got.pop(rid, None) is not None:
        admin.kv_set(conn, TESTS_KEY, json.dumps(got))


def delete_route(conn: sqlite3.Connection, rid: str) -> str:
    """Remove a route nothing uses; returns the reason when it can't ('' = removed)."""
    cfg = get(conn)
    r = find(cfg, rid)
    if not r:
        return "That route no longer exists."
    if uses := in_use(conn, cfg, rid):
        return f"{r['name']} is in use ({', '.join(uses)}): pick another route there first."
    cfg["routes"].remove(r)
    put(conn, cfg)
    forget_test(conn, rid)
    return ""


def check_shared(form: dict[str, str], cfg: dict) -> dict:
    """Validate the shared choices (default posture route, inventory route, CVE look-up route, DoH server) into new
    settings; raises ValueError. A choice missing from the form stays as it is."""
    out = dict(cfg)
    ids = {r["id"] for r in cfg["routes"]} | {DIRECT}
    for use in USES:
        if use not in form:
            continue
        rid = (form.get(use) or DIRECT).strip()
        if rid not in ids:
            raise ValueError(f"Route for {USES[use]}: pick one from the list.")
        if use != "posture" and not _https_ok(find(cfg, rid)):
            raise ValueError(f"A socks4 proxy can't carry HTTPS look-ups ({USES[use]}): use socks5 or http.")
        out[use] = rid
    doh = (form.get("doh") or DOH).strip()
    if not _DOH.match(doh):
        raise ValueError("DoH server: an https:// URL (https://dns.quad9.net/dns-query).")
    out["doh"] = doh
    return out


def _addr(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def route(cfg: dict | None) -> str:
    """A hop's label ('Office: socks5 192.0.2.10:1080', 'Tor: tor 127.0.0.1:9050', 'Mullvad: mullvad
    se-got-wg-socks5-001 (se, follow host)'), '' when there is none. Never the credentials."""
    if not cfg or not cfg.get("enabled"):
        return ""
    return cfg.get("label") or f"{cfg['type']} {_addr(cfg['host'])}:{cfg['port']}"


def details(r: dict, inventory: bool = False) -> str:
    """A route's settings in a few words, never the credentials."""
    k = r["kind"]
    if k == "custom":
        return f"{r['type']} {_addr(r['host'])}:{r['port']}"
    if k == "tor":
        return f"tor {_addr(r['tor_host'])}:{r['tor_port']}"
    mode = r.get("mullvad_mode", "auto")
    if mode == "fixed":
        where = r["mullvad_country"] + (f"-{r['mullvad_city']}" if r.get("mullvad_city") else "")
        return f"mullvad, fixed {where}"
    fb = f" (fallback {r['mullvad_fallback']})" if r.get("mullvad_fallback") else ""
    if inventory:   # a domain has no single country: the fallback country, or any relay
        return f"mullvad, {r['mullvad_fallback']}" if fb else ("mullvad, any country" if mode == "auto" else
                                                               "mullvad, follow host (no fallback: fails)")
    return f"mullvad, {mullvad.MODE_NAMES[mode]}{fb}"


def describe(r: dict | None, inventory: bool = False) -> str:
    """'<route name>: <details>'; '' for direct."""
    return f"{r['name']}: {details(r, inventory)}" if r else ""


def state_line(cfg: dict) -> str:
    return " · ".join(f"{name}: {label(cfg, '', use) or 'direct'}" for name, use in (
        ("Posture scans (default)", "posture"), ("Inventory jobs", "inventory"), ("CVE look-ups", "cve")))


def _hop(kind: str, host: str, port: int, label: str, user: str = "", pw: str = "") -> dict:
    return {"enabled": True, "type": kind, "host": host, "port": int(port), "username": user, "password": pw,
            "cve": False, "label": label}


def public_address(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def hop(conn: sqlite3.Connection, r: dict | None, ip: str = "", country: str = "",
        client: httpx.Client | None = None, rng: random.Random | None = None) -> dict | None:
    """The hop one scan takes on route r (None = direct, gives None). ip and country: the target (a posture scan);
    blank for an inventory job or a look-up. Raises ProxyError when the route can't carry it (private target through
    Tor or Mullvad, no Mullvad relay)."""
    if not r:
        return None
    k, name = r["kind"], r["name"]
    if k == "custom":
        return _hop(r["type"], r["host"], r["port"], f"{name}: {details(r)}", r.get("username", ""),
                    r.get("password", ""))
    if ip and not public_address(ip):
        raise ProxyError(f"private address can't go through {KINDS[k]}")
    if k == "tor":
        return _hop("socks5", r["tor_host"], r["tor_port"], f"{name}: {details(r)}")
    try:
        relays = mullvad.relays(conn, client)
        cc = mullvad.country_code(conn, ip, country) if ip else ""
        relay, how = mullvad.choose(r, relays, cc, rng)
    except mullvad.MullvadError as exc:
        raise ProxyError(str(exc)) from None
    short = relay["socks_name"].split(".")[0]
    return _hop("socks5", relay["socks_name"], relay["socks_port"],
                f"{name}: mullvad {short} ({relay['country_code']}, {how})")


NO_LOOKUPS = {"enabled": True, "cve": True, "type": "none"}   # cve_client: local database only, never direct


def cve_hop(conn: sqlite3.Connection, cfg: dict, scan_route: dict | None = None, scan_hop: dict | None = None,
            client: httpx.Client | None = None) -> dict | None:
    """The hop for CVE look-ups (None = direct): the scan's own hop when the CVE route is the scan's route (the same
    relay), else the CVE route resolved without a target. A route that can't be used gives NO_LOOKUPS."""
    if cfg["cve"] == DIRECT:
        return None
    if scan_route and scan_route["id"] == cfg["cve"]:
        return {**scan_hop, "cve": True} if scan_hop else NO_LOOKUPS
    try:
        h = hop(conn, pick(cfg, "", "cve"), client=client)
    except ProxyError:
        return NO_LOOKUPS
    return {**h, "cve": True} if h else None


MULLVAD_SUFFIX = ".relays.mullvad.net"
MULLVAD_DNS = "10.64.0.1"   # Mullvad's resolver, reachable only inside the tunnel


def mullvad_dns(host: str) -> list[str]:
    """A relay name's A records from Mullvad's in-tunnel resolver; [] when the tunnel or the name is missing."""
    import dns.exception
    import dns.resolver
    r = dns.resolver.Resolver(configure=False)
    r.nameservers, r.lifetime = [MULLVAD_DNS], 4.0
    try:
        return [a.to_text() for a in r.resolve(host, "A")]
    except (dns.exception.DNSException, OSError):
        return []


def resolve(host: str) -> str:
    """The proxy's numeric address (proxychains needs one); IPv4 first."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError:
        infos = []
    ips = [str(i[4][0]) for i in infos]
    if not ips and host.lower().endswith(MULLVAD_SUFFIX):
        ips = mullvad_dns(host)   # hosts without public DNS: ask Mullvad's resolver inside the tunnel
    if not ips:
        raise ProxyError(f"the proxy host {host} does not resolve")
    return next((ip for ip in ips if ":" not in ip), ips[0])


def conf(cfg: dict, ip: str) -> str:
    """A proxychains4 config for one run: one proxy, strict chain, DNS through the proxy."""
    line = f"{cfg['type']} {ip} {cfg['port']}"
    if cfg.get("username"):
        line += f" {cfg['username']} {cfg.get('password') or ''}".rstrip()
    return ("strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n\n"
            f"[ProxyList]\n{line}\n")


def _recv(s: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise ProxyError("the proxy closed the connection")
        data += chunk
    return data


def handshake(cfg: dict, timeout: float = TIMEOUT) -> str:
    """Connect to the proxy and complete its greeting (SOCKS5: methods + user/password auth; SOCKS4 and http: the
    TCP connect). No request to any target. Returns a one-line result; raises ProxyError."""
    ip = resolve(cfg["host"])
    try:
        with socket.create_connection((ip, int(cfg["port"])), timeout=timeout) as s:
            if cfg["type"] != "socks5":
                return f"TCP connect to {ip}:{cfg['port']} OK"
            user, pw = (cfg.get("username") or "").encode(), (cfg.get("password") or "").encode()
            s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
            ver, method = _recv(s, 2)
            if ver != 5:
                raise ProxyError("not a SOCKS5 proxy (wrong reply version)")
            if method == 0xFF:
                raise ProxyError("the proxy accepts none of the offered methods (it may need a user name)")
            if method == 2:
                s.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
                if _recv(s, 2)[1] != 0:
                    raise ProxyError("the proxy refused the user name or password")
                return f"SOCKS5 at {ip}:{cfg['port']} accepted the user name and password"
            if method != 0:
                raise ProxyError(f"the proxy picked an unsupported method ({method})")
            return f"SOCKS5 at {ip}:{cfg['port']} OK (no authentication)"
    except OSError as exc:
        raise ProxyError(f"cannot reach the proxy at {ip}:{cfg['port']}: {exc.strerror or exc}") from None


def greet_target(r: dict) -> dict:
    """What the Test button greets for a custom or Tor route."""
    if r["kind"] == "tor":
        return {"type": "socks5", "host": r["tor_host"], "port": r["tor_port"]}
    return r


def tunnel_state(timeout: float = 1.5) -> tuple[bool, str]:
    """Whether Mullvad's in-tunnel SOCKS5 (10.64.0.1:1080) answers a handshake: the tunnel is up."""
    host, port = mullvad.IN_TUNNEL
    ok, msg = probe(host, port, timeout, fresh=True)
    return (True, f"Mullvad tunnel up (SOCKS5 at {host}:{port} answers)") if ok else \
        (False, f"Mullvad tunnel down ({msg})")


# ---- this host: what each kind of route needs (the "This host" card) ----

PROBE_TTL = 30.0   # seconds a socket probe is reused, so the page stays quick
_probes: dict[tuple[str, int], tuple[float, bool, str]] = {}


def probe(host: str, port: int, timeout: float = 1.0, fresh: bool = False) -> tuple[bool, str]:
    """A SOCKS5 greeting at host:port, cached PROBE_TTL seconds: (answers, one line). No request to any target."""
    key = (host, int(port))
    got = _probes.get(key)
    if got and not fresh and time.monotonic() - got[0] < PROBE_TTL:
        return got[1], got[2]
    try:
        ok, msg = True, handshake({"type": "socks5", "host": host, "port": port}, timeout)
    except ProxyError as exc:
        ok, msg = False, str(exc)
    _probes[key] = (time.monotonic(), ok, msg)
    return ok, msg


def host_check(conn: sqlite3.Connection, state_dir: Path) -> dict:
    """What this host can do: proxychains4 and wireguard-tools installed (a PATH look-up, nothing is run), the tor
    client's SOCKS5 answering, the Mullvad tunnel (the root script's status file, and the in-tunnel SOCKS5 answering)
    and the relay list's age. The web app never runs wg: the tunnel facts come from the status file."""
    cfg = get(conn)
    tor = next((r for r in cfg["routes"] if r["kind"] == "tor"), ROUTE_DEFAULT)
    tor_ok, tor_msg = probe(tor["tor_host"], tor["tor_port"])
    status = mullvad.apply_status(state_dir)
    facts = status.get("tunnel") or {}
    wanted = bool(facts.get("up") or any(r["kind"] == "mullvad" for r in cfg["routes"])
                  or any(mullvad.get_tunnel(conn).values()))
    socks_ok = wanted and probe(*mullvad.IN_TUNNEL, timeout=1.5)[0]
    relays, fetched = mullvad.load(conn)
    a = mullvad.age(fetched)
    return {"proxychains": bool(shutil.which("proxychains4")),
            "tor": {"addr": f"{_addr(tor['tor_host'])}:{tor['tor_port']}", "ok": tor_ok, "message": tor_msg},
            "wg": bool(shutil.which("wg") or facts.get("wg")),
            "tunnel": mullvad.tunnel_summary(status, socks_ok),
            "relays": {"count": len(relays), "age": f"{int(a.total_seconds() // 3600)} h" if a is not None else "",
                       "stale": a is None or a > mullvad.MAX_AGE},
            "apply": status}


def kinds(cap: dict, current: str = "") -> list[dict]:
    """The kind choices for the route form: {value, name, ok (selectable), label (the option's text), note}. Mullvad
    is selectable only while the tunnel is up, or when the route being changed is a Mullvad route already. state: the
    pill (ok, warn: works but proxychains4 is missing for posture scans, bad: does not work here)."""
    tor, tun = cap["tor"], cap["tunnel"]
    out = [
        {"value": "custom", "name": KINDS["custom"], "ok": True, "label": KINDS["custom"],
         "note": "a SOCKS5, SOCKS4 or HTTP proxy you run"},
        {"value": "tor", "name": KINDS["tor"], "ok": True,
         "label": KINDS["tor"] + ("" if tor["ok"] else " (not reachable)"),
         "note": f"the local tor client at {tor['addr']} answers" if tor["ok"] else
                 f"not reachable: no tor SOCKS5 answers at {tor['addr']} (apt install tor, or change the address "
                 "below)"},
        {"value": "mullvad", "name": KINDS["mullvad"], "ok": tun["ok"] or current == "mullvad",
         "label": KINDS["mullvad"] + ("" if tun["ok"] else " (unavailable: tunnel not up)"),
         "note": "the Mullvad tunnel is up" if tun["ok"] else
                 "unavailable until the Mullvad tunnel is up (This host, and Mullvad tunnel below)"},
    ]
    for k, works in zip(out, (True, tor["ok"], tun["ok"]), strict=True):
        k["state"] = "bad" if not works else "ok" if cap["proxychains"] else "warn"
    return out


def http_proxy(cfg: dict) -> httpx.Proxy:
    """The hop as an httpx proxy (http or socks5; the target's name is resolved by the proxy)."""
    if cfg["type"] not in ("http", "socks5"):
        raise ProxyError(f"a {cfg['type']} proxy can't carry HTTPS look-ups")
    auth = (cfg["username"], cfg.get("password") or "") if cfg.get("username") else None
    return httpx.Proxy(f"{cfg['type']}://{_addr(cfg['host'])}:{cfg['port']}", auth=auth)


cve_proxy = http_proxy


@contextmanager
def cve_client(cfg: dict | None, default: httpx.Client | None) -> Iterator[httpx.Client | None]:
    """The client for CVE look-ups: `default` unless the hop is on with look-ups through it (cve_hop); then a client
    via the hop (closed afterwards). A hop that can't carry them (socks4, NO_LOOKUPS) gives None (local database
    only), never a direct client."""
    if not (cfg and cfg.get("enabled") and cfg.get("cve")):
        yield default
        return
    try:
        p = http_proxy(cfg)
    except ProxyError:
        yield None
        return
    client = tools.http_client(proxy=p)
    try:
        yield client
    finally:
        client.close()
