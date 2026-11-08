"""Scan routes: how posture scans and inventory jobs reach the internet (Settings · Scan settings).

Routes: direct, a custom proxy (socks5 / socks4 / http), Tor (the local tor client's SOCKS5) or Mullvad (a relay's
SOCKS5 inside the host's Mullvad tunnel, chosen per target: mullvad.py). Tick boxes pick which jobs use the route.

Posture scans: nmap runs under proxychains4 with a per-run config file (:func:`conf`), so the connect scan and the
version probes both leave through the hop. nmap's own ``--proxies`` covers version detection and NSE only, so it is
not used. Inventory jobs: HTTP look-ups through httpx with the hop as proxy, DNS over DoH through the same client
(scanner.py). Internal zones always stay direct. Fail closed: a scan that cannot use its route fails with the
reason, never a direct scan. Tor and Mullvad never carry a private target.

A hop is one resolved proxy for one scan: {enabled, type, host, port, username, password, cve, label}. The settings
live as JSON in the kv table; the custom proxy's password is stored in plain text there (the database is readable by
the service user only) and never rendered back.
"""
from __future__ import annotations

import ipaddress
import json
import random
import re
import socket
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

import httpx

from . import admin, mullvad, tools

KEY = "scan_proxy"
TYPES = ("socks5", "socks4", "http")
ROUTES = ("direct", "custom", "tor", "mullvad")
ROUTE_NAMES = {"direct": "direct", "custom": "custom proxy", "tor": "Tor", "mullvad": "Mullvad"}
JOBS = {"posture": "Posture scans", "inventory": "Inventory jobs"}
DOH = "https://dns.quad9.net/dns-query"
DEFAULT = {"route": "direct", "posture": True, "inventory": False,
           "type": "socks5", "host": "", "port": 1080, "username": "", "password": "", "cve": False,
           "tor_host": "127.0.0.1", "tor_port": 9050,
           "mullvad_mode": "auto", "mullvad_country": "", "mullvad_city": "", "mullvad_fallback": "", "doh": DOH}
TIMEOUT = 5.0   # seconds, handshake test and pre-flight check

_NAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                   r"[A-Za-z0-9])?)*$")
_CRED = re.compile(r"^[!-~]{1,255}$")   # printable ASCII, no spaces: proxychains splits its line on whitespace
_DOH = re.compile(r"^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]{0,200})?$")
_CC = re.compile(r"^[a-z]{2}$")
_CITY = re.compile(r"^[a-z]{3}$")


class ProxyError(RuntimeError):
    """The route cannot be used (unresolvable, unreachable, refused the handshake, no relay, private target)."""


def get(conn: sqlite3.Connection) -> dict:
    raw = json.loads(admin.kv_get(conn, KEY) or "{}")
    if "route" not in raw and raw:   # settings saved before routes: on/off for the custom proxy, posture only
        raw["route"] = "custom" if raw.get("enabled") else "direct"
        raw["posture"] = True
    raw.pop("enabled", None)
    return {**DEFAULT, **raw}


def public(cfg: dict) -> dict:
    """The settings for a page: no password, only whether one is saved."""
    return {**{k: v for k, v in cfg.items() if k != "password"}, "password_saved": bool(cfg.get("password"))}


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


def check(form: dict[str, str], old: dict, countries: set[str] | None = None) -> dict:
    """Validate the settings form into a config; raises ValueError with a message for the user. A blank password
    keeps the saved one, unless clear_password is ticked. countries: the Mullvad country codes of the cached relay
    list (None: not checked)."""
    route = (form.get("route") or "direct").strip()
    kind = (form.get("type") or "").strip()
    host = (form.get("host") or "").strip()
    user = (form.get("username") or "").strip()
    pw = form.get("password") or ""
    if route not in ROUTES:
        raise ValueError(f"Route: one of {', '.join(ROUTES)}.")
    if kind not in TYPES:
        raise ValueError(f"Type: one of {', '.join(TYPES)}.")
    if host:
        _host(host, "Host")
    elif route == "custom":
        raise ValueError("Give the proxy's host to use the custom proxy.")
    port = _port(form.get("port"), "Port")
    if user and not _CRED.match(user):
        raise ValueError("User name: up to 255 printable characters, no spaces.")
    if pw and not _CRED.match(pw):
        raise ValueError("Password: up to 255 printable characters, no spaces.")
    if not pw and form.get("clear_password") != "on":
        pw = old.get("password", "")
    if pw and not user:
        raise ValueError("A password needs a user name.")
    posture, inventory, cve = (form.get(k) == "on" for k in ("posture", "inventory", "cve"))
    if route == "custom" and kind == "socks4" and (cve or inventory):
        raise ValueError("A socks4 proxy can't carry HTTPS look-ups (CVE look-ups, inventory jobs): use socks5 or "
                         "http.")
    tor_host = _host((form.get("tor_host") or DEFAULT["tor_host"]).strip(), "Tor address")
    tor_port = _port(form.get("tor_port") or str(DEFAULT["tor_port"]), "Tor port")
    mode = (form.get("mullvad_mode") or "auto").strip()
    country, city, fallback = ((form.get(k) or "").strip().lower()
                               for k in ("mullvad_country", "mullvad_city", "mullvad_fallback"))
    if mode not in mullvad.MODES:
        raise ValueError("Mullvad mode: follow host, fixed or automatic.")
    for label, cc in (("Mullvad country", country), ("Fallback country", fallback)):
        if cc and (not _CC.match(cc) or (countries is not None and cc not in countries)):
            raise ValueError(f"{label}: a country from the Mullvad relay list.")
    if city and not _CITY.match(city):
        raise ValueError("Mullvad city: a city from the Mullvad relay list.")
    if route == "mullvad" and mode == "fixed" and not country:
        raise ValueError("Pick the Mullvad country for the fixed mode.")
    doh = (form.get("doh") or DOH).strip()
    if not _DOH.match(doh):
        raise ValueError("DoH server: an https:// URL (https://dns.quad9.net/dns-query).")
    return {"route": route, "posture": posture, "inventory": inventory, "type": kind, "host": host, "port": port,
            "username": user, "password": pw, "cve": cve, "tor_host": tor_host, "tor_port": tor_port,
            "mullvad_mode": mode, "mullvad_country": country, "mullvad_city": city if country else "",
            "mullvad_fallback": fallback, "doh": doh}


def save(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    cfg = check(form, get(conn), {c for c, _, _ in mullvad.countries(mullvad.load(conn)[0])} or None)
    admin.kv_set(conn, KEY, json.dumps(cfg))
    return cfg


def _addr(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def route(cfg: dict | None) -> str:
    """A hop's label ('socks5 192.0.2.10:1080', 'tor 127.0.0.1:9050', 'mullvad se-got-wg-socks5-001 (se, follow
    host)'), '' when there is none. Never the credentials."""
    if not cfg or not cfg.get("enabled"):
        return ""
    return cfg.get("label") or f"{cfg['type']} {_addr(cfg['host'])}:{cfg['port']}"


def describe(cfg: dict, job: str) -> str:
    """How a job type goes out under these settings ('' = direct)."""
    r = cfg.get("route", "direct")
    if r == "direct" or not cfg.get(job):
        return ""
    if r == "custom":
        return f"{cfg['type']} {_addr(cfg['host'])}:{cfg['port']}"
    if r == "tor":
        return f"Tor {_addr(cfg['tor_host'])}:{cfg['tor_port']}"
    mode = cfg.get("mullvad_mode", "auto")
    if mode == "fixed":
        where = cfg["mullvad_country"] + (f"-{cfg['mullvad_city']}" if cfg.get("mullvad_city") else "")
        return f"Mullvad, fixed {where}"
    fb = f" (fallback {cfg['mullvad_fallback']})" if cfg.get("mullvad_fallback") else ""
    if job == "inventory":   # a domain has no single country: the fallback country, or any relay
        return f"Mullvad, {cfg['mullvad_fallback']}" if fb else ("Mullvad, any country" if mode == "auto" else
                                                                 "Mullvad, follow host (no fallback: fails)")
    return f"Mullvad, {mullvad.MODE_NAMES[mode]}{fb}"


def state_line(cfg: dict) -> str:
    return " · ".join(f"{name}: {describe(cfg, job) or 'direct'}" for job, name in JOBS.items())


def _hop(cfg: dict, kind: str, host: str, port: int, label: str, user: str = "", pw: str = "") -> dict:
    return {"enabled": True, "type": kind, "host": host, "port": int(port), "username": user, "password": pw,
            "cve": bool(cfg.get("cve")), "label": label}


def public_address(ip: str) -> bool:
    return ipaddress.ip_address(ip).is_global


def hop(conn: sqlite3.Connection, cfg: dict, job: str, ip: str = "", country: str = "",
        client: httpx.Client | None = None, rng: random.Random | None = None) -> dict | None:
    """The hop one scan uses: None = direct. job: 'posture' (ip and country: the target) or 'inventory'. Raises
    ProxyError when the route can't carry it (private target through Tor or Mullvad, no Mullvad relay)."""
    r = cfg.get("route", "direct")
    if r == "direct" or not cfg.get(job):
        return None
    if r == "custom":
        return _hop(cfg, cfg["type"], cfg["host"], cfg["port"], "", cfg.get("username", ""), cfg.get("password", ""))
    if ip and not public_address(ip):
        raise ProxyError(f"private address can't go through {ROUTE_NAMES[r]}")
    if r == "tor":
        return _hop(cfg, "socks5", cfg["tor_host"], cfg["tor_port"],
                    f"tor {_addr(cfg['tor_host'])}:{cfg['tor_port']}")
    try:
        relays = mullvad.relays(conn, client)
        cc = mullvad.country_code(conn, ip, country) if ip else ""
        relay, how = mullvad.choose(cfg, relays, cc, rng)
    except mullvad.MullvadError as exc:
        raise ProxyError(str(exc)) from None
    name = relay["socks_name"].split(".")[0]
    return _hop(cfg, "socks5", relay["socks_name"], relay["socks_port"],
                f"mullvad {name} ({relay['country_code']}, {how})")


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


def tunnel_state(timeout: float = 1.5) -> tuple[bool, str]:
    """Whether Mullvad's in-tunnel SOCKS5 (10.64.0.1:1080) answers a handshake: the tunnel is up."""
    host, port = mullvad.IN_TUNNEL
    try:
        handshake({"type": "socks5", "host": host, "port": port}, timeout)
        return True, f"Mullvad tunnel up (SOCKS5 at {host}:{port} answers)"
    except ProxyError as exc:
        return False, f"Mullvad tunnel down ({exc})"


def http_proxy(cfg: dict) -> httpx.Proxy:
    """The hop as an httpx proxy (http or socks5; the target's name is resolved by the proxy)."""
    if cfg["type"] not in ("http", "socks5"):
        raise ProxyError(f"a {cfg['type']} proxy can't carry HTTPS look-ups")
    auth = (cfg["username"], cfg.get("password") or "") if cfg.get("username") else None
    return httpx.Proxy(f"{cfg['type']}://{_addr(cfg['host'])}:{cfg['port']}", auth=auth)


cve_proxy = http_proxy


@contextmanager
def cve_client(cfg: dict | None, default: httpx.Client | None) -> Iterator[httpx.Client | None]:
    """The client for CVE look-ups: `default` unless the hop is on with look-ups through it; then a client via the
    hop (closed afterwards). A hop that can't carry them (socks4) gives None (local database only), never a direct
    client."""
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
