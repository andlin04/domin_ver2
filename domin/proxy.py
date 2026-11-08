"""Scan proxy: an admin-chosen proxy that every posture scan goes through (Posture · Scan settings).

nmap runs under proxychains4 with a per-run config file (:func:`conf`), so the connect scan and the version probes
both leave through the proxy. nmap's own ``--proxies`` covers version detection and NSE only, so it is not used.
Off = scans run directly, exactly as before. On = fail closed: a scan that cannot go through the proxy is an error,
never a direct scan.

CVE look-ups (OSV, NVD) can go through the same proxy when it is an http proxy (httpx without the socks extra).
The settings live as JSON in the kv table; the password is stored in plain text there (the database is readable by
the service user only) and never rendered back.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

import httpx

from . import admin, tools

KEY = "scan_proxy"
TYPES = ("socks5", "socks4", "http")
DEFAULT = {"enabled": False, "type": "socks5", "host": "", "port": 1080, "username": "", "password": "",
           "cve": False}
TIMEOUT = 5.0   # seconds, handshake test and pre-flight check

_NAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}"
                   r"[A-Za-z0-9])?)*$")
_CRED = re.compile(r"^[!-~]{1,255}$")   # printable ASCII, no spaces: proxychains splits its line on whitespace


class ProxyError(RuntimeError):
    """The proxy cannot be used (unresolvable, unreachable, refused the handshake)."""


def get(conn: sqlite3.Connection) -> dict:
    raw = admin.kv_get(conn, KEY)
    return {**DEFAULT, **(json.loads(raw) if raw else {})}


def public(cfg: dict) -> dict:
    """The settings for a page: no password, only whether one is saved."""
    return {**{k: v for k, v in cfg.items() if k != "password"}, "password_saved": bool(cfg.get("password"))}


def check(form: dict[str, str], old: dict) -> dict:
    """Validate the settings form into a config; raises ValueError with a message for the user. A blank password
    keeps the saved one, unless clear_password is ticked."""
    kind = (form.get("type") or "").strip()
    host = (form.get("host") or "").strip()
    user = (form.get("username") or "").strip()
    pw = form.get("password") or ""
    enabled = form.get("enabled") == "on"
    if kind not in TYPES:
        raise ValueError(f"Type: one of {', '.join(TYPES)}.")
    if host:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not _NAME.match(host):
                raise ValueError("Host: an IP address or a host name (no scheme, port or spaces).") from None
    elif enabled:
        raise ValueError("Give the proxy's host to turn it on.")
    try:
        port = int((form.get("port") or "").strip())
    except ValueError:
        raise ValueError("Port: a whole number 1-65535.") from None
    if not 1 <= port <= 65535:
        raise ValueError("Port: a whole number 1-65535.")
    if user and not _CRED.match(user):
        raise ValueError("User name: up to 255 printable characters, no spaces.")
    if pw and not _CRED.match(pw):
        raise ValueError("Password: up to 255 printable characters, no spaces.")
    if not pw and form.get("clear_password") != "on":
        pw = old.get("password", "")
    if pw and not user:
        raise ValueError("A password needs a user name.")
    cve = form.get("cve") == "on"
    if cve and kind != "http":
        raise ValueError("CVE look-ups can go through an http proxy only (socks support is not installed).")
    return {"enabled": enabled, "type": kind, "host": host, "port": port, "username": user, "password": pw,
            "cve": cve}


def save(conn: sqlite3.Connection, form: dict[str, str]) -> dict:
    cfg = check(form, get(conn))
    admin.kv_set(conn, KEY, json.dumps(cfg))
    return cfg


def route(cfg: dict | None) -> str:
    """'socks5 192.0.2.10:1080' when the proxy is on, else ''. Never the credentials."""
    if not cfg or not cfg.get("enabled"):
        return ""
    host = f"[{cfg['host']}]" if ":" in cfg["host"] else cfg["host"]
    return f"{cfg['type']} {host}:{cfg['port']}"


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


def cve_proxy(cfg: dict) -> httpx.Proxy:
    host = f"[{cfg['host']}]" if ":" in cfg["host"] else cfg["host"]
    auth = (cfg["username"], cfg.get("password") or "") if cfg.get("username") else None
    return httpx.Proxy(f"http://{host}:{cfg['port']}", auth=auth)


@contextmanager
def cve_client(cfg: dict, default: httpx.Client | None) -> Iterator[httpx.Client | None]:
    """The client for CVE look-ups: `default` unless the proxy is on with look-ups through it; then a client via
    the proxy (closed afterwards). A non-http proxy there gives None (local database only), never a direct client."""
    if not (cfg.get("enabled") and cfg.get("cve")):
        yield default
        return
    if cfg["type"] != "http":
        yield None
        return
    client = tools.http_client(proxy=cve_proxy(cfg))
    try:
        yield client
    finally:
        client.close()
