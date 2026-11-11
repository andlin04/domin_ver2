"""Which addresses the posture and fingerprint engines may probe. The app checks this itself before nmap runs; the
systemd address filter is a second line only (the web unit and a Mullvad tunnel allow localhost, and an empty posture
allow-list allows everything).

Public install: global addresses only (no loopback, private, link-local, CGNAT or other special-use range). On-prem
(DOMIN_INSTALL_MODE=internal): global addresses plus the configured internal networks (install --scan-nets and
Settings · Internal networks); loopback, unspecified and multicast addresses never."""
from __future__ import annotations

import ipaddress
import sqlite3
from collections.abc import Callable

from . import admin
from .config import Settings

Check = Callable[[str], bool]


def _addr(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        a = ipaddress.ip_address((ip or "").strip().split("%", 1)[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped:   # ::ffff:127.0.0.1 is 127.0.0.1
        return a.ipv4_mapped
    return a


def target_ok(ip: str, internal: bool = False, nets: tuple[str, ...] = ()) -> bool:
    a = _addr(ip)
    if a is None:
        return False
    if a.is_global:
        return True
    if not internal or a.is_loopback or a.is_unspecified or a.is_multicast:
        return False
    for n in nets:
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError:
            continue
        if net.version == a.version and a in net:
            return True
    return False


def checker(conn: sqlite3.Connection, settings: Settings | None = None) -> Check:
    """The check for this install: settings from the environment unless given; internal networks from Settings."""
    settings = settings or Settings.from_env()
    if not settings.internal_mode:
        return lambda ip: target_ok(ip)
    nets = tuple(settings.scan_nets) + tuple(admin.effective(settings, conn).internal_nets)
    return lambda ip: target_ok(ip, True, nets)


def refused(ips: list[str], ok: Check) -> list[str]:
    """The addresses among ips that the check refuses."""
    return [ip for ip in ips if not ok(ip)]
