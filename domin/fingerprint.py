"""Host fingerprinting for the security posture engine.

A TCP connect scan (nmap ``-sT -sV``) of an authorised target: the open ports, the service
and version nmap recognises, and the CPEs it reports. No raw-socket scan and no OS detection
(``-O``), so it needs no extra privilege or capability. The CPEs it finds feed the CVE layer
(:func:`cve.lookup`) to list the known vulnerabilities of each service version. The posture
scope (Settings) governs which addresses a scan may probe; the caller checks it before probing.

This module only speaks to the target over TCP, through the scan proxy when one is on (proxy.py).
It never reaches the internet itself; the CVE layer it calls does, through the configured source
and local database.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from . import cve, proxy

# A compact, common-service port set: web, mail, databases, remote access, caches. Keeps a scan
# quick and predictable; the form lets an analyst override it.
DEFAULT_PORTS = ("21,22,23,25,53,80,110,135,139,143,443,445,465,587,993,995,"
                 "1433,1521,2049,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,9000,9200,11211,27017")

_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,253})$")
_PORTS = re.compile(r"^[0-9]([0-9,\-]{0,398}[0-9])?$")


class NmapError(RuntimeError):
    """nmap ran but could not complete the scan."""


def valid_target(target: str) -> bool:
    """A single host name or IPv4 address (no ranges, no shell metacharacters)."""
    t = (target or "").strip()
    return bool(t) and len(t) <= 255 and bool(_HOST.match(t))


def valid_ports(ports: str) -> bool:
    return bool(_PORTS.match((ports or "").strip()))


def resolve(target: str) -> tuple[str, list[str]]:
    """Return (display name, resolved IPs). A literal IP resolves to itself; a name goes through
    the system resolver. An empty list means the name did not resolve."""
    t = (target or "").strip()
    try:
        ipaddress.ip_address(t)
        return t, [t]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(t, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return t, []
    return t, sorted({i[4][0] for i in infos})


def parse_cpe(cpe: str) -> dict | None:
    """A CPE string (2.2 ``cpe:/a:...`` or 2.3 ``cpe:2.3:a:...``) into a cve target, or None when
    it has no part/vendor/product/version to match on."""
    s = (cpe or "").strip().lower()
    if s.startswith("cpe:2.3:"):
        f = s.split(":")[2:]
    elif s.startswith("cpe:/"):
        f = s[5:].split(":")
    else:
        return None
    f = (f + ["", "", "", ""])[:4]
    part, vendor, product, version = f
    version = version.strip("*").strip()
    if part not in ("a", "o", "h") or not vendor or not product or not version or version == "-":
        return None
    return {"kind": "cpe", "part": part, "vendor": vendor, "product": product, "version": version}


# nmap's CPE dictionary keeps some vendors NVD has since renamed; newer CVEs are filed under the new name only
# (nginx 1.24.0: 0 CVEs as igor_sysoev, 2 as f5). Both names are looked up.
VENDOR_ALIASES = {("igor_sysoev", "nginx"): "f5"}


def with_aliases(target: dict) -> list[dict]:
    alias = VENDOR_ALIASES.get((target.get("vendor"), target.get("product")))
    return [target, {**target, "vendor": alias}] if alias else [target]


def nmap_args(ip: str, ports: str, timeout: int, intensity: int = 2, timing: int = 3,
              nmap_bin: str = "nmap") -> list[str]:
    """The nmap command line: connect scan only (``-sT``), no OS detection and no raw packets, so no root or
    cap_net_raw is needed. intensity is nmap's --version-intensity (0-9; 2 = --version-light), timing its -T
    template (1-4)."""
    args = [nmap_bin, "-sT", "-sV", "-Pn", "-n", "--version-intensity", str(int(intensity)), f"-T{int(timing)}",
            "-oX", "-", "-p", str(ports), "--host-timeout", f"{timeout}s", ip]
    if ":" in ip:
        args.insert(1, "-6")
    return args


def run_nmap(ip: str, ports: str, timeout: int, nmap_bin: str = "nmap", intensity: int = 2, timing: int = 3,
             via: dict | None = None) -> str:
    """Run a connect + service-version scan and return the XML. via: the scan proxy settings when it is on; nmap
    then runs under proxychains4 with a per-run config (mode 0600, deleted afterwards). Fails closed: a missing
    proxychains4 or an unresolvable or unreachable proxy is an NmapError, never a direct scan."""
    args = nmap_args(ip, ports, timeout, intensity, timing, nmap_bin)
    if not via:
        return _run(args, timeout)
    pc = shutil.which("proxychains4")
    if not pc:
        raise NmapError("proxy enabled but proxychains4 is not installed")
    try:
        proxy.handshake(via)
        text = proxy.conf(via, proxy.resolve(via["host"]))
    except proxy.ProxyError as exc:
        raise NmapError(f"proxy {proxy.route(via)}: {exc}") from None
    fd, path = tempfile.mkstemp(prefix="domin-proxy-", suffix=".conf")   # 0600 on POSIX
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(path, 0o600)
        return _run([pc, "-q", "-f", path, *args], timeout)
    finally:
        os.unlink(path)


def _run(args: list[str], timeout: int) -> str:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout + 30)
    except subprocess.TimeoutExpired as exc:
        raise NmapError("the scan timed out") from exc
    if not p.stdout.strip():
        last = (p.stderr or "nmap produced no output").strip().splitlines()
        raise NmapError(last[-1][:200] if last else "nmap produced no output")
    return p.stdout


def parse_xml(text: str) -> list[dict]:
    """Open TCP ports with their service, version and CPEs, from nmap XML."""
    root = ET.fromstring(text)
    services: list[dict] = []
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            cpes = [c.text for c in port.findall("./service/cpe") if c.text]
            services.append({
                "port": int(port.get("portid")),
                "proto": port.get("protocol") or "tcp",
                "service": (svc.get("name") if svc is not None else "") or "",
                "product": (svc.get("product") if svc is not None else "") or "",
                "version": (svc.get("version") if svc is not None else "") or "",
                "cpes": cpes,
            })
    services.sort(key=lambda s: s["port"])
    return services


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in sorted(findings, key=lambda x: cve.rank(x["severity"], x["score"])):
        if f["cve"] not in seen:
            seen.add(f["cve"])
            out.append(f)
    return out


def scan(ip: str, *, cve_db: cve.Database, client=None, api_key: str = "", ports: str = DEFAULT_PORTS,
         timeout: int = 120, nmap_bin: str = "nmap", display: str = "", intensity: int = 2,
         timing: int = 3, via: dict | None = None) -> dict:
    """Fingerprint one host and match each service's CPEs against the CVE layer.

    Returns {target, ip, services, note, error, raw, params}. Each service carries its CPEs' findings
    (deduped, worst first) and a `matched` flag (did any CPE yield a cve target to look up). params is
    the nmap command line that ran, plus the route ("via socks5 192.0.2.10:1080") when via (the scan proxy
    settings) is on."""
    via = via if via and via.get("enabled") else None
    params = " ".join(nmap_args(ip, ports, timeout, intensity, timing, "nmap"))
    if via:
        params += f" via {proxy.route(via)}"
    try:
        xml = run_nmap(ip, ports, timeout, nmap_bin, intensity, timing, via=via)
    except FileNotFoundError:
        return {"target": display or ip, "ip": ip, "services": [], "note": "", "params": params,
                "error": "nmap is not installed on this host."}
    except NmapError as exc:
        return {"target": display or ip, "ip": ip, "services": [], "note": "", "error": str(exc), "params": params}

    services = parse_xml(xml)
    cache: dict[str, dict] = {}
    for s in services:
        targets = [a for t in (parse_cpe(c) for c in s["cpes"]) if t for a in with_aliases(t)]
        s["matched"] = bool(targets)
        findings: list[dict] = []
        for t in targets:
            key = cve.target_key(t)
            if key not in cache:
                cache[key] = cve.lookup(cve_db, t, client, api_key)
            findings.extend(cache[key]["findings"])
        s["findings"] = _dedupe(findings)
    note = "" if services else "No open TCP ports found in the scanned range."
    return {"target": display or ip, "ip": ip, "services": services, "note": note, "error": "", "raw": xml,
            "params": params}
