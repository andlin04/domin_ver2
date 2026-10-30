"""One scan of a domain: find host names, resolve them, and look up who announces each address.

Discovery: certificate transparency (crt.sh), common host names, the domain's MX/NS hosts, and amass (passive) when
installed. Brute-forced names are dropped when the zone has wildcard DNS. Address owner and country come from RDAP
(ipwhois), cached per announced prefix and per address in the database.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import dns.exception
import dns.resolver
import httpx
import pycountry

from . import db
from .config import Settings
from .validate import is_under, normalize_domain

log = logging.getLogger("domin.scanner")

COMMON = """www mail webmail smtp imap pop autodiscover autoconfig mx mx1 mx2 ns ns1 ns2 ns3 dns vpn remote portal
login sso auth adfs owa exchange lync sip meet teams api app apps dev test stage staging beta demo shop store blog
news cdn static media img files ftp sftp git gitlab jira confluence wiki intranet extranet support help status docs
admin crm erp hr my m mobile secure web web1 web2 www2 cloud office print citrix rdweb gateway proxy""".split()

CACHE_DAYS = 30
Progress = Callable[[str], None]


def _resolver(timeout: float = 4.0) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = timeout
    return r


def resolve(host: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    resolver = resolver or _resolver()
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips += [a.to_text() for a in resolver.resolve(host, rtype)]
        except (dns.exception.DNSException, OSError):
            pass
    return sorted(set(ips))


def from_crtsh(domain: str, client: httpx.Client) -> set[str]:
    try:
        r = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=90)
        r.raise_for_status()
        names = [n for e in r.json() for n in str(e.get("name_value", "")).splitlines()]
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("crt.sh %s: %s", domain, exc)
        return set()
    # normalize_domain strips a leading www.; keep the www host itself as a candidate too
    found = {n.strip().lstrip("*.").lower().rstrip(".") for n in names}
    return {h for h in found if normalize_domain(h) and is_under(h, domain)}


def from_dns(domain: str, resolver: dns.resolver.Resolver) -> set[str]:
    found = set()
    for rtype in ("MX", "NS"):
        try:
            for a in resolver.resolve(domain, rtype):
                target = (a.exchange if rtype == "MX" else a.target).to_text().rstrip(".").lower()
                if is_under(target, domain):
                    found.add(target)
        except (dns.exception.DNSException, OSError):
            pass
    return found


def from_amass(domain: str, amass: str) -> set[str]:
    exe = shutil.which(amass) or (amass if os.path.exists(amass) else None)
    if not exe:
        return set()
    try:
        out = subprocess.run([exe, "enum", "-passive", "-d", domain, "-timeout", "10"], capture_output=True,
                             text=True, timeout=900).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("amass %s: %s", domain, exc)
        return set()
    return {h for h in (x.strip().lower() for x in out.splitlines()) if normalize_domain(h) and is_under(h, domain)}


def wildcard_ips(domain: str, resolver: dns.resolver.Resolver) -> set[str]:
    return set(resolve(f"wc-{secrets.token_hex(6)}.{domain}", resolver))


def country_name(code: str | None) -> str:
    if not code:
        return ""
    c = pycountry.countries.get(alpha_2=code.upper())
    return c.name if c else code


def _rdap(ip: str) -> dict:
    from ipwhois import IPWhois  # imported late: it reads proxy settings at import
    res = IPWhois(ip).lookup_rdap(depth=0, retry_count=1, rate_limit_timeout=30)
    net = res.get("network") or {}
    return {"asn": str(res.get("asn") or "").split()[0], "prefix": str(res.get("asn_cidr") or "").split()[0],
            "netname": net.get("name") or "", "descr": res.get("asn_description") or "",
            "country": country_name(res.get("asn_country_code") or net.get("country"))}


class Enricher:
    """Owner info per address: database cache (30 days), then the scan's own prefix cache, then RDAP."""

    def __init__(self, conn: sqlite3.Connection, lookup: Callable[[str], dict] = _rdap):
        self.conn, self.lookup = conn, lookup
        self.prefixes: list[tuple[ipaddress._BaseNetwork, dict]] = []
        self.cutoff = (datetime.now() - timedelta(days=CACHE_DAYS)).isoformat(timespec="seconds")

    def get(self, ip: str) -> dict:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return {"asn": "", "prefix": "", "netname": "Private/reserved", "descr": "", "country": ""}
        row = self.conn.execute("SELECT * FROM ip_cache WHERE ip = ? AND fetched >= ?", (ip, self.cutoff)).fetchone()
        if row:
            return {k: row[k] or "" for k in ("asn", "prefix", "netname", "descr", "country")}
        for net, info in self.prefixes:
            if addr.version == net.version and addr in net:
                return info
        try:
            info = self.lookup(ip)
        except Exception as exc:  # RDAP servers fail in many ways; the address is still worth listing
            log.warning("rdap %s: %s", ip, exc)
            return {"asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}
        self.conn.execute("INSERT OR REPLACE INTO ip_cache VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (ip, info["asn"], info["prefix"], info["netname"], info["descr"], info["country"], db.now()))
        try:
            self.prefixes.append((ipaddress.ip_network(info["prefix"], strict=False), info))
        except ValueError:
            pass
        return info


def run(conn: sqlite3.Connection, domain: str, settings: Settings, progress: Progress = lambda _: None,
        client: httpx.Client | None = None, resolver: dns.resolver.Resolver | None = None,
        enricher: Enricher | None = None) -> list[dict]:
    resolver = resolver or _resolver()
    own_client = client is None
    client = client or httpx.Client(headers={"User-Agent": "domin/2 (domain inventory)"}, follow_redirects=True)
    try:
        progress("discovering host names")
        found = {domain} | from_crtsh(domain, client) | from_dns(domain, resolver) | from_amass(domain, settings.amass)
        guessed = {f"{w}.{domain}" for w in COMMON} - found
        wildcard = wildcard_ips(domain, resolver)
    finally:
        if own_client:
            client.close()
    candidates = sorted(found | guessed)[: settings.max_hosts]
    progress(f"resolving {len(candidates)} names")
    with ThreadPoolExecutor(settings.scan_workers) as pool:
        resolved = dict(zip(candidates, pool.map(lambda h: resolve(h, resolver), candidates), strict=True))
    hosts = {}
    for h, ips in resolved.items():
        if h in guessed and (not ips or (wildcard and set(ips) <= wildcard)):
            continue  # a guess that doesn't exist, or only matches the wildcard
        hosts[h] = ips
    unique = sorted({ip for ips in hosts.values() for ip in ips})
    progress(f"looking up owners of {len(unique)} addresses")
    enricher = enricher or Enricher(conn)
    info = {}
    for i, ip in enumerate(unique, 1):
        info[ip] = enricher.get(ip)
        if i % 25 == 0:
            progress(f"looking up owners: {i}/{len(unique)}")
            conn.commit()
    records = []
    for h in sorted(hosts):
        if not hosts[h]:
            records.append({"host": h, "ip": ""})
        for ip in hosts[h]:
            records.append({"host": h, "ip": ip, **info[ip]})
    return records
