"""One scan of a domain: find host names, resolve them, and look up who announces each address.

Discovery: certificate transparency (crt.sh), common host names, the domain's MX/NS hosts, and amass (passive, then
active) when installed. Names resolve over the old version's resolver set. Brute-forced names are dropped when the
zone has wildcard DNS. Address owner comes from RDAP (ipwhois), cached per announced prefix and per address in the
database; country from the DB-IP table when loaded.

Routed (Settings · Routes: the route for inventory jobs; external zones only): crt.sh and RDAP go through the hop
as an httpx proxy, DNS goes over DoH through the same client, amass is skipped. The hop must answer first (fail
closed: the job fails with the reason).
"""
from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
import dns.zone
import httpx
import pycountry

from . import admin, db, proxy, tools
from .config import Settings
from .validate import is_internal, is_under, normalize_domain

log = logging.getLogger("domin.scanner")

COMMON = """www mail webmail smtp imap pop autodiscover autoconfig mx mx1 mx2 ns ns1 ns2 ns3 dns vpn remote portal
login sso auth adfs owa exchange lync sip meet teams api app apps dev test stage staging beta demo shop store blog
news cdn static media img files ftp sftp git gitlab jira confluence wiki intranet extranet support help status docs
admin crm erp hr my m mobile secure web web1 web2 www2 cloud office print citrix rdweb gateway proxy""".split()

CACHE_DAYS = 30
Progress = Callable[[str], None]
RESOLVERS = os.path.join(os.path.dirname(__file__), "resolvers.txt")  # the old version's dns_list.txt


def _resolver(nameservers: tuple[str, ...] | None = None, timeout: float = 5.0,
              lifetime: float = 15.0) -> dns.resolver.Resolver:
    """The given nameservers (an internal scan's LAN DNS), else the old version's public resolver set, tried in
    turn until one answers (it gave dig 15 s)."""
    r = dns.resolver.Resolver(configure=False)
    if nameservers:
        r.nameservers = list(nameservers)
    else:
        with open(RESOLVERS) as f:
            r.nameservers = f.read().split()
    r.rotate, r.timeout, r.lifetime = True, timeout, lifetime
    return r


INTERNAL_QPS = 12   # LAN DNS servers rate-limit a client (Pi-hole: 1000 queries per 60 s); stay well under it


class Paced:
    """A resolver that sends at most `qps` queries per second, shared by all threads of one scan."""

    def __init__(self, inner: dns.resolver.Resolver, qps: float, clock=time.monotonic, sleep=time.sleep):
        self.inner, self.gap, self.clock, self.sleep = inner, 1.0 / qps, clock, sleep
        self.nameservers = getattr(inner, "nameservers", [])
        self.lock, self.next = threading.Lock(), 0.0

    def resolve(self, name, rtype):
        with self.lock:
            now = self.clock()
            wait, self.next = self.next - now, max(self.next, now) + self.gap
        if wait > 0:
            self.sleep(wait)
        return self.inner.resolve(name, rtype)


class DohResolver:
    """DNS over HTTPS (RFC 8484, POST) through an httpx client, for a routed scan: UDP DNS can't go through a SOCKS
    or http proxy, so names are resolved by the DoH server through the same proxy as the look-ups. Same interface
    as dns.resolver.Resolver.resolve for this module: an iterable of rdata, DNSException on failure."""

    def __init__(self, url: str, client: httpx.Client, timeout: float = 15.0):
        self.url, self.client, self.timeout = url, client, timeout
        self.nameservers = [url]

    def resolve(self, name, rtype):
        q = dns.message.make_query(str(name), rtype)
        try:
            r = self.client.post(self.url, content=q.to_wire(), timeout=self.timeout,
                                 headers={"accept": "application/dns-message",
                                          "content-type": "application/dns-message"})
            r.raise_for_status()
            msg = dns.message.from_wire(r.content)
        except (httpx.HTTPError, dns.exception.DNSException, ValueError) as exc:
            raise dns.exception.DNSException(f"DoH {self.url}: {str(exc)[:80]}") from None
        if not q.is_response(msg):
            raise dns.exception.DNSException(f"DoH {self.url}: the answer does not match the query")
        if msg.rcode() == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN
        if msg.rcode() != dns.rcode.NOERROR:
            raise dns.exception.DNSException(f"DoH {self.url}: {dns.rcode.to_text(msg.rcode())}")
        want = dns.rdatatype.from_text(rtype)
        found = [rd for rrset in msg.answer if rrset.rdtype == want for rd in rrset]
        if not found:
            raise dns.resolver.NoAnswer
        return found


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
        got = tools.get_json(client, "https://crt.sh/", timeout=90, params={"q": f"%.{domain}", "output": "json"})
        names = [n for e in (got[1] if got else []) for n in str(e.get("name_value", "")).splitlines()]
    except (httpx.HTTPError, ValueError, AttributeError, TypeError) as exc:   # also JSON of an unexpected shape
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


def from_axfr(domain: str, servers: tuple[str, ...]) -> set[str]:
    """Internal scan: the whole zone from the first internal DNS server that allows a transfer (AXFR)."""
    for server in servers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(server, domain, timeout=10, lifetime=60))
        except Exception as exc:  # refused, not authoritative, timeout: the other methods still run
            log.info("axfr %s @%s: %s", domain, server, str(exc)[:80] or type(exc).__name__)
            continue
        names = {n.derelativize(zone.origin).to_text().rstrip(".").lower() for n in zone.nodes}
        return {h for h in names if "*" not in h and normalize_domain(h, (domain,)) and is_under(h, domain)}
    return set()


def sweep_addresses(nets: tuple[str, ...], seeds: list[str], limit: int) -> list[str]:
    """Addresses to reverse-look-up: the configured networks, else the /24 of each private IPv4 seed address."""
    if nets:
        networks = [ipaddress.ip_network(n, strict=False) for n in nets]
    else:
        networks = list(dict.fromkeys(ipaddress.ip_network(f"{ip}/24", strict=False) for ip in seeds
                                      if _lan_address(ip) and ipaddress.ip_address(ip).version == 4))
    out: list[str] = []
    for net in networks:
        out += [str(a) for a in (net.hosts() if net.num_addresses > 2 else net)]
    return list(dict.fromkeys(out))[:limit]


def from_ptr(addresses: list[str], zone: str, domain: str, resolver: dns.resolver.Resolver,
             workers: int) -> set[str]:
    """Internal scan: reverse look-ups (PTR) of the addresses; names under the domain. A bare name (a hosts-file
    entry such as 'pve') belongs to the zone."""
    def one(ip: str) -> list[str]:
        try:
            return [a.to_text() for a in resolver.resolve(dns.reversename.from_address(ip).to_text(), "PTR")]
        except (dns.exception.DNSException, OSError):
            return []

    found = set()
    with ThreadPoolExecutor(workers) as pool:
        for names in pool.map(one, addresses):
            for n in names:
                n = n.rstrip(".").lower()
                n = n if "." in n else f"{n}.{zone}"
                if normalize_domain(n, (zone,)) and is_under(n, domain):
                    found.add(n)
    return found


def amass_hosts(out: str, domain: str) -> set[str]:
    """amass 3 prints one name per line; later versions 'name (FQDN) --> ...': take the first word."""
    names = (line.split()[0].rstrip(".").lower() for line in out.splitlines() if line.strip())
    return {h for h in names if normalize_domain(h) and is_under(h, domain)}


def from_amass(domain: str, amass: str) -> set[str]:
    """Passive, then active (resolvers.txt, 100 queries/s, at most 20000), 15 min each, as the old version did."""
    exe = shutil.which(amass) or (amass if os.path.exists(amass) else None)
    if not exe:
        return set()
    found: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="amass-") as work:
        env = {"PATH": os.environ.get("PATH", ""), "HOME": work}  # the app's secrets stay out of a third-party tool
        # amass 3.23: -trf = trusted resolvers file (older versions: -resolvers)
        active = ["-active", "-trf", RESOLVERS, "-dns-qps", "100", "-max-dns-queries", "20000"]
        for mode in (["-passive"], active):
            # names go to a file as they are found: a run cut off at the time limit keeps what it had
            names = os.path.join(work, f"names{mode[0]}.txt")
            try:
                subprocess.run([exe, "enum", *mode, "-d", domain, "-dir", work, "-o", names, "-timeout", "15"],
                               capture_output=True, text=True, timeout=960, env=env)
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.warning("amass %s %s: %s", mode[0], domain, str(exc)[:80])
            try:
                with open(names) as f:
                    out = f.read()
            except OSError:
                out = ""
            new = amass_hosts(out, domain) - found
            log.info("amass %s %s: %d names", mode[0], domain, len(new))
            found |= new
    return found


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


def rdap_http(ip: str, client: httpx.Client) -> dict:
    """Address owner from rdap.org over the given client: for a routed scan (ipwhois uses urllib, DNS and whois,
    which a SOCKS proxy can't carry). IP RDAP has no origin AS outside ARIN's extension, so asn is often blank."""
    got = tools.get_json(client, f"https://rdap.org/ip/{ip}", timeout=30)
    if got is None:
        raise ValueError("not found")
    data = got[1]
    cidr = next(iter(data.get("cidr0_cidrs") or []), {})
    prefix = f"{cidr.get('v4prefix') or cidr.get('v6prefix')}/{cidr['length']}" if "length" in cidr else ""
    descr = ""
    for ent in data.get("entities") or []:
        if "registrant" in (ent.get("roles") or []):
            descr = next((i[3] for i in (ent.get("vcardArray") or [None, []])[1] if i and i[0] == "fn"), "")
            break
    asn = next(iter(data.get("arin_originas0_originautnums") or []), "")
    return {"asn": str(asn), "prefix": prefix, "netname": data.get("name") or "", "descr": str(descr or ""),
            "country": country_name(data.get("country"))}


class Enricher:
    """Owner info per address: database cache (30 days), then the scan's own prefix cache, then RDAP.

    Country is where the address is located (DB-IP table, as the old version's geolocation) when that table is
    loaded; else the registry country from RDAP."""

    def __init__(self, conn: sqlite3.Connection, lookup: Callable[[str], dict] = _rdap, internal: bool = False):
        self.conn, self.lookup, self.internal = conn, lookup, internal
        self.prefixes: list[tuple[ipaddress._BaseNetwork, dict]] = []
        self.cutoff = (datetime.now() - timedelta(days=CACHE_DAYS)).isoformat(timespec="seconds")

    def get(self, ip: str) -> dict:
        info = self._owner(ip)
        cc = admin.country(self.conn, ip) if info.get("netname") != "Private/reserved" else ""
        return {**info, "country": country_name(cc)} if cc else info

    def _owner(self, ip: str) -> dict:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return {"asn": "", "prefix": "", "netname": "Private/reserved", "descr": "", "country": ""}
        row = self.conn.execute("SELECT * FROM ip_cache WHERE ip = ? AND fetched >= ?", (ip, self.cutoff)).fetchone()
        if row:
            return {k: row[k] or "" for k in ("asn", "prefix", "netname", "descr", "country")}
        for net, info in self.prefixes:
            if addr.version == net.version and addr in net:
                return info
        if self.internal:   # internal scan: a public address is listed, but no external RDAP lookup
            return {"asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}
        try:
            info = self.lookup(ip)
        except Exception as exc:  # RDAP servers fail in many ways; the address is still worth listing
            log.warning("rdap %s: %s", ip, exc)
            return {"asn": "", "prefix": "", "netname": "", "descr": "", "country": ""}
        self.conn.execute("INSERT OR REPLACE INTO ip_cache VALUES (?, ?, ?, ?, ?, ?, ?)",
                          (ip, info["asn"], info["prefix"], info["netname"], info["descr"], info["country"], db.now()))
        self.conn.commit()   # an open write would hold the lock through the next slow lookups: other scans fail
        try:
            self.prefixes.append((ipaddress.ip_network(info["prefix"], strict=False), info))
        except ValueError:
            pass
        return info


_CGNAT = ipaddress.ip_network("100.64.0.0/10")


def _lan_address(ip: str) -> bool:
    """A usable internal address: private (RFC 1918, ULA, CGNAT), not loopback or link-local."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a in _CGNAT) and not (a.is_loopback or a.is_link_local)


def run(conn: sqlite3.Connection, domain: str, settings: Settings, progress: Progress = lambda _: None,
        client: httpx.Client | None = None, resolver: dns.resolver.Resolver | None = None,
        enricher: Enricher | None = None) -> list[dict]:
    internal = is_internal(domain, settings.internal_zones)
    via = None
    if not internal:   # internal zones never leave the LAN: always direct
        cfg = proxy.get(conn)
        via = proxy.hop(conn, proxy.pick(cfg, "", "inventory"), client=client)   # ProxyError: the job fails
    if via:   # routed: fail closed, the hop must answer before anything goes out
        proxy.handshake(via)
        progress(f"route: {proxy.route(via)}")
        log.info("scan %s via %s", domain, proxy.route(via))
        client = tools.http_client(proxy=proxy.http_proxy(via))   # never the direct client passed in
        own_client = True
        resolver = DohResolver(cfg["doh"], client)
        enricher = enricher or Enricher(conn, lookup=lambda ip: rdap_http(ip, client))
    else:
        own_client = client is None
        client = client or tools.http_client()
    resolver = resolver or _resolver(settings.internal_dns if internal else None)
    if internal:
        resolver = Paced(resolver, INTERNAL_QPS)
    try:
        progress("discovering host names")
        if internal:   # internal scan: discover by DNS queries to the LAN DNS only, no crt.sh/amass egress
            zone = max((z for z in settings.internal_zones if is_under(domain, z)), key=len)
            found = {domain} | from_dns(domain, resolver) | from_axfr(domain, settings.internal_dns)
            sweep = sweep_addresses(settings.internal_nets, [*settings.internal_dns, *resolve(domain, resolver)],
                                    admin.SWEEP_MAX)
            progress(f"reverse look-ups of {len(sweep)} addresses")
            found |= from_ptr(sweep, zone, domain, resolver, settings.scan_workers)
        else:
            found = {domain} | from_crtsh(domain, client) | from_dns(domain, resolver)
            if via:   # amass sends its own UDP DNS, which no proxy carries: skipped, never run direct
                log.info("amass skipped for %s: routed via %s", domain, proxy.route(via))
                progress("amass skipped (routed scan)")
            else:
                found |= from_amass(domain, settings.amass)
        guessed = {f"{w}.{domain}" for w in COMMON} - found
        wildcard = wildcard_ips(domain, resolver)
        candidates = sorted(found | guessed)[: settings.max_hosts]
        progress(f"resolving {len(candidates)} names")
        with ThreadPoolExecutor(settings.scan_workers) as pool:
            resolved = dict(zip(candidates, pool.map(lambda h: resolve(h, resolver), candidates), strict=True))
        # the client stays open: a routed scan's DNS and owner look-ups go through it
        return _records(conn, hosts_of(resolved, guessed, wildcard, internal), progress, internal, enricher)
    finally:
        if own_client:
            client.close()


def hosts_of(resolved: dict[str, list[str]], guessed: set[str], wildcard: set[str], internal: bool
             ) -> dict[str, list[str]]:
    """Resolved names to keep: guesses only when they exist outside the wildcard; LAN answers only internally."""
    hosts = {}
    for h, ips in resolved.items():
        if h in guessed and (not ips or (wildcard and set(ips) <= wildcard)):
            continue  # a guess that doesn't exist, or only matches the wildcard
        hosts[h] = ips
    if internal:   # a LAN resolver (e.g. Pi-hole) forwards what it has no local record for: keep LAN answers only
        hosts = {h: lan for h, ips in hosts.items() if (lan := [ip for ip in ips if _lan_address(ip)]) or not ips}
    return hosts


def _records(conn: sqlite3.Connection, hosts: dict[str, list[str]], progress: Progress, internal: bool,
             enricher: Enricher | None) -> list[dict]:
    """Owner info per address (Enricher), then one record per host and address."""
    unique = sorted({ip for ips in hosts.values() for ip in ips})
    progress(f"looking up owners of {len(unique)} addresses")
    enricher = enricher or Enricher(conn, internal=internal)
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
