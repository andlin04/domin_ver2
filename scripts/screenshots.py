#!/usr/bin/env python3
"""Screenshots of domin with made-up demo data, for the documentation.

    python scripts/screenshots.py [--out docs/screenshots] [--edge PATH] [--only NAME,...]

Creates a throw-away database in a temporary directory, fills it with mock data through domin's own functions
(documentation domains and address ranges only: example.com/.org/.net/.test, 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24, 2001:db8::/32, private-use ASNs; 10.20.0.0/24 for a private lab domain), runs the app on a free
port of 127.0.0.1 and saves one headless-browser PNG per view.

Signing in: a demo admin signs in through the app's own sign-in form (POST /admin/login, in-process); the session
cookie it gets back is added to every browser request by a small ASGI wrapper (the cookie is Secure and the demo
server is plain HTTP on 127.0.0.1, so the browser itself would not send it). The sign-in shot goes without it.
Theme: the wrapper serves theme.js with the chosen theme stored first (localStorage "domin-theme").

The browser: --edge PATH, else $DOMIN_SHOT_BROWSER, else Edge's usual install path, else msedge, chromium or
google-chrome on PATH. Nothing outside the temporary directory and --out is written.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import random
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, unquote

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

import uvicorn  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from domin import access, admin, cve, db, jobs, posture, proxy, users  # noqa: E402
from domin.config import Settings  # noqa: E402
from domin.web import COOKIE, HERE, create_app  # noqa: E402

DEMO_PASSWORD = "demo-password-not-real"
DEMO_PUBLIC = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
EDGE_DEFAULT = "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
NOW = datetime.now().replace(microsecond=0)
RNG = random.Random(20261101)

# ---- mock inventory ------------------------------------------------------------------------------------------

# asn: (prefix, netname, description, country)
NETS = {
    "64496": ("192.0.2.0/25", "EXAMPLE-CLOUD", "Example Cloud AB", "Sweden"),
    "64497": ("198.51.100.0/25", "DEMO-HOSTING", "Demo Hosting GmbH", "Germany"),
    "64498": ("203.0.113.0/25", "SAMPLE-NET", "Sample Networks Ltd", "Ireland"),
    "64499": ("198.51.100.128/25", "TESTNET-DC", "Testnet Datacenter B.V.", "Netherlands"),
    "64500": ("203.0.113.128/25", "PLACEHOLDER-CDN", "Placeholder CDN Inc", "United States"),
    "64501": ("192.0.2.128/25", "NORDIC-DEMO", "Nordic Demo Oy", "Finland"),
    "65536": ("2001:db8:100::/48", "EXAMPLE-CLOUD-V6", "Example Cloud AB", "Sweden"),
    "65537": ("2001:db8:200::/48", "DEMO-HOSTING-V6", "Demo Hosting GmbH", "Germany"),
}
# domain: [(host label, address, asn, first scan index, last scan index)]; '' address = name without an address
SCANS = 10
INVENTORY = {
    "example.com": [
        ("", "192.0.2.10", "64496", 0, 9), ("www", "192.0.2.10", "64496", 0, 9),
        ("www", "2001:db8:100::10", "65536", 0, 9), ("mail", "192.0.2.25", "64496", 0, 9),
        ("vpn", "203.0.113.5", "64498", 0, 9), ("api", "198.51.100.20", "64497", 0, 9),
        ("shop", "198.51.100.140", "64499", 0, 9), ("cdn", "203.0.113.200", "64500", 0, 9),
        ("static", "203.0.113.201", "64500", 2, 9), ("legacy", "192.0.2.40", "64496", 0, 4),
        ("intranet", "", "", 0, 9), ("dev", "198.51.100.30", "64497", 6, 9), ("status", "192.0.2.150", "64501", 3, 9),
        ("autodiscover", "203.0.113.210", "64500", 0, 9), ("beta", "198.51.100.31", "64497", 8, 9),
    ],
    "example.org": [
        ("", "198.51.100.60", "64497", 0, 9), ("www", "198.51.100.60", "64497", 0, 9),
        ("mail", "198.51.100.61", "64497", 0, 9), ("webmail", "198.51.100.61", "64497", 0, 9),
        ("vpn", "192.0.2.160", "64501", 0, 9), ("docs", "203.0.113.220", "64500", 1, 9),
        ("old", "198.51.100.62", "64497", 0, 3), ("api", "2001:db8:200::5", "65537", 4, 9),
    ],
    "example.net": [
        ("", "203.0.113.30", "64498", 0, 9), ("www", "203.0.113.30", "64498", 0, 9),
        ("mail", "203.0.113.31", "64498", 0, 9), ("ns1", "192.0.2.53", "64496", 0, 9),
        ("ns2", "198.51.100.53", "64499", 0, 9), ("portal", "198.51.100.150", "64499", 5, 9),
        ("test", "", "", 0, 6),
    ],
    "example.test": [
        ("", "192.0.2.200", "64501", 0, 9), ("www", "192.0.2.200", "64501", 0, 9),
        ("shop", "203.0.113.240", "64500", 0, 9), ("mail", "192.0.2.201", "64501", 2, 9),
    ],
}

# ---- mock posture: products with a few public CVEs ---------------------------------------------------------------


def finding(cve_id, sev, score, fixed, summary, vector, published, cwe):
    return {"cve": cve_id, "severity": sev, "score": score, "fixed": fixed, "summary": summary,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "source": "NVD", "vector": vector,
            "published": published, "cwe": [cwe], "refs": []}


NET_AV = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVES = {
    ("openbsd", "openssh", "8.9p1"): [
        finding("CVE-2024-6387", "high", 8.1, "9.8p1", "Signal handler race condition in sshd may allow "
                "unauthenticated remote code execution.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "2024-07-01", "CWE-364"),
        finding("CVE-2023-38408", "critical", 9.8, "9.3p2", "The PKCS#11 feature in ssh-agent has an insufficiently "
                "trustworthy search path, leading to remote code execution via a forwarded agent.", NET_AV,
                "2023-07-20", "CWE-428"),
        finding("CVE-2023-48795", "medium", 5.9, "9.6", "The SSH transport protocol with certain extensions allows "
                "a man-in-the-middle to bypass integrity checks (Terrapin).",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", "2023-12-18", "CWE-354"),
        finding("CVE-2021-36368", "low", 3.7, None, "An authentication-forwarding issue may let a malicious server "
                "make the user believe FIDO authentication succeeded.",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N", "2022-03-13", "CWE-287"),
    ],
    ("f5", "nginx", "1.18.0"): [
        finding("CVE-2021-23017", "high", 7.7, "1.21.0", "An off-by-one in the DNS resolver may allow a remote "
                "attacker to cause a 1-byte memory overwrite.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:H",
                "2021-06-01", "CWE-193"),
        finding("CVE-2023-44487", "high", 7.5, "1.25.3", "HTTP/2 request cancellation can reset many streams "
                "quickly (Rapid Reset), exhausting server resources.",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "2023-10-10", "CWE-400"),
    ],
    ("apache", "http_server", "2.4.49"): [
        finding("CVE-2021-42013", "critical", 9.8, "2.4.51", "Path traversal and remote code execution through an "
                "incomplete fix for CVE-2021-41773.", NET_AV, "2021-10-07", "CWE-22"),
        finding("CVE-2021-41773", "high", 7.5, "2.4.50", "A path normalization flaw allows mapping URLs to files "
                "outside the expected document root.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "2021-10-05", "CWE-22"),
        finding("CVE-2022-22720", "critical", 9.8, "2.4.53", "Failure to close the inbound connection on errors "
                "discarding the request body exposes the server to request smuggling.", NET_AV, "2022-03-14",
                "CWE-444"),
    ],
    ("exim", "exim", "4.94.2"): [
        finding("CVE-2023-42115", "critical", 9.8, "4.96.1", "An out-of-bounds write in the SMTP AUTH handling "
                "allows remote code execution.", NET_AV, "2024-05-03", "CWE-787"),
        finding("CVE-2022-37452", "critical", 9.8, "4.95", "A heap-based buffer overflow in the alias handling "
                "of host_name_lookup.", NET_AV, "2022-08-08", "CWE-787"),
    ],
    ("openssl", "openssl", "1.1.1k"): [
        finding("CVE-2022-0778", "high", 7.5, "1.1.1n", "BN_mod_sqrt() can loop forever for non-prime moduli, "
                "e.g. while parsing certificates.", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "2022-03-15", "CWE-835"),
        finding("CVE-2023-0286", "high", 7.4, "1.1.1t", "A type confusion in X.400 address processing in "
                "X.509 GeneralName.", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", "2023-02-08", "CWE-843"),
    ],
}
# product label, nmap service name, cpe (vendor, product, version) or None for a service without known CVEs
SERVICES = {
    "ssh-old": ("OpenSSH", "ssh", ("openbsd", "openssh", "8.9p1")),
    "ssh-new": ("OpenSSH", "ssh", ("openbsd", "openssh", "9.8p1")),
    "nginx-old": ("nginx", "http", ("f5", "nginx", "1.18.0")),
    "nginx-new": ("nginx", "http", ("f5", "nginx", "1.26.2")),
    "apache-old": ("Apache httpd", "http", ("apache", "http_server", "2.4.49")),
    "apache-new": ("Apache httpd", "http", ("apache", "http_server", "2.4.62")),
    "exim": ("Exim smtpd", "smtp", ("exim", "exim", "4.94.2")),
    "openssl": ("OpenSSL", "https", ("openssl", "openssl", "1.1.1k")),
    "dovecot": ("Dovecot imapd", "imaps", ("dovecot", "dovecot", "2.3.21")),
    "postfix": ("Postfix smtpd", "smtp", ("postfix", "postfix", "3.7.11")),
}
# (domain, address, [(days ago, {port: service key})]): oldest first; each list is one address's scan history
POSTURE = [
    ("example.com", "192.0.2.10", [(40, {22: "ssh-old", 80: "nginx-old", 443: "nginx-old"}),
                                   (18, {22: "ssh-old", 80: "nginx-old", 443: "nginx-old", 8443: "openssl"}),
                                   (1, {22: "ssh-new", 80: "nginx-new", 443: "nginx-new", 8443: "openssl"})]),
    ("example.com", "192.0.2.25", [(35, {25: "exim", 587: "exim", 993: "dovecot"}),
                                   (2, {25: "exim", 587: "exim", 993: "dovecot", 22: "ssh-old"})]),
    ("example.com", "203.0.113.5", [(30, {443: "openssl", 22: "ssh-old"}), (0, {443: "openssl"})]),
    ("example.com", "198.51.100.20", [(28, {443: "apache-old", 80: "apache-old"}),
                                      (3, {443: "apache-old", 80: "apache-old", 22: "ssh-new"})]),
    ("example.com", "198.51.100.140", [(25, {80: "apache-old", 443: "apache-old"}),
                                       (0, {80: "apache-new", 443: "apache-new"})]),
    ("example.com", "2001:db8:100::10", [(12, {80: "nginx-new", 443: "nginx-new"})]),
    ("example.org", "198.51.100.60", [(45, {80: "nginx-old", 443: "nginx-old", 22: "ssh-old"}),
                                      (5, {80: "nginx-old", 443: "nginx-old", 22: "ssh-new"})]),
    ("example.org", "198.51.100.61", [(20, {25: "postfix", 993: "dovecot", 443: "nginx-new"})]),
    ("example.org", "192.0.2.160", [(15, {443: "openssl"}), (1, {443: "openssl", 22: "ssh-old"})]),
    ("example.net", "203.0.113.30", [(33, {80: "apache-new", 443: "apache-new"}),
                                     (4, {80: "apache-new", 443: "apache-new"})]),
    ("example.net", "203.0.113.31", [(8, {25: "exim", 22: "ssh-new"})]),
    ("example.test", "192.0.2.200", [(10, {22: "ssh-new", 80: "nginx-new", 443: "nginx-new"})]),
]


def stamp(days_ago: float, hour: int = 10) -> str:
    t = (NOW - timedelta(days=days_ago)).replace(hour=hour, minute=RNG.randrange(60), second=RNG.randrange(60))
    return min(t, NOW - timedelta(minutes=5)).isoformat(timespec="seconds")


def seed_inventory(c) -> None:
    """A weekly scheduled refresh of every domain over the last three months, plus visitors' scans in between."""
    # (days ago, domain index, scan index: which host names exist, see INVENTORY), about every nine days
    runs = [(stamp(84 - i * 9, 3 + d), d, i, "scheduled") for d in range(len(INVENTORY)) for i in range(SCANS)]
    for _ in range(24):   # visitors' scans: one to five days after a refresh, same host names
        i = RNG.randrange(SCANS)
        runs.append((stamp(max(0, 84 - i * 9 - RNG.randrange(1, 6)), RNG.randrange(9, 20)),
                     RNG.randrange(len(INVENTORY)), i, "198.51.100.77"))
    for started, d, i, client in sorted(runs):
        dom, hosts = list(INVENTORY.items())[d]
        rows = []
        for label, ip, asn, first, last in hosts:
            if not first <= i <= last:
                continue
            host = f"{label}.{dom}" if label else dom
            if not ip:
                rows.append({"host": host})
                continue
            prefix, netname, descr, country = NETS[asn]
            rows.append({"host": host, "ip": ip, "asn": asn, "prefix": prefix, "netname": netname,
                         "descr": descr, "country": country})
        finished = (datetime.fromisoformat(started) + timedelta(minutes=4 + d)).isoformat(timespec="seconds")
        sid = db.save_scan(c, dom, started, "scan", rows, finished=finished)
        c.execute("""INSERT INTO jobs (domain, status, created, started, finished, scan_id, client, progress)
                     VALUES (?, 'done', ?, ?, ?, ?, ?, 'done')""", (dom, started, started, finished, sid, client))


def service(port: int, key: str) -> dict:
    label, name, (vendor, product, version) = SERVICES[key]
    s = {"port": port, "proto": "tcp", "service": "https" if port in (443, 8443) and name == "http" else name,
         "product": label, "version": version, "cpes": [f"cpe:/a:{vendor}:{product}:{version}"], "matched": True}
    s["findings"] = [dict(f) for f in CVES.get((vendor, product, version), [])]
    return s


def seed_posture(c, cve_file: Path) -> None:
    store = cve.Database("own", cve_file)
    for (vendor, product, version), found in CVES.items():
        store.store(cve.target_key({"kind": "cpe", "part": "a", "vendor": vendor, "product": product,
                                    "version": version}), found)
    inventory = {(dom, ip): {"hosts": [], "country": NETS[asn][3]}
                 for dom, hosts in INVENTORY.items() for _, ip, asn, *_ in hosts if ip}
    for dom, hosts in INVENTORY.items():
        for label, ip, *_ in hosts:
            if ip:
                inventory[(dom, ip)]["hosts"].append(f"{label}.{dom}" if label else dom)
    for dom, ip, history in POSTURE:
        target = inventory[(dom, ip)]
        prof = posture.profile(c, "web" if 8443 in history[-1][1] else "default")
        for days, ports in history:
            n = posture.enqueue(c, dom, [{"ip": ip, **target}], prof, "alice")
            assert n == 1, (dom, ip)
            sid = c.execute("SELECT MAX(id) FROM posture_scans").fetchone()[0]
            services = [service(p, k) for p, k in sorted(ports.items())]
            params = f"nmap -Pn -sV --version-intensity {prof['intensity']} -T{prof['timing']} -p {prof['ports']} {ip}"
            raw = (f'<nmaprun args="{params}"><host><address addr="{ip}"/><ports>'
                   + "".join(f'<port protocol="tcp" portid="{s["port"]}"><state state="open"/><service name="'
                             f'{s["service"]}" product="{s["product"]}" version="{s["version"]}"/></port>'
                             for s in services) + "</ports></host></nmaprun>")
            posture._finish(c, sid, "done", {"services": services, "raw": raw, "params": params})
            created = stamp(days, 2)
            started = (datetime.fromisoformat(created) + timedelta(minutes=1)).isoformat(timespec="seconds")
            finished = (datetime.fromisoformat(started) + timedelta(minutes=3)).isoformat(timespec="seconds")
            c.execute("UPDATE posture_scans SET created = ?, started = ?, finished = ? WHERE id = ?",
                      (created, started, finished, sid))
    # the Scans board: one address being scanned now, one waiting
    prof = posture.profile(c, "default")
    posture.enqueue(c, "example.net", [{"ip": "192.0.2.53", **inventory[("example.net", "192.0.2.53")]}], prof, "bob")
    posture.enqueue(c, "example.net", [{"ip": "198.51.100.53", **inventory[("example.net", "198.51.100.53")]}],
                    prof, "bob")
    c.execute("""UPDATE posture_scans SET status = 'running', started = ?, chunks = 4, chunks_done = 1
                 WHERE ip = '192.0.2.53'""", ((NOW - timedelta(minutes=2)).isoformat(timespec="seconds"),))


def seed_schedules(c) -> None:
    """Discovery profiles, an nmap stage on example.com's latest scan, and schedules with past runs."""
    from domin import discovery, schedules
    for p in ({"name": "web-quick", "method": "none", "probe_ports": "", "port_mode": "list", "ports": "80,443,8443",
               "top_ports": 100, "timing": 3, "max_rate": 50, "max_retries": 1, "host_timeout": 120, "rdns": 0,
               "route": "r3", "note": "Proxy route: no ping, connect check of the web ports"},
              {"name": "lan-sweep", "method": "syn", "probe_ports": "22,80,443,445", "port_mode": "top",
               "top_ports": 20, "ports": "", "timing": 4, "max_rate": 300, "max_retries": 2, "host_timeout": 300,
               "rdns": 1, "route": "", "note": "Internal networks: reverse names, top 20 ports"}):
        discovery.save(c, p, "alice")
    discovery.set_default(c, "default")
    sid = c.execute("""SELECT s.id FROM scans s JOIN domains d ON d.id = s.domain_id WHERE d.name = 'example.com'
                       ORDER BY s.started DESC LIMIT 1""").fetchone()[0]
    ips = [r[0] for r in c.execute("SELECT DISTINCT ip FROM records WHERE scan_id = ? AND ip != '' ORDER BY ip",
                                   (sid,))]
    found = [{"ip": ip, "names": [], "ports": ["443/tcp"] + (["80/tcp"] if i % 2 else []),
              "reason": "syn-ack"} for i, ip in enumerate(ips[:5])]
    db.save_discovery(c, sid, "default", "nmap -PS22,80,443 -sn -n -T3 --max-retries 1 --host-timeout 120s "
                                         f"--max-rate 100 -oX - -iL <{len(ips)} addresses>", found)
    hosts = posture.hosts(c, "example.com")
    now = NOW.timestamp()
    forms = [("example.com", {"name": "Weekly inventory + nmap", "discovery": "on", "discovery_profile": "default",
                              "freq": "weekly", "weekday": "6", "at_time": "03:00"}),
             ("example.com", {"name": "Web hosts posture", "posture": "on", "posture_profile": "web",
                              "host_mode": "list", "freq": "monthly", "monthday": "31", "at_time": "02:30",
                              **{f"h:{h}": "on" for h in hosts[:3]}}),
             ("example.org", {"name": "Cloud hosts nightly", "discovery": "on", "posture": "on",
                              "posture_profile": "default", "host_mode": "tag", "tag": "cloud", "freq": "daily",
                              "at_time": "01:15"}),
             ("example.net", {"name": "Every 6 hours", "discovery": "on", "freq": "hours", "every": "6",
                              "at_time": "00:00"})]
    for dom, f in forms:
        p, err = schedules.check(c, dom, {"enabled": "on", "weekday": "0", "monthday": "1", "every": "1", **f})
        if not p:
            raise SystemExit(f"demo schedule {f['name']}: {err}")
        schedules.create(c, dom, p, "alice", now=now)
    job = c.execute("SELECT id FROM jobs WHERE domain = 'example.com' ORDER BY id DESC LIMIT 1").fetchone()[0]
    c.execute("UPDATE schedules SET last_run = ?, last_job = ?, last_result = ? WHERE id = 1",
              (stamp(4, 3), job, f"inventory job #{job} queued (nmap discovery: default)"))
    c.execute("""UPDATE schedules SET last_run = ?, hosts = json_insert(hosts, '$[#]', 'old.example.com'),
                 last_result = 'posture: 2 address(es) queued with profile web; hosts no longer in the domain, '
                 || 'skipped: old.example.com' WHERE id = 2""", (stamp(11, 2),))
    c.execute("UPDATE schedules SET enabled = 0 WHERE id = 4")
    # a lab domain on private addresses with a posture schedule on the default route (Office proxy): the route check
    db.save_scan(c, "lab.example.test", stamp(1, 4), "scan", [
        {"host": "nas.lab.example.test", "ip": "10.20.0.5"}, {"host": "printer.lab.example.test", "ip": "10.20.0.9"}])
    p, err = schedules.check(c, "lab.example.test", {"name": "NAS posture", "enabled": "", "posture": "on",
                                                     "posture_profile": "default", "host_mode": "all",
                                                     "freq": "weekly", "weekday": "2", "at_time": "04:00",
                                                     "monthday": "1", "every": "1"})
    if not p:
        raise SystemExit(f"demo schedule NAS posture: {err}")
    schedules.create(c, "lab.example.test", p, "alice", now=now)


def seed_settings(c) -> str:
    """Users, scan profiles, routes and scope; returns the demo admin's TOTP secret."""
    alice = users.create(c, "alice", "admin", DEMO_PASSWORD)
    erin = users.create(c, "erin", "admin", DEMO_PASSWORD)
    bob = users.create(c, "bob", "power", DEMO_PASSWORD)
    carol = users.create(c, "carol", "power", DEMO_PASSWORD)
    dave = users.create(c, "dave", "power", DEMO_PASSWORD)
    frank = users.create(c, "frank", "power", DEMO_PASSWORD)
    users.create(c, "gina", "power", DEMO_PASSWORD, by_admin=True)   # an admin-set password: the change offer
    access.set_grants(c, bob, {"*": "admin"}, "alice")
    access.set_grants(c, carol, {"example.com": "admin", "example.org": "viewer"}, "alice")
    access.set_grants(c, dave, {"example.net": "viewer"}, "alice")
    access.grant_viewer(c, "example.com", frank, {"id": carol, "name": "carol"})   # carol's Viewers panel
    access.set_rights(c, carol, {**access.DEFAULT_RIGHTS, "profiles": "write", "discovery": "none"})
    for actor, action, target, detail in (("alice", "user-add", "carol", "role power"),
                                          ("alice", "grants", "carol", "added example.com=admin, example.org=viewer"),
                                          ("alice", "user-add", "erin", "role admin"),
                                          ("alice", "disable", "dave", "")):
        access.audit(c, actor, action, target, detail)
    from domin import totp
    secret = totp.new_secret()   # alice and bob use 2FA (required for admins below)
    for uid, s in ((alice, secret), (bob, totp.new_secret())):
        codes = json.dumps([totp.hash_recovery(x) for x in totp.new_recovery_codes()])
        c.execute("UPDATE users SET totp_secret = ?, recovery = ? WHERE id = ?", (s, codes, uid))
    users.set_disabled(c, dave, True)
    for uid, days in ((bob, 1), (carol, 6), (erin, 2)):
        c.execute("UPDATE users SET last_login = ? WHERE id = ?", (stamp(days, 9), uid))
    for p, note in (({"name": "web", "ports": "80,443,8080,8443", "intensity": 5, "timing": 3, "timeout": 180,
                      "route": "r1"}, "Web servers, deeper version probes"),
                    ({"name": "mail", "ports": "25,110,143,465,587,993,995", "intensity": 2, "timing": 3,
                      "timeout": 120, "route": "r2"}, "Mail services"),
                    ({"name": "slow-and-quiet", "ports": "22,80,443", "intensity": 0, "timing": 2, "timeout": 300,
                      "route": "r3"}, "Low rate, light probes")):
        posture.save_profile(c, p, note, "bob")
    routes = proxy.get(c)
    routes["routes"] = [
        {**proxy.ROUTE_DEFAULT, "id": "r1", "name": "Tor", "kind": "tor"},
        {**proxy.ROUTE_DEFAULT, "id": "r2", "name": "Mullvad Sweden", "kind": "mullvad", "mullvad_mode": "fixed",
         "mullvad_country": "se"},
        {**proxy.ROUTE_DEFAULT, "id": "r3", "name": "Office proxy", "kind": "custom", "type": "socks5",
         "host": "proxy.example.net", "port": 1080, "username": "scanner"},
        {**proxy.ROUTE_DEFAULT, "id": "r4", "name": "Lab HTTP proxy", "kind": "custom", "type": "http",
         "host": "203.0.113.99", "port": 3128, "enabled": False},
    ]
    routes.update(next=5, posture="r3", inventory="direct", cve="direct", dismissed=["tor", "mullvad"])
    proxy.put(c, routes)
    proxy.record_test(c, "r3", True, "SOCKS5 handshake OK, exit address 203.0.113.99")
    proxy.record_test(c, "r1", True, "Tor SOCKS5 answered; exit verified")
    scope = users.get_scope(c)
    scope.update(domains_allow=["example.com", "example.org", "example.net", "example.test"],
                 domains_deny=["internal.example.com"],
                 ip_allow=["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"],
                 ip_deny=["203.0.113.200/29"], countries_deny=["United States"],
                 require_2fa={"power": False, "admin": True},
                 net_tags=[{"net": "192.0.2.0/25", "tag": "cloud", "note": "Example Cloud tenancy"},
                           {"net": "198.51.100.128/25", "tag": "datacenter", "note": "Colocation racks"}])
    scope["posture_exclude"] = [{"host": "autodiscover.", "owner": "placeholder-cdn",
                                 "note": "Mail provider's hosts"}]
    users.save_scope(c, scope)
    admin.kv_set(c, f"dismiss:auth-notice:{alice}", "1")
    admin.kv_set(c, jobs.CVE_REFRESH_KEY, json.dumps({"at": int((NOW - timedelta(hours=5)).timestamp())}))
    # visit statistics for the Operations page
    doms = list(INVENTORY)
    for day in range(30):
        for k in range(RNG.randrange(6, 18)):   # visitors: a few requests each, seconds to minutes apart
            at = datetime.fromisoformat(stamp(day, RNG.randrange(7, 22)))
            ref, country = RNG.choice(["", "", "search.example", "news.example.org"]), RNG.choice(
                ["Sweden", "Sweden", "Germany", "Finland", "Netherlands", "Ireland", "United States"])
            for _ in range(RNG.randrange(1, 6)):
                dom = RNG.choice(doms)
                kind, path = RNG.choices([("page", "/"), ("page", f"/d/{dom}"), ("page", "/all"),
                                          ("tool", f"/api/rdap/{dom}"), ("tool", f"/api/email/{dom}"),
                                          ("download", f"/scans/{day + 1}.csv"), ("scan", "/api/scan")],
                                         weights=[20, 40, 12, 6, 6, 2, 2])[0]
                c.execute("INSERT INTO visits (at, visitor, kind, path, domain, ref, country) VALUES (?,?,?,?,?,?,?)",
                          (at.isoformat(timespec="seconds"), f"d{day}v{k}", kind, path,
                           "" if path in ("/", "/all") else dom, ref, country))
                at += timedelta(seconds=RNG.randrange(15, 240))
                ref = ""
    return secret


# ---- the app behind a wrapper ------------------------------------------------------------------------------------

# the current shot: session cookie ('' = signed out), theme, script, and a phone width (0 = the browser window)
SHOT = {"cookie": "", "theme": "dark", "js": "", "phone": 0}


def wrap(app):
    """Session cookie and theme on each request of the current shot, and its script injected into HTML pages.

    Phone widths: headless Edge keeps its window at least ~500 px wide, so a phone shot loads /__phone, a page with
    the view in an iframe of that width (the frame-blocking headers are dropped for this demo server only)."""
    theme_js = (HERE / "static" / "theme.js").read_bytes()

    async def asgi(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        if scope["path"] == "/__phone":
            src = html.escape(unquote(scope["query_string"].decode().removeprefix("src=")))
            body = (f'<!doctype html><body style="margin:0;background:#888"><iframe src="{src}" '
                    f'style="width:{SHOT["phone"]}px;height:100vh;border:0;display:block"></iframe></body>').encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/html"), (b"cache-control", b"no-store")]})
            return await send({"type": "http.response.body", "body": body})
        if SHOT["phone"]:
            inner = send

            async def send(msg):
                if msg["type"] == "http.response.start":
                    msg = {**msg, "headers": [h for h in msg["headers"]
                                              if h[0].lower() not in (b"x-frame-options", b"content-security-policy")]}
                return await inner(msg)
        headers = [h for h in scope["headers"] if h[0] != b"cookie"]
        if SHOT["cookie"]:
            headers.append((b"cookie", f"{COOKIE}={SHOT['cookie']}".encode()))
        scope = {**scope, "headers": headers}
        if scope["path"] == "/static/theme.js":
            body = f'try {{ localStorage.setItem("domin-theme", "{SHOT["theme"]}"); }} catch (e) {{}}\n'.encode()
            body += theme_js
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/javascript"), (b"cache-control", b"no-store")]})
            return await send({"type": "http.response.body", "body": body})
        if scope["path"] == "/__shot.js":   # a file, as the page's Content-Security-Policy allows no inline script
            body = ("window.addEventListener('load', () => setTimeout(() => {" + SHOT["js"] + "}, 700));").encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"text/javascript"), (b"cache-control", b"no-store")]})
            return await send({"type": "http.response.body", "body": body})
        if not SHOT["js"]:
            return await app(scope, receive, send)
        start, chunks = {}, []

        async def capture(msg):
            if msg["type"] == "http.response.start":
                start.update(msg)
                return None
            chunks.append(msg.get("body", b""))
            if msg.get("more_body"):
                return None
            body = b"".join(chunks)
            hdrs = [h for h in start["headers"] if h[0] != b"content-length"]
            if any(h[0] == b"content-type" and h[1].startswith(b"text/html") for h in hdrs):
                body = body.replace(b"</body>", b'<script src="/__shot.js"></script></body>')
            await send({**start, "headers": hdrs + [(b"content-length", str(len(body)).encode())]})
            return await send({"type": "http.response.body", "body": body})
        return await app(scope, receive, capture)
    return asgi


# ---- the shots ---------------------------------------------------------------------------------------------------

# headless browsers paint a scrolled page blank: hide what is above a section instead of scrolling
def _hide_above(element_js: str) -> str:
    return (f"{{ const n = {element_js}; if (n) for (let e = n; e && e.tagName !== 'MAIN' && e !== document.body;"
            " e = e.parentElement) for (let s = e.previousElementSibling; s; s = s.previousElementSibling)"
            " if (!['HEADER', 'NAV', 'SCRIPT'].includes(s.tagName)) s.style.display = 'none'; }")


def _card(heading: str) -> str:
    """JS: the card whose h2 starts with heading."""
    return (f"[...document.querySelectorAll('h2')].find(h => h.textContent.trim().startsWith({json.dumps(heading)}))"
            "?.closest('section, .card')")


def show_from(selector: str) -> str:
    return _hide_above(f"document.querySelector({json.dumps(selector)})")


def from_card(heading: str) -> str:
    return _hide_above(_card(heading))


def hide_card(heading: str) -> str:
    return f"{{ const c = {_card(heading)}; if (c) c.style.display = 'none'; }}"


# ?host= opens that name's findings in the host table; then open its first service group and CVE
OPEN_CVE = ("setTimeout(() => { for (const s of ['details.posture-detail', 'details.svc-group', 'details.cve-item'])"
            " { const d = document.querySelector('#posture-hosts ' + s); if (d) d.open = true; } }, 500);")

OPEN_SCHEDULE = "document.querySelector('details.add-schedule').open = true;"
# the add form on lab.example.test with a posture scan, sent once: the answer is the form with the route warning
SUBMIT_LAB = ("if (!sessionStorage.getItem('shot-sent')) { sessionStorage.setItem('shot-sent', '1');"
              " const f = document.querySelector('details.add-schedule form'); f.elements.name.value = 'NAS weekly';"
              " f.elements.posture.checked = true; f.submit(); }"
              " else " + show_from("#schedule-form"))

# name: (path, signed in: True = the demo admin, a name = that power user, False = signed out, height, script)
SHOTS = {
    "header": ("/admin/security", True, 380, "document.querySelector('details.nav-menu').open = true;"),
    "signin": ("/admin", False, 760, ""),
    "overview": ("/", True, 1400, ""),
    "domain": ("/d/example.com", True, 1950, ""),
    "domain-compare": ("/d/example.com/compare", True, 680, ""),
    "drilldown": ("/all", True, 1500, ""),
    "posture-overview": ("/admin/security", True, 1600, ""),
    "posture-analysis": ("/admin/security/analysis", True, 1750, ""),
    "posture-domain": ("/admin/security/analysis?domain=example.com", True, 1500, ""),
    "posture-cve": ("/admin/security/analysis?domain=example.com&host=api.example.com", True, 900,
                    OPEN_CVE + show_from("section.host-list")),
    "posture-scans": ("/admin/security/scans", True, 760, ""),
    "operations": ("/admin", True, 1300, ""),
    "profiles": ("/admin/security/profiles", True, 1000, ""),
    "profiles-list": ("/admin/security/profiles", True, 560, from_card("Profiles")),
    # "This host" reports the tools installed on the machine running this script: not part of the demo
    "routes": ("/admin/security/scan-settings", True, 1050, hide_card("This host")),
    "settings": ("/admin/settings", True, 1000, ""),
    "settings-posture": ("/admin/settings", True, 1250, from_card("Security posture scope")),
    "users": ("/admin/users", True, 1100, ""),
    "user-edit": ("/admin/users/4", True, 1900, ""),   # carol (4th user): two domain grants
    "posture-power": ("/admin/security/analysis", "carol", 1500, ""),
    "account": ("/admin/account", True, 900, ""),
    "discovery-profiles": ("/admin/security/discovery-profiles", True, 1300, ""),
    "discovery-profiles-list": ("/admin/security/discovery-profiles", True, 520, from_card("Profiles")),
    "posture-discovery": ("/admin/security/scans?domain=example.com", True, 700, from_card("nmap discovery")),
    "schedule-edit": ("/admin/schedules/2", True, 1250, "document.querySelector('details.host-pick').open = true;"),
    "posture-schedules": ("/admin/security/scans", True, 1500, OPEN_SCHEDULE + from_card("Scheduled rescans")),
    "posture-schedules-power": ("/admin/security/scans", "carol", 1300,
                                OPEN_SCHEDULE + from_card("Scheduled rescans")),
    "operations-schedules": ("/admin", True, 300, from_card("Scheduled rescans")),
    "settings-signin": ("/admin/settings", True, 520, from_card("Sign-in required for")),
    "settings-csv-import": ("/admin/settings", True, 420, from_card("CSV import")),
    "csv-map": ("", True, 1500, ""),   # the path: an upload of DEMO_CSV, made in main()
    "settings-components": ("/admin/settings/components", True, 760, ""),
    "posture-import": ("/admin/security/import", True, 900, ""),
    "domain-viewers": ("/admin/viewers?domain=example.com", "carol", 560, ""),   # carol: maintainer of example.com
    "users-info": ("/admin/users", True, 560, from_card("Roles and rights")),
    "table-cves": ("/admin/security/analysis?domain=example.com", True, 1000,
                   "document.querySelector('[data-tab=cves]')?.click();" + show_from("section.host-list")),
    "table-hosts": ("/d/example.com", True, 1000, show_from("#records")),
    "table-posture-hosts": ("/admin/security/analysis?domain=example.com", True, 1000, show_from("section.host-list")),
    "table-schedules": ("/admin/security/scans", True, 900, from_card("Scheduled rescans")),
    "schedule-route-warning":("/admin/security/scans?domain=lab.example.test", True, 1000, SUBMIT_LAB),
    "tools": ("/tools", True, 900, ""),
    "lookup": ("/admin/security/lookup", True, 1100, ""),
    "public-overview": ("/", False, 1200, ""),
    "public-domain": ("/d/example.com", False, 1400, ""),
    "not-found": ("/d/no-such-domain.example", True, 500, ""),   # error.html
    # Add a user with a generated password (masked), and the offer after a sign-in with an admin-set password
    "user-add-generated": ("/admin/users", True, 560, "document.querySelector('input[name=name]').value = 'hana';"
                           "document.querySelector('[data-pw-generate]').click();" + from_card("Add a user")),
    "pw-renew": ("/admin/account/renew", "gina", 620, ""),
}
LIGHT = ("overview", "posture-overview", "header", "csv-map")   # also shot in the light theme: NAME-light.png
# another tool's export for the mapping dialog: renamed, reordered, semicolons, a column domin has no field for
DEMO_CSV = (b"Hostname;Address;Owner;AS;Country;Seen at;Ticket\r\n"
            b"www.example.com;192.0.2.10;EXAMPLE-NET;64500;Sweden;2026-11-01 08:00;OPS-1041\r\n"
            b"mail.example.com;198.51.100.25;DOC-MAIL;64501;Germany;2026-11-01 08:00;OPS-1041\r\n"
            b"api.example.org;2001:db8::20;DOC-V6;64502;Netherlands;2026-11-02 09:30;\r\n")
PHONE, PHONE_WIDTH = ("header",), 390   # also shot at a phone width, dark and light: NAME-390[-light].png


def find_browser(arg: str) -> str:
    for cand in (arg, os.environ.get("DOMIN_SHOT_BROWSER", ""), EDGE_DEFAULT):
        if cand and Path(cand).is_file():
            return cand
    for name in ("msedge", "chromium", "chromium-browser", "google-chrome"):
        if found := shutil.which(name):
            return found
    raise SystemExit("No Edge or Chromium found: pass --edge PATH")


def run_edge(browser: str, url: str, w: int, h: int, wait_ms: int, png: Path) -> None:
    """One headless screenshot of url into png (the browser's own process; it ends by itself)."""
    png.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="domin-shot-profile-", ignore_cleanup_errors=True) as profile:
        args = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
                f"--user-data-dir={profile}", f"--virtual-time-budget={wait_ms + 5000}",
                f"--window-size={w + 20},{h}", f"--screenshot={png}", url]
        try:
            subprocess.run(args, capture_output=True, timeout=wait_ms / 1000 + 60, check=False)
        except subprocess.TimeoutExpired:
            print(f"{png.name}: browser timed out", file=sys.stderr)


def totp_now(secret: str) -> str:
    """The current RFC 6238 code (30 s steps, SHA-1, 6 digits), as an authenticator app shows it."""
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    value = struct.unpack(">I", digest[(o := digest[-1] & 0x0F):o + 4])[0] & 0x7FFFFFFF
    return str(value % 10**6).zfill(6)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, default=REPO / "docs" / "screenshots")
    ap.add_argument("--edge", default="", help="Edge or Chromium executable")
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--wait", type=int, default=6000, help="ms the page gets to render (charts)")
    ap.add_argument("--only", default="", help="comma-separated shot names")
    ap.add_argument("--light", default=",".join(LIGHT), help="comma-separated views also shot in the light theme"
                    " ('all' = every view)")
    ap.add_argument("--phone", default=",".join(PHONE), help=f"comma-separated views also shot {PHONE_WIDTH} px wide")
    args = ap.parse_args()
    browser = find_browser(args.edge)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    only = {x.strip() for x in args.only.split(",") if x.strip()}
    light = list(SHOTS) if args.light == "all" else [x for x in args.light.split(",") if x in SHOTS]
    with tempfile.TemporaryDirectory(prefix="domin-demo-", ignore_cleanup_errors=True) as tmp:
        os.chdir(tmp)   # relative data paths: pages that show them show "data/...", not this machine's paths
        for k in [k for k in os.environ if k.startswith("DOMIN_")]:
            del os.environ[k]
        os.environ["DOMIN_DB"] = "data/domin.db"
        settings = Settings.from_env()
        # the demo's documentation ranges stand for public addresses (the route check would call them private)
        real_public = proxy.public_address
        proxy.public_address = lambda ip: real_public(ip) or any(ipaddress.ip_address(ip) in n for n in DEMO_PUBLIC)
        db.init(settings.db_path)
        with db.connect(settings.db_path) as c:
            secret = seed_settings(c)
            seed_inventory(c)
            seed_posture(c, settings.cve_db_file)
            seed_schedules(c)
            ids = [r[0] for r in c.execute("""SELECT s.id FROM scans s JOIN domains d ON d.id = s.domain_id
                                              WHERE d.name = 'example.com' ORDER BY s.started""")]
        path, *rest = SHOTS["domain-compare"]
        SHOTS["domain-compare"] = (f"{path}?a={ids[len(ids) // 3]}&b={ids[-1]}", *rest)
        app = create_app(settings)
        client = TestClient(app, base_url="https://localhost")
        # the sign-in form as a user would fill it: password, then the authenticator app's current code
        r = client.post("/admin/login", data={"name": "alice", "password": DEMO_PASSWORD}, follow_redirects=False)
        if r.status_code != 200 or "code" not in r.text:
            raise SystemExit(f"demo sign-in failed at the password: {r.status_code}")
        r = client.post("/admin/login/totp", data={"code": totp_now(secret)}, follow_redirects=False)
        token = r.cookies.get(COOKIE)
        if r.status_code != 303 or not token:
            raise SystemExit(f"demo sign-in failed at the second factor: {r.status_code}")
        tokens = {True: token, False: ""}
        for name in {s[1] for s in SHOTS.values() if isinstance(s[1], str)}:   # power users: no second factor
            r = client.post("/admin/login", data={"name": name, "password": DEMO_PASSWORD}, follow_redirects=False)
            if r.status_code != 303 or not r.cookies.get(COOKIE):
                raise SystemExit(f"demo sign-in of {name} failed: {r.status_code}")
            tokens[name] = r.cookies.get(COOKIE)
        client.cookies.clear()   # the demo admin again (the power users' sign-ins replaced the cookie)
        client.cookies.set(COOKIE, token)
        csrf = re.search(r'name="csrf" value="([^"]+)"', client.get("/admin/settings").text)[1]
        r = client.post("/admin/settings/csv-import", data={"csrf": csrf},
                        files={"file": ("other-tool-export.csv", DEMO_CSV, "text/csv")}, follow_redirects=False)
        if r.status_code != 303:
            raise SystemExit(f"demo CSV upload failed: {r.status_code}")
        SHOTS["csv-map"] = (r.headers["location"], *SHOTS["csv-map"][1:])
        port = free_port()
        server = uvicorn.Server(uvicorn.Config(wrap(app), host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        while not server.started:
            time.sleep(0.1)
        shots = [(n, "dark", n, 0) for n in SHOTS] + [(n, "light", f"{n}-light", 0) for n in light]
        shots += [(n, t, f"{n}-{PHONE_WIDTH}" + ("-light" if t == "light" else ""), PHONE_WIDTH)
                  for n in args.phone.split(",") if n in SHOTS for t in ("dark", "light")]
        for view, theme, name, phone in shots:
            if only and name not in only:
                continue
            path, signed_in, height, script = SHOTS[view]
            SHOT.update(cookie=tokens[signed_in], theme=theme, js=script, phone=phone)
            png = out / f"{name}.png"
            url = f"http://127.0.0.1:{port}" + (f"/__phone?src={quote(path, safe='/')}" if phone else path)
            run_edge(browser, url, phone + 20 if phone else args.width, height, args.wait, png)
            print(f"{png.name}: {png.stat().st_size // 1024} KB" if png.exists() else f"{png.name}: missing")
        server.should_exit = True
        thread.join(timeout=10)
        os.chdir(REPO)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
