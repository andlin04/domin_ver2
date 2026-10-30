# domin 2

Domain inventory: host names, addresses and hosting providers per domain, and how they change between scans.

- **Overview:** totals, scans per day, hosting countries and providers across all domains, filterable domain table.
- **Domain page:** footprint over time, host names added/removed per scan, countries and providers, changes since
  the previous scan, all records (filter, sort, CSV), compare any two scans.
- **Tools:** registration data (RDAP) and e-mail security (MX, SPF, DMARC, MTA-STS, DNSSEC) for one domain.
- **Scans:** certificate transparency (crt.sh) plus common names, MX and NS; DNS A/AAAA; RDAP for ASN, prefix,
  network name and country. amass is used when installed. One scan per domain per day, 10 per hour per visitor.

Python 3.12, FastAPI, Jinja2, SQLite, Chart.js (vendored). No external CDN, strict Content-Security-Policy.

## Install on a VPS

Debian 12/13 or Ubuntu 24.04, a DNS record for your host name pointing at the server, then as root:

```bash
git clone https://github.com/andlin04/domin_ver2.git && cd domin_ver2
bash deploy/install.sh --domain domin.example.com --email you@example.com --firewall
```

This installs the app in /opt/domin, the database in /var/lib/domin, two systemd services (`domin` web,
`domin-worker` scans), nginx with rate limits, and a Let's Encrypt certificate with automatic renewal.

**Existing history:** copy a database to the server and pass it once:

```bash
scp domin.db root@your-vps:/root/
bash deploy/install.sh --domain domin.example.com --email you@example.com --history /root/domin.db
```

**Update:** `git pull && bash deploy/install.sh --domain domin.example.com --email you@example.com` (keeps the
database and certificate). Options: see the top of [deploy/install.sh](deploy/install.sh).

## Run locally

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m domin import path/to/reports     # optional: old domin's *_YYMMDD_results.csv files
.venv/bin/uvicorn --factory domin.web:create_app --port 8000
.venv/bin/python -m domin worker                     # runs queued scans
.venv/bin/python -m pytest
```

Settings (environment): `DOMIN_DB`, `DOMIN_REFRESH_DAYS` (re-scan domains older than N days, 0 = off),
`DOMIN_SCAN_WORKERS`, `DOMIN_MAX_HOSTS`, `DOMIN_SCANS_PER_HOUR`, `DOMIN_AMASS`.
