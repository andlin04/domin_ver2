# domin 2

Domain inventory: host names, addresses and hosting providers per domain, and how they change between scans.

- **Overview:** totals, scans per day, hosting countries and providers across all domains, filterable domain table.
- **Domain page:** footprint over time, host names added/removed per scan, countries and providers, changes since
  the previous scan, all records (filter, sort, CSV), compare any two scans.
- **Drilldown (All):** a tab on the overview's domain card and a page of its own (`/all`): the domain page's analysis for every domain at once: host names, addresses, domains, ASNs,
  countries and EU share, charts of countries, providers and ASNs (click a bar to filter), and every record. Search
  host, address, ASN, prefix, network, description or country, in the latest scans or the whole history (first
  and last seen); the search and the column filters narrow the figures, charts and table together. CSV download.
  Filtering runs in the browser as you type: the page fetches the whole dataset once (`/data/drill.json`, gzip'd,
  about 1.7 MB for 163k records; built once per scan, the history once an hour; cached by the browser), so many
  users filtering at once cost the server nothing. Without it (no JavaScript, load error) the same filters run on
  the server when Enter is pressed.
- **Tables:** sort by any column; a filter box under each column heading, and the filters add up (Drilldown:
  across every match, not just the page shown).
- **Tools:** registration data (RDAP) and e-mail security (MX, SPF, DMARC, MTA-STS, DNSSEC) for one domain.
- **Admin page:** usage statistics without stored IP addresses, scan job control, live tuning (see below).
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

**Behind Cloudflare** (proxied DNS, Cloudflare does HTTPS): leave out `--email`, add `--cloudflare` so rate limits
see the visitor's address, e.g. `--domain example.com --alias www.example.com --cloudflare`.
To encrypt Cloudflare → server too, create an Origin CA certificate in Cloudflare, save it as `origin.crt` and its
key as `origin.key` (mode 600) in a root-only directory and add `--origin-cert <dir>`: nginx then serves HTTPS on 443
and only accepts Cloudflare's client certificate. In Cloudflare, turn on Authenticated Origin Pulls first, then set
SSL mode to Full (strict); once traffic arrives on 443, close port 80 in the firewall.

**Update:** `git pull && bash deploy/install.sh --domain domin.example.com --email you@example.com` (keeps the
database and certificate). Options: see the top of [deploy/install.sh](deploy/install.sh).

## Admin page

At `/admin`, HTTPS only, for the client addresses in `DOMIN_ADMIN_IPS` (/etc/domin.env, comma-separated IPs or
CIDRs; the installer adds the owner's address once; `systemctl restart domin` after editing). Those clients see an
Admin link in the header; for everyone else there is no link and every /admin path answers 404. The client address
is nginx's `$remote_addr` passed as X-Real-IP (with `--cloudflare`: CF-Connecting-IP, trusted only from Cloudflare's
ranges); other forwarding headers from visitors are ignored. Set the password once:

```bash
cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- /opt/domin/venv/bin/python -m domin admin-password
```

- **Usage:** visitors, page views, visit length and pages in order, top pages, domains, CSV downloads, tools,
  referrers and countries, scans started and refused.
- **Privacy:** no IP addresses are stored. A visitor is a hash of address + browser with a salt that is replaced
  every day; scan rate limits use a salted hash too. Bots are counted apart. Statistics are kept 180 days.
- **Countries:** from [DB-IP](https://db-ip.com) IP to Country Lite (CC BY 4.0), downloaded by the installer;
  re-run the installer monthly to refresh it.
- **Jobs:** cancel queued scans, stop a running one, retry failed ones.
- **Tuning** (applies at once, no restart): pause the worker, once-per-day limit, scans per hour, queue length,
  lookups per minute, max host names per scan, scheduled re-scans, statistics retention.

## Run locally

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m domin import path/to/reports     # optional: old domin's *_YYMMDD_results.csv files
.venv/bin/uvicorn --factory domin.web:create_app --port 8000
.venv/bin/python -m domin worker                     # runs queued scans
.venv/bin/python -m pytest
```

Settings (environment): `DOMIN_DB`, `DOMIN_REFRESH_DAYS` (re-scan domains older than N days, 0 = off),
`DOMIN_SCAN_WORKERS`, `DOMIN_MAX_HOSTS`, `DOMIN_SCANS_PER_HOUR`, `DOMIN_SCANS_PER_DAY` (200),
`DOMIN_USER_WORKERS` (3 parallel visitor scans), `DOMIN_REFRESH_WORKERS` (2 parallel refreshes, a separate queue),
`DOMIN_SCAN_TIMEOUT_HOURS` (3), `DOMIN_AMASS`, `DOMIN_ADMIN_IPS` (who gets /admin).
