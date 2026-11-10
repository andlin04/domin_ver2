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
- **Signed-in area:** user accounts with roles (viewer / analyst / admin), optional two-factor (TOTP), a Users page,
  a Settings/scope page and a Security tab, plus the admin dashboard (usage statistics without stored IP addresses,
  scan job control, live tuning — see below).
- **Scans:** certificate transparency (crt.sh) plus common names, MX and NS; DNS A/AAAA; RDAP for ASN, prefix,
  network name and country. amass is used when installed. One scan per domain per day, 10 per hour per visitor.

Python 3.12, FastAPI, Jinja2, SQLite, Chart.js (vendored). No external CDN, strict Content-Security-Policy.

## Install on a VPS

Debian 12/13 or Ubuntu 24.04, a DNS record for your host name pointing at the server, then as root:

```bash
git clone https://github.com/andlin04/domin_ver2.git && cd domin_ver2
bash deploy/install.sh --domain domin.example.com --email you@example.com --firewall --ssh-from 203.0.113.0/24 \
  --admin-ip 203.0.113.10
```

This installs the app in /opt/domin, the database in /var/lib/domin, two sandboxed systemd services (`domin` web,
`domin-worker` scans), nginx with rate limits, a Let's Encrypt certificate with automatic renewal, and daily
security updates (`AUTO_UPDATES=off` to skip). Python packages are the tested versions in
[deploy/requirements.txt](deploy/requirements.txt). Security model: [SECURITY.md](SECURITY.md); changes:
[CHANGES.md](CHANGES.md).

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

**Uninstall:** `bash deploy/uninstall.sh` removes the services, code and nginx config but keeps the database and
`/etc/domin.env`; `bash deploy/uninstall.sh --purge` also deletes the data and the `domin` user. Reinstall any time
with `install.sh`.

## Install on-prem (internal network)

The vulnerability and posture platform for your own networks: no public name, no Let's Encrypt. A vanilla
Debian 13 or Ubuntu 24.04 host (VM or bare metal, 2 CPU / 2 GB / 16 GB), as root; the installer installs every
dependency (nginx, Python venv with pinned packages, nmap, tor, amass, ...).

```bash
bash deploy/package.sh                        # on a build machine: dist/domin-VERSION-COMMIT.tar.gz + .sha256
# on the target (copy both files there first):
sha256sum -c domin-*.tar.gz.sha256 && tar -xzf domin-*.tar.gz && cd domin-*/
bash deploy/install.sh --internal --domain scanner.corp.example --scan-nets 10.0.0.0/8 \
  --internal-zones corp.example --internal-dns 10.0.0.53 --admin-user you
```

- **Web UI:** `https://<name>/` on 443 (80 redirects), only from `--admin-sources` (default: the private ranges;
  `any` = no network limit). `--admin-user` prints a one-time link to set the first admin's password (24 h).
- **TLS:** self-signed (`/etc/domin/tls.crt`, 825 days) until you replace it: sign `/etc/domin/tls.csr` with your CA,
  write the result to `/etc/domin/tls.crt`, `systemctl reload nginx`. The key never leaves the host.
- **What scans may reach:** public addresses, plus `--scan-nets` (private networks; this host's own addresses stay
  refused) and the `--internal-dns` servers. `--raw` allows nmap SYN scans (raw sockets for the worker only).
- **Behind an HTTP proxy:** in a root shell `export https_proxy=http://proxy:3128 http_proxy=$https_proxy` first
  (with sudo: `sudo -E`); apt, pip and the downloads use it and it is kept for the app.
- **Update:** unpack the new package, `bash deploy/install.sh` (options are kept in `/etc/domin.env`; database,
  users and certificate stay). **Remove:** `bash deploy/uninstall.sh` (data kept) or `--purge`.

## Signed-in area

Everything under `/admin`, HTTPS only. `DOMIN_ADMIN_IPS` (/etc/domin.env, comma-separated IPs or CIDRs;
`install.sh --admin-ip` sets it; `systemctl restart domin` after editing) is an **optional network allowlist** in
front of the whole area: when it is set, every `/admin` path (including the sign-in page) answers 404 for anyone
else; when it is **empty, the sign-in alone governs access**. The client address is nginx's `$remote_addr` passed as
X-Real-IP (with `--cloudflare`: CF-Connecting-IP, trusted only from Cloudflare's ranges); other forwarding headers
from visitors are ignored.

**Users and roles.** viewer reads the signed-in reports; analyst also runs scans and tuning; admin also manages
users and settings. Create the first admin on the server (it prints a one-time link to set the password):

```bash
cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- /opt/domin/venv/bin/python -m domin user-add you --role admin
```

Other commands: `user-list`, `user-passwd <name>`, `user-role <name> <role>`, `user-2fa-reset <name>`;
`admin-password` sets the `admin` user's password. An existing single `admin_password` becomes an `admin` user on
the first start.

- **Two-factor:** each user can enrol a TOTP authenticator with one-time recovery codes on their Account page; an
  admin can require it per role on the Settings page, and reset a user's two-factor from the Users page.
- **Settings / scope:** two separate guardrails, one per engine, each with its own live count:
  - *Domain inventory scope* — a domain/suffix allow and deny list that governs the domain scanner (crt.sh / DNS /
    RDAP). A scan or refresh of a domain outside the allow list, or on the deny list, is refused at every entry point
    (web `/api/scan`, the `scan` CLI, scheduled refreshes and auto-retries). This engine is never limited by IP
    address or geolocation.
  - *Security posture scope* — IP range (CIDR) allow/deny lists and a per-country allow/deny pick-list built from the
    countries actually present in the inventory (DB-IP values). Validated and stored now for the vulnerability /
    posture engine of a later phase; it never affects the domain scanner.
- **Security tab:** the signed-in landing page for the planned fingerprinting and CVE reports, with an
  authorised-use notice. No scanning yet.

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
`DOMIN_SCANS_PER_DAY_TOTAL` (500 visitor scans in 24 h from all clients together),
`DOMIN_USER_WORKERS` (3 parallel visitor scans), `DOMIN_REFRESH_WORKERS` (2 parallel refreshes, a separate queue),
`DOMIN_SCAN_TIMEOUT_HOURS` (3), `DOMIN_AMASS`, `DOMIN_ADMIN_IPS` (who gets /admin), `DOMIN_INTERNAL_IPS`
(private API clients, e.g. over a VPN: `POST /api/scan` without the per-client, once-a-day and queue limits; empty
by default).
