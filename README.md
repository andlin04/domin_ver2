# domin 2

Domain DNS and security posture inventory tool

- Two parts: a public **domain inventory** (DNS) and a signed-in **security posture** area (port and service scans,
  CVEs).
- Python 3.12, FastAPI, Jinja2, SQLite, nmap, Chart.js (vendored). No external CDN, strict Content-Security-Policy.

![Overview](docs/screenshots/overview.png)

**Contents:** [Domain inventory](#domain-inventory) · [Security posture](#security-posture) ·
[Users and admin](#users-and-admin) · [Screenshots](#screenshots) · [Install](#install) ·
[Signed-in area](#signed-in-area) · [Run locally](#run-locally) · [Legal disclaimer](#legal-disclaimer) ·
[Security](SECURITY.md) · [Changes](CHANGES.md)

## Domain inventory
Public pages. Per domain: host names, addresses, ASNs, prefixes, countries and hosting providers, and how they change
between scans.

- **Scans:** certificate transparency (crt.sh) plus common names, MX and NS; DNS A/AAAA; RDAP for ASN, prefix,
  network name and country. amass when installed. One scan per domain per day, 10 per hour per visitor.
- **Overview:** totals, scans per day, hosting countries, top providers, EU share per day, recent scan jobs,
  filterable domain table.
- **Domain page:** footprint over time, host names added and removed per scan, countries, providers, EU share over
  time, changes since the previous scan, all records (filter, sort, CSV), compare any two scans.
- **Drilldown (All):** every domain at once (`/all`, also a tab on the overview): host names, addresses, ASNs,
  countries, EU share, charts of countries, providers and ASNs (a bar click filters). Search host, address, ASN,
  prefix, network, description or country, in the latest scans or the whole history (first and last seen). Filters
  narrow figures, charts and table together; CSV download.
  - Filtering runs in the browser on a dataset fetched once (`/data/drill.json`, gzip, cached); without JavaScript the
    same filters run on the server on Enter.
- **Tables:** sort by any column; a filter box per column, the filters add up.
- **Tools:** registration data (RDAP) and e-mail security (MX, SPF, DMARC, MTA-STS, DNSSEC) for one domain.

## Security posture
Signed-in pages (`/admin`). Finds services on a domain's addresses and matches them to known CVEs.

- **Posture scans:** nmap service and version detection (`-sV`, TCP connect; SYN scans with `--raw`), one scan per address of a
  domain, queued and run by the worker. Progress and raw nmap output per scan.
- **CVE matching:** fingerprinted products (CPE) are looked up in OSV.dev and NVD; results kept in a
  local CVE database (own, or a shared read-only one). Each finding: severity, CVSS score and vector, description,
  fixed versions, NVD/OSV links.
- **Overview tab (What):** KPIs, CVEs over time (stacked by severity, addresses scanned as a line), fix available or
  not, CVEs found.
- **Analysis tab (Where):** attack surface over time, exposed services (the part with CVEs marked), findings by
  address, hosts and CVEs tables (a CVE id opens its details), changes between scans (ports opened/closed, versions,
  new, fixed and gone CVEs). A search narrows the domain list by host, address, ASN, provider, country, tag, product
  or CVE id.
- **Scans tab:** posture scans and scan activity.
- **Separate areas:** the inventory pages show DNS-scan data only; Posture (top bar, users with the right) holds
  posture results, schedules and nmap discovery, and links back through "View DNS records".
- **Scan profiles:** ports, version intensity, timing, note.
- **nmap discovery (optional):** "Scan with nmap" in Posture · Scans (one domain picked) adds an nmap stage to an inventory scan, tuned by
  a discovery profile (Settings · Discovery profiles: probe method, port check, timing, rate, retries, host timeout,
  reverse DNS, route; the command line is shown). A public domain sweeps only its own addresses; an internal domain
  the hosts of Settings · Internal networks.
- **Scheduled rescans:** per domain, listed and added in Posture · Scans (each user sees the schedules of the domains
  they hold a grant on): an inventory scan with or without a discovery profile and/or posture scans with a profile,
  on all hosts, chosen hosts or a tag; daily, weekly, monthly or every N hours/days, server local time; Run now,
  enable/disable, next and last run; a warning when a posture profile's Tor, Mullvad or proxy route meets private
  addresses.
- **Routes:** Direct, Tor, Mullvad (WireGuard tunnel, entry country/city), custom proxy (SOCKS5, SOCKS4, HTTP);
  separate route choice for posture scans, inventory jobs and CVE look-ups; DoH server.
- **Scope:** posture scope (CIDR allow/deny, country allow/deny from the inventory's countries), never-scan
  exclusions, network tags, internal domains; domain inventory scope (domain/suffix allow and deny) refused at every
  entry point.

## Users and admin
- **Roles:** admin (every domain, users, grants, settings, operations; several allowed, never fewer than one) and
  power user (only the domains granted to it). Per domain a grant is viewer (reads inventory, posture, CVEs,
  reports) or maintainer (also posture scans and host tags there); a grant covers the domains under it. Feature
  rights per power user: none / read / read-write for Inventory, Posture & CVEs, Scans & schedules, Tags, Scan
  profiles, Discovery profiles ([docs/delegation.md](docs/delegation.md)). A maintainer can add viewers to its own
  domains (domain page, Viewers). Changes to users, roles, rights and grants are logged on the Users page.
- **Sign-in:** password, optional two-factor (TOTP, recovery codes); two-factor can be required per role
  (Settings) and per user (Users, edit page; the user enrols under My account, sent there after sign-in).
  Settings, "Sign-in required for": Inventory (the public pages) and/or Posture; inventory is open by default.
  Admins create users with a password (typed or Generate, with Copy) and hand it over themselves; Set password on a
  user's page resets it and signs that user out. A user may change or keep an admin-set password at the next 3
  sign-ins; the 4th requires a new one ([docs/delegation.md](docs/delegation.md)).
- **Header:** every page shows "signed in as <name> (role)" top right and a Log out button; the name opens My
  account (no longer in the Admin menu).
- **Admin dashboard:** visits per day, recent visits, usage statistics without stored IP addresses, scan jobs
  (cancel, stop, retry), tuning without restart.

## Screenshots
Made-up demo data: documentation domains, addresses and AS numbers (example.com, 192.0.2.0/24, 2001:db8::/32,
AS64496-64511). Reproduce with `python scripts/screenshots.py`.

| | |
| --- | --- |
| ![Domain](docs/screenshots/domain.png) Domain page: footprint, changes, countries, providers, records | ![Compare](docs/screenshots/domain-compare.png) Compare two scans of a domain |
| ![Drilldown](docs/screenshots/drilldown.png) Drilldown: every domain, filters, charts, table | ![Overview, light](docs/screenshots/overview-light.png) Light theme: overview |
| ![Posture overview](docs/screenshots/posture-overview.png) Security posture, Overview: KPIs, CVEs over time | ![Posture analysis](docs/screenshots/posture-analysis.png) Security posture, Analysis: attack surface, services, findings |
| ![Posture, one domain](docs/screenshots/posture-domain.png) Analysis narrowed to one domain | ![CVE details](docs/screenshots/posture-cve.png) A host's services and a CVE opened |
| ![Posture scans](docs/screenshots/posture-scans.png) Scans tab: posture scans and activity | ![Posture, light](docs/screenshots/posture-overview-light.png) Light theme: security posture |
| ![Profiles](docs/screenshots/profiles.png) Scan profiles: ports, intensity, timing, route | ![Profiles list](docs/screenshots/profiles-list.png) Scan profiles list |
| ![Routes](docs/screenshots/routes.png) Routes: Direct, Tor, Mullvad, proxy per job type | ![Settings](docs/screenshots/settings.png) Settings: inventory scope, scan limits, internal domains |
| ![Posture scope](docs/screenshots/settings-posture.png) Settings: posture scope, never scan, network tags | ![Operations](docs/screenshots/operations.png) Admin dashboard: visits, usage, scan jobs, tuning |
| ![Users](docs/screenshots/users.png) Users: roles, two-factor | ![Account](docs/screenshots/account.png) Own account: password, two-factor |
| ![Sign in](docs/screenshots/signin.png) Sign in (password, optional authenticator code) | |

## Install
Two modes, one script: [deploy/install.sh](deploy/install.sh) (options at its top). Security model:
[SECURITY.md](SECURITY.md).

### Public (VPS)
Debian 12/13 or Ubuntu 24.04, a DNS record for the host name, as root:

```bash
git clone https://github.com/andlin04/domin_ver2.git && cd domin_ver2
bash deploy/install.sh --domain domin.example.com --email you@example.com --firewall --ssh-from 203.0.113.0/24 \
  --admin-ip 203.0.113.10
```

- Installs the app in /opt/domin, the database in /var/lib/domin, two sandboxed systemd services (`domin` web,
  `domin-worker` scans), nginx with rate limits, a Let's Encrypt certificate with renewal, daily security updates
  (`AUTO_UPDATES=off` to skip). Python packages: [deploy/requirements.txt](deploy/requirements.txt).
- **Existing history:** `--history /root/domin.db` (once).
- **Behind Cloudflare:** leave out `--email`, add `--cloudflare` (rate limits see the visitor's address), e.g.
  `--domain example.com --alias www.example.com --cloudflare`. Origin encryption: save a Cloudflare Origin CA
  certificate as `origin.crt` and its key as `origin.key` (mode 600) in a root-only directory, add
  `--origin-cert <dir>`; nginx serves 443 and accepts only Cloudflare's client certificate. In Cloudflare turn on
  Authenticated Origin Pulls first, then SSL mode Full (strict); then close port 80.
- **Update:** `git pull && bash deploy/install.sh --domain domin.example.com --email you@example.com` (database and
  certificate kept).
- **Uninstall:** `bash deploy/uninstall.sh` (database and `/etc/domin.env` kept); `--purge` also deletes the data and
  the `domin` user.

### On-prem (`--internal`)
No public name, no Let's Encrypt. A vanilla Debian 13 or Ubuntu 24.04 host (2 CPU / 2 GB / 16 GB), as root; the
installer installs every dependency (nginx, Python venv with pinned packages, nmap, tor, amass).

```bash
bash deploy/package.sh                        # build machine: dist/domin-VERSION-COMMIT.tar.gz + .sha256
# on the target (copy both files there first):
sha256sum -c domin-*.tar.gz.sha256 && tar -xzf domin-*.tar.gz && cd domin-*/
bash deploy/install.sh --internal --domain scanner.corp.example --scan-nets 10.0.0.0/8 \
  --internal-zones corp.example --internal-dns 10.0.0.53 --admin-user you
```

- **Web UI:** `https://<name>/` on 443 (80 redirects), only from `--admin-sources` (default: the private ranges;
  `any` = no network limit). `--admin-user` creates the first admin and asks for its password (twice).
- **TLS:** self-signed (`/etc/domin/tls.crt`, 825 days) until replaced: sign `/etc/domin/tls.csr` with your CA,
  write the result to `/etc/domin/tls.crt`, re-run `bash deploy/install.sh` (turns on HSTS). The key never leaves
  the host.
- **Firewall:** `--firewall` turns on ufw: SSH (`--ssh-from` to limit it), HTTP/HTTPS only from `--admin-sources`.
- **Database:** a new install starts with an empty database. To populate it from a CSV export (All records >
  CSV on this or another domin) or any CSV with a domain or host column and some record fields (comma, semicolon
  or tab separated; UTF-8 or Latin-1), upload the file in Settings > CSV import (admin, up to 200 MB). A dialog
  shows the file's columns with sample values and asks which column feeds which field (domain, host, ip, asn,
  prefix, netname, descr, country, last_seen, first_seen, eu), pre-filled from the header names and common aliases
  (hostname/fqdn/name → host, address/ip_address → ip, date/timestamp → last_seen, ...); domin's own export is
  pre-mapped, so you only press Import. Only mapped fields are imported; a host without a domain gets its domain
  from the inventory or the host name. The worker imports it in the background; an upload left unmapped is deleted
  after an hour. Or, as root, `cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin
  -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin import-csv <file> [--map field=column ...] [--delimiter ,|;|tab]` (without
  --map the guessed mapping; --map overrides it per field by header name or 1-based number). One imported scan per
  domain, timed by the file's newest "last seen"; existing scans are kept and importing the same file again adds
  nothing.
- **Scan reach:** public addresses, `--scan-nets` (this host's own addresses refused) and the `--internal-dns`
  servers. `--raw` allows nmap SYN scans (raw sockets for the worker only).
- **HTTP proxy:** in a root shell `export https_proxy=http://proxy:3128 http_proxy=$https_proxy` first (sudo:
  `sudo -E`); apt, pip and the downloads use it, and it is kept for the app.
- **Tor:** installed but off; an admin switches it under Settings > Routes (kept across updates).
- **Update:** unpack the new package, `bash deploy/install.sh` (options kept in `/etc/domin.env`; database, users and
  certificate kept). **Remove:** `bash deploy/uninstall.sh` (data kept) or `--purge`.

### Components
domin has two components: **inventory** (the DNS inventory pages, the public scan API and scheduled refreshes) and
**posture** (security posture and CVEs, scans and schedules, nmap discovery, scan profiles). Both modes install both
unless `--components` says otherwise:

```bash
bash deploy/install.sh ... --components inventory            # DNS inventory only: no nmap, Tor or root helpers
bash deploy/install.sh ... --components posture              # posture only
bash deploy/install.sh --components inventory,posture        # later: add the missing one in place (data kept)
```

- **Kept** in `/etc/domin.env` (`DOMIN_COMPONENTS`); later runs and `update.sh` follow it.
- **Posture brings** nmap, Tor, wireguard-tools, the Tor/Mullvad root helper units and (`--raw`) the worker's raw
  sockets. A run without posture removes those units, scripts and raw sockets and prints what it removed. The
  packages and all data (scans, findings, schedules) stay.
- **Settings > Components** (admin): one switch per installed component. A component that is not installed is
  greyed out and shows its install command. Off means:
  - its pages and API answer 404, and its menu entries and feature rights are hidden;
  - the worker skips its jobs and its schedules wait;
  - nothing is deleted.

  At least one component stays on. With inventory off, `/` opens Posture.
- **Posture only:** nmap discovery works as before. The CSV import is under **Posture > Import targets**, with the
  same mapping dialog as Settings > CSV import; its domains and addresses become posture targets. No page links to
  DNS records.

## Signed-in area
- Everything under `/admin`, HTTPS only.
- `DOMIN_ADMIN_IPS` (/etc/domin.env, IPs or CIDRs; set by `install.sh --admin-ip`; `systemctl restart domin` after
  editing): optional network allowlist; when set, every `/admin` path answers 404 to anyone else; when empty, the
  sign-in alone governs access.
- Client address: nginx's `$remote_addr` as X-Real-IP (with `--cloudflare`: CF-Connecting-IP, trusted only from
  Cloudflare's ranges); other forwarding headers ignored.
- **First admin** (asks for the password twice; `--password-stdin` reads one line instead; `--own`: your own
  password, so no change prompt at sign-in):

  ```bash
  cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin user-add you --role admin --own
  ```

  Without `--own` (a password you hand to someone else) the user may keep it for 3 sign-ins, then must renew it.
  Other commands: `user-list`, `user-passwd <name> [--password-stdin]` (sets it as an admin: same 3 sign-ins), `user-role <name> <admin|power>`,
  `user-grant <name> <domain|*> <viewer|admin|none>`, `user-2fa-reset <name>`,
  `admin-password` (the `admin` user's password). An existing single `admin_password` becomes an `admin` user on
  first start.
- **Two-factor key:** the TOTP secrets (and a pending enrolment) are stored encrypted (Fernet, prefix `f1:`) with
  the key in `/etc/domin/totp.key` (root:domin 0640; `DOMIN_TOTP_KEY` overrides the path). `install.sh` and
  `update.sh` create it when missing and never overwrite it; the app encrypts older plaintext values at start.
  - **Backup:** the key is backed up with the host's backup (VM image or full-host backup); no separate key backup.
    A database-only backup cannot decrypt the 2FA secrets without it. A database restored without its key still starts and signs in by password, but no TOTP code is accepted ("2FA unavailable, contact
    an admin"; recovery codes still work): reset each user's 2FA (Users page, or `user-2fa-reset <name>`), and
    they enrol again. `admin-password` and `user-passwd` need no key.
  - **New key** (as root; the CLI runs as domin):

    ```bash
    install -o domin -g domin -m 600 /dev/null /etc/domin/totp.key.new
    cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin totp-rekey --new-key /etc/domin/totp.key.new
    chown root:domin /etc/domin/totp.key.new && chmod 640 /etc/domin/totp.key.new
    mv /etc/domin/totp.key.new /etc/domin/totp.key && systemctl restart domin domin-worker
    ```

    `totp-rekey` writes a fresh key into an empty `--new-key` file (or uses the key in it) and re-encrypts every
    value in one transaction; `--old-key FILE` when the values are under another key than `DOMIN_TOTP_KEY`. A value
    the old key cannot decrypt stops it with nothing changed. Between the re-encryption and the restart, TOTP codes
    are refused.
- **Usage statistics:** visitors, page views, visit length and page order, top pages, domains, CSV downloads, tools,
  referrers, countries, scans started and refused; bots counted apart; kept 180 days.
- **Privacy:** no visitor IP addresses stored; a visitor is a hash of address + browser with a daily salt; scan rate
  limits use a salted hash. Signed-in users are the exception: their sessions keep the address, country and browser
  (the session list), and sign-in protection keeps each sign-in's address and country for the new-place days.
- **Sign-in protection** (Settings > General; each rule on by default, can be turned off):
  - **One session per user:** a new sign-in signs that user's other browsers out.
  - **New place:** a country not seen for the user in N days (default 90; the /24, or /48 for IPv6, when the
    country is unknown). With two-factor: the code step. Without: refused and waiting for an admin (Users: "Sign-ins
    waiting for approval", Approve or Deny; the user row shows "new place: approve?"). A first sign-in sets the
    baseline.
  - **Impossible travel:** over 900 km/h between the country centroids of the previous and this sign-in (same or
    unknown country: skipped): refused, all the user's sessions end, a new password and two-factor are required.
  - **Exempt:** `DOMIN_ADMIN_IPS` and the trusted ranges in Settings (the hit is still logged as "exempt").
  - **Break-glass:** the last enabled admin is never blocked, only stepped up (without two-factor it must enrol
    right after the sign-in); `admin-password` still works.
  - Every hit is in the audit log (Users, Changes) with user, address, country and rule.
- **Sessions:** My account lists your sessions (created, address, country, browser): Sign out one, or Sign out all
  others. Admins see and end a user's sessions on the user's page (Users, Edit).
- **Countries:** [DB-IP](https://db-ip.com) IP to Country Lite (CC BY 4.0), downloaded by the installer; re-run the
  installer monthly to refresh.
- **Tuning** (no restart): pause the worker, once-per-day limit, scans per hour, queue length, lookups per minute, max
  host names per scan, scheduled re-scans, statistics retention.

## Run locally

```bash
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m domin import path/to/reports     # optional: old domin's *_YYMMDD_results.csv files
.venv/bin/uvicorn --factory domin.web:create_app --port 8000
.venv/bin/python -m domin worker                     # runs queued scans
.venv/bin/python -m pytest
```

Environment: `DOMIN_DB`, `DOMIN_REFRESH_DAYS` (re-scan domains older than N days, 0 = off), `DOMIN_SCAN_WORKERS`,
`DOMIN_MAX_HOSTS`, `DOMIN_SCANS_PER_HOUR`, `DOMIN_SCANS_PER_DAY` (200), `DOMIN_SCANS_PER_DAY_TOTAL` (500 visitor scans
in 24 h, all clients), `DOMIN_USER_WORKERS` (3 parallel visitor scans), `DOMIN_REFRESH_WORKERS` (2 parallel
refreshes, separate queue), `DOMIN_SCAN_TIMEOUT_HOURS` (3), `DOMIN_AMASS`, `DOMIN_ADMIN_IPS` (who gets /admin),
`DOMIN_INTERNAL_IPS` (private API clients, e.g. over a VPN: `POST /api/scan` without the per-client, once-a-day and
queue limits; empty by default).

## Legal disclaimer
- This tool is intended for internal use.
- Scan only systems and networks you own or are explicitly authorised in writing to test.
- Unauthorised scanning may be illegal.
- Provided as is, without warranty of any kind. You are responsible for compliance with applicable law and policy.
