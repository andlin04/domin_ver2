# Install

Two modes, one script: [deploy/install.sh](../deploy/install.sh) (every option is described at its top). Security
model: [HARDENING.md](HARDENING.md). Settings after install: [CONFIGURATION.md](CONFIGURATION.md).

**Contents:** [Requirements](#requirements) · [Public (VPS)](#public-vps) · [Behind Cloudflare](#behind-cloudflare) ·
[On-prem](#on-prem---internal) · [Options](#installsh-options) · [Components](#components) ·
[First admin](#first-admin) · [Firewall](#firewall) · [Backup](#backup) · [Update](#update) ·
[Uninstall](#uninstall)

## Requirements
- Debian 12/13 or Ubuntu 24.04 or newer (Python 3.12+), root.
- On-prem sizing: 2 CPU / 2 GB / 16 GB disk.
- Public mode: a DNS record for the host name pointing at the server.
- The installer installs every dependency: nginx, a Python venv with the pinned packages
  ([deploy/requirements.txt](../deploy/requirements.txt), hash-checked), and with the posture component nmap, tor and
  wireguard-tools; amass (pinned release, SHA-256 checked) for subdomain discovery; the DB-IP country table.

## Public (VPS)
As root:

```bash
git clone https://github.com/andlin04/domin_ver2.git && cd domin_ver2
bash deploy/install.sh --domain domin.example.com --email you@example.com --firewall --ssh-from 203.0.113.0/24 \
  --admin-ip 203.0.113.10
```

- Installs the app in `/opt/domin`, the database in `/var/lib/domin`, two sandboxed systemd services (`domin` web,
  `domin-worker` scans), nginx with rate limits, a Let's Encrypt certificate with renewal, daily security updates
  (`AUTO_UPDATES=off` to skip).
- **Existing history:** `--history /root/domin.db` (once; loaded only when the server has no database yet, unless
  `--replace-history`, which keeps the old one as `.bak`).
- Without `--email` the site is served on plain HTTP only (use with Cloudflare, below).
- **Client address:** nginx's `$remote_addr` as X-Real-IP (with `--cloudflare`: CF-Connecting-IP, trusted only from
  Cloudflare's ranges); other forwarding headers are ignored. Rate limits, statistics and `DOMIN_ADMIN_IPS` use it.

## Behind Cloudflare
- Leave out `--email`, add `--cloudflare` (rate limits see the visitor's address: CF-Connecting-IP, trusted only from
  Cloudflare's published ranges), e.g. `--domain example.com --alias www.example.com --cloudflare`.
- **Origin encryption:** save a Cloudflare Origin CA certificate as `origin.crt` and its key as `origin.key` (mode
  600) in a root-only directory, add `--origin-cert <dir>`; nginx serves 443 and accepts only Cloudflare's client
  certificate (and refuses unknown host names in the TLS handshake).
- In Cloudflare turn on Authenticated Origin Pulls first, then SSL mode Full (strict); then close port 80.

## On-prem (`--internal`)
No public name, no Let's Encrypt. A vanilla Debian 13 or Ubuntu 24.04 host, as root.

```bash
bash deploy/package.sh                        # build machine: dist/domin-VERSION-COMMIT.tar.gz + .sha256
# on the target (copy both files there first):
sha256sum -c domin-*.tar.gz.sha256 && tar -xzf domin-*.tar.gz && cd domin-*/
bash deploy/install.sh --internal --domain scanner.corp.example --scan-nets 10.0.0.0/8 \
  --internal-zones corp.example --internal-dns 10.0.0.53 --admin-user you
```

- **Web UI:** `https://<name>/` on 443 (80 redirects), only from `--admin-sources` (default: the private ranges;
  `any` = no network limit). `--domain` defaults to `hostname -f`.
- **TLS:** self-signed (`/etc/domin/tls.crt`, 825 days) until replaced: sign `/etc/domin/tls.csr` with your CA, write
  the result to `/etc/domin/tls.crt`, re-run `bash deploy/install.sh` (turns on HSTS). The key never leaves the host.
- **Scan reach:** public addresses, `--scan-nets` (this host's own addresses refused) and the `--internal-dns`
  servers. `--raw` allows nmap SYN scans (raw sockets for the worker only).
- **Database:** a new install starts with an empty database; populate it by scans or a CSV import
  ([FEATURES.md](FEATURES.md#csv-import)).
- **HTTP proxy:** in a root shell `export https_proxy=http://proxy:3128 http_proxy=$https_proxy` (and `no_proxy`)
  first (sudo: `sudo -E`); apt, pip and the downloads use it, and it is kept in `/etc/domin.env` for the app.
- **Tor:** installed but off; an admin switches it under Settings > Routes (kept across updates).

## install.sh options
Every option is kept in `/etc/domin.env`: later runs need no options (`bash deploy/install.sh`).

| Option | Mode | Meaning |
| --- | --- | --- |
| `--domain D` | both | Host name (public: DNS must point here; on-prem: default `hostname -f`) |
| `--email E` | public | Let's Encrypt account; without it plain HTTP only |
| `--alias A` | public | Extra host name for the same site |
| `--cloudflare` | public | Client address from CF-Connecting-IP (Cloudflare ranges only) |
| `--origin-cert DIR` | public | With `--cloudflare`: HTTPS with a Cloudflare Origin CA certificate, Authenticated Origin Pulls |
| `--history FILE` | public | SQLite database with existing scan history; `--replace-history` to overwrite one |
| `--admin-ip CIDRS` | both | Optional network allowlist for `/admin` (`DOMIN_ADMIN_IPS`) |
| `--deny CIDRS` | both | Extra addresses the app and scans may never connect to |
| `--firewall` | both | ufw: SSH, HTTP, HTTPS ([Firewall](#firewall)) |
| `--ssh-from CIDRS` | both | With `--firewall`: SSH only from these networks |
| `--no-worker` | both | Install the scan worker but don't start it |
| `--internal` | on-prem | On-prem mode: own TLS certificate, HTTPS only |
| `--admin-sources C` | on-prem | Networks that may open the site at all (default private ranges; `any`) |
| `--scan-nets CIDRS` | on-prem | Private networks the scans may reach |
| `--internal-zones Z` | on-prem | DNS zones scanned as internal |
| `--internal-dns IPS` | on-prem | DNS servers for those zones |
| `--raw` / `--no-raw` | on-prem | Give or take the worker's raw sockets (nmap SYN scans) |
| `--admin-user NAME` | on-prem | Create the first admin; asks for its password twice |
| `--components LIST` | both | `inventory`, `posture` or both (default both) |
| `AUTO_UPDATES=off` (env) | both | No automatic security updates |

## Components
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
- Installed components can be turned off and on in Settings > Components ([FEATURES.md](FEATURES.md#components)).

## First admin
On-prem, `--admin-user` does this. Otherwise, or for another admin (asks for the password twice; `--password-stdin`
reads one line instead; `--own`: your own password, so no change prompt at sign-in):

```bash
cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin user-add you --role admin --own
```

Without `--own` (a password you hand to someone else) the user may keep it for 3 sign-ins, then must renew it. Other
user commands: [OPERATIONS.md](OPERATIONS.md#commands). The signed-in area is under `/admin`, HTTPS only.

## Firewall
- `--firewall` turns on ufw: SSH (`--ssh-from` to limit it, kept for later runs), HTTP and HTTPS.
- On-prem, HTTP and HTTPS are open only to `--admin-sources` (unless `any`), so the firewall and nginx both enforce
  that list.
- Behind Cloudflare with `--origin-cert`: close port 80 to the internet once Cloudflare connects on 443.
- ufw rules are left in place by the uninstaller.

## Backup
- **What:** `/var/lib/domin` (the database `domin.db` and the CVE cache), `/etc/domin.env` (settings),
  `/etc/domin/` (on-prem TLS key and certificate, and the two-factor key `totp.key`).
- **Two-factor key:** `/etc/domin/totp.key` is backed up with the host's backup (VM image or full-host backup); there
  is no separate key backup. A database-only backup cannot decrypt the 2FA secrets without it.
- **Restore without the key:** the app still starts and signs in by password, but no TOTP code is accepted ("2FA
  unavailable, contact an admin"; recovery codes still work): reset each user's 2FA (Users page, or
  `user-2fa-reset <name>`), and they enrol again. `admin-password` and `user-passwd` need no key.
- The package and the repository hold no database; a new install starts empty.

## Update
- **Public (clone):** `git pull && bash deploy/install.sh` (options kept in `/etc/domin.env`; e.g. the first run's
  `--domain domin.example.com --email you@example.com` need not be repeated). Database and certificate kept.
- **On-prem (package):** unpack the new package, `bash deploy/install.sh` (options kept in `/etc/domin.env`; database,
  users and certificate kept).
- **Code-only update:** [deploy/update.sh](../deploy/update.sh) reads a tar of `domin/` and `deploy/` (stdin or a file
  with its `.sha256`, or `--sha256 HEX`), copies what differs and restarts only what it needs:
  `git archive HEAD domin deploy | ssh <host> 'sudo bash /opt/domin/app/deploy/update.sh'`. Unit files and dependency
  changes need `install.sh`.
- **Countries:** re-run the installer monthly to refresh the DB-IP table.
- Each release note in [CHANGES.md](../CHANGES.md) has a Rollback line.

## Uninstall
- `bash deploy/uninstall.sh`: removes the services, units and code; the database, `/etc/domin.env` and `/etc/domin`
  are kept.
- `bash deploy/uninstall.sh --purge`: also deletes that data and the `domin` user (copy `/var/lib/domin/domin.db`
  first).
- Distribution packages, the Let's Encrypt certificate, apt security-update settings and ufw rules stay.
