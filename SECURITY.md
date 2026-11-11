# Security

## Reporting a vulnerability
Report it privately through GitHub: this repository's **Security** tab > **Report a vulnerability**. Please don't open
a public issue for it.

## Privilege model
| Part | Runs as | Can do |
| --- | --- | --- |
| nginx | `www-data` | TLS (Let's Encrypt, or a Cloudflare Origin CA certificate with Cloudflare's client certificate required), rate limits, proxies to 127.0.0.1:8000 |
| domin (web, uvicorn) | `domin`, systemd sandbox | Reads and writes only `/var/lib/domin`; outbound HTTPS for the RDAP and e-mail tools |
| domin-worker (scans) | `domin`, systemd sandbox | Same files; DNS, crt.sh, RDAP and amass towards public addresses only |
| amass | child of the worker | Gets only `PATH` and a temporary `HOME`, none of the app's settings |

- **No root at run time.** install.sh runs as root once; both services run as the unprivileged `domin` user. The
  code in `/opt/domin` belongs to root and is read-only for the services. install.sh and update.sh set that
  (`chown -R root:root`, `chmod -R go-w`) after every copy; update.sh refuses archives with links, devices or paths
  outside `domin/` and `deploy/`, checks a `.sha256` next to a file (or `--sha256 HEX`), reads only proxy
  `KEY=VALUE` lines from `/etc/domin.env` (never runs it as shell code) and removes bytecode caches; CLI commands run
  as `domin` with `PYTHONDONTWRITEBYTECODE=1`.
- **Sandbox** (both services): `NoNewPrivileges`, no capabilities, `ProtectSystem=strict` (writes only to
  `/var/lib/domin`), private `/tmp` and `/dev`, no home directories, kernel tunables/modules/logs protected, no
  namespaces, a `@system-service` system call filter without `@privileged` and `@resources`, only IP, Unix and netlink
  sockets, `UMask=0077`. Limits: web 2 GB memory and 200 tasks, worker 16 GB and 2000 tasks.
- **Scans can't be aimed inward.** A scanned domain's DNS decides where the tools connect, so the kernel refuses
  every non-public address for both services and all their child processes (`IPAddressDeny`), plus this server's own
  addresses and the `--deny` list. Outbound HTTP requests also refuse non-HTTPS URLs and non-public targets on every
  redirect, and cap the response size.
- **The app checks scan targets itself** (the kernel filter has exceptions: the web unit allows localhost for nginx,
  the Mullvad tunnel adds 127.0.0.1 and its relay network, and an empty posture allow-list allows everything). Before
  a fingerprint (in the web process) or a posture scan is queued, and again when the worker starts it, every address
  is checked, for a host name every address it resolves to: a public install accepts global addresses only
  (loopback, RFC 1918, link-local, CGNAT 100.64/10, unique-local, documentation and other special-use ranges are
  refused); an on-prem install (`--internal`) also its `--scan-nets` and Settings · Internal networks, never
  loopback, unspecified or multicast.
- **Settings:** `/etc/domin.env` (root, group `domin`, mode 640). The admin password is a scrypt hash in the database.

## Web
- **Admin page:** served only to `DOMIN_ADMIN_IPS` (empty by default: no admin page); everyone else gets the same 404
  as an unknown path. The client address comes from nginx (`X-Real-IP`, trusted from localhost only; behind Cloudflare
  `CF-Connecting-IP` from Cloudflare's published ranges only). Password (scrypt, N=2^15, constant-time comparison),
  5 failed sign-ins in 15 minutes block the client (30 in total block everyone; a wrong current password or code on
  My account counts too), session and second-factor cookies `__Host-` (Path=/), Secure, HttpOnly, SameSite=Strict,
  CSRF token on every form, `Cache-Control: no-store`. Changing the password needs the current one; turning
  two-factor off needs the current password or a code. A new set-password link is shown once to the admin who made
  it, kept server-side for that session (never in a redirect URL).
- **`DOMIN_ALLOW_NO_LOGIN`** (dev/lab only): refused at start-up (sign-in stays on, an error is logged) unless
  `DOMIN_ADMIN_IPS` is set, and on a public install it may list private networks only; while accepted a warning is
  logged at every start and the stand-in session counts only for requests from `DOMIN_ADMIN_IPS`.
- **Scan requests:** JSON only (a cross-site form can't send one), per-client limits per hour and day, a daily limit
  for all visitors together, one scan per domain per day, a bounded queue.
- **Load:** nginx limits requests and connections per client and request sizes; filtered searches and CSV downloads
  run at most two at a time per web process (others wait briefly, then get 503).
- **Headers:** a Content-Security-Policy that allows only the site's own files (no inline script), `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Cross-Origin-Resource-Policy`; HSTS with Let's Encrypt, on the Origin CA (Cloudflare) setup and on-prem once the
  certificate is CA-signed.
- **Output:** templates escape everything; script-built HTML escapes third-party text; CSV cells that a spreadsheet
  would run as a formula are prefixed with `'`.
- **Privacy:** no IP addresses are stored; visitors are a daily-salted hash, scan clients a salted hash kept 24 hours.

## Supply chain
- Python packages: the exact versions in `deploy/requirements.txt` (no "newest at install time"), the full
  dependency set, each with PyPI's SHA-256 hashes; install.sh and update.sh install with `--require-hashes`, so a
  changed or substituted file is refused (`scripts/hash_requirements.py` writes the hashes after a version raise). Check them for known vulnerabilities (PyPI advisory database / OSV) before each release:
  `pip-audit -r deploy/requirements.txt --disable-pip --no-deps`; 2026-11-11 (with segno 1.6.6): none found.
- amass: a pinned release, checked against its SHA-256 before it is installed.
- System packages come from the distribution; install.sh turns on daily security updates (unattended-upgrades, no
  automatic reboot) unless the host has its own apt setup or `AUTO_UPDATES=off`.
- Chart.js is vendored; pages load nothing from other sites.

## Network
- `--firewall`: ufw with HTTP, HTTPS and SSH; `--ssh-from` limits SSH to the networks you list (kept for later runs). On-prem, HTTP and
  HTTPS are open only to `--admin-sources` (unless `any`), so the firewall and nginx both enforce that list.
- The package and the repository hold no database; a new install starts empty. Data comes in only through scans
  and Settings > CSV import; no root unit or SSH key on the host receives database copies.
- CSV import (Settings, admins only; others get 404): the upload is streamed to a temp file in /var/lib/domin
  (never held in memory), at most 200 MB (nginx allows a larger body on that one path only, 4 kB elsewhere; the
  app counts the bytes and stops at the cap), CSRF token in the form, one file and at most five fields. The
  uploaded file waits for the column mapping under a random token (24 bytes) bound to the uploading user and
  session: another user, another session or an unknown token gets 404. It is deleted on Cancel, when the token is
  used past its lifetime, and at the latest about an hour after the upload (UPLOAD_TTL 3600 s; the worker's import
  thread sweeps every 5 s and also removes upload files older than an hour that nothing holds or queued). A queued
  file is deleted when its import finishes or fails. Only the mapped columns are read; every mapped field is
  checked (domain name as for a scan, host name syntax, IP address, ASN, network prefix, ISO dates, EU flag, text
  length and control characters) and the exporter's formula escape `'` is removed. Bad rows are skipped and
  counted, out-of-scope domains skipped; existing scans are never changed or deleted. The worker runs it (no work
  in the web request), the staging files are removed afterwards, and the import is written to the audit log (who,
  file name, counts, delimiter, encoding and the mapping).
- Behind Cloudflare with `--origin-cert`, nginx accepts HTTPS only with Cloudflare's client certificate and refuses
  unknown host names in the TLS handshake; close port 80 to the internet once Cloudflare connects on 443.

## On-prem install (`--internal`)
- HTTPS only (port 80 just redirects); TLS 1.2/1.3, EC P-256 key in `/etc/domin/tls.key` (root, 600), read only by
  nginx's master process, never by the app. Self-signed until you install a CA-signed certificate from the CSR;
  re-run install.sh after that to turn on HSTS (never sent with a self-signed certificate).
- nginx answers only `--admin-sources` (default the private ranges); the sign-in, roles and optional two-factor
  govern `/admin` on top.
- Roles: admin, or power user limited to granted domains (viewer or domain admin per domain, covering the domains
  under it). One scope filter in every list, search, CSV, chart, count and posture query; an object outside a
  power user's grants answers 404 like an unknown one. Feature rights per power user (none / read / read-write per
  feature) are checked once per request from one route table before any handler runs: no right answers 404, read
  only on a change 403. Admins grant; a domain admin may only give existing power users a viewer grant on its own
  domains (audited). Operations, Settings, Routes and Users stay admin-only. The last enabled admin cannot be
  demoted, disabled or deleted. Inventory pages stay public to visitors without a session unless Settings,
  "Sign-in required for: Inventory" is ticked (then the sign-in page; API, CSV and drill data 401; private API
  clients of `DOMIN_INTERNAL_IPS` keep /api/). Posture always needs a session; the lab stand-in (sign-in turned off,
  `DOMIN_ALLOW_NO_LOGIN`) counts there only while "Posture" is unticked. Two-factor can be required per role and per
  user; such a user is sent to My account after each sign-in until enrolled, and cannot turn it off.
- The scan sandbox still refuses every non-public address except `--scan-nets` and `--internal-dns`, written as a
  systemd drop-in; this host's own addresses are cut out of those networks (systemd lets an allow entry win over
  any deny entry). The web service gets no internal networks, only the HTTP proxy, if one is set.
- `--raw` gives the scan worker CAP_NET_RAW/CAP_NET_ADMIN for nmap SYN scans; off by default, `--no-raw` removes it.
- nmap discovery: a profile holds no targets. A public domain's stage sweeps only the global addresses that scan's
  DNS stages tied to the domain, inside the posture scope; an internal domain's stage the hosts of Settings ·
  Internal networks inside the posture IP scope (cap 8192). Every argument comes from an allowlist (method, port
  lists of digits and ranges, bounded numbers, route id), passed as an argv list with a 0600 temporary targets file:
  no free text reaches the command line. Raw-only probes (ACK, UDP, ICMP) need `--raw` and Settings · Raw network
  access. It runs in the worker's sandbox like every scan. Only admins edit discovery profiles.
- Scheduled rescans queue normal jobs (same queue, limits, scopes and sandbox); domain admins manage those of their
  domains, every change is in the audit table.

## Root helpers
- The app never runs privileged commands. Settings actions that need root (Tor on/off, the Mullvad tunnel) drop
  a request file in `/var/lib/domin`; a root path unit runs a fixed script from
  `/opt/domin`. Tor is installed but off until an admin turns it on.
- `/var/lib/domin` belongs to the app user, so those scripts read only one validated word or no-secret JSON from it,
  skip symlinks, and write only through fresh `mktemp` files renamed into place (never a fixed temporary name).
- The helper services are sandboxed (`systemd-analyze security`: 3.0 Tor, 4.3 Mullvad, from 9.6):
  read-only system except the paths each one writes, a short capability list, no new privileges, private /tmp and
  devices; the Tor switch also has no network.
