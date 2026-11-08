# Changes

Newest first. `deploy/install.sh` applies an update in place; the database, `/etc/domin.env` and certificates stay.

## 2026-11-08: host tags with suggested classification

- Signed-in users see a **Tags** column on a domain's records; analysts and admins add a tag (type it, Enter),
  remove one (×) or accept a **suggested** one (dashed `+ tag`). A host can carry any number of tags; they belong to
  the host name and persist across scans.
- Suggestions are rule-based: words in the host name (`www` → webserver, `cam`/`nvr` → iot-device, `nas` → storage,
  `mx`/`mail` → mailserver, `vpn` → remote-access, `dev`/`test` → non-production, …) and, once a posture scan has run,
  the open services at the host's addresses (80/443 → webserver, 1883/554 → iot-device, 9100/631 → printer,
  445 → file-share, database ports → database, …). Nothing is tagged without an analyst's click.
- **Group by tag**: tag chips with host counts above the records; a chip (or a tag) filters the table to those hosts.
- Dropping a domain drops its hosts' tags. Anonymous visitors see no tags.
- Migration: new `host_tags` table at start-up. Rollback: redeploy the previous build (the table is ignored).

## 2026-11-08: scan profiles, saved scan parameters, raw output pane

- **Security → Scan profiles**: named nmap parameter sets (ports, version intensity 0-9, timing T1-T4, per-address
  timeout, note). Analyst or admin adds, changes and deletes them; any signed-in user reads them. A `default` profile
  (the previous fixed settings: common ports, light version probes, T3, 120 s) is created at start-up and cannot be
  deleted.
- The Posture form picks a profile; its port field is now an optional override. **Renew** reuses the scan's profile
  and ports.
- Each posture scan stores its profile, knobs and the exact nmap command line next to the raw nmap XML.
- A domain's page shows signed-in users a **Security posture** section: the latest result per address, its
  parameters and the raw nmap output in a collapsed, expandable pane. Anonymous visitors do not see it.
- Migration: new `posture_profiles` table and five `posture_scans` columns, added at start-up. Rollback: redeploy the
  previous build (the extra table and columns are ignored by it).

## 2026-11-08: security posture (stage 2)

- **Security → Posture**: pick an inventoried domain, then scan the **whole domain** or **one host name**. The scan
  takes the addresses of the domain's latest inventory scan, keeps those inside the posture scope (Settings: IP and
  country rules) and fingerprints each (nmap `-sT -sV`), matching the services' CPEs against the CVE database.
- Analyst or admin starts it, only from this page; an inventory scan never starts one.
- The **worker** runs the posture queue (one address at a time; respects *Pause scans*); the web process never
  probes a target. The scope is checked again when a queued scan starts.
- Results persist in the new `posture_scans` table with their parameters (ports), requester and the raw nmap XML.
  The table shows the latest result per address with **Renew**; each address expands to its services and CVEs.
- Dropping a domain drops its posture scans. IPv6 addresses are scanned with `nmap -6`.
- Migration: the table is created at start-up; nothing else changes.

## 2026-11-08: admin can drop a domain from the inventory

- An **admin** (only) sees a **Drop from inventory** button on a domain's page. It removes that domain and all of its
  scans, records and queued/old jobs from the database (user accounts, settings and scope are untouched), then
  returns to the overview. CSRF-checked; analysts and viewers do not see or reach it.
- Destructive actions now confirm in a **styled modal popup** (naming the domain) instead of the plain browser
  prompt; the same popup covers the other destructive buttons (delete user, reset two-factor, …).
- Reversible only by re-scanning the domain (the removed history is gone); no migration.

## 2026-11-08: internal scan mode (LAN zones, no external egress)

- `DOMIN_INTERNAL_ZONES` lists domain suffixes (e.g. `home.arpa,corp.example`) scanned as internal. A scan of a name
  under one of these zones: resolves only over `DOMIN_INTERNAL_DNS` (the LAN DNS server, e.g. the house resolver),
  discovers host names over that DNS alone (no crt.sh, no amass, no public resolvers), and does no RDAP owner
  look-up — so an internal scan makes no outbound internet request and never leaks internal names upstream.
- Names under a configured internal zone pass validation even when the suffix is otherwise private (so `home.arpa`
  hosts can be scanned); a special-use suffix that is not a configured zone stays rejected.
- Private/reserved addresses the lookup returns are kept and listed (labelled "Private/reserved"), as before — this
  change makes the internal lookups actually return them instead of public DNS answers.
- Reversible: unset `DOMIN_INTERNAL_ZONES` (scans go back to the public/external path); no data change.

## 2026-11-08: Settings tick-box to disable scan limits; nav keeps admin links

- The **Settings** page gains a **Disable scan limits** tick-box (under "Scan limits"). With it on, `POST /api/scan`
  skips every visitor limit (once-per-day, per-client hour/day caps, the daily total and the queue cap), so a domain
  can be re-scanned freely. Off by default; leave it off on an instance exposed to abuse. Also settable at start with
  `DOMIN_SCAN_LIMITS_OFF=1`.
- The signed-in navigation (Security, Dashboard, Settings, Users, account) now stays on the public pages too, instead
  of dropping to just an account link when you leave the admin views.
- Settings copy: the security posture scope is labelled as governing the Host fingerprint tool (now active), not "not
  active yet".
- Reversible: untick the box (or revert the commit); no data change.

## 2026-11-08: security portal (CVE look-up and host fingerprinting)

- A Security page (analyst or admin runs it; any signed-in user reads it). Look up the known vulnerabilities (CVEs)
  of a product version (by CPE, against NVD) or a package version (by ecosystem, against OSV.dev) — the same sources
  an infrastructure vulnerability watch uses, updated continuously upstream.
- Host fingerprinting: the Host tab runs an nmap connect scan (`-sT -sV`, no OS detection and no raw packets, so no
  extra privilege) of one in-scope address, then matches each open port's service CPEs against those sources and
  lists the CVEs per service. The target's resolved address must fall inside the security posture scope (Settings).
- Local CVE database: the instance keeps its own cache (`DOMIN_CVE_DB_MODE=own`, re-queried after
  `DOMIN_CVE_TTL_DAYS`) or reads a shared one read-only (`shared` + `DOMIN_CVE_DB_PATH`). `DOMIN_NVD_API_KEY` raises
  the NVD rate limit. nmap must be installed on the host; internet access (for `own` mode) may go through a proxy via
  the usual `HTTPS_PROXY` environment variable.
- Reversible: `deploy/install.sh` applies this in place and keeps the database, `/etc/domin.env` and certificates; to
  undo, redeploy the previous build.

## 2026-11-08: signed-in area (users, roles, two-factor, scope)

- The single admin password is replaced by user accounts with roles: viewer (reads the signed-in reports), analyst
  (also runs scans and tuning) and admin (also manages users and settings). An existing `admin_password` becomes an
  `admin` user automatically on the first start.
- Optional two-factor (TOTP, standard library) per user, with one-time recovery codes; an admin can require it per
  role in Settings. Second-factor step after the password at sign-in.
- Users page (admin): add, change role, reset password (one-time set-password link), reset two-factor, disable,
  delete; the last remaining admin is protected. Account page (every user): change password, enrol/replace or turn
  off two-factor, regenerate recovery codes.
- Settings page (admin): two separate scope guardrails, one per engine, each with its own live in-scope count, plus
  the per-role two-factor requirement.
  - Domain inventory scope: a domain/suffix allow and deny list that governs the domain scanner. A scan or refresh of
    an out-of-scope domain is refused at every entry point (web, CLI, scheduled refresh, auto-retry); this engine is
    never limited by IP or geolocation.
  - Security posture scope: IP range (CIDR) allow/deny lists and a per-country allow/deny pick-list built from the
    countries present in the inventory. Stored and validated now for the later posture engine; it never affects the
    domain scanner.
- Security tab: signed-in landing page for the planned vulnerability tools, with an authorised-use notice. No
  scanning yet.
- `DOMIN_ADMIN_IPS` is now an optional network allowlist in front of the whole signed-in area; empty means the
  sign-in alone governs access.
- CLI: `domin user-add|user-list|user-passwd|user-role|user-2fa-reset`; `admin-password` still sets the `admin`
  user's password.

## 2026-11-08: uninstall script

- `deploy/uninstall.sh` removes the services, code and nginx config (keeps the database and `/etc/domin.env`);
  `--purge` also deletes the data and the `domin` user. domin is now a clean install/uninstall package.
- Reinstall fix: `install.sh` now starts/enables nginx (`enable --now`) before reloading it. On a host where domin
  is nginx's only site, `uninstall.sh` stops+disables nginx, so a bare `reload` on the next install aborted the
  script (public site down while the app ran). The uninstall → reinstall cycle now completes cleanly.

## 2026-11-08: security hardening

- No built-in admin address: `DOMIN_ADMIN_IPS` is empty by default (no admin page); `install.sh --admin-ip` sets it.
  Existing `/etc/domin.env` files keep their value.
- Both services also refuse this server's own addresses and the `--deny` list (kept as `DOMIN_DENY_IPS` in
  `/etc/domin.env` for later runs).
- Sandbox additions: `UMask=0077`, `ProcSubset=pid`, `RemoveIPC`, no `@privileged` or `@resources` system calls.
- Headers: `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`; HSTS (one year) on the
  Origin CA (Cloudflare) HTTPS server.
- Filtered searches and CSV downloads run at most two at a time per web process; others wait up to 10 s, then 503.
- Daily limit for visitor scans from all clients together: `DOMIN_SCANS_PER_DAY_TOTAL` (500), tunable on the admin
  page.
- Admin password hashes use scrypt N=2^15; older hashes are replaced at the next sign-in.
- install.sh installs the exact package versions in `deploy/requirements.txt` and no longer upgrades pip.
- install.sh turns on daily security updates (unattended-upgrades, no automatic reboot) unless the host has its own
  apt setup or `AUTO_UPDATES=off`.
- `--firewall --ssh-from CIDRS`: SSH only from those networks.
- `pip install -e .` works (package list in pyproject.toml).
- SECURITY.md: privilege model, protections, reporting a vulnerability.
