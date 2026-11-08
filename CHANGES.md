# Changes

Newest first. `deploy/install.sh` applies an update in place; the database, `/etc/domin.env` and certificates stay.

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
