# Changes

Newest first. `deploy/install.sh` applies an update in place; the database, `/etc/domin.env` and certificates stay.

## 2026-11-08: uninstall script

- `deploy/uninstall.sh` removes the services, code and nginx config (keeps the database and `/etc/domin.env`);
  `--purge` also deletes the data and the `domin` user. domin is now a clean install/uninstall package.

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
