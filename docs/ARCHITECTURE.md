# Architecture

Python 3.12, FastAPI, Jinja2 (server-rendered pages), SQLite, nmap, Chart.js (vendored). No external CDN, strict
Content-Security-Policy. Security details: [HARDENING.md](HARDENING.md).

## Processes

```
browser ──HTTPS──> nginx (www-data: TLS, rate limits, X-Real-IP)
                     │ 127.0.0.1:8000
                     v
                   domin (web, uvicorn, 2 workers, user domin)  ── enqueue ──┐
                     │ reads                                                  v
                     └──────────────> SQLite /var/lib/domin/domin.db <──── domin-worker (user domin)
                                        (WAL: web reads while              │ threads: visitor scans, refreshes,
                                         the worker writes)                 │ posture slots, schedules, CSV import,
                                                                            │ hourly housekeeping
                                                                            v
                                         crt.sh, DNS, RDAP, amass, nmap, OSV/NVD (public targets only)
   Settings > Routes ── request file in /var/lib/domin ──> root path units (Tor switch, Mullvad tunnel)
```

| Process | Unit | Runs as | Role |
| --- | --- | --- | --- |
| nginx | `nginx` | `www-data` | TLS, rate and size limits, client address, proxy to 127.0.0.1:8000 |
| Web app | `domin` | `domin`, sandboxed | Pages, JSON API, sign-in; enqueues jobs; never runs scans or privileged commands |
| Worker | `domin-worker` | `domin`, sandboxed | Runs every job: inventory scans, posture scans, CVE look-ups, schedules, CSV imports |
| Tor switch | `domin-tor.path` / `.service` | root, sandboxed, no network | Turns the tor service on or off |
| Mullvad tunnel | `domin-mullvad.path` / `.service` | root, sandboxed | Applies the WireGuard tunnel settings |

## Worker
One process (`python -m domin worker`, `domin/jobs.py`), threads:

- **Visitor scans:** `DOMIN_USER_WORKERS` threads (default 3) on visitors' and admins' inventory jobs.
- **Refreshes:** `DOMIN_REFRESH_WORKERS` threads (default 2) on scheduled refreshes and schedules, a separate queue,
  so a refresh backlog never delays a visitor.
- **Posture:** 4 slots; Tuning "Posture scans at once" (1-4) decides how many take scans.
- **Schedules:** ticks every 60 s (`domin/schedules.py`).
- **CSV import:** one import at a time; sweeps expired uploads.
- **Housekeeping:** hourly: forget old client hashes, prune statistics and sign-in history, fail stuck jobs, retry
  failed domains, queue due refreshes; daily CVE refresh of stored results.
- On start: jobs left `running` fail ("worker restarted"), posture scans in progress go back to the queue.

## Inventory scan (data flow)
1. `POST /api/scan` (or Rescan, a schedule, a refresh, the CLI) validates the domain (`domin/validate.py`) and scope,
   applies the visitor limits and inserts a job.
2. The worker (`domin/scanner.py`): host names from crt.sh, common names, MX and NS, amass (passive, then active);
   A/AAAA through the public resolvers (`domin/resolvers.txt`) or, for internal zones, the internal DNS only;
   RDAP for ASN, prefix, network name and country; country from the DB-IP table when loaded.
3. Optional nmap discovery stage (`domin/discovery.py`) with a discovery profile.
4. Results are written as one scan with its records; pages compare scans over time.

## Posture scan
1. A maintainer or a schedule queues posture rows, one per address (`domin/posture.py`); scope and "Never scan"
   rules are checked when queued and again when started (`domin/netscope.py`).
2. The worker runs nmap `-sV` (TCP connect; SYN with raw sockets), through the chosen route (proxychains4 for a
   proxy, Tor or Mullvad hop) (`domin/fingerprint.py`, `domin/proxy.py`).
3. CPEs are matched against the local CVE database (`domin/cve.py`): own mode queries OSV.dev and NVD and caches the
   results (`cve_db.json`), shared mode reads another instance's file.
4. Findings, changes between scans and reports (`domin/reports.py`, PDF or Markdown) are built from the stored rows.

## Database
- SQLite in `/var/lib/domin` (`domin/db.py`), WAL mode; one connection per call site.
- Schema migrations run in `db.init` on every start, idempotent (`CREATE TABLE IF NOT EXISTS`, added columns).
- Key/value table `kv` holds Settings values, routes and tuning; scans, records, jobs, posture scans, profiles,
  schedules, users, grants, sessions, audit and visits have their own tables.
- Secrets at rest: passwords and recovery codes as scrypt hashes; TOTP secrets Fernet-encrypted with
  `/etc/domin/totp.key` (`domin/secretbox.py`).

## Sandboxing
- Both services: `NoNewPrivileges`, no capabilities, `ProtectSystem=strict` (writes only `/var/lib/domin`), private
  `/tmp` and `/dev`, system call filter, `IPAddressDeny` for every non-public address (plus this host and `--deny`),
  except the on-prem `--scan-nets` and internal DNS (a drop-in). `--raw` adds `CAP_NET_RAW`/`CAP_NET_ADMIN` to the
  worker only (`deploy/worker-raw.conf`).
- The app checks every scan target itself too; the kernel filter is the second line.
- Code in `/opt/domin` is root-owned and read-only for the services.

## Root helpers
- The app never runs privileged commands. Settings actions that need root (Tor on/off, the Mullvad tunnel) drop a
  request file in `/var/lib/domin`; a root path unit runs a fixed script from `/opt/domin` (`deploy/tor-switch.sh`,
  `deploy/mullvad-tunnel.sh`).
- The scripts read only one validated word or no-secret JSON, skip symlinks and write through fresh `mktemp` files.
- Installed only with the posture component.

## Access control
- `domin/access.py`: one route table (path → feature, level) checked for every signed-in request before its handler;
  one scope filter (`Scope`) applied in every query ([delegation.md](delegation.md)).
- `domin/components.py`: a component that is off answers 404 on all its routes, before sign-in and rights.
- `domin/guard.py`: sign-in protection after the password, before the code.

## Repository layout

| Path | Holds |
| --- | --- |
| `domin/` | The package: `web.py` (app factory, routes), `jobs.py` (worker), `scanner.py`, `posture.py`, `fingerprint.py`, `cve.py`, `discovery.py`, `schedules.py`, `proxy.py`, `mullvad.py`, `users.py`, `access.py`, `guard.py`, `totp.py`, `secretbox.py`, `syslog.py`, `csvimport.py`, `reports.py`, `admin.py`, `db.py`, `config.py`, `templates/`, `static/` |
| `deploy/` | `install.sh`, `update.sh`, `uninstall.sh`, `package.sh`, root helper units and scripts, `requirements.txt` (pinned, hashed) |
| `tests/` | pytest suite (no network) |
| `scripts/` | `screenshots.py` (demo data screenshots), `hash_requirements.py` |
| `docs/` | This documentation and `screenshots/` |
