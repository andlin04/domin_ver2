# Configuration

Two places: environment keys in `/etc/domin.env` (root:domin, mode 640; read by both services; `systemctl restart
domin domin-worker` after editing) and the Settings pages in the web UI (stored in the database, no restart).

## Environment (`/etc/domin.env`)
Read by `domin/config.py` (`Settings.from_env`). Defaults suit a local run; `install.sh` writes `DOMIN_DB`,
`DOMIN_REFRESH_DAYS=0`, `DOMIN_QUEUE_MAX=50`, `DOMIN_LOOKUPS_PER_MINUTE=30` on first install and the keys of its
options. Booleans: `1`, `true`, `yes` or `on`. Lists: comma-separated.

| Key | Default | Meaning |
| --- | --- | --- |
| `DOMIN_DB` | `domin.db` (installed: `/var/lib/domin/domin.db`) | SQLite database file |
| `DOMIN_REFRESH_DAYS` | `0` | Re-scan domains whose last scan is older than N days; 0 = off |
| `DOMIN_SCAN_WORKERS` | `20` | Parallel DNS lookups per scan |
| `DOMIN_MAX_HOSTS` | `3000` | Cap on candidate host names per scan |
| `DOMIN_SCANS_PER_HOUR` | `10` | Visitor scans (`POST /api/scan`) per client per hour |
| `DOMIN_SCANS_PER_DAY` | `200` | Visitor scans per client per day |
| `DOMIN_SCANS_PER_DAY_TOTAL` | `500` | Visitor scans in 24 h from all clients together |
| `DOMIN_QUEUE_MAX` | `50` | Queued visitor jobs before new ones are refused |
| `DOMIN_SCAN_LIMITS_OFF` | off | Skip all visitor limits (once-per-day, rate, quota, queue) |
| `DOMIN_USER_WORKERS` | `3` | Parallel scans for visitors' jobs |
| `DOMIN_REFRESH_WORKERS` | `2` | Parallel scans for scheduled refreshes (separate queue) |
| `DOMIN_SCAN_TIMEOUT_HOURS` | `3` | A longer scan fails at its next progress step |
| `DOMIN_LOOKUPS_PER_MINUTE` | `30` | RDAP and e-mail tool lookups per client per minute |
| `DOMIN_ANALYTICS_DAYS` | `180` | Visit statistics older than this are deleted |
| `DOMIN_AMASS` | `/usr/local/bin/amass` | amass binary, used when it exists |
| `DOMIN_ADMIN_IPS` | empty | Optional network allowlist (IPs/CIDRs) for `/admin`: when set, everyone else gets 404; empty = the sign-in alone governs access. Also exempt from sign-in protection. Set by `install.sh --admin-ip` |
| `DOMIN_HIDE_SIGNIN_LINK` | off | No "Sign in" link in the menu; `/admin` still works by URL |
| `DOMIN_INTERNAL_IPS` | empty | Private API clients (e.g. over a VPN): `POST /api/scan` without the per-client, once-a-day and queue limits; keep `/api/` when the inventory requires sign-in |
| `DOMIN_INTERNAL_ZONES` | empty | Domain suffixes scanned internally (resolved through `DOMIN_INTERNAL_DNS`, no public lookups). Also Settings · Internal domains |
| `DOMIN_INTERNAL_DNS` | empty | Resolver addresses for internal zones |
| `DOMIN_INTERNAL_NETS` | empty | Networks whose addresses are reverse-looked-up for names in internal scans. Also Settings · Internal networks |
| `DOMIN_CVE_DB_MODE` | `own` | `own`: this instance maintains its CVE database (queries OSV/NVD); `shared`: read one from elsewhere, read-only, no network |
| `DOMIN_CVE_DB_PATH` | next to `DOMIN_DB` (`cve_db.json`) | CVE database file (shared mode: the file to read) |
| `DOMIN_CVE_TTL_DAYS` | `7` | Own mode: re-query a target whose cached result is older |
| `DOMIN_NVD_API_KEY` | empty | Optional NVD API key (higher rate limit) |
| `DOMIN_ALLOW_NO_LOGIN` | off | Dev/lab only: Settings may turn sign-in off. Refused unless `DOMIN_ADMIN_IPS` is set (public install: private networks only); the stand-in session counts only for those addresses |
| `DOMIN_INSTALL_MODE` | `public` | `internal` = on-prem (`install.sh --internal`) |
| `DOMIN_SCAN_NETS` | empty | On-prem: private networks the scans may reach (`--scan-nets`) |
| `DOMIN_COMPONENTS` | both | Installed components: `inventory`, `posture` (`--components`) |
| `DOMIN_TOTP_KEY` | `/etc/domin/totp.key` | Two-factor encryption key file |

Kept by `install.sh` for later runs (the app does not read them):

| Key | Set by |
| --- | --- |
| `DOMIN_HOSTNAME` | `--domain` (on-prem) |
| `DOMIN_ADMIN_SOURCES` | `--admin-sources` |
| `DOMIN_RAW_SCANS` | `--raw` / `--no-raw` |
| `DOMIN_DENY_IPS` | `--deny` |
| `DOMIN_SSH_FROM` | `--ssh-from` |
| `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` | the root shell's `http_proxy` / `https_proxy` / `no_proxy` at install; also used by the app |

Other: `DOMIN_APP` (`update.sh`: app directory, default `/opt/domin/app`), `DOMIN_SHOT_BROWSER`
(`scripts/screenshots.py`: browser path), `AUTO_UPDATES=off` (`install.sh`: no unattended-upgrades). Retired: `DOMIN_PUBLIC_SYNC` (removed from
`/etc/domin.env` by `install.sh` and `update.sh`).

## Tuning (Operations page)
Admin dashboard, no restart; overrides the environment value while set.

| Setting | Range |
| --- | --- |
| Pause the scan worker (queued jobs wait) | on/off |
| Each domain at most once per day | on/off |
| Scans per hour per client | 0-1000 |
| Scans per day per client | 0-100000 |
| Visitor scans per day, all clients together | 0-100000 |
| Queued visitor scans before new ones are refused | 1-10000 |
| A scan fails after N hours | 1-48 |
| Posture scans at once (each picks its own route exit) | 1-4 |
| RDAP / e-mail lookups per minute per client | 1-1000 |
| Max host names per scan | 10-50000 |
| Re-scan domains older than N days (0 = off) | 0-3650 |
| Keep visit statistics N days | 1-3650 |

## Settings pages (admin)

| Page | Holds |
| --- | --- |
| General | Domain inventory scope (domain/suffix allow and deny); scan limits; internal domains, internal DNS and internal networks; security posture scope (CIDR and country allow/deny), never scan, network tags, raw network access; sign-in required for (Inventory, Posture); require two-factor per role; sign-in protection (rules, new-place days, trusted ranges); sign-in off (dev/lab, `DOMIN_ALLOW_NO_LOGIN` only); CSV import |
| Scan profiles | Posture scan profiles: ports, version intensity, timing, route, note |
| Discovery profiles | nmap discovery profiles and the default ([scheduled-scans.md](scheduled-scans.md)) |
| CVE look-up | CVEs for a host, product or package; about the CVE database; exploit data: last update and error per source, on/off (default on; off hides the markers and skips the daily downloads, kv `exploits:off`) |
| Routes | Direct, Tor (on/off), Mullvad (account, entry country/city), custom proxies; route per job type; DoH server |
| Components | Turn installed components on or off |
| Logging | Syslog server, port, protocol (UDP/TCP/TLS), facility, app-name; test message |

Users (roles, grants, rights, two-factor, sessions, sign-ins waiting for approval) and Operations (jobs, tuning,
statistics) are separate admin pages ([FEATURES.md](FEATURES.md)).
