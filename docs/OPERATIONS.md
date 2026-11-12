# Operations

## Running a command
The CLI is `python -m domin <command>`. On an installed host run it as root through the `domin` user, with the
settings loaded and no bytecode written:

```bash
cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin <command>
```

Below, `domin <command>` stands for that line.

## Commands

| Command | Does |
| --- | --- |
| `init` | Create the database (every command does this when needed) |
| `worker` | Run queued scans (and scheduled refreshes when `DOMIN_REFRESH_DAYS` > 0); the `domin-worker` service |
| `scan <domain>` | Queue an inventory scan (checked against the inventory scope) |
| `import <dir>` | Import the old domin's `reports/<domain>_<YYMMDD>_results.csv` files |
| `import-csv <file> [--map field=column ...] [--delimiter ,\|;\|tab]` | Load a CSV as imported scans ([FEATURES.md](FEATURES.md#csv-import)); without `--map` the guessed mapping; `--map` overrides it per field by header name or 1-based number |
| `geoip <csv>` | Load a DB-IP "IP to Country Lite" CSV (`.csv` or `.csv.gz`); the installer does this |
| `refresh-fixes` | Update the fixed versions on stored posture findings |
| `refresh-exploits` | Download the exploit data now (CISA KEV, Exploit-DB, Metasploit, FIRST EPSS, PoC-in-GitHub; also part of the daily CVE refresh); prints the status per source, exit 1 when a source failed (its old data stays), 2 when posture or the feature is off |
| `user-add <name> [--role admin\|power] [--password-stdin] [--own]` | Create a user; password asked twice (or one stdin line); `--own`: your own password, no renewal prompt |
| `user-list` | List users: role, 2FA, disabled, last sign-in, grants |
| `user-passwd <name> [--password-stdin]` | Set a password as an admin (the user may keep it for 3 sign-ins); signs the user out |
| `user-role <name> <admin\|power>` | Change a role (the last admin cannot be demoted) |
| `user-grant <name> <domain\|*> <viewer\|maintainer\|none>` | Grant a power user a level on a domain and the domains under it (`admin` = maintainer, the stored name) |
| `user-2fa-reset <name>` | Turn a user's two-factor off |
| `admin-password` | Set the `admin` user's password (break-glass; needs no 2FA key) |
| `totp-rekey --new-key FILE [--old-key FILE]` | Re-encrypt every two-factor secret with a new key ([below](#new-two-factor-key)) |

An existing single `admin_password` (older versions) becomes an `admin` user on first start.

## New two-factor key
As root (the CLI runs as domin):

```bash
install -o domin -g domin -m 600 /dev/null /etc/domin/totp.key.new
cd /opt/domin/app && set -a && . /etc/domin.env && runuser -u domin -- env PYTHONDONTWRITEBYTECODE=1 /opt/domin/venv/bin/python -m domin totp-rekey --new-key /etc/domin/totp.key.new
chown root:domin /etc/domin/totp.key.new && chmod 640 /etc/domin/totp.key.new
mv /etc/domin/totp.key.new /etc/domin/totp.key && systemctl restart domin domin-worker
```

- `totp-rekey` writes a fresh key into an empty `--new-key` file (or uses the key in it) and re-encrypts every value
  in one transaction; `--old-key FILE` when the values are under another key than `DOMIN_TOTP_KEY`.
- A value the old key cannot decrypt stops it with nothing changed.
- Between the re-encryption and the restart, TOTP codes are refused.
- The key file: `/etc/domin/totp.key` (root:domin 0640; `DOMIN_TOTP_KEY` overrides the path). `install.sh` and
  `update.sh` create it when missing and never overwrite it; the app encrypts older plaintext values at start. Backup
  and restore without the key: [INSTALL.md](INSTALL.md#backup).

## Services and logs

| Unit | What |
| --- | --- |
| `domin` | Web app (uvicorn, 2 workers, 127.0.0.1:8000 behind nginx) |
| `domin-worker` | Scan worker |
| `domin-tor.path` / `.service` | Root helper: Tor on/off from Settings > Routes (posture) |
| `domin-mullvad.path` / `.service` | Root helper: Mullvad tunnel from Settings > Routes (posture) |

- Logs: `journalctl -u domin -u domin-worker`; optional syslog forwarding (Settings > Logging).
- Audit log: Users page (Changes); every admin change, sign-in protection hit and CSV import.
- Jobs: Operations page (cancel, stop, retry; pause the worker under Tuning).

## Releases
- Each change has an entry in [CHANGES.md](../CHANGES.md) with a Rollback line.
- Before a release: `pip-audit -r deploy/requirements.txt --disable-pip --no-deps`; after a version raise
  `python scripts/hash_requirements.py` rewrites the hashes.
- On-prem package: `bash deploy/package.sh [REF]` (refuses a dirty tree for HEAD).
