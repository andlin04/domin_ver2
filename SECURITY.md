# Security policy

## Reporting a vulnerability
Report it privately through GitHub: this repository's **Security** tab > **Report a vulnerability**. Please don't open
a public issue for it. Include the version (commit or package name), the install mode (public or `--internal`), steps
to reproduce and the impact you see.

## Supported versions
Only the latest commit on `main` (and packages built from it with `deploy/package.sh`) gets fixes. Update with
`deploy/install.sh` or `deploy/update.sh` ([docs/INSTALL.md](docs/INSTALL.md#update)).

## Hardening summary
- **No root at run time:** the web app and the scan worker run as the unprivileged `domin` user in systemd sandboxes;
  the code is root-owned and read-only for them. Settings actions that need root go through fixed, sandboxed helper
  units.
- **Scans can't be aimed inward:** the kernel (`IPAddressDeny`) and the app both refuse non-public targets, except the
  networks an on-prem install allows (`--scan-nets`, internal DNS).
- **Sign-in:** scrypt password hashes, rate-limited sign-in, optional or required two-factor (TOTP secrets encrypted at
  rest), sign-in protection (one session per user, new place, impossible travel), `__Host-` cookies, CSRF tokens,
  audit log, optional syslog.
- **Web:** strict Content-Security-Policy (no inline script, nothing from other sites), security headers, escaped
  output, CSV formula escaping, nginx rate and size limits.
- **Supply chain:** pinned Python packages with SHA-256 hashes (`--require-hashes`), amass checked against its
  SHA-256, vendored Chart.js, daily distribution security updates.
- **Privacy:** no visitor IP addresses stored (salted hashes); signed-in sessions keep address and country.

Details: [docs/HARDENING.md](docs/HARDENING.md).

## Scope note
domin is a scanner: scan only systems and networks you own or are explicitly authorised in writing to test.
