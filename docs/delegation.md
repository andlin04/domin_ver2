# Delegation: power users with per-domain grants

Owner request (2026-11-11): power users with domains assigned to manage or audit; more admin accounts; posture
content from the assigned rights; viewer and administrative rights per domain.

## Roles
| Role | Access |
| --- | --- |
| admin | Everything: every domain, users and grants, Settings, Routes, Operations (jobs, tuning), scan profiles, public DB sync, sign-in switch. Several admins allowed. |
| power (shown "power user") | Only the domains of its grants. No global pages. |

- Last admin: an enabled admin cannot be demoted, disabled or deleted while it is the only one (409; CLI refuses).
- Old roles, migrated once on start (`db.init`, idempotent): `viewer` -> power + grant `*` viewer;
  `analyst` -> power + grant `*` domain admin. Require-2FA setting: power = viewer or analyst ticked before.
- Lost by old analysts (global, admin-only now): Operations page, tuning, job cancel/retry, scan profile edits,
  ad-hoc fingerprint of an address.

## Grants
- Table `grants (user_id, domain, level)`; one row per user and domain.
- `domain`: a domain name, or `*` = every domain (also future ones).
- Levels:
  - viewer: read that domain: inventory pages, records, search/CSV rows, posture, CVEs, changes, reports.
  - domain admin (`admin`): viewer plus that domain's actions: posture scans (whole domain, host, address,
    renew), host tags add/remove, ad-hoc fingerprint of a host name in it.
- Subdomains: a grant on `example.com` covers the domain `example.com` and every inventoried domain `*.example.com`.
- Several grants covering one domain: the highest level wins.
- Grants of an admin are kept but unused.
- Who grants: admins only. Option, not built: a domain admin grants viewer on own domains.

## Filtering
- One helper: `domin/access.py` `Scope` (for_user, sees, manages, `sql(column)` -> SQL fragment).
- Signed-in power user: every list, count, chart, search, CSV, drilldown dataset, domain picker, Changes panel,
  trend, KPIs, report and JSON endpoint is built from the granted domains only (SQL filter in the query).
- Admin, sign-in off (`DOMIN_ALLOW_NO_LOGIN` + Settings): everything (unchanged; sign-in off acts as that admin).
- Anonymous visitors: public inventory pages unchanged (public by design). Posture is signed-in only (unchanged).
- Out-of-scope object: same answer as an unknown one (404 for `/d/<name>`, compare, scan records/CSV, history,
  job; the posture page ignores an unknown `?domain=` as before).
- Action on a visible domain without domain admin: 403 with the reason.
- Admin-only (404 to power users): Users, Settings, Routes, Operations/tuning/jobs, public DB sync, sign-in switch,
  domain delete, scan profile changes (profiles stay readable).

## Not changed
- Public `POST /api/scan` (inventory scan) stays open to every visitor with its limits; it is not a grant action.

## UI
- Users page: role column, grants as pills, Edit per user.
- User edit page `/admin/users/<id>`: role; grant rows (domain picker from the inventory plus "every domain",
  level viewer / domain admin); empty domain = remove; 3 empty rows to add; same card/table/select styles.
- Audit: new table `audit` (no audit log existed): user add/role/disable/delete and grant changes, actor and time;
  last 50 on the Users page.

## Migration
- `CREATE TABLE IF NOT EXISTS grants`, `audit`; role rewrite only for rows still `viewer`/`analyst`.
- Rollback: older code lets any signed-in user read every domain's posture, and has no grants, so a `power` user
  would read everything there. Restore the pre-deploy DB backup, or first run
  `UPDATE users SET role = 'viewer' WHERE role = 'power'`, then deploy the older code. The `grants` and `audit`
  tables stay and are ignored.

## Open (owner)
- On-prem inventory pages are readable without sign-in from the allowed networks, so a power user (or anyone there)
  sees every domain's inventory, not posture. Option: an "inventory needs sign-in" switch.
- Domain admins granting viewer on their own domains.
