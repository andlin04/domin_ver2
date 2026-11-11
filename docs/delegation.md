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
- Anonymous visitors: public inventory pages, unless Sign-in (below) requires it. Posture is signed-in only.

## Sign-in (owner 2026-11-11)
- Settings, "Sign-in required for": Inventory, Posture, both or neither (kv `auth:signin`).
- Inventory (inventory pages, all records, domain pages, search, CSV, drill data, whois/e-mail tools, `POST
  /api/scan`): unticked = open to every visitor that reaches the site (as before; public mode: the internet).
  Ticked: no session -> 303 to `/admin?next=<page>` (the sign-in page; after sign-in back to that page); API, drill
  data, CSV and posts -> 401. Private API clients (`DOMIN_INTERNAL_IPS`) keep `/api/`.
- Posture (posture pages, CVEs, scans, schedules, tags): always needs a user. Unticked only matters on a lab server:
  the stand-in of "Turn sign-in off" (`DOMIN_ALLOW_NO_LOGIN`) then counts there. Without that variable the box stays
  ticked.
- Admin area (Operations, Settings, Routes, Users, profiles, account): a session, or the lab stand-in.
- The stand-in counts in the admin area always, in Inventory and Posture only where unticked. "Turn sign-in off"
  also unticks Posture and turning it on ticks it again (the old switch's meaning).
- Migration (`db.init`, once): inventory open; posture required unless sign-in was off then. Nothing changes until
  an admin saves the setting. Audit: `sign-in`.
- Public mode with "neither": unchanged (inventory public, posture and admin behind sign-in).

## Two-factor
- Required per role (Settings) or per user (Users, edit page: "Require two-factor for this user"; column
  `users.totp_required`), either one is enough. Same edit page: reset button, link to My account.
- Enrolment: the user, under My account: Set up two-factor, adds the secret (or the otpauth link) to an
  authenticator app, confirms with a code; recovery codes shown once.
- A user who must have it and has none is sent to My account after each sign-in; once on, it cannot be turned off
  by the user (admins reset it). Audit: `require-2fa`, `reset-2fa`.
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
- Domain admins granting viewer on their own domains.
- Sign-in: My account shows the secret and an otpauth link, no QR image (needs a QR encoder; none is installed).
