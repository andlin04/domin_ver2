# Delegation: power users with per-domain grants

Design notes. Goal: power users with domains assigned to manage or audit; more admin accounts; posture
content from the assigned rights; viewer and administrative rights per domain.

## Roles
| Role | Access |
| --- | --- |
| admin | Everything: every domain, users and grants, Settings, Routes, Operations (jobs, tuning), scan profiles, CSV import, sign-in switch. Several admins allowed. |
| power (shown "power user") | Only the domains of its grants, only the features of its rights (below). No admin-only pages. |

- Last admin: an enabled admin cannot be demoted, disabled or deleted while it is the only one (409; CLI refuses).
- Old roles, migrated once on start (`db.init`, idempotent): `viewer` -> power + grant `*` viewer;
  `analyst` -> power + grant `*` maintainer. Require-2FA setting: power = viewer or analyst ticked before.
- Lost by old analysts (global, admin-only now): Operations page, tuning, job cancel/retry, scan profile edits,
  ad-hoc fingerprint of an address.

## Grants
- Table `grants (user_id, domain, level)`; one row per user and domain.
- `domain`: a domain name, or `*` = every domain (also future ones).
- Levels:
  - viewer: read that domain: inventory pages, records, search/CSV rows, posture, CVEs, changes, reports.
  - maintainer (`admin`): viewer plus that domain's actions: posture scans (whole domain, host, address,
    renew), host tags add/remove, ad-hoc fingerprint of a host name in it.
- Subdomains: a grant on `example.com` covers the domain `example.com` and every inventoried domain `*.example.com`.
- Several grants covering one domain: the highest level wins.
- Grants of an admin are kept but unused.
- Who grants: admins (any grant, Users page); a maintainer: viewer only, on a domain it is maintainer of
  (Domain viewers, below).

## Feature rights
- Per power user, per feature: none / read / read-write (column `users.rights`, JSON). Admins: everything.
- Features:

| Feature | Read | Read-write adds |
| --- | --- | --- |
| Inventory | inventory pages, all records, domain pages, search, CSV, drill data, whois/e-mail tools | (read only) |
| Posture & CVEs | posture overview and analysis, CVEs, changes, reports, CVE look-up page | (read only) |
| Scans & schedules | Posture · Scans: scan activity, scheduled rescans | posture scans and renew, Scan with nmap, CVE look-ups and fingerprints, schedules |
| Tags | host tags on domain and posture pages | add and remove host tags |
| Scan profiles | the list | add, change, delete |
| Discovery profiles | the list | add, change, delete, the default |

- Admin-only, not in the matrix: Operations (jobs, tuning, visits, dropping a domain), Settings and Routes (incl.
  sign-in), Users (users, roles, rights, grants). Global data with no domain to filter on, or user management.
- How rights and grants combine: the right decides whether the user may use a feature at all, the grants on which
  domains. Reading a domain's data needs read on the feature and a grant (viewer or maintainer) covering the
  domain. An action on a domain needs read-write on the feature and maintainer of the domain. Profiles have no
  domain: read-write on the feature is enough.
- Enforcement: one table, `domin/access.py` `ROUTES` (path -> feature, level; GET = read, other methods = write
  unless fixed), checked for every signed-in request before its handler (`web.signin_gate`). No right: 404, as an
  unknown page. Read without read-write on a change: 403 "may only read". Templates hide links, tabs, buttons and the
  Tags column by the same rights (`access.can`, `access.acts`).
- Anonymous visitors: rights don't apply; the inventory stays public unless Sign-in requires it.
- Migration (`db.init`, once): every existing user gets the abilities power users had before: Inventory, Posture,
  Scan profiles, Discovery profiles read; Scans & schedules, Tags read-write. New users get the same; admins change
  them on the edit page (audit `rights`).

## Domain viewers
- Admin menu > Domain viewers (`GET /admin/viewers?domain=<name>`), for a maintainer of any domain (and admins):
  pick a domain you administer (admins: every domain), see the grants on exactly that domain, "Add viewer" (a pick
  of enabled power users, not the actor) and "Remove" on viewer rows. No maintainer grant: 404. The inventory
  domain page shows no viewer box.
- Only a viewer grant on exactly that domain (it covers the domains under it). Never: making users, maintainer
  grants, admins, lowering a maintainer grant (409), the actor's own grants.
- Routes: `POST /admin/domains/<name>/viewers` (form `user`), `POST /admin/domains/<name>/viewers/<id>/delete`;
  both go back to the page. Not maintainer there: 403 ("needs maintainer rights"); domain outside the grants or unknown: 404. Audit:
  `grant-viewer`, `revoke-viewer`.

## Filtering
- One helper: `domin/access.py` `Scope` (for_user, sees, manages, `sql(column)` -> SQL fragment).
- Signed-in power user: every list, count, chart, search, CSV, drilldown dataset, domain picker, Changes panel,
  trend, KPIs, report and JSON endpoint is built from the granted domains only (SQL filter in the query).
- Admin, sign-in off (`DOMIN_ALLOW_NO_LOGIN` + Settings): everything (unchanged; sign-in off acts as that admin).
- Anonymous visitors: public inventory pages, unless Sign-in (below) requires it. Posture is signed-in only.

## Sign-in
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

## Passwords set by an admin
- Users > Add a user: name, role, Password + Confirm (Generate fills both with 20 random characters in the browser,
  Show/Hide, Copy). A user's edit page: Set password (same fields), which ends that user's sessions. Users list:
  Set password links there. Policy: the two fields match, 12+ characters (`users.password_problem`, also the CLI).
- The admin hands the password over; nothing is shown or sent by domin. Audit: `user-add`, `set password (admin)`;
  the user's own change: `password changed (self)`. No secret in any of them.
- Columns `users.pw_set_by_admin` (1 after an admin set it) and `users.pw_grace_left` (3 then; -1 = must renew).
- Each successful sign-in (after the code, if 2FA is on) with the mark counts one: sign-ins 1-3 open "Your password
  was set by an admin. Change it now?" (`/admin/account/renew`) with the change form and "Keep it (N of 3 left)",
  which goes on to the page the sign-in was for. The 4th sign-in locks every session of the user to that page and
  Sign out: other pages redirect there, the API and form posts answer 403. Setting a password (not the admin's) there
  or under My account clears the mark and the lock; this browser stays signed in, others are signed out.
- Current password: not asked within 15 minutes of the sign-in (the session's age), asked after that.
- Order with two-factor: the code comes first; a user who must enrol is sent to My account first (as before), which
  shows the offer with a link; a locked user renews first, then enrols.
- Users list: "preset password, N grace sign-ins left" or "must renew" in the Status column.
- An admin set or reset (web or CLI `user-passwd`) restores 3. CLI `user-add NAME [--role R] [--password-stdin]
  [--own]`: asks twice on a terminal or reads one stdin line; `--own` (the installer's first admin) leaves no mark.
- Removed: the one-time set-password links (`/admin/set-password`, 24 h tokens in kv `setpw:*`, the admin's copy in
  `setpw-link:*`); `db.init` deletes leftover keys, no table was involved.

## Two-factor
- Required per role (Settings) or per user (Users, edit page: "Require two-factor for this user"; column
  `users.totp_required`), either one is enough. Same edit page: reset button, link to My account.
- Enrolment: the user, under My account: Set up two-factor, adds the secret (or the otpauth link) to an
  authenticator app, confirms with a code; recovery codes shown once.
- A user who must have it and has none is sent to My account after each sign-in; once on, it cannot be turned off
  by the user (admins reset it). Audit: `require-2fa`, `reset-2fa`.
- Out-of-scope object: same answer as an unknown one (404 for `/d/<name>`, compare, scan records/CSV, history,
  job; the posture page ignores an unknown `?domain=` as before).
- Action on a visible domain without maintainer rights: 403 with the reason.
- Admin-only (404 to power users): Users, Settings, Routes, Operations/tuning/jobs, CSV import, sign-in switch,
  domain delete. Profile changes follow the feature rights.

## Not changed
- Public `POST /api/scan` (inventory scan) stays open to every visitor with its limits; it is not a grant action.

## UI
- Users page: role column, grants as pills, Edit per user.
- User edit page `/admin/users/<id>`: role; grant rows (domain picker from the inventory plus "every domain",
  level viewer / maintainer); empty domain = remove; 3 empty rows to add; same card/table/select styles.
- Audit: new table `audit` (no audit log existed): user add/role/disable/delete and grant changes, actor and time;
  last 50 on the Users page.

## Migration
- `CREATE TABLE IF NOT EXISTS grants`, `audit`; role rewrite only for rows still `viewer`/`analyst`.
- Rollback: older code lets any signed-in user read every domain's posture, and has no grants, so a `power` user
  would read everything there. Restore the pre-deploy DB backup, or first run
  `UPDATE users SET role = 'viewer' WHERE role = 'power'`, then deploy the older code. The `grants` and `audit`
  tables stay and are ignored.

## Open questions
- Default rights of new power users: the migration defaults (above); "none" everywhere would be stricter.
