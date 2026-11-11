# Scheduled rescans and nmap discovery profiles

Owner requests (2026-11-11):
1. Schedule rescans of a domain, with a scanning profile and the hosts to rescan.
2. Discovery scan profiles to tune the nmap parameters of a discovery scan.

## A. nmap discovery stage

- Optional stage of an inventory (discovery) job, after the DNS stages and owner look-ups. Off unless the job names
  a discovery profile. The public `POST /api/scan` never sets one, and neither do refreshes or retries.
- Who starts it:
  - a domain admin of that domain: "Scan with nmap" in Posture · Scans, one domain picked (profile picker)
  - a schedule (B)
- What it sweeps:

| Mode | Targets |
| --- | --- |
| public (domain not under an internal zone) | the addresses this scan's DNS stages tied to the domain's host names. Only global (public) addresses, only those inside the posture scope (IP allow/deny, countries). |
| internal (domain under Settings · Internal zones) | the hosts of Settings · Internal networks (private IPv4, at most 8192 addresses, as for the PTR sweep), minus addresses outside the posture IP scope |

- Never: other addresses, ranges typed by a user, or targets from the profile. The profile holds no targets.
- At most 8192 targets per job (admin.SWEEP_MAX). Over the cap: the first 8192 are swept, plus a note.
- Sandbox unchanged: the worker's IPAddressDeny still refuses every non-public address except `--scan-nets` and
  the internal DNS servers. No new unit, capability or privileged path. Raw probes only where the worker already
  has raw sockets (`--raw`) and Settings · Raw network access is on.
- Results per scan (table `discovery_results`): address, name(s) nmap reported, open ports, why it counted as up.
  Shown in Posture · Scans (one domain picked: its latest scan with the stage) with the command line that ran (`scans.discovery_params`). The worker log has it too.
- Inventory effect:
  - internal: a live address whose reverse name (the LAN DNS servers, `--dns-servers`) is under the domain and not
    yet in the scan becomes a record (host name, address).
  - public: none; liveness and open ports only.
  - A live address without a name is listed in the results only; no invented host names.
- Routes:
  - internal: always direct, like the rest of an internal scan.
  - public: the profile's route; Default = the inventory route (Settings · Routes). A proxy route carries only
    `-Pn` with a port check (connect scan): any other combination skips the stage with a note, never a direct run.
    A broken route skips the stage with the reason (fail closed). Reverse DNS is forced off (`-n`) through a proxy.
- Failure of the stage (nmap missing, timeout, skipped) never fails the inventory job: notes on the scan.

### Discovery profile parameters (table `discovery_profiles`)

Every value is checked against this list; no free text reaches argv. The note is never part of argv.

| Field | Allowed | nmap |
| --- | --- | --- |
| name | `[a-z0-9][a-z0-9_-]{0,39}` | none |
| method | `default` / `none` / `syn` / `ack` / `udp` / `echo` / `timestamp` | none / `-Pn` / `-PS<list>` / `-PA<list>` / `-PU<list>` / `-PE` / `-PP` |
| probe ports | syn/ack/udp only (required there): port list, at most 100 ports | glued to -PS/-PA/-PU |
| port check | `none` / `top` / `list` | `-sn` / `--top-ports N` / `-p <list>` (with `-sT`, or `-sS` when raw) |
| top N | 1-1000 | `--top-ports N` |
| port list | at most 1024 ports | `-p` |
| timing | 0-5 | `-T0`..`-T5` |
| max rate | 0 (unset) or 1-10000 packets/s | `--max-rate N` |
| max retries | 0-10 | `--max-retries N` |
| host timeout | 10-3600 s | `--host-timeout Ns` |
| reverse DNS | on/off | `-R` (internal: plus `--dns-servers <internal DNS>`) / `-n` |
| route | Default / Direct / a route id from Settings · Routes | proxychains4 (see Routes) |

- Port list: comma-separated `N` or `N-M`, 1 <= N <= M <= 65535, digits only. Refused: `hello`, `80;echo probe`, `-1`,
  `99999`, `1-2-3`.
- Raw-only methods: `ack`, `udp`, `echo`, `timestamp`. Save is refused unless Settings · Raw network access is on and
  the worker reported raw sockets; at run time without them the stage is skipped with a note. Raw adds
  `--privileged`; a port check then uses `-sS`.
- Refused combination: `none` (-Pn) with port check `none` (it would report every target as up).
- Fixed parts: `nmap`, `-oX -`, `-iL <targets file>` (mode 0600, removed after the run), `-6` for an IPv6 batch.
- The profile page shows the resulting command line per profile, read-only (`<targets>` in place of the file).
- Row `default` (cannot be deleted): `-PS22,80,443 -sn -n -T3 --max-retries 1 --host-timeout 120s --max-rate 100`.
- A profile used by a schedule cannot be deleted (409 with the schedule names); same for posture profiles.

### Choosing a profile

- Manual: the "Scan with nmap" form in Posture · Scans (domain admins).
- Schedule: per schedule (B).
- Default: Settings · Discovery profiles, "Default profile" = preselected in both forms; "none" = DNS only.

## B. Scheduled rescans (table `schedules`)

- Belongs to one domain (one with a finished inventory scan).
- Fields:
  - name (1-60 characters), enabled
  - discovery: on/off, discovery profile (or "DNS only")
  - posture: on/off, posture profile
  - posture hosts: `all` (at run time) / `list` (chosen from the latest inventory: checkbox list) / `tag` (the host
    names carrying a host or network tag at run time)
  - recurrence: `daily` at HH:MM / `weekly` weekday at HH:MM / `monthly` day 1-31 at HH:MM / every N hours (1-168,
    from the first HH:MM) / every N days (1-365, at HH:MM). No cron text.
  - next_run, last_run, last job, last result
- At least one of discovery and posture.

### Times

- Server local time, wall clock.
- `next_ts` (epoch) decides when a schedule is due; `next_run` is its local display text.
- Month end: day 29-31 in a shorter month runs on its last day.
- DST:
  - a time inside the spring-forward gap runs at the same clock time + 1 h (02:30 -> 03:30)
  - a time inside the repeated autumn hour runs once, at its first occurrence
  - every N hours: real elapsed hours, so the clock time shifts by 1 h across a change
- Edit or re-enable: next_run is computed again from now.

### Runner

- The worker's schedule thread ticks every 60 s (`schedules.tick`), like the hourly housekeeping thread.
- Due (`next_ts <= now`), enabled:
  1. previous run of the same schedule still queued or running (its inventory job, the job it waits for, or its
     posture rows): skip, log, last result "skipped: previous run still queued or running"
  2. domain outside the inventory scope (Settings) now: skip with that reason
  3. else queue:
     - discovery: `jobs.enqueue` (client `schedule`, the refresh queue, same one-open-job-per-domain rule and
       worker limits). A job already open for the domain is joined, not doubled; then its parameters apply.
     - posture only: `posture.enqueue` now, with the profile and host selection; scope and "Never scan" rules
       as for a manual scan (`posture.targets`).
     - discovery + posture: posture is queued by a later tick once that inventory job is done, on its new
       inventory; failed/cancelled job: no posture, the reason as the result.
- next_run: the first slot after now. Missed runs after downtime run once, no catch-up.
- Chosen hosts no longer in the latest inventory: skipped, named in the last result and marked on the list.
- Posture profile or discovery profile deleted meanwhile: deletion is refused while used.
- Run now: queues at once if nothing of the schedule is open (else 409); next_run unchanged.
- Domain deleted: its schedules go with it.

## Rights (docs/delegation.md)

| Action | admin | domain admin of the domain | viewer of the domain | outside the grants |
| --- | --- | --- | --- | --- |
| see the domain's schedules (Posture · Scans list) | yes | yes | yes (read-only) | not listed; 404 |
| add / edit / delete / enable / run now | yes | yes | 403 | 404 |
| the domain in the add form's domain picker | yes | yes | no | no |
| "Scan with nmap" in Posture · Scans | yes | yes | 403 | 404 |
| discovery profiles: read | yes | yes | yes | yes (no domain data) |
| discovery profiles: add / edit / delete / default | yes | 403 | 403 | 403 |

- Audit table: schedule add, edit, delete, enable/disable, run now; discovery profile save, delete, default.
- The worker runs a schedule without its creator: scope and posture rules apply at run time; the creator's rights
  are not checked again (open: owner).

## UI

- Posture · Scans, "Scheduled rescans" section (below the scan activity): the schedules of the domains in the
  user's scope (admins: all; the page's Domain filter narrows it), with Edit, Run now, Enable/Disable and Delete on
  the domains the user is domain admin of (viewer rows read-only), and "Add a schedule" with a domain picker of
  those domains (hidden when there are none). Filter the page to one domain to pick single hosts or a tag.
  Actions return to the list with the filter they came from.
- Edit page `/admin/schedules/<id>`: the schedule and its form.
- Posture · Scans with one domain picked: an nmap discovery card ("Scan with nmap" with a profile picker, the latest
  scan with the stage and what it found). The domain page (DNS inventory) shows no schedules.
- Operations: a count and a link to the section.
- Settings · Discovery profiles: list with command line, add/edit form, delete, default picker.

## Route check

A posture scan of a private address fails on a Tor or Mullvad route ("private address can't go through Mullvad");
a custom proxy usually cannot reach one. Private = the domain is under Settings · Internal zones, or a non-global
address among the hosts the schedule's posture part covers (latest inventory).

- Form: the posture profile picker names each profile's proxy or VPN route; a note under it lists the profiles that
  would fail on the domain (on any internal or private domain when none is picked).
- Save (add or edit): with a warning the form comes back (409) with the reason and a "Save anyway" box.
- List: a schedule with the problem shows the reason under "Runs".
- Discovery profiles: no check; an internal domain's nmap stage always runs direct, and a public domain's sweeps
  only public addresses.

## Migration (db.init, idempotent)

- New tables `discovery_profiles` (+ `default` row), `discovery_results`, `schedules`.
- New columns: `jobs.discovery`, `jobs.schedule_id`, `scans.discovery`, `scans.discovery_params`,
  `posture_scans.schedule_id`.
- Rollback: older code ignores the new tables and columns. Disable all schedules first
  (`UPDATE schedules SET enabled = 0`), then deploy the older code.

## Open (owner)

- Add live internal addresses without a name to the inventory (address as host name), so posture can scan them?
- Re-check the creator's rights when a schedule runs (a domain admin who lost the grant)?
- Apply the default discovery profile to automatic refreshes (refresh_days) too?
