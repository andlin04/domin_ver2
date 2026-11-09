# Changes

Newest first. `deploy/install.sh` applies an update in place; the database, `/etc/domin.env` and certificates stay.

## 2026-11-09: Posture Filter on the Domain row

- The Filter box sits in the same row as the Domain picker, pushed to the right; the scan form starts the next row.
- Rollback: revert this change.

## 2026-11-09: Posture Filter narrows the page; expandables stand out

- The search box is now "Filter", last in the panel on the right. Besides the Domain list it narrows the page: all
  domains = the domain table rows; one domain = the host rows (name, addresses, service, product, version, port,
  CVE ids, severities, notes) and the CVE rows (CVE, severity, products, fixed versions, addresses). Every word must
  match, any case. KPIs and charts stay for the whole domain.
- Expandables: accent chevrons, larger; a hover tint on every expandable row; an accent edge on open sections.
- Rollback: revert this change.

## 2026-11-09: search the Posture domain picker

- A search box next to the Domain list narrows it to the domains whose data holds every typed word, any case: domain
  and host names, addresses, ASN (also "AS8075"), prefix, network name, description, country, host tags, and the
  latest posture results (service, product, version, port, CVE ids, severities). Enter opens the first match. The
  server answers (`GET /admin/security/domain-search?q=`, signed in), so the page stays small.
- Rollback: revert this change.

## 2026-11-09: Admin menu in the top bar

- Operations and Settings moved under one "Admin" entry that drops down (marked active on their pages; a click
  elsewhere or Escape closes it). Users and the account link stay where they were.
- Rollback: revert this change.

## 2026-11-09: posture views by depth, trend charts

- Posture, all domains: one row per domain (worst, CVEs per severity, fixable, addresses with high+, open ports,
  last scan, blocked/failed/queued); a name opens the domain. No per-address lists; Changes shows its counters only.
- Posture, one domain: the host table gets a CVEs tab (each CVE once, products, fixed versions, the addresses it
  hits; an address opens its host row). `?host=` lists that host only and opens its row. The per-address CVE
  findings table is gone (the CVEs tab and the host rows hold it).
- Charts: CVEs over time per severity (critical, high, medium, low), attack surface over time (open ports,
  addresses scanned), fix available, exposed services. Dropped: riskiest addresses (= the host table sorted by
  Worst) and scan age (= the Last scan column).
- Domain page (signed in): a posture summary (KPIs + CVE trend + Open in Posture) instead of the full report.
- Rollback: revert this change.

## 2026-11-09: resizable columns in the posture host table

- Drag a header's right edge to change a column's width; widths are kept per browser. The Addresses column starts
  one IPv4 address wide; more addresses end in "…" with the full list on hover. Generic: any table with
  `data-resizable` and a `<colgroup>`.
- Rollback: revert this change.

## 2026-11-09: host rows expand in place

- A host name in the posture host table expands a row under it with its addresses' findings (the same tree: address,
  services, CVEs, description), instead of a dialog; click again to fold it. Sorting keeps an expanded row's
  findings under it, filtering hides them with their row. Chart and CVE-table links expand the right row.
- Rollback: revert this change.

## 2026-11-09: host list and findings in one table

- With a domain picked, the host name table replaces "Findings by address": each row also shows the worst
  severity, CVEs (once per host name, with severity pills), fixable, open ports, "potentially blocked" and failed
  scans; Worst sorts critical first. A host name opens its addresses' findings (CVE groups, services, Renew) in a
  dialog; the riskiest-addresses chart and the CVE table's address links open the same dialog.
- "All domains" and the domain page keep the per-address list.
- Rollback: revert this change.

## 2026-11-09: posture host list with "Scan now"

- With a domain picked, the posture page lists its host names with an address (latest inventory scan): addresses,
  last finished scan ("Never" when none), queued, and "out of scope" / "on the Never scan list" when a scan would
  skip it. Sortable, with the filter box and per-column filters of the domain tables.
- Tick rows (the header box ticks every visible row); "Scan now" opens a dialog with the profile to use and queues
  the ticked rows that are still visible, with the usual progress dialog.
- Tables: sorting uses the clicked header's own column, so a table may start with a column that does not sort.
- Never scan: the owner text is now "AS<number> <netname> <description>", and the defaults match "as8075"
  (Microsoft's ASN) instead of "microsoft": one Microsoft address had no description and was still scanned.
- Rollback: revert this change.

## 2026-11-09: posture "Never scan" list

- Settings · Security posture scope has an editable "Never scan" list: a host is skipped by every posture scan
  when its name contains one text and its network owner (ASN, netname, description) contains the other; an empty
  box matches anything. An address is skipped when every name on it is. Defaults until the settings are saved:
  autodiscover., enterpriseenrollment., enterpriseregistration., lyncdiscover., msoid., sip. at "microsoft".
- Rollback: revert this change (the stored list is ignored by older versions).

## 2026-11-09: CVEs grouped per service

- An address's CVE list is grouped per service (product, version, port), worst group first, each collapsed with
  its CVE count, severity pills and fixable count. A CVE that hits several services is listed under each, with
  "also: ..." naming the others.
- Rollback: revert this change.

## 2026-11-09: "Potentially blocked" addresses

- A finished scan where no port answered (all filtered; through a proxy or relay, all refused) is flagged
  "potentially blocked" (pill, KPI, note) instead of "no open TCP ports". Read from the stored nmap output, so older
  scans are flagged too. A direct scan that got a reset reached a live host and is not flagged. The pill and the
  note are amber (`--flat`).
- Rollback: revert this change.

## 2026-11-09: posture scan form starts at the whole domain

- The scan form no longer takes the host picked in the view: it starts at "Whole domain", and the button says
  "Scan / renew whole domain" or "Scan / renew 1 host". A view narrowed to one host had silently narrowed scans.
- Rollback: revert this change.

## 2026-11-09: CVE findings table in the posture report

- One row per address and CVE (CVE, severity, score, fixed in, address, host names, product · port, domain,
  scanned), with a filter box per column ("!text" = without), an all-columns filter and sorting, as in the domain
  tables. Collapsed by default; typing in the filter opens it. An address link opens its section below.
- Rollback: revert this change.

## 2026-11-09: certificate-log retries, scan notes, host cap warning

- crt.sh gets 3 attempts (waits 10 s and 30 s, 120 s each); when all fail, certspotter's keyless API (up to 8 pages
  of 100 certificates) is used instead. A failed crt.sh used to drop every certificate name without notice.
- A scan stores what made it incomplete (crt.sh replaced or failed, amass missing or failing, names over the
  per-scan limit) in the scan's `error` column; the domain page shows it as "This scan may be incomplete: ...".
- Names found by a source go first under `DOMIN_MAX_HOSTS`; common-name guesses only fill what the cap leaves.
- Rollback: revert this change and run `deploy/install.sh` again.

## 2026-11-09: menu shows where you are

- The current section's menu entry is accent-coloured, bold, tinted and underlined, with `aria-current="page"`;
  a domain's page and its compare view mark Inventory.
- Rollback: revert this change.

## 2026-11-08: daily CVE refresh

- Once a day (the worker's hourly loop, not at startup) CVE entries older than a day are fetched again and the
  latest successful scan of every address is matched against them: newly published CVEs, fixed versions, scores.
  Older scans keep the CVEs of their day, so a CVE published since the previous scan shows as new in the Changes
  panel, whose header shows when the refresh last ran (kv `cve_refresh:last`).
- Rollback: revert this change.

## 2026-11-08: CVE match review (all 237 cached findings checked against NVD)

- A CVE with one range per release branch (nginx 1.26.x fixed in 1.26.3, 1.27.x in 1.27.4) showed every branch's
  fix; now only the range holding the scanned version counts (all when none does). Cache format 4: refetched once.
- Dropbear: nmap names it matt_johnston:dropbear_ssh_server, NVD dropbear_ssh_project:dropbear_ssh (2018.76: 0 vs 5
  CVEs). Both names are looked up now; found on the next scan of such a host.
- `refresh-fixes` now also corrects fixed versions that differ from a fresh look-up (still never adds or drops CVEs).
- Changes panel: a zero count shows "0", not "−0" / "+0".
- Rollback: revert this change.

## 2026-11-08: NVD ranges that end "including X"

- An NVD range closed with versionEndIncluding (affected "through 2.4.55") names the last affected version, not the
  fix: such findings now show "fixed in: after 2.4.55" instead of "no fixed version published yet". Cache format 3:
  older entries are refetched once; `python -m domin refresh-fixes` updates stored results.
- Rollback: revert this change.

## 2026-11-08: posture scans resume where they stopped; fixed versions on stored results

- A posture scan runs its ports in chunks of 10, one nmap run each, and stores each chunk's result (columns
  `chunks`, `chunks_done`; migrated in place). After a worker restart it resumes at the next chunk. A requeued scan
  that made no progress before the next restart fails ("worker restarted twice"). The progress dialog shows
  "part x of y done". The profile timeout is now the limit per 10-port run.
- `python -m domin refresh-fixes`: fills in fixed versions on stored findings that have none, from a fresh CVE
  look-up of the same CPEs; the CVE list of a scan stays as it was.
- Rollback: revert this change (the two columns stay, unused).

## 2026-11-08: updates that leave scans running

- `deploy/update.sh`: code-only update from a tar on stdin (`git archive HEAD domin deploy | ssh <host> 'sudo bash
  /opt/domin/app/deploy/update.sh'`). Copies the changed files and restarts only what they need: the web app for any
  change under domin/, the worker only when a file it runs changed (not templates/, static/, web.py).
- A worker restart puts the posture scans it interrupted back in the queue (same row, same place) instead of failing
  them; a scan interrupted a second time fails ("worker restarted twice"), so it cannot loop.
- Rollback: revert this change; updates go back to `tar -x` plus restarting both services.

## 2026-11-08: fixed versions for NVD matches

- CVEs matched through NVD (by CPE, e.g. Apache httpd) showed "no fixed version published yet" even when the
  advisory names one: only OSV findings carried fixed versions. NVD findings now take the `versionEndExcluding` of
  the product's vulnerable ranges (CVE "2.4.66 and earlier" -> fixed in 2.4.67). Cached CVE look-ups from before
  this change are refetched once; existing scan results update on their next scan.
- Rollback: revert this change (`cve.nvd_fixed`, `cve.FORMAT`); cache entries stay readable.

## 2026-11-08: posture Changes panel

- The posture report (Security, per domain or host) has a Changes panel under the KPIs: each successful scan of an
  address against its previous successful scan. Counts for the last 30 days (new CVEs, CVEs gone, ports opened,
  ports closed, version changes) and a table of the latest 100 changes. Only ports both scans covered count, so a
  scan with another profile is not a change; failed (timed-out) scans are not compared.
- Rollback: revert this change (`posture.changes`, the panel in `_posture_report.html`).

## 2026-11-08: parallel posture scans, Mullvad "random country"

- Tuning: "Posture scans at once" (1-4, default 1). The worker runs 4 posture threads; only as many as the setting
  take scans (claim is atomic). Each scan picks its own route hop, so parallel Mullvad scans use different relays.
- Mullvad routes: a "random country" mode draws a country for every scan (each country with an active relay
  equally likely), then a random relay in it; inventory jobs on such a route also get a random country.
- Rollback: set "Posture scans at once" to 1; switch random-country routes to another mode; revert this change.

## 2026-11-08: a posture scan that hits the per-host timeout says so

- nmap marks a host it gave up on (`--host-timeout`) with `timedout="true"`; such a scan was shown as "No open TCP
  ports found". It now fails with "Timed out: ... the result is incomplete" and keeps the ports found before the
  limit. Seen on a scan through Mullvad: about 7 s per connection, 33 ports did not fit in 120 s.
- Rollback: revert this change in `domin/fingerprint.py`.

## 2026-11-08: Settings > Public database (staging copy of the public data)

- Settings (admin) has a "Public database" section with a Sync button: it replaces this instance's inventory
  (domains, scans, records, address and country caches) with the newest copy of the public server's database and
  adds this instance's own scans back on top with new ids (their jobs follow). Users, settings, posture scans,
  profiles, tags and queued jobs are not touched; no job is created.
- The copy reaches the host by itself: `deploy/public-sync.sh receive` (the forced command of one SSH key) keeps a
  checked zstd copy in /var/lib/domin-sync. The button drops /var/lib/domin/public-sync.request; the new root path
  unit domin-public-sync.path runs `public-sync.sh import` (`python -m domin import-public <db>`, then restarts
  domin) and writes /var/lib/domin/public-sync.status for the page.
- install.sh installs and enables domin-public-sync.path.
- Rollback: `systemctl disable --now domin-public-sync.path`, remove the two unit files, revert this change; restore
  the database from a backup to undo an import.

## 2026-11-08: routes table Save button

- The button under the routes table reads "Save" (was "Make the ticked route the preferred one"); same form.
  It uses the primary style like every other Save button.
- Rollback: restore the old button text in `domin/templates/scan_settings.html`.

## 2026-11-08: ready-made Tor and Mullvad routes

- The Routes page creates a "Tor" route when the local tor client answers and a "Mullvad (automatic)" route
  (fallback se) when the Mullvad tunnel is up: once each, enabled, not tested, used by nothing. Not when a route of
  that kind exists; a deleted one is not created again.
- Shared settings: a default-route picker next to the inventory and CVE pickers; each lists Direct and every route
  with its state (enabled, not tested / verified / last test failed / disabled). With no routes: a pointer to Add a
  route.
- Routes table: an Enabled tick box per route (applies on click), and the table wraps so Enabled, Verified and Test
  fit without scrolling sideways.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: Mullvad relay names resolve inside the tunnel

- A host without public DNS resolves `*.relays.mullvad.net` through Mullvad's in-tunnel resolver (10.64.0.1), so
  Follow host / Fixed / Automatic can pick relays in any country.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: clearer routes page, Mullvad setup fixes

- Routes page, top: **This host**: proxychains4 and wireguard-tools installed, the tor client's SOCKS5 answering,
  the Mullvad tunnel (up / no handshake / not up, with the reason) and the relay list's age. Quick checks: a PATH
  look-up, a SOCKS5 greeting with a short timeout cached for 30 s, and the status file the root script writes; the
  web app runs nothing.
- Each route row: a **Preferred** radio (the default for posture scans; replaces the Default route pick-list in the
  shared settings), **Enabled** on/off, **Verified** (✓ with the time of the last successful Test, ✗ with the error,
  or not tested; changing a route clears it), and what uses it (Default for posture, Inventory, CVE look-ups,
  profiles). A disabled or failed route in use gets a warning at the top; pick-lists on the Routes and Scan profiles
  pages mark it "(disabled)" or "(last test failed)". Scans on a disabled route fail closed: "route: the scan route
  <name> is disabled".
- Add a route: the Kind list says what works on this host. Tor is prefilled with 127.0.0.1:9050 and marked "not
  reachable" when nothing answers there; Mullvad can't be picked (with the reason) until the tunnel is up and is
  prefilled with Automatic and fallback country se; Custom proxy always. Only the chosen kind's fields are shown
  (app.js); without the script all fields show and work.
- Mullvad tunnel: shows which credential is saved (never the value), the last apply's time and result in plain words
  with the next step (for example "Mullvad's API could not be reached from this host: the setup service has no
  internet or proxy").
- `domin-mullvad.service` reads `/etc/domin.env` (`EnvironmentFile=-`), so the script's calls to Mullvad's API go
  through the host's HTTPS proxy. `mullvad-tunnel.sh` waits up to 15 s for a WireGuard handshake after bringing the
  tunnel up; without one it takes the tunnel down again and reports that outbound UDP 51820 is likely blocked
  (proxy-only egress). The status file gets a result code and the tunnel facts (up, last handshake, relay,
  wireguard-tools); `mullvad-tunnel.sh status` refreshes them.
- The service unit changed: run `deploy/install.sh` (it re-installs `domin-mullvad.service` and reloads systemd).

No migration. Rollback: redeploy the previous build.

## 2026-11-08: named scan routes, chosen per scan profile

- Settings · **Routes** (was Scan settings; URL unchanged, admin only): a list of named routes, each a custom proxy
  (socks5 / socks4 / http, host, port, user, password), Tor (SOCKS address) or Mullvad (follow host / fixed /
  automatic, country, city, fallback). Direct is built in. Add, edit, delete; each route has its own **Test** button.
  A route in use (default, inventory or CVE look-up route, or a scan profile) can't be deleted; the page says which.
  Passwords are never shown again (blank keeps, a tick clears).
- Shared settings on the same page: **Default route** (posture scans whose profile says Default, ad-hoc fingerprints),
  **Route for inventory jobs**, **CVE look-ups through** (Direct or a route; socks4 refused for inventory and CVE
  look-ups), DoH server, Mullvad tunnel credentials and relay list as before.
- Scan profiles get a **Route**: Default, Direct or a named route; the profile list and the Posture profile picker
  show it. A queued scan keeps its profile's route (Default resolves when it runs); a route deleted meanwhile fails the
  scan ("route: the scan route no longer exists"). Scan parameters record "via <route name>: <details>", no secrets.
  CVE look-ups take the scan's own hop when the CVE route is the scan's route, else the CVE route on its own; a CVE
  route that can't be used gives the local CVE database only. Fail closed everywhere, as before.
- Database: column `route` on `posture_profiles` and `posture_scans` (added at start, default '' = Default).

Migration: the existing route becomes a named route automatically (named Custom proxy, Tor or Mullvad; its tick
boxes become the defaults: posture scans → default route, inventory jobs → inventory route, CVE look-ups → CVE route);
existing profiles get Default. The new settings are kv `scan_routes`; the old kv `scan_proxy` is only read, never
changed. Rollback: redeploy the previous build; it reads `scan_proxy` as it was before this update (route changes made
since are not carried back) and ignores the new columns. To redo the migration later, delete kv `scan_routes`
(`sqlite3 /var/lib/domin/domin.db "DELETE FROM kv WHERE key = 'scan_routes'"`).

## 2026-11-08: Scan profiles, CVE look-up and Scan settings under Settings

- The Settings menu has sections General · Scan profiles · CVE look-up · Scan settings; Posture shows the report
  only. URLs unchanged. Non-admins see Settings with Scan profiles and CVE look-up only.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: Tor and Mullvad routes for posture scans and inventory jobs

- Posture · **Scan settings**: a route (direct / custom proxy / Tor / Mullvad) and tick boxes for which jobs take it
  (posture scans, inventory jobs). A line at the top shows the state ("Posture scans: Mullvad, follow host (fallback
  se) · Inventory jobs: direct"). Settings saved before keep working (custom proxy for posture scans).
- **Tor**: the local tor client's SOCKS5 (default 127.0.0.1:9050). One exit for all scans, no per-host country.
- **Mullvad**: per target a relay's SOCKS5 (socks_name:1080, reachable only inside the Mullvad tunnel), picked at
  random among active relays. Breakout: **follow host** (the address's DB-IP country, else the fallback country, else
  the scan fails), **fixed** (country, optional city), **automatic** (the address's country, else the fallback, else
  any relay). Inventory jobs use the fixed or fallback country. The relay list (api.mullvad.net, public) is cached a
  day; **Refresh relay list** fetches it now. The page shows list age and count and whether the in-tunnel SOCKS5
  (10.64.0.1:1080) answers.
- Mullvad tunnel credentials on the page: account number, or a WireGuard private key with its tunnel address (from
  Mullvad's WireGuard configuration generator), optional entry country. Never shown again (blank keeps, a tick
  clears); stored in the database. Saving changed credentials writes `/var/lib/domin/mullvad.request` (a time stamp,
  no secrets); the root unit `domin-mullvad.path` runs `deploy/mullvad-tunnel.sh apply`, whose result the page shows.
- `deploy/mullvad-tunnel.sh up|down|status|apply|allow` (root): WireGuard interface `mullvad` with
  `AllowedIPs = 10.64.0.0/10` only (no DNS change, no default route). A private key is used as given; with an account
  number only, a key is generated once and registered with Mullvad. Credentials from the database, else
  `/etc/domin/mullvad-account` (root, 0600/0400). Writes the drop-ins
  `/etc/systemd/system/{domin-worker,domin}.service.d/20-routes.conf` (`IPAddressAllow=10.64.0.0/10 127.0.0.1/32`)
  and restarts those services when they change.
- Posture scans: nmap under proxychains4 through the chosen hop; the route is kept in the scan parameters ("via mullvad
  se-got-wg-socks5-001 (se, follow host)"), never credentials. A private address through Tor or Mullvad fails with
  "private address can't go through Tor/Mullvad". CVE look-ups can now go through socks5 too (not socks4).
- Inventory jobs (external zones): crt.sh and RDAP through the hop (httpx with SOCKS), DNS over DoH through the same
  client (server on the page, default https://dns.quad9.net/dns-query), amass skipped (its UDP DNS can't be proxied).
  Address owners come from rdap.org then (ASN often blank). Internal zones always stay direct. Fail closed: the hop
  must answer first, else the job fails with "route: ...".
- New dependency: `httpx[socks]` (socksio 1.0.0). `deploy/install.sh` installs wireguard-tools and tor (default
  config) and the `domin-mullvad` path unit.

Host steps:
1. `sudo bash deploy/install.sh ...` as usual (packages, socksio, path unit). A host whose egress goes through an http
   proxy only (e.g. Squid) needs `HTTPSProxy` in `/etc/tor/torrc` for Tor.
2. Mullvad: save the credentials on Scan settings (or put the account number in `/etc/domin/mullvad-account`, root,
   0600, and run `sudo bash /opt/domin/app/deploy/mullvad-tunnel.sh up`).
3. Tor without Mullvad: `sudo bash /opt/domin/app/deploy/mullvad-tunnel.sh allow` (the worker drop-in for
   127.0.0.1).

No migration. Rollback: redeploy the previous build; `mullvad-tunnel.sh down`.

## 2026-11-08: scan proxy for posture scans

- Posture · **Scan settings** (admin only): a proxy every posture scan goes through. Type socks5 / socks4 / http,
  host (IP or name), port, optional user name and password, on/off. The password is never shown again (blank on save
  keeps it, a tick clears it); it is stored in plain text in the database.
- nmap runs as `proxychains4 -q -f <per-run config> nmap -sT -sV ...`; the config (strict chain, proxy DNS, one
  proxy by numeric address) is written mode 0600 and deleted after the run. A host name is resolved at scan time.
- Fails closed: proxy on and proxychains4 missing, the proxy host not resolving or the proxy not answering its
  greeting makes that scan fail with the reason; never a direct scan. Proxy off: the command is as before.
- The route ("via socks5 192.0.2.10:1080", no credentials) is kept in the scan's parameters; the Posture and CVE
  look-up pages show "Scans go through ..." while the proxy is on. Ad-hoc host fingerprints use it too.
- **Test proxy** connects to the saved proxy from the web process and completes the greeting (SOCKS5 with user name
  and password; SOCKS4 and http: the TCP connect). No request to any target.
- "Also send CVE look-ups through the proxy": OSV and NVD queries go through an http proxy (socks support for
  look-ups is not installed; the form refuses that combination).
- `deploy/install.sh` installs proxychains4.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: inventory and admin pages back to their previous layout

- Inventory, domain page layout, Operations, Settings, Users and Account return to the layout before the entry below;
  the posture report and the Posture page keep their changes. Kept: the Users role pick-list fix.
- Posture expandables (address, CVE, scan details) show a chevron that turns down when open.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: views ordered by what needs attention, posture report charts

- Posture report (Posture page, domain page): KPIs (critical, high, addresses with high+, fix available, stale /
  failed), then three charts: **Riskiest addresses** (top 10, CVEs stacked by severity; a click opens that address),
  **Fix available?** (distinct CVEs per severity, fix published vs no fix yet) and **Critical & high over time**
  (distinct CVEs per day with a finished scan, from the posture scan history). Findings by address follow; **Scan age**
  and **Exposed services** (ranked bars, were pies) close the report. The severity and worst-finding pies are gone
  (covered by the KPIs, the new charts and the list). An empty chart shows a sentence instead.
- Posture page: the scan controls come before the authorised-use notice.
- Inventory (signed in): a security posture line (critical / high CVEs, fixable, stale / failed) leads the page; the
  domains table and recent jobs come before the charts.
- Domain page: "Changes since" sits right under the KPIs, before the charts.
- Operations: scan jobs first (failed before finished), a red line when the worker is paused, Tuning folded, traffic
  after, the recent-visits log and jobs-per-day table folded.
- Settings: a Save button at the top; posture scope and two-factor first; the Scan limits card turns amber when the
  limits are off; the posture scope text now says countries apply too.
- Users: the role pick-list applies itself again (the inline handler was blocked by the CSP); 2FA and disabled show as
  pills, with a count of active users without two-factor. Account: two-factor before the password form.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: posture findings per address, expandable CVEs with fix flags

- The posture report (Posture page and the domain page) lists findings per address, worst first, all collapsed.
  Each headline shows the worst severity, CVE counts per severity, "N of M fixable" or "no fix published yet",
  open ports, last scan / stale and **Renew**.
- Opening an address lists its CVEs (id, severity, CVSS, product and port, fix flag: "fix: N versions" or
  "no fix yet"). Opening a CVE shows its description, the fixed-in versions and NVD / OSV links.
- Services, scan parameters and raw nmap output sit in a collapsed "Services & scan details" under each address.
- The flat Vulnerabilities table is gone; a new KPI shows "Fix available: N of M" distinct CVEs.
- CVE descriptions are kept up to 1000 characters (was 200) for new look-ups; cached entries keep the short text
  until they are looked up again.

No migration. Rollback: redeploy the previous build.

## 2026-11-08: posture scans show a progress dialog

- **Scan / renew** and the per-address **Renew** (Posture page and the domain page) now queue the scans in the
  background and open a progress dialog: finished / running / queued / failed counts, a progress bar, the address
  being scanned, the elapsed time and each finished address with its worst severity and CVE count (or its error).
  It checks every 2 seconds while open. When all are done it offers **Show results** (reloads the report once).
- Closing the dialog does not stop the scans; a "N posture scan(s) queued or running · show progress" pill on the
  page opens it again. Nothing on the page reloads by itself.
- New `GET /admin/security/posture/status?ids=…[&pending=1&domain=…]` (any signed-in user) returns the progress as
  JSON; the scan form returns the batch (the queued row ids) as JSON when asked with `Accept: application/json`.
  Without JavaScript the forms post and redirect as before.
- No migration.
- Rollback: redeploy the previous build.

## 2026-11-08: internal scans find host names by DNS queries

- A scan of an internal domain now finds its host names with DNS queries to the internal DNS servers: a zone
  transfer (AXFR) when the server allows one, and a reverse look-up (PTR) of every address in the internal networks.
  Bare names from a hosts-style list (`pve`) are taken as names in the zone. Names outside the scanned domain are
  ignored. MX/NS records and common names are still tried; no query leaves the internal DNS servers.
- **Settings → Internal domains** gains **Internal networks** (private IPv4 CIDRs, at most 8192 addresses in all).
  Empty = the /24 of each internal DNS server and of the domain's own address. `DOMIN_INTERNAL_NETS` prefills it.
- Internal scans send at most 12 DNS queries per second: a LAN DNS server such as Pi-hole refuses a client that
  asks more than 1000 times a minute, and the refused look-ups left hosts without addresses. A sweep of four /24
  networks takes about two minutes.
- No migration. Rollback: redeploy the previous build (the stored networks are then ignored).

## 2026-11-08: "Today" look

- New colours and type: blue-violet accent, system font, 12 px cards and 8 px controls. Dark by default, light when
  the device asks for a light theme. Charts follow the theme. Primary, chip and danger buttons use dark text on the
  accent in dark mode.
- No migration. Rollback: redeploy the previous build (browsers may need a reload to drop the cached stylesheet).

## 2026-11-08: internal scans keep LAN addresses only

- A LAN resolver such as Pi-hole answers only the names in its local list and forwards everything else (AAAA
  questions, unknown names) to public DNS, so an internal scan also listed the zone's public addresses. A scan of an
  internal domain now keeps only private addresses (RFC 1918, ULA, CGNAT) and drops public, link-local (`fe80::`)
  and loopback answers; a name with only public addresses is left out. Names that do not resolve are kept as before.
- No migration. Rollback: redeploy the previous build.

## 2026-11-08: internal domains on the Settings page

- **Settings → Internal domains**: list your own domains (e.g. `corp.example`, `home.arpa`; subdomains included) and the
  internal DNS servers that answer for them. A scan of such a name asks only those servers (no public resolvers,
  crt.sh, amass or RDAP), so it returns your own addresses and leaks no internal names.
- Stored in the database; once saved it overrides `DOMIN_INTERNAL_ZONES` / `DOMIN_INTERNAL_DNS` (which still prefill
  the form). Applies to the next scan without a restart: web, worker, scheduled refresh and the CLI read it live.
- Zones without a DNS server are refused (they would fall back to public DNS); DNS servers must be IP addresses.
- No migration. Clearing both fields and saving turns internal mode off (it does not fall back to the environment).
  Rollback: redeploy the previous build (the stored setting is then ignored).

## 2026-11-08: posture report first; clearer navigation

- **Posture page** (was Security) is ordered for a security administrator: controls on top (domain, host, scan
  target, profile, *Scan / renew*), then the risk summary (critical and high CVEs, addresses with high+, distinct
  CVEs, open ports, stale > 30 days and failed scans), three pie charts (CVEs by severity, addresses by worst
  finding, exposed services), one **Vulnerabilities** table (each CVE once, worst first, with the affected product,
  where it is (host:port, linked) and the fixed-in version), then the addresses as expandable headlines, worst first,
  with *Renew* in the headline and the services, CVEs, parameters and raw output inside.
- A **Host** pick narrows the report to one host name.
- A domain's page shows signed-in users the same report at the top, above the inventory.
- Sub-tabs: Posture · Scan profiles · **CVE look-up** (the product/package look-up and ad-hoc host fingerprint moved
  to their own page). On Scan profiles the add/change form comes first.
- Menu renamed: Overview → **Inventory**, Drilldown (All) → **All records**, Tools → **Whois & e-mail**, Security →
  **Posture**, Dashboard → **Operations**. URLs are unchanged.
- The **Authorized use only** banner has a *Dismiss* link that hides it for that user for good (stored per user).
- No migration. Rollback: redeploy the previous build.

## 2026-11-08: host tags with suggested classification

- Signed-in users see a **Tags** column on a domain's records; analysts and admins add a tag (type it, Enter),
  remove one (×) or accept a **suggested** one (dashed `+ tag`). A host can carry any number of tags; they belong to
  the host name and persist across scans.
- Suggestions are rule-based: words in the host name (`www` → webserver, `cam`/`nvr` → iot-device, `nas` → storage,
  `mx`/`mail` → mailserver, `vpn` → remote-access, `dev`/`test` → non-production, …) and, once a posture scan has run,
  the open services at the host's addresses (80/443 → webserver, 1883/554 → iot-device, 9100/631 → printer,
  445 → file-share, database ports → database, …). Nothing is tagged without an analyst's click.
- **Group by tag**: tag chips with host counts above the records; a chip (or a tag) filters the table to those hosts.
- Dropping a domain drops its hosts' tags. Anonymous visitors see no tags.
- Migration: new `host_tags` table at start-up. Rollback: redeploy the previous build (the table is ignored).

## 2026-11-08: scan profiles, saved scan parameters, raw output pane

- **Security → Scan profiles**: named nmap parameter sets (ports, version intensity 0-9, timing T1-T4, per-address
  timeout, note). Analyst or admin adds, changes and deletes them; any signed-in user reads them. A `default` profile
  (the previous fixed settings: common ports, light version probes, T3, 120 s) is created at start-up and cannot be
  deleted.
- The Posture form picks a profile; its port field is now an optional override. **Renew** reuses the scan's profile
  and ports.
- Each posture scan stores its profile, knobs and the exact nmap command line next to the raw nmap XML.
- A domain's page shows signed-in users a **Security posture** section: the latest result per address, its
  parameters and the raw nmap output in a collapsed, expandable pane. Anonymous visitors do not see it.
- Migration: new `posture_profiles` table and five `posture_scans` columns, added at start-up. Rollback: redeploy the
  previous build (the extra table and columns are ignored by it).

## 2026-11-08: security posture (stage 2)

- **Security → Posture**: pick an inventoried domain, then scan the **whole domain** or **one host name**. The scan
  takes the addresses of the domain's latest inventory scan, keeps those inside the posture scope (Settings: IP and
  country rules) and fingerprints each (nmap `-sT -sV`), matching the services' CPEs against the CVE database.
- Analyst or admin starts it, only from this page; an inventory scan never starts one.
- The **worker** runs the posture queue (one address at a time; respects *Pause scans*); the web process never
  probes a target. The scope is checked again when a queued scan starts.
- Results persist in the new `posture_scans` table with their parameters (ports), requester and the raw nmap XML.
  The table shows the latest result per address with **Renew**; each address expands to its services and CVEs.
- Dropping a domain drops its posture scans. IPv6 addresses are scanned with `nmap -6`.
- Migration: the table is created at start-up; nothing else changes.

## 2026-11-08: admin can drop a domain from the inventory

- An **admin** (only) sees a **Drop from inventory** button on a domain's page. It removes that domain and all of its
  scans, records and queued/old jobs from the database (user accounts, settings and scope are untouched), then
  returns to the overview. CSRF-checked; analysts and viewers do not see or reach it.
- Destructive actions now confirm in a **styled modal popup** (naming the domain) instead of the plain browser
  prompt; the same popup covers the other destructive buttons (delete user, reset two-factor, …).
- Reversible only by re-scanning the domain (the removed history is gone); no migration.

## 2026-11-08: internal scan mode (LAN zones, no external egress)

- `DOMIN_INTERNAL_ZONES` lists domain suffixes (e.g. `home.arpa,corp.example`) scanned as internal. A scan of a name
  under one of these zones: resolves only over `DOMIN_INTERNAL_DNS` (the LAN DNS server, e.g. the house resolver),
  discovers host names over that DNS alone (no crt.sh, no amass, no public resolvers), and does no RDAP owner
  look-up — so an internal scan makes no outbound internet request and never leaks internal names upstream.
- Names under a configured internal zone pass validation even when the suffix is otherwise private (so `home.arpa`
  hosts can be scanned); a special-use suffix that is not a configured zone stays rejected.
- Private/reserved addresses the lookup returns are kept and listed (labelled "Private/reserved"), as before — this
  change makes the internal lookups actually return them instead of public DNS answers.
- Reversible: unset `DOMIN_INTERNAL_ZONES` (scans go back to the public/external path); no data change.

## 2026-11-08: Settings tick-box to disable scan limits; nav keeps admin links

- The **Settings** page gains a **Disable scan limits** tick-box (under "Scan limits"). With it on, `POST /api/scan`
  skips every visitor limit (once-per-day, per-client hour/day caps, the daily total and the queue cap), so a domain
  can be re-scanned freely. Off by default; leave it off on an instance exposed to abuse. Also settable at start with
  `DOMIN_SCAN_LIMITS_OFF=1`.
- The signed-in navigation (Security, Dashboard, Settings, Users, account) now stays on the public pages too, instead
  of dropping to just an account link when you leave the admin views.
- Settings copy: the security posture scope is labelled as governing the Host fingerprint tool (now active), not "not
  active yet".
- Reversible: untick the box (or revert the commit); no data change.

## 2026-11-08: security portal (CVE look-up and host fingerprinting)

- A Security page (analyst or admin runs it; any signed-in user reads it). Look up the known vulnerabilities (CVEs)
  of a product version (by CPE, against NVD) or a package version (by ecosystem, against OSV.dev) — the same sources
  an infrastructure vulnerability watch uses, updated continuously upstream.
- Host fingerprinting: the Host tab runs an nmap connect scan (`-sT -sV`, no OS detection and no raw packets, so no
  extra privilege) of one in-scope address, then matches each open port's service CPEs against those sources and
  lists the CVEs per service. The target's resolved address must fall inside the security posture scope (Settings).
- Local CVE database: the instance keeps its own cache (`DOMIN_CVE_DB_MODE=own`, re-queried after
  `DOMIN_CVE_TTL_DAYS`) or reads a shared one read-only (`shared` + `DOMIN_CVE_DB_PATH`). `DOMIN_NVD_API_KEY` raises
  the NVD rate limit. nmap must be installed on the host; internet access (for `own` mode) may go through a proxy via
  the usual `HTTPS_PROXY` environment variable.
- Reversible: `deploy/install.sh` applies this in place and keeps the database, `/etc/domin.env` and certificates; to
  undo, redeploy the previous build.

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
